"""
Bastion engine/parsers/fortinet.py — FortiGate configuration parser.
"""
import re
from typing import Dict, List, Optional

from engine.models import FirewallRule, ParseResult
from engine.parsers.base import AbstractParser, VENDOR_PARSERS


class FortinetParser(AbstractParser):

    def parse(self) -> ParseResult:
        try:
            hostname = self._parse_hostname()
            version = self._parse_version()

            # VDOM detection
            has_vdom = "config vdom" in self.config_text.lower()

            if has_vdom:
                rules, interfaces, mgmt_access = self._parse_with_vdoms()
            else:
                self._parse_addresses()
                self._parse_addrgrps()
                self._parse_services()
                rules = self._parse_policies("", self.lines)
                interfaces, mgmt_access = self._parse_interfaces()

            return ParseResult(
                vendor="fortinet",
                filename=self.filename,
                hostname=hostname,
                version=version,
                rules=rules,
                metadata={
                    "interfaces": interfaces,
                    "zones": list(interfaces.keys()),
                    "objects": self.resolver.objects,
                    "nat_rules": [],
                    "routes": [],
                    "management_access": mgmt_access,
                },
                parse_errors=self.parse_errors,
                parse_warnings=self.parse_warnings,
            )
        except Exception as e:
            self._error(0, f"FortiGate parse failed: {e}")
            return ParseResult(
                vendor="fortinet", filename=self.filename,
                hostname=None, version=None, rules=[],
                metadata={}, parse_errors=self.parse_errors,
                parse_warnings=self.parse_warnings,
            )

    def _parse_hostname(self) -> Optional[str]:
        try:
            for line in self.lines:
                m = re.match(r"^\s*set hostname\s+[\"']?(\S+)[\"']?", line, re.I)
                if m:
                    return m.group(1).strip('"\'')
        except Exception:
            pass
        return None

    def _parse_version(self) -> Optional[str]:
        try:
            for line in self.lines:
                m = re.match(r"#config-version=.+?-(\d[\d.]+)", line, re.I)
                if m:
                    return m.group(1)
        except Exception:
            pass
        return None

    def _parse_with_vdoms(self):
        """Split config by VDOM and process each independently."""
        all_rules = []
        all_interfaces = {}
        all_mgmt = []

        try:
            vdom_sections = re.split(r"^config vdom$", self.config_text,
                                     flags=re.MULTILINE)
            vdom_names = re.findall(r"^edit\s+(\S+)", self.config_text,
                                    re.MULTILINE)

            for i, section in enumerate(vdom_sections[1:], start=0):
                vdom_name = vdom_names[i] if i < len(vdom_names) else f"vdom{i}"
                section_lines = section.splitlines()
                self._parse_addresses_from_lines(section_lines)
                self._parse_addrgrps_from_lines(section_lines)
                rules = self._parse_policies(vdom_name, section_lines)
                all_rules.extend(rules)
                ifaces, mgmt = self._parse_interfaces_from_lines(section_lines)
                all_interfaces.update(ifaces)
                all_mgmt.extend(mgmt)
        except Exception as e:
            self._error(0, f"_parse_with_vdoms failed: {e}")

        return all_rules, all_interfaces, all_mgmt

    def _get_edit_blocks(self, lines: list, config_section: str) -> List[dict]:
        """Extract edit blocks from a config section."""
        blocks = []
        in_section = False
        in_edit = False
        current_block = {}
        current_name = ""
        depth = 0

        try:
            for line in lines:
                stripped = line.strip()

                if re.match(r"^config\s+" + re.escape(config_section), stripped, re.I):
                    in_section = True
                    depth = 1
                    continue

                if not in_section:
                    continue

                if stripped.startswith("end") and depth <= 1:
                    if in_edit and current_name:
                        blocks.append({"name": current_name, **current_block})
                    in_section = False
                    in_edit = False
                    current_block = {}
                    depth = 0
                    continue

                if stripped.startswith("config "):
                    depth += 1
                    continue

                if stripped == "end":
                    depth -= 1
                    continue

                m = re.match(r"^edit\s+[\"']?(.+?)[\"']?$", stripped)
                if m:
                    if in_edit and current_name:
                        blocks.append({"name": current_name, **current_block})
                    current_name = m.group(1).strip('"\'')
                    current_block = {}
                    in_edit = True
                    continue

                if stripped == "next":
                    if in_edit and current_name:
                        blocks.append({"name": current_name, **current_block})
                    current_name = ""
                    current_block = {}
                    in_edit = False
                    continue

                if in_edit:
                    m = re.match(r"^set\s+(\S+)\s+(.*)", stripped, re.I)
                    if m:
                        current_block[m.group(1).lower()] = m.group(2).strip().strip('"\'')
        except Exception as e:
            self._error(0, f"_get_edit_blocks({config_section}) failed: {e}")

        return blocks

    def _parse_addresses(self):
        self._parse_addresses_from_lines(self.lines)

    def _parse_addrgrps(self):
        self._parse_addrgrps_from_lines(self.lines)

    def _parse_services(self):
        try:
            blocks = self._get_edit_blocks(self.lines, "firewall service custom")
            for b in blocks:
                name = b.get("name", "")
                tcp_range = b.get("tcp-portrange", "")
                if tcp_range:
                    m = re.match(r"(\d+)(?::(\d+))?", tcp_range)
                    if m:
                        start = int(m.group(1))
                        end = int(m.group(2)) if m.group(2) else start
                        self.resolver.add_object(name, "service", (start, end))
        except Exception as e:
            self._error(0, f"_parse_services failed: {e}")

    def _parse_addresses_from_lines(self, lines: list):
        try:
            blocks = self._get_edit_blocks(lines, "firewall address")
            for b in blocks:
                name = b.get("name", "")
                addr_type = b.get("type", "subnet")
                if addr_type == "fqdn":
                    fqdn = b.get("fqdn", "")
                    if fqdn:
                        self.resolver.add_object(name, "fqdn", fqdn)
                elif addr_type == "iprange":
                    start_ip = b.get("start-ip", "")
                    end_ip = b.get("end-ip", "")
                    if start_ip:
                        self.resolver.add_object(name, "range",
                                                  f"{start_ip}-{end_ip}")
                else:
                    subnet = b.get("subnet", "")
                    if subnet:
                        parts = subnet.split()
                        if len(parts) == 2:
                            try:
                                import ipaddress
                                cidr = str(ipaddress.ip_network(
                                    f"{parts[0]}/{parts[1]}", strict=False
                                ))
                                self.resolver.add_object(name, "subnet", cidr)
                            except ValueError:
                                self.resolver.add_object(name, "subnet", subnet)
                        else:
                            self.resolver.add_object(name, "subnet", subnet)
        except Exception as e:
            self._error(0, f"_parse_addresses_from_lines failed: {e}")

    def _parse_addrgrps_from_lines(self, lines: list):
        try:
            blocks = self._get_edit_blocks(lines, "firewall addrgrp")
            for b in blocks:
                name = b.get("name", "")
                member_str = b.get("member", "")
                if member_str:
                    members = re.findall(r'"([^"]+)"|\S+', member_str)
                    members = [m.strip('"') for m in members if m]
                    self.resolver.add_group(name, members)
        except Exception as e:
            self._error(0, f"_parse_addrgrps_from_lines failed: {e}")

    def _parse_policies(self, vdom: str, lines: list) -> List[FirewallRule]:
        rules = []
        try:
            blocks = self._get_edit_blocks(lines, "firewall policy")
            for idx, b in enumerate(blocks):
                name = b.get("name", "")
                policy_id = b.get("name", str(idx))
                srcintf = b.get("srcintf", "any").strip('"')
                dstintf = b.get("dstintf", "any").strip('"')
                srcaddr = b.get("srcaddr", "all").strip('"')
                dstaddr = b.get("dstaddr", "all").strip('"')
                service = b.get("service", "ALL").strip('"')
                action_raw = b.get("action", "accept").lower()
                action = "permit" if action_raw in ("accept", "allow") else "deny"
                logtraffic = b.get("logtraffic", "disable").lower()
                status = b.get("status", "enable").lower()
                comments = b.get("comments", "")

                src_list = re.findall(r'"([^"]+)"|\S+', srcaddr)
                src_list = [s.strip('"') for s in src_list if s]
                dst_list = re.findall(r'"([^"]+)"|\S+', dstaddr)
                dst_list = [s.strip('"') for s in dst_list if s]

                src_addresses = []
                for s in src_list:
                    src_addresses.extend(self.resolver.resolve_address(s))

                dst_addresses = []
                for d in dst_list:
                    dst_addresses.extend(self.resolver.resolve_address(d))

                if not src_addresses:
                    src_addresses = ["0.0.0.0/0"]
                if not dst_addresses:
                    dst_addresses = ["0.0.0.0/0"]

                prefix = f"{vdom}:" if vdom else ""
                rules.append(FirewallRule(
                    rule_id=f"{prefix}policy-{policy_id}",
                    rule_name=name or policy_id,
                    enabled=(status == "enable"),
                    action=action,
                    protocol="ip",
                    src_zone=srcintf,
                    dst_zone=dstintf,
                    src_addresses=src_addresses,
                    dst_addresses=dst_addresses,
                    src_ports=None,
                    dst_ports=None,
                    logging=(logtraffic != "disable"),
                    log_level=None,
                    line_number=idx + 1,
                    raw_lines=[f"edit {policy_id}"],
                    nat=None,
                    comments=comments or None,
                    vendor="fortinet",
                    interface_binding=srcintf,
                ))
        except Exception as e:
            self._error(0, f"_parse_policies failed: {e}")
        return rules

    def _parse_interfaces(self):
        return self._parse_interfaces_from_lines(self.lines)

    def _parse_interfaces_from_lines(self, lines: list):
        interfaces = {}
        mgmt_access = []
        try:
            blocks = self._get_edit_blocks(lines, "system interface")
            for b in blocks:
                name = b.get("name", "")
                ip = b.get("ip", "")
                alias = b.get("alias", "")
                vdom = b.get("vdom", "root")
                allowaccess = b.get("allowaccess", "")
                interfaces[name] = {
                    "ip": ip, "alias": alias, "vdom": vdom,
                    "allowaccess": allowaccess,
                }
                for proto in allowaccess.split():
                    p = proto.lower()
                    if p in ("http", "https", "ssh", "telnet"):
                        mgmt_access.append({
                            "proto": p, "network": "0.0.0.0",
                            "mask": "0.0.0.0", "interface": name,
                        })
        except Exception as e:
            self._error(0, f"_parse_interfaces_from_lines failed: {e}")
        return interfaces, mgmt_access


VENDOR_PARSERS["fortinet"] = FortinetParser
