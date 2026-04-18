"""
Bastion engine/parsers/cisco_asa.py — Cisco ASA / PIX / FWSM configuration parser.
"""
import ipaddress
import re
from typing import Dict, List, Optional, Tuple

from engine.models import FirewallRule, ParseResult
from engine.parsers.base import AbstractParser, VENDOR_PARSERS

# Port-name to number mapping
_PORT_NAMES = {
    "ftp": 21, "ftp-data": 20, "ssh": 22, "telnet": 23, "smtp": 25,
    "domain": 53, "dns": 53, "http": 80, "pop3": 110, "ntp": 123,
    "https": 443, "smtps": 465, "imap": 993, "pop3s": 995,
    "bgp": 179, "ldap": 389, "ldaps": 636, "rdp": 3389, "mssql": 1433,
    "mysql": 3306, "snmp": 161, "snmptrap": 162, "tftp": 69,
    "sip": 5060, "sips": 5061, "vnc": 5900, "kerberos": 88,
    "h323": 1720, "pptp": 1723, "isakmp": 500, "esp": 50,
    "netbios-ssn": 139, "netbios-dgm": 138, "netbios-ns": 137,
    "ms-sql-s": 1433, "oracle": 1521, "redis": 6379,
}


def _resolve_port_name(name: str) -> Optional[int]:
    """Convert named port to integer."""
    name = name.lower().strip()
    if name.isdigit():
        return int(name)
    return _PORT_NAMES.get(name)


def _parse_port_arg(tokens: List[str], idx: int) -> Tuple[Optional[List[Tuple[int, int]]], int]:
    """
    Parse port specification starting at tokens[idx].
    Returns (port_ranges, new_idx).
    """
    if idx >= len(tokens):
        return None, idx
    kw = tokens[idx].lower()
    if kw == "eq" and idx + 1 < len(tokens):
        p = _resolve_port_name(tokens[idx + 1])
        if p is not None:
            return [(p, p)], idx + 2
        return None, idx + 2
    elif kw == "range" and idx + 2 < len(tokens):
        p1 = _resolve_port_name(tokens[idx + 1])
        p2 = _resolve_port_name(tokens[idx + 2])
        if p1 is not None and p2 is not None:
            return [(p1, p2)], idx + 3
        return None, idx + 3
    elif kw == "lt" and idx + 1 < len(tokens):
        p = _resolve_port_name(tokens[idx + 1])
        if p is not None:
            return [(0, p - 1)], idx + 2
        return None, idx + 2
    elif kw == "gt" and idx + 1 < len(tokens):
        p = _resolve_port_name(tokens[idx + 1])
        if p is not None:
            return [(p + 1, 65535)], idx + 2
        return None, idx + 2
    elif kw == "neq":
        # Skip
        return None, idx + 2
    return None, idx


class CiscoAsaParser(AbstractParser):
    """Parser for Cisco ASA, PIX, and FWSM firewall configurations."""

    def _parse_hostname(self) -> Optional[str]:
        """Parse hostname from config."""
        try:
            for line in self.lines:
                m = re.match(r"^hostname\s+(\S+)", line.strip())
                if m:
                    return m.group(1)
        except Exception as e:
            self._error(0, f"_parse_hostname failed: {e}")
        return None

    def _parse_version(self) -> Optional[str]:
        """Parse ASA version from config."""
        try:
            for line in self.lines:
                m = re.match(r"^ASA Version\s+([\d.()\w]+)", line.strip(), re.IGNORECASE)
                if m:
                    return m.group(1)
        except Exception as e:
            self._error(0, f"_parse_version failed: {e}")
        return None

    def _parse_interfaces(self) -> dict:
        """
        Parse interface blocks.
        Returns: {nameif → {phy_name, security_level, ip, mask, shutdown}}
        """
        interfaces = {}
        try:
            current_phy = None
            current_data = {}
            in_interface = False

            for line in self.lines:
                stripped = line.strip()

                if re.match(r"^interface\s+(\S+)", stripped):
                    if current_phy and "nameif" in current_data:
                        nameif = current_data["nameif"]
                        interfaces[nameif] = {
                            "phy_name": current_phy,
                            **current_data,
                        }
                    m = re.match(r"^interface\s+(\S+)", stripped)
                    current_phy = m.group(1)
                    current_data = {"shutdown": False}
                    in_interface = True
                elif in_interface:
                    if stripped.startswith("!") or (
                        not stripped.startswith(" ") and stripped and not stripped[0] == " "
                    ):
                        if stripped and not stripped.startswith(" "):
                            if current_phy and "nameif" in current_data:
                                nameif = current_data["nameif"]
                                interfaces[nameif] = {
                                    "phy_name": current_phy,
                                    **current_data,
                                }
                            in_interface = False

                    m = re.match(r"nameif\s+(\S+)", stripped)
                    if m:
                        current_data["nameif"] = m.group(1)

                    m = re.match(r"security-level\s+(\d+)", stripped)
                    if m:
                        current_data["security_level"] = int(m.group(1))

                    m = re.match(r"ip address\s+([\d.]+)\s+([\d.]+)", stripped)
                    if m:
                        current_data["ip"] = m.group(1)
                        current_data["mask"] = m.group(2)

                    if stripped == "shutdown":
                        current_data["shutdown"] = True

            if current_phy and "nameif" in current_data:
                nameif = current_data["nameif"]
                interfaces[nameif] = {"phy_name": current_phy, **current_data}

        except Exception as e:
            self._error(0, f"_parse_interfaces failed: {e}")
        return interfaces

    def _parse_objects(self) -> None:
        """Parse object network and object service blocks into the resolver."""
        try:
            i = 0
            while i < len(self.lines):
                line = self.lines[i].strip()

                # object network <name>
                m = re.match(r"^object network\s+(\S+)", line)
                if m:
                    name = m.group(1)
                    i += 1
                    while i < len(self.lines):
                        sub = self.lines[i].strip()
                        if not sub or sub.startswith("!"):
                            break
                        if sub.lower().startswith("subnet "):
                            parts = sub.split()
                            if len(parts) >= 3:
                                try:
                                    cidr = str(ipaddress.ip_network(
                                        f"{parts[1]}/{parts[2]}", strict=False
                                    ))
                                    self.resolver.add_object(name, "subnet", cidr)
                                except ValueError:
                                    self.resolver.add_object(name, "subnet", parts[1])
                        elif sub.lower().startswith("host "):
                            parts = sub.split()
                            if len(parts) >= 2:
                                self.resolver.add_object(name, "host", parts[1])
                        elif sub.lower().startswith("range "):
                            parts = sub.split()
                            if len(parts) >= 3:
                                self.resolver.add_object(
                                    name, "range", f"{parts[1]}-{parts[2]}"
                                )
                        elif sub.lower().startswith("fqdn "):
                            parts = sub.split()
                            fqdn_val = parts[-1] if len(parts) >= 2 else sub
                            self.resolver.add_object(name, "fqdn", fqdn_val)
                        elif not sub[0] == " " and not sub.startswith("nat"):
                            break
                        i += 1
                    continue

                # object service <name>
                m = re.match(r"^object service\s+(\S+)", line)
                if m:
                    name = m.group(1)
                    i += 1
                    while i < len(self.lines):
                        sub = self.lines[i].strip()
                        if not sub or sub.startswith("!"):
                            break
                        m2 = re.match(
                            r"service\s+(tcp|udp)(?:\s+(source|destination)\s+(\S+)(?:\s+(\S+))?)?",
                            sub, re.IGNORECASE
                        )
                        if m2:
                            # best-effort: grab destination port
                            # service tcp destination eq 80
                            srv_line = sub.lower()
                            pm = re.search(r"(eq|range)\s+(\d+)(?:\s+(\d+))?", srv_line)
                            if pm:
                                p1 = int(pm.group(2))
                                p2 = int(pm.group(3)) if pm.group(3) else p1
                                self.resolver.add_object(name, "service", (p1, p2))
                        elif not sub[0] == " ":
                            break
                        i += 1
                    continue

                i += 1

        except Exception as e:
            self._error(0, f"_parse_objects failed: {e}")

    def _parse_object_groups(self) -> None:
        """Parse object-group blocks into the resolver."""
        try:
            i = 0
            while i < len(self.lines):
                line = self.lines[i].strip()

                # object-group network <name>
                m = re.match(r"^object-group network\s+(\S+)", line)
                if m:
                    name = m.group(1)
                    members = []
                    i += 1
                    while i < len(self.lines):
                        sub = self.lines[i].strip()
                        if not sub or sub.startswith("!"):
                            break
                        if sub.lower().startswith("network-object host "):
                            parts = sub.split()
                            members.append(f"host {parts[2]}")
                        elif sub.lower().startswith("network-object object "):
                            parts = sub.split()
                            members.append(parts[2])
                        elif sub.lower().startswith("network-object "):
                            parts = sub.split()
                            if len(parts) >= 3:
                                members.append(f"{parts[1]} {parts[2]}")
                        elif sub.lower().startswith("group-object "):
                            parts = sub.split()
                            members.append(parts[1])
                        elif not sub[0] == " ":
                            break
                        i += 1
                    self.resolver.add_group(name, members)
                    continue

                # object-group service <name> [tcp|udp]
                m = re.match(r"^object-group service\s+(\S+)", line)
                if m:
                    name = m.group(1)
                    members = []
                    i += 1
                    while i < len(self.lines):
                        sub = self.lines[i].strip()
                        if not sub or sub.startswith("!"):
                            break
                        if sub.lower().startswith("port-object "):
                            members.append(sub[len("port-object "):])
                        elif sub.lower().startswith("service-object "):
                            members.append(sub[len("service-object "):])
                        elif sub.lower().startswith("group-object "):
                            members.append(sub.split()[1])
                        elif not sub[0] == " ":
                            break
                        i += 1
                    self.resolver.add_group(name, members)
                    continue

                # object-group protocol <name>
                m = re.match(r"^object-group protocol\s+(\S+)", line)
                if m:
                    name = m.group(1)
                    members = []
                    i += 1
                    while i < len(self.lines):
                        sub = self.lines[i].strip()
                        if not sub or sub.startswith("!"):
                            break
                        if sub.lower().startswith("protocol-object "):
                            members.append(sub.split()[1])
                        elif not sub[0] == " ":
                            break
                        i += 1
                    self.resolver.add_group(name, members)
                    continue

                i += 1

        except Exception as e:
            self._error(0, f"_parse_object_groups failed: {e}")

    def _parse_acl_address(self, tokens: List[str], idx: int) -> Tuple[List[str], int]:
        """
        Parse an address specification from tokens starting at idx.
        Returns (resolved_addresses, new_idx).
        """
        if idx >= len(tokens):
            return ["0.0.0.0/0"], idx

        t = tokens[idx].lower()

        if t in ("any", "any4", "any6"):
            return ["0.0.0.0/0"], idx + 1

        if t == "host" and idx + 1 < len(tokens):
            ip = tokens[idx + 1]
            resolved = self.resolver.resolve_address(f"host {ip}")
            return resolved, idx + 2

        if t == "object" and idx + 1 < len(tokens):
            resolved = self.resolver.resolve_address(tokens[idx + 1])
            return resolved, idx + 2

        if t == "object-group" and idx + 1 < len(tokens):
            resolved = self.resolver.resolve_address(tokens[idx + 1])
            return resolved, idx + 2

        # network mask
        if idx + 1 < len(tokens):
            net = tokens[idx]
            mask = tokens[idx + 1]
            if re.match(r"^\d+\.\d+\.\d+\.\d+$", net) and re.match(
                r"^\d+\.\d+\.\d+\.\d+$", mask
            ):
                resolved = self.resolver.resolve_address(f"{net} {mask}")
                return resolved, idx + 2

        # Bare CIDR
        if "/" in tokens[idx]:
            resolved = self.resolver.resolve_address(tokens[idx])
            return resolved, idx + 1

        return [tokens[idx]], idx + 1

    def _parse_access_lists(self) -> Dict[str, List[FirewallRule]]:
        """
        Parse access-list extended lines.
        Returns: {acl_name → [FirewallRule]}
        """
        acls: Dict[str, List[FirewallRule]] = {}
        pending_remark: Optional[str] = None

        try:
            for line_num, line in enumerate(self.lines, start=1):
                stripped = line.strip()

                # Remark — attach to next rule
                m = re.match(r"^access-list\s+(\S+)\s+remark\s+(.*)", stripped, re.IGNORECASE)
                if m:
                    pending_remark = m.group(2).strip()
                    continue

                # Extended ACL
                m = re.match(
                    r"^access-list\s+(\S+)\s+extended\s+(permit|deny)\s+(.*)",
                    stripped, re.IGNORECASE
                )
                if not m:
                    continue

                acl_name = m.group(1)
                action = m.group(2).lower()
                rest = m.group(3)
                tokens = rest.split()
                idx = 0

                # Protocol
                protocol = None
                if idx < len(tokens):
                    proto = tokens[idx].lower()
                    if proto in ("tcp", "udp", "icmp", "ip", "tcp-udp",
                                 "object-group", "object"):
                        if proto in ("object-group", "object"):
                            idx += 2  # skip the group name
                            protocol = "ip"
                        else:
                            protocol = proto
                            idx += 1
                    else:
                        protocol = proto
                        idx += 1

                # Source address
                src_addresses, idx = self._parse_acl_address(tokens, idx)

                # Source port (for tcp/udp)
                src_ports = None
                if idx < len(tokens) and tokens[idx].lower() in (
                    "eq", "range", "lt", "gt", "neq"
                ):
                    src_ports, idx = _parse_port_arg(tokens, idx)

                # Destination address
                dst_addresses, idx = self._parse_acl_address(tokens, idx)

                # Destination port
                dst_ports = None
                if idx < len(tokens) and tokens[idx].lower() in (
                    "eq", "range", "lt", "gt", "neq"
                ):
                    dst_ports, idx = _parse_port_arg(tokens, idx)
                elif idx < len(tokens) and tokens[idx].lower() in (
                    "object-group", "object"
                ):
                    # Service object-group reference
                    if idx + 1 < len(tokens):
                        group_ports = self.resolver.resolve_ports(tokens[idx + 1])
                        if group_ports:
                            dst_ports = group_ports
                        idx += 2

                # Logging
                has_log = "log" in [t.lower() for t in tokens[idx:]]

                rule_id = f"{acl_name}:{line_num}"
                rule = FirewallRule(
                    rule_id=rule_id,
                    rule_name=acl_name,
                    enabled=True,
                    action=action,
                    protocol=protocol,
                    src_zone=None,
                    dst_zone=None,
                    src_addresses=src_addresses,
                    dst_addresses=dst_addresses,
                    src_ports=src_ports,
                    dst_ports=dst_ports,
                    logging=has_log,
                    log_level=None,
                    line_number=line_num,
                    raw_lines=[line.rstrip()],
                    nat=None,
                    comments=pending_remark,
                    vendor="cisco_asa",
                    interface_binding=None,
                )
                pending_remark = None

                if acl_name not in acls:
                    acls[acl_name] = []
                acls[acl_name].append(rule)

        except Exception as e:
            self._error(0, f"_parse_access_lists failed: {e}")

        return acls

    def _parse_access_groups(self) -> dict:
        """
        Parse access-group bindings.
        Returns: {acl_name → [(nameif, direction)]}
        """
        bindings: dict = {}
        try:
            for line in self.lines:
                m = re.match(
                    r"^access-group\s+(\S+)\s+(in|out)\s+interface\s+(\S+)",
                    line.strip(), re.IGNORECASE
                )
                if m:
                    acl_name, direction, nameif = m.group(1), m.group(2), m.group(3)
                    bindings.setdefault(acl_name, []).append((nameif, direction.lower()))
        except Exception as e:
            self._error(0, f"_parse_access_groups failed: {e}")
        return bindings

    def _parse_nat(self) -> List[dict]:
        """Parse NAT rules."""
        nat_rules = []
        try:
            for line_num, line in enumerate(self.lines, start=1):
                stripped = line.strip()
                m = re.match(
                    r"^nat\s+\(([^,]+),([^)]+)\)\s+(source|after-auto)?\s*(.*)$",
                    stripped, re.IGNORECASE
                )
                if m:
                    nat_rules.append({
                        "type": "nat",
                        "real_iface": m.group(1).strip(),
                        "mapped_iface": m.group(2).strip(),
                        "mode": m.group(3) or "source",
                        "config": m.group(4).strip(),
                        "line": line_num,
                    })
                    continue

                m = re.match(
                    r"^static\s+\((\S+),(\S+)\)\s+(\S+)\s+(\S+)",
                    stripped, re.IGNORECASE
                )
                if m:
                    nat_rules.append({
                        "type": "static",
                        "real_iface": m.group(1),
                        "mapped_iface": m.group(2),
                        "mapped_ip": m.group(3),
                        "real_ip": m.group(4),
                        "line": line_num,
                    })
        except Exception as e:
            self._error(0, f"_parse_nat failed: {e}")
        return nat_rules

    def _parse_routes(self) -> List[dict]:
        """Parse static route entries."""
        routes = []
        try:
            for line_num, line in enumerate(self.lines, start=1):
                m = re.match(
                    r"^route\s+(\S+)\s+([\d.]+)\s+([\d.]+)\s+([\d.]+)",
                    line.strip(), re.IGNORECASE
                )
                if m:
                    routes.append({
                        "interface": m.group(1),
                        "network": m.group(2),
                        "mask": m.group(3),
                        "gateway": m.group(4),
                        "line": line_num,
                    })
        except Exception as e:
            self._error(0, f"_parse_routes failed: {e}")
        return routes

    def _parse_management_access(self) -> List[dict]:
        """
        Parse management access rules (http, ssh, telnet).
        Returns: [{proto, network, mask, interface}]
        """
        mgmt_access = []
        try:
            for line in self.lines:
                m = re.match(
                    r"^(http|ssh|telnet)\s+([\d.]+)\s+([\d.]+)\s+(\S+)",
                    line.strip(), re.IGNORECASE
                )
                if m:
                    mgmt_access.append({
                        "proto": m.group(1).lower(),
                        "network": m.group(2),
                        "mask": m.group(3),
                        "interface": m.group(4),
                    })
        except Exception as e:
            self._error(0, f"_parse_management_access failed: {e}")
        return mgmt_access

    def parse(self) -> ParseResult:
        """Full parse pipeline — returns ParseResult."""
        hostname = None
        version = None
        interfaces = {}
        nat_rules = []
        routes = []
        mgmt_access = []
        all_rules: List[FirewallRule] = []

        try:
            hostname = self._parse_hostname()
        except Exception as e:
            self._error(0, f"_parse_hostname: {e}")

        try:
            version = self._parse_version()
        except Exception as e:
            self._error(0, f"_parse_version: {e}")

        try:
            interfaces = self._parse_interfaces()
        except Exception as e:
            self._error(0, f"_parse_interfaces: {e}")

        try:
            self._parse_objects()
        except Exception as e:
            self._error(0, f"_parse_objects: {e}")

        try:
            self._parse_object_groups()
        except Exception as e:
            self._error(0, f"_parse_object_groups: {e}")

        acls = {}
        try:
            acls = self._parse_access_lists()
        except Exception as e:
            self._error(0, f"_parse_access_lists: {e}")

        bindings = {}
        try:
            bindings = self._parse_access_groups()
        except Exception as e:
            self._error(0, f"_parse_access_groups: {e}")

        try:
            nat_rules = self._parse_nat()
        except Exception as e:
            self._error(0, f"_parse_nat: {e}")

        try:
            routes = self._parse_routes()
        except Exception as e:
            self._error(0, f"_parse_routes: {e}")

        try:
            mgmt_access = self._parse_management_access()
        except Exception as e:
            self._error(0, f"_parse_management_access: {e}")

        # Sort interfaces by security-level
        sorted_ifaces = sorted(
            interfaces.items(),
            key=lambda x: x[1].get("security_level", 50),
        )

        # Bind ACLs to interfaces and assign zones
        for acl_name, binding_list in bindings.items():
            if acl_name not in acls:
                continue
            for nameif, direction in binding_list:
                iface_info = interfaces.get(nameif, {})
                for rule in acls[acl_name]:
                    rule.interface_binding = acl_name
                    if direction == "in":
                        # Traffic arriving on this interface
                        rule.src_zone = nameif
                        # Find the "other" zone by highest security-level not equal to src
                        other_zones = [
                            n for n, info in sorted_ifaces
                            if n != nameif
                        ]
                        if other_zones:
                            rule.dst_zone = other_zones[-1]  # highest security
                    else:  # out
                        rule.dst_zone = nameif
                        other_zones = [
                            n for n, info in sorted_ifaces
                            if n != nameif
                        ]
                        if other_zones:
                            rule.src_zone = other_zones[0]  # lowest security

        # Flatten all rules
        for acl_rules in acls.values():
            all_rules.extend(acl_rules)

        return ParseResult(
            vendor="cisco_asa",
            filename=self.filename,
            hostname=hostname,
            version=version,
            rules=all_rules,
            metadata={
                "interfaces": interfaces,
                "zones": list(interfaces.keys()),
                "objects": self.resolver.objects,
                "nat_rules": nat_rules,
                "routes": routes,
                "management_access": mgmt_access,
                "acls": {k: len(v) for k, v in acls.items()},
            },
            parse_errors=self.parse_errors,
            parse_warnings=self.parse_warnings,
        )


VENDOR_PARSERS["cisco_asa"] = CiscoAsaParser
