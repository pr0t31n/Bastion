"""
Bastion engine/parsers/palo_alto.py — Palo Alto Networks parser.
Supports both set-command format and XML format.
"""
import re
import xml.etree.ElementTree as ET
from typing import Dict, List, Optional, Tuple

from engine.models import FirewallRule, ParseResult
from engine.parsers.base import AbstractParser, VENDOR_PARSERS

_APP_PORT_MAP = {
    "http": [(80, 80)], "https": [(443, 443)], "ssh": [(22, 22)],
    "rdp": [(3389, 3389)], "ftp": [(21, 21)], "telnet": [(23, 23)],
    "smtp": [(25, 25)], "dns": [(53, 53)], "snmp": [(161, 161)],
    "ntp": [(123, 123)], "ldap": [(389, 389)], "smb": [(445, 445)],
    "mysql": [(3306, 3306)], "mssql": [(1433, 1433)], "redis": [(6379, 6379)],
    "vnc": [(5900, 5900)],
}


class PaloAltoParser(AbstractParser):

    def parse(self) -> ParseResult:
        try:
            if self.config_text.strip().startswith("<"):
                return self._parse_xml()
            else:
                return self._parse_set_commands()
        except Exception as e:
            self._error(0, f"PaloAlto parse failed: {e}")
            return ParseResult(
                vendor="palo_alto", filename=self.filename,
                hostname=None, version=None, rules=[],
                metadata={}, parse_errors=self.parse_errors,
                parse_warnings=self.parse_warnings,
            )

    def _parse_set_commands(self) -> ParseResult:
        hostname = None
        zones = {}
        rule_map: Dict[str, dict] = {}

        try:
            for line_num, line in enumerate(self.lines, start=1):
                stripped = line.strip()

                # Hostname
                m = re.match(r"^set deviceconfig system hostname\s+(\S+)", stripped, re.I)
                if m:
                    hostname = m.group(1)

                # Zones
                m = re.match(r"^set zone\s+(\S+)", stripped, re.I)
                if m:
                    zones[m.group(1)] = {}

                # Addresses
                m = re.match(r"^set address\s+(\S+)\s+ip-netmask\s+(\S+)", stripped, re.I)
                if m:
                    self.resolver.add_object(m.group(1), "subnet", m.group(2))

                # Address groups
                m = re.match(r"^set address-group\s+(\S+)\s+static\s+\[(.+)\]", stripped, re.I)
                if m:
                    members = m.group(2).split()
                    self.resolver.add_group(m.group(1), members)

                # Security rules
                m = re.match(
                    r"^set security rules\s+(\S+)\s+(from|to|source|destination|application|service|action|log-start|log-end|disabled)\s+(.*)",
                    stripped, re.I
                )
                if m:
                    rname = m.group(1)
                    field = m.group(2).lower()
                    val = m.group(3).strip().strip("[]")
                    if rname not in rule_map:
                        rule_map[rname] = {
                            "line": line_num, "raw": [],
                            "from": [], "to": [], "source": [],
                            "destination": [], "application": [],
                            "service": [], "action": "permit",
                            "log": False, "disabled": False,
                        }
                    rule_map[rname]["raw"].append(line.rstrip())

                    if field in ("from", "to", "source", "destination",
                                 "application", "service"):
                        rule_map[rname][field] = val.split()
                    elif field == "action":
                        act = val.lower()
                        rule_map[rname]["action"] = (
                            "permit" if act == "allow" else "deny"
                        )
                    elif field in ("log-start", "log-end"):
                        if val.lower() == "yes":
                            rule_map[rname]["log"] = True
                    elif field == "disabled":
                        rule_map[rname]["disabled"] = val.lower() == "yes"

        except Exception as e:
            self._error(0, f"_parse_set_commands failed: {e}")

        rules = self._build_rules_from_map(rule_map)

        return ParseResult(
            vendor="palo_alto", filename=self.filename,
            hostname=hostname, version=None, rules=rules,
            metadata={"interfaces": zones, "zones": list(zones.keys()),
                      "objects": self.resolver.objects,
                      "nat_rules": [], "routes": [], "management_access": []},
            parse_errors=self.parse_errors,
            parse_warnings=self.parse_warnings,
        )

    def _parse_xml(self) -> ParseResult:
        hostname = None
        rule_map: Dict[str, dict] = {}

        try:
            root = ET.fromstring(self.config_text)

            # Hostname
            hn = root.find(".//devices/entry/deviceconfig/system/hostname")
            if hn is not None:
                hostname = hn.text

            # Address objects
            for addr in root.findall(".//address/entry"):
                name = addr.get("name", "")
                ip_netmask = addr.find("ip-netmask")
                fqdn = addr.find("fqdn")
                if ip_netmask is not None and ip_netmask.text:
                    self.resolver.add_object(name, "subnet", ip_netmask.text)
                elif fqdn is not None and fqdn.text:
                    self.resolver.add_object(name, "fqdn", fqdn.text)

            # Address groups
            for grp in root.findall(".//address-group/entry"):
                name = grp.get("name", "")
                members = [m.text for m in grp.findall(".//member") if m.text]
                if members:
                    self.resolver.add_group(name, members)

            # Security rules
            for rule_entry in root.findall(".//rulebase/security/rules/entry"):
                rname = rule_entry.get("name", "")
                if not rname:
                    continue
                if rname not in rule_map:
                    rule_map[rname] = {
                        "line": 0, "raw": [rname],
                        "from": [], "to": [], "source": [],
                        "destination": [], "application": [],
                        "service": [], "action": "permit",
                        "log": False, "disabled": False,
                    }

                def _members(el_name):
                    return [
                        m.text for m in rule_entry.findall(f".//{el_name}/member")
                        if m.text
                    ]

                rule_map[rname]["from"] = _members("from")
                rule_map[rname]["to"] = _members("to")
                rule_map[rname]["source"] = _members("source")
                rule_map[rname]["destination"] = _members("destination")
                rule_map[rname]["application"] = _members("application")
                rule_map[rname]["service"] = _members("service")

                action_el = rule_entry.find("action")
                if action_el is not None and action_el.text:
                    act = action_el.text.lower()
                    rule_map[rname]["action"] = (
                        "permit" if act == "allow" else "deny"
                    )

                log_start = rule_entry.find("log-start")
                log_end = rule_entry.find("log-end")
                if (log_start is not None and log_start.text == "yes") or \
                   (log_end is not None and log_end.text == "yes"):
                    rule_map[rname]["log"] = True

                disabled = rule_entry.find("disabled")
                if disabled is not None and disabled.text == "yes":
                    rule_map[rname]["disabled"] = True

        except Exception as e:
            self._error(0, f"_parse_xml failed: {e}")

        rules = self._build_rules_from_map(rule_map)
        return ParseResult(
            vendor="palo_alto", filename=self.filename,
            hostname=hostname, version=None, rules=rules,
            metadata={"interfaces": {}, "zones": [],
                      "objects": self.resolver.objects,
                      "nat_rules": [], "routes": [], "management_access": []},
            parse_errors=self.parse_errors,
            parse_warnings=self.parse_warnings,
        )

    def _build_rules_from_map(
        self, rule_map: Dict[str, dict]
    ) -> List[FirewallRule]:
        rules = []
        for idx, (rname, rdata) in enumerate(rule_map.items()):
            try:
                src_zones = rdata.get("from", []) or ["any"]
                dst_zones = rdata.get("to", []) or ["any"]

                src_raw = rdata.get("source", ["any"])
                dst_raw = rdata.get("destination", ["any"])

                src_addresses = []
                for s in src_raw:
                    src_addresses.extend(self.resolver.resolve_address(s))

                dst_addresses = []
                for d in dst_raw:
                    dst_addresses.extend(self.resolver.resolve_address(d))

                if not src_addresses:
                    src_addresses = ["0.0.0.0/0"]
                if not dst_addresses:
                    dst_addresses = ["0.0.0.0/0"]

                # Ports from application
                dst_ports = None
                apps = rdata.get("application", [])
                if apps and apps != ["any"]:
                    dp = []
                    for app in apps:
                        ports = _APP_PORT_MAP.get(app.lower())
                        if ports:
                            dp.extend(ports)
                    if dp:
                        dst_ports = dp

                rules.append(FirewallRule(
                    rule_id=f"pa-{idx}-{rname}",
                    rule_name=rname,
                    enabled=not rdata.get("disabled", False),
                    action=rdata.get("action", "permit"),
                    protocol="ip",
                    src_zone=src_zones[0] if src_zones else None,
                    dst_zone=dst_zones[0] if dst_zones else None,
                    src_addresses=src_addresses,
                    dst_addresses=dst_addresses,
                    src_ports=None,
                    dst_ports=dst_ports,
                    logging=rdata.get("log", False),
                    log_level=None,
                    line_number=rdata.get("line", idx + 1),
                    raw_lines=rdata.get("raw", [rname]),
                    nat=None,
                    comments=None,
                    vendor="palo_alto",
                    interface_binding=None,
                ))
            except Exception as e:
                self._warn(0, f"Failed to build rule {rname}: {e}")
        return rules


VENDOR_PARSERS["palo_alto"] = PaloAltoParser
