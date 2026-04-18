"""
Bastion engine/parsers/juniper_srx.py — Juniper SRX parser.
Supports set-command and hierarchical formats.
"""
import re
from typing import Dict, List, Optional

from engine.models import FirewallRule, ParseResult
from engine.parsers.base import AbstractParser, VENDOR_PARSERS

_JUNOS_APP_MAP = {
    "junos-http": [(80, 80)],
    "junos-https": [(443, 443)],
    "junos-ssh": [(22, 22)],
    "junos-ftp": [(21, 21)],
    "junos-telnet": [(23, 23)],
    "junos-smtp": [(25, 25)],
    "junos-dns": [(53, 53)],
    "junos-snmp": [(161, 161)],
    "junos-bgp": [(179, 179)],
    "junos-rdp": [(3389, 3389)],
}


class JuniperSrxParser(AbstractParser):

    def parse(self) -> ParseResult:
        try:
            # Detect format
            set_lines = [l for l in self.lines if l.strip().startswith("set ")]
            if len(set_lines) > 5:
                return self._parse_set_commands()
            else:
                return self._parse_hierarchical()
        except Exception as e:
            self._error(0, f"Juniper SRX parse failed: {e}")
            return ParseResult(
                vendor="juniper_srx", filename=self.filename,
                hostname=None, version=None, rules=[],
                metadata={}, parse_errors=self.parse_errors,
                parse_warnings=self.parse_warnings,
            )

    def _parse_set_commands(self) -> ParseResult:
        hostname = None
        zones: Dict[str, list] = {}
        address_books: Dict[str, dict] = {}
        rule_map: Dict[str, dict] = {}

        try:
            for line_num, line in enumerate(self.lines, start=1):
                stripped = line.strip()

                # Hostname
                m = re.match(r"^set system host-name\s+(\S+)", stripped, re.I)
                if m:
                    hostname = m.group(1)

                # Zone interfaces
                m = re.match(
                    r"^set security zones security-zone\s+(\S+)\s+interfaces\s+(\S+)",
                    stripped, re.I
                )
                if m:
                    zones.setdefault(m.group(1), []).append(m.group(2))

                # Address book
                m = re.match(
                    r"^set security zones security-zone\s+\S+\s+address-book\s+address\s+(\S+)\s+(\S+)",
                    stripped, re.I
                )
                if m:
                    self.resolver.add_object(m.group(1), "subnet", m.group(2))

                # Policies: match
                m = re.match(
                    r"^set security policies from-zone\s+(\S+)\s+to-zone\s+(\S+)\s+policy\s+(\S+)\s+match\s+(.*)",
                    stripped, re.I
                )
                if m:
                    src_zone, dst_zone, pname, match_rest = (
                        m.group(1), m.group(2), m.group(3), m.group(4)
                    )
                    key = f"{src_zone}::{dst_zone}::{pname}"
                    if key not in rule_map:
                        rule_map[key] = {
                            "src_zone": src_zone, "dst_zone": dst_zone,
                            "name": pname, "line": line_num,
                            "source": [], "destination": [],
                            "application": [], "action": "deny",
                            "log": False,
                        }
                    # match source-address / destination-address / application
                    mp = re.match(r"source-address\s+(.+)", match_rest, re.I)
                    if mp:
                        rule_map[key]["source"].append(mp.group(1).strip())
                    mp = re.match(r"destination-address\s+(.+)", match_rest, re.I)
                    if mp:
                        rule_map[key]["destination"].append(mp.group(1).strip())
                    mp = re.match(r"application\s+(.+)", match_rest, re.I)
                    if mp:
                        rule_map[key]["application"].append(mp.group(1).strip())

                # Policies: then
                m = re.match(
                    r"^set security policies from-zone\s+(\S+)\s+to-zone\s+(\S+)\s+policy\s+(\S+)\s+then\s+(.*)",
                    stripped, re.I
                )
                if m:
                    src_zone, dst_zone, pname, then_rest = (
                        m.group(1), m.group(2), m.group(3), m.group(4)
                    )
                    key = f"{src_zone}::{dst_zone}::{pname}"
                    if key not in rule_map:
                        rule_map[key] = {
                            "src_zone": src_zone, "dst_zone": dst_zone,
                            "name": pname, "line": line_num,
                            "source": ["any"], "destination": ["any"],
                            "application": [], "action": "deny",
                            "log": False,
                        }
                    action_raw = then_rest.strip().lower().split()[0]
                    rule_map[key]["action"] = (
                        "permit" if action_raw == "permit" else "deny"
                    )
                    if "log" in then_rest.lower():
                        rule_map[key]["log"] = True

        except Exception as e:
            self._error(0, f"_parse_set_commands failed: {e}")

        rules = self._build_rules_from_map(rule_map)

        iface_dict = {}
        for zone_name, ifaces in zones.items():
            for iface in ifaces:
                iface_dict[iface] = {"zone": zone_name}

        return ParseResult(
            vendor="juniper_srx", filename=self.filename,
            hostname=hostname, version=None, rules=rules,
            metadata={
                "interfaces": iface_dict,
                "zones": list(zones.keys()),
                "objects": self.resolver.objects,
                "nat_rules": [], "routes": [], "management_access": [],
            },
            parse_errors=self.parse_errors,
            parse_warnings=self.parse_warnings,
        )

    def _parse_hierarchical(self) -> ParseResult:
        """Parse hierarchical curly-brace Junos format."""
        rules = []
        hostname = None
        zones_list = []

        try:
            # Hostname
            m = re.search(r"host-name\s+(\S+);", self.config_text, re.I)
            if m:
                hostname = m.group(1).rstrip(";")

            # Zones from security stanza
            zone_matches = re.findall(
                r"security-zone\s+(\S+)\s*\{", self.config_text, re.I
            )
            zones_list = zone_matches

            # Policies — simple extraction
            policy_blocks = re.findall(
                r"from-zone\s+(\S+)\s+to-zone\s+(\S+)\s*\{[^}]*policy\s+(\S+)\s*\{([^}]+)\}",
                self.config_text, re.DOTALL | re.I
            )
            for idx, (src_z, dst_z, pname, body) in enumerate(policy_blocks):
                action_m = re.search(r"(permit|deny|reject)", body, re.I)
                action_raw = action_m.group(1).lower() if action_m else "deny"
                action = "permit" if action_raw == "permit" else "deny"
                has_log = bool(re.search(r"syslog", body, re.I))

                rules.append(FirewallRule(
                    rule_id=f"junos-{idx}",
                    rule_name=pname,
                    enabled=True,
                    action=action,
                    protocol="ip",
                    src_zone=src_z,
                    dst_zone=dst_z,
                    src_addresses=["0.0.0.0/0"],
                    dst_addresses=["0.0.0.0/0"],
                    src_ports=None,
                    dst_ports=None,
                    logging=has_log,
                    log_level=None,
                    line_number=idx + 1,
                    raw_lines=[pname],
                    nat=None,
                    comments=None,
                    vendor="juniper_srx",
                    interface_binding=None,
                ))
        except Exception as e:
            self._error(0, f"_parse_hierarchical failed: {e}")

        return ParseResult(
            vendor="juniper_srx", filename=self.filename,
            hostname=hostname, version=None, rules=rules,
            metadata={
                "interfaces": {},
                "zones": zones_list,
                "objects": self.resolver.objects,
                "nat_rules": [], "routes": [], "management_access": [],
            },
            parse_errors=self.parse_errors,
            parse_warnings=self.parse_warnings,
        )

    def _build_rules_from_map(self, rule_map: dict) -> List[FirewallRule]:
        rules = []
        for idx, (key, rdata) in enumerate(rule_map.items()):
            try:
                src_raw = rdata.get("source", ["any"])
                dst_raw = rdata.get("destination", ["any"])

                src_addresses = []
                for s in src_raw:
                    src_addresses.extend(
                        self.resolver.resolve_address(s if s != "any" else "0.0.0.0/0")
                    )
                dst_addresses = []
                for d in dst_raw:
                    dst_addresses.extend(
                        self.resolver.resolve_address(d if d != "any" else "0.0.0.0/0")
                    )

                if not src_addresses:
                    src_addresses = ["0.0.0.0/0"]
                if not dst_addresses:
                    dst_addresses = ["0.0.0.0/0"]

                # Ports from applications
                dst_ports = None
                apps = rdata.get("application", [])
                if apps and apps != ["any"]:
                    dp = []
                    for app in apps:
                        ports = _JUNOS_APP_MAP.get(app.lower())
                        if ports:
                            dp.extend(ports)
                    if dp:
                        dst_ports = dp

                rules.append(FirewallRule(
                    rule_id=f"junos-{idx}-{rdata['name']}",
                    rule_name=rdata.get("name", key),
                    enabled=True,
                    action=rdata.get("action", "deny"),
                    protocol="ip",
                    src_zone=rdata.get("src_zone"),
                    dst_zone=rdata.get("dst_zone"),
                    src_addresses=src_addresses,
                    dst_addresses=dst_addresses,
                    src_ports=None,
                    dst_ports=dst_ports,
                    logging=rdata.get("log", False),
                    log_level=None,
                    line_number=rdata.get("line", idx + 1),
                    raw_lines=[rdata.get("name", key)],
                    nat=None,
                    comments=None,
                    vendor="juniper_srx",
                    interface_binding=None,
                ))
            except Exception as e:
                self._warn(0, f"Failed to build Junos rule {key}: {e}")
        return rules


VENDOR_PARSERS["juniper_srx"] = JuniperSrxParser
