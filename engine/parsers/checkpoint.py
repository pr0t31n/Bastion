"""
Bastion engine/parsers/checkpoint.py — Check Point parser.
Supports dbedit format and JSON policy export.
"""
import json
import re
from typing import Dict, List, Optional

from engine.models import FirewallRule, ParseResult
from engine.parsers.base import AbstractParser, VENDOR_PARSERS


class CheckpointParser(AbstractParser):

    def parse(self) -> ParseResult:
        try:
            stripped = self.config_text.strip()
            if stripped.startswith("{"):
                return self._parse_json()
            else:
                return self._parse_dbedit()
        except Exception as e:
            self._error(0, f"CheckPoint parse failed: {e}")
            return ParseResult(
                vendor="checkpoint", filename=self.filename,
                hostname=None, version=None, rules=[],
                metadata={}, parse_errors=self.parse_errors,
                parse_warnings=self.parse_warnings,
            )

    def _parse_dbedit(self) -> ParseResult:
        """Parse dbedit / objects_5_0.C format."""
        rules = []
        interfaces = {}
        hostname = None

        try:
            # Parse objects
            i = 0
            while i < len(self.lines):
                line = self.lines[i].strip()

                # Object types
                if ":type (network-object)" in line or ":type (host-object)" in line:
                    # Look back a few lines for name
                    name = None
                    ipaddr = None
                    netmask = None
                    for j in range(max(0, i - 5), i + 10):
                        if j >= len(self.lines):
                            break
                        l = self.lines[j].strip()
                        m = re.match(r':Name\s+\((\S+)\)', l)
                        if m:
                            name = m.group(1)
                        m = re.match(r':ipaddr\s+\(([^)]+)\)', l)
                        if m:
                            ipaddr = m.group(1)
                        m = re.match(r':netmask\s+\(([^)]+)\)', l)
                        if m:
                            netmask = m.group(1)

                    if name:
                        if netmask and ipaddr:
                            self.resolver.add_object(name, "subnet",
                                                      f"{ipaddr}/{netmask}")
                        elif ipaddr:
                            self.resolver.add_object(name, "host", ipaddr)

                elif ":type (group)" in line:
                    name = None
                    members = []
                    for j in range(max(0, i - 2), i + 20):
                        if j >= len(self.lines):
                            break
                        l = self.lines[j].strip()
                        m = re.match(r':Name\s+\((\S+)\)', l)
                        if m:
                            name = m.group(1)
                        m = re.match(r'\s*:(\S+)\s+\(\)', l)
                        if m and name:
                            members.append(m.group(1))
                    if name:
                        self.resolver.add_group(name, members)

                i += 1

            # Parse rulebase — simplified
            in_rule = False
            rule_num = 0
            current_rule: dict = {}

            for line_num, line in enumerate(self.lines, start=1):
                stripped = line.strip()

                m = re.match(r':src\s+\((.+)\)', stripped)
                if m and in_rule:
                    current_rule["src"] = m.group(1).split()

                m = re.match(r':dst\s+\((.+)\)', stripped)
                if m and in_rule:
                    current_rule["dst"] = m.group(1).split()

                m = re.match(r':action\s+\((\S+)\)', stripped)
                if m and in_rule:
                    act = m.group(1).lower()
                    current_rule["action"] = "permit" if act == "accept" else "deny"

                m = re.match(r':track\s+\((\S+)\)', stripped)
                if m and in_rule:
                    current_rule["log"] = m.group(1).lower() in ("log", "long")

                if stripped.startswith("(rule"):
                    in_rule = True
                    rule_num += 1
                    current_rule = {
                        "src": ["any"], "dst": ["any"],
                        "action": "deny", "log": False,
                        "line": line_num,
                    }

                if stripped == ")" and in_rule:
                    # Build rule
                    src_addresses = []
                    for s in current_rule.get("src", ["any"]):
                        src_addresses.extend(self.resolver.resolve_address(s))
                    dst_addresses = []
                    for d in current_rule.get("dst", ["any"]):
                        dst_addresses.extend(self.resolver.resolve_address(d))

                    if not src_addresses:
                        src_addresses = ["0.0.0.0/0"]
                    if not dst_addresses:
                        dst_addresses = ["0.0.0.0/0"]

                    rules.append(FirewallRule(
                        rule_id=f"cp-rule-{rule_num}",
                        rule_name=f"Rule {rule_num}",
                        enabled=True,
                        action=current_rule.get("action", "deny"),
                        protocol="ip",
                        src_zone=None,
                        dst_zone=None,
                        src_addresses=src_addresses,
                        dst_addresses=dst_addresses,
                        src_ports=None,
                        dst_ports=None,
                        logging=current_rule.get("log", False),
                        log_level=None,
                        line_number=current_rule.get("line", rule_num),
                        raw_lines=[f"Rule {rule_num}"],
                        nat=None,
                        comments=None,
                        vendor="checkpoint",
                        interface_binding=None,
                    ))
                    in_rule = False
                    current_rule = {}

        except Exception as e:
            self._error(0, f"_parse_dbedit failed: {e}")

        return ParseResult(
            vendor="checkpoint", filename=self.filename,
            hostname=hostname, version=None, rules=rules,
            metadata={"interfaces": interfaces, "zones": [],
                      "objects": self.resolver.objects,
                      "nat_rules": [], "routes": [], "management_access": []},
            parse_errors=self.parse_errors,
            parse_warnings=self.parse_warnings,
        )

    def _parse_json(self) -> ParseResult:
        """Parse JSON policy export from SmartConsole."""
        rules = []
        hostname = None
        interfaces = {}

        try:
            data = json.loads(self.config_text)
            objects_dict = data.get("objects_dictionary", {})

            # Register objects
            for obj_name, obj_data in objects_dict.items():
                if isinstance(obj_data, dict):
                    if obj_data.get("type") == "network":
                        subnet = obj_data.get("subnet4", "")
                        mask = obj_data.get("mask-length4", "32")
                        if subnet:
                            self.resolver.add_object(
                                obj_name, "subnet", f"{subnet}/{mask}"
                            )
                    elif obj_data.get("type") == "host":
                        ip = obj_data.get("ipv4-address", "")
                        if ip:
                            self.resolver.add_object(obj_name, "host", ip)
                    elif obj_data.get("type") == "group":
                        members = obj_data.get("members", [])
                        self.resolver.add_group(obj_name, members)

            # Parse rulebase
            rulebase = data.get("rulebase", data.get("data", {}).get("rulebase", []))
            for section in (rulebase if isinstance(rulebase, list) else []):
                rule_list = section.get("rules", [section]) if isinstance(section, dict) else []
                for idx, rule in enumerate(rule_list):
                    if not isinstance(rule, dict):
                        continue

                    src_refs = rule.get("source", ["Any"])
                    dst_refs = rule.get("destination", ["Any"])
                    action_raw = rule.get("action", "Drop")
                    track = rule.get("track", {})

                    action = "permit" if str(action_raw).lower() in (
                        "accept", "allow"
                    ) else "deny"
                    has_log = isinstance(track, dict) and \
                              track.get("type", "").lower() in ("log", "extended")

                    src_addresses = []
                    for s in (src_refs if isinstance(src_refs, list) else [src_refs]):
                        src_addresses.extend(self.resolver.resolve_address(str(s)))
                    dst_addresses = []
                    for d in (dst_refs if isinstance(dst_refs, list) else [dst_refs]):
                        dst_addresses.extend(self.resolver.resolve_address(str(d)))

                    if not src_addresses:
                        src_addresses = ["0.0.0.0/0"]
                    if not dst_addresses:
                        dst_addresses = ["0.0.0.0/0"]

                    rules.append(FirewallRule(
                        rule_id=f"cp-json-{idx}",
                        rule_name=rule.get("name", f"Rule {idx}"),
                        enabled=rule.get("enabled", True),
                        action=action,
                        protocol="ip",
                        src_zone=None,
                        dst_zone=None,
                        src_addresses=src_addresses,
                        dst_addresses=dst_addresses,
                        src_ports=None,
                        dst_ports=None,
                        logging=has_log,
                        log_level=None,
                        line_number=idx + 1,
                        raw_lines=[rule.get("name", f"Rule {idx}")],
                        nat=None,
                        comments=rule.get("comments", None),
                        vendor="checkpoint",
                        interface_binding=None,
                    ))
        except Exception as e:
            self._error(0, f"_parse_json failed: {e}")

        return ParseResult(
            vendor="checkpoint", filename=self.filename,
            hostname=hostname, version=None, rules=rules,
            metadata={"interfaces": interfaces, "zones": [],
                      "objects": self.resolver.objects,
                      "nat_rules": [], "routes": [], "management_access": []},
            parse_errors=self.parse_errors,
            parse_warnings=self.parse_warnings,
        )


VENDOR_PARSERS["checkpoint"] = CheckpointParser
