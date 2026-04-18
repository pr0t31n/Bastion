"""
Bastion engine/parsers/cloudflare.py — Cloudflare Gateway JSON policy parser.
"""
import json
from typing import List, Optional, Tuple

from engine.models import FirewallRule, ParseResult
from engine.parsers.base import AbstractParser, VENDOR_PARSERS


class CloudflareParser(AbstractParser):

    def parse(self) -> ParseResult:
        rules = []

        try:
            data = json.loads(self.config_text)

            # Find rule lists under various key names
            rule_lists = []
            for key in ("gateway_rules", "network_policies", "rules",
                        "policies", "firewall_rules"):
                if key in data:
                    val = data[key]
                    if isinstance(val, list):
                        rule_lists.append(val)
                    elif isinstance(val, dict) and "result" in val:
                        rule_lists.append(val["result"])

            idx = 0
            for rule_list in rule_lists:
                for rule in rule_list:
                    if not isinstance(rule, dict):
                        continue
                    idx += 1

                    name = rule.get("name", f"cf-rule-{idx}")
                    enabled = rule.get("enabled", True)
                    action_raw = str(rule.get("action", "block")).lower()
                    action = "permit" if action_raw in (
                        "allow", "permit", "accept", "on"
                    ) else "deny"

                    # Extract conditions
                    conditions = rule.get("conditions", rule.get("traffic", []))
                    src_addresses, dst_addresses, dst_ports = (
                        self._parse_conditions(conditions)
                    )

                    # Logging
                    has_log = rule.get("log", bool(rule.get("logging", False)))

                    rules.append(FirewallRule(
                        rule_id=f"cf-{idx}",
                        rule_name=name,
                        enabled=enabled,
                        action=action,
                        protocol="ip",
                        src_zone=None,
                        dst_zone=None,
                        src_addresses=src_addresses,
                        dst_addresses=dst_addresses,
                        src_ports=None,
                        dst_ports=dst_ports or None,
                        logging=bool(has_log),
                        log_level=None,
                        line_number=idx,
                        raw_lines=[name],
                        nat=None,
                        comments=rule.get("description", None),
                        vendor="cloudflare",
                        interface_binding=None,
                    ))

        except Exception as e:
            self._error(0, f"Cloudflare parse failed: {e}")

        return ParseResult(
            vendor="cloudflare",
            filename=self.filename,
            hostname=None,
            version=None,
            rules=rules,
            metadata={
                "interfaces": {},
                "zones": [],
                "objects": self.resolver.objects,
                "nat_rules": [],
                "routes": [],
                "management_access": [],
            },
            parse_errors=self.parse_errors,
            parse_warnings=self.parse_warnings,
        )

    def _parse_conditions(self, conditions) -> Tuple[List[str], List[str], List[Tuple[int, int]]]:
        """Parse condition list into src/dst addresses and dst ports."""
        src_addresses = ["0.0.0.0/0"]
        dst_addresses = ["0.0.0.0/0"]
        dst_ports = []

        if not conditions:
            return src_addresses, dst_addresses, dst_ports

        if isinstance(conditions, dict):
            # Inline traffic object
            if "destination" in conditions:
                d = conditions["destination"]
                if isinstance(d, dict):
                    ip = d.get("ip", d.get("value", ""))
                    if ip:
                        dst_addresses = [ip if "/" in ip else f"{ip}/32"]
            return src_addresses, dst_addresses, dst_ports

        if isinstance(conditions, list):
            for cond in conditions:
                if not isinstance(cond, dict):
                    continue
                cond_type = cond.get("type", "").lower()
                val = cond.get("value", "")

                if cond_type == "traffic.destination.ip":
                    if val:
                        dst_addresses = [val if "/" in str(val) else f"{val}/32"]
                elif cond_type == "traffic.destination.port":
                    try:
                        p = int(val)
                        dst_ports.append((p, p))
                    except (ValueError, TypeError):
                        pass
                elif cond_type == "traffic.source.ip":
                    if val:
                        src_addresses = [val if "/" in str(val) else f"{val}/32"]
                elif cond_type == "traffic.protocol":
                    pass  # protocol info is informational

        return src_addresses, dst_addresses, dst_ports


VENDOR_PARSERS["cloudflare"] = CloudflareParser
