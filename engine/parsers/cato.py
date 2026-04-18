"""
Bastion engine/parsers/cato.py — Cato Networks SD-WAN/SASE JSON policy parser.
"""
import json
from typing import List

from engine.models import FirewallRule, ParseResult
from engine.parsers.base import AbstractParser, VENDOR_PARSERS


class CatoParser(AbstractParser):

    def parse(self) -> ParseResult:
        rules = []

        try:
            data = json.loads(self.config_text)

            # Try different top-level keys
            rule_lists = []
            for key in ("wanFirewall", "internetFirewall", "networkRules",
                        "catoNetworks", "rules"):
                if key in data:
                    val = data[key]
                    if isinstance(val, list):
                        rule_lists.append(val)
                    elif isinstance(val, dict):
                        for subkey in ("rules", "items", "policies"):
                            if subkey in val and isinstance(val[subkey], list):
                                rule_lists.append(val[subkey])

            idx = 0
            for rule_list in rule_lists:
                for rule in rule_list:
                    if not isinstance(rule, dict):
                        continue
                    idx += 1

                    name = rule.get("name", f"cato-rule-{idx}")
                    enabled = rule.get("enabled", True)
                    action_raw = str(rule.get("action", "block")).lower()
                    action = "permit" if action_raw in (
                        "allow", "permit", "accept"
                    ) else "deny"
                    has_log = rule.get("track", False)

                    src_data = rule.get("src", {})
                    dst_data = rule.get("dst", {})

                    src_addresses = self._resolve_cato_addr(src_data)
                    dst_addresses = self._resolve_cato_addr(dst_data)

                    dst_ports = None
                    svc = rule.get("service", {})
                    if isinstance(svc, dict):
                        ports = svc.get("ports", [])
                        if ports:
                            dp = []
                            for p in ports:
                                try:
                                    dp.append((int(p), int(p)))
                                except (ValueError, TypeError):
                                    pass
                            if dp:
                                dst_ports = dp

                    rules.append(FirewallRule(
                        rule_id=f"cato-{idx}",
                        rule_name=name,
                        enabled=enabled,
                        action=action,
                        protocol="ip",
                        src_zone=None,
                        dst_zone=None,
                        src_addresses=src_addresses,
                        dst_addresses=dst_addresses,
                        src_ports=None,
                        dst_ports=dst_ports,
                        logging=bool(has_log),
                        log_level=None,
                        line_number=idx,
                        raw_lines=[name],
                        nat=None,
                        comments=None,
                        vendor="cato",
                        interface_binding=None,
                    ))

        except Exception as e:
            self._error(0, f"Cato parse failed: {e}")

        return ParseResult(
            vendor="cato",
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

    def _resolve_cato_addr(self, addr_data) -> List[str]:
        """Resolve Cato address specification to CIDRs."""
        if not addr_data:
            return ["0.0.0.0/0"]

        if isinstance(addr_data, str):
            if addr_data.upper() in ("ANY", "ALL"):
                return ["0.0.0.0/0"]
            return self.resolver.resolve_address(addr_data)

        if isinstance(addr_data, dict):
            addr_type = addr_data.get("type", "").lower()
            val = addr_data.get("value", addr_data.get("ip", ""))

            if addr_type in ("any", "all") or str(val).upper() in ("ANY", "ALL"):
                return ["0.0.0.0/0"]
            if val:
                return self.resolver.resolve_address(str(val))

        if isinstance(addr_data, list):
            result = []
            for item in addr_data:
                result.extend(self._resolve_cato_addr(item))
            return result or ["0.0.0.0/0"]

        return ["0.0.0.0/0"]


VENDOR_PARSERS["cato"] = CatoParser
