"""
Bastion engine/parsers/sangfor.py — Sangfor NGFW XML/JSON parser.
"""
import json
import xml.etree.ElementTree as ET
from typing import List

from engine.models import FirewallRule, ParseResult
from engine.parsers.base import AbstractParser, VENDOR_PARSERS


class SangforParser(AbstractParser):

    def parse(self) -> ParseResult:
        try:
            stripped = self.config_text.strip()
            if stripped.startswith("{") or stripped.startswith("["):
                return self._parse_json()
            else:
                return self._parse_xml()
        except Exception as e:
            self._error(0, f"Sangfor parse failed: {e}")
            return ParseResult(
                vendor="sangfor", filename=self.filename,
                hostname=None, version=None, rules=[],
                metadata={}, parse_errors=self.parse_errors,
                parse_warnings=self.parse_warnings,
            )

    def _parse_xml(self) -> ParseResult:
        rules = []

        try:
            root = ET.fromstring(self.config_text)

            idx = 0
            for policy in root.findall(".//Policy") + root.findall(".//policy"):
                idx += 1
                name = (policy.get("Name") or policy.get("name") or
                        f"sangfor-{idx}")
                src_zone = (policy.get("SrcZone") or policy.get("src-zone") or
                            policy.get("srczone") or "")
                dst_zone = (policy.get("DstZone") or policy.get("dst-zone") or
                            policy.get("dstzone") or "")
                action_raw = (policy.get("Action") or policy.get("action") or
                              "deny").lower()
                action = "permit" if action_raw in (
                    "permit", "allow", "accept"
                ) else "deny"
                enabled_raw = (policy.get("Enabled") or
                               policy.get("enabled") or "true").lower()
                enabled = enabled_raw in ("true", "1", "yes", "enable")
                log = (policy.get("Log") or policy.get("log") or
                       "false").lower() in ("true", "1", "yes", "enable")

                src_addr_el = policy.find(".//SrcAddress") or policy.find(".//src-addr")
                dst_addr_el = policy.find(".//DstAddress") or policy.find(".//dst-addr")

                src_ref = src_addr_el.text if src_addr_el is not None else "any"
                dst_ref = dst_addr_el.text if dst_addr_el is not None else "any"

                src_addresses = self.resolver.resolve_address(
                    "0.0.0.0/0" if (src_ref or "any").lower() == "any" else src_ref
                )
                dst_addresses = self.resolver.resolve_address(
                    "0.0.0.0/0" if (dst_ref or "any").lower() == "any" else dst_ref
                )

                rules.append(FirewallRule(
                    rule_id=f"sangfor-{idx}",
                    rule_name=name,
                    enabled=enabled,
                    action=action,
                    protocol="ip",
                    src_zone=src_zone or None,
                    dst_zone=dst_zone or None,
                    src_addresses=src_addresses,
                    dst_addresses=dst_addresses,
                    src_ports=None,
                    dst_ports=None,
                    logging=log,
                    log_level=None,
                    line_number=idx,
                    raw_lines=[name],
                    nat=None,
                    comments=None,
                    vendor="sangfor",
                    interface_binding=None,
                ))

        except Exception as e:
            self._error(0, f"_parse_xml failed: {e}")

        return ParseResult(
            vendor="sangfor", filename=self.filename,
            hostname=None, version=None, rules=rules,
            metadata={
                "interfaces": {}, "zones": [],
                "objects": self.resolver.objects,
                "nat_rules": [], "routes": [], "management_access": [],
            },
            parse_errors=self.parse_errors,
            parse_warnings=self.parse_warnings,
        )

    def _parse_json(self) -> ParseResult:
        rules = []

        try:
            data = json.loads(self.config_text)
            policies = data.get("policies", data.get("rules",
                      data.get("policy", [])))
            if isinstance(policies, dict):
                policies = policies.get("items", [])

            for idx, rule in enumerate(policies or [], start=1):
                if not isinstance(rule, dict):
                    continue

                name = rule.get("name", f"sangfor-{idx}")
                action_raw = str(rule.get("action", "deny")).lower()
                action = "permit" if action_raw in (
                    "permit", "allow", "accept"
                ) else "deny"
                enabled = rule.get("enabled", True)
                log = rule.get("log", False)

                src_zone = rule.get("src_zone", rule.get("srcZone", ""))
                dst_zone = rule.get("dst_zone", rule.get("dstZone", ""))
                src_addr = rule.get("src_addr", rule.get("srcAddr", "any"))
                dst_addr = rule.get("dst_addr", rule.get("dstAddr", "any"))

                src_addresses = self.resolver.resolve_address(
                    "0.0.0.0/0" if str(src_addr).lower() == "any" else src_addr
                )
                dst_addresses = self.resolver.resolve_address(
                    "0.0.0.0/0" if str(dst_addr).lower() == "any" else dst_addr
                )

                rules.append(FirewallRule(
                    rule_id=f"sangfor-json-{idx}",
                    rule_name=name,
                    enabled=enabled,
                    action=action,
                    protocol="ip",
                    src_zone=src_zone or None,
                    dst_zone=dst_zone or None,
                    src_addresses=src_addresses,
                    dst_addresses=dst_addresses,
                    src_ports=None,
                    dst_ports=None,
                    logging=bool(log),
                    log_level=None,
                    line_number=idx,
                    raw_lines=[name],
                    nat=None,
                    comments=None,
                    vendor="sangfor",
                    interface_binding=None,
                ))

        except Exception as e:
            self._error(0, f"_parse_json failed: {e}")

        return ParseResult(
            vendor="sangfor", filename=self.filename,
            hostname=None, version=None, rules=rules,
            metadata={
                "interfaces": {}, "zones": [],
                "objects": self.resolver.objects,
                "nat_rules": [], "routes": [], "management_access": [],
            },
            parse_errors=self.parse_errors,
            parse_warnings=self.parse_warnings,
        )


VENDOR_PARSERS["sangfor"] = SangforParser
