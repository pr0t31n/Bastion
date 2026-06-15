"""
Bastion engine/parsers/cisco_ftd.py — Cisco FTD (Firepower Threat Defense) parser.

2026-06-11 review fix: previously detected (regex at base.py line 212:
r"NGFW Version|Cisco Firepower") but no parser module was loaded.

FTD configurations can be exported either as:
  * `show running-config` CLI text — looks very similar to ASA's running-
    config because FTD ships LINA (ASA dataplane) underneath. The CLI ACL
    syntax is identical.
  * FMC/FDM REST API JSON — different shape; this parser handles the CLI
    text format. JSON support will be added when FMC export shapes
    stabilise.

This parser subclasses CiscoAsaParser because the underlying ACL/object
syntax is preserved in FTD CLI exports.
"""
import json
import re
from typing import Optional

from engine.parsers.cisco_asa import CiscoAsaParser
from engine.parsers.base import VENDOR_PARSERS


class CiscoFtdParser(CiscoAsaParser):
    """Cisco FTD (Firepower) configuration parser.

    For now handles the LINA/CLI export which is ASA-compatible. JSON
    export from FMC/FDM will be added when those shapes are reliable.
    """

    VENDOR = "cisco_ftd"

    def _parse_hostname(self) -> Optional[str]:
        # FTD CLI: same `hostname <name>` as ASA
        return super()._parse_hostname()

    def _parse_version(self) -> Optional[str]:
        """FTD reports `Cisco Firepower Threat Defense for ... Version 7.2.4`."""
        try:
            for line in self.lines:
                m = re.match(r"^.*Firepower.*Version\s+([\d.()\w]+)",
                              line.strip(), re.IGNORECASE)
                if m: return m.group(1)
                m = re.match(r"^NGFW\s+Version\s+([\d.]+)",
                              line.strip(), re.IGNORECASE)
                if m: return m.group(1)
        except Exception as e:
            self._error(0, f"_parse_version failed: {e}")
        return None

    def parse(self):
        # If body is JSON (FMC export), try a thin JSON-mode parse first.
        body = "\n".join(self.lines).strip() if isinstance(self.lines, list) else (self.lines or "")
        if body.startswith("{") and body.endswith("}"):
            try:
                obj = json.loads(body)
                if isinstance(obj, dict) and (
                        "accessRules" in obj or "policyRules" in obj):
                    return self._parse_fmc_json(obj)
            except (json.JSONDecodeError, AttributeError):
                pass   # Fall through to CLI text parser
        result = super().parse()
        try:
            if hasattr(result, "vendor"):  result.vendor  = self.VENDOR
            if hasattr(result, "summary"): result.summary["vendor"] = self.VENDOR
        except Exception:
            pass
        return result

    def _parse_fmc_json(self, obj: dict):
        """Stub — full FMC REST JSON parsing pending v0.2.x. Emit a parse
        result that records every rule's source/dest/action/protocol at a
        coarse granularity so the AuditEngine can apply structural rules
        (default-deny, shadow-detection, etc.)."""
        from engine.models import FirewallRule, ParseResult
        rules = []
        for entry in (obj.get("accessRules") or obj.get("policyRules") or [])[:20000]:
            try:
                rules.append(FirewallRule(
                    line_no=0,
                    raw_text=json.dumps(entry, default=str)[:500],
                    action=(entry.get("action") or "permit").lower(),
                    protocol=str(entry.get("protocol", "ip")),
                    src_zone=str((entry.get("sourceZones") or [""])[0]),
                    dst_zone=str((entry.get("destinationZones") or [""])[0]),
                    src_addresses=entry.get("sourceNetworks", []) or ["any"],
                    dst_addresses=entry.get("destinationNetworks", []) or ["any"],
                    src_ports=[(0, 65535)],
                    dst_ports=[(0, 65535)],
                    enabled=bool(entry.get("enabled", True)),
                    log=bool(entry.get("logging", False)),
                    comment=entry.get("comment", "") or entry.get("name", ""),
                ))
            except Exception:
                continue
        result = ParseResult(
            vendor=self.VENDOR, hostname=(obj.get("hostname") or ""),
            version=(obj.get("version") or ""), rules=rules,
            objects={}, object_groups={}, nat_rules=[], interfaces=[],
            services={}, errors=[], warnings=[],
            summary={"vendor": self.VENDOR, "source": "fmc_json",
                      "rule_count": len(rules)},
        )
        return result


# Register
VENDOR_PARSERS["cisco_ftd"] = CiscoFtdParser
