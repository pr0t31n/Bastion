"""
Bastion engine/parsers/pfsense.py — pfSense / OPNsense config.xml parser.

2026-06-11 review fix: pfSense and OPNsense ship configurations as XML
(`/cf/conf/config.xml`). This parser extracts the `<filter><rule>` blocks
and emits a ParseResult that AuditEngine can evaluate.

pfSense and OPNsense use almost-identical XML schemas — they share heritage
from m0n0wall. Differences live in newer optional elements (e.g.
OPNsense `<schedule>`); we parse only the structural fields the audit
rules need.
"""
import re
import xml.etree.ElementTree as ET
from typing import List, Optional

from engine.models import FirewallRule, ParseResult
from engine.parsers.base import AbstractParser, VENDOR_PARSERS


class PfSenseParser(AbstractParser):
    """pfSense / OPNsense config.xml parser."""

    VENDOR = "pfsense"

    def parse(self) -> ParseResult:
        body = "\n".join(self.lines) if isinstance(self.lines, list) else (self.lines or "")
        try:
            root = ET.fromstring(body)
        except ET.ParseError as exc:
            self._error(0, f"XML parse error: {exc}")
            return ParseResult(vendor=self.VENDOR, hostname="", version="",
                                rules=[], objects={}, object_groups={},
                                nat_rules=[], interfaces=[], services={},
                                errors=[str(exc)], warnings=[], summary={})
        # Hostname
        hostname = ""
        for path in ("./system/hostname", "./hostname"):
            elem = root.find(path)
            if elem is not None and elem.text:
                hostname = elem.text.strip(); break
        # Version — pfSense reports it as `<version>22.05</version>`
        version_text = ""
        ver_elem = root.find("./version")
        if ver_elem is not None and ver_elem.text:
            version_text = ver_elem.text.strip()
        rules: List[FirewallRule] = []
        # Filter rules live under <filter><rule>...</rule></filter>
        for idx, rule_elem in enumerate(root.findall("./filter/rule")):
            try:
                action = (rule_elem.findtext("type") or "permit").lower()
                if action == "pass": action = "permit"
                elif action == "block": action = "deny"
                elif action == "reject": action = "deny"
                proto  = (rule_elem.findtext("protocol") or "any").lower()
                src_addr = self._addr(rule_elem.find("source"))
                dst_addr = self._addr(rule_elem.find("destination"))
                dst_port = self._port(rule_elem.find("destination"))
                src_port = self._port(rule_elem.find("source"))
                iface   = rule_elem.findtext("interface") or ""
                desc    = rule_elem.findtext("descr") or ""
                disabled = rule_elem.find("disabled") is not None
                log_flag = rule_elem.find("log") is not None
                rules.append(FirewallRule(
                    line_no=idx, raw_text=ET.tostring(rule_elem, encoding="unicode")[:500],
                    action=action, protocol=proto,
                    src_zone=iface, dst_zone="",
                    src_addresses=[src_addr] if src_addr else ["any"],
                    dst_addresses=[dst_addr] if dst_addr else ["any"],
                    src_ports=[src_port] if src_port else [(0, 65535)],
                    dst_ports=[dst_port] if dst_port else [(0, 65535)],
                    enabled=not disabled, log=log_flag,
                    comment=desc,
                ))
            except Exception as exc:
                self._error(idx, f"rule parse error: {exc}")
                continue
        return ParseResult(
            vendor=self.VENDOR, hostname=hostname, version=version_text,
            rules=rules, objects={}, object_groups={}, nat_rules=[],
            interfaces=[], services={}, errors=[], warnings=[],
            summary={"vendor": self.VENDOR, "rule_count": len(rules)},
        )

    def _addr(self, container) -> Optional[str]:
        if container is None: return None
        if container.find("any") is not None: return "any"
        for tag in ("address", "network", "network_lookup"):
            v = container.find(tag)
            if v is not None and v.text: return v.text.strip()
        return None

    def _port(self, container) -> Optional[tuple]:
        if container is None: return None
        port_text = container.findtext("port") or ""
        if not port_text: return None
        if "-" in port_text:
            try:
                lo, hi = port_text.split("-", 1)
                return (int(lo), int(hi))
            except ValueError: return None
        try:
            p = int(port_text)
            return (p, p)
        except ValueError:
            # Named port — leave as wide for now
            return None


# Register under both common aliases. OPNsense reports as a separate
# vendor at runtime (via detect regex) but uses the same parser.
VENDOR_PARSERS["pfsense"]  = PfSenseParser
VENDOR_PARSERS["opnsense"] = PfSenseParser
