"""
Bastion engine/parsers/watchguard.py — WatchGuard Firebox XML parser.
"""
import xml.etree.ElementTree as ET
from typing import List

from engine.models import FirewallRule, ParseResult
from engine.parsers.base import AbstractParser, VENDOR_PARSERS


class WatchguardParser(AbstractParser):

    def parse(self) -> ParseResult:
        rules = []
        interfaces = {}
        hostname = None

        try:
            root = ET.fromstring(self.config_text)

            # Hostname
            hn = root.find(".//system-parameters/device-name")
            if hn is not None:
                hostname = hn.text

            # Interfaces
            for iface in root.findall(".//interface"):
                name = iface.get("name", "")
                iface_type = iface.get("interface-type", "")
                ip_el = iface.find("ip-and-mask")
                if name:
                    ip = ip_el.text if ip_el is not None else ""
                    interfaces[name] = {"type": iface_type, "ip": ip}

            # Aliases (address groups)
            for alias in root.findall(".//alias"):
                name = alias.get("name", "")
                if name:
                    members = []
                    for member in alias.findall(".//member-list/member"):
                        val = member.text or member.get("value", "")
                        if val:
                            members.append(val)
                    if members:
                        self.resolver.add_group(name, members)

            # Policies
            idx = 0
            for policy in root.findall(".//policy"):
                idx += 1
                name = policy.get("name", f"policy-{idx}")
                action_raw = policy.get("type", "Deny").lower()
                action = "permit" if action_raw in ("allow", "allow-all", "packet-filter") else "deny"
                enabled = policy.get("enabled", "true").lower() == "true"
                log = policy.get("log", "false").lower() == "true"

                src_alias = (policy.find(".//from-alias") or
                             policy.find("from-alias"))
                dst_alias = (policy.find(".//to-alias") or
                             policy.find("to-alias"))

                src_ref = (src_alias.text if src_alias is not None else "") or "Any"
                dst_ref = (dst_alias.text if dst_alias is not None else "") or "Any"

                src_zone = None
                dst_zone = None

                # Infer zone from alias names matching interface types
                for iname, idata in interfaces.items():
                    if src_ref.lower() in (iname.lower(), idata.get("type","").lower()):
                        src_zone = iname
                    if dst_ref.lower() in (iname.lower(), idata.get("type","").lower()):
                        dst_zone = iname

                src_addresses = self.resolver.resolve_address(
                    "0.0.0.0/0" if src_ref.lower() == "any" else src_ref
                )
                dst_addresses = self.resolver.resolve_address(
                    "0.0.0.0/0" if dst_ref.lower() == "any" else dst_ref
                )

                rules.append(FirewallRule(
                    rule_id=f"wg-{idx}",
                    rule_name=name,
                    enabled=enabled,
                    action=action,
                    protocol="ip",
                    src_zone=src_zone,
                    dst_zone=dst_zone,
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
                    vendor="watchguard",
                    interface_binding=None,
                ))

        except Exception as e:
            self._error(0, f"WatchGuard parse failed: {e}")

        return ParseResult(
            vendor="watchguard",
            filename=self.filename,
            hostname=hostname,
            version=None,
            rules=rules,
            metadata={
                "interfaces": interfaces,
                "zones": list(interfaces.keys()),
                "objects": self.resolver.objects,
                "nat_rules": [],
                "routes": [],
                "management_access": [],
            },
            parse_errors=self.parse_errors,
            parse_warnings=self.parse_warnings,
        )


VENDOR_PARSERS["watchguard"] = WatchguardParser
