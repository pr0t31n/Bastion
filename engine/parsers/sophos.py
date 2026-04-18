"""
Bastion engine/parsers/sophos.py — Sophos XG/XGS XML parser.
"""
import xml.etree.ElementTree as ET
from typing import List

from engine.models import FirewallRule, ParseResult
from engine.parsers.base import AbstractParser, VENDOR_PARSERS


class SophosParser(AbstractParser):

    def parse(self) -> ParseResult:
        rules = []
        interfaces = {}
        hostname = None

        try:
            root = ET.fromstring(self.config_text)

            # IP Hosts
            for host in root.findall(".//IPHost"):
                name_el = host.find("Name")
                ip_el = host.find("IPAddress")
                subnet_el = host.find("Subnet")
                name = name_el.text if name_el is not None else ""
                if name:
                    if subnet_el is not None and subnet_el.text:
                        # "10.0.0.0/24" or "10.0.0.0/255.255.255.0"
                        self.resolver.add_object(name, "subnet", subnet_el.text)
                    elif ip_el is not None and ip_el.text:
                        self.resolver.add_object(name, "host", ip_el.text)

            # IP Host Groups
            for grp in root.findall(".//IPHostGroup"):
                name_el = grp.find("Name")
                name = name_el.text if name_el is not None else ""
                if name:
                    members = [
                        h.text for h in grp.findall(".//HostList/Host")
                        if h.text
                    ]
                    if members:
                        self.resolver.add_group(name, members)

            # Firewall rules
            idx = 0
            for rule_el in root.findall(".//FirewallRule"):
                idx += 1
                name_el = rule_el.find("Name")
                name = name_el.text if name_el is not None else f"rule-{idx}"

                src_zone_el = rule_el.find("SourceZone")
                dst_zone_el = rule_el.find("DestZone")
                src_net_el = rule_el.find("SourceNetworks/Network")
                dst_net_el = rule_el.find("DestinationNetworks/Network")
                action_el = rule_el.find("Action")
                status_el = rule_el.find("Status")
                log_el = rule_el.find("LogTraffic")

                src_zone = src_zone_el.text if src_zone_el is not None else None
                dst_zone = dst_zone_el.text if dst_zone_el is not None else None
                action_raw = (action_el.text or "Deny").lower()
                action = "permit" if action_raw in ("accept", "allow") else "deny"
                enabled = (status_el.text or "Enable").lower() == "enable"
                log = (log_el.text or "Disable").lower() != "disable"

                src_ref = src_net_el.text if src_net_el is not None else "Any"
                dst_ref = dst_net_el.text if dst_net_el is not None else "Any"

                src_addresses = self.resolver.resolve_address(
                    "0.0.0.0/0" if (src_ref or "Any").lower() == "any" else src_ref
                )
                dst_addresses = self.resolver.resolve_address(
                    "0.0.0.0/0" if (dst_ref or "Any").lower() == "any" else dst_ref
                )

                rules.append(FirewallRule(
                    rule_id=f"sophos-{idx}",
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
                    vendor="sophos",
                    interface_binding=None,
                ))

        except Exception as e:
            self._error(0, f"Sophos parse failed: {e}")

        return ParseResult(
            vendor="sophos",
            filename=self.filename,
            hostname=hostname,
            version=None,
            rules=rules,
            metadata={
                "interfaces": interfaces,
                "zones": [],
                "objects": self.resolver.objects,
                "nat_rules": [],
                "routes": [],
                "management_access": [],
            },
            parse_errors=self.parse_errors,
            parse_warnings=self.parse_warnings,
        )


VENDOR_PARSERS["sophos"] = SophosParser
