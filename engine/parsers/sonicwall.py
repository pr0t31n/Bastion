"""
Bastion engine/parsers/sonicwall.py — SonicWall configuration parser (.exp XML).
"""
import xml.etree.ElementTree as ET
from typing import List

from engine.models import FirewallRule, ParseResult
from engine.parsers.base import AbstractParser, VENDOR_PARSERS


class SonicwallParser(AbstractParser):

    def parse(self) -> ParseResult:
        rules = []
        interfaces = {}
        zones = {}
        mgmt_access = []

        try:
            root = ET.fromstring(self.config_text)

            # Zone table
            for zone in root.findall(".//ZoneTable/Zone"):
                name = zone.get("name", "")
                if name:
                    zones[name] = {"name": name}

            # Address objects
            for ao in root.findall(".//AddressObjectTable/AddressObject"):
                name = ao.get("name", "")
                addr_type = ao.get("Type", "host")
                ip = ao.get("Ip", "")
                netmask = ao.get("Mask", "")
                if name:
                    if addr_type.lower() == "host" and ip:
                        self.resolver.add_object(name, "host", ip)
                    elif addr_type.lower() in ("network", "subnet") and ip and netmask:
                        import ipaddress
                        try:
                            cidr = str(ipaddress.ip_network(f"{ip}/{netmask}", strict=False))
                            self.resolver.add_object(name, "subnet", cidr)
                        except ValueError:
                            self.resolver.add_object(name, "subnet", ip)
                    elif addr_type.lower() == "range":
                        start = ao.get("StartIp", ip)
                        end = ao.get("EndIp", ip)
                        self.resolver.add_object(name, "range", f"{start}-{end}")

            # Address groups
            for ag in root.findall(".//AddressGroupTable/AddressGroup"):
                name = ag.get("name", "")
                if name:
                    members = [m.get("name", "") for m in ag.findall("AddressObject")
                               if m.get("name")]
                    self.resolver.add_group(name, members)

            # Service objects
            for svc in root.findall(".//ServiceObjectTable/ServiceObject"):
                name = svc.get("name", "")
                proto = svc.get("Protocol", "6")
                dst_port = svc.get("DstPort", "0")
                dst_port_end = svc.get("DstPortEnd", dst_port)
                if name:
                    try:
                        self.resolver.add_object(
                            name, "service",
                            (int(dst_port), int(dst_port_end))
                        )
                    except ValueError:
                        pass

            # Policies
            idx = 0
            for policy in root.findall(".//PolicyTable/SonicWALLFWPolicy"):
                idx += 1
                name = policy.get("Name", f"policy-{idx}")
                src_zone = policy.get("SrcZone", "")
                dst_zone = policy.get("DstZone", "")
                src_addr = policy.get("SrcObj", "any")
                dst_addr = policy.get("DstObj", "any")
                svc_obj = policy.get("Service", "Any")
                action_raw = policy.get("Action", "Deny").lower()
                action = "permit" if action_raw in ("allow", "permit") else "deny"
                enable = policy.get("Enable", "true").lower() == "true"
                log = policy.get("Log", "false").lower() == "true"

                src_addresses = self.resolver.resolve_address(
                    "0.0.0.0/0" if src_addr.lower() in ("any", "") else src_addr
                )
                dst_addresses = self.resolver.resolve_address(
                    "0.0.0.0/0" if dst_addr.lower() in ("any", "") else dst_addr
                )

                rules.append(FirewallRule(
                    rule_id=f"sw-{idx}",
                    rule_name=name,
                    enabled=enable,
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
                    vendor="sonicwall",
                    interface_binding=None,
                ))

        except Exception as e:
            self._error(0, f"SonicWall parse failed: {e}")

        return ParseResult(
            vendor="sonicwall",
            filename=self.filename,
            hostname=None,
            version=None,
            rules=rules,
            metadata={
                "interfaces": interfaces,
                "zones": list(zones.keys()),
                "objects": self.resolver.objects,
                "nat_rules": [],
                "routes": [],
                "management_access": mgmt_access,
            },
            parse_errors=self.parse_errors,
            parse_warnings=self.parse_warnings,
        )


VENDOR_PARSERS["sonicwall"] = SonicwallParser
