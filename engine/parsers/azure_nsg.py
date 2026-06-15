"""
Bastion engine/parsers/azure_nsg.py — Azure Network Security Group JSON parser.

2026-06-11 review fix: parses the JSON output of:

  az network nsg list --output json
  az network nsg show --resource-group <rg> --name <nsg> --output json

Each NSG has a `securityRules` array (operator-defined) and
`defaultSecurityRules` (Azure built-in). Each rule has direction,
access (Allow/Deny), protocol (Tcp/Udp/Icmp/*), priority, source/
destination address prefix + port range, and an enabled state.

Rules are flattened one row per source/destination prefix so
AuditEngine's permissive-rule and any-any-rule detectors work
unchanged.
"""
import json
import re
from typing import List

from engine.models import FirewallRule, ParseResult
from engine.parsers.base import AbstractParser, VENDOR_PARSERS


_ANY_TOKENS = {"*", "any", "internet", "virtualnetwork", "azureloadbalancer"}


def _norm_protocol(p: str) -> str:
    p = (p or "").strip().lower()
    if p in ("*", "any", ""):
        return "any"
    return p


def _norm_addresses(prefix, prefixes) -> List[str]:
    out: List[str] = []
    if isinstance(prefixes, list) and prefixes:
        for p in prefixes:
            if p:
                out.append("0.0.0.0/0" if str(p).strip() in _ANY_TOKENS or p == "*" else str(p))
    if prefix:
        out.append("0.0.0.0/0" if str(prefix).strip() in _ANY_TOKENS or prefix == "*" else str(prefix))
    return out or ["0.0.0.0/0"]


def _norm_ports(port_range, port_ranges) -> List[tuple]:
    raw: List[str] = []
    if isinstance(port_ranges, list) and port_ranges:
        raw.extend([str(x) for x in port_ranges if x])
    if port_range:
        raw.append(str(port_range))
    if not raw:
        return [(0, 65535)]
    out: List[tuple] = []
    for r in raw:
        r = r.strip()
        if r in ("*", "any", ""):
            out.append((0, 65535))
        elif "-" in r:
            try:
                a, b = r.split("-", 1)
                out.append((int(a), int(b)))
            except ValueError:
                out.append((0, 65535))
        else:
            try:
                p = int(r)
                out.append((p, p))
            except ValueError:
                out.append((0, 65535))
    return out


class AzureNsgParser(AbstractParser):
    """Parses `az network nsg list/show` JSON output."""

    VENDOR = "azure_nsg"

    def parse(self) -> ParseResult:
        body = "\n".join(self.lines) if isinstance(self.lines, list) else (self.lines or "")
        try:
            obj = json.loads(body)
        except json.JSONDecodeError as exc:
            self._error(0, f"JSON parse error: {exc}")
            return ParseResult(vendor=self.VENDOR, hostname="", version="",
                                rules=[], objects={}, object_groups={},
                                nat_rules=[], interfaces=[], services={},
                                errors=[str(exc)], warnings=[], summary={})

        if isinstance(obj, dict):
            nsgs = [obj]
        elif isinstance(obj, list):
            nsgs = obj
        else:
            nsgs = []

        rules: List[FirewallRule] = []
        for nsg in nsgs:
            nsg_name = nsg.get("name") or nsg.get("id", "").split("/")[-1] or "nsg"
            rg = ""
            try:
                rg = (nsg.get("resourceGroup")
                       or nsg.get("id", "").split("/resourceGroups/")[1].split("/")[0])
            except Exception:
                rg = ""

            for src_key, builtin in [("securityRules", False),
                                       ("defaultSecurityRules", True)]:
                for r in nsg.get(src_key) or []:
                    props = r.get("properties") or r
                    name = r.get("name") or "rule"
                    direction = str(props.get("direction", "inbound")).lower()
                    if direction not in ("inbound", "outbound"):
                        direction = "inbound"
                    access = str(props.get("access", "Allow")).lower()
                    action = "permit" if access == "allow" else "deny"
                    proto = _norm_protocol(props.get("protocol", "*"))
                    enabled = not bool(props.get("provisioningState", "Succeeded") == "Failed")
                    priority = int(props.get("priority") or 0)

                    src_addrs = _norm_addresses(props.get("sourceAddressPrefix"),
                                                  props.get("sourceAddressPrefixes"))
                    dst_addrs = _norm_addresses(props.get("destinationAddressPrefix"),
                                                  props.get("destinationAddressPrefixes"))
                    src_ports = _norm_ports(props.get("sourcePortRange"),
                                              props.get("sourcePortRanges"))
                    dst_ports = _norm_ports(props.get("destinationPortRange"),
                                              props.get("destinationPortRanges"))

                    rules.append(FirewallRule(
                        line_no=priority,
                        raw_text=json.dumps(r)[:500],
                        action=action, protocol=proto,
                        src_zone="internet" if direction == "inbound" else nsg_name,
                        dst_zone=nsg_name if direction == "inbound" else "internet",
                        src_addresses=src_addrs,
                        dst_addresses=dst_addrs,
                        src_ports=src_ports,
                        dst_ports=dst_ports,
                        enabled=enabled, log=False,
                        comment=(f"{'builtin' if builtin else 'user'} nsg={nsg_name} "
                                  f"rg={rg} name={name} prio={priority}")[:240],
                    ))
        return ParseResult(
            vendor=self.VENDOR,
            hostname=", ".join((n.get("name") or "") for n in nsgs[:3]),
            version="", rules=rules, objects={}, object_groups={},
            nat_rules=[], interfaces=[], services={}, errors=[], warnings=[],
            summary={"vendor": self.VENDOR, "rule_count": len(rules),
                      "nsg_count": len(nsgs)},
        )


VENDOR_PARSERS["azure_nsg"] = AzureNsgParser
