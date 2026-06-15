"""
Bastion engine/parsers/gcp_vpc.py — GCP VPC firewall rules JSON parser.

2026-06-11 review fix: parses the JSON output of:

  gcloud compute firewall-rules list --format=json
  gcloud compute firewall-rules describe <name> --format=json

Each rule has a direction (INGRESS/EGRESS), allowed/denied list,
sourceRanges / destinationRanges, targetTags / sourceTags, priority,
and a disabled flag. We flatten one row per (allowed_entry, range)
pair so AuditEngine's permissive-rule and any-any-rule detectors work
unchanged.
"""
import json
from typing import List

from engine.models import FirewallRule, ParseResult
from engine.parsers.base import AbstractParser, VENDOR_PARSERS


def _norm_protocol(p: str) -> str:
    p = (p or "").strip().lower()
    if p in ("all", "any", "*", ""):
        return "any"
    return p


def _ports_from_entry(ports_list) -> List[tuple]:
    if not ports_list:
        return [(0, 65535)]
    out: List[tuple] = []
    for r in ports_list:
        r = str(r).strip()
        if "-" in r:
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


class GcpVpcParser(AbstractParser):
    """Parses `gcloud compute firewall-rules list/describe` JSON output."""

    VENDOR = "gcp_vpc"

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
            entries = [obj]
        elif isinstance(obj, list):
            entries = obj
        else:
            entries = []

        rules: List[FirewallRule] = []
        for fw in entries:
            name = fw.get("name") or "rule"
            network = (fw.get("network") or "").split("/")[-1]
            direction = str(fw.get("direction", "INGRESS")).lower()
            direction = "inbound" if direction == "ingress" else "outbound"
            priority = int(fw.get("priority") or 1000)
            disabled = bool(fw.get("disabled"))
            log_enabled = bool((fw.get("logConfig") or {}).get("enable"))

            src_ranges = fw.get("sourceRanges") or []
            dst_ranges = fw.get("destinationRanges") or []
            src_tags = fw.get("sourceTags") or []
            tgt_tags = fw.get("targetTags") or []
            src_sa = fw.get("sourceServiceAccounts") or []
            tgt_sa = fw.get("targetServiceAccounts") or []

            for action, key in [("permit", "allowed"), ("deny", "denied")]:
                for entry in fw.get(key) or []:
                    proto = _norm_protocol(entry.get("IPProtocol", "any"))
                    dst_ports = _ports_from_entry(entry.get("ports") or [])

                    src_addrs = list(src_ranges) if direction == "inbound" else list(src_tags or src_sa or ["any"])
                    dst_addrs = (list(tgt_tags or tgt_sa or [network or "any"])
                                  if direction == "inbound"
                                  else list(dst_ranges))

                    if not src_addrs:
                        src_addrs = ["0.0.0.0/0"]
                    if not dst_addrs:
                        dst_addrs = [network or "any"]

                    rules.append(FirewallRule(
                        line_no=priority,
                        raw_text=json.dumps({"fw": name, "entry": entry})[:500],
                        action=action, protocol=proto,
                        src_zone="internet" if direction == "inbound" else network,
                        dst_zone=network if direction == "inbound" else "internet",
                        src_addresses=src_addrs,
                        dst_addresses=dst_addrs,
                        src_ports=[(0, 65535)],
                        dst_ports=dst_ports if proto != "any" else [(0, 65535)],
                        enabled=not disabled, log=log_enabled,
                        comment=(f"{direction} fw={name} net={network} prio={priority}")[:240],
                    ))
        return ParseResult(
            vendor=self.VENDOR,
            hostname=", ".join((e.get("name") or "") for e in entries[:3]),
            version="", rules=rules, objects={}, object_groups={},
            nat_rules=[], interfaces=[], services={}, errors=[], warnings=[],
            summary={"vendor": self.VENDOR, "rule_count": len(rules),
                      "fw_count": len(entries)},
        )


VENDOR_PARSERS["gcp_vpc"] = GcpVpcParser
