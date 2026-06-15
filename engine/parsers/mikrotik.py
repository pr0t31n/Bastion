"""
Bastion engine/parsers/mikrotik.py — MikroTik RouterOS config parser.

2026-06-11 review fix: MikroTik RouterOS exports configurations as plain
text via `/export show-sensitive` or `/file print` of a backup. The
syntax is:

  /ip firewall filter
  add chain=input action=accept protocol=icmp comment="ICMP"
  add chain=input action=drop in-interface=ether1 \
      src-address=0.0.0.0/0 comment="drop external"

Only the `/ip firewall filter` and `/ip firewall nat` blocks are
extracted for audit. Inactive (`disabled=yes`) rules are flagged as
non-enabled.
"""
import re
from typing import List, Optional

from engine.models import FirewallRule, ParseResult
from engine.parsers.base import AbstractParser, VENDOR_PARSERS


class MikrotikParser(AbstractParser):
    """MikroTik RouterOS config parser."""

    VENDOR = "mikrotik"

    _BLOCK_HEAD = re.compile(r"^/(ip|ipv6)\s+firewall\s+(filter|nat|raw|mangle)\s*$",
                              re.IGNORECASE)
    _ADD_LINE   = re.compile(r"^\s*add\s+(.*)$", re.IGNORECASE)
    _KV_PAIR    = re.compile(r"""([\w-]+)=                   # key
                                  (?:"((?:[^"\\]|\\.)*)"|    # quoted value
                                  ([^\s\\]+))                # bare value
                               """, re.X)

    def _parse_hostname(self) -> Optional[str]:
        try:
            for line in self.lines:
                m = re.match(r"^/system identity\s*$", line.strip(), re.IGNORECASE)
                if m and self.lines.index(line) + 1 < len(self.lines):
                    next_line = self.lines[self.lines.index(line) + 1]
                    n = re.search(r'set\s+name=(\S+)', next_line)
                    if n: return n.group(1).strip('"')
            for line in self.lines:
                if "name=" in line and "system identity" in line.lower():
                    n = re.search(r'name=(\S+)', line)
                    if n: return n.group(1).strip('"')
        except Exception as exc:
            self._error(0, f"_parse_hostname failed: {exc}")
        return None

    def _parse_version(self) -> Optional[str]:
        try:
            for line in self.lines:
                # `# RouterOS 7.10 ...` typical first-line comment
                m = re.match(r"^#\s*(?:RouterOS|software ID:?)\s*(\S+)",
                              line.strip(), re.IGNORECASE)
                if m: return m.group(1)
        except Exception:
            pass
        return None

    def _parse_kv(self, kv_str: str) -> dict:
        out = {}
        for m in self._KV_PAIR.finditer(kv_str):
            key = m.group(1).lower()
            val = m.group(2) if m.group(2) is not None else (m.group(3) or "")
            out[key] = val
        return out

    def parse(self) -> ParseResult:
        rules: List[FirewallRule] = []
        in_block = None
        for idx, line in enumerate(self.lines):
            stripped = line.strip()
            hdr = self._BLOCK_HEAD.match(stripped)
            if hdr:
                in_block = hdr.group(2).lower()
                continue
            if not in_block: continue
            if stripped.startswith("/"):
                # Different block start — exit current
                in_block = None
                continue
            add_m = self._ADD_LINE.match(line)
            if not add_m: continue
            kv = self._parse_kv(add_m.group(1))
            try:
                action_raw = kv.get("action", "accept").lower()
                if action_raw == "accept":         action = "permit"
                elif action_raw in ("drop", "reject"): action = "deny"
                else: action = action_raw
                proto    = kv.get("protocol", "any").lower()
                src_addr = kv.get("src-address") or kv.get("src-address-list") or "any"
                dst_addr = kv.get("dst-address") or kv.get("dst-address-list") or "any"
                # Port handling
                src_port = self._port_range(kv.get("src-port", ""))
                dst_port = self._port_range(kv.get("dst-port", ""))
                in_iface = kv.get("in-interface", "")
                out_iface = kv.get("out-interface", "")
                disabled = kv.get("disabled", "no").lower() in ("yes", "true", "1")
                log_flag = kv.get("log", "no").lower() in ("yes", "true", "1")
                comment  = kv.get("comment", "")
                rules.append(FirewallRule(
                    line_no=idx + 1, raw_text=stripped[:500],
                    action=action, protocol=proto,
                    src_zone=in_iface, dst_zone=out_iface,
                    src_addresses=[src_addr],
                    dst_addresses=[dst_addr],
                    src_ports=[src_port] if src_port else [(0, 65535)],
                    dst_ports=[dst_port] if dst_port else [(0, 65535)],
                    enabled=not disabled, log=log_flag,
                    comment=comment,
                ))
            except Exception as exc:
                self._error(idx + 1, f"rule parse failed: {exc}")
                continue
        return ParseResult(
            vendor=self.VENDOR, hostname=self._parse_hostname() or "",
            version=self._parse_version() or "",
            rules=rules, objects={}, object_groups={}, nat_rules=[],
            interfaces=[], services={}, errors=[], warnings=[],
            summary={"vendor": self.VENDOR, "rule_count": len(rules)},
        )

    def _port_range(self, port_str: str) -> Optional[tuple]:
        if not port_str: return None
        port_str = port_str.strip().strip('"')
        if "-" in port_str:
            try:
                lo, hi = port_str.split("-", 1)
                return (int(lo), int(hi))
            except ValueError: return None
        if "," in port_str:
            # Multi-port — treat as wide; firstport-firstport
            try:
                first = int(port_str.split(",", 1)[0])
                return (first, first)
            except ValueError: return None
        try:
            p = int(port_str)
            return (p, p)
        except ValueError: return None


VENDOR_PARSERS["mikrotik"] = MikrotikParser
