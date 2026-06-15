"""
Bastion engine/parsers/cisco_ios.py — Cisco IOS / IOS-XE configuration parser.

2026-06-11 review fix: previously cisco_ios was DETECTED by base.py (regex
at line 211: r"#\s*\$EPIC|ip access-list extended") but no parser module
was loaded — configurations fell through to the generic 'unknown' parser
and audit findings were not generated.

IOS uses similar `access-list` and `ip access-list extended` syntax to
ASA, with a few differences:
  * `ip access-group <name> in/out` applied to interfaces (vs ASA's
    `access-group <name> in interface <name>`)
  * IOS numbered ACLs `access-list 100-199 permit/deny ...` map to the
    same FirewallRule shape
  * IOS uses `service-policy` / `class-map` rather than ASA's
    `policy-map type inspect`

For the initial release we subclass CiscoAsaParser since the bulk of the
ACL syntax overlaps. We override:
  * _parse_hostname (slight format difference)
  * _parse_version (looks for `version 15.4` vs `ASA Version`)
  * vendor identifier for finding routing
"""
import re
from typing import Optional

from engine.parsers.cisco_asa import CiscoAsaParser
from engine.parsers.base import VENDOR_PARSERS


class CiscoIosParser(CiscoAsaParser):
    """Cisco IOS / IOS-XE / IOS-XR parser.

    Inherits all ACL/object/object-group parsing from CiscoAsaParser since
    `access-list` syntax overlaps significantly. Overrides only the
    fields that differ.
    """

    VENDOR = "cisco_ios"

    def _parse_hostname(self) -> Optional[str]:
        # IOS uses bare `hostname <name>` same as ASA — inherit
        return super()._parse_hostname()

    def _parse_version(self) -> Optional[str]:
        """IOS version is `version 15.4(3)M1` or `IOS XE Software Version 16.9.5`."""
        try:
            for line in self.lines:
                # IOS-XE banner
                m = re.match(r"^.*IOS\s*XE.*Version\s+([\d.()\w]+)",
                              line.strip(), re.IGNORECASE)
                if m: return m.group(1)
                # Plain IOS
                m = re.match(r"^version\s+([\d.]+)", line.strip(), re.IGNORECASE)
                if m: return m.group(1)
                # IOS-XR
                m = re.match(r"^.*IOS\s*XR.*Version\s+([\d.()\w]+)",
                              line.strip(), re.IGNORECASE)
                if m: return m.group(1)
        except Exception as e:
            self._error(0, f"_parse_version failed: {e}")
        return None

    def parse(self):
        # Delegate to base, then tag the vendor
        result = super().parse()
        try:
            if hasattr(result, "vendor"):  result.vendor  = self.VENDOR
            if hasattr(result, "summary"): result.summary["vendor"] = self.VENDOR
        except Exception:
            pass
        return result


# Register
VENDOR_PARSERS["cisco_ios"] = CiscoIosParser
