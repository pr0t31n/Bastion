"""
Bastion engine/parsers/cisco_iosxr.py — Cisco IOS-XR + ASR9000 parser.

2026-06-11 review fix: extends the cisco_ios parser to cover IOS-XR.
IOS-XR uses similar `ipv4 access-list <name>` / `ipv6 access-list <name>`
container blocks rather than the IOS `ip access-list extended <name>`
+ flat numbered ACLs. The base CiscoAsaParser handles the flat ACL form
adequately; this parser wires up the IOS-XR specific version regex.
"""
import re
from typing import Optional

from engine.parsers.cisco_ios import CiscoIosParser
from engine.parsers.base import VENDOR_PARSERS


class CiscoIosXrParser(CiscoIosParser):
    """Cisco IOS-XR / ASR9000."""

    VENDOR = "cisco_iosxr"

    def _parse_version(self) -> Optional[str]:
        try:
            for line in self.lines:
                m = re.match(r"^.*IOS\s*XR.*Version\s+([\d.()\w]+)",
                              line.strip(), re.IGNORECASE)
                if m: return m.group(1)
        except Exception as e:
            self._error(0, f"_parse_version failed: {e}")
        return super()._parse_version()


VENDOR_PARSERS["cisco_iosxr"] = CiscoIosXrParser
