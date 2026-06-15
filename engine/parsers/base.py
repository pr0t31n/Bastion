"""
Bastion engine/parsers/base.py
ObjectResolver, AbstractParser, detect_vendor, get_parser factory.
"""
import ipaddress
import logging
import re
from abc import ABC, abstractmethod
from typing import Dict, List, Optional, Tuple

from engine.models import ParseResult

# Registry populated by each parser module on import
VENDOR_PARSERS: dict = {}


# ---------------------------------------------------------------------------
# ObjectResolver — Gap 2: Full recursive object resolution with cycle detection
# ---------------------------------------------------------------------------

class ObjectResolver:
    """
    Fully recursive object and object-group resolver.
    Handles: network objects, service objects, object groups,
    deeply nested group-of-groups (up to MAX_DEPTH levels).
    Includes cycle detection to handle misconfigured circular references.
    """

    MAX_DEPTH = 20

    def __init__(self, logger=None):
        self.objects: dict = {}          # name → {type, value}
        self.groups: dict = {}           # name → [member_names_or_literals]
        self.logger = logger or logging.getLogger("ObjectResolver")
        self._resolution_cache: dict = {}  # (ref, visited) → [resolved_CIDRs]

    def add_object(self, name: str, obj_type: str, value) -> None:
        """Register a named object (host, subnet, range, fqdn, service)."""
        self.objects[name] = {"type": obj_type, "value": value}
        self._resolution_cache.clear()

    def add_group(self, name: str, members: list) -> None:
        """Register a named group with a list of member names or literals."""
        self.groups[name] = members
        self._resolution_cache.clear()

    def resolve_address(
        self,
        ref: str,
        _visited: frozenset = None,
        _depth: int = 0,
    ) -> List[str]:
        """
        Resolve a reference to a flat list of CIDRs.
        ref can be: object name, group name, "any"/"any4",
                    "host <ip>", "<network> <mask>", or bare CIDR.
        Returns list of CIDR strings (e.g. ["10.0.0.0/24", "192.168.1.1/32"])
        """
        if _visited is None:
            _visited = frozenset()

        if _depth > self.MAX_DEPTH:
            self.logger.warning(f"Max resolution depth exceeded for {ref!r}")
            return [ref]

        cache_key = (ref, _visited)
        if cache_key in self._resolution_cache:
            return self._resolution_cache[cache_key]

        result = []
        try:
            r = ref.strip()

            # "any" / "any4" / "any6" / "all"
            if r.lower() in ("any", "any4", "any6", "all"):
                result = ["0.0.0.0/0"]

            # "host <ip>"
            elif r.lower().startswith("host "):
                ip = r.split()[1]
                result = [f"{ip}/32"]

            # Bare CIDR: "10.0.0.0/24"
            elif "/" in r:
                try:
                    ipaddress.ip_network(r, strict=False)  # validate
                    result = [r]
                except ValueError:
                    result = [r]

            # "<network> <mask>" dotted notation
            elif len(r.split()) == 2 and all("." in p for p in r.split()):
                try:
                    net, mask = r.split()
                    cidr = str(ipaddress.ip_network(f"{net}/{mask}", strict=False))
                    result = [cidr]
                except ValueError:
                    result = [r]

            # Group reference
            elif r in self.groups:
                if r in _visited:
                    self.logger.warning(f"Circular reference detected: {r!r}")
                    return []
                new_visited = _visited | {r}
                for member in self.groups[r]:
                    resolved = self.resolve_address(member, new_visited, _depth + 1)
                    result.extend(resolved)

            # Object reference
            elif r in self.objects:
                obj = self.objects[r]
                if obj["type"] in ("host", "subnet", "range", "fqdn"):
                    v = obj["value"]
                    if obj["type"] == "host":
                        result = [f"{v}/32"]
                    elif obj["type"] == "subnet":
                        try:
                            result = [str(ipaddress.ip_network(v, strict=False))]
                        except ValueError:
                            result = [v]
                    elif obj["type"] == "range":
                        result = [v]   # best-effort
                    elif obj["type"] == "fqdn":
                        result = [v]   # keep FQDN as-is
                else:
                    result = [r]

            else:
                # Unknown reference — return as-is with debug log
                self.logger.debug(f"Unresolved reference: {r!r}")
                result = [r]

        except Exception as e:
            self.logger.warning(f"resolve_address error for {ref!r}: {e}")
            result = [ref]

        self._resolution_cache[cache_key] = result
        return result

    def resolve_ports(self, ref: str) -> List[Tuple[int, int]]:
        """
        Resolve a port reference to a list of (start, end) tuples.
        ref can be: "eq 80", "range 8000 8080", "object <n>",
                    "object-group <n>", or a bare port number.
        """
        try:
            r = ref.strip()
            if r.startswith("eq "):
                port = int(r.split()[1])
                return [(port, port)]
            elif r.startswith("range "):
                parts = r.split()
                return [(int(parts[1]), int(parts[2]))]
            elif r.startswith("lt "):
                return [(0, int(r.split()[1]) - 1)]
            elif r.startswith("gt "):
                return [(int(r.split()[1]) + 1, 65535)]
            elif r.isdigit():
                p = int(r)
                return [(p, p)]
            elif r in self.objects:
                obj = self.objects[r]
                if isinstance(obj.get("value"), (list, tuple)) and len(obj["value"]) == 2:
                    return [tuple(obj["value"])]
        except Exception as e:
            self.logger.warning(f"resolve_ports error for {ref!r}: {e}")
        return []

    def get_all_object_names(self) -> set:
        return set(self.objects.keys()) | set(self.groups.keys())


# ---------------------------------------------------------------------------
# AbstractParser
# ---------------------------------------------------------------------------

class AbstractParser(ABC):
    def __init__(self, config_text: str, filename: str):
        self.config_text = config_text
        self.filename = filename
        self.lines = config_text.splitlines()
        self.logger = logging.getLogger(self.__class__.__name__)
        self.parse_errors: List[dict] = []
        self.parse_warnings: List[dict] = []
        self.resolver = ObjectResolver(self.logger)

    @abstractmethod
    def parse(self) -> ParseResult:
        ...

    def _warn(self, line_no: int, msg: str) -> None:
        self.parse_warnings.append({"line": line_no, "message": msg})
        self.logger.warning(f"Line {line_no}: {msg}")

    def _error(self, line_no: int, msg: str) -> None:
        self.parse_errors.append({"line": line_no, "message": msg})
        self.logger.error(f"Line {line_no}: {msg}")


# ---------------------------------------------------------------------------
# Vendor detection
# ---------------------------------------------------------------------------

def detect_vendor(config_text: str, filename: str) -> str:
    """Auto-detect vendor from config content and filename."""
    text = config_text[:8000]

    checks = [
        (r"ASA Version\s+[\d.]+|Cisco Adaptive Security Appliance", "cisco_asa"),
        # 2026-06-11: IOS-XR detected before plain IOS to avoid mis-tag,
        # and pfSense / OPNsense (XML root) detected separately.
        (r"IOS\s*XR.*Version|ASR9", "cisco_iosxr"),
        (r"#\s*\$EPIC|ip access-list extended", "cisco_ios"),
        (r"NGFW Version|Cisco Firepower", "cisco_ftd"),
        (r"<pfsense>|<opnsense>", "pfsense"),
        # 2026-06-11 review round 4 additions
        (r'"SecurityGroups"\s*:\s*\[', "aws_sg"),
        (r'"NetworkAcls"\s*:\s*\[',    "aws_nacl"),
        (r"^/ip firewall|^# RouterOS|^# software ID", "mikrotik"),
        # 2026-06-11 review round 5 additions
        (r'"securityRules"\s*:|Microsoft\.Network/networkSecurityGroups', "azure_nsg"),
        (r'"IPProtocol"\s*:|"sourceRanges"\s*:|gcloud compute firewall-rules', "gcp_vpc"),
        (r"config system global|FortiGate-\d+|#config-version=", "fortinet"),
        (r"set deviceconfig system hostname|<config version=.*pan", "palo_alto"),
        (r":type \(network-object\)|SmartDashboard|fw1_implied", "checkpoint"),
        (r"SonicWALL|<SonicWALLConfig|<PolicyTable>", "sonicwall"),
        (r"WatchGuard Technologies|<WatchGuard|<policy\s+name=", "watchguard"),
        (r"SchemaVersion.*Sophos|<XGFirewall|<FirewallRule>", "sophos"),
        (r"set system host-name|security \{[\s\S]{0,100}policies", "juniper_srx"),
        (r"<sangfor|<SANGFOR|sangforfw", "sangfor"),
        (r'"catoNetworks"|"networkRules"|"wanFirewall"', "cato"),
        (r'gateway_rules.*traffic_type.*egress_rule', "cloudflare"),
    ]

    for pattern, vendor in checks:
        if re.search(pattern, text, re.IGNORECASE | re.DOTALL):
            return vendor

    fname = filename.lower()
    if any(x in fname for x in ["asa", "pix", "fwsm"]):
        return "cisco_asa"
    if "fortigate" in fname or "fortinet" in fname:
        return "fortinet"
    if "paloalto" in fname or "panorama" in fname:
        return "palo_alto"
    if "checkpoint" in fname or "cp_" in fname:
        return "checkpoint"
    if "sonicwall" in fname or "sonic" in fname:
        return "sonicwall"
    if "watchguard" in fname or "firebox" in fname:
        return "watchguard"
    if "sophos" in fname or "xg" in fname:
        return "sophos"
    if "juniper" in fname or "srx" in fname or "junos" in fname:
        return "juniper_srx"
    if "cato" in fname:
        return "cato"
    if "cloudflare" in fname:
        return "cloudflare"
    if "sangfor" in fname:
        return "sangfor"

    return "unknown"


# ---------------------------------------------------------------------------
# Parser factory
# ---------------------------------------------------------------------------

def get_parser(vendor: str, config_text: str, filename: str) -> AbstractParser:
    """Return the appropriate parser instance for the given vendor."""
    # Lazy import all parsers to populate VENDOR_PARSERS
    _ensure_parsers_loaded()

    cls = VENDOR_PARSERS.get(vendor)
    if not cls:
        # Fall back to a generic/unknown parser
        cls = VENDOR_PARSERS.get("unknown")
        if not cls:
            raise ValueError(f"No parser available for vendor: {vendor!r}")
    return cls(config_text, filename)


def _ensure_parsers_loaded() -> None:
    """Import all parser modules to register them in VENDOR_PARSERS."""
    if len(VENDOR_PARSERS) > 0:
        return
    try:
        from engine.parsers import cisco_asa      # noqa: F401
        # 2026-06-11 review fix: cisco_ios and cisco_ftd were detected by
        # the vendor regex but NEVER loaded, so they fell through to the
        # 'unknown' parser and audit findings were not generated.
        from engine.parsers import cisco_ios      # noqa: F401
        from engine.parsers import cisco_ftd      # noqa: F401
        from engine.parsers import cisco_iosxr    # noqa: F401 (2026-06-11 review)
        from engine.parsers import pfsense        # noqa: F401 (2026-06-11 review)
        # 2026-06-11 review round 4
        from engine.parsers import mikrotik       # noqa: F401
        from engine.parsers import aws_sg         # noqa: F401
        # 2026-06-11 review round 5
        from engine.parsers import azure_nsg      # noqa: F401
        from engine.parsers import gcp_vpc        # noqa: F401
        from engine.parsers import palo_alto      # noqa: F401
        from engine.parsers import fortinet       # noqa: F401
        from engine.parsers import checkpoint     # noqa: F401
        from engine.parsers import sonicwall      # noqa: F401
        from engine.parsers import watchguard     # noqa: F401
        from engine.parsers import sophos         # noqa: F401
        from engine.parsers import juniper_srx    # noqa: F401
        from engine.parsers import cato           # noqa: F401
        from engine.parsers import cloudflare     # noqa: F401
        from engine.parsers import sangfor        # noqa: F401
    except Exception as e:
        logging.getLogger("base").warning(f"Parser import error: {e}")
