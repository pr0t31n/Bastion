"""
Bastion engine/models.py — Data models for firewall analysis.
"""
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple


@dataclass
class FirewallRule:
    rule_id: str
    rule_name: str
    enabled: bool
    action: str                           # "permit" | "deny"
    protocol: Optional[str]              # "tcp"|"udp"|"icmp"|"ip"|"any"
    src_zone: Optional[str]
    dst_zone: Optional[str]
    src_addresses: List[str]             # CIDRs (already resolved)
    dst_addresses: List[str]
    src_ports: Optional[List[Tuple[int, int]]]   # (start, end) ranges
    dst_ports: Optional[List[Tuple[int, int]]]
    logging: bool
    log_level: Optional[str]
    line_number: int                     # line in raw config
    raw_lines: List[str]                 # exact config line(s)
    nat: Optional[dict]
    comments: Optional[str]
    vendor: str
    interface_binding: Optional[str]
    hit_count: Optional[int] = None     # from log analysis if available


@dataclass
class Finding:
    id: str
    title: str
    description: str
    impact: str
    recommendation: str
    risk: str                            # Critical|High|Medium|Low|Informational
    cvss_score: Optional[float]
    cvss_vector: Optional[str]           # e.g. CVSS:3.1/AV:N/AC:L/PR:N/UI:N/...
    framework: str
    framework_section: str
    framework_control_name: str
    framework_requirement: str
    additional_frameworks: List[dict]
    triggered_lines: List[int]
    triggered_raw: List[str]
    config_file: str
    vendor: str
    audit_rule_id: str
    rule_ids: List[str]
    analyst_notes: str
    accepted: bool = False               # False Positive / Accepted Risk Flag
    acceptance_justification: str = ""
    accepted_by: str = ""
    accepted_at: str = ""
    remediation_effort: str = "short_term"  # immediate|short_term|long_term
    is_new: bool = False                 # set during diff calculation
    is_resolved: bool = False
    risk_changed: bool = False
    previous_risk: Optional[str] = None
    timestamp: str = ""


@dataclass
class NetworkNode:
    node_id: str
    label: str
    node_type: str    # "firewall"|"host"|"network"|"zone"|"internet"
    zone: Optional[str]
    ip: Optional[str]
    network: Optional[str]
    interfaces: List[dict]
    color: str
    device_name: Optional[str] = None   # which device owns this node


@dataclass
class NetworkEdge:
    src: str
    dst: str
    ports: List[str]
    direction: str
    action: str
    label: str
    rule_ids: List[str]
    color: str
    cross_device: bool = False           # spans multiple firewall devices
    device_path: List[str] = field(default_factory=list)


@dataclass
class ParseResult:
    vendor: str
    filename: str
    hostname: Optional[str]
    version: Optional[str]
    rules: List[FirewallRule]
    metadata: dict   # {interfaces, zones, objects, nat_rules, routes}
    parse_errors: List[dict]
    parse_warnings: List[dict]


@dataclass
class AnalysisResult:
    project_id: str
    generated_at: str
    config_files: List[dict]
    findings: List[Finding]
    risk_summary: dict
    framework_summary: dict
    network_nodes: List[NetworkNode]
    network_edges: List[NetworkEdge]
    diff_summary: Optional[dict] = None  # Gap 7


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

RISK_LEVELS = ["Critical", "High", "Medium", "Low", "Informational", "Unknown"]

RISK_COLORS = {
    "Critical":      "#FF00FF",
    "High":          "#E7716F",
    "Medium":        "#FFC000",
    "Low":           "#92D050",
    "Informational": "#BDD7EC",
    "Unknown":       "#a0aec0",
}

RISK_ORDER = {
    "Critical":      0,
    "High":          1,
    "Medium":        2,
    "Low":           3,
    "Informational": 4,
    "Unknown":       5,
}
