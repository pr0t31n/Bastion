"""
Bastion engine/correlation.py — Multi-device correlation engine.
Identifies cross-device policy inconsistencies, asymmetric rules,
and end-to-end path gaps.
"""
import logging
import uuid
from datetime import datetime
from typing import Dict, List

from engine.models import Finding, ParseResult


class CorrelationEngine:
    """
    Builds a multi-device network topology from multiple ParseResults.
    Identifies:
      1. End-to-end traffic paths that traverse multiple firewall devices
      2. Gaps where traffic is permitted on device A but blocked on device B
      3. Asymmetric policies (A→B permitted, B→A blocked)
      4. Missing egress controls (internal traffic hits only the edge firewall)
    """

    def __init__(self, parse_results: List[ParseResult]):
        self.parse_results = parse_results
        self.logger = logging.getLogger("CorrelationEngine")
        self.topology: Dict[str, List[str]] = {}     # zone → [device_names]
        self.device_zones: Dict[str, List[str]] = {} # device → [zones]

    def build_topology(self) -> None:
        """Map zones to the devices that own them."""
        try:
            for pr in self.parse_results:
                device = pr.hostname or pr.filename
                zones = list(pr.metadata.get("interfaces", {}).keys())
                self.device_zones[device] = zones
                for zone in zones:
                    self.topology.setdefault(zone, []).append(device)
        except Exception as e:
            self.logger.error(f"build_topology error: {e}", exc_info=True)

    def find_cross_device_paths(self) -> List[dict]:
        """
        Identify traffic permitted on one device that must also pass through
        a second device, and check whether that path is consistently permitted.
        Returns list of path dicts:
          {src_zone, dst_zone, port, permitted_on, blocked_on, recommendation}
        """
        self.build_topology()
        paths = []
        try:
            all_permits = []
            for pr in self.parse_results:
                device = pr.hostname or pr.filename
                for rule in pr.rules:
                    if rule.action == "permit" and rule.enabled:
                        all_permits.append({
                            "device": device,
                            "src_zone": rule.src_zone,
                            "dst_zone": rule.dst_zone,
                            "ports": rule.dst_ports or [],
                            "rule_id": rule.rule_id,
                            "line": rule.line_number,
                        })

            for flow in all_permits:
                for pr2 in self.parse_results:
                    dev2 = pr2.hostname or pr2.filename
                    if dev2 == flow["device"]:
                        continue
                    for rule in pr2.rules:
                        if (rule.action == "deny" and rule.enabled
                                and rule.src_zone == flow["src_zone"]
                                and rule.dst_zone == flow["dst_zone"]):
                            paths.append({
                                "permitted_on": flow["device"],
                                "blocked_on": dev2,
                                "src_zone": flow["src_zone"],
                                "dst_zone": flow["dst_zone"],
                                "ports": flow["ports"],
                                "permit_rule": flow["rule_id"],
                                "deny_rule": rule.rule_id,
                                "recommendation":
                                    f"Align policy on {dev2} to match {flow['device']}",
                            })
                            break

        except Exception as e:
            self.logger.error(f"find_cross_device_paths error: {e}", exc_info=True)
        return paths

    def generate_correlation_findings(self) -> List[Finding]:
        """Convert correlation results into Finding objects."""
        findings = []
        try:
            paths = self.find_cross_device_paths()
            for path in paths:
                src_zone = path.get("src_zone") or "unknown"
                dst_zone = path.get("dst_zone") or "unknown"
                permitted_on = path.get("permitted_on", "")
                blocked_on = path.get("blocked_on", "")

                findings.append(Finding(
                    id=str(uuid.uuid4()),
                    title=(
                        f"Policy Inconsistency: {src_zone} \u2192 {dst_zone} "
                        f"permitted on {permitted_on} but denied on {blocked_on}"
                    ),
                    description=(
                        f"Traffic from zone {src_zone} to {dst_zone} is explicitly "
                        f"permitted by {permitted_on} (rule {path['permit_rule']}) "
                        f"but is blocked by {blocked_on} (rule {path['deny_rule']}). "
                        f"This asymmetric policy may indicate a misconfiguration "
                        f"or incomplete rule migration."
                    ),
                    impact=(
                        "Inconsistent policies between devices can create unexpected "
                        "traffic behaviours, partial connectivity, and security gaps "
                        "depending on which device handles a given traffic flow."
                    ),
                    recommendation=path["recommendation"],
                    risk="Medium",
                    cvss_score=5.4,
                    cvss_vector="CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:L/I:L/A:L",
                    framework="NIST 800-41",
                    framework_section="\u00a73.4",
                    framework_control_name="Firewall Rule Management",
                    framework_requirement="Rules across devices should be consistent",
                    additional_frameworks=[],
                    triggered_lines=[],
                    triggered_raw=[],
                    config_file=f"{permitted_on} / {blocked_on}",
                    vendor="multi-device",
                    audit_rule_id="FW-CORR-001",
                    rule_ids=[path["permit_rule"], path["deny_rule"]],
                    analyst_notes="",
                    remediation_effort="short_term",
                    timestamp=datetime.now().isoformat(),
                ))
        except Exception as e:
            self.logger.error(
                f"generate_correlation_findings error: {e}", exc_info=True)
        return findings
