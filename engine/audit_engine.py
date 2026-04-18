"""
Bastion engine/audit_engine.py — Audit engine with CVSS 3.1 calculator.
Loads audit_rules.yaml + optional vendor overlays + executive profile rules.
"""
import logging
import math
import os
import re
import uuid
from datetime import datetime
from typing import List, Optional

import yaml

from engine.models import Finding, FirewallRule, ParseResult, RISK_ORDER

logger = logging.getLogger("AuditEngine")

_BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

CVSS_WEIGHTS = {
    "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20},
    "AC": {"L": 0.77, "H": 0.44},
    "PR": {"N": 0.85, "L": 0.62, "H": 0.27},
    "UI": {"N": 0.85, "R": 0.62},
    "S":  {"U": 6.42, "C": 7.52},
    "C":  {"N": 0.0, "L": 0.22, "H": 0.56},
    "I":  {"N": 0.0, "L": 0.22, "H": 0.56},
    "A":  {"N": 0.0, "L": 0.22, "H": 0.56},
}


class AuditEngine:
    BASE_RULES = os.path.join(_BASE_DIR, "engine", "audit_rules.yaml")
    VENDOR_RULES = {
        "cato":       os.path.join(_BASE_DIR, "engine", "audit_rules_cato.yaml"),
        "cloudflare": os.path.join(_BASE_DIR, "engine", "audit_rules_cloudflare.yaml"),
    }
    EXEC_RULES = os.path.join(_BASE_DIR, "engine", "audit_rules_executive.yaml")

    def __init__(self, executive_profile: bool = False):
        self.audit_rules = []
        self._load_ruleset(self.BASE_RULES)
        if executive_profile:
            self._load_ruleset(self.EXEC_RULES)
        self._vendor_overlays_loaded = set()

    def _load_ruleset(self, path: str) -> None:
        try:
            with open(path) as f:
                rules = yaml.safe_load(f) or []
            existing_ids = {r["id"] for r in self.audit_rules}
            for rule in rules:
                if rule.get("id") in existing_ids:
                    self.audit_rules = [r for r in self.audit_rules
                                        if r["id"] != rule["id"]]
                self.audit_rules.append(rule)
        except FileNotFoundError:
            logger.warning(f"Ruleset not found: {path}")
        except Exception as e:
            logger.error(f"Failed loading {path}: {e}")

    def load_vendor_overlay(self, vendor: str) -> None:
        if vendor in self._vendor_overlays_loaded:
            return
        path = self.VENDOR_RULES.get(vendor)
        if path:
            self._load_ruleset(path)
            self._vendor_overlays_loaded.add(vendor)

    def run(self, parse_result: ParseResult) -> List[Finding]:
        self.load_vendor_overlay(parse_result.vendor)
        findings = []
        try:
            findings += self._check_rulebase_structure(parse_result)
            findings += self._check_rule_criteria(parse_result)
            findings += self._check_management_access(parse_result)
            findings += self._check_logging(parse_result)
            findings += self._check_segmentation(parse_result)
            findings += self._check_nat(parse_result)
            findings += self._check_protocol_specific(parse_result)
        except Exception as e:
            logger.error(f"Audit run error: {e}", exc_info=True)
        return self._deduplicate_findings(findings)

    # -----------------------------------------------------------------------
    # Criteria evaluator
    # -----------------------------------------------------------------------

    def _eval_criteria(self, rule: FirewallRule, criteria: dict) -> bool:
        if not criteria:
            return False
        if "and" in criteria:
            return all(self._eval_criteria(rule, c) for c in criteria["and"])
        if "or" in criteria:
            return any(self._eval_criteria(rule, c) for c in criteria["or"])
        if "not" in criteria:
            return not self._eval_criteria(rule, criteria["not"])
        field = criteria.get("field", "")
        operator = criteria.get("operator", "")
        value = criteria.get("value")
        try:
            field_val = getattr(rule, field, None)
            return self._eval_operator(field_val, operator, value)
        except Exception:
            return False

    def _eval_operator(self, field_val, operator, value) -> bool:
        if operator == "is_null":
            return field_val is None or field_val == []
        if field_val is None:
            return False
        fv = str(field_val).lower()
        v = str(value).lower() if value is not None else ""
        if operator == "equals":
            # Handle bool comparison
            if isinstance(field_val, bool):
                if str(value).lower() in ("true", "1", "yes"):
                    return field_val is True
                elif str(value).lower() in ("false", "0", "no"):
                    return field_val is False
            return fv == v
        if operator == "not":
            return fv != v
        if operator == "contains":
            if isinstance(field_val, list):
                return any(v in str(i).lower() for i in field_val)
            return v in fv
        if operator == "matches":
            if isinstance(field_val, list):
                port = int(value) if str(value).isdigit() else None
                if port:
                    for item in field_val:
                        if isinstance(item, (list, tuple)) and len(item) == 2:
                            if item[0] <= port <= item[1]:
                                return True
                        elif str(item) == str(port):
                            return True
            return str(value) == str(field_val)
        if operator == "in_range" and isinstance(value, list) and len(value) == 2:
            try:
                return float(value[0]) <= float(field_val) <= float(value[1])
            except Exception:
                return False
        if operator == "regex":
            return bool(re.search(str(value), str(field_val), re.I))
        if operator == "cidr":
            import ipaddress
            try:
                net = ipaddress.ip_network(str(value), strict=False)
                targets = field_val if isinstance(field_val, list) else [field_val]
                return any(
                    ipaddress.ip_network(str(a), strict=False).subnet_of(net)
                    for a in targets if a and "/" in str(a)
                )
            except Exception:
                return False
        return False

    # -----------------------------------------------------------------------
    # CVSS Calculator
    # -----------------------------------------------------------------------

    def _compute_cvss_vector(self, rule_def: dict) -> Optional[str]:
        comps = rule_def.get("cvss_components")
        if not comps:
            return rule_def.get("cvss_vector")
        try:
            av = str(comps.get("AV", "N"))
            ac = str(comps.get("AC", "L"))
            pr = str(comps.get("PR", "N"))
            ui = str(comps.get("UI", "N"))
            s  = str(comps.get("S", "U"))
            c  = str(comps.get("C", "N"))
            i  = str(comps.get("I", "N"))
            a  = str(comps.get("A", "N"))
            return f"CVSS:3.1/AV:{av}/AC:{ac}/PR:{pr}/UI:{ui}/S:{s}/C:{c}/I:{i}/A:{a}"
        except Exception:
            return None

    def _compute_cvss_score(self, vector: Optional[str]) -> Optional[float]:
        if not vector or not vector.startswith("CVSS:3.1/"):
            return None
        try:
            parts = dict(p.split(":") for p in vector.split("/")[1:])
            av = parts["AV"]; ac = parts["AC"]; pr = parts["PR"]; ui = parts["UI"]
            s  = parts["S"];  c  = parts["C"];  i  = parts["I"];  a  = parts["A"]
            w = CVSS_WEIGHTS
            isc_base = 1 - (1 - w["C"][c]) * (1 - w["I"][i]) * (1 - w["A"][a])
            if s == "U":
                isc = 6.42 * isc_base
            else:
                isc = 7.52 * (isc_base - 0.029) - 3.25 * (isc_base - 0.02) ** 15
            if isc <= 0:
                return 0.0
            eac = 8.22 * w["AV"][av] * w["AC"][ac] * w["PR"][pr] * w["UI"][ui]
            if s == "U":
                score = min(isc + eac, 10)
            else:
                score = min(1.08 * (isc + eac), 10)
            return math.ceil(score * 10) / 10
        except Exception as e:
            logger.debug(f"CVSS calc error: {e}")
            return None

    # -----------------------------------------------------------------------
    # Finding factory
    # -----------------------------------------------------------------------

    def _make_finding(self, audit_rule_id: str, triggered_rules: list,
                      config_file: str, vendor: str) -> Finding:
        rule_def = next((r for r in self.audit_rules
                         if r.get("id") == audit_rule_id), {})
        frameworks = rule_def.get("frameworks", [])
        primary = frameworks[0] if frameworks else {}
        additional = frameworks[1:] if len(frameworks) > 1 else []
        triggered_lines = sorted(set(
            r.line_number for r in triggered_rules if r.line_number))
        triggered_raw = list(dict.fromkeys(
            line for r in triggered_rules for line in r.raw_lines))[:20]
        vector = self._compute_cvss_vector(rule_def)
        score = self._compute_cvss_score(vector)
        return Finding(
            id=str(uuid.uuid4()),
            title=rule_def.get("title", audit_rule_id),
            description=rule_def.get("description", ""),
            impact=rule_def.get("impact", ""),
            recommendation=rule_def.get("recommendation", ""),
            risk=str(rule_def.get("severity", "Medium")).capitalize(),
            cvss_score=score,
            cvss_vector=vector,
            framework=primary.get("id", ""),
            framework_section=primary.get("section", ""),
            framework_control_name=primary.get("control", ""),
            framework_requirement=primary.get("requirement", ""),
            additional_frameworks=[
                {"framework": f.get("id", ""), "section": f.get("section", ""),
                 "control_name": f.get("control", ""),
                 "requirement": f.get("requirement", "")}
                for f in additional],
            triggered_lines=triggered_lines,
            triggered_raw=triggered_raw,
            config_file=config_file,
            vendor=vendor,
            audit_rule_id=audit_rule_id,
            rule_ids=[r.rule_id for r in triggered_rules],
            analyst_notes="",
            remediation_effort=rule_def.get("remediation_effort", "short_term"),
            timestamp=datetime.now().isoformat(),
        )

    def _make_finding_no_rules(self, audit_rule_id: str, config_file: str,
                                vendor: str, extra_lines: list = None,
                                extra_raw: list = None) -> Finding:
        """Make a finding not tied to specific triggered rules."""
        rule_def = next((r for r in self.audit_rules
                         if r.get("id") == audit_rule_id), {})
        frameworks = rule_def.get("frameworks", [])
        primary = frameworks[0] if frameworks else {}
        additional = frameworks[1:] if len(frameworks) > 1 else []
        vector = self._compute_cvss_vector(rule_def)
        score = self._compute_cvss_score(vector)
        return Finding(
            id=str(uuid.uuid4()),
            title=rule_def.get("title", audit_rule_id),
            description=rule_def.get("description", ""),
            impact=rule_def.get("impact", ""),
            recommendation=rule_def.get("recommendation", ""),
            risk=str(rule_def.get("severity", "Medium")).capitalize(),
            cvss_score=score,
            cvss_vector=vector,
            framework=primary.get("id", ""),
            framework_section=primary.get("section", ""),
            framework_control_name=primary.get("control", ""),
            framework_requirement=primary.get("requirement", ""),
            additional_frameworks=[
                {"framework": f.get("id", ""), "section": f.get("section", ""),
                 "control_name": f.get("control", ""),
                 "requirement": f.get("requirement", "")}
                for f in additional],
            triggered_lines=extra_lines or [],
            triggered_raw=extra_raw or [],
            config_file=config_file,
            vendor=vendor,
            audit_rule_id=audit_rule_id,
            rule_ids=[],
            analyst_notes="",
            remediation_effort=rule_def.get("remediation_effort", "short_term"),
            timestamp=datetime.now().isoformat(),
        )

    def _deduplicate_findings(self, findings: List[Finding]) -> List[Finding]:
        seen = {}
        for f in findings:
            key = (f.audit_rule_id, f.config_file)
            if key in seen:
                ex = seen[key]
                ex.triggered_lines = sorted(set(
                    ex.triggered_lines + f.triggered_lines))
                ex.triggered_raw = list(dict.fromkeys(
                    ex.triggered_raw + f.triggered_raw))[:20]
                ex.rule_ids = list(set(ex.rule_ids + f.rule_ids))
            else:
                seen[key] = f
        return sorted(seen.values(), key=lambda f: RISK_ORDER.get(f.risk, 5))

    # -----------------------------------------------------------------------
    # Check: rulebase structure
    # -----------------------------------------------------------------------

    def _check_rulebase_structure(self, pr: ParseResult) -> List[Finding]:
        findings = []
        try:
            rules = pr.rules
            filename = pr.filename
            vendor = pr.vendor

            # FW-001: No default-deny
            groups = {}
            for rule in rules:
                key = rule.interface_binding or "global"
                groups.setdefault(key, []).append(rule)

            for iface, grp_rules in groups.items():
                enabled = [r for r in grp_rules if r.enabled]
                if not enabled:
                    continue
                last = enabled[-1]
                is_deny_all = (
                    last.action == "deny"
                    and ("0.0.0.0/0" in last.src_addresses or not last.src_addresses)
                    and ("0.0.0.0/0" in last.dst_addresses or not last.dst_addresses)
                    and (not last.dst_ports)
                )
                if not is_deny_all:
                    f = self._make_finding_no_rules("FW-001", filename, vendor,
                                                    extra_lines=[last.line_number],
                                                    extra_raw=last.raw_lines)
                    findings.append(f)
                    break  # one finding per config

            # FW-004: Disabled rules
            disabled = [r for r in rules if not r.enabled]
            if disabled:
                f = self._make_finding("FW-004", disabled, filename, vendor)
                findings.append(f)

            # FW-005/FW-006: Duplicates and shadows
            dup_shadow_findings = self._check_duplicates_and_shadows(
                rules, filename, vendor)
            findings.extend(dup_shadow_findings)

        except Exception as e:
            logger.error(f"_check_rulebase_structure error: {e}", exc_info=True)
        return findings

    def _check_duplicates_and_shadows(self, rules: list, filename: str,
                                       vendor: str) -> List[Finding]:
        findings = []
        try:
            enabled = [r for r in rules if r.enabled]
            duplicates = []
            shadowed = []

            for i, r1 in enumerate(enabled):
                for j, r2 in enumerate(enabled):
                    if i >= j:
                        continue
                    # Duplicate check
                    if (r1.action == r2.action
                            and set(r1.src_addresses) == set(r2.src_addresses)
                            and set(r1.dst_addresses) == set(r2.dst_addresses)
                            and r1.protocol == r2.protocol):
                        duplicates.append(r2)

                    # Shadow check: r1 (earlier) shadows r2 (later)
                    if i < j and r1.action == r2.action:
                        src_covered = (
                            "0.0.0.0/0" in r1.src_addresses
                            or set(r2.src_addresses).issubset(set(r1.src_addresses))
                        )
                        dst_covered = (
                            "0.0.0.0/0" in r1.dst_addresses
                            or set(r2.dst_addresses).issubset(set(r1.dst_addresses))
                        )
                        port_covered = (
                            not r1.dst_ports
                            or r1.dst_ports == r2.dst_ports
                        )
                        if src_covered and dst_covered and port_covered:
                            shadowed.append(r2)

            if duplicates:
                f = self._make_finding("FW-005", duplicates, filename, vendor)
                findings.append(f)
            if shadowed:
                f = self._make_finding("FW-006", shadowed, filename, vendor)
                findings.append(f)

        except Exception as e:
            logger.error(f"_check_duplicates_and_shadows error: {e}", exc_info=True)
        return findings

    # -----------------------------------------------------------------------
    # Check: rule criteria (YAML-driven)
    # -----------------------------------------------------------------------

    def _check_rule_criteria(self, pr: ParseResult) -> List[Finding]:
        findings = []
        try:
            criteria_rules = [r for r in self.audit_rules
                              if r.get("check_type") == "rule_criteria"
                              and r.get("criteria")]
            for audit_rule in criteria_rules:
                matched = []
                for fw_rule in pr.rules:
                    try:
                        if self._eval_criteria(fw_rule, audit_rule["criteria"]):
                            matched.append(fw_rule)
                    except Exception:
                        pass
                if matched:
                    f = self._make_finding(audit_rule["id"], matched,
                                           pr.filename, pr.vendor)
                    findings.append(f)
        except Exception as e:
            logger.error(f"_check_rule_criteria error: {e}", exc_info=True)
        return findings

    # -----------------------------------------------------------------------
    # Check: management access
    # -----------------------------------------------------------------------

    def _check_management_access(self, pr: ParseResult) -> List[Finding]:
        findings = []
        try:
            mgmt_list = pr.metadata.get("management_access", [])

            # FW-030: Management not restricted
            unrestricted = [
                m for m in mgmt_list
                if m.get("network") in ("0.0.0.0", "any", "0.0.0.0/0")
            ]
            if unrestricted:
                f = self._make_finding_no_rules(
                    "FW-030", pr.filename, pr.vendor,
                    extra_raw=[str(m) for m in unrestricted])
                findings.append(f)

            # FW-031: HTTP management
            http_mgmt = [m for m in mgmt_list if m.get("proto") == "http"]
            if http_mgmt:
                f = self._make_finding_no_rules(
                    "FW-031", pr.filename, pr.vendor,
                    extra_raw=[str(m) for m in http_mgmt])
                findings.append(f)

            # FW-032: Telnet management
            telnet_mgmt = [m for m in mgmt_list if m.get("proto") == "telnet"]
            if telnet_mgmt:
                f = self._make_finding_no_rules(
                    "FW-032", pr.filename, pr.vendor,
                    extra_raw=[str(m) for m in telnet_mgmt])
                findings.append(f)

            # FW-033: No source restriction on SSH/HTTPS
            ssh_https = [m for m in mgmt_list
                         if m.get("proto") in ("ssh", "https")
                         and m.get("network") in ("0.0.0.0", "any", "0.0.0.0/0")]
            if ssh_https:
                f = self._make_finding_no_rules(
                    "FW-033", pr.filename, pr.vendor,
                    extra_raw=[str(m) for m in ssh_https])
                findings.append(f)

        except Exception as e:
            logger.error(f"_check_management_access error: {e}", exc_info=True)
        return findings

    # -----------------------------------------------------------------------
    # Check: logging
    # -----------------------------------------------------------------------

    def _check_logging(self, pr: ParseResult) -> List[Finding]:
        findings = []
        try:
            rules = pr.rules
            enabled = [r for r in rules if r.enabled]
            if not enabled:
                return findings

            # FW-042: No logging at all
            if all(not r.logging for r in enabled):
                f = self._make_finding_no_rules("FW-042", pr.filename, pr.vendor)
                findings.append(f)
                return findings

            # FW-040: Permit rules without logging
            permit_no_log = [r for r in enabled
                             if r.action == "permit" and not r.logging]
            if permit_no_log:
                f = self._make_finding("FW-040", permit_no_log,
                                       pr.filename, pr.vendor)
                findings.append(f)

            # FW-041: Deny rules without logging
            deny_no_log = [r for r in enabled
                           if r.action == "deny" and not r.logging]
            if deny_no_log:
                f = self._make_finding("FW-041", deny_no_log,
                                       pr.filename, pr.vendor)
                findings.append(f)

        except Exception as e:
            logger.error(f"_check_logging error: {e}", exc_info=True)
        return findings

    # -----------------------------------------------------------------------
    # Check: segmentation
    # -----------------------------------------------------------------------

    def _check_segmentation(self, pr: ParseResult) -> List[Finding]:
        findings = []
        try:
            interfaces = pr.metadata.get("interfaces", {})
            zones = pr.metadata.get("zones", [])

            # FW-052: Flat network (only 1 zone/interface)
            all_zones = set(list(interfaces.keys()) + list(zones))
            if len(all_zones) <= 1:
                f = self._make_finding_no_rules("FW-052", pr.filename, pr.vendor)
                findings.append(f)
                return findings

            # FW-050: No DMZ detected
            dmz_names = {"dmz", "perimeter", "screened", "semi-trusted"}
            has_dmz = any(
                z.lower() in dmz_names or "dmz" in z.lower()
                for z in all_zones
            )
            if not has_dmz:
                # Also check security levels for ASA
                if pr.vendor == "cisco_asa":
                    sec_levels = [
                        iface.get("security_level", -1)
                        for iface in interfaces.values()
                        if isinstance(iface, dict)
                    ]
                    # DMZ = sec level between 5 and 90
                    has_dmz = any(5 <= lvl <= 90 for lvl in sec_levels)
                elif len(all_zones) >= 3:
                    has_dmz = True  # 3+ zones implies segmentation

            if not has_dmz:
                f = self._make_finding_no_rules("FW-050", pr.filename, pr.vendor)
                findings.append(f)

            # FW-051: Direct internet-to-internal permit
            if pr.vendor == "cisco_asa":
                low_sec = {
                    name for name, iface in interfaces.items()
                    if isinstance(iface, dict) and iface.get("security_level", 100) == 0
                }
                high_sec = {
                    name for name, iface in interfaces.items()
                    if isinstance(iface, dict) and iface.get("security_level", 0) >= 90
                }
                direct = [
                    r for r in pr.rules
                    if r.action == "permit" and r.enabled
                    and r.src_zone in low_sec
                    and r.dst_zone in high_sec
                ]
                if direct:
                    f = self._make_finding("FW-051", direct, pr.filename, pr.vendor)
                    findings.append(f)

        except Exception as e:
            logger.error(f"_check_segmentation error: {e}", exc_info=True)
        return findings

    # -----------------------------------------------------------------------
    # Check: NAT
    # -----------------------------------------------------------------------

    def _check_nat(self, pr: ParseResult) -> List[Finding]:
        findings = []
        try:
            nat_rules = pr.metadata.get("nat_rules", [])
            import ipaddress

            RFC1918 = [
                ipaddress.ip_network("10.0.0.0/8"),
                ipaddress.ip_network("172.16.0.0/12"),
                ipaddress.ip_network("192.168.0.0/16"),
            ]

            def is_rfc1918(addr):
                try:
                    net = ipaddress.ip_network(str(addr), strict=False)
                    return any(net.subnet_of(r) for r in RFC1918)
                except Exception:
                    return False

            # FW-060: Internal IPs exposed without NAT
            nat_dst = {str(n.get("real_ip", "")) for n in nat_rules}
            exposed = [
                r for r in pr.rules
                if r.action == "permit" and r.enabled
                and any(is_rfc1918(a) for a in r.dst_addresses)
                and not any(a in nat_dst for a in r.dst_addresses)
                and "0.0.0.0/0" in r.src_addresses
            ]
            if exposed:
                f = self._make_finding("FW-060", exposed, pr.filename, pr.vendor)
                findings.append(f)

        except Exception as e:
            logger.error(f"_check_nat error: {e}", exc_info=True)
        return findings

    # -----------------------------------------------------------------------
    # Check: protocol-specific (delegates to rule_criteria YAML)
    # -----------------------------------------------------------------------

    def _check_protocol_specific(self, pr: ParseResult) -> List[Finding]:
        # Protocol-specific rules are handled via _check_rule_criteria
        # via the YAML criteria definitions
        return []

    # -----------------------------------------------------------------------
    # Framework summary helper (used by app.py)
    # -----------------------------------------------------------------------

    @staticmethod
    def compute_framework_summary(findings_dicts: list) -> dict:
        summary = {}
        for f in findings_dicts:
            fw = f.get("framework", "Unknown") or "Unknown"
            risk = f.get("risk", "Unknown")
            if fw not in summary:
                summary[fw] = {}
            summary[fw][risk] = summary[fw].get(risk, 0) + 1
        return summary
