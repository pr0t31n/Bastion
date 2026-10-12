#!/usr/bin/env python3
"""bastion.py — Firewall config audit CLI.

Replaces the prior Flask+SocketIO app.py with a pure-CLI orchestrator.
The audit engine (engine/) is untouched — it was already a pure
ParseResult → list[Finding] function. This wrapper provides:

  * argparse interface compatible with Helm dispatch
  * __VANTAGE_STATUS__/__VANTAGE_FINDING__/__VANTAGE_LOG__/__VANTAGE_ERR__
    tokens when BASTION_MANAGED=1 (so Helm picks up progress live)
  * Universal output: meta.json + findings.json + summary.json per
    CLAUDE.md §13 schema, written under <output_dir>
  * §13c-compliant output_file relative paths via pr0t31n_schema_compat
  * §14-compliant .log siblings for any external tool call (Bastion is
    pure-Python config parsing; this is a no-op unless future versions
    add subprocess calls)
  * UPPERCASE risk values per §13c (fixes the Bastion TitleCase violation
    flagged in the 2026-06-11 review)
  * Threat-intel IP/URL reputation checking against curated blocklists
  * GeoIP country mapping for IPs referenced in firewall rules

Architectural notes for the 2026-06-11 review:
  * Helm now dispatches Bastion via adapters/bastion.py.
  * Arbiter (post-narrowing) tracks Bastion findings via the universal
    findings.json — no per-tool HTTP hooks needed; the file IS the API.
  * No Flask, no SocketIO, no _auth — Helm provides all of those.

Backwards-compatibility hooks preserved for Helm + Arbiter:
  * --json-status                emit single-line JSON status to stdout
  * --emit-tokens                force token emission even when not managed
  * --config-dir / --output-dir  same naming as prior app.py paths

Usage:
    sudo python3 bastion.py --config-dir <dir> --output-dir <dir> [--vendor cisco_asa]
    sudo python3 bastion.py --config <single-file> --output-dir <dir>
"""
from __future__ import annotations

import argparse
import ipaddress
import json
import logging
import os
import re
import sys
import traceback
import uuid
from datetime import datetime, timezone
from pathlib import Path


VERSION = Path(__file__).resolve().parent.joinpath("VERSION").read_text().strip()


# ── Shared schema helpers ──────────────────────────────────────────────


_HERE = Path(__file__).parent.resolve()
sys.path.insert(0, str(_HERE))
if "/opt/pr0t31n/shared" not in sys.path:
    sys.path.insert(0, "/opt/pr0t31n/shared")

try:
    import pr0t31n_schema as _us
    _HAVE_SCHEMA = True
except ImportError:
    _us = None
    _HAVE_SCHEMA = False

try:
    import pr0t31n_schema_compat as _sc
    _HAVE_COMPAT = True
except ImportError:
    _sc = None
    _HAVE_COMPAT = False

try:
    import pr0t31n_event_log as _el
    _HAVE_EVENTLOG = True
except ImportError:
    _el = None
    _HAVE_EVENTLOG = False

try:
    import pr0t31n_threat_intel as _ti
    _HAVE_THREAT_INTEL = True
except ImportError:
    _ti = None
    _HAVE_THREAT_INTEL = False

# §13b run-dir logger (scan.log + scan.log.json + errors.log + errors.log.json).
# Set in main() once the run directory is known; _log/_err forward to it.
_RUNLOG = None


# Engine (pure-Python, untouched from Flask era)
from engine.parsers.base import detect_vendor, get_parser
from engine.audit_engine import AuditEngine


# ── Token emission ─────────────────────────────────────────────────────


_MANAGED = os.environ.get("BASTION_MANAGED") == "1" or \
           os.environ.get("VANTAGE_MANAGED") == "1"


def _ts() -> str:
    return datetime.now().strftime("%H:%M:%S")


def _emit(token: str, msg: str) -> None:
    if _MANAGED:
        ts = datetime.now().isoformat()
        sys.stdout.write(f"{token} [{ts}] {msg}\n"); sys.stdout.flush()
    else:
        print(f"[{_ts()}] {msg}", flush=True)


def _log(msg: str) -> None:
    _emit("__VANTAGE_LOG__:", msg)
    if _RUNLOG is not None:
        try: _RUNLOG.info(msg)
        except Exception: pass


def _err(msg: str) -> None:
    _emit("__VANTAGE_ERR__:", msg)
    if _RUNLOG is not None:
        try: _RUNLOG.error(msg)
        except Exception: pass


def _status(payload: dict) -> None:
    _emit("__VANTAGE_STATUS__:", json.dumps(payload, default=str))


def _finding_token(finding: dict) -> None:
    _emit("__VANTAGE_FINDING__:", json.dumps(finding, default=str))


# ── Risk normalisation (Bastion native was TitleCase — schema needs UPPERCASE) ──


def _canon_risk(risk: str | None) -> str:
    if _HAVE_COMPAT: return _sc.normalize_risk(risk)
    rs = (risk or "").strip()
    return {
        "Critical": "CRITICAL", "High": "HIGH", "Medium": "MEDIUM",
        "Low": "LOW", "Informational": "INFO", "INFORMATIONAL": "INFO",
        "Info": "INFO",
    }.get(rs, rs.upper() if rs.upper() in ("CRITICAL","HIGH","MEDIUM","LOW","INFO") else "INFO")


# ── Audit workflow ─────────────────────────────────────────────────────


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _write_finding_evidence(fd: dict, output_dir: Path, vendor: str,
                            config_name: str) -> str:
    """§14i: persist a config excerpt (output) + an audit transcript .log per
    finding, both run-dir-relative. Bastion has no subprocess/HTTP, so this is
    the config-audit analogue of the §14 tool .log. Returns the comma-joined
    relative paths, or '' on failure."""
    try:
        ts = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
        rid = fd.get("audit_rule_id") or fd.get("id") or fd.get("title") or "finding"
        safe = re.sub(r"[^\w.-]", "_", str(rid))[:60] or "finding"
        vsafe = re.sub(r"[^\w.-]", "_", str(vendor or "config")) or "config"
        evdir = Path(output_dir) / "evidence" / vsafe
        evdir.mkdir(parents=True, exist_ok=True)
        lines = fd.get("triggered_lines") or []
        raw = fd.get("triggered_raw") or []
        if lines and raw and len(lines) == len(raw):
            excerpt_body = "\n".join(f"{ln}: {txt}" for ln, txt in zip(lines, raw))
        elif raw:
            excerpt_body = "\n".join(str(x) for x in raw)
        else:
            excerpt_body = "(no triggering config lines recorded)"
        excerpt = evdir / f"{safe}_{ts}_excerpt.txt"
        excerpt.write_text(excerpt_body, encoding="utf-8")
        logf = evdir / f"{safe}_{ts}.log"
        logf.write_text(
            f"# Bastion config-audit evidence\n"
            f"# config:     {config_name}\n"
            f"# vendor:     {vendor}\n"
            f"# rule:       {fd.get('audit_rule_id', '')}\n"
            f"# finding:    {fd.get('title', '')}\n"
            f"# risk:       {fd.get('risk', '')}\n"
            f"# framework:  {fd.get('framework', '')} {fd.get('framework_section', '')}\n"
            f"# triggered_lines: {lines}\n"
            f"# excerpt_file: {excerpt.name}\n",
            encoding="utf-8")
        return ",".join(str(p.relative_to(Path(output_dir))) for p in (excerpt, logf))
    except Exception:
        return ""


def audit_one_config(config_path: Path, *, vendor: str | None,
                      output_dir: Path) -> list[dict]:
    """Parse one config file, run AuditEngine, return list of finding dicts.
    Each finding is normalised through Bastion's TitleCase → UPPERCASE."""
    cfg_size = config_path.stat().st_size
    _log(f"[audit] Parsing config {config_path.name} ({cfg_size:,} bytes)...")
    text = config_path.read_text(encoding="utf-8", errors="replace")
    line_count = text.count("\n")
    if vendor is None:
        _log(f"[audit] Auto-detecting vendor for {config_path.name} ({line_count} lines)...")
        vendor = detect_vendor(text)
        _log(f"[audit] Vendor detected as '{vendor}' for {config_path.name}")
    else:
        _log(f"[audit] Using specified vendor '{vendor}' for {config_path.name}")
    parser_cls = get_parser(vendor)
    parser = parser_cls()
    _log(f"[audit] Running {vendor} parser on {config_path.name}...")
    parse_result = parser.parse(text)
    rule_count = len(parse_result.rules) if hasattr(parse_result, "rules") else 0
    _log(f"[audit] Parsed {config_path.name} — {rule_count} firewall rules extracted")

    engine = AuditEngine()
    _log(f"[audit] Running audit engine against {rule_count} rules from {config_path.name}...")
    findings = engine.run(parse_result)
    _log(f"[audit] Audit engine complete — {len(findings)} findings from {config_path.name}")

    rel_config = config_path.name
    if _HAVE_COMPAT:
        try:
            rel_config = _sc.to_relative_output_file(str(config_path), str(output_dir))
        except Exception:
            pass

    risk_tally = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    out: list[dict] = []
    for f in findings:
        try:
            fd = f.to_dict() if hasattr(f, "to_dict") else dict(f)
        except Exception:
            fd = vars(f) if hasattr(f, "__dict__") else {}
        fd["risk"] = _canon_risk(fd.get("risk"))
        r = fd["risk"]
        if r in risk_tally:
            risk_tally[r] += 1
        ev = _write_finding_evidence(fd, output_dir, vendor, config_path.name)
        if ev:
            fd["output_file"] = ev
        elif not fd.get("output_file"):
            fd["output_file"] = rel_config
        if not fd.get("tool"): fd["tool"] = "bastion"
        _log(f"[audit] Finding: [{r}] {fd.get('title', '?')} (rule: {fd.get('audit_rule_id', 'n/a')})")
        out.append(fd)
        _finding_token(fd)
    parts = ", ".join(f"{k}: {v}" for k, v in risk_tally.items() if v)
    _log(f"[audit] {config_path.name} complete — {len(out)} findings ({parts or 'none'})")
    return out


# ── Threat-intel helpers ──────────────────────────────────────────────


def _is_skip_addr(addr: str) -> bool:
    """Return True for addresses that should be skipped during TI lookup."""
    addr = addr.strip().lower()
    if addr in ("any", "all", "0.0.0.0", "0.0.0.0/0", "::", "::/0", ""):
        return True
    try:
        if "/" in addr:
            net = ipaddress.ip_network(addr, strict=False)
            return net.is_private or net.is_loopback or net.is_link_local or net.is_reserved
        else:
            a = ipaddress.ip_address(addr)
            return a.is_private or a.is_loopback or a.is_link_local or a.is_reserved
    except ValueError:
        return True


def _extract_rule_ips(configs: list[Path], vendor_override: str | None) -> list[dict]:
    """Re-parse configs and extract (ip, rule_id, direction, action, config_file, raw_lines)."""
    results = []
    for cfg in configs:
        try:
            text = cfg.read_text(encoding="utf-8", errors="replace")
        except Exception:
            continue
        v = vendor_override or detect_vendor(text)
        parser_cls = get_parser(v)
        parser = parser_cls()
        try:
            pr = parser.parse(text)
        except Exception:
            continue
        for rule in pr.rules:
            if not rule.enabled:
                continue
            for addr in rule.src_addresses:
                if not _is_skip_addr(addr):
                    results.append({
                        "ip": addr, "rule_id": rule.rule_id,
                        "rule_name": rule.rule_name,
                        "direction": "source", "action": rule.action.lower(),
                        "config_file": cfg.name, "raw_lines": rule.raw_lines,
                        "line_number": rule.line_number,
                    })
            for addr in rule.dst_addresses:
                if not _is_skip_addr(addr):
                    results.append({
                        "ip": addr, "rule_id": rule.rule_id,
                        "rule_name": rule.rule_name,
                        "direction": "destination", "action": rule.action.lower(),
                        "config_file": cfg.name, "raw_lines": rule.raw_lines,
                        "line_number": rule.line_number,
                    })
    return results


def check_rule_ips_threat_intel(configs: list[Path], output_dir: Path,
                                threat_db, vendor_override: str | None = None) -> list[dict]:
    """Check all public IPs in firewall rules against threat-intel blocklists.
    Returns a list of finding dicts ready to merge into all_findings."""
    _log(f"[threat-intel] Extracting public IPs from {len(configs)} config file(s)...")
    rule_ips = _extract_rule_ips(configs, vendor_override)
    if not rule_ips:
        _log("[threat-intel] No public IPs found in firewall rules — skipping TI checks")
        return []
    _log(f"[threat-intel] Extracted {len(rule_ips)} rule-IP entries — checking against blocklists...")

    seen: set[tuple[str, str, str]] = set()
    findings: list[dict] = []
    ti_evidence_dir = Path(output_dir) / "evidence" / "threat_intel"
    ti_evidence_dir.mkdir(parents=True, exist_ok=True)
    all_hits: list[dict] = []

    for entry in rule_ips:
        ip_str = entry["ip"]
        base_ip = ip_str.split("/")[0] if "/" in ip_str else ip_str
        dedup_key = (base_ip, entry["rule_id"], entry["direction"])
        if dedup_key in seen:
            continue
        seen.add(dedup_key)

        hit = threat_db.lookup_ip(base_ip)
        if not hit:
            continue

        _log(f"[threat-intel] TI hit on {base_ip} — classification: {hit.classification}, "
             f"sources: {', '.join(hit.sources)} — resolving GeoIP...")
        geo = threat_db.geoip(base_ip)
        geo_str = f" ({geo.country_name}, {geo.country_code})" if geo else ""
        if geo:
            _log(f"[threat-intel] {base_ip} geolocated to {geo.country_name} ({geo.country_code})")
        else:
            _log(f"[threat-intel] {base_ip} — GeoIP data unavailable")

        ev_path = ti_evidence_dir / f"{base_ip.replace(':', '_')}_threat_hit.json"
        ev_data = {
            "ip": base_ip, "hit": hit.as_dict(),
            "geo": geo.as_dict() if geo else None,
            "rule_id": entry["rule_id"], "rule_name": entry["rule_name"],
            "direction": entry["direction"], "action": entry["action"],
            "config_file": entry["config_file"],
            "raw_lines": entry["raw_lines"],
            "checked_at": _now_iso(),
        }
        ev_path.write_text(json.dumps(ev_data, indent=2, default=str), encoding="utf-8")
        rel_ev = str(ev_path.relative_to(output_dir))

        all_hits.append(ev_data)

        is_permit = entry["action"] == "permit"
        is_known = hit.classification == "known_malicious"
        sources_str = ", ".join(hit.sources)
        tags_str = ", ".join(hit.tags) if hit.tags else "unclassified"

        if is_known and is_permit:
            cat_id = "BA-TI-001"
            risk = "HIGH"
            title = f"Firewall Rule Permits Traffic to Known Malicious IP ({base_ip})"
            desc = (
                f"Firewall rule '{entry['rule_id']}' in {entry['config_file']} "
                f"permits traffic with {entry['direction']} address {base_ip}{geo_str} "
                f"which is flagged as KNOWN MALICIOUS by: {sources_str}. "
                f"Tags: {tags_str}. Confidence: high."
            )
            impact = (
                f"This rule allows network traffic to/from an IP address confirmed "
                f"as malicious infrastructure (C2 server, botnet node, compromised "
                f"host, or hijacked network). Active communication with this IP "
                f"may indicate an ongoing compromise, data exfiltration, or "
                f"command-and-control activity."
            )
            remediation = (
                f"1. Immediately add a deny rule for {base_ip} above this permit rule. "
                f"2. Investigate firewall logs for any traffic to/from {base_ip}. "
                f"3. If traffic occurred, treat as a potential incident — isolate "
                f"affected hosts and begin forensic analysis. "
                f"4. Review rule '{entry['rule_id']}' to determine if it can be narrowed."
            )
        elif is_known and not is_permit:
            cat_id = "BA-TI-003"
            risk = "INFO"
            title = f"Firewall Rule Blocks Known Malicious IP ({base_ip})"
            desc = (
                f"Firewall rule '{entry['rule_id']}' in {entry['config_file']} "
                f"correctly denies traffic with {entry['direction']} address "
                f"{base_ip}{geo_str}, which is flagged as KNOWN MALICIOUS by: "
                f"{sources_str}. Tags: {tags_str}."
            )
            impact = (
                f"Positive observation: the firewall is actively blocking traffic "
                f"to/from a confirmed malicious IP. This indicates effective "
                f"threat-intel integration in the firewall policy."
            )
            remediation = (
                f"No action required — the deny rule is correctly blocking {base_ip}. "
                f"Ensure this rule remains in place and is not overridden by a "
                f"broader permit rule above it in the policy."
            )
        elif not is_known and is_permit:
            cat_id = "BA-TI-002"
            risk = "MEDIUM"
            title = f"Firewall Rule Permits Traffic to Suspected Malicious IP ({base_ip})"
            desc = (
                f"Firewall rule '{entry['rule_id']}' in {entry['config_file']} "
                f"permits traffic with {entry['direction']} address {base_ip}{geo_str} "
                f"which is flagged as SUSPECTED malicious by: {sources_str}. "
                f"Tags: {tags_str}. Confidence: moderate — based on honeypot hits, "
                f"scan activity, or crowdsourced reports."
            )
            impact = (
                f"This rule allows traffic to/from an IP reported as suspicious "
                f"by multiple threat-intelligence sources. While not confirmed "
                f"malicious, the IP has been observed in attack activity, scanning, "
                f"or brute-force attempts. Permitting traffic increases exposure "
                f"to potential threats."
            )
            remediation = (
                f"1. Review whether traffic to/from {base_ip} is expected and "
                f"business-justified. 2. Check firewall logs for recent connections. "
                f"3. If not justified, add a deny rule. 4. If justified, document "
                f"the business reason and monitor the connection."
            )
        else:
            continue

        fd = {
            "id": str(uuid.uuid4()),
            "tool": "bastion",
            "title": title,
            "datetime": _now_iso(),
            "ip": base_ip,
            "port": 0,
            "hostname": "",
            "risk": risk,
            "command": f"pr0t31n_threat_intel.lookup_ip('{base_ip}')",
            "description": desc,
            "output": json.dumps(hit.as_dict(), indent=2),
            "output_file": rel_ev,
            "cves": "",
            "sources": f"bastion-threat-intel ({sources_str})",
            "service": "",
            "affected": base_ip,
            "exploitdb": False,
            "metasploit": False,
            "exploit_details": [],
            "remediation": remediation,
            "impact": impact,
            "catalogue_id": cat_id,
            "phase": "threat_intel",
            "scope": None,
        }
        if geo:
            fd["_x_country_code"] = geo.country_code
            fd["_x_country_name"] = geo.country_name

        _log(f"[threat-intel] Finding: [{risk}] {title}")
        findings.append(fd)
        _finding_token(fd)

    _log(f"[threat-intel] IP reputation check complete — {len(seen)} unique IPs checked, "
         f"{len(all_hits)} hits, {len(findings)} findings generated")
    report_path = Path(output_dir) / "threat_intel_report.json"
    report_path.write_text(json.dumps({
        "checked_at": _now_iso(),
        "total_rule_ips_checked": len(seen),
        "total_hits": len(all_hits),
        "known_malicious_hits": sum(1 for h in all_hits if h["hit"]["classification"] == "known_malicious"),
        "suspected_hits": sum(1 for h in all_hits if h["hit"]["classification"] == "suspected"),
        "hits": all_hits,
    }, indent=2, default=str), encoding="utf-8")

    return findings


def build_rule_geo_summary(configs: list[Path], output_dir: Path,
                           threat_db, vendor_override: str | None = None) -> None:
    """Build a per-country summary of all public IPs in firewall rules."""
    rule_ips = _extract_rule_ips(configs, vendor_override)
    if not rule_ips:
        _log("[geo] No public IPs to geolocate — skipping summary")
        return

    _log(f"[geo] Geolocating {len(rule_ips)} rule-IP entries...")
    countries: dict[str, dict] = {}
    seen_ips: set[str] = set()

    for entry in rule_ips:
        ip_str = entry["ip"]
        base_ip = ip_str.split("/")[0] if "/" in ip_str else ip_str
        if base_ip in seen_ips:
            rec_key = base_ip
        else:
            seen_ips.add(base_ip)
            rec_key = base_ip

        geo = threat_db.geoip(base_ip)
        if not geo:
            cc = "XX"
            cn = "Unknown"
        else:
            cc = geo.country_code or "XX"
            cn = geo.country_name or "Unknown"

        if cc not in countries:
            countries[cc] = {
                "country_code": cc, "country_name": cn,
                "permit_ips": set(), "deny_ips": set(),
                "permit_rules": 0, "deny_rules": 0,
                "total_rules": 0,
            }
        c = countries[cc]
        c["total_rules"] += 1
        if entry["action"] == "permit":
            c["permit_ips"].add(base_ip)
            c["permit_rules"] += 1
        else:
            c["deny_ips"].add(base_ip)
            c["deny_rules"] += 1

    for c in countries.values():
        c["permit_ips"] = sorted(c["permit_ips"])
        c["deny_ips"] = sorted(c["deny_ips"])
        c["unique_ips"] = len(set(c["permit_ips"]) | set(c["deny_ips"]))

    geo_summary = {
        "generated_at": _now_iso(),
        "total_public_ips": len(seen_ips),
        "total_countries": len(countries),
        "countries": sorted(countries.values(), key=lambda x: -x["total_rules"]),
    }

    _log(f"[geo] Geographic distribution: {len(seen_ips)} unique IPs across "
         f"{len(countries)} countries")
    top3 = sorted(countries.values(), key=lambda x: -x["total_rules"])[:3]
    for c in top3:
        _log(f"[geo]   • {c['country_name']} ({c['country_code']}): "
             f"{c['unique_ips']} IPs, {c['permit_rules']} permit / {c['deny_rules']} deny rules")

    (Path(output_dir) / "geo_summary.json").write_text(
        json.dumps(geo_summary, indent=2, default=str), encoding="utf-8")


def main() -> int:
    p = argparse.ArgumentParser(
        prog="bastion",
        description="Firewall config audit (pure-CLI orchestrator)")
    p.add_argument("--config", help="Single config file to audit")
    p.add_argument("--config-dir", help="Directory containing config files")
    p.add_argument("--vendor", default=None,
                   help="Override auto-detected vendor (cisco_asa, palo_alto, ...)")
    p.add_argument("--output-dir", required=True,
                   help="Universal-output run directory")
    p.add_argument("--client-short", default="bastion-cli")
    p.add_argument("--client-name", default="Bastion CLI run")
    p.add_argument("--json-status", action="store_true",
                   help="Emit single-line JSON summary on stdout at end")
    p.add_argument("--emit-tokens", action="store_true",
                   help="Force __VANTAGE_* tokens even when BASTION_MANAGED is unset")
    p.add_argument("--skip-threat-intel", action="store_true",
                   help="Skip threat-intelligence and GeoIP checks")
    ns = p.parse_args()

    global _MANAGED
    if ns.emit_tokens:
        _MANAGED = True

    if not ns.config and not ns.config_dir:
        print("ERROR: --config or --config-dir is required", file=sys.stderr)
        return 2

    out_dir = Path(ns.output_dir).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)
    logging.basicConfig(level=logging.INFO,
                        format="%(asctime)s %(levelname)s [bastion-cli] %(message)s")

    # §13b: scan.log + scan.log.json + errors.log + errors.log.json in the run dir
    global _RUNLOG
    if _HAVE_EVENTLOG:
        try:
            _RUNLOG = _el.EventLogger(out_dir / "scan.log",
                                      errors_path=out_dir / "errors.log")
        except Exception as exc:
            _err(f"event log init failed: {exc}")

    # Meta.json (universal §13)
    if _HAVE_SCHEMA:
        try:
            meta = _us.make_meta(
                tool="bastion", version=VERSION,
                client_short=ns.client_short, client_name=ns.client_name,
                engagement_name="bastion run",
                target=ns.config or ns.config_dir)
            _us.atomic_write_json(out_dir / "meta.json", meta)
        except Exception as exc:
            _err(f"meta.json write failed: {exc}")

    _log(f"[startup] Bastion v{VERSION} — firewall configuration security auditor")
    _log(f"[startup] Output directory: {out_dir}")
    if _RUNLOG:
        _RUNLOG.event(f"Bastion v{VERSION} started")

    # Collect configs
    _log(f"[config] Collecting firewall configuration files...")
    configs: list[Path] = []
    if ns.config:
        configs.append(Path(ns.config).resolve())
        _log(f"[config] Single config specified: {ns.config}")
    if ns.config_dir:
        cdir = Path(ns.config_dir).resolve()
        _log(f"[config] Scanning directory {cdir} for config files...")
        for ext in ("*.cfg", "*.conf", "*.txt", "*.xml", "*.json"):
            configs.extend(cdir.rglob(ext))

    if not configs:
        _err("[config] No configuration files found — aborting")
        return 3

    _log(f"[config] Found {len(configs)} configuration file(s) to audit")
    for c in configs:
        _log(f"[config]   • {c.name} ({c.stat().st_size:,} bytes)")
    _status({"phase": "starting", "configs": len(configs)})

    # ── Audit phase ──────────────────────────────────────────────────
    all_findings: list[dict] = []
    started_at = _now_iso()
    if _RUNLOG:
        _RUNLOG.event(f"Audit phase started — {len(configs)} config(s)")
    for i, cfg in enumerate(configs, 1):
        _status({"phase": "audit", "current": i, "total": len(configs),
                 "config": cfg.name})
        _log(f"[audit] ── Config {i}/{len(configs)}: {cfg.name} ──")
        try:
            fl = audit_one_config(cfg, vendor=ns.vendor, output_dir=out_dir)
            all_findings.extend(fl)
        except Exception as exc:
            _err(f"[audit] FAILED on {cfg.name}: {exc}")
            logging.error("audit failed on %s: %s", cfg.name, exc, exc_info=True)
    _log(f"[audit] Audit phase complete — {len(all_findings)} total findings from "
         f"{len(configs)} config(s)")
    if _RUNLOG:
        _RUNLOG.event(f"Audit phase complete — {len(all_findings)} findings")
    ended_at = _now_iso()

    # ── Threat-intel phase ────────────────────────────────────────────
    if _HAVE_THREAT_INTEL and not ns.skip_threat_intel:
        try:
            _status({"phase": "threat_intel", "step": "loading blocklists"})
            _log("[threat-intel] Loading threat intelligence database...")
            if _RUNLOG:
                _RUNLOG.event("Threat-intel phase started")
            threat_db = _ti.ThreatIntelDB()
            stats = threat_db.stats()
            _log(f"[threat-intel] Database loaded — {stats['total_ips']} IPs, "
                 f"{stats['cidr_ranges']} CIDRs, {stats['urls']} URLs, "
                 f"GeoIP={'available' if stats.get('geoip_available') else 'unavailable'}")
            if _RUNLOG:
                _RUNLOG.event(
                    f"Threat-intel DB loaded: {stats['total_ips']} IPs, "
                    f"{stats['cidr_ranges']} CIDRs, "
                    f"GeoIP={stats['geoip_available']}")

            _status({"phase": "threat_intel", "step": "checking rule IPs"})
            _log("[threat-intel] Checking firewall rule IPs against blocklists...")
            ti_findings = check_rule_ips_threat_intel(
                configs, out_dir, threat_db, vendor_override=ns.vendor)
            all_findings.extend(ti_findings)
            if ti_findings:
                _log(f"[threat-intel] Malicious IPs found — {len(ti_findings)} findings generated, "
                     f"building GeoIP country summary...")
            else:
                _log("[threat-intel] No malicious IPs detected in firewall rules")

            _status({"phase": "threat_intel", "step": "building GeoIP summary"})
            _log("[threat-intel] Building geographic distribution summary for rule IPs...")
            build_rule_geo_summary(configs, out_dir, threat_db,
                                   vendor_override=ns.vendor)
            _log("[threat-intel] GeoIP summary written to geo_summary.json")
            if _RUNLOG:
                _RUNLOG.event(f"Threat-intel phase complete — {len(ti_findings)} findings")
        except Exception as exc:
            _err(f"[threat-intel] Phase failed: {exc}")
            logging.error("threat-intel failed: %s", exc, exc_info=True)
    elif ns.skip_threat_intel:
        _log("[threat-intel] Skipped (--skip-threat-intel flag set)")
    elif not _HAVE_THREAT_INTEL:
        _log("[threat-intel] Skipped (pr0t31n_threat_intel module not available)")

    # ── Output phase ─────────────────────────────────────────────────
    _log(f"[output] Writing universal output files ({len(all_findings)} findings)...")
    if _HAVE_COMPAT:
        try:
            _sc.write_universal_findings(out_dir, all_findings,
                                          tool="bastion", version=VERSION)
            _log("[output] findings.json written (universal schema)")
        except Exception as exc:
            _err(f"[output] findings.json write failed: {exc}")
    elif _HAVE_SCHEMA:
        for f in all_findings:
            f["risk"] = _canon_risk(f.get("risk"))
        _us.write_universal_findings(out_dir, all_findings, tool="bastion",
                                      scope=None, phase="audit")
        _log("[output] findings.json written (schema fallback)")

    # Summary
    risk_counts = {"CRITICAL":0,"HIGH":0,"MEDIUM":0,"LOW":0,"INFO":0}
    for f in all_findings:
        r = _canon_risk(f.get("risk"))
        if r in risk_counts: risk_counts[r] += 1
    summary = {
        "tool": "bastion", "version": VERSION,
        "scan_start": started_at, "scan_end": ended_at,
        "target": ns.config or ns.config_dir,
        "success": True, "total_findings": len(all_findings),
        "risk_counts": risk_counts, "config_files": [str(c) for c in configs],
    }
    if _HAVE_COMPAT:
        try:
            _sc.write_summary(out_dir, summary)
            _log("[output] summary.json written")
        except Exception as exc:
            _err(f"[output] summary.json write failed: {exc}")
    elif _HAVE_SCHEMA:
        _us.write_summary(out_dir, _us.make_summary(
            tool="bastion", version=VERSION,
            scan_start=started_at, scan_end=ended_at,
            target=ns.config or ns.config_dir,
            success=True, total_findings=len(all_findings),
            risk_counts=risk_counts))
        _log("[output] summary.json written")
    else:
        (out_dir / "summary.json").write_text(
            json.dumps(summary, indent=2, default=str), encoding="utf-8")
        _log("[output] summary.json written (standalone)")

    parts = ", ".join(f"{k}: {v}" for k, v in risk_counts.items() if v)
    _log(f"[complete] Bastion v{VERSION} finished — {len(all_findings)} findings ({parts or 'none'})")
    _log(f"[complete] Output: {out_dir}")
    _status({"phase": "complete", "total_findings": len(all_findings),
             "risk_counts": risk_counts})
    if _RUNLOG:
        _RUNLOG.event(f"Bastion v{VERSION} complete — {len(all_findings)} findings")

    if ns.json_status:
        print(json.dumps({"ok": True, "total_findings": len(all_findings),
                           "risk_counts": risk_counts,
                           "run_dir": str(out_dir)}))
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        _err("interrupted")
        sys.exit(130)
    except Exception as exc:
        _err(f"fatal: {exc}")
        traceback.print_exc()
        sys.exit(1)
