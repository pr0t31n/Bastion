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
import json
import logging
import os
import re
import sys
import traceback
from datetime import datetime, timezone
from pathlib import Path


VERSION = "2.1.0"   # 2.x = pure-CLI; 1.x was Flask+SocketIO


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

# §13b run-dir logger (scan.log + scan.log.json + errors.log + errors.log.json).
# Set in main() once the run directory is known; _log/_err forward to it.
_RUNLOG = None


# Engine (pure-Python, untouched from Flask era)
from engine.parsers.base import detect_vendor, get_parser
from engine.audit_engine import AuditEngine


# ── Token emission ─────────────────────────────────────────────────────


_MANAGED = os.environ.get("BASTION_MANAGED") == "1" or \
           os.environ.get("VANTAGE_MANAGED") == "1"


def _emit(token: str, msg: str) -> None:
    if _MANAGED:
        sys.stdout.write(f"{token} {msg}\n"); sys.stdout.flush()


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
    text = config_path.read_text(encoding="utf-8", errors="replace")
    if vendor is None:
        vendor = detect_vendor(text)
    parser_cls = get_parser(vendor)
    parser = parser_cls()
    parse_result = parser.parse(text)

    engine = AuditEngine()
    findings = engine.run(parse_result)

    rel_config = config_path.name
    # If config lives under output_dir/configs/ make it relative to that
    if _HAVE_COMPAT:
        try:
            rel_config = _sc.to_relative_output_file(str(config_path), str(output_dir))
        except Exception:
            pass

    out: list[dict] = []
    for f in findings:
        # f is a Finding object — convert to dict, normalise risk, set output_file
        try:
            fd = f.to_dict() if hasattr(f, "to_dict") else dict(f)
        except Exception:
            fd = vars(f) if hasattr(f, "__dict__") else {}
        fd["risk"] = _canon_risk(fd.get("risk"))   # TitleCase → UPPERCASE (§13c)
        # §14i: every finding carries config-excerpt output + audit transcript .log
        ev = _write_finding_evidence(fd, output_dir, vendor, config_path.name)
        if ev:
            fd["output_file"] = ev
        elif not fd.get("output_file"):
            fd["output_file"] = rel_config
        if not fd.get("tool"): fd["tool"] = "bastion"
        out.append(fd)
        _finding_token(fd)
    return out


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

    # Collect configs
    configs: list[Path] = []
    if ns.config:
        configs.append(Path(ns.config).resolve())
    if ns.config_dir:
        cdir = Path(ns.config_dir).resolve()
        for ext in ("*.cfg", "*.conf", "*.txt", "*.xml", "*.json"):
            configs.extend(cdir.rglob(ext))

    if not configs:
        _err("no configs found")
        return 3

    _status({"phase": "starting", "configs": len(configs)})

    all_findings: list[dict] = []
    started_at = _now_iso()
    for i, cfg in enumerate(configs, 1):
        _status({"phase": "audit", "current": i, "total": len(configs),
                 "config": cfg.name})
        _log(f"Auditing {cfg.name} ({i}/{len(configs)})")
        try:
            fl = audit_one_config(cfg, vendor=ns.vendor, output_dir=out_dir)
            all_findings.extend(fl)
            _log(f"{cfg.name}: {len(fl)} findings")
        except Exception as exc:
            _err(f"audit failed on {cfg.name}: {exc}")
            logging.error("audit failed on %s: %s", cfg.name, exc, exc_info=True)
    ended_at = _now_iso()

    # Universal findings.json (§13e) + summary.json
    if _HAVE_COMPAT:
        try:
            _sc.write_universal_findings(out_dir, all_findings,
                                          tool="bastion", version=VERSION)
        except Exception as exc:
            _err(f"findings.json write failed: {exc}")
    elif _HAVE_SCHEMA:
        # Fallback path — manual risk fold
        for f in all_findings:
            f["risk"] = _canon_risk(f.get("risk"))
        _us.write_universal_findings(out_dir, all_findings, tool="bastion",
                                      scope=None, phase="audit")

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
        try: _sc.write_summary(out_dir, summary)
        except Exception as exc: _err(f"summary.json write failed: {exc}")
    elif _HAVE_SCHEMA:
        _us.write_summary(out_dir, _us.make_summary(
            tool="bastion", version=VERSION,
            scan_start=started_at, scan_end=ended_at,
            target=ns.config or ns.config_dir,
            success=True, total_findings=len(all_findings),
            risk_counts=risk_counts))
    else:
        (out_dir / "summary.json").write_text(
            json.dumps(summary, indent=2, default=str), encoding="utf-8")

    _status({"phase": "complete", "total_findings": len(all_findings),
             "risk_counts": risk_counts})

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
