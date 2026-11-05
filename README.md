<details>
<summary><strong>FULL DISCLOSURE</strong> — AI Development & Legal Notice</summary>

---

### AI Development Disclosure

This tool is part of the **pr0t31n toolkit**, a collection of security testing and penetration testing automation tools. The toolkit was created through AI-assisted development, guided by the professional experience and domain expertise of a cybersecurity consultant and penetration tester. Ya, I named it after myself - but to be fair, AI is horrible at naming things.

**The pr0t31n toolkit exists to serve two purposes:**

1. **Automate repetitive penetration testing workflow steps.** Security assessments involve significant amounts of repetitive, procedural work — running sequential tool chains, parsing outputs, correlating findings across tools, and managing engagement data. Automating these steps frees testers to focus on the work that requires human judgment: manual testing, creative attack paths, analysis, and reporting.

2. **Demonstrate the benefits and failures of AI-assisted development.** This toolkit is a real-world case study in building production security tooling with AI assistance. It demonstrates both what AI-assisted development can accomplish and where it falls short. The quality of AI-generated code varies significantly — between context refreshes, the output can range from senior/principal-level software engineering to the work of a still-in-school intern. This inconsistency is itself part of the demonstration.

In the interest of transparency, every tool in the pr0t31n toolkit carries this disclosure. The creator believes that AI-assisted development should be acknowledged openly, not concealed. Users, reviewers, and anyone examining this code should know how it was built so they can evaluate it accordingly.

---

### Legal & Authorization Notice

> **⚠ WARNING: AUTHORIZED USE ONLY**

This tool is designed and intended **exclusively** for use in **authorized security testing engagements**. "Authorized" means **all** of the following conditions are met:

- **Explicit Written Permission.** You possess explicit, documented, written authorization from the owner or authorized representative of the target system(s), network(s), or application(s) to conduct security testing. Verbal agreements are not sufficient.
- **Defined Scope.** The authorization clearly defines the scope of testing, including which systems, networks, IP ranges, applications, and/or endpoints are included. You must not exceed the boundaries of this defined scope under any circumstances.
- **Defined Timeframe.** The authorization specifies the dates and times during which testing is permitted. Testing outside the authorized window is unauthorized testing.
- **Rules of Engagement.** You are operating under a set of rules of engagement (RoE) or equivalent governing document that establishes acceptable testing methods, escalation procedures, emergency contacts, and any restrictions or exclusions.
- **Legal Compliance.** Your testing complies with all applicable local, state, national, and international laws and regulations, including but not limited to the Computer Fraud and Abuse Act (CFAA), the General Data Protection Regulation (GDPR), and equivalent legislation in your jurisdiction.

**Prohibited uses** include but are not limited to: unauthorized access to or testing of any system; testing against systems without explicit written authorization; any activity that violates applicable laws; use for malicious purposes including data theft, extortion, sabotage, or disruption of services; distribution intended to facilitate unauthorized access; and use without a clear legal basis.

**THIS TOOL IS PROVIDED "AS IS," WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE, AND NONINFRINGEMENT.**

The creator(s) and contributor(s) accept no responsibility or liability for any damage, loss, legal consequence, or other harm resulting from the use or misuse of this tool — including damage to systems or data, legal penalties or prosecution, loss of data or revenue, and any direct, indirect, incidental, special, consequential, or punitive damages.

**By using this tool, you acknowledge that you are solely responsible for ensuring that your use is authorized, lawful, and within the defined scope of your engagement. You assume all risk associated with the use of this tool.**

Security testing is a professional discipline with significant ethical and legal obligations. Users operating in a professional capacity are expected to adhere to the standards and codes of conduct established by recognized industry bodies, including PTES, OWASP, NIST, and any certifying body under which they hold credentials.

---

</details>

# Bastion

**Firewall Configuration Analysis Platform**

Bastion is a web-based platform for auditing firewall configurations from 12+ vendors against NIST 800-41, NIST SP 800-53, and ISO 27001 frameworks. Upload raw config files, run automated analysis, visualize your network architecture, and export audit-ready HTML reports — all from a browser.

---


> **[View full documentation on the Codex Wiki](https://wiki.pr0t31n.com/tools/bastion)** — detailed features, CLI reference, findings catalogue, and integration guides.

## Features

- **12+ vendor parsers** — Cisco ASA, Cisco IOS, Cisco FTD, Palo Alto, FortiGate, Check Point, SonicWall, WatchGuard, Sophos XG, Juniper SRX, Cato Networks, Cloudflare Gateway, Sangfor
- **83 audit rules** across three frameworks (NIST 800-41, NIST SP 800-53, ISO 27001)
- **CVSS 3.1 scoring** — automatically calculated for every finding
- **Multi-device correlation** — detect policy inconsistencies across configs from multiple devices in the same engagement
- **Network architecture diagram** — auto-generated PNG from parsed topology data
- **Change tracking** — diff findings between analysis runs; highlights new, resolved, and risk-changed issues
- **Executive profile mode** — stricter FW-100 series rules for C-suite and board-level network environments
- **Cloud overlay rules** — dedicated rule sets for Cato Networks (FW-200) and Cloudflare Gateway (FW-210)
- **False positive management** — accept findings with mandatory justification; accepted findings stay visible but de-emphasised
- **Self-contained HTML reports** — no external dependencies; embed diagram as base64
- **20 UI themes** with dark/light mode toggle (same palette system as the pr0t31n suite)

---

## Requirements

- Python 3.10+
- pip

Supported platforms: macOS, Linux, Windows

---

## Installation

```bash
cd /opt/pr0t31n/Bastion
python3 install.py
```

The installer:
1. Installs all Python dependencies from `requirements.txt`
2. Downloads `socket.io.min.js` from the Socket.IO CDN
3. Initialises the authentication store with default credentials

**Default credentials:** `admin` / `t3mpPas$w0rd`

You will be forced to change both username and password on first login.

---

## Starting Bastion

```bash
python3 app.py
```

Then open **https://localhost:5000** in your browser.

> Bastion uses a self-signed SSL certificate. Accept the browser security warning to proceed — this is expected for local tools.

---

## Quick Start

### 1. Create a project

Click **New Project** and fill in the engagement details:

| Field | Description |
|-------|-------------|
| Client Name | Full client organisation name |
| Client Short | Short slug used in file names (e.g. `acmecorp`) |
| Consultant Name | Your name, included in reports |
| Start / End Date | Engagement dates |
| Executive Environment | Enable stricter FW-100 series rules for executive/board networks |

### 2. Upload configs

Navigate to your project → **Source** tab. Drag and drop firewall config files into the upload zone, or click to browse. Supported extensions: `.cfg`, `.conf`, `.txt`, `.log`, `.xml`, `.json`, `.yaml`, `.yml`, `.exp`, `.backup`, `.cli`

Maximum file size: 64 MB per file.

Bastion auto-detects the vendor from the file content. If detection fails, use the **Set Vendor** dropdown to override manually.

### 3. Analyse

Click **Analyse All**. Progress is shown in real time as each config is parsed, the audit engine runs, and the architecture diagram is generated.

### 4. Review findings

Switch to the **Findings** tab. Findings are colour-coded by risk:

| Colour | Risk Level |
|--------|-----------|
| Magenta | Critical |
| Red | High |
| Amber | Medium |
| Green | Low |
| Blue | Informational |

Use the search box and dropdown filters to narrow results by risk level or framework. Click **Details** on any finding to see the full CVSS vector, affected config lines, and remediation guidance. Click **View** to jump directly to the relevant lines in the config viewer.

### 5. Export a report

Go to the **Summary** tab and click **HTML Report** to download a self-contained audit report suitable for client delivery.

---

## Tabs

| Tab | Contents |
|-----|----------|
| **Source** | Upload and manage config files; trigger analysis; view raw configs with syntax highlighting |
| **Findings** | All findings with risk badges, CVSS scores, framework mapping, and actions |
| **Architecture** | Auto-generated network diagram; zoom/pan controls; PNG download |
| **Logs** | Parse log and application event log |
| **Errors** | Any parse or audit errors encountered during analysis |
| **Summary** | Risk overview cards, quick wins, framework compliance matrix, export buttons |

---

## Supported Vendors

| Vendor | Config Format |
|--------|--------------|
| Cisco ASA | `show running-config` text |
| Cisco IOS / IOS-XE | `show running-config` text |
| Cisco Firepower (FTD) | Running config text |
| Palo Alto Networks | XML export or `set` command format |
| Fortinet FortiGate | FortiOS config (VDOM-aware) |
| Check Point | `dbedit` export or JSON policy export |
| SonicWall | XML config export |
| WatchGuard Firebox | XML policy export |
| Sophos XG | XML firewall rules export |
| Juniper SRX | `show configuration` text |
| Cato Networks | JSON network rules export |
| Cloudflare Gateway | JSON gateway rules export |
| Sangfor | XML config export |

---

## Audit Rule Sets

### Base Rules (FW-001 -- FW-083) — NIST 800-41 / NIST SP 800-53 / ISO 27001

Covers: default-deny policy, logging, zone segmentation, management access controls, overly permissive rules (any/any), unused rules, rule ordering, NAT configuration, inbound/outbound filtering, protocol hygiene, and more.

### Executive Profile (FW-100 -- FW-104)

Enabled when **Executive Environment** is checked at project creation. Applies stricter thresholds appropriate for protecting high-value targets such as executive offices, C-suite workstations, and board meeting networks.

### Cloud Overlays

- **Cato Networks (FW-200 -- FW-212)** — SASE-specific controls: internet access policies, zero-trust socket rules, cloud application controls
- **Cloudflare Gateway (FW-210+)** — DNS filtering, HTTP inspection, egress policies

---

## Configuration Viewer

In the **Source** tab, click the filename of any uploaded config to open the built-in viewer. Features:

- Line numbers
- Syntax highlighting: `permit`/`allow` (green), `deny`/`drop` (red), keywords (purple), comments (muted), IP addresses (blue)
- Search with match count
- **View in Config** from any finding — jumps directly to the triggered lines and highlights them

---

## Change Tracking

When you click **Re-analyse** on a project that has already been analysed, Bastion archives the previous `findings.json` with a timestamp, then runs a fresh analysis and computes:

- **New** findings (appeared in this run, not in the previous)
- **Resolved** findings (were in the previous run, gone now)
- **Risk-changed** findings (same finding, different severity)

A diff banner appears at the top of the Findings tab summarising the changes. New findings are highlighted with a green left border; risk-changed findings with an amber border.

---

## Finding Actions

| Action | Description |
|--------|-------------|
| **Details** | Opens a modal with full CVSS breakdown, framework mapping, triggered config lines, and analyst notes |
| **View** | Switches to Source tab and highlights the relevant config lines |
| **Accept** | Marks the finding as an accepted risk; requires a justification. Accepted findings are greyed out and excluded from risk counts |
| **Un-Accept** | Reverses an acceptance decision |

---

## Exports

| Export | Description |
|--------|-------------|
| **HTML Report** | Self-contained HTML file with embedded diagram, all findings, and remediation guidance |
| **findings.json** | Raw findings data as JSON |
| **Project ZIP** | Complete project directory including configs, findings, logs, and diagram |

---

## Multi-Device Projects

Upload configs from multiple devices in the same project. After analysis, the **Correlation Engine** checks for:

- Rules on one device that are inconsistent with policy on another
- Trust relationships that create unintended transitive access
- Logging gaps — traffic permitted through device A but not logged on device B

Correlation findings appear alongside per-device findings in the Findings tab, tagged with `vendor: correlation`.

---

## Authentication & Security

- Session-based authentication; 15-minute idle timeout
- Passwords hashed with bcrypt
- CSRF protection on all state-changing routes
- Upload path traversal protection — files are confined to the project `configs/` directory
- Config file binary check — rejects non-text uploads
- All routes require authentication except `/api/nexus-status` (used by Nexus for health probing)

---

## Project Layout

```
Bastion/
├── app.py                   # Flask application
├── _auth.py                 # Authentication module
├── install.py               # First-run installer
├── requirements.txt
├── engine/
│   ├── audit_engine.py      # CVSS 3.1 + rule evaluation
│   ├── audit_rules.yaml     # FW-001 – FW-083
│   ├── audit_rules_cato.yaml
│   ├── audit_rules_cloudflare.yaml
│   ├── audit_rules_executive.yaml
│   ├── correlation.py       # Multi-device cross-analysis
│   ├── diagram.py           # Network topology diagram
│   ├── models.py            # Finding, FirewallRule, NetworkNode dataclasses
│   ├── reporter.py          # HTML report generator
│   └── parsers/
│       ├── base.py          # ObjectResolver, detect_vendor, get_parser
│       ├── cisco_asa.py
│       ├── palo_alto.py
│       ├── fortinet.py
│       ├── checkpoint.py
│       ├── sonicwall.py
│       ├── watchguard.py
│       ├── sophos.py
│       ├── juniper_srx.py
│       ├── cato.py
│       ├── cloudflare.py
│       └── sangfor.py
├── static/css/style.css
├── static/js/main.js
└── templates/
    ├── base.html
    ├── index.html
    ├── project.html
    ├── new_project.html
    ├── edit_project.html
    ├── login.html
    └── change_password.html
```

> **Note:** Bastion 2.x is a pure-CLI orchestrator (`app.py`); the 1.x Flask
> app/templates are archived. The layout above reflects the engine, which is
> unchanged.

## CLI Reference

```bash
python3 app.py --output-dir <run_dir> [options]
```

One of `--config` or `--config-dir` is required.

| Flag | Required | Default | Description |
|------|----------|---------|-------------|
| `--config <file>` | One of `--config` / `--config-dir` | -- | Single config file to audit |
| `--config-dir <dir>` | One of `--config` / `--config-dir` | -- | Directory containing config files |
| `--output-dir <dir>` | Yes | -- | Universal-output run directory |
| `--vendor <name>` | No | Auto-detect | Override auto-detected vendor (`cisco_asa`, `cisco_ios`, `cisco_ftd`, `palo_alto`, `fortinet`, `checkpoint`, `sonicwall`, `watchguard`, `sophos`, `juniper_srx`, `cato`, `cloudflare`, `sangfor`) |
| `--client-short <slug>` | No | `bastion-cli` | Client short name used in output paths and `meta.json` |
| `--client-name <name>` | No | `Bastion CLI run` | Client display name written to `meta.json` |
| `--json-status` | No | Off | Emit a single-line JSON summary on stdout when the run completes |
| `--emit-tokens` | No | Off | Force `__CRUCIBLE_*` protocol tokens even when `CRUCIBLE_MANAGED` is not set (used for Crucible integration testing) |
| `--skip-threat-intel` | No | Off | Skip threat-intelligence and GeoIP enrichment checks |

**Examples:**

```bash
# Audit a single config file
python3 app.py --config firewall.cfg --output-dir /clients/acme/2026/bastion/acme_20261105_120000

# Audit all configs in a directory with vendor override
python3 app.py --config-dir ./configs/ --vendor palo_alto --output-dir ./run_output

# CLI run with Crucible token emission and JSON status
python3 app.py --config router.conf --output-dir ./out --emit-tokens --json-status

# Skip threat-intel for air-gapped environments
python3 app.py --config-dir ./fw_exports/ --output-dir ./out --skip-threat-intel
```

---

## Run Output (universal §13)

Each `app.py --output-dir <run_dir>` run writes a universal run directory:

```
<run_dir>/
├── meta.json                       # tool identity / client / engagement
├── findings.json                   # universal findings (risk UPPERCASED)
├── findings.csv
├── summary.json                    # risk_counts, config_files, timing
├── scan.log / scan.log.json        # timestamped event log (§13b/§14f)
├── errors.log / errors.log.json    # ERROR-level entries only
└── evidence/<vendor>/
    ├── <rule>_<ts>_excerpt.txt     # triggering config lines for the finding
    └── <rule>_<ts>.log             # audit transcript (rule/risk/framework)
```

Every finding's `output_file` points at its `evidence/<vendor>/…_excerpt.txt`
**and** `…​.log` pair (run-dir-relative), so each finding carries both output and
log evidence (§14i).

---

## Changing Your Password

Navigate to the top-right user menu → **Change Password**, or go directly to `https://localhost:5000/auth/change-password`.

---

## Integration with the pr0t31n Suite

Bastion exposes a `/api/nexus-status` endpoint that the **Nexus** hub uses to detect and monitor it alongside all other tools in the suite. No additional configuration is required.

Findings from Bastion can be aggregated into unified engagement reports using **Prometheus**.

---

## Troubleshooting

**Diagram not generating**
Install matplotlib and networkx: `pip3 install matplotlib networkx`. If they are unavailable, Bastion falls back to an SVG placeholder.

**Vendor detected incorrectly**
Use the **Set Vendor** dropdown on the config file card in the Source tab to override.

**Analysis errors**
Check the **Errors** tab for detailed tracebacks. Common causes: malformed config syntax, unsupported config version, encoding issues (Bastion reads files as UTF-8 with error replacement).

**SSL certificate warning**
Expected. Bastion uses a self-signed certificate for local HTTPS. Accept the browser exception.

---

## License

Part of the pr0t31n security assessment toolkit. For authorised security testing use only.
