"""
Bastion app.py — Flask + Flask-SocketIO firewall analysis platform.
VERSION = "1.1.0"
"""
import socket
import json
import logging
import os
import platform as _platform
import shutil
import threading
import traceback
import uuid
import zipfile
from datetime import datetime
from io import BytesIO
from pathlib import Path

from flask import (Flask, jsonify, redirect, render_template, request,
                   send_file, session, url_for)
from flask_socketio import SocketIO, emit, join_room
from werkzeug.utils import secure_filename

import _auth
from engine.parsers.base import detect_vendor, get_parser

VERSION = "1.7.0"


def _u_dual_write_meta(project_dir, *, tool: str, version: str,
                       client_short: str = "", client_name: str = "",
                       engagement_name: str = "", target: str = "") -> bool:
    """Write universal meta.json (schema 1.0). Graceful no-op when
    /opt/pr0t31n/shared/pr0t31n_schema.py is not installed."""
    try:
        import sys as _s
        if "/opt/pr0t31n/shared" not in _s.path:
            _s.path.insert(0, "/opt/pr0t31n/shared")
        import pr0t31n_schema as _us
    except ImportError:
        return False
    try:
        meta = _us.make_meta(
            tool=tool, version=version,
            client_short=client_short or "unknown",
            client_name=client_name or client_short or "unknown",
            engagement_name=engagement_name or f"{tool} run",
            target=target or "",
        )
        _us.atomic_write_json(Path(project_dir) / "meta.json", meta)
        return True
    except Exception:
        return False


# ---------------------------------------------------------------------------
# App setup
# ---------------------------------------------------------------------------

_BASE_DIR = os.path.dirname(os.path.abspath(__file__))
_PROJECTS_FILE = os.path.join(_BASE_DIR, "projects.json")
_projects_lock = threading.Lock()

ALLOWED_EXTENSIONS = {
    ".cfg", ".conf", ".txt", ".log", ".xml", ".json",
    ".exp", ".backup", ".cli", ".yaml", ".yml",
}
MAX_CONTENT_LENGTH = 64 * 1024 * 1024  # 64 MB

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s [%(name)s] %(message)s",
)
logger = logging.getLogger("bastion")

app = Flask(__name__)
app.config["SECRET_KEY"] = _auth.load_secret_key()
app.config["MAX_CONTENT_LENGTH"] = MAX_CONTENT_LENGTH
app.config["SESSION_COOKIE_SECURE"] = False  # self-signed cert; HTTPS enforced server-side
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["PERMANENT_SESSION_LIFETIME"] = 1800  # 30 min

socketio = SocketIO(app, cors_allowed_origins="*", async_mode="threading", manage_session=False)

# ---------------------------------------------------------------------------
# Per-project state buffers
# ---------------------------------------------------------------------------

_parse_log: dict = {}       # project_id → [log entries]
_bastion_log: dict = {}     # project_id → [event entries]
_error_buffer: dict = {}    # project_id → [error entries]
_analysis_status: dict = {} # project_id → {status, step, percent}
_analysis_threads: dict = {}  # project_id → Thread

_buf_lock = threading.Lock()

# Job queue — execute-project requests that arrive while analysis is running
_job_queue: list = []
_queue_lock = threading.Lock()
_QUEUE_FILE = os.path.join(_BASE_DIR, "execute_queue.json")


def _buf_append(buf: dict, project_id: str, entry: dict) -> None:
    with _buf_lock:
        buf.setdefault(project_id, []).append(entry)
        # Limit buffer size
        if len(buf[project_id]) > 2000:
            buf[project_id] = buf[project_id][-1000:]


def _ts() -> str:
    return datetime.now().isoformat()


# ---------------------------------------------------------------------------
# Projects JSON helpers
# ---------------------------------------------------------------------------

def load_projects() -> dict:
    try:
        if os.path.exists(_PROJECTS_FILE):
            with open(_PROJECTS_FILE, "r") as f:
                return json.load(f)
        return {"projects": {}}
    except Exception as e:
        logger.error(f"load_projects error: {e}")
        return {"projects": {}}


def save_projects(data: dict) -> None:
    with _projects_lock:
        try:
            with open(_PROJECTS_FILE, "w") as f:
                json.dump(data, f, indent=2)
        except Exception as e:
            logger.error(f"save_projects error: {e}")


def _clients_base() -> Path:
    """Return the OS-appropriate clients root directory, creating it if absent."""
    system = _platform.system()
    if system == "Darwin":
        base = Path("/Users/Shared/clients")
    elif system == "Windows":
        base = Path("C:/clients")
    else:
        base = Path("/clients")
    try:
        base.mkdir(parents=True, exist_ok=True)
    except PermissionError:
        base = Path.home() / "clients"
        base.mkdir(parents=True, exist_ok=True)
    return base


def _project_dir_for(project_id: str) -> str:
    raw = load_projects()
    pinfo = raw.get("projects", {}).get(project_id, {})
    return pinfo.get("project_dir", str(_clients_base() / "bastion" / project_id))


def _compute_framework_summary(findings_dicts: list) -> dict:
    summary = {}
    for f in findings_dicts:
        fw = f.get("framework") or "Unknown"
        risk = f.get("risk", "Unknown")
        if fw not in summary:
            summary[fw] = {}
        summary[fw][risk] = summary[fw].get(risk, 0) + 1
    return summary


# ---------------------------------------------------------------------------
# Auth hooks
# ---------------------------------------------------------------------------

_auth.init_auth()


@app.before_request
def before_request():
    result = _auth.auth_gate()
    if result:
        return result


@app.after_request
def after_request(response):
    return _auth.apply_security_headers(response)


# ---------------------------------------------------------------------------
# Auth routes
# ---------------------------------------------------------------------------

@app.route("/login", methods=["GET", "POST"])
def login():
    try:
        error = None
        if request.method == "POST":
            token = request.form.get("csrf_token", "")
            if not _auth.validate_csrf(token):
                error = "Invalid or expired request. Please try again."
            else:
                username = request.form.get("username", "").strip()
                password = request.form.get("password", "")
                if _auth.verify_credentials(username, password):
                    session.permanent = True
                    session["authenticated"] = True
                    session["username"] = username
                    return redirect(url_for("index"))
                else:
                    error = "Invalid username or password."
        csrf = _auth.generate_csrf()
        return render_template("login.html", csrf_token=csrf, error=error)
    except Exception as e:
        logger.error(f"login error: {e}", exc_info=True)
        return render_template("login.html",
                               csrf_token=_auth.generate_csrf(),
                               error="An error occurred."), 500


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/api/session_ping", methods=["POST"])
def session_ping():
    if not session.get("authenticated"):
        return jsonify({"ok": False}), 401
    session.modified = True
    return jsonify({"ok": True})


@app.route("/auth/change-password", methods=["GET", "POST"])
def change_password():
    try:
        error = None
        success = None
        force_change = _auth.must_change_password()
        if request.method == "POST":
            token = request.form.get("csrf_token", "")
            if not _auth.validate_csrf(token):
                error = "Invalid or expired request. Please try again."
            else:
                new_username = request.form.get("new_username", "").strip()
                current_pw = request.form.get("current_password", "")
                new_pw = request.form.get("new_password", "")
                confirm_pw = request.form.get("confirm_password", "")

                if not _auth.check_current_password(current_pw):
                    error = "Current password is incorrect."
                elif new_pw != confirm_pw:
                    error = "New passwords do not match."
                else:
                    pw_err = _auth.is_weak_password(new_pw, new_username or session.get("username", ""))
                    if pw_err:
                        error = pw_err
                    elif new_username:
                        un_err = _auth.is_weak_username(new_username)
                        if un_err:
                            error = un_err
                        else:
                            _auth.update_credentials(new_username, new_pw)
                            session["username"] = new_username
                            success = "Credentials updated successfully."
                            if force_change:
                                return redirect(url_for("index"))
                    else:
                        _auth.update_password(new_pw)
                        success = "Password updated successfully."
                        if force_change:
                            return redirect(url_for("index"))

        csrf = _auth.generate_csrf()
        return render_template("change_password.html",
                               csrf_token=csrf, error=error, success=success,
                               force_change=force_change)
    except Exception as e:
        logger.error(f"change_password error: {e}", exc_info=True)
        return render_template("change_password.html",
                               csrf_token=_auth.generate_csrf(),
                               error="An error occurred.",
                               force_change=False), 500


# ---------------------------------------------------------------------------
# Main pages
# ---------------------------------------------------------------------------

@app.route("/")
def index():
    try:
        raw = load_projects()
        projects = list(raw.get("projects", {}).values())
        projects.sort(key=lambda p: p.get("created", ""), reverse=True)
        return render_template("index.html", projects=projects, version=VERSION)
    except Exception as e:
        logger.error(f"index error: {e}", exc_info=True)
        return render_template("index.html", projects=[], version=VERSION)


@app.route("/new_project")
def new_project():
    try:
        csrf = _auth.generate_csrf()
        return render_template("new_project.html", csrf_token=csrf)
    except Exception as e:
        logger.error(f"new_project error: {e}", exc_info=True)
        return redirect(url_for("index"))


@app.route("/edit_project/<project_id>")
def edit_project(project_id):
    try:
        raw = load_projects()
        pinfo = raw.get("projects", {}).get(project_id)
        if not pinfo:
            return redirect(url_for("index"))
        csrf = _auth.generate_csrf()
        return render_template("edit_project.html",
                               project=pinfo, csrf_token=csrf)
    except Exception as e:
        logger.error(f"edit_project error: {e}", exc_info=True)
        return redirect(url_for("index"))


@app.route("/project/<project_id>")
@app.route("/project/<project_id>/<tab>")
def project_page(project_id, tab="source"):
    try:
        raw = load_projects()
        pinfo = raw.get("projects", {}).get(project_id)
        if not pinfo:
            return redirect(url_for("index"))
        # Load findings summary
        pdir = _project_dir_for(project_id)
        risk_summary = pinfo.get("risk_summary", {})
        findings_path = os.path.join(pdir, "findings.json")
        if os.path.exists(findings_path):
            try:
                with open(findings_path) as f:
                    fd = json.load(f)
                risk_summary = fd.get("risk_summary", risk_summary)
            except Exception:
                pass
        return render_template("project.html",
                               project=pinfo,
                               project_id=project_id,
                               active_tab=tab,
                               risk_summary=risk_summary,
                               version=VERSION)
    except Exception as e:
        logger.error(f"project_page error: {e}", exc_info=True)
        return redirect(url_for("index"))


# ---------------------------------------------------------------------------
# API: nexus-status (unauthenticated probe)
# ---------------------------------------------------------------------------

@app.route("/api/nexus-status")
def api_nexus_status():
    scanning = any(s.get("status") == "running" for s in _analysis_status.values())
    return jsonify({"status": "ok", "app": "bastion", "tool": "bastion", "hostname": socket.gethostname(), "scanning": scanning, "version": VERSION})


@app.route("/api/arbiter-projects")
def api_arbiter_projects():
    """Return Bastion projects as normalized project records for Arbiter."""
    raw = load_projects()
    result = []
    for pid, proj in raw.get("projects", {}).items():
        proj_status = proj.get("status", "created")
        # Only expose projects that are not completed
        if proj_status == "completed":
            continue
        client_name = proj.get("client_name") or proj.get("client_short", "")
        project_name = proj.get("name", "").strip()
        if not project_name or not client_name:
            continue
        live = _analysis_status.get(pid, {})
        running = live.get("status") == "running"
        result.append({
            "id":               pid,
            "name":             project_name,
            "client_name":      client_name,
            "client_short":     proj.get("client_short", ""),
            "consultant":       proj.get("consultant_name", ""),
            "consultant_email": proj.get("consultant_email", ""),
            "start_date":       proj.get("start_date", ""),
            "end_date":         proj.get("end_date", ""),
            "tool":             "bastion",
            "project_dir":      proj.get("project_dir", ""),
            "status":           "running" if running else proj_status,
            "finding_count":    proj.get("findings_count", 0),
            "has_findings":     bool(proj.get("findings_count", 0)),
            "created":          proj.get("created", ""),
        })
    return jsonify(result)


@app.route("/api/projects/<project_id>/status")
def api_project_status(project_id):
    """Standardized status endpoint polled by Arbiter's scan_poll_worker."""
    raw = load_projects()
    if project_id not in raw.get("projects", {}):
        return jsonify({"error": "not found"}), 404

    live = _analysis_status.get(project_id, {})
    running = live.get("status") == "running"

    queue_position = None
    with _queue_lock:
        for i, job in enumerate(_job_queue):
            if job.get("project_id") == project_id:
                queue_position = i + 1
                break

    if running:
        overall = "running"
    elif queue_position is not None:
        overall = "queued"
    else:
        s = raw["projects"][project_id].get("status", "created")
        if s in ("completed", "complete", "done"):
            overall = "complete"
        elif s == "error":
            overall = "error"
        else:
            overall = "idle"

    return jsonify({
        "project_id":     project_id,
        "status":         overall,
        "tool":           "bastion",
        "progress":       live.get("percent"),
        "queue_position": queue_position,
    })


# ---------------------------------------------------------------------------
# API: Project management
# ---------------------------------------------------------------------------

@app.route("/api/create_project", methods=["POST"])
def api_create_project():
    try:
        token = request.form.get("csrf_token", "")
        if not _auth.validate_csrf(token):
            return jsonify({"error": "Invalid CSRF token"}), 403

        project_name = request.form.get("name", "").strip()
        if not project_name:
            return jsonify({"error": "Project name is required"}), 400

        project_id = str(uuid.uuid4())[:8]
        project_dir = _clients_base() / "bastion" / project_id
        project_dir.mkdir(parents=True, exist_ok=True)
        (project_dir / "configs").mkdir(exist_ok=True)
        (project_dir / "reports").mkdir(exist_ok=True)

        # Dual-write universal meta.json (schema 1.0) for Prometheus UniversalParser.
        _u_dual_write_meta(
            project_dir, tool="bastion", version=VERSION,
            client_short=request.form.get("client_short", ""),
            client_name=request.form.get("client_name", ""),
            engagement_name=project_name,
            target=request.form.get("client_name", "") or project_name,
        )

        raw = load_projects()
        raw.setdefault("projects", {})[project_id] = {
            "id": project_id,
            "name": project_name,
            "client_name": request.form.get("client_name", ""),
            "client_short": request.form.get("client_short", ""),
            "consultant_name": request.form.get("consultant_name", ""),
            "consultant_title": request.form.get("consultant_title", ""),
            "consultant_email": request.form.get("consultant_email", ""),
            "project_dir": str(project_dir),
            "created": datetime.now().strftime("%Y-%m-%d"),
            "start_date": request.form.get("start_date", ""),
            "end_date": request.form.get("end_date", ""),
            "status": "created",
            "executive_profile": bool(request.form.get("executive_profile")),
            "findings_count": 0,
            "risk_summary": {},
            "config_files": [],
        }
        save_projects(raw)

        logger.info(f"Created project {project_id}: {project_name}")
        return redirect(url_for("project_page", project_id=project_id))

    except Exception as e:
        _buf_append(_error_buffer, "global", {
            "ts": _ts(), "type": "APPLICATION",
            "source": "api_create_project", "message": str(e),
            "detail": traceback.format_exc()})
        return jsonify({"error": str(e)}), 500


@app.route("/api/update_project/<project_id>", methods=["POST"])
def api_update_project(project_id):
    try:
        token = request.form.get("csrf_token", "")
        if not _auth.validate_csrf(token):
            return jsonify({"error": "Invalid CSRF token"}), 403

        raw = load_projects()
        pinfo = raw.get("projects", {}).get(project_id)
        if not pinfo:
            return jsonify({"error": "Not found"}), 404

        for field in ["name", "client_name", "client_short",
                      "consultant_name", "consultant_title",
                      "consultant_email", "start_date", "end_date"]:
            val = request.form.get(field)
            if val is not None:
                pinfo[field] = val.strip()

        pinfo["executive_profile"] = bool(request.form.get("executive_profile"))
        save_projects(raw)
        return redirect(url_for("project_page", project_id=project_id))

    except Exception as e:
        _buf_append(_error_buffer, project_id, {
            "ts": _ts(), "type": "APPLICATION",
            "source": "api_update_project", "message": str(e),
            "detail": traceback.format_exc()})
        return jsonify({"error": str(e)}), 500


@app.route("/api/delete_project/<project_id>", methods=["DELETE"])
def api_delete_project(project_id):
    try:
        raw = load_projects()
        pinfo = raw.get("projects", {}).get(project_id)
        if not pinfo:
            return jsonify({"error": "Not found"}), 404

        pdir = pinfo.get("project_dir", "")
        if pdir and os.path.exists(pdir):
            shutil.rmtree(pdir, ignore_errors=True)

        del raw["projects"][project_id]
        save_projects(raw)
        return jsonify({"ok": True})

    except Exception as e:
        _buf_append(_error_buffer, project_id, {
            "ts": _ts(), "type": "APPLICATION",
            "source": "api_delete_project", "message": str(e),
            "detail": traceback.format_exc()})
        return jsonify({"error": str(e)}), 500


# ---------------------------------------------------------------------------
# API: Config file management
# ---------------------------------------------------------------------------

@app.route("/api/upload_config/<project_id>", methods=["POST"])
def api_upload_config(project_id):
    try:
        raw = load_projects()
        pinfo = raw.get("projects", {}).get(project_id)
        if not pinfo:
            return jsonify({"error": "Project not found"}), 404

        if "file" not in request.files:
            return jsonify({"error": "No file part"}), 400

        f = request.files["file"]
        if not f.filename:
            return jsonify({"error": "No filename"}), 400

        filename = secure_filename(f.filename)
        ext = os.path.splitext(filename)[1].lower()
        if ext not in ALLOWED_EXTENSIONS:
            return jsonify({"error": f"Unsupported file type: {ext}"}), 400

        uploaded_bytes = f.read()
        header = uploaded_bytes[:512]
        if b"\x00" in header and ext not in (".bin", ".pcap"):
            return jsonify({"error": "File appears to be binary; text expected"}), 400

        pdir = pinfo.get("project_dir", _project_dir_for(project_id))
        configs_dir = os.path.realpath(os.path.join(pdir, "configs"))
        os.makedirs(configs_dir, exist_ok=True)

        dest = os.path.realpath(os.path.join(configs_dir, filename))
        if not dest.startswith(configs_dir):
            return jsonify({"error": "Access denied"}), 403

        with open(dest, "wb") as out:
            out.write(uploaded_bytes)

        file_size = len(uploaded_bytes)

        # Auto-detect vendor
        try:
            text = uploaded_bytes.decode("utf-8", errors="replace")
            vendor = detect_vendor(text, filename)
        except Exception:
            vendor = "unknown"

        # Update project config_files list
        cfg_files = pinfo.get("config_files", [])
        # Remove existing entry for same filename
        cfg_files = [c for c in cfg_files if c.get("filename") != filename]
        cfg_files.append({
            "filename": filename,
            "vendor": vendor,
            "size": file_size,
            "uploaded": datetime.now().isoformat(),
        })
        pinfo["config_files"] = cfg_files
        save_projects(raw)

        logger.info(f"Uploaded {filename} ({file_size} bytes) vendor={vendor} "
                    f"to project {project_id}")

        return jsonify({"ok": True, "filename": filename,
                        "vendor": vendor, "size": file_size})

    except Exception as e:
        _buf_append(_error_buffer, project_id, {
            "ts": _ts(), "type": "APPLICATION",
            "source": "api_upload_config", "message": str(e),
            "detail": traceback.format_exc()})
        return jsonify({"error": str(e)}), 500


@app.route("/api/detect_vendor/<project_id>", methods=["POST"])
def api_detect_vendor(project_id):
    try:
        data = request.get_json(force=True) or {}
        filename = data.get("filename", "")
        raw = load_projects()
        pinfo = raw.get("projects", {}).get(project_id)
        if not pinfo:
            return jsonify({"error": "Not found"}), 404

        pdir = pinfo.get("project_dir", _project_dir_for(project_id))
        config_path = os.path.join(pdir, "configs", secure_filename(filename))
        if not os.path.exists(config_path):
            return jsonify({"error": "File not found"}), 404

        text = open(config_path, encoding="utf-8", errors="replace").read()
        vendor = detect_vendor(text, filename)
        return jsonify({"vendor": vendor})

    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/set_vendor/<project_id>/<path:filename>", methods=["POST"])
def api_set_vendor(project_id, filename):
    try:
        data = request.get_json(force=True) or {}
        vendor = data.get("vendor", "unknown")
        raw = load_projects()
        pinfo = raw.get("projects", {}).get(project_id)
        if not pinfo:
            return jsonify({"error": "Not found"}), 404

        cfg_files = pinfo.get("config_files", [])
        for cfg in cfg_files:
            if cfg.get("filename") == os.path.basename(filename):
                cfg["vendor"] = vendor
                break
        pinfo["config_files"] = cfg_files
        save_projects(raw)
        return jsonify({"ok": True, "vendor": vendor})

    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/delete_config/<project_id>/<path:filename>", methods=["DELETE"])
def api_delete_config(project_id, filename):
    try:
        raw = load_projects()
        pinfo = raw.get("projects", {}).get(project_id)
        if not pinfo:
            return jsonify({"error": "Not found"}), 404

        pdir = pinfo.get("project_dir", _project_dir_for(project_id))
        safe_name = secure_filename(os.path.basename(filename))
        config_path = os.path.join(pdir, "configs", safe_name)

        if os.path.exists(config_path):
            os.remove(config_path)

        cfg_files = [c for c in pinfo.get("config_files", [])
                     if c.get("filename") != safe_name]
        pinfo["config_files"] = cfg_files
        save_projects(raw)
        return jsonify({"ok": True})

    except Exception as e:
        _buf_append(_error_buffer, project_id, {
            "ts": _ts(), "type": "APPLICATION",
            "source": "api_delete_config", "message": str(e),
            "detail": traceback.format_exc()})
        return jsonify({"error": str(e)}), 500


@app.route("/api/config_content/<project_id>/<path:filename>")
def api_config_content(project_id, filename):
    try:
        raw = load_projects()
        pinfo = raw.get("projects", {}).get(project_id)
        if not pinfo:
            return jsonify({"error": "Not found"}), 404

        pdir = pinfo.get("project_dir", _project_dir_for(project_id))
        config_path = os.path.join(pdir, "configs",
                                   os.path.basename(filename))
        safe_dir = os.path.realpath(os.path.join(pdir, "configs"))
        safe_path = os.path.realpath(config_path)
        if not safe_path.startswith(safe_dir):
            return jsonify({"error": "Access denied"}), 403

        if not os.path.exists(config_path):
            return jsonify({"error": "File not found"}), 404

        content = open(config_path, encoding="utf-8", errors="replace").read()
        lines = content.splitlines()
        return jsonify({
            "content": content,
            "line_count": len(lines),
            "filename": os.path.basename(filename),
        })

    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ---------------------------------------------------------------------------
# API: Config files list
# ---------------------------------------------------------------------------

@app.route("/api/config_files/<project_id>")
def api_config_files(project_id):
    try:
        raw = load_projects()
        pinfo = raw.get("projects", {}).get(project_id)
        if not pinfo:
            return jsonify({"error": "Not found"}), 404

        cfg_files = pinfo.get("config_files", [])
        pdir = pinfo.get("project_dir", _project_dir_for(project_id))
        configs_dir = os.path.join(pdir, "configs")

        result = []
        for cfg in cfg_files:
            fname = cfg.get("filename", "")
            fpath = os.path.join(configs_dir, fname)
            size = os.path.getsize(fpath) if os.path.exists(fpath) else 0
            result.append({
                **cfg,
                "size": size,
            })
        return jsonify({"config_files": result})

    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ---------------------------------------------------------------------------
# API: Analysis
# ---------------------------------------------------------------------------

@app.route("/api/analyze/<project_id>", methods=["POST"])
def api_analyze(project_id):
    try:
        if project_id in _analysis_threads and \
                _analysis_threads[project_id].is_alive():
            return jsonify({"error": "Analysis already running"}), 409

        raw = load_projects()
        pinfo = raw.get("projects", {}).get(project_id)
        if not pinfo:
            return jsonify({"error": "Project not found"}), 404

        cfg_files = pinfo.get("config_files", [])
        if not cfg_files:
            return jsonify({"error": "No config files uploaded"}), 400

        pdir = pinfo.get("project_dir", _project_dir_for(project_id))
        exec_profile = bool(pinfo.get("executive_profile", False))

        t = threading.Thread(
            target=_run_analysis,
            args=(project_id, pdir, cfg_files, exec_profile),
            daemon=True,
        )
        _analysis_threads[project_id] = t
        t.start()

        _buf_append(_bastion_log, project_id, {
            "ts": _ts(), "event": "analysis_started",
            "files": len(cfg_files), "user": session.get("username", "")})

        return jsonify({"ok": True, "message": "Analysis started"})

    except Exception as e:
        _buf_append(_error_buffer, project_id, {
            "ts": _ts(), "type": "APPLICATION",
            "source": "api_analyze", "message": str(e),
            "detail": traceback.format_exc()})
        return jsonify({"error": str(e)}), 500


@app.route("/api/reanalyze/<project_id>", methods=["POST"])
def api_reanalyze(project_id):
    return api_analyze(project_id)


@app.route("/api/analysis_status/<project_id>")
def api_analysis_status(project_id):
    try:
        status = _analysis_status.get(project_id, {})
        running = (project_id in _analysis_threads
                   and _analysis_threads[project_id].is_alive())
        return jsonify({"running": running, **status})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ---------------------------------------------------------------------------
# Background analysis thread
# ---------------------------------------------------------------------------

def _archive_and_diff(project_dir: str, new_findings: list) -> dict:
    """Archive previous findings.json, compute diff, return diff_summary."""
    findings_path = os.path.join(project_dir, "findings.json")
    diff_path = os.path.join(project_dir, "findings_diff.json")
    diff_summary = {"new": [], "resolved": [], "risk_changed": [], "unchanged": 0}

    try:
        if not os.path.exists(findings_path):
            return diff_summary

        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        archive_dir = os.path.join(project_dir, "findings_archive")
        os.makedirs(archive_dir, exist_ok=True)
        archive_path = os.path.join(archive_dir, f"findings_{ts}.json")
        shutil.copy2(findings_path, archive_path)

        with open(findings_path, "r") as f:
            prev_data = json.load(f)

        prev_findings = {fi["id"]: fi for fi in prev_data.get("findings", [])}
        new_by_id = {fi["id"]: fi for fi in new_findings}

        for fid, fi in new_by_id.items():
            if fid not in prev_findings:
                diff_summary["new"].append(
                    {"id": fid, "title": fi.get("title", ""),
                     "risk": fi.get("risk", "")})

        for fid, fi in prev_findings.items():
            if fid not in new_by_id:
                diff_summary["resolved"].append(
                    {"id": fid, "title": fi.get("title", ""),
                     "risk": fi.get("risk", "")})

        for fid in set(new_by_id) & set(prev_findings):
            if new_by_id[fid].get("risk") != prev_findings[fid].get("risk"):
                diff_summary["risk_changed"].append({
                    "id": fid,
                    "title": new_by_id[fid].get("title", ""),
                    "old_risk": prev_findings[fid].get("risk", ""),
                    "new_risk": new_by_id[fid].get("risk", ""),
                })
                new_by_id[fid]["risk_changed"] = True
                new_by_id[fid]["previous_risk"] = prev_findings[fid].get("risk")
            else:
                diff_summary["unchanged"] += 1

        for entry in diff_summary["new"]:
            if entry["id"] in new_by_id:
                new_by_id[entry["id"]]["is_new"] = True

        with open(diff_path, "w") as f:
            json.dump({
                "computed_at": datetime.now().isoformat(),
                "previous_archive": archive_path,
                "summary": diff_summary,
            }, f, indent=2)

    except Exception as e:
        logging.getLogger("diff").error(f"Diff error: {e}", exc_info=True)

    return diff_summary


def _run_analysis(project_id: str, project_dir: str,
                  config_files: list, executive_profile: bool = False):
    try:
        room = f"project:{project_id}"
        all_parse_results = []

        _analysis_status[project_id] = {
            "status": "running", "step": "Starting", "percent": 0}

        for i, cfg in enumerate(config_files):
            try:
                pct = int(10 + (i / len(config_files)) * 40)
                _analysis_status[project_id] = {
                    "status": "running",
                    "step": f"Parsing {cfg['filename']}",
                    "percent": pct,
                }
                try:
                    socketio.emit("analysis_progress",
                                  {"step": f"Parsing {cfg['filename']}",
                                   "percent": pct}, room=room)
                except Exception:
                    pass

                config_path = os.path.join(project_dir, "configs",
                                           cfg["filename"])
                text = open(config_path, encoding="utf-8",
                             errors="replace").read()
                vendor = cfg.get("vendor") or detect_vendor(text, cfg["filename"])
                parser = get_parser(vendor, text, cfg["filename"])
                result = parser.parse()
                all_parse_results.append(result)

                for err in result.parse_errors:
                    _buf_append(_error_buffer, project_id, {
                        "ts": _ts(), "type": "PARSE_ERROR",
                        "source": cfg["filename"],
                        "message": err.get("message", ""),
                        "detail": f"Line {err.get('line', '?')}"})

                for warn in result.parse_warnings:
                    _buf_append(_parse_log, project_id, {
                        "ts": _ts(), "level": "WARNING",
                        "source": cfg["filename"],
                        "message": warn.get("message", "")})

                _buf_append(_parse_log, project_id, {
                    "ts": _ts(), "level": "INFO",
                    "source": cfg["filename"],
                    "message": (f"Parsed {cfg['filename']}: {len(result.rules)} rules, "
                                f"{len(result.parse_errors)} errors"),
                })

                try:
                    socketio.emit("parse_complete", {
                        "filename": cfg["filename"],
                        "vendor": vendor,
                        "rules_count": len(result.rules),
                        "errors": len(result.parse_errors),
                    }, room=room)
                except Exception:
                    pass

            except Exception as e:
                _buf_append(_error_buffer, project_id, {
                    "ts": _ts(), "type": "PARSE_ERROR",
                    "source": cfg.get("filename", "?"),
                    "message": str(e),
                    "detail": traceback.format_exc()})
                try:
                    socketio.emit("parse_error",
                                  {"filename": cfg.get("filename", "?"),
                                   "error": str(e)}, room=room)
                except Exception:
                    pass

        # Audit engine
        _analysis_status[project_id] = {
            "status": "running", "step": "Running audit engine", "percent": 55}
        try:
            socketio.emit("analysis_progress",
                          {"step": "Running audit engine", "percent": 55},
                          room=room)
        except Exception:
            pass

        from engine.audit_engine import AuditEngine
        engine = AuditEngine(executive_profile=executive_profile)
        all_findings = []

        for pr in all_parse_results:
            try:
                findings = engine.run(pr)
                all_findings.extend(findings)
                _buf_append(_parse_log, project_id, {
                    "ts": _ts(), "level": "INFO",
                    "source": pr.filename,
                    "message": f"Audit complete: {len(findings)} findings"})
            except Exception as e:
                _buf_append(_error_buffer, project_id, {
                    "ts": _ts(), "type": "AUDIT_ERROR",
                    "source": pr.filename,
                    "message": str(e),
                    "detail": traceback.format_exc()})

        # Multi-config correlation
        if len(all_parse_results) > 1:
            _analysis_status[project_id] = {
                "status": "running",
                "step": "Running multi-device correlation",
                "percent": 65,
            }
            try:
                socketio.emit("analysis_progress",
                              {"step": "Running multi-device correlation",
                               "percent": 65}, room=room)
            except Exception:
                pass

            try:
                from engine.correlation import CorrelationEngine
                corr = CorrelationEngine(all_parse_results)
                corr_findings = corr.generate_correlation_findings()
                all_findings.extend(corr_findings)
                _buf_append(_parse_log, project_id, {
                    "ts": _ts(), "level": "INFO", "source": "correlation",
                    "message": f"{len(corr_findings)} cross-device findings"})
            except Exception as e:
                _buf_append(_error_buffer, project_id, {
                    "ts": _ts(), "type": "CORRELATION_ERROR",
                    "source": "correlation",
                    "message": str(e), "detail": traceback.format_exc()})

        # Build findings dicts
        import dataclasses
        findings_dicts = [dataclasses.asdict(f) for f in all_findings]

        # Diff + archive
        _analysis_status[project_id] = {
            "status": "running",
            "step": "Computing changes since last run",
            "percent": 72,
        }
        try:
            socketio.emit("analysis_progress",
                          {"step": "Computing changes since last run",
                           "percent": 72}, room=room)
        except Exception:
            pass

        diff_summary = _archive_and_diff(project_dir, findings_dicts)

        # Save findings.json
        _analysis_status[project_id] = {
            "status": "running", "step": "Saving findings", "percent": 78}
        try:
            socketio.emit("analysis_progress",
                          {"step": "Saving findings", "percent": 78},
                          room=room)
        except Exception:
            pass

        risk_summary = {}
        for fi in findings_dicts:
            if not fi.get("accepted"):
                risk = fi.get("risk", "Unknown")
                risk_summary[risk] = risk_summary.get(risk, 0) + 1

        findings_data = {
            "project_id": project_id,
            "generated_at": datetime.now().isoformat(),
            "executive_profile": executive_profile,
            "config_files": [{
                "filename": pr.filename,
                "vendor": pr.vendor,
                "hostname": pr.hostname,
                "version": pr.version,
                "rules_parsed": len(pr.rules),
                "parse_errors": len(pr.parse_errors),
                "parse_warnings": len(pr.parse_warnings),
            } for pr in all_parse_results],
            "risk_summary": risk_summary,
            "framework_summary": _compute_framework_summary(findings_dicts),
            "diff_summary": diff_summary,
            "findings": findings_dicts,
        }

        findings_path = os.path.join(project_dir, "findings.json")
        with open(findings_path, "w") as f:
            json.dump(findings_data, f, indent=2)

        # ── Universal findings synthesis (v1.1) ──────────────────────
        # Bastion's native findings.json is dict-wrapped: {"findings": [...]}
        # Synthesise a universal v1.1 finding array next to it so Prometheus's
        # UniversalParser sees the same data via the canonical schema.
        # Native Bastion fields that map directly:
        #   audit_rule_id     → catalogue_id (PHX-style identifier)
        #   evidence (list)   → output (joined)
        #   triggered_lines   → preserved in output
        #   cvss_score/vector → v1.1 cvss_score / cvss_vector
        #   accepted          → v1.1 accepted
        #   framework_*       → v1.1 compliance lists when known
        _bs_synthesize_universal_findings(project_dir, findings_dicts)

        # Generate diagram
        _analysis_status[project_id] = {
            "status": "running",
            "step": "Generating architecture diagram",
            "percent": 87,
        }
        try:
            socketio.emit("analysis_progress",
                          {"step": "Generating architecture diagram",
                           "percent": 87}, room=room)
        except Exception:
            pass

        try:
            from engine.diagram import generate_architecture_diagram
            diag_path = os.path.join(project_dir, "architecture.png")
            logger.info(f"Generating diagram for project {project_id}")
            diag_result = generate_architecture_diagram(
                all_parse_results, diag_path)
            if diag_result.get("success"):
                _buf_append(_parse_log, project_id, {
                    "ts": _ts(), "level": "INFO", "source": "diagram",
                    "message": (f"Diagram generated: "
                                f"{diag_result.get('node_count',0)} nodes, "
                                f"{diag_result.get('edge_count',0)} edges")})
                try:
                    socketio.emit("diagram_complete",
                                  {"path": diag_path}, room=room)
                except Exception:
                    pass
            else:
                _buf_append(_error_buffer, project_id, {
                    "ts": _ts(), "type": "DIAGRAM_ERROR", "source": "diagram",
                    "message": diag_result.get("error", ""),
                    "detail": ""})
        except Exception as e:
            _buf_append(_error_buffer, project_id, {
                "ts": _ts(), "type": "DIAGRAM_ERROR", "source": "diagram",
                "message": str(e), "detail": traceback.format_exc()})

        # Update projects.json
        _raw = load_projects()
        if project_id in _raw.get("projects", {}):
            _raw["projects"][project_id]["status"] = "analyzed"
            _raw["projects"][project_id]["findings_count"] = len(findings_dicts)
            _raw["projects"][project_id]["risk_summary"] = risk_summary
            save_projects(_raw)

        _analysis_status[project_id] = {
            "status": "complete", "step": "Done", "percent": 100}

        try:
            socketio.emit("analysis_complete", {
                "findings_count": len(findings_dicts),
                "risk_summary": risk_summary,
                "diff_summary": diff_summary,
            }, room=room)
        except Exception:
            pass

        _buf_append(_bastion_log, project_id, {
            "ts": _ts(), "event": "analysis_complete",
            "findings": len(findings_dicts),
            "risk_summary": risk_summary})
        logger.info(f"Analysis complete for {project_id}: "
                    f"{len(findings_dicts)} findings")

    except Exception as e:
        _buf_append(_error_buffer, project_id, {
            "ts": _ts(), "type": "APPLICATION", "source": "analysis",
            "message": str(e), "detail": traceback.format_exc()})
        _analysis_status[project_id] = {
            "status": "error", "step": str(e), "percent": 0}
        try:
            socketio.emit("analysis_error", {"error": str(e)}, room=room)
        except Exception:
            pass
    finally:
        _analysis_threads.pop(project_id, None)
        threading.Thread(target=_dequeue_next, daemon=True).start()


# ---------------------------------------------------------------------------
# API: Findings
# ---------------------------------------------------------------------------

@app.route("/api/findings/<project_id>")
def api_findings(project_id):
    try:
        raw = load_projects()
        pinfo = raw.get("projects", {}).get(project_id)
        if not pinfo:
            return jsonify({"error": "Not found"}), 404

        pdir = pinfo.get("project_dir", _project_dir_for(project_id))
        findings_path = os.path.join(pdir, "findings.json")
        if not os.path.exists(findings_path):
            return jsonify({"findings": [], "risk_summary": {},
                            "framework_summary": {}})

        with open(findings_path) as f:
            data = json.load(f)
        return jsonify(data)

    except Exception as e:
        _buf_append(_error_buffer, project_id, {
            "ts": _ts(), "type": "APPLICATION",
            "source": "api_findings", "message": str(e),
            "detail": traceback.format_exc()})
        return jsonify({"error": str(e)}), 500


@app.route("/api/update_finding_risk", methods=["POST"])
def api_update_finding_risk():
    try:
        data = request.get_json(force=True) or {}
        project_id = data.get("project_id", "").strip()
        finding_id = data.get("finding_id", "").strip()
        new_risk = data.get("risk", "").strip()

        raw = load_projects()
        pinfo = raw.get("projects", {}).get(project_id)
        if not pinfo:
            return jsonify({"error": "Not found"}), 404

        pdir = pinfo.get("project_dir", _project_dir_for(project_id))
        findings_path = os.path.join(pdir, "findings.json")
        if not os.path.exists(findings_path):
            return jsonify({"error": "No findings"}), 404

        with open(findings_path) as f:
            fd = json.load(f)

        for fi in fd.get("findings", []):
            if fi.get("id") == finding_id:
                fi["risk"] = new_risk
                break

        with open(findings_path, "w") as f:
            json.dump(fd, f, indent=2)

        return jsonify({"ok": True})

    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/delete_finding", methods=["POST"])
def api_delete_finding():
    try:
        data = request.get_json(force=True) or {}
        project_id = data.get("project_id", "").strip()
        finding_id = data.get("finding_id", "").strip()

        raw = load_projects()
        pinfo = raw.get("projects", {}).get(project_id)
        if not pinfo:
            return jsonify({"error": "Not found"}), 404

        pdir = pinfo.get("project_dir", _project_dir_for(project_id))
        findings_path = os.path.join(pdir, "findings.json")
        if not os.path.exists(findings_path):
            return jsonify({"error": "No findings"}), 404

        with open(findings_path) as f:
            fd = json.load(f)

        fd["findings"] = [fi for fi in fd.get("findings", [])
                          if fi.get("id") != finding_id]

        with open(findings_path, "w") as f:
            json.dump(fd, f, indent=2)

        return jsonify({"ok": True})

    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ── False-positive management ────────────────────────────────────────────────
# Uses /opt/pr0t31n/shared/pr0t31n_false_positives.py. Mark removes the
# finding from findings.json (Bastion stores findings under fd["findings"]),
# adds it to false_positives.json + false_positives.csv. Recover reverses.
_BS_FP_CSV_FIELDS = [
    "id", "title", "audit_rule_id", "severity", "risk", "category",
    "description", "remediation", "evidence", "vendor", "config_file",
]


def _bs_load_fp_helper():
    try:
        import sys as _s
        if "/opt/pr0t31n/shared" not in _s.path:
            _s.path.insert(0, "/opt/pr0t31n/shared")
        import pr0t31n_false_positives as _fp
        return _fp
    except ImportError:
        return None


def _bs_synthesize_universal_findings(project_dir, findings_list):
    """Write a universal v1.1 findings.json + summary.json alongside Bastion's
    native dict-wrapped findings.json. Maps Bastion-specific fields to v1.1.
    Graceful no-op if /opt/pr0t31n/shared/pr0t31n_schema.py is not installed."""
    try:
        import sys as _s
        if "/opt/pr0t31n/shared" not in _s.path:
            _s.path.insert(0, "/opt/pr0t31n/shared")
        import pr0t31n_schema as _us
    except ImportError:
        return
    try:
        mapped = []
        risk_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        for f in (findings_list or []):
            if not isinstance(f, dict):
                continue
            triggered = f.get("triggered_raw") or []
            evidence_str = "\n".join(triggered) if isinstance(triggered, list) else str(triggered)
            risk = str(f.get("risk") or f.get("severity") or "INFO").upper()
            if risk in risk_counts:
                risk_counts[risk] += 1
            # Lift framework_section / framework into v1.1 compliance lists.
            fw = (f.get("framework") or "").upper()
            fw_section = f.get("framework_section") or ""
            nist_800_53 = [fw_section] if "NIST" in fw and "800-53" in fw and fw_section else []
            nist_csf2   = [fw_section] if "NIST" in fw and "CSF" in fw and fw_section else []
            iso_27001   = [fw_section] if "ISO" in fw and fw_section else []
            pci_dss_4   = [fw_section] if "PCI" in fw and fw_section else []
            mapped.append({
                "title":             f.get("title", ""),
                "datetime":          f.get("datetime") or f.get("timestamp", ""),
                "ip":                "",   # Bastion is config-audit, not host-targeted
                "port":              0,
                "hostname":          "",
                "risk":              risk,
                "command":           "bastion config-audit",
                "description":       f.get("description", ""),
                "output":            (f.get("description", "") + "\n\n" + evidence_str)[:8192],
                "output_file":       f.get("config_file", ""),
                "cves":              ",".join(f.get("cves", []) or []) if isinstance(f.get("cves"), list) else (f.get("cves") or ""),
                "sources":           "bastion",
                "service":           "firewall-config",
                "affected":          f.get("config_file", ""),
                "remediation":       f.get("remediation", "Review firewall configuration."),
                "exploitdb":         False,
                "metasploit":        False,
                "exploit_details":   [],
                "phase":             f.get("category", ""),
                "catalogue_id":      f.get("audit_rule_id", ""),
                # ── v1.1 enrichment — Bastion knows these natively ─────────
                "cvss_score":        f.get("cvss_score"),
                "cvss_vector":       f.get("cvss_vector", ""),
                "accepted":          bool(f.get("accepted", False)),
                "nist_800_53":       nist_800_53,
                "nist_csf2":         nist_csf2,
                "iso_27001":         iso_27001,
                "pci_dss_4":         pci_dss_4,
                "confidence":        "Certain" if not f.get("validation_required") else "Tentative",
            })
        _us.write_universal_findings(project_dir, mapped,
                                     tool="bastion", scope=None, phase="")
        from datetime import datetime as _dt, timezone as _tz
        now = _dt.now(_tz.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        _us.write_summary(project_dir, _us.make_summary(
            tool="bastion", version=VERSION,
            scan_start=now, scan_end=now,
            target="firewall-config", success=True,
            total_findings=len(mapped), risk_counts=risk_counts,
        ))
    except Exception:
        # Bastion analysis must not fail because of universal-write trouble.
        pass


def _bs_read_findings_doc(pdir):
    """Load Bastion's findings.json. Returns the wrapper dict (or None)."""
    p = os.path.join(pdir, "findings.json")
    if not os.path.exists(p):
        return None
    try:
        with open(p) as f:
            d = json.load(f)
        return d if isinstance(d, dict) else None
    except Exception:
        return None


def _bs_write_findings_doc(pdir, doc):
    p = os.path.join(pdir, "findings.json")
    with open(p, "w") as f:
        json.dump(doc, f, indent=2)


@app.route("/api/mark_false_positive", methods=["POST"])
def api_mark_false_positive():
    """Move a finding from findings.json to false_positives.{json,csv}."""
    try:
        data = request.get_json(force=True) or {}
        project_id = data.get("project_id", "").strip()
        finding_id = data.get("finding_id", "").strip()
        if not project_id or not finding_id:
            return jsonify({"error": "project_id and finding_id required"}), 400

        raw = load_projects()
        pinfo = raw.get("projects", {}).get(project_id)
        if not pinfo:
            return jsonify({"error": "Project not found"}), 404
        pdir = pinfo.get("project_dir", _project_dir_for(project_id))

        fp_helper = _bs_load_fp_helper()
        if fp_helper is None:
            return jsonify({"error": "pr0t31n_false_positives helper not installed"}), 500

        doc = _bs_read_findings_doc(pdir)
        if doc is None:
            return jsonify({"error": "findings.json not found"}), 404

        removed = None
        kept = []
        for fi in doc.get("findings", []):
            if fi.get("id") == finding_id and removed is None:
                removed = fi
            else:
                kept.append(fi)
        if removed is None:
            return jsonify({"error": "Finding not found"}), 404

        removed["marked_fp_at"] = _ts()
        doc["findings"] = kept
        _bs_write_findings_doc(pdir, doc)
        fp_helper.add_false_positive(pdir, removed, csv_fieldnames=_BS_FP_CSV_FIELDS)
        return jsonify({"ok": True, "finding": removed})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/recover_false_positive", methods=["POST"])
def api_recover_false_positive():
    """Move a finding from false_positives.{json,csv} back to findings.json."""
    try:
        data = request.get_json(force=True) or {}
        project_id = data.get("project_id", "").strip()
        finding_id = data.get("finding_id", "").strip()
        if not project_id or not finding_id:
            return jsonify({"error": "project_id and finding_id required"}), 400

        raw = load_projects()
        pinfo = raw.get("projects", {}).get(project_id)
        if not pinfo:
            return jsonify({"error": "Project not found"}), 404
        pdir = pinfo.get("project_dir", _project_dir_for(project_id))

        fp_helper = _bs_load_fp_helper()
        if fp_helper is None:
            return jsonify({"error": "pr0t31n_false_positives helper not installed"}), 500

        recovered = fp_helper.remove_false_positive(pdir, finding_id,
                                                     csv_fieldnames=_BS_FP_CSV_FIELDS)
        if recovered is None:
            return jsonify({"error": "Finding not found in false_positives.json"}), 404
        recovered.pop("marked_fp_at", None)

        doc = _bs_read_findings_doc(pdir) or {"findings": []}
        doc.setdefault("findings", [])
        # Skip re-insertion if it somehow already exists
        if not any(fi.get("id") == finding_id for fi in doc["findings"]):
            doc["findings"].append(recovered)
        _bs_write_findings_doc(pdir, doc)
        return jsonify({"ok": True, "finding": recovered})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/false_positives/<project_id>")
def api_false_positives_list(project_id):
    """List all false-positive findings for a project."""
    try:
        raw = load_projects()
        pinfo = raw.get("projects", {}).get(project_id)
        if not pinfo:
            return jsonify({"false_positives": []}), 404
        pdir = pinfo.get("project_dir", _project_dir_for(project_id))
        fp_helper = _bs_load_fp_helper()
        if fp_helper is None:
            return jsonify({"false_positives": []})
        return jsonify({"false_positives": fp_helper.load_false_positives(pdir)})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ─── Config-Audit Intelligence panel (shared aggregator) ─────────────────
@app.route("/api/intel/<project_id>")
def api_intel(project_id):
    """Aggregated Config-Audit Intelligence (vendors / frameworks / accepted /
    top rules-hit). Renders in the UI via the shared intel panel."""
    try:
        import sys as _s
        if "/opt/pr0t31n/shared" not in _s.path:
            _s.path.insert(0, "/opt/pr0t31n/shared")
        import pr0t31n_intel as intel
    except ImportError:
        return jsonify({"error": "pr0t31n_intel not installed"}), 500
    raw = load_projects()
    pinfo = raw.get("projects", {}).get(project_id)
    if not pinfo:
        return jsonify({"error": "project not found"}), 404
    pdir = pinfo.get("project_dir", _project_dir_for(project_id))
    # Bastion findings live in the dict-wrapped findings.json; flatten for the aggregator
    findings_path = os.path.join(pdir, "findings.json")
    if not os.path.exists(findings_path):
        return jsonify(intel.aggregator_config([]))
    try:
        with open(findings_path) as f:
            data = json.load(f)
        findings = data.get("findings", []) if isinstance(data, dict) else (data or [])
    except Exception:
        findings = []
    return jsonify(intel.aggregator_config(findings))


@app.route("/api/accept_finding", methods=["POST"])
def api_accept_finding():
    try:
        data = request.get_json(force=True) or {}
        project_id = data.get("project_id", "").strip()
        finding_id = data.get("finding_id", "").strip()
        justification = data.get("justification", "").strip()
        accept = data.get("accept", True)

        if not finding_id:
            return jsonify({"error": "finding_id required"}), 400
        if accept and not justification:
            return jsonify({"error": "justification required to accept a finding"}), 400

        raw = load_projects()
        pinfo = raw.get("projects", {}).get(project_id)
        if not pinfo:
            return jsonify({"error": "Project not found"}), 404

        pdir = pinfo.get("project_dir", _project_dir_for(project_id))
        findings_path = os.path.join(pdir, "findings.json")
        if not os.path.exists(findings_path):
            return jsonify({"error": "findings.json not found"}), 404

        with open(findings_path) as f:
            findings_data = json.load(f)

        updated = False
        for fi in findings_data.get("findings", []):
            if fi.get("id") == finding_id:
                fi["accepted"] = accept
                fi["acceptance_justification"] = justification if accept else ""
                fi["accepted_by"] = session.get("username", "")
                fi["accepted_at"] = _ts() if accept else ""
                updated = True
                break

        if not updated:
            return jsonify({"error": "Finding not found"}), 404

        # Recompute risk_summary excluding accepted
        risk_summary = {}
        for fi in findings_data["findings"]:
            if not fi.get("accepted"):
                risk = fi.get("risk", "Unknown")
                risk_summary[risk] = risk_summary.get(risk, 0) + 1

        findings_data["risk_summary"] = risk_summary
        acc_summary = {}
        for fi in findings_data["findings"]:
            if fi.get("accepted"):
                risk = fi.get("risk", "Unknown")
                acc_summary[risk] = acc_summary.get(risk, 0) + 1
        findings_data["accepted_risk_summary"] = acc_summary

        with open(findings_path, "w") as f:
            json.dump(findings_data, f, indent=2)

        _buf_append(_bastion_log, project_id, {
            "ts": _ts(),
            "event": "finding_accepted" if accept else "finding_unaccepted",
            "finding_id": finding_id,
            "justification": justification,
            "user": session.get("username", ""),
        })

        try:
            socketio.emit("finding_accepted", {
                "finding_id": finding_id,
                "accepted": accept,
                "justification": justification,
            }, room=f"project:{project_id}")
        except Exception:
            pass

        return jsonify({"ok": True, "accepted": accept})

    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/add_note/<finding_id>", methods=["POST"])
def api_add_note(finding_id):
    try:
        data = request.get_json(force=True) or {}
        project_id = data.get("project_id", "").strip()
        note = data.get("note", "").strip()

        raw = load_projects()
        pinfo = raw.get("projects", {}).get(project_id)
        if not pinfo:
            return jsonify({"error": "Not found"}), 404

        pdir = pinfo.get("project_dir", _project_dir_for(project_id))
        findings_path = os.path.join(pdir, "findings.json")
        if not os.path.exists(findings_path):
            return jsonify({"error": "No findings"}), 404

        with open(findings_path) as f:
            fd = json.load(f)

        for fi in fd.get("findings", []):
            if fi.get("id") == finding_id:
                existing = fi.get("analyst_notes", "")
                fi["analyst_notes"] = (
                    (existing + "\n" if existing else "") + note)
                break

        with open(findings_path, "w") as f:
            json.dump(fd, f, indent=2)

        return jsonify({"ok": True})

    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/deleted_findings/<project_id>")
def api_deleted_findings(project_id):
    return jsonify({"findings": []})


@app.route("/api/findings_diff/<project_id>")
def api_findings_diff(project_id):
    try:
        raw = load_projects()
        pinfo = raw.get("projects", {}).get(project_id)
        if not pinfo:
            return jsonify({"error": "Not found"}), 404

        pdir = pinfo.get("project_dir", _project_dir_for(project_id))
        diff_path = os.path.join(pdir, "findings_diff.json")
        if not os.path.exists(diff_path):
            return jsonify({"summary": None})

        with open(diff_path) as f:
            return jsonify(json.load(f))

    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ---------------------------------------------------------------------------
# API: Logs and errors
# ---------------------------------------------------------------------------

@app.route("/api/parse_log/<project_id>")
def api_parse_log(project_id):
    try:
        entries = _parse_log.get(project_id, [])
        return jsonify({"entries": entries})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/bastion_log/<project_id>")
def api_bastion_log(project_id):
    try:
        entries = _bastion_log.get(project_id, [])
        return jsonify({"entries": entries})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/errors/<project_id>")
def api_errors(project_id):
    try:
        entries = _error_buffer.get(project_id, [])
        return jsonify({"entries": entries})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ---------------------------------------------------------------------------
# API: Architecture diagram
# ---------------------------------------------------------------------------

@app.route("/api/architecture/<project_id>")
def api_architecture(project_id):
    try:
        raw = load_projects()
        pinfo = raw.get("projects", {}).get(project_id)
        if not pinfo:
            return jsonify({"error": "Not found"}), 404

        pdir = pinfo.get("project_dir", _project_dir_for(project_id))
        diag_path = os.path.join(pdir, "architecture.png")
        if not os.path.exists(diag_path):
            # Try SVG fallback
            svg_path = os.path.join(pdir, "architecture.png.svg")
            if os.path.exists(svg_path):
                return send_file(svg_path, mimetype="image/svg+xml")
            return jsonify({"error": "No diagram available"}), 404

        return send_file(diag_path, mimetype="image/png")

    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/regenerate_diagram/<project_id>", methods=["POST"])
def api_regenerate_diagram(project_id):
    try:
        raw = load_projects()
        pinfo = raw.get("projects", {}).get(project_id)
        if not pinfo:
            return jsonify({"error": "Not found"}), 404

        pdir = pinfo.get("project_dir", _project_dir_for(project_id))
        findings_path = os.path.join(pdir, "findings.json")
        if not os.path.exists(findings_path):
            return jsonify({"error": "No analysis data"}), 400

        with open(findings_path) as f:
            fd = json.load(f)

        # Rebuild parse results from stored data (minimal stub for diagram)
        cfg_files = fd.get("config_files", [])
        from engine.models import ParseResult
        parse_results = []
        for cfg in cfg_files:
            pr = ParseResult(
                vendor=cfg.get("vendor", "unknown"),
                filename=cfg.get("filename", ""),
                hostname=cfg.get("hostname"),
                version=cfg.get("version"),
                rules=[],
                metadata={"interfaces": {}},
                parse_errors=[],
                parse_warnings=[],
            )
            parse_results.append(pr)

        from engine.diagram import generate_architecture_diagram
        diag_path = os.path.join(pdir, "architecture.png")
        result = generate_architecture_diagram(parse_results, diag_path)
        return jsonify(result)

    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ---------------------------------------------------------------------------
# API: Exports
# ---------------------------------------------------------------------------

@app.route("/api/export_report/<project_id>")
def api_export_report(project_id):
    try:
        raw = load_projects()
        pinfo = raw.get("projects", {}).get(project_id)
        if not pinfo:
            return jsonify({"error": "Not found"}), 404

        from engine.reporter import generate_html_report
        pdir = pinfo.get("project_dir", _project_dir_for(project_id))
        findings_path = os.path.join(pdir, "findings.json")
        if not os.path.exists(findings_path):
            return jsonify({"error": "No findings — run analysis first"}), 400

        with open(findings_path) as f:
            findings_data = json.load(f)

        report_path = generate_html_report(pdir, findings_data, pinfo)
        if not report_path:
            return jsonify({"error": "Report generation failed"}), 500

        return send_file(report_path, as_attachment=True,
                         download_name=os.path.basename(report_path),
                         mimetype="text/html")

    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/export_findings_json/<project_id>")
def api_export_findings_json(project_id):
    try:
        raw = load_projects()
        pinfo = raw.get("projects", {}).get(project_id)
        if not pinfo:
            return jsonify({"error": "Not found"}), 404

        pdir = pinfo.get("project_dir", _project_dir_for(project_id))
        findings_path = os.path.join(pdir, "findings.json")
        if not os.path.exists(findings_path):
            return jsonify({"error": "No findings"}), 404

        return send_file(findings_path, as_attachment=True,
                         download_name="findings.json",
                         mimetype="application/json")

    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/export_zip/<project_id>")
def api_export_zip(project_id):
    try:
        raw = load_projects()
        pinfo = raw.get("projects", {}).get(project_id)
        if not pinfo:
            return jsonify({"error": "Not found"}), 404

        pdir = pinfo.get("project_dir", _project_dir_for(project_id))
        buf = BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
            for root, dirs, files in os.walk(pdir):
                # Exclude large nested dirs
                dirs[:] = [d for d in dirs if d not in ["__pycache__"]]
                for fname in files:
                    fpath = os.path.join(root, fname)
                    arcname = os.path.relpath(fpath, pdir)
                    zf.write(fpath, arcname)

        buf.seek(0)
        project_name = re.sub(r"[^a-zA-Z0-9_-]", "_",
                               pinfo.get("name", project_id))
        return send_file(buf, as_attachment=True,
                         download_name=f"{project_name}.zip",
                         mimetype="application/zip")

    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ---------------------------------------------------------------------------
# SocketIO events
# ---------------------------------------------------------------------------

@socketio.on("join_project")
def on_join_project(data):
    try:
        project_id = data.get("project_id", "")
        room = f"project:{project_id}"
        join_room(room)
        logger.info(f"Client joined room {room}")
    except Exception as e:
        logger.error(f"on_join_project error: {e}")


@socketio.on("connect")
def on_connect():
    logger.debug("SocketIO client connected")


@socketio.on("disconnect")
def on_disconnect():
    logger.debug("SocketIO client disconnected")


# ---------------------------------------------------------------------------
# Job queue helpers
# ---------------------------------------------------------------------------

def _load_execute_queue() -> None:
    global _job_queue
    try:
        if os.path.exists(_QUEUE_FILE):
            with open(_QUEUE_FILE) as _f:
                _job_queue = json.load(_f)
    except Exception:
        _job_queue = []


def _save_execute_queue() -> None:
    try:
        with open(_QUEUE_FILE, "w") as _f:
            json.dump(_job_queue, _f, indent=2)
    except Exception:
        pass


def _is_any_running() -> bool:
    return any(t.is_alive() for t in _analysis_threads.values())


def _execute_queued_job(job: dict) -> None:
    project_id = job.get("project_id", "")
    if not project_id:
        return
    raw   = load_projects()
    pinfo = raw.get("projects", {}).get(project_id)
    if not pinfo:
        return
    cfg_files    = pinfo.get("config_files", [])
    pdir         = pinfo.get("project_dir", _project_dir_for(project_id))
    exec_profile = bool(pinfo.get("executive_profile", False))
    if not cfg_files:
        return
    t = threading.Thread(
        target=_run_analysis,
        args=(project_id, pdir, cfg_files, exec_profile),
        daemon=True,
    )
    _analysis_threads[project_id] = t
    t.start()


def _dequeue_next() -> None:
    with _queue_lock:
        if not _job_queue or _is_any_running():
            return
        job = _job_queue.pop(0)
        _save_execute_queue()
    threading.Thread(target=_execute_queued_job, args=(job,), daemon=True).start()


# ---------------------------------------------------------------------------
# API: Project template + remote execute
# ---------------------------------------------------------------------------

@app.route("/api/project-template")
def api_project_template():
    return jsonify({
        "tool": "bastion",
        "description": "Firewall configuration analysis platform",
        "fields": {
            "name":               {"type": "string",  "required": True,  "label": "Project Name"},
            "client_name":        {"type": "string",  "required": False, "label": "Client Name"},
            "client_short":       {"type": "string",  "required": False, "label": "Client Short Name"},
            "consultant_name":    {"type": "string",  "required": False, "label": "Consultant Name"},
            "start_date":         {"type": "date",    "required": False, "label": "Start Date"},
            "end_date":           {"type": "date",    "required": False, "label": "End Date"},
            "executive_profile":  {"type": "boolean", "required": False, "label": "Executive Profile", "default": False},
            "config_file_paths":  {"type": "text",    "required": False,
                                   "label": "Config File Paths (server-side)",
                                   "hint": "One absolute path per line — files already on this server"},
        },
    })


@app.route("/api/execute-project", methods=["POST"])
def api_execute_project():
    try:
        body = request.get_json(force=True, silent=True) or {}
        execute = body.get("execute", True)

        project_name = (body.get("name") or "").strip()
        if not project_name:
            return jsonify({"error": "Project name is required"}), 400

        project_id  = str(uuid.uuid4())[:8]
        project_dir = _clients_base() / "bastion" / project_id
        project_dir.mkdir(parents=True, exist_ok=True)
        (project_dir / "configs").mkdir(exist_ok=True)
        (project_dir / "reports").mkdir(exist_ok=True)

        # Accept server-side config file paths
        cfg_paths_raw = body.get("config_file_paths", "") or ""
        cfg_files = []
        for raw_path in cfg_paths_raw.splitlines():
            p = raw_path.strip()
            if p and os.path.isfile(p):
                dest = str(project_dir / "configs" / os.path.basename(p))
                try:
                    import shutil as _shutil
                    _shutil.copy2(p, dest)
                    cfg_files.append(dest)
                except Exception:
                    pass

        raw = load_projects()
        raw.setdefault("projects", {})[project_id] = {
            "id":               project_id,
            "name":             project_name,
            "client_name":      body.get("client_name", ""),
            "client_short":     body.get("client_short", ""),
            "consultant_name":  body.get("consultant_name", ""),
            "consultant_email": body.get("consultant_email", ""),
            "project_dir":      str(project_dir),
            "created":          datetime.now().strftime("%Y-%m-%d"),
            "start_date":       body.get("start_date", ""),
            "end_date":         body.get("end_date", ""),
            "status":           "created",
            "executive_profile": bool(body.get("executive_profile", False)),
            "findings_count":   0,
            "risk_summary":     {},
            "config_files":     cfg_files,
        }
        save_projects(raw)

        if not execute or not cfg_files:
            return jsonify({"ok": True, "project_id": project_id,
                            "queued": False, "started": False,
                            "note": "No config files — upload configs then trigger analysis"})

        job = {"project_id": project_id}
        with _queue_lock:
            if _is_any_running():
                position = len(_job_queue) + 1
                _job_queue.append(job)
                _save_execute_queue()
                return jsonify({"ok": True, "project_id": project_id,
                                "queued": True, "position": position})

        threading.Thread(target=_execute_queued_job, args=(job,), daemon=True).start()
        return jsonify({"ok": True, "project_id": project_id, "queued": False, "started": True})

    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    _load_execute_queue()
    import re

    # Ensure projects.json exists
    if not os.path.exists(_PROJECTS_FILE):
        with open(_PROJECTS_FILE, "w") as f:
            json.dump({"projects": {}}, f, indent=2)

    ssl_ctx = _auth.make_ssl_context()
    logger.info(f"Starting Bastion v{VERSION} on https://0.0.0.0:5600")
    socketio.run(app, host="0.0.0.0", port=5600,
                 ssl_context=ssl_ctx, debug=False,
                 allow_unsafe_werkzeug=True)
