"""
Bastion _auth.py — Authentication, CSRF, SSL context, and security headers.
Modelled on the Gauntlet/Vantage/Crucible auth pattern.
"""
import json
import logging
import os
import re
import secrets
import ssl
import stat
import subprocess
import threading
import time
from typing import Optional

import bcrypt
from flask import redirect, request, session, url_for

logger = logging.getLogger("_auth")

_BASE_DIR = os.path.dirname(os.path.abspath(__file__))
_SECRET_KEY_PATH = os.path.join(_BASE_DIR, ".secret_key")
_AUTH_PATH = os.path.join(_BASE_DIR, ".auth.json")

_BLOCKED_USERNAMES = {
    "admin", "administrator", "root", "user", "users", "guest",
    "test", "demo", "superuser", "super", "sysadmin", "operator",
    "manager", "owner", "service", "support", "helpdesk", "webmaster",
    "postmaster", "nobody", "default", "anonymous", "anon", "public",
    "system", "login", "logon", "access", "account", "info", "mail",
}

_BLOCKED_PASSWORDS = {
    "password", "password1", "password123", "123456", "qwerty",
    "abc123", "letmein", "welcome", "admin", "admin123", "changeme",
    "iloveyou", "monkey", "dragon", "master", "shadow", "trustno1",
    "test", "test123", "guest", "pass", "pass123",
}

# CSRF token store: token -> expiry_timestamp
_csrf_store: dict = {}
_csrf_lock = threading.Lock()
_CSRF_EXPIRY = 3600  # 1 hour


# ---------------------------------------------------------------------------
# 1. load_secret_key
# ---------------------------------------------------------------------------

def load_secret_key() -> str:
    """Read secret key from .secret_key; create 64-hex-char secret on first run."""
    try:
        if os.path.exists(_SECRET_KEY_PATH):
            with open(_SECRET_KEY_PATH, "r") as f:
                key = f.read().strip()
            if len(key) == 64:
                return key
        key = secrets.token_hex(32)
        with open(_SECRET_KEY_PATH, "w") as f:
            f.write(key)
        os.chmod(_SECRET_KEY_PATH, stat.S_IRUSR | stat.S_IWUSR)
        return key
    except Exception as e:
        logger.error(f"load_secret_key error: {e}")
        return secrets.token_hex(32)


# ---------------------------------------------------------------------------
# 2. init_auth
# ---------------------------------------------------------------------------

def init_auth() -> None:
    """Create .auth.json if absent with default admin credentials."""
    try:
        if not os.path.exists(_AUTH_PATH):
            pw_hash = bcrypt.hashpw(b"t3mpPas$w0rd", bcrypt.gensalt()).decode()
            auth_data = {
                "username": "admin",
                "password_hash": pw_hash,
                "must_change": True,
            }
            with open(_AUTH_PATH, "w") as f:
                json.dump(auth_data, f, indent=2)
            os.chmod(_AUTH_PATH, stat.S_IRUSR | stat.S_IWUSR)
            logger.info("Created default auth credentials.")
    except Exception as e:
        logger.error(f"init_auth error: {e}")


def _load_auth() -> dict:
    try:
        with open(_AUTH_PATH, "r") as f:
            return json.load(f)
    except Exception:
        return {}


def _save_auth(data: dict) -> None:
    try:
        with open(_AUTH_PATH, "w") as f:
            json.dump(data, f, indent=2)
        os.chmod(_AUTH_PATH, stat.S_IRUSR | stat.S_IWUSR)
    except Exception as e:
        logger.error(f"_save_auth error: {e}")


# ---------------------------------------------------------------------------
# 3. verify_credentials
# ---------------------------------------------------------------------------

def verify_credentials(username: str, password: str) -> bool:
    """Verify username and password against stored credentials."""
    try:
        auth = _load_auth()
        if not auth:
            return False
        if auth.get("username", "").lower() != username.lower():
            return False
        pw_hash = auth.get("password_hash", "")
        return bcrypt.checkpw(password.encode(), pw_hash.encode())
    except Exception as e:
        logger.error(f"verify_credentials error: {e}")
        return False


# ---------------------------------------------------------------------------
# 4. must_change_password
# ---------------------------------------------------------------------------

def must_change_password() -> bool:
    """Return True if the user must change their password."""
    try:
        return bool(_load_auth().get("must_change", False))
    except Exception:
        return False


# ---------------------------------------------------------------------------
# 5. get_username
# ---------------------------------------------------------------------------

def get_username() -> str:
    """Return the current stored username."""
    try:
        return _load_auth().get("username", "admin")
    except Exception:
        return "admin"


# ---------------------------------------------------------------------------
# 6. check_current_password
# ---------------------------------------------------------------------------

def check_current_password(password: str) -> bool:
    """Check if the provided password matches the current stored password."""
    try:
        auth = _load_auth()
        pw_hash = auth.get("password_hash", "")
        return bcrypt.checkpw(password.encode(), pw_hash.encode())
    except Exception as e:
        logger.error(f"check_current_password error: {e}")
        return False


# ---------------------------------------------------------------------------
# 7. update_password
# ---------------------------------------------------------------------------

def update_password(new_password: str) -> None:
    """Update password only; sets must_change to False."""
    try:
        auth = _load_auth()
        auth["password_hash"] = bcrypt.hashpw(
            new_password.encode(), bcrypt.gensalt()
        ).decode()
        auth["must_change"] = False
        _save_auth(auth)
    except Exception as e:
        logger.error(f"update_password error: {e}")


# ---------------------------------------------------------------------------
# 8. update_credentials
# ---------------------------------------------------------------------------

def update_credentials(new_username: str, new_password: str) -> None:
    """Update both username and password; sets must_change to False."""
    try:
        auth = _load_auth()
        auth["username"] = new_username
        auth["password_hash"] = bcrypt.hashpw(
            new_password.encode(), bcrypt.gensalt()
        ).decode()
        auth["must_change"] = False
        _save_auth(auth)
    except Exception as e:
        logger.error(f"update_credentials error: {e}")


# ---------------------------------------------------------------------------
# 9. generate_csrf
# ---------------------------------------------------------------------------

def generate_csrf() -> str:
    """Generate a CSRF token, store with 1-hour expiry, prune expired tokens."""
    try:
        now = time.time()
        token = secrets.token_hex(16)
        with _csrf_lock:
            # Prune expired tokens
            expired = [t for t, exp in _csrf_store.items() if exp < now]
            for t in expired:
                del _csrf_store[t]
            _csrf_store[token] = now + _CSRF_EXPIRY
        return token
    except Exception as e:
        logger.error(f"generate_csrf error: {e}")
        return secrets.token_hex(16)


# ---------------------------------------------------------------------------
# 10. validate_csrf
# ---------------------------------------------------------------------------

def validate_csrf(token: str) -> bool:
    """Validate and consume a CSRF token."""
    try:
        now = time.time()
        with _csrf_lock:
            expiry = _csrf_store.pop(token, None)
            if expiry is None:
                return False
            return expiry >= now
    except Exception as e:
        logger.error(f"validate_csrf error: {e}")
        return False


# ---------------------------------------------------------------------------
# 11. is_weak_username
# ---------------------------------------------------------------------------

def is_weak_username(username: str) -> Optional[str]:
    """Return error message string if username is weak, else None."""
    if not username:
        return "Username cannot be empty."
    if len(username) < 3:
        return "Username must be at least 3 characters."
    if len(username) > 32:
        return "Username must be 32 characters or fewer."
    if username.lower() in _BLOCKED_USERNAMES:
        return f"Username '{username}' is not allowed."
    return None


# ---------------------------------------------------------------------------
# 12. is_weak_password
# ---------------------------------------------------------------------------

def is_weak_password(password: str, username: str = "") -> Optional[str]:
    """Return error message string if password is weak, else None."""
    if not password:
        return "Password cannot be empty."
    if len(password) < 12:
        return "Password must be at least 12 characters."
    if password.lower() in _BLOCKED_PASSWORDS:
        return "That password is too common. Please choose a stronger password."
    if username and password.lower() == username.lower():
        return "Password cannot be the same as your username."
    return None


# ---------------------------------------------------------------------------
# 13. make_ssl_context
# ---------------------------------------------------------------------------

def _local_ips_for_cert() -> list:
    """Enumerate local IPv4 addresses for the SAN field."""
    ips = ["127.0.0.1"]
    try:
        result = subprocess.run(
            ["ip", "-4", "addr"], capture_output=True, text=True, timeout=5
        )
        if result.returncode == 0:
            found = re.findall(r"inet\s+([\d.]+)/", result.stdout)
            ips.extend(ip for ip in found if ip not in ips)
        else:
            raise OSError("ip command failed")
    except Exception:
        try:
            result = subprocess.run(
                ["ifconfig"], capture_output=True, text=True, timeout=5
            )
            if result.returncode == 0:
                found = re.findall(r"inet\s+([\d.]+)", result.stdout)
                ips.extend(ip for ip in found if ip not in ips)
        except Exception:
            pass
    return ips


def make_ssl_context() -> ssl.SSLContext:
    """Generate self-signed cert if absent; return configured SSLContext."""
    try:
        cert_path = os.path.join(_BASE_DIR, "ssl.crt")
        key_path = os.path.join(_BASE_DIR, "ssl.key")

        if not (os.path.exists(cert_path) and os.path.exists(key_path)):
            local_ips = _local_ips_for_cert()
            san_entries = ",".join(
                [f"IP:{ip}" for ip in local_ips] + ["DNS:localhost"]
            )
            cmd = [
                "openssl", "req", "-x509", "-newkey", "rsa:4096",
                "-nodes", "-days", "3650",
                "-keyout", key_path,
                "-out", cert_path,
                "-subj", "/C=US/ST=Local/L=Local/O=Bastion/CN=localhost",
                "-addext", f"subjectAltName={san_entries}",
            ]
            subprocess.run(cmd, check=True, capture_output=True)
            logger.info("Generated self-signed SSL certificate.")

        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.load_cert_chain(cert_path, key_path)
        try:
            ctx.set_ciphers(
                "ECDHE-ECDSA-AES256-GCM-SHA384:"
                "ECDHE-RSA-AES256-GCM-SHA384:"
                "ECDHE-ECDSA-CHACHA20-POLY1305:"
                "ECDHE-RSA-CHACHA20-POLY1305:"
                "ECDHE-ECDSA-AES128-GCM-SHA256:"
                "ECDHE-RSA-AES128-GCM-SHA256:"
                "!aNULL:!eNULL:!EXPORT:!DES:!RC4"
            )
        except ssl.SSLError:
            pass  # Fall back to default if cipher list fails
        return ctx
    except Exception as e:
        logger.error(f"make_ssl_context error: {e}")
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        cert_path = os.path.join(_BASE_DIR, "ssl.crt")
        key_path = os.path.join(_BASE_DIR, "ssl.key")
        if os.path.exists(cert_path) and os.path.exists(key_path):
            ctx.load_cert_chain(cert_path, key_path)
        return ctx


# ---------------------------------------------------------------------------
# 14. apply_security_headers
# ---------------------------------------------------------------------------

def apply_security_headers(response):
    """Apply security headers to every response."""
    response.headers["Strict-Transport-Security"] = (
        "max-age=31536000; includeSubDomains"
    )
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline'; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
        "font-src 'self' https://fonts.gstatic.com data:; "
        "img-src 'self' data:; "
        "connect-src 'self' wss: ws:; "
        "frame-ancestors 'none'; "
        "base-uri 'self'; "
        "form-action 'self'"
    )
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = (
        "geolocation=(), microphone=(), camera=()"
    )
    response.headers["X-XSS-Protection"] = "1; mode=block"
    return response


# ---------------------------------------------------------------------------
# 15. auth_gate
# ---------------------------------------------------------------------------

def auth_gate():
    """
    Called before every request (via before_request).
    Exempt: /static/*, /login, /logout, /api/nexus-status
    Redirects to /login if not authenticated.
    Redirects to /auth/change-password if must_change is True.
    """
    path = request.path

    # Exempt paths
    if (
        path.startswith("/static/")
        or path in ("/login", "/logout", "/api/nexus-status")
    ):
        return None

    if not session.get("authenticated"):
        return redirect(url_for("login"))

    if must_change_password() and path != "/auth/change-password":
        return redirect(url_for("change_password"))

    return None
