#!/usr/bin/env python3
"""Bastion v1.0.0 — First-run installer."""
import subprocess
import sys
import os
from pathlib import Path


def _pip_installed(pkg_spec):
    """Return True if a pip package is already importable."""
    import importlib.util
    name = pkg_spec.split(">=")[0].split("==")[0].split("[")[0].split("<")[0].strip()
    _IMPORT_MAP = {
        "flask-socketio": "flask_socketio", "pyyaml": "yaml",
        "python-engineio": "engineio", "python-socketio": "socketio",
        "Pillow": "PIL",
    }
    mod = _IMPORT_MAP.get(name, name.replace("-", "_"))
    return importlib.util.find_spec(mod) is not None


def main():
    print("=" * 60)
    print("Bastion v1.0.0 — Installation")
    print("=" * 60)

    # Python version check
    if sys.version_info < (3, 10):
        print("ERROR: Python 3.10+ required")
        sys.exit(1)
    print(f"Python {sys.version_info.major}.{sys.version_info.minor} OK")

    # Install requirements
    print("\nInstalling Python dependencies...")
    req = Path("requirements.txt")
    if req.exists():
        with open(req) as f:
            pkgs = [ln.strip() for ln in f if ln.strip() and not ln.startswith("#")]
        _to_install = []
        for pkg in pkgs:
            if _pip_installed(pkg):
                print(f"  ✓ {pkg} already installed")
            else:
                _to_install.append(pkg)
        if _to_install:
            print(f"  Installing {len(_to_install)} package(s)…")
            try:
                subprocess.check_call([
                    sys.executable, "-m", "pip",
                    "install", "--break-system-packages", "--quiet",
                ] + _to_install)
                print("  Dependencies installed OK")
            except subprocess.CalledProcessError as e:
                print(f"ERROR: pip install failed: {e}")
                sys.exit(1)
        else:
            print("  All pip packages already installed.")
    else:
        print("  ! requirements.txt not found — skipping pip install")

    # Create required directories
    print("\nCreating directory structure...")
    for d in [
        "static/css", "static/js", "templates",
        "engine/parsers", "projects",
    ]:
        Path(d).mkdir(parents=True, exist_ok=True)
    print("Directories OK")

    # Create projects.json if absent
    pjson = Path("projects.json")
    if not pjson.exists():
        pjson.write_text('{"projects": {}}\n')
        print("Created projects.json")

    # Download socket.io.min.js
    sio = Path("static/js/socket.io.min.js")
    if not sio.exists():
        print("\nDownloading socket.io.min.js...")
        try:
            import urllib.request
            url = "https://cdn.socket.io/4.7.5/socket.io.min.js"
            urllib.request.urlretrieve(url, str(sio))
            print("Downloaded socket.io.min.js OK")
        except Exception as e:
            print(f"WARNING: Could not download socket.io.min.js: {e}")
            print("You may need to download it manually from:")
            print("  https://cdn.socket.io/4.7.5/socket.io.min.js")
            # Create a stub so the app doesn't 404
            sio.write_text("/* socket.io.min.js placeholder — download failed */")
    else:
        print("socket.io.min.js already present")

    # Initialize authentication
    print("\nInitializing authentication...")
    try:
        sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
        import _auth
        _auth.init_auth()
        print("Auth initialized OK")
    except Exception as e:
        print(f"WARNING: Auth init failed: {e}")

    # Done
    print("\n" + "=" * 60)
    print("Installation complete!")
    print("=" * 60)
    print()
    print("Default credentials: admin / t3mpPas$w0rd")
    print("You will be required to change these on first login.")
    print()
    print("Start Bastion with:")
    print("  python app.py")
    print()
    print("Then open: https://localhost:5600")
    print()
    print("NOTE: A self-signed TLS certificate will be generated on")
    print("first run. Accept the browser security warning.")
    print("=" * 60)


if __name__ == "__main__":
    main()
