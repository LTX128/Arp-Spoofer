#!/usr/bin/env python3
"""Shared helpers for Linux launcher scripts."""
import os
import shutil
import subprocess
import sys
from typing import Optional

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
REQUIREMENTS = os.path.join(SCRIPT_DIR, "requirements.txt")
START_SCRIPT = os.path.join(SCRIPT_DIR, "auto_generate.py")
VENV_DIR = os.path.join(SCRIPT_DIR, "venv")
VENV_PYTHON = os.path.join(VENV_DIR, "bin", "python")
VENV_PIP = os.path.join(VENV_DIR, "bin", "pip")


def is_wsl() -> bool:
    try:
        with open("/proc/version", "r", encoding="utf-8") as fh:
            return "microsoft" in fh.read().lower()
    except OSError:
        return False


def venv_ready() -> bool:
    return os.path.isfile(VENV_PYTHON)


def running_in_venv() -> bool:
    if not venv_ready():
        return False
    try:
        return os.path.samefile(sys.executable, VENV_PYTHON)
    except OSError:
        return os.path.realpath(sys.executable) == os.path.realpath(VENV_PYTHON)


def get_python() -> str:
    if venv_ready():
        return VENV_PYTHON
    return sys.executable


def destroy_venv() -> bool:
    """Nuke the venv directory from orbit."""
    if os.path.exists(VENV_DIR):
        print("[*] Destroying existing virtual environment (venv/)...")
        try:
            shutil.rmtree(VENV_DIR, ignore_errors=True)
            return True
        except Exception as e:
            print(f"[ERROR] Failed to remove venv: {e}")
            return False
    return True


def create_venv() -> bool:
    if venv_ready():
        return True

    print("[*] Creating virtual environment (venv/)...")
    result = subprocess.run(
        [sys.executable, "-m", "venv", VENV_DIR],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        print("[ERROR] Failed to create virtual environment.")
        err = (result.stderr or result.stdout or "").strip()
        if err:
            print(err)
        print("[!] Install venv support, then retry:")
        print("    sudo apt install python3-venv python3-full")
        return False
    return venv_ready()


def install_requirements(requirements_path: Optional[str] = None, force_reinstall: bool = False) -> bool:
    """Create local venv and install all Python dependencies inside it. Nukes and retries on failure."""
    req = requirements_path or REQUIREMENTS
    if not os.path.isfile(req):
        print(f"[ERROR] Missing requirements file: {req}")
        return False

    if force_reinstall:
        destroy_venv()

    if not create_venv():
        return False

    print("[*] Installing Python packages in virtual environment (no cache)...")
    upgrade = subprocess.run([VENV_PIP, "install", "--no-cache-dir", "-U", "pip"], capture_output=True, text=True)
    if upgrade.returncode != 0:
        print("[ERROR] Failed to upgrade pip in virtual environment.")
        if upgrade.stderr:
            print(upgrade.stderr.strip())
        # Nuke and retry once
        if not force_reinstall:
            print("[*] Retrying with fresh venv...")
            return install_requirements(req, force_reinstall=True)
        return False

    install = subprocess.run([VENV_PIP, "install", "--no-cache-dir", "-r", req], capture_output=True, text=True)
    if install.returncode != 0:
        print("[ERROR] Failed to install Python packages in virtual environment.")
        if install.stderr:
            print(install.stderr.strip())
        # Nuke and retry once
        if not force_reinstall:
            print("[*] Retrying with fresh venv...")
            return install_requirements(req, force_reinstall=True)
        return False

    verify = subprocess.run(
        [VENV_PYTHON, "-c", "import colorama, scapy"],
        capture_output=True,
        text=True,
    )
    if verify.returncode != 0:
        print("[ERROR] Virtual environment verification failed (colorama/scapy).")
        if verify.stderr:
            print(verify.stderr.strip())
        # Nuke and retry once
        if not force_reinstall:
            print("[*] Verification failed. Nuking venv and retrying from scratch...")
            return install_requirements(req, force_reinstall=True)
        return False

    return True


def activate_venv_path() -> bool:
    """Inject venv site-packages into sys.path (works with sudo python3)."""
    if os.name == "nt":
        return False
    if not venv_ready():
        return False

    site_packages = ""
    try:
        result = subprocess.run(
            [VENV_PYTHON, "-c", "import sysconfig; print(sysconfig.get_path('purelib'))"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        if result.returncode == 0:
            site_packages = (result.stdout or "").strip()
    except (OSError, subprocess.TimeoutExpired):
        site_packages = ""

    if site_packages and os.path.isdir(site_packages):
        if site_packages not in sys.path:
            sys.path.insert(0, site_packages)
        return True

    venv_lib = os.path.join(VENV_DIR, "lib")
    if not os.path.isdir(venv_lib):
        return False
    activated = False
    for entry in sorted(os.listdir(venv_lib)):
        if not entry.startswith("python"):
            continue
        candidate = os.path.join(venv_lib, entry, "site-packages")
        if os.path.isdir(candidate) and candidate not in sys.path:
            sys.path.insert(0, candidate)
            activated = True
    return activated


def _venv_deps_available() -> bool:
    try:
        import colorama  # noqa: F401
        return True
    except ModuleNotFoundError:
        return False


def bootstrap_venv(script_path: str) -> None:
    """Ensure project venv packages are visible to the current Python process."""
    if os.name == "nt":
        return
    if not running_in_venv():
        activate_venv_path()
    if _venv_deps_available():
        return
    if not venv_ready():
        print("[ERROR] Virtual environment not found.")
        print("[!] Run setup first:")
        print(f"    python3 {os.path.join(SCRIPT_DIR, 'setup.py')}")
        sys.exit(1)
    print("[ERROR] Virtual environment found but packages could not be loaded.")
    print(f"[!] Re-run setup: python3 {os.path.join(SCRIPT_DIR, 'setup.py')} --force")
    print(f"[!] Or use: sudo {VENV_PYTHON} {script_path}")
    sys.exit(1)


def run_as_root(script_path: str, extra_args: Optional[list[str]] = None) -> None:
    """Re-exec a script with sudo; scripts load venv packages via sys.path."""
    args = ["sudo", sys.executable, script_path]
    if extra_args:
        args.extend(extra_args)
    os.execvp("sudo", args)


def ensure_root_or_exit(script_path: str) -> None:
    if os.geteuid() == 0:
        return
    print("[*] Root privileges required. Re-launching with sudo...")
    try:
        run_as_root(script_path, sys.argv[1:])
    except OSError as exc:
        print(f"[-] sudo failed: {exc}")
        print(f"[!] Run with: sudo {sys.executable} {script_path}")
        sys.exit(1)