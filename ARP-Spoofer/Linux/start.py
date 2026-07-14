#!/usr/bin/env python3
import os
import sys

_SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
if _SCRIPT_DIR not in sys.path:
    sys.path.insert(0, _SCRIPT_DIR)

if os.name == "nt":
    print("This launcher is for Linux. Use Windows/start.bat instead.")
    sys.exit(1)

from common import SCRIPT_DIR, activate_venv_path, bootstrap_venv, ensure_root_or_exit

activate_venv_path()
bootstrap_venv(__file__)

from colorama import Fore, Style, init

init(autoreset=True)

import shlex
import shutil
import subprocess
import time
from typing import Optional

SPOOFER = os.path.join(SCRIPT_DIR, "arp_spoofer.py")
GENERATOR = os.path.join(SCRIPT_DIR, "auto_generate.py")
PYTHON = sys.executable
TITLE = "ARP-SPOOFER - LTX & Moka"


def set_console_title(text: str) -> None:
    sys.stdout.write(f"\x1b]2;{text}\x07")


def clear_console() -> None:
    subprocess.run(["clear"], check=False)


def ensure_root() -> None:
    ensure_root_or_exit(__file__)


def find_terminal() -> Optional[str]:
    for name in (
        "gnome-terminal",
        "konsole",
        "xfce4-terminal",
        "mate-terminal",
        "lxterminal",
        "tilix",
        "kgx",
        "xterm",
        "x-terminal-emulator",
    ):
        if shutil.which(name):
            return name
    return None


def launch_in_new_terminal(title: str, script: str, args: list[str]) -> None:
    cmd_parts = [PYTHON, script, *args]
    inner = (
        f"cd {shlex.quote(SCRIPT_DIR)} && "
        f"export ARP_SPOOFER_WINDOW_TITLE={shlex.quote(title)} && "
        f"{shlex.join(cmd_parts)}; "
        'echo; read -r -p "Press Enter to close..." _'
    )
    term = find_terminal()
    if term == "gnome-terminal":
        subprocess.Popen([term, "--title", title, "--", "bash", "-c", inner])
        return
    if term == "konsole":
        subprocess.Popen([term, "-p", f"tabtitle={title}", "-e", "bash", "-c", inner])
        return
    if term == "xfce4-terminal":
        subprocess.Popen([term, "--title", title, "-e", f"bash -c {shlex.quote(inner)}"])
        return
    if term in ("xterm", "lxterminal", "mate-terminal", "kgx"):
        subprocess.Popen([term, "-T", title, "-e", "bash", "-c", inner])
        return
    if term == "tilix":
        subprocess.Popen([term, "-a", "session-add", "-e", f"bash -c {shlex.quote(inner)}"])
        return
    if term == "x-terminal-emulator":
        subprocess.Popen([term, "-T", title, "-e", f"bash -c {shlex.quote(inner)}"])
        return

    env = os.environ.copy()
    env["ARP_SPOOFER_WINDOW_TITLE"] = title
    proc = subprocess.Popen(cmd_parts, cwd=SCRIPT_DIR, env=env)
    print(Fore.YELLOW + f"[*] No terminal emulator found. Running in background (PID {proc.pid}).")


def print_menu() -> None:
    clear_console()
    print()
    print(Fore.MAGENTA + "  ============================================")
    print(Fore.MAGENTA + "       ARP-SPOOFER - LTX & Moka - Main Menu")
    print(Fore.MAGENTA + "  ============================================")
    print()
    print(Fore.WHITE + "   [1] Launch ARP Attack (auto-detect)")
    print(Fore.WHITE + "   [2] Scan network devices")
    print(Fore.WHITE + "   [3] Scan WiFi networks")
    print(Fore.WHITE + "   [4] Auto command generator")
    print(Fore.WHITE + "   [5] Select adapter (-i) and attack")
    print(Fore.WHITE + "   [6] Manual mode attack (--manual)")
    print(Fore.WHITE + "   [7] Help")
    print(Fore.WHITE + "   [0] Exit")
    print()


def main() -> None:
    ensure_root()
    os.chdir(SCRIPT_DIR)
    os.makedirs(os.path.join(SCRIPT_DIR, "logs"), exist_ok=True)
    set_console_title(TITLE)

    while True:
        print_menu()
        choice = input(Fore.GREEN + "Select option: ").strip()

        if choice == "1":
            launch_in_new_terminal("Launch ARP Attack", SPOOFER, ["--no-elevate", "-a"])
        elif choice == "2":
            launch_in_new_terminal("Scan network devices", SPOOFER, ["--no-elevate", "--scan"])
        elif choice == "3":
            launch_in_new_terminal("Scan WiFi networks", SPOOFER, ["--no-elevate", "--scan-wifi"])
        elif choice == "4":
            launch_in_new_terminal("Auto command generator", GENERATOR, ["--no-elevate"])
        elif choice == "5":
            launch_in_new_terminal(
                "Select adapter (-i) and attack",
                SPOOFER,
                ["--no-elevate", "-i", "-a"],
            )
        elif choice == "6":
            print()
            net_range = input(Fore.WHITE + "Network range (e.g. 192.168.1.0/24): ").strip()
            gateway = input(Fore.WHITE + "Gateway IP (e.g. 192.168.1.1): ").strip()
            launch_in_new_terminal(
                "Manual mode attack (--manual)",
                SPOOFER,
                [
                    "--no-elevate",
                    "--manual",
                    "-r",
                    net_range,
                    "-g",
                    gateway,
                    "-i",
                    "-a",
                ],
            )
        elif choice == "7":
            launch_in_new_terminal("Help", SPOOFER, ["-h", "--no-elevate"])
        elif choice == "0":
            print(Fore.CYAN + "\n[*] Exiting.")
            break
        else:
            print(Fore.RED + "\nInvalid choice.")
            time.sleep(1)
            continue

        time.sleep(0.3)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(Fore.CYAN + "\n[*] Exiting.")
        sys.exit(0)
