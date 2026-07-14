#!/usr/bin/env python3
import os
import sys

_SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
if _SCRIPT_DIR not in sys.path:
    sys.path.insert(0, _SCRIPT_DIR)

if os.name == "nt":
    print("This generator is for Linux. Use Windows/auto_generate.py instead.")
    sys.exit(1)

from common import SCRIPT_DIR, activate_venv_path, bootstrap_venv, run_as_root

activate_venv_path()
bootstrap_venv(__file__)

from colorama import Fore, Style, init

init(autoreset=True)

import shlex
import subprocess
import time

SCRIPT_PATH = os.path.join(SCRIPT_DIR, "arp_spoofer.py")
PYTHON = sys.executable
title = "ARP-SPOOFER - LTX & Moka"
NO_ELEVATE = "--no-elevate" in sys.argv


def is_root() -> bool:
    return os.geteuid() == 0


def set_console_title(text: str) -> None:
    sys.stdout.write(f"\x1b]2;{text}\x07")


def clear_console() -> None:
    subprocess.run(["clear"], check=False)


def pause_console(message: str = "\nPress Enter to continue..."):
    try:
        if sys.stdin.isatty():
            input(message)
            return
    except (EOFError, KeyboardInterrupt):
        pass


def launch_spoofer(args: list[str], elevated: bool = True) -> bool:
    if not os.path.isfile(SCRIPT_PATH):
        print(Fore.RED + f"[!] Missing script: {SCRIPT_PATH}")
        return False

    launch_args = list(args)
    if NO_ELEVATE and "--no-elevate" not in launch_args:
        launch_args.append("--no-elevate")

    if elevated and not is_root():
        print(Fore.YELLOW + "[*] Root privileges required. Re-launching with sudo...")
        try:
            run_as_root(SCRIPT_PATH, launch_args)
        except OSError as exc:
            print(Fore.RED + f"[-] sudo failed: {exc}")
            print(Fore.YELLOW + f"[!] Run with: sudo {sys.executable} {__file__}")
            return False
        return True

    proc = None
    try:
        proc = subprocess.Popen(
            [PYTHON, SCRIPT_PATH, *launch_args],
            cwd=SCRIPT_DIR,
        )
        proc.wait()
        return proc.returncode == 0
    except KeyboardInterrupt:
        print(Fore.CYAN + "\n[*] Stopped by user.")
        if proc is not None and proc.poll() is None:
            try:
                proc.terminate()
                proc.wait(timeout=5)
            except (subprocess.TimeoutExpired, OSError):
                try:
                    proc.kill()
                    proc.wait(timeout=2)
                except (subprocess.TimeoutExpired, OSError):
                    pass
        return False


def banner():
    print(Fore.CYAN + r"""
         █████╗ ██████╗ ██████╗       ███████╗██████╗  ██████╗  ██████╗ ███████╗███████╗██████╗ 
        ██╔══██╗██╔══██╗██╔══██╗      ██╔════╝██╔══██╗██╔═══██╗██╔═══██╗██╔════╝██╔════╝██╔══██╗
        ███████║██████╔╝██████╔╝█████╗███████╗██████╔╝██║   ██║██║   ██║█████╗  █████╗  ██████╔╝
        ██╔══██║██╔══██╗██╔═══╝ ╚════╝╚════██║██╔═══╝ ██║   ██║██║   ██║██╔══╝  ██╔══╝  ██╔══██╗
        ██║  ██║██║  ██║██║           ███████║██║     ╚██████╔╝╚██████╔╝██║     ███████╗██║  ██║
        ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝           ╚══════╝╚═╝      ╚═════╝  ╚═════╝ ╚═╝     ╚══════╝╚═╝  ╚═╝
                    Auto Command Generator - By LTX & Moka
    """ + Style.RESET_ALL)


def separator():
    print(Fore.CYAN + "────────────────────────────────────────────────────────────" + Style.RESET_ALL)


def build_spoofer_args(mode: str) -> list[str]:
    args: list[str] = []

    if mode == "2":
        export = input(Fore.GREEN + "Export to file? (.json/.csv, leave empty to skip): ").strip()
        args.append("--scan")
        if export:
            args.extend(["-o", export])
        if input(Fore.GREEN + "Select adapter with -i? (y/n): ").lower() == "y":
            args.append("-i")
        return args

    if mode == "3":
        export = input(Fore.GREEN + "Export to file? (.json/.csv, leave empty to skip): ").strip()
        args.append("--scan-wifi")
        if export:
            args.extend(["-o", export])
        return args

    print(Fore.CYAN + "\n[NETWORK] Configuration mode:")
    print(Fore.WHITE + "  1. Auto-detect (recommended)")
    print(Fore.WHITE + "  2. Select adapter (-i)")
    print(Fore.WHITE + "  3. Manual (-r / -g)")
    net_mode = input(Fore.GREEN + "Choice (1/2/3) [1]: ").strip() or "1"

    if net_mode == "2":
        args.append("-i")
    elif net_mode == "3":
        net_range = input(Fore.WHITE + "[?] Network range (e.g. 192.168.1.0/24): ").strip()
        gateway = input(Fore.WHITE + "[?] Gateway IP (e.g. 192.168.1.1): ").strip()
        args.extend(["--manual", "-r", net_range, "-g", gateway])
        if input(Fore.GREEN + "Select adapter with -i? (y/n): ").lower() == "y":
            args.append("-i")

    print(Fore.CYAN + "\n[OPTION] -a  (Auto Attack)")
    if input(Fore.GREEN + "Enable -a ? (y/n): ").lower() == "y":
        args.append("-a")

    print(Fore.CYAN + "\n[OPTION] -s  (Sniffer)")
    if input(Fore.GREEN + "Enable -s ? (y/n): ").lower() == "y":
        args.append("-s")

    print(Fore.CYAN + "\n[OPTION] --no-recovery")
    if input(Fore.GREEN + "Disable recovery? (y/n): ").lower() == "y":
        args.append("--no-recovery")

    return args


def format_command(args: list[str]) -> str:
    return shlex.join([PYTHON, SCRIPT_PATH, *args])


def main():
    os.chdir(SCRIPT_DIR)
    set_console_title(os.environ.get("ARP_SPOOFER_WINDOW_TITLE", title))
    clear_console()
    banner()

    print(Fore.CYAN + "\n[MODE] Select operation:")
    print(Fore.WHITE + "  1. ARP Attack (spoof)")
    print(Fore.WHITE + "  2. Scan devices (--scan)")
    print(Fore.WHITE + "  3. Scan WiFi (--scan-wifi)")
    mode = input(Fore.GREEN + "Choice (1/2/3) [1]: ").strip() or "1"

    spoofer_args = build_spoofer_args(mode)
    if NO_ELEVATE and "--no-elevate" not in spoofer_args:
        spoofer_args.append("--no-elevate")
    command_preview = format_command(spoofer_args)

    print("\n" + Fore.GREEN + "[+] Final command:")
    print(Fore.MAGENTA + command_preview)
    separator()

    if input(Fore.WHITE + "\nStart ARP-SPOOFER? (y/n): ").lower() != "y":
        print(Fore.YELLOW + "[*] Cancelled.")
        pause_console()
        return

    print(Fore.YELLOW + "\n[*] Launching ARP-SPOOFER...")
    time.sleep(0.5)

    try:
        elevated = not NO_ELEVATE and not is_root()
        launch_spoofer(spoofer_args, elevated=elevated)
    except KeyboardInterrupt:
        print(Fore.CYAN + "\n[*] Stopped by user.")
    except Exception as exc:
        print(Fore.RED + f"[!] Execution error: {exc}")

    pause_console()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(Fore.CYAN + "\n[*] Stopped by user.")
