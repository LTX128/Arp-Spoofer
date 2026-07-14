import os
import subprocess
import ctypes
import sys
from colorama import Fore, Style, init
import time

init(autoreset=True)

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
SCRIPT_PATH = os.path.join(SCRIPT_DIR, "arp_spoofer.py")
title = "ARP-SPOOFER - LTX & Moka"
NO_ELEVATE = "--no-elevate" in sys.argv


def is_admin_windows() -> bool:
    if os.name != "nt":
        return False
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def set_console_title(text: str) -> None:
    if os.name == "nt":
        try:
            ctypes.windll.kernel32.SetConsoleTitleW(str(text))
        except Exception:
            pass
    else:
        sys.stdout.write(f"\x1b]2;{text}\x07")


def clear_console() -> None:
    if os.name == "nt":
        subprocess.run("cls", shell=True, check=False)
    else:
        subprocess.run(["clear"], check=False)


def pause_console(message: str = "\nPress Enter to continue..."):
    try:
        if sys.stdin.isatty():
            input(message)
            return
    except (EOFError, KeyboardInterrupt):
        pass

    if os.name == "nt":
        try:
            os.system("pause")
        except Exception:
            pass


def launch_spoofer(args: list[str], elevated: bool = True) -> bool:
    """Launch arp_spoofer.py; use UAC elevation on Windows when requested."""
    if not os.path.isfile(SCRIPT_PATH):
        print(Fore.RED + f"[!] Missing script: {SCRIPT_PATH}")
        return False

    launch_args = list(args)
    if NO_ELEVATE and "--no-elevate" not in launch_args:
        launch_args.append("--no-elevate")

    params = subprocess.list2cmdline([SCRIPT_PATH] + launch_args)

    if os.name == "nt" and elevated and not is_admin_windows():
        print(Fore.YELLOW + "[*] Requesting administrator window (accept UAC if prompted)...")
        ret = ctypes.windll.shell32.ShellExecuteW(
            None,
            "runas",
            sys.executable,
            params,
            SCRIPT_DIR,
            1,
        )
        if ret <= 32:
            print(Fore.RED + f"[-] Could not launch elevated process (code {ret}).")
            print(Fore.YELLOW + "[!] Run this terminal as Administrator, then retry.")
            return False
        print(Fore.GREEN + "[+] Launched in a new administrator window.")
        return True

    result = subprocess.run(
        [sys.executable, SCRIPT_PATH] + launch_args,
        cwd=SCRIPT_DIR,
    )
    return result.returncode == 0


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
    return subprocess.list2cmdline([sys.executable, SCRIPT_PATH] + args)


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
        elevated = os.name == "nt" and not NO_ELEVATE and not is_admin_windows()
        launch_spoofer(spoofer_args, elevated=elevated)
    except Exception as exc:
        print(Fore.RED + f"[!] Execution error: {exc}")

    pause_console()


if __name__ == "__main__":
    main()
