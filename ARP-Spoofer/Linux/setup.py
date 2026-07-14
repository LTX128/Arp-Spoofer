#!/usr/bin/env python3
import os
import platform
import shutil
import subprocess
import sys

if os.name == "nt":
    print("This setup script is for Linux. Use Windows/setup.bat instead.")
    sys.exit(1)

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from common import (
    SCRIPT_DIR,
    START_SCRIPT,
    VENV_PYTHON,
    get_python,
    install_requirements,
    is_wsl,
    running_in_venv,
    run_as_root,
)

REQUIREMENTS = os.path.join(SCRIPT_DIR, "requirements.txt")


def pause(message: str = "\nPress Enter to continue..."):
    try:
        input(message)
    except (EOFError, KeyboardInterrupt):
        pass


def main() -> None:
    os.chdir(SCRIPT_DIR)
    os.makedirs(os.path.join(SCRIPT_DIR, "logs"), exist_ok=True)

    if not running_in_venv():
        print()
        print("============================================")
        print("       ARP-SPOOFER - Setup - LTX & Moka")
        print("============================================")
        print(f" Platform: {platform.system()} {platform.release()}")
        if is_wsl():
            print(" Environment: WSL detected")
            print(" Note: WiFi scan/tools may be unavailable inside WSL.")
        print()
        print("[*] Checking Python installation...")
        print(f"[OK] Python {sys.version.split()[0]} detected.")
        print()
        print("[*] Setting up virtual environment...")
        if not install_requirements(REQUIREMENTS):
            pause()
            sys.exit(1)
        print("[OK] Virtual environment ready.")
        print("[*] Restarting setup inside the virtual environment...")
        os.execv(VENV_PYTHON, [VENV_PYTHON, __file__, *sys.argv[1:]])

    from colorama import Fore, Style, init

    init(autoreset=True)

    def detect_package_manager() -> str:
        if shutil.which("apt-get"):
            return "apt"
        if shutil.which("dnf"):
            return "dnf"
        if shutil.which("pacman"):
            return "pacman"
        return ""

    def suggest_system_packages() -> None:
        pm = detect_package_manager()
        if pm == "apt":
            print(Fore.CYAN + "[*] Recommended system packages (Debian/Ubuntu):")
            print(Fore.WHITE + "    sudo apt update")
            print(
                Fore.WHITE
                + "    sudo apt install -y python3-venv python3-full python3-pip "
                + "iproute2 net-tools wireless-tools iw dnsutils"
            )
        elif pm == "dnf":
            print(Fore.CYAN + "[*] Recommended system packages (Fedora/RHEL):")
            print(
                Fore.WHITE
                + "    sudo dnf install -y python3-pip iproute net-tools "
                + "NetworkManager wireless-tools iw dnsutils"
            )
        elif pm == "pacman":
            print(Fore.CYAN + "[*] Recommended system packages (Arch):")
            print(
                Fore.WHITE
                + "    sudo pacman -S python-pip iproute2 net-tools "
                + "networkmanager wireless_tools iw dnsutils"
            )

    print()
    print(Fore.MAGENTA + "============================================")
    print(Fore.MAGENTA + "       ARP-SPOOFER - Setup - LTX & Moka")
    print(Fore.MAGENTA + "============================================")
    print(Fore.WHITE + f" Platform: {platform.system()} {platform.release()}")
    print(Fore.WHITE + f" Python:   {get_python()}")
    if is_wsl():
        print(Fore.YELLOW + " Environment: WSL detected")
        print(Fore.YELLOW + " Note: WiFi scan/tools may be unavailable inside WSL.")
    print()

    print(Fore.CYAN + "[*] Checking Linux network tools...")
    tools = {
        "ip": shutil.which("ip"),
        "nmcli": shutil.which("nmcli"),
        "iw": shutil.which("iw"),
        "iwlist": shutil.which("iwlist"),
        "dhclient": shutil.which("dhclient"),
        "sudo": shutil.which("sudo"),
    }
    for name, path in tools.items():
        status = Fore.GREEN + "[OK]" if path else Fore.YELLOW + "[--]"
        print(f"{status} {name}: {path or 'not found'}")

    if not tools["ip"]:
        print(Fore.RED + "[ERROR] 'ip' command is required (iproute2 package).")
        suggest_system_packages()
        pause()
        sys.exit(1)

    if not is_wsl() and not any((tools["nmcli"], tools["iw"], tools["iwlist"])):
        print(Fore.YELLOW + "[!] WiFi scan tools not found.")
        suggest_system_packages()
    elif is_wsl():
        print(Fore.YELLOW + "[!] WSL: WiFi scan is usually not available in this environment.")
    print()

    print(Fore.CYAN + "[*] Checking packet capture support...")
    python_bin = get_python()
    if shutil.which("getcap"):
        cap_check = subprocess.run(["getcap", python_bin], capture_output=True, text=True)
        caps = cap_check.stdout or ""
        if "cap_net_raw" in caps and "cap_net_admin" in caps:
            print(Fore.GREEN + "[OK] Python has cap_net_raw and cap_net_admin.")
        else:
            print(Fore.YELLOW + "[!] Python does not have packet capture capabilities.")
            print(Fore.YELLOW + "    ARP-SPOOFER will use sudo/root (recommended).")
            print(Fore.WHITE + f"    Optional: sudo setcap cap_net_raw,cap_net_admin+eip {python_bin}")
    else:
        print(Fore.YELLOW + "[!] getcap not found. Root/sudo will be required for attacks.")
    print()

    print(Fore.GREEN + "Setup completed successfully!")
    print(Fore.CYAN + "[*] Launch the menu with:")
    print(Fore.WHITE + f"    sudo python3 {os.path.basename(START_SCRIPT)}")
    print(Fore.CYAN + "[*] Or run directly:")
    print(Fore.WHITE + f"    sudo python3 {os.path.basename(os.path.join(SCRIPT_DIR, 'arp_spoofer.py'))} -a -s")
    print()
    pause("Press Enter to start the main menu...")

    if os.geteuid() != 0:
        print(Fore.YELLOW + "[*] Elevating to root for the main menu...")
        run_as_root(START_SCRIPT)
    else:
        os.execv(python_bin, [python_bin, START_SCRIPT])


if __name__ == "__main__":
    main()
