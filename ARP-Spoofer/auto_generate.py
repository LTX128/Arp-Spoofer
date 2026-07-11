import socket
import os
import subprocess
import platform
import re
from colorama import Fore, Style, init
import time
import sys

init(autoreset=True)

title = "ARP-SPOOFER - LTX & Moka"
if os.name == 'nt':
    os.system(f'title {title}')
else:
    sys.stdout.write(f"\x1b]2;{title}\x07")

os.system('cls' if os.name == 'nt' else 'clear')

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

def main():
    banner()

    print(Fore.CYAN + "\n[MODE] Select operation:")
    print(Fore.WHITE + "  1. ARP Attack (spoof)")
    print(Fore.WHITE + "  2. Scan devices (--scan)")
    print(Fore.WHITE + "  3. Scan WiFi (--scan-wifi)")
    mode = input(Fore.GREEN + "Choice (1/2/3) [1]: ").strip() or "1"

    if mode == "2":
        export = input(Fore.GREEN + "Export to file? (.json/.csv, leave empty to skip): ").strip()
        base_cmd = "python arp_spoofer.py --scan"
        if export:
            base_cmd += f" -o {export}"
        iface = input(Fore.GREEN + "Select adapter with -i? (y/n): ").lower() == 'y'
        if iface:
            base_cmd += " -i"
    elif mode == "3":
        base_cmd = "python arp_spoofer.py --scan-wifi"
    else:
        print(Fore.CYAN + "\n[NETWORK] Configuration mode:")
        print(Fore.WHITE + "  1. Auto-detect (recommended)")
        print(Fore.WHITE + "  2. Select adapter (-i)")
        print(Fore.WHITE + "  3. Manual (-r / -g)")
        net_mode = input(Fore.GREEN + "Choice (1/2/3) [1]: ").strip() or "1"

        if net_mode == "2":
            base_cmd = "python arp_spoofer.py -i"
        elif net_mode == "3":
            net_range = input(Fore.WHITE + "[?] Network range (e.g. 192.168.1.0/24): ").strip()
            gateway = input(Fore.WHITE + "[?] Gateway IP (e.g. 192.168.1.1): ").strip()
            base_cmd = f"python arp_spoofer.py --manual -r {net_range} -g {gateway}"
            if input(Fore.GREEN + "Select adapter with -i? (y/n): ").lower() == 'y':
                base_cmd += " -i"
        else:
            base_cmd = "python arp_spoofer.py"

        print(Fore.CYAN + "\n[OPTION] -a  (Auto Attack)")
        use_a = input(Fore.GREEN + "Enable -a ? (y/n): ").lower() == 'y'

        print(Fore.CYAN + "\n[OPTION] -s  (Sniffer)")
        use_s = input(Fore.GREEN + "Enable -s ? (y/n): ").lower() == 'y'

        print(Fore.CYAN + "\n[OPTION] --no-recovery")
        no_recovery = input(Fore.GREEN + "Disable recovery? (y/n): ").lower() == 'y'

        if use_a:
            base_cmd += " -a"
        if use_s:
            base_cmd += " -s"
        if no_recovery:
            base_cmd += " --no-recovery"

    print("\n" + Fore.GREEN + "[+] Final command generated:")
    print(Fore.MAGENTA + base_cmd)
    separator()

    choice = input(Fore.WHITE + f"\nStart ARP-SPOOFER with {Fore.GREEN}{base_cmd}{Fore.WHITE}? (y/n): ")

    if choice.lower() == 'y':
        print(Fore.YELLOW + "\n[*] Launching ARP-SPOOFER..." + Style.RESET_ALL)
        time.sleep(1)
        try:
            subprocess.run(base_cmd, shell=True)
        except Exception as e:
            print(Fore.RED + f"[!] Execution error: {e}")

if __name__ == "__main__":
    main()
