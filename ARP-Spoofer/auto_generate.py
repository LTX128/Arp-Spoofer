import socket
import os
import subprocess
import platform
import re
from colorama import Fore, Style, init
import time
import sys

init(autoreset=True)

title = "ARP-SPOOFER - LTX74"
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
                    Auto Command Generator - LTX74
    """ + Style.RESET_ALL)

def separator():
    print(Fore.CYAN + "────────────────────────────────────────────────────────────" + Style.RESET_ALL)

def get_network_info():
    ip_address = ""
    gateway = ""
    
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        ip_address = s.getsockname()[0]
    except Exception:
        ip_address = "127.0.0.1"
    finally:
        s.close()

    try:
        if platform.system() != "Windows":
            cmd = "ip route | grep default"
            output = subprocess.check_output(cmd, shell=True).decode().strip()
            match = re.search(r'via\s+(\d+\.\d+\.\d+\.\d+)', output)
            if match:
                gateway = match.group(1)
        else:
            cmd = "route print 0.0.0.0"
            output = subprocess.check_output(cmd, shell=True).decode('cp850')
            lines = output.split('\n')
            for line in lines:
                if "0.0.0.0" in line and "Active Routes" not in line:
                    parts = line.split()
                    if len(parts) >= 3:
                        gateway = parts[2]
                        break
    except:
        gateway = "NOT_FOUND"

    if ip_address and ip_address != "127.0.0.1":
        network_range = ".".join(ip_address.split('.')[:-1]) + ".0/24"
    else:
        network_range = "UNKNOWN"

    return ip_address, gateway, network_range

def main():
    banner()
    
    print(Fore.YELLOW + "[*] Detecting network configuration..." + Style.RESET_ALL)
    time.sleep(1)

    my_ip, gateway, net_range = get_network_info()

    separator()
    print(Fore.WHITE + "Detected Configuration:")
    print(f" - Your IP:       {Fore.YELLOW}{my_ip}")
    print(f" - Gateway:       {Fore.YELLOW}{gateway}")
    print(f" - Network Range: {Fore.YELLOW}{net_range}")
    separator()

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
    elif mode == "3":
        base_cmd = "python arp_spoofer.py --scan-wifi"
    else:
        if gateway == "NOT_FOUND" or not re.match(r'\d+\.\d+\.\d+\.\d+', gateway):
            print(Fore.RED + "[!] Error: Could not automatically detect the Gateway IP.")
            gateway = input(Fore.WHITE + "[?] Enter Gateway manually (e.g. 192.168.1.1): ")

        auto_detect = input(Fore.GREEN + "Auto-detect network (-r/-g optional)? (y/n) [y]: ").lower()
        use_auto = auto_detect != 'n'

        print(Fore.CYAN + "\n[OPTION] -a  (Auto Attack)")
        print(Fore.WHITE + "Description: Spoof ALL devices on the network")
        use_a = input(Fore.GREEN + "Enable -a ? (y/n): ").lower() == 'y'

        print(Fore.CYAN + "\n[OPTION] -s  (Sniffer)")
        print(Fore.WHITE + "Description: DNS/HTTP traffic sniffing")
        use_s = input(Fore.GREEN + "Enable -s ? (y/n): ").lower() == 'y'

        print(Fore.CYAN + "\n[OPTION] --no-recovery")
        print(Fore.WHITE + "Description: Disable auto internet/WiFi recovery")
        no_recovery = input(Fore.GREEN + "Disable recovery? (y/n): ").lower() == 'y'

        if use_auto:
            base_cmd = "python arp_spoofer.py"
        else:
            base_cmd = f"python arp_spoofer.py -r {net_range} -g {gateway}"

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
