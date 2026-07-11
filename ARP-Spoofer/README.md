# ARP-SPOOFER

**By LTX74** - A network-aware ARP spoofing framework with automatic recovery, WiFi management, and long-running session stability. Designed primarily for **Windows**.

---

## Features

### Core ARP Spoofing
- Man-in-the-middle attack via ARP cache poisoning
- Bidirectional spoofing (target <-> gateway)
- Optional live DNS and HTTP traffic sniffing (`-s`)
- Manual or automatic target selection (`-a`)
- Clean network restoration on exit (Ctrl+C)

### Network Resilience Engine
The script monitors connectivity in real time and recovers automatically when the network drops or the host gets blacklisted.

| Recovery Step | Method | Purpose |
|---------------|--------|---------|
| 1 | DHCP Renew | Release and renew the IP lease, flush DNS |
| 2 | Local IP Change | Assign a random static IP within the current subnet |
| 3 | MAC Rotation | Randomize the adapter MAC address via the Windows registry |
| 4 | Adapter Reset | Disable and re-enable the network interface |
| 5 | WiFi Reconnect | Reconnect to the original WiFi using saved credentials |
| 6 | WiFi Scan & Connect | Scan nearby networks and connect automatically |

Additional safeguards:
- **120-second cooldown** between full recovery attempts
- **15-second cache** on internet checks to reduce overhead
- **Captive portal handling** for public WiFi (form submit, link click, fallback POST)

### WiFi Management (Windows)
At startup, the script saves the current WiFi profile:
- SSID, interface name, authentication type
- Password (from the Windows stored profile)

When scanning for alternative networks, candidates are ranked by:
1. Exact SSID match
2. Similar SSID (partial name match)
3. Same BSSID OUI (same router/AP vendor)
4. Open networks
5. Signal strength

Supported auth types: **Open**, **WPA/WPA2-PSK**, **WPA3-SAE**.

### Long-Running Stability
- **Watchdog thread** (every 30s): gateway check, internet check, recovery trigger
- **Target refresh** (every 5 min): detect new devices in auto-attack mode
- **MAC refresh** (every 3 min): re-resolve ARP for all targets
- **Spoof failure recovery**: re-fetch target MAC after 5 consecutive failures
- **Live status bar**: packets, targets, internet status, uptime
- **Session logging** to `logs/session_YYYYMMDD_HHMMSS.log`

### Standalone Scanning
- `--scan` - ARP scan of devices on the current network
- `--scan-wifi` - Scan nearby WiFi networks (Windows)
- `-o` - Export scan results to `.json` or `.csv`

---

## Requirements

- **Windows 10/11** (primary target)
- **Python 3.x**
- **Npcap** (packet capture driver)
- **Administrator privileges** (ARP spoofing, IP/MAC changes, WiFi management)
- **Auto-elevation**: the script automatically triggers a UAC prompt on Windows if not already running as admin

### Python Dependencies

```
scapy
colorama
```

Install everything via:

```bash
setup.bat
```

Or manually:

```bash
pip install -r requirements.txt
```

---

## Installation

1. Clone or download this repository.
2. Run `setup.bat` (do **not** run it as Administrator).
3. Complete the Npcap installer if prompted.
4. Launch the tool via `start.bat` or the command line.

---

## Usage

### Quick Start (Menu)

```bash
start.bat
```

Menu options:
1. Launch ARP attack (auto-detect)
2. Scan network devices
3. Scan WiFi networks
4. Auto command generator
5. Help

### Command Line Examples

```bash
# Standalone device scan
python arp_spoofer.py --scan

# Scan and export to JSON
python arp_spoofer.py --scan -o devices.json

# Scan and export to CSV
python arp_spoofer.py --scan -o devices.csv

# Scan nearby WiFi networks
python arp_spoofer.py --scan-wifi

# Scan WiFi and export
python arp_spoofer.py --scan-wifi -o wifi.json

# Full auto-attack with sniffing (auto-detect network)
python arp_spoofer.py -a -s

# Manual network configuration
python arp_spoofer.py -r 192.168.1.0/24 -g 192.168.1.1 -a -s

# Custom session log
python arp_spoofer.py -a -s --log my_session.log

# Disable automatic recovery
python arp_spoofer.py -a --no-recovery
```

### CLI Arguments

| Argument | Description |
|----------|-------------|
| `--scan` | Scan devices on the network and exit |
| `--scan-wifi` | Scan available WiFi networks and exit (Windows) |
| `-o`, `--output` | Export scan results to `.json` or `.csv` |
| `--log` | Write session events to a custom log file |
| `-r`, `--range` | Network range (e.g. `192.168.1.0/24`) - auto-detected if omitted |
| `-g`, `--gateway` | Gateway IP address - auto-detected if omitted |
| `-a`, `--all` | Auto-target all devices on the network |
| `-s`, `--sniff` | Enable live DNS/HTTP traffic sniffing |
| `--no-recovery` | Disable automatic internet and WiFi recovery |
| `--no-elevate` | Skip automatic UAC administrator elevation (Windows) |

---

## Administrator Elevation (Windows)

When launched without admin rights, the script automatically displays a **UAC prompt** and relaunches itself with elevated privileges. No manual "Run as administrator" step is required.

```bash
# Normal launch - UAC prompt appears automatically
python arp_spoofer.py -a -s

# Skip auto-elevation (limited functionality)
python arp_spoofer.py -a --no-elevate
```

If the UAC prompt is denied, the script exits with an error message.

---

## Architecture

```
arp_spoofer.py
|
|-- NetworkResilience
|   |-- Internet connectivity probes (TCP + HTTP)
|   |-- Multi-step recovery pipeline
|   |-- WiFi profile capture and smart reconnect
|   |-- Captive portal auto-acceptance
|   |-- MAC rotation and IP change (anti-blacklist)
|
|-- SpoofSession
|   |-- ARP spoofing loop
|   |-- Background watchdog thread
|   |-- Target and MAC refresh management
|   |-- Graceful restoration on exit
|
|-- SessionLogger
|   |-- Persistent event logging to logs/
|
|-- Scan modules
|   |-- visual_scan()   - formatted ARP table with hostnames
|   |-- silent_scan()   - background scan for auto-attack mode
|
|-- CLI
    |-- --scan, --scan-wifi, -a, -s, --no-recovery, -o, --log
```

---

## Recovery Flow

```
Internet check fails
        |
        v
[Cooldown check - 120s minimum between attempts]
        |
        v
1. DHCP release / renew
        |-- fail
        v
2. Change local IP (random host in subnet)
        |-- fail
        v
3. Rotate MAC address
        |-- fail
        v
4. Reset network adapter
        |-- fail
        v
5. Reconnect to original WiFi
        |-- fail
        v
6. Scan WiFi and connect to best candidate
        |
        v
[Captive portal check and auto-accept]
        |
        v
Internet restored -> resume spoofing
```

---

## Session Logs

Logs are written automatically to:

```
logs/session_YYYYMMDD_HHMMSS.log
```

Each entry includes a timestamp, severity level, and message:

```
[2026-07-11 14:30:01] [INFO] Session started
[2026-07-11 14:30:02] [INFO] Network: 192.168.1.0/24 | Gateway: 192.168.1.1
[2026-07-11 14:30:03] [INFO] WiFi profile saved: MyNetwork
[2026-07-11 14:45:12] [WARN] No internet access detected.
[2026-07-11 14:45:12] [WARN] Internet lost - starting recovery sequence...
[2026-07-11 14:45:20] [OK] Connectivity restored via _method_dhcp_renew.
```

---

## Files

| File | Description |
|------|-------------|
| `arp_spoofer.py` | Main script |
| `auto_generate.py` | Interactive command builder |
| `start.bat` | Main menu launcher |
| `scan.bat` | Quick network scan launcher |
| `setup.bat` | Dependency and Npcap installer |
| `requirements.txt` | Python package list |
| `logs/` | Session log directory (created at runtime) |

---

## Important Notes

- **Administrator privileges** are required. The script requests them automatically via UAC on startup.
- Use `--no-elevate` only if you intentionally want to run without admin rights.
- **Npcap** must be installed with "WinPcap API-compatible Mode" enabled.
- **WiFi scan** on Windows may require Location Services to be enabled:
  `Settings > Privacy > Location > Let desktop apps access your location`
- Use `--no-recovery` if you want pure ARP spoofing without network adaptation.
- The tool restores ARP tables on exit (Ctrl+C) to avoid leaving the network in a broken state.

---

## Legal Disclaimer

This tool is intended for **authorized security testing and educational purposes only**. Only use it on networks and systems you own or have explicit written permission to test. Unauthorized use may violate local laws.

---

## Author

**LTX74**
