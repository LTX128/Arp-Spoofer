# ARP-SPOOFER

**By LTX & Moka**

A network-aware ARP spoofing framework for **Windows and Linux** with automatic recovery, WiFi management, adapter selection, traffic sniffing, and long-running session stability. Built for enterprise-grade red-teaming and stability.

> **Disclaimer:** This tool is intended for **authorized security testing and educational purposes only**. Only use it on networks and systems you own or have explicit written permission to test.

---

## Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Requirements](#requirements)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [CLI Reference](#cli-reference)
- [Operation Modes](#operation-modes)
- [Network Configuration](#network-configuration)
- [ARP Attack](#arp-attack)
- [Traffic Sniffing](#traffic-sniffing)
- [Network Resilience Engine](#network-resilience-engine)
- [WiFi Management](#wifi-management)
- [Scanning](#scanning)
- [Session Logging](#session-logging)
- [Architecture](#architecture)
- [Project Files](#project-files)
- [Troubleshooting](#troubleshooting)
- [Authors](#authors)

---

## Overview

`arp_spoofer.py` is a Man-in-the-Middle (MITM) tool that performs **ARP cache poisoning** to intercept traffic between targets and the gateway on a local network. Unlike a basic ARP spoofer, this script is built to **run for extended periods**, **adapt to network changes** automatically, and **handle massive target lists without crashing**.

It is fully cross-platform, supporting both **Windows** and **Linux** (including Kali, Ubuntu, Arch, and Fedora). It includes:

- Per-adapter network detection (WiFi / Ethernet)
- Manual configuration mode
- Internet connectivity monitoring and auto-recovery
- WiFi reconnect and captive portal handling
- Live DNS, HTTP logging, and PCAP capture
- Standalone network and WiFi scanning with export
- L2 raw socket injection for zero-CPU overhead
- Unkillable wrapper and global `Ctrl+C` handling

---

## Features

| Category | Capabilities |
|----------|-------------|
| **ARP Spoofing** | Bidirectional poisoning (target ↔ gateway), multi-target support, L2Socket injection, packet caching |
| **Targeting** | Manual single target, auto-attack all devices (`-a`), direct target (`-t`), IP whitelist (`--whitelist`) |
| **Sniffing** | Live DNS/HTTP logging (`-s`), full PCAP traffic capture (`--pcap`) |
| **Attack Options** | MAC spoofing (`--spoof-mac`), 802.11 Deauthentication (`--deauth`), speed control (`--interval`) |
| **Network config** | Auto-detect, manual mode (`--manual`), adapter picker (`-i`) |
| **Scanning** | ARP device scan (`--scan`), WiFi scan (`--scan-wifi`), JSON/CSV export |
| **Recovery** | DHCP renew, IP change, MAC rotation, adapter reset, WiFi reconnect |
| **WiFi** | Profile capture, smart reconnect, captive portal auto-accept |
| **Stability** | Watchdog thread, target/MAC refresh, spoof failure recovery, unkillable wrapper |
| **Logging** | Session logs written to `logs/` directory |
| **Cross-Platform** | Windows (PowerShell, `wlanapi`) & Linux (`iproute2`, `nmcli`, `iw`) |

---

## Requirements

| Requirement | Details |
|-------------|---------|
| **OS** | Windows 10/11 or Linux (Debian/Ubuntu, Arch, Fedora, Kali) |
| **Python** | 3.x |
| **Libraries** | **Windows:** Npcap. **Linux:** libpcap (usually preinstalled) |
| **Tools (Linux)** | `iproute2`, `wireless-tools` or `iw`, `network-manager` (`nmcli`) |
| **Privileges** | Administrator (Windows) / Root (Linux) |
| **Python packages** | `scapy`, `colorama` |

---

## Installation

### 1. Clone or download the repository

```bash
git clone https://github.com/LTX128/Arp-Spoofer.git
cd Arp-Spoofer
```

### 2. Run the setup script

**Windows:**
```bash
setup.bat
```
> Do **not** run `setup.bat` as Administrator. The script will trigger UAC automatically.

**Linux:**
```bash
python3 setup.py
```
The Linux setup script will:
- Verify Python is installed
- Create a virtual environment (`venv/`)
- Install dependencies from `requirements.txt`
- Check for required network tools (`ip`, `nmcli`, etc.)

### 3. Launch the tool

**Windows:**
```bash
python auto_generate.py
```

**Linux:**
```bash
sudo python3 auto_generate.py
```

Or run the core script directly:

```bash
# Windows
python arp_spoofer.py -h

# Linux
sudo python3 arp_spoofer.py -h
```

---

## Quick Start

### Interactive menu

**Windows:**
```bash
python auto_generate.py
```

**Linux:**
```bash
sudo python3 auto_generate.py
```

| Option | Action |
|--------|--------|
| `1` | ARP attack with auto-detection |
| `2` | Scan network devices |
| `3` | Scan WiFi networks |
| `4` | Open command generator wizard |
| `5` | Select adapter (`-i`) and attack |
| `6` | Display help |

### Common commands

```bash
# Scan all devices on the current network
python arp_spoofer.py --scan

# Select WiFi or Ethernet adapter, then attack all devices with sniffing
python arp_spoofer.py -i -a -s

# Manual configuration (no auto-detect)
python arp_spoofer.py --manual -r 192.168.1.0/24 -g 192.168.1.1 -i -a

# Full auto mode with PCAP capture and 0.5s interval
python arp_spoofer.py -a -s --pcap capture.pcap --interval 0.5

# Target specific IP, spoof MAC, and deauth another IP
python arp_spoofer.py -t 192.168.1.50 --spoof-mac --deauth 192.168.1.25
```
*(Note: Use `sudo` on Linux)*

---

## CLI Reference

| Argument | Description |
|----------|-------------|
| `--scan` | Scan devices on the network and exit |
| `--scan-wifi` | Scan nearby WiFi networks and exit |
| `-o`, `--output` | Export scan results to `.json` or `.csv` |
| `--log` | Write session events to a custom log file |
| `-r`, `--range` | Network range (e.g. `192.168.1.0/24`) |
| `-g`, `--gateway` | Gateway IP address |
| `-a`, `--all` | Auto-target all devices on the network |
| `-t`, `--target` | Target a specific IP directly (bypasses interactive menu) |
| `-s`, `--sniff` | Enable live DNS/HTTP traffic sniffing |
| `--pcap` | Save all sniffed traffic to a PCAP file |
| `--whitelist` | Comma-separated IPs to exclude from auto-attack (`-a`) |
| `--spoof-mac` | Randomize MAC address before starting |
| `--deauth <IP>` | Continuously send 802.11 deauth frames to a target IP (use `all` for broadcast) |
| `--interval` | Spoofing interval in seconds (default: `2.0`) |
| `-i`, `--interface [N]` | List adapters and select one. Use `-i` for interactive, `-i 2` for direct selection |
| `--manual` | Manual mode: disables auto-detect, requires `-r` and `-g` |
| `--no-recovery` | Disable automatic internet/WiFi recovery |
| `--no-elevate` | Skip automatic elevation (UAC on Windows, `sudo` on Linux) |

---

## Operation Modes

### 1. ARP Attack Mode (default)

The main mode. Poisons ARP tables to position your machine between targets and the gateway.

```bash
python arp_spoofer.py -a -s
```

### 2. Device Scan Mode (`--scan`)

Performs an ARP scan, displays a table of IP / MAC / hostname, then exits.

```bash
python arp_spoofer.py --scan
python arp_spoofer.py --scan -o devices.json
```

### 3. WiFi Scan Mode (`--scan-wifi`)

Scans nearby WiFi networks.
- **Windows:** Uses native `wlanapi.dll` API.
- **Linux:** Uses `nmcli`, falls back to `iw` and `iwlist`.

```bash
python arp_spoofer.py --scan-wifi
python arp_spoofer.py --scan-wifi -o wifi.json
```

---

## Network Configuration

The script supports three ways to configure the network:

### Auto-detect (default)

When `-r` and `-g` are not provided and `--manual` is not set:

1. Lists all active network adapters:
   - **Windows:** PowerShell (`Get-NetAdapter`, `Get-NetIPAddress`, `Get-NetRoute`)
   - **Linux:** `ip -j link show` and `ip -j -4 addr show`
2. Filters out virtual adapters (VirtualBox, VMware, Hyper-V, VPN, Docker, etc.)
3. Selects the **best adapter** (prioritizes adapters with a valid IP + gateway)
4. Derives the subnet (actual prefix or `/24`) and gateway from that adapter
5. Configures Scapy to use the matching capture interface

### Manual mode (`--manual`)

Disables all auto-detection. You must provide the network range and gateway yourself.

```bash
python arp_spoofer.py --manual -r 192.168.1.0/24 -g 192.168.1.1 -a -s
```

If `-r` or `-g` are missing, the script prompts you interactively.

> **Tip:** Combine with `-i` to also select which adapter Scapy uses for packet capture.

### Adapter selection (`-i`)

Lists all available adapters in a table:

```
+----+----------------------+--------------+----------------+----------------+--------------+
| #  | Name                 | Type         | IP             | Gateway        | Status       |
+----+----------------------+--------------+----------------+----------------+--------------+
| 1  | Wi-Fi                | WiFi         | 192.168.1.42   | 192.168.1.1    | Up           |
| 2  | Ethernet             | Ethernet     | 10.0.0.5       | 10.0.0.1       | Up           |
+----+----------------------+--------------+----------------+----------------+--------------+
```

```bash
# Interactive selection
python arp_spoofer.py -i -a -s

# Direct selection (adapter #2)
python arp_spoofer.py -i 2 -a -s
```

The selected adapter determines:
- Scapy capture interface
- IP address and gateway used for auto-detect
- WiFi profile context for recovery

---

## ARP Attack

### How it works

For each target, the script sends spoofed ARP replies:

1. **To the target:** "The gateway IP is at **my MAC address**"
2. **To the gateway:** "The target IP is at **my MAC address**"

Traffic flows through your machine, enabling interception and sniffing.

### Performance Engine

- **L2Socket Injection:** Instead of opening and closing a raw socket for every packet (`scapy.sendp`), the script opens a persistent `scapy.L2socket`. Packets are injected directly to the network card, reducing CPU usage to near zero.
- **Packet Caching:** ARP packets are built once and stored in an internal cache. The spoofing loop merely iterates over pre-built bytes, only rebuilding the cache if a target MAC changes.

### Target selection

| Mode | Behavior |
|------|----------|
| **Default** | ARP scan → display device table → you pick one IP |
| **`-a` (auto)** | Silently scans and attacks all devices except the gateway and whitelist |
| **`-t` (direct)** | Bypasses scanning, directly attacks the specified IP |

### Live status bar

During the attack, a real-time status line is displayed. ANSI line-clearing ensures DNS/WEB logs don't fragment the status bar:

```
Packets: 126 | Targets: 21 | Internet: ONLINE | Uptime: 00:15:33 | Ctrl+C to stop
```

### Clean exit & Unkillable Wrapper

Press `Ctrl+C` to stop. A global `sys.excepthook` intercepts the interrupt, stops all background threads instantly using `Event.wait()`, and sends restoration ARP packets to restore normal network operation.

If a fatal error occurs, the script catches it, logs the traceback, and prompts: `Do you want to restart the script? (y/N)`.

### Background maintenance

| Task | Interval | Description |
|------|----------|-------------|
| Watchdog | 30s | Checks gateway, internet, triggers recovery |
| Target refresh | 1 min | Detects new devices (auto-attack mode) |
| MAC refresh | 1.15 min | Re-resolves ARP for all targets |
| Spoof failure recovery | Per cycle | Re-fetches MAC after 5 consecutive failures |

---

## Traffic Sniffing

Enable with `-s` or `--pcap`. The sniffer runs in a non-blocking background thread (1-second burst sniffing) and logs:

### DNS Log

Captures **DNS queries only** (not responses). Filters out empty or invalid names.

```
[DNS LOG] www.google.com
[DNS LOG] _bose-passport._tcp.local
```

Filtering rules:
- Only DNS requests (`qr == 0`)
- Skips empty, root, or invalid domain names
- Strips trailing dots and non-printable characters

### WEB Log

Captures HTTP requests (unencrypted):

```
[WEB LOG] example.com/path/to/page
```

### PCAP Capture (`--pcap`)

Save all raw traffic to a file for offline analysis (e.g., Wireshark). Uses `scapy.PcapWriter` in synchronous mode to write to disk without consuming RAM.

```bash
python arp_spoofer.py -a -s --pcap capture.pcap
```

---

## Network Resilience Engine

The `NetworkResilience` class monitors connectivity and recovers automatically when the network drops or your IP gets blacklisted.

### Internet detection

Checks connectivity using:
- TCP probes to public DNS servers (`8.8.8.8`, `1.1.1.1`, `208.67.222.222`)
- HTTP probes to standard connectivity check URLs (Google, Microsoft, Apple)

Results are cached for **15 seconds** to reduce overhead.

### Recovery pipeline

When internet or gateway is lost, the following methods are tried in order:

| Step | Method | Description |
|------|--------|-------------|
| 1 | **DHCP Renew** | Reset to DHCP, release/renew IP, flush DNS |
| 2 | **Local IP Change** | Assign a random static IP in the current subnet |
| 3 | **MAC Rotation** | Randomize adapter MAC |
| 4 | **Adapter Reset** | Disable and re-enable the network interface |
| 5 | **WiFi Reconnect** | Reconnect to the original WiFi using saved credentials |
| 6 | **WiFi Scan & Connect** | Scan nearby networks and connect to the best match |

A **120-second cooldown** prevents aggressive recovery loops.

### Captive portal handling

For public WiFi networks, the script attempts to auto-accept terms through:
1. HTML form submission (accept/agree/connect buttons)
2. Link clicking on portal pages
3. Fallback POST requests to common portal paths

### Recovery flow

```
Internet / Gateway lost
        |
        v
[Cooldown check - 120s minimum]
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
Resume spoofing
```

Disable recovery with `--no-recovery`.

---

## WiFi Management

### Profile capture at startup

When connected via WiFi, the script saves:
- SSID, interface name, authentication type
- Password (from Windows `netsh` or Linux `nmcli`)

### Smart WiFi reconnect

When scanning for alternative networks, candidates are ranked by:

1. Exact SSID match with the original network
2. Similar SSID (partial name match)
3. Same BSSID OUI (same router/AP vendor prefix)
4. Open networks
5. Signal strength

For secured networks, the saved WiFi password is reused. For open networks, a profile is created automatically.

Supported authentication: **Open**, **WPA/WPA2-PSK**, **WPA3-SAE**.

---

## Scanning

### Device scan (`--scan`)

Sends ARP requests across the subnet and resolves hostnames.

```bash
python arp_spoofer.py --scan -o devices.json   # JSON export
python arp_spoofer.py --scan -o devices.csv    # CSV export
```

### WiFi scan (`--scan-wifi`)

```bash
python arp_spoofer.py --scan-wifi -o wifi.json
```

---

## Session Logging

All events are logged automatically to:

```
logs/session_YYYYMMDD_HHMMSS.log
```

Custom path with `--log`:

```bash
python arp_spoofer.py -a -s --log my_session.log
```

**Log format:**

```
[2026-07-11 14:30:01] [INFO] Session started
[2026-07-11 14:30:02] [INFO] Auto-selected adapter: wlan0 (WiFi)
[2026-07-11 14:30:03] [INFO] Network: 192.168.1.0/24 | Gateway: 192.168.1.1
[2026-07-11 14:45:12] [WARN] No internet access detected.
[2026-07-11 14:45:20] [OK] Connectivity restored via _method_dhcp_renew.
```

---

## Architecture

```
arp_spoofer.py
|
|-- Network Configuration
|   |-- get_network_adapters()       Cross-platform adapter enumeration (PowerShell / iproute2)
|   |-- get_best_adapter()           Auto-select best adapter
|   |-- pick_network_adapter()       Interactive adapter selection (-i)
|   |-- configure_network()          Resolves auto / manual / -i modes
|   |-- setup_scapy_iface()          Binds Scapy to the correct interface
|
|-- NativeWifiScanner / Linux Scanner
|   |-- scan()                       Live WiFi scan (wlanapi.dll / nmcli / iw)
|   |-- _parse_bss_list()            Parse BSS entries
|   |-- _read_available_networks()   Read auth types per SSID
|
|-- NetworkResilience
|   |-- has_internet()               TCP + HTTP connectivity probes
|   |-- recover_connectivity()       Multi-step recovery pipeline
|   |-- handle_captive_portal()      Auto-accept public WiFi portals
|   |-- capture_initial_wifi()       Save WiFi profile at startup
|   |-- scan_wifi_networks()         WiFi scan (native + fallbacks)
|   |-- _method_dhcp_renew()         DHCP release/renew
|   |-- _method_change_local_ip()    Random static IP assignment
|   |-- _method_randomize_mac()      MAC address rotation
|   |-- _method_adapter_reset()      Disable/enable adapter
|   |-- _method_wifi_reconnect()     Reconnect to saved WiFi
|   |-- _method_wifi_scan_and_connect()  Scan and connect to best network
|
|-- SpoofSession
|   |-- setup_targets()              Manual, auto, or direct (-t) target selection
|   |-- spoof_cycle()                Send ARP poison packets via L2Socket
|   |-- _build_packet_cache()        Pre-build ARP frames for zero-CPU injection
|   |-- deauth_thread()              802.11 deauthentication spawner
|   |-- watchdog_loop()              Background monitoring thread
|   |-- refresh_targets_if_needed()  Detect new devices every 1 min
|   |-- refresh_target_macs()        Re-resolve MACs every 1.15 min
|   |-- verify_gateway()             Gateway ARP reachability check
|   |-- _restore()                   Clean ARP restoration on exit
|
|-- Traffic Sniffing
|   |-- process_packet()             DNS + HTTP packet handler
|   |-- _extract_dns_queries()       Filter valid DNS query names
|   |-- _decode_http_field()         Decode HTTP Host/Path fields
|
|-- SessionLogger
|   |-- write()                      Timestamped event logging
|
|-- Utilities
    |-- request_admin_elevation()    UAC auto-elevation / sudo relaunch
    |-- _excepthook()                Global Ctrl+C intercept and clean exit
    |-- get_mac()                    ARP resolution with retries
    |-- silent_scan() / visual_scan()  Network device discovery
    |-- export_scan_results()        JSON/CSV device export
    |-- export_wifi_results()        JSON/CSV WiFi export
    |-- safe_print()                 Console-safe output
```

---

## Authors

**LTX & Moka**
