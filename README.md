# ARP-SPOOFER - LTX74
## Professional ARP Spoofing / MITM Framework

Author      : LTX74
Language    : Python 3
Platforms   : Windows / Linux
Category    : Network Security / MITM
Usage       : Educational & Authorized Testing Only

----------------------------------------------------
DISCLAIMER
----------------------------------------------------

⚠️  EDUCATIONAL USE ONLY ⚠️

This tool is designed for:
- Personal labs
- Authorized pentesting
- Network security learning

Any use on networks you do NOT own or do NOT have
explicit permission to test is illegal.

The author (LTX74) assumes NO responsibility for misuse.

----------------------------------------------------
PROJECT OVERVIEW
----------------------------------------------------

ARP-SPOOFER - LTX74 is a professional ARP spoofing
and Man-In-The-Middle framework written in Python.

The tool allows:
- Full LAN discovery
- ARP poisoning between targets and gateway
- Optional DNS & HTTP traffic sniffing
- Automatic or manual target selection
- Clean restoration of the network on exit

An additional helper script is included to
automatically generate the correct attack commands
based on your current network configuration.

----------------------------------------------------
FEATURES
----------------------------------------------------

[+] Automatic network scanning (IP / MAC / Hostname)
[+] Manual or auto attack mode
[+] Multi-target support
[+] DNS query logging
[+] HTTP request logging
[+] Auto gateway detection
[+] Safe ARP table restoration
[+] Clean CLI with colors & banner
[+] Auto command generator script

----------------------------------------------------
FILES
----------------------------------------------------

arp_spoofer.py
---------------
Main ARP spoofing & MITM tool.

auto_generate.py
----------------
Automatically detects:
- Your IP address
- Default gateway
- Network range

Then generates ready-to-use commands
and can directly launch ARP-SPOOFER.

----------------------------------------------------
REQUIREMENTS
----------------------------------------------------

Python 3.8+

Python modules:
- scapy
- colorama

----------------------------------------------------
PLATFORM NOTES
----------------------------------------------------

Windows:
- Install Npcap
- Enable "WinPcap compatible mode"
- Run terminal as Administrator

Linux:
- Run as root
- IP forwarding is enabled automatically

----------------------------------------------------
INSTALLATION
----------------------------------------------------

1) Clone repository
-------------------
git clone https://github.com/LTX128/Arp-Spoofer.git
cd ARP-SPOOFER-LTX74

2) Install dependencies
-----------------------
pip install scapy colorama

3) (Windows only) Install Npcap
-------------------------------
https://npcap.com/download/

----------------------------------------------------
USAGE - ARP SPOOFER
----------------------------------------------------

Basic syntax:
-------------
python arp_spoofer.py -r <NETWORK_RANGE> -g <GATEWAY>

Examples:
---------

Manual target selection:
python arp_spoofer.py -r 192.168.1.0/24 -g 192.168.1.1

Auto attack all devices:
python arp_spoofer.py -r 192.168.1.0/24 -g 192.168.1.1 -a

Auto attack + sniff traffic:
python arp_spoofer.py -r 192.168.1.0/24 -g 192.168.1.1 -a -s

----------------------------------------------------
ARGUMENTS
----------------------------------------------------

-r, --range     Network range (CIDR)
-g, --gateway   Gateway IP address
-a, --all       Attack all devices automatically
-s, --sniff     Enable DNS & HTTP sniffing

----------------------------------------------------
USAGE - AUTO GENERATOR
----------------------------------------------------

Run:
----
python auto_generate.py

The script will:
- Detect your IP
- Detect your gateway
- Detect network range
- Generate correct ARP-SPOOFER commands
- Optionally launch the attack automatically

Recommended for beginners or quick setup.

----------------------------------------------------
STOPPING THE ATTACK
----------------------------------------------------

Press CTRL + C

ARP-SPOOFER will:
- Stop poisoning
- Restore ARP tables
- Exit safely

----------------------------------------------------
LIMITATIONS
----------------------------------------------------

- HTTPS content cannot be decrypted
- Some routers detect ARP spoofing

----------------------------------------------------
ROADMAP / IDEAS
----------------------------------------------------

- HTTPS SNI logging
- Device vendor detection
- Defensive detection mode
- Plugin system
- GUI interface

----------------------------------------------------
LICENSE
----------------------------------------------------

Educational license.
Code can be studied and modified.
Malicious or illegal usage is forbidden.

----------------------------------------------------
AUTHOR
----------------------------------------------------

Made by LTX74
ARP-SPOOFER Project

Learn • Test • Secure
====================================================
