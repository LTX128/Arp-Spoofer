@echo off
title ARP-SPOOFER - Network Scan - LTX
color 3
cls
echo.
echo Scanning devices on the current network...
echo.
python arp_spoofer.py --scan
echo.
pause
