@echo off
title ARP-SPOOFER - LTX
color 5
cls

echo.
echo  ============================================
echo       ARP-SPOOFER - LTX74 - Main Menu
echo  ============================================
echo.
echo   [1] Launch ARP Attack (auto-detect)
echo   [2] Scan network devices
echo   [3] Scan WiFi networks
echo   [4] Auto command generator
echo   [5] Help
echo   [0] Exit
echo.

set /p choice="Select option: "

if "%choice%"=="1" goto attack
if "%choice%"=="2" goto scan
if "%choice%"=="3" goto wifi
if "%choice%"=="4" goto generator
if "%choice%"=="5" goto help
if "%choice%"=="0" exit /b 0
goto invalid

:attack
echo.
echo Starting ARP attack with auto-detection and recovery...
python arp_spoofer.py -a
pause
exit /b 0

:scan
echo.
echo Scanning network devices...
python arp_spoofer.py --scan
pause
exit /b 0

:wifi
echo.
echo Scanning WiFi networks...
python arp_spoofer.py --scan-wifi
pause
exit /b 0

:generator
python auto_generate.py
pause
exit /b 0

:help
echo.
python arp_spoofer.py -h
pause
exit /b 0

:invalid
echo Invalid choice.
pause
exit /b 1
