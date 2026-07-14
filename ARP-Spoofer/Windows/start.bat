@echo off
cd /d "%~dp0"

net session >nul 2>&1
if errorlevel 1 (
    powershell -NoProfile -ExecutionPolicy Bypass -Command "Start-Process -FilePath '%~f0' -Verb RunAs -WorkingDirectory '%~dp0'"
    exit /b 0
)

setlocal EnableExtensions
title "ARP-SPOOFER - LTX & Moka"
color 5

:menu
cls
color 5
echo.
echo  ============================================
echo       ARP-SPOOFER - LTX ^& Moka - Main Menu
echo  ============================================
echo.
echo   [1] Launch ARP Attack (auto-detect)
echo   [2] Scan network devices
echo   [3] Scan WiFi networks
echo   [4] Auto command generator
echo   [5] Select adapter (-i) and attack
echo   [6] Manual mode attack (--manual)
echo   [7] Help
echo   [0] Exit
echo.

set "choice="
set /p choice="Select option: "

if "%choice%"=="1" goto attack
if "%choice%"=="2" goto scan
if "%choice%"=="3" goto wifi
if "%choice%"=="4" goto generator
if "%choice%"=="5" goto iface
if "%choice%"=="6" goto manual
if "%choice%"=="7" goto help
if "%choice%"=="0" goto exit_script
goto invalid

:attack
set "WIN_TITLE=Launch ARP Attack"
start "%WIN_TITLE%" cmd /k "cd /d "%~dp0" & set ARP_SPOOFER_WINDOW_TITLE=%WIN_TITLE% & title %WIN_TITLE% & call python "%~dp0arp_spoofer.py" --no-elevate -a & echo. & pause"
goto menu

:scan
set "WIN_TITLE=Scan network devices"
start "%WIN_TITLE%" cmd /k "cd /d "%~dp0" & set ARP_SPOOFER_WINDOW_TITLE=%WIN_TITLE% & title %WIN_TITLE% & call python "%~dp0arp_spoofer.py" --no-elevate --scan & echo. & pause"
goto menu

:wifi
set "WIN_TITLE=Scan WiFi networks"
start "%WIN_TITLE%" cmd /k "cd /d "%~dp0" & set ARP_SPOOFER_WINDOW_TITLE=%WIN_TITLE% & title %WIN_TITLE% & call python "%~dp0arp_spoofer.py" --no-elevate --scan-wifi & echo. & pause"
goto menu

:generator
set "WIN_TITLE=Auto command generator"
start "%WIN_TITLE%" cmd /k "cd /d "%~dp0" & set ARP_SPOOFER_WINDOW_TITLE=%WIN_TITLE% & title %WIN_TITLE% & call python "%~dp0auto_generate.py" --no-elevate & echo. & pause"
goto menu

:iface
set "WIN_TITLE=Select adapter (-i) and attack"
start "%WIN_TITLE%" cmd /k "cd /d "%~dp0" & set ARP_SPOOFER_WINDOW_TITLE=%WIN_TITLE% & title %WIN_TITLE% & call python "%~dp0arp_spoofer.py" --no-elevate -i -a & echo. & pause"
goto menu

:manual
echo.
set "NET_RANGE="
set "GATEWAY="
set /p NET_RANGE="Network range (e.g. 192.168.1.0/24): "
set /p GATEWAY="Gateway IP (e.g. 192.168.1.1): "
set "WIN_TITLE=Manual mode attack (--manual)"
start "%WIN_TITLE%" cmd /k "cd /d "%~dp0" & set ARP_SPOOFER_WINDOW_TITLE=%WIN_TITLE% & title %WIN_TITLE% & call python "%~dp0arp_spoofer.py" --no-elevate --manual -r "%NET_RANGE%" -g "%GATEWAY%" -i -a & echo. & pause"
goto menu

:help
set "WIN_TITLE=Help"
start "%WIN_TITLE%" cmd /k "cd /d "%~dp0" & set ARP_SPOOFER_WINDOW_TITLE=%WIN_TITLE% & title %WIN_TITLE% & call python "%~dp0arp_spoofer.py" -h --no-elevate & echo. & pause"
goto menu

:invalid
echo.
echo Invalid choice.
timeout /t 2 >nul
goto menu

:exit_script
endlocal
exit /b 0
