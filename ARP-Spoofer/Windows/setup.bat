@echo off
setlocal EnableExtensions
title "ARP_SPOOFER - Setup - LTX & Moka"
color 5

net session >nul 2>&1
if %errorlevel% equ 0 (
    echo ============================================
    echo   DO NOT RUN THIS SCRIPT AS ADMINISTRATOR
    echo ============================================
    echo.
    echo !!! Please do not run this script as administrator !!!
    echo.
    pause
    exit /b 1
)

echo.
echo ============================================
echo        ARP_SPOOFER - Setup - LTX ^& Moka
echo ============================================
echo.

echo Checking Python installation...
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] Python is not installed.
    echo Please install Python 3.x and try again.
    pause
    exit /b 1
)
echo [OK] Python detected.
echo.

echo Installing required Python packages...
pip install -r "%~dp0requirements.txt"
if %errorlevel% neq 0 (
    echo [ERROR] Failed to install Python packages.
    pause
    exit /b 1
)
echo [OK] Python packages installed.
echo.

echo Checking for NPCAP installation...

reg query "HKLM\SOFTWARE\WOW6432Node\Npcap" >nul 2>&1
if %errorlevel% equ 0 (
    echo [OK] NPCAP is already installed.
) else (
    echo NPCAP is not installed.
    echo Launching NPCAP installer...
    start "" "%~dp0npcap-1.86.exe"
    echo Please complete the NPCAP installation window.
    pause
)
echo.

echo Setup completed successfully!
echo.
color 6
cls
echo.
echo Press any key to start arp_spoofer.py
pause >nul

start "" "%~dp0auto_generate.py"
exit /b 0
