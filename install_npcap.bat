@echo off
chcp 65001 >nul
title KeenGuard - Установка драйвера Npcap
cd /d "%~dp0"

net session >nul 2>&1
if %errorlevel% neq 0 (
    echo ========================================================
    echo   KeenGuard: Автоматическая установка драйвера Npcap
    echo ========================================================
    echo.
    echo [INFO] Запрос прав Администратора для установки NDIS-драйвера...
    powershell -NoProfile -ExecutionPolicy Bypass -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
    exit /b
)

echo ========================================================
echo   KeenGuard: Автоматическая установка драйвера Npcap
echo ========================================================
echo.

powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0install_npcap.ps1"

pause
