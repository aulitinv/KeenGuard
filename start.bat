@echo off
chcp 65001 >nul
title KeenGuard - Network Security for Keenetic
cd /d "%~dp0"

echo ========================================================
echo   KeenGuard: Network Security ^& Forensics for Keenetic
echo ========================================================
echo.

if exist "%~dp0venv\Scripts\python.exe" (
    echo [INFO] Запуск KeenGuard из виртуального окружения venv...
    "%~dp0venv\Scripts\python.exe" run.py
    goto end
)

if exist "venv\Scripts\python.exe" (
    echo [INFO] Запуск KeenGuard из виртуального окружения venv...
    "venv\Scripts\python.exe" run.py
    goto end
)

echo [WARNING] Виртуальное окружение venv не найдено!
echo [INFO] Попытка запуска через системный python...
python run.py

:end
echo.
pause
