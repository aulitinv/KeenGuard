@echo off
chcp 65001 >nul
title KeenGuard - Network Security for Keenetic
cd /d "%~dp0"

echo ========================================================
echo   KeenGuard: Network Security ^& Forensics for Keenetic
echo ========================================================
echo.

:: 1. Проверяем наличие Python в системе
where python >nul 2>nul
if errorlevel 1 (
    echo [ERROR] Python не найден в системе!
    echo.
    echo Пожалуйста, установите Python 3.10 или новее:
    echo   https://www.python.org/downloads/
    echo ВАЖНО: При установке обязательно включите галочку "Add Python to PATH".
    goto end
)

:: 2. Если виртуальное окружение venv отсутствует — создаем и устанавливаем зависимости
if not exist "%~dp0venv\Scripts\python.exe" (
    echo [INFO] Виртуальное окружение venv не найдено.
    echo [INFO] Создание виртуального окружения (python -m venv venv)...
    python -m venv "%~dp0venv"
    if errorlevel 1 (
        echo [ERROR] Не удалось создать виртуальное окружение!
        goto end
    )
    echo [INFO] Установка зависимостей из requirements.txt...
    "%~dp0venv\Scripts\python.exe" -m pip install --upgrade pip
    "%~dp0venv\Scripts\python.exe" -m pip install -r "%~dp0requirements.txt"
    if errorlevel 1 (
        echo [ERROR] Ошибка при установке зависимостей!
        goto end
    )
    echo [INFO] Окружение успешно настроено!
    echo.
)

:: 3. Запуск приложения
echo [INFO] Запуск KeenGuard...
"%~dp0venv\Scripts\python.exe" run.py

:end
echo.
pause
