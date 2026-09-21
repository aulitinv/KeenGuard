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
if errorlevel 1 goto no_python

:: 2. Если виртуальное окружение venv уже существует - сразу запускаем
if exist "%~dp0venv\Scripts\python.exe" goto run_app

:: 3. Если venv отсутствует - создаем и устанавливаем зависимости
echo [INFO] Виртуальное окружение venv не найдено.
echo [INFO] Создание виртуального окружения...
python -m venv "%~dp0venv"
if errorlevel 1 goto venv_error

echo [INFO] Установка зависимостей из requirements.txt...
"%~dp0venv\Scripts\python.exe" -m pip install --upgrade pip
"%~dp0venv\Scripts\python.exe" -m pip install -r "%~dp0requirements.txt"
if errorlevel 1 goto install_error

echo [INFO] Окружение успешно настроено!
echo.

:run_app
echo [INFO] Запуск KeenGuard...
"%~dp0venv\Scripts\python.exe" run.py
goto end

:no_python
echo [ERROR] Python не найден в системе!
echo.
echo Пожалуйста, установите Python 3.10 или новее:
echo   https://www.python.org/downloads/
echo ВАЖНО: При установке обязательно включите галочку Add Python to PATH.
goto end

:venv_error
echo [ERROR] Не удалось создать виртуальное окружение!
goto end

:install_error
echo [ERROR] Ошибка при установке зависимостей!
goto end

:end
echo.
pause
echo.
pause
