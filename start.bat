@echo off
:: ══════════════════════════════════════════════════════════════════
::  PhishGuard — One-Command Launcher (Windows)
::  Usage: Double-click start.bat  or  start.bat in cmd
:: ══════════════════════════════════════════════════════════════════

setlocal enabledelayedexpansion
set "SCRIPT_DIR=%~dp0"
set "BACKEND_DIR=%SCRIPT_DIR%backend"
set "VENV_DIR=%SCRIPT_DIR%.venv"
set "PORT=8000"
set "URL=http://localhost:%PORT%"

echo.
echo  ======================================
echo   PhishGuard - Real-Time Phishing Detection
echo  ======================================
echo.

:: Check Python
python --version >nul 2>&1
if errorlevel 1 (
    echo  [ERROR] Python not found. Install from https://python.org
    pause & exit /b 1
)
echo  [OK] Python found

:: Create venv if missing
if not exist "%VENV_DIR%\Scripts\activate.bat" (
    echo  [..] Creating virtual environment...
    python -m venv "%VENV_DIR%"
    echo  [OK] Virtual environment created
)

:: Activate
call "%VENV_DIR%\Scripts\activate.bat"
echo  [OK] Virtual environment activated

:: Install deps
echo  [..] Installing dependencies...
pip install --quiet --upgrade pip
pip install --quiet -r "%BACKEND_DIR%\requirements.txt"
echo  [OK] Dependencies installed

:: Open browser after delay
start "" timeout /t 2 /nobreak >nul
start "" "%URL%"

:: Start server
echo.
echo  PhishGuard starting at %URL%
echo  API Docs at %URL%/docs
echo  Press Ctrl+C to stop.
echo.

cd /d "%BACKEND_DIR%"
uvicorn main:app --host 0.0.0.0 --port %PORT% --reload

pause
