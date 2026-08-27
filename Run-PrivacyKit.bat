@echo off
REM PrivacyKit launcher - requests Administrator rights, then starts the app.
title PrivacyKit

net session >nul 2>&1
if %errorLevel% == 0 goto :run

echo Requesting Administrator rights...
powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs" 2>nul
if %errorLevel% neq 0 (
    echo.
    echo Could not elevate. Starting without Administrator rights.
    echo System changes will be refused; diagnostics, the vault, passwords,
    echo metadata, and the shredder all still work.
    echo.
    pause
    goto :run
)
exit /b

:run
cd /d "%~dp0"

where python >nul 2>&1
if %errorLevel% neq 0 (
    echo.
    echo Python was not found on PATH.
    echo Install Python 3.9 or newer from python.org, ticking
    echo "Add python.exe to PATH" during setup.
    echo.
    pause
    exit /b 1
)

python -c "import PySide6" >nul 2>&1
if %errorLevel% neq 0 (
    echo.
    echo PrivacyKit's interface needs PySide6. Installing it now...
    echo.
    python -m pip install PySide6
    if %errorLevel% neq 0 (
        echo.
        echo Install failed. Run this manually:  pip install PySide6
        echo.
        pause
        exit /b 1
    )
)

python run.py --no-elevate
if %errorLevel% neq 0 (
    echo.
    echo PrivacyKit exited with an error. The message above should say why.
    pause
)
