@echo off
chcp 65001 >nul
cd /d "%~dp0atelier-firmware"
where pythonw >nul 2>nul
if %errorlevel%==0 (
    start "" pythonw "%~dp0atelier-firmware\atelier.pyw"
) else (
    python "%~dp0atelier-firmware\server.py"
)
