@echo off
chcp 65001 >nul
echo ========================================================
echo   Installation d'Atelier Firmware sur ce PC
echo ========================================================
echo.

powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0atelier-firmware\creer-raccourci.ps1"

if exist "%~dp0Rapports-Analyses-Sauvegarde\Atelier Firmware" (
    echo.
    echo Copie des analyses precedentes vers Documents\Atelier Firmware...
    robocopy "%~dp0Rapports-Analyses-Sauvegarde\Atelier Firmware" "%USERPROFILE%\Documents\Atelier Firmware" /E /XC /XN /XO /NFL /NDL /NJH /NJS >nul
    echo Analyses restaurees dans Documents\Atelier Firmware.
)

echo.
echo Termine ! Vous pouvez maintenant lancer "Atelier Firmware" depuis le Bureau,
echo puis aller dans l'onglet "Outils" et cliquer sur "Installer" pour compiler
echo les outils dans Ubuntu (WSL) sur ce nouveau PC.
echo.
pause
