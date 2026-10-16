# Crée le raccourci « Atelier Firmware » sur le bureau.
# Utilisation : clic droit sur ce fichier > « Exécuter avec PowerShell ».
$app = Split-Path -Parent $MyInvocation.MyCommand.Path
$pythonw = (Get-Command pythonw.exe -ErrorAction Stop).Source
$desktop = [Environment]::GetFolderPath('Desktop')

$shell = New-Object -ComObject WScript.Shell
$lnk = $shell.CreateShortcut((Join-Path $desktop 'Atelier Firmware.lnk'))
$lnk.TargetPath = $pythonw
$lnk.Arguments = '"' + (Join-Path $app 'atelier.pyw') + '"'
$lnk.WorkingDirectory = $app
$lnk.Description = 'Analyser des firmwares avec moria et mithril'
$lnk.IconLocation = "$env:SystemRoot\System32\shell32.dll,12"
$lnk.Save()
Write-Host "Raccourci créé sur le bureau : Atelier Firmware"
