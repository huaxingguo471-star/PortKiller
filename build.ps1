$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new()
$OutputEncoding = [System.Text.UTF8Encoding]::new()

$Root = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $Root

Write-Host "正在安装或更新 PyInstaller..."
python -m pip install --upgrade pyinstaller

Write-Host "正在打包 PortKiller.exe..."
python -m PyInstaller `
  --noconfirm `
  --clean `
  --onefile `
  --windowed `
  --uac-admin `
  --name "PortKiller" `
  "port_killer.py"

Write-Host ""
Write-Host "打包完成：${Root}\dist\PortKiller.exe"

