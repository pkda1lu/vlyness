<#
.SYNOPSIS
  VLYNESS — удаление клиента под Windows.
.PARAMETER InstallDir
  Каталог установки (по умолчанию %LOCALAPPDATA%\VLYNESS).
#>
[CmdletBinding()]
param(
    [string] $InstallDir = (Join-Path $env:LOCALAPPDATA 'VLYNESS')
)
$ErrorActionPreference = 'Stop'

# Остановить запущенный клиент, если есть.
Get-Process -Name 'vlyness-client' -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue

$lnk = Join-Path ([Environment]::GetFolderPath('Programs')) 'VLYNESS client.lnk'
if (Test-Path $lnk) { Remove-Item -Force $lnk }

if (Test-Path $InstallDir) {
    Remove-Item -Recurse -Force $InstallDir
    Write-Host "[uninstall] удалён $InstallDir"
} else {
    Write-Host "[uninstall] $InstallDir не найден — нечего удалять"
}
Write-Host "[uninstall] готово."
