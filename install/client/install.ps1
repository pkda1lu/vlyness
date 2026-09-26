<#
.SYNOPSIS
  VLYNESS — простой установщик клиента под Windows (для проверки).

.DESCRIPTION
  Кладёт vlyness-client.exe и профиль client.json в каталог установки, при
  самоподписанном сервере подхватывает сертификат и правит ca_pem_path в профиле,
  пишет лаунчер (run-vlyness-client.cmd) и, по флагу, ярлык в меню «Пуск».
  Клиент поднимает локальный SOCKS5-прокси, через который ходит трафик.

.PARAMETER ProfilePath
  Путь к client.json из серверного бандла (/root/vlyness-client-bundle на VPS). Обязателен.

.PARAMETER Cert
  Путь к vlyness-cert.pem (только для сервера с --self-signed). Копируется рядом,
  ca_pem_path в профиле переписывается на локальный путь.

.PARAMETER Exe
  Путь к готовому vlyness-client.exe. Если не задан — берётся target/release из репозитория
  (или собирается при -Build).

.PARAMETER Build
  Собрать vlyness-client.exe из исходников (нужен установленный Rust/cargo).

.PARAMETER InstallDir
  Каталог установки (по умолчанию %LOCALAPPDATA%\VLYNESS).

.PARAMETER SocksBind
  Адрес локального SOCKS5 (по умолчанию 127.0.0.1:1080).

.PARAMETER Reference
  Контрольный хост для blackhole-детектора (по умолчанию 8.8.8.8:53).

.PARAMETER Shortcut
  Создать ярлык в меню «Пуск».

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File install\client\install.ps1 -ProfilePath .\client.json -Shortcut

.EXAMPLE
  # самоподписанный сервер:
  .\install.ps1 -ProfilePath .\client.json -Cert .\vlyness-cert.pem
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)] [string] $ProfilePath,
    [string] $Cert,
    [string] $Exe,
    [switch] $Build,
    [string] $InstallDir = (Join-Path $env:LOCALAPPDATA 'VLYNESS'),
    [string] $SocksBind = '127.0.0.1:1080',
    [string] $Reference = '8.8.8.8:53',
    [switch] $Shortcut
)

$ErrorActionPreference = 'Stop'
function Info($m) { Write-Host "[install] $m" }
function Die($m) { Write-Error "[install] ОШИБКА: $m"; exit 1 }

if (-not (Test-Path $ProfilePath)) { Die "не найден профиль: $ProfilePath" }

# Корень репозитория — два уровня вверх от скрипта.
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$repoDir = (Resolve-Path (Join-Path $scriptDir '..\..')).Path

# --- 1. получить exe ---
$srcExe = $null
if ($Exe) {
    if (-not (Test-Path $Exe)) { Die "не найден -Exe: $Exe" }
    $srcExe = $Exe
} elseif ($Build) {
    if (-not (Get-Command cargo -ErrorAction SilentlyContinue)) { Die "-Build задан, но cargo не найден (поставь Rust)" }
    Info "собираю release (cargo)…"
    Push-Location $repoDir
    try { & cargo build --release -p vlyness-cli; if ($LASTEXITCODE -ne 0) { Die "сборка не удалась" } }
    finally { Pop-Location }
    $srcExe = Join-Path $repoDir 'target\release\vlyness-client.exe'
} else {
    $candidate = Join-Path $repoDir 'target\release\vlyness-client.exe'
    if (Test-Path $candidate) { $srcExe = $candidate }
    else { Die "vlyness-client.exe не найден. Укажи -Exe <путь> или -Build (нужен cargo)." }
}

# --- 2. каталог установки и файлы ---
New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
$destExe = Join-Path $InstallDir 'vlyness-client.exe'
$destProfile = Join-Path $InstallDir 'client.json'
Copy-Item -Force $srcExe $destExe
Copy-Item -Force $ProfilePath $destProfile
Info "установлено в $InstallDir"

# --- 3. самоподписанный серт: скопировать и переписать ca_pem_path в профиле ---
if ($Cert) {
    if (-not (Test-Path $Cert)) { Die "не найден -Cert: $Cert" }
    $destCert = Join-Path $InstallDir 'vlyness-cert.pem'
    Copy-Item -Force $Cert $destCert
    try {
        $p = Get-Content -Raw $destProfile | ConvertFrom-Json
        if ($null -eq $p.endpoint) { Die "в профиле нет endpoint — нечего править" }
        $p.endpoint.ca_pem_path = $destCert
        # Без BOM: serde_json на клиенте не пропускает BOM в начале файла.
        $json = $p | ConvertTo-Json -Depth 40
        [System.IO.File]::WriteAllText($destProfile, $json, (New-Object System.Text.UTF8Encoding($false)))
        Info "ca_pem_path в профиле → $destCert"
    } catch { Die "не удалось переписать ca_pem_path: $_" }
}

# --- 4. лаунчер ---
$launcher = Join-Path $InstallDir 'run-vlyness-client.cmd'
@"
@echo off
setlocal
set "DIR=%~dp0"
set "VLYNESS_PROFILES=%DIR%client.json"
set "VLYNESS_SOCKS_BIND=$SocksBind"
set "VLYNESS_REFERENCE=$Reference"
echo VLYNESS client -- SOCKS5 on $SocksBind (Ctrl+C to stop)
"%DIR%vlyness-client.exe"
"@ | Set-Content -Encoding ascii $launcher
Info "лаунчер: $launcher"

# --- 5. ярлык (опц.) ---
if ($Shortcut) {
    $startMenu = [Environment]::GetFolderPath('Programs')
    $lnk = Join-Path $startMenu 'VLYNESS client.lnk'
    $ws = New-Object -ComObject WScript.Shell
    $sc = $ws.CreateShortcut($lnk)
    $sc.TargetPath = $launcher
    $sc.WorkingDirectory = $InstallDir
    $sc.Description = 'VLYNESS client (SOCKS5 proxy)'
    $sc.Save()
    Info "ярлык: $lnk"
}

Write-Host ''
Info 'ГОТОВО.'
Info "Запуск   : `"$launcher`""
Info "Прокси   : SOCKS5 $SocksBind"
Info "Проверка : curl --socks5-hostname $SocksBind https://api.ipify.org  (должен вернуть IP сервера)"
Info "Браузер  : настрой SOCKS5-хост $($SocksBind.Split(':')[0]) порт $($SocksBind.Split(':')[1])"
