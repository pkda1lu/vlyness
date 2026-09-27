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
    [switch] $Gui,
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

# --- 1. получить exe (консольный vlyness-client или оконный vlyness-gui) ---
$exeName = if ($Gui) { 'vlyness-gui.exe' } else { 'vlyness-client.exe' }
$cargoPkg = if ($Gui) { 'vlyness-gui' } else { 'vlyness-cli' }
$srcExe = $null
if ($Exe) {
    if (-not (Test-Path $Exe)) { Die "не найден -Exe: $Exe" }
    $srcExe = $Exe
} elseif ($Build) {
    if (-not (Get-Command cargo -ErrorAction SilentlyContinue)) { Die "-Build задан, но cargo не найден (поставь Rust)" }
    Info "собираю release (cargo)…"
    Push-Location $repoDir
    try { & cargo build --release -p $cargoPkg; if ($LASTEXITCODE -ne 0) { Die "сборка не удалась" } }
    finally { Pop-Location }
    $srcExe = Join-Path $repoDir "target\release\$exeName"
} else {
    $candidate = Join-Path $repoDir "target\release\$exeName"
    if (Test-Path $candidate) { $srcExe = $candidate }
    else { Die "$exeName не найден. Укажи -Exe <путь> или -Build (нужен cargo)." }
}

# --- 2. каталог установки и exe ---
New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
$destExe = Join-Path $InstallDir $exeName
Copy-Item -Force $srcExe $destExe
Info "установлено в $InstallDir"

# Скопировать самоподписанный серт рядом и переписать ca_pem_path в профиле (без BOM:
# serde_json на клиенте не пропускает BOM).
function Set-ProfileCert($profile, $dir) {
    if (-not $Cert) { return }
    if (-not (Test-Path $Cert)) { Die "не найден -Cert: $Cert" }
    $destCert = Join-Path $dir 'vlyness-cert.pem'
    Copy-Item -Force $Cert $destCert
    try {
        $p = Get-Content -Raw $profile | ConvertFrom-Json
        if ($null -eq $p.endpoint) { Die "в профиле нет endpoint — нечего править" }
        $p.endpoint.ca_pem_path = $destCert
        $json = $p | ConvertTo-Json -Depth 40
        [System.IO.File]::WriteAllText($profile, $json, (New-Object System.Text.UTF8Encoding($false)))
        Info "ca_pem_path в профиле → $destCert"
    } catch { Die "не удалось переписать ca_pem_path: $_" }
}

# --- 3. профиль + способ запуска (GUI-окно или консольный лаунчер) ---
$launchTarget = $destExe
if ($Gui) {
    # GUI хранит профили и настройки в %APPDATA%\VLYNESS — засеваем их сразу.
    $guiDir = Join-Path $env:APPDATA 'VLYNESS'
    $profDir = Join-Path $guiDir 'profiles'
    New-Item -ItemType Directory -Force -Path $profDir | Out-Null
    $destProfile = Join-Path $profDir ([System.IO.Path]::GetFileName($ProfilePath))
    Copy-Item -Force $ProfilePath $destProfile
    Set-ProfileCert $destProfile $guiDir
    $refVal = if ($Reference) { $Reference } else { '' }
    $settings = [ordered]@{
        profile_paths = @($destProfile)
        socks_bind    = $SocksBind
        reference     = $refVal
        autostart     = $false
    }
    $sj = $settings | ConvertTo-Json -Depth 5
    [System.IO.File]::WriteAllText((Join-Path $guiDir 'gui.json'), $sj, (New-Object System.Text.UTF8Encoding($false)))
    Info "профиль засеян в $guiDir (GUI подхватит при запуске)"
} else {
    # Консоль: профиль + .cmd-лаунчер рядом с exe.
    $destProfile = Join-Path $InstallDir 'client.json'
    Copy-Item -Force $ProfilePath $destProfile
    Set-ProfileCert $destProfile $InstallDir
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
    $launchTarget = $launcher
}

# --- 4. ярлык (опц.) ---
if ($Shortcut) {
    $startMenu = [Environment]::GetFolderPath('Programs')
    $lnk = Join-Path $startMenu 'VLYNESS client.lnk'
    $ws = New-Object -ComObject WScript.Shell
    $sc = $ws.CreateShortcut($lnk)
    $sc.TargetPath = $launchTarget
    $sc.WorkingDirectory = $InstallDir
    $sc.Description = 'VLYNESS client'
    $sc.Save()
    Info "ярлык: $lnk"
}

Write-Host ''
Info 'ГОТОВО.'
if ($Gui) {
    Info "Запуск   : окно VLYNESS ($destExe) — нажми «Подключить»"
} else {
    Info "Запуск   : `"$launchTarget`""
}
Info "Прокси   : SOCKS5 $SocksBind"
Info "Проверка : curl --socks5-hostname $SocksBind https://api.ipify.org  (должен вернуть IP сервера)"
Info "Браузер  : настрой SOCKS5-хост $($SocksBind.Split(':')[0]) порт $($SocksBind.Split(':')[1])"
