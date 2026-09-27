# Установщики VLYNESS (для проверки)

Простые установщики, чтобы быстро поднять связку **сервер на Ubuntu-VPS ↔ клиент на Windows**
и проверить проксирование. Для боевого развёртывания см. `docs/DEPLOY.md`.

```
install/
  server/install.sh     # Ubuntu/Debian: сборка + systemd + конфиг + бандл клиента
  server/uninstall.sh
  client/install.ps1    # Windows: exe + профиль + лаунчер + ярлык
  client/uninstall.ps1
```

## 0. В одну строку (как у 3x-ui) — рекомендуется

На чистом Ubuntu/Debian VPS под root выполни **одну** команду — всё поставится само
(зависимости, Rust, сборка, systemd, firewall, конфиг, панель, бандл клиента):

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/pkda1lu/vlyness/main/install/vps.sh)
```

Без домена поднимется сервер с самоподписанным сертом на публичном IP (быстрая проверка).
С доменом (Let's Encrypt) добавь аргументы:

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/pkda1lu/vlyness/main/install/vps.sh) --domain rtc.example.tld --email you@example.com
```

После установки: панель — по SSH-туннелю (см. ниже), клиентский бандл — в
`/root/vlyness-client-bundle/`. Дальше клиентов удобнее выпускать прямо из панели.

> Требует, чтобы репозиторий был запушен на GitHub (ветка `main`) и публично доступен.
> Другой репозиторий/ветка — через `VLYNESS_REPO` / `VLYNESS_BRANCH`.

## 1. Сервер вручную (Ubuntu/Debian VPS)

Если репозиторий уже на VPS — из его корня запусти:

```bash
# С настоящим доменом (Let's Encrypt, порт 80 должен быть свободен и домен указывать на VPS):
sudo bash install/server/install.sh --domain rtc.example.tld --email you@example.com

# Быстрая проверка без домена/сертификата (самоподпись):
sudo bash install/server/install.sh --domain rtc.example.tld --self-signed
```

Что делает: ставит зависимости и Rust (если нет), собирает release, кладёт
`vlyness-server`/`vlyness-setup` в `/usr/local/bin`, создаёт пользователя `vlyness`,
генерирует `/etc/vlyness/server.toml` + профиль клиента, ставит и запускает
`systemd`-юнит, открывает порты в `ufw`, складывает бандл клиента в
`/root/vlyness-client-bundle/`.

Проверка сервера:

```bash
systemctl status vlyness-server
journalctl -u vlyness-server -f
```

### Веб-панель сервера

Сервер поднимает веб-панель на `127.0.0.1:8088` — **только loopback**, не на 443
(иначе зонд нашёл бы админку на домене и сломал honest-fallback). Сервер отказывается
слушать не-loopback адрес. Панель показывает аптайм, активные/всего сессии по TCP и QUIC,
живой трафик, хвост лога и **управляет клиентами**:

- **Выпустить клиента** — кнопка генерирует новый PSK, отдаёт готовый `client.json`
  (скачивается в браузере) и добавляет клиента в keyring.
- **Отозвать** — клиент мгновенно перестаёт подключаться (сервер отвечает ему
  honest-fallback), остальные не затронуты.

Каждый клиент — отдельный PSK (keyring, `/var/lib/vlyness/keyring.json`), поэтому отзыв
точечный. Ранее розданный общий профиль (из `vlyness-setup`) остаётся как клиент
`default` — работает, пока не отзовёшь.

Доступ со своей машины — по SSH-туннелю, затем `http://127.0.0.1:8088/`:

```bash
ssh -L 8088:127.0.0.1:8088 <user>@<vps>
```

Порт/выключение — поле `admin_bind` в `server.toml` (убери строку, чтобы отключить).

Забери на Windows-машину из `/root/vlyness-client-bundle/`:
- `client.json` (всегда);
- `vlyness-cert.pem` (только если ставил с `--self-signed`).

Опции: `--mode datagram|stream|both` (по умолчанию `datagram`), `--port N` (443),
`--no-firewall`, `--no-build`. Удаление: `sudo bash install/server/uninstall.sh [--purge]`.

## 2. Клиент (Windows)

Из корня репозитория (PowerShell). `vlyness-client.exe` берётся из `target\release`
(собери `cargo build --release -p vlyness-cli` или добавь `-Build`):

```powershell
# Обычный сервер (Let's Encrypt): клиент доверяет системным корням.
powershell -ExecutionPolicy Bypass -File install\client\install.ps1 `
  -ProfilePath C:\path\to\client.json -Shortcut

# Самоподписанный сервер: передай и сертификат.
powershell -ExecutionPolicy Bypass -File install\client\install.ps1 `
  -ProfilePath C:\path\to\client.json -Cert C:\path\to\vlyness-cert.pem -Shortcut
```

Что делает: кладёт `vlyness-client.exe` + `client.json` в `%LOCALAPPDATA%\VLYNESS`,
при `-Cert` правит `ca_pem_path` в профиле, пишет лаунчер `run-vlyness-client.cmd`
и (по `-Shortcut`) ярлык в меню «Пуск».

Запуск: ярлык **VLYNESS client** или `run-vlyness-client.cmd`. Поднимется SOCKS5 на
`127.0.0.1:1080`.

#### Оконный GUI (флаг `-Gui`)

Вместо консоли можно поставить графический клиент `vlyness-gui.exe` (окно: кнопка
Подключить/Отключить, состояние линка, счётчики трафика, импорт профилей файлом/
вставкой/перетаскиванием, лог, автозапуск):

```powershell
# сначала собрать GUI (тянет eframe — нужно место на диске под ~cargo):
cargo build --release -p vlyness-gui
powershell -ExecutionPolicy Bypass -File install\client\install.ps1 -Gui `
  -ProfilePath C:\path\to\client.json -Shortcut
```

С `-Gui` установщик кладёт `vlyness-gui.exe` и засевает профиль/настройки в
`%APPDATA%\VLYNESS` (GUI хранит их там). При `-Cert` так же переписывает `ca_pem_path`.
Ярлык **VLYNESS client** тогда открывает окно.

Проверка проксирования (в другом окне, пока клиент запущен):

```
curl --socks5-hostname 127.0.0.1:1080 https://api.ipify.org
```

Должен вернуться IP **сервера**, а не твой. В браузере укажи SOCKS5-хост `127.0.0.1`
порт `1080`. Удаление: `powershell -File install\client\uninstall.ps1`.

## Замечания

- `--self-signed` — только для проверки: сертификат не доверенный публично, поэтому
  клиент подтягивает его файлом. Для нормальной работы используй домен + Let's Encrypt.
- Если на Windows работает второй прокси с fake-ip (Clash/sing-box, пул `198.18.0.0/15`),
  он может перехватывать DNS и ломать резолв домена сервера — укажи реальный IP VPS в
  `endpoint.server_addr` профиля (SNI останется доменом) или выключи второй клиент.
- Инструмент двойного назначения: разворачивай только на своей инфраструктуре / с согласия
  владельца (см. `docs/04-roadmap.md` §4).
