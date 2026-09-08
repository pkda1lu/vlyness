# Быстрый старт — потрогать прототип

Прототип уже работает как локальный **SOCKS5-прокси**: приложение → vlyness-client →
TLS/HTTP2-туннель → vlyness-server → реальный интернет. Всё на одной машине.

## 1. Собрать

```powershell
cargo build --release --bin vlyness-server --bin vlyness-client
```

## 2. Запустить сервер (терминал 1)

```powershell
$env:VLYNESS_BIND="127.0.0.1:8443"; $env:VLYNESS_DOMAIN="localhost"; $env:VLYNESS_TUNNEL_PATH="/v1/media"; $env:VLYNESS_CERT_OUT=".\vlyness-cert.pem"
.\target\release\vlyness-server.exe
```

Сервер напечатает три строки — **скопируй `VLYNESS_PSK_B64` и `server_pub(b64)`**:

```
[gen] VLYNESS_PSK_B64=<...>
[vlyness-server] server_pub(b64)=<...>
[vlyness-server] сертификат записан в .\vlyness-cert.pem
```

## 3. Запустить клиент (терминал 2)

Подставь значения из вывода сервера:

```powershell
$env:VLYNESS_SERVER_ADDR="127.0.0.1:8443"; $env:VLYNESS_SNI="localhost"; $env:VLYNESS_CA=".\vlyness-cert.pem"
$env:VLYNESS_PSK_B64="<PSK из вывода сервера>"; $env:VLYNESS_SERVER_PUB_B64="<server_pub из вывода>"
$env:VLYNESS_SOCKS_BIND="127.0.0.1:1080"; $env:VLYNESS_TUNNEL_PATH="/v1/media"; $env:VLYNESS_MODE="packet"
.\target\release\vlyness-client.exe
```

Увидишь `[tunnel] установлен` — туннель поднят.

## 4. Направить трафик в прокси

- **Браузер** (Firefox): Настройки → Сеть → Прокси вручную → SOCKS5 `127.0.0.1:1080`,
  отметить «Проксировать DNS при SOCKS5». Открой любой сайт — он пойдёт через туннель.
- **curl**: `curl --socks5-hostname 127.0.0.1:1080 https://example.com`
- **Системный SOCKS5** (Windows): Параметры → Прокси → «Использовать прокси-сервер».

## RTC-режим (HTTP/3 + WebTransport поверх QUIC)

Самая стойкая по *форме транспорта* легенда — трафик выглядит как QUIC-видеозвонок к :443/UDP.
Сервер поднимает QUIC-листенер дополнительно к TCP (тем же сертификатом), клиент идёт `datagram`-режимом:

```powershell
# сервер (терминал 1): добавь UDP-листенер на тот же адрес
$env:VLYNESS_BIND="127.0.0.1:8443"; $env:VLYNESS_QUIC="127.0.0.1:8443"; $env:VLYNESS_DOMAIN="localhost"
.\target\release\vlyness-server.exe
```
```powershell
# клиент (терминал 2): режим datagram (путь по умолчанию /v1/media/s/seg)
$env:VLYNESS_SERVER_ADDR="127.0.0.1:8443"; $env:VLYNESS_SNI="localhost"; $env:VLYNESS_CA=".\vlyness-cert.pem"
$env:VLYNESS_PSK_B64="<PSK>"; $env:VLYNESS_SERVER_PUB_B64="<server_pub>"
$env:VLYNESS_SOCKS_BIND="127.0.0.1:1080"; $env:VLYNESS_MODE="datagram"
.\target\release\vlyness-client.exe
```
Дальше — тот же SOCKS5 на `127.0.0.1:1080`: `curl --socks5-hostname 127.0.0.1:1080 http://example.com`
(и TCP, и UDP работают поверх QUIC). Туннель едет по надёжному WebTransport-стриму внутри QUIC.

## Что покрутить

- `VLYNESS_MODE` = `stream` | `segments` | `packet` | `datagram` — форма несущей (что видит DPI).
- `VLYNESS_QUIC=host:port` — включить серверный QUIC/HTTP-3/WebTransport-листенер (UDP).
- `VLYNESS_ECH` = `grease` (ECH-образный ClientHello) | `doh` (взять ECHConfigList из DNS).
- `VLYNESS_PROFILES=a.json,b.json` — пул носителей с автоматической ротацией.
- `VLYNESS_REFERENCE=1.1.1.1:443` — включить blackhole-детектор (тишина при тихом дропе).

## Оговорка

Это исследовательский прототип. Сервер и клиент — на localhost с самоподписанным
сертификатом: так туннель проверяется целиком на одной машине. Для реального разнесения
(сервер на VPS/за CDN) нужен домен, валидный сертификат/ACME и площадка-носитель —
см. [05-whitelist-traversal.md](05-whitelist-traversal.md) и [02 §3](02-vlyness-design.md).
