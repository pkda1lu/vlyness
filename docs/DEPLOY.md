# Развёртывание VLYNESS на VPS (домен `vlyne.online`)

Полный, пошаговый runbook: свой VPS + домен **`vlyne.online`** + настоящий сертификат
Let's Encrypt. Основной режим — **datagram (HTTP/3 + WebTransport поверх QUIC)**. Сервер
одновременно поднимает **TCP** (TLS/HTTP-2) и **QUIC/UDP** (HTTP-3), так что один процесс
обслуживает и datagram-клиента, и TCP-режимы (`stream`/`segments`).

> **Этика.** Разворачивай на **своей** инфраструктуре / с согласия владельца, под задачу
> доступа к информации в условиях цензуры и авторизованного исследования устойчивости
> сетей. Не под атаку на инфраструктуру и не под массовое злоупотребление (док 04 §4).
> Никаких утверждений «гарантированно необнаружим» — только сдвиг стоимости детекта на
> дату замера.

Содержание:
1. [Предпосылки](#1-предпосылки)
2. [DNS](#2-dns)
3. [Сборка бинарников](#3-сборка-бинарников)
4. [Доставка на VPS](#4-доставка-на-vps)
5. [Сертификат Let's Encrypt](#5-сертификат-lets-encrypt)
6. [Генерация конфигов (`vlyness-setup`)](#6-генерация-конфигов-vlyness-setup)
7. [Пользователь и права на сертификат](#7-пользователь-и-права-на-сертификат)
8. [systemd](#8-systemd)
9. [Firewall / порты](#9-firewall--порты)
10. [Клиент](#10-клиент)
11. [Проверка](#11-проверка)
12. [Эксплуатация](#12-эксплуатация-обновления-серта-логи-апдейт)
13. [Диагностика](#13-диагностика)
14. [Модель безопасности и границы](#14-модель-безопасности-и-границы)

---

## 1. Предпосылки

- **VPS**: Linux x86-64 (Debian/Ubuntu в примерах), публичный IPv4. Root или sudo.
- **Домен** `vlyne.online`, чей `A`-запись указывает на публичный IP VPS.
- **Открытые порты**: `443/tcp` **и** `443/udp` (QUIC — это UDP!) в firewall хоста
  **и** в security group облака.
- Билд-машина с Rust 1.75+ (можно собрать локально и скопировать бинарь — см. §3–§4).

## 2. DNS

Заведи A-запись у регистратора/DNS-провайдера `vlyne.online`:

```
vlyne.online.   A   <ПУБЛИЧНЫЙ_IP_VPS>
```

Проверь, что резолвится в нужный IP (не только у себя — и снаружи):

```bash
dig +short vlyne.online A
```

> Если добавляешь `AAAA` (IPv6) — сервер должен слушать и по IPv6: поставь в
> `server.toml` `bind`/`quic` = `[::]:443` (dual-stack) либо не публикуй AAAA. Клиент
> устойчив к A+AAAA (пробует адреса по очереди, IPv4 первым), но сервер обязан слушать
> ту семью, куда указывает DNS.

## 3. Сборка бинарников

На билд-машине (или прямо на VPS, если там есть Rust):

```bash
git clone <repo> vlyness && cd vlyness
cargo build --release --bin vlyness-server --bin vlyness-setup --bin vlyness-client
```

Бинарники: `target/release/{vlyness-server,vlyness-setup,vlyness-client}`.

**Полностью статичная сборка (musl)** — удобно, чтобы бинарь не зависел от glibc VPS:

```bash
rustup target add x86_64-unknown-linux-musl
cargo build --release --target x86_64-unknown-linux-musl \
  --bin vlyness-server --bin vlyness-setup
# → target/x86_64-unknown-linux-musl/release/...
```

## 4. Доставка на VPS

```bash
scp target/release/vlyness-server target/release/vlyness-setup \
    root@vlyne.online:/usr/local/bin/
ssh root@vlyne.online 'chmod +x /usr/local/bin/vlyness-server /usr/local/bin/vlyness-setup'
```

`vlyness-client` ставится на **клиентскую** машину (твой ноут/телефон-хост), не на VPS.

## 5. Сертификат Let's Encrypt

На VPS:

```bash
apt update && apt install -y certbot
# порт 80 должен быть свободен для standalone-проверки:
certbot certonly --standalone -d vlyne.online --agree-tos -m you@example.com -n
```

Результат:

```
/etc/letsencrypt/live/vlyne.online/fullchain.pem
/etc/letsencrypt/live/vlyne.online/privkey.pem
```

Сервер читает эти PEM **при старте**, поэтому после автопродления сертификата сервис
нужно перезапустить — хук настроим в §12.

> Порт 80 нужен только для проверки. Если он занят — используй `--webroot -w <path>` или
> DNS-01. После выпуска 80 больше не нужен.

## 6. Генерация конфигов (`vlyness-setup`)

Одной командой — серверный `server.toml` и клиентский профиль(и) со **всеми** секретами
(PSK + статическая пара сервера уже внутри, копипаст ключей не нужен):

```bash
cd /root
vlyness-setup --domain vlyne.online --out-dir /root/vlyne-config --mode both
```

- `--mode datagram` — только RTC/HTTP-3 (основной, рекомендуемый);
- `--mode both` — два профиля (`datagram` + `stream`): клиент сам переключится на TCP,
  если сеть режет QUIC/UDP;
- `--tunnel-path /v1/rtc` (по умолчанию), `--port 443` (по умолчанию).

Полученный `server.toml` (пути к серту уже подставлены под `vlyne.online`):

```toml
bind = "0.0.0.0:443"
quic = "0.0.0.0:443"
domain = "vlyne.online"
tunnel_path = "/v1/rtc"
psk_b64 = "<32 байта, base64>"
server_priv_b64 = "<приватный ключ сервера>"
server_pub_b64 = "<публичный ключ сервера>"
cert_pem = "/etc/letsencrypt/live/vlyne.online/fullchain.pem"
key_pem = "/etc/letsencrypt/live/vlyne.online/privkey.pem"
```

Разложи конфиг и перенеси клиентские профили к себе:

```bash
mkdir -p /etc/vlyness && cp /root/vlyne-config/server.toml /etc/vlyness/
chmod 600 /etc/vlyness/server.toml           # в нём секреты
# клиентские профили — на свою машину:
scp root@vlyne.online:/root/vlyne-config/client-*.json ./
```

> `client.json`/`client-*.json` **тоже содержат PSK** — это доверенный секрет, храни
> как ключ, не публикуй.

## 7. Пользователь и права на сертификат

Запускаем под отдельным пользователем без прав, а не под root. `privkey.pem` по умолчанию
читается только root — дадим доступ через группу:

```bash
useradd --system --no-create-home --shell /usr/sbin/nologin vlyness || true
chown -R root:vlyness /etc/letsencrypt/live /etc/letsencrypt/archive
chmod -R g+rX          /etc/letsencrypt/live /etc/letsencrypt/archive
chgrp vlyness /etc/vlyness/server.toml && chmod 640 /etc/vlyness/server.toml
```

## 8. systemd

Юнит уже готов — [`deploy/vlyness-server.service`](../deploy/vlyness-server.service):
запуск под `vlyness`, бинд `:443` без root через `CAP_NET_BIND_SERVICE`, базовый
sandboxing (`ProtectSystem=strict`, `PrivateTmp`, доступ только на чтение к
`/etc/letsencrypt` и `/etc/vlyness`).

```bash
install -m 0644 deploy/vlyness-server.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now vlyness-server
systemctl status vlyness-server            # active (running)
journalctl -u vlyness-server -e            # логи; ожидаем:
#   [vlyness-server] сертификат из PEM: /etc/letsencrypt/live/vlyne.online/fullchain.pem
#   [vlyness-server] QUIC/HTTP-3/WebTransport слушаю 0.0.0.0:443 (UDP)
#   [vlyness-server] TCP (TLS/HTTP-2) слушаю 0.0.0.0:443
```

## 9. Firewall / порты

```bash
ufw allow 443/tcp
ufw allow 443/udp        # ОБЯЗАТЕЛЬНО для QUIC/datagram — без него режим не поднимется
ufw reload
```

Дополнительно открой `443/udp` **в security group облака** (AWS/GCP/Hetzner/… часто
фильтруют отдельно от хостового firewall). Проверить, что UDP реально открыт, можно с §11.

## 10. Клиент

На своей машине (профили из §6):

```bash
# один режим (datagram):
VLYNESS_PROFILES=./client-datagram.json VLYNESS_SOCKS_BIND=127.0.0.1:1080 \
  vlyness-client

# оба (--mode both): пул с авто-переключением datagram→stream, если QUIC/UDP не проходит
VLYNESS_PROFILES=./client-datagram.json,./client-stream.json \
  VLYNESS_SOCKS_BIND=127.0.0.1:1080 vlyness-client
```

Ожидаем `[tunnel] установлен через 'vps-datagram-h3'`. Дальше — обычный SOCKS5
`127.0.0.1:1080`:

- **curl**: `curl --socks5-hostname 127.0.0.1:1080 https://example.com`
- **Firefox**: Настройки → Сеть → Прокси вручную → SOCKS v5 `127.0.0.1:1080`,
  включить «Проксировать DNS при использовании SOCKS v5».
- **Chrome/Chromium**: `--proxy-server="socks5://127.0.0.1:1080"`.

Полезное окружение клиента:
- `VLYNESS_REFERENCE=1.1.1.1:443` — включить blackhole-детектор (тишина при тихом дропе,
  затем ротация носителя);
- `VLYNESS_DOH_RESOLVER=https://1.1.1.1/dns-query` — резолвер для ECH-DoH (в Direct-режиме
  не требуется).

## 11. Проверка

**TCP сквозь туннель:**
```bash
curl --socks5-hostname 127.0.0.1:1080 -sS https://example.com | head
```

**UDP/QUIC открыт на сервере** (со стороны клиента, до запуска — что порт слушает):
```bash
# просто проверить, что UDP/443 не режется: любой QUIC-инструмент, напр.
nc -vzu vlyne.online 443    # UDP «open|filtered» = не зарезан наглухо
```

**Полный datagram-путь** уже подтверждается тем, что клиент печатает `[tunnel] установлен
через 'vps-datagram-h3'` (сессия идёт по QUIC/WebTransport), а `curl` возвращает 200.

## 12. Эксплуатация (обновление серта, логи, апдейт)

**Автопродление сертификата.** certbot ставит таймер `certbot.timer` сам. Но VLYNESS
читает PEM только при старте — поставь deploy-hook, перезапускающий сервис после продления
([`deploy/certbot-deploy-hook.sh`](../deploy/certbot-deploy-hook.sh)):

```bash
install -m 0755 deploy/certbot-deploy-hook.sh \
  /etc/letsencrypt/renewal-hooks/deploy/vlyness.sh
certbot renew --dry-run        # проверить, что продление и хук отрабатывают
```

**Логи:** `journalctl -u vlyness-server -f`.

**Обновление бинарника:**
```bash
scp target/release/vlyness-server root@vlyne.online:/usr/local/bin/
ssh root@vlyne.online 'systemctl restart vlyness-server'
```

**Ротация PSK/ключей:** перегенерируй `vlyness-setup --domain vlyne.online`, разложи новый
`server.toml` и раздай новые клиентские профили, `systemctl restart vlyness-server`.

## 13. Диагностика

| Симптом | Причина / решение |
|---|---|
| Клиент: `timed out`, `[tunnel] не удалось` | `443/udp` закрыт (firewall/облако) → см. §9. Или DNS указывает не туда → §2. |
| Клиент годами висит в datagram, а сеть режет QUIC | Разверни `--mode both` — клиент сам переключится на `stream` (TCP). |
| Сервер: `сертификат из PEM` не печатается, идёт самоподпись | В `server.toml` нет `cert_pem`/`key_pem`, либо пути не читаются пользователем `vlyness` → §7. |
| `Permission denied` на `privkey.pem` | Права на `/etc/letsencrypt/{live,archive}` → §7 (`chgrp vlyness`, `g+rX`). |
| После продления серта клиенты отваливаются | Не настроен deploy-hook → §12 (сервер отдавал старый серт). |
| Всё поднялось, но `curl` через прокси не идёт | Проверь, что клиент реально печатает `[tunnel] установлен`; проверь SNI = `vlyne.online` и что домен резолвится у клиента. |
| IPv6-only VPS | `bind`/`quic` = `[::]:443` в `server.toml`. |

## 14. Модель безопасности и границы

- **Секреты**: `server.toml` и клиентские `*.json` содержат PSK — это доверенные секреты.
  Права `600`/`640`, не коммить (в `.gitignore` уже `*.pem`, `/vlyness-config/`).
- **Аутентификация** — ratchet-токен в cookie CONNECT (= Noise-prologue): подделать нельзя,
  хендшейк не сойдётся. Запрос без валидного токена или на «не тот» путь получает
  honest-fallback (настоящий сайт по TCP, `404` по WebTransport) — зонд не отличит нас от
  обычного сервиса.
- **Что это НЕ решает**: репутацию ASN/подсети (только выбором площадки), тайминг-корреляцию
  глобального наблюдателя, компрометацию самого сервера.
- **Direct против whitelist**: это Direct-развёртывание (свой домен на своём IP). Проход
  сквозь **белые списки** (когда цензор пропускает только разрешённые IP/SNI) требует
  co-tenancy за общим CDN + ECH — отдельный путь, см.
  [05-whitelist-traversal.md](05-whitelist-traversal.md). На «обычной» цензуре (DPI по форме
  и SNI, а не белый список) Direct-развёртывания достаточно.
