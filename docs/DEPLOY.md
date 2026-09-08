# Развёртывание VLYNESS на VPS

Пошаговый runbook: свой VPS + свой домен + настоящий сертификат (Let's Encrypt),
основной режим — **datagram (HTTP/3 + WebTransport поверх QUIC)**. Сервер одновременно
поднимает и TCP (TLS/HTTP-2), и QUIC (UDP), так что клиент может ходить любым режимом.

> Этика: разворачивай **на своей инфраструктуре / с согласия владельца**, под задачу
> доступа к информации в условиях цензуры и авторизованного исследования. Не под атаку
> и не под массовое злоупотребление (док 04 §4).

---

## 0. Что нужно заранее

- **VPS** (Linux, x86-64) с публичным IP; домен `rtc.example.tld`, чей `A`/`AAAA`
  указывает на этот IP.
- Открытые порты **443/tcp и 443/udp** (QUIC — это UDP!).
- Rust 1.75+ на билд-машине (можно собрать локально и `scp` бинарь — статичной musl-сборкой
  или под тот же дистрибутив).

## 1. Сборка

```bash
cargo build --release --bin vlyness-server --bin vlyness-setup   # на сервере/билд-машине
cargo build --release --bin vlyness-client                       # на клиентской машине
```

Готовые бинарники — в `target/release/`. Скопируй на VPS:

```bash
scp target/release/vlyness-server target/release/vlyness-setup root@rtc.example.tld:/usr/local/bin/
```

## 2. Сертификат Let's Encrypt

```bash
apt install certbot
# порт 80 должен быть свободен для standalone-проверки (или используй --webroot)
certbot certonly --standalone -d rtc.example.tld
# → /etc/letsencrypt/live/rtc.example.tld/{fullchain.pem,privkey.pem}
```

Сервер читает PEM при старте, поэтому **после обновления сертификата его нужно
перезапустить**. Хук обновления — [`deploy/certbot-deploy-hook.sh`](../deploy/certbot-deploy-hook.sh):

```bash
install -m 0755 deploy/certbot-deploy-hook.sh \
  /etc/letsencrypt/renewal-hooks/deploy/vlyness.sh
```

## 3. Сгенерировать конфиги (без копипаста ключей)

```bash
vlyness-setup --domain rtc.example.tld --out-dir ./vlyness-config
```

Создаёт:
- `vlyness-config/server.toml` — серверный конфиг (PSK + пара ключей + пути к сертификату
  Let's Encrypt уже подставлены);
- `vlyness-config/client.json` — клиентский профиль (datagram, все секреты внутри).

Разложи:
```bash
mkdir -p /etc/vlyness && cp vlyness-config/server.toml /etc/vlyness/
# client.json — перенеси на клиентскую машину (это и есть весь клиентский конфиг)
```

Опции `vlyness-setup`: `--tunnel-path /v1/rtc`, `--port 443`, `--mode datagram|stream|both`,
`--self-signed` (без домена/CA — для теста), `--cert-dir DIR` (нестандартный путь серта).

## 4. systemd

```bash
# пользователь без прав, которому дадим читать сертификат
useradd --system --no-create-home --shell /usr/sbin/nologin vlyness || true
# доступ к приватному ключу (privkey читается только root по умолчанию):
chgrp -R vlyness /etc/letsencrypt/live /etc/letsencrypt/archive
chmod -R g+rX  /etc/letsencrypt/live /etc/letsencrypt/archive

install -m 0644 deploy/vlyness-server.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now vlyness-server
systemctl status vlyness-server        # должно быть active (running)
journalctl -u vlyness-server -f        # логи
```

Юнит выдаёт процессу `CAP_NET_BIND_SERVICE` (чтобы биндить 443 без root) и включает
базовый sandboxing (`ProtectSystem=strict`, `PrivateTmp` и т.д.).

## 5. Firewall

```bash
ufw allow 443/tcp
ufw allow 443/udp        # ОБЯЗАТЕЛЬНО для QUIC/datagram
```

Многие облака дополнительно фильтруют на уровне security group — открой 443/udp и там.

## 6. Клиент

На своей машине:

```bash
VLYNESS_PROFILES=./client.json VLYNESS_SOCKS_BIND=127.0.0.1:1080 vlyness-client
```

Увидишь `[tunnel] установлен через 'vps-datagram-h3'`. Дальше — обычный SOCKS5 на
`127.0.0.1:1080`:
- **curl**: `curl --socks5-hostname 127.0.0.1:1080 https://example.com`
- **Firefox**: Настройки → Сеть → Прокси → SOCKS5 `127.0.0.1:1080`, «Проксировать DNS».

Blackhole-детектор (тишина при тихом дропе) включается `VLYNESS_REFERENCE=1.1.1.1:443`.

## 7. Проверка

```bash
# TCP через туннель
curl --socks5-hostname 127.0.0.1:1080 -sS https://example.com | head
# UDP/QUIC работает тоже — например DNS через прокси (SOCKS5 UDP ASSOCIATE)
```

## 8. Эксплуатация и оговорки

- **Обновление серта** перезапускает сервис (хук из шага 2) — иначе сервер продолжит
  отдавать старый сертификат.
- **UDP обязателен** для datagram-режима. Если сеть клиента режет QUIC/UDP — сгенерируй
  конфиг `--mode both`: клиент получит пул (datagram + stream) и переключится на TCP-режим
  автоматически при недоступности QUIC.
- **IPv6-only VPS**: в `server.toml` поставь `bind`/`quic` = `[::]:443`.
- **Один домен — одна легенда.** Не крути поля профиля вручную; согласованность проверяет
  валидатор при старте клиента. Профиль генерируется когерентным.
- Это Direct-развёртывание (свой домен на своём IP). Проход сквозь **белые списки**
  требует co-tenancy за общим CDN + ECH — отдельный путь, см.
  [05-whitelist-traversal.md](05-whitelist-traversal.md).
- Никаких утверждений «гарантированно необнаружим»: результат — сдвиг стоимости детекта
  на дату замера (док 04 §4).
