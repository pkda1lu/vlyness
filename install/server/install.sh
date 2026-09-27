#!/usr/bin/env bash
# VLYNESS — простой установщик сервера под Ubuntu/Debian (для проверки).
#
# Собирает бинарники из исходников, ставит их в /usr/local/bin, создаёт
# системного пользователя vlyness, генерирует конфиг через vlyness-setup,
# ставит и запускает systemd-юнит, открывает firewall и складывает бандл
# клиента (client.json) для переноса на Windows-машину.
#
# Использование (из корня репозитория или откуда угодно):
#   sudo bash install/server/install.sh --domain rtc.example.tld [опции]
#
# Опции:
#   --domain D        домен легенды (обязателен; сертификат и SNI на него)
#   --mode M          datagram | stream | both        (по умолчанию datagram)
#   --port N          порт входа (TCP+UDP)            (по умолчанию 443)
#   --self-signed     самоподписанный серт вместо Let's Encrypt (быстрая проверка;
#                     клиент получит vlyness-cert.pem в бандле)
#   --email E         e-mail для регистрации Let's Encrypt (иначе --register-unsafely)
#   --no-firewall     не трогать ufw
#   --no-build        не собирать (бинарники уже в /usr/local/bin)
#   -h | --help       помощь
set -euo pipefail

DOMAIN=""
MODE="datagram"
PORT="443"
SELF_SIGNED="no"
EMAIL=""
DO_FIREWALL="yes"
DO_BUILD="yes"

die() { echo "[install] ОШИБКА: $*" >&2; exit 1; }
info() { echo "[install] $*"; }

while [ $# -gt 0 ]; do
  case "$1" in
    --domain) DOMAIN="${2:-}"; shift 2;;
    --mode) MODE="${2:-}"; shift 2;;
    --port) PORT="${2:-}"; shift 2;;
    --self-signed) SELF_SIGNED="yes"; shift;;
    --email) EMAIL="${2:-}"; shift 2;;
    --no-firewall) DO_FIREWALL="no"; shift;;
    --no-build) DO_BUILD="no"; shift;;
    -h|--help) sed -n '2,26p' "$0"; exit 0;;
    *) die "неизвестный аргумент: $1 (см. --help)";;
  esac
done

[ "$(id -u)" -eq 0 ] || die "запусти под root (sudo)"
[ -n "$DOMAIN" ] || die "нужен --domain"
case "$MODE" in datagram|stream|both) ;; *) die "--mode должен быть datagram|stream|both";; esac

# Корень репозитория: два уровня вверх от этого скрипта.
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
[ -f "$REPO_DIR/Cargo.toml" ] || die "не нашёл Cargo.toml в $REPO_DIR"

ETC_DIR="/etc/vlyness"
BIN_DIR="/usr/local/bin"
BUNDLE_DIR="/root/vlyness-client-bundle"
UNIT_SRC="$REPO_DIR/deploy/vlyness-server.service"

# --- 1. зависимости ---
info "ставлю системные зависимости (apt)"
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq build-essential cmake pkg-config perl curl ca-certificates openssl >/dev/null
if [ "$SELF_SIGNED" = "no" ]; then
  # acl — чтобы дать vlyness право читать privkey Let's Encrypt через setfacl.
  apt-get install -y -qq certbot acl >/dev/null || die "не удалось поставить certbot/acl (или используй --self-signed)"
fi

# --- 2. Rust ---
if ! command -v cargo >/dev/null 2>&1; then
  if [ -x "$HOME/.cargo/bin/cargo" ]; then
    export PATH="$HOME/.cargo/bin:$PATH"
  else
    info "ставлю Rust (rustup)"
    curl -fsSL https://sh.rustup.rs | sh -s -- -y --profile minimal
    export PATH="$HOME/.cargo/bin:$PATH"
  fi
fi

# --- 3. сборка и установка бинарников ---
if [ "$DO_BUILD" = "yes" ]; then
  info "собираю release (может занять несколько минут)"
  ( cd "$REPO_DIR" && cargo build --release -p vlyness-cli )
  install -m 0755 "$REPO_DIR/target/release/vlyness-server" "$BIN_DIR/vlyness-server"
  install -m 0755 "$REPO_DIR/target/release/vlyness-setup" "$BIN_DIR/vlyness-setup"
  info "бинарники: $BIN_DIR/vlyness-server, $BIN_DIR/vlyness-setup"
else
  command -v vlyness-server >/dev/null || die "--no-build, но vlyness-server не найден"
fi

# --- 4. пользователь и каталоги ---
if ! id vlyness >/dev/null 2>&1; then
  info "создаю системного пользователя vlyness"
  useradd --system --no-create-home --shell /usr/sbin/nologin vlyness
fi
mkdir -p "$ETC_DIR"

# --- 5. сертификат ---
CERT_DIR=""
if [ "$SELF_SIGNED" = "yes" ]; then
  # Для IP-адреса SAN должен быть IP:, иначе клиент (проверка по IP SAN) не примет серт.
  if [[ "$DOMAIN" =~ ^[0-9.]+$ || "$DOMAIN" == *:* ]]; then SAN="IP:$DOMAIN"; else SAN="DNS:$DOMAIN"; fi
  info "генерирую самоподписанный сертификат для $DOMAIN ($SAN)"
  # CA:FALSE обязательно: rustls отвергает CA-сертификат в роли листового
  # (openssl -x509 по умолчанию ставит CA:TRUE) — ошибка CaUsedAsEndEntity.
  openssl req -x509 -newkey rsa:2048 -sha256 -days 825 -nodes \
    -keyout "$ETC_DIR/privkey.pem" -out "$ETC_DIR/fullchain.pem" \
    -subj "/CN=$DOMAIN" -addext "subjectAltName=$SAN" \
    -addext "basicConstraints=critical,CA:FALSE" >/dev/null 2>&1
  CERT_DIR="$ETC_DIR"
else
  if [ ! -f "/etc/letsencrypt/live/$DOMAIN/fullchain.pem" ]; then
    info "получаю сертификат Let's Encrypt (certbot --standalone) для $DOMAIN"
    # ACME HTTP-01 идёт на порт 80 — откроем его в ufw ДО запуска (иначе challenge режется).
    if [ "$DO_FIREWALL" = "yes" ] && command -v ufw >/dev/null 2>&1; then
      ufw allow 80/tcp >/dev/null 2>&1 || true
    fi
    if [ -n "$EMAIL" ]; then
      certbot certonly --standalone --non-interactive --agree-tos -m "$EMAIL" -d "$DOMAIN" \
        || die "certbot не смог выпустить серт для $DOMAIN (проверь, что домен указывает на этот VPS и порт 80 свободен), либо ставь с --self-signed"
    else
      certbot certonly --standalone --non-interactive --agree-tos --register-unsafely-without-email -d "$DOMAIN" \
        || die "certbot не смог выпустить серт для $DOMAIN (домен должен резолвиться на этот VPS, порт 80 свободен), либо --self-signed"
    fi
  else
    info "сертификат Let's Encrypt для $DOMAIN уже есть"
  fi
  CERT_DIR="/etc/letsencrypt/live/$DOMAIN"
  # Дать пользователю vlyness право читать privkey (LE кладёт 600 root).
  if command -v setfacl >/dev/null 2>&1; then
    setfacl -R -m u:vlyness:rX /etc/letsencrypt/live /etc/letsencrypt/archive || true
  else
    chgrp -R vlyness /etc/letsencrypt/live /etc/letsencrypt/archive || true
    chmod -R g+rX /etc/letsencrypt/live /etc/letsencrypt/archive || true
  fi
  # Хук перевыпуска: рестарт сервера при обновлении серта.
  install -D -m 0755 "$REPO_DIR/deploy/certbot-deploy-hook.sh" \
    /etc/letsencrypt/renewal-hooks/deploy/vlyness.sh
fi

# --- 6. конфиг через vlyness-setup ---
info "генерирую конфиг (mode=$MODE, port=$PORT)"
SETUP="$BIN_DIR/vlyness-setup"
command -v "$SETUP" >/dev/null || SETUP="vlyness-setup"
if [ "$SELF_SIGNED" = "yes" ]; then
  # ca_pem_path в client.json — placeholder; Windows-установщик его перепишет на
  # локальный путь к vlyness-cert.pem.
  "$SETUP" --domain "$DOMAIN" --port "$PORT" --mode "$MODE" \
    --self-signed --client-ca "vlyness-cert.pem" --out-dir "$ETC_DIR"
  # setup при self-signed не пишет cert_pem/key_pem — добавим наш openssl-серт.
  {
    echo "cert_pem = \"$CERT_DIR/fullchain.pem\""
    echo "key_pem = \"$CERT_DIR/privkey.pem\""
  } >> "$ETC_DIR/server.toml"
else
  "$SETUP" --domain "$DOMAIN" --port "$PORT" --mode "$MODE" \
    --cert-dir "$CERT_DIR" --out-dir "$ETC_DIR"
fi

chown -R root:vlyness "$ETC_DIR"
chmod 750 "$ETC_DIR"
chmod 640 "$ETC_DIR/server.toml"
[ "$SELF_SIGNED" = "yes" ] && chmod 640 "$ETC_DIR/privkey.pem" || true

# --- 7. systemd ---
info "ставлю systemd-юнит"
install -m 0644 "$UNIT_SRC" /etc/systemd/system/vlyness-server.service
systemctl daemon-reload
systemctl enable vlyness-server >/dev/null 2>&1 || true
systemctl restart vlyness-server
sleep 1
systemctl --no-pager --lines=0 status vlyness-server || true

# --- 8. firewall ---
if [ "$DO_FIREWALL" = "yes" ] && command -v ufw >/dev/null 2>&1; then
  info "открываю порты в ufw ($PORT/tcp, $PORT/udp, 80/tcp для certbot)"
  ufw allow "$PORT/tcp" >/dev/null 2>&1 || true
  ufw allow "$PORT/udp" >/dev/null 2>&1 || true
  ufw allow 80/tcp >/dev/null 2>&1 || true
fi

# --- 9. бандл клиента ---
mkdir -p "$BUNDLE_DIR"
if [ "$MODE" = "both" ]; then
  cp -f "$ETC_DIR"/client-*.json "$BUNDLE_DIR"/
else
  cp -f "$ETC_DIR/client.json" "$BUNDLE_DIR"/
fi
if [ "$SELF_SIGNED" = "yes" ]; then
  cp -f "$CERT_DIR/fullchain.pem" "$BUNDLE_DIR/vlyness-cert.pem"
fi

echo
info "ГОТОВО."
info "  сервис : systemctl status vlyness-server   (логи: journalctl -u vlyness-server -f)"
info "  конфиг : $ETC_DIR/server.toml"
info "  бандл клиента: $BUNDLE_DIR/  (скопируй на Windows-машину)"
echo
info "Веб-панель слушает 127.0.0.1:8088 (только loopback — не на 443)."
info "Доступ с твоей машины — по SSH-туннелю, затем http://127.0.0.1:8088/ :"
info "  ssh -L 8088:127.0.0.1:8088 <user>@<этот-vps>"
# --- готовая команда установки Windows-клиента ---
CLIENT_JSON="client.json"; [ "$MODE" = "both" ] && CLIENT_JSON="client-datagram.json"
CERT_ARG=""; [ "$SELF_SIGNED" = "yes" ] && CERT_ARG=" -Cert .\\vlyness-cert.pem"
echo
info "=== Windows-клиент (скопируй и выполни на своей машине) ==="
info "1) забери бандл с VPS в папку с репозиторием vlyness (PowerShell/термин на Windows):"
info "     scp root@$DOMAIN:$BUNDLE_DIR/* ."
info "2) поставь клиента одной строкой из папки репозитория (PowerShell):"
info "     powershell -ExecutionPolicy Bypass -File install\\client\\install.ps1 -ProfilePath .\\$CLIENT_JSON$CERT_ARG -Shortcut"
info "   (оконный GUI: добавь -Gui; при первом разе сначала: cargo build --release -p vlyness-gui)"
info "   сервер-эндпоинт зашит в профиль → $DOMAIN:$PORT (режим $MODE)"
