#!/usr/bin/env bash
# VLYNESS — установщик «в одну строку» (как у 3x-ui).
#
# На чистом Ubuntu/Debian VPS выполни ОДНУ команду под root:
#
#   bash <(curl -fsSL https://raw.githubusercontent.com/pkda1lu/vlyness/main/install/vps.sh)
#
# Без домена — поднимет сервер с самоподписанным сертом на публичном IP (быстрая проверка).
# С доменом (Let's Encrypt) — добавь аргументы:
#
#   bash <(curl -fsSL .../install/vps.sh) --domain rtc.example.tld --email you@example.com
#
# Всё остальное (зависимости, Rust, сборка, systemd, firewall, конфиг, панель, бандл
# клиента) ставится само. Аргументы форвардятся в install/server/install.sh.
#
# Переменные окружения (необязательно):
#   VLYNESS_REPO    репозиторий (по умолчанию github.com/pkda1lu/vlyness)
#   VLYNESS_BRANCH  ветка (по умолчанию main)
#   VLYNESS_DIR     куда клонировать (по умолчанию /opt/vlyness)
set -euo pipefail

REPO="${VLYNESS_REPO:-https://github.com/pkda1lu/vlyness.git}"
BRANCH="${VLYNESS_BRANCH:-main}"
DEST="${VLYNESS_DIR:-/opt/vlyness}"

die() { echo "[vlyness] ОШИБКА: $*" >&2; exit 1; }
info() { echo "[vlyness] $*"; }

[ "$(id -u)" -eq 0 ] || die "запусти под root (sudo -i, затем команду)"
command -v apt-get >/dev/null 2>&1 || die "поддержаны только Debian/Ubuntu (apt)"

info "ставлю git/curl…"
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq git curl ca-certificates >/dev/null

# --- получить исходники ---
if [ -d "$DEST/.git" ]; then
  info "обновляю $DEST"
  git -C "$DEST" fetch --depth 1 origin "$BRANCH" -q
  git -C "$DEST" reset --hard "origin/$BRANCH" -q
else
  info "клонирую $REPO → $DEST"
  git clone --depth 1 -b "$BRANCH" "$REPO" "$DEST" -q
fi

# --- решить: домен (Let's Encrypt) или IP (самоподпись) ---
has_domain="no"
for a in "$@"; do [ "$a" = "--domain" ] && has_domain="yes"; done

ARGS=("$@")
if [ "$has_domain" = "no" ]; then
  info "домен не задан — определяю публичный IP"
  IP="$(curl -fsSL --max-time 8 https://api.ipify.org 2>/dev/null || true)"
  [ -n "$IP" ] || IP="$(curl -fsSL --max-time 8 https://ifconfig.me 2>/dev/null || true)"
  [ -n "$IP" ] || IP="$(hostname -I 2>/dev/null | awk '{print $1}')"
  [ -n "$IP" ] || die "не удалось определить IP; задай домен: … --domain rtc.example.tld"
  info "ставлю с самоподписанным сертом на IP $IP (для домена используй --domain <имя> --email <почта>)"
  ARGS+=(--domain "$IP" --self-signed)
fi

info "запускаю установщик сервера…"
bash "$DEST/install/server/install.sh" "${ARGS[@]}"
