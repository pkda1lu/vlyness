#!/usr/bin/env bash
# VLYNESS — удаление сервера. По умолчанию оставляет /etc/vlyness и пользователя;
# --purge удаляет и их.
#   sudo bash install/server/uninstall.sh [--purge]
set -euo pipefail
[ "$(id -u)" -eq 0 ] || { echo "запусти под root" >&2; exit 1; }
PURGE="no"; [ "${1:-}" = "--purge" ] && PURGE="yes"

echo "[uninstall] останавливаю сервис"
systemctl disable --now vlyness-server 2>/dev/null || true
rm -f /etc/systemd/system/vlyness-server.service
systemctl daemon-reload 2>/dev/null || true

rm -f /usr/local/bin/vlyness-server /usr/local/bin/vlyness-setup
rm -f /etc/letsencrypt/renewal-hooks/deploy/vlyness.sh

if [ "$PURGE" = "yes" ]; then
  echo "[uninstall] --purge: удаляю /etc/vlyness, бандл и пользователя"
  rm -rf /etc/vlyness /root/vlyness-client-bundle
  userdel vlyness 2>/dev/null || true
else
  echo "[uninstall] конфиг /etc/vlyness и пользователь vlyness оставлены (--purge чтобы удалить)"
fi
echo "[uninstall] готово. Сертификаты Let's Encrypt не тронуты."
