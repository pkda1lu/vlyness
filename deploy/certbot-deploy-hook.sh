#!/bin/sh
# Хук certbot: перезапустить VLYNESS после обновления сертификата.
# Сервер читает PEM при старте, поэтому без рестарта отдавал бы старый сертификат.
# Установка: install -m 0755 этот файл в /etc/letsencrypt/renewal-hooks/deploy/vlyness.sh
set -e
systemctl restart vlyness-server
