#!/bin/sh
set -e
if [ ! -s /certs/cert.pem ] || [ ! -s /certs/key.pem ]; then
  python /app/gencert.py
fi
if [ ! -s "$PASSWORD_HASH_FILE" ]; then
  echo "[tresorry] no passphrase set. Run ./set-password.sh on the host first." >&2
  exit 1
fi
exec gunicorn -c /app/gunicorn.conf.py --chdir /app app:app
