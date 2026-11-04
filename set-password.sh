#!/bin/sh
# Generate a fresh passphrase (or pass --stdin to choose your own).
# A running container picks up the new hash automatically and revokes all sessions.
set -e
cd "$(dirname "$0")"
[ -f .env ] || cp .env.example .env
mkdir -p secrets certs && chmod 700 secrets
SHARE_DIR=$(sed -n 's/^SHARE_DIR=//p' .env); [ -n "$SHARE_DIR" ] && mkdir -p "$SHARE_DIR"
docker compose build -q
docker compose run --rm --no-deps -T -v "$PWD/secrets:/out" --entrypoint python tresorry /app/setpw.py "$@"
