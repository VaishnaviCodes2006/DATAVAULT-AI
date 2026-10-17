#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
[ -d .venv ] || python3 -m venv .venv
. .venv/bin/activate
pip install --quiet -r requirements.txt
[ -f .env ] || python scripts/gen_keys.py
set -a; . ./.env; set +a
HOST="${DATAVAULT_HOST:-127.0.0.1}"; PORT="${DATAVAULT_PORT:-8443}"
if [ -f certs/server.key ] && [ -f certs/server.crt ]; then
  exec uvicorn api:create_app --factory --host "$HOST" --port "$PORT" \
       --ssl-keyfile certs/server.key --ssl-certfile certs/server.crt
else
  echo "WARNING: no TLS certs in ./certs - serving plain HTTP on $HOST only. Put a TLS proxy in front for anything beyond local use." >&2
  exec uvicorn api:create_app --factory --host "$HOST" --port "$PORT"
fi
