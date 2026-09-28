#!/bin/sh

set -e

tor &

echo "Waiting for Tor on 127.0.0.1:9050..."

until python - <<'PY'
import socket

s = socket.socket()
s.settimeout(1)

try:
    s.connect(("127.0.0.1", 9050))
except Exception:
    raise SystemExit(1)
finally:
    s.close()
PY
do
    sleep 1
done

echo "Tor SOCKS proxy is running."

exec gunicorn \
    --bind "0.0.0.0:${PORT:-10000}" \
    --workers 1 \
    --threads 8 \
    --timeout 120 \
    app:app
