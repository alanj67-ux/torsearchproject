#!/bin/sh

set -e

tor &

echo "Waiting for Tor on 127.0.0.1:9050..."

until python - <<'PY'
import socket

sock = socket.socket()
sock.settimeout(1)

try:
    sock.connect(("127.0.0.1", 9050))
except Exception:
    raise SystemExit(1)
finally:
    sock.close()
PY
do
    sleep 1
done

echo "Tor is running."

exec gunicorn \
    --bind "0.0.0.0:${PORT:-10000}" \
    --workers 1 \
    --threads 4 \
    --timeout 60 \
    app:app
