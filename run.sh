#!/usr/bin/env bash
set -e
cd "$(dirname "$0")"

echo "=== Starting AmarDNS (DoH: 443, DoT: 853) ==="
if [ "$EUID" -ne 0 ]; then
  echo "Elevating permissions to bind to privileged ports 443 & 853..."
  exec sudo node --env-file=.env src/server.js
else
  exec node --env-file=.env src/server.js
fi
