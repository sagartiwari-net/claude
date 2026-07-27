#!/bin/bash
# Deploy Claude admin panel — run inside /www/wwwroot/1clkaccess.store/cldup
set -euo pipefail

DIR="/www/wwwroot/1clkaccess.store/cldup"
SERVICE="claude-cldup"
BIN="ahrefs-admin"

cd "$DIR"
echo "=== Claude admin panel deploy ($DIR) ==="

if [[ ! -f config.json ]]; then
  if [[ -f config.json.example ]]; then
    cp config.json.example config.json
    echo "Created config.json from example — set mysql_password then re-run"
    exit 1
  fi
  echo "ERROR: config.json missing"
  exit 1
fi

echo "Building $BIN ..."
go build -buildvcs=false -ldflags="-s -w" -o "$BIN" .
chmod +x "$BIN"

cp "$DIR/claude-cldup.service" /etc/systemd/system/claude-cldup.service
systemctl daemon-reload
systemctl enable "$SERVICE"
systemctl restart "$SERVICE"
sleep 2

systemctl is-active "$SERVICE" && echo "OK: $SERVICE active"
curl -sI http://127.0.0.1:7844/ | head -3 || true
echo "Panel: https://cldup.1clkaccess.store"
echo "Login: admin / toolsmandi_admin_xyz123  (change after first login)"
