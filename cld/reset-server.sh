#!/bin/bash
# Reset / rebuild Claude proxy on server — run inside /www/wwwroot/1clkaccess.store/cld
set -euo pipefail

DIR="/www/wwwroot/1clkaccess.store/cld"
PORT="8802"
BIN="claude-ai-go-proxy"
SERVICE="claude-cld"

cd "$DIR"
echo "=== Claude proxy reset ($DIR | port $PORT) ==="

systemctl stop "$SERVICE" 2>/dev/null || true
fuser -k "${PORT}/tcp" 2>/dev/null || true
sleep 1

echo "0" > cooldown.txt
chmod 644 cooldown.txt 2>/dev/null || true

if [[ ! -f config.json ]]; then
  if [[ -f config.json.example ]]; then
    cp config.json.example config.json
    echo "Created config.json from example — set mysql_password then re-run"
    exit 1
  fi
  echo "ERROR: config.json missing"
  exit 1
fi

# Ensure proxy-security is available (sibling of cld when deployed from monorepo layout)
if [[ ! -d ../proxy-security ]] && [[ -d /www/wwwroot/1clkaccess.store/claude-src/proxy-security ]]; then
  ln -sfn /www/wwwroot/1clkaccess.store/claude-src/proxy-security ../proxy-security 2>/dev/null || true
fi

if command -v go &>/dev/null; then
  echo "Building $BIN ..."
  go build -buildvcs=false -ldflags="-s -w" -o "$BIN" .
  chmod +x "$BIN"
else
  echo "ERROR: Go not installed and no prebuilt binary."
  exit 1
fi

cp "$DIR/claude-cld.service" /etc/systemd/system/claude-cld.service
systemctl daemon-reload
systemctl enable "$SERVICE"
systemctl restart "$SERVICE"
sleep 2

systemctl status "$SERVICE" --no-pager | head -12
curl -s -o /dev/null -w "localhost:${PORT}/new → HTTP %{http_code}\n" \
  "http://127.0.0.1:${PORT}/new" \
  -H "User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36" || true

echo "Logs: journalctl -u $SERVICE -f"
echo "Site: https://cld.1clkaccess.store/new"
