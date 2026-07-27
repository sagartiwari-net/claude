#!/bin/bash
# One-shot server setup for Claude-only stack (cld + cldup).
# Run as root on the new server AFTER:
#   1) DNS: cld.1clkaccess.store + cldup.1clkaccess.store → this server
#   2) aaPanel sites created (paths below)
#   3) MySQL user/password ready
#   4) This repo cloned to SRC
#
# Usage:
#   git clone https://github.com/sagartiwari-net/claude.git /www/wwwroot/1clkaccess.store/claude-src
#   cd /www/wwwroot/1clkaccess.store/claude-src
#   export MYSQL_PASS='your-password'
#   ./setup-server.sh
set -euo pipefail

SRC="$(cd "$(dirname "$0")" && pwd)"
BASE="/www/wwwroot/1clkaccess.store"
CLD="$BASE/cld"
CLDUP="$BASE/cldup"
PROXY_SEC="$BASE/proxy-security"
MYSQL_USER="${MYSQL_USER:-claude_1clk}"
MYSQL_DB="${MYSQL_DB:-claude_1clk}"
MYSQL_PASS="${MYSQL_PASS:-}"

echo "=== Claude stack setup ==="
echo "SRC=$SRC"
echo "CLD=$CLD  CLDUP=$CLDUP"

command -v go >/dev/null || { echo "ERROR: install Go first"; exit 1; }
command -v mysql >/dev/null || { echo "ERROR: mysql client missing"; exit 1; }

mkdir -p "$CLD" "$CLDUP"

echo "=== Sync proxy-security ==="
rm -rf "$PROXY_SEC"
cp -a "$SRC/proxy-security" "$PROXY_SEC"

echo "=== Sync cld (proxy) ==="
rsync -a --delete \
  --exclude 'claude-ai-go-proxy' \
  --exclude 'cookie.txt' \
  --exclude 'config.json' \
  "$SRC/cld/" "$CLD/"
# Keep existing config.json if present; else from example
if [[ ! -f "$CLD/config.json" ]]; then
  cp "$CLD/config.json.example" "$CLD/config.json"
fi
echo "0" > "$CLD/cooldown.txt"

echo "=== Sync cldup (admin panel) ==="
rsync -a --delete \
  --exclude 'ahrefs-admin' \
  --exclude 'config.json' \
  "$SRC/cldup/" "$CLDUP/"
if [[ ! -f "$CLDUP/config.json" ]]; then
  cp "$CLDUP/config.json.example" "$CLDUP/config.json"
fi

if [[ -n "$MYSQL_PASS" ]]; then
  echo "=== Patch MySQL password into configs ==="
  python3 - <<PY
import json
for path in ["$CLD/config.json", "$CLDUP/config.json"]:
    with open(path) as f:
        c = json.load(f)
    c["mysql_user"] = "$MYSQL_USER"
    c["mysql_password"] = "$MYSQL_PASS"
    c["mysql_db"] = "$MYSQL_DB"
    with open(path, "w") as f:
        json.dump(c, f, indent=2)
        f.write("\n")
    print("updated", path)
PY

  echo "=== Import sql/schema.sql (Claude-only) ==="
  mysql -u"$MYSQL_USER" -p"$MYSQL_PASS" < "$SRC/sql/schema.sql" || {
    echo "Import failed — create MySQL user/db first, then re-run with MYSQL_PASS set"
    echo "  CREATE USER '$MYSQL_USER'@'localhost' IDENTIFIED BY '...';"
    echo "  CREATE DATABASE $MYSQL_DB;"
    echo "  GRANT ALL ON $MYSQL_DB.* TO '$MYSQL_USER'@'localhost';"
    exit 1
  }
  echo "Schema imported OK"
else
  echo "WARN: MYSQL_PASS not set — skip DB import. Set passwords in:"
  echo "  $CLD/config.json"
  echo "  $CLDUP/config.json"
  echo "Then: mysql -u$USER -p < $SRC/sql/schema.sql"
fi

chmod +x "$CLD/reset-server.sh" "$CLDUP/reset-server.sh"

echo "=== Build & start proxy ==="
"$CLD/reset-server.sh"

echo "=== Build & start admin panel ==="
"$CLDUP/reset-server.sh"

echo ""
echo "=== Done ==="
echo "Proxy:  https://cld.1clkaccess.store/new   → 127.0.0.1:8802"
echo "Panel:  https://cldup.1clkaccess.store     → 127.0.0.1:7844"
echo "Login:  admin / toolsmandi_admin_xyz123"
echo ""
echo "aaPanel: add reverse proxy for both sites (see cld/nginx-cld.conf and cldup/nginx-cldup.conf)"
echo "Then add Claude cookie in panel → Accounts"
