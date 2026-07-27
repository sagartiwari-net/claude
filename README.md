# Claude-only stack (cld + cldup)

Go reverse proxy for **claude.ai** plus a **separate** admin/update panel, with a Claude-only MySQL schema.

| Role | Domain | Server path | Port |
|------|--------|-------------|------|
| Proxy | `cld.1clkaccess.store` | `/www/wwwroot/1clkaccess.store/cld` | `8802` |
| Admin panel | `cldup.1clkaccess.store` | `/www/wwwroot/1clkaccess.store/cldup` | `7844` |
| MySQL | — | DB `claude_1clk` | — |

Repo: https://github.com/sagartiwari-net/claude

## Layout

```
cld/              Claude Go proxy
cldup/            Admin panel (accounts, security, websites)
proxy-security/   Shared security library (go replace)
sql/schema.sql    Full Claude-only DB schema + seed
setup-server.sh   One-shot server deploy
```

## Server setup

### 1. Prerequisites

- Go 1.22+
- MySQL / MariaDB
- Nginx (aaPanel OK)
- DNS A records for `cld.1clkaccess.store` and `cldup.1clkaccess.store`

### 2. MySQL user

```sql
CREATE DATABASE IF NOT EXISTS claude_1clk CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci;
CREATE USER 'claude_1clk'@'localhost' IDENTIFIED BY 'YOUR_STRONG_PASSWORD';
GRANT ALL PRIVILEGES ON claude_1clk.* TO 'claude_1clk'@'localhost';
FLUSH PRIVILEGES;
```

### 3. Clone + deploy

```bash
git clone https://github.com/sagartiwari-net/claude.git /www/wwwroot/1clkaccess.store/claude-src
cd /www/wwwroot/1clkaccess.store/claude-src
export MYSQL_PASS='YOUR_STRONG_PASSWORD'
./setup-server.sh
```

This will:

- Sync `proxy-security`, `cld`, `cldup` into `/www/wwwroot/1clkaccess.store/`
- Import `sql/schema.sql` (Claude tool + website `cld.1clkaccess.store` + admin user)
- Build binaries and enable systemd units `claude-cld` / `claude-cldup`

### 4. aaPanel Nginx

For each site, reverse proxy:

- `cld` → `http://127.0.0.1:8802` (WebSocket headers recommended — see `cld/nginx-cld.conf`)
- `cldup` → `http://127.0.0.1:7844` (see `cldup/nginx-cldup.conf`)

Enable SSL (Let's Encrypt).

### 5. First login

- Panel: https://cldup.1clkaccess.store  
- User: `admin`  
- Password: `toolsmandi_admin_xyz123` — **change immediately**
- Add Claude account cookie under Accounts (website: ToolsMandi Claude)
- aMember handshake: domain `cld.1clkaccess.store`, secret `toolsmandi_claude_secret_xyz123`

### 6. Updates later

```bash
cd /www/wwwroot/1clkaccess.store/claude-src
git pull origin main
./setup-server.sh   # or only cld/reset-server.sh / cldup/reset-server.sh
```

## Local build check (Mac)

```bash
cd cld && go build -o /tmp/claude-ai-go-proxy .
cd ../cldup && go build -o /tmp/ahrefs-admin .
```

## Seed data

`sql/schema.sql` creates all panel/proxy tables and seeds:

- Tool: Claude (id=1)
- Website: `cld.1clkaccess.store` (id=1), secret `toolsmandi_claude_secret_xyz123`
- Reseller: `admin` (master)

No live cookies or old multi-tool data are included.
