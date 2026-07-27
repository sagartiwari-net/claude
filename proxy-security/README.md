# ToolsMandi proxy-security

Shared Go library for anti-sharing security layers across all tool proxies.

**Server path:** `/www/wwwroot/toolsmandi.com/proxy-security`  
**Module:** `toolsmandi.com/proxy-security`

## Contents

| File | Purpose |
|------|---------|
| `config.go` | `session_security` types, normalize, enabled check |
| `ip.go` | RealClientIP, soft IP, concurrent /16 tracker |
| `host.go` | Host mismatch detection |
| `ott.go` | OTT IP validation (soft /16) |
| `headers.go` | X-Frame, CSP, domain-check JS |
| `cloudflare.go` | CF-Ray requirement |
| `score.go` | Free ASN scoring + optional paid Anonymous IP MMDB |
| `log.go` | Security event types + URL sanitization |
| `account_ip.go` | Account cookie /16 concurrent tracker (anti-recloud) |
| `data/hosting_asns.json` | Default hosting ASN list (free tier) |

## Usage in a proxy

```go
import proxysec "toolsmandi.com/proxy-security"

tool := proxysec.ToolContext{
    PublicHost:   cfg.PublicHost,
    PublicScheme: cfg.PublicScheme,
    MemberAreaURL: cfg.MemberAreaURL,
    BypassSecurity: usesCookieFileMode(cfg),
}
dbToggle := currentWebsiteSecurityEnabled
ss := proxysec.Normalize(cfg.SessionSecurity, tool)

if proxysec.Enabled(ss, tool, dbToggle) { ... }
```

## go.mod replace (local monorepo)

```
replace toolsmandi.com/proxy-security => ../../toolsmandi.com/proxy-security
```

## Shared geo data (all tools)

```
/opt/geoip/GeoLite2-ASN.mmdb
/opt/geoip/hosting_asns.json
```

See `security.md` — especially Sections 22, 27 (new tool playbook), 28 (deploy), 29 (SQL).
