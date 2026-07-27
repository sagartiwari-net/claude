package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	proxysec "toolsmandi.com/proxy-security"
)

const proxyBuildTag = "claude-v23-screen"

var (
	dbConnected                   bool = false
	currentWebsiteSecurityEnabled bool = true
)

type ToolAccount struct {
	ID                int
	Name              string
	Cookie            string
	UserAgent         string
	Proxy             string
	ShowLimit         bool
	AutomationTaskUID string
}

func cookieFilePath(cfg Config) string {
	if cfg.CookieFile != "" {
		return cfg.CookieFile
	}
	if cfg.CookiePath != "" {
		return cfg.CookiePath
	}
	return "cookie.txt"
}

func isLocalDev(cfg Config) bool {
	host := strings.ToLower(strings.Split(cfg.PublicHost, ":")[0])
	return strings.HasPrefix(host, "localhost") || strings.HasPrefix(host, "127.0.0.1")
}

func usesCookieFileMode(cfg Config) bool {
	return cfg.BypassAuth || cfg.LocalTestMode || !cfg.UseDatabase || !dbConnected || isLocalDev(cfg)
}

func cookieSecure(r *http.Request, cfg Config) bool {
	if r.TLS != nil {
		return true
	}
	if strings.Contains(strings.ToLower(r.Header.Get("X-Forwarded-Proto")), "https") {
		return true
	}
	if r.Header.Get("X-Forwarded-Ssl") == "on" {
		return true
	}
	return strings.EqualFold(cfg.PublicScheme, "https")
}

func requestScheme(r *http.Request, cfg Config) string {
	if cookieSecure(r, cfg) {
		return "https"
	}
	if cfg.PublicScheme != "" {
		return cfg.PublicScheme
	}
	return "http"
}

func refreshWebsiteSecurityFromDB() {
	if !dbConnected {
		currentWebsiteSecurityEnabled = true
		return
	}
	var enabled int
	err := db.QueryRow(
		"SELECT COALESCE(session_security_enabled, 1) FROM ahrefs_websites WHERE id = ?",
		currentWebsiteID,
	).Scan(&enabled)
	if err != nil {
		currentWebsiteSecurityEnabled = true
		return
	}
	currentWebsiteSecurityEnabled = enabled == 1
}

func initDB(cfg Config) {
	if !cfg.UseDatabase {
		log.Printf("[DB] use_database=false — skipping MySQL")
		dbConnected = false
		return
	}
	dsn := fmt.Sprintf("%s:%s@tcp(%s:%s)/%s?parseTime=true&loc=Asia%%2FKolkata",
		cfg.MySQLUser, cfg.MySQLPassword, cfg.MySQLHost, cfg.MySQLPort, cfg.MySQLDB)
	var err error
	db, err = sql.Open("mysql", dsn)
	if err != nil {
		log.Fatalf("[DB] Failed to open database pool: %v", err)
	}
	db.SetMaxOpenConns(25)
	db.SetMaxIdleConns(5)
	db.SetConnMaxLifetime(5 * time.Minute)
	if err := db.Ping(); err != nil {
		log.Printf("[DB] ⚠️ Database not reachable: %v — falling back to cookie file", err)
		dbConnected = false
		return
	}
	dbConnected = true
	log.Printf("[DB] Connected to MySQL successfully! Database: %s ✅", cfg.MySQLDB)
	_, _ = db.Exec("ALTER TABLE ahrefs_sessions ADD COLUMN device_token VARCHAR(64) DEFAULT ''")
	_, _ = db.Exec("ALTER TABLE ahrefs_accounts ADD COLUMN automation_task_uid VARCHAR(255) DEFAULT ''")
	_, _ = db.Exec("ALTER TABLE ahrefs_websites ADD COLUMN session_security_enabled TINYINT(1) DEFAULT 1")
	resolveWebsiteID(cfg.PublicHost)
	refreshWebsiteSecurityFromDB()
	refreshBlockedIPsFromDB()
}

const accountSelectCols = "id, name, cookie, user_agent, proxy, show_limit, COALESCE(automation_task_uid, '')"

func scanToolAccount(row interface{ Scan(...interface{}) error }) (ToolAccount, error) {
	var acc ToolAccount
	var showLimitVal int
	err := row.Scan(&acc.ID, &acc.Name, &acc.Cookie, &acc.UserAgent, &acc.Proxy, &showLimitVal, &acc.AutomationTaskUID)
	if err != nil {
		return acc, err
	}
	acc.ShowLimit = showLimitVal == 1
	return acc, nil
}

func selectActiveAccount() (ToolAccount, error) {
	row := db.QueryRow(
		"SELECT "+accountSelectCols+" FROM ahrefs_accounts WHERE website_id = ? AND status = 'active' ORDER BY last_used_at ASC LIMIT 1",
		currentWebsiteID,
	)
	acc, err := scanToolAccount(row)
	if err != nil {
		return acc, err
	}
	_, _ = db.Exec("UPDATE ahrefs_accounts SET last_used_at = CURRENT_TIMESTAMP WHERE id = ?", acc.ID)
	return acc, nil
}

func getSessionAssignedAccount(sessionToken string) (ToolAccount, bool) {
	var assignedAccountID sql.NullInt64
	err := db.QueryRow(
		"SELECT assigned_account_id FROM ahrefs_sessions WHERE session_token = ? AND website_id = ?",
		sessionToken, currentWebsiteID,
	).Scan(&assignedAccountID)
	if err != nil || !assignedAccountID.Valid {
		return ToolAccount{}, false
	}
	row := db.QueryRow(
		"SELECT "+accountSelectCols+" FROM ahrefs_accounts WHERE id = ? AND website_id = ? AND status = 'active'",
		assignedAccountID.Int64, currentWebsiteID,
	)
	acc, err := scanToolAccount(row)
	if err != nil {
		return ToolAccount{}, false
	}
	return acc, true
}

func autoAssignNextAccount(sessionToken string) (ToolAccount, error) {
	acc, err := selectActiveAccount()
	if err != nil {
		return acc, err
	}
	_, _ = db.Exec(
		"UPDATE ahrefs_sessions SET assigned_account_id = ? WHERE session_token = ? AND website_id = ?",
		acc.ID, sessionToken, currentWebsiteID,
	)
	log.Printf("[LB] Assigned account '%s' (ID:%d) to session", acc.Name, acc.ID)
	return acc, nil
}

func switchToNextAccount(sessionToken string, currentAccID int, currentAccName, username, reason string) (ToolAccount, error) {
	log.Printf("[LB] Rotating '%s' (ID:%d) | %s", currentAccName, currentAccID, reason)
	var acc ToolAccount
	var err error
	row := db.QueryRow(
		"SELECT "+accountSelectCols+" FROM ahrefs_accounts WHERE website_id = ? AND status = 'active' AND id > ? ORDER BY id ASC LIMIT 1",
		currentWebsiteID, currentAccID,
	)
	acc, err = scanToolAccount(row)
	if err == sql.ErrNoRows {
		row = db.QueryRow(
			"SELECT "+accountSelectCols+" FROM ahrefs_accounts WHERE website_id = ? AND status = 'active' AND id != ? ORDER BY id ASC LIMIT 1",
			currentWebsiteID, currentAccID,
		)
		acc, err = scanToolAccount(row)
	}
	if err != nil {
		row = db.QueryRow(
			"SELECT "+accountSelectCols+" FROM ahrefs_accounts WHERE website_id = ? AND status = 'active' ORDER BY id ASC LIMIT 1",
			currentWebsiteID,
		)
		acc, err = scanToolAccount(row)
	}
	if err != nil {
		return acc, fmt.Errorf("no active accounts for website_id %d", currentWebsiteID)
	}
	_, _ = db.Exec("UPDATE ahrefs_accounts SET last_used_at = CURRENT_TIMESTAMP WHERE id = ?", acc.ID)
	if sessionToken != "" {
		_, _ = db.Exec(
			"UPDATE ahrefs_sessions SET assigned_account_id = ? WHERE session_token = ? AND website_id = ?",
			acc.ID, sessionToken, currentWebsiteID,
		)
	}
	_, _ = db.Exec(
		"INSERT INTO ahrefs_switch_logs (website_id, session_token, username, from_account_id, from_account_name, to_account_id, to_account_name, reason) VALUES (?,?,?,?,?,?,?,?)",
		currentWebsiteID, sessionToken, username, currentAccID, currentAccName, acc.ID, acc.Name, reason,
	)
	log.Printf("[LB] 🔄 Switched '%s'→'%s' for user '%s'", currentAccName, acc.Name, username)
	return acc, nil
}

func parseCookieFromDB(raw string) string {
	raw = strings.TrimSpace(strings.NewReplacer("\r", "", "\n", "", "\x00", "").Replace(raw))
	if raw == "" || raw == "{}" || raw == "[]" {
		return ""
	}
	if !strings.HasPrefix(raw, "[") {
		return raw
	}
	var cookies []struct {
		Name  string `json:"name"`
		Value string `json:"value"`
	}
	if err := json.Unmarshal([]byte(raw), &cookies); err != nil {
		return raw
	}
	parts := make([]string, 0, len(cookies))
	for _, c := range cookies {
		if c.Name != "" {
			parts = append(parts, c.Name+"="+c.Value)
		}
	}
	return strings.Join(parts, "; ")
}

func stripSensitiveCookies(cookieHeader string, cfg Config) string {
	if cookieHeader == "" {
		return ""
	}
	sensitiveSet := map[string]bool{"ct_session": true}
	for _, n := range cfg.SensitiveCookies {
		sensitiveSet[strings.ToLower(n)] = true
	}
	var kept []string
	for _, part := range strings.Split(cookieHeader, ";") {
		trimmed := strings.TrimSpace(part)
		if trimmed == "" {
			continue
		}
		if eqIdx := strings.Index(trimmed, "="); eqIdx != -1 {
			if sensitiveSet[strings.ToLower(strings.TrimSpace(trimmed[:eqIdx]))] {
				continue
			}
		}
		kept = append(kept, trimmed)
	}
	return strings.Join(kept, "; ")
}

func killSession(sessionToken, reason string) {
	if sessionToken == "" || !dbConnected {
		return
	}
	_, _ = db.Exec("DELETE FROM ahrefs_sessions WHERE session_token = ? AND website_id = ?", sessionToken, currentWebsiteID)
	ipTracker.Delete(sessionToken)
	preview := sessionToken
	if len(preview) > 8 {
		preview = preview[:8] + "..."
	}
	log.Printf("[SECURITY] Session killed | reason=%s token=%s", reason, preview)
}

func resolvePremiumCookies(r *http.Request, cfg Config) (string, *ToolAccount) {
	if usesCookieFileMode(cfg) {
		return loadCookiesFromFile(cookieFilePath(cfg)), nil
	}
	cookie, err := r.Cookie("ct_session")
	if err != nil || cookie.Value == "" {
		return "", nil
	}
	activeAcc, found := getSessionAssignedAccount(cookie.Value)
	if !found {
		var assignErr error
		activeAcc, assignErr = autoAssignNextAccount(cookie.Value)
		if assignErr != nil {
			return "", nil
		}
	}
	return parseCookieFromDB(activeAcc.Cookie), &activeAcc
}

func getAuthenticatedUser(r *http.Request, cfg Config) (string, error) {
	if usesCookieFileMode(cfg) {
		return "local_dev", nil
	}
	cookie, err := r.Cookie("ct_session")
	if err != nil {
		return "", fmt.Errorf("ct_session: %w", err)
	}
	sessionToken := cookie.Value
	if sessionToken == "" {
		return "", fmt.Errorf("empty session token")
	}

	var username, sessionIP, deviceToken string
	var expiresAt time.Time
	err = db.QueryRow(
		"SELECT username, expires_at, client_ip, COALESCE(device_token, '') FROM ahrefs_sessions WHERE session_token = ? AND website_id = ?",
		sessionToken, currentWebsiteID,
	).Scan(&username, &expiresAt, &sessionIP, &deviceToken)
	if err == sql.ErrNoRows {
		return "", fmt.Errorf("session not found")
	}
	if err != nil {
		return "", fmt.Errorf("db session lookup: %w", err)
	}
	if time.Now().After(expiresAt) {
		recordSecurityEvent(r, username, "session_expired", "")
		killSession(sessionToken, "expired")
		return "", fmt.Errorf("session expired")
	}

	ss := normalizeSessionSecurity(cfg)
	if securityEnabled(cfg) {
		if !proxysec.CloudflareRequestOK(r, cfg.SessionSecurity, toolCtx(cfg), currentWebsiteSecurityEnabled) {
			recordSecurityEvent(r, username, "cloudflare_fail", "missing CF-Ray header")
			killSession(sessionToken, "cloudflare_ray_missing")
			return "", fmt.Errorf("cloudflare verification failed")
		}
		if cfg.PublicHost != "" && !isLocalDev(cfg) {
			reqHost := requestHost(r)
			if !isInternalRequestHost(reqHost) && !hostMatchesPublic(reqHost, cfg.PublicHost, ss.DomainCheck.AllowedHosts) {
				recordSecurityEvent(r, username, "host_mismatch", "req="+reqHost)
				killSession(sessionToken, "host_mismatch:"+reqHost)
				return "", fmt.Errorf("host mismatch")
			}
		}
		if ss.DeviceCookie.Enabled {
			cookieName := ss.DeviceCookie.CookieName
			if cookieName == "" {
				cookieName = "tm_device"
			}
			devCookie, errD := r.Cookie(cookieName)
			if errD != nil || devCookie.Value == "" || deviceToken == "" || devCookie.Value != deviceToken {
				recordSecurityEvent(r, username, "device_mismatch", "")
				killSession(sessionToken, "device_mismatch")
				return "", fmt.Errorf("device validation failed")
			}
		}
		currentIP := realClientIP(r)
		if claudeDualStackOTT(sessionIP, currentIP) {
			// dual-stack ISP: member area IPv4, subdomain IPv6 — same user
		} else {
			newIP, allow, kill := checkSessionIP(sessionToken, currentIP, sessionIP, ss.IPProtection)
			if kill {
				recordSecurityEvent(r, username, "ip_sharing", "concurrent subnets")
				killSession(sessionToken, "ip_sharing_detected")
				return "", fmt.Errorf("session sharing detected")
			}
			if allow && newIP != sessionIP && newIP != "" {
				_, _ = db.Exec(
					"UPDATE ahrefs_sessions SET client_ip = ? WHERE session_token = ? AND website_id = ?",
					newIP, sessionToken, currentWebsiteID,
				)
			}
		}
	}
	return username, nil
}

func handleLogoutDetected(cfg Config, reason string, acc ToolAccount, username, sessionToken string) {
	log.Printf("[LOGOUT] Detected | user=%s account=%s (ID:%d) reason=%s", username, acc.Name, acc.ID, reason)
	triggerSemrushAutomation(cfg)
	if dbConnected && sessionToken != "" && acc.ID > 0 {
		if nextAcc, err := switchToNextAccount(sessionToken, acc.ID, acc.Name, username, "logout: "+reason); err == nil {
			log.Printf("[LOGOUT] 🔄 Next account: '%s' (ID:%d)", nextAcc.Name, nextAcc.ID)
		}
	}
}

func startDailyResetCron() {
	go func() {
		for {
			loc, err := time.LoadLocation("Asia/Kolkata")
			if err != nil {
				loc = time.Local
			}
			now := time.Now().In(loc)
			next := time.Date(now.Year(), now.Month(), now.Day()+1, 0, 0, 0, 0, loc)
			time.Sleep(next.Sub(now))
			if dbConnected && db != nil {
				_, _ = db.Exec("DELETE FROM ahrefs_credit_logs WHERE website_id = ? AND DATE(timestamp) < CURDATE()", currentWebsiteID)
			}
		}
	}()
}

func renderNoActiveAccountsPage(w http.ResponseWriter, cfg Config) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusServiceUnavailable)
	memberAreaURL := cfg.MemberAreaURL
	if memberAreaURL == "" {
		memberAreaURL = "https://toolsmandi.com/"
	}
	toolName := cfg.ToolName
	if toolName == "" {
		toolName = "Claude"
	}
	fmt.Fprintf(w, `<!DOCTYPE html><html><head><meta charset="UTF-8"><title>Service Unavailable</title>
<style>body{font-family:system-ui,sans-serif;background:#0f172a;color:#fff;display:flex;align-items:center;justify-content:center;height:100vh;margin:0}
.box{max-width:480px;padding:32px;text-align:center;border:1px solid #334155;border-radius:16px}
h1{color:#f87171}p{color:#94a3b8;line-height:1.6}a{color:#818cf8}</style></head>
<body><div class="box"><h1>No Active Accounts</h1>
<p>Premium %s accounts are not configured yet. Please contact support or try again later.</p>
<p><a href="%s">Back to Member Area</a></p></div></body></html>`, toolName, memberAreaURL)
}

func buildWatchdogJS(cfg Config) string {
	triggers := cfg.WatchdogTriggers
	if len(triggers) == 0 {
		triggers = cfg.LogoutDetectTexts
	}
	if len(triggers) == 0 {
		return ""
	}
	b, _ := json.Marshal(triggers)
	return fmt.Sprintf(`
(function(){
    var triggers = %s;
    var done = false;
    function sniff(reason) {
        if (done) return;
        done = true;
        fetch('/api/rotate-session?reason=' + encodeURIComponent(reason)).catch(function(){});
        setTimeout(function(){ location.reload(); }, 5000);
    }
    function check() {
        var t = document.body ? document.body.innerText : '';
        for (var i = 0; i < triggers.length; i++) {
            if (t.indexOf(triggers[i]) !== -1) { sniff('watchdog:' + triggers[i]); return; }
        }
    }
    if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', check);
    else check();
    setInterval(check, 8000);
})();`, string(b))
}

func withCORS(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cfg := loadConfig()
		if origin := corsOrigin(cfg); origin != "" {
			w.Header().Set("Access-Control-Allow-Origin", origin)
		} else {
			w.Header().Set("Access-Control-Allow-Origin", "*")
		}
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Cookie")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusOK)
			return
		}
		h(w, r)
	}
}

// ensure cookie file exists for local dev
func ensureLocalCookieFile(cfg Config) {
	if !usesCookieFileMode(cfg) {
		return
	}
	path := cookieFilePath(cfg)
	if _, err := os.Stat(path); err == nil {
		return
	}
	log.Printf("[COOKIE] Local mode: %s not found — add cookies for testing", path)
}
