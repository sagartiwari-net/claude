package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	proxysec "toolsmandi.com/proxy-security"
)

// claudeDualStackOTT allows OTT when member area stored IPv4 but browser hits subdomain via IPv6 (or vice versa).
func claudeDualStackOTT(tokenIP, reqIP string) bool {
	tokenIP = normalizeOTTIP(tokenIP)
	reqIP = normalizeOTTIP(reqIP)
	if tokenIP == reqIP {
		return false // same IP — not a dual-stack case
	}
	pa, pb := net.ParseIP(tokenIP), net.ParseIP(reqIP)
	if pa == nil || pb == nil {
		return false
	}
	a4, b4 := pa.To4(), pb.To4()
	aIs4 := a4 != nil && len(pa) == net.IPv4len
	bIs4 := b4 != nil && len(pb) == net.IPv4len
	aIs6 := !aIs4 && len(pa) == net.IPv6len
	bIs6 := !bIs4 && len(pb) == net.IPv6len
	return (aIs4 && bIs6) || (aIs6 && bIs4)
}

func normalizeOTTIP(ip string) string {
	ip = strings.TrimSpace(ip)
	if strings.HasPrefix(ip, "[") && strings.HasSuffix(ip, "]") {
		ip = ip[1 : len(ip)-1]
	}
	if p := net.ParseIP(ip); p != nil {
		if v4 := p.To4(); v4 != nil {
			return v4.String()
		}
		return p.String()
	}
	return ip
}

// ottAccessClientIP picks client IP for /access. When handshake stored IPv4, prefer IPv4 from proxy headers.
func ottAccessClientIP(r *http.Request, tokenIP string) string {
	tokenIP = normalizeOTTIP(tokenIP)
	tokenIsV4 := net.ParseIP(tokenIP) != nil && net.ParseIP(tokenIP).To4() != nil

	tryHeader := func(header string) string {
		if header == "" {
			return ""
		}
		var fallback string
		for _, part := range strings.Split(header, ",") {
			raw := strings.TrimSpace(part)
			if raw == "" {
				continue
			}
			if fallback == "" {
				fallback = normalizeOTTIP(raw)
			}
			if tokenIsV4 {
				if p := net.ParseIP(raw); p != nil && p.To4() != nil {
					return p.To4().String()
				}
			}
		}
		return fallback
	}

	for _, h := range []string{
		r.Header.Get("CF-Connecting-IP"),
		r.Header.Get("X-Real-IP"),
		r.Header.Get("X-Forwarded-For"),
	} {
		if ip := tryHeader(h); ip != "" {
			return ip
		}
	}
	host, _, _ := net.SplitHostPort(r.RemoteAddr)
	return normalizeOTTIP(host)
}

// validateOTTForAccess returns true when the /access request should be allowed for this token IP pair.
func validateOTTForAccess(r *http.Request, cfg Config, tokenIP, username string) (ok bool, clientIP, mode string) {
	clientIP = ottAccessClientIP(r, tokenIP)
	tokenIP = normalizeOTTIP(tokenIP)
	mode = cfg.SessionSecurity.OTTIPValidation.Mode
	if mode == "" {
		mode = "soft"
	}

	ss := normalizeSessionSecurity(cfg)
	ottEnabled := securityEnabled(cfg) && ss.OTTIPValidation.Enabled

	log.Printf("[ACCESS] ott_check build=%s user=%s ott_enabled=%v token_ip=%s client_ip=%s dualstack=%v",
		proxyBuildTag, username, ottEnabled, tokenIP, clientIP, claudeDualStackOTT(tokenIP, clientIP))

	if !ottEnabled {
		return true, clientIP, "disabled"
	}
	if tokenIP == clientIP {
		return true, clientIP, mode
	}
	if claudeDualStackOTT(tokenIP, clientIP) {
		log.Printf("[ACCESS] ✅ OTT dual-stack allow | user=%s token_ip=%s client_ip=%s", username, tokenIP, clientIP)
		return true, clientIP, mode
	}
	ottOK, ottMode := proxysec.ValidateOTTClientIP(tokenIP, clientIP, cfg.SessionSecurity, toolCtx(cfg), currentWebsiteSecurityEnabled)
	if ottOK {
		return true, clientIP, ottMode
	}
	if ottMode != "strict" {
		if proxysec.SameSubnet16(tokenIP, clientIP) || proxysec.SameSubnet24(tokenIP, clientIP) {
			return true, clientIP, ottMode
		}
	}
	return false, clientIP, ottMode
}

func authHandshakeHandler(w http.ResponseWriter, r *http.Request) {
	cfg := loadConfig()
	resolveWebsiteID(cfg.PublicHost)
	if rejectIfIPBlocked(w, r, cfg) {
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	var payload struct {
		Username      string        `json:"username"`
		ProductIDsRaw []interface{} `json:"product_ids"`
		ClientIP      string        `json:"client_ip"`
		Timestamp     int64         `json:"timestamp"`
		Signature     string        `json:"signature"`
	}
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		http.Error(w, "Bad Request: Invalid JSON", http.StatusBadRequest)
		return
	}
	var productIDs []int
	for _, v := range payload.ProductIDsRaw {
		switch n := v.(type) {
		case float64:
			productIDs = append(productIDs, int(n))
		case string:
			if i, err := strconv.Atoi(n); err == nil {
				productIDs = append(productIDs, i)
			}
		}
	}
	if payload.Username == "" || payload.ClientIP == "" || payload.Signature == "" {
		http.Error(w, "Bad Request: Missing required fields", http.StatusBadRequest)
		return
	}
	if !dbConnected {
		http.Error(w, "Service Unavailable: Database not connected", http.StatusServiceUnavailable)
		return
	}

	var dbSecretKey string
	var dbSessionDuration int
	err := db.QueryRow("SELECT secret_key, session_duration FROM ahrefs_websites WHERE id = ?", currentWebsiteID).Scan(&dbSecretKey, &dbSessionDuration)
	if err != nil {
		dbSecretKey = cfg.SecretKey
		dbSessionDuration = cfg.SessionDurationMinutes
	}

	h := hmac.New(sha256.New, []byte(dbSecretKey))
	h.Write([]byte(fmt.Sprintf("%s:%d", payload.Username, payload.Timestamp)))
	expectedSig := hex.EncodeToString(h.Sum(nil))
	if !hmac.Equal([]byte(payload.Signature), []byte(expectedSig)) {
		log.Printf("[HANDSHAKE] ❌ HMAC failed for user: %s", payload.Username)
		recordSecurityEvent(r, payload.Username, "invalid_handshake", "HMAC signature mismatch")
		http.Error(w, "Forbidden: Invalid signature", http.StatusForbidden)
		return
	}
	if time.Now().Unix()-payload.Timestamp > 300 {
		http.Error(w, "Forbidden: Request expired", http.StatusForbidden)
		return
	}

	var productCount int
	_ = db.QueryRow("SELECT COUNT(*) FROM ahrefs_products WHERE website_id = ?", currentWebsiteID).Scan(&productCount)
	if productCount > 0 && len(productIDs) > 0 {
		hasAccess := false
		rows, err := db.Query("SELECT product_id FROM ahrefs_products WHERE website_id = ?", currentWebsiteID)
		if err == nil {
			defer rows.Close()
			for rows.Next() {
				var allowedPid string
				if err := rows.Scan(&allowedPid); err == nil {
					for _, userPid := range productIDs {
						if strconv.Itoa(userPid) == allowedPid {
							hasAccess = true
							break
						}
					}
				}
				if hasAccess {
					break
				}
			}
		}
		if !hasAccess {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			fmt.Fprint(w, `{"error":"no_product_access","message":"You do not have an authorized plan."}`)
			return
		}
	}

	var dbStatus string
	err = db.QueryRow("SELECT status FROM ahrefs_users WHERE username = ? AND website_id = ?", payload.Username, currentWebsiteID).Scan(&dbStatus)
	if err == sql.ErrNoRows {
		var defCredits, defExports int
		_ = db.QueryRow("SELECT COALESCE(default_credit_limit,50), COALESCE(default_export_limit,100000) FROM ahrefs_websites WHERE id = ?", currentWebsiteID).Scan(&defCredits, &defExports)
		_, err = db.Exec("INSERT INTO ahrefs_users (username, website_id, credit_limit, export_limit) VALUES (?,?,?,?)", payload.Username, currentWebsiteID, defCredits, defExports)
		if err != nil {
			http.Error(w, "Database error", http.StatusInternalServerError)
			return
		}
		log.Printf("[HANDSHAKE] Auto-created user: %s under website_id %d ✅", payload.Username, currentWebsiteID)
	} else if err != nil {
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	} else if dbStatus == "suspended" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		fmt.Fprint(w, `{"error":"account_suspended","message":"Your account is suspended."}`)
		return
	}

	ott, err := generateOTT()
	if err != nil {
		http.Error(w, "Internal Error", http.StatusInternalServerError)
		return
	}
	expires := time.Now().Add(2 * time.Minute)
	_, err = db.Exec(
		"INSERT INTO ahrefs_tokens (token, username, client_ip, expires_at, website_id) VALUES (?,?,?,?,?)",
		ott, payload.Username, payload.ClientIP, expires, currentWebsiteID,
	)
	if err != nil {
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}

	scheme := requestScheme(r, cfg)
	host := cfg.PublicHost
	if host == "" {
		host = r.Host
	}
	redirectURL := fmt.Sprintf("%s://%s/access?user=%s&token=%s",
		scheme, host, url.QueryEscape(payload.Username), url.QueryEscape(ott))
	log.Printf("[HANDSHAKE] ✅ OTT generated user=%s website_id=%d client_ip=%s → %s",
		payload.Username, currentWebsiteID, payload.ClientIP, redirectURL)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, `{"status":"ok","redirect_url":%q}`, redirectURL)
}

func accessHandler(w http.ResponseWriter, r *http.Request) {
	cfg := loadConfig()
	resolveWebsiteID(cfg.PublicHost)
	if rejectIfIPBlocked(w, r, cfg) {
		renderAccessErrorPage(w, cfg, "ip_blocked")
		return
	}
	if !dbConnected {
		renderAccessErrorPage(w, cfg, "db_offline")
		return
	}
	username := strings.TrimSpace(r.URL.Query().Get("user"))
	token := strings.TrimSpace(r.URL.Query().Get("token"))
	if username == "" || token == "" {
		recordSecurityEvent(r, username, "access_denied", "missing user or token")
		renderAccessErrorPage(w, cfg, "missing_params")
		return
	}

	var dbUsername, dbClientIP string
	var expiresAt time.Time
	err := db.QueryRow(
		"SELECT username, client_ip, expires_at FROM ahrefs_tokens WHERE token = ? AND website_id = ?",
		token, currentWebsiteID,
	).Scan(&dbUsername, &dbClientIP, &expiresAt)
	if err != nil {
		var otherWID int
		_ = db.QueryRow("SELECT website_id FROM ahrefs_tokens WHERE token = ? LIMIT 1", token).Scan(&otherWID)
		tokenPreview := token
		if len(tokenPreview) > 12 {
			tokenPreview = tokenPreview[:12] + "..."
		}
		log.Printf("[ACCESS] ❌ OTT lookup failed user=%s website_id=%d token=%s err=%v other_website_id=%d",
			username, currentWebsiteID, tokenPreview, err, otherWID)
		recordSecurityEvent(r, username, "access_denied", fmt.Sprintf("invalid token website_id=%d other=%d", currentWebsiteID, otherWID))
		if otherWID > 0 && otherWID != currentWebsiteID {
			renderAccessErrorPage(w, cfg, "config_mismatch")
		} else {
			renderAccessErrorPage(w, cfg, "invalid_link")
		}
		return
	}
	if time.Now().After(expiresAt) {
		_, _ = db.Exec("DELETE FROM ahrefs_tokens WHERE token = ? AND website_id = ?", token, currentWebsiteID)
		recordSecurityEvent(r, username, "access_denied", "token expired")
		renderAccessErrorPage(w, cfg, "link_expired")
		return
	}
	if !strings.EqualFold(dbUsername, username) {
		log.Printf("[ACCESS] ❌ Username mismatch token_user=%s query_user=%s", dbUsername, username)
		recordSecurityEvent(r, username, "access_denied", "username mismatch")
		renderAccessErrorPage(w, cfg, "username_mismatch")
		return
	}
	username = dbUsername

	ottOK, clientIP, ottMode := validateOTTForAccess(r, cfg, dbClientIP, username)
	sessionIP := clientIP
	if claudeDualStackOTT(dbClientIP, clientIP) && normalizeOTTIP(dbClientIP) != "" {
		sessionIP = normalizeOTTIP(dbClientIP)
	}
	if !ottOK {
		log.Printf("[ACCESS] ❌ OTT IP mismatch | build=%s mode=%s user=%s website_id=%d token_ip=%s req_ip=%s",
			proxyBuildTag, ottMode, username, currentWebsiteID, dbClientIP, clientIP)
		recordSecurityEvent(r, username, "ott_ip_mismatch", "mode="+ottMode+" token_ip="+dbClientIP+" req_ip="+clientIP)
		_, _ = db.Exec("DELETE FROM ahrefs_tokens WHERE token = ? AND website_id = ?", token, currentWebsiteID)
		renderAccessErrorPage(w, cfg, "ip_mismatch")
		return
	}

	_, _ = db.Exec("DELETE FROM ahrefs_tokens WHERE token = ? AND website_id = ?", token, currentWebsiteID)

	ss := normalizeSessionSecurity(cfg)
	if securityEnabled(cfg) && ss.SingleSessionPerUser {
		_, _ = db.Exec("DELETE FROM ahrefs_sessions WHERE username = ? AND website_id = ?", username, currentWebsiteID)
	}

	sessionBytes := make([]byte, 32)
	if _, err := rand.Read(sessionBytes); err != nil {
		http.Error(w, "Internal Error", http.StatusInternalServerError)
		return
	}
	sessionToken := hex.EncodeToString(sessionBytes)

	deviceToken := ""
	if securityEnabled(cfg) && ss.DeviceCookie.Enabled {
		devBytes := make([]byte, 32)
		if _, err := rand.Read(devBytes); err != nil {
			http.Error(w, "Internal Error", http.StatusInternalServerError)
			return
		}
		deviceToken = hex.EncodeToString(devBytes)
	}

	sessionDuration := cfg.SessionDurationMinutes
	if sessionDuration <= 0 {
		sessionDuration = 30
	}
	var dbSessionDuration int
	if errDb := db.QueryRow("SELECT session_duration FROM ahrefs_websites WHERE id = ?", currentWebsiteID).Scan(&dbSessionDuration); errDb == nil && dbSessionDuration > 0 {
		sessionDuration = dbSessionDuration
	}
	sessionExpires := time.Now().Add(time.Duration(sessionDuration) * time.Minute)

	_, err = db.Exec(
		"INSERT INTO ahrefs_sessions (session_token, username, client_ip, expires_at, website_id, device_token) VALUES (?,?,?,?,?,?)",
		sessionToken, username, sessionIP, sessionExpires, currentWebsiteID, deviceToken,
	)
	if err != nil {
		log.Printf("[ACCESS] Session insert failed: %v", err)
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}
	if _, assignErr := autoAssignNextAccount(sessionToken); assignErr != nil {
		log.Printf("[ACCESS] ⚠️ No active accounts for website_id=%d: %v", currentWebsiteID, assignErr)
	}
	_, _ = db.Exec(
		"INSERT INTO ahrefs_login_logs (website_id, username, client_ip, user_agent) VALUES (?,?,?,?)",
		currentWebsiteID, username, sessionIP, r.Header.Get("User-Agent"),
	)

	secure := cookieSecure(r, cfg)
	http.SetCookie(w, &http.Cookie{
		Name:     "ct_session",
		Value:    sessionToken,
		Path:     "/",
		Expires:  sessionExpires,
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
	})
	if deviceToken != "" && ss.DeviceCookie.Enabled {
		cookieName := ss.DeviceCookie.CookieName
		if cookieName == "" {
			cookieName = "tm_device"
		}
		http.SetCookie(w, &http.Cookie{
			Name:     cookieName,
			Value:    deviceToken,
			Path:     "/",
			Expires:  sessionExpires,
			HttpOnly: true,
			Secure:   secure,
			SameSite: http.SameSiteLaxMode,
		})
	}

	home := cfg.HomePath
	if home == "" {
		home = "/new"
	}
	http.Redirect(w, r, home, http.StatusFound)
	log.Printf("[ACCESS] ✅ Session set for user: %s (secure=%v)", username, secure)
}

func renderAccessDeniedPage(w http.ResponseWriter, cfg Config) {
	renderAccessErrorPage(w, cfg, "direct")
}

func renderAccessErrorPage(w http.ResponseWriter, cfg Config, reason string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusForbidden)
	memberAreaURL := cfg.MemberAreaURL
	if memberAreaURL == "" {
		memberAreaURL = "https://toolsmandi.com/"
	}
	toolName := cfg.ToolName
	if toolName == "" {
		toolName = "Claude AI"
	}

	title := "Access Denied"
	icon := "🔒"
	message := fmt.Sprintf("Please open <strong>%s</strong> from the ToolsMandi Member Area — do not bookmark or share direct links.", toolName)
	cta := "Open Member Area"

	switch reason {
	case "invalid_link":
		title = "Login Link Invalid"
		icon = "🔗"
		message = "This login link is invalid or was already used. Go back to the Member Area and click <strong>Access</strong> again to get a fresh link."
		cta = "Get New Access Link"
	case "link_expired":
		title = "Login Link Expired"
		icon = "⏱️"
		message = "This login link has expired. Please return to the Member Area and click <strong>Access</strong> again."
		cta = "Get New Access Link"
	case "ip_mismatch":
		title = "Security Check Failed"
		icon = "🛡️"
		message = "We could not verify your connection (IP mismatch). Turn off VPN/proxy if enabled, then click <strong>Access</strong> again from the Member Area."
		cta = "Try Again from Member Area"
	case "username_mismatch":
		title = "Session Error"
		icon = "⚠️"
		message = "Your login session could not be verified. Please log in to the Member Area and click <strong>Access</strong> again."
		cta = "Go to Member Area"
	case "ip_blocked":
		title = "IP Blocked"
		icon = "🚫"
		message = "Your IP address has been blocked from accessing this tool. Please contact support if you believe this is a mistake."
		cta = "Contact Support"
	case "config_mismatch":
		title = "Configuration Error"
		icon = "⚙️"
		message = "Server configuration mismatch detected (website ID). Please contact the administrator — proxy <code>public_host</code> must match the control panel domain."
		cta = "Go to Member Area"
	case "db_offline":
		title = "Service Unavailable"
		icon = "🔧"
		message = "The tool database is temporarily unavailable. Please try again in a few minutes."
		cta = "Go to Member Area"
	case "missing_params":
		title = "Invalid Request"
		icon = "❌"
		message = "Missing login parameters. Please use the <strong>Access</strong> button from the Member Area — do not open this URL manually."
		cta = "Go to Member Area"
	}

	fmt.Fprintf(w, `<!DOCTYPE html>
<html lang="en"><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>%s — %s</title>
<link href="https://fonts.googleapis.com/css2?family=Outfit:wght@400;600;700&display=swap" rel="stylesheet">
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:'Outfit',system-ui,sans-serif;background:radial-gradient(circle at center,#1a1f2e 0%%,#0d1117 100%%);color:#e6edf3;min-height:100vh;display:flex;align-items:center;justify-content:center;padding:24px}
.card{max-width:480px;width:100%%;padding:36px 32px;background:rgba(255,255,255,0.04);border:1px solid rgba(255,255,255,0.08);border-radius:20px;text-align:center;box-shadow:0 24px 48px rgba(0,0,0,0.4)}
.icon{font-size:52px;margin-bottom:16px;line-height:1}
h1{font-size:26px;font-weight:700;margin-bottom:14px;color:#f0f6fc}
p{font-size:15px;color:#8b949e;line-height:1.65;margin-bottom:28px}
p strong{color:#c9d1d9}
a{display:inline-block;padding:13px 28px;background:linear-gradient(135deg,#6366f1,#8b5cf6);color:#fff;font-weight:600;text-decoration:none;border-radius:12px;font-size:15px;transition:transform .15s}
a:hover{transform:scale(1.03)}
code{font-size:12px;background:rgba(255,255,255,0.08);padding:2px 6px;border-radius:4px}
.hint{margin-top:20px;font-size:13px;color:#6e7681}
</style></head>
<body><div class="card">
<div class="icon">%s</div>
<h1>%s</h1>
<p>%s</p>
<a href="%s">%s</a>
<p class="hint">If this keeps happening, contact support.</p>
</div></body></html>`, title, toolName, icon, title, message, memberAreaURL, cta)
}

func securityPingHandler(w http.ResponseWriter, r *http.Request) {
	cfg := loadConfig()
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.Error(w, `{"error":"method_not_allowed"}`, http.StatusMethodNotAllowed)
		return
	}
	if !securityEnabled(cfg) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `{"ok":true,"security":"off"}`)
		return
	}
	reqHost := requestHost(r)
	if cfg.PublicHost != "" && !isLocalDev(cfg) && !isInternalRequestHost(reqHost) {
		ss := normalizeSessionSecurity(cfg)
		if !hostMatchesPublic(reqHost, cfg.PublicHost, ss.DomainCheck.AllowedHosts) {
			w.WriteHeader(http.StatusForbidden)
			fmt.Fprint(w, `{"error":"host_mismatch"}`)
			return
		}
	}
	if _, err := getAuthenticatedUser(r, cfg); err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprint(w, `{"error":"unauthorized"}`)
		return
	}
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, `{"ok":true}`)
}

func rotateSessionHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	if !dbConnected {
		fmt.Fprint(w, `{"status":"ok","switched_to":"local"}`)
		return
	}
	cookie, err := r.Cookie("ct_session")
	if err != nil || cookie.Value == "" {
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprint(w, `{"error":"unauthorized"}`)
		return
	}
	sessionToken := cookie.Value
	activeAcc, found := getSessionAssignedAccount(sessionToken)
	if !found {
		var errSelect error
		activeAcc, errSelect = selectActiveAccount()
		if errSelect != nil {
			w.WriteHeader(http.StatusServiceUnavailable)
			fmt.Fprint(w, `{"error":"no_active_accounts"}`)
			return
		}
	}
	reason := r.URL.Query().Get("reason")
	if reason == "" {
		reason = "client-side watchdog"
	}
	var currentUser string
	_ = db.QueryRow("SELECT username FROM ahrefs_sessions WHERE session_token = ? AND website_id = ?", sessionToken, currentWebsiteID).Scan(&currentUser)
	nextAcc, switchErr := switchToNextAccount(sessionToken, activeAcc.ID, activeAcc.Name, currentUser, reason)
	if switchErr != nil {
		w.WriteHeader(http.StatusServiceUnavailable)
		fmt.Fprintf(w, `{"error":"no_other_accounts","message":"%v"}`, switchErr)
		return
	}
	fmt.Fprintf(w, `{"status":"ok","switched_to":"%s","id":%d}`, nextAcc.Name, nextAcc.ID)
}

func userLimitsAPIHandler(w http.ResponseWriter, r *http.Request) {
	cfg := loadConfig()
	w.Header().Set("Content-Type", "application/json")
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusOK)
		return
	}
	currentUser, err := getAuthenticatedUser(r, cfg)
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]interface{}{"error": "unauthorized"})
		return
	}
	var creditLimit, exportLimit, creditUsed int
	_ = db.QueryRow("SELECT credit_limit, export_limit FROM ahrefs_users WHERE username = ? AND website_id = ?", currentUser, currentWebsiteID).Scan(&creditLimit, &exportLimit)
	_ = db.QueryRow("SELECT COUNT(*) FROM ahrefs_credit_logs WHERE username = ? AND website_id = ? AND DATE(timestamp) = CURDATE()", currentUser, currentWebsiteID).Scan(&creditUsed)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"username":     currentUser,
		"credit_limit": creditLimit,
		"credit_used":  creditUsed,
		"tool_name":    cfg.ToolName,
		"show_limit":   false,
	})
}

func triggerAutomationHandler(w http.ResponseWriter, r *http.Request) {
	cfg := loadConfig()
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodPost {
		http.Error(w, `{"error":"method_not_allowed"}`, http.StatusMethodNotAllowed)
		return
	}
	var payload struct {
		Reason string `json:"reason"`
	}
	_ = json.NewDecoder(r.Body).Decode(&payload)
	if payload.Reason == "" {
		payload.Reason = "client_side_detection"
	}
	acc := ToolAccount{ID: 1, Name: "local"}
	username := "local_dev"
	sessionToken := ""
	if c, err := r.Cookie("ct_session"); err == nil {
		sessionToken = c.Value
	}
	if !usesCookieFileMode(cfg) && sessionToken != "" {
		_ = db.QueryRow("SELECT username FROM ahrefs_sessions WHERE session_token = ? AND website_id = ?", sessionToken, currentWebsiteID).Scan(&username)
		if a, ok := getSessionAssignedAccount(sessionToken); ok {
			acc = a
		}
	}
	handleLogoutDetected(cfg, payload.Reason, acc, username, sessionToken)
	json.NewEncoder(w).Encode(map[string]interface{}{"status": "ok", "account_id": acc.ID})
}
