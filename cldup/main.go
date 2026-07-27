package main

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	_ "github.com/go-sql-driver/mysql"
)

// ── CONFIG & DB ──────────────────────────────────────────────────────────────

type Config struct {
	Port                    string `json:"port"` // Panel runs on this port (default: 7843)
	MySQLHost               string `json:"mysql_host"`
	MySQLPort               string `json:"mysql_port"`
	MySQLUser               string `json:"mysql_user"`
	MySQLPassword           string `json:"mysql_password"`
	MySQLDB                 string `json:"mysql_db"`
	SecretKey               string `json:"secret_key"`
	DefaultAutomationAPIURL string `json:"default_automation_api_url"`
	PanelPublicURL          string `json:"panel_public_url"`
}

const CONFIG_FILE = "config.json"

var (
	currentConfig Config
	db            *sql.DB
)

func loadConfig() Config {
	data, err := os.ReadFile(CONFIG_FILE)
	if err != nil {
		log.Printf("[CONFIG] Read error: %v — using default config", err)
		return Config{
			Port:                    "7843",
			MySQLHost:               "127.0.0.1",
			MySQLPort:               "3306",
			MySQLUser:               "root",
			MySQLPassword:           "",
			MySQLDB:                 "toolsmandirefct",
			SecretKey:               "toolsmandi_ahrefs_secret_xyz123",
			DefaultAutomationAPIURL: "https://dashboard.seotoolscart.com/api/tasks/run",
		}
	}

	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		log.Printf("[CONFIG] Parse error: %v", err)
		return currentConfig
	}
	if cfg.Port == "" {
		cfg.Port = "7843"
	}
	if cfg.DefaultAutomationAPIURL == "" {
		cfg.DefaultAutomationAPIURL = "https://dashboard.seotoolscart.com/api/tasks/run"
	}
	currentConfig = cfg
	return cfg
}

func initDB(cfg Config) {
	dsn := fmt.Sprintf("%s:%s@tcp(%s:%s)/%s?parseTime=true&loc=Asia%%2FKolkata",
		cfg.MySQLUser, cfg.MySQLPassword, cfg.MySQLHost, cfg.MySQLPort, cfg.MySQLDB)
	
	var err error
	db, err = sql.Open("mysql", dsn)
	if err != nil {
		log.Fatalf("[DB] Failed to open database pool: %v", err)
	}

	db.SetMaxOpenConns(10)
	db.SetMaxIdleConns(2)
	db.SetConnMaxLifetime(5 * time.Minute)

	if err := db.Ping(); err != nil {
		log.Fatalf("[DB] Database connection error: %v", err)
	}
	
	log.Printf("[DB] Connected to MySQL successfully! Database: %s ✅", cfg.MySQLDB)
	
	// Execute schema migration check automatically
	runMigrations(db)

	// Safe upgrade: ensure default admin password hash is updated to SHA256 if still bcrypt
	// Password is: 'toolsmandi_admin_xyz123'
	shaHash := hashPassword("toolsmandi_admin_xyz123")
	_, _ = db.Exec("UPDATE ahrefs_resellers SET password_hash = ? WHERE username = 'admin' AND password_hash LIKE '$2a$10$%'", shaHash)
}

func runMigrations(db *sql.DB) {
	// 1. Check & Add default_credit_limit, default_export_limit to ahrefs_websites
	var count int
	_ = db.QueryRow("SELECT COUNT(*) FROM information_schema.COLUMNS WHERE table_name = 'ahrefs_websites' AND column_name = 'default_credit_limit' AND table_schema = DATABASE()").Scan(&count)
	if count == 0 {
		_, _ = db.Exec("ALTER TABLE ahrefs_websites ADD COLUMN default_credit_limit INT DEFAULT 50")
		_, _ = db.Exec("ALTER TABLE ahrefs_websites ADD COLUMN default_export_limit INT DEFAULT 100000")
		log.Println("[MIGRATION] Added default limit columns to ahrefs_websites table. ✅")
	}

	// 2. Check & Add show_limit to ahrefs_accounts
	count = 0
	_ = db.QueryRow("SELECT COUNT(*) FROM information_schema.COLUMNS WHERE table_name = 'ahrefs_accounts' AND column_name = 'show_limit' AND table_schema = DATABASE()").Scan(&count)
	if count == 0 {
		_, _ = db.Exec("ALTER TABLE ahrefs_accounts ADD COLUMN show_limit TINYINT(1) DEFAULT 1")
		log.Println("[MIGRATION] Added show_limit column to ahrefs_accounts table. ✅")
	}

	// 3. Check & Add assigned_account_id to ahrefs_sessions
	count = 0
	_ = db.QueryRow("SELECT COUNT(*) FROM information_schema.COLUMNS WHERE table_name = 'ahrefs_sessions' AND column_name = 'assigned_account_id' AND table_schema = DATABASE()").Scan(&count)
	if count == 0 {
		_, _ = db.Exec("ALTER TABLE ahrefs_sessions ADD COLUMN assigned_account_id INT NULL DEFAULT NULL")
		_, _ = db.Exec("ALTER TABLE ahrefs_sessions ADD CONSTRAINT fk_sessions_accounts FOREIGN KEY (assigned_account_id) REFERENCES ahrefs_accounts(id) ON DELETE SET NULL")
		log.Println("[MIGRATION] Added assigned_account_id column to ahrefs_sessions table. ✅")
	}

	// 4. Create ahrefs_login_logs table if not exists
	_, _ = db.Exec(`CREATE TABLE IF NOT EXISTS ahrefs_login_logs (
		id INT AUTO_INCREMENT PRIMARY KEY,
		website_id INT NOT NULL,
		username VARCHAR(100) NOT NULL,
		client_ip VARCHAR(64) NOT NULL,
		user_agent TEXT,
		logged_in_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		INDEX (website_id),
		INDEX (username),
		INDEX (logged_in_at)
	) ENGINE=InnoDB`)
	log.Println("[MIGRATION] Ensured ahrefs_login_logs table exists. ✅")

	// 5. Create ahrefs_switch_logs table if not exists
	_, _ = db.Exec(`CREATE TABLE IF NOT EXISTS ahrefs_switch_logs (
		id INT AUTO_INCREMENT PRIMARY KEY,
		website_id INT NOT NULL,
		session_token VARCHAR(128),
		username VARCHAR(100),
		from_account_id INT,
		from_account_name VARCHAR(100),
		to_account_id INT,
		to_account_name VARCHAR(100),
		reason VARCHAR(255),
		switched_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		INDEX (website_id),
		INDEX (switched_at)
	) ENGINE=InnoDB`)
	log.Println("[MIGRATION] Ensured ahrefs_switch_logs table exists. ✅")

	// 6. Check & Add website_id to ahrefs_products
	count = 0
	_ = db.QueryRow("SELECT COUNT(*) FROM information_schema.COLUMNS WHERE table_name = 'ahrefs_products' AND column_name = 'website_id' AND table_schema = DATABASE()").Scan(&count)
	if count == 0 {
		_, _ = db.Exec("ALTER TABLE ahrefs_products ADD COLUMN website_id INT NOT NULL DEFAULT 1")
		// Drop unique key/index on product_id
		_, _ = db.Exec("ALTER TABLE ahrefs_products DROP INDEX product_id")
		_, _ = db.Exec("ALTER TABLE ahrefs_products DROP INDEX product_id_2")
		// Modify column to varchar
		_, _ = db.Exec("ALTER TABLE ahrefs_products MODIFY COLUMN product_id VARCHAR(255) NOT NULL")
		log.Println("[MIGRATION] Isolated ahrefs_products by website_id and changed product_id to VARCHAR. ✅")
	}

	// 7. Check & Add custom_limit_expire_at to ahrefs_users
	count = 0
	_ = db.QueryRow("SELECT COUNT(*) FROM information_schema.COLUMNS WHERE table_name = 'ahrefs_users' AND column_name = 'custom_limit_expire_at' AND table_schema = DATABASE()").Scan(&count)
	if count == 0 {
		_, _ = db.Exec("ALTER TABLE ahrefs_users ADD COLUMN custom_limit_expire_at DATETIME NULL DEFAULT NULL")
		log.Println("[MIGRATION] Added custom_limit_expire_at column to ahrefs_users table. ✅")
	}

	// 8. Convert category column in ahrefs_tools from ENUM to VARCHAR to allow custom tool categories like 'learning'
	var dataType string
	_ = db.QueryRow("SELECT DATA_TYPE FROM information_schema.COLUMNS WHERE table_name = 'ahrefs_tools' AND column_name = 'category' AND table_schema = DATABASE()").Scan(&dataType)
	if dataType == "enum" {
		_, _ = db.Exec("ALTER TABLE ahrefs_tools MODIFY COLUMN category VARCHAR(100) DEFAULT 'seo'")
		log.Println("[MIGRATION] Successfully modified category column in ahrefs_tools from ENUM to VARCHAR. ✅")
	}

	// 9. Check & Add proxy column to ahrefs_websites (website-level default proxy for proxy services)
	count = 0
	_ = db.QueryRow("SELECT COUNT(*) FROM information_schema.COLUMNS WHERE table_name = 'ahrefs_websites' AND column_name = 'proxy' AND table_schema = DATABASE()").Scan(&count)
	if count == 0 {
		_, _ = db.Exec("ALTER TABLE ahrefs_websites ADD COLUMN proxy VARCHAR(500) DEFAULT ''")
		log.Println("[MIGRATION] Added proxy column to ahrefs_websites table. ✅")
	}

	// 10. Create ahrefs_proxies table for centralized proxy management
	_, _ = db.Exec(`CREATE TABLE IF NOT EXISTS ahrefs_proxies (
		id INT AUTO_INCREMENT PRIMARY KEY,
		name VARCHAR(150) NOT NULL,
		proxy_type ENUM('SOCKS5','HTTP','HTTPS') DEFAULT 'SOCKS5',
		endpoint VARCHAR(500) NOT NULL,
		status ENUM('active','inactive') DEFAULT 'active',
		created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		INDEX (status)
	) ENGINE=InnoDB`)
	log.Println("[MIGRATION] Ensured ahrefs_proxies table exists. ✅")

	// 11. Add GoAuto automation fields to ahrefs_accounts (each column checked separately)
	count = 0
	_ = db.QueryRow("SELECT COUNT(*) FROM information_schema.COLUMNS WHERE table_name = 'ahrefs_accounts' AND column_name = 'goauto_task_uid' AND table_schema = DATABASE()").Scan(&count)
	if count == 0 {
		_, _ = db.Exec("ALTER TABLE ahrefs_accounts ADD COLUMN goauto_task_uid VARCHAR(255) DEFAULT ''")
		log.Println("[MIGRATION] Added goauto_task_uid column to ahrefs_accounts. ✅")
	}
	count = 0
	_ = db.QueryRow("SELECT COUNT(*) FROM information_schema.COLUMNS WHERE table_name = 'ahrefs_accounts' AND column_name = 'automation_ingest_key' AND table_schema = DATABASE()").Scan(&count)
	if count == 0 {
		_, _ = db.Exec("ALTER TABLE ahrefs_accounts ADD COLUMN automation_ingest_key VARCHAR(100) DEFAULT ''")
		log.Println("[MIGRATION] Added automation_ingest_key column to ahrefs_accounts. ✅")
	}
	count = 0
	_ = db.QueryRow("SELECT COUNT(*) FROM information_schema.COLUMNS WHERE table_name = 'ahrefs_accounts' AND column_name = 'automation_api_url' AND table_schema = DATABASE()").Scan(&count)
	if count == 0 {
		_, _ = db.Exec("ALTER TABLE ahrefs_accounts ADD COLUMN automation_api_url VARCHAR(500) DEFAULT ''")
		log.Println("[MIGRATION] Added automation_api_url column to ahrefs_accounts. ✅")
	}
}

func hashPassword(password string) string {
	h := sha256.New()
	h.Write([]byte(password))
	return hex.EncodeToString(h.Sum(nil))
}

var automationIngestKeyRegex = regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9_]*$`)

func validateAutomationIngestKey(key string) error {
	if key == "" {
		return nil
	}
	if len(key) > 64 {
		return fmt.Errorf("automation ingest key must be 64 characters or fewer")
	}
	if !automationIngestKeyRegex.MatchString(key) {
		return fmt.Errorf("automation ingest key may only contain letters, numbers, and underscores, and must start with a letter")
	}
	return nil
}

func ensureUniqueIngestKey(key string, excludeID int) error {
	var existingID int
	err := db.QueryRow(`
		SELECT id FROM ahrefs_accounts
		WHERE automation_ingest_key = ? AND id != ? AND automation_ingest_key != ''
		LIMIT 1`, key, excludeID).Scan(&existingID)
	if err == nil {
		return fmt.Errorf("automation ingest key already in use by account ID %d", existingID)
	}
	if err != sql.ErrNoRows {
		return fmt.Errorf("database error checking ingest key uniqueness")
	}
	return nil
}

func isAuthorizedAutomationRequest(r *http.Request, websiteSecret string) bool {
	auth := strings.TrimSpace(r.Header.Get("Authorization"))
	if strings.HasPrefix(strings.ToLower(auth), "bearer ") {
		token := strings.TrimSpace(auth[7:])
		if token == "" {
			return false
		}
		if token == currentConfig.SecretKey {
			return true
		}
		if websiteSecret != "" && token == websiteSecret {
			return true
		}
	}
	return false
}

// automationIngestHandler accepts cookie updates from GoAuto using a per-account ingest key.
func automationIngestHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	key := strings.Trim(strings.TrimPrefix(r.URL.Path, "/api/automation/ingest/"), "/")
	if key == "" {
		http.Error(w, "Missing ingest key", http.StatusBadRequest)
		return
	}
	if err := validateAutomationIngestKey(key); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	var accountID int
	var websiteSecret string
	err := db.QueryRow(`
		SELECT a.id, w.secret_key
		FROM ahrefs_accounts a
		JOIN ahrefs_websites w ON a.website_id = w.id
		WHERE a.automation_ingest_key = ?
		LIMIT 1`, key).Scan(&accountID, &websiteSecret)
	if err == sql.ErrNoRows {
		http.Error(w, "Unknown ingest key", http.StatusNotFound)
		return
	}
	if err != nil {
		http.Error(w, "Database lookup error", http.StatusInternalServerError)
		return
	}

	if !isAuthorizedAutomationRequest(r, websiteSecret) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprintf(w, `{"error":"unauthorized","message":"Invalid ingest token. Set TOOLSMANDI_INGEST_TOKEN to panel secret_key or this website's handshake secret_key."}`)
		return
	}

	var payload struct {
		Cookie    string `json:"cookie"`
		UserAgent string `json:"user_agent"`
		Status    string `json:"status"`
	}
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		http.Error(w, "Invalid JSON body", http.StatusBadRequest)
		return
	}
	payload.Cookie = strings.TrimSpace(payload.Cookie)
	if payload.Cookie == "" {
		http.Error(w, "cookie is required", http.StatusBadRequest)
		return
	}

	status := strings.TrimSpace(payload.Status)
	if status == "" {
		status = "active"
	}

	if strings.TrimSpace(payload.UserAgent) != "" {
		_, err = db.Exec(`
			UPDATE ahrefs_accounts
			SET cookie = ?, user_agent = ?, status = ?, failure_count = 0, last_used_at = NOW()
			WHERE id = ?`, payload.Cookie, strings.TrimSpace(payload.UserAgent), status, accountID)
	} else {
		_, err = db.Exec(`
			UPDATE ahrefs_accounts
			SET cookie = ?, status = ?, failure_count = 0, last_used_at = NOW()
			WHERE id = ?`, payload.Cookie, status, accountID)
	}
	if err != nil {
		http.Error(w, "Update failed: "+err.Error(), http.StatusInternalServerError)
		return
	}

	log.Printf("[AUTOMATION-INGEST] Updated account %d via ingest key %q", accountID, key)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":     "ok",
		"account_id": accountID,
		"ingest_key": key,
	})
}

// ── AUTHENTICATION MIDDLEWARE ────────────────────────────────────────────────

type AdminSession struct {
	ResellerID int
	Username   string
	Role       string
	Websites   []int // Mapped website IDs
}

func getAdminSession(r *http.Request) (*AdminSession, error) {
	cookie, err := r.Cookie("admin_session")
	if err != nil {
		return nil, err
	}

	var sess AdminSession
	var expiresAt time.Time
	err = db.QueryRow(`
		SELECT s.reseller_id, r.username, r.role, s.expires_at 
		FROM ahrefs_admin_sessions s 
		JOIN ahrefs_resellers r ON s.reseller_id = r.id 
		WHERE s.session_token = ?`, cookie.Value,
	).Scan(&sess.ResellerID, &sess.Username, &sess.Role, &expiresAt)

	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("session not found")
	}
	if err != nil {
		return nil, err
	}

	if time.Now().After(expiresAt) {
		_, _ = db.Exec("DELETE FROM ahrefs_admin_sessions WHERE session_token = ?", cookie.Value)
		return nil, fmt.Errorf("session expired")
	}

	// Fetch assigned website IDs for resellers
	if sess.Role == "reseller" {
		rows, err := db.Query("SELECT website_id FROM ahrefs_reseller_websites WHERE reseller_id = ?", sess.ResellerID)
		if err == nil {
			defer rows.Close()
			for rows.Next() {
				var wid int
				if err := rows.Scan(&wid); err == nil {
					sess.Websites = append(sess.Websites, wid)
				}
			}
		}
	} else {
		// Master admin gets all websites mapped
		rows, err := db.Query("SELECT id FROM ahrefs_websites")
		if err == nil {
			defer rows.Close()
			for rows.Next() {
				var wid int
				if err := rows.Scan(&wid); err == nil {
					sess.Websites = append(sess.Websites, wid)
				}
			}
		}
	}

	return &sess, nil
}

// Helper to check website access
func (s *AdminSession) HasWebsite(id int) bool {
	if s.Role == "master" {
		return true
	}
	for _, wid := range s.Websites {
		if wid == id {
			return true
		}
	}
	return false
}

// ── API ROUTES ───────────────────────────────────────────────────────────────

func authLoginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	var payload struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	var resellerID int
	var storedHash, status, role string
	err := db.QueryRow(
		"SELECT id, password_hash, status, role FROM ahrefs_resellers WHERE username = ?",
		payload.Username,
	).Scan(&resellerID, &storedHash, &status, &role)

	if err == sql.ErrNoRows || storedHash != hashPassword(payload.Password) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprintf(w, `{"error":"auth_failed","message":"Invalid username or password"}`)
		return
	}
	if status == "suspended" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		fmt.Fprintf(w, `{"error":"suspended","message":"Account has been suspended"}`)
		return
	}

	// Create Session Token
	h := sha256.New()
	h.Write([]byte(fmt.Sprintf("%d:%s:%d", resellerID, payload.Username, time.Now().UnixNano())))
	token := hex.EncodeToString(h.Sum(nil))

	expires := time.Now().Add(12 * time.Hour)
	_, err = db.Exec(
		"INSERT INTO ahrefs_admin_sessions (session_token, reseller_id, expires_at) VALUES (?, ?, ?)",
		token, resellerID, expires,
	)
	if err != nil {
		http.Error(w, "Database session creation failed", http.StatusInternalServerError)
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "admin_session",
		Value:    token,
		Path:     "/",
		Expires:  expires,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})

	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(w, `{"status":"ok","username":%q,"role":%q}`, payload.Username, role)
}

func authLogoutHandler(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("admin_session")
	if err == nil {
		_, _ = db.Exec("DELETE FROM ahrefs_admin_sessions WHERE session_token = ?", cookie.Value)
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "admin_session",
		Value:    "",
		Path:     "/",
		Expires:  time.Unix(0, 0),
		HttpOnly: true,
	})

	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(w, `{"status":"ok"}`)
}

func dashboardStatsHandler(w http.ResponseWriter, r *http.Request, sess *AdminSession) {
	var totalSessions, totalAccounts, creditHitsToday int

	// Filter based on assigned websites
	websiteCSV := ""
	var websitesInterface []interface{}
	for _, wid := range sess.Websites {
		websiteCSV += "?,"
		websitesInterface = append(websitesInterface, wid)
	}
	if len(websiteCSV) > 0 {
		websiteCSV = websiteCSV[:len(websiteCSV)-1]
	} else {
		websiteCSV = "0"
	}

	// 1. Active sessions (Timezone-Aware parameter query)
	sessArgs := append([]interface{}{}, websitesInterface...)
	sessArgs = append(sessArgs, time.Now())
	err := db.QueryRow("SELECT COUNT(*) FROM ahrefs_sessions WHERE website_id IN ("+websiteCSV+") AND expires_at > ?", sessArgs...).Scan(&totalSessions)
	if err != nil { log.Printf("[STATS] Error sessions: %v", err) }

	// 2. Total Accounts
	err = db.QueryRow("SELECT COUNT(*) FROM ahrefs_accounts WHERE website_id IN ("+websiteCSV+")", websitesInterface...).Scan(&totalAccounts)
	if err != nil { log.Printf("[STATS] Error accounts: %v", err) }

	// 3. Credit Hits Today
	err = db.QueryRow("SELECT COUNT(*) FROM ahrefs_credit_logs WHERE website_id IN ("+websiteCSV+") AND DATE(timestamp) = CURDATE()", websitesInterface...).Scan(&creditHitsToday)
	if err != nil { log.Printf("[STATS] Error logs: %v", err) }

	// 4. Detailed Active User Logins List
	rows, errS := db.Query(`
		SELECT s.username, w.name AS website_name, s.client_ip, s.created_at, s.expires_at, COALESCE(a.name, 'Auto-Switching')
		FROM ahrefs_sessions s
		JOIN ahrefs_websites w ON s.website_id = w.id
		LEFT JOIN ahrefs_accounts a ON s.assigned_account_id = a.id
		WHERE s.website_id IN (`+websiteCSV+`) AND s.expires_at > ?`, sessArgs...)
	
	var activeUsersList []map[string]interface{}
	if errS == nil {
		defer rows.Close()
		for rows.Next() {
			var username, websiteName, clientIP, assignedAccName string
			var created, expires time.Time
			if errScan := rows.Scan(&username, &websiteName, &clientIP, &created, &expires, &assignedAccName); errScan == nil {
				activeUsersList = append(activeUsersList, map[string]interface{}{
					"username":              username,
					"website_name":          websiteName,
					"client_ip":             clientIP,
					"created_at":            created,
					"expires_at":            expires,
					"assigned_account_name": assignedAccName,
				})
			}
		}
	} else {
		log.Printf("[STATS] Error active users list query: %v", errS)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"active_sessions":    totalSessions,
		"accounts_total":     totalAccounts,
		"credit_hits_today":  creditHitsToday,
		"active_users_list":  activeUsersList,
	})
}

// Mapped accounts handler
func accountsHandler(w http.ResponseWriter, r *http.Request, sess *AdminSession) {
	// Parse Mapped Website IDs into SQL placeholders
	websiteCSV := ""
	var websitesInterface []interface{}
	for _, wid := range sess.Websites {
		websiteCSV += "?,"
		websitesInterface = append(websitesInterface, wid)
	}
	if len(websiteCSV) > 0 {
		websiteCSV = websiteCSV[:len(websiteCSV)-1]
	} else {
		websiteCSV = "0"
	}

	switch r.Method {
	case http.MethodGet:
		rows, err := db.Query(`
			SELECT a.id, a.website_id, w.name AS website_name, w.secret_key AS website_secret_key, a.name, a.cookie, a.user_agent, a.proxy, a.status, a.last_used_at, a.failure_count, a.show_limit,
			       COALESCE(a.goauto_task_uid, ''), COALESCE(a.automation_ingest_key, ''), COALESCE(a.automation_api_url, '')
			FROM ahrefs_accounts a
			JOIN ahrefs_websites w ON a.website_id = w.id
			WHERE a.website_id IN (`+websiteCSV+`)`, websitesInterface...)
		if err != nil {
			http.Error(w, "Database select error: "+err.Error(), http.StatusInternalServerError)
			return
		}
		defer rows.Close()

		var list []map[string]interface{}
		for rows.Next() {
			var id, websiteID, failureCount, showLimitVal int
			var websiteName, websiteSecretKey, name, cookie, userAgent, proxy, status, goautoTaskUID, automationIngestKey, automationAPIURL string
			var lastUsed time.Time
			
			if err := rows.Scan(&id, &websiteID, &websiteName, &websiteSecretKey, &name, &cookie, &userAgent, &proxy, &status, &lastUsed, &failureCount, &showLimitVal, &goautoTaskUID, &automationIngestKey, &automationAPIURL); err == nil {
				list = append(list, map[string]interface{}{
					"id":                    id,
					"website_id":            websiteID,
					"website_name":          websiteName,
					"website_secret_key":    websiteSecretKey,
					"name":                  name,
					"cookie":                cookie,
					"user_agent":            userAgent,
					"proxy":                 proxy,
					"status":                status,
					"last_used_at":          lastUsed,
					"failure_count":         failureCount,
					"show_limit":            showLimitVal == 1,
					"goauto_task_uid":       goautoTaskUID,
					"automation_ingest_key": automationIngestKey,
					"automation_api_url":    automationAPIURL,
				})
			}
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(list)

	case http.MethodPost:
		var payload struct {
			WebsiteID int    `json:"website_id"`
			Name      string `json:"name"`
			Cookie    string `json:"cookie"`
			UserAgent string `json:"user_agent"`
			Proxy     string `json:"proxy"`
			ShowLimit bool   `json:"show_limit"`
		}
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			http.Error(w, "Invalid body", http.StatusBadRequest)
			return
		}
		if !sess.HasWebsite(payload.WebsiteID) {
			http.Error(w, "Forbidden: No access to this website", http.StatusForbidden)
			return
		}

		showLimitVal := 0
		if payload.ShowLimit {
			showLimitVal = 1
		}

		_, err := db.Exec(`
			INSERT INTO ahrefs_accounts (website_id, name, cookie, user_agent, proxy, status, show_limit) 
			VALUES (?, ?, ?, ?, ?, 'active', ?)`,
			payload.WebsiteID, payload.Name, payload.Cookie, payload.UserAgent, payload.Proxy, showLimitVal,
		)
		if err != nil {
			http.Error(w, "Insert failed: "+err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"status":"ok"}`)

	case http.MethodPut:
		var payload struct {
			ID        int    `json:"id"`
			WebsiteID int    `json:"website_id"`
			Name      string `json:"name"`
			Cookie    string `json:"cookie"`
			UserAgent string `json:"user_agent"`
			Proxy     string `json:"proxy"`
			Status    string `json:"status"`
			ShowLimit bool   `json:"show_limit"`
		}
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			http.Error(w, "Invalid body", http.StatusBadRequest)
			return
		}
		if !sess.HasWebsite(payload.WebsiteID) {
			http.Error(w, "Forbidden: No access to this website", http.StatusForbidden)
			return
		}

		showLimitVal := 0
		if payload.ShowLimit {
			showLimitVal = 1
		}

		_, err := db.Exec(`
			UPDATE ahrefs_accounts 
			SET name = ?, cookie = ?, user_agent = ?, proxy = ?, status = ?, failure_count = 0, show_limit = ? 
			WHERE id = ? AND website_id = ?`,
			payload.Name, payload.Cookie, payload.UserAgent, payload.Proxy, payload.Status, showLimitVal, payload.ID, payload.WebsiteID,
		)
		if err != nil {
			http.Error(w, "Update failed: "+err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"status":"ok"}`)

	case http.MethodDelete:
		idStr := r.URL.Query().Get("id")
		id, _ := strconv.Atoi(idStr)

		// Verify ownership before deleting
		var websiteID int
		err := db.QueryRow("SELECT website_id FROM ahrefs_accounts WHERE id = ?", id).Scan(&websiteID)
		if err == sql.ErrNoRows || !sess.HasWebsite(websiteID) {
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}

		_, _ = db.Exec("DELETE FROM ahrefs_accounts WHERE id = ?", id)
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"status":"ok"}`)
	}
}

// accountAutomationHandler updates only automation fields for a mapped account.
func accountAutomationHandler(w http.ResponseWriter, r *http.Request, sess *AdminSession) {
	if r.Method != http.MethodPut {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var payload struct {
		ID                  int    `json:"id"`
		WebsiteID           int    `json:"website_id"`
		GoautoTaskUID       string `json:"goauto_task_uid"`
		AutomationIngestKey string `json:"automation_ingest_key"`
		AutomationAPIURL    string `json:"automation_api_url"`
	}
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		http.Error(w, "Invalid body", http.StatusBadRequest)
		return
	}
	if payload.ID <= 0 || !sess.HasWebsite(payload.WebsiteID) {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	payload.GoautoTaskUID = strings.TrimSpace(payload.GoautoTaskUID)
	payload.AutomationIngestKey = strings.TrimSpace(payload.AutomationIngestKey)
	payload.AutomationAPIURL = strings.TrimSpace(payload.AutomationAPIURL)

	if payload.AutomationIngestKey != "" {
		if err := validateAutomationIngestKey(payload.AutomationIngestKey); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if err := ensureUniqueIngestKey(payload.AutomationIngestKey, payload.ID); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
	}

	_, err := db.Exec(`
		UPDATE ahrefs_accounts
		SET goauto_task_uid = ?, automation_ingest_key = ?, automation_api_url = ?
		WHERE id = ? AND website_id = ?`,
		payload.GoautoTaskUID, payload.AutomationIngestKey, payload.AutomationAPIURL, payload.ID, payload.WebsiteID,
	)
	if err != nil {
		http.Error(w, "Update failed: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(w, `{"status":"ok"}`)
}

// User quota and credit logs handler
func usersHandler(w http.ResponseWriter, r *http.Request, sess *AdminSession) {
	websiteCSV := ""
	var websitesInterface []interface{}
	for _, wid := range sess.Websites {
		websiteCSV += "?,"
		websitesInterface = append(websitesInterface, wid)
	}
	if len(websiteCSV) > 0 {
		websiteCSV = websiteCSV[:len(websiteCSV)-1]
	} else {
		websiteCSV = "0"
	}

	switch r.Method {
	case http.MethodGet:
		// Automatically expire custom limits that have passed their expiration date
		_, _ = db.Exec(`
			UPDATE ahrefs_users u
			JOIN ahrefs_websites w ON u.website_id = w.id
			SET u.credit_limit = COALESCE(w.default_credit_limit, 50),
				u.export_limit = COALESCE(w.default_export_limit, 100000),
				u.custom_limit_expire_at = NULL
			WHERE u.custom_limit_expire_at IS NOT NULL AND u.custom_limit_expire_at < NOW()
		`)

		rows, err := db.Query(`
			SELECT u.id, u.website_id, w.name AS website_name, t.category AS tool_category, t.limit_label_1, t.limit_label_2, u.username, u.credit_limit, u.export_limit, u.status, u.custom_limit_expire_at 
			FROM ahrefs_users u
			JOIN ahrefs_websites w ON u.website_id = w.id
			JOIN ahrefs_tools t ON w.tool_id = t.id
			WHERE u.website_id IN (`+websiteCSV+`)`, websitesInterface...)
		if err != nil {
			http.Error(w, "Database error: "+err.Error(), http.StatusInternalServerError)
			return
		}
		defer rows.Close()

		var list []map[string]interface{}
		for rows.Next() {
			var id, websiteID, creditLimit, exportLimit int
			var websiteName, category, label1, label2, username, status string
			var customLimitExpireAt sql.NullTime
			if err := rows.Scan(&id, &websiteID, &websiteName, &category, &label1, &label2, &username, &creditLimit, &exportLimit, &status, &customLimitExpireAt); err == nil {
				// Fetch current used credits today
				var usedCredits int
				_ = db.QueryRow("SELECT COUNT(*) FROM ahrefs_credit_logs WHERE username = ? AND website_id = ? AND DATE(timestamp) = CURDATE()", username, websiteID).Scan(&usedCredits)

				var expireAtStr *string = nil
				if customLimitExpireAt.Valid {
					s := customLimitExpireAt.Time.Format("2006-01-02 15:04:05")
					expireAtStr = &s
				}

				list = append(list, map[string]interface{}{
					"id":                     id,
					"website_id":             websiteID,
					"website_name":           websiteName,
					"category":               category,
					"limit_label_1":          label1,
					"limit_label_2":          label2,
					"username":               username,
					"credit_limit":           creditLimit,
					"export_limit":           exportLimit,
					"used_credits":           usedCredits,
					"status":                 status,
					"custom_limit_expire_at": expireAtStr,
				})
			}
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(list)

	case http.MethodPost:
		var payload struct {
			ID                  int     `json:"id"`
			WebsiteID           int     `json:"website_id"`
			Username            string  `json:"username"` // Optional: used for manual creation
			CreditLimit         int     `json:"credit_limit"`
			ExportLimit         int     `json:"export_limit"`
			Status              string  `json:"status"`
			ResetUsage          bool    `json:"reset_usage"`
			CustomLimitExpireAt *string `json:"custom_limit_expire_at"` // "YYYY-MM-DD"
		}
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			http.Error(w, "Invalid body", http.StatusBadRequest)
			return
		}
		if !sess.HasWebsite(payload.WebsiteID) {
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}

		var expireAtVal interface{} = nil
		if payload.CustomLimitExpireAt != nil && *payload.CustomLimitExpireAt != "" {
			// Append end of day time so expiration triggers exactly at midnight after the chosen date
			expireAtVal = *payload.CustomLimitExpireAt + " 23:59:59"
		}

		if payload.ID == 0 {
			// MANUAL CREATION / PROVISIONING
			if payload.Username == "" {
				http.Error(w, "Username is required for new records", http.StatusBadRequest)
				return
			}
			_, err := db.Exec(`
				INSERT INTO ahrefs_users (website_id, username, credit_limit, export_limit, status, custom_limit_expire_at) 
				VALUES (?, ?, ?, ?, ?, ?)
				ON DUPLICATE KEY UPDATE credit_limit = ?, export_limit = ?, status = ?, custom_limit_expire_at = ?`,
				payload.WebsiteID, payload.Username, payload.CreditLimit, payload.ExportLimit, payload.Status, expireAtVal,
				payload.CreditLimit, payload.ExportLimit, payload.Status, expireAtVal,
			)
			if err != nil {
				http.Error(w, "Manual user insert failed: "+err.Error(), http.StatusInternalServerError)
				return
			}
			log.Printf("[LIMITS] Manually provisioned/updated user '%s' on website_id %d by Reseller", payload.Username, payload.WebsiteID)
		} else {
			// NORMAL QUOTAS UPDATE
			_, err := db.Exec(`
				UPDATE ahrefs_users 
				SET credit_limit = ?, export_limit = ?, status = ?, custom_limit_expire_at = ? 
				WHERE id = ? AND website_id = ?`,
				payload.CreditLimit, payload.ExportLimit, payload.Status, expireAtVal, payload.ID, payload.WebsiteID,
			)
			if err != nil {
				http.Error(w, "Update limits failed: "+err.Error(), http.StatusInternalServerError)
				return
			}

			if payload.ResetUsage {
				var username string
				_ = db.QueryRow("SELECT username FROM ahrefs_users WHERE id = ?", payload.ID).Scan(&username)
				if username != "" {
					_, _ = db.Exec("DELETE FROM ahrefs_credit_logs WHERE username = ? AND website_id = ?", username, payload.WebsiteID)
					_, _ = db.Exec("DELETE FROM ahrefs_export_logs WHERE username = ? AND website_id = ?", username, payload.WebsiteID)
					log.Printf("[LIMITS] Reset credit usage for user '%s' on Website ID %d by Reseller", username, payload.WebsiteID)
				}
			}
		}

		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"status":"ok"}`)

	case http.MethodDelete:
		idStr := r.URL.Query().Get("id")
		id, _ := strconv.Atoi(idStr)

		// Verify ownership before deleting
		var websiteID int
		err := db.QueryRow("SELECT website_id FROM ahrefs_users WHERE id = ?", id).Scan(&websiteID)
		if err == sql.ErrNoRows || !sess.HasWebsite(websiteID) {
			http.Error(w, "Forbidden: User record not found or no access to website", http.StatusForbidden)
			return
		}

		_, err = db.Exec("DELETE FROM ahrefs_users WHERE id = ?", id)
		if err != nil {
			http.Error(w, "Delete custom user limit failed: "+err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"status":"ok"}`)
	}
}

// Mapped active user sessions handler
func sessionsHandler(w http.ResponseWriter, r *http.Request, sess *AdminSession) {
	websiteCSV := ""
	var websitesInterface []interface{}
	for _, wid := range sess.Websites {
		websiteCSV += "?,"
		websitesInterface = append(websitesInterface, wid)
	}
	if len(websiteCSV) > 0 {
		websiteCSV = websiteCSV[:len(websiteCSV)-1]
	} else {
		websiteCSV = "0"
	}

	switch r.Method {
	case http.MethodGet:
		sessArgs := append([]interface{}{}, websitesInterface...)
		sessArgs = append(sessArgs, time.Now())
		rows, err := db.Query(`
			SELECT s.id, s.website_id, w.name AS website_name, s.session_token, s.username, s.client_ip, s.expires_at, s.created_at, COALESCE(s.assigned_account_id, 0), COALESCE(a.name, 'Auto-Switching')
			FROM ahrefs_sessions s
			JOIN ahrefs_websites w ON s.website_id = w.id
			LEFT JOIN ahrefs_accounts a ON s.assigned_account_id = a.id
			WHERE s.website_id IN (`+websiteCSV+`) AND s.expires_at > ?`, sessArgs...)
		if err != nil {
			http.Error(w, "Database error: "+err.Error(), http.StatusInternalServerError)
			return
		}
		defer rows.Close()

		var list []map[string]interface{}
		for rows.Next() {
			var id, websiteID, assignedAccID int
			var websiteName, sessionToken, username, clientIP, assignedAccName string
			var expires, created time.Time
			if err := rows.Scan(&id, &websiteID, &websiteName, &sessionToken, &username, &clientIP, &expires, &created, &assignedAccID, &assignedAccName); err == nil {
				list = append(list, map[string]interface{}{
					"id":                    id,
					"website_id":            websiteID,
					"website_name":          websiteName,
					"session_token":         sessionToken,
					"username":              username,
					"client_ip":             clientIP,
					"expires_at":            expires,
					"created_at":            created,
					"assigned_account_id":   assignedAccID,
					"assigned_account_name": assignedAccName,
				})
			}
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(list)

	case http.MethodPut:
		// ADMIN SESSION ACCOUNT OVERRIDE
		var payload struct {
			SessionToken string `json:"session_token"`
			AccountID    int    `json:"account_id"` // 0 means unassign (auto-switch)
		}
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			http.Error(w, "Invalid body", http.StatusBadRequest)
			return
		}

		var websiteID int
		err := db.QueryRow("SELECT website_id FROM ahrefs_sessions WHERE session_token = ?", payload.SessionToken).Scan(&websiteID)
		if err == sql.ErrNoRows || !sess.HasWebsite(websiteID) {
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}

		if payload.AccountID > 0 {
			_, err = db.Exec("UPDATE ahrefs_sessions SET assigned_account_id = ? WHERE session_token = ?", payload.AccountID, payload.SessionToken)
		} else {
			_, err = db.Exec("UPDATE ahrefs_sessions SET assigned_account_id = NULL WHERE session_token = ?", payload.SessionToken)
		}

		if err != nil {
			http.Error(w, "Failed mapping: "+err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"status":"ok"}`)

	case http.MethodDelete:
		// Termination / Kill Session
		token := r.URL.Query().Get("token")
		if token == "" {
			http.Error(w, "Missing token", http.StatusBadRequest)
			return
		}

		var websiteID int
		err := db.QueryRow("SELECT website_id FROM ahrefs_sessions WHERE session_token = ?", token).Scan(&websiteID)
		if err != nil {
			if err == sql.ErrNoRows {
				// Session already deleted or purged
				w.Header().Set("Content-Type", "application/json")
				fmt.Fprintf(w, `{"status":"ok"}`)
				return
			}
			http.Error(w, "Database select error: "+err.Error(), http.StatusInternalServerError)
			return
		}
		if !sess.HasWebsite(websiteID) {
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}

		_, _ = db.Exec("DELETE FROM ahrefs_sessions WHERE session_token = ?", token)
		log.Printf("[AUTH] Terminated session token: %s", token)

		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"status":"ok"}`)
	}
}

// Dedicated Quotas & Usage Tracker API
func usageHandler(w http.ResponseWriter, r *http.Request, sess *AdminSession) {
	websiteCSV := ""
	var websitesInterface []interface{}
	for _, wid := range sess.Websites {
		websiteCSV += "?,"
		websitesInterface = append(websitesInterface, wid)
	}
	if len(websiteCSV) > 0 {
		websiteCSV = websiteCSV[:len(websiteCSV)-1]
	} else {
		websiteCSV = "0"
	}

	targetUser := r.URL.Query().Get("username")
	targetWebsite := r.URL.Query().Get("website_id")

	if targetUser != "" {
		// Return detailed log entries filtered for this specific user
		search := r.URL.Query().Get("search")

		q1 := `SELECT c.id, c.website_id, w.name AS website_name, c.username, c.endpoint, c.timestamp, 'credit' AS log_type, 1 AS value
			   FROM ahrefs_credit_logs c
			   JOIN ahrefs_websites w ON c.website_id = w.id
			   WHERE c.website_id IN (`+websiteCSV+`) AND c.username = ?`
		
		args1 := append([]interface{}{}, websitesInterface...)
		args1 = append(args1, targetUser)
		if targetWebsite != "" {
			q1 += " AND c.website_id = ?"
			args1 = append(args1, targetWebsite)
		}
		if search != "" {
			q1 += " AND c.endpoint LIKE ?"
			args1 = append(args1, "%"+search+"%")
		}

		q2 := `SELECT e.id, e.website_id, w.name AS website_name, e.username, e.endpoint, e.timestamp, 'export' AS log_type, e.rows_count AS value
			   FROM ahrefs_export_logs e
			   JOIN ahrefs_websites w ON e.website_id = w.id
			   WHERE e.website_id IN (`+websiteCSV+`) AND e.username = ?`
		
		args2 := append([]interface{}{}, websitesInterface...)
		args2 = append(args2, targetUser)
		if targetWebsite != "" {
			q2 += " AND e.website_id = ?"
			args2 = append(args2, targetWebsite)
		}
		if search != "" {
			q2 += " AND e.endpoint LIKE ?"
			args2 = append(args2, "%"+search+"%")
		}

		unionQuery := "(" + q1 + ") UNION ALL (" + q2 + ") ORDER BY timestamp DESC LIMIT 500"
		argsAll := append(args1, args2...)

		rows, err := db.Query(unionQuery, argsAll...)
		if err != nil {
			http.Error(w, "Database log query error: "+err.Error(), http.StatusInternalServerError)
			return
		}
		defer rows.Close()

		var logs []map[string]interface{}
		for rows.Next() {
			var id, websiteID, value int
			var websiteName, username, endpoint, logType string
			var timestamp time.Time
			if err := rows.Scan(&id, &websiteID, &websiteName, &username, &endpoint, &timestamp, &logType, &value); err == nil {
				logs = append(logs, map[string]interface{}{
					"id":           id,
					"website_id":   websiteID,
					"website_name": websiteName,
					"username":     username,
					"endpoint":     endpoint,
					"timestamp":    timestamp,
					"log_type":     logType,
					"value":        value,
				})
			}
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(logs)
		return
	}

	// Default: Return aggregated user usage statistics (grouped)
	search := r.URL.Query().Get("search")
	queryStr := `
		SELECT u.id, u.website_id, w.name AS website_name, u.username, u.credit_limit, u.export_limit, u.status
		FROM ahrefs_users u
		JOIN ahrefs_websites w ON u.website_id = w.id
		WHERE u.website_id IN (`+websiteCSV+`)`
	
	args := append([]interface{}{}, websitesInterface...)
	if targetWebsite != "" {
		queryStr += " AND u.website_id = ?"
		args = append(args, targetWebsite)
	}
	if search != "" {
		queryStr += " AND u.username LIKE ?"
		args = append(args, "%"+search+"%")
	}
	queryStr += " ORDER BY u.username ASC"

	rows, err := db.Query(queryStr, args...)
	if err != nil {
		http.Error(w, "Database error: "+err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var summaryList []map[string]interface{}
	for rows.Next() {
		var id, websiteID, creditLimit, exportLimit int
		var websiteName, username, status string
		if err := rows.Scan(&id, &websiteID, &websiteName, &username, &creditLimit, &exportLimit, &status); err == nil {
			// 1. Used credits today
			var usedCredits int
			_ = db.QueryRow("SELECT COUNT(*) FROM ahrefs_credit_logs WHERE username = ? AND website_id = ? AND DATE(timestamp) = CURDATE()", username, websiteID).Scan(&usedCredits)

			// 2. Used exports weekly rows
			var usedExports int
			_ = db.QueryRow("SELECT COALESCE(SUM(rows_count), 0) FROM ahrefs_export_logs WHERE username = ? AND website_id = ?", username, websiteID).Scan(&usedExports)

			summaryList = append(summaryList, map[string]interface{}{
				"id":            id,
				"website_id":    websiteID,
				"website_name":  websiteName,
				"username":      username,
				"credit_limit":  creditLimit,
				"export_limit":  exportLimit,
				"used_credits":  usedCredits,
				"used_exports":  usedExports,
				"status":        status,
			})
		}
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(summaryList)
}

// Allowed Products (aMember product IDs authorized for access) handler
func productsHandler(w http.ResponseWriter, r *http.Request, sess *AdminSession) {
	// Parse Mapped Website IDs into SQL placeholders for reseller isolation
	websiteCSV := ""
	var websitesInterface []interface{}
	for _, wid := range sess.Websites {
		websiteCSV += "?,"
		websitesInterface = append(websitesInterface, wid)
	}
	if len(websiteCSV) > 0 {
		websiteCSV = websiteCSV[:len(websiteCSV)-1]
	} else {
		websiteCSV = "0"
	}

	switch r.Method {
	case http.MethodGet:
		var rows *sql.Rows
		var err error
		if sess.Role == "master" {
			rows, err = db.Query(`
				SELECT p.id, p.website_id, w.name AS website_name, p.product_id, p.product_name, p.created_at 
				FROM ahrefs_products p
				JOIN ahrefs_websites w ON p.website_id = w.id
				ORDER BY p.id DESC`)
		} else {
			rows, err = db.Query(`
				SELECT p.id, p.website_id, w.name AS website_name, p.product_id, p.product_name, p.created_at 
				FROM ahrefs_products p
				JOIN ahrefs_websites w ON p.website_id = w.id
				WHERE p.website_id IN (`+websiteCSV+`)
				ORDER BY p.id DESC`, websitesInterface...)
		}

		if err != nil {
			http.Error(w, "Database error: "+err.Error(), http.StatusInternalServerError)
			return
		}
		defer rows.Close()

		var list []map[string]interface{}
		for rows.Next() {
			var id, websiteID int
			var websiteName, productID, productName string
			var createdAt time.Time
			if err := rows.Scan(&id, &websiteID, &websiteName, &productID, &productName, &createdAt); err == nil {
				list = append(list, map[string]interface{}{
					"id":           id,
					"website_id":   websiteID,
					"website_name": websiteName,
					"product_id":   productID,
					"product_name": productName,
					"created_at":   createdAt,
				})
			}
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(list)

	case http.MethodPost:
		var payload struct {
			ID          int    `json:"id"`
			WebsiteID   int    `json:"website_id"`
			ProductID   string `json:"product_id"`
			ProductName string `json:"product_name"`
		}
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			http.Error(w, "Invalid body", http.StatusBadRequest)
			return
		}

		// Security Check: Reseller cannot add to unassigned websites
		if sess.Role != "master" {
			allowed := false
			for _, wid := range sess.Websites {
				if wid == payload.WebsiteID {
					allowed = true
					break
				}
			}
			if !allowed {
				http.Error(w, "Forbidden: website not allowed", http.StatusForbidden)
				return
			}
		}

		if payload.ID > 0 {
			// Security Check for edit
			var originalWebsiteID int
			err := db.QueryRow("SELECT website_id FROM ahrefs_products WHERE id = ?", payload.ID).Scan(&originalWebsiteID)
			if err == nil && sess.Role != "master" {
				allowed := false
				for _, wid := range sess.Websites {
					if wid == originalWebsiteID {
						allowed = true
						break
					}
				}
				if !allowed {
					http.Error(w, "Forbidden: website not allowed", http.StatusForbidden)
					return
				}
			}

			// Update
			_, err = db.Exec("UPDATE ahrefs_products SET website_id = ?, product_id = ?, product_name = ? WHERE id = ?", payload.WebsiteID, payload.ProductID, payload.ProductName, payload.ID)
			if err != nil {
				http.Error(w, "Failed to update product: "+err.Error(), http.StatusInternalServerError)
				return
			}
		} else {
			// Insert
			_, err := db.Exec("INSERT INTO ahrefs_products (website_id, product_id, product_name) VALUES (?, ?, ?)", payload.WebsiteID, payload.ProductID, payload.ProductName)
			if err != nil {
				http.Error(w, "Failed to add product: "+err.Error(), http.StatusInternalServerError)
				return
			}
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"status":"ok"}`)

	case http.MethodDelete:
		idStr := r.URL.Query().Get("id")
		if idStr == "" {
			http.Error(w, "Missing ID", http.StatusBadRequest)
			return
		}

		// Security check for delete
		if sess.Role != "master" {
			var origWebsiteID int
			err := db.QueryRow("SELECT website_id FROM ahrefs_products WHERE id = ?", idStr).Scan(&origWebsiteID)
			if err == nil {
				allowed := false
				for _, wid := range sess.Websites {
					if wid == origWebsiteID {
						allowed = true
						break
					}
				}
				if !allowed {
					http.Error(w, "Forbidden: website not allowed", http.StatusForbidden)
					return
				}
			}
		}

		_, err := db.Exec("DELETE FROM ahrefs_products WHERE id = ?", idStr)
		if err != nil {
			http.Error(w, "Database error: "+err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"status":"ok"}`)
	}
}

// Blocked URL violations log handler
func violationsHandler(w http.ResponseWriter, r *http.Request, sess *AdminSession) {
	websiteCSV := ""
	var websitesInterface []interface{}
	for _, wid := range sess.Websites {
		websiteCSV += "?,"
		websitesInterface = append(websitesInterface, wid)
	}
	if len(websiteCSV) > 0 {
		websiteCSV = websiteCSV[:len(websiteCSV)-1]
	} else {
		websiteCSV = "0"
	}

	switch r.Method {
	case http.MethodGet:
		rows, err := db.Query(`
			SELECT v.id, v.website_id, w.name AS website_name, v.username, v.client_ip, v.attempted_path, v.timestamp
			FROM ahrefs_violations_logs v
			JOIN ahrefs_websites w ON v.website_id = w.id
			WHERE v.website_id IN (`+websiteCSV+`)
			ORDER BY v.timestamp DESC LIMIT 500`, websitesInterface...)
		if err != nil {
			log.Printf("[VIOLATIONS] Query error: %v", err)
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, "[]")
			return
		}
		defer rows.Close()

		var list []map[string]interface{}
		for rows.Next() {
			var id, websiteID int
			var websiteName, username, clientIP, attemptedPath string
			var timestamp time.Time
			if err := rows.Scan(&id, &websiteID, &websiteName, &username, &clientIP, &attemptedPath, &timestamp); err == nil {
				list = append(list, map[string]interface{}{
					"id":             id,
					"website_id":     websiteID,
					"website_name":   websiteName,
					"username":       username,
					"client_ip":      clientIP,
					"attempted_path": attemptedPath,
					"timestamp":      timestamp,
				})
			}
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(list)
	}
}

// Master Admin only websites handler (GET is allowed for resellers restricted to their websites)
func websitesHandler(w http.ResponseWriter, r *http.Request, sess *AdminSession) {
	if sess.Role != "master" && sess.Role != "reseller" {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}
	if r.Method != http.MethodGet && sess.Role != "master" {
		http.Error(w, "Forbidden: Master admin only", http.StatusForbidden)
		return
	}

	switch r.Method {
	case http.MethodGet:
		var rows *sql.Rows
		var err error
		if sess.Role == "master" {
			rows, err = db.Query(`
				SELECT w.id, w.tool_id, t.name AS tool_name, t.category AS tool_category, t.limit_label_1, t.limit_label_2, w.name, w.domain, w.secret_key, w.session_duration, w.created_at, COALESCE(w.default_credit_limit, 50), COALESCE(w.default_export_limit, 100000), COALESCE(w.proxy, '') 
				FROM ahrefs_websites w
				JOIN ahrefs_tools t ON w.tool_id = t.id`)
		} else {
			websiteCSV := ""
			var websitesInterface []interface{}
			for _, wid := range sess.Websites {
				websiteCSV += "?,"
				websitesInterface = append(websitesInterface, wid)
			}
			if len(websiteCSV) > 0 {
				websiteCSV = websiteCSV[:len(websiteCSV)-1]
			} else {
				websiteCSV = "0"
			}
			rows, err = db.Query(`
				SELECT w.id, w.tool_id, t.name AS tool_name, t.category AS tool_category, t.limit_label_1, t.limit_label_2, w.name, w.domain, w.secret_key, w.session_duration, w.created_at, COALESCE(w.default_credit_limit, 50), COALESCE(w.default_export_limit, 100000), COALESCE(w.proxy, '') 
				FROM ahrefs_websites w
				JOIN ahrefs_tools t ON w.tool_id = t.id
				WHERE w.id IN (`+websiteCSV+`)`, websitesInterface...)
		}
		if err != nil {
			http.Error(w, "Database error: "+err.Error(), http.StatusInternalServerError)
			return
		}
		defer rows.Close()

		var list []map[string]interface{}
		for rows.Next() {
			var id, toolID, duration, defaultCredits, defaultExports int
			var toolName, category, label1, label2, name, domain, secretKey, proxy string
			var created time.Time
			if err := rows.Scan(&id, &toolID, &toolName, &category, &label1, &label2, &name, &domain, &secretKey, &duration, &created, &defaultCredits, &defaultExports, &proxy); err == nil {
				list = append(list, map[string]interface{}{
					"id":                   id,
					"tool_id":              toolID,
					"tool_name":            toolName,
					"tool_category":        category,
					"limit_label_1":        label1,
					"limit_label_2":        label2,
					"name":                 name,
					"domain":               domain,
					"secret_key":           secretKey,
					"session_duration":     duration,
					"created_at":           created,
					"default_credit_limit": defaultCredits,
					"default_export_limit": defaultExports,
					"proxy":                proxy,
				})
			}
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(list)

	case http.MethodPost:
		var payload struct {
			ToolID             int    `json:"tool_id"`
			Name               string `json:"name"`
			Domain             string `json:"domain"`
			SecretKey          string `json:"secret_key"`
			SessionDuration    int    `json:"session_duration"`
			DefaultCreditLimit int    `json:"default_credit_limit"`
			DefaultExportLimit int    `json:"default_export_limit"`
			Proxy              string `json:"proxy"`
		}
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			http.Error(w, "Invalid body", http.StatusBadRequest)
			return
		}
		if payload.SessionDuration <= 0 {
			payload.SessionDuration = 30
		}
		if payload.DefaultCreditLimit <= 0 {
			payload.DefaultCreditLimit = 50
		}
		if payload.DefaultExportLimit <= 0 {
			payload.DefaultExportLimit = 100000
		}

		_, err := db.Exec(`
			INSERT INTO ahrefs_websites (tool_id, name, domain, secret_key, session_duration, default_credit_limit, default_export_limit, proxy) 
			VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
			payload.ToolID, payload.Name, payload.Domain, payload.SecretKey, payload.SessionDuration, payload.DefaultCreditLimit, payload.DefaultExportLimit, payload.Proxy,
		)
		if err != nil {
			http.Error(w, "Insert failed: "+err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"status":"ok"}`)

	case http.MethodPut:
		var payload struct {
			ID                 int    `json:"id"`
			ToolID             int    `json:"tool_id"`
			Name               string `json:"name"`
			Domain             string `json:"domain"`
			SecretKey          string `json:"secret_key"`
			SessionDuration    int    `json:"session_duration"`
			DefaultCreditLimit int    `json:"default_credit_limit"`
			DefaultExportLimit int    `json:"default_export_limit"`
			Proxy              string `json:"proxy"`
		}
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			http.Error(w, "Invalid body", http.StatusBadRequest)
			return
		}
		if payload.SessionDuration <= 0 {
			payload.SessionDuration = 30
		}
		if payload.DefaultCreditLimit <= 0 {
			payload.DefaultCreditLimit = 50
		}
		if payload.DefaultExportLimit <= 0 {
			payload.DefaultExportLimit = 100000
		}

		_, err := db.Exec(`
			UPDATE ahrefs_websites 
			SET tool_id = ?, name = ?, domain = ?, secret_key = ?, session_duration = ?, default_credit_limit = ?, default_export_limit = ?, proxy = ? 
			WHERE id = ?`,
			payload.ToolID, payload.Name, payload.Domain, payload.SecretKey, payload.SessionDuration, payload.DefaultCreditLimit, payload.DefaultExportLimit, payload.Proxy, payload.ID,
		)
		if err != nil {
			http.Error(w, "Update failed: "+err.Error(), http.StatusInternalServerError)
			return
		}

		// Sync new default limits to all users of this website who do NOT have an active custom limit
		_, _ = db.Exec(`
			UPDATE ahrefs_users 
			SET credit_limit = ?, export_limit = ? 
			WHERE website_id = ? AND custom_limit_expire_at IS NULL`,
			payload.DefaultCreditLimit, payload.DefaultExportLimit, payload.ID,
		)
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"status":"ok"}`)

	case http.MethodDelete:
		idStr := r.URL.Query().Get("id")
		id, _ := strconv.Atoi(idStr)
		_, _ = db.Exec("DELETE FROM ahrefs_websites WHERE id = ?", id)
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"status":"ok"}`)
	}
}

// Master Admin only resellers handler
func resellersHandler(w http.ResponseWriter, r *http.Request, sess *AdminSession) {
	// Resellers can only GET (and only see their own record)
	// Write operations (POST/PUT/DELETE) are master-only
	if sess.Role != "master" && r.Method != http.MethodGet {
		http.Error(w, "Forbidden: Master admin only", http.StatusForbidden)
		return
	}

	switch r.Method {
	case http.MethodGet:
		var rows *sql.Rows
		var err error
		if sess.Role == "master" {
			// Master admin: fetch all resellers
			rows, err = db.Query("SELECT id, username, role, status, created_at FROM ahrefs_resellers")
		} else {
			// Reseller: only fetch their own record (for frontend dropdown population)
			rows, err = db.Query("SELECT id, username, role, status, created_at FROM ahrefs_resellers WHERE id = ?", sess.ResellerID)
		}
		if err != nil {
			http.Error(w, "Database error", http.StatusInternalServerError)
			return
		}
		defer rows.Close()

		var list []map[string]interface{}
		for rows.Next() {
			var id int
			var username, role, status string
			var created time.Time
			if err := rows.Scan(&id, &username, &role, &status, &created); err == nil {
				// Fetch mapped websites
				var websiteIDs []int
				wRows, err := db.Query("SELECT website_id FROM ahrefs_reseller_websites WHERE reseller_id = ?", id)
				if err == nil {
					for wRows.Next() {
						var wid int
						if err := wRows.Scan(&wid); err == nil {
							websiteIDs = append(websiteIDs, wid)
						}
					}
					wRows.Close()
				}

				list = append(list, map[string]interface{}{
					"id":         id,
					"username":   username,
					"role":       role,
					"status":     status,
					"created_at": created,
					"websites":   websiteIDs,
				})
			}
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(list)

	case http.MethodPost:
		var payload struct {
			Username   string `json:"username"`
			Password   string `json:"password"`
			Role       string `json:"role"`
			Websites   []int  `json:"websites"`
		}
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			http.Error(w, "Invalid body", http.StatusBadRequest)
			return
		}

		passHash := hashPassword(payload.Password)
		res, err := db.Exec(`
			INSERT INTO ahrefs_resellers (username, password_hash, role, status) 
			VALUES (?, ?, ?, 'active')`,
			payload.Username, passHash, payload.Role,
		)
		if err != nil {
			http.Error(w, "Username already exists: "+err.Error(), http.StatusInternalServerError)
			return
		}
		
		resID, _ := res.LastInsertId()

		// Map websites
		for _, wid := range payload.Websites {
			_, _ = db.Exec("INSERT INTO ahrefs_reseller_websites (reseller_id, website_id) VALUES (?, ?)", resID, wid)
		}

		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"status":"ok"}`)

	case http.MethodPut:
		var payload struct {
			ID       int    `json:"id"`
			Status   string `json:"status"`
			Password string `json:"password"`
			Websites []int  `json:"websites"`
		}
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			http.Error(w, "Invalid body", http.StatusBadRequest)
			return
		}

		if payload.Password != "" {
			passHash := hashPassword(payload.Password)
			_, _ = db.Exec("UPDATE ahrefs_resellers SET password_hash = ?, status = ? WHERE id = ?", passHash, payload.Status, payload.ID)
		} else {
			_, _ = db.Exec("UPDATE ahrefs_resellers SET status = ? WHERE id = ?", payload.Status, payload.ID)
		}

		// Re-sync websites mappings
		_, _ = db.Exec("DELETE FROM ahrefs_reseller_websites WHERE reseller_id = ?", payload.ID)
		for _, wid := range payload.Websites {
			_, _ = db.Exec("INSERT INTO ahrefs_reseller_websites (reseller_id, website_id) VALUES (?, ?)", payload.ID, wid)
		}

		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"status":"ok"}`)

	case http.MethodDelete:
		idStr := r.URL.Query().Get("id")
		id, _ := strconv.Atoi(idStr)
		if id == 1 {
			http.Error(w, "Cannot delete master admin", http.StatusBadRequest)
			return
		}
		_, _ = db.Exec("DELETE FROM ahrefs_resellers WHERE id = ?", id)
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"status":"ok"}`)
	}
}

// Master list of available tools
func toolsListHandler(w http.ResponseWriter, r *http.Request, sess *AdminSession) {
	if r.Method == http.MethodPost {
		if sess.Role != "master" {
			http.Error(w, "Forbidden: Master admin only", http.StatusForbidden)
			return
		}

		var payload struct {
			Name        string `json:"name"`
			Category    string `json:"category"`
			LimitLabel1 string `json:"limit_label_1"`
			LimitLabel2 string `json:"limit_label_2"`
		}
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			http.Error(w, "Invalid body", http.StatusBadRequest)
			return
		}
		if payload.Name == "" || payload.Category == "" {
			http.Error(w, "Name and Category are required", http.StatusBadRequest)
			return
		}

		_, err := db.Exec(`
			INSERT INTO ahrefs_tools (name, category, limit_label_1, limit_label_2) 
			VALUES (?, ?, ?, ?)`,
			payload.Name, payload.Category, payload.LimitLabel1, payload.LimitLabel2,
		)
		if err != nil {
			http.Error(w, "Failed to add tool: "+err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"status":"ok"}`)
		return
	}

	rows, err := db.Query("SELECT id, name, category, limit_label_1, limit_label_2 FROM ahrefs_tools")
	if err != nil {
		http.Error(w, "Database error: "+err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var list []map[string]interface{}
	for rows.Next() {
		var id int
		var name, category, label1, label2 string
		if err := rows.Scan(&id, &name, &category, &label1, &label2); err == nil {
			list = append(list, map[string]interface{}{
				"id":            id,
				"name":          name,
				"category":      category,
				"limit_label_1": label1,
				"limit_label_2": label2,
			})
		}
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(list)
}

func profilePasswordHandler(w http.ResponseWriter, r *http.Request, sess *AdminSession) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	var payload struct {
		NewPassword string `json:"new_password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	passHash := hashPassword(payload.NewPassword)
	_, err := db.Exec("UPDATE ahrefs_resellers SET password_hash = ? WHERE id = ?", passHash, sess.ResellerID)
	if err != nil {
		http.Error(w, "Database update error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(w, `{"status":"ok"}`)
}

// automationDefaultsHandler returns panel-level automation defaults for the UI.
func automationDefaultsHandler(w http.ResponseWriter, r *http.Request, sess *AdminSession) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	_ = sess

	panelBase := strings.TrimRight(strings.TrimSpace(currentConfig.PanelPublicURL), "/")
	if panelBase == "" {
		scheme := "https"
		if r.TLS == nil && strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "http") {
			scheme = "http"
		} else if r.TLS == nil && r.Header.Get("X-Forwarded-Proto") == "" {
			scheme = "http"
		}
		if proto := strings.TrimSpace(r.Header.Get("X-Forwarded-Proto")); proto != "" {
			scheme = proto
		}
		panelBase = fmt.Sprintf("%s://%s", scheme, r.Host)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"panel_base_url":             panelBase,
		"default_automation_api_url": currentConfig.DefaultAutomationAPIURL,
		"global_ingest_token":        currentConfig.SecretKey,
		"ingest_auth_header":         "Authorization: Bearer <token>",
		"ingest_env_hint":            "TOOLSMANDI_INGEST_TOKEN=<token below>",
	})
}


func adminRouter(w http.ResponseWriter, r *http.Request) {
	// Set standard CORS & security headers
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusOK)
		return
	}

	path := r.URL.Path

	// A. Public automation ingest API (must be before HTML catch-all)
	if strings.HasPrefix(path, "/api/automation/ingest/") {
		automationIngestHandler(w, r)
		return
	}

	// B. Serves the static HTML dashboard layout for non-API frontend paths
	if !strings.HasPrefix(path, "/api/") {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprint(w, getAdminDashboardHTML())
		return
	}

	// C. Authentication endpoints (No session check required)
	if path == "/api/admin/auth/login" {
		authLoginHandler(w, r)
		return
	}
	if path == "/api/admin/auth/logout" {
		authLogoutHandler(w, r)
		return
	}

	// D. Authenticated endpoints (API requests only)
	sess, err := getAdminSession(r)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprintf(w, `{"error":"unauthorized","message":"Please log in"}`)
		return
	}

	// Route based on paths
	switch path {
	case "/api/admin/dashboard/stats":
		dashboardStatsHandler(w, r, sess)
	case "/api/admin/accounts":
		accountsHandler(w, r, sess)
	case "/api/admin/accounts/automation":
		accountAutomationHandler(w, r, sess)
	case "/api/admin/users":
		usersHandler(w, r, sess)
	case "/api/admin/sessions":
		sessionsHandler(w, r, sess)
	case "/api/admin/usage":
		usageHandler(w, r, sess)
	case "/api/admin/profile/password":
		profilePasswordHandler(w, r, sess)
	case "/api/admin/tools":
		toolsListHandler(w, r, sess)
	case "/api/admin/websites":
		websitesHandler(w, r, sess)
	case "/api/admin/resellers":
		resellersHandler(w, r, sess)
	case "/api/admin/products":
		productsHandler(w, r, sess)
	case "/api/admin/violations":
		violationsHandler(w, r, sess)
	case "/api/admin/proxies":
		proxiesHandler(w, r, sess)
	case "/api/admin/analytics/logins":
		analyticsLoginsHandler(w, r, sess)
	case "/api/admin/analytics/switches":
		analyticsSwitchesHandler(w, r, sess)
	case "/api/admin/automation/defaults":
		automationDefaultsHandler(w, r, sess)
	}
}

// ── PROXIES HANDLER ────────────────────────────────────────────────────────────

func proxiesHandler(w http.ResponseWriter, r *http.Request, sess *AdminSession) {
	if sess.Role != "master" {
		http.Error(w, "Forbidden: Master admin only", http.StatusForbidden)
		return
	}
	switch r.Method {
	case http.MethodGet:
		rows, err := db.Query("SELECT id, name, proxy_type, endpoint, status, created_at FROM ahrefs_proxies ORDER BY created_at DESC")
		if err != nil {
			http.Error(w, "Database error", http.StatusInternalServerError)
			return
		}
		defer rows.Close()
		var list []map[string]interface{}
		for rows.Next() {
			var id int
			var name, proxyType, endpoint, status string
			var created time.Time
			if err := rows.Scan(&id, &name, &proxyType, &endpoint, &status, &created); err == nil {
				list = append(list, map[string]interface{}{
					"id":         id,
					"name":       name,
					"proxy_type": proxyType,
					"endpoint":   endpoint,
					"status":     status,
					"created_at": created,
				})
			}
		}
		if list == nil { list = []map[string]interface{}{} }
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(list)

	case http.MethodPost:
		var payload struct {
			Name      string `json:"name"`
			ProxyType string `json:"proxy_type"`
			Endpoint  string `json:"endpoint"`
			Status    string `json:"status"`
		}
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			http.Error(w, "Invalid body", http.StatusBadRequest)
			return
		}
		if payload.Name == "" || payload.Endpoint == "" {
			http.Error(w, "Name and Endpoint are required", http.StatusBadRequest)
			return
		}
		if payload.ProxyType == "" { payload.ProxyType = "SOCKS5" }
		if payload.Status == "" { payload.Status = "active" }
		_, err := db.Exec("INSERT INTO ahrefs_proxies (name, proxy_type, endpoint, status) VALUES (?, ?, ?, ?)",
			payload.Name, payload.ProxyType, payload.Endpoint, payload.Status)
		if err != nil {
			http.Error(w, "Insert failed: "+err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"status":"ok"}`)

	case http.MethodPut:
		var payload struct {
			ID        int    `json:"id"`
			Name      string `json:"name"`
			ProxyType string `json:"proxy_type"`
			Endpoint  string `json:"endpoint"`
			Status    string `json:"status"`
		}
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			http.Error(w, "Invalid body", http.StatusBadRequest)
			return
		}
		_, err := db.Exec("UPDATE ahrefs_proxies SET name = ?, proxy_type = ?, endpoint = ?, status = ? WHERE id = ?",
			payload.Name, payload.ProxyType, payload.Endpoint, payload.Status, payload.ID)
		if err != nil {
			http.Error(w, "Update failed: "+err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"status":"ok"}`)

	case http.MethodDelete:
		idStr := r.URL.Query().Get("id")
		id, _ := strconv.Atoi(idStr)
		if id <= 0 {
			http.Error(w, "Invalid id", http.StatusBadRequest)
			return
		}
		_, _ = db.Exec("DELETE FROM ahrefs_proxies WHERE id = ?", id)
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"status":"ok"}`)
	}
}

// ── ANALYTICS HANDLERS ────────────────────────────────────────────────────────

// analyticsLoginsHandler: GET /api/admin/analytics/logins
// Returns login history for websites the session has access to.
// Query params: website_id (optional), search (username or IP), page, limit
func analyticsLoginsHandler(w http.ResponseWriter, r *http.Request, sess *AdminSession) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	q := r.URL.Query()
	search := q.Get("search")
	websiteIDStr := q.Get("website_id")
	page := 1
	limit := 50
	if v, err := strconv.Atoi(q.Get("page")); err == nil && v > 0 {
		page = v
	}
	if v, err := strconv.Atoi(q.Get("limit")); err == nil && v > 0 && v <= 200 {
		limit = v
	}
	offset := (page - 1) * limit

	// Build website_id filter respecting role scope
	var websiteFilter string
	var args []interface{}
	if websiteIDStr != "" {
		wid, err := strconv.Atoi(websiteIDStr)
		if err == nil && sess.HasWebsite(wid) {
			websiteFilter = "l.website_id = ?"
			args = append(args, wid)
		}
	}
	if websiteFilter == "" {
		// No specific website — use all accessible ones
		if sess.Role == "master" {
			websiteFilter = "1=1"
		} else {
			if len(sess.Websites) == 0 {
				json.NewEncoder(w).Encode(map[string]interface{}{"logins": []interface{}{}, "total": 0})
				return
			}
			placeholders := make([]string, len(sess.Websites))
			for i, wid := range sess.Websites {
				placeholders[i] = "?"
				args = append(args, wid)
			}
			websiteFilter = "l.website_id IN (" + strings.Join(placeholders, ",") + ")"
		}
	}

	searchClause := ""
	if search != "" {
		searchClause = " AND (l.username LIKE ? OR l.client_ip LIKE ?)"
		args = append(args, "%"+search+"%", "%"+search+"%")
	}

	baseQ := "FROM ahrefs_login_logs l JOIN ahrefs_websites w ON l.website_id = w.id WHERE " + websiteFilter + searchClause

	var total int
	countArgs := make([]interface{}, len(args))
	copy(countArgs, args)
	_ = db.QueryRow("SELECT COUNT(*) "+baseQ, countArgs...).Scan(&total)

	args = append(args, limit, offset)
	rows, err := db.Query(
		"SELECT l.id, l.website_id, w.domain, l.username, l.client_ip, COALESCE(l.user_agent,''), l.logged_in_at "+baseQ+" ORDER BY l.logged_in_at DESC LIMIT ? OFFSET ?",
		args...,
	)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}
	defer rows.Close()

	type LoginEntry struct {
		ID         int    `json:"id"`
		WebsiteID  int    `json:"website_id"`
		Domain     string `json:"domain"`
		Username   string `json:"username"`
		ClientIP   string `json:"client_ip"`
		UserAgent  string `json:"user_agent"`
		LoggedInAt string `json:"logged_in_at"`
	}

	var logins []LoginEntry
	for rows.Next() {
		var e LoginEntry
		var t time.Time
		if err := rows.Scan(&e.ID, &e.WebsiteID, &e.Domain, &e.Username, &e.ClientIP, &e.UserAgent, &t); err != nil {
			continue
		}
		e.LoggedInAt = t.In(time.FixedZone("IST", 5*3600+30*60)).Format("2/1/2006, 3:04:05 pm")
		logins = append(logins, e)
	}
	if logins == nil {
		logins = []LoginEntry{}
	}
	json.NewEncoder(w).Encode(map[string]interface{}{"logins": logins, "total": total, "page": page, "limit": limit})
}

// analyticsSwitchesHandler: GET /api/admin/analytics/switches
// Returns account switch history for websites the session has access to.
// Query params: website_id (optional), page, limit
func analyticsSwitchesHandler(w http.ResponseWriter, r *http.Request, sess *AdminSession) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	q := r.URL.Query()
	websiteIDStr := q.Get("website_id")
	page := 1
	limit := 50
	if v, err := strconv.Atoi(q.Get("page")); err == nil && v > 0 {
		page = v
	}
	if v, err := strconv.Atoi(q.Get("limit")); err == nil && v > 0 && v <= 200 {
		limit = v
	}
	offset := (page - 1) * limit

	var websiteFilter string
	var args []interface{}
	if websiteIDStr != "" {
		wid, err := strconv.Atoi(websiteIDStr)
		if err == nil && sess.HasWebsite(wid) {
			websiteFilter = "s.website_id = ?"
			args = append(args, wid)
		}
	}
	if websiteFilter == "" {
		if sess.Role == "master" {
			websiteFilter = "1=1"
		} else {
			if len(sess.Websites) == 0 {
				json.NewEncoder(w).Encode(map[string]interface{}{"switches": []interface{}{}, "total": 0})
				return
			}
			placeholders := make([]string, len(sess.Websites))
			for i, wid := range sess.Websites {
				placeholders[i] = "?"
				args = append(args, wid)
			}
			websiteFilter = "s.website_id IN (" + strings.Join(placeholders, ",") + ")"
		}
	}

	baseQ := "FROM ahrefs_switch_logs s JOIN ahrefs_websites w ON s.website_id = w.id WHERE " + websiteFilter

	var total int
	countArgs := make([]interface{}, len(args))
	copy(countArgs, args)
	_ = db.QueryRow("SELECT COUNT(*) "+baseQ, countArgs...).Scan(&total)

	args = append(args, limit, offset)
	rows, err := db.Query(
		"SELECT s.id, s.website_id, w.domain, COALESCE(s.username,''), COALESCE(s.from_account_name,''), COALESCE(s.to_account_name,''), COALESCE(s.reason,''), s.switched_at "+baseQ+" ORDER BY s.switched_at DESC LIMIT ? OFFSET ?",
		args...,
	)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}
	defer rows.Close()

	type SwitchEntry struct {
		ID              int    `json:"id"`
		WebsiteID       int    `json:"website_id"`
		Domain          string `json:"domain"`
		Username        string `json:"username"`
		FromAccountName string `json:"from_account_name"`
		ToAccountName   string `json:"to_account_name"`
		Reason          string `json:"reason"`
		SwitchedAt      string `json:"switched_at"`
	}

	var switches []SwitchEntry
	for rows.Next() {
		var e SwitchEntry
		var t time.Time
		if err := rows.Scan(&e.ID, &e.WebsiteID, &e.Domain, &e.Username, &e.FromAccountName, &e.ToAccountName, &e.Reason, &t); err != nil {
			continue
		}
		e.SwitchedAt = t.In(time.FixedZone("IST", 5*3600+30*60)).Format("2/1/2006, 3:04:05 pm")
		switches = append(switches, e)
	}
	if switches == nil {
		switches = []SwitchEntry{}
	}
	json.NewEncoder(w).Encode(map[string]interface{}{"switches": switches, "total": total, "page": page, "limit": limit})
}

// ── GET INDEX STATIC HTML ────────────────────────────────────────────────────
// Serves the full single page control panel built using premium light theme css and pure js.
func getAdminDashboardHTML() string {
	data, err := os.ReadFile("index.html")
	if err != nil {
		log.Printf("[HTML] Read error: %v — trying relative execution path", err)
		return `<!DOCTYPE html><html><head><title>ToolsMandi Error</title></head><body style="font-family:sans-serif;text-align:center;padding:50px;"><h2>ToolsMandi Admin Control Panel</h2><p style="color:red;">Error loading index.html: ` + err.Error() + `</p><p>Please make sure index.html is placed in the same directory as the executable.</p></body></html>`
	}
	return string(data)
}

// ── MAIN ──────────────────────────────────────────────────────────────────────

func main() {
	cfg := loadConfig()
	initDB(cfg)

	// Background database purger goroutine (Ticks every 30s)
	go func() {
		for {
			time.Sleep(30 * time.Second)
			if db != nil {
				_, _ = db.Exec("DELETE FROM ahrefs_sessions WHERE expires_at < ?", time.Now())
				_, _ = db.Exec("DELETE FROM ahrefs_tokens WHERE expires_at < ?", time.Now())
				_, _ = db.Exec("DELETE FROM ahrefs_admin_sessions WHERE expires_at < ?", time.Now())
				// Purge analytics logs older than 30 days
				_, _ = db.Exec("DELETE FROM ahrefs_login_logs WHERE logged_in_at < DATE_SUB(NOW(), INTERVAL 30 DAY)")
				_, _ = db.Exec("DELETE FROM ahrefs_switch_logs WHERE switched_at < DATE_SUB(NOW(), INTERVAL 30 DAY)")
			}
		}
	}()

	mux := http.NewServeMux()
	mux.HandleFunc("/", adminRouter)

	addr := ":" + cfg.Port
	log.Printf("╔══════════════════════════════════════════════════╗")
	log.Printf("║  🚀 ToolsMandi Admin Control Panel               ║")
	log.Printf("║  http://localhost%s                               ║", addr)
	log.Printf("║  Database: %s                              ║", cfg.MySQLDB)
	log.Printf("║  Config: %s (hot-reload enabled ✅)         ║", CONFIG_FILE)
	log.Printf("╚══════════════════════════════════════════════════╝")

	srv := &http.Server{
		Addr:         addr,
		Handler:      mux,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
	}

	if err := srv.ListenAndServe(); err != nil {
		log.Fatalf("[FATAL] %v", err)
	}
}
