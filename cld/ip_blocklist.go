package main

import (
	"log"
	"net/http"
	"strings"
	"sync"
	"time"
)

var (
	blockedIPsMu sync.RWMutex
	blockedIPs   = map[string]struct{}{}
)

func refreshBlockedIPsFromDB() {
	if !dbConnected {
		return
	}
	rows, err := db.Query(
		"SELECT client_ip FROM ahrefs_blocked_ips WHERE website_id IN (0, ?)",
		currentWebsiteID,
	)
	if err != nil {
		return
	}
	defer rows.Close()
	next := map[string]struct{}{}
	for rows.Next() {
		var ip string
		if err := rows.Scan(&ip); err == nil {
			ip = strings.TrimSpace(ip)
			if ip != "" {
				next[ip] = struct{}{}
			}
		}
	}
	blockedIPsMu.Lock()
	blockedIPs = next
	blockedIPsMu.Unlock()
}

func startBlockedIPRefreshLoop() {
	refreshBlockedIPsFromDB()
	go func() {
		for {
			time.Sleep(30 * time.Second)
			refreshBlockedIPsFromDB()
		}
	}()
}

func isClientIPBlocked(ip string) bool {
	ip = strings.TrimSpace(ip)
	if ip == "" {
		return false
	}
	blockedIPsMu.RLock()
	_, ok := blockedIPs[ip]
	blockedIPsMu.RUnlock()
	return ok
}

func rejectIfIPBlocked(w http.ResponseWriter, r *http.Request, cfg Config) bool {
	if !dbConnected {
		return false
	}
	ip := realClientIP(r)
	if !isClientIPBlocked(ip) {
		return false
	}
	log.Printf("[SECURITY] Blocked IP rejected | ip=%s path=%s", ip, r.URL.Path)
	recordSecurityEvent(r, "", "ip_blocked", "banned_ip="+ip)
	accept := r.Header.Get("Accept")
	if strings.Contains(accept, "text/html") {
		renderAccessDeniedPage(w, cfg)
	} else {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"error":"ip_blocked","message":"Your IP has been blocked."}`))
	}
	return true
}
