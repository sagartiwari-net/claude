package proxysecurity

import (
	"sync"
	"time"
)

// AccountCookieProtectionConfig detects the same premium account cookie used from multiple /16 subnets
// (PHP recloud mirrors often share stolen account cookies from ctrl panel).
type AccountCookieProtectionConfig struct {
	Enabled                 bool `json:"enabled"`
	ConcurrentKillEnabled   bool `json:"concurrent_kill_enabled"`
	ConcurrentWindowSeconds int  `json:"concurrent_window_seconds"`
}

type accountIPState struct {
	mu         sync.Mutex
	subnetSeen map[string]time.Time
}

// AccountIPTracker tracks client /16 subnets per upstream account ID.
type AccountIPTracker struct {
	store sync.Map // accountID string → *accountIPState
}

// Check returns true when concurrent /16 usage suggests account cookie sharing (recloud).
func (t *AccountIPTracker) Check(accountID int, clientIP string, cfg AccountCookieProtectionConfig) bool {
	if t == nil || accountID <= 0 || !cfg.Enabled || !cfg.ConcurrentKillEnabled {
		return false
	}
	clientIP = trimSpace(clientIP)
	if clientIP == "" {
		return false
	}
	window := time.Duration(cfg.ConcurrentWindowSeconds) * time.Second
	if window <= 0 {
		window = 5 * time.Minute
	}
	cur16 := IPv4Prefix16(clientIP)
	now := time.Now()

	key := itoa(accountID)
	raw, _ := t.store.LoadOrStore(key, &accountIPState{subnetSeen: map[string]time.Time{}})
	state := raw.(*accountIPState)
	state.mu.Lock()
	defer state.mu.Unlock()

	state.subnetSeen[cur16] = now
	for k, ts := range state.subnetSeen {
		if now.Sub(ts) > window {
			delete(state.subnetSeen, k)
		}
	}
	return len(state.subnetSeen) >= 2
}

func trimSpace(s string) string {
	for len(s) > 0 && (s[0] == ' ' || s[0] == '\t') {
		s = s[1:]
	}
	for len(s) > 0 && (s[len(s)-1] == ' ' || s[len(s)-1] == '\t') {
		s = s[:len(s)-1]
	}
	return s
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [12]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}
