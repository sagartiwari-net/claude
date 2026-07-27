package proxysecurity

import (
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// RealClientIP returns the client IP, preferring CF-Connecting-IP when present.
func RealClientIP(r *http.Request) string {
	if r == nil {
		return ""
	}
	if ip := r.Header.Get("CF-Connecting-IP"); ip != "" {
		return NormalizeClientIP(strings.TrimSpace(ip))
	}
	if ip := r.Header.Get("X-Real-IP"); ip != "" {
		return NormalizeClientIP(strings.TrimSpace(ip))
	}
	if ip := r.Header.Get("X-Forwarded-For"); ip != "" {
		return preferIPv4FromList(ip)
	}
	host, _, _ := net.SplitHostPort(r.RemoteAddr)
	return NormalizeClientIP(host)
}

// preferIPv4FromList returns the first IPv4 in a comma-separated header, else the first IP.
func preferIPv4FromList(header string) string {
	var fallback string
	for _, part := range strings.Split(header, ",") {
		raw := strings.TrimSpace(part)
		if raw == "" {
			continue
		}
		if fallback == "" {
			fallback = raw
		}
		if p := net.ParseIP(raw); p != nil && p.To4() != nil && len(p) == net.IPv4len {
			return p.To4().String()
		}
	}
	if fallback != "" {
		return NormalizeClientIP(fallback)
	}
	return ""
}

// NormalizeClientIP collapses IPv4-mapped IPv6 (::ffff:x.x.x.x) to plain IPv4 so
// concurrent /16 tracking does not treat one user as two subnets.
func NormalizeClientIP(ip string) string {
	ip = strings.TrimSpace(ip)
	if p := net.ParseIP(ip); p != nil {
		if v4 := p.To4(); v4 != nil {
			return v4.String()
		}
		return p.String()
	}
	return ip
}

// IPv4Prefix16 returns the first two octets of an IPv4 address.
// For IPv6, uses the first 4 hextets (/64) so the same user is not counted twice
// when requests flip between IPv4 and IPv6.
func IPv4Prefix16(ip string) string {
	ip = NormalizeClientIP(ip)
	if p := net.ParseIP(ip); p != nil {
		if v4 := p.To4(); v4 != nil {
			return fmt.Sprintf("%d.%d", v4[0], v4[1])
		}
		if len(p) == net.IPv6len {
			return fmt.Sprintf("%02x%02x:%02x%02x:%02x%02x:%02x%02x",
				p[0], p[1], p[2], p[3], p[4], p[5], p[6], p[7])
		}
	}
	parts := strings.Split(ip, ".")
	if len(parts) >= 2 {
		return parts[0] + "." + parts[1]
	}
	return ip
}

// SameSubnet16 returns true when both IPs share the same /16 (first two octets).
func SameSubnet16(a, b string) bool {
	a, b = strings.TrimSpace(a), strings.TrimSpace(b)
	pa, pb := net.ParseIP(a), net.ParseIP(b)
	if pa == nil || pb == nil {
		return a == b
	}
	a4, b4 := pa.To4(), pb.To4()
	if a4 == nil || b4 == nil {
		return a == b
	}
	return a4[0] == b4[0] && a4[1] == b4[1]
}

// SameSubnet24 returns true when both IPs share the same /24.
func SameSubnet24(a, b string) bool {
	a, b = strings.TrimSpace(a), strings.TrimSpace(b)
	pa, pb := net.ParseIP(a), net.ParseIP(b)
	if pa == nil || pb == nil {
		return a == b
	}
	a4, b4 := pa.To4(), pb.To4()
	if a4 == nil || b4 == nil {
		return a == b
	}
	return a4[0] == b4[0] && a4[1] == b4[1] && a4[2] == b4[2]
}

// IPTrackerState tracks soft IP grace and concurrent /16 subnets per session.
type IPTrackerState struct {
	Mu               sync.Mutex
	GraceWindowStart time.Time
	IPChangeCount    int
	SubnetSeen       map[string]time.Time
}

// IPTracker stores per-session IP state (key = session token).
type IPTracker struct {
	store sync.Map
}

// Delete removes tracking state for a session token.
func (t *IPTracker) Delete(sessionToken string) {
	if t != nil {
		t.store.Delete(sessionToken)
	}
}

// ConcurrentSubnetCount returns how many distinct /16 prefixes were seen in the window.
func (t *IPTracker) ConcurrentSubnetCount(sessionToken string) int {
	if t == nil {
		return 0
	}
	raw, ok := t.store.Load(sessionToken)
	if !ok {
		return 0
	}
	state, ok := raw.(*IPTrackerState)
	if !ok {
		return 0
	}
	state.Mu.Lock()
	defer state.Mu.Unlock()
	return len(state.SubnetSeen)
}

// CheckSessionIP implements Layer 2 soft IP stickiness + concurrent /16 kill.
func CheckSessionIP(tracker *IPTracker, sessionToken, currentIP, sessionIP string, ipCfg IPProtectionConfig) (updatedIP string, allow bool, kill bool) {
	if !ipCfg.Enabled || ipCfg.Mode != "soft" {
		return sessionIP, true, false
	}
	if SameSubnet24(currentIP, sessionIP) {
		return sessionIP, true, false
	}

	now := time.Now()
	window := time.Duration(ipCfg.ConcurrentWindowSeconds) * time.Second
	cur16 := IPv4Prefix16(currentIP)

	raw, _ := tracker.store.LoadOrStore(sessionToken, &IPTrackerState{
		GraceWindowStart: now,
		SubnetSeen:       map[string]time.Time{},
	})
	state := raw.(*IPTrackerState)
	state.Mu.Lock()
	defer state.Mu.Unlock()

	state.SubnetSeen[cur16] = now
	for k, t := range state.SubnetSeen {
		if now.Sub(t) > window {
			delete(state.SubnetSeen, k)
		}
	}

	if ipCfg.ConcurrentKillEnabled && len(state.SubnetSeen) >= 2 {
		return sessionIP, false, true
	}

	if now.Sub(state.GraceWindowStart) > 30*time.Minute {
		state.GraceWindowStart = now
		state.IPChangeCount = 0
	}
	if state.IPChangeCount < ipCfg.GraceChangesPer30Min {
		state.IPChangeCount++
		return currentIP, true, false
	}

	return sessionIP, false, true
}
