package proxysecurity

import (
	_ "embed"
	"encoding/json"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"

	"github.com/oschwald/maxminddb-golang"
)

//go:embed data/hosting_asns.json
var defaultHostingASNsJSON []byte

type anonymousIPRecord struct {
	IsAnonymous       bool `maxminddb:"is_anonymous"`
	IsAnonymousVPN    bool `maxminddb:"is_anonymous_vpn"`
	IsHostingProvider bool `maxminddb:"is_hosting_provider"`
	IsPublicProxy     bool `maxminddb:"is_public_proxy"`
	IsTorExitNode     bool `maxminddb:"is_tor_exit_node"`
}

type asnRecord struct {
	AutonomousSystemNumber       uint32 `maxminddb:"autonomous_system_number"`
	AutonomousSystemOrganization string `maxminddb:"autonomous_system_organization"`
}

// ScoreEngine performs local MMDB lookups (no per-request API calls).
type ScoreEngine struct {
	mu              sync.Mutex
	db              *maxminddb.Reader
	dbPath          string
	scoreMode       string
	hostingASN      map[uint32]bool
	hostingASNsPath string
}

// InitScoreEngine opens the MMDB and loads hosting ASN list when datacenter score is enabled.
func InitScoreEngine(ss Config, tool ToolContext) *ScoreEngine {
	ss = Normalize(ss, tool)
	dc := ss.DatacenterScore
	if !dc.Enabled {
		return nil
	}
	e := &ScoreEngine{
		scoreMode:       dc.ScoreMode,
		hostingASNsPath: dc.HostingASNsPath,
	}
	e.loadHostingASNs()
	path := dc.MMDBPath
	if path == "" {
		return e
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.db != nil && e.dbPath == path {
		return e
	}
	if e.db != nil {
		_ = e.db.Close()
		e.db = nil
	}
	if _, err := os.Stat(path); err != nil {
		log.Printf("[proxy-security] MMDB not found at %s — datacenter score inactive until file is added", path)
		return e
	}
	db, err := maxminddb.Open(path)
	if err != nil {
		log.Printf("[proxy-security] MMDB open failed: %v", err)
		return e
	}
	e.db = db
	e.dbPath = path
	log.Printf("[proxy-security] MMDB loaded: %s mode=%s ✅", path, e.scoreMode)
	return e
}

func (e *ScoreEngine) loadHostingASNs() {
	if e == nil {
		return
	}
	e.hostingASN = map[uint32]bool{}
	path := e.hostingASNsPath
	raw := defaultHostingASNsJSON
	if path != "" {
		if b, err := os.ReadFile(path); err == nil && len(b) > 0 {
			raw = b
		}
	}
	var asns []int
	if err := json.Unmarshal(raw, &asns); err != nil {
		return
	}
	for _, n := range asns {
		if n > 0 {
			e.hostingASN[uint32(n)] = true
		}
	}
}

func (e *ScoreEngine) lookupASN(ip string) (asnRecord, bool) {
	var rec asnRecord
	if e == nil {
		return rec, false
	}
	e.mu.Lock()
	db := e.db
	e.mu.Unlock()
	if db == nil {
		return rec, false
	}
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return rec, false
	}
	if err := db.Lookup(parsed, &rec); err != nil {
		return rec, false
	}
	return rec, true
}

func (e *ScoreEngine) lookupAnonymous(ip string) (anonymousIPRecord, bool) {
	var rec anonymousIPRecord
	if e == nil {
		return rec, false
	}
	e.mu.Lock()
	db := e.db
	e.mu.Unlock()
	if db == nil {
		return rec, false
	}
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return rec, false
	}
	if err := db.Lookup(parsed, &rec); err != nil {
		return rec, false
	}
	return rec, true
}

func (e *ScoreEngine) isHostingASN(asn uint32) bool {
	if e == nil || asn == 0 {
		return false
	}
	return e.hostingASN[asn]
}

func hostingOrgLooksLikeDC(org string) bool {
	org = strings.ToLower(org)
	keywords := []string{
		"amazon", "aws", "google", "cloud", "digitalocean", "hetzner", "ovh",
		"contabo", "linode", "vultr", "microsoft", "azure", "hosting", "datacenter",
		"data center", "server", "vps", "choopa", "leaseweb", "m247",
	}
	for _, k := range keywords {
		if strings.Contains(org, k) {
			return true
		}
	}
	return false
}

// ComputeScore returns a risk score for the request (0 = low risk).
func ComputeScore(e *ScoreEngine, r *http.Request, ss Config, tool ToolContext, dbToggle bool, hasDeviceCookie bool, concurrentIPFlag bool) int {
	ss = Normalize(ss, tool)
	dc := ss.DatacenterScore
	if !Enabled(ss, tool, dbToggle) || !dc.Enabled || e == nil {
		return 0
	}

	score := 0
	ip := RealClientIP(r)

	switch dc.ScoreMode {
	case "anonymous":
		if rec, ok := e.lookupAnonymous(ip); ok {
			if rec.IsHostingProvider {
				score += dc.PointsHosting
			}
			if rec.IsTorExitNode {
				score += dc.PointsVPN * 2
			} else if rec.IsAnonymousVPN || rec.IsPublicProxy {
				if dc.BlockVPNAlone {
					score += dc.ThresholdKill
				} else {
					score += dc.PointsVPN
				}
			}
			if rec.IsAnonymous && !rec.IsAnonymousVPN && !rec.IsPublicProxy {
				score += dc.PointsVPN / 2
			}
		}
	default:
		if rec, ok := e.lookupASN(ip); ok {
			if e.isHostingASN(rec.AutonomousSystemNumber) || hostingOrgLooksLikeDC(rec.AutonomousSystemOrganization) {
				score += dc.PointsHosting
			}
		}
	}

	if concurrentIPFlag {
		score += dc.PointsConcurrentIP
	}
	if ss.DeviceCookie.Enabled && !hasDeviceCookie {
		score += dc.PointsNoDeviceCookie
	}
	if dc.PointsForeignReferer > 0 && tool.PublicHost != "" && r != nil {
		ref := r.Header.Get("Referer")
		if ref != "" && !strings.Contains(strings.ToLower(ref), strings.ToLower(tool.PublicHost)) {
			member := tool.MemberAreaURL
			if member == "" || !strings.Contains(strings.ToLower(ref), strings.ToLower(member)) {
				score += dc.PointsForeignReferer
			}
		}
	}
	return score
}

// Close releases the MMDB reader.
func (e *ScoreEngine) Close() {
	if e == nil {
		return
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.db != nil {
		_ = e.db.Close()
		e.db = nil
	}
}
