package proxysecurity

// BuildID is logged at proxy startup to confirm deployed security library version.
const BuildID = "20260612-dualstack-ott-v2"

// ToolContext holds per-tool values used when normalizing session_security defaults.
type ToolContext struct {
	PublicHost     string
	PublicScheme   string
	MemberAreaURL  string
	BypassSecurity bool // true when cookie-file / local dev — all layers off
}

// Config is the session_security block from each tool's config.json.
type Config struct {
	Enabled              bool                  `json:"enabled"`
	SingleSessionPerUser bool                  `json:"single_session_per_user"`
	IPProtection         IPProtectionConfig    `json:"ip_protection"`
	DeviceCookie         DeviceCookieConfig    `json:"device_cookie"`
	DomainCheck          DomainCheckConfig     `json:"domain_check"`
	Headers              SecurityHeadersConfig `json:"headers"`
	OTTIPValidation      OTTIPValidationConfig `json:"ott_ip_validation"`
	DatacenterScore          DatacenterScoreConfig         `json:"datacenter_score"`
	Cloudflare               CloudflareConfig              `json:"cloudflare"`
	AccountCookieProtection  AccountCookieProtectionConfig `json:"account_cookie_protection"`
	SecurityHeartbeat        SecurityHeartbeatConfig       `json:"security_heartbeat"`
}

type OTTIPValidationConfig struct {
	Enabled bool   `json:"enabled"`
	Mode    string `json:"mode"` // soft (/16), soft24, strict
}

type DatacenterScoreConfig struct {
	Enabled              bool   `json:"enabled"`
	ScoreMode            string `json:"score_mode"` // "asn" (free GeoLite ASN) or "anonymous" (paid)
	MMDBPath             string `json:"mmdb_path"`
	HostingASNsPath      string `json:"hosting_asns_path"`
	ThresholdKill        int    `json:"threshold_kill"`
	ThresholdWarn        int    `json:"threshold_warn"`
	BlockVPNAlone        bool   `json:"block_vpn_alone"`
	PointsHosting        int    `json:"points_hosting"`
	PointsVPN            int    `json:"points_vpn"`
	PointsConcurrentIP   int    `json:"points_concurrent_ip"`
	PointsNoDeviceCookie int    `json:"points_no_device_cookie"`
	PointsForeignReferer int    `json:"points_foreign_referer"`
}

type CloudflareConfig struct {
	Enabled           bool `json:"enabled"`
	TrustConnectingIP bool `json:"trust_connecting_ip"`
	RequireCFRay      bool `json:"require_cf_ray"`
}

type IPProtectionConfig struct {
	Enabled                 bool   `json:"enabled"`
	Mode                    string `json:"mode"`
	GraceChangesPer30Min    int    `json:"grace_changes_per_30min"`
	ConcurrentKillEnabled   bool   `json:"concurrent_kill_enabled"`
	ConcurrentWindowSeconds int    `json:"concurrent_window_seconds"`
}

type DeviceCookieConfig struct {
	Enabled    bool   `json:"enabled"`
	CookieName string `json:"cookie_name"`
}

type DomainCheckConfig struct {
	Enabled                bool     `json:"enabled"`
	ExpectedHost           string   `json:"expected_host"`
	AllowedHosts           []string `json:"allowed_hosts"`
	DelaySeconds           int      `json:"delay_seconds"`
	RecheckIntervalSeconds int      `json:"recheck_interval_seconds"`
	ImmediateCheck         bool     `json:"immediate_check"`
	Action                 string   `json:"action"`
}

type SecurityHeartbeatConfig struct {
	Enabled         bool `json:"enabled"`
	IntervalSeconds int  `json:"interval_seconds"`
}

type SecurityHeadersConfig struct {
	XFrameOptions     string `json:"x_frame_options"`
	CSPFrameAncestors string `json:"csp_frame_ancestors"`
	CorsAllowOrigin   string `json:"cors_allow_origin"`
}

// Enabled reports whether security layers should run (config + ctrl DB toggle).
func Enabled(ss Config, tool ToolContext, dbToggle bool) bool {
	if tool.BypassSecurity || !dbToggle {
		return false
	}
	return Normalize(ss, tool).Enabled
}

// Normalize fills session_security defaults from tool context.
func Normalize(ss Config, tool ToolContext) Config {
	if ss.DeviceCookie.CookieName == "" {
		ss.DeviceCookie.CookieName = "tm_device"
	}
	if ss.IPProtection.GraceChangesPer30Min <= 0 {
		ss.IPProtection.GraceChangesPer30Min = 2
	}
	if ss.IPProtection.ConcurrentWindowSeconds <= 0 {
		ss.IPProtection.ConcurrentWindowSeconds = 300
	}
	if ss.IPProtection.Mode == "" {
		ss.IPProtection.Mode = "soft"
	}
	if ss.DomainCheck.DelaySeconds <= 0 {
		ss.DomainCheck.DelaySeconds = 2
	}
	if ss.DomainCheck.RecheckIntervalSeconds <= 0 {
		ss.DomainCheck.RecheckIntervalSeconds = 60
	}
	if ss.DomainCheck.Action == "" {
		ss.DomainCheck.Action = "logout"
	}
	if ss.DomainCheck.ExpectedHost == "" {
		ss.DomainCheck.ExpectedHost = tool.PublicHost
	}
	if ss.Headers.XFrameOptions == "" {
		ss.Headers.XFrameOptions = "DENY"
	}
	if ss.Headers.CSPFrameAncestors == "" {
		ss.Headers.CSPFrameAncestors = "'none'"
	}
	if ss.Headers.CorsAllowOrigin == "" && tool.PublicScheme != "" && tool.PublicHost != "" {
		ss.Headers.CorsAllowOrigin = tool.PublicScheme + "://" + tool.PublicHost
	}
	if ss.OTTIPValidation.Mode == "" {
		ss.OTTIPValidation.Mode = "soft"
	}
	dc := &ss.DatacenterScore
	if dc.ThresholdKill <= 0 {
		dc.ThresholdKill = 70
	}
	if dc.ThresholdWarn <= 0 {
		dc.ThresholdWarn = 40
	}
	if dc.PointsHosting <= 0 {
		dc.PointsHosting = 20
	}
	if dc.PointsVPN <= 0 {
		dc.PointsVPN = 15
	}
	if dc.PointsConcurrentIP <= 0 {
		dc.PointsConcurrentIP = 30
	}
	if dc.PointsNoDeviceCookie <= 0 {
		dc.PointsNoDeviceCookie = 25
	}
	if dc.PointsForeignReferer <= 0 {
		dc.PointsForeignReferer = 15
	}
	if dc.ScoreMode == "" {
		dc.ScoreMode = "asn"
	}
	if dc.MMDBPath == "" {
		if dc.ScoreMode == "anonymous" {
			dc.MMDBPath = "GeoLite2-Anonymous-IP.mmdb"
		} else {
			dc.MMDBPath = "/opt/geoip/GeoLite2-ASN.mmdb"
		}
	}
	if dc.HostingASNsPath == "" {
		dc.HostingASNsPath = "/opt/geoip/hosting_asns.json"
	}
	acp := &ss.AccountCookieProtection
	if acp.ConcurrentWindowSeconds <= 0 {
		acp.ConcurrentWindowSeconds = 300
	}
	hb := &ss.SecurityHeartbeat
	if hb.IntervalSeconds <= 0 {
		hb.IntervalSeconds = 45
	}
	return ss
}
