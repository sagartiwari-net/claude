package proxysecurity

import (
	"net"
	"strings"
)

// ValidateOTTClientIP checks handshake token IP vs /access request IP.
// soft = /16 (Jio/Airtel rotation), soft24 = /24, strict = exact.
func ValidateOTTClientIP(tokenIP, requestIP string, ss Config, tool ToolContext, dbToggle bool) (ok bool, mode string) {
	ss = Normalize(ss, tool)
	mode = ss.OTTIPValidation.Mode
	if !Enabled(ss, tool, dbToggle) || !ss.OTTIPValidation.Enabled {
		return true, mode
	}
	tokenIP = NormalizeClientIP(strings.TrimSpace(tokenIP))
	requestIP = NormalizeClientIP(strings.TrimSpace(requestIP))
	if tokenIP == "" || requestIP == "" {
		return true, mode
	}

	// Dual-stack: member area (e.g. amzpremiumsoftware.com) often records IPv6 while
	// chat subdomain behind Cloudflare/nginx reports IPv4 for the same user.
	if mode != "strict" && IPv4IPv6DualStack(tokenIP, requestIP) {
		return true, mode
	}

	switch mode {
	case "strict":
		return tokenIP == requestIP, mode
	case "soft24":
		return SameSubnet24(tokenIP, requestIP), mode
	default:
		return SameSubnet16(tokenIP, requestIP), mode
	}
}

// IPv4IPv6DualStack returns true when one IP is IPv4 and the other is IPv6 (same user, dual-stack ISP).
func IPv4IPv6DualStack(a, b string) bool {
	pa, pb := net.ParseIP(a), net.ParseIP(b)
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
