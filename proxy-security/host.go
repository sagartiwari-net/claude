package proxysecurity

import (
	"net"
	"net/http"
	"strings"
)

// RequestHost returns the external host from the request (X-Forwarded-Host or Host).
func RequestHost(r *http.Request) string {
	if r == nil {
		return ""
	}
	host := r.Host
	if xh := r.Header.Get("X-Forwarded-Host"); xh != "" {
		host = strings.TrimSpace(strings.Split(xh, ",")[0])
	}
	host = strings.ToLower(host)
	if i := strings.Index(host, ":"); i != -1 {
		host = host[:i]
	}
	return host
}

// IsInternalRequestHost is true when nginx forwards to Go without the public Host header.
func IsInternalRequestHost(host string) bool {
	if host == "" {
		return true
	}
	host = strings.ToLower(host)
	if host == "localhost" || host == "::1" {
		return true
	}
	if strings.HasPrefix(host, "127.") {
		return true
	}
	if ip := net.ParseIP(host); ip != nil && (ip.IsLoopback() || ip.IsPrivate()) {
		return true
	}
	return false
}

// HostMatchesPublic checks request host against public host and optional allowed hosts.
func HostMatchesPublic(reqHost, publicHost string, allowed []string) bool {
	reqHost = strings.ToLower(strings.TrimSpace(reqHost))
	publicHost = strings.ToLower(strings.TrimSpace(publicHost))
	if i := strings.Index(publicHost, ":"); i != -1 {
		publicHost = publicHost[:i]
	}
	if i := strings.Index(reqHost, ":"); i != -1 {
		reqHost = reqHost[:i]
	}
	if reqHost == publicHost {
		return true
	}
	for _, a := range allowed {
		a = strings.ToLower(strings.TrimSpace(a))
		if a != "" && a == reqHost {
			return true
		}
	}
	return false
}
