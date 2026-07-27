package proxysecurity

import "net/http"

// CloudflareRequestOK returns false when CF-Ray is required but missing.
func CloudflareRequestOK(r *http.Request, ss Config, tool ToolContext, dbToggle bool) bool {
	ss = Normalize(ss, tool)
	cf := ss.Cloudflare
	if !Enabled(ss, tool, dbToggle) || !cf.Enabled || !cf.RequireCFRay {
		return true
	}
	if r == nil {
		return false
	}
	return r.Header.Get("CF-Ray") != ""
}
