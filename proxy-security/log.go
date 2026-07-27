package proxysecurity

import (
	"net/http"
	"net/url"
	"strings"
)

// SecurityEvent is passed to the proxy's DB writer callback.
type SecurityEvent struct {
	WebsiteID    int
	Username     string
	ClientIP     string
	EventType    string
	AttemptedURL string
	Details      string
	UserAgent    string
}

// EventRecorder writes security events to persistent storage (MySQL via proxy callback).
type EventRecorder func(e SecurityEvent)

// SanitizeAttemptedURL redacts sensitive query params (e.g. OTT token).
func SanitizeAttemptedURL(path, rawQuery string) string {
	u := path
	if rawQuery != "" {
		u += "?" + rawQuery
	}
	if len(u) > 500 {
		u = u[:500]
	}
	if !strings.Contains(u, "token=") {
		return u
	}
	parts := strings.SplitN(u, "?", 2)
	if len(parts) != 2 {
		return u
	}
	vals, err := url.ParseQuery(parts[1])
	if err != nil {
		return parts[0] + "?token=***"
	}
	if vals.Get("token") != "" {
		vals.Set("token", "***")
	}
	return parts[0] + "?" + vals.Encode()
}

// RequestAttemptedURL builds a sanitized URL from an HTTP request.
func RequestAttemptedURL(r *http.Request) string {
	if r == nil || r.URL == nil {
		return ""
	}
	return SanitizeAttemptedURL(r.URL.Path, r.URL.RawQuery)
}

// RecordEvent builds a SecurityEvent from an HTTP request and invokes the recorder.
func RecordEvent(recorder EventRecorder, websiteID int, r *http.Request, username, eventType, details string) {
	if recorder == nil || websiteID == 0 || eventType == "" {
		return
	}
	clientIP := ""
	attemptedURL := ""
	userAgent := ""
	if r != nil {
		clientIP = RealClientIP(r)
		attemptedURL = RequestAttemptedURL(r)
		userAgent = r.UserAgent()
	}
	if len(details) > 255 {
		details = details[:255]
	}
	if len(username) > 100 {
		username = username[:100]
	}
	recorder(SecurityEvent{
		WebsiteID:    websiteID,
		Username:     username,
		ClientIP:     clientIP,
		EventType:    eventType,
		AttemptedURL: attemptedURL,
		Details:      details,
		UserAgent:    userAgent,
	})
}
