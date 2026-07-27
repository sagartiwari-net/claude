package proxysecurity

import (
	"encoding/json"
	"fmt"
	"net/http"
)

// ApplySecurityHeaders sets anti-embed and referrer headers.
func ApplySecurityHeaders(w http.ResponseWriter, ss Config, tool ToolContext, dbToggle bool) {
	ss = Normalize(ss, tool)
	if !Enabled(ss, tool, dbToggle) {
		return
	}
	if ss.Headers.XFrameOptions != "" {
		w.Header().Set("X-Frame-Options", ss.Headers.XFrameOptions)
	}
	if ss.Headers.CSPFrameAncestors != "" {
		w.Header().Set("Content-Security-Policy", "frame-ancestors "+ss.Headers.CSPFrameAncestors)
	}
	w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
}

// CorsOrigin returns the allowed CORS origin for this tool.
func CorsOrigin(ss Config, tool ToolContext) string {
	ss = Normalize(ss, tool)
	if ss.Headers.CorsAllowOrigin != "" {
		return ss.Headers.CorsAllowOrigin
	}
	if tool.PublicScheme != "" && tool.PublicHost != "" {
		return tool.PublicScheme + "://" + tool.PublicHost
	}
	return ""
}

// BuildDomainCheckJS returns delayed domain-check script HTML (Layer 6).
func BuildDomainCheckJS(ss Config, tool ToolContext, dbToggle bool) string {
	ss = Normalize(ss, tool)
	dc := ss.DomainCheck
	if !Enabled(ss, tool, dbToggle) || !dc.Enabled {
		return ""
	}
	expected := dc.ExpectedHost
	if expected == "" {
		expected = tool.PublicHost
	}
	if expected == "" {
		return ""
	}
	allowedJSON, _ := json.Marshal(dc.AllowedHosts)
	delayMs := dc.DelaySeconds * 1000
	recheckMs := dc.RecheckIntervalSeconds * 1000
	immediate := dc.ImmediateCheck || dc.DelaySeconds <= 0
	action := dc.Action
	if action == "" {
		action = "logout"
	}
	immediateBlock := ""
	if immediate {
		immediateBlock = "if(!checkDomain())return;"
	}
	return fmt.Sprintf(`<script>
(function(){
  var EXPECTED=%q;
  var ALLOWED=%s;
  var DELAY=%d;
  var RECHECK=%d;
  var ACTION=%q;
  function hostOK(h){
    h=(h||"").toLowerCase();
    var e=EXPECTED.toLowerCase();
    if(h===e||h.endsWith("."+e))return true;
    for(var i=0;i<ALLOWED.length;i++){
      var a=(ALLOWED[i]||"").toLowerCase();
      if(h===a||h.endsWith("."+a))return true;
    }
    return false;
  }
  function checkDomain(){
    if(hostOK(window.location.hostname))return true;
    if(ACTION==="logout"){window.location.href="/user/logout";return false;}
    document.body.innerHTML="<h1 style=\"font-family:sans-serif;text-align:center;margin-top:20vh\">Unauthorized mirror detected</h1>";
    return false;
  }
  %s
  setTimeout(function(){
    if(!checkDomain())return;
    if(RECHECK>0)setInterval(checkDomain,RECHECK);
  },DELAY);
})();
</script>`, expected, string(allowedJSON), delayMs, recheckMs, action, immediateBlock)
}

// BuildSecurityHeartbeatJS pings the proxy API; PHP mirrors on foreign domains fail (no valid /api/security-ping).
func BuildSecurityHeartbeatJS(ss Config, tool ToolContext, dbToggle bool) string {
	ss = Normalize(ss, tool)
	hb := ss.SecurityHeartbeat
	if !Enabled(ss, tool, dbToggle) || !hb.Enabled {
		return ""
	}
	intervalMs := hb.IntervalSeconds * 1000
	if intervalMs < 15000 {
		intervalMs = 45000
	}
	return fmt.Sprintf(`<script>
(function(){
  var IV=%d;
  var FAILS=0;
  var MAX_FAILS=3;
  function ping(){
    fetch("/api/security-ping",{credentials:"include",cache:"no-store"}).then(function(r){
      if(!r.ok){
        FAILS++;
        if(FAILS>=MAX_FAILS){window.location.href="/user/logout";}
      }else{FAILS=0;}
    }).catch(function(){
      FAILS++;
      if(FAILS>=MAX_FAILS){window.location.href="/user/logout";}
    });
  }
  setInterval(ping,IV);
  setTimeout(ping,5000);
})();
</script>`, intervalMs)
}
