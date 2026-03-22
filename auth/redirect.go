package main

import (
	"net/url"
	"strings"
)

// validateRedirectURI checks if uri matches any of the allowed patterns.
// Matching compares scheme, host, and port. A "*" in the port position
// of a pattern matches any port. URLs with userinfo are always rejected.
func validateRedirectURI(uri string, patterns []string) bool {
	parsed, err := url.Parse(uri)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return false
	}
	if parsed.User != nil {
		return false
	}

	uriScheme := parsed.Scheme
	uriHost := parsed.Hostname()
	uriPort := parsed.Port()

	for _, pattern := range patterns {
		pScheme, pHost, pPort, ok := parsePattern(pattern)
		if !ok {
			continue
		}

		if uriScheme != pScheme {
			continue
		}
		if !strings.EqualFold(uriHost, pHost) {
			continue
		}
		if pPort == "*" || pPort == uriPort {
			return true
		}
	}
	return false
}

// parsePattern extracts scheme, host, and port from a pattern string.
// The port may be "*" to indicate wildcard matching. Returns ok=false
// if the pattern cannot be parsed or has no scheme/host.
func parsePattern(pattern string) (scheme, host, port string, ok bool) {
	// Detect and strip "scheme://" prefix manually to handle wildcard port.
	schemeEnd := strings.Index(pattern, "://")
	if schemeEnd < 0 {
		return
	}
	scheme = pattern[:schemeEnd]
	rest := pattern[schemeEnd+3:]

	// rest is "host", "host:port", or "host:*"
	// Split on the last ":" to separate host from port.
	if idx := strings.LastIndex(rest, ":"); idx >= 0 {
		host = rest[:idx]
		port = rest[idx+1:]
	} else {
		host = rest
		port = ""
	}

	if scheme == "" || host == "" {
		return
	}
	ok = true
	return
}
