// Package api — HTTP security headers. Applied to every response the REST
// router serves (API + embedded SPA): the UI holds a bearer token, so
// clickjacking/mime-sniffing protections matter even though the SPA itself
// never renders untrusted HTML.
package api

import (
	"net/http"
)

// csp is the Content-Security-Policy for the buildless Vue SPA. The vendored
// vue.global build compiles the inline templates at runtime, which requires
// 'unsafe-eval' in script-src; inline styles (Vue style bindings + xterm's
// inline styles) require 'unsafe-inline' in style-src. Everything else is
// locked to same-origin; framing is denied outright.
const csp = "default-src 'self'; " +
	"script-src 'self' 'unsafe-eval'; " +
	"style-src 'self' 'unsafe-inline'; " +
	"img-src 'self' data:; " +
	"font-src 'self'; " +
	"connect-src 'self'; " +
	"object-src 'none'; " +
	"base-uri 'self'; " +
	"frame-ancestors 'none'"

// setSecurityHeaders applies the baseline header set. hsts is added only when
// the server runs TLS (the api Handler knows via SetTLS) — HSTS on a plaintext
// response is ignored by browsers but misleading in headers dumps.
func (h *Handler) setSecurityHeaders(w http.ResponseWriter) {
	hdr := w.Header()
	hdr.Set("X-Content-Type-Options", "nosniff")
	hdr.Set("X-Frame-Options", "DENY")
	hdr.Set("Referrer-Policy", "no-referrer")
	hdr.Set("Content-Security-Policy", csp)
	if h.ca != nil {
		hdr.Set("Strict-Transport-Security", "max-age=31536000")
	}
}
