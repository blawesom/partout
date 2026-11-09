// Package api — static web UI serving (ui-guidelines S0, hard constraint 1).
//
// The embedded SPA is served same-origin on the main listener. REST/SSE/gRPC
// live under their explicit routes (/api/..., /healthz, /readyz); any other
// GET request is the SPA — an asset, or index.html for the client-side
// router (so deep links and refreshes work). We wrap the API router rather
// than register a "GET /" mux pattern, which would conflict with the
// unmethod-scoped /api/v1/events route (Go 1.22+ ServeMux).
package api

import (
	"bytes"
	"io"
	"net/http"
	"path"
	"strconv"
	"strings"

	"github.com/blawesom/partout/internal/agent/facts"
	"github.com/blawesom/partout/internal/api/webui"
)

// RegisterStatic installs the SPA in front of the API mux. It must be called
// after every API route is registered (it reassigns h.router).
func (h *Handler) RegisterStatic() {
	api := h.router
	h.router = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := r.URL.Path
		// API namespace (including the bare /api), the health probes, and
		// the machine-readable stubs (openapi.json) are never the SPA;
		// everything else GET is. A bare /api must not be served the SPA
		// document, which would mislead a client expecting JSON.
		if r.Method == http.MethodGet &&
			p != "/api" && !strings.HasPrefix(p, "/api/") && p != "/healthz" && p != "/readyz" && p != "/openapi.json" {
			h.serveUI(w, r)
			return
		}
		api.ServeHTTP(w, r)
	})
}

// serveUI resolves the request path against the embedded FS, serving the
// document for asset paths and the SPA entry (index.html) for everything
// else — the client-side router takes it from there.
func (h *Handler) serveUI(w http.ResponseWriter, r *http.Request) {
	p := path.Clean(strings.TrimPrefix(r.URL.Path, "/"))
	if p == "" || p == "." || p == "index.html" {
		writeUI(w, "text/html; charset=utf-8", h.indexHTML())
		return
	}

	f, err := webui.FS().Open(p)
	if err == nil {
		defer f.Close()
		st, err := f.Stat()
		if err == nil && !st.IsDir() {
			data, rerr := io.ReadAll(f)
			if rerr == nil {
				w.Header().Set("Content-Type", contentType(p))
				w.Header().Set("Cache-Control", "no-cache")
				w.Header().Set("Content-Length", strconv.Itoa(len(data)))
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write(data)
				return
			}
		}
	}

	// Not an asset → SPA route (client router).
	writeUI(w, "text/html; charset=utf-8", h.indexHTML())
}

// indexHTML serves the SPA entry document with the build stamp filled in:
// versioned release builds get content="release", which makes app.js keep the
// window.__partout / window.__partoutTerm debug hooks (and the bearer token
// they expose) out of the page. Dev builds ("0.0.0-dev" etc.) keep "dev" so
// the headless smoke harness can drive the app.
func (h *Handler) indexHTML() []byte {
	b := webui.IndexHTML()
	if isReleaseVersion(facts.Version) {
		return bytes.Replace(b, []byte(`name="partout-build" content="dev"`),
			[]byte(`name="partout-build" content="release"`), 1)
	}
	return b
}

// isReleaseVersion reports whether v is a stamped release semver (set via
// -ldflags at release time), as opposed to a dev build ("0.0.0-dev").
func isReleaseVersion(v string) bool {
	if v == "" {
		return false
	}
	parts := strings.Split(v, ".")
	if len(parts) != 3 {
		return false
	}
	for _, p := range parts {
		if p == "" {
			return false
		}
		for _, c := range p {
			if c < '0' || c > '9' {
				return false
			}
		}
	}
	return true
}

// contentType picks the MIME type for the asset kinds the SPA ships.
func contentType(p string) string {
	switch {
	case strings.HasSuffix(p, ".html"):
		return "text/html; charset=utf-8"
	case strings.HasSuffix(p, ".js"):
		return "text/javascript; charset=utf-8"
	case strings.HasSuffix(p, ".css"):
		return "text/css; charset=utf-8"
	default:
		return "application/octet-stream"
	}
}

func writeUI(w http.ResponseWriter, ctype string, body []byte) {
	w.Header().Set("Content-Type", ctype)
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Content-Length", strconv.Itoa(len(body)))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(body)
}
