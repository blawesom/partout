// Package api is the REST v1 handler layer (PRD §10). Handlers are thin: they
// parse/validate payloads, call into control/observe/store, and return JSON
// or SSE streams.
package api

import (
	"log"
	"net/http"

	"github.com/blawesom/partout/internal/certutil"
	"github.com/blawesom/partout/internal/control"
	"github.com/blawesom/partout/internal/server/files"
	"github.com/blawesom/partout/internal/server/packages"
	"github.com/blawesom/partout/internal/server/jobs"
	"github.com/blawesom/partout/internal/server/tasks"
	"github.com/blawesom/partout/internal/server/externaldata"
	serversecrets "github.com/blawesom/partout/internal/server/secrets"
	"github.com/blawesom/partout/internal/server/provision"
	"github.com/blawesom/partout/internal/server/sessions"
	"github.com/blawesom/partout/internal/server/stream"
	"github.com/blawesom/partout/internal/sse"
	"github.com/blawesom/partout/internal/store"
)

// Handler wraps the server-side resources and serves REST endpoints.
type Handler struct {
	st     *store.Store
	ctrl   *control.Control
	prov   *provision.Provisioner
	files      *files.Controller
	pkgs       *packages.Controller
	tasks      *tasks.Controller
	jobs       *jobs.Controller
	sess       *sessions.Manager
	secretsMgr *serversecrets.Manager
	extdata    *externaldata.Refresher
	sse        *sse.Broker
	log    *log.Logger
	router http.Handler
	auth   *auth
	ca     *certutil.CA // TLS root CA; nil when the server runs in plaintext mode
}

// New builds the REST handler and its router.
func New(st *store.Store, h *stream.Handler, sseB *sse.Broker, lg *log.Logger) *Handler {
	if lg == nil {
		lg = log.Default()
	}
	ctrl := control.New(st, h, sseB, lg)
	handler := &Handler{st: st, ctrl: ctrl, sse: sseB, log: lg}
	mux := http.NewServeMux()

	// REST v1 endpoints (PRD §10).
	handler.RegisterExecutions(mux)
	handler.RegisterHosts(mux)
	handler.RegisterPolicies(mux)

	// GET /api/v1/events — SSE event stream.
	mux.Handle("/api/v1/events", sseB)

	// GET /healthz — health check.
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})

	// GET /readyz — readiness check.
	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		if err := st.DB().PingContext(ctx); err != nil {
			writeError(w, http.StatusServiceUnavailable, "not_ready", "not ready", nil)
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"status": "ready"})
	})

	// Enrollment (PRD R2).
	handler.RegisterEnrollment(mux)

	// Host provisioning (PRD R17, arch §3.5) — admin-gated routes are
	// registered lazily once a provisioner is installed (see SetProvisioner).
	handler.RegisterProvision(mux)

	// TLS CA bootstrap (public material, admin-gated for convenience).
	mux.Handle("GET /api/v1/tls/ca", handler.requireRole(roleAdmin)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if handler.ca == nil {
			writeError(w, http.StatusServiceUnavailable, "tls_disabled",
				"server is not running in TLS mode", nil)
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"cert": handler.ca.CertPEM()})
	})))

	// M2: files + sessions (PRD §5.3, §5.2.2).
	handler.RegisterFiles(mux)
	handler.RegisterSessions(mux)

	// M3: packages (PRD §5.6).
	handler.RegisterPackages(mux)

	// M3: tasks + playbooks (PRD §5.5).
	handler.RegisterTasks(mux)

	// M3: scheduled jobs (PRD §5.4).
	handler.RegisterJobs(mux)

	// M3: secrets (PRD §5.7). Routes 503 until a master key is installed.
	handler.RegisterSecrets(mux)

	// M3: external data status/refresh (PRD §6.3).
	handler.RegisterExternalData(mux)

	handler.router = mux
	return handler
}

// ServeHTTP implements http.Handler.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.router.ServeHTTP(w, r)
}

// SetAuth configures the RBAC bearer tokens. Must be called before serving.
// If all are empty, the server runs in single-user local mode.
func (h *Handler) SetAuth(admin, operator, viewer string) {
	h.auth = newAuth(admin, operator, viewer)
}

// SetTLS installs the root CA used to sign agent enrollment certs. When the
// server runs in plaintext mode this is not called.
func (h *Handler) SetTLS(ca *certutil.CA) {
	h.ca = ca
}

// SetProvisioner installs the host-provisioning engine. When nil (or never
// called), the provisioning endpoints return 503.
func (h *Handler) SetProvisioner(p *provision.Provisioner) {
	h.prov = p
}

// SetFiles installs the files controller (M2, PRD §5.3).
func (h *Handler) SetFiles(fc *files.Controller) { h.files = fc }

// SetPkgs installs the packages controller (M3, PRD §5.6).
func (h *Handler) SetPkgs(pc *packages.Controller) { h.pkgs = pc }

// SetTasks installs the tasks controller (M3, PRD §5.5).
func (h *Handler) SetTasks(tc *tasks.Controller) { h.tasks = tc }

// SetJobs installs the jobs controller (M3, PRD §5.4).
func (h *Handler) SetJobs(jc *jobs.Controller) { h.jobs = jc }

// SetSessions installs the sessions manager (M2, PRD §5.2.2).
func (h *Handler) SetSessions(sm *sessions.Manager) { h.sess = sm }

// SetExternalData installs the EOL/vuln refresher (M3, PRD §6.3).
func (h *Handler) SetExternalData(r *externaldata.Refresher) { h.extdata = r }

// Store returns the underlying store (for tests).
func (h *Handler) Store() *store.Store {
	return h.st
}

// Control returns the control plane (for main.go to install the server
// signing identity).
func (h *Handler) Control() *control.Control {
	return h.ctrl
}
