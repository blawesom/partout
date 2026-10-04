// Package api is the REST v1 handler layer (PRD §10). Handlers are thin: they
// parse/validate payloads, call into control/observe/store, and return JSON
// or SSE streams.
package api

import (
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/blawesom/partout/internal/agent/facts"
	"github.com/blawesom/partout/internal/certutil"
	"github.com/blawesom/partout/internal/control"
	"github.com/blawesom/partout/internal/release"
	serverapprovals "github.com/blawesom/partout/internal/server/approvals"
	"github.com/blawesom/partout/internal/server/assistant"
	serverauth "github.com/blawesom/partout/internal/server/auth"
	"github.com/blawesom/partout/internal/server/externaldata"
	"github.com/blawesom/partout/internal/server/files"
	"github.com/blawesom/partout/internal/server/jobs"
	"github.com/blawesom/partout/internal/server/oauth"
	"github.com/blawesom/partout/internal/server/packages"
	"github.com/blawesom/partout/internal/server/provision"
	serversecrets "github.com/blawesom/partout/internal/server/secrets"
	"github.com/blawesom/partout/internal/server/sessions"
	"github.com/blawesom/partout/internal/server/stream"
	"github.com/blawesom/partout/internal/server/tasks"
	"github.com/blawesom/partout/internal/server/updates"
	"github.com/blawesom/partout/internal/sse"
	"github.com/blawesom/partout/internal/store"
)

// Handler wraps the server-side resources and serves REST endpoints.
type Handler struct {
	st                *store.Store
	ctrl              *control.Control
	prov              *provision.Provisioner
	files             *files.Controller
	pkgs              *packages.Controller
	tasks             *tasks.Controller
	jobs              *jobs.Controller
	approvals         *serverapprovals.Controller
	oauthC            *oauth.Manager
	mcpWired          bool // true once HandleMCP registered the /mcp route
	sess              *sessions.Manager
	secretsMgr        *serversecrets.Manager
	extdata           *externaldata.Refresher
	sse               *sse.Broker
	log               *log.Logger
	router            http.Handler   // final router (API mux + SPA static wrapper)
	mux               *http.ServeMux // the API mux (routes register here, pre-wrapper)
	auth              *auth
	authC             *serverauth.Controller // local user identity (PRD Decision 6); nil until set
	usersActive       bool                   // true once the principals table is non-empty
	ca                *certutil.CA           // TLS root CA; nil when the server runs in plaintext mode
	streamH           *stream.Handler        // stream handler (for mTLS leaf rotation)
	updatesMgr        *updates.Manager       // M8.1 rollout orchestrator
	allowUnsigned     bool                   // GA: unsigned releases accepted only when PARTOUT_ALLOW_UNSIGNED_RELEASES=true (default false = signed-only)
	releaseVerifyKey  ed25519.PublicKey      // optional: verify upload signatures at registration (PARTOUT_RELEASE_VERIFY_KEY); nil = store-and-forward
	autoDraftRollouts bool                   // M8.1.1: auto-draft a parked rollout on agent release upload
	assistant         *assistant.Service     // R26 LLM assistant; nil until SetAssistant (routes 503)
	secretsKeyPath    string                 // data-dir default master-key file (UI bootstrap target; empty = no bootstrap)
	backupDir         string                 // snapshot destination for POST /server/backup; empty = endpoint 503
}

// New builds the REST handler and its router.
func New(st *store.Store, h *stream.Handler, sseB *sse.Broker, lg *log.Logger) *Handler {
	if lg == nil {
		lg = log.Default()
	}
	ctrl := control.New(st, h, sseB, lg)
	handler := &Handler{st: st, ctrl: ctrl, sse: sseB, log: lg, streamH: h}
	mux := http.NewServeMux()

	// REST v1 endpoints (PRD §10).
	handler.RegisterExecutions(mux)
	handler.RegisterHosts(mux)
	handler.RegisterPolicies(mux)
	handler.RegisterPreset(mux)
	handler.RegisterObserve(mux)

	// GET /api/v1/events — SSE event stream (PRD R10). Auth-gated: mirrors the
	// read surface it exposes (executions/output/audit/hosts), so any
	// authenticated role may subscribe. Accepts ?token= (EventSource cannot set
	// headers) in addition to the Authorization header.
	mux.Handle("/api/v1/events", handler.requireSSE(roleViewer)(sseB))

	// GET /healthz — health check.
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})

	// GET /openapi.json — honest 501 (PRD §10.1: "Full OpenAPI spec is a
	// later deliverable"). Without this route the SPA fallback served
	// HTML at a .json path — a content-type lie for every automated
	// consumer that probed it.
	mux.HandleFunc("GET /openapi.json", func(w http.ResponseWriter, r *http.Request) {
		writeError(w, http.StatusNotImplemented, "not_implemented",
			"the OpenAPI spec is a post-1.0 deliverable; the REST surface is documented in PRD §10.1 and docs/deployment.md", nil)
	})

	// GET /api/v1/version — server version (same value `partout --version`
	// prints). Public metadata, like /healthz.
	mux.HandleFunc("GET /api/v1/version", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"version": facts.Version})
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

	// POST /api/v1/tls/rotate (admin) — re-sign an agent's mTLS leaf now.
	// Body: {"agent_id": "ag_..."} or {"all": true} (rotate every connected
	// TLS agent). Returns the new leaf serial(s).
	mux.Handle("POST /api/v1/tls/rotate", handler.requireRole(roleAdmin)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if handler.ca == nil {
			writeError(w, http.StatusServiceUnavailable, "tls_disabled",
				"server is not running in TLS mode", nil)
			return
		}
		var body struct {
			AgentID string `json:"agent_id"`
			All     bool   `json:"all"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil && err.Error() != "EOF" {
			writeError(w, http.StatusBadRequest, "bad_request", err.Error(), nil)
			return
		}
		if body.All {
			agents, _ := handler.st.Agents()
			n := 0
			for _, a := range agents {
				if a.TlsPub == "" {
					continue
				}
				if _, err := handler.streamH.RotateAgentCert(a.ID); err == nil {
					n++
				}
			}
			handler.audit("tls.rotate", "admin", map[string]string{"scope": "all", "rotated": fmt.Sprint(n)})
			writeJSON(w, http.StatusOK, map[string]any{"rotated": n})
			return
		}
		if body.AgentID == "" {
			writeError(w, http.StatusBadRequest, "bad_request", "agent_id or all required", nil)
			return
		}
		serial, err := handler.streamH.RotateAgentCert(body.AgentID)
		if err != nil {
			writeError(w, http.StatusConflict, "rotate_failed", err.Error(), nil)
			return
		}
		handler.audit("tls.rotate", "admin", map[string]string{"agent_id": body.AgentID, "serial": serial})
		writeJSON(w, http.StatusOK, map[string]string{"agent_id": body.AgentID, "serial": serial})
	})))

	// GET /api/v1/tls/status (viewer) — per-agent mTLS leaf expiry.
	mux.Handle("GET /api/v1/tls/status", handler.requireRole(roleViewer)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		agents, err := handler.st.Agents()
		if err != nil {
			writeError(w, http.StatusInternalServerError, "internal_error", err.Error(), nil)
			return
		}
		type row struct {
			AgentID  string `json:"agent_id"`
			TLS      bool   `json:"tls"`
			NotAfter int64  `json:"not_after,omitempty"`
			DaysLeft int64  `json:"days_left,omitempty"`
			State    string `json:"state"`
		}
		out := make([]row, 0, len(agents))
		for _, a := range agents {
			r := row{AgentID: a.ID, State: a.State}
			if a.TlsPub != "" {
				r.TLS = true
				r.NotAfter = a.TlsNotAfter
				r.DaysLeft = (a.TlsNotAfter - time.Now().Unix()) / 86400
			}
			out = append(out, r)
		}
		writeJSON(w, http.StatusOK, map[string]any{"tls": handler.ca != nil, "agents": out})
	})))

	// M2: files + sessions (PRD §5.3, §5.2.2).
	handler.RegisterFiles(mux)
	handler.RegisterSessions(mux)

	// M3: packages (PRD §5.6).
	handler.RegisterPackages(mux)

	// M5.1: security scan (CVE detection).
	handler.RegisterSecurity(mux)

	// M8.1: update release store (PRD §11).
	handler.RegisterUpdates(mux)

	// M3: tasks + playbooks (PRD §5.5).
	handler.RegisterTasks(mux)

	// M3: scheduled jobs (PRD §5.4).
	handler.RegisterJobs(mux)

	// M4: approvals engine (PRD §5.8). Routes 503 until SetApprovals.
	handler.RegisterApprovals(mux)

	// M4: MCP self-description (R11). Read-only catalog for the UI's MCP page.
	handler.RegisterMCP(mux)

	// M4: OAuth2 (PKCE) for the MCP HTTP transport (R11, A20) + client
	// registry. Routes 503 until SetOAuth installs the manager.
	handler.RegisterOAuth(mux)

	// M6: alert engine (PRD R23/R25). Read/list routes; rule CRUD.
	handler.RegisterAlerts(mux)

	// M3: secrets (PRD §5.7). Routes 503 until a master key is installed.
	handler.RegisterSecrets(mux)

	// R26: LLM assistant (M9). Routes 503 until SetAssistant installs the
	// service (endpoint config + sessions + SSE chat).
	handler.RegisterAssistant(mux)

	// M3: external data status/refresh (PRD §6.3).
	handler.RegisterExternalData(mux)

	// Local user identity (PRD Decision 6): login/logout/me/password +
	// admin user management.
	handler.RegisterAuth(mux)

	// Capability probe for the UI's data-driven gating (ui-guidelines B1).
	handler.RegisterCapabilities(mux)

	// Ops plane: control-plane backup trigger (admin).
	mux.Handle("POST /api/v1/server/backup", handler.requireRole(roleAdmin)(http.HandlerFunc(handler.handleServerBackup)))

	handler.router = mux
	handler.mux = mux

	// Embedded web UI (ui-guidelines S0). Wraps the API mux: any GET that
	// isn't an API/health route serves the SPA. Installed last so it sees a
	// fully-populated router.
	handler.RegisterStatic()

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

// SetUpdates installs the M8.1 rollout orchestrator.
func (h *Handler) SetUpdates(m *updates.Manager) { h.updatesMgr = m }

// SetAllowUnsignedReleases sets the GA policy for unsigned releases
// (PARTOUT_ALLOW_UNSIGNED_RELEASES; default false = signed-only).
func (h *Handler) SetAllowUnsignedReleases(v bool) { h.allowUnsigned = v }

// SetReleaseVerifyKey sets the optional registration-time signature check
// (PARTOUT_RELEASE_VERIFY_KEY, base64 Ed25519 public key). Empty disables it.
func (h *Handler) SetReleaseVerifyKey(pubB64 string) {
	h.releaseVerifyKey = nil
	if strings.TrimSpace(pubB64) == "" {
		return
	}
	if pub, err := release.PubKeyFromB64(pubB64); err == nil {
		h.releaseVerifyKey = pub
	} else if h.log != nil {
		h.log.Printf("api: PARTOUT_RELEASE_VERIFY_KEY is not a valid Ed25519 public key: %v", err)
	}
}

// SetAutoDraftRollouts sets the M8.1.1 policy: when true, uploading an
// agent-kind release also creates a parked draft rollout awaiting start.
func (h *Handler) SetAutoDraftRollouts(v bool) { h.autoDraftRollouts = v }

// SetSessions installs the sessions manager (M2, PRD §5.2.2).
func (h *Handler) SetSessions(sm *sessions.Manager) { h.sess = sm }

// SetExternalData installs the EOL/vuln refresher (M3, PRD §6.3).
func (h *Handler) SetExternalData(r *externaldata.Refresher) { h.extdata = r }

// HandleMCP registers the MCP Streamable HTTP endpoint (POST /mcp, R11).
// The caller's bearer token (Authorization header) is forwarded to the
// control plane for every tool call, so RBAC + policy + audit attribute
// actions to the caller exactly as the REST API does. Read tools are
// usable by any authenticated role (viewer+); write tools enforce their
// own role gates at the REST layer (a refusal is returned as a structured
// tool error).
func (h *Handler) HandleMCP(mcpSrv http.Handler) {
	// Register on the API mux directly (h.router is the SPA-wrapped router
	// after RegisterStatic; POSTs fall through the wrapper to the mux).
	if h.mux == nil {
		h.log.Printf("api: HandleMCP before router built; /mcp not registered")
		return
	}
	h.mux.Handle("POST /mcp", h.requireRole(roleViewer)(mcpSrv))
	h.mcpWired = true
}

// SetAuthController installs the local-user identity controller (PRD
// Decision 6). Session tokens become valid bearer credentials alongside
// the static env tokens; once a user exists, unauthenticated requests are
// rejected (the single-user local-mode exemption is lifted).
func (h *Handler) SetAuthController(c *serverauth.Controller) {
	h.authC = c
	if active, err := h.st.AnyPrincipal(); err == nil {
		h.usersActive = active
	}
}

// Store returns the underlying store (for tests).
func (h *Handler) Store() *store.Store {
	return h.st
}

// Control returns the control plane (for main.go to install the server
// signing identity).
func (h *Handler) Control() *control.Control {
	return h.ctrl
}
