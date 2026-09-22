// Package api — enrollment endpoints (PRD R2).
//
// POST /api/v1/agents/enrollment-tokens  (operator) — create a one-time token.
// POST /api/v1/agents/enroll             (agent)    — present a token + keys to register.
package api

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/blawesom/partout/internal/id"
	"github.com/blawesom/partout/internal/store"
)

const tokenPrefix = "par_enr_"

// RegisterEnrollment adds the enrollment routes to the mux.
//
// POST /api/v1/agents/enrollment-tokens is operator-gated (RBAC). The agent
// enroll endpoint is public: the agent authenticates with its one-time token
// (it has no bearer yet).
func (h *Handler) RegisterEnrollment(mux *http.ServeMux) {
	mux.Handle("POST /api/v1/agents/enrollment-tokens", h.requireRole(roleOperator)(http.HandlerFunc(h.handleCreateEnrollmentToken)))
	mux.Handle("POST /api/v1/agents/enroll", http.HandlerFunc(h.handleEnroll))
}

// ---- operator: create a token --------------------------------------------

// createTokenRequest is the JSON body for creating an enrollment token.
type createTokenRequest struct {
	TTLS int `json:"ttl_s"` // seconds; default 900
}

// createTokenResponse returns the token once (it is never retrievable again).
type createTokenResponse struct {
	Token   string `json:"token"`
	Mask    string `json:"mask"`
	Expires int64  `json:"expires"`
}

func (h *Handler) handleCreateEnrollmentToken(w http.ResponseWriter, r *http.Request) {
	var req createTokenRequest
	if r.Body != nil {
		json.NewDecoder(r.Body).Decode(&req)
	}
	if req.TTLS <= 0 {
		req.TTLS = 900
	}

	// Generate a random 32-byte token.
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	plain := tokenPrefix + hex.EncodeToString(raw)
	hash := sha256.Sum256([]byte(plain))
	hashHex := hex.EncodeToString(hash[:])
	mask := plain[:14] // first 14 chars (includes prefix)

	if err := h.st.CreateEnrollmentToken(hashHex, mask, req.TTLS); err != nil {
		http.Error(w, "create token: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Audit.
	h.audit("enroll.token.create", "operator", map[string]string{
		"mask":  mask,
		"ttl_s": fmt.Sprint(req.TTLS),
	})

	resp := createTokenResponse{
		Token:   plain,
		Mask:    mask,
		Expires: time.Now().Unix() + int64(req.TTLS),
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// ---- agent: enroll with a token ------------------------------------------

// enrollRequest is the JSON body the agent sends to register.
type enrollRequest struct {
	Token        string            `json:"token"`
	UUID         string            `json:"uuid"`
	ED25519Pub   string            `json:"ed25519_pub"` // base64
	X25519Pub    string            `json:"x25519_pub"`  // base64
	AgentVersion string            `json:"agent_version"`
	Facts        map[string]string `json:"facts"`
	CSR          string            `json:"csr"` // PEM CSR for the agent's local TLS key (TLS mode)
}

// enrollResponse is returned on successful enrollment.
type enrollResponse struct {
	AgentID string     `json:"agent_id"`
	UUID    string     `json:"uuid"`
	TLS     *enrollTLS `json:"tls,omitempty"`
}

// enrollTLS carries the mTLS material for an agent (only in TLS mode).
type enrollTLS struct {
	CACert   string `json:"ca_cert"`   // PEM — trust anchor
	LeafCert string `json:"leaf_cert"` // PEM — the agent's signed leaf (CN=agent_id)
}

func (h *Handler) handleEnroll(w http.ResponseWriter, r *http.Request) {
	var req enrollRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request: "+err.Error(), http.StatusBadRequest)
		return
	}

	if req.Token == "" || req.UUID == "" || req.ED25519Pub == "" {
		http.Error(w, "token, uuid, ed25519_pub required", http.StatusBadRequest)
		return
	}

	// Consume the token (single-use).
	hash := sha256.Sum256([]byte(req.Token))
	hashHex := hex.EncodeToString(hash[:])
	ok, err := h.st.ConsumeEnrollmentToken(hashHex)
	if err != nil {
		// Unknown or expired token.
		http.Error(w, "invalid token", http.StatusUnauthorized)
		return
	}
	if !ok {
		http.Error(w, "token already used or invalid", http.StatusUnauthorized)
		return
	}

	// Create the agent row.
	agentID := id.New("ag")
	version := req.AgentVersion
	if version == "" {
		version = "unknown"
	}
	if err := h.st.UpsertAgent(store.Agent{
		ID:         agentID,
		UUID:       req.UUID,
		ED25519Pub: req.ED25519Pub,
		X25519Pub:  req.X25519Pub,
		Version:    version,
		State:      "pending",
	}); err != nil {
		http.Error(w, "create agent: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Link this enrollment to a provisioning run (if the token was created
	// by the provisioner). The run's agent_id is set so step 5
	// (wait-enroll) can detect completion.
	if runID, err := h.st.ProvisionRunForToken(hashHex); err == nil && runID != "" {
		if err := h.st.LinkProvisionRunAgent(runID, agentID); err == nil {
			h.log.Printf("enroll: linked agent %s to provision run %s", agentID, runID)
		}
	}

	// Store initial facts.
	if len(req.Facts) > 0 {
		if err := h.st.UpsertFacts(store.Facts{
			AgentID: agentID,
			TS:      time.Now().Unix(),
			Data:    req.Facts,
		}); err != nil {
			h.log.Printf("enroll: upsert facts %s: %v", agentID, err)
		}
	}

	// Audit.
	h.audit("enroll.agent.create", "agent", map[string]string{
		"agent_id": agentID,
		"uuid":     req.UUID,
		"tls":      fmt.Sprint(req.CSR != ""),
	})

	resp := enrollResponse{AgentID: agentID, UUID: req.UUID}

	// Issue the agent's mTLS leaf cert (only in TLS mode).
	if h.ca != nil {
		if req.CSR == "" {
			// Roll the agent row back — enrollment is all-or-nothing. A TLS-mode
			// server cannot serve an agent that has no leaf cert.
			_ = h.st.DeleteAgent(agentID)
			writeError(w, http.StatusBadRequest, "bad_request",
				"server is in TLS mode: enrollment requires a CSR for the agent's local TLS key", nil)
			return
		}
		leafPEM, err := h.ca.SignAgentCert([]byte(req.CSR), agentID)
		if err != nil {
			_ = h.st.DeleteAgent(agentID)
			writeError(w, http.StatusInternalServerError, "internal_error",
				"failed to sign agent TLS cert: "+err.Error(), nil)
			return
		}
		resp.TLS = &enrollTLS{CACert: h.ca.CertPEM(), LeafCert: leafPEM}
		if h.log != nil {
			h.log.Printf("enroll: issued TLS leaf cert for %s", agentID)
		}
	}

	if h.sse != nil {
		h.sse.Emit("host.state", map[string]string{"agent_id": agentID, "state": "enrolled"})
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// audit appends an audit row.
func (h *Handler) audit(kind, actor string, payload map[string]string) {
	b, _ := json.Marshal(payload)
	h.st.AppendAudit(store.AuditEvent{
		TS:      time.Now().Unix(),
		Kind:    kind,
		Actor:   actor,
		Payload: string(b),
	})
}
