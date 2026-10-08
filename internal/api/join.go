// Package api — one-line join (E1) and agent-binary serving (E2).
//
// GET /api/v1/join/{token}          the bootstrap script (public; gated by
//
//	                                 the one-time enrollment token — the
//	                                 same credential the manual recipe and
//	                                 SSH provisioning use, validated
//	                                 without consumption: only the agent's
//	                                 actual enrollment consumes it).
//	?arch=amd64|arm64                render the arch-specific installer
//	                                 (stage 2; omitted → the arch-detecting
//	                                 loader, stage 1)
//	&elevate=<stored policy name>     install that elevation policy + wire
//	                                 PARTOUT_ELEVATE=sudo at join time
//	&labels=<unit,unit>              PARTOUT_SERVICE_LABELS for agent.env
//
// GET /api/v1/join/{token}/binary?arch=…  the agent binary: newest matching
//
//	release from the M8.1 release store,
//	else the server's own executable when
//	the arch matches (it is the same
//	static binary).
//
// The TLS rule: the UI only offers `curl … | sudo bash` over HTTPS (a
// plaintext fetch of a root-running script is a mid-flight-tampering
// surface); the endpoint itself stays functional for operators who know
// their network (VPN/loopback), and the script carries a warning banner
// when rendered for a plaintext base URL.
package api

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"os"
	"regexp"
	"runtime"
	"time"

	"github.com/blawesom/partout/internal/agent/elevate"
	"github.com/blawesom/partout/internal/agent/facts"
	"github.com/blawesom/partout/internal/server/provision"
	"github.com/blawesom/partout/internal/version"
)

// joinLabelsRe constrains the service-labels query param before it is
// embedded in a shell script (defense in depth: it is also quoted).
var joinLabelsRe = regexp.MustCompile(`^[A-Za-z0-9,_.\-]*$`)

// RegisterJoin adds the join routes (public; the enrollment token is the
// credential) and the elevation-bootstrap routes (P1: mint is admin, the
// script fetch is gated by the one-time host-scoped token).
func (h *Handler) RegisterJoin(mux *http.ServeMux) {
	mux.Handle("GET /api/v1/join/{token}", http.HandlerFunc(h.handleJoinScript))
	mux.Handle("GET /api/v1/join/{token}/binary", http.HandlerFunc(h.handleJoinBinary))
	mux.Handle("POST /api/v1/hosts/{id}/elevation/bootstrap", h.requireRole(roleAdmin)(http.HandlerFunc(h.handleElevationBootstrapMint)))
	mux.Handle("GET /api/v1/elevate/{token}", http.HandlerFunc(h.handleElevateScript))
}

// validateJoinToken checks the enrollment token without consuming it.
func (h *Handler) validateJoinToken(plain string) bool {
	sum := sha256.Sum256([]byte(plain))
	if err := h.st.ValidateEnrollmentToken(hex.EncodeToString(sum[:])); err != nil {
		return false
	}
	return true
}

// baseURL derives the scheme://host the TARGET host can reach: it just
// fetched this response from there, so r.Host is reachable by construction.
func (h *Handler) baseURL(r *http.Request) string {
	scheme := "http"
	if h.ca != nil {
		scheme = "https"
	}
	return scheme + "://" + r.Host
}

// scriptHeaders sets the response headers for served shell scripts.
func scriptHeaders(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "text/x-shellscript; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Cache-Control", "no-store")
}

// handleJoinScript serves the one-line join flow: stage 1 (arch-detecting
// loader) when no arch is given, or the arch-specific stage-2 installer.
func (h *Handler) handleJoinScript(w http.ResponseWriter, r *http.Request) {
	token := r.PathValue("token")
	if !h.validateJoinToken(token) {
		writeError(w, http.StatusUnauthorized, "invalid_token", "join token unknown, expired, or already used", nil)
		return
	}
	base := h.baseURL(r)

	arch := r.URL.Query().Get("arch")
	if arch == "" {
		elevate := r.URL.Query().Get("elevate")
		labels := r.URL.Query().Get("labels")
		if elevate != "" {
			// The policy name must resolve BEFORE it is embedded in a
			// shell script (it is server-validated content, not operator
			// free text).
			if _, err := h.resolveJoinPolicy(elevate); err != nil {
				writeError(w, http.StatusBadRequest, "bad_request", "elevate: unknown policy", nil)
				return
			}
		}
		if !joinLabelsRe.MatchString(labels) {
			writeError(w, http.StatusBadRequest, "bad_request", "labels: invalid characters", nil)
			return
		}
		h.audit("join.script", "public", map[string]string{
			"token_mask": token[:14], "elevate": elevate, "labels": labels,
		})
		scriptHeaders(w)
		_, _ = w.Write([]byte(provision.BuildJoinLoader(base, token, elevate, labels)))
		return
	}

	if arch != "amd64" && arch != "arm64" {
		writeError(w, http.StatusBadRequest, "bad_request", "arch must be amd64 or arm64", nil)
		return
	}
	elevateName := r.URL.Query().Get("elevate")
	labels := r.URL.Query().Get("labels")
	if !joinLabelsRe.MatchString(labels) {
		writeError(w, http.StatusBadRequest, "bad_request", "labels: invalid characters", nil)
		return
	}
	var policies []provision.ElevationPolicySpec
	if elevateName != "" {
		ep, err := h.resolveJoinPolicy(elevateName)
		if err != nil {
			writeError(w, http.StatusBadRequest, "bad_request", "elevate: unknown policy", nil)
			return
		}
		policies = append(policies, ep)
	}
	bin, binSHA, binVersion, ok := h.resolveAgentBinary(arch)
	if !ok {
		writeError(w, http.StatusNotFound, "no_binary",
			"no agent binary for arch "+arch+" (upload a release on the Updates page, or install from GitHub releases)", nil)
		return
	}
	_ = bin // not served here; only its fingerprint is embedded
	var caPEM string
	if h.ca != nil {
		caPEM = h.ca.CertPEM()
	}
	script, err := provision.BuildJoinScript(provision.JoinScriptInput{
		BaseURL: base, Token: token, Arch: arch,
		BinSHA: binSHA, BinVersion: binVersion,
		CAPEM: caPEM, Policies: policies,
		ServiceLabels: labels,
		ServerPubB64:  h.ctrl.ServerPubB64(),
	})
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal_error", "failed to render join script", nil)
		return
	}
	h.audit("join.script.arch", "public", map[string]string{
		"token_mask": token[:14], "arch": arch, "elevate": elevateName,
		"bin_sha12": binSHA[:12], "bin_version": binVersion,
	})
	scriptHeaders(w)
	_, _ = w.Write([]byte(script))
}

// resolveJoinPolicy resolves a stored elevation policy by name into the
// canonical spec the installer verifies (same canonicalization as the
// provisioning flow — a hand-formatted document must normalize or the
// on-host sha256 gate correctly rejects it).
func (h *Handler) resolveJoinPolicy(name string) (provision.ElevationPolicySpec, error) {
	p, err := h.st.ElevationPolicy(name)
	if err != nil {
		return provision.ElevationPolicySpec{}, err
	}
	pol, err := elevate.LoadPolicyJSON([]byte(`{"rules":` + p.RulesJSON + `}`))
	if err != nil {
		return provision.ElevationPolicySpec{}, err
	}
	canonical := marshalRules(pol)
	return provision.ElevationPolicySpec{
		Name: p.Name, RulesJSON: canonical, SHA: pol.PolicyHash(),
	}, nil
}

// handleJoinBinary serves the agent binary for an arch: the newest agent
// release in the store, else the server's own executable when the arch
// matches (same static binary — the join flow works without any release
// upload, and on dev builds too).
func (h *Handler) handleJoinBinary(w http.ResponseWriter, r *http.Request) {
	token := r.PathValue("token")
	if !h.validateJoinToken(token) {
		writeError(w, http.StatusUnauthorized, "invalid_token", "join token unknown, expired, or already used", nil)
		return
	}
	arch := r.URL.Query().Get("arch")
	if arch != "amd64" && arch != "arm64" {
		writeError(w, http.StatusBadRequest, "bad_request", "arch must be amd64 or arm64", nil)
		return
	}
	data, sha, version, ok := h.resolveAgentBinary(arch)
	if !ok {
		writeError(w, http.StatusNotFound, "no_binary",
			"no agent binary for arch "+arch+" (upload a release on the Updates page, or install from GitHub releases)", nil)
		return
	}
	h.audit("join.binary", "public", map[string]string{
		"token_mask": token[:14], "arch": arch, "sha12": sha[:12], "version": version,
	})
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("X-Partout-Sha256", sha)
	w.Header().Set("X-Partout-Version", version)
	w.Header().Set("Content-Length", itoa(len(data)))
	_, _ = w.Write(data)
}

// resolveAgentBinary finds the binary to install for arch: the newest
// agent-kind release in the M8.1 store matching the arch, else the server's
// own executable when the arch matches.
func (h *Handler) resolveAgentBinary(arch string) (data []byte, sha, ver string, ok bool) {
	rels, err := h.st.ListAgentReleases()
	if err == nil {
		best := ""
		bestID := ""
		for _, m := range rels {
			if m.Arch != "linux-"+arch && m.Arch != arch {
				continue
			}
			if best == "" || version.Compare(m.Version, best) > 0 {
				best, bestID = m.Version, m.ID
			}
		}
		if bestID != "" {
			if rel, err := h.st.GetRelease(bestID); err == nil && len(rel.Artifact) > 0 {
				return rel.Artifact, rel.SHA256, rel.Version, true
			}
		}
	}
	// Fall back to the running server binary (same static binary, all
	// modes). Only valid when the arch matches.
	if arch == runtime.GOARCH {
		if exe, err := os.Executable(); err == nil {
			if b, err := os.ReadFile(exe); err == nil && len(b) > 0 {
				sum := sha256.Sum256(b)
				return b, hex.EncodeToString(sum[:]), facts.Version, true
			}
		}
	}
	return nil, "", "", false
}

// itoa avoids importing strconv for one call.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}

// marshalRules renders the canonical compact rules JSON (the same
// canonicalization the provisioning flow performs before transfer).
func marshalRules(p *elevate.Policy) string {
	b, _ := json.Marshal(p.Rules)
	return string(b)
}

// ---- elevation bootstrap (P1) ----------------------------------------------

const elevateTokenPrefix = "par_elev_"

// elevateBootstrapBody is the mint request for the one-line elevation
// enablement.
type elevateBootstrapBody struct {
	Policy string `json:"policy"` // stored policy name; default default-baseline
}

// handleElevationBootstrapMint mints a one-time, host-scoped token and
// returns the URL of the bootstrap script the operator pastes ON the host.
func (h *Handler) handleElevationBootstrapMint(w http.ResponseWriter, r *http.Request) {
	agentID := r.PathValue("id")
	ag, err := h.st.Agent(agentID)
	if err != nil || ag == nil {
		writeError(w, http.StatusNotFound, "not_found", "host not found", nil)
		return
	}
	var body elevateBootstrapBody
	if r.Body != nil {
		_ = json.NewDecoder(r.Body).Decode(&body)
	}
	if body.Policy == "" {
		body.Policy = "default-baseline"
	}
	ep, err := h.resolveJoinPolicy(body.Policy)
	if err != nil {
		writeError(w, http.StatusBadRequest, "bad_request", "unknown elevation policy "+body.Policy, nil)
		return
	}
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		writeError(w, http.StatusInternalServerError, "internal_error", "token generation failed", nil)
		return
	}
	plain := elevateTokenPrefix + hex.EncodeToString(raw)
	sum := sha256.Sum256([]byte(plain))
	if err := h.st.CreateElevationToken(hex.EncodeToString(sum[:]), agentID, body.Policy, 900); err != nil {
		writeError(w, http.StatusInternalServerError, "internal_error", "token creation failed", nil)
		return
	}
	principal, _ := h.actorFor(r)
	h.audit("elevation.bootstrap.mint", principal, map[string]string{
		"agent_id": agentID, "policy": body.Policy, "policy_sha12": ep.SHA[:12],
	})
	writeJSON(w, http.StatusOK, map[string]any{
		"token":   plain,
		"url":     h.baseURL(r) + "/api/v1/elevate/" + plain,
		"policy":  body.Policy,
		"expires": time.Now().Add(15 * time.Minute).Unix(),
	})
}

// handleElevateScript serves the one-line elevation bootstrap for an
// already-enrolled host: the token is consumed on fetch (single serve; the
// mint dialog re-mints in one click), the policy is re-resolved from the
// store at fetch time (mint-fresh content), and the script carries a
// hostname guard so a paste on the wrong host aborts.
func (h *Handler) handleElevateScript(w http.ResponseWriter, r *http.Request) {
	token := r.PathValue("token")
	sum := sha256.Sum256([]byte(token))
	agentID, policyName, ok, err := h.st.ConsumeElevationToken(hex.EncodeToString(sum[:]))
	if err != nil || !ok {
		writeError(w, http.StatusUnauthorized, "invalid_token", "elevation bootstrap token unknown, expired, or already served", nil)
		return
	}
	ep, err := h.resolveJoinPolicy(policyName)
	if err != nil {
		writeError(w, http.StatusGone, "gone", "policy "+policyName+" no longer exists — re-mint the bootstrap", nil)
		return
	}
	hostname := ""
	if fl, err := h.st.LatestFacts(agentID); err == nil {
		hostname = fl.Data["host.hostname"]
	}
	script, err := provision.BuildElevationBootstrapScript(provision.ElevationBootstrapInput{
		Hostname: hostname, PolicyName: ep.Name, RulesJSON: ep.RulesJSON, SHA: ep.SHA,
		ServerPubB64: h.ctrl.ServerPubB64(),
	})
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal_error", "failed to render bootstrap script", nil)
		return
	}
	h.audit("elevation.bootstrap.script", agentID, map[string]string{
		"policy": policyName, "policy_sha12": ep.SHA[:12], "token_mask": token[:14],
	})
	scriptHeaders(w)
	_, _ = w.Write([]byte(script))
}
