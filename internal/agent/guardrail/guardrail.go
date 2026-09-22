// Package guardrail implements the agent-side policy re-check
// (architecture §5.3).  When the server pushes a policy bundle and signs a
// decision for each dispatched command, the agent verifies (a) the decision
// signature, (b) that the decision's bundle version matches its cached
// bundle, and (c) re-evaluates the rule set over the local action.  Any
// mismatch → deny, emit ACK_DENIED_AGENT.
package guardrail

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync/atomic"

	"github.com/blawesom/partout/internal/policy"
	pb "github.com/blawesom/partout/internal/proto"
)

// Guard is the agent-side policy cache + evaluator.  It is populated when the
// server pushes a POLICY_BUNDLE and then consulted for every COMMAND envelope.
// The agent is single-streamed, so no locking is needed: bundle updates and
// command re-checks both happen on the stream goroutine.
type Guard struct {
	agentID     string // this agent's id (for host:<id> predicates)
	version     uint64
	rules       []policy.Rule
	contentHash string
	serverPub   []byte            // Ed25519 public key (raw 32 bytes)
	hostTags    map[string]string // this agent's tags (from the bundle)
	hostRoles   []string          // this agent's roles (from the bundle)
	loaded      atomic.Bool
	policyDir   string
}

// NewGuard creates a guard for agentID backed by policyDir (the agent's
// policy dir).
func NewGuard(agentID, policyDir string) *Guard {
	return &Guard{agentID: agentID, policyDir: policyDir}
}

// Load reads the persisted bundle + server public key from disk so the guard
// is effective from agent start (survives restarts).
func (g *Guard) Load() error {
	// Rules.
	rulesData, err := os.ReadFile(filepath.Join(g.policyDir, "policy.json"))
	if err != nil {
		return nil // no persisted bundle — first POLICY_BUNDLE envelope will populate.
	}
	var rules []policy.Rule
	if err := json.Unmarshal(rulesData, &rules); err != nil {
		return fmt.Errorf("guardrail: parse rules: %w", err)
	}
	g.rules = rules
	// Meta (version / content_hash / received_unix).
	if meta, err := os.ReadFile(filepath.Join(g.policyDir, "policy.meta")); err == nil {
		g.version, g.contentHash = parseMeta(string(meta))
	}
	// Server public key.
	if pub, err := os.ReadFile(filepath.Join(g.policyDir, "server.pub")); err == nil && len(pub) > 0 {
		g.serverPub = pub
	}
	g.loaded.Store(true)
	return nil
}

// OnBundle stores a policy bundle pushed by the server and persists it.
func (g *Guard) OnBundle(b *pb.PolicyBundle) {
	g.version = b.Version
	g.contentHash = b.ContentHash
	if b.RulesJson != "" {
		if err := json.Unmarshal([]byte(b.RulesJson), &g.rules); err != nil {
			return
		}
	}
	if len(b.ServerPubkey) > 0 {
		// The bundle carries the server public key base64-encoded; decode it.
		if decoded, err := base64.StdEncoding.DecodeString(string(b.ServerPubkey)); err == nil {
			g.serverPub = decoded
		} else {
			g.serverPub = b.ServerPubkey // fall back to raw bytes if not b64
		}
	}
	g.hostTags = b.HostTags
	g.hostRoles = b.HostRoles
	if b.AgentId != "" {
		g.agentID = b.AgentId
	}
	g.loaded.Store(true)
	g.persist()
}

// Recheck verifies a command's Decision against the cached bundle and rule
// set (architecture §5.3).  Returns (allow, reason).  Fails closed:
// no bundle received → deny; no decision → deny; signature invalid → deny;
// local evaluation disagrees → deny.  An empty rule set is a valid
// default-allow state (the policy is a deny-list).
func (g *Guard) Recheck(cmd *pb.Command) (bool, string) {
	if !g.loaded.Load() {
		return false, "guardrail: no policy bundle received"
	}
	d := cmd.Decision
	if d == nil {
		return false, "guardrail: no decision in command"
	}
	// (b) bundle version must match the cached bundle.
	if d.BundleVersion != g.version {
		return false, fmt.Sprintf("guardrail: bundle version mismatch (decision=%d cached=%d)",
			d.BundleVersion, g.version)
	}
	// (a) verify the decision signature (when the server public key is known).
	if len(g.serverPub) > 0 {
		if !policy.VerifyDecision(g.serverPub, d.RunId, d.BundleVersion,
			d.Effect, d.MatchedRules, d.ActorRole, d.Sig) {
			return false, "guardrail: decision signature invalid"
		}
	}
	// (c) re-evaluate the rule set over the local action (the bundle
	// carries this agent's tags/roles; the decision carries the actor role).
	action := policy.Action{
		HostID:      g.agentID,
		HostTags:    g.hostTags,
		HostRoles:   g.hostRoles,
		ActorRole:   d.ActorRole,
		Cmd:         cmd.Cmd,
		Args:        cmd.Args,
		CommandLine: commandLine(cmd.Cmd, cmd.Args),
	}
	dec := policy.Evaluate(g.rules, action)
	if dec.Effect != policy.EffectAllow {
		return false, fmt.Sprintf("guardrail: local recheck says %s (%s)",
			dec.Effect, dec.Reason)
	}
	// (d) the server's own decision must be allow.
	if d.Effect != policy.EffectAllow {
		return false, fmt.Sprintf("guardrail: server decision is %s", d.Effect)
	}
	return true, ""
}

// ServerPubB64 returns the base64-encoded server public key (empty if unknown).
func (g *Guard) ServerPubB64() string {
	if len(g.serverPub) == 0 {
		return ""
	}
	return base64.StdEncoding.EncodeToString(g.serverPub)
}

// BundleVersion returns the cached bundle version.
func (g *Guard) BundleVersion() uint64 { return g.version }

// Loaded reports whether a policy bundle has been received/persisted.
func (g *Guard) Loaded() bool { return g.loaded.Load() }

// persist writes the bundle + server public key to the policy dir.
func (g *Guard) persist() {
	if err := os.MkdirAll(g.policyDir, 0o700); err != nil {
		return
	}
	rulesJSON, err := json.Marshal(g.rules)
	if err != nil {
		return
	}
	_ = os.WriteFile(filepath.Join(g.policyDir, "policy.json"), rulesJSON, 0o600)
	meta := fmt.Sprintf("version=%d\ncontent_hash=%s\n", g.version, g.contentHash)
	_ = os.WriteFile(filepath.Join(g.policyDir, "policy.meta"), []byte(meta), 0o600)
	if len(g.serverPub) > 0 {
		_ = os.WriteFile(filepath.Join(g.policyDir, "server.pub"), g.serverPub, 0o644)
	}
}

func commandLine(cmd string, args []string) string {
	parts := make([]string, 0, len(args)+1)
	parts = append(parts, cmd)
	parts = append(parts, args...)
	return joinStrings(parts, " ")
}

func joinStrings(parts []string, sep string) string {
	out := ""
	for i, p := range parts {
		if i > 0 {
			out += sep
		}
		out += p
	}
	return out
}

// parseMeta parses the "version=N\ncontent_hash=H\n" meta file.
func parseMeta(s string) (uint64, string) {
	var version uint64
	var hash string
	for _, line := range splitLines(s) {
		if v, ok := prefix(line, "version="); ok {
			fmt.Sscanf(v, "%d", &version)
		}
		if h, ok := prefix(line, "content_hash="); ok {
			hash = h
		}
	}
	return version, hash
}

func splitLines(s string) []string {
	var out []string
	cur := ""
	for _, c := range s {
		if c == '\n' {
			out = append(out, cur)
			cur = ""
		} else {
			cur += string(c)
		}
	}
	if cur != "" {
		out = append(out, cur)
	}
	return out
}

func prefix(s, p string) (string, bool) {
	if len(s) < len(p) {
		return "", false
	}
	return s[len(p):], s[:len(p)] == p
}
