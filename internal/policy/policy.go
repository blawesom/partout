// Package policy implements the declarative rule model and evaluator
// (architecture §5.2). A rule matches on selector (host scope), action
// classes, actor roles, and a command regex; its effect is one of
// deny | require_approval | allow.
//
// Evaluation: all matching rules are considered.  If any deny rule matches
// → deny (with the matched rule IDs).  Otherwise require_approval.  Then allow.
//
// Default posture (v1): **allow when no rules match**.  Full default-deny
// for writes is gated on the M4 approvals engine (PRD §7).
//
// The same IR and evaluator are used server-side (dispatch gating) and
// agent-side (guardrail re-check).
package policy

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/blawesom/partout/internal/selector"
)

// Effect values.
const (
	EffectDeny            = "deny"
	EffectRequireApproval = "require_approval"
	EffectAllow           = "allow"
)

// Action classes (arch A6 taxonomy: file classes land with M2, pkg with M3).
// Rules may name a class ("file.write"), a parent class ("file"), or leave
// Actions empty (match every class).
const (
	ActionExec      = "exec"
	ActionFileRead  = "file.read"
	ActionFileWrite = "file.write"
	ActionFilePerm  = "file.perm"
	ActionPkgList   = "pkg.list"
	ActionPkgApply  = "pkg.apply"

	// M3 tasks (PRD §5.5).
	ActionTaskRun = "task.run"
)

// Priority ordering for precedence: lower number = higher priority.
const DefaultPriority = 0

// Match describes what a rule targets.
type Match struct {
	Hosts        string   `json:"hosts"`         // selector expression ("role:prod", "tag:env=lab", "all")
	Actions      []string `json:"actions"`       // action classes ("exec", "file"); empty = all
	ActorRoles   []string `json:"actor_roles"`   // RBAC roles ("admin", "operator"); empty = all
	CommandRegex string   `json:"command_regex"` // regex against "cmd args..."; empty = match any
}

// Rule is one declarative policy rule.
type Rule struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Match    Match  `json:"match"`
	Effect   string `json:"effect"`
	Priority int    `json:"priority"`
}

// Action is the concrete context an evaluator checks.
type Action struct {
	HostID      string
	HostTags    map[string]string
	HostRoles   []string
	ActorRole   string // RBAC role of the requester (viewer, operator, admin)
	Cmd         string
	Args        []string
	CommandLine string // "cmd args..." for exec; "kind path" for file actions
	// ActionClass is the class being evaluated (M2 taxonomy). Empty means
	// "exec" (legacy call sites).
	ActionClass string
	// Path is the target path for file actions.
	Path string
}

// Decision is the outcome of evaluating rules against an action.
type Decision struct {
	Effect       string   // deny | require_approval | allow
	MatchedRules []string // IDs of all matching rules (for audit)
	Reason       string   // human-readable summary
}

// Evaluate returns the decision for a given action, given a list of rules.
// Rules are evaluated in order; all matching rules are gathered, then
// precedence is applied: deny > require_approval > allow.
//
// Default-deny is NOT the v1 default — a write with no matching rule is
// allowed (the operator must explicitly deny via rules).
func Evaluate(rules []Rule, a Action) Decision {
	var denyRules, reqApproval, allowRules []string
	for _, r := range rules {
		if !matchesRule(r, a) {
			continue
		}
		switch r.Effect {
		case EffectDeny:
			denyRules = append(denyRules, r.ID)
		case EffectRequireApproval:
			reqApproval = append(reqApproval, r.ID)
		case EffectAllow:
			allowRules = append(allowRules, r.ID)
		}
	}
	if len(denyRules) > 0 {
		return Decision{
			Effect:       EffectDeny,
			MatchedRules: denyRules,
			Reason:       fmt.Sprintf("denied by rules: %s", strings.Join(denyRules, ", ")),
		}
	}
	if len(reqApproval) > 0 {
		return Decision{
			Effect:       EffectRequireApproval,
			MatchedRules: reqApproval,
			Reason:       fmt.Sprintf("require_approval by rules: %s (not yet available — M4)", strings.Join(reqApproval, ", ")),
		}
	}
	if len(allowRules) > 0 {
		return Decision{
			Effect:       EffectAllow,
			MatchedRules: allowRules,
			Reason:       fmt.Sprintf("allowed by rules: %s", strings.Join(allowRules, ", ")),
		}
	}
	return Decision{
		Effect:       EffectAllow,
		MatchedRules: nil,
		Reason:       "default allow (no matching rules)",
	}
}

func matchesRule(r Rule, a Action) bool {
	if !matchHosts(r.Match.Hosts, a) {
		return false
	}
	if !matchActions(r.Match.Actions, a) {
		return false
	}
	if !matchActorRoles(r.Match.ActorRoles, a) {
		return false
	}
	if !matchCommandRegex(r.Match.CommandRegex, a) {
		return false
	}
	return true
}

func matchHosts(hostsExpr string, a Action) bool {
	if hostsExpr == "" {
		return true // no host filter → matches all
	}
	predicates, err := selector.Parse(hostsExpr)
	if err != nil {
		return false // bad selector → treat as non-matching
	}
	// Single-host resolution: check if this host would be returned by
	// selector.Resolve against a single-host resolver.
	return selectorResolveSingle(predicates, a)
}

// selectorResolveSingle checks whether a HostInfo would be returned by
// selector.Resolve for a given set of parsed predicates.  Only
// PHost/PTag/PRole predicates are supported for single-host checks;
// PGroup is treated as non-matching (groups require store resolution).
//
// Predicates are conjunctions (AND) — all must hold.
func selectorResolveSingle(predicates []selector.Predicate, a Action) bool {
	info := selector.HostInfo{
		ID:    a.HostID,
		Tags:  a.HostTags,
		Roles: a.HostRoles,
	}
	for _, p := range predicates {
		switch p.Kind {
		case selector.PAll:
			// "all" matches everything — no filter.
			continue
		case selector.PHost:
			if info.ID != p.HostID {
				return false
			}
		case selector.PTag:
			val, ok := info.Tags[p.Key]
			if !ok {
				return false
			}
			if p.Value != "" && val != p.Value {
				return false
			}
		case selector.PRole:
			found := false
			for _, r := range info.Roles {
				if r == p.Key {
					found = true
					break
				}
			}
			if !found {
				return false
			}
		case selector.PGroup:
			// Groups require store resolution — can't evaluate here.
			// Treat as non-matching (the rule won't fire for groups).
			return false
		}
	}
	return true
}

func matchActions(actions []string, a Action) bool {
	if len(actions) == 0 {
		return true // no action filter → matches all
	}
	class := a.ActionClass
	if class == "" {
		class = ActionExec
	}
	for _, act := range actions {
		if act == class {
			return true // exact class match ("exec", "file.write", …)
		}
		// Parent class: a rule naming "file" matches any file.* class.
		if strings.HasPrefix(class, "file.") && act == "file" {
			return true
		}
	}
	return false
}

func matchActorRoles(roles []string, a Action) bool {
	if len(roles) == 0 {
		return true // no actor role filter → matches all
	}
	for _, role := range roles {
		if role == a.ActorRole {
			return true
		}
	}
	return false
}

// CompileCommandRegex validates a command regex (used by the API before
// persisting a rule so the store never holds a broken pattern).
func CompileCommandRegex(re string) (*regexp.Regexp, error) {
	if re == "" {
		return nil, nil
	}
	return regexp.Compile(re)
}

func matchCommandRegex(re string, a Action) bool {
	if re == "" {
		return true
	}
	if re == a.CommandLine {
		return true
	}
	reCompiled, err := regexp.Compile(re)
	if err != nil {
		return false // bad regex → non-matching
	}
	return reCompiled.MatchString(a.CommandLine)
}

// ---- Policy bundle (version + hash) -----------------------------------------

// BuildBundle constructs a versioned, content-hashed bundle from a list of rules.
func BuildBundle(rules []Rule) (version uint64, contentHash string, jsonStr string) {
	version = uint64(len(rules))
	jsonStr = canonicalRulesJSON(rules)
	// Hash = SHA-256 of rules JSON.
	h := sha256.Sum256([]byte(jsonStr))
	contentHash = base64.StdEncoding.EncodeToString(h[:])
	return
}

// rulesJSON serialises rules to a canonical, stable JSON string (sorted by ID).
func canonicalRulesJSON(rules []Rule) string {
	if rules == nil {
		return "[]"
	}
	sorted := make([]Rule, len(rules))
	copy(sorted, rules)
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].ID < sorted[j].ID
	})
	b, _ := json.Marshal(sorted)
	return string(b)
}

// ---- Decision signing --------------------------------------------------------

// SignDecision creates an Ed25519 signature for a Decision.  Canonical form:
//
//	runID \x00 versionBe64 \x00 effect \x00 sortedRuleIDs|... \x00 actorRole
//
// Returns the raw signature bytes.
func SignDecision(priv ed25519.PrivateKey, runID string, bundleVersion uint64, effect string, matchedRules []string, actorRole string) []byte {
	return ed25519.Sign(priv, decisionPayload(runID, bundleVersion, effect, matchedRules, actorRole))
}

// VerifyDecision checks a Decision's signature against the given public key.
func VerifyDecision(pub ed25519.PublicKey, runID string, bundleVersion uint64, effect string, matchedRules []string, actorRole string, sig []byte) bool {
	return ed25519.Verify(pub, decisionPayload(runID, bundleVersion, effect, matchedRules, actorRole), sig)
}

// decisionPayload builds the canonical byte string that is signed/verified.
func decisionPayload(runID string, bundleVersion uint64, effect string, matchedRules []string, actorRole string) []byte {
	payload := make([]byte, 0, len(runID)+8+1+len(effect)+1+len(actorRole))
	payload = append(payload, []byte(runID)...)
	payload = append(payload, '\x00')
	payload = append(payload, uint64Bytes(bundleVersion)...)
	payload = append(payload, '\x00')
	payload = append(payload, []byte(effect)...)
	payload = append(payload, '\x00')
	if len(matchedRules) > 0 {
		sorted := make([]string, len(matchedRules))
		copy(sorted, matchedRules)
		sort.Strings(sorted)
		payload = append(payload, []byte(strings.Join(sorted, "|"))...)
	}
	payload = append(payload, '\x00')
	payload = append(payload, []byte(actorRole)...)
	return payload
}

func uint64Bytes(v uint64) []byte {
	b := make([]byte, 8)
	b[0] = byte(v >> 56)
	b[1] = byte(v >> 48)
	b[2] = byte(v >> 40)
	b[3] = byte(v >> 32)
	b[4] = byte(v >> 24)
	b[5] = byte(v >> 16)
	b[6] = byte(v >> 8)
	b[7] = byte(v)
	return b
}
