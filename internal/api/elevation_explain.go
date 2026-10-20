// Elevation policy legibility endpoints (P3.3/P3.4 server half).
//
// Routes (auth: viewer+ — all read-only with respect to the store):
//
//	POST /api/v1/elevation/validate   typing-time rule feedback
//	POST /api/v1/elevation/explain     why does (not) this command elevate
//	POST /api/v1/elevation/generate    fleet-aware policy proposal
//
// None of these touch a host: validate/explain operate on the document in
// the editor, generate proposes rules from observed facts and explicitly
// does NOT apply them — the operator reviews the proposal in the editor
// and pushes through the normal (signed, gated) channels.
package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"

	"github.com/blawesom/partout/internal/agent/elevate"
	"github.com/blawesom/partout/internal/server/observe"
	"github.com/blawesom/partout/internal/store"
)

// registerElevationExplain wires the legibility routes (called from
// RegisterElevationPolicies so all elevation routes live in one block).
func (h *Handler) registerElevationExplain(mux *http.ServeMux) {
	mux.Handle("POST /api/v1/elevation/validate", h.requireRole(roleViewer)(http.HandlerFunc(h.eplValidate)))
	mux.Handle("POST /api/v1/elevation/explain", h.requireRole(roleViewer)(http.HandlerFunc(h.eplExplain)))
	mux.Handle("POST /api/v1/elevation/generate", h.requireRole(roleViewer)(http.HandlerFunc(h.eplGenerate)))
}

// eplValidateBody is the validate request: a rules document (bare array
// or {"rules":[...]}).
type eplValidateBody struct {
	Rules json.RawMessage `json:"rules"`
}

// eplValidate: typing-time feedback for the editor. Accepts the same
// rule-document shapes as the create endpoint, runs them through
// LoadPolicyJSON (which names the offending rule), and answers
// {ok, tier, rule_count} or {ok:false, error} — a 200 with ok=false is
// deliberate: a malformed draft is expected editor state, not a failed
// request.
func (h *Handler) eplValidate(w http.ResponseWriter, r *http.Request) {
	var body eplValidateBody
	if err := decodeJSON(r, &body); err != nil {
		writeError(w, http.StatusBadRequest, "bad_request", "invalid JSON body", nil)
		return
	}
	wrapped, err := wrapRulesDoc(body.Rules)
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	pol, err := elevate.LoadPolicyJSON(wrapped)
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok": true, "tier": pol.Tier(), "rule_count": len(pol.Rules),
	})
}

// eplExplainBody is the explain request: either inline rules or a stored
// policy name, plus the command to test.
type eplExplainBody struct {
	Rules   json.RawMessage `json:"rules"`
	Policy  string          `json:"policy"`
	Command string          `json:"command"`
}

// eplExplain: "does this command elevate under this policy, and why".
// The policy comes from the body's inline rules (editor draft) or a
// stored name (the test-against-installed-policy flow). The command is
// split shell-like into name + argv, then run through elevate.Explain —
// the same matcher the agent uses, so the verdict here is the verdict
// the host would reach.
func (h *Handler) eplExplain(w http.ResponseWriter, r *http.Request) {
	var body eplExplainBody
	if err := decodeJSON(r, &body); err != nil {
		writeError(w, http.StatusBadRequest, "bad_request", "invalid JSON body", nil)
		return
	}
	name, args := splitCommand(body.Command)
	if name == "" {
		writeError(w, http.StatusBadRequest, "bad_request", "command required (e.g. \"systemctl restart nginx\")", nil)
		return
	}
	var pol *elevate.Policy
	switch {
	case body.Policy != "":
		p, err := h.st.ElevationPolicy(body.Policy)
		if err != nil || p == nil {
			writeError(w, http.StatusBadRequest, "bad_request", "unknown elevation policy "+body.Policy, nil)
			return
		}
		pol, err = elevate.LoadPolicyJSON([]byte(`{"rules":` + p.RulesJSON + `}`))
		if err != nil {
			writeError(w, http.StatusBadRequest, "bad_policy", "stored policy "+body.Policy+" is invalid: "+err.Error(), nil)
			return
		}
	case len(body.Rules) > 0:
		wrapped, err := wrapRulesDoc(body.Rules)
		if err != nil {
			writeError(w, http.StatusBadRequest, "bad_policy", err.Error(), nil)
			return
		}
		pol, err = elevate.LoadPolicyJSON(wrapped)
		if err != nil {
			writeError(w, http.StatusBadRequest, "bad_policy", err.Error(), nil)
			return
		}
	default:
		writeError(w, http.StatusBadRequest, "bad_request", "either rules or policy is required", nil)
		return
	}
	res := elevate.Explain(pol, name, args)
	writeJSON(w, http.StatusOK, map[string]any{
		"elevated": res.Elevated, "note": res.Note,
		"rule_index": res.RuleIndex, "tier": res.Tier,
	})
}

// wrapRulesDoc accepts a bare rules array or a {"rules":[...]} document
// and returns the {"rules": ...} envelope LoadPolicyJSON wants.
func wrapRulesDoc(raw json.RawMessage) ([]byte, error) {
	b := []byte(raw)
	if len(b) == 0 || string(b) == "null" {
		return nil, fmt.Errorf("rules required (a JSON array of rules)")
	}
	trimmed := strings.TrimSpace(string(b))
	if strings.HasPrefix(trimmed, "{") {
		var doc struct {
			Rules json.RawMessage `json:"rules"`
		}
		if err := json.Unmarshal(b, &doc); err != nil {
			return nil, fmt.Errorf("rules document must be an array or {\"rules\":[...]}: %v", err)
		}
		if len(doc.Rules) == 0 {
			return nil, fmt.Errorf("rules document has no \"rules\" array")
		}
		b = doc.Rules
	}
	return json.Marshal(map[string]json.RawMessage{"rules": json.RawMessage(b)})
}

// splitCommand splits a shell-like command line into name + argv,
// honoring single and double quotes (the editor's command field is one
// line; operators paste `systemctl restart nginx` or
// `apt-get -y install "some pkg"`). No escapes, expansions, or pipelines
// — a policy target is one command.
func splitCommand(s string) (string, []string) {
	var (
		parts []string
		cur   strings.Builder
		f     = func() {
			if cur.Len() > 0 {
				parts = append(parts, cur.String())
				cur.Reset()
			}
		}
	)
	var quote rune
	for _, c := range s {
		switch {
		case quote != 0:
			if c == quote {
				quote = 0
			} else {
				cur.WriteRune(c)
			}
		case c == '\'' || c == '"':
			quote = c
		case c == ' ' || c == '\t':
			f()
		default:
			cur.WriteRune(c)
		}
	}
	f()
	if len(parts) == 0 {
		return "", nil
	}
	return parts[0], parts[1:]
}

// eplGenBody is the fleet-aware generator request (P3.4).
type eplGenBody struct {
	Selector string `json:"selector"`
	// Basis: "broad" (default-broad shapes, trimmed) or "strict"
	// (exact-argv shapes, trimmed).
	Basis string `json:"basis"`
	// IncludeSelfGrant keeps the signed-policy self-grant (default true;
	// without it the host cannot accept policy pushes).
	IncludeSelfGrant *bool `json:"include_self_grant"`
	// IncludeUserSteps keeps the useradd/groupadd task-step grants
	// (default true, matching broad).
	IncludeUserSteps *bool `json:"include_user_steps"`
	// IncludeConfigReads keeps the cat grants for root-owned config trees
	// (default true, matching broad).
	IncludeConfigReads *bool `json:"include_config_reads"`
}

// eplGenHost is one matched host's contribution to the proposal.
type eplGenHost struct {
	AgentID  string   `json:"agent_id"`
	Hostname string   `json:"hostname,omitempty"`
	Distro   string   `json:"distro,omitempty"`
	Units    []string `json:"units"`
	Configs  []string `json:"configs"`
}

// eplGenResult is the proposal: rules to review in the editor, the tier
// they classify as, and a note for every inclusion/exclusion decision —
// the generator must be legible, not magic. No auto-apply.
type eplGenResult struct {
	Rules        []elevate.Rule `json:"rules"`
	Tier         string         `json:"tier"`
	HostsMatched int            `json:"hosts_matched"`
	HostDetails  []eplGenHost   `json:"host_details"`
	Notes        []string       `json:"notes"`
}

// eplGenerate proposes a minimal elevation policy for the hosts a
// selector resolves, derived from what the fleet actually runs (latest
// observed facts): package-manager family from host.distro, systemctl
// scope from observed custom units, validators + config reads only for
// observed configs. The proposal is never applied — it lands in the
// editor for review.
func (h *Handler) eplGenerate(w http.ResponseWriter, r *http.Request) {
	var body eplGenBody
	if err := decodeJSON(r, &body); err != nil {
		writeError(w, http.StatusBadRequest, "bad_request", "invalid JSON body", nil)
		return
	}
	if body.Selector == "" {
		body.Selector = "all"
	}
	if body.Basis == "" {
		body.Basis = "broad"
	}
	if body.Basis != "broad" && body.Basis != "strict" {
		writeError(w, http.StatusBadRequest, "bad_request", "basis must be \"broad\" or \"strict\"", nil)
		return
	}
	selfGrant := body.IncludeSelfGrant == nil || *body.IncludeSelfGrant
	userSteps := body.IncludeUserSteps == nil || *body.IncludeUserSteps
	configReads := body.IncludeConfigReads == nil || *body.IncludeConfigReads

	infos, err := store.NewResolver(h.st).ResolveSelector(body.Selector)
	if err != nil {
		writeError(w, http.StatusBadRequest, "bad_request", "selector: "+err.Error(), nil)
		return
	}
	var (
		notes    []string
		details  = make([]eplGenHost, 0, len(infos))
		families = map[string][]string{} // apt/dnf → observed distros
		unitSet  = map[string]bool{}
		nginxN   int
		haproxyN int
		noFactsN int
	)
	for _, hi := range infos {
		d := eplGenHost{AgentID: hi.ID, Units: []string{}, Configs: []string{}}
		blob, err := h.st.LatestHostFactsJSON(hi.ID)
		if err != nil || blob == "" {
			noFactsN++
			details = append(details, d)
			continue
		}
		doc, err := observe.ParseDocument(blob)
		if err != nil {
			noFactsN++
			details = append(details, d)
			continue
		}
		d.Distro = doc.Flat["host.distro"]
		d.Hostname = doc.Flat["host.hostname"]
		switch familyOf(d.Distro) {
		case "apt":
			families["apt"] = appendUnique(families["apt"], d.Distro)
		case "dnf":
			families["dnf"] = appendUnique(families["dnf"], d.Distro)
		}
		if svc := doc.Services(); svc != nil {
			for _, u := range svc.Units {
				// Custom units carry labels (the observe layer's rule for
				// what Partout considers "managed"); scope systemctl to
				// exactly those.
				if len(u.Labels) == 0 {
					continue
				}
				if !unitSet[u.Name] {
					unitSet[u.Name] = true
					d.Units = append(d.Units, u.Name)
				}
			}
		}
		if cfg := doc.Configs(); cfg != nil {
			if cfg.Nginx != nil && cfg.Nginx.Present {
				nginxN++
				d.Configs = append(d.Configs, "nginx")
			}
			if cfg.HAProxy != nil && cfg.HAProxy.Present {
				haproxyN++
				d.Configs = append(d.Configs, "haproxy")
			}
		}
		details = append(details, d)
	}
	if noFactsN > 0 {
		notes = append(notes, fmt.Sprintf("%d host(s) in the selection report no facts — they contributed nothing to the proposal", noFactsN))
	}

	// Package family: keep only what the fleet runs.
	for _, fam := range []string{"apt", "dnf"} {
		if ds := families[fam]; len(ds) > 0 {
			sort.Strings(ds)
			notes = append(notes, fmt.Sprintf("package rules kept for the %s family (observed distros: %s)", fam, strings.Join(ds, ", ")))
		} else {
			notes = append(notes, fmt.Sprintf("package rules for the %s family dropped (no host in the selection runs it)", fam))
		}
	}

	// Unit scope: observed custom unit names, as unit globs (name + * —
	// the unit and its .service sibling).
	units := make([]string, 0, len(unitSet))
	for u := range unitSet {
		units = append(units, u)
	}
	sort.Strings(units)
	var unitGlobs []string
	for _, u := range units {
		base := strings.TrimSuffix(u, ".service")
		unitGlobs = append(unitGlobs, base+"*")
	}
	if len(unitGlobs) > 0 {
		notes = append(notes, "systemctl scoped to the observed custom units: "+strings.Join(unitGlobs, ", "))
	} else {
		notes = append(notes, "no custom (labeled) units observed — all systemctl grants omitted")
	}

	// Validators + config reads: only for observed configs.
	var catFiles []string
	if nginxN > 0 {
		notes = append(notes, fmt.Sprintf("nginx validator included (config facts show nginx on %d host(s))", nginxN))
		catFiles = append(catFiles, "/etc/nginx/*", "/etc/nginx/*/*")
	} else {
		notes = append(notes, "nginx validator dropped (no nginx config facts in the selection)")
	}
	if haproxyN > 0 {
		notes = append(notes, fmt.Sprintf("haproxy validator included (config facts show haproxy on %d host(s))", haproxyN))
		catFiles = append(catFiles, "/etc/haproxy/*")
	} else {
		notes = append(notes, "haproxy validator dropped (no haproxy config facts in the selection)")
	}

	// Option-gated grants.
	if selfGrant {
		notes = append(notes, "self-grant included — hosts accept signed policy pushes (partout ctl elevation apply -)")
	} else {
		notes = append(notes, "self-grant omitted per include_self_grant=false — hosts cannot accept policy pushes")
	}
	if userSteps {
		notes = append(notes, "user/group task-step grants included (include_user_steps default)")
	} else {
		notes = append(notes, "user/group task-step grants dropped per include_user_steps=false")
	}
	if configReads && len(catFiles) > 0 {
		notes = append(notes, "config reads (cat) scoped to the observed config trees: "+strings.Join(catFiles, ", "))
	} else if configReads {
		notes = append(notes, "config reads (cat) dropped (no observed config trees to read)")
	} else {
		notes = append(notes, "config reads (cat) dropped per include_config_reads=false")
	}

	var rules []elevate.Rule
	if body.Basis == "broad" {
		rules = genBroadRules(families, unitGlobs, nginxN, haproxyN, catFiles, selfGrant, userSteps, configReads)
		notes = append(notes, "basis broad: wildcard-prefix package grants and verb-scoped systemctl (default-broad shapes, trimmed to the fleet)")
	} else {
		rules = genStrictRules(families, unitGlobs, nginxN, haproxyN, catFiles, selfGrant, userSteps, configReads)
		notes = append(notes, "basis strict: exact-argv package forms and bare reboot (default-strict shapes, trimmed to the fleet)")
	}
	sort.Strings(notes)

	pol, err := elevate.LoadPolicyJSON(mustMarshalRules(rules))
	if err != nil {
		// The generator only emits shapes validate accepts; a failure here
		// is a programming error, surfaced loudly.
		writeError(w, http.StatusInternalServerError, "internal_error", "generated policy invalid: "+err.Error(), nil)
		return
	}

	actor, _ := h.actorFor(r)
	h.audit("elevation.policy.generate", actor, map[string]string{
		"selector": body.Selector, "basis": body.Basis,
		"hosts_matched": fmt.Sprint(len(infos)), "rules": fmt.Sprint(len(rules)),
	})

	writeJSON(w, http.StatusOK, eplGenResult{
		Rules: pol.Rules, Tier: pol.Tier(), HostsMatched: len(infos),
		HostDetails: details, Notes: notes,
	})
}

// familyOf maps a host.distro fact to its package family ("" = unknown).
func familyOf(distro string) string {
	switch distro {
	case "ubuntu", "debian", "linuxmint", "pop":
		return "apt"
	case "rhel", "centos", "rocky", "alma", "fedora", "ol":
		return "dnf"
	}
	return ""
}

// broadVerbs is the systemctl verb list of the broad tier (management
// verbs only — no link/mask).
var broadVerbs = []string{"status", "show", "start", "stop", "restart", "reload", "try-restart", "enable", "disable", "is-active", "is-enabled"}

// genBroadRules derives a broad-basis rule set, trimmed to observations.
func genBroadRules(families map[string][]string, unitGlobs []string, nginxN, haproxyN int, catFiles []string, selfGrant, userSteps, configReads bool) []elevate.Rule {
	var rules []elevate.Rule
	add := func(rs ...elevate.Rule) { rules = append(rules, rs...) }
	if len(families["apt"]) > 0 {
		add(
			elevate.Rule{Allow: "apt-get", ArgsPrefix: []string{"-y"}},
			elevate.Rule{Allow: "apt-get", ArgsPrefix: []string{"-qq"}},
			elevate.Rule{Allow: "apt-get", ArgsPrefix: []string{"-q"}},
			elevate.Rule{Allow: "apt-get", ArgsPrefix: []string{"-o"}},
			elevate.Rule{Allow: "apt-get", Args: []string{"-y", "upgrade"}},
		)
	}
	if len(families["dnf"]) > 0 {
		add(
			elevate.Rule{Allow: "dnf", ArgsPrefix: []string{"-y"}},
			elevate.Rule{Allow: "dnf", ArgsPrefix: []string{"-q"}},
			elevate.Rule{Allow: "dnf", Args: []string{"check-update"}},
			elevate.Rule{Allow: "dnf", Args: []string{"upgrade", "--assumeno"}},
			elevate.Rule{Allow: "dnf", Args: []string{"-y", "upgrade"}},
		)
	}
	if nginxN > 0 {
		add(elevate.Rule{Allow: "nginx", Args: []string{"-t"}})
	}
	if haproxyN > 0 {
		add(elevate.Rule{Allow: "haproxy", ArgsPrefix: []string{"-c", "-f"}})
	}
	if configReads && len(catFiles) > 0 {
		add(elevate.Rule{Allow: "cat", Files: catFiles})
	}
	add(elevate.Rule{Allow: "hostnamectl", Args: []string{"set-hostname", "*"}})
	if len(unitGlobs) > 0 {
		add(elevate.Rule{Allow: "systemctl", Verbs: broadVerbs, Units: unitGlobs})
		add(elevate.Rule{Allow: "systemctl", Args: []string{"daemon-reload"}})
	}
	if userSteps {
		add(
			elevate.Rule{Allow: "useradd", ArgsPrefix: []string{"--system"}},
			elevate.Rule{Allow: "useradd", ArgsPrefix: []string{"*", "*"}},
			elevate.Rule{Allow: "useradd", ArgsPrefix: []string{"*", "*", "*"}},
			elevate.Rule{Allow: "useradd", ArgsPrefix: []string{"*", "*", "*", "*"}},
			elevate.Rule{Allow: "useradd"},
			elevate.Rule{Allow: "groupadd", ArgsPrefix: []string{"*"}},
		)
	}
	add(
		elevate.Rule{Allow: "shutdown", Args: []string{"-r", "now"}},
		elevate.Rule{Allow: "systemctl", Args: []string{"reboot"}},
		elevate.Rule{Allow: "reboot"},
	)
	if selfGrant {
		add(elevate.Rule{Allow: "/usr/local/bin/partout", Args: []string{"ctl", "elevation", "apply", "-"}})
	}
	return rules
}

// genStrictRules derives a strict-basis rule set: the same trimming, but
// exact-argv package forms and (per the strict vocabulary) reboot.
func genStrictRules(families map[string][]string, unitGlobs []string, nginxN, haproxyN int, catFiles []string, selfGrant, userSteps, configReads bool) []elevate.Rule {
	var rules []elevate.Rule
	add := func(rs ...elevate.Rule) { rules = append(rules, rs...) }
	if len(families["apt"]) > 0 {
		add(
			elevate.Rule{Allow: "apt-get", Args: []string{"-y", "upgrade"}},
			elevate.Rule{Allow: "apt-get", Args: []string{"-y", "install", "*"}},
			elevate.Rule{Allow: "apt-get", Args: []string{"-q", "makecache"}},
			elevate.Rule{Allow: "apt-get", Args: []string{"-qq", "update"}},
		)
	}
	if len(families["dnf"]) > 0 {
		add(
			elevate.Rule{Allow: "dnf", Args: []string{"-y", "upgrade"}},
			elevate.Rule{Allow: "dnf", Args: []string{"-y", "install", "*"}},
			elevate.Rule{Allow: "dnf", Args: []string{"-q", "makecache"}},
			elevate.Rule{Allow: "dnf", Args: []string{"check-update"}},
			elevate.Rule{Allow: "dnf", Args: []string{"upgrade", "--assumeno"}},
		)
	}
	if nginxN > 0 {
		add(elevate.Rule{Allow: "nginx", Args: []string{"-t"}})
	}
	if haproxyN > 0 {
		add(elevate.Rule{Allow: "haproxy", Args: []string{"-c", "-f", "*"}})
	}
	if configReads && len(catFiles) > 0 {
		add(elevate.Rule{Allow: "cat", Files: catFiles})
	}
	if len(unitGlobs) > 0 {
		add(elevate.Rule{Allow: "systemctl", Verbs: broadVerbs, Units: unitGlobs})
	}
	add(elevate.Rule{Allow: "reboot"})
	if selfGrant {
		add(elevate.Rule{Allow: "/usr/local/bin/partout", Args: []string{"ctl", "elevation", "apply", "-"}})
	}
	_ = userSteps // strict basis has no user/group step shapes (exact-argv wall)
	return rules
}

func appendUnique(ss []string, v string) []string {
	for _, s := range ss {
		if s == v {
			return ss
		}
	}
	return append(ss, v)
}

func mustMarshalRules(rules []elevate.Rule) []byte {
	b, err := json.Marshal(map[string]any{"rules": rules})
	if err != nil {
		panic(err)
	}
	return b
}
