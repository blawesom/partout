// Package serversecrets wires task dispatch to the secrets manager: the
// v0.9.13 known gap ("task→secret references are unwired"). Task steps
// declare secrets with the `secret:NAME` ref syntax (in step env values,
// command arguments, file/template content, and template vars); before a
// task run is dispatched to an agent this package scans the steps for
// those refs, resolves each secret's selector binding against the target
// host (fail-fast: an unbound ref aborts the dispatch server-side with a
// clear error instead of failing on the host with "secret unavailable"),
// and materializes each bound secret down the stream (E2E-encrypted) so
// the agent's cache is warm when the step runs. Materialization is
// one-per-run per ref (distinct refs only).
package secrets

import (
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/blawesom/partout/internal/proto"
)

// secretRefPrefix is the ref syntax a step uses to declare a secret:
// `secret:NAME` (NAME must be non-empty and contain no whitespace or
// colon — otherwise the run fails fast with a clear error).
const secretRefPrefix = "secret:"

// ErrSecretsDisabled is returned when a task declares secret refs but the
// secrets manager is not installed (no master key): the run fails fast
// server-side rather than failing on the host at step time.
var ErrSecretsDisabled = errors.New("secrets feature disabled; configure a master key (PARTOUT_SECRET_KEY_FILE or PARTOUT_SECRET_KEY) to run tasks that declare secrets")

// Materializer materializes a named secret to an agent, E2E-encrypted
// (serversecrets.Manager implements it). ref is the declaring run id, for
// the audit binding.
type Materializer interface {
	Materialize(agentID, name, ref string) (int64, error)
}

// StepSecretRefs scans task steps for `secret:NAME` refs and returns the
// distinct names in first-seen order. It never returns an error: an
// empty name (`secret:`) yields no ref (kept for the agent's version-aware
// lookup; a server-side reject would silently change what the host sees).
func StepSecretRefs(steps []*proto.TaskStep) []string {
	var names []string
	seen := map[string]bool{}
	add := func(v string) {
		name, ok := ParseSecretRef(v)
		if !ok || seen[name] {
			return
		}
		seen[name] = true
		names = append(names, name)
	}
	for _, s := range steps {
		if s == nil {
			continue
		}
		add(s.GetCommand())
		for _, a := range s.GetArgs() {
			add(a)
		}
		for _, v := range s.GetEnv() {
			add(v)
		}
		add(s.GetContent())
		add(s.GetTemplate())
		for _, v := range s.GetVars() {
			add(v)
		}
		add(s.GetPath())
		add(s.GetService())
		add(s.GetUser())
		add(s.GetGroup())
		add(s.GetPackage())
	}
	return names
}

// ParseSecretRef parses a `secret:NAME` value. ok=false when v is not a
// secret ref.
func ParseSecretRef(v string) (name string, ok bool) {
	if !strings.HasPrefix(v, secretRefPrefix) {
		return "", false
	}
	name = strings.TrimPrefix(v, secretRefPrefix)
	return name, name != ""
}

// MaterializeForRun materializes every distinct secret the steps declare
// to the agent, before the run envelope is sent (the agent's cache must
// be warm when a step runs). refs must be distinct names (StepSecretRefs
// output). A nil m (feature off) or a materialization error fails the
// dispatch fast with a clear error — the host would otherwise fail the
// step "secret unavailable" with no server-side signal.
func MaterializeForRun(m Materializer, agentID, ref string, refs []string) error {
	if len(refs) == 0 {
		return nil
	}
	if m == nil {
		return fmt.Errorf("task declares secrets (%s) but %w", strings.Join(refs, ", "), ErrSecretsDisabled)
	}
	// Sorted so the error (and the materialization order) is deterministic.
	names := append([]string(nil), refs...)
	sort.Strings(names)
	for _, name := range names {
		if _, err := m.Materialize(agentID, name, ref); err != nil {
			return fmt.Errorf("secret %q: %w", name, err)
		}
	}
	return nil
}
