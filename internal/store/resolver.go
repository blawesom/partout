package store

import (
	"github.com/blawesom/partout/internal/selector"
)

// Resolver satisfies selector.Resolver, backed by a Store. It is the adapter
// the control plane and agent-side re-check both use (shared selector
// semantics, architecture §1).
type Resolver struct {
	s *Store
}

// NewResolver builds a selector resolver over s.
func NewResolver(s *Store) *Resolver { return &Resolver{s: s} }

// All returns every agent as a HostInfo.
func (r *Resolver) All() []selector.HostInfo {
	agents, _ := r.s.Agents()
	return r.toInfos(agents)
}

// ByIDs returns the named agents.
func (r *Resolver) ByIDs(ids ...string) []selector.HostInfo {
	want := make(map[string]bool, len(ids))
	for _, id := range ids {
		want[id] = true
	}
	var out []*Agent
	for _, id := range ids {
		a, err := r.s.Agent(id)
		if err != nil {
			continue
		}
		out = append(out, a)
	}
	return r.toInfos(out)
}

// ByTag returns agents with the given tag (value "" = key-only).
func (r *Resolver) ByTag(key, value string) []selector.HostInfo {
	agents, _ := r.s.Agents()
	var out []*Agent
	for _, a := range agents {
		tags, _ := r.s.Tags(a.ID)
		v, ok := tags[key]
		if !ok {
			continue
		}
		if value == "" || v == value {
			out = append(out, a)
		}
	}
	return r.toInfos(out)
}

// ByRole returns agents with the given role.
func (r *Resolver) ByRole(role string) []selector.HostInfo {
	agents, _ := r.s.Agents()
	var out []*Agent
	for _, a := range agents {
		roles, _ := r.s.Roles(a.ID)
		for _, rl := range roles {
			if rl == role {
				out = append(out, a)
				break
			}
		}
	}
	return r.toInfos(out)
}

// toInfos loads tags/roles for each agent and returns selector.HostInfo.
func (r *Resolver) toInfos(agents []*Agent) []selector.HostInfo {
	out := make([]selector.HostInfo, 0, len(agents))
	for _, a := range agents {
		tags, _ := r.s.Tags(a.ID)
		roles, _ := r.s.Roles(a.ID)
		out = append(out, selector.HostInfo{ID: a.ID, Tags: tags, Roles: roles})
	}
	return out
}

// ResolveSelector resolves a selector expression against the store.
func (r *Resolver) ResolveSelector(expr string) ([]selector.HostInfo, error) {
	groups, _ := r.s.Groups()
	return selector.Resolve(expr, r, groups)
}
