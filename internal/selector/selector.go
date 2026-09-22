// Package selector implements the targeting grammar (PRD §5.1, arch §5.7, A12).
//
// A selector is a comma-separated conjunction (AND) of predicates:
//
//	all
//	host:<id>                       (repeatable, e.g. host:a,host:b)
//	tag:env=prod | tag:env          (key=value or key-only)
//	role:web
//	group:webservers                (a saved named selector)
//
// `a,b,c` = intersection. No OR in v1 — compose with groups instead.
// Resolution is deterministic (sorted by host id) and an empty result is an
// error, never a silent no-op (PRD §5.1).
package selector

import (
	"fmt"
	"sort"
	"strings"
)

// PredicateKind identifies the type of a selector predicate.
type PredicateKind int

const (
	PAll PredicateKind = iota
	PHost
	PTag
	PRole
	PGroup
)

// Predicate is a single selector predicate.
type Predicate struct {
	Kind   PredicateKind
	Key    string // tag key / role name / group name
	Value  string // tag value ("" = key-only)
	HostID string // for PHost
}

// HostInfo is the minimal host shape the resolver needs.
type HostInfo struct {
	ID    string
	Tags  map[string]string // key-only tags are mapped to ""
	Roles []string
}

// Groups maps a saved group name to its selector expression.
type Groups map[string]string

// Resolver is the data source the selector uses to fetch host sets.
type Resolver interface {
	All() []HostInfo
	ByIDs(ids ...string) []HostInfo
	ByTag(key, value string) []HostInfo // value "" = key-only
	ByRole(role string) []HostInfo
}

// Parse splits a selector expression into an ordered list of predicates.
func Parse(expr string) ([]Predicate, error) {
	expr = strings.TrimSpace(expr)
	if expr == "" {
		return nil, fmt.Errorf("selector: empty expression")
	}
	parts := strings.Split(expr, ",")
	var out []Predicate
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		if err := appendPredicate(&out, p); err != nil {
			return nil, err
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("selector: no predicates in %q", expr)
	}
	return out, nil
}

func appendPredicate(out *[]Predicate, p string) error {
	switch {
	case p == "all":
		*out = append(*out, Predicate{Kind: PAll})
	case strings.HasPrefix(p, "host:"):
		id := strings.TrimPrefix(p, "host:")
		if id == "" {
			return fmt.Errorf("selector: empty host id in %q", p)
		}
		*out = append(*out, Predicate{Kind: PHost, HostID: id})
	case strings.HasPrefix(p, "tag:"):
		rest := strings.TrimPrefix(p, "tag:")
		k, v, _ := strings.Cut(rest, "=")
		if k == "" {
			return fmt.Errorf("selector: empty tag key in %q", p)
		}
		*out = append(*out, Predicate{Kind: PTag, Key: k, Value: v})
	case strings.HasPrefix(p, "role:"):
		r := strings.TrimPrefix(p, "role:")
		if r == "" {
			return fmt.Errorf("selector: empty role in %q", p)
		}
		*out = append(*out, Predicate{Kind: PRole, Key: r})
	case strings.HasPrefix(p, "group:"):
		g := strings.TrimPrefix(p, "group:")
		if g == "" {
			return fmt.Errorf("selector: empty group in %q", p)
		}
		*out = append(*out, Predicate{Kind: PGroup, Key: g})
	default:
		return fmt.Errorf("selector: unknown predicate %q (want all|host:|tag:|role:|group:)", p)
	}
	return nil
}

// Resolve evaluates a selector expression against the resolver.
// Returns a deterministic (id-sorted) slice of matching hosts.
// Returns an error if the result is empty or on parse/unknown-group errors.
func Resolve(expr string, r Resolver, groups Groups) ([]HostInfo, error) {
	preds, err := Parse(expr)
	if err != nil {
		return nil, err
	}
	result, err := resolvePreds(preds, r, groups, 0)
	if err != nil {
		return nil, err
	}
	sort.Slice(result, func(i, j int) bool { return result[i].ID < result[j].ID })
	if len(result) == 0 {
		return nil, fmt.Errorf("selector: %q resolved to no hosts", expr)
	}
	return result, nil
}

// resolvePreds intersects predicates. groupDepth guards against cycles.
func resolvePreds(preds []Predicate, r Resolver, groups Groups, groupDepth int) ([]HostInfo, error) {
	if groupDepth > 8 {
		return nil, fmt.Errorf("selector: group recursion too deep (cycle?)")
	}
	var set []HostInfo
	first := true
	for _, p := range preds {
		var next []HostInfo
		switch p.Kind {
		case PAll:
			next = r.All()
		case PHost:
			next = r.ByIDs(p.HostID)
		case PTag:
			next = r.ByTag(p.Key, p.Value)
		case PRole:
			next = r.ByRole(p.Key)
		case PGroup:
			sub, ok := groups[p.Key]
			if !ok {
				return nil, fmt.Errorf("selector: unknown group %q", p.Key)
			}
			subPreds, err := Parse(sub)
			if err != nil {
				return nil, err
			}
			next, err = resolvePreds(subPreds, r, groups, groupDepth+1)
			if err != nil {
				return nil, err
			}
		default:
			return nil, fmt.Errorf("selector: unhandled predicate kind %d", p.Kind)
		}
		if first {
			set = next
			first = false
		} else {
			set = intersect(set, next)
		}
	}
	return set, nil
}

// intersect returns the hosts present in both a and b.
func intersect(a, b []HostInfo) []HostInfo {
	bset := make(map[string]bool, len(b))
	for _, h := range b {
		bset[h.ID] = true
	}
	var out []HostInfo
	for _, h := range a {
		if bset[h.ID] {
			out = append(out, h)
		}
	}
	return out
}
