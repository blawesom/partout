package selector

import (
	"sort"
	"testing"
)

type fakeResolver struct {
	hosts []HostInfo
}

func (f *fakeResolver) All() []HostInfo { return f.hosts }

func (f *fakeResolver) ByIDs(ids ...string) []HostInfo {
	want := make(map[string]bool, len(ids))
	for _, id := range ids {
		want[id] = true
	}
	var out []HostInfo
	for _, h := range f.hosts {
		if want[h.ID] {
			out = append(out, h)
		}
	}
	return out
}

func (f *fakeResolver) ByTag(key, value string) []HostInfo {
	var out []HostInfo
	for _, h := range f.hosts {
		v, ok := h.Tags[key]
		if !ok {
			continue
		}
		if value == "" || v == value {
			out = append(out, h)
		}
	}
	return out
}

func (f *fakeResolver) ByRole(role string) []HostInfo {
	var out []HostInfo
	for _, h := range f.hosts {
		for _, r := range h.Roles {
			if r == role {
				out = append(out, h)
				break
			}
		}
	}
	return out
}

func testHosts() *fakeResolver {
	return &fakeResolver{hosts: []HostInfo{
		{ID: "ag_web1", Tags: map[string]string{"env": "prod"}, Roles: []string{"web"}},
		{ID: "ag_web2", Tags: map[string]string{"env": "prod"}, Roles: []string{"web"}},
		{ID: "ag_db1", Tags: map[string]string{"env": "prod"}, Roles: []string{"db"}},
		{ID: "ag_lab1", Tags: map[string]string{"env": "lab"}, Roles: []string{"web"}},
	}}
}

func TestParseAll(t *testing.T) {
	preds, err := Parse("all")
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(preds) != 1 || preds[0].Kind != PAll {
		t.Fatalf("got %v, want 1 PAll", preds)
	}
}

func TestParseCombined(t *testing.T) {
	preds, err := Parse("role:web,tag:env=prod")
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(preds) != 2 {
		t.Fatalf("len = %d, want 2", len(preds))
	}
	if preds[0].Kind != PRole || preds[0].Key != "web" {
		t.Errorf("pred[0] = %+v", preds[0])
	}
	if preds[1].Kind != PTag || preds[1].Key != "env" || preds[1].Value != "prod" {
		t.Errorf("pred[1] = %+v", preds[1])
	}
}

func TestParseInvalid(t *testing.T) {
	for _, expr := range []string{"", "   ", "bogus", "host:", "tag:", "role:", "group:", "foo=bar"} {
		if _, err := Parse(expr); err == nil {
			t.Errorf("Parse(%q) = nil error, want error", expr)
		}
	}
}

func TestResolveAll(t *testing.T) {
	r := testHosts()
	hosts, err := Resolve("all", r, nil)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if len(hosts) != 4 {
		t.Fatalf("len = %d, want 4", len(hosts))
	}
	// Deterministic: sorted by id.
	if !sort.SliceIsSorted(hosts, func(i, j int) bool { return hosts[i].ID < hosts[j].ID }) {
		t.Fatal("result not sorted by id")
	}
}

func TestResolveTagAndRole(t *testing.T) {
	r := testHosts()
	// web role AND prod env => ag_web1, ag_web2
	hosts, err := Resolve("role:web,tag:env=prod", r, nil)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if len(hosts) != 2 {
		t.Fatalf("len = %d, want 2; got %v", len(hosts), ids(hosts))
	}
	if hosts[0].ID != "ag_web1" || hosts[1].ID != "ag_web2" {
		t.Fatalf("ids = %v", ids(hosts))
	}
}

func TestResolveTagOnly(t *testing.T) {
	r := testHosts()
	// key-only tag env => all 4 (all have env)
	hosts, err := Resolve("tag:env", r, nil)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if len(hosts) != 4 {
		t.Fatalf("len = %d, want 4", len(hosts))
	}
}

func TestResolveEmptyError(t *testing.T) {
	r := testHosts()
	if _, err := Resolve("role:nonexistent", r, nil); err == nil {
		t.Fatal("expected error for empty resolution")
	}
	// And an impossible intersection.
	if _, err := Resolve("role:web,tag:env=lab,role:db", r, nil); err == nil {
		t.Fatal("expected error for impossible intersection")
	}
}

func TestResolveGroup(t *testing.T) {
	r := testHosts()
	groups := Groups{"prod": "tag:env=prod"}
	hosts, err := Resolve("group:prod", r, groups)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if len(hosts) != 3 {
		t.Fatalf("len = %d, want 3", len(hosts))
	}
}

func TestResolveUnknownGroup(t *testing.T) {
	r := testHosts()
	if _, err := Resolve("group:nope", r, nil); err == nil {
		t.Fatal("expected error for unknown group")
	}
}

func TestResolveGroupCycle(t *testing.T) {
	r := testHosts()
	groups := Groups{"a": "group:b", "b": "group:a"}
	if _, err := Resolve("group:a", r, groups); err == nil {
		t.Fatal("expected error for group cycle")
	}
}

func ids(hosts []HostInfo) []string {
	out := make([]string, len(hosts))
	for i, h := range hosts {
		out[i] = h.ID
	}
	return out
}

// TestMatchesHost covers the single-host predicate check used by the policy
// engine, including group expansion.
func TestMatchesHost(t *testing.T) {
	groups := Groups{"web": "role:web", "prod": "tag:env=prod", "webprod": "group:web,tag:env=prod"}
	web := HostInfo{ID: "ag_1", Tags: map[string]string{"env": "prod"}, Roles: []string{"web"}}
	db := HostInfo{ID: "ag_2", Tags: map[string]string{"env": "dev"}, Roles: []string{"db"}}

	cases := []struct {
		expr string
		host HostInfo
		want bool
	}{
		{"all", web, true},
		{"host:ag_1", web, true},
		{"host:ag_2", web, false},
		{"role:web", web, true},
		{"role:web", db, false},
		{"tag:env=prod", web, true},
		{"tag:env=dev", web, false},
		{"group:web", web, true},
		{"group:web", db, false},
		{"group:webprod", web, true},   // nested group + tag
		{"group:webprod", db, false},   // db is neither web nor prod
		{"group:nosuch", web, false},   // unknown group → no match
		{"role:web,tag:env=dev", web, false},
		{"bogus predicate", web, false},
	}
	for _, c := range cases {
		if got := MatchesHost(c.expr, c.host, groups); got != c.want {
			t.Errorf("MatchesHost(%q, %s) = %v, want %v", c.expr, c.host.ID, got, c.want)
		}
	}
	// Nil groups: group predicates never match.
	if MatchesHost("group:web", web, nil) {
		t.Error("MatchesHost(group:web, nil groups) = true, want false")
	}
}
