package agent

import (
	"encoding/json"
	"testing"

	"github.com/blawesom/partout/internal/agent/factscollect"
	pb "github.com/blawesom/partout/internal/proto"
)

// TestObserveEnvelopesShape locks in the wire contract for observe fact
// uploads: one envelope per non-empty domain, correct kind label, and a JSON
// body carrying exactly that domain's key.
func TestObserveEnvelopesShape(t *testing.T) {
	f := &factscollect.Facts{
		ServicesDetailed: &factscollect.ServiceFacts{Units: []factscollect.UnitFact{{Name: "myapp", State: "active"}}},
		Configs:          &factscollect.ConfigFacts{HAProxy: &factscollect.HAProxyConfig{Present: true, Version: "2.8"}},
		Certificates:     &factscollect.CertFacts{Items: []factscollect.CertFact{{Path: "/etc/ssl/a.pem"}}},
	}
	envs := observeEnvelopes("uuid-123", f)
	if len(envs) != 3 {
		t.Fatalf("got %d envelopes, want 3 (one per domain)", len(envs))
	}

	wantKeys := map[string]string{
		"services": "services_detailed",
		"configs":  "configs",
		"certs":    "certificates",
	}
	seen := make(map[string]bool)
	for _, env := range envs {
		if env.Kind != pb.EnvelopeKind_OBSERVE_FACTS {
			t.Errorf("kind = %v, want OBSERVE_FACTS", env.Kind)
		}
		of := env.GetObserveFacts()
		if of == nil {
			t.Fatalf("envelope has no ObserveFacts payload: %+v", env)
		}
		if of.HostId != "uuid-123" {
			t.Errorf("HostId = %q, want uuid-123 (diagnostics only)", of.HostId)
		}
		key, ok := wantKeys[of.Kind]
		if !ok {
			t.Errorf("unexpected kind %q", of.Kind)
			continue
		}
		seen[of.Kind] = true

		var body map[string]json.RawMessage
		if err := json.Unmarshal([]byte(of.Json), &body); err != nil {
			t.Fatalf("kind %s: body is not JSON: %v (%s)", of.Kind, err, of.Json)
		}
		if _, ok := body[key]; !ok {
			t.Errorf("kind %s: body missing %q: %s", of.Kind, key, of.Json)
		}
		if len(body) != 1 {
			t.Errorf("kind %s: body should carry only its own domain, got %v", of.Kind, body)
		}
	}
	for kind := range wantKeys {
		if !seen[kind] {
			t.Errorf("no envelope for domain %q", kind)
		}
	}
}

// TestObserveEnvelopesSkipsEmptyDomains: a collection result with only one
// populated domain must not emit empty envelopes for the others.
func TestObserveEnvelopesSkipsEmptyDomains(t *testing.T) {
	cases := []struct {
		name string
		f    *factscollect.Facts
		want []string
	}{
		{
			name: "services only",
			f:    &factscollect.Facts{ServicesDetailed: &factscollect.ServiceFacts{}},
			want: []string{"services"},
		},
		{
			name: "configs only",
			f:    &factscollect.Facts{Configs: &factscollect.ConfigFacts{}},
			want: []string{"configs"},
		},
		{
			name: "certs only",
			f:    &factscollect.Facts{Certificates: &factscollect.CertFacts{}},
			want: []string{"certs"},
		},
		{
			name: "all empty",
			f:    &factscollect.Facts{},
			want: nil,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			envs := observeEnvelopes("u", c.f)
			if len(envs) != len(c.want) {
				t.Fatalf("got %d envelopes, want %d", len(envs), len(c.want))
			}
			for i, kind := range c.want {
				if got := envs[i].GetObserveFacts().Kind; got != kind {
					t.Errorf("envelope[%d].Kind = %q, want %q", i, got, kind)
				}
			}
		})
	}
}

// TestObserveEnvelopesNilFacts: a nil collection result (host has nothing to
// report) produces no envelopes at all.
func TestObserveEnvelopesNilFacts(t *testing.T) {
	if envs := observeEnvelopes("u", nil); len(envs) != 0 {
		t.Errorf("nil facts produced %d envelopes, want 0", len(envs))
	}
}

// TestObserveEnvelopesBodyRoundTripsThroughServerSchema ensures the agent's
// JSON keys are exactly the ones the server-side parser expects.
func TestObserveEnvelopesBodyRoundTripsThroughServerSchema(t *testing.T) {
	f := &factscollect.Facts{
		ServicesDetailed: &factscollect.ServiceFacts{Units: []factscollect.UnitFact{{Name: "myapp"}}},
	}
	envs := observeEnvelopes("u", f)
	if len(envs) != 1 {
		t.Fatalf("got %d envelopes, want 1", len(envs))
	}
	body := envs[0].GetObserveFacts().Json

	// The key names must match the observe package's domain constants. This
	// is asserted literally (rather than by importing observe) to keep the
	// agent free of a server-package dependency; the constants are guarded by
	// TestDomainKeysStable on the server side.
	var decoded struct {
		ServicesDetailed *struct {
			Units []struct {
				Name string `json:"name"`
			} `json:"units"`
		} `json:"services_detailed"`
	}
	if err := json.Unmarshal([]byte(body), &decoded); err != nil {
		t.Fatalf("decode: %v (%s)", err, body)
	}
	if decoded.ServicesDetailed == nil || len(decoded.ServicesDetailed.Units) != 1 ||
		decoded.ServicesDetailed.Units[0].Name != "myapp" {
		t.Errorf("body did not round-trip: %s", body)
	}
}

// TestObserveCollectingGuardIsReentrantSafe documents the atomic guard used to
// skip overlapping collection ticks.
func TestObserveCollectingGuard(t *testing.T) {
	a := &Agent{}
	if !a.obsCollecting.CompareAndSwap(false, true) {
		t.Fatal("first acquisition should succeed")
	}
	if a.obsCollecting.CompareAndSwap(false, true) {
		t.Fatal("second acquisition while held should fail")
	}
	a.obsCollecting.Store(false)
	if !a.obsCollecting.CompareAndSwap(false, true) {
		t.Fatal("acquisition after release should succeed")
	}
}
