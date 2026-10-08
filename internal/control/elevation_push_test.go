// P2: server-signed elevation policy push — control-layer gating + dispatch.
package control_test

import (
	"io"
	"log"
	"testing"

	"github.com/blawesom/partout/internal/certutil"
	"github.com/blawesom/partout/internal/control"
	"github.com/blawesom/partout/internal/identity"
	"github.com/blawesom/partout/internal/policy"
	"github.com/blawesom/partout/internal/server/stream"
	"github.com/blawesom/partout/internal/sse"
	"github.com/blawesom/partout/internal/store"
)

func pushTestSetup(t *testing.T) (*control.Control, *store.Store) {
	t.Helper()
	st, err := store.New("sqlite::memory:")
	if err != nil {
		t.Fatalf("store.New: %v", err)
	}
	t.Cleanup(func() { st.Close() })

	id, err := identity.LoadOrGenerate(t.TempDir())
	if err != nil {
		t.Fatalf("identity: %v", err)
	}
	if err := st.UpsertAgent(store.Agent{
		ID: "ag_push", UUID: id.UUID, ED25519Pub: "k1", X25519Pub: "k2", State: "disconnected",
	}); err != nil {
		t.Fatalf("UpsertAgent: %v", err)
	}
	if err := st.SetRole("ag_push", "web"); err != nil {
		t.Fatalf("SetRole: %v", err)
	}
	// The stored policy to push (with the self-grant).
	if err := st.CreateElevationPolicy(&store.ElevationPolicy{
		ID: "epl_1", Name: "default-baseline",
		RulesJSON: `[{"allow":"reboot"},{"allow":"/usr/local/bin/partout","args":["ctl","elevation","apply","-"]}]`,
		PolicySHA: "fixme", // recomputed by the push (canonicalization)
	}); err != nil {
		t.Fatalf("CreateElevationPolicy: %v", err)
	}

	ident, err := certutil.LoadOrCreateServerIdentity(t.TempDir())
	if err != nil {
		t.Fatalf("server identity: %v", err)
	}
	sseB := sse.New()
	h := stream.NewHandler(st, sseB, log.New(io.Discard, "srv: ", 0))
	h.SetServerPubKey(ident.PubB64())
	ctl := control.New(st, h, sseB, log.New(io.Discard, "ctl: ", 0))
	ctl.SetIdentity(ident)
	return ctl, st
}

func TestPushElevationPolicyOfflineRefused(t *testing.T) {
	ctl, st := pushTestSetup(t)

	// No session connected: a privilege-document push must be REFUSED for
	// the offline host (never queued), and audited.
	pushed, skipped, err := ctl.PushElevationPolicy("default-baseline", "all", "admin", "admin")
	if err != nil {
		t.Fatalf("push: %v", err)
	}
	if len(pushed) != 0 {
		t.Fatalf("pushed = %+v, want none (host offline)", pushed)
	}
	if len(skipped) != 1 || skipped[0].State != "refused" {
		t.Fatalf("skipped = %+v, want one refused", skipped)
	}
	audits, _ := st.ListAudit("elevation.push.dispatched", 10)
	if len(audits) != 0 {
		t.Fatalf("dispatched audit rows for an offline host: %+v", audits)
	}
}

func TestPushElevationPolicyPolicyGated(t *testing.T) {
	ctl, st := pushTestSetup(t)

	// A deny-list rule on the elevation.push action class must gate the
	// push per host, exactly like any other governed write.
	if err := st.CreatePolicy("pol_no_push", "no-push", policy.Match{
		Hosts:   "all",
		Actions: []string{policy.ActionElevationPush},
	}, policy.EffectDeny, 1); err != nil {
		t.Fatalf("CreatePolicy: %v", err)
	}
	pushed, skipped, err := ctl.PushElevationPolicy("default-baseline", "all", "admin", "admin")
	if err != nil {
		t.Fatalf("push: %v", err)
	}
	if len(pushed) != 0 {
		t.Fatalf("pushed = %+v, want none (denied)", pushed)
	}
	if len(skipped) != 1 || skipped[0].State != "denied" {
		t.Fatalf("skipped = %+v, want one denied", skipped)
	}

	// require_approval also refuses (fail closed and loud, no parked push).
	if _, err := st.DeletePolicy("pol_no_push"); err != nil {
		t.Fatalf("DeletePolicy: %v", err)
	}
	if err := st.CreatePolicy("pol_appr_push", "appr-push", policy.Match{
		Hosts:   "all",
		Actions: []string{policy.ActionElevationPush},
	}, policy.EffectRequireApproval, 1); err != nil {
		t.Fatalf("CreatePolicy: %v", err)
	}
	_, skipped, err = ctl.PushElevationPolicy("default-baseline", "all", "admin", "admin")
	if err != nil {
		t.Fatalf("push: %v", err)
	}
	if len(skipped) != 1 || skipped[0].State != "denied" || skipped[0].Detail == "" {
		t.Fatalf("skipped = %+v, want require_approval refused loudly", skipped)
	}
}

func TestPushElevationPolicyUnknownPolicy(t *testing.T) {
	ctl, _ := pushTestSetup(t)
	if _, _, err := ctl.PushElevationPolicy("no-such-policy", "all", "admin", "admin"); err == nil {
		t.Fatal("unknown policy accepted")
	}
}
