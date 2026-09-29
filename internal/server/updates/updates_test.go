package updates

import (
	"io"
	"log"
	"testing"
	"time"

	"github.com/blawesom/partout/internal/policy"
	pb "github.com/blawesom/partout/internal/proto"
	"github.com/blawesom/partout/internal/server/approvals"
	"github.com/blawesom/partout/internal/server/stream"
	"github.com/blawesom/partout/internal/store"
)

type testEnv struct {
	st  *store.Store
	h   *stream.Handler
	m   *Manager
	rel store.Release
}

func newTestEnv(t *testing.T, hostCount int) *testEnv {
	t.Helper()
	st, err := store.New("sqlite::memory:")
	if err != nil {
		t.Fatalf("store.New: %v", err)
	}
	t.Cleanup(func() { st.Close() })

	// Fleet of N agents.
	for i := 1; i <= hostCount; i++ {
		id := hostID(i)
		if err := st.UpsertAgent(store.Agent{ID: id, UUID: "u" + id}); err != nil {
			t.Fatalf("UpsertAgent: %v", err)
		}
	}

	// One signed agent release (signature content is irrelevant to the
	// orchestrator — the agent is the verifier).
	rel := store.Release{
		ID: "rel_t", Version: "v2.0.0", Arch: "linux-amd64", Kind: "agent",
		SHA256: "aa", Signature: "sig", Artifact: []byte("x"),
	}
	if err := st.InsertRelease(rel); err != nil {
		t.Fatalf("InsertRelease: %v", err)
	}

	h := stream.NewHandler(st, nil, log.New(io.Discard, "", 0))
	m := New(st, h, nil, log.New(io.Discard, "", 0))
	m.SetPollInterval(20 * time.Millisecond)
	return &testEnv{st: st, h: h, m: m, rel: rel}
}

func hostID(i int) string {
	return map[int]string{1: "ag_1", 2: "ag_2", 3: "ag_3", 4: "ag_4", 5: "ag_5"}[i]
}

// verify simulates an agent reporting its update outcome (what the stream
// hook does on UPDATE_RESULT).
func (e *testEnv) verify(id, phase, version string) {
	e.m.OnResult(id, &pb.UpdateResult{ReleaseId: "rel_t", Phase: phase, Version: version})
}

func (e *testEnv) fail(id string) {
	e.m.OnResult(id, &pb.UpdateResult{ReleaseId: "rel_t", Phase: "failed", Error: "boom"})
}

func (e *testEnv) runStatus(t *testing.T, runID string) string {
	t.Helper()
	r, err := e.st.GetUpdateRun(runID)
	if err != nil || r == nil {
		t.Fatalf("GetUpdateRun(%s): %v", runID, err)
	}
	return r.Status
}

func (e *testEnv) hostStatus(t *testing.T, runID, hostID string) string {
	t.Helper()
	h, err := e.st.GetUpdateHost(runID, hostID)
	if err != nil || h == nil {
		t.Fatalf("GetUpdateHost(%s,%s): %v", runID, hostID, err)
	}
	return h.Status
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

// TestRolloutCanaryWaves is the happy path: 4 hosts, canary 1, 50% waves.
// canary -> wave(2) -> wave(1) -> completed.
func TestRolloutCanaryWaves(t *testing.T) {
	e := newTestEnv(t, 4)
	run, req, err := e.m.StartRun(Params{
		ReleaseID: "rel_t", Selector: "all", Canary: 1, WavePct: 50,
		Actor: "admin", ActorRole: "admin",
	})
	if err != nil {
		t.Fatalf("StartRun: %v", err)
	}
	if req != nil {
		t.Fatalf("unexpected approval request: %+v", req)
	}
	if run.Status != StatusCanary {
		t.Fatalf("initial status = %q, want %q", run.Status, StatusCanary)
	}

	// The canary (ag_1, first sorted) is dispatched.
	waitFor(t, "canary dispatched", func() bool {
		return e.hostStatus(t, run.ID, "ag_1") == HostDispatching
	})

	// Canary verifies -> run goes rolling.
	e.verify("ag_1", "verified", "v2.0.0")
	waitFor(t, "rolling after canary", func() bool {
		return e.runStatus(t, run.ID) == StatusRolling
	})

	// Wave 1: 2 hosts dispatched.
	waitFor(t, "wave 1 dispatched", func() bool {
		return e.hostStatus(t, run.ID, "ag_2") == HostDispatching &&
			e.hostStatus(t, run.ID, "ag_3") == HostDispatching
	})

	e.verify("ag_2", "verified", "v2.0.0")
	e.verify("ag_3", "verified", "v2.0.0")

	// Wave 2: the last host.
	waitFor(t, "wave 2 dispatched", func() bool {
		return e.hostStatus(t, run.ID, "ag_4") == HostDispatching
	})
	e.verify("ag_4", "verified", "v2.0.0")

	waitFor(t, "completed", func() bool {
		return e.runStatus(t, run.ID) == StatusCompleted
	})

	// Counters.
	r, _ := e.st.GetUpdateRun(run.ID)
	if r.DoneHosts != 4 || r.TotalHosts != 4 || r.FailedHosts != 0 {
		t.Errorf("counters = done:%d total:%d failed:%d, want 4/4/0", r.DoneHosts, r.TotalHosts, r.FailedHosts)
	}
	// CurrentWave tracks waves actually dispatched: canary(1) then two
	// waves of 50% of 4 = 2 hosts, then the remaining 1.
	if r.CurrentWave < 3 {
		t.Errorf("current_wave = %d, want >= 3 (canary + 2 waves)", r.CurrentWave)
	}
}

// TestRolloutCanaryFailureHardGate: a failed canary fails the whole run.
func TestRolloutCanaryFailureHardGate(t *testing.T) {
	e := newTestEnv(t, 4)
	run, _, err := e.m.StartRun(Params{ReleaseID: "rel_t", Selector: "all", Canary: 1, WavePct: 50, Actor: "admin", ActorRole: "admin"})
	if err != nil {
		t.Fatal(err)
	}
	waitFor(t, "canary dispatched", func() bool {
		return e.hostStatus(t, run.ID, "ag_1") == HostDispatching
	})
	e.fail("ag_1")
	waitFor(t, "run failed", func() bool {
		return e.runStatus(t, run.ID) == StatusFailed
	})
	// Non-canary hosts were never touched.
	if got := e.hostStatus(t, run.ID, "ag_2"); got != HostQueued {
		t.Errorf("ag_2 = %q, want queued (canary hard gate)", got)
	}
}

// TestRolloutWaveFailureSkip: a wave failure pauses the run; the operator
// skips the failed host and the rest completes.
func TestRolloutWaveFailureSkip(t *testing.T) {
	e := newTestEnv(t, 4)
	run, _, err := e.m.StartRun(Params{ReleaseID: "rel_t", Selector: "all", WavePct: 50, Actor: "admin", ActorRole: "admin"})
	if err != nil {
		t.Fatal(err)
	}
	// No canary (canary=0) -> straight to rolling, wave 1 = 2 hosts.
	waitFor(t, "wave 1 dispatched", func() bool {
		return e.hostStatus(t, run.ID, "ag_1") == HostDispatching &&
			e.hostStatus(t, run.ID, "ag_2") == HostDispatching
	})
	e.verify("ag_1", "verified", "v2.0.0")
	e.fail("ag_2")

	waitFor(t, "paused_failure", func() bool {
		return e.runStatus(t, run.ID) == StatusPausedFailure
	})

	// Skip the failed host.
	if err := e.m.Skip(run.ID, "admin"); err != nil {
		t.Fatalf("Skip: %v", err)
	}
	waitFor(t, "wave 2 dispatched", func() bool {
		return e.hostStatus(t, run.ID, "ag_3") == HostDispatching &&
			e.hostStatus(t, run.ID, "ag_4") == HostDispatching
	})
	e.verify("ag_3", "verified", "v2.0.0")
	e.verify("ag_4", "verified", "v2.0.0")
	waitFor(t, "completed", func() bool {
		return e.runStatus(t, run.ID) == StatusCompleted
	})
	r, _ := e.st.GetUpdateRun(run.ID)
	if r.DoneHosts != 3 || r.SkippedHosts != 1 {
		t.Errorf("counters = done:%d skipped:%d, want 3/1", r.DoneHosts, r.SkippedHosts)
	}
}

// TestRolloutWaveFailureRetry: a wave failure pauses; the operator retries
// the failed host and it recovers.
func TestRolloutWaveFailureRetry(t *testing.T) {
	e := newTestEnv(t, 2)
	run, _, err := e.m.StartRun(Params{ReleaseID: "rel_t", Selector: "all", WavePct: 100, Actor: "admin", ActorRole: "admin"})
	if err != nil {
		t.Fatal(err)
	}
	waitFor(t, "both dispatched", func() bool {
		return e.hostStatus(t, run.ID, "ag_1") == HostDispatching &&
			e.hostStatus(t, run.ID, "ag_2") == HostDispatching
	})
	e.verify("ag_1", "verified", "v2.0.0")
	e.fail("ag_2")
	waitFor(t, "paused_failure", func() bool {
		return e.runStatus(t, run.ID) == StatusPausedFailure
	})

	if err := e.m.Retry(run.ID, "admin"); err != nil {
		t.Fatalf("Retry: %v", err)
	}
	waitFor(t, "ag_2 re-dispatched", func() bool {
		return e.hostStatus(t, run.ID, "ag_2") == HostDispatching
	})
	e.verify("ag_2", "verified", "v2.0.0")
	waitFor(t, "completed", func() bool {
		return e.runStatus(t, run.ID) == StatusCompleted
	})
}

// TestRolloutApprovalGate: a require_approval policy parks the run; an admin
// approval starts it.
func TestRolloutApprovalGate(t *testing.T) {
	e := newTestEnv(t, 2)
	// Policy: require_approval for update.apply on all hosts.
	if err := e.st.CreatePolicy("pol_upd", "require approval for updates",
		policy.Match{Hosts: "all", Actions: []string{policy.ActionUpdateApply}},
		policy.EffectRequireApproval, 0); err != nil {
		t.Fatalf("CreatePolicy: %v", err)
	}
	// Approvals must be wired before creation so the run can park.
	e.m.SetApprovals(approvals.New(e.st, e.h, nil, log.New(io.Discard, "", 0)))

	run, req, err := e.m.StartRun(Params{ReleaseID: "rel_t", Selector: "all", WavePct: 100, Actor: "admin", ActorRole: "admin"})
	if err != nil {
		t.Fatalf("StartRun: %v", err)
	}
	if req == nil {
		t.Fatalf("expected an approval request")
	}
	if run.Status != StatusPending {
		t.Fatalf("status = %q, want pending", run.Status)
	}

	// No dispatch while parked.
	time.Sleep(50 * time.Millisecond)
	if got := e.hostStatus(t, run.ID, "ag_1"); got != HostQueued {
		t.Fatalf("host dispatched before approval: %q", got)
	}

	// Approve via the registered dispatcher (what the approvals controller
	// calls on approval).
	if err := e.m.DispatchApprovedRun(req, nil); err != nil {
		t.Fatalf("DispatchApprovedRun: %v", err)
	}
	waitFor(t, "rolling after approval", func() bool {
		return e.runStatus(t, run.ID) == StatusRolling
	})
	e.verify("ag_1", "verified", "v2.0.0")
	e.verify("ag_2", "verified", "v2.0.0")
	waitFor(t, "completed", func() bool {
		return e.runStatus(t, run.ID) == StatusCompleted
	})
}

// TestRolloutDenyExcludesHost: a deny rule excludes the matching host up
// front (recorded skipped), the rest proceeds.
func TestRolloutDenyExcludesHost(t *testing.T) {
	e := newTestEnv(t, 3)
	if err := e.st.CreatePolicy("pol_deny", "deny updates to ag_2",
		policy.Match{Hosts: "host:ag_2", Actions: []string{policy.ActionUpdateApply}},
		policy.EffectDeny, 0); err != nil {
		t.Fatalf("CreatePolicy: %v", err)
	}
	run, _, err := e.m.StartRun(Params{ReleaseID: "rel_t", Selector: "all", WavePct: 100, Actor: "admin", ActorRole: "admin"})
	if err != nil {
		t.Fatal(err)
	}
	// ag_2 is pre-marked skipped.
	if got := e.hostStatus(t, run.ID, "ag_2"); got != HostSkipped {
		t.Fatalf("ag_2 = %q, want skipped", got)
	}
	e.verify("ag_1", "verified", "v2.0.0")
	e.verify("ag_3", "verified", "v2.0.0")
	waitFor(t, "completed", func() bool {
		return e.runStatus(t, run.ID) == StatusCompleted
	})
	r, _ := e.st.GetUpdateRun(run.ID)
	if r.SkippedHosts != 1 {
		t.Errorf("skipped = %d, want 1", r.SkippedHosts)
	}
}

// TestRolloutAbort: abort ends a running run.
func TestRolloutAbort(t *testing.T) {
	e := newTestEnv(t, 4)
	run, _, err := e.m.StartRun(Params{ReleaseID: "rel_t", Selector: "all", WavePct: 50, Actor: "admin", ActorRole: "admin"})
	if err != nil {
		t.Fatal(err)
	}
	waitFor(t, "wave 1 dispatched", func() bool {
		return e.hostStatus(t, run.ID, "ag_1") == HostDispatching
	})
	if err := e.m.Abort(run.ID, "admin"); err != nil {
		t.Fatalf("Abort: %v", err)
	}
	if got := e.runStatus(t, run.ID); got != StatusAborted {
		t.Fatalf("status = %q, want aborted", got)
	}
}
