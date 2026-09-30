package updates

import (
	"context"
	"fmt"
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

// TestRunSurvivesServerRestart: a directive dispatched to an offline host is
// durable (pending_updates); a restart + ResumeAll re-attaches the run, and
// the terminal result retires the pending row.
func TestRunSurvivesServerRestart(t *testing.T) {
	e := newTestEnv(t, 1)
	run, _, err := e.m.StartRun(Params{
		ReleaseID: e.rel.ID, Selector: "all", WavePct: 100, Actor: "t", ActorRole: "admin",
	})
	if err != nil {
		t.Fatalf("StartRun: %v", err)
	}
	runID := run.ID

	// Host is offline (no session): dispatch queues the directive durably.
	waitFor(t, "host dispatching", func() bool {
		return e.hostStatus(t, runID, "ag_1") == HostDispatching
	})
	if p, _ := e.st.GetPendingUpdate("ag_1"); p == nil || p.ReleaseID != e.rel.ID {
		t.Fatalf("pending row = %+v, want release %s", p, e.rel.ID)
	}

	// "Restart": new stream handler + manager on the same store.
	h2 := stream.NewHandler(e.st, nil, log.New(io.Discard, "", 0))
	m2 := New(e.st, h2, nil, log.New(io.Discard, "", 0))
	m2.SetPollInterval(20 * time.Millisecond)
	m2.ResumeAll(context.Background())
	// The resumed run keeps driving (still rolling, host still in flight).
	waitFor(t, "run re-attached after restart", func() bool {
		st := e.runStatus(t, runID)
		return st == StatusRolling || st == StatusCanary
	})

	// The host's (re)connect delivers the directive; it completes the update.
	// (Drain delivery itself is covered by the stream whitebox tests; here we
	// assert the manager bookkeeping: terminal result retires the row.)
	m2.OnResult("ag_1", &pb.UpdateResult{ReleaseId: e.rel.ID, Phase: "verified", Version: "v2.0.0"})
	waitFor(t, "host verified", func() bool {
		return e.hostStatus(t, runID, "ag_1") == HostVerified
	})
	waitFor(t, "run completed", func() bool {
		return e.runStatus(t, runID) == StatusCompleted
	})
	if p, _ := e.st.GetPendingUpdate("ag_1"); p != nil {
		t.Errorf("pending row not retired after verified: %+v", p)
	}
}

// TestAbortClearsPendingAndTerminatesHosts: aborting a run whose hosts are
// still offline must terminate their host rows and retire the pending row.
func TestAbortClearsPendingAndTerminatesHosts(t *testing.T) {
	e := newTestEnv(t, 1)
	run, _, err := e.m.StartRun(Params{
		ReleaseID: e.rel.ID, Selector: "all", WavePct: 100, Actor: "t", ActorRole: "admin",
	})
	if err != nil {
		t.Fatalf("StartRun: %v", err)
	}
	runID := run.ID
	waitFor(t, "host dispatching", func() bool {
		return e.hostStatus(t, runID, "ag_1") == HostDispatching
	})
	if p, _ := e.st.GetPendingUpdate("ag_1"); p == nil {
		t.Fatal("expected a pending row for the offline host")
	}

	if err := e.m.Abort(runID, "t"); err != nil {
		t.Fatalf("Abort: %v", err)
	}
	if st := e.runStatus(t, runID); st != StatusAborted {
		t.Fatalf("run = %q, want aborted", st)
	}
	if st := e.hostStatus(t, runID, "ag_1"); st != HostSkipped {
		t.Fatalf("host = %q, want skipped (terminated by abort)", st)
	}
	if p, _ := e.st.GetPendingUpdate("ag_1"); p != nil {
		t.Errorf("pending row not cleared on abort: %+v", p)
	}
}

// TestRolloutScale100: a 100-host rollout (canary 1, waves of 10%) completes
// cleanly — the FSM, store, and dispatch path at fleet scale (1.0 prep).
func TestRolloutScale100(t *testing.T) {
	t.Helper()
	const N = 100
	st, err := store.New("sqlite::memory:")
	if err != nil {
		t.Fatalf("store.New: %v", err)
	}
	t.Cleanup(func() { st.Close() })

	for i := 0; i < N; i++ {
		id := fmt.Sprintf("ag_s100_%03d", i)
		if err := st.UpsertAgent(store.Agent{ID: id, UUID: "u" + id}); err != nil {
			t.Fatalf("UpsertAgent: %v", err)
		}
	}
	rel := store.Release{
		ID: "rel_s100", Version: "v2.0.0", Arch: "linux-amd64", Kind: "agent",
		SHA256: "aa", Signature: "sig", Artifact: []byte("x"),
	}
	if err := st.InsertRelease(rel); err != nil {
		t.Fatalf("InsertRelease: %v", err)
	}
	h := stream.NewHandler(st, nil, log.New(io.Discard, "", 0))
	m := New(st, h, nil, log.New(io.Discard, "", 0))
	m.SetPollInterval(10 * time.Millisecond)

	run, _, err := m.StartRun(Params{
		ReleaseID: rel.ID, Selector: "all", Canary: 1, WavePct: 10,
		Actor: "scale", ActorRole: "admin",
	})
	if err != nil {
		t.Fatalf("StartRun: %v", err)
	}

	// Verify hosts as they are dispatched (a real fleet reports promptly).
	done := 0
	deadline := time.Now().Add(120 * time.Second)
	for time.Now().Before(deadline) {
		r, _ := st.GetUpdateRun(run.ID)
		if r == nil {
			t.Fatal("run row gone")
		}
		if r.Status == StatusCompleted {
			break
		}
		if r.Status == StatusFailed || r.Status == StatusPausedFailure {
			t.Fatalf("run ended in %s: %s", r.Status, r.Error)
		}
		hosts, err := st.ListUpdateHosts(run.ID)
		if err != nil {
			t.Fatalf("ListUpdateHosts: %v", err)
		}
		for _, hh := range hosts {
			if hh.Status == HostDispatching {
				m.OnResult(hh.HostID, &pb.UpdateResult{ReleaseId: rel.ID, Phase: "verified", Version: "v2.0.0"})
			}
		}
		if r.DoneHosts > done {
			done = r.DoneHosts
		}
		time.Sleep(5 * time.Millisecond)
	}
	r, _ := st.GetUpdateRun(run.ID)
	if r.Status != StatusCompleted {
		t.Fatalf("run status = %s (done=%d/%d), want completed", r.Status, r.DoneHosts, r.TotalHosts)
	}
	if r.DoneHosts != N || r.TotalHosts != N || r.FailedHosts != 0 {
		t.Fatalf("counters = done:%d total:%d failed:%d, want %d/%d/0", r.DoneHosts, r.TotalHosts, r.FailedHosts, N, N)
	}
}

// --- M8.1.1: parked drafts (auto-draft rollout) ---------------------------

func TestDraftRolloutParkAndStart(t *testing.T) {
	e := newTestEnv(t, 4)

	// Parked draft: persisted, but nothing dispatches.
	run, _, err := e.m.StartRun(Params{ReleaseID: "rel_t", Selector: "all", Canary: 1,
		Actor: "admin", ActorRole: "admin", Park: true})
	if err != nil {
		t.Fatalf("StartRun(park): %v", err)
	}
	if got := e.runStatus(t, run.ID); got != StatusDraft {
		t.Fatalf("draft status = %q, want %q", got, StatusDraft)
	}
	time.Sleep(150 * time.Millisecond) // the FSM must not touch a draft
	if got := e.runStatus(t, run.ID); got != StatusDraft {
		t.Fatalf("draft moved on its own to %q", got)
	}

	// An operator starts it: canary phase begins.
	if err := e.m.Start(run.ID, "admin"); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if got := e.runStatus(t, run.ID); got != StatusCanary {
		t.Fatalf("status after start = %q, want %q", got, StatusCanary)
	}
	// Starting a non-draft run must fail.
	if err := e.m.Start(run.ID, "admin"); err == nil {
		t.Fatal("Start on a non-draft run should fail")
	}
}

func TestDraftWithNoCanaryGoesRolling(t *testing.T) {
	e := newTestEnv(t, 3)
	run, _, err := e.m.StartRun(Params{ReleaseID: "rel_t", Selector: "all", Canary: 0,
		Actor: "admin", ActorRole: "admin", Park: true})
	if err != nil {
		t.Fatalf("StartRun(park): %v", err)
	}
	if err := e.m.Start(run.ID, "admin"); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if got := e.runStatus(t, run.ID); got != StatusRolling {
		t.Fatalf("status after start = %q, want %q", got, StatusRolling)
	}
}

func TestMaybeDraftDedup(t *testing.T) {
	e := newTestEnv(t, 3)
	first := e.m.MaybeDraft(e.rel, "admin")
	if first == nil || first.Status != StatusDraft {
		t.Fatalf("MaybeDraft = %v, want a draft run", first)
	}
	// A second call while the draft is non-terminal: no duplicate.
	if second := e.m.MaybeDraft(e.rel, "admin"); second != nil {
		t.Fatalf("MaybeDraft duplicated while non-terminal: %s", second.ID)
	}
	// A terminal run doesn't block a new draft.
	if err := e.m.Abort(first.ID, "admin"); err != nil {
		t.Fatalf("Abort: %v", err)
	}
	if third := e.m.MaybeDraft(e.rel, "admin"); third == nil {
		t.Fatal("MaybeDraft after abort should create a new draft")
	}
}
