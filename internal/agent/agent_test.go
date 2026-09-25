package agent_test

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc"

	"github.com/blawesom/partout/internal/agent"
	"github.com/blawesom/partout/internal/config"
	"github.com/blawesom/partout/internal/control"
	"github.com/blawesom/partout/internal/identity"
	"github.com/blawesom/partout/internal/server/stream"
	"github.com/blawesom/partout/internal/sse"
	"github.com/blawesom/partout/internal/store"
)

// TestAgentRunLoop runs the real agent run loop against a real (localhost
// TCP) server: connect, handshake, facts, command execution, output capture.
func TestAgentRunLoop(t *testing.T) {
	// Server side.
	st, err := store.New("sqlite::memory:")
	if err != nil {
		t.Fatalf("store.New: %v", err)
	}
	t.Cleanup(func() { st.Close() })

	sseB := sse.New()
	h := stream.NewHandler(st, sseB, log.New(io.Discard, "srv: ", 0))
	ctl := control.New(st, h, sseB, log.New(io.Discard, "ctl: ", 0))

	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	gs := grpc.NewServer()
	h.Register(gs)
	go func() { _ = gs.Serve(lis) }()
	t.Cleanup(gs.Stop)

	// Seed the agent (pre-enrolled, as if enrollment already completed).
	id, err := identity.LoadOrGenerate(t.TempDir())
	if err != nil {
		t.Fatalf("identity: %v", err)
	}
	if err := st.UpsertAgent(store.Agent{
		ID: "ag_run", UUID: id.UUID,
		ED25519Pub: id.Ed25519PubB64(), X25519Pub: id.X25519PubB64(),
	}); err != nil {
		t.Fatalf("UpsertAgent: %v", err)
	}
	if err := st.SetRole("ag_run", "web"); err != nil {
		t.Fatalf("SetRole: %v", err)
	}

	// Agent side.
	agentCfg := &config.Config{
		Mode:          "agent",
		ServerURL:     lis.Addr().String(),
		DataDir:       t.TempDir(),
		FactsInterval: 3600,
		Elevate:       "none",
		Root:          "/",
	}
	ag := agent.New(id, agentCfg, log.New(io.Discard, "agent: ", 0))

	ctx, cancel := context.WithCancel(context.Background())
	runDone := make(chan error, 1)
	go func() { runDone <- ag.Run(ctx) }()
	t.Cleanup(func() {
		cancel()
		select {
		case <-runDone:
		case <-time.After(3 * time.Second):
			t.Log("agent Run did not return within 3s of cancel")
		}
	})

	// Wait for the agent to connect.
	deadline := time.Now().Add(5 * time.Second)
	for {
		if h.AgentSession("ag_run") != nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("agent did not connect within 5s")
		}
		time.Sleep(20 * time.Millisecond)
	}

	// Wait for the agent to receive the policy bundle (pushed on connect),
	// so the guardrail is effective before we dispatch.
	deadline = time.Now().Add(5 * time.Second)
	for !ag.GuardLoaded() {
		if time.Now().After(deadline) {
			t.Fatal("agent did not receive policy bundle within 5s")
		}
		time.Sleep(10 * time.Millisecond)
	}

	// Dispatch a command.
	res, err := ctl.Dispatch(ctx, control.DispatchRequest{
		Selector: "role:web", Cmd: "echo", Args: []string{"agent-loop-works"},
		TimeoutS: 10, CreatedBy: "test",
	})
	if err != nil {
		t.Fatalf("Dispatch: %v", err)
	}
	if len(res.Runs) != 1 || !res.Runs[0].Delivered {
		t.Fatalf("dispatch result = %+v (errors: %v)", res, res.Errors)
	}
	runID := res.Runs[0].RunID
	execID := res.ExecutionID

	// Wait for the run to reach a terminal state with captured output.
	deadline = time.Now().Add(5 * time.Second)
	for {
		runs, err := st.ListRunsForExecution(execID)
		if err == nil && len(runs) == 1 && runs[0].State == "succeeded" {
			break
		}
		if time.Now().After(deadline) {
			state := "none"
			if err == nil && len(runs) == 1 {
				state = runs[0].State
			}
			t.Fatalf("run did not succeed (state=%s)", state)
		}
		time.Sleep(50 * time.Millisecond)
	}

	chunks, err := st.ListOutput(runID)
	if err != nil {
		t.Fatalf("ListOutput: %v", err)
	}
	var out strings.Builder
	for _, c := range chunks {
		out.Write(c.Data)
	}
	if got := strings.TrimSpace(out.String()); got != "agent-loop-works" {
		t.Fatalf("output = %q, want 'agent-loop-works'", got)
	}
}

// TestOfflineSpoolReplay is the M1 E2E for offline spooling
// (architecture §3.4: "Server down, agent up → results spool; replay on
// reconnect"). A long-running command is dispatched; the server is stopped
// mid-run; the agent keeps the process alive and spools its output; the
// server is restarted on the same port; the agent reconnects and drains the
// spool; the run reaches succeeded with complete output.
func TestOfflineSpoolReplay(t *testing.T) {
	// Server side (real TCP, stoppable).
	st, err := store.New("sqlite::memory:")
	if err != nil {
		t.Fatalf("store.New: %v", err)
	}
	defer st.Close()

	sseB := sse.New()
	h := stream.NewHandler(st, sseB, log.New(io.Discard, "srv: ", 0))
	ctl := control.New(st, h, sseB, log.New(io.Discard, "ctl: ", 0))

	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := lis.Addr().String()
	gs := grpc.NewServer()
	h.Register(gs)
	go func() { _ = gs.Serve(lis) }()

	// Seed the agent (pre-enrolled).
	id, err := identity.LoadOrGenerate(t.TempDir())
	if err != nil {
		t.Fatalf("identity: %v", err)
	}
	if err := st.UpsertAgent(store.Agent{
		ID: "ag_spool", UUID: id.UUID,
		ED25519Pub: id.Ed25519PubB64(), X25519Pub: id.X25519PubB64(),
	}); err != nil {
		t.Fatalf("UpsertAgent: %v", err)
	}
	if err := st.SetRole("ag_spool", "web"); err != nil {
		t.Fatalf("SetRole: %v", err)
	}

	// Agent side.
	dataDir := t.TempDir()
	agentCfg := &config.Config{
		Mode:          "agent",
		ServerURL:     addr,
		DataDir:       dataDir,
		FactsInterval: 3600,
		Elevate:       "none",
		Root:          "/",
	}
	ag := agent.New(id, agentCfg, log.New(io.Discard, "agent: ", 0))

	ctx, cancel := context.WithCancel(context.Background())
	runDone := make(chan error, 1)
	go func() { runDone <- ag.Run(ctx) }()
	gsStopped := false
	t.Cleanup(func() {
		cancel()
		select {
		case <-runDone:
		case <-time.After(5 * time.Second):
		}
		if !gsStopped {
			gs.Stop()
		}
	})

	// Wait for connection + policy bundle.
	deadline := time.Now().Add(5 * time.Second)
	for {
		if h.AgentSession("ag_spool") != nil && ag.GuardLoaded() {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("agent did not connect + load guard within 5s")
		}
		time.Sleep(20 * time.Millisecond)
	}

	// Dispatch a long-running command (~2.1s, one line every 0.4s).
	res, err := ctl.Dispatch(ctx, control.DispatchRequest{
		Selector: "role:web",
		Cmd:      "sh",
		Args:     []string{"-c", "for i in 1 2 3 4 5; do echo line-$i; sleep 0.4; done"},
		TimeoutS: 20, CreatedBy: "test",
	})
	if err != nil {
		t.Fatalf("Dispatch: %v", err)
	}
	if len(res.Runs) != 1 || !res.Runs[0].Delivered {
		t.Fatalf("dispatch result = %+v (errors: %v)", res, res.Errors)
	}
	runID := res.Runs[0].RunID
	execID := res.ExecutionID

	// Wait until the run is running (first output delivered).
	deadline = time.Now().Add(5 * time.Second)
	for {
		runs, err := st.ListRunsForExecution(execID)
		if err == nil && len(runs) == 1 && runs[0].State == "running" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("run did not reach running within 5s")
		}
		time.Sleep(50 * time.Millisecond)
	}

	// --- Stop the server mid-run (the outage). ---
	gs.Stop()
	gsStopped = true

	// The agent goes disconnected and the server marks the run interrupted.
	deadline = time.Now().Add(10 * time.Second)
	var agState, runState string
	for {
		a, _ := st.Agent("ag_spool")
		agState = ""
		if a != nil {
			agState = a.State
		}
		runs, err := st.ListRunsForExecution(execID)
		runState = ""
		if err == nil && len(runs) == 1 {
			runState = runs[0].State
		}
		if agState == "disconnected" && runState == "interrupted" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("after stop: agent=%q run=%q, want disconnected/interrupted", agState, runState)
		}
		time.Sleep(100 * time.Millisecond)
	}

	// --- Restart the server on the same port (the recovery). ---
	time.Sleep(500 * time.Millisecond)
	lis2, err := net.Listen("tcp", addr)
	if err != nil {
		t.Fatalf("re-listen: %v", err)
	}
	gs2 := grpc.NewServer()
	h.Register(gs2)
	go func() { _ = gs2.Serve(lis2) }()
	t.Cleanup(gs2.Stop)

	// --- Wait for the replay: run succeeds with the complete output. ---
	deadline = time.Now().Add(25 * time.Second)
	var finalState string
	for {
		runs, err := st.ListRunsForExecution(execID)
		finalState = ""
		if err == nil && len(runs) == 1 {
			finalState = runs[0].State
		}
		if finalState == "succeeded" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("run did not succeed after recovery (state=%q)", finalState)
		}
		time.Sleep(100 * time.Millisecond)
	}

	chunks, err := st.ListOutput(runID)
	if err != nil {
		t.Fatalf("ListOutput: %v", err)
	}
	var out strings.Builder
	for _, c := range chunks {
		out.Write(c.Data)
	}
	text := out.String()
	// The complete output must be present in order: a gap in the middle is
	// exactly the failure mode this feature exists to prevent, so assert the
	// exact expected text rather than a subset/count.
	want := ""
	for i := 1; i <= 5; i++ {
		want += fmt.Sprintf("line-%d\n", i)
	}
	if text != want {
		t.Errorf("output = %q, want %q (every line must survive the outage in order)", text, want)
	}

	// The execution aggregate must converge to succeeded after the replay.
	exec, err := st.GetExecution(execID)
	if err != nil {
		t.Fatalf("GetExecution: %v", err)
	}
	if exec.State != "succeeded" {
		t.Errorf("execution state = %q, want succeeded", exec.State)
	}

	// The spool must be empty after a successful drain.
	entries, _ := os.ReadDir(filepath.Join(dataDir, "spool"))
	if len(entries) != 0 {
		t.Errorf("spool dir not empty after drain: %v", entries)
	}
}

// TestAgentSpoolLayoutAndFailFast locks in two startup guarantees:
//   - the spool lives directly under the agent data dir (which is already the
//     per-agent root, e.g. /var/lib/partout/agent → <dir>/spool, not
//     <dir>/agent/spool);
//   - an unusable spool dir fails Run loudly instead of silently dropping
//     every result produced during a disconnect.
func TestAgentSpoolLayoutAndFailFast(t *testing.T) {
	id, err := identity.LoadOrGenerate(t.TempDir())
	if err != nil {
		t.Fatalf("identity: %v", err)
	}

	t.Run("layout", func(t *testing.T) {
		dataDir := t.TempDir()
		ag := agent.New(id, &config.Config{
			Mode: "agent", DataDir: dataDir, FactsInterval: 3600,
		}, log.New(io.Discard, "agent: ", 0))
		// Run only to open the spool, then stop immediately (no server).
		ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
		defer cancel()
		_ = ag.Run(ctx)

		if _, err := os.Stat(filepath.Join(dataDir, "spool")); err != nil {
			t.Errorf("expected spool at <datadir>/spool: %v", err)
		}
		if _, err := os.Stat(filepath.Join(dataDir, "agent", "spool")); err == nil {
			t.Errorf("unexpected nested spool at <datadir>/agent/spool")
		}
	})

	t.Run("fail-fast on unwritable dir", func(t *testing.T) {
		// A regular file where the data dir should be makes MkdirAll fail.
		file := filepath.Join(t.TempDir(), "not-a-dir")
		if err := os.WriteFile(file, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
		ag := agent.New(id, &config.Config{
			Mode: "agent", DataDir: file, FactsInterval: 3600,
		}, log.New(io.Discard, "agent: ", 0))

		err := ag.Run(context.Background())
		if err == nil {
			t.Fatal("Run succeeded without a usable spool; want a loud failure")
		}
		if !strings.Contains(err.Error(), "spool") {
			t.Errorf("error %q does not mention the spool", err)
		}
	})
}

// TestAgentObserveFactsUpload is the M5 E2E: a connected agent collects
// structured facts (services/configs/certs) and uploads OBSERVE_FACTS
// envelopes; the server merges them into the host_facts JSON blob. On hosts
// without systemd or TLS material the collectors return nil and the test
// skips — the envelope path itself is covered by TestObserveFactsIngestion.
func TestAgentObserveFactsUpload(t *testing.T) {
	st, err := store.New("sqlite::memory:")
	if err != nil {
		t.Fatalf("store.New: %v", err)
	}
	defer st.Close()

	sseB := sse.New()
	h := stream.NewHandler(st, sseB, log.New(io.Discard, "srv: ", 0))

	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	gs := grpc.NewServer()
	h.Register(gs)
	go func() { _ = gs.Serve(lis) }()
	defer gs.Stop()

	id, err := identity.LoadOrGenerate(t.TempDir())
	if err != nil {
		t.Fatalf("identity: %v", err)
	}
	if err := st.UpsertAgent(store.Agent{
		ID: "ag_obs", UUID: id.UUID,
		ED25519Pub: id.Ed25519PubB64(), X25519Pub: id.X25519PubB64(),
	}); err != nil {
		t.Fatalf("UpsertAgent: %v", err)
	}

	agentCfg := &config.Config{
		Mode:                 "agent",
		ServerURL:            lis.Addr().String(),
		DataDir:              t.TempDir(),
		FactsInterval:        3600,
		ObserveFactsInterval: 1,
		Elevate:              "none",
		Root:                 "/",
	}
	ag := agent.New(id, agentCfg, log.New(io.Discard, "agent: ", 0))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = ag.Run(ctx) }()

	// Wait for the agent to connect, then poll for the observe facts blob.
	// Collection probes systemctl/openssl and can take several seconds; the
	// flat facts row lands first, so wait for a domain key, not any blob.
	var blob string
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		b, err := st.LatestHostFactsJSON("ag_obs")
		if err == nil && (strings.Contains(b, "\"services_detailed\"") || strings.Contains(b, "\"configs\"") || strings.Contains(b, "\"certificates\"")) {
			blob = b
			break
		}
		time.Sleep(200 * time.Millisecond)
	}
	if blob == "" {
		t.Skip("no structured facts collected (no systemd/TLS material on this host)")
	}
	// The blob must be valid JSON with at least one known domain key.
	var parsed map[string]any
	if err := json.Unmarshal([]byte(blob), &parsed); err != nil {
		t.Fatalf("host_facts blob is not valid JSON: %v\nblob: %s", err, blob)
	}
	found := false
	for _, key := range []string{"services_detailed", "configs", "certificates"} {
		if _, ok := parsed[key]; ok {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("blob has no known domain key: %s", blob)
	}
}
