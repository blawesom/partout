package agent_test

import (
	"context"
	"io"
	"log"
	"net"
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
