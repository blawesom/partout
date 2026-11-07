package agent_test

import (
	"context"
	"io"
	"log"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"google.golang.org/grpc"

	"github.com/blawesom/partout/internal/agent"
	"github.com/blawesom/partout/internal/agent/fs"
	"github.com/blawesom/partout/internal/config"
	"github.com/blawesom/partout/internal/identity"
	"github.com/blawesom/partout/internal/server/stream"
	"github.com/blawesom/partout/internal/sse"
	"github.com/blawesom/partout/internal/store"
)

// File-root fact reporting (docs/spec-file-root.md): the file-root fact
// must survive fact collection — sendFacts replaces the factset with each
// fresh Collector() snapshot, and the first replacement used to wipe the
// fact set at construction, making every 0.9.5+ agent look like a
// pre-file-root "legacy agent" on the server. An uncreatable root must
// report partout.file_root_error instead (fail closed, reason visible).
func TestAgentFileRootFacts(t *testing.T) {
	t.Run("root reported", func(t *testing.T) {
		root := t.TempDir()
		data, _ := runAgentForFacts(t, root)
		if data["partout.file_root"] == "" {
			t.Fatalf("file-root fact missing after the first facts batch (wiped by re-collection?): %v", data)
		}
		if data["partout.file_root_error"] != "" {
			t.Fatalf("unexpected file_root_error with a usable root: %q", data["partout.file_root_error"])
		}
	})

	t.Run("uncreatable root reports the reason", func(t *testing.T) {
		// A regular file as the parent: MkdirAll cannot create under it.
		f := filepath.Join(t.TempDir(), "not-a-dir")
		if err := os.WriteFile(f, []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
		data, _ := runAgentForFacts(t, filepath.Join(f, "root"))
		if data["partout.file_root"] != "" {
			t.Fatalf("file_root must be absent when the root is unusable: %q", data["partout.file_root"])
		}
		if data["partout.file_root_error"] == "" {
			t.Fatalf("file_root_error fact missing (server cannot tell fail-closed from legacy): %v", data)
		}
	})
}

// TestAgentFileRootFallsBackUnderDataDir (review §2.4): the default
// /home/partout cannot be used by a non-root user (uncreatable, or a
// root-owned leftover), which used to disable — or silently half-break —
// the file surface for every demo/manual agent; the UI then advises
// creating a partout service user, useless advice mid-demo. With no
// explicit root, the agent must fall back to <data-dir>/files.
func TestAgentFileRootFallsBackUnderDataDir(t *testing.T) {
	if fs.RootWritable(fs.DefaultFileRoot) {
		t.Skipf("default root %s is usable by this user (root, or a prepared install): the fallback never triggers", fs.DefaultFileRoot)
	}
	data, dataDir := runAgentForFacts(t, "")
	want, err := fs.PrepareFileRoot(filepath.Join(dataDir, "files"))
	if err != nil {
		t.Fatalf("prepare the expected fallback root: %v", err)
	}
	if data["partout.file_root"] != want {
		t.Fatalf("file_root = %q, want the data-dir fallback %q (file_root_error: %q)", data["partout.file_root"], want, data["partout.file_root_error"])
	}
	if data["partout.file_root_error"] != "" {
		t.Fatalf("file_root_error must be empty when the fallback engaged: %q", data["partout.file_root_error"])
	}
}

// runAgentForFacts boots a real agent against an in-process stream server
// and returns its first facts batch (plus the data dir it used, so callers
// can assert data-dir-derived paths).
func runAgentForFacts(t *testing.T, fileRoot string) (map[string]string, string) {
	t.Helper()
	dataDir := t.TempDir()
	st, err := store.New("sqlite::memory:")
	if err != nil {
		t.Fatalf("store.New: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	sseB := sse.New()
	h := stream.NewHandler(st, sseB, log.New(io.Discard, "srv: ", 0))

	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	gs := grpc.NewServer()
	h.Register(gs)
	go func() { _ = gs.Serve(lis) }()
	t.Cleanup(gs.Stop)

	id, err := identity.LoadOrGenerate(t.TempDir())
	if err != nil {
		t.Fatalf("identity: %v", err)
	}
	if err := st.UpsertAgent(store.Agent{
		ID: "ag_fr", UUID: id.UUID,
		ED25519Pub: id.Ed25519PubB64(), X25519Pub: id.X25519PubB64(),
	}); err != nil {
		t.Fatalf("UpsertAgent: %v", err)
	}

	ag := agent.New(id, &config.Config{
		Mode: "agent", ServerURL: lis.Addr().String(),
		DataDir: dataDir, FactsInterval: 3600,
		Elevate: "none", Root: "/", FileRoot: fileRoot,
	}, log.New(io.Discard, "agent: ", 0))

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

	// Wait for connect, then for the first facts batch (hello sends a
	// full snapshot) to land server-side.
	deadline := time.Now().Add(5 * time.Second)
	for {
		if h.AgentSession("ag_fr") != nil {
			if fl, err := st.LatestFacts("ag_fr"); err == nil && fl.Data["partout.version"] != "" {
				return fl.Data, dataDir
			}
		}
		if time.Now().After(deadline) {
			t.Fatal("agent did not connect + report facts within 5s")
		}
		time.Sleep(20 * time.Millisecond)
	}
}
