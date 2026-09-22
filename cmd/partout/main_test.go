package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/blawesom/partout/internal/config"
)

// freePort returns a port that is (almost certainly) free right now.
func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("freePort: %v", err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

// runEmbeddedOnce starts embedded mode on the given port/tmp dir, waits for
// the local agent to connect, then shuts it down cleanly. Returns the
// connected agent's id.
func runEmbeddedOnce(t *testing.T, port int, tmp string) string {
	t.Helper()
	cfg := config.Config{
		Mode:          "embedded",
		Port:          port,
		DBPath:        filepath.Join(tmp, "em.db"),
		DataDir:       filepath.Join(tmp, "agent"),
		AdminToken:    "test-admin",
		FactsInterval: 3600,
		Elevate:       "none",
		Root:          "/",
	}
	lg := log.New(io.Discard, "", 0)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errCh := make(chan error, 1)
	go func() { errCh <- runEmbedded(ctx, &cfg, lg) }()

	url := "http://127.0.0.1:" + strconv.Itoa(port) + "/api/v1/hosts"
	client := &http.Client{Timeout: 2 * time.Second}
	var hostID string
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) && hostID == "" {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			break
		}
		req.Header.Set("Authorization", "Bearer test-admin")
		resp, err := client.Do(req)
		if err != nil {
			time.Sleep(200 * time.Millisecond)
			continue
		}
		var body struct {
			Items []struct {
				ID    string `json:"id"`
				State string `json:"state"`
			} `json:"items"`
		}
		_ = json.NewDecoder(resp.Body).Decode(&body)
		resp.Body.Close()
		for _, h := range body.Items {
			if h.State == "connected" {
				hostID = h.ID
			}
		}
		time.Sleep(200 * time.Millisecond)
	}

	if hostID == "" {
		select {
		case e := <-errCh:
			t.Fatalf("runEmbedded exited early: %v", e)
		default:
		}
		t.Fatal("embedded agent did not become connected within 30s")
	}

	cancel()
	select {
	case e := <-errCh:
		if e != nil && !errors.Is(e, context.Canceled) {
			t.Fatalf("runEmbedded returned non-canceled error on shutdown: %v", e)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("runEmbedded did not shut down within 15s")
	}
	return hostID
}

// TestEmbeddedFirstBoot verifies the full first-boot pipeline: server
// bootstrap → local token creation → loopback enrollment → gRPC handshake →
// identity persistence → clean shutdown.
func TestEmbeddedFirstBoot(t *testing.T) {
	port := freePort(t)
	tmp := t.TempDir()

	hostID := runEmbeddedOnce(t, port, tmp)
	if hostID == "" {
		t.Fatal("no host id returned")
	}
	t.Logf("embedded agent connected as %s", hostID)

	if _, err := os.Stat(filepath.Join(tmp, "agent", "identity.json")); err != nil {
		t.Fatalf("agent identity not persisted: %v", err)
	}
}

// TestEmbeddedRestart verifies the second-boot path: the persisted identity
// reconnects to the same server without re-enrolling (same agent id).
func TestEmbeddedRestart(t *testing.T) {
	port := freePort(t)
	tmp := t.TempDir()

	first := runEmbeddedOnce(t, port, tmp)
	second := runEmbeddedOnce(t, port, tmp)
	if first == "" || second == "" {
		t.Fatalf("missing host id: first=%q second=%q", first, second)
	}
	if first != second {
		t.Fatalf("restart changed the agent id: first=%s second=%s", first, second)
	}
	t.Logf("restart reconnected with same agent %s", first)
}
