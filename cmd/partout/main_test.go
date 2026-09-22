package main

import (
	"bytes"
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

// ---- host provisioning (REST wiring) ----------------------------------------

// writeFakeFleet writes fake ssh/scp/ssh-keyscan/ssh-keygen binaries to binDir
// that emulate a remote host without systemd (so the run terminates at the
// preflight handoff, before any real install/enrollment is needed).
func writeFakeFleet(t *testing.T, binDir string) {
	t.Helper()
	ssh := `#!/bin/sh
echo "os=Alpine 3.20"
echo "arch=x86_64"
echo "init=none"
echo "user=root"
echo "sudo=yes"
echo "disk=100000000"
exit 0
`
	scp := "#!/bin/sh\nexit 0\n"
	keyscan := `#!/bin/sh
echo "$3 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFakeFleetKeyForTest0123456789abcdef"
exit 0
`
	keygen := `#!/bin/sh
case "$1" in
  -F) if grep -qF "$2" "$HOME/.ssh/known_hosts" 2>/dev/null; then exit 0; else exit 1; fi ;;
  -H) exit 0 ;;
  -l) cat >/dev/null; echo "256 SHA256:FakeFleetFingerprint comment (ED25519)"; exit 0 ;;
esac
exit 0
`
	for name, body := range map[string]string{
		"ssh": ssh, "scp": scp, "ssh-keyscan": keyscan, "ssh-keygen": keygen,
	} {
		if err := os.WriteFile(filepath.Join(binDir, name), []byte(body), 0o755); err != nil {
			t.Fatalf("write fake %s: %v", name, err)
		}
	}
}

// TestProvisionREST validates the full REST wiring end-to-end: the server
// builds the provisioner, the admin endpoint creates a run, the fingerprint
// gate pauses the run at key_confirm, and confirming the key lets the run
// proceed to preflight (which hands off on the non-systemd fake host).
func TestProvisionREST(t *testing.T) {
	tmp := t.TempDir()
	binDir := filepath.Join(tmp, "fakes")
	os.MkdirAll(binDir, 0o755)
	writeFakeFleet(t, binDir)

	sshDir := filepath.Join(tmp, "ssh")
	os.MkdirAll(sshDir, 0o700)

	// Point the process at our fakes and the temp ssh dir. These are
	// process-global, so restore on cleanup.
	oldPath := os.Getenv("PATH")
	oldSSHDir := os.Getenv("PARTOUT_SSH_DIR")
	oldServerHost := os.Getenv("PARTOUT_SERVER_HOST")
	os.Setenv("PATH", binDir+string(os.PathListSeparator)+oldPath)
	os.Setenv("PARTOUT_SSH_DIR", sshDir)
	os.Setenv("PARTOUT_SERVER_HOST", "127.0.0.1")
	t.Cleanup(func() {
		os.Setenv("PATH", oldPath)
		os.Setenv("PARTOUT_SSH_DIR", oldSSHDir)
		os.Setenv("PARTOUT_SERVER_HOST", oldServerHost)
	})

	port := freePort(t)
	cfg := config.Config{
		Mode:       "server",
		Port:       port,
		DBPath:     filepath.Join(tmp, "srv.db"),
		AdminToken: "prov-admin",
	}
	lg := log.New(io.Discard, "", 0)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	errCh := make(chan error, 1)
	go func() { errCh <- runServer(ctx, &cfg, lg) }()

	base := "http://127.0.0.1:" + strconv.Itoa(port)
	client := &http.Client{Timeout: 2 * time.Second}
	get := func(path string, out any) error {
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, base+path, nil)
		req.Header.Set("Authorization", "Bearer prov-admin")
		resp, err := client.Do(req)
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		if resp.StatusCode >= 400 {
			b, _ := io.ReadAll(resp.Body)
			return errors.New(string(b))
		}
		return json.NewDecoder(resp.Body).Decode(out)
	}
	post := func(path string, body any, out any) error {
		b, _ := json.Marshal(body)
		req, _ := http.NewRequestWithContext(ctx, http.MethodPost, base+path, bytes.NewReader(b))
		req.Header.Set("Authorization", "Bearer prov-admin")
		req.Header.Set("Content-Type", "application/json")
		resp, err := client.Do(req)
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		if resp.StatusCode >= 400 {
			bb, _ := io.ReadAll(resp.Body)
			return errors.New(string(bb))
		}
		if out != nil {
			return json.NewDecoder(resp.Body).Decode(out)
		}
		return nil
	}

	// Wait for the server to be ready.
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		var hz struct{}
		if err := get("/healthz", &hz); err == nil {
			break
		}
		select {
		case e := <-errCh:
			t.Fatalf("server exited early: %v", e)
		case <-time.After(100 * time.Millisecond):
		}
	}

	// Create a provision run for an untrusted fake host.
	var created struct {
		ID    string `json:"id"`
		State string `json:"state"`
	}
	if err := post("/api/v1/provision-runs", map[string]string{"host": "web01.test", "mode": "fresh"}, &created); err != nil {
		t.Fatalf("create run: %v", err)
	}
	if created.ID == "" {
		t.Fatal("no run id returned")
	}

	// The run must pause at key_confirm (untrusted host).
	type runView struct {
		State string `json:"state"`
		Step  string `json:"step"`
		Error string `json:"error"`
	}
	waitFor := func(want string) *runView {
		var lastErr error
		deadline := time.Now().Add(30 * time.Second)
		for time.Now().Before(deadline) {
			var res struct {
				Run *runView `json:"run"`
			}
			lastErr = get("/api/v1/provision-runs/"+created.ID, &res)
			if lastErr == nil && res.Run != nil && res.Run.State == want {
				return res.Run
			}
			time.Sleep(100 * time.Millisecond)
		}
		t.Fatalf("run did not reach %q (lastErr=%v)", want, lastErr)
		return nil
	}

	waitFor("key_confirm")

	// Confirm the key: the run should proceed to preflight and, on the
	// non-systemd fake host, terminate in the "handoff" state.
	if err := post("/api/v1/provision-runs/"+created.ID+"/key", map[string]string{"action": "confirm"}, nil); err != nil {
		t.Fatalf("confirm key: %v", err)
	}
	run := waitFor("handoff")
	if run.Error == "" {
		t.Error("handoff run should carry a remediation note")
	}
}
