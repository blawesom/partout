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
	"strings"
	"testing"
	"time"

	"github.com/blawesom/partout/internal/config"
	serverauth "github.com/blawesom/partout/internal/server/auth"
	"github.com/blawesom/partout/internal/store"
)

// freePort returns a port that is free right now and confirmed bindable on
// the wildcard address runEmbedded actually uses (":port"), so a restart
// cannot collide with a lingering listener from a previous instance.
func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("freePort: %v", err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	l.Close()
	// Confirm the wildcard bind (what runEmbedded uses) also succeeds.
	wl, err := net.Listen("tcp", ":"+strconv.Itoa(port))
	if err != nil {
		t.Fatalf("freePort: wildcard bind :%d: %v", port, err)
	}
	wl.Close()
	return port
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
		// Fail fast if runEmbedded died (e.g. the port was still bound by a
		// previous instance). Otherwise the loop spins for the full 30s and
		// reports a misleading "did not become connected" error.
		select {
		case e := <-errCh:
			t.Fatalf("runEmbedded exited early: %v", e)
		default:
		}
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

// TestEmbeddedBootstrapAdmin verifies first-run admin bootstrap: a generated
// password is persisted to <db dir>/admin_password.txt (0600) and the admin
// principal verifies against it.
func TestEmbeddedBootstrapAdmin(t *testing.T) {
	port := freePort(t)
	tmp := t.TempDir()

	if hostID := runEmbeddedOnce(t, port, tmp); hostID == "" {
		t.Fatal("no host id returned")
	}

	pwPath := filepath.Join(tmp, "admin_password.txt")
	info, err := os.Stat(pwPath)
	if err != nil {
		t.Fatalf("admin password file missing: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Fatalf("admin password file mode = %o, want 600", perm)
	}
	pwBytes, err := os.ReadFile(pwPath)
	if err != nil {
		t.Fatal(err)
	}
	pw := strings.TrimSpace(string(pwBytes))
	if len(pw) < 8 {
		t.Fatalf("generated password too short: %d chars", len(pw))
	}

	// The principal exists and verifies against the file's password. Retry
	// the open: right after the embedded server shuts down the WAL lock may
	// not be released yet (transient SQLITE_BUSY under CI load).
	var st *store.Store
	deadline := time.Now().Add(10 * time.Second)
	for {
		st, err = store.New("sqlite:" + filepath.Join(tmp, "em.db"))
		if err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("open store: %v", err)
		}
		time.Sleep(200 * time.Millisecond)
	}
	defer st.Close()
	p, err := st.Principal("admin")
	if err != nil || p == nil {
		t.Fatalf("admin principal: %v %v", err, p)
	}
	if p.Role != "admin" {
		t.Fatalf("admin role = %q", p.Role)
	}
	if !serverauth.VerifyPassword(p.PasswordHash, pw) {
		t.Fatal("admin password file does not verify against stored hash")
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

// ---- embedded: auth + identity edge cases (regression) ----------------------

// runEmbeddedCfg is runEmbeddedOnce with a caller-supplied config, so tests can
// exercise the password-only / stale-identity paths the static-token helper
// never covers. Returns the connected host id ("" on failure).
func runEmbeddedCfg(t *testing.T, cfg *config.Config, lg *log.Logger, wait time.Duration) string {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	errCh := make(chan error, 1)
	go func() { errCh <- runEmbedded(ctx, cfg, lg) }()

	url := "http://127.0.0.1:" + strconv.Itoa(cfg.Port) + "/api/v1/hosts"
	client := &http.Client{Timeout: 2 * time.Second}

	// The embedded server requires auth; use the static token when present,
	// otherwise log in as the bootstrap admin (password or generated file).
	adminTok := cfg.AdminToken
	var hostID string
	deadline := time.Now().Add(wait)
	for time.Now().Before(deadline) {
		select {
		case e := <-errCh:
			t.Fatalf("runEmbedded exited early: %v", e)
		default:
		}
		if adminTok == "" {
			pw := cfg.AdminPassword
			if pw == "" {
				if b, err := os.ReadFile(filepath.Join(filepath.Dir(cfg.DBPath), "admin_password.txt")); err == nil {
					pw = strings.TrimSpace(string(b))
				}
			}
			if pw != "" {
				body, _ := json.Marshal(map[string]string{"username": "admin", "password": pw})
				if r, err := client.Post("http://127.0.0.1:"+strconv.Itoa(cfg.Port)+"/api/v1/auth/login",
					"application/json", bytes.NewReader(body)); err == nil {
					var out struct {
						Token string `json:"token"`
					}
					_ = json.NewDecoder(r.Body).Decode(&out)
					r.Body.Close()
					adminTok = out.Token
				}
			}
		}
		if adminTok != "" {
			req, _ := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
			req.Header.Set("Authorization", "Bearer "+adminTok)
			if resp, err := client.Do(req); err == nil {
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
			}
		}
		if hostID != "" {
			break
		}
		time.Sleep(200 * time.Millisecond)
	}

	cancel()
	select {
	case e := <-errCh:
		if e != nil && !errors.Is(e, context.Canceled) {
			t.Fatalf("runEmbedded returned non-canceled error: %v", e)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("runEmbedded did not shut down within 15s")
	}
	return hostID
}

func newEmbeddedCfg(port int, dbPath, dataDir string) *config.Config {
	return &config.Config{
		Mode:          "embedded",
		Port:          port,
		DBPath:        dbPath,
		DataDir:       dataDir,
		FactsInterval: 3600,
		Elevate:       "none",
		Root:          "/",
	}
}

// TestEmbeddedEnrollWithPasswordOnly is the regression for the enrollment
// chicken-and-egg: embedded mode with PARTOUT_ADMIN_PASSWORD and NO static
// token must still enroll its co-located agent. Previously
// createEnrollmentToken sent no Authorization header → 401 → the agent looped
// on "unknown agent uuid" and the fleet stayed empty. This escaped CI because
// every other embedded test set AdminToken.
func TestEmbeddedEnrollWithPasswordOnly(t *testing.T) {
	port := freePort(t)
	tmp := t.TempDir()
	cfg := newEmbeddedCfg(port, filepath.Join(tmp, "pw.db"), filepath.Join(tmp, "agent"))
	cfg.AdminPassword = "password-only-1" // no AdminToken

	hostID := runEmbeddedCfg(t, cfg, log.New(io.Discard, "", 0), 30*time.Second)
	if hostID == "" {
		t.Fatal("embedded agent did not connect with a password-only server (no static token)")
	}
	t.Logf("password-only embedded agent connected as %s", hostID)
}

// TestEmbeddedStaleIdentityFreshDB is the regression for the demo-reset case:
// an agent identity persisted from a previous run, but a wiped/replaced
// database. The agent must re-enroll rather than loop on "unknown agent uuid".
func TestEmbeddedStaleIdentityFreshDB(t *testing.T) {
	base := freePort(t)
	tmp := t.TempDir()
	dataDir := filepath.Join(tmp, "agent") // shared across both runs

	// Run 1 creates the identity and enrolls it into db1.
	cfg1 := newEmbeddedCfg(base, filepath.Join(tmp, "db1.db"), dataDir)
	cfg1.AdminPassword = "password-only-1"
	if id := runEmbeddedCfg(t, cfg1, log.New(io.Discard, "", 0), 30*time.Second); id == "" {
		t.Fatal("first run did not connect")
	}
	if _, err := os.Stat(filepath.Join(dataDir, "identity.json")); err != nil {
		t.Fatalf("identity not persisted on first run: %v", err)
	}

	// Run 2: SAME identity, FRESH database. Must re-enroll and connect.
	cfg2 := newEmbeddedCfg(base+1, filepath.Join(tmp, "db2.db"), dataDir)
	cfg2.AdminPassword = "password-only-1"
	if id := runEmbeddedCfg(t, cfg2, log.New(io.Discard, "", 0), 30*time.Second); id == "" {
		t.Fatal("agent did not re-enroll against a fresh DB with a stale identity file")
	}
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

	// A duplicate confirm must be a clean API error, not an abrupt EOF
	// (regression guard for the "close of closed channel" panic).
	if err := post("/api/v1/provision-runs/"+created.ID+"/key", map[string]string{"action": "confirm"}, nil); err == nil {
		t.Error("duplicate confirm returned success, want a conflict error")
	}
	var hz struct{}
	if err := get("/healthz", &hz); err != nil {
		t.Fatalf("server unhealthy after duplicate confirm: %v", err)
	}

	run := waitFor("handoff")
	if run.Error == "" {
		t.Error("handoff run should carry a remediation note")
	}
}
