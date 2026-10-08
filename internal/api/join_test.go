// One-line join (E1) + agent-binary serving (E2) tests.
package api_test

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
)

func joinToken(t *testing.T, srvURL string) string {
	t.Helper()
	resp, err := http.Post(srvURL+"/api/v1/agents/enrollment-tokens", "application/json", strings.NewReader(`{"ttl_s":900}`))
	if err != nil {
		t.Fatalf("create token: %v", err)
	}
	defer resp.Body.Close()
	var out struct {
		Token string `json:"token"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&out)
	if out.Token == "" {
		t.Fatal("no token")
	}
	return out.Token
}

func TestJoinLoaderAndArchScript(t *testing.T) {
	_, _, srv := startAPITest(t)
	token := joinToken(t, srv.URL)

	// Stage 1: the arch-detecting loader.
	resp, err := http.Get(srv.URL + "/api/v1/join/" + token)
	if err != nil {
		t.Fatalf("loader: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("loader status: %d %s", resp.StatusCode, string(body))
	}
	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/x-shellscript") {
		t.Errorf("content type %q", ct)
	}
	loader := string(body)
	for _, want := range []string{"uname -m", "/api/v1/join/" + token + "?arch="} {
		if !strings.Contains(loader, want) {
			t.Errorf("loader missing %q", want)
		}
	}

	// Stage 2: the arch-specific installer reuses the provision install
	// body (sha256 gate, M8.1 layout, systemd unit, enrollment env).
	resp, err = http.Get(srv.URL + "/api/v1/join/" + token + "?arch=amd64")
	if err == nil {
		body, _ = io.ReadAll(resp.Body)
		resp.Body.Close()
	}
	// amd64 may be servable (server's own exe) or not (arm64 host) — the
	// contract that matters is renderable-or-404, never a 500.
	if resp.StatusCode == http.StatusOK {
		script := string(body)
		for _, want := range []string{
			"sha256sum",                    // the binary verification gate
			"/var/lib/partout/bin/partout", // M8.1 agent-writable layout
			"partout-update-guard",         // the boot guard
			"/etc/systemd/system/partout-agent.service",
			"PARTOUT_TOKEN=" + token,         // the enrollment env
			"systemctl enable partout-agent", // persistence by default
			"INSTALL_OK",
		} {
			if !strings.Contains(script, want) {
				t.Errorf("installer missing %q", want)
			}
		}
	} else if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("arch script status: %d (want 200 or 404)", resp.StatusCode)
	}
}

func TestJoinBinaryServing(t *testing.T) {
	_, _, srv := startAPITest(t)
	token := joinToken(t, srv.URL)
	arch := "amd64"
	resp, err := http.Get(srv.URL + "/api/v1/join/" + token + "/binary?arch=" + arch)
	if err != nil {
		t.Fatalf("binary: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("binary status: %d (the test server should serve its own exe for amd64)", resp.StatusCode)
	}
	sum := sha256.Sum256(body)
	if got := resp.Header.Get("X-Partout-Sha256"); got != hex.EncodeToString(sum[:]) {
		t.Errorf("X-Partout-Sha256 = %q, want sha256(body)", got)
	}
	if resp.Header.Get("X-Partout-Version") == "" {
		t.Errorf("X-Partout-Version missing")
	}
}

func TestJoinAuthAndValidation(t *testing.T) {
	_, _, srv := startAPITest(t)

	// Unknown token.
	resp, _ := http.Get(srv.URL + "/api/v1/join/par_enr_nope")
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("unknown token: %d, want 401", resp.StatusCode)
	}
	resp.Body.Close()

	// Bad arch.
	token := joinToken(t, srv.URL)
	resp, _ = http.Get(srv.URL + "/api/v1/join/" + token + "?arch=mips")
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("bad arch: %d, want 400", resp.StatusCode)
	}
	resp.Body.Close()

	// Bad labels (shell metacharacters must be rejected before embedding).
	resp, _ = http.Get(srv.URL + "/api/v1/join/" + token + "?labels=$(rm%20-rf%20%2F)")
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("bad labels: %d, want 400", resp.StatusCode)
	}
	resp.Body.Close()

	// Unknown elevation policy.
	resp, _ = http.Get(srv.URL + "/api/v1/join/" + token + "?elevate=does-not-exist")
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("unknown policy: %d, want 400", resp.StatusCode)
	}
	resp.Body.Close()

	// A used (enrolled) token no longer serves the join flow.
	resp, _ = http.Post(srv.URL+"/api/v1/agents/enroll", "application/json",
		strings.NewReader(`{"token":"`+token+`","uuid":"u-join","ed25519_pub":"a","x25519_pub":"b"}`))
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("enroll: %d", resp.StatusCode)
	}
	resp, _ = http.Get(srv.URL + "/api/v1/join/" + token)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("used token: %d, want 401", resp.StatusCode)
	}
	resp.Body.Close()
}

func TestElevationBootstrapFlow(t *testing.T) {
	_, _, srv := startAPITest(t)

	// Seed a stored policy (the canonical store the mint resolves).
	polBody := `{"name":"default-baseline","description":"test","rules":[{"allow":"reboot"}]}`
	resp, err := http.Post(srv.URL+"/api/v1/elevation/policies", "application/json", strings.NewReader(polBody))
	if err != nil || (resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated) {
		t.Fatalf("create policy: %v %d", err, resp.StatusCode)
	}
	resp.Body.Close()

	// Mint for the seeded test host.
	resp, err = http.Post(srv.URL+"/api/v1/hosts/ag_api/elevation/bootstrap", "application/json",
		strings.NewReader(`{"policy":"default-baseline"}`))
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	var mint struct {
		Token string `json:"token"`
		URL   string `json:"url"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&mint)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || mint.Token == "" || mint.URL == "" {
		t.Fatalf("mint: %d token=%q url=%q", resp.StatusCode, mint.Token, mint.URL)
	}

	// The script: one privileged paste, rendered with the policy + guards.
	resp, err = http.Get(srv.URL + "/api/v1/elevate/" + mint.Token)
	if err != nil {
		t.Fatalf("fetch script: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("script status: %d %s", resp.StatusCode, string(body))
	}
	script := string(body)
	for _, want := range []string{
		"ctl elevation install-sudoers", // renders the sudoers wall on the host
		"/etc/partout/elevation.d/10-default-baseline.json",
		"PARTOUT_ELEVATE=sudo", // env wiring
		"NoNewPrivileges",      // the unit fix
		"systemctl restart partout-agent",
		"ELEVATION_OK",
	} {
		if !strings.Contains(script, want) {
			t.Errorf("script missing %q", want)
		}
	}

	// Single serve: a second fetch of the same token is refused.
	resp, _ = http.Get(srv.URL + "/api/v1/elevate/" + mint.Token)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("re-fetch: %d, want 401 (single serve)", resp.StatusCode)
	}
	resp.Body.Close()

	// Unknown policy at mint time is a 400, not a broken script later.
	resp, _ = http.Post(srv.URL+"/api/v1/hosts/ag_api/elevation/bootstrap", "application/json",
		strings.NewReader(`{"policy":"nope"}`))
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("unknown policy: %d, want 400", resp.StatusCode)
	}
	resp.Body.Close()
}
