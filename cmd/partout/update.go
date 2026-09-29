// Command partout — `update` one-command (M8.1).
//
// `partout update` takes "server + fleet at N" to "all at N+1" and reports
// one status line. It runs on the server host (or with --server pointed at
// one) and is the ONLY component that fetches from the internet: the
// server and agents never do. Trust is unchanged — both artifacts are
// verified locally against the operator-provisioned release key before
// anything touches a machine, and every agent re-verifies at swap time.
//
// Flow:
//   1. resolve target version (--version or the repo's "latest")
//   2. fetch server + agent artifacts + signatures from PARTOUT_RELEASE_REPO
//   3. verify BOTH against PARTOUT_RELEASE_KEY (fail closed)
//   4. supervised server update (scripts/update-server.sh: selftest the new
//      binary on this host, proven backup, swap, post-checks, auto-rollback)
//   5. publish the agent artifact to the new server's release store
//   6. start the fleet rollout (canary -> waves) and watch it to a stop
//
// Idempotent/convergent: re-run at the latest version = "already current".

package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/blawesom/partout/internal/release"
)

func runUpdate(args []string) {
	fs := flag.NewFlagSet("update", flag.ExitOnError)
	server := fs.String("server", envOr("PARTOUT_SERVER", ""), "server host:port to update + roll out")
	token := fs.String("token", envOr("PARTOUT_TOKEN", envOr("PARTOUT_ADMIN_TOKEN", "")), "admin bearer token")
	version := fs.String("version", "", "target version (default: the repo's latest)")
	repo := fs.String("repo", envOr("PARTOUT_RELEASE_REPO", ""), "base URL of published releases (or $PARTOUT_RELEASE_REPO)")
	arch := fs.String("arch", defaultArch(), "target arch (e.g. linux-amd64)")
	selector := fs.String("selector", "all", "fleet selector for the rollout")
	canary := fs.Int("canary", 1, "canary cohort size (0 = no canary phase)")
	wave := fs.Int("wave", 25, "per-wave percentage of the fleet")
	script := fs.String("script", envOr("PARTOUT_UPDATE_SCRIPT", ""), "update-server.sh path (default: next to the binary)")
	serverBin := fs.String("server-bin", envOr("PARTOUT_UPDATE_BIN", "/usr/local/bin/partout"), "installed server binary path (for the update script)")
	serverDB := fs.String("server-db", envOr("PARTOUT_UPDATE_DB", "/var/lib/partout/partout.db"), "server DB path (for the update script)")
	service := fs.String("service", envOr("PARTOUT_UPDATE_SERVICE", "partout-server.service"), "systemd unit for the server")
	caFile := fs.String("ca-file", envOr("PARTOUT_TLS_CA", ""), "server root CA (PEM) when the server runs TLS")
	serverOnly := fs.Bool("server-only", false, "update the server only; skip the fleet rollout")
	checkOnly := fs.Bool("check", false, "report current + target state and exit (no changes)")
	fs.Parse(args)

	usage := func() {
		fmt.Fprintln(os.Stderr, `usage: partout update [flags]

  Takes "server + fleet at N" to "all at N+1": fetches the signed release
  from the repo, verifies both artifacts against PARTOUT_RELEASE_KEY,
  supervises the server swap (selftest + backup + rollback), publishes the
  agent artifact to the release store, and drives the fleet rollout
  (canary -> waves) to a stop. One status line at the end.

Flags:
  --server host:port    server to update (or $PARTOUT_SERVER)
  --token T             admin bearer token (or $PARTOUT_TOKEN)
  --version V           target version (default: repo "latest")
  --repo URL            release repo base URL (or $PARTOUT_RELEASE_REPO)
  --arch A              target arch (default: this host)
  --selector S          fleet selector (default "all")
  --canary N            canary cohort size (default 1)
  --wave N              per-wave % of the fleet (default 25)
  --script PATH         update-server.sh (default: next to the binary)
  --ca-file PEM         server root CA (TLS mode)
  --server-only         skip the fleet rollout
  --check               report state and exit; no changes`)
		os.Exit(2)
	}
	if *server == "" || *token == "" {
		fmt.Fprintln(os.Stderr, "partout update: --server and --token are required")
		usage()
	}

	client := &http.Client{Timeout: 10 * time.Minute}
	if *caFile != "" {
		c, err := tlsHTTPClient(*caFile)
		if err != nil {
			fatal(err)
		}
		client = c
	}
	base := schemeFromCA(*caFile) + "://" + *server
	adminReq := func(method, path string, body any) (*http.Response, error) {
		var rdr io.Reader
		if body != nil {
			b, _ := json.Marshal(body)
			rdr = strings.NewReader(string(b))
		}
		req, err := http.NewRequest(method, base+path, rdr)
		if err != nil {
			return nil, err
		}
		req.Header.Set("Authorization", "Bearer "+*token)
		if body != nil {
			req.Header.Set("Content-Type", "application/json")
		}
		return client.Do(req)
	}

	// ---- 1. current + target state ----------------------------------------
	var cur struct {
		Version string `json:"version"`
	}
	res, err := adminReq("GET", "/api/v1/version", nil)
	if err == nil {
		b, _ := io.ReadAll(res.Body)
		res.Body.Close()
		_ = json.Unmarshal(b, &cur)
	} else {
		fatal(fmt.Errorf("current server version: %w", err))
	}
	if cur.Version == "" {
		fatal(fmt.Errorf("cannot read the current server version from %s/api/v1/version", base))
	}
	target := *version
	if target == "" {
		if *repo == "" {
			fatal(fmt.Errorf("no --version and no --repo/$PARTOUT_RELEASE_REPO; cannot resolve a target"))
		}
		t, err := http.Get(*repo + "/latest")
		if err != nil {
			fatal(fmt.Errorf("repo latest: %w", err))
		}
		defer t.Body.Close()
		if t.StatusCode != 200 {
			fatal(fmt.Errorf("repo latest: HTTP %d from %s/latest", t.StatusCode, *repo))
		}
		lb, _ := io.ReadAll(t.Body)
		target = strings.TrimSpace(string(lb))
		if target == "" {
			fatal(fmt.Errorf("repo %s/latest is empty", *repo))
		}
	}
	fmt.Printf("partout update: server at %s, target %s\n", cur.Version, target)

	serverAtTarget := cur.Version == target

	// ---- --check: report and exit ------------------------------------------
	if *checkOnly {
		res, err := adminReq("GET", "/api/v1/hosts", nil)
		n := 0
		if err == nil {
			var hosts struct {
				Items []map[string]any `json:"items"`
			}
			b, _ := io.ReadAll(res.Body)
			res.Body.Close()
			_ = json.Unmarshal(b, &hosts)
			n = len(hosts.Items)
			for _, h := range hosts.Items {
				name, _ := h["name"].(string)
				if name == "" {
					name, _ = h["id"].(string)
				}
				v, _ := h["version"].(string)
				fmt.Printf("  host %s at %s\n", name, v)
			}
		}
		state := "update available"
		if serverAtTarget {
			state = "already current"
		}
		// Preflight: fetch and verify the artifacts the real run would use.
		// --check still makes no system changes — it only downloads to temp.
		artState := "no --repo configured (artifact preflight skipped)"
		if *repo != "" {
			if err := checkArtifacts(client, *repo, target, *arch, serverAtTarget); err != nil {
				artState = "ARTIFACT PRECHECK FAILED: " + err.Error()
			} else {
				artState = "artifacts verified against release key"
			}
		}
		fmt.Printf("update --check: server=%s target=%s hosts=%d (%s)\n", cur.Version, target, n, state)
		fmt.Printf("update --check: %s\n", artState)
		if artState != "artifacts verified against release key" && !strings.HasPrefix(artState, "no --repo") {
			os.Exit(1)
		}
		return
	}

	// ---- 2+3. fetch + verify both artifacts --------------------------------
	var srvFile, srvSig, srvSHA, agtFile, agtSig, agtSHA string
	if !serverAtTarget {
		if *repo == "" {
			fatal(fmt.Errorf("server is behind but no --repo/$PARTOUT_RELEASE_REPO to fetch %s", target))
		}
		srvFile, srvSig, srvSHA = fetchArtifact(client, *repo, target, *arch, "server")
		agtFile, agtSig, agtSHA = fetchArtifact(client, *repo, target, *arch, "agent")
		if err := verifyArtifact(target, *arch, "server", srvFile, srvSHA, srvSig); err != nil {
			fatal(err)
		}
		if err := verifyArtifact(target, *arch, "agent", agtFile, agtSHA, agtSig); err != nil {
			fatal(err)
		}
		fmt.Println("partout update: both artifacts verified against the release key")
	} else {
		// Server is already at target: only the agent artifact is needed.
		if *serverOnly {
			fmt.Printf("update: already at %s — nothing to do\n", target)
			return
		}
		if *repo == "" {
			fatal(fmt.Errorf("server already at %s but no --repo to fetch the agent artifact", target))
		}
		agtFile, agtSig, agtSHA = fetchArtifact(client, *repo, target, *arch, "agent")
		if err := verifyArtifact(target, *arch, "agent", agtFile, agtSHA, agtSig); err != nil {
			fatal(err)
		}
	}

	// ---- 4. supervised server update ---------------------------------------
	if !serverAtTarget {
		sc := resolveUpdateScript(*script)
		cmd := exec.Command(sc,
			"--new", srvFile, "--version", target, "--arch", *arch,
			"--sha256", srvSHA, "--signature", srvSig, "--key", releaseKeyOrFatal(),
			"--binary", *serverBin, "--db", *serverDB, "--service", *service,
			"--health-url", base, "--admin-token", *token,
		)
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			fatal(fmt.Errorf("supervised server update failed: %w", err))
		}
		fmt.Printf("partout update: server now at %s (supervised, rollback-safe)\n", target)
	}

	if *serverOnly {
		fmt.Printf("update: server %s ok; fleet untouched (--server-only)\n", target)
		return
	}

	// ---- 5. publish the agent artifact to the release store ----------------
	relID, err := publishAgentRelease(client, base, *token, target, *arch, agtFile, agtSHA, agtSig)
	if err != nil {
		fatal(err)
	}
	fmt.Printf("partout update: agent artifact in release store (%s)\n", relID)

	// ---- 6. fleet rollout ----------------------------------------------------
	var runResp struct {
		RunID      string `json:"run_id"`
		State      string `json:"state"`
		ApprovalID string `json:"approval_id"`
	}
	res, err = adminReq("POST", "/api/v1/updates/runs", map[string]any{
		"release_id": relID, "selector": *selector,
		"canary": *canary, "wave_pct": *wave,
	})
	if err != nil {
		fatal(fmt.Errorf("start rollout: %w", err))
	}
	rb, _ := io.ReadAll(res.Body)
	res.Body.Close()
	if res.StatusCode != 201 {
		fatal(fmt.Errorf("start rollout: HTTP %d %s", res.StatusCode, strings.TrimSpace(string(rb))))
	}
	_ = json.Unmarshal(rb, &runResp)
	if runResp.State == "pending_approval" {
		fmt.Printf("update: rollout parked on approval %s — approve it to proceed\n", runResp.ApprovalID)
		return
	}
	fmt.Printf("partout update: rollout %s started (canary=%d, wave=%d%%)\n", runResp.RunID, *canary, *wave)

	// Watch to a stop.
	deadline := time.Now().Add(60 * time.Minute)
	last := ""
	for time.Now().Before(deadline) {
		res, err := adminReq("GET", "/api/v1/updates/runs/"+runResp.RunID, nil)
		var r struct {
			Status       string `json:"status"`
			DoneHosts    int    `json:"done_hosts"`
			FailedHosts  int    `json:"failed_hosts"`
			SkippedHosts int    `json:"skipped_hosts"`
			TotalHosts   int    `json:"total_hosts"`
		}
		if err == nil {
			b, _ := io.ReadAll(res.Body)
			res.Body.Close()
			var det struct {
				Run struct {
					Status       string `json:"status"`
					DoneHosts    int    `json:"done_hosts"`
					FailedHosts  int    `json:"failed_hosts"`
					SkippedHosts int    `json:"skipped_hosts"`
					TotalHosts   int    `json:"total_hosts"`
				} `json:"run"`
			}
			_ = json.Unmarshal(b, &det)
			r = det.Run
		}
		if r.Status != "" && r.Status != last {
			last = r.Status
			fmt.Printf("  run %s: %s (verified %d/%d, failed %d, skipped %d)\n",
				runResp.RunID, r.Status, r.DoneHosts, r.TotalHosts, r.FailedHosts, r.SkippedHosts)
		}
		switch r.Status {
		case "completed":
			fmt.Printf("update: server %s ok; fleet %d verified, %d failed, %d skipped (%s) — DONE\n",
				target, r.DoneHosts, r.FailedHosts, r.SkippedHosts, runResp.RunID)
			return
		case "failed", "aborted":
			fmt.Printf("update: server %s ok; fleet rollout %s (%s) — FAILED\n", target, r.Status, runResp.RunID)
			os.Exit(1)
		}
		time.Sleep(5 * time.Second)
	}
	fatal(fmt.Errorf("rollout %s still running after 60m; inspect with: partout ctl update show %s", runResp.RunID, runResp.RunID))
}

// publishAgentRelease uploads the verified agent artifact to the release
// store, or returns the id of the existing row when the (version, arch,
// kind) triple is already present.
func publishAgentRelease(client *http.Client, base, token, version, arch, file, sha, sig string) (string, error) {
	req, err := http.NewRequest("POST", base+"/api/v1/updates/releases",
		strings.NewReader(fmt.Sprintf(`{"version":%q,"arch":%q,"kind":"agent","sha256":%q,"signature":%q,"artifact_b64":%q}`,
			version, arch, sha, sig, base64.StdEncoding.EncodeToString(readFileBytes(file)))))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	res, err := client.Do(req)
	if err != nil {
		return "", err
	}
	rb, _ := io.ReadAll(res.Body)
	res.Body.Close()
	if res.StatusCode == 201 {
		var out struct {
			ID string `json:"id"`
		}
		_ = json.Unmarshal(rb, &out)
		if out.ID == "" {
			return "", fmt.Errorf("release upload returned no id: %s", string(rb))
		}
		return out.ID, nil
	}
	if res.StatusCode != http.StatusConflict {
		// Anything else (400 bad signature/sha, 413 too large, 5xx) is a real
		// failure — do not paper over it by reusing some existing row.
		return "", fmt.Errorf("release upload: HTTP %d %s", res.StatusCode, strings.TrimSpace(string(rb)))
	}
	// 409: the release already exists — reuse that row (converged re-run).
	req2, _ := http.NewRequest("GET", base+"/api/v1/updates/releases", nil)
	req2.Header.Set("Authorization", "Bearer "+token)
	res2, err := client.Do(req2)
	if err != nil {
		return "", err
	}
	b2, _ := io.ReadAll(res2.Body)
	res2.Body.Close()
	var rels struct {
		Items []map[string]any `json:"items"`
	}
	_ = json.Unmarshal(b2, &rels)
	for _, r := range rels.Items {
		if r["version"] == version && r["arch"] == arch && r["kind"] == "agent" {
			return fmt.Sprint(r["id"]), nil
		}
	}
	return "", fmt.Errorf("release upload: HTTP %d %s", res.StatusCode, strings.TrimSpace(string(rb)))
}

// fetchArtifact downloads one artifact + its signature from the release
// repo: <repo>/<version>/partout-<version>-<arch>-<kind>[.sig].
func fetchArtifact(client *http.Client, repo, version, arch, kind string) (file, sig, sha string) {
	base := strings.TrimRight(repo, "/") + "/" + url.PathEscape(version) + "/"
	name := fmt.Sprintf("partout-%s-%s-%s", version, arch, kind)
	tmp, err := os.MkdirTemp("", "partout-update-*")
	if err != nil {
		fatal(err)
	}
	file = filepath.Join(tmp, name)
	fetchFile := func(p, out string) {
		res, err := client.Get(p)
		if err != nil {
			fatal(fmt.Errorf("fetch %s: %w", p, err))
		}
		defer res.Body.Close()
		if res.StatusCode != 200 {
			fatal(fmt.Errorf("fetch %s: HTTP %d", p, res.StatusCode))
		}
		w, err := os.Create(out)
		if err != nil {
			fatal(err)
		}
		defer w.Close()
		if _, err := io.Copy(w, res.Body); err != nil {
			fatal(err)
		}
	}
	fetchFile(base+name, file)
	if err := os.Chmod(file, 0o755); err != nil {
		fatal(err)
	}
	sigFile := filepath.Join(tmp, name+".sig")
	fetchFile(base+name+".sig", sigFile)
	sb, err := os.ReadFile(sigFile)
	if err != nil {
		fatal(err)
	}
	h := sha256.Sum256(readFileBytes(file))
	return file, strings.TrimSpace(string(sb)), hex.EncodeToString(h[:])
}

// checkArtifacts fetches and signature-verifies the artifacts a real run
// would use (both when the server is behind; agent-only when the server is
// already at target). Fail closed: any fetch or signature error is
// returned so --check exits non-zero.
func checkArtifacts(client *http.Client, repo, version, arch string, serverAtTarget bool) error {
	if !serverAtTarget {
		srvFile, srvSig, srvSHA := fetchArtifact(client, repo, version, arch, "server")
		if err := verifyArtifact(version, arch, "server", srvFile, srvSHA, srvSig); err != nil {
			return fmt.Errorf("server artifact: %w", err)
		}
	}
	agtFile, agtSig, agtSHA := fetchArtifact(client, repo, version, arch, "agent")
	return verifyArtifact(version, arch, "agent", agtFile, agtSHA, agtSig)
}

// verifyArtifact checks the Ed25519 signature over the canonical manifest
// against the operator-provisioned release key (fail closed).
func verifyArtifact(version, arch, kind, file, sha, sigB64 string) error {
	pub, err := release.PubKeyFromB64(releaseKeyOrFatal())
	if err != nil {
		return fmt.Errorf("release key: %w", err)
	}
	sig, err := base64.StdEncoding.DecodeString(sigB64)
	if err != nil {
		return fmt.Errorf("signature b64: %w", err)
	}
	m := release.Manifest{Version: version, Arch: arch, Kind: kind, SHA256: sha}
	if !release.Verify(pub, m, sig) {
		return fmt.Errorf("update: artifact signature verification FAILED for %s %s (%s)", version, kind, arch)
	}
	return nil
}

func releaseKeyOrFatal() string {
	k := os.Getenv("PARTOUT_RELEASE_KEY")
	if k == "" {
		fatal(fmt.Errorf("PARTOUT_RELEASE_KEY is not set; refusing to update (fail closed)"))
	}
	return k
}

func resolveUpdateScript(flagVal string) string {
	if flagVal != "" {
		if _, err := os.Stat(flagVal); err == nil {
			return flagVal
		}
		fatal(fmt.Errorf("update script not found: %s", flagVal))
	}
	if exe, err := os.Executable(); err == nil {
		p := filepath.Join(filepath.Dir(exe), "update-server.sh")
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	if p, err := exec.LookPath("update-server.sh"); err == nil {
		return p
	}
	fatal(fmt.Errorf("cannot find update-server.sh (use --script or $PARTOUT_UPDATE_SCRIPT)"))
	return ""
}

// defaultArch uses Go's own OS/arch naming — the same canonical form the
// agent checks against (runtime.GOOS + "-" + runtime.GOARCH).
func defaultArch() string {
	return runtime.GOOS + "-" + runtime.GOARCH
}

func schemeFromCA(caFile string) string {
	if caFile != "" {
		return "https"
	}
	return "http"
}

func readFileBytes(p string) []byte {
	b, err := os.ReadFile(p)
	if err != nil {
		fatal(err)
	}
	return b
}
