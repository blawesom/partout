package pkg

import (
	"context"
	"errors"
	"fmt"
	"github.com/blawesom/partout/internal/agent/elevate"
	"strings"
	"testing"
	"time"
)

// TestSelectBackend verifies the distro → backend mapping.
func TestSelectBackend(t *testing.T) {
	cases := []struct {
		distro string
		want   string // type of backend
	}{
		{"ubuntu", "apt"},
		{"debian", "apt"},
		{"linuxmint", "apt"},
		{"rhel", "dnf"},
		{"centos", "dnf"},
		{"rocky", "dnf"},
		{"alma", "dnf"},
		{"fedora", "dnf"},
		{"ol", "dnf"},
		{"alpine", "noop"},
		{"", "noop"},
	}
	for _, c := range cases {
		facts := map[string]string{"host.distro": c.distro}
		b := SelectBackend(facts, elevate.None)
		switch c.want {
		case "apt":
			if _, ok := b.(*aptBackend); !ok {
				t.Errorf("distro %s: got %T, want *aptBackend", c.distro, b)
			}
		case "dnf":
			if _, ok := b.(*dnfBackend); !ok {
				t.Errorf("distro %s: got %T, want *dnfBackend", c.distro, b)
			}
		case "noop":
			if _, ok := b.(*noopBackend); !ok {
				t.Errorf("distro %s: got %T, want *noopBackend", c.distro, b)
			}
		}
	}
}

// TestParseAptUpgrade verifies parsing of `apt-get upgrade -s` output.
func TestParseAptUpgrade(t *testing.T) {
	out := `
Reading package lists... Done
Building dependency tree... Done
Reading state information... Done
The following additional packages will be installed:
  libpython3.12 python3.12
The following packages will be upgraded:
  python3.12 libpython3.12
2 upgraded, 0 newly installed, 0 to remove and 0 not upgraded.
Inst libpython3.12:amd64 (3.12.3-1, auto, ubuntu) -> (3.12.3-1ubuntu0.5, auto, ubuntu)
Inst python3.12:amd64 (3.12.3-1, auto, ubuntu) -> (3.12.3-1ubuntu0.5, auto, ubuntu)
`
	got := parseAptUpgrade(out)
	if len(got) != 2 {
		t.Fatalf("got %d packages, want 2: %+v", len(got), got)
	}
	if got[0].Name != "libpython3.12" || got[0].Installed != "3.12.3-1" || got[0].Available != "3.12.3-1ubuntu0.5" {
		t.Errorf("bad parse: %+v", got[0])
	}
	if got[1].Name != "python3.12" {
		t.Errorf("bad parse: %+v", got[1])
	}
}

// TestParseAptUpgradeApt28 covers the bracket format printed by apt 2.8+
// (Ubuntu 24.04): "Inst name [old] (new repo [arch])" — no arrow. Without
// this, the pending-updates list (and the CVE scan built on it) is empty on
// current Ubuntu hosts even with upgrades available.
func TestParseAptUpgradeApt28(t *testing.T) {
	out := `
Reading package lists... Done
Building dependency tree... Done
Reading state information... Done
9 upgraded, 0 newly installed, 0 to remove and 0 not upgraded.
Inst libaudit-common [1:3.1.2-2.1build1.1] (1:3.1.2-2.1ubuntu0.1 Ubuntu:24.04/noble-updates [all])
Inst libaudit1 [1:3.1.2-2.1build1.1] (1:3.1.2-2.1ubuntu0.1 Ubuntu:24.04/noble-updates [amd64])
Inst containerd.io [2.3.5-1~ubuntu.24.04~noble] (2.3.6-1~ubuntu.24.04~noble Docker CE:noble [amd64])
`
	got := parseAptUpgrade(out)
	if len(got) != 3 {
		t.Fatalf("got %d packages, want 3: %+v", len(got), got)
	}
	if got[0].Name != "libaudit-common" || got[0].Installed != "1:3.1.2-2.1build1.1" || got[0].Available != "1:3.1.2-2.1ubuntu0.1" {
		t.Errorf("bad parse: %+v", got[0])
	}
	if got[2].Name != "containerd.io" || got[2].Available != "2.3.6-1~ubuntu.24.04~noble" {
		t.Errorf("bad parse: %+v", got[2])
	}
}

// TestParseDpkgQuery verifies parsing of `dpkg-query -W` output.
func TestParseDpkgQuery(t *testing.T) {
	b := []byte("bash\t5.2.15-2ubuntu1\tinstalled\n" +
		"coreutils\t9.4-3ubuntu6\tinstalled\n" +
		"python3.12\t3.12.3-1ubuntu0.5\tinstalled\n" +
		"python3-venv\t3.12.3-0ubuntu4\tinstall-installed\n" +
		"zlib1g:amd64\t1:1.3.dfsg-3.1ubuntu6\tinstalled")
	got := parseDpkgQuery(b)
	if len(got) != 4 { // 4 installed (python3-venv skipped: install-installed)
		t.Fatalf("got %d, want 4: %+v", len(got), got)
	}
	found := false
	for _, p := range got {
		if p.Name == "bash" && p.Installed == "5.2.15-2ubuntu1" {
			found = true
		}
	}
	if !found {
		t.Error("bash not found in parsed output")
	}
}

// TestParseDNFCheck verifies parsing of `dnf check-update` output.
func TestParseDNFCheck(t *testing.T) {
	out := "Last metadata expiration check: 0:00:01 ago on Fri 01 Jan 2026.\n" +
		"Package         Arch        Version          Repository\n" +
		"bash            x86_64      5.2.15-1.el9     appstream\n" +
		"coreutils       x86_64      9.9-3.el9        appstream\n" +
		"\n" +
		"Update Available\n" +
		"bash.x86_64        5.2.15-1.el9      appstream\n" +
		"coreutils.x86_64   9.9-3.el9         appstream\n" +
		"glibc.x86_64       2.34-161.el9      appstream"
	got := parseDNFCheck(out)
	if len(got) != 3 {
		t.Fatalf("got %d, want 3: %+v", len(got), got)
	}
	found := false
	for _, p := range got {
		if p.Name == "glibc" && p.Available == "2.34-161.el9" {
			found = true
		}
	}
	if !found {
		t.Error("glibc update not found in parsed output")
	}
}

// TestParseRPMQA verifies parsing of `rpm -qa` output.
func TestParseRPMQA(t *testing.T) {
	b := []byte("bash\t5.2.15-1.el9\t0\ncoreutils\t9.9-3.el9\t0\nglibc\t2.34-161.el9\t0")
	got := parseRPMQA(b)
	if len(got) != 3 {
		t.Fatalf("got %d, want 3: %+v", len(got), got)
	}
	if got[0].Name != "bash" || got[0].Installed != "5.2.15-1.el9" {
		t.Errorf("bad parse: %+v", got[0])
	}
}

// TestNoopBackend verifies the noop backend returns empty results.
func TestNoopBackend(t *testing.T) {
	b := &noopBackend{}
	ctx := context.Background()
	if ups, err := b.List(ctx); err != nil || len(ups) != 0 {
		t.Errorf("List: %v / %d", err, len(ups))
	}
	if _, err := b.DryRun(ctx); err != nil {
		t.Errorf("DryRun: %v", err)
	}
	if err := b.Apply(ctx); err == nil {
		t.Error("Apply should fail for noop")
	}
	if _, err := b.Installed(ctx); err != nil {
		t.Errorf("Installed: %v", err)
	}
}

// TestSummarizeAptUpgrade verifies summary extraction.
func TestSummarizeAptUpgrade(t *testing.T) {
	// 50 lines of output, last 20 should be kept.
	var lines []string
	for i := 0; i < 50; i++ {
		lines = append(lines, "line "+string(rune('a'+i%26))+string(rune('0'+i/26)))
	}
	out := summarizeAptUpgrade(strings.Join(lines, "\n"))
	got := len(strings.Split(out, "\n"))
	if got > 20 {
		t.Errorf("summary has %d lines, want <= 20", got)
	}
}

// TestRunHonoursTimeout: the timeout argument was accepted but never applied,
// so a command that blocks (apt waiting on a lock/prompt, stalled mirror) hung
// forever — the package action stayed "running" and the server never received
// a result. run() must bound the child and surface a timeout error.
func TestRunHonoursTimeout(t *testing.T) {
	start := time.Now()
	_, err := run(context.Background(), 300*time.Millisecond, "sleep", "30")
	if err == nil {
		t.Fatal("expected a timeout error from a hanging command")
	}
	if !strings.Contains(err.Error(), "timed out") {
		t.Errorf("error = %v, want a timeout error", err)
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Errorf("run blocked for %s; the timeout was not enforced", elapsed)
	}
}

// TestRunNilStdin: a child must not be able to block on terminal input.
func TestRunNilStdin(t *testing.T) {
	if _, err := run(context.Background(), 5*time.Second, "true"); err != nil {
		t.Fatalf("run(true): %v", err)
	}
}

// elevHint: a permission-shaped failure on a non-sudo host carries the
// elevation remedy (it is the user-facing message on the Updates page);
// sudo mode and unrelated failures pass through untouched.
func TestElevHint(t *testing.T) {
	permErr := fmt.Errorf("apt-get upgrade: exit 100: E: Could not open lock file /var/lib/dpkg/lock-frontend - open (13: Permission denied)")
	netErr := fmt.Errorf("apt-get upgrade: exit 100: E: Unable to fetch some archives")

	if got := elevHint(elevate.Sudo, permErr); got != permErr {
		t.Fatalf("sudo mode must not append the hint: %v", got)
	}
	if got := elevHint(elevate.None, netErr); got != netErr {
		t.Fatalf("unrelated failure must pass through: %v", got)
	}
	got := elevHint(elevate.None, permErr)
	if !strings.Contains(got.Error(), "PARTOUT_ELEVATE=sudo") || !strings.Contains(got.Error(), "elevation is OFF") {
		t.Fatalf("permission failure on a non-sudo host must carry the remedy: %v", got)
	}
	// The original error stays wrapped (errors.Is chains keep working).
	if !errors.Is(got, permErr) {
		t.Fatalf("original error must stay wrapped")
	}
}
