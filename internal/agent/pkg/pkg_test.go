package pkg

import (
	"context"
	"strings"
	"testing"
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
		b := SelectBackend(facts)
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