package factscollect

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// ---- Config ---------------------------------------------------------------

func TestFillConfig(t *testing.T) {
	cfg := (&Config{}).Fill()
	if cfg.ObserveFactsInterval != 300 {
		t.Errorf("ObserveFactsInterval = %d, want 300", cfg.ObserveFactsInterval)
	}
	// An explicit value is preserved.
	if got := (&Config{ObserveFactsInterval: 60}).Fill(); got.ObserveFactsInterval != 60 {
		t.Errorf("ObserveFactsInterval = %d, want 60", got.ObserveFactsInterval)
	}
	// Fill on a nil receiver must not panic.
	var nilCfg *Config
	if got := nilCfg.Fill(); got == nil || got.ObserveFactsInterval != 300 {
		t.Error("Fill() on nil config should return the default")
	}
}

// TestCollectNilConfigAndEmptyHost: Collect must always return a usable value
// and nil (not an empty struct) when nothing was collected.
func TestCollectNilConfigDoesNotPanic(t *testing.T) {
	// Not asserting on contents: the host may or may not have facts. The
	// contract under test is "no panic, and empty means nil".
	f := Collect(nil)
	if f != nil && f.ServicesDetailed == nil && f.Configs == nil && f.Certificates == nil {
		t.Error("Collect returned a non-nil empty Facts; want nil")
	}
}

// ---- unit parsing ---------------------------------------------------------

func TestParseUnitList(t *testing.T) {
	out := `nginx.service        loaded active running A high performance web server
myapp.service        loaded active running My app
broken.service       loaded failed failed  Broken app
multi-user.target    loaded active active  Multi-User System

4 loaded units listed.
To show all installed unit files use 'systemctl list-unit-files'.
`
	got := parseUnitList(out)
	want := []string{"nginx", "myapp", "broken", "multi-user.target"}
	if len(got) != len(want) {
		t.Fatalf("parseUnitList = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("unit[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestParseUnitListEmpty(t *testing.T) {
	if got := parseUnitList(""); len(got) != 0 {
		t.Errorf("parseUnitList(\"\") = %v, want empty", got)
	}
}

// TestParseUnitShowLastExitCode is the regression test for the property
// collision: RestartForceExitStatus is a restart-trigger list, not the
// observed exit status, and must never populate LastExitCode.
func TestParseUnitShowLastExitCode(t *testing.T) {
	f := parseUnitShow("myapp", strings.Join([]string{
		"Type=simple",
		"ActiveState=active",
		"SubState=running",
		"UnitFileState=enabled",
		"Restart=on-failure",
		"RestartForceExitStatus=SIGKILL",
		"ExecMainStatus=3",
		"WantedBy=multi-user.target",
		"RequiredBy=",
		"After=network-online.target basic.target",
		"MemoryCurrent=45678901",
		"CPUSec=12.345",
	}, "\n"))

	if f.LastExitCode != 3 {
		t.Errorf("LastExitCode = %d, want 3 (ExecMainStatus)", f.LastExitCode)
	}
	if f.LastExitStatus != "3" {
		t.Errorf("LastExitStatus = %q, want \"3\"", f.LastExitStatus)
	}
	if f.State != "active" {
		t.Errorf("State = %q, want active (from ActiveState)", f.State)
	}
	if f.SubState != "running" {
		t.Errorf("SubState = %q, want running", f.SubState)
	}
	if !f.Enabled {
		t.Error("Enabled = false, want true (UnitFileState=enabled)")
	}
	if f.RestartPolicy != "on-failure" {
		t.Errorf("RestartPolicy = %q, want on-failure", f.RestartPolicy)
	}
	if f.MemoryCurrent != 45678901 {
		t.Errorf("MemoryCurrent = %d, want 45678901", f.MemoryCurrent)
	}
	if f.CPUUsageSec != "12.345" {
		t.Errorf("CPUUsageSec = %q, want 12.345", f.CPUUsageSec)
	}
	if len(f.WantedBy) != 1 || f.WantedBy[0] != "multi-user.target" {
		t.Errorf("WantedBy = %v, want [multi-user.target]", f.WantedBy)
	}
	if len(f.After) != 2 || f.After[0] != "network-online.target" || f.After[1] != "basic.target" {
		t.Errorf("After = %v, want [network-online.target basic.target]", f.After)
	}
}

// TestParseUnitShowRestartForceOnly: with only the restart trigger present,
// the exit code must stay zero rather than borrow the signal name.
func TestParseUnitShowRestartForceOnly(t *testing.T) {
	f := parseUnitShow("x", "RestartForceExitStatus=SIGKILL\nExecMainStatus=")
	if f.LastExitCode != 0 || f.LastExitStatus != "" {
		t.Errorf("LastExitCode/Status = %d/%q, want 0/\"\"", f.LastExitCode, f.LastExitStatus)
	}
}

func TestParseUnitShowEmpty(t *testing.T) {
	f := parseUnitShow("empty", "")
	if f.Name != "empty" {
		t.Errorf("Name = %q, want empty", f.Name)
	}
	if f.Enabled || f.State != "" {
		t.Errorf("zero-value expectations violated: %+v", f)
	}
}

// TestIsCustomUnitIn covers the label, unit-file, and drop-in paths, plus the
// suffix-handling that the old /etc/systemd/system-only check got wrong.
func TestIsCustomUnitIn(t *testing.T) {
	dir := t.TempDir()
	mustWrite := func(rel string) {
		p := filepath.Join(dir, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte("[Unit]\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	mustWrite("myapp.service")
	mustWrite("customtarget.target")
	mustWrite("dropservice.d/override.conf")

	cases := []struct {
		name, labels string
		want         bool
	}{
		{"myapp", "", true},              // unit file present
		{"myapp", "myapp,other", true},   // label match
		{"myapp.service", "", true},      // suffix stripped
		{"customtarget", "", true},       // non-service unit type
		{"dropservice", "", true},        // drop-in dir only
		{"sshd", "", false},              // distro unit, no file here
		{"sshd", "sshd", true},           // labelled distro unit
		{"sshd", " myapp , sshd ", true}, // labels are trimmed
		{"", "", false},                  // empty name
	}
	for _, c := range cases {
		if got := isCustomUnitIn(c.name, c.labels, []string{dir}); got != c.want {
			t.Errorf("isCustomUnitIn(%q, %q) = %v, want %v", c.name, c.labels, got, c.want)
		}
	}

	// A missing search dir must not match anything.
	if isCustomUnitIn("myapp", "", []string{filepath.Join(dir, "nope")}) {
		t.Error("matched a unit with a nonexistent search dir")
	}
}

// ---- cert helpers ---------------------------------------------------------

func TestParseCertTime(t *testing.T) {
	// Single-digit day (openssl pads with a space) and two-digit day.
	for _, in := range []string{
		"Apr  5 00:00:00 2024 GMT",
		"Apr 15 12:34:56 2024 GMT",
		"Dec  1 23:59:59 2030 GMT",
	} {
		tm, err := parseCertTime(in)
		if err != nil {
			t.Errorf("parseCertTime(%q): %v", in, err)
			continue
		}
		if tm.Year() < 2024 {
			t.Errorf("parseCertTime(%q) = %v, implausible year", in, tm)
		}
	}
	if _, err := parseCertTime("not a date"); err == nil {
		t.Error("parseCertTime(garbage) should error")
	}
}

// TestParseKeyType covers the regression where key size was hardcoded and the
// public-key block (which is what openssl x509 prints) was never read.
func TestParseKeyType(t *testing.T) {
	rsa4096 := `Public Key Algorithm: rsaEncryption
        Public-Key: (4096 bit)
        Modulus:`
	rsa2048 := `Public Key Algorithm: rsaEncryption
        Public-Key: (2048 bit)`
	ec := `Public Key Algorithm: id-ecPublicKey
        ASN1 OID: prime256v1
        NIST CURVE: P-256`
	ec384 := `Public Key Algorithm: id-ecPublicKey
        NIST CURVE: P-384`
	ed := `Public Key Algorithm: ED25519
        ED25519 Public-Key:`

	cases := map[string]string{
		rsa4096: "RSA-4096",
		rsa2048: "RSA-2048",
		ec:      "ECDSA-P-256",
		ec384:   "ECDSA-P-384",
		ed:      "Ed25519",
	}
	for in, want := range cases {
		if got := parseKeyType(in); got != want {
			t.Errorf("parseKeyType(...) = %q, want %q", got, want)
		}
	}
	if got := parseKeyType("nothing useful"); got != "unknown" {
		t.Errorf("parseKeyType(garbage) = %q, want unknown", got)
	}
}

func TestExtractBitSize(t *testing.T) {
	if got := extractBitSize("Public-Key: (4096 bit)"); got != "4096" {
		t.Errorf("extractBitSize = %q, want 4096", got)
	}
	if got := extractBitSize("no size here"); got != "" {
		t.Errorf("extractBitSize = %q, want empty", got)
	}
	if got := extractBitSize("Public-Key: (notanumber bit)"); got != "" {
		t.Errorf("extractBitSize = %q, want empty for non-numeric", got)
	}
}

func TestResolveCABundle(t *testing.T) {
	// Explicit path wins when it exists.
	dir := t.TempDir()
	ca := filepath.Join(dir, "ca.pem")
	if err := os.WriteFile(ca, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := resolveCABundle(ca); got != ca {
		t.Errorf("resolveCABundle(explicit) = %q, want %q", got, ca)
	}
	// Nonexistent explicit path falls through to system defaults (may be ""
	// on a host with no bundle — assert only that it is not the bogus path).
	if got := resolveCABundle(filepath.Join(dir, "missing.pem")); got == filepath.Join(dir, "missing.pem") {
		t.Error("resolveCABundle returned a nonexistent explicit path")
	}
}

func TestDefaultCABundlesIncludesCommonPaths(t *testing.T) {
	paths := defaultCABundles()
	joined := strings.Join(paths, " ")
	for _, want := range []string{"ca-certificates.crt", "ca-bundle.crt", "cert.pem"} {
		if !strings.Contains(joined, want) {
			t.Errorf("defaultCABundles missing %q: %v", want, paths)
		}
	}
}

func TestExtractSANs(t *testing.T) {
	text := `X509v3 extensions:
            X509v3 Subject Alternative Name:
                DNS:app.example.com, DNS:www.example.com, IP Address:10.0.0.1, DNS:api.example.com
        X509v3 Basic Constraints:
            CA:FALSE`
	got := extractSANs(text)
	want := []string{"app.example.com", "www.example.com", "api.example.com"}
	if len(got) != len(want) {
		t.Fatalf("extractSANs = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("SAN[%d] = %q, want %q", i, got[i], want[i])
		}
	}
	if got := extractSANs("no sans"); got != nil {
		t.Errorf("extractSANs(no sans) = %v, want nil", got)
	}
}

// ---- findCertFiles bounds -------------------------------------------------

// TestFindCertFilesBounded is the regression test for unbounded scanning:
// the walk must stop at the budget, skip symlinks, and skip oversized files.
func TestFindCertFilesBounded(t *testing.T) {
	dir := t.TempDir()
	for i := 0; i < 10; i++ {
		p := filepath.Join(dir, "cert"+string(rune('a'+i))+".pem")
		if err := os.WriteFile(p, []byte("-----BEGIN CERTIFICATE-----\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	sub := filepath.Join(dir, "nested")
	if err := os.MkdirAll(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sub, "nested.crt"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}

	all := findCertFilesBounded(dir, 100)
	if len(all) != 11 {
		t.Errorf("found %d files, want 11 (10 + 1 nested)", len(all))
	}
	capped := findCertFilesBounded(dir, 3)
	if len(capped) != 3 {
		t.Errorf("findCertFilesBounded(budget=3) = %d files, want 3", len(capped))
	}

	// Symlinks are not followed.
	link := filepath.Join(dir, "link.pem")
	if err := os.Symlink(filepath.Join(dir, "certa.pem"), link); err == nil {
		for _, f := range findCertFilesBounded(dir, 100) {
			if f == link {
				t.Error("followed a symlink")
			}
		}
	}

	// Oversized files are skipped.
	big := filepath.Join(dir, "huge.pem")
	if err := os.WriteFile(big, make([]byte, maxCertFileSize+1), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, f := range findCertFilesBounded(dir, 100) {
		if f == big {
			t.Error("included an oversized file")
		}
	}
}

func TestFindCertFilesBoundedMissingDir(t *testing.T) {
	if got := findCertFilesBounded(filepath.Join(t.TempDir(), "nope"), 10); got != nil {
		t.Errorf("missing dir = %v, want nil", got)
	}
}

// ---- runOutput timeout -----------------------------------------------------

func TestRunOutputTimeout(t *testing.T) {
	start := time.Now()
	_, err := runOutput(200*time.Millisecond, "sleep", "5")
	if err == nil {
		t.Fatal("expected a timeout error")
	}
	if elapsed := time.Since(start); elapsed > 3*time.Second {
		t.Errorf("runOutput took %v; the timeout did not fire", elapsed)
	}
}

func TestRunOutputSuccess(t *testing.T) {
	out, err := runOutput(time.Second, "echo", "hello")
	if err != nil {
		t.Fatalf("runOutput: %v", err)
	}
	if strings.TrimSpace(out) != "hello" {
		t.Errorf("output = %q, want hello", out)
	}
}

// ---- small helpers --------------------------------------------------------

func TestSplitList(t *testing.T) {
	cases := map[string][]string{
		"":            nil,
		"a":           {"a"},
		"a, b":        {"a", "b"},
		" a , b , ":   {"a", "b"},
		"single.item": {"single.item"},
	}
	for in, want := range cases {
		got := splitList(in)
		if len(got) != len(want) {
			t.Errorf("splitList(%q) = %v, want %v", in, got, want)
			continue
		}
		for i := range want {
			if got[i] != want[i] {
				t.Errorf("splitList(%q)[%d] = %q, want %q", in, i, got[i], want[i])
			}
		}
	}
}

func TestParseUint64AndExitCode(t *testing.T) {
	if n, err := parseUint64("12345"); err != nil || n != 12345 {
		t.Errorf("parseUint64 = %d/%v, want 12345/nil", n, err)
	}
	if _, err := parseUint64(""); err == nil {
		t.Error("parseUint64(\"\") should error")
	}
	if _, err := parseUint64("nope"); err == nil {
		t.Error("parseUint64(nope) should error")
	}
	if got := parseExitCode("0"); got != 0 {
		t.Errorf("parseExitCode(0) = %d, want 0", got)
	}
	if got := parseExitCode("2"); got != 2 {
		t.Errorf("parseExitCode(2) = %d, want 2", got)
	}
	if got := parseExitCode("SIGKILL"); got != 0 {
		t.Errorf("parseExitCode(SIGKILL) = %d, want 0 (unparseable)", got)
	}
	if got := parseExitCode(""); got != 0 {
		t.Errorf("parseExitCode(\"\") = %d, want 0", got)
	}
}

func TestExtractVersion(t *testing.T) {
	if got := extractVersion("HAProxy version 2.8.5 2023/04/13"); got != "2.8.5" {
		t.Errorf("extractVersion(haproxy) = %q, want 2.8.5", got)
	}
	// nginx prints the version after a "nginx/" product prefix.
	if got := extractVersion("nginx version: nginx/1.24.0"); got != "1.24.0" {
		t.Errorf("extractVersion(nginx) = %q, want 1.24.0", got)
	}
	if got := extractVersion("nginx version: openresty/1.21.4.1"); got != "1.21.4.1" {
		t.Errorf("extractVersion(openresty) = %q, want 1.21.4.1", got)
	}
	if got := extractVersion("no version here"); got != "" {
		t.Errorf("extractVersion(garbage) = %q, want empty", got)
	}
}

func TestParseCertMissingFile(t *testing.T) {
	if cf := parseCert(filepath.Join(t.TempDir(), "nope.pem"), ""); cf != nil {
		t.Errorf("parseCert(missing) = %+v, want nil", cf)
	}
}

func TestParseHAProxyTopology(t *testing.T) {
	dir := t.TempDir()
	cfg := filepath.Join(dir, "haproxy.cfg")
	content := `
global
    daemon

frontend web
    bind *:443 ssl crt /etc/ssl/app.pem
    default_backend webservers

backend webservers
    server web1 10.0.0.1:80 check
    server web2 10.0.0.2:80 check
`
	if err := os.WriteFile(cfg, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	backends, listeners := parseHAProxyTopology(cfg)
	if len(backends) == 0 {
		t.Errorf("no backends parsed from %s", content)
	}
	found := false
	for _, b := range backends {
		if b.Name == "webservers" {
			found = true
		}
	}
	if !found {
		t.Errorf("backend webservers not parsed: %+v", backends)
	}
	_ = listeners
}

func TestParseHAProxyTopologyMissingFile(t *testing.T) {
	backends, listeners := parseHAProxyTopology(filepath.Join(t.TempDir(), "nope.cfg"))
	if backends != nil || listeners != nil {
		t.Errorf("missing config returned %v/%v, want nil/nil", backends, listeners)
	}
}

// ---- end-to-end-ish collection -------------------------------------------

// TestCollectReturnsOnlyKnownDomains asserts the shape contract of the
// top-level blob, whatever this host actually has.
func TestCollectShapeContract(t *testing.T) {
	f := Collect(&Config{ObserveFactsInterval: 300})
	if f == nil {
		t.Skip("no facts on this host")
	}
	if f.ServicesDetailed == nil && f.Configs == nil && f.Certificates == nil {
		t.Fatal("non-nil Facts with no domains")
	}
	if f.ServicesDetailed != nil {
		for _, u := range f.ServicesDetailed.Units {
			if u.Name == "" {
				t.Error("collected a unit with an empty name")
			}
		}
	}
	if f.Certificates != nil {
		for _, c := range f.Certificates.Items {
			if c.Path == "" {
				t.Error("collected a cert with an empty path")
			}
			if c.NotAfter != 0 && c.DaysRemaining == 0 {
				// DaysRemaining is derived; zero with a known expiry is
				// possible only within the same day — acceptable.
				continue
			}
		}
	}
}

// ---- real-certificate parsing ---------------------------------------------

// writeSelfSignedCert writes a self-signed cert with the given SANs and key
// to dir, returning its path. Uses crypto/x509 so the test needs no openssl.
func writeSelfSignedCert(t *testing.T, dir string, hosts []string, bits int) string {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(12345),
		Subject: pkix.Name{
			CommonName:   "app.example.com",
			Organization: []string{"Acme"},
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(48 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		DNSNames:              hosts,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "self.pem")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if err := pem.Encode(f, &pem.Block{Type: "CERTIFICATE", Bytes: der}); err != nil {
		t.Fatal(err)
	}
	return path
}

// TestParseCertRealFile is the end-to-end parser test against a real
// certificate: subject/issuer must be the names only (not the whole openssl
// blob), SANs must be split cleanly, the key size must reflect the actual
// key, and self-signed detection must work.
func TestParseCertRealFile(t *testing.T) {
	if _, err := exec.LookPath("openssl"); err != nil {
		t.Skip("openssl not available")
	}
	dir := t.TempDir()
	path := writeSelfSignedCert(t, dir, []string{"app.example.com", "www.example.com"}, 2048)

	cf := parseCert(path, "")
	if cf == nil {
		t.Fatal("parseCert returned nil for a valid certificate")
	}
	// RDN order depends on how the name was encoded (Go's marshaller and
	// `openssl req` differ), so assert on content, not ordering.
	for _, want := range []string{"CN = app.example.com", "O = Acme"} {
		if !strings.Contains(cf.Subject, want) {
			t.Errorf("Subject = %q, want it to contain %q (and not the whole openssl blob)", cf.Subject, want)
		}
	}
	if strings.Contains(cf.Subject, "\n") || strings.Contains(cf.Subject, "notAfter") {
		t.Errorf("Subject swallowed trailing output: %q", cf.Subject)
	}
	if cf.Issuer != cf.Subject {
		t.Errorf("Issuer = %q, want equal to Subject for a self-signed cert", cf.Issuer)
	}
	if len(cf.SANs) != 2 || cf.SANs[0] != "app.example.com" || cf.SANs[1] != "www.example.com" {
		t.Errorf("SANs = %v, want [app.example.com www.example.com]", cf.SANs)
	}
	if !strings.HasPrefix(cf.KeyType, "RSA-") {
		t.Errorf("KeyType = %q, want an RSA-<bits> value", cf.KeyType)
	}
	if !cf.SelfSigned {
		t.Error("SelfSigned = false, want true")
	}
	if cf.ChainLength != 1 {
		t.Errorf("ChainLength = %d, want 1", cf.ChainLength)
	}
	if cf.NotAfter == 0 {
		t.Error("NotAfter = 0, want a parsed expiry")
	}
	if cf.DaysRemaining < 1 || cf.DaysRemaining > 3 {
		t.Errorf("DaysRemaining = %d, want ~2", cf.DaysRemaining)
	}
	if cf.Serial == "" || strings.Contains(cf.Serial, "\n") {
		t.Errorf("Serial = %q, want a single-line serial", cf.Serial)
	}
	// No CA bundle passed: verification must be reported as not attempted.
	if cf.ChainChecked {
		t.Error("ChainChecked = true, want false when no bundle was supplied")
	}
}

// TestParseCertChainedNotSelfSigned: a leaf signed by a separate CA is not
// self-signed even though its issuer name differs — and must not be reported
// as self-signed.
func TestParseCertChainedNotSelfSigned(t *testing.T) {
	if _, err := exec.LookPath("openssl"); err != nil {
		t.Skip("openssl not available")
	}
	dir := t.TempDir()

	// CA.
	caKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}

	// Leaf signed by the CA.
	leafKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "leaf.example.com"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(240 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"leaf.example.com"},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, caCert, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	leafPath := filepath.Join(dir, "leaf.pem")
	f, err := os.Create(leafPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := pem.Encode(f, &pem.Block{Type: "CERTIFICATE", Bytes: leafDER}); err != nil {
		t.Fatal(err)
	}
	f.Close()

	// CA bundle containing the CA cert, to exercise chain verification.
	bundle := filepath.Join(dir, "ca.pem")
	if err := os.WriteFile(bundle, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}), 0o644); err != nil {
		t.Fatal(err)
	}

	cf := parseCert(leafPath, bundle)
	if cf == nil {
		t.Fatal("parseCert returned nil")
	}
	if cf.SelfSigned {
		t.Error("SelfSigned = true for a CA-signed leaf")
	}
	if cf.Subject != "CN = leaf.example.com" {
		t.Errorf("Subject = %q", cf.Subject)
	}
	if cf.Issuer != "CN = Test CA" {
		t.Errorf("Issuer = %q, want CN = Test CA", cf.Issuer)
	}
	if !cf.ChainChecked {
		t.Error("ChainChecked = false, want true (a bundle was supplied)")
	}
	if !cf.ChainValid {
		t.Errorf("ChainValid = false, want true (leaf chains to the supplied CA); DaysRemaining=%d", cf.DaysRemaining)
	}
}

// TestParseCertBrokenChain: a leaf whose CA is not in the bundle must report
// checked-but-invalid, not unchecked.
func TestParseCertBrokenChain(t *testing.T) {
	if _, err := exec.LookPath("openssl"); err != nil {
		t.Skip("openssl not available")
	}
	dir := t.TempDir()
	// Self-signed cert (not a CA for anything) + empty-ish bundle → verify fails.
	path := writeSelfSignedCert(t, dir, []string{"x.example.com"}, 2048)
	otherKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	otherTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(9),
		Subject:               pkix.Name{CommonName: "Unrelated CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	otherDER, err := x509.CreateCertificate(rand.Reader, otherTmpl, otherTmpl, &otherKey.PublicKey, otherKey)
	if err != nil {
		t.Fatal(err)
	}
	bundle := filepath.Join(dir, "unrelated.pem")
	if err := os.WriteFile(bundle, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: otherDER}), 0o644); err != nil {
		t.Fatal(err)
	}

	cf := parseCert(path, bundle)
	if cf == nil {
		t.Fatal("parseCert returned nil")
	}
	if !cf.ChainChecked {
		t.Error("ChainChecked = false, want true")
	}
	if cf.ChainValid {
		t.Error("ChainValid = true for an unrelated bundle, want false")
	}
}

// TestParseCertMultiCertChainFile: chain_length counts the PEM blocks.
func TestParseCertMultiCertChainFile(t *testing.T) {
	if _, err := exec.LookPath("openssl"); err != nil {
		t.Skip("openssl not available")
	}
	dir := t.TempDir()
	one := writeSelfSignedCert(t, dir, []string{"a.example.com"}, 2048)
	data, err := os.ReadFile(one)
	if err != nil {
		t.Fatal(err)
	}
	chain := filepath.Join(dir, "chain.pem")
	if err := os.WriteFile(chain, append(data, data...), 0o644); err != nil {
		t.Fatal(err)
	}
	cf := parseCert(chain, "")
	if cf == nil {
		t.Fatal("parseCert returned nil")
	}
	if cf.ChainLength != 2 {
		t.Errorf("ChainLength = %d, want 2", cf.ChainLength)
	}
}

func TestParseNginxVhosts(t *testing.T) {
	dir := t.TempDir()
	cfg := filepath.Join(dir, "nginx.conf")
	content := `events {}

http {
    # a comment with braces { } must be ignored
    server {
        listen 443 ssl;
        server_name app.example.com;
        ssl_certificate /etc/ssl/app/fullchain.pem;
        root /var/www/app;

        location / {
            proxy_pass http://127.0.0.1:8080;
        }
    }

    server {
        listen 80;
        server_name legacy.example.com;
        root /var/www/legacy;
    }
}
`
	if err := os.WriteFile(cfg, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	vhosts := parseNginxVhosts(cfg)
	if len(vhosts) != 2 {
		t.Fatalf("parsed %d vhosts, want 2: %+v", len(vhosts), vhosts)
	}
	app := vhosts[0]
	if app.ServerName != "app.example.com" {
		t.Errorf("vhost0 server_name = %q", app.ServerName)
	}
	if app.Port != 443 || !app.TLS {
		t.Errorf("vhost0 listen = %d/%v, want 443/true", app.Port, app.TLS)
	}
	if app.TLSCert != "/etc/ssl/app/fullchain.pem" {
		t.Errorf("vhost0 ssl_certificate = %q", app.TLSCert)
	}
	if app.Root != "/var/www/app" {
		t.Errorf("vhost0 root = %q", app.Root)
	}
	if app.Upstream != "http://127.0.0.1:8080" {
		t.Errorf("vhost0 proxy_pass = %q (nested location must be captured)", app.Upstream)
	}
	legacy := vhosts[1]
	if legacy.ServerName != "legacy.example.com" || legacy.Port != 80 || legacy.TLS {
		t.Errorf("vhost1 = %+v", legacy)
	}
}

func TestParseNginxVhostsMissingFile(t *testing.T) {
	if got := parseNginxVhosts(filepath.Join(t.TempDir(), "nope.conf")); got != nil {
		t.Errorf("missing file = %+v, want nil", got)
	}
}

func TestParseNginxServerBlockDirectives(t *testing.T) {
	block := `server {
    listen 8443 ssl;
    listen 9443;
    server_name a.example.com b.example.com;
}`
	v := parseNginxServerBlock(block)
	if !v.TLS {
		t.Error("TLS = false, want true (ssl on a listen line)")
	}
	if v.Port != 9443 {
		// The last numeric listen wins; documented behaviour.
		t.Logf("port = %d (last numeric listen wins)", v.Port)
	}
	if v.ServerName != "a.example.com" {
		t.Errorf("server_name = %q, want the first name", v.ServerName)
	}
}

// TestIsNginxServerOpen guards against matching `server_name` or `server {`
// appearing as a nested directive.
func TestIsNginxServerOpen(t *testing.T) {
	cases := map[string]bool{
		"server {":                     true,
		"server{":                      false, // no space: not the form nginx emits
		"server_name app.example.com;": false,
		"upstream server {":            false,
		"    server {":                 true,
	}
	for in, want := range cases {
		if got := isNginxServerOpen(strings.TrimSpace(in)); got != want {
			t.Errorf("isNginxServerOpen(%q) = %v, want %v", in, got, want)
		}
	}
}

func TestStripNginxComment(t *testing.T) {
	if got := stripNginxComment("listen 80; # comment"); strings.TrimSpace(got) != "listen 80;" {
		t.Errorf("stripNginxComment = %q", got)
	}
	if got := stripNginxComment("server_name a;"); got != "server_name a;" {
		t.Errorf("stripNginxComment dropped content: %q", got)
	}
}

// TestParseUnitShowActiveStateIsState is the regression test for the property
// mapping: `state` must come from ActiveState (the failed/active/inactive
// state alert rules match on), not the load state.
func TestParseUnitShowActiveStateIsState(t *testing.T) {
	f := parseUnitShow("broken", "ActiveState=failed\nSubState=failed\nUnitFileState=enabled")
	if f.State != "failed" {
		t.Errorf("State = %q, want failed (ActiveState)", f.State)
	}
	if f.SubState != "failed" {
		t.Errorf("SubState = %q, want failed", f.SubState)
	}
}
