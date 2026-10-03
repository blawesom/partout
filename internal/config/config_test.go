package config

import (
	"os"
	"testing"
)

// setenv sets (value) or unsets ("-") env vars for the duration of the
// test, restoring previous state on cleanup.
func setenv(t *testing.T, kvs ...string) {
	t.Helper()
	for i := 0; i+1 < len(kvs); i += 2 {
		k, v := kvs[i], kvs[i+1]
		old, had := os.LookupEnv(k)
		if v == "-" {
			os.Unsetenv(k)
		} else {
			os.Setenv(k, v)
		}
		t.Cleanup(func() {
			if had {
				os.Setenv(k, old)
			} else {
				os.Unsetenv(k)
			}
		})
	}
}

// clearPartout unsets every PARTOUT_* variable the package reads.
func clearPartout(t *testing.T) {
	t.Helper()
	for _, k := range []string{
		"PARTOUT_MODE", "PARTOUT_PORT", "PARTOUT_DB_PATH", "PARTOUT_DATA_DIR",
		"PARTOUT_TLS", "PARTOUT_TLS_SERVER_NAMES",
		"PARTOUT_TOKEN_ADMIN", "PARTOUT_TOKEN_OPERATOR", "PARTOUT_TOKEN_VIEWER",
		"PARTOUT_SERVER", "PARTOUT_TOKEN", "PARTOUT_FACTS_INTERVAL",
		"PARTOUT_TLS_CA", "PARTOUT_RELEASE_KEY", "PARTOUT_UPDATE_HEALTH_S",
		"PARTOUT_UPDATE_RESTART_CMD",
		"PARTOUT_ALLOW_UNSIGNED_RELEASES", "PARTOUT_RELEASE_VERIFY_KEY",
	} {
		setenv(t, k, "-")
	}
}

func TestDefaults(t *testing.T) {
	clearPartout(t)
	c, err := Load()
	if err != nil {
		t.Fatalf("Load(): %v", err)
	}
	if c.Mode != "server" {
		t.Errorf("mode = %q, want server (unset default)", c.Mode)
	}
	if c.Port != 8443 {
		t.Errorf("port = %d, want 8443", c.Port)
	}
	if c.Addr != "" {
		t.Errorf("addr = %q, want empty (all interfaces) by default", c.Addr)
	}
	if c.DBPath != "./partout.db" {
		t.Errorf("db = %q, want ./partout.db", c.DBPath)
	}
	if c.TLS {
		t.Error("tls should be off by default")
	}
	if c.FactsInterval != 3600 {
		t.Errorf("facts interval = %d, want 3600", c.FactsInterval)
	}
	if c.TLSCAFile != "" || c.TLSCertFile != "" || c.TLSKeyFile != "" {
		t.Error("TLS material paths should be empty by default")
	}
}

func TestServerEnv(t *testing.T) {
	clearPartout(t)
	setenv(t,
		"PARTOUT_MODE", "server",
		"PARTOUT_PORT", "9443",
		"PARTOUT_ADDR", "127.0.0.1",
		"PARTOUT_DB_PATH", "/srv/partout/partout.db",
		"PARTOUT_TLS", "on",
		"PARTOUT_TLS_SERVER_NAMES", "partout.example.com,10.0.0.5",
		"PARTOUT_TOKEN_ADMIN", "adm",
		"PARTOUT_TOKEN_OPERATOR", "op",
		"PARTOUT_TOKEN_VIEWER", "view",
	)
	c, err := Load()
	if err != nil {
		t.Fatalf("Load(): %v", err)
	}
	if c.Port != 9443 {
		t.Errorf("port = %d, want 9443", c.Port)
	}
	if c.Addr != "127.0.0.1" {
		t.Errorf("addr = %q, want 127.0.0.1", c.Addr)
	}
	if c.DBPath != "/srv/partout/partout.db" {
		t.Errorf("db = %q", c.DBPath)
	}
	if !c.TLS {
		t.Error("tls should be on")
	}
	if c.TLSNames != "partout.example.com,10.0.0.5" {
		t.Errorf("tls names = %q", c.TLSNames)
	}
	if c.AdminToken != "adm" || c.OperatorToken != "op" || c.ViewerToken != "view" {
		t.Errorf("tokens = %q/%q/%q", c.AdminToken, c.OperatorToken, c.ViewerToken)
	}
}

func TestTLSBoolParsing(t *testing.T) {
	clearPartout(t)
	for v, want := range map[string]bool{
		"on": true, "true": true, "1": true, "yes": true,
		"off": false, "false": false, "0": false, "no": false, "": false, "bogus": false,
	} {
		setenv(t, "PARTOUT_TLS", v)
		c, err := Load()
		if err != nil {
			t.Fatalf("Load() with PARTOUT_TLS=%q: %v", v, err)
		}
		if c.TLS != want {
			t.Errorf("PARTOUT_TLS=%q → TLS=%v, want %v", v, c.TLS, want)
		}
	}
}

func TestAgentValid(t *testing.T) {
	clearPartout(t)
	setenv(t,
		"PARTOUT_MODE", "agent",
		"PARTOUT_SERVER", "192.0.2.1:8443",
		"PARTOUT_TOKEN", "par_enr_test",
		"PARTOUT_FACTS_INTERVAL", "600",
		"PARTOUT_TLS_CA", "/etc/partout/ca.crt",
		"PARTOUT_DATA_DIR", "/var/lib/partout/agent",
	)
	c, err := Load()
	if err != nil {
		t.Fatalf("Load(): %v", err)
	}
	if c.ServerURL != "192.0.2.1:8443" {
		t.Errorf("server = %q", c.ServerURL)
	}
	if c.Token != "par_enr_test" {
		t.Errorf("token = %q", c.Token)
	}
	if c.FactsInterval != 600 {
		t.Errorf("facts interval = %d, want 600", c.FactsInterval)
	}
	if c.TLSCAFile != "/etc/partout/ca.crt" {
		t.Errorf("tls ca = %q", c.TLSCAFile)
	}
	if c.DataDir != "/var/lib/partout/agent" {
		t.Errorf("data dir = %q", c.DataDir)
	}
}

func TestAgentMissingServer(t *testing.T) {
	clearPartout(t)
	setenv(t, "PARTOUT_MODE", "agent", "PARTOUT_SERVER", "-")
	if _, err := Load(); err == nil {
		t.Fatal("expected error for missing PARTOUT_SERVER in agent mode")
	}
}

func TestInvalidMode(t *testing.T) {
	clearPartout(t)
	setenv(t, "PARTOUT_MODE", "foobar")
	if _, err := Load(); err == nil {
		t.Fatal("expected error for invalid mode")
	}
}

func TestModeCaseInsensitive(t *testing.T) {
	clearPartout(t)
	setenv(t, "PARTOUT_MODE", "AGENT", "PARTOUT_SERVER", "x:1")
	c, err := Load()
	if err != nil {
		t.Fatalf("Load(): %v", err)
	}
	if c.Mode != "agent" {
		t.Errorf("mode = %q, want agent (lowercased)", c.Mode)
	}
}

func TestEmbedded(t *testing.T) {
	clearPartout(t)
	setenv(t, "PARTOUT_MODE", "embedded", "PARTOUT_SERVER", "-")
	c, err := Load()
	if err != nil {
		t.Fatalf("Load(): %v", err)
	}
	if c.Mode != "embedded" {
		t.Errorf("mode = %q, want embedded", c.Mode)
	}
}

func TestObserveFactsDefaults(t *testing.T) {
	clearPartout(t)
	c, err := Load()
	if err != nil {
		t.Fatalf("Load(): %v", err)
	}
	if c.ObserveFactsInterval != 300 {
		t.Errorf("ObserveFactsInterval = %d, want default 300", c.ObserveFactsInterval)
	}
	if c.ServiceLabels != "" {
		t.Errorf("ServiceLabels = %q, want empty", c.ServiceLabels)
	}
	if c.CertPaths != "" {
		t.Errorf("CertPaths = %q, want empty", c.CertPaths)
	}
}

func TestObserveFactsEnv(t *testing.T) {
	clearPartout(t)
	setenv(t,
		"PARTOUT_MODE", "agent",
		"PARTOUT_SERVER", "x:1",
		"PARTOUT_OBSERVE_FACTS_INTERVAL", "60",
		"PARTOUT_SERVICE_LABELS", "myapp,critical",
		"PARTOUT_CERT_PATHS", "/etc/ssl/myapp",
		"PARTOUT_CERT_CA", "/etc/ssl/myapp/ca.pem",
	)
	c, err := Load()
	if err != nil {
		t.Fatalf("Load(): %v", err)
	}
	if c.ObserveFactsInterval != 60 {
		t.Errorf("ObserveFactsInterval = %d, want 60", c.ObserveFactsInterval)
	}
	if c.ServiceLabels != "myapp,critical" {
		t.Errorf("ServiceLabels = %q, want myapp,critical", c.ServiceLabels)
	}
	if c.CertPaths != "/etc/ssl/myapp" {
		t.Errorf("CertPaths = %q, want /etc/ssl/myapp", c.CertPaths)
	}
	if c.CertCA != "/etc/ssl/myapp/ca.pem" {
		t.Errorf("CertCA = %q, want /etc/ssl/myapp/ca.pem", c.CertCA)
	}
}

func TestCertCADefaultsEmpty(t *testing.T) {
	clearPartout(t)
	c, err := Load()
	if err != nil {
		t.Fatalf("Load(): %v", err)
	}
	if c.CertCA != "" {
		t.Errorf("CertCA = %q, want empty (resolved at collection time)", c.CertCA)
	}
}

func TestObserveFactsIntervalInvalidFallsBack(t *testing.T) {
	clearPartout(t)
	setenv(t, "PARTOUT_OBSERVE_FACTS_INTERVAL", "not-a-number")
	c, err := Load()
	if err != nil {
		t.Fatalf("Load(): %v", err)
	}
	if c.ObserveFactsInterval != 300 {
		t.Errorf("ObserveFactsInterval = %d, want default 300 for invalid input", c.ObserveFactsInterval)
	}
}

func TestAllowUnsignedReleasesDefault(t *testing.T) {
	// Unset → beta default true (checksum + version-stamp rollouts).
	t.Setenv("PARTOUT_ALLOW_UNSIGNED_RELEASES", "")
	os.Unsetenv("PARTOUT_ALLOW_UNSIGNED_RELEASES")
	c, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !c.AllowUnsignedReleases {
		t.Error("unset env: want beta default true (unsigned accepted)")
	}

	// Explicit off → false (opt back into signed-only before 1.0).
	t.Setenv("PARTOUT_ALLOW_UNSIGNED_RELEASES", "false")
	c, err = Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if c.AllowUnsignedReleases {
		t.Error("env=false: want false")
	}

	// Explicit off → false.
	t.Setenv("PARTOUT_ALLOW_UNSIGNED_RELEASES", "false")
	c, err = Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if c.AllowUnsignedReleases {
		t.Error("env=false: want false")
	}
}

func TestAutoDraftRolloutsBetaDefault(t *testing.T) {
	// Unset → default true (the pre-armed reminder is the beta posture).
	os.Unsetenv("PARTOUT_AUTO_DRAFT_ROLLOUTS")
	c, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !c.AutoDraftRollouts {
		t.Error("unset env: want default true")
	}

	// Explicit off → false.
	t.Setenv("PARTOUT_AUTO_DRAFT_ROLLOUTS", "false")
	c, err = Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if c.AutoDraftRollouts {
		t.Error("explicit false: want false")
	}
}

// TestDefaultServerHostStripsPort: the provisioner appends its own listener
// port to PARTOUT_SERVER_HOST, so an explicit ":port" in the value used to
// yield "host:8443:8443" agent addresses. The helper must strip it (and
// leave bare IPv6 literals alone).
func TestDefaultServerHostStripsPort(t *testing.T) {
	cases := map[string]string{
		"myhost:8443":      "myhost",
		"[::1]:8443":       "::1",
		"203.0.113.7:9443": "203.0.113.7",
		"myhost":           "myhost",
		"203.0.113.7":      "203.0.113.7",
		"2001:db8::1":      "2001:db8::1", // no brackets: does not split
	}
	for in, want := range cases {
		t.Setenv("PARTOUT_SERVER_HOST", in)
		if got := DefaultServerHost(); got != want {
			t.Errorf("DefaultServerHost(%q) = %q, want %q", in, got, want)
		}
	}
}
