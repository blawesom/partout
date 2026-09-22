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
		"PARTOUT_TLS_CA",
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
