package config

import (
	"os"
	"testing"
)

func TestDefaults(t *testing.T) {
	c, err := Load()
	if err != nil {
		t.Fatalf("Load(): %v", err)
	}
	if c.Mode != "" {
		t.Errorf("mode = %q, want empty", c.Mode)
	}
	if c.Addr != ":8443" {
		t.Errorf("addr = %q, want :8443", c.Addr)
	}
	if c.DataDir != "/var/lib/partout/server" {
		t.Errorf("data dir = %q, want /var/lib/partout/server", c.DataDir)
	}
	if c.DB != "sqlite:partout.db" {
		t.Errorf("db = %q, want sqlite:partout.db", c.DB)
	}
	if c.SPOOL.Mem != 16 {
		t.Errorf("spool mem = %d, want 16", c.SPOOL.Mem)
	}
	if c.SPOOL.Disk != 128 {
		t.Errorf("spool disk = %d, want 128", c.SPOOL.Disk)
	}
	if c.SPOOL.Age != 86400 {
		t.Errorf("spool age = %d, want 86400", c.SPOOL.Age)
	}
	if c.RetentionOutput != 30 {
		t.Errorf("retention output = %d, want 30", c.RetentionOutput)
	}
	if c.LogLevel != "info" {
		t.Errorf("log level = %q, want info", c.LogLevel)
	}
	if c.MCPEnabled != true {
		t.Errorf("MCP enabled = %v, want true", c.MCPEnabled)
	}
}

func TestServerValid(t *testing.T) {
	os.Unsetenv("PARTOUT_MODE")
	os.Setenv("PARTOUT_MODE", "server")
	defer os.Unsetenv("PARTOUT_MODE")
	c, err := Load()
	if err != nil {
		t.Fatalf("Load(): %v", err)
	}
	if c.Mode != "server" {
		t.Errorf("mode = %q, want server", c.Mode)
	}
}

func TestAgentMissingServer(t *testing.T) {
	os.Unsetenv("PARTOUT_MODE")
	os.Setenv("PARTOUT_MODE", "agent")
	os.Unsetenv("PARTOUT_SERVER")
	defer os.Unsetenv("PARTOUT_MODE")
	_, err := Load()
	if err == nil {
		t.Fatal("expected error for missing PARTOUT_SERVER")
	}
}

func TestAgentValid(t *testing.T) {
	os.Unsetenv("PARTOUT_MODE")
	os.Setenv("PARTOUT_MODE", "agent")
	os.Setenv("PARTOUT_SERVER", "https://server.local:8443")
	os.Unsetenv("PARTOUT_TOKEN")
	defer os.Unsetenv("PARTOUT_MODE")
	defer os.Unsetenv("PARTOUT_SERVER")
	c, err := Load()
	if err != nil {
		t.Fatalf("Load(): %v", err)
	}
	if c.ServerURL != "https://server.local:8443" {
		t.Errorf("server = %q", c.ServerURL)
	}
	if c.Token != "" {
		t.Errorf("token should be empty (not provided)")
	}
}

func TestInvalidMode(t *testing.T) {
	os.Unsetenv("PARTOUT_MODE")
	os.Setenv("PARTOUT_MODE", "foobar")
	defer os.Unsetenv("PARTOUT_MODE")
	_, err := Load()
	if err == nil {
		t.Fatal("expected error for invalid mode")
	}
}

func TestEnvOverrides(t *testing.T) {
	os.Unsetenv("PARTOUT_MODE")
	os.Unsetenv("PARTOUT_ADDR")
	os.Unsetenv("PARTOUT_LOG_LEVEL")
	os.Unsetenv("PARTOUT_RETENTION_OUTPUT_DAYS")
	os.Unsetenv("PARTOUT_SPOOL_")
	os.Setenv("PARTOUT_MODE", "server")
	os.Setenv("PARTOUT_ADDR", ":9443")
	os.Setenv("PARTOUT_LOG_LEVEL", "debug")
	os.Setenv("PARTOUT_RETENTION_OUTPUT_DAYS", "60")
	os.Setenv("PARTOUT_SPOOL_MEM_MB", "32")
	defer func() {
		os.Unsetenv("PARTOUT_MODE")
		os.Unsetenv("PARTOUT_ADDR")
		os.Unsetenv("PARTOUT_LOG_LEVEL")
		os.Unsetenv("PARTOUT_RETENTION_OUTPUT_DAYS")
		os.Unsetenv("PARTOUT_SPOOL_MEM_MB")
	}()
	c, err := Load()
	if err != nil {
		t.Fatalf("Load(): %v", err)
	}
	if c.Addr != ":9443" {
		t.Errorf("addr = %q, want :9443", c.Addr)
	}
	if c.LogLevel != "debug" {
		t.Errorf("log level = %q, want debug", c.LogLevel)
	}
	if c.RetentionOutput != 60 {
		t.Errorf("retention output = %d, want 60", c.RetentionOutput)
	}
}

func TestInvalidElevate(t *testing.T) {
	os.Unsetenv("PARTOUT_MODE")
	os.Setenv("PARTOUT_MODE", "agent")
	os.Setenv("PARTOUT_SERVER", "https://x")
	os.Setenv("PARTOUT_ELEVATE", "rootful")
	defer func() {
		os.Unsetenv("PARTOUT_MODE")
		os.Unsetenv("PARTOUT_SERVER")
		os.Unsetenv("PARTOUT_ELEVATE")
	}()
	_, err := Load()
	if err == nil {
		t.Fatal("expected error for invalid elevate")
	}
}

func TestEmbedded(t *testing.T) {
	os.Unsetenv("PARTOUT_MODE")
	os.Setenv("PARTOUT_MODE", "embedded")
	os.Unsetenv("PARTOUT_SERVER")
	defer os.Unsetenv("PARTOUT_MODE")
	c, err := Load()
	if err != nil {
		t.Fatalf("Load(): %v", err)
	}
	if c.Mode != "embedded" {
		t.Errorf("mode = %q, want embedded", c.Mode)
	}
	// ServerURL may be empty for embedded.
}
