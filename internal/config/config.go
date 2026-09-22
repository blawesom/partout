// Package config parses environment variables and CLI flags to produce a
// validated configuration for the server, agent, or embedded mode.
// All configuration is via env vars (PRD R15); flags override env.
//
// Defaults are the proposed defaults from the architecture document §15.
package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// Config holds the complete Partout configuration.
type Config struct {
	Mode string // "server", "agent", "embedded"

	// ---- server only (populated when Mode == "server") ----
	Addr                               string // ":8443"
	TLSCert, TLSKey                    string
	H2C                                bool
	DataDir                            string
	DB                                 string
	SecretKeyFile, SecretKey           string
	DisableExternalData                bool
	RetentionOutput, RetentionSessions int
	RetentionRuns, RetentionFacts      int
	MaxOutputMB, MaxTransferMB         int
	MaxConcurrentRunsPerHost           int
	DispatchTTL, PolicyStaleness       int
	MCPEnabled                         bool

	// RBAC bearer tokens (PRD R10; local users, no OIDC in v1). When none are
	// set the server runs in single-user local mode (all requests allowed).
	AdminToken, OperatorToken, ViewerToken string
	SPOOL

	// ---- agent only (populated when Mode == "agent") ----
	ServerURL     string
	Token         string
	Elevate       string
	Root          string
	FactsInterval int
	SSHPDir       string

	// mTLS material (agent mode). All empty = plaintext h2c. The agent
	// persists these under <DataDir>/tls/ after a TLS enrollment.
	TLSCAFile, TLSCertFile, TLSKeyFile string

	// ---- common ----
	LogLevel string
}

// SPOOL holds spool capacity limits.
type SPOOL struct {
	Mem  int // 16 MB
	Disk int // 128 MB
	Age  int // 86400 (24h)
}

// Load reads env vars, applies defaults, and validates. Returns an error
// if the config is invalid.
func Load() (*Config, error) {
	c := &Config{
		// Defaults (proposed — architecture §15).
		Mode:     strings.ToLower(os.Getenv("PARTOUT_MODE")),
		LogLevel: getEnv("PARTOUT_LOG_LEVEL", "info"),
		DataDir:  getEnv("PARTOUT_DATA_DIR", "/var/lib/partout/server"),
		DB:       getEnv("PARTOUT_DB", "sqlite:partout.db"),
		Addr:     getEnv("PARTOUT_ADDR", ":8443"),
		SSHPDir:  getEnv("PARTOUT_SSH_DIR", getDefaultSSHDir()),
		SPOOL: SPOOL{
			Mem:  getEnvInt("PARTOUT_SPOOL_MEM_MB", 16),
			Disk: getEnvInt("PARTOUT_SPOOL_DISK_MB", 128),
			Age:  getEnvInt("PARTOUT_SPOOL_AGE_S", 86400),
		},
		// Server defaults.
		RetentionOutput:          getEnvInt("PARTOUT_RETENTION_OUTPUT_DAYS", 30),
		RetentionSessions:        getEnvInt("PARTOUT_RETENTION_SESSIONS_DAYS", 30),
		RetentionRuns:            getEnvInt("PARTOUT_RETENTION_RUNS_DAYS", 90),
		RetentionFacts:           getEnvInt("PARTOUT_RETENTION_FACTS_DAYS", 90),
		MaxOutputMB:              getEnvInt("PARTOUT_MAX_OUTPUT_MB", 16),
		MaxTransferMB:            getEnvInt("PARTOUT_MAX_TRANSFER_MB", 256),
		MaxConcurrentRunsPerHost: getEnvInt("PARTOUT_MAX_CONCURRENT_RUNS_PER_HOST", 4),
		DispatchTTL:              getEnvInt("PARTOUT_DISPATCH_TTL_S", 900),
		PolicyStaleness:          getEnvInt("PARTOUT_POLICY_STALE_S", 172800),
		MCPEnabled:               getEnvBool("PARTOUT_MCP_ENABLED", true),
		DisableExternalData:      getEnvBool("PARTOUT_DISABLE_EXTERNAL_DATA_REFRESH", false),
		AdminToken:               os.Getenv("PARTOUT_TOKEN_ADMIN"),
		OperatorToken:            os.Getenv("PARTOUT_TOKEN_OPERATOR"),
		ViewerToken:              os.Getenv("PARTOUT_TOKEN_VIEWER"),
		// Agent defaults.
		Elevate:       getEnv("PARTOUT_ELEVATE", "none"),
		Root:          getEnv("PARTOUT_ROOT", "/"),
		FactsInterval: getEnvInt("PARTOUT_FACTS_INTERVAL", 3600),
	}

	// Secrets.
	c.SecretKeyFile = os.Getenv("PARTOUT_SECRET_KEY_FILE")
	c.SecretKey = os.Getenv("PARTOUT_SECRET_KEY")

	// TLS.
	c.TLSCert = os.Getenv("PARTOUT_TLS_CERT")
	c.TLSKey = os.Getenv("PARTOUT_TLS_KEY")
	c.H2C = getEnvBool("PARTOUT_H2C", false)

	// Agent-only envs.
	c.ServerURL = os.Getenv("PARTOUT_SERVER")
	c.Token = os.Getenv("PARTOUT_TOKEN")

	if err := c.Validate(); err != nil {
		return nil, err
	}
	return c, nil
}

// Validate checks invariants and returns an error if the config is invalid.
func (c *Config) Validate() error {
	switch c.Mode {
	case "server":
		return c.validateServer()
	case "agent":
		return c.validateAgent()
	case "embedded":
		return c.validateEmbedded()
	case "":
		return nil // un-set; set before use (main() dispatches)
	default:
		return fmt.Errorf("config: invalid mode %q (want server|agent|embedded)", c.Mode)
	}
}

func (c *Config) validateServer() error {
	if c.SPOOL.Mem <= 0 || c.SPOOL.Disk <= 0 || c.SPOOL.Age <= 0 {
		return fmt.Errorf("config: SPOOL values must be positive")
	}
	return nil
}

func (c *Config) validateAgent() error {
	if c.ServerURL == "" {
		return fmt.Errorf("config: PARTOUT_SERVER required for agent mode")
	}
	if c.SPOOL.Mem <= 0 || c.SPOOL.Disk <= 0 || c.SPOOL.Age <= 0 {
		return fmt.Errorf("config: SPOOL values must be positive")
	}
	switch c.Elevate {
	case "none", "sudoers", "sudo":
		// ok
	default:
		return fmt.Errorf("config: PARTOUT_ELEVATE must be none|sudoers|sudo")
	}
	return nil
}

func (c *Config) validateEmbedded() error {
	// Embedded = server + agent on one box; both sets of constraints apply.
	if err := c.validateServer(); err != nil {
		return err
	}
	// ServerURL is allowed to be empty for embedded.
	return nil
}

// DefaultSSHDir returns the OS-specific default SSH directory for the
// current user. For the server service user, this is typically $HOME/.ssh.
func getDefaultSSHDir() string {
	h, err := os.UserHomeDir()
	if err != nil {
		return ".ssh"
	}
	return filepath.Join(h, ".ssh")
}

// Helper functions.
func getEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func getEnvInt(key string, fallback int) int {
	s := os.Getenv(key)
	if s == "" {
		return fallback
	}
	v, err := strconv.Atoi(s)
	if err != nil {
		return fallback
	}
	return v
}

func getEnvBool(key string, fallback bool) bool {
	s := os.Getenv(key)
	if s == "" {
		return fallback
	}
	return s == "true" || s == "1"
}
