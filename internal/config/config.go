// Package config holds the validated runtime configuration for the Partout
// binary.
//
// Single source of truth: cmd/partout calls Load() (env vars + defaults) and
// CLI flags override the loaded values, so precedence is flag > env > default.
//
// Scope: only the settings the v0.1 binary actually enforces. The wider
// surface (retention, spool, MCP, H2C, secret key, SSH provisioning dir, log
// level, split gRPC listener, elevation) is planned — see
// docs/deployment.md §4 "Planned, not wired yet" — and intentionally not
// parsed here: an env var that is documented but never read is a false
// promise. Add a variable here only when its feature lands.
package config

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
)

// Config is the validated runtime configuration for one process.
type Config struct {
	// Mode: server | agent | embedded.
	Mode string

	// ---- Server ----
	// Port is the single listener port (REST v1 + SSE + gRPC, demuxed by
	// protocol/content-type).
	Port int
	// Addr is the bind address for the single listener (PARTOUT_ADDR /
	// --addr). Empty = all interfaces ("0.0.0.0"); set "127.0.0.1" to bind
	// loopback-only when the server sits behind a reverse proxy on the same
	// host (the recommended deployment, see docs/deployment.md).
	Addr string
	// DBPath is the SQLite database path (server data set).
	DBPath string
	// DataDir: agent — identity, TLS material, policy dir (used).
	// server — reserved (output blobs, extern cache; M1+).
	DataDir string
	// TLS enables server-native TLS with local root-CA bootstrap
	// (PARTOUT_TLS=on / --tls=on).
	TLS bool
	// TLSNames: comma-separated SANs for the server leaf cert.
	// Empty → default localhost,127.0.0.1,hostname.
	TLSNames string
	// RBAC bearer tokens; when none are set the server runs in single-user
	// local mode (no auth).
	AdminToken, OperatorToken, ViewerToken string
	AdminPassword                          string // first-run admin bootstrap (PARTOUT_ADMIN_PASSWORD)

	// ---- Agent ----
	ServerURL     string // server host:port (gRPC + REST, single port)
	Token         string // one-time enrollment token (first boot)
	FactsInterval int    // facts refresh, seconds
	// ForceEnroll makes the agent enroll even when a local identity already
	// exists. Used by embedded mode when the co-located server's database is
	// fresh (no agents): the persisted identity is stale for this server, so
	// the agent must (re-)enroll rather than loop on "unknown agent uuid".
	ForceEnroll bool
	// ObserveFactsInterval: structured fact upload cadence, seconds (M5, R18–R20).
	ObserveFactsInterval int
	// ServiceLabels: comma-separated operator labels marking custom units (M5, R18).
	ServiceLabels string
	// CertPaths: comma-separated TLS cert discovery paths, in addition to the
	// defaults /etc/ssl and /etc/pki/tls (M5, R20).
	CertPaths string
	// CertCA: trust bundle used to verify certificate chains (M5, R20).
	// Empty = resolve from the standard system locations.
	CertCA string
	// --- M8.1 updates (agent side) ---
	// ReleaseKey is the base64 Ed25519 release public key this agent trusts
	// for self-update artifacts (PARTOUT_RELEASE_KEY). A locally provisioned
	// key always wins over anything server-delivered; with none set the agent
	// refuses every update directive (fails closed).
	ReleaseKey string
	// AllowUnsignedReleases is the server-side beta policy for M8.1
	// (PARTOUT_ALLOW_UNSIGNED_RELEASES): when true, the release store accepts
	// releases WITHOUT a signature and keyless agents may apply them. Beta
	// default is TRUE; at GA the default flips to false (signed-only).
	// A release that carries a signature is always verified regardless.
	AllowUnsignedReleases bool
	// UpdateHealthS is the post-swap health window in seconds
	// (PARTOUT_UPDATE_HEALTH_S): the new version must boot and connect within
	// it or the boot guard rolls back to N-1.
	UpdateHealthS int
	// UpdateRestartCmd is executed after a successful binary swap
	// (PARTOUT_UPDATE_RESTART_CMD); default is the systemd unit restart.
	UpdateRestartCmd string
	// TLSCAFile: path to the server root CA (PEM); enables HTTPS
	// enrollment + mTLS stream.
	TLSCAFile string
	// TLSCertFile/TLSKeyFile: the agent's CA-signed leaf + private key.
	// Persisted after a TLS enrollment, reloaded on later starts.
	TLSCertFile, TLSKeyFile string

	// ---- Reserved (elevation, M1+) ----
	// Elevate/Root are part of the agent's runtime contract but elevation
	// is not implemented yet; main.go hardcodes "none"/"/" until it lands.
	// Not parsed from the environment on purpose.
	Elevate, Root string
}

// Load reads configuration from the environment and returns the validated
// result. PARTOUT_MODE unset defaults to "server" (the --mode default).
func Load() (*Config, error) {
	mode := strings.ToLower(strings.TrimSpace(os.Getenv("PARTOUT_MODE")))
	if mode == "" {
		mode = "server"
	}
	c := &Config{
		Mode:                  mode,
		Port:                  envInt("PARTOUT_PORT", 8443),
		Addr:                  os.Getenv("PARTOUT_ADDR"),
		DBPath:                envStr("PARTOUT_DB_PATH", "./partout.db"),
		DataDir:               os.Getenv("PARTOUT_DATA_DIR"),
		TLS:                   envBool("PARTOUT_TLS"),
		TLSNames:              os.Getenv("PARTOUT_TLS_SERVER_NAMES"),
		AdminToken:            os.Getenv("PARTOUT_TOKEN_ADMIN"),
		OperatorToken:         os.Getenv("PARTOUT_TOKEN_OPERATOR"),
		ViewerToken:           os.Getenv("PARTOUT_TOKEN_VIEWER"),
		AdminPassword:         os.Getenv("PARTOUT_ADMIN_PASSWORD"),
		ServerURL:             os.Getenv("PARTOUT_SERVER"),
		Token:                 os.Getenv("PARTOUT_TOKEN"),
		FactsInterval:         envInt("PARTOUT_FACTS_INTERVAL", 3600),
		ObserveFactsInterval:  envInt("PARTOUT_OBSERVE_FACTS_INTERVAL", 300),
		ServiceLabels:         os.Getenv("PARTOUT_SERVICE_LABELS"),
		CertPaths:             os.Getenv("PARTOUT_CERT_PATHS"),
		CertCA:                os.Getenv("PARTOUT_CERT_CA"),
		TLSCAFile:             os.Getenv("PARTOUT_TLS_CA"),
		ReleaseKey:            os.Getenv("PARTOUT_RELEASE_KEY"),
		AllowUnsignedReleases: envBoolDefaultTrue("PARTOUT_ALLOW_UNSIGNED_RELEASES"),
		UpdateHealthS:         envInt("PARTOUT_UPDATE_HEALTH_S", 60),
		UpdateRestartCmd:      envOrStr("PARTOUT_UPDATE_RESTART_CMD", "systemctl restart partout-agent"),
	}
	if err := c.Validate(); err != nil {
		return nil, err
	}
	return c, nil
}

// Validate checks mode-specific requirements.
func (c *Config) Validate() error {
	switch c.Mode {
	case "server", "embedded":
		// nothing mode-specific
	case "agent":
		if c.ServerURL == "" {
			return errors.New("agent mode requires PARTOUT_SERVER (or --server) to be set")
		}
	case "mcp":
		if c.ServerURL == "" {
			return errors.New("mcp mode requires PARTOUT_SERVER (or --server) to be set")
		}
		if c.Token == "" {
			return errors.New("mcp mode requires PARTOUT_TOKEN (or --token): the caller's bearer token (admin|operator|viewer or a session token from `ctl auth login`)")
		}
	default:
		return fmt.Errorf("invalid mode %q (want server|agent|embedded|mcp)", c.Mode)
	}
	return nil
}

func envStr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func envInt(key string, def int) int {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return def
}

// envOrStr returns the env var value, or def when unset/empty.
func envOrStr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

// envBool accepts on/true/1/yes as true; everything else (including unset
// and off/false/0/no) is false.
func envBool(key string) bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv(key))) {
	case "on", "true", "1", "yes":
		return true
	default:
		return false
	}
}

// envBoolDefaultTrue is envBool with a beta-period default: unset = true.
func envBoolDefaultTrue(key string) bool {
	if strings.TrimSpace(os.Getenv(key)) == "" {
		return true
	}
	return envBool(key)
}
