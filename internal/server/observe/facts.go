// Package observe provides server-side fact ingestion for the observe layer
// (M5, R18–R20). The agent uploads structured facts as JSON blobs via the
// OBSERVE_FACTS gRPC envelope. The server upserts them into the host_facts
// JSON blob alongside the flat FactsBatch (architecture §7.3).

package observe

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/blawesom/partout/internal/proto"
)

// Kind identifies the observation domain.
type Kind string

const (
	KindServices Kind = "services"
	KindConfigs  Kind = "configs"
	KindCerts    Kind = "certs"
)

// Facts is the top-level facts blob the server stores as a key in host_facts.
// Each observation domain uses the same envelope with a different `kind` label.
type Facts struct {
	ServicesDetailed *ServiceFacts `json:"services_detailed,omitempty"` // R18
	Configs          *ConfigFacts  `json:"configs,omitempty"`           // R19
	Certificates     *CertFacts    `json:"certificates,omitempty"`      // R20
}

// ServiceFacts carries systemd unit facts for the server to aggregate and
// alert on (PRD §5.1, arch §7.2).
type ServiceFacts struct {
	Units []UnitFact `json:"units"`
}

// UnitFact is one systemd unit's state, dependencies, enablement, and labels.
type UnitFact struct {
	Name           string   `json:"name"`
	Type           string   `json:"type"`
	State          string   `json:"state"`
	SubState       string   `json:"sub_state"`
	Enabled        bool     `json:"enabled"`
	WantedBy       []string `json:"wanted_by,omitempty"`
	RequiredBy     []string `json:"required_by,omitempty"`
	After          []string `json:"after,omitempty"`
	RestartPolicy  string   `json:"restart_policy,omitempty"`
	MemoryCurrent  uint64   `json:"memory_current,omitempty"`
	CPUUsageSec    string   `json:"cpu_usage_sec,omitempty"`
	LastExitCode   int      `json:"last_exit_code,omitempty"`
	LastExitStatus string   `json:"last_exit_status,omitempty"`
	Labels         []string `json:"labels,omitempty"`
}

// ConfigFacts carries webservice config facts (haproxy, nginx).
type ConfigFacts struct {
	HAProxy *HAProxyConfig `json:"haproxy,omitempty"`
	Nginx   *NginxConfig   `json:"nginx,omitempty"`
}

// HAProxyConfig is haproxy's config fact set.
type HAProxyConfig struct {
	Present      bool            `json:"present"`
	Version      string          `json:"version"`
	ConfigFile   string          `json:"config_file"`
	ConfigSHA256 string          `json:"config_sha256"`
	ConfigValid  bool            `json:"config_valid"`
	Backends     []BackendFact   `json:"backends"`
	Listeners    []ListenerFact  `json:"listeners"`
}

// NginxConfig is nginx's config fact set.
type NginxConfig struct {
	Present      bool        `json:"present"`
	Version      string      `json:"version"`
	ConfigFile   string      `json:"config_file"`
	ConfigSHA256 string      `json:"config_sha256"`
	ConfigValid  bool        `json:"config_valid"`
	Vhosts       []VHostFact `json:"vhosts"`
}

// BackendFact is one haproxy backend's server state.
type BackendFact struct {
	Name    string `json:"name"`
	Servers int64  `json:"servers"`
	Active  int64  `json:"active"`
}

// ListenerFact is one haproxy frontend/listener.
type ListenerFact struct {
	Port int    `json:"port"`
	Mode string `json:"mode"` // http or https
	TLS  string `json:"tls"`  // cert path if TLS
}

// VHostFact is one nginx virtual host.
type VHostFact struct {
	ServerName string `json:"server_name"`
	Port       int    `json:"port"`
	TLS        bool   `json:"tls"`
	TLSCert    string `json:"tls_cert"`
	Root       string `json:"root"`
	Upstream   string `json:"upstream"`
}

// CertFacts carries TLS certificate facts.
type CertFacts struct {
	Items []CertFact `json:"items"`
}

// CertFact is one certificate's details (arch §7.2).
type CertFact struct {
	Path          string   `json:"path"`
	Subject       string   `json:"subject"`
	Issuer        string   `json:"issuer"`
	Serial        string   `json:"serial"`
	NotBefore     int64    `json:"not_before"` // epoch
	NotAfter      int64    `json:"not_after"`  // epoch
	DaysRemaining int64    `json:"days_remaining"`
	KeyType       string   `json:"key_type"`
	SANs          []string `json:"san"`
	ChainValid    bool     `json:"chain_valid"`
	ChainLength   int      `json:"chain_length"`
	SelfSigned    bool     `json:"self_signed"`
	OCSPStapling  bool     `json:"ocsp_stapling"`
	OCSPStatus    string   `json:"ocsp_status"`
	Labels        []string `json:"labels,omitempty"`
}

// Ingest parses an ObserveFacts envelope and merges it into the host_facts
// JSON blob. Returns the new facts blob (as JSON string) for the caller to
// upsert.
func Ingest(factsBlob string, env *proto.ObserveFacts) (string, error) {
	if env == nil {
		return factsBlob, nil
	}
	// Parse existing blob
	var facts Facts
	if factsBlob != "" {
		if err := json.Unmarshal([]byte(factsBlob), &facts); err != nil {
			return "", fmt.Errorf("parse host_facts: %w", err)
		}
	}
	// Merge incoming facts
	if err := json.Unmarshal([]byte(env.GetJson()), &facts); err != nil {
		return "", fmt.Errorf("parse observe facts kind %q: %w", env.GetKind(), err)
	}
	// Serialize back
	out, err := json.Marshal(&facts)
	if err != nil {
		return "", fmt.Errorf("marshal merged facts: %w", err)
	}
	return string(out), nil
}

// Timestamp returns the server-side ingestion timestamp.
func Timestamp() time.Time {
	return time.Now()
}
