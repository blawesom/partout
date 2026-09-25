// Package observe provides typed views over the structured observe facts
// stored in the host_facts JSON document (M5, R18–R20; architecture §7).
//
// Storage: the agent uploads one OBSERVE_FACTS envelope per domain
// (services, configs, certs); the stream handler merges each domain into the
// host's single host_facts JSON document (store.UpsertHostFactsJSON), which
// also carries the flat fact keys. This package parses that document into
// the typed structs the REST API and (M6) alert engine consume.

package observe

import "encoding/json"

// Domain keys inside the host_facts JSON document.
const (
	KeyServices = "services_detailed"
	KeyConfigs  = "configs"
	KeyCerts    = "certificates"
)

// Document is the full host_facts document (flat keys + structured
// observe facts).
type Document struct {
	// Flat carries the scalar fact keys (host.*, partout.*, runtime.*).
	Flat map[string]string `json:"-"`
	// Structured carries the observe fact objects by domain key.
	Structured map[string]json.RawMessage `json:"-"`
}

// ParseDocument splits a host_facts JSON document into its flat (string)
// and structured (object) parts.
func ParseDocument(blob string) (*Document, error) {
	doc := &Document{Flat: make(map[string]string), Structured: make(map[string]json.RawMessage)}
	if blob == "" {
		return doc, nil
	}
	var raw map[string]any
	if err := json.Unmarshal([]byte(blob), &raw); err != nil {
		return nil, err
	}
	for k, v := range raw {
		if s, ok := v.(string); ok {
			doc.Flat[k] = s
			continue
		}
		b, err := json.Marshal(v)
		if err != nil {
			return nil, err
		}
		doc.Structured[k] = b
	}
	return doc, nil
}

// Services returns the services domain (R18), or nil when absent.
func (d *Document) Services() *ServiceFacts {
	b, ok := d.Structured[KeyServices]
	if !ok {
		return nil
	}
	var f ServiceFacts
	if err := json.Unmarshal(b, &f); err != nil {
		return nil
	}
	return &f
}

// Configs returns the configs domain (R19), or nil when absent.
func (d *Document) Configs() *ConfigFacts {
	b, ok := d.Structured[KeyConfigs]
	if !ok {
		return nil
	}
	var f ConfigFacts
	if err := json.Unmarshal(b, &f); err != nil {
		return nil
	}
	return &f
}

// Certificates returns the certs domain (R20), or nil when absent.
func (d *Document) Certificates() *CertFacts {
	b, ok := d.Structured[KeyCerts]
	if !ok {
		return nil
	}
	var f CertFacts
	if err := json.Unmarshal(b, &f); err != nil {
		return nil
	}
	return &f
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
	Present      bool           `json:"present"`
	Version      string         `json:"version"`
	ConfigFile   string         `json:"config_file"`
	ConfigSHA256 string         `json:"config_sha256"`
	ConfigValid  bool           `json:"config_valid"`
	Backends     []BackendFact  `json:"backends"`
	Listeners    []ListenerFact `json:"listeners"`
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
