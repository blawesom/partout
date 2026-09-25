// Package observe provides typed views over the structured observe facts
// stored in the host_facts JSON document (M5, R18–R20; architecture §7).
//
// Storage: the agent uploads one OBSERVE_FACTS envelope per domain
// (services, configs, certs); the stream handler merges each domain into the
// host's single host_facts JSON document (store.UpsertHostFactsJSON), which
// also carries the flat fact keys. This package parses that document into
// the typed structs the REST API and (M6) alert engine consume.

package observe

import (
	"bytes"
	"encoding/json"
)

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
//
// Classification: a JSON string becomes a flat fact; a JSON null is treated
// as absent (it carries no information and must not make a domain look
// present); every other JSON value (object/array/number/bool) is preserved
// verbatim as a structured value. Non-object structured values are kept so
// they can be inspected, but the typed accessors reject them.
func ParseDocument(blob string) (*Document, error) {
	doc := &Document{Flat: make(map[string]string), Structured: make(map[string]json.RawMessage)}
	if blob == "" {
		return doc, nil
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal([]byte(blob), &raw); err != nil {
		return nil, err
	}
	for k, v := range raw {
		trimmed := bytes.TrimSpace(v)
		if len(trimmed) == 0 || string(trimmed) == "null" {
			continue // absent
		}
		if trimmed[0] == '"' {
			var s string
			if err := json.Unmarshal(trimmed, &s); err != nil {
				return nil, err
			}
			doc.Flat[k] = s
			continue
		}
		doc.Structured[k] = append(json.RawMessage(nil), trimmed...)
	}
	return doc, nil
}

// Services returns the services domain (R18), or nil when absent or not a
// JSON object.
func (d *Document) Services() *ServiceFacts {
	b, ok := d.domain(KeyServices)
	if !ok {
		return nil
	}
	var f ServiceFacts
	if err := json.Unmarshal(b, &f); err != nil {
		return nil
	}
	return &f
}

// Configs returns the configs domain (R19), or nil when absent or not a
// JSON object.
func (d *Document) Configs() *ConfigFacts {
	b, ok := d.domain(KeyConfigs)
	if !ok {
		return nil
	}
	var f ConfigFacts
	if err := json.Unmarshal(b, &f); err != nil {
		return nil
	}
	return &f
}

// Certificates returns the certs domain (R20), or nil when absent or not a
// JSON object.
func (d *Document) Certificates() *CertFacts {
	b, ok := d.domain(KeyCerts)
	if !ok {
		return nil
	}
	var f CertFacts
	if err := json.Unmarshal(b, &f); err != nil {
		return nil
	}
	return &f
}

// domain fetches a structured value and reports whether it is a JSON object
// (the only shape the typed accessors accept).
func (d *Document) domain(key string) (json.RawMessage, bool) {
	b, ok := d.Structured[key]
	if !ok {
		return nil, false
	}
	trimmed := bytes.TrimSpace(b)
	if len(trimmed) == 0 || trimmed[0] != '{' {
		return nil, false
	}
	return b, true
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
	NotBefore     int64    `json:"not_before"` // epoch; 0 = unknown
	NotAfter      int64    `json:"not_after"`  // epoch; 0 = unknown
	DaysRemaining int64    `json:"days_remaining"`
	KeyType       string   `json:"key_type"`
	SANs          []string `json:"san"`
	ChainChecked  bool     `json:"chain_checked"`
	ChainValid    bool     `json:"chain_valid"`
	ChainLength   int      `json:"chain_length"`
	SelfSigned    bool     `json:"self_signed"`
	OCSPStapling  bool     `json:"ocsp_stapling"`
	OCSPStatus    string   `json:"ocsp_status"`
	Labels        []string `json:"labels,omitempty"`
}
