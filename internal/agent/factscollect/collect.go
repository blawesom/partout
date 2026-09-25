// Package factscollect implements structured fact collectors for the observe
// layer (M5, R18–R20). Collectors run on the agent and upload JSON blobs
// via the OBSERVE_FACTS gRPC envelope to the server, which upserts them into
// host_facts (architecture §7.2).
package factscollect

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// Kind identifies the observation domain.
type Kind string

const (
	KindServices Kind = "services"
	KindConfigs  Kind = "configs"
	KindCerts    Kind = "certs"
)

// Facts is the top-level facts blob the server stores as a key in host_facts.
type Facts struct {
	ServicesDetailed *ServiceFacts `json:"services_detailed,omitempty"` // R18
	Configs          *ConfigFacts  `json:"configs,omitempty"`           // R19
	Certificates     *CertFacts    `json:"certificates,omitempty"`      // R20
}

// Collect runs all collectors and returns the merged Facts blob, or nil if
// all collectors return empty (no structured facts to upload).
func Collect(cfg *Config) *Facts {
	if cfg == nil {
		cfg = &Config{}
	}
	f := &Facts{}
	if sf := collectServices(cfg); sf != nil {
		f.ServicesDetailed = sf
	}
	if cf := collectConfigs(cfg); cf != nil {
		f.Configs = cf
	}
	if ce := collectCerts(cfg); ce != nil {
		f.Certificates = ce
	}
	if f.ServicesDetailed == nil && f.Configs == nil && f.Certificates == nil {
		return nil
	}
	return f
}

// Config controls collector behaviour.
type Config struct {
	// ServiceLabels: comma-separated operator labels for custom unit
	// identification (PARTOUT_SERVICE_LABELS). Empty = units from
	// /etc/systemd/system/* are auto-marked as custom.
	ServiceLabels string
	// CertPaths: comma-separated paths for cert discovery, in addition to
	// defaults (/etc/ssl/, /etc/pki/tls/).
	CertPaths string
	// ObserveFactsInterval: seconds between uploads (PARTOUT_OBSERVE_FACTS_INTERVAL).
	ObserveFactsInterval int
}

// Fill returns a config with defaults filled in.
func (c *Config) Fill() *Config {
	if c == nil {
		c = &Config{}
	}
	if c.ObserveFactsInterval <= 0 {
		c.ObserveFactsInterval = 300
	}
	return c
}

// ---- Service facts (R18) ------------------------------------------------

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

// collectServices runs `systemctl list-units` + `systemctl show` to collect
// full unit state for custom units (PRD Decision 13: custom units only in
// output — units from /etc/systemd/system/* or labelled by operator).
//
// Refresh: 5 minutes (arch §7.2).
func collectServices(cfg *Config) *ServiceFacts {
	cfg = cfg.Fill()
	units, err := listUnits()
	if err != nil || len(units) == 0 {
		return nil
	}
	facts := &ServiceFacts{Units: make([]UnitFact, 0, len(units))}
	for _, u := range units {
		f := unitDetail(u)
		if isCustomUnit(u, cfg.ServiceLabels) {
			facts.Units = append(facts.Units, f)
		}
	}
	if len(facts.Units) == 0 {
		return nil
	}
	return facts
}

// listUnits runs systemctl list-units and returns unit names that are active,
// failed, or in a transitional state.
func listUnits() ([]string, error) {
	cmd := exec.Command("systemctl", "list-units", "--no-pager", "--no-legend",
		"--type=service", "--state=active", "--state=failed",
		"--state=activating", "--state=deactivating", "--state=auto-restarting")
	var out bytes.Buffer
	cmd.Stdout = &out
	if err := cmd.Run(); err != nil {
		return nil, err
	}
	var names []string
	for _, line := range strings.Split(strings.TrimSpace(out.String()), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 1 {
			continue
		}
		name := fields[0]
		// Strip .service suffix for consistency
		name = strings.TrimSuffix(name, ".service")
		names = append(names, name)
	}
	return names, nil
}

// unitDetail runs systemctl show for a unit and parses the key=value output.
func unitDetail(name string) UnitFact {
	f := UnitFact{Name: name}
	cmd := exec.Command("systemctl", "show", name,
		"--property=Type,State,SubState,ActiveState,UnitFileState,Requires,RequiredBy,Wants,WantedBy,After,Before,Restart,MemoryCurrent,CPUSec,RestartForceExitStatus,ExecMainStatus")
	var out bytes.Buffer
	cmd.Stdout = &out
	if err := cmd.Run(); err != nil {
		return f
	}
	for _, line := range strings.Split(strings.TrimSpace(out.String()), "\n") {
		line = strings.TrimSpace(line)
		kv := strings.SplitN(line, "=", 2)
		if len(kv) != 2 {
			continue
		}
		k, v := kv[0], kv[1]
		switch k {
		case "Type":
			f.Type = v
		case "State":
			f.State = v
		case "SubState":
			f.SubState = v
		case "UnitFileState":
			f.Enabled = v == "enabled" || v == "enabled-runtime" || v == "static"
		case "WantedBy":
			f.WantedBy = splitList(v)
		case "RequiredBy":
			f.RequiredBy = splitList(v)
		case "After":
			f.After = splitList(v)
		case "Restart":
			f.RestartPolicy = v
		case "MemoryCurrent":
			if n, err := parseUint64(v); err == nil {
				f.MemoryCurrent = n
			}
		case "CPUSec":
			f.CPUUsageSec = v
		case "RestartForceExitStatus":
			f.LastExitCode = parseExitCode(v)
		case "ExecMainStatus":
			f.LastExitCode = parseExitCode(v)
		}
	}
	return f
}

// isCustomUnit checks if a unit should be included in the custom unit set
// (PRD Decision 13). A unit is custom if:
// - It matches an operator-assigned label, OR
// - Its unit file is under /etc/systemd/system/* (not /lib/systemd/system/*)
func isCustomUnit(name, labels string) bool {
	// Check operator labels first
	if labels != "" {
		for _, l := range strings.Split(labels, ",") {
			l = strings.TrimSpace(l)
			if l != "" && l == name {
				return true
			}
		}
	}
	// Check if unit file is under /etc/systemd/system/*
	unitPath := fmt.Sprintf("/etc/systemd/system/%s.service", name)
	if _, err := os.Stat(unitPath); err == nil {
		return true
	}
	// Also check for .timer, .socket, etc.
	exts := []string{".service", ".timer", ".socket", ".target"}
	for _, ext := range exts {
		if _, err := os.Stat(fmt.Sprintf("/etc/systemd/system/%s%s", name, ext)); err == nil {
			return true
		}
	}
	return false
}

// ---- Config facts (R19) --------------------------------------------------

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

// collectConfigs runs haproxy -c and nginx -t for validation, and extracts
// topology from the config files (lightweight regex/line parsing).
// Refresh: 15 min or on file mtime change (arch §7.2).
func collectConfigs(cfg *Config) *ConfigFacts {
	cfg = cfg.Fill()
	f := &ConfigFacts{}
	if hf := collectHAProxy(cfg); hf != nil {
		f.HAProxy = hf
	}
	if nf := collectNginx(cfg); nf != nil {
		f.Nginx = nf
	}
	if f.HAProxy == nil && f.Nginx == nil {
		return nil
	}
	return f
}

// collectHAProxy runs haproxy -c for validation and parses topology.
func collectHAProxy(cfg *Config) *HAProxyConfig {
	if _, err := exec.LookPath("haproxy"); err != nil {
		return nil
	}
	cfgPath := "/etc/haproxy/haproxy.cfg"
	if _, err := os.Stat(cfgPath); err != nil {
		return nil
	}
	h := &HAProxyConfig{
		Present:    true,
		ConfigFile: cfgPath,
	}
	// Validate: haproxy -c
	cmd := exec.Command("haproxy", "-c", "-f", cfgPath)
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	if err := cmd.Run(); err == nil {
		h.ConfigValid = true
	} else {
		h.ConfigValid = false
		_ = out.String() // discard for now
	}
	// Version: haproxy -v
	cmd = exec.Command("haproxy", "-v")
	out.Reset()
	cmd.Stdout = &out
	cmd.Stderr = &out
	if err := cmd.Run(); err == nil {
		h.Version = extractVersion(out.String())
	}
	// Config SHA256
	if sha, err := fileSHA256(cfgPath); err == nil {
		h.ConfigSHA256 = sha
	}
	// Topology: lightweight parsing
	h.Backends, h.Listeners = parseHAProxyTopology(cfgPath)
	return h
}

// collectNginx runs nginx -t for validation and extracts vhost topology.
func collectNginx(cfg *Config) *NginxConfig {
	if _, err := exec.LookPath("nginx"); err != nil {
		return nil
	}
	cfgPath := "/etc/nginx/nginx.conf"
	if _, err := os.Stat(cfgPath); err != nil {
		return nil
	}
	n := &NginxConfig{
		Present:    true,
		ConfigFile: cfgPath,
	}
	// Validate: nginx -t
	cmd := exec.Command("nginx", "-t")
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	if err := cmd.Run(); err == nil {
		n.ConfigValid = true
	} else {
		n.ConfigValid = false
	}
	// Version: nginx -v
	cmd = exec.Command("nginx", "-v")
	out.Reset()
	cmd.Stderr = &out
	cmd.Stdout = &out
	if err := cmd.Run(); err == nil {
		n.Version = extractVersion(out.String())
	}
	// Config SHA256
	if sha, err := fileSHA256(cfgPath); err == nil {
		n.ConfigSHA256 = sha
	}
	// Topology: lightweight parsing
	n.Vhosts = parseNginxVhosts(cfgPath)
	return n
}

// ---- Cert facts (R20) ----------------------------------------------------

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

// collectCerts walks cert directories and runs openssl x509 on each file.
// Discovery: paths from config facts (TLS bindings) + defaults
// (/etc/ssl/, /etc/pki/tls/) + PARTOUT_CERT_PATHS.
// Refresh: 1 hour (arch §7.2).
func collectCerts(cfg *Config) *CertFacts {
	cfg = cfg.Fill()
	certPaths := defaultCertPaths()
	if cfg.CertPaths != "" {
		for _, p := range strings.Split(cfg.CertPaths, ",") {
			p = strings.TrimSpace(p)
			if p != "" {
				certPaths = append(certPaths, p)
			}
		}
	}
	var items []CertFact
	for _, dir := range certPaths {
		files := findCertFiles(dir)
		for _, f := range files {
			cf := parseCert(f)
			if cf != nil {
				items = append(items, *cf)
			}
		}
	}
	if len(items) == 0 {
		return nil
	}
	return &CertFacts{Items: items}
}

// defaultCertPaths returns the standard certificate directories to scan.
func defaultCertPaths() []string {
	return []string{
		"/etc/ssl/",
		"/etc/pki/tls/",
	}
}

// findCertFiles walks a directory and returns .pem, .crt, .cert files.
func findCertFiles(dir string) []string {
	var files []string
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	for _, e := range entries {
		if e.IsDir() {
			// Recurse into subdirs (but not . or ..)
			if subFiles := findCertFiles(filepath.Join(dir, e.Name())); len(subFiles) > 0 {
				files = append(files, subFiles...)
			}
			continue
		}
		name := e.Name()
		if strings.HasSuffix(name, ".pem") || strings.HasSuffix(name, ".crt") || strings.HasSuffix(name, ".cert") {
			files = append(files, filepath.Join(dir, name))
		}
	}
	return files
}

// parseCert runs openssl x509 to extract certificate details.
func parseCert(path string) *CertFact {
	cf := &CertFact{Path: path}

	// Subject, issuer, dates, serial, SANs
	cmd := exec.Command("openssl", "x509", "-in", path, "-noout",
		"-subject", "-issuer", "-dates", "-serial", "-ext", "subjectAltName",
		"-fingerprint", "-text")
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	if err := cmd.Run(); err != nil {
		return nil
	}
	outStr := out.String()

	// Parse subject
	if m := extractKV(outStr, "subject="); m != "" {
		cf.Subject = m
	}
	// Parse issuer
	if m := extractKV(outStr, "issuer="); m != "" {
		cf.Issuer = m
	}
	// Parse dates
	if notBefore := extractKV(outStr, "notBefore="); notBefore != "" {
		t, err := parseNotBefore(notBefore)
		if err == nil {
			cf.NotBefore = t.Unix()
		}
	}
	if notAfter := extractKV(outStr, "notAfter="); notAfter != "" {
		t, err := parseNotAfter(notAfter)
		if err == nil {
			cf.NotAfter = t.Unix()
			cf.DaysRemaining = int64(t.Sub(time.Now()).Hours() / 24)
		}
	}
	// Parse serial
	if m := extractKV(outStr, "serial="); m != "" {
		cf.Serial = m
	}
	// Parse SANs
	sans := extractSANs(outStr)
	if len(sans) > 0 {
		cf.SANs = sans
	}

	// Key type from text
	if strings.Contains(outStr, "RSA Public-Key") {
		cf.KeyType = "RSA-2048"
		if strings.Contains(outStr, "RSA Private-Key") {
			cf.KeyType = extractKeySize(outStr)
		}
	} else if strings.Contains(outStr, "EC Public-Key") {
		cf.KeyType = "ECDSA-P256"
		if strings.Contains(outStr, "EC Private-Key") {
			cf.KeyType = extractKeySize(outStr)
		}
	}

	// Chain validation: openssl verify
	verifyCmd := exec.Command("openssl", "verify", "-CAfile", "/etc/ssl/certs/ca-certificates.crt", path)
	var verifyOut bytes.Buffer
	verifyCmd.Stdout = &verifyOut
	verifyCmd.Stderr = &verifyOut
	if err := verifyCmd.Run(); err == nil {
		cf.ChainValid = true
	} else {
		cf.ChainValid = false
	}
	// Chain length: count certs in chain file (heuristic: file size / avg cert size)
	if data, err := os.ReadFile(path); err == nil {
		count := bytes.Count(data, []byte("-----BEGIN CERTIFICATE-----"))
		cf.ChainLength = count
	}

	// Self-signed check (simplified: subject == issuer)
	if cf.Subject != "" && cf.Issuer != "" && cf.Subject == cf.Issuer {
		cf.SelfSigned = true
	}

	// OCSP stapling from text
	if strings.Contains(outStr, "OCSP") {
		cf.OCSPStapling = true
		if strings.Contains(outStr, "OCSP Response Status: successful") {
			cf.OCSPStatus = "good"
		} else if strings.Contains(outStr, "revoked") {
			cf.OCSPStatus = "revoked"
		}
	}

	return cf
}

// ---- Helpers -------------------------------------------------------------

func splitList(s string) []string {
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	result := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			result = append(result, p)
		}
	}
	return result
}

func parseUint64(s string) (uint64, error) {
	if s == "" {
		return 0, fmt.Errorf("empty")
	}
	return strconv.ParseUint(strings.TrimSpace(s), 10, 64)
}

func parseExitCode(s string) int {
	if s == "" {
		return 0
	}
	n, err := strconv.Atoi(s)
	if err != nil {
		return 0
	}
	return n
}

func extractKV(s, key string) string {
	idx := strings.Index(s, key)
	if idx < 0 {
		return ""
	}
	val := s[idx+len(key):]
	// Value goes until next key or end of line
	for _, line := range strings.Split(val, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		// Check if next key starts
		if strings.Contains(line, "=") && !strings.HasPrefix(line, " ") {
			break
		}
		return strings.TrimSpace(line)
	}
	return strings.TrimSpace(val)
}

func extractSANs(s string) []string {
	var sans []string
	// Look for DNS: patterns in SANs section
	sansSection := extractAfter(s, "X509v3 Subject Alternative Name:")
	if sansSection == "" {
		return nil
	}
	for _, field := range strings.Fields(sansSection) {
		if strings.HasPrefix(field, "DNS:") {
			sans = append(sans, strings.TrimPrefix(field, "DNS:"))
		}
	}
	return sans
}

func extractAfter(s, prefix string) string {
	idx := strings.Index(s, prefix)
	if idx < 0 {
		return ""
	}
	return strings.TrimSpace(s[idx+len(prefix):])
}

func parseNotBefore(s string) (time.Time, error) {
	// Format: "Apr  5 00:00:00 2024 GMT"
	return time.Parse("Jan 2 15:04:05 2006 MST", s)
}

func parseNotAfter(s string) (time.Time, error) {
	return parseNotBefore(s)
}

func extractVersion(s string) string {
	// haproxy version X.Y.Z or nginx X.Y.Z
	idx := strings.Index(s, "version")
	if idx < 0 {
		return ""
	}
	s = s[idx+7:]
	for i, c := range s {
		if !('0' <= c && c <= '9') && c != '.' {
			return strings.TrimSpace(s[:i])
		}
	}
	return strings.TrimSpace(s)
}

func extractKeySize(s string) string {
	// Extract key size from text like "RSA Private-Key: (2048 bit)"
	if idx := strings.Index(s, "bit)"); idx > 0 {
		start := strings.LastIndex(s[:idx], "(")
		if start > 0 {
			size := strings.TrimSpace(s[start+1 : idx])
			return size
		}
	}
	return "unknown"
}

func fileSHA256(path string) (string, error) {
	// Lightweight: use sha256sum if available, else openssl
	if _, err := exec.LookPath("sha256sum"); err == nil {
		cmd := exec.Command("sha256sum", path)
		var out bytes.Buffer
		cmd.Stdout = &out
		if err := cmd.Run(); err == nil {
			fields := strings.Fields(out.String())
			if len(fields) > 0 {
				return fields[0], nil
			}
		}
	}
	// Fallback: openssl
	cmd := exec.Command("openssl", "dgst", "-sha256", path)
	var out bytes.Buffer
	cmd.Stdout = &out
	if err := cmd.Run(); err == nil {
		fields := strings.Fields(out.String())
		if len(fields) > 1 {
			return fields[len(fields)-1], nil
		}
	}
	return "", fmt.Errorf("sha256sum not available")
}

// parseHAProxyTopology does lightweight regex/line-based parsing of the
// haproxy config to extract backends, servers, frontends, TLS bindings.
// No full YAML parsing dependency — just line scanning.
func parseHAProxyTopology(path string) ([]BackendFact, []ListenerFact) {
	var backends []BackendFact
	var listeners []ListenerFact
	data, err := os.ReadFile(path)
	if err != nil {
		return backends, listeners
	}
	lines := strings.Split(string(data), "\n")
	var currentSection string
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "backend ") {
			currentSection = "backend"
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				backends = append(backends, BackendFact{Name: fields[1]})
			}
		} else if strings.HasPrefix(line, "frontend ") || strings.HasPrefix(line, "listen ") {
			currentSection = "frontend"
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				mode := "http"
				port := 0
				tls := ""
				for _, field := range fields[1:] {
					if field == ":443" || field == ":8443" {
						mode = "https"
						port, _ = strconv.Atoi(field[1:])
						tls = "enabled"
					} else if n, err := strconv.Atoi(field[1:]); err == nil {
						port = n
					}
				}
				listeners = append(listeners, ListenerFact{
					Port: port, Mode: mode, TLS: tls,
				})
			}
		} else if currentSection == "backend" && strings.HasPrefix(line, "server ") {
			if len(backends) > 0 {
				backends[len(backends)-1].Servers++
			}
		}
	}
	return backends, listeners
}

// parseNginxVhosts does lightweight parsing of nginx config to extract
// server blocks (vhosts) with their TLS and upstream info.
func parseNginxVhosts(path string) []VHostFact {
	var vhosts []VHostFact
	data, err := os.ReadFile(path)
	if err != nil {
		return vhosts
	}
	content := string(data)
	// Find server { ... } blocks (naive: look for "server " followed by "{")
	var currentBlock strings.Builder
	inServer := false
	bracketDepth := 0
	words := strings.Fields(content)
	i := 0
	for i < len(words) {
		w := words[i]
		if w == "server" && i+1 < len(words) && words[i+1] == "{" {
			inServer = true
			bracketDepth = 1
			currentBlock.Reset()
			currentBlock.WriteString(w + " ")
			i++
			currentBlock.WriteString(words[i] + " ")
			i++
			continue
		}
		if inServer {
			currentBlock.WriteString(w + " ")
			for _, c := range w {
				if c == '{' {
					bracketDepth++
				} else if c == '}' {
					bracketDepth--
					if bracketDepth == 0 {
						vhosts = append(vhosts, parseNginxServerBlock(currentBlock.String()))
						inServer = false
						break
					}
				}
			}
		}
		i++
	}
	return vhosts
}

// parseNginxServerBlock extracts vhost details from a server { ... } block.
func parseNginxServerBlock(block string) VHostFact {
	var vhost VHostFact
	lines := strings.Split(block, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "server_name ") {
			parts := strings.Fields(line)
			if len(parts) > 1 {
				vhost.ServerName = parts[1]
			}
		} else if strings.HasPrefix(line, "listen ") {
			parts := strings.Fields(line)
			for _, p := range parts[1:] {
				if p == "ssl" {
					vhost.TLS = true
				} else if n, err := strconv.Atoi(strings.TrimSuffix(p, ";")); err == nil {
					vhost.Port = n
				}
			}
		} else if strings.HasPrefix(line, "ssl_certificate ") {
			parts := strings.Fields(line)
			if len(parts) > 1 {
				vhost.TLSCert = strings.TrimSuffix(parts[1], ";")
			}
		} else if strings.HasPrefix(line, "root ") {
			parts := strings.Fields(line)
			if len(parts) > 1 {
				vhost.Root = strings.TrimSuffix(parts[1], ";")
			}
		} else if strings.HasPrefix(line, "proxy_pass ") {
			parts := strings.Fields(line)
			if len(parts) > 1 {
				vhost.Upstream = strings.TrimSuffix(parts[1], ";")
			}
		}
	}
	return vhost
}

// Exported helpers for testing.
func SplitListForTest(s string) []string          { return splitList(s) }
func ParseUint64ForTest(s string) (uint64, error) { return parseUint64(s) }
func ParseExitCodeForTest(s string) int           { return parseExitCode(s) }
