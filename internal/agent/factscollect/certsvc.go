package factscollect

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// Service-config certificate discovery.
//
// The directory scan (/etc/ssl, /etc/pki/tls, PARTOUT_CERT_PATHS) misses the
// most important class of certificate: the ones a running service actually
// presents, which commonly live outside those trees (/etc/letsencrypt/live,
// /etc/nginx/ssl, /opt/..., custom paths). So cert discovery also parses
// the standard nginx / haproxy / caddy configs for the certificate files
// they reference, collects those files first (ahead of the scan's file
// budget), and labels each fact with the referencing service so the server
// and UI can show "used by nginx:443" even for paths the directory walk
// would never reach.
//
// Presence of the service binary is NOT required: a config that references
// a certificate is worth monitoring while the service is stopped or being
// redeployed — the expiry clock does not stop.

type svcCertRef struct {
	Path    string
	Service string // nginx | haproxy | caddy
}

var (
	// ssl_certificate /path/leaf.pem; — the key directive
	// (ssl_certificate_key) does not match: the next char is '_', not
	// whitespace, so the key file is never treated as a certificate.
	// Run on comment-stripped content (see stripNginxComments).
	reNginxCert = regexp.MustCompile(`(?m)ssl_certificate\s+([^\s;{}]+)`)
	// haproxy 2.4+: `ssl-certificates <path>` per frontend/listener;
	// 2.0–2.3: `ssl-certificates-file <path>`.
	reHaproxyCert = regexp.MustCompile(`(?m)^\s*ssl-certificates(?:-file)?\s+([^\s;]+)`)
	// nginx `include /etc/nginx/conf.d/*.conf;`
	reNginxInclude = regexp.MustCompile(`(?m)^\s*include\s+([^\s;]+);`)
)

const (
	svcConfMaxFiles    = 64 // include expansion cap (nginx conf.d + sites-enabled)
	svcConfMaxFileSize = 1 << 20
)

// discoverServiceCerts parses the service config locations (defaults or
// operator overrides) and returns the distinct certificate references,
// service-tagged. Missing files are skipped (service not installed).
func discoverServiceCerts(cfg *Config) []svcCertRef {
	cfg = cfg.Fill()
	seen := map[string]bool{}
	var refs []svcCertRef
	add := func(path, svc string) {
		p := strings.TrimSpace(path)
		if p == "" || !strings.HasPrefix(p, "/") || seen[p+svc] {
			return
		}
		seen[p+svc] = true
		refs = append(refs, svcCertRef{Path: p, Service: svc})
	}

	nginxCfg := orDefault(cfg.NginxConf, "/etc/nginx/nginx.conf")
	for _, f := range nginxConfTree(nginxCfg) {
		data, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		content := stripNginxComments(string(data))
		for _, m := range reNginxCert.FindAllStringSubmatch(content, -1) {
			add(m[1], "nginx")
		}
	}

	if hap, err := os.ReadFile(orDefault(cfg.HaproxyConf, "/etc/haproxy/haproxy.cfg")); err == nil {
		for _, m := range reHaproxyCert.FindAllStringSubmatch(string(hap), -1) {
			add(m[1], "haproxy")
		}
	}

	// Caddy: Caddyfile and/or JSON config. The Caddyfile wins when present
	// (it is the live format; caddy.json is the compiled/alternate form).
	cfPath, jsonPath := caddyConfPaths(cfg)
	if data, err := os.ReadFile(cfPath); err == nil {
		for _, p := range caddyfileCertPaths(string(data)) {
			add(p, "caddy")
		}
	} else if data, err := os.ReadFile(jsonPath); err == nil {
		for _, p := range caddyJSONCertPaths(string(data)) {
			add(p, "caddy")
		}
	}
	return refs
}

func orDefault(v, def string) string {
	if strings.TrimSpace(v) != "" {
		return v
	}
	return def
}

// stripNginxComments removes '#' to end-of-line from each line so that
// commented-out directives cannot match the cert-path regex. (A '#' inside
// a quoted path would over-strip — nginx cert paths containing '#' do not
// occur in practice.)
func stripNginxComments(data string) string {
	lines := strings.Split(data, "\n")
	for i, l := range lines {
		if j := strings.Index(l, "#"); j >= 0 {
			lines[i] = l[:j]
		}
	}
	return strings.Join(lines, "\n")
}

func caddyConfPaths(cfg *Config) (string, string) {
	cf := orDefault(cfg.CaddyConf, "/etc/caddy/Caddyfile")
	jsonPath := "/etc/caddy/caddy.json"
	if base := filepath.Dir(cf); base != "/etc/caddy" {
		jsonPath = filepath.Join(base, "caddy.json")
	}
	return cf, jsonPath
}

// nginxConfTree returns the main conf plus one level of `include` expansion
// (glob-aware), bounded. Non-existent includes are skipped; the cap guards
// against pathological include loops via the visited set.
func nginxConfTree(main string) []string {
	if _, err := os.Stat(main); err != nil {
		return nil
	}
	data, err := os.ReadFile(main)
	if err != nil {
		return []string{main}
	}
	seen := map[string]bool{main: true}
	out := []string{main}
	for _, m := range reNginxInclude.FindAllStringSubmatch(string(data), -1) {
		pattern := strings.TrimSpace(m[1])
		if strings.HasPrefix(pattern, "<") { // <stdin> etc. — not a file
			continue
		}
		var matches []string
		if strings.ContainsAny(pattern, "*?[") {
			if ms, err := filepath.Glob(pattern); err == nil {
				matches = ms
			}
		} else {
			matches = []string{pattern}
		}
		for _, p := range matches {
			if len(out) >= svcConfMaxFiles || seen[p] {
				continue
			}
			st, err := os.Stat(p)
			if err != nil || st.IsDir() || st.Size() > svcConfMaxFileSize {
				continue
			}
			seen[p] = true
			out = append(out, p)
		}
	}
	return out
}

// caddyfileCertPaths extracts the certificate argument of `tls` directives:
//
//	tls /etc/certs/site.pem [key]     — first path arg is the certificate
//	tls internal                     — no file
//	tls { "certificates": [...] }    — inline JSON, skipped (caddy.json
//	                                parser covers the JSON form)
//
// Only the first argument is considered: `tls <cert> <key>` puts the key
// second, and both commonly share the .pem suffix.
func caddyfileCertPaths(data string) []string {
	var out []string
	seen := map[string]bool{}
	for _, raw := range strings.Split(data, "\n") {
		line := stripNginxComment(raw) // same '#' comment rule
		fields := strings.Fields(line)
		if len(fields) < 2 || fields[0] != "tls" {
			continue
		}
		arg := fields[1]
		if !strings.HasPrefix(arg, "/") {
			continue
		}
		if strings.Contains(arg, "{") {
			continue // inline JSON block
		}
		if !strings.HasSuffix(arg, ".pem") && !strings.HasSuffix(arg, ".crt") && !strings.HasSuffix(arg, ".cert") {
			continue
		}
		if !seen[arg] {
			seen[arg] = true
			out = append(out, arg)
		}
	}
	return out
}

// caddyJSONCertPaths extracts certificate file paths from caddy.json's
// "tls.certificates" entries (source: "file" or explicit paths).
func caddyJSONCertPaths(data string) []string {
	var cfg struct {
		TLS struct {
			Certificates []struct {
				Certificate string `json:"certificate"`
			} `json:"certificates"`
		} `json:"tls"`
	}
	if err := json.Unmarshal([]byte(data), &cfg); err != nil {
		return nil
	}
	var out []string
	seen := map[string]bool{}
	for _, c := range cfg.TLS.Certificates {
		p := strings.TrimSpace(c.Certificate)
		if p == "" || !strings.HasPrefix(p, "/") || seen[p] {
			continue
		}
		seen[p] = true
		out = append(out, p)
	}
	return out
}
