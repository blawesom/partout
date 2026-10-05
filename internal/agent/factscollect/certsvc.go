package factscollect

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/blawesom/partout/internal/agent/elevate"
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
	// haproxy `bind ... crt <path> [crt <path2> ...]` — the standard TLS
	// syntax since 1.x and by far the most common form on real fleets
	// (field report: ccc.laplane.net — two certs per bind line, zero
	// discovered by the ssl-certificates-only regex). Each crt entry is a
	// PEM bundle (cert [+ key]); only the certificate part is parsed.
	// `crt-list <file>` does NOT match: the hyphen after `crt` breaks the
	// `crt\s` boundary (and its arg is a list file, not a certificate).
	reHaproxyBind = regexp.MustCompile(`(?m)^\s*bind\b.*$`)
	reHaproxyCrt  = regexp.MustCompile(`\bcrt\s+([^\s;]+)`)
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
// Root-only configs are read via elevation when the policy authorizes
// `cat <path>` (field report: ccc.laplane.net — haproxy.cfg 0640
// root:haproxy meant zero service certs were discovered on a fleet whose
// entire TLS surface runs through haproxy).
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
	readCfg := func(path string) ([]byte, bool) {
		b, err := elevate.ReadFile(cfg.Elevate, cfg.Elevation, path)
		return b, err == nil
	}

	nginxCfg := orDefault(cfg.NginxConf, "/etc/nginx/nginx.conf")
	for _, f := range nginxConfTree(nginxCfg, cfg.Elevate, cfg.Elevation) {
		data, ok := readCfg(f)
		if !ok {
			continue
		}
		content := stripNginxComments(string(data))
		for _, m := range reNginxCert.FindAllStringSubmatch(content, -1) {
			add(m[1], "nginx")
		}
	}

	if hap, ok := readCfg(orDefault(cfg.HaproxyConf, "/etc/haproxy/haproxy.cfg")); ok {
		for _, m := range reHaproxyCert.FindAllStringSubmatch(string(hap), -1) {
			add(m[1], "haproxy")
		}
		// bind-line crt entries — see reHaproxyBindCrt. Each match is a
		// full bind line; scan it for every crt token (multiple per line
		// is normal: one crt per hostname).
		for _, bind := range reHaproxyBind.FindAllString(string(hap), -1) {
			for _, m := range reHaproxyCrt.FindAllStringSubmatch(bind, -1) {
				add(m[1], "haproxy")
			}
		}
	}

	// Caddy: Caddyfile and/or JSON config. The Caddyfile wins when present
	// (it is the live format; caddy.json is the compiled/alternate form).
	cfPath, jsonPath := caddyConfPaths(cfg)
	if data, ok := readCfg(cfPath); ok {
		for _, p := range caddyfileCertPaths(string(data)) {
			add(p, "caddy")
		}
	} else if data, ok := readCfg(jsonPath); ok {
		for _, p := range caddyJSONCertPaths(string(data)) {
			add(p, "caddy")
		}
	}
	return refs
}

// parseCertPEM fills a CertFact from raw PEM bytes in-process
// (crypto/x509), without shelling out to openssl. Used for root-only cert
// files read via an authorized elevation: the openssl CLI path requires
// the file to be directly readable by the agent user, which root-only
// service certs (haproxy crt bundles at 0640 root:service) are not.
// Chain verification is skipped — `openssl verify` needs a readable file
// — and reported as unchecked (the same shape as a host with no trust
// bundle). The certificate's public fields are all extractable from the
// DER: subject, issuer, serial, dates, SANs, key type, self-signed.
func parseCertPEM(path string, pemBytes []byte) *CertFact {
	block, _ := pem.Decode(pemBytes)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil
	}
	cf := &CertFact{Path: path}
	cf.Subject = cert.Subject.String()
	cf.Issuer = cert.Issuer.String()
	cf.Serial = cert.SerialNumber.String()
	cf.NotBefore = cert.NotBefore.Unix()
	cf.NotAfter = cert.NotAfter.Unix()
	cf.DaysRemaining = int64(time.Until(cert.NotAfter).Hours() / 24)
	for _, s := range cert.DNSNames {
		cf.SANs = append(cf.SANs, s)
	}
	for _, ip := range cert.IPAddresses {
		cf.SANs = append(cf.SANs, ip.String())
	}
	cf.KeyType = x509KeyType(cert)
	cf.ChainLength = bytes.Count(pemBytes, []byte("-----BEGIN CERTIFICATE-----"))
	// Direct signature verification against the cert's own public key.
	// NOT CheckSignatureFrom: it enforces the CA basic constraint on the
	// parent, so a self-signed leaf without IsCA (the common `openssl
	// req -new -x509` minus CA flag output, and letsencrypt-style leafs) would
	// false-negative. The signature itself either verifies against the
	// subject's key or it does not.
	cf.SelfSigned = cert.CheckSignature(cert.SignatureAlgorithm, cert.RawTBSCertificate, cert.Signature) == nil
	cf.OCSPStatus = "unknown"
	return cf
}

// x509KeyType renders the public-key algorithm and size from a parsed
// certificate, matching the openssl-based parseKeyType output shape
// ("RSA-4096", "ECDSA-P256").
func x509KeyType(cert *x509.Certificate) string {
	switch pub := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		return "RSA-" + strconv.Itoa(pub.N.BitLen())
	case *ecdsa.PublicKey:
		return "ECDSA-P" + strconv.Itoa(pub.Curve.Params().BitSize)
	case ed25519.PublicKey:
		return "Ed25519"
	default:
		return ""
	}
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
// against pathological include loops via the visited set. The main conf is
// read via elevation when needed (root-only nginx.conf + readable
// conf.d includes, and the reverse, both occur on real fleets).
func nginxConfTree(main string, m elevate.Mode, p *elevate.Policy) []string {
	if _, err := os.Stat(main); err != nil {
		return nil
	}
	data, err := elevate.ReadFile(m, p, main)
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
