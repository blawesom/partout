package factscollect

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/blawesom/partout/internal/agent/elevate"
)

func TestNginxCertPaths(t *testing.T) {
	data := `
# comment ssl_certificate /should/not/match.pem
server {
    listen 443 ssl;
    ssl_certificate /etc/nginx/ssl/site.pem;
    ssl_certificate_key /etc/nginx/ssl/site.key;
    ssl_trusted_certificate /etc/nginx/ssl/chain.pem;
}
`
	got := reNginxCert.FindAllStringSubmatch(stripNginxComments(data), -1)
	var paths []string
	for _, m := range got {
		paths = append(paths, m[1])
	}
	want := []string{"/etc/nginx/ssl/site.pem"}
	if !reflect.DeepEqual(paths, want) {
		t.Fatalf("nginx cert paths = %v, want %v", paths, want)
	}
}

func TestNginxConfTree(t *testing.T) {
	dir := t.TempDir()
	main := filepath.Join(dir, "nginx.conf")
	inc1 := filepath.Join(dir, "conf.d", "a.conf")
	inc2 := filepath.Join(dir, "conf.d", "b.conf")
	if err := os.MkdirAll(filepath.Dir(inc1), 0o755); err != nil {
		t.Fatal(err)
	}
	mustWrite := func(p, s string) {
		if err := os.WriteFile(p, []byte(s), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	mustWrite(main, "events {}\nhttp {\n  include "+filepath.Join(dir, "conf.d", "*.conf")+";\n  include /nonexistent/x.conf;\n}\n")
	mustWrite(inc1, "server {}\n")
	mustWrite(inc2, "server {}\n")

	got := nginxConfTree(main, elevate.None, nil)
	want := []string{main, inc1, inc2}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("conf tree = %v, want %v", got, want)
	}
}

func TestNginxConfTreeMissing(t *testing.T) {
	if got := nginxConfTree("/nonexistent/nginx.conf", elevate.None, nil); got != nil {
		t.Fatalf("missing main conf = %v, want nil", got)
	}
}

func TestHaproxyCertPaths(t *testing.T) {
	data := `
frontend fe
    bind :443 ssl crt-/etc/haproxy/ssl/fe.pem
    http-request set-header X-Forwarded-Proto https

backend be
    server s1 10.0.0.5:80 check

defaults
    mode http

listen api :8443
    ssl-certificates /etc/haproxy/certs/api.pem
    ssl-certificates-file /etc/haproxy/certs/legacy.pem
`
	got := reHaproxyCert.FindAllStringSubmatch(data, -1)
	var paths []string
	for _, m := range got {
		paths = append(paths, m[1])
	}
	want := []string{"/etc/haproxy/certs/api.pem", "/etc/haproxy/certs/legacy.pem"}
	if !reflect.DeepEqual(paths, want) {
		t.Fatalf("haproxy cert paths = %v, want %v", paths, want)
	}
}

func TestCaddyfileCertPaths(t *testing.T) {
	data := `
:80 {
	reverse_proxy 127.0.0.1:8080
}

example.com {
	tls /etc/caddy/certs/site.pem /etc/caddy/certs/site.key
	reverse_proxy 127.0.0.1:8080
}

acme.test {
	tls internal
}

json.test {
	tls {
		"certificate_authority": "local"
	}
}
`
	got := caddyfileCertPaths(data)
	want := []string{"/etc/caddy/certs/site.pem"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("caddyfile cert paths = %v, want %v", got, want)
	}
}

func TestCaddyJSONCertPaths(t *testing.T) {
	data := `{
  "tls": {
    "certificates": [
      {"source": "file", "certificate": "/etc/caddy/pki/a.crt", "key": "/etc/caddy/pki/a.key"},
      {"source": "internal"}
    ]
  }
}`
	got := caddyJSONCertPaths(data)
	want := []string{"/etc/caddy/pki/a.crt"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("caddy json cert paths = %v, want %v", got, want)
	}
	if got := caddyJSONCertPaths("not json"); got != nil {
		t.Fatalf("bad json = %v, want nil", got)
	}
}

func TestDiscoverServiceCerts(t *testing.T) {
	dir := t.TempDir()
	certFile := filepath.Join(dir, "site.pem")
	if err := os.WriteFile(certFile, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	nginxCfg := filepath.Join(dir, "nginx.conf")
	inc := filepath.Join(dir, "vhost.conf")
	if err := os.WriteFile(nginxCfg, []byte("http {\n  include "+inc+";\n}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(inc, []byte("server { ssl_certificate "+certFile+"; }\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	hapCfg := filepath.Join(dir, "haproxy.cfg")
	if err := os.WriteFile(hapCfg, []byte("listen api :8443\n  ssl-certificates "+certFile+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	// Caddyfile in a separate dir; its caddy.json is NOT consulted when a
	// Caddyfile exists.
	caddyDir := filepath.Join(dir, "caddy")
	if err := os.MkdirAll(caddyDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(caddyDir, "Caddyfile"), []byte("example.com {\n\ttls "+certFile+" /etc/caddy/key.pem\n}\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	cfg := &Config{NginxConf: nginxCfg, HaproxyConf: hapCfg, CaddyConf: filepath.Join(caddyDir, "Caddyfile")}
	refs := discoverServiceCerts(cfg)
	want := []svcCertRef{
		{Path: certFile, Service: "nginx"},
		{Path: certFile, Service: "haproxy"},
		{Path: certFile, Service: "caddy"},
	}
	if !reflect.DeepEqual(refs, want) {
		t.Fatalf("refs = %+v, want %+v", refs, want)
	}
}

func TestDiscoverServiceCertsAllMissing(t *testing.T) {
	cfg := &Config{NginxConf: "/nope/nginx.conf", HaproxyConf: "/nope/haproxy.cfg", CaddyConf: "/nope/Caddyfile"}
	if refs := discoverServiceCerts(cfg); len(refs) != 0 {
		t.Fatalf("missing configs produced refs: %+v", refs)
	}
}

// TestDiscoverServiceCertsHAProxyBindCrt: the standard haproxy TLS syntax
// `bind *:443 ssl crt /a.pem crt /b.pem` — multiple crt entries per bind
// line, each discovered (field report: ccc.laplane.net — two certs on one
// bind line, previously invisible because only the rare haproxy 2.4+
// ssl-certificates directive was matched). crt-list and ca-file must NOT
// be treated as certificates.
func TestDiscoverServiceCertsHAProxyBindCrt(t *testing.T) {
	dir := t.TempDir()
	hapCfg := filepath.Join(dir, "haproxy.cfg")
	cfgText := `
global
    ssl-default-bind-ciphers PROFILE=SYSTEM

frontend https
    bind *:443 ssl crt /var/lib/haproxy/cert/a.pem crt /var/lib/haproxy/cert/b.pem
    bind *:80

frontend mtls
    bind *:8443 ssl crt /etc/haproxy/ssl/c.pem ca-file /etc/haproxy/ca.pem verify required crt-list /etc/haproxy/crtlist.txt
`
	if err := os.WriteFile(hapCfg, []byte(cfgText), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg := &Config{NginxConf: "/nope/nginx.conf", HaproxyConf: hapCfg, CaddyConf: "/nope/Caddyfile"}
	refs := discoverServiceCerts(cfg)
	paths := make([]string, len(refs))
	for i, r := range refs {
		paths[i] = r.Path
	}
	want := []string{"/var/lib/haproxy/cert/a.pem", "/var/lib/haproxy/cert/b.pem", "/etc/haproxy/ssl/c.pem"}
	if !reflect.DeepEqual(paths, want) {
		t.Fatalf("bind crt paths = %v, want %v", paths, want)
	}
	for _, r := range refs {
		if r.Service != "haproxy" {
			t.Errorf("ref %q service = %q, want haproxy", r.Path, r.Service)
		}
	}
}

// TestDiscoverServiceCertsHAProxyLegacySSLCertificates: the haproxy 2.4+
// ssl-certificates directive still matches alongside bind-crt.
func TestDiscoverServiceCertsHAProxyLegacySSLCertificates(t *testing.T) {
	dir := t.TempDir()
	hapCfg := filepath.Join(dir, "haproxy.cfg")
	cfgText := "frontend f\n    ssl-certificates /etc/haproxy/ssl/d.pem\n"
	if err := os.WriteFile(hapCfg, []byte(cfgText), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg := &Config{NginxConf: "/nope/nginx.conf", HaproxyConf: hapCfg, CaddyConf: "/nope/Caddyfile"}
	refs := discoverServiceCerts(cfg)
	if len(refs) != 1 || refs[0].Path != "/etc/haproxy/ssl/d.pem" {
		t.Fatalf("ssl-certificates refs = %+v", refs)
	}
}

// TestCollectCertsReferencedButUnreadable: a service-referenced file that
// exists but cannot be parsed surfaces as a read-error fact (path + labels
// + reason) instead of silently disappearing — the certs page shows the
// remedy. Walk-discovered files stay silent (not asserted here — /etc/ssl
// legitimately holds non-certs).
func TestCollectCertsReferencedButUnreadable(t *testing.T) {
	dir := t.TempDir()
	// A file the agent user cannot read (chmod 0), referenced by the
	// nginx config.
	certFile := filepath.Join(dir, "site.pem")
	if err := os.WriteFile(certFile, []byte("placeholder"), 0o600); err != nil {
		t.Fatal(err)
	}
	if os.Geteuid() == 0 {
		t.Skip("root reads anything; EACCES path not exercisable")
	}
	if err := os.Chmod(certFile, 0); err != nil {
		t.Fatal(err)
	}
	defer os.Chmod(certFile, 0o600)

	nginxCfg := filepath.Join(dir, "nginx.conf")
	conf := "server {\n    listen 443 ssl;\n    ssl_certificate " + certFile + ";\n}\n"
	if err := os.WriteFile(nginxCfg, []byte(conf), 0o644); err != nil {
		t.Fatal(err)
	}

	f := Collect(&Config{NginxConf: nginxCfg, HaproxyConf: filepath.Join(dir, "nope.cfg"), CaddyConf: filepath.Join(dir, "nope")})
	if f == nil || f.Certificates == nil {
		t.Fatal("Collect = nil, want cert facts with the read-error entry")
	}
	var found *CertFact
	for i := range f.Certificates.Items {
		if f.Certificates.Items[i].Path == certFile {
			found = &f.Certificates.Items[i]
		}
	}
	if found == nil {
		t.Fatalf("no fact for referenced unreadable cert %s: %+v", certFile, f.Certificates.Items)
	}
	if found.ReadError == "" {
		t.Error("ReadError empty, want a reason (permission denied)")
	}
	if found.NotAfter != 0 {
		t.Errorf("NotAfter = %d, want 0 (unknown, never expired)", found.NotAfter)
	}
	if len(found.Labels) != 1 || found.Labels[0] != "nginx" {
		t.Errorf("Labels = %v, want [nginx] (the referencing service)", found.Labels)
	}
}

// TestCertReadError: the classifier distinguishes permission failures
// (actionable: policy grant or chmod) from non-certificates.
func TestCertReadError(t *testing.T) {
	dir := t.TempDir()

	// Readable but not a certificate.
	notCert := filepath.Join(dir, "notcert.pem")
	if err := os.WriteFile(notCert, []byte("hello"), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := certReadError(notCert, elevate.None, nil); got != "not a certificate" {
		t.Errorf("certReadError(readable non-cert) = %q", got)
	}

	if os.Geteuid() != 0 {
		// Root-only file without a policy: permission denied.
		locked := filepath.Join(dir, "locked.pem")
		if err := os.WriteFile(locked, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(locked, 0); err != nil {
			t.Fatal(err)
		}
		defer os.Chmod(locked, 0o600)
		if got := certReadError(locked, elevate.None, nil); got != "permission denied (no cat grant)" {
			t.Errorf("certReadError(root-only, no policy) = %q", got)
		}
	}
}

// TestParseCertPEM: the in-process parser (crypto/x509) used for root-only
// certs read via elevation. All public fields come from the DER; chain
// verification is skipped (unchecked, like a host with no trust bundle).
func TestParseCertPEM(t *testing.T) {
	// A real self-signed test cert (generated in-process for determinism).
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(42),
		Subject:      pkix.Name{CommonName: "test.laplane.net"},
		DNSNames:     []string{"test.laplane.net"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(90 * 24 * time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatal(err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})

	cf := parseCertPEM("/x/test.pem", pemBytes)
	if cf == nil {
		t.Fatal("parseCertPEM = nil")
	}
	if cf.Subject != "CN=test.laplane.net" {
		t.Errorf("Subject = %q", cf.Subject)
	}
	if cf.Serial != "42" {
		t.Errorf("Serial = %q, want 42", cf.Serial)
	}
	if cf.NotAfter == 0 || cf.DaysRemaining < 89 || cf.DaysRemaining > 90 {
		t.Errorf("NotAfter/DaysRemaining = %d/%d, want ~90d", cf.NotAfter, cf.DaysRemaining)
	}
	if len(cf.SANs) != 1 || cf.SANs[0] != "test.laplane.net" {
		t.Errorf("SANs = %v", cf.SANs)
	}
	if cf.KeyType != "ECDSA-P256" {
		t.Errorf("KeyType = %q, want ECDSA-P256", cf.KeyType)
	}
	if !cf.SelfSigned {
		t.Error("SelfSigned = false, want true")
	}
	if cf.ChainLength != 1 {
		t.Errorf("ChainLength = %d, want 1", cf.ChainLength)
	}
	if cf.ChainChecked {
		t.Error("ChainChecked = true, want false (no openssl verify on elevated path)")
	}
	if cf.OCSPStatus != "unknown" {
		t.Errorf("OCSPStatus = %q", cf.OCSPStatus)
	}
}

// TestParseCertPEMNotACert: PEM bytes that are not a certificate yield nil
// (no phantom fact).
func TestParseCertPEMNotACert(t *testing.T) {
	key := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("bogus")})
	if cf := parseCertPEM("/x/key.pem", key); cf != nil {
		t.Errorf("parseCertPEM(key) = %+v, want nil", cf)
	}
	if cf := parseCertPEM("/x/garbage", []byte("not pem at all")); cf != nil {
		t.Errorf("parseCertPEM(garbage) = %+v, want nil", cf)
	}
}

func TestCaddyJSONFallback(t *testing.T) {
	dir := t.TempDir()
	jsonPath := filepath.Join(dir, "caddy.json")
	if err := os.WriteFile(jsonPath, []byte(`{"tls":{"certificates":[{"certificate":"/x/a.crt"}]}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	// Pin nginx/haproxy to nonexistent paths: the defaults may exist on
	// the test host (a dev box with a local haproxy fleet config would
	// otherwise leak its crt references into this caddy-only test).
	cfg := &Config{NginxConf: "/nope/nginx.conf", HaproxyConf: "/nope/haproxy.cfg", CaddyConf: filepath.Join(dir, "Caddyfile")} // no Caddyfile
	refs := discoverServiceCerts(cfg)
	if len(refs) != 1 || refs[0].Path != "/x/a.crt" || refs[0].Service != "caddy" {
		t.Fatalf("json fallback refs = %+v", refs)
	}
}
