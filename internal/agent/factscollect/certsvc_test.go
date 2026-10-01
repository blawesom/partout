package factscollect

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
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

	got := nginxConfTree(main)
	want := []string{main, inc1, inc2}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("conf tree = %v, want %v", got, want)
	}
}

func TestNginxConfTreeMissing(t *testing.T) {
	if got := nginxConfTree("/nonexistent/nginx.conf"); got != nil {
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

func TestCaddyJSONFallback(t *testing.T) {
	dir := t.TempDir()
	jsonPath := filepath.Join(dir, "caddy.json")
	if err := os.WriteFile(jsonPath, []byte(`{"tls":{"certificates":[{"certificate":"/x/a.crt"}]}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg := &Config{CaddyConf: filepath.Join(dir, "Caddyfile")} // no Caddyfile
	refs := discoverServiceCerts(cfg)
	if len(refs) != 1 || refs[0].Path != "/x/a.crt" || refs[0].Service != "caddy" {
		t.Fatalf("json fallback refs = %+v", refs)
	}
}
