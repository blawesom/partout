package observe_test

import (
	"testing"

	"github.com/blawesom/partout/internal/server/observe"
)

func TestParseDocumentEmpty(t *testing.T) {
	doc, err := observe.ParseDocument("")
	if err != nil {
		t.Fatalf("ParseDocument(\"\"): %v", err)
	}
	if len(doc.Flat) != 0 || len(doc.Structured) != 0 {
		t.Errorf("expected empty document, got flat=%v structured=%v", doc.Flat, doc.Structured)
	}
	if doc.Services() != nil || doc.Configs() != nil || doc.Certificates() != nil {
		t.Error("expected nil domains on empty document")
	}
}

func TestParseDocumentMixed(t *testing.T) {
	blob := `{
		"host.arch": "amd64",
		"partout.version": "0.4.0",
		"services_detailed": {"units": [{"name": "myapp", "state": "active", "enabled": true}]},
		"certificates": {"items": [{"path": "/etc/ssl/x.pem", "days_remaining": 90}]}
	}`
	doc, err := observe.ParseDocument(blob)
	if err != nil {
		t.Fatalf("ParseDocument: %v", err)
	}
	// Flat keys preserved.
	if doc.Flat["host.arch"] != "amd64" {
		t.Errorf("host.arch = %q, want amd64", doc.Flat["host.arch"])
	}
	if doc.Flat["partout.version"] != "0.4.0" {
		t.Errorf("partout.version = %q, want 0.4.0", doc.Flat["partout.version"])
	}
	if _, ok := doc.Flat["services_detailed"]; ok {
		t.Error("services_detailed must not appear in flat view")
	}
	// Services domain.
	sf := doc.Services()
	if sf == nil {
		t.Fatal("Services() = nil")
	}
	if len(sf.Units) != 1 || sf.Units[0].Name != "myapp" || sf.Units[0].State != "active" {
		t.Errorf("units = %+v", sf.Units)
	}
	// Certs domain.
	cf := doc.Certificates()
	if cf == nil {
		t.Fatal("Certificates() = nil")
	}
	if len(cf.Items) != 1 || cf.Items[0].Path != "/etc/ssl/x.pem" || cf.Items[0].DaysRemaining != 90 {
		t.Errorf("items = %+v", cf.Items)
	}
	// Configs domain absent.
	if doc.Configs() != nil {
		t.Error("Configs() should be nil")
	}
}

func TestParseDocumentInvalidJSON(t *testing.T) {
	if _, err := observe.ParseDocument("{not json"); err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

// TestParseDocumentNullDomain: a JSON null means "absent", not "present but
// empty". A null must not appear as a structured key and its accessor must
// return nil (previously it produced a non-nil zero-value struct).
func TestParseDocumentNullDomain(t *testing.T) {
	doc, err := observe.ParseDocument(`{"configs":null,"certificates":null,"host.os":"linux"}`)
	if err != nil {
		t.Fatalf("ParseDocument: %v", err)
	}
	if _, ok := doc.Structured["configs"]; ok {
		t.Error("null configs should be absent, not structured")
	}
	if doc.Configs() != nil {
		t.Error("Configs() on null should be nil")
	}
	if doc.Certificates() != nil {
		t.Error("Certificates() on null should be nil")
	}
	if doc.Flat["host.os"] != "linux" {
		t.Errorf("host.os = %q, want linux", doc.Flat["host.os"])
	}
}

// TestParseDocumentNonObjectDomain: a non-object where a domain object is
// expected must be rejected by the typed accessor. JSON strings are flat
// facts by definition, so they never reach Structured at all.
func TestParseDocumentNonObjectDomain(t *testing.T) {
	doc, err := observe.ParseDocument(`{"configs":"oops","certificates":[1,2,3],"services_detailed":42}`)
	if err != nil {
		t.Fatalf("ParseDocument: %v", err)
	}
	if doc.Configs() != nil {
		t.Error("Configs() on a scalar should be nil")
	}
	if doc.Certificates() != nil {
		t.Error("Certificates() on an array should be nil")
	}
	if doc.Services() != nil {
		t.Error("Services() on a number should be nil")
	}
	// A JSON string is a flat fact, never a structured domain.
	if doc.Flat["configs"] != "oops" {
		t.Errorf("flat configs = %q, want oops", doc.Flat["configs"])
	}
	if _, ok := doc.Structured["configs"]; ok {
		t.Error("string value must not be structured")
	}
	// Non-string, non-object values stay inspectable.
	if string(doc.Structured["certificates"]) != `[1,2,3]` {
		t.Errorf("raw certificates = %s, want [1,2,3]", doc.Structured["certificates"])
	}
	if string(doc.Structured["services_detailed"]) != `42` {
		t.Errorf("raw services_detailed = %s, want 42", doc.Structured["services_detailed"])
	}
}

// TestParseDocumentWhitespaceAndEscapes: whitespace around values and escaped
// strings must classify correctly.
func TestParseDocumentWhitespaceAndEscapes(t *testing.T) {
	doc, err := observe.ParseDocument(`{  "host.os" : "linux" , "services_detailed" : { "units" : [] } , "x" : null }`)
	if err != nil {
		t.Fatalf("ParseDocument: %v", err)
	}
	if doc.Flat["host.os"] != "linux" {
		t.Errorf("host.os = %q, want linux", doc.Flat["host.os"])
	}
	if doc.Services() == nil {
		t.Error("Services() should parse despite whitespace")
	}
	if _, ok := doc.Structured["x"]; ok {
		t.Error("whitespace-padded null should be absent")
	}

	// Escaped string round-trip.
	doc2, err := observe.ParseDocument(`{"msg":"a\"b\\c"}`)
	if err != nil {
		t.Fatalf("ParseDocument(escapes): %v", err)
	}
	if doc2.Flat["msg"] != `a"b\c` {
		t.Errorf("msg = %q, want a\"b\\c", doc2.Flat["msg"])
	}
}

// TestParseDocumentNonStringKeptVerbatim: numbers and booleans survive as
// structured values without being mangled by a re-marshal.
func TestParseDocumentNonStringKeptVerbatim(t *testing.T) {
	doc, err := observe.ParseDocument(`{"a":1.5,"b":true,"c":{"d":[1,2]}}`)
	if err != nil {
		t.Fatalf("ParseDocument: %v", err)
	}
	if string(doc.Structured["a"]) != "1.5" {
		t.Errorf("a = %s, want 1.5", doc.Structured["a"])
	}
	if string(doc.Structured["b"]) != "true" {
		t.Errorf("b = %s, want true", doc.Structured["b"])
	}
	if string(doc.Structured["c"]) != `{"d":[1,2]}` {
		t.Errorf("c = %s, want {\"d\":[1,2]}", doc.Structured["c"])
	}
}

// TestChainCheckedRoundTrip: the cert domain carries chain_checked so callers
// can tell "not verified" from "verified and broken".
func TestChainCheckedRoundTrip(t *testing.T) {
	doc, err := observe.ParseDocument(`{"certificates":{"items":[{"path":"/a.pem","chain_checked":true,"chain_valid":false},{"path":"/b.pem","chain_checked":false}]}}`)
	if err != nil {
		t.Fatalf("ParseDocument: %v", err)
	}
	cf := doc.Certificates()
	if cf == nil || len(cf.Items) != 2 {
		t.Fatalf("certs = %+v", cf)
	}
	if !cf.Items[0].ChainChecked || cf.Items[0].ChainValid {
		t.Errorf("item0 = %+v, want checked-but-invalid", cf.Items[0])
	}
	if cf.Items[1].ChainChecked {
		t.Errorf("item1 = %+v, want unchecked", cf.Items[1])
	}
}

// TestConfigsDomainParses covers the haproxy/nginx typed view.
func TestConfigsDomainParses(t *testing.T) {
	blob := `{"configs":{"haproxy":{"present":true,"version":"2.8","config_valid":true,"backends":[{"name":"web","servers":3,"active":2}]},"nginx":{"present":true,"version":"1.24","vhosts":[{"server_name":"a.example.com","port":443,"tls":true}]}}}`
	doc, err := observe.ParseDocument(blob)
	if err != nil {
		t.Fatalf("ParseDocument: %v", err)
	}
	cf := doc.Configs()
	if cf == nil {
		t.Fatal("Configs() = nil")
	}
	if cf.HAProxy == nil || cf.HAProxy.Version != "2.8" || len(cf.HAProxy.Backends) != 1 {
		t.Errorf("haproxy = %+v", cf.HAProxy)
	}
	if cf.HAProxy.Backends[0].Active != 2 {
		t.Errorf("backend active = %d, want 2", cf.HAProxy.Backends[0].Active)
	}
	if cf.Nginx == nil || len(cf.Nginx.Vhosts) != 1 || cf.Nginx.Vhosts[0].ServerName != "a.example.com" {
		t.Errorf("nginx = %+v", cf.Nginx)
	}
}

// TestDomainKeysStable guards the storage keys used by the store merge and the
// agent's JSON tags against accidental renames.
func TestDomainKeysStable(t *testing.T) {
	if observe.KeyServices != "services_detailed" {
		t.Errorf("KeyServices = %q", observe.KeyServices)
	}
	if observe.KeyConfigs != "configs" {
		t.Errorf("KeyConfigs = %q", observe.KeyConfigs)
	}
	if observe.KeyCerts != "certificates" {
		t.Errorf("KeyCerts = %q", observe.KeyCerts)
	}
}
