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
