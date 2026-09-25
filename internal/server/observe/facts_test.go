package observe_test

import (
	"testing"

	"github.com/blawesom/partout/internal/server/observe"
)

func TestIngestWithNilEnv(t *testing.T) {
	// When env is nil, the blob should be returned unchanged
	existing := `{"configs":{"haproxy":{"present":true}}}`
	merged, err := observe.Ingest(existing, nil)
	if err != nil {
		t.Fatalf("Ingest failed: %v", err)
	}
	if merged != existing {
		t.Errorf("merged = %q, want %q", merged, existing)
	}
}

func TestIngestWithEmptyBlob(t *testing.T) {
	// Empty blob with nil env should return empty blob
	merged, err := observe.Ingest("", nil)
	if err != nil {
		t.Fatalf("Ingest failed: %v", err)
	}
	if merged != "" {
		t.Errorf("merged = %q, want empty string", merged)
	}
}
