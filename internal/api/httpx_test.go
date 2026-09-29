package api

import (
	"bytes"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestDecodeJSONBodyCap: a JSON body above the 256 MiB cap is rejected
// (memory-DoS bound on every JSON endpoint, release uploads included).
func TestDecodeJSONBodyCap(t *testing.T) {
	big := make([]byte, maxJSONBody+4096)
	r := httptest.NewRequest("POST", "/x", bytes.NewReader(big))
	var v map[string]any
	if err := decodeJSON(r, &v); err == nil {
		t.Fatal("oversized body decoded without error")
	}
	// A small valid body still works.
	r2 := httptest.NewRequest("POST", "/x", strings.NewReader(`{"a":1}`))
	if err := decodeJSON(r2, &v); err != nil || v["a"] != float64(1) {
		t.Fatalf("small body: v=%v err=%v", v, err)
	}
}
