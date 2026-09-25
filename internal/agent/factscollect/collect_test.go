package factscollect_test

import (
	"testing"

	"github.com/blawesom/partout/internal/agent/factscollect"
)

func TestCollectWithConfig(t *testing.T) {
	cfg := &factscollect.Config{
		ObserveFactsInterval: 300,
	}
	f := factscollect.Collect(cfg)
	if f == nil {
		t.Skip("no structured facts available on this host")
	}
	// At least one domain should have facts (or nil if none available)
	if f.ServicesDetailed == nil && f.Configs == nil && f.Certificates == nil {
		t.Skip("no structured facts collected (expected in CI)")
	}
}

func TestFillConfig(t *testing.T) {
	cfg := &factscollect.Config{}
	filled := cfg.Fill()
	if filled.ObserveFactsInterval != 300 {
		t.Errorf("ObserveFactsInterval = %d, want 300", filled.ObserveFactsInterval)
	}
}

func TestSplitList(t *testing.T) {
	tests := []struct {
		input  string
		expect []string
	}{
		{"", nil},
		{"multi-user.target", []string{"multi-user.target"}},
		{"multi-user.target, network.target", []string{"multi-user.target", "network.target"}},
		{"  space  ,  here  ", []string{"space", "here"}},
	}
	for _, tt := range tests {
		got := splitList(tt.input)
		if len(got) != len(tt.expect) {
			t.Errorf("splitList(%q) = %v (len %d), want %v (len %d)", tt.input, got, len(got), tt.expect, len(tt.expect))
			continue
		}
		for i, v := range got {
			if v != tt.expect[i] {
				t.Errorf("splitList(%q)[%d] = %q, want %q", tt.input, i, v, tt.expect[i])
			}
		}
	}
}

func TestParseUint64(t *testing.T) {
	if n, err := parseUint64("12345"); err != nil || n != 12345 {
		t.Errorf("parseUint64(\"12345\") = %d, %v, want 12345, nil", n, err)
	}
	if _, err := parseUint64(""); err == nil {
		t.Error("parseUint64(\"\") should error")
	}
}

// ---- helpers to expose private functions for testing ----

func splitList(s string) []string {
	return factscollect.SplitListForTest(s)
}

func parseUint64(s string) (uint64, error) {
	return factscollect.ParseUint64ForTest(s)
}
