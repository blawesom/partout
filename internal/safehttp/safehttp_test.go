package safehttp

import (
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
	"time"
)

func TestDisallowed(t *testing.T) {
	bad := []string{
		"127.0.0.1", "::1", "0.0.0.0", "::",
		"169.254.169.254", "169.254.0.1", "fe80::1",
		"224.0.0.1", "ff02::1",
	}
	for _, s := range bad {
		if !disallowed(netip.MustParseAddr(s)) {
			t.Errorf("disallowed(%s) = false, want true", s)
		}
	}
	// RFC1918 stays allowed (air-gapped LAN receivers).
	ok := []string{"10.0.0.5", "192.168.1.10", "172.16.0.2", "8.8.8.8", "2606:4700:4700::1111"}
	for _, s := range ok {
		if disallowed(netip.MustParseAddr(s)) {
			t.Errorf("disallowed(%s) = true, want false", s)
		}
	}
}

// TestNewClientRefusesLoopback: the dial-time guard must refuse a loopback
// target (httptest receivers are loopback — that is why tests use
// NewClientAllowLoopback).
func TestNewClientRefusesLoopback(t *testing.T) {
	rcv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	}))
	defer rcv.Close()

	c := NewClient(2 * time.Second)
	_, err := c.Get(rcv.URL)
	if err == nil {
		t.Fatal("loopback request must be refused by the dial guard")
	}
}

// TestAllowLoopbackVariant: the test-only constructor reaches loopback.
func TestAllowLoopbackVariant(t *testing.T) {
	rcv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	}))
	defer rcv.Close()

	c := NewClientAllowLoopback(2 * time.Second)
	resp, err := c.Get(rcv.URL)
	if err != nil {
		t.Fatalf("loopback-allowed client failed: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("status = %d", resp.StatusCode)
	}
}
