// Package safehttp provides an HTTP client for server-side calls to
// operator-configured URLs (alert webhooks, ntfy channels) where the classic
// SSRF targets — loopback services and the cloud metadata endpoint — must
// never be reachable, even though the URL passed validation at rule-create
// time (DNS can re-resolve between check and dial).
//
// The guard runs in the dialer's Control hook, i.e. on the RESOLVED address
// at connect time, so DNS rebinding cannot bypass it. Private RFC1918 ranges
// stay ALLOWED: air-gapped fleets legitimately point alert channels at
// self-hosted ntfy/webhook receivers on the LAN. Loopback, link-local
// (169.254.0.0/16, which includes 169.254.169.254 metadata), unspecified, and
// multicast addresses are rejected.
package safehttp

import (
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"syscall"
	"time"
)

// disallowed reports whether an IP may not be dialed for server-side
// operator-configured egress.
func disallowed(ip netip.Addr) bool {
	return ip.IsLoopback() ||
		ip.IsLinkLocalUnicast() || // includes 169.254.169.254 (cloud metadata)
		ip.IsLinkLocalMulticast() ||
		ip.IsUnspecified() ||
		ip.IsMulticast()
}

// NewClient returns an *http.Client whose transport refuses to connect to
// disallowed IPs at dial time. timeout bounds the whole request.
func NewClient(timeout time.Duration) *http.Client {
	return newClient(timeout, false)
}

// NewClientAllowLoopback is NewClient with loopback/link-local permitted.
// TESTS ONLY: httptest receivers live on 127.0.0.1, and no production code
// path may use this constructor.
func NewClientAllowLoopback(timeout time.Duration) *http.Client {
	return newClient(timeout, true)
}

func newClient(timeout time.Duration, allowLoopback bool) *http.Client {
	d := &net.Dialer{
		Timeout:   10 * time.Second,
		KeepAlive: 30 * time.Second,
		Control: func(network, address string, c syscall.RawConn) error {
			host, _, err := net.SplitHostPort(address)
			if err != nil {
				return fmt.Errorf("safehttp: bad dial address %q: %w", address, err)
			}
			ip, err := netip.ParseAddr(host)
			if err != nil {
				// Not a literal IP: Control runs after resolution, so this
				// is unexpected — fail closed.
				return fmt.Errorf("safehttp: unresolved dial address %q", address)
			}
			if disallowed(ip) && !(allowLoopback && (ip.IsLoopback() || ip.IsLinkLocalUnicast())) {
				return fmt.Errorf("safehttp: refusing connection to disallowed address %s", ip)
			}
			return nil
		},
	}
	return &http.Client{
		Timeout:   timeout,
		Transport: &http.Transport{DialContext: d.DialContext},
	}
}
