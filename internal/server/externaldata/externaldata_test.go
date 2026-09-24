package externaldata

import (
	"context"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/blawesom/partout/internal/store"
)

// eolFixture returns JSON mimicking endoflife.date with the mixed
// extendedSupport types (string / bool / absent) the real feeds use.
func eolFixture() string {
	return `[
		{"cycle":"12","codename":"Bookworm","releaseDate":"2023-06-10","eol":"2028-06-30","latest":"12.15","lts":false,"support":"2031-06-10","extendedSupport":"2035-06-30"},
		{"cycle":"10","codename":"Bullseye","releaseDate":"2021-08-14","eol":"2026-06-30","latest":"10.15","lts":false,"support":false,"extendedSupport":true},
		{"cycle":"13","codename":"Trixie","releaseDate":"2025-08-09","eol":"2030-06-30","latest":"13.7"}
	]`
}

func newTestRefresher(t *testing.T, serverURL string) (*Refresher, *store.Store) {
	t.Helper()
	st, err := store.New("sqlite::memory:")
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	r := New(st, log.New(io.Discard, "", 0))
	if serverURL != "" {
		r.eolBase = serverURL + "/api/"
	}
	return r, st
}

func TestParseEOLMixedTypes(t *testing.T) {
	rows, err := parseEOL("debian", []byte(eolFixture()))
	if err != nil {
		t.Fatalf("parseEOL: %v", err)
	}
	if len(rows) != 3 {
		t.Fatalf("rows = %d, want 3", len(rows))
	}
	// Row 1: string extendedSupport.
	if rows[0].ExtendedSupport != "2035-06-30" || rows[0].EOLDate != "2028-06-30" {
		t.Fatalf("row0 = %+v", rows[0])
	}
	// Row 2: bool extendedSupport / support → normalized to "".
	if rows[1].ExtendedSupport != "" || rows[1].SupportDate != "" {
		t.Fatalf("row2 (bool fields) = %+v", rows[1])
	}
	// Row 3: absent fields → "".
	if rows[2].ExtendedSupport != "" || rows[2].Codename != "Trixie" {
		t.Fatalf("row3 = %+v", rows[2])
	}
}

func TestRefreshAllOrNothing(t *testing.T) {
	// First: one feed fails → cache stays empty.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "rhel.json") {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		io.WriteString(w, eolFixture())
	}))
	t.Cleanup(srv.Close)
	r, st := newTestRefresher(t, srv.URL)

	if n, err := r.DoRefresh(context.Background()); err == nil {
		t.Fatalf("DoRefresh: want error (rhel 500), got n=%d", n)
	}
	rows, _ := st.ListEOLCache()
	if len(rows) != 0 {
		t.Fatalf("cache after failed refresh = %d rows, want 0", len(rows))
	}
	if msg, _ := st.GetExternalMeta("last_error"); msg == "" {
		t.Fatal("last_error not set after failed refresh")
	}

	// Second: all feeds OK → cache replaced.
	srv2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, eolFixture())
	}))
	t.Cleanup(srv2.Close)
	r.eolBase = srv2.URL + "/api/"
	n, err := r.DoRefresh(context.Background())
	if err != nil {
		t.Fatalf("DoRefresh: %v", err)
	}
	if n != len(eolDistros)*3 {
		t.Fatalf("rows = %d, want %d", n, len(eolDistros)*3)
	}
	if msg, _ := st.GetExternalMeta("last_error"); msg != "" {
		t.Fatalf("last_error = %q after success", msg)
	}
}

func TestEOLStateFor(t *testing.T) {
	// Build a cache by hand.
	st, err := store.New("sqlite::memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	now := time.Now()
	eolSoon := now.AddDate(0, 3, 0).Format("2006-01-02")  // 3 months out
	eolPast := now.AddDate(0, -3, 0).Format("2006-01-02") // 3 months ago
	eolFar := now.AddDate(2, 0, 0).Format("2006-01-02")
	rows := []store.EOLRow{
		{Distro: "ubuntu", Cycle: "20.04", EOLDate: eolPast, FetchedAt: now.Unix()}, // ended
		{Distro: "ubuntu", Cycle: "22.04", EOLDate: eolSoon, FetchedAt: now.Unix()}, // ending_soon
		{Distro: "ubuntu", Cycle: "24.04", EOLDate: eolFar, FetchedAt: now.Unix()},  // supported
		{Distro: "debian", Cycle: "12", EOLDate: eolFar,
			ExtendedSupport: now.AddDate(2, 0, 0).Format("2006-01-02"), FetchedAt: now.Unix()},
	}
	if err := st.ReplaceEOLCache(rows); err != nil {
		t.Fatal(err)
	}
	r := New(st, log.New(io.Discard, "", 0))

	if s := r.EOLStateFor("ubuntu", "20.04"); s.State != "ended" {
		t.Fatalf("20.04 = %q, want ended: %+v", s.State, s)
	}
	if s := r.EOLStateFor("ubuntu", "22.04"); s.State != "ending_soon" {
		t.Fatalf("22.04 = %q, want ending_soon: %+v", s.State, s)
	}
	if s := r.EOLStateFor("ubuntu", "24.04"); s.State != "supported" {
		t.Fatalf("24.04 = %q, want supported: %+v", s.State, s)
	}
	// Unknown distro → unknown.
	if s := r.EOLStateFor("gentoo", "any"); s.State != "unknown" {
		t.Fatalf("gentoo = %q, want unknown", s.State)
	}
	// Aliased distro (rocky → rockylinux): no row → unknown.
	if s := r.EOLStateFor("rocky", "9"); s.State != "unknown" {
		t.Fatalf("rocky 9 = %q, want unknown (no rockylinux rows)", s.State)
	}
}

// TestCorrelateOSV uses a fake OSV server.
func TestCorrelateOSV(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/querybatch" {
			http.NotFound(w, r)
			return
		}
		_, _ = io.ReadAll(r.Body) // discard request body
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"results":[{"vulns":[{"id":"DEBIAN-CVE-2026-0001"},{"id":"DEBIAN-CVE-2026-0002"}]}]}`)

	}))
	t.Cleanup(srv.Close)

	st, err := store.New("sqlite::memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	r := New(st, log.New(io.Discard, "", 0))
	r.osvBase = srv.URL + "/v1/"

	rows, err := r.Correlate(context.Background(), "nginx", "Debian:12", "1.22.1")
	if err != nil {
		t.Fatalf("Correlate: %v", err)
	}
	if len(rows) != 2 {
		t.Fatalf("vulns = %d, want 2", len(rows))
	}
	// Second call hits the cache (no network):
	rows2, err := r.Correlate(context.Background(), "nginx", "Debian:12", "1.22.1")
	if err != nil {
		t.Fatal(err)
	}
	if len(rows2) != 2 {
		t.Fatalf("cached vulns = %d, want 2", len(rows2))
	}
	// Clean package → tombstone cached, second call returns (nil, nil).
	srvClean := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, `{"results":[{"vulns":[]}]}`)
	}))
	t.Cleanup(srvClean.Close)
	r.osvBase = srvClean.URL + "/v1/"
	if rows, err := r.Correlate(context.Background(), "hello", "Debian:12", "2.12-1"); err != nil || len(rows) != 0 {
		t.Fatalf("clean package: rows=%d err=%v", len(rows), err)
	}
	if rows, err := r.Correlate(context.Background(), "hello", "Debian:12", "2.12-1"); err != nil || len(rows) != 0 {
		t.Fatalf("cached clean: rows=%d err=%v", len(rows), err)
	}
}
