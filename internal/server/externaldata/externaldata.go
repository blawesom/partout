// Package externaldata implements the server-side external data refresh
// (M3, PRD §6.3): OS end-of-support dates from endoflife.date and
// vulnerability correlation via OSV.dev.
//
// The server (which has outbound access) fetches and caches public feeds;
// agents never fetch these directly. EOL refresh is all-or-nothing: the
// cache is replaced only if every feed fetches and parses, otherwise the
// previous cache is left untouched (PRD §6.3). Vulnerability results are
// fetched on demand by list-updates correlation and TTL-cached in
// vuln_cache.
//
// PARTOUT_DISABLE_EXTERNAL_DATA_REFRESH disables all fetching (air-gapped
// deployments): the last cached copy applies, and correlation fails closed
// (no ranking — alphabetical fallback).
package externaldata

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/blawesom/partout/internal/store"
)

// eolDistros is the set of distros whose EOL feeds we track (endoflife.date
// project names).
var eolDistros = []string{
	"debian", "ubuntu", "rhel", "alpine", "rockylinux", "almalinux",
	"fedora", "centos", "oraclelinux", "opensuse",
}

// distroAlias maps /etc/os-release IDs to endoflife.date project names.
var distroAlias = map[string]string{
	"debian":   "debian",
	"ubuntu":   "ubuntu",
	"rhel":     "rhel",
	"alpine":   "alpine",
	"rocky":    "rockylinux",
	"alma":     "almalinux",
	"fedora":   "fedora",
	"centos":   "centos",
	"ol":       "oraclelinux",
	"opensuse": "opensuse",
}

// VulnTTL is how long a correlated vuln result is considered fresh.
const VulnTTL = time.Hour

// Refresher manages the EOL cache and vulnerability correlation.
type Refresher struct {
	st        *store.Store
	hc        *http.Client
	eolBase   string // endoflife.date API base
	osvBase   string // OSV.dev API base
	log       *log.Logger
	airGapped bool
}

// New builds a Refresher.
func New(st *store.Store, lg *log.Logger) *Refresher {
	if lg == nil {
		lg = log.Default()
	}
	return &Refresher{
		st:        st,
		hc:        &http.Client{Timeout: 60 * time.Second},
		eolBase:   "https://endoflife.date/api/",
		osvBase:   "https://api.osv.dev/v1/",
		log:       lg,
		airGapped: os.Getenv("PARTOUT_DISABLE_EXTERNAL_DATA_REFRESH") != "",
	}
}

// Status reports the external data subsystem for the REST API.
type Status struct {
	AirGapped  bool   `json:"air_gapped"`
	LastAt     int64  `json:"last_at"`     // unix ts of last successful refresh
	LastError  string `json:"last_error"`  // "" when the last refresh succeeded
	EOLCount   int    `json:"eol_count"`   // rows in the EOL cache
	VulnCached int    `json:"vuln_cached"` // rows in the vuln cache
}

// GetStatus reads the status (external_meta) and cache counts.
func (r *Refresher) GetStatus() Status {
	s := Status{AirGapped: r.airGapped}
	if lastAt, _ := r.st.GetExternalMeta("last_at"); lastAt != "" {
		s.LastAt, _ = strconv.ParseInt(lastAt, 10, 64)
	}
	s.LastError, _ = r.st.GetExternalMeta("last_error")
	if rows, err := r.st.ListEOLCache(); err == nil {
		s.EOLCount = len(rows)
	}
	if n, err := r.st.CountVulnsCached(); err == nil {
		s.VulnCached = n
	}
	return s
}

// DoRefresh fetches all EOL feeds and replaces the cache all-or-nothing
// (PRD §6.3). Returns the number of rows written; 0 when air-gapped.
func (r *Refresher) DoRefresh(ctx context.Context) (int, error) {
	if r.airGapped {
		return 0, nil
	}
	batches := make([][]store.EOLRow, 0, len(eolDistros))
	for _, d := range eolDistros {
		b, err := r.fetchJSON(ctx, r.eolBase+d+".json")
		if err != nil {
			r.failRefresh(fmt.Sprintf("eol %s: %v", d, err))
			return 0, err
		}
		rows, err := parseEOL(d, b)
		if err != nil {
			r.failRefresh(fmt.Sprintf("eol %s: %v", d, err))
			return 0, err
		}
		batches = append(batches, rows)
	}
	rows := make([]store.EOLRow, 0)
	for _, b := range batches {
		rows = append(rows, b...)
	}
	if err := r.st.ReplaceEOLCache(rows); err != nil {
		r.failRefresh("store: " + err.Error())
		return 0, err
	}
	now := time.Now().Unix()
	_ = r.st.SetExternalMeta("last_at", strconv.FormatInt(now, 10))
	_ = r.st.SetExternalMeta("last_error", "")
	r.log.Printf("externaldata: refreshed EOL cache (%d rows, %d distros)", len(rows), len(eolDistros))
	return len(rows), nil
}

// failRefresh records the failure and logs one line (previous cache kept).
func (r *Refresher) failRefresh(msg string) {
	_ = r.st.SetExternalMeta("last_error", msg)
	r.log.Printf("externaldata: refresh failed (%s) — keeping previous cache", msg)
}

// EOLState is a host's support state computed from the EOL cache.
type EOLState struct {
	State        string `json:"state"` // supported|ending_soon|ended|unknown
	Distro       string `json:"distro"`
	Cycle        string `json:"cycle"`
	EOLDate      string `json:"eol_date,omitempty"`
	Extended     string `json:"extended_support,omitempty"`
	CacheAgeDays int64  `json:"cache_age_days"`
}

// EOLStateFor computes the EOL state for a host from its os-release facts
// (distro = host.distro, cycle = host.distro_version). Unknown distro or
// empty cache → "unknown" (patch gating treats unknown as not-ended).
func (r *Refresher) EOLStateFor(distro, cycle string) EOLState {
	st := EOLState{Distro: distro, Cycle: cycle, State: "unknown"}
	rows, err := r.st.ListEOLCache()
	if err != nil || len(rows) == 0 {
		return st
	}
	proj, ok := distroAlias[distro]
	if !ok {
		proj = distro
	}
	match := -1
	var newest int64
	for i, row := range rows {
		if row.Distro != proj || row.Cycle != cycle {
			continue
		}
		match = i
		if row.FetchedAt > newest {
			newest = row.FetchedAt
		}
	}
	if match < 0 {
		return st
	}
	m := rows[match]
	now := time.Now()
	st.State = "supported"
	if eol, err := time.Parse("2006-01-02", m.EOLDate); err == nil {
		switch {
		case now.After(eol):
			// EOL passed. Extended/LTS support may still be active.
			if end := parseDate(m.ExtendedSupport); !end.IsZero() && now.Before(end) {
				st.State = "ending_soon" // past EOL, in extended support
			} else if sup := parseDate(m.SupportDate); !sup.IsZero() && now.Before(sup) {
				st.State = "ending_soon"
			} else {
				st.State = "ended"
			}
		case now.AddDate(0, 6, 0).After(eol):
			st.State = "ending_soon" // EOL within 6 months
		}
	}
	st.EOLDate = m.EOLDate
	st.Extended = m.ExtendedSupport
	st.CacheAgeDays = (now.Unix() - newest) / 86400
	return st
}

// Correlate returns vulnerabilities for (pkg, ecosystem, version) via
// OSV.dev, TTL-cached in vuln_cache (VulnTTL). When the cache is fresh, no
// network call is made. Air-gapped → (nil, nil) so the caller falls back
// to unranked ordering. An empty result is also cached (short TTL) to
// avoid hammering OSV for clean packages.
func (r *Refresher) Correlate(ctx context.Context, pkg, ecosystem, version string) ([]store.VulnRow, error) {
	if ecosystem == "" {
		return nil, nil // distro not covered by OSV
	}
	rows, err := r.st.GetVulnsForVersion(pkg, ecosystem, version)
	if err != nil {
		return nil, err
	}
	if len(rows) > 0 && rows[0].VulnID != "-" && time.Since(time.Unix(rows[0].FetchedAt, 0)) < VulnTTL {
		return rows, nil
	}
	if len(rows) > 0 && rows[0].VulnID == "-" && time.Since(time.Unix(rows[0].FetchedAt, 0)) < VulnTTL {
		return nil, nil // cached "clean" result
	}
	if r.airGapped {
		if len(rows) > 0 && rows[0].VulnID != "-" {
			return rows, nil // stale cache is better than nothing offline
		}
		return nil, nil
	}
	fresh, err := r.osvQuery(ctx, pkg, ecosystem, version)
	if err != nil {
		if len(rows) > 0 && rows[0].VulnID != "-" {
			return rows, nil // fall back to stale cache
		}
		return nil, err
	}
	return fresh, nil
}

// ---- OSV.dev ---------------------------------------------------------------

type osvQueryReq struct {
	Queries []osvQuery `json:"queries"`
}

type osvQuery struct {
	Package struct {
		Name      string `json:"name"`
		Ecosystem string `json:"ecosystem"`
	} `json:"package"`
	Version string `json:"version"`
}

type osvVulnEntry struct {
	ID      string   `json:"id"`
	Aliases []string `json:"aliases"`
}

type osvBatchResult struct {
	Vulns []osvVulnEntry `json:"vulns"`
}

type osvBatchResp struct {
	Results []osvBatchResult `json:"results"`
}

// osvQuery hits OSV.dev's batch query API for one package/version and
// stores the result in the vuln cache (empty list included, with a shorter
// TTL via fetched_at = now - TTL/2 so it re-checks sooner).
func (r *Refresher) osvQuery(ctx context.Context, pkg, ecosystem, version string) ([]store.VulnRow, error) {
	q := osvQueryReq{}
	q.Queries = append(q.Queries, osvQuery{Version: version})
	q.Queries[0].Package.Name = pkg
	q.Queries[0].Package.Ecosystem = ecosystem
	body, err := json.Marshal(q)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, "POST", r.osvBase+"querybatch", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := r.hc.Do(req)
	if err != nil {
		return nil, fmt.Errorf("osv: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 256))
		return nil, fmt.Errorf("osv: status %d: %s", resp.StatusCode, string(b))
	}
	var out osvBatchResp
	if err := json.NewDecoder(io.LimitReader(resp.Body, 10<<20)).Decode(&out); err != nil {
		return nil, fmt.Errorf("osv: decode: %w", err)
	}
	if len(out.Results) == 0 {
		return nil, fmt.Errorf("osv: no result")
	}
	vulns := out.Results[0].Vulns
	now := time.Now().Unix()
	rows := make([]store.VulnRow, 0, len(vulns))
	for _, v := range vulns {
		rows = append(rows, store.VulnRow{
			VulnID:    v.ID,
			Package:   pkg,
			Ecosystem: ecosystem,
			Version:   version,
			FetchedAt: now,
		})
	}
	if len(rows) == 0 {
		// Cache the "clean" result so we don't re-query for clean packages
		// within the TTL: store a tombstone row (vuln_id = "-").
		rows = append(rows, store.VulnRow{
			VulnID: "-", Package: pkg, Ecosystem: ecosystem,
			Version: version, FetchedAt: now,
		})
	}
	if err := r.st.InsertVulns(rows); err != nil {
		return nil, err
	}
	if len(rows) == 1 && rows[0].VulnID == "-" {
		return nil, nil // clean
	}
	return rows, nil
}

// ---- HTTP / parsing --------------------------------------------------------

// fetchJSON GETs url and returns the body (10 MiB cap).
func (r *Refresher) fetchJSON(ctx context.Context, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := r.hc.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("status %d", resp.StatusCode)
	}
	return io.ReadAll(io.LimitReader(resp.Body, 10<<20))
}

// eolCycle is one endoflife.date cycle object. Fields are kept loose: the
// API uses "null", a date string, or a bool for support windows depending on
// the distro, so we parse into json.RawMessage and normalize.
type eolCycle struct {
	Cycle       string          `json:"cycle"`
	Codename    string          `json:"codename"`
	ReleaseDate string          `json:"releaseDate"`
	EOL         json.RawMessage `json:"eol"`
	Support     json.RawMessage `json:"support"`
	Extended    json.RawMessage `json:"extendedSupport"`
	Latest      string          `json:"latest"`
}

// eolDate normalizes an endoflife.date date field, which may be a date
// string ("2030-06-30"), null, or a bool. Returns the empty string for
// non-date values.
func eolDate(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		return s
	}
	return ""
}

func parseEOL(distro string, b []byte) ([]store.EOLRow, error) {
	var cycles []eolCycle
	if err := json.Unmarshal(b, &cycles); err != nil {
		return nil, fmt.Errorf("decode: %w", err)
	}
	if len(cycles) == 0 {
		return nil, fmt.Errorf("empty feed")
	}
	rows := make([]store.EOLRow, 0, len(cycles))
	for _, c := range cycles {
		eol := eolDate(c.EOL)
		if c.Cycle == "" || eol == "" {
			continue // future/in-support cycles with no EOL date yet
		}
		rows = append(rows, store.EOLRow{
			Distro:          distro,
			Cycle:           c.Cycle,
			Codename:        c.Codename,
			ReleaseDate:     c.ReleaseDate,
			EOLDate:         eol,
			SupportDate:     eolDate(c.Support),
			ExtendedSupport: eolDate(c.Extended),
			Latest:          c.Latest,
		})
	}
	if len(rows) == 0 {
		return nil, fmt.Errorf("no parseable cycles")
	}
	return rows, nil
}

func parseDate(s string) time.Time {
	t, _ := time.Parse("2006-01-02", s)
	return t
}

// OSVEcosystem maps (distro, version) to the OSV.dev ecosystem string for
// vulnerability queries. Returns "" when the distro is not covered (v1
// covers Debian, Ubuntu, and the RHEL family; other distros fall back to
// unranked updates).
func OSVEcosystem(distro, version string) string {
	switch distro {
	case "debian":
		return "Debian:" + majorVersion(version)
	case "ubuntu":
		return "Ubuntu:" + version
	case "rhel", "rocky", "alma", "ol", "centos":
		return "RedHat:" + majorVersion(version)
	}
	return ""
}

func majorVersion(v string) string {
	if i := strings.IndexByte(v, '.'); i > 0 {
		return v[:i]
	}
	return v
}
