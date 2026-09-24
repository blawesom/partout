package auth

import (
	"testing"
	"time"

	"github.com/blawesom/partout/internal/store"
)

// TestSweepDropsExpiredSessions verifies the sweeper reclaims expired session
// tokens deterministically (no reliance on wall-clock login timing, which is
// flaky under -race): sessions are injected with explicit expiries.
func TestSweepDropsExpiredSessions(t *testing.T) {
	st, err := store.New("sqlite::memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	c := New(st, nil)

	now := time.Now()
	live := &Session{Token: "live", Username: "alice", Role: "viewer", Expires: now.Add(time.Hour)}
	c.sessions["live"] = live
	for i, tok := range []string{"exp1", "exp2", "exp3"} {
		c.sessions[tok] = &Session{
			Token: tok, Username: "alice", Role: "viewer",
			Expires: now.Add(-time.Duration(i+1) * time.Minute),
		}
	}

	got, _ := c.Sweep()
	if got != 3 {
		t.Fatalf("swept %d sessions, want 3", got)
	}
	if _, ok := c.sessions["live"]; !ok {
		t.Fatal("live session was swept")
	}
	if got, _ := c.Sweep(); got != 0 {
		t.Fatalf("second sweep removed %d, want 0", got)
	}
	if len(c.sessions) != 1 {
		t.Fatalf("sessions after sweep = %d, want 1", len(c.sessions))
	}
}

// TestSweepDropsStaleThrottleEntries verifies stale throttle state is
// reclaimed (bounded memory for attacker-chosen usernames).
func TestSweepDropsStaleThrottleEntries(t *testing.T) {
	st, _ := store.New("sqlite::memory:")
	defer st.Close()
	c := New(st, nil)

	c.throttled["stale"] = &throttle{last: time.Now().Add(-time.Hour)}
	c.throttled["fresh"] = &throttle{last: time.Now()}

	if _, got := c.Sweep(); got != 1 {
		t.Fatalf("swept %d throttle entries, want 1", got)
	}
	if _, ok := c.throttled["fresh"]; !ok {
		t.Fatal("fresh throttle entry was swept")
	}
}

// TestThrottleMapIsBounded verifies the throttle map cannot grow past its cap
// when an attacker sprays distinct usernames.
func TestThrottleMapIsBounded(t *testing.T) {
	st, _ := store.New("sqlite::memory:")
	defer st.Close()
	c := New(st, nil)
	c.SetThrottle(maxLoginFailures, time.Millisecond, time.Millisecond)

	// Fill past the cap, then prune-expire and keep going: the map must stay
	// bounded regardless.
	for i := 0; i < maxThrottleEntries+50; i++ {
		c.throttleFail(string(rune('a'+i%26)) + string(rune('a'+i/26)))
		if len(c.throttled) > maxThrottleEntries {
			t.Fatalf("throttle map grew to %d (cap %d)", len(c.throttled), maxThrottleEntries)
		}
	}
}
