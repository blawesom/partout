package auth_test

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/argon2"

	serverauth "github.com/blawesom/partout/internal/server/auth"
	"github.com/blawesom/partout/internal/store"
)

func newTestStore(t *testing.T) *store.Store {
	t.Helper()
	st, err := store.New("sqlite::memory:")
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	return st
}

func seedUser(t *testing.T, st *store.Store, name, pw, role string) {
	t.Helper()
	hash, err := serverauth.HashPassword(pw)
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	if err := st.CreatePrincipal(name, hash, role); err != nil {
		t.Fatalf("CreatePrincipal: %v", err)
	}
}

func TestHashPasswordRoundtrip(t *testing.T) {
	hash, err := serverauth.HashPassword("correct horse battery")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(hash, "argon2id$v=19$") {
		t.Fatalf("hash format: %q", hash)
	}
	if !serverauth.VerifyPassword(hash, "correct horse battery") {
		t.Fatal("verify: wrong password should pass")
	}
	if serverauth.VerifyPassword(hash, "wrong") {
		t.Fatal("verify: wrong password must fail")
	}
	if serverauth.VerifyPassword("garbage", "x") {
		t.Fatal("verify: malformed PHC must fail")
	}
}

// TestHashPasswordUniquePeppers verifies each hash uses a fresh pepper
// (same password → different PHC strings).
func TestHashPasswordUniquePeppers(t *testing.T) {
	h1, _ := serverauth.HashPassword("samepassword")
	h2, _ := serverauth.HashPassword("samepassword")
	if h1 == h2 {
		t.Fatal("two hashes of the same password must differ (pepper)")
	}
}

func TestValidatePassword(t *testing.T) {
	if err := serverauth.ValidatePassword("short"); err == nil {
		t.Fatal("short password should fail")
	}
	if err := serverauth.ValidatePassword(strings.Repeat("a", 101)); err == nil {
		t.Fatal("long password should fail")
	}
	if err := serverauth.ValidatePassword("goodpassword"); err != nil {
		t.Fatalf("valid password rejected: %v", err)
	}
}

func TestLoginValid(t *testing.T) {
	st := newTestStore(t)
	seedUser(t, st, "alice", "passw0rd!", "admin")
	c := serverauth.New(st, nil)

	sess, err := c.Login("alice", "passw0rd!")
	if err != nil {
		t.Fatalf("Login: %v", err)
	}
	if sess.Username != "alice" || sess.Role != "admin" || sess.Token == "" {
		t.Fatalf("bad session: %+v", sess)
	}
	if _, role, ok := c.RoleFor(sess.Token); !ok || role != "admin" {
		t.Fatal("RoleFor: expected admin")
	}
}

func TestLoginBadCredentials(t *testing.T) {
	st := newTestStore(t)
	seedUser(t, st, "alice", "passw0rd!", "admin")
	c := serverauth.New(st, nil)

	if _, err := c.Login("alice", "wrongpass"); err != serverauth.ErrBadCredentials {
		t.Fatalf("wrong password: got %v, want ErrBadCredentials", err)
	}
	if _, err := c.Login("nobody", "passw0rd!"); err != serverauth.ErrBadCredentials {
		t.Fatalf("unknown user: got %v, want ErrBadCredentials (no enumeration)", err)
	}
}

func TestLoginDisabledUser(t *testing.T) {
	st := newTestStore(t)
	seedUser(t, st, "alice", "passw0rd!", "operator")
	if err := st.SetPrincipalDisabled("alice", true); err != nil {
		t.Fatal(err)
	}
	c := serverauth.New(st, nil)
	if _, err := c.Login("alice", "passw0rd!"); err != serverauth.ErrBadCredentials {
		t.Fatalf("disabled user login: got %v", err)
	}
}

func TestSessionExpiry(t *testing.T) {
	st := newTestStore(t)
	seedUser(t, st, "alice", "passw0rd!", "viewer")
	c := serverauth.New(st, nil)
	c.SetTTL(30 * time.Millisecond)

	sess, err := c.Login("alice", "passw0rd!")
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(60 * time.Millisecond)
	if _, err := c.Validate(sess.Token); err != serverauth.ErrSessionExpired {
		t.Fatalf("expired session: got %v", err)
	}
}

func TestSessionUnknown(t *testing.T) {
	st := newTestStore(t)
	c := serverauth.New(st, nil)
	b := make([]byte, 32)
	rand.Read(b)
	if _, err := c.Validate(hex.EncodeToString(b)); err != serverauth.ErrSessionUnknown {
		t.Fatalf("unknown token: got %v", err)
	}
}

func TestLogout(t *testing.T) {
	st := newTestStore(t)
	seedUser(t, st, "alice", "passw0rd!", "viewer")
	c := serverauth.New(st, nil)
	sess, _ := c.Login("alice", "passw0rd!")
	c.Logout(sess.Token)
	if _, err := c.Validate(sess.Token); err != serverauth.ErrSessionUnknown {
		t.Fatalf("after logout: got %v", err)
	}
}

func TestChangePassword(t *testing.T) {
	st := newTestStore(t)
	seedUser(t, st, "alice", "oldpass123", "operator")
	c := serverauth.New(st, nil)
	sess, _ := c.Login("alice", "oldpass123")

	if err := c.ChangePassword("alice", "wrongold", "newpass123"); err != serverauth.ErrBadCredentials {
		t.Fatalf("wrong old password: got %v", err)
	}
	if err := c.ChangePassword("alice", "oldpass123", "newpass123"); err != nil {
		t.Fatalf("ChangePassword: %v", err)
	}
	// Old session invalidated.
	if _, err := c.Validate(sess.Token); err == nil {
		t.Fatal("old session must be invalidated after password change")
	}
	// Old password no longer works; new one does.
	if _, err := c.Login("alice", "oldpass123"); err != serverauth.ErrBadCredentials {
		t.Fatal("old password still valid")
	}
	if _, err := c.Login("alice", "newpass123"); err != nil {
		t.Fatalf("new password rejected: %v", err)
	}
}

func TestCreateUserGuards(t *testing.T) {
	st := newTestStore(t)
	c := serverauth.New(st, nil)

	if err := c.CreateUser("admin", "bob", "passw0rd1", "root"); err == nil {
		t.Fatal("invalid role should fail")
	}
	if err := c.CreateUser("admin", "bob", "short", "viewer"); err == nil {
		t.Fatal("weak password should fail")
	}
	if err := c.CreateUser("admin", "B ob", "passw0rd1", "viewer"); err == nil {
		t.Fatal("invalid username should fail")
	}
	if err := c.CreateUser("admin", "bob", "passw0rd1", "viewer"); err != nil {
		t.Fatalf("create: %v", err)
	}
	if err := c.CreateUser("admin", "bob", "passw0rd2", "viewer"); err == nil {
		t.Fatal("duplicate username should fail")
	}
}

func TestLastAdminProtection(t *testing.T) {
	st := newTestStore(t)
	seedUser(t, st, "root", "passw0rd1", "admin")
	c := serverauth.New(st, nil)

	// The single active admin cannot be demoted, disabled, or deleted.
	if err := c.SetRole("someone", "root", "viewer"); err != serverauth.ErrLastAdmin {
		t.Fatalf("demote last admin: got %v", err)
	}
	if err := c.SetDisabled("someone", "root", true); err != serverauth.ErrLastAdmin {
		t.Fatalf("disable last admin: got %v", err)
	}
	if err := c.DeleteUser("someone", "root"); err != serverauth.ErrLastAdmin {
		t.Fatalf("delete last admin: got %v", err)
	}

	// With a second admin, the first can be modified.
	seedUser(t, st, "root2", "passw0rd2", "admin")
	if err := c.SetRole("root2", "root", "viewer"); err != nil {
		t.Fatalf("demote with 2 admins: %v", err)
	}

	// Self-modification guards.
	if err := c.SetRole("root2", "root2", "viewer"); err == nil {
		t.Fatal("self role change should fail")
	}
	if err := c.SetDisabled("root2", "root2", true); err == nil {
		t.Fatal("self disable should fail")
	}
	if err := c.DeleteUser("root2", "root2"); err != serverauth.ErrSelfDelete {
		t.Fatalf("self delete: got %v", err)
	}
}

func TestBootstrapAdmin(t *testing.T) {
	st := newTestStore(t)
	c := serverauth.New(st, nil)
	if err := c.BootstrapAdmin("admin", "initialpass1"); err != nil {
		t.Fatalf("BootstrapAdmin: %v", err)
	}
	if _, err := c.Login("admin", "initialpass1"); err != nil {
		t.Fatalf("bootstrap login: %v", err)
	}
}

func TestGeneratePassword(t *testing.T) {
	pw, err := serverauth.GeneratePassword()
	if err != nil {
		t.Fatal(err)
	}
	if len(pw) != 16 {
		t.Fatalf("password length = %d, want 16", len(pw))
	}
	pw2, _ := serverauth.GeneratePassword()
	if pw == pw2 {
		t.Fatal("two generated passwords must differ")
	}
}

// TestVerifyPasswordArgon2Compat verifies the PHC string is parseable by a
// reference argon2 implementation (guards against format drift).
func TestVerifyPasswordArgon2Compat(t *testing.T) {
	hash, _ := serverauth.HashPassword("interop-test")
	fields := strings.Split(hash, "$")
	if len(fields) != 5 {
		t.Fatalf("bad PHC fields: %v", fields)
	}
	var m, tim, p uint32
	if _, err := fmt.Sscanf(fields[2], "m=%d,t=%d,p=%d", &m, &tim, &p); err != nil {
		t.Fatalf("parse params: %v", err)
	}
	pepper, _ := base64.RawStdEncoding.DecodeString(fields[3])
	want, _ := base64.RawStdEncoding.DecodeString(fields[4])
	got := argon2.IDKey([]byte("interop-test"), pepper, tim, m, uint8(p), uint32(len(want)))
	if string(got) != string(want) {
		t.Fatal("reference argon2.IDKey does not reproduce the stored hash")
	}
}

// --- login throttle, sweeper, timing equalizer (review fixes) -----------------

// TestLoginThrottle verifies consecutive failures lock a username out with
// backoff, that the lockout applies to correct passwords too, and that a
// successful login clears it.
func TestLoginThrottle(t *testing.T) {
	st := newTestStore(t)
	seedUser(t, st, "alice", "passw0rd!", "admin")
	c := serverauth.New(st, nil)
	c.SetThrottle(3, 200*time.Millisecond, 2*time.Second)

	// Two failures: still allowed through to the credential check.
	for i := 0; i < 2; i++ {
		if _, err := c.Login("alice", "wrong"); err != serverauth.ErrBadCredentials {
			t.Fatalf("attempt %d: got %v, want ErrBadCredentials", i+1, err)
		}
	}
	// Third failure arms the lockout.
	if _, err := c.Login("alice", "wrong"); err != serverauth.ErrBadCredentials {
		t.Fatalf("third failure: got %v", err)
	}
	// Even the correct password is rejected while throttled.
	if _, err := c.Login("alice", "passw0rd!"); err != serverauth.ErrThrottled {
		t.Fatalf("throttled attempt: got %v, want ErrThrottled", err)
	}
	// After the window, login succeeds and clears the state.
	time.Sleep(250 * time.Millisecond)
	if _, err := c.Login("alice", "passw0rd!"); err != nil {
		t.Fatalf("after backoff: %v", err)
	}
	if _, err := c.Login("alice", "passw0rd!"); err != nil {
		t.Fatalf("after reset: %v", err)
	}
}

// TestLoginThrottleCoversUnknownUsers verifies unknown usernames are throttled
// identically (no enumeration via lockout behaviour, and no unbounded growth:
// the map is capped).
func TestLoginThrottleCoversUnknownUsers(t *testing.T) {
	st := newTestStore(t)
	c := serverauth.New(st, nil)
	c.SetThrottle(2, 500*time.Millisecond, time.Second)

	c.Login("ghost", "x")
	c.Login("ghost", "x")
	if _, err := c.Login("ghost", "x"); err != serverauth.ErrThrottled {
		t.Fatalf("unknown user throttle: got %v, want ErrThrottled", err)
	}
}

// TestSessionCapPerUser verifies repeated logins by one user do not grow the
// session map without bound.
func TestSessionCapPerUser(t *testing.T) {
	st := newTestStore(t)
	seedUser(t, st, "alice", "passw0rd!", "viewer")
	c := serverauth.New(st, nil)

	first, err := c.Login("alice", "passw0rd!")
	if err != nil {
		t.Fatal(err)
	}
	// maxSessionsPerUser is 8: after 12 logins the oldest must be evicted.
	for i := 1; i < 12; i++ {
		if _, err := c.Login("alice", "passw0rd!"); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := c.Validate(first.Token); err == nil {
		t.Fatal("oldest session should have been evicted by the per-user cap")
	}
}

// TestDecoyHashMatchesHashParameters guards the timing equalizer: the decoy
// must use the same argon2id parameters as real hashes, or login latency
// would leak which usernames exist.
func TestDecoyHashMatchesHashParameters(t *testing.T) {
	decoy := serverauth.DecoyHashForTest()
	real, err := serverauth.HashPassword("whatever-password")
	if err != nil {
		t.Fatal(err)
	}
	params := func(phc string) string {
		f := strings.Split(phc, "$")
		if len(f) != 5 {
			t.Fatalf("bad PHC: %q", phc)
		}
		return strings.Join(f[:3], "$")
	}
	if params(decoy) != params(real) {
		t.Fatalf("decoy params %q != real params %q", params(decoy), params(real))
	}
	if serverauth.VerifyPassword(decoy, "anything") {
		t.Fatal("decoy hash must never verify successfully")
	}
}
