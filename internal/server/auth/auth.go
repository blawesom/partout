// Package auth implements local user identity (PRD Decision 6):
// username + argon2id password (per-user pepper), session tokens with a
// TTL, and admin user management. No OIDC (post-v1).
//
// Security model:
//   - Passwords are hashed with argon2id (OWASP parameters) and a fresh
//     random 16-byte pepper per password set; only the PHC string is stored.
//   - Login issues a random 256-bit bearer token valid for the session TTL
//     (default 12 h). Tokens live in memory: a server restart logs everyone
//     out (accepted v1 posture; the audit log records logins).
//   - A password change invalidates that user's sessions.
//   - Login failures are throttled per username with exponential backoff
//     (see SetThrottle); unknown usernames are throttled identically.
//   - Unknown/disabled usernames still pay a full argon2 verification
//     against a decoy hash, so response time does not disclose which
//     usernames exist.
//   - Last-admin protection: the last active admin cannot be deleted,
//     disabled, or demoted. Users cannot delete themselves.
package auth

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/argon2"

	"github.com/blawesom/partout/internal/store"
)

// Argon2id parameters (OWASP recommendation, 2024+).
const (
	argonTime    = 3
	argonMemory  = 64 * 1024 // 64 MiB
	argonThreads = 4
	argonKeyLen  = 32
	pepperLen    = 16
)

var (
	ErrBadCredentials = errors.New("auth: bad credentials")
	ErrSessionExpired = errors.New("auth: session expired")
	ErrSessionUnknown = errors.New("auth: unknown session token")
	ErrUserDisabled   = errors.New("auth: user disabled")
	ErrWeakPassword   = errors.New("auth: password must be 8-100 characters")
	ErrLastAdmin      = errors.New("auth: cannot remove the last active admin")
	ErrSelfDelete     = errors.New("auth: cannot delete your own account")
	ErrSelfModify     = errors.New("auth: cannot change your own account")
	ErrThrottled      = errors.New("auth: too many failed attempts; retry later")
)

// decoyHash is a valid argon2id PHC string (same parameters as HashPassword)
// verified against for unknown/disabled usernames so that login latency does
// not reveal which accounts exist. The password it encodes is never accepted:
// the result is discarded.
const decoyHash = "argon2id$v=19$m=65536,t=3,p=4$ad/jeXxztGN89/QaZL57DA$oQYRtPAtHvaWIMRfBhZtAJG73FhYKHdpGrC025xYV14"

// DecoyHashForTest exposes the decoy PHC string so tests can assert it uses
// the same argon2id parameters as HashPassword (timing-equalizer invariant).
func DecoyHashForTest() string { return decoyHash }

// Login throttle defaults: after maxLoginFailures consecutive failures for a
// username, attempts back off exponentially up to maxThrottle. Throttle state
// is in-memory and bounded (maxThrottleEntries), so it cannot be used to grow
// memory without limit.
const (
	maxLoginFailures   = 5
	baseThrottle       = 2 * time.Second
	maxThrottle        = 5 * time.Minute
	maxThrottleEntries = 4096
	maxSessionsPerUser = 8
)

// Session is a validated login.
type Session struct {
	Token       string
	Username    string
	Role        string
	Expires     time.Time
	ExpiresUnix int64
}

// throttle tracks consecutive login failures for one username.
type throttle struct {
	fails int
	until time.Time // attempts rejected before this instant
	last  time.Time // last failure (for lazy pruning)
}

// Controller manages principals + sessions.
type Controller struct {
	st       *store.Store
	log      *log.Logger
	ttl      time.Duration
	sessMu   sync.Mutex
	sessions map[string]*Session

	// Login throttle (bounded, in-memory). Config via SetThrottle.
	thrMu        sync.Mutex
	throttled    map[string]*throttle
	maxFails     int
	baseThrottle time.Duration
	maxThrottle  time.Duration
}

// New builds a Controller with the given session TTL (0 → 12 h).
func New(st *store.Store, lg *log.Logger) *Controller {
	if lg == nil {
		lg = log.Default()
	}
	return &Controller{
		st: st, log: lg, ttl: 12 * time.Hour,
		sessions:     make(map[string]*Session),
		throttled:    make(map[string]*throttle),
		maxFails:     maxLoginFailures,
		baseThrottle: baseThrottle,
		maxThrottle:  maxThrottle,
	}
}

// SetTTL overrides the session TTL.
func (c *Controller) SetTTL(d time.Duration) {
	if d > 0 {
		c.ttl = d
	}
}

// SetThrottle overrides the login backoff policy (0 values keep the default).
// maxFails consecutive failures lock a username out for baseThrottle, doubling
// per further failure up to max. Operators can lower maxFails to harden a
// deployment; tests use it to exercise the path quickly.
func (c *Controller) SetThrottle(maxFails int, base, max time.Duration) {
	if maxFails > 0 {
		c.maxFails = maxFails
	}
	if base > 0 {
		c.baseThrottle = base
	}
	if max > 0 {
		c.maxThrottle = max
	}
}

// --- password hashing (PHC argon2id) ---------------------------------------

// HashPassword encodes password with argon2id + a fresh pepper.
func HashPassword(password string) (string, error) {
	pepper := make([]byte, pepperLen)
	if _, err := rand.Read(pepper); err != nil {
		return "", fmt.Errorf("auth: pepper: %w", err)
	}
	hash := argon2.IDKey([]byte(password), pepper, argonTime, argonMemory, argonThreads, argonKeyLen)
	enc := func(b []byte) string { return base64.RawStdEncoding.EncodeToString(b) }
	return fmt.Sprintf("argon2id$v=19$m=%d,t=%d,p=%d$%s$%s",
		argonMemory, argonTime, argonThreads, enc(pepper), enc(hash)), nil
}

// VerifyPassword checks a PHC argon2id string against a password
// (constant-time on the derived hash).
func VerifyPassword(phc, password string) bool {
	fields := strings.Split(phc, "$")
	if len(fields) != 5 || fields[0] != "argon2id" || fields[1] != "v=19" {
		return false
	}
	var m, t, p uint32
	if _, err := fmt.Sscanf(fields[2], "m=%d,t=%d,p=%d", &m, &t, &p); err != nil {
		return false
	}
	pepper, err := base64.RawStdEncoding.DecodeString(fields[3])
	if err != nil || len(pepper) != pepperLen {
		return false
	}
	want, err := base64.RawStdEncoding.DecodeString(fields[4])
	if err != nil || len(want) != argonKeyLen {
		return false
	}
	got := argon2.IDKey([]byte(password), pepper, t, m, uint8(p), argonKeyLen)
	return subtle.ConstantTimeCompare(got, want) == 1
}

// ValidatePassword enforces the password policy.
func ValidatePassword(pw string) error {
	if len(pw) < 8 || len(pw) > 100 {
		return ErrWeakPassword
	}
	return nil
}

// --- session tokens ----------------------------------------------------------

func newToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// Login authenticates username/password and issues a session token.
// Audits auth.login / auth.login_failed / auth.login_throttled.
//
// Unknown and disabled usernames pay a decoy argon2 verification so latency
// does not disclose which accounts exist, and consecutive failures throttle
// the username (unknown ones included) with exponential backoff.
func (c *Controller) Login(username, password string) (*Session, error) {
	if wait, until := c.throttleCheck(username); wait {
		c.audit("auth.login_throttled", username, "retry after "+until.UTC().Format(time.RFC3339))
		return nil, ErrThrottled
	}

	p, err := c.st.Principal(username)
	if err != nil || p.Disabled {
		VerifyPassword(decoyHash, password) // equalize timing; result discarded
		c.throttleFail(username)
		c.audit("auth.login_failed", username, "bad credentials")
		return nil, ErrBadCredentials
	}
	if !VerifyPassword(p.PasswordHash, password) {
		c.throttleFail(username)
		c.audit("auth.login_failed", username, "bad credentials")
		return nil, ErrBadCredentials
	}
	c.throttleReset(username)

	tok, err := newToken()
	if err != nil {
		return nil, err
	}
	now := time.Now()
	sess := &Session{
		Token: tok, Username: p.Username, Role: p.Role,
		Expires: now.Add(c.ttl), ExpiresUnix: now.Add(c.ttl).Unix(),
	}
	c.sessMu.Lock()
	c.pruneSessionsLocked(now)
	c.evictUserSessionsLocked(p.Username)
	c.sessions[tok] = sess
	c.sessMu.Unlock()
	c.audit("auth.login", p.Username, "ok")
	return sess, nil
}

// --- login throttle -----------------------------------------------------------

// throttleCheck reports whether attempts for username are currently rejected,
// and until when.
func (c *Controller) throttleCheck(username string) (bool, time.Time) {
	now := time.Now()
	c.thrMu.Lock()
	defer c.thrMu.Unlock()
	t, ok := c.throttled[username]
	if !ok {
		return false, time.Time{}
	}
	if now.Before(t.until) {
		return true, t.until
	}
	return false, time.Time{}
}

// throttleFail records a failure and arms the backoff window.
func (c *Controller) throttleFail(username string) {
	now := time.Now()
	c.thrMu.Lock()
	defer c.thrMu.Unlock()
	c.pruneThrottleLocked(now)
	t, ok := c.throttled[username]
	if !ok {
		// Bound the map: attacker-chosen usernames must not grow memory.
		if len(c.throttled) >= maxThrottleEntries {
			return
		}
		t = &throttle{}
		c.throttled[username] = t
	}
	t.fails++
	t.last = now
	if t.fails >= c.maxFails {
		d := c.baseThrottle << uint(min(t.fails-c.maxFails, 16))
		if d <= 0 || d > c.maxThrottle {
			d = c.maxThrottle
		}
		t.until = now.Add(d)
	}
}

// throttleReset clears a username's failure state after a successful login.
func (c *Controller) throttleReset(username string) {
	c.thrMu.Lock()
	delete(c.throttled, username)
	c.thrMu.Unlock()
}

// pruneThrottleLocked drops entries whose backoff has expired and whose last
// failure is old. Caller holds thrMu.
func (c *Controller) pruneThrottleLocked(now time.Time) {
	for u, t := range c.throttled {
		if now.After(t.until) && now.Sub(t.last) > c.maxThrottle {
			delete(c.throttled, u)
		}
	}
}

// --- session housekeeping --------------------------------------------------------

// Sweep drops expired sessions and stale throttle entries, returning how many
// of each were removed. Safe to call concurrently; wire it to a ticker.
func (c *Controller) Sweep() (sessions, throttled int) {
	now := time.Now()
	c.sessMu.Lock()
	n := c.pruneSessionsLocked(now)
	c.sessMu.Unlock()
	c.thrMu.Lock()
	before := len(c.throttled)
	c.pruneThrottleLocked(now)
	m := before - len(c.throttled)
	c.thrMu.Unlock()
	return n, m
}

// pruneSessionsLocked removes expired sessions. Caller holds sessMu.
func (c *Controller) pruneSessionsLocked(now time.Time) int {
	n := 0
	for tok, s := range c.sessions {
		if now.After(s.Expires) {
			delete(c.sessions, tok)
			n++
		}
	}
	return n
}

// evictUserSessionsLocked keeps at most maxSessionsPerUser sessions per user,
// dropping the ones that expire soonest. Caller holds sessMu.
func (c *Controller) evictUserSessionsLocked(username string) {
	if maxSessionsPerUser <= 0 {
		return
	}
	var mine []*Session
	for _, s := range c.sessions {
		if s.Username == username {
			mine = append(mine, s)
		}
	}
	for len(mine) >= maxSessionsPerUser {
		oldest := mine[0]
		for _, s := range mine[1:] {
			if s.Expires.Before(oldest.Expires) {
				oldest = s
			}
		}
		delete(c.sessions, oldest.Token)
		for i, s := range mine {
			if s == oldest {
				mine = append(mine[:i], mine[i+1:]...)
				break
			}
		}
	}
}

// Validate checks a session token (expiry enforced; expired sessions are
// evicted). Returns the role for RBAC.
func (c *Controller) Validate(token string) (*Session, error) {
	c.sessMu.Lock()
	defer c.sessMu.Unlock()
	sess, ok := c.sessions[token]
	if !ok {
		return nil, ErrSessionUnknown
	}
	if time.Now().After(sess.Expires) {
		delete(c.sessions, token)
		return nil, ErrSessionExpired
	}
	return sess, nil
}

// Logout invalidates one session token.
func (c *Controller) Logout(token string) {
	c.sessMu.Lock()
	delete(c.sessions, token)
	c.sessMu.Unlock()
}

// InvalidateUserSessions kills every session for a user (password change,
// disable, role change).
func (c *Controller) InvalidateUserSessions(username string) {
	c.sessMu.Lock()
	defer c.sessMu.Unlock()
	for tok, s := range c.sessions {
		if s.Username == username {
			delete(c.sessions, tok)
		}
	}
}

// RoleFor resolves a bearer token to an RBAC role ("" if invalid).
func (c *Controller) RoleFor(token string) (username string, role string, ok bool) {
	s, err := c.Validate(token)
	if err != nil {
		return "", "", false
	}
	return s.Username, s.Role, true
}

// --- password management -----------------------------------------------------

// ChangePassword verifies the old password, sets the new one, and kills
// the user's sessions.
func (c *Controller) ChangePassword(username, oldPassword, newPassword string) error {
	if err := ValidatePassword(newPassword); err != nil {
		return err
	}
	p, err := c.st.Principal(username)
	if err != nil {
		return ErrBadCredentials
	}
	if !VerifyPassword(p.PasswordHash, oldPassword) {
		return ErrBadCredentials
	}
	hash, err := HashPassword(newPassword)
	if err != nil {
		return err
	}
	if err := c.st.SetPrincipalPassword(username, hash); err != nil {
		return err
	}
	c.InvalidateUserSessions(username)
	c.audit("auth.password_changed", username, "ok")
	return nil
}

// ResetPassword is the admin path (no old password required); kills the
// user's sessions.
func (c *Controller) ResetPassword(actor, username, newPassword string) error {
	if err := ValidatePassword(newPassword); err != nil {
		return err
	}
	if _, err := c.st.Principal(username); err != nil {
		return err
	}
	hash, err := HashPassword(newPassword)
	if err != nil {
		return err
	}
	if err := c.st.SetPrincipalPassword(username, hash); err != nil {
		return err
	}
	c.InvalidateUserSessions(username)
	c.audit("auth.password_reset", username, "by "+actor)
	return nil
}

// --- user management (admin) ---------------------------------------------------

// validRoles is the RBAC role set.
var validRoles = map[string]bool{"viewer": true, "operator": true, "admin": true}

// ValidRole reports whether role is a known RBAC role.
func ValidRole(role string) bool { return validRoles[role] }

// CreateUser creates a user (admin path).
func (c *Controller) CreateUser(actor, username, password, role string) error {
	if !ValidRole(role) {
		return fmt.Errorf("auth: invalid role %q", role)
	}
	if !validUsername(username) {
		return errors.New("auth: username must be 3-32 chars [a-z0-9._-]")
	}
	if err := ValidatePassword(password); err != nil {
		return err
	}
	hash, err := HashPassword(password)
	if err != nil {
		return err
	}
	if err := c.st.CreatePrincipal(username, hash, role); err != nil {
		return fmt.Errorf("auth: create %s: %w", username, err)
	}
	c.audit("user.created", username, "by "+actor+" role="+role)
	return nil
}

// SetRole changes a user's role (last-admin guard) and kills their
// sessions.
func (c *Controller) SetRole(actor, username, newRole string) error {
	if !ValidRole(newRole) {
		return fmt.Errorf("auth: invalid role %q", newRole)
	}
	if username == actor {
		return ErrSelfModify
	}
	p, err := c.st.Principal(username)
	if err != nil {
		return err
	}
	if p.Role == "admin" && newRole != "admin" {
		if n, _ := c.st.CountActiveAdmins(); n <= 1 {
			return ErrLastAdmin
		}
	}
	if err := c.st.SetPrincipalRole(username, newRole); err != nil {
		return err
	}
	c.InvalidateUserSessions(username)
	c.audit("user.role_changed", username, "by "+actor+" role="+newRole)
	return nil
}

// SetDisabled enables/disables a user (last-admin guard) and kills their
// sessions.
func (c *Controller) SetDisabled(actor, username string, disabled bool) error {
	if username == actor {
		return ErrSelfModify
	}
	p, err := c.st.Principal(username)
	if err != nil {
		return err
	}
	if disabled && p.Role == "admin" && !p.Disabled {
		if n, _ := c.st.CountActiveAdmins(); n <= 1 {
			return ErrLastAdmin
		}
	}
	if err := c.st.SetPrincipalDisabled(username, disabled); err != nil {
		return err
	}
	c.InvalidateUserSessions(username)
	c.audit("user.disabled", username, fmt.Sprintf("by %s disabled=%v", actor, disabled))
	return nil
}

// DeleteUser removes a user (last-admin + self-delete guards) and kills
// their sessions.
func (c *Controller) DeleteUser(actor, username string) error {
	if username == actor {
		return ErrSelfDelete
	}
	p, err := c.st.Principal(username)
	if err != nil {
		return err
	}
	if p.Role == "admin" && !p.Disabled {
		if n, _ := c.st.CountActiveAdmins(); n <= 1 {
			return ErrLastAdmin
		}
	}
	if err := c.st.DeletePrincipal(username); err != nil {
		return err
	}
	c.InvalidateUserSessions(username)
	c.audit("user.deleted", username, "by "+actor)
	return nil
}

// --- first-run bootstrap ------------------------------------------------------

// BootstrapAdmin creates the initial admin user (PRD Decision 6). Called
// only when the principals table is empty. If generated is true the
// password was machine-generated (caller persists/reports it).
func (c *Controller) BootstrapAdmin(username, password string) error {
	if err := ValidatePassword(password); err != nil {
		return err
	}
	hash, err := HashPassword(password)
	if err != nil {
		return err
	}
	if err := c.st.CreatePrincipal(username, hash, "admin"); err != nil {
		return fmt.Errorf("auth: bootstrap admin: %w", err)
	}
	c.audit("auth.bootstrap_admin", username, "first-run admin created")
	return nil
}

// GeneratePassword returns a random 16-char [a-zA-Z0-9] password.
func GeneratePassword() (string, error) {
	const alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	out := make([]byte, 16)
	for i := range b {
		out[i] = alphabet[int(b[i])%len(alphabet)]
	}
	return string(out), nil
}

// --- helpers -------------------------------------------------------------------

func validUsername(u string) bool {
	if len(u) < 3 || len(u) > 32 {
		return false
	}
	for _, r := range u {
		ok := (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '.' || r == '_' || r == '-'
		if !ok {
			return false
		}
	}
	return true
}

func (c *Controller) audit(kind, actor, detail string) {
	_ = c.st.AppendAudit(store.AuditEvent{
		TS: time.Now().Unix(), Kind: kind, Actor: actor, Payload: detail,
	})
}
