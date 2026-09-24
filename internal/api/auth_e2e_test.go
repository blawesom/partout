package api_test

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	serverauth "github.com/blawesom/partout/internal/server/auth"
)

// startAuthTest wires local-user auth on top of the standard API test
// harness: one admin + one viewer seeded directly in the store.
func startAuthTest(t *testing.T) (*serverauth.Controller, string) {
	apiH, _, srv := startAPITest(t)
	seedUserStore(t, apiH.Store(), "admin", "adminpass1", "admin")
	seedUserStore(t, apiH.Store(), "viewer1", "viewerpass1", "viewer")
	c := serverauth.New(apiH.Store(), nil)
	apiH.SetAuthController(c)
	return c, srv.URL
}

func seedUserStore(t *testing.T, st interface {
	CreatePrincipal(string, string, string) error
}, name, pw, role string) {
	t.Helper()
	hash, err := serverauth.HashPassword(pw)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.CreatePrincipal(name, hash, role); err != nil {
		t.Fatal(err)
	}
}

// apiReq performs a request with an optional bearer token.
func apiReq(t *testing.T, method, url, token, body string) (int, []byte) {
	t.Helper()
	var rd io.Reader
	if body != "" {
		rd = strings.NewReader(body)
	}
	req, err := http.NewRequest(method, url, rd)
	if err != nil {
		t.Fatal(err)
	}
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, url, err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, b
}

func loginToken(t *testing.T, base, user, pw string) string {
	t.Helper()
	code, b := apiReq(t, "POST", base+"/api/v1/auth/login", "",
		`{"username":"`+user+`","password":"`+pw+`"}`)
	if code != 200 {
		t.Fatalf("login %s: status %d body %s", user, code, b)
	}
	var res struct {
		Token string `json:"token"`
		Role  string `json:"role"`
	}
	if err := json.Unmarshal(b, &res); err != nil || res.Token == "" {
		t.Fatalf("login %s: bad response %s", user, b)
	}
	return res.Token
}

func TestAuthLoginMeLogout(t *testing.T) {
	_, base := startAuthTest(t)

	tok := loginToken(t, base, "admin", "adminpass1")

	// /auth/me with the session token.
	code, b := apiReq(t, "GET", base+"/api/v1/auth/me", tok, "")
	if code != 200 || !bytes.Contains(b, []byte(`"username":"admin"`)) {
		t.Fatalf("me: status %d body %s", code, b)
	}

	// Wrong password → 401, generic message (no user enumeration).
	code, b = apiReq(t, "POST", base+"/api/v1/auth/login", "",
		`{"username":"admin","password":"wrong"}`)
	if code != 401 {
		t.Fatalf("bad login: status %d, want 401 (%s)", code, b)
	}

	// Unknown user → same 401.
	code, _ = apiReq(t, "POST", base+"/api/v1/auth/login", "",
		`{"username":"nobody","password":"whatever1"}`)
	if code != 401 {
		t.Fatalf("unknown user login: status %d, want 401", code)
	}

	// Logout kills the token.
	code, _ = apiReq(t, "POST", base+"/api/v1/auth/logout", tok, "")
	if code != 200 {
		t.Fatalf("logout: %d", code)
	}
	code, _ = apiReq(t, "GET", base+"/api/v1/auth/me", tok, "")
	if code != 401 {
		t.Fatalf("me after logout: %d, want 401", code)
	}
}

func TestAuthUnauthenticatedRejected(t *testing.T) {
	_, base := startAuthTest(t)

	// Users exist → local-mode exemption is lifted: no token = 401.
	code, _ := apiReq(t, "GET", base+"/api/v1/hosts", "", "")
	if code != 401 {
		t.Fatalf("unauthenticated /hosts: %d, want 401", code)
	}
	// Bad token = 401.
	code, _ = apiReq(t, "GET", base+"/api/v1/hosts", "not-a-token", "")
	if code != 401 {
		t.Fatalf("bad token /hosts: %d, want 401", code)
	}
	// /healthz stays public.
	code, _ = apiReq(t, "GET", base+"/healthz", "", "")
	if code != 200 {
		t.Fatalf("healthz: %d, want 200", code)
	}
}

func TestAuthRBACBySessionRole(t *testing.T) {
	_, base := startAuthTest(t)

	viewer := loginToken(t, base, "viewer1", "viewerpass1")

	// viewer can read.
	code, _ := apiReq(t, "GET", base+"/api/v1/hosts", viewer, "")
	if code != 200 {
		t.Fatalf("viewer GET /hosts: %d", code)
	}
	// viewer cannot write (operator route).
	code, _ = apiReq(t, "POST", base+"/api/v1/jobs", viewer, `{"name":"x"}`)
	if code != 403 {
		t.Fatalf("viewer POST /jobs: %d, want 403", code)
	}
	// viewer cannot manage users (admin route).
	code, _ = apiReq(t, "GET", base+"/api/v1/users", viewer, "")
	if code != 403 {
		t.Fatalf("viewer GET /users: %d, want 403", code)
	}
}

func TestAuthUserManagement(t *testing.T) {
	_, base := startAuthTest(t)
	admin := loginToken(t, base, "admin", "adminpass1")

	// Create a user.
	code, _ := apiReq(t, "POST", base+"/api/v1/users", admin,
		`{"username":"newbie","password":"newbiepass1","role":"operator"}`)
	if code != 201 {
		t.Fatalf("create user: %d", code)
	}
	// The new user can log in and has the right role.
	op := loginToken(t, base, "newbie", "newbiepass1")
	code, b := apiReq(t, "GET", base+"/api/v1/auth/me", op, "")
	if code != 200 || !bytes.Contains(b, []byte(`"role":"operator"`)) {
		t.Fatalf("newbie me: %d %s", code, b)
	}

	// List shows all users, no password material.
	code, b = apiReq(t, "GET", base+"/api/v1/users", admin, "")
	if code != 200 || bytes.Contains(b, []byte("passw0rd")) || bytes.Contains(b, []byte("pass")) {
		t.Fatalf("user list: %d %s", code, b)
	}

	// Patch role.
	code, _ = apiReq(t, "PATCH", base+"/api/v1/users/newbie", admin, `{"role":"viewer"}`)
	if code != 200 {
		t.Fatalf("patch role: %d", code)
	}

	// Reset password → old sessions die.
	code, _ = apiReq(t, "PATCH", base+"/api/v1/users/newbie", admin,
		`{"password":"newbiepass2"}`)
	if code != 200 {
		t.Fatalf("reset password: %d", code)
	}
	code, _ = apiReq(t, "GET", base+"/api/v1/auth/me", op, "")
	if code != 401 {
		t.Fatalf("old session after reset: %d, want 401", code)
	}

	// Delete.
	code, _ = apiReq(t, "DELETE", base+"/api/v1/users/newbie", admin, "")
	if code != 200 {
		t.Fatalf("delete user: %d", code)
	}
}

func TestAuthLastAdminGuards(t *testing.T) {
	apiH, _, srv := startAPITest(t)
	seedUserStore(t, apiH.Store(), "onlyadmin", "adminpass1", "admin")
	apiH.SetAuthController(serverauth.New(apiH.Store(), nil))
	base := srv.URL

	admin := loginToken(t, base, "onlyadmin", "adminpass1")

	// Cannot demote the last admin.
	code, _ := apiReq(t, "PATCH", base+"/api/v1/users/onlyadmin", admin, `{"role":"viewer"}`)
	if code != 409 {
		t.Fatalf("demote last admin: %d, want 409", code)
	}
	// Cannot disable the last admin.
	code, _ = apiReq(t, "PATCH", base+"/api/v1/users/onlyadmin", admin, `{"disabled":true}`)
	if code != 409 {
		t.Fatalf("disable last admin: %d, want 409", code)
	}
	// Cannot delete self.
	code, _ = apiReq(t, "DELETE", base+"/api/v1/users/onlyadmin", admin, "")
	if code != 409 {
		t.Fatalf("self delete: %d, want 409", code)
	}
}

func TestAuthChangeOwnPassword(t *testing.T) {
	_, base := startAuthTest(t)
	admin := loginToken(t, base, "admin", "adminpass1")

	// Wrong old password.
	code, _ := apiReq(t, "POST", base+"/api/v1/auth/password", admin,
		`{"old_password":"nope","new_password":"freshpass1"}`)
	if code != 401 {
		t.Fatalf("wrong old password: %d, want 401", code)
	}
	// Success returns a fresh token; old token is dead.
	code, b := apiReq(t, "POST", base+"/api/v1/auth/password", admin,
		`{"old_password":"adminpass1","new_password":"freshpass1"}`)
	if code != 200 {
		t.Fatalf("change password: %d %s", code, b)
	}
	var res struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(b, &res); err != nil || res.Token == "" {
		t.Fatalf("change password: no new token: %s", b)
	}
	code, _ = apiReq(t, "GET", base+"/api/v1/auth/me", admin, "")
	if code != 401 {
		t.Fatalf("old token after change: %d, want 401", code)
	}
	// New password works.
	if got := loginToken(t, base, "admin", "freshpass1"); got == "" {
		t.Fatal("login with new password failed")
	}
}

func TestAuthStaticTokensStillWork(t *testing.T) {
	apiH, _, srv := startAPITest(t)
	seedUserStore(t, apiH.Store(), "admin", "adminpass1", "admin")
	apiH.SetAuth(staticAdminToken, "", "viewer-static")
	apiH.SetAuthController(serverauth.New(apiH.Store(), nil))
	base := srv.URL

	// Static admin token still authorizes (coexistence).
	code, _ := apiReq(t, "GET", base+"/api/v1/users", "static-admin-token", "")
	if code != 200 {
		t.Fatalf("static admin token: %d, want 200", code)
	}
	// Static viewer token is capped at viewer.
	code, _ = apiReq(t, "GET", base+"/api/v1/users", "viewer-static", "")
	if code != 403 {
		t.Fatalf("static viewer token on admin route: %d, want 403", code)
	}
}

const staticAdminToken = "static-admin-token"

// TestAuthLoginInputBounds verifies oversized login input is rejected before
// it reaches the throttle map or the audit log.
func TestAuthLoginInputBounds(t *testing.T) {
	_, base := startAuthTest(t)

	long := strings.Repeat("u", 65)
	code, _ := apiReq(t, "POST", base+"/api/v1/auth/login", "",
		`{"username":"`+long+`","password":"whatever"}`)
	if code != 400 {
		t.Fatalf("oversized username: %d, want 400", code)
	}
}

// TestAuthLoginThrottled verifies repeated failures return 429.
func TestAuthLoginThrottled(t *testing.T) {
	apiH, _, srv := startAPITest(t)
	seedUserStore(t, apiH.Store(), "admin", "adminpass1", "admin")
	c := serverauth.New(apiH.Store(), nil)
	// Lock out after two failures to keep the test fast.
	c.SetThrottle(2, 500*time.Millisecond, time.Second)
	apiH.SetAuthController(c)
	base := srv.URL

	for i := 0; i < 2; i++ {
		code, _ := apiReq(t, "POST", base+"/api/v1/auth/login", "",
			`{"username":"admin","password":"wrong"}`)
		if code != 401 {
			t.Fatalf("failure %d: %d, want 401", i+1, code)
		}
	}
	code, b := apiReq(t, "POST", base+"/api/v1/auth/login", "",
		`{"username":"admin","password":"adminpass1"}`)
	if code != 429 {
		t.Fatalf("throttled login: %d (%s), want 429", code, b)
	}
	if !bytes.Contains(b, []byte("throttled")) {
		t.Fatalf("throttled body = %s, want code=throttled", b)
	}
}
