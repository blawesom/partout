package api_test

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"testing"

	"github.com/blawesom/partout/internal/identity"
)

// TestEnrollFlow verifies the full enrollment path:
// create token → enroll with token → agent registered → token consumed.
func TestEnrollFlow(t *testing.T) {
	apiH, _, srv := startAPITest(t)

	// 1. Create a token.
	tokenResp, err := http.Post(srv.URL+"/api/v1/agents/enrollment-tokens", "application/json", bytes.NewReader(nil))
	if err != nil {
		t.Fatalf("create token: %v", err)
	}
	tokenBody, _ := io.ReadAll(tokenResp.Body)
	tokenResp.Body.Close()
	var tokenRespData map[string]interface{}
	if err := json.Unmarshal(tokenBody, &tokenRespData); err != nil {
		t.Fatalf("parse token: %v", err)
	}
	token, _ := tokenRespData["token"].(string)
	if token == "" {
		t.Fatalf("token empty in response: %s", string(tokenBody))
	}

	// 2. Generate an identity for the agent.
	id, err := identity.LoadOrGenerate(t.TempDir())
	if err != nil {
		t.Fatalf("identity: %v", err)
	}
	pubB64 := base64.StdEncoding.EncodeToString(id.Ed25519Pub)
	xpubB64 := base64.StdEncoding.EncodeToString(id.X25519Pub)

	// 3. Enroll the agent.
	enrollBody, _ := json.Marshal(map[string]interface{}{
		"token":         token,
		"uuid":          id.UUID,
		"ed25519_pub":   pubB64,
		"x25519_pub":    xpubB64,
		"agent_version": "0.0.1",
		"facts":         map[string]string{"host.os": "linux"},
	})
	resp, err := http.Post(srv.URL+"/api/v1/agents/enroll", "application/json", bytes.NewReader(enrollBody))
	if err != nil {
		t.Fatalf("enroll: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	t.Logf("enroll response: %s", string(body))

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("enroll status = %d, want 200", resp.StatusCode)
	}

	var enrollResp map[string]interface{}
	if err := json.Unmarshal(body, &enrollResp); err != nil {
		t.Fatalf("parse enroll: %v", err)
	}
	agentID, ok := enrollResp["agent_id"].(string)
	if !ok || agentID == "" {
		t.Fatalf("enroll response missing agent_id: %s", string(body))
	}

	// 4. Verify the agent was created in the store.
	agents, err := apiH.Store().Agents()
	if err != nil {
		t.Fatalf("Agents: %v", err)
	}
	found := false
	for _, a := range agents {
		if a.ID == agentID {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("agent not found in store after enrollment")
	}

	// 5. Verify the token was consumed (second use fails).
	resp2, err := http.Post(srv.URL+"/api/v1/agents/enroll", "application/json", bytes.NewReader(enrollBody))
	if err != nil {
		t.Fatalf("enroll again: %v", err)
	}
	io.Copy(io.Discard, resp2.Body)
	resp2.Body.Close()
	if resp2.StatusCode == http.StatusOK {
		t.Fatal("second enrollment should fail (token consumed)")
	}
}
