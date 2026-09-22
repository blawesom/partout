package api_test

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// TestListHosts verifies GET /api/v1/hosts returns enrolled agents.
func TestListHosts(t *testing.T) {
	_, _, srv := startAPITest(t)

	resp, err := http.Get(srv.URL + "/api/v1/hosts")
	if err != nil {
		t.Fatalf("GET /hosts: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d; body = %s", resp.StatusCode, string(body))
	}

	var page map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&page); err != nil {
		t.Fatalf("decode page: %v", err)
	}

	items, ok := page["items"].([]any)
	if !ok {
		t.Fatalf("expected items array, got %T", page["items"])
	}
	if len(items) != 1 {
		t.Fatalf("expected 1 host, got %d", len(items))
	}

	host, ok := items[0].(map[string]any)
	if !ok {
		t.Fatalf("expected host object, got %T", items[0])
	}
	if host["id"] != "ag_api" {
		t.Fatalf("host id = %v, want ag_api", host["id"])
	}
	if host["roles"] == nil {
		t.Fatal("expected roles on host")
	}
}

// TestGetHost verifies GET /api/v1/hosts/:id and 404.
func TestGetHost(t *testing.T) {
	_, _, srv := startAPITest(t)

	resp, err := http.Get(srv.URL + "/api/v1/hosts/ag_nonexistent")
	if err != nil {
		t.Fatalf("GET /hosts/:id: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", resp.StatusCode)
	}

	resp, err = http.Get(srv.URL + "/api/v1/hosts/ag_api")
	if err != nil {
		t.Fatalf("GET /hosts/ag_api: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d; body = %s", resp.StatusCode, string(body))
	}
	var host map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&host); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if host["id"] != "ag_api" {
		t.Fatalf("host id = %v, want ag_api", host["id"])
	}
}

// TestListExecutions verifies GET /api/v1/executions.
func TestListExecutions(t *testing.T) {
	_, _, srv := startAPITest(t)

	resp, err := http.Get(srv.URL + "/api/v1/executions")
	if err != nil {
		t.Fatalf("GET /executions: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d; body = %s", resp.StatusCode, string(body))
	}

	var page map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&page); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if _, ok := page["items"].([]any); !ok {
		t.Fatal("expected items array")
	}
	if page["next_cursor"] == nil {
		t.Fatal("expected next_cursor key")
	}
}

// dispatchAndWait dispatches a command and waits for a terminal state.
func dispatchAndWait(t *testing.T, srv *httptest.Server, body string) map[string]any {
	t.Helper()
	resp, err := http.Post(srv.URL+"/api/v1/executions", "application/json", bytes.NewReader([]byte(body)))
	if err != nil {
		t.Fatalf("POST /executions: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("dispatch status = %d; body = %s", resp.StatusCode, string(b))
	}
	var dispatch map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&dispatch); err != nil {
		t.Fatalf("decode dispatch: %v", err)
	}
	return dispatch
}

func executionState(t *testing.T, url string) string {
	t.Helper()
	resp, err := http.Get(url)
	if err != nil {
		t.Fatalf("GET execution: %v", err)
	}
	defer resp.Body.Close()
	var e map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&e); err != nil {
		t.Fatalf("decode: %v", err)
	}
	return e["state"].(string)
}

func waitForTerminal(t *testing.T, url string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		state := executionState(t, url)
		switch state {
		case "succeeded", "failed", "partial", "cancelled":
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("execution not terminal after 5s (state=%s)", state)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// TestGetExecutionDetail verifies GET /api/v1/executions/:id with runs.
func TestGetExecutionDetail(t *testing.T) {
	_, _, srv := startAPITest(t)

	d := dispatchAndWait(t, srv,
		`{"selector":"role:test","cmd":"echo hello","args":["a"],"timeout_s":10,"created_by":"test"}`)
	execID := d["execution_id"].(string)

	waitForTerminal(t, srv.URL+"/api/v1/executions/"+execID)

	resp, err := http.Get(srv.URL + "/api/v1/executions/" + execID)
	if err != nil {
		t.Fatalf("GET /executions/:id: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d; body = %s", resp.StatusCode, string(b))
	}
	var detail map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&detail); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if detail["state"] != "succeeded" {
		t.Fatalf("state = %v, want succeeded", detail["state"])
	}
	runs, ok := detail["runs"].([]any)
	if !ok || len(runs) != 1 {
		t.Fatalf("expected 1 run, got %v", detail["runs"])
	}
	run := runs[0].(map[string]any)
	if run["state"] != "succeeded" {
		t.Fatalf("run state = %v, want succeeded", run["state"])
	}
}

// TestGetOutput verifies GET /api/v1/executions/:id/output.
func TestGetOutput(t *testing.T) {
	_, _, srv := startAPITest(t)

	d := dispatchAndWait(t, srv,
		`{"selector":"role:test","cmd":"echo hello","args":["a"],"timeout_s":10,"created_by":"test"}`)
	execID := d["execution_id"].(string)

	waitForTerminal(t, srv.URL+"/api/v1/executions/"+execID)

	resp, err := http.Get(srv.URL + "/api/v1/executions/" + execID + "/output")
	if err != nil {
		t.Fatalf("GET output: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d; body = %s", resp.StatusCode, string(b))
	}

	var outputs []map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&outputs); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(outputs) != 1 {
		t.Fatalf("expected 1 run output, got %d", len(outputs))
	}
	stdout, _ := outputs[0]["stdout"].(string)
	if !bytes.Contains([]byte(stdout), []byte("a")) {
		t.Fatalf("stdout = %q, want to contain 'a'", stdout)
	}
}

// TestCancelExecution verifies POST /api/v1/executions/:id/cancel error paths.
func TestCancelExecution(t *testing.T) {
	_, _, srv := startAPITest(t)

	d := dispatchAndWait(t, srv,
		`{"selector":"role:test","cmd":"echo done","timeout_s":10,"created_by":"test"}`)
	execID := d["execution_id"].(string)
	waitForTerminal(t, srv.URL+"/api/v1/executions/"+execID)

	// Terminal execution → 409 Conflict.
	resp, err := http.Post(srv.URL+"/api/v1/executions/"+execID+"/cancel", "application/json", nil)
	if err != nil {
		t.Fatalf("POST cancel: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusConflict {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("cancel status = %d; body = %s", resp.StatusCode, string(b))
	}

	// Nonexistent execution → 404.
	resp, err = http.Post(srv.URL+"/api/v1/executions/exec_nonexistent/cancel", "application/json", nil)
	if err != nil {
		t.Fatalf("POST cancel nonexistent: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("cancel nonexistent status = %d", resp.StatusCode)
	}
}

// TestAuditList verifies GET /api/v1/audit.
func TestAuditList(t *testing.T) {
	_, _, srv := startAPITest(t)

	resp, err := http.Get(srv.URL + "/api/v1/audit")
	if err != nil {
		t.Fatalf("GET /audit: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d; body = %s", resp.StatusCode, string(b))
	}

	var page map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&page); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if _, ok := page["items"].([]any); !ok {
		t.Fatal("expected items array")
	}
}

// TestAuthEnforcement verifies RBAC bearer token enforcement.
func TestAuthEnforcement(t *testing.T) {
	apiH, _, srv := startAPITest(t)
	apiH.SetAuth("admin-token", "op-token", "view-token")

	// No token → 401.
	resp, err := http.Get(srv.URL + "/api/v1/hosts")
	if err != nil {
		t.Fatalf("GET /hosts: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("no token status = %d, want 401", resp.StatusCode)
	}

	// Viewer token on viewer endpoint → 200.
	req, _ := http.NewRequest("GET", srv.URL+"/api/v1/hosts", nil)
	req.Header.Set("Authorization", "Bearer view-token")
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET /hosts with token: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("viewer token status = %d, want 200", resp.StatusCode)
	}

	// Viewer token on operator endpoint → 403.
	req, _ = http.NewRequest("POST", srv.URL+"/api/v1/executions",
		bytes.NewReader([]byte(`{"selector":"role:test","cmd":"echo"}`)))
	req.Header.Set("Authorization", "Bearer view-token")
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST /executions: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("viewer on operator endpoint status = %d, want 403", resp.StatusCode)
	}

	// Operator token on operator endpoint → allowed (200).
	req, _ = http.NewRequest("POST", srv.URL+"/api/v1/executions",
		bytes.NewReader([]byte(`{"selector":"role:test","cmd":"echo hi","timeout_s":10}`)))
	req.Header.Set("Authorization", "Bearer op-token")
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST /executions with op token: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("op token status = %d; body = %s", resp.StatusCode, string(b))
	}
}

// TestGroupsVerify verifies GET/POST /api/v1/groups.
func TestGroupsVerify(t *testing.T) {
	_, _, srv := startAPITest(t)

	// Create.
	resp, err := http.Post(srv.URL+"/api/v1/groups", "application/json",
		bytes.NewReader([]byte(`{"name":"prod","selector":"tag:env=prod"}`)))
	if err != nil {
		t.Fatalf("POST /groups: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("create status = %d; body = %s", resp.StatusCode, string(b))
	}

	// List.
	resp, err = http.Get(srv.URL + "/api/v1/groups")
	if err != nil {
		t.Fatalf("GET /groups: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /groups status = %d", resp.StatusCode)
	}
	var groups []map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&groups); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(groups) != 1 || groups[0]["name"] != "prod" {
		t.Fatalf("groups = %v", groups)
	}
}

// TestHostFacts verifies GET/PUT /api/v1/hosts/:id/facts.
func TestHostFacts(t *testing.T) {
	_, _, srv := startAPITest(t)

	// PUT facts.
	req, _ := http.NewRequest("PUT", srv.URL+"/api/v1/hosts/ag_api/facts",
		bytes.NewReader([]byte(`{"os":"linux","kernel":"5.15","cpu":"4"}`)))
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("PUT /hosts/:id/facts: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("PUT status = %d; body = %s", resp.StatusCode, string(b))
	}

	// GET facts.
	resp, err = http.Get(srv.URL + "/api/v1/hosts/ag_api/facts")
	if err != nil {
		t.Fatalf("GET /hosts/:id/facts: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("GET status = %d; body = %s", resp.StatusCode, string(b))
	}
	var factsResp map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&factsResp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	factsMap, ok := factsResp["facts"].(map[string]any)
	if !ok {
		t.Fatalf("expected facts object, got %T", factsResp["facts"])
	}
	if factsMap["os"] != "linux" {
		t.Fatalf("facts.os = %v, want linux", factsMap["os"])
	}

	// Missing host → 404.
	resp, err = http.Get(srv.URL + "/api/v1/hosts/ag_fake/facts")
	if err != nil {
		t.Fatalf("GET /hosts/ag_fake/facts: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("GET facts for missing host status = %d, want 404", resp.StatusCode)
	}
}
