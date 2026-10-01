package api

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/blawesom/partout/internal/server/packages"
	"github.com/blawesom/partout/internal/store"
)

// mustApplyBody decodes a request body the way the handler does.
func mustApplyBody(t *testing.T, raw string) pkgApplyRequest {
	t.Helper()
	var b pkgApplyRequest
	if err := json.Unmarshal([]byte(raw), &b); err != nil {
		t.Fatalf("unmarshal %q: %v", raw, err)
	}
	return b
}

// TestParseApplyTargets covers the two request forms and validation.
func TestParseApplyTargets(t *testing.T) {
	// Legacy single-host form.
	got, err := parseApplyTargets(mustApplyBody(t, `{"agent_id":"ag_1","packages":["nginx"]}`))
	if err != nil {
		t.Fatalf("legacy: %v", err)
	}
	if len(got) != 1 || got[0].AgentID != "ag_1" || len(got[0].Packages) != 1 || got[0].Packages[0] != "nginx" {
		t.Fatalf("legacy = %+v", got)
	}

	// Fan-out form.
	got, err = parseApplyTargets(mustApplyBody(t, `{"targets":[{"agent_id":"ag_1"},{"agent_id":"ag_2","packages":["openssl"]}]}`))
	if err != nil {
		t.Fatalf("targets: %v", err)
	}
	if len(got) != 2 || got[0].AgentID != "ag_1" || got[1].AgentID != "ag_2" || len(got[1].Packages) != 1 || got[1].Packages[0] != "openssl" {
		t.Fatalf("targets = %+v", got)
	}

	// targets[] wins over agent_id.
	got, err = parseApplyTargets(mustApplyBody(t, `{"agent_id":"ag_x","targets":[{"agent_id":"ag_1"}]}`))
	if err != nil || len(got) != 1 || got[0].AgentID != "ag_1" {
		t.Fatalf("targets-wins = %+v, %v", got, err)
	}

	// Nothing at all → error.
	if _, err := parseApplyTargets(mustApplyBody(t, `{}`)); err == nil {
		t.Fatal("empty body: want error")
	}
	// Blank agent_id inside targets → error.
	if _, err := parseApplyTargets(mustApplyBody(t, `{"targets":[{"agent_id":"  "}]}`)); err == nil {
		t.Fatal("blank targets[].agent_id: want error")
	}
	// Duplicate host → error.
	if _, err := parseApplyTargets(mustApplyBody(t, `{"targets":[{"agent_id":"ag_1"},{"agent_id":"ag_1"}]}`)); err == nil {
		t.Fatal("duplicate agent_id: want error")
	}
}

// TestFanoutApplyAggregation verifies per-target outcome classification
// (ok / approval_required / error), result ordering, and the summary.
func TestFanoutApplyAggregation(t *testing.T) {
	apply := func(ctx context.Context, agentID string, pkgs []string, dryRun bool) (*store.PkgAction, error) {
		switch agentID {
		case "ag_ok":
			return &store.PkgAction{ID: "pko_1", AgentID: "ag_ok", Kind: "apply", Status: "succeeded", AppliedCount: 2}, nil
		case "ag_appr":
			return nil, &packages.ApprovalRequiredError{ApprovalID: "apr_1"}
		default:
			return nil, errors.New("agent offline")
		}
	}
	targets := []pkgApplyTarget{
		{AgentID: "ag_ok"}, {AgentID: "ag_appr"}, {AgentID: "ag_err"}, {AgentID: "ag_ok2"},
	}
	out := fanoutApply(context.Background(), apply, targets, false)
	results, ok := out["results"].([]map[string]any)
	if !ok || len(results) != 4 {
		t.Fatalf("results = %#v", out["results"])
	}
	wantState := []string{"ok", "approval_required", "error", "error"}
	for i, r := range results {
		if r["state"] != wantState[i] {
			t.Errorf("results[%d].state = %v, want %s (agent %v)", i, r["state"], wantState[i], r["agent_id"])
		}
	}
	if results[0]["id"] != "pko_1" || results[0]["applied_count"] != int64(2) {
		t.Errorf("ok result missing action fields: %#v", results[0])
	}
	if results[1]["approval_id"] != "apr_1" {
		t.Errorf("approval result missing approval_id: %#v", results[1])
	}
	if results[2]["error"] == "" {
		t.Errorf("error result missing error text: %#v", results[2])
	}
	summary, ok := out["summary"].(map[string]int)
	if !ok || summary["ok"] != 1 || summary["approval_required"] != 1 || summary["error"] != 2 {
		t.Errorf("summary = %#v", out["summary"])
	}
}
