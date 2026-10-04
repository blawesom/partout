// parseToolMeta unit tests: only the known structured response shapes yield
// meta; read-only results that merely mention "approval" (policy listings,
// audit queries — the old substring heuristic's false positives) yield none.
package assistant

import (
	"encoding/json"
	"testing"
)

func TestParseToolMetaExecDispatch(t *testing.T) {
	res := `{
  "execution_id": "exec_abc",
  "runs": [
    {"run_id": "run_1", "agent_id": "ag_x", "state": "awaiting_approval", "approval_id": "apr_1"},
    {"run_id": "run_2", "agent_id": "ag_y", "state": "delivered", "delivered": true}
  ],
  "errors": ["ag_x: approval required (apr_1)"]
}`
	m := parseToolMeta(res)
	if m == nil {
		t.Fatalf("no meta parsed")
	}
	if m.ExecutionID != "exec_abc" {
		t.Fatalf("execution_id = %q", m.ExecutionID)
	}
	if len(m.ApprovalIDs) != 1 || m.ApprovalIDs[0] != "apr_1" {
		t.Fatalf("approval_ids = %v, want [apr_1]", m.ApprovalIDs)
	}
	if len(m.RunIDs) != 2 {
		t.Fatalf("run_ids = %v", m.RunIDs)
	}
	if !m.Parked() {
		t.Fatalf("Parked() should be true")
	}
}

func TestParseToolMetaParkedAck(t *testing.T) {
	m := parseToolMeta(`{"state":"approval_required","approval_id":"apr_9","run_id":"run_9","message":"job run parked on an approval request"}`)
	if m == nil || !m.Parked() || m.ApprovalIDs[0] != "apr_9" || m.RunIDs[0] != "run_9" {
		t.Fatalf("meta = %+v", m)
	}
	// A non-parked success with a "state" field yields nothing.
	if m2 := parseToolMeta(`{"state":"ok","id":"pact_1"}`); m2 != nil {
		t.Fatalf("plain success must not yield meta, got %+v", m2)
	}
}

func TestParseToolMetaPackageFanout(t *testing.T) {
	m := parseToolMeta(`{"results":[{"agent_id":"ag_x","state":"approval_required","approval_id":"apr_5"},{"agent_id":"ag_y","state":"ok"}],"summary":{"ok":1,"approval_required":1,"error":0}}`)
	if m == nil || len(m.ApprovalIDs) != 1 || m.ApprovalIDs[0] != "apr_5" {
		t.Fatalf("meta = %+v", m)
	}
}

func TestParseToolMetaNoFalsePositives(t *testing.T) {
	// The old substring heuristic fired on all of these; none is a park.
	cases := []string{
		`{"items":[{"id":"pol_1","name":"guard","effect":"require_approval","match":{"actions":["exec"]}}]}`, // list_policies
		`{"approvals":[{"id":"apr_old","state":"pending"}]}`,                                                 // list_approvals
		`{"items":[{"kind":"approval.approved","actor":"local"}]}`,                                           // get_audit
		`error: run_command → HTTP 403: forbidden`,                                                           // tool error text
		`ok`,
	}
	for _, c := range cases {
		if m := parseToolMeta(c); m != nil {
			t.Fatalf("false positive on %q → %+v", c, m)
		}
	}
	// Ids without the real prefixes never yield meta (a model-fabricated
	// "approval_id" in prose cannot fabricate a card).
	if m := parseToolMeta(`{"state":"approval_required","approval_id":"not-an-id"}`); m != nil {
		t.Fatalf("unprefixed id accepted: %+v", m)
	}
}

func TestToolMetaJSONRoundTrip(t *testing.T) {
	m := parseToolMeta(`{"execution_id":"exec_z","runs":[{"run_id":"run_z","state":"queued"}]}`)
	var back ToolMeta
	if err := json.Unmarshal([]byte(m.JSON()), &back); err != nil {
		t.Fatalf("round trip: %v", err)
	}
	if back.ExecutionID != "exec_z" || len(back.RunIDs) != 1 {
		t.Fatalf("round trip lost data: %+v", back)
	}
	var nilMeta *ToolMeta
	if nilMeta.JSON() != "" || nilMeta.Parked() {
		t.Fatalf("nil meta must render empty and not parked")
	}
}
