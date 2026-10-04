// Tool-meta parsing (feedback parity): the write surfaces return structured
// results — exec dispatches a DispatchResult (runs[].state="awaiting_approval"
// + approval_id), jobs/sessions/files/packages park with
// 202 {"state":"approval_required","approval_id":…}. The chat renders its
// confirmation artifacts (approval cards, execution chips) from THESE parsed
// ids, never from grepping the result text — so "approval required" can only
// appear in the chat when an approval request actually exists, and every
// assistant-issued action links back to the same surface a user-issued one
// does.
package assistant

import (
	"encoding/json"
	"strings"
)

// ToolMeta is the structured half of a tool result. Persisted on the tool
// message and carried on the tool_result/approval_required SSE events.
type ToolMeta struct {
	// ApprovalIDs are the approval requests this action parked on
	// (apr_…). Empty = the action did not park.
	ApprovalIDs []string `json:"approval_ids,omitempty"`
	// ExecutionID is the execution a run_command created (exec_…).
	ExecutionID string `json:"execution_id,omitempty"`
	// RunIDs are the per-host runs the action created (run_…).
	RunIDs []string `json:"run_ids,omitempty"`
}

// Parked reports whether the action parked on any approval.
func (m *ToolMeta) Parked() bool { return m != nil && len(m.ApprovalIDs) > 0 }

// parseToolMeta extracts ToolMeta from a tool result. It only matches the
// known structured shapes (exact keys, real id prefixes), so a read-only
// result that merely mentions "approval" (a policy listing, an audit query)
// yields no meta — the old substring heuristic could not tell those apart.
func parseToolMeta(result string) *ToolMeta {
	s := strings.TrimSpace(result)
	if !strings.HasPrefix(s, "{") {
		return nil // not a JSON object (error text, plain string)
	}
	var v map[string]any
	if err := json.Unmarshal([]byte(s), &v); err != nil {
		return nil
	}
	var meta ToolMeta

	// Shape 1 — the parked-action acknowledgment shared by jobs, sessions,
	// files and package applies: 202 {"state":"approval_required",
	// "approval_id":"apr_…", "run_id"?:"run_…"}.
	if state, _ := v["state"].(string); state == "approval_required" {
		if id, _ := v["approval_id"].(string); strings.HasPrefix(id, "apr_") {
			meta.ApprovalIDs = append(meta.ApprovalIDs, id)
		}
		if rid, _ := v["run_id"].(string); strings.HasPrefix(rid, "run_") {
			meta.RunIDs = append(meta.RunIDs, rid)
		}
	}

	// Shape 2 — the exec DispatchResult: {"execution_id":"exec_…",
	// "runs":[{"run_id","agent_id","state","approval_id"?}], "errors":[…]}.
	if eid, _ := v["execution_id"].(string); strings.HasPrefix(eid, "exec_") {
		meta.ExecutionID = eid
		if runs, ok := v["runs"].([]any); ok {
			for _, r := range runs {
				rm, _ := r.(map[string]any)
				if rm == nil {
					continue
				}
				if rid, _ := rm["run_id"].(string); strings.HasPrefix(rid, "run_") {
					meta.RunIDs = append(meta.RunIDs, rid)
				}
				if st, _ := rm["state"].(string); st == "awaiting_approval" {
					if aid, _ := rm["approval_id"].(string); strings.HasPrefix(aid, "apr_") {
						meta.ApprovalIDs = append(meta.ApprovalIDs, aid)
					}
				}
			}
		}
	}

	// Shape 3 — the package fan-out: {"results":[{"state":"approval_required",
	// "approval_id":"apr_…"}], "summary":…}.
	if results, ok := v["results"].([]any); ok {
		for _, r := range results {
			rm, _ := r.(map[string]any)
			if rm == nil {
				continue
			}
			if st, _ := rm["state"].(string); st == "approval_required" {
				if aid, _ := rm["approval_id"].(string); strings.HasPrefix(aid, "apr_") {
					meta.ApprovalIDs = append(meta.ApprovalIDs, aid)
				}
			}
		}
	}

	if meta.ApprovalIDs == nil && meta.ExecutionID == "" && meta.RunIDs == nil {
		return nil
	}
	return &meta
}

// JSON renders the meta for persistence ("" when nil).
func (m *ToolMeta) JSON() string {
	if m == nil {
		return ""
	}
	b, err := json.Marshal(m)
	if err != nil {
		return ""
	}
	return string(b)
}
