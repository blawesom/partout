// Package assistant implements the Partout LLM assistant (R26, PRD
// Decision 17): an operator-configured OpenAI-compatible endpoint driving a
// chat assistant that reuses the R11 MCP tool registry in-process — one tool
// surface, two front doors. Every tool call runs through the same REST
// router the UI/CLI/MCP clients use with the authenticated user's token, so
// RBAC, the policy gate, approvals, and audit apply unchanged; the model
// can request a governed action, never approve one.
//
// Profiles (PRD §6 of docs/assistant.md) are allow-lists over the MCP
// catalog's read/write split and are additionally capped by the caller's
// role. Transcripts persist split-store (Decision 18); the endpoint is
// server-wide and admin-set (Decision 19).
package assistant

import (
	"github.com/blawesom/partout/internal/server/mcp"
)

// Profile names (docs/assistant.md §6). The zero value is never valid —
// callers resolve through ResolveProfile.
const (
	ProfileReadonly = "readonly"
	ProfileOperator = "operator"
	ProfileFull     = "full"
)

// neverAssistantReachable is removed from every profile regardless of
// classification: approvals are a human act (the model can request an
// action and see the parked request, but never decide one).
var neverAssistantReachable = map[string]bool{
	"decide_approval": true,
}

// Profiles returns the profile → tool-name allow-list, derived from the MCP
// catalog's read/write split (mcp.writeTools). The catalog is the single
// source of truth: a tool added there is automatically available to the
// matching assistant profile (minus the never-reachable set).
func Profiles() map[string]map[string]bool {
	tools := mcp.ToolCatalog()
	out := map[string]map[string]bool{
		ProfileReadonly: {},
		ProfileOperator: {},
		ProfileFull:     {},
	}
	for _, t := range tools {
		if neverAssistantReachable[t.Name] {
			continue
		}
		if !t.Write {
			// Reads are in every profile (readonly ⊆ operator ⊆ full).
			out[ProfileReadonly][t.Name] = true
			out[ProfileOperator][t.Name] = true
			out[ProfileFull][t.Name] = true
			continue
		}
		out[ProfileOperator][t.Name] = true // operator = readonly + writes (policy still gates them)
		out[ProfileFull][t.Name] = true
	}
	return out
}

// ProfileFor resolves a profile name; write-scoped profiles additionally
// require the given role ("viewer"|"operator"|"admin" — the REST layer's
// actorFor strings). An unknown or over-scoped request falls back to the
// safest valid profile for that role (readonly), never errors open.
func ProfileFor(name, role string) string {
	switch name {
	case ProfileFull:
		if role == "admin" {
			return ProfileFull
		}
		return ProfileOperatorIf(role)
	case ProfileOperator:
		return ProfileOperatorIf(role)
	default: // readonly (and anything unknown — fail safe)
		return ProfileReadonly
	}
}

// ProfileOperatorIf returns the operator profile when the role may write,
// else readonly.
func ProfileOperatorIf(role string) string {
	if role == "operator" || role == "admin" {
		return ProfileOperator
	}
	return ProfileReadonly
}

// ToolSchemasFor renders the OpenAI tool-call schemas for a profile: only
// allow-listed tools, each with its MCP JSON schema (the same description
// and shape external MCP clients see — parity is the invariant).
func ToolSchemasFor(profile string) []map[string]any {
	allow := Profiles()[profile]
	if allow == nil {
		allow = Profiles()[ProfileReadonly]
	}
	var out []map[string]any
	for _, t := range mcp.DefaultTools() {
		if !allow[t.Name] {
			continue
		}
		out = append(out, map[string]any{
			"type": "function",
			"function": map[string]any{
				"name":        t.Name,
				"description": t.Description,
				"parameters":  t.InputSchema,
			},
		})
	}
	return out
}
