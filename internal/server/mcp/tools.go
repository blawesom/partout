package mcp

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"sort"
)

// Tool is one MCP tool: a thin, documented wrapper over one REST surface.
// The control plane (RBAC, policy gate, audit) is the REST layer's — a tool
// never bypasses it; structured refusals (403 role, policy deny,
// approval_required) are returned as tool errors with the server's message.
type Tool struct {
	Name        string
	Description string
	InputSchema map[string]any
	Call        func(ctx context.Context, api API, token string, args map[string]any) (string, error)
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

func objSchema(props map[string]any, required ...string) map[string]any {
	s := map[string]any{"type": "object", "properties": props, "additionalProperties": false}
	if len(required) > 0 {
		s["required"] = required
	}
	return s
}

func prop(t, d string) map[string]any { return map[string]any{"type": t, "description": d} }
func strProp(d string) map[string]any { return prop("string", d) }
func intProp(d string) map[string]any { return prop("integer", d) }

func boolProp(d string) map[string]any { return prop("boolean", d) }

func arrProp(itemType, d string) map[string]any {
	return map[string]any{"type": "array", "items": map[string]any{"type": itemType}, "description": d}
}

func argStr(args map[string]any, key string) string {
	if v, ok := args[key].(string); ok {
		return v
	}
	return ""
}

func argInt(args map[string]any, key string) (int, bool) {
	switch v := args[key].(type) {
	case float64:
		return int(v), true
	case int:
		return v, true
	}
	return 0, false
}

func argBool(args map[string]any, key string) bool {
	if v, ok := args[key].(bool); ok {
		return v
	}
	return false
}

func argStrSlice(args map[string]any, key string) []string {
	v, ok := args[key].([]any)
	if !ok {
		return nil
	}
	out := make([]string, 0, len(v))
	for _, it := range v {
		if s, ok := it.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

// doCall executes one REST call and maps the result: 2xx → pretty JSON text;
// 4xx/5xx → error carrying the server's structured message (the MCP client
// sees it as a tool error, which is how structured refusals surface).
func doCall(ctx context.Context, api API, token, method, path string, body any) (string, error) {
	code, b, err := doCallRaw(ctx, api, token, method, path, body)
	if err != nil {
		return "", fmt.Errorf("%s %s: %w", method, path, err)
	}
	if code >= 200 && code < 300 {
		return prettyJSON(b), nil
	}
	msg := ""
	var eb struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	}
	if json.Unmarshal(b, &eb) == nil && eb.Message != "" {
		msg = fmt.Sprintf("%s (%s)", eb.Message, eb.Code)
	} else if len(b) > 0 {
		msg = string(b)
	}
	return "", fmt.Errorf("%s %s → HTTP %d: %s", method, path, code, msg)
}

// doCallRaw is doCall's lower half: it returns the status + raw body so
// tools with binary responses (download_file) can post-process.
func doCallRaw(ctx context.Context, api API, token, method, path string, body any) (int, []byte, error) {
	return api.Call(ctx, method, path, token, body)
}

func prettyJSON(b []byte) string {
	var v any
	if err := json.Unmarshal(b, &v); err != nil {
		return string(b)
	}
	out, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return string(b)
	}
	return string(out)
}

// query builds a "?k=v&..." suffix from non-empty k/v pairs (sorted for
// determinism).
func query(pairs ...[2]string) string {
	type kv struct{ k, v string }
	var qs []kv
	for _, p := range pairs {
		if p[1] != "" {
			qs = append(qs, kv{p[0], p[1]})
		}
	}
	sort.Slice(qs, func(i, j int) bool { return qs[i].k < qs[j].k })
	if len(qs) == 0 {
		return ""
	}
	b := &url.Values{}
	for _, p := range qs {
		b.Set(p.k, p.v)
	}
	return "?" + b.Encode()
}

// ---------------------------------------------------------------------------
// tool registry
// ---------------------------------------------------------------------------

// ToolInfo is one catalog entry (for the UI and the self-description
// endpoint): name + read/write class + description.
type ToolInfo struct {
	Name        string `json:"name"`
	Write       bool   `json:"write"`
	Description string `json:"description"`
}

// writeTools are the mutating tools; every other catalog entry is read-only.
var writeTools = map[string]bool{
	"run_command":      true,
	"cancel_execution": true,
	"run_job":          true,
	"run_playbook":     true,
	"apply_updates":    true,
	"upload_file":      true,
	"create_secret":    true,
	"decide_approval":  true,
	"set_host_tag":     true,
	"delete_host_tag":  true,
	"add_host_role":    true,
	"remove_host_role": true,
	"delete_host":      true,
}

// ToolCatalog returns the tool set with its read/write classification
// (sorted by name). It is what the Web UI MCP page and the
// GET /api/v1/mcp/info endpoint render.
func ToolCatalog() []ToolInfo {
	tools := DefaultTools()
	out := make([]ToolInfo, 0, len(tools))
	for _, t := range tools {
		out = append(out, ToolInfo{Name: t.Name, Write: writeTools[t.Name], Description: t.Description})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// DefaultTools is the R11 tool set (PRD §10.3): read tools for the fleet +
// observe layer, and write tools for the governed control plane. Interactive
// PTY (open_session) is deliberately absent — MCP is request/response.
func DefaultTools() []*Tool {
	tools := []*Tool{
		// ---- reads ----
		{
			Name:        "list_hosts",
			Description: "List managed hosts: id, state (connected/disconnected), version, last seen, tags, roles, EOL status.",
			InputSchema: objSchema(map[string]any{
				"selector": strProp(`selector expression to filter ("all", "role:web", "tag:env=prod", "host:ag_x"); empty = all`),
			}),
			Call: func(ctx context.Context, api API, token string, args map[string]any) (string, error) {
				return doCall(ctx, api, token, "GET", "/api/v1/hosts"+query([2]string{"selector", argStr(args, "selector")}), nil)
			},
		},
		{
			Name:        "get_host",
			Description: "Get one host's detail: state, uuid, version, enrollment, last seen, tags, roles.",
			InputSchema: objSchema(map[string]any{"agent_id": strProp("host id (ag_…)")}, "agent_id"),
			Call: func(ctx context.Context, api API, token string, args map[string]any) (string, error) {
				return doCall(ctx, api, token, "GET", "/api/v1/hosts/"+url.PathEscape(argStr(args, "agent_id")), nil)
			},
		},
		{
			Name:        "get_host_facts",
			Description: "Get one host's collected facts (OS, kernel, uptime, interfaces, distro, …).",
			InputSchema: objSchema(map[string]any{"agent_id": strProp("host id (ag_…)")}, "agent_id"),
			Call: func(ctx context.Context, api API, token string, args map[string]any) (string, error) {
				return doCall(ctx, api, token, "GET", "/api/v1/hosts/"+url.PathEscape(argStr(args, "agent_id"))+"/facts", nil)
			},
		},
		{
			Name:        "list_groups",
			Description: "List host groups (name + selector).",
			InputSchema: objSchema(nil),
			Call: func(ctx context.Context, api API, token string, args map[string]any) (string, error) {
				return doCall(ctx, api, token, "GET", "/api/v1/groups", nil)
			},
		},
		{
			Name:        "list_executions",
			Description: "List command executions (aggregate state per execution).",
			InputSchema: objSchema(map[string]any{
				"limit": intProp("max results (default 50)"),
			}),
			Call: func(ctx context.Context, api API, token string, args map[string]any) (string, error) {
				limit := ""
				if n, ok := argInt(args, "limit"); ok {
					limit = fmt.Sprint(n)
				}
				return doCall(ctx, api, token, "GET", "/api/v1/executions"+query([2]string{"limit", limit}), nil)
			},
		},
		{
			Name:        "get_execution",
			Description: "Get one execution's detail: aggregate state + per-host runs (state, exit code, duration).",
			InputSchema: objSchema(map[string]any{"execution_id": strProp("execution id (exec_…)")}, "execution_id"),
			Call: func(ctx context.Context, api API, token string, args map[string]any) (string, error) {
				return doCall(ctx, api, token, "GET", "/api/v1/executions/"+url.PathEscape(argStr(args, "execution_id")), nil)
			},
		},
		{
			Name:        "get_execution_output",
			Description: "Get the streamed stdout/stderr chunks of an execution (per run).",
			InputSchema: objSchema(map[string]any{"execution_id": strProp("execution id (exec_…)")}, "execution_id"),
			Call: func(ctx context.Context, api API, token string, args map[string]any) (string, error) {
				return doCall(ctx, api, token, "GET", "/api/v1/executions/"+url.PathEscape(argStr(args, "execution_id"))+"/output", nil)
			},
		},
		{
			Name:        "get_audit",
			Description: "Read the append-only audit log (immutable). Filter by event kind and/or actor.",
			InputSchema: objSchema(map[string]any{
				"kind":  strProp("event kind filter (e.g. exec.dispatch, policy.deny, approval.approved)"),
				"actor": strProp("actor (principal) filter"),
				"limit": intProp("max events (default 50)"),
			}),
			Call: func(ctx context.Context, api API, token string, args map[string]any) (string, error) {
				limit := ""
				if n, ok := argInt(args, "limit"); ok {
					limit = fmt.Sprint(n)
				}
				return doCall(ctx, api, token, "GET", "/api/v1/audit"+query(
					[2]string{"kind", argStr(args, "kind")},
					[2]string{"actor", argStr(args, "actor")},
					[2]string{"limit", limit},
				), nil)
			},
		},
		{
			Name:        "list_policies",
			Description: "List policy rules (match predicate + effect: deny/allow/require_approval).",
			InputSchema: objSchema(nil),
			Call: func(ctx context.Context, api API, token string, args map[string]any) (string, error) {
				return doCall(ctx, api, token, "GET", "/api/v1/policies", nil)
			},
		},
		{
			Name:        "list_jobs",
			Description: "List scheduled jobs (cron, task, selector, enabled, last run).",
			InputSchema: objSchema(nil),
			Call: func(ctx context.Context, api API, token string, args map[string]any) (string, error) {
				return doCall(ctx, api, token, "GET", "/api/v1/jobs", nil)
			},
		},
		{
			Name:        "list_tasks",
			Description: "List tasks (ordered step definitions).",
			InputSchema: objSchema(nil),
			Call: func(ctx context.Context, api API, token string, args map[string]any) (string, error) {
				return doCall(ctx, api, token, "GET", "/api/v1/tasks", nil)
			},
		},
		{
			Name:        "list_approvals",
			Description: "List approval requests (actions parked by require_approval policy rules). State filter: pending/approved/denied/expired.",
			InputSchema: objSchema(map[string]any{
				"state": strProp("filter by state (pending|approved|denied|expired); empty = all"),
				"limit": intProp("max results (default 50)"),
			}),
			Call: func(ctx context.Context, api API, token string, args map[string]any) (string, error) {
				limit := ""
				if n, ok := argInt(args, "limit"); ok {
					limit = fmt.Sprint(n)
				}
				return doCall(ctx, api, token, "GET", "/api/v1/approvals"+query(
					[2]string{"state", argStr(args, "state")},
					[2]string{"limit", limit},
				), nil)
			},
		},
		{
			Name:        "list_alerts",
			Description: "List alerts from the alert engine (M6, R25): firing and recently resolved alerts over service/cert/config facts. Filter by state (firing|resolved) and severity (info|warning|critical).",
			InputSchema: objSchema(map[string]any{
				"state":    strProp("filter by state (firing|resolved); empty = all"),
				"severity": strProp("filter by severity (info|warning|critical)"),
			}),
			Call: func(ctx context.Context, api API, token string, args map[string]any) (string, error) {
				return doCall(ctx, api, token, "GET", "/api/v1/alerts"+query(
					[2]string{"state", argStr(args, "state")},
					[2]string{"severity", argStr(args, "severity")},
				), nil)
			},
		},
		{
			Name:        "list_updates",
			Description: "List available package updates for one host (installed vs available, CVE correlation when available).",
			InputSchema: objSchema(map[string]any{"agent_id": strProp("host id (ag_…)")}, "agent_id"),
			Call: func(ctx context.Context, api API, token string, args map[string]any) (string, error) {
				return doCall(ctx, api, token, "GET", "/api/v1/packages/updates"+query([2]string{"agent_id", argStr(args, "agent_id")}), nil)
			},
		},
		{
			Name:        "list_services",
			Description: "Fleet service health from agent-collected facts (M5, R18): unit state, enabled, deps, labels. Filter by label/state/name.",
			InputSchema: objSchema(map[string]any{
				"label": strProp("filter by label"),
				"state": strProp("filter by state (active|failed|inactive)"),
				"name":  strProp("filter by unit name substring"),
			}),
			Call: func(ctx context.Context, api API, token string, args map[string]any) (string, error) {
				return doCall(ctx, api, token, "GET", "/api/v1/services"+query(
					[2]string{"label", argStr(args, "label")},
					[2]string{"state", argStr(args, "state")},
					[2]string{"name", argStr(args, "name")},
				), nil)
			},
		},
		{
			Name:        "list_certificates",
			Description: "Fleet TLS certificate inventory (M5, R20): expiry, days remaining, subject, SAN, chain status. Filter by host and/or max days remaining.",
			InputSchema: objSchema(map[string]any{
				"agent_id":          strProp("filter by host id"),
				"days_remaining_lt": strProp("only certs expiring in fewer than N days"),
			}),
			Call: func(ctx context.Context, api API, token string, args map[string]any) (string, error) {
				days := ""
				if n, ok := argInt(args, "days_remaining_lt"); ok {
					days = fmt.Sprint(n)
				}
				return doCall(ctx, api, token, "GET", "/api/v1/certificates"+query(
					[2]string{"agent_id", argStr(args, "agent_id")},
					[2]string{"days_remaining_lt", days},
				), nil)
			},
		},
		{
			Name:        "list_configs",
			Description: "Webservice config facts per host (M5, R19): haproxy/nginx validity + topology (backends, line/brace depth).",
			InputSchema: objSchema(map[string]any{
				"agent_id": strProp("filter by host id"),
				"kind":     strProp("filter by config kind (haproxy|nginx)"),
			}),
			Call: func(ctx context.Context, api API, token string, args map[string]any) (string, error) {
				return doCall(ctx, api, token, "GET", "/api/v1/configs"+query(
					[2]string{"agent_id", argStr(args, "agent_id")},
					[2]string{"kind", argStr(args, "kind")},
				), nil)
			},
		},

		// ---- writes (RBAC + policy gated at the REST layer) ----
		{
			Name: "run_command",
			Description: "Dispatch a non-interactive command to a selector of hosts (operator+). " +
				"Policy-gated: a deny returns an error naming the rule; require_approval returns " +
				"an error with the approval request id (an admin must approve before it runs). " +
				"Returns the execution id + per-host run states.",
			InputSchema: objSchema(map[string]any{
				"selector":  strProp(`target selector ("all", "role:web", "tag:env=prod", "host:ag_x")`),
				"cmd":       strProp("command to run"),
				"args":      arrProp("string", "command arguments"),
				"timeout_s": intProp("per-run timeout seconds (default 60)"),
			}, "selector", "cmd"),
			Call: func(ctx context.Context, api API, token string, args map[string]any) (string, error) {
				body := map[string]any{"selector": argStr(args, "selector"), "cmd": argStr(args, "cmd")}
				if a := argStrSlice(args, "args"); len(a) > 0 {
					body["args"] = a
				}
				if n, ok := argInt(args, "timeout_s"); ok && n > 0 {
					body["timeout_s"] = n
				}
				return doCall(ctx, api, token, "POST", "/api/v1/executions", body)
			},
		},
		{
			Name:        "cancel_execution",
			Description: "Cancel an in-flight execution (operator+): in-flight runs are killed on the agents; pending runs are cancelled.",
			InputSchema: objSchema(map[string]any{"execution_id": strProp("execution id (exec_…)")}, "execution_id"),
			Call: func(ctx context.Context, api API, token string, args map[string]any) (string, error) {
				return doCall(ctx, api, token, "POST", "/api/v1/executions/"+url.PathEscape(argStr(args, "execution_id"))+"/cancel", nil)
			},
		},
		{
			Name:        "run_job",
			Description: "Trigger a scheduled job on one host now (operator+; job policy applies — the job's task must be policy-allowed).",
			InputSchema: objSchema(map[string]any{
				"job_id":   strProp("job id (job_…)"),
				"agent_id": strProp("host to run on (ag_…)"),
			}, "job_id", "agent_id"),
			Call: func(ctx context.Context, api API, token string, args map[string]any) (string, error) {
				return doCall(ctx, api, token, "POST", "/api/v1/jobs/"+url.PathEscape(argStr(args, "job_id"))+"/run",
					map[string]any{"agent_id": argStr(args, "agent_id")})
			},
		},
		{
			Name:        "run_playbook",
			Description: "Run a playbook (a pinned task version + selector) on every host the selector matches (operator+). Per-host outcomes come back as runs; a host whose task.run is require_approval parks with state awaiting_approval (an admin must approve it).",
			InputSchema: objSchema(map[string]any{
				"playbook_id": strProp("playbook id (pb_…)"),
			}, "playbook_id"),
			Call: func(ctx context.Context, api API, token string, args map[string]any) (string, error) {
				return doCall(ctx, api, token, "POST", "/api/v1/playbooks/"+url.PathEscape(argStr(args, "playbook_id"))+"/run", nil)
			},
		},
		{
			Name: "apply_updates",
			Description: "Apply package updates on one host (operator+). Policy-gated (pkg.apply); " +
				"with dry_run=true it only reports what would change (read-only, not gated). " +
				"Blocks until the op completes or fails.",
			InputSchema: objSchema(map[string]any{
				"agent_id": strProp("host id (ag_…)"),
				"packages": arrProp("string", "package names to update (empty = all available)"),
				"dry_run":  boolProp("true = report only, change nothing"),
			}, "agent_id"),
			Call: func(ctx context.Context, api API, token string, args map[string]any) (string, error) {
				body := map[string]any{"agent_id": argStr(args, "agent_id"), "dry_run": argBool(args, "dry_run")}
				if p := argStrSlice(args, "packages"); len(p) > 0 {
					body["packages"] = p
				}
				return doCall(ctx, api, token, "POST", "/api/v1/packages/apply", body)
			},
		},
		{
			Name: "upload_file",
			Description: "Upload a file to one host (operator+; file.write policy gate — a " +
				"require_approval match parks the op and returns 202 {approval_required}; " +
				"an admin must approve before the file lands). Content is base64.",
			InputSchema: objSchema(map[string]any{
				"agent_id":    strProp("host id (ag_…)"),
				"path":        strProp("absolute destination path on the host"),
				"content_b64": strProp("file content, base64-encoded"),
				"mode":        strProp("octal mode (e.g. 0644); default 0644"),
			}, "agent_id", "path", "content_b64"),
			Call: func(ctx context.Context, api API, token string, args map[string]any) (string, error) {
				body := map[string]any{
					"agent_id":    argStr(args, "agent_id"),
					"path":        argStr(args, "path"),
					"content_b64": argStr(args, "content_b64"),
				}
				if m := argStr(args, "mode"); m != "" {
					body["mode"] = m
				}
				return doCall(ctx, api, token, "POST", "/api/v1/files/upload", body)
			},
		},
		{
			Name: "download_file",
			Description: "Download a file from one host (operator+; file.read policy gate). " +
				"Returns the content base64-encoded with its size.",
			InputSchema: objSchema(map[string]any{
				"agent_id": strProp("host id (ag_…)"),
				"path":     strProp("absolute path on the host"),
			}, "agent_id", "path"),
			Call: func(ctx context.Context, api API, token string, args map[string]any) (string, error) {
				code, b, err := doCallRaw(ctx, api, token, "GET",
					"/api/v1/files/download"+query(
						[2]string{"agent_id", argStr(args, "agent_id")},
						[2]string{"path", argStr(args, "path")}), nil)
				if err != nil {
					return "", fmt.Errorf("GET /api/v1/files/download: %w", err)
				}
				if code < 200 || code >= 300 {
					var eb struct {
						Code    string `json:"code"`
						Message string `json:"message"`
					}
					msg := string(b)
					if json.Unmarshal(b, &eb) == nil && eb.Message != "" {
						msg = fmt.Sprintf("%s (%s)", eb.Message, eb.Code)
					}
					return "", fmt.Errorf("GET /api/v1/files/download → HTTP %d: %s", code, msg)
				}
				return prettyJSON([]byte(fmt.Sprintf(`{"path":%q,"size":%d,"content_b64":"%s"}`,
					argStr(args, "path"), len(b), base64.StdEncoding.EncodeToString(b)))), nil
			},
		},
		{
			Name: "create_secret",
			Description: "Create a secret (admin+; value is write-only — never returned by any read). " +
				"Materialized to matching hosts by the agent when a task references it.",
			InputSchema: objSchema(map[string]any{
				"name":     strProp("secret name"),
				"value":    strProp("secret value (write-only)"),
				"selector": strProp(`which hosts may materialize it ("all" or a selector)`),
			}, "name", "value"),
			Call: func(ctx context.Context, api API, token string, args map[string]any) (string, error) {
				body := map[string]any{"name": argStr(args, "name"), "value": argStr(args, "value")}
				if s := argStr(args, "selector"); s != "" {
					body["selector"] = s
				}
				return doCall(ctx, api, token, "POST", "/api/v1/secrets", body)
			},
		},
		{
			Name: "decide_approval",
			Description: "Approve or deny a pending approval request (admin+). Approve re-dispatches the " +
				"exact stored payload to the agent under a freshly signed allow decision; deny records a reason. " +
				"Only pending (unexpired) requests can be decided.",
			InputSchema: objSchema(map[string]any{
				"request_id": strProp("approval request id (apr_…)"),
				"decision":   strProp("approve | deny"),
				"reason":     strProp("deny reason (optional)"),
			}, "request_id", "decision"),
			Call: func(ctx context.Context, api API, token string, args map[string]any) (string, error) {
				decision := argStr(args, "decision")
				if decision != "approve" && decision != "deny" {
					return "", fmt.Errorf("decision must be \"approve\" or \"deny\" (got %q)", decision)
				}
				body := map[string]any{}
				if r := argStr(args, "reason"); r != "" {
					body["reason"] = r
				}
				return doCall(ctx, api, token, "POST",
					"/api/v1/approvals/"+url.PathEscape(argStr(args, "request_id"))+"/"+decision, body)
			},
		},
		// ---- host identity (tags / roles / lifecycle) ----
		{
			Name: "set_host_tag",
			Description: "Set (or replace) a tag on a host (operator+). Tags drive selectors (tag:key=value) " +
				"and display naming: the \"name\" tag is the operator-assigned display name, \"service\" the service label.",
			InputSchema: objSchema(map[string]any{
				"agent_id": strProp("host id (ag_…)"),
				"key":      strProp("tag key (no ',', '=' or spaces)"),
				"value":    strProp("tag value; omit or empty for a key-only tag"),
			}, "agent_id", "key"),
			Call: func(ctx context.Context, api API, token string, args map[string]any) (string, error) {
				body := map[string]any{}
				if v := argStr(args, "value"); v != "" {
					body["value"] = v
				}
				return doCall(ctx, api, token, "PUT",
					"/api/v1/hosts/"+url.PathEscape(argStr(args, "agent_id"))+"/tags/"+url.PathEscape(argStr(args, "key")), body)
			},
		},
		{
			Name:        "delete_host_tag",
			Description: "Remove a tag from a host (operator+).",
			InputSchema: objSchema(map[string]any{
				"agent_id": strProp("host id (ag_…)"),
				"key":      strProp("tag key"),
			}, "agent_id", "key"),
			Call: func(ctx context.Context, api API, token string, args map[string]any) (string, error) {
				return doCall(ctx, api, token, "DELETE",
					"/api/v1/hosts/"+url.PathEscape(argStr(args, "agent_id"))+"/tags/"+url.PathEscape(argStr(args, "key")), nil)
			},
		},
		{
			Name:        "add_host_role",
			Description: "Add a role to a host (operator+). Roles drive role:name selectors and the host display name fallback.",
			InputSchema: objSchema(map[string]any{
				"agent_id": strProp("host id (ag_…)"),
				"role":     strProp("role name (no ',', '=' or spaces)"),
			}, "agent_id", "role"),
			Call: func(ctx context.Context, api API, token string, args map[string]any) (string, error) {
				return doCall(ctx, api, token, "PUT",
					"/api/v1/hosts/"+url.PathEscape(argStr(args, "agent_id"))+"/roles/"+url.PathEscape(argStr(args, "role")), nil)
			},
		},
		{
			Name:        "remove_host_role",
			Description: "Remove a role from a host (operator+).",
			InputSchema: objSchema(map[string]any{
				"agent_id": strProp("host id (ag_…)"),
				"role":     strProp("role name"),
			}, "agent_id", "role"),
			Call: func(ctx context.Context, api API, token string, args map[string]any) (string, error) {
				return doCall(ctx, api, token, "DELETE",
					"/api/v1/hosts/"+url.PathEscape(argStr(args, "agent_id"))+"/roles/"+url.PathEscape(argStr(args, "role")), nil)
			},
		},
		{
			Name: "delete_host",
			Description: "Remove a host and all its data (admin+). The agent can never re-authenticate with its " +
				"current identity after deletion (re-enrollment required) — removal doubles as revocation.",
			InputSchema: objSchema(map[string]any{
				"agent_id": strProp("host id (ag_…)"),
			}, "agent_id"),
			Call: func(ctx context.Context, api API, token string, args map[string]any) (string, error) {
				return doCall(ctx, api, token, "DELETE",
					"/api/v1/hosts/"+url.PathEscape(argStr(args, "agent_id")), nil)
			},
		},
	}
	return tools
}
