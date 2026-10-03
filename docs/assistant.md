# Partout — LLM Assistant (design)

**Status:** ✅ implemented — 1.0 slice shipped in v0.9.9 (the 1.0-scoped beta) · **PRD:** R26 (§4), Decisions 17–19 (§15.1), Milestone M9 (§14) · **Mockup:** [`mockups/assistant.html`](mockups/assistant.html)
**Companions:** `PRD.md` (R11 MCP, §10.3), `docs/architecture.md` (§10 API, §11 Frontend),
`docs/ui-guidelines.md` (tokens, state vocabulary, capability gating), `internal/server/mcp/`
(tool registry, `API` interface).

---

## 1. Purpose

Let the operator **configure an external LLM endpoint** (OpenAI-compatible) and chat with a
built-in assistant that can inspect and act on the fleet **through the exact same governed tool
surface the MCP server already exposes** — no new write path, no bypassed gates.

```
user: "any certs expiring soon on role:web?"
assistant: [list_hosts] [list_certificates] → "api-2: cert expires in 6 days (Apr 18)…"
user: "can you renew it?"
assistant: [run_playbook] → "parked for approval #42 — an admin must decide (link)"
```

The assistant is a *reflection of the control plane*, same doctrine as the UI (ui-guidelines §1):
RBAC, policy, approvals, and audit are enforced by the server, never by the model.

## 2. Goals / non-goals

**Goals**
- Reuse the `mcp.Tool` registry verbatim — one tool surface, two front doors (MCP clients + in-UI assistant). Design invariant.
- Model-agnostic: any OpenAI-compatible `chat/completions` + `tools` endpoint (OpenAI, OpenRouter, Ollama, vLLM, LM Studio, Azure).
- Hard, configurable boundaries: tool profiles, per-run caps, cancellation.
- Full audit parity: every assistant action is a normal audit row, tagged with assistant session + model.

**Non-goals (1.0 slice)**
- No streaming from the LLM mid-token *for tool results* (SSE to the browser is event-level, not token-level — simpler, still responsive).
- No multi-agent orchestration, no RAG over the fact store, no `decide_approval` for the assistant (approvals stay human).
- No fine-tuned/hosted model — the endpoint is always operator-configured; Partout never ships a model.

## 3. Architecture

```
Browser (Assistant panel)                    Settings > Assistant (admin)
     │  POST /api/v1/assistant/chat (SSE)          │
     ▼                                             ▼
┌────────────────────────── CONTROL PLANE ─────────────────────────────┐
│  internal/server/assistant  (new package)                            │
│   • llm.go     — OpenAI-compatible client (chat + tools, retry)      │
│   • loop.go    — agent loop: LLM ⇄ tool dispatch, caps, cancel       │
│   • profile.go — tool profiles (allow-lists over the MCP catalog)    │
│   • config.go  — endpoint store (base URL, model, vault key, caps)   │
│  mcp.Tool registry (reused) · in-process mcp.localAPI · user token   │
│  → REST router → RBAC → policy gate → approvals → audit             │
└──────────────────────────────────────────────────────────────────────┘
                            │  outbound HTTPS (audited egress)
                            ▼
                  user-configured LLM endpoint
```

Key decisions:

1. **The assistant acts as the user.** Every tool call runs through the in-process REST
   router with the authenticated user's role-scoped token — the same path `localAPI` already
   uses for `/mcp`. Structured refusals (403 role, policy deny, `approval_required`) come back
   as tool errors and are rendered as chat events ("parked for approval #42, link").
2. **Profiles = documented boundaries** (see §6). Profile selection is per-session and capped
   by the user's role (viewer → readonly only; operator → up to operator; admin → any).
3. **Endpoint config is admin-only and server-wide (PRD Decision 19).** One admin-set
   endpoint is the only egress destination — one consent surface, one audit destination,
   no personal keys; per-user endpoints, if ever requested, ship as an admin-granted
   capability (never user-self-serve URL+key entry). First-class deployment: a local
   endpoint (Ollama/vLLM on the server host — zero external egress). Base URL, model, max
   turns, default profile; API key in the existing secrets vault (write-only, masked in
   UI — ui-guidelines §12.6).
4. **One loop, small.** `loop.go` is deliberately dumb: send messages + tool schemas →
   execute requested tools in-process → append results → repeat until the model stops
   requesting tools or a cap fires. No retry-on-hallucination, no re-planning.

## 4. API surface (new)

| Endpoint | Auth | Purpose |
|---|---|---|
| `GET  /api/v1/assistant/config` | operator (admin for write) | endpoint, model, caps, default profile |
| `PUT  /api/v1/assistant/config` | admin | update endpoint/model/caps; key via secrets vault |
| `GET  /api/v1/assistant/capabilities` | operator | probe: `tools` support, model, latency — and the enablement **hard gate**: no tool calling → refuse with a clear error (no text-protocol emulation fallback) |
| `POST /api/v1/assistant/sessions` | operator+ | create session (profile) |
| `POST /api/v1/assistant/sessions/{id}/chat` | session owner, **SSE** | one user turn → event stream (`assistant_delta`, `tool_call`, `tool_result`, `approval_required`, `egress`, `done`) |
| `POST /api/v1/assistant/sessions/{id}/cancel` | session owner | abort in-flight loop |
| `GET  /api/v1/assistant/sessions/{id}` | session owner | transcript + tool calls + audit links |

SSE, not token streaming: the client renders **events** (tool chips, result summaries,
approval cards) which is what a control-plane UI wants; token-level streaming adds little
value and complicates cancellation/audit.

## 5. Components & effort

| Piece | Notes | ~LOC |
|---|---|---|
| `assistant/llm.go` | OpenAI-compatible client, `tools` param, timeouts, one retry | 200 |
| `assistant/loop.go` | dispatch, caps (max tool calls, wall clock, context trim of large tool results) | 200 |
| `assistant/profile.go` + `config.go` | profiles over `mcp.ToolCatalog()` read/write split; endpoint store | 250 |
| `assistant/store.go` | `assistant_sessions` + `assistant_messages` (Decision 18), retention sweep (30 d default) | 120 |
| `internal/api/assistant.go` | routes, SSE, authz, egress audit hook | 300 |
| UI: Assistant panel + Settings card | event renderer, tool chips, approval link, egress banner | ~1 day |
| Docs: threat model, boundaries matrix | this doc + PRD/roadmap entries | — |

**Realistic 1.0 slice: 2–3 days.** `mcp.Tool`/`localAPI`/`ToolCatalog` are reused unchanged.

## 6. Boundaries (the "documented" part)

| Profile | Tools | Notes |
|---|---|---|
| `readonly` (default) | all read tools | no mutating calls possible, even if the model asks |
| `operator` | readonly + write tools | every write still hits policy + can park on approval |
| `full` | operator + `create_secret`, `delete_host`, role/tag mgmt | admin-only profile |

Never assistant-reachable: **`decide_approval`** (approvals are a human act) and interactive
PTY (already absent from the MCP tool set).

Per-run caps (server-configured, admin): max tool calls per turn (default 15), max loop
wall clock (default 120 s), max tool-result bytes per call (truncated, default 32 KB).

## 7. Security & threat model

1. **Data egress.** Fleet hostnames, command output, and file contents leave to an
   operator-chosen external endpoint. Mitigations:
   - a **blocking consent modal at first enablement** (the data boundary changes — that
     deserves an explicit click) plus the recurring egress badge on every session header
     (`egress` SSE event: endpoint host, model, approx bytes);
   - per-turn egress audit row; prompts **not** logged by default (opt-in flag, admin);
   - `readonly` default profile; local endpoints (Ollama/LM Studio) are a zero-egress option.
2. **Prompt injection via host output.** Command/file output is untrusted data that
   re-enters the model context and can steer it toward tool calls. The existing policy
   deny-list + approval parking bounds the blast radius — the model can *request* a write
   but never *approve* one. This is the reason every tool call routes through the control
   plane rather than calling agents directly.
3. **RBAC.** Assistant capabilities = user role ∩ profile. A viewer gets readonly regardless
   of configuration.
4. **Key handling.** Endpoint API key lives in the secrets vault, write-only, never returned;
   egress to the LLM uses it server-side only — the browser never sees it.

## 8. UX (see mockup)

- **Assistant** sidebar entry (gated like MCP: off/hidden when no endpoint configured).
- Chat column: user messages, assistant prose, **tool chips** (name + one-line result +
  audit link), **approval cards** (parked action, payload, decide link), cancel button.
- Session header: profile selector (capped by role), endpoint + model, egress badge.
- **Settings > Assistant** (admin): endpoint URL, model, caps, default profile, key status
  (set/reset), capabilities-probe result.
- Quick wins after the 1.0 slice: "Explain" buttons on alert/execution detail views (read-only single
  call), alert-triage drafts proposing remediation playbooks (parked as approvals),
  scheduled natural-language checks, fleet-drift reports.

## 9. Phasing

1. **1.0 slice — chat + profiles + config + audit tag + transcript store +
   mockup-matching UI.** (this doc; PRD Decisions 17–19) Ships with 1.0 — built after
   the roadmap item-20 gate.
2. **1.0.x — Explain buttons + alert-triage draft** (reuse: same loop, one-shot prompts).
3. **later — scheduled NL checks, drift reports, token-budget metering in UI.**

## 10. Decisions (recorded)

- **Transcripts persist — split-store (PRD Decision 18).** `assistant_sessions` +
  `assistant_messages`, 30-day default retention (the sessions-recording precedent).
  The transcript holds full prompts + replies — user-owned, admin-readable (the
  approvals visibility split). Audit rows carry the action half only: `source=assistant`,
  session id, model, tool calls, prompt sha256 (correlation without content; "prompts
  not logged" is about the audit log and its opt-in flag).
- **One server-wide, admin-set endpoint (PRD Decision 19).** Single egress destination;
  per-user endpoints only ever as an admin-granted capability. Local endpoints
  (Ollama/vLLM on the server host) are the zero-egress first-class option.
- **SSE stays event-level.** No token streaming in v1; if an operator asks, it ships
  behind a config flag as a new event type (no schema change).
- **`readonly` default profile; blocking consent modal at first enablement; hard `tools`
  probe gate** — no emulation fallback for function-call-weak models.
