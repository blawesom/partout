# Partout — Web UI Definition & Guidelines

**Status:** v0.9.5 — UI implemented (S0 shell + data pages for M1–M8.1: Fleet, Execute,
Observe (Services/Certificates/Configs/Alerts), Updates (releases + rollout runs),
Files (view/edit/upload/perm), Sessions, Jobs, Tasks, Secrets, Policies, Approvals,
Provision, Users, MCP). This document is the definition; `internal/api/webui/` is
the build. (The slice table below is the original plan; ✅ marks what has since shipped.)
**Companion docs:** `docs/ui-design.png` (north-star mockup), `PRD.md` (§3 principles, §11 Frontend,
§15.1 decisions), `docs/architecture.md` (§10.1 API, §10.2 SSE, §11 Frontend),
`docs/deployment.md` (§4 config)
**Stack (implemented):** Vue 3 (single-file SPA, no build step) with the runtime vendored in
`internal/api/webui/lib/` so a deployed binary works fully offline. No router/pinia/tailwind
packages — state and nav are in one component; styles are hand-written CSS using the §7 tokens.
`xterm.js` (PTY) and `uPlot` (metrics) are still deferred.
**Serving:** `go:embed` of `internal/api/webui/`, served same-origin on the main listener.
One binary, one origin. (Deviates from the original Vite→`web/dist` plan: the source *is* the
artifact, so `go build` needs no Node and the UI is offline-capable.)

> **Scope.** Definition and guidelines: what the UI covers, how it behaves, how it is gated by
> real capability, and in what order it ships. The implementation lives in
> `internal/api/webui/` (index.html, app.js, style.css, lib/) plus the backend prerequisites B1
> (`/api/v1/capabilities`) and B2 (`/api/v1/hosts?selector=`).

---

## 1. Purpose

The UI exists to let a human **walk the core loop without a terminal or `curl`**:

```
log in → see the fleet → run a command against a selector →
watch per-host output live → confirm it in the audit log
```

Everything else is additive. The UI is a *reflection* of the control plane, never a second
authority: the server owns RBAC, policy, selector resolution, and audit.

---

## 2. North-star reference (`docs/ui-design.png`)

The mockup is the **target shell and visual language**, not a build order. It depicts a
host-scoped updates page with policy holds and approvals — i.e. **M3/M4 surface on an M1/M2
backend**. It is used for three things only: layout, tokens, and component vocabulary.

What the mockup settles:

- Left sidebar navigation with labeled sections, scope shortcuts, and a user card footer.
- Light theme; Tailwind-default palette; monospace for ids, commands, diffs, streams.
- Breadcrumb + page-context badge + contextual top-bar actions.
- Host-scoped tab strip.
- Card/stat/alert/terminal/stream component shapes.
- Connection state displayed **inline where data flows**, not as global chrome.

What it does **not** settle (do not copy blindly):

- `FleetConsole` brand — replaced by **Partout Fleet Management**.
- `LABELS` (Production/Staging/Development) — **removed**; no tag store exists (§3).
- `Healthy / Degrading / Offline / Pending Approval` — not the data model (§9).
- `Active Alerts` — M6 alert engine; now expanded to full Observe section with Services,
  Certificates, and Configs pages (see §5 sidebar).
- `Services` — new Observe sub-page: fleet service health table with state, labels, restart count, dependency tree.
- `Approve & Apply` as a usable button — approvals engine is M4 (§4).
- `diff -u …` output — the API returns a summary string, not a diff (§3).
- Fleet-wide health cards shown inside a *host* page — incoherent; moved to the fleet landing page (§5).

> **Artifact:** the mockup has a watermark (*"until supply is restored"*) across the diff body.
> It is not UI.

**Runnable mock:** [`docs/mockups/fleet-management.html`](mockups/fleet-management.html) renders this
shell as a single static file (no build, no network, no framework) with hard-coded sample data.
Its bottom-right panel simulates `GET /api/v1/capabilities` and the current principal's role, so
both gating axes (§4) and the state vocabulary (§9) can be reviewed visually. It is a design
reference, not the application — the real UI is Vue + Tailwind embedded via `go:embed`.

---

## 3. Capability reconciliation

Status legend: **✅ real** · **🟡 shape mismatch** · **🔵 planned** (PRD milestone, no code) ·
**⛔ no source of truth**

| Mockup element | Backing in code | Verdict | Lands in |
|---|---|---|---|
| Sidebar shell, brand, port badge | listen config (`:8443`) | ✅ | S0 |
| User card (name + role) | `GET /api/v1/auth/me` → `username`, `role` | 🟡 no display name / job title | S0 |
| `FLEET` nav items | PRD §11 pages | 🟡 mock's names are invented (see §5 glossary) | S0 |
| `LABELS` | `host_tags` + `host_roles`: full CRUD shipped — `PUT/DELETE /api/v1/hosts/{id}/tags|roles`, `ctl hosts tag/role`, MCP `set_host_tag`/`add_host_role`…; host-detail UI edits them; `tag:`/`role:` selectors resolve | ✅ (shipped v0.7/M8.1 — the original ⛔ "dropped" verdict is obsolete) | S1+ |
| `GROUPS` | `GET/POST /api/v1/groups` (groups are named selectors) | ✅ no rename/delete | S1 |
| Breadcrumb `Fleet › host` | `GET /api/v1/hosts/{id}` | ✅ | S1 |
| Host tabs | overview (none) · updates ✅ · audit ✅ | 🟡 audit filter is global, not per-host | S1–S3 |
| Fleet Health cards | `GET /api/v1/hosts` → `state` | 🟡 mock's state names are wrong; count is a client roll-up | S1 |
| `382` hosts | cursor-paginated list, default limit 100 | 🟡 **no summary endpoint** — accepted, fleet is tens (§13) | S1 |
| `Active Alerts` | alert engine (M6, `internal/server/observe`): `GET /api/v1/alerts` + rules CRUD + SSE `alert.firing`/`alert.resolved`; the **Alerts page** is live with rule management, and nav badges count firing alerts | ✅ (shipped v0.6.5/v0.7) | S6 |
| `Services` | `GET /api/v1/services`; rendered as the Observe · Services page (state, labels, restart, memory) | ✅ (data page; M5 facts) | S7 |
| `Certificates` | `GET /api/v1/certificates`; Observe · Certificates page (expiry, chain status, key, self-signed) | ✅ (data page; M5 facts) | S7 |
| `Configs` | `GET /api/v1/configs`; Observe · Configs page (validity, backends/vhosts topology) | ✅ (data page; M5 facts) | S7 |
| `Dry-Run Diff` terminal | `POST /api/v1/packages/apply {dry_run}` → **`dry_summary` string** | 🟡 no diff text, no per-package records | S3 |
| `Held · <rule>` chip | policy engine returns matched **rule IDs** | ✅ | S4 |
| `Update held for approval` banner | same rule IDs; `require_approval` **fails closed today** | ✅ as a *denial* | S4 |
| `Approve & Apply` | no approvals engine, no queue, no API | 🔵 M4 | S4 |
| Approver avatar stack `+2` | no non-admin principals directory | ⛔ → initials chips | S4 |
| `PTY` top-bar action | sessions API complete; `xterm.js` UI deferred | ✅ backend, 🔵 frontend | S2 |
| `Live Patch Stream` + `SSE connected` + `live` | single broker `GET /api/v1/events` | 🟡 `stream: …` is a **display label**, not a path | S0/S1 |
| `CRITICAL CVE` badge | `/hosts/{id}/eol` + `/packages/updates` | 🟡 no fleet-wide "N hosts affected" correlation | S3 |
| Terminal frame (traffic lights) | — | ✅ pure UI | S3 |
| Static asset serving | `internal/api/webui/` `go:embed` + SPA fallback (`internal/api/static.go`) | ✅ | S0 |
| Selector resolution preview | `GET /api/v1/hosts?selector=<sel>` (B2) | ✅ | S1 |

### Selector grammar caveat

`internal/selector` supports `all`, `host:`, `tag:`, `role:`, `group:` (arch A12). Tags
and roles have had full CRUD since v0.7/M8.1 (REST, CLI, MCP, host-detail UI), so
`tag:`/`role:` predicates resolve against real data. The UI still never re-implements the
grammar: selectors are free-form text passed to the server unchanged, with
server-authoritative resolution previews (B2) and host/group shortcuts where a concrete
list helps.

---

## 4. Gating convention (capability-aware UI)

Gating must be **data-driven**, not hardcoded milestones. Two signals already exist:

1. **Disabled-subsystem responses.** Every subsystem returns HTTP 503 with a stable code when
   it is not wired: `auth`, `tls`, `files`, `sessions`, `secrets`, `packages`, `jobs`, `tasks`,
   `external_data`, `provision`, `observe` (`<name>_disabled`).
2. **A capability probe** (backend addition **B1**): `GET /api/v1/capabilities` →
   `{auth, users, hosts, groups, exec, sessions, files, jobs, tasks, packages, secrets,
   policies, audit, external_data, provision, approvals, observe}` as booleans.

One Pinia `capabilities` store is loaded after login and read by nav, routes, and buttons.

### Control states

| State | Trigger | Presentation |
|---|---|---|
| **Enabled** | capability `true` **and** role allows | normal |
| **Role-gated** | capability `true`, role insufficient | disabled, lock icon, tooltip **"Requires operator role"** / **"Requires admin role"** |
| **Not in this build** | capability `false` or absent | disabled, `Not yet available` chip, tooltip names the milestone: **"Not yet available — approvals (M4)"** |
| **Absent** | never planned | not rendered |

### Hard rules

1. **Never assume.** A control renders enabled only if the capability probe said so. Do not
   "try it and catch the 503".
2. **Never conflate.** Role-gated and not-in-build must be distinguishable at a glance
   (different affordance, different wording). Conflating them teaches users a false permission
   model.
3. **Fail closed.** Unknown/absent/erroring capability ⇒ render as unavailable, matching the
   server's fail-closed posture.
4. **Runtime flip.** A 503 `<x>_disabled` from a call means capability changed under the UI:
   refresh capabilities, switch the surface to *not in this build*, and do **not** show a red
   error banner.
5. **No dead chrome.** A disabled control must still explain itself (tooltip) and must never
   look clickable.

---

## 5. Information architecture

### Shell

- **Sidebar** (persistent, 270px): brand lockup → primary nav → scope shortcuts → user card.
- **Top bar**: breadcrumb (left), page-context badge, contextual page actions (right).
- **Body**: tab strip (for scoped pages) + sections.

### Sidebar

```
[logo]  Partout                 [:8443]   ← bold wordmark, two-line lockup
        Fleet Management                 ← muted product line
──────────────────────────────────────────
FLEET
  Fleet Management   (host inventory + the 3 health cards)
  Execute
  Audit Log
  Sessions
  Files
  Jobs
  Tasks & Playbooks
  Updates
  Secrets
  Policies
  Provision          (admin)
  Users              (admin)

OBSERVE
  Services                ← fleet service health, label filter, dependency tree
  Certificates            ← expiry timeline, chain status, cross-link to configs
  Configs                 ← haproxy/nginx validity, topology, drift comparison

GROUPS
  <named selector>              ← one row per group; selecting it filters the host list
```

- Items enable per slice (§13); not-yet-built entries render **not in this build** with the
  milestone name.
- `GROUPS` rows are **scopes, not pages** — selecting one filters Fleet Management and must be
  visually distinguishable from an active page.
- The port badge and the connection indicator are the only global status chrome.

### Page-name glossary

UI labels are presentation names; the PRD/API nouns stay authoritative.

| UI label | PRD §11 page | Primary API |
|---|---|---|
| Fleet Management | Hosts + Overview | `/hosts`, `/groups`, `/hosts/{id}/facts` |
| Execute | Execute | `/executions` |
| Audit Log | Audit | `/audit` |
| Sessions | Sessions | `/sessions` |
| Files | Files | `/files/*` |
| Jobs | Jobs | `/jobs` |
| Tasks & Playbooks | Tasks & Playbooks | `/tasks`, `/playbooks` |
| Updates | Updates | `/packages/updates`, `/packages/apply` |
| Secrets | Secrets | `/secrets` |
| Policies | Policy & Approvals | `/policies` |
| Provision | Provision | `/provision-runs`, `/provision/ssh-status` |
| Users | (admin) | `/users` |
| Observe · Services | Observe → Services | `/services`, `/services?agent_id=&name=` |
| Observe · Certificates | Observe → Certificates | `/certificates`, `/certificates?days_remaining_lt=` |
| Observe · Configs | Observe → Configs | `/configs`, `/configs?kind=&agent_id=` |

### Routes

```
/login
/                        → redirect /fleet
/fleet                   Fleet Management (host list + Fleet Health cards)
/fleet/:hostId           → redirect /fleet/:hostId/overview
/fleet/:hostId/:tab      overview | facts | terminal | files | updates | audit
/execute                 /execute/:executionId
/audit
/sessions                /sessions/:sessionId            (replay)
/files                   (global browser + host picker)
/jobs                    /jobs/:jobId
/tasks                   /tasks/:taskId       /playbooks
/updates
/secrets                 (values write-only; never displayed)
/policies
/provision               /provision/:runId
/observe                 /observe/services | /observe/certificates | /observe/configs
/users                   (admin)
/account
```

### Host detail tabs

`Overview · Facts · Terminal · Files · Updates · Audit` — enabled per slice.

**Fleet-wide cards belong on `/fleet`, not on a host page.** Host pages carry host-scoped cards
only: connection state, last seen, distro/version, updates available.

---

## 6. App shell spec

| Region | Rules |
|---|---|
| Brand | ASCII wordmark `Partout` (bold) + `Fleet Management` (muted, second line); blue hexagonal logo mark; port badge as monospace `[:8443]`. The wordmark is text, not an image. |
| User card (footer) | Initials avatar · `username` · role badge (`viewer`/`operator`/`admin`). Opens a menu: Account · Change password · Sign out. **No job title** field. |
| Top bar left | Breadcrumb `Fleet › <host>` (or page name). Page-context badge only when a real state exists (e.g. CVE severity from `/hosts/{id}/eol`). No decorative badges. |
| Top bar right | Page-scoped actions only (`PTY`, `Approve & Apply`, `Run`, `Cancel`). Non-applicable actions are disabled per §4. |
| Connection indicator | One global dot (green = SSE open, amber = reconnecting, red = down) in the top bar, plus per-widget `live` chips driven by last-event time. |
| Body | One page per route. No modal cascades. Sections separated by consistent spacing; section headings always carry their own caption/actions. |

**Density:** operator tool — compact rows, monospace for machine text, restrained color.
**Responsive floor:** usable at ≈1280px. Mobile is out of scope, but layouts must not break.

---

## 7. Design tokens

Adopt Tailwind defaults with semantic aliases. Light is the default theme; **dark is built**
(topbar toggle, `localStorage("partout_theme")`, defaults to `prefers-color-scheme`). The
dark values re-derive the same semantic tokens (slate-900 app / slate-800 surfaces, state
colors one step brighter for dark-bg contrast, `*-subtle` tints at ~14% alpha); a few
surface-specific colors (box text, scrims, shadows, brand hover) are separate tokens with
light+dark values. Terminals (`.console`, xterm) stay dark in both themes.

| Semantic | Value | Use |
|---|---|---|
| `--brand` | `blue-600 #2563eb` | logo, active nav text, active tab underline, primary button |
| `--brand-subtle` | `blue-50 #eff6ff` | active nav background |
| `--surface` | `#ffffff` | cards, sidebar, top bar |
| `--surface-app` | `slate-50 #f8fafc` | page background |
| `--border` | `slate-200 #e2e8f0` | card/table/dividers |
| `--text` | `slate-900` | headings, numbers |
| `--text-muted` | `slate-600 #475569` | body copy, descriptions |
| `--text-faint` | `slate-400 #94a3b8` | section labels, captions, metadata |
| `--state-healthy` | `emerald-600` (~`#119b70`) | connected, succeeded |
| `--state-warning` | `amber-600 #d97706` | degrading, timed out, partial |
| `--state-critical` | `red-600 #dc2626` | offline, failed, critical alert |
| `--state-critical-subtle` | `red-200 #fecaca` | critical surface borders |
| `--state-info` | `blue-600` | pending approval, running |
| `--state-neutral` | `slate-500` | cancelled, interrupted, disabled |

Rules:
- **Color never carries meaning alone.** Every state is icon + text (or icon + tooltip);
  color is reinforcement. This is an accessibility requirement, not a preference.
- Radius: `12px` cards, `8px` controls, `full` pills. Shadows: none-to-subtle; borders do the
  separating.
- Type: system/Inter stack for UI; monospace (`ui-monospace`/JetBrains Mono) for host ids,
  commands, args, diffs, stream output, and the port badge.
- Live surfaces animate; honour `prefers-reduced-motion` (fall back to static `live` chips).

---

## 8. Component inventory

Build these once in S0/S1 and reuse at S3–S5; do not re-invent per page.

| Component | Notes |
|---|---|
| `AppShell`, `Sidebar`, `NavSection`, `NavItem`, `ScopeItem`, `UserCard` | nav items accept a capability state (§4) |
| `Breadcrumb`, `ContextBadge`, `SectionHeading` | section headings take an optional caption + right-aligned slot |
| `Button` (`primary`/`secondary`/`danger`/`ghost`), `IconButton`, `SplitButton` | every button exposes `enabled`/`role-gated`/`not-in-build` |
| `Tabs` | horizontal, underline indicator, host-scoped |
| `StatCard` | muted label + state icon + large number; optional drill-through |
| `DataTable` | cursor pagination, sticky header, monospace cells opt-in, empty/loading/error states |
| `AlertRow` / `AlertList` | severity icon + title + detail + optional chip + relative time; container takes a severity tint |
| `Chip` (`neutral`/`rule`/`severity`) | used for rule IDs, holds, milestones |
| `TerminalFrame` | traffic-light chrome + monospace command line; host for diff/summary/console |
| `DiffView` | `+`/`-` line tinting, unchanged context dimmed, copy button — **required before S3 lands** (the mock omits all three) |
| `StreamConsole` | append-only monospace log, tag prefix, virtualized/windowed, autoscroll with "paused" affordance, `live` chip |
| `LiveBadge` / `StatusDot` | last-event-time driven; distinct from socket health |
| `EmptyState`, `ErrorState`, `PermissionDenied`, `NotAvailable` | the last two render `forbidden` reasons and the capability reason respectively |
| `ConfirmDialog` | required for destructive/mutating actions (remove host, apply updates, delete secret) |
| `CronField`, `SelectorField`, `WhenGuardField` | constrained inputs; the UI emits structured models, never free-form YAML |
| `AvatarStack` | initials chips + overflow count; no photo avatars until a principals endpoint exists |
| `CodeEditor` | CAS-aware file edit (S2) |
| `ServiceCard` | unit name + state icon (shield for active, X for failed, clock for restarting) + restart count + label chips; hover/expansion shows deps, enablement, resource usage |
| `ServiceDetailPanel` | full unit properties: type, restart policy, memory, CPU, dependencies (required-by/wanted-by/after), task action buttons (restart/reload/stop/disable) |
| `CertCard` | subject + issuer + days-remaining badge (color-coded: red <7d, amber <30d, green >30d) + SANs + chain status icon |
| `CertDetailPanel` | full cert detail: path, key-type, not-before/after, chain length, self-signed flag, OCSP status, cross-links to configs |
| `ConfigCard` | kind (haproxy/nginx) + version + validity icon + config hash + backends count + TLS count. Drifted config flagged with amber outline |
| `ConfigDetailPanel` | topology view: backends/servers with active counts, frontends, vhosts, TLS bindings, cross-links to certs |
| `DriftIndicator` | amber outline + "drifted: 1 of 3 hosts differ" caption |

---

## 9. State vocabulary and visuals

**Agent state** (fleet health — exactly three cards):

| `state` | Card | Visual |
|---|---|---|
| `connected` | Connected | emerald, shield-check |
| `disconnected` | Disconnected | red, circled-X |
| `pending` | Pending | blue, clock |

`revoked` is unreachable today (no revoke endpoint — see §14) and is excluded from the cards; if
it becomes reachable it gets its own row, not a card.

**Execution aggregate:** `pending · running · succeeded · failed · partial · cancelled`

**Per-run:** `queued · delivered · running · succeeded · failed · timed_out · cancelled ·
interrupted · not_delivered · denied`

**Task/playbook step:** `ok · changed · failed · skipped`

| State | Visual |
|---|---|
| `succeeded` | emerald |
| `failed` | red |
| `partial` (aggregate) | amber |
| `timed_out` | amber, clock icon |
| `cancelled` | slate, slash icon |
| `interrupted` | slate + dashed border (must differ from `cancelled`) |
| `denied` | red **outline**, no fill — a policy refusal, not an execution failure |
| `not_delivered` | amber **outline**, no fill — the host was offline; nothing ran |
| `pending` / `queued` / `delivered` | slate |
| `running` | blue + spinner (the only animated state) |

The `denied` vs `failed` and `not_delivered` vs `timed_out` distinctions are load-bearing: they
tell the operator whether anything executed at all.

---

## 10. State, liveness, and reconciliation

- **One SSE subscription**, `GET /api/v1/events`, established after login, authenticated
  with the session token as `?token=<jwt>` (EventSource cannot set headers). Pages filter
  event kinds; they never open their own stream. No polling, ever — including
  the onboarding wizard's live phase (event-driven over `provision.*`, §21).
- **Session expiry is explained, not silent.** Any API 401 goes through
  `sessionExpired()`: a warn toast ("Session expired — sign in to continue")
  explains the drop to the login page, and the interrupted route is captured
  (`_returnRoute`, first capture wins) so a successful sign-in returns the
  operator to the page they were on — a 12h in-memory session (and every server
  restart, including the one `partout update` just drove) otherwise logs
  everyone out mid-task with no explanation and no way back. Idempotent: the
  sign-out itself triggers unauthenticated page loads whose 401s re-enter the
  path, so the guard (`!token → return`) keeps the first route and one toast.
  Explicit sign-out keeps no return route (different intent).
- **Stale-data banner.** If the stream drops *after* a real connection (`sseWasConnected`
  && `sseStatus !== 'connected'`), a persistent **stale banner** appears ("Live updates
  paused — data may be stale") and the data tables dim (`.sse-stale`). This prevents an
  operator from acting on a view that looks live but isn't. It only shows after a genuine
  connection is lost, so there's no flash on initial load.
- **Loading vs. empty.** `loadPageData` sets a single `pageLoading` flag around
  each page's fetch. While `pageLoading` **and** the page's primary list is
  still empty (`pagePrimaryEmpty`), a “Loading…” indicator shows and the
  page's empty state is suppressed — so an empty table during the first load
  reads as “loading”, not “nothing here”. On a reconnect the data is already
  present, so the indicator never flashes. Empty states render only once data
  has loaded.
- **Actionable empty states.** When an empty list is something the operator can
  create, the empty state offers a primary CTA that opens the create form
  (Jobs → “+ New job”, Tasks → “Create task”, Alerts rules → “+ New rule”).
  System-generated lists (alerts, audit, sessions) stay informational.
- **Row-level dispatch feedback.** A write that targets one row (a job/task/
  playbook dispatch) reports on the affected row, not only in a global toast:
  the row's action button shows a spinner while the request is in flight, and
  an inline note row under the affected row (`.row-note`, the provision
  step-detail pattern) carries the outcome — “Dispatching on <host>…” →
  “Run started on <host> (run X, state Y)” / “Parked on approval <id>…” /
  the error text — with a Dismiss control. The note map (`jobNote`,
  `taskNote`) is keyed by row id, so concurrent dispatches on different rows
  each get their own note.
- **Event → UI map:**

| Kind | Consumer |
|---|---|
| `connected` | global connection indicator |
| `host.state` | Fleet Management list + health cards |
| `execution.state` | Execute list/detail, Audit refresh |
| `audit.event` | Audit table append |
| `session.data`, `session.opened`, `session.interrupted`, `session.result` | Sessions / PTY |
| `job.run`, `task.run` | Jobs, Tasks |
| `provision.start`, `provision.step`, `provision.connected`, `provision.key_confirm` | Provision wizard |
| `package.action` | Updates |
| `file.action` | Files |
| `alert.firing` | Fleet Management alert count, Observe pages, MCP tools |
| `alert.resolved` | Fleet Management alert count, Observe pages |
| `facts.upload` | Internal tracking (facts received) |

- **Stream widgets display their identity** (`stream: <label>`) and are always a *filtered view*
  of the single broker, never a per-resource endpoint.
- **Slow consumers are dropped** by the broker. On drop or reconnect, the UI reconciles with
  **one list refetch** and never re-issues a write. A dropped stream is a visible state
  (`amber`, "reconnecting"), not a silent stall.
- **Output must stream, not buffer**: append chunk-by-chunk, window the DOM, cap retained lines
  with a "show all" escape hatch. Large output must not block the UI.
- **Selectors are server-authoritative.** The preview calls the resolve endpoint (B2) and
  renders what the server returns; the client never re-implements the grammar. An empty
  resolution is a hard error, never a silent no-op.
- **Cursor pagination** (`next_cursor`) for all lists — no offsets.
- **Errors** render the stable codes (`bad_request`, `not_found`, `conflict`, `unauthorized`,
  `forbidden`, `throttled`, `already_terminal`, `*_disabled`) with a message, and for
  `forbidden`/policy denials the structured reason (rule ID + what would satisfy it).
- **`forbidden` is not a bug**: it renders `PermissionDenied`, distinct from `ErrorState`.

---

## 11. RBAC reflection

Roles: `viewer` < `operator` < `admin`. The UI hides/disables what the role lacks; the server
remains the authority.

| Capability | viewer | operator | admin |
|---|---|---|---|
| See hosts, facts, executions, output, audit | ✅ | ✅ | ✅ |
| Dispatch / cancel command, open PTY, upload/edit files | — | ✅ | ✅ |
| Apply updates, run jobs/tasks, create groups | — | ✅ | ✅ |
| Secrets manage/rotate, policies, provisioning, users | — | — | ✅ |

In single-user local mode the principal is `admin`; the chrome is identical with all controls
enabled.

---

## 12. Hard constraints

1. **Embedded, same-origin.** REST/SSE/gRPC/UI on one listener; the UI talks to `.` — no CORS.
2. **SSE-only liveness.** No `setInterval` data fetching. Cosmetic timers (relative time
   formatting) are fine.
3. **RBAC reflects the backend.** Never render an enabled control the role cannot use.
4. **Capability-honest.** Never render an enabled control the build cannot serve (§4).
5. **Audit is read-only.** No edit/delete affordance, ever.
6. **Secrets values are never displayed** — write-only, in every surface, including logs and
   errors.
7. **One page per route.** No modal-cascade dashboards.
8. **Selector fidelity.** Always show the concrete resolved host set before dispatch.
9. **Every stream widget names its stream** and shows a live/reconnecting state.
10. **No dead chrome.** Disabled controls explain why.
11. **UI↔API shapes are pinned by tests.** The SPA has no compile-time link to the handlers,
    so `internal/api/ui_shape_test.go` asserts the container keys/fields each page reads, and
    `scripts/ui-smoke.sh` renders the real SPA in a headless DOM against a live server and
    asserts real data appears on every page. Add a row to the smoke script when adding a page
    field — a renamed API key otherwise blanks a page without failing any Go test.

---

## 13. Slice plan

Slices follow **implementation progress**, not the mockup's ambition. Fleet-scale assumption:
**tens of hosts** (≤ ~200). Client-side roll-up and client-side filtering are accepted at this
scale; revisit if fleet size grows.

**Implementation status (v0.9.5):** S0 (shell, login, capabilities, SSE) is built. Data pages
are
live for the M1–M8.1 backend: Fleet (with pending host-key confirmations as toast + nav
badge), Execute (with B2 selector preview + live per-host output),
Audit, Sessions (with **live xterm.js PTY** — open/attach, input over REST, output over SSE,
close→replay), Files (**view/edit-CAS, upload, perm controls** — jailed to the file root),
Jobs (**create/edit/delete + run history**), Tasks (with **task/playbook
run actions** + run inspection), Updates (**M8.1 fleet releases + rollout runs**: seeded
store, run creation with canary/wave, per-host states, retry/skip/abort; package
apply / dry-run + action history on the host page), Secrets,
Policies, Approvals, MCP, Provision (**start a run, confirm/deny the host key, cancel, live
step detail over SSE**), Users, and the four Observe pages (Services (with the honest
action bar: role + target per service), Certificates, Configs (valid / **not readable** /
invalid tri-state badge with validator output),
Alerts) — the **Alerts page now includes the full rule-management UI** (create/edit/enable/
disable/delete all rule kinds), **cert→config→service cross-links** are navigable, and **config
drift (R22)** is surfaced as the `config_drift` alert rule. All slices S0–S7 are built; the only
remaining mockup element is `Active Alerts` as a standalone `/fleet` card (the Alerts page already
shows firing-now count). Write actions (jobs, packages, provision, alert rules) are exercised
end-to-end against the real server by `scripts/writes-e2e.py`.

| Slice | Capability required (all ✅ unless marked) | Mockup elements **enabled** | Mockup elements **greyed + labeled** | Exit criteria |
|---|---|---|---|---|
| **S0 — Shell** | asset embedding (**new**), login, `auth/me`, capabilities (**B1**) | sidebar, brand + port badge, user card, breadcrumb, nav, top bar, `SSE connected` / `live` | `Observe · Services`, `Observe · Certificates`, `Observe · Configs`, `Active Alerts`, `Approve & Apply` → *"not yet available (M7/M6/M4)"* | Login → shell renders; nav reflects capabilities; disabled items self-explain |
| **S1 — The loop (M1)** | hosts, selector resolve (**B2**), exec, audit, policy | Fleet Management list + **Fleet Health (3 cards)**, Execute w/ selector preview + live per-host output, Audit Log table, GROUPS | `Degrading`/`Pending Approval` cards removed; host tabs other than Overview/Audit → not available | log in → see hosts → run `whoami` via selector → watch live → confirm in audit |
| **S2 — Host workbench (M2)** | sessions, files, replay | `PTY` action, host tabs Terminal/Files, Sessions, Files | `Active Alerts` greyed | Open a PTY from a host page; upload/download/edit a file; replay a session |
| **S3 — Patch (M3)** | packages, external data, EOL | host `Updates` tab, `DiffView` rendering **`dry_summary`** in the terminal frame, captioned *"simulated · summary only"*, CVE badge, Updates page | real diff text → *"not yet available"* | Dry-run renders honestly; apply is confirmed and audited |
| **S4 — Governance (M4)** | approvals engine (**✅ shipped v0.6**) | `Held · <rule>` chips, hold banner as the **real `require_approval` denial**, Policies page, initials avatar stack, **Approvals page** (list/decide) | `Approve & Apply` (mockup flow replaced by the Approvals page) | A `require_approval` rule parks the action; admin approve/deny on the Approvals page re-dispatches with a signed decision |
| **S5 — Observe · Facts (M5)** | fact collectors (services, configs, certs), API endpoints B6–B8 | `Services` table, `Certificates` table, `Configs` table — **✅ pages shipped v0.5** | `Active Alerts` (live since **v0.6.5** — see S6) | `GET /services`, `/certificates`, `/certificates`, `/configs` return live data from a connected agent |
| **S6 — Observe · Alerts (M6)** | alert rules + engine (B9) ✅ shipped v0.6.5, SSE `alert.firing`/`alert.resolved` ✅ | **Alerts page** (firing-now count + firing/recently-resolved table, SSE-refreshed) ✅ + **rule-management UI** ✅ (shipped S7/v0.7) | `Active Alerts` on `/fleet` | A `service_failed` alert fires and appears on the Alerts page; resolving the unit resolves the alert; rules CRUD from the browser |
| **S7 — Observe · Pages (M7)** | all B6–B9 endpoints, `observe` capability boolean | `Services` page (table + detail + cross-links + `NRestarts`), `Certificates` page (expiry + chain + **Used-by** cross-links), `Configs` page (validity + **drift** + topology + cross-links), **live PTY**, **task actions**, **alert rule-management** | — | All pages render from real data; cross-links navigable; rule CRUD from the browser; live PTY round-trips (verified by `scripts/pty-e2e.py`) |

Sequencing rule: the visual vocabulary (`StatCard`, `AlertRow`, `TerminalFrame`,
`StreamConsole`, `Chip`, `Tabs`, `DiffView`) is built in S0/S1 and reused; S5–S7 add
data plumbing and new components rather than reinventing the shell.

---

## 14. Required backend additions

Definition-level asks surfaced by this reconciliation. None are implemented; each is a
prerequisite for the slice beside it.

| # | Endpoint / change | RBAC | For | Why |
|---|---|---|---|---|
| **B1** | `GET /api/v1/capabilities` → booleans per subsystem | viewer | S0 | data-driven gating (§4) instead of hardcoded milestones |
| **B2** | `GET /api/v1/hosts?selector=<sel>` → resolved set + count | viewer | S1 | selector **preview** before dispatch; today resolution only happens inside `Dispatch` |
| **B3** | `DELETE /api/v1/agents/{id}` (thin wrapper over `store.DeleteAgent`, audited) | admin | S1 | `store.DeleteAgent` exists but has **no HTTP endpoint**; decommissioned hosts would stay in the fleet forever. Also makes `revoked` reachable |
| **B4** | `GET /api/v1/audit?agent_id=` filter | viewer | later | host-scoped audit tab; client-side filtering is acceptable until log volume grows |
| **B5** | Unified-diff / per-package change records from `packages` | viewer | S3+ | the mock's `diff -u` view; today only `dry_summary` (a string) exists |
| **B6** | `GET /api/v1/services` + `GET /api/v1/services?agent_id=&name=` | viewer | S5 | fleet service health table + per-unit detail with dependency tree |
| **B7** | `GET /api/v1/certificates` + `GET /api/v1/certificates?days_remaining_lt=` | viewer | S5 | cert inventory with expiry timeline, chain status |
| **B8** | `GET /api/v1/configs` + per-host config detail | viewer | S5 | config validity, topology, cross-host drift |
| **B9** | `GET/POST/PUT/DELETE /api/v1/alerts/rules` + `GET /api/v1/alerts` | admin/viewer | S5 | alert rule CRUD + active alert list |
| **B10** | `observe` capability boolean in `/api/v1/capabilities` | — | S5 | gates all Observe pages |

Also recorded: **no static asset serving exists** (`embed.FS`, `FileServer`, `web/` all absent)
— S0 must add Vite → `web/dist` → `go:embed` plus a SPA fallback route.

**Not** to be added: a fleet summary endpoint (scale is tens — client roll-up), and any
tags/labels API (dropped).

---

## 15. Deferred / out of scope

Shipped since this list was written (kept here as history, not as open work):
**labels/tags** (full CRUD since v0.7/M8.1), **Active Alerts** (M6 alert engine + live
Alerts page, v0.6.5/v0.7), **the approvals engine** (M4 — `require_approval` parks the
action and admins approve/deny; the mockup's `Approve & Apply` flow is the Approvals
page), and **dark theme** (§7 — built, topbar toggle, OS default, per-browser persist).

Still deferred:

- **Cross-fact correlation analytics (R21)** — cert→config→service cross-links are
  rendered (S7, navigable in the UI); automated correlation analytics remain deferred.
- **Real diffs** — B5 (unified-diff / per-package change records from `packages`);
  today the Updates page renders the `dry_summary` string, captioned as a summary.
- **PWA / offline** — later polish.
- **Photo avatars** — initials chips; no principals directory for non-admins.
- **Mobile-first layouts** — floor is ~1280px.

---

## 16. Decisions log

1. **Labels removed** from the UI; no tags API will be added.
2. **Fleet Health = Connected · Disconnected · Pending** — real agent states.
3. **Fleet scale is tens of hosts** → client-side roll-up, no summary endpoint, list page size ~25.
4. **Selector preview endpoint added** (B2).
5. **Capability endpoint endorsed** (B1); gating is data-driven.
6. **Brand = "Partout Fleet Management."**
7. **Approvals shown honestly** — hold banner = the real `require_approval` denial; `Approve & Apply` greyed at M4.
8. **Diff = `dry_summary`** in the terminal frame, captioned *"simulated · summary only"*.
9. **Role lives in the user card + account page**; no job title.
10. **Initials chips** for approvers — no principals endpoint.
11. **Light default**; dark later (tokens only).
12. **Vite → `web/dist` → `go:embed`**; `web/dist` committed so `go build` needs no Node; CI gains a Vite step.
13. **Job title omitted** from the user model.
14. **Fleet Health cards live on `/fleet`**, not on host pages; host pages get host-scoped cards.
15. **Host tabs:** Overview · Facts · Terminal · Files · Updates · Audit.
16. **Host-scoped audit** = client-side filter of `GET /audit` until B4.
17. **Accessibility floor** (current state, kept honest): keyboard operation of the
    interactive non-control elements — clickable rows (fleet, executions, task/package/
    provision/services), tabs, and nav items/sections/scopes are `tabindex`-focusable with a
    visible `:focus-visible` ring and Enter activation (`Space` on nav sections); tooltips work
    on keyboard focus (`data-tip` CSS, `data-jtip` floating); icon-only controls carry
    `aria-label`s; `prefers-reduced-motion` is honoured; state is never color-only (icon +
    text). **Still open** toward full WCAG AA: a complete audit pass (form labeling and error
    association, focus order, landmark roles, a screen-reader walkthrough) — the decision-
    level target stands, the audit is tracked follow-up work.
18. **Buildless SPA (v0.5):** the UI is a single-file Vue 3 SPA in `internal/api/webui/` with the
    runtime vendored in `lib/` (offline-capable, no Node in `go build`). This supersedes decision 12's
    Vite→`web/dist` plan; the source is the artifact. Backend prerequisites B1 (`/capabilities`) and
    B2 (`/hosts?selector=`) are implemented.
18. **Brand lockup** is two lines (`Partout` / `Fleet Management`) to fit 270px.
19. **Host removal** action added to host detail with confirmation (needs B3).

---

## 17. Open questions

None blocking. Two cosmetic items to confirm during S0 review:

1. Port badge format — `[:8443]` monospace chip (as mocked) vs. `server: port` line in the
   account menu.
2. Whether `Monitoring` appears in the sidebar at all before M7, or is omitted and introduced
   with the observe layer (currently: shown, greyed, per the no-dead-chrome rule).

---

## 18. Verifying the UI

```bash
# 1. Shape contract: the response keys/fields each page reads (runs in CI).
go test ./internal/api/ -run TestUIShape -v

# 2. End-to-end render: boots an embedded server + agent, seeds data, renders the
#    real SPA in a headless DOM and asserts real data on every page.
#    Needs node/npm (installs jsdom itself) and a free port.
bash scripts/ui-smoke.sh

# 3. Browser write-path E2E: real Chromium drives the SPA through the write
#    surfaces (create a job, package DRY-RUN apply, start+cancel a provision run).
#    Needs `playwright` + a chromium install. Never performs a real package apply.
python3 scripts/writes-e2e.py

# 4. Live PTY round-trip E2E (open a terminal, type, verify the echo, replay).
python3 scripts/pty-e2e.py
```

The smoke script is the guard against the failure mode this layer is prone to: the UI has no
compile-time link to the API, so a handler rename or a loader reading the wrong response key
blanks a page silently. It found the `/secrets` `{secrets:[...]}` wrapper, `/files/list`
requiring `agent_id`, `/hosts/{id}/facts` not carrying the overview fields, and the per-host
`/packages/updates` requirement.

## 19. Add-host dialog (Fleet)

The Fleet page is the onboarding entry point: **+ Add host** in the hosts card header
(operator+) and **Add your first host** in the empty state. It opens a dialog
(`.overlay` / `.dialog card`, first dialog in the SPA; click-outside or ✕ closes)
with two explicitly framed options, because a new user with an *existing* deployment
has two valid paths and the old UI only exposed one (SSH provision, admin-only):

- **Run on the host** (primary; operator+): mint a one-time enrollment token
  (`POST /agents/enrollment-tokens`, 15-min TTL) and render a **complete recipe**:
  **1 · Get the binary onto the host** — on a stamped release build, a copy-pasteable
  `curl`+`tar` for the exact `partout_<ver>_linux_<arch>.tar.gz` asset (arch mapped from
  `uname -m`); on a dev build, the releases-page link. **2 · Trust the server CA**
  (https servers only) — the dialog fetches the root CA via the admin session
  (`GET /tls/ca`; an operator gets the `partout ctl ca` fallback instruction) and offers
  a **Download ca.crt** button. **3 · Run the agent** — `PARTOUT_SERVER=<host:port>
  PARTOUT_TLS_CA=ca.crt PARTOUT_TOKEN=par_enr_… partout --mode=agent` (the CA variable
  only on https) — with a Copy button and a live TTL countdown. The token is shown
  **once** (server-side one-time + hashed; the UI must not re-fetch or persist it).
  A note covers the proxy case (replace the browser-visible host with an address
  the host can reach). **Connection watch:** after minting, the dialog snapshots the
  fleet and reports the outcome itself — a spinner ("Waiting for the host to
  connect…") flips to **✓ Connected** (with a View host link) when a new host
  appears (diffed on every `loadHosts`, which `host.state` SSE triggers), and after
  90 s without a connect it swaps to targeted troubleshooting (token still valid?
  host→server reachability with a `curl /healthz` test line, CA present?, agent
  logs) — the operator is never left staring at an empty fleet.
- **Onboard over SSH** (admin+): the existing provision flow (`user@host` +
  fresh/join), with the **precondition stated up front** ("the server's own
  `~/.ssh` must reach `user@host`") — it used to surface only as a mid-run
  failure. Non-admins see the tab with a tooltip "requires admin role".

**fresh/join mode semantics** (tooltips on the `<option>`s + a visible hint line
`provModeHint` below the select, on both the Provision page and the dialog):
- `fresh` — clean slate: stops and removes any existing partout agent + identity on
  the host, enrolls a brand-new agent. For new hosts or a reset.
- `join` — non-destructive in-place binary update for an already-enrolled agent
  (identity preserved). For upgrades.

Guards: `TestUIShape_AddHostSurface` (entry points, both tabs, token call, tooltips)
+ `scripts/ui-smoke.js` (open dialog → mint token → recipe renders with the binary
step and the token command → CA step + `PARTOUT_TLS_CA=ca.crt` + shifted numbering
on https (faked protocol) → connection watch waiting → Connected on a new host
(real fleet diff) → troubleshooting hints after the 90 s window → tooltips → close).

## 20. Provision runs link to live host state

A finished provision run's terminal state (`connected`) is a **past-tense
snapshot** — it says enrollment happened, not that the host is healthy *now*.
Live state lives on the host, so the Provision page must link to it instead of
duplicating it:

- Runs that enrolled an agent (`run.agent_id`) show a **live host-state chip**
  (connected/disconnected, from the fleet's `hosts` list, refreshed by the
  existing `host.state` SSE) in the row's action cell. Clicking it navigates
  to `#/host/<agent_id>`.
- The inline step-detail panel (the row expands under the clicked run) shows
  the same chip plus host name, last-seen, and a **View host →** button.
- The provision page loads `hosts` on demand (`loadProvRuns` triggers
  `loadHosts` when empty) so the chip is correct without visiting Fleet first.

Guards: `scripts/ui-smoke.js` (injects a connected run + host via
`window.__partout` → asserts the chip renders → click → asserts hash
navigation to the host page).

## 21. Onboarding wizard (Provision)

The Provision page offers two paths: a **guided wizard** (the primary entry,
"Start onboarding →") and the pre-existing quick **New run** form (power
users). The wizard turns the 5-step server-side state machine into a focused,
step-by-step modal so a first-time operator isn't staring at a run table.

Phases (one modal, `provWiz` state): **1 · target** (host + mode, with live
mode guidance — see below) →
**2 · confirm** (the plan: **live SSH-key readiness**, host-key gate, the
five steps `connect → preflight → transfer → install → wait-enroll`) →
**3 · live** (**event-driven over SSE**: every `provision.*` event for the
watched run refetches it — state badge, current step, step list; the initial
fetch happens on watch/start, a stream reconnect catches up a non-terminal
run once, and a foreign run's events are ignored. There is no polling
interval — the wizard was the last poller, so the §10 "no polling, ever"
invariant now holds app-wide. A `key_confirm` run shows the fingerprint
prominently with Confirm/Deny; a terminal run shows the result). On
`connected`/`handoff` it offers a link straight to the enrolled host.

**Mode guidance (target phase).** The fresh/join choice is the wizard's main
trap — `fresh` is destructive. The selected mode shows a full one-line
explanation (`provWizModeHint`). On top of that, a **soft, targeted hint**
(`provWizKnownHost`) does a best-effort match of the target's host part
against enrolled hosts: if it looks already enrolled, a warning appears that
`fresh` will stop and remove its existing agent + identity (choose `join`),
or a neutral note that `join` updates in place. It deliberately does **not**
auto-switch the mode — a fuzzy hostname match silently changing a destructive
default would be worse than a hint. No match → no hint (a genuinely new host).

The confirm screen's **SSH access** row is dynamic: on entering the phase it
calls `GET /api/v1/provision/ssh-status` (viewer) and shows exactly what the
provisioner will use — a conventional file key (`<ssh_dir>/id_ed25519`), the
ssh-agent fallback, or a red **no identity key found** warning that a run
will fail until a key is added. This reuses the same `sshutil.IdentityStatus`
that `partout doctor` and the provisioner's own SSH args use, so the
operator sees the real outcome, not a guess. The run-lifecycle parts reuse the
existing `/provision-runs` endpoints; the quick form is unchanged.

Guards: `scripts/ui-smoke.js` (deterministic — drives the Vue instance via
`window.__partout`, no real SSH: asserts the entry button, target → confirm
phases, the mode hint + already-enrolled warning/join hint, the five-step
plan, the three SSH-access row variants, the key_confirm fingerprint panel
with Confirm/Deny, the enrolled result + host link, and close). `TestIdentityStatus` / `TestIdentityStatusAgent`
(`internal/sshutil`) pin the shared key-detection; `TestProvisionREST`
asserts the `ssh-status` endpoint shape.

**Batch onboard (hosts 2..N).** Next to the quick New-run form, a Batch card:
one `user@host` per line (same mode select), and Start issues one
`POST /provision-runs` per non-empty line — each host is its own run with its
own key-confirm gate and five steps, appearing in the runs table with live SSE
steps like any other run. Per-line failures (invalid host, and so on) are
collected and reported without aborting the batch; the summary names every
started run id. The server-side run machinery is unchanged — this is pure
fan-out over it (`scripts/fleet-provision-e2e.sh` proves the concurrent path
on real machines).

## 22. First-run UI affordances

Five small surfaces make a brand-new server self-explanatory:

- **Login page — cleartext warning.** When the page itself was served over
  plain `http:` from a non-loopback host, an amber warn-box sits above the
  sign-in form: the password and every session token would cross the network
  unencrypted; it names the remedy (`PARTOUT_TLS=on` — a local root CA is
  bootstrapped on first run — or a TLS proxy) and asks for a reload after.
  Loopback origins (`localhost`, `127.0.0.1`, `::1`, `*.localhost`, or a bare
  host) and any `https:` origin show nothing — this is the browser-side mirror
  of `partout doctor`'s plain-HTTP bind warning, for the operator who never
  ran doctor. `cleartextLogin` is a computed over `locProtocol`/`locHostname`
  captured from the real `location` at mount (data fields so the smoke
  harness can drive all three branches).
- **Login page — first-run password hint.** Below the sign-in form: “First
  run? Sign in as `admin`. If you did not set `PARTOUT_ADMIN_PASSWORD`, the
  generated password was written to `admin_password.txt` next to the database
  — log in, change it, then delete the file.” Shown only on the logged-out
  view (always, since a first-run operator has no other reference).
- **Fleet page — "Secure this server" card** (cleartext origins only). Shown while
  the page itself was served over plain `http:` from a non-loopback host (`cleartextLogin`,
  the same condition as the login banner — the operator is now signed in and can act):
  three steps — turn on TLS (`PARTOUT_TLS=on`, local-CA bootstrap, reload over https — or
  `PARTOUT_ADDR=127.0.0.1` behind a TLS proxy), rotate the admin password (Account link,
  especially if it was generated into `admin_password.txt`), review the preset guardrails
  (Policies/Alerts links). Dismissible, persisted per-browser
  (`partout.secure.dismissed`); never renders on `https:` or loopback origins.
- **Fleet page — first-command nudge** (fleet 0 → 1). Once a host is connected
  (and the getting-started checklist is not dismissed — the operator has not
  asked to stop being guided), a dismissable card walks the core loop the UI
  exists for: **Run your first command** prefills Execute with a harmless
  `uptime` scoped to the new host (the operator presses Run — nothing
  auto-executes), and **Confirm it in the audit log** links to Audit.
  Dismissal persists per-browser (`partout.nudge.firstcmd`).
- **Fleet page — getting-started checklist.** A dismissible card shown only
  while the fleet is empty (`!hosts.length`, not just filtered/scoped) and not
  yet dismissed. Three numbered steps with clear hierarchy: **1 · onboard the
  first host** is the primary action (a highlighted row + primary
  “Start onboarding →” button → Provision); **2 · review the default
  guardrails** (→ Policies / Alerts) and **3 · keep the fleet current** (→
  Updates) are secondary links. Dismissal is persisted per-browser in
  `localStorage` (`partout.gs.dismissed`) so it does not reappear.

Guards: `scripts/ui-smoke.js` (checklist: clears `hosts` on the fleet page →
asserts the card + the primary onboarding CTA → `dismissGettingStarted()` →
asserts it is gone; login hint: clears `token` to render the logged-out view → asserts
the hint → restores `token` → asserts the shell returns; cleartext: asserts no
warn-box on the loopback smoke origin → fakes a non-loopback http origin → asserts
the warn-box → fakes https → asserts it is gone, plus the `isLoopbackHost` matrix)
and `TestUIShape_CleartextLoginBanner` (pins the binding, the computed, and the
`PARTOUT_TLS=on` remedy against silent removal).

## 23. Tooltip mechanism (`data-tip`)

A lightweight, focus-capable tooltip for **non-clipped** elements (spans,
badges, the sidebar brand). `data-tip` + CSS shows the text on hover **and**
keyboard focus (`:focus-visible`) — the native `title=` only covers hover for
mouse users. Long text wraps (max-width 280px); `data-tip-pos="below"` flips
it under the element for topbar items near the top edge.

Migrated: sidebar server version, the SSE status dot, the EOL/external-data
status chip, and the “unsigned (beta)” release badge. A `tabindex` is added
where the element wasn’t otherwise focusable so keyboard users can reach it.

**Deliberate ceiling — now lifted for the highest-value cases.** A **body-ported
JS tooltip** (`data-jtip`) ships for the `overflow:hidden` truncated cells the
CSS `::after` tooltip cannot reach: a single floating element
(`initJTip()`, delegated `mouseover`/`mouseout`/`focusin`/`focusout` listeners
— no per-cell wiring) shows the full text on hover **and** keyboard focus
(cells carry `tabindex="0"`), positioned below the cell and clamped to the
viewport (above when there is no room), hidden on leave/blur/scroll. Same
visual language as `[data-tip]`; `word-break` + `pre-wrap` suit long sha256
and error text. Migrated sites: the sessions output excerpt, the release
sha256, the update-run host error, and the provision-run error cells.
`<option>` mode hints still use native `title=` (CSS and the floating tip
cannot reach select options); their guidance is already inline text. Remaining
`title=` sites (buttons, non-clipped cells) are fine as-is — native hover
tooltips on unclipped elements behave identically.

## 24. Confirmation dialog (no native `confirm()`)

All destructive/security actions use the shared **confirm dialog**
(`askConfirm`), never the browser's `confirm()` — the native dialog is
unstyled, blocking, and can't show context. `askConfirm(opts)` returns a
Promise<boolean> and renders a modal with:

- `title` + `body` (multi-line), and an optional `mono` block for the exact
target (host id, fingerprint, release) so the operator sees what's affected.
- a `variant` (`danger` / `primary` / `ok`) on the confirm button.
- an optional `requireText` **type-to-confirm guard**: for the highest-stakes
  actions (Remove host, Delete release, Delete secret/user) the operator must
  type the exact id/version/name before the confirm button enables.
- `askInput(opts)` — the same dialog with a **free-text input** (optionally
  `inputType: "password"`) instead of a boolean: resolves the trimmed input on
  confirm, `null` on cancel/Esc. The typed replacement for the remaining
  native `prompt()` sites: the approval **deny reason** (recorded on the audit
  trail) and the **secret rotate value** (password-masked — a native prompt
  echoed the secret in cleartext). The job/task host picker and group-create
  prompts remain native `prompt()` for now (multi-field forms, add-on-request).
- `Esc` or Cancel resolves `false` for `askConfirm`, `null` for `askInput`.

The host-key **confirm** in the provision flow now renders the fingerprint in
the `mono` block (previously it was `\n`-separated text in a native
`confirm()`), which is the one place a glanceable, prominent fingerprint
matters most. Deny still uses a `prompt()` for the optional reason (input, not
a confirmation).
