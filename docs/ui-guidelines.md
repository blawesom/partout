# Partout — Web UI Definition & Guidelines

**Status:** Draft v0.4 — capacity reconciliation + slices (definition only, **not implementation**)
**Companion docs:** `docs/ui-design.png` (north-star mockup), `PRD.md` (§3 principles, §11 Frontend,
§15.1 decisions), `docs/architecture.md` (§10.1 API, §10.2 SSE, §11 Frontend),
`docs/deployment.md` (§4 config)
**Stack:** Vue 3 + TypeScript + Pinia + Tailwind; `xterm.js` (PTY), `uPlot` (metrics, later)
**Serving:** Vite → `web/dist` → `go:embed`, served on the main listener. One binary, one origin.

> **Scope.** This document is *definition and guidelines*: what the UI covers, how it behaves,
> how it is gated by real capability, and in what order it ships. It contains no code and does
> not scaffold `web/`. It exists so each slice is small, honest, and verifiable.

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
- `Active Alerts` — no alert engine exists (M5).
- `Approve & Apply` as a usable button — approvals engine is M4 (§4).
- `diff -u …` output — the API returns a summary string, not a diff (§3).
- Fleet-wide health cards shown inside a *host* page — incoherent; moved to the fleet landing page (§5).

> **Artifact:** the mockup has a watermark (*"until supply is restored"*) across the diff body.
> It is not UI.

---

## 3. Capability reconciliation

Status legend: **✅ real** · **🟡 shape mismatch** · **🔵 planned** (PRD milestone, no code) ·
**⛔ no source of truth**

| Mockup element | Backing in code | Verdict | Lands in |
|---|---|---|---|
| Sidebar shell, brand, port badge | listen config (`:8443`) | ✅ | S0 |
| User card (name + role) | `GET /api/v1/auth/me` → `username`, `role` | 🟡 no display name / job title | S0 |
| `FLEET` nav items | PRD §11 pages | 🟡 mock's names are invented (see §5 glossary) | S0 |
| `LABELS` | `host_tags` table exists, **zero writers, zero endpoints** | ⛔ always empty | **dropped** |
| `GROUPS` | `GET/POST /api/v1/groups` (groups are named selectors) | ✅ no rename/delete | S1 |
| Breadcrumb `Fleet › host` | `GET /api/v1/hosts/{id}` | ✅ | S1 |
| Host tabs | overview (none) · updates ✅ · audit ✅ | 🟡 audit filter is global, not per-host | S1–S3 |
| Fleet Health cards | `GET /api/v1/hosts` → `state` | 🟡 mock's state names are wrong; count is a client roll-up | S1 |
| `382` hosts | cursor-paginated list, default limit 100 | 🟡 **no summary endpoint** — accepted, fleet is tens (§13) | S1 |
| `Active Alerts` | `internal/server/observe` is empty; no thresholds, no alert store | ⛔ 🔵 M5 | S5 |
| `Dry-Run Diff` terminal | `POST /api/v1/packages/apply {dry_run}` → **`dry_summary` string** | 🟡 no diff text, no per-package records | S3 |
| `Held · <rule>` chip | policy engine returns matched **rule IDs** | ✅ | S4 |
| `Update held for approval` banner | same rule IDs; `require_approval` **fails closed today** | ✅ as a *denial* | S4 |
| `Approve & Apply` | no approvals engine, no queue, no API | 🔵 M4 | S4 |
| Approver avatar stack `+2` | no non-admin principals directory | ⛔ → initials chips | S4 |
| `PTY` top-bar action | sessions API complete; `xterm.js` UI deferred | ✅ backend, 🔵 frontend | S2 |
| `Live Patch Stream` + `SSE connected` + `live` | single broker `GET /api/v1/events` | 🟡 `stream: …` is a **display label**, not a path | S0/S1 |
| `CRITICAL CVE` badge | `/hosts/{id}/eol` + `/packages/updates` | 🟡 no fleet-wide "N hosts affected" correlation | S3 |
| Terminal frame (traffic lights) | — | ✅ pure UI | S3 |
| Static asset serving | **no `embed.FS`, no `FileServer`, no `web/`** | ⛔ **S0 prerequisite** | S0 |
| Selector resolution preview | resolution happens *inside* `Dispatch`; no endpoint | ⛔ **backend addition B2** | S1 |

### Selector grammar caveat

`internal/selector` supports `all`, `host:`, `tag:`, `role:`, `group:` (arch A12). Because
nothing populates `host_tags` or agent roles, **the UI must not offer `tag:` / `role:`
shortcuts** — they resolve empty. Offer `host:` and `group:` only, and let free-form selector
text pass through to the server unchanged (the UI never re-implements the grammar).

---

## 4. Gating convention (capability-aware UI)

Gating must be **data-driven**, not hardcoded milestones. Two signals already exist:

1. **Disabled-subsystem responses.** Every subsystem returns HTTP 503 with a stable code when
   it is not wired: `auth`, `tls`, `files`, `sessions`, `secrets`, `packages`, `jobs`, `tasks`,
   `external_data` (`<name>_disabled`).
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
| Provision | Provision | `/provision-runs` |
| Users | (admin) | `/users` |

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

Adopt Tailwind defaults with semantic aliases. Light is the default theme; dark is a planned
toggle (tokens defined, not built).

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

- **One SSE subscription**, `GET /api/v1/events`, established after login. Pages filter
  event kinds; they never open their own stream. No polling, ever.
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

---

## 13. Slice plan

Slices follow **implementation progress**, not the mockup's ambition. Fleet-scale assumption:
**tens of hosts** (≤ ~200). Client-side roll-up and client-side filtering are accepted at this
scale; revisit if fleet size grows.

| Slice | Capability required (all ✅ unless marked) | Mockup elements **enabled** | Mockup elements **greyed + labeled** | Exit criteria |
|---|---|---|---|---|
| **S0 — Shell** | asset embedding (**new**), login, `auth/me`, capabilities (**B1**) | sidebar, brand + port badge, user card, breadcrumb, nav, top bar, `SSE connected` / `live` | `Monitoring`, `Active Alerts`, `Approve & Apply` → *"not yet available (M5/M4)"* | Login → shell renders; nav reflects capabilities; disabled items self-explain |
| **S1 — The loop (M1)** | hosts, selector resolve (**B2**), exec, audit, policy | Fleet Management list + **Fleet Health (3 cards)**, Execute w/ selector preview + live per-host output, Audit Log table, GROUPS | `Degrading`/`Pending Approval` cards removed; host tabs other than Overview/Audit → not available | log in → see hosts → run `whoami` via selector → watch live → confirm in audit |
| **S2 — Host workbench (M2)** | sessions, files, replay | `PTY` action, host tabs Terminal/Files, Sessions, Files | `Active Alerts` greyed | Open a PTY from a host page; upload/download/edit a file; replay a session |
| **S3 — Patch (M3)** | packages, external data, EOL | host `Updates` tab, `DiffView` rendering **`dry_summary`** in the terminal frame, captioned *"simulated · summary only"*, CVE badge, Updates page | real diff text → *"not yet available"* | Dry-run renders honestly; apply is confirmed and audited |
| **S4 — Governance (M4)** | approvals engine (**not built**) | `Held · <rule>` chips, hold banner as the **real `require_approval` denial**, Policies page, initials avatar stack | `Approve & Apply` → *"approvals engine (M4)"* until the engine lands | A `require_approval` rule produces a truthful hold; approval flow completes once the engine exists |
| **S5 — Observe (M5)** | thresholds, alert store, uPlot | `Active Alerts`, `Monitoring`, real health model, metrics | — | Alerts and health render from real data |

Sequencing rule: the visual vocabulary (`StatCard`, `AlertRow`, `TerminalFrame`,
`StreamConsole`, `Chip`, `Tabs`, `DiffView`) is built in S0/S1 and reused, so S3–S5 add data
plumbing rather than new components.

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

Also recorded: **no static asset serving exists** (`embed.FS`, `FileServer`, `web/` all absent)
— S0 must add Vite → `web/dist` → `go:embed` plus a SPA fallback route.

**Not** to be added: a fleet summary endpoint (scale is tens — client roll-up), and any
tags/labels API (dropped).

---

## 15. Deferred / out of scope

- **Labels/tags** — dropped; the `host_tags` table has no writers. `tag:`/`role:` selector
  predicates are not surfaced in the UI until a tag store exists.
- **Active Alerts / Monitoring / Observe dashboard** — M5; `internal/server/observe` is empty.
- **Approvals engine** — M4; `require_approval` behaves as deny today.
- **Real diffs** — B5.
- **Dark theme** — tokens defined, not built.
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
17. **Accessibility floor:** WCAG AA, full keyboard operation, `prefers-reduced-motion` honoured, no color-only state.
18. **Brand lockup** is two lines (`Partout` / `Fleet Management`) to fit 270px.
19. **Host removal** action added to host detail with confirmation (needs B3).

---

## 17. Open questions

None blocking. Two cosmetic items to confirm during S0 review:

1. Port badge format — `[:8443]` monospace chip (as mocked) vs. `server: port` line in the
   account menu.
2. Whether `Monitoring` appears in the sidebar at all before M5, or is omitted and introduced
   with the observe layer (currently: shown, greyed, per the no-dead-chrome rule).
