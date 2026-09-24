# PRD — Partout: Remote Host Management

**Product:** Partout
**Repo:** `hiersoir` (rename to `partout` as a follow-up)
**Status:** Draft v0.3 — all open questions resolved
**Date:** 2025-09-21

---

## 1. Summary

Partout is a **remote host management control plane**: a single Go binary that lets you
discover, execute against, configure, patch, and orchestrate work across many Linux hosts —
from a central server with a web UI and an MCP server for AI assistants.

It embeds a full **read/observe layer** (monitoring: containers, endpoints, heartbeats,
certificates, resources, alerts) as its own, adds a **write/control path** on top of it, and
sources facts from **external public data** (OS end-of-support dates, package vulnerability
feeds) wherever doing so beats embedding stale tables.

> **The one-sentence positioning:**
> Partout answers *"how do I reach every host, run things, and make them converge to a state I
> declare?"* — and its entire purpose is to touch your hosts, safely and auditably.

---

## 2. Problem & positioning

### 2.1 Problem

Operators manage fleets with a patchwork of SSH keys, bastion hosts, ad-hoc `ssh` loops,
`rsync`/`scp`, per-host cron, and hand-written Ansible/Puppet/Chef. This imposes:

- **No single inventory** — hosts are spread across `~/.ssh/config`, cloud consoles, spreadsheets.
- **No audit trail** — "who ran what where" lives in shell history and syslog, if at all.
- **Credential sprawl** — SSH keys and `sudo` on every host, with no revocation story.
- **No safe automation surface** — there is no first-class, policy-checked way for an AI assistant
  or a script to act on a host without shelling out to `ssh`.
- **Heavyweight convergence tooling** — configuration management demands agents + control nodes
  + a DSL, which is overkill for "run this, make sure these files/package/service exist."

### 2.2 Positioning

Partout occupies the gap between **read-only monitoring** (which observes hosts but never
mutates them) and **heavyweight configuration management** (which demands agents + control
nodes + a DSL). Its posture:

| Dimension | Partout |
|---|---|
| Relationship to hosts | **Read + write** (executes, configures, patches) |
| Primary question | "How do I make it so, and prove it?" |
| Agent purpose | Bidirectional: stream state *up*, receive commands *down* |
| Safety posture | Central: authz, audit, approval, guardrails, idempotency |
| Licensing | No editions — every capability is free and self-hosted |

Partout is **not** an SSH multiplexer (it is agent-based, no inbound SSH on hosts) and **not** a
full desired-state orchestrator in the Ansible/Chef sense (it favors small, idempotent,
declarative *tasks* over a new DSL). It brings a "one binary, zero deps, real-time" ethos to the
control plane.

**Monitoring is embedded, not delegated.** Partout ships its own read/observe surface
(containers, endpoints, heartbeats, certificates, resources, alerts) as a first-class layer, so
the product loop is *"observe → act → verify"* in one dashboard. There is no dependency on a
separate monitoring tool; the control plane consumes the same inventory and facts the observe
layer collects.

### 2.3 Personas

- **Solo self-hoster** — one or a handful of VPS/bare-metal boxes; wants one pane to run commands,
  push files, schedule jobs, and see results without juggling keys.
- **Fleet operator** — tens-to-hundreds of hosts; wants grouping, targeting, approvals, and audit.
- **AI assistant / automation** — Claude Code / Cursor / CI wants a governed MCP surface to inspect
  and (with policy) act on hosts, instead of raw SSH.

---

## 3. Design principles

1. **Single binary** — Vue 3 frontend embedded via `embed.FS`; one file to deploy.
2. **Zero external dependencies** — SQLite by default; optional PostgreSQL for the
   server data set; no Redis, no queue, no control node beyond the server.
3. **Real-time by default** — state changes pushed via SSE; no polling.
4. **Agent-based, no inbound SSH** — hosts run a lightweight agent that holds an
   outbound connection; the server never needs SSH credentials to the hosts.
5. **Label/declarative-driven** — targeting and task intent expressed declaratively
   (labels, tags, roles, selectors), not as imperative shell one-offs.
6. **Runtime-agnostic** — the agent auto-detects environment (systemd, Docker, K8s node).
7. **Read-before-write observability** — every mutation is grounded in a live read of host
   state, so "make it so" is checkable, not fire-and-forget.
8. **Everything is auditable** — every command, file change, job, and package action is
   recorded with actor, host, input, output, exit code, and timing. This is non-negotiable.
9. **Principle of least privilege by default** — the agent runs unprivileged; privilege
   elevation is explicit, scoped, and recorded per action.
10. **Fail-safe network path** — commands are not silently dropped; the outage spool and
    idempotency model (see §7) guarantee at-least-once, converge-on-retry semantics.
11. **Live external facts over embedded tables** — where a fact changes over time (OS
    support dates, package vulnerabilities), fetch it from a public source at runtime with a
    safe fallback, rather than baking a snapshot into the binary (see §6.3).

---

## 4. Requirements matrix

The requirements reference for the rest of this document. R1–R16 cover platform and
observability concerns; C1–C9 cover the control-plane capabilities unique to Partout.

| # | Concern | Notes |
|---|---|---|
| R1 | Agent/server/embedded **modes** (`--mode=`) | Three modes; `embedded` = self-managed single host. |
| R2 | **Enrollment** (one-time token, hashed at rest, shown once) | One-time token, hashed at rest, shown once; token naming `par_enr_…`. |
| R3 | **Ed25519 identity + challenge-response** per stream | `identity.json` mode `0600`; `sign(nonce ‖ uuid ‖ ts_be64)`; ±300s skew. |
| R4 | **gRPC bidirectional stream** + reconnection backoff | The stream is event-*up* and adds a command-*down* channel on the same connection. |
| R5 | ~~**Outage spool**~~ ⬜ **REVIEW** (memory→disk→drop-oldest) | Also spools *outbound command results* and *inbound command delivery acknowledgements*. |
| R6 | **Per-agent rate limiting** (token bucket) | Applies to both event upload and command dispatch. |
| R7 | **Revoke/delete/edit-label** agent lifecycle | Cascade delete of all host-scoped rows. |
| R8 | **`agent_id` on all entities** + cascade | Every command/file/job/package row carries `agent_id`. |
| R9 | **Storage engines** (SQLite default, optional Postgres, one migration version) | One dialect abstraction; replaceable-server rationale. |
| R10 | **REST v1 + SSE broker** | New handlers for the control surface; shared broker fan-out. |
| R11 | **MCP server** (stdio + Streamable HTTP, OAuth2 PKCE) | Monitoring read tools; adds **write** tools under policy. |
| R12 | **UI stack** (Vue 3 + TS + Pinia + Tailwind + uPlot + PWA) | Vue 3 + TS + Pinia + Tailwind + uPlot + PWA; new pages. |
| R13 | **Host OS identification** (`/etc/os-release`, `osImage`, support table) | Feeds package/patch logic and the external data refresh (§6.3). |
| R14 | **Editions/licensing** | No editions or license keys; every capability is free and self-hosted. |
| R15 | **Config via env vars; label-driven discovery** | Configuration via env vars; label-driven discovery. |
| R16 | **Install paths** (bare binary + systemd, `docker run`, compose, cloud-init, Helm) | Bare binary + systemd, `docker run`, compose, cloud-init, Helm. |
| R17 | **Host provisioning** (server installs the agent over the operator's existing fleet SSH) | Preflight → scp binary + unit → start agent → standard enrollment. Credentials used in-memory only; never persisted; Docker-host installs are manual handoff. |
| C1 | **Remote command execution** (ad-hoc, sessions, scripts) | The core control primitive. |
| C2 | **File management** (upload/download/edit/perm/checksum) | |
| C3 | **Targeting model** (groups, tags, roles, selectors) | Groups, tags, roles, selectors. |
| C4 | **Scheduled/automated jobs** across hosts | Partout *runs* scheduled work across hosts. |
| C5 | **Declarative tasks / playbooks** (idempotent steps) | Small, JSON/YAML-defined steps; not a DSL. |
| C6 | **Package & patch management** (apt/dnf/apk) | Reuses R13 OS identity + external CVE data (§6.3). |
| C7 | **Secrets** (host-scoped distribution) | |
| C8 | **Execution audit log + approvals + policy guardrails** | The trust boundary that lets this be safe. |
| C9 | **RBAC / human identity** | A control plane needs users and roles. |
| C10 | **Host provisioning** | Server-side agent bootstrap over the operator's existing fleet SSH; admin-gated, policy-evaluable, fully audited. One-time: no persistent SSH use afterward. |

---

## 5. Core capabilities (functional requirements)

### 5.1 Host inventory, provisioning & enrollment — `[R1,R2,R3,R8,R13,R17,C10]`

The multi-host model:

- Three modes: `embedded` (single host, self-managed), `server` (central), `agent` (remote).
- Enrollment token: one-time, cleartext shown once, stored as `sha256` + first-14 mask.
- Agent generates Ed25519 keypair on first boot → `RegisterAgent` → enrolled → bidirectional stream.
- Every host reports OS identity (os-release / `osImage`) and, new for Partout, an expanded
  **capability/fact set**: distro+version, init system (systemd/OpenRC), package manager,
  arch, CPU/mem/disk, installed package list hash (change-detection only — the full
  package+version list is fetched on demand by package operations, §5.6), running services
  (systemd units),
  users/groups (names only), and network interfaces. Facts are refreshed hourly and on change.

**New — targeting model `[C3]`:**
- Hosts carry **tags** (key=value and key-only) and **roles**, assigned via enrollment `--label`,
  the UI, the API, or an MCP tool.
- **Selectors** reference hosts for every action: `role=web`, `tag:env=prod`, explicit host list,
  `all`, or a saved **group** (a named selector).
- A selector always resolves to a concrete host set at dispatch time and is recorded with the job.

**Host provisioning `[R17,C10]`:** the server bootstraps the agent on a new host over the
operator's *existing* fleet SSH credentials on the server box (the server process can already
`ssh` to its hosts). Flow: (1) UI/API "add host" with address or `~/.ssh/config` alias +
install mode (systemd / bare); (2) preflight over SSH — host-key check (fingerprint shown and
confirmed for unknown hosts), os-release/arch/init detected, sudo capability probed,
existing install detected (idempotent: re-provisioning an installed host offers *update*);
(3) the same-version binary is copied via `scp` (sha256 verified on the host), the systemd
unit + env file (with a fresh one-time token) are written, and the agent is started;
(4) the agent generates its own Ed25519 keypair locally and completes the standard
enrollment flow above — provisioning never registers on the agent's behalf. SSH is used
**only** for this bootstrap: it never carries commands, files, or observation data, and no
credential is persisted server-side. Hosts the server cannot reach over SSH (air-gapped,
Docker-host installs in v1) get a **manual handoff**: the UI hands the operator the binary
and a one-line install command with the token.

**Acceptance criteria:**
- Provisioning a reachable host (systemd or bare) yields a connected agent with facts visible
  in <10s after the provisioning step completes; every step is streamed to the UI live and
  recorded in the audit log (`provision` taxonomy kind).
- An unknown SSH host key blocks provisioning until the operator confirms the fingerprint in
  the wizard; confirmed fingerprints are written to the server's `known_hosts`.
- Enrolling a host with a token yields a connected agent with facts visible in <10s.
- Revoking an agent closes its stream immediately and purges its rows (cascade).
- Selectors resolve deterministically; empty result is an error, never a silent no-op.

### 5.2 Remote command execution — `[C1]`

The core primitive. Three surfaces, one implementation:

1. **Ad-hoc command** — one-shot `cmd` with args, cwd, env, timeout, working user, optional
   privilege escalation (`sudo`/`runuser`, scoped), and stdin. Returns stdout/stderr (streamed),
   exit code, and wall-clock duration.
2. **Interactive session** — a long-lived PTY stream with real-time input/output, scrollback,
   and session recording (optional, stored, replayable). Output flows server → browser over SSE;
   input flows browser → server as `POST /api/v1/sessions/{id}/input`, then down the gRPC
   back-channel (WebSocket is a future optimization, not v1).
3. **Script execution** — upload or reference a script; run with a declared interpreter/shebang.

**Semantics:**
- Streaming output over the same gRPC stream (server → agent command, agent → server output),
  chunked and order-preserving; large output is not buffered whole in memory.
- **Cancellation** (SIGINT/SIGTERM/SIGKILL escalation) and **timeout** (default 30s, configurable,
  hard cap) are first-class and recorded.
- **Working directory** default is the agent's home; `$HOME`, `$PATH` sanitized.
- Commands are **logged in full** (command, args, env keys — never env *values* unless marked
  secret, which are redacted), with a unique `execution_id`.

**Acceptance criteria:**
- A command dispatched to N hosts streams per-host output in real time to the UI.
- A timed-out or cancelled command is reported distinctly from a non-zero exit.
- Output of a finished command is retrievable for the retention window (§9).

### 5.3 File management — `[C2]`

- **Upload** a file (or directory tarball) to a host path; atomic write (temp + rename).
- **Download** a file/directory from a host.
- **Read/edit** small text files with content-addressed concurrency (compare-and-swap on checksum).
- **Stat** — mode, owner, group, size, mtime, sha256.
- **Permissions/ownership** changes recorded as their own audit entry.
- All transfers bounded by size limits (§12); symlinks are not followed across the transfer boundary
  (path-traversal protections).

### 5.4 Scheduled & automated jobs — `[C4]`

- Define a **job** = (selector, schedule, task). Schedule in cron syntax with timezone; one-off and
  recurring.
- Jobs are **agent-side** (the agent runs them on its own clock) so the server being down or a
  network partition does not stop scheduled work; results spool and replay (`[R5]`).
- **Selector resolution is server-side**: a job's selector resolves to concrete per-host
  schedules (plus a recorded selector snapshot) at save/update time; agents receive and run those
  resolved schedules, never the selector itself. Server-down stops *new* job edits, not
  already-distributed work.
- Job runs produce the same audit record as ad-hoc commands, plus a job-run lineage.
- **Overlap policy** — allow-concurrent / skip-if-running / replace, per job.
- **Failure policy** — retry with backoff, and optional alert via the alert channel system.

**Acceptance criteria:**
- A scheduled job runs agent-side with the server stopped, and its result replays on reconnect.
- Editing a job's selector re-resolves and re-pushes per-host schedules.

### 5.5 Declarative tasks / playbooks — `[C5]`

A **task** is a small, idempotent, ordered list of steps. Steps are **intent**, not shell:

| Step type | Semantics |
|---|---|
| `command` | Run; pass if exit 0 (or declared expected codes). |
| `file` | Ensure file exists with content/mode/owner; `state: present|absent`. |
| `package` | Ensure package `present|absent|latest` via native package manager. |
| `service` | Ensure systemd unit `started|stopped|enabled|disabled`. |
| `user` / `group` | Ensure user/group exists with declared attrs. |
| `template` | Render a small template (values from task vars or a secret ref) then `file`. |
| `assert` | Run a check; fail the task if false (drives convergence). |
| `reboot` | Reboot with a post-reboot continuation handshake. The agent persists task-run state and a `resume-after-reboot` marker in its local spool; on start it resumes any pending continuation and reports `rebooting → resumed`. |

- Tasks are **declarative and re-runnable**: each step states the desired end-state; the agent
  checks before changing and reports `changed|ok|failed`.
- Tasks are versioned, and a **playbook** is a saved task (or task set) bound to a selector.
- **`when` guards (optional).** Every step may carry a `when` condition evaluated **agent-side**
  before the step runs; the step is skipped (reported `skipped`) when false. `when` is a
  **constrained expression** — not free-form code: a small fact-based grammar
  (`fact.key == 'value'`, `host.distro in ['debian','ubuntu']`, `!file.exists('/x')`, `and`/`or`).
  It reads live host facts (§5.1) and can never execute arbitrary commands, so the guard itself
  stays safe and auditable.
- Deliberately **no** general-purpose YAML DSL: no loops, no branching beyond `when`.
  Anything more complex (loops, multi-branch) is a script (`5.2`), which keeps the language
  surface tiny and auditable.

**Acceptance criteria:**
- Re-running a completed task is a no-op (`ok`) or `changed`, never a duplicate side effect.
- A false `when` reports `skipped`, distinct from `ok`/`changed`/`failed`.

### 5.6 Package & patch management — `[C6]` `[R13]`

- `list-updates` per host (apt/dnf/apk native; OS identity from R13 decides the backend).
- `apply-updates` — dry-run first (always), then apply; staged by selector; per-host rollback
  journal (package version before/after).
- **Vulnerability-driven prioritization**: installed packages are correlated against public
  vulnerability feeds (§6.3) so updates are ranked by severity, not alphabetically.
- OS end-of-support data (from endoflife.date, §6.3) now also **gates** patch automation: an
  `ended` host is flagged and defaults to "require approval" for upgrades.

**Acceptance criteria:**
- `list-updates` ranks by CVE severity, not alphabetically.
- `apply-updates` always dry-runs first and records a per-host before/after journal.

### 5.7 Secrets — `[C7]`

- Server-side secret store: key → value, encrypted at rest, versioned.
- **Key management**: the server reads a master key from `PARTOUT_SECRET_KEY_FILE` (mode `0600`)
  or `PARTOUT_SECRET_KEY` (env); per-secret keys are derived via HKDF from the master key. No
  key configured → the secrets feature is disabled with a clear startup error. Losing the master
  key loses the store; KMS/HSM remains post-v1.
- **Distribution**: a secret is bound to a selector and materialized agent-side only for the
  lifetime of a task/command that declares it (injected as env var, temp file, or template value);
  never written to the spool in cleartext; never returned by read APIs.
- **Rotation**: new version invalidates prior binding; audit records which version was used.
- **Offline jobs**: secrets are fetched at run time over the live stream. If the server is
  unreachable, a step that declares a secret fails closed with a recorded "secret unavailable"
  result. An optional per-secret `offline_ttl` (default `0` = never cache) permits an agent to
  hold an encrypted copy for a bounded window.

**Acceptance criteria:**
- A secret's value is never returned by any read API or written to the spool in cleartext.
- Rotating a secret invalidates prior bindings and records which version each run used.

### 5.8 Audit, approvals & guardrails — `[C8,C9]`

The section that makes this a safe control plane rather than a remote shell.

- **Execution audit log**: append-only record of every command/file/job/task/package/secrets
  action — actor, host, selector, full input, output reference, exit code, timestamps, elevation used.
  Privileged commands are recorded **in full** — the exact elevated command including the
  `sudo`/`runuser` wrapper and all arguments, with no redaction (see §15).
  Immutable (no update/delete endpoints); retained per §9.
- **Approvals**: a policy may require approval for actions matching a predicate (e.g. any
  `apply-updates`, any command with `sudo`, any action on `role=db`). Approval requests carry the
  exact payload; approvers act via UI/API/MCP; approvals are recorded with the execution.
- **Guardrails / policy engine**: declarative rules that *deny or require-approval* based on
  host tag/role, command pattern (allowlist/denylist regex), elevation, time window, and actor
  role. Evaluated server-side before dispatch and agent-side before execution (defense in depth).
  Regex is a coarse first gate only (prefer structured argv matching when available); the
  authoritative boundary is elevation scoping (Decision 3) + full-fidelity audit.
- **Policy replication**: the server pushes a versioned, content-hashed policy bundle to each
  agent; every dispatch also carries a signed per-command server decision. The agent re-checks
  against its cached bundle and denies on divergence. Scheduled jobs run against the
  last-received bundle; if it is older than a configurable staleness window, the job fails closed.
- **Human identity & RBAC**: local users (v1); OIDC post-v1; roles
  `viewer`, `operator`, `admin`. Every actor is a principal, not an anonymous session.

**Acceptance criteria:**
- A denied action never reaches the agent.
- Every executed action can be attributed to a principal and replayed from the audit log
  (full output replay within the 30-day output window; after that, metadata only — exit code,
  duration, redacted command, output digest).
- An approval can be scoped to the exact payload, not a blanket "allow".

---

## 6. Architecture

Architecture overview:

```
┌──────────────────────────────────────────────────────┐
│                  Single Go Binary                     │
│   Vue 3 + TS + Tailwind (embed.FS) · SSE · uPlot     │
│   REST API v1 + SSE Broker + MCP (stdio + HTTP)      │
│        ┌─────────────── Control Plane ─────────────┐ │
│        │ Policy · Approval · Secrets · Audit       │ │
│        │ Targeting · Jobs · Tasks · Playbooks      │ │
│        └───────────────────────────────────────────┘ │
│        ┌─────────────── Observe Layer ─────────────┐  │
│        │ Containers · Endpoints · Heartbeats ·     │  │
│        │ Certificates · Resources · Alerts         │  │
│        └───────────────────────────────────────────┘  │
│        ┌─────────────── Transport ─────────────────┐  │
│        │ gRPC bidirectional (events ↑ commands ↓)  │  │
│        │ Ed25519 challenge-response · spool · rl   │  │
│        └───────────────────────────────────────────┘  │
│              │                    │                    │
│      ┌───────▼───────┐    ┌───────▼───────┐            │
│      │  Agent (host) │    │ Agent (host)  │  …         │
│      │ observe·exec· │    │ jobs·pkg·svc  │            │
│      │ fs·facts      │    │               │            │
│      └───────────────┘    └───────────────┘            │
│   SQLite (default) · PostgreSQL (optional server data) │
└──────────────────────────────────────────────────────┘
```

Key architecture points:

1. **Bidirectional stream.** The gRPC stream carries events *up* **and** command envelopes
   *down*, with per-envelope ACK/result correlation IDs, on a single persistent connection with
   reconnection (R4).
2. **The agent gains a write surface** (`exec`, `fs`, `job`, `task`, `pkg` modules) that sits
   behind the same auth handshake and is subject to agent-side guardrails.
3. **The server gains a control plane** (policy/approval/audit/secrets/targeting) that sits in
   front of the transport, so every dispatch passes through it. The observe layer is a sibling
   plane that feeds facts into both monitoring and control decisions.
4. **SSE broker reuse**: the broker now also fans out live command output, job run transitions,
   and audit events to browsers.

### 6.1 Command flow (end-to-end)

```
Client (UI/API/MCP)
  → REST: POST /api/v1/executions  (payload: selector, cmd, policy-relevant fields)
    → Control plane: resolve selector → hosts; evaluate policy (deny / require-approval)
      → Audit: write execution + per-host run (state=pending)
        → Dispatch: enqueue command envelope on each host's stream (ACL'd by agent auth)
          → Agent: re-check guardrails → execute (pty/non-pty) → stream output chunks
            → Server: correlate by execution_id/run_id → persist output → SSE broadcast
              → Completion: record exit code/timing → resolve → notify (alerts if policy says)
```

### 6.2 Reconnection & delivery semantics

- The spool (R5) now holds **both directions**: event upload and
  command result upload. A command dispatched while an agent is offline is queued with a TTL;
  on reconnect the agent fetches pending envelopes before streaming. Replay is at-least-once,
  deduped server-side by `(run_id, chunk_seq)`. **REVIEW: the original design specified an
  in-process SQLite `spool.db`; the implementation uses per-run append-only `.sp` logs
  (`<data dir>/spool/<run_id>.sp`), which is simpler and avoids WAL contention on the main DB.
  Does the PRD requirement text need updating?**
- **Idempotency / convergence**: a command interrupted by disconnect is reported as `interrupted`,
  not silently dropped. Tasks/playbooks are convergent (re-run to completion); ad-hoc commands are
  not auto-replayed unless flagged `retryable`.
- At-least-once for results; the audit log dedupes by `run_id`.

### 6.3 External public data sources

Partout prefers **live, public sources** for facts that change over time, instead of embedding
snapshots in the binary. The server (which has outbound access) fetches and caches them; the agent
never fetches them directly.

| Data | Public source | Use |
|---|---|---|
| OS end-of-support dates | [endoflife.date](https://endoflife.date) | Gates patch automation; drives per-host `supported/ending_soon/ended` state (R13). |
| Package vulnerabilities (OS) | Distro security trackers: Debian Security Tracker, Ubuntu USN/CVE tracker, Red Hat errata, Alpine secdb, Rocky/Alma errata | Ranks `list-updates` by severity; drives `apply-updates` priority. |
| Package vulnerabilities (cross-distro) | [OSV.dev](https://osv.dev) / GitHub Security Advisories (GHSA) | Fills gaps the distro trackers don't cover; dedupes against distro data by CVE ID. |

**Refresh & fallback rules (all-or-nothing):**
- Refreshed once at startup and then on a daily cadence. A manual refresh can be triggered at
  any time via API; daily is sufficient for both EOL dates and CVE data (see §15).
- A refresh replaces the cache only if **all** fetches succeed and parse; any failure leaves the
  previous cache untouched and logs one line — never a partial or empty table.
- An env switch (`PARTOUT_DISABLE_EXTERNAL_DATA_REFRESH`) turns the fetches off for air-gapped
  deployments; the last cached copy (or a minimal embedded fallback for EOL dates) then applies.
- **No host *identity*, host lists, or operator data leaves the network**. Vulnerability
  correlation does share installed-package identifiers (name+version, plus distro+version) with
  the sources above as query parameters; this is gated by the same air-gapped switch
  (`PARTOUT_DISABLE_EXTERNAL_DATA_REFRESH`). Telemetry, if enabled at all, is governed by the
  opt-out switch.

---

## 7. Security model

This is the highest-risk area. Layers:

| Layer | Mechanism | Ref |
|---|---|---|
| Transport | TLS at gRPC listener, or h2c behind trusted proxy (opt-in) | R4 |
| Per-stream auth | Ed25519 challenge-response, fresh nonce, ±300s skew | R3 |
| Enrollment | One-time token, hashed at rest, shown once, masked | R2 |
| Agent identity | `identity.json` mode 0600; revoke = new keypair | R3 |
| **Agent privilege** | Runs unprivileged; elevation explicit + recorded per action | C8 |
| **Command authz** | Policy engine: allowlist/denylist, approval gates, RBAC roles | C8/C9 |
| **Agent-side guardrails** | Re-check policy before execution (defense in depth) | C8 |
| **Secrets** | Encrypted at rest, versioned, scoped materialization, never in spool/API | C7 |
| **Audit immutability** | Append-only, no mutate/delete endpoints; cryptographic tamper-evidence is a deferred post-v1 enhancement (§15) | C8 |
| **Human identity** | Local users (v1); OIDC post-v1; no anonymous write surface | C9 |
| **Path safety** | No symlink traversal on transfers; atomic writes; size caps | C2 |
| **External data** | Outbound-only fetches, no host data in requests, cached + validated | §6.3 |
| **Provisioning SSH** | Preflight + binary install via the operator's pre-existing fleet keys; in-memory use only; admin-gated, policy-evaluable, per-step audited | §5.1, C10 |

**Non-negotiable invariants:**
1. No SSH-based command or observation path exists in Partout. The agent stream is the sole
data/execution channel. SSH is used **only** for agent provisioning (§5.1), exclusively via
the operator's pre-existing fleet credentials on the server; Partout never creates, copies,
or persists fleet keys.
2. No write path without an authenticated principal (humans and MCP both authenticate).
3. No command reaches a host without a server-side policy evaluation **and** an agent-side re-check.
4. Secrets are never persisted in cleartext outside the server's encrypted store.
5. No host *identity*, host lists, or operator data is transmitted to external data sources
   (installed-package identifiers are shared for vulnerability correlation; see §6.3).

---

## 8. Data model (high level)

Every entity carries `agent_id` (`NULL` = local/embedded), SQL
cascade delete on agent removal, TEXT keys, epoch-second BIGINTs, `ON CONFLICT ... DO UPDATE`.

New tables (illustrative):

- `hosts` (alias of agents) + `host_facts` (JSON facts, latest + history)
- `host_tags`, `host_roles`, `groups`
- `executions` (1) → `execution_runs` (N per host) → `output_chunks` (streamed, retention-bounded)
- `sessions` (PTY) → `session_records`
- `files_actions` (upload/download/edit/stat audit)
- `jobs`, `job_runs`
- `tasks`, `task_versions`, `playbooks`, `task_runs`, `task_run_steps`
- `package_actions` (list/apply/dry-run + per-host journal) + `vulnerability_cache` (§6.3)
- `secrets`, `secret_versions`, `secret_bindings`
- `audit_events` (append-only, covering all of the above)
- `policies`, `approval_requests`, `approvals`
- `principals` (users) + `roles`
- `provision_runs` (per-host provisioning steps + status, linked to `agent_id` once enrolled; see architecture §3.5)

Storage engine rules, single-writer, WAL, and one-migration-version across SQLite/PostgreSQL
follow R9. Retention (§9) applies to output chunks, session recordings, and job/task runs;
the audit log and secret versions have their own, longer retention.

---

## 9. Retention & limits

| Data | Retention (default) | Notes |
|---|---|---|
| Command output chunks | 30 days | Bounded; large outputs stream to disk, not RAM |
| Session recordings | 30 days | Optional at capture time |
| Job/task run history | 90 days | Raw runs; rollups beyond |
| Host facts history | 90 days | Latest always kept |
| **Audit log** | Indefinitely by default (no auto-purge); operator-configurable floor | Immutable; operator-configurable |
| Secret versions | Until rotated (no auto-delete) | |
| External data cache | Until next successful refresh | Never partially applied |
| Spool | 16 MB mem / 128 MB disk / 24 h age | |

Limits: max command output size, max upload/download size, max concurrent runs per host, rate
limits per agent and per principal. All configurable via env vars.

---

## 10. API surface

### 10.1 REST (v1)

Illustrative. Full OpenAPI spec is a later deliverable.

```
# Hosts & targeting
GET    /api/v1/hosts
GET    /api/v1/hosts/{id}
GET    /api/v1/hosts/{id}/facts
POST   /api/v1/hosts/{id}/tags          DELETE /api/v1/hosts/{id}/tags
GET    /api/v1/groups                   POST /api/v1/groups
# Enrollment
POST   /api/v1/agents/enrollment-tokens
DELETE /api/v1/agents/{id}              # revoke/delete
# Provisioning (R17, C10)
POST   /api/v1/hosts/provision          # start bootstrap (live step log via SSE)
GET    /api/v1/provision-runs/{id}      # run status + per-step log
# Execution
POST   /api/v1/executions               # dispatch command/script
GET    /api/v1/executions/{id}          # status + per-host runs
GET    /api/v1/executions/{id}/output   # streamed chunks
POST   /api/v1/executions/{id}/cancel
POST   /api/v1/sessions                 # open PTY session
POST   /api/v1/sessions/{id}/input     # PTY stdin (output via SSE)
# Files
POST   /api/v1/files/upload   GET /api/v1/files/download
GET    /api/v1/files/stat     POST /api/v1/files/edit
# Jobs & tasks
CRUD   /api/v1/jobs            POST /api/v1/jobs/{id}/run
CRUD   /api/v1/tasks           CRUD /api/v1/playbooks
POST   /api/v1/playbooks/{id}/run
# Packages
GET    /api/v1/hosts/{id}/updates      POST /api/v1/hosts/updates/apply
# Secrets, policy, approvals, audit
CRUD   /api/v1/secrets       (values write-only)
CRUD   /api/v1/policies      CRUD /api/v1/approvals
GET    /api/v1/audit
# Monitoring endpoints, alerts, channels, status page
```

### 10.2 SSE

Single `/api/v1/events` stream (or per-resource) carrying:
command output chunks, job/task run transitions, host connection state, approval requests,
provision run steps (R17), audit events, and alert events (alert engine).

### 10.3 MCP server

- Transport + OAuth2 (PKCE) scaffolding (R11): stdio + Streamable HTTP.
- All **read** monitoring tools (containers, endpoints, heartbeats, certificates,
  resources, alerts, updates, security) for the embedded observe layer.
- Add **read** tools: `list_hosts`, `get_host_facts`, `list_groups`, `list_updates`,
  `list_jobs`, `list_tasks`, `get_audit`, `list_sessions`, `get_session`.
- Add **write** tools, each gated by policy/RBAC and producing audit entries:
  `run_command`, `upload_file`, `download_file`, `run_job`, `run_playbook`,
  `apply_updates`, `create_secret` (value write-only), `request_approval`. Interactive PTY
  (`open_session`) is deliberately **not** an MCP tool — MCP is request/response; terminals are a
  UI/CLI surface. `run_command` is the non-interactive MCP equivalent.
- Write tools refuse by default unless the caller's principal has the role + the policy permits;
  the same decision-table pattern — a structured refusal that names the offending rule and what
  would satisfy it — is used for `policy_denied` / `approval_required` (the control-plane
  gate).

---

## 11. Frontend

Stack per R12. New pages:

- **Hosts** — inventory, facts, tags/roles, connection state, per-host terminal + files.
- **Provision** — "add host" wizard: address or `~/.ssh/config` alias, install mode,
  fingerprint confirmation gate, live per-step progress over SSE, manual-handoff output
  for unreachable hosts.
- **Execute** — ad-hoc command builder with selector, live per-host output, cancel/timeout.
- **Sessions** — PTY terminal with recording/replay.
- **Files** — per-host file browser with upload/download/edit/stat.
- **Jobs** — scheduler list, run history, overlap/failure policy.
- **Tasks & Playbooks** — step editor (declarative, not raw YAML), run results with
  `changed|ok|failed` coloring.
- **Updates** — per-host package updates ranked by CVE severity, dry-run → apply, EOL gating.
- **Secrets** — store, bind, rotate (values never shown).
- **Policy & Approvals** — rule editor, pending approvals queue.
- **Audit** — filterable, append-only log.
- **Observe** — the embedded monitoring dashboard feeding the
  "observe → act → verify" loop.
- **Overview** — "fleet control" summary (hosts connected, pending approvals, recent failures)
  alongside monitoring widgets.

---

## 12. Licensing

**No editions, everything free.** Partout is not provided as a service — there are no tiers,
no license keys, and no paid features. Every capability in this PRD (hosts, execution, files,
sessions, jobs, tasks/playbooks, packages, CVE-ranked updates, secrets, policy engine, audit log,
MCP write tools, and the embedded observe layer) is available to all users, self-hosted.

The product differentiates on the control plane (safe, auditable remote management), not on a
feature paywall (R14). Consequences that follow from "everything free":

- No license-validation subsystem, no `get_edition` endpoint, no `edition_required` errors.
- No host-cap or feature gating; scaling to more hosts is purely a capacity question, not a
  licensing one.
- Support/maintenance, if offered later, would be a *service* (out of scope here), not a
  feature gate.

---

## 13. Non-goals (v1)

- **Not** a general SSH bastion / port-forwarding tool (provisioning reuses the operator's
  existing fleet SSH one-way — it is not an interactive or forwarding surface).
- **Not** a per-host SSH credential store (v1): the server uses only the fleet keys already
  present on the server box; no key import, no per-host key management, no key rotation UI.
  (A secrets-store-backed per-host credential option is a post-v1 consideration.)
- **Not** a full configuration-management DSL (no Puppet/Chef/Ansible compatibility layer; no
  roles-in-YAML with loops/conditionals — those are scripts + tasks).
- **Not** Windows host management (Linux first).
- **Not** an orchestrator for HA of itself (no leader election;
  the operator's cluster manager owns that).
- **Not** container-*orchestration* (Swarm/K8s control); containers are observed, not scheduled.
- **Not** a replacement for secret managers at enterprise scale (no HSM/KMS integration in v1;
  a pluggable KMS hook is a later concern).

---

## 14. Milestones

- **M0 — Spine:** modes, enrollment, Ed25519 auth, gRPC stream, spool,
  SQLite/Postgres dialect, SSE broker, UI shell. (This is ~80% of the scaffolding.)
- **M1 — First write path:** ad-hoc command execution + streaming output + audit log + policy
  deny-list + RBAC. *Ship the safety floor before anything else mutates.* Host provisioning
  (R17) lands here — it is the first server-initiated write to a host, so it inherits the same
  safety floor (RBAC, policy evaluation, full-fidelity audit) rather than bolting it on.
- **M2 — Files & sessions:** file browser, transfers, PTY terminal, recording.
- **M3 — Automation:** jobs, tasks/playbooks, packages, secrets, external data refresh (§6.3).
- **M4 — Governance:** approvals, full policy, MCP write tools.
- **M5 — Distribution & polish:** installers, cloud-init, Helm, status page integration.

---

## 15. Decisions & open questions

### 15.1 Decisions made

1. **Monitoring — embedded, not delegated.** The read/observe layer is part of Partout itself
   (§6), enabling "observe → act → verify" without a separate monitoring tool.
2. **External data — live public sources preferred.** OS end-of-support (endoflife.date) and
   package vulnerability feeds (distro trackers, OSV.dev, GHSA) are fetched at runtime with
   all-or-nothing refresh and safe fallback (§6.3), rather than embedded snapshots.
3. **Elevation — hybrid.** Default is per-command `sudoers`-style: the agent only
   elevates commands that match a named `sudoers` entry, scoped to the exact command pattern.
   A host-level default (`--elevate=none|sudoers|sudo`) can loosen *or tighten* the base posture
   for the whole host; per-command overrides can always tighten (never loosen) the host default.
   Precedence: `per-command > host-level`, and `sudoers` wins over `sudo` at any level.
4. **Task language — minimal + `when`.** Tasks are ordered idempotent steps with a
   single optional `when` guard per step — a constrained, fact-based expression evaluated
   agent-side (never free-form code). No loops and no branching beyond `when`; anything more
   complex is a script. Steps skipped by a false `when` report `skipped`, distinct from
   `ok`/`changed`.
5. **Audit tamper-evidence — append-only + retention.** The audit log is append-only
   with no update/delete endpoints and long retention (§9); no cryptographic hash-chain in v1.
   Tamper evidence relies on restricting DB access and, optionally, exporting the log to a
   secure sink. A content-addressed/WORM hash-chain is recorded as a **deferred post-v1**
   enhancement, not a v1 requirement.
6. **Human identity — local users only.** First-run creates an admin user; the server
   maintains its own user database with role assignment. OIDC is deferred to a **post-v1**
   enhancement, keeping the product self-contained.
7. **Licensing — no editions, everything free.** Nothing is provided as a service, so there are
   no tiers, no license keys, and no paid features. Every capability is free and self-hosted.
   The product differentiates on the control plane, not on a feature paywall (§12).
8. **Sudo/privilege recording — full fidelity.** Privileged commands are recorded in the audit
   log as-is, including the exact elevated command (`sudo -u root apt-get install foo`) and all
   arguments. No redaction — secrets passed as args are a usage error the audit log will surface,
   not mask away.
9. **External data freshness — daily is sufficient.** The daily refresh cadence is adequate for
   both OS EOL dates and package vulnerability feeds; no sub-hourly polling required. A manual
   refresh is available at any time via API.
10. **Product name — Partout.** Chosen for its fit with the fleet/remote story: the agent reaches
    everywhere, the server reaches everywhere. The repo is currently `hiersoir`; a rename to
    `partout` is a follow-up action (including the enrollment-token prefix `par_enr_…`).
11. **Host provisioning — fleet SSH, one-time, v1.** New hosts are provisioned by the server
    over the operator's *existing* fleet SSH credentials on the server box (Decision: no new
    credential store, no per-host keys in v1 — see §13). The server shells out to the system
    `ssh`/`scp` (honoring `~/.ssh/config`, `known_hosts`, and the operator's agent), copies the
    same-version binary, installs the systemd unit + env with a fresh one-time token, and starts
    the agent. The agent then generates its own keypair locally and completes the standard
    enrollment flow — provisioning never creates or transmits the agent identity, and never
    persists operator keys. Unknown host keys require explicit fingerprint confirmation in the
    wizard (no silent TOFU). Docker-host agents and air-gapped hosts use manual handoff in v1.
    SSH is used for provisioning only — never for commands, files, or observation — and
    provisioning is `admin`-only, policy-evaluable (`provision` action class), and audited
    per step (architecture §3.5, §12.4). Consequence for the security model: the server box
    (and its service user's access to the fleet keys) is a critical asset — see operations
    doc §1/§4.

### 15.2 Open questions

**None — all decisions recorded.**


