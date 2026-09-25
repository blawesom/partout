# Partout

**Remote host management control plane** — one Go binary to discover, execute against,
configure, patch, and orchestrate work across Linux hosts, with a web UI and an MCP server
for AI assistants.
| Doc | What it covers | Status |
|---|---|---|
| [PRD.md](PRD.md) | Product spec, positioning, capabilities, decisions | **v0.5** (observe layer + Web UI shipped) |
| [docs/architecture.md](docs/architecture.md) | Module layout, stream protocol, state machines, control plane, storage, testing | **Draft v0.5** (observe layer + Web UI) |
| [docs/deployment.md](docs/deployment.md) | Topology, install paths (systemd/Docker/compose/cloud-init/Helm), config reference, recipes | Draft v0.5 |
| [docs/operations.md](docs/operations.md) | Day-2 ops: backups, upgrades, incident runbooks, troubleshooting, compliance, go-live | Draft v0.5 |
| [docs/ui-guidelines.md](docs/ui-guidelines.md) | Web UI definition: mockup reconciliation, capability gating, IA/tokens/components, slice plan | v0.5 (S0 shell + M1–M5 data pages built) |

## Quick start

Five minutes to a working control plane with one managed host. Build once, then run a server
and an agent.

```bash
go build -o partout ./cmd/partout
```

> **Just want a one-process demo?** `./partout --mode=embedded` runs the server **and** a
> co-located local agent together — the fleet is populated the moment you open the UI:
> ```bash
> PARTOUT_MODE=embedded PARTOUT_ADMIN_PASSWORD='change-me-123' ./partout
> ```
> Open <http://localhost:8443>, sign in as `admin` / `change-me-123`. No enrollment token or
> second process needed.

**1. Start the server** (plaintext, on one terminal). `PARTOUT_ADMIN_PASSWORD` bootstraps the
first-run `admin` user for the **web UI**; `PARTOUT_TOKEN_ADMIN` gives the **CLI** a static
token so you don't have to log in twice. Both coexist.

```bash
PARTOUT_PORT=8443 PARTOUT_DB_PATH=./partout.db PARTOUT_MODE=server \
  PARTOUT_ADMIN_PASSWORD='change-me-123' \
  PARTOUT_TOKEN_ADMIN='cli-admin-token' \
  ./partout
```

Open **http://localhost:8443** and sign in as `admin` / `change-me-123`.

**2. Mint a one-time enrollment token** (second terminal):

```bash
PARTOUT_SERVER=localhost:8443 PARTOUT_CTL_TOKEN='cli-admin-token' \
  ./partout ctl enroll-token
# → token:  par_enr_…
```

**3. Run the agent** on the host you want to manage (third terminal; loopback here):

```bash
PARTOUT_SERVER=localhost:8443 PARTOUT_TOKEN='par_enr_…' ./partout --mode=agent
```

The host now appears in the **Fleet** page. Drive it two ways:

```bash
# CLI
PARTOUT_SERVER=localhost:8443 PARTOUT_CTL_TOKEN='cli-admin-token' \
  ./partout ctl run --selector all -- hostname
```
…or the **Execute** page in the UI (pick a selector → type a command → Run → watch output).

Observe facts (services, TLS certs, webservice configs) appear automatically on the **Observe**
pages after the first facts upload.

### Token env vars (don't mix these up)

| Where | Env var | Purpose |
|---|---|---|
| Server (static CLI/script tokens) | `PARTOUT_TOKEN_ADMIN` / `_OPERATOR` / `_VIEWER` | RBAC bearer tokens for the three roles |
| Server (web UI login) | `PARTOUT_ADMIN_PASSWORD` | bootstraps the first-run `admin` user the UI login form uses |
| CLI (`partout ctl`) | `PARTOUT_CTL_TOKEN` (or `--token`) | the bearer token the CLI sends |
| Agent (enroll) | `PARTOUT_TOKEN` (or `--token`) | the one-time enrollment token from `ctl enroll-token` |

> The web **UI login form only accepts username/password** (a local user). If you start the
> server with a static token but **no** `PARTOUT_ADMIN_PASSWORD`, the UI login form has no user
> to sign in as — set `PARTOUT_ADMIN_PASSWORD` for UI access, and/or a static token for the CLI.

### Demoing to a customer

Read this before showing Partout to someone else.

- **Turn on TLS: add `PARTOUT_TLS=on`.** The default is **plaintext HTTP bound to all
  interfaces** (`0.0.0.0`), so on a shared/office network the admin login, command output, and
  the SSE session token are on the wire in cleartext. `PARTOUT_TLS=on` bootstraps a local root
  CA and serves HTTPS with mTLS on the agent stream — no per-host cert work, no external CA.
  (The browser will warn once about the self-signed local CA; that's expected.) Alternatively
  bind to loopback and tunnel.
- **Start from a clean slate.** For a repeatable demo, use a throwaway dir:
  `rm -rf /tmp/demo && mkdir -p /tmp/demo && cd /tmp/demo`. A fresh DB re-enrolls the local
  agent automatically; a *stale* agent data dir against a *wiped* DB is also handled (it
  re-enrolls), but keeping both fresh is simplest.
- **Skip the Alerts page.** It is an honest **“M6 · not yet available”** placeholder. Fine to
  acknowledge, but lead with what works.
- **Suggested flow:** log in → **Fleet** (hosts + health cards) → **Execute** (pick a selector,
  run `hostname`, watch live per-host output) → **Audit** (the action is recorded) → the three
  **Observe** pages (Services, Certificates, Configs — real facts from the host). That walks the
  observe → act → verify loop end to end.
- **Don't open devtools during the demo.** Navigating straight to a gated/deep-linked route
  (e.g. a disabled subsystem) logs a handled 404/503 to the console. The UI degrades gracefully,
  but the red lines are distracting.

## Positioning

> **Partout** asks "how do I make it so, and prove it?" — and its purpose is to touch your
> hosts, safely and auditably.

It ships a single binary that embeds the observe layer (containers, endpoints, heartbeats,
systemd service health, webservice configs, TLS cert expiry + chain, resources, alerts)
and adds the write/control path: executions, files, sessions,
jobs, tasks, packages, secrets, policy, approvals, and a tamper-resilient audit log. Enrollment,
agent modes, gRPC transport, Ed25519 auth, SQLite/Postgres, SSE, UI stack, and MCP are all
first-class. No editions — everything is free and self-hosted.

## Documentation status

The three implementation docs are **drafts for review**. All choices the PRD doesn't lock
are marked **(proposed)** and are collected in
[architecture §15](docs/architecture.md#15-proposed-defaults-needing-sign-off) — sign those
off and the docs become the implementation contract.

## Implementation status

| Milestone | Status | Notes |
|---|---|---|
| **M0 — Spine** | ✅ Complete | Single Go binary, all 3 modes, enrollment, Ed25519 auth, gRPC stream, SQLite storage, SSE broker, restart resilience |
| **M1 — First write path** | ✅ Complete | Command execution + streamed output + audit + RBAC + `partout ctl` CLI + systemd deploy + **TLS/mTLS bootstrap** + **policy deny-list** + **host provisioning (fleet SSH)** + **offline spool**. (Postgres backend deferred to a later phase) |
| **M2 — Files & sessions** | ✅ Complete | File stat/list/download/upload/edit-CAS/perm with path safety + size caps + audit; PTY sessions (open/input/resize/close) with SSE output, optional recording + replay + 30-day retention; D1 file policy posture; D2 stream-drop interruption; CLI `files` + `sessions` subcommands. Web UI: files browser + sessions list/replay built; live PTY (xterm.js) terminal deferred to a later V1 phase |
| **M3 — Automation** | ✅ Features, ⚠ 2 gaps | Secrets ✅, external data ✅, packages ✅, tasks/playbooks ✅, scheduled jobs ✅ (cron, agent-side execution, overlap/retry policy, per-host resolved schedules). **Known gaps:** (a) ~~scheduled job steps run without a policy decision or agent guardrail~~ ✅ **fixed** — job create/update/RunNow now gated under `task.run`, per-host signed `Decision` in `JOB_ASSIGN`, agent re-checks guardrail before every fire (fail-closed); (b) **reboot continuation** (PRD §5.5 acceptance criterion) unimplemented; (c) job dispatch path (`JOB_ASSIGN` → agent) has no live E2E test |
| **M4 — Governance** | 🚧 In progress | **Local user auth ✅** (login/logout, session tokens, admin user management, first-run bootstrap) + **SSE stream auth-gated ✅**; remaining: approvals engine, full policy surface, MCP server (R11) + write tools |
| **M5 — Observe: fact collectors** | ✅ Complete | R18–R20: agent collectors for service/config/cert facts; server merge-on-write into `host_facts` JSON; read-only API (`GET /services`, `/certificates`, `/configs`). Web UI pages render real data. MCP read tools ship with the R11 server (REST endpoints are their backing surface). |
| **M7 — Observe: Web UI pages** | ✅ Built (v0.5) | S0 shell + data pages for M1–M5 (Fleet, Execute, Audit, Sessions, Files, Jobs, Tasks, Updates, Secrets, Policies, Provision, Users, Services, Certificates, Configs). Remaining: cert→config→service cross-links, config drift, task actions, live PTY; Alerts page is a labeled M6 placeholder. |

### M0 — Spine (complete)

- ✅ `cmd/partout` — single binary, modes: `--mode=server|agent|embedded`
- ✅ `internal/config` — env-based configuration
- ✅ `internal/identity` — agent identity (Ed25519 + X25519 key material)
- ✅ `internal/cryptoutil` — Ed25519, X25519, HKDF, AES-256-GCM
- ✅ `internal/hsauth` — shared challenge-response builder
- ✅ `internal/selector` — AND-only selector grammar (`all`, `host:`, `tag:`, `role:`, `group:`)
- ✅ `internal/store` — SQLite (WAL), schema v1: agents, tokens, facts, tags/roles/groups, executions, runs, output, audit
- ✅ `internal/sse` — SSE broker
- ✅ `internal/server/stream` — gRPC handler: handshake, envelope loop, session registry, `SendCommand`, `SendCancel`
- ✅ `internal/agent/stream` — gRPC stream client: connect, handshake, send/recv
- ✅ `internal/agent/exec` — command runner: 64KiB output chunks, timeout, cancel, exit code
- ✅ `internal/agent/facts` — host fact collection (hostname, OS, arch, CPU, memory, uptime, IP)
- ✅ `internal/agent/enroll.go` — REST enrollment client
- ✅ `internal/agent/agent.go` — run loop: backoff, heartbeat, facts, command exec, policy, revoke, cancel
- ✅ `internal/api` — REST v1: 26 API routes (25 JSON + SSE), RBAC (viewer/operator/admin), structured errors, cursor pagination, `/healthz` + `/readyz`
- ✅ `internal/control` — dispatch orchestration, cancel, finalize, audit
- ✅ `internal/id` — opaque TEXT keys (`prefix_` + 12 hex)
- ✅ 124 tests, race detector clean (+3 opt-in live-sshd tests under `-tags live`)

### M1 — First write path (complete)

Done:
- ✅ Ad-hoc command execution with streamed output (stdout/stderr)
- ✅ Command cancellation (server → agent CANCEL envelope, live process kill)
- ✅ Full audit log (append-only, filterable, REST-exportable)
- ✅ RBAC bearer tokens (`PARTOUT_TOKEN_ADMIN`/`OPERATOR`/`VIEWER`), single-user local mode
- ✅ Run lifecycle: `queued → delivered → running → terminal` (succeeded/failed/timed_out/cancelled/interrupted/denied)
- ✅ Execution aggregate: `succeeded/failed/partial/cancelled`
- ✅ Operator CLI: `partout ctl` (enroll-token, hosts, run, exec, audit, **policy**, ca; `--ca-file` for HTTPS)
- ✅ Deploy artifacts: `deploy/systemd/` (server + agent units, env templates, install README)
- ✅ Server restart resilience: agents marked `disconnected` at startup, flip back on reconnect
- ✅ Agent restart resilience: identity persisted, no re-enrollment needed
- ✅ **TLS/mTLS bootstrap** (see below): local root CA on first run, CA-signed agent leaves via CSR at enrollment, mTLS on the gRPC stream, REST over HTTPS
- ✅ **Policy deny-list engine**: rule CRUD (REST `/api/v1/policies` + `partout ctl policy`), per-host dispatch gating (`deny` / `require_approval→deny` / allow), signed `Decision` on every command envelope, agent-side re-check (`internal/agent/guardrail`) — verifies signature, bundle version, re-evaluates rules over local action (any mismatch → deny). Empty rule set = default-allow (deny-list model). Requires no new flags/env vars.
- ✅ **Host provisioning via fleet SSH** (architecture §3.5, §5.8): `partout ctl provision new --host user@host` drives a server-side 5-step state machine — `connect` (ssh-keyscan fingerprint + no-silent-TOFU gate: a new host key pauses the run at `key_confirm` until an admin confirms it) → `preflight` (OS/arch/init/sudo/disk) → `transfer` (scp the server binary) → `install` (base64-piped sudo bash: place binary, create `partout` user, write `agent.env` + systemd unit) → `wait-enroll` (agent self-enrolls with a one-time token). Uses only system `ssh`/`scp`/`ssh-keyscan`/`ssh-keygen` with hardened flags (`BatchMode`, `ConnectTimeout`, `StrictHostKeyChecking=yes`); no credentials are created, copied, or persisted (the operator's existing `~/.ssh` is the bootstrap channel). Non-systemd hosts hand off cleanly (terminal `handoff`, not an error). REST: `POST/GET /api/v1/provision-runs[/{id}]`, `POST .../key` (confirm|deny), `POST .../cancel`; SSE emits `provision.*` events. Tested with fake ssh binaries (unit + REST integration) **and** an opt-in live suite against real OpenSSH (`PARTOUT_LIVE_SSH=1 go test -tags live ./internal/sshutil/`) — the fakes encode ssh's intended semantics, so the live suite is what catches real-world divergence. Real-host (multi-machine) E2E through a fleet is still deferred. Policy action-class gating for provisioning lands with M4 (admin-only for now).
- ✅ **Offline spool** (architecture §3.1.4, §3.4): when the stream to the server drops, in-flight commands **keep running** on the host; their output and result are buffered locally in a bounded per-run spool (16 MB mem → 128 MB disk → 24 h TTL → drop-oldest) and **replayed on reconnect** before new down traffic. The server marks in-flight runs `interrupted` on disconnect, then re-finalizes them when the replayed result arrives. Output chunks are appended idempotently keyed by `(run_id, chunk_seq)` and run-state updates are guarded, so replay is at-least-once and duplicate-safe. Spooled records are fsync'd per-run files under `<data dir>/spool/` and survive an agent restart (orphaned runs replay their partial output; the server shows the run as `interrupted`). Heartbeats report `spool_mem_bytes` / `spool_disk_bytes`. If the spool directory cannot be opened the agent **fails fast at startup** rather than running without offline buffering.
- ✅ **Embedded mode**: `--mode=embedded` runs the server + a co-located local agent in one process. The agent enrolls over loopback with a locally created one-time token (first boot only), reconnects with its persisted identity on restart, and works over plaintext or TLS (mTLS).

Remaining:
- [ ] Postgres backend (second store implementation) — deferred to a later phase (after M2)
- [ ] TLS cert rotation via the stream (v1.x) + optional revocation list
- [ ] Dispatch to offline agents (server-side down-queue with TTL) — follow-up

### M2 — Files & sessions (complete)

Done (decisions D1–D5 per PRD review):
- ✅ **File operations** (PRD §5.3, arch A6): `stat`, `list`, `download` (chunked, resumable offset), `upload` (atomic temp + rename, chunked 256 KiB), `edit` (compare-and-swap on sha256), `perm` (mode/owner/group). Synchronous request/response over the agent stream (`FILE_OP` down / `FILE_OP_RESULT` up), REST at `/api/v1/files/*`.
- ✅ **Path safety (D4)**: absolute paths only; any symlink component in the path is rejected (no traversal across the transfer boundary); intermediate components must be real directories. Enforced agent-side in `internal/agent/fs`.
- ✅ **Size caps (D3)**: 256 MiB max transfer, 256 KiB chunk, 1 MiB edit cap, 2048 list-entry cap (env-configurable).
- ✅ **File policy posture (D1)**: reads (stat/list/download) bypass policy; writes (upload/edit/perm) require server-side policy evaluation over the `file.write`/`file.perm` action classes, attach a signed `Decision`, and the agent guardrail re-checks before executing. Deny → 403 + audit row.
- ✅ **Auditability**: every file op records a `files_actions` row (op, path, actor, state, size, sha256) + append-only `audit_events` entry + `file.action` SSE event.
- ✅ **PTY sessions** (PRD §5.2.2, arch §6.1): `open`/`input`/`resize`/`close` over the stream (`SESSION_*` envelopes), real PTY via `creack/pty`, 64 KiB chunks, SIGHUP-then-SIGKILL graceful close (1 s). REST at `/api/v1/sessions*`; live output via SSE (`session.data`, `session.result`, `session.opened`, `session.interrupted`).
- ✅ **Session policy**: a session open is an `exec` action (command regex applies to `cmd args`); a deny records the session `denied` and blocks the agent.
- ✅ **Recording + replay (PRD §9)**: optional per-session PTY capture to `session_records` (monotonic seq), `GET /api/v1/sessions/{id}/replay`, 30-day retention sweeper (daily, `PARTOUT_SESSION_RETENTION_DAYS`).
- ✅ **Stream-drop semantics (D2)**: on agent disconnect the server interrupts all open sessions (`interrupted`); the agent kills all PTYs on stream end. PTY traffic is never spooled (sessions are live-only).
- ✅ **CLI**: `partout ctl files stat|list|upload|edit|perm` and `partout ctl sessions open|close|list|replay`.
- ✅ E2E tests: files over a live bufconn stream (stat/list/download/upload/edit-CAS/conflict/perm/symlink-rejection/policy-deny/audit) and sessions (open→data→close→result, recording+replay, policy deny, disconnect interruption).

### M3 — Automation (features complete; known gaps documented in the status table)

Done so far:
- ✅ **Secrets** (PRD §5.7, arch §5.5): server-side encrypted store — master key from `PARTOUT_SECRET_KEY_FILE` (0600) or `PARTOUT_SECRET_KEY`, per-secret keys = HKDF(master, secret_id), values AES-256-GCM at rest, versioned. **No master key → feature disabled with a clear message** (503 on the endpoints).
- ✅ **Rotation**: new version revokes all prior versions; audit records which version each materialization used (`secret_bindings`). Revoke and delete included.
- ✅ **E2E distribution**: `SecretMaterialize{ref, version, eph_pub, sealed, cache_ttl_s}` down envelope. Server decrypts at-rest, seals with an **ephemeral X25519** ECDH key to the agent's enrolled transport key (HKDF → AES-256-GCM). Cleartext held in server memory for one materialization only; the sealed form is bound to that agent (a different agent cannot open it — tested).
- ✅ **Agent cache** (`internal/agent/secrets`): in-memory for the declaring run's lifetime; with `offline_ttl_s > 0` persists the **sealed form only** (0600 JSON, never plaintext — asserted by test) so a restart within the window still serves the value offline. Fail-closed otherwise ("secret unavailable").
- ✅ **Read APIs never return values**: `GET /api/v1/secrets` and `/secrets/:name` return metadata (name, selector, version, agent count) only. Values are write-only via create/rotate.
- ✅ **Audit**: `secret.created/rotated/revoked/materialized/updated/deleted` with master-key digest (never the key), version, agent, run ref.
- ✅ **REST** (`/api/v1/secrets*`; reads = operator+, writes = admin) and **CLI** (`partout ctl secrets list|create|rotate|revoke|delete`, `-value` or `-value-file`).
- ✅ **External data refresh** (PRD §6.3, arch §8): EOL dates from **endoflife.date** for 10 distros, fetched at startup + daily (24 h), **all-or-nothing** (a failed feed keeps the previous cache, sets `last_error`, one log line). `GET /api/v1/hosts/:id/eol` computes per-host `supported / ending_soon / ended` from os-release facts — the agent now ships `host.distro` / `host.distro_version` / `host.distro_codename` / `host.distro_name` parsed from `/etc/os-release`. Vulnerability correlation goes through **OSV.dev** `querybatch` at `list-updates` time (not at refresh): 1 h TTL in `vuln_cache`, clean packages tombstone-cached (`vuln_id="-"`), air-gapped sites serve the stale cache. `PARTOUT_DISABLE_EXTERNAL_DATA_REFRESH` disables all fetching.
- ✅ **REST** (`GET /external-data/status` viewer, `POST /external-data/refresh` admin, `GET /hosts/:id/eol` viewer) and **CLI** (`ctl external-data status|refresh|host-eol`).
- ✅ Tests: store (CRUD/rotate/revoke/cascade), agent cache (roundtrip, no-plaintext-on-disk, expiry, cross-agent rejection), E2E over a live bufconn stream (materialize→agent decrypt, rotation invalidation, selector binding, offline reopen).
- ✅ **Package management** (PRD §5.6, arch §5.6): `list-updates` and `apply-updates` dispatch to the agent, which runs the native backend (apt/dnf, selected by os-release distro). **Dry-run is always run first** before apply; a before/after `dpkg-query`/`rpm -qa` journal is stored per action in `package_actions` (schema v7). Results ranked by CVE severity via the vuln cache (PRD §6.3). `pkg.apply` action class is policy-gated with a signed Decision (agent guardrail re-check). E2E-tested on a live Ubuntu host (real `apt-get -s upgrade` + phasing-deferred summary captured).
- ✅ **REST** (`GET /packages/updates` viewer, `GET /packages/actions` viewer, `GET /packages/actions/:id` viewer, `POST /packages/apply` operator) and **CLI** (`ctl packages updates <agent> | apply <agent> [--dry-run] [--packages ...] | actions`).
- ✅ **Tasks / Playbooks** (PRD §5.5, arch §4.5, §8.5): **versioned tasks** with 9 step kinds (`command`, `file`, `package`, `service`, `user`, `group`, `template`, `assert`, `reboot`), constrained **`when` guard** grammar (dotted fact refs, `==`/`!=`/`in [list]`, `and`/`or`, `!`, `file.exists(path)`), **task runs** recorded in `task_runs`/`task_run_steps` tables with per-step state (ok/changed/failed/skipped), **playbooks** bind a task + version + selector to hosts. Agent-side runner executes steps in order, stops on `failed`, reports aggregate state. Guardrail re-checks every run over the `task.run` action class. Server dispatches over the stream, waits for result, records audit events. CLI: `ctl tasks list|create|show|run|runs|run-show`, `ctl playbooks list|create`.
- ✅ **Scheduled jobs** (PRD §5.4, arch §5.4.1): jobs = (selector, cron schedule, task). Server resolves the selector to concrete hosts at save/update time and pushes a per-host schedule (`JOB_ASSIGN` down). The agent runs each job on its own clock (robfig/cron), so a server outage does not stop scheduled work. Overlap policy (allow/skip/replace), failure policy (no_retry/retry with backoff). Job runs produce a `JobRunResult` (up) that the server records in `job_runs` (lineage) + audit. Assignments persist to disk (agent restart resumes schedules). **Policy-gated (security fix)**: create/update/`RunNow` evaluate the job's steps under the `task.run` action class per host BEFORE persisting (denied → `403 policy_denied`, nothing written); each `JOB_ASSIGN` carries a server-signed `Decision` (run_id = job id, bound to the policy bundle version); the agent re-checks it via the guardrail before **every** cron fire and fails closed (missing/stale/unsigned decision → run reported `denied`, no retry). **Selector edits reconcile assignments**: hosts that fall out of a narrowed selector are unassigned (`JOB_UNASSIGN`) so they stop firing with a stale decision. REST: `GET/POST /api/v1/jobs`, `PUT/DELETE /api/v1/jobs/:id`, `GET /api/v1/jobs/:id/runs`, `POST /api/v1/jobs/:id/run`, `GET /api/v1/jobs/runs`. CLI: `ctl jobs list|create|show|delete|run|runs|list-runs`.

### M5 — Observe: fact collectors (complete)

Done (R18–R20, the read side of the observe→act→verify loop):
- ✅ **Agent collectors** (`internal/agent/factscollect`): **services** (systemd unit state from `ActiveState`, enabled, wants/after deps, restart policy, memory, last exit status — custom + operator-labelled units only), **webservice configs** (HAProxy + Nginx native validation + line/brace-depth topology parse; read-only), **TLS certs** (expiry/`days_remaining`, subject/issuer/serial, SAN, key type, chain check, in-process `crypto/x509` self-signed detection; bounded path scan, deduped).
- ✅ **Transport**: new gRPC `OBSERVE_FACTS` envelope (kind 27) carrying a per-kind JSON blob; facts never spooled (collection runs off the loop goroutine, re-entrancy-guarded).
- ✅ **Server ingest**: `internal/server/observe/facts.go` `ParseDocument` (null=absent, flat scalars + typed accessors) merges into a **single `host_facts` JSON document per host** — merge-on-write so concurrent fact streams never clobber each other. Keyed strictly by the authenticated agent id (client-supplied `host_id` ignored for storage).
- ✅ **Read APIs** (viewer): `GET /api/v1/services?label&state&name&agent_id`, `GET /api/v1/certificates?agent_id&days_remaining_lt`, `GET /api/v1/configs?agent_id&kind`. Host-capped, unknown-expiry certs excluded from the days filter.
- ✅ **Web UI pages** (M7, v0.5): Services / Certificates / Configs render real data with label/state/expiry filters.
- ✅ **Tests**: parser unit tests incl. real generated certs (chained / broken-chain / multi-cert), the nginx vhost parser, `ActiveState` mapping; server `host_facts` merge + same-second collision probe; API shape tests.
- Remaining: **M6 alert engine** (makes this actionable), **MCP read tools** (ship with the R11 server; these REST endpoints are their backing surface), config **drift detection** (R22) + **cross-fact correlation** (R21) rendering.

### Not started

- Live PTY terminal in the web UI (xterm.js) — backend input/resize exist; the interactive terminal frontend is deferred
- M3 known gaps (from the verification audit, tracked in Next steps): job dispatch E2E, reboot continuation
- M4: approvals engine, full policy surface, MCP server (R11) + write tools
- M6: alert engine; M7 remaining: cross-links, drift, task actions; M8: installers, cloud-init, Helm, status page
- MCP read tools (ship with the R11 MCP server; the M5 REST endpoints are their backing surface)

## Next steps

1. ~~Review docs; sign off the proposed defaults (architecture §15).~~ ✅ Done
2. ~~Resolve the repo rename `hiersoir` → `partout` (PRD Decision 10).~~ ✅ Done
3. ~~Scaffold the Go module + `deploy/` artifacts per architecture §1.~~ ✅ Done
4. ~~Build milestone M0 (spine).~~ ✅ Done
5. ~~**Finish M1**: policy deny-list~~ ✅ Done (v0.2.0)
6. ~~**Finish M1**: host provisioning (fleet SSH)~~ ✅ Done (see M1 Done list)
7. ~~**Finish M1**: offline spool~~ ✅ Done (see M1 Done list)
8. ~~**Review PRD R5** (spool storage)~~ ✅ Done — PRD updated to the per-run `.sp` log design (R5 table + §6.2)
9. ~~**M2**: files & sessions~~ ✅ Done — see M2 Done list
10. **Finish M1**: Postgres backend — deferred to a later phase (after M2)
11. ~~**M3**: secrets, external data, packages, tasks/playbooks, scheduled jobs~~ ✅ Done — features complete, CI green; two known gaps tracked below
12. ~~**Web UI**~~ ✅ Done (v0.5) — buildless Vue 3 SPA in `internal/api/webui/`, served same-origin via `go:embed`; S0 shell + data pages for M1–M5; capability-gated; UI↔API shape tests + `scripts/ui-smoke.sh` headless render check. Remaining: live PTY (xterm.js), cert→config→service cross-links, config drift, task actions, Active Alerts (M6). See ui-guidelines §13–18.

### Next (priority order, from the M3 verification audit)

13. ~~**Enforce policy on scheduled job steps** (security, M3/§5.4+§5.5)~~ ✅ Done — job create/update/RunNow gated under `task.run`; per-host signed `Decision` in `JOB_ASSIGN`; agent guardrail re-check before every fire (fail-closed). **Upgrade note:** after upgrading, re-save each job (or delete + recreate) so the server re-issues signed decisions; until then, fires fail closed with state `denied`.
14. **E2E test the job dispatch path** — `JOB_ASSIGN` → connected agent → cron fire →
    `JOB_RUN_RESULT` → `job_runs` row. Current tests stop at store/selector level and use a
    nil stream handler, so the real wire path is unverified.
15. **Reboot continuation** (PRD §5.5 acceptance criterion) — the `reboot` step kind is a
    stub (returns "reboot requested"); no `resume-after-reboot` marker exists. Implement or
    explicitly defer in the PRD.
16. **M4 — Governance** (local user auth ✅ done — see below): approvals engine (`require_approval` currently fails closed with
    "not yet available — M4"), full policy surface, MCP server (R11) + write tools.
17. ~~**Observe layer (§6)**~~ ✅ Done (M5) — fact collectors + `host_facts` merge + read APIs + Web UI pages. Remaining: M6 alert engine, MCP read tools (with the R11 server).
18. Postgres backend; then **M8 — Distribution & polish** (installers, cloud-init, Helm, status page).

## TLS / transport security (implemented)

Partout v1 ships a **local root-CA bootstrap** with **mutual TLS on the agent stream**,
zero per-host certificate management. Plaintext (`h2c`) remains the default for local dev.

### How it works

1. **First server run with `--tls on`** generates a local **root CA** (10y, ECDSA P-256)
   and the **server leaf** (2y, SANs from `--tls-names`, default
   `localhost,127.0.0.1,<hostname>`), persisted under `<db dir>/tls/`
   (`ca.key` 0600). See `internal/certutil`.
2. **Operator** fetches the CA (e.g. `partout ctl ca` or `scp` of `ca.crt`) and ships it to
   each managed host.
3. **Agent first run** (with `--ca-file` / `PARTOUT_TLS_CA`): generates a **local ECDSA
   P-256 keypair**, ships a **CSR** in the enroll request over HTTPS, and receives back the
   **CA + a signed leaf** (CN = agent id, EKU clientAuth). The private key **never leaves
   the host**; it's persisted under `<data dir>/tls/` (key 0600).
4. **mTLS stream**: the gRPC agent stream connects over TLS with the client cert.
   The server verifies client certs (`VerifyClientCertIfGiven`) and **enforces** a valid
   client cert for gRPC requests (403 without one) while REST/SSE remain open to bearer-auth
   clients. The **Ed25519 handshake still gates the stream** on top, so revocation is
   instant (no cert revocation list needed for v1).

### Endpoints / flags

| Item | Detail |
|---|---|
| Server `--tls on` / `PARTOUT_TLS=on` | enable TLS + local CA bootstrap |
| Server `--tls-names` / `PARTOUT_TLS_SERVER_NAMES` | comma-separated SANs for the server leaf |
| `GET /api/v1/tls/ca` (admin) | returns `{"cert": "<PEM CA>"}` |
| `POST /api/v1/agents/enroll` | accepts `csr` (required in TLS mode); returns `tls.{ca_cert,leaf_cert}` |
| Agent `--ca-file` / `PARTOUT_TLS_CA` | the server root CA; enables HTTPS enroll + mTLS stream |
| `partout ctl --ca-file` | talks to the server over HTTPS with the given CA |
| `partout ctl ca` | fetch the server root CA |

### Security notes

- Single port still serves **both** gRPC and REST — the demux is
  `content-type: application/grpc`-driven, so it stays correct over TLS (both can be h2).
- **mTLS is enforced only for the gRPC path** (the agent stream); REST/SSE rely on bearer
  tokens. A plaintext client is rejected outright on a TLS port.
- The CA is the only trust anchor; agent leaves are CA-signed, so there is **no per-host
  cert distribution** beyond the enroll response. **Rotation** (stream-delivered new
  leaves) and a **revocation list** are v1.x follow-ups — the Ed25519 gate already gives
  instant server-side revocation in the interim.

See `deploy/systemd/` for the systemd units and env templates.

### Not yet covered (v1.x)

- Certificate rotation via the stream (`TLS_CSR`/`TLS_CERT` envelopes).
- Long-lived CA management / renewal reminders.
- Optional `PARTOUT_TLS_INSECURE` (skip-verify) escape hatch for dev — intentionally **not**
  shipped; use a local CA instead.

## Policy deny-list (implemented, v0.2.0)

Declarative deny rules gate every dispatch. v1 is a **deny-list**: the default is *allow*
(a rule set with no match is allowed); a matching `deny` (or `require_approval`, which acts
as deny until the M4 approvals engine) blocks the command **server-side, before any envelope
reaches the agent**.

```bash
# Block any command containing 'secret' on all hosts
partout ctl --server localhost:8443 --token $ADMIN \
  policy create --name no-secret --effect deny --command-regex 'secret'

# Scope to hosts by tag/role and by requester role
partout ctl --server localhost:8443 --token $ADMIN \
  policy create --name no-prod-restart --effect deny \
    --hosts 'tag:env=prod' --actor-roles operator --command-regex 'systemctl (restart|stop)'

partout ctl policy list
partout ctl policy delete pol_<id>
```

**Match fields** (all optional; empty = match any):
`hosts` (selector: `all`, `host:`, `tag:`, `role:`, `group:`), `actions` (`exec` in v1),
`actor_roles` (requester RBAC role), `command_regex` (against `"cmd args…"`).

**How it's enforced (architecture §5.2–5.3):**

1. **Dispatch gate** — `internal/control` evaluates the rule set per host per action.
   Deny → run recorded `denied`, audit `policy.deny`, no envelope sent. An execution whose
   runs are *all* denied finalizes `failed` immediately.
2. **Signed decision** — every `Command` envelope carries a `Decision` signed with the
   server's Ed25519 key (`server_identity.key`, auto-generated under `<db dir>/identity/`;
   public key distributed in every policy bundle).
3. **Agent re-check** — `internal/agent/guardrail` verifies the decision signature, that the
   `bundle_version` matches its cached bundle, and re-evaluates the rules over the local
   action (the bundle carries the agent's own tags/roles/id; the decision carries the actor
   role). Any mismatch → **deny** with `ACK_DENIED_AGENT` + reason. Fails closed until the
   first bundle; persists across agent restarts.
4. **Bundle delivery** — the server pushes a versioned, content-hashed bundle to each agent
   **on connect and on every policy change** (create/delete broadcasts to all connected).

**Audit:** `policy.create`, `policy.delete`, `policy.deny` (with matched rule id(s)).
**RBAC:** list = viewer; create/delete = admin.
**Deviations from the proposed design** (tracked in architecture §15): default-allow in v1
(default-deny writes deferred to M2/M3 with the action-class taxonomy); `require_approval`
evaluates as deny until M4; `requires_elevation` match field not wired (elevation is
`none` in v1).

## Local user auth (implemented, M4)

Local username/password identity (PRD Decision 6) — no OIDC (post-v1). Replaces the
"paste a static env token" model for the web UI while **keeping static env tokens working**
(side-by-side; useful for the CLI and scripts).

- **First-run bootstrap**: with no users, the server creates an `admin` user. The password
  comes from `PARTOUT_ADMIN_PASSWORD` (or the `--admin-password` flag — note a password on
  the command line is visible in `ps`, so the env var is preferred); otherwise a random
  password is
  generated, written to `<db dir>/admin_password.txt` (0600), and the operator is logged a
  pointer to rotate it after first login.
- **Passwords**: argon2id (OWASP params) + a fresh 16-byte pepper per password; stored as a
  PHC string in the `principals` table. Verification is constant-time.
- **Sessions**: `POST /api/v1/auth/login` returns a random 256-bit bearer token valid for
  12 h (in-memory; a server restart logs everyone out). `GET /auth/me`,
  `POST /auth/logout`, `POST /auth/password` (change own, re-issues a token).
- **User management** (admin): `GET/POST /api/v1/users`, `PATCH/DELETE /api/v1/users/{name}`
  (change role / disable / reset password / delete).
- **Guards**: last-active-admin cannot be deleted/disabled/demoted; no self-delete or
  self-modify; password change / reset / disable / role change invalidate that user's
  sessions. Login failures and user ops are audited (`auth.*`, `user.*`); login returns a
  generic 401 (no user enumeration) and unknown usernames pay a decoy argon2 verification
  so response *timing* does not disclose them either.
- **Login throttling**: consecutive failures per username (unknown usernames included)
  back off exponentially (5 failures, then 2 s doubling to a 5 min cap) and return 429
  `throttled`; a successful login clears the counter. Throttle state is in-memory and
  bounded.
- **Session hygiene**: expired sessions are pruned on access and by a background sweeper
  (15 min); at most 8 live sessions per user are kept (oldest evicted), so neither repeated
  logins nor abandoned browsers grow memory without bound.
- **RBAC**: session tokens and static env tokens both authorize. Once any user exists the
  single-user local-mode exemption is lifted — unauthenticated requests get 401 (public
  routes like `/healthz` and `/api/v1/auth/login` stay open). In single-user local mode
  (no users, no tokens) requests are treated as **role `admin`** for RBAC *and* for policy
  `actor_roles` matching (it used to present as the non-role label `local` — a rule set that
  matched `actor_roles: ["local"]` must be updated to `["admin"]`).
- **CLI**: `partout ctl auth login --username U --password P` stores the session token at
  `~/.config/partout/token`; `ctl` auto-uses it when no `--token`/`PARTOUT_CTL_TOKEN` is set.

## Host provisioning (implemented, v0.3)

Boot a new agent over the operator's **existing fleet SSH** — no credentials are created,
copied, or persisted; the operator's key material is the bootstrap channel (PRD R17,
Decision 11). Driven by a server-side 5-step run:

```bash
partout ctl --server srv:8443 --token $ADMIN provision new --host deploy@web01
partout ctl provision get prv_ab12cd34ef56      # watch state + per-step output
partout ctl provision key prv_ab12cd34ef56 confirm   # if the host key is new
partout ctl provision cancel prv_ab12cd34ef56
```

| Step | What happens |
|---|---|
| `connect` | `ssh-keyscan` captures the host key; **new keys pause the run** at `key_confirm` until an admin confirms the fingerprint (no silent TOFU) |
| `preflight` | read-only: OS/arch/init/`sudo -n`/disk + **host→server reachability** (`/healthz`), so a firewall fails fast |
| `transfer` | `scp` the server binary to `/tmp/partout-<sha12>` |
| `install` | one `sudo -n bash -s` script: verify sha256, install the binary, create the `partout` user, write `/etc/partout/agent.env` + the systemd unit, `systemctl enable --now` |
| `wait-enroll` | the agent self-enrolls with a short-TTL one-time token and flips to `connected` |

States: `queued → connecting → key_confirm → confirming → preflight → transferring →
installing → enrolling → connected`; terminals `failed` / `cancelled` / `handoff`
(`handoff` = non-systemd host, with the manual recipe — not an error).

**What the server runs:** only the system `ssh`/`scp`/`ssh-keyscan`/`ssh-keygen`, with
`BatchMode=yes`, `ConnectTimeout=10s`, `ServerAliveInterval=15`, `StrictHostKeyChecking=yes`.
`PARTOUT_SSH_DIR` (default `$HOME/.ssh`) is passed **explicitly** (`-F`, `UserKnownHostsFile`,
`IdentityFile`) because OpenSSH resolves `~/.ssh` from the passwd database and ignores
`$HOME`; a non-default dir replaces the per-user `ssh_config`.

**REST:** `POST/GET /api/v1/provision-runs[/{id}]`, `POST .../key` (confirm|deny),
`POST .../cancel`; SSE emits `provision.*`. **RBAC:** admin (viewer may read).
`confirm` is idempotent-safe (duplicate/racing → **409**); unknown run → **404**.

**Tested:** fake-fleet unit tests (fingerprint gate, non-systemd handoff, unreachable-server
preflight, duplicate/racing confirm, restart-while-paused) + a REST integration test, plus an
**opt-in live suite against real OpenSSH** (`PARTOUT_LIVE_SSH=1 go test -tags live
./internal/sshutil/`) — the fakes encode ssh's *intended* semantics, so the live suite is what
catches real-world divergence.

**Deferred:** destructive `--mode fresh` wipe and the version-diff update check (the install
is an idempotent in-place update for now); policy action-class gating (admin-only until M4);
multi-machine fleet E2E.
