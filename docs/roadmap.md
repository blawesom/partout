# Partout — Roadmap & implementation status

> The milestone **plan and steps**: what is built, what each milestone shipped, and what is
> next. This is the working plan of record — keep it current as milestones land.
>
> Design rationale lives in [architecture.md](architecture.md); day-2 operations in
> [operations.md](operations.md); deployment topologies in [deployment.md](deployment.md).
> The [README](../README.md) is a short overview (objectives, problem, architecture, deploy,
> UI, CLI).

---

## Implementation status

| Milestone | Status | Notes |
|---|---|---|
| **M0 — Spine** | ✅ Complete | Single Go binary, all 3 modes, enrollment, Ed25519 auth, gRPC stream, SQLite storage, SSE broker, restart resilience |
| **M1 — First write path** | ✅ Complete | Command execution + streamed output + audit + RBAC + `partout ctl` CLI + systemd deploy + **TLS/mTLS bootstrap** + **policy deny-list** + **host provisioning (fleet SSH)** + **offline spool**. (Postgres backend deferred to a later phase) |
| **M2 — Files & sessions** | ✅ Complete | File stat/list/download/upload/edit-CAS/perm with path safety + size caps + audit; PTY sessions (open/input/resize/close) with SSE output, optional recording + replay + 30-day retention; D1 file policy posture; D2 stream-drop interruption; CLI `files` + `sessions` subcommands. Web UI: files browser + sessions list/replay built; live PTY (xterm.js) terminal deferred to a later V1 phase |
| **M3 — Automation** | ✅ Complete | Secrets ✅, external data ✅, packages ✅, tasks/playbooks ✅, scheduled jobs ✅ (cron, agent-side execution, overlap/retry policy, per-host resolved schedules). Former gaps all closed: (a) ~~scheduled job steps without policy~~ ✅ gated under `task.run` with per-host signed `Decision` + agent guardrail re-check (fail-closed); (b) **reboot continuation** ✅ — `reboot` step persists a resume marker, reboots, and resumes after boot (PRD §5.5); (c) job dispatch E2E ✅ — live bufconn test drives `JOB_ASSIGN` → real agent scheduler → `JOB_RUN_RESULT` → `job_runs` row |
| **M4 — Governance** | ✅ **Done** | **Local user auth ✅** + **SSE stream auth-gated ✅** + **approvals engine ✅** on every policy-gated surface (exec, pkg.apply, files, sessions, tasks, jobs) + **MCP server ✅** (R11: stdio + Streamable HTTP + **OAuth2 (PKCE)**, 25 read/write tools) |
| **M5 — Observe: fact collectors** | ✅ Complete | R18–R20: agent collectors for service/config/cert facts; server merge-on-write into `host_facts` JSON; read-only API (`GET /services`, `/certificates`, `/configs`). Web UI pages render real data. MCP read tools ship with the R11 server (REST endpoints are their backing surface). |
| **M6 — Observe: alert engine** | ✅ **Done** | **Alert engine ✅** (R23/R25): threshold rules over service/cert/config facts — `service_failed`, **`service_restarting` (M6.1)**, `cert_expiring`, `config_invalid`, **`config_drift` (R22)**; `alerts` + `alert_rules` store; dedup per (rule, host, subject); firing/resolved transitions; SSE `alert.firing`/`alert.resolved`; `GET /alerts` + rules CRUD; `partout ctl alerts`; MCP `list_alerts`; live Alerts page. |
| **M7 — Observe: Web UI pages** | ✅ **Done** | S0 shell + data pages for M1–M6 (Fleet, Execute, Audit, Sessions, Files, Jobs, Tasks, Updates, Secrets, Policies, **Approvals (M4)**, **Alerts (M6 live list)**, Provision, Users, Services, Certificates, Configs). Now complete: **alert rule-management UI**, **cert→config→service cross-links**, **config drift (R22)**, **task actions** (run task/playbook + run inspection), **live PTY terminal (xterm.js)**, and **write actions** (jobs CRUD + run history, package apply/dry-run + history, provision start/key-confirm/cancel + live steps). |

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
- ✅ 378 test functions across 37 packages, race detector clean (+3 opt-in live-sshd tests under `-tags live`)

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
- ✅ **Host provisioning via fleet SSH** (architecture §3.5, §5.8): `partout ctl provision new --host user@host` drives a server-side 5-step state machine — `connect` (ssh-keyscan fingerprint + no-silent-TOFU gate: a new host key pauses the run at `key_confirm` until an admin confirms it) → `preflight` (OS/arch/init/sudo/disk) → `transfer` (scp the server binary) → `install` (base64-piped sudo bash: place binary, create `partout` user, write `agent.env` + systemd unit) → `wait-enroll` (agent self-enrolls with a one-time token). Uses only system `ssh`/`scp`/`ssh-keyscan`/`ssh-keygen` with hardened flags (`BatchMode`, `ConnectTimeout`, `StrictHostKeyChecking=yes`); no credentials are created, copied, or persisted (the operator's existing `~/.ssh` is the bootstrap channel). Non-systemd hosts hand off cleanly (terminal `handoff`, not an error). REST: `POST/GET /api/v1/provision-runs[/{id}]`, `POST .../key` (confirm|deny), `POST .../cancel`; SSE emits `provision.*` events. Tested with fake ssh binaries (unit + REST integration) **and** an opt-in live suite against real OpenSSH (`PARTOUT_LIVE_SSH=1 go test -tags live ./internal/sshutil/`) — the fakes encode ssh's intended semantics, so the live suite is what catches real-world divergence. **Mode semantics (v0.7.1):** `fresh` (default) is a **destructive wipe** — the install script stops + disables the existing `partout-agent` unit and removes its identity + env, so a re-provision enrolls as a brand-new agent (clean slate); `join` is a **non-destructive** in-place binary update (preserves identity). **Version-diff check:** preflight now reports the currently-installed agent version vs the version being installed (`remote_version`/`update=install|same|a -> b`), recorded in the preflight step output. **Multi-machine fleet E2E:** `scripts/fleet-provision-e2e.sh` (opt-in, 2+ real hosts) provisions two machines in parallel through the key-confirm gate to `connected`. Policy action-class gating for provisioning lands with M4 (admin-only for now).
- ✅ **Offline spool** (architecture §3.1.4, §3.4): when the stream to the server drops, in-flight commands **keep running** on the host; their output and result are buffered locally in a bounded per-run spool (16 MB mem → 128 MB disk → 24 h TTL → drop-oldest) and **replayed on reconnect** before new down traffic. The server marks in-flight runs `interrupted` on disconnect, then re-finalizes them when the replayed result arrives. Output chunks are appended idempotently keyed by `(run_id, chunk_seq)` and run-state updates are guarded, so replay is at-least-once and duplicate-safe. Spooled records are fsync'd per-run files under `<data dir>/spool/` and survive an agent restart (orphaned runs replay their partial output; the server shows the run as `interrupted`). Heartbeats report `spool_mem_bytes` / `spool_disk_bytes`. If the spool directory cannot be opened the agent **fails fast at startup** rather than running without offline buffering.
- ✅ **Embedded mode**: `--mode=embedded` runs the server + a co-located local agent in one process. The agent enrolls over loopback with a locally created one-time token (first boot only), reconnects with its persisted identity on restart, and works over plaintext or TLS (mTLS).

Remaining:
- [ ] Postgres backend (second store implementation) — deferred to a later phase (after M2)
- [x] TLS cert rotation via the stream — ✅ shipped (see TLS section below)
- [x] Dispatch to offline agents — ✅ shipped (see below)

#### Dispatch to offline agents (shipped)

- **Server-side down-queue with TTL.** A command dispatched to a host that is not
  currently connected is **queued** (run state `queued_offline`) instead of failing
  `not_delivered`. Each queued envelope carries a TTL (default 30 min, `SetOfflineTTL`).
- **Delivered on reconnect.** When the agent reconnects, the server drains the queue:
  the command is sent and the run transitions `queued_offline → delivered → <result>`.
  The execution aggregate stays `running` (pending) while any run is `queued_offline`.
- **Expiry.** A background sweeper (30 s) expires queued envelopes for agents that do not
  reconnect within the TTL (the run becomes `expired`, a terminal state).
- **Bounded.** Per-agent queue cap (default 100) to bound memory; the oldest is dropped
  on overflow. Approvals re-dispatch also honors the queue (an approved command for an
  offline agent is queued, not lost).
- **API/CLI:** unchanged — `POST /api/v1/executions` to an offline host now reports the run
  as `queued_offline`. Verified: unit tests (queue/drain/expiry/connected) + store state-
  transition tests + a live E2E (`scripts/offline-dispatch-e2e.sh`).

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

### M3 — Automation (complete)

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
- ✅ **Reboot continuation** (PRD §5.5, the `reboot` step kind): a task run that hits a `reboot` step persists a `resume-after-reboot` marker (`<data>/resume/<run_id>.json`, 0600 — remaining steps, results so far, the signed `Decision`, creation time), waits `PARTOUT_REBOOT_FLUSH_S` (default 5 s) so the `rebooting` report flushes, then reboots (`systemctl reboot` → `shutdown -r now` → `reboot`; the agent needs host reboot permission). The run reports `rebooting` and stops. After the host comes back and the first policy bundle loads, the agent verifies the reboot actually happened (system uptime < marker age — a host that never rebooted yields a stale marker: run reported `failed`, marker discarded), re-checks the run's signed decision via the guardrail (fail-closed on missing/stale/denied), runs the remaining steps, reports the final state with `trigger: resume`, and deletes the marker. Job runs report `JOB_RUN_RESULT` (the server finalizes the `rebooting` row in place); manual task runs report `TASK_RUN_RESULT` (a late result with no waiter finalizes the `task_runs` row via the stream's `TaskResultHook`). The reboot command is injectable for tests (no test reboots a machine); `internal/agent/resume` + `internal/agent/task` cover the flow, and `internal/server/jobs` covers the `rebooting → resume` row upsert.
- ✅ **Job dispatch E2E** (wire path, was the last untested M3 gap): `internal/server/jobs/jobs_dispatch_e2e_test.go` drives a live bufconn stream with the **real** agent-side scheduler (real task executor + real policy guardrail): `JOB_ASSIGN` → fire → `JOB_RUN_RESULT` → `job_runs` row + assignment state, then selector edits re-push a fresh `JOB_ASSIGN` and narrow to a zero-match selector to unassign every host (reconciliation, PRD §5.4).

### M5 — Observe: fact collectors (complete)

Done (R18–R20, the read side of the observe→act→verify loop):
- ✅ **Agent collectors** (`internal/agent/factscollect`): **services** (systemd unit state from `ActiveState`, enabled, wants/after deps, restart policy, memory, last exit status — custom + operator-labelled units only), **webservice configs** (HAProxy + Nginx native validation + line/brace-depth topology parse; read-only), **TLS certs** (expiry/`days_remaining`, subject/issuer/serial, SAN, key type, chain check, in-process `crypto/x509` self-signed detection; bounded path scan, deduped).
- ✅ **Transport**: new gRPC `OBSERVE_FACTS` envelope (kind 27) carrying a per-kind JSON blob; facts never spooled (collection runs off the loop goroutine, re-entrancy-guarded).
- ✅ **Server ingest**: `internal/server/observe/facts.go` `ParseDocument` (null=absent, flat scalars + typed accessors) merges into a **single `host_facts` JSON document per host** — merge-on-write so concurrent fact streams never clobber each other. Keyed strictly by the authenticated agent id (client-supplied `host_id` ignored for storage).
- ✅ **Read APIs** (viewer): `GET /api/v1/services?label&state&name&agent_id`, `GET /api/v1/certificates?agent_id&days_remaining_lt`, `GET /api/v1/configs?agent_id&kind`. Host-capped, unknown-expiry certs excluded from the days filter.
- ✅ **Web UI pages** (M7, v0.5): Services / Certificates / Configs render real data with label/state/expiry filters.
- ✅ **Tests**: parser unit tests incl. real generated certs (chained / broken-chain / multi-cert), the nginx vhost parser, `ActiveState` mapping; server `host_facts` merge + same-second collision probe; API shape tests.
- Remaining: **cross-fact correlation** (R21) rendering. Config **drift detection** (R22) is shipped as the `config_drift` alert rule (M6/M7): per-host `config_sha256` vs the fleet majority, alerting on divergence; the M6 alert engine and MCP read tools are shipped.

### M6 — Observe: alert engine (shipped)

Done (R23/R25 — the engine that makes observe data actionable; PRD Decision 16: server-side only):
- ✅ **Rules** (`alert_rules` table, schema v13; `CRUD /api/v1/alerts/rules`): name, `kind` (**`service_failed`** — unit in `failed` state, optional delay window `service_failed_minutes`, default 5; **`service_restarting` (M6.1)** — restart rate over the systemd `NRestarts` counter fact, `service_restart_rate_per_hour` default 10; **`cert_expiring`** — `cert_days_remaining`, default 30; **`config_invalid`** — haproxy/nginx `config_valid=false`; **`config_drift` (R22)** — cross-host `config_sha256` divergence vs the fleet majority, `config_drift_tolerance` default 0), selector (`all`/`role:x`/`tag:k=v`/host id), severity, enabled.
- ✅ **Engine** (`internal/server/observe/alerts.go`): ticks every `PARTOUT_ALERT_TICK_S` (default 30 s); one bulk `host_facts` read per tick (arch §7.5 cache, not per-host queries); evaluates each enabled rule × matching hosts; **dedup key = rule|host|subject** (unit name / cert path / config kind) so one condition yields one row; recovery transitions firing→resolved (missing facts fail soft — they neither fire nor resolve); a re-fail re-arms the same row.
- ✅ **Alerts** (`alerts` table): severity, message, state, started/resolved timestamps; `GET /api/v1/alerts[?state=&severity=&agent_id=]` + `GET /api/v1/alerts/{id}` (viewer).
- ✅ **SSE fan-out**: `alert.firing` / `alert.resolved` on the shared broker; every transition is audit-logged (`alert` events).
- ✅ **Web UI** (M6→M7): the **Alerts page** is live — firing-now count + firing/resolved table, SSE-refreshed, **plus the full rule-management UI** (create/edit/enable-disable/delete all five rule kinds). Capability probe: `alerts: true`.
- ✅ **CLI**: `partout ctl alerts list [--state S] [--severity S]` + `alerts rules`.
- ✅ **MCP**: `list_alerts` read tool (state/severity filters) — 26 tools total.
- ✅ **Tests**: engine unit tests (fire→dedup→resolve→re-arm, delay window, restart-rate over `NRestarts` incl. counter reset, drift tolerance, selector scoping, disabled rules, fail-soft), rules CRUD API (all five kinds), E2E fact-flip→`alert.firing` SSE→recovery→`alert.resolved`, UI shape + headless render.

### M7 — Observe: Web UI pages (complete)

Done (ui-guidelines S7 — the last open M7 slice; all remainders closed in v0.7):
- ✅ **Alert rule-management UI** (Alerts page): create / edit / enable-disable / delete rules for all five kinds with per-kind threshold fields (`service_failed_minutes`, `service_restart_rate_per_hour`, `cert_days_remaining`, `config_drift_tolerance`; `config_invalid` has none). Writes are operator-gated; the rule list is viewer-readable. Seeded + rendered by `scripts/ui-smoke.sh`.
- ✅ **Cert → config → service cross-links** (R21 rendering): the **Certificates** page's *Used by* column resolves a cert's path to the haproxy listener / nginx vhost that references it (link → Configs, filtered); the **Configs** page's listener/vhost TLS-cert cells link back to the Certificates page (filtered by path); config cards link to their `haproxy`/`nginx` **Services** row, and service rows link to their config. Cross-link targets are hash-route query params (`#/obs/certs?host=…&q=…`) pre-filled into page filters.
- ✅ **Config drift (R22)**: rendered as the `config_drift` alert rule (above) — cross-host `config_sha256` vs the fleet majority, per-host divergence alert, tolerance-thresholded.
- ✅ **Task actions**: the **Tasks & Playbooks** page gains per-task **Run…** (host prompt, policy-gated, parks on approvals with a notice) and per-playbook **Run** (fan-out with per-host outcome summary), plus a **Recent task runs** table with expandable per-step state/detail (ok/changed/failed/skipped/rebooting), SSE-refreshed on `task.run`.
- ✅ **Live PTY terminal (xterm.js)**: the **Sessions** page gains *Open terminal* (host + command, operator-gated, record-on) and the session page renders a live xterm.js terminal when the session is `open` — input via `POST /sessions/{id}/input` (base64), output via the `session.data` SSE stream (pre-mount chunks are buffered and replayed on attach), resize via `POST /sessions/{id}/resize`, close via `POST /sessions/{id}/close`. Closed sessions fall back to the recorded replay. Vendored offline in `internal/api/webui/lib/` (no CDN). Verified end-to-end against a real embedded server in a headless browser (`scripts/pty-e2e.py`: mount → type command → output round-trips → close → replay).
- ✅ **Write actions** (previously read-only surfaces are now drivable from the browser): the **Provision** page can **start a run** (host + mode, admin-gated), **confirm/deny the host key** at the `key_confirm` security gate (fingerprint shown), **cancel** a run, and shows live **step detail** (SSE-refreshed on `provision.*`); the **Updates** page can **apply packages** (package list, **dry-run** toggle, operator-gated, parks on approvals, shows the action history with expandable `dry_summary`) and shows **EOL external-data status + refresh** (admin); the **Jobs** page can **create/edit/delete** jobs (task + cron + selector + enabled form, `policy_denied` surfaced) and inspect **run history**; the **Tasks** page can **create a task** (versioned multi-step form: command/file/package/service steps); the **Secrets** page can **create + rotate** secrets (values stay write-only, never displayed); the **Users** page can **create a user** and **change role / enable / disable** (self-protection: you can't demote/disable/delete yourself); the **Files** page can **download** a host file; the **MCP** page lists **registered OAuth2 clients**. All are exercised by `scripts/ui-smoke.sh` (headless render checks).
- ✅ **Services page** now shows the `NRestarts` counter (feeds the `service_restarting` rule).

### M4 — Governance: approvals + MCP (shipped)

Done (PRD §5.8 — the approval path of the guardrail system):
- ✅ **Approval requests** (`internal/server/approvals` + `approval_requests` table, schema v12): a `require_approval` policy match parks the action — exec runs go `awaiting_approval`, package applies return `202 {approval_required}` — and create a request carrying the **exact payload** (approvals are scoped to the payload, not a blanket allow), actor, matched rules, and a TTL (`PARTOUT_APPROVAL_TTL_S`, default 1 h).
- ✅ **Approve/deny** (`GET/POST /api/v1/approvals[/{id}[/approve|deny]]`): list/get = viewer; approve/deny = admin only. Approve signs a **fresh `EffectAllow` decision carrying the approval id** — the id is part of the signed payload, so a decision cannot be grafted with a foreign approval reference — and re-dispatches the stored payload through the surface's registered dispatcher. Deny records the reason. Expired requests can never be retroactively honored (lazy expiry finalizes parked exec runs `failed` and re-finalizes the execution).
- ✅ **Agent guardrail** (`internal/agent/guardrail`): a decision with a non-empty `approval_id` passes when locally signed-valid (the local bundle may still carry the `require_approval` rule — the signed decision is the authority); a **local hard deny still wins** (belt and braces). Forged approval ids / wrong-effect approvals are rejected.
- ✅ **Safety rails**: without the approvals engine wired, `require_approval` fails closed as a deny; a cancelled/finalized run can no longer be approved; parked runs are cancellable with the execution; every transition is audit-logged (`approval.requested/approved/denied/expired` + surface audit) and SSE-broadcast (`approval.*` events).
- ✅ **Surfaces** (every policy-gated action class): exec (parked runs) · pkg.apply (`202 {approval_required}`) · **files** upload/edit/perm (upload bodies are staged in `<dbdir>/filestaging/` 0600 until decided; edit content likewise) · **sessions** open (parked session row) · **tasks** run (parked task-run row) · **jobs** manual RunNow (parked job-run row; scheduled fires stay fail-closed on the agent guardrail — a job cannot carry a standing decision that requires approval, and job *writes* name the hosts that need it). Secrets are a server-side vault (RBAC-only; no host action class, so no policy gate). Each surface keeps its own dispatcher; expiry finalizes the parked row per surface.
- ✅ **Web UI** (M4, v0.6): an **Approvals** page (capability-gated on `approvals`) — state filter (pending/approved/denied/expired), exact-payload request table with matched-rule chips, Approve (confirm) / Deny (reason prompt) for admins, SSE-refreshed on `approval.*` events; admin-only buttons for non-admins. Covered by the `scripts/ui-smoke.sh` headless harness (seeds a parked request, asserts the row renders) and a `TestUIShape_ApprovalsFields` UI↔API shape test.
- ✅ **CLI**: `partout ctl approvals list|get|approve|deny`.
- ✅ **MCP server** (R11, PRD §10.3, `internal/server/mcp`): JSON-RPC 2.0 (2025-06-18) over two transports — **stdio** (`partout --mode=mcp --server host:port --token T`, launched by MCP clients like Claude Code / Cursor / CI) and **Streamable HTTP** (`POST /mcp` on the main listener) — with **OAuth2 (PKCE)** for the HTTP transport (below). 26 tools: 18 read (`list_hosts`, `get_host`, `get_host_facts`, `list_groups`, `list_executions`, `get_execution`, `get_execution_output`, `get_audit`, `list_policies`, `list_jobs`, `list_tasks`, `list_approvals`, `list_alerts`, `list_updates`, `list_services`, `list_certificates`, `list_configs`, `download_file`) + 8 write (`run_command`, `cancel_execution`, `run_job`, `run_playbook`, `apply_updates`, `upload_file`, `create_secret`, `decide_approval`). The caller's credential (bearer token or OAuth2 access token) is forwarded to the **same REST router** the UI/CLI use (in-process for HTTP, a plain REST client for stdio) — RBAC, the policy gate, and audit are enforced by the control plane, not duplicated; a 403 / policy-deny / `approval_required` comes back as a structured tool error (`isError`) naming the offending rule. Interactive PTY is deliberately not a tool (request/response only).
- ✅ **OAuth2 (PKCE)** for the MCP HTTP transport (PRD R11, architecture A20; `internal/server/oauth`): admin-registered MCP clients (`POST /api/v1/mcp/clients`), `POST /oauth2/authorize` (the resource owner's existing bearer credential) issues a 5-min one-time code bound to the S256 challenge, `POST /oauth2/token` verifies `S256(code_verifier) == challenge` and issues a 1-h access token (stored only as a SHA-256 hash) that works as a bearer on the REST + MCP routes exactly like any other credential — RBAC/policy/audit unchanged. Tracked deviation: no browser login (this codebase is bearer-token-based), no refresh tokens in v1.
- ✅ **Playbook run** (`POST /api/v1/playbooks/{id}/run`, operator): runs the playbook's pinned task version on every host its selector matches; per-host outcomes come back as runs (the `run_playbook` MCP tool wraps it).
- ✅ **Tests**: store CRUD/expiry, controller approve/deny/expiry/no-dispatcher, guardrail approved/forged/hard-deny decisions, E2E park→no-wire-traffic→approve→signed re-dispatch for **every surface** (control/exec, packages, files upload, sessions, tasks, jobs), OAuth PKCE flow + failure paths + full HTTP E2E (token works on `/mcp`), playbook fan-out, API RBAC + error paths, UI shape + headless render.

### Not started

- **M8 — Distribution & polish**: installers, cloud-init, Helm, status page.

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
11. ~~**M3**: secrets, external data, packages, tasks/playbooks, scheduled jobs~~ ✅ Done — features complete, CI green; former gaps (reboot continuation, job dispatch E2E) closed — see items 14–15
12. ~~**Web UI**~~ ✅ Done — buildless Vue 3 SPA in `internal/api/webui/`, served same-origin via `go:embed`; S0 shell + data pages for M1–M7; capability-gated; UI↔API shape tests + `scripts/ui-smoke.sh` headless render check. All former remainders closed in v0.7: live PTY (xterm.js), cert→config→service cross-links, config drift, task actions, alert rule-management. See the M7 section below and ui-guidelines §13–18.

### Next (priority order, from the M3 verification audit)

13. ~~**Enforce policy on scheduled job steps** (security, M3/§5.4+§5.5)~~ ✅ Done — job create/update/RunNow gated under `task.run`; per-host signed `Decision` in `JOB_ASSIGN`; agent guardrail re-check before every fire (fail-closed). **Upgrade note:** after upgrading, re-save each job (or delete + recreate) so the server re-issues signed decisions; until then, fires fail closed with state `denied`.
14. ~~**E2E test the job dispatch path**~~ ✅ Done — `internal/server/jobs/jobs_dispatch_e2e_test.go`: `JOB_ASSIGN` over a live bufconn stream → real agent-side scheduler (real task executor + real policy guardrail) fires → `JOB_RUN_RESULT` over the wire → `job_runs` row + assignment state; selector edits re-push and unassign over the wire.
15. ~~**Reboot continuation**~~ ✅ Done (PRD §5.5) — the `reboot` step persists a `resume-after-reboot` marker (`<data>/resume/<run_id>.json`), reboots the host, and after boot the agent verifies the reboot happened (uptime check), re-checks the signed decision (fail-closed), runs the remaining steps, and reports `trigger: resume`. Stale markers (host never rebooted) fail the run and are discarded. `PARTOUT_REBOOT_FLUSH_S` (default 5 s) is the pre-reboot report-flush grace.
16. ~~**M4 — Governance**~~ ✅ Done (v0.6): local user auth ✅, approvals engine ✅ on all policy-gated surfaces (exec, pkg.apply, files, sessions, tasks, jobs), MCP server ✅ (stdio + HTTP + OAuth2 PKCE, 26 tools). Secrets are a server-side vault (RBAC-only, not policy-gated). See the M4 section above.
17. ~~**Observe layer (§6)**~~ ✅ Done (M5) — fact collectors + `host_facts` merge + read APIs + Web UI pages.
17a. ~~**M6 — Alert engine**~~ ✅ Done (v0.6.5) — see the M6 section above (rules, evaluation, dedup, SSE, API/CLI/MCP, live Alerts page).
17b. ~~**M6.1 — `service_restarting` rule kind**~~ ✅ Done (v0.7) — agent collects systemd `NRestarts`; engine computes restarts/hour per unit over the real interval between counter movements (not the 30 s alert tick, which inflated the rate ~10×), holds the rate while a loop continues (no firing/resolved flapping between facts uploads), folds counter resets, and ignores units whose collector failed; fires ≥ `service_restart_rate_per_hour` (default 10), resolves after 10 min quiet.
17c. ~~**M7 remainders**~~ ✅ Done (v0.7) — alert rule-management UI, cert→config→service cross-links, config drift (R22, `config_drift` rule), task actions, live PTY (xterm.js), and write actions (jobs CRUD, package apply/dry-run, provision start/key-confirm/cancel). See the M7 section above.
18. Postgres backend; then **M8 — Distribution & polish** (installers, cloud-init, Helm, status page).

### Polish items (closed this cycle)

- **`partout --version`** — prints the stamped version and exits (used by the
  provisioning version-diff check too).
- **Live audit log** — the previously-dead `audit.event` SSE subscription is now
  real: the server emits `audit.event` on every audit record, so the Audit page
  updates live. The `TestUIShape_SSESubscriptionsAreEmitted` guard no longer needs
  a `knownDead` exemption for it.
- **Global toast notifications** — consistent success/error feedback across every
  page (replaces blocking `alert()` boxes); write actions surface errors globally,
  GET loads stay quiet. See the M7 Web UI section.
- **UI write surfaces wired** — users (create + role/enable/disable), secrets
  (create + rotate), tasks (create), external-data (status + refresh), MCP
  clients (list), files (download). See the M7 Write actions item above.

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
  cert distribution** beyond the enroll response. **Rotation** is shipped (below); a full
  **revocation list** is still a v1.x follow-up — the Ed25519 gate already gives instant
  server-side revocation in the interim.

#### mTLS leaf rotation (shipped)

- **Server re-signs from the enrolled key.** At enrollment the agent's ECDSA public key is
  persisted (`agents.tls_pub` + `tls_not_after`, schema v14). The server re-signs a fresh
  2-year leaf from that key at any time — the agent's private key never changes or leaves
  the host.
- **Over the stream.** New `TLS_CERT` (down) / `TLS_RENEW` (up) envelopes. The server pushes
  a rotated leaf on demand, on expiry (hourly sweep, 30-day window), or when the agent asks
  (its leaf is expired/near-expiry on connect). The agent verifies the leaf chains to the CA
  and matches its identity, **hot-swaps** it into the live client cert (`GetClientCertificate`),
  persists it, and ACKs with the new serial.
- **No interruption.** The old leaf stays valid until its own expiry, so a swap on the next
  reconnect is seamless; both leaves verify against the same CA.
- **API/CLI.** `POST /api/v1/tls/rotate` (admin; `{agent_id}` or `{all:true}`),
  `GET /api/v1/tls/status` (viewer; per-agent expiry), `partout ctl tls status|rotate`.
  SSE `tls.rotated`.
- **Revocation** stays on the Ed25519 handshake (instant); cert-level revocation = re-issue.
- Verified: unit tests (certutil round-trip, agent hot-swap + reject-bad, server re-sign +
  store update) and a live TLS-mode E2E (`scripts/tls-rotation-e2e.sh`).

See `deploy/systemd/` for the systemd units and env templates.

### Not yet covered (v1.x)

- ~~Certificate rotation via the stream (`TLS_CSR`/`TLS_CERT` envelopes).~~ ✅ Shipped (see above; uses `TLS_CERT`/`TLS_RENEW`).
- Long-lived CA management / renewal reminders.
- Optional `PARTOUT_TLS_INSECURE` (skip-verify) escape hatch for dev — intentionally **not**
  shipped; use a local CA instead.

## Policy deny-list (implemented, v0.2.0)

Declarative deny rules gate every dispatch. v1 is a **deny-list**: the default is *allow*
(a rule set with no match is allowed); a matching `deny` blocks the command **server-side,
before any envelope reaches the agent**; a matching `require_approval` (M4) parks the action
on an approval request (exec + pkg.apply surfaces — see the M4 section) and fails closed
as a deny on the other surfaces.

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
   Every decision now also carries an optional `approval_id` (M4) covered by the signature.

**Audit:** `policy.create`, `policy.delete`, `policy.deny`, `policy.require_approval` (with matched rule id(s) and, when parked, the approval request id), `approval.*` (request/approve/deny/expiry), `approval.dispatch`.
**RBAC:** list = viewer; create/delete = admin; approvals approve/deny = admin (see the M4 section).
**Deviations from the proposed design** (tracked in architecture §15): default-allow in v1
(default-deny writes deferred to M2/M3 with the action-class taxonomy); `require_approval`
shipped for exec + pkg.apply in M4 (other surfaces fail closed); `requires_elevation`
match field not wired (elevation is
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
