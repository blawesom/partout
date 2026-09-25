# Partout — Architecture

**Status:** Draft v0.4 — observe layer: services, configs, TLS certs (implementation-level design)
**Companion docs:** `PRD.md` (product), `docs/deployment.md`, `docs/operations.md`

This document is the implementation-level design. The PRD is the source of truth for *what* and
*why*; this document defines *how*: module layout, the stream protocol, state machines, the
policy engine's shape, storage details, and failure semantics. Items the PRD does not lock down
are marked **(proposed)** and need sign-off.

---

## 1. Repository & binary layout

Single Go module, single binary, three modes (`--mode=server|agent|embedded`), Vue 3 frontend
embedded via `embed.FS` (PRD R1). Module path: `github.com/blawesom/partout`.

```
partout/
├── cmd/partout/            # main: mode dispatch, flag/env config, first-run bootstrap
├── internal/
│   ├── server/
│   │   ├── api/            # REST v1 handlers (mux), authz middleware, RBAC
│   │   ├── sse/            # SSE broker: subscribe, fan-out, per-client buffers
│   │   ├── mcp/            # MCP server (stdio + Streamable HTTP, OAuth2 PKCE)
│   │   ├── control/        # dispatcher, selector resolution, approvals
│   │   ├── provision/      # host bootstrap: preflight, install, update runs (PRD R17)
│   │   ├── policy/         # rule model, evaluator, decision signing, bundle builder
│   │   ├── secrets/        # store (HKDF), bindings, materialization envelopes
│   │   ├── audit/          # append-only writer, taxonomy, export
│   │   ├── jobs/           # job store, selector → per-host schedule resolution
│   │   ├── tasks/          # task/playbook store, versioning
│   │   ├── pkgmgmt/        # update orchestration, vuln correlation, EOL gating
│   │   ├── extern/         # external data service (EOL, CVE feeds), cache, refresh
│   │   ├── observe/        # facts ingestion, alert rules, alert engine, containers, endpoints
│   │   │   ├── facts.go         # server-side facts store (upsert into host_facts JSON)
│   │   │   ├── service.go       # service fact aggregation, label filtering, health rollup
│   │   │   ├── config.go        # config fact aggregation, drift detection, cross-host compare
│   │   │   ├── cert.go          # cert fact aggregation, expiry tracking, chain validation
│   │   │   ├── alerts.go        # alert rule store, rule evaluation, firing/resolved states
│   │   │   └── channels.go      # alert channels (SSE fan-out, future: webhook, email)
│   │   └── web/            # embed.FS of the built UI
│   ├── agent/
│   │   ├── stream/         # gRPC client, reconnect/backoff, handshake, flow control
│   │   ├── identity/       # Ed25519 + X25519 keypairs, identity.json (0600)
│   │   ├── guardrail/      # cached policy bundle, re-check, staleness
│   │   ├── exec/           # command/session/script runner, pty, output chunking
│   │   ├── fs/             # transfers, stat, edit (CAS), path safety
│   │   ├── jobsched/       # agent-side cron, overlap/failure policies, spool of runs
│   │   ├── taskrun/        # step runner, when-evaluator, reboot continuation
│   │   ├── pkg/            # apt/dnf/apk backends, journals
│   │   └── facts/          # collectors (os-release, init, pkg hash, units, ifaces…)
│   │   └── factscollect/   # observe-layer collectors: service/config/cert facts
│   │       ├── service.go  # systemd unit facts: state, deps, enablement, labels, resources
│   │       ├── config.go   # haproxy/nginx config facts: validity, topology, backends
│   │       └── cert.go     # TLS cert facts: expiry, chain, SAN, OCSP, key-type
│   ├── spool/              # shared spool: mem → disk → drop-oldest (both directions)
│   ├── store/              # dialect abstraction: sqlite | postgres; migrations
│   ├── proto/              # .proto + generated code for the stream service
│   ├── selector/           # selector grammar, resolution (shared server/agent tests)
│   ├── sshutil/            # system ssh/scp/ssh-keygen wrapper (provisioning only; §3.5)
│   ├── cryptoutil/         # ed25519 sign/verify, x25519, hkdf, aead helpers
│   └── config/             # env parsing (R15), defaults, validation
├── web/                    # Vue 3 + TS + Pinia + Tailwind + uPlot + xterm.js source
├── docs/                   # this directory
├── deploy/                 # systemd units, docker, compose, cloud-init, helm chart
└── test/
    ├── e2e/                # compose rig: server + 2 container agents
    └── fixtures/
```

Rules:

- `internal/` only — no importable packages; the binary is the product.
- `store` is the only layer that touches SQL; everything else uses repository interfaces.
- `selector` and `policy` IR are shared so server evaluation and agent re-check use one
  implementation of the rule semantics (defense in depth without two divergent engines).

---

## 2. Component overview

```
                        ┌────────────────────────────────────────────────────┐
                        │                    PARTOUT SERVER                  │
                        │                                                    │
  Browser ──── SSE ───► │  api ──► control ──► policy ──► approvals          │
  MCP client ─ HTTP ──► │               │            │          │            │
  CLI/curl ─── REST ──► │               ▼            ▼          ▼            │
                        │          selector     decisions   audit ◄─(all)   │
                        │               │            │          │            │
                        │               ▼            ▼          ▼            │
                        │  ┌── dispatch queue (per-agent, ordered) ──┐       │
                        │  │  jobs · tasks · secrets · pkgmgmt ·     │       │
                        │  │  extern (EOL/CVE) · observe (facts)     │       │
                        │  └───────────────────┬─────────────────────┘       │
                        │                      │                             │
                        │                store (SQLite | Postgres)           │
                        └──────────────────────┬─────────────────────────────┘
                                               │ gRPC bidi stream (TLS or h2c)
                          ┌────────────────────┼────────────────────┐
                          ▼                    ▼                    ▼
                     agent (host A)       agent (host B)       agent (host C)
                     exec·fs·jobsched·    …                   …
                     taskrun·pkg·facts·
                     guardrail·spool
```

The **control plane** (control/policy/approvals/secrets/audit) sits in front of the transport:
nothing reaches a dispatch queue without a policy decision and an audit row. The **observe
layer** (observe/extern) is a sibling plane that feeds facts and external data into both
monitoring (alerts, UI) and control decisions (EOL gating, CVE ranking, `when` guards).
**Provisioning** (`provision`, PRD R17) enters through the same API → RBAC → policy → audit
path and is the only authorized consumer of `sshutil` — a bootstrap channel, never a command
or observation path (§3.5).

---

## 3. Transport & stream protocol

### 3.1 Connection lifecycle

1. **Enroll** (one-time, PRD R2): `POST /api/v1/agents/enrollment-tokens` → token
   `par_enr_…` shown once; stored as `sha256` + first-14 mask. Agent runs
   `partout --mode=agent --server=<url> --token=<tok>` → generates keypairs
   (Ed25519 identity + X25519 transport **(proposed** — needed to encrypt per-agent material
   like secret envelopes at rest in the spool)) → `RegisterAgent(pubkeys, uuid, facts)` →
   enrolled; token consumed.
2. **Handshake** (per stream, PRD R3): server sends `Challenge{nonce, server_ts}`; agent
   replies `AuthProof{agent_uuid, ts, sig}` where `sig = ed25519_sign(nonce ‖ uuid ‖ ts_be64)`.
   Server verifies against the enrolled public key, rejects skew > ±300s, and marks the stream
   authenticated. Every subsequent envelope is bound to that `agent_id`.
3. **Stream**: authenticated bidirectional stream of `Envelope` messages.
4. **Reconnect**: exponential backoff with jitter, 1s base, 60s cap **(proposed)**; each
   attempt re-hands-hakes from scratch. On success the agent first drains its local spool
   (events/results) and then receives any pending down-queue (undelivered command envelopes
   whose TTL has not expired), in original dispatch order.
5. **Revoke**: server closes the stream and purges cascade rows (PRD R7). A revoked agent's
   keypair fails handshake on any subsequent attempt; re-enrollment issues a fresh keypair.

### 3.2 Envelope model (illustrative proto)

```proto
service AgentStream {
  rpc Stream(stream Envelope) returns (stream Envelope);
}

message Envelope {
  string id            = 1;  // unique per envelope
  AgentMsgKind kind    = 2;  // see below
  uint64  seq          = 3;  // per-direction monotonic, for ordering/loss detection
  string  corr_id      = 4;  // run_id / request id correlation
  int64   ttl_unix     = 5;  // expiry for queued down envelopes
  bytes   payload      = 6;  // typed payload (oneof in full proto)
  Ack     ack          = 7;  // optional: ack of a previously received envelope
}
```

**Up (agent → server):**

| Kind | Carries |
|---|---|
| `Heartbeat` | liveness, agent version, spool usage, uptime |
| `FactsBatch` | full or delta fact set (hourly + on change) |
| `EventsBatch` | observe events (metrics, containers, endpoints, certs, alerts) |
| `CommandOutput` | `run_id`, chunk seq, stdout/stderr bytes (≤ 64 KiB **(proposed)**) |
| `CommandResult` | `run_id`, exit code / timeout / cancel / interrupted, duration, final state |
| `SessionData` / `SessionResult` | PTY output chunks / close |
| `FileOpResult`, `PkgOpResult`, `JobRunReport`, `TaskRunReport` | per-domain results + journals |
| `Ack` | delivered + guardrail re-check outcome for a down envelope |

**Down (server → agent):**

| Kind | Carries |
|---|---|
| `CommandEnvelope` | full exec spec (cmd/args/cwd/env/user/timeout/elevation profile/stdin) + `Decision` (below) + `secret_refs` |
| `SessionOpen` / `SessionInput` / `SessionResize` / `SessionClose` | PTY control |
| `FileOp` | upload chunk / download request / edit CAS / stat / perm change |
| `SchedulePush` | resolved per-host schedules for a job (cron+tz, overlap/failure policy, task ref) |
| `TaskRunRequest` | `task_version_id`, steps, vars, `secret_refs` |
| `PkgOpRequest` | list-updates / dry-run / apply + correlation hints |
| `PolicyBundlePush` | version, content hash, full ruleset |
| `SecretMaterialize` | `secret_ref`, version, ciphertext (X25519-encrypted to the agent; never plaintext) |
| `Revoke` | (server closes stream; explicit for logging) |

### 3.3 Ordering, acks, dedup

- Each direction is a single ordered stream per agent; `seq` detects gaps. No reordering.
- **Down**: server marks a command envelope `delivered` on `Ack`; unacked envelopes stay in the
  per-agent queue with a TTL (default 15 min **(proposed)**; expiry → run state
  `not_delivered`, audited).
- **Up**: results are persisted idempotently keyed by `run_id` (PRD §6.2: at-least-once,
  dedupe on the audit side). Output chunks are appended by `(run_id, chunk_seq)`; replays are
  no-ops.
- **Flow control / rate limiting** (PRD R6): per-agent token bucket on both event upload and
  command dispatch; server-side backpressure: if the server cannot persist output faster than
  it arrives, the agent's up-window for that run shrinks (agent holds chunks in spool, bounded).

### 3.4 Failure semantics

| Scenario | Behavior |
|---|---|
| Disconnect mid-command | ✅ run → `interrupted` (server marks it when the session ends); the in-flight process **keeps running** on the host, its output spools, and the run re-finalizes when the replayed result lands. Ad-hoc commands are **not** auto-replayed unless flagged `retryable`; task steps re-run convergently (idempotent by construction) |
| Dispatch to offline agent | envelope queued with TTL; on reconnect agent pulls pending queue — **follow-up** (M0/M1 dispatch to an offline host returns `not_delivered`) |
| Server down, agent up | ✅ in-flight runs keep running (agent clock); command output + result spool (16 MB mem / 128 MB disk / 24 h TTL, drop-oldest); replayed on reconnect |
| Agent restart | ✅ spool reloaded from disk (orphaned runs replay partial output); pending `resume-after-reboot` continuation starts first (M3); stream re-hands-shake |
| Run lost to spool TTL/overflow | run is dropped wholesale (its `.sp` log deleted); the server-side run stays `interrupted` — never silently `succeeded` |
| Policy bundle mismatch | agent-side deny (see §5.3); alert + bundle refresh request |
| Clock skew > 300 s | handshake rejected; remediation is NTP (see ops doc) |

> **Known M1 limitation (fix in M3).** `interrupted` currently counts as a failure when
> the execution aggregate is computed, so a disconnect momentarily reports the execution
> as `failed` before the replayed result re-finalizes it to its true state. That is
> tolerable for human-driven ad-hoc commands, but a job/task failure policy acting on the
> transient state would wrongly retry or remediate. M3 must either keep the execution
> `running` while any run is `interrupted` (with a bound to resolve stranded runs), or
> model `interrupted` as its own execution state.

### 3.5 Host provisioning (PRD R17, C10; Decision 11)

The server bootstraps the agent on a new host over the **operator's existing fleet SSH** —
the server process can already `ssh` to its hosts. SSH is a *bootstrap channel only*: it never
carries commands, files, or observation data (PRD §7 invariant 1), and Partout never creates,
copies, or persists operator credentials.

**Modules:** `internal/sshutil/` — a thin wrapper around the **system** `ssh`/`scp`/
`ssh-keygen` binaries (deliberately not a Go SSH client library: the operator's
`~/.ssh/config`, known_hosts, ssh-agent, and ProxyJump all keep working as-is) — and
`internal/server/provision/` — run state machine, preflight, install plan, step executor,
SSE step log.

**SSH child-process contract (A16, implemented):**
- Runs as the server's service user. `PARTOUT_SSH_DIR` (default: the service user's
  `$HOME/.ssh`) is **authoritative**, and is passed to every child *explicitly*:
  `-F <dir>/config`, `-o UserKnownHostsFile=<dir>/known_hosts`, and
  `-o IdentityFile=<dir>/id_*` for any conventional key present. It is **not** applied via
  `$HOME`: OpenSSH resolves `~/.ssh` from the passwd database (`getpwuid`), so a `HOME`
  override is silently ignored — a bug this contract exists to prevent.
- Because `ssh -F` *replaces* the per-user config, a non-default `PARTOUT_SSH_DIR` means the
  operator's own `~/.ssh/config` is not read (the isolated dir's `config` is the contract).
  With the default dir the two are the same file, so behaviour is unchanged.
- Hardened flags: `BatchMode=yes` (no interactive prompts), `ConnectTimeout=10s`,
  `ServerAliveInterval=15`, `StrictHostKeyChecking=yes`. Fingerprint capture uses
  `ssh-keyscan` (which trusts nothing) rather than an unverified connect.
- The operator provides a host address **or a `~/.ssh/config` alias**; the alias used is
  recorded in `provision_runs`.

**Fingerprint gate (no silent TOFU).** If the target is not in `known_hosts`, the run pauses
in `key_confirm`: `partout ctl provision get <id>` shows key type + fingerprint; operator
confirms → public key hashed and appended to `<PARTOUT_SSH_DIR>/known_hosts`
(`ssh-keygen -H`) → run continues; operator denies → run cancelled, nothing changed on the
host. Confirm is **idempotent-safe**: a duplicate or racing confirm is rejected with a
conflict, never a panic. The gate is in-memory, so if the server restarts while a run is
paused, confirming it **fails the run** with a "re-run provisioning" remediation rather
than leaving a permanent `key_confirm` zombie.

**Run state machine** (see §4):

```
queued → connecting → key_confirm → confirming → preflight → transferring → installing
       → enrolling → connected
any step → failed | cancelled | handoff
```

(`confirming` is the brief transition after the operator approves the key, before preflight;
`installing` includes starting the unit — the install script runs
`systemctl enable --now partout-agent`, so there is no separate `starting` state.)

**Steps** (each audited under taxonomy kind `provision`, streamed as `provision.step` SSE
events with a bounded output excerpt):

1. **connect** — fingerprint gate above.
2. **preflight** (read-only, remote): `/etc/os-release`, arch, init system (`systemctl`
   present?), `whoami` + `sudo -n true` (install needs root or NOPASSWD sudo), free disk,
   host→server outbound reachability (`curl`/`wget` against `<server>/healthz`, caught here
   so a firewall fails fast instead of burning the 60 s enroll window; skipped if neither
   tool exists), and existing partout install
   (binary + `identity.json` → *update* or *fresh* path, below). Failure → `failed` with
   concrete remediation text.
3. **transfer** — `scp` of the same-version server binary (sha256 known) to
   `/tmp/partout-<sha256[:12]>` on the host.
4. **install** — one `ssh 'sudo -n bash -s'` script: verify sha256; `install -m 0755` →
   `/usr/local/bin/partout`; create `partout` user/group; `mkdir -p /var/lib/partout/agent`
   (0750 `partout:partout`); write `/etc/partout/agent.env` (0640) with `PARTOUT_SERVER`, a
   fresh short-TTL one-time `PARTOUT_TOKEN`, and labels from the run; write the systemd
   unit (deployment §3.2); `systemctl daemon-reload`; `systemctl enable --now partout-agent`.
   The script **never touches** existing agent state (`identity.json`, `tls/`, `spool/`;
   the install is idempotent; a re-run overwrites the binary and unit, keeps agent state).
   The `fresh` destructive path — explicit wipe of `identity.json` and `tls/` for
   post-revocation re-provisioning — is the next provisioning increment.
5. **wait-enroll** — server waits (≤ 60 s) for `RegisterAgent` with the run's token →
   `agent_id` linked to the run → `connected` once the stream authenticates.
6. **handoff** (terminal, non-error): hosts the v1 server cannot install — unreachable,
   non-systemd init (v1: systemd + bare binary only), Docker-host sidecar (manual), or
   air-gapped. `partout ctl provision get` prints the exact manual recipe: binary download
   + one-line install command with the one-time token (PRD §5.1).

**Update path:** re-provisioning an installed, connected host replaces the binary (when the
version differs) and restarts the unit; identity and spool are untouched; audited with
`mode=update`. (Post-v1 option: agent self-update over a gRPC `AgentUpdate` envelope would
remove the SSH dependency for upgrades entirely — noted in PRD Decision 11.)

> *v0.3 simplification:* the `--mode` flag (`fresh` | `join`, default `fresh`) is recorded
> on the run and in the audit trail, but the state machine does not yet branch on it — the
> install script is idempotent (overwrites binary + unit, keeps `identity.json`), so a
> re-run over an installed host acts as an in-place update. The `fresh` destructive path
> (explicit wipe of `identity.json` and `tls/`, per step 4 above) and the version-diff
> update check are the next provisioning increments.

**Security properties (regression-tested, §14):** `provision` is `admin`-only (RBAC). No run
reads, copies, or logs private key material — step logs capture command lines with
identity-file *names*, never contents. A failed run leaves no usable state: the token is
one-time + short-TTL, a partial install is overwritten idempotently by a re-run.

> *v0.3 deviation:* policy **action-class** gating for `provision` (so a policy rule can
> deny/require-approval a provisioning run, default-deny like any other write) lands with
> the M4 policy engine. In v0.3 the run is gated by **RBAC (admin) only** — there is no
> policy rule for it yet. The destructive `fresh` wipe path is not implemented (see above),
> so no explicit-confirmation gate exists yet either.

### 3.6 TLS / mTLS bootstrap (implemented)

Transport security is opt-in (`--tls on` / `PARTOUT_TLS=on`); plaintext `h2c` is the default
for local dev. When enabled, the control-plane port serves **only TLS** (a plaintext client
is rejected), and the port still multiplexes gRPC + REST — the demux is
`content-type: application/grpc`-driven, so it is unaffected by TLS (both may be h2).

**Trust model — local root CA, one trust anchor:**

- The server generates a **local root CA** (10y, ECDSA P-256) + its own **leaf** (2y) on
  first run, under `<db dir>/tls/` (`ca.key` 0600). SANs from `--tls-names`
  (default `localhost,127.0.0.1,<hostname>`).
- The **operator** distributes the CA (public) to managed hosts (e.g. `scp`, or
  `partout ctl ca` over HTTPS with the admin token → `GET /api/v1/tls/ca`).
- At **enrollment**, the agent generates a **local ECDSA P-256 keypair**, ships a **CSR** in
  the enroll request (over HTTPS), and receives the **CA + a signed leaf**
  (CN = agent id, EKU clientAuth, 2y). The private key never leaves the host; it is persisted
  under `<agent data dir>/tls/` (key 0600) and reused on restarts.
- The **gRPC agent stream** then connects over **mTLS**: server verifies client certs
  (`VerifyClientCertIfGiven`) and **requires** a valid client cert for gRPC requests (403
  otherwise), while REST/SSE remain open to bearer-auth clients.

**Why mTLS is not the primary auth:** the **Ed25519 handshake (§3.1 step 2) still gates every
stream** on top of TLS. So revocation is instant (purge the agent row → handshake fails) and
no certificate revocation list is needed for v1. The client cert protects the transport
channel (confidentiality + tamper-evidence against a misconfigured/compromised CA-less
listener), not agent identity.

**Certificate lifecycle (v1 vs v1.x):**

- v1: CA + leaves have fixed 10y/2y validity; leaf rotation is out of scope. An expired
  leaf → the agent re-enrolls (fresh CSR, same CA).
- v1.x: stream-delivered rotation (`TLS_CSR`/`TLS_CERT` envelopes) and a revocation list.

Implementation: `internal/certutil` (CA/leaf/CSR), `cmd/partout` (server bootstrap + agent
TLS flow), `internal/agent/{enroll,stream}`, `internal/api/{enroll,api}` (CSR/CA endpoints).

---

## 4. State machines

**Execution** (1) → **execution_runs** (N per host):

```
execution:    pending → dispatching → running → succeeded | failed | partial
run:          queued → delivered → running → succeeded | failed | timed_out
                                        │  └→ cancelled | interrupted
              queued → not_delivered (TTL expired)
              delivered → denied_agent (guardrail re-check failed; server notified)
```

- `partial` = mixed per-host outcomes; `failed` = all runs failed or policy-denied pre-dispatch.
- `timed_out` / `cancelled` are distinct terminal states, recorded with the timeout/cancel event
  (PRD §5.2).

**Task run** — ordered steps, each:

```
step:  pending → running → ok | changed | failed | skipped
run:   running → succeeded | failed | interrupted
```

- Any `failed` stops the run (no auto-rollback; before/after state is recorded where the step
  kind supports it — packages, services, files).
- `skipped` only via a false `when` (PRD Decision 4).

**Job run** = execution with `job_id` lineage (PRD §5.4).

**Approval**: `requested → approved | denied | expired` (TTL **(proposed**: 1 h default)); an
approval binds to the exact payload hash — a changed payload needs a new request
(PRD §5.8: scoped, not blanket).

**Provision run** (PRD R17; steps in §3.5):

```
run:  queued → connecting → key_confirm → confirming → preflight → transferring
      → installing → enrolling → connected
      → failed | cancelled | handoff        (from any step; handoff is non-error)
```

- `key_confirm` blocks on operator fingerprint confirmation (no timer in v1 **proposed**).
  `confirming` is the brief transition between approval and preflight; a duplicate/racing
  confirm is rejected with a conflict (never a panic).
- Confirm state is **in-memory**: if the server restarts while a run is paused at
  `key_confirm`, a subsequent confirm **fails the run** with a "re-run provisioning"
  remediation (the paused state machine is gone).
- `connected` additionally requires `RegisterAgent` + authenticated stream for the run's
  token; if enrollment doesn't complete within the wait window the run is `failed`
  (enrollment step), with the agent left installed — re-running picks up from *preflight*.

---

## 5. Control plane

### 5.1 Dispatch pipeline

```
POST /api/v1/executions {selector, cmd, …}
 1. authn (principal) + RBAC role check (viewer denied)
 2. resolve selector → concrete host set (deterministic; empty → 400, never silent)
 3. policy evaluate (per host, per action) → allow | deny | require_approval
 4. if require_approval: create approval_request; dispatch waits (or queues with TTL)
 5. audit write: execution + N runs (state=queued)
 6. enqueue CommandEnvelope per host (ordered per agent queue)
 7. agent ack → runs → delivered → … → results → SSE broadcast → alerts if policy says
```

### 5.2 Policy engine

**Implemented in v0.2** (M1): rules in `policies` (SQLite, versioned bundle), REST CRUD at
`/api/v1/policies`, `partout ctl policy list|create|delete`, dispatch gating in
`internal/control` (per-host evaluation, fail-closed on `deny`/`require_approval`),
signed decisions on `Command` envelopes, bundle push on connect + on change, agent
re-check in `internal/agent/guardrail` (architecture §5.3).

Rule (one declarative object, stored in `policies`):

```json
{
  "id": "pol_…", "name": "no-secret",
  "match": {
    "hosts":        "role=db",                     // selector expression ("all" = any host)
    "actions":      ["exec"],                      // action classes (v1: exec only)
    "actor_roles":  ["operator"],                  // requester RBAC role; empty = any
    "command_regex": "secret"                      // regex against "cmd args..."; empty = any
  },
  "effect": "deny | require_approval | allow",
  "priority": 10
}
```

- **Evaluation**: all matching rules considered; precedence `deny > require_approval > allow`.
- **Action classes (M2, D1)**: `exec` (commands, incl. session opens), `file.read`
  (stat/list/download — bypasses policy), `file.write` (upload/edit), `file.perm`
  (mode/owner changes). A rule's `match.actions` may list `file` (the parent class, matching
  any file op) or a specific class. File ops set `Action.Path` + `CommandLine = "kind path"`
  so `command_regex` can gate on path. A session open is an `exec` action (`cmd args`).
- **v1 default: default-allow** (deny-list model): an action with no matching rule is
  allowed. `require_approval` is accepted as an effect but evaluated as `deny` until the
  approvals engine lands (M4).
- **Structured refusal**: every deny carries the matched rule id(s) + reason in the API
  response, the run/session record (`state=denied`), and the audit log (`policy.deny`).
  Write file ops additionally attach a signed `Decision` to the `FileOp` envelope so the
  agent guardrail re-checks (arch §5.3); a mismatch → agent-side 403.

### 5.3 Server decision + agent re-check

**Implemented in v0.2** (M1), with the noted exceptions below.

- On dispatch, the server signs a compact `Decision{run_id, bundle_version, effect,
  matched_rules, actor_role}` with the server's Ed25519 key (`server_identity.key` under the
  server data dir; public key distributed in every policy bundle — `server_pubkey`).
- The server pushes a versioned, content-hashed **policy bundle** to each agent **on connect
  and on every policy change** (create/delete broadcasts to all connected sessions).
- **Agent re-check (defense in depth, PRD R/C8)**: before executing any envelope, the agent
  verifies (a) decision signature, (b) `bundle_version` equals its cached bundle, and (c)
  re-evaluates the rule set over the local action (the bundle carries the agent's own
  `host_tags`/`host_roles`/`agent_id`; the decision carries `actor_role`). Any mismatch →
  **deny**, emit `ACK_DENIED_AGENT` with the reason. **M2 (D1)**: write file ops (upload,
  edit, perm) attach the same signed `Decision` to the `FileOp` envelope and go through
  `guardrail.RecheckFile` before execution; read ops (stat/list/download) carry no decision
  and skip the re-check (they are policy-bypass by design). Session opens reuse the exec
  re-check path.
- The guardrail **fails closed** until the first bundle is received; an *empty* rule set is a
  valid default-allow state. The bundle + server public key persist under `<data-dir>/agent/`
  so the guardrail is effective from agent start (survives restarts).
- **v1 exceptions**: the agent does not alert the server / request a bundle refresh on a local
  deny (the reason is logged and visible in the run output); bundle staleness (48 h) applies
  to scheduled jobs, which land with M4.

### 5.4 Approvals

- `approval_requests` carry the exact payload (selector snapshot, command, elevation) and its
  hash; approvers (role `admin`, or `operator` where policy assigns) act via UI/API/MCP.
- Approval records are linked into the execution's audit row (approver principal + timestamp).
- Expiry: un-acted requests expire (default 1 h **(proposed)**) and the run ends `approval_expired`.

### 5.5 Secrets

- Store: `secrets` + `secret_versions` (append-only until rotation), `secret_bindings`
  (secret → selector → materialization mode: env / temp file / template value).
- Keys: master key from `PARTOUT_SECRET_KEY_FILE` (0600) or `PARTOUT_SECRET_KEY`; per-secret
  keys = HKDF(master, secret_id) (PRD §5.7). No key → feature disabled at startup with a clear
  error.
- Distribution: `SecretMaterialize{ref, version, eph_pub, sealed, cache_ttl_s}` over the
  authenticated (TLS) stream. The server decrypts the at-rest ciphertext, then seals the
  plaintext with an **ephemeral** X25519 key (ECDH with the agent's enrolled transport key,
  HKDF-derived AES-256-GCM) so the server holds the cleartext for a single materialization
  only and the sealed form is E2E-bound to that agent. The agent decrypts in memory,
  materializes only for the lifetime of the declaring task/command, and wipes on completion.
  With `cache_ttl_s > 0` it persists the **sealed form only** (0600, never cleartext) so a
  restart within the window can still serve the value while offline.
- **Offline**: default fail-closed ("secret unavailable", recorded). Per-secret `offline_ttl`
  (default 0) allows a bounded encrypted cache agent-side.
- Rotation: new version → prior binding invalidated; audit records which version each run used.

### 5.5.1 Tasks / Playbooks (M3, PRD §5.5)

- Store: `tasks` (name/description), `task_versions` (composite PK `task_id,version`; JSON `steps_json`),
  `task_runs` (agent, task, version, state, started, finished), `task_run_steps` (composite PK `run_id,step_index`;
  kind, name, state, detail, started, finished), `playbooks` (task_id + version + selector).
- Steps: 9 kinds — `command` (exec.CommandContext), `file` (idempotent write), `package` (apt/dnf
  by distro fact), `service` (systemctl), `user` (id + useradd), `group` (getent + groupadd),
  `template` (Go text/template with facts + vars), `assert` (when-evaluator expression),
  `reboot` (returns "reboot requested", stub for resume-after-reboot).
- **`when` guards**: constrained fact-based guard grammar — tokenizer + recursive-descent parser
  + evaluator. Supports: `==`, `!=`, `in [list]`, `!`, `and`, `or`, parentheses, string/number/bool
  literals, dotted fact refs (e.g. `host.distro`), `file.exists('path')` predicate. Fail-closed
  on unknown identifiers.
- **Runner**: executes steps in order, stops on `failed`, reports aggregate state in `task_runs`.
  False `when` → step skipped. Re-runs are idempotent (ok/changed, never duplicate side-effects).
- **Server dispatch**: `POST /api/v1/tasks/:id/run` → policy gate over `task.run` action class
  (signs Decision) → dispatch `TASK_RUN` down the stream → wait for `TASK_RUN_RESULT` → record
  per-step results in `task_run_steps` → emit SSE audit event.
- **Agent guardrail**: `RecheckTask(run)` verifies bundle version, decision signature (Ed25519),
  local policy re-evaluation over `task.run` action class, and server effect. Deny → step aborted.
- REST: `GET/POST /api/v1/tasks` (list/create task), `GET /api/v1/tasks/:id` (show task),
  `POST /api/v1/tasks/:id/run` (run on host), `GET /api/v1/tasks/runs` (list runs),
  `GET /api/v1/tasks/runs/:id` (run detail + steps), `GET/POST /api/v1/playbooks`.
- CLI: `ctl tasks list|create|show|run <id> <agent>|runs|run-show <id>`, `ctl playbooks list|create`.

### 5.5.2 Scheduled Jobs (M3, PRD §5.4)

- Store: `jobs` (name, task_id+version, cron, selector, overlap/failure policy, enabled),
  `job_assignments` (composite PK `job_id,agent_id`; last_run_state/at), `job_runs`
  (lineage: job_id, agent_id, task_id+version, scheduled/started/finished, state, trigger, error).
- **Server-side selector resolution** (PRD §5.4): at save/update the job's selector
  resolves to concrete hosts; each agent gets its own `JobAssignment` (cron + tz + task
  steps + policies). The agent never sees the selector — only the resolved schedule
  (plus a `selector_snapshot` recorded for audit). Editing a selector re-resolves and
  re-pushes per-host schedules (acceptance criterion).
- **Agent-side execution**: `internal/agent/jobs` scheduler uses `robfig/cron/v3`;
  each job runs on the agent's own clock, so a server outage or partition does not stop
  scheduled work. Assignments persist to `<data>/jobs.json` (0600) and reload on restart.
- **Overlap policy** (per job): `allow` (concurrent), `skip` (skip if in flight),
  `replace` (cancel prior). **Failure policy**: `no_retry` | `retry` with backoff (max 3).
- **Per-run deadline** (`max_run_s`, default 30 min) → `timeout` state.
- Runs produce `job_runs` rows (lineage) + audit event + SSE `job.run`.
- **Stream**: `JOB_ASSIGN` down, `JOB_UNASSIGN` down, `JOB_RUN_RESULT` up (hook →
  `jobs.Controller.OnRunResult`).
- **Policy gate (PRD §5.5, arch §5.3)**: job create/update evaluate the task under the
  `task.run` action class for every host the selector matches, BEFORE persisting — a denied
  host rejects the whole write (`403 policy_denied`). Each per-host `JOB_ASSIGN` carries a
  signed `Decision` (run_id = job id: a standing authorization bound to the job + the
  current policy bundle version). `POST /jobs/:id/run` (manual) signs a fresh per-run
  decision, like `task.run` dispatch. The agent re-checks the decision via the guardrail
  before **every** cron fire: missing decision, missing guard, bundle-version mismatch,
  bad signature, or local re-eval denial → run reported `denied` (no retry, fail closed).
  Consequence: after a policy bundle change or a server/agent upgrade, jobs must be
  re-saved from the server to re-authorize.
- REST: `GET/POST /api/v1/jobs`, `GET/PUT/DELETE /api/v1/jobs/:id`, `GET /jobs/:id/runs`,
  `POST /jobs/:id/run`, `GET /jobs/runs`. CLI: `ctl jobs list|create|show|delete|run|runs|list-runs`.
- **Selector edits reconcile assignments**: `PUT /jobs/:id` re-resolves the selector and
  **unassigns** (store + `JOB_UNASSIGN`) every host that no longer matches, so a narrowed
  selector stops those hosts from firing with a stale signed decision. A selector that
  resolves to zero hosts is rejected (the write is refused, existing assignments stand).

### 5.6 Audit

- `audit_events`: append-only; no update/delete endpoints (PRD §5.8). One writer goroutine,
  batched inserts; taxonomy: `enroll`, `revoke`, `exec`, `file`, `session`, `job`, `task`,
  `pkg`, `secret`, `policy`, `approval`, `principal`, `system`.
- Privileged commands recorded **in full, no redaction** (PRD Decision 8).
- Output replay within 30-day window; metadata (exit, duration, redacted command, output
  digest) retained with the run indefinitely (PRD §5.8 acceptance).
- Export: `GET /api/v1/audit?format=json|csv` with filters; intended to be piped by cron to a
  sink the server can't modify (syslog/remote DB/WORM). Cryptographic hash-chain: deferred
  post-v1 (PRD Decision 5).

### 5.7 Targeting / selectors

Grammar **(proposed)** — a selector is a comma-separated conjunction of predicates:

```
all
host:<id>                      # explicit host (repeatable)
tag:env=prod | tag:env         # key=value or key-only
role:web
group:webservers               # a saved group (named selector)
```

- `a,b,c` = intersection (AND). No OR in v1 — compose with groups instead (keeps the language
  tiny, matching the task-language philosophy).
- Resolution: deterministic (result sorted by host id), recorded with every job/execution as a
  snapshot. Empty result = error (PRD §5.1).
- Jobs resolve selectors **server-side at save/update time** into per-host schedules
  (`SchedulePush`); agents never see selectors (PRD §5.4).

---

## 6. Agent internals

### 6.1 Modules

- **facts** — collectors for os-release/osImage, init system, package manager, arch,
  cpu/mem/disk, installed-package *hash* (change detection), systemd units, users/groups
  (names), interfaces. Refresh hourly + on detected change (PRD §5.1). Feeds `when` guards.
- **factscollect** — observe-layer fact collectors (`R18`-`R20`). Three sub-collectors:
  (a) **service**: `systemctl list-units` + `systemctl show` for full unit state, deps,
  enablement, resource usage, operator labels. Custom units only in output (units from
  `/etc/systemd/system/*` or labelled by operator). Refresh: 5 min.
  (b) **config**: `haproxy -c` / `nginx -t` for validity; lightweight regex parsing for
  topology (backends, frontends, vhosts, TLS bindings). Config sha256 for drift detection.
  Refresh: 15 min or on file mtime change. (c) **cert**: openssl x509 for subject, issuer,
  expiry, SANs, chain validity, OCSP status. Discovery from config TLS paths + default
  cert dirs. Refresh: 1 hour. All three feed into the FactsBatch stream under named JSON
  keys in `host_facts`.
- **exec** — non-pty and pty execution; env sanitized (`$HOME`, `$PATH` from a clean base;
  only explicitly declared env passed); cwd defaults to agent home. All fs/exec paths are
  interpreted relative to the **agent root** (`PARTOUT_ROOT`, default `/`; `--root=` flag),
  which makes the identical binary work on bare metal and in a container mounting the host
  at `/host` (deployment §3.4). Output chunked ≤ 64 KiB
  **(proposed)**, streamed, never buffered whole. Cancellation ladder: SIGTERM → 5 s grace →
  SIGKILL **(proposed)**; timeout default 30 s, configurable, hard cap.
- **elevation** (PRD Decision 3) — the agent executes `sudo -n -u <target> -- <cmd>` only when
  the command matches a named **elevation profile** (pattern-scoped, declared in the command
  spec and constrained by policy). Precedence: per-command > host-level `--elevate`; `sudoers`
  wins over `sudo` at any level. Host-level `--elevate=none` (default **(proposed**) / `sudoers`
  / `sudo`) sets the floor; per-command can only tighten.
- **fs** (M2, implemented) — atomic writes (temp + rename), stat, CAS edit (compare-and-swap
  on sha256), chunked upload (256 KiB), chunked download (resumable offset), size caps
  (256 MiB transfer / 1 MiB edit / 2048 list entries), no symlink traversal across the
  transfer boundary (PRD §5.3, D4: any symlink component in the path is rejected; absolute
  paths only; intermediate components must be real directories). `SafePath` is the single
  choke point every op calls before touching the filesystem.
- **session** (M2, implemented) — PTY session manager over `creack/pty`. `Open` spawns the
  command in a PTY at the requested cols/rows, sanitizes the environment, and wires a
  single read-loop that pumps 64 KiB chunks to the server (up `SESSION_DATA`) and, when the
  process exits, reports `SESSION_RESULT {state, exit, duration}`. `Input`/`Resize` forward
  terminal bytes / window size. `Close` sends SIGHUP, waits 1 s, escalates to SIGKILL
  (graceful, deliberate → state `closed`); `KillAll` (stream drop, D2) kills immediately
  (state `interrupted`). Only one goroutine ever calls `cmd.Wait()`, so exit is reported
  exactly once.
- **jobsched** — in-process cron on the agent's clock; stores resolved schedules + run state +
  overlap locks in agent-local state; overlap policy (allow/skip/replace) and failure
  retry-with-backoff executed here; results spool offline.
- **taskrun** — ordered step runner; each step checks-then-changes and reports
  `ok|changed|failed|skipped`; `when` evaluated agent-side against live facts;
  **reboot continuation**: before reboot the agent persists
  `resume-after-reboot.json {task_run_id, step_index, ts}` in its state dir; on boot, if a
  marker exists and is within its validity window (10 min **(proposed)**), the run resumes and
  reports `rebooting → resumed`.
- **when grammar** (constrained, agent-side, never free-form — PRD Decision 4):
  comparisons over facts (`fact.os == 'debian'`, `host.distro in ['debian','ubuntu']`),
  state predicates (`!file.exists('/x')`, `pkg.installed('nginx')`,
  `service.running('ssh')`, `service.failed('myapp')`, `config.valid('haproxy')`,
  `cert.expiring('/etc/ssl/app.pem', 30)`), combined with `and`/`or`. Parsed to a tiny
  AST; anything else is rejected at task validation time.
- **pkg** — apt/dnf backends (apk in M3.1) selected from os-release `ID` fact (R13);
  `list-updates` runs `apt-get -s upgrade` / `dnf check-update` on the agent and returns
  available upgrades, which the server ranks by CVE severity via `vuln_cache` (PRD §6.3);
  `apply-updates` always dry-runs first, then applies, and records a before/after
  `dpkg-query` / `rpm -qa` journal per action (PRD §5.6). `pkg.apply` is a distinct policy
  action class; the agent re-checks the signed Decision before running.
  **Live-verified** on a real Ubuntu 24.04 host (dry-run captured the apt phasing summary).
- **guardrail** — cached policy bundle (content-hashed), re-check per §5.3, staleness watcher.
- **spool** — shared implementation: 16 MB mem → 128 MB disk → drop-oldest, 24 h max age
  (PRD §9); per-run append-only log (length-prefixed proto envelope, fsync'd); a run is
  drained only once its CommandResult is present, oldest-first, and only the records
  actually sent are removed (records appended while a drain is in flight stay queued).
  Opening the spool is fatal on failure — the agent never runs without offline buffering.
  M1 spools command output + result upload; event upload and delivery acks follow in later
  milestones. Encrypted payloads (secret materialization) stay encrypted at rest.

### 6.2 Agent state on disk

```
/var/lib/partout/agent/
├── identity.json          # keypairs + uuid, mode 0600 (PRD R3)
├── spool/                 # offline spool: one append-only log per run (<run_id>.sp, 0600)
│                          #   record = [4-byte BE length][proto Envelope], fsync'd.
│                          #   M1: COMMAND_OUTPUT chunks + COMMAND_RESULT. Survives
│                          #   agent restart (orphaned runs replay partial output).
├── policy-bundle.json     # last received bundle (rules only, no secrets)
└── secret-cache/          # optional, only for secrets with offline_ttl>0; encrypted
```

---

## 7. Observe layer

This layer collects facts from agents, stores them in the database alongside other host facts,
and evaluates alert rules over stored facts. It is the bridge between "what's running on
my hosts" and "something is wrong" — the observe side of the "observe → act → verify" loop.

### 7.1 Architecture

```
┌──────────────────────────────────────────────────────────────┐
│                    SERVER: observe/                          │
│                                                              │
│  facts.go ───► upsert into host_facts JSON blob             │
│  (one endpoint per fact kind)                                │
│       │                                                       │
│       ▼                                                       │
│  service.go ──► label filtering, health rollup, dep tree     │
│  config.go  ──► drift detection, cross-host compare          │
│  cert.go    ──► expiry tracking, chain validation, SAN list  │
│       │                                                       │
│       ▼                                                       │
│  alerts.go ──► rule evaluation ──► firing/resolved states    │
│  channels.go ─► SSE fan-out + future webhook/email           │
└──────────────────┬───────────────────────────────────────────┘
                   │
      ┌────────────▼────────────┐    ┌──────────────────────┐
      │  Agent: factscollect/   │    │  Agent: facts/       │
      │  service.go             │    │  (existing: os-     │
      │  config.go              │    │   release, init,    │
      │  cert.go                │    │   pkg hash, etc.)   │
      └────────────┬────────────┘    └──────────┬───────────┘
                   │ FactsBatch up (same       │ FactsBatch up
                   │  stream, different JSON   │ (same stream)
                   │  keys in host_facts)      │
                   ▼                           ▼
              server/observe/ facts.go ───────► upsert
              (unified: all fact kinds merge
               into one JSON blob per host)
```

Key principle: all fact kinds merge into one `host_facts` JSON blob per host. There are no
separate tables per fact kind. The schema is: `host_facts(agent_id, facts_json, facts_hash,
updated_at)`. Fact collectors produce named keys in the JSON:

```json
{
  "os": { "id": "ubuntu", "version": "24.04", "osImage": "..." },
  "resources": { "cpu": 4, "mem_bytes": 8589934592, "disk_bytes": 214748364800 },
  "packages_hash": "sha256:abc123...",
  "interfaces": [ { "name": "eth0", "addr": "10.0.1.5" } ],
  "services": {                    // existing: basic unit list
    "unit_names": ["sshd","nginx","myapp"]
  },
  "services_detailed": {           // R18: full service facts
    "units": [
      { "name": "myapp", "state": "active", "sub_state": "running",
        "enabled": true, "wanted_by": ["multi-user.target"],
        "after": ["network-online.target"], "restart_policy": "on-failure",
        "memory_current": 45678901, "last_exit_code": 0,
        "labels": ["myapp", "webtier"] }
    ]
  },
  "configs": {                     // R19: webservice config facts
    "haproxy": { "present": true, "version": "2.8.5",
      "config_file": "/etc/haproxy/haproxy.cfg", "config_sha256": "sha256:def...",
      "config_valid": true,
      "backends": [
        { "name": "webservers", "servers": 3, "active": 3 },
        { "name": "api", "servers": 2, "active": 1 }
      ]
    },
    "nginx": { "present": true, "version": "1.24",
      "config_file": "/etc/nginx/nginx.conf", "config_sha256": "sha256:ghi...",
      "config_valid": true,
      "vhosts": [
        { "server_name": "app.example.com", "port": 443, "tls": true,
          "tls_cert": "/etc/ssl/app/fullchain.pem",
          "root": "/var/www/app", "upstream": "unix:/run/myapp.sock" }
      ]
    }
  },
  "certificates": {                // R20: TLS cert facts
    "items": [
      { "path": "/etc/ssl/app/fullchain.pem",
        "subject": "CN=app.example.com",
        "issuer": "CN=Let's Encrypt Authority X3",
        "not_after": 1728000000, "days_remaining": 14,
        "key_type": "ECDSA-P256", "san": ["app.example.com"],
        "chain_valid": true, "chain_length": 3,
        "self_signed": false, "ocsp_stapling": true,
        "ocsp_status": "good",
        "labels": ["webtier", "prod"] }
    ]
  }
}
```

### 7.2 Agent-side collectors

**Service collector (`factscollect/service.go`)**:
- Command: `systemctl list-units --no-pager --no-legend --type=service --state=active,failed,deactivating,activating` for active units.
- For each unit: `systemctl show <unit>` (key=value format) for properties: State, SubState, ActiveState, UnitFileState (enabled/disabled/masked), Requires, RequiredBy, Wants, WantedBy, After, Before, Restart, MemoryCurrent, CPUSec.
- Custom labels: read from `PARTOUT_SERVICE_LABELS` env var (`myapp,nginx`) or from operator-assigned labels at enrollment. Units from `/etc/systemd/system/*` (not `/lib/systemd/system/*`) are auto-marked as custom.
- Output: `services_detailed.units[]` JSON array.
- Refresh: every 5 minutes (services change less often than resources).

**Config collector (`factscollect/config.go`)**:
- Commands: `haproxy -c -f /etc/haproxy/haproxy.cfg` (validation), `nginx -t` (validation).
- Config parsing: lightweight regex/line-based parsing (not full YAML parsing) to extract backends, servers, frontends, vhosts, TLS bindings. This keeps the collector fast and avoids dependency on config-file-format parsers.
- Topology: for each backend, count total servers and servers marked as "up" (reachable on the host, detected via a lightweight TCP probe to the server address:port within a timeout — optional, can be disabled).
- Output: `configs.haproxy`, `configs.nginx` objects.
- Config drift: server compares `config_sha256` across hosts with the same role/group; flag when divergent.
- Refresh: every 15 minutes or on change (detected by config file mtime — inotify watch).

**Cert collector (`factscollect/cert.go`)**:
- Discovery: scan paths from config facts (TLS binding paths in haproxy/nginx configs), plus default walks of `/etc/ssl/`, `/etc/ssl/certs/`, `/etc/pki/tls/`. Also respect `PARTOUT_CERT_PATHS` env var for custom paths.
- For each `.pem`/`.crt`/`.cert` file: `openssl x509 -in <path> -noout -subject -issuer -dates -serial -ext subjectAltName -fingerprint -text` (single command, all info in one parse).
- Chain validation: `openssl verify -CAfile /etc/ssl/certs/ca-certificates.crt <path>` (system trust store).
- OCSP: extract stapled response from the cert (not an outbound OCSP request — the agent never initiates outbound connections beyond gRPC). `openssl x509 -in <path> -noout -text | grep -A2 'OCSP'`.
- Custom labels: same label mechanism as services.
- Output: `certificates.items[]` JSON array.
- Refresh: every 1 hour (certs change very rarely).

All collectors run in parallel on the agent. Results are included in the next `FactsBatch`
upload with the appropriate JSON keys. Upload is part of the regular facts stream, not a
separate channel.

### 7.3 Server-side fact storage

Facts ingestion (`observe/facts.go`):
- All fact kinds merge into one JSON blob per host: `host_facts(agent_id, facts_json, facts_hash, updated_at)`.
- On each upload, the server computes a sha256 of the new facts_json; if it matches the latest facts_hash, the facts are unchanged (skip processing).
- A change-triggered history row is written when the hash differs (for drift detection and time-series views).
- Fact data is stored as JSON in a TEXT column; no SQL-level field extraction. The server processes facts in Go code for aggregation and alert evaluation.
- Retention: latest always kept; history rows retained per PRD §9 (90 days).

### 7.4 Aggregation and cross-fact correlation

**Service aggregation (`observe/service.go`)**:
- Filter: by operator labels (`myapp`, `webtier`), by state, by host group.
- Health rollup: per-service, count active/failed/inactive across fleet.
- Dependency tree: reverse-dep analysis (which services require this one?).
- API: `GET /api/v1/services?label=myapp&state=failed` returns aggregated view.

**Config drift (`observe/config.go`)**:
- Hash comparison: group hosts by role/selector, compare `config_sha256` within groups.
- Flag: hosts whose config hash differs from the group majority are flagged as drifted.
- API: `GET /api/v1/configs?kind=haproxy&agent_id=` returns per-host config state.

**Cert expiry (`observe/cert.go`)**:
- Days-remaining calculation from `not_after` epoch.
- Chain validation summary: valid/broken/self-signed/unknown.
- Cross-link: cert path in `configs.nginx.vhosts[*].tls_cert` → linked to cert in `certificates.items[*]` → linked to service via haproxy frontend/backend.
- API: `GET /api/v1/certificates?days_remaining_lt=30` returns near-expiry certs.

### 7.5 Alert engine (`observe/alerts.go`)

**Rule model**:

```json
{
  "rule_id": "alert_rule_abc",
  "name": "prod-web-cert-expires-soon",
  "kind": "cert_expiring",
  "selector": "tag:env=prod AND role=web",
  "thresholds": {
    "cert_days_remaining": 30
  },
  "severity": "warning",
  "enabled": true
}
```

**Alert kinds**:

| Kind | Source fact | Threshold | Default severity |
|---|---|---|---|
| `service_failed` | `services_detailed.units[*].state == "failed"` | `service_failed_minutes: 5` | critical |
| `service_restarting` | Unit in `auto-restarting` sub-state | `service_restart_rate_per_hour: 10` | warning |
| `service_absent` | Expected custom unit not present | `unit_name: "myapp"` | critical |
| `cert_expiring` | `certificates.items[*].days_remaining` < threshold | `cert_days_remaining: 30` | warning |
| `cert_chain_broken` | `certificates.items[*].chain_valid == false` | (boolean) | critical |
| `config_invalid` | `configs.*.config_valid == false` | (boolean) | critical |
| `config_drift` | `configs.*.config_sha256` differs from group | `config_drift_tolerance: 0` | info |
| `endpoint_down` | (future: health endpoint probe) | (TBD) | warning |

**Evaluation flow**:

1. **Periodic ticker** (default: every 2 minutes): server iterates all enabled alert rules.
2. For each rule, resolve the selector to concrete hosts.
3. For each host, load the latest `host_facts` blob and evaluate the rule's thresholds against
   the relevant fact keys.
4. If a threshold is violated, check the alert store for an existing firing alert for this
   (rule, host, dedup key) triple.
5. If no existing firing alert: create a new alert (`state: firing`), emit an `alert.firing` SSE event.
6. If an existing firing alert exists: update `last_evaluated` timestamp (no duplicate event).
7. If a threshold is NOT violated but an alert is firing: update alert to `state: resolved`,
   emit `alert.resolved` SSE event, set `resolved_at`.

**Dedup key**: unique per (rule_id, host_id, threshold_key) to prevent duplicate alerts. For
`cert_expiring`, the dedup key is the cert file path. For `service_failed`, it's the unit name.

**Performance**: with 500 hosts and 50 rules, evaluation is 500 × 50 = 25k fact lookups per
tick. Facts are loaded from in-memory cache (DB cache, not hot queries) — each lookup is a
JSON key traversal in Go, negligible cost. Full evaluation cycle is <1s.

### 7.6 SSE event types

New SSE event kinds for the observe layer:

| Kind | Payload | Consumer |
|---|---|---|
| `alert.firing` | `{alert_id, rule_id, kind, host_id, severity, message}` | UI alert banner, MCP tools |
| `alert.resolved` | `{alert_id, rule_id, kind, host_id}` | UI alert banner |
| `facts.upload` | `{agent_id, fact_kinds: ["services","configs","certs"], changed: true/false}` | Internal tracking |

### 7.7 Architectural coupling to control plane

1. **Facts feed `when` guards** — the agent's fact cache is the single source for task guards.
   New predicates: `service.failed("myapp")`, `config.valid("haproxy")`, `cert.expiring("/path/to/cert", 30)`.
2. **Task `assert` step** can verify facts: `assert: {check: "config_valid", value: true, context: "haproxy"}`.
3. **Alert rules can require approval** — a `service_failed` alert can trigger a task via
   MCP tool integration (AI assistant sees the alert, recommends a restart task).
4. **EOL state feeds patch gating** — `extern` publishes per-host `supported | ending_soon | ended`
   from the EOL cache; `pkg` and policy rules may require approval on `ended` hosts (PRD §5.6).
5. **Alerts fan out on the same SSE broker** as command output and audit events.

---

## 8. External data service (PRD §6.3)

```
startup ──► refresh ◄── daily timer (24 h)
             │                ▲
             ▼                └── POST /api/v1/external-data/refresh (manual)
        fetchers (endoflife.date, per-distro):
          • debian, ubuntu, rhel, alpine, rocky-linux, almalinux,
            fedora, centos, oracle-linux, opensuse  → eol_cache
   all-or-nothing: every feed must fetch AND parse → atomic eol_cache replace
   any failure    → previous cache untouched, one log line, last_error set

vuln_cache (on demand, not at refresh):
   list-updates correlation → OSV.dev /v1/querybatch (pkg, ecosystem, version)
   → 1 h TTL in vuln_cache; clean packages get a tombstone row (vuln_id="-")
   → air-gapped: stale cache served, no network
```

- Cache is in-DB (SQL tables `eol_cache`, `vuln_cache`) so it survives restarts and is
  inspectable; a **minimal embedded EOL fallback** (major distros only) ships in the binary for
  first boot / air-gapped use.
- `PARTOUT_DISABLE_EXTERNAL_DATA_REFRESH` (PRD) disables all fetching for air-gapped sites.
- **Privacy invariant (PRD §6.3/§7):** only installed-package identifiers (name+version, distro,
  arch) leave the server, as query parameters. No host identity, host lists, or operator data.
- Correlation output: per-host `updates` ranked by severity (distro-adjusted score where the
  tracker provides one, else CVSSv3 base); drives the Updates UI and `apply-updates` priority.

---

## 9. Storage

### 9.1 Dialect & migration discipline (PRD R9)

- Two engines: SQLite (default, WAL, single writer) and PostgreSQL (optional for the server
data set). One dialect abstraction (`internal/store`); no engine-specific queries outside it.
- **One migration version**: a single monotonic version applied identically to both dialects;
  forward-only; run automatically at boot. Migration tests run against **both** engines in CI
  (parity matrix).
- All entities carry `agent_id` (`NULL` = local/embedded); `ON DELETE CASCADE` on
  agent removal (PRD R7/R8). TEXT keys (opaque ids, `ag_…`, `exec_…`, `run_…`), epoch-second
  BIGINTs, `ON CONFLICT … DO UPDATE` upserts.

### 9.2 Tables (illustrative; full schema in migration v1)

| Table | Notes |
|---|---|
| `agents` (hosts) | `agent_id`, uuid, public keys (ed25519 + x25519), version, state, last_seen, first/last facts hash |
| `host_facts` | latest + history (JSON), 90-day history retention, latest always kept |
| `host_tags`, `host_roles`, `groups` | targeting (group = named selector) |
| `enrollment_tokens` | sha256 + mask, one-time, TTL |
| `executions` → `execution_runs` | 1:N; run carries state machine (§4), `retryable` flag |
| `output_chunks` | `(run_id, chunk_seq)` unique; stream-to-disk above 1 MiB/run **(proposed)**; 30-day retention |
| `sessions`, `session_records` | PTY byte streams; 30-day retention; optional capture |
| `files_actions` | upload/download/edit/stat/perm audit rows |
| `secrets`, `secret_versions`, `secret_bindings` | HKDF-encrypted at rest; versioned; per-materialization audit |
| `tasks`, `task_versions`, `playbooks`, `task_runs`, `task_run_steps` | versioned; step state per §4 |
| `jobs`, `job_assignments`, `job_runs` | scheduled jobs (agent-side cron, PRD §5.4) |
| `package_actions` | list/apply/dry-run + per-host before/after journal |
| `eol_cache`, `vuln_cache` | external data (§8) |
| `secrets`, `secret_versions`, `secret_bindings` | values encrypted at rest (HKDF-derived keys) |
| `audit_events` | append-only, all taxonomy kinds; no update/delete paths |
| `policies`, `approval_requests`, `approvals` | control plane |
| `principals` | local users (v1), roles `viewer|operator|admin`, hash+pepper of password |
| `provision_runs` | per-run state, host alias, mode (`fresh` or `join`, default `fresh`), per-step rows (kind, ts, bounded output excerpt), linked `agent_id` once enrolled; `key_line`/`token_hash` stored but never serialized; retention 90 d (audit keeps `provision` events) |
| `alerts` | unified alert store: `alert_id`, `agent_id` (NULL= fleet-wide), `kind` (service_failed, service_restarting, cert_expiring, cert_chain_broken, config_invalid, config_drift), `host_id` (nullable for fleet-wide alerts), `rule_id`, `severity`, `message`, `state` (firing/resolved), `started_at`, `resolved_at`. Dedup key prevents duplicate firing. Retention: indefinitely (no auto-purge). |
| `alert_rules` | threshold rules: `rule_id`, `name`, `kind`, `selector`, `thresholds` (JSON: `{cert_days_remaining: 30}`, `{service_failed_minutes: 5}`), `severity`, `enabled`, `created_by`, `created_at`, `updated_at`.

### 9.3 Retention sweeper

A server-side sweeper enforces PRD §9. **M2 (implemented)**: session recordings are purged
past 30 days (daily ticker; `PARTOUT_SESSION_RETENTION_DAYS` overrides the window; purged
chunk count is logged). **Planned** (later milestones): output chunks 30 d, job/task run
history 90 d, facts history 90 d, spool age 24 h (agent-side). Audit and secret versions are
**not** swept (operator-configurable floor for audit; secrets until rotated). Sweeper actions
are themselves audited.

---

## 10. API, events, MCP

### 10.1 REST v1

Conventions (PRD R10): JSON, `/api/v1`, cursor pagination, structured
error bodies `{code, message, details}`.

#### Endpoint surface

| Method | Path | RBAC | Description |
|--------|------|------|-------------|
| POST   | `/api/v1/executions` | operator | Dispatch a command across a selector |
| GET    | `/api/v1/executions` | viewer | List executions (cursor paginated) |
| GET    | `/api/v1/executions/:id` | viewer | Get execution detail with runs |
| POST   | `/api/v1/executions/:id/cancel` | operator | Cancel a running execution |
| GET    | `/api/v1/executions/:id/output` | viewer | Get command output (stdout/stderr) |
| GET    | `/api/v1/hosts` | viewer | List connected hosts |
| GET    | `/api/v1/hosts/:id` | viewer | Get host detail (state, tags, roles) |
| GET    | `/api/v1/hosts/:id/facts` | viewer | Get latest fact set |
| PUT    | `/api/v1/hosts/:id/facts` | operator | Update facts (agent-side) |
| GET    | `/api/v1/groups` | viewer | List named selectors |
| POST   | `/api/v1/groups` | operator | Create a named selector |
| POST   | `/api/v1/agents/enrollment-tokens` | operator | Create one-time enrollment token |
| POST   | `/api/v1/agents/enroll` | — | Agent enrollment (token auth; accepts `csr` in TLS mode) |
| POST   | `/api/v1/agents/enroll` (TLS) | — | enroll returns `tls.{ca_cert,leaf_cert}` when the server has a CA |
| GET    | `/api/v1/tls/ca` | admin | Fetch the server root CA (PEM, `{"cert": ...}`) |
| POST   | `/api/v1/auth/login` | — | Local-user login → session bearer token (PRD Decision 6) |
| GET    | `/api/v1/auth/me` | any | Current session identity (username, role, expiry) |
| POST   | `/api/v1/auth/logout` | any | Invalidate this session token |
| POST   | `/api/v1/auth/password` | any | Change own password (re-issues a token) |
| GET    | `/api/v1/users` | admin | List local users (no password material) |
| POST   | `/api/v1/users` | admin | Create a user (username, password, role) |
| PATCH  | `/api/v1/users/:name` | admin | Change role / disable / reset password |
| DELETE | `/api/v1/users/:name` | admin | Delete a user (last-admin + self-delete guarded) |
| GET    | `/api/v1/files/stat` | viewer | File metadata (`stat` + sha256) |
| GET    | `/api/v1/files/list` | viewer | Directory listing |
| GET    | `/api/v1/files/download` | viewer | Chunked file download (resumable) |
| POST   | `/api/v1/files/upload` | operator | Chunked upload (base64 in JSON) |
| POST   | `/api/v1/files/edit` | operator | CAS edit (compare-and-swap on sha256) |
| POST   | `/api/v1/files/perm` | operator | Change file mode/ownership |
| POST   | `/api/v1/sessions` | operator | Open a PTY session |
| POST   | `/api/v1/sessions/:id/input` | operator | Send terminal input |
| POST   | `/api/v1/sessions/:id/resize` | operator | Resize terminal |
| POST   | `/api/v1/sessions/:id/close` | operator | Close a PTY session |
| GET    | `/api/v1/sessions` | viewer | Session list |
| GET    | `/api/v1/sessions/:id` | viewer | Session detail |
| GET    | `/api/v1/sessions/:id/replay` | viewer | Replay recorded PTY chunks |
| GET    | `/api/v1/audit` | viewer | Audit event log |
| GET    | `/api/v1/secrets` | operator | List secret metadata (**never values**) |
| GET    | `/api/v1/secrets/:name` | operator | Secret metadata (version, selector, agent count) |
| POST   | `/api/v1/secrets` | admin | Create `{name, value, selector, offline_ttl_s}` (value write-only) |
| POST   | `/api/v1/secrets/:name/rotate` | admin | New version `{value}`; revokes all prior versions |
| POST   | `/api/v1/secrets/:name/revoke` | admin | Revoke the current version |
| DELETE | `/api/v1/secrets/:name` | admin | Delete secret + all versions |
| GET    | `/api/v1/packages/updates?agent_id=` | viewer | CVE-ranked package updates (M3 §5.6) |
| POST   | `/api/v1/packages/apply` | operator | `{agent_id, packages[], dry_run}` → dry-run first (M3 §5.6) |
| GET    | `/api/v1/packages/actions` | viewer | List package actions (M3 §5.6) |
| GET    | `/api/v1/packages/actions/:id` | viewer | Package action detail (M3 §5.6) |
| GET    | `/api/v1/tasks` | viewer | List tasks (M3 §5.5) |
| POST   | `/api/v1/tasks` | operator | Create task `{name, steps[]}` (M3 §5.5) |
| GET    | `/api/v1/tasks/:id` | viewer | Task + latest steps (M3 §5.5) |
| POST   | `/api/v1/tasks/:id/run` | operator | `{agent_id}` → run task (M3 §5.5) |
| GET    | `/api/v1/tasks/runs` | viewer | List task runs (M3 §5.5) |
| GET    | `/api/v1/tasks/runs/:id` | viewer | Run detail + steps (M3 §5.5) |
| GET    | `/api/v1/playbooks` | viewer | List playbooks (M3 §5.5) |
| POST   | `/api/v1/playbooks` | operator | Create playbook `{name, task_id, selector}` (M3 §5.5) |
| GET    | `/api/v1/jobs` | viewer | List scheduled jobs (M3 §5.4) |
| POST   | `/api/v1/jobs` | operator | Create job `{name, task_id, cron, selector}` → resolves + pushes (M3 §5.4) |
| GET    | `/api/v1/jobs/:id` | viewer | Job detail (M3 §5.4) |
| PUT    | `/api/v1/jobs/:id` | operator | Update job → re-resolve + re-push (M3 §5.4) |
| DELETE | `/api/v1/jobs/:id` | operator | Delete job + unassign hosts (M3 §5.4) |
| GET    | `/api/v1/jobs/:id/runs` | viewer | Job run lineage (M3 §5.4) |
| POST   | `/api/v1/jobs/:id/run` | operator | `{agent_id}` → dispatch manual run (M3 §5.4) |
| GET    | `/api/v1/jobs/runs` | viewer | All job runs (M3 §5.4) |
| GET    | `/api/v1/hosts/:id/eol` | viewer | EOL state from os-release facts (M3 §6.3) |
| GET    | `/api/v1/external-data/status` | viewer | External data refresh status (M3 §6.3) |
| POST   | `/api/v1/external-data/refresh` | admin | Trigger external data refresh (M3 §6.3) |
| GET    | `/api/v1/files/stat?agent_id=&path=` | viewer | File metadata (M2) |
| GET    | `/api/v1/files/list?agent_id=&path=` | viewer | Directory listing (M2) |
| GET    | `/api/v1/files/download?agent_id=&path=` | viewer | File bytes, `Range: bytes=N-` resumable (M2) |
| POST   | `/api/v1/files/upload` | operator | `{agent_id, path, content_b64, mode}` → atomic (M2) |
| POST   | `/api/v1/files/edit` | operator | `{agent_id, path, expected_sha256, content_b64}` → CAS (M2) |
| POST   | `/api/v1/files/perm` | operator | `{agent_id, path, mode, owner, group}` (M2) |
| POST   | `/api/v1/sessions` | operator | `{agent_id, cmd, args, cols, rows, record}` → open PTY (M2) |
| POST   | `/api/v1/sessions/:id/input` | operator | `{data_b64}` terminal input (M2) |
| POST   | `/api/v1/sessions/:id/resize` | operator | `{cols, rows}` (M2) |
| POST   | `/api/v1/sessions/:id/close` | operator | End session (SIGHUP→SIGKILL, M2) |
| GET    | `/api/v1/sessions` | viewer | Recent sessions (M2) |
| GET    | `/api/v1/sessions/:id` | viewer | Session detail (M2) |
| GET    | `/api/v1/sessions/:id/replay` | viewer | Recorded PTY chunks (M2) |
| GET    | `/healthz` | — | Liveness |
| GET    | `/readyz` | — | Readiness (DB ping) |
| GET    | `/api/v1/events` | — | SSE event stream |

#### Planned additions (not implemented)

Surfaced by the web-UI reconciliation ([ui-guidelines §14](ui-guidelines.md)); each is a
prerequisite for a UI slice and none exist today.

| Method | Path | RBAC | Why |
|--------|------|------|-----|
| GET | `/api/v1/capabilities` | viewer | Boolean per subsystem, so the UI greys controls from data instead of hardcoded milestones. Complements the existing `503 <subsystem>_disabled` codes |
| GET | `/api/v1/hosts?selector=<sel>` | viewer | Selector **preview** before dispatch. Today resolution only happens inside `Control.Dispatch`, so the UI cannot show the resolved host set first |
| DELETE | `/api/v1/agents/{id}` | admin | `store.DeleteAgent` exists but has no HTTP route, so a decommissioned host can never leave the fleet; also makes the `revoked` agent state reachable |
| GET | `/api/v1/audit?agent_id=` | viewer | Per-host audit view; client-side filtering is adequate until log volume grows |
| GET | `/api/v1/services` | viewer | Fleet service health: aggregated view filtered by label/state/group | R18 |
| GET | `/api/v1/services?agent_id=&name=` | viewer | Single unit state + deps on a host | R18 |
| GET | `/api/v1/certificates` | viewer | Fleet cert inventory with expiry, chain status, labels | R20 |
| GET | `/api/v1/certificates?days_remaining_lt=30` | viewer | Near-expiry certs filter | R20 |
| GET | `/api/v1/configs` | viewer | Per-host config state: kind (haproxy/nginx), validity, topology, hash | R19 |
| GET | `/api/v1/configs?kind=haproxy&agent_id=` | viewer | Single host config detail with cross-host drift comparison | R19 |
| GET | `/api/v1/alerts` | viewer | Active + recently resolved alerts, filterable by kind/severity | R25 |
| GET | `/api/v1/alerts/:id` | viewer | Single alert detail | R25 |
| GET | `/api/v1/alerts/rules` | admin | Alert rule list | R25 |
| POST | `/api/v1/alerts/rules` | admin | Create alert rule | R25 |
| PUT | `/api/v1/alerts/rules/:id` | admin | Update alert rule | R25 |
| DELETE | `/api/v1/alerts/rules/:id` | admin | Delete alert rule | R25 |

Also required for S0: **static asset serving** — there is currently no `embed.FS`, no
`http.FileServer`, and no `web/` directory. Planned shape: Vite → `web/dist` → `go:embed` +
SPA fallback on the main listener.

#### Request / response shapes

**POST /api/v1/executions**
```json
{
  "selector": "role:prod",
  "cmd": "echo", "args": ["hi"],
  "env": {"KEY": "val"},
  "timeout_s": 120,
  "created_by": "admin"
}
```
Response: `{"execution_id": "exec_...", "runs": [{"run_id": "run_...", "agent_id": "ag_...", "delivered": true}], "errors": []}`

**POST /api/v1/agents/enroll** (TLS mode)
```json
{
  "token": "par_enr_...",
  "uuid": "...",
  "ed25519_pub": "...",
  "x25519_pub": "...",
  "agent_version": "...",
  "csr": "-----BEGIN CERTIFICATE REQUEST-----..."
}
```
Response: `{"agent_id": "ag_...", "uuid": "...", "tls": {"ca_cert": "...", "leaf_cert": "..."}}`
(`csr` is required in TLS mode — 400 without it; `tls` is omitted in plaintext mode.)

**GET /api/v1/hosts?limit=50&cursor=ag_abc** → `{"items": [...], "next_cursor": "ag_def"}`

**POST /api/v1/executions/:id/cancel** → `{"execution_id": "...", "cancelled": ["run_..."], "already_done": [...]}`

**GET /api/v1/executions/:id/output?stream=stdout|stderr** → `[{"run_id": "...", "agent_id": "...", "stdout": "...", "stderr": "..."}]`

**GET /api/v1/audit?kind=exec.dispatch&actor=admin&since=1700000000** → `{"items": [...], "next_cursor": "1700000100"}`

#### Error body
```json
{"code": "bad_request", "message": "selector is required", "details": null}
```
Stable codes: `bad_request`, `not_found`, `conflict`, `unauthorized`, `forbidden`, `internal_error`, `already_terminal`.

#### RBAC

Two credential kinds, checked in order: (1) a **local-user session token** from
`POST /api/v1/auth/login` (PRD Decision 6; argon2id + pepper in the `principals` table,
12 h in-memory session), (2) **static env tokens**
(`PARTOUT_TOKEN_ADMIN`, `PARTOUT_TOKEN_OPERATOR`, `PARTOUT_TOKEN_VIEWER`). Once any user
exists the single-user local mode is lifted and unauthenticated requests get 401; with no
users and no tokens the server still runs in single-user local mode (all requests allowed,
single log warning) and requests present as role **`admin`** — including for policy
`actor_roles` matching. First run bootstraps an `admin` user (`PARTOUT_ADMIN_PASSWORD`,
`--admin-password`, or a generated password in `<db dir>/admin_password.txt`). Login
failures are throttled per username (exponential backoff, 429 `throttled`), and unknown
usernames pay a decoy argon2 verification so neither messages nor timing disclose which
accounts exist.

### 10.2 SSE

One broker, fan-out per browser (PRD R10). Event types: `output.chunk`, `execution.state`,
`session.data`, `job.run`, `task.run`, `host.state`, `approval.request`, `provision.step`,
`audit.event`, `alert.*`, `extern.refresh`. Each client gets a buffered channel; slow consumers
are dropped and re-subscribe (SSE retry) — never block the broker.

### 10.3 MCP (PRD §10.3)

- Transports: stdio (local assistants) + Streamable HTTP (remote, OAuth2 PKCE).
- Read tools from the observe layer + new: `list_hosts`, `get_host_facts`,
  `list_groups`, `list_updates`, `list_jobs`, `list_tasks`, `get_audit`, `list_sessions`,
  `get_session`.
- Write tools (each = full control-plane pipeline: authn → RBAC → selector → policy → approval
  → audit → dispatch): `run_command`, `upload_file`, `download_file`, `run_job`,
  `run_playbook`, `apply_updates`, `create_secret`, `request_approval`.
- No PTY tool (PRD). Refusals use the structured decision-table shape (rule id + what would
  satisfy it).

---

## 11. Frontend

Stack (PRD R12): Vue 3 + TS + Pinia + Tailwind, uPlot for metrics, xterm.js for PTY,
PWA. Page map = PRD §11. Implementation notes:

- One SSE subscription per page (or one app-wide, filtered) — no polling anywhere.
- **Execute** page: selector input with live resolution preview (resolves on type, shows the
  concrete host set before dispatch); per-host live output panes; cancel/timeout controls.
- **Sessions**: xterm.js over SSE output + `POST /sessions/{id}/input` (PRD §5.2); replay from
  stored recordings.
- **Tasks & Playbooks**: step editor emits the JSON task model directly (no YAML in the UI);
  `when` editor is a form over the constrained grammar.
- **Audit**: filterable table, full-fidelity expansion for privileged commands (Decision 8).
- Embedded as `embed.FS`; no separate build server; served on the main listener.
- **Capability-gated UI**: one capability probe (`GET /api/v1/capabilities`) drives which nav
  items and controls are enabled; not-yet-built surfaces render disabled with the milestone
  named, and role-gated controls are visually distinct from not-yet-available ones (see
  [ui-guidelines §4](ui-guidelines.md)).
- **Selector preview**: the Execute page resolves and displays the concrete host set before
  dispatch, via the planned selector filter on `/api/v1/hosts`.

Layout, tokens, component inventory, state vocabulary, and the S0–S5 slicing live in
[ui-guidelines.md](ui-guidelines.md); `docs/ui-design.png` is the north-star mockup.

---

## 12. Security walkthroughs

### 12.1 Enrollment

```
operator: POST /agents/enrollment-tokens {ttl} → par_enr_… (shown once; sha256+mask at rest)
          [TLS] ship ca.crt to the host (scp / ctl ca)
agent:    generates ed25519 + x25519, uuid
          [TLS] generates local ECDSA P-256 key + CSR
          RegisterAgent{token, pubkeys, uuid, initial_facts, csr}
server:   verifies token (one-time, unexpired) → insert agent row
          [TLS] signs the CSR with the root CA → returns {ca_cert, leaf_cert}
          → return agent_id
agent:    writes identity.json (0600); [TLS] persists ca.crt/agent.crt/key.pem (0600)
          → open stream → mTLS + handshake (§3.1, §3.6) → connected
```

### 12.2 Privileged command (end-to-end)

```
UI:     command with elevation profile "pkgadmin" (pattern-scoped)
server: RBAC ok → selector ok → policy: match "prod-db-elevation"?
        → require_approval → approval_request created → operator approves (exact payload)
        → audit rows (execution + runs, queued)
        → CommandEnvelope + signed Decision{bundle_v17, allow, rules:[…]}
agent:  verify Decision signature (server pubkey) → bundle_version == cached (17) ✓
        re-evaluate rules locally over (host tags, action, elevation, command) ✓
        command matches elevation profile "pkgadmin" pattern ✓ (host --elevate=sudoers)
        exec: sudo -n -u root -- apt-get install …  (full command recorded, no redaction)
        stream output chunks → CommandResult{exit 0}
server: persist, SSE broadcast, audit rows finalized (approver + executor principals)
```

Any single check failing → structured deny; nothing executes.

### 12.3 Secret usage in a task step

```
task step declares secret_ref "db_password" v3, mode=env
server: resolve binding (selector includes host) → SecretMaterialize{v3, ct(agent_pub)}
agent:  X25519-decrypt in memory → inject env for the step's process only
        → spool contains only ciphertext → wipe after step → audit records v3 used
offline (server unreachable): default → step fails closed "secret unavailable"
        (offline_ttl>0: bounded encrypted cache may satisfy, still versioned + audited)
```

### 12.4 Host provisioning (end-to-end)

```
operator (CLI):  `partout ctl provision new --host web01`
server:          RBAC: admin ✓ → policy: action=provision, target=web01 → allow
                 (or require_approval) → audit provision.requested
step 1 connect:  ssh-keyscan -t ed25519,ecdsa,rsa web01   (trusts nothing)
                 → host key not in <PARTOUT_SSH_DIR>/known_hosts → run → key_confirm (SSE)
operator (CLI):  `provision get <id>` shows fingerprint → confirm via
                 `provision key <id> confirm`   (duplicate confirm → 409)
server:          fingerprint hashed → appended to <PARTOUT_SSH_DIR>/known_hosts
                 → run → confirming
step 2 preflight: ssh web01: os-release, arch, systemctl?, whoami + sudo -n true,
                  free disk, curl/wget <server>/healthz (host→server egress), existing
                  partout? → plan; reach=no → fail with firewall remediation
step 3 transfer: scp /usr/local/bin/partout web01:/tmp/partout-<sha12>
step 4 install:  ssh web01 'sudo -n bash -s': verify sha256 → install -m0755
                  /usr/local/bin/partout → useradd partout → agent dir (0750) →
                  agent.env (0640: PARTOUT_SERVER + PARTOUT_TOKEN + labels) → unit →
                  daemon-reload → systemctl enable --now partout-agent
step 5 enroll:   agent (on host) generates keypair → RegisterAgent{par_enr_…}
                  → stream handshake → connected; run → connected;
                  audit: provision.completed + per-step rows (principal, alias, key file
                  name, host, duration)
any failure:     run → failed with step + bounded stderr excerpt; token (one-time,
                  short-TTL) expires unused; partial install idempotent under re-run
```

Any single check failing (RBAC, policy, fingerprint deny, sudo probe, sha256, enrollment
window) stops the run; nothing executes past the failed step.

---

## 13. Performance & capacity (targets)

| Dimension | Target **(proposed)** |
|---|---|
| Agents per server | 500 streams on a 2 vCPU / 4 GB box (streams are idle-cheap; heartbeat + facts are small) |
| SSE clients per server | 100 concurrent browsers, fan-out via buffered channels |
| Output throughput | 10 MB/s sustained per execution across hosts; chunks to disk above 1 MiB/run |
| DB | SQLite WAL fine to ~10k hosts of audit+runs before Postgres is advisable |
| Facts load | hourly refresh of 500 hosts ≈ negligible (batched upserts) |
| Dispatch fan-out | 500-host execution enqueued in <1 s (per-agent ordered queues) |

Scaling path beyond one server (multi-region, sharding) is a non-goal (PRD §13: no self-HA);
the operator's cluster manager owns availability, and the design keeps the server stateless
*except* the data dir + secret key (ops doc §4 covers backups/restore).

---

## 14. Testing strategy

- **Unit**: selector grammar; policy evaluator (exhaustive precedence table); `when` AST parser
  + evaluator; spool mem/disk/drop-oldest transitions; HKDF/AEAD helpers; cron resolution.
- **Integration**: in-process server + **fake agent** over a real gRPC transport (test
  listener) — handshake, reconnect, spool replay, ack/timeout, policy mismatch deny;
  **dialect parity**: full migration + repository suite run against SQLite **and** Postgres.
- **Live SSH** (`//go:build live`, `PARTOUT_LIVE_SSH=1`): `internal/sshutil` runs against a
  **real sshd** (opt-in; manual CI job). This exists because fake ssh binaries implement
  ssh's *intended* semantics and therefore cannot catch real-world divergence — notably
  that OpenSSH resolves `~/.ssh` from the passwd database, not `$HOME`, which once made
  `PARTOUT_SSH_DIR` silently non-functional.
- **Provisioning** (implemented): fake-fleet unit tests (fingerprint gate, non-systemd
  handoff, unreachable-server preflight, duplicate/racing confirm, restart-while-paused) +
  a REST integration test through the live server. *Still to add:* byte-level assertion that
  no SSH private-key material appears in logs/DB, and a multi-machine E2E fleet.
- **Security properties** (regression-tested): no write endpoint reachable without a
  principal; denied action never produces a `CommandEnvelope`; privileged audit row always
  full-fidelity; provisioning run unreachable by non-admins (RBAC admin-only), and an
  unknown host key blocks the run until confirmation.
- **E2E** (`test/e2e`, docker compose): server + 2 container agents on real distros;
  scenarios: enroll → facts <10 s → exec fan-out → cancel/timeout → task with `when` skip →
  job survives server restart → apply-updates dry-run journal → revoke cascade. Runs on CI for
  amd64; arm64 smoke.
- **Load**: scripted 500 fake agents (heartbeat + facts + periodic exec) against the compose
  server; asserts §13 targets.

---

## 15. Proposed defaults needing sign-off

Everything else in this document follows PRD-locked decisions. These are new:

| # | Item | Proposal |
|---|---|---|
| A1 | Listener | **Implemented in v0.1**: single port `:8443` serving REST/SSE + gRPC (h2); UI deferred, MCP proposed. Optional split gRPC port still proposed. |
| A2 | Transport keys | Add X25519 transport keypair alongside Ed25519 identity (agent spool encryption) |
| A3 | Output chunk size | 64 KiB |
| A4 | Stream backoff | 1 s → 60 s cap, jittered |
| A5 | Dispatch TTL (offline agents) | 15 min |
| A6 | Policy default | **v1 (M1)**: default-allow (deny-list) for exec. Default-deny writes deferred to M2/M3 with the action-class taxonomy; `require_approval` acts as deny until M4. |
| A7 | Approval TTL | 1 h |
| A8 | Policy bundle staleness (agent jobs) | 48 h |
| A9 | Reboot continuation marker validity | 10 min |
| A10 | Agent default `--elevate` | `none` |
| A11 | Cancel ladder | SIGTERM → 5 s → SIGKILL |
| A12 | Selector grammar | AND-only predicates (`all`, `host:`, `tag:`, `role:`, `group:`) |
| A13 | Health endpoints | `/healthz`, `/readyz` |
| A14 | Retention sweeper | hourly; audited |
| A15 | Capacity targets | §13 table |
| A16 | Provisioning SSH | system `ssh`/`scp`; `BatchMode=yes`, `ConnectTimeout=10s`, `ServerAliveInterval=15`, `StrictHostKeyChecking=yes` after fingerprint gate; `PARTOUT_SSH_DIR` (default `$HOME/.ssh`) passed explicitly via `-F`/`UserKnownHostsFile`/`IdentityFile` (a `HOME` override is ignored by OpenSSH) | §3.5 |
| A17 | Preflight checks | os-release, arch, systemd, `sudo -n true`, disk, host→server `/healthz`, existing install; remediation text on failure | §3.5 |
| A18 | Install/update layout | `/usr/local/bin/partout`, `partout` user, `/etc/partout/agent.env` 0640, unit per deployment §3.2; agent state (`identity.json`, `tls/`, `spool/`) untouched unless `fresh` | §3.5 |
| A19 | Manual handoff triggers | unreachable, non-systemd init, Docker-host, air-gapped; prints binary + one-line install with one-time token | §3.5 |