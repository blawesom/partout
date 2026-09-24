# Partout — Architecture

**Status:** Draft v0.1 (implementation-level design)
**Companion docs:** `PRD.md` (product), `docs/deployment.md`, `docs/operations.md`

This document is the implementation-level design. The PRD is the source of truth for *what* and
*why*; this document defines *how*: module layout, the stream protocol, state machines, the
policy engine's shape, storage details, and failure semantics. Items the PRD does not lock down
are marked **(proposed)** and need sign-off.

---

## 1. Repository & binary layout

Single Go module, single binary, three modes (`--mode=server|agent|embedded`), Vue 3 frontend
embedded via `embed.FS` (PRD R1). Module path: `github.com/<org>/partout` (final org pending the
repo rename from `hiersoir`).

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
│   │   ├── observe/        # facts ingestion, containers, endpoints, certs, alerts
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
- Distribution: `SecretMaterialize{ciphertext_to_agent, version}` over the authenticated
  (TLS) stream; ciphertext additionally X25519-encrypted to the agent's transport key so the
  on-disk spool never holds cleartext. Agent decrypts in memory, materializes only for the
  lifetime of the declaring task/command, and wipes on completion.
- **Offline**: default fail-closed ("secret unavailable", recorded). Per-secret `offline_ttl`
  (default 0) allows a bounded encrypted cache agent-side.
- Rotation: new version → prior binding invalidated; audit records which version each run used.

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
  `service.running('ssh')`), combined with `and`/`or`. Parsed to a tiny AST; anything else is
  rejected at task validation time.
- **pkg** — apt/dnf/apk backends selected from OS identity (R13); `list-updates` ranks by
  correlated CVE severity (server-computed hints in the request); `apply-updates` always
  dry-runs first and writes a per-host before/after journal (PRD §5.6).
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

## 7. Observe layer (elided)

Facts ingestion, containers, endpoints, heartbeats, certificates, resources, and the alert
engine are defined by PRD §6, R10/R13 and are not re-derived here. The only
architectural coupling to the control plane:

- **facts feed `when` guards** — the agent's fact cache is the single source for task guards.
- **EOL state feeds patch gating** — `extern` publishes per-host `supported | ending_soon | ended`
  from the EOL cache; `pkg` and policy rules may require approval on `ended` hosts (PRD §5.6).
- **alerts fan out on the same SSE broker** as command output and audit events.

---

## 8. External data service (PRD §6.3)

```
startup ──► refresh ◄── daily timer
             │                ▲
             ▼                └── POST /api/v1/extern/refresh (manual)
        fetchers (parallel, per-source timeout 30 s):
          • endoflife.date          → eol_cache
          • distro security trackers→ vuln_cache (distro CVE/USN/errata entries)
          • OSV.dev / GHSA          → vuln_cache (cross-distro, deduped by CVE id)
             │
             ▼
   all-or-nothing: every fetch must succeed AND parse → atomic cache replace
   any failure    → previous cache untouched, one log line, retry next cadence
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
| `jobs`, `job_runs` | resolved per-host schedule stored with job; run lineage |
| `tasks`, `task_versions`, `playbooks`, `task_runs`, `task_run_steps` | versioned; step state per §4 |
| `package_actions` | list/apply/dry-run + per-host before/after journal |
| `eol_cache`, `vuln_cache` | external data (§8) |
| `secrets`, `secret_versions`, `secret_bindings` | values encrypted at rest (HKDF-derived keys) |
| `audit_events` | append-only, all taxonomy kinds; no update/delete paths |
| `policies`, `approval_requests`, `approvals` | control plane |
| `principals` | local users (v1), roles `viewer|operator|admin`, hash+pepper of password |
| `provision_runs` | per-run state, host alias, mode (`fresh` or `join`, default `fresh`), per-step rows (kind, ts, bounded output excerpt), linked `agent_id` once enrolled; `key_line`/`token_hash` stored but never serialized; retention 90 d (audit keeps `provision` events) |

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

Bearer tokens from env (`PARTOUT_TOKEN_ADMIN`, `PARTOUT_TOKEN_OPERATOR`, `PARTOUT_TOKEN_VIEWER`).
No tokens → single-user local mode (all requests allowed, single log warning).

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