# Partout

**Remote host management control plane** — one Go binary to discover, execute against,
configure, patch, and orchestrate work across Linux hosts, with a web UI and an MCP server
for AI assistants.

| Doc | What it covers | Status |
|---|---|---|
| [PRD.md](PRD.md) | Product spec, positioning, capabilities, decisions | v0.3 (decisions locked) |
| [docs/architecture.md](docs/architecture.md) | Module layout, stream protocol, state machines, control plane, storage, testing | **Draft v0.1** (v0.2 planned) |
| [docs/deployment.md](docs/deployment.md) | Topology, install paths (systemd/Docker/compose/cloud-init/Helm), config reference, recipes | Draft v0.1 |
| [docs/operations.md](docs/operations.md) | Day-2 ops: backups, upgrades, incident runbooks, troubleshooting, compliance, go-live | Draft v0.1 |

## Positioning

> **Partout** asks "how do I make it so, and prove it?" — and its purpose is to touch your
> hosts, safely and auditably.

It ships a single binary that embeds the observe layer (containers, endpoints, heartbeats,
certificates, resources, alerts) and adds the write/control path: executions, files, sessions,
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
| **M1 — First write path** | 🟡 In progress | Command execution + streamed output + audit + RBAC + `partout ctl` CLI + systemd deploy + **TLS/mTLS bootstrap** + **policy deny-list** + **host provisioning (fleet SSH)**. Missing: Postgres, offline spool |
| **M2 — Files & sessions** | ⬜ Not started | — |
| **M3 — Automation** | ⬜ Not started | — |
| **M4 — Governance** | ⬜ Not started | — |
| **M5 — Distribution & polish** | ⬜ Not started | — |

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

### M1 — First write path (in progress)

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
- ✅ **Embedded mode**: `--mode=embedded` runs the server + a co-located local agent in one process. The agent enrolls over loopback with a locally created one-time token (first boot only), reconnects with its persisted identity on restart, and works over plaintext or TLS (mTLS).

Remaining:
- [ ] Postgres backend (second store implementation)
- [ ] Offline spool (16 MB mem / 128 MB disk / 24h TTL, replay on reconnect)
- [ ] TLS cert rotation via the stream (v1.x) + optional revocation list

### Not started

- M2: file browser, transfers, PTY sessions, recording
- M3: jobs, tasks/playbooks, packages, secrets, external data refresh
- M4: approvals, full policy engine, MCP write tools
- M5: installers, cloud-init, Helm, status page
- Web UI (Vue 3 + TS + Pinia) — explicitly deferred to later V1 phase

## Next steps

1. ~~Review docs; sign off the proposed defaults (architecture §15).~~ ✅ Done
2. ~~Resolve the repo rename `hiersoir` → `partout` (PRD Decision 10).~~ ✅ Done
3. ~~Scaffold the Go module + `deploy/` artifacts per architecture §1.~~ ✅ Done
4. ~~Build milestone M0 (spine).~~ ✅ Done
5. ~~**Finish M1**: policy deny-list~~ ✅ Done (v0.2.0)
6. ~~**Finish M1**: host provisioning (fleet SSH)~~ ✅ Done (see M1 Done list)
7. **Finish M1**: Postgres backend, offline spool
8. **M2**: files & sessions
9. **Web UI** (deferred V1 phase)

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
