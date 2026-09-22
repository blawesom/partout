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
| **M1 — First write path** | 🟡 In progress | Command execution + streamed output + audit + RBAC + `partout ctl` CLI + systemd deploy + **TLS/mTLS bootstrap**. Missing: policy deny-list, host provisioning |
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
- ✅ `internal/api` — REST v1: 16 API routes (15 JSON + SSE), RBAC (viewer/operator/admin), structured errors, cursor pagination, `/healthz` + `/readyz`
- ✅ `internal/control` — dispatch orchestration, cancel, finalize, audit
- ✅ `internal/id` — opaque TEXT keys (`prefix_` + 12 hex)
- ✅ 81 tests, race detector clean

### M1 — First write path (in progress)

Done:
- ✅ Ad-hoc command execution with streamed output (stdout/stderr)
- ✅ Command cancellation (server → agent CANCEL envelope, live process kill)
- ✅ Full audit log (append-only, filterable, REST-exportable)
- ✅ RBAC bearer tokens (`PARTOUT_TOKEN_ADMIN`/`OPERATOR`/`VIEWER`), single-user local mode
- ✅ Run lifecycle: `queued → delivered → running → terminal` (succeeded/failed/timed_out/cancelled/interrupted)
- ✅ Execution aggregate: `succeeded/failed/partial/cancelled`
- ✅ Operator CLI: `partout ctl` (enroll-token, hosts, run, exec, audit, ca; `--ca-file` for HTTPS)
- ✅ Deploy artifacts: `deploy/systemd/` (server + agent units, env templates, install README)
- ✅ Server restart resilience: agents marked `disconnected` at startup, flip back on reconnect
- ✅ Agent restart resilience: identity persisted, no re-enrollment needed
- ✅ **TLS/mTLS bootstrap** (see below): local root CA on first run, CA-signed agent leaves via CSR at enrollment, mTLS on the gRPC stream, REST over HTTPS

Remaining:
- [ ] Policy deny-list (agent-side guardrail recheck before execution)
- [ ] Host provisioning via fleet SSH (architecture §3.5, §5.8)
- [ ] Postgres backend (second store implementation)
- [ ] Offline spool (16 MB mem / 128 MB disk / 24h TTL, replay on reconnect)
- [ ] Embedded mode: wire local agent to co-located server
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
5. **Finish M1**: policy deny-list, host provisioning (fleet SSH), Postgres backend, offline spool
6. **M2**: files & sessions
7. **Web UI** (deferred V1 phase)

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