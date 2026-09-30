# Partout — Deployment

**Status:** v0.8.0 — reflects the current implementation (M0–M8.1 complete: Web UI,
M4 approvals + MCP + OAuth2, M6.1 alert rule kinds, v0.7.x in-stream mTLS rotation /
offline down-queue dispatch / provisioning fresh+join modes / `partout --version`,
and **M8.1 signed fleet updates**: release store + Ed25519 signatures, agent
self-swap with auto-rollback, canary→wave rollout orchestration, supervised server
update via `partout selftest` + `scripts/update-server.sh`, and the one-command
`partout update`). Sections marked *proposed* describe planned work that is not yet
wired into the binary.
**Companion docs:** `PRD.md`, `docs/architecture.md`, `docs/operations.md`
**PRD anchor:** R16 (install paths), R15 (env config), R9 (storage engines).

**What v0.1 ships:** single Go binary (server/agent/embedded modes), single listener
(REST v1 + SSE + gRPC demuxed by content-type/protocol), SQLite storage, command
execution + cancellation + audit, RBAC bearer tokens, TLS/mTLS bootstrap
(`PARTOUT_TLS=on`), `partout ctl` CLI, systemd units (`deploy/systemd/`).

**What v0.2 adds (M1):** the policy deny-list engine — rule CRUD at
`/api/v1/policies` (`partout ctl policy list|create|delete`), per-host evaluation at
dispatch (deny / `require_approval`→deny / allow), signed `Decision` on every command,
agent-side re-check (`internal/agent/guardrail`), and audit rows (`policy.create`,
`policy.delete`, `policy.deny`). No new flags or env vars; the server generates a
`server_identity.key` under `<db-dir>/identity/` on first run.
**What v0.3 adds (M1):** host provisioning over fleet SSH (PRD R17) —
`partout ctl provision new --host user@host` drives a server-side 5-step run
(connect + no-silent-TOFU `key_confirm` gate → preflight → transfer → install →
wait-enroll). The server spawns the system `ssh`/`scp`/`ssh-keyscan`/`ssh-keygen`.
`PARTOUT_SSH_DIR` (default the service user's `$HOME/.ssh`) selects the SSH dir and is
passed to the binaries **explicitly** (`-F`, `UserKnownHostsFile`, `IdentityFile`); a
non-default dir replaces the per-user `ssh_config`. `PARTOUT_SERVER_HOST` sets the address
written into the new agent's `agent.env`. Preflight also probes host→server reachability
(`/healthz`) so a firewall fails fast.
New env vars: `PARTOUT_SSH_DIR`, `PARTOUT_SERVER_HOST`.
**What v0.3 also ships (M2–M3, M4 in progress):** offline spool (R5), files &
sessions (M2), secrets (C7), external data refresh (§6.3), package management (C6),
tasks/playbooks (C5), scheduled jobs (C4), and local user auth (C9, M4).
**What v0.4 adds (M5, done):** observe layer fact collectors — systemd
service facts (R18), webservice config facts (R19, `haproxy`/`nginx`), TLS
certificate facts (R20, expiry/chain/SAN/OCSP). Agent-side collectors upload
structured JSON via a new `OBSERVE_FACTS` gRPC envelope. Server-side
`observe/facts.go` upserts into `host_facts` JSON blob. Read-only REST endpoints
(`/services`, `/certificates`, `/configs`) serve the data (MCP read tools ship with the
R11 MCP server). No alerting yet (alert engine is M6). See `PRD.md` §14 for the
M5–M8 milestone breakdown.
**What v0.6 adds (M4: approvals engine, PRD §5.8):** a `require_approval` policy
match now **parks the action** instead of failing closed — exec runs go
`awaiting_approval`, package apply returns `202 {approval_required, approval_id}` — and
creates an `approval_requests` row carrying the exact payload, actor, matched rules, and
a TTL (`PARTOUT_APPROVAL_TTL_S`, default 1 h). Admins act via `GET/POST
/api/v1/approvals[/{id}[/approve|deny]]`; approve signs a fresh `EffectAllow` decision
whose signature covers the approval id and re-dispatches the stored payload (the agent
guardrail honors approved decisions; a local hard deny still wins). Expired requests
can never be retroactively honored. **Every policy-gated surface has the
approval path** (exec, pkg.apply, files upload/edit/perm — staged bodies live
in `<dbdir>/filestaging/` 0600 until decided — sessions, tasks, jobs manual
RunNow); secrets are a server-side vault (RBAC-only, no host action class),
and any build without the approvals engine wired still fails closed as deny.
New env var: `PARTOUT_APPROVAL_TTL_S`.
**What v0.6 also adds (M4: MCP server + OAuth2, R11/A20):** a JSON-RPC 2.0
tool surface over stdio (`partout --mode=mcp`, §3.9) and Streamable HTTP
(`POST /mcp`) — 26 read/write tools that forward the caller's credential to
the same REST router the UI/CLI use, so RBAC/policy/audit are the control
plane's (no duplicated write path). **OAuth2 (PKCE)** for the HTTP transport:
admin-registered MCP clients (`POST /api/v1/mcp/clients`),
`POST /oauth2/authorize` (owner's existing bearer) → one-time code bound to
an S256 challenge, `POST /oauth2/token` → 1-h access token (hashed at rest)
valid as a bearer on REST + MCP. No new server env vars; the stdio mode takes
`--server` + `--token` (+ `--ca-file` for TLS). Browser-login grant + refresh
tokens are post-v1 (A20).

**What v0.6.5 adds (M6: alert engine, PRD R23/R25):** server-side threshold
rules over the observe facts — `service_failed` (delay window
`service_failed_minutes`), `cert_expiring` (`cert_days_remaining`),
`config_invalid` (selector + severity per rule; CRUD on
`/api/v1/alerts/rules`, list on `GET /api/v1/alerts`). The engine ticks every
`PARTOUT_ALERT_TICK_S` (default 30 s), dedups per (rule, host, subject),
transitions firing→resolved on recovery, and fans out `alert.firing` /
`alert.resolved` SSE events. `service_restarting` is deferred to M6.1 (the
agent doesn't collect a restart counter yet; A21). **Web UI**: the Alerts page
now renders live firing alerts (the rule-management UI is M7).
New env var: `PARTOUT_ALERT_TICK_S`.

**Not yet wired:** elevation (`PARTOUT_ELEVATE`/`PARTOUT_ROOT` are hardcoded
`none`/`/`), the Postgres backend, the OAuth2 browser-login grant + refresh
tokens (post-v1, A20), MCP session-read tools, and the M6.1 alert kinds
(`service_restarting` et al.; A21).
**Web UI is shipped** (v0.5): open the main
listener in a browser and log in — the fleet, execute, audit, and M1–M6 data pages (including
Observe · Services/Certificates/Configs/Alerts) are live. Remaining UI scope:
alert rule management and M7 cross-links/task-actions.

---

## 1. Topology & network

### 1.1 The only topology

One **server** (central) + N **agents** (one per managed host) + optional **embedded**
mode (server + agent in one process on a single self-managed host). No control nodes
beyond the server, no queue, no Redis (PRD principle 2). The server is **not** HA'd by
Partout — the operator's cluster manager owns availability (PRD §13).

### 1.2 Ports & listener

| What | Default | Notes |
|---|---|---|
| Main listener | `:8443` (`PARTOUT_PORT`) | Single Go http server serving REST v1 + SSE (HTTP/1.1) **and** gRPC (h2c/h2, by `content-type: application/grpc`) |
| Split gRPC listener | *(proposed — `PARTOUT_GRPC_ADDR`, not wired)* | Optional separate port if the operator wants gRPC on its own LB/TLS policy |
| Agent → server | outbound only | Agent needs only **egress** to the server (gRPC + REST enrollment); never inbound |

- TLS: server-native via a **local root-CA bootstrap** — `PARTOUT_TLS=on` (or `--tls on`)
  generates a root CA + server leaf cert under `<db dir>/tls/` on first run. Plaintext
  `h2c` is the default when TLS is off (no separate H2C switch). The older
  `PARTOUT_TLS_CERT`/`PARTOUT_TLS_KEY` vars are **not parsed** — use the CA
  bootstrap.
- The agent connects to one address: `PARTOUT_SERVER=host:port` (scheme optional; a
  `http(s)://` prefix is accepted and stripped). In TLS mode
  `PARTOUT_TLS_CA=/path/to/ca.crt` (or `--ca-file`) enables HTTPS enrollment + mTLS.

### 1.3 Reverse proxy routing

Single TLS edge, route by content-type (Caddy shown; nginx equivalent in §3.5):

```caddy
partout.example.com {
    reverse_proxy 127.0.0.1:8443
    header_up X-Forwarded-Proto {scheme}
}
```

(No path rules needed: REST/SSE/gRPC all live on the same port; the mux demuxes by
content-type. The split gRPC port is *proposed* — if added, add a second site or
`handle` block on `content_type application/grpc` → `127.0.0.1:9443`.)

**Behind HAProxy** (validated on a live multi-SNI edge, 2026-09-29):
`deploy/haproxy/partout.cfg` ships a working snippet. The two gotchas that cost
time there: (1) `timeout client` is a **frontend** directive — HAProxy silently
ignores it on a `backend`, and the 1m default drops idle SSE/PTY streams, so set
1h on the frontend; (2) a second domain on the same :443 is just another `crt`
entry on the bind line. Bind the server loopback-only behind the edge:
`PARTOUT_ADDR=127.0.0.1`.

---

## 2. Artifacts

- **One static Go binary** `partout` (CGO-free; `go build` with `CGO_ENABLED=0`).
  The Web frontend is embedded (`embed.FS`) and served by the server — no
  separate artifact, no Node build step.
- **Release matrix** (current): GitHub Releases ship prebuilt
  `partout_<version>_linux_{amd64,arm64}.tar.gz` + `SHA-256SUMS` (layout:
  `partout_linux_<arch>/partout`). Version is injected at build time:
  `-ldflags "-X …/internal/agent/facts.Version=<version>"`.
- **M8.1 signed release repo** (for `partout update`): separate from the
  GitHub tarballs — `partout-<version>-<arch>-{server,agent}` binaries +
  `.sig` (Ed25519 over `version|arch|kind|sha256`) under `<repo>/<version>/`
  plus a `<repo>/latest` text file. See §2.1.
- **Images are distro-agnostic**: no OS packages required on hosts (agent is the binary).

### 2.1 Upgrading from v0.7.x (manual, one-time)

The signed-update feature is forward, not backward, compatible: a v0.7.x
host cannot run `partout update` (it has no release repo, no signature
checks, no `/api/v1/version`). The hop to v0.8.0 is a **manual binary swap**;
every release after that is the one-command.

**Per host:**

```sh
# 1. Get + verify (GitHub auth + checksum are the trust path for this hop;
#    the tarballs are not Ed25519-signed releases)
curl -LO https://github.com/blawesom/partout/releases/download/v0.8.0/partout_0.8.0_linux_amd64.tar.gz
curl -LO https://github.com/blawesom/partout/releases/download/v0.8.0/SHA-256SUMS
sha256sum -c <(grep amd64 SHA-256SUMS)
tar xzf partout_0.8.0_linux_amd64.tar.gz

# 2. Server (keep N-1 + optional DB snapshot)
cp /usr/local/bin/partout /usr/local/bin/partout.prev
sqlite3 /var/lib/partout/partout.db "VACUUM INTO '/var/lib/partout/pre-upgrade.db'"   # optional
install -m 0755 partout_linux_amd64/partout /usr/local/bin/partout
systemctl restart partout-server
curl -fsS localhost:8443/healthz && curl -fsS localhost:8443/readyz

# 3. Agent (skip in embedded mode — step 2 already replaced it)
install -m 0755 partout_linux_amd64/partout /usr/local/bin/partout
systemctl restart partout-agent
```

- **Rollback**: restore `partout.prev` and restart. Schema migrations are
  additive (v15→v16 adds tables only) and v0.7.x is forward-compatible with
  newer schemas, so the DB does not need restoring.
- **Guard (recommended)**: point the agent unit's `ExecStart` at
  `deploy/systemd/partout-update-guard.sh` (see `deploy/systemd/README.md`) so
  future one-command updates get crashloop rollback; set `PARTOUT_RELEASE_KEY`
  in the agent env from the start.

**Enabling the one-command afterwards** (operator side): `partout update`
fetches from `PARTOUT_RELEASE_REPO` and refuses anything not signed with
`PARTOUT_RELEASE_KEY` — the GitHub tarballs are *not* signed releases, so run
the one-command only after you have published signed artifacts for the next
release (build → `partout ctl update sign` → publish under `<repo>/<version>/`
+ `latest`). Then, on the upgraded server:

```sh
export PARTOUT_RELEASE_KEY=<pub> PARTOUT_RELEASE_REPO=https://releases.example.com/partout
partout update --check   # report-only first
partout update           # server + fleet, from here on
```

**Beta shortcut — unsigned fleet updates:** while `PARTOUT_ALLOW_UNSIGNED_RELEASES`
is on (**the default during beta**; GA flips it to false), the in-server release
store accepts releases **without a signature** (`partout ctl update upload`
without `--signature`, or the Updates page — the form's signature field is
optional). Keyless agents apply an unsigned release on the sha256 integrity
check alone; an agent with `PARTOUT_RELEASE_KEY` provisioned stays
strict-signed and refuses unsigned releases. The UI labels such releases
`unsigned (beta)` and the audit trail records `unsigned: true` on
`update.apply`/`update.dispatch`.

### 2.2 First boot: the fleet-management preset

A fresh server does not start as a blank slate. On first boot (no principals
in the DB) Partout seeds a **preset** of sensible defaults so the fleet is
usable and guarded immediately. Every seeded row is named `default-*` and is
visible + editable/deletable in the UI (Policies and Alerts) — the preset is a
starting point, not a lock-in.

**Policies** (all hosts, `exec`):

| Rule | Effect | Catches |
|---|---|---|
| `default-deny-rm-rf-root` | deny | `rm -rf /`, `sudo rm -r -f /`, `--no-preserve-root` — not `rm -rf /tmp` |
| `default-deny-disk-wipe` | deny | `dd of=/dev/…`, `mkfs*`, `wipefs`, `shred /dev/…` |
| `default-deny-auth-file-tamper` | deny | shell-redirect writes to `/etc/passwd`, `/etc/shadow`, `/etc/sudoers` |
| `default-require-approval-reboot` | require_approval | `reboot`, `shutdown`, `halt`, `poweroff` (incl. `systemctl reboot`) |

**Alert rules** (all hosts, engine-default thresholds):
`default-service-failed` (critical), `default-service-restarting` (warning),
`default-cert-expiring` 30 d (warning), `default-config-invalid` (critical),
`default-config-drift` (info), `default-update-run` (warning — stuck rollout).

**Re-apply after a restore** (a pre-preset backup has no `default-*` rows, and
first-boot does not re-fire because the admin user already exists):

```sh
partout ctl preset show     # which defaults are present / missing
partout ctl preset apply    # idempotent — creates only what is missing
```

`apply` never touches user rows: it creates only missing defaults, so an
operator who edited or deleted a `default-*` rule on purpose keeps their edit
until they explicitly re-apply that one.

---

## 3. Install paths (PRD R16)

### 3.1 Bare binary + systemd — **server** *(implemented — `deploy/systemd/`)*

```
/usr/local/bin/partout
/etc/partout/server.env        # EnvironmentFile (see server.env.example), mode 0640
/var/lib/partout/              # SQLite db + tls/ CA material (db dir)
```

`deploy/systemd/partout-server.service` (installed to
`/etc/systemd/system/partout-server.service`):

```ini
[Service]
Type=simple
User=partout
EnvironmentFile=/etc/partout/server.env
ExecStart=/usr/local/bin/partout --mode=server \
    --port=8443 \
    --db=/var/lib/partout/partout.db
Restart=on-failure
RestartSec=3
# Hardening: NoNewPrivileges, ProtectSystem=full, ProtectHome, PrivateTmp, …
```

First run: create the service account, then `systemctl enable --now partout-server`.
Verify: `curl -sf http://localhost:8443/healthz` → `{"status":"ok"}`.

> *Implemented in v0.3:* server-side agent provisioning over the operator's fleet SSH
> (`PARTOUT_SSH_DIR`, PRD R17) — `partout ctl provision new --host user@host`.
> First-run admin bootstrap is via `PARTOUT_ADMIN_PASSWORD`/`--admin-password` (§4.1),
> not an interactive `--create-admin` prompt. Manual agent install (§3.2) remains the
> fallback.

### 3.2 Bare binary + systemd — **agent** *(implemented — `deploy/systemd/`)*

```
/usr/local/bin/partout
/etc/partout/agent.env         # PARTOUT_SERVER, PARTOUT_TOKEN, … (see agent.env.example)
/var/lib/partout/agent/        # identity.json (0600), tls/ (0700)
```

`deploy/systemd/partout-agent.service`:

```ini
[Service]
Type=simple
User=partout
EnvironmentFile=/etc/partout/agent.env
ExecStart=/usr/local/bin/partout --mode=agent --data-dir=/var/lib/partout/agent
Restart=always
RestartSec=2
```

Enrollment (on the host, one-time):

```
sudo -u partout /usr/local/bin/partout --mode=agent \
  --server=partout.example.com:8443 --token=par_enr_…
# → writes identity.json (0600), consumes the token, opens the stream
systemctl enable --now partout-agent
```

TLS variant: add `--ca-file /etc/partout/ca.crt` (or `PARTOUT_TLS_CA` in the env file);
the agent then enrolls over HTTPS and stores its CA-signed leaf + key under
`<data dir>/tls/` (key 0600), and reconnects over mTLS on later starts.

> *Proposed (not wired):* elevation (`--elevate=sudoers`, scoped sudoers profiles,
> PRD Decision 3) — the binary hardcodes elevation off (`none`). Docker-host,
> air-gapped and non-systemd manual paths follow the same env + flags (§4).

### 3.3 Docker — server *(proposed — no artifacts in repo)*

```
docker run -d --name partout-server \
  -p 127.0.0.1:8443:8443 \
  -v partout-data:/var/lib/partout \
  -e PARTOUT_TLS=on \
  --restart unless-stopped \
  <image> --mode=server --db=/var/lib/partout/partout.db
```

`partout-data` holds the DB and `tls/` CA material — this volume **is** the server's
state (back it up; ops doc §4.1).

### 3.4 Docker — agent *(proposed — no artifacts in repo)*

```
docker run -d --name partout-agent \
  --restart unless-stopped \
  --pid=host \
  -v /:/host:rw \
  -e PARTOUT_SERVER=partout.example.com:8443 \
  <image> --mode=agent --root=/host
```

> `--root=/host` and `PARTOUT_ROOT` are *proposed* (not parsed); the containerized
> agent is for environments where a container is already the standard host-management
> vehicle. For hosts that will need elevation, prefer the bare-binary agent (§3.2).

### 3.5 Compose *(proposed — no artifacts in repo)*

`deploy/compose/local.yaml` would hold server + same-host agent (the "one box" lab).
nginx single-port routing (if not using Caddy):

```nginx
server {
    listen 443 ssl http2;
    # certs…
    location / {
        proxy_pass http://127.0.0.1:8443;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;   # SSE keepalive
        proxy_read_timeout 3600s;
    }
}
```

### 3.6 cloud-init *(proposed — no artifacts in repo)*

`deploy/cloud-init/agent.yaml` user-data for new VMs (Debian/Ubuntu):

```yaml
#cloud-config
write_files:
  - path: /etc/partout/agent.env
    permissions: "0640"
    content: |
      PARTOUT_SERVER=partout.example.com:8443
runcmd:
  - <install binary + unit, see §3.2>
  - 'echo "PARTOUT_TOKEN=par_enr_…" >> /etc/partout/agent.env'   # rotate after use
  - systemctl restart partout-agent
```

Better practice: mint a **short-TTL token per VM** and inject it via the cloud API's
user-data at create time (token shown once; the server logs the enrolling host's facts).

### 3.7 Helm *(proposed — no artifacts in repo)*

1. **Server**: single-replica `Deployment` (no HPA/leader election — PRD §13), `PVC` for
   `/var/lib/partout`, `Service` (+ optional Ingress TLS).
2. **Agent**: `DaemonSet` on **nodes** with hostPath `/` → `/host`, `--pid=host`.
   In-cluster *workload* observation (pods) is not the agent's job.

### 3.8 Embedded mode

`partout --mode=embedded` — runs the **server + a co-located local agent** in one
process (the agent enrolls over loopback with a locally-created one-time token on
first boot and reconnects with its persisted identity on restart). Use: single
self-managed machine, dev environment, CI e2e rig. Data under `PARTOUT_DB_PATH`
(default `./partout.db`).

### 3.9 MCP mode (R11, M4)

`partout --mode=mcp --server host:port --token T [--ca-file ca.crt]` — runs the
**MCP server over stdio** against a remote server, for MCP clients (Claude Code /
Cursor / CI) that launch the process. It is a JSON-RPC 2.0 (2025-06-18) tool
surface (26 tools: fleet/observe reads + governed writes); the `--token` is the
**caller's** credential — a static RBAC token, a local-user session token from
`partout ctl auth login`, or an OAuth2 (PKCE) access token (§3.10) — and is
forwarded with every tool call, so RBAC, policy
gating, and audit attribute each action to that principal exactly as the REST API
does. A policy denial / 403 / `approval_required` comes back as a structured tool
error. Example (Claude Code / `mcp.json`):

```json
{ "mcpServers": { "partout": {
    "command": "/usr/local/bin/partout",
    "args": ["--mode=mcp", "--server=partout.example.com:8443",
             "--token=par_tok_…", "--ca-file=/etc/partout/ca.crt"] } } }
```

The same tools are also reachable over **Streamable HTTP** at `POST /mcp` on the
main listener (bearer / OAuth2 access token in `Authorization`). No PTY tool
(PRD §10.3).

### 3.10 OAuth2 (PKCE) for MCP clients (R11/A20, M4)

For MCP clients that can hold a credential (or to scope per-assistant access),
the HTTP transport supports the authorization-code + PKCE flow:

1. **Register a client** (admin): `POST /api/v1/mcp/clients {"name":"claude-code"}`
   → `mcpcl_…` (list: `GET /api/v1/mcp/clients`).
2. **Authorize** (the resource owner, using their existing bearer token):
   `POST /oauth2/authorize {client_id, code_challenge, code_challenge_method:"S256"}`
   → one-time `code` (5-min TTL, bound to the owner + challenge).
3. **Exchange**: `POST /oauth2/token {grant_type:"authorization_code", code,
   code_verifier, client_id}` → `access_token` (1 h) + principal/role. The
   server verifies `S256(code_verifier) == code_challenge`; codes are single-use.

The access token then works anywhere a bearer works: `POST /mcp`, any REST
route, SSE — RBAC/policy/audit attribute it to the owner exactly as a session
token would. Tokens are stored only as SHA-256 hashes. v1 deviations (A20):
no browser-login grant (this codebase is bearer-token-based), no refresh
tokens.

---

## 4. Configuration reference

All configuration is env + flags (PRD R15). Precedence: **flag > env > default**.

### 4.1 Server — wired

| Var / Flag | Default | Notes |
|---|---|---|
| `PARTOUT_PORT` / `--port` | **8443** | single listener (REST + SSE + gRPC) |
| `PARTOUT_ADDR` / `--addr` | *(empty = all interfaces)* | bind address for the single listener; set `127.0.0.1` when the server sits behind a reverse proxy on the same host — keeps a plaintext (or TLS) control plane off the public interface |
| `PARTOUT_DB_PATH` / `--db` | **./partout.db** | SQLite path; `tls/` CA material is created in `<db dir>/tls/` |
| `PARTOUT_TLS` / `--tls` | **off** | `on` → local root-CA bootstrap + mTLS on the gRPC stream; REST/SSE stay bearer-auth |
| `PARTOUT_TLS_SERVER_NAMES` / `--tls-names` | **localhost,127.0.0.1,\<hostname\>** | comma-separated SANs for the server leaf |
| `PARTOUT_TOKEN_ADMIN` / `--admin-token` | *(empty)* | admin bearer token |
| `PARTOUT_TOKEN_OPERATOR` / `--operator-token` | *(empty)* | operator bearer token |
| `PARTOUT_TOKEN_VIEWER` / `--viewer-token` | *(empty)* | viewer bearer token |
| `PARTOUT_ADMIN_PASSWORD` / `--admin-password` | *(empty)* | first-run admin-user bootstrap password (M4); otherwise a random password is generated into `<db dir>/admin_password.txt` (0600). Prefer the env var — a flag value is visible in `ps` |
| `PARTOUT_SECRET_KEY_FILE` / `PARTOUT_SECRET_KEY` | *(empty)* | secrets master key (PRD §5.7): key file (mode `0600`) or env var; per-secret keys derived via HKDF. No key → the secrets feature is disabled at startup |
| `PARTOUT_SESSION_RETENTION_DAYS` | **30** | retention sweeper window for session recordings (PRD §9) |
| `PARTOUT_APPROVAL_TTL_S` | **3600** | (M4) approval-request TTL in seconds (PRD §5.8): a `require_approval`-parked action expires and is finalized `failed` if un-acted within this window; expired requests can never be retroactively honored |
| `PARTOUT_ALERT_TICK_S` | **30** | (M6) alert-engine evaluation cadence in seconds (PRD R25); one pass over all enabled rules × all host facts per tick |
| `PARTOUT_DISABLE_EXTERNAL_DATA_REFRESH` | **false** | air-gap switch: disables all external data fetching, EOL + CVE (PRD §6.3) |
| `PARTOUT_DATA_DIR` / `--data-dir` | *(empty)* | parsed; reserved for future output blobs — external data cache is in-DB (`eol_cache`/`vuln_cache`) |
| `PARTOUT_SSH_DIR` | **~/.ssh** | (v0.3) SSH dir for fleet-SSH provisioning: `config`, `known_hosts`, identity files; the operator's existing key material is the bootstrap channel (R17, Decision 11) — no credentials created or persisted by Partout. Passed to `ssh`/`scp`/`ssh-keygen` **explicitly** (`-F <dir>/config`, `UserKnownHostsFile`, `IdentityFile`), because OpenSSH resolves `~/.ssh` from the passwd database and ignores `$HOME`. Note: a non-default dir *replaces* the per-user config (`ssh -F` semantics), so the isolated dir's `config` must carry any `Host`/`ProxyJump`/`IdentityFile` rules |
| `PARTOUT_SERVER_HOST` | **\<hostname\>** | (v0.3) server address written into the new agent's `agent.env` `PARTOUT_SERVER` during provisioning (the listen address `:8443` is not usable by remote agents) |

RBAC: when no token is set the server runs in **single-user local mode** (no auth);
hierarchy viewer < operator < admin.

### 4.2 Agent — wired

| Var / Flag | Default | Notes |
|---|---|---|
| `PARTOUT_SERVER` / `--server` | *(required)* | server `host:port` (a `http(s)://` prefix is accepted); gRPC + REST on the same port |
| `PARTOUT_TOKEN` / `--token` | *(first boot only)* | one-time enrollment token |
| `PARTOUT_TLS_CA` / `--ca-file` | *(empty)* | path to the server root CA (PEM); enables HTTPS enrollment + mTLS stream |
| `PARTOUT_DATA_DIR` / `--data-dir` | **~/.partout/agent** | identity.json (0600), `tls/` (0700), policy |
| `PARTOUT_FACTS_INTERVAL` / `--facts-interval` | **3600** | basic host facts refresh seconds (floor 30) |
| `PARTOUT_OBSERVE_FACTS_INTERVAL` / `--observe-facts-interval` | **300** | (M5) structured fact upload interval; individual collector cadences may differ (arch §7.2) |
| `PARTOUT_REBOOT_FLUSH_S` | **5** | (M3) pre-reboot grace for a task `reboot` step (PRD §5.5): the agent waits this long after persisting the resume marker, so the `rebooting` report flushes up the stream before the host goes down |

### 4.3 `partout ctl` — wired

| Var / Flag | Notes |
|---|---|
| `PARTOUT_CTL_TOKEN` / `--token` | bearer token for the REST call |
| `PARTOUT_SERVER` / `--server` | server `host:port` (scheme accepted) |
| `PARTOUT_TLS_CA` / `--ca-file` | server root CA (PEM) → HTTPS |

Commands: `enroll-token [--ttl S]`, `hosts`, `run --selector S -- CMD [ARGS…]`,
`exec EXEC_ID`, `audit [--kind K] [--actor A] [--limit N]`, `policy
<list|create|delete>`, `provision <new|list|get|key|cancel>` (admin), `ca`,
`files <stat|list|upload|edit|perm>`, `sessions <open|close|list|replay>`, `secrets
<list|create|rotate|revoke|delete>`, `packages <updates|apply|actions>`, `tasks
<list|create|show|run|runs|run-show>`, `playbooks <list|create>`, `jobs
<list|create|show|delete|run|runs|list-runs>`, `external-data
<status|refresh|host-eol>`, `auth <login>`. Global flags may be given before or after
the subcommand.

`provision` drives fleet-SSH host provisioning (PRD R17): `new --host user@host
[--mode fresh|join]` starts a run; `get RUN_ID` shows state + per-step output; when a
host key is new to `known_hosts` the run pauses at `key_confirm` until `key RUN_ID
confirm|deny`; `cancel RUN_ID` aborts. States: `queued → connecting → key_confirm →
confirming → preflight → transferring → installing → enrolling → connected` (terminals
`failed`/`handoff`/`cancelled`; `handoff` = non-systemd host, manual install).

**First-run SSH precondition:** the *server process user* must already have
key-based trust to the target — an identity file (conventional `id_ed25519`/
`id_ecdsa`/`id_rsa`) in the SSH dir whose public key is in the target's
`authorized_keys`. OpenSSH resolves `~/.ssh` from the passwd database, so for a
service account (e.g. `partout` with home `/var/lib/partout`) the key belongs in
*that* home — not the operator's `~/.ssh`, which the service user cannot read.
`BatchMode=yes` makes password auth impossible: with no usable key the run
fails at `preflight` with `Permission denied (publickey)` plus a hint naming the
SSH dir to fix.

A duplicate/racing `confirm` returns **409** (`not_pending`), an unknown run **404**, and
`cancel` on a finished run reports `noop` with the current state. The `key_confirm` gate
lives in memory only: if the server restarts while a run is paused, a later `confirm`
**fails the run** ("re-run provisioning") rather than silently doing nothing.

### 4.4 Planned — documented, **not wired** (current)

These are PRD/architecture targets. They are **not parsed** by the current binary; setting
them has no effect. (The config package deliberately refuses to parse vars without an
implementation.)

| Var | Planned default | Planned feature |
|---|---|---|
| `PARTOUT_ADDR` / `PARTOUT_GRPC_ADDR` | `:8443` / off | main listener naming / split gRPC listener (§1.2) |
| `PARTOUT_H2C` | false | explicit cleartext-h2 acceptance flag |
| `PARTOUT_DB` | `sqlite:$PARTOUT_DATA_DIR/db.partout` | Postgres backend (R9) |
| `PARTOUT_RETENTION_*` (output/runs/facts days) | 30/90/90 | retention (PRD §9; session recordings are wired via `PARTOUT_SESSION_RETENTION_DAYS`) |
| `PARTOUT_MAX_OUTPUT_MB` / `PARTOUT_MAX_TRANSFER_MB` | 16 / 256 | size limits |
| `PARTOUT_MAX_CONCURRENT_RUNS_PER_HOST` | 4 | concurrency |
| `PARTOUT_SPOOL_MEM_MB` / `PARTOUT_SPOOL_DISK_MB` / `PARTOUT_SPOOL_AGE_S` | 16 / 128 / 86400 | offline spool (PRD §9) |
| `PARTOUT_DISPATCH_TTL_S` | 900 | offline queue expiry |
| `PARTOUT_POLICY_STALE_S` | 172800 | agent job bundle staleness |
| `PARTOUT_MCP_ENABLED` | true | MCP server |
| `PARTOUT_LOG_LEVEL` | info | structured log level |
| `PARTOUT_OBSERVE_FACTS_INTERVAL` | **300** | (M5) seconds between structured fact uploads (services/configs/certs); per-collector cadences in PRD arch §7.2
| `PARTOUT_CERT_PATHS` | *(empty)* | (M5) comma-separated paths for cert discovery, in addition to defaults (`/etc/ssl/`, `/etc/pki/tls/`)
| `PARTOUT_CERT_CA` | *(empty)* | (M5) trust bundle for certificate chain verification; empty = resolve from standard system locations. When none is found, chains are reported as *unchecked*, never as broken |
| `PARTOUT_SERVICE_LABELS` | *(empty)* | (M5) comma-separated operator labels for custom unit identification
| `PARTOUT_ELEVATE` | none | agent elevation `none\|sudoers\|sudo` (Decision 3; hardcoded `none`) |
| `PARTOUT_ROOT` | `/` | agent fs/exec root prefix (containers; hardcoded `/`) |
| `--label=k=v`, `--version` | — | flags *proposed* in earlier drafts; not wired |

### 4.5 All flags (current)

`--mode=server|agent|embedded|mcp`, `--port=`, `--db=`, `--data-dir=`, `--server=`,
`--token=`, `--facts-interval=`, `--admin-token=`, `--operator-token=`,
`--viewer-token=`, `--admin-password=`, `--tls=on|off`, `--tls-names=…`, `--ca-file=…`.
For `mcp` mode, `--token` is the caller's bearer token (not an enrollment token).
Subcommand: `ctl` (§4.3). Flags override env; env overrides defaults.

---

## 5. Environment recipes

### 5.1 Solo: one server VPS + a few boxes

- Server on the VPS (§3.1) behind Caddy; set the three RBAC bearer tokens; enroll agents
  by hand (§3.2) or via fleet SSH provision (`partout ctl provision new --host user@host`).
- Everything else defaults. This is the reference deployment for the solo persona (PRD §2.3).

### 5.2 Fleet: tens-to-hundreds

- Server on a beefier box. *Proposed:* `PARTOUT_DB=postgres://` once hosts > ~10k or
  audit volume is high (R9); the current build is SQLite-only.
- *Proposed:* image the agent (cloud-init §3.6), per-VM short-TTL tokens, concurrency /
  spool tuning.

### 5.3 Air-gapped

- `PARTOUT_DISABLE_EXTERNAL_DATA_REFRESH=true` disables all external data fetching
  (wired); ship the last extern cache (in-DB `eol_cache`/`vuln_cache`).
- Releases transfer as signed tarballs; verify SHA-256SUMS on the boundary host.
- No host data leaves the network (PRD invariant 5).

---

## 6. Bring-up checklist (first deployment, current)

1. Install server (§3.1) → `systemctl status partout-server` green;
   `GET /healthz` 200, `GET /readyz` 200.
2. Set up auth: pre-seed the first-run admin user with `PARTOUT_ADMIN_PASSWORD` (or
   read the generated password from `<db dir>/admin_password.txt`), and/or set the RBAC
   bearer tokens (`PARTOUT_TOKEN_ADMIN/OPERATOR/VIEWER`) in `/etc/partout/server.env`;
   restart. Verify `GET /api/v1/hosts` without credentials → 401, with a bearer token
   → 200. (The Web UI is shipped — open the main listener in a browser and log in as the admin
   user; the API and UI share the same auth.)
3. Mint an enrollment token: `partout ctl enroll-token --server … --token $ADMIN`.
4. On the first host: install the agent (§3.2) with that token → `GET
   /api/v1/hosts` shows it `connected` with facts within ~10 s.
5. Bind + expose: if the server sits behind a reverse proxy on the same host,
   set `PARTOUT_ADDR=127.0.0.1` so the control plane is not reachable from the
   network at all (the edge is the only path in). If exposing beyond localhost
   directly: `PARTOUT_TLS=on`, fetch the CA
   (`partout ctl ca --server https://… --ca-file <fetched-ca>`), put `ca.crt` on agents
   (`PARTOUT_TLS_CA`), restart both sides → agents reconnect over mTLS.
6. Run a command: `partout ctl run --selector all -- whoami` → verify output + an
   `exec.dispatch` audit row.
7. Back up the DB file **and** `<db dir>/tls/` (CA + keys) **before** onboarding more
   hosts (ops §4.1). Shipped: `scripts/backup.sh` (atomic snapshot via
   `partout ctl db-backup`, retention) + `deploy/systemd/partout-backup.{service,timer}`
   (daily 03:00, `Persistent=true`) — enable with `systemctl enable --now
   partout-backup.timer`. Also version the config (`/etc/partout/`) in git: commit,
   not back up.
8. Open the UI: `http://<server>:8443/` (or `https://` with `PARTOUT_TLS=on`) → log in →
   see the fleet, run a command from **Execute**, and browse Observe · Services/Certificates/Configs.
9. Dogfood: on a server + agent split deployment, enroll the server host as its own
   fleet member (a `partout-agent` unit alongside `partout-server`) and add alert
   rules for `partout-server`/`partout-agent` failed + your edge service. Note: the
   alert engine is server-side, so it cannot fire when the control plane itself dies —
   an external observer (cron from another host hitting `/healthz`) is still needed
   for that.

---

## 7. Versioning & compatibility

- Server and agent are independently upgradable; both speak the stream protocol.
- **Compatibility rule (P)**: an agent of version N works against servers N, N+1, and an
  agent N+1 works against server N (rolling upgrades). On skew beyond the rule the server
  marks the agent `version_mismatch` and refuses command dispatch.
- **Upgrade order**: server first (forward-only migrations on boot), then agents in
  waves. Agent restart drops the stream; backoff reconnect is automatic; in-flight runs
  report `interrupted`.
- DB migration is one-directional; pre-upgrade backup is the rollback path (ops §4.3).