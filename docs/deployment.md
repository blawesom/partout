# Partout — Deployment

**Status:** Draft v0.1 — reflects the **v0.1.0 binary** (tag `v0.1.0`).
Sections marked *proposed* describe planned work beyond v0.1.
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
wait-enroll). The server spawns the system `ssh`/`scp`/`ssh-keyscan`/`ssh-keygen`
(`PARTOUT_SSH_DIR` overrides the SSH dir, default the service user's `$HOME/.ssh`;
`PARTOUT_SERVER_HOST` sets the address written into the new agent's `agent.env`).
New env vars: `PARTOUT_SSH_DIR`, `PARTOUT_SERVER_HOST`.
**Not yet in v0.3:** Web UI, elevation, files & sessions, jobs/scheduling, Postgres
backend, offline spool, secret store, MCP.

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
| Split gRPC listener | *(proposed — `PARTOUT_GRPC_ADDR`, not in v0.1)* | Optional separate port if the operator wants gRPC on its own LB/TLS policy |
| Agent → server | outbound only | Agent needs only **egress** to the server (gRPC + REST enrollment); never inbound |

- TLS: server-native via a **local root-CA bootstrap** — `PARTOUT_TLS=on` (or `--tls on`)
  generates a root CA + server leaf cert under `<db dir>/tls/` on first run. Plaintext
  `h2c` is the default when TLS is off (no separate H2C switch). The older
  `PARTOUT_TLS_CERT`/`PARTOUT_TLS_KEY` vars are **not parsed** in v0.1 — use the CA
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

---

## 2. Artifacts

- **One static Go binary** `partout`. The Web frontend (embedded `embed.FS`) is
  *proposed* — v0.1 is API + agent only; operators use REST/SSE or `partout ctl`.
- **Release matrix** (*proposed*): `linux/amd64`, `linux/arm64`, `darwin/arm64`+`amd64`;
  optional musl build. v0.1: build from source (`go build ./cmd/partout`).
- **Per release** (*proposed*): binary tarballs, SHA-256SUMS, Docker image, Helm chart.
- **Images are distro-agnostic**: no OS packages required on hosts (agent is the binary).

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
> *Proposed (not yet):* `--create-admin=<name>` interactive bootstrap (replaced in v0.1 by
> RBAC bearer tokens, §4.1). Manual agent install (§3.2) remains the fallback.

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

> *Proposed (not in v0.1):* elevation (`--elevate=sudoers`, scoped sudoers profiles,
> PRD Decision 3) — the binary hardcodes elevation off (`none`) in v0.1. Docker-host,
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

> `--root=/host` and `PARTOUT_ROOT` are *proposed* (not parsed in v0.1); the containerized
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

`partout --mode=embedded` — v0.1 runs the **server** (a note is printed that the
co-located local agent is M1+). Use: single self-managed machine, dev environment, CI
e2e rig. Data under `PARTOUT_DB_PATH` (default `./partout.db`).

---

## 4. Configuration reference

All configuration is env + flags (PRD R15). Precedence: **flag > env > default**.

### 4.1 Server — wired in v0.1

| Var / Flag | Default | Notes |
|---|---|---|
| `PARTOUT_PORT` / `--port` | **8443** | single listener (REST + SSE + gRPC) |
| `PARTOUT_DB_PATH` / `--db` | **./partout.db** | SQLite path; `tls/` CA material is created in `<db dir>/tls/` |
| `PARTOUT_TLS` / `--tls` | **off** | `on` → local root-CA bootstrap + mTLS on the gRPC stream; REST/SSE stay bearer-auth |
| `PARTOUT_TLS_SERVER_NAMES` / `--tls-names` | **localhost,127.0.0.1,\<hostname\>** | comma-separated SANs for the server leaf |
| `PARTOUT_TOKEN_ADMIN` / `--admin-token` | *(empty)* | admin bearer token |
| `PARTOUT_TOKEN_OPERATOR` / `--operator-token` | *(empty)* | operator bearer token |
| `PARTOUT_TOKEN_VIEWER` / `--viewer-token` | *(empty)* | viewer bearer token |
| `PARTOUT_DATA_DIR` / `--data-dir` | *(empty)* | parsed; reserved for output blobs / extern cache (M1+) — not used by the server in v0.1 |
| `PARTOUT_SSH_DIR` | **~/.ssh** | (v0.3) SSH dir for fleet-SSH provisioning: `config`, `known_hosts`, identity files; the operator's existing key material is the bootstrap channel (R17, Decision 11) — no credentials created or persisted by Partout |
| `PARTOUT_SERVER_HOST` | **\<hostname\>** | (v0.3) server address written into the new agent's `agent.env` `PARTOUT_SERVER` during provisioning (the listen address `:8443` is not usable by remote agents) |

RBAC: when no token is set the server runs in **single-user local mode** (no auth);
hierarchy viewer < operator < admin.

### 4.2 Agent — wired in v0.1

| Var / Flag | Default | Notes |
|---|---|---|
| `PARTOUT_SERVER` / `--server` | *(required)* | server `host:port` (a `http(s)://` prefix is accepted); gRPC + REST on the same port |
| `PARTOUT_TOKEN` / `--token` | *(first boot only)* | one-time enrollment token |
| `PARTOUT_TLS_CA` / `--ca-file` | *(empty)* | path to the server root CA (PEM); enables HTTPS enrollment + mTLS stream |
| `PARTOUT_DATA_DIR` / `--data-dir` | **~/.partout/agent** | identity.json (0600), `tls/` (0700), policy |
| `PARTOUT_FACTS_INTERVAL` / `--facts-interval` | **3600** | facts refresh seconds (floor 30) |

### 4.3 `partout ctl` — wired in v0.1 (policy + provision added in v0.2/v0.3)

| Var / Flag | Notes |
|---|---|
| `PARTOUT_CTL_TOKEN` / `--token` | bearer token for the REST call |
| `PARTOUT_SERVER` / `--server` | server `host:port` (scheme accepted) |
| `PARTOUT_TLS_CA` / `--ca-file` | server root CA (PEM) → HTTPS |

Commands: `enroll-token [--ttl S]`, `hosts`, `run --selector S -- CMD [ARGS…]`,
`exec EXEC_ID`, `audit [--kind K] [--actor A] [--limit N]`,
`policy <list|create|delete>` (v0.2), `provision <new|list|get|key|cancel>` (v0.3,
admin), `ca`. Global flags may be given before or after the subcommand.

`provision` drives fleet-SSH host provisioning (PRD R17): `new --host user@host
[--mode fresh|join]` starts a run; `get RUN_ID` shows state + per-step output; when a
host key is new to `known_hosts` the run pauses at `key_confirm` until `key RUN_ID
confirm|deny`; `cancel RUN_ID` aborts. States: `queued → connecting → key_confirm →
preflight → transfer → install → enrolling → connected` (terminals `failed`/`handoff`/
`cancelled`; `handoff` = non-systemd host, manual install).

### 4.4 Planned — documented, **not wired** in v0.3

These are PRD/architecture targets. They are **not parsed** by the v0.3 binary; setting
them has no effect. (The v0.1 config package deliberately refuses to parse vars without
an implementation.)

| Var | Planned default | Planned feature |
|---|---|---|
| `PARTOUT_ADDR` / `PARTOUT_GRPC_ADDR` | `:8443` / off | main listener naming / split gRPC listener (§1.2) |
| `PARTOUT_H2C` | false | explicit cleartext-h2 acceptance flag |
| `PARTOUT_DB` | `sqlite:$PARTOUT_DATA_DIR/db.partout` | Postgres backend (R9) |
| `PARTOUT_SECRET_KEY_FILE` / `PARTOUT_SECRET_KEY` | none | secret store (PRD §5.7) |
| `PARTOUT_DISABLE_EXTERNAL_DATA_REFRESH` | false | air-gap switch |
| `PARTOUT_RETENTION_*` (output/sessions/runs/facts days) | 30/30/90/90 | retention (PRD §9) |
| `PARTOUT_MAX_OUTPUT_MB` / `PARTOUT_MAX_TRANSFER_MB` | 16 / 256 | size limits |
| `PARTOUT_MAX_CONCURRENT_RUNS_PER_HOST` | 4 | concurrency |
| `PARTOUT_SPOOL_MEM_MB` / `PARTOUT_SPOOL_DISK_MB` / `PARTOUT_SPOOL_AGE_S` | 16 / 128 / 86400 | offline spool (PRD §9) |
| `PARTOUT_DISPATCH_TTL_S` | 900 | offline queue expiry |
| `PARTOUT_POLICY_STALE_S` | 172800 | agent job bundle staleness |
| `PARTOUT_MCP_ENABLED` | true | MCP server |
| `PARTOUT_LOG_LEVEL` | info | structured log level |
| `PARTOUT_ELEVATE` | none | agent elevation `none\|sudoers\|sudo` (Decision 3; hardcoded `none` in v0.1) |
| `PARTOUT_ROOT` | `/` | agent fs/exec root prefix (containers; hardcoded `/` in v0.1) |
| `--label=k=v`, `--create-admin`, `--version` | — | flags *proposed* in earlier drafts; not in v0.1 |

### 4.5 All flags (v0.1)

`--mode=server|agent|embedded`, `--port=`, `--db=`, `--data-dir=`, `--server=`,
`--token=`, `--facts-interval=`, `--admin-token=`, `--operator-token=`,
`--viewer-token=`, `--tls=on|off`, `--tls-names=…`, `--ca-file=…`.
Subcommand: `ctl` (§4.3). Flags override env; env overrides defaults.

---

## 5. Environment recipes

### 5.1 Solo: one server VPS + a few boxes

- Server on the VPS (§3.1) behind Caddy; set the three RBAC bearer tokens; enroll agents
  by hand (§3.2) or via fleet SSH provision (`partout ctl provision new --host user@host`).
- Everything else defaults. This is the reference deployment for the solo persona (PRD §2.3).

### 5.2 Fleet: tens-to-hundreds

- Server on a beefier box. *Proposed:* `PARTOUT_DB=postgres://` once hosts > ~10k or
  audit volume is high (R9); v0.1 is SQLite-only.
- *Proposed:* image the agent (cloud-init §3.6), per-VM short-TTL tokens, concurrency /
  spool tuning.

### 5.3 Air-gapped

- *Proposed:* `PARTOUT_DISABLE_EXTERNAL_DATA_REFRESH=true`; ship the last extern cache.
- Releases transfer as signed tarballs; verify SHA-256SUMS on the boundary host.
- No host data leaves the network (PRD invariant 5).

---

## 6. Bring-up checklist (first deployment, v0.1)

1. Install server (§3.1) → `systemctl status partout-server` green;
   `GET /healthz` 200, `GET /readyz` 200.
2. Set RBAC bearer tokens in `/etc/partout/server.env` (admin/operator/viewer) and
   restart; verify `GET /api/v1/hosts` without a token → 401, with `Authorization:
   Bearer …` → 200. *(No UI / password bootstrap in v0.1.)*
3. Mint an enrollment token: `partout ctl enroll-token --server … --token $ADMIN`.
4. On the first host: install the agent (§3.2) with that token → `GET
   /api/v1/hosts` shows it `connected` with facts within ~10 s.
5. If exposing beyond localhost: `PARTOUT_TLS=on`, fetch the CA
   (`partout ctl ca --server https://… --ca-file <fetched-ca>`), put `ca.crt` on agents
   (`PARTOUT_TLS_CA`), restart both sides → agents reconnect over mTLS.
6. Run a command: `partout ctl run --selector all -- whoami` → verify output + an
   `exec.dispatch` audit row.
7. Back up the DB file **and** `<db dir>/tls/` (CA + keys) **before** onboarding more
   hosts (ops §4.1).

> *Proposed (later milestones):* baseline policy + approval rules, provisioning via
> `Provision → Add host`, alert channel for `host.state` / approvals, secret key backup.

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