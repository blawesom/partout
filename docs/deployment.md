# Partout — Deployment

**Status:** Draft v0.1
**Companion docs:** `PRD.md`, `docs/architecture.md`, `docs/operations.md`
**PRD anchor:** R16 (install paths), R15 (env config), R9 (storage engines).

---

## 1. Topology & network

### 1.1 The only topology

One **server** (central) + N **agents** (one per managed host) + optional **embedded** mode
(server and agent in one process on a single self-managed host). No control nodes beyond the
server, no queue, no Redis (PRD principle 2). The server is **not** HA'd by Partout — the
operator's cluster manager owns availability (PRD §13).

### 1.2 Ports & listener

**(proposed — see architecture §15, A1)**

| What | Default | Notes |
|---|---|---|
| Main listener | `:8443` | Single Go http server serving UI + REST v1 + SSE + MCP (HTTP/1.1) **and** gRPC (h2, by `content-type: application/grpc`) |
| Split gRPC listener | off (`PARTOUT_GRPC_ADDR`) | Optional separate port (e.g. `:9443`) if the operator wants gRPC on its own LB/TLS policy |
| Agent → server | outbound only | Agent needs only **egress** to the server's gRPC + REST (enrollment); never inbound |

- TLS: server-native via a **local root-CA bootstrap** — `PARTOUT_TLS=on` generates a root
  CA + server leaf cert under `<db dir>/tls/` on first run (§3.6). `PARTOUT_H2C=true` is the
  plaintext default for local dev; a TLS port rejects plaintext clients. (The older
  `PARTOUT_TLS_CERT`/`PARTOUT_TLS_KEY` vars are parsed but not wired — use the CA bootstrap.)
- The agent connects to one address: `PARTOUT_SERVER=host:port` (gRPC and REST derived from
  it); in TLS mode `PARTOUT_TLS_CA=/path/to/ca.crt` enables HTTPS enroll + mTLS.

### 1.3 Reverse proxy routing

Single TLS edge, route by content-type (Caddy shown; nginx equivalent in §3.5):

```caddy
partout.example.com {
    reverse_proxy 127.0.0.1:8443
    header_up X-Forwarded-Proto {scheme}
}
```

(No path rules needed: REST/SSE/MCP/gRPC all live on the same port; the mux demuxes by
content-type. If using the split gRPC port, add a second site or `handle` block on
`content_type application/grpc` → `127.0.0.1:9443`.)

---

## 2. Artifacts

- **One static Go binary** `partout` per architecture; frontend embedded (`embed.FS`).
- **Release matrix**: `linux/amd64`, `linux/arm64` (aarch64 VPS/bare metal are common);
  `darwin/arm64`+`amd64` for operator laptops (embedded/CLI use). Optional musl build for
  alpine-style hosts.
- **Per release**: binary tarballs, SHA-256SUMS, Docker image `ghcr.io/<org>/partout:<tag>`,
  Helm chart package. Semantic versioning; the PRD's repo rename (`hiersoir` → `partout`)
  applies to all artifact names.
- **Images are distro-agnostic**: no OS packages required on hosts (agent is the binary).

---

## 3. Install paths (PRD R16)

### 3.1 Bare binary + systemd — **server**

```
/usr/local/bin/partout
/etc/partout/server.env        # EnvironmentFile, mode 0640 root:root
/var/lib/partout/server/       # PARTOUT_DATA_DIR: db.partout, output blobs, extern cache
/var/log/partout/              # optional; default: journal
```

**Provisioning prerequisite (PRD R17):** if the server should install agents on remote hosts,
its service user must be able to read the operator's existing fleet SSH keys and
`~/.ssh/config` (`PARTOUT_SSH_DIR`, §4.1). The server box therefore becomes a **critical
asset**: it can reach every host the fleet keys allow (ops §1).

`/etc/systemd/system/partout-server.service`:

```ini
[Unit]
Description=Partout control plane
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=partout
Group=partout
EnvironmentFile=/etc/partout/server.env
ExecStart=/usr/local/bin/partout --mode=server
Restart=on-failure
RestartSec=3
# Hardening
NoNewPrivileges=true
ProtectSystem=full
ProtectHome=true
ReadWritePaths=/var/lib/partout
PrivateTmp=true
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
```

First run: create the service account, then

```
sudo -u partout /usr/local/bin/partout --mode=server --create-admin=alice   # (proposed flag)
# → interactive password prompt; prints UI URL
```

### 3.2 Bare binary + systemd — **agent**

**Prefer provisioning for new remote hosts (PRD R17):** `Provision → Add host` in the UI —
the server installs exactly this layout over the operator's existing fleet SSH (architecture
§3.5). This section is the reference layout provisioning writes, and the manual path for
Docker-host, air-gapped, or non-systemd hosts.

```
/usr/local/bin/partout
/etc/partout/agent.env         # PARTOUT_SERVER, PARTOUT_ELEVATE, … (0640)
/var/lib/partout/agent/        # identity.json (0600), spool.db, policy bundle, job state
```

`/etc/systemd/system/partout-agent.service`:

```ini
[Unit]
Description=Partout agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=partout
Group=partout
EnvironmentFile=/etc/partout/agent.env
ExecStart=/usr/local/bin/partout --mode=agent
Restart=always
RestartSec=2
LimitNOFILE=65536
PrivateTmp=true
# Deliberately no filesystem sandboxing and no NoNewPrivileges: the agent's job
# is to read/write the host filesystem, and elevation exec's setuid sudo.
# Safety model = unprivileged user + scoped sudoers profiles (PRD §7, Decision 3).

[Install]
WantedBy=multi-user.target
```

Enrollment (on the host, one-time):

```
sudo -u partout /usr/local/bin/partout --mode=agent \
  --server=https://partout.example.com --token=par_enr_…
# → writes identity.json (0600), opens the stream; token is consumed server-side
systemctl enable --now partout-agent
```

**Elevation setup**: for `--elevate=sudoers` hosts, drop the scoped sudoers file first
(bootstrapped by hand or — dogfooding — by a Partout task once the host is enrolled):

```
/etc/sudoers.d/partout   # NOPASSWD, per named profile pattern, target user only
# e.g.  partout ALL=(root) NOPASSWD: /usr/bin/apt-get update, /usr/bin/apt-get install *
```

Only commands matching a named elevation profile (architecture §6.1) are ever elevated
(PRD Decision 3).

### 3.3 Docker — server

```
docker run -d --name partout-server \
  -p 127.0.0.1:8443:8443 \
  -v partout-data:/var/lib/partout/server \
  -e PARTOUT_TLS_CERT= -e PARTOUT_TLS_KEY= \
  --restart unless-stopped \
  ghcr.io/<org>/partout:1.x.y --mode=server
```

Bind to `127.0.0.1` and front with the reverse proxy (§1.3), or expose with server-native TLS.
`partout-data` holds the DB, output blobs, and extern cache — this volume **is** the server's
state (back it up; ops doc §4.1).

### 3.4 Docker — agent

The agent must see the host. Run it as a thin view of the host:

```
docker run -d --name partout-agent \
  --restart unless-stopped \
  --pid=host \
  -v /:/host:rw \
  -v /etc:/host/etc:rw -v /var:/host/var:rw \
  -e PARTOUT_ROOT=/host \
  -e PARTOUT_SERVER=https://partout.example.com \
  ghcr.io/<org>/partout:1.x.y --mode=agent --root=/host
```

- `PARTOUT_ROOT` (architecture §6.1) makes every fs/exec path relative to the mounted host
  root, so the agent works unchanged on bare metal (`PARTOUT_ROOT=/`) or in a container.
- `--pid=host` for container/ps facts; host `/proc` and `/sys` are visible through the `/` mount
  if needed by collectors.
- Elevation in a containerized agent is the awkward case: the agent would exec the host's
  `sudo` via the root prefix (e.g. `/host/usr/bin/sudo`), which requires 1:1 uid mapping and
  works but couples the agent to host internals. **For hosts that need elevation, prefer the
  bare-binary agent (§3.2); the containerized agent is for environments where a container is
  already the standard host-management vehicle.**
- **Embedded Docker** (single machine, no fleet): one container, `--mode=embedded`,
  `PARTOUT_ROOT=/host`; UI is local-only.

### 3.5 Compose

`deploy/compose/local.yaml` — server + same-host agent (the "one box" lab):

```yaml
services:
  server:
    image: ghcr.io/<org>/partout:1.x.y
    command: ["--mode=server"]
    ports: ["127.0.0.1:8443:8443"]
    volumes: [partout-data:/var/lib/partout/server]
    environment: [PARTOUT_TLS_CERT=, PARTOUT_TLS_KEY=]
  agent:
    image: ghcr.io/<org>/partout:1.x.y
    command: ["--mode=agent", "--root=/host"]
    pid: host
    volumes: ["/:/host:rw"]
    environment:
      PARTOUT_SERVER: http://server:8443
      # PARTOUT_TOKEN: set on first run only
volumes:
  partout-data:
```

For a remote fleet the compose file runs **server only**; agents live on their hosts (§3.2).

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
    # gRPC on same port: content-type-based demux is handled server-side;
    # for split-port deployments:
    # location / { if ($http_content_type ~* application/grpc) { proxy_pass http://127.0.0.1:9443; } … }
}
```

### 3.6 cloud-init (VPS images)

`deploy/cloud-init/agent.yaml` — user-data for new VMs (Debian/Ubuntu shown):

```yaml
#cloud-config
package_update: true
packages: [curl]
write_files:
  - path: /etc/partout/agent.env
    permissions: "0640"
    content: |
      PARTOUT_SERVER=https://partout.example.com
      PARTOUT_ELEVATE=sudoers
runcmd:
  - curl -fsSL https://get.partout.example.com/install | sh -s -- --mode=agent
    # installer: fetch pinned binary, install unit, enable; token passed via:
  - 'echo "PARTOUT_TOKEN=par_enr_…" >> /etc/partout/agent.env'   # rotate after use
  - systemctl restart partout-agent
```

Better practice: mint a **short-TTL token per VM** and inject it via the cloud API's
user-data at create time (token shown once anyway; the server logs the enrolling host's
facts so you can verify). For AMI-style reuse, ship the binary in the image and enroll at
first boot from metadata.

### 3.7 Helm (Kubernetes)

`deploy/helm/partout/` — two installable pieces:

1. **Server** (namespace-scoped): single-replica `Deployment` (no HPA/leader election — PRD
   §13), `PVC` for `/var/lib/partout/server`, `Service` (+ optional `Ingress`/`ServiceMesh`
   TLS), `Secret` for `PARTOUT_SECRET_KEY_FILE` content and TLS certs. Values: `image`,
   `adminBootstrap`, `tls.mode` (secret/ingress/off), `retention.*`, `extern.disabled`.
2. **Agent** (per cluster): `DaemonSet` running the agent on **nodes** (the agent is
   runtime-agnostic, PRD principle 6; a K8s node is a Linux host). Host mounts via `hostPath`:
   `/` → `/host` (`--root=/host`), `--pid=host`, tolerations `Exists`, `nodeSelector`
   optional. The control plane then treats nodes as hosts: exec, files, jobs, packages.

Notes: Helm is the M5 distribution path (PRD §14); values are 1:1 with the env vars below.
In-cluster *workload* observation (pods) is **not** the agent's job — pods are observed via
the node's container runtime (observe layer), not as managed hosts.

### 3.8 Embedded mode

`partout --mode=embedded` — server + agent in one process, no network listener for the
stream, UI on localhost. Use: single self-managed machine, dev environment, CI e2e rig.
Data under `~/.local/share/partout` (or `PARTOUT_DATA_DIR`).

---

## 4. Configuration reference

All configuration is env (PRD R15). Defaults in **bold**; "(P)" = proposed, awaiting sign-off.

### 4.1 Server

| Var | Default | Notes |
|---|---|---|
| `PARTOUT_ADDR` (P) | **:8443** | main listener (UI/REST/SSE/MCP/gRPC) |
| `PARTOUT_GRPC_ADDR` (P) | *(off)* | split gRPC listener |
| `PARTOUT_TLS_CERT` / `PARTOUT_TLS_KEY` | *(empty)* | parsed, not yet wired (legacy; see `PARTOUT_TLS` below) |
| `PARTOUT_TLS` | **off** | `on` → enable TLS: local root CA + server leaf bootstrap (§3.6) |
| `PARTOUT_TLS_SERVER_NAMES` | **localhost,127.0.0.1,\<hostname\>** | comma-separated SANs for the server leaf |
| `PARTOUT_H2C` (P) | **false** | accept cleartext from trusted proxy |
| `PARTOUT_DATA_DIR` | **/var/lib/partout/server** | db, output blobs, extern cache |
| `PARTOUT_DB` | **sqlite:$PARTOUT_DATA_DIR/db.partout** | or `postgres://…` (server data set only; PRD R9) |
| `PARTOUT_SECRET_KEY_FILE` / `PARTOUT_SECRET_KEY` | *(none)* | PRD §5.7; secrets disabled without it |
| `PARTOUT_SSH_DIR` (P) | **$HOME/.ssh** | dir holding `config`, `known_hosts`, identity files used for provisioning (R17, architecture A16); ssh children run with `HOME` set to its parent |
| `PARTOUT_DISABLE_EXTERNAL_DATA_REFRESH` | **false** | PRD §6.3 air-gap switch |
| `PARTOUT_RETENTION_OUTPUT_DAYS` (P) | **30** | PRD §9 |
| `PARTOUT_RETENTION_SESSIONS_DAYS` (P) | **30** | |
| `PARTOUT_RETENTION_RUNS_DAYS` (P) | **90** | job/task runs |
| `PARTOUT_RETENTION_FACTS_DAYS` (P) | **90** | |
| `PARTOUT_MAX_OUTPUT_MB` (P) | **16** | per run |
| `PARTOUT_MAX_TRANSFER_MB` (P) | **256** | file upload/download |
| `PARTOUT_MAX_CONCURRENT_RUNS_PER_HOST` (P) | **4** | |
| `PARTOUT_SPOOL_*` — mem/disk/age | **16 MB / 128 MB / 24 h** | defaults (PRD §9) |
| `PARTOUT_DISPATCH_TTL_S` (P) | **900** | offline-agent queue expiry |
| `PARTOUT_POLICY_STALE_S` (P) | **172800** | agent-job bundle staleness (48 h) |
| `PARTOUT_MCP_ENABLED` (P) | **true** | MCP server on/off |
| `PARTOUT_LOG_LEVEL` (P) | **info** | trace..warn |

### 4.2 Agent

| Var | Default | Notes |
|---|---|---|
| `PARTOUT_SERVER` | *(required)* | server `host:port` (gRPC + REST, single port) |
| `PARTOUT_TOKEN` | *(first boot only)* | consumed at enrollment |
| `PARTOUT_TLS_CA` | *(empty)* | path to the server root CA (PEM); enables HTTPS enroll + mTLS stream |
| `PARTOUT_DATA_DIR` | **/var/lib/partout/agent** | identity, TLS material, spool, state |
| `PARTOUT_ELEVATE` | **none** (P) | `none|sudoers|sudo` (PRD Decision 3) |
| `PARTOUT_ROOT` (P) | **/** | fs/exec root prefix (containers) |
| `PARTOUT_FACTS_INTERVAL` (P) | **3600** | hourly refresh (PRD §5.1) |
| `PARTOUT_SPOOL_*` | **16 MB / 128 MB / 24 h** | |
| `PARTOUT_LOG_LEVEL` (P) | **info** | |

### 4.3 Flags

`--mode=server|agent|embedded` (PRD R1), `--server=`, `--token=`, `--label=k=v` (repeatable;
tags at enrollment, PRD §5.1), `--elevate=`, `--root=`, `--tls=on|off`,
`--tls-names=…` (server SANs), `--ca-file=…` (agent/ctl CA for TLS), `--create-admin=` (P),
`--version`. Flags override env.

---

## 5. Environment recipes

### 5.1 Solo: one server VPS + a few boxes

- Server on the VPS (§3.1) behind Caddy with a Let's Encrypt cert; `PARTOUT_SECRET_KEY_FILE`
  set; `PARTOUT_ELEVATE=sudoers` on hosts that need privileged tasks.
- Agents: §3.2 on each box; tags like `env=prod,env=lab` set at enrollment (`--label`).
- Everything else defaults. This is the reference deployment for the solo persona (PRD §2.3).

### 5.2 Fleet: tens-to-hundreds

- Server on a beefier box (or the operator's platform) with `PARTOUT_DB=postgres://`
  (R9) once hosts > ~10k or audit volume is high; otherwise SQLite is fine (architecture §13).
- **Image the agent**: bake binary + unit into the host image (or cloud-init §3.6); enroll at
  first boot with per-VM short-TTL tokens; tags/roles assigned by the enrollment tooling.
- Set `PARTOUT_MAX_CONCURRENT_RUNS_PER_HOST` and rate limits deliberately (architecture §13
  targets); monitor spool usage via heartbeats (alert channel).
- Groups mirror your real topology (`group:webservers`, `role:db`) — targeting is the
  day-to-day surface (PRD C3).

### 5.3 Air-gapped

- `PARTOUT_DISABLE_EXTERNAL_DATA_REFRESH=true`; ship the last extern cache (or rely on the
  embedded EOL fallback); pre-publish the Docker image/chart to the internal registry.
- Releases transfer as signed tarballs; verify SHA-256SUMS on the boundary host.
- MCP stdio still works locally; remote MCP HTTP stays inside the boundary.
- No host data leaves the network (PRD invariant 5); the air-gap switch makes that total.

---

## 6. Bring-up checklist (first deployment)

1. Install server (§3.1) → `systemctl status partout-server` green; `GET /healthz` 200.
2. `--create-admin` → log in to UI.
3. **Set the secret key** (secrets feature) or accept it disabled; back it up (ops §4.1).
4. Baseline policy: one `require_approval` rule for `requires_elevation` actions (the safety
   floor — PRD M1) + explicit `allow` rules for what you intend to run routinely (default-deny
   writes, architecture A6).
5. Add the first host (UI → **Provision**, PRD R17): address or `~/.ssh/config` alias → the
   server bootstraps the agent over the operator's existing fleet SSH (confirm the host-key
   fingerprint if new) → facts visible <10 s (PRD §5.1 acceptance). Manual path (Docker-host,
   air-gapped, non-systemd): mint a short-TTL enrollment token → enroll by hand (§3.2).
6. Run a read-only command (`whoami`) to the host; verify audit row with principal.
7. Configure alert channel for `host.state` (agent disconnected) and `approval.request`.
8. Set up backup of `/var/lib/partout/server` + the secret key file (ops §4.1) **before**
   onboarding more hosts.

---

## 7. Versioning & compatibility

- Server and agent are independently upgradable; both speak the stream protocol.
- **Compatibility rule (P)**: an agent of version N works against servers N, N+1 (rolling
  server upgrade), and an agent N+1 works against server N (rolling agent upgrade). The
  handshake carries protocol versions; on skew beyond the rule the server marks the agent
  `version_mismatch` and refuses command dispatch (reads/facts still flow) until the agent is
  updated.
- **Upgrade order (safe either way)**: server first (migrations run forward-only on boot,
  architecture §9.1), then agents in waves (canary group → rest). Agent restart drops the
  stream; backoff reconnect is automatic; in-flight runs report `interrupted` (architecture §3.4)
  and convergent tasks re-run.
- DB migration is one-directional; pre-upgrade backup is the rollback path (ops §4.3).