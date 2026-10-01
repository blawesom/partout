# deploy/systemd — Linux install via systemd

## Quick install (single node)

### 1. Drop the binary

```bash
sudo cp /path/to/partout /usr/local/bin/partout
sudo chmod 0755 /usr/local/bin/partout
```

### 2. Create runtime user

```bash
sudo useradd --system --home-dir /var/lib/partout --shell /usr/sbin/nologin partout
sudo mkdir -p /var/lib/partout
sudo chown partout:partout /var/lib/partout
# File root (docs/spec-file-root.md): the file surface is confined to this
# directory; the agent creates it when missing, but the provisioner/deploy
# path creates it explicitly so it exists before first use.
sudo mkdir -p /home/partout
sudo chown partout:partout /home/partout
sudo chmod 0750 /home/partout
```

### 3. Server

Copy the env template and generate real tokens:

```bash
sudo cp server.env.example /etc/partout/server.env
sudo chown root:root /etc/partout/server.env
sudo chmod 0600 /etc/partout/server.env

# Generate real tokens (replace the empty values):
export T=$(openssl rand -hex 24)
sudo sed -i \
  -e "s/^PARTOUT_TOKEN_ADMIN=/PARTOUT_TOKEN_ADMIN=$T/" \
  -e "s/^PARTOUT_TOKEN_OPERATOR=/PARTOUT_TOKEN_OPERATOR=$T/" \
  /etc/partout/server.env
```

Install the unit:

```bash
sudo cp partout-server.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now partout-server.service
```

### 4. Agent (managed host)

```bash
sudo cp partout-agent.service /etc/systemd/system/
# M8.1: boot guard that supervises the agent's signed self-update
# (rolls a failed swap back to N-1 before the agent starts).
sudo cp partout-update-guard.sh /usr/local/sbin/partout-update-guard
sudo chmod 0755 /usr/local/sbin/partout-update-guard
sudo mkdir -p /etc/partout
sudo cp agent.env.example /etc/partout/agent.env

# Set the server address (required):
sudo sed -i 's|^PARTOUT_SERVER=.*|PARTOUT_SERVER=10.0.0.5:8443|' \
  /etc/partout/agent.env
```

First-time enrollment (only once):

```bash
# Get a one-time token from the server operator.
TOK=$(curl -s -H "Authorization: Bearer $ADMIN_TOKEN" \
  http://10.0.0.5:8443/api/v1/agents/enrollment-tokens \
  | python3 -c 'import sys,json;print(json.load(sys.stdin)["token"])')

sudo sed -i "s|^PARTOUT_TOKEN=.*|PARTOUT_TOKEN=$TOK|" \
  /etc/partout/agent.env
```

Start the agent.  After the first enrollment completes (agent.log shows
"enrolled as ag_…"), **remove the token** from agent.env so the service
never leaks it.

# Optional (M8.1 self-update): provision the release signing public key so
# the agent will accept signed self-update directives. Without it the agent
# refuses every update (fails closed).
#   sudo sed -i '/^PARTOUT_RELEASE_KEY=/d' /etc/partout/agent.env
#   echo 'PARTOUT_RELEASE_KEY=<base64 release public key>' >> /etc/partout/agent.env

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now partout-agent.service
sudo sed -i '/^PARTOUT_TOKEN=/d' /etc/partout/agent.env
sudo systemctl restart partout-agent.service
```

## Elevation (optional; agent runs privileged operations)

The agent runs as the unprivileged `partout` user by default (PRD Decision 3). That
means it **cannot** install/manage packages, start/stop services, reboot, or read
root-only config files (e.g. `haproxy.cfg`). To enable those without running the
whole agent as root, turn on host-level elevation:

```bash
# 1) Install the sudoers scope (fail-closed: nothing elevates unless listed)
sudo install -m 0440 -o root -g root deploy/sudoers/partout-agent /etc/sudoers.d/partout-agent
sudo visudo -cf /etc/sudoers.d/partout-agent

# 2) Enable elevation in the agent env
sudo sed -i 's/^# PARTOUT_ELEVATE=.*/PARTOUT_ELEVATE=sudo/' /etc/partout/agent.env

# 3) sudo needs setuid — the unit's NoNewPrivileges blocks it. Remove that line.
sudo sed -i '/^NoNewPrivileges=true/d' /etc/systemd/system/partout-agent.service
sudo systemctl daemon-reload
sudo systemctl restart partout-agent
```

What elevates (all via `sudo -n`, non-interactive, no password): dispatched
exec, PTY sessions (a root terminal), package apply + metadata refresh, task
steps (command/package/service/user/group/reboot), and root-only config-file
reads for the observe layer. Everything else stays as `partout`. A command with
no matching sudoers entry **fails closed** with a normal non-zero exit — the
dispatch/surface reports it like any failed command. The shipped drop-in also
passes custom environment through (`!env_reset`), so `partout ctl run --env
K=V` works on elevated commands out of the box — trade-off and how to
re-tighten later: operations.md §3.6. Per-command elevation
profiles (pattern-scoped, policy-constrained) are the later full Decision 3
implementation (see docs/roadmap.md).

If you don't need privilege on a host, leave `PARTOUT_ELEVATE` unset: the agent
stays fully unprivileged.

## Uninstall

One command, local to the machine (deployment §3.11 for the full reference):

```bash
sudo partout uninstall --dry-run   # preview
sudo partout uninstall             # stop + remove units/env/binary, keep /var/lib/partout
sudo partout uninstall --purge     # also remove state (db, TLS, identity) + user partout
```

On a managed host the same command can be dispatched from the server
(`partout ctl run --agent <id> -- sudo partout uninstall --purge`); removing
the host from the fleet itself is `partout ctl hosts delete <id>` (revocation,
separate from the local uninstall).

## TLS / mTLS (optional; server runs `PARTOUT_TLS=on`)

1. **Enable on the server**: set `PARTOUT_TLS=on` in `/etc/partout/server.env` (and
   `PARTOUT_TLS_SERVER_NAMES=…` for the SANs) and restart. On first start the server
   generates a local root CA + its leaf under `<db dir>/tls/`.
2. **Distribute the CA** to each managed host (public material):
   ```bash
   scp /var/lib/partout/tls/ca.crt root@host:/etc/partout/ca.crt
   ```
   (or, from a host that has the admin token:
   `partout ctl --server 10.0.0.5:8443 --ca-file ca.crt --token $ADMIN ca > ca.crt`).
3. **Agent env**: set `PARTOUT_TLS_CA=/etc/partout/ca.crt` in `agent.env`. The agent then
   enrolls over HTTPS, ships a CSR, and stores the CA-signed client cert under
   `/var/lib/partout/agent/tls/` (key 0600). Subsequent restarts reuse it.
4. **Operator CLI**: `partout ctl --server host:port --ca-file ca.crt …` talks over HTTPS.

Plaintext mode (the default) works exactly as documented above; the single port serves
either TLS or h2c, not both.

## Architecture notes

- The server exposes gRPC + REST + SSE on a **single port** (default 8443).
  Plaintext uses Go 1.25's native h2c; with `PARTOUT_TLS=on` the same port serves TLS and
  the gRPC agent stream is **mTLS** (see `docs/architecture.md` §3.6).
- The agent connects **outbound only** — no inbound ports on managed hosts.
- The same binary is scp'ed to every host and runs in `--mode=agent`
  (v0.3 fleet-SSH provisioning does this via `partout ctl provision`; deployment §4.1).
- SQLite with WAL is the default storage; a Postgres backend is planned
  for v1.