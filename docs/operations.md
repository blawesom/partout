# Partout — Operations

**Status:** Draft v0.1 — day-2 runbook for the *planned* control plane. Reflects the
**v0.1.0 binary** where stated; steps for features that ship later are marked
*(proposed)*.
**Companion docs:** `PRD.md`, `docs/architecture.md`, `docs/deployment.md`

Day-2 guide for the Partout control plane: first-time setup, daily operations, backups, upgrades,
incident response, capacity, compliance, and a go-live checklist.

> **v0.1 reality check** (binary tag `v0.1.0`):
> - Auth is **bearer tokens** (`PARTOUT_TOKEN_ADMIN/OPERATOR/VIEWER`) or single-user local mode —
>   there is no `--create-admin` and no secret key store in v0.1.
> - Server state = the **SQLite file** (`PARTOUT_DB_PATH`, default `./partout.db`) plus
>   `<db dir>/tls/` when `PARTOUT_TLS=on` and `<db dir>/identity/` (server Ed25519 signing key,
>   v0.2). No output blobs, extern cache, spool, or Postgres yet.
> - Agent state = `<data dir>/identity.json` + `<data dir>/tls/` (mTLS leaf/key) +
>   `<data dir>/agent/` (cached policy bundle + server pubkey, v0.2).
> - **v0.2.0 adds the policy deny-list engine** (rule CRUD, dispatch gating, signed decisions,
>   agent re-check). Steps below marked *(v0.2)* are live on tag `v0.2.0`.
> - **v0.3 adds host provisioning over fleet SSH** (PRD R17): `partout ctl provision new
>   --host user@host` (server-side 5-step run, `key_confirm` gate). New vars
>   `PARTOUT_SSH_DIR` / `PARTOUT_SERVER_HOST` (deployment §4.1).
> - No Web UI in v0.1: use `partout ctl` or REST/SSE (`docs/deployment.md` §4).
> - Not wired in v0.3 (planned, see deployment §4.4): `PARTOUT_SECRET_KEY*`,
>   `PARTOUT_ELEVATE`/`PARTOUT_ROOT` (elevation hardcoded `none`), `PARTOUT_SPOOL_*`,
>   `PARTOUT_RETENTION_*`, `PARTOUT_MAX_*`, `PARTOUT_DISABLE_EXTERNAL_DATA_REFRESH`,
>   `PARTOUT_MCP_ENABLED`, `PARTOUT_LOG_LEVEL`.

---

## 1. State inventory

Where everything lives (for backup/restore/troubleshooting):

| Component | Path / Resource | Notes |
|---|---|---|
| Server DB | `PARTOUT_DB_PATH` (default `./partout.db`; `db.partout` when using `PARTOUT_DATA_DIR`) | SQLite WAL *(Postgres proposed)*; `<db dir>/tls/` holds the CA + server leaf when `PARTOUT_TLS=on` |
| Server output blobs | `PARTOUT_DATA_DIR/output/` | large command output, session recordings; retention-bounded *(P)* |
| Server extern cache | `PARTOUT_DATA_DIR/extern/` | EOL dates, vulnerability data *(P)* |
| Secret key | `PARTOUT_SECRET_KEY_FILE` (mode `0600`) | **critical** — losing it = lost secret store (PRD §5.7) *(P)* |
| Server config | `/etc/partout/server.env` (systemd) | env vars (PRD R15) |
| Server SSH dir | `PARTOUT_SSH_DIR` (default: service user's `$HOME/.ssh`) | fleet keys + `known_hosts` used for provisioning (R17) — **critical asset**: server compromise ⇒ fleet-key exposure *(P)* |
| Server UI/API | `http(s)://:8443` | main listener |
| Agent identity | `/var/lib/partout/agent/identity.json` (0600) | **critical** — losing = re-enroll with new keypair |
| Agent TLS | `/var/lib/partout/agent/tls/` (0700) | CA, CA-signed leaf (0644), private key (0600) — mTLS material *(v0.1, when `PARTOUT_TLS_CA` set)* |
| Agent spool | `/var/lib/partout/agent/spool.db` | in-flight results, job state *(P)* |
| Agent config | `/etc/partout/agent.env` | env vars |
| Provision runs | DB `provision_runs` + `provision_steps` (v0.3) | per-run state + per-step excerpts; `key_line`/`token_hash` are never serialized over the API; captured in the DB backup |
| Audit log | DB `audit_events` + optional exported sink | append-only, indefinitely retained (PRD §9) |
| Agents | `systemctl status partout-agent` | logs in `journalctl -u partout-agent` |

---

## 2. First-time setup (day-0)

Step-by-step bring-up, also referenced in deployment §6:

1. **Install the server** (§3.1 of deployment). Create the `partout` system user. Start the
   systemd unit. `journalctl -u partout-server` should show a clean startup: DB ready,
   listener on the configured port. *(v0.1: no secret key; if `PARTOUT_TLS=on` the local CA
   bootstrap runs here.)*
2. **Set RBAC bearer tokens** (v0.1): put `PARTOUT_TOKEN_ADMIN`, `PARTOUT_TOKEN_OPERATOR`,
   `PARTOUT_TOKEN_VIEWER` in `/etc/partout/server.env` and restart. *(Proposed, not in v0.1:
   `--create-admin=<name>` interactive password bootstrap.)*
3. **Verify the health endpoint**: `curl -sf http://localhost:8443/healthz` should return 200.
   *(The Web UI is proposed — not in v0.1; use `partout ctl` or REST/SSE.)*
4. **Create a baseline policy** *(v0.2 — implemented on tag `v0.2.0`; the engine is a
   default-allow deny-list, and `require_approval` acts as a hard deny until the M4 approvals
   engine)*:
   - Rule 1: `deny` on the commands you never want run (e.g. `rm -rf`, `mkfs`, `shutdown`).
   - Rule 2: `deny` host-scoped, e.g. `--hosts 'tag:env=prod' --command-regex 'restart'`.
   - Rule 3: `deny` actor-scoped, e.g. `--actor-roles operator --command-regex '…'`.
   ```bash
   partout ctl --server … --token $ADMIN policy create \
     --name no-destructive --effect deny --command-regex 'rm\s+-rf|mkfs|shutdown'
   ```
   Start restrictive; loosen later. The audit log captures everything
   (`policy.create`/`policy.delete`/`policy.deny`, PRD §5.8).
5. **Add your first host** *(fleet SSH provisioning, v0.3; manual install still works)*:
   - **v0.3 auto path** (fleet SSH): `partout ctl provision new --host user@host`
     starts the server-side run — a key_confirm gate pauses until the admin reviews
     and confirms the fingerprint, then preflight → scp binary → install unit → wait-enroll.
     `partout ctl provision get <id>` polls progress; `key <id> confirm` confirms.
   - **v0.1 manual path**: mint a token (`partout ctl enroll-token`), install the binary
     + agent unit on the host (§3.2) with that token.
   - Host should appear with facts in `<10 s` (PRD §5.1 acceptance).
6. **Run a test command**: `whoami` or `hostname` against the new host. Verify the audit log
   has a row with your principal.
7. **Enable alerts** for `host.state=disconnected` and `approval.request` — a control plane
   that can't alert on host status defeats the "observe → act → verify" loop.
8. **Backup** (`/var/lib/partout/server` + secret key file) **before onboarding more hosts**.

---

## 3. Day-to-day operations

### 3.1 Host lifecycle

- **Enroll / provision**: preferred (v0.3) — `partout ctl provision new --host user@host`
  (PRD R17): the server installs and starts the agent over the operator's existing fleet
  SSH; confirm the host-key fingerprint for hosts new to `known_hosts` (the run pauses at
  `key_confirm` until an admin confirms). Re-provisioning an installed host replaces the
  binary and unit and **keeps** the existing `identity.json` (idempotent in-place update).
  To force a brand-new identity, remove `/var/lib/partout/agent/identity.json` on the host
  first (the destructive `--mode fresh` wipe is not wired yet — architecture §3.5). Manual
  alternative: mint a short-TTL token → run enrollment on the host.
  Tags/roles assigned. Agent writes `identity.json` (0600); server marks `connected`.
- **Tag / role / group**: done in the UI, API, or via an MCP tool. Groups are saved
  selectors (PRD §5.1).
- **Revoke / decommission**: `DELETE /api/v1/agents/{id}` → stream closed, cascade-delete
  purges all host rows (PRD R7). The agent's `identity.json` on the host is useless
  (re-enrollment requires a fresh keypair). Keep a clean-up playbook: after revocation,
  remove any leftover tasks/jobs/policies targeting the host.

### 3.2 RBAC & users

- v1: local users only (PRD Decision 6). Roles: `viewer` (read-only), `operator` (exec,
  files, jobs, tasks, secret read-use, request approval), `admin` (all + principals + policy
  + approvals act).
- **v0.1**: auth is **bearer tokens** (`PARTOUT_TOKEN_ADMIN/OPERATOR/VIEWER`), not a user DB.
  No principals/identities yet — audit rows carry `actor` (token role) + agent id.
- OIDC is post-v1 (PRD Decision 6). Until then, manage the local user DB; remove
  departed operators promptly — every action is attributable.
- Periodic access review: export the audit log filtered by `principal` and check for
  stale principals with write access.

### 3.3 Policy & approvals

- Rules are declarative; the server evaluates them **before dispatch** *(v0.2)*, and the agent
  re-checks agent-side *(v0.2 — signature + bundle version + local re-eval; any mismatch →
  deny, `ACK_DENIED_AGENT`)* (architecture §5.3, defense in depth).
- **Approvals** *(M4 — not yet)*: will be scoped to the exact payload hash — a modified command
  needs a new request. Until then `require_approval` rules deny.
- **Editing a rule** *(v0.2)*: create/delete a rule; the server pushes a fresh bundle to all
  connected agents immediately (no reconnect needed). Bundles are versioned + content-hashed,
  and the agent's cached bundle persists under `<data dir>/agent/`.
- **Testing policy**: the UI dry-run is *(proposed — Web UI deferred)*; verify with
  `partout ctl policy list` and a test dispatch (a denied run records `state=denied` with the
  matched rule id(s) and reason).

### 3.4 Secrets management

- **Secret key backup**: `PARTOUT_SECRET_KEY_FILE` is the single point of truth for the
  encrypted secret store. **No in-place rotation in v1** (PRD: KMS/HSM is post-v1).
  Backup this file and consider a secure escrow (e.g. a hardware token, vault, or
  multi-party key-sharing scheme).
- **Secret rotation**: create a new version in the store; bind it to the target; prior
  bindings are invalidated (PRD §5.7). Audit records which version each run used.
- **Secret leak** (value exposed in command args): the audit log captures the full-fidelity
  command (PRD Decision 8, including no redaction). If a secret was leaked this way:
  1. rotate the secret immediately (invalidate prior bindings).
  2. review the audit log for all hosts/actors that ran the command.
  3. educate — secrets as command args are a usage error the audit surfaces, not a design
     flaw.
- **Offline TTL**: per-secret, default `0` (fail closed when server is unreachable). If you
  need short-lived offline access: `offline_ttl=300` (5 min) on the binding — the agent
  caches an encrypted copy for that window, versioned + audited.

---

## 4. Maintenance

### 4.1 Backups

| What | How | RPO target |
|---|---|---|
| Server DB (SQLite) | `sqlite3 db.partout ".backup '/backup/db.partout.bak'"` (atomic hot copy) or `cp` after WAL checkpoint | per-hour or nightly |
| Server output blobs | `rsync` or `cp -l` — large, append-only; prune by retention | daily |
| Extern cache | included in DB backup | nightly |
| Secret key file | encrypted offsite copy (GPG, HSM) | **always available** |
| Agent identity dir | optional — losing it = re-enroll with new keypair; backup for audit replay of session recordings (agent stores locally) | optional |
| Config files | version-controlled (git) | commit, not backup |
| Audit export (optional) | `GET /api/v1/audit?format=json | crontab → remote S3 / syslog / WORM | continuous |

**Restore**: stop the server, replace `db.partout` from backup, start. Migrations will run
forward. If the server was down longer than the retention window, some output/session data
may be gone (by design; PRD §9). The audit log (the immutable record) is the recovery
anchor for forensics.

### 4.2 Upgrades

**Server upgrade**:
1. Download the new binary (verify SHA-256SUMS).
2. `systemctl stop partout-server` (short downtime is unavoidable — single-writer, no
   self-HA).
3. Replace the binary, `systemctl start partout-server`. Migrations auto-run at boot.
4. Verify: `GET /healthz` → 200; UI loads.

**Rollback**: restore the DB from backup + revert the binary + restart. Migrations are
one-directional.

**Agent upgrade**:
1. Pick a canary group (non-prod, or `role=web` subset if prod).
2. Deploy the new binary to canary hosts; restart the agent.
3. Check: stream reconnected, facts flowing, a dry-run command succeeded.
4. Roll out to remaining hosts in waves. Agent-side jobs continue uninterrupted during
   upgrade (the stream drops and reconnects; spool buffers results).

**Version skew tolerance** (deployment §7): agent N works against server N and N+1, and vice
versa. Rolling upgrades are safe in either order (server first is the standard path).

### 4.3 External data

- The server fetches daily at startup and on a daily cadence (PRD Decision 9). Manual
  refresh: `POST /api/v1/extern/refresh`.
- Air-gapped: `PARTOUT_DISABLE_EXTERNAL_DATA_REFRESH=true` disables all fetching; the last
  cached copy or the embedded EOL fallback applies (architecture §8).
- Check the logs for "extern refresh completed" or "extern refresh partial — previous cache
  retained" (all-or-nothing, PRD §6.3).

### 4.4 Spool management

- **Location**: `<agent data dir>/spool/` — one append-only log per spooled run
  (`<run_id>.sp`, mode 0600), plus in-memory hot tier.
- **Limits** (architecture §3.4 defaults, not currently env-tunable): 16 MB mem →
  128 MB disk → 24 h per-run TTL, drop-oldest.
- **Monitoring**: agent heartbeat includes spool usage (`spool_mem_bytes`,
  `spool_disk_bytes`); alert when disk usage grows toward the 128 MB cap.
- **Spool full / TTL expired**: the oldest spooled run is dropped wholesale; the
  server-side run stays `interrupted` with whatever output was already delivered
  (never silently `succeeded`).
- **Mitigate persistent overflow**: investigate why the agent can't flush (network
  path to server, server load) or keep outages short (< 24 h).

### 4.5 Retention & disk

- The retention sweeper (hourly, architecture A14) prunes output chunks and session records
  per PRD §9. Run `sqlite3 db.partout "SELECT count(*) FROM output_chunks WHERE created <
  datetime('now', '−30 days');"` to check how much is due for cleanup.
- **Disk budgeting** (rough): ~500 KB/hour/host for facts + heartbeats in audit; command
  output varies wildly (stream large logs to disk — architecture §13). Set retention
  conservatively for environments where you'll need audit replay.
- **Long-lived audit export**: for compliance, pipe audit rows to a sink the server can't
  modify (syslog, remote database, S3 with WORM bucket).

---

## 5. Monitoring the control plane itself

Partout observes **hosts**; you also need to observe the control plane:

- **Health**: `GET /healthz` (live, DB check), `GET /readyz` (DB + stream subsystem ready;
  proposed, architecture A13). Return 200 or 503 with a body.
- **Heartbeats**: every agent sends a heartbeat every minute; the server records last_seen.
  Alert on `last_seen > 5 min` (a flag in the host table; the observe layer fires a
  `host.state=disconnected` alert).
- **Log tail**: `journalctl -u partout-server -f` — monitor for "migrations failed",
  "secret key missing", "DB connection error", "extern refresh failed", "stream handler
  panic" (shouldn't happen — panic means a bug).
- **Dogfooding**: deploy the embedded agent on the server host — you'll have real-time
  observability of the host running Partout.
- **Metrics**: Prometheus / OTLP metrics export is a post-v1 enhancement (not in v1 scope;
  the alert channel + log tail is the v1 observability surface).

---

## 6. Incident runbooks

### 6.1 Host unreachable (agent disconnected)

```
1. Check the host: is it powered on, on the network, disk full?
2. On the host: systemctl status partout-agent; journalctl -u partout-agent --since "10 min ago"
   → look for "handshake failed: clock skew", "connection refused", "spool full".
3. Fix the root cause; restart: systemctl restart partout-agent
4. Verify: host state flips back to "connected" in <10 s; new command succeeds.
5. If the agent identity was lost/corrupted: re-enroll (§2).
```

### 6.2 Agent revocation → re-enrollment (new host)

```
1. DELETE /api/v1/agents/{old_id} → cascade-purges rows.
2. On the (same or new) host: remove the stale agent state, then re-provision:
   ssh <host> 'sudo rm -f /var/lib/partout/agent/identity.json'
   partout ctl provision new --host user@host        # fresh identity is generated
   (the destructive `--mode fresh` wipe is not wired yet, so remove identity.json
   explicitly — architecture §3.5). Or by hand: install the binary and run
   `partout --mode=agent --server=... --token=par_enr_new` (fresh token).
3. Agent generates a new keypair; writes identity.json (0600); connects.
4. Tag/role/group the host per your topology.
5. Verify: facts visible; a test command succeeds; audit shows new enrollment event.
```

### 6.3 Server down — agent behavior

What happens (by design — PRD §6.2, architecture §3.4):
- In-flight commands **keep running** on the host (the stream drop does not kill them).
- Their output + result spool locally (16 MB mem / 128 MB disk / 24 h TTL).
- No new commands can be dispatched (server is the dispatch origin).
- The server marks in-flight runs `interrupted` when the session ends.
- On reconnect, the agent drains its spool first; the replayed results re-finalize the
  `interrupted` runs to their true terminal state (at-least-once, deduped server-side).

**Post-restore recovery**:
1. Start the server; verify `GET /healthz` → 200.
2. Agents reconnect automatically (backoff) and drain their spools.
3. Check the agent reconnect logs and the host list: all agents should show
   `connected` within a few minutes; runs that were in-flight flip from `interrupted`
   to their final state as replays land.
4. Runs still `interrupted` after recovery (e.g. spool TTL/overflow dropped them) need a
   manual re-dispatch.

### 6.4 Policy misconfiguration (lockout)

Scenario: a rule inadvertently denies all write access (e.g. `deny` on `all` selectors,
wrong predicate).

**Recovery path (preserves invariants — no escape hatch; PRD §7, architecture §5.3)**:
1. If the server is still reachable: edit the policy via the UI/API/MCP (remove/fix the
   rule; publish the new bundle). The server pushes the updated bundle to agents; re-check
   should allow the actions.
2. If the server is **unreachable** AND the agent's cached bundle denies everything:
   scheduled jobs fail closed (architecture §5.3). This is intentional — a stale bundle that
   over-denies is safer than the alternative (no guarantee the old bundle is correct).
   Recovery requires server availability (restore from backup) or a planned restart of
   agents with a locally-supplied policy bundle (future: `--policy-bundle` flag, not in
   v1 scope).
3. **Prevention**: test policy changes in a staging environment; use the UI's "dry-run"
   preview for selectors and actions.

### 6.5 Master secret key loss / leak

- **Loss**: the secret store is still in the DB, but no new secrets can be encrypted (no
  master key to derive per-secret keys). The feature is effectively unusable. **No in-place
  rotation in v1** (KMS/HSM is post-v1).
  Recovery: create a new secret key; the server's encrypted store is now unusable with the
  new key. You must **re-create all secrets** from scratch (values are not derivable from
  the old store). The audit log remains intact (it records operations, not secret values).
- **Leak**: treat it as a security incident. Rotate the master key (loss of the store —
  re-create all secrets). Review audit logs for any unauthorized use.

### 6.6 Spool full (agent-side)

Symptom: spooled runs dropped wholesale (oldest first); their server-side runs stay
`interrupted` instead of reaching a final state.

```
1. On the host: check spool usage (agent heartbeat reports spool_mem_bytes /
   spool_disk_bytes; check disk: ls -la /var/lib/partout/agent/spool/*.sp)
2. Investigate: is the agent stuck in a loop producing output? Is the network path to
   the server down? How long is the outage (24 h TTL per run)?
3. If the agent is producing more than it can flush: fix the command causing large
   output (streaming already chunks at 64 KiB — the issue is usually the network or a
   huge one-off dump).
4. Monitor: set up an alert on spool disk usage growing toward 128 MB.
```

### 6.7 Clock skew > 300 s (handshake rejection)

Symptom: agent logs "handshake failed: clock skew" or server rejects `AuthProof`; agent
never connects.

```
1. Check time: timedatectl status (NTP should be running).
2. Fix: timedatectl set-ntp true; systemctl restart chronyd | ntpd; verify
   timedatectl shows "NTP synchronized: yes".
3. Restart: systemctl restart partout-agent.
4. If the agent is on a host with no NTP and can't install it: consider a one-time
   offset correction with `date -s` (manual) — the ±300s window is generous for
   a few minutes of drift.
```

---

## 7. Troubleshooting table

| Symptom | Likely cause | Fix |
|---|---|---|
| Agent never connects | Wrong `PARTOUT_SERVER` URL / TLS / network block | Verify URL, check `curl -v`, verify firewall egress to port |
| Agent TLS handshake fails | Missing/wrong `PARTOUT_TLS_CA`, or server leaf SAN doesn't match the address | Confirm `ca.crt` path on the host; add the address to `PARTOUT_TLS_SERVER_NAMES` and re-run the server; check agent log for cert errors |
| Operator CLI can't reach server over HTTPS | `--ca-file` missing / wrong, or server plaintext | Use `--ca-file <ca.crt>`; or the server isn't running `--tls on` (switch to `http://`) |
| Provision run failed at `preflight` | no sudo (`sudo -n` fails), non-systemd init, no host→server egress, disk full | follow the step's remediation text; fix on the host, re-run (idempotent). A `reach=no` failure means the host cannot open `<server>/healthz` — fix the firewall/NAT path |
| Provision run stuck at `key_confirm` | host key new to `known_hosts` | review the fingerprint (`partout ctl provision get <id>`), then `partout ctl provision key <id> confirm` (appends to `known_hosts`) or `deny` |
| `provision key ... confirm` returns 409 `not_pending` | the run already left `key_confirm` (duplicate submit, or another admin confirmed/denied) | re-`get` the run; nothing to do — confirm is idempotent-safe |
| `provision key ... confirm` says "lost its state machine (server restart)" | the server restarted while the run was paused; the paused goroutine is gone | re-run `partout ctl provision new --host <host>` (the old run is marked `failed`) |
| Provision `enrolling` timed out | agent installed but never enrolled (stale token, firewall to server) | `journalctl -u partout-agent` on the host; re-run the provision (install is idempotent) |
| "handshake failed: clock skew" | Host clock drifted >300 s | Sync NTP, restart agent (runbook 6.7) |
| "token expired" / "token consumed" | Token already used or TTL expired | Re-mint a fresh token (UI/API) |
| Command shows `not_delivered` | Agent was offline past dispatch TTL (default 15 min, A5) | Re-dispatch or retry the command; increase TTL if needed |
| Command shows `denied_agent` | Agent-side guardrail re-check failed (policy mismatch or rule deny) | Check policy bundle version; review agent logs for the denial reason; fix the rule |
| No output in the UI for a running command | SSE client disconnected or broker dropped the client | Refresh the page; output chunks are persisted and replayable within the retention window |
| `result_lost` in the audit | Agent spool overflowed before the result could flush | Increase spool size; investigate root cause of overflow |
| `version_mismatch` on the host | Server and agent versions are beyond compatibility skew | Upgrade the agent to match the server (or vice versa) |
| "secret key missing" at startup | `PARTOUT_SECRET_KEY_FILE` or `PARTOUT_SECRET_KEY` not configured | Set the key; the secrets feature is disabled until then |
| `apply-updates` fails on `ended` host | EOL gate (host is past end-of-support, defaults to require-approval) | Approve manually or remove the EOL gate from the rule |
| Policy stale → jobs fail closed | Agent hasn't received a fresh bundle in >48 h (A8), server unreachable | Restore server; agents will fetch the bundle on reconnect |
| Empty selector → no hosts affected | No hosts match the selector predicates | Check the live resolution preview in the UI before dispatch |
| Output too large → UI hangs | Command producing >16 MB output (PARTOUT_MAX_OUTPUT_MB) | Reduce output or increase the limit |

---

## 8. Capacity planning

### 8.1 Target numbers (architecture §13)

| Metric | Target | Tuning knob |
|---|---|---|
| Agents | 500 on 2 vCPU / 4 GB | More agents → scale server CPU/RAM; streams are cheap (idle) |
| SSE clients | 100 concurrent browsers | Buffer size, fan-out goroutines (default fine) |
| Concurrent runs per host | 4 | `PARTOUT_MAX_CONCURRENT_RUNS_PER_HOST` |
| Output per day (500 hosts) | 1–5 GB (varies) | Set retention; archive output to object storage post-v1 |
| Audit rows per day (500 hosts) | ~5–20 k (light traffic) | Export to sink; no auto-purge (operator-configurable floor) |

### 8.2 When to migrate to PostgreSQL

- >10k agents OR audit rows >50 M (SQLite can handle this but write contention increases).
- Operator requirements: remote DB hosting, replication, existing Postgres tooling.
- The migration is a DDL operation (one direction, PRD R9); the store abstraction means the
  application code doesn't change.

### 8.3 Disk budgeting

- **DB**: ~2–5 MB/100 hosts/week of audit. At 500 hosts with light activity (~100 runs/day):
  ~1–2 GB/month.
- **Output blobs**: the biggest variable. 500 hosts × 2 MB avg command output × 10 runs/day
  = 10 GB/day; set retention and/or archive to S3.
- **Spool**: 128 MB per agent on the host (configurable); total = 128 MB × N agents.

---

## 9. Compliance

- **Audit trail**: every action attributed to a principal with the full-fidelity record
  (privileged commands recorded as-is, no redaction, PRD Decision 8). Retain indefinitely
  by default; export via `GET /api/v1/audit` to your compliance sink.
- **Access review**: quarterly export of principals and roles; remove departed staff.
  No anonymous write surface (PRD invariant 2).
- **Retention**: operator-configurable floors for audit and secret versions (PRD §9).
- **Data minimization**: no host identity or operator data leaves the network to external
  data sources (PRD invariant 5); vulnerability correlation uses only package identifiers.
- **Encryption in transit**: TLS at the gRPC listener — `PARTOUT_TLS=on` bootstraps a local
  root CA + server leaf (§3.6); the agent stream is mTLS (client cert from enrollment), REST
  uses bearer auth. Plaintext `h2c` is the local-dev default only.
- **Encryption at rest**: secrets encrypted at rest with HKDF-derived keys (PRD §5.7);
  audit log is plaintext DB (DB access is the trust boundary; restrict OS-level access).
- **Access controls**: RBAC roles (`viewer|operator|admin`); policy engine deny-by-default
  for writes (architecture A6); defense-in-depth with agent-side re-check (architecture §5.3).

---

## 10. Go-live checklist

v0.1 items first; items marked *(P)* are proposed and track later milestones.

- [ ] Server installed, systemd unit active, `GET /healthz` returns 200
- [ ] RBAC bearer tokens set (admin/operator/viewer) and verified (`/api/v1/hosts` → 401 without, 200 with)
- [ ] TLS enabled if exposing beyond localhost (`PARTOUT_TLS=on`); CA fetched via `partout ctl ca`; `ca.crt` in the agent env
- [ ] ≥1 agent enrolled; facts visible <10 s; test command executed and audited (`partout ctl run`)
- [ ] Backup runbook tested: DB + `<db dir>/tls/` restored from backup; audit log intact
- [ ] Upgrades tested on a non-prod host: new binary → restart → reconnect → command works
- [ ] *(P)* Admin principal / password bootstrap (v0.1 uses bearer tokens only)
- [ ] *(P)* Secret key file set and **backed up** (encrypted offsite) — secret store feature
- [ ] *(P)* Baseline policy: deny on elevation, require-approval on patch, allow-list for routine
- [ ] *(P)* Alert channels configured: host state (disconnected), approval request
- [ ] *(P)* Capacity baseline: disk usage recorded; retention set; spool limits appropriate
- [ ] *(P)* Access review process documented (who gets operator/admin, quarterly review)
- [ ] *(P)* Air-gap mode tested (if applicable): `PARTOUT_DISABLE_EXTERNAL_DATA_REFRESH=true`
- [ ] Operator training: UI tour for hosts, execute, sessions, jobs, tasks, updates, secrets,
  policy, audit, observe pages
- [ ] Runbooks accessible: this document published to the team's knowledge base

---

## 11. Post-v1 roadmap (operations-relevant)

| Feature | Ops impact |
|---|---|
| Cryptographic hash-chain for audit (§15.1, Decision 5) | Tamper evidence at rest; WORM becomes verifiable |
| OIDC integration (Decision 6) | Enterprise SSO / SAML / SCIM provisioning |
| KMS/HSM for secrets (PRD §5.7) | In-place secret-key rotation; multi-party escrow |
| Self-HA (PRD §13 non-goal) | Multi-region failover, automatic leader election |
| Metrics export (Prometheus / OTLP) | Integrated monitoring via your existing stack |
| Remote output archival to object storage | Offload from server disk; longer retention at lower cost |
| `--policy-bundle` local override (agent) | Emergency bypass for agent-side policy lockout (runbook 6.4) |
