# Partout — Operations

**Status:** Draft v0.6 — day-2 runbook for the control plane. Reflects the current
implementation (M0–M6 complete, Web UI shipped, M7-remainder in progress) where stated;
steps for features that ship later are marked *(proposed)*.
**Companion docs:** `PRD.md`, `docs/architecture.md`, `docs/deployment.md`

Day-2 guide for the Partout control plane: first-time setup, daily operations, backups, upgrades,
incident response, capacity, compliance, and a go-live checklist.

> **v0.3 reality check** (current implementation):
> - Auth is **local users** (login → session token; first-run admin bootstrap) **plus**
>   static bearer tokens (`PARTOUT_TOKEN_ADMIN/OPERATOR/VIEWER`) for CLI/scripts; with no
>   users and no tokens, single-user local mode.
> - Server state = the **SQLite file** (`PARTOUT_DB_PATH`, default `./partout.db`) plus
>   `<db dir>/tls/` when `PARTOUT_TLS=on` and `<db dir>/identity/` (server Ed25519 signing
>   key). External data cache is in-DB (`eol_cache`/`vuln_cache`); Postgres is not wired.
> - Agent state = `<data dir>/identity.json` + `<data dir>/tls/` (mTLS leaf/key) +
>   `<data dir>/agent/` (cached policy bundle + server pubkey) + `<data dir>/spool/`
>   (offline spool).
> - **v0.2.0 adds the policy deny-list engine** (rule CRUD, dispatch gating, signed decisions,
>   agent re-check).
> - **v0.3 adds host provisioning over fleet SSH** (PRD R17) plus the M2/M3 features:
  files & sessions, secrets, external data, packages, tasks/playbooks, scheduled jobs.
- **M5 (done)**: observe layer — service/config/cert fact collectors upload
  structured JSON via `OBSERVE_FACTS` gRPC envelope (M5). Server-side `observe/`
  upserts into `host_facts` JSON. Read-only API endpoints (`/services`,
  `/certificates`, `/configs`). No alerting yet (alert engine is M6).
- **M6** (planned): alert engine — threshold rules, evaluation, firing/resolved states,
  SSE fan-out. Alert store (`alerts`, `alert_rules` tables).
- **M7 (partial, v0.5)**: UI pages — the embedded Web UI now ships the Observe
  Services/Certificates/Configs data pages (plus the M1–M5 control-plane pages); the remaining
  M7 scope (cross-links, task actions, Active Alerts section) is still open.
- **M8** (planned): Distribution & polish — installers, cloud-init, Helm.
> - **M4 in progress**: local user auth (login, sessions, user management) is done; the
>   approvals engine, full policy surface, and MCP server are still to come.
> - **Web UI shipped (v0.5)**: open the main listener in a browser and log in
>   (`docs/deployment.md` §6 step 8). `partout ctl` / REST / SSE remain available for scripts.
> - Not wired (planned, see deployment §4.4): `PARTOUT_ELEVATE`/`PARTOUT_ROOT` (elevation
>   hardcoded `none`), `PARTOUT_SPOOL_*`, `PARTOUT_RETENTION_*` (except
>   `PARTOUT_SESSION_RETENTION_DAYS`), `PARTOUT_MAX_*`, `PARTOUT_MCP_ENABLED`,
>   `PARTOUT_LOG_LEVEL`.

---

## 1. State inventory

Where everything lives (for backup/restore/troubleshooting):

| Component | Path / Resource | Notes |
|---|---|---|
| Server DB | `PARTOUT_DB_PATH` (default `./partout.db`) | SQLite WAL *(Postgres proposed)*; `<db dir>/tls/` holds the CA + server leaf when `PARTOUT_TLS=on`; `<db dir>/admin_password.txt` (0600) holds the first-run admin password until rotated |
| Server output / recordings | DB `output_chunks` + `session_records` | command output chunks and PTY session recordings, retention-bounded (PRD §9) |
| Server extern cache | DB `eol_cache` + `vuln_cache` | EOL dates and vulnerability data (architecture §8) |
| Secret key | `PARTOUT_SECRET_KEY_FILE` (mode `0600`) or `PARTOUT_SECRET_KEY` | **critical** — losing it = lost secret store (PRD §5.7) |
| Server config | `/etc/partout/server.env` (systemd) | env vars (PRD R15) |
| Server SSH dir | `PARTOUT_SSH_DIR` (default: service user's `$HOME/.ssh`) | fleet keys + `known_hosts` used for provisioning (R17) — **critical asset**: server compromise ⇒ fleet-key exposure |
| Server UI/API | `http(s)://:8443` | main listener |
| Agent identity | `/var/lib/partout/agent/identity.json` (0600) | **critical** — losing = re-enroll with new keypair |
| Agent TLS | `/var/lib/partout/agent/tls/` (0700) | CA, CA-signed leaf (0644), private key (0600) — mTLS material *(when `PARTOUT_TLS_CA` is set)* |
| Agent spool | `/var/lib/partout/agent/spool/` | in-flight output chunks + results buffered during a server outage (`<run_id>.sp`, 0600); replayed on reconnect |
| Agent config | `/etc/partout/agent.env` | env vars |
| Provision runs | DB `provision_runs` + `provision_steps` (v0.3) | per-run state + per-step excerpts; `key_line`/`token_hash` are never serialized over the API; captured in the DB backup |
| Audit log | DB `audit_events` + optional exported sink | append-only, indefinitely retained (PRD §9) |
| **Alerts** | DB `alerts` + `alert_rules` (M6) | alert rule definitions, firing/resolved states, severity levels |
| **Observe facts** | DB `host_facts` (M5) | JSON blob merged with basic facts; keys: `services_detailed`, `configs`, `certificates` |
| Agents | `systemctl status partout-agent` | logs in `journalctl -u partout-agent` |

---

## 2. First-time setup (day-0)

Step-by-step bring-up, also referenced in deployment §6:

1. **Install the server** (§3.1 of deployment). Create the `partout` system user. Start the
   systemd unit. `journalctl -u partout-server` should show a clean startup: DB ready,
   listener on the configured port. *(If `PARTOUT_SECRET_KEY_FILE`/`PARTOUT_SECRET_KEY` is
   set the secret store enables here; if `PARTOUT_TLS=on` the local CA bootstrap runs here.)*
2. **Set up auth**: on first run the server bootstraps an `admin` local user
   (PRD Decision 6). Either pre-seed it with `PARTOUT_ADMIN_PASSWORD`
   in `/etc/partout/server.env`, or read the generated password from
   `<db dir>/admin_password.txt` (0600), then **log in, change the password, and delete the
   file**. Static env tokens (`PARTOUT_TOKEN_ADMIN`, `PARTOUT_TOKEN_OPERATOR`,
   `PARTOUT_TOKEN_VIEWER`) still work side-by-side for the CLI/scripts.
   ```bash
   # CLI login (stores the session token in ~/.config/partout/token):
   partout ctl --server … auth login --username admin --password …
   # or keep using a static token:
   partout ctl --server … --token $ADMIN …
   ```
3. **Verify the health endpoint**: `curl -sf http://localhost:8443/healthz` should return 200.
   Open `http://localhost:8443/` in a browser to reach the Web UI (log in as the admin user).
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
   - **Manual path**: mint a token (`partout ctl enroll-token`), install the binary
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
  `key_confirm` until an admin confirms). `fresh` mode (default) is a **destructive wipe**:
  it stops + disables any existing `partout-agent` unit and removes its identity + env, so
  the reinstall enrolls as a brand-new agent. `--mode update` keeps the existing
  `identity.json` (idempotent in-place update). Manual alternative: mint a short-TTL token →
  run enrollment on the host.
  Tags/roles assigned. Agent writes `identity.json` (0600); server marks `connected`.
- **Tag / role / group**: done in the UI, API, or via an MCP tool. Groups are saved
  selectors (PRD §5.1).
- **Remove / revoke**: `DELETE /api/v1/hosts/{id}` (admin) — UI “Remove host”,
  `partout ctl hosts delete <id>`, or the MCP `delete_host` tool. The server deletes the
  agent row (cascade-delete purges the host's runs, sessions, files, facts, tags, roles —
  PRD R7) and, if the agent is still streaming, pushes a `REVOKE` envelope: the agent logs
  “revoked by server” and exits **cleanly (exit 0, no systemd crashloop)**. Removal doubles
  as revocation — the store row is gone, so the agent can never re-authenticate again, even
  a rogue one holding its private key. The machine's files are untouched by default; set
  `PARTOUT_AGENT_CLEANUP_ON_REVOKE=1` on the agent to also wipe its local `identity.json` +
  `tls/` on revoke (destructive, opt-in). To reuse the machine, re-provision it in `fresh`
  mode. Keep a clean-up playbook: after removal, remove any leftover tasks/jobs/policies
  targeting the host.
- **Full uninstall (local or remote)**: to remove Partout entirely from a machine
  (units, env, state, binary, user) run `sudo partout uninstall --purge` on it —
  `--dry-run` previews the plan first; the default (no `--purge`) keeps the state
  dir (deployment.md §3.11). For a managed host you don't have shell access to,
  dispatch it through the fleet: `partout ctl run --agent <id> -- sudo partout
  uninstall --purge` (the command survives its own cgroup SIGTERM), or revoke
  first (`hosts delete`) then give the operator the one-liner for the console.

### 3.2 RBAC & users

- v1: local users only (PRD Decision 6). Roles: `viewer` (read-only), `operator` (exec,
  files, jobs, tasks, secret read-use, request approval), `admin` (all + principals + policy
  + approvals act).
- Auth is **local users** (login → session token) **plus** static bearer tokens
  (`PARTOUT_TOKEN_ADMIN/OPERATOR/VIEWER`) working side-by-side; audit rows carry the
  authenticated principal (user name or token role).
- OIDC is post-v1 (PRD Decision 6). Until then, manage the local user DB; remove
  departed operators promptly — every action is attributable.
- Periodic access review: export the audit log filtered by `principal` and check for
  stale principals with write access.

### 3.3 Policy & approvals

- Rules are declarative; the server evaluates them **before dispatch** *(v0.2)*, and the agent
  re-checks agent-side *(v0.2 — signature + bundle version + local re-eval; any mismatch →
  deny, `ACK_DENIED_AGENT`)* (architecture §5.3, defense in depth).
- **Approvals** *(M4 — shipped)*: scoped to the **exact payload** — a modified command needs a
  new request. A `require_approval` match parks the action (exec runs `awaiting_approval`;
  package apply → `202 {approval_required, approval_id}`); an **admin** acts via
  `GET/POST /api/v1/approvals[/{id}[/approve|deny]]` (list = viewer, decide = admin).
  Approve signs a fresh `EffectAllow` decision carrying the approval id and re-dispatches the
  stored payload; the agent guardrail honors it (a local hard deny still wins). Requests
  expire after `PARTOUT_APPROVAL_TTL_S` (default 1 h) and can never be retroactively
  honored — the parked run/row finalizes `failed` (per surface). Every policy-
gated surface has an approval path: exec, pkg.apply, files (upload/edit/perm —
  bodies staged in `<dbdir>/filestaging/` 0600), sessions, tasks, jobs manual
  RunNow. Secrets are a server-side vault (RBAC-only; no host action class).
- **Editing a rule** *(v0.2)*: create/delete a rule; the server pushes a fresh bundle to all
  connected agents immediately (no reconnect needed). Bundles are versioned + content-hashed,
  and the agent's cached bundle persists under `<data dir>/agent/`.
- **Testing policy**: the UI dry-run is *(proposed — Web UI deferred)*; verify with
  `partout ctl policy list` and a test dispatch (a denied run records `state=denied` with the
  matched rule id(s) and reason).

### 3.4 Observe layer & alerts (M5 done, M6 engine shipped)

- **Fact collection cadence**: service facts refresh every 5 min, config facts every 15 min
  or on mtime change, cert facts every 1 hour. Configurable via
  `PARTOUT_OBSERVE_FACTS_INTERVAL` (default 300s; individual collectors may differ).
- **Config fact validity**: `haproxy -c` and `nginx -t` run on each refresh; a failed
  validation fires a `config_invalid` alert and is flagged in the config UI.
- **Config drift**: shipped (R22) as the `config_drift` rule kind — each host's
  `config_sha256` is compared against the fleet majority (lexicographic tie-break)
  and a minority host alerts. `config_drift_tolerance` (default 0) allows that many
  competing hashes before anything is flagged.
- **Certificate expiry tracking**: the server computes `days_remaining` from each cert's
  `not_after` epoch. `cert_expiring` fires at or below the rule's `cert_days_remaining`
  threshold (default 30). `cert_chain_broken` is M6.1+ (A21).
- **Service health**: `service_failed` fires when a unit is in `failed` state and has
  stayed there for the rule's `service_failed_minutes` (default 5; set 0 for immediate).
  Restart-loop detection (`service_restarting`, M6.1) uses the systemd `NRestarts`
  counter the agent now collects: the server computes a rate (restarts/hour) over the
  interval between counter movements and fires at or above
  `service_restart_rate_per_hour` (default 10), resolving after the unit has been
  quiet for 10 minutes.
- **Alert engine** (M6): server-side only (PRD Decision 16) — ticks every
  `PARTOUT_ALERT_TICK_S` (default 30 s) over one bulk `host_facts` read; dedup key is
  rule|host|subject (unit name / cert path / config kind) so a flapping condition yields
  one alert that re-arms on recurrence; missing facts fail soft (they neither fire nor
  resolve). Every transition is audit-logged (`alert` events) + SSE-broadcast
  (`alert.firing` / `alert.resolved`).
- **Alert rule CRUD** (M6): `GET /api/v1/alerts/rules` (viewer) + `POST/PUT/DELETE`
  (operator) + `GET /api/v1/alerts[?state=&severity=]` (viewer). CLI:
  `partout ctl alerts list [--state firing] [--severity critical]` and
  `partout ctl alerts rules`. MCP read tool: `list_alerts`.

### 3.5 Secrets management

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
| Server DB (SQLite) | **Shipped:** `scripts/backup.sh` + `deploy/systemd/partout-backup.timer` (daily, `Persistent=true`, retention 14) — atomic hot snapshot via `partout ctl db-backup` (VACUUM INTO; no sqlite3 CLI needed, server may be running). Manual: `partout ctl db-backup <db> <out>`, or `sqlite3 partout.db ".backup '…'"` | per-hour or nightly |
| Server output / recordings | in-DB (`output_chunks` + `session_records`); included in the DB backup | daily |
| Extern cache | in-DB (`eol_cache` + `vuln_cache`); included in the DB backup | nightly |
| Secret key file | encrypted offsite copy (GPG, HSM) | **always available** |
| Agent identity dir | optional — losing it = re-enroll with new keypair; backup for audit replay of session recordings (agent stores locally) | optional |
| Config files | version-controlled (git) | commit, not backup |
| Audit export (optional) | `GET /api/v1/audit?format=json | crontab → remote S3 / syslog / WORM | continuous |

**Restore**: stop the server, replace `partout.db` from backup, start. Migrations will run
forward. If the server was down longer than the retention window, some output/session data
may be gone (by design; PRD §9). The audit log (the immutable record) is the recovery
anchor for forensics.

### 4.2 Upgrades (M8.1: signed one-command)

**The standard path (v0.8.0+): `partout update`** — server + fleet to N+1 in one
command, one status line at the end:

```sh
# operator env (the only component that ever touches the internet):
export PARTOUT_RELEASE_KEY=<ed25519 pub> PARTOUT_RELEASE_REPO=https://releases.example.com/partout
partout update --check     # report-only: current vs target, what would happen
partout update             # fetch -> verify both artifacts -> supervised server
                           # swap -> publish agent artifact -> canary -> waves -> DONE
```

How it supervises each hop:
- **Artifacts** are verified against `PARTOUT_RELEASE_KEY` before anything is
  touched (fail closed). The GitHub tarballs are *not* signed releases — the
  release repo (`<repo>/latest` + `<repo>/<v>/partout-<v>-<arch>-{server,agent}[.sig]`)
  is the update path.
- **Server**: `scripts/update-server.sh` — signature verify, `partout selftest`
  on the new binary *on this host*, proven `VACUUM INTO` backup, swap with
  `.prev` retention, ~60 s post-check window, automatic rollback on any
  failure (the backup is preserved outside the temp dir).
- **Fleet**: canary cohort → waves (`--canary`, `--wave`). A canary failure is
  a hard gate (run → `failed`); a wave failure pauses the run
  (`paused_failure`) for retry/skip/abort. Hosts already at the target report
  `verified` without touching the binary, so re-runs converge.
- **Jobs**: when a host's verified version changes, the server re-signs and
  re-pushes its job decisions automatically — the old "re-save all jobs"
  step is gone.
- **Offline hosts**: the directive is queued durably (survives a server
  restart) and delivered on reconnect with a fresh artifact grant.
- **Stuck runs**: an `update_run` alert rule (default statuses
  `paused_failure,failed`) fires a server-level alert per stuck run.
- **Security**: a periodic scan (default 6 h, `PARTOUT_SECURITY_SCAN_S`) lists
  each connected host's pending updates and correlates the *installed*
  versions against OSV; the fleet Security card (Updates page) shows the top
  findings, and the `default-security-updates` preset rule alerts per host
  with a known CVE at CVSS ≥ 7 (high). Patch via the per-host Apply (or the
  M5.1b pre-armed patch plan, not yet shipped).
- **New releases**: uploading an agent release auto-creates a **parked**
  rollout draft (whole fleet, one canary — `PARTOUT_AUTO_DRAFT_ROLLOUTS=false`
  disables it). It dispatches nothing until you press **Start** on the Runs
  board (policy re-checked at start). The `default-update-drift` alert keeps
  nagging while any agent is behind the store's newest release.

`--server-only` is the two-phase mode (fleet later); an approval-parked run
reports the approval id and stops — approve it in the UI/CLI, then re-run
`partout update` to continue.

**First-time adoption (from v0.7.x)**: manual one-time swap — see
`docs/deployment.md` §2.1 (the one-command cannot roll out v0.8.0 itself;
a pre-0.8 agent ignores update directives by design).

**Manual fallback** (no release repo / air gap / debugging):
1. Download the new binary (verify SHA-256SUMS).
2. Server: keep `partout.prev`, optional `VACUUM INTO` snapshot, replace,
   `systemctl restart partout-server`. Migrations are additive and
   auto-run at boot; v0.7.x is forward-compatible with newer schemas, so
   rolling the binary back does not require restoring the DB.
3. Verify: `GET /healthz` → 200; `GET /api/v1/version` → new version.
4. Agents: replace + `systemctl restart partout-agent` per host (canary
   first). With the boot guard wired (deployment §3.2), a crashlooping new
   version rolls back to N-1 automatically.

**Version skew tolerance** (deployment §7): agent N works against server N
and N+1, and vice versa — an updated agent against a rolled-back server just
runs at N+1 unprompted. Rolling upgrades are safe in either order (server
first is the standard path). One direction is *not* skew: a pre-0.8 agent
cannot run an update (no directive handler) — the manual hop first.

### 4.3 External data

- The server fetches daily at startup and on a daily cadence (PRD Decision 9). Manual
  refresh: `POST /api/v1/external-data/refresh` (admin).
- Air-gapped: `PARTOUT_DISABLE_EXTERNAL_DATA_REFRESH=true` disables all fetching; the last
  cached copy or the embedded EOL fallback applies (architecture §8).
- Check the logs for "extern refresh completed" or "extern refresh partial — previous cache
  retained" (all-or-nothing, PRD §6.3).

### 4.4 Spool management

- **Location**: `<agent data dir>/spool/` — one append-only log per spooled run
  (`<run_id>.sp`, mode 0600), plus in-memory hot tier. With the shipped units that is
  `/var/lib/partout/agent/spool/` (`PARTOUT_DATA_DIR` is already the per-agent root).
- **Startup**: if the spool directory cannot be created the agent exits with
  `offline spool unavailable` — it never starts in a mode where a disconnect would
  silently discard results.
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
  per PRD §9. Run `sqlite3 partout.db "SELECT count(*) FROM output_chunks WHERE created <
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
- **Dogfooding**: deploy the [local] agent on the server host (a `partout-agent`
  unit alongside `partout-server`) — you'll have real-time observability of the host
  running Partout. Add alert rules for `partout-server`/`partout-agent` failed plus
  your edge (e.g. `haproxy.service`) and the edge's certs. **Limitation:** the alert
  engine is server-side, so it cannot fire when the control plane itself dies — keep
  an external observer (cron from another host hitting `/healthz`, or a second fleet
  member) for that case.
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

### 6.8 Update rollout stuck (M8.1)

Symptom: `update.run` alert firing, or the Updates → Runs board shows a run in
`failed` / `paused_failure` / a host stuck `dispatching` or `timed_out`.
Inspect: `partout ctl update show <run_id>` (per-host status + error) and the
host's agent log.

Decision tree:

- **Canary host `failed_rollback`** — the run is `failed` (hard gate); no
  hosts beyond the canary were touched. Read the host error:
  - `verify: ... signature verification FAILED` → key mismatch between the
    release repo and the agent's `PARTOUT_RELEASE_KEY`. Fix the key (or the
    release), `update abort`, re-run.
  - `no release key provisioned` → the agent env is missing
    `PARTOUT_RELEASE_KEY`. Fix env + restart the agent unit, then
    `update abort` + re-run.
  - host is unhealthy for unrelated reasons → exclude it (deny policy rule
    `host:<id>` or a tag) and re-run; or fix the host, abort, re-run.
- **Wave host `failed_rollback`, run `paused_failure`** — pick per host:
  - transient (network blip, host rebooted mid-update) →
    `partout ctl update retry <run_id>` (re-dispatches failed + timed-out
    hosts with fresh grants).
  - host has a real problem you want to work around →
    `partout ctl update skip <run_id>` (marks it `skipped`, the next wave
    proceeds) — then fix the host and update it later.
  - artifact itself is bad → `partout ctl update abort <run_id>`. Do not
    retry: every host will fail the same way. Delete/fix the release
    (`ctl update list` + upload a corrected one) and start a new run.
- **Host `timed_out` (no result within 15 min)** — usually the host was
  offline at dispatch and has not reconnected. Verify connectivity + agent
  state, then `update retry`. (If the host reconnected while the row was
  still live, the queued directive would already have been delivered.)
- **Run `pending_approval`** — a policy rule requires approval for
  `update.apply`. Approve (UI → Approvals, or `ctl approvals`) — the run
  resumes automatically once approved.
- **Fleet-wide rollback to N-1** — start a new run against the N-1 release
  (it must still be in the release store — releases are retained until you
  delete them; there is no automatic GC). The server side is separate: if
  the supervised server swap rolled back on its own, the binary is already
  N-1; if you need the DB, restore the pre-swap backup it preserved
  (`partout-backup-rollback-*.db` in the DB dir) or the scheduled backup.
- **Server swapped but a fleet host is still N** — expected mid-rollout state
  and safe: N agents against an N+1 server work fine (skew tolerance).
  Finish or abort the run; the mixed state converges either way.

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
| No observe facts in `GET /services` | Agent hasn't uploaded structured facts yet; check agent logs for `observe` errors; verify `PARTOUT_OBSERVE_FACTS_INTERVAL` is set | Check `journalctl -u partout-agent` for observe collector errors; ensure `OBSERVE_FACTS` envelope is not dropped |
| Config validation reports invalid but service is running | The collector runs validation on refresh cadence (15 min); a recent config change may not have been picked up yet; or the service is running but would fail on reload | Run `haproxy -c` or `nginx -t` manually on the host; check if the issue is transient (e.g. port conflict) |
| Certificates show `chain_checked: false` | No trust bundle was found on the host (or `PARTOUT_CERT_CA` points at a missing file), so `openssl verify` was skipped | Set `PARTOUT_CERT_CA` to the host's bundle, or install the distro CA package. Unchecked ≠ broken: do not alert on `chain_valid` alone |
| A certificate shows `days_remaining: 0` | Its expiry date failed to parse (`not_after: 0` = unknown), not "expires today" | Inspect the file with `openssl x509 -noout -dates -in <path>`; a malformed/hostile cert is the usual cause. Filters exclude unknown expiry by design |
| Only some certificates are listed | Discovery is capped (512 files per collection; >1 MiB files and symlinks skipped) and restricted to `/etc/ssl`, `/etc/pki/tls` plus `PARTOUT_CERT_PATHS` | Add the deployment's cert directory to `PARTOUT_CERT_PATHS`. Raise the cap only if the host genuinely needs it |
| Observe facts stop updating on a busy host | A collector subprocess hit its timeout, or collection is slower than `PARTOUT_OBSERVE_FACTS_INTERVAL` so overlapping ticks are skipped | Check agent logs; raise `PARTOUT_OBSERVE_FACTS_INTERVAL` if collection is legitimately slow, or narrow `PARTOUT_CERT_PATHS` |
| Services list looks empty though units are running | Custom-units-only filter: distro units are excluded unless labelled | Add the unit name to `PARTOUT_SERVICE_LABELS`, or place a unit file/drop-in under `/etc/systemd/system` |
| `version_mismatch` on the host | Server and agent versions are beyond compatibility skew | Upgrade the agent to match the server (or vice versa) |
| "secret key missing" at startup | `PARTOUT_SECRET_KEY_FILE` or `PARTOUT_SECRET_KEY` not configured | Set the key; the secrets feature is disabled until then |
| `apply-updates` fails on `ended` host | EOL gate (host is past end-of-support, defaults to require-approval) | Approve manually or remove the EOL gate from the rule |
| `packages list-updates` / `apply` fails with repo/GPG errors | The host's own package manager is broken (e.g. a third-party repo's GPG key is stale — `grafana`, `tailscale` are frequent offenders); `dnf` fails *silently* until `--disablerepo=…` is added | Fix the repo keys on the host (`rpm --import …`, or remove the broken repo); the package surface only reports what `dnf`/`apt`/`apk` report, it does not repair the host's repos |
| Policy stale → jobs fail closed | Agent hasn't received a fresh bundle in >48 h (A8), server unreachable | Restore server; agents will fetch the bundle on reconnect |
| A rebooted host's task run stays `rebooting` (never resumes) | The `resume-after-reboot` marker (`<data dir>/resume/<run_id>.json`) is only processed after the first policy bundle loads post-boot; a stale marker (host never actually rebooted, or reboot command lacked permission) is discarded and the run reported `failed` | Check agent logs for `resume:` lines; verify the agent user can reboot (root/sudo/polkit); confirm the marker file exists until processed, then check `job_runs`/`task_runs` for the final `trigger: resume` report |
| Run shows `awaiting_approval` and never dispatches | A `require_approval` rule matched; an admin must approve (or the request expired after `PARTOUT_APPROVAL_TTL_S`, default 1 h → run finalizes `failed`) | `GET /api/v1/approvals?state=pending`, then `POST /api/v1/approvals/{id}/approve` (admin token). An already-decided/expired request returns 409 — re-run the action for a fresh request |
| Approve returns 409 `not_pending` | The request was already approved/denied/expired, or its parked run was cancelled/finalized meanwhile | Re-list requests; if the run was cancelled, re-dispatch the action |
| MCP tool call returns `isError` with `insufficient role` | The caller's bearer token (stdio `--token` / `Authorization` header) has a role below the tool's gate (writes need operator/admin; `create_secret`/`decide_approval` need admin) | Re-run with a higher-privileged token (or `partout ctl auth login` as an operator/admin user) |
| MCP `run_command`/`apply_updates` returns a policy refusal or `approval_required` | A `deny`/`require_approval` policy matched (structured message names the rule / approval id) | Satisfy the policy: change the command/selector, or have an admin `decide_approval` (approve) the parked request; do not retry a `deny` |
| `POST /mcp` returns 404 | The build predates the MCP route, or the request hit the SPA wrapper (must be `POST`, not `GET`) | Confirm v0.6+; use `POST` with `Content-Type: application/json` and a bearer token |
| MCP stdio client hangs / no tools | The launched `partout --mode=mcp` needs a reachable `--server` and a valid `--token`; a dead server or bad token fails the first call (the process stays up) | Verify `--server` is reachable and `--token` is a live bearer token; test with `curl` against `POST /mcp` on the same server |
| `POST /oauth2/token` returns `invalid_grant` | PKCE mismatch (`code_verifier` ≠ the challenge), code reused, code expired (5 min), or the `client_id` doesn't match the one that was authorized | Redo the authorize→exchange round-trip with a fresh code + matching verifier/client; S256 only |
| MCP upload returns `202 {approval_required}` | A `require_approval` rule matched file.write; the body is staged in `<dbdir>/filestaging/` (0600) until decided | An admin `decide_approval` (approve) re-dispatches the staged body; expiry (default 1 h) discards it and the request can never be retroactively honored |
| Job create/update rejected: `task.run blocked … (requires approval)` | A host in the selector matches `require_approval` for task.run; a job carries a *standing* decision and cannot hold one that needs approval | Change the policy/selector, or use the existing job's manual RunNow (park → admin approve → dispatch) |
| No alerts fire although a unit is `failed` | The engine ticks every `PARTOUT_ALERT_TICK_S` (30 s) over *stored* facts — the agent's service collector runs every 5 min by default, so a new failure can take up to ~5.5 min to become visible; `service_failed_minutes` (default 5) adds a delay window on top; the rule must be enabled and its selector must match the host | Check `partout ctl alerts rules` (enabled? selector?), `GET /api/v1/services?state=failed` (fact present?), and the server log line `observe/alerts: tick:` |
| Alert won't resolve after recovery | Missing/stale facts fail soft by design (no data ≠ recovery): if the host's facts stop updating (agent down), the alert stays firing; also confirm the unit's `state` actually left `failed` in the stored facts | Check host last-seen + `GET /api/v1/services?agent_id=…`; once fresh facts show `active`, the next tick resolves it |
| Duplicate alerts for the same condition | Should not happen — the dedup key is rule|host|subject; if you see repeats, check for two rules with the same kind+selector (each rule has its own dedup key) | Consolidate rules or delete the redundant one (`DELETE /api/v1/alerts/rules/{id}`) |
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

Current items first; items marked *(P)* track later milestones (M4/M5).

- [ ] Server installed, systemd unit active, `GET /healthz` returns 200
- [ ] First-run admin user created (pre-seeded via `PARTOUT_ADMIN_PASSWORD`, or the generated
  password read from `<db dir>/admin_password.txt` and rotated); RBAC bearer tokens set
  (admin/operator/viewer) and verified (`/api/v1/hosts` → 401 without, 200 with)
- [ ] TLS enabled if exposing beyond localhost (`PARTOUT_TLS=on`); CA fetched via `partout ctl ca`; `ca.crt` in the agent env
- [ ] ≥1 agent enrolled; facts visible <10 s; test command executed and audited (`partout ctl run`)
- [ ] Backup runbook tested: DB + `<db dir>/tls/` + secret key file restored from backup; audit log intact
- [ ] Upgrades tested on a non-prod host: new binary → restart → reconnect → command works
- [ ] Baseline policy: deny destructive commands (e.g. `rm -rf`, `mkfs`), host/role-scoped denies as needed
- [ ] Air-gap mode tested (if applicable): `PARTOUT_DISABLE_EXTERNAL_DATA_REFRESH=true`
- [ ] *(P)* Approvals workflow (M4): require-approval rules, approval queue
- [ ] *(P)* Alert channels configured: host state (disconnected), approval request
- [ ] *(P)* Capacity baseline: disk usage recorded; retention set; spool limits appropriate
- [ ] *(P)* Observe layer (M5): agents upload service/config/cert facts; API endpoints
  return live data; basic health visible via `partout ctl`
- [ ] *(P)* Alert engine (M6): at least one alert rule tested (e.g. `cert_expiring` with
  <30-day threshold); firing and resolving alerts visible via API/SSE
- [ ] *(P)* Access review process documented (who gets operator/admin, quarterly review)
- [ ] Operator training: hosts, execute, sessions, jobs, tasks, updates, secrets, policy,
  audit (CLI + REST; the Web UI ships in a later V1 phase)
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
