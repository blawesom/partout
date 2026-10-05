package store

// schemaSQL is the M0 migration (v1), applied identically to the SQLite
// dialect. Postgres uses the same shape with dialect-specific tweaks
// (see openPostgres). Migrations are forward-only, one monotonic version
// (PRD R9, architecture §9.1).
const schemaSQL = `
CREATE TABLE IF NOT EXISTS schema_version (
  version INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS agents (
  id            TEXT PRIMARY KEY,
  uuid          TEXT NOT NULL UNIQUE,
  ed25519_pub   TEXT NOT NULL,
  x25519_pub    TEXT NOT NULL,
  tls_pub       TEXT NOT NULL DEFAULT '',   -- enrolled ECDSA pub (PKIX b64); '' = non-TLS agent
  tls_not_after INTEGER NOT NULL DEFAULT 0, -- current mTLS leaf expiry (unix s); 0 = none
  version       TEXT,
  state         TEXT NOT NULL DEFAULT 'pending',
  first_seen    INTEGER,
  last_seen     INTEGER,
  created       INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS host_facts (
  agent_id      TEXT NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
  ts            INTEGER NOT NULL,
  data          TEXT NOT NULL,
  PRIMARY KEY (agent_id, ts)
);

CREATE TABLE IF NOT EXISTS host_tags (
  agent_id      TEXT NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
  k             TEXT NOT NULL,
  v             TEXT NOT NULL DEFAULT '',
  PRIMARY KEY (agent_id, k)
);

CREATE TABLE IF NOT EXISTS host_roles (
  agent_id      TEXT NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
  role          TEXT NOT NULL,
  PRIMARY KEY (agent_id, role)
);

CREATE TABLE IF NOT EXISTS groups (
  name          TEXT PRIMARY KEY,
  selector      TEXT NOT NULL,
  created       INTEGER NOT NULL,
  updated       INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS enrollment_tokens (
  token_hash    TEXT PRIMARY KEY,
  token_mask    TEXT NOT NULL,
  created       INTEGER NOT NULL,
  expires       INTEGER NOT NULL,
  used          INTEGER NOT NULL DEFAULT 0,
  used_at       INTEGER
);

CREATE TABLE IF NOT EXISTS executions (
  id            TEXT PRIMARY KEY,
  selector      TEXT NOT NULL,
  cmd           TEXT NOT NULL,
  args_json     TEXT,
  created       INTEGER NOT NULL,
  created_by    TEXT,
  state         TEXT NOT NULL DEFAULT 'pending'
);

CREATE TABLE IF NOT EXISTS execution_runs (
  id            TEXT PRIMARY KEY,
  execution_id  TEXT NOT NULL REFERENCES executions(id) ON DELETE CASCADE,
  agent_id      TEXT NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
  state         TEXT NOT NULL DEFAULT 'queued',
  exit_code     INTEGER,
  duration_ms   INTEGER,
  created       INTEGER NOT NULL,
  updated       INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_runs_exec ON execution_runs(execution_id);
CREATE INDEX IF NOT EXISTS idx_runs_agent ON execution_runs(agent_id);

CREATE TABLE IF NOT EXISTS output_chunks (
  run_id        TEXT NOT NULL REFERENCES execution_runs(id) ON DELETE CASCADE,
  chunk_seq     INTEGER NOT NULL,
  stream        TEXT NOT NULL,
  data          BLOB NOT NULL,
  ts            INTEGER NOT NULL,
  PRIMARY KEY (run_id, chunk_seq)
);

CREATE TABLE IF NOT EXISTS audit_events (
  id            INTEGER PRIMARY KEY AUTOINCREMENT,
  ts            INTEGER NOT NULL,
  kind          TEXT NOT NULL,
  actor         TEXT,
  agent_id      TEXT,
  payload       TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit_events(ts);
CREATE INDEX IF NOT EXISTS idx_audit_kind ON audit_events(kind);

CREATE TABLE IF NOT EXISTS policies (
  id           TEXT PRIMARY KEY,
  name         TEXT NOT NULL,
  match_json   TEXT NOT NULL,
  effect       TEXT NOT NULL,
  priority     INTEGER NOT NULL DEFAULT 0,
  created_unix INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_policies_effect ON policies(effect);

-- Approval requests (M4, PRD §5.8): a policy require_approval match parks
-- the exact payload here; an admin approves/denies; approvals are scoped to
-- the exact payload (not a blanket allow) and audit-logged.
CREATE TABLE IF NOT EXISTS approval_requests (
  id            TEXT PRIMARY KEY,
  action_class  TEXT NOT NULL,              -- exec | pkg.apply | file.write | ...
  payload_json  TEXT NOT NULL,              -- exact action payload (scoped approval)
  agent_id      TEXT NOT NULL,
  execution_id  TEXT,                       -- command executions (nullable)
  run_id        TEXT,                       -- created run row (nullable)
  actor         TEXT NOT NULL,              -- requesting principal
  actor_role    TEXT NOT NULL,
  matched_rules TEXT,                       -- rule IDs that required approval
  state         TEXT NOT NULL DEFAULT 'pending' CHECK (state IN ('pending','approved','denied','expired')),
  created_unix  INTEGER NOT NULL,
  expires_unix  INTEGER NOT NULL,
  decided_unix  INTEGER,
  decided_by    TEXT,
  decision_reason TEXT
);
CREATE INDEX IF NOT EXISTS idx_approvals_state ON approval_requests(state);

CREATE TABLE IF NOT EXISTS meta (
  key   TEXT PRIMARY KEY,
  value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS provision_runs (
  id            TEXT PRIMARY KEY,
  host          TEXT NOT NULL,
  mode          TEXT NOT NULL DEFAULT 'fresh',
  state         TEXT NOT NULL DEFAULT 'queued',
  key_type      TEXT,
  fingerprint   TEXT,
  key_line      TEXT,
  resolved_host TEXT,
  token_hash    TEXT,
  agent_id      TEXT REFERENCES agents(id) ON DELETE SET NULL,
  step          TEXT,
  error         TEXT,
  created       INTEGER NOT NULL,
  updated       INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_provision_state ON provision_runs(state);

CREATE TABLE IF NOT EXISTS provision_steps (
  run_id         TEXT NOT NULL REFERENCES provision_runs(id) ON DELETE CASCADE,
  seq            INTEGER NOT NULL,
  name           TEXT NOT NULL,
  state          TEXT NOT NULL DEFAULT 'pending',
  stdout_excerpt TEXT,
  stderr_excerpt TEXT,
  started        INTEGER,
  finished       INTEGER,
  PRIMARY KEY (run_id, seq)
);

-- M2: files & sessions (PRD §5.2.2, §5.3; arch §8).

CREATE TABLE IF NOT EXISTS sessions (
  id         TEXT PRIMARY KEY,
  agent_id   TEXT NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
  cmd        TEXT NOT NULL,
  args_json  TEXT,
  cols       INTEGER,
  rows       INTEGER,
  record     INTEGER NOT NULL DEFAULT 0,  -- capture PTY output (PRD §9: 30 d)
  state      TEXT NOT NULL DEFAULT 'open', -- open|closed|interrupted|denied
  exit_code  INTEGER,
  error      TEXT,
  actor      TEXT NOT NULL,
  opened     INTEGER NOT NULL,
  closed     INTEGER
);
CREATE INDEX IF NOT EXISTS idx_sessions_agent ON sessions(agent_id);
CREATE INDEX IF NOT EXISTS idx_sessions_state ON sessions(state);

CREATE TABLE IF NOT EXISTS session_records (
  session_id TEXT NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
  seq        INTEGER NOT NULL,
  data       BLOB NOT NULL,
  PRIMARY KEY (session_id, seq)
);

CREATE TABLE IF NOT EXISTS files_actions (
  id       TEXT PRIMARY KEY,
  agent_id TEXT NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
  kind     TEXT NOT NULL,   -- stat|list|download|upload|edit|perm
  path     TEXT NOT NULL,
  op_id    TEXT NOT NULL,   -- agent-side op id(s); joined with "+" for uploads
  actor    TEXT NOT NULL,
  state    TEXT NOT NULL,   -- ok|denied|error
  code     INTEGER NOT NULL DEFAULT 0,
  size     INTEGER,
  sha256   TEXT,
  error    TEXT,
  created  INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_files_actions_agent ON files_actions(agent_id);
CREATE INDEX IF NOT EXISTS idx_files_actions_created ON files_actions(created);

-- M3: secrets (PRD §5.7): encrypted at rest (HKDF from master key),
-- versioned, bound to a selector; values never returned by read APIs.

CREATE TABLE IF NOT EXISTS secrets (
  id          TEXT PRIMARY KEY,
  name        TEXT NOT NULL UNIQUE,
  selector    TEXT NOT NULL DEFAULT '',   -- hosts the secret may materialize on
  offline_ttl INTEGER NOT NULL DEFAULT 0, -- agent-side encrypted cache window (s); 0 = never
  created     INTEGER NOT NULL,
  updated     INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS secret_versions (
  id         TEXT PRIMARY KEY,
  secret_id  TEXT NOT NULL REFERENCES secrets(id) ON DELETE CASCADE,
  version    INTEGER NOT NULL,
  ciphertext BLOB NOT NULL,  -- AES-GCM(value) under HKDF(master, secret_id)
  created    INTEGER NOT NULL,
  revoked    INTEGER NOT NULL DEFAULT 0,
  UNIQUE (secret_id, version)
);

CREATE TABLE IF NOT EXISTS secret_bindings (
  id        TEXT PRIMARY KEY,
  secret_id TEXT NOT NULL REFERENCES secrets(id) ON DELETE CASCADE,
  version   INTEGER NOT NULL,   -- which version was materialized (audit)
  agent_id  TEXT NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
  ref       TEXT NOT NULL,      -- task/execution run that declared it
  ts        INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_secret_bindings_agent ON secret_bindings(agent_id);
CREATE INDEX IF NOT EXISTS idx_secret_bindings_ref ON secret_bindings(ref);

-- M3: external data refresh (PRD §6.3). Live public feeds fetched by the
-- server (which has outbound access) and cached. Agents never fetch these.
-- EOL: one row per distro+cycle; replaced all-or-nothing on refresh.
-- Vulns: per CVE, populated lazily by list-updates correlation (OSV.dev),
-- TTL-cached.

CREATE TABLE IF NOT EXISTS eol_cache (
  distro              TEXT NOT NULL,   -- e.g. debian, ubuntu, rhel
  cycle               TEXT NOT NULL,   -- e.g. 12, 24.04
  codename            TEXT,
  release_date        TEXT,
  eol_date            TEXT NOT NULL,
  support_date        TEXT,
  extended_support    TEXT,
  latest              TEXT,
  fetched_at          INTEGER NOT NULL,
  PRIMARY KEY (distro, cycle)
);

CREATE TABLE IF NOT EXISTS vuln_cache (
  vuln_id      TEXT NOT NULL,
  package      TEXT NOT NULL,   -- source package name
  ecosystem    TEXT NOT NULL,   -- e.g. "Debian:12"
  version      TEXT NOT NULL,   -- affected version (as queried)
  severity     REAL,            -- CVSS score (0-10); NULL if ungraded
  summary      TEXT,
  url          TEXT,
  fetched_at   INTEGER NOT NULL,
  PRIMARY KEY (vuln_id, package, ecosystem, version)
);
CREATE INDEX IF NOT EXISTS idx_vuln_pkg ON vuln_cache(package, ecosystem);

CREATE TABLE IF NOT EXISTS external_meta (
  key    TEXT PRIMARY KEY,   -- last_refresh, last_refresh_ok, last_error, ...
  value  TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS package_actions (
  id           TEXT PRIMARY KEY,
  agent_id     TEXT NOT NULL,
  kind         TEXT NOT NULL,   -- list | dry_run | apply
  status       TEXT NOT NULL,   -- running | succeeded | failed
  dry_summary  TEXT,            -- dry-run output (truncated)
  before_json  TEXT,            -- before-state journal (JSON []PkgUpdate)
  after_json   TEXT,            -- after-state journal (JSON []PkgUpdate)
  applied_count INTEGER NOT NULL DEFAULT 0,
  error        TEXT,
  created      INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_pkg_actions_agent ON package_actions(agent_id);
CREATE INDEX IF NOT EXISTS idx_pkg_actions_created ON package_actions(created);

CREATE TABLE IF NOT EXISTS tasks (
  id        TEXT PRIMARY KEY,
  name      TEXT NOT NULL UNIQUE,
  description TEXT,
  created   INTEGER NOT NULL,
  updated   INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS task_versions (
  task_id   TEXT NOT NULL,
  version   INTEGER NOT NULL,
  steps_json TEXT NOT NULL,     -- JSON []TaskStep
  created   INTEGER NOT NULL,
  PRIMARY KEY (task_id, version),
  FOREIGN KEY (task_id) REFERENCES tasks(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS task_runs (
  id           TEXT PRIMARY KEY,
  task_id      TEXT NOT NULL,
  task_version INTEGER NOT NULL,
  agent_id     TEXT NOT NULL,   -- target host
  state        TEXT NOT NULL,   -- running | succeeded | failed | interrupted
  started      INTEGER NOT NULL,
  finished     INTEGER,
  error        TEXT,
  FOREIGN KEY (task_id) REFERENCES tasks(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_task_runs_agent ON task_runs(agent_id);
CREATE INDEX IF NOT EXISTS idx_task_runs_task ON task_runs(task_id);
CREATE INDEX IF NOT EXISTS idx_task_runs_state ON task_runs(state);

CREATE TABLE IF NOT EXISTS task_run_steps (
  run_id     TEXT NOT NULL,
  step_index INTEGER NOT NULL,
  kind       TEXT NOT NULL,   -- command|file|package|service|user|group|template|assert|reboot
  name       TEXT,
  state      TEXT NOT NULL,   -- pending|running|ok|changed|failed|skipped
  detail     TEXT,
  started    INTEGER,
  finished   INTEGER,
  PRIMARY KEY (run_id, step_index),
  FOREIGN KEY (run_id) REFERENCES task_runs(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_task_run_steps ON task_run_steps(run_id);

CREATE TABLE IF NOT EXISTS playbooks (
  id           TEXT PRIMARY KEY,
  name         TEXT NOT NULL,
  task_id      TEXT NOT NULL,
  task_version INTEGER NOT NULL,
  selector     TEXT NOT NULL,
  created      INTEGER NOT NULL,
  FOREIGN KEY (task_id) REFERENCES tasks(id) ON DELETE CASCADE
);

-- M3 jobs (PRD §5.4): scheduled tasks with agent-side execution.
CREATE TABLE IF NOT EXISTS jobs (
  id            TEXT PRIMARY KEY,
  name          TEXT NOT NULL,
  task_id       TEXT NOT NULL,
  task_version  INTEGER NOT NULL,
  cron          TEXT NOT NULL,
  selector      TEXT NOT NULL,
  max_run_s     INTEGER NOT NULL DEFAULT 1800,
  enabled       INTEGER NOT NULL DEFAULT 1,
  created       INTEGER NOT NULL,
  updated       INTEGER NOT NULL,
  FOREIGN KEY (task_id) REFERENCES tasks(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS job_assignments (
  job_id        TEXT NOT NULL,
  agent_id      TEXT NOT NULL,
  assigned_at   INTEGER NOT NULL,
  last_run_at   INTEGER NOT NULL DEFAULT 0,
  last_run_state TEXT NOT NULL DEFAULT '',
  PRIMARY KEY (job_id, agent_id),
  FOREIGN KEY (job_id) REFERENCES jobs(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS job_runs (
  id            TEXT PRIMARY KEY,
  job_id        TEXT NOT NULL,
  agent_id      TEXT NOT NULL,
  task_id       TEXT NOT NULL,
  task_version  INTEGER NOT NULL,
  scheduled_at  INTEGER NOT NULL,
  started_at    INTEGER NOT NULL DEFAULT 0,
  finished_at   INTEGER NOT NULL DEFAULT 0,
  state         TEXT NOT NULL DEFAULT 'pending',
  trigger       TEXT NOT NULL DEFAULT 'cron',
  error         TEXT NOT NULL DEFAULT '',
  FOREIGN KEY (job_id) REFERENCES jobs(id) ON DELETE CASCADE,
  FOREIGN KEY (task_id) REFERENCES tasks(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_job_runs_job ON job_runs(job_id);
CREATE INDEX IF NOT EXISTS idx_job_runs_agent ON job_runs(agent_id);
CREATE TABLE IF NOT EXISTS principals (
  username      TEXT PRIMARY KEY,
  password_hash TEXT NOT NULL,  -- PHC argon2id string (per-user pepper inside)
  role          TEXT NOT NULL CHECK (role IN ('viewer','operator','admin')),
  disabled      INTEGER NOT NULL DEFAULT 0,
  created_unix  INTEGER NOT NULL
);

-- M4 OAuth2 (PKCE) for the MCP HTTP transport (PRD R11, A20).
-- mcp_clients: registered MCP clients (admin-managed). Codes and tokens are
-- stored hashed (SHA-256 hex); the plaintext exists only in transit.
CREATE TABLE IF NOT EXISTS mcp_clients (
  id         TEXT PRIMARY KEY,
  name       TEXT NOT NULL,
  scope      TEXT NOT NULL DEFAULT 'fleet',
  created    INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS oauth_codes (
  id          TEXT PRIMARY KEY,
  code_hash   TEXT NOT NULL UNIQUE,
  client_id   TEXT NOT NULL,
  principal   TEXT NOT NULL,
  role        TEXT NOT NULL,
  scope       TEXT NOT NULL,
  challenge   TEXT NOT NULL,   -- S256 code challenge
  expires     INTEGER NOT NULL,
  used        INTEGER NOT NULL DEFAULT 0,
  created     INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS oauth_tokens (
  token_hash  TEXT PRIMARY KEY,
  client_id   TEXT NOT NULL,
  principal   TEXT NOT NULL,
  role        TEXT NOT NULL,
  scope       TEXT NOT NULL,
  created     INTEGER NOT NULL,
  expires     INTEGER NOT NULL
);

-- M6 alert engine (PRD R23/R25, arch §7): threshold rules over the observe
-- domains + the unified alert store. Dedup key = rule|host|subject so one
-- condition yields one alert row (re-fires re-arm the same row).
CREATE TABLE IF NOT EXISTS alert_rules (
  id         TEXT PRIMARY KEY,
  name       TEXT NOT NULL,
  kind       TEXT NOT NULL,
               -- service_failed | service_restarting | cert_expiring | config_invalid | config_drift
  selector   TEXT NOT NULL DEFAULT 'all',
  thresholds TEXT NOT NULL DEFAULT '{}',
               -- JSON: {"service_failed_minutes":0|5}, {"service_restart_rate_per_hour":10},
               --       {"cert_days_remaining":30}, {"config_drift_tolerance":0}
  severity   TEXT NOT NULL DEFAULT 'warning' CHECK (severity IN ('info','warning','critical')),
  enabled    INTEGER NOT NULL DEFAULT 1,
  webhook_url TEXT NOT NULL DEFAULT '',
               -- optional external channel: POST on firing + resolved
  created_by TEXT,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS alerts (
  id          TEXT PRIMARY KEY,
  rule_id     TEXT NOT NULL,
  agent_id    TEXT,              -- NULL = fleet-wide (v1 rules are per-host)
  kind        TEXT NOT NULL,     -- matches alert_rules.kind
  severity    TEXT NOT NULL CHECK (severity IN ('info','warning','critical')),
  message     TEXT NOT NULL,
  state       TEXT NOT NULL DEFAULT 'firing' CHECK (state IN ('firing','resolved')),
  dedup_key   TEXT NOT NULL UNIQUE,
  started_at  INTEGER NOT NULL,
  resolved_at INTEGER
);
CREATE INDEX IF NOT EXISTS idx_alerts_state ON alerts(state);
CREATE INDEX IF NOT EXISTS idx_alerts_agent ON alerts(agent_id);
CREATE INDEX IF NOT EXISTS idx_alerts_rule ON alerts(rule_id);

-- M8.1 release store: signed partout release artifacts (agent + server
-- binaries). The server stores and serves artifacts but is NOT the trust
-- anchor: every consumer verifies the Ed25519 signature (over
-- "version|arch|kind|sha256") against the operator-provisioned release
-- public key before executing anything.
CREATE TABLE IF NOT EXISTS update_releases (
  id          TEXT PRIMARY KEY,
  version     TEXT NOT NULL,
  arch        TEXT NOT NULL,
  kind        TEXT NOT NULL CHECK (kind IN ('agent','server')),
  sha256      TEXT NOT NULL,          -- hex, of the artifact
  signature   TEXT NOT NULL,          -- base64 Ed25519 over the canonical manifest
  artifact    BLOB NOT NULL,
  uploaded_by TEXT,
  created_at  INTEGER NOT NULL,
  UNIQUE (version, arch, kind)
);

-- M8.1 rollout orchestration: one row per fleet rollout (run), one row per
-- (run, host). The per-host row is the state machine; the run row carries
-- the wave plan + counters.
CREATE TABLE IF NOT EXISTS update_runs (
  id           TEXT PRIMARY KEY,
  version      TEXT NOT NULL,
  release_id   TEXT NOT NULL,
  arch         TEXT NOT NULL,
  selector     TEXT NOT NULL DEFAULT 'all',
  canary_hosts TEXT NOT NULL DEFAULT '',      -- comma-joined canary cohort
  canary_count INTEGER NOT NULL DEFAULT 1,
  wave_pct     INTEGER NOT NULL DEFAULT 25,
  status       TEXT NOT NULL DEFAULT 'pending',
  current_wave INTEGER NOT NULL DEFAULT 0,
  total_hosts  INTEGER NOT NULL DEFAULT 0,
  done_hosts   INTEGER NOT NULL DEFAULT 0,
  failed_hosts INTEGER NOT NULL DEFAULT 0,
  skipped_hosts INTEGER NOT NULL DEFAULT 0,
  error        TEXT NOT NULL DEFAULT '',
  approval_id  TEXT NOT NULL DEFAULT '',
  created_by   TEXT NOT NULL,
  created_at   INTEGER NOT NULL,
  updated_at   INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_update_runs_status ON update_runs(status);

CREATE TABLE IF NOT EXISTS update_hosts (
  id         TEXT PRIMARY KEY,
  run_id     TEXT NOT NULL,
  host_id    TEXT NOT NULL,
  status     TEXT NOT NULL DEFAULT 'queued',
  version    TEXT NOT NULL DEFAULT '',
  error      TEXT NOT NULL DEFAULT '',
  updated_at INTEGER NOT NULL,
  UNIQUE (run_id, host_id)
);
CREATE INDEX IF NOT EXISTS idx_update_hosts_run ON update_hosts(run_id);
CREATE INDEX IF NOT EXISTS idx_update_hosts_host ON update_hosts(host_id);

-- v17: update directives queued for offline hosts (M8.1). Persisted so a
-- server restart between dispatch and reconnect does not lose them (the
-- in-memory offline queue is the fast path; this is the durable one). One
-- row per agent: the newest queued directive wins. Only (agent, release) is
-- stored — the delivery side mints a fresh one-time grant, so a directive
-- queued across a long outage never carries an expired grant.
CREATE TABLE IF NOT EXISTS pending_updates (
  agent_id   TEXT PRIMARY KEY,
  release_id TEXT NOT NULL,
  created_at INTEGER NOT NULL
);

-- M5.1: periodic security scan results (server-side, derived from agent
-- update lists + OSV correlation; the alert engine reads these).
CREATE TABLE IF NOT EXISTS security_findings (
  agent_id   TEXT NOT NULL,
  pkg        TEXT NOT NULL,
  installed  TEXT NOT NULL DEFAULT '',
  available  TEXT NOT NULL DEFAULT '',
  vuln_count INTEGER NOT NULL DEFAULT 0,
  max_cvss   REAL NOT NULL DEFAULT 0,
  vuln_ids   TEXT NOT NULL DEFAULT '',
  updated_at INTEGER NOT NULL,
  PRIMARY KEY (agent_id, pkg)
);
CREATE TABLE IF NOT EXISTS security_scan_meta (
  agent_id         TEXT PRIMARY KEY,
  scanned_at       INTEGER NOT NULL,
  updates_total    INTEGER NOT NULL DEFAULT 0,
  security_updates INTEGER NOT NULL DEFAULT 0
);

-- v19: LLM assistant (R26, M9). assistant_config is a single row (id=1):
-- the operator-configured OpenAI-compatible endpoint. The API key is stored
-- SEALED (AES-GCM under a key derived from the secrets master key) and never
-- returned by read APIs. Sessions + messages are the split-store transcript
-- (PRD Decision 18): prompts + replies live here (user-owned, admin-readable);
-- the audit log records only the action half (session, model, tool calls,
-- prompt hash).
CREATE TABLE IF NOT EXISTS assistant_config (
  id              INTEGER PRIMARY KEY CHECK (id = 1),
  base_url        TEXT NOT NULL DEFAULT '',
  model           TEXT NOT NULL DEFAULT '',
  api_key_sealed  BLOB,
  max_tool_calls  INTEGER NOT NULL DEFAULT 15,
  timeout_s       INTEGER NOT NULL DEFAULT 120,
  default_profile TEXT NOT NULL DEFAULT 'readonly',
  enabled         INTEGER NOT NULL DEFAULT 0,
  updated         INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS assistant_sessions (
  id      TEXT PRIMARY KEY,
  user_id TEXT NOT NULL,
  profile TEXT NOT NULL,
  created INTEGER NOT NULL DEFAULT 0,
  updated INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_assistant_sessions_user ON assistant_sessions(user_id);
CREATE TABLE IF NOT EXISTS assistant_messages (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  session_id TEXT NOT NULL,
  role       TEXT NOT NULL,              -- user|assistant|tool
  content    TEXT NOT NULL,
  tool_name  TEXT NOT NULL DEFAULT '',
  tool_args  TEXT NOT NULL DEFAULT '',   -- JSON, tool rows only
  meta       TEXT NOT NULL DEFAULT '',   -- JSON, tool rows only: parsed result ids (feedback parity)
  created    INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_assistant_messages_session ON assistant_messages(session_id);

CREATE TABLE IF NOT EXISTS elevation_policies (
  id           TEXT PRIMARY KEY,
  name         TEXT NOT NULL UNIQUE,
  description  TEXT NOT NULL DEFAULT '',
  rules_json   TEXT NOT NULL,           -- canonical rules array (elevate.Rule)
  policy_sha256 TEXT NOT NULL,          -- canonical rules-only hash (matches the agent fact)
  created      INTEGER NOT NULL DEFAULT 0,
  updated      INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS elevation_policy_versions (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  policy_id   TEXT NOT NULL,
  version     INTEGER NOT NULL,
  rules_json  TEXT NOT NULL,
  policy_sha256 TEXT NOT NULL,
  description TEXT NOT NULL DEFAULT '',
  changed_by  TEXT NOT NULL DEFAULT '',
  created     INTEGER NOT NULL DEFAULT 0,
  UNIQUE(policy_id, version)
);
`

// currentSchemaVersion is applied on first migrate.
const currentSchemaVersion = 23

// CurrentSchemaVersion exposes the constant (selftest, ops tooling).
func CurrentSchemaVersion() int { return currentSchemaVersion }
