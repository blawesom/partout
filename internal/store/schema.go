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

CREATE TABLE IF NOT EXISTS meta (
  key   TEXT PRIMARY KEY,
  value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS provision_runs (
  id           TEXT PRIMARY KEY,
  host         TEXT NOT NULL,
  mode         TEXT NOT NULL DEFAULT 'fresh',
  state        TEXT NOT NULL DEFAULT 'queued',
  key_type     TEXT,
  fingerprint  TEXT,
  key_line     TEXT,
  token_hash   TEXT,
  agent_id     TEXT REFERENCES agents(id) ON DELETE SET NULL,
  step         TEXT,
  error        TEXT,
  created      INTEGER NOT NULL,
  updated      INTEGER NOT NULL
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
`

// currentSchemaVersion is applied on first migrate.
const currentSchemaVersion = 8
