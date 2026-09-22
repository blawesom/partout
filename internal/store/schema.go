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
`

// currentSchemaVersion is applied on first migrate.
const currentSchemaVersion = 2
