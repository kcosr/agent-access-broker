-- Audit database baseline (001_audit_baseline). The broker sets
-- auto_vacuum = INCREMENTAL and journal_mode = WAL before this migration, and
-- stores the database_id in audit_meta within the migration's transaction.

CREATE TABLE schema_migrations (
  version TEXT PRIMARY KEY,
  checksum TEXT NOT NULL,
  applied_at TEXT NOT NULL
);

-- database_id: random UUID generated when the database is created; never changes.
CREATE TABLE audit_meta (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL
) WITHOUT ROWID;

-- Single row written only by recovery transactions.
CREATE TABLE audit_probe (
  id INTEGER PRIMARY KEY CHECK (id = 1),
  probed_at_us INTEGER NOT NULL,
  padding BLOB NOT NULL
);

CREATE TABLE audit_events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  audit_id TEXT NOT NULL UNIQUE,
  node_id TEXT NOT NULL,
  ts_us INTEGER NOT NULL,
  broker_request_id TEXT NOT NULL,
  agent_request_id TEXT NOT NULL,
  principal TEXT NOT NULL,
  service TEXT NOT NULL,
  scope_service TEXT,
  action TEXT NOT NULL,
  decision TEXT NOT NULL CHECK (decision IN ('allow', 'deny', 'error')),
  reason_code TEXT,
  phase TEXT,
  token_id TEXT,
  token_class TEXT,
  grant_id TEXT,
  execution_context TEXT,
  upstream_status INTEGER,
  upstream_duration_ms INTEGER,
  remote TEXT NOT NULL,
  record_bytes INTEGER NOT NULL,
  record_json TEXT NOT NULL
);

CREATE INDEX audit_events_ts ON audit_events(ts_us);
CREATE INDEX audit_events_scope_ts ON audit_events(scope_service, ts_us);
CREATE INDEX audit_events_principal_ts ON audit_events(principal, ts_us);
CREATE INDEX audit_events_service_ts ON audit_events(service, ts_us);
CREATE INDEX audit_events_action_ts ON audit_events(action, ts_us);
CREATE INDEX audit_events_decision_ts ON audit_events(decision, ts_us);
CREATE INDEX audit_events_reason_ts ON audit_events(reason_code, ts_us)
  WHERE reason_code IS NOT NULL;
CREATE INDEX audit_events_token_ts ON audit_events(token_id, ts_us)
  WHERE token_id IS NOT NULL;
CREATE INDEX audit_events_grant_ts ON audit_events(grant_id, ts_us)
  WHERE grant_id IS NOT NULL;
CREATE INDEX audit_events_broker_request ON audit_events(broker_request_id);
CREATE INDEX audit_events_agent_request ON audit_events(agent_request_id);

CREATE VIRTUAL TABLE audit_events_fts USING fts5(
  text,
  content = '',
  contentless_delete = 1,
  tokenize = 'unicode61 remove_diacritics 2'
);

CREATE TRIGGER audit_events_fts_delete AFTER DELETE ON audit_events BEGIN
  DELETE FROM audit_events_fts WHERE rowid = old.id;
END;
