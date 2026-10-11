UPDATE principal_login_methods SET status = 'active' WHERE status = 'locked';
ALTER TABLE principal_login_methods DROP COLUMN failed_attempts;
ALTER TABLE principal_login_methods DROP COLUMN locked_until;

CREATE TABLE local_password_failures (
  principal_id TEXT NOT NULL CHECK (length(principal_id) BETWEEN 1 AND 256),
  source TEXT NOT NULL CHECK (length(source) BETWEEN 1 AND 64),
  failed_attempts INTEGER NOT NULL CHECK (failed_attempts >= 1),
  last_failed_at TEXT NOT NULL,
  locked_until TEXT,
  PRIMARY KEY (principal_id, source)
);

CREATE INDEX idx_local_password_failures_last_failed_at
  ON local_password_failures(last_failed_at);
