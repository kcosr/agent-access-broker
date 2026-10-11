CREATE TABLE principal_service_limits (
  principal_id TEXT NOT NULL REFERENCES principals(principal_id) ON DELETE CASCADE,
  service TEXT NOT NULL CHECK (length(service) BETWEEN 1 AND 63),
  requests INTEGER NOT NULL CHECK (requests BETWEEN 1 AND 1000000),
  window_seconds INTEGER NOT NULL CHECK (window_seconds BETWEEN 1 AND 86400),
  created_at TEXT NOT NULL,
  created_by TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  updated_by TEXT NOT NULL,
  PRIMARY KEY (principal_id, service)
);
