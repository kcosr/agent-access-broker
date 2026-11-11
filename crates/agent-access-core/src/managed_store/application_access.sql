-- A person's approval of one registered client application. The refresh
-- token is kept only as the broker-token keyed hash; it is absent between an
-- approval and the first code exchange.
CREATE TABLE application_access (
  access_id TEXT PRIMARY KEY NOT NULL,
  principal_id TEXT NOT NULL REFERENCES principals(principal_id) ON DELETE CASCADE,
  application_id TEXT NOT NULL CHECK(length(CAST(application_id AS BLOB)) BETWEEN 1 AND 64),
  enabled INTEGER NOT NULL CHECK(enabled IN (0, 1)),
  read_only INTEGER NOT NULL CHECK(read_only IN (0, 1)),
  version INTEGER NOT NULL CHECK(typeof(version) = 'integer' AND version > 0),
  refresh_token_hash TEXT UNIQUE,
  created_at TEXT NOT NULL,
  connected_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  updated_by TEXT NOT NULL,
  last_used_at TEXT,
  UNIQUE(principal_id, application_id)
);

CREATE TRIGGER application_access_require_human
BEFORE INSERT ON application_access
WHEN NOT EXISTS (SELECT 1 FROM principals WHERE principal_id = NEW.principal_id AND kind = 'user')
BEGIN
  SELECT RAISE(ABORT, 'application access requires a human principal');
END;

CREATE TRIGGER application_access_immutable_identity
BEFORE UPDATE OF access_id, principal_id, application_id ON application_access
WHEN NEW.access_id <> OLD.access_id OR NEW.principal_id <> OLD.principal_id
  OR NEW.application_id <> OLD.application_id
BEGIN
  SELECT RAISE(ABORT, 'application access identity is immutable');
END;

-- Pending browser authorization requests: one use, short lived, bounded.
CREATE TABLE application_authorization_requests (
  request_sequence INTEGER PRIMARY KEY AUTOINCREMENT,
  request_hash BLOB NOT NULL UNIQUE CHECK(length(request_hash) = 32),
  application_id TEXT NOT NULL CHECK(length(CAST(application_id AS BLOB)) BETWEEN 1 AND 64),
  encrypted_payload BLOB NOT NULL CHECK(length(encrypted_payload) BETWEEN 1 AND 16384),
  encryption_nonce BLOB NOT NULL CHECK(length(encryption_nonce) = 12),
  created_at TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  consumed_at TEXT,
  CHECK(expires_at > created_at)
);

CREATE INDEX idx_application_authorization_requests_pending_expiry
  ON application_authorization_requests(expires_at, request_sequence) WHERE consumed_at IS NULL;

-- One-use authorization codes, bound to the client, redirect URI and PKCE
-- challenge of the approved request.
CREATE TABLE application_authorization_codes (
  code_hash TEXT PRIMARY KEY NOT NULL,
  access_id TEXT NOT NULL REFERENCES application_access(access_id) ON DELETE CASCADE,
  application_id TEXT NOT NULL CHECK(length(CAST(application_id AS BLOB)) BETWEEN 1 AND 64),
  redirect_uri TEXT NOT NULL CHECK(length(CAST(redirect_uri AS BLOB)) BETWEEN 1 AND 2048),
  code_challenge TEXT NOT NULL CHECK(length(code_challenge) = 43),
  created_at TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  consumed_at TEXT,
  CHECK(expires_at > created_at)
);

CREATE INDEX idx_application_authorization_codes_access
  ON application_authorization_codes(access_id);

-- The application access that minted an agent token. Deliberately not a
-- foreign key: tokens of a removed access keep the value, stay out of token
-- lists and are deleted by retention.
ALTER TABLE broker_tokens ADD COLUMN application_access_id TEXT;

CREATE INDEX idx_broker_tokens_application_access
  ON broker_tokens(application_access_id) WHERE application_access_id IS NOT NULL;

-- Disabling a person ends the tokens their applications hold at once, on
-- every path that changes the status.
CREATE TRIGGER application_access_tokens_on_principal_disable
AFTER UPDATE OF status ON principals
WHEN NEW.status = 'disabled' AND OLD.status <> 'disabled'
BEGIN
  UPDATE broker_tokens
    SET revoked_at = NEW.updated_at, revoked_by = 'system:principal_status'
    WHERE principal_id = NEW.principal_id AND application_access_id IS NOT NULL
      AND revoked_at IS NULL;
END;
