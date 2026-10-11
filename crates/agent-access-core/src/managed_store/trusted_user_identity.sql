CREATE TABLE principal_identity_access (
  principal_id TEXT PRIMARY KEY REFERENCES principals(principal_id) ON DELETE CASCADE,
  incarnation TEXT NOT NULL UNIQUE,
  paused INTEGER NOT NULL CHECK(paused IN (0, 1)),
  version INTEGER NOT NULL CHECK(typeof(version) = 'integer' AND version > 0),
  updated_at TEXT NOT NULL,
  updated_by TEXT NOT NULL
);

INSERT INTO principal_identity_access
  (principal_id, incarnation, paused, version, updated_at, updated_by)
SELECT p.principal_id, lower(hex(randomblob(16))), COALESCE(t.paused, 0), 1,
       COALESCE(t.updated_at, p.updated_at), 'system:identity_access_migration'
FROM principals p LEFT JOIN principal_identity_tokens t ON t.principal_id = p.principal_id
WHERE p.kind = 'user';

CREATE TABLE principal_username_bindings (
  binding_id TEXT PRIMARY KEY,
  principal_id TEXT NOT NULL REFERENCES principals(principal_id) ON DELETE CASCADE,
  namespace TEXT NOT NULL,
  username TEXT NOT NULL,
  enabled INTEGER NOT NULL CHECK(enabled IN (0, 1)),
  version INTEGER NOT NULL CHECK(typeof(version) = 'integer' AND version > 0),
  created_at TEXT NOT NULL,
  created_by TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  updated_by TEXT NOT NULL,
  UNIQUE(namespace, username)
);
CREATE INDEX idx_principal_username_bindings_principal
  ON principal_username_bindings(principal_id, namespace, username);

CREATE TABLE principal_identity_tokens_new (
  principal_id TEXT PRIMARY KEY REFERENCES principals(principal_id) ON DELETE CASCADE,
  fingerprint TEXT UNIQUE,
  key_id TEXT,
  nonce BLOB,
  ciphertext BLOB,
  revision INTEGER NOT NULL CHECK(typeof(revision) = 'integer' AND revision > 0),
  updated_at TEXT NOT NULL,
  CHECK ((fingerprint IS NULL AND key_id IS NULL AND nonce IS NULL AND ciphertext IS NULL)
      OR (fingerprint IS NOT NULL AND key_id IS NOT NULL AND nonce IS NOT NULL AND ciphertext IS NOT NULL))
);
INSERT INTO principal_identity_tokens_new
  (principal_id, fingerprint, key_id, nonce, ciphertext, revision, updated_at)
SELECT principal_id, fingerprint, key_id, nonce, ciphertext, 1, updated_at
FROM principal_identity_tokens;
DROP TABLE principal_identity_tokens;
ALTER TABLE principal_identity_tokens_new RENAME TO principal_identity_tokens;

-- The gate belongs to the human, independently of encrypted token inventory.
-- Database triggers keep every creation/status path in the same transaction.
CREATE TRIGGER principal_identity_access_on_user_create
AFTER INSERT ON principals WHEN NEW.kind = 'user'
BEGIN
  INSERT INTO principal_identity_access
    (principal_id, incarnation, paused, version, updated_at, updated_by)
  VALUES (NEW.principal_id, lower(hex(randomblob(16))), 0, 1, NEW.updated_at, NEW.created_by);
END;

CREATE TRIGGER principal_identity_access_on_status_change
AFTER UPDATE OF status ON principals
WHEN NEW.kind = 'user' AND OLD.status <> NEW.status
BEGIN
  SELECT CASE WHEN NOT EXISTS (
    SELECT 1 FROM principal_identity_access WHERE principal_id = NEW.principal_id
  ) THEN RAISE(ABORT, 'human identity access gate is missing') END;
  UPDATE principal_identity_access
    SET version = version + 1, updated_at = NEW.updated_at,
        updated_by = 'system:principal_status'
    WHERE principal_id = NEW.principal_id;
END;

CREATE TRIGGER principal_identity_access_preserve_human_kind
BEFORE UPDATE OF kind ON principals
WHEN OLD.kind <> NEW.kind AND (OLD.kind = 'user' OR NEW.kind = 'user')
BEGIN
  SELECT RAISE(ABORT, 'human principal kind is immutable');
END;

CREATE TRIGGER principal_identity_access_require_human
BEFORE INSERT ON principal_identity_access
WHEN NOT EXISTS (SELECT 1 FROM principals WHERE principal_id = NEW.principal_id AND kind = 'user')
BEGIN
  SELECT RAISE(ABORT, 'identity access requires a human principal');
END;

CREATE TRIGGER principal_username_bindings_require_human
BEFORE INSERT ON principal_username_bindings
WHEN NOT EXISTS (SELECT 1 FROM principals WHERE principal_id = NEW.principal_id AND kind = 'user')
BEGIN
  SELECT RAISE(ABORT, 'username binding requires a human principal');
END;

CREATE TRIGGER principal_username_bindings_immutable_identity
BEFORE UPDATE OF binding_id, principal_id, namespace, username ON principal_username_bindings
WHEN NEW.binding_id <> OLD.binding_id OR NEW.principal_id <> OLD.principal_id
  OR NEW.namespace <> OLD.namespace OR NEW.username <> OLD.username
BEGIN
  SELECT RAISE(ABORT, 'username binding identity is immutable');
END;
