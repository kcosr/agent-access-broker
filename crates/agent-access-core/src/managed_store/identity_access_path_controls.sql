-- Per-path controls: each username binding and the identity token can be
-- read-only, and the identity token can be disabled while keeping its secret.
ALTER TABLE principal_username_bindings
  ADD COLUMN read_only INTEGER NOT NULL DEFAULT 0 CHECK(read_only IN (0, 1));
ALTER TABLE principal_identity_tokens
  ADD COLUMN enabled INTEGER NOT NULL DEFAULT 1 CHECK(enabled IN (0, 1));
ALTER TABLE principal_identity_tokens
  ADD COLUMN read_only INTEGER NOT NULL DEFAULT 0 CHECK(read_only IN (0, 1));

-- Every human now has exactly one identity-token row. A human without one gets
-- a not-configured row; existing rows keep their secrets and revisions.
INSERT INTO principal_identity_tokens
  (principal_id, fingerprint, key_id, nonce, ciphertext, revision, updated_at, enabled, read_only)
SELECT p.principal_id, NULL, NULL, NULL, NULL, 1, p.updated_at, 1, 0
FROM principals p
WHERE p.kind = 'user'
  AND NOT EXISTS (SELECT 1 FROM principal_identity_tokens t WHERE t.principal_id = p.principal_id);

-- Like the gate, the row belongs to the human and is created in the same
-- transaction by every creation path. Secret writes and settings changes
-- update it in place; nothing recreates a missing row.
CREATE TRIGGER principal_identity_tokens_on_user_create
AFTER INSERT ON principals WHEN NEW.kind = 'user'
BEGIN
  INSERT INTO principal_identity_tokens
    (principal_id, revision, updated_at, enabled, read_only)
  VALUES (NEW.principal_id, 1, NEW.updated_at, 1, 0);
END;

CREATE TRIGGER principal_identity_tokens_require_human
BEFORE INSERT ON principal_identity_tokens
WHEN NOT EXISTS (SELECT 1 FROM principals WHERE principal_id = NEW.principal_id AND kind = 'user')
BEGIN
  SELECT RAISE(ABORT, 'identity token requires a human principal');
END;
