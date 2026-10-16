CREATE TABLE oauth_revocations (
 revocation_id TEXT PRIMARY KEY CHECK(length(revocation_id) = 36),
 owner_principal_id TEXT NOT NULL CHECK(length(owner_principal_id) > 0),
 registration_id TEXT NOT NULL CHECK(length(registration_id) > 0),
 config_fingerprint TEXT NOT NULL CHECK(length(config_fingerprint) > 0),
 family_id TEXT NOT NULL CHECK(length(family_id) > 0),
 cause TEXT NOT NULL CHECK(cause IN ('disconnect','superseded','principal_disabled','refresh_uncertain')),
 state TEXT NOT NULL CHECK(state IN ('pending','revoked','failed','unconfirmed')),
 refresh_attempt_id TEXT CHECK(length(refresh_attempt_id) > 0),
 due_at INTEGER NOT NULL,
 created_at TEXT NOT NULL,
 updated_at TEXT NOT NULL,
 payload_version INTEGER CHECK(payload_version = 1),
 key_id TEXT CHECK(length(key_id) > 0),
 nonce BLOB CHECK(length(nonce) = 12),
 ciphertext BLOB CHECK(length(ciphertext) BETWEEN 16 AND 2097152),
 CHECK((payload_version IS NULL) = (key_id IS NULL)
   AND (key_id IS NULL) = (nonce IS NULL)
   AND (nonce IS NULL) = (ciphertext IS NULL)),
 CHECK(ciphertext IS NULL OR state IN ('pending','unconfirmed')),
 CHECK(ciphertext IS NOT NULL OR state <> 'pending'),
 CHECK(refresh_attempt_id IS NULL OR state IN ('pending','unconfirmed'))
);
CREATE INDEX oauth_revocations_owner ON oauth_revocations(owner_principal_id, registration_id);
CREATE INDEX oauth_revocations_due ON oauth_revocations(due_at);
CREATE INDEX oauth_revocations_key_id ON oauth_revocations(key_id);
