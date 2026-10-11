CREATE TABLE oauth_registrations (
 registration_id TEXT PRIMARY KEY,
 fingerprint TEXT NOT NULL
);
CREATE TABLE oauth_slots (
 owner_principal_id TEXT NOT NULL REFERENCES principals(principal_id) ON DELETE CASCADE,
 registration_id TEXT NOT NULL,
 generation TEXT NOT NULL,
 config_fingerprint TEXT NOT NULL,
 payload_version INTEGER NOT NULL CHECK(payload_version = 1),
 key_id TEXT NOT NULL,
 nonce BLOB NOT NULL CHECK(length(nonce) = 12),
 ciphertext BLOB NOT NULL CHECK(length(ciphertext) <= 1048576),
 updated_at TEXT NOT NULL,
 PRIMARY KEY(owner_principal_id, registration_id)
);
