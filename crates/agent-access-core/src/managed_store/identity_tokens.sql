CREATE TABLE principal_identity_tokens (
 principal_id TEXT PRIMARY KEY REFERENCES principals(principal_id) ON DELETE CASCADE,
 fingerprint TEXT UNIQUE,
 key_id TEXT,
 nonce BLOB,
 ciphertext BLOB,
 paused INTEGER NOT NULL DEFAULT 0 CHECK(paused IN (0,1)),
 updated_at TEXT NOT NULL,
 CHECK ((fingerprint IS NULL AND key_id IS NULL AND nonce IS NULL AND ciphertext IS NULL) OR (fingerprint IS NOT NULL AND key_id IS NOT NULL AND nonce IS NOT NULL AND ciphertext IS NOT NULL))
);
