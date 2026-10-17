-- Temporary transferred secrets are distinct from durable execution credentials.
-- The reference capability itself is never persisted: only its SHA-256 digest.
CREATE TABLE secret_reference_receipts (
  receipt_id TEXT PRIMARY KEY,
  broker_request_id TEXT NOT NULL UNIQUE,
  principal_id TEXT NOT NULL,
  execution_context TEXT NOT NULL,
  service TEXT NOT NULL,
  action TEXT NOT NULL,
  created_at TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  retain_until TEXT NOT NULL,
  outcome TEXT NOT NULL CHECK (outcome IN ('reserved','captured','not_dispatched','unknown','capture_failed','expired')),
  metadata_json TEXT NOT NULL CHECK (json_valid(metadata_json)),
  origin_key_id TEXT NOT NULL,
  origin_nonce BLOB NOT NULL CHECK (length(origin_nonce) = 12),
  origin_ciphertext BLOB NOT NULL CHECK (length(origin_ciphertext) >= 16)
);
CREATE INDEX secret_reference_receipts_principal ON secret_reference_receipts(principal_id);
CREATE INDEX secret_reference_receipts_retention ON secret_reference_receipts(retain_until);

CREATE TABLE secret_reference_material (
  reference_hash TEXT PRIMARY KEY CHECK (length(reference_hash) = 64),
  receipt_id TEXT NOT NULL REFERENCES secret_reference_receipts(receipt_id) ON DELETE CASCADE,
  output_pointer TEXT NOT NULL,
  max_bytes INTEGER NOT NULL CHECK (max_bytes > 0 AND max_bytes <= 1048576),
  charged_bytes INTEGER NOT NULL CHECK (charged_bytes >= 0 AND charged_bytes <= max_bytes),
  state TEXT NOT NULL CHECK (state IN ('reserved','captured','released','expired')),
  key_id TEXT,
  nonce BLOB,
  ciphertext BLOB,
  UNIQUE(receipt_id, output_pointer),
  CHECK ((state = 'captured' AND key_id IS NOT NULL AND nonce IS NOT NULL AND ciphertext IS NOT NULL AND length(nonce) = 12 AND length(ciphertext) >= 16)
      OR (state <> 'captured' AND key_id IS NULL AND nonce IS NULL AND ciphertext IS NULL)),
  CHECK ((state IN ('released','expired') AND charged_bytes = 0)
      OR (state = 'reserved' AND charged_bytes = max_bytes)
      OR (state = 'captured' AND charged_bytes > 0 AND length(ciphertext) = charged_bytes + 16))
);
CREATE INDEX secret_reference_material_receipt ON secret_reference_material(receipt_id);

-- A durable generation fences caller-key and security-contract ABA changes.
CREATE TABLE secret_reference_caller_generations (
  caller TEXT PRIMARY KEY,
  key_id TEXT NOT NULL,
  nonce BLOB NOT NULL CHECK (length(nonce) = 12),
  ciphertext BLOB NOT NULL CHECK (length(ciphertext) = 48),
  generation INTEGER NOT NULL CHECK (generation > 0),
  active INTEGER NOT NULL CHECK (active IN (0,1))
);
