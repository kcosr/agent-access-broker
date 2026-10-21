CREATE TABLE oidc_membership_renewals (
  login_method_id TEXT PRIMARY KEY
    REFERENCES principal_login_methods(login_method_id) ON DELETE CASCADE,
  token_version TEXT NOT NULL CHECK (length(token_version) = 36),
  state TEXT NOT NULL CHECK (state IN ('active', 'retrying', 'blocked', 'ended')),
  ended_reason TEXT CHECK (ended_reason IN ('sign_in_required', 'not_issued', 'identity_mismatch')),
  payload_version INTEGER CHECK (payload_version IS NULL OR payload_version = 1),
  key_id TEXT CHECK (key_id IS NULL OR length(key_id) BETWEEN 1 AND 128),
  nonce BLOB CHECK (nonce IS NULL OR length(nonce) = 12),
  ciphertext BLOB CHECK (ciphertext IS NULL OR length(ciphertext) BETWEEN 16 AND 65536),
  recorded_at TEXT NOT NULL,            -- when the current token or ending was recorded
  observation_iat INTEGER NOT NULL,     -- highest raw iat of any trusted observation
  last_renewed_at TEXT,
  last_attempt_at TEXT,                 -- durable start of the latest attempt
  failure_count INTEGER NOT NULL DEFAULT 0 CHECK (failure_count >= 0),
  last_failure_code TEXT CHECK (last_failure_code IN
    ('groups_incomplete', 'client_rejected', 'request_rejected', 'invalid_response',
     'throttled', 'unavailable')),
  last_failure_at TEXT,
  next_attempt_after TEXT,
  updated_at TEXT NOT NULL,
  CHECK ((state = 'ended') = (ended_reason IS NOT NULL)),
  CHECK ((state = 'ended') = (ciphertext IS NULL)),
  CHECK ((payload_version IS NULL) = (ciphertext IS NULL)
     AND (key_id IS NULL) = (ciphertext IS NULL)
     AND (nonce IS NULL) = (ciphertext IS NULL)),
  CHECK ((last_failure_code IS NULL) = (last_failure_at IS NULL)),
  CHECK ((state IN ('retrying', 'blocked')) = (last_failure_code IS NOT NULL)),
  CHECK ((state IN ('retrying', 'blocked')) = (next_attempt_after IS NOT NULL))
);
CREATE INDEX idx_oidc_membership_renewals_key ON oidc_membership_renewals(key_id)
  WHERE key_id IS NOT NULL;
