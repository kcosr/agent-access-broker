ALTER TABLE principals ADD COLUMN agent_token_issuance TEXT NOT NULL DEFAULT 'inherit'
    CHECK (agent_token_issuance IN ('inherit', 'disabled', 'read_only', 'write_capable'));
ALTER TABLE groups ADD COLUMN agent_token_issuance TEXT NOT NULL DEFAULT 'disabled'
    CHECK (agent_token_issuance IN ('disabled', 'read_only', 'write_capable'));
