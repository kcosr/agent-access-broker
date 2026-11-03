CREATE TABLE principal_agent_token_issuance_contexts (
    principal_id TEXT NOT NULL REFERENCES principals(principal_id) ON DELETE CASCADE,
    execution_context TEXT NOT NULL,
    PRIMARY KEY (principal_id, execution_context)
);
CREATE TABLE group_agent_token_issuance_contexts (
    group_id TEXT NOT NULL REFERENCES groups(group_id) ON DELETE CASCADE,
    execution_context TEXT NOT NULL,
    PRIMARY KEY (group_id, execution_context)
);
