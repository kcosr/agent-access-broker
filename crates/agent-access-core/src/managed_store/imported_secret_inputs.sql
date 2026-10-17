ALTER TABLE imported_actions ADD COLUMN secret_inputs_json TEXT
    NOT NULL DEFAULT '[]' CHECK(length(secret_inputs_json) <= 65536);
