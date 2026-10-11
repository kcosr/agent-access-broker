CREATE TABLE imported_catalog_revision (
    singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
    revision INTEGER NOT NULL CHECK(revision >= 0)
);
INSERT INTO imported_catalog_revision(singleton, revision) VALUES(1, 0);
CREATE TABLE imported_services (
    service TEXT PRIMARY KEY NOT NULL CHECK(length(service) BETWEEN 1 AND 63),
    definition_json TEXT NOT NULL CHECK(length(definition_json) <= 32768),
    status TEXT NOT NULL CHECK(status IN ('draft','disabled','enabled','retired')),
    version INTEGER NOT NULL CHECK(version > 0),
    created_at TEXT NOT NULL,
    created_by TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    updated_by TEXT NOT NULL
);
CREATE TABLE imported_actions (
    service TEXT NOT NULL REFERENCES imported_services(service),
    action TEXT NOT NULL CHECK(length(action) BETWEEN 1 AND 256),
    source_json TEXT NOT NULL,
    definition_json TEXT NOT NULL CHECK(length(definition_json) <= 262144),
    definition_hash TEXT NOT NULL,
    status TEXT NOT NULL CHECK(status IN ('enabled','disabled','quarantined','retired')),
    version INTEGER NOT NULL CHECK(version > 0),
    PRIMARY KEY(service, action)
);
CREATE UNIQUE INDEX imported_actions_live_source ON imported_actions(service, source_json)
    WHERE status != 'retired';
CREATE TABLE imported_previews (
    service TEXT PRIMARY KEY NOT NULL REFERENCES imported_services(service),
    preview_json TEXT NOT NULL CHECK(length(preview_json) <= 17039360)
);
CREATE TABLE imported_secret_material (
    service TEXT NOT NULL REFERENCES imported_services(service),
    purpose TEXT NOT NULL CHECK(purpose IN ('execution','discovery','transport')),
    credential_kind TEXT NOT NULL CHECK(credential_kind = 'bearer_token'),
    material_version TEXT NOT NULL CHECK(length(material_version) > 0),
    key_id TEXT NOT NULL CHECK(length(key_id) > 0),
    nonce BLOB NOT NULL CHECK(length(nonce) = 12),
    ciphertext BLOB NOT NULL CHECK(length(ciphertext) BETWEEN 16 AND 32784),
    PRIMARY KEY(service,purpose)
);
CREATE INDEX imported_secret_material_key_id ON imported_secret_material(key_id);
