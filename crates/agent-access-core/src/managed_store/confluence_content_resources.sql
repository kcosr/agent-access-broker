CREATE TEMP TABLE content_resources_saved_members AS
SELECT resource_group_id, resource_id, effect FROM resource_group_members;

CREATE TEMP TABLE content_resources_saved_material AS
SELECT resource_id, attribute_name, material_version, key_id, nonce, ciphertext
FROM resource_secret_material;

DELETE FROM resource_group_members;
DELETE FROM resource_secret_material;

CREATE TABLE resources_v4 (
  resource_id TEXT PRIMARY KEY,
  resource_type TEXT NOT NULL CHECK (
    length(resource_type) BETWEEN 1 AND 64
    AND resource_type GLOB '[a-z]*'
    AND resource_type NOT GLOB '*[^a-z0-9_]*'
  ),
  selector_kind TEXT NOT NULL CHECK (selector_kind IN ('exact', 'namespace', 'all', 'subtree')),
  selector_value TEXT NOT NULL,
  display_name TEXT,
  allowed_execution_contexts_json TEXT NOT NULL,
  enabled INTEGER NOT NULL CHECK (enabled IN (0, 1)),
  version INTEGER NOT NULL CHECK (version >= 1),
  created_at TEXT NOT NULL,
  created_by TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  updated_by TEXT NOT NULL,
  CHECK (
    (selector_kind = 'all' AND selector_value = '') OR
    (selector_kind IN ('exact', 'namespace', 'subtree') AND length(selector_value) > 0)
  ),
  UNIQUE (resource_type, selector_kind, selector_value)
);

INSERT INTO resources_v4
SELECT resource_id, resource_type, selector_kind, selector_value, display_name,
       allowed_execution_contexts_json, enabled, version, created_at, created_by,
       updated_at, updated_by
FROM resources;

DROP TABLE resources;
ALTER TABLE resources_v4 RENAME TO resources;

INSERT INTO resource_group_members(resource_group_id, resource_id, effect)
SELECT resource_group_id, resource_id, effect FROM content_resources_saved_members;

INSERT INTO resource_secret_material(resource_id, attribute_name, material_version, key_id, nonce, ciphertext)
SELECT resource_id, attribute_name, material_version, key_id, nonce, ciphertext
FROM content_resources_saved_material;

DROP TABLE content_resources_saved_members;
DROP TABLE content_resources_saved_material;
