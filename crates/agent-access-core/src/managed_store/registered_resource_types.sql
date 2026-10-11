CREATE TEMP TABLE registered_resource_types_saved_members AS
SELECT resource_group_id, resource_id, effect FROM resource_group_members;

DELETE FROM resource_group_members;

CREATE TABLE resources_v3 (
  resource_id TEXT PRIMARY KEY,
  resource_type TEXT NOT NULL CHECK (
    length(resource_type) BETWEEN 1 AND 64
    AND resource_type GLOB '[a-z]*'
    AND resource_type NOT GLOB '*[^a-z0-9_]*'
  ),
  selector_kind TEXT NOT NULL CHECK (selector_kind IN ('exact', 'namespace', 'all')),
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
    (selector_kind IN ('exact', 'namespace') AND length(selector_value) > 0)
  ),
  UNIQUE (resource_type, selector_kind, selector_value)
);

INSERT INTO resources_v3
SELECT resource_id, resource_type, selector_kind, selector_value, display_name,
       allowed_execution_contexts_json, enabled, version, created_at, created_by,
       updated_at, updated_by
FROM resources;

DROP TABLE resources;
ALTER TABLE resources_v3 RENAME TO resources;

INSERT INTO resource_group_members(resource_group_id, resource_id, effect)
SELECT resource_group_id, resource_id, effect FROM registered_resource_types_saved_members;

DROP TABLE registered_resource_types_saved_members;
