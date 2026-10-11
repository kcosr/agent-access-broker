CREATE TEMP TABLE cloudbees_ci_saved_resource_members AS
SELECT resource_group_id, resource_id, effect FROM resource_group_members;

DELETE FROM resource_group_members;

CREATE TABLE resources_v2 (
  resource_id TEXT PRIMARY KEY,
  resource_type TEXT NOT NULL,
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
  CHECK (selector_kind != 'namespace' OR resource_type IN ('git_repository', 'cloudbees_ci_job')),
  UNIQUE (resource_type, selector_kind, selector_value)
);

INSERT INTO resources_v2
SELECT resource_id, resource_type, selector_kind, selector_value, display_name,
       allowed_execution_contexts_json, enabled, version, created_at, created_by,
       updated_at, updated_by
FROM resources;

DROP TABLE resources;
ALTER TABLE resources_v2 RENAME TO resources;

INSERT INTO resource_group_members(resource_group_id, resource_id, effect)
SELECT resource_group_id, resource_id, effect FROM cloudbees_ci_saved_resource_members;

DROP TABLE cloudbees_ci_saved_resource_members;
