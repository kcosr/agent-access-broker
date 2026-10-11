-- This deployment has never delegated policy management. Stop rather than
-- silently discard unexpected authority in the narrow schema upgrade.
CREATE TABLE principal_access_upgrade_precondition (
    assignment_count INTEGER NOT NULL
      CONSTRAINT service_policy_manager_assignments_must_be_empty CHECK (assignment_count = 0)
);
INSERT INTO principal_access_upgrade_precondition
  SELECT COUNT(*) FROM service_policy_management_assignments;
DROP TABLE principal_access_upgrade_precondition;

ALTER TABLE principals ADD COLUMN role TEXT NOT NULL DEFAULT 'user'
  CHECK (role IN ('user', 'auditor', 'service_policy_manager', 'admin')
    AND (kind = 'user' OR (kind = 'system' AND role IN ('user', 'service_policy_manager'))
      OR (kind = 'service_account' AND role = 'user')));
ALTER TABLE principals ADD COLUMN self_service_enabled INTEGER NOT NULL DEFAULT 0
  CHECK (self_service_enabled IN (0, 1)
    AND (kind != 'service_account' OR self_service_enabled = 0));
UPDATE principals SET role = 'admin'
  WHERE kind = 'user' AND principal_id IN (SELECT principal_id FROM principal_roles WHERE role = 'admin');
UPDATE principals SET self_service_enabled = 1 WHERE kind IN ('user', 'system');
DROP TABLE principal_roles;
DROP TABLE service_policy_management_assignments;
CREATE TABLE service_policy_management_assignments (
  assignment_id TEXT PRIMARY KEY,
  service TEXT NOT NULL,
  principal_id TEXT NOT NULL REFERENCES principals(principal_id) ON DELETE RESTRICT,
  created_at TEXT NOT NULL,
  created_by TEXT NOT NULL,
  UNIQUE(service, principal_id)
);
CREATE INDEX idx_service_policy_management_principal
  ON service_policy_management_assignments(principal_id, service);
