-- Existing accounts never receive a later backfill of initial local groups.
ALTER TABLE principals ADD COLUMN microsoft_group_enrollment_processed INTEGER NOT NULL
  DEFAULT 0 CHECK(microsoft_group_enrollment_processed IN (0, 1));
UPDATE principals SET microsoft_group_enrollment_processed = 1;

CREATE TABLE pending_microsoft_enrollments (
  enrollment_id TEXT PRIMARY KEY NOT NULL,
  principal_id TEXT NOT NULL UNIQUE REFERENCES principals(principal_id) ON DELETE CASCADE,
  tenant_id TEXT NOT NULL,
  match_email TEXT NOT NULL CHECK(length(CAST(match_email AS BLOB)) BETWEEN 1 AND 320),
  revision INTEGER NOT NULL CHECK(typeof(revision) = 'integer' AND revision > 0),
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  created_by TEXT NOT NULL,
  updated_by TEXT NOT NULL,
  UNIQUE(tenant_id, match_email)
);

CREATE TRIGGER pending_microsoft_enrollment_insert
BEFORE INSERT ON pending_microsoft_enrollments
WHEN NOT EXISTS(SELECT 1 FROM principals WHERE principal_id = NEW.principal_id AND kind = 'user')
  OR EXISTS(SELECT 1 FROM principal_login_methods WHERE principal_id = NEW.principal_id
    AND method = 'oidc' AND external_provider = 'microsoft')
BEGIN SELECT RAISE(ABORT, 'Microsoft enrollment requires an unbound human principal'); END;

CREATE TRIGGER pending_microsoft_enrollment_update
BEFORE UPDATE ON pending_microsoft_enrollments
WHEN NEW.enrollment_id != OLD.enrollment_id OR NEW.principal_id != OLD.principal_id
  OR NEW.tenant_id != OLD.tenant_id OR NEW.created_at != OLD.created_at
  OR NEW.created_by != OLD.created_by
  OR NOT EXISTS(SELECT 1 FROM principals WHERE principal_id = NEW.principal_id AND kind = 'user')
  OR EXISTS(SELECT 1 FROM principal_login_methods WHERE principal_id = NEW.principal_id
    AND method = 'oidc' AND external_provider = 'microsoft')
BEGIN SELECT RAISE(ABORT, 'Microsoft enrollment identity is immutable'); END;

CREATE TRIGGER microsoft_login_method_pending_insert
BEFORE INSERT ON principal_login_methods
WHEN NEW.method = 'oidc' AND NEW.external_provider = 'microsoft'
  AND EXISTS(SELECT 1 FROM pending_microsoft_enrollments WHERE principal_id = NEW.principal_id)
BEGIN SELECT RAISE(ABORT, 'Microsoft enrollment must be consumed before binding'); END;

CREATE TRIGGER microsoft_login_method_pending_update
BEFORE UPDATE ON principal_login_methods
WHEN NEW.method = 'oidc' AND NEW.external_provider = 'microsoft'
  AND EXISTS(SELECT 1 FROM pending_microsoft_enrollments WHERE principal_id = NEW.principal_id)
BEGIN SELECT RAISE(ABORT, 'Microsoft enrollment must be consumed before binding'); END;

CREATE TRIGGER microsoft_enrollment_principal_kind_update
BEFORE UPDATE OF kind ON principals
WHEN NEW.kind != 'user'
  AND EXISTS(SELECT 1 FROM pending_microsoft_enrollments WHERE principal_id = OLD.principal_id)
BEGIN SELECT RAISE(ABORT, 'Microsoft enrollment requires a human principal'); END;
