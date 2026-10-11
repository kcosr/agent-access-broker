-- Fresh managed-store baseline. Existing stores must be reset; no legacy migrations.

CREATE TABLE schema_migrations (
  version TEXT PRIMARY KEY,
  checksum TEXT NOT NULL,
  applied_at TEXT NOT NULL
);

CREATE TABLE principals (
  principal_id TEXT PRIMARY KEY,
  kind TEXT NOT NULL CHECK (kind IN ('user', 'service_account', 'system')),
  display_name TEXT,
  email TEXT,
  external_subject TEXT,
  status TEXT NOT NULL CHECK (status IN ('active', 'disabled')),
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  disabled_at TEXT,
  created_by TEXT NOT NULL
);

CREATE TABLE broker_tokens (
  token_id TEXT PRIMARY KEY,
  token_hash TEXT NOT NULL UNIQUE,
  principal_id TEXT NOT NULL REFERENCES principals(principal_id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  token_class TEXT NOT NULL CHECK (token_class IN ('agent_invoke', 'user_manage', 'admin')),
  scopes_json TEXT NOT NULL,
  created_at TEXT NOT NULL,
  expires_at TEXT,
  revoked_at TEXT,
  revoked_by TEXT,
  last_used_at TEXT,
  created_by TEXT NOT NULL,
  paused_at TEXT,
  paused_by TEXT
);

CREATE TABLE rights (
  right_id TEXT PRIMARY KEY,
  principal_id TEXT NOT NULL REFERENCES principals(principal_id) ON DELETE CASCADE,
  right_name TEXT NOT NULL,
  service TEXT,
  credential_name TEXT,
  resource_scope_json TEXT,
  created_by TEXT NOT NULL,
  created_at TEXT NOT NULL,
  expires_at TEXT,
  revoked_at TEXT,
  revoked_by TEXT,
  reason TEXT
);

CREATE TABLE credentials (
  credential_id TEXT PRIMARY KEY,
  owner_principal_id TEXT NOT NULL REFERENCES principals(principal_id) ON DELETE CASCADE,
  owner_kind TEXT NOT NULL CHECK (owner_kind IN ('user', 'service_account', 'system')),
  service TEXT NOT NULL,
  name TEXT NOT NULL,
  profile TEXT NOT NULL,
  credential_kind TEXT NOT NULL CHECK (credential_kind IN ('basic_api_token', 'bearer_token')),
  metadata_json TEXT NOT NULL,
  secret_backend TEXT NOT NULL CHECK (secret_backend = 'sqlite_encrypted'),
  secret_ref TEXT NOT NULL,
  material_version TEXT NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('active', 'disabled')),
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  created_by TEXT NOT NULL,
  updated_by TEXT NOT NULL,
  last_used_at TEXT,
  last_verified_at TEXT,
  verification_status TEXT,
  last_verification_attempt_at TEXT,
  last_verification_error_code TEXT,
  UNIQUE (owner_kind, owner_principal_id, service, name)
);

CREATE TABLE credential_secret_material (
  secret_ref TEXT PRIMARY KEY,
  credential_id TEXT NOT NULL UNIQUE REFERENCES credentials(credential_id) ON DELETE CASCADE,
  backend TEXT NOT NULL CHECK (backend = 'sqlite_encrypted'),
  secret_ciphertext BLOB NOT NULL,
  secret_nonce BLOB NOT NULL,
  key_id TEXT NOT NULL,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE INDEX idx_broker_tokens_principal ON broker_tokens(principal_id);

CREATE INDEX idx_rights_principal ON rights(principal_id, right_name, service, credential_name);

CREATE INDEX idx_credentials_owner ON credentials(owner_kind, owner_principal_id, service, name);

CREATE INDEX idx_credential_secret_material_credential ON credential_secret_material(credential_id);

CREATE TABLE principal_login_methods (
  login_method_id TEXT PRIMARY KEY,
  principal_id TEXT NOT NULL REFERENCES principals(principal_id) ON DELETE CASCADE,
  method TEXT NOT NULL CHECK (method IN ('local_password', 'oidc')),
  external_provider TEXT,
  external_subject TEXT,
  status TEXT NOT NULL CHECK (status IN ('active', 'disabled', 'locked')),
  password_hash_phc TEXT,
  password_set_at TEXT,
  must_change_password INTEGER NOT NULL DEFAULT 0 CHECK (must_change_password IN (0, 1)),
  failed_attempts INTEGER NOT NULL DEFAULT 0 CHECK (failed_attempts >= 0),
  locked_until TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  created_by TEXT NOT NULL,
  updated_by TEXT NOT NULL,
  CHECK (
    (method = 'local_password' AND password_hash_phc IS NOT NULL AND external_provider IS NULL AND external_subject IS NULL)
    OR
    (method = 'oidc' AND password_hash_phc IS NULL AND external_provider IS NOT NULL AND external_subject IS NOT NULL)
  )
);

CREATE UNIQUE INDEX idx_principal_login_methods_local_password
  ON principal_login_methods(principal_id, method)
  WHERE method = 'local_password';

CREATE UNIQUE INDEX idx_principal_login_methods_oidc_subject
  ON principal_login_methods(external_provider, external_subject)
  WHERE method = 'oidc';

CREATE INDEX idx_principal_login_methods_principal
  ON principal_login_methods(principal_id, method, status);

CREATE TABLE browser_sessions (
  token_id TEXT PRIMARY KEY REFERENCES broker_tokens(token_id) ON DELETE CASCADE,
  principal_id TEXT NOT NULL REFERENCES principals(principal_id) ON DELETE CASCADE,
  login_method TEXT NOT NULL CHECK (login_method IN ('local_password', 'oidc')),
  login_method_id TEXT NOT NULL REFERENCES principal_login_methods(login_method_id) ON DELETE CASCADE,
  auth_time TEXT NOT NULL,
  created_at TEXT NOT NULL,
  password_change_required INTEGER NOT NULL DEFAULT 0 CHECK (password_change_required IN (0, 1))
);

CREATE INDEX idx_browser_sessions_principal_method
  ON browser_sessions(principal_id, login_method);

CREATE TABLE principal_roles (
  principal_id TEXT NOT NULL REFERENCES principals(principal_id) ON DELETE CASCADE,
  role TEXT NOT NULL CHECK (role IN ('admin')),
  created_at TEXT NOT NULL,
  created_by TEXT NOT NULL,
  PRIMARY KEY (principal_id, role)
);

CREATE INDEX idx_principal_roles_role ON principal_roles(role, principal_id);

CREATE TABLE groups (
  group_id TEXT PRIMARY KEY,
  display_name TEXT,
  description TEXT,
  status TEXT NOT NULL CHECK (status IN ('active', 'disabled')),
  created_at TEXT NOT NULL,
  created_by TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  updated_by TEXT NOT NULL,
  disabled_at TEXT
);

CREATE TABLE principal_groups (
  principal_id TEXT NOT NULL REFERENCES principals(principal_id) ON DELETE CASCADE,
  group_id TEXT NOT NULL REFERENCES groups(group_id) ON DELETE RESTRICT,
  created_at TEXT NOT NULL,
  created_by TEXT NOT NULL,
  PRIMARY KEY (principal_id, group_id)
);

CREATE INDEX idx_groups_status ON groups(status, group_id);

CREATE INDEX idx_principal_groups_group ON principal_groups(group_id, principal_id);

CREATE TABLE policy_revisions (
  id INTEGER PRIMARY KEY CHECK (id = 1),
  generation INTEGER NOT NULL CHECK (generation >= 0),
  updated_at TEXT NOT NULL,
  updated_by TEXT NOT NULL
);

CREATE TABLE policy_grants (
  grant_id TEXT PRIMARY KEY,
  grant_order INTEGER NOT NULL UNIQUE,
  service TEXT NOT NULL,
  actions_json TEXT NOT NULL,
  resources_json TEXT NOT NULL,
  credential_mode TEXT NOT NULL CHECK (credential_mode IN ('service', 'per_user')),
  priority INTEGER,
  status TEXT NOT NULL CHECK (status IN ('active', 'disabled', 'deleted')),
  description TEXT,
  version INTEGER NOT NULL CHECK (version >= 1),
  created_at TEXT NOT NULL,
  created_by TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  updated_by TEXT NOT NULL,
  disabled_at TEXT,
  deleted_at TEXT
);

CREATE TABLE policy_grant_subjects (
  grant_id TEXT NOT NULL REFERENCES policy_grants(grant_id) ON DELETE CASCADE,
  subject TEXT NOT NULL,
  subject_order INTEGER NOT NULL CHECK (subject_order >= 0),
  PRIMARY KEY (grant_id, subject),
  UNIQUE (grant_id, subject_order)
);

CREATE INDEX idx_policy_grant_subjects_subject ON policy_grant_subjects(subject);

CREATE INDEX idx_policy_grants_service ON policy_grants(service, status);

CREATE INDEX idx_policy_grants_status ON policy_grants(status, grant_order);

CREATE TABLE shell_approval_revisions (
  id INTEGER PRIMARY KEY CHECK (id = 1),
  generation INTEGER NOT NULL CHECK (generation >= 0),
  updated_at TEXT NOT NULL,
  updated_by TEXT NOT NULL
);

CREATE TABLE shell_approval_policy (
  id INTEGER PRIMARY KEY CHECK (id = 1),
  config_json TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  updated_by TEXT NOT NULL
);

CREATE UNIQUE INDEX idx_principal_login_methods_oidc_principal_provider
  ON principal_login_methods(principal_id, external_provider)
  WHERE method = 'oidc';

CREATE TABLE oidc_provider_state (
  provider_id TEXT PRIMARY KEY CHECK (provider_id = 'microsoft'),
  tenant_id TEXT NOT NULL CHECK (length(tenant_id) = 36),
  client_id TEXT NOT NULL CHECK (length(client_id) = 36),
  enabled INTEGER NOT NULL CHECK (enabled IN (0, 1)),
  config_generation INTEGER NOT NULL CHECK (config_generation >= 1),
  config_fingerprint TEXT NOT NULL CHECK (length(config_fingerprint) BETWEEN 1 AND 256),
  external_membership_ttl_s INTEGER NOT NULL CHECK (external_membership_ttl_s BETWEEN 900 AND 86400),
  updated_at TEXT NOT NULL
);

CREATE TABLE oidc_authorization_flows (
  flow_sequence INTEGER PRIMARY KEY AUTOINCREMENT,
  state_hash BLOB NOT NULL UNIQUE CHECK (length(state_hash) = 32),
  browser_binding_hash BLOB NOT NULL CHECK (length(browser_binding_hash) = 32),
  provider_generation INTEGER NOT NULL CHECK (provider_generation >= 1),
  encrypted_payload BLOB NOT NULL CHECK (length(encrypted_payload) BETWEEN 1 AND 16384),
  encryption_nonce BLOB NOT NULL CHECK (length(encryption_nonce) = 12),
  return_path TEXT NOT NULL CHECK (length(return_path) BETWEEN 1 AND 2048),
  created_at TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  consumed_at TEXT,
  outcome_code TEXT CHECK (outcome_code IS NULL OR length(outcome_code) BETWEEN 1 AND 128),
  CHECK (expires_at > created_at),
  CHECK ((consumed_at IS NULL AND outcome_code IS NULL) OR consumed_at IS NOT NULL)
);

CREATE INDEX idx_oidc_authorization_flows_pending_expiry
  ON oidc_authorization_flows(expires_at, flow_sequence) WHERE consumed_at IS NULL;

CREATE TABLE oidc_subject_flow_watermarks (
  external_subject TEXT PRIMARY KEY CHECK (length(external_subject) = 82),
  last_flow_sequence INTEGER NOT NULL CHECK (last_flow_sequence >= 1),
  updated_at TEXT NOT NULL
);

CREATE INDEX idx_oidc_subject_flow_watermarks_updated
  ON oidc_subject_flow_watermarks(updated_at, external_subject);

CREATE TABLE external_group_bindings (
  binding_id TEXT PRIMARY KEY,
  external_group_id TEXT NOT NULL UNIQUE CHECK (length(external_group_id) = 36),
  group_id TEXT NOT NULL REFERENCES groups(group_id) ON DELETE RESTRICT,
  status TEXT NOT NULL CHECK (status IN ('active', 'disabled')),
  created_at TEXT NOT NULL,
  created_by TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  updated_by TEXT NOT NULL
);

CREATE INDEX idx_external_group_bindings_group
  ON external_group_bindings(group_id, status, binding_id);

CREATE TABLE oidc_membership_refresh_state (
  login_method_id TEXT PRIMARY KEY REFERENCES principal_login_methods(login_method_id) ON DELETE CASCADE,
  observed_at TEXT NOT NULL,
  evidence_at TEXT NOT NULL,
  valid_until TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  CHECK (observed_at >= evidence_at),
  CHECK (valid_until > evidence_at)
);

CREATE TABLE external_principal_groups (
  login_method_id TEXT NOT NULL REFERENCES principal_login_methods(login_method_id) ON DELETE CASCADE,
  binding_id TEXT NOT NULL REFERENCES external_group_bindings(binding_id) ON DELETE CASCADE,
  observed_at TEXT NOT NULL,
  evidence_at TEXT NOT NULL,
  valid_until TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  PRIMARY KEY (login_method_id, binding_id),
  CHECK (observed_at >= evidence_at),
  CHECK (valid_until > evidence_at)
);

CREATE INDEX idx_external_principal_groups_binding_expiry
  ON external_principal_groups(binding_id, valid_until, login_method_id);

CREATE INDEX idx_external_principal_groups_expiry
  ON external_principal_groups(valid_until, login_method_id);

CREATE TABLE policy_grant_contexts (
  grant_id TEXT NOT NULL REFERENCES policy_grants(grant_id) ON DELETE CASCADE,
  execution_context TEXT NOT NULL,
  context_order INTEGER NOT NULL CHECK (context_order >= 0),
  PRIMARY KEY (grant_id, execution_context),
  UNIQUE (grant_id, context_order)
);

CREATE INDEX idx_policy_grant_contexts_context
  ON policy_grant_contexts(execution_context, grant_id);

CREATE TABLE service_policy_management_assignments (
  assignment_id TEXT PRIMARY KEY,
  service TEXT NOT NULL,
  principal_id TEXT REFERENCES principals(principal_id) ON DELETE RESTRICT,
  group_id TEXT REFERENCES groups(group_id) ON DELETE RESTRICT,
  created_at TEXT NOT NULL,
  created_by TEXT NOT NULL,
  CHECK (
    (principal_id IS NOT NULL AND group_id IS NULL) OR
    (principal_id IS NULL AND group_id IS NOT NULL)
  )
);

CREATE UNIQUE INDEX idx_service_policy_management_principal_unique
  ON service_policy_management_assignments(service, principal_id)
  WHERE principal_id IS NOT NULL;

CREATE UNIQUE INDEX idx_service_policy_management_group_unique
  ON service_policy_management_assignments(service, group_id)
  WHERE group_id IS NOT NULL;

CREATE INDEX idx_service_policy_management_principal
  ON service_policy_management_assignments(principal_id, service);

CREATE INDEX idx_service_policy_management_group
  ON service_policy_management_assignments(group_id, service);

CREATE TABLE resources (
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
  CHECK (selector_kind != 'namespace' OR resource_type = 'git_repository'),
  UNIQUE (resource_type, selector_kind, selector_value)
);

CREATE TABLE resource_groups (
  resource_group_id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  version INTEGER NOT NULL CHECK (version >= 1),
  created_at TEXT NOT NULL,
  created_by TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  updated_by TEXT NOT NULL
);

CREATE TABLE resource_group_members (
  resource_group_id TEXT NOT NULL REFERENCES resource_groups(resource_group_id) ON DELETE CASCADE,
  resource_id TEXT NOT NULL REFERENCES resources(resource_id) ON DELETE RESTRICT,
  effect TEXT NOT NULL CHECK (effect IN ('include', 'exclude')),
  PRIMARY KEY (resource_group_id, resource_id, effect)
);

CREATE INDEX idx_resource_group_members_resource ON resource_group_members(resource_id, resource_group_id);

INSERT INTO policy_revisions(id, generation, updated_at, updated_by)
VALUES (1, 0, '1970-01-01T00:00:00Z', 'system');

INSERT INTO shell_approval_revisions(id, generation, updated_at, updated_by)
VALUES (1, 0, '1970-01-01T00:00:00Z', 'system');

INSERT INTO shell_approval_policy(id, config_json, updated_at, updated_by)
VALUES (1, '{"authority":"managed"}', '1970-01-01T00:00:00Z', 'system');
