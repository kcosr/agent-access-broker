-- Usernames: the ID a person or a service account is known by to the
-- services that resolve their access keys. One primary key holds people's
-- names and service-account principal IDs, so the two sets cannot overlap;
-- names the operator reserves are refused when a name is allocated. Changing
-- or removing a name replaces or deletes its row, so every allocation has
-- its own incarnation.
CREATE TABLE account_usernames (
  account_username TEXT PRIMARY KEY NOT NULL
    CHECK(length(CAST(account_username AS BLOB)) BETWEEN 1 AND 256
      AND account_username NOT GLOB '*[^A-Za-z0-9._@+-]*'
      AND account_username <> 'anonymous'),
  principal_id TEXT NOT NULL UNIQUE REFERENCES principals(principal_id) ON DELETE CASCADE,
  holder_kind TEXT NOT NULL CHECK(holder_kind IN ('user', 'service_account')),
  incarnation TEXT NOT NULL UNIQUE
    CHECK(length(incarnation) BETWEEN 1 AND 64 AND incarnation NOT GLOB '*[^A-Za-z0-9_-]*'),
  origin TEXT NOT NULL CHECK(origin IN ('derived', 'administrator', 'service_account')),
  assigned_at TEXT NOT NULL,
  assigned_by TEXT NOT NULL,
  confirmed_at TEXT,
  confirmed_by TEXT,
  CHECK((confirmed_at IS NULL) = (confirmed_by IS NULL)),
  CHECK((holder_kind = 'service_account') = (origin = 'service_account')),
  CHECK(holder_kind <> 'service_account' OR (account_username = principal_id AND confirmed_at IS NULL))
);

CREATE TRIGGER account_usernames_require_holder
BEFORE INSERT ON account_usernames
WHEN NOT EXISTS (SELECT 1 FROM principals
  WHERE principal_id = NEW.principal_id AND kind = NEW.holder_kind)
BEGIN
  SELECT RAISE(ABORT, 'username holder does not match its principal');
END;

-- Only an administrator's confirmation changes a row in place.
CREATE TRIGGER account_usernames_immutable_allocation
BEFORE UPDATE OF account_username, principal_id, holder_kind, incarnation, origin, assigned_at,
  assigned_by ON account_usernames
WHEN NEW.account_username <> OLD.account_username OR NEW.principal_id <> OLD.principal_id
  OR NEW.holder_kind <> OLD.holder_kind OR NEW.incarnation <> OLD.incarnation
  OR NEW.origin <> OLD.origin OR NEW.assigned_at <> OLD.assigned_at
  OR NEW.assigned_by <> OLD.assigned_by
BEGIN
  SELECT RAISE(ABORT, 'username allocation is immutable');
END;

-- A service account's username is its principal ID, held from creation on
-- every path that creates one or changes a principal's kind. An ID a person
-- holds as a username cannot become a service account.
INSERT INTO account_usernames
  (account_username, principal_id, holder_kind, incarnation, origin, assigned_at, assigned_by)
SELECT principal_id, principal_id, 'service_account', lower(hex(randomblob(16))),
       'service_account', created_at, 'system:access_keys_migration'
FROM principals
WHERE kind = 'service_account'
  AND length(CAST(principal_id AS BLOB)) BETWEEN 1 AND 256
  AND principal_id NOT GLOB '*[^A-Za-z0-9._@+-]*'
  AND principal_id <> 'anonymous';

CREATE TRIGGER account_usernames_service_account_id_free_on_create
BEFORE INSERT ON principals
WHEN NEW.kind = 'service_account'
  AND EXISTS (SELECT 1 FROM account_usernames WHERE account_username = NEW.principal_id)
BEGIN
  SELECT RAISE(ABORT, 'service account ID is held as a username');
END;

CREATE TRIGGER account_usernames_on_service_account_create
AFTER INSERT ON principals
WHEN NEW.kind = 'service_account'
  AND length(CAST(NEW.principal_id AS BLOB)) BETWEEN 1 AND 256
  AND NEW.principal_id NOT GLOB '*[^A-Za-z0-9._@+-]*'
  AND NEW.principal_id <> 'anonymous'
BEGIN
  INSERT INTO account_usernames
    (account_username, principal_id, holder_kind, incarnation, origin, assigned_at, assigned_by)
  VALUES (NEW.principal_id, NEW.principal_id, 'service_account', lower(hex(randomblob(16))),
          'service_account', NEW.updated_at, NEW.created_by);
END;

CREATE TRIGGER account_usernames_service_account_id_free_on_kind_change
BEFORE UPDATE OF kind ON principals
WHEN NEW.kind = 'service_account' AND OLD.kind <> 'service_account'
  AND EXISTS (SELECT 1 FROM account_usernames
    WHERE account_username = NEW.principal_id AND principal_id <> NEW.principal_id)
BEGIN
  SELECT RAISE(ABORT, 'service account ID is held as a username');
END;

CREATE TRIGGER account_usernames_on_service_account_kind_removed
AFTER UPDATE OF kind ON principals
WHEN OLD.kind = 'service_account' AND NEW.kind <> 'service_account'
BEGIN
  DELETE FROM account_usernames
    WHERE principal_id = NEW.principal_id AND holder_kind = 'service_account';
END;

CREATE TRIGGER account_usernames_on_service_account_kind_assigned
AFTER UPDATE OF kind ON principals
WHEN NEW.kind = 'service_account' AND OLD.kind <> 'service_account'
  AND length(CAST(NEW.principal_id AS BLOB)) BETWEEN 1 AND 256
  AND NEW.principal_id NOT GLOB '*[^A-Za-z0-9._@+-]*'
  AND NEW.principal_id <> 'anonymous'
BEGIN
  INSERT INTO account_usernames
    (account_username, principal_id, holder_kind, incarnation, origin, assigned_at, assigned_by)
  VALUES (NEW.principal_id, NEW.principal_id, 'service_account', lower(hex(randomblob(16))),
          'service_account', NEW.updated_at, 'system:principal_kind');
END;

-- How a person's name is decided: it follows the profile email, or an
-- administrator sets it. Every existing account starts on the email; the
-- names themselves are allocated after startup, not by this migration.
ALTER TABLE principals ADD COLUMN account_username_mode TEXT NOT NULL DEFAULT 'from_email'
  CHECK(account_username_mode IN ('from_email', 'manual'));

-- Access keys are presented to a resolving service, never to the Broker.
-- They are kept apart from broker_tokens so that no Broker path can resolve
-- one. Only the broker-token keyed hash of a key is stored.
CREATE TABLE access_keys (
  key_id TEXT PRIMARY KEY NOT NULL
    CHECK(length(key_id) BETWEEN 4 AND 63 AND substr(key_id, 1, 3) = 'ak_'
      AND substr(key_id, 4) NOT GLOB '*[^A-Za-z0-9_-]*'),
  key_hash TEXT NOT NULL UNIQUE CHECK(length(key_hash) = 43),
  principal_id TEXT NOT NULL REFERENCES principals(principal_id) ON DELETE CASCADE,
  name TEXT NOT NULL CHECK(length(CAST(name AS BLOB)) BETWEEN 1 AND 128),
  origin TEXT NOT NULL CHECK(origin IN ('portal', 'administrator', 'application')),
  username_incarnation TEXT NOT NULL
    CHECK(length(username_incarnation) BETWEEN 1 AND 64
      AND username_incarnation NOT GLOB '*[^A-Za-z0-9_-]*'),
  created_at TEXT NOT NULL,
  created_by TEXT NOT NULL,
  expires_at TEXT,
  revoked_at TEXT,
  revoked_by TEXT,
  last_used_at TEXT,
  CHECK (expires_at IS NULL OR expires_at > created_at),
  CHECK((revoked_at IS NULL) = (revoked_by IS NULL))
);

CREATE INDEX idx_access_keys_principal ON access_keys(principal_id, created_at);

-- A person holds the keys they create, those an application obtains for
-- them and those an administrator issues for them; a service account holds
-- only keys an administrator issues for it.
CREATE TRIGGER access_keys_origin_matches_owner
BEFORE INSERT ON access_keys
WHEN NOT EXISTS (SELECT 1 FROM principals WHERE principal_id = NEW.principal_id
  AND ((NEW.origin = 'administrator' AND kind IN ('user', 'service_account'))
    OR (NEW.origin IN ('portal', 'application') AND kind = 'user')))
BEGIN
  SELECT RAISE(ABORT, 'access key origin does not match its owner');
END;

CREATE TRIGGER access_keys_immutable_identity
BEFORE UPDATE OF key_id, key_hash, principal_id, origin, username_incarnation, created_at,
  created_by, expires_at ON access_keys
WHEN NEW.key_id <> OLD.key_id OR NEW.key_hash <> OLD.key_hash
  OR NEW.principal_id <> OLD.principal_id OR NEW.origin <> OLD.origin
  OR NEW.username_incarnation <> OLD.username_incarnation OR NEW.created_at <> OLD.created_at
  OR NEW.created_by <> OLD.created_by OR NEW.expires_at IS NOT OLD.expires_at
BEGIN
  SELECT RAISE(ABORT, 'access key identity is immutable');
END;

CREATE TRIGGER access_keys_revocation_is_final
BEFORE UPDATE OF revoked_at, revoked_by ON access_keys
WHEN OLD.revoked_at IS NOT NULL
  AND (NEW.revoked_at IS NOT OLD.revoked_at OR NEW.revoked_by IS NOT OLD.revoked_by)
BEGIN
  SELECT RAISE(ABORT, 'access key revocation is final');
END;

-- The access key type names a key carries, in the order they were
-- requested. What each name currently allows is read from configuration at
-- resolution.
CREATE TABLE access_key_type_links (
  key_id TEXT NOT NULL REFERENCES access_keys(key_id) ON DELETE CASCADE,
  access_key_type TEXT NOT NULL
    CHECK(length(access_key_type) BETWEEN 1 AND 64 AND access_key_type GLOB '[a-z]*'
      AND access_key_type NOT GLOB '*[^a-z0-9_-]*'),
  access_key_type_order INTEGER NOT NULL
    CHECK(typeof(access_key_type_order) = 'integer' AND access_key_type_order BETWEEN 0 AND 15),
  PRIMARY KEY (key_id, access_key_type),
  UNIQUE (key_id, access_key_type_order)
);

-- Who may hold each access key type, decided separately for each type. An
-- account allows or denies a type, or says nothing and inherits; a group
-- allows a type for its local members that inherit it, and never denies.
-- The rows name access key types only: what each name means is read from
-- configuration.
CREATE TABLE principal_access_key_types (
  principal_id TEXT NOT NULL REFERENCES principals(principal_id) ON DELETE CASCADE,
  access_key_type TEXT NOT NULL
    CHECK(length(access_key_type) BETWEEN 1 AND 64 AND access_key_type GLOB '[a-z]*'
      AND access_key_type NOT GLOB '*[^a-z0-9_-]*'),
  decision TEXT NOT NULL CHECK(decision IN ('allow', 'deny')),
  PRIMARY KEY (principal_id, access_key_type)
);

CREATE TABLE group_access_key_types (
  group_id TEXT NOT NULL REFERENCES groups(group_id) ON DELETE CASCADE,
  access_key_type TEXT NOT NULL
    CHECK(length(access_key_type) BETWEEN 1 AND 64 AND access_key_type GLOB '[a-z]*'
      AND access_key_type NOT GLOB '*[^a-z0-9_-]*'),
  PRIMARY KEY (group_id, access_key_type)
);
