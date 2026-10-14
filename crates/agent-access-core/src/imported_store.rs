//! Transactional imported-service definitions and service-owned encrypted tokens.
//! No imported credential is represented by a synthetic principal.
use super::*;
use crate::imports::{
    IMPORT_MAX_MANIFEST_BYTES, IMPORT_MAX_SERVICES, IMPORT_MAX_TOOLS, IMPORT_PREVIEW_TTL_SECONDS,
    ImportedActionDefinition, ImportedCredentialPurpose, ImportedServiceDefinition,
};

// Retired identities have their own bounded retention allowance so replacing
// tools does not consume the active discovery budget. The whole serialized
// catalog (all services, including tombstones) still has a 64 MiB ceiling.
const IMPORT_MAX_RETIRED_ACTIONS: usize = 8192;
const IMPORT_MAX_RETIRED_ACTION_BYTES: usize = 32 * 1024 * 1024;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ImportedServiceStatus {
    Draft,
    Disabled,
    Enabled,
    Retired,
}
impl ImportedServiceStatus {
    fn as_str(self) -> &'static str {
        match self {
            Self::Draft => "draft",
            Self::Disabled => "disabled",
            Self::Enabled => "enabled",
            Self::Retired => "retired",
        }
    }
}
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ImportedActionStatus {
    Enabled,
    Disabled,
    Quarantined,
    Retired,
}
impl ImportedActionStatus {
    fn as_str(self) -> &'static str {
        match self {
            Self::Enabled => "enabled",
            Self::Disabled => "disabled",
            Self::Quarantined => "quarantined",
            Self::Retired => "retired",
        }
    }
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ImportedActionRecord {
    pub definition: ImportedActionDefinition,
    pub status: ImportedActionStatus,
    pub version: u64,
    pub definition_hash: String,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ImportedServiceRecord {
    pub definition: ImportedServiceDefinition,
    pub status: ImportedServiceStatus,
    pub version: u64,
    pub actions: Vec<ImportedActionRecord>,
    pub slot_versions: BTreeMap<ImportedCredentialPurpose, String>,
    pub created_at: String,
    pub created_by: String,
    pub updated_at: String,
    pub updated_by: String,
}
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ImportedCatalog {
    pub revision: u64,
    pub services: Vec<ImportedServiceRecord>,
}
impl ImportedCatalog {
    pub fn service(&self, service: &str) -> Option<&ImportedServiceRecord> {
        self.services
            .iter()
            .find(|r| r.definition.service == service)
    }
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ImportedPreview {
    pub service: String,
    pub service_version: u64,
    pub catalog_revision: u64,
    pub config_revision: String,
    pub credential_versions: BTreeMap<String, String>,
    pub manifest_hash: String,
    /// Complete bounded discovery, including unsupported tools. No credentials.
    pub manifest: Value,
    pub created_at: String,
    pub expires_at: String,
    pub created_by: String,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ImportedActionWrite {
    pub definition: ImportedActionDefinition,
    pub status: ImportedActionStatus,
}
#[derive(Debug, Clone)]
pub struct ImportedPreviewAcceptance {
    pub manifest_hash: String,
    pub config_revision: String,
    pub credential_versions: BTreeMap<String, String>,
}
#[derive(Debug, Clone)]
pub struct ImportedServiceUpdateRequest {
    pub definition: ImportedServiceDefinition,
    pub status: ImportedServiceStatus,
    /// Complete retained action set: omission cannot delete an accepted identity.
    pub actions: Vec<ImportedActionWrite>,
    pub expected_version: u64,
    pub expected_catalog_revision: u64,
    pub accepted_preview: Option<ImportedPreviewAcceptance>,
    pub actor: String,
}
#[derive(Debug, Clone)]
pub struct ImportedPreviewWriteRequest {
    pub service: String,
    pub expected_version: u64,
    pub expected_catalog_revision: u64,
    pub config_revision: String,
    pub credential_versions: BTreeMap<String, String>,
    pub manifest: Value,
    /// Changed/missing accepted actions from this complete authorized observation.
    pub quarantine_actions: Vec<String>,
    pub actor: String,
}
/// The caller builds a publication candidate while the SQLite transaction is
/// open. After this returns successfully, publishing `value` must be infallible.
#[derive(Debug)]
pub struct ImportedMutationResult<T> {
    pub catalog: ImportedCatalog,
    pub value: T,
}

impl ManagedStore {
    pub fn imported_catalog(&self) -> Result<ImportedCatalog, ManagedStoreError> {
        catalog(&self.connection.lock().unwrap())
    }
    pub fn imported_discovery_credential_versions(
        &self,
        service: &str,
        expected_service_version: u64,
    ) -> Result<BTreeMap<String, String>, ManagedStoreError> {
        let conn = self.connection.lock().unwrap();
        let record = service_record(&conn, service)?
            .ok_or_else(|| input_invalid("imported service was not found"))?;
        if record.version != expected_service_version {
            return Err(ManagedStoreError::VersionConflict);
        }
        discovery_versions(&conn, &record)
    }
    pub fn imported_preview(
        &self,
        service: &str,
    ) -> Result<Option<ImportedPreview>, ManagedStoreError> {
        let conn = self.connection.lock().unwrap();
        let Some(preview) = preview(&conn, service)? else {
            return Ok(None);
        };
        let record = service_record(&conn, service)?
            .ok_or_else(|| input_invalid("imported service was not found"))?;
        if preview.service_version != record.version
            || preview.catalog_revision != revision(&conn)?
            || discovery_versions(&conn, &record).ok().as_ref()
                != Some(&preview.credential_versions)
            || DateTime::parse_from_rfc3339(&preview.expires_at).map_err(|_| invalid_data())?
                <= Utc::now()
        {
            return Ok(None);
        }
        Ok(Some(preview))
    }
    pub fn create_imported_service<T>(
        &self,
        definition: ImportedServiceDefinition,
        actor: &str,
        validate: impl FnOnce(&ImportedCatalog) -> Result<T, ManagedStoreError>,
    ) -> Result<ImportedMutationResult<T>, ManagedStoreError> {
        definition.validate().map_err(input_invalid)?;
        validate_actor(actor)?;
        let json = bounded_json(&definition, 32768)?;
        let mut conn = self.connection.lock().unwrap();
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sql_unavailable)?;
        require_import_admin(&tx, actor)?;
        require_discovery_owner(&definition, actor)?;
        require_unused_service_identity(&tx, &definition.service)?;
        if service_record(&tx, &definition.service)?.is_some() {
            return Err(input_invalid(
                "imported service identity already exists and cannot be recycled",
            ));
        }
        if count_table(&tx, "imported_services")? >= IMPORT_MAX_SERVICES as u64 {
            return Err(input_invalid("imported service capacity is exhausted"));
        }
        let now = normalized_now_string();
        tx.execute("INSERT INTO imported_services(service,definition_json,status,version,created_at,created_by,updated_at,updated_by) VALUES(?1,?2,'draft',1,?3,?4,?3,?4)", params![definition.service,json,now,actor]).map_err(sql_unavailable)?;
        finish(tx, validate)
    }
    pub fn update_imported_service<T>(
        &self,
        request: ImportedServiceUpdateRequest,
        validate: impl FnOnce(&ImportedCatalog) -> Result<T, ManagedStoreError>,
    ) -> Result<ImportedMutationResult<T>, ManagedStoreError> {
        validate_actor(&request.actor)?;
        let mut conn = self.connection.lock().unwrap();
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sql_unavailable)?;
        require_import_admin(&tx, &request.actor)?;
        let old = require_version(
            &tx,
            &request.definition.service,
            request.expected_version,
            request.expected_catalog_revision,
        )?;
        let newly_enabled = request.status == ImportedServiceStatus::Enabled
            && old.status != ImportedServiceStatus::Enabled;
        if request.definition != old.definition || newly_enabled {
            request.definition.validate().map_err(input_invalid)?;
        }
        if request.definition.discovery != old.definition.discovery {
            require_discovery_owner(&request.definition, &request.actor)?;
        }
        validate_actions(
            &request.definition.service,
            &request.actions,
            &old.actions,
            newly_enabled,
        )?;
        let empty_draft_edit = old.status == ImportedServiceStatus::Draft
            && old.actions.is_empty()
            && request.actions.is_empty()
            && request.accepted_preview.is_none();
        if !old.definition.same_base_destination(&request.definition)
            || (!empty_draft_edit && !old.definition.same_destination(&request.definition))
        {
            return Err(input_invalid(
                "changing an import destination requires a new service identity",
            ));
        }
        if empty_draft_edit && !old.definition.same_destination(&request.definition) {
            // Settings are adapter-owned, so conservatively invalidate both token
            // purposes for any destination/settings/delivery change. Do not
            // repurpose another user's stored personal token or silently delete it.
            let has_personal_credentials: bool = tx
                .query_row(
                    "SELECT EXISTS(SELECT 1 FROM credentials WHERE service=?1)",
                    [&request.definition.service],
                    |row| row.get(0),
                )
                .map_err(sql_unavailable)?;
            if has_personal_credentials {
                return Err(input_invalid(
                    "remove personal credentials before changing draft connection settings or token delivery",
                ));
            }
            tx.execute(
                "DELETE FROM imported_secret_material WHERE service=?1 AND purpose IN ('execution','discovery')",
                [&request.definition.service],
            ).map_err(sql_unavailable)?;
        }
        if old.status == ImportedServiceStatus::Retired
            && request.status != ImportedServiceStatus::Retired
        {
            return Err(input_invalid(
                "retired imported service identities cannot be reused",
            ));
        }
        if old.status != ImportedServiceStatus::Draft
            && request.status == ImportedServiceStatus::Draft
        {
            return Err(input_invalid(
                "accepted imported services cannot become drafts",
            ));
        }
        if let Some(acceptance) = &request.accepted_preview {
            require_discovery_owner(&old.definition, &request.actor)?;
            let pending = preview(&tx, &request.definition.service)?
                .ok_or(ManagedStoreError::VersionConflict)?;
            if pending.service_version != old.version
                || pending.catalog_revision != request.expected_catalog_revision
                || pending.manifest_hash != acceptance.manifest_hash
                || pending.config_revision != acceptance.config_revision
                || pending.credential_versions != acceptance.credential_versions
                || discovery_versions(&tx, &old)? != acceptance.credential_versions
                || DateTime::parse_from_rfc3339(&pending.expires_at).map_err(|_| invalid_data())?
                    <= Utc::now()
            {
                return Err(ManagedStoreError::VersionConflict);
            }
        }
        if old.status != ImportedServiceStatus::Draft
            && old.definition.execution_bindings.iter().any(|binding| {
                !request
                    .definition
                    .execution_bindings
                    .iter()
                    .any(|candidate| candidate.owner_mode == binding.owner_mode)
            })
        {
            return Err(input_invalid(
                "accepted credential modes must be retained as unavailable bindings",
            ));
        }
        validate_retained_actions(&request.actions, &old.actions)?;
        // Retire old mappings before inserting replacements, regardless of the
        // caller's order, so the live-source uniqueness constraint stays valid.
        for action in request
            .actions
            .iter()
            .filter(|action| action.status == ImportedActionStatus::Retired)
            .chain(
                request
                    .actions
                    .iter()
                    .filter(|action| action.status != ImportedActionStatus::Retired),
            )
        {
            let old_action = old
                .actions
                .iter()
                .find(|v| v.definition.action == action.definition.action);
            let changed = old_action
                .is_none_or(|v| v.definition != action.definition || v.status != action.status);
            let version = old_action.map_or(1, |v| v.version + u64::from(changed));
            let definition_json =
                bounded_json(&action.definition, crate::imports::IMPORT_MAX_TOOL_BYTES)?;
            let hash = sha256_hex(definition_json.as_bytes());
            let source =
                serde_json::to_string(&action.definition.source).map_err(|_| invalid_data())?;
            tx.execute("INSERT INTO imported_actions(service,action,source_json,definition_json,definition_hash,status,version) VALUES(?1,?2,?3,?4,?5,?6,?7) ON CONFLICT(service,action) DO UPDATE SET definition_json=excluded.definition_json,definition_hash=excluded.definition_hash,status=excluded.status,version=excluded.version", params![request.definition.service,action.definition.action,source,definition_json,hash,action.status.as_str(),db_version(version)?]).map_err(sql_unavailable)?;
        }
        let json = bounded_json(&request.definition, 32768)?;
        tx.execute("UPDATE imported_services SET definition_json=?2,status=?3,version=version+1,updated_at=?4,updated_by=?5 WHERE service=?1",params![request.definition.service,json,request.status.as_str(),normalized_now_string(),request.actor]).map_err(sql_unavailable)?;
        tx.execute(
            "DELETE FROM imported_previews WHERE service=?1",
            [&request.definition.service],
        )
        .map_err(sql_unavailable)?;
        finish(tx, validate)
    }
    pub fn write_imported_preview<T>(
        &self,
        request: ImportedPreviewWriteRequest,
        validate: impl FnOnce(&ImportedCatalog) -> Result<T, ManagedStoreError>,
    ) -> Result<ImportedMutationResult<T>, ManagedStoreError> {
        validate_actor(&request.actor)?;
        validate_preview_context(&request.config_revision, &request.credential_versions)?;
        let manifest = bounded_json(&request.manifest, IMPORT_MAX_MANIFEST_BYTES)?;
        let mut conn = self.connection.lock().unwrap();
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sql_unavailable)?;
        require_import_admin(&tx, &request.actor)?;
        let record = require_version(
            &tx,
            &request.service,
            request.expected_version,
            request.expected_catalog_revision,
        )?;
        require_discovery_owner(&record.definition, &request.actor)?;
        if record.status == ImportedServiceStatus::Retired {
            return Err(input_invalid(
                "retired imported services cannot be refreshed",
            ));
        }
        if discovery_versions(&tx, &record)? != request.credential_versions {
            return Err(ManagedStoreError::VersionConflict);
        }
        let mut seen = BTreeSet::new();
        for action in &request.quarantine_actions {
            if !seen.insert(action) {
                return Err(input_invalid("duplicate quarantine action"));
            }
            let stored = record
                .actions
                .iter()
                .find(|r| r.definition.action == *action)
                .ok_or_else(|| input_invalid("quarantine action was not found"))?;
            if stored.status != ImportedActionStatus::Retired
                && stored.status != ImportedActionStatus::Quarantined
            {
                tx.execute("UPDATE imported_actions SET status='quarantined',version=version+1 WHERE service=?1 AND action=?2",params![request.service,action]).map_err(sql_unavailable)?;
            }
        }
        let now = Utc::now();
        let pending = ImportedPreview {
            service: request.service.clone(),
            service_version: record.version + 1,
            catalog_revision: request.expected_catalog_revision + 1,
            config_revision: request.config_revision,
            credential_versions: request.credential_versions,
            manifest_hash: sha256_hex(manifest.as_bytes()),
            manifest: request.manifest,
            created_at: now.to_rfc3339_opts(SecondsFormat::Secs, true),
            expires_at: (now + Duration::seconds(IMPORT_PREVIEW_TTL_SECONDS))
                .to_rfc3339_opts(SecondsFormat::Secs, true),
            created_by: request.actor.clone(),
        };
        tx.execute("INSERT INTO imported_previews(service,preview_json) VALUES(?1,?2) ON CONFLICT(service) DO UPDATE SET preview_json=excluded.preview_json",params![request.service,bounded_json(&pending,IMPORT_MAX_MANIFEST_BYTES + 262144)?]).map_err(sql_unavailable)?;
        touch(&tx, &request.service, &request.actor)?;
        finish(tx, validate)
    }
}

// Services are an authority namespace, not just a presentation label. A removed
// built-in may leave credentials or delegated administration behind in this DB.
// Import creation must never attach a new endpoint to that retained authority.
fn require_unused_service_identity(
    conn: &Connection,
    service: &str,
) -> Result<(), ManagedStoreError> {
    let used: bool = conn
        .query_row(
            "SELECT EXISTS(
            SELECT 1 FROM credentials WHERE service=?1
            UNION ALL SELECT 1 FROM rights WHERE service=?1
            UNION ALL SELECT 1 FROM policy_grants WHERE service=?1
            UNION ALL SELECT 1 FROM service_policy_management_assignments WHERE service=?1
            UNION ALL SELECT 1 FROM principal_service_limits WHERE service=?1
        )",
            [service],
            |row| row.get(0),
        )
        .map_err(sql_unavailable)?;
    if used {
        return Err(input_invalid(
            "service identity already in use by retained credentials or authority",
        ));
    }
    Ok(())
}
fn require_discovery_owner(
    definition: &ImportedServiceDefinition,
    actor: &str,
) -> Result<(), ManagedStoreError> {
    if let crate::imports::ImportedDiscoveryCredential::PerUser { principal } =
        &definition.discovery
        && principal != actor
    {
        return Err(ManagedStoreError::RightMissing);
    }
    Ok(())
}

impl ManagedStore {
    pub fn can_manage_imported_oauth(
        &self,
        actor: &str,
        service: &str,
    ) -> Result<bool, ManagedStoreError> {
        let conn = self
            .connection
            .lock()
            .map_err(|_| ManagedStoreError::Unavailable("managed store lock".into()))?;
        admin_oauth_admission(&conn, actor, service)
    }
}
pub(super) fn admin_oauth_admission(
    conn: &Connection,
    actor: &str,
    service: &str,
) -> Result<bool, ManagedStoreError> {
    if principal_by_id_without_groups(conn, actor)?.status != "active"
        || management_authority_conn(conn, actor)?.principal.role != PrincipalRole::Admin
    {
        return Ok(false);
    }
    let Some(record) = service_record(conn, service)? else {
        return Ok(false);
    };
    Ok(
        matches!(&record.definition.discovery, crate::imports::ImportedDiscoveryCredential::PerUser { principal } if principal == actor)
            && record.definition.execution_bindings.iter().any(|b| {
                b.is_supported()
                    && b.owner_mode == crate::imports::ImportedCredentialMode::PerUser
                    && b.mechanism == crate::imports::ImportedAuthMechanism::Oauth
            }),
    )
}
pub(super) fn oauth_admission_version(
    conn: &Connection,
    service: &str,
    version: u64,
) -> Result<bool, ManagedStoreError> {
    Ok(service_record(conn, service)?
        .is_some_and(|r| r.version == version && r.status != ImportedServiceStatus::Retired))
}

fn require_import_admin(conn: &Connection, actor: &str) -> Result<(), ManagedStoreError> {
    let principal = principal_by_id_without_groups(conn, actor)?;
    if principal.status != "active" {
        return Err(ManagedStoreError::PrincipalDisabled);
    }
    if management_authority_conn(conn, actor)?.principal.role != PrincipalRole::Admin {
        return Err(ManagedStoreError::RightMissing);
    }
    Ok(())
}
fn discovery_versions(
    conn: &Connection,
    record: &ImportedServiceRecord,
) -> Result<BTreeMap<String, String>, ManagedStoreError> {
    let mut versions = BTreeMap::new();
    let slot = |purpose: ImportedCredentialPurpose| {
        record
            .slot_versions
            .get(&purpose)
            .cloned()
            .ok_or(ManagedStoreError::CredentialNotFound)
    };
    match &record.definition.discovery {
        crate::imports::ImportedDiscoveryCredential::Anonymous => {}
        crate::imports::ImportedDiscoveryCredential::Execution => {
            versions.insert(
                "execution".into(),
                slot(ImportedCredentialPurpose::Execution)?,
            );
        }
        crate::imports::ImportedDiscoveryCredential::Slot => {
            versions.insert(
                "discovery".into(),
                slot(ImportedCredentialPurpose::Discovery)?,
            );
        }
        crate::imports::ImportedDiscoveryCredential::PerUser { principal } => {
            if principal_by_id_without_groups(conn, principal)?.status != "active" {
                return Err(ManagedStoreError::PrincipalDisabled);
            }
            let oauth = record.definition.execution_bindings.iter().find(|b| {
                b.owner_mode == crate::imports::ImportedCredentialMode::PerUser
                    && b.mechanism == crate::imports::ImportedAuthMechanism::Oauth
            });
            if let Some(binding) = oauth {
                let registration = binding
                    .registration_id
                    .as_deref()
                    .ok_or(ManagedStoreError::CredentialNotFound)?;
                let version: Option<String> = conn.query_row("SELECT s.generation || ':' || s.config_fingerprint || ':' || s.discovery_revision FROM oauth_slots s JOIN oauth_registrations r ON r.registration_id=s.registration_id AND r.fingerprint=s.config_fingerprint WHERE s.owner_principal_id=?1 AND s.registration_id=?2", params![principal,registration], |r| r.get(0)).optional().map_err(sql_unavailable)?;
                versions.insert(
                    "personal_oauth".into(),
                    version.ok_or(ManagedStoreError::CredentialNotFound)?,
                );
            } else {
                let metadata = credential_metadata_by_tuple(
                    conn,
                    principal,
                    &record.definition.service,
                    "default",
                )?;
                if metadata.status != "active"
                    || metadata.profile != "token"
                    || metadata.credential_kind != "bearer_token"
                {
                    return Err(ManagedStoreError::CredentialNotFound);
                }
                versions.insert(format!("user:{principal}"), metadata.material_version);
            }
        }
    }
    if record.definition.transport_auth {
        versions.insert(
            "transport".into(),
            slot(ImportedCredentialPurpose::Transport)?,
        );
    }
    Ok(versions)
}

fn validate_preview_context(
    config: &str,
    credentials: &BTreeMap<String, String>,
) -> Result<(), ManagedStoreError> {
    if config.is_empty()
        || config.len() > 256
        || credentials.len() > 8
        || credentials
            .iter()
            .any(|(k, v)| k.is_empty() || k.len() > 256 || v.is_empty() || v.len() > 256)
    {
        return Err(input_invalid("import preview revision metadata is invalid"));
    }
    Ok(())
}
fn validate_actions(
    service: &str,
    actions: &[ImportedActionWrite],
    old: &[ImportedActionRecord],
    validate_all: bool,
) -> Result<(), ManagedStoreError> {
    validate_action_capacity(actions)?;
    let mut names = BTreeSet::new();
    let mut sources = BTreeSet::new();
    for action in actions {
        let previous = old
            .iter()
            .find(|previous| previous.definition.action == action.definition.action);
        if validate_all
            || previous.is_none_or(|previous| {
                previous.definition != action.definition
                    || (previous.status != ImportedActionStatus::Enabled
                        && action.status == ImportedActionStatus::Enabled)
            })
        {
            action.definition.validate(service).map_err(input_invalid)?;
        }
        if !names.insert(&action.definition.action)
            || (action.status != ImportedActionStatus::Retired
                && !sources.insert(
                    serde_json::to_string(&action.definition.source).map_err(|_| invalid_data())?,
                ))
        {
            return Err(input_invalid(
                "duplicate imported action name or upstream identity",
            ));
        }
    }
    validate_retained_actions(actions, old)
}
fn validate_action_capacity(actions: &[ImportedActionWrite]) -> Result<(), ManagedStoreError> {
    let (active, retired): (Vec<_>, Vec<_>) = actions
        .iter()
        .partition(|action| action.status != ImportedActionStatus::Retired);
    if active.len() > IMPORT_MAX_TOOLS {
        return Err(input_invalid(
            "non-retired import action count exceeds limit",
        ));
    }
    if retired.len() > IMPORT_MAX_RETIRED_ACTIONS {
        return Err(input_invalid(
            "retired import action count exceeds retention limit",
        ));
    }
    bounded_json(&active, IMPORT_MAX_MANIFEST_BYTES)?;
    bounded_json(&retired, IMPORT_MAX_RETIRED_ACTION_BYTES)?;
    Ok(())
}
fn validate_retained_actions(
    actions: &[ImportedActionWrite],
    old: &[ImportedActionRecord],
) -> Result<(), ManagedStoreError> {
    for previous in old {
        let Some(candidate) = actions
            .iter()
            .find(|v| v.definition.action == previous.definition.action)
        else {
            return Err(input_invalid(
                "accepted action identities must be retained; disable or retire them",
            ));
        };
        if candidate.definition.source != previous.definition.source {
            return Err(input_invalid("accepted action mappings are immutable"));
        }
        if previous.status == ImportedActionStatus::Retired
            && candidate.status != ImportedActionStatus::Retired
        {
            return Err(input_invalid("retired action identities cannot be reused"));
        }
    }
    Ok(())
}
fn bounded_json<T: Serialize + ?Sized>(value: &T, max: usize) -> Result<String, ManagedStoreError> {
    let json =
        serde_json::to_string(value).map_err(|_| input_invalid("import data cannot be encoded"))?;
    if json.len() > max {
        return Err(input_invalid("import data exceeds size limit"));
    }
    Ok(json)
}
fn invalid_data() -> ManagedStoreError {
    ManagedStoreError::SchemaInvalid("imported service records are invalid".into())
}
fn db_version(value: u64) -> Result<i64, ManagedStoreError> {
    i64::try_from(value).map_err(|_| input_invalid("import version exceeds database range"))
}
fn row_version(row: &rusqlite::Row<'_>, index: usize) -> rusqlite::Result<u64> {
    let value: i64 = row.get(index)?;
    u64::try_from(value).map_err(|error| {
        rusqlite::Error::FromSqlConversionFailure(index, Type::Integer, Box::new(error))
    })
}
fn revision(conn: &Connection) -> Result<u64, ManagedStoreError> {
    conn.query_row(
        "SELECT revision FROM imported_catalog_revision WHERE singleton=1",
        [],
        |r| row_version(r, 0),
    )
    .map_err(sql_unavailable)
}
fn require_version(
    conn: &Connection,
    service: &str,
    version: u64,
    catalog_revision: u64,
) -> Result<ImportedServiceRecord, ManagedStoreError> {
    if revision(conn)? != catalog_revision {
        return Err(ManagedStoreError::VersionConflict);
    }
    let record = service_record(conn, service)?
        .ok_or_else(|| input_invalid("imported service was not found"))?;
    if record.version != version {
        return Err(ManagedStoreError::VersionConflict);
    }
    Ok(record)
}
fn touch(conn: &Connection, service: &str, actor: &str) -> Result<(), ManagedStoreError> {
    conn.execute("UPDATE imported_services SET version=version+1,updated_at=?2,updated_by=?3 WHERE service=?1", params![service,normalized_now_string(),actor]).map_err(sql_unavailable)?;
    Ok(())
}
fn finish<T>(
    tx: rusqlite::Transaction<'_>,
    validate: impl FnOnce(&ImportedCatalog) -> Result<T, ManagedStoreError>,
) -> Result<ImportedMutationResult<T>, ManagedStoreError> {
    tx.execute(
        "UPDATE imported_catalog_revision SET revision=revision+1 WHERE singleton=1",
        [],
    )
    .map_err(sql_unavailable)?;
    let catalog = catalog(&tx)?;
    let value = validate(&catalog)?;
    tx.commit().map_err(sql_unavailable)?;
    Ok(ImportedMutationResult { catalog, value })
}
fn preview(conn: &Connection, service: &str) -> Result<Option<ImportedPreview>, ManagedStoreError> {
    let json: Option<String> = conn
        .query_row(
            "SELECT preview_json FROM imported_previews WHERE service=?1",
            [service],
            |r| r.get(0),
        )
        .optional()
        .map_err(sql_unavailable)?;
    json.map(|v| serde_json::from_str(&v).map_err(|_| invalid_data()))
        .transpose()
}
fn catalog(conn: &Connection) -> Result<ImportedCatalog, ManagedStoreError> {
    let mut statement = conn
        .prepare("SELECT service FROM imported_services ORDER BY service")
        .map_err(sql_unavailable)?;
    let names: Vec<String> = collect_rows(
        statement
            .query_map([], |r| r.get(0))
            .map_err(sql_unavailable)?,
    )?;
    let services = names
        .iter()
        .map(|name| service_record(conn, name)?.ok_or_else(invalid_data))
        .collect::<Result<Vec<_>, _>>()?;
    let result = ImportedCatalog {
        revision: revision(conn)?,
        services,
    };
    // Includes retained tombstones, but never pending manifests or plaintext.
    bounded_json(&result, 64 * 1024 * 1024)?;
    Ok(result)
}
fn service_record(
    conn: &Connection,
    service: &str,
) -> Result<Option<ImportedServiceRecord>, ManagedStoreError> {
    let row: Option<(String,String,u64,String,String,String,String)> = conn.query_row("SELECT definition_json,status,version,created_at,created_by,updated_at,updated_by FROM imported_services WHERE service=?1",[service],|r| Ok((r.get(0)?,r.get(1)?,row_version(r,2)?,r.get(3)?,r.get(4)?,r.get(5)?,r.get(6)?))).optional().map_err(sql_unavailable)?;
    let Some((definition, status, version, created_at, created_by, updated_at, updated_by)) = row
    else {
        return Ok(None);
    };
    let definition: ImportedServiceDefinition =
        serde_json::from_str(&definition).map_err(|_| invalid_data())?;
    // Evolving adapter/config validation must not make retained records unreadable.
    // The runtime marks unsupported records unavailable; administrators can retire them.
    if service == "broker"
        || definition.service != service
        || !agent_access_provider::is_service_name(service)
    {
        return Err(invalid_data());
    }
    let status = serde_json::from_value(Value::String(status)).map_err(|_| invalid_data())?;
    let mut statement = conn.prepare("SELECT definition_json,status,version,definition_hash FROM imported_actions WHERE service=?1 ORDER BY action").map_err(sql_unavailable)?;
    let rows: Vec<(String, String, u64, String)> = collect_rows(
        statement
            .query_map([service], |r| {
                Ok((r.get(0)?, r.get(1)?, row_version(r, 2)?, r.get(3)?))
            })
            .map_err(sql_unavailable)?,
    )?;
    let actions = rows
        .into_iter()
        .map(|(definition, status, version, definition_hash)| {
            Ok(ImportedActionRecord {
                definition: serde_json::from_str(&definition).map_err(|_| invalid_data())?,
                status: serde_json::from_value(Value::String(status))
                    .map_err(|_| invalid_data())?,
                version,
                definition_hash,
            })
        })
        .collect::<Result<Vec<_>, ManagedStoreError>>()?;
    let mut statement = conn.prepare("SELECT purpose,material_version FROM imported_secret_material WHERE service=?1 ORDER BY purpose").map_err(sql_unavailable)?;
    let versions: Vec<(String, String)> = collect_rows(
        statement
            .query_map([service], |r| Ok((r.get(0)?, r.get(1)?)))
            .map_err(sql_unavailable)?,
    )?;
    let slot_versions = versions
        .into_iter()
        .map(|(purpose, version)| {
            Ok((
                serde_json::from_value(Value::String(purpose)).map_err(|_| invalid_data())?,
                version,
            ))
        })
        .collect::<Result<BTreeMap<_, _>, ManagedStoreError>>()?;
    Ok(Some(ImportedServiceRecord {
        definition,
        status,
        version,
        actions,
        slot_versions,
        created_at,
        created_by,
        updated_at,
        updated_by,
    }))
}

/// Never derive Debug or Serialize for raw service token inputs.
pub struct ImportedSecretWriteRequest {
    pub service: String,
    pub purpose: ImportedCredentialPurpose,
    pub expected_version: u64,
    pub expected_catalog_revision: u64,
    pub token: String,
    pub actor: String,
}
/// Ephemeral attestation of the plaintext and version written by this transaction.
/// Never serialized, logged, persisted, or constructible by publication callers.
pub struct ImportedSecretWriteProof {
    service: String,
    purpose: ImportedCredentialPurpose,
    material_version: String,
    token_digest: [u8; 32],
}
impl ImportedSecretWriteProof {
    pub(crate) fn target(&self) -> (&str, ImportedCredentialPurpose) {
        (&self.service, self.purpose)
    }
    pub(crate) fn bind_transport(
        &self,
        service: &str,
        token_digest: &[u8; 32],
    ) -> Result<String, ManagedStoreError> {
        if self.service != service
            || self.purpose != ImportedCredentialPurpose::Transport
            || &self.token_digest != token_digest
        {
            return Err(input_invalid(
                "prepared transport does not match the secret write",
            ));
        }
        Ok(self.material_version.clone())
    }
}

pub struct ImportedSecretDeleteRequest {
    pub service: String,
    pub purpose: ImportedCredentialPurpose,
    pub expected_version: u64,
    pub expected_catalog_revision: u64,
    pub actor: String,
}
struct SecretRow {
    service: String,
    purpose: String,
    credential_kind: String,
    material_version: String,
    key_id: String,
    nonce: Vec<u8>,
    ciphertext: Vec<u8>,
}
impl ManagedStore {
    pub fn write_imported_secret<T>(
        &self,
        request: ImportedSecretWriteRequest,
        ring: &CredentialKeyRing,
        validate: impl FnOnce(
            &ImportedCatalog,
            &ImportedSecretWriteProof,
        ) -> Result<T, ManagedStoreError>,
    ) -> Result<ImportedMutationResult<T>, ManagedStoreError> {
        validate_actor(&request.actor)?;
        if request.token.is_empty()
            || request.token.len() > 32768
            || !request.token.bytes().all(|b| (0x21..=0x7e).contains(&b))
        {
            return Err(input_invalid(
                "import token must contain visible ASCII characters and fit the size limit",
            ));
        }
        let mut conn = self.connection.lock().unwrap();
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sql_unavailable)?;
        require_import_admin(&tx, &request.actor)?;
        let record = require_version(
            &tx,
            &request.service,
            request.expected_version,
            request.expected_catalog_revision,
        )?;
        if record.status == ImportedServiceStatus::Retired {
            return Err(input_invalid(
                "retired imports cannot receive new credentials",
            ));
        }
        let mut row = SecretRow {
            service: request.service.clone(),
            purpose: request.purpose.as_str().into(),
            credential_kind: "bearer_token".into(),
            material_version: Uuid::new_v4().to_string(),
            key_id: ring.active_key_id().into(),
            nonce: Vec::new(),
            ciphertext: Vec::new(),
        };
        let encrypted = encrypt(ring, &row, &request.token)?;
        row.nonce = encrypted.nonce;
        row.ciphertext = encrypted.ciphertext;
        tx.execute("INSERT INTO imported_secret_material(service,purpose,credential_kind,material_version,key_id,nonce,ciphertext) VALUES(?1,?2,?3,?4,?5,?6,?7) ON CONFLICT(service,purpose) DO UPDATE SET credential_kind=excluded.credential_kind,material_version=excluded.material_version,key_id=excluded.key_id,nonce=excluded.nonce,ciphertext=excluded.ciphertext",params![row.service,row.purpose,row.credential_kind,row.material_version,row.key_id,row.nonce,row.ciphertext]).map_err(sql_unavailable)?;
        touch(&tx, &request.service, &request.actor)?;
        tx.execute(
            "DELETE FROM imported_previews WHERE service=?1",
            [&request.service],
        )
        .map_err(sql_unavailable)?;
        use sha2::Digest as _;
        let proof = ImportedSecretWriteProof {
            service: request.service,
            purpose: request.purpose,
            material_version: row.material_version,
            token_digest: Sha256::digest(request.token.as_bytes()).into(),
        };
        finish(tx, |catalog| validate(catalog, &proof))
    }
    pub fn delete_imported_secret<T>(
        &self,
        request: ImportedSecretDeleteRequest,
        validate: impl FnOnce(&ImportedCatalog) -> Result<T, ManagedStoreError>,
    ) -> Result<ImportedMutationResult<T>, ManagedStoreError> {
        validate_actor(&request.actor)?;
        let mut conn = self.connection.lock().unwrap();
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sql_unavailable)?;
        require_import_admin(&tx, &request.actor)?;
        require_version(
            &tx,
            &request.service,
            request.expected_version,
            request.expected_catalog_revision,
        )?;
        tx.execute(
            "DELETE FROM imported_secret_material WHERE service=?1 AND purpose=?2",
            params![request.service, request.purpose.as_str()],
        )
        .map_err(sql_unavailable)?;
        touch(&tx, &request.service, &request.actor)?;
        tx.execute(
            "DELETE FROM imported_previews WHERE service=?1",
            [&request.service],
        )
        .map_err(sql_unavailable)?;
        finish(tx, validate)
    }
    /// The host must authorize the purpose and compare its admitted service and
    /// action revisions before resolving. A stale token is never substituted.
    pub fn resolve_imported_secret(
        &self,
        service: &str,
        purpose: ImportedCredentialPurpose,
        expected_material_version: &str,
        ring: &CredentialKeyRing,
    ) -> Result<ExecutionCredential, ManagedStoreError> {
        let conn = self.connection.lock().unwrap();
        let row = secret_row(&conn, service, purpose.as_str())?
            .ok_or(ManagedStoreError::CredentialNotFound)?;
        if row.material_version != expected_material_version {
            return Err(ManagedStoreError::VersionConflict);
        }
        // Imported secret slots hold only bearer material.
        if row.credential_kind != "bearer_token" {
            return Err(ManagedStoreError::CredentialInvalid(
                "unsupported credential kind".to_string(),
            ));
        }
        Ok(agent_access_provider::host::bearer_credential(decrypt(
            ring, &row,
        )?))
    }
}
fn secret_row(
    conn: &Connection,
    service: &str,
    purpose: &str,
) -> Result<Option<SecretRow>, ManagedStoreError> {
    conn.query_row("SELECT service,purpose,credential_kind,material_version,key_id,nonce,ciphertext FROM imported_secret_material WHERE service=?1 AND purpose=?2",params![service,purpose],secret_from_row).optional().map_err(sql_unavailable)
}
fn secret_rows(conn: &Connection) -> Result<Vec<SecretRow>, ManagedStoreError> {
    let mut statement = conn.prepare("SELECT service,purpose,credential_kind,material_version,key_id,nonce,ciphertext FROM imported_secret_material ORDER BY service,purpose").map_err(sql_unavailable)?;
    collect_rows(
        statement
            .query_map([], secret_from_row)
            .map_err(sql_unavailable)?,
    )
}
fn secret_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<SecretRow> {
    Ok(SecretRow {
        service: row.get(0)?,
        purpose: row.get(1)?,
        credential_kind: row.get(2)?,
        material_version: row.get(3)?,
        key_id: row.get(4)?,
        nonce: row.get(5)?,
        ciphertext: row.get(6)?,
    })
}
fn aad(row: &SecretRow) -> Result<Vec<u8>, ManagedStoreError> {
    serde_json::to_vec(&(
        "aab-imported-service-credential:v1",
        &row.service,
        &row.purpose,
        &row.credential_kind,
        &row.material_version,
        &row.key_id,
    ))
    .map_err(|_| ManagedStoreError::CredentialEncryptFailed)
}
fn encrypt(
    ring: &CredentialKeyRing,
    row: &SecretRow,
    plaintext: &str,
) -> Result<EncryptedSecret, ManagedStoreError> {
    let key = ring
        .keys
        .get(&row.key_id)
        .ok_or_else(|| ManagedStoreError::EncryptionKeyMissing(row.key_id.clone()))?;
    let cipher =
        Aes256Gcm::new_from_slice(key).map_err(|_| ManagedStoreError::CredentialEncryptFailed)?;
    let mut nonce = [0; 12];
    OsRng.fill_bytes(&mut nonce);
    let ciphertext = cipher
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: plaintext.as_bytes(),
                aad: &aad(row)?,
            },
        )
        .map_err(|_| ManagedStoreError::CredentialEncryptFailed)?;
    Ok(EncryptedSecret {
        key_id: row.key_id.clone(),
        nonce: nonce.to_vec(),
        ciphertext,
    })
}
fn decrypt(ring: &CredentialKeyRing, row: &SecretRow) -> Result<String, ManagedStoreError> {
    let key = ring
        .keys
        .get(&row.key_id)
        .ok_or_else(|| ManagedStoreError::EncryptionKeyMissing(row.key_id.clone()))?;
    let cipher =
        Aes256Gcm::new_from_slice(key).map_err(|_| ManagedStoreError::CredentialDecryptFailed)?;
    let nonce: [u8; 12] = row
        .nonce
        .as_slice()
        .try_into()
        .map_err(|_| ManagedStoreError::CredentialDecryptFailed)?;
    let plaintext = cipher
        .decrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: &row.ciphertext,
                aad: &aad(row)?,
            },
        )
        .map_err(|_| ManagedStoreError::CredentialDecryptFailed)?;
    String::from_utf8(plaintext).map_err(|_| ManagedStoreError::CredentialDecryptFailed)
}
pub(super) fn check_ready(
    conn: &Connection,
    ring: Option<&CredentialKeyRing>,
) -> Result<(), ManagedStoreError> {
    for row in secret_rows(conn)? {
        let ring =
            ring.ok_or_else(|| ManagedStoreError::EncryptionKeyMissing(row.key_id.clone()))?;
        decrypt(ring, &row)?;
    }
    Ok(())
}
pub(super) fn rewrap(
    conn: &mut Connection,
    ring: &CredentialKeyRing,
    from: &str,
    to: &str,
) -> Result<u64, ManagedStoreError> {
    let tx = conn.transaction().map_err(sql_unavailable)?;
    let mut count = 0;
    for mut row in secret_rows(&tx)?.into_iter().filter(|r| r.key_id == from) {
        let plaintext = decrypt(ring, &row)?;
        row.key_id = to.into();
        let encrypted = encrypt(ring, &row, &plaintext)?;
        tx.execute("UPDATE imported_secret_material SET key_id=?3,nonce=?4,ciphertext=?5 WHERE service=?1 AND purpose=?2",params![row.service,row.purpose,to,encrypted.nonce,encrypted.ciphertext]).map_err(sql_unavailable)?;
        count += 1;
    }
    tx.commit().map_err(sql_unavailable)?;
    Ok(count)
}
pub(super) fn validate_structure(conn: &Connection) -> Result<(), ManagedStoreError> {
    validate_structure_with_extension(conn, "")
}
pub(super) fn validate_structure_with_extension(
    conn: &Connection,
    extension: &str,
) -> Result<(), ManagedStoreError> {
    let expected = expected_schema_connection(true, true)?;
    for sql in [
        OAUTH_SQL,
        REGISTERED_RESOURCE_TYPES_SQL,
        RESOURCE_ATTRIBUTES_SQL,
        LOCAL_PASSWORD_FAILURES_SQL,
        PRINCIPAL_SERVICE_LIMITS_SQL,
        IMPORTED_SERVICES_SQL,
        extension,
    ] {
        expected.execute_batch(sql).map_err(sql_unavailable)?;
    }
    compare_schema(conn, &expected)?;
    run_foreign_key_check(conn)?;
    run_quick_check(conn)?;
    check_secret_material_ready(conn, None)?;
    check_policy_revision_ready(conn)?;
    catalog(conn)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::imports::{
        ImportedCredentialBinding, ImportedCredentialDelivery, ImportedCredentialMode,
        ImportedDiscoveryCredential,
    };
    use agent_access_provider::test_support::bearer_credential;
    use serde_json::json;
    include!("managed_store/imported_store_golden_tests.rs");
    fn fixture() -> (
        tempfile::TempDir,
        ManagedStoreConfig,
        ManagedStore,
        CredentialKeyRing,
    ) {
        let temp = tempfile::TempDir::new().unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
        }
        let config = ManagedStoreConfig {
            kind: "sqlite".into(),
            path: temp.path().join("store.sqlite").display().to_string(),
            auto_migrate: true,
            require_registered_principal_for_invocation: false,
        };
        let store = ManagedStore::open(&config, ManagedStoreOpenMode::Startup).unwrap();
        let ring = CredentialKeyRing {
            active_key: "old".into(),
            keys: Arc::new(BTreeMap::from([
                ("old".into(), [7; 32]),
                ("new".into(), [8; 32]),
            ])),
        };
        store
            .create_principal(PrincipalWriteRequest {
                role: crate::PrincipalRole::User,
                self_service_enabled: None,
                principal_id: "admin".into(),
                kind: "user".into(),
                display_name: None,
                email: None,
                external_subject: None,
                created_by: "test".into(),
            })
            .unwrap();
        store
            .patch_principal_access(crate::PrincipalAccessPatchRequest {
                principal_id: ("admin").into(),
                role: Some(crate::PrincipalRole::Admin),
                self_service_enabled: None,
                actor: ("test").into(),
            })
            .unwrap();
        (temp, config, store, ring)
    }
    fn definition() -> ImportedServiceDefinition {
        ImportedServiceDefinition {
            service: "observability".into(),
            display_name: "Observability".into(),
            adapter_kind: "mcp_http".into(),
            endpoint: "https://tools.example/mcp".into(),
            connection_settings: BTreeMap::new(),
            execution_bindings: vec![ImportedCredentialBinding::token(
                ImportedCredentialMode::Service,
                ImportedCredentialDelivery::Bearer,
            )],
            discovery: ImportedDiscoveryCredential::Execution,
            transport_auth: false,
            invocation_limit: None,
        }
    }
    fn action() -> ImportedActionWrite {
        ImportedActionWrite {
            definition: ImportedActionDefinition {
                action: "query".into(),
                source: json!({"toolName":"upstream_query"}),
                label: None,
                description: "Query telemetry".into(),
                input_schema: json!({"type":"object","properties":{"query":{"type":"string"}},"required":["query"]}),
                output_schema: None,
                annotations: json!({"readOnlyHint":true}),
                read_only: true,
            },
            status: ImportedActionStatus::Enabled,
        }
    }
    fn accept(_: &ImportedCatalog) -> Result<(), ManagedStoreError> {
        Ok(())
    }
    fn reject(_: &ImportedCatalog) -> Result<(), ManagedStoreError> {
        Err(input_invalid("candidate rejected"))
    }
    fn update(catalog: &ImportedCatalog) -> ImportedServiceUpdateRequest {
        let service = &catalog.services[0];
        ImportedServiceUpdateRequest {
            definition: service.definition.clone(),
            status: ImportedServiceStatus::Disabled,
            actions: service
                .actions
                .iter()
                .map(|a| ImportedActionWrite {
                    definition: a.definition.clone(),
                    status: a.status,
                })
                .collect(),
            expected_version: service.version,
            expected_catalog_revision: catalog.revision,
            accepted_preview: None,
            actor: "admin".into(),
        }
    }
    fn slot(catalog: &ImportedCatalog, token: &str) -> ImportedSecretWriteRequest {
        ImportedSecretWriteRequest {
            service: "observability".into(),
            purpose: ImportedCredentialPurpose::Execution,
            expected_version: catalog.services[0].version,
            expected_catalog_revision: catalog.revision,
            token: token.into(),
            actor: "admin".into(),
        }
    }
    fn pending(catalog: &ImportedCatalog) -> ImportedPreviewWriteRequest {
        ImportedPreviewWriteRequest {
            service: "observability".into(),
            expected_version: catalog.services[0].version,
            expected_catalog_revision: catalog.revision,
            config_revision: "config-one".into(),
            credential_versions: BTreeMap::from([(
                "execution".into(),
                catalog.services[0].slot_versions[&ImportedCredentialPurpose::Execution].clone(),
            )]),
            manifest: json!({"tools":[{"name":"upstream_query"}]}),
            quarantine_actions: Vec::new(),
            actor: "admin".into(),
        }
    }
    #[test]
    fn draft_persists_without_principal_and_candidate_failure_rolls_back() {
        let (_temp, config, store, _) = fixture();
        assert!(
            store
                .create_imported_service(definition(), "admin", reject)
                .is_err()
        );
        assert_eq!(
            store.imported_catalog().unwrap(),
            ImportedCatalog::default()
        );
        let result = store
            .create_imported_service(definition(), "admin", |c| Ok(c.services.len()))
            .unwrap();
        assert_eq!(result.value, 1);
        assert_eq!(result.catalog.revision, 1);
        assert_eq!(
            result.catalog.services[0].status,
            ImportedServiceStatus::Draft
        );
        assert_eq!(
            count_table(&store.connection.lock().unwrap(), "principals").unwrap(),
            1
        );
        drop(store);
        let reopened = ManagedStore::open(&config, ManagedStoreOpenMode::Reload).unwrap();
        assert_eq!(reopened.imported_catalog().unwrap(), result.catalog);
        assert!(
            reopened
                .create_imported_service(definition(), "admin", accept)
                .is_err()
        );
    }
    #[test]
    fn empty_draft_can_choose_connection_settings_but_acceptance_freezes_them() {
        let (_temp, _config, store, _) = fixture();
        let mut definition = definition();
        definition.discovery = ImportedDiscoveryCredential::Anonymous;
        let draft = store
            .create_imported_service(definition, "admin", accept)
            .unwrap()
            .catalog;
        assert!(
            store
                .imported_discovery_credential_versions("observability", draft.services[0].version)
                .unwrap()
                .is_empty()
        );
        let mut retarget = update(&draft);
        retarget.definition.endpoint = "https://other.example/api".into();
        assert!(store.update_imported_service(retarget, accept).is_err());
        let mut edit = update(&draft);
        edit.status = ImportedServiceStatus::Draft;
        edit.definition
            .connection_settings
            .insert("selectedProfile".into(), "api-key".into());
        edit.definition.execution_bindings[0].delivery = ImportedCredentialDelivery::RawHeader {
            name: "X-Api-Key".into(),
        };
        let configured = store.update_imported_service(edit, accept).unwrap().catalog;
        let mut accept_with_retarget = update(&configured);
        accept_with_retarget.actions.push(action());
        accept_with_retarget
            .definition
            .connection_settings
            .insert("selectedProfile".into(), "other".into());
        assert!(
            store
                .update_imported_service(accept_with_retarget, accept)
                .is_err()
        );
        let mut acceptance = update(&configured);
        acceptance.actions.push(action());
        let accepted = store
            .update_imported_service(acceptance, accept)
            .unwrap()
            .catalog;
        let mut edit = update(&accepted);
        edit.definition
            .connection_settings
            .insert("selectedProfile".into(), "other".into());
        assert!(store.update_imported_service(edit, accept).is_err());
    }

    #[test]
    fn draft_destination_changes_invalidate_saved_tokens_atomically() {
        let (_temp, _config, store, ring) = fixture();
        let mut definition = definition();
        definition.discovery = ImportedDiscoveryCredential::Slot;
        definition
            .connection_settings
            .insert("definitionUrl".into(), "https://docs.example/old".into());
        let mut catalog = store
            .create_imported_service(definition, "admin", accept)
            .unwrap()
            .catalog;
        for delivery_change in [false, true] {
            for purpose in [
                ImportedCredentialPurpose::Execution,
                ImportedCredentialPurpose::Discovery,
            ] {
                let mut write = slot(&catalog, "draft-secret");
                write.purpose = purpose;
                catalog = store
                    .write_imported_secret(write, &ring, |catalog, _| accept(catalog))
                    .unwrap()
                    .catalog;
            }
            let saved = catalog.clone();
            let change = || {
                let mut edit = update(&saved);
                edit.status = ImportedServiceStatus::Draft;
                if delivery_change {
                    edit.definition.execution_bindings[0].delivery =
                        ImportedCredentialDelivery::RawHeader {
                            name: "X-Api-Key".into(),
                        };
                } else {
                    edit.definition
                        .connection_settings
                        .insert("definitionUrl".into(), "https://docs.example/new".into());
                }
                edit
            };
            assert!(store.update_imported_service(change(), reject).is_err());
            assert_eq!(store.imported_catalog().unwrap(), saved);
            for (purpose, version) in &saved.services[0].slot_versions {
                assert!(
                    store
                        .resolve_imported_secret("observability", *purpose, version, &ring)
                        .is_ok()
                );
            }
            catalog = store
                .update_imported_service(change(), accept)
                .unwrap()
                .catalog;
            assert!(catalog.services[0].slot_versions.is_empty());
            assert!(
                store
                    .imported_discovery_credential_versions(
                        "observability",
                        catalog.services[0].version
                    )
                    .is_err()
            );
            for (purpose, version) in &saved.services[0].slot_versions {
                assert!(matches!(
                    store.resolve_imported_secret("observability", *purpose, version, &ring),
                    Err(ManagedStoreError::CredentialNotFound)
                ));
            }
        }
    }

    #[test]
    fn draft_destination_changes_cannot_repurpose_personal_credentials() {
        let (_temp, _config, store, ring) = fixture();
        let catalog = store
            .create_imported_service(definition(), "admin", accept)
            .unwrap()
            .catalog;
        store
            .upsert_user_credential(
                &ring,
                CredentialWriteRequest {
                    owner_principal_id: "admin".into(),
                    service: "observability".into(),
                    name: "default".into(),
                    profile: "token".into(),
                    credential_kind: "bearer_token".into(),
                    secret: json!({"token":"personal-token"}),
                    metadata: json!({}),
                    actor: "admin".into(),
                },
                crate::CredentialManagementPurpose::Administrative,
            )
            .unwrap();
        let mut edit = update(&catalog);
        edit.status = ImportedServiceStatus::Draft;
        edit.definition.execution_bindings[0].delivery = ImportedCredentialDelivery::RawHeader {
            name: "X-Api-Key".into(),
        };
        let error = store
            .update_imported_service(edit, accept)
            .err()
            .unwrap()
            .to_string();
        assert!(error.contains("remove personal credentials"));
        assert_eq!(store.imported_catalog().unwrap(), catalog);
    }

    #[test]
    fn definitions_enforce_retention_destination_and_optimistic_versions() {
        let (_temp, _config, store, _) = fixture();
        let draft = store
            .create_imported_service(definition(), "admin", accept)
            .unwrap()
            .catalog;
        let mut request = update(&draft);
        request.actions.push(action());
        let accepted = store
            .update_imported_service(request, accept)
            .unwrap()
            .catalog;
        assert_eq!(accepted.services[0].actions[0].version, 1);
        assert!(matches!(
            store.update_imported_service(update(&draft), accept),
            Err(ManagedStoreError::VersionConflict)
        ));
        let mut request = update(&accepted);
        request.definition.endpoint = "https://other.example/mcp".into();
        assert!(store.update_imported_service(request, accept).is_err());
        let mut request = update(&accepted);
        request.actions.clear();
        assert!(store.update_imported_service(request, accept).is_err());
        let mut request = update(&accepted);
        request.actions[0].definition.source = json!({"toolName":"different"});
        assert!(store.update_imported_service(request, accept).is_err());
        let mut request = update(&accepted);
        request.actions[0].status = ImportedActionStatus::Retired;
        request.status = ImportedServiceStatus::Retired;
        let retired = store
            .update_imported_service(request, accept)
            .unwrap()
            .catalog;
        assert_eq!(retired.services[0].actions[0].version, 2);
        assert!(
            store
                .update_imported_service(update(&retired), accept)
                .is_err()
        );
        assert_eq!(store.imported_catalog().unwrap(), retired);
        assert!(
            store
                .create_imported_service(definition(), "admin", accept)
                .is_err()
        );
    }
    #[test]
    fn retired_sources_allow_fresh_actions_but_reserve_old_names() {
        let (_temp, _config, store, _) = fixture();
        let draft = store
            .create_imported_service(definition(), "admin", accept)
            .unwrap()
            .catalog;
        let mut request = update(&draft);
        request.actions.push(action());
        let accepted = store
            .update_imported_service(request, accept)
            .unwrap()
            .catalog;
        let mut duplicate = update(&accepted);
        let mut replacement = action();
        replacement.definition.action = "query_replacement".into();
        duplicate.actions.push(replacement.clone());
        assert!(store.update_imported_service(duplicate, accept).is_err());
        assert_eq!(store.imported_catalog().unwrap(), accepted);
        let mut request = update(&accepted);
        request.actions[0].status = ImportedActionStatus::Retired;
        // New mapping first exercises transaction ordering against the SQL index.
        request.actions.insert(0, replacement);
        let replaced = store
            .update_imported_service(request, accept)
            .unwrap()
            .catalog;
        assert_eq!(replaced.services[0].actions.len(), 2);
        let mut request = update(&replaced);
        request
            .actions
            .iter_mut()
            .find(|action| action.definition.action == "query")
            .unwrap()
            .status = ImportedActionStatus::Enabled;
        assert!(store.update_imported_service(request, accept).is_err());
        let mut request = update(&replaced);
        request
            .actions
            .iter_mut()
            .for_each(|action| action.status = ImportedActionStatus::Retired);
        let mut third = action();
        third.definition.action = "query_third".into();
        request.actions.insert(0, third);
        let replaced_twice = store
            .update_imported_service(request, accept)
            .unwrap()
            .catalog;
        assert_eq!(replaced_twice.services[0].actions.len(), 3);
        assert_eq!(
            replaced_twice.services[0]
                .actions
                .iter()
                .filter(|action| action.status == ImportedActionStatus::Enabled)
                .count(),
            1
        );
        // The index independently rejects two non-retired identities for a source.
        assert!(
            store
                .connection
                .lock()
                .unwrap()
                .execute(
                    "UPDATE imported_actions SET status='enabled' WHERE action='query'",
                    []
                )
                .is_err()
        );
        assert_eq!(store.imported_catalog().unwrap(), replaced_twice);
    }
    #[test]
    fn near_limit_catalog_can_replace_many_actions_without_spending_live_capacity_on_tombstones() {
        let (_temp, config, store, _) = fixture();
        let draft = store
            .create_imported_service(definition(), "admin", accept)
            .unwrap()
            .catalog;
        let mut request = update(&draft);
        request.actions = (0..1500)
            .map(|index| {
                let mut action = action();
                action.definition.action = format!("query_{index}");
                action.definition.source = json!({"toolName":format!("upstream_{index}")});
                action.definition.description = "x".repeat(9 * 1024);
                action
            })
            .collect();
        let accepted = store
            .update_imported_service(request, accept)
            .unwrap()
            .catalog;
        let mut request = update(&accepted);
        let mut replacements = Vec::new();
        for old in request.actions.iter_mut().take(600) {
            old.status = ImportedActionStatus::Retired;
            let mut replacement = old.clone();
            replacement.status = ImportedActionStatus::Enabled;
            replacement.definition.action.push_str("_replacement");
            replacements.push(replacement);
        }
        request.actions.extend(replacements);
        assert_eq!(request.actions.len(), 2100);
        assert!(serde_json::to_vec(&request.actions).unwrap().len() > IMPORT_MAX_MANIFEST_BYTES);
        let replaced = store
            .update_imported_service(request, accept)
            .unwrap()
            .catalog;
        assert_eq!(
            replaced.services[0]
                .actions
                .iter()
                .filter(|action| action.status != ImportedActionStatus::Retired)
                .count(),
            1500
        );
        assert_eq!(
            replaced.services[0]
                .actions
                .iter()
                .filter(|action| action.status == ImportedActionStatus::Retired)
                .count(),
            600
        );
        let reopened = ManagedStore::open(&config, ManagedStoreOpenMode::Startup).unwrap();
        assert_eq!(reopened.imported_catalog().unwrap(), replaced);
    }

    #[test]
    fn retained_action_capacity_is_bounded_separately_from_active_actions() {
        let mut retired = action();
        retired.status = ImportedActionStatus::Retired;
        let mut actions = vec![retired.clone(); IMPORT_MAX_RETIRED_ACTIONS];
        actions.extend(vec![action(); IMPORT_MAX_TOOLS]);
        validate_action_capacity(&actions).unwrap();
        actions.push(action());
        assert!(validate_action_capacity(&actions).is_err());
        actions.pop();
        actions.push(retired.clone());
        assert!(validate_action_capacity(&actions).is_err());
        // Each definition fits its own 256 KiB bound. The aggregate retention
        // allowance independently bounds schema/annotation storage.
        retired.definition.annotations = json!({"payload":"x".repeat(200 * 1024)});
        assert!(bounded_json(&retired.definition, crate::imports::IMPORT_MAX_TOOL_BYTES).is_ok());
        let retired = vec![retired; 170];
        assert!(serde_json::to_vec(&retired).unwrap().len() > IMPORT_MAX_RETIRED_ACTION_BYTES);
        assert!(validate_action_capacity(&retired).is_err());
        let mut active = action();
        active.definition.annotations = json!({"payload":"x".repeat(200 * 1024)});
        assert!(validate_action_capacity(&vec![active; 85]).is_err());
    }
    #[test]
    fn complete_observation_quarantines_atomically_and_preview_acceptance_is_bound() {
        let (_temp, _config, store, ring) = fixture();
        let draft = store
            .create_imported_service(definition(), "admin", accept)
            .unwrap()
            .catalog;
        let draft = store
            .write_imported_secret(slot(&draft, "discovery-token"), &ring, |catalog, _| {
                accept(catalog)
            })
            .unwrap()
            .catalog;
        let mut request = update(&draft);
        request.actions.push(action());
        let accepted = store
            .update_imported_service(request, accept)
            .unwrap()
            .catalog;
        let mut request = pending(&accepted);
        request.quarantine_actions.push("query".into());
        assert!(
            store
                .write_imported_preview(request.clone(), reject)
                .is_err()
        );
        assert_eq!(store.imported_catalog().unwrap(), accepted);
        assert!(store.imported_preview("observability").unwrap().is_none());
        let observed = store
            .write_imported_preview(request, accept)
            .unwrap()
            .catalog;
        assert_eq!(
            observed.services[0].actions[0].status,
            ImportedActionStatus::Quarantined
        );
        let preview = store.imported_preview("observability").unwrap().unwrap();
        assert_eq!(preview.catalog_revision, observed.revision);
        let mut request = update(&observed);
        request.accepted_preview = Some(ImportedPreviewAcceptance {
            manifest_hash: "wrong".into(),
            config_revision: preview.config_revision.clone(),
            credential_versions: preview.credential_versions.clone(),
        });
        assert!(matches!(
            store.update_imported_service(request.clone(), accept),
            Err(ManagedStoreError::VersionConflict)
        ));
        request.accepted_preview.as_mut().unwrap().manifest_hash = preview.manifest_hash;
        request.actions[0].status = ImportedActionStatus::Enabled;
        let accepted = store
            .update_imported_service(request, accept)
            .unwrap()
            .catalog;
        assert_eq!(
            accepted.services[0].actions[0].status,
            ImportedActionStatus::Enabled
        );
        assert!(store.imported_preview("observability").unwrap().is_none());
    }
    #[test]
    fn preview_expires_and_rotating_credentials_invalidates_it() {
        let (_temp, _config, store, ring) = fixture();
        let draft = store
            .create_imported_service(definition(), "admin", accept)
            .unwrap()
            .catalog;
        let draft = store
            .write_imported_secret(slot(&draft, "discovery-token"), &ring, |catalog, _| {
                accept(catalog)
            })
            .unwrap()
            .catalog;
        let observed = store
            .write_imported_preview(pending(&draft), accept)
            .unwrap()
            .catalog;
        let mut expired = store.imported_preview("observability").unwrap().unwrap();
        expired.expires_at = "2000-01-01T00:00:00Z".into();
        store
            .connection
            .lock()
            .unwrap()
            .execute(
                "UPDATE imported_previews SET preview_json=?1",
                [serde_json::to_string(&expired).unwrap()],
            )
            .unwrap();
        assert!(store.imported_preview("observability").unwrap().is_none());
        let refreshed = store
            .write_imported_preview(pending(&observed), accept)
            .unwrap()
            .catalog;
        assert!(store.imported_preview("observability").unwrap().is_some());
        store
            .write_imported_secret(slot(&refreshed, "sentinel-token"), &ring, |catalog, _| {
                accept(catalog)
            })
            .unwrap();
        assert!(store.imported_preview("observability").unwrap().is_none());
    }
    #[test]
    fn secrets_are_service_owned_encrypted_versioned_and_retained_in_key_inventory() {
        let (_temp, _config, store, ring) = fixture();
        let draft = store
            .create_imported_service(definition(), "admin", accept)
            .unwrap()
            .catalog;
        assert!(
            store
                .write_imported_secret(slot(&draft, "do-not-commit"), &ring, |catalog, _| reject(
                    catalog
                ))
                .is_err()
        );
        assert!(store.active_credential_key_ids().unwrap().is_empty());
        let with_secret = store
            .write_imported_secret(
                slot(&draft, "unique-private-sentinel"),
                &ring,
                |catalog, _| accept(catalog),
            )
            .unwrap()
            .catalog;
        let version = &with_secret.services[0].slot_versions[&ImportedCredentialPurpose::Execution];
        assert!(!format!("{with_secret:?}").contains("unique-private-sentinel"));
        assert!(
            !serde_json::to_string(&with_secret)
                .unwrap()
                .contains("unique-private-sentinel")
        );
        assert_eq!(
            store
                .resolve_imported_secret(
                    "observability",
                    ImportedCredentialPurpose::Execution,
                    version,
                    &ring
                )
                .unwrap(),
            bearer_credential("unique-private-sentinel")
        );
        assert!(matches!(
            store.resolve_imported_secret(
                "observability",
                ImportedCredentialPurpose::Execution,
                "stale",
                &ring
            ),
            Err(ManagedStoreError::VersionConflict)
        ));
        let row = secret_row(
            &store.connection.lock().unwrap(),
            "observability",
            "execution",
        )
        .unwrap()
        .unwrap();
        assert!(
            !row.ciphertext
                .windows("unique-private-sentinel".len())
                .any(|v| v == b"unique-private-sentinel")
        );
        let mut retire = update(&with_secret);
        retire.status = ImportedServiceStatus::Retired;
        let retired = store
            .update_imported_service(retire, accept)
            .unwrap()
            .catalog;
        assert_eq!(store.active_credential_key_ids().unwrap(), vec!["old"]);
        assert!(store.check_ready(None).is_err());
        store.check_ready(Some(&ring)).unwrap();
        let summary = store
            .rewrap_credentials(&ring, "old", "new", "admin")
            .unwrap();
        assert_eq!(summary.rewrapped, 1);
        assert_eq!(store.active_credential_key_ids().unwrap(), vec!["new"]);
        assert_eq!(store.imported_catalog().unwrap(), retired);
        assert_eq!(
            store
                .resolve_imported_secret(
                    "observability",
                    ImportedCredentialPurpose::Execution,
                    version,
                    &ring
                )
                .unwrap(),
            bearer_credential("unique-private-sentinel")
        );
        assert_eq!(
            count_table(&store.connection.lock().unwrap(), "principals").unwrap(),
            1
        );
        let delete = ImportedSecretDeleteRequest {
            service: "observability".into(),
            purpose: ImportedCredentialPurpose::Execution,
            expected_version: retired.services[0].version,
            expected_catalog_revision: retired.revision,
            actor: "admin".into(),
        };
        store.delete_imported_secret(delete, accept).unwrap();
        assert!(store.active_credential_key_ids().unwrap().is_empty());
    }
    #[test]
    fn ciphertext_cannot_move_between_purposes() {
        let (_temp, _config, store, ring) = fixture();
        let draft = store
            .create_imported_service(definition(), "admin", accept)
            .unwrap()
            .catalog;
        store
            .write_imported_secret(slot(&draft, "private-token"), &ring, |catalog, _| {
                accept(catalog)
            })
            .unwrap();
        store
            .connection
            .lock()
            .unwrap()
            .execute(
                "UPDATE imported_secret_material SET purpose='discovery'",
                [],
            )
            .unwrap();
        assert!(matches!(
            store.check_ready(Some(&ring)),
            Err(ManagedStoreError::CredentialDecryptFailed)
        ));
    }
    #[test]
    fn prior_schema_migrates_forward_and_preserves_existing_ledger() {
        let (temp, _config, store, _) = fixture();
        drop(store);
        let config = ManagedStoreConfig {
            kind: "sqlite".into(),
            path: temp.path().join("previous.sqlite").display().to_string(),
            auto_migrate: true,
            require_registered_principal_for_invocation: false,
        };
        let old = ManagedStore::open_with_catalog(
            &config,
            ManagedStoreOpenMode::Startup,
            ManagedStoreMigrationCatalog {
                migrations: &MANAGED_STORE_MIGRATIONS[..9],
            },
        )
        .unwrap();
        assert!(
            !sqlite_object_exists(
                &old.connection.lock().unwrap(),
                "table",
                "imported_services"
            )
            .unwrap()
        );
        drop(old);
        assert!(matches!(
            ManagedStore::open(&config, ManagedStoreOpenMode::Reload),
            Err(ManagedStoreError::MigrationRequired)
        ));
        let migrated = ManagedStore::open(&config, ManagedStoreOpenMode::Startup).unwrap();
        assert!(migrated.migration_applied_this_open(MANAGED_STORE_SCHEMA_VERSION));
        assert_eq!(
            migrated.imported_catalog().unwrap(),
            ImportedCatalog::default()
        );
    }
    #[test]
    fn administrator_demotion_is_checked_inside_mutation_transaction() {
        let (_temp, _config, store, ring) = fixture();
        let draft = store
            .create_imported_service(definition(), "admin", accept)
            .unwrap()
            .catalog;
        store
            .create_principal(PrincipalWriteRequest {
                role: crate::PrincipalRole::User,
                self_service_enabled: None,
                principal_id: "second-admin".into(),
                kind: "user".into(),
                display_name: None,
                email: None,
                external_subject: None,
                created_by: "test".into(),
            })
            .unwrap();
        store
            .patch_principal_access(crate::PrincipalAccessPatchRequest {
                principal_id: ("second-admin").into(),
                role: Some(crate::PrincipalRole::Admin),
                self_service_enabled: None,
                actor: ("test").into(),
            })
            .unwrap();
        store
            .patch_principal_access(crate::PrincipalAccessPatchRequest {
                principal_id: ("admin").into(),
                role: Some(crate::PrincipalRole::User),
                self_service_enabled: None,
                actor: "test".into(),
            })
            .unwrap();
        assert!(matches!(
            store.update_imported_service(update(&draft), accept),
            Err(ManagedStoreError::RightMissing)
        ));
        assert!(matches!(
            store
                .write_imported_secret(slot(&draft, "secret"), &ring, |catalog, _| accept(catalog)),
            Err(ManagedStoreError::RightMissing)
        ));
        let mut other = definition();
        other.service = "another".into();
        assert!(matches!(
            store.create_imported_service(other, "admin", accept),
            Err(ManagedStoreError::RightMissing)
        ));
        assert_eq!(store.imported_catalog().unwrap(), draft);
    }
    #[test]
    fn personal_discovery_rotation_invalidates_observation_and_acceptance_without_service_change() {
        let (_temp, _config, store, ring) = fixture();
        let mut definition = definition();
        definition
            .execution_bindings
            .push(ImportedCredentialBinding::token(
                ImportedCredentialMode::PerUser,
                ImportedCredentialDelivery::Bearer,
            ));
        definition.discovery = ImportedDiscoveryCredential::PerUser {
            principal: "admin".into(),
        };
        let draft = store
            .create_imported_service(definition, "admin", accept)
            .unwrap()
            .catalog;
        let draft = store
            .write_imported_secret(slot(&draft, "service-token"), &ring, |catalog, _| {
                accept(catalog)
            })
            .unwrap()
            .catalog;
        let token = |secret: &str| CredentialWriteRequest {
            owner_principal_id: "admin".into(),
            service: "observability".into(),
            name: "default".into(),
            profile: "token".into(),
            credential_kind: "bearer_token".into(),
            secret: json!({"token": secret}),
            metadata: json!({}),
            actor: "admin".into(),
        };
        store
            .upsert_user_credential(
                &ring,
                token("first-token"),
                crate::CredentialManagementPurpose::Administrative,
            )
            .unwrap();
        let mut request = pending(&draft);
        request.credential_versions = store
            .imported_discovery_credential_versions("observability", draft.services[0].version)
            .unwrap();
        let observed = store
            .write_imported_preview(request.clone(), accept)
            .unwrap()
            .catalog;
        let preview = store.imported_preview("observability").unwrap().unwrap();
        store
            .upsert_user_credential(
                &ring,
                token("rotated-token"),
                crate::CredentialManagementPurpose::Administrative,
            )
            .unwrap();
        assert_eq!(store.imported_catalog().unwrap(), observed);
        assert!(store.imported_preview("observability").unwrap().is_none());
        let mut accept_request = update(&observed);
        accept_request.accepted_preview = Some(ImportedPreviewAcceptance {
            manifest_hash: preview.manifest_hash,
            config_revision: preview.config_revision,
            credential_versions: preview.credential_versions,
        });
        assert!(matches!(
            store.update_imported_service(accept_request, accept),
            Err(ManagedStoreError::VersionConflict)
        ));
        request.expected_version = observed.services[0].version;
        request.expected_catalog_revision = observed.revision;
        assert!(matches!(
            store.write_imported_preview(request, accept),
            Err(ManagedStoreError::VersionConflict)
        ));
    }
    #[test]
    fn import_identity_cannot_reuse_retained_service_credentials_or_authority() {
        for leftover in ["credential", "right", "grant", "manager", "limit"] {
            let (_temp, _config, store, ring) = fixture();
            if leftover == "credential" {
                store
                    .upsert_user_credential(
                        &ring,
                        CredentialWriteRequest {
                            owner_principal_id: "admin".into(),
                            service: "observability".into(),
                            name: "default".into(),
                            profile: "token".into(),
                            credential_kind: "bearer_token".into(),
                            secret: json!({"token":"old-endpoint-token"}),
                            metadata: json!({}),
                            actor: "admin".into(),
                        },
                        crate::CredentialManagementPurpose::Administrative,
                    )
                    .unwrap();
            } else {
                let sql = match leftover {
                    "right" => {
                        "INSERT INTO rights(right_id,principal_id,right_name,service,created_by,created_at,revoked_at) VALUES('old','admin','credentials:self:write','observability','admin','2026-01-01','2026-01-02')"
                    }
                    "grant" => {
                        "INSERT INTO policy_grants(grant_id,grant_order,service,actions_json,resources_json,credential_mode,status,version,created_at,created_by,updated_at,updated_by) VALUES('old',0,'observability','[\"query\"]','{}','per_user','deleted',1,'2026-01-01','admin','2026-01-01','admin')"
                    }
                    "manager" => {
                        "INSERT INTO service_policy_management_assignments(assignment_id,service,principal_id,created_at,created_by) VALUES('old','observability','admin','2026-01-01','admin')"
                    }
                    "limit" => {
                        "INSERT INTO principal_service_limits(principal_id,service,requests,window_seconds,created_at,created_by,updated_at,updated_by) VALUES('admin','observability',1,60,'2026-01-01','admin','2026-01-01','admin')"
                    }
                    _ => unreachable!(),
                };
                store.connection.lock().unwrap().execute(sql, []).unwrap();
            }
            let rejected = store.create_imported_service(definition(), "admin", accept);
            assert!(
                matches!(rejected, Err(ManagedStoreError::InputInvalid(ref reason)) if reason.contains("identity already in use")),
                "{leftover}: {rejected:?}"
            );
            assert_eq!(
                store.imported_catalog().unwrap(),
                ImportedCatalog::default()
            );
        }
    }

    #[test]
    fn personal_discovery_requires_its_owner_for_selection_observation_and_acceptance() {
        let (_temp, _config, store, ring) = fixture();
        store
            .create_principal(PrincipalWriteRequest {
                role: crate::PrincipalRole::User,
                self_service_enabled: None,
                principal_id: "second-admin".into(),
                kind: "user".into(),
                display_name: None,
                email: None,
                external_subject: None,
                created_by: "test".into(),
            })
            .unwrap();
        store
            .patch_principal_access(crate::PrincipalAccessPatchRequest {
                principal_id: ("second-admin").into(),
                role: Some(crate::PrincipalRole::Admin),
                self_service_enabled: None,
                actor: ("test").into(),
            })
            .unwrap();
        let mut personal = definition();
        personal
            .execution_bindings
            .push(ImportedCredentialBinding::token(
                ImportedCredentialMode::PerUser,
                ImportedCredentialDelivery::Bearer,
            ));
        personal.discovery = ImportedDiscoveryCredential::PerUser {
            principal: "second-admin".into(),
        };
        assert!(matches!(
            store.create_imported_service(personal.clone(), "admin", accept),
            Err(ManagedStoreError::RightMissing)
        ));
        personal.discovery = ImportedDiscoveryCredential::PerUser {
            principal: "admin".into(),
        };
        let draft = store
            .create_imported_service(personal, "admin", accept)
            .unwrap()
            .catalog;
        let draft = store
            .write_imported_secret(slot(&draft, "service-token"), &ring, |catalog, _| {
                accept(catalog)
            })
            .unwrap()
            .catalog;
        store
            .upsert_user_credential(
                &ring,
                CredentialWriteRequest {
                    owner_principal_id: "admin".into(),
                    service: "observability".into(),
                    name: "default".into(),
                    profile: "token".into(),
                    credential_kind: "bearer_token".into(),
                    secret: json!({"token":"personal-token"}),
                    metadata: json!({}),
                    actor: "admin".into(),
                },
                crate::CredentialManagementPurpose::Administrative,
            )
            .unwrap();
        let mut changed = update(&draft);
        changed.definition.discovery = ImportedDiscoveryCredential::PerUser {
            principal: "second-admin".into(),
        };
        assert!(matches!(
            store.update_imported_service(changed, accept),
            Err(ManagedStoreError::RightMissing)
        ));
        let mut observation = pending(&draft);
        observation.credential_versions = store
            .imported_discovery_credential_versions("observability", draft.services[0].version)
            .unwrap();
        observation.actor = "second-admin".into();
        assert!(matches!(
            store.write_imported_preview(observation.clone(), accept),
            Err(ManagedStoreError::RightMissing)
        ));
        assert_eq!(store.imported_catalog().unwrap(), draft);
        observation.actor = "admin".into();
        let observed = store
            .write_imported_preview(observation, accept)
            .unwrap()
            .catalog;
        let preview = store.imported_preview("observability").unwrap().unwrap();
        let mut acceptance = update(&observed);
        acceptance.actor = "second-admin".into();
        acceptance.accepted_preview = Some(ImportedPreviewAcceptance {
            manifest_hash: preview.manifest_hash,
            config_revision: preview.config_revision,
            credential_versions: preview.credential_versions,
        });
        assert!(matches!(
            store.update_imported_service(acceptance, accept),
            Err(ManagedStoreError::RightMissing)
        ));
        // Cleanup by another base administrator uses no personal token.
        let mut disable = update(&observed);
        disable.actor = "second-admin".into();
        store.update_imported_service(disable, accept).unwrap();
    }

    #[test]
    fn reserved_broker_namespace_is_rejected_even_in_persisted_imports() {
        let (_temp, _config, store, _) = fixture();
        let mut reserved = definition();
        reserved.service = "broker".into();
        assert!(
            store
                .create_imported_service(reserved.clone(), "admin", accept)
                .is_err()
        );
        store
            .create_imported_service(definition(), "admin", accept)
            .unwrap();
        store
            .connection
            .lock()
            .unwrap()
            .execute(
                "UPDATE imported_services SET service='broker', definition_json=?1",
                [serde_json::to_string(&reserved).unwrap()],
            )
            .unwrap();
        assert!(store.imported_catalog().is_err());
    }

    #[test]
    fn retained_semantically_invalid_records_remain_readable_and_can_be_disabled_or_retired() {
        let (_temp, config, store, _) = fixture();
        let draft = store
            .create_imported_service(definition(), "admin", accept)
            .unwrap()
            .catalog;
        let mut enabled = update(&draft);
        enabled.actions.push(action());
        enabled.status = ImportedServiceStatus::Enabled;
        let enabled = store
            .update_imported_service(enabled, accept)
            .unwrap()
            .catalog;
        let mut unsupported = enabled.services[0].definition.clone();
        unsupported
            .connection_settings
            .insert("future-setting".into(), "true".into());
        let mut unsupported_action = action().definition;
        unsupported_action.input_schema = json!({"type":"object","properties":{"x":{"$ref":"https://unsupported.invalid/schema"}}});
        {
            let conn = store.connection.lock().unwrap();
            conn.execute(
                "UPDATE imported_services SET definition_json=?1",
                [serde_json::to_string(&unsupported).unwrap()],
            )
            .unwrap();
            conn.execute(
                "UPDATE imported_actions SET definition_json=?1",
                [serde_json::to_string(&unsupported_action).unwrap()],
            )
            .unwrap();
        }
        drop(store);
        let store = ManagedStore::open(&config, ManagedStoreOpenMode::Reload).unwrap();
        let retained = store.imported_catalog().unwrap();
        let disabled = store
            .update_imported_service(update(&retained), accept)
            .unwrap()
            .catalog;
        let mut enable = update(&disabled);
        enable.status = ImportedServiceStatus::Enabled;
        assert!(matches!(
            store.update_imported_service(enable, accept),
            Err(ManagedStoreError::InputInvalid(_))
        ));
        let mut disable_action = update(&disabled);
        disable_action.actions[0].status = ImportedActionStatus::Disabled;
        let disabled = store
            .update_imported_service(disable_action, accept)
            .unwrap()
            .catalog;
        let mut enable_action = update(&disabled);
        enable_action.actions[0].status = ImportedActionStatus::Enabled;
        assert!(matches!(
            store.update_imported_service(enable_action, accept),
            Err(ManagedStoreError::InputInvalid(_))
        ));
        let mut retire = update(&disabled);
        retire.status = ImportedServiceStatus::Retired;
        store.update_imported_service(retire, accept).unwrap();
        let mut wrong_identity = unsupported;
        wrong_identity.service = "different".into();
        store
            .connection
            .lock()
            .unwrap()
            .execute(
                "UPDATE imported_services SET definition_json=?1",
                [serde_json::to_string(&wrong_identity).unwrap()],
            )
            .unwrap();
        assert!(
            store.imported_catalog().is_err(),
            "stored identity mismatch remains structural corruption"
        );
    }
}
