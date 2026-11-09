use super::*;

/// The one-time Microsoft email match. Ordinary profile email is independent.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct MicrosoftEnrollmentRecord {
    pub enrollment_id: String,
    pub principal_id: String,
    pub tenant_id: String,
    pub match_email: String,
    pub revision: u64,
    pub created_at: String,
    pub updated_at: String,
    pub created_by: String,
    pub updated_by: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MicrosoftEnrollmentCreate {
    pub email: String,
}

#[derive(Debug, Clone)]
pub struct MicrosoftEnrollmentCreateRequest {
    pub principal_id: String,
    pub email: String,
    pub provider_generation: u64,
    pub actor: String,
}

#[derive(Debug, Clone)]
pub struct MicrosoftEnrollmentUpdateRequest {
    pub principal_id: String,
    pub enrollment_id: String,
    pub expected_revision: u64,
    pub email: String,
    pub provider_generation: u64,
    pub actor: String,
}

#[derive(Debug, Clone)]
pub struct MicrosoftEnrollmentCancelRequest {
    pub principal_id: String,
    pub enrollment_id: String,
    pub expected_revision: u64,
    pub actor: String,
}

/// Match only a bounded email claim, with the same rules for administrator input.
pub fn canonical_microsoft_enrollment_email(value: &str) -> Option<String> {
    let value = value.trim();
    if value.is_empty() || value.len() > 320 || value.chars().any(char::is_control) {
        return None;
    }
    let (local, domain) = value.split_once('@')?;
    (value.matches('@').count() == 1
        && !local.is_empty()
        && !domain.is_empty()
        && domain.contains('.')
        && !domain.starts_with('.')
        && !domain.ends_with('.'))
    .then(|| value.to_ascii_lowercase())
}

impl ManagedStore {
    pub fn microsoft_enrollment(
        &self,
        principal_id: &str,
    ) -> Result<Option<MicrosoftEnrollmentRecord>, ManagedStoreError> {
        validate_principal_id(principal_id)?;
        let conn = self.connection.lock().unwrap();
        Ok(principal_by_id_without_groups(&conn, principal_id)?.microsoft_enrollment)
    }

    pub fn create_microsoft_enrollment(
        &self,
        request: MicrosoftEnrollmentCreateRequest,
    ) -> Result<MicrosoftEnrollmentRecord, ManagedStoreError> {
        let mut conn = self.connection.lock().unwrap();
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sql_unavailable)?;
        let record = create_tx(&tx, &request)?;
        tx.commit().map_err(sql_unavailable)?;
        Ok(record)
    }

    pub fn update_microsoft_enrollment(
        &self,
        request: MicrosoftEnrollmentUpdateRequest,
    ) -> Result<MicrosoftEnrollmentRecord, ManagedStoreError> {
        validate_principal_id(&request.principal_id)?;
        validate_canonical_uuid(&request.enrollment_id, "enrollmentId")?;
        validate_actor(&request.actor)?;
        let email = canonical_microsoft_enrollment_email(&request.email)
            .ok_or_else(|| input_invalid("Microsoft enrollment email is invalid"))?;
        let mut conn = self.connection.lock().unwrap();
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sql_unavailable)?;
        let principal = principal_by_id_without_groups(&tx, &request.principal_id)?;
        require_interactive_principal(&principal)?;
        let current = require_current(
            &tx,
            &request.principal_id,
            &request.enrollment_id,
            request.expected_revision,
        )?;
        let provider = require_preparation_provider(&tx, request.provider_generation)?;
        if current.tenant_id != provider.tenant_id {
            return Err(ManagedStoreError::OidcLoginMethodConflict);
        }
        if current.match_email == email {
            tx.commit().map_err(sql_unavailable)?;
            return Ok(current);
        }
        let revision = current
            .revision
            .checked_add(1)
            .filter(|revision| *revision <= i64::MAX as u64)
            .ok_or_else(|| input_invalid("Microsoft enrollment revision is exhausted"))?;
        tx.execute(
            "UPDATE pending_microsoft_enrollments SET match_email = ?2, revision = ?3,
             updated_at = ?4, updated_by = ?5 WHERE enrollment_id = ?1",
            params![
                current.enrollment_id,
                email,
                revision as i64,
                normalized_now_string(),
                request.actor
            ],
        )
        .map_err(map_oidc_method_insert_error)?;
        let record =
            read(&tx, &request.principal_id)?.ok_or(ManagedStoreError::OidcLoginMethodConflict)?;
        tx.commit().map_err(sql_unavailable)?;
        Ok(record)
    }

    pub fn cancel_microsoft_enrollment(
        &self,
        request: MicrosoftEnrollmentCancelRequest,
    ) -> Result<MicrosoftEnrollmentRecord, ManagedStoreError> {
        validate_principal_id(&request.principal_id)?;
        validate_canonical_uuid(&request.enrollment_id, "enrollmentId")?;
        validate_actor(&request.actor)?;
        let mut conn = self.connection.lock().unwrap();
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sql_unavailable)?;
        principal_by_id_without_groups(&tx, &request.principal_id)?;
        let current = require_current(
            &tx,
            &request.principal_id,
            &request.enrollment_id,
            request.expected_revision,
        )?;
        tx.execute(
            "DELETE FROM pending_microsoft_enrollments WHERE enrollment_id = ?1",
            [&current.enrollment_id],
        )
        .map_err(sql_unavailable)?;
        tx.commit().map_err(sql_unavailable)?;
        Ok(current)
    }
}

fn require_preparation_provider(
    conn: &Connection,
    generation: u64,
) -> Result<OidcProviderStateRecord, ManagedStoreError> {
    let provider = oidc_provider_state(conn)?.ok_or(ManagedStoreError::OidcProviderUnavailable)?;
    if provider.config_generation != generation {
        return Err(ManagedStoreError::OidcProviderUnavailable);
    }
    Ok(provider)
}

pub(super) fn create_tx(
    conn: &Connection,
    request: &MicrosoftEnrollmentCreateRequest,
) -> Result<MicrosoftEnrollmentRecord, ManagedStoreError> {
    validate_principal_id(&request.principal_id)?;
    validate_actor(&request.actor)?;
    let email = canonical_microsoft_enrollment_email(&request.email)
        .ok_or_else(|| input_invalid("Microsoft enrollment email is invalid"))?;
    let principal = principal_by_id_without_groups(conn, &request.principal_id)?;
    require_interactive_principal(&principal)?;
    let provider = require_preparation_provider(conn, request.provider_generation)?;
    if principal.microsoft_enrollment.is_some()
        || oidc_login_method_for_principal(conn, &request.principal_id)?.is_some()
    {
        return Err(ManagedStoreError::OidcLoginMethodConflict);
    }
    let enrollment_id = Uuid::new_v4().to_string();
    let now = normalized_now_string();
    conn.execute(
        "INSERT INTO pending_microsoft_enrollments (enrollment_id, principal_id, tenant_id,
         match_email, revision, created_at, updated_at, created_by, updated_by)
         VALUES (?1, ?2, ?3, ?4, 1, ?5, ?5, ?6, ?6)",
        params![
            enrollment_id,
            request.principal_id,
            provider.tenant_id,
            email,
            now,
            request.actor
        ],
    )
    .map_err(map_oidc_method_insert_error)?;
    read(conn, &request.principal_id)?.ok_or(ManagedStoreError::OidcLoginMethodConflict)
}

fn require_current(
    conn: &Connection,
    principal_id: &str,
    enrollment_id: &str,
    revision: u64,
) -> Result<MicrosoftEnrollmentRecord, ManagedStoreError> {
    read(conn, principal_id)?
        .filter(|record| record.enrollment_id == enrollment_id && record.revision == revision)
        .ok_or(ManagedStoreError::OidcLoginMethodConflict)
}

pub(super) fn read(
    conn: &Connection,
    principal_id: &str,
) -> Result<Option<MicrosoftEnrollmentRecord>, ManagedStoreError> {
    conn.query_row(
        "SELECT enrollment_id, principal_id, tenant_id, match_email, revision,
         created_at, updated_at, created_by, updated_by FROM pending_microsoft_enrollments
         WHERE principal_id = ?1",
        [principal_id],
        |row| {
            Ok(MicrosoftEnrollmentRecord {
                enrollment_id: row.get(0)?,
                principal_id: row.get(1)?,
                tenant_id: row.get(2)?,
                match_email: row.get(3)?,
                revision: u64::try_from(row.get::<_, i64>(4)?).map_err(|error| {
                    rusqlite::Error::FromSqlConversionFailure(4, Type::Integer, Box::new(error))
                })?,
                created_at: row.get(5)?,
                updated_at: row.get(6)?,
                created_by: row.get(7)?,
                updated_by: row.get(8)?,
            })
        },
    )
    .optional()
    .map_err(sql_unavailable)
}

pub(super) fn find_match(
    conn: &Connection,
    tenant_id: &str,
    email: Option<&str>,
) -> Result<Option<MicrosoftEnrollmentRecord>, ManagedStoreError> {
    let Some(email) = email.and_then(canonical_microsoft_enrollment_email) else {
        return Ok(None);
    };
    let owner: Option<String> = conn
        .query_row(
            "SELECT principal_id FROM pending_microsoft_enrollments
         WHERE tenant_id = ?1 AND match_email = ?2",
            params![tenant_id, email],
            |row| row.get(0),
        )
        .optional()
        .map_err(sql_unavailable)?;
    owner
        .map(|principal| read(conn, &principal))
        .transpose()
        .map(Option::flatten)
}

pub(super) fn enroll_initial_groups(
    conn: &Connection,
    principal_id: &str,
    now: &str,
    actor: &str,
) -> Result<Vec<String>, ManagedStoreError> {
    let processed: bool = conn
        .query_row(
            "SELECT microsoft_group_enrollment_processed FROM principals WHERE principal_id = ?1",
            [principal_id],
            |row| row.get(0),
        )
        .map_err(sql_unavailable)?;
    if processed {
        return Ok(Vec::new());
    }
    let mut statement = conn
        .prepare(
            "SELECT group_id FROM groups WHERE status = 'active'
         AND auto_enroll_new_microsoft_users = 1 ORDER BY group_id",
        )
        .map_err(sql_unavailable)?;
    let groups: Vec<String> = collect_rows(
        statement
            .query_map([], |row| row.get(0))
            .map_err(sql_unavailable)?,
    )?;
    let mut inserted = Vec::new();
    for group_id in groups {
        if conn
            .execute(
                "INSERT INTO principal_groups (principal_id, group_id, created_at, created_by)
             VALUES (?1, ?2, ?3, ?4) ON CONFLICT(principal_id, group_id) DO NOTHING",
                params![principal_id, group_id, now, actor],
            )
            .map_err(sql_unavailable)?
            != 0
        {
            inserted.push(group_id);
        }
    }
    conn.execute(
        "UPDATE principals SET microsoft_group_enrollment_processed = 1
        WHERE principal_id = ?1",
        [principal_id],
    )
    .map_err(sql_unavailable)?;
    Ok(inserted)
}

pub(super) fn refresh_display_name(
    conn: &Connection,
    principal_id: &str,
    value: Option<&str>,
    now: &str,
) -> Result<bool, ManagedStoreError> {
    let Some(value) = value.map(str::trim).filter(|value| {
        !value.is_empty() && value.len() <= 256 && !value.chars().any(char::is_control)
    }) else {
        return Ok(false);
    };
    Ok(conn
        .execute(
            "UPDATE principals SET display_name = ?2, updated_at = ?3
         WHERE principal_id = ?1 AND display_name IS NOT ?2",
            params![principal_id, value, now],
        )
        .map_err(sql_unavailable)?
        != 0)
}

pub(super) fn validate_structure(conn: &Connection) -> Result<(), ManagedStoreError> {
    if conn.is_autocommit() {
        let tx = conn.unchecked_transaction().map_err(sql_unavailable)?;
        validate_structure(&tx)?;
        tx.commit().map_err(sql_unavailable)?;
        return Ok(());
    }
    imported_store::validate_structure_through(conn, MANAGED_STORE_MICROSOFT_ENROLLMENTS_VERSION)?;
    agent_token_issuance::validate_context_rows(conn)?;
    imported_gateway_routes::check_rows(conn)?;
    let invalid =
        || ManagedStoreError::SchemaInvalid("pending Microsoft enrollment is invalid".into());
    let mut statement = conn
        .prepare("SELECT principal_id FROM pending_microsoft_enrollments")
        .map_err(sql_unavailable)?;
    let owners: Vec<String> = collect_rows(
        statement
            .query_map([], |row| row.get(0))
            .map_err(sql_unavailable)?,
    )?;
    let provider = oidc_provider_state(conn)?;
    for owner in owners {
        let record = read(conn, &owner)?.ok_or_else(invalid)?;
        let kind: String = conn
            .query_row(
                "SELECT kind FROM principals WHERE principal_id = ?1",
                [&owner],
                |row| row.get(0),
            )
            .map_err(sql_unavailable)?;
        if kind != "user"
            || record.revision == 0
            || record.revision > i64::MAX as u64
            || validate_canonical_uuid(&record.enrollment_id, "enrollmentId").is_err()
            || validate_canonical_uuid(&record.tenant_id, "tenantId").is_err()
            || canonical_microsoft_enrollment_email(&record.match_email).as_deref()
                != Some(&record.match_email)
            || provider
                .as_ref()
                .is_none_or(|provider| provider.tenant_id != record.tenant_id)
            || oidc_login_method_for_principal(conn, &owner)?.is_some()
            || validate_actor(&record.created_by).is_err()
            || validate_actor(&record.updated_by).is_err()
            || DateTime::parse_from_rfc3339(&record.created_at).is_err()
            || DateTime::parse_from_rfc3339(&record.updated_at).is_err()
        {
            return Err(invalid());
        }
    }
    Ok(())
}
