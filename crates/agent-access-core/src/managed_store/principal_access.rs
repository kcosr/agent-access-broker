use super::*;

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PrincipalRole {
    #[default]
    User,
    Auditor,
    ServicePolicyManager,
    Admin,
}
impl PrincipalRole {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::User => "user",
            Self::Auditor => "auditor",
            Self::ServicePolicyManager => "service_policy_manager",
            Self::Admin => "admin",
        }
    }
    pub fn can_read_admin(self) -> bool {
        matches!(self, Self::Admin | Self::Auditor)
    }
}
impl std::str::FromStr for PrincipalRole {
    type Err = ManagedStoreError;
    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "user" => Ok(Self::User),
            "auditor" => Ok(Self::Auditor),
            "service_policy_manager" => Ok(Self::ServicePolicyManager),
            "admin" => Ok(Self::Admin),
            _ => Err(input_invalid("principal role is invalid")),
        }
    }
}
impl std::fmt::Display for PrincipalRole {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", tag = "kind")]
pub enum PolicyReadScope {
    Global,
    Services { services: BTreeSet<String> },
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", tag = "kind")]
pub enum PolicyWriteScope {
    Global,
    Services { services: BTreeSet<String> },
}
macro_rules! scope_methods {
    ($scope:ident) => {
        impl $scope {
            pub fn services(&self) -> Option<&BTreeSet<String>> {
                match self {
                    Self::Global => None,
                    Self::Services { services } => Some(services),
                }
            }
            pub fn authorizes_service(&self, service: &str) -> bool {
                match self {
                    Self::Global => true,
                    Self::Services { services } => services.contains(service),
                }
            }
            pub fn is_empty(&self) -> bool {
                self.services().is_some_and(BTreeSet::is_empty)
            }
        }
    };
}
scope_methods!(PolicyReadScope);
scope_methods!(PolicyWriteScope);
impl PolicyWriteScope {
    pub fn as_read_scope(&self) -> PolicyReadScope {
        match self {
            Self::Global => PolicyReadScope::Global,
            Self::Services { services } => PolicyReadScope::Services {
                services: services.clone(),
            },
        }
    }
}

#[derive(Debug, Clone)]
pub struct ManagedManagementAuthority {
    pub principal: PrincipalRecord,
    pub policy_read_scope: PolicyReadScope,
    pub policy_write_scope: PolicyWriteScope,
    pub authorities: Vec<EffectiveServicePolicyManagementAuthority>,
}
#[derive(Debug, Clone)]
pub struct PrincipalAccessPatchRequest {
    pub principal_id: String,
    pub role: Option<PrincipalRole>,
    pub self_service_enabled: Option<bool>,
    pub actor: String,
}
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PrincipalAccessChange {
    pub principal: PrincipalRecord,
    pub previous_role: PrincipalRole,
    pub previous_self_service_enabled: bool,
    pub removed_services: Vec<String>,
    pub revoked_admin_token_ids: Vec<String>,
}
#[derive(Debug, Clone)]
pub struct ServicePolicyManagementAssignmentPutRequest {
    pub service: String,
    pub principal_id: String,
    pub created_by: String,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ServicePolicyManagementAssignmentRecord {
    pub assignment_id: String,
    pub service: String,
    pub principal_id: String,
    pub display_name: Option<String>,
    pub principal_status: String,
    pub created_at: String,
    pub created_by: String,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "camelCase")]
pub struct EffectiveServicePolicyManagementAuthority {
    pub service: String,
    pub assignment_id: String,
    pub principal_id: String,
}

pub(super) fn validate_principal_access(
    kind: &str,
    role: PrincipalRole,
    self_service_enabled: bool,
) -> Result<(), ManagedStoreError> {
    let allowed = match kind {
        "user" => true,
        "system" => matches!(
            role,
            PrincipalRole::User | PrincipalRole::ServicePolicyManager
        ),
        "service_account" => role == PrincipalRole::User && !self_service_enabled,
        _ => false,
    };
    if allowed {
        Ok(())
    } else {
        Err(input_invalid(
            "principal kind does not permit this role or self-service setting",
        ))
    }
}
pub(super) fn require_self_service(
    conn: &Connection,
    principal_id: &str,
) -> Result<(), ManagedStoreError> {
    let principal = principal_by_id_without_groups(conn, principal_id)?;
    if principal.status != "active" {
        return Err(ManagedStoreError::PrincipalDisabled);
    }
    if !principal.self_service_enabled {
        return Err(ManagedStoreError::SelfServiceDisabled);
    }
    Ok(())
}
pub(super) fn management_authority_conn(
    conn: &Connection,
    principal_id: &str,
) -> Result<ManagedManagementAuthority, ManagedStoreError> {
    let principal = principal_by_id(conn, principal_id)?;
    if principal.status != "active" {
        return Err(ManagedStoreError::PrincipalDisabled);
    }
    let authorities = if principal.role == PrincipalRole::ServicePolicyManager {
        let mut statement = conn.prepare("SELECT service, assignment_id FROM service_policy_management_assignments WHERE principal_id=?1 ORDER BY service, assignment_id").map_err(sql_unavailable)?;
        collect_rows(
            statement
                .query_map([principal_id], |row| {
                    Ok(EffectiveServicePolicyManagementAuthority {
                        service: row.get(0)?,
                        assignment_id: row.get(1)?,
                        principal_id: principal_id.into(),
                    })
                })
                .map_err(sql_unavailable)?,
        )?
    } else {
        Vec::new()
    };
    let services = authorities
        .iter()
        .map(|authority| authority.service.clone())
        .collect();
    let policy_write_scope = if principal.role == PrincipalRole::Admin {
        PolicyWriteScope::Global
    } else {
        PolicyWriteScope::Services { services }
    };
    let policy_read_scope = if principal.role.can_read_admin() {
        PolicyReadScope::Global
    } else {
        policy_write_scope.as_read_scope()
    };
    Ok(ManagedManagementAuthority {
        principal,
        policy_read_scope,
        policy_write_scope,
        authorities,
    })
}

impl ManagedStore {
    pub fn management_authority(
        &self,
        principal_id: &str,
    ) -> Result<ManagedManagementAuthority, ManagedStoreError> {
        validate_principal_id(principal_id)?;
        let mut conn = self.connection.lock().unwrap();
        let tx = conn.transaction().map_err(sql_unavailable)?;
        let authority = management_authority_conn(&tx, principal_id)?;
        tx.commit().map_err(sql_unavailable)?;
        Ok(authority)
    }
    pub fn effective_service_policy_management_services(
        &self,
        principal_id: &str,
    ) -> Result<Vec<String>, ManagedStoreError> {
        Ok(self
            .management_authority(principal_id)?
            .authorities
            .into_iter()
            .map(|authority| authority.service)
            .collect())
    }
    pub fn effective_service_policy_management_authorities(
        &self,
        principal_id: &str,
    ) -> Result<Vec<EffectiveServicePolicyManagementAuthority>, ManagedStoreError> {
        Ok(self.management_authority(principal_id)?.authorities)
    }
    pub fn patch_principal_access(
        &self,
        request: PrincipalAccessPatchRequest,
    ) -> Result<PrincipalAccessChange, ManagedStoreError> {
        validate_principal_id(&request.principal_id)?;
        validate_actor(&request.actor)?;
        if request.role.is_none() && request.self_service_enabled.is_none() {
            return Err(input_invalid("at least one access setting is required"));
        }
        let mut conn = self.connection.lock().unwrap();
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sql_unavailable)?;
        let principal = principal_by_id(&tx, &request.principal_id)?;
        let role = request.role.unwrap_or(principal.role);
        let self_service_enabled = request
            .self_service_enabled
            .unwrap_or(principal.self_service_enabled);
        validate_principal_access(&principal.kind, role, self_service_enabled)?;
        let role_changed = role != principal.role;
        if role_changed
            && principal_is_active_admin(&tx, &request.principal_id)?
            && active_admin_principal_count(&tx)? <= 1
        {
            return Err(input_invalid("last active admin cannot lose admin role"));
        }
        let mut removed_services = Vec::new();
        let mut revoked_admin_token_ids = Vec::new();
        let now = normalized_now_string();
        if role_changed {
            let mut statement = tx.prepare("SELECT service FROM service_policy_management_assignments WHERE principal_id=?1 ORDER BY service").map_err(sql_unavailable)?;
            removed_services = collect_rows(
                statement
                    .query_map([&request.principal_id], |row| row.get(0))
                    .map_err(sql_unavailable)?,
            )?;
            tx.execute(
                "DELETE FROM service_policy_management_assignments WHERE principal_id=?1",
                [&request.principal_id],
            )
            .map_err(sql_unavailable)?;
            let mut statement = tx.prepare("SELECT token_id FROM broker_tokens WHERE principal_id=?1 AND token_class='admin' AND revoked_at IS NULL ORDER BY token_id").map_err(sql_unavailable)?;
            revoked_admin_token_ids = collect_rows(
                statement
                    .query_map([&request.principal_id], |row| row.get(0))
                    .map_err(sql_unavailable)?,
            )?;
            tx.execute("UPDATE broker_tokens SET revoked_at=?2, revoked_by=?3 WHERE principal_id=?1 AND token_class='admin' AND revoked_at IS NULL", params![request.principal_id,now,request.actor]).map_err(sql_unavailable)?;
        }
        if role_changed || self_service_enabled != principal.self_service_enabled {
            tx.execute("UPDATE principals SET role=?2,self_service_enabled=?3,updated_at=?4 WHERE principal_id=?1",params![request.principal_id,role.as_str(),self_service_enabled,now]).map_err(sql_unavailable)?;
        }
        let result = PrincipalAccessChange {
            principal: principal_by_id(&tx, &request.principal_id)?,
            previous_role: principal.role,
            previous_self_service_enabled: principal.self_service_enabled,
            removed_services,
            revoked_admin_token_ids,
        };
        tx.commit().map_err(sql_unavailable)?;
        Ok(result)
    }
    pub fn put_service_policy_management_assignment(
        &self,
        request: ServicePolicyManagementAssignmentPutRequest,
    ) -> Result<ServicePolicyManagementAssignmentRecord, ManagedStoreError> {
        validate_policy_grant_service_field(&request.service)?;
        validate_principal_id(&request.principal_id)?;
        validate_actor(&request.created_by)?;
        let mut conn = self.connection.lock().unwrap();
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sql_unavailable)?;
        let authority = management_authority_conn(&tx, &request.principal_id)?;
        if authority.principal.role != PrincipalRole::ServicePolicyManager {
            return Err(input_invalid(
                "service policy scope requires the service_policy_manager role",
            ));
        }
        tx.execute("INSERT OR IGNORE INTO service_policy_management_assignments (assignment_id,service,principal_id,created_at,created_by) VALUES (?1,?2,?3,?4,?5)",params![Uuid::new_v4().to_string(),request.service,request.principal_id,normalized_now_string(),request.created_by]).map_err(sql_unavailable)?;
        let assignment = service_policy_management_assignments(&tx, Some(&request.service))?
            .into_iter()
            .find(|assignment| assignment.principal_id == request.principal_id)
            .ok_or(ManagedStoreError::PrincipalNotFound)?;
        tx.commit().map_err(sql_unavailable)?;
        Ok(assignment)
    }
    pub fn delete_service_policy_management_assignment(
        &self,
        service: &str,
        principal_id: &str,
    ) -> Result<bool, ManagedStoreError> {
        validate_policy_grant_service_field(service)?;
        validate_principal_id(principal_id)?;
        let mut conn = self.connection.lock().unwrap();
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sql_unavailable)?;
        let changed = tx.execute("DELETE FROM service_policy_management_assignments WHERE service=?1 AND principal_id=?2",params![service,principal_id]).map_err(sql_unavailable)?;
        tx.commit().map_err(sql_unavailable)?;
        Ok(changed != 0)
    }
    pub fn service_policy_management_assignments(
        &self,
        service: Option<&str>,
    ) -> Result<Vec<ServicePolicyManagementAssignmentRecord>, ManagedStoreError> {
        if let Some(service) = service {
            validate_policy_grant_service_field(service)?;
        }
        service_policy_management_assignments(&self.connection.lock().unwrap(), service)
    }
}
fn service_policy_management_assignments(
    conn: &Connection,
    service: Option<&str>,
) -> Result<Vec<ServicePolicyManagementAssignmentRecord>, ManagedStoreError> {
    let mut statement = conn.prepare("SELECT a.assignment_id,a.service,a.principal_id,p.display_name,p.status,a.created_at,a.created_by FROM service_policy_management_assignments a JOIN principals p ON p.principal_id=a.principal_id WHERE (?1 IS NULL OR a.service=?1) ORDER BY a.service,a.principal_id").map_err(sql_unavailable)?;
    collect_rows(
        statement
            .query_map([service], |row| {
                Ok(ServicePolicyManagementAssignmentRecord {
                    assignment_id: row.get(0)?,
                    service: row.get(1)?,
                    principal_id: row.get(2)?,
                    display_name: row.get(3)?,
                    principal_status: row.get(4)?,
                    created_at: row.get(5)?,
                    created_by: row.get(6)?,
                })
            })
            .map_err(sql_unavailable)?,
    )
}

pub(super) fn validate_structure(conn: &Connection) -> Result<(), ManagedStoreError> {
    let expected = expected_schema_connection(true, true)?;
    for sql in [
        OAUTH_SQL,
        REGISTERED_RESOURCE_TYPES_SQL,
        RESOURCE_ATTRIBUTES_SQL,
        LOCAL_PASSWORD_FAILURES_SQL,
        PRINCIPAL_SERVICE_LIMITS_SQL,
        IMPORTED_SERVICES_SQL,
        include_str!("oauth_discovery_revision.sql"),
        include_str!("principal_access.sql"),
    ] {
        expected.execute_batch(sql).map_err(sql_unavailable)?;
    }
    compare_schema(conn, &expected)?;
    run_foreign_key_check(conn)?;
    run_quick_check(conn)?;
    check_secret_material_ready(conn, None)?;
    check_policy_revision_ready(conn)
}

/// The operation's authorization purpose is independent of its target owner.
/// Administrative token management remains available when personal access is off.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AgentTokenManagementPurpose {
    Personal,
    Administrative,
}

/// Distinguishes personal management from an administrator acting on a target,
/// including an administrator explicitly managing their own principal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CredentialManagementPurpose {
    Personal,
    Administrative,
}
impl CredentialManagementPurpose {
    pub(super) fn check_active_owner(
        self,
        conn: &Connection,
        principal_id: &str,
    ) -> Result<(), ManagedStoreError> {
        if self == Self::Personal {
            return require_self_service(conn, principal_id);
        }
        if principal_by_id_without_groups(conn, principal_id)?.status != "active" {
            return Err(ManagedStoreError::PrincipalDisabled);
        }
        Ok(())
    }
}
