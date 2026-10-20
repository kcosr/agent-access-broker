use crate::handlers::management::common::{
    AgentTokenIssueBody, CredentialPutBody, ManagementAccess, ManagementAuditExtra,
    admin_agent_token_issue_expires_at, agent_token_boundary_audit, agent_token_issue_scopes,
    agent_token_list_query, append_management_audit_with_phase, credential_input_schema_query,
    default_token_ttl_seconds, management_audit_unavailable_response,
    management_committed_write_audit_completion, management_context,
    management_context_error_response, management_pre_audited_success_response,
    management_response, management_store_call, management_store_error_response,
    management_success_envelope, management_success_response, management_token_store_call,
    management_write_audit_preflight, parse_and_validate_agent_token_issue_scopes,
    timestamp_after_seconds_checked,
};
use crate::handlers::management::connections;
use crate::handlers::management::credentials::{
    ConnectionCredentialRequest, CredentialAccess, connection_input_schema, connection_verify_body,
    delete_connection_credential, get_connection_credential, put_connection_credential,
    verify_connection_credential,
};
use crate::state::AppState;
use agent_access_core::{
    BrokerConfig, BrokerRuntime, BrokerTokenClass, BrokerTokenIssueRequest, BrokerTokenRecord,
    DEFAULT_EXECUTION_CONTEXT, EffectiveGroupMembershipRecord, ExternalGroupBindingCreateRequest,
    GroupMemberRecord, GroupPatchRequest, GroupRecord, GroupWriteRequest, IdentityContext,
    LocalPasswordWriteRequest, LoginMethodRecord, ManagedPolicyGrantRecord, ManagedStoreError,
    OidcLoginMethodLinkRequest, PrincipalAccessPatchRequest, PrincipalPatchRequest,
    PrincipalRecord, PrincipalRole, PrincipalWriteRequest, RightGrantRequest,
    broker_token_ttl_options_allow_never, broker_token_ttl_options_allow_ttl, parse_ttl_seconds,
};
use agent_access_provider::ReasonCode;
use axum::Json;
use axum::body::Bytes;
use axum::extract::{ConnectInfo, Path, RawQuery, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::{Value, json};
use std::net::SocketAddr;
use url::form_urlencoded;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct PrincipalCreateBody {
    principal_id: String,
    #[serde(default = "default_user_kind")]
    kind: String,
    display_name: Option<String>,
    email: Option<String>,
    external_subject: Option<String>,
    #[serde(default)]
    role: PrincipalRole,
    self_service_enabled: Option<bool>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct PrincipalAccessBody {
    #[serde(default, deserialize_with = "deserialize_present")]
    role: Option<PrincipalRole>,
    #[serde(default, deserialize_with = "deserialize_present")]
    self_service_enabled: Option<bool>,
}

/// Reads an optional field that, when present, must hold a value: an
/// explicit `null` is invalid rather than an omitted field.
pub(super) fn deserialize_present<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    T::deserialize(deserializer).map(Some)
}

fn default_user_kind() -> String {
    "user".to_string()
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct PrincipalPatchBody {
    #[serde(default, deserialize_with = "deserialize_nullable_string_patch")]
    display_name: Option<Option<String>>,
    #[serde(default, deserialize_with = "deserialize_nullable_string_patch")]
    email: Option<Option<String>>,
    status: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct GroupCreateBody {
    group_id: String,
    display_name: Option<String>,
    description: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct GroupPatchBody {
    #[serde(default, deserialize_with = "deserialize_nullable_string_patch")]
    display_name: Option<Option<String>>,
    #[serde(default, deserialize_with = "deserialize_nullable_string_patch")]
    description: Option<Option<String>>,
    status: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct ExternalGroupBindingCreateBody {
    external_group_id: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct ExternalGroupBindingPatchBody {
    status: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct MicrosoftOidcLinkBody {
    user_object_id: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct PolicyReference {
    grant_ref: String,
    writable: bool,
    grant_id: Option<String>,
    index: Option<usize>,
    subjects: Vec<String>,
    execution_contexts: Vec<String>,
    service: String,
    actions: Vec<String>,
    credential_mode: String,
    priority: Option<i32>,
    resources: Value,
    status: String,
    description: Option<String>,
    version: Option<i64>,
    updated_at: Option<String>,
    updated_by: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    derived_via_subjects: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    derived_via_groups: Vec<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct PolicyReferenceSection {
    kind: String,
    title: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    subject: Option<String>,
    subject_runtime_eligible: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    runtime_ineligible_reason: Option<String>,
    references: Vec<PolicyReference>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct PrincipalDetail {
    #[serde(flatten)]
    principal: PrincipalRecord,
    group_memberships: Vec<EffectiveGroupMembershipRecord>,
    active_policy_group_subjects: Vec<String>,
    policy_reference_sections: Vec<PolicyReferenceSection>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct GroupDetail {
    #[serde(flatten)]
    group: GroupRecord,
    members: Vec<GroupMemberRecord>,
    policy_reference_sections: Vec<PolicyReferenceSection>,
}

fn deserialize_nullable_string_patch<'de, D>(
    deserializer: D,
) -> Result<Option<Option<String>>, D::Error>
where
    D: Deserializer<'de>,
{
    Option::<String>::deserialize(deserializer).map(Some)
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct LocalPasswordResetBody {
    password: String,
    #[serde(default = "default_must_change_password")]
    must_change_password: bool,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct LocalPasswordEnableBody {
    password: String,
    #[serde(default = "default_must_change_password")]
    must_change_password: bool,
    #[serde(default)]
    acknowledge_separate_sign_in: bool,
}

fn default_must_change_password() -> bool {
    true
}

fn admin_principal_filter_query(raw_query: Option<&str>) -> Result<Option<String>, String> {
    let Some(raw_query) = raw_query else {
        return Ok(None);
    };
    let mut principal = None;
    for (key, value) in form_urlencoded::parse(raw_query.as_bytes()) {
        match key.as_ref() {
            "principal" if principal.is_none() => principal = Some(value.into_owned()),
            "principal" => {
                return Err("principal query parameter is duplicated".to_string());
            }
            _ => {
                return Err(format!("query parameter {key} is not supported"));
            }
        }
    }
    Ok(principal)
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct RightGrantBody {
    principal_id: String,
    right: String,
    service: Option<String>,
    credential_name: Option<String>,
    resource_scope_json: Option<String>,
    expires_at: Option<String>,
    reason: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct TokenIssueBody {
    name: String,
    token_class: BrokerTokenClass,
    #[serde(default)]
    scopes: Value,
    ttl: Option<String>,
    ttl_seconds: Option<u64>,
    expires_at: Option<String>,
    #[serde(default)]
    never: bool,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct AdminBrokerTokenRecord {
    #[serde(flatten)]
    record: BrokerTokenRecord,
    browser_session: bool,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct AdminIssuedBrokerToken {
    token: String,
    record: AdminBrokerTokenRecord,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct RewrapBody {
    from_key: String,
    to_key: String,
}

pub(super) fn managed_principal_identity(
    runtime: &BrokerRuntime,
    principal: PrincipalRecord,
    policy_groups: Vec<String>,
) -> IdentityContext {
    let principal_kind = principal.principal_kind();
    runtime.identity_from_principal_groups(
        principal.principal_id,
        principal_kind,
        principal.external_subject,
        principal.groups,
        Some(policy_groups),
        None,
    )
}

fn admin_token_record(record: BrokerTokenRecord, browser_session: bool) -> AdminBrokerTokenRecord {
    AdminBrokerTokenRecord {
        record,
        browser_session,
    }
}

fn admin_issued_token(
    token: String,
    record: BrokerTokenRecord,
    browser_session: bool,
) -> AdminIssuedBrokerToken {
    AdminIssuedBrokerToken {
        token,
        record: admin_token_record(record, browser_session),
    }
}

fn admin_token_success_audit_target(record: &BrokerTokenRecord) -> Option<Value> {
    let mut target = serde_json::Map::from_iter([
        ("principal".to_string(), json!(record.principal_id.clone())),
        ("tokenId".to_string(), json!(record.token_id.clone())),
        ("tokenClass".to_string(), json!(record.token_class.as_str())),
        ("name".to_string(), json!(record.name.clone())),
        ("expiresAt".to_string(), json!(record.expires_at.clone())),
    ]);
    if record.token_class == BrokerTokenClass::AgentInvoke {
        target.insert(
            "boundary".to_string(),
            agent_token_boundary_audit(&record.scopes),
        );
    }
    Some(Value::Object(target))
}

fn admin_token_issue_expires_at(
    config: &BrokerConfig,
    body: &TokenIssueBody,
) -> Result<Option<String>, String> {
    let options = admin_token_ttl_options(config, &body.token_class)?;
    let supplied = [
        body.expires_at.is_some(),
        body.ttl_seconds.is_some(),
        body.ttl.is_some(),
        body.never,
    ]
    .into_iter()
    .filter(|present| *present)
    .count();
    if supplied > 1 {
        return Err("expiresAt, ttlSeconds, ttl, and never are mutually exclusive".to_string());
    }
    if body.never {
        if body.token_class != BrokerTokenClass::AgentInvoke {
            return Err("never is only allowed for agent_invoke tokens".to_string());
        }
        if !broker_token_ttl_options_allow_never(options) {
            return Err(
                "never is not allowed by broker_tokens.admin_agent_invoke_ttl_options".to_string(),
            );
        }
        return Ok(None);
    }
    if let Some(ttl) = body.ttl.as_deref() {
        let seconds = parse_ttl_seconds(ttl)
            .ok_or_else(|| "ttl must use a duration like 30d, 8h, or 120m".to_string())?;
        if !broker_token_ttl_options_allow_ttl(options, ttl) {
            return Err(format!(
                "ttl is not allowed for administrator-issued {} tokens",
                body.token_class.as_str()
            ));
        }
        return timestamp_after_seconds_checked(seconds).map(Some);
    }
    if let Some(seconds) = body.ttl_seconds {
        if seconds == 0 {
            return Err("ttlSeconds must be positive".to_string());
        }
        if !broker_token_ttl_options_allow_ttl(options, &format!("{seconds}s")) {
            return Err(format!(
                "ttlSeconds is not allowed for administrator-issued {} tokens",
                body.token_class.as_str()
            ));
        }
        return timestamp_after_seconds_checked(seconds).map(Some);
    }
    if let Some(expires_at) = body.expires_at.as_deref() {
        let parsed = DateTime::parse_from_rfc3339(expires_at)
            .map_err(|_| "expiresAt must be an RFC3339 timestamp".to_string())?
            .with_timezone(&Utc);
        if parsed <= Utc::now() {
            return Err("expiresAt must be in the future".to_string());
        }
        return Ok(Some(parsed.to_rfc3339()));
    }
    if let Some(seconds) = default_token_ttl_seconds(config, &body.token_class) {
        if !broker_token_ttl_options_allow_ttl(options, &format!("{seconds}s")) {
            return Err(format!(
                "default TTL is not allowed for administrator-issued {} tokens",
                body.token_class.as_str()
            ));
        }
        return timestamp_after_seconds_checked(seconds).map(Some);
    }
    Err(format!(
        "{} token expiry{} is required when its broker_tokens default TTL is not configured",
        body.token_class.as_str(),
        if body.token_class == BrokerTokenClass::AgentInvoke {
            " or never = true"
        } else {
            ""
        }
    ))
}

fn admin_token_ttl_options<'a>(
    config: &'a BrokerConfig,
    token_class: &BrokerTokenClass,
) -> Result<&'a [agent_access_core::BrokerTokenTtlOption], String> {
    let tokens = config
        .broker_tokens
        .as_ref()
        .ok_or_else(|| "broker token configuration is unavailable".to_string())?;
    Ok(match token_class {
        BrokerTokenClass::AgentInvoke => &tokens.admin_agent_invoke_ttl_options,
        BrokerTokenClass::UserManage => &tokens.user_manage_ttl_options,
        BrokerTokenClass::Admin => &tokens.admin_ttl_options,
    })
}

fn management_token_scopes(scopes: &Value) -> Result<Value, String> {
    if let Some(scopes) = scopes.as_object() {
        for key in [
            "allowedExecutionContexts",
            "allowedServices",
            "serviceRestrictions",
        ] {
            if scopes.contains_key(key) {
                return Err(format!("{key} is only valid for agent_invoke token scopes"));
            }
        }
    }
    Ok(if scopes.is_null() {
        json!({})
    } else {
        scopes.clone()
    })
}

fn toml_group_records(config: &BrokerConfig) -> Vec<GroupRecord> {
    let mut groups: Vec<GroupRecord> = config
        .identity
        .groups
        .iter()
        .map(|group| GroupRecord {
            group_id: group.id.clone(),
            display_name: None,
            description: None,
            status: group.status.clone(),
            created_at: None,
            created_by: None,
            updated_at: None,
            updated_by: None,
            disabled_at: None,
            member_count: group.members.len() as u64,
        })
        .collect();
    groups.sort_by(|left, right| left.group_id.cmp(&right.group_id));
    groups
}

fn toml_group_record(config: &BrokerConfig, group_id: &str) -> Option<GroupRecord> {
    toml_group_records(config)
        .into_iter()
        .find(|group| group.group_id == group_id)
}

fn toml_group_members(config: &BrokerConfig, group_id: &str) -> Option<Vec<GroupMemberRecord>> {
    let group = config
        .identity
        .groups
        .iter()
        .find(|group| group.id == group_id)?;
    let mut members: Vec<GroupMemberRecord> = group
        .members
        .iter()
        .map(|principal| GroupMemberRecord {
            principal_id: principal.clone(),
            kind: Some("static".to_string()),
            display_name: None,
            email: None,
            status: Some("active".to_string()),
            created_at: None,
            created_by: None,
            membership: None,
        })
        .collect();
    members.sort_by(|left, right| left.principal_id.cmp(&right.principal_id));
    Some(members)
}

fn toml_policy_references(config: &BrokerConfig, subject: &str) -> Vec<PolicyReference> {
    config
        .policy
        .grants
        .iter()
        .enumerate()
        .filter(|(_, grant)| {
            grant
                .subjects
                .iter()
                .any(|grant_subject| grant_subject == subject)
        })
        .map(|(index, grant)| toml_policy_reference(index, grant))
        .collect()
}

fn toml_group_derived_policy_references(
    config: &BrokerConfig,
    direct_subject: &str,
    active_group_subjects: &[String],
) -> Vec<PolicyReference> {
    config
        .policy
        .grants
        .iter()
        .enumerate()
        .filter_map(|(index, grant)| {
            if grant
                .subjects
                .iter()
                .any(|subject| subject == direct_subject)
            {
                return None;
            }
            let derived_via_subjects = active_group_subjects
                .iter()
                .filter(|group_subject| {
                    grant
                        .subjects
                        .iter()
                        .any(|grant_subject| grant_subject == *group_subject)
                })
                .cloned()
                .collect::<Vec<_>>();
            if derived_via_subjects.is_empty() {
                return None;
            }
            let derived_via_groups = derived_via_subjects
                .iter()
                .filter_map(|subject| subject.strip_prefix("group:").map(str::to_string))
                .collect::<Vec<_>>();
            let mut reference = toml_policy_reference(index, grant);
            reference.derived_via_subjects = derived_via_subjects;
            reference.derived_via_groups = derived_via_groups;
            Some(reference)
        })
        .collect()
}

fn toml_policy_reference(
    index: usize,
    grant: &agent_access_core::PolicyGrantConfig,
) -> PolicyReference {
    PolicyReference {
        grant_ref: format!("toml:{index}"),
        writable: false,
        grant_id: None,
        index: Some(index),
        subjects: grant.subjects.clone(),
        execution_contexts: grant
            .execution_contexts
            .clone()
            .unwrap_or_else(|| vec![DEFAULT_EXECUTION_CONTEXT.to_string()]),
        service: grant.service.clone(),
        actions: grant.actions.clone(),
        credential_mode: grant.credential_mode.clone(),
        priority: grant.priority,
        resources: json!(grant.resources),
        status: "active".to_string(),
        description: None,
        version: None,
        updated_at: None,
        updated_by: None,
        derived_via_subjects: Vec::new(),
        derived_via_groups: Vec::new(),
    }
}

fn managed_policy_references(
    grants: &[ManagedPolicyGrantRecord],
    subject: &str,
) -> Vec<PolicyReference> {
    grants
        .iter()
        .filter(|grant| {
            grant.status != "deleted"
                && grant
                    .subjects
                    .iter()
                    .any(|grant_subject| grant_subject == subject)
        })
        .map(managed_policy_reference)
        .collect()
}

fn managed_group_derived_policy_references(
    grants: &[ManagedPolicyGrantRecord],
    direct_subject: &str,
    active_group_subjects: &[String],
) -> Vec<PolicyReference> {
    grants
        .iter()
        .filter_map(|grant| {
            if grant.status == "deleted"
                || grant
                    .subjects
                    .iter()
                    .any(|grant_subject| grant_subject == direct_subject)
            {
                return None;
            }
            let derived_via_subjects = active_group_subjects
                .iter()
                .filter(|group_subject| {
                    grant
                        .subjects
                        .iter()
                        .any(|grant_subject| grant_subject == *group_subject)
                })
                .cloned()
                .collect::<Vec<_>>();
            if derived_via_subjects.is_empty() {
                return None;
            }
            let derived_via_groups = derived_via_subjects
                .iter()
                .filter_map(|subject| subject.strip_prefix("group:").map(str::to_string))
                .collect::<Vec<_>>();
            let mut reference = managed_policy_reference(grant);
            reference.derived_via_subjects = derived_via_subjects;
            reference.derived_via_groups = derived_via_groups;
            Some(reference)
        })
        .collect()
}

fn managed_policy_reference(grant: &ManagedPolicyGrantRecord) -> PolicyReference {
    PolicyReference {
        grant_ref: grant.grant_id.clone(),
        writable: true,
        grant_id: Some(grant.grant_id.clone()),
        index: None,
        subjects: grant.subjects.clone(),
        execution_contexts: grant.execution_contexts.clone(),
        service: grant.service.clone(),
        actions: grant.actions.clone(),
        credential_mode: grant.credential_mode.clone(),
        priority: grant.priority,
        resources: json!(grant.resources),
        status: grant.status.clone(),
        description: grant.description.clone(),
        version: Some(grant.version),
        updated_at: Some(grant.updated_at.clone()),
        updated_by: Some(grant.updated_by.clone()),
        derived_via_subjects: Vec::new(),
        derived_via_groups: Vec::new(),
    }
}

fn group_subject(group_id: &str) -> String {
    format!("group:{group_id}")
}

fn principal_subject(principal_id: &str) -> String {
    format!("user:{principal_id}")
}

fn login_method_projection(method: LoginMethodRecord) -> Value {
    let mut projection = serde_json::to_value(&method).unwrap_or(Value::Null);
    if method.method != "oidc" || method.external_provider.as_deref() != Some("microsoft") {
        return projection;
    }
    if let Some(object) = projection.as_object_mut() {
        object.remove("externalProvider");
        object.remove("externalSubject");
    }
    let Some((tenant_id, user_object_id)) = method
        .external_subject
        .as_deref()
        .and_then(|subject| subject.strip_prefix("entra:v1:"))
        .and_then(|subject| subject.split_once(':'))
    else {
        return projection;
    };
    if let Some(object) = projection.as_object_mut() {
        object.insert(
            "oidc".to_string(),
            json!({
                "provider": "microsoft",
                "tenantId": tenant_id,
                "userObjectId": user_object_id,
            }),
        );
    }
    projection
}

fn group_detail(
    group: GroupRecord,
    members: Vec<GroupMemberRecord>,
    policy_reference_sections: Vec<PolicyReferenceSection>,
) -> GroupDetail {
    GroupDetail {
        group,
        members,
        policy_reference_sections,
    }
}

fn principal_detail(
    principal: PrincipalRecord,
    group_memberships: Vec<EffectiveGroupMembershipRecord>,
    active_policy_group_subjects: Vec<String>,
    policy_reference_sections: Vec<PolicyReferenceSection>,
) -> PrincipalDetail {
    PrincipalDetail {
        principal,
        group_memberships,
        active_policy_group_subjects,
        policy_reference_sections,
    }
}

fn direct_user_policy_section(
    principal: &PrincipalRecord,
    subject: String,
    references: Vec<PolicyReference>,
) -> PolicyReferenceSection {
    let (eligible, reason) = principal_runtime_eligibility(principal);
    policy_reference_section(
        "direct_user",
        "Direct User Grants",
        Some(subject),
        eligible,
        reason,
        references,
    )
}

fn group_derived_policy_section(
    principal: &PrincipalRecord,
    active_policy_group_subjects: &[String],
    references: Vec<PolicyReference>,
) -> PolicyReferenceSection {
    let (eligible, reason) = if principal.status != "active" {
        principal_runtime_eligibility(principal)
    } else if active_policy_group_subjects.is_empty() {
        (false, Some("not_applicable".to_string()))
    } else {
        (true, None)
    };
    policy_reference_section(
        "group_derived",
        "Group-Derived Grants",
        None,
        eligible,
        reason,
        references,
    )
}

fn direct_group_policy_section(
    group: &GroupRecord,
    subject: String,
    references: Vec<PolicyReference>,
) -> PolicyReferenceSection {
    let (eligible, reason) = group_runtime_eligibility(group);
    policy_reference_section(
        "direct_group",
        "Group Grants",
        Some(subject),
        eligible,
        reason,
        references,
    )
}

fn policy_reference_section(
    kind: &str,
    title: &str,
    subject: Option<String>,
    subject_runtime_eligible: bool,
    runtime_ineligible_reason: Option<String>,
    references: Vec<PolicyReference>,
) -> PolicyReferenceSection {
    PolicyReferenceSection {
        kind: kind.to_string(),
        title: title.to_string(),
        subject,
        subject_runtime_eligible,
        runtime_ineligible_reason,
        references,
    }
}

fn principal_runtime_eligibility(principal: &PrincipalRecord) -> (bool, Option<String>) {
    if principal.status == "active" {
        (true, None)
    } else {
        (false, Some("principal_disabled".to_string()))
    }
}

fn group_runtime_eligibility(group: &GroupRecord) -> (bool, Option<String>) {
    if group.status == "active" {
        (true, None)
    } else {
        (false, Some("group_disabled".to_string()))
    }
}

pub(crate) async fn admin_store_status(
    State(state): State<AppState>,
    ConnectInfo(remote_addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let operation = "admin.store.status";
    let context = match management_context(
        &state,
        remote_addr,
        &headers,
        operation,
        ManagementAccess::AdminRead,
    )
    .await
    {
        Ok(context) => context,
        Err(response) => return *response,
    };
    match management_store_call(&context, |store| store.status()).await {
        Ok(status) => management_success_response(&context, operation, None, json!(status)).await,
        Err(error) => management_store_error_response(&context, operation, None, error).await,
    }
}

pub(crate) async fn admin_principals_list(
    State(state): State<AppState>,
    ConnectInfo(remote_addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let operation = "admin.principals.list";
    let context = match management_context(
        &state,
        remote_addr,
        &headers,
        operation,
        ManagementAccess::AdminRead,
    )
    .await
    {
        Ok(context) => context,
        Err(response) => return *response,
    };
    match management_store_call(&context, |store| store.list_principals()).await {
        Ok(principals) => {
            management_success_response(&context, operation, None, json!(principals)).await
        }
        Err(error) => management_store_error_response(&context, operation, None, error).await,
    }
}

pub(crate) async fn admin_groups_list(
    State(state): State<AppState>,
    ConnectInfo(remote_addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let operation = "admin.groups.list";
    let context = match management_context(
        &state,
        remote_addr,
        &headers,
        operation,
        ManagementAccess::AdminRead,
    )
    .await
    {
        Ok(context) => context,
        Err(response) => return *response,
    };
    if context.snapshot.runtime.config().identity.authority == "toml" {
        let groups = toml_group_records(context.snapshot.runtime.config());
        return management_success_response(&context, operation, None, json!(groups)).await;
    }
    match management_store_call(&context, |store| store.list_groups()).await {
        Ok(groups) => management_success_response(&context, operation, None, json!(groups)).await,
        Err(error) => management_store_error_response(&context, operation, None, error).await,
    }
}

pub(crate) async fn admin_groups_get(
    State(state): State<AppState>,
    Path(group): Path<String>,
    ConnectInfo(remote_addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let operation = "admin.groups.inspect";
    let context = match management_context(
        &state,
        remote_addr,
        &headers,
        operation,
        ManagementAccess::AdminRead,
    )
    .await
    {
        Ok(context) => context,
        Err(response) => return *response,
    };
    let target = Some(json!({"group": group}));
    if context.snapshot.runtime.config().identity.authority == "toml" {
        let Some(record) = toml_group_record(context.snapshot.runtime.config(), &group) else {
            return management_context_error_response(
                &context,
                StatusCode::NOT_FOUND,
                operation,
                ReasonCode::GroupNotFound,
                "group was not found",
                target,
            )
            .await;
        };
        let members =
            toml_group_members(context.snapshot.runtime.config(), &group).unwrap_or_default();
        let subject = group_subject(&group);
        let policy_references = toml_policy_references(context.snapshot.runtime.config(), &subject);
        let section = direct_group_policy_section(&record, subject, policy_references);
        let detail = group_detail(record, members, vec![section]);
        return management_success_response(&context, operation, target, json!(detail)).await;
    }
    let managed_policy = context.snapshot.runtime.config().policy.authority == "managed";
    let group_for_store = group.clone();
    match management_store_call(&context, move |store| {
        let record = store.group(&group_for_store)?;
        let members = store.group_members(&group_for_store)?;
        let policy_grants = if managed_policy {
            store.policy_grants()?
        } else {
            Vec::new()
        };
        Ok((record, members, policy_grants))
    })
    .await
    {
        Ok((record, members, policy_grants)) => {
            let subject = group_subject(&record.group_id);
            let policy_references =
                if context.snapshot.runtime.config().policy.authority == "managed" {
                    managed_policy_references(&policy_grants, &subject)
                } else {
                    toml_policy_references(context.snapshot.runtime.config(), &subject)
                };
            let section = direct_group_policy_section(&record, subject, policy_references);
            let detail = group_detail(record, members, vec![section]);
            management_success_response(&context, operation, target, json!(detail)).await
        }
        Err(error) => management_store_error_response(&context, operation, target, error).await,
    }
}

pub(crate) async fn admin_group_members_list(
    State(state): State<AppState>,
    Path(group): Path<String>,
    ConnectInfo(remote_addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let operation = "admin.groups.members.list";
    let context = match management_context(
        &state,
        remote_addr,
        &headers,
        operation,
        ManagementAccess::AdminRead,
    )
    .await
    {
        Ok(context) => context,
        Err(response) => return *response,
    };
    let target = Some(json!({"group": group}));
    if context.snapshot.runtime.config().identity.authority == "toml" {
        let Some(members) = toml_group_members(context.snapshot.runtime.config(), &group) else {
            return management_context_error_response(
                &context,
                StatusCode::NOT_FOUND,
                operation,
                ReasonCode::GroupNotFound,
                "group was not found",
                target,
            )
            .await;
        };
        return management_success_response(&context, operation, target, json!(members)).await;
    }
    let group_for_store = group.clone();
    match management_store_call(&context, move |store| store.group_members(&group_for_store)).await
    {
        Ok(members) => {
            management_success_response(&context, operation, target, json!(members)).await
        }
        Err(error) => management_store_error_response(&context, operation, target, error).await,
    }
}

pub(crate) async fn admin_groups_create(
    State(state): State<AppState>,
    ConnectInfo(remote_addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(body): Json<GroupCreateBody>,
) -> impl IntoResponse {
    let operation = "admin.groups.create";
    let context = match management_context(
        &state,
        remote_addr,
        &headers,
        operation,
        ManagementAccess::AdminWrite,
    )
    .await
    {
        Ok(context) => context,
        Err(response) => return *response,
    };
    let target = Some(json!({"group": body.group_id}));
    if let Err(response) =
        management_write_audit_preflight(&context, operation, target.clone()).await
    {
        return *response;
    }
    if context.snapshot.runtime.config().identity.authority != "managed" {
        return management_context_error_response(
            &context,
            StatusCode::BAD_REQUEST,
            operation,
            ReasonCode::InputInvalid,
            "group writes require identity.authority = managed",
            target,
        )
        .await;
    }
    let actor = context.identity.principal.clone();
    match management_store_call(&context, move |store| {
        store.create_group(GroupWriteRequest {
            group_id: body.group_id,
            display_name: body.display_name,
            description: body.description,
            created_by: actor,
        })
    })
    .await
    {
        Ok(group) => {
            management_pre_audited_success_response(&context, operation, target, json!(group))
        }
        Err(error) => management_store_error_response(&context, operation, target, error).await,
    }
}

pub(crate) async fn admin_groups_patch(
    State(state): State<AppState>,
    Path(group): Path<String>,
    ConnectInfo(remote_addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(body): Json<GroupPatchBody>,
) -> impl IntoResponse {
    let operation = "admin.groups.patch";
    let context = match management_context(
        &state,
        remote_addr,
        &headers,
        operation,
        ManagementAccess::AdminWrite,
    )
    .await
    {
        Ok(context) => context,
        Err(response) => return *response,
    };
    let target = Some(json!({"group": group}));
    if let Err(response) =
        management_write_audit_preflight(&context, operation, target.clone()).await
    {
        return *response;
    }
    if context.snapshot.runtime.config().identity.authority != "managed" {
        return management_context_error_response(
            &context,
            StatusCode::BAD_REQUEST,
            operation,
            ReasonCode::InputInvalid,
            "group writes require identity.authority = managed",
            target,
        )
        .await;
    }
    let actor = context.identity.principal.clone();
    let group_for_store = group.clone();
    match management_store_call(&context, move |store| {
        store.patch_group(GroupPatchRequest {
            group_id: group_for_store,
            display_name: body.display_name,
            description: body.description,
            status: body.status,
            updated_by: actor,
        })
    })
    .await
    {
        Ok(group) => {
            management_pre_audited_success_response(&context, operation, target, json!(group))
        }
        Err(error) => management_store_error_response(&context, operation, target, error).await,
    }
}

pub(crate) async fn admin_group_member_add(
    State(state): State<AppState>,
    Path((group, principal)): Path<(String, String)>,
    ConnectInfo(remote_addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let operation = "admin.groups.members.add";
    let context = match management_context(
        &state,
        remote_addr,
        &headers,
        operation,
        ManagementAccess::AdminWrite,
    )
    .await
    {
        Ok(context) => context,
        Err(response) => return *response,
    };
    let target = Some(json!({"group": group, "principal": principal}));
    if let Err(response) =
        management_write_audit_preflight(&context, operation, target.clone()).await
    {
        return *response;
    }
    if context.snapshot.runtime.config().identity.authority != "managed" {
        return management_context_error_response(
            &context,
            StatusCode::BAD_REQUEST,
            operation,
            ReasonCode::InputInvalid,
            "group writes require identity.authority = managed",
            target,
        )
        .await;
    }
    let group_for_store = group.clone();
    let principal_for_store = principal.clone();
    let actor = context.identity.principal.clone();
    match management_store_call(&context, move |store| {
        store.add_group(&principal_for_store, &group_for_store, &actor)
    })
    .await
    {
        Ok(()) => management_pre_audited_success_response(
            &context,
            operation,
            target,
            json!({"ok": true}),
        ),
        Err(error) => management_store_error_response(&context, operation, target, error).await,
    }
}

pub(crate) async fn admin_group_member_delete(
    State(state): State<AppState>,
    Path((group, principal)): Path<(String, String)>,
    ConnectInfo(remote_addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let operation = "admin.groups.members.delete";
    let context = match management_context(
        &state,
        remote_addr,
        &headers,
        operation,
        ManagementAccess::AdminWrite,
    )
    .await
    {
        Ok(context) => context,
        Err(response) => return *response,
    };
    let target = Some(json!({"group": group, "principal": principal}));
    if let Err(response) =
        management_write_audit_preflight(&context, operation, target.clone()).await
    {
        return *response;
    }
    if context.snapshot.runtime.config().identity.authority != "managed" {
        return management_context_error_response(
            &context,
            StatusCode::BAD_REQUEST,
            operation,
            ReasonCode::InputInvalid,
            "group writes require identity.authority = managed",
            target,
        )
        .await;
    }
    let group_for_store = group.clone();
    let principal_for_store = principal.clone();
    match management_store_call(&context, move |store| {
        store.remove_local_group_with_effect(&principal_for_store, &group_for_store)
    })
    .await
    {
        Ok(result) => management_pre_audited_success_response(
            &context,
            operation,
            target,
            json!({
                "removed": result.removed,
                "effectiveMembershipRemains": result.still_effective,
            }),
        ),
        Err(error) => management_store_error_response(&context, operation, target, error).await,
    }
}

pub(crate) async fn admin_external_group_bindings_list(
    State(state): State<AppState>,
    Path(group): Path<String>,
    ConnectInfo(remote_addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let operation = "admin.groups.external_group_bindings.list";
    let context = match management_context(
        &state,
        remote_addr,
        &headers,
        operation,
        ManagementAccess::AdminRead,
    )
    .await
    {
        Ok(context) => context,
        Err(response) => return *response,
    };
    let target = Some(json!({"group": group}));
    let group_for_store = group.clone();
    match management_store_call(&context, move |store| {
        store.group(&group_for_store)?;
        store.list_external_group_bindings(Some(&group_for_store))
    })
    .await
    {
        Ok(bindings) => {
            management_success_response(&context, operation, target, json!(bindings)).await
        }
        Err(error) => management_store_error_response(&context, operation, target, error).await,
    }
}

pub(crate) async fn admin_external_group_binding_create(
    State(state): State<AppState>,
    Path(group): Path<String>,
    ConnectInfo(remote_addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(body): Json<ExternalGroupBindingCreateBody>,
) -> impl IntoResponse {
    let operation = "admin.groups.external_group_bindings.create";
    let context = match management_context(
        &state,
        remote_addr,
        &headers,
        operation,
        ManagementAccess::AdminWrite,
    )
    .await
    {
        Ok(context) => context,
        Err(response) => return *response,
    };
    let target = Some(json!({
        "group": group,
        "externalGroupId": body.external_group_id,
    }));
    if let Err(response) =
        management_write_audit_preflight(&context, operation, target.clone()).await
    {
        return *response;
    }
    let actor = context.identity.principal.clone();
    match management_store_call(&context, move |store| {
        store.create_external_group_binding(ExternalGroupBindingCreateRequest {
            external_group_id: body.external_group_id,
            group_id: group,
            actor,
        })
    })
    .await
    {
        Ok(binding) => {
            management_pre_audited_success_response(&context, operation, target, json!(binding))
        }
        Err(error) => management_store_error_response(&context, operation, target, error).await,
    }
}

pub(crate) async fn admin_external_group_binding_patch(
    State(state): State<AppState>,
    Path((group, binding)): Path<(String, String)>,
    ConnectInfo(remote_addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(body): Json<ExternalGroupBindingPatchBody>,
) -> impl IntoResponse {
    let operation = "admin.groups.external_group_bindings.patch";
    let context = match management_context(
        &state,
        remote_addr,
        &headers,
        operation,
        ManagementAccess::AdminWrite,
    )
    .await
    {
        Ok(context) => context,
        Err(response) => return *response,
    };
    let target = Some(json!({"group": group, "binding": binding}));
    let enabled = match body.status.as_str() {
        "active" => true,
        "disabled" => false,
        _ => {
            return management_context_error_response(
                &context,
                StatusCode::BAD_REQUEST,
                operation,
                ReasonCode::InputInvalid,
                "status must be active or disabled",
                target,
            )
            .await;
        }
    };
    let target = Some(json!({
        "group": group,
        "binding": binding,
        "status": body.status,
    }));
    if let Err(response) =
        management_write_audit_preflight(&context, operation, target.clone()).await
    {
        return *response;
    }
    let actor = context.identity.principal.clone();
    let binding_for_store = binding.clone();
    let group_for_store = group.clone();
    match management_store_call(&context, move |store| {
        let record = store.external_group_binding(&binding_for_store)?;
        if record.group_id != group_for_store {
            return Err(ManagedStoreError::ExternalGroupBindingNotFound);
        }
        store.set_external_group_binding_enabled(&binding_for_store, enabled, &actor)
    })
    .await
    {
        Ok(binding) => {
            management_pre_audited_success_response(&context, operation, target, json!(binding))
        }
        Err(error) => management_store_error_response(&context, operation, target, error).await,
    }
}

pub(crate) async fn admin_external_group_binding_delete(
    State(state): State<AppState>,
    Path((group, binding)): Path<(String, String)>,
    ConnectInfo(remote_addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let operation = "admin.groups.external_group_bindings.delete";
    let context = match management_context(
        &state,
        remote_addr,
        &headers,
        operation,
        ManagementAccess::AdminWrite,
    )
    .await
    {
        Ok(context) => context,
        Err(response) => return *response,
    };
    let target = Some(json!({"group": group, "binding": binding}));
    if let Err(response) =
        management_write_audit_preflight(&context, operation, target.clone()).await
    {
        return *response;
    }
    let binding_for_store = binding.clone();
    let group_for_store = group.clone();
    match management_store_call(&context, move |store| {
        let record = store.external_group_binding(&binding_for_store)?;
        if record.group_id != group_for_store {
            return Err(ManagedStoreError::ExternalGroupBindingNotFound);
        }
        store.delete_external_group_binding(&binding_for_store)
    })
    .await
    {
        Ok(()) => management_pre_audited_success_response(
            &context,
            operation,
            target,
            json!({"deleted": true}),
        ),
        Err(error) => management_store_error_response(&context, operation, target, error).await,
    }
}

pub(crate) async fn admin_principals_create(
    State(state): State<AppState>,
    ConnectInfo(remote_addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(body): Json<PrincipalCreateBody>,
) -> impl IntoResponse {
    let operation = "admin.principals.create";
    let context = match management_context(
        &state,
        remote_addr,
        &headers,
        operation,
        ManagementAccess::AdminWrite,
    )
    .await
    {
        Ok(context) => context,
        Err(response) => return *response,
    };
    let target = Some(json!({"principal": body.principal_id}));
    if let Err(response) =
        management_write_audit_preflight(&context, operation, target.clone()).await
    {
        return *response;
    }
    let actor = context.identity.principal.clone();
    match management_token_store_call(&state, &context, move |store, _catalog| {
        store.create_principal(PrincipalWriteRequest {
            principal_id: body.principal_id,
            kind: body.kind,
            display_name: body.display_name,
            email: body.email,
            external_subject: body.external_subject,
            role: body.role,
            self_service_enabled: body.self_service_enabled,
            created_by: actor,
        })
    })
    .await
    {
        Ok(principal) => {
            management_pre_audited_success_response(&context, operation, target, json!(principal))
        }
        Err(error) => management_store_error_response(&context, operation, target, error).await,
    }
}

pub(crate) async fn admin_principals_get(
    State(state): State<AppState>,
    Path(principal): Path<String>,
    ConnectInfo(remote_addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let operation = "admin.principals.inspect";
    let context = match management_context(
        &state,
        remote_addr,
        &headers,
        operation,
        ManagementAccess::AdminRead,
    )
    .await
    {
        Ok(context) => context,
        Err(response) => return *response,
    };
    let target = Some(json!({"principal": principal}));
    let managed_policy = context.snapshot.runtime.config().policy.authority == "managed";
    let principal_for_store = principal.clone();
    let resolved_at = Utc::now().to_rfc3339();
    match management_store_call(&context, move |store| {
        let mut principal = store.principal(&principal_for_store)?;
        let membership = store.effective_membership_at(&principal_for_store, &resolved_at)?;
        principal.groups.clone_from(&membership.groups);
        let policy_grants = if managed_policy {
            store.policy_grants()?
        } else {
            Vec::new()
        };
        Ok((principal, membership, policy_grants))
    })
    .await
    {
        Ok((principal, membership, policy_grants)) => {
            let subject = principal_subject(&principal.principal_id);
            let active_policy_group_subjects = membership
                .policy_groups
                .iter()
                .map(|group| group_subject(group))
                .collect::<Vec<_>>();
            let direct_references =
                if context.snapshot.runtime.config().policy.authority == "managed" {
                    managed_policy_references(&policy_grants, &subject)
                } else {
                    toml_policy_references(context.snapshot.runtime.config(), &subject)
                };
            let derived_references =
                if context.snapshot.runtime.config().policy.authority == "managed" {
                    managed_group_derived_policy_references(
                        &policy_grants,
                        &subject,
                        &active_policy_group_subjects,
                    )
                } else {
                    toml_group_derived_policy_references(
                        context.snapshot.runtime.config(),
                        &subject,
                        &active_policy_group_subjects,
                    )
                };
            let sections = vec![
                direct_user_policy_section(&principal, subject, direct_references),
                group_derived_policy_section(
                    &principal,
                    &active_policy_group_subjects,
                    derived_references,
                ),
            ];
            let detail = principal_detail(
                principal,
                membership.details,
                active_policy_group_subjects,
                sections,
            );
            management_success_response(&context, operation, target, json!(detail)).await
        }
        Err(error) => management_store_error_response(&context, operation, target, error).await,
    }
}

pub(crate) async fn admin_principal_services(
    State(state): State<AppState>,
    Path(principal): Path<String>,
    ConnectInfo(remote_addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let operation = "admin.principals.services";
    let context = match management_context(
        &state,
        remote_addr,
        &headers,
        operation,
        ManagementAccess::AdminRead,
    )
    .await
    {
        Ok(context) => context,
        Err(response) => return *response,
    };
    let target = Some(json!({"principal": principal}));
    let principal_for_store = principal.clone();
    let (principal_record, policy_groups) = match management_store_call(&context, move |store| {
        let principal = store.principal(&principal_for_store)?;
        let policy_groups = store.policy_groups(&principal_for_store)?;
        Ok((principal, policy_groups))
    })
    .await
    {
        Ok(principal) => principal,
        Err(error) => {
            return management_store_error_response(&context, operation, target, error).await;
        }
    };
    let identity =
        managed_principal_identity(&context.snapshot.runtime, principal_record, policy_groups);
    let services = context
        .snapshot
        .runtime
        .visible_services_for_management(&identity);
    management_success_response(&context, operation, target, json!(services)).await
}

/// The principal's credential connections and retained rows, as its own
/// `GET /v1/credentials` lists them: evaluated for its kind, grants and
/// stored rows, so an active token whose owner lost every grant on the
/// connection still shows as active.
pub(crate) async fn admin_principal_credentials_list(
    State(state): State<AppState>,
    Path(principal): Path<String>,
    ConnectInfo(remote_addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let operation = crate::handlers::management::audit_actions::ADMIN_CREDENTIALS_LIST_PRINCIPAL;
    let context = match management_context(
        &state,
        remote_addr,
        &headers,
        operation,
        ManagementAccess::AdminRead,
    )
    .await
    {
        Ok(context) => context,
        Err(response) => return *response,
    };
    let target = Some(json!({"principal": principal}));
    let principal_for_store = principal.clone();
    let (principal_record, policy_groups, rows) =
        match management_store_call(&context, move |store| {
            let principal = store.principal(&principal_for_store)?;
            let policy_groups = store.policy_groups(&principal_for_store)?;
            let rows = store.list_credentials(Some(&principal_for_store))?;
            Ok((principal, policy_groups, rows))
        })
        .await
        {
            Ok(stored) => stored,
            Err(error) => {
                return management_store_error_response(&context, operation, target, error).await;
            }
        };
    let runtime = &context.snapshot.runtime;
    let identity = managed_principal_identity(runtime, principal_record, policy_groups);
    let result = connections::credential_list(runtime, &identity, rows, None);
    management_success_response(&context, operation, target, json!(result)).await
}

pub(crate) async fn admin_principal_credential_targets(
    State(state): State<AppState>,
    Path(principal): Path<String>,
    ConnectInfo(remote_addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let operation = crate::handlers::management::audit_actions::ADMIN_CREDENTIALS_TARGETS;
    let context = match management_context(
        &state,
        remote_addr,
        &headers,
        operation,
        ManagementAccess::AdminRead,
    )
    .await
    {
        Ok(context) => context,
        Err(response) => return *response,
    };
    let target = Some(json!({"principal": principal}));
    let principal_for_store = principal.clone();
    let (principal_record, policy_groups) = match management_store_call(&context, move |store| {
        let principal = store.principal(&principal_for_store)?;
        let policy_groups = store.policy_groups(&principal_for_store)?;
        Ok((principal, policy_groups))
    })
    .await
    {
        Ok(principal) => principal,
        Err(error) => {
            return management_store_error_response(&context, operation, target, error).await;
        }
    };
    let runtime = &context.snapshot.runtime;
    let identity = managed_principal_identity(runtime, principal_record, policy_groups);
    // The principal's setup targets: connections selecting the token method
    // for its kind, with a consumer it holds a per_user grant on.
    let targets = connections::connection_ids(runtime)
        .into_iter()
        .filter_map(|connection| {
            let entitled = connections::entitled_consumers(runtime, &identity, &connection);
            if entitled.is_empty() {
                return None;
            }
            connections::target(runtime, &connection, identity.principal_kind, &entitled)
        })
        .collect::<Vec<_>>();
    management_success_response(&context, operation, target, json!(targets)).await
}

pub(crate) async fn admin_principals_patch(
    State(state): State<AppState>,
    Path(principal): Path<String>,
    ConnectInfo(remote_addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(body): Json<PrincipalPatchBody>,
) -> impl IntoResponse {
    let operation = "admin.principals.patch";
    let context = match management_context(
        &state,
        remote_addr,
        &headers,
        operation,
        ManagementAccess::AdminWrite,
    )
    .await
    {
        Ok(context) => context,
        Err(response) => return *response,
    };
    let target = Some(json!({"principal": principal}));
    if body.display_name.is_none() && body.email.is_none() && body.status.is_none() {
        return management_context_error_response(
            &context,
            StatusCode::BAD_REQUEST,
            operation,
            ReasonCode::InputInvalid,
            "at least one of displayName, email, or status is required",
            target,
        )
        .await;
    };
    if let Some(status) = body.status.as_deref()
        && !matches!(status, "active" | "disabled")
    {
        return management_context_error_response(
            &context,
            StatusCode::BAD_REQUEST,
            operation,
            ReasonCode::InputInvalid,
            "status must be active or disabled",
            target,
        )
        .await;
    }
    if let Err(response) =
        management_write_audit_preflight(&context, operation, target.clone()).await
    {
        return *response;
    }
    let principal_for_store = principal.clone();
    match management_store_call(&context, move |store| {
        store.patch_principal(PrincipalPatchRequest {
            principal_id: principal_for_store,
            display_name: body.display_name,
            email: body.email,
            status: body.status,
        })
    })
    .await
    {
        Ok(principal) => {
            management_pre_audited_success_response(&context, operation, target, json!(principal))
        }
        Err(error) => management_store_error_response(&context, operation, target, error).await,
    }
}

pub(crate) async fn admin_principal_access_patch(
    State(state): State<AppState>,
    Path(principal): Path<String>,
    ConnectInfo(remote_addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(body): Json<PrincipalAccessBody>,
) -> impl IntoResponse {
    let operation = "admin.principals.access.patch";
    let context = match management_context(
        &state,
        remote_addr,
        &headers,
        operation,
        ManagementAccess::AdminWrite,
    )
    .await
    {
        Ok(context) => context,
        Err(response) => return *response,
    };
    let target = Some(json!({"principal": principal}));
    if body.role.is_none() && body.self_service_enabled.is_none() {
        return management_context_error_response(
            &context,
            StatusCode::BAD_REQUEST,
            operation,
            ReasonCode::InputInvalid,
            "at least one of role or selfServiceEnabled is required",
            target,
        )
        .await;
    }
    if let Err(response) =
        management_write_audit_preflight(&context, operation, target.clone()).await
    {
        return *response;
    }
    let actor = context.identity.principal.clone();
    match management_token_store_call(&state, &context, move |store, _catalog| {
        store.patch_principal_access(PrincipalAccessPatchRequest {
            principal_id: principal,
            role: body.role,
            self_service_enabled: body.self_service_enabled,
            actor,
        })
    })
    .await
    {
        Ok(change) => {
            let completion_target = Some(json!({
                "principal": change.principal.principal_id,
                "previousRole": change.previous_role,
                "role": change.principal.role,
                "previousSelfServiceEnabled": change.previous_self_service_enabled,
                "selfServiceEnabled": change.principal.self_service_enabled,
                "removedServices": change.removed_services,
                "revokedAdminTokenIds": change.revoked_admin_token_ids,
            }));
            management_committed_write_audit_completion(&context, operation, completion_target)
                .await;
            // Use the admitted context even when this request revoked its own bearer.
            management_pre_audited_success_response(
                &context,
                operation,
                target,
                json!(change.principal),
            )
        }
        Err(error) => management_store_error_response(&context, operation, target, error).await,
    }
}

pub(crate) async fn admin_principal_group_add(
    State(state): State<AppState>,
    Path((principal, group)): Path<(String, String)>,
    ConnectInfo(remote_addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let operation = "admin.principals.groups.add";
    let context = match management_context(
        &state,
        remote_addr,
        &headers,
        operation,
        ManagementAccess::AdminWrite,
    )
    .await
    {
        Ok(context) => context,
        Err(response) => return *response,
    };
    let target = Some(json!({"principal": principal, "group": group}));
    if let Err(response) =
        management_write_audit_preflight(&context, operation, target.clone()).await
    {
        return *response;
    }
    if context.snapshot.runtime.config().identity.authority != "managed" {
        return management_context_error_response(
            &context,
            StatusCode::BAD_REQUEST,
            operation,
            ReasonCode::InputInvalid,
            "group writes require identity.authority = managed",
            target,
        )
        .await;
    }
    let principal_for_store = principal.clone();
    let group_for_store = group.clone();
    let actor = context.identity.principal.clone();
    match management_store_call(&context, move |store| {
        store.add_group(&principal_for_store, &group_for_store, &actor)
    })
    .await
    {
        Ok(()) => management_pre_audited_success_response(
            &context,
            operation,
            target,
            json!({"ok": true}),
        ),
        Err(error) => management_store_error_response(&context, operation, target, error).await,
    }
}

pub(crate) async fn admin_principal_group_delete(
    State(state): State<AppState>,
    Path((principal, group)): Path<(String, String)>,
    ConnectInfo(remote_addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let operation = "admin.principals.groups.delete";
    let context = match management_context(
        &state,
        remote_addr,
        &headers,
        operation,
        ManagementAccess::AdminWrite,
    )
    .await
    {
        Ok(context) => context,
        Err(response) => return *response,
    };
    let target = Some(json!({"principal": principal, "group": group}));
    if let Err(response) =
        management_write_audit_preflight(&context, operation, target.clone()).await
    {
        return *response;
    }
    if context.snapshot.runtime.config().identity.authority != "managed" {
        return management_context_error_response(
            &context,
            StatusCode::BAD_REQUEST,
            operation,
            ReasonCode::InputInvalid,
            "group writes require identity.authority = managed",
            target,
        )
        .await;
    }
    let principal_for_store = principal.clone();
    let group_for_store = group.clone();
    match management_store_call(&context, move |store| {
        store.remove_local_group_with_effect(&principal_for_store, &group_for_store)
    })
    .await
    {
        Ok(result) => management_pre_audited_success_response(
            &context,
            operation,
            target,
            json!({
                "removed": result.removed,
                "effectiveMembershipRemains": result.still_effective,
            }),
        ),
        Err(error) => management_store_error_response(&context, operation, target, error).await,
    }
}

pub(crate) async fn admin_principal_login_methods_list(
    State(state): State<AppState>,
    Path(principal): Path<String>,
    ConnectInfo(remote_addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let operation = "admin.principals.login_methods.list";
    let context = match management_context(
        &state,
        remote_addr,
        &headers,
        operation,
        ManagementAccess::AdminRead,
    )
    .await
    {
        Ok(context) => context,
        Err(response) => return *response,
    };
    let target = Some(json!({"principal": principal}));
    let principal_for_store = principal.clone();
    match management_store_call(&context, move |store| {
        store.list_login_methods(&principal_for_store)
    })
    .await
    {
        Ok(methods) => {
            let methods = methods
                .into_iter()
                .map(login_method_projection)
                .collect::<Vec<_>>();
            management_success_response(&context, operation, target, json!(methods)).await
        }
        Err(error) => management_store_error_response(&context, operation, target, error).await,
    }
}

pub(crate) async fn admin_principal_microsoft_oidc_link(
    State(state): State<AppState>,
    Path(principal): Path<String>,
    ConnectInfo(remote_addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(body): Json<MicrosoftOidcLinkBody>,
) -> impl IntoResponse {
    let operation = "admin.principals.login_methods.oidc.microsoft.link";
    let context = match management_context(
        &state,
        remote_addr,
        &headers,
        operation,
        ManagementAccess::AdminWrite,
    )
    .await
    {
        Ok(context) => context,
        Err(response) => return *response,
    };
    let target = Some(json!({
        "principal": principal,
        "provider": "microsoft",
        "userObjectId": body.user_object_id,
    }));
    if let Err(response) =
        management_write_audit_preflight(&context, operation, target.clone()).await
    {
        return *response;
    }
    let actor = context.identity.principal.clone();
    match management_store_call(&context, move |store| {
        store.link_oidc_login_method(OidcLoginMethodLinkRequest {
            principal_id: principal,
            user_object_id: body.user_object_id,
            actor,
        })
    })
    .await
    {
        Ok(method) => management_pre_audited_success_response(
            &context,
            operation,
            target,
            login_method_projection(method),
        ),
        Err(error) => management_store_error_response(&context, operation, target, error).await,
    }
}

pub(crate) async fn admin_principal_microsoft_oidc_unlink(
    State(state): State<AppState>,
    Path(principal): Path<String>,
    ConnectInfo(remote_addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let operation = "admin.principals.login_methods.oidc.microsoft.unlink";
    let context = match management_context(
        &state,
        remote_addr,
        &headers,
        operation,
        ManagementAccess::AdminWrite,
    )
    .await
    {
        Ok(context) => context,
        Err(response) => return *response,
    };
    let target = Some(json!({"principal": principal, "provider": "microsoft"}));
    if let Err(response) =
        management_write_audit_preflight(&context, operation, target.clone()).await
    {
        return *response;
    }
    let actor = context.identity.principal.clone();
    match management_store_call(&context, move |store| {
        store.unlink_oidc_login_method(&principal, &actor)
    })
    .await
    {
        Ok(()) => management_pre_audited_success_response(
            &context,
            operation,
            target,
            json!({"unlinked": true}),
        ),
        Err(error) => management_store_error_response(&context, operation, target, error).await,
    }
}

pub(crate) async fn admin_principal_local_password_reset(
    State(state): State<AppState>,
    Path(principal): Path<String>,
    ConnectInfo(remote_addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(body): Json<LocalPasswordResetBody>,
) -> impl IntoResponse {
    let operation = "admin.principals.local_password.reset";
    let context = match management_context(
        &state,
        remote_addr,
        &headers,
        operation,
        ManagementAccess::AdminWrite,
    )
    .await
    {
        Ok(context) => context,
        Err(response) => return *response,
    };
    let target = Some(json!({"principal": principal, "method": "local_password"}));
    let Some(hasher) = context.snapshot.runtime.local_password_hasher().cloned() else {
        return management_context_error_response(
            &context,
            StatusCode::SERVICE_UNAVAILABLE,
            operation,
            ReasonCode::EncryptionKeyMissing,
            "local password hasher is unavailable",
            target,
        )
        .await;
    };
    if let Err(response) =
        management_write_audit_preflight(&context, operation, target.clone()).await
    {
        return *response;
    }
    let min_password_length = context
        .snapshot
        .runtime
        .config()
        .browser_auth
        .local_password
        .min_password_length;
    let actor = context.identity.principal.clone();
    let principal_for_store = principal.clone();
    match management_store_call(&context, move |store| {
        store.reset_local_password(
            &hasher,
            LocalPasswordWriteRequest {
                principal_id: principal_for_store,
                password: body.password,
                min_password_length,
                password_change_required: body.must_change_password,
                actor,
            },
        )
    })
    .await
    {
        Ok(method) => {
            management_pre_audited_success_response(&context, operation, target, json!(method))
        }
        Err(error) => management_store_error_response(&context, operation, target, error).await,
    }
}

pub(crate) async fn admin_principal_local_password_enable(
    State(state): State<AppState>,
    Path(principal): Path<String>,
    ConnectInfo(remote_addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(body): Json<LocalPasswordEnableBody>,
) -> impl IntoResponse {
    let operation = "admin.principals.local_password.enable";
    let context = match management_context(
        &state,
        remote_addr,
        &headers,
        operation,
        ManagementAccess::AdminWrite,
    )
    .await
    {
        Ok(context) => context,
        Err(response) => return *response,
    };
    let target = Some(json!({"principal": principal, "method": "local_password"}));
    if !body.acknowledge_separate_sign_in {
        return management_context_error_response(
            &context,
            StatusCode::BAD_REQUEST,
            operation,
            ReasonCode::InputInvalid,
            "enabling local sign-in requires acknowledgeSeparateSignIn: true",
            target,
        )
        .await;
    }
    let Some(hasher) = context.snapshot.runtime.local_password_hasher().cloned() else {
        return management_context_error_response(
            &context,
            StatusCode::SERVICE_UNAVAILABLE,
            operation,
            ReasonCode::EncryptionKeyMissing,
            "local password hasher is unavailable",
            target,
        )
        .await;
    };
    if let Err(response) =
        management_write_audit_preflight(&context, operation, target.clone()).await
    {
        return *response;
    }
    let min_password_length = context
        .snapshot
        .runtime
        .config()
        .browser_auth
        .local_password
        .min_password_length;
    let actor = context.identity.principal.clone();
    let principal_for_store = principal.clone();
    match management_store_call(&context, move |store| {
        store.enable_local_password(
            &hasher,
            LocalPasswordWriteRequest {
                principal_id: principal_for_store,
                password: body.password,
                min_password_length,
                password_change_required: body.must_change_password,
                actor,
            },
        )
    })
    .await
    {
        Ok(method) => {
            let target = Some(
                json!({"principal": principal, "method": "local_password", "previousStatus": method.previous_status}),
            );
            management_committed_write_audit_completion(&context, operation, target.clone()).await;
            management_pre_audited_success_response(&context, operation, target, json!(method))
        }
        Err(error) => management_store_error_response(&context, operation, target, error).await,
    }
}

pub(crate) async fn admin_principal_local_password_disable(
    State(state): State<AppState>,
    Path(principal): Path<String>,
    ConnectInfo(remote_addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let operation = "admin.principals.local_password.disable";
    let context = match management_context(
        &state,
        remote_addr,
        &headers,
        operation,
        ManagementAccess::AdminWrite,
    )
    .await
    {
        Ok(context) => context,
        Err(response) => return *response,
    };
    let target = Some(json!({"principal": principal, "method": "local_password"}));
    if let Err(response) =
        management_write_audit_preflight(&context, operation, target.clone()).await
    {
        return *response;
    }
    let actor = context.identity.principal.clone();
    let principal_for_store = principal.clone();
    match management_store_call(&context, move |store| {
        store.disable_local_password(&principal_for_store, &actor)
    })
    .await
    {
        Ok(method) => {
            management_pre_audited_success_response(&context, operation, target, json!(method))
        }
        Err(error) => management_store_error_response(&context, operation, target, error).await,
    }
}

pub(crate) async fn admin_principal_local_password_unlock(
    State(state): State<AppState>,
    Path(principal): Path<String>,
    ConnectInfo(remote_addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let operation = "admin.principals.local_password.unlock";
    let context = match management_context(
        &state,
        remote_addr,
        &headers,
        operation,
        ManagementAccess::AdminWrite,
    )
    .await
    {
        Ok(context) => context,
        Err(response) => return *response,
    };
    let target = Some(json!({"principal": principal, "method": "local_password"}));
    if let Err(response) =
        management_write_audit_preflight(&context, operation, target.clone()).await
    {
        return *response;
    }
    let actor = context.identity.principal.clone();
    let principal_for_store = principal.clone();
    match management_store_call(&context, move |store| {
        store.unlock_local_password(&principal_for_store, &actor)
    })
    .await
    {
        Ok(method) => {
            management_pre_audited_success_response(&context, operation, target, json!(method))
        }
        Err(error) => management_store_error_response(&context, operation, target, error).await,
    }
}

pub(crate) async fn admin_rights_list(
    State(state): State<AppState>,
    ConnectInfo(remote_addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let operation = "admin.rights.list";
    let context = match management_context(
        &state,
        remote_addr,
        &headers,
        operation,
        ManagementAccess::AdminRead,
    )
    .await
    {
        Ok(context) => context,
        Err(response) => return *response,
    };
    match management_store_call(&context, |store| store.list_rights(None)).await {
        Ok(rights) => management_success_response(&context, operation, None, json!(rights)).await,
        Err(error) => management_store_error_response(&context, operation, None, error).await,
    }
}

pub(crate) async fn admin_rights_grant(
    State(state): State<AppState>,
    ConnectInfo(remote_addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(body): Json<RightGrantBody>,
) -> impl IntoResponse {
    let operation = crate::handlers::management::audit_actions::ADMIN_RIGHTS_GRANT;
    let context = match management_context(
        &state,
        remote_addr,
        &headers,
        operation,
        ManagementAccess::AdminWrite,
    )
    .await
    {
        Ok(context) => context,
        Err(response) => return *response,
    };
    let target = Some(json!({
        "principal": body.principal_id,
        "service": body.service,
        "credential": body.credential_name
    }));
    if let Err(response) =
        management_write_audit_preflight(&context, operation, target.clone()).await
    {
        return *response;
    }
    let actor = context.identity.principal.clone();
    match management_store_call(&context, move |store| {
        store.grant_right(RightGrantRequest {
            principal_id: body.principal_id,
            right: body.right,
            service: body.service,
            credential_name: body.credential_name,
            resource_scope_json: body.resource_scope_json,
            created_by: actor,
            expires_at: body.expires_at,
            reason: body.reason,
        })
    })
    .await
    {
        Ok(right) => {
            management_pre_audited_success_response(&context, operation, target, json!(right))
        }
        Err(error) => management_store_error_response(&context, operation, target, error).await,
    }
}

pub(crate) async fn admin_right_revoke(
    State(state): State<AppState>,
    Path(right_id): Path<String>,
    ConnectInfo(remote_addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let operation = "admin.rights.revoke";
    let context = match management_context(
        &state,
        remote_addr,
        &headers,
        operation,
        ManagementAccess::AdminWrite,
    )
    .await
    {
        Ok(context) => context,
        Err(response) => return *response,
    };
    let target = Some(json!({"rightId": right_id}));
    if let Err(response) =
        management_write_audit_preflight(&context, operation, target.clone()).await
    {
        return *response;
    }
    let right_id_for_store = right_id.clone();
    let actor = context.identity.principal.clone();
    match management_store_call(&context, move |store| {
        store.revoke_right(&right_id_for_store, &actor)
    })
    .await
    {
        Ok(right) => {
            management_pre_audited_success_response(&context, operation, target, json!(right))
        }
        Err(error) => management_store_error_response(&context, operation, target, error).await,
    }
}

pub(crate) async fn admin_principal_token_issue(
    State(state): State<AppState>,
    Path(principal): Path<String>,
    ConnectInfo(remote_addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(body): Json<TokenIssueBody>,
) -> impl IntoResponse {
    let operation = super::audit_actions::ADMIN_TOKENS_ISSUE;
    let context = match management_context(
        &state,
        remote_addr,
        &headers,
        operation,
        ManagementAccess::AdminWrite,
    )
    .await
    {
        Ok(context) => context,
        Err(response) => return *response,
    };
    let target = Some(json!({
        "principal": principal,
        "tokenClass": body.token_class.as_str(),
        "name": body.name.clone(),
        "ttl": body.ttl.clone(),
        "ttlSeconds": body.ttl_seconds,
        "requestedExpiresAt": body.expires_at.clone(),
        "never": body.never,
    }));
    if body.token_class == BrokerTokenClass::Admin {
        let principal_for_store = principal.clone();
        let target_principal = match management_store_call(&context, move |store| {
            store.active_principal(&principal_for_store)
        })
        .await
        {
            Ok(principal) => principal,
            Err(error) => {
                return management_store_error_response(&context, operation, target, error).await;
            }
        };
        if !matches!(
            target_principal.role,
            PrincipalRole::Admin | PrincipalRole::Auditor
        ) {
            return management_context_error_response(
                &context,
                StatusCode::BAD_REQUEST,
                operation,
                ReasonCode::InputInvalid,
                "admin tokens require a human admin or auditor target",
                target,
            )
            .await;
        }
    }
    let expires_at = match admin_token_issue_expires_at(context.snapshot.runtime.config(), &body) {
        Ok(expires_at) => expires_at,
        Err(message) => {
            return management_context_error_response(
                &context,
                StatusCode::BAD_REQUEST,
                operation,
                ReasonCode::InputInvalid,
                &message,
                target,
            )
            .await;
        }
    };
    let Some(hasher) = context.snapshot.runtime.broker_token_hasher().cloned() else {
        return management_context_error_response(
            &context,
            StatusCode::SERVICE_UNAVAILABLE,
            operation,
            ReasonCode::EncryptionKeyMissing,
            "broker token hash key is not configured",
            target,
        )
        .await;
    };
    let scopes = if body.token_class == BrokerTokenClass::AgentInvoke {
        let requested_scopes = if body.scopes.is_null() {
            json!({})
        } else {
            body.scopes.clone()
        };
        let principal_for_store = principal.clone();
        let (principal_record, policy_groups) =
            match management_store_call(&context, move |store| {
                let principal = store.principal(&principal_for_store)?;
                let policy_groups = store.policy_groups(&principal_for_store)?;
                Ok((principal, policy_groups))
            })
            .await
            {
                Ok(principal) => principal,
                Err(error) => {
                    return management_store_error_response(&context, operation, target, error)
                        .await;
                }
            };
        let identity =
            managed_principal_identity(&context.snapshot.runtime, principal_record, policy_groups);
        let options = context
            .snapshot
            .runtime
            .agent_token_options_for_identity(&identity);
        match parse_and_validate_agent_token_issue_scopes(
            &context.snapshot.runtime,
            requested_scopes,
            &options,
        ) {
            Ok(scopes) => scopes,
            Err(message) => {
                return management_context_error_response(
                    &context,
                    StatusCode::BAD_REQUEST,
                    operation,
                    ReasonCode::InputInvalid,
                    &message,
                    target,
                )
                .await;
            }
        }
    } else {
        match management_token_scopes(&body.scopes) {
            Ok(scopes) => scopes,
            Err(message) => {
                return management_context_error_response(
                    &context,
                    StatusCode::BAD_REQUEST,
                    operation,
                    ReasonCode::InputInvalid,
                    &message,
                    target,
                )
                .await;
            }
        }
    };
    let target = Some(json!({
        "principal": principal,
        "tokenClass": body.token_class.as_str(),
        "name": body.name.clone(),
        "boundary": (body.token_class == BrokerTokenClass::AgentInvoke)
            .then(|| agent_token_boundary_audit(&scopes)),
        "ttl": body.ttl.clone(),
        "ttlSeconds": body.ttl_seconds,
        "requestedExpiresAt": body.expires_at.clone(),
        "expiresAt": expires_at.clone(),
        "never": body.never,
    }));
    if let Err(response) =
        management_write_audit_preflight(&context, operation, target.clone()).await
    {
        return *response;
    }
    let actor = context.identity.principal.clone();
    match super::common::management_token_store_call(&state, &context, move |store, catalog| {
        let issue_request = BrokerTokenIssueRequest {
            principal_id: principal,
            name: body.name,
            token_class: body.token_class,
            scopes,
            expires_at,
            created_by: actor,
        };
        store.issue_broker_token_with_catalog(&hasher, issue_request, catalog.as_ref())
    })
    .await
    {
        Ok(token) => {
            let success_target = admin_token_success_audit_target(&token.record);
            let audit_envelope = management_success_envelope(
                &context,
                operation,
                success_target.clone(),
                Value::Null,
            );
            if let Err(error) = append_management_audit_with_phase(
                &context.snapshot,
                &context.request_id,
                &context.broker_request_id,
                &context.identity,
                &context.source,
                &audit_envelope,
                ManagementAuditExtra {
                    catalog_change: None,
                    phase: Some("success"),
                    verification: None,
                },
            )
            .await
            {
                return management_audit_unavailable_response(
                    &context.request_id,
                    &context.broker_request_id,
                    operation,
                    &context.identity.principal,
                    error,
                );
            }
            let token = admin_issued_token(token.token, token.record, false);
            management_response(
                StatusCode::OK,
                management_success_envelope(&context, operation, success_target, json!(token)),
            )
        }
        Err(error) => management_store_error_response(&context, operation, target, error).await,
    }
}

pub(crate) async fn admin_principal_agent_tokens_list(
    State(state): State<AppState>,
    Path(principal): Path<String>,
    RawQuery(raw_query): RawQuery,
    ConnectInfo(remote_addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let operation = crate::handlers::management::audit_actions::ADMIN_TOKENS_LIST_PRINCIPAL_AGENT;
    let context = match management_context(
        &state,
        remote_addr,
        &headers,
        operation,
        ManagementAccess::AdminRead,
    )
    .await
    {
        Ok(context) => context,
        Err(response) => return *response,
    };
    let target = Some(json!({"principal": principal, "tokenClass": "agent_invoke"}));
    let query = match agent_token_list_query(raw_query.as_deref()) {
        Ok(query) => query,
        Err(message) => {
            return management_context_error_response(
                &context,
                StatusCode::BAD_REQUEST,
                operation,
                ReasonCode::InputInvalid,
                &message,
                target,
            )
            .await;
        }
    };
    let principal_for_store = principal.clone();
    match management_store_call(&context, move |store| {
        store.principal(&principal_for_store)?;
        store.list_self_agent_tokens(
            &principal_for_store,
            query.include_revoked,
            query.include_expired,
        )
    })
    .await
    {
        Ok(tokens) => management_success_response(&context, operation, target, json!(tokens)).await,
        Err(error) => management_store_error_response(&context, operation, target, error).await,
    }
}

pub(crate) async fn admin_principal_agent_token_options(
    State(state): State<AppState>,
    Path(principal): Path<String>,
    ConnectInfo(remote_addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let operation =
        crate::handlers::management::audit_actions::ADMIN_TOKENS_OPTIONS_PRINCIPAL_AGENT;
    let context = match management_context(
        &state,
        remote_addr,
        &headers,
        operation,
        ManagementAccess::AdminRead,
    )
    .await
    {
        Ok(context) => context,
        Err(response) => return *response,
    };
    let target = Some(json!({"principal": principal, "tokenClass": "agent_invoke"}));
    let principal_for_store = principal.clone();
    let (principal_record, policy_groups) = match management_store_call(&context, move |store| {
        let principal = store.principal(&principal_for_store)?;
        let policy_groups = store.policy_groups(&principal_for_store)?;
        Ok((principal, policy_groups))
    })
    .await
    {
        Ok(principal) => principal,
        Err(error) => {
            return management_store_error_response(&context, operation, target, error).await;
        }
    };
    let identity =
        managed_principal_identity(&context.snapshot.runtime, principal_record, policy_groups);
    let mut options = context
        .snapshot
        .runtime
        .agent_token_options_for_identity(&identity);
    // Where an issued token connects is only for callers that can issue one.
    if context.principal_role == Some(PrincipalRole::Auditor) {
        options.mcp = None;
    }
    management_success_response(&context, operation, target, json!(options)).await
}

pub(crate) async fn admin_principal_agent_token_issue(
    State(state): State<AppState>,
    Path(principal): Path<String>,
    ConnectInfo(remote_addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(raw_body): Json<Value>,
) -> impl IntoResponse {
    let operation = crate::handlers::management::audit_actions::ADMIN_TOKENS_ISSUE_PRINCIPAL_AGENT;
    let context = match management_context(
        &state,
        remote_addr,
        &headers,
        operation,
        ManagementAccess::AdminWrite,
    )
    .await
    {
        Ok(context) => context,
        Err(response) => return *response,
    };
    let body = match serde_json::from_value::<AgentTokenIssueBody>(raw_body) {
        Ok(body) => body,
        Err(error) => {
            return management_context_error_response(
                &context,
                StatusCode::BAD_REQUEST,
                operation,
                ReasonCode::InputInvalid,
                &format!("token issue body is invalid: {error}"),
                Some(json!({"principal": principal, "tokenClass": "agent_invoke"})),
            )
            .await;
        }
    };
    let target = Some(json!({
        "principal": principal,
        "tokenClass": "agent_invoke",
        "name": body.name.clone(),
        "ttl": body.ttl.clone(),
        "requestedExpiresAt": body.expires_at.clone(),
        "never": body.never,
    }));
    if body.name.trim().is_empty() {
        return management_context_error_response(
            &context,
            StatusCode::BAD_REQUEST,
            operation,
            ReasonCode::InputInvalid,
            "token name must not be empty",
            target,
        )
        .await;
    }
    let Some(hasher) = context.snapshot.runtime.broker_token_hasher().cloned() else {
        return management_context_error_response(
            &context,
            StatusCode::SERVICE_UNAVAILABLE,
            operation,
            ReasonCode::EncryptionKeyMissing,
            "broker token hash key is not configured",
            target,
        )
        .await;
    };
    let principal_for_store = principal.clone();
    let (principal_record, policy_groups) = match management_store_call(&context, move |store| {
        let principal = store.principal(&principal_for_store)?;
        let policy_groups = store.policy_groups(&principal_for_store)?;
        Ok((principal, policy_groups))
    })
    .await
    {
        Ok(principal) => principal,
        Err(error) => {
            return management_store_error_response(&context, operation, target, error).await;
        }
    };
    let identity =
        managed_principal_identity(&context.snapshot.runtime, principal_record, policy_groups);
    let options = context
        .snapshot
        .runtime
        .agent_token_options_for_identity(&identity);
    let scopes = match agent_token_issue_scopes(
        &context.snapshot.runtime,
        body.allowed_services.clone(),
        body.allowed_execution_contexts.clone(),
        body.service_restrictions.clone(),
        &options,
    ) {
        Ok(scopes) => scopes,
        Err(message) => {
            return management_context_error_response(
                &context,
                StatusCode::BAD_REQUEST,
                operation,
                ReasonCode::InputInvalid,
                &message,
                target,
            )
            .await;
        }
    };
    let expires_at =
        match admin_agent_token_issue_expires_at(context.snapshot.runtime.config(), &body) {
            Ok(expires_at) => expires_at,
            Err(message) => {
                return management_context_error_response(
                    &context,
                    StatusCode::BAD_REQUEST,
                    operation,
                    ReasonCode::InputInvalid,
                    &message,
                    target,
                )
                .await;
            }
        };
    let target = Some(json!({
        "principal": principal,
        "tokenClass": "agent_invoke",
        "name": body.name.clone(),
        "boundary": agent_token_boundary_audit(&scopes),
        "ttl": body.ttl.clone(),
        "requestedExpiresAt": body.expires_at.clone(),
        "expiresAt": expires_at.clone(),
        "never": body.never,
    }));
    if let Err(response) =
        management_write_audit_preflight(&context, operation, target.clone()).await
    {
        return *response;
    }
    let actor = context.identity.principal.clone();
    let principal_for_store = principal.clone();
    match super::common::management_token_store_call(&state, &context, move |store, catalog| {
        store.issue_broker_token_with_catalog(
            &hasher,
            BrokerTokenIssueRequest {
                principal_id: principal_for_store,
                name: body.name,
                token_class: BrokerTokenClass::AgentInvoke,
                scopes,
                expires_at,
                created_by: actor,
            },
            catalog.as_ref(),
        )
    })
    .await
    {
        Ok(token) => {
            let success_target = admin_token_success_audit_target(&token.record);
            let audit_envelope = management_success_envelope(
                &context,
                operation,
                success_target.clone(),
                Value::Null,
            );
            if let Err(error) = append_management_audit_with_phase(
                &context.snapshot,
                &context.request_id,
                &context.broker_request_id,
                &context.identity,
                &context.source,
                &audit_envelope,
                ManagementAuditExtra {
                    catalog_change: None,
                    phase: Some("success"),
                    verification: None,
                },
            )
            .await
            {
                return management_audit_unavailable_response(
                    &context.request_id,
                    &context.broker_request_id,
                    operation,
                    &context.identity.principal,
                    error,
                );
            }
            management_response(
                StatusCode::OK,
                management_success_envelope(&context, operation, success_target, json!(token)),
            )
        }
        Err(error) => management_store_error_response(&context, operation, target, error).await,
    }
}

pub(crate) async fn admin_principal_agent_token_get(
    State(state): State<AppState>,
    Path((principal, token_id)): Path<(String, String)>,
    ConnectInfo(remote_addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let operation =
        crate::handlers::management::audit_actions::ADMIN_TOKENS_INSPECT_PRINCIPAL_AGENT;
    let context = match management_context(
        &state,
        remote_addr,
        &headers,
        operation,
        ManagementAccess::AdminRead,
    )
    .await
    {
        Ok(context) => context,
        Err(response) => return *response,
    };
    let target = Some(json!({
        "principal": principal,
        "tokenClass": "agent_invoke",
        "tokenId": token_id
    }));
    let principal_for_store = principal.clone();
    let token_id_for_store = token_id.clone();
    match management_store_call(&context, move |store| {
        store.self_agent_token(&principal_for_store, &token_id_for_store)
    })
    .await
    {
        Ok(token) => management_success_response(&context, operation, target, json!(token)).await,
        Err(error) => management_store_error_response(&context, operation, target, error).await,
    }
}

pub(crate) async fn admin_principal_agent_token_revoke(
    State(state): State<AppState>,
    Path((principal, token_id)): Path<(String, String)>,
    ConnectInfo(remote_addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let operation = crate::handlers::management::audit_actions::ADMIN_TOKENS_REVOKE_PRINCIPAL_AGENT;
    let context = match management_context(
        &state,
        remote_addr,
        &headers,
        operation,
        ManagementAccess::AdminWrite,
    )
    .await
    {
        Ok(context) => context,
        Err(response) => return *response,
    };
    let target = Some(json!({
        "principal": principal,
        "tokenClass": "agent_invoke",
        "tokenId": token_id
    }));
    if let Err(response) =
        management_write_audit_preflight(&context, operation, target.clone()).await
    {
        return *response;
    }
    let actor = context.identity.principal.clone();
    let principal_for_store = principal.clone();
    let token_id_for_store = token_id.clone();
    match management_store_call(&context, move |store| {
        store.revoke_self_agent_token(&principal_for_store, &token_id_for_store, &actor)
    })
    .await
    {
        Ok(token) => {
            management_pre_audited_success_response(&context, operation, target, json!(token))
        }
        Err(error) => management_store_error_response(&context, operation, target, error).await,
    }
}

pub(crate) async fn admin_principal_agent_token_pause(
    State(state): State<AppState>,
    Path((principal, token_id)): Path<(String, String)>,
    ConnectInfo(remote_addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let operation = crate::handlers::management::audit_actions::ADMIN_TOKENS_PAUSE_PRINCIPAL_AGENT;
    let context = match management_context(
        &state,
        remote_addr,
        &headers,
        operation,
        ManagementAccess::AdminWrite,
    )
    .await
    {
        Ok(context) => context,
        Err(response) => return *response,
    };
    let target = Some(json!({
        "principal": principal,
        "tokenClass": "agent_invoke",
        "tokenId": token_id,
        "resultingState": "Paused"
    }));
    if let Err(response) =
        management_write_audit_preflight(&context, operation, target.clone()).await
    {
        return *response;
    }
    let actor = context.identity.principal.clone();
    let principal_for_store = principal.clone();
    let token_id_for_store = token_id.clone();
    match management_store_call(&context, move |store| {
        store.pause_principal_agent_token(
            &principal_for_store,
            &token_id_for_store,
            &actor,
            agent_access_core::AgentTokenManagementPurpose::Administrative,
        )
    })
    .await
    {
        Ok(token) => {
            management_pre_audited_success_response(&context, operation, target, json!(token))
        }
        Err(error) => management_store_error_response(&context, operation, target, error).await,
    }
}

pub(crate) async fn admin_principal_agent_token_resume(
    State(state): State<AppState>,
    Path((principal, token_id)): Path<(String, String)>,
    ConnectInfo(remote_addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let operation = crate::handlers::management::audit_actions::ADMIN_TOKENS_RESUME_PRINCIPAL_AGENT;
    let context = match management_context(
        &state,
        remote_addr,
        &headers,
        operation,
        ManagementAccess::AdminWrite,
    )
    .await
    {
        Ok(context) => context,
        Err(response) => return *response,
    };
    let target = Some(json!({
        "principal": principal,
        "tokenClass": "agent_invoke",
        "tokenId": token_id,
        "resultingState": "Active"
    }));
    if let Err(response) =
        management_write_audit_preflight(&context, operation, target.clone()).await
    {
        return *response;
    }
    let actor = context.identity.principal.clone();
    let principal_for_store = principal.clone();
    let token_id_for_store = token_id.clone();
    match super::common::management_token_store_call(&state, &context, move |store, catalog| {
        store.resume_principal_agent_token_with_catalog(
            &principal_for_store,
            &token_id_for_store,
            &actor,
            catalog.as_ref(),
            agent_access_core::AgentTokenManagementPurpose::Administrative,
        )
    })
    .await
    {
        Ok(token) => {
            management_pre_audited_success_response(&context, operation, target, json!(token))
        }
        Err(error) => management_store_error_response(&context, operation, target, error).await,
    }
}

pub(crate) async fn admin_tokens_list(
    State(state): State<AppState>,
    RawQuery(raw_query): RawQuery,
    ConnectInfo(remote_addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let operation = "admin.tokens.list";
    let context = match management_context(
        &state,
        remote_addr,
        &headers,
        operation,
        ManagementAccess::AdminRead,
    )
    .await
    {
        Ok(context) => context,
        Err(response) => return *response,
    };
    let principal = match admin_principal_filter_query(raw_query.as_deref()) {
        Ok(principal) => principal,
        Err(message) => {
            return management_context_error_response(
                &context,
                StatusCode::BAD_REQUEST,
                operation,
                ReasonCode::InputInvalid,
                &message,
                None,
            )
            .await;
        }
    };
    match management_store_call(&context, move |store| {
        let tokens = match principal {
            Some(principal) => store.list_broker_tokens_for_principal(&principal)?,
            None => store.list_broker_tokens()?,
        };
        tokens
            .into_iter()
            .map(|token| {
                let browser_session = store.broker_token_is_browser_session(&token.token_id)?;
                Ok(admin_token_record(token, browser_session))
            })
            .collect::<Result<Vec<_>, _>>()
    })
    .await
    {
        Ok(tokens) => management_success_response(&context, operation, None, json!(tokens)).await,
        Err(error) => management_store_error_response(&context, operation, None, error).await,
    }
}

pub(crate) async fn admin_token_get(
    State(state): State<AppState>,
    Path(token_id): Path<String>,
    ConnectInfo(remote_addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let operation = "admin.tokens.inspect";
    let context = match management_context(
        &state,
        remote_addr,
        &headers,
        operation,
        ManagementAccess::AdminRead,
    )
    .await
    {
        Ok(context) => context,
        Err(response) => return *response,
    };
    let target = Some(json!({"tokenId": token_id}));
    let token_id_for_store = token_id.clone();
    match management_store_call(&context, move |store| {
        let token = store.broker_token(&token_id_for_store)?;
        let browser_session = store.broker_token_is_browser_session(&token.token_id)?;
        Ok(admin_token_record(token, browser_session))
    })
    .await
    {
        Ok(token) => management_success_response(&context, operation, target, json!(token)).await,
        Err(error) => management_store_error_response(&context, operation, target, error).await,
    }
}

pub(crate) async fn admin_token_revoke(
    State(state): State<AppState>,
    Path(token_id): Path<String>,
    ConnectInfo(remote_addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let operation = "admin.tokens.revoke";
    let context = match management_context(
        &state,
        remote_addr,
        &headers,
        operation,
        ManagementAccess::AdminWrite,
    )
    .await
    {
        Ok(context) => context,
        Err(response) => return *response,
    };
    let target = Some(json!({"tokenId": token_id}));
    if let Err(response) =
        management_write_audit_preflight(&context, operation, target.clone()).await
    {
        return *response;
    }
    let token_id_for_store = token_id.clone();
    let actor = context.identity.principal.clone();
    match management_store_call(&context, move |store| {
        let token = store.revoke_broker_token(&token_id_for_store, &actor)?;
        let browser_session = store.broker_token_is_browser_session(&token.token_id)?;
        Ok(admin_token_record(token, browser_session))
    })
    .await
    {
        Ok(token) => {
            management_pre_audited_success_response(&context, operation, target, json!(token))
        }
        Err(error) => management_store_error_response(&context, operation, target, error).await,
    }
}

pub(crate) async fn admin_token_pause(
    State(state): State<AppState>,
    Path(token_id): Path<String>,
    ConnectInfo(remote_addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let operation = "admin.tokens.pause";
    let context = match management_context(
        &state,
        remote_addr,
        &headers,
        operation,
        ManagementAccess::AdminWrite,
    )
    .await
    {
        Ok(context) => context,
        Err(response) => return *response,
    };
    let target = Some(json!({
        "tokenId": token_id,
        "tokenClass": "agent_invoke",
        "resultingState": "Paused"
    }));
    if let Err(response) =
        management_write_audit_preflight(&context, operation, target.clone()).await
    {
        return *response;
    }
    let token_id_for_store = token_id.clone();
    let actor = context.identity.principal.clone();
    match management_store_call(&context, move |store| {
        let token = store.pause_broker_token(&token_id_for_store, &actor)?;
        let browser_session = store.broker_token_is_browser_session(&token.token_id)?;
        Ok(admin_token_record(token, browser_session))
    })
    .await
    {
        Ok(token) => {
            management_pre_audited_success_response(&context, operation, target, json!(token))
        }
        Err(error) => management_store_error_response(&context, operation, target, error).await,
    }
}

pub(crate) async fn admin_token_resume(
    State(state): State<AppState>,
    Path(token_id): Path<String>,
    ConnectInfo(remote_addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let operation = "admin.tokens.resume";
    let context = match management_context(
        &state,
        remote_addr,
        &headers,
        operation,
        ManagementAccess::AdminWrite,
    )
    .await
    {
        Ok(context) => context,
        Err(response) => return *response,
    };
    let target = Some(json!({
        "tokenId": token_id,
        "tokenClass": "agent_invoke",
        "resultingState": "Active"
    }));
    if let Err(response) =
        management_write_audit_preflight(&context, operation, target.clone()).await
    {
        return *response;
    }
    let token_id_for_store = token_id.clone();
    let actor = context.identity.principal.clone();
    match super::common::management_token_store_call(&state, &context, move |store, catalog| {
        let token = store.resume_broker_token_with_catalog(
            &token_id_for_store,
            &actor,
            catalog.as_ref(),
        )?;
        let browser_session = store.broker_token_is_browser_session(&token.token_id)?;
        Ok(admin_token_record(token, browser_session))
    })
    .await
    {
        Ok(token) => {
            management_pre_audited_success_response(&context, operation, target, json!(token))
        }
        Err(error) => management_store_error_response(&context, operation, target, error).await,
    }
}

fn admin_request(principal: String, connection: String) -> ConnectionCredentialRequest {
    ConnectionCredentialRequest::new(principal, connection, CredentialAccess::Administrator)
}

pub(crate) async fn admin_principal_credential_get(
    State(state): State<AppState>,
    Path((principal, connection)): Path<(String, String)>,
    ConnectInfo(remote_addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let operation = crate::handlers::management::audit_actions::ADMIN_CREDENTIALS_INSPECT;
    let context = match management_context(
        &state,
        remote_addr,
        &headers,
        operation,
        ManagementAccess::AdminRead,
    )
    .await
    {
        Ok(context) => context,
        Err(response) => return *response,
    };
    get_connection_credential(context, operation, admin_request(principal, connection)).await
}

pub(crate) async fn admin_principal_credential_put(
    State(state): State<AppState>,
    Path((principal, connection)): Path<(String, String)>,
    ConnectInfo(remote_addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(body): Json<CredentialPutBody>,
) -> impl IntoResponse {
    let operation = crate::handlers::management::audit_actions::ADMIN_CREDENTIALS_PUT;
    let context = match management_context(
        &state,
        remote_addr,
        &headers,
        operation,
        ManagementAccess::AdminWrite,
    )
    .await
    {
        Ok(context) => context,
        Err(response) => return *response,
    };
    put_connection_credential(
        context,
        operation,
        admin_request(principal, connection),
        body,
    )
    .await
}

pub(crate) async fn admin_principal_credential_input_schema(
    State(state): State<AppState>,
    Path((principal, connection)): Path<(String, String)>,
    RawQuery(raw_query): RawQuery,
    ConnectInfo(remote_addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let operation = crate::handlers::management::audit_actions::ADMIN_CREDENTIALS_INPUT_SCHEMA;
    let context = match management_context(
        &state,
        remote_addr,
        &headers,
        operation,
        ManagementAccess::AdminRead,
    )
    .await
    {
        Ok(context) => context,
        Err(response) => return *response,
    };
    let query = match credential_input_schema_query(raw_query.as_deref()) {
        Ok(query) => query,
        Err(message) => {
            let target = Some(connections::audit_target(&principal, &connection));
            return management_context_error_response(
                &context,
                StatusCode::BAD_REQUEST,
                operation,
                ReasonCode::InputInvalid,
                &message,
                target,
            )
            .await;
        }
    };
    connection_input_schema(
        context,
        operation,
        admin_request(principal, connection),
        query,
    )
    .await
}

pub(crate) async fn admin_principal_credential_delete(
    State(state): State<AppState>,
    Path((principal, connection)): Path<(String, String)>,
    ConnectInfo(remote_addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let operation = crate::handlers::management::audit_actions::ADMIN_CREDENTIALS_DELETE;
    let context = match management_context(
        &state,
        remote_addr,
        &headers,
        operation,
        ManagementAccess::AdminWrite,
    )
    .await
    {
        Ok(context) => context,
        Err(response) => return *response,
    };
    delete_connection_credential(context, operation, admin_request(principal, connection)).await
}

pub(crate) async fn admin_principal_credential_verify(
    State(state): State<AppState>,
    Path((principal, connection)): Path<(String, String)>,
    ConnectInfo(remote_addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    body: Bytes,
) -> impl IntoResponse {
    let operation = crate::handlers::management::audit_actions::ADMIN_CREDENTIALS_VERIFY;
    let context = match management_context(
        &state,
        remote_addr,
        &headers,
        operation,
        ManagementAccess::AdminWrite,
    )
    .await
    {
        Ok(context) => context,
        Err(response) => return *response,
    };
    let body = match connection_verify_body(body) {
        Ok(body) => body,
        Err(message) => {
            let target = Some(connections::audit_target(&principal, &connection));
            return management_context_error_response(
                &context,
                StatusCode::BAD_REQUEST,
                operation,
                ReasonCode::InputInvalid,
                &message,
                target,
            )
            .await;
        }
    };
    verify_connection_credential(
        context,
        operation,
        admin_request(principal, connection),
        body,
    )
    .await
}

pub(crate) async fn admin_credentials_list(
    State(state): State<AppState>,
    RawQuery(raw_query): RawQuery,
    ConnectInfo(remote_addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let operation = "admin.credentials.list";
    let context = match management_context(
        &state,
        remote_addr,
        &headers,
        operation,
        ManagementAccess::AdminRead,
    )
    .await
    {
        Ok(context) => context,
        Err(response) => return *response,
    };
    let principal = match admin_principal_filter_query(raw_query.as_deref()) {
        Ok(principal) => principal,
        Err(message) => {
            return management_context_error_response(
                &context,
                StatusCode::BAD_REQUEST,
                operation,
                ReasonCode::InputInvalid,
                &message,
                None,
            )
            .await;
        }
    };
    match management_store_call(&context, move |store| {
        store.list_credentials(principal.as_deref())
    })
    .await
    {
        Ok(credentials) => {
            management_success_response(&context, operation, None, json!(credentials)).await
        }
        Err(error) => management_store_error_response(&context, operation, None, error).await,
    }
}

pub(crate) async fn admin_credential_get(
    State(state): State<AppState>,
    Path(credential_id): Path<String>,
    ConnectInfo(remote_addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let operation = crate::handlers::management::audit_actions::ADMIN_CREDENTIALS_INSPECT;
    let context = match management_context(
        &state,
        remote_addr,
        &headers,
        operation,
        ManagementAccess::AdminRead,
    )
    .await
    {
        Ok(context) => context,
        Err(response) => return *response,
    };
    let target = Some(json!({"credentialId": credential_id}));
    let credential_id_for_store = credential_id.clone();
    match management_store_call(&context, move |store| {
        store.credential_by_id(&credential_id_for_store)
    })
    .await
    {
        Ok(credential) => {
            management_success_response(&context, operation, target, json!(credential)).await
        }
        Err(error) => management_store_error_response(&context, operation, target, error).await,
    }
}

pub(crate) async fn admin_credential_delete(
    State(state): State<AppState>,
    Path(credential_id): Path<String>,
    ConnectInfo(remote_addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let operation = crate::handlers::management::audit_actions::ADMIN_CREDENTIALS_DELETE;
    let context = match management_context(
        &state,
        remote_addr,
        &headers,
        operation,
        ManagementAccess::AdminWrite,
    )
    .await
    {
        Ok(context) => context,
        Err(response) => return *response,
    };
    let target = Some(json!({"credentialId": credential_id}));
    if let Err(response) =
        management_write_audit_preflight(&context, operation, target.clone()).await
    {
        return *response;
    }
    let credential_id_for_store = credential_id.clone();
    match management_store_call(&context, move |store| {
        store.delete_user_credential_by_id(
            &credential_id_for_store,
            agent_access_core::CredentialManagementPurpose::Administrative,
        )
    })
    .await
    {
        Ok(credential) => {
            management_pre_audited_success_response(&context, operation, target, json!(credential))
        }
        Err(error) => management_store_error_response(&context, operation, target, error).await,
    }
}

pub(crate) async fn admin_credentials_rewrap(
    State(state): State<AppState>,
    ConnectInfo(remote_addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(body): Json<RewrapBody>,
) -> impl IntoResponse {
    let operation = "admin.credentials.rewrap";
    let context = match management_context(
        &state,
        remote_addr,
        &headers,
        operation,
        ManagementAccess::AdminWrite,
    )
    .await
    {
        Ok(context) => context,
        Err(response) => return *response,
    };
    let Some(key_ring) = context.snapshot.runtime.credential_key_ring().cloned() else {
        return management_context_error_response(
            &context,
            StatusCode::SERVICE_UNAVAILABLE,
            operation,
            ReasonCode::EncryptionKeyMissing,
            "credential encryption key ring is not configured",
            None,
        )
        .await;
    };
    if let Err(response) = management_write_audit_preflight(&context, operation, None).await {
        return *response;
    }
    let actor = context.identity.principal.clone();
    match management_store_call(&context, move |store| {
        store.rewrap_credentials(&key_ring, &body.from_key, &body.to_key, &actor)
    })
    .await
    {
        Ok(summary) => {
            management_pre_audited_success_response(&context, operation, None, json!(summary))
        }
        Err(error) => management_store_error_response(&context, operation, None, error).await,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use agent_access_core::parse_broker_config_raw;

    fn token_issue_body(token_class: BrokerTokenClass) -> TokenIssueBody {
        TokenIssueBody {
            name: "token".to_string(),
            token_class,
            scopes: json!({}),
            ttl: None,
            ttl_seconds: None,
            expires_at: None,
            never: false,
        }
    }

    #[test]
    fn generic_admin_token_issue_requires_explicit_non_expiring_intent() {
        let config = parse_broker_config_raw(
            "test.toml",
            r#"
[identity]
mode = "optional"
authority = "toml"

[policy]
authority = "toml"
default_decision = "deny"

[broker_tokens]
hash_key_ref = "env:TOKEN_HASH_KEY"

[limits]
upload_spool_dir = "upload-spool"
"#,
            &std::sync::Arc::new(crate::backend_registry()),
        )
        .unwrap();

        for token_class in [BrokerTokenClass::UserManage, BrokerTokenClass::Admin] {
            let mut body = token_issue_body(token_class);
            assert!(admin_token_issue_expires_at(&config, &body).is_err());
            body.never = true;
            assert!(admin_token_issue_expires_at(&config, &body).is_err());
        }

        let mut agent = token_issue_body(BrokerTokenClass::AgentInvoke);
        assert!(admin_token_issue_expires_at(&config, &agent).is_err());
        agent.never = true;
        assert_eq!(admin_token_issue_expires_at(&config, &agent).unwrap(), None);
    }

    #[test]
    fn management_token_scopes_reject_agent_only_caveats() {
        assert_eq!(management_token_scopes(&Value::Null).unwrap(), json!({}));
        assert_eq!(
            management_token_scopes(&json!({"managementRight": "credentials.write"})).unwrap(),
            json!({"managementRight": "credentials.write"})
        );
        for key in [
            "allowedExecutionContexts",
            "allowedServices",
            "serviceRestrictions",
        ] {
            let error = management_token_scopes(&json!({(key): ["default"]})).unwrap_err();
            assert_eq!(
                error,
                format!("{key} is only valid for agent_invoke token scopes")
            );
        }
    }
}
