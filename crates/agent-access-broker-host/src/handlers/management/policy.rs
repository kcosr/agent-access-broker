use crate::handlers::management::common::{
    ManagementAccess, management_context, management_context_error_response,
    management_pre_audited_success_response, management_store_call,
    management_store_error_response, management_success_response, management_write_audit_preflight,
};
use crate::state::AppState;
use agent_access_core::{
    BrokerConfig, DEFAULT_EXECUTION_CONTEXT, ManagedPolicyGrantCreateRequest,
    ManagedPolicyGrantPatchRequest, ManagedPolicyGrantRecord, ManagedPolicyGrantStatusRequest,
    ManagedPolicyGrantSubjectAddRequest, ManagedPolicyGrantSubjectRemoveRequest,
    ManagedPolicyRevision, ManagedStoreError, PolicyGrantConfig, PolicyReadScope, PolicyWriteScope,
    ResourceSelection, ServicePolicyManagementAssignmentPutRequest,
    ServicePolicyManagementAssignmentRecord,
};
use agent_access_provider::{
    ActionCapabilities, CredentialDescriptor, ReasonCode, ResourceScopeCapabilities,
    ServiceCapabilities,
};
use axum::body::Bytes;
use axum::extract::{ConnectInfo, Path, RawQuery, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};
use std::net::SocketAddr;
use url::form_urlencoded;

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct PolicyStatusResponse {
    identity_authority: String,
    policy_authority: String,
    writable: bool,
    default_decision: String,
    config_generation: u64,
    policy_generation: u64,
    counts: PolicyGrantCounts,
    management_scope: PolicyReadScope,
    #[serde(skip_serializing_if = "Option::is_none")]
    last_updated_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    last_updated_by: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ServicePolicyManagementAssignmentView {
    assignment_id: String,
    service: String,
    principal_id: String,
    display_name: Option<String>,
    principal_status: String,
    service_configured: bool,
    created_at: String,
    created_by: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ServicePolicyManagementAssignmentDeleteResponse {
    removed: bool,
}

#[derive(Debug, Default, Serialize)]
#[serde(rename_all = "camelCase")]
struct PolicyGrantCounts {
    active: u64,
    disabled: u64,
    deleted: u64,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct PolicyCatalogResponse {
    services: Vec<PolicyServiceCatalog>,
    subjects: PolicySubjectCatalogResponse,
    execution_contexts: PolicyExecutionContextCatalog,
    resources: Vec<agent_access_core::ResourceDefinition>,
    resource_groups: Vec<agent_access_core::ResourceGroupDefinition>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct PolicyExecutionContextCatalog {
    allowed_values: Vec<String>,
    default_context: Option<String>,
    context_required: bool,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct PolicyServiceCatalog {
    available: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    unavailable_reason: Option<String>,
    service: String,
    display_name: String,
    surface: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    gateway_kind: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    broker_hosts: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    credential_verification_inputs: Vec<String>,
    actions: Vec<PolicyActionCatalog>,
    resource_scopes: BTreeMap<String, PolicyScopeCatalog>,
    configured_credential_modes: Vec<String>,
    lookup_credential_configured: bool,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct PolicyActionCatalog {
    available: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    unavailable_reason: Option<String>,
    action: String,
    read_only: bool,
    description: String,
    required_scope_types: Vec<String>,
    credential_modes: Vec<String>,
    lookup_required: bool,
    input_schema: Value,
    /// For a command import's action, who checks its resources.
    #[serde(skip_serializing_if = "Option::is_none")]
    resources_checked_by: Option<agent_access_core::ResourcesCheckedBy>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct PolicyScopeCatalog {
    resource_type: agent_access_provider::ResourceType,
    selectors: Vec<String>,
}

#[derive(Debug, Default, Serialize)]
#[serde(rename_all = "camelCase")]
struct PolicySubjectCatalogResponse {
    users: Vec<PolicyCatalogPrincipal>,
    groups: Vec<PolicyCatalogGroup>,
    anonymous: bool,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct PolicyCatalogPrincipal {
    principal_id: String,
    display_name: Option<String>,
    status: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct PolicyCatalogGroup {
    group_id: String,
    display_name: Option<String>,
    status: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct PolicyGrantView {
    grant_ref: String,
    writable: bool,
    grant_id: Option<String>,
    index: Option<usize>,
    grant_order: Option<i64>,
    subjects: Vec<String>,
    execution_contexts: Vec<String>,
    service: String,
    actions: Vec<String>,
    resources: ResourceSelection,
    credential_mode: String,
    priority: Option<i32>,
    status: String,
    description: Option<String>,
    version: Option<i64>,
    created_at: Option<String>,
    created_by: Option<String>,
    updated_at: Option<String>,
    updated_by: Option<String>,
    disabled_at: Option<String>,
    deleted_at: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct PolicyExportResponse {
    policy_authority: String,
    policy_generation: u64,
    exported_at: String,
    grants: Vec<ManagedPolicyGrantRecord>,
    resources: Vec<agent_access_core::ResourceDefinition>,
    resource_groups: Vec<agent_access_core::ResourceGroupDefinition>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct PolicyValidationResponse {
    valid: bool,
    errors: Vec<PolicyValidationMessage>,
    warnings: Vec<PolicyValidationMessage>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct PolicyValidationMessage {
    field: String,
    code: String,
    message: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct PolicyGrantCreateBody {
    grant_id: Option<String>,
    subjects: Vec<String>,
    execution_contexts: Vec<String>,
    service: String,
    actions: Vec<String>,
    resources: ResourceSelection,
    credential_mode: String,
    priority: Option<i32>,
    status: Option<String>,
    description: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct PolicyGrantPatchBody {
    expected_version: Option<i64>,
    subjects: Option<Vec<String>>,
    #[serde(default, deserialize_with = "deserialize_nullable_string_list_patch")]
    execution_contexts: Option<Option<Vec<String>>>,
    service: Option<String>,
    actions: Option<Vec<String>>,
    #[serde(default, deserialize_with = "deserialize_resource_selection_patch")]
    resources: Option<ResourceSelection>,
    credential_mode: Option<String>,
    #[serde(default, deserialize_with = "deserialize_nullable_i32_patch")]
    priority: Option<Option<i32>>,
    status: Option<String>,
    #[serde(default, deserialize_with = "deserialize_nullable_string_patch")]
    description: Option<Option<String>>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct PolicyGrantStatusBody {
    expected_version: Option<i64>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct PolicyGrantSubjectAddBody {
    expected_version: Option<i64>,
    subject: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct PolicyGrantSubjectRemoveBody {
    expected_version: Option<i64>,
    subject: String,
    #[serde(default = "default_last_subject_behavior")]
    last_subject_behavior: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct PolicyGrantValidateBody {
    grant_id: Option<String>,
    expected_version: Option<i64>,
    subjects: Option<Vec<String>>,
    #[serde(default, deserialize_with = "deserialize_nullable_string_list_patch")]
    execution_contexts: Option<Option<Vec<String>>>,
    service: Option<String>,
    actions: Option<Vec<String>>,
    #[serde(default, deserialize_with = "deserialize_resource_selection_patch")]
    resources: Option<ResourceSelection>,
    credential_mode: Option<String>,
    #[serde(default, deserialize_with = "deserialize_nullable_i32_patch")]
    priority: Option<Option<i32>>,
    status: Option<String>,
    #[serde(default, deserialize_with = "deserialize_nullable_string_patch")]
    description: Option<Option<String>>,
}

#[derive(Debug, Default)]
struct PolicyGrantListQuery {
    subject: Option<String>,
    service: Option<String>,
    execution_context: Option<String>,
    status: Option<String>,
}

fn configured_policy_services(
    context: &crate::handlers::management::common::ManagementContext,
) -> BTreeSet<String> {
    context
        .snapshot
        .runtime
        .configured_service_capabilities()
        .into_iter()
        .map(|capabilities| capabilities.service)
        .collect()
}

pub(super) fn policy_management_scope(
    context: &crate::handlers::management::common::ManagementContext,
) -> &PolicyReadScope {
    context
        .policy_management_scope
        .as_ref()
        .expect("policy management routes resolve a policy management scope")
}

pub(super) fn policy_write_scope(
    context: &crate::handlers::management::common::ManagementContext,
) -> &PolicyWriteScope {
    context
        .policy_write_scope
        .as_ref()
        .expect("write routes resolve a policy write scope")
}

pub(super) fn proposed_service_authorized(
    context: &crate::handlers::management::common::ManagementContext,
    service: &str,
) -> bool {
    match policy_management_scope(context) {
        PolicyReadScope::Global => true,
        scope => scope.authorizes_service(service),
    }
}

fn service_policy_management_assignment_view(
    assignment: ServicePolicyManagementAssignmentRecord,
    configured_services: &BTreeSet<String>,
) -> ServicePolicyManagementAssignmentView {
    ServicePolicyManagementAssignmentView {
        service_configured: configured_services.contains(&assignment.service),
        assignment_id: assignment.assignment_id,
        service: assignment.service,
        principal_id: assignment.principal_id,
        display_name: assignment.display_name,
        principal_status: assignment.principal_status,
        created_at: assignment.created_at,
        created_by: assignment.created_by,
    }
}

fn service_manager_list_query(raw_query: Option<&str>) -> Result<Option<String>, String> {
    let Some(raw_query) = raw_query else {
        return Ok(None);
    };
    let mut service = None;
    for (key, value) in form_urlencoded::parse(raw_query.as_bytes()) {
        match key.as_ref() {
            "service" if service.is_none() => service = Some(value.into_owned()),
            "service" => return Err("service query parameter is duplicated".to_string()),
            _ => return Err(format!("query parameter {key} is not supported")),
        }
    }
    Ok(service)
}

pub(super) fn deserialize_nullable_string_patch<'de, D>(
    deserializer: D,
) -> Result<Option<Option<String>>, D::Error>
where
    D: Deserializer<'de>,
{
    Option::<String>::deserialize(deserializer).map(Some)
}

fn deserialize_resource_selection_patch<'de, D>(
    deserializer: D,
) -> Result<Option<ResourceSelection>, D::Error>
where
    D: Deserializer<'de>,
{
    ResourceSelection::deserialize(deserializer).map(Some)
}

fn deserialize_nullable_i32_patch<'de, D>(deserializer: D) -> Result<Option<Option<i32>>, D::Error>
where
    D: Deserializer<'de>,
{
    Option::<i32>::deserialize(deserializer).map(Some)
}

fn deserialize_nullable_string_list_patch<'de, D>(
    deserializer: D,
) -> Result<Option<Option<Vec<String>>>, D::Error>
where
    D: Deserializer<'de>,
{
    Option::<Vec<String>>::deserialize(deserializer).map(Some)
}

fn default_last_subject_behavior() -> String {
    "reject".to_string()
}

pub(super) async fn parse_policy_json_body<T>(
    context: &crate::handlers::management::common::ManagementContext,
    operation: &str,
    body: Bytes,
) -> Result<T, Box<Response>>
where
    T: DeserializeOwned,
{
    match serde_json::from_slice(&body) {
        Ok(body) => Ok(body),
        Err(error) => Err(Box::new(
            management_context_error_response(
                context,
                StatusCode::BAD_REQUEST,
                operation,
                ReasonCode::InputInvalid,
                &format!("request body is not valid JSON: {error}"),
                None,
            )
            .await,
        )),
    }
}

async fn parse_optional_policy_json_body<T>(
    context: &crate::handlers::management::common::ManagementContext,
    operation: &str,
    body: Bytes,
) -> Result<Option<T>, Box<Response>>
where
    T: DeserializeOwned,
{
    if body.iter().all(|byte| byte.is_ascii_whitespace()) {
        return Ok(None);
    }
    parse_policy_json_body(context, operation, body)
        .await
        .map(Some)
}

pub(crate) async fn admin_policy_status(
    State(state): State<AppState>,
    ConnectInfo(remote_addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let operation = "admin.policy.status";
    let context = match management_context(
        &state,
        remote_addr,
        &headers,
        operation,
        ManagementAccess::PolicyRead,
    )
    .await
    {
        Ok(context) => context,
        Err(response) => return *response,
    };
    let config = context.snapshot.runtime.config();
    if config.policy.authority == "managed" {
        let result = management_store_call(&context, |store| {
            let revision = store.policy_revision()?;
            let grants = store.policy_grants()?;
            Ok((revision, grants))
        })
        .await;
        return match result {
            Ok((revision, grants)) => {
                let response = policy_status_response(
                    config,
                    &context.snapshot,
                    policy_management_scope(&context),
                    Some(revision),
                    Some(&grants),
                );
                management_success_response(&context, operation, None, json!(response)).await
            }
            Err(error) => management_store_error_response(&context, operation, None, error).await,
        };
    }
    let response = policy_status_response(
        config,
        &context.snapshot,
        policy_management_scope(&context),
        None,
        None,
    );
    management_success_response(&context, operation, None, json!(response)).await
}

pub(crate) async fn admin_policy_catalog(
    State(state): State<AppState>,
    ConnectInfo(remote_addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let operation = "admin.policy.catalog";
    let context = match management_context(
        &state,
        remote_addr,
        &headers,
        operation,
        ManagementAccess::PolicyRead,
    )
    .await
    {
        Ok(context) => context,
        Err(response) => return *response,
    };
    let subjects = match policy_catalog_subjects(&context).await {
        Ok(subjects) => subjects,
        Err(error) => {
            return management_store_error_response(&context, operation, None, error).await;
        }
    };
    let services = context
        .snapshot
        .runtime
        .configured_service_capabilities()
        .into_iter()
        .filter(|capabilities| {
            policy_management_scope(&context).authorizes_service(&capabilities.service)
        })
        .map(|capabilities| {
            let descriptor = context
                .snapshot
                .runtime
                .service_descriptor(&capabilities.service);
            let runtime = &context.snapshot.runtime;
            let mut catalog = service_catalog(
                runtime.effective_credentials(),
                capabilities,
                descriptor
                    .as_ref()
                    .map(|descriptor| &descriptor.credentials),
            );
            if runtime
                .imported_catalog()
                .service(&catalog.service)
                .is_some()
            {
                for action in &mut catalog.actions {
                    action.resources_checked_by =
                        runtime.resources_checked_by(&catalog.service, &action.action);
                    action.available = runtime
                        .imported_action_available(&catalog.service, &action.action)
                        && !catalog.configured_credential_modes.is_empty();
                    if !action.available {
                        action.unavailable_reason = Some(
                            "Imported action is unavailable; retained grants can be maintained."
                                .into(),
                        );
                    }
                }
                catalog.available = catalog.actions.iter().any(|action| action.available);
                if !catalog.available {
                    catalog.unavailable_reason = runtime
                        .imported_service_unavailable_reason(&catalog.service)
                        .map(str::to_owned);
                }
            }
            catalog
        })
        .collect::<Vec<_>>();
    let execution_contexts = policy_execution_context_catalog(context.snapshot.runtime.config());
    let catalog = context
        .snapshot
        .runtime
        .policy_resource_catalog_for_scope(policy_management_scope(&context));
    management_success_response(
        &context,
        operation,
        None,
        json!(PolicyCatalogResponse {
            services,
            subjects,
            execution_contexts,
            resources: catalog.resources,
            resource_groups: catalog.resource_groups,
        }),
    )
    .await
}

pub(crate) async fn admin_policy_grants_list(
    State(state): State<AppState>,
    RawQuery(raw_query): RawQuery,
    ConnectInfo(remote_addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let operation = "admin.policy.grants.list";
    let context = match management_context(
        &state,
        remote_addr,
        &headers,
        operation,
        ManagementAccess::PolicyRead,
    )
    .await
    {
        Ok(context) => context,
        Err(response) => return *response,
    };
    let query = match policy_grant_list_query(raw_query.as_deref()) {
        Ok(query) => query,
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
    let grants = if context.snapshot.runtime.config().policy.authority == "managed" {
        match management_store_call(&context, |store| store.policy_grants()).await {
            Ok(grants) => grants
                .into_iter()
                .map(managed_policy_grant_view)
                .collect::<Vec<_>>(),
            Err(error) => {
                return management_store_error_response(&context, operation, None, error).await;
            }
        }
    } else {
        toml_policy_grant_views(context.snapshot.runtime.config())
    };
    let grants = grants
        .into_iter()
        .filter(|grant| {
            if !policy_management_scope(&context).authorizes_service(&grant.service) {
                return false;
            }
            if query.status.is_none() && grant.status == "deleted" {
                return false;
            }
            policy_grant_matches_query(grant, &query)
        })
        .collect::<Vec<_>>();
    management_success_response(&context, operation, None, json!(grants)).await
}

pub(crate) async fn admin_policy_service_managers_list(
    State(state): State<AppState>,
    RawQuery(raw_query): RawQuery,
    ConnectInfo(remote_addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let operation = "admin.policy.service_managers.list";
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
    if context.snapshot.runtime.config().identity.authority != "managed"
        || context.snapshot.runtime.config().policy.authority != "managed"
    {
        return management_context_error_response(
            &context,
            StatusCode::BAD_REQUEST,
            operation,
            ReasonCode::InputInvalid,
            "service policy managers require managed identity and policy authority",
            None,
        )
        .await;
    }
    let service = match service_manager_list_query(raw_query.as_deref()) {
        Ok(service) => service,
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
    let service_for_store = service.clone();
    let assignments = match management_store_call(&context, move |store| {
        store.service_policy_management_assignments(service_for_store.as_deref())
    })
    .await
    {
        Ok(assignments) => assignments,
        Err(error) => {
            return management_store_error_response(&context, operation, None, error).await;
        }
    };
    let configured_services = configured_policy_services(&context);
    let assignments = assignments
        .into_iter()
        .map(|assignment| {
            service_policy_management_assignment_view(assignment, &configured_services)
        })
        .collect::<Vec<_>>();
    management_success_response(&context, operation, None, json!(assignments)).await
}

pub(crate) async fn admin_policy_service_manager_grant(
    State(state): State<AppState>,
    Path((service, principal_id)): Path<(String, String)>,
    ConnectInfo(remote_addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let operation = crate::handlers::management::audit_actions::ADMIN_POLICY_SERVICE_MANAGERS_GRANT;
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
        "service": service,
        "principalId": principal_id,
    }));
    if let Err(response) =
        management_write_audit_preflight(&context, operation, target.clone()).await
    {
        return *response;
    }
    if context.snapshot.runtime.config().identity.authority != "managed"
        || context.snapshot.runtime.config().policy.authority != "managed"
    {
        return management_context_error_response(
            &context,
            StatusCode::BAD_REQUEST,
            operation,
            ReasonCode::InputInvalid,
            "service policy managers require managed identity and policy authority",
            target,
        )
        .await;
    }
    let configured_services = configured_policy_services(&context);
    if !configured_services.contains(&service) {
        return management_context_error_response(
            &context,
            StatusCode::BAD_REQUEST,
            operation,
            ReasonCode::InputInvalid,
            "service is not configured",
            target,
        )
        .await;
    }
    let actor = context.identity.principal.clone();
    let request = ServicePolicyManagementAssignmentPutRequest {
        service,
        principal_id,
        created_by: actor,
    };
    match management_store_call(&context, move |store| {
        store.put_service_policy_management_assignment(request)
    })
    .await
    {
        Ok(assignment) => management_pre_audited_success_response(
            &context,
            operation,
            target,
            json!(service_policy_management_assignment_view(
                assignment,
                &configured_services,
            )),
        ),
        Err(error) => management_store_error_response(&context, operation, target, error).await,
    }
}

pub(crate) async fn admin_policy_service_manager_revoke(
    State(state): State<AppState>,
    Path((service, principal_id)): Path<(String, String)>,
    ConnectInfo(remote_addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let operation =
        crate::handlers::management::audit_actions::ADMIN_POLICY_SERVICE_MANAGERS_REVOKE;
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
        "service": service,
        "principalId": principal_id,
    }));
    if let Err(response) =
        management_write_audit_preflight(&context, operation, target.clone()).await
    {
        return *response;
    }
    if context.snapshot.runtime.config().identity.authority != "managed"
        || context.snapshot.runtime.config().policy.authority != "managed"
    {
        return management_context_error_response(
            &context,
            StatusCode::BAD_REQUEST,
            operation,
            ReasonCode::InputInvalid,
            "service policy managers require managed identity and policy authority",
            target,
        )
        .await;
    }
    match management_store_call(&context, move |store| {
        store.delete_service_policy_management_assignment(&service, &principal_id)
    })
    .await
    {
        Ok(removed) => management_pre_audited_success_response(
            &context,
            operation,
            target,
            json!(ServicePolicyManagementAssignmentDeleteResponse { removed }),
        ),
        Err(error) => management_store_error_response(&context, operation, target, error).await,
    }
}

pub(crate) async fn admin_policy_grants_export(
    State(state): State<AppState>,
    ConnectInfo(remote_addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let operation = "admin.policy.grants.export";
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
    if context.snapshot.runtime.config().policy.authority != "managed" {
        return policy_authority_unavailable(&context, operation, None).await;
    }
    match management_store_call(&context, |store| store.load_policy_export()).await {
        Ok(export) => {
            let response = PolicyExportResponse {
                policy_authority: "managed".to_string(),
                policy_generation: export.revision.generation,
                exported_at: chrono::Utc::now().to_rfc3339(),
                grants: export.grants,
                resources: export.catalog.resources,
                resource_groups: export.catalog.resource_groups,
            };
            management_success_response(&context, operation, None, json!(response)).await
        }
        Err(error) => management_store_error_response(&context, operation, None, error).await,
    }
}

pub(crate) async fn admin_policy_grants_get(
    State(state): State<AppState>,
    Path(grant_ref): Path<String>,
    ConnectInfo(remote_addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let operation = crate::handlers::management::audit_actions::ADMIN_POLICY_GRANTS_INSPECT;
    let context = match management_context(
        &state,
        remote_addr,
        &headers,
        operation,
        ManagementAccess::PolicyRead,
    )
    .await
    {
        Ok(context) => context,
        Err(response) => return *response,
    };
    let target = Some(json!({"grantRef": grant_ref}));
    if let Some(index) = parse_toml_grant_ref(&grant_ref) {
        let grants = toml_policy_grant_views(context.snapshot.runtime.config());
        if let Some(grant) = grants.into_iter().find(|grant| {
            grant.index == Some(index)
                && policy_management_scope(&context).authorizes_service(&grant.service)
        }) {
            return management_success_response(&context, operation, target, json!(grant)).await;
        }
        return policy_grant_not_found(&context, operation, target).await;
    }
    if context.snapshot.runtime.config().policy.authority != "managed" {
        return policy_grant_not_found(&context, operation, target).await;
    }
    match management_store_call(&context, move |store| store.policy_grant(&grant_ref)).await {
        Ok(grant) if policy_management_scope(&context).authorizes_service(&grant.service) => {
            management_success_response(
                &context,
                operation,
                target,
                json!(managed_policy_grant_view(grant)),
            )
            .await
        }
        Ok(_) => policy_grant_not_found(&context, operation, target).await,
        Err(error) => management_store_error_response(&context, operation, target, error).await,
    }
}

pub(crate) async fn admin_policy_grants_create(
    State(state): State<AppState>,
    ConnectInfo(remote_addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    body: Bytes,
) -> impl IntoResponse {
    let operation = crate::handlers::management::audit_actions::ADMIN_POLICY_GRANTS_CREATE;
    let context = match management_context(
        &state,
        remote_addr,
        &headers,
        operation,
        ManagementAccess::PolicyWrite,
    )
    .await
    {
        Ok(context) => context,
        Err(response) => return *response,
    };
    let body =
        match parse_policy_json_body::<PolicyGrantCreateBody>(&context, operation, body).await {
            Ok(body) => body,
            Err(response) => return *response,
        };
    let target = Some(json!({"subjects": body.subjects.clone(), "service": body.service.clone()}));
    if let Err(response) =
        management_write_audit_preflight(&context, operation, target.clone()).await
    {
        return *response;
    }
    if !policy_write_scope(&context).authorizes_service(&body.service) {
        return management_context_error_response(
            &context,
            StatusCode::FORBIDDEN,
            operation,
            ReasonCode::ManagementDenied,
            "service is not within the caller's policy management scope",
            target,
        )
        .await;
    }
    let actor = context.identity.principal.clone();
    let request = ManagedPolicyGrantCreateRequest {
        grant_id: body.grant_id,
        subjects: body.subjects,
        execution_contexts: body.execution_contexts,
        service: body.service,
        actions: body.actions,
        resources: body.resources,
        credential_mode: body.credential_mode,
        priority: body.priority,
        status: body.status,
        description: body.description,
        created_by: actor,
    };
    match state
        .reloadable
        .managed_policy_mutation_from_snapshot(context.snapshot.clone(), move |runtime| {
            runtime.create_managed_policy_grant(request)
        })
        .await
    {
        Ok(result) => {
            management_pre_audited_success_response(&context, operation, target, json!(result))
        }
        Err(error) => management_store_error_response(&context, operation, target, error).await,
    }
}

pub(crate) async fn admin_policy_grants_patch(
    State(state): State<AppState>,
    Path(grant_id): Path<String>,
    ConnectInfo(remote_addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    body: Bytes,
) -> impl IntoResponse {
    let operation = crate::handlers::management::audit_actions::ADMIN_POLICY_GRANTS_PATCH;
    let context = match management_context(
        &state,
        remote_addr,
        &headers,
        operation,
        ManagementAccess::PolicyWrite,
    )
    .await
    {
        Ok(context) => context,
        Err(response) => return *response,
    };
    let target = Some(json!({"grantRef": grant_id}));
    if context.snapshot.runtime.config().policy.authority != "managed"
        || parse_toml_grant_ref(&grant_id).is_some()
    {
        return policy_authority_unavailable(&context, operation, target).await;
    }
    let body = match parse_policy_json_body::<PolicyGrantPatchBody>(&context, operation, body).await
    {
        Ok(body) => body,
        Err(response) => return *response,
    };
    let execution_contexts = match body.execution_contexts {
        Some(Some(execution_contexts)) => Some(execution_contexts),
        Some(None) => {
            return management_context_error_response(
                &context,
                StatusCode::BAD_REQUEST,
                operation,
                ReasonCode::InputInvalid,
                "executionContexts must not be null",
                target,
            )
            .await;
        }
        None => None,
    };
    let expected_version = match required_expected_version(body.expected_version) {
        Ok(expected_version) => expected_version,
        Err(error) => {
            return management_store_error_response(&context, operation, target, error).await;
        }
    };
    if let Err(response) =
        management_write_audit_preflight(&context, operation, target.clone()).await
    {
        return *response;
    }
    let actor = context.identity.principal.clone();
    let scope = policy_write_scope(&context).clone();
    match state
        .reloadable
        .managed_policy_mutation_from_snapshot(context.snapshot.clone(), move |runtime| {
            runtime.patch_managed_policy_grant_authorized(
                ManagedPolicyGrantPatchRequest {
                    grant_id,
                    expected_version,
                    subjects: body.subjects,
                    execution_contexts,
                    service: body.service,
                    actions: body.actions,
                    resources: body.resources,
                    credential_mode: body.credential_mode,
                    priority: body.priority,
                    status: body.status,
                    description: body.description,
                    updated_by: actor,
                },
                &scope,
            )
        })
        .await
    {
        Ok(result) => {
            management_pre_audited_success_response(&context, operation, target, json!(result))
        }
        Err(error) => management_store_error_response(&context, operation, target, error).await,
    }
}

pub(crate) async fn admin_policy_grants_subject_add(
    State(state): State<AppState>,
    Path(grant_id): Path<String>,
    ConnectInfo(remote_addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    body: Bytes,
) -> impl IntoResponse {
    let operation = crate::handlers::management::audit_actions::ADMIN_POLICY_GRANTS_SUBJECTS_ADD;
    let context = match management_context(
        &state,
        remote_addr,
        &headers,
        operation,
        ManagementAccess::PolicyWrite,
    )
    .await
    {
        Ok(context) => context,
        Err(response) => return *response,
    };
    let base_target = Some(json!({"grantRef": grant_id.clone()}));
    if context.snapshot.runtime.config().policy.authority != "managed"
        || parse_toml_grant_ref(&grant_id).is_some()
    {
        return policy_authority_unavailable(&context, operation, base_target).await;
    }
    let body = match parse_policy_json_body::<PolicyGrantSubjectAddBody>(&context, operation, body)
        .await
    {
        Ok(body) => body,
        Err(response) => return *response,
    };
    let target = Some(json!({"grantRef": grant_id.clone(), "subject": body.subject.clone()}));
    let expected_version = match required_expected_version(body.expected_version) {
        Ok(expected_version) => expected_version,
        Err(error) => {
            return management_store_error_response(&context, operation, target, error).await;
        }
    };
    if let Err(response) =
        management_write_audit_preflight(&context, operation, target.clone()).await
    {
        return *response;
    }
    let actor = context.identity.principal.clone();
    let scope = policy_write_scope(&context).clone();
    match state
        .reloadable
        .managed_policy_mutation_from_snapshot(context.snapshot.clone(), move |runtime| {
            runtime.add_managed_policy_grant_subject_authorized(
                ManagedPolicyGrantSubjectAddRequest {
                    grant_id,
                    expected_version,
                    subject: body.subject,
                    updated_by: actor,
                },
                &scope,
            )
        })
        .await
    {
        Ok(result) => {
            management_pre_audited_success_response(&context, operation, target, json!(result))
        }
        Err(error) => management_store_error_response(&context, operation, target, error).await,
    }
}

pub(crate) async fn admin_policy_grants_subject_remove(
    State(state): State<AppState>,
    Path(grant_id): Path<String>,
    ConnectInfo(remote_addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    body: Bytes,
) -> impl IntoResponse {
    let operation = crate::handlers::management::audit_actions::ADMIN_POLICY_GRANTS_SUBJECTS_REMOVE;
    let context = match management_context(
        &state,
        remote_addr,
        &headers,
        operation,
        ManagementAccess::PolicyWrite,
    )
    .await
    {
        Ok(context) => context,
        Err(response) => return *response,
    };
    let base_target = Some(json!({"grantRef": grant_id.clone()}));
    if context.snapshot.runtime.config().policy.authority != "managed"
        || parse_toml_grant_ref(&grant_id).is_some()
    {
        return policy_authority_unavailable(&context, operation, base_target).await;
    }
    let body =
        match parse_policy_json_body::<PolicyGrantSubjectRemoveBody>(&context, operation, body)
            .await
        {
            Ok(body) => body,
            Err(response) => return *response,
        };
    let target = Some(json!({
        "grantRef": grant_id.clone(),
        "subject": body.subject.clone(),
        "lastSubjectBehavior": body.last_subject_behavior.clone()
    }));
    let expected_version = match required_expected_version(body.expected_version) {
        Ok(expected_version) => expected_version,
        Err(error) => {
            return management_store_error_response(&context, operation, target, error).await;
        }
    };
    if let Err(response) =
        management_write_audit_preflight(&context, operation, target.clone()).await
    {
        return *response;
    }
    let actor = context.identity.principal.clone();
    let scope = policy_write_scope(&context).clone();
    match state
        .reloadable
        .managed_policy_mutation_from_snapshot(context.snapshot.clone(), move |runtime| {
            runtime.remove_managed_policy_grant_subject_authorized(
                ManagedPolicyGrantSubjectRemoveRequest {
                    grant_id,
                    expected_version,
                    subject: body.subject,
                    last_subject_behavior: body.last_subject_behavior,
                    updated_by: actor,
                },
                &scope,
            )
        })
        .await
    {
        Ok(result) => {
            management_pre_audited_success_response(&context, operation, target, json!(result))
        }
        Err(error) => management_store_error_response(&context, operation, target, error).await,
    }
}

pub(crate) async fn admin_policy_grants_enable(
    State(state): State<AppState>,
    Path(grant_id): Path<String>,
    ConnectInfo(remote_addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    body: Bytes,
) -> impl IntoResponse {
    policy_grant_status_change(state, remote_addr, headers, grant_id, body, "enable").await
}

pub(crate) async fn admin_policy_grants_disable(
    State(state): State<AppState>,
    Path(grant_id): Path<String>,
    ConnectInfo(remote_addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    body: Bytes,
) -> impl IntoResponse {
    policy_grant_status_change(state, remote_addr, headers, grant_id, body, "disable").await
}

pub(crate) async fn admin_policy_grants_delete(
    State(state): State<AppState>,
    Path(grant_id): Path<String>,
    RawQuery(raw_query): RawQuery,
    ConnectInfo(remote_addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let operation = crate::handlers::management::audit_actions::ADMIN_POLICY_GRANTS_DELETE;
    let context = match management_context(
        &state,
        remote_addr,
        &headers,
        operation,
        ManagementAccess::PolicyWrite,
    )
    .await
    {
        Ok(context) => context,
        Err(response) => return *response,
    };
    let target = Some(json!({"grantRef": grant_id}));
    if context.snapshot.runtime.config().policy.authority != "managed"
        || parse_toml_grant_ref(&grant_id).is_some()
    {
        return policy_authority_unavailable(&context, operation, target).await;
    }
    let expected_version = match expected_version_query(raw_query.as_deref()) {
        Ok(version) => version,
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
    let expected_version = match required_expected_version(expected_version) {
        Ok(expected_version) => expected_version,
        Err(error) => {
            return management_store_error_response(&context, operation, target, error).await;
        }
    };
    if let Err(response) =
        management_write_audit_preflight(&context, operation, target.clone()).await
    {
        return *response;
    }
    let actor = context.identity.principal.clone();
    let scope = policy_write_scope(&context).clone();
    match state
        .reloadable
        .managed_policy_mutation_from_snapshot(context.snapshot.clone(), move |runtime| {
            runtime.delete_managed_policy_grant_authorized(
                ManagedPolicyGrantStatusRequest {
                    grant_id,
                    expected_version,
                    updated_by: actor,
                },
                &scope,
            )
        })
        .await
    {
        Ok(result) => {
            management_pre_audited_success_response(&context, operation, target, json!(result))
        }
        Err(error) => management_store_error_response(&context, operation, target, error).await,
    }
}

pub(crate) async fn admin_policy_grants_validate(
    State(state): State<AppState>,
    ConnectInfo(remote_addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    body: Bytes,
) -> impl IntoResponse {
    let operation = crate::handlers::management::audit_actions::ADMIN_POLICY_GRANTS_VALIDATE;
    let context = match management_context(
        &state,
        remote_addr,
        &headers,
        operation,
        ManagementAccess::PolicyRead,
    )
    .await
    {
        Ok(context) => context,
        Err(response) => return *response,
    };
    let body =
        match parse_policy_json_body::<PolicyGrantValidateBody>(&context, operation, body).await {
            Ok(body) => body,
            Err(response) => return *response,
        };
    let validate_create_with_explicit_grant_id =
        body.grant_id.is_some() && body.expected_version.is_none();
    let validate_patch = body.grant_id.is_some() && body.expected_version.is_some();
    let validation_grant_ref = body.grant_id.clone();
    if !validate_patch
        && let Some(service) = body.service.as_deref()
        && !proposed_service_authorized(&context, service)
    {
        return management_context_error_response(
            &context,
            StatusCode::FORBIDDEN,
            operation,
            ReasonCode::ManagementDenied,
            "service is not within the caller's policy management scope",
            None,
        )
        .await;
    }
    let execution_contexts = match body.execution_contexts {
        Some(Some(execution_contexts)) => Some(execution_contexts),
        Some(None) => {
            let response = PolicyValidationResponse {
                valid: false,
                errors: vec![PolicyValidationMessage {
                    field: "executionContexts".to_string(),
                    code: "null".to_string(),
                    message: "executionContexts must not be null".to_string(),
                }],
                warnings: vec![],
            };
            return management_success_response(&context, operation, None, json!(response)).await;
        }
        None => None,
    };
    let actor = context.identity.principal.clone();
    let runtime = context.snapshot.runtime.clone();
    let scope = policy_management_scope(&context).clone();
    let result = tokio::task::spawn_blocking(move || {
        if let Some(grant_id) = body.grant_id {
            if let Some(expected_version) = body.expected_version {
                runtime.validate_managed_policy_grant_patch_authorized(
                    ManagedPolicyGrantPatchRequest {
                        grant_id,
                        expected_version,
                        subjects: body.subjects,
                        execution_contexts,
                        service: body.service,
                        actions: body.actions,
                        resources: body.resources,
                        credential_mode: body.credential_mode,
                        priority: body.priority,
                        status: body.status,
                        description: body.description,
                        updated_by: actor,
                    },
                    &scope,
                )
            } else {
                runtime.validate_managed_policy_grant_create(ManagedPolicyGrantCreateRequest {
                    grant_id: Some(grant_id),
                    subjects: required_validate_field(body.subjects, "subjects")?,
                    execution_contexts: required_validate_field(
                        execution_contexts,
                        "executionContexts",
                    )?,
                    service: required_validate_field(body.service, "service")?,
                    actions: required_validate_field(body.actions, "actions")?,
                    resources: required_validate_field(body.resources, "resources")?,
                    credential_mode: required_validate_field(
                        body.credential_mode,
                        "credentialMode",
                    )?,
                    priority: body.priority.flatten(),
                    status: body.status,
                    description: body.description.flatten(),
                    created_by: actor,
                })
            }
        } else {
            runtime.validate_managed_policy_grant_create(ManagedPolicyGrantCreateRequest {
                grant_id: None,
                subjects: required_validate_field(body.subjects, "subjects")?,
                execution_contexts: required_validate_field(
                    execution_contexts,
                    "executionContexts",
                )?,
                service: required_validate_field(body.service, "service")?,
                actions: required_validate_field(body.actions, "actions")?,
                resources: required_validate_field(body.resources, "resources")?,
                credential_mode: required_validate_field(body.credential_mode, "credentialMode")?,
                priority: body.priority.flatten(),
                status: body.status,
                description: body.description.flatten(),
                created_by: actor,
            })
        }
    })
    .await
    .map_err(|error| {
        ManagedStoreError::Unavailable(format!("managed policy validation task failed: {error}"))
    })
    .and_then(|result| result);
    let response = match result {
        Ok(()) => PolicyValidationResponse {
            valid: true,
            errors: vec![],
            warnings: vec![],
        },
        Err(error)
            if validate_patch
                && matches!(
                    error,
                    ManagedStoreError::PolicyGrantNotFound
                        | ManagedStoreError::PolicyManagementServiceMoveDenied
                ) =>
        {
            return management_store_error_response(
                &context,
                operation,
                validation_grant_ref.map(|grant_ref| json!({"grantRef": grant_ref})),
                error,
            )
            .await;
        }
        Err(error) if candidate_validation_error(&error) => {
            if matches!(error, ManagedStoreError::PolicyAuthorityUnavailable(_)) {
                tracing::warn!(operation, request_id = %context.request_id,
                    broker_request_id = %context.broker_request_id, error = %error,
                    "management policy authority is unavailable");
            }
            PolicyValidationResponse {
                valid: false,
                errors: if validate_create_with_explicit_grant_id
                    && matches!(error, ManagedStoreError::VersionConflict)
                {
                    vec![PolicyValidationMessage {
                        field: "grantId".to_string(),
                        code: "grant_id_duplicate".to_string(),
                        message: error.to_string(),
                    }]
                } else {
                    policy_validation_messages(&error)
                },
                warnings: vec![],
            }
        }
        Err(error) => {
            return management_store_error_response(&context, operation, None, error).await;
        }
    };
    management_success_response(&context, operation, None, json!(response)).await
}

async fn policy_grant_status_change(
    state: AppState,
    remote_addr: SocketAddr,
    headers: HeaderMap,
    grant_id: String,
    body: Bytes,
    change: &'static str,
) -> axum::response::Response {
    let operation = match change {
        "enable" => crate::handlers::management::audit_actions::ADMIN_POLICY_GRANTS_ENABLE,
        "disable" => crate::handlers::management::audit_actions::ADMIN_POLICY_GRANTS_DISABLE,
        _ => unreachable!("unsupported policy status operation"),
    };
    let context = match management_context(
        &state,
        remote_addr,
        &headers,
        operation,
        ManagementAccess::PolicyWrite,
    )
    .await
    {
        Ok(context) => context,
        Err(response) => return *response,
    };
    let target = Some(json!({"grantRef": grant_id}));
    if context.snapshot.runtime.config().policy.authority != "managed"
        || parse_toml_grant_ref(&grant_id).is_some()
    {
        return policy_authority_unavailable(&context, operation, target).await;
    }
    let body =
        match parse_optional_policy_json_body::<PolicyGrantStatusBody>(&context, operation, body)
            .await
        {
            Ok(body) => body,
            Err(response) => return *response,
        };
    let expected_version =
        match required_expected_version(body.and_then(|body| body.expected_version)) {
            Ok(expected_version) => expected_version,
            Err(error) => {
                return management_store_error_response(&context, operation, target, error).await;
            }
        };
    if let Err(response) =
        management_write_audit_preflight(&context, operation, target.clone()).await
    {
        return *response;
    }
    let actor = context.identity.principal.clone();
    let scope = policy_write_scope(&context).clone();
    let result = state
        .reloadable
        .managed_policy_mutation_from_snapshot(context.snapshot.clone(), move |runtime| {
            let request = ManagedPolicyGrantStatusRequest {
                grant_id,
                expected_version,
                updated_by: actor,
            };
            match change {
                "enable" => runtime.enable_managed_policy_grant_authorized(request, &scope),
                "disable" => runtime.disable_managed_policy_grant_authorized(request, &scope),
                _ => unreachable!("unsupported policy status operation"),
            }
        })
        .await;
    match result {
        Ok(result) => {
            management_pre_audited_success_response(&context, operation, target, json!(result))
        }
        Err(error) => management_store_error_response(&context, operation, target, error).await,
    }
}

fn policy_status_response(
    config: &BrokerConfig,
    context: &crate::state::RuntimeSnapshot,
    management_scope: &PolicyReadScope,
    revision: Option<ManagedPolicyRevision>,
    managed_grants: Option<&[ManagedPolicyGrantRecord]>,
) -> PolicyStatusResponse {
    let counts = match managed_grants {
        Some(grants) => managed_policy_grant_counts(
            &grants
                .iter()
                .filter(|grant| management_scope.authorizes_service(&grant.service))
                .cloned()
                .collect::<Vec<_>>(),
        ),
        None => PolicyGrantCounts {
            active: config.policy.grants.len() as u64,
            disabled: 0,
            deleted: 0,
        },
    };
    let (last_updated_at, last_updated_by) = if matches!(management_scope, PolicyReadScope::Global)
    {
        revision
            .map(|revision| (Some(revision.updated_at), Some(revision.updated_by)))
            .unwrap_or((None, None))
    } else {
        (None, None)
    };
    PolicyStatusResponse {
        identity_authority: config.identity.authority.clone(),
        policy_authority: config.policy.authority.clone(),
        writable: config.identity.authority == "managed" && config.policy.authority == "managed",
        default_decision: config.policy.default_decision.clone(),
        config_generation: context.generation,
        policy_generation: context.runtime.policy_generation(),
        counts,
        management_scope: management_scope.clone(),
        last_updated_at,
        last_updated_by,
    }
}

fn managed_policy_grant_counts(grants: &[ManagedPolicyGrantRecord]) -> PolicyGrantCounts {
    let mut counts = PolicyGrantCounts::default();
    for grant in grants {
        match grant.status.as_str() {
            "active" => counts.active += 1,
            "disabled" => counts.disabled += 1,
            "deleted" => counts.deleted += 1,
            _ => {}
        }
    }
    counts
}

async fn policy_catalog_subjects(
    context: &crate::handlers::management::common::ManagementContext,
) -> Result<PolicySubjectCatalogResponse, ManagedStoreError> {
    if context.snapshot.runtime.config().identity.authority == "managed" {
        let (principals, groups) = management_store_call(context, |store| {
            Ok((store.list_principals()?, store.list_groups()?))
        })
        .await?;
        return Ok(PolicySubjectCatalogResponse {
            users: principals
                .into_iter()
                .map(|principal| PolicyCatalogPrincipal {
                    principal_id: principal.principal_id,
                    display_name: principal.display_name,
                    status: principal.status,
                })
                .collect(),
            groups: groups
                .into_iter()
                .map(|group| PolicyCatalogGroup {
                    group_id: group.group_id,
                    display_name: group.display_name,
                    status: group.status,
                })
                .collect(),
            anonymous: true,
        });
    }
    let config = context.snapshot.runtime.config();
    let mut principals = config
        .identity
        .sources
        .iter()
        .flat_map(|source| {
            source
                .principals
                .iter()
                .map(|principal| &principal.principal)
        })
        .cloned()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .map(|principal_id| PolicyCatalogPrincipal {
            principal_id,
            display_name: None,
            status: "active".to_string(),
        })
        .collect::<Vec<_>>();
    let mut groups = config
        .identity
        .groups
        .iter()
        .map(|group| PolicyCatalogGroup {
            group_id: group.id.clone(),
            display_name: None,
            status: group.status.clone(),
        })
        .collect::<Vec<_>>();
    principals.sort_by(|left, right| left.principal_id.cmp(&right.principal_id));
    groups.sort_by(|left, right| left.group_id.cmp(&right.group_id));
    Ok(PolicySubjectCatalogResponse {
        users: principals,
        groups,
        anonymous: true,
    })
}

pub(crate) fn service_catalog(
    configured_credentials: &agent_access_core::CredentialsConfig,
    capabilities: ServiceCapabilities,
    credentials: Option<&CredentialDescriptor>,
) -> PolicyServiceCatalog {
    let configured_credential_modes = configured_credential_modes(
        configured_credentials,
        &capabilities.service,
        &capabilities.actions,
        credentials,
    );
    let actions = capabilities
        .actions
        .into_iter()
        .map(action_catalog)
        .collect();
    let resource_scopes = capabilities
        .resource_scopes
        .into_iter()
        .map(|(scope, capabilities)| (scope.clone(), scope_catalog(&scope, capabilities)))
        .collect();
    PolicyServiceCatalog {
        available: true,
        unavailable_reason: None,
        service: capabilities.service.clone(),
        display_name: capabilities.display_name,
        surface: capabilities.surface,
        gateway_kind: capabilities.gateway_kind,
        broker_hosts: capabilities.broker_hosts,
        credential_verification_inputs: capabilities.credential_verification_inputs,
        actions,
        resource_scopes,
        configured_credential_modes,
        lookup_credential_configured: configured_credentials
            .lookup
            .contains_key(&capabilities.service),
    }
}

fn action_catalog(action: ActionCapabilities) -> PolicyActionCatalog {
    PolicyActionCatalog {
        available: true,
        unavailable_reason: None,
        action: action.action,
        read_only: action.read_only,
        description: action.description,
        required_scope_types: action.required_scope_types,
        credential_modes: action.credential_modes,
        lookup_required: action.lookup_required,
        input_schema: action.input_schema,
        resources_checked_by: None,
    }
}

fn scope_catalog(_scope: &str, capabilities: ResourceScopeCapabilities) -> PolicyScopeCatalog {
    PolicyScopeCatalog {
        resource_type: capabilities.resource_type,
        selectors: capabilities.selectors,
    }
}

fn configured_credential_modes(
    configured_credentials: &agent_access_core::CredentialsConfig,
    service: &str,
    actions: &[ActionCapabilities],
    credentials: Option<&CredentialDescriptor>,
) -> Vec<String> {
    let action_modes = actions
        .iter()
        .flat_map(|action| action.credential_modes.iter())
        .cloned()
        .collect::<BTreeSet<_>>();
    ["service", "per_user"]
        .into_iter()
        .filter(|mode| {
            action_modes.contains(*mode)
                && agent_access_core::credential_mode_available(
                    configured_credentials,
                    service,
                    mode,
                    credentials,
                )
        })
        .map(str::to_string)
        .collect()
}

fn policy_execution_context_catalog(config: &BrokerConfig) -> PolicyExecutionContextCatalog {
    match &config.execution_context {
        Some(execution_context) => PolicyExecutionContextCatalog {
            allowed_values: execution_context.allowed_values.clone(),
            default_context: execution_context.default_context.clone(),
            context_required: execution_context.default_context.is_none(),
        },
        None => PolicyExecutionContextCatalog {
            allowed_values: vec![DEFAULT_EXECUTION_CONTEXT.to_string()],
            default_context: Some(DEFAULT_EXECUTION_CONTEXT.to_string()),
            context_required: false,
        },
    }
}

fn toml_policy_grant_views(config: &BrokerConfig) -> Vec<PolicyGrantView> {
    config
        .policy
        .grants
        .iter()
        .enumerate()
        .map(|(index, grant)| toml_policy_grant_view(index, grant))
        .collect()
}

fn toml_policy_grant_view(index: usize, grant: &PolicyGrantConfig) -> PolicyGrantView {
    PolicyGrantView {
        grant_ref: format!("toml:{index}"),
        writable: false,
        grant_id: None,
        index: Some(index),
        grant_order: Some(i64::try_from(index).unwrap_or(i64::MAX)),
        subjects: grant.subjects.clone(),
        execution_contexts: grant
            .execution_contexts
            .clone()
            .unwrap_or_else(|| vec![DEFAULT_EXECUTION_CONTEXT.to_string()]),
        service: grant.service.clone(),
        actions: grant.actions.clone(),
        resources: grant.resources.clone(),
        credential_mode: grant.credential_mode.clone(),
        priority: grant.priority,
        status: "active".to_string(),
        description: None,
        version: None,
        created_at: None,
        created_by: None,
        updated_at: None,
        updated_by: None,
        disabled_at: None,
        deleted_at: None,
    }
}

fn managed_policy_grant_view(grant: ManagedPolicyGrantRecord) -> PolicyGrantView {
    let writable = grant.status != "deleted";
    PolicyGrantView {
        grant_ref: grant.grant_id.clone(),
        writable,
        grant_id: Some(grant.grant_id),
        index: None,
        grant_order: Some(grant.grant_order),
        subjects: grant.subjects,
        execution_contexts: grant.execution_contexts,
        service: grant.service,
        actions: grant.actions,
        resources: grant.resources,
        credential_mode: grant.credential_mode,
        priority: grant.priority,
        status: grant.status,
        description: grant.description,
        version: Some(grant.version),
        created_at: Some(grant.created_at),
        created_by: Some(grant.created_by),
        updated_at: Some(grant.updated_at),
        updated_by: Some(grant.updated_by),
        disabled_at: grant.disabled_at,
        deleted_at: grant.deleted_at,
    }
}

fn policy_grant_matches_query(grant: &PolicyGrantView, query: &PolicyGrantListQuery) -> bool {
    query.subject.as_ref().is_none_or(|subject| {
        grant
            .subjects
            .iter()
            .any(|grant_subject| grant_subject == subject)
    }) && query
        .service
        .as_ref()
        .is_none_or(|service| service == &grant.service)
        && query.execution_context.as_ref().is_none_or(|context| {
            grant
                .execution_contexts
                .iter()
                .any(|grant_context| grant_context == context)
        })
        && query
            .status
            .as_ref()
            .is_none_or(|status| status == &grant.status)
}

fn policy_grant_list_query(raw_query: Option<&str>) -> Result<PolicyGrantListQuery, String> {
    let Some(raw_query) = raw_query else {
        return Ok(PolicyGrantListQuery::default());
    };
    let mut query = PolicyGrantListQuery::default();
    for (key, value) in form_urlencoded::parse(raw_query.as_bytes()) {
        match key.as_ref() {
            "subject" if query.subject.is_none() => query.subject = Some(value.into_owned()),
            "subject" => return Err("subject query parameter is duplicated".to_string()),
            "service" if query.service.is_none() => query.service = Some(value.into_owned()),
            "service" => return Err("service query parameter is duplicated".to_string()),
            "executionContext" if query.execution_context.is_none() => {
                query.execution_context = Some(value.into_owned())
            }
            "executionContext" => {
                return Err("executionContext query parameter is duplicated".to_string());
            }
            "status" if query.status.is_none() => query.status = Some(value.into_owned()),
            "status" => return Err("status query parameter is duplicated".to_string()),
            _ => return Err(format!("query parameter {key} is not supported")),
        }
    }
    Ok(query)
}

pub(super) fn expected_version_query(raw_query: Option<&str>) -> Result<Option<i64>, String> {
    let Some(raw_query) = raw_query else {
        return Ok(None);
    };
    let mut expected_version = None;
    for (key, value) in form_urlencoded::parse(raw_query.as_bytes()) {
        match key.as_ref() {
            "expectedVersion" if expected_version.is_none() => {
                expected_version = Some(value.parse::<i64>().map_err(|_| {
                    "expectedVersion query parameter must be an integer".to_string()
                })?)
            }
            "expectedVersion" => {
                return Err("expectedVersion query parameter is duplicated".to_string());
            }
            _ => return Err(format!("query parameter {key} is not supported")),
        }
    }
    Ok(expected_version)
}

fn parse_toml_grant_ref(value: &str) -> Option<usize> {
    value.strip_prefix("toml:")?.parse::<usize>().ok()
}

pub(super) fn required_expected_version(
    expected_version: Option<i64>,
) -> Result<i64, ManagedStoreError> {
    expected_version
        .ok_or_else(|| ManagedStoreError::InputInvalid("expectedVersion is required".to_string()))
}

fn required_validate_field<T>(value: Option<T>, field: &str) -> Result<T, ManagedStoreError> {
    value.ok_or_else(|| ManagedStoreError::InputInvalid(format!("{field} is required")))
}

fn candidate_validation_error(error: &ManagedStoreError) -> bool {
    matches!(
        error,
        ManagedStoreError::InputInvalid(_)
            | ManagedStoreError::PolicyValidationFailed(_)
            | ManagedStoreError::PolicyValidationIssues(_)
            | ManagedStoreError::PolicyAuthorityUnavailable(_)
            | ManagedStoreError::VersionConflict
            | ManagedStoreError::PolicyGrantNotFound
    )
}

fn policy_validation_messages(error: &ManagedStoreError) -> Vec<PolicyValidationMessage> {
    match error {
        ManagedStoreError::PolicyValidationIssues(issues) => issues
            .iter()
            .map(|issue| PolicyValidationMessage {
                field: issue.field.clone(),
                code: issue.code.clone(),
                message: issue.message.clone(),
            })
            .collect(),
        ManagedStoreError::PolicyValidationFailed(message) => message
            .strip_prefix("policy candidate validation failed: ")
            .unwrap_or(message)
            .split("; ")
            .filter(|part| !part.trim().is_empty())
            .map(validation_message_from_text)
            .collect(),
        ManagedStoreError::InputInvalid(message) => vec![validation_message_from_text(message)],
        ManagedStoreError::VersionConflict => vec![PolicyValidationMessage {
            field: "expectedVersion".to_string(),
            code: "version_conflict".to_string(),
            message: error.to_string(),
        }],
        ManagedStoreError::PolicyGrantNotFound => vec![PolicyValidationMessage {
            field: "grantId".to_string(),
            code: "grant_not_found".to_string(),
            message: error.to_string(),
        }],
        ManagedStoreError::PolicyAuthorityUnavailable(_) => vec![PolicyValidationMessage {
            field: "policyAuthority".to_string(),
            code: "policy_authority_unavailable".to_string(),
            message: super::common::management_store_public_error_message("policy.validate", error),
        }],
        _ => vec![PolicyValidationMessage {
            field: "grant".to_string(),
            code: "validation_failed".to_string(),
            message: error.to_string(),
        }],
    }
}

fn validation_message_from_text(message: &str) -> PolicyValidationMessage {
    let lower = message.to_ascii_lowercase();
    if lower.contains("executioncontexts") || lower.contains("execution context") {
        let code = if lower.contains("required") {
            "required"
        } else if lower.contains("empty") || lower.contains("at least") {
            "empty"
        } else if lower.contains("duplicate") {
            "execution_context_duplicate"
        } else if lower.contains("at most") {
            "too_many"
        } else if lower.contains("unknown") || lower.contains("configured") {
            "execution_context_unknown"
        } else {
            "execution_context_invalid"
        };
        return PolicyValidationMessage {
            field: "executionContexts".to_string(),
            code: code.to_string(),
            message: message.to_string(),
        };
    }
    if let Some(field) = indexed_subject_field(message) {
        let code = if lower.contains("duplicates") {
            "subject_duplicate"
        } else if lower.contains("does not reference") {
            "subject_not_found"
        } else {
            "subject_invalid"
        };
        return PolicyValidationMessage {
            field,
            code: code.to_string(),
            message: message.to_string(),
        };
    }
    let (field, code) = if lower.contains("duplicates") {
        ("grant", "grant_duplicate")
    } else if lower.contains("grantid") {
        ("grantId", "grant_id_invalid")
    } else if lower.contains("ambiguous credential mode precedence") {
        ("credentialMode", "credential_mode_ambiguous")
    } else if lower.contains("subjects") {
        if lower.contains("required") {
            ("subjects", "required")
        } else if lower.contains("empty") || lower.contains("must not be empty") {
            ("subjects", "empty")
        } else if lower.contains("at most") {
            ("subjects", "too_many")
        } else if lower.contains("duplicates") {
            ("subjects", "subject_duplicate")
        } else {
            ("subjects", "subject_invalid")
        }
    } else if lower.contains("subject") {
        if lower.contains("does not reference") {
            ("subjects", "subject_not_found")
        } else {
            ("subjects", "subject_invalid")
        }
    } else if lower.contains("scope") && (lower.contains("required") || lower.contains("constrain"))
    {
        ("resources", "scope_required")
    } else if lower.contains("action") || lower.contains("actions") {
        if lower.contains("unknown") {
            ("actions", "action_unknown")
        } else if lower.contains("empty") || lower.contains("at least") {
            ("actions", "action_required")
        } else {
            ("actions", "action_invalid")
        }
    } else if lower.contains("service") && lower.contains("unknown") {
        ("service", "service_unknown")
    } else if lower.contains("credentialmode") || lower.contains("credential mode") {
        if lower.contains("not configured") {
            ("credentialMode", "credential_mode_unconfigured")
        } else if lower.contains("unsupported") {
            ("credentialMode", "credential_mode_unsupported")
        } else {
            ("credentialMode", "credential_mode_invalid")
        }
    } else if lower.contains("credentials") && lower.contains("not configured") {
        ("credentialMode", "credential_mode_unconfigured")
    } else if lower.contains("repository selector") {
        ("resources", "repository_selector_invalid")
    } else if lower.contains("scope") {
        if lower.contains("required") || lower.contains("constrain") {
            ("resources", "scope_required")
        } else {
            ("resources", "scope_invalid")
        }
    } else if lower.contains("priority") {
        ("priority", "priority_invalid")
    } else if lower.contains("description") {
        ("description", "description_invalid")
    } else if lower.contains("expectedversion") {
        ("expectedVersion", "expected_version_required")
    } else {
        ("grant", "validation_failed")
    };
    PolicyValidationMessage {
        field: field.to_string(),
        code: code.to_string(),
        message: message.to_string(),
    }
}

fn indexed_subject_field(message: &str) -> Option<String> {
    let start = message.find("subjects[")?;
    let tail = &message[start..];
    let end = tail.find(']')?;
    Some(tail[..=end].to_string())
}

pub(super) async fn policy_authority_unavailable(
    context: &crate::handlers::management::common::ManagementContext,
    operation: &str,
    target: Option<Value>,
) -> axum::response::Response {
    management_context_error_response(
        context,
        StatusCode::BAD_REQUEST,
        operation,
        ReasonCode::PolicyAuthorityUnavailable,
        "managed policy operation requires policy.authority = managed",
        target,
    )
    .await
}

async fn policy_grant_not_found(
    context: &crate::handlers::management::common::ManagementContext,
    operation: &str,
    target: Option<Value>,
) -> axum::response::Response {
    management_context_error_response(
        context,
        StatusCode::NOT_FOUND,
        operation,
        ReasonCode::PolicyGrantNotFound,
        "policy grant was not found",
        target,
    )
    .await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn policy_validation_sanitizes_internal_authority_details() {
        let messages = policy_validation_messages(&ManagedStoreError::PolicyAuthorityUnavailable(
            "private-database-marker /private/store.sqlite".into(),
        ));
        assert_eq!(messages[0].code, "policy_authority_unavailable");
        assert_eq!(messages[0].message, "policy authority is unavailable");
    }

    #[test]
    fn policy_patch_distinguishes_absent_contexts_from_null() {
        let absent: PolicyGrantPatchBody =
            serde_json::from_value(json!({"expectedVersion": 1})).expect("patch should parse");
        assert_eq!(absent.execution_contexts, None);

        let explicit_null: PolicyGrantPatchBody = serde_json::from_value(json!({
            "expectedVersion": 1,
            "executionContexts": null
        }))
        .expect("patch should preserve explicit null");
        assert_eq!(explicit_null.execution_contexts, Some(None));

        let contexts: PolicyGrantPatchBody = serde_json::from_value(json!({
            "expectedVersion": 1,
            "executionContexts": ["external", "internal"]
        }))
        .expect("patch should parse contexts");
        assert_eq!(
            contexts.execution_contexts,
            Some(Some(vec!["external".to_string(), "internal".to_string()]))
        );
    }

    #[test]
    fn policy_list_query_supports_one_execution_context_filter() {
        let query = policy_grant_list_query(Some(
            "subject=group%3Adevelopers&executionContext=external&status=active",
        ))
        .expect("query should parse");
        assert_eq!(query.subject.as_deref(), Some("group:developers"));
        assert_eq!(query.execution_context.as_deref(), Some("external"));
        assert_eq!(query.status.as_deref(), Some("active"));

        assert_eq!(
            policy_grant_list_query(Some("executionContext=external&executionContext=internal"))
                .expect_err("duplicate execution-context filters must fail"),
            "executionContext query parameter is duplicated"
        );
    }

    #[test]
    fn policy_validation_maps_execution_context_failures() {
        let required = validation_message_from_text("executionContexts is required");
        assert_eq!(required.field, "executionContexts");
        assert_eq!(required.code, "required");

        let unknown = validation_message_from_text(
            "execution context `retired` is not in configured allowed values",
        );
        assert_eq!(unknown.field, "executionContexts");
        assert_eq!(unknown.code, "execution_context_unknown");
    }
}
