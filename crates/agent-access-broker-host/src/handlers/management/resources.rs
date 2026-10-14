//! Catalog management uses the same mutation/publication guard as grants.
use super::common::{
    ManagementAccess, ManagementContext, management_committed_catalog_audit_completion,
    management_context, management_context_error_response, management_pre_audited_success_response,
    management_store_call, management_store_error_response, management_success_response,
    management_write_audit_preflight,
};
use super::policy::{
    deserialize_nullable_string_patch, expected_version_query, parse_policy_json_body,
    policy_authority_unavailable, policy_management_scope, proposed_service_authorized,
    required_expected_version,
};
use crate::state::{AppState, ReloadableState};
use agent_access_core::{
    AgentInvokeTokenCaveats, CreateResourceGroupRequest, CreateResourceRequest,
    DeleteResourceRequest, ExecutionContext, PatchResourceGroupRequest, PatchResourceRequest,
    PolicyReadScope, ResourceSelection,
};
use agent_access_provider::{ReasonCode, ResourceAttributes, ResourceSelector, ResourceType};
use axum::body::Bytes;
use axum::extract::{ConnectInfo, Path, RawQuery, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::net::SocketAddr;
use std::sync::Arc;

/// Own mutation, publication, and supplemental completion audit as one task.
/// Dropping the HTTP waiter must not drop audit emission after the commit.
pub(crate) async fn committed_catalog_mutation<T, F>(
    reloadable: Arc<ReloadableState>,
    context: ManagementContext,
    operation: &'static str,
    target: Option<Value>,
    mutate: F,
) -> Response
where
    T: Serialize + Send + Sync + 'static,
    F: FnOnce(
            agent_access_core::BrokerRuntime,
        ) -> Result<
            agent_access_core::ManagedCatalogMutationResult<T>,
            agent_access_core::ManagedStoreError,
        > + Send
        + 'static,
{
    let context = Arc::new(context);
    let owner_context = context.clone();
    let owner_target = target.clone();
    let owner = tokio::spawn(async move {
        let context = owner_context;
        match reloadable
            .managed_policy_mutation_from_snapshot(context.snapshot.clone(), mutate)
            .await
        {
            Ok(result) => {
                management_committed_catalog_audit_completion(&context, operation, &result).await;
                management_pre_audited_success_response(
                    &context,
                    operation,
                    owner_target,
                    json!({"record":result.record,"previousRevision":result.previous_revision,"revision":result.revision}),
                )
            }
            Err(error) => {
                management_store_error_response(&context, operation, owner_target, error).await
            }
        }
    });
    match owner.await {
        Ok(response) => response,
        Err(_) => {
            management_store_error_response(
                &context,
                operation,
                target,
                agent_access_core::ManagedStoreError::Unavailable(
                    "catalog mutation owner failed".into(),
                ),
            )
            .await
        }
    }
}

fn default_enabled() -> bool {
    true
}
fn deserialize_patch<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    T::deserialize(deserializer).map(Some)
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ResourceCreateBody {
    id: Option<String>,
    display_name: Option<String>,
    resource_type: ResourceType,
    selector: ResourceSelector,
    allowed_execution_contexts: Vec<String>,
    #[serde(default = "default_enabled")]
    enabled: bool,
    #[serde(default)]
    attributes: ResourceAttributes,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ResourcePatchBody {
    expected_version: i64,
    #[serde(default, deserialize_with = "deserialize_nullable_string_patch")]
    display_name: Option<Option<String>>,
    #[serde(default, deserialize_with = "deserialize_patch")]
    resource_type: Option<ResourceType>,
    #[serde(default, deserialize_with = "deserialize_patch")]
    selector: Option<ResourceSelector>,
    #[serde(default, deserialize_with = "deserialize_patch")]
    allowed_execution_contexts: Option<Vec<String>>,
    #[serde(default, deserialize_with = "deserialize_patch")]
    enabled: Option<bool>,
    #[serde(default)]
    attributes: ResourceAttributes,
}

// Serde errors can include invalid values or unknown field names. Resource
// writes may contain signed URLs, so never include parser diagnostics in output.
async fn parse_resource_json_body<T: serde::de::DeserializeOwned>(
    context: &super::common::ManagementContext,
    operation: &str,
    body: Bytes,
) -> Result<T, Box<Response>> {
    match serde_json::from_slice(&body) {
        Ok(body) => Ok(body),
        Err(_) => Err(Box::new(
            management_context_error_response(
                context,
                StatusCode::BAD_REQUEST,
                operation,
                ReasonCode::InputInvalid,
                "request body does not match the resource schema",
                None,
            )
            .await,
        )),
    }
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ResourceGroupCreateBody {
    id: Option<String>,
    name: String,
    #[serde(default)]
    included_resource_ids: Vec<String>,
    #[serde(default)]
    excluded_resource_ids: Vec<String>,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ResourceGroupPatchBody {
    expected_version: i64,
    #[serde(default, deserialize_with = "deserialize_patch")]
    name: Option<String>,
    #[serde(default, deserialize_with = "deserialize_patch")]
    included_resource_ids: Option<Vec<String>>,
    #[serde(default, deserialize_with = "deserialize_patch")]
    excluded_resource_ids: Option<Vec<String>>,
}

pub(crate) async fn admin_policy_resources_list(
    State(state): State<AppState>,
    ConnectInfo(remote_addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let operation = "admin.policy.resources.list";
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
    let target = None;
    if context.snapshot.runtime.config().policy.authority != "managed"
        || !matches!(policy_management_scope(&context), PolicyReadScope::Global)
    {
        let catalog = context
            .snapshot
            .runtime
            .policy_resource_catalog_for_scope(policy_management_scope(&context));
        return management_success_response(&context, operation, target, json!(catalog.resources))
            .await;
    }
    match management_store_call(&context, move |store| store.resources()).await {
        Ok(result) => management_success_response(&context, operation, target, json!(result)).await,
        Err(error) => management_store_error_response(&context, operation, target, error).await,
    }
}

pub(crate) async fn admin_policy_resources_get(
    State(state): State<AppState>,
    Path(id): Path<String>,
    ConnectInfo(remote_addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let operation = "admin.policy.resources.get";
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
    let target = Some(json!({"id":id}));
    if context.snapshot.runtime.config().policy.authority != "managed"
        || !matches!(policy_management_scope(&context), PolicyReadScope::Global)
    {
        let catalog = context
            .snapshot
            .runtime
            .policy_resource_catalog_for_scope(policy_management_scope(&context));
        return match catalog.resources.into_iter().find(|record| record.id == id) {
            Some(record) => {
                management_success_response(&context, operation, target, json!(record)).await
            }
            None => {
                management_context_error_response(
                    &context,
                    StatusCode::NOT_FOUND,
                    operation,
                    ReasonCode::ResourceNotFound,
                    "resource catalog entry not found",
                    target,
                )
                .await
            }
        };
    }
    match management_store_call(&context, move |store| store.resource(&id)).await {
        Ok(result) => management_success_response(&context, operation, target, json!(result)).await,
        Err(error) => management_store_error_response(&context, operation, target, error).await,
    }
}

pub(crate) async fn admin_policy_resources_used_by(
    State(state): State<AppState>,
    Path(id): Path<String>,
    ConnectInfo(remote_addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let operation = "admin.policy.resources.used_by";
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
    let target = Some(json!({"id":id}));
    if context.snapshot.runtime.config().policy.authority != "managed" {
        return toml_used_by_response(&context, operation, &id, false).await;
    }
    match management_store_call(&context, move |store| store.resource_used_by(&id)).await {
        Ok(result) => management_success_response(&context, operation, target, json!(result)).await,
        Err(error) => management_store_error_response(&context, operation, target, error).await,
    }
}

pub(crate) async fn admin_policy_resource_attribute_reveal(
    State(state): State<AppState>,
    Path((id, attribute)): Path<(String, String)>,
    ConnectInfo(remote_addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> Response {
    let mut response = reveal_resource_attribute(state, id, attribute, remote_addr, headers).await;
    response.headers_mut().insert(
        axum::http::header::CACHE_CONTROL,
        axum::http::HeaderValue::from_static("no-store"),
    );
    response
}

async fn reveal_resource_attribute(
    state: AppState,
    id: String,
    attribute: String,
    remote_addr: SocketAddr,
    headers: HeaderMap,
) -> Response {
    let operation = "admin.policy.resources.attribute.reveal";
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
    let target = Some(json!({"id":id,"attribute":attribute}));
    if context.snapshot.runtime.config().policy.authority != "managed" {
        return policy_authority_unavailable(&context, operation, target).await;
    }
    if let Err(response) =
        management_write_audit_preflight(&context, operation, target.clone()).await
    {
        return *response;
    }
    let ring = context.snapshot.runtime.credential_key_ring().cloned();
    let result = management_store_call(&context, move |store| {
        let ring = ring.as_ref().ok_or_else(|| {
            agent_access_core::ManagedStoreError::EncryptionKeyMissing(
                "resource attribute key ring".into(),
            )
        })?;
        store.reveal_resource_attribute(&id, &attribute, ring)
    })
    .await;
    match result {
        Ok(value) => management_pre_audited_success_response(
            &context,
            operation,
            target,
            json!({"value":value}),
        ),
        Err(error) => management_store_error_response(&context, operation, target, error).await,
    }
}

pub(crate) async fn admin_policy_resources_create(
    State(state): State<AppState>,
    ConnectInfo(remote_addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    body: Bytes,
) -> impl IntoResponse {
    let operation = "admin.policy.resources.create";
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
    let target = None;
    if context.snapshot.runtime.config().policy.authority != "managed" {
        return policy_authority_unavailable(&context, operation, target).await;
    }
    if let Err(response) =
        management_write_audit_preflight(&context, operation, target.clone()).await
    {
        return *response;
    }
    let body = match parse_resource_json_body::<ResourceCreateBody>(&context, operation, body).await
    {
        Ok(body) => body,
        Err(response) => return *response,
    };
    let request = CreateResourceRequest {
        id: body.id,
        display_name: body.display_name,
        resource_type: body.resource_type,
        selector: body.selector,
        allowed_execution_contexts: body.allowed_execution_contexts,
        enabled: body.enabled,
        attributes: body.attributes,
        created_by: context.identity.principal.clone(),
    };
    committed_catalog_mutation(
        state.reloadable,
        context,
        operation,
        target,
        move |runtime| runtime.create_managed_resource(request),
    )
    .await
}

pub(crate) async fn admin_policy_resources_patch(
    State(state): State<AppState>,
    Path(id): Path<String>,
    ConnectInfo(remote_addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    body: Bytes,
) -> impl IntoResponse {
    let operation = "admin.policy.resources.patch";
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
    let target = Some(json!({"id":id}));
    if context.snapshot.runtime.config().policy.authority != "managed" {
        return policy_authority_unavailable(&context, operation, target).await;
    }
    if let Err(response) =
        management_write_audit_preflight(&context, operation, target.clone()).await
    {
        return *response;
    }
    let body = match parse_resource_json_body::<ResourcePatchBody>(&context, operation, body).await
    {
        Ok(body) => body,
        Err(response) => return *response,
    };
    if let Err(error) = required_expected_version(Some(body.expected_version)) {
        return management_store_error_response(&context, operation, target, error).await;
    }
    let request = PatchResourceRequest {
        id,
        display_name: body.display_name,
        resource_type: body.resource_type,
        selector: body.selector,
        allowed_execution_contexts: body.allowed_execution_contexts,
        enabled: body.enabled,
        attributes: body.attributes,
        expected_version: body.expected_version,
        updated_by: context.identity.principal.clone(),
    };
    committed_catalog_mutation(
        state.reloadable,
        context,
        operation,
        target,
        move |runtime| runtime.patch_managed_resource(request),
    )
    .await
}

pub(crate) async fn admin_policy_resources_delete(
    State(state): State<AppState>,
    Path(id): Path<String>,
    RawQuery(raw_query): RawQuery,
    ConnectInfo(remote_addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let operation = "admin.policy.resources.delete";
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
    let target = Some(json!({"id":id}));
    if context.snapshot.runtime.config().policy.authority != "managed" {
        return policy_authority_unavailable(&context, operation, target).await;
    }
    if let Err(response) =
        management_write_audit_preflight(&context, operation, target.clone()).await
    {
        return *response;
    }
    let expected_version = match expected_version_query(raw_query.as_deref())
        .map_err(agent_access_core::ManagedStoreError::InputInvalid)
        .and_then(required_expected_version)
    {
        Ok(version) => version,
        Err(error) => {
            return management_store_error_response(&context, operation, target, error).await;
        }
    };
    let request = DeleteResourceRequest {
        id,
        expected_version,
        updated_by: context.identity.principal.clone(),
    };
    committed_catalog_mutation(
        state.reloadable,
        context,
        operation,
        target,
        move |runtime| runtime.delete_managed_resource(request),
    )
    .await
}

pub(crate) async fn admin_policy_resource_groups_list(
    State(state): State<AppState>,
    ConnectInfo(remote_addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let operation = "admin.policy.resource_groups.list";
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
    let target = None;
    if context.snapshot.runtime.config().policy.authority != "managed"
        || !matches!(policy_management_scope(&context), PolicyReadScope::Global)
    {
        let catalog = context
            .snapshot
            .runtime
            .policy_resource_catalog_for_scope(policy_management_scope(&context));
        return management_success_response(
            &context,
            operation,
            target,
            json!(catalog.resource_groups),
        )
        .await;
    }
    match management_store_call(&context, move |store| store.resource_groups()).await {
        Ok(result) => management_success_response(&context, operation, target, json!(result)).await,
        Err(error) => management_store_error_response(&context, operation, target, error).await,
    }
}

pub(crate) async fn admin_policy_resource_groups_get(
    State(state): State<AppState>,
    Path(id): Path<String>,
    ConnectInfo(remote_addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let operation = "admin.policy.resource_groups.get";
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
    let target = Some(json!({"id":id}));
    if context.snapshot.runtime.config().policy.authority != "managed"
        || !matches!(policy_management_scope(&context), PolicyReadScope::Global)
    {
        let catalog = context
            .snapshot
            .runtime
            .policy_resource_catalog_for_scope(policy_management_scope(&context));
        return match catalog
            .resource_groups
            .into_iter()
            .find(|record| record.id == id)
        {
            Some(record) => {
                management_success_response(&context, operation, target, json!(record)).await
            }
            None => {
                management_context_error_response(
                    &context,
                    StatusCode::NOT_FOUND,
                    operation,
                    ReasonCode::ResourceGroupNotFound,
                    "resource catalog entry not found",
                    target,
                )
                .await
            }
        };
    }
    match management_store_call(&context, move |store| store.resource_group(&id)).await {
        Ok(result) => management_success_response(&context, operation, target, json!(result)).await,
        Err(error) => management_store_error_response(&context, operation, target, error).await,
    }
}

pub(crate) async fn admin_policy_resource_groups_used_by(
    State(state): State<AppState>,
    Path(id): Path<String>,
    ConnectInfo(remote_addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let operation = "admin.policy.resource_groups.used_by";
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
    let target = Some(json!({"id":id}));
    if context.snapshot.runtime.config().policy.authority != "managed" {
        return toml_used_by_response(&context, operation, &id, true).await;
    }
    match management_store_call(&context, move |store| store.resource_group_used_by(&id)).await {
        Ok(result) => management_success_response(&context, operation, target, json!(result)).await,
        Err(error) => management_store_error_response(&context, operation, target, error).await,
    }
}

pub(crate) async fn admin_policy_resource_groups_create(
    State(state): State<AppState>,
    ConnectInfo(remote_addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    body: Bytes,
) -> impl IntoResponse {
    let operation = "admin.policy.resource_groups.create";
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
    let target = None;
    if context.snapshot.runtime.config().policy.authority != "managed" {
        return policy_authority_unavailable(&context, operation, target).await;
    }
    if let Err(response) =
        management_write_audit_preflight(&context, operation, target.clone()).await
    {
        return *response;
    }
    let body =
        match parse_policy_json_body::<ResourceGroupCreateBody>(&context, operation, body).await {
            Ok(body) => body,
            Err(response) => return *response,
        };
    let request = CreateResourceGroupRequest {
        id: body.id,
        name: body.name,
        included_resource_ids: body.included_resource_ids,
        excluded_resource_ids: body.excluded_resource_ids,
        created_by: context.identity.principal.clone(),
    };
    committed_catalog_mutation(
        state.reloadable,
        context,
        operation,
        target,
        move |runtime| runtime.create_managed_resource_group(request),
    )
    .await
}

pub(crate) async fn admin_policy_resource_groups_patch(
    State(state): State<AppState>,
    Path(id): Path<String>,
    ConnectInfo(remote_addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    body: Bytes,
) -> impl IntoResponse {
    let operation = "admin.policy.resource_groups.patch";
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
    let target = Some(json!({"id":id}));
    if context.snapshot.runtime.config().policy.authority != "managed" {
        return policy_authority_unavailable(&context, operation, target).await;
    }
    if let Err(response) =
        management_write_audit_preflight(&context, operation, target.clone()).await
    {
        return *response;
    }
    let body =
        match parse_policy_json_body::<ResourceGroupPatchBody>(&context, operation, body).await {
            Ok(body) => body,
            Err(response) => return *response,
        };
    if let Err(error) = required_expected_version(Some(body.expected_version)) {
        return management_store_error_response(&context, operation, target, error).await;
    }
    let request = PatchResourceGroupRequest {
        id,
        name: body.name,
        included_resource_ids: body.included_resource_ids,
        excluded_resource_ids: body.excluded_resource_ids,
        expected_version: body.expected_version,
        updated_by: context.identity.principal.clone(),
    };
    committed_catalog_mutation(
        state.reloadable,
        context,
        operation,
        target,
        move |runtime| runtime.patch_managed_resource_group(request),
    )
    .await
}

pub(crate) async fn admin_policy_resource_groups_delete(
    State(state): State<AppState>,
    Path(id): Path<String>,
    RawQuery(raw_query): RawQuery,
    ConnectInfo(remote_addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let operation = "admin.policy.resource_groups.delete";
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
    let target = Some(json!({"id":id}));
    if context.snapshot.runtime.config().policy.authority != "managed" {
        return policy_authority_unavailable(&context, operation, target).await;
    }
    if let Err(response) =
        management_write_audit_preflight(&context, operation, target.clone()).await
    {
        return *response;
    }
    let expected_version = match expected_version_query(raw_query.as_deref())
        .map_err(agent_access_core::ManagedStoreError::InputInvalid)
        .and_then(required_expected_version)
    {
        Ok(version) => version,
        Err(error) => {
            return management_store_error_response(&context, operation, target, error).await;
        }
    };
    let request = DeleteResourceRequest {
        id,
        expected_version,
        updated_by: context.identity.principal.clone(),
    };
    committed_catalog_mutation(
        state.reloadable,
        context,
        operation,
        target,
        move |runtime| runtime.delete_managed_resource_group(request),
    )
    .await
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PolicyEffectiveAccessBody {
    service: String,
    actions: Vec<String>,
    execution_contexts: Vec<ExecutionContext>,
    resources: ResourceSelection,
}
pub(crate) async fn admin_policy_effective_access(
    State(state): State<AppState>,
    ConnectInfo(remote_addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    body: Bytes,
) -> impl IntoResponse {
    let operation = "admin.policy.effective_access";
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
    let body = match parse_policy_json_body::<PolicyEffectiveAccessBody>(&context, operation, body)
        .await
    {
        Ok(body) => body,
        Err(response) => return *response,
    };
    if !proposed_service_authorized(&context, &body.service) {
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
    // A previously selected group may now be empty and absent from filtered
    // pickers. The preview only returns scopes for the authorized service.
    match context.snapshot.runtime.preview_policy_resources(
        &body.service,
        &body.actions,
        &body.execution_contexts,
        &body.resources,
    ) {
        Ok(result) => management_success_response(&context, operation, None, json!(result)).await,
        Err(error) => management_store_error_response(&context, operation, None, error).await,
    }
}

pub(crate) async fn user_token_effective_access(
    State(state): State<AppState>,
    ConnectInfo(remote_addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    body: Bytes,
) -> impl IntoResponse {
    let operation = "tokens.effective_access";
    let context = match management_context(
        &state,
        remote_addr,
        &headers,
        operation,
        ManagementAccess::User,
    )
    .await
    {
        Ok(context) => context,
        Err(response) => return *response,
    };
    token_effective_access_response(&context, &context.identity, operation, body).await
}

pub(super) async fn token_effective_access_response(
    context: &super::common::ManagementContext,
    identity: &agent_access_core::IdentityContext,
    operation: &str,
    body: Bytes,
) -> Response {
    let value = match parse_policy_json_body::<serde_json::Value>(context, operation, body).await {
        Ok(value) => value,
        Err(response) => return *response,
    };
    let caveats = match AgentInvokeTokenCaveats::parse_issuance(
        &value,
        context.snapshot.runtime.config().execution_context.as_ref(),
    ) {
        Ok(caveats) => caveats,
        Err(error) => {
            return management_context_error_response(
                context,
                StatusCode::BAD_REQUEST,
                operation,
                ReasonCode::InputInvalid,
                &error.to_string(),
                None,
            )
            .await;
        }
    };
    // A saved token can outlive its current grant access. Preview its current
    // intersection rather than reject selections that disappeared from pickers.
    match context
        .snapshot
        .runtime
        .preview_agent_token_access(identity, &caveats)
    {
        Ok(result) => management_success_response(context, operation, None, json!(result)).await,
        Err(error) => management_store_error_response(context, operation, None, error).await,
    }
}

pub(crate) async fn admin_principal_agent_token_effective_access(
    State(state): State<AppState>,
    Path(principal): Path<String>,
    ConnectInfo(remote_addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    body: Bytes,
) -> impl IntoResponse {
    let operation = "admin.tokens.effective_access_principal_agent";
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
    let principal_for_store = principal.clone();
    let (record, groups) = match management_store_call(&context, move |store| {
        Ok((
            store.principal(&principal_for_store)?,
            store.policy_groups(&principal_for_store)?,
        ))
    })
    .await
    {
        Ok(value) => value,
        Err(error) => {
            return management_store_error_response(
                &context,
                operation,
                Some(json!({"principal":principal})),
                error,
            )
            .await;
        }
    };
    let identity =
        super::admin::managed_principal_identity(&context.snapshot.runtime, record, groups);
    token_effective_access_response(&context, &identity, operation, body).await
}

/// Read-only TOML catalogs have no mirrored managed resource rows. Resolve
/// configured references directly, and ask the store only for live token links.
async fn toml_used_by_response(
    context: &super::common::ManagementContext,
    operation: &str,
    id: &str,
    is_group: bool,
) -> Response {
    use agent_access_core::{ManagedStoreError, ResourceReference};
    let catalog = context
        .snapshot
        .runtime
        .policy_resource_catalog_for_scope(&PolicyReadScope::Global);
    let target = Some(json!({"id":id}));
    let exists = if is_group {
        catalog.resource_groups.iter().any(|group| group.id == id)
    } else {
        catalog.resources.iter().any(|resource| resource.id == id)
    };
    if !exists {
        let error = if is_group {
            ManagedStoreError::ResourceGroupNotFound
        } else {
            ManagedStoreError::ResourceNotFound
        };
        return management_store_error_response(context, operation, target, error).await;
    }
    let memberships = catalog
        .resource_groups
        .iter()
        .flat_map(|group| {
            [
                ("include", &group.included_resource_ids),
                ("exclude", &group.excluded_resource_ids),
            ]
            .into_iter()
            .filter(move |(_, ids)| ids.iter().any(|value| value == id))
            .map(move |(effect, _)| (group.id.clone(), effect.to_string()))
        })
        .collect::<Vec<_>>();
    let mut references = Vec::new();
    if !is_group {
        references.extend(
            memberships
                .iter()
                .map(|(group_id, effect)| ResourceReference {
                    kind: "resource_group".to_string(),
                    id: group_id.clone(),
                    service: None,
                    principal_id: None,
                    via_group_id: None,
                    effect: Some(effect.clone()),
                }),
        );
    }
    for (index, grant) in context
        .snapshot
        .runtime
        .config()
        .policy
        .grants
        .iter()
        .enumerate()
    {
        let selection = &grant.resources;
        let direct = if is_group {
            &selection.resource_group_ids
        } else {
            &selection.resource_ids
        };
        if direct.iter().any(|value| value == id) {
            references.push(ResourceReference {
                kind: "grant".to_string(),
                id: format!("toml:{index}"),
                service: Some(grant.service.clone()),
                principal_id: None,
                via_group_id: None,
                effect: (!is_group).then(|| "include".to_string()),
            });
        }
        if !is_group {
            references.extend(
                memberships
                    .iter()
                    .filter(|(group_id, _)| selection.resource_group_ids.contains(group_id))
                    .map(|(group_id, effect)| ResourceReference {
                        kind: "grant".to_string(),
                        id: format!("toml:{index}"),
                        service: Some(grant.service.clone()),
                        principal_id: None,
                        via_group_id: Some(group_id.clone()),
                        effect: Some(effect.clone()),
                    }),
            );
        }
    }
    if context.snapshot.runtime.managed_store().is_some() {
        let id = id.to_string();
        match management_store_call(context, move |store| {
            store.token_resource_used_by(&id, is_group, &catalog)
        })
        .await
        {
            Ok(tokens) => references.extend(tokens),
            Err(error) => {
                return management_store_error_response(context, operation, target, error).await;
            }
        }
    }
    management_success_response(context, operation, target, json!(references)).await
}
