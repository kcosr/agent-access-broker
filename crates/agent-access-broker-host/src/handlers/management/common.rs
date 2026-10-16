use crate::handlers::auth::{csrf_header_valid, resolve_browser_cookie_identity_blocking};
use crate::handlers::common::{
    CallerAdmission, acquire_caller_guard, acquire_global_concurrency_guard,
    check_auth_source_rate_guard, envelope_response, request_id_from_headers,
    resolve_identity_blocking,
};
use crate::observability;
use crate::state::{AppState, RequestPermits, RuntimeSnapshot};
use agent_access_core::{
    AgentInvokeTokenCaveats, AgentTokenOptions, AuditRecord, BrokerConfig, BrokerRuntime,
    BrokerTokenClass, CredentialInputSchema, DEFAULT_MAX_SELF_ISSUED_AGENT_INVOKE_TTL_SECONDS,
    EffectiveServicePolicyManagementAuthority, ManagedManagementAuthority, PolicyReadScope,
    PolicyWriteScope, PrincipalRole, ResourceSelection, RuntimeError, SourceContext,
    broker_token_ttl_options_allow_never, broker_token_ttl_options_allow_ttl,
    new_broker_request_id, parse_ttl_seconds,
};
use agent_access_provider::{
    Decision, ProviderCredentialVerification, ProviderError, ProviderReason, ReasonCode,
    ReasonCodeId, ResourceScopes,
};
use axum::Json;
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};
use std::net::SocketAddr;
use std::sync::Arc;
use url::form_urlencoded;

#[derive(Debug, Clone, Copy)]
pub(crate) enum ManagementAccess {
    User,
    UserManageToken,
    PolicyRead,
    PolicyWrite,
    AdminRead,
    AdminWrite,
}

pub(crate) struct ManagementContext {
    pub(crate) snapshot: Arc<RuntimeSnapshot>,
    pub(crate) request_id: String,
    pub(crate) broker_request_id: String,
    pub(crate) identity: agent_access_core::IdentityContext,
    pub(crate) source: SourceContext,
    pub(crate) policy_management_scope: Option<PolicyReadScope>,
    pub(crate) policy_write_scope: Option<PolicyWriteScope>,
    pub(crate) principal_role: Option<PrincipalRole>,
    pub(crate) credential_purpose: agent_access_core::CredentialManagementPurpose,
    pub(crate) policy_management_authorities: Vec<EffectiveServicePolicyManagementAuthority>,
    _permits: RequestPermits,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ManagementEnvelope {
    ok: bool,
    decision: Decision,
    #[serde(skip_serializing_if = "Option::is_none")]
    reason_code: Option<ReasonCodeId>,
    request_id: String,
    broker_request_id: String,
    operation: String,
    principal: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    target: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<agent_access_core::ErrorBody>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct CredentialPutBody {
    pub(super) profile: Option<String>,
    pub(super) secret: Value,
    #[serde(default = "empty_json_object_value")]
    pub(super) metadata: Value,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct CredentialInputSchemaQuery {
    pub(super) profile: Option<String>,
}

pub(super) fn credential_input_schema_query(
    raw_query: Option<&str>,
) -> Result<CredentialInputSchemaQuery, String> {
    let Some(raw_query) = raw_query else {
        return Ok(CredentialInputSchemaQuery { profile: None });
    };
    let mut profile = None;
    for (key, value) in form_urlencoded::parse(raw_query.as_bytes()) {
        match key.as_ref() {
            "profile" if profile.is_none() => profile = Some(value.into_owned()),
            "profile" => {
                return Err("credential input schema profile query is duplicated".to_string());
            }
            _ => {
                return Err(format!(
                    "credential input schema query parameter {key} is not supported"
                ));
            }
        }
    }
    Ok(CredentialInputSchemaQuery { profile })
}

fn empty_json_object_value() -> Value {
    json!({})
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct AgentTokenIssueBody {
    pub(super) name: String,
    pub(super) ttl: Option<String>,
    pub(super) expires_at: Option<String>,
    #[serde(default)]
    pub(super) never: bool,
    pub(super) allowed_services: Option<Vec<String>>,
    pub(super) allowed_execution_contexts: Vec<String>,
    pub(super) service_restrictions: Option<BTreeMap<String, AgentTokenServiceRestrictionBody>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct AgentTokenServiceRestrictionBody {
    pub(super) actions: Vec<String>,
    #[serde(
        default,
        deserialize_with = "deserialize_token_resources",
        skip_serializing_if = "Option::is_none"
    )]
    pub(super) resources: Option<ResourceSelection>,
}

fn deserialize_token_resources<'de, D>(
    deserializer: D,
) -> Result<Option<ResourceSelection>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    ResourceSelection::deserialize(deserializer).map(Some)
}

#[derive(Debug, Clone, Copy)]
pub(super) struct AgentTokenListQuery {
    pub(super) include_revoked: bool,
    pub(super) include_expired: bool,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct CredentialTarget {
    pub(super) service: String,
    pub(super) display_name: String,
    /// Inputs verifying this credential needs besides the credential itself,
    /// such as `repository` for Git. Empty when verification needs none.
    pub(super) credential_verification_inputs: Vec<String>,
    pub(super) credential_name: String,
    pub(super) profile: String,
    pub(super) credential_kind: String,
    pub(super) input_schema: CredentialInputSchema,
}

fn self_service_max_agent_token_ttl_seconds(config: &BrokerConfig) -> u64 {
    config
        .broker_tokens
        .as_ref()
        .and_then(|tokens| tokens.max_self_issued_agent_invoke_ttl.as_deref())
        .and_then(parse_ttl_seconds)
        .unwrap_or(DEFAULT_MAX_SELF_ISSUED_AGENT_INVOKE_TTL_SECONDS)
}

fn self_service_default_agent_token_ttl_seconds(config: &BrokerConfig) -> u64 {
    config
        .broker_tokens
        .as_ref()
        .and_then(|tokens| tokens.default_agent_invoke_ttl.as_deref())
        .and_then(parse_ttl_seconds)
        .unwrap_or_else(|| self_service_max_agent_token_ttl_seconds(config))
}

pub(super) fn self_agent_token_issue_expires_at(
    config: &BrokerConfig,
    body: &AgentTokenIssueBody,
) -> Result<Option<String>, String> {
    let options = config
        .broker_tokens
        .as_ref()
        .map(|tokens| tokens.self_agent_invoke_ttl_options.as_slice())
        .ok_or_else(|| "broker token configuration is unavailable".to_string())?;
    let supplied = [body.ttl.is_some(), body.expires_at.is_some(), body.never]
        .into_iter()
        .filter(|present| *present)
        .count();
    if supplied > 1 {
        return Err("expiresAt, ttl, and never are mutually exclusive".to_string());
    }
    if body.never {
        if broker_token_ttl_options_allow_never(options) {
            return Ok(None);
        }
        return Err(
            "never is not allowed by broker_tokens.self_agent_invoke_ttl_options".to_string(),
        );
    }
    let max_seconds = self_service_max_agent_token_ttl_seconds(config);
    if let Some(ttl) = body.ttl.as_deref() {
        let seconds = parse_ttl_seconds(ttl)
            .ok_or_else(|| "ttl must use a duration like 30d, 8h, or 120m".to_string())?;
        if !broker_token_ttl_options_allow_ttl(options, ttl) {
            return Err(
                "ttl is not allowed by broker_tokens.self_agent_invoke_ttl_options".to_string(),
            );
        }
        if seconds > max_seconds {
            return Err("ttl exceeds broker_tokens.max_self_issued_agent_invoke_ttl".to_string());
        }
        return timestamp_after_seconds_checked(seconds).map(Some);
    }
    if let Some(expires_at) = body.expires_at.as_deref() {
        let parsed = DateTime::parse_from_rfc3339(expires_at)
            .map_err(|_| "expiresAt must be an RFC3339 timestamp".to_string())?
            .with_timezone(&Utc);
        let now = Utc::now();
        if parsed <= now {
            return Err("expiresAt must be in the future".to_string());
        }
        let max_seconds = i64::try_from(max_seconds).map_err(|_| {
            "broker_tokens.max_self_issued_agent_invoke_ttl is too large".to_string()
        })?;
        let max_duration = chrono::Duration::try_seconds(max_seconds).ok_or_else(|| {
            "broker_tokens.max_self_issued_agent_invoke_ttl is too large".to_string()
        })?;
        let max_expires_at = now.checked_add_signed(max_duration).ok_or_else(|| {
            "broker_tokens.max_self_issued_agent_invoke_ttl is too large".to_string()
        })?;
        if parsed > max_expires_at {
            return Err(
                "expiresAt exceeds broker_tokens.max_self_issued_agent_invoke_ttl".to_string(),
            );
        }
        return Ok(Some(parsed.to_rfc3339()));
    }
    let default_seconds = self_service_default_agent_token_ttl_seconds(config);
    if default_seconds > max_seconds {
        return Err(
            "broker_tokens.default_agent_invoke_ttl exceeds broker_tokens.max_self_issued_agent_invoke_ttl".to_string(),
        );
    }
    if !options
        .iter()
        .any(|option| option.ttl_seconds() == Some(default_seconds))
    {
        return Err(
            "effective default agent_invoke TTL is not allowed by broker_tokens.self_agent_invoke_ttl_options"
                .to_string(),
        );
    }
    timestamp_after_seconds_checked(default_seconds).map(Some)
}

pub(super) fn admin_agent_token_issue_expires_at(
    config: &BrokerConfig,
    body: &AgentTokenIssueBody,
) -> Result<Option<String>, String> {
    let options = config
        .broker_tokens
        .as_ref()
        .map(|tokens| tokens.admin_agent_invoke_ttl_options.as_slice())
        .ok_or_else(|| "broker token configuration is unavailable".to_string())?;
    let supplied = [body.ttl.is_some(), body.expires_at.is_some(), body.never]
        .into_iter()
        .filter(|present| *present)
        .count();
    if supplied > 1 {
        return Err("expiresAt, ttl, and never are mutually exclusive".to_string());
    }
    if body.never {
        if broker_token_ttl_options_allow_never(options) {
            return Ok(None);
        }
        return Err(
            "never is not allowed by broker_tokens.admin_agent_invoke_ttl_options".to_string(),
        );
    }
    if let Some(ttl) = body.ttl.as_deref() {
        let seconds = parse_ttl_seconds(ttl)
            .ok_or_else(|| "ttl must use a duration like 30d, 8h, or 120m".to_string())?;
        if !broker_token_ttl_options_allow_ttl(options, ttl) {
            return Err(
                "ttl is not allowed by broker_tokens.admin_agent_invoke_ttl_options".to_string(),
            );
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
    if let Some(seconds) = default_token_ttl_seconds(config, &BrokerTokenClass::AgentInvoke) {
        if !options
            .iter()
            .any(|option| option.ttl_seconds() == Some(seconds))
        {
            return Err(
                "default agent_invoke TTL is not allowed by broker_tokens.admin_agent_invoke_ttl_options"
                    .to_string(),
            );
        }
        return timestamp_after_seconds_checked(seconds).map(Some);
    }
    Err(
        "agent_invoke token expiry or never = true is required when broker_tokens.default_agent_invoke_ttl is not configured"
            .to_string(),
    )
}

pub(super) fn agent_token_issue_scopes(
    runtime: &BrokerRuntime,
    allowed_services: Option<Vec<String>>,
    allowed_execution_contexts: Vec<String>,
    service_restrictions: Option<BTreeMap<String, AgentTokenServiceRestrictionBody>>,
    options: &AgentTokenOptions,
) -> Result<Value, String> {
    let mut scopes = serde_json::Map::new();
    if let Some(allowed_services) = allowed_services {
        scopes.insert("allowedServices".to_string(), json!(allowed_services));
    }
    scopes.insert(
        "allowedExecutionContexts".to_string(),
        json!(allowed_execution_contexts),
    );
    if let Some(service_restrictions) = service_restrictions {
        scopes.insert(
            "serviceRestrictions".to_string(),
            json!(service_restrictions),
        );
    }
    parse_and_validate_agent_token_issue_scopes(runtime, Value::Object(scopes), options)
}

pub(super) fn parse_and_validate_agent_token_issue_scopes(
    runtime: &BrokerRuntime,
    scopes: Value,
    options: &AgentTokenOptions,
) -> Result<Value, String> {
    let caveats = AgentInvokeTokenCaveats::parse_issuance(
        &scopes,
        runtime.config().execution_context.as_ref(),
    )
    .map_err(|error| error.to_string())?;
    validate_agent_token_options(&caveats, options)?;
    Ok(caveats.to_scopes_value())
}

pub(super) fn agent_token_boundary_audit(scopes: &Value) -> Value {
    json!({
        "allowedServices": scopes.get("allowedServices").cloned(),
        "allowedExecutionContexts": scopes.get("allowedExecutionContexts").cloned(),
        "serviceRestrictions": scopes.get("serviceRestrictions").cloned(),
    })
}

pub(super) fn validate_agent_token_options(
    caveats: &AgentInvokeTokenCaveats,
    options: &AgentTokenOptions,
) -> Result<(), String> {
    let selected_contexts = caveats
        .allowed_execution_contexts
        .as_ref()
        .expect("new agent token caveats always contain execution contexts")
        .iter()
        .map(|context| context.as_str())
        .collect::<BTreeSet<_>>();
    for context in &selected_contexts {
        if !options
            .execution_contexts
            .iter()
            .any(|effective| effective.as_str() == *context)
        {
            return Err(format!(
                "allowedExecutionContexts context is not available to the principal: {context}"
            ));
        }
    }
    if let Some(allowed_services) = caveats.allowed_services.as_ref() {
        for service in allowed_services {
            let Some(option) = options
                .services
                .iter()
                .find(|option| option.service == *service)
            else {
                return Err(format!(
                    "allowedServices service is not visible to the principal: {service}"
                ));
            };
            if !option
                .execution_contexts
                .iter()
                .any(|context| selected_contexts.contains(context.as_str()))
            {
                return Err(format!(
                    "allowedServices service is not visible in any selected execution context: {service}"
                ));
            }
        }
    }
    let Some(restrictions) = caveats.service_restrictions.as_ref() else {
        return Ok(());
    };
    for (service, restriction) in restrictions {
        let service_option = options
            .services
            .iter()
            .find(|option| option.service == *service)
            .ok_or_else(|| {
                format!("serviceRestrictions service is not visible to the principal: {service}")
            })?;
        for action in &restriction.actions {
            let option = service_option.actions.iter().find(|option| option.action == *action)
                .ok_or_else(|| format!("serviceRestrictions action is not available to the principal: {service}.{action}"))?;
            if !option
                .execution_contexts
                .iter()
                .any(|context| selected_contexts.contains(context.as_str()))
            {
                return Err(format!(
                    "serviceRestrictions action is not available in any selected execution context: {service}.{action}"
                ));
            }
        }

        if let Some(resources) = &restriction.resources {
            for id in &resources.resource_ids {
                if !options.resources.iter().any(|resource| resource.id == *id) {
                    return Err(format!("resource is not available to the principal: {id}"));
                }
            }
            for id in &resources.resource_group_ids {
                if !options.resource_groups.iter().any(|group| group.id == *id) {
                    return Err(format!(
                        "resource group is not available to the principal: {id}"
                    ));
                }
            }
        }
    }
    Ok(())
}

pub(super) fn agent_token_list_query(
    raw_query: Option<&str>,
) -> Result<AgentTokenListQuery, String> {
    let Some(raw_query) = raw_query else {
        return Ok(AgentTokenListQuery {
            include_revoked: false,
            include_expired: false,
        });
    };
    let mut query = AgentTokenListQuery {
        include_revoked: false,
        include_expired: false,
    };
    let mut seen = BTreeSet::new();
    for (key, value) in form_urlencoded::parse(raw_query.as_bytes()) {
        if !seen.insert(key.to_string()) {
            return Err(format!("tokens query parameter {key} is duplicated"));
        }
        let parsed = match value.as_ref() {
            "true" => true,
            "false" => false,
            _ => {
                return Err(format!(
                    "tokens query parameter {key} must be true or false"
                ));
            }
        };
        match key.as_ref() {
            "includeRevoked" => query.include_revoked = parsed,
            "includeExpired" => query.include_expired = parsed,
            _ => return Err(format!("tokens query parameter {key} is not supported")),
        }
    }
    Ok(query)
}

pub(super) fn visible_per_user_services(
    runtime: &BrokerRuntime,
    identity: &agent_access_core::IdentityContext,
) -> BTreeSet<String> {
    runtime
        .visible_services_for_management(identity)
        .into_iter()
        .filter(|service| runtime.has_any_per_user_policy_for_service(identity, &service.service))
        .map(|service| service.service)
        .collect()
}

pub(super) fn credential_targets(
    runtime: &BrokerRuntime,
    allowed_services: Option<&BTreeSet<String>>,
) -> Vec<CredentialTarget> {
    runtime
        .effective_credentials()
        .per_user
        .iter()
        .filter_map(|(service, credential)| {
            if let Some(allowed_services) = allowed_services
                && !allowed_services.contains(service)
            {
                return None;
            }
            if credential.kind != "connection" {
                return None;
            }
            let (profile, credential_kind) = runtime.personal_token_profile(service)?;
            let credential_name = agent_access_core::CONNECTION_CREDENTIAL_NAME.to_string();
            let profile = profile.to_string();
            let input_schema =
                runtime.credential_input_schema(service, &profile, credential_kind)?;
            let descriptor = runtime.service_descriptor(service)?;
            Some(CredentialTarget {
                service: service.clone(),
                display_name: descriptor.display_name.clone(),
                credential_verification_inputs: descriptor.credential_verification_inputs(),
                credential_name,
                profile,
                credential_kind: credential_kind.to_string(),
                input_schema,
            })
        })
        .collect()
}

pub(super) async fn run_managed_store_blocking<T, F>(
    operation: F,
) -> Result<T, agent_access_core::ManagedStoreError>
where
    T: Send + 'static,
    F: FnOnce() -> Result<T, agent_access_core::ManagedStoreError> + Send + 'static,
{
    // Keep the store work in the request's span for log correlation.
    let span = tracing::Span::current();
    tokio::task::spawn_blocking(move || span.in_scope(operation))
        .await
        .map_err(|error| {
            agent_access_core::ManagedStoreError::Unavailable(format!(
                "managed store task failed: {error}"
            ))
        })?
}

/// Serialize token reference admission with catalog deletion and configuration reload.
pub(super) async fn management_token_store_call<T, F>(
    state: &AppState,
    context: &ManagementContext,
    operation: F,
) -> Result<T, agent_access_core::ManagedStoreError>
where
    T: Send + 'static,
    F: FnOnce(
            agent_access_core::ManagedStore,
            Option<agent_access_core::ManagedResourceCatalog>,
        ) -> Result<T, agent_access_core::ManagedStoreError>
        + Send
        + 'static,
{
    state
        .reloadable
        .token_store_call_from_snapshot(context.snapshot.clone(), move |runtime| {
            let store = runtime.managed_store().cloned().ok_or_else(|| {
                agent_access_core::ManagedStoreError::Unavailable(
                    "managed store is unavailable".to_string(),
                )
            })?;
            let catalog = (runtime.config().policy.authority != "managed")
                .then(|| runtime.policy_resource_catalog_for_scope(&PolicyReadScope::Global));
            operation(store, catalog)
        })
        .await
}

pub(super) async fn management_store_call<T, F>(
    context: &ManagementContext,
    operation: F,
) -> Result<T, agent_access_core::ManagedStoreError>
where
    T: Send + 'static,
    F: FnOnce(agent_access_core::ManagedStore) -> Result<T, agent_access_core::ManagedStoreError>
        + Send
        + 'static,
{
    let Some(store) = context.snapshot.runtime.managed_store().cloned() else {
        return Err(agent_access_core::ManagedStoreError::Unavailable(
            "managed store is not configured".to_string(),
        ));
    };
    run_managed_store_blocking(move || operation(store)).await
}

pub(crate) fn delegated_policy_management_enabled(config: &BrokerConfig) -> bool {
    config.policy.authority == "managed"
}

/// Resolve all managed control-plane authority from one store snapshot, then
/// restrict delegated scopes to services in the current runtime configuration.
pub(crate) async fn effective_management_authority(
    snapshot: &RuntimeSnapshot,
    identity: &agent_access_core::IdentityContext,
) -> Result<ManagedManagementAuthority, agent_access_core::ManagedStoreError> {
    let store = snapshot.runtime.managed_store().cloned().ok_or_else(|| {
        agent_access_core::ManagedStoreError::Unavailable("managed store is not configured".into())
    })?;
    let principal = identity.principal.clone();
    let mut authority =
        run_managed_store_blocking(move || store.management_authority(&principal)).await?;
    let configured = snapshot
        .runtime
        .configured_service_capabilities()
        .into_iter()
        .map(|service| service.service)
        .collect::<BTreeSet<_>>();
    let enabled = delegated_policy_management_enabled(snapshot.runtime.config());
    if let PolicyReadScope::Services { services } = &mut authority.policy_read_scope {
        services.retain(|service| enabled && configured.contains(service));
    }
    if let PolicyWriteScope::Services { services } = &mut authority.policy_write_scope {
        services.retain(|service| enabled && configured.contains(service));
    }
    authority
        .authorities
        .retain(|entry| enabled && configured.contains(&entry.service));
    Ok(authority)
}

pub(crate) async fn management_context(
    state: &AppState,
    remote_addr: SocketAddr,
    headers: &HeaderMap,
    operation: &str,
    access: ManagementAccess,
) -> Result<ManagementContext, Box<axum::response::Response>> {
    observability::record_operation(operation);
    let request_id = match request_id_from_headers(headers, String::new(), operation.to_string()) {
        Ok(request_id) => request_id,
        Err(response) => return Err(Box::new(envelope_response(*response).into_response())),
    };
    let snapshot = state.reloadable.current();
    let broker_request_id = new_broker_request_id();
    observability::record_broker_request_id(&broker_request_id);
    let source = snapshot
        .source_resolver
        .source_context(remote_addr, headers);
    if !snapshot.runtime.config().management.enabled {
        let identity = agent_access_core::IdentityContext::anonymous();
        return Err(Box::new(
            management_pre_context_error_response(ManagementPreContextError {
                snapshot: &snapshot,
                request_id: &request_id,
                broker_request_id: &broker_request_id,
                operation,
                identity: &identity,
                source: &source,
                status: StatusCode::NOT_FOUND,
                reason_code: ReasonCode::ManagementDenied,
                message: "management routes are disabled",
            })
            .await,
        ));
    }
    let global_permit = match acquire_global_concurrency_guard(
        state,
        &snapshot,
        &request_id,
        "broker".to_string(),
        operation.to_string(),
        &source,
    )
    .await
    {
        Ok(permit) => permit,
        Err(response) => return Err(Box::new(envelope_response(*response).into_response())),
    };
    let mut browser_password_change_required = false;
    let identity_result = if !snapshot.runtime.has_configured_identity_header(headers) {
        match resolve_browser_cookie_identity_blocking(snapshot.clone(), headers.clone()).await {
            Ok(Some(cookie_identity)) => {
                browser_password_change_required = cookie_identity.password_change_required;
                Ok(cookie_identity.identity)
            }
            Ok(None) => resolve_identity_blocking(snapshot.clone(), headers.clone()).await,
            Err(failure) => Err(failure),
        }
    } else {
        resolve_identity_blocking(snapshot.clone(), headers.clone()).await
    };
    if !matches!(&identity_result, Ok(identity) if identity.authenticated) {
        check_auth_source_rate_guard(
            state,
            &snapshot,
            &request_id,
            "broker".to_string(),
            operation.to_string(),
            &source,
        )
        .await
        .map_err(|response| Box::new(envelope_response(*response).into_response()))?;
    }
    let identity = match identity_result {
        Ok(identity) if identity.authenticated => identity,
        Ok(_) => {
            let identity = agent_access_core::IdentityContext::anonymous();
            return Err(Box::new(
                management_pre_context_error_response(ManagementPreContextError {
                    snapshot: &snapshot,
                    request_id: &request_id,
                    broker_request_id: &broker_request_id,
                    operation,
                    identity: &identity,
                    source: &source,
                    status: StatusCode::UNAUTHORIZED,
                    reason_code: ReasonCode::IdentityRequired,
                    message: "authenticated identity is required",
                })
                .await,
            ));
        }
        Err(failure) => {
            let reason_code = failure.reason_code();
            let identity = agent_access_core::IdentityContext::anonymous();
            return Err(Box::new(
                management_pre_context_error_response(ManagementPreContextError {
                    snapshot: &snapshot,
                    request_id: &request_id,
                    broker_request_id: &broker_request_id,
                    operation,
                    identity: &identity,
                    source: &source,
                    status: StatusCode::from_u16(reason_code.http_status())
                        .unwrap_or(StatusCode::UNAUTHORIZED),
                    reason_code,
                    message: failure.message(),
                })
                .await,
            ));
        }
    };
    let browser_session_token_id = identity
        .source
        .as_ref()
        .filter(|source| source.name == "browser-session")
        .and_then(|source| source.token_id.clone());
    observability::record_principal(&identity.principal);
    let principal_permit = match acquire_caller_guard(
        state,
        &snapshot,
        &request_id,
        "broker".to_string(),
        operation.to_string(),
        &source,
        CallerAdmission {
            identity: &identity,
        },
    )
    .await
    {
        Ok(permit) => permit,
        Err(response) => return Err(Box::new(envelope_response(*response).into_response())),
    };
    let token_class = identity
        .source
        .as_ref()
        .and_then(|source| source.token_class.as_ref());
    let mut policy_management_scope = None;
    let mut policy_write_scope = None;
    let mut policy_management_authorities = Vec::new();
    let mut principal_role = None;
    let config = snapshot.runtime.config();
    // Credential class and principal authority are independent boundaries.
    // A user_manage bearer intentionally does not gain general admin access.
    let class_allowed = match access {
        ManagementAccess::User => {
            matches!(token_class, Some(BrokerTokenClass::UserManage))
                || (token_class.is_none() && config.management.allow_classless_user_management)
        }
        ManagementAccess::UserManageToken => {
            matches!(token_class, Some(BrokerTokenClass::UserManage))
        }
        ManagementAccess::AdminRead | ManagementAccess::AdminWrite => {
            matches!(token_class, Some(BrokerTokenClass::Admin))
                || (matches!(token_class, Some(BrokerTokenClass::UserManage))
                    && browser_session_token_id.is_some())
                || (token_class.is_none() && config.management.allow_classless_admin_identities)
        }
        ManagementAccess::PolicyRead | ManagementAccess::PolicyWrite => {
            matches!(
                token_class,
                Some(BrokerTokenClass::Admin | BrokerTokenClass::UserManage)
            ) || (token_class.is_none() && config.management.allow_classless_admin_identities)
        }
    };
    let personal = matches!(
        access,
        ManagementAccess::User | ManagementAccess::UserManageToken
    );
    let admission = if !class_allowed {
        Err((
            ReasonCode::BrokerTokenClassDenied,
            "credential class cannot access this management route",
        ))
    } else if token_class.is_none() && !personal {
        if management_admin_authorized(config, &identity) {
            policy_management_scope = Some(PolicyReadScope::Global);
            if matches!(
                access,
                ManagementAccess::AdminWrite | ManagementAccess::PolicyWrite
            ) {
                policy_write_scope = Some(PolicyWriteScope::Global);
            }
            Ok(())
        } else {
            Err((
                ReasonCode::ManagementDenied,
                "identity is not a configured classless administrator",
            ))
        }
    } else {
        match effective_management_authority(&snapshot, &identity).await {
            Err(error) => Err((
                error.reason_code(),
                "managed authority could not be resolved",
            )),
            Ok(authority) => {
                let role = authority.principal.role;
                principal_role = Some(role);
                let global_read = matches!(role, PrincipalRole::Admin | PrincipalRole::Auditor)
                    && authority.principal.kind == "user";
                let global_write =
                    role == PrincipalRole::Admin && authority.principal.kind == "user";
                let read_allowed = match &authority.policy_read_scope {
                    PolicyReadScope::Global => true,
                    PolicyReadScope::Services { services } => !services.is_empty(),
                };
                let write_allowed = match &authority.policy_write_scope {
                    PolicyWriteScope::Global => true,
                    PolicyWriteScope::Services { services } => !services.is_empty(),
                };
                let allowed = match access {
                    ManagementAccess::User | ManagementAccess::UserManageToken => {
                        authority.principal.self_service_enabled
                    }
                    ManagementAccess::AdminRead => global_read,
                    ManagementAccess::AdminWrite => global_write,
                    ManagementAccess::PolicyRead => {
                        read_allowed
                            && (!matches!(token_class, Some(BrokerTokenClass::Admin))
                                || global_read)
                    }
                    ManagementAccess::PolicyWrite => {
                        write_allowed
                            && (!matches!(token_class, Some(BrokerTokenClass::Admin))
                                || global_write)
                    }
                };
                if !allowed {
                    if personal {
                        Err((
                            ReasonCode::SelfServiceDisabled,
                            "self-service access is disabled",
                        ))
                    } else {
                        Err((
                            ReasonCode::ManagementDenied,
                            "principal role does not permit this operation",
                        ))
                    }
                } else {
                    if !personal {
                        policy_management_scope = Some(authority.policy_read_scope);
                        // Only admitted writes receive a write scope; a read handler
                        // cannot accidentally use the actor's broader write authority.
                        if matches!(
                            access,
                            ManagementAccess::AdminWrite | ManagementAccess::PolicyWrite
                        ) {
                            policy_write_scope = Some(authority.policy_write_scope);
                        }
                        policy_management_authorities = authority.authorities;
                    }
                    Ok(())
                }
            }
        }
    };
    if let Err((reason_code, message)) = admission {
        return Err(Box::new(
            management_pre_context_error_response(ManagementPreContextError {
                snapshot: &snapshot,
                request_id: &request_id,
                broker_request_id: &broker_request_id,
                operation,
                identity: &identity,
                source: &source,
                status: StatusCode::from_u16(reason_code.http_status())
                    .unwrap_or(StatusCode::FORBIDDEN),
                reason_code,
                message,
            })
            .await,
        ));
    }
    if browser_session_token_id.is_some() && browser_password_change_required {
        return Err(Box::new(
            management_pre_context_error_response(ManagementPreContextError {
                snapshot: &snapshot,
                request_id: &request_id,
                broker_request_id: &broker_request_id,
                operation,
                identity: &identity,
                source: &source,
                status: StatusCode::FORBIDDEN,
                reason_code: ReasonCode::PasswordChangeRequired,
                message: "password change is required before management",
            })
            .await,
        ));
    }
    if let Some(token_id) = browser_session_token_id.as_deref()
        && management_cookie_csrf_required(operation)
        && !csrf_header_valid(&snapshot, headers, token_id)
    {
        return Err(Box::new(
            management_pre_context_error_response(ManagementPreContextError {
                snapshot: &snapshot,
                request_id: &request_id,
                broker_request_id: &broker_request_id,
                operation,
                identity: &identity,
                source: &source,
                status: StatusCode::FORBIDDEN,
                reason_code: ReasonCode::CsrfInvalid,
                message: "CSRF token is invalid",
            })
            .await,
        ));
    }
    Ok(ManagementContext {
        snapshot,
        request_id,
        broker_request_id,
        identity,
        source,
        policy_management_scope,
        policy_write_scope,
        principal_role,
        credential_purpose: if personal {
            agent_access_core::CredentialManagementPurpose::Personal
        } else {
            agent_access_core::CredentialManagementPurpose::Administrative
        },
        policy_management_authorities,
        _permits: RequestPermits {
            _global: global_permit,
            _principal: principal_permit,
        },
    })
}

fn management_cookie_csrf_required(operation: &str) -> bool {
    !matches!(
        operation,
        "admin.imports.list"
            | "admin.imports.inspect"
            | "admin.imports.preview"
            | "credentials.list"
            | "oauth.connections.list"
            | "oauth.connections.callback"
            | "credentials.inspect"
            | "credentials.input_schema"
            | "credentials.targets"
            | "tokens.list"
            | "tokens.inspect"
            | "admin.store.status"
            | "config.status"
            | "admin.policy.status"
            | "admin.policy.catalog"
            | "admin.policy.grants.list"
            | "admin.policy.grants.inspect"
            | "admin.policy.grants.export"
            | "admin.policy.service_managers.list"
            | "admin.principals.list"
            | "admin.principals.inspect"
            | "admin.principals.services"
            | "admin.principals.service_limits.list"
            | "admin.principals.login_methods.list"
            | "admin.groups.list"
            | "admin.groups.inspect"
            | "admin.groups.members.list"
            | "admin.groups.external_group_bindings.list"
            | "admin.rights.list"
            | "admin.tokens.list"
            | "admin.tokens.inspect"
            | "admin.tokens.list_principal_agent"
            | "admin.tokens.inspect_principal_agent"
            | "admin.credentials.list"
            | "admin.credentials.inspect"
            | "admin.credentials.input_schema"
            | "admin.credentials.targets"
            | "admin.audit.options"
            | "audit.options"
            | "admin.audit.events.list"
            | "admin.audit.requests.inspect"
            | "audit.events.list"
            | "audit.requests.inspect"
    )
}

pub(crate) fn management_admin_authorized(
    config: &BrokerConfig,
    identity: &agent_access_core::IdentityContext,
) -> bool {
    config
        .management
        .admin_principals
        .iter()
        .any(|principal| principal == &identity.principal)
        || identity.policy_groups.iter().any(|group| {
            config
                .management
                .admin_groups
                .iter()
                .any(|admin_group| admin_group == group)
        })
}

pub(super) fn is_broker_user_manage_context(context: &ManagementContext) -> bool {
    context
        .identity
        .source
        .as_ref()
        .and_then(|source| source.token_class.as_ref())
        == Some(&BrokerTokenClass::UserManage)
}

pub(crate) fn management_error_envelope(
    request_id: &str,
    broker_request_id: &str,
    operation: &str,
    principal: &str,
    reason_code: impl Into<ReasonCodeId>,
    message: &str,
    target: Option<Value>,
) -> ManagementEnvelope {
    ManagementEnvelope {
        ok: false,
        decision: Decision::Deny,
        reason_code: Some(reason_code.into()),
        request_id: request_id.to_string(),
        broker_request_id: broker_request_id.to_string(),
        operation: operation.to_string(),
        principal: principal.to_string(),
        target,
        result: None,
        error: Some(agent_access_core::ErrorBody {
            message: message.to_string(),
        }),
    }
}

pub(crate) fn management_failure_envelope(
    context: &ManagementContext,
    operation: &str,
    decision: Decision,
    reason_code: impl Into<ReasonCodeId>,
    message: &str,
    target: Option<Value>,
) -> ManagementEnvelope {
    ManagementEnvelope {
        ok: false,
        decision,
        reason_code: Some(reason_code.into()),
        request_id: context.request_id.clone(),
        broker_request_id: context.broker_request_id.clone(),
        operation: operation.to_string(),
        principal: context.identity.principal.clone(),
        target,
        result: None,
        error: Some(agent_access_core::ErrorBody {
            message: message.to_string(),
        }),
    }
}

pub(crate) fn management_success_envelope(
    context: &ManagementContext,
    operation: &str,
    target: Option<Value>,
    result: Value,
) -> ManagementEnvelope {
    ManagementEnvelope {
        ok: true,
        decision: Decision::Allow,
        reason_code: None,
        request_id: context.request_id.clone(),
        broker_request_id: context.broker_request_id.clone(),
        operation: operation.to_string(),
        principal: context.identity.principal.clone(),
        target,
        result: Some(result),
        error: None,
    }
}

pub(crate) fn management_response(
    status: StatusCode,
    envelope: ManagementEnvelope,
) -> axum::response::Response {
    observability::record_request_ids(&envelope.request_id, &envelope.broker_request_id);
    observability::record_operation(&envelope.operation);
    observability::record_principal(&envelope.principal);
    observability::record_decision(envelope.decision.as_str());
    if let Some(reason_code) = &envelope.reason_code {
        observability::record_reason_code(reason_code.as_str());
    }
    observability::record_status(status.as_u16());
    let mut response = (status, Json(&envelope)).into_response();
    response.headers_mut().insert(
        axum::http::header::CACHE_CONTROL,
        axum::http::HeaderValue::from_static("no-store"),
    );
    if let Some(retry_after) =
        crate::handlers::common::retry_after_header(status.as_u16(), envelope.result.as_ref())
    {
        response
            .headers_mut()
            .insert(axum::http::header::RETRY_AFTER, retry_after);
    }
    response
}

/// Management operations whose successful responses write nothing to audit
/// and emit no replacement log event. Each is a plain read of data the
/// caller may see: it returns no secret material, calls no upstream, and
/// changes no state. Auditing them would add records for every portal page
/// load and refresh, and because audit is fail-closed these reads would stop
/// working exactly when audit writes fail.
///
/// Only the success is unaudited: denials and failures of these operations
/// (authorization, invalid input, not found, store errors, and so on) stay on
/// the audited error path. Every operation not listed here is audited when it
/// succeeds, so a new route is audited until it is deliberately added. The
/// names are the operation names handlers write to responses and audit
/// records, which for some routes differ from the catalog operation id; the
/// classification test maps them.
pub(crate) const UNAUDITED_READ_OPERATIONS: &[&str] = &[
    // Self-service.
    "auth.session",
    "tokens.list",
    "tokens.inspect",
    "tokens.options",
    "tokens.effective_access",
    "credentials.list",
    "credentials.inspect",
    "credentials.targets",
    "credentials.input_schema",
    "oauth.connections.list",
    "audit.options",
    "audit.events.list",
    "audit.requests.inspect",
    // Administration and status.
    "admin.imports.list",
    "admin.imports.inspect",
    "admin.imports.preview",
    "config.status",
    "admin.store.status",
    "admin.principals.list",
    "admin.principals.inspect",
    "admin.principals.services",
    "admin.principals.login_methods.list",
    "admin.principals.service_limits.list",
    "admin.principals.identity_token.inspect",
    "admin.principals.identity_access.inspect",
    "admin.principals.identity_bindings.list",
    "admin.groups.list",
    "admin.groups.inspect",
    "admin.groups.members.list",
    "admin.groups.external_group_bindings.list",
    "admin.rights.list",
    "admin.tokens.list",
    "admin.tokens.inspect",
    "admin.tokens.list_principal_agent",
    "admin.tokens.inspect_principal_agent",
    "admin.tokens.options_principal_agent",
    "admin.tokens.effective_access_principal_agent",
    "admin.credentials.list",
    "admin.credentials.inspect",
    "admin.credentials.targets",
    "admin.credentials.input_schema",
    // Policy, including the read-only POST dry runs.
    "admin.policy.status",
    "admin.policy.catalog",
    "admin.policy.grants.list",
    "admin.policy.grants.inspect",
    "admin.policy.grants.validate",
    "admin.policy.service_managers.list",
    "admin.policy.effective_access",
    "admin.policy.resources.list",
    "admin.policy.resources.get",
    "admin.policy.resources.used_by",
    "admin.policy.resource_groups.list",
    "admin.policy.resource_groups.get",
    "admin.policy.resource_groups.used_by",
    "admin.audit.options",
    "admin.audit.events.list",
    "admin.audit.requests.inspect",
];

/// Reads that stay audited when they succeed: they return plaintext secrets
/// or the whole policy, send stored secrets upstream, or complete an OAuth
/// connection. Only the classification test uses this list, to require an
/// explicit decision for every read route.
#[cfg(test)]
pub(crate) const AUDITED_READ_OPERATIONS: &[&str] = &[
    "admin.principals.identity_token.reveal",
    "admin.policy.resources.attribute.reveal",
    "admin.policy.grants.export",
    "credentials.verify",
    "admin.credentials.verify",
    "oauth.connections.callback",
];

/// POST routes that read rather than change state. A method cannot
/// reveal them, so they are named here and classified like GET reads.
#[cfg(test)]
pub(crate) const READ_ONLY_POST_CATALOG_OPERATIONS: &[&str] = &[
    "tokens.effective_access",
    "admin.tokens.effective_access_principal_agent",
    "admin.policy.effective_access",
    "admin.policy.grants.validate",
    "admin.principals.identity_token.reveal",
    "admin.policy.resources.attribute.reveal",
    "credentials.verify",
    "admin.credentials.verify",
    "admin.principals.credentials.verify",
];

/// Classified reads the catalog does not list: the browser session probe
/// (an auth envelope route) and the OAuth provider redirect.
#[cfg(test)]
pub(crate) const NON_CATALOG_READ_OPERATIONS: &[&str] =
    &["auth.session", "oauth.connections.callback"];

#[cfg(test)]
pub(crate) use super::audit_actions::{CATALOG_TO_HANDLER_OPERATION, handler_operation};

/// Whether a successful `operation` is answered without an audit record.
pub(crate) fn is_unaudited_read(operation: &str) -> bool {
    UNAUDITED_READ_OPERATIONS.contains(&operation)
}

/// The response of a successful management operation that wrote no
/// preflight record. An operation in [`UNAUDITED_READ_OPERATIONS`] is
/// answered without touching the audit writer; any other operation first
/// appends its success record and fails closed with `audit_unavailable`.
pub(crate) async fn management_success_response<R: Serialize>(
    context: &ManagementContext,
    operation: &str,
    target: Option<Value>,
    result: R,
) -> axum::response::Response {
    if !is_unaudited_read(operation) {
        // The record carries the operation, decision, and target, never the result.
        let record = management_success_envelope(context, operation, target.clone(), Value::Null);
        if let Err(error) = append_management_audit_with_details(
            ManagementAuditContext {
                snapshot: &context.snapshot,
                request_id: &context.request_id,
                broker_request_id: &context.broker_request_id,
                identity: &context.identity,
                source: &context.source,
            },
            &record,
            ManagementAuditExtra {
                catalog_change: None,
                phase: None,
                verification: None,
            },
            context.policy_management_scope.as_ref(),
            context.principal_role,
            &context.policy_management_authorities,
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
    }
    #[derive(Serialize)]
    #[serde(rename_all = "camelCase")]
    struct SuccessEnvelope<'a, R> {
        ok: bool,
        decision: Decision,
        request_id: &'a str,
        broker_request_id: &'a str,
        operation: &'a str,
        principal: &'a str,
        #[serde(skip_serializing_if = "Option::is_none")]
        target: Option<Value>,
        result: R,
    }
    observability::record_request_ids(&context.request_id, &context.broker_request_id);
    observability::record_operation(operation);
    observability::record_principal(&context.identity.principal);
    observability::record_decision(Decision::Allow.as_str());
    observability::record_status(StatusCode::OK.as_u16());
    (
        StatusCode::OK,
        [(axum::http::header::CACHE_CONTROL, "no-store")],
        Json(SuccessEnvelope {
            ok: true,
            decision: Decision::Allow,
            request_id: &context.request_id,
            broker_request_id: &context.broker_request_id,
            operation,
            principal: &context.identity.principal,
            target,
            result,
        }),
    )
        .into_response()
}

pub(super) fn management_pre_audited_success_response(
    context: &ManagementContext,
    operation: &str,
    target: Option<Value>,
    result: Value,
) -> axum::response::Response {
    let envelope = management_success_envelope(context, operation, target, result);
    management_response(StatusCode::OK, envelope)
}

pub(crate) async fn management_write_audit_preflight(
    context: &ManagementContext,
    operation: &str,
    target: Option<Value>,
) -> Result<(), Box<axum::response::Response>> {
    let envelope = management_success_envelope(context, operation, target, Value::Null);
    append_management_audit_with_details(
        ManagementAuditContext {
            snapshot: &context.snapshot,
            request_id: &context.request_id,
            broker_request_id: &context.broker_request_id,
            identity: &context.identity,
            source: &context.source,
        },
        &envelope,
        ManagementAuditExtra {
            catalog_change: None,
            phase: Some("preflight"),
            verification: None,
        },
        context.policy_management_scope.as_ref(),
        context.principal_role,
        &context.policy_management_authorities,
    )
    .await
    .map_err(|error| {
        Box::new(management_audit_unavailable_response(
            &context.request_id,
            &context.broker_request_id,
            operation,
            &context.identity.principal,
            error,
        ))
    })
}

pub(super) async fn management_write_audit_completion(
    context: &ManagementContext,
    operation: &str,
    target: Option<Value>,
) -> Result<(), Box<axum::response::Response>> {
    append_management_write_completion(context, operation, target)
        .await
        .map_err(|error| {
            Box::new(management_audit_unavailable_response(
                &context.request_id,
                &context.broker_request_id,
                operation,
                &context.identity.principal,
                error,
            ))
        })
}

/// An already committed write with a successful mandatory preflight must keep
/// its truthful success response if the supplemental completion audit fails.
pub(super) async fn management_committed_write_audit_completion(
    context: &ManagementContext,
    operation: &str,
    target: Option<Value>,
) {
    if append_management_write_completion(context, operation, target)
        .await
        .is_err()
    {
        tracing::error!(
            event = "management_committed_write_audit_append_failed",
            operation,
            agentRequestId = context.request_id.as_str(),
            brokerRequestId = context.broker_request_id.as_str(),
            reasonCode = ReasonCode::AuditUnavailable.as_str(),
            "committed management write succeeded; completion audit is unavailable",
        );
    }
}

/// Append the safe change captured by the managed-store transaction. The caller
/// owns this future past HTTP cancellation, and never turns a committed write
/// into a retry-inviting failure when the supplemental audit is unavailable.
pub(super) async fn management_committed_catalog_audit_completion<T>(
    context: &ManagementContext,
    operation: &str,
    result: &agent_access_core::ManagedCatalogMutationResult<T>,
) {
    let envelope = management_success_envelope(
        context,
        operation,
        Some(json!(result.audit.target())),
        Value::Null,
    );
    let mut change = json!(result.audit);
    change["previousRevision"] = json!(result.previous_revision);
    change["revision"] = json!(result.revision);
    if append_management_audit_with_details(
        ManagementAuditContext {
            snapshot: &context.snapshot,
            request_id: &context.request_id,
            broker_request_id: &context.broker_request_id,
            identity: &context.identity,
            source: &context.source,
        },
        &envelope,
        ManagementAuditExtra {
            catalog_change: Some(&change),
            phase: Some("success"),
            verification: None,
        },
        context.policy_management_scope.as_ref(),
        context.principal_role,
        &context.policy_management_authorities,
    )
    .await
    .is_err()
    {
        tracing::error!(
            event = "management_committed_write_audit_append_failed",
            operation,
            agentRequestId = context.request_id.as_str(),
            brokerRequestId = context.broker_request_id.as_str(),
            reasonCode = ReasonCode::AuditUnavailable.as_str(),
            "committed management write succeeded; completion audit is unavailable",
        );
    }
}

async fn append_management_write_completion(
    context: &ManagementContext,
    operation: &str,
    target: Option<Value>,
) -> Result<(), RuntimeError> {
    let envelope = management_success_envelope(context, operation, target, Value::Null);
    append_management_audit_with_details(
        ManagementAuditContext {
            snapshot: &context.snapshot,
            request_id: &context.request_id,
            broker_request_id: &context.broker_request_id,
            identity: &context.identity,
            source: &context.source,
        },
        &envelope,
        ManagementAuditExtra {
            catalog_change: None,
            phase: Some("success"),
            verification: None,
        },
        context.policy_management_scope.as_ref(),
        context.principal_role,
        &context.policy_management_authorities,
    )
    .await
}

/// What a credential verification adds to its audit record: the provider's
/// `providerAudit.verification` details and the upstream status and
/// duration, which a command import, having no upstream status, leaves
/// `null`.
#[derive(Clone, Copy)]
pub(super) struct VerificationAudit<'a> {
    pub(super) audit: &'a Value,
    pub(super) upstream_status: Option<u16>,
    pub(super) upstream_duration_ms: Option<u64>,
}

impl<'a> VerificationAudit<'a> {
    /// A successful verification's audit; `command` marks a command
    /// import's, whose status is not an upstream one.
    pub(super) fn verified(
        verification: &'a ProviderCredentialVerification,
        command: bool,
    ) -> Self {
        Self {
            audit: &verification.audit,
            upstream_status: (!command).then_some(verification.upstream_status),
            upstream_duration_ms: Some(verification.upstream_duration_ms),
        }
    }
}

pub(super) async fn management_write_audit_upstream_verification(
    context: &ManagementContext,
    operation: &str,
    target: Option<Value>,
    verification: VerificationAudit<'_>,
) -> Result<(), Box<axum::response::Response>> {
    let envelope = management_success_envelope(context, operation, target, Value::Null);
    append_management_audit_with_details(
        ManagementAuditContext {
            snapshot: &context.snapshot,
            request_id: &context.request_id,
            broker_request_id: &context.broker_request_id,
            identity: &context.identity,
            source: &context.source,
        },
        &envelope,
        ManagementAuditExtra {
            catalog_change: None,
            phase: Some("upstream_verification"),
            verification: Some(verification),
        },
        context.policy_management_scope.as_ref(),
        context.principal_role,
        &context.policy_management_authorities,
    )
    .await
    .map_err(|error| {
        Box::new(management_audit_unavailable_response(
            &context.request_id,
            &context.broker_request_id,
            operation,
            &context.identity.principal,
            error,
        ))
    })
}

pub(super) async fn management_audited_response(
    context: &ManagementContext,
    status: StatusCode,
    envelope: ManagementEnvelope,
) -> axum::response::Response {
    match append_management_audit_with_details(
        ManagementAuditContext {
            snapshot: &context.snapshot,
            request_id: &context.request_id,
            broker_request_id: &context.broker_request_id,
            identity: &context.identity,
            source: &context.source,
        },
        &envelope,
        ManagementAuditExtra {
            catalog_change: None,
            phase: None,
            verification: None,
        },
        context.policy_management_scope.as_ref(),
        context.principal_role,
        &context.policy_management_authorities,
    )
    .await
    {
        Ok(()) => management_response(status, envelope),
        Err(error) => management_audit_unavailable_response(
            &context.request_id,
            &context.broker_request_id,
            &envelope.operation,
            &context.identity.principal,
            error,
        ),
    }
}

struct ManagementPreContextError<'a> {
    snapshot: &'a RuntimeSnapshot,
    request_id: &'a str,
    broker_request_id: &'a str,
    operation: &'a str,
    identity: &'a agent_access_core::IdentityContext,
    source: &'a SourceContext,
    status: StatusCode,
    reason_code: ReasonCode,
    message: &'a str,
}

async fn management_pre_context_error_response(
    input: ManagementPreContextError<'_>,
) -> axum::response::Response {
    let envelope = management_error_envelope(
        input.request_id,
        input.broker_request_id,
        input.operation,
        &input.identity.principal,
        input.reason_code,
        input.message,
        None,
    );
    match append_management_audit(
        input.snapshot,
        input.request_id,
        input.broker_request_id,
        input.identity,
        input.source,
        &envelope,
    )
    .await
    {
        Ok(()) => management_response(input.status, envelope),
        Err(error) => management_audit_unavailable_response(
            input.request_id,
            input.broker_request_id,
            input.operation,
            &input.identity.principal,
            error,
        ),
    }
}

pub(super) async fn append_management_audit(
    snapshot: &RuntimeSnapshot,
    request_id: &str,
    broker_request_id: &str,
    identity: &agent_access_core::IdentityContext,
    source: &SourceContext,
    envelope: &ManagementEnvelope,
) -> Result<(), RuntimeError> {
    append_management_audit_with_phase(
        snapshot,
        request_id,
        broker_request_id,
        identity,
        source,
        envelope,
        ManagementAuditExtra {
            catalog_change: None,
            phase: None,
            verification: None,
        },
    )
    .await
}

pub(super) struct ManagementAuditExtra<'a> {
    pub(super) catalog_change: Option<&'a Value>,
    pub(super) phase: Option<&'a str>,
    pub(super) verification: Option<VerificationAudit<'a>>,
}

pub(super) async fn append_management_audit_with_phase(
    snapshot: &RuntimeSnapshot,
    request_id: &str,
    broker_request_id: &str,
    identity: &agent_access_core::IdentityContext,
    source: &SourceContext,
    envelope: &ManagementEnvelope,
    extra: ManagementAuditExtra<'_>,
) -> Result<(), RuntimeError> {
    append_management_audit_with_details(
        ManagementAuditContext {
            snapshot,
            request_id,
            broker_request_id,
            identity,
            source,
        },
        envelope,
        extra,
        None,
        None,
        &[],
    )
    .await
}

struct ManagementAuditContext<'a> {
    snapshot: &'a RuntimeSnapshot,
    request_id: &'a str,
    broker_request_id: &'a str,
    identity: &'a agent_access_core::IdentityContext,
    source: &'a SourceContext,
}

async fn append_management_audit_with_details(
    context: ManagementAuditContext<'_>,
    envelope: &ManagementEnvelope,
    extra: ManagementAuditExtra<'_>,
    policy_management_scope: Option<&PolicyReadScope>,
    principal_role: Option<PrincipalRole>,
    policy_management_authorities: &[EffectiveServicePolicyManagementAuthority],
) -> Result<(), RuntimeError> {
    let ManagementAuditContext {
        snapshot,
        request_id,
        broker_request_id,
        identity,
        source,
    } = context;
    let mut management = serde_json::Map::new();
    management.insert("operation".to_string(), json!(envelope.operation));
    management.insert("target".to_string(), json!(envelope.target));
    management.insert("reasonCode".to_string(), json!(envelope.reason_code));
    if let Some(change) = extra.catalog_change {
        management.insert("change".to_string(), change.clone());
    }
    if let Some(phase) = extra.phase {
        management.insert("phase".to_string(), json!(phase));
    }
    if let Some(scope) = policy_management_scope {
        let (target_service, service_specific) = audit_target_service(snapshot, envelope).await;
        for (key, value) in
            policy_management_audit_target_metadata(scope, target_service.as_deref())
        {
            management.insert(key, value);
        }
        let basis = policy_management_authorization_basis(
            scope,
            principal_role,
            policy_management_authorities,
            target_service.as_deref(),
            service_specific,
        );
        management.insert("authorizationBasis".to_string(), json!(basis));
    } else if let Some(target_service) = admin_target_service(envelope) {
        management.insert("targetService".to_string(), json!(target_service));
    }
    if !policy_management_authorities.is_empty() {
        management.insert(
            "authorizationAssignments".to_string(),
            json!(policy_management_authorities),
        );
    }
    let mut provider_audit = serde_json::Map::new();
    provider_audit.insert("management".to_string(), Value::Object(management));
    if let Some(verification) = extra.verification {
        provider_audit.insert("verification".to_string(), verification.audit.clone());
    }
    let record = AuditRecord {
        caller_id: identity.caller_id.clone(),
        search_authorization: None,
        timestamp: Utc::now().to_rfc3339(),
        agent_request_id: request_id.to_string(),
        broker_request_id: broker_request_id.to_string(),
        config_generation: Some(snapshot.generation),
        policy_generation: Some(snapshot.runtime.policy_generation()),
        principal: identity.principal.clone(),
        principal_subject: identity.principal_subject.clone(),
        groups: identity.groups.clone(),
        service: "broker".to_string(),
        action: envelope.operation.clone(),
        resource_scopes: ResourceScopes::new(),
        matched_grant: None,
        credential_mode: Some(None),
        decision: envelope.decision.clone(),
        reason_code: envelope.reason_code.clone(),
        upstream_status: extra
            .verification
            .and_then(|verification| verification.upstream_status),
        upstream_duration_ms: extra
            .verification
            .and_then(|verification| verification.upstream_duration_ms),
        object_ids: None,
        identity_source: identity.source.clone(),
        source: source.clone(),
        execution_context: None,
        provider_audit: Some(Value::Object(provider_audit)),
    };
    snapshot.runtime.append_audit_record(&record).await
}

/// The service an admin operation acts on, taken from its target, so admin
/// records carry `targetService` like policy-management records do and are
/// visible to that service's policy managers. Self-service operations are
/// excluded: a user's own actions stay out of service managers' view.
fn admin_target_service(envelope: &ManagementEnvelope) -> Option<&str> {
    if !envelope.operation.starts_with("admin.") {
        return None;
    }
    envelope
        .target
        .as_ref()?
        .get("service")?
        .as_str()
        .filter(|service| !service.is_empty())
}

fn policy_management_audit_target_metadata(
    scope: &PolicyReadScope,
    target_service: Option<&str>,
) -> serde_json::Map<String, Value> {
    let mut metadata = serde_json::Map::new();
    if let Some(target_service) = target_service {
        metadata.insert("targetService".to_string(), json!(target_service));
        if matches!(scope, PolicyReadScope::Services { .. })
            && !scope.authorizes_service(target_service)
        {
            metadata.insert(
                "authorizationDeniedReason".to_string(),
                json!("service_out_of_scope"),
            );
        }
    }
    metadata
}

async fn audit_target_service(
    snapshot: &RuntimeSnapshot,
    envelope: &ManagementEnvelope,
) -> (Option<String>, bool) {
    let Some(target) = envelope.target.as_ref() else {
        return (None, false);
    };
    if let Some(service) = target.get("service").and_then(Value::as_str) {
        return (Some(service.to_string()), true);
    }
    let Some(grant_ref) = target.get("grantRef").and_then(Value::as_str) else {
        return (None, false);
    };
    if snapshot.runtime.config().policy.authority != "managed" {
        return (None, true);
    }
    let Some(store) = snapshot.runtime.managed_store().cloned() else {
        return (None, true);
    };
    let grant_ref = grant_ref.to_string();
    let service = run_managed_store_blocking(move || store.policy_grant(&grant_ref))
        .await
        .ok()
        .map(|grant| grant.service);
    (service, true)
}

fn policy_management_authorization_basis(
    scope: &PolicyReadScope,
    role: Option<PrincipalRole>,
    authorities: &[EffectiveServicePolicyManagementAuthority],
    target_service: Option<&str>,
    service_specific: bool,
) -> String {
    if matches!(scope, PolicyReadScope::Global) {
        return if role == Some(PrincipalRole::Auditor) {
            "global_auditor"
        } else {
            "global_admin"
        }
        .to_string();
    }
    let authority = if service_specific {
        target_service.and_then(|service| {
            authorities
                .iter()
                .find(|authority| authority.service == service)
        })
    } else {
        authorities.first()
    };
    authority
        .map(|authority| format!("direct_assignment:{}", authority.assignment_id))
        .unwrap_or_else(|| "delegated_assignment".to_string())
}

pub(crate) fn management_audit_unavailable_response(
    request_id: &str,
    broker_request_id: &str,
    operation: &str,
    principal: &str,
    error: RuntimeError,
) -> axum::response::Response {
    tracing::error!(
        event = "management_audit_append_failed",
        operation,
        agentRequestId = request_id,
        brokerRequestId = broker_request_id,
        principal,
        decision = Decision::Error.as_str(),
        reasonCode = ReasonCode::AuditUnavailable.as_str(),
        error = %error,
    );
    management_response(
        StatusCode::SERVICE_UNAVAILABLE,
        management_error_envelope(
            request_id,
            broker_request_id,
            operation,
            principal,
            ReasonCode::AuditUnavailable,
            "audit sink is unavailable",
            None,
        ),
    )
}

pub(crate) async fn management_context_error_response(
    context: &ManagementContext,
    status: StatusCode,
    operation: &str,
    reason_code: impl Into<ReasonCodeId>,
    message: &str,
    target: Option<Value>,
) -> axum::response::Response {
    let envelope = management_error_envelope(
        &context.request_id,
        &context.broker_request_id,
        operation,
        &context.identity.principal,
        reason_code,
        message,
        target,
    );
    management_audited_response(context, status, envelope).await
}

pub(super) async fn management_store_error_response(
    context: &ManagementContext,
    operation: &str,
    target: Option<Value>,
    error: agent_access_core::ManagedStoreError,
) -> axum::response::Response {
    let reason_code = error.reason_code();
    let status = StatusCode::from_u16(reason_code.http_status())
        .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    if matches!(
        error,
        agent_access_core::ManagedStoreError::Unavailable(_)
            | agent_access_core::ManagedStoreError::SchemaInvalid(_)
            | agent_access_core::ManagedStoreError::PolicyAuthorityUnavailable(_)
            | agent_access_core::ManagedStoreError::EncryptionKeyMissing(_)
            | agent_access_core::ManagedStoreError::EncryptionKeyInvalid(_)
    ) {
        tracing::warn!(operation, request_id = %context.request_id,
            broker_request_id = %context.broker_request_id, error = %error,
            "management store operation failed");
    }
    let mut details = serde_json::Map::new();
    match &error {
        agent_access_core::ManagedStoreError::ResourceConflict(existing) => {
            details.insert("conflict".into(), json!(existing));
        }
        // The grants or resources an import change would leave invalid.
        agent_access_core::ManagedStoreError::ImportChangeBlocked(blocked) => {
            if let Value::Object(lists) = json!(blocked) {
                details.extend(lists.into_iter().filter(|(key, _)| key != "message"));
            }
        }
        _ => {}
    }
    let target = if details.is_empty() {
        target
    } else {
        let mut target = target
            .and_then(|value| value.as_object().cloned())
            .unwrap_or_default();
        target.extend(details);
        Some(Value::Object(target))
    };
    let message = management_store_public_error_message(operation, &error);
    management_context_error_response(context, status, operation, reason_code, &message, target)
        .await
}

pub(super) fn management_store_public_error_message(
    _operation: &str,
    error: &agent_access_core::ManagedStoreError,
) -> String {
    match error {
        agent_access_core::ManagedStoreError::Unavailable(_) => {
            "managed store is unavailable".to_string()
        }
        agent_access_core::ManagedStoreError::SchemaInvalid(_) => {
            "managed store schema is invalid".to_string()
        }
        agent_access_core::ManagedStoreError::PolicyAuthorityUnavailable(_) => {
            "policy authority is unavailable".to_string()
        }
        agent_access_core::ManagedStoreError::EncryptionKeyMissing(_) => {
            "credential encryption key is unavailable".to_string()
        }
        agent_access_core::ManagedStoreError::EncryptionKeyInvalid(_) => {
            "credential encryption key is invalid".to_string()
        }
        _ => error.to_string(),
    }
}

/// Reports a host failure, such as a store read or import preparation, with
/// management's own decision for it, deny, and its reason's status.
pub(super) async fn management_host_error_response(
    context: &ManagementContext,
    operation: &str,
    target: Option<Value>,
    reason_code: impl Into<ProviderReason>,
    message: &str,
) -> axum::response::Response {
    let reason_code = reason_code.into();
    let status = StatusCode::from_u16(reason_code.http_status())
        .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    management_context_error_response(context, status, operation, reason_code, message, target)
        .await
}

/// Reports a failed provider hook or adapter discovery, a host port acting
/// for one, or the gateway's upstream credential verification, with the
/// failure's own outcome: a domain reason's or host port's fixed decision and
/// status, or a standard reason's deny or error. The response and its audit
/// record carry the same decision. A management failure never reports allow,
/// which only an invocation's verification result may carry, so an allow
/// outcome is reported as deny.
pub(super) async fn management_provider_error_response(
    context: &ManagementContext,
    operation: &str,
    target: Option<Value>,
    error: ProviderError,
) -> axum::response::Response {
    let (status, envelope) = provider_error_envelope(context, operation, target, &error);
    management_audited_response(context, status, envelope).await
}

/// A failed credential verification's response, whose audit record keeps
/// what the verification reported, such as a command's process facts, under
/// `providerAudit.verification`, with its upstream status and duration.
pub(super) async fn management_verification_error_response(
    context: &ManagementContext,
    operation: &str,
    target: Option<Value>,
    error: ProviderError,
) -> axum::response::Response {
    let (status, envelope) = provider_error_envelope(context, operation, target, &error);
    let Some(audit) = error.audit.as_deref() else {
        return management_audited_response(context, status, envelope).await;
    };
    let verification = VerificationAudit {
        audit,
        upstream_status: error.upstream_status,
        upstream_duration_ms: error.upstream_duration_ms,
    };
    match append_management_audit_with_details(
        ManagementAuditContext {
            snapshot: &context.snapshot,
            request_id: &context.request_id,
            broker_request_id: &context.broker_request_id,
            identity: &context.identity,
            source: &context.source,
        },
        &envelope,
        ManagementAuditExtra {
            catalog_change: None,
            phase: None,
            verification: Some(verification),
        },
        context.policy_management_scope.as_ref(),
        context.principal_role,
        &context.policy_management_authorities,
    )
    .await
    {
        Ok(()) => management_response(status, envelope),
        Err(error) => management_audit_unavailable_response(
            &context.request_id,
            &context.broker_request_id,
            &envelope.operation,
            &context.identity.principal,
            error,
        ),
    }
}

fn provider_error_envelope(
    context: &ManagementContext,
    operation: &str,
    target: Option<Value>,
    error: &ProviderError,
) -> (StatusCode, ManagementEnvelope) {
    let reason_code = error.reason_code();
    let status = StatusCode::from_u16(reason_code.http_status())
        .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    let decision = match error.decision() {
        Decision::Allow => Decision::Deny,
        decision => decision,
    };
    let envelope = management_failure_envelope(
        context,
        operation,
        decision,
        reason_code,
        &error.message,
        target,
    );
    (status, envelope)
}

pub(super) fn default_token_ttl_seconds(
    config: &BrokerConfig,
    token_class: &BrokerTokenClass,
) -> Option<u64> {
    let tokens = config.broker_tokens.as_ref()?;
    let ttl = match token_class {
        BrokerTokenClass::AgentInvoke => tokens.default_agent_invoke_ttl.as_deref(),
        BrokerTokenClass::UserManage => tokens.default_user_manage_ttl.as_deref(),
        BrokerTokenClass::Admin => tokens.default_admin_ttl.as_deref(),
    }?;
    parse_ttl_seconds(ttl)
}

pub(super) fn timestamp_after_seconds_checked(seconds: u64) -> Result<String, String> {
    let seconds =
        i64::try_from(seconds).map_err(|_| "token ttl is too large to represent".to_string())?;
    let duration = chrono::Duration::try_seconds(seconds)
        .ok_or_else(|| "token ttl is too large to represent".to_string())?;
    Utc::now()
        .checked_add_signed(duration)
        .map(|timestamp| timestamp.to_rfc3339())
        .ok_or_else(|| "token ttl is too large to represent".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use agent_access_core::{
        AgentTokenActionOption, AgentTokenServiceOption, ExecutionContext, IdentityContext,
        parse_broker_config_raw,
    };

    #[test]
    fn management_internal_store_errors_are_sanitized_for_every_operation() {
        use agent_access_core::ManagedStoreError;
        for operation in [
            "tokens.issue",
            "admin.tokens.issue",
            "admin.credentials.rewrap",
        ] {
            for error in [
                ManagedStoreError::Unavailable(
                    "SQL SELECT secret FROM private_table at /private/store.sqlite".into(),
                ),
                ManagedStoreError::SchemaInvalid("private_table constraint failed".into()),
                ManagedStoreError::PolicyAuthorityUnavailable("/private/policy.sqlite".into()),
                ManagedStoreError::EncryptionKeyMissing("/private/keys/secret.key".into()),
                ManagedStoreError::EncryptionKeyInvalid("/private/keys/secret.key".into()),
            ] {
                let message = management_store_public_error_message(operation, &error);
                assert!(
                    !message.contains("private") && !message.contains("SELECT"),
                    "{operation}: {message}"
                );
                assert_ne!(message, error.to_string());
            }
            assert_eq!(
                management_store_public_error_message(
                    operation,
                    &ManagedStoreError::InputInvalid("name is required".into())
                ),
                "input is invalid: name is required"
            );
        }
    }

    #[test]
    fn management_success_and_error_responses_forbid_caching() {
        for status in [StatusCode::OK, StatusCode::BAD_REQUEST] {
            let response = management_response(
                status,
                ManagementEnvelope {
                    ok: status.is_success(),
                    decision: Decision::Allow,
                    reason_code: None,
                    request_id: "request".into(),
                    broker_request_id: "broker".into(),
                    operation: "tokens.issue".into(),
                    principal: "alice".into(),
                    target: None,
                    result: Some(json!({"token": "one-time-secret"})),
                    error: None,
                },
            );
            assert_eq!(
                response.headers()[axum::http::header::CACHE_CONTROL],
                "no-store"
            );
        }
    }

    fn restricted_token_options() -> AgentTokenOptions {
        let internal = ExecutionContext::new("internal").unwrap();
        let external = ExecutionContext::new("external").unwrap();
        AgentTokenOptions {
            policy_generation: 1,
            resources: vec![agent_access_core::ResourceDefinition {
                id: "eng".to_string(),
                display_name: None,
                resource_type: agent_access_jira::JIRA_PROJECT_RESOURCE.id().clone(),
                selector: agent_access_provider::ResourceSelector::Exact {
                    value: "ENG".to_string(),
                },
                allowed_execution_contexts: vec!["internal".to_string()],
                enabled: true,
            }],
            resource_groups: vec![],
            execution_contexts: vec![internal.clone(), external.clone()],
            services: vec![AgentTokenServiceOption {
                service: "jira".to_string(),
                display_name: "Jira".to_string(),
                broker_hosts: vec![],
                execution_contexts: vec![internal.clone(), external.clone()],
                actions: vec![AgentTokenActionOption {
                    action: "issue.view".to_string(),
                    description: "View issue".to_string(),
                    read_only: true,
                    required_scope_types: vec!["project".to_string()],
                    resource_type: Some(agent_access_jira::JIRA_PROJECT_RESOURCE.id().clone()),
                    execution_contexts: vec![internal, external],
                    effective_access_by_execution_context: BTreeMap::new(),
                }],
            }],
            mcp: None,
        }
    }

    #[test]
    fn credential_target_serializes_service_metadata_in_camel_case() {
        let target = |credential_verification_inputs: Vec<String>| CredentialTarget {
            service: "gitlab_git".to_string(),
            display_name: "GitLab Git".to_string(),
            credential_verification_inputs,
            credential_name: "default".to_string(),
            profile: "git-bearer-token".to_string(),
            credential_kind: "bearer_token".to_string(),
            input_schema: agent_access_core::CredentialInputSchema {
                service: "gitlab_git".to_string(),
                profile: "git-bearer-token".to_string(),
                credential_kind: "bearer_token".to_string(),
                fields: vec![],
            },
        };
        let with_inputs = serde_json::to_value(target(vec!["repository".to_string()])).unwrap();
        assert_eq!(with_inputs["displayName"], "GitLab Git");
        assert_eq!(
            with_inputs["credentialVerificationInputs"],
            json!(["repository"])
        );
        // Always serialized, even when verification needs no input.
        let without_inputs = serde_json::to_value(target(vec![])).unwrap();
        assert_eq!(without_inputs["credentialVerificationInputs"], json!([]));
        let mut keys = without_inputs
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect::<Vec<_>>();
        keys.sort_unstable();
        assert_eq!(
            keys,
            [
                "credentialKind",
                "credentialName",
                "credentialVerificationInputs",
                "displayName",
                "inputSchema",
                "profile",
                "service"
            ]
        );
    }

    #[test]
    fn agent_token_options_serialize_service_metadata_in_camel_case() {
        let options = serde_json::to_value(restricted_token_options()).unwrap();
        let service = &options["services"][0];
        assert_eq!(service["displayName"], "Jira");
        assert_eq!(service["brokerHosts"], json!([]));
        assert_eq!(service["actions"][0]["readOnly"], true);
        // Always serialized: null when issued tokens have no HTTP MCP endpoint.
        assert_eq!(options["mcp"], Value::Null);
        let round_trip: AgentTokenOptions = serde_json::from_value(options).unwrap();
        assert_eq!(round_trip, restricted_token_options());
        let mut connected = restricted_token_options();
        connected.mcp = Some(agent_access_core::AgentTokenMcpEndpoint {
            url: "https://broker.example.com/mcp".to_string(),
        });
        assert_eq!(
            serde_json::to_value(connected).unwrap()["mcp"],
            json!({"url": "https://broker.example.com/mcp"})
        );
    }

    #[test]
    fn agent_token_issue_body_requires_execution_contexts() {
        let error = serde_json::from_value::<AgentTokenIssueBody>(json!({"name": "agent"}))
            .expect_err("new agent tokens must declare execution contexts");
        assert!(error.to_string().contains("allowedExecutionContexts"));
    }

    #[test]
    fn agent_token_references_allow_ineffective_selection_but_reject_unknown_ids() {
        let options = restricted_token_options();
        let caveats = |selection| {
            AgentInvokeTokenCaveats::parse_stored(&json!({
                "allowedServices":["jira"],"allowedExecutionContexts":["external"],
                "serviceRestrictions":{"jira":{"actions":["issue.view"],"resources":selection}}
            }))
            .unwrap()
        };
        // The known internal-only resource is a valid persistent selection even externally.
        assert!(
            validate_agent_token_options(&caveats(json!({"resourceIds":["eng"]})), &options)
                .is_ok()
        );
        assert!(
            validate_agent_token_options(&caveats(json!({"resourceIds":[]})), &options).is_ok()
        );
        assert!(
            validate_agent_token_options(&caveats(json!({"resourceIds":["private"]})), &options)
                .unwrap_err()
                .contains("not available")
        );
        assert!(
            validate_agent_token_options(
                &caveats(json!({"resourceGroupIds":["private"]})),
                &options
            )
            .unwrap_err()
            .contains("not available")
        );
    }

    #[test]
    fn agent_token_restrictions_retain_absent_versus_empty_selection() {
        let restriction =
            |value| serde_json::from_value::<AgentTokenServiceRestrictionBody>(value).unwrap();
        assert!(
            restriction(json!({"actions":["issue.view"]}))
                .resources
                .is_none()
        );
        assert_eq!(
            restriction(json!({"actions":["issue.view"],"resources":{}})).resources,
            Some(ResourceSelection::default())
        );
        assert!(
            serde_json::from_value::<AgentTokenServiceRestrictionBody>(
                json!({"actions":["issue.view"],"resources":null})
            )
            .is_err()
        );
        assert!(
            serde_json::from_value::<AgentTokenServiceRestrictionBody>(json!({
                "actions":["issue.view"],"resourceScopes":{"project":["ENG"]}
            }))
            .is_err()
        );
    }

    #[test]
    fn agent_token_options_reject_unavailable_action_and_context() {
        let options = restricted_token_options();
        for value in [
            json!({"allowedExecutionContexts":["partner"]}),
            json!({"allowedServices":["jira"],"allowedExecutionContexts":["external"],"serviceRestrictions":{"jira":{"actions":["issue.delete"]}}}),
            json!({"allowedServices":["gitlab"],"allowedExecutionContexts":["external"]}),
        ] {
            let caveats = AgentInvokeTokenCaveats::parse_stored(&value).unwrap();
            assert!(validate_agent_token_options(&caveats, &options).is_err());
        }
    }

    #[test]
    fn timestamp_after_seconds_checked_rejects_unrepresentable_offsets() {
        assert!(timestamp_after_seconds_checked(60).is_ok());
        assert!(timestamp_after_seconds_checked(u64::MAX).is_err());
        assert!(timestamp_after_seconds_checked(i64::MAX as u64).is_err());
    }

    #[test]
    fn agent_token_expiry_policy_separates_self_service_and_admin_issuance() {
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
default_agent_invoke_ttl = "8h"
max_self_issued_agent_invoke_ttl = "1d"
self_agent_invoke_ttl_options = ["8h", "1d"]
admin_agent_invoke_ttl_options = ["8h", "2d", "never"]

[limits]
upload_spool_dir = "upload-spool"
"#,
            &std::sync::Arc::new(crate::backend_registry()),
        )
        .unwrap();
        let body = AgentTokenIssueBody {
            name: "agent".to_string(),
            ttl: None,
            expires_at: None,
            never: true,
            allowed_services: None,
            allowed_execution_contexts: vec!["default".to_string()],
            service_restrictions: None,
        };

        assert!(self_agent_token_issue_expires_at(&config, &body).is_err());
        assert_eq!(
            admin_agent_token_issue_expires_at(&config, &body).unwrap(),
            None
        );

        let mut self_never_config = config.clone();
        self_never_config
            .broker_tokens
            .as_mut()
            .unwrap()
            .self_agent_invoke_ttl_options
            .push(agent_access_core::BrokerTokenTtlOption::Never);
        assert_eq!(
            self_agent_token_issue_expires_at(&self_never_config, &body).unwrap(),
            None
        );

        let conflicting = AgentTokenIssueBody {
            ttl: Some("8h".to_string()),
            never: true,
            ..body
        };
        assert!(
            self_agent_token_issue_expires_at(&self_never_config, &conflicting)
                .unwrap_err()
                .contains("mutually exclusive")
        );

        let long_lived = AgentTokenIssueBody {
            ttl: Some("2d".to_string()),
            never: false,
            ..conflicting
        };
        assert!(self_agent_token_issue_expires_at(&config, &long_lived).is_err());
        assert!(
            admin_agent_token_issue_expires_at(&config, &long_lived)
                .unwrap()
                .is_some()
        );

        let mut unrepresentable_max = config.clone();
        unrepresentable_max
            .broker_tokens
            .as_mut()
            .unwrap()
            .max_self_issued_agent_invoke_ttl = Some(format!("{}s", i64::MAX));
        let absolute = AgentTokenIssueBody {
            ttl: None,
            expires_at: Some("2999-01-01T00:00:00Z".to_string()),
            never: false,
            ..long_lived
        };
        assert!(
            self_agent_token_issue_expires_at(&unrepresentable_max, &absolute)
                .unwrap_err()
                .contains("too large")
        );
    }

    #[test]
    fn admin_group_authorization_uses_policy_groups() {
        let config = parse_broker_config_raw(
            "test.toml",
            r#"
[identity]
mode = "required"
authority = "toml"

[[identity.sources]]
name = "bootstrap"
type = "static_principals"
header = "X-Agent-Access-Identity-Token"

[[identity.sources.principals]]
principal = "admin"
token_refs = ["env:ADMIN_TOKEN"]

[[identity.groups]]
id = "broker-admins"
status = "disabled"
members = ["admin"]

[management]
enabled = true
admin_groups = ["broker-admins"]

[policy]
authority = "toml"
default_decision = "deny"

[limits]
upload_spool_dir = "upload-spool"
"#,
            &std::sync::Arc::new(crate::backend_registry()),
        )
        .unwrap();
        let identity = IdentityContext {
            principal: "admin".to_string(),
            principal_kind: None,
            principal_subject: None,
            groups: vec!["broker-admins".to_string()],
            policy_groups: vec![],
            authenticated: true,
            source: None,
            caller_id: None,
        };

        assert!(!management_admin_authorized(&config, &identity));

        let active_identity = IdentityContext {
            policy_groups: vec!["broker-admins".to_string()],
            ..identity
        };
        assert!(management_admin_authorized(&config, &active_identity));
    }

    #[test]
    fn policy_audit_basis_prefers_an_authority_for_the_target_service() {
        let authorities = vec![
            EffectiveServicePolicyManagementAuthority {
                service: "alpha".to_string(),
                assignment_id: "assignment-a".to_string(),
                principal_id: "manager".to_string(),
            },
            EffectiveServicePolicyManagementAuthority {
                service: "beta".to_string(),
                assignment_id: "assignment-b".to_string(),
                principal_id: "beta-managers".to_string(),
            },
        ];
        let scope = PolicyReadScope::Services {
            services: ["alpha".to_string(), "beta".to_string()]
                .into_iter()
                .collect(),
        };

        assert_eq!(
            policy_management_authorization_basis(
                &scope,
                Some(PrincipalRole::ServicePolicyManager),
                &authorities,
                Some("beta"),
                true
            ),
            "direct_assignment:assignment-b"
        );
        assert_eq!(
            policy_management_authorization_basis(
                &scope,
                Some(PrincipalRole::ServicePolicyManager),
                &authorities,
                None,
                false
            ),
            "direct_assignment:assignment-a"
        );
        assert_eq!(
            policy_management_authorization_basis(
                &PolicyReadScope::Global,
                Some(PrincipalRole::Admin),
                &[],
                None,
                false
            ),
            "global_admin"
        );
        assert_eq!(
            policy_management_authorization_basis(
                &scope,
                Some(PrincipalRole::ServicePolicyManager),
                &authorities,
                None,
                true
            ),
            "delegated_assignment"
        );

        assert_eq!(
            policy_management_authorization_basis(
                &PolicyReadScope::Global,
                Some(PrincipalRole::Auditor),
                &[],
                None,
                false
            ),
            "global_auditor"
        );

        let cross_service = policy_management_audit_target_metadata(&scope, Some("gamma"));
        assert_eq!(cross_service["targetService"], "gamma");
        assert_eq!(
            cross_service["authorizationDeniedReason"],
            "service_out_of_scope"
        );
        let unknown_grant = policy_management_audit_target_metadata(&scope, None);
        assert!(!unknown_grant.contains_key("targetService"));
        assert!(!unknown_grant.contains_key("authorizationDeniedReason"));
    }

    #[test]
    fn every_management_read_route_has_an_audit_classification() {
        use agent_access_core::ResponseKind;

        for list in [UNAUDITED_READ_OPERATIONS, AUDITED_READ_OPERATIONS] {
            let unique = list.iter().collect::<BTreeSet<_>>();
            assert_eq!(unique.len(), list.len(), "duplicate classification entry");
        }
        let registry = crate::backend_registry();
        let routes = agent_access_core::http_route_specs(registry.resource_types());
        let mut classified_routes = BTreeSet::new();
        for route in routes
            .iter()
            .filter(|route| route.response_kind == ResponseKind::ManagementEnvelope)
        {
            let operation = handler_operation(&route.operation);
            let unaudited = UNAUDITED_READ_OPERATIONS.contains(&operation);
            let audited = AUDITED_READ_OPERATIONS.contains(&operation);
            let read = route.method == "GET"
                || READ_ONLY_POST_CATALOG_OPERATIONS.contains(&route.operation.as_str());
            if read {
                assert!(
                    unaudited != audited,
                    "{} {} ({operation}) must be classified exactly once as an unaudited or \
                     audited read",
                    route.method,
                    route.route,
                );
                classified_routes.insert(operation);
            } else {
                assert!(
                    !unaudited && !audited,
                    "{} {} ({operation}) changes state and must stay audited",
                    route.method,
                    route.route,
                );
            }
        }
        for operation in UNAUDITED_READ_OPERATIONS
            .iter()
            .chain(AUDITED_READ_OPERATIONS)
        {
            assert!(
                classified_routes.contains(operation)
                    || NON_CATALOG_READ_OPERATIONS.contains(operation),
                "{operation} is classified but names no read route"
            );
        }
        for (catalog, _) in CATALOG_TO_HANDLER_OPERATION {
            assert!(
                routes.iter().any(|route| route.operation == *catalog),
                "{catalog} is not a catalog operation"
            );
        }
        for operation in READ_ONLY_POST_CATALOG_OPERATIONS {
            assert!(
                routes
                    .iter()
                    .any(|route| route.method == "POST" && route.operation == *operation),
                "{operation} is not a catalog POST operation"
            );
        }
    }

    #[test]
    fn delegated_policy_management_requires_managed_policy_authority() {
        let mut config = parse_broker_config_raw(
            "test.toml",
            r#"
[identity]
mode = "optional"
authority = "toml"

[policy]
authority = "toml"
default_decision = "deny"

[limits]
upload_spool_dir = "upload-spool"
"#,
            &std::sync::Arc::new(crate::backend_registry()),
        )
        .unwrap();
        assert!(!delegated_policy_management_enabled(&config));

        config.policy.authority = "managed".to_string();
        assert!(delegated_policy_management_enabled(&config));
    }
}
