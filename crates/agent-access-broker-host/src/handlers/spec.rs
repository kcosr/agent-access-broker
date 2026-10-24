use crate::handlers::common::{
    CallerAdmission, acquire_caller_guard, acquire_global_concurrency_guard,
    check_auth_source_rate_guard, discovery_unavailable_envelope, envelope_response,
    request_id_from_headers, resolve_request_identity_pending,
};
use crate::handlers::management::common::{
    effective_management_authority, management_admin_authorized,
};
use crate::observability;
use crate::state::{AppState, RequestPermits, RuntimeSnapshot};
use agent_access_core::{
    ApiCatalog, BrokerResponse, BrokerTokenClass, EXECUTION_CONTEXT_HEADER, ErrorBody,
    ExecutionContext, GovernedOperationContext, IdentityContext, OperationContext, PolicyReadScope,
    PolicyWriteScope, PrincipalRole, RenderAuthMode, ResponseEnvelope, RouteAccess, RouteFeature,
    SourceContext, empty_catalog, http_route_specs, new_broker_request_id, openapi_from_catalog,
    send_schema_from_catalog,
};
use agent_access_provider::{Decision, ReasonCode, ResourceScopes};
use axum::Json;
use axum::extract::{ConnectInfo, Query, State};
use axum::http::header::{CACHE_CONTROL, VARY};
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::response::IntoResponse;
use serde::Deserialize;
use serde_json::Value;
use std::collections::BTreeSet;
use std::net::SocketAddr;
use std::sync::Arc;

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct SpecQuery {
    auth: Option<String>,
    visibility: Option<String>,
    format: Option<String>,
}

struct SpecContext {
    snapshot: Arc<RuntimeSnapshot>,
    request_id: String,
    identity: IdentityContext,
    source: SourceContext,
    execution_context: Option<ExecutionContext>,
    _permits: RequestPermits,
}

struct SpecAccess {
    visibility_all: bool,
    can_agent_invoke: bool,
    can_user_management: bool,
    can_user_token_management: bool,
    can_policy_read: bool,
    can_policy_write: bool,
    can_admin_read: bool,
    can_admin_write: bool,
    role: Option<PrincipalRole>,
}

pub(crate) async fn spec_catalog(
    State(state): State<AppState>,
    ConnectInfo(remote_addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Query(query): Query<SpecQuery>,
) -> impl IntoResponse {
    spec_document_response(state, remote_addr, headers, query, "catalog").await
}

pub(crate) async fn spec_openapi(
    State(state): State<AppState>,
    ConnectInfo(remote_addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Query(query): Query<SpecQuery>,
) -> impl IntoResponse {
    spec_document_response(state, remote_addr, headers, query, "openapi").await
}

pub(crate) async fn spec_send_schema(
    State(state): State<AppState>,
    ConnectInfo(remote_addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Query(query): Query<SpecQuery>,
) -> impl IntoResponse {
    spec_document_response(state, remote_addr, headers, query, "send-schema").await
}

async fn spec_document_response(
    state: AppState,
    remote_addr: SocketAddr,
    headers: HeaderMap,
    query: SpecQuery,
    document: &'static str,
) -> axum::response::Response {
    let request_id =
        match request_id_from_headers(&headers, "spec".to_string(), document.to_string()) {
            Ok(request_id) => request_id,
            Err(response) => return envelope_response(*response).into_response(),
        };
    let auth = match parse_auth_mode(&query, &request_id, document) {
        Ok(auth) => auth,
        Err(response) => return envelope_response(*response).into_response(),
    };
    if let Err(response) = validate_format(&query, &request_id, document) {
        return envelope_response(*response).into_response();
    }
    let mut context = match spec_context(&state, remote_addr, &headers, request_id, document).await
    {
        Ok(context) => context,
        Err(response) => return *response,
    };
    let access = match spec_access(&context, &query, document).await {
        Ok(access) => access,
        Err(response) => return envelope_response(*response).into_response(),
    };
    if should_resolve_execution_context(&access) {
        context.execution_context = match resolve_execution_context_or_response(
            &context.snapshot,
            &headers,
            context.request_id.clone(),
            document,
            &context.source,
        )
        .await
        {
            Ok(execution_context) => Some(execution_context),
            Err(response) => return *response,
        };
        let execution_context = context
            .execution_context
            .as_ref()
            .expect("caller-visible specs resolve an execution context");
        if let Err(error) = context
            .snapshot
            .runtime
            .admit_agent_invoke_execution_context(&context.identity, execution_context)
        {
            let broker_request_id = new_broker_request_id();
            observability::record_broker_request_id(&broker_request_id);
            let response = context
                .snapshot
                .runtime
                .context_authorization_error_response(
                    GovernedOperationContext {
                        admission: None,
                        operation: OperationContext {
                            agent_request_id: context.request_id.clone(),
                            broker_request_id,
                            identity: context.identity.clone(),
                            service: "spec".to_string(),
                            action: document.to_string(),
                            source: context.source.clone(),
                        },
                        execution_context: execution_context.clone(),
                    },
                    error,
                )
                .await;
            return envelope_response(response).into_response();
        }
    }
    if visibility_all_requested(&query) && !access.visibility_all {
        return envelope_response(spec_error_envelope(
            context.request_id.clone(),
            new_broker_request_id(),
            document,
            ReasonCode::ManagementDenied,
            "visibility=all requires administrative read access",
        ))
        .into_response();
    }
    if access.visibility_all {
        let token_class = context
            .identity
            .source
            .as_ref()
            .and_then(|source| source.token_class.as_ref());
        tracing::warn!(
            event = "spec_visibility_all",
            principal = context.identity.principal.as_str(),
            tokenClass = ?token_class,
            role = ?access.role,
            requestId = context.request_id.as_str(),
            specDocument = document,
        );
    }
    let failure_request_id = context.request_id.clone();
    let (context, access, catalog) = match tokio::task::spawn_blocking(move || {
        let catalog = render_catalog(&context, &access);
        (context, access, catalog)
    })
    .await
    {
        Ok(result) => result,
        Err(_) => {
            return envelope_response(discovery_unavailable_envelope(failure_request_id))
                .into_response();
        }
    };
    let document = match document {
        "catalog" => serde_json::to_value(catalog).expect("api catalog serializes"),
        "openapi" => {
            let mut document = openapi_from_catalog(
                &catalog,
                auth,
                &identity_header_names(&context.snapshot),
                &context
                    .snapshot
                    .runtime
                    .config()
                    .browser_auth
                    .session_cookie_name,
            );
            let mcp = &context.snapshot.runtime.config().mcp;
            if mcp.enabled
                && (access.can_agent_invoke || access.visibility_all)
                && let Some(url) = mcp.public_url.as_deref()
            {
                super::mcp_openapi::add(&mut document, url, auth);
            }
            document
        }
        "send-schema" => send_schema_from_catalog(&catalog),
        _ => unreachable!("unknown spec document"),
    };
    raw_spec_json_response(&context.snapshot, document)
}

/// A spec request's identity failure: the source's authentication budget is
/// charged, then the identity error is returned.
async fn spec_identity_failure(
    state: &AppState,
    snapshot: &RuntimeSnapshot,
    request_id: &str,
    document: &str,
    source: &SourceContext,
    failure: agent_access_core::IdentityFailure,
) -> Box<axum::response::Response> {
    if let Err(response) = check_auth_source_rate_guard(
        state,
        snapshot,
        request_id,
        "spec".to_string(),
        document.to_string(),
        source,
    )
    .await
    {
        return Box::new(envelope_response(*response).into_response());
    }
    let response = snapshot.runtime.identity_error_response(
        request_id.to_string(),
        new_broker_request_id(),
        failure,
    );
    Box::new(envelope_response(response).into_response())
}

async fn spec_context(
    state: &AppState,
    remote_addr: SocketAddr,
    headers: &HeaderMap,
    request_id: String,
    document: &str,
) -> Result<SpecContext, Box<axum::response::Response>> {
    observability::record_operation(&format!("spec.{document}"));
    let snapshot = state.reloadable.current();
    let source = snapshot
        .source_resolver
        .source_context(remote_addr, headers);
    let global_permit = acquire_global_concurrency_guard(
        state,
        &snapshot,
        &request_id,
        "spec".to_string(),
        document.to_string(),
        &source,
    )
    .await
    .map_err(|response| Box::new(envelope_response(*response).into_response()))?;

    let pending =
        match resolve_request_identity_pending(state, snapshot.clone(), headers.clone()).await {
            Ok(pending) => pending,
            Err(failure) => {
                return Err(spec_identity_failure(
                    state,
                    &snapshot,
                    &request_id,
                    document,
                    &source,
                    failure,
                )
                .await);
            }
        };
    let password_change_required = |request_id: String| {
        Box::new(
            envelope_response(spec_error_envelope(
                request_id,
                new_broker_request_id(),
                document,
                ReasonCode::PasswordChangeRequired,
                "password change is required before reading specs",
            ))
            .into_response(),
        )
    };
    if pending.value().password_change_required {
        return Err(password_change_required(request_id));
    }
    if !pending.value().identity.authenticated {
        return Err(spec_identity_failure(
            state,
            &snapshot,
            &request_id,
            document,
            &source,
            agent_access_core::IdentityFailure::Required,
        )
        .await);
    }
    observability::record_principal(&pending.value().identity.principal);
    // A membership renewal wait holds the caller's capacity.
    let principal_permit = acquire_caller_guard(
        state,
        &snapshot,
        &request_id,
        "spec".to_string(),
        document.to_string(),
        &source,
        CallerAdmission {
            identity: &pending.value().identity,
        },
    )
    .await
    .map_err(|response| Box::new(envelope_response(*response).into_response()))?;
    let identity = match pending.admit(state, &snapshot, headers).await {
        Ok(resolved) if resolved.password_change_required => {
            return Err(password_change_required(request_id));
        }
        Ok(resolved) => resolved.identity,
        Err(failure) => {
            return Err(spec_identity_failure(
                state,
                &snapshot,
                &request_id,
                document,
                &source,
                failure,
            )
            .await);
        }
    };

    Ok(SpecContext {
        snapshot,
        request_id,
        identity,
        source,
        execution_context: None,
        _permits: RequestPermits {
            _global: global_permit,
            _principal: principal_permit,
        },
    })
}

async fn spec_access(
    context: &SpecContext,
    query: &SpecQuery,
    document: &str,
) -> Result<SpecAccess, Box<BrokerResponse<Value>>> {
    let visibility_all_requested = visibility_all_requested(query);
    if let Some(visibility) = query.visibility.as_deref()
        && visibility != "caller"
        && visibility != "all"
    {
        return Err(Box::new(spec_error_envelope(
            context.request_id.clone(),
            new_broker_request_id(),
            document,
            ReasonCode::InputInvalid,
            "visibility must be caller or all",
        )));
    }
    let managed = effective_management_authority(&context.snapshot, &context.identity)
        .await
        .ok();
    let enabled = context.snapshot.runtime.config().management.enabled;
    let config = &context.snapshot.runtime.config().management;
    let class = token_class(context);
    let browser = context
        .identity
        .source
        .as_ref()
        .is_some_and(|s| s.name == "browser-session" && s.token_id.is_some());
    let classless_admin = class.is_none()
        && config.allow_classless_admin_identities
        && management_admin_authorized(context.snapshot.runtime.config(), &context.identity);
    let role = managed.as_ref().map(|authority| authority.principal.role);
    let human = managed
        .as_ref()
        .is_some_and(|authority| authority.principal.kind == "user");
    let global_read = human && matches!(role, Some(PrincipalRole::Admin | PrincipalRole::Auditor));
    let global_write = human && role == Some(PrincipalRole::Admin);
    let admin_class = class == Some(BrokerTokenClass::Admin)
        || (class == Some(BrokerTokenClass::UserManage) && browser);
    let can_admin_read = enabled && (classless_admin || (admin_class && global_read));
    let can_admin_write = enabled && (classless_admin || (admin_class && global_write));
    let policy_class = class == Some(BrokerTokenClass::UserManage);
    let can_policy_read = enabled
        && (classless_admin
            || (class == Some(BrokerTokenClass::Admin) && global_read)
            || (policy_class
                && managed
                    .as_ref()
                    .is_some_and(|authority| match &authority.policy_read_scope {
                        PolicyReadScope::Global => true,
                        PolicyReadScope::Services { services } => !services.is_empty(),
                    })));
    let can_policy_write = enabled
        && (classless_admin
            || (class == Some(BrokerTokenClass::Admin) && global_write)
            || (policy_class
                && managed.as_ref().is_some_and(|authority| {
                    match &authority.policy_write_scope {
                        PolicyWriteScope::Global => true,
                        PolicyWriteScope::Services { services } => !services.is_empty(),
                    }
                })));
    let self_service = enabled
        && managed
            .as_ref()
            .is_some_and(|authority| authority.principal.self_service_enabled);
    Ok(SpecAccess {
        visibility_all: visibility_all_requested && can_admin_read,
        can_agent_invoke: class
            .as_ref()
            .is_none_or(|class| *class == BrokerTokenClass::AgentInvoke),
        can_user_management: self_service
            && (class == Some(BrokerTokenClass::UserManage)
                || (class.is_none() && config.allow_classless_user_management)),
        can_user_token_management: self_service && class == Some(BrokerTokenClass::UserManage),
        can_policy_read,
        can_policy_write,
        can_admin_read,
        can_admin_write,
        role,
    })
}

fn render_catalog(context: &SpecContext, access: &SpecAccess) -> ApiCatalog {
    let mut catalog = empty_catalog(
        serde_json::to_value(context.identity.summary()).expect("identity serializes"),
    );
    catalog.services = if access.visibility_all {
        context.snapshot.runtime.api_services_all()
    } else if let Some(execution_context) = context.execution_context.as_ref() {
        context
            .snapshot
            .runtime
            .api_services_for_identity(&context.identity, execution_context)
    } else {
        Vec::new()
    };
    catalog.execution_context = context.execution_context.clone();
    catalog.resource_types = context.snapshot.runtime.resource_type_metadata();
    catalog.routes = http_route_specs(context.snapshot.runtime.resource_types())
        .into_iter()
        .filter(|route| route_visible(context, access, route.access))
        .filter(|route| {
            route
                .required_feature
                .is_none_or(|feature| route_feature_available(&context.snapshot, feature))
        })
        .collect();
    catalog
}

/// Whether this generation's configuration provides a route's feature. A
/// route whose feature is unavailable is absent from every rendering of the
/// catalog, including `visibility=all`.
pub(crate) fn route_feature_available(snapshot: &RuntimeSnapshot, feature: RouteFeature) -> bool {
    match feature {
        RouteFeature::AuditQuery => {
            snapshot.runtime.config().management.enabled
                && snapshot
                    .runtime
                    .audit_store()
                    .is_some_and(|store| store.supports_queries())
        }
    }
}

fn visibility_all_requested(query: &SpecQuery) -> bool {
    matches!(query.visibility.as_deref(), Some("all"))
}

fn should_resolve_execution_context(access: &SpecAccess) -> bool {
    !access.visibility_all && access.can_agent_invoke
}

fn route_visible(context: &SpecContext, access: &SpecAccess, route_access: RouteAccess) -> bool {
    match route_access {
        RouteAccess::Authenticated | RouteAccess::Spec => true,
        RouteAccess::AgentInvoke => access.visibility_all || access.can_agent_invoke,
        RouteAccess::BrowserManagement => {
            !context
                .snapshot
                .runtime
                .config()
                .oauth
                .registrations
                .is_empty()
                && (access.visibility_all
                    || (access.can_user_management
                        && context
                            .identity
                            .source
                            .as_ref()
                            .is_some_and(|s| s.name == "browser-session")))
        }
        RouteAccess::UserManagement => access.visibility_all || access.can_user_management,
        RouteAccess::UserTokenManagement => {
            access.visibility_all || access.can_user_token_management
        }
        RouteAccess::PolicyRead => access.can_policy_read,
        RouteAccess::PolicyWrite => access.can_policy_write,
        RouteAccess::AdminRead => access.can_admin_read,
        RouteAccess::AdminWrite => access.can_admin_write,
    }
}

fn token_class(context: &SpecContext) -> Option<BrokerTokenClass> {
    context
        .identity
        .source
        .as_ref()
        .and_then(|source| source.token_class.clone())
}

fn parse_auth_mode(
    query: &SpecQuery,
    request_id: &str,
    document: &str,
) -> Result<RenderAuthMode, Box<BrokerResponse<Value>>> {
    match query.auth.as_deref().unwrap_or("include") {
        "include" => Ok(RenderAuthMode::Include),
        "omit" => Ok(RenderAuthMode::Omit),
        _ => Err(Box::new(spec_error_envelope(
            request_id.to_string(),
            new_broker_request_id(),
            document,
            ReasonCode::InputInvalid,
            "auth must be include or omit",
        ))),
    }
}

fn validate_format(
    query: &SpecQuery,
    request_id: &str,
    document: &str,
) -> Result<(), Box<BrokerResponse<Value>>> {
    match query.format.as_deref().unwrap_or("json") {
        "json" => Ok(()),
        _ => Err(Box::new(spec_error_envelope(
            request_id.to_string(),
            new_broker_request_id(),
            document,
            ReasonCode::InputInvalid,
            "format must be json",
        ))),
    }
}

fn raw_spec_json_response(snapshot: &RuntimeSnapshot, value: Value) -> axum::response::Response {
    let mut response = (StatusCode::OK, Json(value)).into_response();
    let headers = response.headers_mut();
    headers.insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
    if let Ok(value) = HeaderValue::from_str(&vary_header(snapshot)) {
        headers.insert(VARY, value);
    }
    response
}

fn vary_header(snapshot: &RuntimeSnapshot) -> String {
    let mut values = BTreeSet::from([
        "Authorization".to_string(),
        "Cookie".to_string(),
        EXECUTION_CONTEXT_HEADER.to_string(),
    ]);
    for source in identity_header_names(snapshot) {
        values.insert(source);
    }
    values.into_iter().collect::<Vec<_>>().join(", ")
}

async fn resolve_execution_context_or_response(
    snapshot: &RuntimeSnapshot,
    headers: &HeaderMap,
    agent_request_id: String,
    document: &str,
    source: &SourceContext,
) -> Result<ExecutionContext, Box<axum::response::Response>> {
    match snapshot.resolve_execution_context(headers) {
        Ok(execution_context) => {
            observability::record_execution_context(&execution_context);
            Ok(execution_context)
        }
        Err(failure) => {
            let broker_request_id = new_broker_request_id();
            observability::record_broker_request_id(&broker_request_id);
            let response = snapshot
                .runtime
                .ingress_error_response_for_operation(
                    OperationContext {
                        agent_request_id,
                        broker_request_id,
                        identity: IdentityContext::anonymous(),
                        service: "spec".to_string(),
                        action: document.to_string(),
                        source: source.clone(),
                    },
                    failure,
                )
                .await;
            Err(Box::new(envelope_response(response).into_response()))
        }
    }
}

fn identity_header_names(snapshot: &RuntimeSnapshot) -> Vec<String> {
    let mut values = BTreeSet::new();
    for source in &snapshot.runtime.config().identity.sources {
        values.insert(source.header.clone());
    }
    values.into_iter().collect::<Vec<_>>()
}

fn spec_error_envelope(
    agent_request_id: String,
    broker_request_id: String,
    document: &str,
    reason_code: ReasonCode,
    message: &str,
) -> BrokerResponse<Value> {
    BrokerResponse {
        retry_after_seconds: None,
        status: reason_code.http_status(),
        envelope: ResponseEnvelope {
            agent_request_id,
            broker_request_id,
            decision: Decision::Deny,
            service: "spec".to_string(),
            action: document.to_string(),
            resource_scopes: ResourceScopes::new(),
            reason_code: Some(reason_code.into()),
            reason: Some(message.to_string()),
            result: None,
            error: Some(ErrorBody {
                message: message.to_string(),
            }),
        },
        stream: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn access(visibility_all: bool) -> SpecAccess {
        SpecAccess {
            visibility_all,
            can_agent_invoke: !visibility_all,
            can_user_management: false,
            can_user_token_management: false,
            can_policy_read: false,
            can_policy_write: false,
            can_admin_read: visibility_all,
            can_admin_write: visibility_all,
            role: None,
        }
    }

    #[test]
    fn only_authorized_visibility_all_skips_context_resolution() {
        assert!(!should_resolve_execution_context(&access(true)));
        assert!(should_resolve_execution_context(&access(false)));
        let mut management_only = access(false);
        management_only.can_agent_invoke = false;
        management_only.can_policy_read = true;
        assert!(!should_resolve_execution_context(&management_only));
    }

    #[test]
    fn visibility_all_is_recognized_exactly() {
        assert!(visibility_all_requested(&SpecQuery {
            visibility: Some("all".to_string()),
            ..SpecQuery::default()
        }));
        assert!(!visibility_all_requested(&SpecQuery {
            visibility: Some("caller".to_string()),
            ..SpecQuery::default()
        }));
    }
}
