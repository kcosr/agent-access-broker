use crate::handlers::auth::{auth_local_login, auth_logout, auth_password_change, auth_session};
use crate::handlers::data::{
    broker_status, capabilities, healthz, invoke, me, readyz, resource_types, service,
    service_actions, service_resource_access, services,
};
use crate::handlers::gateway::gateway_dispatch;
use crate::handlers::management::admin::{
    admin_credential_delete, admin_credential_get, admin_credentials_list,
    admin_credentials_rewrap, admin_external_group_binding_create,
    admin_external_group_binding_delete, admin_external_group_binding_patch,
    admin_external_group_bindings_list, admin_group_member_add, admin_group_member_delete,
    admin_group_members_list, admin_groups_create, admin_groups_get, admin_groups_list,
    admin_groups_patch, admin_principal_access_patch, admin_principal_agent_token_get,
    admin_principal_agent_token_issue, admin_principal_agent_token_options,
    admin_principal_agent_token_pause, admin_principal_agent_token_resume,
    admin_principal_agent_token_revoke, admin_principal_agent_tokens_list,
    admin_principal_credential_delete, admin_principal_credential_get,
    admin_principal_credential_input_schema, admin_principal_credential_put,
    admin_principal_credential_targets, admin_principal_credential_verify,
    admin_principal_credentials_list, admin_principal_group_add, admin_principal_group_delete,
    admin_principal_local_password_disable, admin_principal_local_password_enable,
    admin_principal_local_password_reset, admin_principal_local_password_unlock,
    admin_principal_login_methods_list, admin_principal_microsoft_oidc_link,
    admin_principal_microsoft_oidc_unlink, admin_principal_services, admin_principal_token_issue,
    admin_principals_create, admin_principals_get, admin_principals_list, admin_principals_patch,
    admin_right_revoke, admin_rights_grant, admin_rights_list, admin_store_status, admin_token_get,
    admin_token_pause, admin_token_resume, admin_token_revoke, admin_tokens_list,
};
use crate::handlers::management::audit;
use crate::handlers::management::imports;
use crate::handlers::management::policy::{
    admin_policy_catalog, admin_policy_grants_create, admin_policy_grants_delete,
    admin_policy_grants_disable, admin_policy_grants_enable, admin_policy_grants_export,
    admin_policy_grants_get, admin_policy_grants_list, admin_policy_grants_patch,
    admin_policy_grants_subject_add, admin_policy_grants_subject_remove,
    admin_policy_grants_validate, admin_policy_service_manager_grant,
    admin_policy_service_manager_revoke, admin_policy_service_managers_list, admin_policy_status,
};
use crate::handlers::management::resources::*;
use crate::handlers::management::service_limits;
use crate::handlers::management::user::{
    user_credential_input_schema, user_credential_targets, user_credentials_delete,
    user_credentials_get, user_credentials_list, user_credentials_put, user_credentials_verify,
    user_retained_credential_delete, user_token_get, user_token_issue, user_token_options,
    user_token_pause, user_token_resume, user_token_revoke, user_tokens_list,
};
use crate::handlers::management::{identity_access, identity_bindings, identity_tokens};
use crate::handlers::oidc::{microsoft_oidc_callback, microsoft_oidc_start};
use crate::handlers::portal::{portal_asset, portal_index};
use crate::handlers::spec::{spec_catalog, spec_openapi, spec_send_schema};
use crate::observability::{ListenerKind, RequestTracingLayer};
use crate::reload::{admin_config_reload, admin_config_status};
use crate::state::{AppState, ReloadableState, RuntimeSnapshot};
use axum::Router;
use axum::routing::{delete, get, patch, post, put};
use std::sync::Arc;

/// The public router over one runtime, outside any serving lifecycle, for
/// host tests that route requests to a specific runtime instance, such as a
/// superseded generation's runtime.
#[cfg(test)]
pub(crate) fn runtime_router(runtime: agent_access_core::BrokerRuntime) -> Router {
    /// The serving defaults of `--reload-timeout-ms` and
    /// `--shutdown-timeout-ms`.
    const TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);
    let body_hard_cap = runtime.max_http_body_bytes();
    let audit_registry = runtime.audit_registry();
    let backends = Arc::clone(runtime.config().providers.registry());
    let snapshot = RuntimeSnapshot::new(
        1,
        "sha256:static".to_string(),
        runtime.with_config_generation(1),
        agent_access_core::StateLockSet::empty(),
    );
    let state = Arc::new(ReloadableState::from_snapshot(
        std::path::PathBuf::new(),
        backends,
        crate::broker_build_status(),
        snapshot,
        body_hard_cap,
        TIMEOUT,
        TIMEOUT,
        audit_registry,
    ));
    public_router(state).0
}

/// The public router and the HTTP MCP endpoint it serves.
pub(crate) fn public_router(state: Arc<ReloadableState>) -> (Router, crate::mcp::Endpoint) {
    let node_id = state.node_id();
    let mcp = crate::mcp::Endpoint::new(state.clone());
    let endpoint = mcp.clone();
    let router = Router::new()
        .route(
            "/mcp",
            axum::routing::any(crate::mcp::handle).layer(axum::Extension(mcp.clone())),
        )
        .route(
            "/mcp/{service}",
            axum::routing::any(crate::mcp::handle).layer(axum::Extension(mcp)),
        )
        .route(
            "/v1/admin/imports",
            get(imports::list).post(imports::create),
        )
        .route(
            "/v1/admin/imports/{service}",
            get(imports::get).patch(imports::update),
        )
        .route(
            "/v1/admin/imports/{service}/discover",
            post(imports::discover),
        )
        .route("/v1/admin/imports/{service}/preview", get(imports::preview))
        .route("/v1/admin/imports/{service}/accept", post(imports::accept))
        .route("/v1/admin/imports/{service}/status", post(imports::status))
        .route(
            "/v1/admin/imports/{service}/actions/{action}/status",
            post(imports::action_status),
        )
        .route(
            "/v1/admin/imports/{service}/credentials/{purpose}",
            put(imports::secret_put).delete(imports::secret_delete),
        )
        .route("/v1/healthz", get(healthz))
        .route("/v1/readyz", get(readyz))
        .route("/v1/auth/session", get(auth_session))
        .route("/v1/auth/local/login", post(auth_local_login))
        .route("/v1/auth/local/password/change", post(auth_password_change))
        .route("/v1/auth/logout", post(auth_logout))
        .route("/v1/auth/oidc/microsoft/start", get(microsoft_oidc_start))
        .route(
            "/v1/auth/oidc/microsoft/callback",
            get(microsoft_oidc_callback),
        )
        .route("/ui", get(portal_index))
        .route("/ui/{*path}", get(portal_asset))
        .route("/v1/me", get(me))
        .route("/v1/broker/status", get(broker_status))
        .route("/v1/resource-types", get(resource_types))
        .route("/v1/capabilities", get(capabilities))
        .route("/v1/services", get(services))
        .route("/v1/services/{service}", get(service))
        .route(
            "/v1/services/{service}/resource-access",
            get(service_resource_access),
        )
        .route("/v1/services/{service}/actions", get(service_actions))
        .route("/v1/spec/catalog", get(spec_catalog))
        .route("/v1/spec/openapi.json", get(spec_openapi))
        .route("/v1/spec/send-schema.json", get(spec_send_schema))
        .route("/v1/invoke/{service}/{action}", post(invoke))
        .route("/v1/credentials", get(user_credentials_list))
        .route(
            "/v1/oauth/connections",
            get(crate::handlers::management::oauth::list),
        )
        .route(
            "/v1/oauth/connect",
            post(crate::handlers::management::oauth::connect),
        )
        .route(
            "/v1/oauth/connections/{registration}",
            delete(crate::handlers::management::oauth::disconnect),
        )
        .route(
            "/v1/oauth/callback/{registration}",
            get(crate::handlers::management::oauth::callback),
        )
        .route("/v1/credentials/targets", get(user_credential_targets))
        .route(
            "/v1/credentials/connections/{connection}",
            get(user_credentials_get)
                .put(user_credentials_put)
                .delete(user_credentials_delete),
        )
        .route(
            "/v1/credentials/connections/{connection}/verify",
            post(user_credentials_verify),
        )
        .route(
            "/v1/credentials/connections/{connection}/input-schema",
            get(user_credential_input_schema),
        )
        .route(
            "/v1/credentials/retained/{credential_id}",
            delete(user_retained_credential_delete),
        )
        .route("/v1/tokens", get(user_tokens_list).post(user_token_issue))
        .route("/v1/tokens/options", get(user_token_options))
        .route(
            "/v1/tokens/{token_id}",
            get(user_token_get).delete(user_token_revoke),
        )
        .route("/v1/tokens/{token_id}/pause", post(user_token_pause))
        .route("/v1/tokens/{token_id}/resume", post(user_token_resume))
        .route("/v1/audit/options", get(audit::self_options))
        .route("/v1/audit/events", get(audit::self_events_list))
        .route(
            "/v1/audit/requests/{brokerRequestId}",
            get(audit::self_request_inspect),
        )
        .route("/v1/admin/audit/options", get(audit::admin_options))
        .route("/v1/admin/audit/events", get(audit::admin_events_list))
        .route(
            "/v1/admin/audit/requests/{brokerRequestId}",
            get(audit::admin_request_inspect),
        )
        .route(
            "/v1/admin/principals/{principal}/identity-token",
            get(identity_tokens::inspect)
                .put(identity_tokens::set)
                .patch(identity_tokens::patch)
                .delete(identity_tokens::remove),
        )
        .route(
            "/v1/admin/principals/{principal}/identity-token/reveal",
            post(identity_tokens::reveal),
        )
        .route(
            "/v1/admin/principals/{principal}/identity-token/generate",
            post(identity_tokens::generate),
        )
        .route(
            "/v1/admin/principals/{principal}/identity-access",
            get(identity_access::get).patch(identity_access::patch),
        )
        .route(
            "/v1/admin/principals/{principal}/identity-bindings",
            get(identity_bindings::list).post(identity_bindings::create),
        )
        .route(
            "/v1/admin/principals/{principal}/identity-bindings/{binding}",
            patch(identity_bindings::patch).delete(identity_bindings::delete),
        )
        .route("/v1/admin/store/status", get(admin_store_status))
        .route("/v1/admin/config/status", get(admin_config_status))
        .route("/v1/admin/config/reload", post(admin_config_reload))
        .route("/v1/admin/policy/status", get(admin_policy_status))
        .route("/v1/admin/policy/catalog", get(admin_policy_catalog))
        .route(
            "/v1/tokens/effective-access",
            post(user_token_effective_access),
        )
        .route(
            "/v1/admin/principals/{principal}/agent-token-effective-access",
            post(admin_principal_agent_token_effective_access),
        )
        .route(
            "/v1/admin/policy/effective-access",
            post(admin_policy_effective_access),
        )
        .route(
            "/v1/admin/policy/resources",
            get(admin_policy_resources_list).post(admin_policy_resources_create),
        )
        .route(
            "/v1/admin/policy/resources/{id}",
            get(admin_policy_resources_get)
                .patch(admin_policy_resources_patch)
                .delete(admin_policy_resources_delete),
        )
        .route(
            "/v1/admin/policy/resources/{id}/used-by",
            get(admin_policy_resources_used_by),
        )
        .route(
            "/v1/admin/policy/resources/{id}/attributes/{attribute}/reveal",
            post(admin_policy_resource_attribute_reveal),
        )
        .route(
            "/v1/admin/policy/resource-groups",
            get(admin_policy_resource_groups_list).post(admin_policy_resource_groups_create),
        )
        .route(
            "/v1/admin/policy/resource-groups/{id}",
            get(admin_policy_resource_groups_get)
                .patch(admin_policy_resource_groups_patch)
                .delete(admin_policy_resource_groups_delete),
        )
        .route(
            "/v1/admin/policy/resource-groups/{id}/used-by",
            get(admin_policy_resource_groups_used_by),
        )
        .route(
            "/v1/admin/policy/grants",
            get(admin_policy_grants_list).post(admin_policy_grants_create),
        )
        .route(
            "/v1/admin/policy/grants/export",
            get(admin_policy_grants_export),
        )
        .route(
            "/v1/admin/policy/grants/validate",
            post(admin_policy_grants_validate),
        )
        .route(
            "/v1/admin/policy/service-managers",
            get(admin_policy_service_managers_list),
        )
        .route(
            "/v1/admin/policy/services/{service}/managers/{principal}",
            put(admin_policy_service_manager_grant).delete(admin_policy_service_manager_revoke),
        )
        .route(
            "/v1/admin/policy/grants/{grant_ref}/subjects",
            post(admin_policy_grants_subject_add),
        )
        .route(
            "/v1/admin/policy/grants/{grant_ref}/subjects/remove",
            post(admin_policy_grants_subject_remove),
        )
        .route(
            "/v1/admin/policy/grants/{grant_ref}",
            get(admin_policy_grants_get)
                .patch(admin_policy_grants_patch)
                .delete(admin_policy_grants_delete),
        )
        .route(
            "/v1/admin/policy/grants/{grant_ref}/enable",
            post(admin_policy_grants_enable),
        )
        .route(
            "/v1/admin/policy/grants/{grant_ref}/disable",
            post(admin_policy_grants_disable),
        )
        .route(
            "/v1/admin/groups",
            get(admin_groups_list).post(admin_groups_create),
        )
        .route(
            "/v1/admin/groups/{group}",
            get(admin_groups_get).patch(admin_groups_patch),
        )
        .route(
            "/v1/admin/groups/{group}/members",
            get(admin_group_members_list),
        )
        .route(
            "/v1/admin/groups/{group}/members/{principal}",
            put(admin_group_member_add).delete(admin_group_member_delete),
        )
        .route(
            "/v1/admin/groups/{group}/external-group-bindings",
            get(admin_external_group_bindings_list).post(admin_external_group_binding_create),
        )
        .route(
            "/v1/admin/groups/{group}/external-group-bindings/{binding}",
            patch(admin_external_group_binding_patch).delete(admin_external_group_binding_delete),
        )
        .route(
            "/v1/admin/principals",
            get(admin_principals_list).post(admin_principals_create),
        )
        .route(
            "/v1/admin/principals/{principal}",
            get(admin_principals_get).patch(admin_principals_patch),
        )
        .route(
            "/v1/admin/principals/{principal}/groups/{group}",
            put(admin_principal_group_add).delete(admin_principal_group_delete),
        )
        .route(
            "/v1/admin/principals/{principal}/access",
            patch(admin_principal_access_patch),
        )
        .route(
            "/v1/admin/principals/{principal}/login-methods",
            get(admin_principal_login_methods_list),
        )
        .route(
            "/v1/admin/principals/{principal}/login-methods/local-password",
            put(admin_principal_local_password_reset)
                .delete(admin_principal_local_password_disable),
        )
        .route(
            "/v1/admin/principals/{principal}/login-methods/local-password/enable",
            post(admin_principal_local_password_enable),
        )
        .route(
            "/v1/admin/principals/{principal}/login-methods/local-password/unlock",
            post(admin_principal_local_password_unlock),
        )
        .route(
            "/v1/admin/principals/{principal}/login-methods/oidc/microsoft",
            put(admin_principal_microsoft_oidc_link).delete(admin_principal_microsoft_oidc_unlink),
        )
        .route(
            "/v1/admin/principals/{principal}/services",
            get(admin_principal_services),
        )
        .route(
            "/v1/admin/principals/{principal}/service-limits",
            get(service_limits::list),
        )
        .route(
            "/v1/admin/principals/{principal}/service-limits/{service}",
            put(service_limits::set).delete(service_limits::clear),
        )
        .route(
            "/v1/admin/principals/{principal}/credentials",
            get(admin_principal_credentials_list),
        )
        .route(
            "/v1/admin/principals/{principal}/credentials/targets",
            get(admin_principal_credential_targets),
        )
        .route(
            "/v1/admin/principals/{principal}/agent-token-options",
            get(admin_principal_agent_token_options),
        )
        .route(
            "/v1/admin/principals/{principal}/agent-tokens",
            get(admin_principal_agent_tokens_list).post(admin_principal_agent_token_issue),
        )
        .route(
            "/v1/admin/principals/{principal}/agent-tokens/{token_id}",
            get(admin_principal_agent_token_get).delete(admin_principal_agent_token_revoke),
        )
        .route(
            "/v1/admin/principals/{principal}/agent-tokens/{token_id}/pause",
            post(admin_principal_agent_token_pause),
        )
        .route(
            "/v1/admin/principals/{principal}/agent-tokens/{token_id}/resume",
            post(admin_principal_agent_token_resume),
        )
        .route(
            "/v1/admin/principals/{principal}/tokens",
            post(admin_principal_token_issue),
        )
        .route(
            "/v1/admin/principals/{principal}/credentials/connections/{connection}",
            get(admin_principal_credential_get)
                .put(admin_principal_credential_put)
                .delete(admin_principal_credential_delete),
        )
        .route(
            "/v1/admin/principals/{principal}/credentials/connections/{connection}/verify",
            post(admin_principal_credential_verify),
        )
        .route(
            "/v1/admin/principals/{principal}/credentials/connections/{connection}/input-schema",
            get(admin_principal_credential_input_schema),
        )
        .route(
            "/v1/admin/rights",
            get(admin_rights_list).post(admin_rights_grant),
        )
        .route("/v1/admin/rights/{right_id}", delete(admin_right_revoke))
        .route("/v1/admin/tokens", get(admin_tokens_list))
        .route(
            "/v1/admin/tokens/{token_id}",
            get(admin_token_get).delete(admin_token_revoke),
        )
        .route("/v1/admin/tokens/{token_id}/pause", post(admin_token_pause))
        .route(
            "/v1/admin/tokens/{token_id}/resume",
            post(admin_token_resume),
        )
        .route("/v1/admin/credentials", get(admin_credentials_list))
        .route(
            "/v1/admin/credentials/rewrap",
            post(admin_credentials_rewrap),
        )
        .route(
            "/v1/admin/credentials/{credential_id}",
            get(admin_credential_get).delete(admin_credential_delete),
        )
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            crate::ingress::body::admit_public_body,
        ))
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            verify_caller_ingress,
        ))
        .layer(axum::middleware::from_fn(
            crate::membership_renewal::scope_request_renewal,
        ))
        .layer(RequestTracingLayer::new(ListenerKind::Public, &node_id))
        .with_state(AppState { reloadable: state });
    (router, endpoint)
}

pub(crate) fn build_gateway_router(state: Arc<ReloadableState>) -> Router {
    let node_id = state.node_id();
    Router::new()
        .fallback(gateway_dispatch)
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            crate::ingress::body::admit_gateway_body,
        ))
        .layer(axum::middleware::map_response(
            crate::handlers::gateway::gateway_cache_policy,
        ))
        .layer(axum::middleware::from_fn(
            crate::membership_renewal::scope_request_renewal,
        ))
        .layer(RequestTracingLayer::new(ListenerKind::Gateway, &node_id))
        .with_state(AppState { reloadable: state })
}

async fn verify_caller_ingress(
    axum::extract::State(state): axum::extract::State<Arc<ReloadableState>>,
    mut request: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    let snapshot = state.current();
    let mcp = crate::mcp::is_mcp_route(&request);
    // Legacy MCP has a deliberately finite transport error for all trailers.
    // Check declarations before general protected-header admission can replace
    // that contract with an assertion envelope.
    if mcp
        && request.headers().contains_key("trailer")
        && !request
            .headers()
            .contains_key(agent_access_core::USER_HEADER)
    {
        return crate::mcp::trailers_failure();
    }
    let admitted = if mcp {
        snapshot.runtime.admit_mcp_ingress(request.headers())
    } else {
        snapshot.runtime.admit_ingress(request.headers())
    };
    match admitted {
        Ok(admission) => {
            if mcp {
                request.extensions_mut().insert(crate::mcp::McpIngress {
                    snapshot,
                    admission,
                });
            }
            next.run(request).await
        }
        Err(failure) => {
            let remote = request
                .extensions()
                .get::<axum::extract::ConnectInfo<std::net::SocketAddr>>()
                .map(|info| info.0);
            admission_failure_response(
                &AppState { reloadable: state },
                snapshot,
                request.headers(),
                remote,
                failure,
            )
            .await
        }
    }
}

/// Canonical pre-protocol admission errors, shared by router validation and MCP
/// live-proof checks. Generate correlation before any JSON-RPC body is parsed.
pub(crate) async fn admission_failure_response(
    app_state: &AppState,
    snapshot: Arc<RuntimeSnapshot>,
    headers: &axum::http::HeaderMap,
    remote: Option<std::net::SocketAddr>,
    failure: agent_access_core::IdentityFailure,
) -> axum::response::Response {
    use crate::handlers::common::{
        acquire_global_concurrency_guard, check_auth_source_rate_guard, envelope_response,
    };
    use agent_access_core::{
        IdentityContext, OperationContext, SourceContext, new_broker_request_id,
    };
    use agent_access_provider::REQUEST_ID_HEADER;
    use axum::response::IntoResponse;
    crate::observability::record_execution_context_failure(failure.reason_code().as_str());
    // Browser, health and MCP requests need not carry an agent request ID. For rejected
    // ingress, generate correlation when absent or malformed without trusting other headers.
    let mut ids = headers.get_all(REQUEST_ID_HEADER).iter();
    let supplied_id = ids
        .next()
        .and_then(|value| value.to_str().ok())
        .filter(|value| {
            !value.is_empty()
                && value.len() <= 128
                && value
                    .bytes()
                    .all(|ch| ch.is_ascii_alphanumeric() || b"._-".contains(&ch))
        })
        .filter(|_| ids.next().is_none());
    let agent_request_id = supplied_id
        .map(str::to_owned)
        .unwrap_or_else(new_broker_request_id);
    let source = SourceContext {
        listener: "http".into(),
        remote: remote
            .map(|addr| addr.to_string())
            .unwrap_or_else(|| "unknown".into()),
        proxy_chain: Vec::new(),
        agent_request_id_generated: Some(supplied_id.is_none()),
    };
    let service = "broker".to_string();
    let action = crate::handlers::management::audit_actions::CALLER_AUTHENTICATE.to_string();
    let _permit = match acquire_global_concurrency_guard(
        app_state,
        &snapshot,
        &agent_request_id,
        service.clone(),
        action.clone(),
        &source,
    )
    .await
    {
        Ok(permit) => permit,
        Err(response) => {
            return admission_response_headers(envelope_response(*response).into_response());
        }
    };
    if let Err(response) = check_auth_source_rate_guard(
        app_state,
        &snapshot,
        &agent_request_id,
        service.clone(),
        action.clone(),
        &source,
    )
    .await
    {
        return admission_response_headers(envelope_response(*response).into_response());
    }
    let response = snapshot
        .runtime
        .ingress_error_response_for_operation(
            OperationContext {
                agent_request_id,
                broker_request_id: new_broker_request_id(),
                identity: IdentityContext::anonymous(),
                service,
                action,
                source,
            },
            failure,
        )
        .await;
    admission_response_headers(envelope_response(response).into_response())
}

fn admission_response_headers(mut response: axum::response::Response) -> axum::response::Response {
    use axum::http::{HeaderValue, StatusCode};
    response
        .headers_mut()
        .insert("cache-control", HeaderValue::from_static("no-store"));
    if response.status() == StatusCode::UNAUTHORIZED {
        response.headers_mut().insert(
            "www-authenticate",
            HeaderValue::from_static("Bearer realm=\"agent-access-broker\""),
        );
    }
    response
}
