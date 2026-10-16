//! Human-owned delegated service connections. Broker invocation tokens cannot consent.
use super::common::{
    ManagementAccess, ManagementContext, management_context, management_context_error_response,
    management_success_response, management_write_audit_preflight,
};
use crate::state::AppState;
use agent_access_core::{
    OAuthBinding, OAuthConnectIntent, OAuthError, OAuthManagementAdmission, OAuthReturnPath,
};
use agent_access_provider::{CorrelationContext, ReasonCode, host::with_correlation_context};
use axum::Json;
use axum::extract::{ConnectInfo, Path, RawQuery, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::response::Response;
use serde::Deserialize;
use serde_json::json;
use std::collections::{BTreeMap, BTreeSet};
use std::net::SocketAddr;
use std::sync::Arc;

mod completion;

fn private_response(mut response: Response) -> Response {
    response
        .headers_mut()
        .insert("cache-control", HeaderValue::from_static("no-store"));
    response
        .headers_mut()
        .insert("referrer-policy", HeaderValue::from_static("no-referrer"));
    response
}

async fn error(context: &ManagementContext, operation: &str, failure: OAuthError) -> Response {
    let (status, reason) = match failure {
        OAuthError::SelfServiceDisabled => (StatusCode::FORBIDDEN, ReasonCode::SelfServiceDisabled),
        OAuthError::SetupDenied => (StatusCode::FORBIDDEN, ReasonCode::ServiceActionDenied),
        _ => (StatusCode::BAD_REQUEST, ReasonCode::CredentialInvalid),
    };
    private_response(
        management_context_error_response(context, status, operation, reason, failure.code(), None)
            .await,
    )
}

fn session(context: &ManagementContext) -> Option<&str> {
    context
        .identity
        .source
        .as_ref()
        .filter(|s| s.name == "browser-session")
        .and_then(|s| s.token_id.as_deref())
}

async fn browser_context(
    state: &AppState,
    remote: SocketAddr,
    headers: &HeaderMap,
    operation: &str,
) -> Result<ManagementContext, Box<Response>> {
    let context =
        management_context(state, remote, headers, operation, ManagementAccess::User).await?;
    if session(&context).is_none() {
        return Err(Box::new(private_response(
            management_context_error_response(
                &context,
                StatusCode::FORBIDDEN,
                operation,
                ReasonCode::ManagementDenied,
                "A signed-in browser session is required for OAuth connections",
                None,
            )
            .await,
        )));
    }
    Ok(context)
}

fn binding(context: &ManagementContext, service: &str) -> Result<OAuthBinding, OAuthError> {
    let runtime = &context.snapshot.runtime;
    if let Some(connection) = runtime.effective_credentials().personal_connection(service) {
        // The signed-in principal's kind selects the connection's method.
        return match connection.select(context.identity.principal_kind) {
            agent_access_core::Selection::OAuth(oauth) => Ok(oauth.binding()),
            _ => Err(OAuthError::Configuration),
        };
    }
    let credential = runtime
        .effective_credentials()
        .per_user
        .get(service)
        .filter(|c| c.kind == "oauth")
        .ok_or(OAuthError::Configuration)?;
    Ok(OAuthBinding {
        registration: credential
            .provider
            .clone()
            .ok_or(OAuthError::Configuration)?,
        permission_profile: credential
            .profile
            .clone()
            .ok_or(OAuthError::Configuration)?,
    })
}

fn setup_unavailable_reason(
    context: &ManagementContext,
    service: &str,
) -> Result<Option<&'static str>, OAuthError> {
    let runtime = &context.snapshot.runtime;
    if let Some(record) = runtime.imported_catalog().service(service)
        && (record.status == agent_access_core::ImportedServiceStatus::Retired
            || runtime
                .require_import_destination(&record.definition)
                .is_err())
    {
        return Ok(Some("service_unavailable"));
    }
    let store = runtime.managed_store().ok_or(OAuthError::Storage)?;
    let admin_discovery = store
        .can_manage_imported_oauth(&context.identity.principal, service)
        .map_err(|_| OAuthError::Storage)?;
    Ok((!admin_discovery
        && !runtime.has_any_per_user_policy_for_service(&context.identity, service))
    .then_some("no_personal_access"))
}

fn binding_for_setup(
    context: &ManagementContext,
    service: &str,
) -> Result<OAuthBinding, OAuthError> {
    let binding = binding(context, service)?;
    if setup_unavailable_reason(context, service)?.is_some() {
        return Err(OAuthError::SetupDenied);
    }
    Ok(binding)
}

pub(crate) async fn list(
    State(state): State<AppState>,
    ConnectInfo(remote): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> Response {
    let operation = "oauth.connections.list";
    let context = match browser_context(&state, remote, &headers, operation).await {
        Ok(c) => c,
        Err(r) => return *r,
    };
    let runtime = &context.snapshot.runtime;
    let Some(manager) = runtime.oauth_manager() else {
        return private_response(
            management_success_response(&context, operation, None, json!([])).await,
        );
    };
    let connections = match manager.list(&context.identity.principal) {
        Ok(c) => c,
        Err(e) => return error(&context, operation, e).await,
    };
    let mut candidates = Vec::new();
    let mut entitled_registrations = BTreeSet::new();
    for service in runtime.effective_credentials().per_user.keys() {
        let Ok(binding) = binding(&context, service) else {
            continue;
        };
        let unavailable = match setup_unavailable_reason(&context, service) {
            Ok(reason) => reason,
            Err(failure) => return error(&context, operation, failure).await,
        };
        if unavailable.is_none() {
            entitled_registrations.insert(binding.registration.clone());
        }
        candidates.push((service, binding, unavailable));
    }
    let mut rows = Vec::new();
    let mut cleanup_registrations = BTreeSet::new();
    for (service, binding, unavailable) in candidates {
        let connection = connections
            .iter()
            .find(|c| c.registration == binding.registration);
        let owned = connection.is_some_and(|c| c.connection_id.is_some());
        if unavailable.is_some()
            && (!owned
                || entitled_registrations.contains(&binding.registration)
                || !cleanup_registrations.insert(binding.registration.clone()))
        {
            continue;
        }
        let Some(registration) = manager.config().registrations.get(&binding.registration) else {
            continue;
        };
        let Some(profile) = registration
            .permission_profiles
            .get(&binding.permission_profile)
        else {
            continue;
        };
        // The backend describes its own connection; the portal names no service.
        let descriptor = runtime.service_descriptor(service);
        let display_name = descriptor.as_ref().map_or(service.as_str(), |descriptor| {
            descriptor.display_name.as_str()
        });
        let description = descriptor
            .as_ref()
            .and_then(|descriptor| descriptor.credentials.delegated.as_ref())
            .map(|connection| connection.description);
        rows.push(json!({"service":service,"serviceDisplayName":display_name,
            "connectionDescription":description,"registration":binding.registration,
            "permissionProfile":binding.permission_profile,"scopeMode":profile.scope_mode,
            "requestedScopes":profile.requested_scopes(),
            "target":profile.target,"canConnect":unavailable.is_none(),
            "connectUnavailableReason":unavailable,
            "canDisconnect":owned,"connection":connection}));
    }
    private_response(management_success_response(&context, operation, None, json!(rows)).await)
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct ConnectBody {
    service: String,
    #[serde(default)]
    intent: OAuthConnectIntent,
    return_path: Option<OAuthReturnPath>,
}

pub(crate) async fn connect(
    State(state): State<AppState>,
    ConnectInfo(remote): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(body): Json<ConnectBody>,
) -> Response {
    let operation = "oauth.connections.connect";
    let context = match browser_context(&state, remote, &headers, operation).await {
        Ok(c) => c,
        Err(r) => return *r,
    };
    let binding = match binding_for_setup(&context, &body.service) {
        Ok(b) => b,
        Err(e) => return error(&context, operation, e).await,
    };
    let Some(manager) = context.snapshot.runtime.oauth_manager() else {
        return error(&context, operation, OAuthError::Configuration).await;
    };
    if let Err(r) =
        management_write_audit_preflight(&context, operation, Some(json!({"service":body.service})))
            .await
    {
        return *r;
    }
    match manager
        .connect(
            &context.identity.principal,
            session(&context).unwrap(),
            &binding,
            body.intent,
            OAuthManagementAdmission {
                imported_service_version: context
                    .snapshot
                    .runtime
                    .imported_catalog()
                    .service(&body.service)
                    .map(|r| r.version),
                service: body.service,
                credential_name: "default".into(),
                return_path: body.return_path,
            },
            {
                let reloadable = state.reloadable.clone();
                Arc::new(move || Arc::new(reloadable.current().runtime.clone()))
            },
        )
        .await
    {
        Ok(result) => private_response(
            management_success_response(&context, operation, None, json!(result)).await,
        ),
        Err(e) => error(&context, operation, e).await,
    }
}

pub(crate) async fn disconnect(
    State(state): State<AppState>,
    ConnectInfo(remote): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Path(service): Path<String>,
) -> Response {
    let operation = "oauth.connections.disconnect";
    let context = match browser_context(&state, remote, &headers, operation).await {
        Ok(c) => c,
        Err(r) => return *r,
    };
    let binding = match binding(&context, &service) {
        Ok(b) => b,
        Err(e) => return error(&context, operation, e).await,
    };
    let Some(manager) = context.snapshot.runtime.oauth_manager() else {
        return error(&context, operation, OAuthError::Configuration).await;
    };
    let owned = match manager.status(&context.identity.principal, &binding.registration) {
        Ok(connection) => connection.connection_id.is_some(),
        Err(failure) => return error(&context, operation, failure).await,
    };
    if let Err(r) =
        management_write_audit_preflight(&context, operation, Some(json!({"service":service})))
            .await
    {
        return *r;
    }
    if owned
        && let Err(failure) = manager
            .disconnect(&context.identity.principal, &binding.registration)
            .await
    {
        return error(&context, operation, failure).await;
    }
    private_response(
        management_success_response(
            &context,
            operation,
            None,
            json!({"disconnected":true,"remoteRevocation":"not_requested"}),
        )
        .await,
    )
}

pub(crate) async fn callback(
    State(state): State<AppState>,
    ConnectInfo(remote): ConnectInfo<SocketAddr>,
    mut headers: HeaderMap,
    Path(registration): Path<String>,
    RawQuery(raw): RawQuery,
) -> Response {
    let operation = crate::handlers::management::audit_actions::OAUTH_CONNECTIONS_CALLBACK;
    // A top-level provider redirect cannot attach the API correlation header.
    // Generate one only for this browser endpoint; supplied values still pass
    // the normal management validation and every identity/CSRF admission stays intact.
    if !headers.contains_key(agent_access_provider::REQUEST_ID_HEADER) {
        headers.insert(
            agent_access_provider::REQUEST_ID_HEADER,
            HeaderValue::from_str(&format!(
                "oauth-{}",
                agent_access_core::new_broker_request_id()
            ))
            .expect("generated OAuth request ID is a valid header"),
        );
    }

    let context = match browser_context(&state, remote, &headers, operation).await {
        Ok(c) => c,
        Err(r) => return *r,
    };
    let Some(raw) = raw else {
        // Completion HTML clears its one-use query. Reloading that document is
        // a neutral browser page read, not another consent attempt. Authentication
        // above still applies; do not inspect or mutate a flow, or audit a result.
        return completion::status_page();
    };
    if raw.len() > 8192 {
        return error(&context, operation, OAuthError::InvalidFlow).await;
    }
    let mut params = BTreeMap::new();
    for (key, value) in url::form_urlencoded::parse(raw.as_bytes()) {
        // OAuth servers may append extension parameters (Google includes scope,
        // authuser and prompt). Bound and reject duplicates, but ignore their value.
        if key.is_empty()
            || key.len() > 128
            || params.len() >= 32
            || value.len() > 4096
            || params
                .insert(key.into_owned(), value.into_owned())
                .is_some()
        {
            return error(&context, operation, OAuthError::InvalidFlow).await;
        }
    }
    let Some(state_token) = params.get("state").filter(|s| !s.is_empty()) else {
        return error(&context, operation, OAuthError::InvalidFlow).await;
    };
    let Some(manager) = context.snapshot.runtime.oauth_manager() else {
        return error(&context, operation, OAuthError::Configuration).await;
    };
    let issuer = match manager.callback_issuer(
        &context.identity.principal,
        session(&context).unwrap(),
        &registration,
        state_token,
    ) {
        Ok(issuer) => issuer,
        Err(oauth_error) => return error(&context, operation, oauth_error).await,
    };
    if !issuer.accepts(params.get("iss").map(String::as_str)) {
        return error(&context, operation, OAuthError::InvalidFlow).await;
    }
    let return_path = match manager.callback_return_path(
        &context.identity.principal,
        session(&context).unwrap(),
        &registration,
        state_token,
    ) {
        Ok(path) => path,
        Err(oauth_error) => return error(&context, operation, oauth_error).await,
    };
    if let Err(r) = management_write_audit_preflight(
        &context,
        operation,
        Some(json!({"registration":registration})),
    )
    .await
    {
        return *r;
    }
    // Code exchange and discovery carry this callback's request IDs upstream.
    let correlation = CorrelationContext::new(
        context.request_id.clone(),
        context.broker_request_id.clone(),
    );
    let canceled = params.contains_key("error") && !params.contains_key("code");
    let result = if canceled {
        manager
            .cancel(
                &context.identity.principal,
                session(&context).unwrap(),
                &registration,
                state_token,
            )
            .await
    } else if let Some(code) = params
        .get("code")
        .filter(|c| !c.is_empty() && !params.contains_key("error"))
    {
        with_correlation_context(
            correlation,
            manager.complete(
                &context.identity.principal,
                session(&context).unwrap(),
                &registration,
                state_token,
                code,
                {
                    let reloadable = state.reloadable.clone();
                    Arc::new(move || Arc::new(reloadable.current().runtime.clone()))
                },
            ),
        )
        .await
        .map(|_| ())
    } else {
        Err(OAuthError::InvalidFlow)
    };
    if let Err(e) = result {
        return error(&context, operation, e).await;
    }
    // Audit contains the outcome only, never the callback code, state, or tokens.
    let response = management_success_response(
        &context,
        operation,
        Some(json!({"registration":registration})),
        json!({"completed":true}),
    )
    .await;
    if !response.status().is_success() {
        return private_response(response);
    }
    let outcome = if !canceled {
        completion::Outcome::Authorized
    } else if params.get("error").map(String::as_str) == Some("access_denied") {
        completion::Outcome::Denied
    } else {
        completion::Outcome::ProviderError
    };
    completion::page(response, &return_path, outcome)
}
