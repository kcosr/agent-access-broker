//! Human-owned delegated service connections. Broker invocation tokens cannot consent.
use super::common::{
    ManagementAccess, ManagementContext, management_context, management_context_error_response,
    management_success_response, management_write_audit_preflight,
};
use super::connections;
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
use std::collections::BTreeMap;
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

/// The registrations the signed-in user's credential connections select
/// OAuth for, each with its binding, the selecting connections and their
/// consumers in configured order.
struct RegistrationConsumers {
    binding: OAuthBinding,
    connections: Vec<String>,
    consumers: Vec<String>,
}

fn selected_registrations(context: &ManagementContext) -> BTreeMap<String, RegistrationConsumers> {
    let runtime = &context.snapshot.runtime;
    let mut registrations = BTreeMap::<String, RegistrationConsumers>::new();
    for connection in connections::connection_ids(runtime) {
        // The signed-in principal's kind selects the connection's method.
        let Some(agent_access_core::Selection::OAuth(oauth)) =
            connections::selection(runtime, &connection, context.identity.principal_kind)
        else {
            continue;
        };
        let entry = registrations
            .entry(oauth.registration.clone())
            .or_insert_with(|| RegistrationConsumers {
                binding: oauth.binding(),
                connections: Vec::new(),
                consumers: Vec::new(),
            });
        entry
            .consumers
            .extend(connections::consumers(runtime, &connection));
        entry.connections.push(connection);
    }
    registrations
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

/// The consumers of a registration the user may set up through, and why
/// the others are unavailable.
fn entitlement(
    context: &ManagementContext,
    consumers: &[String],
) -> Result<(Vec<String>, Vec<&'static str>), OAuthError> {
    let mut entitled = Vec::new();
    let mut reasons = Vec::new();
    for service in consumers {
        match setup_unavailable_reason(context, service)? {
            None => entitled.push(service.clone()),
            Some(reason) => reasons.push(reason),
        }
    }
    Ok((entitled, reasons))
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
    let owned_connections = match manager.list(&context.identity.principal) {
        Ok(c) => c,
        Err(e) => return error(&context, operation, e).await,
    };
    let mut rows = Vec::new();
    for (registration_id, selected) in selected_registrations(&context) {
        let (entitled, reasons) = match entitlement(&context, &selected.consumers) {
            Ok(entitlement) => entitlement,
            Err(failure) => return error(&context, operation, failure).await,
        };
        let connection = owned_connections
            .iter()
            .find(|c| c.registration == registration_id);
        let owned = connection.is_some_and(|c| c.connection_id.is_some());
        // Without a consumer to set up through, an owned connection stays
        // listed for local disconnect.
        let unavailable = if entitled.is_empty() {
            if !owned {
                continue;
            }
            Some(if reasons.contains(&"service_unavailable") {
                "service_unavailable"
            } else {
                "no_personal_access"
            })
        } else {
            None
        };
        let Some(registration) = manager.config().registrations.get(&registration_id) else {
            continue;
        };
        let Some(profile) = registration
            .permission_profiles
            .get(&selected.binding.permission_profile)
        else {
            continue;
        };
        let (consumers, other_consumers) =
            registration_consumer_view(runtime, &selected, &entitled);
        // The backend describes its own connection.
        let description = entitled
            .first()
            .or(selected.consumers.first())
            .and_then(|service| runtime.service_descriptor(service))
            .and_then(|descriptor| {
                descriptor
                    .credentials
                    .delegated
                    .as_ref()
                    .map(|connection| connection.description)
            });
        let display_name = connections::display_name(runtime, &selected.connections[0]);
        rows.push(json!({"registration":registration_id,
            "permissionProfile":selected.binding.permission_profile,
            "displayName":display_name,"connectionDescription":description,
            "scopeMode":profile.scope_mode,"requestedScopes":profile.requested_scopes(),
            "target":profile.target,"consumers":consumers,"otherConsumers":other_consumers,
            "canConnect":unavailable.is_none(),"connectUnavailableReason":unavailable,
            "canDisconnect":owned,"connection":connection}));
    }
    private_response(management_success_response(&context, operation, None, json!(rows)).await)
}

/// The entitled consumers across a registration's connections and the
/// count of its other consumers.
fn registration_consumer_view(
    runtime: &agent_access_core::BrokerRuntime,
    selected: &RegistrationConsumers,
    entitled: &[String],
) -> (Vec<connections::ConnectionConsumer>, usize) {
    let mut views = Vec::new();
    for service in entitled {
        if let Some(descriptor) = runtime.service_descriptor(service) {
            views.push(connections::ConnectionConsumer {
                service: service.clone(),
                display_name: descriptor.display_name.clone(),
                credential_verification_inputs: descriptor.credential_verification_inputs(),
            });
        }
    }
    let other = selected.consumers.len().saturating_sub(views.len());
    (views, other)
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct ConnectBody {
    registration: String,
    /// The imported service whose administrator discovery, or whose
    /// catalog page, this connection serves.
    #[serde(default)]
    imported_service: Option<String>,
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
    let mut registrations = selected_registrations(&context);
    let Some(selected) = registrations.remove(&body.registration) else {
        return error(&context, operation, OAuthError::Configuration).await;
    };
    let (entitled, _) = match entitlement(&context, &selected.consumers) {
        Ok(entitlement) => entitlement,
        Err(failure) => return error(&context, operation, failure).await,
    };
    let admission_service = match body.imported_service.as_deref() {
        Some(service) => {
            if !selected
                .consumers
                .iter()
                .any(|consumer| consumer == service)
                || context
                    .snapshot
                    .runtime
                    .imported_catalog()
                    .service(service)
                    .is_none()
            {
                return error(&context, operation, OAuthError::Configuration).await;
            }
            if !entitled.iter().any(|consumer| consumer == service) {
                return error(&context, operation, OAuthError::SetupDenied).await;
            }
            service.to_string()
        }
        None => {
            if body.return_path == Some(OAuthReturnPath::Catalog) {
                return error(&context, operation, OAuthError::Configuration).await;
            }
            match entitled.first() {
                Some(service) => service.clone(),
                None => return error(&context, operation, OAuthError::SetupDenied).await,
            }
        }
    };
    let Some(manager) = context.snapshot.runtime.oauth_manager() else {
        return error(&context, operation, OAuthError::Configuration).await;
    };
    let mut target = json!({"registration": body.registration});
    if let Some(service) = &body.imported_service {
        target["importedService"] = json!(service);
    }
    if let Err(r) = management_write_audit_preflight(&context, operation, Some(target)).await {
        return *r;
    }
    match manager
        .connect(
            &context.identity.principal,
            session(&context).unwrap(),
            &selected.binding,
            body.intent,
            OAuthManagementAdmission {
                imported_service_version: context
                    .snapshot
                    .runtime
                    .imported_catalog()
                    .service(&admission_service)
                    .map(|r| r.version),
                service: admission_service,
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
    Path(registration): Path<String>,
) -> Response {
    let operation = "oauth.connections.disconnect";
    let context = match browser_context(&state, remote, &headers, operation).await {
        Ok(c) => c,
        Err(r) => return *r,
    };
    let Some(manager) = context.snapshot.runtime.oauth_manager() else {
        return error(&context, operation, OAuthError::Configuration).await;
    };
    if !manager.config().registrations.contains_key(&registration) {
        return error(&context, operation, OAuthError::Configuration).await;
    }
    let owned = match manager.status(&context.identity.principal, &registration) {
        Ok(connection) => connection.connection_id.is_some(),
        Err(failure) => return error(&context, operation, failure).await,
    };
    if let Err(r) = management_write_audit_preflight(
        &context,
        operation,
        Some(json!({"registration": registration})),
    )
    .await
    {
        return *r;
    }
    if owned
        && let Err(failure) = manager
            .disconnect(&context.identity.principal, &registration)
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
