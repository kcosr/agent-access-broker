//! The OAuth 2.0 authorization server registered applications use: metadata
//! (RFC 8414), the authorization endpoint, the token endpoint and revocation
//! (RFC 7009). The token and revocation endpoints answer RFC 6749 JSON, never
//! a Broker envelope. Client secrets, codes, verifiers and refresh tokens
//! never reach logs, audit records or error text.
use crate::handlers::auth::auth_request_ids;
use crate::handlers::management::audit_actions::{
    APPLICATIONS_TOKEN_ISSUED, APPLICATIONS_TOKEN_REFUSED, APPLICATIONS_TOKEN_REVOKED,
};
use crate::ingress::source::auth_source_key;
use crate::observability;
use crate::state::{AppState, RuntimeSnapshot};
use agent_access_core::{
    ApplicationAuthorizationParameters, ApplicationGrant, ApplicationGrantRefusal,
    ApplicationRevocation, AuditRecord, ManagedStoreError, RegisteredApplication, SourceContext,
    is_valid_application_code_challenge,
};
use agent_access_provider::{Decision, ReasonCode, ResourceScopes};
use axum::body::Bytes;
use axum::extract::{ConnectInfo, RawQuery, Request, State};
use axum::http::header::{
    AUTHORIZATION, CACHE_CONTROL, CONTENT_TYPE, LOCATION, RETRY_AFTER, WWW_AUTHENTICATE,
};
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use base64::Engine;
use chrono::Utc;
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tracing::Instrument;
use tracing::instrument::WithSubscriber;
use url::Url;

pub(crate) const METADATA_PATH: &str = "/.well-known/oauth-authorization-server";
pub(crate) const AUTHORIZE_PATH: &str = "/v1/applications/authorize";
pub(crate) const TOKEN_PATH: &str = "/v1/applications/token";
pub(crate) const REVOKE_PATH: &str = "/v1/applications/revoke";
/// The portal page a pending request's ID is appended to.
const CONSENT_PATH: &str = "/ui/authorize";

const QUERY_LIMIT_BYTES: usize = 8 * 1024;
const FORM_LIMIT_BYTES: usize = 16 * 1024;
const PARAM_LIMIT_BYTES: usize = 4 * 1024;
const STATE_LIMIT_BYTES: usize = 512;

/// Marks a response the token or revocation handler built, which already
/// follows the protocol's error contract.
#[derive(Clone, Copy)]
struct ProtocolResponse;

fn no_store(headers: &mut HeaderMap) {
    headers.insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
    headers.insert("pragma", HeaderValue::from_static("no-cache"));
}

fn protocol_json(status: StatusCode, body: Value) -> Response {
    observability::record_status(status.as_u16());
    let mut response = (status, axum::Json(body)).into_response();
    no_store(response.headers_mut());
    response.extensions_mut().insert(ProtocolResponse);
    response
}

fn protocol_error(status: StatusCode, error: &'static str) -> Response {
    observability::record_decision(Decision::Deny.as_str());
    let mut response = protocol_json(status, json!({ "error": error }));
    if status == StatusCode::UNAUTHORIZED {
        response.headers_mut().insert(
            WWW_AUTHENTICATE,
            HeaderValue::from_static("Basic realm=\"agent-access-broker\""),
        );
    }
    response
}

/// Keeps the token and revocation endpoints on the RFC 6749 error contract
/// for refusals made before their handlers run: transport admission, rate
/// limits, body limits and routing.
pub(crate) async fn protocol_error_contract(request: Request, next: Next) -> Response {
    let protocol = matches!(request.uri().path(), TOKEN_PATH | REVOKE_PATH);
    let response = next.run(request).await;
    if !protocol || response.extensions().get::<ProtocolResponse>().is_some() {
        return response;
    }
    let retry_after = response.headers().get(RETRY_AFTER).cloned();
    let (status, error) = match response.status().as_u16() {
        429 | 503 => (StatusCode::SERVICE_UNAVAILABLE, "temporarily_unavailable"),
        500..=599 => (StatusCode::INTERNAL_SERVER_ERROR, "server_error"),
        _ => (StatusCode::BAD_REQUEST, "invalid_request"),
    };
    let mut replaced = protocol_error(status, error);
    if let Some(retry_after) = retry_after {
        replaced.headers_mut().insert(RETRY_AFTER, retry_after);
    }
    replaced
}

/// The Broker's public origin while applications are registered.
fn issuer(snapshot: &RuntimeSnapshot) -> Option<String> {
    let config = snapshot.runtime.config();
    (!snapshot.runtime.applications().is_empty())
        .then_some(config.browser_auth.public_origin.as_deref())
        .flatten()
        .map(|origin| origin.trim_end_matches('/').to_string())
}

pub(crate) async fn metadata(State(state): State<AppState>) -> Response {
    let snapshot = state.reloadable.current();
    let Some(issuer) = issuer(&snapshot) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let mut response = axum::Json(json!({
        "issuer": issuer,
        "authorization_endpoint": format!("{issuer}{AUTHORIZE_PATH}"),
        "token_endpoint": format!("{issuer}{TOKEN_PATH}"),
        "revocation_endpoint": format!("{issuer}{REVOKE_PATH}"),
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code", "refresh_token"],
        "code_challenge_methods_supported": ["S256"],
        "token_endpoint_auth_methods_supported": ["client_secret_basic"],
        "revocation_endpoint_auth_methods_supported": ["client_secret_basic"],
    }))
    .into_response();
    no_store(response.headers_mut());
    response
}

/// The named parameters of a query or form. `None` when it is oversized or
/// repeats a parameter.
fn parameters(raw: &[u8], limit: usize) -> Option<BTreeMap<String, String>> {
    if raw.len() > limit {
        return None;
    }
    let mut values = BTreeMap::new();
    for (name, value) in url::form_urlencoded::parse(raw) {
        if value.len() > PARAM_LIMIT_BYTES
            || values
                .insert(name.into_owned(), value.into_owned())
                .is_some()
        {
            return None;
        }
    }
    Some(values)
}

/// A refusal the browser is shown directly: the client or its redirect URI
/// is not registered, so nothing is sent to the supplied address.
fn authorization_error_page(status: StatusCode, request_id: &str) -> Response {
    observability::record_decision(Decision::Deny.as_str());
    observability::record_status(status.as_u16());
    let body = format!(
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">\
         <title>Authorization request refused</title></head><body>\
         <h1>Authorization request refused</h1>\
         <p>The application that sent you here is not registered with this service, or its \
         request is not valid. Return to the application and try again, or contact your \
         administrator.</p><p>Request ID: {request_id}</p></body></html>"
    );
    let mut response = (status, body).into_response();
    let headers = response.headers_mut();
    headers.insert(
        CONTENT_TYPE,
        HeaderValue::from_static("text/html; charset=utf-8"),
    );
    headers.insert(
        "content-security-policy",
        HeaderValue::from_static("default-src 'none'; frame-ancestors 'none'"),
    );
    headers.insert(
        "x-content-type-options",
        HeaderValue::from_static("nosniff"),
    );
    headers.insert("referrer-policy", HeaderValue::from_static("no-referrer"));
    no_store(headers);
    response
}

fn see_other(location: &str) -> Response {
    observability::record_status(StatusCode::SEE_OTHER.as_u16());
    let mut response = StatusCode::SEE_OTHER.into_response();
    let headers = response.headers_mut();
    match HeaderValue::from_str(location) {
        Ok(location) => headers.insert(LOCATION, location),
        Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    };
    headers.insert("referrer-policy", HeaderValue::from_static("no-referrer"));
    no_store(headers);
    response
}

/// `redirect_uri` with the response parameters appended to its query.
pub(crate) fn application_redirect(
    redirect_uri: &str,
    parameters: &[(&str, &str)],
) -> Option<String> {
    let mut url = Url::parse(redirect_uri).ok()?;
    {
        let mut query = url.query_pairs_mut();
        for (name, value) in parameters {
            query.append_pair(name, value);
        }
    }
    Some(url.into())
}

fn valid_state(state: &str) -> bool {
    !state.is_empty()
        && state.len() <= STATE_LIMIT_BYTES
        && state.bytes().all(|byte| (0x20..=0x7e).contains(&byte))
}

pub(crate) async fn authorize(
    State(state): State<AppState>,
    ConnectInfo(remote_addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    RawQuery(raw_query): RawQuery,
) -> Response {
    let operation = "applications.authorize";
    let (request_id, _broker_request_id) = match auth_request_ids(&headers, operation) {
        Ok(ids) => ids,
        Err(response) => return *response,
    };
    let snapshot = state.reloadable.current();
    let source = snapshot
        .source_resolver
        .source_context(remote_addr, &headers);
    // The same budgets as the sign-in routes.
    let limits = snapshot.runtime.limits();
    let Ok(_permit) = state
        .reloadable
        .shared_ingress
        .try_global_concurrency(limits.max_concurrent_requests)
    else {
        return authorization_error_page(StatusCode::SERVICE_UNAVAILABLE, &request_id);
    };
    if state
        .reloadable
        .shared_ingress
        .check_auth_source_rate(
            &auth_source_key(&source),
            limits.auth_requests_per_source_per_minute,
        )
        .is_err()
    {
        return authorization_error_page(StatusCode::TOO_MANY_REQUESTS, &request_id);
    }
    let refused = |reason: &'static str| {
        tracing::info!(
            event = "application_authorization_refused",
            agentRequestId = request_id.as_str(),
            reason,
            "application authorization request refused"
        );
        authorization_error_page(StatusCode::BAD_REQUEST, &request_id)
    };
    let Some(query) = parameters(
        raw_query.as_deref().unwrap_or("").as_bytes(),
        QUERY_LIMIT_BYTES,
    ) else {
        return refused("query_invalid");
    };
    let Some(application) = query
        .get("client_id")
        .and_then(|client_id| snapshot.runtime.applications().get(client_id))
    else {
        return refused("client_unknown");
    };
    let Some(redirect_uri) = query
        .get("redirect_uri")
        .filter(|redirect_uri| application.accepts_redirect_uri(redirect_uri))
    else {
        return refused("redirect_uri_unregistered");
    };
    // Every later outcome returns to the registered redirect URI.
    let state_parameter = query.get("state").filter(|value| valid_state(value));
    let back = |error: &'static str| {
        observability::record_decision(Decision::Deny.as_str());
        tracing::info!(
            event = "application_authorization_refused",
            agentRequestId = request_id.as_str(),
            applicationId = application.id(),
            reason = error,
            "application authorization request returned an error"
        );
        let mut response = vec![("error", error)];
        if let Some(state_parameter) = state_parameter {
            response.push(("state", state_parameter.as_str()));
        }
        match application_redirect(redirect_uri, &response) {
            Some(location) => see_other(&location),
            None => authorization_error_page(StatusCode::BAD_REQUEST, &request_id),
        }
    };
    if query.contains_key("scope") {
        return back("invalid_scope");
    }
    let (Some(state_parameter), Some(code_challenge)) = (
        state_parameter,
        query
            .get("code_challenge")
            .filter(|challenge| is_valid_application_code_challenge(challenge)),
    ) else {
        return back("invalid_request");
    };
    if query.get("response_type").map(String::as_str) != Some("code")
        || query.get("code_challenge_method").map(String::as_str) != Some("S256")
    {
        return back("invalid_request");
    }
    let Some(hasher) = snapshot.runtime.broker_token_hasher().cloned() else {
        return back("server_error");
    };
    let application_id = application.id().to_string();
    let parameters = ApplicationAuthorizationParameters {
        redirect_uri: redirect_uri.clone(),
        state: state_parameter.clone(),
        code_challenge: code_challenge.clone(),
    };
    match snapshot
        .managed_store_call(move |store| {
            store.create_application_authorization_request(&hasher, &application_id, &parameters)
        })
        .await
    {
        Ok(pending_id) => {
            observability::record_decision(Decision::Allow.as_str());
            see_other(&format!("{CONSENT_PATH}/{pending_id}"))
        }
        Err(_) => back("server_error"),
    }
}

/// `client_secret_basic`: the form-urlencoded client ID and secret of RFC
/// 6749 section 2.3.1. `None` for anything else.
fn basic_credentials(headers: &HeaderMap) -> Option<(String, String)> {
    let mut values = headers.get_all(AUTHORIZATION).iter();
    let raw = values.next()?.to_str().ok()?;
    if values.next().is_some() {
        return None;
    }
    let (scheme, encoded) = raw.split_once(' ')?;
    if !scheme.eq_ignore_ascii_case("Basic") || encoded.len() > PARAM_LIMIT_BYTES {
        return None;
    }
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(encoded.trim())
        .ok()?;
    let decoded = String::from_utf8(decoded).ok()?;
    let (client_id, client_secret) = decoded.split_once(':')?;
    let decode = |value: &str| {
        let mut pairs = url::form_urlencoded::parse(value.as_bytes());
        let (decoded, rest) = pairs.next()?;
        (rest.is_empty() && pairs.next().is_none() && !value.contains(['&', '=']))
            .then(|| decoded.into_owned())
    };
    Some((decode(client_id)?, decode(client_secret)?))
}

struct ProtocolRequest {
    snapshot: Arc<RuntimeSnapshot>,
    request_id: String,
    broker_request_id: String,
    source: SourceContext,
    application: RegisteredApplication,
    form: BTreeMap<String, String>,
}

/// Authenticates the client and reads the form, or answers the refusal.
async fn protocol_request(
    state: &AppState,
    remote_addr: SocketAddr,
    headers: &HeaderMap,
    body: &Bytes,
    operation: &'static str,
) -> Result<ProtocolRequest, Box<Response>> {
    let (request_id, broker_request_id) = match auth_request_ids(headers, operation) {
        Ok(ids) => ids,
        Err(_) => {
            return Err(Box::new(protocol_error(
                StatusCode::BAD_REQUEST,
                "invalid_request",
            )));
        }
    };
    let snapshot = state.reloadable.current();
    let source = snapshot
        .source_resolver
        .source_context(remote_addr, headers);
    let credentials = basic_credentials(headers);
    let application = credentials.as_ref().and_then(|(client_id, client_secret)| {
        snapshot
            .runtime
            .applications()
            .authenticate(client_id, client_secret)
            .cloned()
    });
    let Some(application) = application else {
        // The claimed ID is recorded only when it names a registration.
        let claimed = credentials
            .as_ref()
            .map(|(client_id, _)| client_id.as_str())
            .filter(|client_id| snapshot.runtime.applications().get(client_id).is_some());
        let _ = append_audit(
            &snapshot,
            AuditEvent {
                request_id: &request_id,
                broker_request_id: &broker_request_id,
                source: &source,
                action: APPLICATIONS_TOKEN_REFUSED,
                principal: None,
                decision: Decision::Deny,
                reason_code: Some(ReasonCode::CallerAuthenticationInvalid),
                details: json!({
                    "applicationId": claimed,
                    "endpoint": operation,
                    "reason": "client_authentication_failed",
                }),
            },
        )
        .await;
        return Err(Box::new(protocol_error(
            StatusCode::UNAUTHORIZED,
            "invalid_client",
        )));
    };
    let form_content = headers
        .get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(';').next())
        .is_some_and(|value| {
            value
                .trim()
                .eq_ignore_ascii_case("application/x-www-form-urlencoded")
        });
    let form = form_content
        .then(|| parameters(body, FORM_LIMIT_BYTES))
        .flatten()
        // Credentials belong in the Authorization header only.
        .filter(|form| !form.contains_key("client_secret") && !form.contains_key("client_id"));
    let Some(form) = form else {
        return Err(Box::new(protocol_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
        )));
    };
    Ok(ProtocolRequest {
        snapshot,
        request_id,
        broker_request_id,
        source,
        application,
        form,
    })
}

struct AuditEvent<'a> {
    request_id: &'a str,
    broker_request_id: &'a str,
    source: &'a SourceContext,
    action: &'static str,
    principal: Option<&'a str>,
    decision: Decision,
    reason_code: Option<ReasonCode>,
    details: Value,
}

async fn append_audit(snapshot: &RuntimeSnapshot, event: AuditEvent<'_>) -> Result<(), ()> {
    observability::record_operation(event.action);
    if let Some(principal) = event.principal {
        observability::record_principal(principal);
    }
    let record = AuditRecord {
        caller_id: None,
        search_authorization: None,
        timestamp: Utc::now().to_rfc3339(),
        agent_request_id: event.request_id.to_string(),
        broker_request_id: event.broker_request_id.to_string(),
        config_generation: Some(snapshot.generation),
        policy_generation: Some(snapshot.runtime.policy_generation()),
        principal: event.principal.unwrap_or("anonymous").to_string(),
        principal_subject: None,
        groups: Vec::new(),
        service: "broker".to_string(),
        action: event.action.to_string(),
        resource_scopes: ResourceScopes::new(),
        matched_grant: None,
        credential_mode: Some(None),
        credential_connection: None,
        decision: event.decision,
        reason_code: event.reason_code.map(Into::into),
        upstream_status: None,
        upstream_duration_ms: None,
        object_ids: None,
        identity_source: None,
        source: event.source.clone(),
        execution_context: None,
        audit_inputs: Vec::new(),
        provider_audit: Some(json!({ "application": event.details })),
    };
    snapshot
        .runtime
        .append_audit_record(&record)
        .await
        .map_err(|_| ())
}

/// A store failure a later attempt may not meet again, or one it will.
fn store_failure(error: &ManagedStoreError) -> Response {
    match error {
        ManagedStoreError::Unavailable(_)
        | ManagedStoreError::VersionConflict
        | ManagedStoreError::ReloadInProgress => {
            protocol_error(StatusCode::SERVICE_UNAVAILABLE, "temporarily_unavailable")
        }
        _ => protocol_error(StatusCode::INTERNAL_SERVER_ERROR, "server_error"),
    }
}

pub(crate) async fn token(
    State(state): State<AppState>,
    ConnectInfo(remote_addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let request =
        match protocol_request(&state, remote_addr, &headers, &body, "applications.token").await {
            Ok(request) => request,
            Err(response) => return *response,
        };
    let field = |name: &str| {
        request
            .form
            .get(name)
            .filter(|value| !value.is_empty())
            .cloned()
    };
    enum Presented {
        Code(String, String, String),
        Refresh(String),
    }
    let presented = match request.form.get("grant_type").map(String::as_str) {
        Some("authorization_code") => {
            match (field("code"), field("redirect_uri"), field("code_verifier")) {
                (Some(code), Some(redirect_uri), Some(verifier)) => {
                    Presented::Code(code, redirect_uri, verifier)
                }
                _ => return protocol_error(StatusCode::BAD_REQUEST, "invalid_request"),
            }
        }
        Some("refresh_token") => match field("refresh_token") {
            Some(refresh_token) => Presented::Refresh(refresh_token),
            None => return protocol_error(StatusCode::BAD_REQUEST, "invalid_request"),
        },
        Some(_) => return protocol_error(StatusCode::BAD_REQUEST, "unsupported_grant_type"),
        None => return protocol_error(StatusCode::BAD_REQUEST, "invalid_request"),
    };
    let Some(hasher) = request.snapshot.runtime.broker_token_hasher().cloned() else {
        return protocol_error(StatusCode::SERVICE_UNAVAILABLE, "temporarily_unavailable");
    };
    // The token's commit and its completion audit belong to one owner that
    // outlives the response waiter. The reload fence keeps the registration
    // these terms come from current for the insertion.
    let owner = tokio::spawn(
        async move {
            let ProtocolRequest {
                snapshot,
                request_id,
                broker_request_id,
                source,
                application,
                ..
            } = request;
            let application_id = application.id().to_string();
            let terms = application.terms();
            let grant_type = match &presented {
                Presented::Code(..) => "authorization_code",
                Presented::Refresh(_) => "refresh_token",
            };
            let store_application = application_id.clone();
            let outcome = state
                .reloadable
                .token_store_call_from_snapshot(snapshot.clone(), move |runtime| {
                    let store = runtime.managed_store().ok_or_else(|| {
                        ManagedStoreError::Unavailable("managed store is unavailable".into())
                    })?;
                    let grant = match &presented {
                        Presented::Code(code, redirect_uri, code_verifier) => {
                            ApplicationGrant::AuthorizationCode {
                                code,
                                redirect_uri,
                                code_verifier,
                            }
                        }
                        Presented::Refresh(refresh_token) => {
                            ApplicationGrant::RefreshToken { refresh_token }
                        }
                    };
                    store.mint_application_token(&hasher, &store_application, terms.as_ref(), grant)
                })
                .await;
            match outcome {
                Ok(Ok(minted)) => {
                    let details = json!({
                        "applicationId": application_id,
                        "grantType": grant_type,
                        "accessId": minted.access.access_id,
                        "tokenId": minted.record.token_id,
                        "tokenClass": "agent_invoke",
                        "expiresAt": minted.record.expires_at,
                        "boundary": minted.record.scopes,
                    });
                    if append_audit(
                        &snapshot,
                        AuditEvent {
                            request_id: &request_id,
                            broker_request_id: &broker_request_id,
                            source: &source,
                            action: APPLICATIONS_TOKEN_ISSUED,
                            principal: Some(&minted.record.principal_id),
                            decision: Decision::Allow,
                            reason_code: None,
                            details,
                        },
                    )
                    .await
                    .is_err()
                    {
                        // The committed token stays; its secret is withheld.
                        tracing::error!(
                            event = "application_token_audit_append_failed",
                            agentRequestId = request_id.as_str(),
                            brokerRequestId = broker_request_id.as_str(),
                            applicationId = application_id.as_str(),
                            reasonCode = ReasonCode::AuditUnavailable.as_str(),
                            "an application token was committed but its audit record is unavailable"
                        );
                        return protocol_error(StatusCode::SERVICE_UNAVAILABLE, "server_error");
                    }
                    observability::record_decision(Decision::Allow.as_str());
                    let mut body = json!({
                        "access_token": minted.token,
                        "token_type": "Bearer",
                        "expires_in": minted.expires_in_seconds,
                        "principal_id": minted.record.principal_id,
                        "principal_name": minted.principal_name,
                        "read_only": minted.read_only,
                    });
                    if let Some(refresh_token) = &minted.refresh_token {
                        body["refresh_token"] = json!(refresh_token);
                    }
                    protocol_json(StatusCode::OK, body)
                }
                Ok(Err(refused)) => {
                    let _ = append_audit(
                        &snapshot,
                        AuditEvent {
                            request_id: &request_id,
                            broker_request_id: &broker_request_id,
                            source: &source,
                            action: APPLICATIONS_TOKEN_REFUSED,
                            principal: refused.principal_id.as_deref(),
                            decision: Decision::Deny,
                            reason_code: None,
                            details: json!({
                                "applicationId": application_id,
                                "endpoint": "applications.token",
                                "grantType": grant_type,
                                "accessId": refused.access_id,
                                "reason": refused.refusal,
                            }),
                        },
                    )
                    .await;
                    if refused.refusal == ApplicationGrantRefusal::TokenLimit {
                        protocol_error(StatusCode::SERVICE_UNAVAILABLE, "temporarily_unavailable")
                    } else {
                        protocol_error(StatusCode::BAD_REQUEST, "invalid_grant")
                    }
                }
                Err(error) => {
                    tracing::warn!(
                        event = "application_token_store_failed",
                        agentRequestId = request_id.as_str(),
                        brokerRequestId = broker_request_id.as_str(),
                        applicationId = application_id.as_str(),
                        reasonCode = error.reason_code().as_str(),
                        "application token request failed"
                    );
                    store_failure(&error)
                }
            }
        }
        .in_current_span()
        .with_current_subscriber(),
    );
    owner
        .await
        .unwrap_or_else(|_| protocol_error(StatusCode::INTERNAL_SERVER_ERROR, "server_error"))
}

pub(crate) async fn revoke(
    State(state): State<AppState>,
    ConnectInfo(remote_addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let request =
        match protocol_request(&state, remote_addr, &headers, &body, "applications.revoke").await {
            Ok(request) => request,
            Err(response) => return *response,
        };
    let Some(token) = request
        .form
        .get("token")
        .filter(|token| !token.is_empty())
        .cloned()
    else {
        return protocol_error(StatusCode::BAD_REQUEST, "invalid_request");
    };
    let Some(hasher) = request.snapshot.runtime.broker_token_hasher().cloned() else {
        return protocol_error(StatusCode::SERVICE_UNAVAILABLE, "temporarily_unavailable");
    };
    let owner = tokio::spawn(
        async move {
            let application_id = request.application.id().to_string();
            let store_application = application_id.clone();
            let outcome = request
                .snapshot
                .managed_store_call(move |store| {
                    store.revoke_application_token(&hasher, &store_application, &token)
                })
                .await;
            let (principal, details) = match outcome {
                Ok(ApplicationRevocation::Unknown) => (None, None),
                Ok(ApplicationRevocation::AccessToken {
                    principal_id,
                    access_id,
                    token_id,
                }) => (
                    Some(principal_id),
                    Some(json!({
                        "applicationId": application_id,
                        "revoked": "access_token",
                        "accessId": access_id,
                        "tokenId": token_id,
                    })),
                ),
                Ok(ApplicationRevocation::Access {
                    access,
                    revoked_tokens,
                }) => (
                    Some(access.principal_id),
                    Some(json!({
                        "applicationId": application_id,
                        "revoked": "refresh_token",
                        "accessId": access.access_id,
                        "revokedTokens": revoked_tokens,
                    })),
                ),
                Err(error) => return store_failure(&error),
            };
            // The revocation is committed; a missing audit record is logged.
            if let Some(details) = details
                && append_audit(
                    &request.snapshot,
                    AuditEvent {
                        request_id: &request.request_id,
                        broker_request_id: &request.broker_request_id,
                        source: &request.source,
                        action: APPLICATIONS_TOKEN_REVOKED,
                        principal: principal.as_deref(),
                        decision: Decision::Allow,
                        reason_code: None,
                        details,
                    },
                )
                .await
                .is_err()
            {
                tracing::error!(
                    event = "application_revocation_audit_append_failed",
                    agentRequestId = request.request_id.as_str(),
                    brokerRequestId = request.broker_request_id.as_str(),
                    applicationId = application_id.as_str(),
                    reasonCode = ReasonCode::AuditUnavailable.as_str(),
                    "an application revocation was committed but its audit record is unavailable"
                );
            }
            observability::record_decision(Decision::Allow.as_str());
            protocol_json(StatusCode::OK, json!({}))
        }
        .in_current_span()
        .with_current_subscriber(),
    );
    owner
        .await
        .unwrap_or_else(|_| protocol_error(StatusCode::INTERNAL_SERVER_ERROR, "server_error"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn basic(value: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(
            AUTHORIZATION,
            HeaderValue::from_str(&format!(
                "Basic {}",
                base64::engine::general_purpose::STANDARD.encode(value)
            ))
            .unwrap(),
        );
        headers
    }

    #[test]
    fn basic_credentials_are_form_urlencoded_and_strict() {
        assert_eq!(
            basic_credentials(&basic("example-runner:secret%2Bvalue%3A1+2")),
            Some(("example-runner".into(), "secret+value:1 2".into()))
        );
        for refused in ["example-runner", "a=b:secret", "example-runner:a&b"] {
            assert_eq!(basic_credentials(&basic(refused)), None, "{refused}");
        }
        let mut bearer = HeaderMap::new();
        bearer.insert(AUTHORIZATION, HeaderValue::from_static("Bearer token"));
        assert_eq!(basic_credentials(&bearer), None);
        assert_eq!(basic_credentials(&HeaderMap::new()), None);
    }

    #[test]
    fn redirects_append_to_an_existing_query_and_encode_values() {
        assert_eq!(
            application_redirect(
                "https://runner.example.test/callback?tenant=a",
                &[("error", "access_denied"), ("state", "a b&c")]
            )
            .as_deref(),
            Some("https://runner.example.test/callback?tenant=a&error=access_denied&state=a+b%26c")
        );
        assert!(parameters(b"a=1&a=2", 64).is_none());
        assert!(parameters(b"a=1&b=2", 4).is_none());
        assert!(valid_state("opaque-state") && !valid_state("") && !valid_state("line\nbreak"));
    }
}
