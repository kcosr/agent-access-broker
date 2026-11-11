//! The OAuth 2.0 authorization server registered applications use: metadata
//! (RFC 8414), the authorization endpoint, the token endpoint and revocation
//! (RFC 7009). The token and revocation endpoints answer RFC 6749 JSON, never
//! a Broker envelope. Client secrets, codes, verifiers and refresh tokens
//! never reach logs, audit records or error text.
use crate::handlers::auth::auth_request_ids;
use crate::handlers::management::audit_actions::{
    APPLICATIONS_AUTHORIZE_REFUSED, APPLICATIONS_TOKEN_ISSUED, APPLICATIONS_TOKEN_REFUSED,
    APPLICATIONS_TOKEN_REVOKED,
};
use crate::ingress::guards::IngressPermit;
use crate::ingress::source::auth_source_key;
use crate::observability;
use crate::state::{AppState, RuntimeSnapshot};
use agent_access_core::{
    ApplicationAuthorizationParameters, ApplicationGrant, ApplicationGrantRefusal,
    ApplicationGrantRefused, ApplicationRegistration, ApplicationRevocation, ApplicationTokenMint,
    AuditRecord, ManagedStore, ManagedStoreError, RegisteredApplication, SourceContext,
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

/// A refused authorization request: the fixed reason and, when the request
/// named a registration, its application.
struct AuthorizationRefusal {
    application_id: Option<String>,
    reason: &'static str,
}

pub(crate) async fn authorize(
    State(state): State<AppState>,
    ConnectInfo(remote_addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    RawQuery(raw_query): RawQuery,
) -> Response {
    let operation = "applications.authorize";
    let (request_id, broker_request_id) = match auth_request_ids(&headers, operation) {
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
    let (response, refusal) =
        authorization_response(&snapshot, &request_id, raw_query.as_deref()).await;
    // Like a failed sign-in start, a refused authorization request is audited.
    if let Some(refusal) = refusal {
        observability::record_decision(Decision::Deny.as_str());
        let _ = append_audit(
            &snapshot,
            AuditEvent {
                request_id: &request_id,
                broker_request_id: &broker_request_id,
                source: &source,
                action: APPLICATIONS_AUTHORIZE_REFUSED,
                principal: None,
                decision: Decision::Deny,
                reason_code: None,
                details: json!({
                    "applicationId": refusal.application_id,
                    "endpoint": operation,
                    "reason": refusal.reason,
                }),
            },
        )
        .await;
    }
    response
}

async fn authorization_response(
    snapshot: &RuntimeSnapshot,
    request_id: &str,
    raw_query: Option<&str>,
) -> (Response, Option<AuthorizationRefusal>) {
    let page = |application: Option<&RegisteredApplication>, reason: &'static str| {
        (
            authorization_error_page(StatusCode::BAD_REQUEST, request_id),
            Some(AuthorizationRefusal {
                application_id: application.map(|application| application.id().to_string()),
                reason,
            }),
        )
    };
    let Some(query) = parameters(raw_query.unwrap_or("").as_bytes(), QUERY_LIMIT_BYTES) else {
        return page(None, "query_invalid");
    };
    let Some(application) = query
        .get("client_id")
        .and_then(|client_id| snapshot.runtime.applications().get(client_id))
    else {
        return page(None, "client_unknown");
    };
    let Some(redirect_uri) = query
        .get("redirect_uri")
        .filter(|redirect_uri| application.accepts_redirect_uri(redirect_uri))
    else {
        return page(Some(application), "redirect_uri_unregistered");
    };
    // Every later outcome returns to the registered redirect URI.
    let state_parameter = query.get("state").filter(|value| valid_state(value));
    let back = |error: &'static str, reason: &'static str| {
        let mut response = vec![("error", error)];
        if let Some(state_parameter) = state_parameter {
            response.push(("state", state_parameter.as_str()));
        }
        let response = match application_redirect(redirect_uri, &response) {
            Some(location) => see_other(&location),
            None => authorization_error_page(StatusCode::BAD_REQUEST, request_id),
        };
        (
            response,
            Some(AuthorizationRefusal {
                application_id: Some(application.id().to_string()),
                reason,
            }),
        )
    };
    if query.contains_key("scope") {
        return back("invalid_scope", "scope_not_supported");
    }
    let (Some(state_parameter), Some(code_challenge)) = (
        state_parameter,
        query
            .get("code_challenge")
            .filter(|challenge| is_valid_application_code_challenge(challenge)),
    ) else {
        return back("invalid_request", "parameters_invalid");
    };
    if query.get("response_type").map(String::as_str) != Some("code")
        || query.get("code_challenge_method").map(String::as_str) != Some("S256")
    {
        return back("invalid_request", "parameters_invalid");
    }
    let Some(hasher) = snapshot.runtime.broker_token_hasher().cloned() else {
        return back("server_error", "server_unavailable");
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
            (see_other(&format!("{CONSENT_PATH}/{pending_id}")), None)
        }
        Err(_) => back("server_error", "server_unavailable"),
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

/// A token or revocation request from an authenticated application.
pub(crate) struct ProtocolRequest {
    snapshot: Arc<RuntimeSnapshot>,
    request_id: String,
    broker_request_id: String,
    source: SourceContext,
    endpoint: &'static str,
    application: RegisteredApplication,
    /// `None` when the body is not the form the endpoint accepts.
    form: Option<BTreeMap<String, String>>,
    /// The request's admitted capacity. A mutation owner keeps the request,
    /// and so this permit, until its store work and audit have completed,
    /// whether or not the response waiter is still there.
    _permit: IngressPermit,
    /// The request's place in the shutdown drain, held like the permit: the
    /// owner's audit is written before the audit writers close.
    _lease: crate::owner_drain::OwnerLease,
}

impl ProtocolRequest {
    /// Refuses the request with a fixed, value-free reason, audited with
    /// the application's ID.
    async fn refuse(
        &self,
        status: StatusCode,
        error: &'static str,
        reason: &'static str,
        grant_type: Option<&'static str>,
    ) -> Response {
        let decision = if status.is_server_error() {
            Decision::Error
        } else {
            Decision::Deny
        };
        let _ = append_audit(
            &self.snapshot,
            AuditEvent {
                request_id: &self.request_id,
                broker_request_id: &self.broker_request_id,
                source: &self.source,
                action: APPLICATIONS_TOKEN_REFUSED,
                principal: None,
                decision,
                reason_code: None,
                details: json!({
                    "applicationId": self.application.id(),
                    "endpoint": self.endpoint,
                    "grantType": grant_type,
                    "reason": reason,
                }),
            },
        )
        .await;
        protocol_error(status, error)
    }

    fn field(&self, name: &str) -> Option<String> {
        self.form
            .as_ref()?
            .get(name)
            .filter(|value| !value.is_empty())
            .cloned()
    }
}

/// Admits the request and authenticates its client, or answers the refusal.
/// Failed client authentication is audited, like a failed sign-in, with the
/// claimed ID only when it names a registration. Every refusal after this
/// point goes through [`ProtocolRequest::refuse`].
pub(crate) async fn protocol_request(
    state: &AppState,
    remote_addr: SocketAddr,
    headers: &HeaderMap,
    body: &Bytes,
    endpoint: &'static str,
) -> Result<ProtocolRequest, Box<Response>> {
    let (request_id, broker_request_id) = match auth_request_ids(headers, endpoint) {
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
    // The transport's own permit when it admitted this request.
    let Ok(permit) = state
        .reloadable
        .shared_ingress
        .try_global_concurrency(snapshot.runtime.limits().max_concurrent_requests)
    else {
        return Err(Box::new(protocol_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "temporarily_unavailable",
        )));
    };
    let credentials = basic_credentials(headers);
    let application = credentials.as_ref().and_then(|(client_id, client_secret)| {
        snapshot
            .runtime
            .applications()
            .authenticate(client_id, client_secret)
            .cloned()
    });
    let Some(application) = application else {
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
                    "endpoint": endpoint,
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
    Ok(ProtocolRequest {
        snapshot,
        request_id,
        broker_request_id,
        source,
        endpoint,
        application,
        form,
        _permit: permit,
        _lease: state.reloadable.application_owners.register(),
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
fn store_failure(error: &ManagedStoreError) -> (StatusCode, &'static str) {
    match error {
        ManagedStoreError::Unavailable(_)
        | ManagedStoreError::VersionConflict
        | ManagedStoreError::ReloadInProgress => {
            (StatusCode::SERVICE_UNAVAILABLE, "temporarily_unavailable")
        }
        _ => (StatusCode::INTERNAL_SERVER_ERROR, "server_error"),
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
    enum Presented {
        Code(String, String, String),
        Refresh(String),
    }
    let Some(form) = &request.form else {
        return request
            .refuse(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "request_malformed",
                None,
            )
            .await;
    };
    let presented = match form.get("grant_type").map(String::as_str) {
        Some("authorization_code") => {
            match (
                request.field("code"),
                request.field("redirect_uri"),
                request.field("code_verifier"),
            ) {
                (Some(code), Some(redirect_uri), Some(verifier)) => {
                    Presented::Code(code, redirect_uri, verifier)
                }
                _ => {
                    return request
                        .refuse(
                            StatusCode::BAD_REQUEST,
                            "invalid_request",
                            "grant_parameters_missing",
                            Some("authorization_code"),
                        )
                        .await;
                }
            }
        }
        Some("refresh_token") => match request.field("refresh_token") {
            Some(refresh_token) => Presented::Refresh(refresh_token),
            None => {
                return request
                    .refuse(
                        StatusCode::BAD_REQUEST,
                        "invalid_request",
                        "grant_parameters_missing",
                        Some("refresh_token"),
                    )
                    .await;
            }
        },
        Some(_) => {
            return request
                .refuse(
                    StatusCode::BAD_REQUEST,
                    "unsupported_grant_type",
                    "grant_type_unsupported",
                    None,
                )
                .await;
        }
        None => {
            return request
                .refuse(
                    StatusCode::BAD_REQUEST,
                    "invalid_request",
                    "grant_type_missing",
                    None,
                )
                .await;
        }
    };
    let grant_type = match &presented {
        Presented::Code(..) => "authorization_code",
        Presented::Refresh(_) => "refresh_token",
    };
    let Some(hasher) = request.snapshot.runtime.broker_token_hasher().cloned() else {
        return request
            .refuse(
                StatusCode::SERVICE_UNAVAILABLE,
                "temporarily_unavailable",
                "server_unavailable",
                Some(grant_type),
            )
            .await;
    };
    let application_id = request.application.id().to_string();
    committed_application_mint(state, request, grant_type, move |store, registration| {
        let grant = match &presented {
            Presented::Code(code, redirect_uri, code_verifier) => {
                ApplicationGrant::AuthorizationCode {
                    code,
                    redirect_uri,
                    code_verifier,
                }
            }
            Presented::Refresh(refresh_token) => ApplicationGrant::RefreshToken { refresh_token },
        };
        store.mint_application_token(&hasher, &application_id, registration, grant)
    })
    .await
}

/// Owns a mint from its insertion to its completion audit, with the
/// request's admitted capacity, independently of the response waiter. The
/// reload fence keeps the registration `mint` receives the current one.
pub(crate) async fn committed_application_mint<F>(
    state: AppState,
    request: ProtocolRequest,
    grant_type: &'static str,
    mint: F,
) -> Response
where
    F: FnOnce(
            &ManagedStore,
            Option<&ApplicationRegistration>,
        )
            -> Result<Result<ApplicationTokenMint, ApplicationGrantRefused>, ManagedStoreError>
        + Send
        + 'static,
{
    let owner = tokio::spawn(
        async move {
            let application_id = request.application.id().to_string();
            let store_application = application_id.clone();
            let outcome = state
                .reloadable
                .token_store_call_from_snapshot(request.snapshot.clone(), move |runtime| {
                    let store = runtime.managed_store().ok_or_else(|| {
                        ManagedStoreError::Unavailable("managed store is unavailable".into())
                    })?;
                    let registration = runtime.applications().registration(&store_application);
                    mint(store, registration.as_ref())
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
                        "replacedTokens": minted.replaced_tokens,
                    });
                    if append_audit(
                        &request.snapshot,
                        AuditEvent {
                            request_id: &request.request_id,
                            broker_request_id: &request.broker_request_id,
                            source: &request.source,
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
                            agentRequestId = request.request_id.as_str(),
                            brokerRequestId = request.broker_request_id.as_str(),
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
                        &request.snapshot,
                        AuditEvent {
                            request_id: &request.request_id,
                            broker_request_id: &request.broker_request_id,
                            source: &request.source,
                            action: APPLICATIONS_TOKEN_REFUSED,
                            principal: refused.principal_id.as_deref(),
                            decision: Decision::Deny,
                            reason_code: None,
                            details: json!({
                                "applicationId": application_id,
                                "endpoint": request.endpoint,
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
                        agentRequestId = request.request_id.as_str(),
                        brokerRequestId = request.broker_request_id.as_str(),
                        applicationId = application_id.as_str(),
                        reasonCode = error.reason_code().as_str(),
                        "application token request failed"
                    );
                    let (status, code) = store_failure(&error);
                    request
                        .refuse(status, code, "store_unavailable", Some(grant_type))
                        .await
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
    let Some(token) = request.field("token") else {
        let reason = if request.form.is_some() {
            "token_missing"
        } else {
            "request_malformed"
        };
        return request
            .refuse(StatusCode::BAD_REQUEST, "invalid_request", reason, None)
            .await;
    };
    let Some(hasher) = request.snapshot.runtime.broker_token_hasher().cloned() else {
        return request
            .refuse(
                StatusCode::SERVICE_UNAVAILABLE,
                "temporarily_unavailable",
                "server_unavailable",
                None,
            )
            .await;
    };
    let application_id = request.application.id().to_string();
    committed_application_revocation(request, move |store| {
        store.revoke_application_token(&hasher, &application_id, &token)
    })
    .await
}

/// Owns a revocation from its commit to its audit, with the request's
/// admitted capacity, independently of the response waiter.
pub(crate) async fn committed_application_revocation<F>(
    request: ProtocolRequest,
    revoke: F,
) -> Response
where
    F: FnOnce(ManagedStore) -> Result<ApplicationRevocation, ManagedStoreError> + Send + 'static,
{
    let owner = tokio::spawn(
        async move {
            let application_id = request.application.id().to_string();
            let outcome = request.snapshot.managed_store_call(revoke).await;
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
                    row_removed,
                }) => (
                    Some(access.principal_id),
                    Some(json!({
                        "applicationId": application_id,
                        "revoked": "refresh_token",
                        "accessId": access.access_id,
                        "revokedTokens": revoked_tokens,
                        "accessRemoved": row_removed,
                    })),
                ),
                Err(error) => {
                    let (status, code) = store_failure(&error);
                    return request
                        .refuse(status, code, "store_unavailable", None)
                        .await;
                }
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
