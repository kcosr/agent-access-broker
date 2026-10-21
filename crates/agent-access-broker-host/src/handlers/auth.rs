use crate::handlers::common::PendingIdentity;
use crate::handlers::management::audit_actions::{
    AUTH_LOCAL_LOGIN, AUTH_LOCAL_PASSWORD_CHANGE, AUTH_LOGOUT, AUTH_SESSION,
};
use crate::handlers::management::common::{effective_management_authority, is_unaudited_read};
use crate::ingress::guards::{IngressLimitError, IngressPermit, source_log_address};
use crate::ingress::source::auth_source_key;
use crate::observability;
use crate::state::{AppState, RuntimeSnapshot};
use agent_access_core::{
    AuditRecord, BrokerConfig, BrokerTokenClass, DEFAULT_MAX_SELF_ISSUED_AGENT_INVOKE_TTL,
    ErrorBody, IdentityContext, IdentityFailure, IdentitySourceAudit, LocalPasswordChangeRequest,
    LocalPasswordVerifyRequest, ManagedStoreError, PolicyReadScope, PrincipalRole, RuntimeError,
    SignInMethods, SourceContext, broker_token_ttl_option_for_ttl, new_broker_request_id,
    parse_ttl_seconds,
};
use agent_access_provider::{Decision, REQUEST_ID_HEADER, ReasonCode, ResourceScopes};
use axum::Json;
use axum::extract::{ConnectInfo, State};
use axum::http::header::{CACHE_CONTROL, COOKIE, HOST, ORIGIN, REFERER, SET_COOKIE};
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use chrono::Utc;
use percent_encoding::percent_decode_str;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::net::SocketAddr;
use std::sync::Arc;
use url::Url;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct LocalLoginBody {
    principal_id: String,
    password: String,
    return_to: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct PasswordChangeBody {
    current_password: String,
    new_password: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct AuthEnvelope {
    ok: bool,
    decision: Decision,
    #[serde(skip_serializing_if = "Option::is_none")]
    reason_code: Option<ReasonCode>,
    request_id: String,
    broker_request_id: String,
    operation: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    principal: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<ErrorBody>,
}

#[derive(Debug, Clone)]
pub(crate) struct BrowserCookieIdentity {
    pub(crate) sign_in_methods: SignInMethods,
    pub(crate) identity: IdentityContext,
    /// Read with the session's membership: whether membership renewal
    /// applies.
    pub(crate) membership_renewal: Option<agent_access_core::MembershipRenewalHint>,
    pub(crate) display_name: Option<String>,
    pub(crate) email: Option<String>,
    pub(crate) token_id: String,
    pub(crate) login_method: String,
    pub(crate) expires_at: Option<String>,
    pub(crate) password_change_required: bool,
}

enum BrowserCookieResolutionError {
    Identity(IdentityFailure),
    Store(ReasonCode),
}

#[derive(Clone, Copy)]
struct AuthResponseContext<'a> {
    snapshot: &'a RuntimeSnapshot,
    request_id: &'a str,
    broker_request_id: &'a str,
    operation: &'a str,
    source: &'a SourceContext,
}

struct BrowserSessionResultFields<'a> {
    sign_in_methods: &'a SignInMethods,
    identity: &'a IdentityContext,
    display_name: Option<&'a str>,
    email: Option<&'a str>,
    token_id: &'a str,
    login_method: &'a str,
    expires_at: Option<&'a str>,
    password_change_required: bool,
    role: PrincipalRole,
    self_service_enabled: bool,
    policy_management_services: &'a [String],
    return_to: Option<String>,
}

pub(crate) async fn auth_session(
    State(state): State<AppState>,
    ConnectInfo(remote_addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let operation = AUTH_SESSION;
    let (request_id, broker_request_id) = match auth_request_ids(&headers, operation) {
        Ok(ids) => ids,
        Err(response) => return *response,
    };
    let snapshot = state.reloadable.current();
    let source = snapshot
        .source_resolver
        .source_context(remote_addr, &headers);
    let response_context = AuthResponseContext {
        snapshot: &snapshot,
        request_id: &request_id,
        broker_request_id: &broker_request_id,
        operation,
        source: &source,
    };
    let _source_permit = match acquire_auth_global_guard(&state, response_context).await {
        Ok(permit) => permit,
        Err(response) => return *response,
    };
    if !snapshot.runtime.config().browser_auth.enabled {
        if let Err(response) = check_auth_source_guard(&state, response_context).await {
            return *response;
        }
        return auth_error_response(
            response_context,
            None,
            StatusCode::NOT_FOUND,
            ReasonCode::ManagementDenied,
            "browser authentication is disabled",
        )
        .await;
    }
    match resolve_browser_cookie_identity_blocking(&state, snapshot.clone(), headers.clone()).await
    {
        Ok(Some(cookie_identity)) => {
            let result = session_result(&snapshot, &cookie_identity).await;
            auth_success_response(
                response_context,
                Some(cookie_identity.identity.principal.clone()),
                &cookie_identity.identity,
                result,
            )
            .await
        }
        Ok(None) => {
            // A browser opening the login page normally has no session cookie.
            // Keep admission limits, but do not turn that ordinary read into
            // audit traffic or make it depend on audit-writer availability.
            if let Err(response) = check_auth_source_guard(&state, response_context).await {
                return *response;
            }
            auth_response(
                StatusCode::OK,
                auth_success_envelope(
                    &request_id,
                    &broker_request_id,
                    operation,
                    None,
                    unauthenticated_result(&snapshot),
                ),
            )
        }
        Err(_) => {
            if let Err(response) = check_auth_source_guard(&state, response_context).await {
                return *response;
            }
            let envelope = auth_success_envelope(
                &request_id,
                &broker_request_id,
                operation,
                None,
                unauthenticated_result(&snapshot),
            );
            let identity = IdentityContext::anonymous();
            let mut response =
                auth_audited_response(&snapshot, StatusCode::OK, envelope, &identity, &source)
                    .await;
            clear_session_cookie(&snapshot, response.headers_mut());
            response
        }
    }
}

pub(crate) async fn auth_local_login(
    State(state): State<AppState>,
    ConnectInfo(remote_addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(body): Json<LocalLoginBody>,
) -> impl IntoResponse {
    let operation = AUTH_LOCAL_LOGIN;
    let (request_id, broker_request_id) = match auth_request_ids(&headers, operation) {
        Ok(ids) => ids,
        Err(response) => return *response,
    };
    let snapshot = state.reloadable.current();
    let source = snapshot
        .source_resolver
        .source_context(remote_addr, &headers);
    let response_context = AuthResponseContext {
        snapshot: &snapshot,
        request_id: &request_id,
        broker_request_id: &broker_request_id,
        operation,
        source: &source,
    };
    let _source_permit = match acquire_auth_source_guard(&state, response_context).await {
        Ok(permit) => permit,
        Err(response) => return *response,
    };
    let _principal_permit = if principal_rate_key_is_safe(&body.principal_id) {
        match acquire_auth_principal_guard(&state, response_context, &body.principal_id, false)
            .await
        {
            Ok(permit) => Some(permit),
            Err(response) => return *response,
        }
    } else {
        None
    };
    if let Err((status, reason_code, message)) = auth_preflight(&snapshot, &headers) {
        return local_login_failure_response(
            response_context,
            body.principal_id,
            status,
            reason_code,
            message,
        )
        .await;
    }
    let Some(store) = snapshot.runtime.managed_store().cloned() else {
        return local_login_failure_response(
            response_context,
            body.principal_id,
            StatusCode::SERVICE_UNAVAILABLE,
            ReasonCode::ManagedStoreUnavailable,
            "managed store is unavailable",
        )
        .await;
    };
    let Some(password_hasher) = snapshot.runtime.local_password_hasher().cloned() else {
        return local_login_failure_response(
            response_context,
            body.principal_id,
            StatusCode::SERVICE_UNAVAILABLE,
            ReasonCode::EncryptionKeyMissing,
            "local password hasher is unavailable",
        )
        .await;
    };
    let Some(token_hasher) = snapshot.runtime.broker_token_hasher().cloned() else {
        return local_login_failure_response(
            response_context,
            body.principal_id,
            StatusCode::SERVICE_UNAVAILABLE,
            ReasonCode::EncryptionKeyMissing,
            "broker token hash key is unavailable",
        )
        .await;
    };
    let lockout_ttl_seconds = parse_ttl_seconds(
        &snapshot
            .runtime
            .config()
            .browser_auth
            .local_password
            .lockout_ttl,
    )
    .unwrap_or(15 * 60);
    let max_failed_attempts = snapshot
        .runtime
        .config()
        .browser_auth
        .local_password
        .max_failed_attempts;
    let principal_id = body.principal_id.clone();
    let password = body.password;
    let login_source = auth_source_key(&source);
    let session_ttl_seconds =
        parse_ttl_seconds(&snapshot.runtime.config().browser_auth.session_ttl).unwrap_or(8 * 3600);
    let work = match store.try_admit_local_password_request() {
        Ok(work) => work,
        Err(_) => {
            return local_login_failure_response(
                response_context,
                body.principal_id,
                StatusCode::TOO_MANY_REQUESTS,
                ReasonCode::ConcurrencyLimited,
                "local password capacity is exhausted",
            )
            .await;
        }
    };
    let authenticated = match run_store_blocking(move || {
        let _work = work;
        store.authenticate_local_password_session(
            &password_hasher,
            &token_hasher,
            LocalPasswordVerifyRequest {
                principal_id,
                password,
                source: login_source,
                max_failed_attempts,
                lockout_ttl_seconds,
            },
            session_ttl_seconds,
        )
    })
    .await
    {
        Ok(authenticated) => authenticated,
        Err(error) => {
            let (reason_code, message) = match error {
                ManagedStoreError::LocalLoginLocked => {
                    (ReasonCode::LocalLoginLocked, "login failed")
                }
                ManagedStoreError::LocalLoginFailed | ManagedStoreError::InputInvalid(_) => {
                    (ReasonCode::LocalLoginFailed, "login failed")
                }
                _ => (error.reason_code(), "login is unavailable"),
            };
            return local_login_failure_response(
                response_context,
                body.principal_id,
                StatusCode::from_u16(reason_code.http_status())
                    .unwrap_or(StatusCode::SERVICE_UNAVAILABLE),
                reason_code,
                message,
            )
            .await;
        }
    };
    let verified = authenticated.verified;
    let issued = authenticated.session;
    let identity = cookie_identity_from_session(
        &snapshot.runtime,
        verified.principal_id.clone(),
        verified.groups,
        verified.policy_groups,
        issued.record.token_id.clone(),
        issued.record.scopes.clone(),
    );
    let return_to = sanitize_return_to(snapshot.runtime.config(), body.return_to.as_deref());
    let (role, self_service_enabled, policy_management_services) =
        session_management_access(&snapshot, &identity).await;
    let result = browser_session_result(
        &snapshot,
        BrowserSessionResultFields {
            sign_in_methods: &verified.sign_in_methods,
            identity: &identity,
            display_name: verified.display_name.as_deref(),
            email: verified.email.as_deref(),
            token_id: &issued.record.token_id,
            login_method: &issued.session.login_method,
            expires_at: issued.record.expires_at.as_deref(),
            password_change_required: issued.session.password_change_required,
            role,
            self_service_enabled,
            policy_management_services: &policy_management_services,
            return_to: Some(return_to),
        },
    );
    let mut response = auth_success_response(
        response_context,
        Some(identity.principal.clone()),
        &identity,
        result,
    )
    .await;
    attach_session_cookie_or_revoke(
        &snapshot,
        &issued.record.token_id,
        &issued.token,
        session_ttl_seconds,
        &identity.principal,
        &mut response,
    )
    .await;
    response
}

pub(crate) async fn auth_password_change(
    State(state): State<AppState>,
    ConnectInfo(remote_addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(body): Json<PasswordChangeBody>,
) -> impl IntoResponse {
    let operation = AUTH_LOCAL_PASSWORD_CHANGE;
    let (request_id, broker_request_id) = match auth_request_ids(&headers, operation) {
        Ok(ids) => ids,
        Err(response) => return *response,
    };
    let snapshot = state.reloadable.current();
    let source = snapshot
        .source_resolver
        .source_context(remote_addr, &headers);
    let response_context = AuthResponseContext {
        snapshot: &snapshot,
        request_id: &request_id,
        broker_request_id: &broker_request_id,
        operation,
        source: &source,
    };
    let _source_permit = match acquire_auth_source_guard(&state, response_context).await {
        Ok(permit) => permit,
        Err(response) => return *response,
    };
    if let Err((status, reason_code, message)) = auth_preflight(&snapshot, &headers) {
        return auth_error_response(response_context, None, status, reason_code, message).await;
    }
    let session_failure = |failure: IdentityFailure| async move {
        let reason_code = failure.reason_code();
        auth_error_response(
            response_context,
            None,
            StatusCode::from_u16(reason_code.http_status()).unwrap_or(StatusCode::UNAUTHORIZED),
            reason_code,
            failure.message(),
        )
        .await
    };
    let pending =
        match resolve_browser_cookie_identity_pending(snapshot.clone(), headers.clone()).await {
            Ok(Some(pending)) => pending,
            Ok(None) => {
                return auth_error_response(
                    response_context,
                    None,
                    StatusCode::UNAUTHORIZED,
                    ReasonCode::IdentityRequired,
                    "browser session is required",
                )
                .await;
            }
            Err(failure) => return session_failure(failure).await,
        };
    // A membership renewal wait holds the principal's capacity.
    let _principal_permit = match acquire_auth_principal_guard(
        &state,
        response_context,
        &pending.value().identity.principal,
        true,
    )
    .await
    {
        Ok(permit) => permit,
        Err(response) => return *response,
    };
    let cookie_identity = match pending.admit(&state, &snapshot, &headers).await {
        Ok(cookie_identity) => cookie_identity,
        Err(failure) => return session_failure(failure).await,
    };
    if !csrf_header_valid(&snapshot, &headers, &cookie_identity.token_id) {
        return auth_error_response(
            response_context,
            Some(cookie_identity.identity.principal.clone()),
            StatusCode::FORBIDDEN,
            ReasonCode::CsrfInvalid,
            "CSRF token is invalid",
        )
        .await;
    }
    let Some(password_hasher) = snapshot.runtime.local_password_hasher().cloned() else {
        return auth_error_response(
            response_context,
            Some(cookie_identity.identity.principal.clone()),
            StatusCode::SERVICE_UNAVAILABLE,
            ReasonCode::EncryptionKeyMissing,
            "local password hasher is unavailable",
        )
        .await;
    };
    let Some(token_hasher) = snapshot.runtime.broker_token_hasher().cloned() else {
        return auth_error_response(
            response_context,
            Some(cookie_identity.identity.principal.clone()),
            StatusCode::SERVICE_UNAVAILABLE,
            ReasonCode::EncryptionKeyMissing,
            "broker token hash key is unavailable",
        )
        .await;
    };
    let lockout_ttl_seconds = parse_ttl_seconds(
        &snapshot
            .runtime
            .config()
            .browser_auth
            .local_password
            .lockout_ttl,
    )
    .unwrap_or(15 * 60);
    let max_failed_attempts = snapshot
        .runtime
        .config()
        .browser_auth
        .local_password
        .max_failed_attempts;
    let min_password_length = snapshot
        .runtime
        .config()
        .browser_auth
        .local_password
        .min_password_length;
    let principal_id = cookie_identity.identity.principal.clone();
    let current_password = body.current_password;
    let new_password = body.new_password;
    let store = snapshot.runtime.managed_store().unwrap().clone();
    let login_source = auth_source_key(&source);
    let session_ttl_seconds =
        parse_ttl_seconds(&snapshot.runtime.config().browser_auth.session_ttl).unwrap_or(8 * 3600);
    let replace_local_session = cookie_identity.login_method == "local_password";
    let principal_for_change = principal_id.clone();
    if let Err(response) =
        auth_write_audit_preflight(response_context, &cookie_identity.identity).await
    {
        return *response;
    }
    let work = match store.try_admit_local_password_request() {
        Ok(work) => work,
        Err(_) => {
            return auth_error_response(
                response_context,
                Some(principal_id),
                StatusCode::TOO_MANY_REQUESTS,
                ReasonCode::ConcurrencyLimited,
                "local password capacity is exhausted",
            )
            .await;
        }
    };
    let changed = match run_store_blocking(move || {
        let _work = work;
        store.change_local_password(
            &password_hasher,
            &token_hasher,
            LocalPasswordChangeRequest {
                verification: LocalPasswordVerifyRequest {
                    principal_id: principal_for_change,
                    password: current_password,
                    source: login_source,
                    max_failed_attempts,
                    lockout_ttl_seconds,
                },
                new_password,
                min_password_length,
                replace_local_session,
                session_ttl_seconds,
            },
        )
    })
    .await
    {
        Ok(changed) => changed,
        Err(error) => {
            let (reason, message) = match error {
                ManagedStoreError::LocalLoginFailed | ManagedStoreError::LocalLoginLocked => {
                    (ReasonCode::LocalLoginFailed, "login failed".to_string())
                }
                ManagedStoreError::InputInvalid(_) => (error.reason_code(), error.to_string()),
                _ => (
                    error.reason_code(),
                    "password change is unavailable".to_string(),
                ),
            };
            return auth_error_response(
                response_context,
                Some(principal_id),
                StatusCode::from_u16(reason.http_status()).unwrap_or(StatusCode::BAD_REQUEST),
                reason,
                &message,
            )
            .await;
        }
    };
    let Some(issued) = changed.replacement_session else {
        // Keep the OIDC cookie and session provenance. Local password writes only
        // revoke local sessions; do not silently exchange the Microsoft session.
        let result = session_result(&snapshot, &cookie_identity).await;
        return auth_committed_success_response(
            response_context,
            Some(principal_id),
            &cookie_identity.identity,
            result,
        )
        .await;
    };
    let verified = changed.verified;
    let identity = cookie_identity_from_session(
        &snapshot.runtime,
        verified.principal_id.clone(),
        verified.groups,
        verified.policy_groups,
        issued.record.token_id.clone(),
        issued.record.scopes.clone(),
    );
    let (role, self_service_enabled, policy_management_services) =
        session_management_access(&snapshot, &identity).await;
    let result = browser_session_result(
        &snapshot,
        BrowserSessionResultFields {
            sign_in_methods: &verified.sign_in_methods,
            identity: &identity,
            display_name: verified.display_name.as_deref(),
            email: verified.email.as_deref(),
            token_id: &issued.record.token_id,
            login_method: &issued.session.login_method,
            expires_at: issued.record.expires_at.as_deref(),
            password_change_required: issued.session.password_change_required,
            role,
            self_service_enabled,
            policy_management_services: &policy_management_services,
            return_to: None,
        },
    );
    let mut response = auth_committed_success_response(
        response_context,
        Some(identity.principal.clone()),
        &identity,
        result,
    )
    .await;
    attach_session_cookie_or_revoke(
        &snapshot,
        &issued.record.token_id,
        &issued.token,
        session_ttl_seconds,
        &identity.principal,
        &mut response,
    )
    .await;
    response
}

pub(crate) async fn auth_logout(
    State(state): State<AppState>,
    ConnectInfo(remote_addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let operation = AUTH_LOGOUT;
    let (request_id, broker_request_id) = match auth_request_ids(&headers, operation) {
        Ok(ids) => ids,
        Err(response) => return *response,
    };
    let snapshot = state.reloadable.current();
    let source = snapshot
        .source_resolver
        .source_context(remote_addr, &headers);
    let response_context = AuthResponseContext {
        snapshot: &snapshot,
        request_id: &request_id,
        broker_request_id: &broker_request_id,
        operation,
        source: &source,
    };
    let _source_permit = match acquire_auth_global_guard(&state, response_context).await {
        Ok(permit) => permit,
        Err(response) => return *response,
    };
    if !snapshot.runtime.config().browser_auth.enabled {
        if let Err(response) = check_auth_source_guard(&state, response_context).await {
            return *response;
        }
        return auth_error_response(
            response_context,
            None,
            StatusCode::NOT_FOUND,
            ReasonCode::ManagementDenied,
            "browser authentication is disabled",
        )
        .await;
    }
    let cookie_identity =
        match resolve_browser_cookie_identity_detailed_blocking(snapshot.clone(), headers.clone())
            .await
        {
            Ok(Some(cookie_identity)) => cookie_identity,
            Err(BrowserCookieResolutionError::Store(reason)) => {
                if let Err(response) = check_auth_source_guard(&state, response_context).await {
                    return *response;
                }
                return auth_error_response(
                    response_context,
                    None,
                    StatusCode::from_u16(reason.http_status())
                        .unwrap_or(StatusCode::SERVICE_UNAVAILABLE),
                    reason,
                    "browser session could not be revoked",
                )
                .await;
            }
            Ok(None) | Err(_) => {
                if let Err(response) = check_auth_source_guard(&state, response_context).await {
                    return *response;
                }
                let envelope = auth_success_envelope(
                    &request_id,
                    &broker_request_id,
                    operation,
                    None,
                    json!({"authenticated": false}),
                );
                let identity = IdentityContext::anonymous();
                let mut response =
                    auth_audited_response(&snapshot, StatusCode::OK, envelope, &identity, &source)
                        .await;
                clear_session_cookie(&snapshot, response.headers_mut());
                return response;
            }
        };
    if !csrf_header_valid(&snapshot, &headers, &cookie_identity.token_id) {
        return auth_error_response(
            response_context,
            Some(cookie_identity.identity.principal.clone()),
            StatusCode::FORBIDDEN,
            ReasonCode::CsrfInvalid,
            "CSRF token is invalid",
        )
        .await;
    }
    if let Err(response) =
        auth_write_audit_preflight(response_context, &cookie_identity.identity).await
    {
        return *response;
    }
    let store = snapshot.runtime.managed_store().unwrap().clone();
    let token_id = cookie_identity.token_id.clone();
    let actor = cookie_identity.identity.principal.clone();
    if let Err(error) =
        run_store_blocking(move || store.revoke_browser_session(&token_id, &actor)).await
    {
        return auth_error_response(
            response_context,
            Some(cookie_identity.identity.principal.clone()),
            StatusCode::from_u16(error.reason_code().http_status())
                .unwrap_or(StatusCode::SERVICE_UNAVAILABLE),
            error.reason_code(),
            "browser session could not be revoked",
        )
        .await;
    }
    let mut response = auth_committed_success_response(
        response_context,
        Some(cookie_identity.identity.principal.clone()),
        &cookie_identity.identity,
        json!({"authenticated": false}),
    )
    .await;
    clear_session_cookie(&snapshot, response.headers_mut());
    response
}

async fn acquire_auth_source_guard(
    state: &AppState,
    context: AuthResponseContext<'_>,
) -> Result<IngressPermit, Box<Response>> {
    let global_permit = acquire_auth_global_guard(state, context).await?;
    check_auth_source_guard(state, context).await?;
    Ok(global_permit)
}

async fn acquire_auth_global_guard(
    state: &AppState,
    context: AuthResponseContext<'_>,
) -> Result<IngressPermit, Box<Response>> {
    match state
        .reloadable
        .shared_ingress
        .try_global_concurrency(context.snapshot.runtime.limits().max_concurrent_requests)
    {
        Ok(permit) => Ok(permit),
        Err(error) => Err(Box::new(auth_limit_response(context, None, error).await)),
    }
}

async fn check_auth_source_guard(
    state: &AppState,
    context: AuthResponseContext<'_>,
) -> Result<(), Box<Response>> {
    let source_key = auth_source_key(context.source);
    if let Err(error) = state.reloadable.shared_ingress.check_auth_source_rate(
        &source_key,
        context
            .snapshot
            .runtime
            .limits()
            .auth_requests_per_source_per_minute,
    ) {
        return Err(Box::new(auth_limit_response(context, None, error).await));
    }
    Ok(())
}

/// Charges the local-password principal guards. The authentication principal
/// budget is keyed by `(principal, source)` so that another source cannot
/// spend it. Before authentication the principal is only claimed, so login
/// also keys its in-flight slot by `(principal, source)` rather than holding
/// the principal's own concurrency.
async fn acquire_auth_principal_guard(
    state: &AppState,
    context: AuthResponseContext<'_>,
    principal: &str,
    authenticated: bool,
) -> Result<IngressPermit, Box<Response>> {
    let limits = context.snapshot.runtime.limits();
    let principal_source = auth_principal_source_key(principal, &auth_source_key(context.source));
    let concurrency_key = if authenticated {
        principal
    } else {
        principal_source.as_str()
    };
    let principal_permit = match state.reloadable.shared_ingress.try_principal_concurrency(
        concurrency_key,
        limits.max_concurrent_requests_per_principal,
    ) {
        Ok(permit) => permit,
        Err(error) => {
            return Err(Box::new(
                auth_limit_response(context, Some(principal.to_string()), error).await,
            ));
        }
    };
    if let Err(error) = state.reloadable.shared_ingress.check_auth_principal_rate(
        &principal_source,
        limits.auth_requests_per_principal_per_minute,
    ) {
        return Err(Box::new(
            auth_limit_response(context, Some(principal.to_string()), error).await,
        ));
    }
    Ok(principal_permit)
}

async fn auth_limit_response(
    context: AuthResponseContext<'_>,
    principal: Option<String>,
    error: IngressLimitError,
) -> Response {
    let provider_error = error.provider_error();
    tracing::warn!(
        event = "auth_request_limited",
        agentRequestId = context.request_id,
        brokerRequestId = context.broker_request_id,
        operation = context.operation,
        limitKind = error.kind().as_str(),
        limit = error.limit(),
        source = source_log_address(context.source),
        principal = principal.as_deref().unwrap_or(""),
        decision = provider_error.decision().as_str(),
        reasonCode = provider_error.reason_code().as_str(),
        "http.statusCode" = provider_error.reason_code().http_status(),
    );
    auth_error_response(
        context,
        principal,
        StatusCode::from_u16(provider_error.reason_code().http_status())
            .unwrap_or(StatusCode::TOO_MANY_REQUESTS),
        error.reason_code(),
        &provider_error.message,
    )
    .await
}

/// Composite `(principal, source)` limiter key. Principals used here are
/// restricted to characters that cannot contain the separator.
fn auth_principal_source_key(principal: &str, login_source: &str) -> String {
    format!("{principal}|{login_source}")
}

fn principal_rate_key_is_safe(principal: &str) -> bool {
    !principal.is_empty()
        && principal.len() <= 256
        && principal
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '.' | '_' | '@' | '+' | '-'))
}

/// Resolves the request's browser session, then admits Microsoft membership
/// renewal for it, for a route without per-principal capacity. After a wait
/// the session is resolved again from the same cookie, so a session revoked
/// meanwhile fails.
pub(crate) async fn resolve_browser_cookie_identity_blocking(
    state: &AppState,
    snapshot: Arc<RuntimeSnapshot>,
    headers: HeaderMap,
) -> Result<Option<BrowserCookieIdentity>, IdentityFailure> {
    match resolve_browser_cookie_identity_pending(snapshot.clone(), headers.clone()).await? {
        Some(pending) => pending.admit(state, &snapshot, &headers).await.map(Some),
        None => Ok(None),
    }
}

/// Resolves the request's browser session for membership renewal
/// admission; after a wait it is resolved again from the same cookie.
pub(crate) async fn resolve_browser_cookie_identity_pending(
    snapshot: Arc<RuntimeSnapshot>,
    headers: HeaderMap,
) -> Result<Option<PendingIdentity<BrowserCookieIdentity, IdentityFailure>>, IdentityFailure> {
    let Some(cookie) =
        resolve_browser_cookie_identity_without_renewal(snapshot.clone(), headers.clone()).await?
    else {
        return Ok(None);
    };
    let hint = cookie.membership_renewal.clone();
    let recheck = async move {
        resolve_browser_cookie_identity_without_renewal(snapshot, headers)
            .await?
            .ok_or(IdentityFailure::Invalid)
    };
    Ok(Some(PendingIdentity::new(cookie, hint, recheck)))
}

/// Resolves the request's browser session without membership renewal, as
/// body admission does before its handler's admission.
pub(crate) async fn resolve_browser_cookie_identity_without_renewal(
    snapshot: Arc<RuntimeSnapshot>,
    headers: HeaderMap,
) -> Result<Option<BrowserCookieIdentity>, IdentityFailure> {
    resolve_browser_cookie_identity_detailed_blocking(snapshot, headers)
        .await
        .map_err(|error| match error {
            BrowserCookieResolutionError::Identity(error) => error,
            BrowserCookieResolutionError::Store(_) => IdentityFailure::Invalid,
        })
}

async fn resolve_browser_cookie_identity_detailed_blocking(
    snapshot: Arc<RuntimeSnapshot>,
    headers: HeaderMap,
) -> Result<Option<BrowserCookieIdentity>, BrowserCookieResolutionError> {
    tokio::task::spawn_blocking(move || resolve_browser_cookie_identity(&snapshot, &headers))
        .await
        .unwrap_or(Err(BrowserCookieResolutionError::Store(
            ReasonCode::ManagedStoreUnavailable,
        )))
}

pub(crate) fn csrf_header_valid(
    snapshot: &RuntimeSnapshot,
    headers: &HeaderMap,
    token_id: &str,
) -> bool {
    let Some(csrf_key) = snapshot.runtime.browser_csrf_key() else {
        return false;
    };
    let expected = match csrf_key.token_for_session(token_id) {
        Ok(token) => token,
        Err(_) => return false,
    };
    let Some(actual) = headers
        .get(snapshot.runtime.config().browser_auth.csrf_header.as_str())
        .and_then(|value| value.to_str().ok())
    else {
        return false;
    };
    actual == expected
}

fn resolve_browser_cookie_identity(
    snapshot: &RuntimeSnapshot,
    headers: &HeaderMap,
) -> Result<Option<BrowserCookieIdentity>, BrowserCookieResolutionError> {
    let ingress = snapshot
        .runtime
        .admit_ingress(headers)
        .map_err(BrowserCookieResolutionError::Identity)?;
    if !snapshot.runtime.config().browser_auth.enabled {
        return Ok(None);
    }
    let cookie_name = snapshot
        .runtime
        .config()
        .browser_auth
        .session_cookie_name
        .as_str();
    let Some(raw_token) = browser_session_cookie(headers, cookie_name)
        .map_err(BrowserCookieResolutionError::Identity)?
    else {
        return Ok(None);
    };
    let store = snapshot
        .runtime
        .managed_store()
        .ok_or(BrowserCookieResolutionError::Store(
            ReasonCode::ManagedStoreUnavailable,
        ))?;
    let hasher =
        snapshot
            .runtime
            .broker_token_hasher()
            .ok_or(BrowserCookieResolutionError::Store(
                ReasonCode::EncryptionKeyMissing,
            ))?;
    let session = store
        .resolve_browser_session(hasher, &raw_token)
        .map_err(|error| {
            let reason = error.reason_code();
            if reason.http_status() >= 500 {
                BrowserCookieResolutionError::Store(reason)
            } else {
                BrowserCookieResolutionError::Identity(identity_failure_from_store_error(error))
            }
        })?;
    let token_id = session.token_id.clone();
    let membership_renewal = session.membership_renewal.clone();
    let mut identity = cookie_identity_from_session(
        &snapshot.runtime,
        session.principal_id,
        session.groups,
        session.policy_groups,
        session.token_id,
        session.scopes,
    );
    identity.caller_id = ingress.caller_id().map(str::to_owned);
    Ok(Some(BrowserCookieIdentity {
        sign_in_methods: session.sign_in_methods,
        identity,
        membership_renewal,
        display_name: session.display_name,
        email: session.email,
        token_id,
        login_method: session.login_method,
        expires_at: session.expires_at,
        password_change_required: session.password_change_required,
    }))
}

fn identity_failure_from_store_error(error: ManagedStoreError) -> IdentityFailure {
    match error {
        ManagedStoreError::BrokerTokenNotFound => IdentityFailure::BrokerTokenNotFound,
        ManagedStoreError::BrokerTokenExpired => IdentityFailure::BrokerTokenExpired,
        ManagedStoreError::BrokerTokenRevoked => IdentityFailure::BrokerTokenRevoked,
        ManagedStoreError::PrincipalRequired | ManagedStoreError::PrincipalNotFound => {
            IdentityFailure::PrincipalRequired
        }
        ManagedStoreError::PrincipalDisabled => IdentityFailure::PrincipalDisabled,
        _ => IdentityFailure::Invalid,
    }
}

fn cookie_identity_from_session(
    runtime: &agent_access_core::BrokerRuntime,
    principal: String,
    groups: Vec<String>,
    policy_groups: Vec<String>,
    token_id: String,
    scopes: Value,
) -> IdentityContext {
    // The store resolves browser sessions only for user principals.
    runtime.identity_from_principal_groups(
        principal,
        Some(agent_access_core::PrincipalKind::User),
        None,
        groups,
        Some(policy_groups),
        Some(IdentitySourceAudit {
            read_only_access: None,
            namespace: None,
            binding_id: None,
            name: "browser-session".to_string(),
            kind: "broker_tokens".to_string(),
            token_header: "Cookie".to_string(),
            token_scheme: "cookie".to_string(),
            token_class: Some(BrokerTokenClass::UserManage),
            token_id: Some(token_id),
            token_scopes: Some(scopes),
        }),
    )
}

fn browser_session_result(
    snapshot: &RuntimeSnapshot,
    fields: BrowserSessionResultFields<'_>,
) -> Value {
    let csrf_token = snapshot
        .runtime
        .browser_csrf_key()
        .and_then(|key| key.token_for_session(fields.token_id).ok());
    let is_admin = fields.role == PrincipalRole::Admin;
    let mut result = json!({
        "authenticated": true,
        "principal": &fields.identity.principal,
        "displayName": fields.display_name,
        "email": fields.email,
        "groups": &fields.identity.groups,
        "role": fields.role,
        "selfServiceEnabled": fields.self_service_enabled,
        "policyManagementServices": fields.policy_management_services,
        "tokenClass": "user_manage",
        "loginMethod": fields.login_method,
        "signInMethods": fields.sign_in_methods,
        "loginOptions": login_options(snapshot),
        "expiresAt": fields.expires_at,
        "passwordChangeRequired": fields.password_change_required,
        "csrfHeader": &snapshot.runtime.config().browser_auth.csrf_header,
        "csrfToken": csrf_token,
        "tokenIssuancePolicy": token_issuance_policy(snapshot.runtime.config(), is_admin),
        "auditQueryable": crate::handlers::spec::route_feature_available(
            snapshot,
            agent_access_core::RouteFeature::AuditQuery,
        ),
    });
    if let Some(return_to) = fields.return_to {
        result["returnTo"] = json!(return_to);
    }
    result
}

fn token_issuance_policy(config: &BrokerConfig, is_admin: bool) -> Value {
    let Some(tokens) = config.broker_tokens.as_ref() else {
        return json!({});
    };
    let self_max_ttl = tokens
        .max_self_issued_agent_invoke_ttl
        .as_deref()
        .unwrap_or(DEFAULT_MAX_SELF_ISSUED_AGENT_INVOKE_TTL)
        .trim();
    let effective_self_default = tokens
        .default_agent_invoke_ttl
        .as_deref()
        .unwrap_or(self_max_ttl);
    let self_default_ttl = broker_token_ttl_option_for_ttl(
        &tokens.self_agent_invoke_ttl_options,
        effective_self_default,
    );
    let mut policy = json!({
        "selfAgentInvoke": {
            "defaultTtl": self_default_ttl,
            "maxTtl": self_max_ttl,
            "options": tokens.self_agent_invoke_ttl_options.iter().map(|option| option.as_str()).collect::<Vec<_>>(),
        }
    });
    if is_admin {
        policy["administered"] = json!({
            "agentInvoke": {
                "defaultTtl": tokens.default_agent_invoke_ttl.as_deref().and_then(|default| broker_token_ttl_option_for_ttl(&tokens.admin_agent_invoke_ttl_options, default)),
                "maxTtl": null,
                "options": tokens.admin_agent_invoke_ttl_options.iter().map(|option| option.as_str()).collect::<Vec<_>>(),
            },
            "userManage": {
                "defaultTtl": tokens.default_user_manage_ttl.as_deref().and_then(|default| broker_token_ttl_option_for_ttl(&tokens.user_manage_ttl_options, default)),
                "maxTtl": null,
                "options": tokens.user_manage_ttl_options.iter().map(|option| option.as_str()).collect::<Vec<_>>(),
            },
            "admin": {
                "defaultTtl": tokens.default_admin_ttl.as_deref().and_then(|default| broker_token_ttl_option_for_ttl(&tokens.admin_ttl_options, default)),
                "maxTtl": null,
                "options": tokens.admin_ttl_options.iter().map(|option| option.as_str()).collect::<Vec<_>>(),
            }
        });
    }
    policy
}

async fn session_result(
    snapshot: &RuntimeSnapshot,
    cookie_identity: &BrowserCookieIdentity,
) -> Value {
    let (role, self_service_enabled, policy_management_services) =
        session_management_access(snapshot, &cookie_identity.identity).await;
    browser_session_result(
        snapshot,
        BrowserSessionResultFields {
            sign_in_methods: &cookie_identity.sign_in_methods,
            identity: &cookie_identity.identity,
            display_name: cookie_identity.display_name.as_deref(),
            email: cookie_identity.email.as_deref(),
            token_id: &cookie_identity.token_id,
            login_method: &cookie_identity.login_method,
            expires_at: cookie_identity.expires_at.as_deref(),
            password_change_required: cookie_identity.password_change_required,
            role,
            self_service_enabled,
            policy_management_services: &policy_management_services,
            return_to: None,
        },
    )
}

async fn session_management_access(
    snapshot: &RuntimeSnapshot,
    identity: &IdentityContext,
) -> (PrincipalRole, bool, Vec<String>) {
    match effective_management_authority(snapshot, identity).await {
        Ok(authority) => (
            authority.principal.role,
            authority.principal.self_service_enabled,
            match authority.policy_read_scope {
                PolicyReadScope::Global => Vec::new(),
                PolicyReadScope::Services { services } => services.into_iter().collect(),
            },
        ),
        Err(_) => (PrincipalRole::User, false, Vec::new()),
    }
}

fn unauthenticated_result(snapshot: &RuntimeSnapshot) -> Value {
    json!({
        "authenticated": false,
        "loginOptions": login_options(snapshot),
    })
}

fn login_options(snapshot: &RuntimeSnapshot) -> Value {
    let local_enabled = snapshot.runtime.config().browser_auth.enabled
        && snapshot
            .runtime
            .config()
            .browser_auth
            .local_password
            .enabled;
    let microsoft_enabled = snapshot.runtime.microsoft_oidc().is_some();
    let microsoft_available = snapshot
        .microsoft_oidc
        .as_ref()
        .is_some_and(|provider| provider.available());
    json!({
        "localPassword": { "enabled": local_enabled },
        "microsoft": {
            "enabled": microsoft_enabled,
            "available": microsoft_available,
            "displayName": "Microsoft",
            "startPath": "/v1/auth/oidc/microsoft/start",
        },
    })
}

pub(crate) fn auth_request_ids(
    headers: &HeaderMap,
    operation: &str,
) -> Result<(String, String), Box<Response>> {
    observability::record_operation(operation);
    let broker_request_id = new_broker_request_id();
    observability::record_broker_request_id(&broker_request_id);
    let request_id = match headers
        .get(REQUEST_ID_HEADER)
        .and_then(|value| value.to_str().ok())
    {
        Some(value) if valid_request_id(value) => value.to_string(),
        Some(_) => {
            observability::record_decision(Decision::Deny.as_str());
            observability::record_reason_code(ReasonCode::RequestIdInvalid.as_str());
            observability::record_status(StatusCode::BAD_REQUEST.as_u16());
            let envelope = AuthEnvelope {
                ok: false,
                decision: Decision::Deny,
                reason_code: Some(ReasonCode::RequestIdInvalid),
                request_id: String::new(),
                broker_request_id,
                operation: operation.to_string(),
                principal: None,
                result: None,
                error: Some(ErrorBody {
                    message: "request id is invalid".to_string(),
                }),
            };
            return Err(Box::new(auth_response(StatusCode::BAD_REQUEST, envelope)));
        }
        None => format!("auth-{}", new_broker_request_id()),
    };
    observability::record_agent_request_id(&request_id);
    Ok((request_id, broker_request_id))
}

fn valid_request_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || ch == '.' || ch == '_' || ch == '-')
}

fn auth_preflight(
    snapshot: &RuntimeSnapshot,
    headers: &HeaderMap,
) -> Result<(), (StatusCode, ReasonCode, &'static str)> {
    if !snapshot.runtime.config().browser_auth.enabled {
        return Err((
            StatusCode::NOT_FOUND,
            ReasonCode::ManagementDenied,
            "browser authentication is disabled",
        ));
    }
    if !snapshot
        .runtime
        .config()
        .browser_auth
        .local_password
        .enabled
    {
        return Err((
            StatusCode::NOT_FOUND,
            ReasonCode::ManagementDenied,
            "local password login is disabled",
        ));
    }
    if headers
        .get("sec-fetch-site")
        .and_then(|value| value.to_str().ok())
        == Some("cross-site")
    {
        return Err((
            StatusCode::FORBIDDEN,
            ReasonCode::CsrfInvalid,
            "cross-site browser request is denied",
        ));
    }
    if !same_origin_request(snapshot, headers) {
        return Err((
            StatusCode::FORBIDDEN,
            ReasonCode::CsrfInvalid,
            "request origin is invalid",
        ));
    }
    Ok(())
}

fn same_origin_request(snapshot: &RuntimeSnapshot, headers: &HeaderMap) -> bool {
    let Some(expected_origin) = expected_origin(snapshot, headers) else {
        return false;
    };
    if let Some(origin) = headers.get(ORIGIN).and_then(|value| value.to_str().ok()) {
        return origin == expected_origin;
    }
    if let Some(referer) = headers.get(REFERER).and_then(|value| value.to_str().ok()) {
        return Url::parse(referer)
            .ok()
            .and_then(|url| url_origin(&url))
            .map(|origin| origin == expected_origin)
            .unwrap_or(false);
    }
    false
}

fn expected_origin(snapshot: &RuntimeSnapshot, headers: &HeaderMap) -> Option<String> {
    if let Some(origin) = snapshot
        .runtime
        .config()
        .browser_auth
        .public_origin
        .as_deref()
    {
        return Url::parse(origin).ok().and_then(|url| url_origin(&url));
    }
    headers
        .get(HOST)
        .and_then(|value| value.to_str().ok())
        .map(|host| format!("http://{host}"))
}

fn url_origin(url: &Url) -> Option<String> {
    let host = url.host_str()?;
    let port = url
        .port()
        .map(|port| format!(":{port}"))
        .unwrap_or_default();
    Some(format!("{}://{}{}", url.scheme(), host, port))
}

pub(crate) fn sanitize_return_to(
    config: &agent_access_core::BrokerConfig,
    return_to: Option<&str>,
) -> String {
    let fallback = config
        .browser_auth
        .allowed_return_paths
        .first()
        .cloned()
        .unwrap_or_else(|| "/ui".to_string());
    let Some(return_to) = return_to else {
        return fallback;
    };
    if clean_return_path(return_to)
        && config
            .browser_auth
            .allowed_return_paths
            .iter()
            .any(|path| return_to == path || return_to.starts_with(&format!("{path}/")))
    {
        return return_to.to_string();
    }
    fallback
}

fn clean_return_path(value: &str) -> bool {
    if value.is_empty()
        || !value.starts_with('/')
        || value.starts_with("//")
        || value.contains('?')
        || value.contains('#')
        || value.contains('\\')
        || value.chars().any(char::is_control)
    {
        return false;
    }
    let Ok(decoded) = percent_decode_str(value).decode_utf8() else {
        return false;
    };
    if decoded.as_ref() != value {
        return false;
    }
    !value
        .split('/')
        .skip(1)
        .any(|segment| segment.is_empty() || segment == "." || segment == "..")
}

/// Distinguish an absent session from a presented but unusable cookie. A
/// malformed session cookie, empty session value, or duplicate session cookie
/// must remain on the audited authentication-failure path. Unrelated cookies
/// cannot prevent a valid broker session from authenticating.
fn browser_session_cookie(
    headers: &HeaderMap,
    name: &str,
) -> Result<Option<String>, IdentityFailure> {
    let mut token = None;
    for header in headers.get_all(COOKIE) {
        for part in header.as_bytes().split(|byte| *byte == b';') {
            let part = part.trim_ascii();
            let Some(separator) = part.iter().position(|byte| *byte == b'=') else {
                if part == name.as_bytes() {
                    return Err(IdentityFailure::Invalid);
                }
                continue;
            };
            let cookie_name = &part[..separator];
            if cookie_name.trim_ascii() != name.as_bytes() {
                continue;
            }
            let value = &part[separator + 1..];
            if cookie_name != name.as_bytes() || value.is_empty() || token.is_some() {
                return Err(IdentityFailure::Invalid);
            }
            token = Some(
                std::str::from_utf8(value)
                    .map_err(|_| IdentityFailure::Invalid)?
                    .to_owned(),
            );
        }
    }
    Ok(token)
}

async fn attach_session_cookie_or_revoke(
    snapshot: &RuntimeSnapshot,
    token_id: &str,
    token: &str,
    ttl_seconds: u64,
    actor: &str,
    response: &mut Response,
) {
    if response.status() == StatusCode::OK {
        set_session_cookie(snapshot, token, ttl_seconds, response.headers_mut());
        return;
    }
    if let Some(store) = snapshot.runtime.managed_store().cloned() {
        let token_id = token_id.to_string();
        let actor = actor.to_string();
        let _ = run_store_blocking(move || store.revoke_browser_session(&token_id, &actor)).await;
    }
}

pub(crate) fn set_session_cookie(
    snapshot: &RuntimeSnapshot,
    token: &str,
    ttl_seconds: u64,
    headers: &mut HeaderMap,
) {
    let cookie = format!(
        "{}={}; Path=/v1; HttpOnly; SameSite=Lax; Max-Age={}{}",
        snapshot.runtime.config().browser_auth.session_cookie_name,
        token,
        ttl_seconds,
        secure_cookie_suffix(snapshot)
    );
    if let Ok(value) = HeaderValue::from_str(&cookie) {
        headers.insert(SET_COOKIE, value);
    }
}

fn clear_session_cookie(snapshot: &RuntimeSnapshot, headers: &mut HeaderMap) {
    let cookie = format!(
        "{}=; Path=/v1; HttpOnly; SameSite=Lax; Max-Age=0{}",
        snapshot.runtime.config().browser_auth.session_cookie_name,
        secure_cookie_suffix(snapshot)
    );
    if let Ok(value) = HeaderValue::from_str(&cookie) {
        headers.insert(SET_COOKIE, value);
    }
}

fn secure_cookie_suffix(snapshot: &RuntimeSnapshot) -> &'static str {
    if snapshot
        .runtime
        .config()
        .browser_auth
        .public_origin
        .as_deref()
        .and_then(|origin| Url::parse(origin).ok())
        .is_some_and(|origin| origin.scheme() == "https")
    {
        "; Secure"
    } else {
        ""
    }
}

pub(crate) async fn run_store_blocking<T, F>(operation: F) -> Result<T, ManagedStoreError>
where
    T: Send + 'static,
    F: FnOnce() -> Result<T, ManagedStoreError> + Send + 'static,
{
    tokio::task::spawn_blocking(operation)
        .await
        .map_err(|error| {
            ManagedStoreError::Unavailable(format!("managed store task failed: {error}"))
        })?
}

fn auth_success_envelope(
    request_id: &str,
    broker_request_id: &str,
    operation: &str,
    principal: Option<String>,
    result: Value,
) -> AuthEnvelope {
    AuthEnvelope {
        ok: true,
        decision: Decision::Allow,
        reason_code: None,
        request_id: request_id.to_string(),
        broker_request_id: broker_request_id.to_string(),
        operation: operation.to_string(),
        principal,
        result: Some(result),
        error: None,
    }
}

/// A successful auth response. Like management successes, an operation
/// classified as an unaudited read (`auth.session` for a signed-in session)
/// is answered without touching the audit writer; logins and password
/// changes append their record first and fail closed.
async fn auth_success_response(
    context: AuthResponseContext<'_>,
    principal: Option<String>,
    identity: &IdentityContext,
    result: Value,
) -> Response {
    let envelope = auth_success_envelope(
        context.request_id,
        context.broker_request_id,
        context.operation,
        principal,
        result,
    );
    if is_unaudited_read(context.operation) {
        return auth_response(StatusCode::OK, envelope);
    }
    auth_audited_response(
        context.snapshot,
        StatusCode::OK,
        envelope,
        identity,
        context.source,
    )
    .await
}

async fn auth_error_response(
    context: AuthResponseContext<'_>,
    principal: Option<String>,
    status: StatusCode,
    reason_code: ReasonCode,
    message: &str,
) -> Response {
    auth_error_response_with(
        context,
        principal,
        status,
        reason_code,
        message,
        AuthAuditDetail::default(),
    )
    .await
}

/// A failed `auth.local.login` names the submitted principal ID only when it
/// passes the principal key check. Any other value is neither recorded in
/// audit nor echoed: the record uses `anonymous` and sets
/// `providerAudit.auth.claimedPrincipalInvalid`.
async fn local_login_failure_response(
    context: AuthResponseContext<'_>,
    claimed_principal: String,
    status: StatusCode,
    reason_code: ReasonCode,
    message: &str,
) -> Response {
    let (principal, detail) = if principal_rate_key_is_safe(&claimed_principal) {
        (Some(claimed_principal), AuthAuditDetail::default())
    } else {
        (
            None,
            AuthAuditDetail {
                claimed_principal_invalid: true,
                ..AuthAuditDetail::default()
            },
        )
    };
    auth_error_response_with(context, principal, status, reason_code, message, detail).await
}

/// Extra `providerAudit.auth` fields for one authentication record.
#[derive(Clone, Copy, Default)]
struct AuthAuditDetail {
    claimed_principal_invalid: bool,
    phase: Option<&'static str>,
}

async fn auth_error_response_with(
    context: AuthResponseContext<'_>,
    principal: Option<String>,
    status: StatusCode,
    reason_code: ReasonCode,
    message: &str,
    detail: AuthAuditDetail,
) -> Response {
    let identity = principal
        .as_ref()
        .map(|principal| IdentityContext {
            principal: principal.clone(),
            principal_kind: None,
            principal_subject: None,
            groups: vec![],
            policy_groups: vec![],
            authenticated: false,
            source: None,
            caller_id: None,
        })
        .unwrap_or_else(IdentityContext::anonymous);
    let envelope = AuthEnvelope {
        ok: false,
        decision: Decision::Deny,
        reason_code: Some(reason_code),
        request_id: context.request_id.to_string(),
        broker_request_id: context.broker_request_id.to_string(),
        operation: context.operation.to_string(),
        principal,
        result: None,
        error: Some(ErrorBody {
            message: message.to_string(),
        }),
    };
    auth_audited_response_with(
        context.snapshot,
        status,
        envelope,
        &identity,
        context.source,
        detail,
    )
    .await
}

async fn auth_audited_response(
    snapshot: &RuntimeSnapshot,
    status: StatusCode,
    envelope: AuthEnvelope,
    identity: &IdentityContext,
    source: &SourceContext,
) -> Response {
    auth_audited_response_with(
        snapshot,
        status,
        envelope,
        identity,
        source,
        AuthAuditDetail::default(),
    )
    .await
}

async fn auth_audited_response_with(
    snapshot: &RuntimeSnapshot,
    status: StatusCode,
    envelope: AuthEnvelope,
    identity: &IdentityContext,
    source: &SourceContext,
    detail: AuthAuditDetail,
) -> Response {
    let envelope = match append_auth_audit(snapshot, &envelope, identity, source, detail).await {
        Ok(()) => envelope,
        Err(error) => {
            tracing::error!(
                event = "auth_audit_append_failed",
                error = %error,
                brokerRequestId = envelope.broker_request_id,
                agentRequestId = envelope.request_id,
            );
            AuthEnvelope {
                ok: false,
                decision: Decision::Deny,
                reason_code: Some(ReasonCode::AuditUnavailable),
                request_id: envelope.request_id,
                broker_request_id: envelope.broker_request_id,
                operation: envelope.operation,
                principal: envelope.principal,
                result: None,
                error: Some(ErrorBody {
                    message: "audit sink is unavailable".to_string(),
                }),
            }
        }
    };
    let status = if envelope.reason_code == Some(ReasonCode::AuditUnavailable) {
        StatusCode::SERVICE_UNAVAILABLE
    } else {
        status
    };
    auth_response(status, envelope)
}

async fn append_auth_audit(
    snapshot: &RuntimeSnapshot,
    envelope: &AuthEnvelope,
    identity: &IdentityContext,
    source: &SourceContext,
    detail: AuthAuditDetail,
) -> Result<(), RuntimeError> {
    let mut auth_audit = json!({
        "operation": &envelope.operation,
        "reasonCode": envelope.reason_code,
    });
    if detail.claimed_principal_invalid {
        auth_audit["claimedPrincipalInvalid"] = Value::Bool(true);
    }
    if let Some(phase) = detail.phase {
        auth_audit["phase"] = json!(phase);
    }
    let record = AuditRecord {
        caller_id: identity.caller_id.clone(),
        search_authorization: None,
        timestamp: Utc::now().to_rfc3339(),
        agent_request_id: envelope.request_id.clone(),
        broker_request_id: envelope.broker_request_id.clone(),
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
        credential_connection: None,
        decision: envelope.decision.clone(),
        reason_code: envelope.reason_code.map(Into::into),
        upstream_status: None,
        upstream_duration_ms: None,
        object_ids: None,
        identity_source: identity.source.clone(),
        source: source.clone(),
        execution_context: None,
        provider_audit: Some(json!({ "auth": auth_audit })),
    };
    snapshot.runtime.append_audit_record(&record).await
}

/// Record intent before a durable authentication change. No passwords or
/// response/session material are included in either audit phase.
async fn auth_write_audit_preflight(
    context: AuthResponseContext<'_>,
    identity: &IdentityContext,
) -> Result<(), Box<Response>> {
    let envelope = auth_success_envelope(
        context.request_id,
        context.broker_request_id,
        context.operation,
        Some(identity.principal.clone()),
        Value::Null,
    );
    let response = auth_audited_response_with(
        context.snapshot,
        StatusCode::OK,
        envelope,
        identity,
        context.source,
        AuthAuditDetail {
            phase: Some("preflight"),
            ..AuthAuditDetail::default()
        },
    )
    .await;
    if response.status() == StatusCode::OK {
        Ok(())
    } else {
        Err(Box::new(response))
    }
}

/// A preflight was persisted and the store committed. A failed completion
/// append cannot turn a completed password change or logout into a retryable error.
async fn auth_committed_success_response(
    context: AuthResponseContext<'_>,
    principal: Option<String>,
    identity: &IdentityContext,
    result: Value,
) -> Response {
    let envelope = auth_success_envelope(
        context.request_id,
        context.broker_request_id,
        context.operation,
        principal,
        result,
    );
    if append_auth_audit(
        context.snapshot,
        &envelope,
        identity,
        context.source,
        AuthAuditDetail {
            phase: Some("success"),
            ..AuthAuditDetail::default()
        },
    )
    .await
    .is_err()
    {
        tracing::error!(
            event = "auth_committed_write_audit_append_failed",
            operation = context.operation,
            agentRequestId = context.request_id,
            brokerRequestId = context.broker_request_id,
            reasonCode = ReasonCode::AuditUnavailable.as_str(),
            "committed authentication change succeeded; completion audit is unavailable",
        );
    }
    auth_response(StatusCode::OK, envelope)
}

fn auth_response(status: StatusCode, envelope: AuthEnvelope) -> Response {
    observability::record_request_ids(&envelope.request_id, &envelope.broker_request_id);
    observability::record_operation(&envelope.operation);
    if let Some(principal) = envelope.principal.as_deref() {
        observability::record_principal(principal);
    }
    observability::record_decision(envelope.decision.as_str());
    if let Some(reason_code) = envelope.reason_code {
        observability::record_reason_code(reason_code.as_str());
    }
    observability::record_status(status.as_u16());
    let mut response = (status, Json(&envelope)).into_response();
    response
        .headers_mut()
        .insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
    if let Some(retry_after) =
        crate::handlers::common::retry_after_header(status.as_u16(), envelope.result.as_ref())
    {
        response
            .headers_mut()
            .insert(axum::http::header::RETRY_AFTER, retry_after);
    }
    response
}
