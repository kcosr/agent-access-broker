use crate::handlers::auth::{
    auth_request_ids, run_store_blocking, sanitize_return_to, set_session_cookie,
};
use crate::ingress::guards::{IngressLimitError, IngressPermit};
use crate::ingress::source::auth_source_key;
use crate::observability;
use crate::state::{AppState, RuntimeSnapshot};
use aes_gcm::aead::{Aead, Payload};
use aes_gcm::{Aes256Gcm, KeyInit, Nonce as AeadNonce};
use agent_access_core::microsoft_oidc::{
    MICROSOFT_OIDC_MAX_ID_TOKEN_BYTES, MICROSOFT_OIDC_SCOPES, MicrosoftGroupClaimClassification,
    MicrosoftOidcAdditionalClaims, MicrosoftOidcProviderMetadata, MicrosoftOidcRuntimeConfig,
    ValidatedMicrosoftOidcIdentity, validate_microsoft_id_token_payload_syntax,
    validate_microsoft_oidc_identity,
};
use agent_access_core::{
    AuditRecord, IdentityContext, ManagedStoreError, OidcCompleteLoginRequest,
    OidcCompletionOutcome, OidcFlowClaimRequest, OidcFlowCreateRequest, SourceContext,
    parse_ttl_seconds,
};
use agent_access_provider::{Decision, ReasonCode, ResourceScopes};
use axum::extract::{ConnectInfo, RawQuery, State};
use axum::http::header::{CACHE_CONTROL, COOKIE, LOCATION, SET_COOKIE};
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use base64::Engine;
use chrono::{Duration as ChronoDuration, SecondsFormat, Utc};
use openidconnect::core::{
    CoreAuthenticationFlow, CoreClient, CoreGenderClaim, CoreJweContentEncryptionAlgorithm,
    CoreJwsSigningAlgorithm,
};
use openidconnect::{
    AccessTokenHash, AuthType, AuthorizationCode, ClientId, ClientSecret, CsrfToken, IdToken,
    JsonWebKey, Nonce, OAuth2TokenResponse, PkceCodeChallenge, PkceCodeVerifier, RequestTokenError,
    Scope, TokenResponse,
};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::net::SocketAddr;
use uuid::Uuid;

const OIDC_BINDING_COOKIE: &str = "__Host-aab_oidc_binding";
const FLOW_AAD_PREFIX: &[u8] = b"aab:oidc:microsoft:flow:v1";
const QUERY_LIMIT_BYTES: usize = 8 * 1024;
const PARAM_LIMIT_BYTES: usize = 4 * 1024;

type MicrosoftIdToken = IdToken<
    MicrosoftOidcAdditionalClaims,
    CoreGenderClaim,
    CoreJweContentEncryptionAlgorithm,
    CoreJwsSigningAlgorithm,
>;

#[derive(Debug, Serialize, Deserialize)]
struct EncryptedFlowPayload {
    nonce: String,
    verifier: String,
}

#[derive(Debug)]
struct CallbackQuery {
    state: String,
    outcome: CallbackOutcome,
}

#[derive(Debug)]
enum CallbackOutcome {
    Code(String),
    ProviderError,
}

struct OidcAdmissionDebugGroups<'a> {
    matched_external_group_ids: &'a BTreeSet<String>,
    mapped_broker_group_ids: &'a BTreeSet<String>,
    effective_group_ids: &'a [String],
    policy_group_ids: &'a [String],
}

struct OidcClaimsDebugContext {
    tenant_id: String,
    user_object_id: String,
    name: Option<String>,
    preferred_username: Option<String>,
    email: Option<String>,
    group_claim_status: &'static str,
    group_count: Option<usize>,
    external_group_ids: Option<Vec<String>>,
    malformed_group_reason: Option<String>,
}

impl OidcClaimsDebugContext {
    fn new(
        identity: &ValidatedMicrosoftOidcIdentity,
        name: Option<String>,
        preferred_username: Option<String>,
        email: Option<String>,
        group_claims: &MicrosoftGroupClaimClassification,
    ) -> Self {
        let (group_claim_status, group_count, external_group_ids, malformed_group_reason) =
            match group_claims {
                MicrosoftGroupClaimClassification::Complete(groups) => (
                    if groups.is_empty() {
                        "empty"
                    } else {
                        "complete"
                    },
                    Some(groups.len()),
                    Some(groups.iter().cloned().collect()),
                    None,
                ),
                MicrosoftGroupClaimClassification::Overage => ("overage", None, None, None),
                MicrosoftGroupClaimClassification::Malformed(reason) => {
                    ("malformed", None, None, Some(format!("{reason:?}")))
                }
            };
        Self {
            tenant_id: identity.tenant_id.clone(),
            user_object_id: identity.user_object_id.clone(),
            name,
            preferred_username,
            email,
            group_claim_status,
            group_count,
            external_group_ids,
            malformed_group_reason,
        }
    }

    fn observed(
        &self,
        request_id: &str,
        broker_request_id: &str,
        admission_outcome: &str,
        principal: Option<&str>,
        jit_created: Option<bool>,
        admission_groups: Option<OidcAdmissionDebugGroups<'_>>,
    ) {
        let empty_group_set = BTreeSet::new();
        let matched_external_group_ids = admission_groups
            .as_ref()
            .map(|groups| groups.matched_external_group_ids)
            .unwrap_or(&empty_group_set);
        let mapped_broker_group_ids = admission_groups
            .as_ref()
            .map(|groups| groups.mapped_broker_group_ids)
            .unwrap_or(&empty_group_set);
        let effective_group_ids = admission_groups
            .as_ref()
            .map(|groups| groups.effective_group_ids)
            .unwrap_or(&[]);
        let policy_group_ids = admission_groups
            .as_ref()
            .map(|groups| groups.policy_group_ids)
            .unwrap_or(&[]);
        tracing::debug!(
            target: "agent_access_broker::handlers::oidc",
            event = "oidc_claims_observed",
            agentRequestId = request_id,
            brokerRequestId = broker_request_id,
            tenantId = %self.tenant_id,
            userObjectId = %self.user_object_id,
            name = self.name.as_deref().unwrap_or(""),
            preferredUsername = self.preferred_username.as_deref().unwrap_or(""),
            email = self.email.as_deref().unwrap_or(""),
            groupClaimStatus = self.group_claim_status,
            groupCount = self.group_count.unwrap_or(0),
            groupCountKnown = self.group_count.is_some(),
            externalGroupIds = ?self.external_group_ids.as_deref().unwrap_or(&[]),
            malformedGroupReason = self.malformed_group_reason.as_deref().unwrap_or(""),
            admissionOutcome = admission_outcome,
            principal = principal.unwrap_or(""),
            jitCreated = jit_created.unwrap_or(false),
            admissionDetailsAvailable = admission_groups.is_some(),
            matchedExternalGroupIds = ?matched_external_group_ids,
            mappedBrokerGroupIds = ?mapped_broker_group_ids,
            effectiveGroupIds = ?effective_group_ids,
            policyGroupIds = ?policy_group_ids,
            "validated Microsoft OIDC identity claims"
        );
    }
}

pub(crate) async fn microsoft_oidc_start(
    State(state): State<AppState>,
    ConnectInfo(remote_addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    RawQuery(raw_query): RawQuery,
) -> Response {
    let operation = crate::handlers::management::audit_actions::OIDC_LOGIN_STARTED;
    let (request_id, broker_request_id) = match auth_request_ids(&headers, operation) {
        Ok(ids) => ids,
        Err(response) => return *response,
    };
    let snapshot = state.reloadable.current();
    let source = snapshot
        .source_resolver
        .source_context(remote_addr, &headers);
    let _permit = match acquire_oidc_source_guard(&state, &snapshot, &source) {
        Ok(permit) => permit,
        Err((status, reason_code)) => {
            return oidc_direct_error(
                &snapshot,
                &request_id,
                &broker_request_id,
                operation,
                &source,
                status,
                reason_code,
            )
            .await;
        }
    };
    let Some(provider) = snapshot.microsoft_oidc.as_ref() else {
        return oidc_direct_error(
            &snapshot,
            &request_id,
            &broker_request_id,
            operation,
            &source,
            StatusCode::SERVICE_UNAVAILABLE,
            ReasonCode::OidcUnavailable,
        )
        .await;
    };
    let provider_generation = provider.provider_generation();
    if provider_generation == 0 {
        return oidc_direct_error(
            &snapshot,
            &request_id,
            &broker_request_id,
            operation,
            &source,
            StatusCode::SERVICE_UNAVAILABLE,
            ReasonCode::OidcUnavailable,
        )
        .await;
    }
    let return_to = match parse_start_return_to(raw_query.as_deref()) {
        Ok(return_to) => sanitize_return_to(snapshot.runtime.config(), return_to.as_deref()),
        Err(()) => {
            return oidc_direct_error(
                &snapshot,
                &request_id,
                &broker_request_id,
                operation,
                &source,
                StatusCode::BAD_REQUEST,
                ReasonCode::OidcFlowInvalid,
            )
            .await;
        }
    };
    let metadata = match provider.metadata_for_start().await {
        Ok(metadata) => metadata,
        Err(_) => {
            return oidc_direct_error(
                &snapshot,
                &request_id,
                &broker_request_id,
                operation,
                &source,
                StatusCode::SERVICE_UNAVAILABLE,
                ReasonCode::OidcUnavailable,
            )
            .await;
        }
    };
    let Some(store) = snapshot.runtime.managed_store().cloned() else {
        return oidc_direct_error(
            &snapshot,
            &request_id,
            &broker_request_id,
            operation,
            &source,
            StatusCode::SERVICE_UNAVAILABLE,
            ReasonCode::OidcUnavailable,
        )
        .await;
    };

    let state_secret = random_secret();
    let nonce_secret = random_secret();
    let verifier_secret = random_secret();
    let binding_secret = oidc_binding_cookie(&headers)
        .filter(|value| valid_secret(value))
        .unwrap_or_else(random_secret);
    let state_hash = hash_secret(&state_secret);
    let binding_hash = hash_secret(&binding_secret);
    let (encrypted_payload, encryption_nonce) = match encrypt_flow_payload(
        provider.config(),
        provider_generation,
        &state_hash,
        &EncryptedFlowPayload {
            nonce: nonce_secret.clone(),
            verifier: verifier_secret.clone(),
        },
    ) {
        Ok(value) => value,
        Err(()) => {
            return oidc_direct_error(
                &snapshot,
                &request_id,
                &broker_request_id,
                operation,
                &source,
                StatusCode::SERVICE_UNAVAILABLE,
                ReasonCode::OidcUnavailable,
            )
            .await;
        }
    };
    let expires_at = (provider.clock().now()
        + ChronoDuration::seconds(provider.config().flow_ttl_seconds() as i64))
    .to_rfc3339_opts(SecondsFormat::Secs, true);
    let max_pending_flows = u64::from(provider.config().max_pending_flows());
    let flow_store = store.clone();
    let created = run_store_blocking(move || {
        flow_store.create_oidc_flow(OidcFlowCreateRequest {
            state_hash,
            browser_binding_hash: binding_hash,
            provider_generation,
            encrypted_payload,
            encryption_nonce,
            return_path: return_to,
            expires_at,
            max_pending_flows,
        })
    })
    .await;
    let created = match created {
        Ok(created) => created,
        Err(_) => {
            return oidc_direct_error(
                &snapshot,
                &request_id,
                &broker_request_id,
                operation,
                &source,
                StatusCode::SERVICE_UNAVAILABLE,
                ReasonCode::OidcUnavailable,
            )
            .await;
        }
    };

    let verifier = PkceCodeVerifier::new(verifier_secret);
    let challenge = PkceCodeChallenge::from_code_verifier_sha256(&verifier);
    let client = CoreClient::from_provider_metadata(
        metadata.metadata().clone(),
        ClientId::new(provider.config().client_id().to_string()),
        Some(ClientSecret::new(
            provider.config().secrets().client_secret().to_string(),
        )),
    )
    .set_redirect_uri(provider.config().redirect_url().clone())
    .set_auth_type(AuthType::RequestBody);
    let (authorization_url, _, _) = client
        .authorize_url(
            CoreAuthenticationFlow::AuthorizationCode,
            || CsrfToken::new(state_secret),
            || Nonce::new(nonce_secret),
        )
        .add_scopes(
            MICROSOFT_OIDC_SCOPES
                .iter()
                .filter(|scope| **scope != "openid")
                .map(|scope| Scope::new((*scope).to_string())),
        )
        .add_extra_param("response_mode", "query")
        .set_pkce_challenge(challenge)
        .url();

    if append_oidc_audit(
        &snapshot,
        &request_id,
        &broker_request_id,
        operation,
        &source,
        &IdentityContext::anonymous(),
        Decision::Allow,
        None,
        json!({"provider": "microsoft"}),
    )
    .await
    .is_err()
    {
        let _ = run_store_blocking(move || {
            store.claim_oidc_flow(OidcFlowClaimRequest {
                state_hash: created.state_hash,
                browser_binding_hash: created.browser_binding_hash,
                provider_generation,
                outcome_code: "audit_failed".to_string(),
            })
        })
        .await;
        return oidc_direct_error_without_audit(
            StatusCode::SERVICE_UNAVAILABLE,
            &request_id,
            &broker_request_id,
            operation,
            ReasonCode::AuditUnavailable,
        );
    }

    let binding_cookie = format!(
        "{OIDC_BINDING_COOKIE}={binding_secret}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age={}",
        provider.config().flow_ttl_seconds()
    );
    let mut response = StatusCode::SEE_OTHER.into_response();
    response.headers_mut().insert(
        LOCATION,
        HeaderValue::from_str(authorization_url.as_str())
            .expect("validated Microsoft authorization URL is a header value"),
    );
    response.headers_mut().insert(
        SET_COOKIE,
        HeaderValue::from_str(&binding_cookie).expect("random binding cookie is a header value"),
    );
    set_browser_security_headers(response.headers_mut());
    response
}

pub(crate) async fn microsoft_oidc_callback(
    State(state): State<AppState>,
    ConnectInfo(remote_addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    RawQuery(raw_query): RawQuery,
) -> Response {
    let operation = crate::handlers::management::audit_actions::OIDC_LOGIN_CALLBACK;
    let (request_id, broker_request_id) = match auth_request_ids(&headers, operation) {
        Ok(ids) => ids,
        Err(response) => return *response,
    };
    let snapshot = state.reloadable.current();
    let source = snapshot
        .source_resolver
        .source_context(remote_addr, &headers);
    let _permit = match acquire_oidc_source_guard(&state, &snapshot, &source) {
        Ok(permit) => permit,
        Err((_, reason_code)) => {
            return oidc_callback_error(
                &snapshot,
                &request_id,
                &broker_request_id,
                operation,
                &source,
                reason_code,
                None,
            )
            .await;
        }
    };
    let Some(provider) = snapshot.microsoft_oidc.as_ref() else {
        return oidc_callback_error(
            &snapshot,
            &request_id,
            &broker_request_id,
            operation,
            &source,
            ReasonCode::OidcUnavailable,
            None,
        )
        .await;
    };
    let query = match parse_callback_query(raw_query.as_deref()) {
        Ok(query) => query,
        Err(()) => {
            return oidc_callback_error(
                &snapshot,
                &request_id,
                &broker_request_id,
                operation,
                &source,
                ReasonCode::OidcFlowInvalid,
                None,
            )
            .await;
        }
    };
    let Some(binding_secret) = oidc_binding_cookie(&headers).filter(|value| valid_secret(value))
    else {
        return oidc_callback_error(
            &snapshot,
            &request_id,
            &broker_request_id,
            operation,
            &source,
            ReasonCode::OidcFlowInvalid,
            None,
        )
        .await;
    };
    let Some(store) = snapshot.runtime.managed_store().cloned() else {
        return oidc_callback_error(
            &snapshot,
            &request_id,
            &broker_request_id,
            operation,
            &source,
            ReasonCode::OidcUnavailable,
            None,
        )
        .await;
    };
    let provider_generation = provider.provider_generation();
    let state_hash = hash_secret(&query.state);
    let binding_hash = hash_secret(&binding_secret);
    let outcome_code = match &query.outcome {
        CallbackOutcome::Code(_) => "code",
        CallbackOutcome::ProviderError => "provider_error",
    }
    .to_string();
    let flow = match run_store_blocking(move || {
        store.claim_oidc_flow(OidcFlowClaimRequest {
            state_hash,
            browser_binding_hash: binding_hash,
            provider_generation,
            outcome_code,
        })
    })
    .await
    {
        Ok(flow) => flow,
        Err(ManagedStoreError::OidcFlowExpired) => {
            return oidc_callback_error(
                &snapshot,
                &request_id,
                &broker_request_id,
                operation,
                &source,
                ReasonCode::OidcFlowExpired,
                None,
            )
            .await;
        }
        Err(_) => {
            return oidc_callback_error(
                &snapshot,
                &request_id,
                &broker_request_id,
                operation,
                &source,
                ReasonCode::OidcFlowInvalid,
                None,
            )
            .await;
        }
    };
    if matches!(query.outcome, CallbackOutcome::ProviderError) {
        return oidc_callback_error(
            &snapshot,
            &request_id,
            &broker_request_id,
            operation,
            &source,
            ReasonCode::OidcProviderDenied,
            Some(flow.return_path.as_str()),
        )
        .await;
    }
    let CallbackOutcome::Code(code) = query.outcome else {
        unreachable!()
    };
    let payload = match decrypt_flow_payload(provider.config(), &flow) {
        Ok(payload) => payload,
        Err(()) => {
            return oidc_callback_error(
                &snapshot,
                &request_id,
                &broker_request_id,
                operation,
                &source,
                ReasonCode::OidcFlowInvalid,
                Some(flow.return_path.as_str()),
            )
            .await;
        }
    };
    let metadata = match provider.metadata_for_token_validation().await {
        Ok(metadata) => metadata,
        Err(_) => {
            return oidc_callback_error(
                &snapshot,
                &request_id,
                &broker_request_id,
                operation,
                &source,
                ReasonCode::OidcUnavailable,
                Some(flow.return_path.as_str()),
            )
            .await;
        }
    };
    let client = CoreClient::from_provider_metadata(
        metadata.metadata().clone(),
        ClientId::new(provider.config().client_id().to_string()),
        Some(ClientSecret::new(
            provider.config().secrets().client_secret().to_string(),
        )),
    )
    .set_redirect_uri(provider.config().redirect_url().clone())
    .set_auth_type(AuthType::RequestBody);
    let token_response = match client
        .exchange_code(AuthorizationCode::new(code))
        .expect("validated discovery metadata contains a token endpoint")
        .set_pkce_verifier(PkceCodeVerifier::new(payload.verifier))
        .request_async(provider.http_client())
        .await
    {
        Ok(response) => response,
        Err(RequestTokenError::Request(_)) => {
            return oidc_callback_error(
                &snapshot,
                &request_id,
                &broker_request_id,
                operation,
                &source,
                ReasonCode::OidcUnavailable,
                Some(flow.return_path.as_str()),
            )
            .await;
        }
        Err(_) => {
            return oidc_callback_error(
                &snapshot,
                &request_id,
                &broker_request_id,
                operation,
                &source,
                ReasonCode::OidcIdentityInvalid,
                Some(flow.return_path.as_str()),
            )
            .await;
        }
    };
    let Some(raw_id_token) = token_response.id_token().map(ToString::to_string) else {
        return oidc_callback_error(
            &snapshot,
            &request_id,
            &broker_request_id,
            operation,
            &source,
            ReasonCode::OidcIdentityInvalid,
            Some(flow.return_path.as_str()),
        )
        .await;
    };
    if raw_id_token.len() > MICROSOFT_OIDC_MAX_ID_TOKEN_BYTES
        || validate_microsoft_id_token_payload_syntax(&raw_id_token).is_err()
    {
        return oidc_callback_error(
            &snapshot,
            &request_id,
            &broker_request_id,
            operation,
            &source,
            ReasonCode::OidcIdentityInvalid,
            Some(flow.return_path.as_str()),
        )
        .await;
    }
    let (kid, algorithm) = match token_header(&raw_id_token) {
        Some(header) => header,
        None => {
            return oidc_callback_error(
                &snapshot,
                &request_id,
                &broker_request_id,
                operation,
                &source,
                ReasonCode::OidcIdentityInvalid,
                Some(flow.return_path.as_str()),
            )
            .await;
        }
    };
    if algorithm != "RS256" {
        return oidc_callback_error(
            &snapshot,
            &request_id,
            &broker_request_id,
            operation,
            &source,
            ReasonCode::OidcIdentityInvalid,
            Some(flow.return_path.as_str()),
        )
        .await;
    }
    let metadata = if metadata_has_kid(&metadata, &kid) {
        metadata
    } else {
        match provider.refresh_unknown_key(&metadata).await {
            Ok(refreshed) if metadata_has_kid(&refreshed, &kid) => refreshed,
            Ok(_) => {
                return oidc_callback_error(
                    &snapshot,
                    &request_id,
                    &broker_request_id,
                    operation,
                    &source,
                    ReasonCode::OidcIdentityInvalid,
                    Some(flow.return_path.as_str()),
                )
                .await;
            }
            Err(_) => {
                return oidc_callback_error(
                    &snapshot,
                    &request_id,
                    &broker_request_id,
                    operation,
                    &source,
                    ReasonCode::OidcUnavailable,
                    Some(flow.return_path.as_str()),
                )
                .await;
            }
        }
    };
    let id_token: MicrosoftIdToken = match serde_json::from_value(Value::String(raw_id_token)) {
        Ok(token) => token,
        Err(_) => {
            return oidc_callback_error(
                &snapshot,
                &request_id,
                &broker_request_id,
                operation,
                &source,
                ReasonCode::OidcIdentityInvalid,
                Some(flow.return_path.as_str()),
            )
            .await;
        }
    };
    let clock = provider.clock_arc();
    let verification_client = CoreClient::from_provider_metadata(
        metadata.metadata().clone(),
        ClientId::new(provider.config().client_id().to_string()),
        Some(ClientSecret::new(
            provider.config().secrets().client_secret().to_string(),
        )),
    )
    .set_redirect_uri(provider.config().redirect_url().clone())
    .set_auth_type(AuthType::RequestBody);
    let verifier = verification_client
        .id_token_verifier()
        .set_allowed_algs([CoreJwsSigningAlgorithm::RsaSsaPkcs1V15Sha256])
        .set_time_fn(move || clock.now());
    let claims = match id_token.claims(&verifier, &Nonce::new(payload.nonce)) {
        Ok(claims) => claims,
        Err(_) => {
            return oidc_callback_error(
                &snapshot,
                &request_id,
                &broker_request_id,
                operation,
                &source,
                ReasonCode::OidcIdentityInvalid,
                Some(flow.return_path.as_str()),
            )
            .await;
        }
    };
    if let Some(expected_hash) = claims.access_token_hash() {
        let actual_hash = (|| {
            let algorithm = id_token.signing_alg().ok()?;
            let key = id_token.signing_key(&verifier).ok()?;
            AccessTokenHash::from_token(token_response.access_token(), algorithm, key).ok()
        })();
        if actual_hash.as_ref() != Some(expected_hash) {
            return oidc_callback_error(
                &snapshot,
                &request_id,
                &broker_request_id,
                operation,
                &source,
                ReasonCode::OidcIdentityInvalid,
                Some(flow.return_path.as_str()),
            )
            .await;
        }
    }
    let identity = match validate_microsoft_oidc_identity(
        claims,
        provider.config().tenant_id(),
        provider.config().client_id(),
        provider.clock(),
    ) {
        Ok(identity) => identity,
        Err(_) => {
            return oidc_callback_error(
                &snapshot,
                &request_id,
                &broker_request_id,
                operation,
                &source,
                ReasonCode::OidcIdentityInvalid,
                Some(flow.return_path.as_str()),
            )
            .await;
        }
    };
    let name = claims
        .name()
        .and_then(|value| value.get(None))
        .and_then(|value| sanitized_profile_value(value.as_str(), 256));
    let preferred_username = claims
        .preferred_username()
        .and_then(|value| sanitized_profile_value(value.as_str(), 256));
    let email = claims
        .email()
        .and_then(|value| sanitized_email_claim(value.as_str()));
    let display_name = name
        .clone()
        .or_else(|| preferred_username.clone())
        .or_else(|| {
            email
                .as_deref()
                .and_then(|value| sanitized_profile_value(value, 256))
        });
    let group_claims = claims.additional_claims().classify_groups();
    let claims_debug = OidcClaimsDebugContext::new(
        &identity,
        name.clone(),
        preferred_username.clone(),
        email.clone(),
        &group_claims,
    );
    let groups = match group_claims {
        MicrosoftGroupClaimClassification::Complete(groups) => groups,
        MicrosoftGroupClaimClassification::Overage
        | MicrosoftGroupClaimClassification::Malformed(_) => {
            let store = snapshot.runtime.managed_store().unwrap().clone();
            let external_subject = identity.external_subject.clone();
            let observed_at = provider
                .clock()
                .now()
                .to_rfc3339_opts(SecondsFormat::Secs, true);
            let watermark = run_store_blocking(move || {
                store.record_trusted_incomplete_oidc_callback(
                    &external_subject,
                    flow.flow_sequence,
                    provider_generation,
                    &observed_at,
                )
            })
            .await;
            match watermark {
                Ok(true) => {}
                Ok(false) => {
                    claims_debug.observed(
                        &request_id,
                        &broker_request_id,
                        "superseded",
                        None,
                        None,
                        None,
                    );
                    return oidc_callback_error(
                        &snapshot,
                        &request_id,
                        &broker_request_id,
                        operation,
                        &source,
                        ReasonCode::OidcFlowInvalid,
                        Some(flow.return_path.as_str()),
                    )
                    .await;
                }
                Err(_) => {
                    claims_debug.observed(
                        &request_id,
                        &broker_request_id,
                        "store_unavailable",
                        None,
                        None,
                        None,
                    );
                    return oidc_callback_error(
                        &snapshot,
                        &request_id,
                        &broker_request_id,
                        operation,
                        &source,
                        ReasonCode::OidcUnavailable,
                        Some(flow.return_path.as_str()),
                    )
                    .await;
                }
            }
            claims_debug.observed(
                &request_id,
                &broker_request_id,
                "group_claims_incomplete",
                None,
                None,
                None,
            );
            return oidc_callback_error(
                &snapshot,
                &request_id,
                &broker_request_id,
                operation,
                &source,
                ReasonCode::OidcGroupClaimsIncomplete,
                Some(flow.return_path.as_str()),
            )
            .await;
        }
    };
    let callback_now = provider.clock().now();
    let evidence_at = std::cmp::min(identity.issued_at, callback_now);
    let callback_now = callback_now.to_rfc3339_opts(SecondsFormat::Secs, true);
    let evidence_at = evidence_at.to_rfc3339_opts(SecondsFormat::Secs, true);
    let session_ttl_seconds =
        parse_ttl_seconds(&snapshot.runtime.config().browser_auth.session_ttl).unwrap_or(8 * 3600);
    let Some(token_hasher) = snapshot.runtime.broker_token_hasher().cloned() else {
        return oidc_callback_error(
            &snapshot,
            &request_id,
            &broker_request_id,
            operation,
            &source,
            ReasonCode::OidcUnavailable,
            Some(flow.return_path.as_str()),
        )
        .await;
    };
    let jit_provisioning = provider.config().jit_provisioning();
    let external_subject = identity.external_subject.clone();
    let completion_groups = groups.clone();
    let completion_display_name = display_name.clone();
    let completion_email = email.clone();
    // External exchange is complete. Serialize only the store mutation with
    // reload, rejecting a stale key-ring snapshot before JIT can encrypt inventory.
    let completion = state
        .reloadable
        .token_store_call_from_snapshot(snapshot.clone(), move |runtime| {
            let store = runtime.managed_store().ok_or_else(|| {
                ManagedStoreError::Unavailable("managed store is unavailable".into())
            })?;
            store.complete_oidc_login(
                &token_hasher,
                OidcCompleteLoginRequest {
                    flow_sequence: flow.flow_sequence,
                    provider_generation,
                    external_subject,
                    external_group_ids: completion_groups,
                    jit_provisioning,
                    jit_principal_id: format!("usr-{}", Uuid::new_v4()),
                    display_name: completion_display_name,
                    email: completion_email,
                    evidence_at,
                    callback_now,
                    session_ttl_seconds,
                    created_by: "oidc-microsoft".to_string(),
                },
            )
        })
        .await;
    let result = match completion {
        Ok(OidcCompletionOutcome::Succeeded {
            result,
            jit_created,
        }) => (result, jit_created),
        Ok(OidcCompletionOutcome::Denied { reason }) => {
            claims_debug.observed(&request_id, &broker_request_id, &reason, None, None, None);
            return oidc_callback_error(
                &snapshot,
                &request_id,
                &broker_request_id,
                operation,
                &source,
                ReasonCode::OidcAdmissionDenied,
                Some(flow.return_path.as_str()),
            )
            .await;
        }
        Ok(OidcCompletionOutcome::Superseded) => {
            claims_debug.observed(
                &request_id,
                &broker_request_id,
                "superseded",
                None,
                None,
                None,
            );
            return oidc_callback_error(
                &snapshot,
                &request_id,
                &broker_request_id,
                operation,
                &source,
                ReasonCode::OidcFlowInvalid,
                Some(flow.return_path.as_str()),
            )
            .await;
        }
        Err(ManagedStoreError::OidcLoginMethodConflict) => {
            claims_debug.observed(
                &request_id,
                &broker_request_id,
                "login_method_conflict",
                None,
                None,
                None,
            );
            return oidc_callback_error(
                &snapshot,
                &request_id,
                &broker_request_id,
                operation,
                &source,
                ReasonCode::OidcLoginMethodConflict,
                Some(flow.return_path.as_str()),
            )
            .await;
        }
        Err(_) => {
            claims_debug.observed(
                &request_id,
                &broker_request_id,
                "store_unavailable",
                None,
                None,
                None,
            );
            return oidc_callback_error(
                &snapshot,
                &request_id,
                &broker_request_id,
                operation,
                &source,
                ReasonCode::OidcUnavailable,
                Some(flow.return_path.as_str()),
            )
            .await;
        }
    };
    let (result, jit_created) = result;
    let matched_external_group_ids = result
        .membership
        .details
        .iter()
        .flat_map(|membership| {
            membership
                .microsoft
                .iter()
                .map(|contribution| contribution.external_group_id.clone())
        })
        .collect::<BTreeSet<_>>();
    let mapped_broker_group_ids = result
        .membership
        .details
        .iter()
        .filter(|membership| !membership.microsoft.is_empty())
        .map(|membership| membership.group_id.clone())
        .collect::<BTreeSet<_>>();
    let audit_identity = IdentityContext {
        principal: result.principal.principal_id.clone(),
        principal_subject: None,
        groups: result.membership.groups.clone(),
        policy_groups: result.membership.policy_groups.clone(),
        authenticated: true,
        source: None,
        caller_id: None,
    };
    let audit = append_oidc_audit(
        &snapshot,
        &request_id,
        &broker_request_id,
        crate::handlers::management::audit_actions::OIDC_LOGIN_SUCCEEDED,
        &source,
        &audit_identity,
        Decision::Allow,
        None,
        json!({
            "provider": "microsoft",
            "loginMethodId": result.login_method.login_method_id,
            "jitCreated": jit_created,
            "effectiveGroupCount": result.membership.groups.len(),
        }),
    )
    .await;
    if audit.is_err() {
        claims_debug.observed(
            &request_id,
            &broker_request_id,
            "audit_unavailable",
            Some(result.principal.principal_id.as_str()),
            Some(jit_created),
            Some(OidcAdmissionDebugGroups {
                matched_external_group_ids: &matched_external_group_ids,
                mapped_broker_group_ids: &mapped_broker_group_ids,
                effective_group_ids: &result.membership.groups,
                policy_group_ids: &result.membership.policy_groups,
            }),
        );
        let store = snapshot.runtime.managed_store().unwrap().clone();
        let token_id = result.session.record.token_id.clone();
        let actor = result.principal.principal_id.clone();
        let _ = run_store_blocking(move || store.revoke_browser_session(&token_id, &actor)).await;
        return oidc_callback_error_without_audit(
            &request_id,
            &broker_request_id,
            ReasonCode::AuditUnavailable,
        );
    }
    claims_debug.observed(
        &request_id,
        &broker_request_id,
        "succeeded",
        Some(result.principal.principal_id.as_str()),
        Some(jit_created),
        Some(OidcAdmissionDebugGroups {
            matched_external_group_ids: &matched_external_group_ids,
            mapped_broker_group_ids: &mapped_broker_group_ids,
            effective_group_ids: &result.membership.groups,
            policy_group_ids: &result.membership.policy_groups,
        }),
    );
    let mut response = StatusCode::SEE_OTHER.into_response();
    response.headers_mut().insert(
        LOCATION,
        HeaderValue::from_str(&flow.return_path).expect("sanitized return path is a header value"),
    );
    set_session_cookie(
        &snapshot,
        &result.session.token,
        session_ttl_seconds,
        response.headers_mut(),
    );
    set_browser_security_headers(response.headers_mut());
    response
}

fn acquire_oidc_source_guard(
    state: &AppState,
    snapshot: &RuntimeSnapshot,
    source: &SourceContext,
) -> Result<IngressPermit, (StatusCode, ReasonCode)> {
    let limits = snapshot.runtime.limits();
    let permit = state
        .reloadable
        .shared_ingress
        .try_global_concurrency(limits.max_concurrent_requests)
        .map_err(oidc_limit_error)?;
    state
        .reloadable
        .shared_ingress
        .check_auth_source_rate(
            &auth_source_key(source),
            limits.auth_requests_per_source_per_minute,
        )
        .map_err(oidc_limit_error)?;
    Ok(permit)
}

fn oidc_limit_error(error: IngressLimitError) -> (StatusCode, ReasonCode) {
    let reason = error.reason_code();
    (
        StatusCode::from_u16(reason.http_status()).unwrap_or(StatusCode::TOO_MANY_REQUESTS),
        reason,
    )
}

fn parse_start_return_to(raw: Option<&str>) -> Result<Option<String>, ()> {
    let Some(raw) = raw else {
        return Ok(None);
    };
    if raw.len() > QUERY_LIMIT_BYTES {
        return Err(());
    }
    let mut return_to = None;
    for (name, value) in url::form_urlencoded::parse(raw.as_bytes()) {
        if name == "returnTo" {
            if return_to.is_some() || value.len() > PARAM_LIMIT_BYTES {
                return Err(());
            }
            return_to = Some(value.into_owned());
        }
    }
    Ok(return_to)
}

fn parse_callback_query(raw: Option<&str>) -> Result<CallbackQuery, ()> {
    let raw = raw.ok_or(())?;
    if raw.len() > QUERY_LIMIT_BYTES {
        return Err(());
    }
    let mut state = None;
    let mut code = None;
    let mut provider_error = None;
    for (name, value) in url::form_urlencoded::parse(raw.as_bytes()) {
        if value.len() > PARAM_LIMIT_BYTES {
            return Err(());
        }
        match name.as_ref() {
            "state" if state.is_none() => state = Some(value.into_owned()),
            "code" if code.is_none() => code = Some(value.into_owned()),
            "error" if provider_error.is_none() => provider_error = Some(value.into_owned()),
            "state" | "code" | "error" => return Err(()),
            _ => {}
        }
    }
    let state = state.filter(|value| valid_secret(value)).ok_or(())?;
    let outcome = match (code, provider_error) {
        (Some(code), None) if !code.is_empty() => CallbackOutcome::Code(code),
        (None, Some(error)) if !error.is_empty() => CallbackOutcome::ProviderError,
        _ => return Err(()),
    };
    Ok(CallbackQuery { state, outcome })
}

fn random_secret() -> String {
    let mut bytes = [0_u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

fn valid_secret(value: &str) -> bool {
    value.len() == 43
        && base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(value)
            .is_ok_and(|bytes| bytes.len() == 32)
}

fn oidc_binding_cookie(headers: &HeaderMap) -> Option<String> {
    let mut binding = None;
    for header in headers.get_all(COOKIE) {
        let raw = header.to_str().ok()?;
        for part in raw.split(';') {
            let Some((name, value)) = part.trim().split_once('=') else {
                continue;
            };
            if name == OIDC_BINDING_COOKIE {
                if binding.is_some() || value.is_empty() {
                    return None;
                }
                binding = Some(value.to_string());
            }
        }
    }
    binding
}

fn hash_secret(value: &str) -> Vec<u8> {
    Sha256::digest(value.as_bytes()).to_vec()
}

fn flow_aad(provider_generation: u64, state_hash: &[u8]) -> Vec<u8> {
    let mut aad = Vec::with_capacity(FLOW_AAD_PREFIX.len() + 8 + state_hash.len());
    aad.extend_from_slice(FLOW_AAD_PREFIX);
    aad.extend_from_slice(&provider_generation.to_be_bytes());
    aad.extend_from_slice(state_hash);
    aad
}

fn encrypt_flow_payload(
    config: &MicrosoftOidcRuntimeConfig,
    provider_generation: u64,
    state_hash: &[u8],
    payload: &EncryptedFlowPayload,
) -> Result<(Vec<u8>, Vec<u8>), ()> {
    let plaintext = serde_json::to_vec(payload).map_err(|_| ())?;
    let cipher = Aes256Gcm::new_from_slice(config.secrets().flow_key()).map_err(|_| ())?;
    let mut nonce = [0_u8; 12];
    rand::rngs::OsRng.fill_bytes(&mut nonce);
    let ciphertext = cipher
        .encrypt(
            AeadNonce::from_slice(&nonce),
            Payload {
                msg: &plaintext,
                aad: &flow_aad(provider_generation, state_hash),
            },
        )
        .map_err(|_| ())?;
    Ok((ciphertext, nonce.to_vec()))
}

fn decrypt_flow_payload(
    config: &MicrosoftOidcRuntimeConfig,
    flow: &agent_access_core::OidcFlowRecord,
) -> Result<EncryptedFlowPayload, ()> {
    if flow.encryption_nonce.len() != 12 {
        return Err(());
    }
    let cipher = Aes256Gcm::new_from_slice(config.secrets().flow_key()).map_err(|_| ())?;
    let plaintext = cipher
        .decrypt(
            AeadNonce::from_slice(&flow.encryption_nonce),
            Payload {
                msg: &flow.encrypted_payload,
                aad: &flow_aad(flow.provider_generation, &flow.state_hash),
            },
        )
        .map_err(|_| ())?;
    let payload: EncryptedFlowPayload = serde_json::from_slice(&plaintext).map_err(|_| ())?;
    if !valid_secret(&payload.nonce) || !valid_secret(&payload.verifier) {
        return Err(());
    }
    Ok(payload)
}

fn token_header(raw_id_token: &str) -> Option<(String, String)> {
    let header = raw_id_token.split('.').next()?;
    let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(header)
        .ok()?;
    if decoded.len() > 4096 {
        return None;
    }
    let value: Value = serde_json::from_slice(&decoded).ok()?;
    let object = value.as_object()?;
    let kid = object.get("kid")?.as_str()?;
    let algorithm = object.get("alg")?.as_str()?;
    if kid.is_empty() || kid.len() > 256 {
        return None;
    }
    Some((kid.to_string(), algorithm.to_string()))
}

fn metadata_has_kid(metadata: &MicrosoftOidcProviderMetadata, kid: &str) -> bool {
    metadata
        .jwks()
        .keys()
        .iter()
        .any(|key| key.key_id().is_some_and(|key_id| key_id.as_str() == kid))
}

fn sanitized_profile_value(value: &str, max_bytes: usize) -> Option<String> {
    let value = value.trim();
    (!value.is_empty() && value.len() <= max_bytes && !value.chars().any(char::is_control))
        .then(|| value.to_string())
}

fn sanitized_email_claim(value: &str) -> Option<String> {
    let value = sanitized_profile_value(value, 320)?;
    let (local, domain) = value.split_once('@')?;
    (value.matches('@').count() == 1
        && !local.is_empty()
        && !domain.is_empty()
        && domain.contains('.')
        && !domain.starts_with('.')
        && !domain.ends_with('.'))
    .then_some(value)
}

#[allow(clippy::too_many_arguments)]
async fn append_oidc_audit(
    snapshot: &RuntimeSnapshot,
    request_id: &str,
    broker_request_id: &str,
    operation: &str,
    source: &SourceContext,
    identity: &IdentityContext,
    decision: Decision,
    reason_code: Option<ReasonCode>,
    details: Value,
) -> Result<(), ()> {
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
        action: operation.to_string(),
        resource_scopes: ResourceScopes::new(),
        matched_grant: None,
        credential_mode: Some(None),
        decision,
        reason_code: reason_code.map(Into::into),
        upstream_status: None,
        upstream_duration_ms: None,
        object_ids: None,
        identity_source: identity.source.clone(),
        source: source.clone(),
        execution_context: None,
        provider_audit: Some(json!({"oidc": details})),
    };
    snapshot
        .runtime
        .append_audit_record(&record)
        .await
        .map_err(|_| ())
}

async fn oidc_direct_error(
    snapshot: &RuntimeSnapshot,
    request_id: &str,
    broker_request_id: &str,
    operation: &str,
    source: &SourceContext,
    status: StatusCode,
    reason_code: ReasonCode,
) -> Response {
    let _ = append_oidc_audit(
        snapshot,
        request_id,
        broker_request_id,
        operation,
        source,
        &IdentityContext::anonymous(),
        Decision::Deny,
        Some(reason_code),
        json!({"provider": "microsoft", "reasonCode": reason_code}),
    )
    .await;
    oidc_direct_error_without_audit(
        status,
        request_id,
        broker_request_id,
        operation,
        reason_code,
    )
}

fn oidc_direct_error_without_audit(
    status: StatusCode,
    request_id: &str,
    broker_request_id: &str,
    operation: &str,
    reason_code: ReasonCode,
) -> Response {
    observability::record_request_ids(request_id, broker_request_id);
    observability::record_operation(operation);
    observability::record_decision(Decision::Deny.as_str());
    observability::record_reason_code(reason_code.as_str());
    observability::record_status(status.as_u16());
    let mut response = (
        status,
        axum::Json(json!({
            "ok": false,
            "decision": "deny",
            "reasonCode": reason_code,
            "requestId": request_id,
            "brokerRequestId": broker_request_id,
            "operation": operation,
            "error": { "message": "Microsoft login is unavailable" },
        })),
    )
        .into_response();
    set_browser_security_headers(response.headers_mut());
    response
}

async fn oidc_callback_error(
    snapshot: &RuntimeSnapshot,
    request_id: &str,
    broker_request_id: &str,
    operation: &str,
    source: &SourceContext,
    reason_code: ReasonCode,
    _return_path: Option<&str>,
) -> Response {
    let _ = append_oidc_audit(
        snapshot,
        request_id,
        broker_request_id,
        crate::handlers::management::audit_actions::OIDC_LOGIN_FAILED,
        source,
        &IdentityContext::anonymous(),
        Decision::Deny,
        Some(reason_code),
        json!({"provider": "microsoft", "reasonCode": reason_code}),
    )
    .await;
    observability::record_request_ids(request_id, broker_request_id);
    observability::record_operation(operation);
    observability::record_decision(Decision::Deny.as_str());
    observability::record_reason_code(reason_code.as_str());
    observability::record_status(StatusCode::SEE_OTHER.as_u16());
    oidc_callback_error_without_audit(request_id, broker_request_id, reason_code)
}

fn oidc_callback_error_without_audit(
    request_id: &str,
    _broker_request_id: &str,
    reason_code: ReasonCode,
) -> Response {
    let location = format!(
        "/ui/login?error={}&requestId={}",
        reason_code.as_str(),
        request_id
    );
    let mut response = StatusCode::SEE_OTHER.into_response();
    response.headers_mut().insert(
        LOCATION,
        HeaderValue::from_str(&location).expect("reason and request IDs are header-safe"),
    );
    set_browser_security_headers(response.headers_mut());
    response
}

fn set_browser_security_headers(headers: &mut HeaderMap) {
    headers.insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
    headers.insert("pragma", HeaderValue::from_static("no-cache"));
    headers.insert("referrer-policy", HeaderValue::from_static("no-referrer"));
}
