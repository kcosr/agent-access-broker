//! Microsoft ID-token validation, shared by the sign-in callback and
//! membership renewal. Both run the same checks: size and claim syntax,
//! RS256 with a key ID from the cached JWKS (one throttled refresh for an
//! unknown key ID), issuer, audience and the `azp` rule, the `exp`, `iat`
//! and `nbf` skew, `tid` and canonical `oid`, and `at_hash` against the
//! response's access token when present. A sign-in requires its flow's
//! nonce; a renewal compares the token with the values stored with its
//! refresh token (OIDC Core §12.2).
use crate::state::MicrosoftOidcProviderRuntime;
use agent_access_core::OidcRenewalReference;
use agent_access_core::microsoft_oidc::renewal::{
    RenewalObservation, RenewalReferenceMismatch, compare_renewal_reference, renewal_nonce_matches,
};
use agent_access_core::microsoft_oidc::{
    MICROSOFT_OIDC_MAX_ID_TOKEN_BYTES, MicrosoftOidcAdditionalClaims, MicrosoftOidcIdTokenClaims,
    MicrosoftOidcProviderMetadata, ValidatedMicrosoftOidcIdentity,
    microsoft_id_token_audience_claim, validate_microsoft_id_token_payload_syntax,
    validate_microsoft_oidc_identity,
};
use base64::Engine;
use openidconnect::core::{
    CoreClient, CoreGenderClaim, CoreJweContentEncryptionAlgorithm, CoreJwsSigningAlgorithm,
};
use openidconnect::{
    AccessToken, AccessTokenHash, AuthType, ClientId, ClientSecret, IdToken, JsonWebKey, Nonce,
};
use serde_json::Value;

type MicrosoftIdToken = IdToken<
    MicrosoftOidcAdditionalClaims,
    CoreGenderClaim,
    CoreJweContentEncryptionAlgorithm,
    CoreJwsSigningAlgorithm,
>;

/// What a token is validated against.
pub(crate) enum IdTokenReference<'a> {
    /// A sign-in callback: the token must carry the flow's nonce.
    SignIn { nonce: &'a str },
    /// A renewal: the token must repeat the stored `sub`, exact `aud`,
    /// `azp` (present exactly when it was), and `auth_time` if present; its
    /// `nonce` is absent or the sign-in's; and its Broker subject is the
    /// login method's.
    Renewal {
        reference: &'a OidcRenewalReference,
        external_subject: &'a str,
    },
}

/// Why a token was not accepted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum IdTokenRejection {
    /// The token fails a check.
    Invalid,
    /// Its key ID is unknown and the signing keys could not be refreshed.
    KeysUnavailable,
    /// Renewal only: an otherwise valid token whose `sub` or Broker subject
    /// differs from the stored identity.
    IdentityMismatch,
}

/// An accepted ID token.
pub(crate) struct ValidatedIdToken {
    pub(crate) claims: MicrosoftOidcIdTokenClaims,
    pub(crate) identity: ValidatedMicrosoftOidcIdentity,
    /// The `aud` claim exactly as issued, when it is a nonempty string or a
    /// nonempty array of nonempty strings; the parsed claims normalize it.
    pub(crate) audience: Option<Value>,
    /// The raw `iat`: Microsoft's own clock, which orders observations.
    pub(crate) issued_at: i64,
}

/// Validates `raw_id_token` against `metadata` (refreshing its keys once
/// for an unknown key ID) and `reference`.
pub(crate) async fn validate_microsoft_id_token(
    provider: &MicrosoftOidcProviderRuntime,
    metadata: MicrosoftOidcProviderMetadata,
    raw_id_token: &str,
    access_token: Option<&AccessToken>,
    reference: IdTokenReference<'_>,
) -> Result<ValidatedIdToken, IdTokenRejection> {
    if raw_id_token.len() > MICROSOFT_OIDC_MAX_ID_TOKEN_BYTES
        || validate_microsoft_id_token_payload_syntax(raw_id_token).is_err()
    {
        return Err(IdTokenRejection::Invalid);
    }
    let audience = microsoft_id_token_audience_claim(raw_id_token).ok();
    let (kid, algorithm) = token_header(raw_id_token).ok_or(IdTokenRejection::Invalid)?;
    if algorithm != "RS256" {
        return Err(IdTokenRejection::Invalid);
    }
    let metadata = if metadata_has_kid(&metadata, &kid) {
        metadata
    } else {
        match provider.refresh_unknown_key(&metadata).await {
            Ok(refreshed) if metadata_has_kid(&refreshed, &kid) => refreshed,
            Ok(_) => return Err(IdTokenRejection::Invalid),
            Err(_) => return Err(IdTokenRejection::KeysUnavailable),
        }
    };
    let id_token: MicrosoftIdToken =
        serde_json::from_value(Value::String(raw_id_token.to_string()))
            .map_err(|_| IdTokenRejection::Invalid)?;
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
    let claims = match &reference {
        IdTokenReference::SignIn { nonce } => {
            id_token.claims(&verifier, &Nonce::new(nonce.to_string()))
        }
        IdTokenReference::Renewal { reference, .. } => {
            id_token.claims(&verifier, |nonce: Option<&Nonce>| {
                if renewal_nonce_matches(reference, nonce.map(|nonce| nonce.secret().as_str())) {
                    Ok(())
                } else {
                    Err("nonce mismatch".to_string())
                }
            })
        }
    }
    .map_err(|_| IdTokenRejection::Invalid)?;
    if let Some(expected_hash) = claims.access_token_hash() {
        let actual_hash = (|| {
            let access_token = access_token?;
            let algorithm = id_token.signing_alg().ok()?;
            let key = id_token.signing_key(&verifier).ok()?;
            AccessTokenHash::from_token(access_token, algorithm, key).ok()
        })();
        if actual_hash.as_ref() != Some(expected_hash) {
            return Err(IdTokenRejection::Invalid);
        }
    }
    let identity = validate_microsoft_oidc_identity(
        claims,
        provider.config().tenant_id(),
        provider.config().client_id(),
        provider.clock(),
    )
    .map_err(|_| IdTokenRejection::Invalid)?;
    if let IdTokenReference::Renewal {
        reference,
        external_subject,
    } = reference
    {
        let issued_audience = audience.as_ref().ok_or(IdTokenRejection::Invalid)?;
        compare_renewal_reference(
            reference,
            &RenewalObservation {
                subject: claims.subject().as_str(),
                audience: issued_audience,
                authorized_party: claims.authorized_party().map(|value| value.as_str()),
                auth_time: claims.auth_time().map(|auth_time| auth_time.timestamp()),
                external_subject: &identity.external_subject,
            },
            external_subject,
        )
        .map_err(|mismatch| match mismatch {
            RenewalReferenceMismatch::Claims => IdTokenRejection::Invalid,
            RenewalReferenceMismatch::Identity => IdTokenRejection::IdentityMismatch,
        })?;
    }
    Ok(ValidatedIdToken {
        issued_at: claims.issue_time().timestamp(),
        claims: claims.clone(),
        identity,
        audience,
    })
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
