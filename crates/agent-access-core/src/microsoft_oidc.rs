use base64::Engine;
use chrono::{DateTime, Duration as ChronoDuration, Utc};
use futures_util::StreamExt;
use hmac::{Hmac, Mac};
use openidconnect::core::{
    CoreGenderClaim, CoreJsonWebKeySet, CoreJwsSigningAlgorithm, CoreProviderMetadata,
    CoreResponseType,
};
use openidconnect::{
    AdditionalClaims, AsyncHttpClient, HttpRequest, HttpResponse, IdTokenClaims, IssuerUrl,
    JsonWebKey, RedirectUrl,
};
use serde::de::{IgnoredAny, MapAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::Value;
use sha2::Sha256;
use std::collections::BTreeSet;
use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;
use thiserror::Error;
use url::Url;
use uuid::Uuid;

use crate::load_secret_ref_value;
use crate::{MicrosoftOidcConfig, parse_ttl_seconds};
use agent_access_provider::is_loopback_or_localhost;

pub const MICROSOFT_OIDC_PROVIDER_ID: &str = "microsoft";
pub const MICROSOFT_OIDC_HOST: &str = "login.microsoftonline.com";
pub const MICROSOFT_OIDC_CALLBACK_PATH: &str = "/v1/auth/oidc/microsoft/callback";
pub const MICROSOFT_OIDC_SCOPES: [&str; 3] = ["openid", "profile", "email"];
pub const MICROSOFT_OIDC_CLOCK_SKEW_SECONDS: i64 = 120;
pub const MICROSOFT_OIDC_MAX_GROUPS: usize = 200;
pub const MICROSOFT_OIDC_MAX_ID_TOKEN_BYTES: usize = 32 * 1024;
pub const MICROSOFT_OIDC_MAX_PAYLOAD_BYTES: usize = 24 * 1024;
pub const MICROSOFT_OIDC_MAX_TOP_LEVEL_CLAIMS: usize = 128;
pub const MICROSOFT_OIDC_MAX_CLAIM_NAME_BYTES: usize = 128;
pub const MICROSOFT_OIDC_MAX_SUBJECT_BYTES: usize = 1024;
pub const MICROSOFT_OIDC_MAX_DISCOVERY_KEYS: usize = 64;
pub const MICROSOFT_OIDC_MAX_HTTP_REQUEST_BYTES: usize = 32 * 1024;
pub const MICROSOFT_OIDC_MAX_HTTP_RESPONSE_BYTES: usize = 256 * 1024;

#[derive(Debug, Clone, Error, PartialEq, Eq)]
pub enum MicrosoftOidcValidationError {
    #[error("Microsoft OIDC UUID is not canonical")]
    NonCanonicalUuid,
    #[error("Microsoft OIDC URL is invalid")]
    InvalidUrl,
    #[error("Microsoft OIDC provider metadata is invalid")]
    InvalidProviderMetadata,
    #[error("Microsoft OIDC ID token is malformed")]
    MalformedIdToken,
    #[error("Microsoft OIDC ID token payload is too large")]
    IdTokenPayloadTooLarge,
    #[error("Microsoft OIDC ID token contains a duplicate top-level claim")]
    DuplicateTopLevelClaim,
    #[error("Microsoft OIDC identity claims are invalid")]
    InvalidIdentityClaims,
}

#[derive(Debug, Clone, Error, PartialEq, Eq)]
pub enum MicrosoftOidcSecretError {
    #[error("Microsoft OIDC secret material is unavailable")]
    Unavailable,
    #[error("Microsoft OIDC client secret is empty")]
    EmptyClientSecret,
    #[error("Microsoft OIDC flow key is invalid")]
    InvalidFlowKey,
}

#[derive(Debug, Error)]
pub enum MicrosoftOidcRuntimeConfigError {
    #[error("Microsoft OIDC runtime configuration is incomplete")]
    Incomplete,
    #[error(transparent)]
    Secret(#[from] MicrosoftOidcSecretError),
    #[error(transparent)]
    Validation(#[from] MicrosoftOidcValidationError),
}

#[derive(Clone)]
pub struct ResolvedMicrosoftOidcSecrets {
    client_secret: String,
    flow_key: [u8; 32],
}

impl fmt::Debug for ResolvedMicrosoftOidcSecrets {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ResolvedMicrosoftOidcSecrets")
            .field("client_secret", &"[REDACTED]")
            .field("flow_key", &"[REDACTED]")
            .finish()
    }
}

impl ResolvedMicrosoftOidcSecrets {
    pub fn client_secret(&self) -> &str {
        &self.client_secret
    }

    pub fn flow_key(&self) -> &[u8; 32] {
        &self.flow_key
    }
}

#[derive(Clone)]
pub struct MicrosoftOidcRuntimeConfig {
    tenant_id: String,
    client_id: String,
    issuer_url: IssuerUrl,
    discovery_url: Url,
    redirect_url: RedirectUrl,
    flow_ttl_seconds: u64,
    max_pending_flows: u32,
    jit_provisioning: bool,
    external_membership_ttl_seconds: u64,
    secrets: ResolvedMicrosoftOidcSecrets,
    config_fingerprint: String,
}

impl fmt::Debug for MicrosoftOidcRuntimeConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MicrosoftOidcRuntimeConfig")
            .field("tenant_id", &self.tenant_id)
            .field("client_id", &self.client_id)
            .field("issuer_url", &self.issuer_url)
            .field("discovery_url", &self.discovery_url)
            .field("redirect_url", &self.redirect_url)
            .field("flow_ttl_seconds", &self.flow_ttl_seconds)
            .field("max_pending_flows", &self.max_pending_flows)
            .field("jit_provisioning", &self.jit_provisioning)
            .field(
                "external_membership_ttl_seconds",
                &self.external_membership_ttl_seconds,
            )
            .field("secrets", &self.secrets)
            .field("config_fingerprint", &self.config_fingerprint)
            .finish()
    }
}

impl MicrosoftOidcRuntimeConfig {
    pub fn from_config(
        config: &MicrosoftOidcConfig,
        public_origin: Option<&str>,
    ) -> Result<Option<Self>, MicrosoftOidcRuntimeConfigError> {
        let Some(secrets) = resolve_microsoft_oidc_secrets(config)? else {
            return Ok(None);
        };
        let tenant_id = config
            .tenant_id
            .as_deref()
            .ok_or(MicrosoftOidcRuntimeConfigError::Incomplete)?;
        let client_id = config
            .client_id
            .as_deref()
            .ok_or(MicrosoftOidcRuntimeConfigError::Incomplete)?;
        let public_origin = public_origin.ok_or(MicrosoftOidcRuntimeConfigError::Incomplete)?;
        let flow_ttl_seconds = parse_ttl_seconds(&config.flow_ttl)
            .ok_or(MicrosoftOidcRuntimeConfigError::Incomplete)?;
        let external_membership_ttl_seconds = parse_ttl_seconds(&config.external_membership_ttl)
            .ok_or(MicrosoftOidcRuntimeConfigError::Incomplete)?;
        let tenant_id = canonical_microsoft_uuid(tenant_id)?;
        let client_id = canonical_microsoft_uuid(client_id)?;
        let issuer_url = microsoft_oidc_issuer_url(&tenant_id)?;
        let discovery_url = Url::parse(&format!(
            "{}/.well-known/openid-configuration",
            issuer_url.as_str().trim_end_matches('/')
        ))
        .map_err(|_| MicrosoftOidcValidationError::InvalidUrl)?;
        let redirect_url = microsoft_oidc_redirect_url(public_origin)?;
        let config_fingerprint = microsoft_oidc_config_fingerprint(
            &tenant_id,
            &client_id,
            issuer_url.as_str(),
            discovery_url.as_str(),
            redirect_url.as_str(),
            flow_ttl_seconds,
            config.max_pending_flows,
            config.jit_provisioning,
            external_membership_ttl_seconds,
            &secrets,
        );
        Ok(Some(Self {
            tenant_id,
            client_id,
            issuer_url,
            discovery_url,
            redirect_url,
            flow_ttl_seconds,
            max_pending_flows: config.max_pending_flows,
            jit_provisioning: config.jit_provisioning,
            external_membership_ttl_seconds,
            secrets,
            config_fingerprint,
        }))
    }

    pub fn tenant_id(&self) -> &str {
        &self.tenant_id
    }

    pub fn client_id(&self) -> &str {
        &self.client_id
    }

    pub fn issuer_url(&self) -> &IssuerUrl {
        &self.issuer_url
    }

    pub fn discovery_url(&self) -> &Url {
        &self.discovery_url
    }

    pub fn redirect_url(&self) -> &RedirectUrl {
        &self.redirect_url
    }

    pub fn flow_ttl_seconds(&self) -> u64 {
        self.flow_ttl_seconds
    }

    pub fn max_pending_flows(&self) -> u32 {
        self.max_pending_flows
    }

    pub fn jit_provisioning(&self) -> bool {
        self.jit_provisioning
    }

    pub fn external_membership_ttl_seconds(&self) -> u64 {
        self.external_membership_ttl_seconds
    }

    pub fn secrets(&self) -> &ResolvedMicrosoftOidcSecrets {
        &self.secrets
    }

    pub fn config_fingerprint(&self) -> &str {
        &self.config_fingerprint
    }
}

#[allow(clippy::too_many_arguments)]
fn microsoft_oidc_config_fingerprint(
    tenant_id: &str,
    client_id: &str,
    issuer_url: &str,
    discovery_url: &str,
    redirect_url: &str,
    flow_ttl_seconds: u64,
    max_pending_flows: u32,
    jit_provisioning: bool,
    external_membership_ttl_seconds: u64,
    secrets: &ResolvedMicrosoftOidcSecrets,
) -> String {
    let mut mac = Hmac::<Sha256>::new_from_slice(secrets.flow_key())
        .expect("HMAC-SHA256 accepts a 32-byte Microsoft OIDC flow key");
    for value in [
        b"aab-microsoft-oidc-config-fingerprint-v1".as_slice(),
        tenant_id.as_bytes(),
        client_id.as_bytes(),
        issuer_url.as_bytes(),
        discovery_url.as_bytes(),
        redirect_url.as_bytes(),
        secrets.client_secret().as_bytes(),
    ] {
        mac.update(&(value.len() as u64).to_be_bytes());
        mac.update(value);
    }
    mac.update(&flow_ttl_seconds.to_be_bytes());
    mac.update(&max_pending_flows.to_be_bytes());
    mac.update(&[u8::from(jit_provisioning)]);
    mac.update(&external_membership_ttl_seconds.to_be_bytes());
    let digest = mac.finalize().into_bytes();
    let encoded = digest
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    format!("hmac-sha256:{encoded}")
}

pub fn resolve_microsoft_oidc_secrets(
    config: &MicrosoftOidcConfig,
) -> Result<Option<ResolvedMicrosoftOidcSecrets>, MicrosoftOidcSecretError> {
    if !config.enabled {
        return Ok(None);
    }
    let client_secret_ref = config
        .client_secret_ref
        .as_deref()
        .ok_or(MicrosoftOidcSecretError::Unavailable)?;
    let flow_key_ref = config
        .flow_key_ref
        .as_deref()
        .ok_or(MicrosoftOidcSecretError::Unavailable)?;
    let client_secret = load_secret_ref_value(
        "browser_auth.oidc.microsoft.client_secret_ref",
        client_secret_ref,
    )
    .map_err(|_| MicrosoftOidcSecretError::Unavailable)?;
    if client_secret.is_empty() {
        return Err(MicrosoftOidcSecretError::EmptyClientSecret);
    }
    let encoded_flow_key =
        load_secret_ref_value("browser_auth.oidc.microsoft.flow_key_ref", flow_key_ref)
            .map_err(|_| MicrosoftOidcSecretError::Unavailable)?;
    let decoded_flow_key = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(encoded_flow_key)
        .map_err(|_| MicrosoftOidcSecretError::InvalidFlowKey)?;
    let flow_key = decoded_flow_key
        .try_into()
        .map_err(|_| MicrosoftOidcSecretError::InvalidFlowKey)?;
    Ok(Some(ResolvedMicrosoftOidcSecrets {
        client_secret,
        flow_key,
    }))
}

pub fn canonical_microsoft_uuid(value: &str) -> Result<String, MicrosoftOidcValidationError> {
    let parsed =
        Uuid::parse_str(value).map_err(|_| MicrosoftOidcValidationError::NonCanonicalUuid)?;
    let canonical = parsed.hyphenated().to_string();
    if value != canonical {
        return Err(MicrosoftOidcValidationError::NonCanonicalUuid);
    }
    Ok(canonical)
}

pub fn microsoft_oidc_issuer_url(
    tenant_id: &str,
) -> Result<IssuerUrl, MicrosoftOidcValidationError> {
    let tenant_id = canonical_microsoft_uuid(tenant_id)?;
    IssuerUrl::new(format!("https://{MICROSOFT_OIDC_HOST}/{tenant_id}/v2.0"))
        .map_err(|_| MicrosoftOidcValidationError::InvalidUrl)
}

pub fn microsoft_oidc_redirect_url(
    public_origin: &str,
) -> Result<RedirectUrl, MicrosoftOidcValidationError> {
    let origin = Url::parse(public_origin).map_err(|_| MicrosoftOidcValidationError::InvalidUrl)?;
    let loopback_http = origin.scheme() == "http" && is_loopback_or_localhost(origin.host());
    if (origin.scheme() != "https" && !loopback_http)
        || origin.cannot_be_a_base()
        || origin.username() != ""
        || origin.password().is_some()
        || origin.query().is_some()
        || origin.fragment().is_some()
        || origin.path() != "/"
    {
        return Err(MicrosoftOidcValidationError::InvalidUrl);
    }
    let redirect = origin
        .join(MICROSOFT_OIDC_CALLBACK_PATH)
        .map_err(|_| MicrosoftOidcValidationError::InvalidUrl)?;
    Ok(RedirectUrl::from_url(redirect))
}

pub fn canonical_microsoft_external_subject(
    tenant_id: &str,
    user_object_id: &str,
) -> Result<String, MicrosoftOidcValidationError> {
    Ok(format!(
        "entra:v1:{}:{}",
        canonical_microsoft_uuid(tenant_id)?,
        canonical_microsoft_uuid(user_object_id)?
    ))
}

pub trait MicrosoftOidcClock: Send + Sync {
    fn now(&self) -> DateTime<Utc>;
}

#[derive(Debug, Clone, Copy, Default)]
pub struct SystemMicrosoftOidcClock;

impl MicrosoftOidcClock for SystemMicrosoftOidcClock {
    fn now(&self) -> DateTime<Utc> {
        Utc::now()
    }
}

#[derive(Debug, Clone, Default, PartialEq)]
enum ClaimPresence<T> {
    #[default]
    Missing,
    Present(T),
}

impl<T> ClaimPresence<T> {
    fn is_missing(&self) -> bool {
        matches!(self, Self::Missing)
    }
}

impl<'de, T> Deserialize<'de> for ClaimPresence<T>
where
    T: Deserialize<'de>,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        T::deserialize(deserializer).map(Self::Present)
    }
}

impl<T> Serialize for ClaimPresence<T>
where
    T: Serialize,
{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            Self::Missing => serializer.serialize_unit(),
            Self::Present(value) => value.serialize(serializer),
        }
    }
}

#[derive(Debug, Clone, Default, Deserialize, PartialEq, Serialize)]
pub struct MicrosoftOidcAdditionalClaims {
    tid: String,
    oid: String,
    #[serde(default)]
    nbf: Option<i64>,
    #[serde(default, skip_serializing_if = "ClaimPresence::is_missing")]
    groups: ClaimPresence<Value>,
    #[serde(default, skip_serializing_if = "ClaimPresence::is_missing")]
    hasgroups: ClaimPresence<Value>,
    #[serde(
        default,
        rename = "_claim_names",
        skip_serializing_if = "ClaimPresence::is_missing"
    )]
    claim_names: ClaimPresence<Value>,
}

impl AdditionalClaims for MicrosoftOidcAdditionalClaims {}

impl MicrosoftOidcAdditionalClaims {
    pub fn tenant_id(&self) -> &str {
        &self.tid
    }

    pub fn user_object_id(&self) -> &str {
        &self.oid
    }

    pub fn not_before(&self) -> Option<i64> {
        self.nbf
    }

    pub fn classify_groups(&self) -> MicrosoftGroupClaimClassification {
        classify_microsoft_groups(&self.groups, &self.hasgroups, &self.claim_names)
    }
}

pub type MicrosoftOidcIdTokenClaims = IdTokenClaims<MicrosoftOidcAdditionalClaims, CoreGenderClaim>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatedMicrosoftOidcIdentity {
    pub tenant_id: String,
    pub user_object_id: String,
    pub external_subject: String,
    pub issued_at: DateTime<Utc>,
}

pub fn validate_microsoft_oidc_identity(
    claims: &MicrosoftOidcIdTokenClaims,
    expected_tenant_id: &str,
    expected_client_id: &str,
    clock: &dyn MicrosoftOidcClock,
) -> Result<ValidatedMicrosoftOidcIdentity, MicrosoftOidcValidationError> {
    let expected_tenant_id = canonical_microsoft_uuid(expected_tenant_id)?;
    let expected_client_id = canonical_microsoft_uuid(expected_client_id)?;
    let additional = claims.additional_claims();
    let tenant_id = canonical_microsoft_uuid(additional.tenant_id())?;
    let user_object_id = canonical_microsoft_uuid(additional.user_object_id())?;
    if tenant_id != expected_tenant_id
        || claims.subject().as_str().is_empty()
        || claims.subject().as_str().len() > MICROSOFT_OIDC_MAX_SUBJECT_BYTES
    {
        return Err(MicrosoftOidcValidationError::InvalidIdentityClaims);
    }

    let client_is_audience = claims
        .audiences()
        .iter()
        .any(|audience| audience.as_str() == expected_client_id);
    if !client_is_audience {
        return Err(MicrosoftOidcValidationError::InvalidIdentityClaims);
    }
    let authorized_party = claims.authorized_party().map(|value| value.as_str());
    if authorized_party.is_some_and(|value| value != expected_client_id)
        || (claims.audiences().len() > 1 && authorized_party != Some(expected_client_id.as_str()))
    {
        return Err(MicrosoftOidcValidationError::InvalidIdentityClaims);
    }

    let now = clock.now();
    let skew = ChronoDuration::seconds(MICROSOFT_OIDC_CLOCK_SKEW_SECONDS);
    if claims.expiration() <= now - skew || claims.issue_time() > now + skew {
        return Err(MicrosoftOidcValidationError::InvalidIdentityClaims);
    }
    if let Some(not_before) = additional.not_before() {
        let not_before = DateTime::<Utc>::from_timestamp(not_before, 0)
            .ok_or(MicrosoftOidcValidationError::InvalidIdentityClaims)?;
        if not_before > now + skew {
            return Err(MicrosoftOidcValidationError::InvalidIdentityClaims);
        }
    }

    Ok(ValidatedMicrosoftOidcIdentity {
        external_subject: canonical_microsoft_external_subject(&tenant_id, &user_object_id)?,
        tenant_id,
        user_object_id,
        issued_at: claims.issue_time(),
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MicrosoftMalformedGroupClaims {
    ConflictingMarkers,
    InvalidGroups,
    TooManyGroups,
    InvalidGroupId,
    InvalidHasGroups,
    InvalidDistributedClaimMarker,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MicrosoftGroupClaimClassification {
    Complete(BTreeSet<String>),
    Overage,
    Malformed(MicrosoftMalformedGroupClaims),
}

fn classify_microsoft_groups(
    groups: &ClaimPresence<Value>,
    hasgroups: &ClaimPresence<Value>,
    claim_names: &ClaimPresence<Value>,
) -> MicrosoftGroupClaimClassification {
    let hasgroups_overage = match hasgroups {
        ClaimPresence::Missing => false,
        ClaimPresence::Present(Value::Bool(true)) => true,
        ClaimPresence::Present(_) => {
            return MicrosoftGroupClaimClassification::Malformed(
                MicrosoftMalformedGroupClaims::InvalidHasGroups,
            );
        }
    };
    let distributed_overage = match claim_names {
        ClaimPresence::Missing => false,
        ClaimPresence::Present(Value::Object(names)) => match names.get("groups") {
            None => false,
            Some(Value::String(source)) if !source.is_empty() => true,
            Some(_) => {
                return MicrosoftGroupClaimClassification::Malformed(
                    MicrosoftMalformedGroupClaims::InvalidDistributedClaimMarker,
                );
            }
        },
        ClaimPresence::Present(_) => {
            return MicrosoftGroupClaimClassification::Malformed(
                MicrosoftMalformedGroupClaims::InvalidDistributedClaimMarker,
            );
        }
    };
    let overage = hasgroups_overage || distributed_overage;

    match groups {
        ClaimPresence::Missing if overage => MicrosoftGroupClaimClassification::Overage,
        ClaimPresence::Missing => MicrosoftGroupClaimClassification::Complete(BTreeSet::new()),
        ClaimPresence::Present(_) if overage => MicrosoftGroupClaimClassification::Malformed(
            MicrosoftMalformedGroupClaims::ConflictingMarkers,
        ),
        ClaimPresence::Present(Value::Array(values)) => {
            if values.len() > MICROSOFT_OIDC_MAX_GROUPS {
                return MicrosoftGroupClaimClassification::Malformed(
                    MicrosoftMalformedGroupClaims::TooManyGroups,
                );
            }
            let mut canonical = BTreeSet::new();
            for value in values {
                let Value::String(group_id) = value else {
                    return MicrosoftGroupClaimClassification::Malformed(
                        MicrosoftMalformedGroupClaims::InvalidGroups,
                    );
                };
                let Ok(group_id) = canonical_microsoft_uuid(group_id) else {
                    return MicrosoftGroupClaimClassification::Malformed(
                        MicrosoftMalformedGroupClaims::InvalidGroupId,
                    );
                };
                canonical.insert(group_id);
            }
            MicrosoftGroupClaimClassification::Complete(canonical)
        }
        ClaimPresence::Present(_) => MicrosoftGroupClaimClassification::Malformed(
            MicrosoftMalformedGroupClaims::InvalidGroups,
        ),
    }
}

pub fn validate_microsoft_id_token_payload_syntax(
    id_token: &str,
) -> Result<(), MicrosoftOidcValidationError> {
    if id_token.len() > MICROSOFT_OIDC_MAX_ID_TOKEN_BYTES {
        return Err(MicrosoftOidcValidationError::IdTokenPayloadTooLarge);
    }
    let mut segments = id_token.split('.');
    let _header = segments.next();
    let payload = segments
        .next()
        .ok_or(MicrosoftOidcValidationError::MalformedIdToken)?;
    if segments.next().is_none() || segments.next().is_some() {
        return Err(MicrosoftOidcValidationError::MalformedIdToken);
    }
    let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload)
        .map_err(|_| MicrosoftOidcValidationError::MalformedIdToken)?;
    if decoded.len() > MICROSOFT_OIDC_MAX_PAYLOAD_BYTES {
        return Err(MicrosoftOidcValidationError::IdTokenPayloadTooLarge);
    }

    let mut deserializer = serde_json::Deserializer::from_slice(&decoded);
    deserializer
        .deserialize_any(TopLevelClaimVisitor)
        .map_err(|error| {
            if error.to_string().contains("duplicate top-level claim") {
                MicrosoftOidcValidationError::DuplicateTopLevelClaim
            } else {
                MicrosoftOidcValidationError::MalformedIdToken
            }
        })?;
    deserializer
        .end()
        .map_err(|_| MicrosoftOidcValidationError::MalformedIdToken)
}

struct TopLevelClaimVisitor;

impl<'de> Visitor<'de> for TopLevelClaimVisitor {
    type Value = ();

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a bounded JSON object")
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut names = BTreeSet::new();
        while let Some(name) = map.next_key::<String>()? {
            if names.len() >= MICROSOFT_OIDC_MAX_TOP_LEVEL_CLAIMS
                || name.len() > MICROSOFT_OIDC_MAX_CLAIM_NAME_BYTES
            {
                return Err(serde::de::Error::custom("top-level claims exceed bounds"));
            }
            if !names.insert(name) {
                return Err(serde::de::Error::custom("duplicate top-level claim"));
            }
            map.next_value::<IgnoredAny>()?;
        }
        Ok(())
    }
}

#[derive(Debug, Error)]
pub enum MicrosoftOidcHttpError {
    #[error("Microsoft OIDC HTTP client configuration failed")]
    ClientConfiguration(#[source] reqwest::Error),
    #[error("Microsoft OIDC HTTP request was rejected")]
    RequestRejected,
    #[error("Microsoft OIDC HTTP request failed")]
    Request(#[source] reqwest::Error),
    #[error("Microsoft OIDC HTTP response exceeded its size limit")]
    ResponseTooLarge,
    #[error("Microsoft OIDC HTTP response was invalid")]
    InvalidResponse(#[source] http::Error),
}

#[derive(Clone)]
pub struct MicrosoftOidcHttpClient {
    client: reqwest::Client,
    allowed_host: Arc<str>,
    max_request_bytes: usize,
    max_response_bytes: usize,
}

impl fmt::Debug for MicrosoftOidcHttpClient {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MicrosoftOidcHttpClient")
            .field("allowed_host", &self.allowed_host)
            .field("max_request_bytes", &self.max_request_bytes)
            .field("max_response_bytes", &self.max_response_bytes)
            .finish_non_exhaustive()
    }
}

impl MicrosoftOidcHttpClient {
    pub fn new(outbound_tls: &crate::PreparedOutboundTls) -> Result<Self, MicrosoftOidcHttpError> {
        let client = outbound_tls
            .apply(reqwest::Client::builder())
            .https_only(true)
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(Duration::from_secs(3))
            .timeout(Duration::from_secs(10))
            .no_proxy()
            .build()
            .map_err(MicrosoftOidcHttpError::ClientConfiguration)?;
        Ok(Self {
            client,
            allowed_host: Arc::from(MICROSOFT_OIDC_HOST),
            max_request_bytes: MICROSOFT_OIDC_MAX_HTTP_REQUEST_BYTES,
            max_response_bytes: MICROSOFT_OIDC_MAX_HTTP_RESPONSE_BYTES,
        })
    }

    fn validate_request(&self, request: &HttpRequest) -> Result<(), MicrosoftOidcHttpError> {
        let uri = Url::parse(&request.uri().to_string())
            .map_err(|_| MicrosoftOidcHttpError::RequestRejected)?;
        if uri.scheme() != "https"
            || uri.host_str() != Some(self.allowed_host.as_ref())
            || uri.username() != ""
            || uri.password().is_some()
            || uri.port().is_some()
            || uri.fragment().is_some()
            || request.body().len() > self.max_request_bytes
        {
            return Err(MicrosoftOidcHttpError::RequestRejected);
        }
        Ok(())
    }
}

impl<'c> AsyncHttpClient<'c> for MicrosoftOidcHttpClient {
    type Error = MicrosoftOidcHttpError;
    type Future =
        Pin<Box<dyn Future<Output = Result<HttpResponse, Self::Error>> + Send + Sync + 'c>>;

    fn call(&'c self, request: HttpRequest) -> Self::Future {
        Box::pin(async move {
            self.validate_request(&request)?;
            let response = self
                .client
                .execute(
                    request
                        .try_into()
                        .map_err(|_| MicrosoftOidcHttpError::RequestRejected)?,
                )
                .await
                .map_err(MicrosoftOidcHttpError::Request)?;
            if response
                .content_length()
                .is_some_and(|length| length > self.max_response_bytes as u64)
            {
                return Err(MicrosoftOidcHttpError::ResponseTooLarge);
            }
            let status = response.status();
            let version = response.version();
            let headers = response.headers().clone();
            let mut body = Vec::new();
            let mut chunks = response.bytes_stream();
            while let Some(chunk) = chunks.next().await {
                let chunk = chunk.map_err(MicrosoftOidcHttpError::Request)?;
                if body.len().saturating_add(chunk.len()) > self.max_response_bytes {
                    return Err(MicrosoftOidcHttpError::ResponseTooLarge);
                }
                body.extend_from_slice(&chunk);
            }
            let mut builder = http::Response::builder().status(status).version(version);
            for (name, value) in &headers {
                builder = builder.header(name, value);
            }
            builder
                .body(body)
                .map_err(MicrosoftOidcHttpError::InvalidResponse)
        })
    }
}

#[derive(Clone)]
pub struct MicrosoftOidcProviderMetadata {
    metadata: CoreProviderMetadata,
    loaded_at: DateTime<Utc>,
}

impl fmt::Debug for MicrosoftOidcProviderMetadata {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MicrosoftOidcProviderMetadata")
            .field("issuer", self.metadata.issuer())
            .field("loaded_at", &self.loaded_at)
            .field("key_count", &self.metadata.jwks().keys().len())
            .finish()
    }
}

impl MicrosoftOidcProviderMetadata {
    pub async fn discover<'c, C>(
        tenant_id: &str,
        http_client: &'c C,
        loaded_at: DateTime<Utc>,
    ) -> Result<Self, MicrosoftOidcValidationError>
    where
        C: AsyncHttpClient<'c>,
    {
        let issuer = microsoft_oidc_issuer_url(tenant_id)?;
        let metadata = CoreProviderMetadata::discover_async(issuer.clone(), http_client)
            .await
            .map_err(|_| MicrosoftOidcValidationError::InvalidProviderMetadata)?;
        Self::from_discovered(issuer, metadata, loaded_at)
    }

    pub fn from_discovered(
        expected_issuer: IssuerUrl,
        metadata: CoreProviderMetadata,
        loaded_at: DateTime<Utc>,
    ) -> Result<Self, MicrosoftOidcValidationError> {
        if metadata.issuer() != &expected_issuer
            || !valid_microsoft_metadata_url(metadata.authorization_endpoint().url())
            || !valid_microsoft_metadata_url(metadata.jwks_uri().url())
            || metadata
                .token_endpoint()
                .is_none_or(|endpoint| !valid_microsoft_metadata_url(endpoint.url()))
            || !metadata
                .response_types_supported()
                .iter()
                .any(|response| response.as_slice() == [CoreResponseType::Code])
            || !metadata
                .id_token_signing_alg_values_supported()
                .contains(&CoreJwsSigningAlgorithm::RsaSsaPkcs1V15Sha256)
        {
            return Err(MicrosoftOidcValidationError::InvalidProviderMetadata);
        }
        validate_microsoft_jwks(metadata.jwks())?;
        Ok(Self {
            metadata,
            loaded_at,
        })
    }

    pub fn metadata(&self) -> &CoreProviderMetadata {
        &self.metadata
    }

    pub fn jwks(&self) -> &CoreJsonWebKeySet {
        self.metadata.jwks()
    }

    pub fn loaded_at(&self) -> DateTime<Utc> {
        self.loaded_at
    }

    pub fn with_refreshed_jwks(
        &self,
        jwks: CoreJsonWebKeySet,
        loaded_at: DateTime<Utc>,
    ) -> Result<Self, MicrosoftOidcValidationError> {
        validate_microsoft_jwks(&jwks)?;
        Ok(Self {
            metadata: self.metadata.clone().set_jwks(jwks),
            loaded_at,
        })
    }
}

fn valid_microsoft_metadata_url(url: &Url) -> bool {
    url.scheme() == "https"
        && url.host_str() == Some(MICROSOFT_OIDC_HOST)
        && url.username().is_empty()
        && url.password().is_none()
        && url.port().is_none()
        && url.query().is_none()
        && url.fragment().is_none()
        && url.as_str().len() <= 2048
}

fn validate_microsoft_jwks(jwks: &CoreJsonWebKeySet) -> Result<(), MicrosoftOidcValidationError> {
    if jwks.keys().is_empty() || jwks.keys().len() > MICROSOFT_OIDC_MAX_DISCOVERY_KEYS {
        return Err(MicrosoftOidcValidationError::InvalidProviderMetadata);
    }
    let mut key_ids = BTreeSet::new();
    for key in jwks.keys() {
        let Some(key_id) = key.key_id() else {
            return Err(MicrosoftOidcValidationError::InvalidProviderMetadata);
        };
        if key_id.as_str().is_empty() || !key_ids.insert(key_id.as_str()) {
            return Err(MicrosoftOidcValidationError::InvalidProviderMetadata);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use chrono::TimeZone;
    use serde_json::json;
    use std::fs;

    fn additional_claims(value: Value) -> MicrosoftOidcAdditionalClaims {
        serde_json::from_value(value).unwrap()
    }

    fn token_with_payload(payload: &str) -> String {
        format!("e30.{}.c2ln", URL_SAFE_NO_PAD.encode(payload))
    }

    #[test]
    fn canonical_subject_uses_only_lowercase_hyphenated_ids() {
        let tenant = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa1";
        let user = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbb2";
        assert_eq!(
            canonical_microsoft_external_subject(tenant, user).unwrap(),
            format!("entra:v1:{tenant}:{user}")
        );
        assert!(canonical_microsoft_uuid(&tenant.to_uppercase()).is_err());
        assert!(canonical_microsoft_uuid("00000000000040008000000000000001").is_err());
    }

    #[test]
    fn issuer_and_redirect_are_fixed_and_local() {
        let tenant = "00000000-0000-4000-8000-000000000001";
        assert_eq!(
            microsoft_oidc_issuer_url(tenant).unwrap().as_str(),
            format!("https://login.microsoftonline.com/{tenant}/v2.0")
        );
        assert_eq!(
            microsoft_oidc_redirect_url("https://broker.example.test")
                .unwrap()
                .as_str(),
            "https://broker.example.test/v1/auth/oidc/microsoft/callback"
        );
        for host in ["localhost", "127.0.0.1", "[::1]"] {
            let origin = format!("http://{host}:8080");
            assert_eq!(
                microsoft_oidc_redirect_url(&origin).unwrap().as_str(),
                format!("{origin}/v1/auth/oidc/microsoft/callback")
            );
        }
        assert!(microsoft_oidc_redirect_url("https://broker.example.test/base").is_err());
        for host in [
            "127.0.0.2",
            "[::2]",
            "[::ffff:127.0.0.1]",
            "broker.example.test",
        ] {
            assert!(
                microsoft_oidc_redirect_url(&format!("http://{host}:8080")).is_err(),
                "{host}"
            );
        }
    }

    #[test]
    fn runtime_config_accepts_ipv6_loopback_redirect_and_rejects_non_loopback() {
        let directory = tempfile::tempdir().unwrap();
        let client_secret_path = directory.path().join("client-secret");
        let flow_key_path = directory.path().join("flow-key");
        fs::write(&client_secret_path, "oidc-loopback-test-client-secret").unwrap();
        fs::write(&flow_key_path, URL_SAFE_NO_PAD.encode([17_u8; 32])).unwrap();
        let config = MicrosoftOidcConfig {
            enabled: true,
            tenant_id: Some("00000000-0000-4000-8000-000000000001".to_string()),
            client_id: Some("00000000-0000-4000-8000-000000000002".to_string()),
            client_secret_ref: Some(format!("file:{}", client_secret_path.display())),
            flow_key_ref: Some(format!("file:{}", flow_key_path.display())),
            ..MicrosoftOidcConfig::default()
        };
        let runtime = MicrosoftOidcRuntimeConfig::from_config(&config, Some("http://[::1]:8080"))
            .unwrap()
            .unwrap();
        assert_eq!(
            runtime.redirect_url().as_str(),
            "http://[::1]:8080/v1/auth/oidc/microsoft/callback"
        );
        assert!(matches!(
            MicrosoftOidcRuntimeConfig::from_config(&config, Some("http://[::2]:8080")),
            Err(MicrosoftOidcRuntimeConfigError::Validation(
                MicrosoftOidcValidationError::InvalidUrl
            ))
        ));
    }

    #[test]
    fn group_claims_distinguish_complete_empty_overage_and_malformed() {
        let tenant = "00000000-0000-4000-8000-000000000001";
        let user = "00000000-0000-4000-8000-000000000002";
        let group = "00000000-0000-4000-8000-000000000003";
        let base = json!({"tid": tenant, "oid": user});
        assert_eq!(
            additional_claims(base.clone()).classify_groups(),
            MicrosoftGroupClaimClassification::Complete(BTreeSet::new())
        );
        let claims = additional_claims(json!({
            "tid": tenant,
            "oid": user,
            "groups": [group, group]
        }));
        assert_eq!(
            claims.classify_groups(),
            MicrosoftGroupClaimClassification::Complete(BTreeSet::from([group.to_string()]))
        );
        assert_eq!(
            additional_claims(json!({"tid": tenant, "oid": user, "hasgroups": true}))
                .classify_groups(),
            MicrosoftGroupClaimClassification::Overage
        );
        assert_eq!(
            additional_claims(json!({
                "tid": tenant,
                "oid": user,
                "_claim_names": {"groups": "src1"}
            }))
            .classify_groups(),
            MicrosoftGroupClaimClassification::Overage
        );
        assert!(matches!(
            additional_claims(json!({"tid": tenant, "oid": user, "groups": null}))
                .classify_groups(),
            MicrosoftGroupClaimClassification::Malformed(
                MicrosoftMalformedGroupClaims::InvalidGroups
            )
        ));
        assert!(matches!(
            additional_claims(json!({
                "tid": tenant,
                "oid": user,
                "groups": [group],
                "hasgroups": true
            }))
            .classify_groups(),
            MicrosoftGroupClaimClassification::Malformed(
                MicrosoftMalformedGroupClaims::ConflictingMarkers
            )
        ));
    }

    #[test]
    fn group_claims_enforce_canonical_ids_and_the_microsoft_limit() {
        let tenant = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa1";
        let user = "00000000-0000-4000-8000-000000000002";
        assert!(matches!(
            additional_claims(
                json!({"tid": tenant, "oid": user, "groups": [tenant.to_uppercase()]})
            )
            .classify_groups(),
            MicrosoftGroupClaimClassification::Malformed(
                MicrosoftMalformedGroupClaims::InvalidGroupId
            )
        ));
        let groups = (0..=MICROSOFT_OIDC_MAX_GROUPS)
            .map(|index| format!("00000000-0000-4000-8000-{index:012}"))
            .collect::<Vec<_>>();
        assert!(matches!(
            additional_claims(json!({"tid": tenant, "oid": user, "groups": groups}))
                .classify_groups(),
            MicrosoftGroupClaimClassification::Malformed(
                MicrosoftMalformedGroupClaims::TooManyGroups
            )
        ));
    }

    #[test]
    fn duplicate_top_level_claims_are_rejected_without_rejecting_nested_duplicates() {
        let duplicate = token_with_payload(r#"{"tid":"one","tid":"two"}"#);
        assert_eq!(
            validate_microsoft_id_token_payload_syntax(&duplicate),
            Err(MicrosoftOidcValidationError::DuplicateTopLevelClaim)
        );
        let nested = token_with_payload(r#"{"tid":"one","nested":{"key":1,"key":2}}"#);
        assert_eq!(validate_microsoft_id_token_payload_syntax(&nested), Ok(()));
        assert_eq!(
            validate_microsoft_id_token_payload_syntax("not-a-jwt"),
            Err(MicrosoftOidcValidationError::MalformedIdToken)
        );
    }

    #[derive(Debug)]
    struct FixedClock(DateTime<Utc>);

    impl MicrosoftOidcClock for FixedClock {
        fn now(&self) -> DateTime<Utc> {
            self.0
        }
    }

    #[test]
    fn clock_seam_is_deterministic() {
        let now = Utc.with_ymd_and_hms(2026, 8, 11, 0, 0, 0).unwrap();
        assert_eq!(FixedClock(now).now(), now);
    }

    #[test]
    fn identity_validation_enforces_tenant_audience_azp_and_time_bounds() {
        let now = Utc.with_ymd_and_hms(2026, 8, 11, 0, 0, 0).unwrap();
        let tenant = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa1";
        let user = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbb2";
        let client = "cccccccc-cccc-4ccc-8ccc-ccccccccccc3";
        let claims: MicrosoftOidcIdTokenClaims = serde_json::from_value(json!({
            "iss": format!("https://login.microsoftonline.com/{tenant}/v2.0"),
            "aud": [client, "another-audience"],
            "azp": client,
            "exp": (now + ChronoDuration::minutes(5)).timestamp(),
            "iat": now.timestamp(),
            "nbf": now.timestamp(),
            "sub": "pairwise-subject",
            "tid": tenant,
            "oid": user
        }))
        .unwrap();
        let identity =
            validate_microsoft_oidc_identity(&claims, tenant, client, &FixedClock(now)).unwrap();
        assert_eq!(
            identity.external_subject,
            format!("entra:v1:{tenant}:{user}")
        );

        let wrong_azp: MicrosoftOidcIdTokenClaims = serde_json::from_value(json!({
            "iss": format!("https://login.microsoftonline.com/{tenant}/v2.0"),
            "aud": [client, "another-audience"],
            "azp": "dddddddd-dddd-4ddd-8ddd-ddddddddddd4",
            "exp": (now + ChronoDuration::minutes(5)).timestamp(),
            "iat": now.timestamp(),
            "sub": "pairwise-subject",
            "tid": tenant,
            "oid": user
        }))
        .unwrap();
        assert_eq!(
            validate_microsoft_oidc_identity(&wrong_azp, tenant, client, &FixedClock(now),),
            Err(MicrosoftOidcValidationError::InvalidIdentityClaims)
        );
    }

    #[test]
    fn bounded_transport_rejects_non_microsoft_and_oversized_requests() {
        let client = MicrosoftOidcHttpClient::new(&crate::tests::test_outbound_tls()).unwrap();
        let allowed = http::Request::builder()
            .uri("https://login.microsoftonline.com/tenant/oauth2/v2.0/token")
            .body(Vec::new())
            .unwrap();
        assert!(client.validate_request(&allowed).is_ok());

        let wrong_host = http::Request::builder()
            .uri("https://example.test/token")
            .body(Vec::new())
            .unwrap();
        assert!(matches!(
            client.validate_request(&wrong_host),
            Err(MicrosoftOidcHttpError::RequestRejected)
        ));
        let oversized = http::Request::builder()
            .uri("https://login.microsoftonline.com/tenant/oauth2/v2.0/token")
            .body(vec![0; MICROSOFT_OIDC_MAX_HTTP_REQUEST_BYTES + 1])
            .unwrap();
        assert!(matches!(
            client.validate_request(&oversized),
            Err(MicrosoftOidcHttpError::RequestRejected)
        ));
    }

    #[tokio::test]
    async fn outbound_tls_snapshot_is_used_without_relaxing_oidc_request_validation() {
        use rustls::pki_types::pem::PemObject;
        use std::io::{Read, Write};
        use std::net::TcpListener;

        let directory = tempfile::tempdir().unwrap();
        let ca_path = directory.path().join("ca.pem");
        fs::write(
            &ca_path,
            include_bytes!("../tests/fixtures/outbound-tls/ca-a.pem"),
        )
        .unwrap();
        let config = crate::OutboundTlsConfig {
            trust: crate::OutboundTlsTrustMode::Custom,
            ca_certificate: Some(ca_path.clone()),
        };
        let snapshot = crate::PreparedOutboundTls::load(&config).unwrap();
        // Changing the bundle after preparation must not change this generation.
        fs::write(
            &ca_path,
            include_bytes!("../tests/fixtures/outbound-tls/ca-b.pem"),
        )
        .unwrap();
        let different_snapshot = crate::PreparedOutboundTls::load(&config).unwrap();
        fs::remove_file(&ca_path).unwrap();
        let trusted = MicrosoftOidcHttpClient::new(&snapshot).unwrap();
        let untrusted = MicrosoftOidcHttpClient::new(&different_snapshot).unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let certificate = rustls::pki_types::CertificateDer::from_pem_slice(include_bytes!(
            "../tests/fixtures/outbound-tls/leaf-a.pem"
        ))
        .unwrap();
        let key = rustls::pki_types::PrivateKeyDer::from_pem_slice(include_bytes!(
            "../tests/fixtures/outbound-tls/leaf-a.key"
        ))
        .unwrap();
        let server_config = Arc::new(
            rustls::ServerConfig::builder()
                .with_no_client_auth()
                .with_single_cert(vec![certificate], key)
                .unwrap(),
        );
        let server = std::thread::spawn(move || {
            let mut accepted_requests = 0;
            for _ in 0..2 {
                let (stream, _) = listener.accept().unwrap();
                stream
                    .set_read_timeout(Some(Duration::from_secs(5)))
                    .unwrap();
                stream
                    .set_write_timeout(Some(Duration::from_secs(5)))
                    .unwrap();
                let connection = rustls::ServerConnection::new(server_config.clone()).unwrap();
                let mut stream = rustls::StreamOwned::new(connection, stream);
                let mut request = Vec::new();
                let mut byte = [0_u8];
                while !request.ends_with(b"\r\n\r\n") {
                    if stream.read_exact(&mut byte).is_err() {
                        break;
                    }
                    request.push(byte[0]);
                    assert!(request.len() < 8192);
                }
                if request.ends_with(b"\r\n\r\n") {
                    accepted_requests += 1;
                    stream
                        .write_all(
                            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}",
                        )
                        .unwrap();
                    stream.flush().unwrap();
                }
            }
            accepted_requests
        });
        let url = format!("https://{address}/token");
        // Probe the exact transport constructed by new; the OIDC adapter itself
        // deliberately rejects loopback destinations and nonstandard ports.
        assert_eq!(
            trusted
                .client
                .get(&url)
                .send()
                .await
                .unwrap()
                .text()
                .await
                .unwrap(),
            "{}"
        );
        let failure = untrusted.client.get(&url).send().await.unwrap_err();
        assert!(failure.is_connect());
        let request = http::Request::builder().uri(url).body(Vec::new()).unwrap();
        assert!(matches!(
            trusted.call(request).await,
            Err(MicrosoftOidcHttpError::RequestRejected)
        ));
        assert_eq!(server.join().unwrap(), 1);
    }

    #[test]
    fn secret_resolution_is_disabled_locally_and_redacts_enabled_material() {
        assert!(
            resolve_microsoft_oidc_secrets(&MicrosoftOidcConfig::default())
                .unwrap()
                .is_none()
        );

        let directory = tempfile::tempdir().unwrap();
        let client_secret_path = directory.path().join("client-secret");
        let flow_key_path = directory.path().join("flow-key");
        fs::write(&client_secret_path, "extremely-sensitive-client-secret\n").unwrap();
        fs::write(&flow_key_path, URL_SAFE_NO_PAD.encode([7_u8; 32])).unwrap();
        let config = MicrosoftOidcConfig {
            enabled: true,
            client_secret_ref: Some(format!("file:{}", client_secret_path.display())),
            flow_key_ref: Some(format!("file:{}", flow_key_path.display())),
            ..MicrosoftOidcConfig::default()
        };
        let resolved = resolve_microsoft_oidc_secrets(&config).unwrap().unwrap();
        assert_eq!(
            resolved.client_secret(),
            "extremely-sensitive-client-secret"
        );
        assert_eq!(resolved.flow_key(), &[7_u8; 32]);
        let debug = format!("{resolved:?}");
        assert!(!debug.contains("extremely-sensitive"));
        assert!(!debug.contains("BwcH"));
    }
}
