//! The Microsoft side of membership renewal: the bounded refresh-token
//! request to the token endpoint, what its response may contribute, the
//! classification of an attempt's outcome and when the next attempt may run.
//!
//! Only the HTTP status, `Retry-After`, Microsoft's `error` and numeric
//! `error_codes` (for a non-200 response) and the ID, refresh and access
//! tokens (for a 200) are ever taken from a response. Raw bodies,
//! `error_description` and parse-error text are never kept.
use super::*;
use crate::OidcRenewalReference;
use bytes::Bytes;
use http::HeaderValue;
use http::header::RETRY_AFTER;

/// The scopes a redemption asks for: the sign-in scopes with
/// `offline_access`, so Microsoft returns an ID token and a new refresh
/// token.
pub const MICROSOFT_OIDC_RENEWAL_SCOPES: [&str; 4] = [
    "openid",
    "profile",
    "email",
    MICROSOFT_OIDC_OFFLINE_ACCESS_SCOPE,
];
/// At most this many of Microsoft's numeric `error_codes` are kept for logs.
pub const MICROSOFT_OIDC_MAX_ERROR_CODES: usize = 8;
/// How long the process-wide throttle lasts after a 429 without a usable
/// `Retry-After`.
pub const MICROSOFT_OIDC_DEFAULT_THROTTLE_SECONDS: i64 = 60;
/// The minimum time between two attempts for one login method.
pub const MEMBERSHIP_RENEWAL_MIN_ATTEMPT_INTERVAL_SECONDS: i64 = 60;
/// The first local backoff after a retryable failure; it doubles per
/// consecutive failure up to [`MEMBERSHIP_RENEWAL_MAX_BACKOFF_SECONDS`].
pub const MEMBERSHIP_RENEWAL_MIN_BACKOFF_SECONDS: i64 = 30;
pub const MEMBERSHIP_RENEWAL_MAX_BACKOFF_SECONDS: i64 = 15 * 60;
/// How long a blocked renewal waits before it tries again.
pub const MEMBERSHIP_RENEWAL_BLOCKED_RETRY_SECONDS: i64 = 60 * 60;
/// The longest `Retry-After` honoured as given, as seconds or a date; a
/// longer one is clamped so that time arithmetic cannot overflow.
const MAX_RETRY_AFTER_SECONDS: u64 = 10 * 365 * 24 * 60 * 60;

/// When a token endpoint asked to be retried: a number of seconds, or an
/// HTTP-date in any of the three formats RFC 9110 §5.6.7 has recipients
/// accept (IMF-fixdate, RFC 850 and asctime).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RetryAfter {
    Seconds(u64),
    At(DateTime<Utc>),
}

impl RetryAfter {
    /// Parses a `Retry-After` value; anything else is unusable.
    pub fn parse(value: &HeaderValue) -> Option<Self> {
        let value = value.to_str().ok()?.trim();
        if !value.is_empty() && value.bytes().all(|byte| byte.is_ascii_digit()) {
            return Some(Self::Seconds(
                value
                    .parse::<u64>()
                    .unwrap_or(u64::MAX)
                    .min(MAX_RETRY_AFTER_SECONDS),
            ));
        }
        httpdate::parse_http_date(value)
            .ok()
            .map(|at| Self::At(DateTime::<Utc>::from(at)))
    }

    /// The earliest time it allows a retry, never before `now` and at most
    /// ten years after it.
    pub fn not_before(self, now: DateTime<Utc>) -> DateTime<Utc> {
        let latest = now + ChronoDuration::seconds(MAX_RETRY_AFTER_SECONDS as i64);
        match self {
            Self::Seconds(seconds) => {
                now + ChronoDuration::seconds(seconds.min(MAX_RETRY_AFTER_SECONDS) as i64)
            }
            Self::At(at) => at.clamp(now, latest),
        }
    }
}

/// How much of a token-endpoint response body arrived.
pub enum TokenEndpointBody {
    /// The complete body, within the size limit.
    Complete(Vec<u8>),
    /// The body failed or timed out before it ended.
    Failed,
    /// The body exceeded the size limit.
    Oversized,
}

/// A token-endpoint response as far as it arrived. A response whose headers
/// never arrived has no status. Its debug output never shows the body.
pub struct TokenEndpointResponse {
    status: Option<u16>,
    retry_after: Option<RetryAfter>,
    body: TokenEndpointBody,
}

impl fmt::Debug for TokenEndpointResponse {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TokenEndpointResponse")
            .field("status", &self.status)
            .field("retry_after", &self.retry_after)
            .finish_non_exhaustive()
    }
}

impl TokenEndpointResponse {
    /// No response: the connection failed or timed out before headers.
    pub fn no_response() -> Self {
        Self {
            status: None,
            retry_after: None,
            body: TokenEndpointBody::Failed,
        }
    }

    /// A response with `status`, its `Retry-After` header, if any, and as
    /// much of the body as arrived.
    pub fn new(status: u16, retry_after: Option<&HeaderValue>, body: TokenEndpointBody) -> Self {
        Self {
            status: Some(status),
            retry_after: retry_after.and_then(RetryAfter::parse),
            body,
        }
    }

    pub fn status(&self) -> Option<u16> {
        self.status
    }

    pub fn retry_after(&self) -> Option<RetryAfter> {
        self.retry_after
    }
}

/// Reads a response body of at most `max_bytes`. A declared or actual
/// length over the limit is [`TokenEndpointBody::Oversized`]; a stream error
/// (including the client's total timeout) is [`TokenEndpointBody::Failed`].
pub async fn read_token_endpoint_body<S, E>(
    content_length: Option<u64>,
    mut chunks: S,
    max_bytes: usize,
) -> TokenEndpointBody
where
    S: futures_util::Stream<Item = Result<Bytes, E>> + Unpin,
{
    if content_length.is_some_and(|length| length > max_bytes as u64) {
        return TokenEndpointBody::Oversized;
    }
    let mut body = Vec::new();
    while let Some(chunk) = chunks.next().await {
        let Ok(chunk) = chunk else {
            return TokenEndpointBody::Failed;
        };
        if body.len().saturating_add(chunk.len()) > max_bytes {
            return TokenEndpointBody::Oversized;
        }
        body.extend_from_slice(&chunk);
    }
    TokenEndpointBody::Complete(body)
}

impl MicrosoftOidcHttpClient {
    /// Sends one token request with this client's pinned host, timeouts and
    /// no redirects or proxy, keeping the status and `Retry-After` as soon
    /// as headers arrive even when the body then fails or exceeds the limit.
    pub async fn send_token_request(&self, request: HttpRequest) -> TokenEndpointResponse {
        if self.validate_request(&request).is_err() {
            return TokenEndpointResponse::no_response();
        }
        let Ok(request) = reqwest::Request::try_from(request) else {
            return TokenEndpointResponse::no_response();
        };
        let Ok(response) = self.client.execute(request).await else {
            return TokenEndpointResponse::no_response();
        };
        let status = response.status().as_u16();
        let retry_after = response.headers().get(RETRY_AFTER).cloned();
        let content_length = response.content_length();
        let body = read_token_endpoint_body(
            content_length,
            response.bytes_stream(),
            self.max_response_bytes,
        )
        .await;
        TokenEndpointResponse::new(status, retry_after.as_ref(), body)
    }
}

/// The tokens of a 200 response. Its debug output never shows them.
pub struct RefreshedTokens {
    pub id_token: Option<String>,
    pub refresh_token: Option<String>,
    pub access_token: Option<String>,
}

impl fmt::Debug for RefreshedTokens {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RefreshedTokens")
            .field("id_token", &self.id_token.is_some())
            .field("refresh_token", &self.refresh_token.is_some())
            .field("access_token", &self.access_token.is_some())
            .finish()
    }
}

/// What a response contributes before ID-token validation (design §8.6).
#[derive(Debug)]
pub enum TokenEndpointClass {
    /// Rules 1, 3 and 5: no response, a 5xx, or a 4xx `server_error` or
    /// `temporarily_unavailable`.
    Unavailable,
    /// Rule 2: a 429, whatever its body.
    Throttled,
    /// Rule 4: a 200 whose body parsed; its ID token decides the outcome.
    Issued(RefreshedTokens),
    /// Rule 4's unusable 200 body, or rule 9's unexpected status.
    InvalidResponse,
    /// Rule 6: an interactive sign-in is needed.
    SignInRequired,
    /// Rule 7: Microsoft rejected the client.
    ClientRejected,
    /// Rule 8: any other 4xx.
    RequestRejected,
}

/// What may be logged about a response: its status, `Retry-After`,
/// Microsoft's `error` reduced to an allowlist and at most eight numeric
/// `error_codes`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TokenEndpointDiagnostics {
    pub status: Option<u16>,
    pub retry_after: Option<RetryAfter>,
    /// An allowlisted identifier, `other`, or `None` when the response named
    /// no error.
    pub error: Option<&'static str>,
    pub error_codes: Vec<u64>,
}

/// The `error` identifiers that may be logged as given.
const LOGGED_ERRORS: &[&str] = &[
    "server_error",
    "temporarily_unavailable",
    "invalid_grant",
    "interaction_required",
    "consent_required",
    "login_required",
    "invalid_client",
    "unauthorized_client",
    "invalid_request",
    "invalid_scope",
    "unsupported_grant_type",
];

fn logged_error(error: &str) -> &'static str {
    LOGGED_ERRORS
        .iter()
        .find(|candidate| **candidate == error)
        .copied()
        .unwrap_or("other")
}

#[derive(Deserialize)]
struct ErrorFields {
    #[serde(default)]
    error: Option<String>,
    #[serde(default)]
    error_codes: Option<Vec<Value>>,
}

#[derive(Deserialize)]
struct TokenFields {
    #[serde(default)]
    id_token: Option<String>,
    #[serde(default)]
    refresh_token: Option<String>,
    #[serde(default)]
    access_token: Option<String>,
}

/// Classifies a response by the precedence of design §8.6, rules 1 to 9;
/// a 200 is [`TokenEndpointClass::Issued`] only when its body is a JSON
/// object, and its ID token is validated afterwards.
pub fn classify_token_endpoint_response(
    response: TokenEndpointResponse,
) -> (TokenEndpointClass, TokenEndpointDiagnostics) {
    let TokenEndpointResponse {
        status,
        retry_after,
        body,
    } = response;
    let mut diagnostics = TokenEndpointDiagnostics {
        status,
        retry_after,
        ..TokenEndpointDiagnostics::default()
    };
    let Some(status) = status else {
        return (TokenEndpointClass::Unavailable, diagnostics);
    };
    if status == 429 {
        return (TokenEndpointClass::Throttled, diagnostics);
    }
    if (500..=599).contains(&status) {
        return (TokenEndpointClass::Unavailable, diagnostics);
    }
    let body = match body {
        TokenEndpointBody::Complete(body) => Some(body),
        TokenEndpointBody::Failed | TokenEndpointBody::Oversized => None,
    };
    if status == 200 {
        let tokens = body
            .as_deref()
            .and_then(|body| serde_json::from_slice::<Value>(body).ok())
            .filter(Value::is_object)
            .and_then(|body| serde_json::from_value::<TokenFields>(body).ok());
        return match tokens {
            Some(tokens) => (
                TokenEndpointClass::Issued(RefreshedTokens {
                    id_token: tokens.id_token,
                    refresh_token: tokens.refresh_token,
                    access_token: tokens.access_token,
                }),
                diagnostics,
            ),
            None => (TokenEndpointClass::InvalidResponse, diagnostics),
        };
    }
    if !(400..=499).contains(&status) {
        return (TokenEndpointClass::InvalidResponse, diagnostics);
    }
    let fields = body
        .as_deref()
        .and_then(|body| serde_json::from_slice::<Value>(body).ok())
        .filter(Value::is_object)
        .and_then(|body| serde_json::from_value::<ErrorFields>(body).ok());
    let error = fields.as_ref().and_then(|fields| fields.error.as_deref());
    diagnostics.error = error.map(logged_error);
    diagnostics.error_codes = fields
        .as_ref()
        .and_then(|fields| fields.error_codes.as_ref())
        .map(|codes| {
            codes
                .iter()
                .filter_map(Value::as_u64)
                .take(MICROSOFT_OIDC_MAX_ERROR_CODES)
                .collect()
        })
        .unwrap_or_default();
    let class = match error {
        Some("server_error" | "temporarily_unavailable") => TokenEndpointClass::Unavailable,
        Some("invalid_grant" | "interaction_required" | "consent_required" | "login_required") => {
            TokenEndpointClass::SignInRequired
        }
        Some("invalid_client" | "unauthorized_client") => TokenEndpointClass::ClientRejected,
        _ => TokenEndpointClass::RequestRejected,
    };
    (class, diagnostics)
}

/// The outcome of one renewal attempt that reached Microsoft (design §8.6).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MembershipRenewalClassification {
    Renewed,
    GroupsIncomplete,
    SignInRequired,
    IdentityMismatch,
    ClientRejected,
    RequestRejected,
    InvalidResponse,
    Throttled,
    Unavailable,
}

impl MembershipRenewalClassification {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Renewed => "renewed",
            Self::GroupsIncomplete => "groups_incomplete",
            Self::SignInRequired => "sign_in_required",
            Self::IdentityMismatch => "identity_mismatch",
            Self::ClientRejected => "client_rejected",
            Self::RequestRejected => "request_rejected",
            Self::InvalidResponse => "invalid_response",
            Self::Throttled => "throttled",
            Self::Unavailable => "unavailable",
        }
    }
}

/// Whether a complete-groups token issued at `issued_at` is too old to
/// renew: its evidence would already be inside the renewal window, `ahead =
/// ttl / 4` (design §8.6, rule 4).
pub fn membership_renewal_issued_at_stale(
    issued_at: i64,
    now: DateTime<Utc>,
    ttl_seconds: u64,
) -> bool {
    let evidence_at = issued_at.min(now.timestamp());
    let ttl = i64::try_from(ttl_seconds).unwrap_or(i64::MAX);
    evidence_at
        .saturating_add(ttl)
        .saturating_sub(now.timestamp())
        <= ttl / 4
}

/// The local backoff after `consecutive_failures` (at least 1) failures in
/// a row: 30 s doubling to a 15-minute cap, scaled by `1 + jitter` for a
/// `jitter` in `[-0.2, 0.2]`.
pub fn membership_renewal_backoff(consecutive_failures: u32, jitter: f64) -> ChronoDuration {
    let doublings = consecutive_failures.saturating_sub(1).min(16);
    let base = MEMBERSHIP_RENEWAL_MIN_BACKOFF_SECONDS
        .saturating_mul(1_i64 << doublings)
        .min(MEMBERSHIP_RENEWAL_MAX_BACKOFF_SECONDS);
    let jitter = jitter.clamp(-0.2, 0.2);
    ChronoDuration::milliseconds(((base * 1000) as f64 * (1.0 + jitter)).round() as i64)
}

/// When a failed attempt's login method may next be attempted, or `None`
/// for outcomes that do not retry. A `Retry-After` is a minimum and is never
/// shortened; local caps apply only to the local backoff.
pub fn membership_renewal_next_attempt(
    classification: MembershipRenewalClassification,
    consecutive_failures: u32,
    retry_after: Option<RetryAfter>,
    now: DateTime<Utc>,
    jitter: f64,
) -> Option<DateTime<Utc>> {
    let local = match classification {
        MembershipRenewalClassification::Throttled
        | MembershipRenewalClassification::Unavailable => {
            now + membership_renewal_backoff(consecutive_failures, jitter)
        }
        MembershipRenewalClassification::GroupsIncomplete
        | MembershipRenewalClassification::ClientRejected
        | MembershipRenewalClassification::RequestRejected
        | MembershipRenewalClassification::InvalidResponse => {
            now + ChronoDuration::seconds(MEMBERSHIP_RENEWAL_BLOCKED_RETRY_SECONDS)
        }
        MembershipRenewalClassification::Renewed
        | MembershipRenewalClassification::SignInRequired
        | MembershipRenewalClassification::IdentityMismatch => return None,
    };
    Some(match retry_after {
        Some(retry_after) => local.max(retry_after.not_before(now)),
        None => local,
    })
}

/// The provider throttle a 429 sets: `Retry-After`, or 60 s without a
/// usable one, from `now`.
pub fn microsoft_oidc_throttle_until(
    retry_after: Option<RetryAfter>,
    now: DateTime<Utc>,
) -> DateTime<Utc> {
    match retry_after {
        Some(retry_after) => retry_after.not_before(now),
        None => now + ChronoDuration::seconds(MICROSOFT_OIDC_DEFAULT_THROTTLE_SECONDS),
    }
}

/// The token request redeeming `refresh_token` at `token_endpoint` with
/// `client_secret_post`.
pub fn microsoft_refresh_token_request(
    token_endpoint: &Url,
    client_id: &str,
    client_secret: &str,
    refresh_token: &str,
) -> Result<HttpRequest, MicrosoftOidcValidationError> {
    let body = url::form_urlencoded::Serializer::new(String::new())
        .append_pair("grant_type", "refresh_token")
        .append_pair("refresh_token", refresh_token)
        .append_pair("client_id", client_id)
        .append_pair("client_secret", client_secret)
        .append_pair("scope", &MICROSOFT_OIDC_RENEWAL_SCOPES.join(" "))
        .finish();
    http::Request::builder()
        .method(http::Method::POST)
        .uri(token_endpoint.as_str())
        .header(
            http::header::CONTENT_TYPE,
            "application/x-www-form-urlencoded",
        )
        .header(http::header::ACCEPT, "application/json")
        .body(body.into_bytes())
        .map_err(|_| MicrosoftOidcValidationError::InvalidUrl)
}

/// How a refreshed ID token's identity claims compare with the reference
/// stored with its refresh token (OIDC Core §12.2) and with the login
/// method.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RenewalReferenceMismatch {
    /// `aud`, `azp` or `auth_time` differ: an invalid response.
    Claims,
    /// `sub`, or the Broker subject from `tid` and `oid`, differ: the
    /// token belongs to someone else.
    Identity,
}

/// The identity claims of a validated refreshed ID token.
#[derive(Debug, Clone, Copy)]
pub struct RenewalObservation<'a> {
    pub subject: &'a str,
    pub audience: &'a Value,
    pub authorized_party: Option<&'a str>,
    pub auth_time: Option<i64>,
    pub external_subject: &'a str,
}

/// Compares a refreshed ID token with its stored reference: `aud` exactly as
/// issued, `azp` present exactly when it was with the same value and
/// `auth_time` absent or equal, then `sub` and the Broker subject. Claim
/// differences are checked first, so an identity mismatch is reported only
/// for an otherwise valid token.
pub fn compare_renewal_reference(
    reference: &OidcRenewalReference,
    observed: &RenewalObservation<'_>,
    method_external_subject: &str,
) -> Result<(), RenewalReferenceMismatch> {
    if observed.audience != reference.audience()
        || observed.authorized_party != reference.azp()
        || observed
            .auth_time
            .is_some_and(|auth_time| Some(auth_time) != reference.auth_time())
    {
        return Err(RenewalReferenceMismatch::Claims);
    }
    if observed.subject != reference.subject()
        || observed.external_subject != method_external_subject
    {
        return Err(RenewalReferenceMismatch::Identity);
    }
    Ok(())
}

/// Whether a refreshed ID token's `nonce` is acceptable: absent, or the
/// sign-in nonce whose digest the reference keeps.
pub fn renewal_nonce_matches(reference: &OidcRenewalReference, nonce: Option<&str>) -> bool {
    nonce.is_none_or(|nonce| {
        let digest = microsoft_oidc_nonce_sha256(nonce);
        bool::from(subtle::ConstantTimeEq::ct_eq(
            digest.as_bytes(),
            reference.nonce_sha256().as_bytes(),
        ))
    })
}

#[cfg(test)]
#[path = "renewal_tests.rs"]
mod tests;
