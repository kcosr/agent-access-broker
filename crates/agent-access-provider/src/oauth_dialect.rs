//! OAuth dialects: how the broker talks to one family of authorization
//! servers. Core's OAuth manager owns consent flows, credential encryption,
//! refresh coordination, fences, and retry budgets; a dialect owns the wire:
//! the authorization URL, token requests, identity and target discovery, and
//! how failures classify. Dialects register with the broker binary, so an
//! authorization server family can live outside core.
use crate::host::UpstreamClientFactory;
use crate::{
    BodyReadError, ClientProfile, EgressDeclaration, ModuleMetadata, ProviderBuildError,
    UpstreamAuthority, UpstreamCall, UpstreamClient, UpstreamClientSpec, UpstreamError,
    complete_upstream_trace, read_bounded_body,
};
use async_trait::async_trait;
use reqwest::{Method, RequestBuilder, Response};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::borrow::Cow;
use std::collections::{BTreeMap, BTreeSet};
use std::time::Duration;
use thiserror::Error;
use url::Url;

/// Largest OAuth response body the broker reads.
pub const OAUTH_MAX_RESPONSE_BYTES: usize = 256 * 1024;
/// Every OAuth request completes within this bound, well inside a refresh
/// attempt's lifetime.
const OAUTH_REQUEST_TIMEOUT: Duration = Duration::from_secs(15);
const OAUTH_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

/// The registered dialect a registration speaks, such as `stub`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct OAuthAdapter(Cow<'static, str>);

impl OAuthAdapter {
    pub fn new(id: impl Into<String>) -> Self {
        Self(Cow::Owned(id.into()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// One `[oauth.registrations.<id>]` configuration table.
///
/// Configuration schema is intentionally exhaustive: its fields are the
/// documented keys of a table that rejects unknown keys, so adding one is a
/// configuration contract change that every consumer rendering or validating
/// the table must handle. Dialects only read it.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OAuthRegistrationConfig {
    pub adapter: OAuthAdapter,
    pub base_url: String,
    pub redirect_uri: String,
    pub client_id: String,
    #[serde(default)]
    pub client_secret_ref: String,
    /// Operator-approved dialect settings; never populated from imported tool metadata.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub adapter_settings: BTreeMap<String, String>,
    #[serde(default)]
    pub client_auth: OAuthClientAuth,
    #[serde(default)]
    pub encoding: OAuthTokenEncoding,
    #[serde(default)]
    pub rotation: OAuthRotation,
    #[serde(default)]
    pub allow_insecure_loopback: bool,
    pub permission_profiles: BTreeMap<String, OAuthPermissionProfile>,
    /// Binds each connected upstream account to its owner's Broker sign-in.
    /// Only a dialect that reports linked identities
    /// ([`OAuthDialect::supports_login_binding`]) accepts it.
    // Omitting it preserves existing registration fingerprints.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub login_binding: Option<OAuthLoginBinding>,
}

/// A registration's `login_binding`: the Broker sign-in an upstream account
/// must be linked to before the Broker installs a connection to it.
///
/// The host requires the connected account to report a linked identity at
/// `upstream_identity_provider` whose external ID is the owner's user ID at
/// the Broker's sign-in `provider`. Configuration schema, intentionally
/// exhaustive like [`OAuthRegistrationConfig`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OAuthLoginBinding {
    /// The Broker sign-in whose linked identity is authoritative.
    pub provider: OAuthLoginProvider,
    /// The upstream's name for the identity provider it signs people in
    /// through, as its linked identities report it.
    pub upstream_identity_provider: String,
    /// The operator's attestation that `upstream_identity_provider` signs
    /// people in through this tenant of `provider`: the tenant must also be
    /// the Broker sign-in's own.
    pub upstream_tenant_id: String,
}

/// A Broker sign-in an upstream account can be bound to.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OAuthLoginProvider {
    /// Microsoft Entra ID sign-in: the owner's linked identity is their
    /// object ID (`oid`) in the Broker's tenant.
    Microsoft,
}

#[non_exhaustive]
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum OAuthClientAuth {
    None,
    #[default]
    ClientSecretPost,
    ClientSecretBasic,
}

#[non_exhaustive]
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum OAuthTokenEncoding {
    #[default]
    Form,
    Json,
}

#[non_exhaustive]
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum OAuthRotation {
    PreserveOld,
    #[default]
    RotateRefresh,
    RotateBoth,
}

/// Whether a permission profile requests configured scopes or leaves the
/// resource-bound authorization decision to the authorization server.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum OAuthScopeMode {
    #[default]
    Explicit,
    ServerDefault,
}

impl OAuthScopeMode {
    pub fn is_explicit(&self) -> bool {
        *self == Self::Explicit
    }
}

/// One permission profile of an OAuth registration's configuration.
///
/// Configuration schema is intentionally exhaustive, like
/// [`OAuthRegistrationConfig`].
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OAuthPermissionProfile {
    // Omitting the default mode preserves existing registration fingerprints.
    #[serde(default, skip_serializing_if = "OAuthScopeMode::is_explicit")]
    pub scope_mode: OAuthScopeMode,
    /// Must be present and nonempty for explicit mode, absent for server default.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present_scopes"
    )]
    pub scopes: Option<Vec<String>>,
    pub audience: String,
    pub target: String,
}

impl OAuthPermissionProfile {
    pub fn requested_scopes(&self) -> &[String] {
        self.scopes.as_deref().unwrap_or_default()
    }
}

// A supplied null is not the same as an omitted configuration field.
fn present_scopes<'de, D>(deserializer: D) -> Result<Option<Vec<String>>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    Vec::<String>::deserialize(deserializer).map(Some)
}

/// A resource the authorization server lets a connection reach, with the
/// scopes it grants there.
#[non_exhaustive]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OAuthTarget {
    pub id: String,
    #[serde(default)]
    pub name: String,
    pub audience: String,
    pub scopes: BTreeSet<String>,
}

impl OAuthTarget {
    /// The resource `id` for the API `audience`, granting `scopes` there. It
    /// has an empty display name until [`Self::with_name`] sets one.
    pub fn new(
        id: impl Into<String>,
        audience: impl Into<String>,
        scopes: BTreeSet<String>,
    ) -> Self {
        Self {
            id: id.into(),
            name: String::new(),
            audience: audience.into(),
            scopes,
        }
    }

    pub fn with_name(mut self, name: impl Into<String>) -> Self {
        self.name = name.into();
        self
    }
}

/// A dialect the broker binary links, under the `adapter` name registrations
/// select it by. Declare it as a `static` with the `const` builder.
#[non_exhaustive]
pub struct OAuthDialectRegistration {
    module: ModuleMetadata,
    id: &'static str,
    development_only: bool,
    dialect: &'static dyn OAuthDialect,
}

impl OAuthDialectRegistration {
    /// `dialect` from `module`, selected by the adapter name `id`. It is not
    /// a development fixture.
    pub const fn new(
        module: ModuleMetadata,
        id: &'static str,
        dialect: &'static dyn OAuthDialect,
    ) -> Self {
        Self {
            module,
            id,
            development_only: false,
            dialect,
        }
    }

    /// Marks the dialect as a development fixture: allowed only in
    /// non-production deployments with the development fixtures enabled.
    pub const fn development_only(mut self) -> Self {
        self.development_only = true;
        self
    }

    /// The package that declares this dialect.
    pub const fn module(&self) -> ModuleMetadata {
        self.module
    }

    /// The `adapter` name OAuth registrations select the dialect by.
    pub const fn id(&self) -> &'static str {
        self.id
    }

    pub const fn is_development_only(&self) -> bool {
        self.development_only
    }

    pub const fn dialect(&self) -> &'static dyn OAuthDialect {
        self.dialect
    }
}

impl std::fmt::Debug for OAuthDialectRegistration {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("OAuthDialectRegistration")
            .field("module", &self.module)
            .field("id", &self.id)
            .field("development_only", &self.development_only)
            .finish_non_exhaustive()
    }
}

/// One registration as its dialect sees it. The host creates it; dialect
/// tests build one with [`Self::new`].
#[non_exhaustive]
pub struct OAuthClient<'a> {
    pub registration_id: &'a str,
    pub config: &'a OAuthRegistrationConfig,
    pub client_secret: &'a str,
}

impl<'a> OAuthClient<'a> {
    pub fn new(
        registration_id: &'a str,
        config: &'a OAuthRegistrationConfig,
        client_secret: &'a str,
    ) -> Self {
        Self {
            registration_id,
            config,
            client_secret,
        }
    }
}

impl std::fmt::Debug for OAuthClient<'_> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("OAuthClient")
            .field("registration_id", &self.registration_id)
            .finish_non_exhaustive()
    }
}

/// What the authorization URL carries for one consent flow. The host
/// creates it; dialect tests build one with [`Self::new`].
#[non_exhaustive]
#[derive(Debug, Clone, Copy)]
pub struct AuthorizationRequest<'a> {
    pub state: &'a str,
    /// The PKCE S256 challenge.
    pub code_challenge_s256: &'a str,
}

impl<'a> AuthorizationRequest<'a> {
    pub fn new(state: &'a str, code_challenge_s256: &'a str) -> Self {
        Self {
            state,
            code_challenge_s256,
        }
    }
}

/// An authorization code to exchange, with its PKCE verifier. The host
/// creates it; dialect tests build one with [`Self::new`].
#[non_exhaustive]
#[derive(Clone, Copy)]
pub struct CodeExchange<'a> {
    pub code: &'a str,
    pub code_verifier: &'a str,
    pub profile: &'a OAuthPermissionProfile,
}

impl<'a> CodeExchange<'a> {
    pub fn new(code: &'a str, code_verifier: &'a str, profile: &'a OAuthPermissionProfile) -> Self {
        Self {
            code,
            code_verifier,
            profile,
        }
    }
}

/// What a token response says about the refresh token.
///
/// Intentionally exhaustive: a response issues a new refresh token, keeps the
/// old one valid or issues none, and the manager's refresh fences depend on
/// handling each of them.
pub enum IssuedRefreshToken {
    /// A new refresh token replaces the old one.
    Issued(String),
    /// No new token was issued and the old one stays valid.
    Retained,
    /// No refresh token was issued.
    Absent,
}

/// A token response. The manager validates its bounds.
///
/// The public fields are what the manager reads. A dialect builds a grant
/// with [`Self::new`] and the `with_*` builders.
#[non_exhaustive]
pub struct TokenGrant {
    pub access_token: String,
    pub token_type: String,
    pub expires_in: u64,
    /// Known access-token scopes, from the response or protocol-defined inference.
    /// Empty represents unknown server-default permissions, never explicit authority.
    pub scopes: Vec<String>,
    pub refresh_token: IssuedRefreshToken,
    /// Whether this grant invalidates access tokens issued earlier for other
    /// permission profiles of the same connection.
    pub supersedes_other_access: bool,
}

impl TokenGrant {
    /// An access token of `token_type` that expires `expires_in` seconds
    /// after issue. Its scopes are unknown until [`Self::with_scopes`]
    /// records them, and it supersedes no other access.
    pub fn new(
        access_token: impl Into<String>,
        token_type: impl Into<String>,
        expires_in: u64,
        refresh_token: IssuedRefreshToken,
    ) -> Self {
        Self {
            access_token: access_token.into(),
            token_type: token_type.into(),
            expires_in,
            scopes: Vec::new(),
            refresh_token,
            supersedes_other_access: false,
        }
    }

    /// Known access-token scopes, from the response or protocol-defined
    /// inference. Empty represents unknown server-default permissions.
    pub fn with_scopes(mut self, scopes: Vec<String>) -> Self {
        self.scopes = scopes;
        self
    }

    /// Whether this grant invalidates access tokens issued earlier for other
    /// permission profiles of the same connection.
    pub fn with_supersedes_other_access(mut self, supersedes_other_access: bool) -> Self {
        self.supersedes_other_access = supersedes_other_access;
        self
    }
}

/// Optional upstream account evidence. When present, the subject must be stable
/// across code exchange and later consent revalidation. Authorization-only
/// protocols must leave it absent instead of inventing an upstream user.
#[non_exhaustive]
pub struct ConnectedIdentity {
    /// None means the grant authorizes a resource but proves no upstream account identity.
    pub subject: Option<String>,
    pub display_name: String,
    /// The upstream account's identities at external identity providers, as
    /// the upstream reports them. Empty when it reports none.
    pub linked_identities: Vec<LinkedIdentity>,
}

impl ConnectedIdentity {
    /// A connection shown as `display_name` that proves no upstream account
    /// identity until [`Self::with_subject`] records one, and reports no
    /// linked identities.
    pub fn new(display_name: impl Into<String>) -> Self {
        Self {
            subject: None,
            display_name: display_name.into(),
            linked_identities: Vec::new(),
        }
    }

    /// The stable upstream account the grant proves.
    pub fn with_subject(mut self, subject: impl Into<String>) -> Self {
        self.subject = Some(subject.into());
        self
    }

    /// The account's identities at external identity providers, which a
    /// registration's `login_binding` checks.
    pub fn with_linked_identities(
        mut self,
        identities: impl IntoIterator<Item = LinkedIdentity>,
    ) -> Self {
        self.linked_identities = identities.into_iter().collect();
        self
    }
}

/// One identity an upstream account is linked to at an external identity
/// provider.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinkedIdentity {
    /// The upstream's name for the identity provider.
    pub provider: String,
    /// The account's user ID at that identity provider.
    pub external_id: String,
}

impl LinkedIdentity {
    /// The account's identity `external_id` at the identity provider the
    /// upstream calls `provider`.
    pub fn new(provider: impl Into<String>, external_id: impl Into<String>) -> Self {
        Self {
            provider: provider.into(),
            external_id: external_id.into(),
        }
    }
}

/// Which kind of token a revocation names: RFC 7009's `token_type_hint`.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OAuthTokenType {
    AccessToken,
    RefreshToken,
}

impl OAuthTokenType {
    /// The RFC 7009 `token_type_hint` value: `access_token` or
    /// `refresh_token`.
    pub fn hint(&self) -> &'static str {
        match self {
            Self::AccessToken => "access_token",
            Self::RefreshToken => "refresh_token",
        }
    }
}

/// One token a registration issued, for the host to revoke at the
/// authorization server. It holds the token, so it has no Debug. The host
/// creates it; dialect tests build one with [`Self::new`].
#[non_exhaustive]
#[derive(Clone, Copy)]
pub struct TokenRevocation<'a> {
    pub token: &'a str,
    pub token_type: OAuthTokenType,
}

impl<'a> TokenRevocation<'a> {
    pub fn new(token: &'a str, token_type: OAuthTokenType) -> Self {
        Self { token, token_type }
    }
}

/// How an authorization server answered a revocation.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RevocationOutcome {
    /// The server revoked the token.
    Revoked,
    /// The server reported the token already invalid: revoked earlier,
    /// expired or unknown to it.
    AlreadyInvalid,
}

/// How an OAuth request failed. The manager's refresh fences depend on the
/// distinction between failures that provably left a grant unused and those
/// that might have consumed it: a dialect must report `RetryAfter`,
/// `PermissionRejected`, and `RequestRejected` only when the authorization
/// server guarantees the grant was not consumed.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum OAuthDialectError {
    #[error("OAuth request was not sent")]
    NotSent,
    #[error("OAuth provider request failed")]
    Failed,
    #[error("OAuth provider response is invalid")]
    InvalidResponse,
    /// Token endpoint only.
    #[error("OAuth provider asked to retry after {0} seconds")]
    RetryAfter(u64),
    #[error("OAuth provider is throttling requests")]
    Throttled,
    #[error("OAuth provider rejected the requested permission")]
    PermissionRejected,
    #[error("OAuth provider rejected the request")]
    RequestRejected,
    #[error("OAuth grant is no longer valid")]
    GrantInvalid,
    #[error("OAuth provider rejected the application credential")]
    ClientRejected,
    #[error("OAuth registration is invalid for its dialect")]
    Configuration,
}

/// Whether an uncertain refresh exchange may safely reuse its input material.
/// This is a provider guarantee, independent of successful-response rotation.
///
/// Intentionally exhaustive: an exchange either consumes its input or may
/// reuse it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RefreshReplay {
    Consuming,
    Reusable,
}

/// The `iss` a consent callback carries: `value`, and whether the callback
/// must carry it.
#[non_exhaustive]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OAuthCallbackIssuer {
    pub value: String,
    pub required: bool,
}

/// An authorization URL and the issuer its consent callback must carry.
#[non_exhaustive]
pub struct PreparedAuthorization {
    pub url: Url,
    pub callback_issuer: OAuthCallbackIssuer,
}

impl PreparedAuthorization {
    pub fn new(url: Url, callback_issuer: OAuthCallbackIssuer) -> Self {
        Self {
            url,
            callback_issuer,
        }
    }
}

impl OAuthCallbackIssuer {
    pub fn new(value: impl Into<String>, required: bool) -> Self {
        Self {
            value: value.into(),
            required,
        }
    }

    pub fn accepts(&self, actual: Option<&str>) -> bool {
        match actual {
            Some(value) => value == self.value,
            None => !self.required,
        }
    }
}

/// One family of authorization servers. Each token method sends at most one
/// request and never retries.
#[async_trait]
pub trait OAuthDialect: Send + Sync + 'static {
    /// Whether registrations may explicitly opt in to server-default permissions.
    fn supports_server_default_scopes(&self) -> bool {
        false
    }

    /// Initial consent may omit refresh capability only when the dialect opts in.
    fn allows_access_without_refresh(&self) -> bool {
        false
    }

    /// Whether [`Self::identity`] reports the account's linked identities,
    /// so registrations may set `login_binding`. The host rejects a
    /// `login_binding` on a dialect that does not opt in, rather than
    /// ignoring it; `validate_registration` need not check the field.
    fn supports_login_binding(&self) -> bool {
        false
    }

    /// Whether [`Self::revoke`] revokes tokens at the authorization server.
    /// When the host ends a connection's token family (disconnect, a
    /// replacing consent, an uncertain refresh or the owner's disablement),
    /// it keeps the family's tokens for remote revocation only for a dialect
    /// that opts in; for any other it reports that revocation was not
    /// requested.
    fn supports_revocation(&self) -> bool {
        false
    }

    /// Revokes one token the registration issued (RFC 7009), sending at
    /// most one request and never retrying. The host retries
    /// `NotSent`, `Failed`, `Throttled`, `RetryAfter` and `ClientRejected`
    /// within a bounded schedule; any other error is final for that token.
    /// The host calls it only when [`Self::supports_revocation`] is `true`;
    /// the default fails as `Configuration`.
    async fn revoke(
        &self,
        _http: &OAuthHttp,
        _client: &OAuthClient<'_>,
        _revocation: TokenRevocation<'_>,
    ) -> Result<RevocationOutcome, OAuthDialectError> {
        Err(OAuthDialectError::Configuration)
    }

    /// Checks the dialect adds to a registration's generic validation; the
    /// error explains, without secrets, what the registration must change.
    fn validate_registration(&self, config: &OAuthRegistrationConfig) -> Result<(), String>;

    /// Checks that a service whose credential connection uses this
    /// registration's `profile` acts on the registration's resource
    /// authority, which is distinct from its authorization server.
    /// `consumer` is the service's declared [`UpstreamAuthority`], `None` when
    /// it declares none. The host calls it offline at configuration
    /// validation, startup and reload. The default accepts every consumer;
    /// a dialect whose grants act on one upstream instance or tenant
    /// overrides it. The error explains, without secrets, what must match.
    fn check_consumer_authority(
        &self,
        _config: &OAuthRegistrationConfig,
        _profile: &OAuthPermissionProfile,
        _consumer: Option<&UpstreamAuthority>,
    ) -> Result<(), String> {
        Ok(())
    }

    /// URL patterns the registration's requests may reach.
    fn upstream_allowlist(&self, config: &OAuthRegistrationConfig) -> Vec<String>;

    fn authorization_url(
        &self,
        client: &OAuthClient<'_>,
        profile: &OAuthPermissionProfile,
        request: AuthorizationRequest<'_>,
    ) -> Result<Url, OAuthDialectError>;

    /// Dynamic dialects validate metadata before redirecting. The manager binds
    /// this issuer policy to the same flow record as state and the PKCE verifier.
    async fn prepare_authorization(
        &self,
        _http: &OAuthHttp,
        client: &OAuthClient<'_>,
        profile: &OAuthPermissionProfile,
        request: AuthorizationRequest<'_>,
    ) -> Result<PreparedAuthorization, OAuthDialectError> {
        Ok(PreparedAuthorization::new(
            self.authorization_url(client, profile, request)?,
            self.callback_issuer(client.config),
        ))
    }

    /// The `iss` a consent callback must carry, when the dialect requires one.
    fn callback_issuer(&self, config: &OAuthRegistrationConfig) -> OAuthCallbackIssuer;

    fn refresh_replay(&self, config: &OAuthRegistrationConfig) -> RefreshReplay;

    async fn exchange_code(
        &self,
        http: &OAuthHttp,
        client: &OAuthClient<'_>,
        exchange: CodeExchange<'_>,
    ) -> Result<TokenGrant, OAuthDialectError>;

    /// `granted_scopes` is original consent evidence, never scopes learned only
    /// from later access-token responses. Empty means consent scopes are unknown.
    async fn refresh(
        &self,
        http: &OAuthHttp,
        client: &OAuthClient<'_>,
        profile: &OAuthPermissionProfile,
        refresh_token: &str,
        granted_scopes: &BTreeSet<String>,
    ) -> Result<TokenGrant, OAuthDialectError>;

    async fn identity(
        &self,
        http: &OAuthHttp,
        client: &OAuthClient<'_>,
        access_token: &str,
    ) -> Result<ConnectedIdentity, OAuthDialectError>;

    /// Receives validated known token scopes, including protocol-defined inference
    /// for omitted response scopes. Empty means unknown server-default permissions.
    async fn discover_targets(
        &self,
        http: &OAuthHttp,
        client: &OAuthClient<'_>,
        access_token: &str,
        granted_scopes: &BTreeSet<String>,
    ) -> Result<Vec<OAuthTarget>, OAuthDialectError>;
}

/// A registration's HTTP transport: an [`UpstreamClient`] with OAuth's own
/// timeouts, sending each request once.
#[derive(Debug, Clone)]
pub struct OAuthHttp {
    client: UpstreamClient,
    destinations: BTreeMap<String, UpstreamClient>,
}

impl OAuthHttp {
    /// Builds one client per approved destination origin through the host's
    /// OAuth client factory, each routed on its own. A literal IPv4/IPv6
    /// loopback origin asks for the direct loopback route; every other origin,
    /// including `localhost`, takes the host's ordinary route, so a loopback
    /// issuer never exempts another destination. Plain HTTP is accepted only
    /// for literal loopback origins.
    pub fn build(
        label: &str,
        provider: &'static str,
        base: &Url,
        allowed_upstream_hosts: &[String],
        clients: &dyn UpstreamClientFactory,
    ) -> Result<Self, ProviderBuildError> {
        let build = |base: &Url| {
            let loopback = crate::is_literal_loopback(base);
            if base.scheme() != "https" && !(loopback && base.scheme() == "http") {
                return Err(ProviderBuildError::invalid(
                    "OAuth destinations require HTTPS; plain HTTP is limited to literal loopback IP addresses",
                ));
            }
            UpstreamClient::build(
                UpstreamClientSpec::new(
                    label,
                    provider,
                    base,
                    if loopback {
                        EgressDeclaration::LiteralLoopback
                    } else {
                        EgressDeclaration::Ordinary(None)
                    },
                    allowed_upstream_hosts,
                    ClientProfile::Bounded {
                        total: OAUTH_REQUEST_TIMEOUT,
                        connect: OAUTH_CONNECT_TIMEOUT,
                    },
                ),
                clients,
            )
        };
        let client = build(base)?;
        let mut destinations = BTreeMap::new();
        for pattern in allowed_upstream_hosts {
            let endpoint = Url::parse(pattern).map_err(|_| {
                ProviderBuildError::invalid("OAuth allowlist requires URL destinations")
            })?;
            if endpoint.host_str().is_none_or(|host| host.contains('*'))
                || !endpoint.username().is_empty()
                || endpoint.password().is_some()
            {
                return Err(ProviderBuildError::invalid(
                    "OAuth allowlist requires fixed HTTP(S) destination origins",
                ));
            }
            let origin = endpoint.origin().ascii_serialization();
            if let std::collections::btree_map::Entry::Vacant(entry) = destinations.entry(origin) {
                entry.insert(build(&endpoint)?);
            }
        }
        Ok(Self {
            client,
            destinations,
        })
    }

    pub fn request(&self, method: Method, url: Url) -> RequestBuilder {
        self.destinations
            .get(&url.origin().ascii_serialization())
            .unwrap_or(&self.client)
            .request(method, url)
    }

    /// Sends a request once. A request that never reached the server,
    /// including one outside the allowlist, fails as `NotSent`.
    pub async fn send(
        &self,
        request: RequestBuilder,
        operation: &str,
    ) -> Result<OAuthResponse, OAuthDialectError> {
        let (request_client, request) = request.build_split();
        let request = request.map_err(|_| OAuthDialectError::NotSent)?;
        let destination = self
            .destinations
            .get(&request.url().origin().ascii_serialization())
            .ok_or(OAuthDialectError::NotSent)?;
        let mut response = destination
            .send(
                RequestBuilder::from_parts(request_client, request),
                UpstreamCall::new(operation),
            )
            .await
            .map_err(|error| match error {
                // A redirect authorizer's failure stops a hop before it is
                // sent; a single send never has one.
                UpstreamError::NotAllowed
                | UpstreamError::NotSent { .. }
                | UpstreamError::RequestBudgetExceeded
                | UpstreamError::Authorization(_) => OAuthDialectError::NotSent,
                UpstreamError::Timeout | UpstreamError::Transport(_) | UpstreamError::Redirect => {
                    OAuthDialectError::Failed
                }
            })?;
        complete_upstream_trace(&mut response, None);
        Ok(OAuthResponse { response })
    }
}

/// A response whose status is known before its body is read.
pub struct OAuthResponse {
    response: Response,
}

impl OAuthResponse {
    pub fn status(&self) -> u16 {
        self.response.status().as_u16()
    }

    pub fn header(&self, name: &str) -> Option<&str> {
        self.response
            .headers()
            .get(name)
            .and_then(|value| value.to_str().ok())
    }

    /// The body as JSON, read within [`OAUTH_MAX_RESPONSE_BYTES`].
    pub async fn json(self) -> Result<Value, OAuthDialectError> {
        let body = read_bounded_body(self.response, OAUTH_MAX_RESPONSE_BYTES as u64, None)
            .await
            .map_err(|error| match error {
                BodyReadError::TooLarge => OAuthDialectError::InvalidResponse,
                _ => OAuthDialectError::Failed,
            })?;
        serde_json::from_slice(&body).map_err(|_| OAuthDialectError::InvalidResponse)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support;

    #[test]
    fn permission_profiles_preserve_explicit_serialization_and_reject_null_scopes() {
        let old = serde_json::json!({
            "scopes": ["records.read"], "audience": "records-api", "target": "one"
        });
        let profile: OAuthPermissionProfile = serde_json::from_value(old.clone()).unwrap();
        assert_eq!(profile.scope_mode, OAuthScopeMode::Explicit);
        assert_eq!(serde_json::to_value(profile).unwrap(), old);
        let default = serde_json::json!({
            "scope_mode": "server_default", "audience": "records-api", "target": "one"
        });
        let profile: OAuthPermissionProfile = serde_json::from_value(default.clone()).unwrap();
        assert_eq!(profile.scope_mode, OAuthScopeMode::ServerDefault);
        assert!(profile.scopes.is_none());
        assert_eq!(serde_json::to_value(profile).unwrap(), default);
        for mode in ["explicit", "server_default"] {
            assert!(
                serde_json::from_value::<OAuthPermissionProfile>(serde_json::json!({
                    "scope_mode": mode, "scopes": null,
                    "audience": "records-api", "target": "one"
                }))
                .is_err()
            );
        }
        assert!(
            serde_json::from_value::<OAuthPermissionProfile>(serde_json::json!({
                "scope_mode": "unknown", "audience": "records-api", "target": "one"
            }))
            .is_err()
        );
    }

    fn build(base: &str, allowlist: &[String]) -> Result<OAuthHttp, ProviderBuildError> {
        OAuthHttp::build(
            "oauth.test",
            "oauth",
            &Url::parse(base).unwrap(),
            allowlist,
            &test_support::TestHost::default(),
        )
    }

    #[test]
    fn oauth_requests_the_loopback_route_only_for_literal_loopback_origins() {
        let host = test_support::TestHost::default();
        let urls = [
            "https://issuer.example/metadata".to_owned(),
            "https://localhost:9/token".to_owned(),
            "https://127.0.0.2:9443/token".to_owned(),
            "http://[::1]:8787/token".to_owned(),
        ];
        OAuthHttp::build(
            "oauth.test",
            "oauth",
            &Url::parse("http://127.0.0.1:8787/").unwrap(),
            &urls,
            &host,
        )
        .unwrap();
        let requested = host
            .built_clients()
            .into_iter()
            .map(|client| {
                (
                    client.base.origin().ascii_serialization(),
                    client.literal_loopback,
                    client.profile,
                )
            })
            .collect::<Vec<_>>();
        let profile = ClientProfile::Bounded {
            total: OAUTH_REQUEST_TIMEOUT,
            connect: OAUTH_CONNECT_TIMEOUT,
        };
        assert_eq!(
            requested,
            [
                ("http://127.0.0.1:8787".to_owned(), true, profile),
                ("https://issuer.example".to_owned(), false, profile),
                ("https://localhost:9".to_owned(), false, profile),
                ("https://127.0.0.2:9443".to_owned(), true, profile),
                ("http://[::1]:8787".to_owned(), true, profile),
            ]
        );
    }

    #[test]
    fn oauth_plain_http_requires_a_literal_loopback_address() {
        for base in ["http://127.0.0.1:8787/", "http://[::1]:8787/"] {
            build(base, &[format!("{base}token")]).unwrap();
        }
        for insecure in [
            "http://localhost:8787/",
            "http://LOCALHOST:8787/",
            "http://token.example/",
            "http://[::ffff:127.0.0.1]:8787/",
        ] {
            // Rejected as the base and as any allowlisted destination, even
            // beside an approved loopback issuer.
            assert!(build(insecure, &[]).is_err(), "{insecure}");
            assert!(
                build(
                    "http://127.0.0.1:8787/",
                    &[
                        "http://127.0.0.1:8787/token".into(),
                        format!("{insecure}token")
                    ],
                )
                .is_err(),
                "{insecure}"
            );
        }
        for invalid in [
            "ftp://127.0.0.1/token",
            "https://*.example/token",
            "https://user:pass@token.example/token",
            "token.example/token",
        ] {
            assert!(
                build("https://issuer.example/", &[invalid.into()]).is_err(),
                "{invalid}"
            );
        }
    }
}
