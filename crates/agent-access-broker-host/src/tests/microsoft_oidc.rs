use super::{TestBroker, fake_config, response_json, temp_path};
use crate::state::{MicrosoftOidcTransport, MicrosoftOidcTransportError};
use agent_access_core::microsoft_oidc::{
    MICROSOFT_OIDC_CALLBACK_PATH, MICROSOFT_OIDC_HOST, MicrosoftOidcClock,
    MicrosoftOidcProviderMetadata,
};
use agent_access_core::{
    BrokerTokensConfig, ExternalGroupBindingCreateRequest, GroupWriteRequest, IdentityConfig,
    IdentitySourceConfig, ManagedStore, ManagedStoreConfig, ManagedStoreOpenMode, ManagementConfig,
    MicrosoftOidcConfig,
};
use axum::Router;
use axum::body::Body;
use axum::extract::ConnectInfo;
use axum::http::header::{CACHE_CONTROL, LOCATION, SET_COOKIE};
use axum::http::{Method, Request, StatusCode};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chrono::{DateTime, TimeZone, Utc};
use openidconnect::core::{
    CoreAuthenticationFlow, CoreClient, CoreJwsSigningAlgorithm, CoreRsaPrivateSigningKey,
};
use openidconnect::{
    AsyncHttpClient, AuthType, AuthorizationCode, ClientId, ClientSecret, CsrfToken, HttpRequest,
    HttpResponse, JsonWebKeyId, Nonce, PkceCodeChallenge, PkceCodeVerifier, PrivateSigningKey,
    RedirectUrl, Scope, TokenResponse as OpenIdTokenResponse,
};
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap};
use std::error::Error;
use std::fmt;
use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::{Arc, Mutex};
use tower::ServiceExt;
use url::Url;

const TENANT_ID: &str = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa1";
const CLIENT_ID: &str = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbb2";
const USER_OBJECT_ID: &str = "cccccccc-cccc-4ccc-8ccc-ccccccccccc3";
const GROUP_ID: &str = "dddddddd-dddd-4ddd-8ddd-ddddddddddd4";
const CLIENT_SECRET: &str = "test-client-secret";
const INITIAL_KEY_ID: &str = "microsoft-test-key-1";
const ROTATED_KEY_ID: &str = "microsoft-test-key-2";
const FIXED_NOW: i64 = 1_893_456_000;

// Public test vector from RFC 7520 via openidconnect-rs. It is never used by production code.
const TEST_RSA_PRIVATE_KEY: &str = "-----BEGIN RSA PRIVATE KEY-----\n\
MIIEowIBAAKCAQEAn4EPtAOCc9AlkeQHPzHStgAbgs7bTZLwUBZdR8/KuKPEHLd4\n\
rHVTeT+O+XV2jRojdNhxJWTDvNd7nqQ0VEiZQHz/AJmSCpMaJMRBSFKrKb2wqVwG\n\
U/NsYOYL+QtiWN2lbzcEe6XC0dApr5ydQLrHqkHHig3RBordaZ6Aj+oBHqFEHYpP\n\
e7Tpe+OfVfHd1E6cS6M1FZcD1NNLYD5lFHpPI9bTwJlsde3uhGqC0ZCuEHg8lhzw\n\
OHrtIQbS0FVbb9k3+tVTU4fg/3L/vniUFAKwuCLqKnS2BYwdq/mzSnbLY7h/qixo\n\
R7jig3//kRhuaxwUkRz5iaiQkqgc5gHdrNP5zwIDAQABAoIBAG1lAvQfhBUSKPJK\n\
Rn4dGbshj7zDSr2FjbQf4pIh/ZNtHk/jtavyO/HomZKV8V0NFExLNi7DUUvvLiW7\n\
0PgNYq5MDEjJCtSd10xoHa4QpLvYEZXWO7DQPwCmRofkOutf+NqyDS0QnvFvp2d+\n\
Lov6jn5C5yvUFgw6qWiLAPmzMFlkgxbtjFAWMJB0zBMy2BqjntOJ6KnqtYRMQUxw\n\
TgXZDF4rhYVKtQVOpfg6hIlsaoPNrF7dofizJ099OOgDmCaEYqM++bUlEHxgrIVk\n\
wZz+bg43dfJCocr9O5YX0iXaz3TOT5cpdtYbBX+C/5hwrqBWru4HbD3xz8cY1TnD\n\
qQa0M8ECgYEA3Slxg/DwTXJcb6095RoXygQCAZ5RnAvZlno1yhHtnUex/fp7AZ/9\n\
nRaO7HX/+SFfGQeutao2TDjDAWU4Vupk8rw9JR0AzZ0N2fvuIAmr/WCsmGpeNqQn\n\
ev1T7IyEsnh8UMt+n5CafhkikzhEsrmndH6LxOrvRJlsPp6Zv8bUq0kCgYEAuKE2\n\
dh+cTf6ERF4k4e/jy78GfPYUIaUyoSSJuBzp3Cubk3OCqs6grT8bR/cu0Dm1MZwW\n\
mtdqDyI95HrUeq3MP15vMMON8lHTeZu2lmKvwqW7anV5UzhM1iZ7z4yMkuUwFWoB\n\
vyY898EXvRD+hdqRxHlSqAZ192zB3pVFJ0s7pFcCgYAHw9W9eS8muPYv4ZhDu/fL\n\
2vorDmD1JqFcHCxZTOnX1NWWAj5hXzmrU0hvWvFC0P4ixddHf5Nqd6+5E9G3k4E5\n\
2IwZCnylu3bqCWNh8pT8T3Gf5FQsfPT5530T2BcsoPhUaeCnP499D+rb2mTnFYeg\n\
mnTT1B/Ue8KGLFFfn16GKQKBgAiw5gxnbocpXPaO6/OKxFFZ+6c0OjxfN2PogWce\n\
TU/k6ZzmShdaRKwDFXisxRJeNQ5Rx6qgS0jNFtbDhW8E8WFmQ5urCOqIOYk28EBi\n\
At4JySm4v+5P7yYBh8B8YD2l9j57z/s8hJAxEbn/q8uHP2ddQqvQKgtsni+pHSk9\n\
XGBfAoGBANz4qr10DdM8DHhPrAb2YItvPVz/VwkBd1Vqj8zCpyIEKe/07oKOvjWQ\n\
SgkLDH9x2hBgY01SbP43CvPk0V72invu2TGkI/FXwXWJLLG7tDSgw4YyfhrYrHmg\n\
1Vre3XB9HH8MYBVB6UIexaAq4xSeoemRKTBesZro7OKjKT8/GmiO\n\
-----END RSA PRIVATE KEY-----";

const ROTATED_TEST_RSA_PRIVATE_KEY: &str = "-----BEGIN RSA PRIVATE KEY-----\n\
MIIEowIBAAKCAQEAzXwYwQmfDsvqHS5xShuB83SxOmVPUKZZWi7QTOuXfX5PDqOG\n\
+XWn8I/ttpGOAldWm3OLKvKqTSq4xleIcZGvYGZHkTeGKbFCvx9zUXOzxLT1r21V\n\
zKh4NNAKT6/yiOo3o7QxKdqqRO4jkHTuyDSAswDwU1+apGLBYt3ye4pZD7ltHrm8\n\
ryJJrYL6sYbuA2J8Fj/VsTgzmIEwzb58YqtAFt/uEUm5glEuByLhCz0lwLRmapGT\n\
19AhLN1aJwAo6pUnpjYLqUj8rAgsn2IAZZh58LncyCln8DAePVWjtb11gSWmNKFw\n\
LRP146GqlGwAkll/GuPVtFtMCFIhKZRw5/tE4QIDAQABAoIBAB5knA61Wxrnq12c\n\
mHIjJnH5kRs3j+c4a5/sq6+s6w/LRms+YcD1F5171Ge8GLqc63j7uppkIS9fwcvI\n\
d6yApWWHS0+d3FC/YMV/I+Ho0K6oK2zCqb2nL3x0RwopVqDMr+UdSmZL6wJeDNGZ\n\
khX3ug9/9IwIaImm976lYG/Ic0rhWPpp2QSevji9Z/tWKRgIWPQjwJlAhPtSfeQ+\n\
YlVPv10naY6xOYb3I115zdCrH5ODa5zqQwXYh5kD2BnmGIkkxPq2raQxUM6ouECt\n\
AyUPbFrD6Fcau6kK8M4Arw5pyPeB933Urvn7gMr8EyLTDHwBCReP8xbd3qPBTkFg\n\
a3RYjE8CgYEA5ttn7FbM7kOjFgvo/Yz8yb1WTflPPV+tOsDqswsXPl5K+lwI48/B\n\
1awgEuRdTwhXY1XE1dPtdM0qEMGCM5KpCTxreXEubw245wF6Vyyem0fwTiHnDpFU\n\
CXFGSJOSl5wx30UlQ1+FEZ9CnZ/GA/N6KL9Wtc/xXyqZuLmCeQ59izMCgYEA491H\n\
L5QQkIzCEi8CI3r+ecdTHz4UgTt4OOY/vwzqoAWZA3H+gGqW/sIpa+INj2yboCEf\n\
gteK5yxcpb5vEK8hqSR9HbefdXDzYfGW59nEqC9SxybzUzW5bEDlTCFdvAr7zjrW\n\
/S6t8SD5ETyVNWmoJvn6/0FIn24nsnVp2Z3wD5sCgYAikRW1gKW8w2nnAi+Hz5WG\n\
S5BhqoPf57STiJFb77wyPYIyjJdULSaT7Or8iS8jh1c2a4BGmC4FADddPOxW9o3S\n\
8TYSgAz42fAmvsTnyqmRDKuBt3fWaZJQu6JPebFIfD3HdZ4HwYS2R8d8vJC0xL80\n\
3LmKDbHRkxpjW3uazr2jmwKBgQC9iQS6Za21nu+a0nEz9A2SXCMe/LNvn3jr01G4\n\
59SNkLprLDnmtUKt2/E6ZIilAVEdzA969TD8A2F5GEMoHJSiLdDIlEFWHcLEeIDu\n\
j6xNvTdcomCJmUmH6x8PyT0/ud8j9rt3U4mp5aRnGv59tEoDSbHm+nWe77Cjd5i5\n\
Q+83+wKBgChFZSXxfebcl12Lg4csEuO8HnTANs9x8pzASwE65DTwq3jeImDOltT5\n\
Lx3h6Dt0U1UkiuX/ZYnvocrLl5Mh5jCoSZ5iDJBIN7JOU50DxLo6EEmkG0S0D0ZK\n\
FhLLN2jKwUJYMo5q0kFboM6aPDJvvZNMivHWsdOdDiQdpV5/TyQs\n\
-----END RSA PRIVATE KEY-----";

#[derive(Debug, Clone, PartialEq, Eq)]
enum FakeGroupClaims {
    Complete(Vec<String>),
    Empty,
    Overage,
    Malformed,
}

#[derive(Debug, Clone)]
struct FakeTokenClaims {
    tenant_id: String,
    user_object_id: String,
    audience: Vec<String>,
    authorized_party: Option<String>,
    groups: FakeGroupClaims,
    expires_at: i64,
    issued_at: i64,
    not_before: Option<i64>,
    issuer: String,
    subject: String,
    name: Option<String>,
    preferred_username: Option<String>,
    email: Option<String>,
    nonce_override: Option<String>,
    duplicate_tenant_claim: bool,
    corrupt_signature: bool,
}

impl FakeTokenClaims {
    fn valid(now: i64) -> Self {
        Self {
            tenant_id: TENANT_ID.to_string(),
            user_object_id: USER_OBJECT_ID.to_string(),
            audience: vec![CLIENT_ID.to_string()],
            authorized_party: None,
            groups: FakeGroupClaims::Complete(vec![GROUP_ID.to_string()]),
            expires_at: now + 300,
            issued_at: now,
            not_before: Some(now),
            issuer: format!("https://{MICROSOFT_OIDC_HOST}/{TENANT_ID}/v2.0"),
            subject: "microsoft-subject".to_string(),
            name: Some("Ada Lovelace".to_string()),
            preferred_username: Some("ada.lovelace@example.test".to_string()),
            email: Some("ada@example.test".to_string()),
            nonce_override: None,
            duplicate_tenant_claim: false,
            corrupt_signature: false,
        }
    }
}

#[derive(Debug, Clone)]
struct AuthorizationGrant {
    code_challenge: String,
    nonce: String,
    redirect_uri: String,
    claims: FakeTokenClaims,
    signing_key_id: String,
}

#[derive(Debug, Default)]
struct FakeProviderState {
    active_key_id: String,
    next_claims: Option<FakeTokenClaims>,
    grants: HashMap<String, AuthorizationGrant>,
    next_code: u64,
    discovery_requests: usize,
    jwks_requests: usize,
    token_requests: usize,
    last_token_rejection: Option<&'static str>,
    discovery_outage: bool,
    jwks_outage: bool,
    token_outage: bool,
}

#[derive(Clone)]
struct FakeMicrosoftOidcProvider {
    state: Arc<Mutex<FakeProviderState>>,
    clock: TestClock,
}

impl fmt::Debug for FakeMicrosoftOidcProvider {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let state = self.state.lock().unwrap();
        formatter
            .debug_struct("FakeMicrosoftOidcProvider")
            .field("active_key_id", &state.active_key_id)
            .field("discovery_requests", &state.discovery_requests)
            .field("jwks_requests", &state.jwks_requests)
            .field("token_requests", &state.token_requests)
            .finish_non_exhaustive()
    }
}

impl FakeMicrosoftOidcProvider {
    fn new(clock: TestClock) -> Self {
        Self {
            state: Arc::new(Mutex::new(FakeProviderState {
                active_key_id: INITIAL_KEY_ID.to_string(),
                next_code: 1,
                ..FakeProviderState::default()
            })),
            clock,
        }
    }

    fn set_next_claims(&self, claims: FakeTokenClaims) {
        self.state.lock().unwrap().next_claims = Some(claims);
    }

    fn set_token_outage(&self, outage: bool) {
        self.state.lock().unwrap().token_outage = outage;
    }

    fn set_discovery_outage(&self, outage: bool) {
        self.state.lock().unwrap().discovery_outage = outage;
    }

    fn set_jwks_outage(&self, outage: bool) {
        self.state.lock().unwrap().jwks_outage = outage;
    }

    fn rotate_signing_key(&self) {
        self.state.lock().unwrap().active_key_id = ROTATED_KEY_ID.to_string();
    }

    fn request_counts(&self) -> (usize, usize, usize) {
        let state = self.state.lock().unwrap();
        (
            state.discovery_requests,
            state.jwks_requests,
            state.token_requests,
        )
    }

    fn last_token_rejection(&self) -> Option<&'static str> {
        self.state.lock().unwrap().last_token_rejection
    }

    fn authorize(&self, authorization_location: &str) -> Result<String, FakeProviderError> {
        let url = Url::parse(authorization_location)
            .map_err(|_| FakeProviderError::InvalidAuthorizationRequest)?;
        if url.scheme() != "https"
            || url.host_str() != Some(MICROSOFT_OIDC_HOST)
            || url.path() != format!("/{TENANT_ID}/oauth2/v2.0/authorize")
        {
            return Err(FakeProviderError::InvalidAuthorizationRequest);
        }
        let query = query_parameters(&url)?;
        require_parameter(&query, "client_id", CLIENT_ID)?;
        require_parameter(&query, "response_type", "code")?;
        require_parameter(&query, "response_mode", "query")?;
        require_parameter(&query, "code_challenge_method", "S256")?;
        let scopes = query
            .get("scope")
            .ok_or(FakeProviderError::InvalidAuthorizationRequest)?
            .split(' ')
            .collect::<Vec<_>>();
        if scopes != ["openid", "profile", "email"] {
            return Err(FakeProviderError::InvalidAuthorizationRequest);
        }
        let state_value = query
            .get("state")
            .filter(|value| !value.is_empty())
            .ok_or(FakeProviderError::InvalidAuthorizationRequest)?;
        let nonce = query
            .get("nonce")
            .filter(|value| !value.is_empty())
            .ok_or(FakeProviderError::InvalidAuthorizationRequest)?
            .clone();
        let code_challenge = query
            .get("code_challenge")
            .filter(|value| !value.is_empty())
            .ok_or(FakeProviderError::InvalidAuthorizationRequest)?
            .clone();
        let redirect_uri = query
            .get("redirect_uri")
            .filter(|value| {
                value.as_str()
                    == format!("https://broker.example.test{MICROSOFT_OIDC_CALLBACK_PATH}")
            })
            .ok_or(FakeProviderError::InvalidAuthorizationRequest)?
            .clone();

        let mut provider = self.state.lock().unwrap();
        let code = format!("fake-code-{}", provider.next_code);
        provider.next_code += 1;
        let claims = provider
            .next_claims
            .take()
            .unwrap_or_else(|| FakeTokenClaims::valid(self.clock.now_timestamp()));
        let signing_key_id = provider.active_key_id.clone();
        provider.grants.insert(
            code.clone(),
            AuthorizationGrant {
                code_challenge,
                nonce,
                redirect_uri: redirect_uri.clone(),
                claims,
                signing_key_id,
            },
        );

        let mut callback = Url::parse(&redirect_uri)
            .map_err(|_| FakeProviderError::InvalidAuthorizationRequest)?;
        callback
            .query_pairs_mut()
            .append_pair("code", &code)
            .append_pair("state", state_value);
        Ok(callback.into())
    }

    fn discovery_response(&self) -> Result<HttpResponse, FakeProviderError> {
        let mut state = self.state.lock().unwrap();
        state.discovery_requests += 1;
        if state.discovery_outage {
            return Err(FakeProviderError::ProviderUnavailable);
        }
        json_response(json!({
            "issuer": format!("https://{MICROSOFT_OIDC_HOST}/{TENANT_ID}/v2.0"),
            "authorization_endpoint": format!("https://{MICROSOFT_OIDC_HOST}/{TENANT_ID}/oauth2/v2.0/authorize"),
            "token_endpoint": format!("https://{MICROSOFT_OIDC_HOST}/{TENANT_ID}/oauth2/v2.0/token"),
            "jwks_uri": format!("https://{MICROSOFT_OIDC_HOST}/{TENANT_ID}/discovery/v2.0/keys"),
            "response_types_supported": ["code"],
            "response_modes_supported": ["query"],
            "subject_types_supported": ["pairwise"],
            "id_token_signing_alg_values_supported": ["RS256"],
            "token_endpoint_auth_methods_supported": ["client_secret_post"],
            "scopes_supported": ["openid", "profile", "email"],
        }))
    }

    fn jwks_response(&self) -> Result<HttpResponse, FakeProviderError> {
        let mut state = self.state.lock().unwrap();
        state.jwks_requests += 1;
        if state.jwks_outage {
            return Err(FakeProviderError::ProviderUnavailable);
        }
        let signing_key = signing_key(&state.active_key_id);
        json_response(json!({"keys": [signing_key.as_verification_key()]}))
    }

    fn token_response(&self, request: &HttpRequest) -> Result<HttpResponse, FakeProviderError> {
        let mut state = self.state.lock().unwrap();
        state.token_requests += 1;
        if state.token_outage {
            state.last_token_rejection = Some("outage");
            return Err(FakeProviderError::ProviderUnavailable);
        }
        let form = form_parameters(request.body())?;
        for (name, expected) in [
            ("grant_type", "authorization_code"),
            ("client_id", CLIENT_ID),
            ("client_secret", CLIENT_SECRET),
        ] {
            if form.get(name).map(String::as_str) != Some(expected) {
                state.last_token_rejection = Some(name);
                return Err(FakeProviderError::InvalidTokenRequest);
            }
        }
        let code = form.get("code").ok_or_else(|| {
            state.last_token_rejection = Some("code");
            FakeProviderError::InvalidTokenRequest
        })?;
        let verifier = form.get("code_verifier").ok_or_else(|| {
            state.last_token_rejection = Some("code_verifier");
            FakeProviderError::InvalidTokenRequest
        })?;
        let grant = state.grants.remove(code).ok_or_else(|| {
            state.last_token_rejection = Some("unknown_code");
            FakeProviderError::InvalidTokenRequest
        })?;
        if form.get("redirect_uri") != Some(&grant.redirect_uri) {
            state.last_token_rejection = Some("redirect_uri");
            return Err(FakeProviderError::InvalidTokenRequest);
        }
        if pkce_challenge(verifier) != grant.code_challenge {
            state.last_token_rejection = Some("pkce");
            return Err(FakeProviderError::InvalidTokenRequest);
        }
        state.last_token_rejection = None;
        drop(state);

        let id_token = sign_id_token(&grant)?;
        json_response(json!({
            "access_token": "fake-access-token",
            "token_type": "Bearer",
            "expires_in": 300,
            "scope": "openid profile email",
            "id_token": id_token,
        }))
    }

    fn handle(&self, request: HttpRequest) -> Result<HttpResponse, FakeProviderError> {
        let url = Url::parse(&request.uri().to_string())
            .map_err(|_| FakeProviderError::UnexpectedRequest)?;
        if url.scheme() != "https" || url.host_str() != Some(MICROSOFT_OIDC_HOST) {
            return Err(FakeProviderError::UnexpectedRequest);
        }
        let method = request.method().as_str();
        let path = url.path();
        if method == "GET"
            && path == format!("/{TENANT_ID}/v2.0/.well-known/openid-configuration")
            && request.body().is_empty()
        {
            self.discovery_response()
        } else if method == "GET"
            && path == format!("/{TENANT_ID}/discovery/v2.0/keys")
            && request.body().is_empty()
        {
            self.jwks_response()
        } else if method == "POST" && path == format!("/{TENANT_ID}/oauth2/v2.0/token") {
            self.token_response(&request)
        } else {
            Err(FakeProviderError::UnexpectedRequest)
        }
    }
}

impl<'c> AsyncHttpClient<'c> for FakeMicrosoftOidcProvider {
    type Error = FakeProviderError;
    type Future =
        Pin<Box<dyn Future<Output = Result<HttpResponse, Self::Error>> + Send + Sync + 'c>>;

    fn call(&'c self, request: HttpRequest) -> Self::Future {
        Box::pin(async move { self.handle(request) })
    }
}

impl MicrosoftOidcTransport for FakeMicrosoftOidcProvider {
    fn call<'a>(
        &'a self,
        request: HttpRequest,
    ) -> Pin<
        Box<
            dyn Future<Output = Result<HttpResponse, MicrosoftOidcTransportError>>
                + Send
                + Sync
                + 'a,
        >,
    > {
        Box::pin(async move {
            self.handle(request)
                .map_err(|_| MicrosoftOidcTransportError)
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum FakeProviderError {
    ProviderUnavailable,
    UnexpectedRequest,
    InvalidAuthorizationRequest,
    InvalidTokenRequest,
    SigningFailed,
    ResponseConstructionFailed,
}

impl fmt::Display for FakeProviderError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::ProviderUnavailable => "fake Microsoft provider is unavailable",
            Self::UnexpectedRequest => "unexpected fake Microsoft provider request",
            Self::InvalidAuthorizationRequest => "invalid authorization request",
            Self::InvalidTokenRequest => "invalid token request",
            Self::SigningFailed => "test token signing failed",
            Self::ResponseConstructionFailed => "test response construction failed",
        })
    }
}

impl Error for FakeProviderError {}

#[derive(Debug, Clone)]
struct TestClock(Arc<AtomicI64>);

impl TestClock {
    fn new(timestamp: i64) -> Self {
        Self(Arc::new(AtomicI64::new(timestamp)))
    }

    fn now_timestamp(&self) -> i64 {
        self.0.load(Ordering::SeqCst)
    }

    fn advance_seconds(&self, seconds: i64) {
        self.0.fetch_add(seconds, Ordering::SeqCst);
    }
}

impl MicrosoftOidcClock for TestClock {
    fn now(&self) -> DateTime<Utc> {
        Utc.timestamp_opt(self.now_timestamp(), 0)
            .single()
            .expect("fixed test timestamp is valid")
    }
}

fn query_parameters(url: &Url) -> Result<BTreeMap<String, String>, FakeProviderError> {
    unique_parameters(
        url.query_pairs()
            .map(|(key, value)| (key.into(), value.into())),
    )
}

fn form_parameters(body: &[u8]) -> Result<BTreeMap<String, String>, FakeProviderError> {
    unique_parameters(
        url::form_urlencoded::parse(body).map(|(key, value)| (key.into(), value.into())),
    )
}

fn unique_parameters(
    pairs: impl IntoIterator<Item = (String, String)>,
) -> Result<BTreeMap<String, String>, FakeProviderError> {
    let mut parameters = BTreeMap::new();
    for (key, value) in pairs {
        if parameters.insert(key, value).is_some() {
            return Err(FakeProviderError::UnexpectedRequest);
        }
    }
    Ok(parameters)
}

fn require_parameter(
    parameters: &BTreeMap<String, String>,
    name: &str,
    expected: &str,
) -> Result<(), FakeProviderError> {
    if parameters.get(name).map(String::as_str) == Some(expected) {
        Ok(())
    } else {
        Err(FakeProviderError::InvalidTokenRequest)
    }
}

fn pkce_challenge(verifier: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()))
}

fn signing_key(key_id: &str) -> CoreRsaPrivateSigningKey {
    let pem = if key_id == ROTATED_KEY_ID {
        ROTATED_TEST_RSA_PRIVATE_KEY
    } else {
        TEST_RSA_PRIVATE_KEY
    };
    CoreRsaPrivateSigningKey::from_pem(pem, Some(JsonWebKeyId::new(key_id.to_string())))
        .expect("fixed test RSA key is valid")
}

fn sign_id_token(grant: &AuthorizationGrant) -> Result<String, FakeProviderError> {
    let mut payload = Map::from_iter([
        (
            "iss".to_string(),
            Value::String(grant.claims.issuer.clone()),
        ),
        (
            "sub".to_string(),
            Value::String(grant.claims.subject.clone()),
        ),
        ("aud".to_string(), json!(grant.claims.audience)),
        ("exp".to_string(), json!(grant.claims.expires_at)),
        ("iat".to_string(), json!(grant.claims.issued_at)),
        (
            "tid".to_string(),
            Value::String(grant.claims.tenant_id.clone()),
        ),
        (
            "oid".to_string(),
            Value::String(grant.claims.user_object_id.clone()),
        ),
        (
            "nonce".to_string(),
            Value::String(
                grant
                    .claims
                    .nonce_override
                    .clone()
                    .unwrap_or_else(|| grant.nonce.clone()),
            ),
        ),
    ]);
    if let Some(authorized_party) = &grant.claims.authorized_party {
        payload.insert("azp".to_string(), Value::String(authorized_party.clone()));
    }
    if let Some(name) = &grant.claims.name {
        payload.insert("name".to_string(), Value::String(name.clone()));
    }
    if let Some(preferred_username) = &grant.claims.preferred_username {
        payload.insert(
            "preferred_username".to_string(),
            Value::String(preferred_username.clone()),
        );
    }
    if let Some(email) = &grant.claims.email {
        payload.insert("email".to_string(), Value::String(email.clone()));
    }
    if let Some(not_before) = grant.claims.not_before {
        payload.insert("nbf".to_string(), json!(not_before));
    }
    match &grant.claims.groups {
        FakeGroupClaims::Complete(groups) => {
            payload.insert("groups".to_string(), json!(groups));
        }
        FakeGroupClaims::Empty => {
            payload.insert("groups".to_string(), json!([]));
        }
        FakeGroupClaims::Overage => {
            payload.insert("hasgroups".to_string(), Value::Bool(true));
        }
        FakeGroupClaims::Malformed => {
            payload.insert("groups".to_string(), Value::String("invalid".to_string()));
        }
    }
    let header = json!({"alg": "RS256", "kid": grant.signing_key_id, "typ": "JWT"});
    let header = URL_SAFE_NO_PAD
        .encode(serde_json::to_vec(&header).map_err(|_| FakeProviderError::SigningFailed)?);
    let mut payload =
        serde_json::to_string(&payload).map_err(|_| FakeProviderError::SigningFailed)?;
    if grant.claims.duplicate_tenant_claim {
        payload.insert_str(1, &format!("\"tid\":\"{}\",", grant.claims.tenant_id));
    }
    let payload = URL_SAFE_NO_PAD.encode(payload.as_bytes());
    let signing_input = format!("{header}.{payload}");
    let mut signature = signing_key(&grant.signing_key_id)
        .sign(
            &CoreJwsSigningAlgorithm::RsaSsaPkcs1V15Sha256,
            signing_input.as_bytes(),
        )
        .map_err(|_| FakeProviderError::SigningFailed)?;
    if grant.claims.corrupt_signature
        && let Some(first) = signature.first_mut()
    {
        *first ^= 0x80;
    }
    Ok(format!(
        "{signing_input}.{}",
        URL_SAFE_NO_PAD.encode(signature)
    ))
}

fn json_response(value: Value) -> Result<HttpResponse, FakeProviderError> {
    axum::http::Response::builder()
        .status(200)
        .header("content-type", "application/json")
        .body(
            serde_json::to_vec(&value)
                .map_err(|_| FakeProviderError::ResponseConstructionFailed)?,
        )
        .map_err(|_| FakeProviderError::ResponseConstructionFailed)
}

struct OidcBrowserFixture {
    _broker: TestBroker,
    app: Router,
    provider: FakeMicrosoftOidcProvider,
    clock: TestClock,
    store: ManagedStore,
    audit_path: std::path::PathBuf,
}

struct PendingBrowserLogin {
    callback_uri: String,
    binding_cookie: String,
}

async fn oidc_browser_fixture(discovery_outage: bool) -> OidcBrowserFixture {
    oidc_browser_fixture_with_audit(
        discovery_outage,
        temp_path("microsoft-oidc-browser.audit.jsonl"),
    )
    .await
}

async fn oidc_browser_fixture_with_audit(
    discovery_outage: bool,
    audit_path: std::path::PathBuf,
) -> OidcBrowserFixture {
    let store_path = temp_path("microsoft-oidc-browser.sqlite");
    let broker_hash_key_path = temp_path("microsoft-oidc-broker-hash-key");
    let csrf_key_path = temp_path("microsoft-oidc-csrf-key");
    let password_pepper_path = temp_path("microsoft-oidc-password-pepper");
    let client_secret_path = temp_path("microsoft-oidc-client-secret");
    let flow_key_path = temp_path("microsoft-oidc-flow-key");
    std::fs::write(&broker_hash_key_path, URL_SAFE_NO_PAD.encode([11_u8; 32])).unwrap();
    std::fs::write(&csrf_key_path, URL_SAFE_NO_PAD.encode([12_u8; 32])).unwrap();
    std::fs::write(&password_pepper_path, URL_SAFE_NO_PAD.encode([13_u8; 32])).unwrap();
    std::fs::write(&client_secret_path, CLIENT_SECRET).unwrap();
    std::fs::write(&flow_key_path, URL_SAFE_NO_PAD.encode([14_u8; 32])).unwrap();

    let mut config = fake_config(audit_path.to_str().unwrap());
    config.deployment.enable_fake_service = false;
    config.providers.remove("fake");
    config.credentials.service.clear();
    config.policy.grants.clear();
    config.identity = IdentityConfig {
        trusted_callers: Default::default(),
        mode: "required".to_string(),
        authority: "managed".to_string(),
        sources: vec![IdentitySourceConfig {
            name: "broker".to_string(),
            kind: "broker_tokens".to_string(),
            header: "Authorization".to_string(),
            scheme: "Bearer".to_string(),
            principals: vec![],
        }],
        groups: vec![],
    };
    config.managed_store = Some(ManagedStoreConfig {
        kind: "sqlite".to_string(),
        path: store_path.display().to_string(),
        require_registered_principal_for_invocation: true,
        auto_migrate: true,
    });
    config.management = ManagementConfig {
        enabled: true,
        ..ManagementConfig::default()
    };
    config.broker_tokens = Some(BrokerTokensConfig {
        hash_key_ref: format!("file:{}", broker_hash_key_path.display()),
        ..BrokerTokensConfig::default()
    });
    config.browser_auth.enabled = true;
    config.browser_auth.public_origin = Some("https://broker.example.test".to_string());
    config.browser_auth.session_cookie_name = "aab_session".to_string();
    config.browser_auth.csrf_key_ref = Some(format!("file:{}", csrf_key_path.display()));
    config.browser_auth.allowed_return_paths = vec!["/ui".to_string()];
    config.browser_auth.local_password.enabled = true;
    config.browser_auth.local_password.pepper_ref =
        Some(format!("file:{}", password_pepper_path.display()));
    config.browser_auth.oidc.microsoft = MicrosoftOidcConfig {
        enabled: true,
        tenant_id: Some(TENANT_ID.to_string()),
        client_id: Some(CLIENT_ID.to_string()),
        client_secret_ref: Some(format!("file:{}", client_secret_path.display())),
        flow_key_ref: Some(format!("file:{}", flow_key_path.display())),
        flow_ttl: "10m".to_string(),
        max_pending_flows: 100,
        jit_provisioning: true,
        external_membership_ttl: "8h".to_string(),
    };

    let store = ManagedStore::open(
        config.managed_store.as_ref().unwrap(),
        ManagedStoreOpenMode::Startup,
    )
    .unwrap();
    store
        .create_group(GroupWriteRequest {
            group_id: "microsoft-users".to_string(),
            display_name: Some("Microsoft users".to_string()),
            description: None,
            auto_enroll_new_microsoft_users: false,
            created_by: "test".to_string(),
        })
        .unwrap();
    store
        .create_external_group_binding(ExternalGroupBindingCreateRequest {
            external_group_id: GROUP_ID.to_string(),
            group_id: "microsoft-users".to_string(),
            actor: "test".to_string(),
        })
        .unwrap();

    let clock = TestClock::new(FIXED_NOW);
    let provider = FakeMicrosoftOidcProvider::new(clock.clone());
    provider.set_discovery_outage(discovery_outage);
    let broker = TestBroker::start_with(
        TestBroker::config_builder(&config)
            .microsoft_oidc_components(Arc::new(provider.clone()), Arc::new(clock.clone())),
    )
    .await;
    OidcBrowserFixture {
        app: broker.app(),
        _broker: broker,
        provider,
        clock,
        store,
        audit_path,
    }
}

async fn start_browser_login(
    fixture: &OidcBrowserFixture,
    binding_cookie: Option<&str>,
) -> PendingBrowserLogin {
    let mut builder = Request::builder()
        .method(Method::GET)
        .uri("/v1/auth/oidc/microsoft/start?returnTo=%2Fui%2Fsettings")
        .extension(ConnectInfo(
            "127.0.0.1:43410".parse::<SocketAddr>().unwrap(),
        ))
        .header(
            agent_access_provider::REQUEST_ID_HEADER,
            "oidc-browser-start",
        )
        .header("Host", "broker.example.test");
    if let Some(binding_cookie) = binding_cookie {
        builder = builder.header("Cookie", binding_cookie);
    }
    let response = fixture
        .app
        .clone()
        .oneshot(builder.body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    assert_eq!(response.headers().get(CACHE_CONTROL).unwrap(), "no-store");
    assert_eq!(
        response.headers().get("referrer-policy").unwrap(),
        "no-referrer"
    );
    let location = response
        .headers()
        .get(LOCATION)
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    let set_cookie = response
        .headers()
        .get_all(SET_COOKIE)
        .iter()
        .find_map(|value| {
            let value = value.to_str().ok()?;
            value
                .starts_with("__Host-aab_oidc_binding=")
                .then(|| value.to_string())
        })
        .expect("start sets the browser binding cookie");
    assert!(set_cookie.contains("; Path=/"));
    assert!(set_cookie.contains("; HttpOnly"));
    assert!(set_cookie.contains("; Secure"));
    assert!(set_cookie.contains("; SameSite=Lax"));
    assert!(set_cookie.contains("; Max-Age=600"));
    assert!(!set_cookie.to_ascii_lowercase().contains("domain="));
    let binding_cookie = set_cookie.split(';').next().unwrap().to_string();
    let callback_uri = fixture.provider.authorize(&location).unwrap();
    PendingBrowserLogin {
        callback_uri,
        binding_cookie,
    }
}

async fn finish_browser_login(
    fixture: &OidcBrowserFixture,
    pending: &PendingBrowserLogin,
    request_id: &str,
) -> axum::response::Response {
    finish_browser_login_with(
        fixture,
        &pending.callback_uri,
        &pending.binding_cookie,
        request_id,
    )
    .await
}

async fn finish_browser_login_with(
    fixture: &OidcBrowserFixture,
    callback_uri: &str,
    binding_cookie: &str,
    request_id: &str,
) -> axum::response::Response {
    let callback = Url::parse(callback_uri).unwrap();
    let relative = callback
        .query()
        .map(|query| format!("{}?{query}", callback.path()))
        .unwrap_or_else(|| callback.path().to_string());
    fixture
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri(relative)
                .extension(ConnectInfo(
                    "127.0.0.1:43411".parse::<SocketAddr>().unwrap(),
                ))
                .header(agent_access_provider::REQUEST_ID_HEADER, request_id)
                .header("Host", "broker.example.test")
                .header("Cookie", binding_cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap()
}

fn session_cookie(response: &axum::response::Response) -> Option<String> {
    response
        .headers()
        .get_all(SET_COOKIE)
        .iter()
        .find_map(|value| {
            let value = value.to_str().ok()?;
            value
                .starts_with("aab_session=")
                .then(|| value.split(';').next().unwrap().to_string())
        })
}

fn assert_callback_error(response: &axum::response::Response, reason_code: &str, request_id: &str) {
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    assert_eq!(
        response.headers().get(LOCATION).unwrap().to_str().unwrap(),
        format!("/ui/login?error={reason_code}&requestId={request_id}")
    );
    assert!(session_cookie(response).is_none());
}

#[tokio::test]
async fn microsoft_oidc_browser_happy_path_binds_code_pkce_nonce_cookie_and_rejects_replay() {
    let fixture = oidc_browser_fixture(false).await;
    let pending = start_browser_login(&fixture, None).await;
    let response = finish_browser_login(&fixture, &pending, "oidc-happy-callback").await;
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    assert_eq!(
        response.headers().get(LOCATION).unwrap(),
        "/ui/settings",
        "fake token rejection: {:?}",
        fixture.provider.last_token_rejection()
    );
    let browser_session_cookie = session_cookie(&response).expect("browser session cookie");
    assert_eq!(fixture.provider.request_counts(), (1, 1, 1));

    let principals = fixture.store.list_principals().unwrap();
    assert_eq!(principals.len(), 1);
    let principal = &principals[0];
    assert!(principal.principal_id.starts_with("usr-"));
    assert_eq!(principal.display_name.as_deref(), Some("Ada Lovelace"));
    assert_eq!(principal.email.as_deref(), Some("ada@example.test"));
    let session_response = fixture
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri("/v1/auth/session")
                .extension(ConnectInfo(
                    "127.0.0.1:43412".parse::<SocketAddr>().unwrap(),
                ))
                .header(
                    agent_access_provider::REQUEST_ID_HEADER,
                    "oidc-happy-session",
                )
                .header("Cookie", browser_session_cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(session_response.status(), StatusCode::OK);
    let session_body = response_json(session_response).await;
    assert_eq!(session_body["result"]["principal"], principal.principal_id);
    assert_eq!(session_body["result"]["displayName"], "Ada Lovelace");
    assert_eq!(session_body["result"]["email"], "ada@example.test");
    let methods = fixture
        .store
        .list_login_methods(&principal.principal_id)
        .unwrap();
    assert_eq!(methods.len(), 1);
    assert_eq!(methods[0].method, "oidc");
    assert_eq!(
        methods[0].external_subject.as_deref(),
        Some(format!("entra:v1:{TENANT_ID}:{USER_OBJECT_ID}").as_str())
    );
    let membership = fixture
        .store
        .effective_membership_at(&principal.principal_id, &fixture.clock.now().to_rfc3339())
        .unwrap();
    assert_eq!(membership.groups, ["microsoft-users"]);
    assert_eq!(
        login_success_audit(&fixture, "oidc-happy-callback")["autoEnrolledGroupIds"],
        json!([])
    );

    let replay = finish_browser_login(&fixture, &pending, "oidc-replay-callback").await;
    assert_callback_error(&replay, "oidc_flow_invalid", "oidc-replay-callback");
    assert_eq!(fixture.provider.request_counts(), (1, 1, 1));
}

fn login_success_audit(fixture: &OidcBrowserFixture, request_id: &str) -> Value {
    let records = super::read_audit_records(&fixture.audit_path);
    let record = records
        .iter()
        .find(|record| {
            record["agentRequestId"] == request_id
                && record["action"]
                    == crate::handlers::management::audit_actions::OIDC_LOGIN_SUCCEEDED
        })
        .expect("successful login audit");
    record["providerAudit"]["oidc"].clone()
}

#[tokio::test]
async fn microsoft_oidc_browser_enrolls_new_users_once_with_persistent_local_memberships() {
    let fixture = oidc_browser_fixture(false).await;
    for group in ["baseline", "paused"] {
        fixture
            .store
            .create_group(GroupWriteRequest {
                group_id: group.into(),
                display_name: None,
                description: None,
                auto_enroll_new_microsoft_users: true,
                created_by: "test".into(),
            })
            .unwrap();
    }
    fixture
        .store
        .patch_group(agent_access_core::GroupPatchRequest {
            group_id: "paused".into(),
            display_name: None,
            description: None,
            status: Some("disabled".into()),
            auto_enroll_new_microsoft_users: None,
            updated_by: "test".into(),
        })
        .unwrap();
    fixture
        .store
        .patch_group(agent_access_core::GroupPatchRequest {
            group_id: "microsoft-users".into(),
            display_name: None,
            description: None,
            status: None,
            auto_enroll_new_microsoft_users: Some(true),
            updated_by: "test".into(),
        })
        .unwrap();
    let pending = start_browser_login(&fixture, None).await;
    let response = finish_browser_login(&fixture, &pending, "oidc-enrollment-new").await;
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    assert!(session_cookie(&response).is_some());
    let principal_id = fixture.store.list_principals().unwrap()[0]
        .principal_id
        .clone();
    let membership = fixture
        .store
        .effective_membership_at(&principal_id, &fixture.clock.now().to_rfc3339())
        .unwrap();
    assert_eq!(membership.groups, ["baseline", "microsoft-users"]);
    assert_eq!(
        membership
            .details
            .iter()
            .find(|group| group.group_id == "baseline")
            .unwrap()
            .source,
        "local"
    );
    assert_eq!(
        membership
            .details
            .iter()
            .find(|group| group.group_id == "microsoft-users")
            .unwrap()
            .source,
        "local_and_microsoft"
    );
    for group in &membership.details {
        assert_eq!(group.local.as_ref().unwrap().added_by, "oidc-microsoft");
    }
    let audit = login_success_audit(&fixture, "oidc-enrollment-new");
    assert_eq!(audit["jitCreated"], true);
    assert_eq!(
        audit["autoEnrolledGroupIds"],
        json!(["baseline", "microsoft-users"])
    );

    fixture.clock.advance_seconds(8 * 60 * 60 + 1);
    let membership = fixture
        .store
        .effective_membership_at(&principal_id, &fixture.clock.now().to_rfc3339())
        .unwrap();
    assert_eq!(membership.groups, ["baseline", "microsoft-users"]);
    fixture
        .store
        .remove_group(&principal_id, "baseline")
        .unwrap();
    fixture
        .store
        .create_group(GroupWriteRequest {
            group_id: "later-default".into(),
            display_name: None,
            description: None,
            auto_enroll_new_microsoft_users: true,
            created_by: "test".into(),
        })
        .unwrap();
    // Authoritative empty Microsoft evidence removes its contribution. New
    // defaults and manually removed local memberships do not reappear.
    let mut claims = FakeTokenClaims::valid(fixture.clock.now().timestamp());
    claims.groups = FakeGroupClaims::Empty;
    fixture.provider.set_next_claims(claims);
    let returning = start_browser_login(&fixture, Some(&pending.binding_cookie)).await;
    let response = finish_browser_login(&fixture, &returning, "oidc-enrollment-returning").await;
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    assert!(session_cookie(&response).is_some());
    let membership = fixture
        .store
        .effective_membership_at(&principal_id, &fixture.clock.now().to_rfc3339())
        .unwrap();
    assert_eq!(membership.groups, ["microsoft-users"]);
    assert_eq!(membership.details[0].source, "local");
    let audit = login_success_audit(&fixture, "oidc-enrollment-returning");
    assert_eq!(audit["jitCreated"], false);
    assert_eq!(audit["autoEnrolledGroupIds"], json!([]));
}

#[tokio::test]
async fn microsoft_oidc_browser_audit_failure_does_not_repeat_committed_enrollment() {
    let fixture =
        oidc_browser_fixture_with_audit(false, temp_path("microsoft-enrollment.audit.sqlite"))
            .await;
    fixture
        .store
        .create_group(GroupWriteRequest {
            group_id: "baseline".into(),
            display_name: None,
            description: None,
            auto_enroll_new_microsoft_users: true,
            created_by: "test".into(),
        })
        .unwrap();
    let connection = rusqlite::Connection::open(&fixture.audit_path).unwrap();
    connection.execute_batch(&format!(
        "CREATE TRIGGER fail_login_success_audit BEFORE INSERT ON audit_events WHEN NEW.action = '{}' BEGIN SELECT RAISE(ABORT, 'injected-audit-failure'); END;",
        crate::handlers::management::audit_actions::OIDC_LOGIN_SUCCEEDED,
    )).unwrap();
    let pending = start_browser_login(&fixture, None).await;
    let response = finish_browser_login(&fixture, &pending, "oidc-enrollment-audit-failure").await;
    assert_callback_error(
        &response,
        "audit_unavailable",
        "oidc-enrollment-audit-failure",
    );
    let principals = fixture.store.list_principals().unwrap();
    assert_eq!(principals.len(), 1);
    let principal_id = &principals[0].principal_id;
    assert_eq!(fixture.store.group_members("baseline").unwrap().len(), 1);
    // Administrative removal after creation is respected even though the
    // first login never delivered a browser session cookie.
    fixture
        .store
        .remove_group(principal_id, "baseline")
        .unwrap();
    connection
        .execute_batch("DROP TRIGGER fail_login_success_audit;")
        .unwrap();
    fixture.clock.advance_seconds(1);
    let returning = start_browser_login(&fixture, Some(&pending.binding_cookie)).await;
    let response =
        finish_browser_login(&fixture, &returning, "oidc-enrollment-after-failure").await;
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    assert!(session_cookie(&response).is_some());
    assert_eq!(fixture.store.list_principals().unwrap().len(), 1);
    assert!(fixture.store.group_members("baseline").unwrap().is_empty());
    let audit = login_success_audit(&fixture, "oidc-enrollment-after-failure");
    assert_eq!(audit["jitCreated"], false);
    assert_eq!(audit["autoEnrolledGroupIds"], json!([]));
}

#[tokio::test]
async fn microsoft_oidc_browser_default_group_does_not_bypass_mapped_group_admission() {
    let fixture = oidc_browser_fixture(false).await;
    fixture
        .store
        .create_group(GroupWriteRequest {
            group_id: "baseline".into(),
            display_name: None,
            description: None,
            auto_enroll_new_microsoft_users: true,
            created_by: "test".into(),
        })
        .unwrap();
    let mut claims = FakeTokenClaims::valid(FIXED_NOW);
    claims.groups = FakeGroupClaims::Empty;
    fixture.provider.set_next_claims(claims);
    let pending = start_browser_login(&fixture, None).await;
    let response = finish_browser_login(&fixture, &pending, "oidc-enrollment-denied").await;
    assert_callback_error(&response, "oidc_admission_denied", "oidc-enrollment-denied");
    assert!(fixture.store.list_principals().unwrap().is_empty());
    assert!(fixture.store.group_members("baseline").unwrap().is_empty());
}

#[tokio::test(flavor = "current_thread")]
async fn microsoft_oidc_debug_tracing_reports_validated_claims_without_protocol_secrets() {
    let captured = super::install_trace_capture().start();

    let fixture = oidc_browser_fixture(false).await;
    let pending = start_browser_login(&fixture, None).await;
    let callback = Url::parse(&pending.callback_uri).unwrap();
    let callback_secrets = callback
        .query_pairs()
        .filter(|(name, _)| matches!(name.as_ref(), "code" | "state"))
        .map(|(_, value)| value.into_owned())
        .collect::<Vec<_>>();
    let binding_secret = pending
        .binding_cookie
        .split_once('=')
        .map(|(_, value)| value)
        .unwrap();
    let response = captured
        .run(finish_browser_login(
            &fixture,
            &pending,
            "oidc-debug-success",
        ))
        .await;
    assert_eq!(response.status(), StatusCode::SEE_OTHER);

    let mut overage_claims = FakeTokenClaims::valid(FIXED_NOW + 1);
    overage_claims.groups = FakeGroupClaims::Overage;
    fixture.provider.set_next_claims(overage_claims);
    let overage = start_browser_login(&fixture, Some(&pending.binding_cookie)).await;
    let response = captured
        .run(finish_browser_login(
            &fixture,
            &overage,
            "oidc-debug-overage",
        ))
        .await;
    assert_callback_error(
        &response,
        "oidc_group_claims_incomplete",
        "oidc-debug-overage",
    );

    let denied_fixture = oidc_browser_fixture(false).await;
    let binding = denied_fixture
        .store
        .list_external_group_bindings(None)
        .unwrap()
        .into_iter()
        .next()
        .unwrap();
    denied_fixture
        .store
        .set_external_group_binding_enabled(&binding.binding_id, false, "test")
        .unwrap();
    let denied = start_browser_login(&denied_fixture, None).await;
    let response = captured
        .run(finish_browser_login(
            &denied_fixture,
            &denied,
            "oidc-debug-denied",
        ))
        .await;
    assert_callback_error(&response, "oidc_admission_denied", "oidc-debug-denied");

    let events = captured.take_events();
    let oidc_events = events
        .iter()
        .filter(|event| {
            event.get("event").and_then(Value::as_str) == Some("oidc_claims_observed")
                && event
                    .get("agentRequestId")
                    .and_then(Value::as_str)
                    .is_some_and(|request_id| request_id.starts_with("oidc-debug-"))
        })
        .collect::<Vec<_>>();
    let logs = serde_json::to_string(&oidc_events).unwrap();
    assert_eq!(oidc_events.len(), 3, "{logs}");
    assert!(
        oidc_events
            .iter()
            .all(|event| { event.get("level").and_then(Value::as_str) == Some("DEBUG") })
    );
    for outcome in ["succeeded", "group_claims_incomplete", "no_mapped_group"] {
        assert!(
            oidc_events.iter().any(|event| {
                event.get("admissionOutcome").and_then(Value::as_str) == Some(outcome)
            }),
            "missing admission outcome {outcome} in {logs}"
        );
    }
    assert!(
        oidc_events.iter().any(|event| {
            event.get("groupClaimStatus").and_then(Value::as_str) == Some("overage")
        })
    );
    for expected in [
        TENANT_ID,
        USER_OBJECT_ID,
        GROUP_ID,
        "Ada Lovelace",
        "ada.lovelace@example.test",
        "ada@example.test",
        "microsoft-users",
    ] {
        assert!(logs.contains(expected), "missing {expected} in {logs}");
    }
    for secret in callback_secrets
        .iter()
        .map(String::as_str)
        .chain([binding_secret, CLIENT_SECRET])
    {
        assert!(!logs.contains(secret), "debug logs exposed protocol secret");
    }
}

#[tokio::test]
async fn microsoft_oidc_browser_rejects_state_and_binding_cookie_mismatches_before_exchange() {
    let fixture = oidc_browser_fixture(false).await;
    let pending = start_browser_login(&fixture, None).await;
    let wrong_binding = format!(
        "__Host-aab_oidc_binding={}",
        URL_SAFE_NO_PAD.encode([99_u8; 32])
    );
    let wrong_cookie = finish_browser_login_with(
        &fixture,
        &pending.callback_uri,
        &wrong_binding,
        "oidc-wrong-binding",
    )
    .await;
    assert_callback_error(&wrong_cookie, "oidc_flow_invalid", "oidc-wrong-binding");

    let second = start_browser_login(&fixture, Some(&pending.binding_cookie)).await;
    assert_eq!(second.binding_cookie, pending.binding_cookie);
    let mut callback = Url::parse(&second.callback_uri).unwrap();
    let mut query = query_parameters(&callback).unwrap();
    query.insert("state".to_string(), URL_SAFE_NO_PAD.encode([98_u8; 32]));
    callback.set_query(Some(
        &url::form_urlencoded::Serializer::new(String::new())
            .extend_pairs(query)
            .finish(),
    ));
    let wrong_state = finish_browser_login_with(
        &fixture,
        callback.as_str(),
        &second.binding_cookie,
        "oidc-wrong-state",
    )
    .await;
    assert_callback_error(&wrong_state, "oidc_flow_invalid", "oidc-wrong-state");
    assert_eq!(fixture.provider.request_counts(), (1, 1, 0));
}

#[tokio::test]
async fn microsoft_oidc_browser_rejects_nonce_signature_and_duplicate_claim_failures() {
    let fixture = oidc_browser_fixture(false).await;

    let mut claims = FakeTokenClaims::valid(FIXED_NOW);
    claims.nonce_override = Some("wrong-nonce".to_string());
    fixture.provider.set_next_claims(claims);
    let nonce = start_browser_login(&fixture, None).await;
    let response = finish_browser_login(&fixture, &nonce, "oidc-wrong-nonce").await;
    assert_callback_error(&response, "oidc_identity_invalid", "oidc-wrong-nonce");

    let mut claims = FakeTokenClaims::valid(FIXED_NOW);
    claims.corrupt_signature = true;
    fixture.provider.set_next_claims(claims);
    let signature = start_browser_login(&fixture, Some(&nonce.binding_cookie)).await;
    let response = finish_browser_login(&fixture, &signature, "oidc-bad-signature").await;
    assert_callback_error(&response, "oidc_identity_invalid", "oidc-bad-signature");

    let mut claims = FakeTokenClaims::valid(FIXED_NOW);
    claims.duplicate_tenant_claim = true;
    fixture.provider.set_next_claims(claims);
    let duplicate = start_browser_login(&fixture, Some(&nonce.binding_cookie)).await;
    let response = finish_browser_login(&fixture, &duplicate, "oidc-duplicate-claim").await;
    assert_callback_error(&response, "oidc_identity_invalid", "oidc-duplicate-claim");

    let mut claims = FakeTokenClaims::valid(FIXED_NOW);
    claims.groups = FakeGroupClaims::Malformed;
    fixture.provider.set_next_claims(claims);
    let malformed = start_browser_login(&fixture, Some(&nonce.binding_cookie)).await;
    let response = finish_browser_login(&fixture, &malformed, "oidc-malformed-groups").await;
    assert_callback_error(
        &response,
        "oidc_group_claims_incomplete",
        "oidc-malformed-groups",
    );

    assert_eq!(fixture.provider.request_counts(), (1, 1, 4));
    assert!(fixture.store.list_principals().unwrap().is_empty());
}

#[tokio::test]
async fn microsoft_oidc_browser_distinguishes_overage_from_authoritative_empty_membership() {
    let fixture = oidc_browser_fixture(false).await;
    let initial = start_browser_login(&fixture, None).await;
    let response = finish_browser_login(&fixture, &initial, "oidc-complete-groups").await;
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    let principal_id = fixture.store.list_principals().unwrap()[0]
        .principal_id
        .clone();

    let mut claims = FakeTokenClaims::valid(FIXED_NOW + 1);
    claims.groups = FakeGroupClaims::Overage;
    fixture.provider.set_next_claims(claims);
    let overage = start_browser_login(&fixture, Some(&initial.binding_cookie)).await;
    let response = finish_browser_login(&fixture, &overage, "oidc-overage").await;
    assert_callback_error(&response, "oidc_group_claims_incomplete", "oidc-overage");
    let membership = fixture
        .store
        .effective_membership_at(&principal_id, &fixture.clock.now().to_rfc3339())
        .unwrap();
    assert_eq!(membership.groups, ["microsoft-users"]);

    let mut claims = FakeTokenClaims::valid(FIXED_NOW + 2);
    claims.groups = FakeGroupClaims::Empty;
    fixture.provider.set_next_claims(claims);
    let empty = start_browser_login(&fixture, Some(&initial.binding_cookie)).await;
    let response = finish_browser_login(&fixture, &empty, "oidc-empty-groups").await;
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    assert!(session_cookie(&response).is_some());
    let membership = fixture
        .store
        .effective_membership_at(&principal_id, &fixture.clock.now().to_rfc3339())
        .unwrap();
    assert!(membership.groups.is_empty());
}

#[tokio::test]
async fn microsoft_oidc_browser_refreshes_one_unknown_key_and_does_not_refresh_bad_signatures() {
    let fixture = oidc_browser_fixture(false).await;
    assert_eq!(fixture.provider.request_counts(), (1, 1, 0));
    fixture.provider.rotate_signing_key();
    let rotated = start_browser_login(&fixture, None).await;
    let response = finish_browser_login(&fixture, &rotated, "oidc-rotated-key").await;
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    assert!(session_cookie(&response).is_some());
    assert_eq!(fixture.provider.request_counts(), (1, 2, 1));

    let mut claims = FakeTokenClaims::valid(FIXED_NOW + 1);
    claims.corrupt_signature = true;
    fixture.provider.set_next_claims(claims);
    let bad_signature = start_browser_login(&fixture, Some(&rotated.binding_cookie)).await;
    let response = finish_browser_login(&fixture, &bad_signature, "oidc-known-bad-signature").await;
    assert_callback_error(
        &response,
        "oidc_identity_invalid",
        "oidc-known-bad-signature",
    );
    assert_eq!(fixture.provider.request_counts(), (1, 2, 2));
}

#[tokio::test]
async fn microsoft_oidc_browser_reports_jwks_refresh_outage_as_provider_unavailable() {
    let fixture = oidc_browser_fixture(false).await;
    fixture.provider.rotate_signing_key();
    fixture.provider.set_jwks_outage(true);
    let pending = start_browser_login(&fixture, None).await;
    let response = finish_browser_login(&fixture, &pending, "oidc-jwks-outage").await;
    assert_callback_error(&response, "oidc_unavailable", "oidc-jwks-outage");
    assert_eq!(fixture.provider.request_counts(), (1, 2, 1));
}

#[tokio::test]
async fn microsoft_oidc_outages_are_provider_scoped_and_token_outage_is_unavailable() {
    let unavailable = oidc_browser_fixture(true).await;
    let start = unavailable
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri("/v1/auth/oidc/microsoft/start")
                .extension(ConnectInfo(
                    "127.0.0.1:43412".parse::<SocketAddr>().unwrap(),
                ))
                .header(
                    agent_access_provider::REQUEST_ID_HEADER,
                    "oidc-provider-down",
                )
                .header("Host", "broker.example.test")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(start.status(), StatusCode::SERVICE_UNAVAILABLE);
    let ready = unavailable
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri("/v1/readyz")
                .extension(ConnectInfo(
                    "127.0.0.1:43413".parse::<SocketAddr>().unwrap(),
                ))
                .header(
                    agent_access_provider::REQUEST_ID_HEADER,
                    "oidc-ready-provider-down",
                )
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(ready.status(), StatusCode::OK);

    let fixture = oidc_browser_fixture(false).await;
    let pending = start_browser_login(&fixture, None).await;
    fixture.provider.set_token_outage(true);
    let response = finish_browser_login(&fixture, &pending, "oidc-token-outage").await;
    assert_callback_error(&response, "oidc_unavailable", "oidc-token-outage");
}

#[tokio::test]
async fn fake_microsoft_provider_exercises_real_discovery_and_jwks_loading() {
    let clock = TestClock::new(FIXED_NOW);
    let provider = FakeMicrosoftOidcProvider::new(clock.clone());
    let metadata = MicrosoftOidcProviderMetadata::discover(TENANT_ID, &provider, clock.now())
        .await
        .unwrap();

    assert_eq!(
        metadata.metadata().issuer().as_str(),
        format!("https://{MICROSOFT_OIDC_HOST}/{TENANT_ID}/v2.0")
    );
    assert_eq!(metadata.jwks().keys().len(), 1);
    assert_eq!(provider.request_counts(), (1, 1, 0));

    clock.advance_seconds(1);
    assert_eq!(clock.now_timestamp(), FIXED_NOW + 1);
}

#[tokio::test]
async fn fake_microsoft_provider_drives_real_openidconnect_exchange_and_verification() {
    let clock = TestClock::new(FIXED_NOW);
    let provider = FakeMicrosoftOidcProvider::new(clock.clone());
    let metadata = MicrosoftOidcProviderMetadata::discover(TENANT_ID, &provider, clock.now())
        .await
        .unwrap();
    let client = CoreClient::from_provider_metadata(
        metadata.metadata().clone(),
        ClientId::new(CLIENT_ID.to_string()),
        Some(ClientSecret::new(CLIENT_SECRET.to_string())),
    )
    .set_auth_type(AuthType::RequestBody)
    .set_redirect_uri(
        RedirectUrl::new(format!(
            "https://broker.example.test{MICROSOFT_OIDC_CALLBACK_PATH}"
        ))
        .unwrap(),
    );
    let verifier = PkceCodeVerifier::new(URL_SAFE_NO_PAD.encode([15_u8; 32]));
    let challenge = PkceCodeChallenge::from_code_verifier_sha256(&verifier);
    let (authorization_url, state, nonce) = client
        .authorize_url(
            CoreAuthenticationFlow::AuthorizationCode,
            || CsrfToken::new("test-state".to_string()),
            || Nonce::new("test-nonce".to_string()),
        )
        .add_scopes(
            ["profile", "email"]
                .into_iter()
                .map(|scope| Scope::new(scope.to_string())),
        )
        .add_extra_param("response_mode", "query")
        .set_pkce_challenge(challenge)
        .url();
    let callback = Url::parse(&provider.authorize(authorization_url.as_str()).unwrap()).unwrap();
    let callback = query_parameters(&callback).unwrap();
    assert_eq!(
        callback.get("state").map(String::as_str),
        Some(state.secret().as_str())
    );
    let code = callback.get("code").unwrap().clone();

    let response = client
        .exchange_code(AuthorizationCode::new(code))
        .unwrap()
        .set_pkce_verifier(verifier)
        .request_async(&provider)
        .await
        .unwrap();
    let id_token = response.id_token().expect("fake returns an ID token");
    let clock_for_verifier = clock.clone();
    let verifier = client
        .id_token_verifier()
        .set_time_fn(move || clock_for_verifier.now());
    let claims = id_token.claims(&verifier, &nonce).unwrap();
    assert_eq!(claims.subject().as_str(), "microsoft-subject");
    assert_eq!(provider.request_counts(), (1, 1, 1));
}

#[test]
fn fake_microsoft_authorization_and_token_exchange_enforce_pkce() {
    let clock = TestClock::new(FIXED_NOW);
    let provider = FakeMicrosoftOidcProvider::new(clock);
    let verifier = "test-verifier-with-enough-entropy-for-pkce";
    let start = format!(
        "https://{MICROSOFT_OIDC_HOST}/{TENANT_ID}/oauth2/v2.0/authorize?client_id={CLIENT_ID}&response_type=code&response_mode=query&scope=openid%20profile%20email&redirect_uri=https%3A%2F%2Fbroker.example.test%2Fv1%2Fauth%2Foidc%2Fmicrosoft%2Fcallback&state=test-state&nonce=test-nonce&code_challenge={}&code_challenge_method=S256",
        pkce_challenge(verifier)
    );
    let callback = provider.authorize(&start).unwrap();
    let callback = Url::parse(&callback).unwrap();
    let code = query_parameters(&callback).unwrap().remove("code").unwrap();

    let body = url::form_urlencoded::Serializer::new(String::new())
        .append_pair("grant_type", "authorization_code")
        .append_pair("client_id", CLIENT_ID)
        .append_pair("client_secret", CLIENT_SECRET)
        .append_pair("code", &code)
        .append_pair(
            "redirect_uri",
            "https://broker.example.test/v1/auth/oidc/microsoft/callback",
        )
        .append_pair("code_verifier", "wrong-verifier")
        .finish();
    let request = axum::http::Request::builder()
        .method("POST")
        .uri(format!(
            "https://{MICROSOFT_OIDC_HOST}/{TENANT_ID}/oauth2/v2.0/token"
        ))
        .body(body.into_bytes())
        .unwrap();
    assert_eq!(
        provider.handle(request).unwrap_err(),
        FakeProviderError::InvalidTokenRequest
    );
}
