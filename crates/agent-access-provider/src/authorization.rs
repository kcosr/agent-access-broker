//! Credential presentation: the SDK puts lent credential material on upstream
//! requests, and providers never read it or hold a request that carries it.
//!
//! An [`ExecutionCredential`](crate::ExecutionCredential) or
//! [`DelegatedAccess`](crate::DelegatedAccess) yields an
//! [`UpstreamAuthorization`], either in the credential's own HTTP
//! authentication scheme or in a [`CredentialPlacement`] the provider names.
//! A provider hands the authorization to a send method of
//! [`UpstreamClient`](crate::UpstreamClient) together with its request
//! ([`UpstreamCall::with_authorization`](crate::UpstreamCall::with_authorization),
//! [`RedirectRules::with_authorization`](crate::RedirectRules::with_authorization)
//! or, obtained for each hop, a
//! [`RedirectAuthorizer`](crate::RedirectAuthorizer)); the client adds the
//! sensitive header to the built request immediately before dispatch, and
//! only on its base origin (along a redirect chain, only within its
//! authorized path).
use crate::correlation::{BROKER_REQUEST_ID_HEADER, REQUEST_ID_HEADER};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use reqwest::RequestBuilder;
use reqwest::header::{AUTHORIZATION, HeaderMap, HeaderName, HeaderValue};
#[cfg(any(test, feature = "test-support"))]
use sha2::{Digest, Sha256};
use std::fmt;
#[cfg(any(test, feature = "test-support"))]
use subtle::ConstantTimeEq;

/// The largest token, in bytes, that a [`CredentialPlacement`] presents.
const PLACED_TOKEN_MAX_BYTES: usize = 32 * 1024;

/// The longest username, in bytes, that the host-only token-as-Basic
/// placement ([`crate::host::token_as_basic`]) presents.
const TOKEN_BASIC_USERNAME_MAX_BYTES: usize = 64;

/// Where a provider presents a credential when the upstream needs a specific
/// placement instead of the credential's own HTTP authentication
/// ([`ExecutionCredential::authorization`](crate::ExecutionCredential::authorization)).
///
/// A placement checks the material before presenting it and fails with a
/// [`CredentialPlacementError`] instead of sending something the placement
/// cannot carry:
///
/// - [`Self::bearer`] and [`Self::header`] present a token: a `bearer_token`
///   credential's token or delegated access. The token must be 1 to 32,768
///   visible ASCII characters (`!` through `~`), with no space or control
///   character.
/// - [`Self::basic`] presents a `basic_api_token` credential whose username
///   and token are both non-empty.
///
/// The host also builds one placement providers never use:
/// [`crate::host::token_as_basic`] presents a token as HTTP Basic with a
/// configured username, for the host's own clients.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CredentialPlacement {
    placement: Placement,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Placement {
    Bearer,
    Basic,
    Header(HeaderName),
    /// A token as the password of HTTP Basic under this username.
    TokenAsBasic(String),
}

impl CredentialPlacement {
    /// `Authorization: Bearer <token>`.
    pub const fn bearer() -> Self {
        Self {
            placement: Placement::Bearer,
        }
    }

    /// `Authorization: Basic <base64 of username:token>`.
    pub const fn basic() -> Self {
        Self {
            placement: Placement::Basic,
        }
    }

    /// The token as the whole value of the header `name`, such as an API-key
    /// header. The value replaces any value the request already has for
    /// `name`.
    pub fn header(name: HeaderName) -> Self {
        Self {
            placement: Placement::Header(name),
        }
    }

    /// A token as `Authorization: Basic <base64 of username:token>`; the host
    /// builds it with [`crate::host::token_as_basic`].
    pub(crate) fn token_as_basic(username: String) -> Self {
        Self {
            placement: Placement::TokenAsBasic(username),
        }
    }
}

/// Why a credential cannot be presented in a [`CredentialPlacement`]. It
/// carries no credential material; a provider reports it as its own failure,
/// usually `credential_invalid`.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum CredentialPlacementError {
    /// The placement does not take this kind of credential, such as a
    /// `basic_api_token` credential for [`CredentialPlacement::bearer`].
    #[error("the credential kind cannot be presented in this placement")]
    KindMismatch,
    /// The material is not what the placement requires: an empty Basic
    /// username or token, a token that is empty, too long or contains a
    /// character the placement does not allow, or a username the host's
    /// token-as-Basic placement cannot carry.
    #[error("the credential material cannot be presented in this placement")]
    InvalidMaterial,
}

/// Credential material the SDK presents on upstream requests. It exposes
/// nothing: a provider hands it to the send method with the request
/// ([`UpstreamCall::with_authorization`](crate::UpstreamCall::with_authorization),
/// [`RedirectRules::with_authorization`](crate::RedirectRules::with_authorization)
/// or a [`RedirectAuthorizer`](crate::RedirectAuthorizer)),
/// and the [`UpstreamClient`](crate::UpstreamClient) adds its header to the
/// built request immediately before dispatch.
///
/// The header value is marked sensitive, so the client refuses a request to
/// another origin than its base that would carry it (see
/// [`UpstreamClient::request`](crate::UpstreamClient::request)). Debug output
/// names only the header. Clones present the same material.
#[derive(Clone)]
pub struct UpstreamAuthorization {
    name: HeaderName,
    value: Presented,
}

#[derive(Clone)]
enum Presented {
    Value(HeaderValue),
    /// Text no header value can hold, such as a stored token with a line
    /// break. Presenting it makes the request fail to build, so the send
    /// methods report [`UpstreamError::NotSent`](crate::UpstreamError::NotSent)
    /// before anything leaves.
    Unrepresentable(String),
}

impl UpstreamAuthorization {
    fn sensitive(name: HeaderName, text: String) -> Self {
        let value = match HeaderValue::from_bytes(text.as_bytes()) {
            Ok(mut value) => {
                value.set_sensitive(true);
                Presented::Value(value)
            }
            Err(_) => Presented::Unrepresentable(text),
        };
        Self { name, value }
    }

    /// `request` with this authorization's header, replacing any value it
    /// already has for that header. Only the host's own clients use this
    /// directly ([`crate::host::authorize_host_request`]); the upstream
    /// client presents authorizations through [`attach`].
    pub(crate) fn apply_to_builder(&self, request: RequestBuilder) -> RequestBuilder {
        match &self.value {
            Presented::Value(value) => {
                request.headers(HeaderMap::from_iter([(self.name.clone(), value.clone())]))
            }
            Presented::Unrepresentable(text) => request.header(self.name.clone(), text.clone()),
        }
    }
}

impl fmt::Debug for UpstreamAuthorization {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("UpstreamAuthorization")
            .field("header", &self.name.as_str())
            .finish_non_exhaustive()
    }
}

/// Where the upstream client adds authorizations to a built request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AuthorizationPosition {
    /// Immediately after the client's correlation headers, before every
    /// header the provider set: where a provider that authorized the request
    /// right after [`UpstreamClient::request`](crate::UpstreamClient::request)
    /// put it.
    AfterCorrelation,
    /// After every header already on the request: a redirect hop's
    /// authorization follows its decoration.
    End,
}

/// Adds `authorizations`, in order, to a request's `headers`. A header the
/// request already has with an authorization's name is replaced in place;
/// any other is inserted at `position`. Returns the first authorization whose
/// material cannot be a header value, leaving the request to fail its build.
pub(crate) fn attach<'a>(
    headers: &mut HeaderMap,
    authorizations: &'a [UpstreamAuthorization],
    position: AuthorizationPosition,
) -> Result<(), &'a UpstreamAuthorization> {
    if authorizations.is_empty() {
        return Ok(());
    }
    let mut entries: Vec<(HeaderName, HeaderValue)> = headers
        .iter()
        .map(|(name, value)| (name.clone(), value.clone()))
        .collect();
    let mut insert_at = match position {
        AuthorizationPosition::AfterCorrelation => entries
            .iter()
            .take_while(|(name, _)| {
                name.as_str().eq_ignore_ascii_case(REQUEST_ID_HEADER)
                    || name.as_str().eq_ignore_ascii_case(BROKER_REQUEST_ID_HEADER)
            })
            .count(),
        AuthorizationPosition::End => entries.len(),
    };
    for authorization in authorizations {
        let value = match &authorization.value {
            Presented::Value(value) => value.clone(),
            Presented::Unrepresentable(_) => return Err(authorization),
        };
        match entries
            .iter()
            .position(|(name, _)| *name == authorization.name)
        {
            Some(first) => {
                entries[first].1 = value;
                let mut index = first + 1;
                while index < entries.len() {
                    if entries[index].0 == authorization.name {
                        entries.remove(index);
                        if index < insert_at {
                            insert_at -= 1;
                        }
                    } else {
                        index += 1;
                    }
                }
            }
            None => {
                entries.insert(insert_at, (authorization.name.clone(), value));
                insert_at += 1;
            }
        }
    }
    headers.clear();
    for (name, value) in entries {
        headers.append(name, value);
    }
    Ok(())
}

/// Lent credential material as the SDK presents it.
#[derive(Clone, Copy)]
pub(crate) enum Material<'a> {
    Basic { username: &'a str, token: &'a str },
    Token(&'a str),
}

impl Material<'_> {
    /// The material in its own HTTP authentication scheme, with the bytes
    /// reqwest's `basic_auth` and `bearer_auth` produce.
    pub(crate) fn authorization(self) -> UpstreamAuthorization {
        match self {
            Self::Basic { username, token } => basic(username, token),
            Self::Token(token) => {
                UpstreamAuthorization::sensitive(AUTHORIZATION, format!("Bearer {token}"))
            }
        }
    }

    pub(crate) fn placed(
        self,
        placement: &CredentialPlacement,
    ) -> Result<UpstreamAuthorization, CredentialPlacementError> {
        match (&placement.placement, self) {
            (Placement::Basic, Self::Basic { username, token }) => {
                if username.is_empty() || token.is_empty() {
                    Err(CredentialPlacementError::InvalidMaterial)
                } else {
                    Ok(basic(username, token))
                }
            }
            (Placement::Bearer, Self::Token(token)) => Ok(UpstreamAuthorization::sensitive(
                AUTHORIZATION,
                format!("Bearer {}", placed_token(token)?),
            )),
            (Placement::Header(name), Self::Token(token)) => Ok(UpstreamAuthorization::sensitive(
                name.clone(),
                placed_token(token)?.to_owned(),
            )),
            (Placement::TokenAsBasic(username), Self::Token(token)) => {
                if token_basic_username_is_valid(username) {
                    Ok(basic(username, placed_token(token)?))
                } else {
                    Err(CredentialPlacementError::InvalidMaterial)
                }
            }
            (Placement::Basic, Self::Token(_))
            | (
                Placement::Bearer | Placement::Header(_) | Placement::TokenAsBasic(_),
                Self::Basic { .. },
            ) => Err(CredentialPlacementError::KindMismatch),
        }
    }

    /// A digest of the kind and material under an unambiguous,
    /// length-delimited encoding, for constant-time comparison in tests.
    #[cfg(any(test, feature = "test-support"))]
    pub(crate) fn digest(self) -> [u8; 32] {
        let mut digest = Sha256::new();
        digest.update(b"agent-access/credential-material/v1\0");
        let fields: &[&str] = match self {
            Self::Basic { username, token } => {
                digest.update([1]);
                &[username, token]
            }
            Self::Token(token) => {
                digest.update([2]);
                &[token]
            }
        };
        for field in fields {
            digest.update((field.len() as u64).to_be_bytes());
            digest.update(field.as_bytes());
        }
        digest.finalize().into()
    }
}

/// Whether two material digests are equal, in time independent of where they
/// differ.
#[cfg(any(test, feature = "test-support"))]
pub(crate) fn digests_equal(left: &[u8; 32], right: &[u8; 32]) -> bool {
    left.ct_eq(right).into()
}

fn basic(username: &str, token: &str) -> UpstreamAuthorization {
    UpstreamAuthorization::sensitive(
        AUTHORIZATION,
        format!("Basic {}", STANDARD.encode(format!("{username}:{token}"))),
    )
}

/// Whether `username` can carry a token as HTTP Basic: 1 to 64 printable
/// ASCII characters (space through `~`), without the colon that ends the
/// username.
fn token_basic_username_is_valid(username: &str) -> bool {
    !username.is_empty()
        && username.len() <= TOKEN_BASIC_USERNAME_MAX_BYTES
        && username
            .bytes()
            .all(|byte| (0x20..=0x7e).contains(&byte) && byte != b':')
}

fn placed_token(token: &str) -> Result<&str, CredentialPlacementError> {
    if !token.is_empty()
        && token.len() <= PLACED_TOKEN_MAX_BYTES
        && token.bytes().all(|byte| (0x21..=0x7e).contains(&byte))
    {
        Ok(token)
    } else {
        Err(CredentialPlacementError::InvalidMaterial)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use reqwest::Method;

    fn request() -> RequestBuilder {
        reqwest::Client::new().request(Method::GET, "https://service.example.test/")
    }

    /// The headers of `request` once the client has attached
    /// `authorizations` at `position`.
    fn attached(
        request: RequestBuilder,
        authorizations: &[UpstreamAuthorization],
        position: AuthorizationPosition,
    ) -> Vec<(String, Vec<u8>)> {
        let mut built = request.build().unwrap();
        attach(built.headers_mut(), authorizations, position).unwrap();
        listed(built.headers())
    }

    fn listed(headers: &HeaderMap) -> Vec<(String, Vec<u8>)> {
        headers
            .iter()
            .map(|(name, value)| (name.as_str().to_owned(), value.as_bytes().to_vec()))
            .collect()
    }

    fn correlated() -> RequestBuilder {
        request()
            .header(REQUEST_ID_HEADER, "agent-request")
            .header(BROKER_REQUEST_ID_HEADER, "broker-request")
    }

    /// The client produces exactly the headers, in exactly the order, that a
    /// provider authorizing right after `UpstreamClient::request` produced
    /// with reqwest's own `basic_auth` and `bearer_auth`.
    #[test]
    fn attached_authorization_matches_reqwest_bytes_and_order() {
        for (material, expected) in [
            (
                Material::Basic {
                    username: "user@example.test",
                    token: "basic:secret",
                },
                correlated().basic_auth("user@example.test", Some("basic:secret")),
            ),
            (
                Material::Basic {
                    username: "",
                    token: "",
                },
                correlated().basic_auth("", Some("")),
            ),
            (
                Material::Token("bearer-secret"),
                correlated().bearer_auth("bearer-secret"),
            ),
            (
                Material::Token("uni\u{e9}code token"),
                correlated().bearer_auth("uni\u{e9}code token"),
            ),
        ] {
            let provider_headers = |request: RequestBuilder| {
                request
                    .header("Accept", "application/json")
                    .json(&serde_json::json!({"field": "value"}))
            };
            let expected = provider_headers(expected).build().unwrap();
            let actual = attached(
                provider_headers(correlated()),
                &[material.authorization()],
                AuthorizationPosition::AfterCorrelation,
            );
            assert_eq!(actual, listed(expected.headers()));
            let mut built = provider_headers(correlated()).build().unwrap();
            attach(
                built.headers_mut(),
                &[material.authorization()],
                AuthorizationPosition::AfterCorrelation,
            )
            .unwrap();
            assert!(built.headers()[AUTHORIZATION].is_sensitive());
        }
    }

    /// Without correlation headers the authorization goes first; at the end
    /// position it follows every header, as a redirect hop's authorization
    /// follows its decoration.
    #[test]
    fn positions_place_the_header_before_or_after_the_provider_headers() {
        let bearer = Material::Token("token-1").authorization();
        let first = attached(
            request().header("accept-encoding", "identity"),
            std::slice::from_ref(&bearer),
            AuthorizationPosition::AfterCorrelation,
        );
        assert_eq!(first[0].0, "authorization");
        let hop = attached(
            correlated().header("accept-encoding", "identity"),
            std::slice::from_ref(&bearer),
            AuthorizationPosition::End,
        );
        let expected = correlated()
            .header("accept-encoding", "identity")
            .bearer_auth("token-1")
            .build()
            .unwrap();
        assert_eq!(hop, listed(expected.headers()));
    }

    /// An authorization replaces a header of the same name in its position,
    /// as reqwest's `headers` does, and several authorizations keep their
    /// order.
    #[test]
    fn authorizations_replace_same_named_headers_in_place_and_keep_their_order() {
        let api_key = HeaderName::from_static("x-api-key");
        let key = Material::Token("key-123")
            .placed(&CredentialPlacement::header(api_key.clone()))
            .unwrap();
        let headers = attached(
            correlated()
                .header("count", "1")
                .header("X-Api-Key", "caller-value")
                .header("X-Api-Key", "second-value")
                .header("accept", "application/json"),
            std::slice::from_ref(&key),
            AuthorizationPosition::AfterCorrelation,
        );
        let names: Vec<_> = headers.iter().map(|(name, _)| name.as_str()).collect();
        assert_eq!(
            names,
            [
                "x-agent-access-request-id",
                "x-agent-access-broker-request-id",
                "count",
                "x-api-key",
                "accept"
            ]
        );
        assert_eq!(headers[3].1, b"key-123");

        let transport = Material::Token("transport-token")
            .placed(&CredentialPlacement::bearer())
            .unwrap();
        let headers = attached(
            correlated().header("mcp-protocol-version", "2026-07-28"),
            &[key, transport],
            AuthorizationPosition::AfterCorrelation,
        );
        let names: Vec<_> = headers.iter().map(|(name, _)| name.as_str()).collect();
        assert_eq!(
            names,
            [
                "x-agent-access-request-id",
                "x-agent-access-broker-request-id",
                "x-api-key",
                "authorization",
                "mcp-protocol-version"
            ]
        );
        assert_eq!(headers[3].1, b"Bearer transport-token");
    }

    /// A token no header value can hold is reported, so the client fails the
    /// request build as `bearer_auth` would, and nothing is sent.
    #[test]
    fn unrepresentable_material_is_reported_and_fails_the_build() {
        let authorization = Material::Token("token\r\ninjected: header").authorization();
        let mut built = request().build().unwrap();
        assert!(
            attach(
                built.headers_mut(),
                std::slice::from_ref(&authorization),
                AuthorizationPosition::AfterCorrelation
            )
            .is_err()
        );
        assert!(authorization.apply_to_builder(request()).build().is_err());
        assert!(
            request()
                .bearer_auth("token\r\ninjected: header")
                .build()
                .is_err()
        );
    }

    #[test]
    fn placements_present_checked_material() {
        let bearer = Material::Token("token-1")
            .placed(&CredentialPlacement::bearer())
            .unwrap();
        assert_eq!(
            attached(request(), &[bearer], AuthorizationPosition::End),
            [("authorization".to_owned(), b"Bearer token-1".to_vec())]
        );
        let basic = Material::Basic {
            username: "ci-user",
            token: "api-token",
        }
        .placed(&CredentialPlacement::basic())
        .unwrap();
        let expected = request()
            .basic_auth("ci-user", Some("api-token"))
            .build()
            .unwrap();
        assert_eq!(
            attached(request(), &[basic], AuthorizationPosition::End),
            listed(expected.headers())
        );
    }

    #[test]
    fn placements_reject_the_wrong_kind_and_unsuitable_material() {
        let basic = Material::Basic {
            username: "user",
            token: "token",
        };
        for placement in [
            CredentialPlacement::bearer(),
            CredentialPlacement::header(HeaderName::from_static("x-api-key")),
        ] {
            assert_eq!(
                basic.placed(&placement).unwrap_err(),
                CredentialPlacementError::KindMismatch
            );
            for token in [
                String::new(),
                "with space".to_owned(),
                "tab\there".to_owned(),
                "uni\u{e9}code".to_owned(),
                "\u{7f}".to_owned(),
                "a".repeat(PLACED_TOKEN_MAX_BYTES + 1),
            ] {
                assert_eq!(
                    Material::Token(&token).placed(&placement).unwrap_err(),
                    CredentialPlacementError::InvalidMaterial
                );
            }
            let longest = "~".repeat(PLACED_TOKEN_MAX_BYTES);
            assert!(Material::Token(&longest).placed(&placement).is_ok());
        }
        assert_eq!(
            Material::Token("token")
                .placed(&CredentialPlacement::basic())
                .unwrap_err(),
            CredentialPlacementError::KindMismatch
        );
        for (username, token) in [("", "token"), ("user", "")] {
            assert_eq!(
                Material::Basic { username, token }
                    .placed(&CredentialPlacement::basic())
                    .unwrap_err(),
                CredentialPlacementError::InvalidMaterial
            );
        }
    }

    /// The host's token-as-Basic placement presents a token under the
    /// configured username with the bytes reqwest's `basic_auth` produces, as
    /// a sensitive header, whether the upstream client attaches it or the host
    /// applies it to its own request.
    #[test]
    fn token_as_basic_presents_a_token_under_the_configured_username() {
        let longest = "~".repeat(TOKEN_BASIC_USERNAME_MAX_BYTES);
        for username in ["oauth2", "service account", "!", longest.as_str()] {
            let authorization = Material::Token("glpat-token")
                .placed(&CredentialPlacement::token_as_basic(username.to_owned()))
                .unwrap();
            let expected = request()
                .basic_auth(username, Some("glpat-token"))
                .build()
                .unwrap();
            let mut built = request().build().unwrap();
            attach(
                built.headers_mut(),
                std::slice::from_ref(&authorization),
                AuthorizationPosition::End,
            )
            .unwrap();
            assert_eq!(listed(built.headers()), listed(expected.headers()));
            assert!(built.headers()[AUTHORIZATION].is_sensitive());
            let applied = authorization.apply_to_builder(request()).build().unwrap();
            assert_eq!(
                applied.headers()[AUTHORIZATION],
                expected.headers()[AUTHORIZATION]
            );
            assert!(applied.headers()[AUTHORIZATION].is_sensitive());
        }
    }

    #[test]
    fn token_as_basic_rejects_basic_material_and_unsuitable_usernames_or_tokens() {
        let oauth2 = CredentialPlacement::token_as_basic("oauth2".to_owned());
        assert_eq!(
            Material::Basic {
                username: "user",
                token: "token"
            }
            .placed(&oauth2)
            .unwrap_err(),
            CredentialPlacementError::KindMismatch
        );
        for username in [
            String::new(),
            "a".repeat(TOKEN_BASIC_USERNAME_MAX_BYTES + 1),
            "user:name".to_owned(),
            ":".to_owned(),
            "tab\tname".to_owned(),
            "line\nbreak".to_owned(),
            "\u{7f}".to_owned(),
            "uni\u{e9}code".to_owned(),
        ] {
            assert_eq!(
                Material::Token("token")
                    .placed(&CredentialPlacement::token_as_basic(username.clone()))
                    .unwrap_err(),
                CredentialPlacementError::InvalidMaterial,
                "{username:?}"
            );
        }
        for token in [
            String::new(),
            "with space".to_owned(),
            "line\nbreak".to_owned(),
            "uni\u{e9}code".to_owned(),
            "a".repeat(PLACED_TOKEN_MAX_BYTES + 1),
        ] {
            assert_eq!(
                Material::Token(&token).placed(&oauth2).unwrap_err(),
                CredentialPlacementError::InvalidMaterial
            );
        }
        let longest = "~".repeat(PLACED_TOKEN_MAX_BYTES);
        assert!(Material::Token(&longest).placed(&oauth2).is_ok());
    }

    /// Digests separate kinds and field boundaries, and compare equal only
    /// for the same kind and material.
    #[test]
    fn material_digests_are_unambiguous() {
        let digest = |material: Material<'_>| material.digest();
        let basic = digest(Material::Basic {
            username: "ab",
            token: "c",
        });
        assert!(digests_equal(
            &basic,
            &digest(Material::Basic {
                username: "ab",
                token: "c"
            })
        ));
        for other in [
            Material::Basic {
                username: "a",
                token: "bc",
            },
            Material::Basic {
                username: "ab",
                token: "d",
            },
            Material::Token("ab:c"),
        ] {
            assert!(!digests_equal(&basic, &digest(other)));
        }
    }

    #[test]
    fn debug_output_names_only_the_header() {
        let rendered = format!(
            "{:?} {:?} {:?}",
            Material::Token("bearer-secret").authorization(),
            Material::Basic {
                username: "user@example.test",
                token: "basic-secret"
            }
            .authorization(),
            Material::Token("token-secret")
                .placed(&CredentialPlacement::token_as_basic(
                    "user@example.test".to_owned()
                ))
                .unwrap()
        );
        for secret in [
            "bearer-secret",
            "user@example.test",
            "basic-secret",
            "token-secret",
            "Bearer",
            "Basic",
        ] {
            assert!(!rendered.contains(secret), "{rendered}");
        }
        assert!(rendered.contains("authorization"));
    }
}
