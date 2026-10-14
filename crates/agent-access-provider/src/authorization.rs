//! Credential presentation: providers put lent credential material on
//! upstream requests through the SDK and never read it.
//!
//! An [`ExecutionCredential`](crate::ExecutionCredential) or
//! [`DelegatedAccess`](crate::DelegatedAccess) yields an
//! [`UpstreamAuthorization`], either in the credential's own HTTP
//! authentication scheme or in a [`CredentialPlacement`] the provider names.
//! The authorization applies one sensitive header to a request; the governed
//! send methods of [`UpstreamClient`](crate::UpstreamClient) then keep it on
//! the client's base origin.
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use reqwest::RequestBuilder;
use reqwest::header::{AUTHORIZATION, HeaderMap, HeaderName, HeaderValue};
use std::fmt;

/// The largest token, in bytes, that a [`CredentialPlacement`] presents.
const PLACED_TOKEN_MAX_BYTES: usize = 32 * 1024;

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
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CredentialPlacement {
    placement: Placement,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Placement {
    Bearer,
    Basic,
    Header(HeaderName),
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
    /// username or token, or a token that is empty, too long or contains a
    /// character the placement does not allow.
    #[error("the credential material cannot be presented in this placement")]
    InvalidMaterial,
}

/// Credential material ready to present on upstream requests. Providers
/// apply it with [`Self::apply`] and never read it.
///
/// It adds one header whose value is marked sensitive, so every send method
/// of [`UpstreamClient`](crate::UpstreamClient) refuses to deliver it to
/// another origin than the client's base (see
/// [`UpstreamClient::request`](crate::UpstreamClient::request)). Its Debug
/// output names only the header. Clones present the same material.
#[derive(Clone)]
pub struct UpstreamAuthorization {
    name: HeaderName,
    value: Presented,
}

#[derive(Clone)]
enum Presented {
    Value(HeaderValue),
    /// Text no header value can hold, such as a stored token with a line
    /// break. Applying it makes the request fail to build, so the send
    /// methods report [`UpstreamError::NotSent`](crate::UpstreamError::NotSent)
    /// before anything leaves.
    Unrepresentable(String),
}

impl UpstreamAuthorization {
    /// `request` with this authorization's header, replacing any value it
    /// already has for that header.
    pub fn apply(&self, request: RequestBuilder) -> RequestBuilder {
        match &self.value {
            Presented::Value(value) => {
                request.headers(HeaderMap::from_iter([(self.name.clone(), value.clone())]))
            }
            Presented::Unrepresentable(text) => request.header(self.name.clone(), text.clone()),
        }
    }

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
}

impl fmt::Debug for UpstreamAuthorization {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("UpstreamAuthorization")
            .field("header", &self.name.as_str())
            .finish_non_exhaustive()
    }
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
            (Placement::Basic, Self::Token(_))
            | (Placement::Bearer | Placement::Header(_), Self::Basic { .. }) => {
                Err(CredentialPlacementError::KindMismatch)
            }
        }
    }
}

fn basic(username: &str, token: &str) -> UpstreamAuthorization {
    UpstreamAuthorization::sensitive(
        AUTHORIZATION,
        format!("Basic {}", STANDARD.encode(format!("{username}:{token}"))),
    )
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

    fn headers(authorization: &UpstreamAuthorization, request: RequestBuilder) -> HeaderMap {
        authorization
            .apply(request)
            .build()
            .unwrap()
            .headers()
            .clone()
    }

    fn request() -> RequestBuilder {
        reqwest::Client::new().request(Method::GET, "https://service.example.test/")
    }

    /// The SDK presents exactly the bytes reqwest's own helpers produce, so
    /// moving a provider onto it leaves the wire unchanged.
    #[test]
    fn native_authorization_matches_reqwest_basic_and_bearer_bytes() {
        for (material, expected) in [
            (
                Material::Basic {
                    username: "user@example.test",
                    token: "basic:secret",
                },
                request().basic_auth("user@example.test", Some("basic:secret")),
            ),
            (
                Material::Basic {
                    username: "",
                    token: "",
                },
                request().basic_auth("", Some("")),
            ),
            (
                Material::Token("bearer-secret"),
                request().bearer_auth("bearer-secret"),
            ),
            (
                Material::Token("uni\u{e9}code token"),
                request().bearer_auth("uni\u{e9}code token"),
            ),
        ] {
            let expected = expected.build().unwrap();
            let actual = headers(&material.authorization(), request());
            let value = &actual[AUTHORIZATION];
            assert_eq!(value, &expected.headers()[AUTHORIZATION]);
            assert!(value.is_sensitive());
            assert_eq!(actual.len(), 1);
        }
    }

    /// A token no header value can hold fails the request build, as
    /// `bearer_auth` would, so it is never sent.
    #[test]
    fn unrepresentable_material_fails_the_request_build() {
        let authorization = Material::Token("token\r\ninjected: header").authorization();
        assert!(authorization.apply(request()).build().is_err());
        assert!(
            request()
                .bearer_auth("token\r\ninjected: header")
                .build()
                .is_err()
        );
    }

    #[test]
    fn placements_present_checked_material_and_replace_the_header() {
        let api_key = HeaderName::from_static("x-api-key");
        let presented = Material::Token("key-123")
            .placed(&CredentialPlacement::header(api_key.clone()))
            .unwrap();
        let sent = headers(&presented, request().header("X-Api-Key", "caller-value"));
        assert_eq!(sent.get_all(&api_key).iter().count(), 1);
        assert_eq!(sent[&api_key], "key-123");
        assert!(sent[&api_key].is_sensitive());

        let bearer = Material::Token("token-1")
            .placed(&CredentialPlacement::bearer())
            .unwrap();
        assert_eq!(headers(&bearer, request())[AUTHORIZATION], "Bearer token-1");

        let basic = Material::Basic {
            username: "ci-user",
            token: "api-token",
        }
        .placed(&CredentialPlacement::basic())
        .unwrap();
        let expected = request().basic_auth("ci-user", Some("api-token"));
        assert_eq!(
            headers(&basic, request())[AUTHORIZATION],
            expected.build().unwrap().headers()[AUTHORIZATION]
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

    #[test]
    fn debug_output_names_only_the_header() {
        let rendered = format!(
            "{:?} {:?}",
            Material::Token("bearer-secret").authorization(),
            Material::Basic {
                username: "user@example.test",
                token: "basic-secret"
            }
            .authorization()
        );
        for secret in [
            "bearer-secret",
            "user@example.test",
            "basic-secret",
            "Bearer",
            "Basic",
        ] {
            assert!(!rendered.contains(secret), "{rendered}");
        }
        assert!(rendered.contains("authorization"));
    }
}
