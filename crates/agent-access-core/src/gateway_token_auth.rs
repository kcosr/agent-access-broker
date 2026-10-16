//! How a Git gateway presents its upstream execution credential: the
//! `[gateways.<name>].upstream_token_auth` setting and the one presentation
//! that gateway forwarding and Git credential verification share.
use agent_access_provider::host::token_as_basic;
use agent_access_provider::{
    CredentialPlacement, DelegatedAccess, ExecutionCredential, ProviderError, ReasonCode,
    StaticCredentialKind, UpstreamAuthorization,
};
use serde::Deserialize;

/// The longest `upstream_token_auth.username`, in characters.
const BASIC_USERNAME_MAX_CHARS: usize = 64;

/// `[gateways.<name>].upstream_token_auth`: how a gateway presents token
/// material: a `bearer_token` credential or an OAuth access token. One table
/// shape, tagged by `scheme`: `{ scheme = "bearer" }`, the default when the
/// setting is absent, or `{ scheme = "basic", username = "<name>" }`. A
/// `basic_api_token` credential always presents its own stored username.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(tag = "scheme", rename_all = "snake_case", deny_unknown_fields)]
pub enum GatewayUpstreamTokenAuth {
    /// `Authorization: Bearer <token>`. A struct variant, so that a `username`
    /// beside `scheme = "bearer"` is rejected as an unknown field.
    Bearer {},
    /// `Authorization: Basic` with `username` and the token as the password,
    /// for an upstream that accepts tokens only as HTTP Basic, such as GitLab.
    Basic { username: String },
}

impl Default for GatewayUpstreamTokenAuth {
    fn default() -> Self {
        Self::Bearer {}
    }
}

impl GatewayUpstreamTokenAuth {
    /// The placement a token-kind credential is presented in, or `None` to
    /// present it in its own Bearer scheme.
    fn token_placement(&self) -> Option<CredentialPlacement> {
        match self {
            Self::Bearer {} => None,
            Self::Basic { username } => Some(token_as_basic(username.as_str())),
        }
    }
}

/// Validates `[gateways.<service>].upstream_token_auth`. The table's shape,
/// including a `username` required exactly for `basic`, is checked when the
/// configuration is parsed.
pub(crate) fn validate_upstream_token_auth(
    service: &str,
    token_auth: &GatewayUpstreamTokenAuth,
    errors: &mut Vec<String>,
) {
    match token_auth {
        GatewayUpstreamTokenAuth::Bearer {} => {}
        GatewayUpstreamTokenAuth::Basic { username } => {
            if let Some(problem) = basic_username_problem(username) {
                errors.push(format!(
                    "gateways.{service}.upstream_token_auth.username {problem}"
                ));
            }
        }
    }
}

/// Why `username` cannot carry a token as HTTP Basic: it must be 1 to 64
/// printable ASCII characters without a colon.
fn basic_username_problem(username: &str) -> Option<&'static str> {
    if username.is_empty() {
        Some("must not be empty")
    } else if username.chars().any(char::is_control) {
        Some("must not contain control characters")
    } else if !username.is_ascii() {
        Some("must be printable ASCII")
    } else if username.contains(':') {
        Some("must not contain a colon")
    } else if username.len() > BASIC_USERNAME_MAX_CHARS {
        Some("must be at most 64 characters")
    } else {
        None
    }
}

/// Host-only: the opaque authorization a Git gateway presents upstream for
/// `credential`. Git forwarding (in the Broker host) and Git credential
/// verification (in the runtime) both obtain it here and attach it to their
/// own request with the SDK's host-only
/// [`authorize_host_request`](agent_access_provider::host::authorize_host_request),
/// so a verified credential is presented exactly as forwarded requests
/// present it.
///
/// A `basic_api_token` credential presents its stored username and token as
/// HTTP Basic. A `bearer_token` credential presents its token as
/// `token_auth` selects: as a Bearer token, or as the password of HTTP Basic
/// under the configured username through the SDK's host-only
/// [`token_as_basic`] placement. Any other kind fails closed.
///
/// The result exposes no material, but it presents a credential the way only
/// the host's own clients may. Native, adapter, reference and helper crates
/// never call this, even where they depend on this crate:
/// `scripts/check-crate-boundaries.mjs` rejects any use in their sources.
pub fn gateway_upstream_authorization(
    token_auth: &GatewayUpstreamTokenAuth,
    credential: &ExecutionCredential,
) -> Result<UpstreamAuthorization, ProviderError> {
    let authorization = match credential.kind() {
        StaticCredentialKind::BasicApiToken => credential.authorization(),
        StaticCredentialKind::BearerToken => match token_auth.token_placement() {
            None => credential.authorization(),
            Some(placement) => credential.authorization_as(&placement).map_err(|_| {
                ProviderError::deny(
                    ReasonCode::CredentialInvalid,
                    "the Git gateway cannot present this credential's token as HTTP Basic",
                )
            })?,
        },
        _ => {
            return Err(ProviderError::deny(
                ReasonCode::CredentialInvalid,
                "the Git gateway does not support this credential kind",
            ));
        }
    };
    Ok(authorization)
}

/// The authorization a Git gateway presents for delegated (OAuth) `access`,
/// which is token material: a Bearer token, or the password of HTTP Basic
/// under the configured username, as for a `bearer_token` credential. The
/// caller has revalidated `access` and pinned it to the gateway's upstream.
pub(crate) fn gateway_delegated_authorization(
    token_auth: &GatewayUpstreamTokenAuth,
    access: &DelegatedAccess,
) -> Result<UpstreamAuthorization, ProviderError> {
    match token_auth.token_placement() {
        None => Ok(access.authorization()),
        Some(placement) => access.authorization_as(&placement).map_err(|_| {
            ProviderError::deny(
                ReasonCode::CredentialInvalid,
                "the Git gateway cannot present this OAuth access token as HTTP Basic",
            )
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use agent_access_provider::test_support::{basic_credential, bearer_credential};

    /// The `Authorization` header the host attaches for `credential`.
    fn authorization(
        token_auth: &GatewayUpstreamTokenAuth,
        credential: &ExecutionCredential,
    ) -> String {
        header(&gateway_upstream_authorization(token_auth, credential).unwrap())
    }

    /// The `Authorization` header the host attaches for `authorization`.
    fn header(authorization: &UpstreamAuthorization) -> String {
        let request = agent_access_provider::host::authorize_host_request(
            reqwest::Client::new().get("https://gitlab.example.com/team/project.git/info/refs"),
            authorization,
        )
        .build()
        .unwrap();
        let value = &request.headers()[reqwest::header::AUTHORIZATION];
        assert!(value.is_sensitive());
        value.to_str().unwrap().to_owned()
    }

    fn delegated(token: &str) -> DelegatedAccess {
        DelegatedAccess::new(
            token,
            "https://gitlab.example.com",
            "gitlab",
            "v1",
            i64::MAX,
        )
    }

    /// OAuth access is token material: Bearer by default, and the password
    /// of HTTP Basic under the configured username.
    #[test]
    fn delegated_access_is_presented_as_configured_for_tokens() {
        let access = delegated("oauth-access");
        assert_eq!(
            header(
                &gateway_delegated_authorization(&GatewayUpstreamTokenAuth::default(), &access)
                    .unwrap()
            ),
            "Bearer oauth-access"
        );
        assert_eq!(
            header(&gateway_delegated_authorization(&basic("oauth2"), &access).unwrap()),
            "Basic b2F1dGgyOm9hdXRoLWFjY2Vzcw=="
        );
        let error = gateway_delegated_authorization(&basic("oauth2"), &delegated("with space"))
            .unwrap_err();
        assert_eq!(error.reason_code(), ReasonCode::CredentialInvalid);
    }

    fn basic(username: &str) -> GatewayUpstreamTokenAuth {
        GatewayUpstreamTokenAuth::Basic {
            username: username.to_owned(),
        }
    }

    #[test]
    fn bearer_presentation_is_the_default_and_unchanged() {
        let default = GatewayUpstreamTokenAuth::default();
        assert_eq!(default, GatewayUpstreamTokenAuth::Bearer {});
        assert_eq!(
            authorization(&default, &bearer_credential("upstream-token")),
            "Bearer upstream-token"
        );
    }

    #[test]
    fn basic_presentation_puts_a_bearer_token_under_the_configured_username() {
        assert_eq!(
            authorization(&basic("oauth2"), &bearer_credential("upstream-token")),
            "Basic b2F1dGgyOnVwc3RyZWFtLXRva2Vu"
        );
    }

    /// A `basic_api_token` credential keeps its stored username under either
    /// scheme.
    #[test]
    fn basic_credentials_keep_their_own_username() {
        let credential = basic_credential("deploy-user", "deploy-token");
        for token_auth in [GatewayUpstreamTokenAuth::Bearer {}, basic("oauth2")] {
            assert_eq!(
                authorization(&token_auth, &credential),
                "Basic ZGVwbG95LXVzZXI6ZGVwbG95LXRva2Vu"
            );
        }
    }

    /// A token Basic cannot carry fails before anything is sent.
    #[test]
    fn basic_presentation_rejects_unsuitable_tokens() {
        let error = gateway_upstream_authorization(
            &basic("oauth2"),
            &bearer_credential("token with space"),
        )
        .unwrap_err();
        assert_eq!(error.reason_code(), ReasonCode::CredentialInvalid);
    }

    #[test]
    fn basic_usernames_must_be_short_printable_ascii_without_a_colon() {
        let longest = "~".repeat(BASIC_USERNAME_MAX_CHARS);
        for valid in ["oauth2", "a", "service account", longest.as_str()] {
            assert_eq!(basic_username_problem(valid), None, "{valid:?}");
        }
        let too_long = "a".repeat(BASIC_USERNAME_MAX_CHARS + 1);
        for (invalid, problem) in [
            ("", "must not be empty"),
            ("oauth:2", "must not contain a colon"),
            ("tab\tname", "must not contain control characters"),
            ("line\nbreak", "must not contain control characters"),
            ("\u{7f}", "must not contain control characters"),
            ("uni\u{e9}code", "must be printable ASCII"),
            (too_long.as_str(), "must be at most 64 characters"),
        ] {
            assert_eq!(
                basic_username_problem(invalid),
                Some(problem),
                "{invalid:?}"
            );
        }
    }
}
