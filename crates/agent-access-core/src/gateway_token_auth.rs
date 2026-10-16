//! How a Git gateway presents its upstream execution credential: the
//! `[gateways.<name>].upstream_token_auth` setting and the one presentation
//! that gateway forwarding and Git credential verification share.
use agent_access_provider::host::{authorize_host_request, token_as_basic};
use agent_access_provider::{
    CredentialPlacement, ExecutionCredential, ProviderError, ReasonCode, StaticCredentialKind,
};
use serde::Deserialize;

/// The longest `upstream_token_auth.username`, in characters.
const BASIC_USERNAME_MAX_CHARS: usize = 64;

/// `[gateways.<name>].upstream_token_auth`: how a gateway presents a
/// token-kind (`bearer_token`) upstream credential. One table shape, tagged by
/// `scheme`: `{ scheme = "bearer" }`, the default when the setting is absent,
/// or `{ scheme = "basic", username = "<name>" }`. A `basic_api_token`
/// credential always presents its own stored username.
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

/// `request` with the gateway's upstream authorization for `credential`. Git
/// forwarding and Git credential verification both present the gateway's
/// credential through this function, so a verified credential is presented
/// exactly as forwarded requests present it.
///
/// A `basic_api_token` credential presents its stored username and token as
/// HTTP Basic. A `bearer_token` credential presents its token as
/// `token_auth` selects: as a Bearer token, or as the password of HTTP Basic
/// under the configured username. Any other kind fails closed.
pub fn authorize_gateway_upstream_request(
    request: reqwest::RequestBuilder,
    token_auth: &GatewayUpstreamTokenAuth,
    credential: &ExecutionCredential,
) -> Result<reqwest::RequestBuilder, ProviderError> {
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
    Ok(authorize_host_request(request, &authorization))
}

#[cfg(test)]
mod tests {
    use super::*;
    use agent_access_provider::test_support::{basic_credential, bearer_credential};

    fn authorization(
        token_auth: &GatewayUpstreamTokenAuth,
        credential: &ExecutionCredential,
    ) -> String {
        let request = authorize_gateway_upstream_request(
            reqwest::Client::new().get("https://gitlab.example.com/team/project.git/info/refs"),
            token_auth,
            credential,
        )
        .unwrap()
        .build()
        .unwrap();
        let value = &request.headers()[reqwest::header::AUTHORIZATION];
        assert!(value.is_sensitive());
        value.to_str().unwrap().to_owned()
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
        let error = authorize_gateway_upstream_request(
            reqwest::Client::new().get("https://gitlab.example.com/"),
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
