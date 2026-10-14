//! Typed credential selection: the grant's credential mode and the execution
//! material the host lends one invocation.
use crate::authorization::Material;
use crate::{
    CredentialPlacement, CredentialPlacementError, DelegatedCredential, UpstreamAuthorization,
};
use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;

/// The grant mode that selected an invocation's credentials, independent of
/// whether the action needs execution material. Descriptors, configuration
/// and audit spell it `service` or `per_user`.
///
/// Intentionally exhaustive: the two modes are a closed, stored and
/// configured contract, and every grant, credential slot and audit record
/// names one of them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CredentialMode {
    Service,
    PerUser,
}

impl CredentialMode {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Service => "service",
            Self::PerUser => "per_user",
        }
    }
}

impl fmt::Display for CredentialMode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// A credential mode spelling other than `service` or `per_user`. A unit
/// error by design: it carries no detail.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("unsupported credential mode")]
pub struct UnsupportedCredentialMode;

impl FromStr for CredentialMode {
    type Err = UnsupportedCredentialMode;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "service" => Ok(Self::Service),
            "per_user" => Ok(Self::PerUser),
            _ => Err(UnsupportedCredentialMode),
        }
    }
}

/// The static credential kinds the host stores and selects, spelled
/// `basic_api_token` and `bearer_token` in configuration and stored rows.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum StaticCredentialKind {
    BasicApiToken,
    BearerToken,
}

impl StaticCredentialKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::BasicApiToken => "basic_api_token",
            Self::BearerToken => "bearer_token",
        }
    }
}

/// Static credential material selected by the host. Only the host
/// construction port ([`crate::host`]) and test support construct it, so the
/// material each kind requires is always present.
///
/// Providers never read the material. They obtain an
/// [`UpstreamAuthorization`] with [`Self::authorization`], in the kind's own
/// HTTP authentication scheme, or [`Self::authorization_as`], in a
/// [`CredentialPlacement`] the upstream requires, and hand it to the upstream
/// client's send methods, which add it to the request. [`Self::kind`] is the
/// only fact about it they can inspect. The
/// value does not serialize, never appears in Debug output, and compares
/// equal to a credential with the same kind and material.
#[derive(Clone, PartialEq, Eq)]
pub struct ExecutionCredential {
    material: CredentialMaterial,
}

#[derive(Clone, PartialEq, Eq)]
enum CredentialMaterial {
    Basic { username: String, token: String },
    Bearer { token: String },
}

impl ExecutionCredential {
    pub(crate) fn basic(username: String, token: String) -> Self {
        Self {
            material: CredentialMaterial::Basic { username, token },
        }
    }

    pub(crate) fn bearer(token: String) -> Self {
        Self {
            material: CredentialMaterial::Bearer { token },
        }
    }

    pub fn kind(&self) -> StaticCredentialKind {
        match self.material {
            CredentialMaterial::Basic { .. } => StaticCredentialKind::BasicApiToken,
            CredentialMaterial::Bearer { .. } => StaticCredentialKind::BearerToken,
        }
    }

    /// The credential in its kind's own HTTP authentication scheme:
    /// `Authorization: Basic` with the username and token for
    /// `basic_api_token`, and `Authorization: Bearer` with the token for
    /// `bearer_token`. It presents the material as stored, without further
    /// checks. A provider that supports only some kinds checks
    /// [`Self::kind`] first and rejects the others.
    pub fn authorization(&self) -> UpstreamAuthorization {
        self.material().authorization()
    }

    /// The credential presented in `placement`, after the placement's checks
    /// of its kind and material.
    pub fn authorization_as(
        &self,
        placement: &CredentialPlacement,
    ) -> Result<UpstreamAuthorization, CredentialPlacementError> {
        self.material().placed(placement)
    }

    fn material(&self) -> Material<'_> {
        match &self.material {
            CredentialMaterial::Basic { username, token } => Material::Basic { username, token },
            CredentialMaterial::Bearer { token } => Material::Token(token),
        }
    }
}

impl fmt::Debug for ExecutionCredential {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ExecutionCredential")
            .field("kind", &self.kind().as_str())
            .finish_non_exhaustive()
    }
}

/// The execution material lent to one invocation. Static and delegated
/// material never coexist; lookup material is separate and never stands in
/// for either.
#[non_exhaustive]
#[derive(Debug, Clone)]
pub enum ExecutionAccess {
    /// The action needs no execution credential, such as a Teams Workflow
    /// whose authority is a private resource attribute.
    None,
    Static(ExecutionCredential),
    Delegated(DelegatedCredential),
}

impl ExecutionAccess {
    pub fn static_credential(&self) -> Option<&ExecutionCredential> {
        match self {
            Self::Static(credential) => Some(credential),
            Self::None | Self::Delegated(_) => None,
        }
    }

    pub fn delegated(&self) -> Option<&DelegatedCredential> {
        match self {
            Self::Delegated(credential) => Some(credential),
            Self::None | Self::Static(_) => None,
        }
    }

    pub fn is_none(&self) -> bool {
        matches!(self, Self::None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn credential_modes_keep_their_external_spellings() {
        for (mode, spelling) in [
            (CredentialMode::Service, "service"),
            (CredentialMode::PerUser, "per_user"),
        ] {
            assert_eq!(mode.as_str(), spelling);
            assert_eq!(mode.to_string(), spelling);
            assert_eq!(spelling.parse::<CredentialMode>(), Ok(mode));
            assert_eq!(
                serde_json::to_value(mode).unwrap(),
                serde_json::json!(spelling)
            );
            assert_eq!(
                serde_json::from_value::<CredentialMode>(serde_json::json!(spelling)).unwrap(),
                mode
            );
        }
        for rejected in ["lookup", "Service", "per-user", ""] {
            assert_eq!(
                rejected.parse::<CredentialMode>(),
                Err(UnsupportedCredentialMode)
            );
        }
    }

    fn authorization_header(authorization: UpstreamAuthorization) -> String {
        let request = crate::host::authorize_host_request(
            reqwest::Client::new().get("https://service.example.test/"),
            &authorization,
        )
        .build()
        .unwrap();
        let value = &request.headers()[reqwest::header::AUTHORIZATION];
        assert!(value.is_sensitive());
        value.to_str().unwrap().to_owned()
    }

    #[test]
    fn credentials_present_their_kind_and_redact_debug() {
        let basic = ExecutionCredential::basic("user@example.test".into(), "basic-secret".into());
        assert_eq!(basic.kind(), StaticCredentialKind::BasicApiToken);
        assert_eq!(basic.kind().as_str(), "basic_api_token");
        assert_eq!(
            authorization_header(basic.authorization()),
            "Basic dXNlckBleGFtcGxlLnRlc3Q6YmFzaWMtc2VjcmV0"
        );
        let bearer = ExecutionCredential::bearer("bearer-secret".into());
        assert_eq!(bearer.kind().as_str(), "bearer_token");
        assert_eq!(
            authorization_header(bearer.authorization()),
            "Bearer bearer-secret"
        );
        assert_eq!(
            authorization_header(
                bearer
                    .authorization_as(&CredentialPlacement::bearer())
                    .unwrap()
            ),
            "Bearer bearer-secret"
        );
        assert_eq!(
            basic
                .authorization_as(&CredentialPlacement::bearer())
                .unwrap_err(),
            CredentialPlacementError::KindMismatch
        );
        let rendered = format!(
            "{basic:?} {bearer:?} {:?} {:?}",
            basic.authorization(),
            ExecutionAccess::Static(bearer.clone())
        );
        for secret in ["user@example.test", "basic-secret", "bearer-secret"] {
            assert!(!rendered.contains(secret), "{rendered}");
        }
        assert!(rendered.contains("basic_api_token") && rendered.contains("bearer_token"));
    }

    #[test]
    fn credentials_compare_by_kind_and_material() {
        let basic = ExecutionCredential::basic("user".into(), "token".into());
        assert_eq!(
            basic,
            ExecutionCredential::basic("user".into(), "token".into())
        );
        assert_ne!(
            basic,
            ExecutionCredential::basic("user".into(), "other".into())
        );
        assert_ne!(
            basic,
            ExecutionCredential::basic("other".into(), "token".into())
        );
        assert_ne!(
            ExecutionCredential::bearer("token".into()),
            ExecutionCredential::basic(String::new(), "token".into())
        );
    }

    #[test]
    fn execution_access_holds_one_kind_of_material() {
        let credential = ExecutionCredential::bearer("token".into());
        let static_access = ExecutionAccess::Static(credential);
        assert!(static_access.static_credential().is_some());
        assert!(static_access.delegated().is_none());
        assert!(!static_access.is_none());
        assert!(ExecutionAccess::None.is_none());
        assert!(ExecutionAccess::None.static_credential().is_none());
    }
}
