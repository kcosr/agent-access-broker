//! A registration's optional `login_binding`: the Broker installs an OAuth
//! connection only when the upstream account is linked to its owner's
//! Broker sign-in.
//!
//! The owner's linked sign-in is authoritative, whatever sign-in method the
//! browser session used: for Microsoft, their active Microsoft login method,
//! whose external subject is `entra:v1:{tenant}:{object ID}`. The tenant must
//! be the binding's `upstream_tenant_id`, which configuration validation
//! requires to be the Broker's own Microsoft tenant, and the account must
//! report a linked identity at `upstream_identity_provider` whose external ID
//! is that object ID. A principal without such a sign-in cannot connect.
//! Failures carry only their code: never the owner's or the account's
//! identity values.
use super::OAuthError;
use crate::MicrosoftOidcConfig;
use agent_access_provider::{
    LinkedIdentity, OAuthDialect, OAuthLoginBinding, OAuthLoginProvider, OAuthRegistrationConfig,
};

/// External subjects of Microsoft login methods.
const ENTRA_SUBJECT_PREFIX: &str = "entra:v1:";
const MAX_UPSTREAM_IDENTITY_PROVIDER_BYTES: usize = 128;

/// The `principal_login_methods.external_provider` of the binding's sign-in.
pub(crate) fn login_provider(binding: &OAuthLoginBinding) -> Result<&'static str, OAuthError> {
    match binding.provider {
        OAuthLoginProvider::Microsoft => Ok("microsoft"),
        _ => Err(OAuthError::Configuration),
    }
}

/// The owner's user ID at the binding's sign-in, from the external subject
/// of their active linked login method, `None` when they have none.
pub(super) fn owner_id(
    binding: &OAuthLoginBinding,
    linked: Option<&str>,
) -> Result<String, OAuthError> {
    match binding.provider {
        OAuthLoginProvider::Microsoft => {
            let (tenant, object_id) = linked
                .and_then(|subject| subject.strip_prefix(ENTRA_SUBJECT_PREFIX))
                .and_then(|rest| rest.split_once(':'))
                .ok_or(OAuthError::LoginBindingRequired)?;
            if tenant != binding.upstream_tenant_id || object_id.is_empty() {
                return Err(OAuthError::LoginBindingRequired);
            }
            Ok(object_id.to_owned())
        }
        _ => Err(OAuthError::Configuration),
    }
}

/// Whether the connected account is linked to the owner's sign-in: whether
/// it reports an identity at the binding's upstream identity provider whose
/// external ID is the owner's. Entra object IDs are UUIDs, so their case is
/// not significant.
pub(super) fn check(
    binding: &OAuthLoginBinding,
    linked: Option<&str>,
    identities: &[LinkedIdentity],
) -> Result<(), OAuthError> {
    let owner = owner_id(binding, linked)?;
    if identities.iter().any(|identity| {
        identity.provider == binding.upstream_identity_provider
            && identity.external_id.eq_ignore_ascii_case(&owner)
    }) {
        Ok(())
    } else {
        Err(OAuthError::LoginBindingMismatch)
    }
}

/// Whether a binding's own values are well formed.
pub(super) fn well_formed(binding: &OAuthLoginBinding) -> bool {
    upstream_identity_provider_valid(&binding.upstream_identity_provider)
        && canonical_uuid(&binding.upstream_tenant_id)
}

fn upstream_identity_provider_valid(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= MAX_UPSTREAM_IDENTITY_PROVIDER_BYTES
        && !name.chars().any(|c| c.is_whitespace() || c.is_control())
}

fn canonical_uuid(value: &str) -> bool {
    uuid::Uuid::parse_str(value).is_ok_and(|id| id.hyphenated().to_string() == value)
}

/// Offline validation of `oauth.registrations.<name>.login_binding`.
pub(crate) fn validate_config(
    name: &str,
    registration: &OAuthRegistrationConfig,
    dialect: &dyn OAuthDialect,
    microsoft: &MicrosoftOidcConfig,
    errors: &mut Vec<String>,
) {
    let Some(binding) = &registration.login_binding else {
        return;
    };
    let label = format!("oauth.registrations.{name}.login_binding");
    if !dialect.supports_login_binding() {
        errors.push(format!(
            "{label} is not supported by the {} dialect, which reports no linked identities to check",
            registration.adapter.as_str()
        ));
    }
    if !upstream_identity_provider_valid(&binding.upstream_identity_provider) {
        errors.push(format!(
            "{label}.upstream_identity_provider must be the upstream's identity provider name: 1-{MAX_UPSTREAM_IDENTITY_PROVIDER_BYTES} bytes without whitespace or control characters"
        ));
    }
    if !canonical_uuid(&binding.upstream_tenant_id) {
        errors.push(format!(
            "{label}.upstream_tenant_id must be a canonical lowercase UUID"
        ));
    }
    match binding.provider {
        OAuthLoginProvider::Microsoft => {
            if !microsoft.enabled {
                errors.push(format!(
                    "{label} with provider = \"microsoft\" requires browser_auth.oidc.microsoft.enabled"
                ));
            } else if microsoft.tenant_id.as_deref() != Some(binding.upstream_tenant_id.as_str()) {
                errors.push(format!(
                    "{label}.upstream_tenant_id must be browser_auth.oidc.microsoft.tenant_id: the upstream must sign people in through the Broker's own Microsoft tenant"
                ));
            }
        }
        _ => errors.push(format!("{label}.provider is not supported")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TENANT: &str = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa1";
    const OTHER_TENANT: &str = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbb2";
    const OBJECT: &str = "cccccccc-cccc-4ccc-8ccc-ccccccccccc3";

    fn binding() -> OAuthLoginBinding {
        OAuthLoginBinding {
            provider: OAuthLoginProvider::Microsoft,
            upstream_identity_provider: "azure_activedirectory_v2".into(),
            upstream_tenant_id: TENANT.into(),
        }
    }

    fn subject(tenant: &str, object: &str) -> String {
        format!("entra:v1:{tenant}:{object}")
    }

    #[test]
    fn the_account_must_report_the_owners_object_id_at_the_bound_provider() {
        let owner = subject(TENANT, OBJECT);
        let matching = LinkedIdentity::new("azure_activedirectory_v2", OBJECT);
        assert_eq!(
            check(&binding(), Some(&owner), std::slice::from_ref(&matching)),
            Ok(())
        );
        // Entra object IDs are UUIDs, whose case is not significant.
        assert_eq!(
            check(
                &binding(),
                Some(&owner),
                &[LinkedIdentity::new(
                    "azure_activedirectory_v2",
                    OBJECT.to_uppercase()
                )]
            ),
            Ok(())
        );
        // Any of several identities may match.
        assert_eq!(
            check(
                &binding(),
                Some(&owner),
                &[LinkedIdentity::new("ldapmain", "uid=alice"), matching]
            ),
            Ok(())
        );
        for identities in [
            vec![],
            vec![LinkedIdentity::new(
                "azure_activedirectory_v2",
                "dddddddd-dddd-4ddd-8ddd-ddddddddddd4",
            )],
            vec![LinkedIdentity::new("openid_connect", OBJECT)],
            // A user principal name or other ID is never the object ID.
            vec![LinkedIdentity::new(
                "azure_activedirectory_v2",
                "alice@example.com",
            )],
        ] {
            assert_eq!(
                check(&binding(), Some(&owner), &identities),
                Err(OAuthError::LoginBindingMismatch),
                "{identities:?}"
            );
        }
    }

    #[test]
    fn an_owner_without_a_sign_in_in_the_bound_tenant_cannot_connect() {
        let identities = [LinkedIdentity::new("azure_activedirectory_v2", OBJECT)];
        for linked in [
            None,
            Some(subject(OTHER_TENANT, OBJECT)),
            Some(format!("entra:v1:{TENANT}")),
            Some(subject(TENANT, "")),
            Some(format!("other:v1:{TENANT}:{OBJECT}")),
        ] {
            assert_eq!(
                check(&binding(), linked.as_deref(), &identities),
                Err(OAuthError::LoginBindingRequired),
                "{linked:?}"
            );
        }
    }

    #[test]
    fn binding_values_must_be_well_formed() {
        assert!(well_formed(&binding()));
        for change in [
            |b: &mut OAuthLoginBinding| b.upstream_identity_provider.clear(),
            |b: &mut OAuthLoginBinding| b.upstream_identity_provider = "azure ad".into(),
            |b: &mut OAuthLoginBinding| b.upstream_identity_provider = "x".repeat(129),
            |b: &mut OAuthLoginBinding| b.upstream_tenant_id = TENANT.to_uppercase(),
            |b: &mut OAuthLoginBinding| b.upstream_tenant_id = "tenant".into(),
        ] {
            let mut binding = binding();
            change(&mut binding);
            assert!(!well_formed(&binding), "{binding:?}");
        }
    }
}
