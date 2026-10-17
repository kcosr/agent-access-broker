//! Shared ownership checks for native and core-owned domain reasons.
use agent_access_provider::{
    BackendRegistration, ProviderReasonDefinition, ReasonCode, domain_reason_prefix,
};
use std::collections::BTreeMap;

/// The namespace standard reasons added by the Broker use.
const RESERVED_PREFIX: &str = "broker_";

/// Checks every registration's declared domain reasons. A code must start
/// with its owner's prefix (the kind with hyphens as underscores, then `_`)
/// and a nonempty name, must not be a standard code, and must have exactly
/// one owner. Because no owner prefix may start `broker_`, no domain code
/// enters the reserved namespace. Only complete codes are owned: kinds
/// whose prefixes overlap or normalize equally coexist while their codes
/// differ. A kind that cannot fit a prefix and name in the 64-byte cap, or
/// whose prefix is reserved, registers only without domain reasons.
/// Internal ownership record. A core built-in does not pretend to be a linked
/// native backend: only its domain definitions participate in these checks.
pub(super) struct DomainReasonOwner {
    kind: &'static str,
    reasons: &'static [&'static ProviderReasonDefinition],
    core: bool,
}

impl DomainReasonOwner {
    pub(super) fn native(registration: &'static BackendRegistration) -> Self {
        Self {
            kind: registration.kind(),
            reasons: registration.domain_reasons(),
            core: false,
        }
    }

    pub(super) const fn core(
        kind: &'static str,
        reasons: &'static [&'static ProviderReasonDefinition],
    ) -> Self {
        Self {
            kind,
            reasons,
            core: true,
        }
    }

    fn label(&self) -> String {
        format!(
            "{} {}",
            if self.core {
                "core built-in owner"
            } else {
                "backend kind"
            },
            self.kind
        )
    }
}

pub(super) fn validate_owners(owners: impl IntoIterator<Item = DomainReasonOwner>) -> Vec<String> {
    let mut errors = Vec::new();
    let mut registered = BTreeMap::<&'static str, (&'static str, bool)>::new();
    for owner in owners {
        let core = owner.core;
        let kind = owner.kind;
        let reasons = owner.reasons;
        let label = owner.label();
        if reasons.is_empty() {
            continue;
        }
        let prefix = domain_reason_prefix(kind);
        if prefix.starts_with(RESERVED_PREFIX) {
            errors.push(format!(
                "{label} cannot declare domain reasons: the {RESERVED_PREFIX} \
                 reason namespace is reserved for the Broker"
            ));
            continue;
        }
        if prefix.len() >= agent_access_provider::ReasonCodeId::MAX_LEN {
            errors.push(format!(
                "{label} is too long to declare domain reasons: a code must fit \
                 {prefix} and a name in {} bytes",
                agent_access_provider::ReasonCodeId::MAX_LEN
            ));
            continue;
        }
        for definition in reasons {
            let code = definition.code();
            if code.len() <= prefix.len() || !code.starts_with(&prefix) {
                errors.push(format!(
                    "domain reason {code} of {label} must start with {prefix} \
                     followed by a name"
                ));
            } else if ReasonCode::all()
                .iter()
                .any(|standard| standard.as_str() == code)
            {
                errors.push(format!(
                    "domain reason {code} of {label} is a standard reason"
                ));
            } else if let Some(owner) = registered.insert(code, (kind, core)) {
                errors.push(if owner == (kind, core) {
                    format!("domain reason {code} is declared more than once by {label}")
                } else if !owner.1 && !core {
                    format!(
                        "domain reason {code} is declared by backend kinds {} and {kind}",
                        owner.0
                    )
                } else {
                    format!("domain reason {code} is declared by multiple owners including {label}")
                });
            }
        }
    }
    errors
}

#[cfg(test)]
fn validate(registrations: &[&'static BackendRegistration]) -> Vec<String> {
    validate_owners(registrations.iter().copied().map(DomainReasonOwner::native))
}

#[cfg(test)]
mod tests {
    use super::*;
    use agent_access_provider::{
        BackendConfig, ProviderFailureStatus, ProviderReasonDefinition, module_metadata,
    };

    fn parse(
        _: toml::de::ValueDeserializer<'_>,
    ) -> Result<Box<dyn BackendConfig>, toml::de::Error> {
        unreachable!("validation never parses configuration")
    }

    fn registration(
        kind: &'static str,
        reasons: &'static [&'static ProviderReasonDefinition],
    ) -> &'static BackendRegistration {
        Box::leak(Box::new(
            BackendRegistration::new(module_metadata!(), kind, parse).with_domain_reasons(reasons),
        ))
    }

    fn deny(code: &'static str) -> &'static ProviderReasonDefinition {
        Box::leak(Box::new(ProviderReasonDefinition::deny(
            code,
            ProviderFailureStatus::Conflict,
        )))
    }

    fn reasons(codes: &[&'static str]) -> &'static [&'static ProviderReasonDefinition] {
        Box::leak(
            codes
                .iter()
                .map(|code| deny(code))
                .collect::<Vec<_>>()
                .into_boxed_slice(),
        )
    }

    #[test]
    fn core_owners_obey_the_same_namespace_and_uniqueness_rules() {
        assert!(
            validate_owners([DomainReasonOwner::core(
                "access_management",
                reasons(&["access_management_target_exists"])
            )])
            .is_empty()
        );
        let errors = validate_owners([
            DomainReasonOwner::core(
                "access_management",
                reasons(&["access_management_target_exists"]),
            ),
            DomainReasonOwner::native(registration(
                "access-management",
                reasons(&["access_management_target_exists"]),
            )),
        ]);
        assert_eq!(errors.len(), 1);
        assert!(errors[0].contains("multiple owners"));
        let errors = validate_owners([DomainReasonOwner::core(
            "broker_management",
            reasons(&["broker_management_exists"]),
        )]);
        assert_eq!(errors.len(), 1);
        assert!(errors[0].contains("reserved"));
    }

    #[test]
    fn overlapping_and_equal_prefixes_coexist_with_distinct_codes() {
        let registrations = [
            registration(
                "gitlab",
                reasons(&["gitlab_merge_blocked", "gitlab_dedicated_x"]),
            ),
            registration("gitlab_dedicated", reasons(&["gitlab_dedicated_quota"])),
            registration("gitlab-dedicated", reasons(&["gitlab_dedicated_export"])),
        ];
        assert_eq!(validate(&registrations), Vec::<String>::new());
    }

    #[test]
    fn complete_codes_have_exactly_one_owner() {
        let registrations = [
            registration("gitlab", reasons(&["gitlab_dedicated_quota"])),
            registration("gitlab_dedicated", reasons(&["gitlab_dedicated_quota"])),
            registration("gitlab-dedicated", reasons(&["gitlab_dedicated_export"])),
            registration("gitlab_dedicated2", reasons(&[])),
            registration("jira", reasons(&["jira_lock", "jira_lock"])),
        ];
        assert_eq!(
            validate(&registrations),
            [
                "domain reason gitlab_dedicated_quota is declared by backend kinds gitlab and \
                 gitlab_dedicated",
                "domain reason jira_lock is declared more than once by backend kind jira",
            ]
        );
    }

    #[test]
    fn codes_start_with_their_owner_prefix_and_a_name() {
        let registrations = [registration(
            "cloud-ci",
            reasons(&[
                "cloud_ci_ok",
                "cloud_ci_",
                "cloudci_x",
                "jira_lock",
                "cloud_ci",
            ]),
        )];
        assert_eq!(
            validate(&registrations),
            [
                "domain reason cloud_ci_ of backend kind cloud-ci must start with cloud_ci_ \
                 followed by a name",
                "domain reason cloudci_x of backend kind cloud-ci must start with cloud_ci_ \
                 followed by a name",
                "domain reason jira_lock of backend kind cloud-ci must start with cloud_ci_ \
                 followed by a name",
                "domain reason cloud_ci of backend kind cloud-ci must start with cloud_ci_ \
                 followed by a name",
            ]
        );
    }

    #[test]
    fn standard_codes_are_never_domain_reasons() {
        let registrations = [
            registration("upstream", reasons(&["upstream_failed", "upstream_quota"])),
            registration("git", reasons(&["git_ref_denied"])),
        ];
        assert_eq!(
            validate(&registrations),
            [
                "domain reason upstream_failed of backend kind upstream is a standard reason",
                "domain reason git_ref_denied of backend kind git is a standard reason",
            ]
        );
    }

    #[test]
    fn reserved_and_long_kinds_register_only_without_domain_reasons() {
        let long: &'static str = Box::leak("k".repeat(63).into_boxed_str());
        let longest_with_reasons: &'static str = Box::leak("k".repeat(62).into_boxed_str());
        let longest_code: &'static str =
            Box::leak(format!("{longest_with_reasons}_x").into_boxed_str());
        let registrations = [
            registration("broker-tools", reasons(&[])),
            registration("broker_tools", reasons(&[])),
            registration(long, reasons(&[])),
            registration(longest_with_reasons, reasons(&[longest_code])),
        ];
        assert_eq!(validate(&registrations), Vec::<String>::new());

        let registrations = [
            registration("broker-tools", reasons(&["broker_tools_quota"])),
            registration("broker", reasons(&["broker_quota"])),
            registration(long, reasons(&["k_x"])),
        ];
        assert_eq!(
            validate(&registrations),
            [
                "backend kind broker-tools cannot declare domain reasons: the broker_ reason \
                 namespace is reserved for the Broker",
                "backend kind broker cannot declare domain reasons: the broker_ reason \
                 namespace is reserved for the Broker",
                format!(
                    "backend kind {long} is too long to declare domain reasons: a code must fit \
                     {long}_ and a name in 64 bytes"
                )
                .as_str(),
            ]
        );
    }
}
