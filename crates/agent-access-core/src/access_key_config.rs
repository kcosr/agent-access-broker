//! `[access_key_types.<id>]` and `[usernames]`: what an access key may be used
//! for at the service that resolves it, and how people are named there.
use crate::{
    BrokerConfig, ConfigError, finish_validation, is_safe_principal,
    is_valid_execution_context_value, parse_ttl_seconds,
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

/// `[access_key_types]`, keyed by access key type ID.
pub type AccessKeyTypesConfig = BTreeMap<String, AccessKeyTypeConfig>;

/// Access key types one access key may carry.
pub const ACCESS_KEY_MAX_TYPES: usize = 16;
/// The longest finite lifetime an access key type may offer.
pub const ACCESS_KEY_MAX_FINITE_LIFETIME_SECONDS: u64 = 3650 * 24 * 60 * 60;
/// Lifetime choices one access key type may offer.
pub const ACCESS_KEY_MAX_LIFETIME_OPTIONS: usize = 16;
const ACCESS_KEY_TYPE_DISPLAY_NAME_MAX_BYTES: usize = 128;
const ACCESS_KEY_TYPE_DESCRIPTION_MAX_BYTES: usize = 1024;
const ACCOUNT_USERNAME_EMAIL_DOMAIN_MAX_BYTES: usize = 253;

#[derive(Debug, Clone, Deserialize)]
#[serde(remote = "Self", deny_unknown_fields)]
pub struct AccessKeyTypeConfig {
    pub display_name: String,
    /// Plain text for people, such as where to point their tool.
    #[serde(default)]
    pub description: Option<String>,
    pub lifetime_options: Vec<String>,
    pub default_lifetime: String,
    /// Whether people may create tokens of this type for themselves. Who may
    /// hold the type is each account's access key type setting, not
    /// configuration.
    #[serde(default)]
    pub self_service: bool,
}

// A table only: an array is not read as the keys in order.
crate::deserialize_object_only!(AccessKeyTypeConfig);

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum AccessKeyLifetime {
    Finite(u64),
    Never,
}

/// Whether a requested access key lifetime is a positive duration of at most
/// 3650 days, or the literal `never`. Offering that lifetime is a separate
/// per-type issuance check.
pub fn is_valid_access_key_lifetime(value: &str) -> bool {
    parse_access_key_lifetime(value).is_some()
}

pub(crate) fn parse_access_key_lifetime(value: &str) -> Option<AccessKeyLifetime> {
    if value == "never" {
        Some(AccessKeyLifetime::Never)
    } else {
        parse_ttl_seconds(value)
            .filter(|seconds| *seconds <= ACCESS_KEY_MAX_FINITE_LIFETIME_SECONDS)
            .map(AccessKeyLifetime::Finite)
    }
}

/// `[usernames]`: how people are named at the services that resolve keys.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(remote = "Self", deny_unknown_fields)]
pub struct AccountUsernamesConfig {
    /// Email domains whose addresses name their account by local part.
    #[serde(default)]
    pub email_domains: Vec<String>,
    /// Names never given to a person.
    #[serde(default)]
    pub reserved_names: Vec<String>,
    /// IDs that services already use for people: a person holding one cannot use
    /// it until an administrator confirms the account is that person.
    #[serde(default)]
    pub existing_usernames: Vec<String>,
}

crate::deserialize_object_only!(AccountUsernamesConfig);

/// Whether `value` can be a username: 1 to 256 bytes of letters,
/// digits and `._@+-`, other than `anonymous` or the Broker secret namespace `aab_`.
pub fn is_valid_account_username(value: &str) -> bool {
    value != "anonymous" && !crate::has_broker_secret_prefix(value) && is_safe_principal(value)
}

fn is_valid_email_domain(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= ACCOUNT_USERNAME_EMAIL_DOMAIN_MAX_BYTES
        && value.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        })
}

/// Plain text people read: 1 to `max` bytes, without control characters or
/// surrounding whitespace.
fn is_plain_text(text: &str, max: usize) -> bool {
    !text.trim().is_empty()
        && text.trim() == text
        && text.len() <= max
        && !text.chars().any(char::is_control)
}

pub(crate) fn validate(config: &BrokerConfig, errors: &mut Vec<String>) {
    let names = &config.usernames;
    let configured = !config.access_key_types.is_empty()
        || !names.email_domains.is_empty()
        || !names.reserved_names.is_empty()
        || !names.existing_usernames.is_empty();
    if configured
        && (config.identity.authority != "managed"
            || config.managed_store.is_none()
            || config.broker_tokens.is_none())
    {
        errors.push(
            "access_key_types and usernames require identity.authority = \"managed\", [managed_store] and [broker_tokens]: access keys and usernames exist only for managed accounts"
                .to_string(),
        );
    }
    for (id, access_key_type) in &config.access_key_types {
        let label = format!("access_key_types.{id}");
        if !is_valid_execution_context_value(id) {
            errors.push(format!(
                "{label} has an invalid access key type ID; use [a-z][a-z0-9_-]{{0,63}}"
            ));
        }
        if !is_plain_text(
            &access_key_type.display_name,
            ACCESS_KEY_TYPE_DISPLAY_NAME_MAX_BYTES,
        ) {
            errors.push(format!(
                "{label}.display_name must be 1 to {ACCESS_KEY_TYPE_DISPLAY_NAME_MAX_BYTES} bytes without control characters or surrounding whitespace"
            ));
        }
        if access_key_type
            .description
            .as_deref()
            .is_some_and(|description| {
                !is_plain_text(description, ACCESS_KEY_TYPE_DESCRIPTION_MAX_BYTES)
            })
        {
            errors.push(format!(
                "{label}.description must be 1 to {ACCESS_KEY_TYPE_DESCRIPTION_MAX_BYTES} bytes without control characters or surrounding whitespace"
            ));
        }
        if access_key_type.lifetime_options.is_empty()
            || access_key_type.lifetime_options.len() > ACCESS_KEY_MAX_LIFETIME_OPTIONS
        {
            errors.push(format!(
                "{label}.lifetime_options must contain 1 to {ACCESS_KEY_MAX_LIFETIME_OPTIONS} choices"
            ));
        }
        let mut lifetimes = BTreeSet::new();
        for value in &access_key_type.lifetime_options {
            match parse_access_key_lifetime(value) {
                Some(lifetime) if lifetimes.insert(lifetime) => {}
                Some(_) => errors.push(format!(
                    "{label}.lifetime_options must not repeat an effective duration or never"
                )),
                None => errors.push(format!(
                    "{label}.lifetime_options entries must be positive durations of at most 3650d, such as 8h or 30d, or never"
                )),
            }
        }
        if parse_access_key_lifetime(&access_key_type.default_lifetime)
            .is_none_or(|lifetime| !lifetimes.contains(&lifetime))
        {
            errors.push(format!(
                "{label}.default_lifetime must match a lifetime_options entry by effective duration or never"
            ));
        }
    }
    let mut seen = BTreeSet::new();
    if names
        .email_domains
        .iter()
        .any(|domain| !is_valid_email_domain(domain) || !seen.insert(domain))
    {
        errors
            .push("usernames.email_domains must list distinct lower-case domain names".to_string());
    }
    let mut reserved = BTreeSet::new();
    if names
        .reserved_names
        .iter()
        .any(|name| !is_safe_principal(name) || !reserved.insert(name))
    {
        errors.push(
            "usernames.reserved_names must list distinct usernames of 1 to 256 letters, digits and ._@+-"
                .to_string(),
        );
    }
    let mut existing = BTreeSet::new();
    if names
        .existing_usernames
        .iter()
        .any(|name| !is_valid_account_username(name) || !existing.insert(name))
    {
        errors.push(
            "usernames.existing_usernames must list distinct usernames of 1 to 256 letters, digits and ._@+-"
                .to_string(),
        );
    }
    if existing.iter().any(|name| reserved.contains(name)) {
        errors.push(
            "usernames.existing_usernames must not repeat a name in usernames.reserved_names"
                .to_string(),
        );
    }
}

/// One access key type as the current configuration defines it.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct AccessKeyType {
    pub id: String,
    pub display_name: String,
    /// Plain text for people, or `None`.
    pub description: Option<String>,
    pub lifetime_options: Vec<String>,
    pub default_lifetime: String,
    /// Whether people may create tokens of this type for themselves.
    pub self_service: bool,
}

impl AccessKeyType {
    pub(crate) fn offers_lifetime(&self, lifetime: AccessKeyLifetime) -> bool {
        self.lifetime_options
            .iter()
            .any(|value| parse_access_key_lifetime(value) == Some(lifetime))
    }

    /// `None` means that the type offers an unlimited lifetime.
    pub(crate) fn maximum_lifetime_seconds(&self) -> Option<u64> {
        self.lifetime_options
            .iter()
            .map(|value| {
                match parse_access_key_lifetime(value)
                    .expect("validated access key lifetime option")
                {
                    AccessKeyLifetime::Finite(seconds) => Some(seconds),
                    AccessKeyLifetime::Never => None,
                }
            })
            .try_fold(0, |maximum, seconds| {
                seconds.map(|seconds| maximum.max(seconds))
            })
    }
}

/// The access key types of one runtime generation. Any access key type requires
/// managed identity authority, which configuration validation enforces.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AccessKeyTypes {
    entries: BTreeMap<String, AccessKeyType>,
}

impl AccessKeyTypes {
    /// The validated access key types of `config`.
    pub fn from_config(config: &BrokerConfig) -> Result<Self, ConfigError> {
        let mut errors = Vec::new();
        validate(config, &mut errors);
        finish_validation(errors)?;
        let entries = config
            .access_key_types
            .iter()
            .map(|(id, access_key_type)| {
                (
                    id.clone(),
                    AccessKeyType {
                        id: id.clone(),
                        display_name: access_key_type.display_name.clone(),
                        description: access_key_type.description.clone(),
                        lifetime_options: access_key_type.lifetime_options.clone(),
                        default_lifetime: access_key_type.default_lifetime.clone(),
                        self_service: access_key_type.self_service,
                    },
                )
            })
            .collect();
        Ok(Self { entries })
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn get(&self, id: &str) -> Option<&AccessKeyType> {
        self.entries.get(id)
    }

    /// Every access key type, by ID.
    pub fn iter(&self) -> impl ExactSizeIterator<Item = &AccessKeyType> {
        self.entries.values()
    }
}

/// Why derivation from an email produced no candidate name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccountUsernameCandidateError {
    /// The account has no profile email.
    NoEmail,
    /// The profile email is not one address with a local part and a domain.
    EmailUnusable,
    /// The email's domain is not one derivation applies to.
    DomainNotListed,
    /// The lower-cased local part is not a valid username.
    NameInvalid,
}

/// The username settings of one runtime generation.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AccountUsernamePolicy {
    email_domains: BTreeSet<String>,
    reserved_names: BTreeSet<String>,
    existing_usernames: BTreeSet<String>,
}

impl AccountUsernamePolicy {
    /// The validated username settings of `config`.
    pub fn from_config(config: &BrokerConfig) -> Result<Self, ConfigError> {
        let mut errors = Vec::new();
        validate(config, &mut errors);
        finish_validation(errors)?;
        let names = &config.usernames;
        Ok(Self {
            email_domains: names.email_domains.iter().cloned().collect(),
            reserved_names: names.reserved_names.iter().cloned().collect(),
            existing_usernames: names.existing_usernames.iter().cloned().collect(),
        })
    }

    /// Whether the operator reserved `name`: it is never given to a person.
    pub fn is_reserved(&self, name: &str) -> bool {
        self.reserved_names.contains(name)
    }

    /// Whether `name` is an ID that services already use for a person, which an
    /// administrator must confirm before its holder can use it.
    pub fn requires_confirmation(&self, name: &str) -> bool {
        self.existing_usernames.contains(name)
    }

    /// The name `email` derives: its lower-cased local part, when the
    /// address has exactly one `@`, its lower-cased domain is listed and the
    /// local part is a valid username. The email only names the account it
    /// is stored on; it never selects an account.
    pub fn candidate(&self, email: Option<&str>) -> Result<String, AccountUsernameCandidateError> {
        let email = email
            .map(str::trim)
            .filter(|email| !email.is_empty())
            .ok_or(AccountUsernameCandidateError::NoEmail)?;
        let (local, domain) = email
            .split_once('@')
            .filter(|(local, domain)| {
                !local.is_empty() && !domain.is_empty() && !domain.contains('@')
            })
            .ok_or(AccountUsernameCandidateError::EmailUnusable)?;
        if !self.email_domains.contains(&domain.to_ascii_lowercase()) {
            return Err(AccountUsernameCandidateError::DomainNotListed);
        }
        let name = local.to_ascii_lowercase();
        if is_valid_account_username(&name) {
            Ok(name)
        } else {
            Err(AccountUsernameCandidateError::NameInvalid)
        }
    }
}

#[cfg(test)]
impl AccountUsernamePolicy {
    pub(crate) fn for_test(domains: &[&str], reserved: &[&str], existing: &[&str]) -> Self {
        let set = |values: &[&str]| values.iter().map(|value| (*value).to_string()).collect();
        Self {
            email_domains: set(domains),
            reserved_names: set(reserved),
            existing_usernames: set(existing),
        }
    }
}

#[cfg(test)]
impl AccessKeyTypes {
    pub(crate) fn for_test(entries: impl IntoIterator<Item = AccessKeyType>) -> Self {
        Self {
            entries: entries
                .into_iter()
                .map(|access_key_type| (access_key_type.id.clone(), access_key_type))
                .collect(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn candidate_is_the_lower_cased_local_part_of_a_listed_domain() {
        let policy = AccountUsernamePolicy::for_test(&["example.com"], &[], &[]);
        assert_eq!(
            policy.candidate(Some("Alice.Smith@Example.COM")).unwrap(),
            "alice.smith"
        );
        assert_eq!(
            policy.candidate(Some(" bob+ci@example.com ")).unwrap(),
            "bob+ci"
        );
        for (email, expected) in [
            (None, AccountUsernameCandidateError::NoEmail),
            (Some("  "), AccountUsernameCandidateError::NoEmail),
            (Some("alice"), AccountUsernameCandidateError::EmailUnusable),
            (
                Some("@example.com"),
                AccountUsernameCandidateError::EmailUnusable,
            ),
            (Some("alice@"), AccountUsernameCandidateError::EmailUnusable),
            (
                Some("a@b@example.com"),
                AccountUsernameCandidateError::EmailUnusable,
            ),
            (
                Some("alice@example.org"),
                AccountUsernameCandidateError::DomainNotListed,
            ),
            (
                Some("alice@mail.example.com"),
                AccountUsernameCandidateError::DomainNotListed,
            ),
            (
                Some("alice smith@example.com"),
                AccountUsernameCandidateError::NameInvalid,
            ),
            (
                Some("al/ice@example.com"),
                AccountUsernameCandidateError::NameInvalid,
            ),
            (
                Some("anonymous@example.com"),
                AccountUsernameCandidateError::NameInvalid,
            ),
            (
                Some("ålice@example.com"),
                AccountUsernameCandidateError::NameInvalid,
            ),
        ] {
            assert_eq!(policy.candidate(email).unwrap_err(), expected, "{email:?}");
        }
        let long = format!("{}@example.com", "a".repeat(257));
        assert_eq!(
            policy.candidate(Some(&long)).unwrap_err(),
            AccountUsernameCandidateError::NameInvalid
        );
        assert_eq!(
            AccountUsernamePolicy::default()
                .candidate(Some("alice@example.com"))
                .unwrap_err(),
            AccountUsernameCandidateError::DomainNotListed
        );
    }
}
