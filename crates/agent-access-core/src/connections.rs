//! Credential connections: the per-principal credential slots services
//! consume, and how a principal's kind selects a connection's method.
//!
//! `[credentials.connections.<id>]` configures a connection and each
//! consuming service names it from `[credentials.per_user.<service>]` with
//! `type = "connection"`. The runtime adds a single-consumer connection for
//! each imported service with a supported, allowed personal binding, keyed
//! by the imported service ID, so the effective connections are the
//! configured ones plus those. [`select`] decides a principal's method from
//! configuration alone; whether that method's material is present is a
//! separate availability check.
//!
//! Token rows of a connection live in the managed store's `credentials`
//! table with the connection ID in the `service` column and
//! [`CONNECTION_CREDENTIAL_NAME`] as the name, so a connection with the same
//! ID and profile as an earlier per-service credential reads its rows
//! unchanged. OAuth connections keep their per-owner, per-registration slots.

use crate::{BrokerConfig, CredentialsConfig, OAuthBinding};
use agent_access_provider::{ServiceDescriptor, is_service_name};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::sync::Arc;

/// The stored name of every connection token row; the row's `service`
/// column holds the connection ID.
pub const CONNECTION_CREDENTIAL_NAME: &str = "default";

/// The kind of a managed principal, read from `principals.kind`. It selects a
/// credential connection's method; configured static principals and
/// anonymous callers have none, so they select no personal method.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PrincipalKind {
    User,
    ServiceAccount,
    System,
}

impl PrincipalKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::User => "user",
            Self::ServiceAccount => "service_account",
            Self::System => "system",
        }
    }

    /// The kind a stored `principals.kind` value names. Any other value is
    /// `None`, which selects no personal credential method.
    pub fn from_stored(kind: &str) -> Option<Self> {
        match kind {
            "user" => Some(Self::User),
            "service_account" => Some(Self::ServiceAccount),
            "system" => Some(Self::System),
            _ => None,
        }
    }
}

/// `[credentials.connections.<id>]`: one per-principal credential slot that
/// every service whose `credentials.per_user` entry names it consumes.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConnectionConfig {
    /// The name management shows for the connection.
    pub display_name: Option<String>,
    /// The stored token form: self-service for users when `oauth` is unset
    /// and for system principals, administrator-provisioned for service
    /// accounts.
    pub token_profile: Option<String>,
    /// OAuth for user principals, who then never store a token.
    pub oauth: Option<ConnectionOAuthConfig>,
}

/// `oauth = { registration, profile }` of a connection: a configured OAuth
/// registration and one of its permission profiles.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConnectionOAuthConfig {
    pub registration: String,
    pub profile: String,
}

impl ConnectionOAuthConfig {
    /// The OAuth binding a selected principal's connection uses.
    pub fn binding(&self) -> OAuthBinding {
        OAuthBinding {
            registration: self.registration.clone(),
            permission_profile: self.profile.clone(),
        }
    }
}

/// A principal's method for one connection, from configuration alone.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Selection<'a> {
    /// The principal's stored token row for the connection, which must have
    /// this profile.
    Token(&'a str),
    /// The principal's OAuth connection for this registration and profile;
    /// a stored token row is never read.
    OAuth(&'a ConnectionOAuthConfig),
    /// No personal method through this connection.
    Unavailable,
}

/// The method `principal_kind` uses for `connection`. It never reads stored
/// rows or OAuth slots, and there is no fallback between methods:
///
/// | Principal | Connection has `oauth` | `token_profile` only |
/// | --- | --- | --- |
/// | `User` | `OAuth` | `Token` |
/// | `ServiceAccount` | `Token` if `token_profile` is set, otherwise `Unavailable` | `Token` |
/// | `System` | `Token` if `token_profile` is set, otherwise `Unavailable` | `Token` |
/// | `None` | `Unavailable` | `Unavailable` |
pub fn select(
    connection: &ConnectionConfig,
    principal_kind: Option<PrincipalKind>,
) -> Selection<'_> {
    match (
        principal_kind,
        connection.oauth.as_ref(),
        connection.token_profile.as_deref(),
    ) {
        (None, _, _) => Selection::Unavailable,
        (Some(PrincipalKind::User), Some(oauth), _) => Selection::OAuth(oauth),
        (Some(_), _, Some(profile)) => Selection::Token(profile),
        (Some(_), _, None) => Selection::Unavailable,
    }
}

/// The connection a service's `credentials.per_user` entry names.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PersonalConnection<'a> {
    /// The connection ID, which is also the `service` column of its token
    /// rows and the namespace of its credential rights.
    pub id: &'a str,
    pub config: &'a ConnectionConfig,
}

impl<'a> PersonalConnection<'a> {
    /// [`select`] for this connection.
    pub fn select(&self, principal_kind: Option<PrincipalKind>) -> Selection<'a> {
        select(self.config, principal_kind)
    }
}

impl CredentialsConfig {
    /// The connection `service` consumes: its `credentials.per_user` entry is
    /// `type = "connection"` and names one of these credentials' connections.
    pub fn personal_connection(&self, service: &str) -> Option<PersonalConnection<'_>> {
        let entry = self.per_user.get(service)?;
        if entry.kind != "connection" {
            return None;
        }
        let id = entry.connection.as_deref()?;
        let (id, config) = self.connections.get_key_value(id)?;
        Some(PersonalConnection { id, config })
    }

    /// The services whose `credentials.per_user` entry names `connection`,
    /// in key order.
    pub fn connection_consumers<'a>(
        &'a self,
        connection: &'a str,
    ) -> impl Iterator<Item = &'a str> + 'a {
        self.per_user.iter().filter_map(move |(service, entry)| {
            (entry.kind == "connection" && entry.connection.as_deref() == Some(connection))
                .then_some(service.as_str())
        })
    }
}

/// The kind of `profile` among `consumers`' descriptors: the declared kind
/// when every declaring consumer agrees, `Err` naming the disagreement
/// otherwise, and `Ok(None)` when no consumer declares it.
fn declared_profile_kind<'a>(
    profile: &str,
    consumers: impl IntoIterator<Item = &'a ServiceDescriptor>,
) -> Result<Option<&'static str>, ()> {
    let mut kind = None;
    for descriptor in consumers {
        if let Some(declared) = descriptor.credential_profile_kind(profile) {
            match kind {
                Some(previous) if previous != declared => return Err(()),
                _ => kind = Some(declared),
            }
        }
    }
    Ok(kind)
}

/// Checks `[credentials.connections]` against the configured services: the
/// ID namespace, at least one method, every consumer's profile and
/// delegated-access support, the OAuth registration binding, and one
/// permission profile per shared registration.
pub(crate) fn validate_connections(
    config: &BrokerConfig,
    services: &BTreeMap<String, Arc<ServiceDescriptor>>,
    errors: &mut Vec<String>,
) {
    let credentials = &config.credentials;
    for (id, connection) in &credentials.connections {
        let label = format!("credentials.connections.{id}");
        if id == "broker" || !is_service_name(id) {
            errors.push(format!("{label} uses an invalid connection ID"));
        }
        let consumers = credentials.connection_consumers(id).collect::<Vec<_>>();
        // Connection IDs share the namespace of token rows and credential
        // rights with services; only a consumer may hold the same ID.
        if (services.contains_key(id) || config.gateways.contains_key(id))
            && !consumers.contains(&id.as_str())
        {
            errors.push(format!(
                "{label} collides with the configured service {id}, which does not consume it"
            ));
        }
        if connection
            .display_name
            .as_deref()
            .is_some_and(|name| name.trim().is_empty())
        {
            errors.push(format!("{label}.display_name must not be empty"));
        }
        if connection.token_profile.is_none() && connection.oauth.is_none() {
            errors.push(format!("{label} must set token_profile, oauth, or both"));
        }
        let descriptors = consumers
            .iter()
            .filter_map(|service| services.get(*service).map(|d| (*service, d.as_ref())))
            .collect::<Vec<_>>();
        if let Some(profile) = connection.token_profile.as_deref() {
            validate_token_profile(config, &label, profile, &descriptors, errors);
        }
        if let Some(oauth) = &connection.oauth {
            validate_connection_oauth(config, &label, oauth, &descriptors, errors);
        }
    }
    let mut registration_profiles = BTreeMap::<&str, (&str, &str)>::new();
    for (id, connection) in &credentials.connections {
        let Some(oauth) = &connection.oauth else {
            continue;
        };
        match registration_profiles.get(oauth.registration.as_str()) {
            Some((first, profile)) if *profile != oauth.profile => errors.push(format!(
                "credentials.connections.{first} and credentials.connections.{id} share OAuth registration {} and must use the same profile",
                oauth.registration
            )),
            Some(_) => {}
            None => {
                registration_profiles.insert(&oauth.registration, (id, &oauth.profile));
            }
        }
    }
}

/// Every consumer declares `profile` with one kind, except that a Git
/// gateway accepts any token- or basic-kind profile another consumer or the
/// gateway itself declares.
fn validate_token_profile(
    config: &BrokerConfig,
    label: &str,
    profile: &str,
    consumers: &[(&str, &ServiceDescriptor)],
    errors: &mut Vec<String>,
) {
    let kind = match declared_profile_kind(profile, consumers.iter().map(|(_, d)| *d)) {
        Ok(kind) => kind,
        Err(()) => {
            errors.push(format!(
                "{label}.token_profile {profile} is declared with different credential kinds by its consumers"
            ));
            return;
        }
    };
    for (service, descriptor) in consumers {
        if config.gateways.contains_key(*service) {
            if !matches!(kind, Some("bearer_token" | "basic_api_token")) {
                errors.push(format!(
                    "{label}.token_profile {profile} is not a token or basic profile the gateway {service} can present"
                ));
            }
        } else if descriptor.credential_profile_kind(profile).is_none() {
            errors.push(format!(
                "{label}.token_profile {profile} is unsupported for service {service}"
            ));
        }
    }
}

/// The registration and permission profile exist, and every consumer
/// accepts delegated credentials without needing a per-user lookup
/// credential, which OAuth cannot provide.
fn validate_connection_oauth(
    config: &BrokerConfig,
    label: &str,
    oauth: &ConnectionOAuthConfig,
    consumers: &[(&str, &ServiceDescriptor)],
    errors: &mut Vec<String>,
) {
    if config
        .oauth
        .registrations
        .get(&oauth.registration)
        .is_none_or(|registration| {
            !registration
                .permission_profiles
                .contains_key(&oauth.profile)
        })
    {
        errors.push(format!(
            "{label}.oauth must name a configured registration and permission profile"
        ));
    }
    for (service, descriptor) in consumers {
        if descriptor.credentials.delegated.is_none() {
            errors.push(format!(
                "{label}.oauth requires every consumer to accept delegated credentials, which {service} does not"
            ));
            continue;
        }
        for action in descriptor.actions.iter().filter(|action| {
            action.lookup.credential_required()
                && action
                    .credential_modes
                    .iter()
                    .any(|mode| mode == "per_user")
        }) {
            errors.push(format!(
                "{label}.oauth: {service} action {} needs a per-user lookup credential, which an OAuth credential cannot provide",
                action.action
            ));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn connection(token_profile: Option<&str>, oauth: bool) -> ConnectionConfig {
        ConnectionConfig {
            display_name: None,
            token_profile: token_profile.map(str::to_owned),
            oauth: oauth.then(|| ConnectionOAuthConfig {
                registration: "gitlab".into(),
                profile: "default".into(),
            }),
        }
    }

    #[test]
    fn principal_kinds_round_trip_their_stored_spellings_and_reject_others() {
        for kind in [
            PrincipalKind::User,
            PrincipalKind::ServiceAccount,
            PrincipalKind::System,
        ] {
            assert_eq!(PrincipalKind::from_stored(kind.as_str()), Some(kind));
            assert_eq!(
                serde_json::to_value(kind).unwrap(),
                serde_json::Value::String(kind.as_str().into())
            );
        }
        for unknown in ["", "User", "admin", "service-account", "robot"] {
            assert_eq!(PrincipalKind::from_stored(unknown), None);
            assert!(serde_json::from_value::<PrincipalKind>(unknown.into()).is_err());
        }
    }

    #[test]
    fn select_follows_the_principal_method_table() {
        use PrincipalKind::{ServiceAccount, System, User};
        let token_only = connection(Some("gitlab-access-token"), false);
        let oauth_only = connection(None, true);
        let both = connection(Some("gitlab-access-token"), true);
        let oauth = both.oauth.as_ref().unwrap();
        let token = Selection::Token("gitlab-access-token");

        assert_eq!(select(&both, Some(User)), Selection::OAuth(oauth));
        assert_eq!(
            select(&oauth_only, Some(User)),
            Selection::OAuth(oauth_only.oauth.as_ref().unwrap())
        );
        assert_eq!(select(&token_only, Some(User)), token);

        for kind in [ServiceAccount, System] {
            assert_eq!(select(&both, Some(kind)), token);
            assert_eq!(select(&oauth_only, Some(kind)), Selection::Unavailable);
            assert_eq!(select(&token_only, Some(kind)), token);
        }
        for configured in [&token_only, &oauth_only, &both] {
            assert_eq!(select(configured, None), Selection::Unavailable);
        }
    }

    #[test]
    fn connection_oauth_binds_its_registration_and_profile() {
        let configured = connection(None, true);
        assert_eq!(
            configured.oauth.unwrap().binding(),
            OAuthBinding {
                registration: "gitlab".into(),
                permission_profile: "default".into(),
            }
        );
    }
}
