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

use crate::{
    BackendRegistry, BrokerConfig, CredentialsConfig, GatewayConfig, OAuthBinding, OAuthConfig,
};
use agent_access_provider::{ServiceDescriptor, is_service_name};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::sync::Arc;

/// The stored name of every connection token row; the row's `service`
/// column holds the connection ID.
pub const CONNECTION_CREDENTIAL_NAME: &str = "default";

/// The kind of a managed principal, read from `principals.kind`. It selects a
/// credential connection's method. A configured static principal carries the
/// kind of the active managed principal with its ID; other static principals
/// and anonymous callers have none, so they select no personal method.
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
///
/// The valid combinations are: nothing (the implicit type), `token_profiles`,
/// `token_profiles` with `service_account_token_profiles`, `oauth`, and
/// `oauth` with `token_profiles`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConnectionConfig {
    /// The name management shows for the connection; its ID when unset.
    pub display_name: Option<String>,
    /// The token profiles (types) principals that use tokens may store, in
    /// the order a picker offers them: people when the connection has no
    /// `oauth`, and service accounts and system principals unless
    /// `service_account_token_profiles` overrides it. With neither `oauth`
    /// nor a list configured, the effective connection holds the
    /// connection's only possible type here (see
    /// [`resolve_effective_connections`]).
    pub token_profiles: Option<Vec<String>>,
    /// Overrides `token_profiles` for service accounts and system
    /// principals: administrator-provisioned for service accounts,
    /// self-service for system principals. Requires `token_profiles`, and
    /// is rejected beside `oauth`, where `token_profiles` already applies
    /// only to them.
    pub service_account_token_profiles: Option<Vec<String>>,
    /// OAuth for user principals, who then never store a token.
    pub oauth: Option<ConnectionOAuthConfig>,
}

impl ConnectionConfig {
    /// Every token profile either list names, each once, `token_profiles`
    /// first, in configuration order.
    pub fn accepted_token_profiles(&self) -> Vec<&str> {
        let mut profiles = Vec::new();
        for profile in self
            .token_profiles
            .iter()
            .chain(&self.service_account_token_profiles)
            .flatten()
        {
            if !profiles.contains(&profile.as_str()) {
                profiles.push(profile.as_str());
            }
        }
        profiles
    }

    /// Whether either token list is set. An effective connection holds its
    /// implicit type in `token_profiles`, so this is whether it has a token
    /// method.
    pub fn has_token_profiles(&self) -> bool {
        self.token_profiles.is_some() || self.service_account_token_profiles.is_some()
    }
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
    /// The principal's stored token row for the connection, whose stored
    /// profile must be one of these, in picker order. The row is presented
    /// as its own profile.
    Token(&'a [String]),
    /// The principal's OAuth connection for this registration and profile;
    /// a stored token row is never read.
    OAuth(&'a ConnectionOAuthConfig),
    /// No personal method through this connection.
    Unavailable,
}

/// The method `principal_kind` uses for `connection`, an effective
/// connection whose implicit type is resolved. It never reads stored rows
/// or OAuth slots, and there is no fallback between methods:
///
/// | Principal | Connection has `oauth` | No `oauth` |
/// | --- | --- | --- |
/// | `User` | `OAuth` | `Token(token_profiles)` |
/// | `ServiceAccount`, `System` | `Token(token_profiles)` if set, otherwise `Unavailable` | `Token(service_account_token_profiles)` if set, otherwise `Token(token_profiles)` |
/// | `None` (no active managed principal) | `Unavailable` | `Unavailable` |
///
/// Service accounts and system principals share one list, so changing a
/// principal between those kinds never strands its stored token.
pub fn select(
    connection: &ConnectionConfig,
    principal_kind: Option<PrincipalKind>,
) -> Selection<'_> {
    fn token(profiles: Option<&Vec<String>>) -> Selection<'_> {
        match profiles.map(Vec::as_slice) {
            Some(profiles) if !profiles.is_empty() => Selection::Token(profiles),
            _ => Selection::Unavailable,
        }
    }
    match principal_kind {
        None => Selection::Unavailable,
        Some(PrincipalKind::User) => match &connection.oauth {
            Some(oauth) => Selection::OAuth(oauth),
            None => token(connection.token_profiles.as_ref()),
        },
        Some(PrincipalKind::ServiceAccount | PrincipalKind::System) => match &connection.oauth {
            Some(_) => token(connection.token_profiles.as_ref()),
            None => token(
                connection
                    .service_account_token_profiles
                    .as_ref()
                    .or(connection.token_profiles.as_ref()),
            ),
        },
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

/// The kind `connection`'s consumers declare for `profile`, when they
/// agree; `None` when it is undeclared or declared with different kinds,
/// which validation rejects.
pub(crate) fn connection_profile_kind(
    credentials: &CredentialsConfig,
    services: &BTreeMap<String, Arc<ServiceDescriptor>>,
    connection: &str,
    profile: &str,
) -> Option<&'static str> {
    declared_profile_kind(
        profile,
        credentials
            .connection_consumers(connection)
            .filter_map(|service| services.get(service).map(Arc::as_ref)),
    )
    .ok()
    .flatten()
}

/// How `descriptors` declare `profile`, over every declaration: `Some(true)`
/// when any declaration marks it route-bound, `Some(false)` when some
/// declare it and none does, `None` when none declares it. Descriptor
/// validation rejects a repeated profile; this stays fail-closed even so.
pub(crate) fn profile_route_binding<'a>(
    descriptors: impl IntoIterator<Item = &'a ServiceDescriptor>,
    profile: &str,
) -> Option<bool> {
    descriptors
        .into_iter()
        .flat_map(|descriptor| &descriptor.credentials.profiles)
        .filter(|declared| declared.name == profile)
        .map(|declared| declared.route_bound)
        .reduce(|left, right| left || right)
}

/// The label `connection`'s consumers declare for `profile`: the first one
/// in service ID order that declares a label.
pub(crate) fn connection_profile_label(
    credentials: &CredentialsConfig,
    services: &BTreeMap<String, Arc<ServiceDescriptor>>,
    connection: &str,
    profile: &str,
) -> Option<String> {
    credentials
        .connection_consumers(connection)
        .filter_map(|service| services.get(service))
        .find_map(|descriptor| descriptor.credential_profile(profile)?.label.clone())
}

/// The configuration keys of a connection's token lists.
const TOKEN_PROFILES: &str = "token_profiles";
const SERVICE_ACCOUNT_TOKEN_PROFILES: &str = "service_account_token_profiles";

/// Checks `[credentials.connections]` against the configured services: the
/// ID namespace, the valid combinations of keys, every listed profile's
/// rules and delegated-access support, the OAuth registration binding, and
/// then [`resolve_effective_connections`] on a copy of the configured
/// connections. Returns that copy, with each implicit type resolved, for the
/// checks that read a connection's accepted token profiles.
pub(crate) fn validate_connections(
    config: &BrokerConfig,
    services: &BTreeMap<String, Arc<ServiceDescriptor>>,
    errors: &mut Vec<String>,
) -> CredentialsConfig {
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
        if connection.service_account_token_profiles.is_some() {
            if connection.oauth.is_some() {
                errors.push(format!(
                    "{label}.{SERVICE_ACCOUNT_TOKEN_PROFILES} cannot be set beside oauth: there {TOKEN_PROFILES} applies only to service accounts and system principals"
                ));
            } else if connection.token_profiles.is_none() {
                errors.push(format!(
                    "{label}.{SERVICE_ACCOUNT_TOKEN_PROFILES} requires {TOKEN_PROFILES}, which it overrides for service accounts and system principals"
                ));
            }
        }
        let descriptors = consumer_descriptors(credentials, services, id);
        let mut validated = Vec::new();
        for (key, profiles) in [
            (TOKEN_PROFILES, &connection.token_profiles),
            (
                SERVICE_ACCOUNT_TOKEN_PROFILES,
                &connection.service_account_token_profiles,
            ),
        ] {
            let Some(profiles) = profiles else {
                continue;
            };
            let list = format!("{label}.{key}");
            if profiles.is_empty() {
                errors.push(format!("{list} must not be empty"));
            }
            for (index, profile) in profiles.iter().enumerate() {
                if profiles[..index].contains(profile) {
                    errors.push(format!("{list} lists {profile} more than once"));
                } else if !validated.contains(&profile) {
                    // A profile in both lists is checked once.
                    validated.push(profile);
                    errors.extend(token_profile_errors(
                        &config.gateways,
                        &list,
                        profile,
                        &descriptors,
                    ));
                }
            }
        }
        if let Some(oauth) = &connection.oauth {
            validate_connection_oauth(config, &label, oauth, &descriptors, errors);
        }
    }
    let mut effective = credentials.clone();
    errors.extend(resolve_effective_connections(
        &mut effective,
        services,
        &config.gateways,
        &config.oauth,
        config.providers.registry(),
    ));
    effective
}

/// The consumers of `connection` that have a descriptor, in service ID
/// order.
fn consumer_descriptors<'a>(
    credentials: &'a CredentialsConfig,
    services: &'a BTreeMap<String, Arc<ServiceDescriptor>>,
    connection: &'a str,
) -> Vec<(&'a str, &'a ServiceDescriptor)> {
    credentials
        .connection_consumers(connection)
        .filter_map(|service| services.get(service).map(|d| (service, d.as_ref())))
        .collect()
}

/// Makes `credentials`' connections effective and checks them together:
/// resolves each implicit type ([`resolve_implicit_token_profiles`]), then
/// runs [`connection_authority_errors`] and [`shared_registration_errors`].
/// Offline validation runs it on the configured connections; startup,
/// reload and every imported-catalog publication run it on the complete
/// effective set, configured and synthesized for imports, and publish the
/// result, so [`select`] reads resolved lists. A publication that breaks a
/// check fails.
pub(crate) fn resolve_effective_connections(
    credentials: &mut CredentialsConfig,
    services: &BTreeMap<String, Arc<ServiceDescriptor>>,
    gateways: &BTreeMap<String, GatewayConfig>,
    oauth: &OAuthConfig,
    registry: &BackendRegistry,
) -> Vec<String> {
    let mut errors = resolve_implicit_token_profiles(credentials, services, gateways);
    errors.extend(connection_authority_errors(
        credentials,
        services,
        oauth,
        registry,
    ));
    errors.extend(shared_registration_errors(credentials));
    errors
}

/// Gives each connection with no `oauth` and no token list its implicit
/// type: the one token profile it could accept, that is, a profile its
/// consumers declare that passes every per-profile rule (every non-gateway
/// consumer declares it, the declaring consumers agree on its kind, and a
/// Git gateway consumer can present it, which excludes route-bound
/// profiles). That profile becomes the connection's `token_profiles`, as if
/// configured. No candidate means the connection has no method; several
/// need an explicit `token_profiles`. Both are errors, and leave the
/// connection without a list.
pub(crate) fn resolve_implicit_token_profiles(
    credentials: &mut CredentialsConfig,
    services: &BTreeMap<String, Arc<ServiceDescriptor>>,
    gateways: &BTreeMap<String, GatewayConfig>,
) -> Vec<String> {
    let mut errors = Vec::new();
    let mut resolved = Vec::new();
    for (id, connection) in &credentials.connections {
        if connection.oauth.is_some() || connection.has_token_profiles() {
            continue;
        }
        let label = format!("credentials.connections.{id}");
        let candidates = implicit_token_profile_candidates(
            &consumer_descriptors(credentials, services, id),
            gateways,
        );
        match candidates.as_slice() {
            [profile] => resolved.push((id.clone(), (*profile).to_string())),
            [] => errors.push(format!(
                "{label} has no method: set oauth or {TOKEN_PROFILES}; its consumers declare no token profile it could accept"
            )),
            several => errors.push(format!(
                "{label} must set {TOKEN_PROFILES}: its consumers accept several token profiles ({})",
                several.join(", ")
            )),
        }
    }
    for (id, profile) in resolved {
        if let Some(connection) = credentials.connections.get_mut(&id) {
            connection.token_profiles = Some(vec![profile]);
        }
    }
    errors
}

/// The token profiles a connection whose consumers are `consumers` could
/// accept: every profile a consumer declares that passes the per-profile
/// rules, each once, in consumer and declaration order.
fn implicit_token_profile_candidates<'a>(
    consumers: &[(&str, &'a ServiceDescriptor)],
    gateways: &BTreeMap<String, GatewayConfig>,
) -> Vec<&'a str> {
    let mut seen = Vec::new();
    let mut candidates = Vec::new();
    for declared in consumers
        .iter()
        .flat_map(|(_, descriptor)| &descriptor.credentials.profiles)
    {
        let profile = declared.name.as_str();
        if seen.contains(&profile) {
            continue;
        }
        seen.push(profile);
        if token_profile_errors(gateways, TOKEN_PROFILES, profile, consumers).is_empty() {
            candidates.push(profile);
        }
    }
    candidates
}

/// Connections that share an OAuth registration share each user's OAuth
/// connection for it, so they must use one permission profile: consent
/// admits a registration's flow only for the profile every connection that
/// selects it uses.
pub(crate) fn shared_registration_errors(credentials: &CredentialsConfig) -> Vec<String> {
    let mut errors = Vec::new();
    let mut registration_profiles = BTreeMap::<&str, (&str, &str)>::new();
    for (id, connection) in &credentials.connections {
        let Some(oauth) = &connection.oauth else {
            continue;
        };
        match registration_profiles.get(oauth.registration.as_str()) {
            Some((first, profile)) if *profile != oauth.profile => errors.push(format!(
                "credential connections {first} and {id} share OAuth registration {} with different permission profiles ({profile} and {}); connections sharing a registration must use the same profile",
                oauth.registration, oauth.profile
            )),
            Some(_) => {}
            None => {
                registration_profiles.insert(&oauth.registration, (id, &oauth.profile));
            }
        }
    }
    errors
}

/// Whether each connection's consumers act on one upstream (design: the
/// upstream authority contract). A token method (either list, or the
/// implicit type an effective connection holds in `token_profiles`)
/// requires every consumer of a shared connection to declare an authority
/// naming the same instance: one origin, instance path, tenant and tenant
/// gateway. An OAuth method requires the registration's dialect to accept
/// each consumer's authority. Connections whose OAuth registration or
/// profile is missing are reported elsewhere.
/// Runs offline, at startup and reload, and at every imported-catalog
/// publication, without contacting upstream.
pub(crate) fn connection_authority_errors(
    credentials: &CredentialsConfig,
    services: &BTreeMap<String, Arc<ServiceDescriptor>>,
    oauth: &OAuthConfig,
    registry: &BackendRegistry,
) -> Vec<String> {
    let mut errors = Vec::new();
    for (id, connection) in &credentials.connections {
        let label = format!("credentials.connections.{id}");
        let consumers = consumer_descriptors(credentials, services, id);
        if connection.has_token_profiles() && consumers.len() > 1 {
            let mut first: Option<(&str, &agent_access_provider::UpstreamAuthority)> = None;
            for (service, descriptor) in &consumers {
                let Some(authority) = descriptor.upstream_authority.as_ref() else {
                    errors.push(format!(
                        "{label}: {service} declares no upstream authority, so it cannot share a token connection"
                    ));
                    continue;
                };
                match first {
                    None => first = Some((service, authority)),
                    Some((first_service, first_authority))
                        if !first_authority.same_instance(authority) =>
                    {
                        errors.push(format!(
                            "{label}: {first_service} acts on {first_authority} but {service} acts on {authority}; a token connection's consumers must act on one upstream"
                        ));
                    }
                    Some(_) => {}
                }
            }
        }
        let Some(binding) = &connection.oauth else {
            continue;
        };
        let Some(registration) = oauth.registrations.get(&binding.registration) else {
            continue;
        };
        let (Some(profile), Some(dialect)) = (
            registration.permission_profiles.get(&binding.profile),
            registry.oauth_dialect(registration.adapter.as_str()),
        ) else {
            continue;
        };
        for (service, descriptor) in &consumers {
            if let Err(reason) = dialect.dialect().check_consumer_authority(
                registration,
                profile,
                descriptor.upstream_authority.as_ref(),
            ) {
                errors.push(format!(
                    "{label}.oauth: {service} does not act on the upstream registration {} grants access to: {reason}",
                    binding.registration
                ));
            }
        }
    }
    errors
}

/// The errors of `profile`, an entry of the token list `list`: every
/// consumer declares it with one kind, except that a Git gateway accepts
/// any token- or basic-kind profile another consumer or the gateway itself
/// declares, unless a consumer marks it route-bound: only its declaring
/// provider may present such a profile.
fn token_profile_errors(
    gateways: &BTreeMap<String, GatewayConfig>,
    list: &str,
    profile: &str,
    consumers: &[(&str, &ServiceDescriptor)],
) -> Vec<String> {
    let kind = match declared_profile_kind(profile, consumers.iter().map(|(_, d)| *d)) {
        Ok(kind) => kind,
        Err(()) => {
            return vec![format!(
                "{list} profile {profile} is declared with different credential kinds by its consumers"
            )];
        }
    };
    let route_bound =
        profile_route_binding(consumers.iter().map(|(_, descriptor)| *descriptor), profile)
            == Some(true);
    let mut errors = Vec::new();
    for (service, descriptor) in consumers {
        if gateways.contains_key(*service) {
            if route_bound {
                errors.push(format!(
                    "{list} profile {profile} is route-bound: only the provider declaring it may present it, so the gateway {service} cannot consume this connection"
                ));
            } else if !matches!(kind, Some("bearer_token" | "basic_api_token")) {
                errors.push(format!(
                    "{list} profile {profile} is not a token or basic profile the gateway {service} can present"
                ));
            }
        } else if descriptor.credential_profile_kind(profile).is_none() {
            errors.push(format!(
                "{list} profile {profile} is unsupported for service {service}, which accepts {}",
                accepted_profiles(descriptor)
            ));
        }
    }
    errors
}

/// The token profiles `descriptor` declares under the current
/// configuration, as a rejection names them.
fn accepted_profiles(descriptor: &ServiceDescriptor) -> String {
    let profiles = descriptor
        .credentials
        .profiles
        .iter()
        .map(|profile| profile.name.as_str())
        .collect::<Vec<_>>();
    if profiles.is_empty() {
        "no token profile".to_string()
    } else {
        profiles.join(", ")
    }
}

/// The registration and permission profile exist, and every consumer
/// accepts delegated credentials. The OAuth connection serves a consumer's
/// lookups as well as its execution.
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
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn profiles(names: &[&str]) -> Option<Vec<String>> {
        Some(names.iter().map(|name| (*name).to_owned()).collect())
    }

    /// A connection with the lists `token` and `service_account` and
    /// optionally OAuth.
    fn lists(
        token: Option<&[&str]>,
        service_account: Option<&[&str]>,
        oauth: bool,
    ) -> ConnectionConfig {
        ConnectionConfig {
            display_name: None,
            token_profiles: token.and_then(profiles),
            service_account_token_profiles: service_account.and_then(profiles),
            oauth: oauth.then(|| ConnectionOAuthConfig {
                registration: "gitlab".into(),
                profile: "default".into(),
            }),
        }
    }

    /// `token_profiles` with one profile, or none, beside optional OAuth.
    fn connection(token_profile: Option<&str>, oauth: bool) -> ConnectionConfig {
        let list = token_profile.map(|profile| vec![profile]);
        lists(list.as_deref(), None, oauth)
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
        let people = ["gitlab-access-token".to_string()];
        let machines = [
            "gitlab-access-token".to_string(),
            "gitlab-deploy-token".to_string(),
        ];
        let oauth_and_tokens = lists(
            Some(&["gitlab-access-token", "gitlab-deploy-token"]),
            None,
            true,
        );
        let oauth = oauth_and_tokens.oauth.as_ref().unwrap();
        let oauth_only = lists(None, None, true);
        let tokens_only = lists(Some(&["gitlab-access-token"]), None, false);
        let overridden = lists(
            Some(&["gitlab-access-token"]),
            Some(&["gitlab-access-token", "gitlab-deploy-token"]),
            false,
        );
        // Combinations validation rejects follow the table all the same:
        // beside OAuth the override is not read, and without
        // `token_profiles` people have no list.
        let oauth_and_override = lists(
            None,
            Some(&["gitlab-access-token", "gitlab-deploy-token"]),
            true,
        );
        let override_only = lists(
            None,
            Some(&["gitlab-access-token", "gitlab-deploy-token"]),
            false,
        );
        // A connection whose implicit type is not resolved, and lists
        // validation rejects as empty, select nothing.
        let unresolved = lists(None, None, false);
        let empty = lists(Some(&[]), Some(&[]), false);

        for (configured, user, machine) in [
            (
                &oauth_and_tokens,
                Selection::OAuth(oauth),
                Selection::Token(&machines[..]),
            ),
            (
                &oauth_only,
                Selection::OAuth(oauth_only.oauth.as_ref().unwrap()),
                Selection::Unavailable,
            ),
            (
                &tokens_only,
                Selection::Token(&people[..]),
                Selection::Token(&people[..]),
            ),
            (
                &overridden,
                Selection::Token(&people[..]),
                Selection::Token(&machines[..]),
            ),
            (
                &oauth_and_override,
                Selection::OAuth(oauth_and_override.oauth.as_ref().unwrap()),
                Selection::Unavailable,
            ),
            (
                &override_only,
                Selection::Unavailable,
                Selection::Token(&machines[..]),
            ),
            (&unresolved, Selection::Unavailable, Selection::Unavailable),
            (&empty, Selection::Unavailable, Selection::Unavailable),
        ] {
            assert_eq!(select(configured, Some(User)), user, "{configured:?}");
            // Service accounts and system principals share one list.
            for kind in [ServiceAccount, System] {
                assert_eq!(select(configured, Some(kind)), machine, "{configured:?}");
            }
            assert_eq!(select(configured, None), Selection::Unavailable);
        }
    }

    #[test]
    fn accepted_token_profiles_name_each_listed_profile_once_token_profiles_first() {
        assert_eq!(
            lists(Some(&["b", "a"]), Some(&["a", "c"]), false).accepted_token_profiles(),
            ["b", "a", "c"]
        );
        assert!(lists(None, None, true).accepted_token_profiles().is_empty());
        assert!(!lists(None, None, true).has_token_profiles());
        assert!(!lists(None, None, false).has_token_profiles());
        assert!(lists(None, Some(&[]), false).has_token_profiles());
    }

    /// Connections no key of which is a list: the implicit type is the one
    /// profile the consumers could accept, set as `token_profiles`. None, or
    /// several, is an error that names the remedy, and leaves the
    /// connection without a list. Connections with OAuth or a list are left
    /// as configured.
    #[test]
    fn the_implicit_type_is_the_one_profile_the_consumers_could_accept() {
        use agent_access_provider::{CredentialDescriptor, CredentialProfile};
        let service = |name: &str, credentials: CredentialDescriptor| {
            (
                name.to_string(),
                Arc::new(ServiceDescriptor::new(name, name).with_credentials(credentials)),
            )
        };
        let services = BTreeMap::from([
            service(
                "rest",
                CredentialDescriptor::default().profile("rest-token", "bearer_token"),
            ),
            service(
                "routed",
                CredentialDescriptor::default()
                    .with_profile(
                        CredentialProfile::new("site-token", "basic_api_token").route_bound(),
                    )
                    .with_profile(
                        CredentialProfile::new("gateway-token", "bearer_token").route_bound(),
                    ),
            ),
            service(
                "routed_site",
                CredentialDescriptor::default().with_profile(
                    CredentialProfile::new("site-token", "basic_api_token").route_bound(),
                ),
            ),
            service(
                "git",
                CredentialDescriptor::default()
                    .profile("git-basic-api-token", "basic_api_token")
                    .profile("git-bearer-token", "bearer_token"),
            ),
            service(
                "rest_basic",
                CredentialDescriptor::default().profile("rest-token", "basic_api_token"),
            ),
            service(
                "delegated",
                CredentialDescriptor::default().delegated("Act as you."),
            ),
        ]);
        let gateway: GatewayConfig = serde_json::from_value(serde_json::json!({
            "kind": "git_http",
            "display_name": "Git",
            "upstream_base_url": "https://git.example.com",
            "egress_proxy": null,
            "request_body_max_bytes": null,
            "response_body_max_bytes": null,
            "streaming_idle_timeout_ms": null,
            "git": null,
        }))
        .unwrap();
        let gateways = BTreeMap::from([("git".to_string(), gateway)]);
        let resolve = |connection: ConnectionConfig, consumers: &[&str]| {
            let mut credentials = shared(connection, consumers);
            let errors = resolve_implicit_token_profiles(&mut credentials, &services, &gateways);
            (credentials.connections["shared"].clone(), errors)
        };
        let implied = |profile: &str| ConnectionConfig {
            token_profiles: Some(vec![profile.to_string()]),
            ..lists(None, None, false)
        };
        let nothing = || lists(None, None, false);

        // One consumer declaring one profile; a Git gateway beside it adds
        // nothing the other consumer does not declare.
        assert_eq!(
            resolve(nothing(), &["rest"]),
            (implied("rest-token"), vec![])
        );
        assert_eq!(
            resolve(nothing(), &["rest", "git"]),
            (implied("rest-token"), vec![])
        );
        // Only the profiles every non-gateway consumer declares.
        assert_eq!(
            resolve(nothing(), &["routed", "routed_site"]),
            (implied("site-token"), vec![])
        );
        // Several candidates, named in consumer and declaration order.
        assert_eq!(
            resolve(nothing(), &["routed"]),
            (
                nothing(),
                vec![
                    "credentials.connections.shared must set token_profiles: its consumers accept several token profiles (site-token, gateway-token)"
                        .to_string()
                ]
            )
        );
        assert_eq!(
            resolve(nothing(), &["git"]).1,
            [
                "credentials.connections.shared must set token_profiles: its consumers accept several token profiles (git-basic-api-token, git-bearer-token)"
            ]
        );
        // None: route-bound profiles are excluded beside a Git gateway, kinds
        // must agree, and a consumer may declare no profile at all, or there
        // may be no consumer.
        let no_method = [
            "credentials.connections.shared has no method: set oauth or token_profiles; its consumers declare no token profile it could accept",
        ];
        for consumers in [
            &["routed_site", "git"][..],
            &["rest", "rest_basic"],
            &["delegated"],
            &["rest", "delegated"],
            &[],
        ] {
            assert_eq!(
                resolve(nothing(), consumers),
                (nothing(), no_method.map(String::from).to_vec()),
                "{consumers:?}"
            );
        }
        // Nothing is implied beside OAuth or a list.
        for configured in [
            connection(None, true),
            connection(Some("rest-token"), false),
            lists(None, Some(&["rest-token"]), false),
        ] {
            assert_eq!(resolve(configured.clone(), &["rest"]), (configured, vec![]));
        }
    }

    fn consumers(authorities: &[(&str, Option<&str>)]) -> BTreeMap<String, Arc<ServiceDescriptor>> {
        authorities
            .iter()
            .map(|(service, authority)| {
                let mut descriptor = ServiceDescriptor::new(*service, *service);
                if let Some(base) = authority {
                    descriptor = descriptor.with_upstream_authority(
                        agent_access_provider::UpstreamAuthority::from_base_url(base).unwrap(),
                    );
                }
                ((*service).to_string(), Arc::new(descriptor))
            })
            .collect()
    }

    fn shared(connection: ConnectionConfig, consumers: &[&str]) -> CredentialsConfig {
        let mut credentials = CredentialsConfig::default();
        credentials.connections.insert("shared".into(), connection);
        for consumer in consumers {
            credentials.per_user.insert(
                (*consumer).into(),
                crate::CredentialConfig {
                    kind: "connection".into(),
                    username_ref: None,
                    token_ref: None,
                    provider: None,
                    path: None,
                    read_only: None,
                    connection: Some("shared".into()),
                    profile: None,
                },
            );
        }
        credentials
    }

    #[test]
    fn a_rejected_token_profile_names_the_profiles_the_consumer_accepts() {
        let none = ServiceDescriptor::new("plain", "Plain");
        assert_eq!(accepted_profiles(&none), "no token profile");
        let declared = ServiceDescriptor::new("site", "Site").with_credentials(
            agent_access_provider::CredentialDescriptor::default()
                .profile("site-api-token", "basic_api_token")
                .profile("site-bearer-token", "bearer_token"),
        );
        assert_eq!(
            accepted_profiles(&declared),
            "site-api-token, site-bearer-token"
        );
    }

    #[test]
    fn token_connection_consumers_must_act_on_one_upstream_instance() {
        let registry = BackendRegistry::empty();
        let oauth = OAuthConfig::default();
        let token = connection(Some("token"), false);
        let check = |services: &[(&str, Option<&str>)]| {
            let names = services.iter().map(|(name, _)| *name).collect::<Vec<_>>();
            connection_authority_errors(
                &shared(token.clone(), &names),
                &consumers(services),
                &oauth,
                &registry,
            )
        };
        assert!(
            check(&[
                ("rest", Some("https://GitLab.example.com:443/")),
                ("git", Some("https://gitlab.example.com")),
            ])
            .is_empty()
        );
        // One consumer shares with no one, so it needs no declaration.
        assert!(check(&[("solo", None)]).is_empty());
        assert_eq!(
            check(&[
                ("rest", Some("https://gitlab.example.com")),
                ("git", Some("https://gitlab.example.com/other")),
            ]),
            [
                "credentials.connections.shared: git acts on https://gitlab.example.com/other but rest acts on https://gitlab.example.com; a token connection's consumers must act on one upstream"
            ]
        );
        assert_eq!(
            check(&[
                ("rest", Some("https://gitlab.example.com")),
                ("undeclared", None)
            ]),
            [
                "credentials.connections.shared: undeclared declares no upstream authority, so it cannot share a token connection"
            ]
        );
    }

    /// The stub dialect with instance-bound grants: a profile's target names
    /// the one instance (origin and path) its consumers must act on.
    struct InstanceBoundDialect;
    static INSTANCE_BOUND_DIALECT: agent_access_provider::OAuthDialectRegistration =
        agent_access_provider::OAuthDialectRegistration::new(
            agent_access_provider::module_metadata!(),
            "instance_bound_fixture",
            &InstanceBoundDialect,
        )
        .development_only();

    fn stub() -> &'static dyn OAuthDialect {
        agent_access_fake::STUB_OAUTH_DIALECT.dialect()
    }

    use agent_access_provider::{
        AuthorizationRequest, CodeExchange, ConnectedIdentity, OAuthCallbackIssuer, OAuthClient,
        OAuthDialect, OAuthDialectError, OAuthHttp, OAuthPermissionProfile,
        OAuthRegistrationConfig, OAuthTarget, RefreshReplay, TokenGrant, UpstreamAuthority,
    };

    #[async_trait::async_trait]
    impl OAuthDialect for InstanceBoundDialect {
        fn validate_registration(&self, config: &OAuthRegistrationConfig) -> Result<(), String> {
            stub().validate_registration(config)
        }
        fn check_consumer_authority(
            &self,
            _config: &OAuthRegistrationConfig,
            profile: &OAuthPermissionProfile,
            consumer: Option<&UpstreamAuthority>,
        ) -> Result<(), String> {
            let consumer = consumer.ok_or("the service declares no upstream authority")?;
            let instance = format!("{}{}", consumer.origin(), consumer.instance_path());
            if instance == profile.target {
                Ok(())
            } else {
                Err(format!("the profile target is {}", profile.target))
            }
        }
        fn upstream_allowlist(&self, config: &OAuthRegistrationConfig) -> Vec<String> {
            stub().upstream_allowlist(config)
        }
        fn authorization_url(
            &self,
            client: &OAuthClient<'_>,
            profile: &OAuthPermissionProfile,
            request: AuthorizationRequest<'_>,
        ) -> Result<url::Url, OAuthDialectError> {
            stub().authorization_url(client, profile, request)
        }
        fn callback_issuer(&self, config: &OAuthRegistrationConfig) -> OAuthCallbackIssuer {
            stub().callback_issuer(config)
        }
        fn refresh_replay(&self, config: &OAuthRegistrationConfig) -> RefreshReplay {
            stub().refresh_replay(config)
        }
        async fn exchange_code(
            &self,
            http: &OAuthHttp,
            client: &OAuthClient<'_>,
            exchange: CodeExchange<'_>,
        ) -> Result<TokenGrant, OAuthDialectError> {
            stub().exchange_code(http, client, exchange).await
        }
        async fn refresh(
            &self,
            http: &OAuthHttp,
            client: &OAuthClient<'_>,
            profile: &OAuthPermissionProfile,
            refresh_token: &str,
            granted_scopes: &std::collections::BTreeSet<String>,
        ) -> Result<TokenGrant, OAuthDialectError> {
            stub()
                .refresh(http, client, profile, refresh_token, granted_scopes)
                .await
        }
        async fn identity(
            &self,
            http: &OAuthHttp,
            client: &OAuthClient<'_>,
            access_token: &str,
        ) -> Result<ConnectedIdentity, OAuthDialectError> {
            stub().identity(http, client, access_token).await
        }
        async fn discover_targets(
            &self,
            http: &OAuthHttp,
            client: &OAuthClient<'_>,
            access_token: &str,
            granted_scopes: &std::collections::BTreeSet<String>,
        ) -> Result<Vec<OAuthTarget>, OAuthDialectError> {
            stub()
                .discover_targets(http, client, access_token, granted_scopes)
                .await
        }
    }

    #[test]
    fn oauth_connection_consumers_must_satisfy_the_dialect() {
        let registry = BackendRegistry::empty()
            .with_oauth_dialects([&INSTANCE_BOUND_DIALECT])
            .unwrap();
        let mut oauth = OAuthConfig::default();
        oauth.registrations.insert(
            "gitlab".into(),
            serde_json::from_value(serde_json::json!({
                "adapter": "instance_bound_fixture",
                "base_url": "https://gitlab.example.com",
                "redirect_uri": "https://broker.example.com/v1/oauth/callback/gitlab",
                "client_id": "broker",
                "client_secret_ref": "env:GITLAB_OAUTH_SECRET",
                "permission_profiles": {"default": {
                    "scopes": ["api"],
                    "audience": "gitlab",
                    "target": "https://gitlab.example.com"
                }}
            }))
            .unwrap(),
        );
        let check = |services: &[(&str, Option<&str>)]| {
            let names = services.iter().map(|(name, _)| *name).collect::<Vec<_>>();
            connection_authority_errors(
                &shared(connection(None, true), &names),
                &consumers(services),
                &oauth,
                &registry,
            )
        };
        assert!(
            check(&[
                ("rest", Some("https://gitlab.example.com")),
                ("git", Some("https://gitlab.example.com/")),
            ])
            .is_empty()
        );
        assert_eq!(
            check(&[("rest", Some("https://other.example.com")), ("git", None)]),
            [
                "credentials.connections.shared.oauth: git does not act on the upstream registration gitlab grants access to: the service declares no upstream authority",
                "credentials.connections.shared.oauth: rest does not act on the upstream registration gitlab grants access to: the profile target is https://gitlab.example.com",
            ]
        );
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
