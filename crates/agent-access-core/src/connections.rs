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

use crate::{BackendRegistry, BrokerConfig, CredentialsConfig, OAuthBinding, OAuthConfig};
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

/// The kind of a connection's token profile as its consumers declare it,
/// when they agree; `None` when the profile is unset, undeclared or
/// declared with different kinds, which validation rejects.
pub(crate) fn connection_token_kind(
    credentials: &CredentialsConfig,
    services: &BTreeMap<String, Arc<ServiceDescriptor>>,
    connection: &str,
) -> Option<&'static str> {
    let profile = credentials
        .connections
        .get(connection)?
        .token_profile
        .as_deref()?;
    declared_profile_kind(
        profile,
        credentials
            .connection_consumers(connection)
            .filter_map(|service| services.get(service).map(Arc::as_ref)),
    )
    .ok()
    .flatten()
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
    errors.extend(connection_authority_errors(
        credentials,
        services,
        &config.oauth,
        config.providers.registry(),
    ));
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

/// Whether each connection's consumers act on one upstream (design: the
/// upstream authority contract). A token method requires every consumer of
/// a shared connection to declare an authority naming the same instance:
/// one origin and instance path. An OAuth method requires the
/// registration's dialect to accept each consumer's authority. Connections
/// whose OAuth registration or profile is missing are reported elsewhere.
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
        let consumers = credentials
            .connection_consumers(id)
            .filter_map(|service| services.get(service).map(|d| (service, d.as_ref())))
            .collect::<Vec<_>>();
        if connection.token_profile.is_some() && consumers.len() > 1 {
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
                },
            );
        }
        credentials
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
