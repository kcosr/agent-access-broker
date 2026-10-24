//! Credential connections as management presents them: setup targets, list
//! rows, retained rows and the consuming services a principal is entitled
//! to see.
//!
//! A connection's token rows live under the connection ID in the stored
//! `service` column with the name [`CONNECTION_CREDENTIAL_NAME`]. A row is
//! the principal's *active* row when its connection selects
//! [`Selection::Token`] for the principal's kind with a list that accepts
//! the row's profile; every other row the principal owns is *retained*:
//! listed read-only and deletable only by its credential ID.

use agent_access_core::{
    BrokerRuntime, CONNECTION_CREDENTIAL_NAME, ConnectionTokenProfile, CredentialInputSchema,
    CredentialMetadata, IdentityContext, PrincipalKind, RemoteRevocation, Selection,
};
use serde::Serialize;
use serde_json::{Value, json};
use std::collections::BTreeSet;

/// One service consuming a connection, as a list or target row names it.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct ConnectionConsumer {
    pub(super) service: String,
    pub(super) display_name: String,
    /// Inputs verifying through this consumer needs besides the credential,
    /// such as `repository` for a Git gateway. Empty when it needs none.
    pub(super) credential_verification_inputs: Vec<String>,
}

/// One token profile a connection accepts from the principal, with the
/// form storing a token of it takes.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct TokenProfileView {
    pub(super) profile: String,
    /// The label a consumer declares; clients show the profile otherwise.
    pub(super) label: Option<String>,
    pub(super) credential_kind: String,
    pub(super) input_schema: CredentialInputSchema,
}

/// A connection whose token the principal can store now.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct ConnectionTarget {
    pub(super) connection: String,
    pub(super) display_name: String,
    pub(super) consumers: Vec<ConnectionConsumer>,
    pub(super) other_consumers: usize,
    /// The token profiles the principal may store, in configuration order.
    pub(super) token_profiles: Vec<TokenProfileView>,
}

/// The method a connection selects for a principal, as a list row reports
/// it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum ConnectionMethod {
    Token,
    Oauth,
    Unavailable,
}

impl ConnectionMethod {
    pub(super) fn of(selection: Selection<'_>) -> Self {
        match selection {
            Selection::Token(_) => Self::Token,
            Selection::OAuth(_) => Self::Oauth,
            Selection::Unavailable => Self::Unavailable,
        }
    }
}

/// One row of the personal credentials list.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct ConnectionRow {
    pub(super) connection: String,
    pub(super) display_name: String,
    pub(super) method: ConnectionMethod,
    pub(super) consumers: Vec<ConnectionConsumer>,
    pub(super) other_consumers: usize,
    /// The token profiles the principal may store, for the token method;
    /// empty for the others.
    pub(super) token_profiles: Vec<TokenProfileView>,
    /// The OAuth registration, for the OAuth method.
    pub(super) registration: Option<String>,
    /// What is known about revoking the principal's ended families of that
    /// registration at the provider, for the OAuth method.
    pub(super) remote_revocation: Option<RemoteRevocation>,
    /// The stored active token, for the token method; `null` until one is
    /// stored.
    pub(super) credential: Option<Value>,
}

/// The name management shows for `connection`: its configured display name,
/// else its ID. A consumer's name never stands in for it, since the caller
/// may not be entitled to that consumer.
pub(super) fn display_name(runtime: &BrokerRuntime, connection: &str) -> String {
    runtime
        .effective_credentials()
        .connections
        .get(connection)
        .and_then(|config| config.display_name.clone())
        .unwrap_or_else(|| connection.to_string())
}

/// The services consuming `connection`, in service ID order.
pub(super) fn consumers(runtime: &BrokerRuntime, connection: &str) -> Vec<String> {
    runtime
        .effective_credentials()
        .connection_consumers(connection)
        .map(str::to_string)
        .collect()
}

/// The consumers of `connection` on which `identity` holds an active
/// `per_user` grant, in service ID order.
pub(super) fn entitled_consumers(
    runtime: &BrokerRuntime,
    identity: &IdentityContext,
    connection: &str,
) -> Vec<String> {
    consumers(runtime, connection)
        .into_iter()
        .filter(|service| runtime.has_any_per_user_policy_for_service(identity, service))
        .collect()
}

/// The entitled consumers' views and the count of the others.
pub(super) fn consumer_view(
    runtime: &BrokerRuntime,
    connection: &str,
    entitled: &[String],
) -> (Vec<ConnectionConsumer>, usize) {
    let all = consumers(runtime, connection);
    let views = entitled
        .iter()
        .filter_map(|service| {
            let descriptor = runtime.service_descriptor(service)?;
            Some(ConnectionConsumer {
                service: service.clone(),
                display_name: descriptor.display_name.clone(),
                credential_verification_inputs: descriptor.credential_verification_inputs(),
            })
        })
        .collect::<Vec<_>>();
    let other = all.len().saturating_sub(views.len());
    (views, other)
}

/// The method `connection` selects for `kind`; `None` for a connection the
/// effective configuration does not have.
pub(super) fn selection<'a>(
    runtime: &'a BrokerRuntime,
    connection: &str,
    kind: Option<PrincipalKind>,
) -> Option<Selection<'a>> {
    runtime
        .effective_credentials()
        .connections
        .get(connection)
        .map(|config| agent_access_core::select(config, kind))
}

/// The token profiles `connection` accepts from a principal of `kind`,
/// when it selects the token method for that kind.
pub(super) fn token_selection(
    runtime: &BrokerRuntime,
    connection: &str,
    kind: Option<PrincipalKind>,
) -> Option<Vec<ConnectionTokenProfile>> {
    runtime.connection_token_profiles(connection, kind)
}

/// The input schema of a token of `profile` for `connection`: its fields
/// come from the profile's credential kind.
pub(super) fn input_schema(
    runtime: &BrokerRuntime,
    connection: &str,
    profile: &ConnectionTokenProfile,
) -> Option<CredentialInputSchema> {
    runtime.connection_credential_input_schema(
        connection,
        &display_name(runtime, connection),
        &profile.profile,
        profile.credential_kind,
    )
}

/// The views of `profiles`, each with its input schema; a profile whose
/// kind has no input form is left out.
pub(super) fn token_profile_views(
    runtime: &BrokerRuntime,
    connection: &str,
    profiles: &[ConnectionTokenProfile],
) -> Vec<TokenProfileView> {
    profiles
        .iter()
        .filter_map(|profile| {
            Some(TokenProfileView {
                profile: profile.profile.clone(),
                label: profile.label.clone(),
                credential_kind: profile.credential_kind.to_string(),
                input_schema: input_schema(runtime, connection, profile)?,
            })
        })
        .collect()
}

/// The setup target of `connection` for a principal of `kind` with the
/// given entitled consumers, when the connection selects the token method
/// for that kind.
pub(super) fn target(
    runtime: &BrokerRuntime,
    connection: &str,
    kind: Option<PrincipalKind>,
    entitled: &[String],
) -> Option<ConnectionTarget> {
    let profiles = token_selection(runtime, connection, kind)?;
    let token_profiles = token_profile_views(runtime, connection, &profiles);
    if token_profiles.is_empty() {
        return None;
    }
    let (consumers, other_consumers) = consumer_view(runtime, connection, entitled);
    Some(ConnectionTarget {
        connection: connection.to_string(),
        display_name: display_name(runtime, connection),
        consumers,
        other_consumers,
        token_profiles,
    })
}

/// Every effective connection ID, in ID order.
pub(super) fn connection_ids(runtime: &BrokerRuntime) -> Vec<String> {
    runtime
        .effective_credentials()
        .connections
        .keys()
        .cloned()
        .collect()
}

/// The `(connection, profile)` pairs whose `(connection, default)` row is
/// active for a principal of `kind`: the connections selecting the token
/// method for that kind, with each token profile their list accepts.
pub(super) fn active_token_rows(
    runtime: &BrokerRuntime,
    kind: Option<PrincipalKind>,
) -> BTreeSet<(String, String)> {
    connection_ids(runtime)
        .into_iter()
        .flat_map(|connection| {
            token_selection(runtime, &connection, kind)
                .unwrap_or_default()
                .into_iter()
                .map(move |profile| (connection.clone(), profile.profile))
        })
        .collect()
}

/// Whether `credential` is its owner's active row among `active`.
pub(super) fn is_active_row(
    active: &BTreeSet<(String, String)>,
    credential: &CredentialMetadata,
) -> bool {
    credential.name == CONNECTION_CREDENTIAL_NAME
        && active.contains(&(credential.service.clone(), credential.profile.clone()))
}

/// Active token metadata keyed by its connection: the stored `service` and
/// `name` are replaced by `connection`, and its profile's `label` is added.
pub(super) fn connection_credential(
    runtime: &BrokerRuntime,
    credential: CredentialMetadata,
) -> Value {
    let connection = credential.service.clone();
    let mut value = stored_credential(runtime, credential);
    if let Some(object) = value.as_object_mut() {
        object.remove("service");
        object.remove("name");
        object.insert("connection".to_string(), json!(connection));
    }
    value
}

/// A stored row's metadata with the `label` its connection's consumers
/// declare for its profile, or `null`.
pub(super) fn stored_credential(runtime: &BrokerRuntime, credential: CredentialMetadata) -> Value {
    let label = runtime.connection_profile_label(&credential.service, &credential.profile);
    let mut value = json!(credential);
    if let Some(object) = value.as_object_mut() {
        object.insert("label".to_string(), json!(label));
    }
    value
}

/// The management audit target of a connection operation.
pub(super) fn audit_target(principal: &str, connection: &str) -> Value {
    json!({
        "principal": principal,
        "connection": connection,
    })
}

/// A principal's credential connections and the retained rows it owns.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct CredentialList {
    pub(super) connections: Vec<ConnectionRow>,
    /// The retained rows' metadata, each with its profile's label.
    pub(super) retained: Vec<Value>,
}

/// `identity`'s credential list from its stored `rows`: every connection
/// it is entitled to through a consumer, whatever the method, every
/// connection whose active token it still owns, and every OAuth connection
/// whose remote revocation still needs attention, then its retained rows.
/// `readable` restricts a classless caller to the token connections its
/// rights cover.
pub(super) fn credential_list(
    runtime: &BrokerRuntime,
    identity: &IdentityContext,
    rows: Vec<CredentialMetadata>,
    readable: Option<&BTreeSet<String>>,
) -> CredentialList {
    let kind = identity.principal_kind;
    let active = active_token_rows(runtime, kind);
    let (active_rows, retained): (Vec<_>, Vec<_>) = rows
        .into_iter()
        .partition(|row| is_active_row(&active, row));
    let mut listed = Vec::new();
    for connection in connection_ids(runtime) {
        let Some(selection) = selection(runtime, &connection, kind) else {
            continue;
        };
        let method = ConnectionMethod::of(selection);
        let entitled = entitled_consumers(runtime, identity, &connection);
        let credential = active_rows
            .iter()
            .find(|row| row.service == connection)
            .cloned();
        let registration = match selection {
            Selection::OAuth(oauth) => Some(oauth.registration.clone()),
            _ => None,
        };
        // Unknown, and so null, while OAuth is inactive or the store cannot
        // answer.
        let remote_revocation = registration.as_ref().and_then(|registration| {
            runtime
                .oauth_manager()?
                .remote_revocation(&identity.principal, registration)
                .ok()
        });
        // An OAuth connection whose remote revocation is unfinished or needs
        // provider-side cleanup stays listed after its owner lost every
        // grant on it.
        let include = match readable {
            Some(readable) => readable.contains(&connection),
            None => {
                !entitled.is_empty()
                    || credential.is_some()
                    || remote_revocation.is_some_and(RemoteRevocation::needs_attention)
            }
        };
        if !include {
            continue;
        }
        let (consumers, other_consumers) = consumer_view(runtime, &connection, &entitled);
        let token_profiles = match selection {
            Selection::Token(_) => token_selection(runtime, &connection, kind)
                .map(|profiles| token_profile_views(runtime, &connection, &profiles))
                .unwrap_or_default(),
            _ => Vec::new(),
        };
        listed.push(ConnectionRow {
            display_name: display_name(runtime, &connection),
            connection,
            method,
            consumers,
            other_consumers,
            token_profiles,
            registration,
            remote_revocation,
            credential: credential.map(|credential| connection_credential(runtime, credential)),
        });
    }
    CredentialList {
        connections: listed,
        retained: retained
            .into_iter()
            .map(|credential| stored_credential(runtime, credential))
            .collect(),
    }
}
