//! Credential connections as management presents them: setup targets, list
//! rows, retained rows and the consuming services a principal is entitled
//! to see.
//!
//! A connection's token rows live under the connection ID in the stored
//! `service` column with the name [`CONNECTION_CREDENTIAL_NAME`]. A row is
//! the principal's *active* row when its connection selects
//! [`Selection::Token`] for the principal's kind with the row's profile;
//! every other row the principal owns is *retained*: listed read-only and
//! deletable only by its credential ID.

use agent_access_core::{
    BrokerRuntime, CONNECTION_CREDENTIAL_NAME, CredentialInputSchema, CredentialMetadata,
    IdentityContext, PrincipalKind, Selection,
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

/// A connection whose token the principal can store now.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct ConnectionTarget {
    pub(super) connection: String,
    pub(super) display_name: String,
    pub(super) consumers: Vec<ConnectionConsumer>,
    pub(super) other_consumers: usize,
    pub(super) profile: String,
    pub(super) credential_kind: String,
    pub(super) input_schema: CredentialInputSchema,
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
    /// The token profile, for the token method.
    pub(super) profile: Option<String>,
    /// The token profile's credential kind, for the token method.
    pub(super) credential_kind: Option<String>,
    /// The OAuth registration, for the OAuth method.
    pub(super) registration: Option<String>,
    /// The stored active token, for the token method; `null` until one is
    /// stored.
    pub(super) credential: Option<Value>,
}

/// The name management shows for `connection`: its configured display name,
/// else its first consumer's, else its ID.
pub(super) fn display_name(runtime: &BrokerRuntime, connection: &str) -> String {
    let credentials = runtime.effective_credentials();
    if let Some(name) = credentials
        .connections
        .get(connection)
        .and_then(|config| config.display_name.clone())
    {
        return name;
    }
    credentials
        .connection_consumers(connection)
        .find_map(|service| runtime.service_descriptor(service))
        .map_or_else(
            || connection.to_string(),
            |descriptor| descriptor.display_name.clone(),
        )
}

/// The services consuming `connection`, in configured order.
pub(super) fn consumers(runtime: &BrokerRuntime, connection: &str) -> Vec<String> {
    runtime
        .effective_credentials()
        .connection_consumers(connection)
        .map(str::to_string)
        .collect()
}

/// The consumers of `connection` on which `identity` holds an active
/// `per_user` grant, in configured order.
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

/// The token profile and its credential kind when `connection` selects the
/// token method for `kind`.
pub(super) fn token_selection(
    runtime: &BrokerRuntime,
    connection: &str,
    kind: Option<PrincipalKind>,
) -> Option<(String, String)> {
    let Some(Selection::Token(_)) = selection(runtime, connection, kind) else {
        return None;
    };
    let (profile, credential_kind) = runtime.connection_token_profile(connection)?;
    Some((profile.to_string(), credential_kind.to_string()))
}

/// The input schema of `connection`'s token profile.
pub(super) fn input_schema(
    runtime: &BrokerRuntime,
    connection: &str,
) -> Option<CredentialInputSchema> {
    let (profile, credential_kind) = runtime.connection_token_profile(connection)?;
    agent_access_core::credential_input_schema(
        connection,
        &display_name(runtime, connection),
        profile,
        credential_kind,
    )
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
    let (profile, credential_kind) = token_selection(runtime, connection, kind)?;
    let input_schema = input_schema(runtime, connection)?;
    let (consumers, other_consumers) = consumer_view(runtime, connection, entitled);
    Some(ConnectionTarget {
        connection: connection.to_string(),
        display_name: display_name(runtime, connection),
        consumers,
        other_consumers,
        profile,
        credential_kind,
        input_schema,
    })
}

/// Every effective connection ID, in configured order.
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
/// method for that kind, with their token profile.
pub(super) fn active_token_rows(
    runtime: &BrokerRuntime,
    kind: Option<PrincipalKind>,
) -> BTreeSet<(String, String)> {
    connection_ids(runtime)
        .into_iter()
        .filter_map(|connection| {
            let (profile, _) = token_selection(runtime, &connection, kind)?;
            Some((connection, profile))
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
/// `name` are replaced by `connection`.
pub(super) fn connection_credential(credential: CredentialMetadata) -> Value {
    let connection = credential.service.clone();
    let mut value = json!(credential);
    if let Some(object) = value.as_object_mut() {
        object.remove("service");
        object.remove("name");
        object.insert("connection".to_string(), json!(connection));
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
