//! The request documents core writes to a command's stdin, and the secrets
//! each one supplies.
//!
//! Core builds a request after the budget permit and the final checks, from
//! what admission planned (the caller, the authority) and what it resolved
//! after the permit (credentials, decrypted resource attributes). Every
//! secret it holds is zeroized on drop, none of these types has `Debug`,
//! `Clone` or a public `Serialize`, and the only output is the encoded
//! [`CommandRequest`]:
//!
//! - `invoke`: `format`, `action` (the manifest name), `context`,
//!   `requestId`, `deadline`, `caller`, `inputs`, `authorization`,
//!   `credentials` for a command with a credential, and `network` with
//!   `network = "inherit"`;
//! - `verify`: `format`, `requestId`, `deadline`, the one `credential` to
//!   check and `network` with `network = "inherit"`.
//!
//! Credentials and authorization grants are keyed by wire mode: `service`
//! for the import's execution slot and `user` for a personal credential
//! (stored `per_user`). A command without a credential receives no
//! `credentials` and no `credential` member anywhere.
use super::{COMMAND_FORMAT, CommandRequest, ImportedCredentialKind};
use crate::network::{InheritedNetwork, InheritedNetworkWire};
use agent_access_provider::ProviderError;
use serde::Serialize;
use serde::ser::{SerializeMap, Serializer};
use serde_json::Value;
use std::collections::BTreeMap;
use std::fmt;
use zeroize::Zeroizing;

/// The wire spelling of a stored credential mode: `service`, or `user` for
/// `per_user`. `None` for any other mode, which a command never receives.
pub(crate) fn wire_mode(mode: &str) -> Option<&'static str> {
    match mode {
        "service" => Some("service"),
        "per_user" => Some("user"),
        _ => None,
    }
}

/// The secrets core supplied to one command run: credential tokens,
/// decrypted private attribute values and the inherited proxy password.
/// Command output must not echo them where the Broker copies it outside the
/// sensitive result, such as a receipt's `safeLocators`.
///
/// Values are zeroized on drop; `Debug` shows only their count. Empty
/// values are not kept, since every text contains them.
#[derive(Default)]
pub struct CommandSecrets(Vec<Zeroizing<String>>);

impl CommandSecrets {
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds `secret` unless it is empty.
    pub fn insert(&mut self, secret: &str) {
        if !secret.is_empty() && !self.0.iter().any(|known| known.as_str() == secret) {
            self.0.push(Zeroizing::new(secret.to_owned()));
        }
    }

    /// Whether `text` contains any supplied secret.
    pub fn found_in(&self, text: &str) -> bool {
        self.0.iter().any(|secret| text.contains(secret.as_str()))
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl fmt::Debug for CommandSecrets {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CommandSecrets")
            .field("count", &self.0.len())
            .finish()
    }
}

/// One stored credential as a command receives it: `{"kind": "token",
/// "token"}` or `{"kind": "username_token", "username", "token"}`.
pub(crate) struct CommandCredential {
    username: Option<Zeroizing<String>>,
    token: Zeroizing<String>,
}

impl CommandCredential {
    /// A `token` credential (stored `bearer_token`).
    pub(crate) fn token(token: String) -> Self {
        Self {
            username: None,
            token: Zeroizing::new(token),
        }
    }

    /// A `username_token` credential (stored `basic_api_token`).
    pub(crate) fn username_token(username: String, token: String) -> Self {
        Self {
            username: Some(Zeroizing::new(username)),
            token: Zeroizing::new(token),
        }
    }

    pub(crate) fn kind(&self) -> ImportedCredentialKind {
        if self.username.is_some() {
            ImportedCredentialKind::UsernameToken
        } else {
            ImportedCredentialKind::Token
        }
    }

    fn supply(&self, secrets: &mut CommandSecrets) {
        secrets.insert(&self.token);
    }

    fn wire<'a>(&'a self, mode: Option<&'static str>) -> CredentialWire<'a> {
        CredentialWire {
            mode,
            kind: self.kind().as_str(),
            username: self.username.as_deref().map(String::as_str),
            token: &self.token,
        }
    }
}

#[derive(Serialize)]
struct CredentialWire<'a> {
    #[serde(skip_serializing_if = "Option::is_none")]
    mode: Option<&'static str>,
    kind: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    username: Option<&'a str>,
    token: &'a str,
}

/// The request's `caller`: the stored principal, the trusted username
/// assertion and the agent token the call used, and the caller's policy
/// groups.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub(crate) struct CommandCaller {
    pub principal: String,
    /// `user`, `service_account` or `system`.
    pub kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub username: Option<CommandCallerUsername>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token: Option<CommandCallerToken>,
    pub groups: Vec<String>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub(crate) struct CommandCallerUsername {
    pub namespace: String,
    pub name: String,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub(crate) struct CommandCallerToken {
    pub id: String,
    pub label: String,
}

/// One resource the request names: its value and, when an enabled exact
/// entry in the call's context holds it, the entry's ID, display name and
/// decrypted private attributes. A value covered only by an `all` grant
/// carries just its value.
pub(crate) struct RequestResource {
    value: String,
    entry: Option<RequestResourceEntry>,
}

struct RequestResourceEntry {
    id: String,
    name: Option<String>,
    attributes: BTreeMap<String, Zeroizing<String>>,
}

impl RequestResource {
    pub(crate) fn value(value: String) -> Self {
        Self { value, entry: None }
    }

    pub(crate) fn entry(
        value: String,
        id: String,
        name: Option<String>,
        attributes: BTreeMap<String, Zeroizing<String>>,
    ) -> Self {
        Self {
            value,
            entry: Some(RequestResourceEntry {
                id,
                name,
                attributes,
            }),
        }
    }

    fn supply(&self, secrets: &mut CommandSecrets) {
        for value in self
            .entry
            .iter()
            .flat_map(|entry| entry.attributes.values())
        {
            secrets.insert(value);
        }
    }
}

impl Serialize for RequestResource {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut map = serializer.serialize_map(None)?;
        map.serialize_entry("value", &self.value)?;
        if let Some(entry) = &self.entry {
            map.serialize_entry("id", &entry.id)?;
            if let Some(name) = &entry.name {
                map.serialize_entry("name", name)?;
            }
            map.serialize_entry(
                "attributes",
                &entry
                    .attributes
                    .iter()
                    .map(|(name, value)| (name, value.as_str()))
                    .collect::<BTreeMap<_, _>>(),
            )?;
        }
        map.end()
    }
}

/// The request's `authorization` block.
pub(crate) enum RequestAuthorization {
    /// `{"mode": "broker", "credential"?, "resourceType", "resources"}`:
    /// every resource the inputs name, covered by the one selected grant.
    Broker {
        credential: Option<&'static str>,
        resource_type: String,
        resources: Vec<RequestResource>,
    },
    /// `{"mode": "command", "resourceType"?, "grants"}`: the caller's grants
    /// the command constrains its work to.
    Command {
        resource_type: Option<String>,
        grants: Vec<RequestGrant>,
    },
}

/// One command-enforced grant: `{"credential"?, "resources": "any",
/// "except"?}` or `{"credential"?, "resources": [...]}`.
pub(crate) struct RequestGrant {
    pub credential: Option<&'static str>,
    pub boundary: RequestBoundary,
}

pub(crate) enum RequestBoundary {
    /// Every value except `except`, the excluded exact values.
    Any { except: Vec<String> },
    /// Exactly these resources.
    Resources(Vec<RequestResource>),
}

impl RequestAuthorization {
    fn supply(&self, secrets: &mut CommandSecrets) {
        let resources: Box<dyn Iterator<Item = &RequestResource>> = match self {
            Self::Broker { resources, .. } => Box::new(resources.iter()),
            Self::Command { grants, .. } => {
                Box::new(grants.iter().flat_map(|grant| match &grant.boundary {
                    RequestBoundary::Resources(resources) => resources.as_slice(),
                    RequestBoundary::Any { .. } => &[],
                }))
            }
        };
        for resource in resources {
            resource.supply(secrets);
        }
    }
}

impl Serialize for RequestAuthorization {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut map = serializer.serialize_map(None)?;
        match self {
            Self::Broker {
                credential,
                resource_type,
                resources,
            } => {
                map.serialize_entry("mode", "broker")?;
                if let Some(credential) = credential {
                    map.serialize_entry("credential", credential)?;
                }
                map.serialize_entry("resourceType", resource_type)?;
                map.serialize_entry("resources", resources)?;
            }
            Self::Command {
                resource_type,
                grants,
            } => {
                map.serialize_entry("mode", "command")?;
                if let Some(resource_type) = resource_type {
                    map.serialize_entry("resourceType", resource_type)?;
                }
                map.serialize_entry("grants", grants)?;
            }
        }
        map.end()
    }
}

impl Serialize for RequestGrant {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut map = serializer.serialize_map(None)?;
        if let Some(credential) = self.credential {
            map.serialize_entry("credential", credential)?;
        }
        match &self.boundary {
            RequestBoundary::Any { except } => {
                map.serialize_entry("resources", "any")?;
                if !except.is_empty() {
                    map.serialize_entry("except", except)?;
                }
            }
            RequestBoundary::Resources(resources) => {
                map.serialize_entry("resources", resources)?;
            }
        }
        map.end()
    }
}

/// The credentials one request carries, keyed by wire mode.
#[derive(Default)]
pub(crate) struct RequestCredentials(BTreeMap<&'static str, CommandCredential>);

impl RequestCredentials {
    pub(crate) fn insert(&mut self, wire_mode: &'static str, credential: CommandCredential) {
        self.0.insert(wire_mode, credential);
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl Serialize for RequestCredentials {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_map(
            self.0
                .iter()
                .map(|(mode, credential)| (*mode, credential.wire(None))),
        )
    }
}

/// Everything one `invoke` request holds.
pub(crate) struct InvokeRequest<'a> {
    /// The accepted action's manifest name.
    pub action: &'a str,
    pub context: &'a str,
    pub request_id: &'a str,
    /// RFC 3339 UTC.
    pub deadline: &'a str,
    pub caller: &'a CommandCaller,
    pub inputs: &'a Value,
    pub authorization: RequestAuthorization,
    /// `None` for a command without a credential.
    pub credentials: Option<RequestCredentials>,
    /// `Some` exactly with `network = "inherit"`.
    pub network: Option<&'a InheritedNetwork>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct InvokeDocument<'a> {
    format: &'static str,
    action: &'a str,
    context: &'a str,
    request_id: &'a str,
    deadline: &'a str,
    caller: &'a CommandCaller,
    inputs: &'a Value,
    authorization: &'a RequestAuthorization,
    #[serde(skip_serializing_if = "Option::is_none")]
    credentials: Option<&'a RequestCredentials>,
    #[serde(skip_serializing_if = "Option::is_none")]
    network: Option<InheritedNetworkWire<'a>>,
}

impl InvokeRequest<'_> {
    /// The encoded request and the secrets it supplies. A request over
    /// [`CommandRequest::MAX_BYTES`] fails `operation_failed`.
    pub(crate) fn encode(&self) -> Result<(CommandRequest, CommandSecrets), ProviderError> {
        let mut secrets = CommandSecrets::new();
        self.authorization.supply(&mut secrets);
        for credential in self.credentials.iter().flat_map(|all| all.0.values()) {
            credential.supply(&mut secrets);
        }
        for secret in self
            .network
            .iter()
            .flat_map(|network| network.supplied_secrets())
        {
            secrets.insert(secret);
        }
        let request = CommandRequest::encode(&InvokeDocument {
            format: COMMAND_FORMAT,
            action: self.action,
            context: self.context,
            request_id: self.request_id,
            deadline: self.deadline,
            caller: self.caller,
            inputs: self.inputs,
            authorization: &self.authorization,
            credentials: self.credentials.as_ref(),
            network: self.network.map(InheritedNetwork::wire),
        })?;
        Ok((request, secrets))
    }
}

/// Everything one `verify` request holds.
pub(crate) struct VerifyRequest<'a> {
    pub request_id: &'a str,
    pub deadline: &'a str,
    /// The wire mode of the credential: `service` or `user`.
    pub mode: &'static str,
    pub credential: &'a CommandCredential,
    pub network: Option<&'a InheritedNetwork>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct VerifyDocument<'a> {
    format: &'static str,
    request_id: &'a str,
    deadline: &'a str,
    credential: CredentialWire<'a>,
    #[serde(skip_serializing_if = "Option::is_none")]
    network: Option<InheritedNetworkWire<'a>>,
}

impl VerifyRequest<'_> {
    pub(crate) fn encode(&self) -> Result<CommandRequest, ProviderError> {
        CommandRequest::encode(&VerifyDocument {
            format: COMMAND_FORMAT,
            request_id: self.request_id,
            deadline: self.deadline,
            credential: self.credential.wire(Some(self.mode)),
            network: self.network.map(InheritedNetwork::wire),
        })
    }
}

/// `deadline`, a monotonic instant, as the RFC 3339 UTC time a command
/// reads: now plus the time remaining, in whole seconds.
pub(crate) fn wire_deadline(deadline: tokio::time::Instant) -> String {
    let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
    let at = chrono::Utc::now()
        + chrono::TimeDelta::from_std(remaining).unwrap_or(chrono::TimeDelta::zero());
    at.to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn caller() -> CommandCaller {
        CommandCaller {
            principal: "avery".into(),
            kind: "user".into(),
            display_name: Some("Avery Example".into()),
            email: Some("avery@example.com".into()),
            username: None,
            token: Some(CommandCallerToken {
                id: "tok_5c1d".into(),
                label: "laptop agent".into(),
            }),
            groups: vec!["engineering".into()],
        }
    }

    fn decode(request: &CommandRequest) -> Value {
        serde_json::from_slice(request.stdin()).unwrap()
    }

    fn attributes(entries: &[(&str, &str)]) -> BTreeMap<String, Zeroizing<String>> {
        entries
            .iter()
            .map(|(name, value)| ((*name).to_owned(), Zeroizing::new((*value).to_owned())))
            .collect()
    }

    #[test]
    fn broker_enforced_requests_pass_the_resources_and_one_credential() {
        let caller = caller();
        let inputs = json!({"project": "OPS", "issue": 42});
        let mut credentials = RequestCredentials::default();
        credentials.insert(
            "user",
            CommandCredential::username_token("avery".into(), "pat-example".into()),
        );
        let request = InvokeRequest {
            action: "issue.view",
            context: "internal",
            request_id: "brk_01JA7Q2W9V8X",
            deadline: "2026-10-14T15:04:35Z",
            caller: &caller,
            inputs: &inputs,
            authorization: RequestAuthorization::Broker {
                credential: Some("user"),
                resource_type: "project".into(),
                resources: vec![
                    RequestResource::entry(
                        "OPS".into(),
                        "ops".into(),
                        Some("Operations".into()),
                        attributes(&[("region", "eu-1"), ("webhookSecret", "s3cr3t-example")]),
                    ),
                    RequestResource::value("DEV".into()),
                ],
            },
            credentials: Some(credentials),
            network: None,
        };
        let (encoded, secrets) = request.encode().unwrap();
        assert_eq!(
            decode(&encoded),
            json!({
                "format": "agent-access-command/1", "action": "issue.view", "context": "internal",
                "requestId": "brk_01JA7Q2W9V8X", "deadline": "2026-10-14T15:04:35Z",
                "caller": { "principal": "avery", "kind": "user", "displayName": "Avery Example",
                    "email": "avery@example.com", "token": { "id": "tok_5c1d", "label": "laptop agent" },
                    "groups": ["engineering"] },
                "inputs": { "project": "OPS", "issue": 42 },
                "authorization": { "mode": "broker", "credential": "user", "resourceType": "project",
                    "resources": [{ "value": "OPS", "id": "ops", "name": "Operations",
                        "attributes": { "region": "eu-1", "webhookSecret": "s3cr3t-example" } },
                        { "value": "DEV" }] },
                "credentials": { "user": { "kind": "username_token", "username": "avery", "token": "pat-example" } }
            })
        );
        // Tokens and attribute values are supplied secrets; usernames are not.
        assert_eq!(secrets.len(), 3);
        assert!(secrets.found_in("pat-example"));
        assert!(secrets.found_in("x-eu-1-y"));
        assert!(secrets.found_in("s3cr3t-example"));
        assert!(!secrets.found_in("avery"));
        assert_eq!(format!("{secrets:?}"), "CommandSecrets { count: 3 }");
    }

    #[test]
    fn command_enforced_requests_pass_each_grant_with_its_own_credential() {
        let caller = caller();
        let inputs = json!({"query": "status = open"});
        let mut credentials = RequestCredentials::default();
        credentials.insert("user", CommandCredential::token("user-token".into()));
        credentials.insert("service", CommandCredential::token("service-token".into()));
        let request = InvokeRequest {
            action: "issue.search",
            context: "internal",
            request_id: "brk_1",
            deadline: "2026-10-14T15:05:10Z",
            caller: &caller,
            inputs: &inputs,
            authorization: RequestAuthorization::Command {
                resource_type: Some("project".into()),
                grants: vec![
                    RequestGrant {
                        credential: Some("user"),
                        boundary: RequestBoundary::Any {
                            except: vec!["SEC".into()],
                        },
                    },
                    RequestGrant {
                        credential: Some("service"),
                        boundary: RequestBoundary::Resources(vec![RequestResource::entry(
                            "OPS".into(),
                            "ops".into(),
                            None,
                            BTreeMap::new(),
                        )]),
                    },
                    RequestGrant {
                        credential: Some("service"),
                        boundary: RequestBoundary::Any { except: vec![] },
                    },
                ],
            },
            credentials: Some(credentials),
            network: None,
        };
        let (encoded, secrets) = request.encode().unwrap();
        let document = decode(&encoded);
        assert_eq!(
            document["authorization"],
            json!({"mode": "command", "resourceType": "project", "grants": [
                {"credential": "user", "resources": "any", "except": ["SEC"]},
                {"credential": "service", "resources": [{"value": "OPS", "id": "ops", "attributes": {}}]},
                {"credential": "service", "resources": "any"}
            ]})
        );
        assert_eq!(
            document["credentials"],
            json!({"service": {"kind": "token", "token": "service-token"},
                "user": {"kind": "token", "token": "user-token"}})
        );
        assert_eq!(secrets.len(), 2);
    }

    #[test]
    fn credential_free_and_untyped_requests_omit_credentials_and_resource_types() {
        let caller = caller();
        let inputs = json!({});
        let request = InvokeRequest {
            action: "time.now",
            context: "default",
            request_id: "brk_2",
            deadline: "2026-10-14T15:05:10Z",
            caller: &caller,
            inputs: &inputs,
            authorization: RequestAuthorization::Command {
                resource_type: None,
                grants: vec![RequestGrant {
                    credential: None,
                    boundary: RequestBoundary::Any { except: vec![] },
                }],
            },
            credentials: None,
            network: None,
        };
        let (encoded, secrets) = request.encode().unwrap();
        let document = decode(&encoded);
        assert_eq!(
            document["authorization"],
            json!({"mode": "command", "grants": [{"resources": "any"}]})
        );
        assert!(document.get("credentials").is_none());
        assert!(document.get("network").is_none());
        assert!(secrets.is_empty());
    }

    #[test]
    fn verify_requests_carry_only_the_credential_to_check() {
        let credential = CommandCredential::username_token("svc".into(), "svc-example".into());
        let request = VerifyRequest {
            request_id: "brk_3",
            deadline: "2026-10-14T15:06:00Z",
            mode: "service",
            credential: &credential,
            network: None,
        };
        assert_eq!(
            decode(&request.encode().unwrap()),
            json!({"format": "agent-access-command/1", "requestId": "brk_3",
                "deadline": "2026-10-14T15:06:00Z",
                "credential": {"mode": "service", "kind": "username_token",
                    "username": "svc", "token": "svc-example"}})
        );
        let token = CommandCredential::token("personal".into());
        let request = VerifyRequest {
            mode: "user",
            credential: &token,
            ..request
        };
        assert_eq!(
            decode(&request.encode().unwrap())["credential"],
            json!({"mode": "user", "kind": "token", "token": "personal"})
        );
    }

    #[test]
    fn modes_and_deadlines_use_their_wire_spellings() {
        assert_eq!(wire_mode("service"), Some("service"));
        assert_eq!(wire_mode("per_user"), Some("user"));
        assert_eq!(wire_mode("lookup"), None);
        let deadline =
            wire_deadline(tokio::time::Instant::now() + std::time::Duration::from_secs(90));
        let parsed = chrono::DateTime::parse_from_rfc3339(&deadline).unwrap();
        let remaining = parsed.with_timezone(&chrono::Utc) - chrono::Utc::now();
        assert!((88..=90).contains(&remaining.num_seconds()), "{deadline}");
        assert!(
            deadline.ends_with('Z') && !deadline.contains('.'),
            "{deadline}"
        );
    }

    #[test]
    fn empty_secrets_are_never_found() {
        let mut secrets = CommandSecrets::new();
        secrets.insert("");
        secrets.insert("abc");
        secrets.insert("abc");
        assert_eq!(secrets.len(), 1);
        assert!(!secrets.found_in("ab"));
        assert!(secrets.found_in("xabcx"));
    }
}
