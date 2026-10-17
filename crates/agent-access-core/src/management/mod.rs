//! Application-internal management cooperation. These capabilities are issued
//! only by core admission and never cross the provider SDK boundary.
use agent_access_provider::{ProviderError, ProviderResult};
use serde::Deserialize;
use serde_json::Value;
use std::{future::Future, pin::Pin};

pub use crate::runtime::broker_management::AdmittedManagementCommand;

/// A host fence bound to the exact runtime snapshot that admitted the command.
/// Implementations retain ownership through commit, publication and completion.
pub trait LocalOperationHost: Send + Sync {
    fn execute(
        &self,
        command: AdmittedManagementCommand,
    ) -> Pin<Box<dyn Future<Output = LocalOperationOutcome> + Send + 'static>>;
}

/// A local result with an optional sealed, already committed secret capture.
/// It deliberately has no Debug, Clone or general serialization implementation.
pub struct LocalOperationOutcome {
    pub(crate) result: Result<ProviderResult, ProviderError>,
    pub(crate) captured: Option<crate::runtime::broker_management::CapturedLocalOutput>,
}
impl LocalOperationOutcome {
    /// A host fence failure cannot impersonate successful local execution.
    pub fn rejected(error: ProviderError) -> Self {
        Self {
            result: Err(error),
            captured: None,
        }
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct PrincipalInput {
    pub principal_id: String,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct PrincipalCreateInput {
    pub principal_id: String,
    pub display_name: Option<String>,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct GroupInput {
    pub group_id: String,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct MembershipInput {
    pub principal_id: String,
    pub group_id: String,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct GrantInput {
    pub grant_id: String,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct SubjectInput {
    pub principal_id: String,
    pub grant_id: String,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct SubjectWriteInput {
    pub principal_id: String,
    pub grant_id: String,
    pub expected_version: i64,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct CredentialInput {
    pub principal_id: String,
    pub connection_id: String,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct CredentialInstallInput {
    pub principal_id: String,
    pub connection_id: String,
    pub token: ReferenceInput,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct ReferenceInput {
    pub secret_ref: String,
    pub expires_at: Option<String>,
}
impl Drop for ReferenceInput {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.secret_ref.zeroize();
    }
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct TokenInput {
    pub principal_id: String,
    pub token_id: String,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct TokenCreateInput {
    pub principal_id: String,
    pub grant_id: String,
    pub expected_version: i64,
    pub token_id: String,
    pub name: String,
    pub allowed_execution_contexts: Vec<crate::ExecutionContext>,
    pub ttl_seconds: u64,
}

pub(crate) enum ManagementCommand {
    PrincipalCreate(PrincipalCreateInput),
    PrincipalView(PrincipalInput),
    GroupView(GroupInput),
    MemberView(MembershipInput),
    MemberAdd(MembershipInput),
    MemberRemove(MembershipInput),
    GrantView(GrantInput),
    SubjectView(SubjectInput),
    SubjectAdd(SubjectWriteInput),
    SubjectRemove(SubjectWriteInput),
    CredentialView(CredentialInput),
    CredentialInstall(CredentialInstallInput),
    TokenCreate(TokenCreateInput),
    TokenView(TokenInput),
}
impl ManagementCommand {
    pub(crate) fn parse(action: &str, inputs: &Value) -> Result<Self, ProviderError> {
        fn parse<T: serde::de::DeserializeOwned>(inputs: &Value) -> Result<T, ProviderError> {
            serde_json::from_value(inputs.clone()).map_err(|_| invalid())
        }
        Ok(match action {
            "principal.create" => Self::PrincipalCreate(parse(inputs)?),
            "principal.view" => Self::PrincipalView(parse(inputs)?),
            "group.view" => Self::GroupView(parse(inputs)?),
            "group.member.view" => Self::MemberView(parse(inputs)?),
            "group.member.add" => Self::MemberAdd(parse(inputs)?),
            "group.member.remove" => Self::MemberRemove(parse(inputs)?),
            "grant.view" => Self::GrantView(parse(inputs)?),
            "grant.subject.view" => Self::SubjectView(parse(inputs)?),
            "grant.subject.add" => Self::SubjectAdd(parse(inputs)?),
            "grant.subject.remove" => Self::SubjectRemove(parse(inputs)?),
            "credential.view" => Self::CredentialView(parse(inputs)?),
            "credential.install" => Self::CredentialInstall(parse(inputs)?),
            "token.create" => Self::TokenCreate(parse(inputs)?),
            "token.view" => Self::TokenView(parse(inputs)?),
            _ => return Err(invalid()),
        })
    }
    pub(crate) fn is_write(&self) -> bool {
        matches!(
            self,
            Self::PrincipalCreate(_)
                | Self::MemberAdd(_)
                | Self::MemberRemove(_)
                | Self::SubjectAdd(_)
                | Self::SubjectRemove(_)
                | Self::CredentialInstall(_)
                | Self::TokenCreate(_)
        )
    }
    pub(crate) fn is_policy_write(&self) -> bool {
        matches!(self, Self::SubjectAdd(_) | Self::SubjectRemove(_))
    }
}
fn invalid() -> ProviderError {
    ProviderError::deny(
        agent_access_provider::ReasonCode::InputInvalid,
        "management action inputs are invalid",
    )
}

impl ManagementCommand {
    pub(crate) fn scopes(&self) -> Result<agent_access_provider::ResourceScopes, ProviderError> {
        use crate::managed_store::{
            validate_group_name, validate_policy_grant_id, validate_principal_id,
        };
        use ManagementCommand::*;
        let mut scopes = agent_access_provider::ResourceScopes::new();
        let (principal, group, grant, connection) = match self {
            PrincipalCreate(v) => (Some(v.principal_id.as_str()), None, None, None),
            PrincipalView(v) => (Some(v.principal_id.as_str()), None, None, None),
            GroupView(v) => (None, Some(v.group_id.as_str()), None, None),
            MemberView(v) | MemberAdd(v) | MemberRemove(v) => (
                Some(v.principal_id.as_str()),
                Some(v.group_id.as_str()),
                None,
                None,
            ),
            GrantView(v) => (None, None, Some(v.grant_id.as_str()), None),
            SubjectView(v) => (
                Some(v.principal_id.as_str()),
                None,
                Some(v.grant_id.as_str()),
                None,
            ),
            SubjectAdd(v) | SubjectRemove(v) => (
                Some(v.principal_id.as_str()),
                None,
                Some(v.grant_id.as_str()),
                None,
            ),
            CredentialView(v) => (
                Some(v.principal_id.as_str()),
                None,
                None,
                Some(v.connection_id.as_str()),
            ),
            CredentialInstall(v) => (
                Some(v.principal_id.as_str()),
                None,
                None,
                Some(v.connection_id.as_str()),
            ),
            TokenCreate(v) => (
                Some(v.principal_id.as_str()),
                None,
                Some(v.grant_id.as_str()),
                None,
            ),
            TokenView(v) => (Some(v.principal_id.as_str()), None, None, None),
        };
        for (name, value, validator) in [
            (
                "principal",
                principal,
                validate_principal_id as fn(&str) -> Result<(), crate::ManagedStoreError>,
            ),
            ("group", group, validate_group_name),
            ("grant", grant, validate_policy_grant_id),
        ] {
            if let Some(value) = value {
                validator(value).map_err(|_| invalid())?;
                scopes.insert(name.into(), vec![value.into()]);
            }
        }
        if let Some(value) = connection {
            if !agent_access_provider::is_service_name(value) {
                return Err(invalid());
            }
            scopes.insert("connection".into(), vec![value.into()]);
        }
        match self {
            PrincipalCreate(v)
                if v.display_name
                    .as_ref()
                    .is_some_and(|name| name.len() > 256 || name.chars().any(char::is_control)) =>
            {
                return Err(invalid());
            }
            SubjectAdd(v) | SubjectRemove(v) if v.expected_version < 1 => return Err(invalid()),
            CredentialInstall(v) => {
                if !crate::runtime::broker_management::valid_reference(&v.token.secret_ref)
                    || v.token
                        .expires_at
                        .as_ref()
                        .is_some_and(|value| value.len() > 64)
                {
                    return Err(invalid());
                }
            }
            TokenCreate(v) => {
                validate_token_id(&v.token_id)?;
                let unique = v
                    .allowed_execution_contexts
                    .iter()
                    .collect::<std::collections::BTreeSet<_>>();
                if v.expected_version < 1
                    || v.ttl_seconds == 0
                    || v.name.trim().is_empty()
                    || v.name.len() > 128
                    || v.name.chars().any(char::is_control)
                    || unique.is_empty()
                    || unique.len() != v.allowed_execution_contexts.len()
                {
                    return Err(invalid());
                }
            }
            TokenView(v) => validate_token_id(&v.token_id)?,
            _ => {}
        }
        Ok(scopes)
    }
}
fn validate_token_id(value: &str) -> Result<(), ProviderError> {
    let id = uuid::Uuid::parse_str(value).map_err(|_| invalid())?;
    if id.get_version() != Some(uuid::Version::Random)
        || id.get_variant() != uuid::Variant::RFC4122
        || id.to_string() != value
    {
        return Err(invalid());
    }
    Ok(())
}

pub(crate) enum CommandError {
    Store(crate::ManagedStoreError),
    CommitUnknown,
    Ineligible,
    Exists,
    Precondition(&'static str),
    Denied,
    ConnectionIneligible,
    ReferenceDenied,
}
impl From<crate::ManagedStoreError> for CommandError {
    fn from(value: crate::ManagedStoreError) -> Self {
        match value {
            crate::ManagedStoreError::CommitUnknown => Self::CommitUnknown,
            error => Self::Store(error),
        }
    }
}

impl std::fmt::Debug for CommandError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Store(_) => "CommandError::Store",
            Self::CommitUnknown => "CommandError::CommitUnknown",
            Self::Ineligible => "CommandError::Ineligible",
            Self::Exists => "CommandError::Exists",
            Self::Precondition(_) => "CommandError::Precondition",
            Self::Denied => "CommandError::Denied",
            Self::ConnectionIneligible => "CommandError::ConnectionIneligible",
            Self::ReferenceDenied => "CommandError::ReferenceDenied",
        })
    }
}

/// A committed management response and its safe facts captured in the same
/// transaction. Only the transport adapter decides whether the value is secret.
pub struct ManagementMutation<T> {
    pub value: T,
    pub audit: Value,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    #[test]
    fn parser_seals_exact_complete_tuples_and_rejects_privilege_fields() {
        let parsed = ManagementCommand::parse(
            "group.member.add",
            &json!({"principalId":"worker+one@example.test","groupId":"workers"}),
        )
        .unwrap();
        let scopes = parsed.scopes().unwrap();
        assert_eq!(scopes.len(), 2);
        assert_eq!(scopes["principal"], ["worker+one@example.test"]);
        for forbidden in ["role", "actor", "credentialMode", "isAdmin", "subject"] {
            let mut input = json!({"principalId":"worker","groupId":"workers"});
            input[forbidden] = json!("admin");
            assert!(ManagementCommand::parse("group.member.add", &input).is_err());
        }
    }
    #[test]
    fn token_ids_are_canonical_v4_and_install_requires_reference_object() {
        for (token_id, valid) in [
            ("f47ac10b-58cc-4372-a567-0e02b2c3d479", true),
            ("F47AC10B-58CC-4372-A567-0E02B2C3D479", false),
            ("00000000-0000-1000-8000-000000000000", false),
            ("f47ac10b-58cc-4372-2567-0e02b2c3d479", false),
        ] {
            let input = json!({"principalId":"worker","tokenId":token_id});
            assert_eq!(
                ManagementCommand::parse("token.view", &input)
                    .unwrap()
                    .scopes()
                    .is_ok(),
                valid
            );
        }
        assert!(
            ManagementCommand::parse(
                "credential.install",
                &json!({"principalId":"worker","connectionId":"gitlab-main","token":"literal"})
            )
            .is_err()
        );
        assert!(ManagementCommand::parse("credential.install",&json!({"principalId":"worker","connectionId":"gitlab-main","token":{"secretRef":"not-a-reference"}})).unwrap().scopes().is_err());
    }
}
