//! Offline, adapter-owned static credential requirements shared by every import surface.
use super::{
    ImportedAuthMechanism, ImportedCredentialDelivery, ImportedCredentialKind,
    ImportedCredentialPurpose, ImportedDiscoveryCredential, ImportedServiceDefinition,
};
use crate::{CredentialInputField, CredentialInputSchema, ManagedStoreError};
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ImportedCredentialInputPolicy {
    TokenHeader,
    HttpBasic,
    CommandStdin,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImportedCredentialRequirement {
    material: Option<(ImportedCredentialKind, ImportedCredentialInputPolicy)>,
    unavailable_reason: String,
}
impl ImportedCredentialRequirement {
    pub fn token_header() -> Self {
        Self::ready(
            ImportedCredentialKind::Token,
            ImportedCredentialInputPolicy::TokenHeader,
        )
    }
    pub fn http_basic() -> Self {
        Self::ready(
            ImportedCredentialKind::UsernameToken,
            ImportedCredentialInputPolicy::HttpBasic,
        )
    }
    pub fn command_stdin(kind: ImportedCredentialKind) -> Self {
        Self::ready(kind, ImportedCredentialInputPolicy::CommandStdin)
    }
    fn ready(kind: ImportedCredentialKind, policy: ImportedCredentialInputPolicy) -> Self {
        Self {
            material: Some((kind, policy)),
            unavailable_reason: String::new(),
        }
    }
    pub fn unavailable(reason: impl Into<String>) -> Self {
        Self {
            material: None,
            unavailable_reason: reason.into(),
        }
    }
    pub fn kind(&self) -> Option<ImportedCredentialKind> {
        self.material.map(|v| v.0)
    }
    pub fn input_policy(&self) -> Option<ImportedCredentialInputPolicy> {
        self.material.map(|v| v.1)
    }
    pub(crate) fn require_kind(&self) -> Result<ImportedCredentialKind, ManagedStoreError> {
        self.kind()
            .ok_or_else(|| ManagedStoreError::InputInvalid(self.unavailable_reason.clone()))
    }
    pub fn input(&self) -> ImportedCredentialInput {
        let Some((kind, policy)) = self.material else {
            return ImportedCredentialInput::Unavailable {
                reason: self.unavailable_reason.clone(),
            };
        };
        ImportedCredentialInput::Ready {
            credential_kind: kind.credential_kind().into(),
            input_policy: policy,
            fields: self.fields(),
        }
    }
    pub fn input_schema(&self, connection: &str, profile: &str) -> Option<CredentialInputSchema> {
        let kind = self.kind()?;
        (profile == kind.personal_profile()).then(|| CredentialInputSchema {
            connection: connection.into(),
            profile: profile.into(),
            credential_kind: kind.credential_kind().into(),
            input_policy: self.input_policy(),
            fields: self.fields(),
        })
    }
    fn fields(&self) -> Vec<CredentialInputField> {
        let Some((kind, policy)) = self.material else {
            return Vec::new();
        };
        let field = |name: &str, secret, prompt: &str| CredentialInputField {
            name: name.into(),
            required: true,
            secret,
            prompt: prompt.into(),
            description: None,
            input_methods: Some(
                if secret {
                    vec!["prompt", "env", "file", "stdin"]
                } else {
                    vec!["prompt", "literal", "env", "file"]
                }
                .into_iter()
                .map(str::to_owned)
                .collect(),
            ),
        };
        let mut fields = Vec::new();
        if kind == ImportedCredentialKind::UsernameToken {
            fields.push(field("username", false, "Username"));
        }
        fields.push(field(
            "token",
            true,
            if policy == ImportedCredentialInputPolicy::HttpBasic {
                "Password or API token"
            } else {
                "Token"
            },
        ));
        fields
    }
    /// Validate while core still owns plaintext, before creating opaque SDK material.
    pub(crate) fn validate_secret(
        &self,
        kind: &str,
        secret: &Value,
    ) -> Result<(), ManagedStoreError> {
        let expected = self.require_kind()?;
        if expected.credential_kind() != kind {
            return Err(ManagedStoreError::CredentialInvalid(
                "stored credential kind does not match the imported contract".into(),
            ));
        }
        if self.input_policy() == Some(ImportedCredentialInputPolicy::CommandStdin) {
            return crate::managed_store::validate_credential_secret(kind, secret);
        }
        let object = secret
            .as_object()
            .ok_or_else(|| invalid("import credential must be an object"))?;
        let token = object
            .get("token")
            .and_then(Value::as_str)
            .ok_or_else(|| invalid("import credential requires a token"))?;
        let username = object.get("username").and_then(Value::as_str);
        if object.len()
            != if expected == ImportedCredentialKind::Token {
                1
            } else {
                2
            }
        {
            return Err(invalid("import credential has unsupported fields"));
        }
        self.plaintext(token, username).map(drop)
    }
    pub(crate) fn validate_stored_secret(
        &self,
        kind: &str,
        secret: &Value,
    ) -> Result<(), ManagedStoreError> {
        self.validate_secret(kind, secret)
            .map_err(|error| match error {
                ManagedStoreError::InputInvalid(message) => {
                    ManagedStoreError::CredentialInvalid(message)
                }
                other => other,
            })
    }
    pub(crate) fn plaintext(
        &self,
        token: &str,
        username: Option<&str>,
    ) -> Result<String, ManagedStoreError> {
        let kind = self.require_kind()?;
        let policy = self.input_policy().expect("ready requirement has policy");
        if token.is_empty() || token.len() > 32768 {
            return Err(invalid(
                "import credential token must be nonempty and fit the size limit",
            ));
        }
        if policy == ImportedCredentialInputPolicy::HttpBasic {
            if token.chars().any(char::is_control) {
                return Err(invalid(
                    "HTTP Basic password must not contain control characters",
                ));
            }
        } else if !token.bytes().all(|b| (0x21..=0x7e).contains(&b)) {
            return Err(invalid(
                "import token must contain visible ASCII characters",
            ));
        }
        match (kind, username) {
            (ImportedCredentialKind::Token, None) => Ok(token.into()),
            (ImportedCredentialKind::UsernameToken, Some(username))
                if !username.is_empty()
                    && username.len() <= 256
                    && !username.chars().any(char::is_control)
                    && (policy != ImportedCredentialInputPolicy::HttpBasic
                        || !username.contains(':')) =>
            {
                let encoded =
                    serde_json::to_string(&serde_json::json!({"username":username,"token":token}))
                        .map_err(|_| invalid("import credential cannot be encoded"))?;
                if encoded.len() > 32768 {
                    return Err(invalid("import credential exceeds the size limit"));
                }
                Ok(encoded)
            }
            (ImportedCredentialKind::UsernameToken, _) => Err(invalid(
                "import credential requires a valid username of at most 256 UTF-8 bytes",
            )),
            (ImportedCredentialKind::Token, Some(_)) => {
                Err(invalid("import credential takes no username"))
            }
        }
    }
}
fn invalid(message: &str) -> ManagedStoreError {
    ManagedStoreError::InputInvalid(message.into())
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "state",
    rename_all = "snake_case",
    rename_all_fields = "camelCase"
)]
pub enum ImportedCredentialInput {
    Ready {
        credential_kind: String,
        input_policy: ImportedCredentialInputPolicy,
        fields: Vec<CredentialInputField>,
    },
    Unavailable {
        reason: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImportedCredentialContract {
    execution: Option<ImportedCredentialRequirement>,
    discovery: Option<ImportedCredentialRequirement>,
    transport: Option<ImportedCredentialRequirement>,
}
impl ImportedCredentialContract {
    pub fn new(
        execution: Option<ImportedCredentialRequirement>,
        discovery: Option<ImportedCredentialRequirement>,
        transport: Option<ImportedCredentialRequirement>,
    ) -> Self {
        Self {
            execution,
            discovery,
            transport,
        }
    }
    pub fn requirement(
        &self,
        purpose: ImportedCredentialPurpose,
    ) -> Option<&ImportedCredentialRequirement> {
        match purpose {
            ImportedCredentialPurpose::Execution => self.execution.as_ref(),
            ImportedCredentialPurpose::Discovery => self.discovery.as_ref(),
            ImportedCredentialPurpose::Transport => self.transport.as_ref(),
        }
    }
    pub fn validate(&self, definition: &ImportedServiceDefinition) -> Result<(), String> {
        let static_bindings = definition
            .execution_bindings
            .iter()
            .filter(|b| b.mechanism == ImportedAuthMechanism::StaticToken)
            .collect::<Vec<_>>();
        if self.execution.is_some() == static_bindings.is_empty()
            || self.discovery.is_some()
                != matches!(definition.discovery, ImportedDiscoveryCredential::Slot)
            || self.transport.is_some() != definition.transport_auth
        {
            return Err("imported credential contract disagrees with declared purposes".into());
        }
        for requirement in [&self.execution, &self.discovery, &self.transport]
            .into_iter()
            .flatten()
        {
            if requirement.material.is_none()
                && (requirement.unavailable_reason.is_empty()
                    || requirement.unavailable_reason.len() > 256
                    || requirement.unavailable_reason.chars().any(char::is_control))
            {
                return Err(
                    "imported credential contract has an invalid unavailable reason".into(),
                );
            }
        }
        if let Some((kind, policy)) = self.execution.as_ref().and_then(|r| r.material) {
            for binding in static_bindings {
                let valid = match &binding.delivery {
                    ImportedCredentialDelivery::Bearer
                    | ImportedCredentialDelivery::RawHeader { .. } => {
                        kind == ImportedCredentialKind::Token
                            && policy == ImportedCredentialInputPolicy::TokenHeader
                    }
                    ImportedCredentialDelivery::Basic => {
                        kind == ImportedCredentialKind::UsernameToken
                            && policy == ImportedCredentialInputPolicy::HttpBasic
                    }
                    ImportedCredentialDelivery::Stdin => {
                        policy == ImportedCredentialInputPolicy::CommandStdin
                    }
                };
                if !valid {
                    return Err("imported credential material and delivery disagree".into());
                }
            }
        }
        if self.discovery.as_ref().is_some_and(|requirement| {
            requirement.input_policy() == Some(ImportedCredentialInputPolicy::CommandStdin)
        }) {
            return Err("dedicated discovery credentials require an HTTP delivery policy".into());
        }
        if self.transport.as_ref().is_some_and(|r| {
            r.material.is_some_and(|material| {
                material
                    != (
                        ImportedCredentialKind::Token,
                        ImportedCredentialInputPolicy::TokenHeader,
                    )
            })
        }) {
            return Err("transport credential must be a header token".into());
        }
        Ok(())
    }
}

/// Explicit contract of core's synthetic adapters; production adapters implement their own seam.
#[cfg(test)]
pub(crate) fn test_credential_contract(
    definition: &ImportedServiceDefinition,
    import: &super::ImportedAdapterContext<'_>,
) -> Result<ImportedCredentialContract, String> {
    let execution = definition
        .execution_bindings
        .iter()
        .find(|b| b.mechanism == ImportedAuthMechanism::StaticToken)
        .map(|binding| match &binding.delivery {
            ImportedCredentialDelivery::Basic => ImportedCredentialRequirement::http_basic(),
            ImportedCredentialDelivery::Bearer | ImportedCredentialDelivery::RawHeader { .. } => {
                ImportedCredentialRequirement::token_header()
            }
            ImportedCredentialDelivery::Stdin => import
                .accepted_metadata
                .and_then(|m| m.credential.as_ref())
                .map(|c| ImportedCredentialRequirement::command_stdin(c.kind))
                .unwrap_or_else(|| {
                    ImportedCredentialRequirement::unavailable(
                        "Accept the command manifest before setting its credential",
                    )
                }),
        });
    Ok(ImportedCredentialContract::new(
        execution,
        matches!(definition.discovery, ImportedDiscoveryCredential::Slot)
            .then(ImportedCredentialRequirement::token_header),
        definition
            .transport_auth
            .then(ImportedCredentialRequirement::token_header),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn basic_preserves_utf8_spaces_and_colons_in_password() {
        let requirement = ImportedCredentialRequirement::http_basic();
        let secret = json!({"username":"  Ålice ","token":" : pässword: "});
        requirement
            .validate_secret("basic_api_token", &secret)
            .unwrap();
        assert_eq!(
            serde_json::from_str::<Value>(
                &requirement
                    .plaintext(" : pässword: ", Some("  Ålice "))
                    .unwrap()
            )
            .unwrap(),
            secret
        );
        assert_eq!(
            requirement.plaintext(" ", Some(" ")).unwrap(),
            r#"{"token":" ","username":" "}"#
        );
    }

    #[test]
    fn basic_rejects_wrong_kind_controls_colon_username_and_byte_limits() {
        let requirement = ImportedCredentialRequirement::http_basic();
        for username in ["", "alice:admin", "line\nname", "alice\u{85}"] {
            assert!(requirement.plaintext("token", Some(username)).is_err());
        }
        for token in ["", "line\nsecret", "\t", "secret\u{85}", "\u{7f}"] {
            assert!(requirement.plaintext(token, Some("alice")).is_err());
        }
        assert!(
            requirement
                .plaintext("token", Some(&"é".repeat(129)))
                .is_err()
        );
        assert!(
            requirement
                .plaintext(&"a".repeat(32768), Some("alice"))
                .is_err()
        );
        assert!(
            requirement
                .plaintext(&"\\".repeat(17000), Some("alice"))
                .is_err()
        );
        assert!(
            requirement
                .validate_secret("bearer_token", &json!({"token":"token"}))
                .is_err()
        );
        assert!(
            requirement
                .validate_secret(
                    "basic_api_token",
                    &json!({"username":"alice","token":"token","password":"alias"})
                )
                .is_err()
        );
    }

    #[test]
    fn header_token_and_command_stdin_keep_their_distinct_input_rules() {
        let header = ImportedCredentialRequirement::token_header();
        for token in [" ", "token value", "é", "\n"] {
            assert!(header.plaintext(token, None).is_err());
        }
        assert_eq!(
            header.plaintext("token:with-punctuation", None).unwrap(),
            "token:with-punctuation"
        );
        assert!(header.plaintext("token", Some("alice")).is_err());
        let command =
            ImportedCredentialRequirement::command_stdin(ImportedCredentialKind::UsernameToken);
        assert!(command.plaintext("token", Some("alice:region")).is_ok());
        // Existing personal command credentials carry opaque stdin values; HTTP rules do not apply.
        command
            .validate_secret(
                "basic_api_token",
                &json!({"username":"alice:region","token":"opaque unicode é"}),
            )
            .unwrap();
    }

    #[test]
    fn descriptors_distinguish_basic_command_and_unavailable_contracts() {
        let basic = ImportedCredentialRequirement::http_basic();
        let schema = basic.input_schema("inventory", "username-token").unwrap();
        assert_eq!(
            schema.input_policy,
            Some(ImportedCredentialInputPolicy::HttpBasic)
        );
        assert_eq!(schema.fields[0].prompt, "Username");
        assert_eq!(schema.fields[1].prompt, "Password or API token");
        assert!(basic.input_schema("inventory", "token").is_none());
        assert_eq!(
            serde_json::to_value(basic.input()).unwrap()["inputPolicy"],
            "http_basic"
        );
        assert_eq!(
            ImportedCredentialRequirement::command_stdin(ImportedCredentialKind::UsernameToken)
                .input_policy(),
            Some(ImportedCredentialInputPolicy::CommandStdin)
        );
        let unavailable = ImportedCredentialRequirement::unavailable("Accept the manifest first");
        assert_eq!(
            serde_json::to_value(unavailable.input()).unwrap(),
            json!({"state":"unavailable","reason":"Accept the manifest first"})
        );
        assert!(unavailable.kind().is_none());
        assert!(unavailable.plaintext("token", None).is_err());
    }
}
