//! Service-level metadata an import accepts together with its actions.
//!
//! A command import's manifest declares service-level data besides its
//! actions: the manifest format, the command version, the execution
//! credential, verification support and resource types. Discovery proposes it
//! in [`super::ImportedDiscovery::service_metadata`]; acceptance stores the
//! proposal verbatim in the nullable `imported_services.accepted_metadata_json`
//! column, in the same transaction as the accepted actions, and the record
//! carries it as [`crate::ImportedServiceRecord::accepted_metadata`]. MCP and
//! OpenAPI imports record none.
use super::ImportedCredentialMode;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

/// Upper bound of the encoded metadata, well below the manifest budget.
pub const IMPORT_MAX_METADATA_BYTES: usize = 256 * 1024;
/// Most resource types one import declares.
pub const IMPORT_MAX_RESOURCE_TYPES: usize = 16;
/// Most attributes one imported resource type declares.
pub const IMPORT_MAX_RESOURCE_ATTRIBUTES: usize = 16;

/// The accepted service-level metadata of an import.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ImportedServiceMetadata {
    /// The manifest format the adapter accepted, such as
    /// `agent-access-command/1`.
    pub format: String,
    /// The source's self-reported version: display only, never compared or
    /// pinned ("Imported at version X").
    pub version: String,
    /// The declared execution credential; `None` for an import that needs no
    /// credential, which then has no execution bindings and uses service-mode
    /// grants without a slot.
    pub credential: Option<ImportedCredentialDeclaration>,
    /// Whether the source supports credential verification.
    pub verify: bool,
    /// Declared resource types with their Broker type IDs.
    pub resource_types: Vec<ImportedResourceTypeDeclaration>,
}

/// One kind of execution credential for every mode of an import. Kind and
/// delivery are fixed once actions are accepted.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ImportedCredentialDeclaration {
    pub kind: ImportedCredentialKind,
    /// The modes the source supports: a nonempty subset of `service` and
    /// `per_user`. The import's execution bindings choose among them.
    pub modes: Vec<ImportedCredentialMode>,
}

/// The stored credential kind of an import's execution credential.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum ImportedCredentialKind {
    /// A single token, stored as `bearer_token`.
    Token,
    /// A username and token, stored as `basic_api_token`.
    UsernameToken,
}

impl ImportedCredentialKind {
    /// The wire spelling, `token` or `username_token`.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Token => "token",
            Self::UsernameToken => "username_token",
        }
    }

    /// The persisted credential kind of service slots and personal
    /// credentials: `bearer_token` or `basic_api_token`.
    pub fn credential_kind(self) -> &'static str {
        match self {
            Self::Token => "bearer_token",
            Self::UsernameToken => "basic_api_token",
        }
    }

    /// The managed-store profile of personal credentials: `token` or
    /// `username-token`.
    pub fn personal_profile(self) -> &'static str {
        match self {
            Self::Token => "token",
            Self::UsernameToken => "username-token",
        }
    }
}

/// A declared resource type and the Broker type ID it is registered under.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ImportedResourceTypeDeclaration {
    /// The source's type id, `^[a-z][a-z0-9_]{0,31}$`, which the request's
    /// `resourceType` names.
    pub id: String,
    /// The Broker resource type ID, `^[a-z][a-z0-9_]{0,63}$`; proposed as
    /// `<service>_<id>` and fixed after first acceptance.
    pub broker_type: String,
    pub label: String,
    pub plural_label: String,
    /// Matched against the whole exact selector value.
    pub pattern: String,
    pub max_length: u32,
    pub example: String,
    /// Private, encrypted attributes of resources of this type.
    pub attributes: Vec<ImportedResourceAttributeDeclaration>,
}

/// A declared private attribute. Values are encrypted, at most 8 KiB, shown
/// to administrators by name only and revealed only through the reveal route.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ImportedResourceAttributeDeclaration {
    pub name: String,
    pub label: String,
    pub description: String,
    pub required: bool,
    pub pattern: Option<String>,
}

fn bounded_text(value: &str, max: usize) -> bool {
    !value.is_empty() && value.len() <= max && !value.chars().any(char::is_control)
}

/// The source bound of declared patterns: nonempty and at most 8 KiB. The
/// grammar is the SDK resource pattern's; adapters compile it.
fn pattern_source(value: &str) -> bool {
    !value.is_empty() && value.len() <= 8 * 1024
}

fn identifier(value: &str, max: usize) -> bool {
    let bytes = value.as_bytes();
    (1..=max).contains(&bytes.len())
        && bytes[0].is_ascii_lowercase()
        && bytes
            .iter()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || *b == b'_')
}

impl ImportedServiceMetadata {
    /// Structural bounds the store enforces before writing or after reading
    /// the column. Adapters own the semantic rules of their manifests.
    pub fn validate(&self) -> Result<(), String> {
        if !bounded_text(&self.format, 64) || !bounded_text(&self.version, 64) {
            return Err("import metadata format or version is invalid".into());
        }
        if let Some(credential) = &self.credential {
            let modes = credential.modes.iter().collect::<BTreeSet<_>>();
            if modes.is_empty() || modes.len() != credential.modes.len() {
                return Err("import credential modes must be a nonempty set".into());
            }
        }
        if self.resource_types.len() > IMPORT_MAX_RESOURCE_TYPES {
            return Err("import declares too many resource types".into());
        }
        let mut ids = BTreeSet::new();
        let mut broker_types = BTreeSet::new();
        for declared in &self.resource_types {
            if !identifier(&declared.id, 32)
                || !identifier(&declared.broker_type, 64)
                || !ids.insert(&declared.id)
                || !broker_types.insert(&declared.broker_type)
            {
                return Err("import resource type ids are invalid or duplicated".into());
            }
            if !bounded_text(&declared.label, 64)
                || !bounded_text(&declared.plural_label, 64)
                || !pattern_source(&declared.pattern)
                || declared.example.is_empty()
                || declared.example.len() > declared.max_length as usize
                || !(1..=1024).contains(&declared.max_length)
                || declared.attributes.len() > IMPORT_MAX_RESOURCE_ATTRIBUTES
            {
                return Err("import resource type declaration exceeds limits".into());
            }
            let mut names = BTreeSet::new();
            for attribute in &declared.attributes {
                let name = attribute.name.as_bytes();
                if !(1..=64).contains(&name.len())
                    || !name[0].is_ascii_lowercase()
                    || !name.iter().all(|b| b.is_ascii_alphanumeric() || *b == b'_')
                    || !names.insert(&attribute.name)
                    || !bounded_text(&attribute.label, 64)
                    || attribute.description.len() > 1024
                    || attribute.description.chars().any(char::is_control)
                    || attribute
                        .pattern
                        .as_ref()
                        .is_some_and(|pattern| !pattern_source(pattern))
                {
                    return Err("import resource attribute declaration is invalid".into());
                }
            }
        }
        if serde_json::to_vec(self)
            .map_err(|_| "import metadata cannot be encoded")?
            .len()
            > IMPORT_MAX_METADATA_BYTES
        {
            return Err("import metadata exceeds size limit".into());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn sample() -> ImportedServiceMetadata {
        ImportedServiceMetadata {
            format: "agent-access-command/1".into(),
            version: "1.4.0".into(),
            credential: Some(ImportedCredentialDeclaration {
                kind: ImportedCredentialKind::UsernameToken,
                modes: vec![
                    ImportedCredentialMode::Service,
                    ImportedCredentialMode::PerUser,
                ],
            }),
            verify: true,
            resource_types: vec![ImportedResourceTypeDeclaration {
                id: "project".into(),
                broker_type: "ticketing_project".into(),
                label: "Project".into(),
                plural_label: "Projects".into(),
                pattern: "[A-Z][A-Z0-9]{1,9}".into(),
                max_length: 256,
                example: "OPS".into(),
                attributes: vec![ImportedResourceAttributeDeclaration {
                    name: "region".into(),
                    label: "Region".into(),
                    description: "Hosting region.".into(),
                    required: false,
                    pattern: Some("[a-z0-9-]{1,32}".into()),
                }],
            }],
        }
    }

    #[test]
    fn metadata_round_trips_its_column_encoding_and_checks_bounds() {
        let metadata = sample();
        metadata.validate().unwrap();
        let encoded = serde_json::to_value(&metadata).unwrap();
        assert_eq!(
            encoded,
            json!({"format":"agent-access-command/1","version":"1.4.0",
                "credential":{"kind":"username_token","modes":["service","per_user"]},
                "verify":true,
                "resourceTypes":[{"id":"project","brokerType":"ticketing_project","label":"Project",
                    "pluralLabel":"Projects","pattern":"[A-Z][A-Z0-9]{1,9}","maxLength":256,
                    "example":"OPS","attributes":[{"name":"region","label":"Region",
                    "description":"Hosting region.","required":false,"pattern":"[a-z0-9-]{1,32}"}]}]})
        );
        assert_eq!(
            serde_json::from_value::<ImportedServiceMetadata>(encoded).unwrap(),
            metadata
        );
        let credential_free = ImportedServiceMetadata {
            credential: None,
            ..sample()
        };
        credential_free.validate().unwrap();
        let mut invalid = sample();
        invalid.credential.as_mut().unwrap().modes.clear();
        assert!(invalid.validate().is_err());
        let mut invalid = sample();
        invalid
            .resource_types
            .push(invalid.resource_types[0].clone());
        assert!(invalid.validate().is_err());
        let mut invalid = sample();
        invalid.resource_types[0].broker_type = "Ticketing".into();
        assert!(invalid.validate().is_err());
        let mut invalid = sample();
        invalid.version = String::new();
        assert!(invalid.validate().is_err());
        assert!(
            serde_json::from_value::<ImportedServiceMetadata>(json!({
                "format":"agent-access-command/1","version":"1","credential":null,
                "verify":false,"resourceTypes":[],"extra":true}))
            .is_err()
        );
    }

    #[test]
    fn credential_kinds_map_to_durable_spellings() {
        assert_eq!(
            ImportedCredentialKind::Token.credential_kind(),
            "bearer_token"
        );
        assert_eq!(ImportedCredentialKind::Token.personal_profile(), "token");
        assert_eq!(
            ImportedCredentialKind::UsernameToken.credential_kind(),
            "basic_api_token"
        );
        assert_eq!(
            ImportedCredentialKind::UsernameToken.personal_profile(),
            "username-token"
        );
    }
}
