//! Mapping a manifest onto imported definitions: actions with their
//! `annotations.command`, unsupported reasons, the proposed service-level
//! metadata with Broker type IDs, and the OAuth notice.
use crate::manifest::{ActionDeclaration, Manifest, ResourceDeclaration};
use agent_access_core::imports::{
    BoundedImportSchema, COMMAND_FORMAT, ImportedActionDefinition, ImportedCredentialMode,
    ImportedDiscoveredTool, ImportedDiscovery, ImportedResourceTypeDeclaration,
    ImportedServiceDefinition, ImportedServiceMetadata, credential_admits_bindings,
};
use serde_json::{Map, Value, json};

/// Shown in the preview when a manifest declares phase-2 OAuth.
pub(crate) const OAUTH_NOTICE: &str = "This command declares OAuth, which this Broker does not support yet; static credentials still work.";

/// `annotations.command`: the action's resource declaration and credential
/// modes. Discovery's behavioral diff compares annotations, so a change to
/// either quarantines the accepted action.
pub(crate) fn command_annotations(declaration: &ActionDeclaration) -> Value {
    let mut command = Map::new();
    if let Some(resources) = &declaration.resources {
        let mut value = json!({"type": resources.resource_type});
        if !resources.inputs.is_empty() {
            value["inputs"] = json!(resources.inputs);
        }
        command.insert("resources".into(), value);
    }
    if !declaration.credential_modes.is_empty() {
        command.insert(
            "credentialModes".into(),
            json!(
                declaration
                    .credential_modes
                    .iter()
                    .map(|mode| mode.as_str())
                    .collect::<Vec<_>>()
            ),
        );
    }
    json!({"command": command})
}

/// The Broker type ID proposed for a manifest type: `<service>_<id>`, hyphens
/// replaced by underscores, within the 64-byte type ID bound.
pub(crate) fn proposed_type_id(service: &str, id: &str) -> String {
    let mut proposed = format!("{service}_{id}").replace('-', "_");
    proposed.truncate(64);
    proposed.trim_end_matches('_').to_owned()
}

/// The service-level metadata a manifest proposes. A type already accepted
/// under the same manifest id keeps its Broker type ID.
pub(crate) fn proposed_metadata(
    service: &str,
    manifest: &Manifest,
    accepted: Option<&ImportedServiceMetadata>,
) -> ImportedServiceMetadata {
    ImportedServiceMetadata {
        format: COMMAND_FORMAT.into(),
        version: manifest.version.clone(),
        credential: manifest.credential.clone(),
        verify: manifest.verify,
        resource_types: manifest
            .resource_types
            .iter()
            .map(|declared| ImportedResourceTypeDeclaration {
                id: declared.id.clone(),
                broker_type: accepted
                    .and_then(|accepted| {
                        accepted
                            .resource_types
                            .iter()
                            .find(|existing| existing.id == declared.id)
                    })
                    .map_or_else(
                        || proposed_type_id(service, &declared.id),
                        |existing| existing.broker_type.clone(),
                    ),
                label: declared.label.clone(),
                plural_label: declared.plural_label.clone(),
                pattern: declared.pattern.clone(),
                max_length: declared.max_length,
                example: declared.example.clone(),
                attributes: declared.attributes.clone(),
            })
            .collect(),
    }
}

/// The import's credential shape must match the manifest's: a command
/// without a credential has no execution bindings, and a credentialed one
/// binds only declared modes. An accepted declaration never changes.
pub(crate) fn check_credential(
    definition: &ImportedServiceDefinition,
    manifest: &Manifest,
    accepted: Option<&ImportedServiceMetadata>,
) -> Result<(), String> {
    if let Some(accepted) = accepted
        && accepted.credential != manifest.credential
    {
        return Err(
            "the command added, removed or changed its credential declaration; create a new import for it"
                .into(),
        );
    }
    credential_admits_bindings(manifest.credential.as_ref(), definition)
}

/// The discovered tools and metadata of a validated manifest.
pub(crate) fn discovery(
    definition: &ImportedServiceDefinition,
    command: &str,
    manifest: &Manifest,
    accepted: Option<&ImportedServiceMetadata>,
) -> Result<ImportedDiscovery, String> {
    let bound = definition
        .execution_bindings
        .iter()
        .map(|binding| binding.owner_mode)
        .collect::<Vec<_>>();
    let tools = manifest
        .actions
        .iter()
        .map(|action| {
            let (definition, unsupported_reason) = match &action.declaration {
                Ok(declaration) => {
                    let definition = action_definition(&action.name, declaration);
                    let reason = supported(&definition, declaration, &bound).err();
                    (definition, reason)
                }
                Err(reason) => (
                    ImportedActionDefinition {
                        action: action.name.clone(),
                        source: json!({"name": action.name}),
                        label: None,
                        description: String::new(),
                        input_schema: json!({"type": "object"}),
                        output_schema: None,
                        annotations: json!({"command": {}}),
                        read_only: false,
                    },
                    Some(reason.clone()),
                ),
            };
            ImportedDiscoveredTool {
                definition,
                unsupported_reason,
                read_only_hint: action.read_only_hint,
            }
        })
        .collect();
    let mut metadata = json!({
        "adapterKind": "command",
        "command": command,
        "commandVersion": manifest.version,
    });
    if manifest.oauth_declared {
        metadata["notices"] = json!([OAUTH_NOTICE]);
    }
    let service_metadata = proposed_metadata(&definition.service, manifest, accepted);
    service_metadata.validate()?;
    Ok(ImportedDiscovery {
        protocol_version: COMMAND_FORMAT.into(),
        metadata,
        tools,
        service_metadata: Some(service_metadata),
    })
}

fn action_definition(name: &str, declaration: &ActionDeclaration) -> ImportedActionDefinition {
    ImportedActionDefinition {
        action: name.to_owned(),
        source: json!({"name": name}),
        label: None,
        description: declaration.description.clone(),
        input_schema: declaration.input_schema.clone(),
        output_schema: declaration.output_schema.clone(),
        annotations: command_annotations(declaration),
        // The administrator classifies; `readOnly` is only a hint.
        read_only: false,
    }
}

fn supported(
    definition: &ImportedActionDefinition,
    declaration: &ActionDeclaration,
    bound: &[ImportedCredentialMode],
) -> Result<(), String> {
    if !bound.is_empty()
        && !declaration
            .credential_modes
            .iter()
            .any(|mode| bound.contains(mode))
    {
        return Err("none of the action's credential modes is configured for this import".into());
    }
    CompiledAction::new(definition).map(|_| ())
}

/// An accepted action as this adapter executes it: its manifest name and
/// compiled schemas.
pub(crate) struct CompiledAction {
    pub read_only: bool,
    #[expect(
        dead_code,
        reason = "the response contract validates results against it"
    )]
    pub output: Option<BoundedImportSchema>,
}

impl CompiledAction {
    /// Checks an accepted or proposed definition offline: the `{name}` source,
    /// `annotations.command`, and both schemas in the import profile.
    pub(crate) fn new(definition: &ImportedActionDefinition) -> Result<Self, String> {
        source_name(definition)?;
        let command = definition
            .annotations
            .as_object()
            .filter(|annotations| annotations.len() == 1)
            .and_then(|annotations| annotations.get("command"))
            .and_then(Value::as_object)
            .ok_or("command action annotations must hold only annotations.command")?;
        if command
            .keys()
            .any(|key| key != "resources" && key != "credentialModes")
        {
            return Err("annotations.command has unsupported fields".into());
        }
        if let Some(resources) = command.get("resources") {
            let resources = resources
                .as_object()
                .ok_or("annotations.command.resources must be an object")?;
            let declaration = ResourceDeclaration {
                resource_type: resources
                    .get("type")
                    .and_then(Value::as_str)
                    .ok_or("annotations.command.resources.type is required")?
                    .to_owned(),
                inputs: match resources.get("inputs") {
                    None => Vec::new(),
                    Some(inputs) => inputs
                        .as_array()
                        .filter(|inputs| (1..=4).contains(&inputs.len()))
                        .ok_or("annotations.command.resources.inputs is invalid")?
                        .iter()
                        .map(|input| input.as_str().map(str::to_owned))
                        .collect::<Option<Vec<_>>>()
                        .ok_or("annotations.command.resources.inputs is invalid")?,
                },
            };
            if resources.keys().any(|key| key != "type" && key != "inputs") {
                return Err("annotations.command.resources has unsupported fields".into());
            }
            for pointer in &declaration.inputs {
                crate::manifest::resource_input(&definition.input_schema, pointer)?;
            }
        }
        if let Some(modes) = command.get("credentialModes")
            && !modes.as_array().is_some_and(|modes| {
                !modes.is_empty()
                    && modes
                        .iter()
                        .all(|mode| matches!(mode.as_str(), Some("service" | "per_user")))
            })
        {
            return Err("annotations.command.credentialModes is invalid".into());
        }
        if definition.input_schema.get("type").and_then(Value::as_str) != Some("object") {
            return Err("command action input schema must describe an object".into());
        }
        BoundedImportSchema::compile(&definition.input_schema)?;
        let output = definition
            .output_schema
            .as_ref()
            .map(BoundedImportSchema::compile)
            .transpose()?;
        Ok(Self {
            read_only: definition.read_only,
            output,
        })
    }
}

/// The manifest name of a `{"name": ...}` source.
pub(crate) fn source_name(definition: &ImportedActionDefinition) -> Result<&str, String> {
    definition
        .source
        .as_object()
        .filter(|source| source.len() == 1)
        .and_then(|source| source.get("name"))
        .and_then(Value::as_str)
        .filter(|name| !name.is_empty() && name.len() <= 256 && !name.chars().any(char::is_control))
        .ok_or_else(|| "command action source must be {\"name\": <manifest name>}".into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manifest::parse;
    use agent_access_core::imports::{
        ImportedCredentialBinding, ImportedCredentialDelivery, ImportedCredentialKind,
        ImportedDiscoveryCredential,
    };
    use std::collections::BTreeMap;

    fn definition(modes: &[ImportedCredentialMode]) -> ImportedServiceDefinition {
        ImportedServiceDefinition {
            service: "ticketing".into(),
            display_name: "Ticketing".into(),
            adapter_kind: "command".into(),
            endpoint: "command:ticketing".into(),
            connection_settings: BTreeMap::new(),
            execution_bindings: modes
                .iter()
                .map(|mode| {
                    ImportedCredentialBinding::token(*mode, ImportedCredentialDelivery::Stdin)
                })
                .collect(),
            discovery: ImportedDiscoveryCredential::Anonymous,
            transport_auth: false,
            invocation_limit: None,
        }
    }

    fn sample() -> Manifest {
        parse(&serde_json::to_vec(&crate::manifest::tests::sample()).unwrap()).unwrap()
    }

    #[test]
    fn actions_map_with_command_annotations_and_proposed_metadata() {
        let definition = definition(&[
            ImportedCredentialMode::Service,
            ImportedCredentialMode::PerUser,
        ]);
        let manifest = sample();
        check_credential(&definition, &manifest, None).unwrap();
        let discovery = discovery(&definition, "ticketing", &manifest, None).unwrap();
        assert_eq!(discovery.protocol_version, "agent-access-command/1");
        assert_eq!(discovery.metadata["command"], "ticketing");
        assert_eq!(discovery.metadata["commandVersion"], "1.4.0");
        assert!(discovery.metadata.get("notices").is_none());
        let view = &discovery.tools[0];
        assert!(view.unsupported_reason.is_none(), "{view:?}");
        assert_eq!(view.read_only_hint, Some(true));
        assert!(!view.definition.read_only);
        assert_eq!(view.definition.source, json!({"name": "issue.view"}));
        assert_eq!(view.definition.action, "issue.view");
        assert_eq!(
            view.definition.annotations,
            json!({"command": {"resources": {"type": "project", "inputs": ["/project"]},
                "credentialModes": ["service", "per_user"]}})
        );
        assert_eq!(
            discovery.tools[1].definition.annotations,
            json!({"command": {"resources": {"type": "project"},
                "credentialModes": ["service", "per_user"]}})
        );
        let metadata = discovery.service_metadata.clone().unwrap();
        assert_eq!(metadata.version, "1.4.0");
        assert!(metadata.verify);
        assert_eq!(
            metadata.credential.as_ref().unwrap().kind,
            ImportedCredentialKind::UsernameToken
        );
        assert_eq!(metadata.resource_types[0].broker_type, "ticketing_project");
        assert_eq!(metadata.resource_types[0].attributes.len(), 2);
        for tool in &discovery.tools {
            CompiledAction::new(&tool.definition).unwrap();
        }
        // An accepted type keeps its Broker type ID across refreshes.
        let mut accepted = metadata.clone();
        accepted.resource_types[0].broker_type = "tickets".into();
        let refreshed = super::discovery(&definition, "ticketing", &manifest, Some(&accepted))
            .unwrap()
            .service_metadata
            .unwrap();
        assert_eq!(refreshed.resource_types[0].broker_type, "tickets");
    }

    #[test]
    fn proposed_type_ids_fit_the_type_id_bound() {
        assert_eq!(
            proposed_type_id("ticket-ops", "project"),
            "ticket_ops_project"
        );
        let long = proposed_type_id(&"s".repeat(60), "project");
        assert_eq!(long, format!("{}_pro", "s".repeat(60)));
        assert_eq!(proposed_type_id(&"s".repeat(63), "project"), "s".repeat(63));
        assert_eq!(proposed_type_id(&"s".repeat(63), "_x"), "s".repeat(63));
    }

    #[test]
    fn credential_shapes_must_match_the_import() {
        let manifest = sample();
        for modes in [
            vec![],
            vec![ImportedCredentialMode::Service],
            vec![ImportedCredentialMode::PerUser],
        ] {
            let result = check_credential(&definition(&modes), &manifest, None);
            assert_eq!(result.is_ok(), !modes.is_empty(), "{modes:?}");
        }
        let mut service_only = sample();
        service_only.credential.as_mut().unwrap().modes = vec![ImportedCredentialMode::Service];
        assert!(
            check_credential(
                &definition(&[ImportedCredentialMode::PerUser]),
                &service_only,
                None
            )
            .unwrap_err()
            .contains("only the credential modes service")
        );
        let mut credential_free = sample();
        credential_free.credential = None;
        check_credential(&definition(&[]), &credential_free, None).unwrap();
        assert!(
            check_credential(
                &definition(&[ImportedCredentialMode::Service]),
                &credential_free,
                None
            )
            .is_err()
        );
        // Adding, removing or changing an accepted credential fails.
        let accepted = proposed_metadata("ticketing", &manifest, None);
        let both = definition(&[ImportedCredentialMode::Service]);
        check_credential(&both, &manifest, Some(&accepted)).unwrap();
        for changed in [
            {
                let mut changed = sample();
                changed.credential.as_mut().unwrap().kind = ImportedCredentialKind::Token;
                changed
            },
            {
                let mut changed = sample();
                changed.credential.as_mut().unwrap().modes = vec![ImportedCredentialMode::Service];
                changed
            },
            credential_free,
        ] {
            assert!(
                check_credential(&both, &changed, Some(&accepted))
                    .unwrap_err()
                    .contains("create a new import")
            );
        }
    }

    #[test]
    fn unconfigured_modes_and_invalid_actions_are_unsupported_and_oauth_is_noted() {
        let mut value = crate::manifest::tests::sample();
        value["actions"][0]["credentialModes"] = json!(["per_user"]);
        value["actions"][1]["outputSchema"] = json!({"$dynamicRef": "#x"});
        value["oauth"] = json!({"issuer": "https://login.example.net"});
        let manifest = parse(&serde_json::to_vec(&value).unwrap()).unwrap();
        let discovery = discovery(
            &definition(&[ImportedCredentialMode::Service]),
            "ticketing",
            &manifest,
            None,
        )
        .unwrap();
        assert!(
            discovery.tools[0]
                .unsupported_reason
                .as_ref()
                .unwrap()
                .contains("credential modes")
        );
        assert!(
            discovery.tools[1]
                .unsupported_reason
                .as_ref()
                .unwrap()
                .contains("outputSchema")
        );
        assert_eq!(
            discovery.tools[1].definition.source,
            json!({"name": "issue.search"})
        );
        assert_eq!(discovery.metadata["notices"], json!([OAUTH_NOTICE]));
    }

    #[test]
    fn accepted_definitions_are_checked_offline() {
        let manifest = sample();
        let discovery = discovery(
            &definition(&[ImportedCredentialMode::Service]),
            "ticketing",
            &manifest,
            None,
        )
        .unwrap();
        let accepted = discovery.tools[0].definition.clone();
        CompiledAction::new(&accepted).unwrap();
        for corrupt in [
            json!({"toolName": "issue.view"}),
            json!({"name": "issue.view", "extra": 1}),
            json!({"name": ""}),
        ] {
            let mut definition = accepted.clone();
            definition.source = corrupt;
            assert!(CompiledAction::new(&definition).is_err());
        }
        for annotations in [
            json!({}),
            json!({"command": {}, "toolAnnotations": {}}),
            json!({"command": {"resources": {"type": "project", "inputs": ["/issue"]}}}),
            json!({"command": {"credentialModes": []}}),
            json!({"command": {"extra": true}}),
        ] {
            let mut definition = accepted.clone();
            definition.annotations = annotations;
            assert!(CompiledAction::new(&definition).is_err());
        }
    }
}
