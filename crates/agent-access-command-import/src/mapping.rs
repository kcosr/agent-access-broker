//! Mapping a manifest onto imported definitions: actions with their
//! `annotations.command`, unsupported reasons, the proposed service-level
//! metadata with Broker type IDs, and the OAuth notice.
use crate::manifest::{ActionDeclaration, Manifest, ResourceDeclaration};
use agent_access_core::imports::{
    BoundedImportSchema, COMMAND_FORMAT, ImportedActionAuthority, ImportedActionDefinition,
    ImportedActionResources, ImportedCredentialMode, ImportedDiscoveredTool, ImportedDiscovery,
    ImportedResourceTypeDeclaration, ImportedServiceDefinition, ImportedServiceMetadata,
    credential_admits_bindings,
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

/// The longest Broker type ID.
const MAX_TYPE_ID_BYTES: usize = 64;

/// `<service>_<tail>` with hyphens replaced by underscores, shortening only
/// the service part so the whole tail fits the 64-byte type ID bound.
/// Service names are ASCII and start with a lowercase letter, and a tail is
/// at most 41 bytes, so at least 22 service bytes remain.
fn type_id_with(service: &str, tail: &str) -> String {
    let service = service.replace('-', "_");
    let keep = MAX_TYPE_ID_BYTES
        .saturating_sub(tail.len() + 1)
        .min(service.len());
    format!("{}_{tail}", &service[..keep])
}

/// The stable suffixes that separate a colliding proposal, in the order they
/// are tried: the first eight hex digits of the SHA-256 of the manifest type
/// id, then of `<id>#1`, `<id>#2` and so on.
fn type_id_suffixes(id: &str) -> impl Iterator<Item = String> + '_ {
    use sha2::Digest as _;
    (0u32..).map(move |attempt| {
        let input = match attempt {
            0 => id.to_owned(),
            n => format!("{id}#{n}"),
        };
        sha2::Sha256::digest(input.as_bytes())[..4]
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect()
    })
}

/// Broker type IDs for manifest type ids that have none yet: `<service>_<id>`
/// with only the service part shortened. Every ID the import holds and every
/// proposal that collides with nothing are reserved first; then, in manifest
/// order, each colliding type takes the first `<service>_<id>_<suffix>` from
/// [`type_id_suffixes`] that is still free. All IDs fit 64 bytes and the
/// result is deterministic.
pub(crate) fn proposed_type_ids(service: &str, ids: &[&str], held: &[&str]) -> Vec<String> {
    let base = ids
        .iter()
        .map(|id| type_id_with(service, id))
        .collect::<Vec<_>>();
    let unique = base
        .iter()
        .map(|proposal| {
            !held.contains(&proposal.as_str())
                && base.iter().filter(|other| *other == proposal).count() == 1
        })
        .collect::<Vec<_>>();
    let mut reserved = held
        .iter()
        .map(|id| (*id).to_owned())
        .chain(
            base.iter()
                .zip(&unique)
                .filter(|(_, unique)| **unique)
                .map(|(proposal, _)| proposal.clone()),
        )
        .collect::<std::collections::BTreeSet<_>>();
    ids.iter()
        .zip(base)
        .zip(unique)
        .map(|((id, proposal), unique)| {
            if unique {
                return proposal;
            }
            type_id_suffixes(id)
                .map(|suffix| type_id_with(service, &format!("{id}_{suffix}")))
                .find(|candidate| reserved.insert(candidate.clone()))
                .expect("an unbounded suffix sequence yields a free ID")
        })
        .collect()
}

/// The service-level metadata a manifest proposes. A type already accepted
/// under the same manifest id keeps its Broker type ID; new types get
/// [`proposed_type_ids`] that avoid every ID the import holds.
pub(crate) fn proposed_metadata(
    service: &str,
    manifest: &Manifest,
    accepted: Option<&ImportedServiceMetadata>,
) -> ImportedServiceMetadata {
    let accepted_types = accepted.map_or(&[][..], |accepted| &accepted.resource_types[..]);
    let new_ids = manifest
        .resource_types
        .iter()
        .filter(|declared| {
            !accepted_types
                .iter()
                .any(|existing| existing.id == declared.id)
        })
        .map(|declared| declared.id.as_str())
        .collect::<Vec<_>>();
    let held = accepted_types
        .iter()
        .map(|existing| existing.broker_type.as_str())
        .collect::<Vec<_>>();
    let mut proposals = new_ids
        .iter()
        .copied()
        .zip(proposed_type_ids(service, &new_ids, &held))
        .collect::<std::collections::BTreeMap<_, _>>();
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
                broker_type: accepted_types
                    .iter()
                    .find(|existing| existing.id == declared.id)
                    .map(|existing| existing.broker_type.clone())
                    .or_else(|| proposals.remove(declared.id.as_str()))
                    .unwrap_or_default(),
                removed: false,
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
        resource_type_changes: Vec::new(),
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

/// An accepted action as this adapter executes it: its compiled schemas and
/// its resource and credential declaration.
pub(crate) struct CompiledAction {
    pub read_only: bool,
    pub input: BoundedImportSchema,
    #[expect(
        dead_code,
        reason = "the response contract validates results against it"
    )]
    pub output: Option<BoundedImportSchema>,
    pub authority: ImportedActionAuthority,
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
        let resources = command
            .get("resources")
            .map(|resources| resource_declaration(resources, &definition.input_schema))
            .transpose()?;
        let credential_modes = command
            .get("credentialModes")
            .map(|modes| {
                modes
                    .as_array()
                    .filter(|modes| !modes.is_empty())
                    .and_then(|modes| {
                        modes
                            .iter()
                            .map(|mode| {
                                serde_json::from_value::<ImportedCredentialMode>(mode.clone()).ok()
                            })
                            .collect::<Option<Vec<_>>>()
                    })
                    .ok_or("annotations.command.credentialModes is invalid")
            })
            .transpose()?;
        if definition.input_schema.get("type").and_then(Value::as_str) != Some("object") {
            return Err("command action input schema must describe an object".into());
        }
        let input = BoundedImportSchema::compile(&definition.input_schema)?;
        let output = definition
            .output_schema
            .as_ref()
            .map(BoundedImportSchema::compile)
            .transpose()?;
        Ok(Self {
            read_only: definition.read_only,
            input,
            output,
            authority: ImportedActionAuthority {
                resources: resources.map(|declaration| ImportedActionResources {
                    resource_type: declaration.resource_type,
                    inputs: declaration.inputs,
                }),
                credential_modes,
            },
        })
    }
}

/// `annotations.command.resources`: a declared type and, for a
/// Broker-enforced action, 1–4 pointers to required string or string-array
/// inputs.
fn resource_declaration(
    resources: &Value,
    input_schema: &Value,
) -> Result<ResourceDeclaration, String> {
    let resources = resources
        .as_object()
        .ok_or("annotations.command.resources must be an object")?;
    if resources.keys().any(|key| key != "type" && key != "inputs") {
        return Err("annotations.command.resources has unsupported fields".into());
    }
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
    for pointer in &declaration.inputs {
        crate::manifest::resource_input(input_schema, pointer)?;
    }
    Ok(declaration)
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
        // The view names its project in an input, so the Broker checks it;
        // the search leaves its project type to the command.
        let declared = discovery
            .tools
            .iter()
            .map(|tool| CompiledAction::new(&tool.definition).unwrap().authority)
            .collect::<Vec<_>>();
        let both = Some(vec![
            ImportedCredentialMode::Service,
            ImportedCredentialMode::PerUser,
        ]);
        assert_eq!(
            declared,
            [
                ImportedActionAuthority {
                    resources: Some(ImportedActionResources {
                        resource_type: "project".into(),
                        inputs: vec!["/project".into()],
                    }),
                    credential_modes: both.clone(),
                },
                ImportedActionAuthority {
                    resources: Some(ImportedActionResources {
                        resource_type: "project".into(),
                        inputs: Vec::new(),
                    }),
                    credential_modes: both,
                },
            ]
        );
        assert!(declared[0].resources.as_ref().unwrap().broker_enforced());
        assert!(!declared[1].resources.as_ref().unwrap().broker_enforced());
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
    fn proposed_type_ids_are_distinct_and_keep_the_type_id_whole() {
        let service = format!("{}-qx", "a".repeat(60));
        assert_eq!(service.len(), 63);
        let mut value = crate::manifest::tests::sample();
        let template = value["resourceTypes"][0].clone();
        value["resourceTypes"] = json!(
            [
                "project_alpha_component_one",
                "project_alpha_component_two",
                "q_r",
                "r"
            ]
            .iter()
            .map(|id| {
                let mut declared = template.clone();
                declared["id"] = json!(id);
                declared
            })
            .collect::<Vec<_>>()
        );
        value["actions"] = json!([]);
        let manifest = parse(&serde_json::to_vec(&value).unwrap()).unwrap();
        let proposed = proposed_metadata(&service, &manifest, None);
        let ids = proposed
            .resource_types
            .iter()
            .map(|declared| declared.broker_type.clone())
            .collect::<Vec<_>>();
        assert_eq!(
            ids.iter().collect::<std::collections::BTreeSet<_>>().len(),
            ids.len(),
            "{ids:?}"
        );
        for (declared, id) in proposed.resource_types.iter().zip(&ids) {
            assert!(id.len() <= 64, "{id}");
            assert!(id.as_bytes()[0].is_ascii_lowercase(), "{id}");
            assert!(
                id.bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_'),
                "{id}"
            );
            assert!(id.contains(&format!("_{}", declared.id)), "{id}");
        }
        // Distinct long ids keep their whole id with a shortened service part.
        assert_eq!(
            ids[0],
            format!("{}_project_alpha_component_one", "a".repeat(36))
        );
        assert_eq!(
            ids[1],
            format!("{}_project_alpha_component_two", "a".repeat(36))
        );
        // `q_r` and `r` would both become `<60 a>_q_r`; each gets a stable suffix.
        assert_ne!(ids[2], format!("{}_q_r", "a".repeat(60)));
        assert_ne!(ids[3], format!("{}_q_r", "a".repeat(60)));
        assert!(ids[2].ends_with(&format!("_q_r_{}", type_id_suffix("q_r"))));
        assert!(ids[3].ends_with(&format!("_r_{}", type_id_suffix("r"))));
        proposed.validate().unwrap();
        // Proposals are deterministic, and avoid IDs the import already holds.
        assert_eq!(proposed_metadata(&service, &manifest, None), proposed);
        let mut accepted = proposed.clone();
        accepted.resource_types.truncate(1);
        accepted.resource_types[0].id = "retired".into();
        accepted.resource_types[0].broker_type = ids[1].clone();
        let refreshed = proposed_metadata(&service, &manifest, Some(&accepted));
        assert_ne!(refreshed.resource_types[1].broker_type, ids[1]);
        assert!(
            refreshed.resource_types[1]
                .broker_type
                .ends_with(&type_id_suffix("project_alpha_component_two"))
        );
    }

    /// The first suffix tried for `id`.
    fn type_id_suffix(id: &str) -> String {
        type_id_suffixes(id).next().unwrap()
    }

    fn manifest_with_types(ids: &[&str]) -> Manifest {
        let mut value = crate::manifest::tests::sample();
        let template = value["resourceTypes"][0].clone();
        value["resourceTypes"] = json!(
            ids.iter()
                .map(|id| {
                    let mut declared = template.clone();
                    declared["id"] = json!(id);
                    declared
                })
                .collect::<Vec<_>>()
        );
        value["actions"] = json!([]);
        parse(&serde_json::to_vec(&value).unwrap()).unwrap()
    }

    fn assert_distinct_type_ids(ids: &[String]) {
        assert_eq!(
            ids.iter().collect::<std::collections::BTreeSet<_>>().len(),
            ids.len(),
            "{ids:?}"
        );
        for id in ids {
            assert!(
                id.len() <= 64 && id.as_bytes()[0].is_ascii_lowercase(),
                "{id}"
            );
        }
    }

    #[test]
    fn suffixed_type_ids_avoid_other_proposals_and_held_ids() {
        let service = format!("{}-qx", "a".repeat(60));
        assert_eq!(type_id_suffix("q_r"), "9666ac00");
        // `q_r` and `r` collide, and `q_r`'s first suffixed candidate is the
        // third type's own proposal, which it keeps.
        let types = ["q_r", "r", "q_r_9666ac00"];
        let ids = proposed_type_ids(&service, &types, &[]);
        assert_distinct_type_ids(&ids);
        assert_eq!(ids[2], type_id_with(&service, "q_r_9666ac00"));
        assert_eq!(proposed_type_ids(&service, &types, &[]), ids);
        let proposed = proposed_metadata(&service, &manifest_with_types(&types), None);
        proposed.validate().unwrap();
        assert_eq!(
            proposed
                .resource_types
                .iter()
                .map(|declared| declared.broker_type.clone())
                .collect::<Vec<_>>(),
            ids
        );
        // A suffixed candidate the import already holds is skipped too.
        let held = type_id_with(&service, &format!("q_r_{}", type_id_suffix("q_r")));
        let ids = proposed_type_ids(&service, &["q_r", "r"], &[&held]);
        assert_distinct_type_ids(&ids);
        assert!(!ids.contains(&held), "{ids:?}");
        assert_eq!(proposed_type_ids(&service, &["q_r", "r"], &[&held]), ids);
    }

    #[test]
    fn proposed_type_ids_fit_the_type_id_bound() {
        assert_eq!(
            proposed_type_ids("ticket-ops", &["project"], &[]),
            ["ticket_ops_project"]
        );
        assert_eq!(
            proposed_type_ids(&"s".repeat(63), &["project"], &[]),
            [format!("{}_project", "s".repeat(56))]
        );
        let id = "i".repeat(32);
        let [suffixed] = proposed_type_ids(
            &"s".repeat(63),
            &[&id],
            &[&format!("{}_{id}", "s".repeat(31))],
        )
        .try_into()
        .unwrap();
        assert_eq!(suffixed.len(), 64);
        assert_eq!(
            suffixed,
            format!("{}_{id}_{}", "s".repeat(22), type_id_suffix(&id))
        );
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
