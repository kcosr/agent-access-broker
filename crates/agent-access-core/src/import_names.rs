//! Stable proposed names. Once accepted, source mappings are immutable records.
use crate::imports::ImportedDiscovery;
use crate::{ImportedActionStatus, ImportedServiceRecord};
use agent_access_provider::is_action_name;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

pub fn assign_imported_action_names(
    record: &ImportedServiceRecord,
    discovery: &mut ImportedDiscovery,
) -> Result<(), String> {
    let existing = record
        .actions
        .iter()
        .filter(|action| action.status != ImportedActionStatus::Retired)
        .map(|action| {
            (
                action.definition.source.to_string(),
                action.definition.action.clone(),
            )
        })
        .collect::<BTreeMap<_, _>>();
    let mut sources = BTreeSet::new();
    let mut proposed = BTreeMap::<String, Vec<usize>>::new();
    for (index, tool) in discovery.tools.iter_mut().enumerate() {
        let source = tool.definition.source.to_string();
        if !sources.insert(source.clone()) {
            return Err("discovery contains duplicate upstream identities".into());
        }
        if let Some(name) = existing.get(&source) {
            tool.definition.action = name.clone();
            continue;
        }
        let raw = tool
            .definition
            .source
            .get("toolName")
            .and_then(serde_json::Value::as_str)
            .unwrap_or(&tool.definition.action);
        let name = normalize(&record.definition.service, raw);
        proposed.entry(name).or_default().push(index);
    }
    let mut reserved = record
        .actions
        .iter()
        .map(|action| action.definition.action.clone())
        .collect::<BTreeSet<_>>();
    // BTree iteration makes normalization collisions independent of server ordering.
    for (name, indices) in proposed {
        let collision = indices.len() > 1 || reserved.contains(&name);
        for index in indices {
            let tool = &mut discovery.tools[index];
            let mut candidate = if collision {
                let hash = format!(
                    "{:x}",
                    Sha256::digest(tool.definition.source.to_string().as_bytes())
                );
                format!("{name}_{hash}")
            } else {
                name.clone()
            };
            // Repeated retirement keeps every earlier identity reserved. Choose a
            // stable free suffix rather than reusing a retired grant target.
            let base = candidate.clone();
            let mut suffix = 2;
            while !reserved.insert(candidate.clone()) {
                candidate = format!("{base}_{suffix}");
                suffix += 1;
            }
            tool.definition.action = candidate;
        }
    }
    Ok(())
}
fn normalize(service: &str, raw: &str) -> String {
    if is_action_name(raw) && raw.len() <= 128 && !raw.starts_with(&format!("{service}.")) {
        return raw.to_owned();
    }
    let mut normalized = String::new();
    for character in raw.chars().flat_map(char::to_lowercase) {
        if normalized.len() >= 96 {
            break;
        }
        let character =
            if character.is_ascii_lowercase() || character.is_ascii_digit() || character == '-' {
                character
            } else {
                '_'
            };
        if character != '_' || !normalized.ends_with('_') {
            normalized.push(character);
        }
    }
    let normalized = normalized.trim_matches('_');
    if normalized.is_empty() {
        "tool".into()
    } else if normalized.as_bytes()[0].is_ascii_lowercase() {
        normalized.into()
    } else {
        format!("tool_{normalized}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::imports::{
        ImportedActionDefinition, ImportedCredentialBinding, ImportedCredentialDelivery,
        ImportedCredentialMode, ImportedDiscoveredTool, ImportedDiscoveryCredential,
        ImportedServiceDefinition,
    };
    use crate::*;
    use serde_json::json;
    fn record() -> ImportedServiceRecord {
        ImportedServiceRecord {
            definition: ImportedServiceDefinition {
                service: "search".into(),
                display_name: "Search".into(),
                adapter_kind: "mcp_http".into(),
                endpoint: "https://tools.example/mcp".into(),
                connection_settings: BTreeMap::new(),
                execution_bindings: vec![ImportedCredentialBinding::token(
                    ImportedCredentialMode::Service,
                    ImportedCredentialDelivery::Bearer,
                )],
                discovery: ImportedDiscoveryCredential::Execution,
                transport_auth: false,
                invocation_limit: None,
            },
            status: ImportedServiceStatus::Draft,
            version: 1,
            actions: vec![],
            slot_versions: BTreeMap::new(),
            accepted_metadata: None,
            created_at: String::new(),
            created_by: String::new(),
            updated_at: String::new(),
            updated_by: String::new(),
        }
    }
    fn discovery(names: &[&str]) -> ImportedDiscovery {
        ImportedDiscovery {
            protocol_version: "fixture".into(),
            metadata: json!({}),
            tools: names
                .iter()
                .map(|name| ImportedDiscoveredTool {
                    definition: ImportedActionDefinition {
                        action: "pending".into(),
                        source: json!({"toolName":name}),
                        label: None,
                        description: String::new(),
                        input_schema: json!({"type":"object"}),
                        output_schema: None,
                        annotations: json!({}),
                        read_only: false,
                    },
                    unsupported_reason: None,
                    read_only_hint: None,
                })
                .collect(),
            service_metadata: None,
            resource_type_changes: Vec::new(),
        }
    }
    #[test]
    fn names_are_stable_across_order_and_preserve_accepted_mappings() {
        let mut record = record();
        let mut first = discovery(&["foo/bar", "foo_bar", "search.query", "9show", "valid.read"]);
        assign_imported_action_names(&record, &mut first).unwrap();
        let mapping = |manifest: &ImportedDiscovery| {
            manifest
                .tools
                .iter()
                .map(|row| {
                    (
                        row.definition.source.to_string(),
                        row.definition.action.clone(),
                    )
                })
                .collect::<BTreeMap<_, _>>()
        };
        let mut reverse = first.clone();
        reverse.tools.reverse();
        assign_imported_action_names(&record, &mut reverse).unwrap();
        assert_eq!(mapping(&first), mapping(&reverse));
        for row in &first.tools {
            row.definition.validate("search").unwrap();
        }
        assert_eq!(first.tools[4].definition.action, "valid.read");
        record.actions.push(ImportedActionRecord {
            definition: ImportedActionDefinition {
                action: "custom".into(),
                ..first.tools[0].definition.clone()
            },
            status: ImportedActionStatus::Enabled,
            version: 1,
            definition_hash: String::new(),
        });
        assign_imported_action_names(&record, &mut reverse).unwrap();
        assert_eq!(
            mapping(&reverse)[&first.tools[0].definition.source.to_string()],
            "custom"
        );
        let mut duplicate = discovery(&["same", "same"]);
        assert!(assign_imported_action_names(&record, &mut duplicate).is_err());
    }
    #[test]
    fn repeated_retirement_proposes_fresh_names_and_live_mapping_wins() {
        let mut record = record();
        let mut observed = discovery(&["query"]);
        for version in 1..=4 {
            assign_imported_action_names(&record, &mut observed).unwrap();
            let proposed = observed.tools[0].definition.clone();
            assert!(
                !record
                    .actions
                    .iter()
                    .any(|old| old.definition.action == proposed.action)
            );
            proposed.validate("search").unwrap();
            record.actions.push(ImportedActionRecord {
                definition: proposed.clone(),
                status: ImportedActionStatus::Enabled,
                version,
                definition_hash: String::new(),
            });
            let mut refreshed = discovery(&["query"]);
            assign_imported_action_names(&record, &mut refreshed).unwrap();
            assert_eq!(refreshed.tools[0].definition.action, proposed.action);
            record.actions.last_mut().unwrap().status = ImportedActionStatus::Retired;
        }
        assert_eq!(
            record
                .actions
                .iter()
                .map(|action| &action.definition.action)
                .collect::<BTreeSet<_>>()
                .len(),
            4
        );
    }
}
