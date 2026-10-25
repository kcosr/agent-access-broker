use super::*;
use agent_access_core::imports::{ImportedAdapter, ImportedDiscoveryCredential};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

fn rules() -> Value {
    json!([
        {"key":"query", "label":"Requested query", "pointer":"/query",
         "display":"primary", "role":"fact", "kind":"query", "capture":"value",
         "shape":"scalar", "maxBytes":4096, "overflow":"prefix"},
        {"key":"body", "label":"Body supplied", "pointer":"/body", "display":"detail",
         "role":"change", "kind":"boolean", "capture":"presence"},
        {"key":"secret", "pointer":"/secret", "capture":"omit"}
    ])
}

fn source(audit_inputs: Option<Value>) -> Value {
    let mut action = json!({"name":"issue.search", "description":"Search synthetic issues.",
        "readOnly":true, "inputSchema":{"type":"object", "properties":{
            "query":{"type":"string", "pattern":"^accepted$"},
            "body":{"type":"string"}, "other":{"type":"string"},
            "secret":{"type":"string", "x-agent-access-sensitive":true}},
            "additionalProperties":false}});
    if let Some(rules) = audit_inputs {
        action["auditInputs"] = rules;
    }
    json!({"format":"agent-access-command/1", "version":"1.0.0", "actions":[action]})
}

fn discover(source: Value) -> ImportedDiscovery {
    let manifest = crate::manifest::parse(&serde_json::to_vec(&source).unwrap()).unwrap();
    discovery(
        &ImportedServiceDefinition {
            service: "ticketing".into(),
            display_name: "Ticketing".into(),
            adapter_kind: "command".into(),
            endpoint: "command:ticketing".into(),
            connection_settings: BTreeMap::new(),
            execution_bindings: Vec::new(),
            discovery: ImportedDiscoveryCredential::Anonymous,
            transport_auth: false,
            invocation_limit: None,
        },
        "ticketing",
        &manifest,
        None,
        false,
    )
    .unwrap()
}

fn hash(value: &impl serde::Serialize) -> String {
    format!("{:x}", Sha256::digest(serde_json::to_vec(value).unwrap()))
}

#[test]
fn canonical_declaration_round_trips_through_manifest_annotation_and_adapter_hook() {
    let discovered = discover(source(Some(rules())));
    let action = &discovered.tools[0];
    assert!(action.unsupported_reason.is_none(), "{action:?}");
    assert_eq!(
        action.definition.annotations,
        json!({"command":{"auditInputs":rules()}})
    );
    let persisted = serde_json::to_vec(&action.definition).unwrap();
    assert_eq!(
        std::str::from_utf8(&persisted).unwrap(),
        include_str!("fixtures/audit-inputs-action.json").trim_end()
    );
    assert_eq!(
        hash(&action.definition),
        "97d0206c88754517fdb006a267bb616b1824facbfc8746097b3c7b550d84da96"
    );
    let restored: ImportedActionDefinition = serde_json::from_slice(&persisted).unwrap();
    crate::CommandAdapter.validate_action(&restored).unwrap();
    let projection = crate::CommandAdapter
        .action_audit_inputs(&restored)
        .unwrap()
        .unwrap();
    assert_eq!(serde_json::to_value(&projection).unwrap(), rules());
    assert_eq!(serde_json::to_vec(&restored).unwrap(), persisted);
    let plan =
        agent_access_provider::host::prepare_audit_inputs(&restored.input_schema, &projection)
            .unwrap();
    let record = serde_json::to_value(
        plan.project(&json!({"query":"requested-pattern-invalid",
        "body":"BODY_CANARY", "secret":"SECRET_CANARY"}))
            .unwrap(),
    )
    .unwrap();
    let text = record.to_string();
    assert!(text.contains("requested-pattern-invalid"), "{record}");
    assert!(!text.contains("BODY_CANARY"));
    assert!(!text.contains("SECRET_CANARY"));
}

#[test]
fn omitted_declaration_keeps_historical_annotation_and_hook_absence() {
    let discovered = discover(source(None));
    let definition = &discovered.tools[0].definition;
    assert_eq!(definition.annotations, json!({"command":{}}));
    assert_eq!(
        serde_json::to_string(definition).unwrap(),
        include_str!("fixtures/no-audit-inputs-action.json").trim_end()
    );
    assert_eq!(
        hash(definition),
        "209de2145babe2fe45661e925c22b7153267d382c2fc4a3c889ab7d9f130e4e7"
    );
    assert!(
        !serde_json::to_string(definition)
            .unwrap()
            .contains("auditInputs")
    );
    assert!(
        crate::CommandAdapter
            .action_audit_inputs(definition)
            .unwrap()
            .is_none()
    );
    assert!(
        CompiledAction::new(definition)
            .unwrap()
            .audit_inputs
            .is_none()
    );
}

#[test]
fn every_rule_change_participates_in_definition_and_manifest_hashing() {
    let initial = discover(source(Some(rules())));
    let initial_definition_hash = hash(&initial.tools[0].definition);
    let initial_manifest_hash = hash(&initial);
    let changes = [
        ("key", json!("requested_query")),
        ("label", json!("A revised label")),
        ("display", json!("detail")),
        ("role", json!("target")),
        ("pointer", json!("/other")),
        ("kind", json!("text")),
        ("maxBytes", json!(1024)),
        ("overflow", json!("omit")),
        ("shape", json!("list")),
    ];
    for (field, value) in changes {
        let mut changed = rules();
        changed[0][field] = value;
        let changed = discover(source(Some(changed)));
        assert!(
            changed.tools[0].unsupported_reason.is_none(),
            "{field}: {changed:?}"
        );
        assert_ne!(
            hash(&changed.tools[0].definition),
            initial_definition_hash,
            "{field}"
        );
        assert_ne!(hash(&changed), initial_manifest_hash, "{field}");
    }
    let mut reordered = rules();
    reordered.as_array_mut().unwrap().reverse();
    for changed in [
        Some(reordered),
        None,
        Some(json!([{"key":"query","pointer":"/query","capture":"omit"}])),
    ] {
        let changed = discover(source(changed));
        assert_ne!(hash(&changed.tools[0].definition), initial_definition_hash);
        assert_ne!(hash(&changed), initial_manifest_hash);
    }
    // JSON object member order does not change canonical typed metadata.
    assert_eq!(
        hash(&discover(source(Some(
            serde_json::from_str(&rules().to_string()).unwrap()
        )))),
        initial_manifest_hash
    );
}

#[test]
fn malformed_or_sensitive_declarations_are_unsupported_and_stored_metadata_fails_closed() {
    let base = discover(source(Some(rules()))).tools.remove(0).definition;
    let mut invalid = vec![
        Value::Null,
        json!({"rules":rules()}),
        json!([]),
        json!("METADATA_CANARY"),
    ];
    for (field, value) in [
        ("unknown", json!("METADATA_CANARY")),
        ("capture", json!("METADATA_CANARY")),
        ("shape", Value::Null),
        ("pointer", json!("/secret")),
        ("pointer", json!("/credentials/service/token")),
        ("pointer", json!("/authorization/resources/attributes")),
        ("pointer", json!("/result")),
    ] {
        let mut changed = json!([rules()[0].clone()]);
        changed[0][field] = value;
        invalid.push(changed);
    }
    for invalid in invalid {
        let discovered = discover(source(Some(invalid.clone())));
        let reason = discovered.tools[0].unsupported_reason.as_ref().unwrap();
        assert!(reason.contains("auditInputs"));
        assert!(!reason.contains("METADATA_CANARY"));
        let mut accepted = base.clone();
        accepted.annotations["command"]["auditInputs"] = invalid;
        for result in [
            crate::CommandAdapter.validate_action(&accepted),
            crate::CommandAdapter
                .action_audit_inputs(&accepted)
                .map(|_| ()),
        ] {
            assert!(result.is_err());
            assert!(!result.unwrap_err().contains("METADATA_CANARY"));
        }
    }
}
