//! Shared identity and transport helpers for the two native search smoke suites.
use agent_access_broker_host::test_support::{IsolatedBroker, RunningBroker};
use agent_access_core::{
    BrokerTokenClass, BrokerTokenHasher, BrokerTokenIssueRequest, BrokerTokensConfig,
    ManagedResourceCatalog, ManagedStore, ManagedStoreConfig, ManagedStoreOpenMode, PrincipalRole,
    PrincipalWriteRequest,
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::process::Command;

#[derive(Clone, Copy)]
pub enum GrantShape {
    Finite,
    AllExcept,
}

pub struct Tokens {
    pub unrestricted: String,
    pub narrowed: String,
    pub disjoint: String,
    pub ungranted: String,
}

/// The upstream credential can see everything. Policy grants authorize either
/// the first two keys or all except PRIVATE; token restrictions are independent.
pub fn configure(
    application: &IsolatedBroker,
    document: &mut toml::Value,
    service: &str,
    resource_type: &str,
    keys: [&str; 2],
    actions: &[&str],
    shape: GrantShape,
) -> Tokens {
    let directory = application.directory();
    let key = directory
        .secret_file("search-token-key", URL_SAFE_NO_PAD.encode([41_u8; 32]))
        .unwrap();
    let store_config = ManagedStoreConfig {
        kind: "sqlite".into(),
        path: directory.join("search-tokens.sqlite").display().to_string(),
        auto_migrate: true,
        require_registered_principal_for_invocation: true,
    };
    let table = document.as_table_mut().unwrap();
    for (name, value) in [
        (
            "identity",
            json!({
                "mode":"required", "authority":"managed",
                "sources":[{"name":"broker", "type":"broker_tokens", "header":"Authorization", "scheme":"Bearer"}]
            }),
        ),
        (
            "managed_store",
            json!({"type":"sqlite", "path":store_config.path, "auto_migrate":true, "require_registered_principal_for_invocation":true}),
        ),
        (
            "broker_tokens",
            json!({"hash_key_ref":format!("file:{}",key.display())}),
        ),
        (
            "credential_encryption",
            json!({"active_key":"fixture", "keys":[{"id":"fixture","provider":"file","path":key.display().to_string()}]}),
        ),
        (
            "execution_context",
            json!({"allowed_values":["default"],"default_context":"default"}),
        ),
    ] {
        table.insert(name.into(), toml::Value::try_from(value).unwrap());
    }
    // No search filter operand may trigger a resource metadata lookup.
    document["credentials"]
        .as_table_mut()
        .unwrap()
        .remove("lookup");
    let selectors = [
        ("first", json!({"kind":"exact","value":keys[0]})),
        ("second", json!({"kind":"exact","value":keys[1]})),
        ("private", json!({"kind":"exact","value":"PRIVATE"})),
        ("all", json!({"kind":"all"})),
    ];
    document["policy"]["resources"] = toml::Value::try_from(
        selectors
            .iter()
            .map(|(id, selector)| {
                json!({
                    "id":id,"resource_type":resource_type,"selector":selector,
                    "allowed_execution_contexts":["default"]
                })
            })
            .collect::<Vec<_>>(),
    )
    .unwrap();
    document["policy"].as_table_mut().unwrap().insert(
        "resource_groups".into(),
        toml::Value::try_from(json!([{
            "id":"except-private", "name":"All except private",
            "included_resource_ids":["all"], "excluded_resource_ids":["private"]
        }]))
        .unwrap(),
    );
    let selection = match shape {
        GrantShape::Finite => json!({"resource_ids":["first","second"]}),
        GrantShape::AllExcept => json!({"resource_group_ids":["except-private"]}),
    };
    document["policy"]["grants"] = toml::Value::try_from(json!([{
        "subjects":["user:search-user"], "service":service, "actions":actions,
        "resources":selection, "credential_mode":"service", "execution_contexts":["default"]
    }]))
    .unwrap();
    let catalog: ManagedResourceCatalog = serde_json::from_value(json!({
        "resources":selectors.iter().map(|(id,selector)|json!({
            "id":id,"resourceType":resource_type,"selector":selector,
            "allowedExecutionContexts":["default"],"enabled":true
        })).collect::<Vec<_>>(),
        "resourceGroups":[]
    }))
    .unwrap();
    let store = ManagedStore::open(&store_config, ManagedStoreOpenMode::Startup).unwrap();
    for principal in ["search-user", "ungranted-user"] {
        store
            .create_principal(PrincipalWriteRequest {
                principal_id: principal.into(),
                kind: "user".into(),
                role: PrincipalRole::User,
                display_name: None,
                email: None,
                external_subject: None,
                self_service_enabled: None,
                created_by: "test".into(),
            })
            .unwrap();
    }
    let hasher = BrokerTokenHasher::load(&BrokerTokensConfig {
        hash_key_ref: format!("file:{}", key.display()),
        ..Default::default()
    })
    .unwrap();
    let issue = |principal: &str, name: &str, resource: Option<&str>| {
        let mut restriction = json!({"actions":actions});
        if let Some(resource) = resource {
            restriction["resources"] = json!({"resourceIds":[resource]});
        }
        store.issue_broker_token_with_catalog(&hasher, BrokerTokenIssueRequest {
            principal_id:principal.into(),name:name.into(),token_class:BrokerTokenClass::AgentInvoke,
            scopes:json!({"allowedServices":[service],"allowedExecutionContexts":["default"],
                "serviceRestrictions":{service:restriction}}),
            expires_at:None,created_by:"test".into(),
        },Some(&catalog)).unwrap().token
    };
    Tokens {
        unrestricted: issue("search-user", "current-grants", None),
        narrowed: issue("search-user", "first-only", Some("first")),
        disjoint: issue("search-user", "private-only", Some("private")),
        ungranted: issue("ungranted-user", "no-grants", None),
    }
}

pub fn cli(broker: &RunningBroker, token: &str) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_agent-access"));
    for (key, _) in std::env::vars_os() {
        if key.to_string_lossy().starts_with("AGENT_ACCESS_") {
            command.env_remove(key);
        }
    }
    command.args(["--url", &broker.public_url(), "--token-value", token]);
    command
}

pub fn run(broker: &RunningBroker, token: &str, args: &[&str], success: bool) -> Value {
    let output = cli(broker, token).args(args).output().unwrap();
    assert_eq!(
        output.status.success(),
        success,
        "{args:?}: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).unwrap()
}

pub fn invoke(
    broker: &RunningBroker,
    token: &str,
    action: &str,
    inputs: &Value,
    success: bool,
) -> Value {
    run(
        broker,
        token,
        &["invoke", action, "--input-json", &inputs.to_string()],
        success,
    )
}

pub fn send(
    broker: &RunningBroker,
    token: &str,
    service: &str,
    action: &str,
    inputs: &Value,
) -> Value {
    let path = broker.directory().join("search-request.json");
    std::fs::write(
        &path,
        json!({"version":"agent-access.send.v1","kind":"invoke",
        "service":service,"action":action,"inputs":inputs})
        .to_string(),
    )
    .unwrap();
    run(
        broker,
        token,
        &["send", "--request-file", path.to_str().unwrap()],
        true,
    )
}

pub async fn http(
    broker: &RunningBroker,
    token: &str,
    service: &str,
    action: &str,
    inputs: &Value,
) -> Value {
    reqwest::Client::new()
        .post(format!(
            "{}/v1/invoke/{service}/{action}",
            broker.public_url()
        ))
        .bearer_auth(token)
        .header(
            agent_access_provider::REQUEST_ID_HEADER,
            "search-exclusion-fixture",
        )
        .json(&json!({"inputs":inputs}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap()
}

pub fn denied(value: &Value, reason: &str) {
    assert_eq!(value["decision"], "deny", "{value}");
    assert_eq!(value["reasonCode"], reason, "{value}");
    assert!(value.get("result").is_none(), "{value}");
    assert!(!value.to_string().contains("DENIED_CONTENT"), "{value}");
    assert!(!value.to_string().contains("PRIVATE_LITERAL"), "{value}");
}

pub fn negation_audit(
    broker: &RunningBroker,
    service: &str,
    action: &str,
    query: &Value,
    version: u64,
    operands: &[(&str, &str)],
) {
    let expected_hashes = json!(
        operands
            .iter()
            .map(|(_, value)| format!("{:x}", Sha256::digest(value.as_bytes())))
            .collect::<Vec<_>>()
    );
    let audit = broker.audit().unwrap();
    let records = audit.require_action(service, action);
    let successful = records
        .into_iter()
        .filter(|record| {
            record["decision"] == "allow"
                && record["auditInputs"].as_array().is_some_and(|inputs| {
                    inputs
                        .iter()
                        .any(|input| input["input"] == "query" && input["value"] == *query)
                })
        })
        .collect::<Vec<_>>();
    assert!(
        !successful.is_empty(),
        "the configured audit input must retain the caller query"
    );
    for record in successful {
        let provider = &record["providerAudit"];
        assert_eq!(provider["queryAstVersion"], version, "{record}");
        assert_eq!(provider["textOperandHashes"], expected_hashes, "{record}");
        let clauses = provider["queryShape"]["filter"]["children"]
            .as_array()
            .unwrap();
        let mut without_inputs = record.clone();
        without_inputs
            .as_object_mut()
            .unwrap()
            .remove("auditInputs");
        let diagnostics = without_inputs.to_string();
        for (field, value) in operands {
            assert!(
                clauses
                    .iter()
                    .any(|clause| { clause["field"] == *field && clause["operator"] == "!~" }),
                "{provider}"
            );
            assert!(!diagnostics.contains(value), "{diagnostics}");
        }
    }
}

pub fn documentation(
    broker: &RunningBroker,
    token: &str,
    service: &str,
    action: &str,
    fields: &[&str],
) -> Value {
    let catalog = run(broker, token, &["spec", "catalog"], true);
    let entry = catalog["services"]
        .as_array()
        .unwrap()
        .iter()
        .find(|entry| entry["service"] == service)
        .unwrap()["actions"]
        .as_array()
        .unwrap()
        .iter()
        .find(|entry| entry["action"] == action)
        .unwrap();
    let documentation = entry["documentation"].clone();
    let grammar = if service == "jira" { "jql" } else { "cql" };
    for field in fields {
        let inventory = documentation[grammar]["fields"]
            .as_array()
            .unwrap()
            .iter()
            .find(|entry| entry["name"] == *field)
            .unwrap();
        assert_eq!(inventory["operators"], json!(["=", "!=", "IN", "NOT IN"]));
    }
    let text_fields: &[&str] = if service == "jira" {
        &["summary", "description"]
    } else {
        &["title", "text"]
    };
    let inventory = documentation[grammar]["fields"].as_array().unwrap();
    for field in text_fields {
        let entry = inventory
            .iter()
            .find(|entry| entry["name"] == *field)
            .unwrap();
        assert_eq!(entry["operators"], json!(["~", "!~"]));
    }
    for entry in inventory {
        let name = entry["name"].as_str().unwrap();
        assert_eq!(
            entry["operators"]
                .as_array()
                .unwrap()
                .contains(&json!("!~")),
            text_fields.contains(&name),
            "{entry}"
        );
    }
    if service == "jira" {
        assert!(
            documentation[grammar]["customFields"]["operators"]
                .as_array()
                .unwrap()
                .contains(&json!("!~"))
        );
        assert!(
            entry["description"]
                .as_str()
                .unwrap()
                .contains("text negation")
        );
        assert!(
            entry["inputSchema"]["properties"]["query"]["properties"]["value"]["description"]
                .as_str()
                .unwrap()
                .contains("text negation")
        );
    }
    let detail = run(
        broker,
        token,
        &["actions", "describe", "--service", service, action],
        true,
    );
    assert_eq!(detail["documentation"], documentation);
    let openapi = run(broker, token, &["spec", "openapi"], true);
    assert_eq!(
        openapi["paths"][format!("/v1/invoke/{service}/{action}")]["post"]["x-agent-access-documentation"],
        documentation
    );
    let send = run(broker, token, &["spec", "send-schema"], true);
    let variant = send["oneOf"]
        .as_array()
        .unwrap()
        .iter()
        .find(|variant| {
            variant["properties"]["service"]["const"] == service
                && variant["properties"]["action"]["const"] == action
        })
        .unwrap();
    assert_eq!(variant["x-agent-access-documentation"], documentation);
    documentation
}
