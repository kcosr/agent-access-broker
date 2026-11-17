//! Real Broker admission, projections, audit and CLI around the Jira provider.
//! The in-memory Jira seam records mutations without contacting an upstream.
use super::*;
use serde_json::{Value, json};

const ACTION: &str = "issue.url_field.set";
const FIELD: &str = "customfield_12345";
const ISSUE_ID: &str = "10001";
const NAME: &str = "secret-url-field-name";
const LINK: &str = "https://reports.example.com/secret-url-value#runs?run=latest";

async fn start(backend: Arc<StubJiraBackend>, allowed_field_ids: &[&str]) -> RunningBroker {
    let application = IsolatedBroker::new(
        agent_access_broker::composition().unwrap(),
        agent_access_broker::build_identity(),
    )
    .unwrap();
    let mut document: toml::Value = toml::from_str(&jira_document(
        application.directory(),
        JiraAccess::AgentService,
    ))
    .unwrap();
    document["providers"]["jira"]
        .as_table_mut()
        .unwrap()
        .insert(
            "url_fields".into(),
            toml::Value::try_from(json!({"allowed_field_ids":allowed_field_ids})).unwrap(),
        );
    for grant in document["policy"]["grants"].as_array_mut().unwrap() {
        grant["actions"] = toml::Value::try_from(vec![ACTION]).unwrap();
    }
    let config = document["providers"]["jira"].clone().try_into().unwrap();
    application
        .config_document(toml::to_string(&document).unwrap())
        .provider_fixture(
            "jira",
            ProviderFixture::instance(jira_service(config, Default::default(), backend)),
        )
        .start()
        .await
        .unwrap()
}

fn run(base: &str, arguments: &[&str]) -> Value {
    let output = authenticated_jira_cli(base)
        .args(arguments)
        .output()
        .unwrap();
    assert_success("URL custom-field CLI", &output);
    serde_json::from_slice(&output.stdout).unwrap()
}

fn backend() -> Arc<StubJiraBackend> {
    Arc::new(StubJiraBackend {
        issues: BTreeMap::from([(
            "PROJ-1".to_string(),
            JiraIssue {
                id: ISSUE_ID.to_string(),
                key: "PROJ-1".to_string(),
                project: "PROJ".to_string(),
                summary: None,
                status: None,
                issue_type: None,
                description: None,
                created: None,
                updated: None,
                creator: None,
                reporter: None,
                assignee: None,
                priority: None,
                labels: None,
            },
        )]),
        url_fields: Mutex::new(BTreeMap::from([(
            (ISSUE_ID.to_string(), FIELD.to_string()),
            json!({
                "id":ISSUE_ID,"key":"PROJ-1",
                "fields":{"project":{"key":"PROJ"},FIELD:null},
                "names":{FIELD:NAME},
                "schema":{FIELD:{"type":"string","custom":"com.atlassian.jira.plugin.system.customfieldtypes:url"}}
            }),
        )])),
        ..Default::default()
    })
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn jira_url_field_set_projects_authority_and_preserves_idempotence_and_private_audit() {
    let backend = backend();
    let broker = start(backend.clone(), &[FIELD]).await;
    let base = broker.public_url();
    let catalog = run(&base, &["spec", "catalog"]);
    let actions = catalog["services"]
        .as_array()
        .unwrap()
        .iter()
        .find(|service| service["service"] == "jira")
        .unwrap()["actions"]
        .as_array()
        .unwrap();
    assert_eq!(
        actions.len(),
        1,
        "the grant authorizes only URL-field writes"
    );
    let action = &actions[0];
    assert_eq!(action["action"], ACTION);
    assert_eq!(action["readOnly"], false);
    assert_eq!(action["lookupRequired"], true);
    assert_eq!(action["requiredScopeTypes"], json!(["project"]));
    assert_eq!(action["documentation"]["allowedFieldIds"], json!([FIELD]));
    assert_eq!(
        action["inputSchema"]["required"],
        json!(["fieldId", "value", "expectedValue"])
    );
    let openapi = run(&base, &["spec", "openapi"]);
    let operation = &openapi["paths"]["/v1/invoke/jira/issue.url_field.set"]["post"];
    assert_eq!(operation["x-agent-access-read-only"], false);
    assert_eq!(
        operation["x-agent-access-documentation"],
        action["documentation"]
    );
    let schema = run(&base, &["spec", "send-schema"]);
    let variant = schema["oneOf"]
        .as_array()
        .unwrap()
        .iter()
        .find(|variant| {
            variant["properties"]["service"]["const"] == "jira"
                && variant["properties"]["action"]["const"] == ACTION
        })
        .unwrap();
    assert_eq!(variant["x-agent-access-read-only"], false);
    assert_eq!(
        variant["x-agent-access-documentation"],
        action["documentation"]
    );
    assert!(backend.credential_observations.lock().unwrap().is_empty());

    let written = run(
        &base,
        &[
            "jira",
            "issue",
            "url-field",
            "set",
            "PROJ-1",
            "--expected-issue-id",
            ISSUE_ID,
            "--field-id",
            FIELD,
            "--value",
            LINK,
        ],
    );
    assert_eq!(written["decision"], "allow");
    assert_eq!(written["result"]["operation"], ACTION);
    assert_eq!(written["result"]["changed"], true);
    assert_eq!(written["result"]["issue"]["id"], ISSUE_ID);
    assert_eq!(written["result"]["issue"]["key"], "PROJ-1");
    assert_eq!(
        written["result"]["field"],
        json!({"id":FIELD,"name":NAME,"type":"url","value":LINK})
    );
    let inputs = json!({
        "issue":"PROJ-1", "expectedIssueId":ISSUE_ID,
        "fieldId":FIELD, "value":LINK, "expectedValue":null
    });
    let replayed = run(
        &base,
        &[
            "invoke",
            "jira.issue.url_field.set",
            "--input-json",
            &inputs.to_string(),
        ],
    );
    assert_eq!(replayed["result"]["changed"], false);
    assert_eq!(replayed["result"]["field"]["value"], LINK);

    let mut conflict = inputs.clone();
    conflict["value"] = json!("https://reports.example.com/secret-conflicting-value");
    conflict["expectedValue"] = json!("https://reports.example.com/secret-expected-value");
    let output = authenticated_jira_cli(&base)
        .args([
            "invoke",
            "jira.issue.url_field.set",
            "--input-json",
            &conflict.to_string(),
        ])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
    let refused: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(refused["decision"], "deny");
    assert_eq!(refused["reasonCode"], "jira_url_field_conflict");
    assert!(refused["result"].is_null());
    assert_eq!(
        backend.url_field_updates.lock().unwrap().as_slice(),
        &[(ISSUE_ID.to_string(), FIELD.to_string(), LINK.to_string())]
    );
    let observations = backend.credential_observations.lock().unwrap().clone();
    for observation in &observations {
        let token = if observation.operation == "issue_metadata" {
            "jira-lookup-token"
        } else {
            "jira-token"
        };
        assert_eq!(observation.credential, jira_credential(token));
    }
    assert_eq!(
        observations
            .iter()
            .filter(|observation| observation.operation == "issue_url_field")
            .count(),
        4,
        "initial read and verification, one replay read, one conflict read"
    );
    let audit = broker.audit().unwrap().text();
    assert!(audit.contains("\"action\":\"issue.url_field.set\""));
    assert!(audit.contains("jira_url_field_conflict"));
    assert!(audit.contains(FIELD));
    for hidden in [
        NAME,
        LINK,
        "secret-conflicting-value",
        "secret-expected-value",
    ] {
        assert!(!audit.contains(hidden), "audit disclosed {hidden}");
        assert!(
            !refused.to_string().contains(hidden),
            "denial disclosed {hidden}"
        );
    }
    stop(broker).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn jira_url_field_allowlist_refusal_survives_admission_without_field_access() {
    for (allowed, requested) in [
        (&[] as &[&str], FIELD),
        (&[FIELD] as &[&str], "customfield_99999"),
    ] {
        let backend = backend();
        let broker = start(backend.clone(), allowed).await;
        let inputs = json!({
            "issue":"PROJ-1", "fieldId":requested,
            "value":LINK, "expectedValue":null,
        });
        let output = authenticated_jira_cli(&broker.public_url())
            .args([
                "invoke",
                "jira.issue.url_field.set",
                "--input-json",
                &inputs.to_string(),
            ])
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(2));
        let refused: Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(refused["decision"], "deny");
        assert_eq!(refused["reasonCode"], "jira_url_field_not_allowed");
        assert!(refused["result"].is_null());
        assert!(backend.url_field_updates.lock().unwrap().is_empty());
        let observations = backend.credential_observations.lock().unwrap().clone();
        assert_eq!(
            observations.len(),
            1,
            "only project scope resolution is needed"
        );
        assert_eq!(observations[0].operation, "issue_metadata");
        assert_eq!(
            observations[0].credential,
            jira_credential("jira-lookup-token")
        );
        let audit = broker.audit().unwrap().text();
        assert!(audit.contains("jira_url_field_not_allowed"));
        assert!(audit.contains(requested));
        for hidden in [NAME, LINK] {
            assert!(!audit.contains(hidden));
            assert!(!refused.to_string().contains(hidden));
        }
        stop(broker).await;
    }
}
