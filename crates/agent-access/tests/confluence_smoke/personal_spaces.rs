use super::*;
use agent_access_core::{
    BrokerTokenClass, BrokerTokenHasher, BrokerTokenIssueRequest, BrokerTokensConfig,
    ManagedResourceCatalog, ManagedStore, ManagedStoreConfig, ManagedStoreOpenMode, PrincipalRole,
    PrincipalWriteRequest,
};
use serde_json::{Value, json};

fn personal_page(id: &str, space: &str) -> ConfluencePage {
    ConfluencePage {
        id: id.into(),
        title: "Personal notes".into(),
        space: space.into(),
        web_url: None,
        space_web_url: None,
        status: Some("current".into()),
        version: 1,
        created_at: None,
        updated_at: None,
        created_by: None,
        updated_by: None,
        bodies: BTreeMap::from([("storage".into(), "<p>Personal notes</p>".into())]),
    }
}

fn personal_backend(include_bob_in_search: bool) -> Arc<WriteStubConfluenceBackend> {
    let alice = personal_page("111", "~alice");
    let bob = personal_page("222", "~bob");
    Arc::new(WriteStubConfluenceBackend {
        spaces: Mutex::new(
            [("11", "~alice", "111"), ("22", "~bob", "222")]
                .into_iter()
                .map(|(id, key, homepage)| {
                    (
                        id.into(),
                        ConfluenceSpace {
                            id: id.into(),
                            key: key.into(),
                            web_url: None,
                            alias: None,
                            status: Some("current".into()),
                            homepage_id: Some(homepage.into()),
                        },
                    )
                })
                .collect(),
        ),
        pages: Mutex::new(BTreeMap::from([
            (alice.id.clone(), alice.clone()),
            (bob.id.clone(), bob.clone()),
        ])),
        search_page: Mutex::new(Some(ConfluenceSearchPage {
            pages: if include_bob_in_search {
                vec![alice, bob]
            } else {
                vec![alice]
            },
            max_results: 2,
            next_page_token: None,
        })),
        next_page_id: Mutex::new(333),
        ..Default::default()
    })
}

// Real broker startup admits the TOML resource catalog, then both tokens use
// Alice's per-user credential. That upstream credential can see both spaces;
// only Broker grants and token restrictions distinguish them.
async fn personal_broker(
    selection: &str,
    backend: Arc<WriteStubConfluenceBackend>,
) -> (RunningBroker, String, String) {
    let application = IsolatedBroker::new(
        agent_access_broker::composition().unwrap(),
        agent_access_broker::build_identity(),
    )
    .unwrap();
    let directory = application.directory();
    let mut document = confluence_document(
        directory,
        &["page.view", "search", "page.create", "page.update"],
    )
    .replace(
        "mode = \"anonymous\"\nauthority = \"toml\"",
        "mode = \"required\"\nauthority = \"managed\"",
    )
    .replace("space-eng", "space-alice")
    .replace("value = \"ENG\"", "value = \"~alice\"")
    .replace(
        "subjects = [\"group:anonymous\"]",
        "subjects = [\"user:alice\"]",
    )
    .replace(
        "credential_mode = \"service\"",
        "credential_mode = \"per_user\"",
    )
    .replace(
        "resources = { resource_ids = [\"space-alice\"] }",
        &format!("resources = {{ {selection} }}"),
    );
    let username = directory
        .secret_file("personal-username", "alice@example.com")
        .unwrap();
    let secret = directory
        .secret_file("personal-token", "alice-upstream-token")
        .unwrap();
    let credentials = directory
        .secret_file(
            "personal-credentials.json",
            json!({"credentials":[{
                "principal":"alice", "type":"basic_api_token",
                "username_ref":format!("file:{}", username.display()),
                "token_ref":format!("file:{}", secret.display())
            }]})
            .to_string(),
        )
        .unwrap();
    let store_config = ManagedStoreConfig {
        kind: "sqlite".into(),
        path: directory.join("personal.sqlite").display().to_string(),
        require_registered_principal_for_invocation: true,
        auto_migrate: true,
    };
    let encryption_key = directory
        .secret_file(
            "personal-encryption-key",
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([7_u8; 32]),
        )
        .unwrap();
    document.push_str(&format!(
        r#"
[[identity.sources]]
name = "broker"
type = "broker_tokens"
header = "Authorization"
scheme = "Bearer"

[managed_store]
type = "sqlite"
path = {store}
auto_migrate = true
require_registered_principal_for_invocation = true

[credential_encryption]
active_key = "fixture"
[[credential_encryption.keys]]
id = "fixture"
provider = "file"
path = {encryption_key}

[credentials.per_user.confluence]
type = "secret_store"
provider = "local_file"
path = {credentials}

[[policy.resources]]
id = "space-bob"
resource_type = "confluence_space"
selector = {{ kind = "exact", value = "~bob" }}
allowed_execution_contexts = ["default"]
enabled = false

[[policy.resources]]
id = "all-spaces"
resource_type = "confluence_space"
selector = {{ kind = "all" }}
allowed_execution_contexts = ["default"]

[[policy.resource_groups]]
id = "except-bob"
name = "Spaces except Bob"
included_resource_ids = ["all-spaces"]
excluded_resource_ids = ["space-bob"]
"#,
        store = toml_string(&store_config.path),
        credentials = toml_string(credentials.display()),
        encryption_key = toml_string(encryption_key.display()),
    ));
    let store = ManagedStore::open(&store_config, ManagedStoreOpenMode::Startup).unwrap();
    store
        .create_principal(PrincipalWriteRequest {
            principal_id: "alice".into(),
            kind: "user".into(),
            role: PrincipalRole::User,
            display_name: None,
            email: None,
            external_subject: None,
            self_service_enabled: None,
            created_by: "test".into(),
        })
        .unwrap();
    let hasher = BrokerTokenHasher::load(&BrokerTokensConfig {
        hash_key_ref: format!(
            "file:{}",
            directory
                .join("confluence-broker-token-hash-key.txt")
                .display()
        ),
        ..Default::default()
    })
    .unwrap();
    let catalog: ManagedResourceCatalog = serde_json::from_value(json!({
        "resources":[{"id":"space-alice", "resourceType":"confluence_space",
            "selector":{"kind":"exact", "value":"~alice"}, "allowedExecutionContexts":["default"], "enabled":true}],
        "resourceGroups":[]
    })).unwrap();
    let issue = |restricted: bool| {
        let mut scopes =
            json!({"allowedServices":["confluence"], "allowedExecutionContexts":["default"]});
        if restricted {
            scopes["serviceRestrictions"] = json!({"confluence":{
                "actions":["page.view","search","page.create","page.update"],
                "resources":{"resourceIds":["space-alice"]}
            }});
        }
        store
            .issue_broker_token_with_catalog(
                &hasher,
                BrokerTokenIssueRequest {
                    principal_id: "alice".into(),
                    name: if restricted {
                        "Alice space only"
                    } else {
                        "Current grants"
                    }
                    .into(),
                    token_class: BrokerTokenClass::AgentInvoke,
                    scopes,
                    expires_at: None,
                    created_by: "test".into(),
                },
                Some(&catalog),
            )
            .unwrap()
            .token
    };
    let token = issue(false);
    let restricted = issue(true);
    drop(store);
    let broker = application
        .config_document(document)
        .provider_fixture("confluence", confluence_fixture(backend))
        .start()
        .await
        .unwrap();
    (broker, token, restricted)
}

fn personal_cli(broker: &RunningBroker, token: &str, arguments: &[&str], allow: bool) -> Value {
    let output = Command::new(env!("CARGO_BIN_EXE_agent-access"))
        .args([
            "--url",
            &broker.public_url(),
            "--token-value",
            token,
            "--identity-header",
            "Authorization",
            "--identity-scheme",
            "Bearer",
        ])
        .args(arguments)
        .output()
        .unwrap();
    assert_eq!(
        output.status.success(),
        allow,
        "{arguments:?}: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let result: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(result["decision"], if allow { "allow" } else { "deny" });
    result
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cli_personal_space_exact_grant_uses_per_user_credentials_and_contains_writes() {
    let backend = personal_backend(false);
    let (broker, token, _) =
        personal_broker("resource_ids = [\"space-alice\"]", backend.clone()).await;
    for locator in [
        vec!["confluence", "page", "view", "111"],
        vec![
            "confluence",
            "page",
            "view",
            "--page-url",
            "https://example.atlassian.net/wiki/spaces/~alice/pages/111/Notes",
        ],
    ] {
        let page = personal_cli(&broker, &token, &locator, true);
        assert_eq!(page["resourceScopes"]["space"], json!(["~alice"]));
        assert_eq!(
            page["result"]["spaceUrl"],
            "https://example.atlassian.net/wiki/spaces/~alice"
        );
    }
    let search = personal_cli(
        &broker,
        &token,
        &[
            "confluence",
            "page",
            "search",
            "--space",
            "~alice",
            "--cql",
            "space = \"~alice\"",
        ],
        true,
    );
    assert_eq!(search["result"]["pages"][0]["space"], "~alice");
    let request = backend.searches.lock().unwrap().last().unwrap().clone();
    assert_eq!(request.spaces, ["~alice"]);
    assert!(
        request.cql.contains("space IN (\"~alice\")"),
        "{}",
        request.cql
    );
    let created = personal_cli(
        &broker,
        &token,
        &[
            "confluence",
            "page",
            "create",
            "--space",
            "~alice",
            "--title",
            "New notes",
            "--parent",
            "111",
            "--content",
            "<p>New notes</p>",
            "--content-format",
            "storage",
        ],
        true,
    );
    assert_eq!(created["result"]["pageId"], "333");
    assert_eq!(created["result"]["verification"]["status"], "matched");
    let updated = personal_cli(
        &broker,
        &token,
        &[
            "confluence",
            "page",
            "update",
            "333",
            "--base-version",
            "1",
            "--content",
            "<p>Updated notes</p>",
            "--content-format",
            "storage",
        ],
        true,
    );
    assert_eq!(updated["result"]["pageId"], "333");
    assert_eq!(updated["result"]["space"], "~alice");
    assert_eq!(updated["result"]["previousVersion"], 1);
    assert_eq!(updated["result"]["version"], 2);
    {
        let pages = backend.pages.lock().unwrap();
        assert_eq!(pages["333"].version, 2);
        assert!(pages["333"].bodies["storage"].contains("<p>Updated notes</p>"));
    }
    personal_cli(
        &broker,
        &token,
        &["confluence", "page", "view", "222"],
        false,
    );
    let searches = backend.searches.lock().unwrap().len();
    personal_cli(
        &broker,
        &token,
        &[
            "confluence",
            "page",
            "search",
            "--space",
            "~bob",
            "--text",
            "notes",
        ],
        false,
    );
    assert_eq!(backend.searches.lock().unwrap().len(), searches);
    personal_cli(
        &broker,
        &token,
        &[
            "confluence",
            "page",
            "create",
            "--space",
            "~bob",
            "--title",
            "Denied",
            "--parent",
            "222",
            "--content",
            "Denied",
            "--content-format",
            "plain_text",
        ],
        false,
    );
    personal_cli(
        &broker,
        &token,
        &[
            "confluence",
            "page",
            "update",
            "222",
            "--base-version",
            "1",
            "--content",
            "Denied",
            "--content-format",
            "plain_text",
        ],
        false,
    );
    assert_eq!(backend.pages.lock().unwrap().len(), 3);
    assert_eq!(backend.pages.lock().unwrap()["222"].version, 1);
    {
        let credentials = backend.credentials.lock().unwrap();
        assert!(!credentials.is_empty());
        assert!(credentials.iter().all(|credential| credential
            == &agent_access_provider::test_support::basic_credential(
                "alice@example.com",
                "alice-upstream-token"
            )));
    }
    let audit = std::fs::read_to_string(broker.directory().join("audit.jsonl")).unwrap();
    assert!(audit.contains("\"credentialMode\":\"per_user\""));
    assert!(!audit.contains("alice-upstream-token"));
    stop(broker).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cli_personal_spaces_respect_all_grants_exclusions_and_token_ceilings() {
    for excluded in [false, true] {
        let backend = personal_backend(!excluded);
        let selection = if excluded {
            "resource_group_ids = [\"except-bob\"]"
        } else {
            "resource_ids = [\"all-spaces\"]"
        };
        let (broker, token, restricted) = personal_broker(selection, backend.clone()).await;
        let search = personal_cli(
            &broker,
            &token,
            &["confluence", "page", "search", "--text", "notes"],
            true,
        );
        assert_eq!(
            search["result"]["pages"].as_array().unwrap().len(),
            if excluded { 1 } else { 2 }
        );
        let request = backend.searches.lock().unwrap().last().unwrap().clone();
        assert!(request.spaces.is_empty());
        assert_eq!(
            request.cql.contains("space NOT IN (\"~bob\")"),
            excluded,
            "{}",
            request.cql
        );
        personal_cli(
            &broker,
            &token,
            &["confluence", "page", "view", "222"],
            !excluded,
        );
        personal_cli(
            &broker,
            &restricted,
            &["confluence", "page", "view", "111"],
            true,
        );
        personal_cli(
            &broker,
            &restricted,
            &["confluence", "page", "view", "222"],
            false,
        );
        backend.search_page.lock().unwrap().as_mut().unwrap().pages =
            vec![personal_page("111", "~alice")];
        personal_cli(
            &broker,
            &restricted,
            &["confluence", "page", "search", "--text", "notes"],
            true,
        );
        let request = backend.searches.lock().unwrap().last().unwrap().clone();
        assert_eq!(request.spaces, ["~alice"]);
        assert!(
            request.cql.contains("space IN (\"~alice\")"),
            "{}",
            request.cql
        );
        stop(broker).await;
    }
}
