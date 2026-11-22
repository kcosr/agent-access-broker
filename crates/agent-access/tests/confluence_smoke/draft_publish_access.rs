//! Runtime authorization for an already-created draft: the explicit publish
//! action on that exact identity needs no create/update or parent permission.
use super::*;
use serde_json::{Value, json};

async fn invoke(broker: &RunningBroker, action: &str, inputs: Value) -> Value {
    reqwest::Client::new()
        .post(format!(
            "{}/v1/invoke/confluence/{action}",
            broker.public_url()
        ))
        .header(
            agent_access_provider::REQUEST_ID_HEADER,
            "publish-only-fixture",
        )
        .json(&json!({"inputs":inputs}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn exact_draft_publish_only_grant_needs_no_create_update_or_parent_coverage() {
    let backend = Arc::new(WriteStubConfluenceBackend {
        spaces: Mutex::new(BTreeMap::from([(
            "1".into(),
            ConfluenceSpace {
                id: "1".into(),
                key: "ENG".into(),
                web_url: None,
                alias: None,
                status: Some("current".into()),
                homepage_id: Some("100".into()),
            },
        )])),
        pages: Mutex::new(BTreeMap::from([(
            "100".into(),
            ConfluencePage {
                id: "100".into(),
                title: "Engineering".into(),
                space: "ENG".into(),
                web_url: None,
                space_web_url: None,
                space_alias: None,
                status: Some("current".into()),
                version: 1,
                created_at: None,
                updated_at: None,
                created_by: None,
                updated_by: None,
                bodies: BTreeMap::new(),
            },
        )])),
        page_parents: Mutex::new(BTreeMap::from([("100".into(), None)])),
        next_page_id: Mutex::new(200),
        ..Default::default()
    });
    let broker = start_broker(
        &["page.draft.create", "page.draft.publish"],
        backend.clone(),
    )
    .await;
    let created = invoke(
        &broker,
        "page.draft.create",
        json!({
            "space":"ENG", "parent":{"kind":"page","id":"100"},
            "title":"Publish approved draft", "contentFormat":"storage",
            "content":"<p>Exact draft publication fixture</p>"
        }),
    )
    .await;
    assert_eq!(created["decision"], "allow", "{created}");
    assert_eq!(created["result"]["pageId"], "200");
    let handle = created["result"]["draftHandle"].as_str().unwrap();

    let mut document: toml::Value =
        toml::from_str(&std::fs::read_to_string(broker.config_path()).unwrap()).unwrap();
    document["policy"]["resources"] = toml::Value::try_from(json!([{
        "id":"exact-draft", "resource_type":"confluence_content",
        "selector":{"kind":"exact","value":"https://example.atlassian.net/wiki/content/page/200"},
        "allowed_execution_contexts":["default"]
    }]))
    .unwrap();
    document["policy"]["grants"][0]["resources"] =
        toml::Value::try_from(json!({"resource_ids":["exact-draft"]})).unwrap();
    document["policy"]["grants"][0]["actions"] =
        toml::Value::try_from(json!(["page.draft.publish"])).unwrap();
    broker
        .rewrite_config(toml::to_string(&document).unwrap())
        .unwrap();
    let reloaded = broker.reload().await.unwrap();
    assert!(reloaded.is_success(), "{:?}", reloaded.message());

    for (action, inputs) in [
        (
            "page.create",
            json!({"space":"ENG","parent":{"kind":"page","id":"100"},
            "title":"Not permitted", "contentFormat":"storage", "content":"<p>Denied</p>"}),
        ),
        (
            "page.update",
            json!({"pageId":"100","baseVersion":1,
            "contentFormat":"storage","content":"<p>Denied</p>"}),
        ),
        (
            "page.draft.update",
            json!({"pageId":"200","draftHandle":handle,
            "contentFormat":"storage","content":"<p>Denied</p>"}),
        ),
    ] {
        let denied = invoke(&broker, action, inputs).await;
        assert_eq!(denied["decision"], "deny", "{action}: {denied}");
        assert!(denied.get("result").is_none(), "{denied}");
    }
    assert_eq!(backend.pages.lock().unwrap().len(), 1);
    assert_eq!(backend.page_drafts.lock().unwrap().len(), 1);

    let output = confluence_cli()
        .args([
            "--url",
            &broker.public_url(),
            "confluence",
            "page",
            "draft",
            "publish",
            "200",
            "--draft-handle",
            handle,
            "--body-format",
            "storage",
        ])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let published: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(published["decision"], "allow", "{published}");
    assert_eq!(published["result"]["pageId"], "200");
    assert_eq!(published["result"]["status"], "current");
    assert_eq!(published["result"]["version"], 1);
    assert_eq!(
        published["result"]["parent"],
        json!({"kind":"page","id":"100"})
    );
    assert_eq!(backend.pages.lock().unwrap().len(), 2);
    assert!(backend.page_drafts.lock().unwrap().is_empty());
    assert_eq!(
        backend.page_parents.lock().unwrap()["200"].as_deref(),
        Some("100")
    );
    stop(broker).await;
}
