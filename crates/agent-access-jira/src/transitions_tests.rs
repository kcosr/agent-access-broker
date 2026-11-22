use super::*;
use std::sync::atomic::{AtomicUsize, Ordering};
use wiremock::matchers::query_param;

const ISSUE_ID: &str = "10001";
const PRIVATE: &str = "private workflow content";

fn issue_status(id: &str, name: &str) -> Value {
    json!({"id":ISSUE_ID, "key":"PROJ-1", "fields":{"project":{"key":"PROJ"}, "status":{"id":id,"name":name,"statusCategory":{"id":2,"key":"indeterminate","name":"In Progress"}}}})
}

fn offered() -> Value {
    json!({"transitions":[{
        "id":"31", "name":"Stall work", "to":{"id":"10002", "name":"Stalled"},
        "hasScreen":false, "isAvailable":true, "fields":{}
    }]})
}

fn apply_inputs() -> Value {
    json!({"issue":"PROJ-1", "transitionId":"31", "toStatusId":"10002", "expectedIssueId":ISSUE_ID, "expectedStatusId":"10000"})
}

fn invocation(action: &str, inputs: Value) -> ProviderInvocation {
    InvocationBuilder::new("jira", action)
        .inputs(inputs)
        .resources(BTreeMap::from([("project".into(), vec!["PROJ".into()])]))
        .credential(test_credential())
        .lookup_credential(test_lookup_credential())
        .build()
}

struct Fixture {
    api: MockServer,
    provider: JiraProvider,
    posts: Arc<AtomicUsize>,
}

impl Fixture {
    async fn new(transitions: Value, post: ResponseTemplate, readback: ResponseTemplate) -> Self {
        let api = MockServer::start().await;
        let posts = Arc::new(AtomicUsize::new(0));
        Mock::given(method("GET"))
            .and(path("/rest/api/3/issue/PROJ-1"))
            .and(query_param("fields", "project"))
            .respond_with(ResponseTemplate::new(200).set_body_json(
                json!({"id":ISSUE_ID,"key":"PROJ-1","fields":{"project":{"key":"PROJ"}}}),
            ))
            .mount(&api)
            .await;
        let writes = posts.clone();
        Mock::given(method("GET"))
            .and(path("/rest/api/3/issue/10001"))
            .and(query_param("fields", "project,status"))
            .respond_with(move |_: &wiremock::Request| {
                if writes.load(Ordering::SeqCst) == 0 {
                    ResponseTemplate::new(200).set_body_json(issue_status("10000", "New"))
                } else {
                    readback.clone()
                }
            })
            .mount(&api)
            .await;
        Mock::given(method("GET"))
            .and(path("/rest/api/3/issue/10001/transitions"))
            .respond_with(ResponseTemplate::new(200).set_body_json(transitions))
            .mount(&api)
            .await;
        let writes = posts.clone();
        Mock::given(method("POST"))
            .and(path("/rest/api/3/issue/10001/transitions"))
            .respond_with(move |_: &wiremock::Request| {
                writes.fetch_add(1, Ordering::SeqCst);
                post.clone()
            })
            .mount(&api)
            .await;
        let mut config = jira_config();
        config.allowed_upstream_hosts = vec![format!("{}/rest/api/3/**", api.uri())];
        let limits = ProviderLimits::default();
        let backend = HttpJiraBackend::new_with_api_base(
            config.clone(),
            limits.clone(),
            Url::parse(&format!("{}/rest/api/3/", api.uri())).unwrap(),
        );
        Self {
            api,
            provider: JiraProvider::from_backend(config, limits, Arc::new(backend)),
            posts,
        }
    }

    async fn ready(transitions: Value) -> Self {
        Self::new(
            transitions,
            ResponseTemplate::new(204),
            ResponseTemplate::new(200).set_body_json(issue_status("10002", "Stalled")),
        )
        .await
    }

    async fn invoke(&self, action: &str, inputs: Value) -> Result<ProviderResult, ProviderError> {
        self.provider
            .invoke_checked(invocation(action, inputs))
            .await
    }
}

#[test]
fn transition_inputs_and_descriptors_preserve_the_narrow_contract() {
    let config = jira_config();
    let descriptor = config.descriptor();
    let list = descriptor.action("issue.transition.list").unwrap();
    let apply = descriptor.action("issue.transition.apply").unwrap();
    assert!(list.read_only);
    assert!(!apply.read_only);
    for action in [list, apply] {
        assert_eq!(action.lookup, LookupRequirement::ScopeResolution);
        assert_eq!(action.required_scope_types(), ["project"]);
        assert_eq!(action.credential_modes, ["service", "per_user"]);
        assert!(action.documentation.is_some());
    }
    let validator = jsonschema::validator_for(&apply.input_schema).unwrap();
    let good = apply_inputs();
    assert!(transitions::parse_apply(&good, &config).is_ok());
    assert!(validator.is_valid(&good));
    for (key, value) in [
        ("transitionId", json!("../bad")),
        ("transitionId", json!(31)),
        ("toStatusId", json!("Stalled")),
        ("toStatusId", json!("0")),
        ("resolutionId", Value::Null),
        ("expectedStatusId", json!("01")),
        ("expectedIssueId", json!("1".repeat(65))),
        ("fields", json!({"summary":PRIVATE})),
        ("update", json!({"comment":PRIVATE})),
        ("notifyUsers", json!(false)),
        ("status", json!("Stalled")),
    ] {
        let mut candidate = good.clone();
        candidate[key] = value;
        let error = transitions::parse_apply(&candidate, &config).err().unwrap();
        assert_eq!(error.reason_code(), ReasonCode::InputInvalid);
        assert!(!error.message.contains(PRIVATE));
        assert!(!validator.is_valid(&candidate));
    }
    for key in ["transitionId", "toStatusId"] {
        let mut candidate = good.clone();
        candidate.as_object_mut().unwrap().remove(key);
        assert!(transitions::parse_apply(&candidate, &config).is_err());
    }
    let mut url = good;
    url["issue"] = Value::Null;
    url["url"] = json!("https://example.atlassian.net/browse/PROJ-1");
    assert!(transitions::parse_apply(&url, &config).is_ok());
    assert!(validator.is_valid(&url));
    for candidate in [
        json!({}),
        json!({"issue":"PROJ-1","url":"https://example.atlassian.net/browse/PROJ-1"}),
        json!({"issue":"PROJ-1","includeFields":null}),
    ] {
        assert!(transitions::parse_list(&candidate, &config).is_err());
    }
}

#[tokio::test]
async fn transition_optional_metadata_and_nested_fields_conform_without_becoming_opaque() {
    for fields in [None, Some(Value::Null)] {
        let mut offered = offered();
        let transition = offered["transitions"][0].as_object_mut().unwrap();
        transition.remove("hasScreen");
        transition.remove("fields");
        if let Some(fields) = fields {
            transition.insert("fields".into(), fields);
        }
        let fixture = Fixture::ready(offered).await;
        let outcome = fixture
            .invoke(
                "issue.transition.list",
                json!({"issue":"PROJ-1", "includeFields":true}),
            )
            .await
            .unwrap();
        let transition = &outcome.result["transitions"][0];
        assert_eq!(transition["fields"], Value::Null);
        assert_eq!(transition["hasScreen"], Value::Null);
        assert_eq!(transition["to"]["statusCategory"], Value::Null);

        let descriptor = jira_descriptor(&jira_config());
        let action = descriptor.action("issue.transition.list").unwrap();
        let schema = action.result_schemas.as_ref().unwrap().success();
        assert_eq!(
            schema.pointer("/properties/transitions/items/properties/fields/properties/items/items/properties/allowedValues/properties/items/items/properties/id/type"),
            Some(&json!("string"))
        );
        let mut undeclared = outcome.result.clone();
        undeclared["transitions"][0]["to"]["rawStatus"] = json!(PRIVATE);
        assert!(
            agent_access_provider::test_support::check_result_conforms(
                action,
                &Ok(ProviderResult::new(undeclared)),
            )
            .is_err()
        );
        let mut wrong_type = outcome.result;
        wrong_type["transitions"][0]["fields"] = json!({"count":1,"truncated":false,"items":[{
            "id":"resolution","name":"Resolution","required":true,
            "hasDefaultValue":null,"brokerInput":"resolutionId",
            "allowedValues":{"count":1,"truncated":false,"items":[{"id":1,"name":"Fixed"}]}
        }]});
        assert!(
            agent_access_provider::test_support::check_result_conforms(
                action,
                &Ok(ProviderResult::new(wrong_type)),
            )
            .is_err()
        );
        assert_eq!(fixture.posts.load(Ordering::SeqCst), 0);
    }
}

#[tokio::test]
async fn transition_list_projects_names_destinations_and_only_safe_requested_fields() {
    let mut value = offered();
    value["transitions"][0]["fields"] = json!({
        "resolution":{"name":"Resolution","required":true,"hasDefaultValue":false,"allowedValues":[{"id":"1","name":"Fixed","description":PRIVATE,"self":PRIVATE}],"defaultValue":PRIVATE},
        "customfield_12345":{"name":"Approval","required":true,"hasDefaultValue":true,"allowedValues":[{"id":"23","name":PRIVATE}],"schema":{"custom":PRIVATE},"defaultValue":PRIVATE}
    });
    let fixture = Fixture::ready(value).await;
    let basic = fixture
        .invoke("issue.transition.list", json!({"issue":"PROJ-1"}))
        .await
        .unwrap();
    assert_eq!(basic.result["currentStatus"]["name"], "New");
    assert_eq!(basic.result["transitions"][0]["to"]["name"], "Stalled");
    assert!(basic.result["transitions"][0].get("fields").is_none());
    let expanded = fixture
        .invoke(
            "issue.transition.list",
            json!({"issue":"PROJ-1","includeFields":true}),
        )
        .await
        .unwrap();
    let fields = expanded.result["transitions"][0]["fields"]["items"]
        .as_array()
        .unwrap();
    let resolution = fields.iter().find(|f| f["id"] == "resolution").unwrap();
    assert_eq!(resolution["brokerInput"], "resolutionId");
    assert_eq!(
        resolution["allowedValues"]["items"],
        json!([{"id":"1","name":"Fixed"}])
    );
    let custom = fields
        .iter()
        .find(|f| f["id"] == "customfield_12345")
        .unwrap();
    assert_eq!(custom["brokerInput"], Value::Null);
    assert!(custom.get("allowedValues").is_none());
    assert!(!expanded.result.to_string().contains(PRIVATE));
    assert!(
        !expanded
            .audit
            .as_ref()
            .unwrap()
            .to_string()
            .contains("Stalled")
    );
    let requests = fixture.api.received_requests().await.unwrap();
    assert_eq!(requests.len(), 6);
    for group in requests.as_chunks::<3>().0 {
        assert_eq!(
            group[0].headers["authorization"],
            "Basic bG9va3VwQGV4YW1wbGUuY29tOmxvb2t1cC10b2tlbg=="
        );
        for request in &group[1..] {
            assert_eq!(
                request.headers["authorization"],
                "Basic c2VydmljZUBleGFtcGxlLmNvbTp0b2tlbg=="
            );
        }
        assert_eq!(group[2].url.path(), "/rest/api/3/issue/10001/transitions");
        assert!(
            !group[2]
                .url
                .as_str()
                .contains("includeUnavailableTransitions")
        );
        assert!(!group[2].url.as_str().contains("skipRemoteOnlyCondition"));
    }
    assert!(requests[2].url.query().is_none());
    assert_eq!(requests[5].url.query(), Some("expand=transitions.fields"));
}

#[tokio::test]
async fn transition_apply_posts_one_id_and_optional_resolution_then_observes_status() {
    for resolution in [None, Some("1")] {
        let fixture = Fixture::ready(offered()).await;
        let mut inputs = apply_inputs();
        if let Some(id) = resolution {
            inputs["resolutionId"] = json!(id);
        }
        let result = fixture
            .invoke("issue.transition.apply", inputs)
            .await
            .unwrap();
        assert_eq!(result.result["status"], "transitioned");
        assert_eq!(result.result["fromStatusId"], "10000");
        assert_eq!(result.result["toStatusId"], "10002");
        assert_eq!(result.result["verification"]["status"], "matched");
        assert_eq!(
            result.result["verification"]["observedStatus"]["name"],
            "Stalled"
        );
        assert_eq!(result.upstream_status, Some(204));
        assert_eq!(fixture.posts.load(Ordering::SeqCst), 1);
        let requests = fixture.api.received_requests().await.unwrap();
        assert_eq!(requests.len(), 5);
        assert_eq!(requests[2].url.query(), Some("transitionId=31"));
        assert_eq!(
            requests[3].url.path(),
            "/rest/api/3/issue/10001/transitions"
        );
        assert!(requests[3].url.query().is_none());
        let body: Value = serde_json::from_slice(&requests[3].body).unwrap();
        let mut expected = json!({"transition":{"id":"31"}});
        if let Some(id) = resolution {
            expected["fields"] = json!({"resolution":{"id":id}});
        }
        assert_eq!(body, expected);
        for request in &requests[1..] {
            assert_eq!(
                request.headers["authorization"],
                "Basic c2VydmljZUBleGFtcGxlLmNvbTp0b2tlbg=="
            );
        }
        assert!(
            !result
                .audit
                .as_ref()
                .unwrap()
                .to_string()
                .contains("Stalled")
        );
    }
}

#[tokio::test]
async fn transition_apply_refuses_stale_identity_status_or_destination_without_posting() {
    for (key, wrong, reason) in [
        ("expectedIssueId", "99999", "scope_unresolved"),
        ("expectedStatusId", "10002", "jira_transition_unavailable"),
        ("toStatusId", "10003", "jira_transition_unavailable"),
        ("transitionId", "41", "jira_transition_unavailable"),
    ] {
        let fixture = Fixture::ready(offered()).await;
        let mut inputs = apply_inputs();
        inputs[key] = json!(wrong);
        let error = fixture
            .invoke("issue.transition.apply", inputs)
            .await
            .unwrap_err();
        assert_eq!(error.reason_code().as_str(), reason);
        assert_eq!(fixture.posts.load(Ordering::SeqCst), 0);
        assert!(error.result.is_none());
        assert!(!error.message.contains("Stalled"));
    }
    for values in [json!({"transitions":[]}), {
        let mut v = offered();
        v["transitions"][0]["isAvailable"] = json!(false);
        v
    }] {
        let fixture = Fixture::ready(values).await;
        let error = fixture
            .invoke("issue.transition.apply", apply_inputs())
            .await
            .unwrap_err();
        assert_eq!(error.reason_code().as_str(), "jira_transition_unavailable");
        assert_eq!(fixture.posts.load(Ordering::SeqCst), 0);
    }
}

#[tokio::test]
async fn transition_projection_handles_empty_lists_and_bounds_collections() {
    let fixture = Fixture::ready(json!({"transitions":[]})).await;
    let result = fixture
        .invoke("issue.transition.list", json!({"issue":"PROJ-1"}))
        .await
        .unwrap();
    assert_eq!(result.result["transitions"], json!([]));
    assert_eq!(result.result["truncated"], false);
    let values = (1..=101)
        .map(|i| {
            let mut v = offered()["transitions"][0].clone();
            v["id"] = json!(i.to_string());
            v
        })
        .collect::<Vec<_>>();
    let fixture = Fixture::ready(json!({"transitions":values})).await;
    let result = fixture
        .invoke(
            "issue.transition.list",
            json!({"issue":"PROJ-1","includeFields":true}),
        )
        .await
        .unwrap();
    assert_eq!(result.result["count"], 100);
    assert_eq!(result.result["truncated"], true);
    assert_eq!(result.result["transitions"].as_array().unwrap().len(), 100);
}

#[tokio::test]
async fn transition_invalid_metadata_and_project_movement_fail_before_execution() {
    let mut malformed = Vec::new();
    for (key, value) in [
        ("name", json!("x".repeat(1025))),
        ("id", json!(31)),
        ("to", json!({"id":"10002"})),
        ("fields", json!([])),
    ] {
        let mut v = offered();
        v["transitions"][0][key] = value;
        malformed.push(v);
    }
    malformed.push(json!({"transitions":null}));
    malformed
        .push(json!({"transitions":[offered()["transitions"][0], offered()["transitions"][0]]}));
    for value in malformed {
        let fixture = Fixture::ready(value).await;
        let error = fixture
            .invoke(
                "issue.transition.list",
                json!({"issue":"PROJ-1","includeFields":true}),
            )
            .await
            .unwrap_err();
        assert_eq!(error.reason_code(), ReasonCode::UpstreamProtocolFailed);
    }
    let mut cases = Vec::new();
    for (key, value, reason) in [
        ("id", json!("99999"), ReasonCode::ScopeUnresolved),
        ("key", json!("OTHER-1"), ReasonCode::UpstreamProtocolFailed),
        (
            "fields",
            json!({"project":{"key":"OTHER"},"status":{"id":"10000","name":"New"}}),
            ReasonCode::UpstreamProtocolFailed,
        ),
    ] {
        let mut value_status = issue_status("10000", "New");
        value_status[key] = value;
        cases.push((value_status, reason));
    }
    let mut moved = issue_status("10000", "New");
    moved["key"] = json!("OTHER-1");
    moved["fields"]["project"]["key"] = json!("OTHER");
    cases.push((moved, ReasonCode::ScopeUnresolved));
    for (value, reason) in cases {
        for (action, inputs) in [
            ("issue.transition.list", json!({"issue":"PROJ-1"})),
            ("issue.transition.apply", apply_inputs()),
        ] {
            let fixture = Fixture::ready(offered()).await;
            Mock::given(method("GET"))
                .and(path("/rest/api/3/issue/10001"))
                .respond_with(ResponseTemplate::new(200).set_body_json(value.clone()))
                .with_priority(1)
                .mount(&fixture.api)
                .await;
            let error = fixture.invoke(action, inputs).await.unwrap_err();
            assert_eq!(error.reason_code(), reason);
            assert_eq!(fixture.posts.load(Ordering::SeqCst), 0);
            let requests = fixture.api.received_requests().await.unwrap();
            assert_eq!(requests.len(), 2);
            assert!(
                requests
                    .iter()
                    .all(|r| !r.url.path().ends_with("/transitions"))
            );
        }
    }
}

#[tokio::test]
async fn transition_readback_difference_succeeds_and_failure_keeps_applied_receipt() {
    let fixture = Fixture::new(
        offered(),
        ResponseTemplate::new(204),
        ResponseTemplate::new(200).set_body_json(issue_status("10003", "Automated next state")),
    )
    .await;
    let result = fixture
        .invoke("issue.transition.apply", apply_inputs())
        .await
        .unwrap();
    assert_eq!(result.result["status"], "transitioned");
    assert_eq!(result.result["verification"]["status"], "differs");
    for response in [
        ResponseTemplate::new(403),
        ResponseTemplate::new(200).set_body_json(json!({})),
        ResponseTemplate::new(200).set_body_json({
            let mut v = issue_status("10002", "Stalled");
            v["id"] = json!("99999");
            v
        }),
    ] {
        let fixture = Fixture::new(offered(), ResponseTemplate::new(204), response).await;
        let error = fixture
            .invoke("issue.transition.apply", apply_inputs())
            .await
            .unwrap_err();
        let receipt = error.result.as_ref().unwrap();
        assert_eq!(receipt["mutationStatus"], "applied_unverified");
        assert_eq!(receipt["retrySafe"], false);
        assert_eq!(receipt["verificationStage"], "post_transition_readback");
        assert_eq!(fixture.posts.load(Ordering::SeqCst), 1);
    }
}

#[tokio::test]
async fn transition_upstream_rejection_is_private_and_ambiguous_writes_are_not_replayed() {
    for (status, reason, mutation) in [
        (400, "jira_transition_rejected", None),
        (422, "jira_transition_rejected", None),
        (403, "upstream_forbidden", None),
        (409, "jira_transition_unavailable", None),
        (503, "upstream_failed", Some("unknown")),
        (200, "upstream_protocol_failed", Some("applied_unverified")),
    ] {
        let fixture = Fixture::new(
            offered(),
            ResponseTemplate::new(status).set_body_json(json!({"errors":{"resolution":PRIVATE}})),
            ResponseTemplate::new(200),
        )
        .await;
        let error = fixture
            .invoke("issue.transition.apply", apply_inputs())
            .await
            .unwrap_err();
        assert_eq!(error.reason_code().as_str(), reason, "{error:?}");
        assert!(!format!("{error:?}").contains(PRIVATE));
        match mutation {
            Some(mutation) => {
                assert_eq!(error.result.as_ref().unwrap()["mutationStatus"], mutation);
                assert_eq!(error.result.as_ref().unwrap()["retrySafe"], false);
            }
            None => assert!(error.result.is_none()),
        }
        assert_eq!(fixture.posts.load(Ordering::SeqCst), 1);
        assert_eq!(fixture.api.received_requests().await.unwrap().len(), 4);
    }
}

#[tokio::test]
async fn transition_timeout_after_post_keeps_unknown_receipt_without_replay() {
    let mut fixture = Fixture::new(
        offered(),
        ResponseTemplate::new(204).set_delay(Duration::from_secs(2)),
        ResponseTemplate::new(200),
    )
    .await;
    let config = fixture.provider.config.clone();
    let limits = ProviderLimits::default().with_request_timeout_ms(500);
    let backend = HttpJiraBackend::new_with_api_base(
        config.clone(),
        limits.clone(),
        Url::parse(&format!("{}/rest/api/3/", fixture.api.uri())).unwrap(),
    );
    fixture.provider = JiraProvider::from_backend(config, limits, Arc::new(backend));
    let error = fixture
        .invoke("issue.transition.apply", apply_inputs())
        .await
        .unwrap_err();
    assert_eq!(error.reason_code(), ReasonCode::UpstreamTimeout);
    assert_eq!(error.result.as_ref().unwrap()["mutationStatus"], "unknown");
    assert_eq!(error.result.as_ref().unwrap()["retrySafe"], false);
    assert_eq!(fixture.posts.load(Ordering::SeqCst), 1);
    assert_eq!(fixture.api.received_requests().await.unwrap().len(), 4);
}

#[tokio::test]
async fn transition_names_and_destinations_do_not_collapse_distinct_transition_ids() {
    let mut value = offered();
    let mut other = value["transitions"][0].clone();
    other["id"] = json!("41");
    value["transitions"]
        .as_array_mut()
        .unwrap()
        .push(other.clone());
    let fixture = Fixture::ready(value).await;
    let result = fixture
        .invoke("issue.transition.list", json!({"issue":"PROJ-1"}))
        .await
        .unwrap();
    assert_eq!(result.result["count"], 2);
    assert_eq!(result.result["transitions"][0]["id"], "31");
    assert_eq!(result.result["transitions"][1]["id"], "41");
    Mock::given(method("GET"))
        .and(path("/rest/api/3/issue/10001/transitions"))
        .and(query_param("transitionId", "41"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"transitions":[other]})))
        .with_priority(1)
        .mount(&fixture.api)
        .await;
    let mut inputs = apply_inputs();
    inputs["transitionId"] = json!("41");
    let result = fixture
        .invoke("issue.transition.apply", inputs)
        .await
        .unwrap();
    assert_eq!(result.result["transitionId"], "41");
    let requests = fixture.api.received_requests().await.unwrap();
    let post = requests.iter().find(|r| r.method == "POST").unwrap();
    assert_eq!(
        serde_json::from_slice::<Value>(&post.body).unwrap(),
        json!({"transition":{"id":"41"}})
    );
}

#[tokio::test]
async fn transition_field_limit_retains_resolution_and_bounds_its_choices() {
    let mut fields = (1..=101)
        .map(|i| {
            (
                format!("customfield_{i}"),
                json!({"name":"Custom field","required":false}),
            )
        })
        .collect::<serde_json::Map<_, _>>();
    fields.insert("resolution".into(), json!({"name":"Resolution","required":true,"allowedValues":(1..=101).map(|i|json!({"id":i.to_string(),"name":"Choice"})).collect::<Vec<_>>()}));
    let mut value = offered();
    value["transitions"][0]["fields"] = json!(fields);
    let fixture = Fixture::ready(value).await;
    let response = fixture
        .invoke(
            "issue.transition.list",
            json!({"issue":"PROJ-1","includeFields":true}),
        )
        .await
        .unwrap();
    let fields = &response.result["transitions"][0]["fields"];
    assert_eq!(fields["count"], 100);
    assert_eq!(fields["items"].as_array().unwrap().len(), 100);
    assert_eq!(fields["truncated"], true);
    let resolution = &fields["items"][0];
    assert_eq!(resolution["id"], "resolution");
    assert_eq!(resolution["brokerInput"], "resolutionId");
    assert_eq!(resolution["allowedValues"]["count"], 100);
    assert_eq!(
        resolution["allowedValues"]["items"]
            .as_array()
            .unwrap()
            .len(),
        100
    );
    assert_eq!(resolution["allowedValues"]["truncated"], true);
}
