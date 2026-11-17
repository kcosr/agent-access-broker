use super::*;
use std::sync::atomic::{AtomicBool, Ordering};
use wiremock::matchers::{body_json, query_param};

const FIELD_ID: &str = "customfield_12345";
const LINK: &str = "https://reports.example/#/jobs/check/issues/7?view=runs&run=latest";

fn inputs() -> Value {
    json!({"issue":"PROJ-1", "fieldId":FIELD_ID, "value":LINK, "expectedValue":null, "expectedIssueId":"10001"})
}

fn field_response(value: Value) -> Value {
    json!({
        "id":"10001", "key":"PROJ-1",
        "fields":{"project":{"key":"PROJ"}, FIELD_ID: value},
        "names":{FIELD_ID:"Field name sentinel"},
        "schema":{FIELD_ID:{"type":"string", "custom":"com.atlassian.jira.plugin.system.customfieldtypes:url"}},
    })
}

fn invocation(inputs: Value) -> ProviderInvocation {
    InvocationBuilder::new("jira", "issue.url_field.set")
        .inputs(inputs)
        .resources(BTreeMap::from([("project".into(), vec!["PROJ".into()])]))
        .credential(test_credential())
        .lookup_credential(test_lookup_credential())
        .build()
}

struct Fixture {
    api: MockServer,
    provider: JiraProvider,
}

impl Fixture {
    async fn new(before: Value, after: Value, put_status: u16) -> Self {
        let api = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/rest/api/3/issue/PROJ-1"))
            .and(query_param("fields", "project"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "id":"10001", "key":"PROJ-1", "fields":{"project":{"key":"PROJ"}},
            })))
            .mount(&api)
            .await;
        let written = Arc::new(AtomicBool::new(false));
        let check_written = written.clone();
        Mock::given(method("GET"))
            .and(path("/rest/api/3/issue/10001"))
            .and(query_param("fields", "project,customfield_12345"))
            .and(query_param("expand", "names,schema"))
            .respond_with(move |_: &wiremock::Request| {
                ResponseTemplate::new(200).set_body_json(if check_written.load(Ordering::SeqCst) {
                    after.clone()
                } else {
                    before.clone()
                })
            })
            .mount(&api)
            .await;
        Mock::given(method("PUT"))
            .and(path("/rest/api/3/issue/10001"))
            .and(body_json(json!({"fields":{FIELD_ID:LINK}})))
            .respond_with(move |_: &wiremock::Request| {
                written.store(true, Ordering::SeqCst);
                ResponseTemplate::new(put_status)
            })
            .mount(&api)
            .await;
        let mut config = jira_config();
        config.url_fields.allowed_field_ids = vec![FIELD_ID.into()];
        config.allowed_upstream_hosts = vec![format!("{}/rest/api/3/**", api.uri())];
        let limits = ProviderLimits::default();
        let backend = HttpJiraBackend::new_with_api_base(
            config.clone(),
            limits.clone(),
            Url::parse(&format!("{}/rest/api/3/", api.uri())).unwrap(),
        );
        let provider = JiraProvider::from_backend(config, limits, Arc::new(backend));
        Self { api, provider }
    }

    async fn puts(&self) -> usize {
        self.api
            .received_requests()
            .await
            .unwrap()
            .iter()
            .filter(|request| request.method.as_str() == "PUT")
            .count()
    }
}

#[test]
fn url_field_inputs_reject_ambiguous_unsafe_or_unbounded_values() {
    let config = jira_config();
    assert!(url_field::parse_inputs(&inputs(), &config).is_ok());
    let mut url_locator = inputs();
    url_locator.as_object_mut().unwrap().remove("issue");
    url_locator["url"] = json!("https://example.atlassian.net/browse/PROJ-1");
    assert!(url_field::parse_inputs(&url_locator, &config).is_ok());
    for (field, value) in [
        ("value", json!("javascript:alert(1)")),
        ("value", json!("https:reports.example")),
        ("value", json!("https://user:password@reports.example/")),
        ("value", json!("https://reports.example/line\nsecret")),
        ("value", json!("https://reports.example/with space")),
        ("value", json!("https://reports.example/\\x")),
        (
            "value",
            json!(format!("https://reports.example/{}", "x".repeat(256))),
        ),
        ("value", Value::Null),
        ("fieldId", json!("summary")),
        ("fieldId", json!("customfield_0123")),
        ("fieldId", json!("customfield_123?fields=summary")),
        ("expectedValue", json!(1)),
        ("expectedValue", json!("x".repeat(256))),
        ("expectedIssueId", json!("10001/../../issue/OTHER-1")),
        ("expectedIssueId", json!("001")),
        ("expectedIssueId", Value::Null),
        ("extra", json!("caller-secret")),
    ] {
        let mut candidate = inputs();
        candidate[field] = value;
        let error = url_field::parse_inputs(&candidate, &config).err().unwrap();
        assert_eq!(error.reason_code(), ReasonCode::InputInvalid);
        assert!(!error.message.contains("reports.example"));
        assert!(!error.message.contains("caller-secret"));
    }
    let mut missing = inputs();
    missing.as_object_mut().unwrap().remove("expectedValue");
    assert!(url_field::parse_inputs(&missing, &config).is_err());
    let mut maximum = inputs();
    maximum["value"] = json!(format!(
        "https://reports.example/{}",
        "x".repeat(255 - "https://reports.example/".len())
    ));
    assert!(url_field::parse_inputs(&maximum, &config).is_ok());
}

#[test]
fn url_field_config_requires_unique_canonical_ids_and_defaults_to_disabled() {
    let mut config = jira_config();
    assert!(config.url_fields.allowed_field_ids.is_empty());
    let limits = ProviderLimits::default();
    let context = ValidationContext::new(
        "development",
        "managed",
        &limits,
        ServiceCredentialKinds::default()
            .with_service(Some(CredentialSource::static_kind("basic_api_token"))),
    );
    for fields in [
        vec!["summary"],
        vec!["customfield_0"],
        vec![FIELD_ID, FIELD_ID],
    ] {
        config.url_fields.allowed_field_ids = fields.into_iter().map(str::to_string).collect();
        let mut errors = Vec::new();
        config.validate(&context, &mut errors);
        assert!(
            errors
                .iter()
                .any(|error| error.contains("url_fields.allowed_field_ids")),
            "{errors:?}"
        );
    }
    config.url_fields.allowed_field_ids = vec![FIELD_ID.into()];
    let mut errors = Vec::new();
    config.validate(&context, &mut errors);
    assert!(errors.is_empty(), "{errors:?}");
    let descriptor = config.descriptor();
    let action = descriptor.action("issue.url_field.set").unwrap();
    assert!(!action.read_only);
    assert_eq!(action.required_scope_types(), ["project"]);
    assert_eq!(action.lookup, LookupRequirement::ScopeResolution);
    assert_eq!(
        action.sensitive_output_pointers,
        ["/result/field/value", "/result/field/name"]
    );
    assert_eq!(
        action.documentation.as_ref().unwrap()["allowedFieldIds"],
        json!([FIELD_ID])
    );
}

#[tokio::test]
async fn url_field_set_targets_immutable_issue_id_preserves_url_and_replays_without_writing() {
    let fixture = Fixture::new(
        field_response(Value::Null),
        field_response(json!(LINK)),
        204,
    )
    .await;
    let result = fixture.provider.invoke(invocation(inputs())).await.unwrap();
    assert_eq!(
        result.result,
        json!({
            "operation":"issue.url_field.set",
            "issue":{"id":"10001","key":"PROJ-1","project":"PROJ","webUrl":"https://example.atlassian.net/browse/PROJ-1"},
            "field":{"id":FIELD_ID,"name":"Field name sentinel","type":"url","value":LINK},
            "changed":true,
        })
    );
    let audit = format!("{:?} {:?}", result.audit, result.object_ids);
    assert!(!audit.contains("reports.example"));
    assert!(!audit.contains("sentinel"));
    let retry = fixture.provider.invoke(invocation(inputs())).await.unwrap();
    assert_eq!(retry.result["changed"], false);
    assert_eq!(retry.result["field"]["value"], LINK);
    assert_eq!(fixture.puts().await, 1);
    let requests = fixture.api.received_requests().await.unwrap();
    let update = requests
        .iter()
        .find(|request| request.method.as_str() == "PUT")
        .unwrap();
    assert_eq!(update.url.path(), "/rest/api/3/issue/10001");
    assert!(update.url.query().is_none());
    assert_eq!(
        serde_json::from_slice::<Value>(&update.body).unwrap(),
        json!({"fields":{FIELD_ID:LINK}})
    );
    for request in requests {
        let authorization = request
            .headers
            .get("authorization")
            .unwrap()
            .to_str()
            .unwrap();
        if request.url.path().ends_with("/PROJ-1") {
            assert_eq!(
                authorization,
                "Basic bG9va3VwQGV4YW1wbGUuY29tOmxvb2t1cC10b2tlbg=="
            );
        } else {
            assert_eq!(authorization, "Basic c2VydmljZUBleGFtcGxlLmNvbTp0b2tlbg==");
        }
    }
}

#[tokio::test]
async fn url_field_refuses_foreign_values_but_accepts_explicit_expected_previous_value() {
    let prior = "https://old-reports.example/subject/7";
    let fixture = Fixture::new(
        field_response(json!(prior)),
        field_response(json!(LINK)),
        204,
    )
    .await;
    let error = fixture
        .provider
        .invoke(invocation(inputs()))
        .await
        .unwrap_err();
    assert_eq!(error.reason_code().as_str(), "jira_url_field_conflict");
    assert_eq!(error.decision(), Decision::Deny);
    assert!(error.result.is_none());
    assert!(!error.message.contains(prior));
    assert_eq!(fixture.puts().await, 0);
    let mut expected = inputs();
    expected["expectedValue"] = json!(prior);
    assert_eq!(
        fixture
            .provider
            .invoke(invocation(expected))
            .await
            .unwrap()
            .result["changed"],
        true
    );
    assert_eq!(fixture.puts().await, 1);
}

#[tokio::test]
async fn url_field_default_allowlist_blocks_lookup_and_invocation_without_upstream_requests() {
    let mut fixture = Fixture::new(
        field_response(Value::Null),
        field_response(json!(LINK)),
        204,
    )
    .await;
    fixture.provider.config.url_fields.allowed_field_ids.clear();
    let lookup_error = fixture
        .provider
        .lookup_scopes(
            "issue.url_field.set",
            &inputs(),
            Some(&AtlassianCredential::from_static(test_lookup_credential())),
        )
        .await
        .unwrap_err();
    assert_eq!(
        lookup_error.reason_code().as_str(),
        "jira_url_field_not_allowed"
    );
    let invoke_error = fixture
        .provider
        .invoke(invocation(inputs()))
        .await
        .unwrap_err();
    assert_eq!(
        invoke_error.reason_code().as_str(),
        "jira_url_field_not_allowed"
    );
    assert!(fixture.api.received_requests().await.unwrap().is_empty());
}

#[tokio::test]
async fn url_field_checks_current_project_and_expected_immutable_identity_before_field_access() {
    let fixture = Fixture::new(
        field_response(Value::Null),
        field_response(json!(LINK)),
        204,
    )
    .await;
    let outside = InvocationBuilder::from(invocation(inputs()))
        .resources(BTreeMap::from([("project".into(), vec!["OTHER".into()])]))
        .build();
    assert_eq!(
        fixture
            .provider
            .invoke(outside)
            .await
            .unwrap_err()
            .reason_code(),
        ReasonCode::ScopeUnresolved
    );
    let mut wrong_identity = inputs();
    wrong_identity["expectedIssueId"] = json!("20002");
    assert_eq!(
        fixture
            .provider
            .invoke(invocation(wrong_identity))
            .await
            .unwrap_err()
            .reason_code(),
        ReasonCode::ScopeUnresolved
    );
    assert!(
        fixture
            .api
            .received_requests()
            .await
            .unwrap()
            .iter()
            .all(|request| request.url.path().ends_with("/PROJ-1"))
    );
}

#[tokio::test]
async fn url_field_requires_present_exact_builtin_url_schema_and_matching_issue() {
    let mut absent = field_response(Value::Null);
    absent["fields"].as_object_mut().unwrap().remove(FIELD_ID);
    let mut wrong_type = field_response(Value::Null);
    wrong_type["schema"][FIELD_ID]["custom"] = json!("third-party:secret-url");
    let mut wrong_json_type = field_response(Value::Null);
    wrong_json_type["schema"][FIELD_ID]["type"] = json!("object");
    let mut wrong_issue = field_response(Value::Null);
    wrong_issue["id"] = json!("20002");
    for (before, reason) in [
        (absent, "jira_url_field_not_settable"),
        (wrong_type, "jira_url_field_not_settable"),
        (wrong_json_type, "jira_url_field_not_settable"),
        (wrong_issue, "scope_unresolved"),
        (
            field_response(json!({"secret":"sentinel"})),
            "upstream_protocol_failed",
        ),
    ] {
        let fixture = Fixture::new(before, field_response(json!(LINK)), 204).await;
        let error = fixture
            .provider
            .invoke(invocation(inputs()))
            .await
            .unwrap_err();
        assert_eq!(error.reason_code().as_str(), reason);
        assert!(error.result.is_none());
        assert!(!error.message.contains("sentinel"));
        assert_eq!(fixture.puts().await, 0);
    }
}

#[tokio::test]
async fn url_field_jira_rejections_are_definite_and_server_errors_remain_uncertain() {
    for status in [400, 403, 422, 500] {
        let fixture = Fixture::new(
            field_response(Value::Null),
            field_response(json!(LINK)),
            status,
        )
        .await;
        let error = fixture
            .provider
            .invoke(invocation(inputs()))
            .await
            .unwrap_err();
        assert_eq!(fixture.puts().await, 1);
        if status == 500 {
            assert_eq!(error.reason_code(), ReasonCode::UpstreamFailed);
            assert_eq!(
                error.result.as_deref().unwrap()["mutationStatus"],
                "unknown"
            );
        } else {
            assert_eq!(error.reason_code().as_str(), "jira_url_field_not_settable");
            assert_eq!(error.upstream_status, Some(status));
            assert!(error.result.is_none());
        }
    }
}

#[tokio::test]
async fn url_field_readback_mismatch_preserves_applied_unverified_receipt() {
    let fixture = Fixture::new(
        field_response(Value::Null),
        field_response(json!("https://other.example/")),
        204,
    )
    .await;
    let error = fixture
        .provider
        .invoke(invocation(inputs()))
        .await
        .unwrap_err();
    assert_eq!(error.reason_code(), ReasonCode::VerificationMismatch);
    assert_eq!(
        error.result.as_deref().unwrap()["mutationStatus"],
        "applied_unverified"
    );
    assert_eq!(error.result.as_deref().unwrap()["retrySafe"], false);
    assert_eq!(fixture.puts().await, 1);
    assert!(!format!("{error:?}").contains("other.example"));
}
