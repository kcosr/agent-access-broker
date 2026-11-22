use super::*;
use wiremock::matchers::query_param;

const FIELD_ID: &str = "customfield_12345";
const SENTINEL: &str = "private custom-field value sentinel";

fn inputs(value: Value) -> Value {
    json!({"issue":"PROJ-1", "fieldId":FIELD_ID, "value":value, "expectedIssueId":"10001"})
}

fn invocation(inputs: Value) -> ProviderInvocation {
    InvocationBuilder::new("jira", "issue.custom_field.set")
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
    async fn new(response: ResponseTemplate) -> Self {
        let api = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/rest/api/3/issue/PROJ-1"))
            .and(query_param("fields", "project"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "id":"10001", "key":"PROJ-1", "fields":{"project":{"key":"PROJ"}},
            })))
            .mount(&api)
            .await;
        Mock::given(method("PUT"))
            .and(path("/rest/api/3/issue/10001"))
            .respond_with(response)
            .mount(&api)
            .await;
        let mut config = jira_config();
        config.custom_fields.allowed_field_ids = vec![FIELD_ID.into()];
        config.allowed_upstream_hosts = vec![format!("{}/rest/api/3/**", api.uri())];
        let mut limits = ProviderLimits::default();
        limits.max_upstream_response_bytes = 1024;
        let backend = HttpJiraBackend::new_with_api_base(
            config.clone(),
            limits.clone(),
            Url::parse(&format!("{}/rest/api/3/", api.uri())).unwrap(),
        );
        Self {
            api,
            provider: JiraProvider::from_backend(config, limits, Arc::new(backend)),
        }
    }
}

#[test]
fn custom_field_inputs_require_value_and_preserve_all_json_types() {
    let config = jira_config();
    let validator =
        jsonschema::validator_for(&custom_field::descriptor(&config.custom_fields).input_schema)
            .unwrap();
    for value in [
        json!(1),
        json!(1.5),
        json!("1"),
        json!({"id":"17"}),
        json!(["a", false, null]),
        json!(true),
        Value::Null,
    ] {
        let candidate = inputs(value);
        assert!(custom_field::parse_inputs(&candidate, &config).is_ok());
        assert!(validator.is_valid(&candidate));
    }
    let mut absent = inputs(Value::Null);
    absent.as_object_mut().unwrap().remove("value");
    assert_eq!(
        custom_field::parse_inputs(&absent, &config)
            .err()
            .unwrap()
            .reason_code(),
        ReasonCode::InputInvalid
    );
    assert!(!validator.is_valid(&absent));
    for (field, value) in [
        ("fieldId", json!("summary")),
        ("fieldId", json!("customfield_01")),
        ("fieldId", json!("customfield_0")),
        ("expectedIssueId", Value::Null),
        ("expectedIssueId", json!("01")),
        ("expectedValue", Value::Null),
        ("notifyUsers", json!(false)),
    ] {
        let mut candidate = inputs(Value::Null);
        candidate[field] = value;
        assert_eq!(
            custom_field::parse_inputs(&candidate, &config)
                .err()
                .unwrap()
                .reason_code(),
            ReasonCode::InputInvalid
        );
    }
    let mut nullable_url = inputs(Value::Null);
    nullable_url["url"] = Value::Null;
    let mut url_locator = nullable_url.clone();
    url_locator["issue"] = Value::Null;
    url_locator["url"] = json!("https://example.atlassian.net/browse/PROJ-1");
    for candidate in [nullable_url, url_locator] {
        assert!(custom_field::parse_inputs(&candidate, &config).is_ok());
        assert!(validator.is_valid(&candidate));
    }
}

#[test]
fn custom_field_config_requires_unique_canonical_ids_and_defaults_to_disabled() {
    let mut config = jira_config();
    assert!(config.custom_fields.allowed_field_ids.is_empty());
    assert!(
        config
            .descriptor()
            .action("issue.custom_field.set")
            .is_some()
    );
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
        vec!["customfield_01"],
        vec![FIELD_ID, FIELD_ID],
    ] {
        config.custom_fields.allowed_field_ids = fields.into_iter().map(str::to_string).collect();
        let mut errors = Vec::new();
        config.validate(&context, &mut errors);
        assert!(
            errors
                .iter()
                .any(|error| error.contains("custom_fields.allowed_field_ids")),
            "{errors:?}"
        );
    }
    config.custom_fields.allowed_field_ids = vec![FIELD_ID.into()];
    let mut errors = Vec::new();
    config.validate(&context, &mut errors);
    assert!(errors.is_empty(), "{errors:?}");
    let descriptor = config.descriptor();
    let action = descriptor.action("issue.custom_field.set").unwrap();
    assert!(!action.read_only);
    assert_eq!(action.required_scope_types(), ["project"]);
    assert_eq!(action.lookup, LookupRequirement::ScopeResolution);
    assert!(action.sensitive_output_pointers.is_empty());
    assert_eq!(
        action.documentation.as_ref().unwrap()["allowedFieldIds"],
        json!([FIELD_ID])
    );
}

#[tokio::test]
async fn custom_field_put_preserves_json_targets_immutable_id_and_does_not_read_field() {
    let fixture = Fixture::new(ResponseTemplate::new(204)).await;
    let values = [
        json!(1),
        json!(1.5),
        json!("1"),
        json!({"id":"17","text":SENTINEL}),
        json!(["a", false, null]),
        json!(true),
        Value::Null,
        json!("{\"nested\":true}"),
    ];
    for value in &values {
        let result = fixture
            .provider
            .invoke_checked(invocation(inputs(value.clone())))
            .await
            .unwrap();
        assert_eq!(
            result.result,
            json!({"operation":"issue.custom_field.set","issue":{"id":"10001","key":"PROJ-1","project":"PROJ","webUrl":"https://example.atlassian.net/browse/PROJ-1"},"fieldId":FIELD_ID,"status":"set"})
        );
        assert!(!format!("{:?} {:?}", result.audit, result.object_ids).contains(SENTINEL));
    }
    let requests = fixture.api.received_requests().await.unwrap();
    assert_eq!(requests.len(), values.len() * 2);
    for (pair, value) in requests.as_chunks::<2>().0.iter().zip(values) {
        assert_eq!(pair[0].method.as_str(), "GET");
        assert_eq!(pair[0].url.path(), "/rest/api/3/issue/PROJ-1");
        assert_eq!(pair[0].url.query(), Some("fields=project"));
        assert_eq!(
            pair[0].headers.get("authorization").unwrap(),
            "Basic bG9va3VwQGV4YW1wbGUuY29tOmxvb2t1cC10b2tlbg=="
        );
        assert_eq!(pair[1].method.as_str(), "PUT");
        assert_eq!(pair[1].url.path(), "/rest/api/3/issue/10001");
        assert!(pair[1].url.query().is_none());
        assert_eq!(
            pair[1].headers.get("authorization").unwrap(),
            "Basic c2VydmljZUBleGFtcGxlLmNvbTp0b2tlbg=="
        );
        assert_eq!(
            serde_json::from_slice::<Value>(&pair[1].body).unwrap(),
            json!({"fields":{FIELD_ID:value}})
        );
    }
}

#[tokio::test]
async fn custom_field_allowlist_size_and_identity_guards_precede_write() {
    let mut fixture = Fixture::new(ResponseTemplate::new(204)).await;
    fixture
        .provider
        .config
        .custom_fields
        .allowed_field_ids
        .clear();
    assert_eq!(
        fixture
            .provider
            .invoke_checked(invocation(inputs(Value::Null)))
            .await
            .unwrap_err()
            .reason_code()
            .as_str(),
        "jira_custom_field_not_allowed"
    );
    assert!(fixture.api.received_requests().await.unwrap().is_empty());
    fixture
        .provider
        .config
        .custom_fields
        .allowed_field_ids
        .push(FIELD_ID.into());
    fixture.provider.config.content.max_body_bytes = 3;
    // Quoted JSON string is four bytes, although its raw text is two bytes.
    assert_eq!(
        fixture
            .provider
            .invoke_checked(invocation(inputs(json!("ab"))))
            .await
            .unwrap_err()
            .reason_code(),
        ReasonCode::BodySizeDenied
    );
    assert!(fixture.api.received_requests().await.unwrap().is_empty());
    fixture.provider.config.content.max_body_bytes = 4;
    fixture
        .provider
        .invoke_checked(invocation(inputs(json!("ab"))))
        .await
        .unwrap();
    fixture.api.reset().await;
    let fixture = Fixture::new(ResponseTemplate::new(204)).await;
    let outside = InvocationBuilder::from(invocation(inputs(Value::Null)))
        .resources(BTreeMap::from([("project".into(), vec!["OTHER".into()])]))
        .build();
    assert_eq!(
        fixture
            .provider
            .invoke_checked(outside)
            .await
            .unwrap_err()
            .reason_code(),
        ReasonCode::ScopeUnresolved
    );
    let mut wrong = inputs(Value::Null);
    wrong["expectedIssueId"] = json!("20002");
    assert_eq!(
        fixture
            .provider
            .invoke_checked(invocation(wrong))
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
            .all(|request| request.method.as_str() == "GET")
    );
}

#[tokio::test]
async fn custom_field_reconfirms_current_key_and_refuses_noncanonical_immutable_ids() {
    for id in ["", "0", "01", "../10001"] {
        let fixture = Fixture::new(ResponseTemplate::new(204)).await;
        fixture.api.reset().await;
        Mock::given(method("GET"))
            .and(path("/rest/api/3/issue/PROJ-1"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "id": id, "key":"PROJ-1", "fields":{"project":{"key":"PROJ"}}
            })))
            .mount(&fixture.api)
            .await;
        let error = fixture
            .provider
            .invoke_checked(invocation(inputs(Value::Null)))
            .await
            .unwrap_err();
        assert_eq!(error.reason_code(), ReasonCode::UpstreamProtocolFailed);
        assert!(
            fixture
                .api
                .received_requests()
                .await
                .unwrap()
                .iter()
                .all(|request| request.method.as_str() == "GET")
        );
    }
    let fixture = Fixture::new(ResponseTemplate::new(204)).await;
    Mock::given(method("GET"))
        .and(path("/rest/api/3/issue/PROJ-1"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id":"10001", "key":"PROJ-2", "fields":{"project":{"key":"PROJ"}}
        })))
        .with_priority(1)
        .mount(&fixture.api)
        .await;
    let result = fixture
        .provider
        .invoke_checked(invocation(inputs(Value::Null)))
        .await
        .unwrap();
    assert_eq!(result.result["issue"]["key"], "PROJ-2");
    assert_eq!(result.result["issue"]["id"], "10001");
    let requests = fixture.api.received_requests().await.unwrap();
    assert_eq!(requests.len(), 2);
    assert_eq!(requests[1].url.path(), "/rest/api/3/issue/10001");
}

#[tokio::test]
async fn custom_field_rejections_are_value_free_and_standard_statuses_keep_their_reasons() {
    for (status, reason) in [
        (400, "jira_custom_field_rejected"),
        (422, "jira_custom_field_rejected"),
        (401, "upstream_unauthorized"),
        (403, "upstream_forbidden"),
        (404, "scope_unresolved"),
    ] {
        let fixture = Fixture::new(
            ResponseTemplate::new(status)
                .set_body_json(json!({"errorMessages":[SENTINEL],"errors":{FIELD_ID:SENTINEL}})),
        )
        .await;
        let capture = agent_access_provider::test_support::install_trace_capture().start();
        let error = capture
            .run(agent_access_provider::host::with_provider_context(
                CorrelationContext::for_tests(),
                "jira".to_string(),
                "issue.custom_field.set".to_string(),
                agent_access_provider::host::with_hook_context(
                    agent_access_provider::host::hook_context(
                        "jira",
                        "issue.custom_field.set",
                        HookPhase::Invocation,
                        JIRA_BACKEND.domain_reasons(),
                    ),
                    fixture
                        .provider
                        .invoke_checked(invocation(inputs(json!(SENTINEL)))),
                ),
            ))
            .await
            .unwrap_err();
        assert_eq!(error.reason_code().as_str(), reason);
        assert_eq!(
            error.upstream_status,
            matches!(status, 400 | 422).then_some(status)
        );
        assert!(error.result.is_none());
        assert!(!format!("{error:?}").contains(SENTINEL));
        let events = capture.take_events();
        assert!(
            !events
                .iter()
                .any(|event| event["event"] == "provider_contract_failed")
        );
        let writes = events
            .iter()
            .filter(|event| {
                event["event"] == "upstream_request_completed"
                    && event["upstreamOperation"] == "issue.custom_field.set"
            })
            .collect::<Vec<_>>();
        assert_eq!(writes.len(), 1, "{events:?}");
        assert_eq!(writes[0]["reasonCode"], reason);
        assert_eq!(writes[0]["http.statusCode"], status);
        assert!(!serde_json::to_string(&events).unwrap().contains(SENTINEL));
    }
}

#[tokio::test]
async fn custom_field_http_acceptance_and_redirects_preserve_receipts_without_readback() {
    for (response, expected) in [
        (ResponseTemplate::new(503), "unknown"),
        (
            ResponseTemplate::new(302).insert_header("Location", "https://other.example/"),
            "unknown",
        ),
        (
            ResponseTemplate::new(200).set_body_bytes(vec![b'x'; 1025]),
            "applied_unverified",
        ),
    ] {
        let fixture = Fixture::new(response).await;
        let error = fixture
            .provider
            .invoke_checked(invocation(inputs(json!(SENTINEL))))
            .await
            .unwrap_err();
        assert_eq!(error.result.as_deref().unwrap()["mutationStatus"], expected);
        assert_eq!(fixture.api.received_requests().await.unwrap().len(), 2);
        assert!(!format!("{error:?}").contains(SENTINEL));
    }
}

#[tokio::test]
async fn custom_field_transport_and_result_construction_failures_preserve_safe_receipts() {
    for (error, status) in [
        (
            JiraBackendError::NotSent { timed_out: false },
            "not_applied",
        ),
        (JiraBackendError::NoResponse { timed_out: true }, "unknown"),
        (
            JiraBackendError::AcceptedUnreadable(Box::new(JiraBackendError::Timeout)),
            "applied_unverified",
        ),
    ] {
        let mut backend = StubJiraBackend::default();
        backend.issues.insert("PROJ-1".into(), visible_issue());
        *backend.custom_field_error.lock().unwrap() = Some(error);
        let mut config = jira_config();
        config.custom_fields.allowed_field_ids = vec![FIELD_ID.into()];
        let provider =
            JiraProvider::with_backend(config, ProviderLimits::default(), Arc::new(backend));
        let error = provider
            .invoke_checked(invocation(inputs(json!(SENTINEL))))
            .await
            .unwrap_err();
        assert_eq!(error.result.as_deref().unwrap()["mutationStatus"], status);
        assert!(!format!("{error:?}").contains(SENTINEL));
    }
    let mut fixture = Fixture::new(ResponseTemplate::new(204)).await;
    fixture.provider.limits.max_upstream_response_bytes = 1;
    let error = fixture
        .provider
        .invoke_checked(invocation(inputs(json!(SENTINEL))))
        .await
        .unwrap_err();
    assert_eq!(
        error.result.as_deref().unwrap()["mutationStatus"],
        "applied_unverified"
    );
    assert_eq!(
        error.result.as_deref().unwrap()["verificationStage"],
        "mutation_response"
    );
    assert_eq!(
        error.result.as_deref().unwrap()["safeLocators"],
        json!({"issueId":"10001","issueKey":"PROJ-1","fieldId":FIELD_ID})
    );
    assert!(!format!("{error:?}").contains(SENTINEL));
}
