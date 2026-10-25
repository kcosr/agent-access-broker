use super::*;
use agent_access_provider::test_support::{InvocationBuilder, basic_credential, bearer_credential};
use wiremock::matchers::{body_json, header, method, path, query_param};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn backend(api: &MockServer, limits: ProviderLimits) -> HttpJiraBackend {
    let config = serde_json::from_value(json!({
        "tenant_host":"example.atlassian.net",
        "allowed_upstream_hosts":[format!("{}/**",api.uri())]
    }))
    .unwrap();
    HttpJiraBackend::new_with_api_base(
        config,
        limits,
        Url::parse(&format!("{}/rest/api/3/", api.uri())).unwrap(),
    )
}

fn provider(api: &MockServer, limits: ProviderLimits) -> JiraProvider {
    let backend = backend(api, limits.clone());
    JiraProvider::with_backend(backend.config.clone(), limits, Arc::new(backend))
}

fn invocation(inputs: Value) -> ProviderInvocation {
    InvocationBuilder::new("jira", "project.view")
        .inputs(inputs)
        .resources(BTreeMap::from([(
            "project".to_string(),
            vec!["PROJ".to_string()],
        )]))
        .credential(basic_credential("service@example.com", "token"))
        .build()
}

fn project() -> Value {
    json!({"id":"10001","key":"PROJ","name":"Project sentinel","description":"Description sentinel",
        "lead":{"secret":"never-project"},"url":"https://untrusted.example/",
        "versions":[{"id":"20001","name":"2.4","description":"Release","released":false,"archived":false,"releaseDate":"2027-01-01","secret":"never-version"}],
        "components":[{"id":"30001","name":"Backend","description":"Server","lead":{"secret":"never-component"}}],
        "issueTypes":[{"id":"40001","name":"Task","description":"A task","subtask":false,"scope":{"secret":"never-type"}}]
    })
}

fn field() -> Value {
    json!({"value":"External ticket","cfid":"cf[12345]","displayName":"External ticket number","types":["java.lang.String"],"operators":["~","!~","is","is not"],"searchable":"true","secret":"never-field"})
}

fn fields() -> Value {
    json!({"visibleFieldNames":[field()],"visibleFunctionNames":[{"secret":"never-function"}]})
}

async fn mount_project(api: &MockServer, value: Value) {
    Mock::given(method("GET"))
        .and(path("/rest/api/3/project/PROJ"))
        .respond_with(ResponseTemplate::new(200).set_body_json(value))
        .mount(api)
        .await;
}

async fn mount_fields(api: &MockServer) {
    Mock::given(method("POST"))
        .and(path("/rest/api/3/jql/autocompletedata"))
        .and(body_json(
            json!({"projectIds":[10001],"includeCollapsedFields":false}),
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(fields()))
        .mount(api)
        .await;
}

#[tokio::test]
async fn descriptor_and_scope_resolution_are_read_only_and_local() {
    let api = MockServer::start().await;
    let provider = provider(&api, ProviderLimits::default());
    let action = descriptor();
    assert!(action.read_only);
    assert_eq!(action.lookup, LookupRequirement::None);
    assert_eq!(action.required_scope_types(), ["project"]);
    assert_eq!(action.credential_modes, ["service", "per_user"]);
    assert_eq!(
        provider
            .lookup_scopes("project.view", &json!({"project":"PROJ"}), None)
            .await
            .unwrap(),
        BTreeMap::from([("project".to_string(), vec!["PROJ".to_string()])])
    );
    assert!(api.received_requests().await.unwrap().is_empty());
}

#[tokio::test]
async fn invalid_inputs_and_unauthorized_project_stop_before_http() {
    let api = MockServer::start().await;
    let provider = provider(&api, ProviderLimits::default());
    for input in [
        Value::Null,
        json!([]),
        json!({}),
        json!({"project":"proj"}),
        json!({"project":"PROJ","extra":true}),
        json!({"project":"PROJ","include":null}),
        json!({"project":"PROJ","include":["fields","fields"]}),
        json!({"project":"PROJ","include":["createFields"]}),
        json!({"project":"PROJ","include":"fields"}),
        json!({"project":"PROJ","query":" "}),
        json!({"project":"PROJ","query":null}),
        json!({"project":"PROJ","query":"a".repeat(257)}),
        json!({"project":"PROJ","query":"a\nb"}),
    ] {
        assert!(
            provider.local_scopes("project.view", &input).is_err(),
            "{input}"
        );
        assert_eq!(
            provider
                .invoke(invocation(input))
                .await
                .unwrap_err()
                .reason_code(),
            ReasonCode::InputInvalid
        );
    }
    assert_eq!(
        provider
            .invoke(invocation(json!({"project":"OTHER"})))
            .await
            .unwrap_err()
            .reason_code(),
        ReasonCode::ScopeUnresolved
    );
    assert!(api.received_requests().await.unwrap().is_empty());
}

#[tokio::test]
async fn identity_is_checked_before_field_discovery_and_no_raw_payload_is_released() {
    let api = MockServer::start().await;
    let provider = provider(&api, ProviderLimits::default());
    for (key, id) in [
        ("OTHER", json!("10001")),
        ("PROJ", json!("bad")),
        ("PROJ", json!("0")),
        ("PROJ", json!("01")),
        ("PROJ", json!(10001)),
        ("PROJ", json!("9223372036854775808")),
    ] {
        api.reset().await;
        let mut response = project();
        response["key"] = json!(key);
        response["id"] = id;
        mount_project(&api, response).await;
        assert!(
            provider
                .invoke(invocation(json!({"project":"PROJ"})))
                .await
                .is_err()
        );
        assert_eq!(api.received_requests().await.unwrap().len(), 1);
    }
    api.reset().await;
    mount_project(&api, project()).await;
    mount_fields(&api).await;
    let response = provider
        .invoke(invocation(json!({"project":"PROJ"})))
        .await
        .unwrap();
    assert_eq!(
        response.result["project"]["webUrl"],
        "https://example.atlassian.net/browse/PROJ"
    );
    assert_eq!(
        response.result["fields"]["items"][0]["id"],
        "customfield_12345"
    );
    assert_eq!(
        response.result["fields"]["items"][0]["jqlReference"],
        "cf[12345]"
    );
    assert_eq!(
        response.result["fields"]["items"][0]["operators"],
        json!(["IS EMPTY", "IS NOT EMPTY", "~"])
    );
    assert_eq!(response.result["fields"]["truncated"], false);
    assert!(response.result.get("versions").is_none());
    assert!(!response.result.to_string().contains("never-"));
    assert!(!response.result.to_string().contains("untrusted"));
    assert!(!format!("{:?} {:?}", response.audit, response.object_ids).contains("sentinel"));
    assert!(response.audit.as_ref().unwrap().get("project").is_none());
    assert_eq!(response.object_ids.as_ref().unwrap()["project"], "PROJ");
    assert!(response.audit.as_ref().unwrap().get("include").is_some());
    assert_eq!(api.received_requests().await.unwrap().len(), 2);
}

#[tokio::test]
async fn identity_only_and_metadata_sections_make_only_needed_requests() {
    let api = MockServer::start().await;
    let provider = provider(&api, ProviderLimits::default());
    mount_project(&api, project()).await;
    let response = provider
        .invoke(invocation(json!({"project":"PROJ","include":[]})))
        .await
        .unwrap();
    assert_eq!(response.result.as_object().unwrap().len(), 2);
    assert_eq!(api.received_requests().await.unwrap().len(), 1);
    api.reset().await;
    mount_project(&api, project()).await;
    let status = json!({"id":"5","name":"Open","description":"Open status","statusCategory":{"id":2,"key":"new","name":"To Do","secret":"never-category"},"secret":"never-status"});
    Mock::given(method("GET"))
        .and(path("/rest/api/3/project/10001/statuses"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([
            {"id":"40001","statuses":[status.clone()]},{"id":"40002","statuses":[status]}
        ])))
        .expect(1)
        .mount(&api)
        .await;
    let response = provider
        .invoke(invocation(
            json!({"project":"PROJ","include":["versions","components","issueTypes","statuses"]}),
        ))
        .await
        .unwrap();
    assert_eq!(
        response.result["versions"]["items"][0]["releaseDate"],
        "2027-01-01"
    );
    assert_eq!(response.result["components"]["items"][0]["name"], "Backend");
    assert_eq!(response.result["issueTypes"]["items"][0]["subtask"], false);
    assert_eq!(response.result["statuses"]["count"], 1);
    assert_eq!(
        response.result["statuses"]["items"][0]["statusCategory"]["id"],
        2
    );
    assert!(!response.result.to_string().contains("never-"));
    let requests = api.received_requests().await.unwrap();
    assert_eq!(requests.len(), 2);
    assert!(requests[0].url.query().unwrap().contains("issueTypes"));
}

#[tokio::test]
async fn execution_credentials_use_site_or_gateway_for_each_read() {
    let api = MockServer::start().await;
    let mut backend = backend(&api, ProviderLimits::default());
    backend.routes.gateway_mut().unwrap().api_base =
        Url::parse(&format!("{}/ex/jira/cloud/rest/api/3/", api.uri())).unwrap();
    for (base, auth, credential) in [
        (
            "/rest/api/3",
            "Basic c2VydmljZUBleGFtcGxlLmNvbTp0b2tlbg==",
            basic_credential("service@example.com", "token"),
        ),
        (
            "/ex/jira/cloud/rest/api/3",
            "Bearer selected-token",
            bearer_credential("selected-token"),
        ),
    ] {
        Mock::given(method("GET"))
            .and(path(format!("{base}/project/PROJ")))
            .and(query_param("expand", "description,issueTypes"))
            .and(header("Authorization", auth))
            .respond_with(ResponseTemplate::new(200).set_body_json(project()))
            .expect(1)
            .mount(&api)
            .await;
        Mock::given(method("POST"))
            .and(path(format!("{base}/jql/autocompletedata")))
            .and(body_json(
                json!({"projectIds":[10001],"includeCollapsedFields":false}),
            ))
            .and(header("Authorization", auth))
            .respond_with(ResponseTemplate::new(200).set_body_json(fields()))
            .expect(1)
            .mount(&api)
            .await;
        Mock::given(method("GET"))
            .and(path(format!("{base}/project/10001/statuses")))
            .and(header("Authorization", auth))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!([])))
            .expect(1)
            .mount(&api)
            .await;
        let credential = AtlassianCredential::from_static(credential);
        backend
            .project_details("PROJ", true, &credential)
            .await
            .unwrap();
        backend
            .project_search_fields(10001, &credential)
            .await
            .unwrap();
        backend.project_statuses(10001, &credential).await.unwrap();
    }
}

#[test]
fn fields_filter_unsupported_operators_and_preserve_stable_custom_identity() {
    let mut omitted = field();
    omitted.as_object_mut().unwrap().remove("searchable");
    let value = json!({"visibleFieldNames":[
        omitted,
        {"value":"fixVersion","displayName":"Fix versions","types":["Version"],"operators":["=","was","in"]},
        {"value":"summary","displayName":"Summary","types":["java.lang.String"],"operators":["=","~","!~"]},
        {"value":"unknown","displayName":"Unsupported","types":[],"operators":[]},
        {"value":"\"Component[Dropdown]\"","displayName":"Collapsed","types":["Option"],"operators":["="]},
        {"value":"priority","searchable":"false"}
    ]});
    let items = searchable_fields(&value).unwrap();
    assert_eq!(items.len(), 3);
    assert_eq!(items[0]["id"], "customfield_12345");
    assert_eq!(items[1]["id"], "fixVersions");
    assert_eq!(items[1]["jqlReference"], "fixVersion");
    assert_eq!(items[1]["operators"], json!(["=", "IN"]));
    assert_eq!(items[2]["operators"], json!(["~"]));
}

#[test]
fn system_alias_rows_do_not_conflict_with_canonical_field_metadata() {
    let value = json!({"visibleFieldNames":[
        {"value":"type","displayName":"type","types":["IssueType"],"operators":["="]},
        {"value":"issuetype","displayName":"issuetype","types":["IssueType"],"operators":["=","in"]},
        {"value":"key","displayName":"key","types":["Issue"],"operators":["=","in"]},
        {"value":"issuekey","displayName":"issuekey","types":["Issue"],"operators":["="]},
        {"value":"fixVersions","displayName":"Fix Versions alias","types":["Version"],"operators":["="]},
        {"value":"FIXVERSION","displayName":"Fix Version","types":["Version"],"operators":["=","in"]},
        {"value":"text","displayName":"Text","types":["java.lang.String"],"operators":["~"]},
        {"value":"statusCategory","displayName":"Status Category","types":["StatusCategory"],"operators":["=","in"]}
    ]});
    let projected = collection(searchable_fields(&value).unwrap(), None).unwrap();
    assert_eq!(projected["count"], 3);
    assert_eq!(projected["items"][0]["id"], "issuetype");
    assert_eq!(projected["items"][0]["name"], "issuetype");
    assert_eq!(projected["items"][0]["operators"], json!(["=", "IN"]));
    assert_eq!(projected["items"][1]["id"], "issuekey");
    assert_eq!(projected["items"][1]["jqlReference"], "key");
    assert_eq!(projected["items"][2]["id"], "fixVersions");
    assert_eq!(projected["items"][2]["jqlReference"], "fixVersion");
    assert!(
        !projected["items"]
            .as_array()
            .unwrap()
            .iter()
            .any(|item| item["id"] == "text" || item["id"] == "statusCategory")
    );
}

#[test]
fn conflicting_custom_field_metadata_still_fails_closed() {
    let first = field();
    let mut second = field();
    second["displayName"] = json!("Conflicting name");
    let items = searchable_fields(&json!({"visibleFieldNames":[first,second]})).unwrap();
    assert_eq!(
        collection(items, None).unwrap_err().reason_code(),
        ReasonCode::UpstreamProtocolFailed
    );
}

#[test]
fn query_length_counts_unicode_characters_consistently_with_schema() {
    let query = "検索語".repeat(50);
    let input = parse_inputs(&json!({"project":"PROJ","query":query})).unwrap();
    assert_eq!(input.query.as_deref(), Some(query.as_str()));
    assert!(parse_inputs(&json!({"project":"PROJ","query":"語".repeat(256)})).is_ok());
    assert_eq!(
        parse_inputs(&json!({"project":"PROJ","query":"語".repeat(257)}))
            .err()
            .unwrap()
            .reason_code(),
        ReasonCode::InputInvalid
    );
}

#[test]
fn malformed_field_shapes_fail_without_including_raw_values() {
    for (key, value) in [
        ("cfid", json!(3)),
        ("displayName", Value::Null),
        ("searchable", json!(true)),
        ("operators", json!("=")),
        ("operators", json!([true])),
        ("types", json!([])),
        ("types", json!(["secret-value".repeat(100)])),
    ] {
        let mut candidate = field();
        candidate[key] = value;
        let error = searchable_fields(&json!({"visibleFieldNames":[candidate]})).unwrap_err();
        assert_eq!(error.reason_code(), ReasonCode::UpstreamProtocolFailed);
        assert!(!format!("{error:?}").contains("secret-value"));
    }
    assert!(searchable_fields(&json!({})).is_err());
    assert!(searchable_fields(&json!({"visibleFieldNames":{}})).is_err());
}

#[test]
fn limits_are_explicit_and_queries_filter_before_cap_and_preview() {
    let mut items: Vec<Value> = (1..=101)
        .map(|id| json!({"id":id.to_string(),"name":format!("Field {id}"),"description":""}))
        .collect();
    items[100]["name"] = json!(format!("{}Needle", "é".repeat(3000)));
    let all = collection(items.clone(), None).unwrap();
    assert_eq!(all["count"], 100);
    assert_eq!(all["truncated"], true);
    let filtered = collection(items, Some("needle")).unwrap();
    assert_eq!(filtered["count"], 1);
    assert_eq!(filtered["truncated"], false);
    assert_eq!(filtered["items"][0]["id"], "101");
    assert_eq!(filtered["items"][0]["name"].as_str().unwrap().len(), 4096);
    assert_eq!(filtered["items"][0]["previewTruncated"], true);
    assert_eq!(
        collection(
            vec![json!({"id":"1","name":"N","jqlReference":"cf[12345]"})],
            Some("cf[12345]")
        )
        .unwrap()["count"],
        1
    );
}

#[test]
fn duplicate_conflicting_metadata_fails_instead_of_choosing_an_identity() {
    let items = vec![
        json!({"id":"1","name":"First"}),
        json!({"id":"1","name":"Other"}),
    ];
    assert!(collection(items, None).is_err());
}

#[tokio::test]
async fn upstream_errors_redirects_and_byte_limits_fail_closed() {
    let api = MockServer::start().await;
    let provider = provider(&api, ProviderLimits::default());
    for (status, reason) in [
        (401, ReasonCode::UpstreamUnauthorized),
        (403, ReasonCode::UpstreamForbidden),
        (404, ReasonCode::ScopeUnresolved),
        (429, ReasonCode::UpstreamRateLimited),
        (500, ReasonCode::UpstreamFailed),
        (302, ReasonCode::UpstreamProtocolFailed),
    ] {
        api.reset().await;
        Mock::given(method("GET"))
            .respond_with(
                ResponseTemplate::new(status)
                    .insert_header("Location", format!("{}/secret", api.uri()))
                    .set_body_string("secret-value"),
            )
            .mount(&api)
            .await;
        let error = provider
            .invoke(invocation(json!({"project":"PROJ"})))
            .await
            .unwrap_err();
        assert_eq!(error.reason_code(), reason);
        assert!(!format!("{error:?}").contains("secret-value"));
        assert_eq!(api.received_requests().await.unwrap().len(), 1);
    }
    api.reset().await;
    mount_project(&api, project()).await;
    let limited = super::tests::provider(
        &api,
        ProviderLimits::default().with_max_upstream_response_bytes(64),
    );
    assert_eq!(
        limited
            .invoke(invocation(json!({"project":"PROJ"})))
            .await
            .unwrap_err()
            .reason_code(),
        ReasonCode::UpstreamProtocolFailed
    );
}
