use super::*;

fn invocation(inputs: Value) -> ProviderInvocation {
    let mut invocation = issue_create_invocation(inputs);
    invocation = InvocationBuilder::from(invocation)
        .action("issue_type.list")
        .build();
    invocation
}

fn page(start_at: u32, total: u32) -> JiraIssueTypePage {
    JiraIssueTypePage {
        start_at,
        max_results: 1,
        total,
        issue_types: vec![JiraIssueType {
            id: "10001".to_string(),
            name: "Type name sentinel".to_string(),
            description: "Type description sentinel".to_string(),
            subtask: true,
        }],
    }
}

#[tokio::test]
async fn issue_type_list_is_read_only_project_scoped_and_needs_no_lookup() {
    let backend = Arc::new(StubJiraBackend::default());
    let provider =
        JiraProvider::with_backend(jira_config(), ProviderLimits::default(), backend.clone());
    let action = jira_descriptor(&provider.config)
        .actions
        .into_iter()
        .find(|action| action.action == "issue_type.list")
        .unwrap();
    assert!(action.read_only);
    assert_eq!(action.resource_scopes, ["project"]);
    assert_eq!(action.lookup, LookupRequirement::None);
    assert_eq!(action.credential_modes, ["service", "per_user"]);
    assert_eq!(action.input_schema["required"], json!(["project"]));
    assert_eq!(action.input_schema["additionalProperties"], false);
    assert!(action.documentation.is_some());
    let scopes = provider
        .lookup_scopes("issue_type.list", &json!({"project":"PROJ"}), None)
        .await
        .unwrap();
    assert_eq!(
        scopes,
        BTreeMap::from([("project".to_string(), vec!["PROJ".to_string()])])
    );
    assert!(backend.credential_observations.lock().unwrap().is_empty());
}

#[tokio::test]
async fn issue_type_list_rejects_bad_inputs_and_scope_before_dispatch() {
    let backend = Arc::new(StubJiraBackend::default());
    let provider =
        JiraProvider::with_backend(jira_config(), ProviderLimits::default(), backend.clone());
    for inputs in [
        json!(null),
        json!([]),
        json!({}),
        json!({"project":1}),
        json!({"project":"proj"}),
        json!({"project":"PROJ/OTHER"}),
        json!({"project":"PROJ","extra":true}),
        json!({"project":"PROJ","startAt":-1}),
        json!({"project":"PROJ","startAt":4294967296u64}),
        json!({"project":"PROJ","startAt":null}),
        json!({"project":"PROJ","maxResults":0}),
        json!({"project":"PROJ","maxResults":101}),
        json!({"project":"PROJ","maxResults":1.5}),
        json!({"project":"PROJ","maxResults":"50"}),
        json!({"project":"PROJ","maxResults":null}),
    ] {
        assert!(
            provider.local_scopes("issue_type.list", &inputs).is_err(),
            "{inputs}"
        );
        assert!(provider.invoke(invocation(inputs)).await.is_err());
    }
    let error = provider
        .invoke(invocation(json!({"project":"OTHER"})))
        .await
        .unwrap_err();
    assert_eq!(error.reason_code(), ReasonCode::ScopeUnresolved);
    assert!(backend.issue_type_requests.lock().unwrap().is_empty());
    assert!(backend.credential_observations.lock().unwrap().is_empty());
}

#[tokio::test]
async fn issue_type_list_uses_execution_credential_and_preserves_copyable_ids_without_auditing_text()
 {
    for (mode, credential) in [
        (CredentialMode::Service, test_credential()),
        (CredentialMode::PerUser, test_per_user_credential()),
    ] {
        let backend = Arc::new(StubJiraBackend::default());
        *backend.issue_type_page.lock().unwrap() = Some(page(0, 2));
        let provider =
            JiraProvider::with_backend(jira_config(), ProviderLimits::default(), backend.clone());
        let mut request = invocation(json!({"project":"PROJ"}));
        request = InvocationBuilder::from(request)
            .credential_mode(mode)
            .build();
        request = InvocationBuilder::from(request)
            .execution(ExecutionAccess::Static(credential.clone()))
            .build();
        let response = provider.invoke(request).await.unwrap();
        assert_eq!(
            response.result,
            json!({
                "operation":"issue_type.list", "project":"PROJ",
                "issueTypes":[{"id":"10001","name":"Type name sentinel","description":"Type description sentinel","subtask":true}],
                "startAt":0, "maxResults":1, "count":1, "total":2, "isLast":false, "nextStartAt":1
            })
        );
        let id = response.result["issueTypes"][0]["id"].clone();
        assert!(
            parse_issue_create_inputs(
                &json!({"project":"PROJ","issueTypeId":id,"summary":"New issue"}),
                &jira_config()
            )
            .is_ok()
        );
        assert_eq!(
            backend.issue_type_requests.lock().unwrap().as_slice(),
            &[(
                "PROJ".to_string(),
                JiraIssueTypeListRequest {
                    start_at: 0,
                    max_results: 50
                }
            )]
        );
        let observations = backend.credential_observations.lock().unwrap();
        assert_eq!(observations.len(), 1);
        assert_eq!(observations[0].operation, "issue_types");
        assert_eq!(observations[0].credential, credential);
        assert_eq!(response.upstream_status, Some(200));
        assert_eq!(response.upstream_duration_ms, Some(7));
        let audit = response.audit.unwrap();
        assert_eq!(audit["credentialMode"], mode.as_str());
        assert_eq!(audit["issueTypeCount"], 1);
        let metadata = format!("{audit} {:?}", response.object_ids);
        assert!(!metadata.contains("sentinel"));
    }
}

#[tokio::test]
async fn issue_type_list_reports_last_and_empty_pages_explicitly() {
    let backend = Arc::new(StubJiraBackend::default());
    let provider =
        JiraProvider::with_backend(jira_config(), ProviderLimits::default(), backend.clone());
    for (start_at, total, empty) in [
        (1, 2, false),
        (0, 0, true),
        (10, 2, true),
        (u32::MAX, 0, true),
    ] {
        let mut page = page(start_at, total);
        if empty {
            page.issue_types.clear();
        }
        *backend.issue_type_page.lock().unwrap() = Some(page);
        let response = provider
            .invoke(invocation(
                json!({"project":"PROJ","startAt":start_at,"maxResults":1}),
            ))
            .await
            .unwrap();
        assert_eq!(response.result["isLast"], true);
        assert!(response.result["nextStartAt"].is_null());
        assert_eq!(response.result["startAt"], start_at);
        assert_eq!(response.result["count"], if empty { 0 } else { 1 });
    }
}

#[tokio::test]
async fn issue_type_list_validates_backend_page_and_result_budget() {
    let backend = Arc::new(StubJiraBackend::default());
    let provider =
        JiraProvider::with_backend(jira_config(), ProviderLimits::default(), backend.clone());
    let mut malformed = page(0, 1);
    malformed.issue_types[0].id = "bad-id-sentinel".to_string();
    *backend.issue_type_page.lock().unwrap() = Some(malformed);
    let error = provider
        .invoke(invocation(json!({"project":"PROJ"})))
        .await
        .unwrap_err();
    assert_eq!(error.reason_code(), ReasonCode::UpstreamProtocolFailed);
    assert!(!error.message.contains("sentinel"));

    *backend.issue_type_page.lock().unwrap() = Some(page(0, 1));
    let provider = JiraProvider::with_backend(
        jira_config(),
        ProviderLimits::default().with_max_upstream_response_bytes(32),
        backend,
    );
    let error = provider
        .invoke(invocation(json!({"project":"PROJ"})))
        .await
        .unwrap_err();
    assert_eq!(error.reason_code(), ReasonCode::UpstreamProtocolFailed);
    assert!(!error.message.contains("sentinel"));
}
