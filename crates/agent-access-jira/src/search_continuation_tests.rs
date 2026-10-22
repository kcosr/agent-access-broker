//! `search` continuations through the provider: Jira's upstream token is
//! sealed for the caller and unwrapped only for the same normalized search,
//! context, caller and configuration, and every page is authorized again.
use super::*;

const QUERY: &str = "status = Done ORDER BY updated DESC";
const UPSTREAM: &str = "upstream-page-2";

fn finite(values: &[&str]) -> SearchAuthorizationScope {
    SearchAuthorizationScope::from_exact_values(values.iter().map(ToString::to_string).collect())
}

fn all_except(values: &[&str]) -> SearchAuthorizationScope {
    SearchAuthorizationScope::excluding_exact_values(
        values.iter().map(ToString::to_string).collect(),
    )
}

/// A per-user `search` under `scope`, with `token` added to `inputs`.
fn search(
    inputs: Value,
    scope: SearchAuthorizationScope,
    token: Option<&str>,
) -> InvocationBuilder {
    let mut inputs = inputs;
    if let Some(token) = token {
        inputs["nextPageToken"] = json!(token);
    }
    InvocationBuilder::from(per_user_invocation("search", inputs, vec![]))
        .search(SearchAuthorization::new("project".to_string(), scope))
}

fn base_inputs() -> Value {
    json!({"query": {"type": "jql", "value": QUERY}, "projects": ["PROJ", "OPS_TOOLS"]})
}

fn base_scope() -> SearchAuthorizationScope {
    finite(&["PROJ", "OPS_TOOLS", "OTHER"])
}

struct Harness {
    backend: Arc<StubJiraBackend>,
    provider: JiraProvider,
}

impl Harness {
    fn new() -> Self {
        Self::with_limits(ProviderLimits::default())
    }

    fn with_limits(limits: ProviderLimits) -> Self {
        let backend = Arc::new(StubJiraBackend {
            search_page: Mutex::new(Some(page_with_upstream_token(UPSTREAM))),
            ..StubJiraBackend::default()
        });
        let provider = JiraProvider::with_backend(jira_config(), limits, backend.clone());
        Self { backend, provider }
    }

    async fn first_page(&self, request: ProviderInvocation) -> String {
        let response = self.provider.invoke(request).await.unwrap();
        let token = response.result["nextPageToken"].as_str().unwrap();
        assert_ne!(token, UPSTREAM);
        assert!(!token.contains(UPSTREAM));
        token.to_string()
    }

    fn upstream_searches(&self) -> usize {
        self.backend
            .credential_observations
            .lock()
            .unwrap()
            .iter()
            .filter(|observation| observation.operation == "search")
            .count()
    }

    fn last_search(&self) -> JiraSearchRequest {
        self.backend.last_search.lock().unwrap().clone().unwrap()
    }
}

fn assert_rejected_token(error: ProviderError) {
    assert_eq!(error.reason_code(), ReasonCode::InputInvalid);
    assert_eq!(error.decision(), Decision::Deny);
    assert_eq!(
        error.message,
        "jira.search nextPageToken is invalid or expired; reuse it only with the same query, projects, and maxResults"
    );
}

fn assert_scope_changed(error: ProviderError) {
    assert_eq!(error.reason_code(), ReasonCode::InputInvalid);
    assert_eq!(error.decision(), Decision::Deny);
    assert_eq!(
        error.message,
        "the effective Jira project scope changed since nextPageToken was issued; repeat the search without nextPageToken"
    );
}

#[tokio::test]
async fn search_continuations_seal_jira_tokens_and_round_trip_normalized_searches() {
    let harness = Harness::new();
    let token = harness
        .first_page(search(base_inputs(), base_scope(), None).build())
        .await;
    assert!(token.len() <= harness.provider.search_pages.max_token_bytes());
    assert!(harness.last_search().next_page_token.is_none());
    for value in ["agent-one", "PROJ", "OPS_TOOLS", "status", "Done"] {
        assert!(!token.contains(value), "{value}");
    }

    // Equivalent requests: canonical JQL, project order and duplicates, and
    // maxResults defaulted, explicit or clamped to the same page size.
    for inputs in [
        base_inputs(),
        json!({"query": {"type": "jql", "value": "status = \"Done\" ORDER BY updated DESC"}, "projects": ["OPS_TOOLS", "PROJ", "PROJ"]}),
        json!({"query": {"type": "jql", "value": QUERY}, "projects": ["PROJ", "OPS_TOOLS"], "maxResults": 50}),
        json!({"query": {"type": "jql", "value": QUERY}, "projects": ["PROJ", "OPS_TOOLS"], "maxResults": 500}),
    ] {
        let searches = harness.upstream_searches();
        let response = harness
            .provider
            .invoke(search(inputs.clone(), base_scope(), Some(&token)).build())
            .await
            .unwrap_or_else(|error| panic!("{inputs}: {error:?}"));
        assert_eq!(harness.upstream_searches(), searches + 1);
        let upstream = harness.last_search();
        assert_eq!(upstream.next_page_token.as_deref(), Some(UPSTREAM));
        assert_eq!(upstream.max_results, 50);
        assert_eq!(
            upstream.jql,
            "(status = Done) AND project IN (OPS_TOOLS, PROJ) ORDER BY updated DESC"
        );
        // The next page's continuation is sealed again, and neither token
        // reaches the provider audit.
        let next = response.result["nextPageToken"].as_str().unwrap();
        assert_ne!(next, UPSTREAM);
        let audit = response.audit.unwrap().to_string();
        for private in [UPSTREAM, token.as_str(), next] {
            assert!(!audit.contains(private), "{private}");
        }
    }

    // The last page carries no continuation.
    *harness.backend.search_page.lock().unwrap() = Some(JiraSearchPage {
        next_page_token: None,
        is_last: Some(true),
        ..page_with_upstream_token(UPSTREAM)
    });
    let last = harness
        .provider
        .invoke(search(base_inputs(), base_scope(), Some(&token)).build())
        .await
        .unwrap();
    assert!(last.result["nextPageToken"].is_null());
    assert_eq!(last.result["isLast"], true);
}

#[tokio::test]
async fn search_continuations_reject_changed_searches_callers_and_contexts() {
    let harness = Harness::new();
    let token = harness
        .first_page(search(base_inputs(), base_scope(), None).build())
        .await;
    let changed = [
        // Caller query, filters and page size.
        search(
            json!({"query": {"type": "jql", "value": "status = Open ORDER BY updated DESC"}, "projects": ["PROJ", "OPS_TOOLS"]}),
            base_scope(),
            Some(&token),
        ),
        search(
            json!({"query": {"type": "jql", "value": "status = Done"}, "projects": ["PROJ", "OPS_TOOLS"]}),
            base_scope(),
            Some(&token),
        ),
        search(
            json!({"query": {"type": "jql", "value": QUERY}, "projects": ["PROJ"]}),
            base_scope(),
            Some(&token),
        ),
        search(
            json!({"query": {"type": "jql", "value": QUERY}}),
            base_scope(),
            Some(&token),
        ),
        search(
            json!({"query": {"type": "jql", "value": QUERY}, "projects": ["PROJ", "OPS_TOOLS"], "maxResults": 10}),
            base_scope(),
            Some(&token),
        ),
        // Execution context, principal, authentication and mode.
        search(base_inputs(), base_scope(), Some(&token)).execution_context("external"),
        search(base_inputs(), base_scope(), Some(&token)).principal("agent-two"),
        search(base_inputs(), base_scope(), Some(&token)).identity(crate::InvocationIdentity::new(
            "agent-one".to_string(),
            false,
        )),
        search(base_inputs(), base_scope(), Some(&token))
            .credential_mode(CredentialMode::Service)
            .credential(test_credential()),
    ];
    let searches = harness.upstream_searches();
    for request in changed {
        let error = harness.provider.invoke(request.build()).await.unwrap_err();
        assert_rejected_token(error);
    }
    // Without a cloud ID a bearer token has no route, so its continuation
    // is refused before Jira sees anything.
    let error = harness
        .provider
        .invoke(
            search(base_inputs(), base_scope(), Some(&token))
                .credential(bearer_credential("per-user-bearer-token"))
                .build(),
        )
        .await
        .unwrap_err();
    assert_eq!(error.reason_code(), ReasonCode::CredentialNotProvisioned);
    assert_eq!(harness.upstream_searches(), searches);

    // A text query and the JQL it lowers to are different searches.
    let text_token = harness
        .first_page(
            search(
                json!({"query": {"type": "jql", "value": "text ~ \"release notes\""}, "projects": ["PROJ"]}),
                base_scope(),
                None,
            )
            .build(),
        )
        .await;
    let searches = harness.upstream_searches();
    let error = harness
        .provider
        .invoke(
            search(
                json!({"query": {"type": "text", "value": "release notes"}, "projects": ["PROJ"]}),
                base_scope(),
                Some(&text_token),
            )
            .build(),
        )
        .await
        .unwrap_err();
    assert_rejected_token(error);
    assert_eq!(harness.upstream_searches(), searches);
}

#[tokio::test]
async fn search_continuations_bind_the_jira_configuration_and_provider_generation() {
    let harness = Harness::new();
    let token = harness
        .first_page(search(base_inputs(), base_scope(), None).build())
        .await;
    let sharing_keys = |config: JiraProviderConfig| JiraProvider {
        search_configuration: config.site().route_fingerprint(),
        config,
        ..harness.provider.clone()
    };
    let mut tenant = jira_config();
    tenant.tenant_host = "other.atlassian.net".to_string();
    let mut gateway = jira_config();
    gateway.cloud_id = Some("11111111-2222-4333-8444-555555555555".to_string());
    gateway
        .allowed_upstream_hosts
        .push("https://api.atlassian.com/ex/jira/**".to_string());
    let searches = harness.upstream_searches();
    for provider in [
        sharing_keys(tenant),
        sharing_keys(gateway),
        // A reload builds a new provider instance with a new generation key.
        JiraProvider::with_backend(
            jira_config(),
            ProviderLimits::default(),
            harness.backend.clone(),
        ),
    ] {
        let error = provider
            .invoke(search(base_inputs(), base_scope(), Some(&token)).build())
            .await
            .unwrap_err();
        assert_rejected_token(error);
    }
    assert_eq!(harness.upstream_searches(), searches);

    // Configuration the upstream token does not depend on is not bound.
    let mut comments = jira_config();
    comments.comments.max_results = 10;
    sharing_keys(comments)
        .invoke(search(base_inputs(), base_scope(), Some(&token)).build())
        .await
        .unwrap();
    assert_eq!(
        harness.last_search().next_page_token.as_deref(),
        Some(UPSTREAM)
    );
}

#[tokio::test]
async fn search_continuations_apply_grant_changes_on_the_next_page() {
    let harness = Harness::new();
    let browse = json!({"query": {"type": "jql", "value": QUERY}});

    // Effective access, no explicit projects: the composed query follows the
    // current grant, so a changed grant cannot reuse the old upstream token.
    let token = harness
        .first_page(search(browse.clone(), finite(&["PROJ", "OPS_TOOLS"]), None).build())
        .await;
    let searches = harness.upstream_searches();
    for scope in [finite(&["PROJ"]), finite(&["PROJ", "OPS_TOOLS", "OTHER"])] {
        let error = harness
            .provider
            .invoke(search(browse.clone(), scope, Some(&token)).build())
            .await
            .unwrap_err();
        assert_scope_changed(error);
    }
    assert_eq!(harness.upstream_searches(), searches);
    harness
        .provider
        .invoke(search(browse.clone(), finite(&["PROJ", "OPS_TOOLS"]), Some(&token)).build())
        .await
        .unwrap();
    let upstream = harness.last_search();
    assert_eq!(upstream.next_page_token.as_deref(), Some(UPSTREAM));
    assert!(upstream.jql.contains("project IN (OPS_TOOLS, PROJ)"));

    // All except: a new exclusion recomposes the query.
    let token = harness
        .first_page(search(browse.clone(), all_except(&[]), None).build())
        .await;
    let searches = harness.upstream_searches();
    let error = harness
        .provider
        .invoke(search(browse.clone(), all_except(&["OPS_TOOLS"]), Some(&token)).build())
        .await
        .unwrap_err();
    assert_scope_changed(error);
    assert_eq!(harness.upstream_searches(), searches);

    // Explicit projects: an unrelated grant change keeps the composed query
    // and the continuation, but losing a requested project denies before the
    // token is used, and returned issues are checked against the current
    // grant boundary rather than the requested projects (Jira resolves a
    // previous project key to the renamed project's current issues).
    let narrowed = json!({"query": {"type": "jql", "value": QUERY}, "projects": ["PROJ"]});
    let token = harness
        .first_page(search(narrowed.clone(), finite(&["PROJ", "OPS_TOOLS"]), None).build())
        .await;
    harness
        .provider
        .invoke(search(narrowed.clone(), finite(&["PROJ", "OTHER"]), Some(&token)).build())
        .await
        .unwrap();
    assert_eq!(
        harness.last_search().next_page_token.as_deref(),
        Some(UPSTREAM)
    );
    let searches = harness.upstream_searches();
    let error = harness
        .provider
        .invoke(search(narrowed.clone(), finite(&["OTHER"]), Some(&token)).build())
        .await
        .unwrap_err();
    assert_eq!(error.reason_code(), ReasonCode::ServiceActionDenied);
    assert_eq!(harness.upstream_searches(), searches);
    let mut renamed = page_with_upstream_token(UPSTREAM);
    renamed.issues[0].project = "OPS_TOOLS".to_string();
    renamed.issues[0].key = "OPS_TOOLS-7".to_string();
    *harness.backend.search_page.lock().unwrap() = Some(renamed.clone());
    harness
        .provider
        .invoke(
            search(
                narrowed.clone(),
                finite(&["PROJ", "OPS_TOOLS"]),
                Some(&token),
            )
            .build(),
        )
        .await
        .unwrap();
    let mut outside = renamed;
    outside.issues[0].project = "OTHER".to_string();
    outside.issues[0].key = "OTHER-7".to_string();
    *harness.backend.search_page.lock().unwrap() = Some(outside);
    let error = harness
        .provider
        .invoke(search(narrowed, finite(&["PROJ", "OPS_TOOLS"]), Some(&token)).build())
        .await
        .unwrap_err();
    assert_eq!(error.reason_code(), ReasonCode::ScopeUnresolved);
    assert!(error.result.is_none());
}

#[tokio::test]
async fn search_page_tokens_follow_the_response_cap_and_are_never_truncated() {
    // No fixed schema bound: the continuation's size follows the configured
    // response cap and is enforced when it is opened.
    let descriptor = jira_descriptor(&jira_config());
    let action = descriptor
        .actions
        .iter()
        .find(|action| action.action == "search")
        .unwrap();
    let schema = &action.input_schema["properties"]["nextPageToken"];
    assert_eq!(schema["minLength"], 1);
    assert!(schema.get("maxLength").is_none(), "{schema}");

    // A token beyond the envelope's 64 KiB ceiling for provider-built
    // payloads round-trips under the default response cap.
    let harness = Harness::new();
    let long = "w".repeat(100 * 1024);
    *harness.backend.search_page.lock().unwrap() = Some(page_with_upstream_token(&long));
    let token = harness
        .first_page(search(base_inputs(), base_scope(), None).build())
        .await;
    harness
        .provider
        .invoke(search(base_inputs(), base_scope(), Some(&token)).build())
        .await
        .unwrap();
    assert_eq!(
        harness.last_search().next_page_token.as_deref(),
        Some(long.as_str())
    );

    // Under a small response cap, presented tokens that are empty or longer
    // than the largest continuation are rejected before Jira is called;
    // emptiness already in scope resolution.
    let harness =
        Harness::with_limits(ProviderLimits::default().with_max_upstream_response_bytes(16 * 1024));
    let bound = harness.provider.search_pages.max_token_bytes();
    assert_eq!(bound, 16 * 1024);
    let oversized = "A".repeat(bound + 1);
    let mut empty = base_inputs();
    empty["nextPageToken"] = json!("");
    assert_rejected_token(harness.provider.local_scopes("search", &empty).unwrap_err());
    for token in ["", oversized.as_str()] {
        assert_rejected_token(
            harness
                .provider
                .invoke(search(base_inputs(), base_scope(), Some(token)).build())
                .await
                .unwrap_err(),
        );
    }
    assert_eq!(harness.upstream_searches(), 0);

    // A Jira token whose continuation would not fit the cap is an explicit
    // upstream failure, never truncated.
    let limit = harness.provider.search_pages.max_upstream_token_bytes();
    let too_long = "v".repeat(limit + 1);
    *harness.backend.search_page.lock().unwrap() = Some(page_with_upstream_token(&too_long));
    let error = harness
        .provider
        .invoke(search(base_inputs(), base_scope(), None).build())
        .await
        .unwrap_err();
    assert_eq!(error.reason_code(), ReasonCode::UpstreamProtocolFailed);
    assert_eq!(error.decision(), Decision::Error);
    assert_eq!(error.upstream_status, Some(200));
    assert!(
        error.message.contains(&format!("{limit}-byte limit")),
        "{}",
        error.message
    );
    assert!(error.result.is_none());
    assert!(!error.message.contains("vvvv"));

    // A token within the bound still shares the page's response cap with
    // the issues: a page that would exceed it fails whole, unchanged.
    *harness.backend.search_page.lock().unwrap() =
        Some(page_with_upstream_token(&"v".repeat(limit)));
    let error = harness
        .provider
        .invoke(search(base_inputs(), base_scope(), None).build())
        .await
        .unwrap_err();
    assert_eq!(error.reason_code(), ReasonCode::UpstreamProtocolFailed);
    assert!(error.result.is_none());
    let fits = "v".repeat(limit / 2);
    *harness.backend.search_page.lock().unwrap() = Some(page_with_upstream_token(&fits));
    let token = harness
        .first_page(search(base_inputs(), base_scope(), None).build())
        .await;
    harness
        .provider
        .invoke(search(base_inputs(), base_scope(), Some(&token)).build())
        .await
        .unwrap();
    assert_eq!(
        harness.last_search().next_page_token.as_deref(),
        Some(fits.as_str())
    );
}

#[tokio::test]
async fn http_search_continuations_send_jira_only_its_own_token() {
    let api = MockServer::start().await;
    let page = |next: Option<&str>| {
        json!({
            "issues": [{
                "id": "10001",
                "key": "PROJ-1",
                "fields": {"project": {"key": "PROJ"}, "summary": "visible summary"}
            }],
            "maxResults": 1,
            "isLast": next.is_none(),
            "nextPageToken": next,
        })
    };
    Mock::given(method("GET"))
        .and(path("/rest/api/3/search/jql"))
        .and(wiremock::matchers::query_param_is_missing("nextPageToken"))
        .respond_with(ResponseTemplate::new(200).set_body_json(page(Some("upstream-cursor-2"))))
        .mount(&api)
        .await;
    Mock::given(method("GET"))
        .and(path("/rest/api/3/search/jql"))
        .and(wiremock::matchers::query_param(
            "nextPageToken",
            "upstream-cursor-2",
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(page(None)))
        .mount(&api)
        .await;
    let mut config = jira_config();
    config.allowed_upstream_hosts = vec![format!("{}/rest/api/3/**", api.uri())];
    let backend = HttpJiraBackend::new_with_api_base(
        config.clone(),
        ProviderLimits::default(),
        Url::parse(&format!("{}/rest/api/3/", api.uri())).unwrap(),
    );
    let provider = JiraProvider::with_backend(config, ProviderLimits::default(), Arc::new(backend));
    let inputs = json!({"query": {"type": "jql", "value": QUERY}, "maxResults": 1});

    let first = agent_access_provider::host::with_correlation_context(
        crate::CorrelationContext::for_tests(),
        provider.invoke(search(inputs.clone(), finite(&["PROJ"]), None).build()),
    )
    .await
    .unwrap();
    let token = first.result["nextPageToken"].as_str().unwrap().to_string();
    assert_ne!(token, "upstream-cursor-2");
    let second = agent_access_provider::host::with_correlation_context(
        crate::CorrelationContext::for_tests(),
        provider.invoke(search(inputs, finite(&["PROJ"]), Some(&token)).build()),
    )
    .await
    .unwrap();
    assert!(second.result["nextPageToken"].is_null());
    assert_eq!(second.result["isLast"], true);

    let requests = api.received_requests().await.unwrap();
    assert_eq!(requests.len(), 2);
    for (request, expected) in requests.iter().zip([None, Some("upstream-cursor-2")]) {
        let query = request
            .url
            .query_pairs()
            .into_owned()
            .collect::<BTreeMap<_, _>>();
        assert_eq!(query.get("nextPageToken").map(String::as_str), expected);
        assert_eq!(
            query.get("jql").map(String::as_str),
            Some("(status = Done) AND project IN (PROJ) ORDER BY updated DESC")
        );
        assert!(!request.url.as_str().contains(&token));
    }
}

#[tokio::test]
async fn the_upstream_response_cap_bounds_jira_tokens_before_sealing() {
    let api = MockServer::start().await;
    let token = "t".repeat(8 * 1024);
    Mock::given(method("GET"))
        .and(path("/rest/api/3/search/jql"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "issues": [{"id": "10001", "key": "PROJ-1", "fields": {"project": {"key": "PROJ"}}}],
            "isLast": false,
            "nextPageToken": token,
        })))
        .mount(&api)
        .await;
    let mut config = jira_config();
    config.allowed_upstream_hosts = vec![format!("{}/rest/api/3/**", api.uri())];
    let limits = ProviderLimits::default().with_max_upstream_response_bytes(4 * 1024);
    let backend = HttpJiraBackend::new_with_api_base(
        config.clone(),
        limits.clone(),
        Url::parse(&format!("{}/rest/api/3/", api.uri())).unwrap(),
    );
    let provider = JiraProvider::with_backend(config, limits, Arc::new(backend));
    // The response carrying the token exceeds the configured response cap,
    // so the page fails as an oversized upstream response before any
    // continuation is sealed, and nothing is truncated.
    let error = agent_access_provider::host::with_correlation_context(
        crate::CorrelationContext::for_tests(),
        provider.invoke(
            search(
                json!({"query": {"type": "jql", "value": QUERY}}),
                finite(&["PROJ"]),
                None,
            )
            .build(),
        ),
    )
    .await
    .unwrap_err();
    assert_eq!(error.reason_code(), ReasonCode::UpstreamProtocolFailed);
    assert_eq!(error.decision(), Decision::Error);
    assert!(error.result.is_none());
    assert!(!error.message.contains("tttt"));
}
