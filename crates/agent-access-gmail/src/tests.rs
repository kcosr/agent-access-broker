use super::*;
use agent_access_provider::test_support::{InvocationBuilder, delegated_binding_id};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use std::collections::BTreeMap;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::SystemTime;
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{body_json, header, method, path, query_param},
};

const BINDING: &str = "gmail-test-binding";

/// A delegated lease for one connection binding. Recovery after a 401, when
/// enabled, renews the access once within the same binding, as the host does.
struct Lease {
    binding: DelegatedBindingId,
    token: Mutex<String>,
    target: &'static str,
    audience: &'static str,
    recovers_to: Option<&'static str>,
    recovered: AtomicBool,
}
#[async_trait]
impl DelegatedLease for Lease {
    fn binding_identity(&self) -> DelegatedBindingId {
        self.binding
    }
    fn mark_rejected(&self, _: &str) -> Result<(), ProviderError> {
        Ok(())
    }
    fn access(&self) -> DelegatedAccess {
        let token = self.token.lock().unwrap().clone();
        let version = format!("version-{token}");
        DelegatedAccess::new(token, self.target, self.audience, version, i64::MAX)
    }
    async fn revalidate(&self) -> Result<(), ProviderError> {
        Ok(())
    }
    async fn recover_after_unauthorized(&self) -> Result<DelegatedAccess, ProviderError> {
        match self.recovers_to {
            Some(token) if !self.recovered.swap(true, Ordering::SeqCst) => {
                *self.token.lock().unwrap() = token.into();
                Ok(self.access())
            }
            _ => Err(ProviderError::deny(
                ReasonCode::CredentialInvalid,
                "test refused refresh",
            )),
        }
    }
}
/// A lease whose refresh is already in progress for the same connection.
struct BusyLease;
#[async_trait]
impl DelegatedLease for BusyLease {
    fn binding_identity(&self) -> DelegatedBindingId {
        lease(BINDING, "secret").binding_identity()
    }
    fn mark_rejected(&self, _: &str) -> Result<(), ProviderError> {
        Ok(())
    }
    fn access(&self) -> DelegatedAccess {
        lease(BINDING, "secret").access()
    }
    async fn revalidate(&self) -> Result<(), ProviderError> {
        Ok(())
    }
    async fn recover_after_unauthorized(&self) -> Result<DelegatedAccess, ProviderError> {
        Err(agent_access_provider::host::port_failure(
            agent_access_provider::host::HostPort::DelegatedLease,
            ProviderError::error(ReasonCode::ConcurrencyLimited, "oauth_refresh_busy"),
        ))
    }
}

#[tokio::test]
async fn a_busy_refresh_passes_through_as_the_leases_concurrency_limit() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(401))
        .mount(&server)
        .await;
    let request = InvocationBuilder::from(invocation("account.view", json!({})))
        .delegated(agent_access_provider::host::delegated_credential(Arc::new(
            BusyLease,
        )))
        .build();
    let error = provider(&server).invoke(request).await.unwrap_err();
    assert_eq!(error.decision(), agent_access_provider::Decision::Error);
    assert_eq!(error.reason_code(), ReasonCode::ConcurrencyLimited);
    assert_eq!(error.reason_code().http_status(), 429);
    assert_eq!(
        error.reason_code().host_port(),
        Some(agent_access_provider::host::HostPort::DelegatedLease)
    );
    // The host accepts it at the invocation boundary, though Gmail itself
    // could not report concurrency_limited.
    let hook = agent_access_provider::host::hook_context(
        "gmail",
        "account.view",
        agent_access_provider::HookPhase::Invocation,
        GMAIL_BACKEND.domain_reasons(),
    );
    assert_eq!(hook.check_failure(&error), Ok(()));
}

fn lease(binding: &str, token: &str) -> Lease {
    Lease {
        binding: delegated_binding_id(binding),
        token: Mutex::new(token.into()),
        target: GMAIL_TARGET,
        audience: GMAIL_AUDIENCE,
        recovers_to: None,
        recovered: AtomicBool::new(false),
    }
}
fn delegated(lease: Lease) -> DelegatedCredential {
    agent_access_provider::host::delegated_credential(Arc::new(lease))
}
fn request(action: &str, inputs: Value) -> InvocationBuilder {
    InvocationBuilder::new("gmail", action)
        .inputs(inputs)
        .correlation(CorrelationContext::new(
            "gmail-test".into(),
            "gmail-broker-test".into(),
        ))
        .credential_mode(CredentialMode::PerUser)
        .identity(InvocationIdentity::new("alice", true))
        .execution_context("default")
        .delegated(delegated(lease(BINDING, "secret")))
}
fn invocation(action: &str, inputs: Value) -> ProviderInvocation {
    request(action, inputs).build()
}
fn provider(server: &MockServer) -> GmailProvider {
    let host = agent_access_provider::test_support::TestHost::default();
    GmailProvider::new(
        Url::parse(&format!("{}/gmail/v1/users/me/", server.uri())).unwrap(),
        &host,
        &host.limits,
    )
    .unwrap()
}

#[test]
fn build_uses_one_request_client_for_the_gmail_api() {
    let host = agent_access_provider::test_support::TestHost::default();
    GmailConfig {}.build(&host.context()).unwrap();
    let built = host.built_clients();
    assert_eq!(built.len(), 1);
    assert_eq!(built[0].base.as_str(), API);
    assert_eq!(built[0].profile, ClientProfile::Request);
    assert!(!built[0].literal_loopback);
}
fn message() -> Value {
    json!({"id":"a123","threadId":"b456","labelIds":["INBOX"],"snippet":"private snippet","payload":{"mimeType":"text/plain","headers":[{"name":"Subject","value":"private subject"}],"body":{"data":URL_SAFE_NO_PAD.encode("private body")}}})
}

#[test]
fn action_inputs_are_bounded_and_never_accept_mailboxes_urls_or_unsupported_effects() {
    for action in [
        "message.send",
        "message.delete",
        "thread.delete",
        "draft.create",
    ] {
        assert!(validate_inputs(action, &json!({"id":"a123"})).is_err());
    }
    for inputs in [
        json!({"id":"../../send"}),
        json!({"id":"a123","user":"other@example.test"}),
        json!({"id":"a123","url":"https://evil.test"}),
    ] {
        assert!(validate_inputs("message.trash", &inputs).is_err());
    }
    for inputs in [
        json!({"maxResults":51}),
        json!({"maxResults":0}),
        json!({"includeSpamTrash":"true"}),
        json!({"query":"a".repeat(2049)}),
        json!({"pageToken":""}),
        json!({"pageToken":"A".repeat(MAX_PAGE_TOKEN_BYTES + 1)}),
    ] {
        assert!(validate_inputs("message.search", &inputs).is_err());
    }
    assert!(
        validate_inputs(
            "message.search",
            &json!({"pageToken":"A".repeat(MAX_PAGE_TOKEN_BYTES)})
        )
        .is_ok()
    );
    let d = descriptor();
    assert_eq!(d.actions.len(), 11);
    for a in d.actions {
        assert_eq!(
            a.read_only,
            a.action.ends_with("view")
                || a.action.ends_with("list")
                || a.action.ends_with("search")
        );
    }
}
#[test]
fn mime_projection_decodes_text_marks_omissions_and_rejects_invalid_base64() {
    let result = mail::message(&message(), true).unwrap();
    assert_eq!(result["textParts"][0]["text"], "private body");
    assert_eq!(result["contentTrust"], "untrusted");
    let mut m = message();
    m["payload"]["body"]["data"] = json!("***");
    assert!(mail::message(&m, true).is_err());
    m["payload"] = json!({"mimeType":"text/plain","headers":[{"name":"Content-Type","value":"text/plain; charset=iso-8859-1"}],"body":{"data":URL_SAFE_NO_PAD.encode([0xe9])}});
    assert_eq!(
        mail::message(&m, true).unwrap()["textParts"][0]["text"],
        "é"
    );
    m["payload"]["body"]["data"] = json!(URL_SAFE_NO_PAD.encode(vec![b'a'; 256 * 1024 + 1]));
    assert_eq!(
        mail::message(&m, true).unwrap()["bodyOmissions"],
        json!(["text_limit"])
    );
    let mut part = json!({});
    for _ in 0..18 {
        part = json!({"parts":[part]});
    }
    m["payload"] = part;
    assert_eq!(
        mail::message(&m, true).unwrap()["bodyOmissions"],
        json!(["depth_limit"])
    );
    m["payload"] = json!({"parts":vec![json!({});101]});
    assert_eq!(
        mail::message(&m, true).unwrap()["bodyOmissions"],
        json!(["part_limit"])
    );
}
#[tokio::test]
async fn message_and_thread_mutations_use_explicit_routes_with_no_bulk_expansion() {
    let server = MockServer::start().await;
    let p = provider(&server);
    for entity in ["message", "thread"] {
        for (verb, endpoint) in [
            ("archive", "modify"),
            ("trash", "trash"),
            ("restore", "untrash"),
        ] {
            let mut m = Mock::given(method("POST"))
                .and(path(format!(
                    "/gmail/v1/users/me/{entity}s/a123/{endpoint}"
                )))
                .and(header("authorization", "Bearer secret"));
            if verb == "archive" {
                m = m.and(body_json(json!({"removeLabelIds":["INBOX"]})));
            }
            m.respond_with(
                ResponseTemplate::new(200).set_body_json(json!({"id":"a123","labelIds":["SENT"]})),
            )
            .expect(1)
            .mount(&server)
            .await;
            let r = p
                .invoke(invocation(
                    &format!("{entity}.{verb}"),
                    json!({"id":"a123"}),
                ))
                .await
                .unwrap();
            assert_eq!(r.object_ids, Some(json!({entity:"a123"})));
            assert_eq!(r.upstream_status, Some(200));
            assert_eq!(r.result["kind"], entity);
            assert_eq!(r.result["operation"], verb);
            assert_eq!(
                r.audit.unwrap(),
                json!({"provider":"gmail","operation":format!("{entity}.{verb}")})
            );
        }
    }
    assert_eq!(server.received_requests().await.unwrap().len(), 6);
}
#[tokio::test]
async fn search_is_one_page_with_explicit_trash_and_metadata_only_details() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/gmail/v1/users/me/messages"))
        .and(query_param("includeSpamTrash", "true"))
        .and(query_param("q", "in:trash"))
        .and(query_param("maxResults", "1"))
        .respond_with(ResponseTemplate::new(200).set_body_json(
            json!({"messages":[{"id":"a123","threadId":"b456"}],"nextPageToken":"next"}),
        ))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/gmail/v1/users/me/messages/a123"))
        .and(query_param("format", "metadata"))
        .respond_with(ResponseTemplate::new(200).set_body_json(message()))
        .expect(1)
        .mount(&server)
        .await;
    let r = provider(&server)
        .invoke(invocation(
            "message.search",
            json!({"query":"in:trash","maxResults":1,"includeSpamTrash":true}),
        ))
        .await
        .unwrap();
    // Gmail's token is returned only inside a Broker envelope.
    let token = r.result["nextPageToken"].as_str().unwrap();
    assert_ne!(token, "next");
    assert!(token.len() <= MAX_PAGE_TOKEN_BYTES);
    assert_eq!(r.result["messages"][0]["textParts"], json!([]));
    assert!(!r.audit.unwrap().to_string().contains("trash"));
    assert_eq!(server.received_requests().await.unwrap().len(), 2);
}
#[tokio::test]
async fn rate_limits_and_ambiguous_mutations_never_replay() {
    let date = UpstreamRetryAfter::after_seconds(40)
        .at()
        .format("%a, %d %b %Y %H:%M:%S GMT")
        .to_string();
    for (status, reason, retry_after, expected, wait) in [
        (
            403,
            "userRateLimitExceeded",
            Some("12"),
            ReasonCode::UpstreamRateLimited,
            Some(12..=12),
        ),
        (
            403,
            "rateLimitExceeded",
            None,
            ReasonCode::UpstreamRateLimited,
            None,
        ),
        (
            403,
            "dailyLimitExceeded",
            Some("200000"),
            ReasonCode::UpstreamRateLimited,
            Some(86_400..=86_400),
        ),
        (
            429,
            "rateLimitExceeded",
            Some(date.as_str()),
            ReasonCode::UpstreamRateLimited,
            Some(38..=41),
        ),
        (
            403,
            "forbidden",
            Some("12"),
            ReasonCode::ServiceActionDenied,
            None,
        ),
        (500, "backendError", None, ReasonCode::UpstreamFailed, None),
    ] {
        let server = MockServer::start().await;
        let mut template = ResponseTemplate::new(status)
            .set_body_json(json!({"error":{"message":"secret body","errors":[{"reason":reason}]}}));
        if let Some(value) = retry_after {
            template = template.insert_header("Retry-After", value);
        }
        Mock::given(method("POST"))
            .respond_with(template)
            .expect(1)
            .mount(&server)
            .await;
        let err = provider(&server)
            .invoke(invocation("thread.trash", json!({"id":"a123"})))
            .await
            .unwrap_err();
        assert_eq!(err.object_ids.as_deref(), Some(&json!({"thread":"a123"})));
        assert_eq!(err.upstream_status, Some(status));
        assert_eq!(err.reason_code(), expected, "{status} {reason}");
        assert!(!err.message.contains("secret"));
        assert_eq!(server.received_requests().await.unwrap().len(), 1);
        if expected != ReasonCode::UpstreamRateLimited {
            assert!(err.result.is_none());
            continue;
        }
        assert_eq!(err.decision(), Decision::Error);
        let result = err.result.as_deref().unwrap();
        assert_eq!(result["limitScope"], "upstream");
        assert_eq!(result["service"], "gmail");
        assert!(result.get("retrySafe").is_none());
        assert!(result.get("executionState").is_none());
        match wait {
            Some(range) => {
                let seconds = result["retryAfterSeconds"].as_u64().unwrap();
                assert!(range.contains(&seconds), "{reason}: {seconds}");
                assert_eq!(
                    err.message,
                    format!(
                        "gmail is rate limiting requests. Retry after {seconds}s (at {}).",
                        result["retryAt"].as_str().unwrap()
                    )
                );
            }
            None => {
                assert!(result.get("retryAfterSeconds").is_none());
                assert_eq!(err.message, "gmail is rate limiting requests. Retry later.");
            }
        }
    }
}
#[tokio::test]
async fn provider_bounds_total_response_bytes_and_unexpected_page_size() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(json!({"messages":[{"id":"a123"},{"id":"a124"}]})),
        )
        .mount(&server)
        .await;
    assert!(
        provider(&server)
            .invoke(invocation("message.search", json!({"maxResults":1})))
            .await
            .is_err()
    );
    let mut p = provider(&server);
    p.max_bytes = 8;
    assert!(
        p.invoke(invocation("account.view", json!({})))
            .await
            .is_err()
    );
}

#[test]
fn long_threads_keep_metadata_and_mark_text_and_charset_limits() {
    let mut m = message();
    let text = m["payload"].clone();
    m["payload"] = json!({"mimeType":"multipart/alternative","parts":[text.clone(),text]});
    let thread = mail::thread(&json!({"id":"b456","messages":vec![m.clone();50]})).unwrap();
    assert_eq!(thread["messages"].as_array().unwrap().len(), 50);
    assert!(
        thread["messages"]
            .as_array()
            .unwrap()
            .iter()
            .all(|m| m["bodyTruncated"] == false)
    );
    m["payload"]["parts"][0]["body"]["data"] =
        json!(URL_SAFE_NO_PAD.encode(vec![b'a'; 200 * 1024]));
    let thread = mail::thread(&json!({"id":"b456","messages":[m.clone(),m]})).unwrap();
    assert_eq!(thread["messages"][1]["id"], "a123");
    assert_eq!(
        thread["messages"][1]["bodyOmissions"],
        json!(["text_limit"])
    );
    let mut m = message();
    m["payload"]["headers"] = json!([{"name":"Content-Type","value":"text/plain; charset=x-unknown"},{"name":"X-Unused","value":"a".repeat(20000)}]);
    m["payload"]["body"]["data"] = json!(URL_SAFE_NO_PAD.encode([0xff]));
    let projected = mail::message(&m, true).unwrap();
    assert_eq!(projected["textParts"][0]["charsetFallback"], true);
    assert_eq!(projected["textParts"][0]["decodeErrors"], true);
}

#[tokio::test]
async fn non_json_failures_keep_status_and_only_uncertain_writes_get_unknown_outcome() {
    for (status, reason) in [
        (429, ReasonCode::UpstreamRateLimited),
        (503, ReasonCode::UpstreamFailed),
        (400, ReasonCode::InputInvalid),
        (409, ReasonCode::UpstreamFailed),
    ] {
        for action in ["message.view", "message.trash"] {
            let server = MockServer::start().await;
            Mock::given(path(if action.ends_with("view") {
                "/gmail/v1/users/me/messages/a123"
            } else {
                "/gmail/v1/users/me/messages/a123/trash"
            }))
            .respond_with(
                ResponseTemplate::new(status)
                    .set_body_string("<html>private upstream detail</html>"),
            )
            .expect(1)
            .mount(&server)
            .await;
            let error = provider(&server)
                .invoke(invocation(action, json!({"id":"a123"})))
                .await
                .unwrap_err();
            assert_eq!(error.reason_code(), reason);
            assert_eq!(error.upstream_status, Some(status));
            assert_eq!(
                error.message.contains("unknown"),
                status >= 500 && action.ends_with("trash")
            );
            assert!(!error.message.contains("private"));
        }
    }
}

#[test]
fn oversized_part_metadata_preserves_every_message_in_a_thread() {
    let mut attachment = message();
    attachment["payload"]["mimeType"] = json!("application/octet-stream");
    attachment["payload"]["filename"] = json!("é".repeat(3000));
    let mut invalid_mime = message();
    invalid_mime["payload"]["mimeType"] = json!("x".repeat(257));
    let thread =
        mail::thread(&json!({"id":"b456","messages":[attachment, invalid_mime, message()]}))
            .unwrap();
    let messages = thread["messages"].as_array().unwrap();
    assert_eq!(messages.len(), 3);
    assert!(
        messages
            .iter()
            .all(|m| m["id"] == "a123" && m["headers"][0]["value"] == "private subject")
    );
    assert_eq!(messages[0]["attachments"][0]["filenameTruncated"], true);
    assert_eq!(
        messages[0]["attachments"][0]["filename"]
            .as_str()
            .unwrap()
            .len(),
        4096
    );
    assert_eq!(messages[1]["bodyOmissions"], json!(["part_metadata_limit"]));
    assert_eq!(messages[2]["textParts"][0]["text"], "private body");
}

/// Mounts one search page with no messages: the first page when `page_token`
/// is `None`, otherwise the page Gmail's `page_token` continues, answering
/// `next` as Gmail's continuation.
async fn mount_page(server: &MockServer, page_token: Option<&str>, next: Option<&str>) {
    let mut page = json!({"resultSizeEstimate":0});
    if let Some(next) = next {
        page["nextPageToken"] = json!(next);
    }
    let mock = Mock::given(method("GET")).and(path("/gmail/v1/users/me/messages"));
    match page_token {
        Some(token) => mock.and(query_param("pageToken", token)),
        None => mock.and(wiremock::matchers::query_param_is_missing("pageToken")),
    }
    .respond_with(ResponseTemplate::new(200).set_body_json(page))
    .expect(1)
    .mount(server)
    .await;
}
async fn first_page_token(p: &GmailProvider, first: InvocationBuilder) -> String {
    let page = p.invoke(first.build()).await.unwrap();
    page.result["nextPageToken"].as_str().unwrap().to_owned()
}
async fn list_requests(server: &MockServer, page_token: &str) -> Vec<wiremock::Request> {
    server
        .received_requests()
        .await
        .unwrap()
        .into_iter()
        .filter(|r| {
            r.url.path() == "/gmail/v1/users/me/messages"
                && r.url
                    .query_pairs()
                    .any(|(k, v)| k == "pageToken" && v == page_token)
        })
        .collect()
}

#[tokio::test]
async fn search_continuations_round_trip_with_normalized_defaults() {
    let server = MockServer::start().await;
    mount_page(&server, None, Some("upstream-page-2")).await;
    mount_page(&server, Some("upstream-page-2"), None).await;
    let p = provider(&server);
    // Omitted defaults bind as their values, so a page requested with them
    // explicitly (as the typed CLI does) continues the same search.
    let token = first_page_token(&p, request("message.search", json!({"query":"in:inbox"}))).await;
    assert_ne!(token, "upstream-page-2");
    let raw = URL_SAFE_NO_PAD.decode(&token).unwrap();
    assert_eq!(raw[0], SEARCH_PAGES.version());
    assert!(token.len() <= MAX_PAGE_TOKEN_BYTES);
    let next = p
        .invoke(invocation(
            "message.search",
            json!({"query":"in:inbox","maxResults":20,"includeSpamTrash":false,"pageToken":token}),
        ))
        .await
        .unwrap();
    assert!(next.result["nextPageToken"].is_null());
    let continued = list_requests(&server, "upstream-page-2").await;
    assert_eq!(continued.len(), 1);
    let pairs: BTreeMap<_, _> = continued[0].url.query_pairs().into_owned().collect();
    assert_eq!(pairs["q"], "in:inbox");
    assert_eq!(pairs["maxResults"], "20");
    assert_eq!(pairs["includeSpamTrash"], "false");
}

#[tokio::test]
async fn search_continuations_reject_changed_settings_caller_context_and_connection() {
    let server = MockServer::start().await;
    mount_page(&server, None, Some("upstream-page-2")).await;
    let p = provider(&server);
    let first = json!({"query":"label:work","maxResults":5});
    let token = first_page_token(&p, request("message.search", first.clone())).await;
    let continued = |inputs: Value| {
        let mut inputs = inputs;
        inputs["pageToken"] = json!(token);
        request("message.search", inputs)
    };
    let same = || continued(first.clone());
    let cases = vec![
        // Normalized query settings, including absence and defaults.
        (
            "query",
            continued(json!({"query":"label:home","maxResults":5})),
        ),
        ("absent query", continued(json!({"maxResults":5}))),
        ("empty query", continued(json!({"query":"","maxResults":5}))),
        (
            "maxResults",
            continued(json!({"query":"label:work","maxResults":6})),
        ),
        (
            "default maxResults",
            continued(json!({"query":"label:work"})),
        ),
        (
            "includeSpamTrash",
            continued(json!({"query":"label:work","maxResults":5,"includeSpamTrash":true})),
        ),
        // The admitted execution context, caller and credential mode.
        ("context", same().execution_context("external")),
        ("principal", same().principal("mallory")),
        (
            "authentication",
            same().identity(InvocationIdentity::new("alice", false)),
        ),
        ("mode", same().credential_mode(CredentialMode::Service)),
        // Reconnecting or replacing the account changes the binding identity.
        (
            "connection",
            same().delegated(delegated(lease("gmail-reconnected-binding", "secret"))),
        ),
    ];
    // Another provider instance, as after a reload, has its own key.
    let reloaded = provider(&server);
    for (change, builder) in cases {
        let error = p.invoke(builder.build()).await.unwrap_err();
        assert_eq!(error.reason_code(), ReasonCode::InputInvalid, "{change}");
        assert_eq!(error.decision(), Decision::Deny, "{change}");
        assert!(error.message.contains("restart the search"), "{change}");
    }
    let error = reloaded.invoke(same().build()).await.unwrap_err();
    assert_eq!(error.reason_code(), ReasonCode::InputInvalid);
    // A lease for another target or audience is refused as a credential
    // before its continuation is considered.
    for (target, audience) in [
        ("other", GMAIL_AUDIENCE),
        (GMAIL_TARGET, "https://other.test/"),
    ] {
        let mut other = lease(BINDING, "secret");
        other.target = target;
        other.audience = audience;
        let error = p
            .invoke(same().delegated(delegated(other)).build())
            .await
            .unwrap_err();
        assert_eq!(error.reason_code(), ReasonCode::CredentialInvalid);
    }
    // Only the first page reached Gmail, and the unchanged request continues.
    assert_eq!(server.received_requests().await.unwrap().len(), 1);
    mount_page(&server, Some("upstream-page-2"), None).await;
    p.invoke(same().build()).await.unwrap();
}

#[tokio::test]
async fn search_continuations_are_purpose_separated_expiring_and_tamper_evident() {
    const OTHER_PURPOSE: ContinuationFamily = ContinuationFamily::new(
        "gmail",
        "thread-search-page",
        1,
        ContinuationLifetime::Generation,
        MAX_UPSTREAM_PAGE_TOKEN_BYTES,
    )
    .expires_after(Duration::from_secs(SEARCH_PAGE_TOKEN_TTL_MINUTES * 60));
    let server = MockServer::start().await;
    let p = provider(&server);
    let builder = request("message.search", json!({}));
    let template = builder.clone().build();
    let credential = template.execution().delegated().unwrap();
    let settings = SearchSettings::from_inputs(template.inputs());
    let binding = p.search_binding(template.context(), credential, &settings);
    let page = "upstream-page-2";
    let foreign = p
        .search_pages
        .seal_relayed(
            &OTHER_PURPOSE
                .bind(template.context(), p.client.base().as_str())
                .delegated(credential)
                .optional_text("query", None)
                .number("maxResults", DEFAULT_MAX_RESULTS)
                .flag("includeSpamTrash", false),
            None,
            page,
        )
        .unwrap();
    let expired = p
        .search_pages
        .seal_relayed_at(
            &binding,
            None,
            page,
            SystemTime::now() - Duration::from_secs(SEARCH_PAGE_TOKEN_TTL_MINUTES * 60 + 1),
        )
        .unwrap();
    // A token sealed as an ordinary envelope is not a relayed page token.
    let ordinary = p.search_pages.seal(&binding, page.as_bytes()).unwrap();
    let valid = p.search_pages.seal_relayed(&binding, None, page).unwrap();
    let mut tampered = valid.clone().into_bytes();
    let middle = tampered.len() / 2;
    tampered[middle] = if tampered[middle] == b'A' { b'B' } else { b'A' };
    let tampered = String::from_utf8(tampered).unwrap();
    // Raw upstream tokens are no longer accepted.
    for token in [
        foreign,
        expired,
        tampered,
        ordinary,
        "upstream-page-2".to_owned(),
    ] {
        let error = p
            .invoke(builder.clone().input("pageToken", json!(token)).build())
            .await
            .unwrap_err();
        assert_eq!(error.reason_code(), ReasonCode::InputInvalid);
    }
    assert!(server.received_requests().await.unwrap().is_empty());
    // The same binding's current token does reach Gmail.
    mount_page(&server, Some("upstream-page-2"), None).await;
    p.invoke(builder.input("pageToken", json!(valid)).build())
        .await
        .unwrap();
}

#[tokio::test]
async fn search_continuations_survive_access_refresh_and_recover_only_one_401() {
    let server = MockServer::start().await;
    mount_page(&server, None, Some("upstream-page-2")).await;
    let p = provider(&server);
    let token = first_page_token(&p, request("message.search", json!({}))).await;
    let continuation = |lease: Lease| {
        request("message.search", json!({"pageToken":token}))
            .delegated(delegated(lease))
            .build()
    };
    let refreshing = || {
        let mut refreshed = lease(BINDING, "refreshed");
        refreshed.recovers_to = Some("recovered");
        refreshed
    };
    // Routine refresh renews the access under the same binding: the
    // continuation opens, and the one explicit 401 recovery repeats that page.
    let page = |authorization: &'static str, status: u16| {
        Mock::given(method("GET"))
            .and(path("/gmail/v1/users/me/messages"))
            .and(query_param("pageToken", "upstream-page-2"))
            .and(header("authorization", authorization))
            .respond_with(ResponseTemplate::new(status).set_body_json(json!({})))
    };
    page("Bearer refreshed", 401).expect(1).mount(&server).await;
    page("Bearer recovered", 200).expect(1).mount(&server).await;
    let next = p.invoke(continuation(refreshing())).await.unwrap();
    assert!(next.result["nextPageToken"].is_null());
    assert_eq!(list_requests(&server, "upstream-page-2").await.len(), 2);
    // A second 401 never causes a third dispatch.
    server.reset().await;
    page("Bearer refreshed", 401).expect(1).mount(&server).await;
    page("Bearer recovered", 401).expect(1).mount(&server).await;
    let error = p.invoke(continuation(refreshing())).await.unwrap_err();
    assert_eq!(error.reason_code(), ReasonCode::CredentialInvalid);
    assert_eq!(error.upstream_status, Some(401));
    assert_eq!(server.received_requests().await.unwrap().len(), 2);
}

#[tokio::test]
async fn upstream_page_tokens_keep_their_cap_and_are_never_truncated() {
    let largest = "7".repeat(MAX_UPSTREAM_PAGE_TOKEN_BYTES);
    let server = MockServer::start().await;
    mount_page(&server, None, Some(&largest)).await;
    mount_page(&server, Some(&largest), None).await;
    let p = provider(&server);
    let token = first_page_token(&p, request("message.search", json!({}))).await;
    // The input bound is exactly the largest envelope's size.
    assert_eq!(MAX_PAGE_TOKEN_BYTES, 2786);
    assert_eq!(token.len(), MAX_PAGE_TOKEN_BYTES);
    let search = descriptor()
        .actions
        .into_iter()
        .find(|a| a.action == "message.search")
        .unwrap();
    assert_eq!(
        search.input_schema["properties"]["pageToken"]["maxLength"],
        MAX_PAGE_TOKEN_BYTES
    );
    p.invoke(invocation("message.search", json!({"pageToken":token})))
        .await
        .unwrap();
    assert_eq!(list_requests(&server, &largest).await.len(), 1);
    // One byte more is an upstream protocol failure.
    let server = MockServer::start().await;
    mount_page(
        &server,
        None,
        Some(&"7".repeat(MAX_UPSTREAM_PAGE_TOKEN_BYTES + 1)),
    )
    .await;
    let error = provider(&server)
        .invoke(invocation("message.search", json!({})))
        .await
        .unwrap_err();
    assert_eq!(error.reason_code(), ReasonCode::UpstreamProtocolFailed);
    assert_eq!(error.decision(), Decision::Error);
    assert!(error.message.contains("not truncated"), "{}", error.message);
    assert!(error.result.is_none());
}

/// Every search continuation failure the invoke hook can report stays within
/// the provider-reportable subset for an invocation.
#[test]
fn page_token_failures_pass_the_invocation_contract() {
    let hook = agent_access_provider::host::hook_context(
        "gmail",
        "message.search",
        HookPhase::Invocation,
        GMAIL_BACKEND.domain_reasons(),
    );
    for error in [
        ContinuationError::Invalid,
        ContinuationError::UnsupportedVersion,
        ContinuationError::Expired,
        ContinuationError::UpstreamQueryChanged,
        ContinuationError::TokenTooLarge { limit: 1 },
        ContinuationError::PayloadTooLarge { limit: 1 },
        ContinuationError::SigningUnavailable,
        ContinuationError::DurableKeyUnavailable,
    ] {
        let failure = page_token_failure(error);
        assert_eq!(
            hook.check_failure(&failure),
            Ok(()),
            "{error:?}: {failure:?}"
        );
    }
    for failure in [page_token_error(), oversized_page_token()] {
        assert_eq!(hook.check_failure(&failure), Ok(()), "{failure:?}");
    }
}
