use super::*;
use agent_access_provider::test_support::InvocationBuilder;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{body_json, header, method, path, query_param},
};

struct Lease;
#[async_trait]
impl DelegatedLease for Lease {
    fn binding_identity(&self) -> DelegatedBindingId {
        agent_access_provider::test_support::delegated_binding_id("gmail-test-binding")
    }
    fn mark_rejected(&self, _: &str) -> Result<(), ProviderError> {
        Ok(())
    }
    fn access(&self) -> DelegatedAccess {
        DelegatedAccess {
            token: "secret".into(),
            target: GMAIL_TARGET.into(),
            audience: GMAIL_AUDIENCE.into(),
            version: "v1".into(),
            expires_at: i64::MAX,
        }
    }
    async fn revalidate(&self) -> Result<(), ProviderError> {
        Ok(())
    }
    async fn recover_after_unauthorized(&self) -> Result<DelegatedAccess, ProviderError> {
        Err(ProviderError::deny(
            ReasonCode::CredentialInvalid,
            "test refused refresh",
        ))
    }
}
/// A lease whose refresh is already in progress for the same connection.
struct BusyLease;
#[async_trait]
impl DelegatedLease for BusyLease {
    fn binding_identity(&self) -> DelegatedBindingId {
        Lease.binding_identity()
    }
    fn mark_rejected(&self, _: &str) -> Result<(), ProviderError> {
        Ok(())
    }
    fn access(&self) -> DelegatedAccess {
        Lease.access()
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
        .delegated(DelegatedCredential::new(Arc::new(BusyLease)))
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

fn invocation(action: &str, inputs: Value) -> ProviderInvocation {
    InvocationBuilder::new("gmail", action)
        .inputs(inputs)
        .correlation(CorrelationContext::new(
            "gmail-test".into(),
            "gmail-broker-test".into(),
        ))
        .credential_mode(CredentialMode::PerUser)
        .delegated(DelegatedCredential::new(Arc::new(Lease)))
        .build()
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
    ] {
        assert!(validate_inputs("message.search", &inputs).is_err());
    }
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
    assert_eq!(r.result["nextPageToken"], "next");
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
