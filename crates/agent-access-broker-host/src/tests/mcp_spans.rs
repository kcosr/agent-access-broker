//! Owned execution must finish populating the originating HTTP request span.
use super::*;
use tracing::{Id, span};

#[derive(Clone, Default)]
struct RequestSpans(Arc<std::sync::Mutex<BTreeMap<u64, BTreeMap<String, Value>>>>);

impl<S> tracing_subscriber::Layer<S> for RequestSpans
where
    S: Subscriber + for<'a> LookupSpan<'a>,
{
    fn on_new_span(&self, attrs: &span::Attributes<'_>, id: &Id, _: TracingLayerContext<'_, S>) {
        if attrs.metadata().name() == "http.request" {
            let mut fields = BTreeMap::new();
            attrs.record(&mut JsonVisitor(&mut fields));
            self.0.lock().unwrap().insert(id.into_u64(), fields);
        }
    }
    fn on_record(&self, id: &Id, values: &span::Record<'_>, _: TracingLayerContext<'_, S>) {
        if let Some(fields) = self.0.lock().unwrap().get_mut(&id.into_u64()) {
            values.record(&mut JsonVisitor(fields));
        }
    }
}

#[test]
fn rest_and_mcp_owned_results_populate_the_originating_request_span() {
    let _capture_lock = crate::observability::tracing_capture_test_lock().blocking_lock();
    let _registration_guard = tracing::Dispatch::new(tracing::subscriber::NoSubscriber::default());
    let captured = RequestSpans::default();
    let _subscriber =
        tracing::subscriber::set_default(tracing_subscriber::registry().with(captured.clone()));
    tracing_core::callsite::rebuild_interest_cache();
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(async {
            let fixture = mcp::Fixture::new(|_| {}).await;
            let session = fixture.initialize().await;
            for (transport, project, expected_decision) in [
                ("rest", "TEST", "allow"),
                ("rest", "OTHER", "deny"),
                ("mcp", "TEST", "allow"),
                ("mcp", "OTHER", "deny"),
            ] {
                let request_id = format!("span-{transport}-{project}");
                let inputs = json!({"project":project,"message":"span regression"});
                let mut request = if transport == "rest" {
                    Request::builder()
                        .method(Method::POST)
                        .uri("/v1/invoke/fake/echo")
                        .extension(ConnectInfo(
                            "127.0.0.1:45000".parse::<SocketAddr>().unwrap(),
                        ))
                        .header(AUTHORIZATION, format!("Bearer {}", mcp::TOKEN_A))
                        .header(CONTENT_TYPE, "application/json")
                        .body(Body::from(json!({"inputs":inputs}).to_string()))
                        .unwrap()
                } else {
                    mcp::request(
                        Method::POST,
                        Some(mcp::TOKEN_A),
                        Some(&session),
                        Some(json!({
                            "jsonrpc":"2.0","id":request_id,"method":"tools/call","params":{
                                "name":agent_access_core::mcp::tool_name("fake","echo"),
                                "arguments":{"inputs":inputs}
                            }
                        })),
                    )
                };
                request
                    .headers_mut()
                    .insert(REQUEST_ID_HEADER, request_id.parse().unwrap());
                let response = tokio::time::timeout(
                    Duration::from_secs(10),
                    fixture.app.clone().oneshot(request),
                )
                .await
                .unwrap()
                .unwrap();
                let envelope = if transport == "rest" {
                    response_json(response).await
                } else {
                    mcp::rpc_body(response).await["result"]["structuredContent"].clone()
                };
                assert_eq!(envelope["decision"], expected_decision, "{envelope}");
                let spans = captured.0.lock().unwrap();
                let span = spans
                    .values()
                    .find(|fields| fields.get("agentRequestId") == Some(&json!(request_id)))
                    .expect("originating HTTP request span has correlation");
                for (field, expected) in [
                    ("service", json!("fake")),
                    ("action", json!("echo")),
                    ("principal", json!("mcp-user")),
                    ("decision", json!(expected_decision)),
                    ("brokerRequestId", envelope["brokerRequestId"].clone()),
                ] {
                    assert_eq!(
                        span.get(field),
                        Some(&expected),
                        "{transport} missing {field}: {span:?}"
                    );
                }
                assert!(span.contains_key("configGeneration"));
                let broker_status = if expected_decision == "deny" {
                    403
                } else {
                    200
                };
                assert_eq!(
                    span.get("http.statusCode"),
                    Some(&json!(if transport == "mcp" {
                        200
                    } else {
                        broker_status
                    }))
                );
                if transport == "mcp" {
                    assert_eq!(span.get("broker.statusCode"), Some(&json!(broker_status)));
                }
                if expected_decision == "deny" {
                    assert_eq!(span.get("reasonCode"), envelope.get("reasonCode"));
                }
            }
        });
}
