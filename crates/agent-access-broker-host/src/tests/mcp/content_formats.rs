//! Connection preferences are request data, including on reused SDK sessions.
use super::*;
use agent_access_provider::presentation::{
    ActionPresentation, EmbeddedBody, EmbeddedBodyCodec, OutputContentFormat, RenderBudget,
    RenderError, SelectedContent,
};

struct TestBody;
const FORMATS: &[OutputContentFormat] = &[OutputContentFormat::Markdown, OutputContentFormat::Text];
const BODIES: &[EmbeddedBody] = &[EmbeddedBody::new(&[], "body", &TestBody)];

impl EmbeddedBodyCodec for TestBody {
    fn supported_formats(&self) -> &'static [OutputContentFormat] {
        FORMATS
    }

    fn select(
        &self,
        source: &Value,
        format: OutputContentFormat,
        max_body_bytes: u64,
        _budget: &mut RenderBudget,
    ) -> Result<Option<SelectedContent>, RenderError> {
        let source = source.as_str().ok_or(RenderError)?;
        if source.len() as u64 > max_body_bytes {
            return Err(RenderError);
        }
        match format {
            OutputContentFormat::Markdown => Ok(Some(SelectedContent::markdown(source))),
            OutputContentFormat::Text => Ok(Some(SelectedContent::text(source))),
            _ => Err(RenderError),
        }
    }
}

#[derive(Clone, Default)]
struct ContentProvider {
    lookups: Arc<AtomicUsize>,
    executions: Arc<AtomicUsize>,
}

impl agent_access_provider::test_support::DescribedProvider for ContentProvider {
    fn descriptor(&self) -> ServiceDescriptor {
        let mut descriptor = agent_access_fake::fake_descriptor()
            .with_preferred_output_content_format(OutputContentFormat::Text);
        descriptor.credentials = CredentialDescriptor::default();
        descriptor.actions[0].presentation = Some(ActionPresentation::new(
            BODIES,
            FORMATS,
            OutputContentFormat::Markdown,
        ));
        descriptor
    }
}

#[async_trait::async_trait]
impl Provider for ContentProvider {
    async fn resolve_scopes(
        &self,
        request: ScopeRequest<'_>,
    ) -> Result<ScopeResolution, ProviderError> {
        self.lookups.fetch_add(1, Ordering::SeqCst);
        agent_access_fake::FakeProvider
            .echo_scopes("echo", request.inputs())
            .map(ScopeResolution::resources)
    }

    async fn invoke(&self, _request: ProviderInvocation) -> Result<ProviderResult, ProviderError> {
        self.executions.fetch_add(1, Ordering::SeqCst);
        Ok(ProviderResult::new(json!({
            "body":"synthetic rich content", "unchanged":"metadata"
        })))
    }
}

fn at(path: &str, mut request: Request<Body>) -> Request<Body> {
    *request.uri_mut() = path.parse().unwrap();
    request
}

async fn rpc(
    fixture: &Fixture,
    path: &str,
    session: &str,
    id: u64,
    method: &str,
    params: Value,
) -> Value {
    let response = fixture
        .send(at(
            path,
            request(
                Method::POST,
                Some(TOKEN_A),
                Some(session),
                Some(json!({"jsonrpc":"2.0","id":id,"method":method,"params":params})),
            ),
        ))
        .await;
    assert_eq!(response.status(), StatusCode::OK);
    rpc_body(response).await
}

fn invoke(name: &str, exact: Option<&str>) -> Value {
    let mut arguments = json!({"inputs":{"project":"TEST","message":"fixture"}});
    if let Some(exact) = exact {
        arguments["outputContentFormat"] = json!(exact);
    }
    json!({"name":name,"arguments":arguments})
}

#[tokio::test]
async fn http_mcp_preferences_are_per_request_with_exact_override_and_native_fallback() {
    let provider = ContentProvider::default();
    let fixture = Fixture::with_providers(|_| {}, vec![Arc::new(provider.clone())]).await;
    let mut calls = 0;
    for (base, name) in [("/mcp", "fake_echo"), ("/mcp/fake", "echo")] {
        let session = scoped::initialize(&fixture, base, TOKEN_A).await;
        for (index, preference, exact, expected) in [
            (0, None, None, "text"),
            (1, Some("markdown"), None, "markdown"),
            // Unsupported preference falls straight to native, not service text.
            (2, Some("adf"), None, "markdown"),
            (3, Some("storage"), Some("text"), "text"),
            // A previous request's preference never changes the reusable handler.
            (4, None, None, "text"),
        ] {
            let path = preference.map_or_else(
                || base.to_owned(),
                |preference| format!("{base}?preferredOutputContentFormat={preference}"),
            );
            let result = rpc(
                &fixture,
                &path,
                &session,
                10 + index,
                "tools/call",
                invoke(name, exact),
            )
            .await;
            assert_eq!(result["result"]["isError"], false, "{result}");
            let envelope = structured(&result);
            assert_eq!(
                envelope["result"]["body"],
                json!({"format":expected,"value":"synthetic rich content"})
            );
            assert_eq!(envelope["result"]["unchanged"], "metadata");
            assert!(envelope["result"].get("renderedBody").is_none());
            calls += 1;
            assert_eq!(provider.executions.load(Ordering::SeqCst), calls);
        }

        let detail = rpc(
            &fixture,
            &format!("{base}?preferredOutputContentFormat=adf"),
            &session,
            20,
            "tools/call",
            json!({"name":"actions_describe","arguments":{"service":"fake","action":"echo"}}),
        )
        .await;
        assert_eq!(
            structured(&detail)["defaultOutputContentFormat"],
            "markdown"
        );
        let detail = rpc(
            &fixture,
            base,
            &session,
            21,
            "tools/call",
            json!({"name":"actions_describe","arguments":{"service":"fake","action":"echo"}}),
        )
        .await;
        assert_eq!(structured(&detail)["defaultOutputContentFormat"], "text");
        let properties = &structured(&detail)["mcpTool"]["inputSchema"]["properties"];
        assert!(properties.get("preferredOutputContentFormat").is_none());
        assert!(properties["outputContentFormat"].get("default").is_none());

        let lookups = provider.lookups.load(Ordering::SeqCst);
        for (index, field, value) in [
            (30, "outputContentFormat", json!("adf")),
            (31, "outputContentFormat", Value::Null),
            (32, "preferredOutputContentFormat", json!("text")),
            (33, "readContentFormat", json!("text")),
            (34, "responseFormat", json!("markdown")),
        ] {
            let mut params = invoke(name, None);
            params["arguments"][field] = value;
            let rejected = rpc(&fixture, base, &session, index, "tools/call", params).await;
            assert_eq!(rejected["result"]["isError"], true, "{rejected}");
        }
        assert_eq!(provider.lookups.load(Ordering::SeqCst), lookups);
        assert_eq!(provider.executions.load(Ordering::SeqCst), calls);

        let markdown = format!("{base}?preferredOutputContentFormat=markdown");
        let text = format!("{base}?preferredOutputContentFormat=text");
        let (markdown, text) = tokio::join!(
            rpc(
                &fixture,
                &markdown,
                &session,
                40,
                "tools/call",
                invoke(name, None)
            ),
            rpc(
                &fixture,
                &text,
                &session,
                41,
                "tools/call",
                invoke(name, None)
            ),
        );
        assert_eq!(
            structured(&markdown)["result"]["body"]["format"],
            "markdown"
        );
        assert_eq!(structured(&text)["result"]["body"]["format"], "text");
        calls += 2;
    }
    assert_eq!(provider.executions.load(Ordering::SeqCst), calls);
    let catalog = spec_get(
        fixture.app.clone(),
        "/v1/spec/catalog",
        "mcp-preference-canonical-catalog",
        Some(TOKEN_A),
    )
    .await;
    assert_eq!(catalog.status(), StatusCode::OK);
    let catalog = response_json(catalog).await;
    assert_eq!(
        catalog["services"][0]["actions"][0]["defaultOutputContentFormat"],
        "text"
    );
}

#[tokio::test]
async fn http_mcp_text_copy_is_per_request_and_composes_with_content_preferences() {
    let provider = ContentProvider::default();
    let fixture = Fixture::with_providers(|_| {}, vec![Arc::new(provider.clone())]).await;
    let mut calls = 0;
    for (base, name) in [("/mcp", "fake_echo"), ("/mcp/fake", "echo")] {
        // Initialize with false; following requests independently choose their mode.
        let session =
            scoped::initialize(&fixture, &format!("{base}?includeTextCopy=false"), TOKEN_A).await;
        for (index, query, has_copy, format) in [
            (0, "?includeTextCopy=false", false, "text"),
            (1, "", true, "text"),
            (2, "?includeTextCopy=true", true, "text"),
            (
                3,
                "?includeTextCopy=false&preferredOutputContentFormat=markdown",
                false,
                "markdown",
            ),
            (
                4,
                "?preferredOutputContentFormat=text&includeTextCopy=false",
                false,
                "text",
            ),
        ] {
            let path = format!("{base}{query}");
            let result = rpc(
                &fixture,
                &path,
                &session,
                10 + index,
                "tools/call",
                invoke(name, None),
            )
            .await;
            assert_eq!(result["result"]["isError"], false, "{result}");
            let envelope = structured(&result);
            assert_eq!(
                envelope["result"]["body"],
                json!({"format":format,"value":"synthetic rich content"})
            );
            assert_eq!(
                result["result"]["content"].as_array().unwrap().is_empty(),
                !has_copy
            );
            if has_copy {
                assert_eq!(
                    serde_json::from_str::<Value>(
                        result["result"]["content"][0]["text"].as_str().unwrap()
                    )
                    .unwrap(),
                    *envelope
                );
            }
            calls += 1;
            assert_eq!(provider.executions.load(Ordering::SeqCst), calls);
        }
        let path = format!("{base}?includeTextCopy=false");
        for (index, name, arguments, error) in [
            (20, "services_list", json!({}), false),
            (21, "services_describe", json!({"service":"fake"}), false),
            (
                22,
                "actions_describe",
                json!({"service":"fake","action":"echo"}),
                false,
            ),
            (
                23,
                "resource_access_describe",
                json!({"service":"fake"}),
                false,
            ),
            (
                24,
                "services_describe",
                json!({"service":"unavailable"}),
                true,
            ),
            (25, "services_describe", json!({"unexpected":true}), true),
            (26, name, json!({}), true),
            (27, name, json!({"inputs":{},"includeTextCopy":false}), true),
            (
                28,
                name,
                json!({"inputs":{"project":"PRIVATE","message":"fixture"}}),
                true,
            ),
        ] {
            let result = rpc(
                &fixture,
                &path,
                &session,
                index,
                "tools/call",
                json!({"name":name,"arguments":arguments}),
            )
            .await;
            assert_eq!(result["result"]["isError"], error, "{result}");
            assert_eq!(result["result"]["content"], json!([]), "{result}");
            assert!(
                result["result"]["structuredContent"].is_object(),
                "{result}"
            );
        }
        assert_eq!(provider.executions.load(Ordering::SeqCst), calls);
        // A protocol error stays a protocol error, with no synthetic tool result.
        let unknown = rpc(
            &fixture,
            &path,
            &session,
            40,
            "tools/call",
            json!({"name":"missing_tool","arguments":{}}),
        )
        .await;
        assert_eq!(unknown["error"]["code"], -32602);
        assert!(unknown.get("result").is_none());
        let original = rpc(&fixture, base, &session, 41, "tools/list", json!({})).await;
        let without_copy = rpc(&fixture, &path, &session, 42, "tools/list", json!({})).await;
        assert_eq!(original["result"], without_copy["result"]);
    }
}

#[tokio::test]
async fn http_mcp_no_text_copy_preserves_rate_charging_and_admission_errors() {
    let fixture = Fixture::new(|config| fake_invocation_limit(config, 2)).await;
    let session = fixture.initialize().await;
    let path = "/mcp?includeTextCopy=false";
    for id in 10..13 {
        let helper = rpc(
            &fixture,
            path,
            &session,
            id,
            "tools/call",
            json!({"name":"services_list","arguments":{}}),
        )
        .await;
        assert_eq!(helper["result"]["content"], json!([]));
        assert_eq!(helper["result"]["isError"], false);
    }
    for id in [20, 21] {
        let result = rpc(
            &fixture,
            path,
            &session,
            id,
            "tools/call",
            invoke("fake_echo", None),
        )
        .await;
        assert_eq!(structured(&result)["decision"], "allow", "{result}");
        assert_eq!(result["result"]["content"], json!([]));
    }
    let limited = rpc(
        &fixture,
        path,
        &session,
        22,
        "tools/call",
        invoke("fake_echo", None),
    )
    .await;
    assert_eq!(limited["result"]["content"], json!([]));
    assert_eq!(limited["result"]["isError"], true);
    assert_eq!(structured(&limited)["reasonCode"], "rate_limited");
    assert!(
        structured(&limited)["error"]["message"]
            .as_str()
            .unwrap()
            .contains("Retry after ")
    );
    let records = read_audit_records(&fixture.audit_path);
    assert_eq!(
        records
            .iter()
            .filter(|record| record["decision"] == "allow")
            .count(),
        2
    );
    assert_eq!(
        records
            .iter()
            .filter(|record| record["reasonCode"] == "rate_limited")
            .count(),
        1
    );
}

#[tokio::test]
async fn http_mcp_query_preferences_use_one_literal_closed_grammar() {
    let fixture = Fixture::new(|_| {}).await;
    let session = fixture.initialize().await;
    for base in ["/mcp", "/mcp/fake"] {
        for query in [
            "preferredOutputContentFormat=markdown",
            "preferredOutputContentFormat=text",
            "preferredOutputContentFormat=adf",
            "preferredOutputContentFormat=storage",
            "includeTextCopy=true",
            "includeTextCopy=false",
            "includeTextCopy=false&preferredOutputContentFormat=text",
            "preferredOutputContentFormat=markdown&includeTextCopy=true",
        ] {
            let response = fixture.send(at(
                &format!("{base}?{query}"),
                request(Method::POST, Some(TOKEN_A), None, Some(json!({
                    "jsonrpc":"2.0","id":1,"method":"initialize","params":{
                        "protocolVersion":VERSION,"capabilities":{},"clientInfo":{"name":"literal-query-test","version":"1"}
                    }
                }))),
            )).await;
            assert_eq!(response.status(), StatusCode::OK, "{query}");
            let created = response.headers()["mcp-session-id"]
                .to_str()
                .unwrap()
                .to_owned();
            let _ = rpc_body(response).await;
            let deleted = fixture
                .send(at(
                    base,
                    request(Method::DELETE, Some(TOKEN_A), Some(&created), None),
                ))
                .await;
            assert_eq!(deleted.status(), StatusCode::ACCEPTED);
        }
        for query in [
            "",
            "preferredOutputContentFormat",
            "preferredOutputContentFormat=",
            "preferredOutputContentFormat=null",
            "preferredOutputContentFormat=native",
            "preferredOutputContentFormat=Markdown",
            "preferredoutputcontentformat=text",
            "%70referredOutputContentFormat=text",
            "preferredOutputContentFormat=%74ext",
            "preferredOutputContentFormat=text+",
            "preferredOutputContentFormat=text&",
            "preferredOutputContentFormat=text&preferredOutputContentFormat=text",
            "preferredOutputContentFormat=text&preferredOutputContentFormat=adf",
            "preferredOutputContentFormat=text;token=QUERY_SECRET",
            "preferredOutputContentFormat=text&token=QUERY_SECRET",
            "token=QUERY_SECRET",
            "includeTextCopy",
            "includeTextCopy=",
            "includeTextCopy=True",
            "includeTextCopy=FALSE",
            "includeTextCopy=0",
            "includeTextCopy=1",
            "includeTextCopy=null",
            "includetextcopy=false",
            "%69ncludeTextCopy=false",
            "includeTextCopy=%66alse",
            "includeTextCopy=false+",
            "includeTextCopy=false=",
            "includeTextCopy=false&",
            "&includeTextCopy=false",
            "includeTextCopy=false&&preferredOutputContentFormat=text",
            "includeTextCopy=false&includeTextCopy=false",
            "includeTextCopy=false&includeTextCopy=true",
            "preferredOutputContentFormat=text&includeTextCopy=false&preferredOutputContentFormat=text",
            "includeTextCopy=false&unknown=QUERY_SECRET",
        ] {
            let rejected = fixture
                .send(at(
                    &format!("{base}?{query}"),
                    request(
                        Method::POST,
                        Some(TOKEN_A),
                        Some(&session),
                        Some(json!({"jsonrpc":"2.0","id":7,"method":"ping"})),
                    ),
                ))
                .await;
            assert_eq!(rejected.status(), StatusCode::BAD_REQUEST, "{query}");
            let body = axum::body::to_bytes(rejected.into_body(), 1024)
                .await
                .unwrap();
            assert!(!String::from_utf8_lossy(&body).contains("QUERY_SECRET"));
            assert!(String::from_utf8_lossy(&body).contains("Invalid MCP query options"));
        }
    }
}

#[tokio::test]
async fn http_mcp_catalog_cursor_is_bound_to_the_request_preference() {
    let fixture = Fixture::with_providers(
        |config| config.mcp.max_response_bytes = 64 * 1024,
        vec![Arc::new(CatalogProvider)],
    )
    .await;
    for base in ["/mcp", "/mcp/fake"] {
        let session = scoped::initialize(&fixture, base, TOKEN_A).await;
        let preferred = format!("{base}?preferredOutputContentFormat=text");
        let first = rpc(&fixture, &preferred, &session, 50, "tools/list", json!({})).await;
        let cursor = first["result"]["nextCursor"].as_str().unwrap();
        let same = rpc(
            &fixture,
            &preferred,
            &session,
            51,
            "tools/list",
            json!({"cursor":cursor}),
        )
        .await;
        assert!(same.get("error").is_none(), "{same}");
        let without_copy = rpc(
            &fixture,
            &format!("{base}?includeTextCopy=false&preferredOutputContentFormat=text"),
            &session,
            53,
            "tools/list",
            json!({"cursor":cursor}),
        )
        .await;
        assert_eq!(same["result"], without_copy["result"]);
        for path in [
            base.to_owned(),
            format!("{base}?preferredOutputContentFormat=markdown"),
        ] {
            let rejected = rpc(
                &fixture,
                &path,
                &session,
                52,
                "tools/list",
                json!({"cursor":cursor}),
            )
            .await;
            assert_eq!(rejected["error"]["code"], -32602);
        }
    }
}
