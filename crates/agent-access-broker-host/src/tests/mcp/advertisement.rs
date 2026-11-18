//! The `outputSchemas` endpoint query: one strict parser, evaluated on every
//! request with no session state, selecting only whether MCP output-schema
//! metadata is advertised.
use super::*;
use agent_access_provider::{ScopeRequest, ScopeResolution};

const QUERY_ERROR: &str =
    "Invalid MCP endpoint query; only outputSchemas=on or outputSchemas=off is accepted";
const SELECTIONS: [Selection; 3] = [Some(OutputSchemas::On), Some(OutputSchemas::Off), None];

fn initialize_message() -> Value {
    json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":VERSION,"capabilities":{},"clientInfo":{"name":"advertisement-tests","version":"1"}}})
}

fn without_output_schema(tool: &Value) -> Value {
    let mut tool = tool.clone();
    tool.as_object_mut().unwrap().remove("outputSchema");
    tool
}

fn by_name(tools: &[Value]) -> BTreeMap<String, Value> {
    tools
        .iter()
        .map(|tool| (tool["name"].as_str().unwrap().to_owned(), tool.clone()))
        .collect()
}

/// A tool result without the per-request correlation IDs.
fn comparable(response: &Value) -> Value {
    let mut result = response["result"].clone();
    if let Some(structured) = result
        .get_mut("structuredContent")
        .and_then(Value::as_object_mut)
    {
        structured.remove("agentRequestId");
        structured.remove("brokerRequestId");
    }
    if let Some(text) = result["content"][0]["text"].as_str()
        && let Ok(mut parsed) = serde_json::from_str::<Value>(text)
    {
        if let Some(object) = parsed.as_object_mut() {
            object.remove("agentRequestId");
            object.remove("brokerRequestId");
        }
        result["content"][0]["text"] = parsed;
    }
    result
}

async fn list(
    fixture: &Fixture,
    path: &str,
    selection: Selection,
    session: &str,
    id: u64,
) -> Vec<Value> {
    let listed = fixture
        .rpc_at(path, selection, session, id, "tools/list", json!({}))
        .await;
    assert!(listed["result"].get("nextCursor").is_none(), "{listed}");
    listed["result"]["tools"].as_array().unwrap().clone()
}

#[tokio::test]
async fn endpoint_query_accepts_one_exact_selection_and_rejects_everything_else_before_dispatch() {
    let fixture = Fixture::new(|_| {}).await;
    for path in ["/mcp", "/mcp/fake"] {
        for query in ["", "?outputSchemas=on", "?outputSchemas=off"] {
            let response = fixture
                .send(at_uri(
                    &format!("{path}{query}"),
                    request(
                        Method::POST,
                        Some(TOKEN_A),
                        None,
                        Some(initialize_message()),
                    ),
                ))
                .await;
            assert_eq!(response.status(), StatusCode::OK, "{path}{query}");
        }
        let session = fixture
            .initialize_at(path, Some(OutputSchemas::On), TOKEN_A, VERSION)
            .await;
        for query in [
            "?",
            "?outputSchemas",
            "?outputSchemas=",
            "?outputSchemas=ON",
            "?outputSchemas=On",
            "?outputSchemas=true",
            "?outputSchemas=1",
            "?outputSchemas=o%6E",
            "?output%53chemas=on",
            "?outputschemas=on",
            "?outputSchemas=on&outputSchemas=on",
            "?outputSchemas=on&outputSchemas=off",
            "?outputSchemas=on&",
            "?&outputSchemas=on",
            "?outputSchemas=on;secret=must-not-echo",
            "?outputSchemas=on&token=must-not-echo",
            "?token=must-not-echo",
            "?outputSchemas=must-not-echo",
            "?outputSchemas=on=on",
            "?=on",
            "?outputSchemas+=on",
        ] {
            let uri = format!("{path}{query}");
            for (token, session, message) in [
                (None, None, initialize_message()),
                (Some(TOKEN_A), None, initialize_message()),
                (
                    Some(TOKEN_A),
                    Some(session.as_str()),
                    json!({"jsonrpc":"2.0","id":2,"method":"tools/list"}),
                ),
            ] {
                let response = fixture
                    .send(at_uri(
                        &uri,
                        request(Method::POST, token, session, Some(message)),
                    ))
                    .await;
                assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{uri}");
                assert_eq!(response.headers()["cache-control"], "no-store");
                assert!(response.headers().get("mcp-session-id").is_none());
                assert!(!response.headers().contains_key("www-authenticate"));
                let body = rpc_body(response).await;
                assert_eq!(body, json!({"error": QUERY_ERROR}), "{uri}");
            }
            for method in [Method::DELETE, Method::GET] {
                let response = fixture
                    .send(at_uri(
                        &uri,
                        request(method.clone(), Some(TOKEN_A), Some(&session), None),
                    ))
                    .await;
                assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{method} {uri}");
            }
        }
        // A refused request leaves the session intact on every selection.
        for (id, selection) in (3..).zip(SELECTIONS) {
            assert_eq!(
                fixture
                    .rpc_at(path, selection, &session, id, "ping", json!({}))
                    .await["result"],
                json!({})
            );
        }
        // An authenticated GET with a valid selection keeps its 405.
        let get = fixture
            .send(at_uri(
                &endpoint(path, Some(OutputSchemas::On)),
                request(Method::GET, Some(TOKEN_A), Some(&session), None),
            ))
            .await;
        assert_eq!(get.status(), StatusCode::METHOD_NOT_ALLOWED);
        let delete = fixture
            .send(at_uri(
                &endpoint(path, Some(OutputSchemas::Off)),
                request(Method::DELETE, Some(TOKEN_A), Some(&session), None),
            ))
            .await;
        assert_eq!(delete.status(), StatusCode::ACCEPTED);
    }
    // Path checks still precede the query and keep their own message.
    let response = fixture
        .send(at_uri(
            "/mcp/FAKE?outputSchemas=on",
            request(
                Method::POST,
                Some(TOKEN_A),
                None,
                Some(initialize_message()),
            ),
        ))
        .await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        rpc_body(response).await,
        json!({"error":"Invalid MCP endpoint path"})
    );
    // Rejections are refused before any provider dispatch or audit.
    assert!(read_audit_records(&fixture.audit_path).is_empty());
}

#[tokio::test]
async fn selection_applies_per_request_to_both_views_helpers_and_concurrent_sessions() {
    let fixture = Fixture::new(|_| {}).await;
    for path in ["/mcp", "/mcp/fake"] {
        let echo = if path == "/mcp" { "fake_echo" } else { "echo" };
        // Sessions initialized under each selection, listed concurrently.
        let on = fixture
            .initialize_at(path, Some(OutputSchemas::On), TOKEN_A, VERSION)
            .await;
        let off = fixture
            .initialize_at(path, Some(OutputSchemas::Off), TOKEN_A, VERSION)
            .await;
        let omitted = fixture.initialize_at(path, None, TOKEN_A, VERSION).await;
        let (with, without, default) = tokio::join!(
            list(&fixture, path, Some(OutputSchemas::On), &on, 2),
            list(&fixture, path, Some(OutputSchemas::Off), &off, 2),
            list(&fixture, path, None, &omitted, 2),
        );
        assert_eq!(with.len(), 6);
        assert!(with.iter().all(|tool| tool.get("outputSchema").is_some()));
        assert!(
            without
                .iter()
                .all(|tool| tool.get("outputSchema").is_none())
        );
        // The default omits MCP output-schema metadata exactly like off.
        assert_eq!(default, without);
        assert_eq!(
            with.iter().map(without_output_schema).collect::<Vec<_>>(),
            without
        );
        // No session state: each request's own selection applies.
        assert_eq!(list(&fixture, path, None, &on, 3).await, without);
        assert_eq!(
            list(&fixture, path, Some(OutputSchemas::On), &off, 3).await,
            with
        );
        assert_eq!(
            list(&fixture, path, Some(OutputSchemas::Off), &on, 4).await,
            without
        );

        // Helpers and invocations return the same results either way,
        // except action details, which follow the selection.
        let calls = [
            ("services_list", json!({})),
            ("actions_list", json!({"service":"fake","resource":"TEST"})),
            ("resource_access_describe", json!({"service":"fake"})),
            ("services_describe", json!({"service":"fake"})),
            ("actions_list", json!({"service":"fake","unexpected":true})),
            (
                echo,
                json!({"inputs":{"project":"TEST","message":"parity"}}),
            ),
            (
                echo,
                json!({"inputs":{"project":"OTHER","message":"denied"}}),
            ),
            (echo, json!({"inputs":{"project":"TEST"}})),
            (
                echo,
                json!({"inputs":{"project":"TEST","message":"x"},"outputPath":"/tmp/x"}),
            ),
        ];
        for (id, (name, arguments)) in (10..).zip(calls) {
            let mut results = Vec::new();
            for (session, selection) in [
                (&on, Some(OutputSchemas::On)),
                (&off, Some(OutputSchemas::Off)),
                (&omitted, None),
                // The same session in another mode.
                (&on, Some(OutputSchemas::Off)),
            ] {
                let response = fixture
                    .call_at(path, selection, session, id, name, arguments.clone())
                    .await;
                assert!(response.get("error").is_none(), "{response}");
                if name == "services_describe" {
                    // Live limits are observations, not part of the contract.
                    let mut result = comparable(&response);
                    result["structuredContent"]
                        .as_object_mut()
                        .unwrap()
                        .remove("limits");
                    result["content"][0]["text"]
                        .as_object_mut()
                        .unwrap()
                        .remove("limits");
                    results.push(result);
                } else {
                    results.push(comparable(&response));
                }
            }
            for result in &results[1..] {
                assert_eq!(result, &results[0], "{path} {name} {arguments}");
            }
        }
        let outcomes = read_audit_records(&fixture.audit_path)
            .into_iter()
            .filter(|record| record["action"] == "echo")
            .map(|record| record["decision"].as_str().unwrap().to_owned())
            .collect::<Vec<_>>();
        assert!(outcomes.iter().any(|decision| decision == "allow"));
        assert!(outcomes.iter().any(|decision| decision == "deny"));

        let described: Vec<_> = futures_util::future::join_all(
            [
                (&on, Some(OutputSchemas::On)),
                (&off, Some(OutputSchemas::Off)),
                (&omitted, None),
            ]
            .into_iter()
            .map(|(session, selection)| {
                fixture.call_at(
                    path,
                    selection,
                    session,
                    20,
                    "actions_describe",
                    json!({"service":"fake","action":"echo"}),
                )
            }),
        )
        .await;
        let [with_detail, without_detail, default_detail] =
            described.iter().map(structured).collect::<Vec<_>>()[..]
        else {
            unreachable!()
        };
        let listed_echo = by_name(&with).remove(echo).unwrap();
        assert_eq!(
            with_detail["mcpTool"]["outputSchema"],
            listed_echo["outputSchema"]
        );
        assert!(with_detail.get("resultSchemas").is_none());
        for detail in [without_detail, default_detail] {
            assert!(detail["mcpTool"].get("outputSchema").is_none(), "{detail}");
            assert!(detail.get("resultSchemas").is_none(), "{detail}");
            assert_eq!(detail["mcpTool"]["name"], echo);
            assert_eq!(detail["mcpTool"]["inputSchema"], listed_echo["inputSchema"]);
        }
        let mut stripped = with_detail.clone();
        stripped["mcpTool"]
            .as_object_mut()
            .unwrap()
            .remove("outputSchema");
        assert_eq!(&stripped, without_detail);
        assert_eq!(without_detail, default_detail);
    }
}

#[tokio::test]
async fn action_details_follow_the_selection_for_conflicts_overlong_names_and_file_actions() {
    let fixture = Fixture::new(|config| names::configure(config, false)).await;
    let long = "a".repeat(124);
    for path in ["/mcp", "/mcp/fake"] {
        let session = fixture.initialize_at(path, None, TOKEN_A, VERSION).await;
        let aggregate = path == "/mcp";
        for (index, action) in ["echo", "item.read", "file.read", "file_read", &long]
            .into_iter()
            .enumerate()
        {
            let arguments = json!({"service":"fake","action":action});
            let id = 2 + index as u64 * 3;
            let with = fixture
                .call_at(
                    path,
                    Some(OutputSchemas::On),
                    &session,
                    id,
                    "actions_describe",
                    arguments.clone(),
                )
                .await;
            let without = fixture
                .call_at(
                    path,
                    Some(OutputSchemas::Off),
                    &session,
                    id + 1,
                    "actions_describe",
                    arguments.clone(),
                )
                .await;
            let default = fixture
                .call_at(path, None, &session, id + 2, "actions_describe", arguments)
                .await;
            let (with, without) = (structured(&with), structured(&without));
            assert_eq!(structured(&default), without);
            assert!(without.get("resultSchemas").is_none(), "{without}");
            assert!(
                !without.to_string().contains("\"outputSchema\""),
                "{without}"
            );
            let unavailable = match action {
                "file.read" if aggregate => Some("name_conflict"),
                action if aggregate && action == long => Some("name_too_long"),
                _ => None,
            };
            for detail in [with, without] {
                assert_eq!(
                    detail.get("mcpToolUnavailable").and_then(Value::as_str),
                    unavailable,
                    "{path} {action}"
                );
            }
            // A raw download is described but never a tool on HTTP.
            let executable = unavailable.is_none() && action != "file_read";
            if executable {
                assert!(with["mcpTool"]["outputSchema"].is_object(), "{with}");
                assert!(with.get("resultSchemas").is_none(), "{with}");
                assert!(without["mcpTool"].is_object());
            } else {
                assert!(with.get("mcpTool").is_none(), "{with}");
                assert!(without.get("mcpTool").is_none());
                // On keeps the payload schemas of an action without a tool.
                assert!(with["resultSchemas"]["success"].is_object(), "{with}");
            }
            let mut stripped = with.clone();
            let object = stripped.as_object_mut().unwrap();
            object.remove("resultSchemas");
            if let Some(tool) = object.get_mut("mcpTool") {
                tool.as_object_mut().unwrap().remove("outputSchema");
            }
            assert_eq!(&stripped, without, "{path} {action}");
        }
    }
}

/// A backend selected as `fake`: the fake service with typed echo-shaped
/// actions whose descriptions force byte-bounded pagination in both
/// selections.
#[derive(Clone, Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PagedBackend {}

static PAGED_BACKEND: agent_access_provider::BackendRegistration =
    agent_access_provider::BackendRegistration::new(
        agent_access_fake::FAKE_BACKEND.module(),
        "fake",
        agent_access_provider::parse_backend_config::<PagedBackend>,
    )
    .with_resource_types(agent_access_fake::FAKE_BACKEND.resource_types())
    .development_only();

impl agent_access_provider::BackendConfig for PagedBackend {
    fn kind(&self) -> &'static str {
        "fake"
    }

    fn validate(
        &self,
        _context: &agent_access_provider::ValidationContext<'_>,
        _errors: &mut Vec<String>,
    ) {
    }

    fn descriptor(&self) -> ServiceDescriptor {
        let mut descriptor = agent_access_fake::fake_descriptor();
        let echo = descriptor.actions[0].clone();
        for name in ["page.one", "page.two", "page.three"] {
            let mut action = echo.clone();
            action.action = name.into();
            action.description = format!("{name} {}", "x".repeat(30_000));
            descriptor.actions.push(action);
        }
        descriptor
    }

    fn egress_proxies(&self) -> Vec<(String, &agent_access_provider::EgressProxyConfig)> {
        Vec::new()
    }

    fn build(
        &self,
        _host: &agent_access_provider::BuildContext<'_>,
    ) -> Result<Arc<dyn Provider>, agent_access_provider::ProviderBuildError> {
        Ok(Arc::new(self.clone()))
    }
}

#[async_trait::async_trait]
impl Provider for PagedBackend {
    async fn resolve_scopes(
        &self,
        request: ScopeRequest<'_>,
    ) -> Result<ScopeResolution, ProviderError> {
        agent_access_fake::FakeProvider
            .echo_scopes("echo", request.inputs())
            .map(ScopeResolution::resources)
    }
    async fn invoke(&self, _request: ProviderInvocation) -> Result<ProviderResult, ProviderError> {
        panic!("catalog-only provider must not be invoked")
    }
}

#[tokio::test]
async fn pagination_completes_in_each_selection_and_cursors_never_cross_modes() {
    let fixture = Fixture::new(|config| {
        use agent_access_provider::BackendConfig;
        let backend = PagedBackend {};
        config.mcp.max_response_bytes = 64 * 1024;
        config.policy.grants[0].actions = backend
            .descriptor()
            .actions
            .into_iter()
            .map(|action| action.action)
            .collect();
        config.providers = agent_access_core::ProvidersConfig::new(Arc::new(
            crate::test_composition::backend_registry_replacing(&PAGED_BACKEND),
        ))
        .with(backend);
    })
    .await;
    for path in ["/mcp", "/mcp/fake"] {
        let session = fixture.initialize_at(path, None, TOKEN_A, VERSION).await;
        let mut pages = BTreeMap::new();
        let mut first_cursor = BTreeMap::new();
        for (base, selection) in (100..).step_by(10).zip(SELECTIONS) {
            let mut tools = Vec::new();
            let mut cursor: Option<String> = None;
            for id in base.. {
                let params = match &cursor {
                    Some(cursor) => json!({"cursor":cursor}),
                    None => json!({}),
                };
                let page = fixture
                    .rpc_at(path, selection, &session, id, "tools/list", params)
                    .await;
                tools.extend(page["result"]["tools"].as_array().unwrap().iter().cloned());
                cursor = page["result"]["nextCursor"].as_str().map(str::to_owned);
                if id == base {
                    first_cursor.insert(selection, cursor.clone().expect("paginated listing"));
                }
                if cursor.is_none() {
                    break;
                }
                assert!(id < base + 9, "unbounded pagination");
            }
            assert_eq!(tools.len(), 9, "{path} {selection:?}");
            pages.insert(selection, by_name(&tools));
        }
        let with = &pages[&Some(OutputSchemas::On)];
        let without = &pages[&Some(OutputSchemas::Off)];
        assert_eq!(&pages[&None], without);
        assert_eq!(
            with.keys().collect::<Vec<_>>(),
            without.keys().collect::<Vec<_>>()
        );
        for (name, tool) in with {
            assert!(tool.get("outputSchema").is_some(), "{name}");
            assert_eq!(&without_output_schema(tool), &without[name]);
        }
        let invalid = "Invalid or stale catalog cursor; restart tools/list";
        for (id, (issued, used)) in (200..).zip([
            (Some(OutputSchemas::On), Some(OutputSchemas::Off)),
            (Some(OutputSchemas::On), None),
            (Some(OutputSchemas::Off), Some(OutputSchemas::On)),
            (None, Some(OutputSchemas::On)),
        ]) {
            let rejected = fixture
                .rpc_at(
                    path,
                    used,
                    &session,
                    id,
                    "tools/list",
                    json!({"cursor":first_cursor[&issued]}),
                )
                .await;
            assert_eq!(rejected["error"]["code"], -32602, "{rejected}");
            assert_eq!(rejected["error"]["message"], invalid);
        }
        // Omitted and explicit off are one projection, so their cursors agree.
        for (id, (issued, used)) in (210..).zip([
            (None, Some(OutputSchemas::Off)),
            (Some(OutputSchemas::Off), None),
        ]) {
            let accepted = fixture
                .rpc_at(
                    path,
                    used,
                    &session,
                    id,
                    "tools/list",
                    json!({"cursor":first_cursor[&issued]}),
                )
                .await;
            assert!(accepted["result"]["tools"].is_array(), "{accepted}");
        }
    }
    // The other view's cursor is refused in every selection too.
    let aggregate = fixture.initialize_at("/mcp", None, TOKEN_A, VERSION).await;
    let first = fixture
        .rpc_at(
            "/mcp",
            Some(OutputSchemas::On),
            &aggregate,
            300,
            "tools/list",
            json!({}),
        )
        .await;
    let scoped = fixture
        .initialize_at("/mcp/fake", None, TOKEN_A, VERSION)
        .await;
    let rejected = fixture
        .rpc_at(
            "/mcp/fake",
            Some(OutputSchemas::On),
            &scoped,
            301,
            "tools/list",
            json!({"cursor":first["result"]["nextCursor"]}),
        )
        .await;
    assert_eq!(rejected["error"]["code"], -32602);
}
