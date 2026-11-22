//! Transport-local TOML defaults never become session state.
use super::*;

#[tokio::test]
async fn http_defaults_and_explicit_overrides_apply_in_both_views() {
    for default_schemas in [OutputSchemas::Off, OutputSchemas::On] {
        for default_copy in [false, true] {
            let fixture = Fixture::new(|config| {
                config.mcp.output_schemas = default_schemas;
                config.mcp.include_text_copy = default_copy;
            })
            .await;
            let spec = fixture
                .send(at_uri(
                    "/v1/spec/openapi.json",
                    request(Method::GET, Some(TOKEN_A), None, None),
                ))
                .await;
            assert_eq!(spec.status(), StatusCode::OK);
            let spec = response_json(spec).await;
            for path in ["/mcp", "/mcp/{service}"] {
                let parameters = spec["paths"][path]["parameters"].as_array().unwrap();
                for (name, expected) in [
                    ("outputSchemas", json!(default_schemas)),
                    ("includeTextCopy", json!(default_copy)),
                ] {
                    assert_eq!(
                        parameters.iter().find(|p| p["name"] == name).unwrap()["schema"]["default"],
                        expected
                    );
                }
            }
            for (base, name) in [("/mcp", "fake_echo"), ("/mcp/fake", "echo")] {
                let session = scoped::initialize(&fixture, base, TOKEN_A).await;
                for schemas in [None, Some(OutputSchemas::Off), Some(OutputSchemas::On)] {
                    for copy in [None, Some(false), Some(true)] {
                        let mut fields = Vec::new();
                        if let Some(schemas) = schemas {
                            fields.push(format!("outputSchemas={}", schemas.as_str()));
                        }
                        if let Some(copy) = copy {
                            fields.push(format!("includeTextCopy={copy}"));
                        }
                        let uri = if fields.is_empty() {
                            base.to_string()
                        } else {
                            format!("{base}?{}", fields.join("&"))
                        };
                        let expected_schemas = schemas.unwrap_or(default_schemas);
                        let expected_copy = copy.unwrap_or(default_copy);
                        let listed = content_formats::rpc(
                            &fixture,
                            &uri,
                            &session,
                            1,
                            "tools/list",
                            json!({}),
                        )
                        .await;
                        let tools = listed["result"]["tools"].as_array().unwrap();
                        let tool = tools.iter().find(|tool| tool["name"] == name).unwrap();
                        assert_eq!(
                            tool.get("outputSchema").is_some(),
                            expected_schemas == OutputSchemas::On
                        );
                        for inputs in [json!({"project":"TEST","message":"defaults"}), json!({})] {
                            let result = content_formats::rpc(
                                &fixture,
                                &uri,
                                &session,
                                2,
                                "tools/call",
                                json!({"name":name,"arguments":{"inputs":inputs}}),
                            )
                            .await;
                            assert!(
                                result["result"]["structuredContent"].is_object(),
                                "{result}"
                            );
                            assert_eq!(
                                result["result"]["content"].as_array().unwrap().is_empty(),
                                !expected_copy
                            );
                        }
                        let detail = content_formats::rpc(&fixture, &uri, &session, 3, "tools/call", json!({"name":"actions_describe","arguments":{"service":"fake","action":"echo"}})).await;
                        assert_eq!(
                            detail["result"]["content"].as_array().unwrap().is_empty(),
                            !expected_copy
                        );
                    }
                }
            }
        }
    }
}

#[tokio::test]
async fn http_reload_updates_defaults_on_existing_sessions_and_preserves_admitted_copy() {
    let provider = ControlledProvider::new(true);
    let fixture = controlled_fixture_with(provider.clone(), |config| {
        config.mcp.output_schemas = OutputSchemas::On;
        config.mcp.include_text_copy = false;
    })
    .await;
    let session = fixture.initialize().await;
    let response = start_controlled_call(&fixture, &session, 80).await;
    provider.wait_entered().await;
    publish_reload(&fixture, |config| {
        config.mcp.output_schemas = OutputSchemas::Off;
        config.mcp.include_text_copy = true;
    })
    .await;
    provider.release.add_permits(1);
    let result = rpc_body(response).await;
    assert!(result.get("error").is_none(), "{result}");
    assert_eq!(result["result"]["structuredContent"]["decision"], "allow");
    assert_eq!(result["result"]["content"], json!([]));
    let listed = fixture
        .rpc_at("/mcp", None, &session, 81, "tools/list", json!({}))
        .await;
    assert!(
        listed["result"]["tools"]
            .as_array()
            .unwrap()
            .iter()
            .all(|tool| tool.get("outputSchema").is_none())
    );
    let helper = fixture
        .rpc_at(
            "/mcp",
            None,
            &session,
            82,
            "tools/call",
            json!({"name":"services_list","arguments":{}}),
        )
        .await;
    assert_eq!(helper["result"]["content"].as_array().unwrap().len(), 1);
    assert_eq!(provider.executions.load(Ordering::SeqCst), 1);
}
