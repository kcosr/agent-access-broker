use super::*;
use agent_access_provider::test_support::check_strict_conformance;

fn action(io: Value, result_schemas: Option<Value>) -> ApiActionSpec {
    let mut spec = json!({
        "action": "issue.view", "scopedMcpName": "issue.view", "description": "View an issue",
        "readOnly": true, "requiredScopeTypes": [], "credentialModes": ["service"],
        "inputSchema": {"type": "object"}, "io": io,
        "responseKind": "response_envelope", "exitPolicy": "invoke_decision",
        "readContentFormats": ["native", "markdown", "text"], "responseFormats": ["json", "markdown"],
        "renderedBodyOwners": ["/result", "/result/comments/*", "/result/parent"],
        "optionalRenderedBodyOwnerPrefixes": ["/result/parent"]
    });
    if let Some(schemas) = result_schemas {
        spec["resultSchemas"] = schemas;
    }
    serde_json::from_value(spec).unwrap()
}

fn schemas() -> Value {
    json!({
        "success": {"type": "object", "properties": {
            "key": {"type": "string"},
            "body": {"type": "object"},
            "comments": {"type": "array", "items": {"type": "object", "properties": {"id": {"type": "string"}, "body": {}}}},
            "parent": {"type": ["object", "null"], "properties": {"key": {"type": "string"}}}
        }, "required": ["key"]},
        "error": {"type": "object", "properties": {
            "conflict": {"type": "boolean"},
            "comments": {"type": "array", "items": {"type": "object", "properties": {"id": {"type": "string"}}}}
        }}
    })
}

fn json_action() -> ApiActionSpec {
    action(json!({"type": "json"}), Some(schemas()))
}

fn download_action() -> ApiActionSpec {
    let mut action = action(
        json!({"type": "raw_download", "metadataHeader": "X-Metadata", "metadataEncoding": "base64_json"}),
        Some(json!({"success": {"type": "object", "properties": {
            "filename": {"type": "string"}, "size": {"type": "integer"}
        }, "required": ["filename", "size"]}})),
    );
    action.read_content_formats.clear();
    action.response_formats.clear();
    action.rendered_body_owners.clear();
    action.optional_rendered_body_owner_prefixes.clear();
    action
}

fn valid(schema: &Value, value: &Value) -> bool {
    jsonschema::validator_for(schema).unwrap().is_valid(value)
}

fn assert_no_refs(value: &Value) {
    let text = serde_json::to_string(value).unwrap();
    assert!(!text.contains("$ref"), "{text}");
    assert!(!text.contains("\"oneOf\""), "{text}");
    assert!(!text.contains("\"allOf\""), "{text}");
}

#[test]
fn actions_without_result_schemas_publish_no_output_schema() {
    let action = action(json!({"type": "json"}), None);
    assert!(result_payload_schema(&action).is_none());
    for mode in [ProjectionMode::Http, ProjectionMode::Stdio] {
        assert!(action_output_schema(&action, mode).is_none());
    }
    // A download has no HTTP MCP tool at all.
    assert!(action_output_schema(&download_action(), ProjectionMode::Http).is_none());
    assert!(action_output_schema(&download_action(), ProjectionMode::Stdio).is_some());
}

#[test]
fn the_payload_union_injects_rendered_bodies_markdown_and_shared_failures() {
    let payload = result_payload_schema(&json_action()).unwrap();
    assert_no_refs(&payload);
    assert_eq!(payload["type"], "object");
    let branches = payload["anyOf"].as_array().unwrap();
    assert_eq!(branches.len(), 4);
    let success = &branches[0];
    for owner in [
        &success["properties"],
        &success["properties"]["comments"]["items"]["properties"],
        &success["properties"]["parent"]["properties"],
    ] {
        assert_eq!(
            owner["renderedBody"]["required"],
            json!(["format", "value"])
        );
    }
    assert_eq!(branches[1], markdown_result_schema());
    // The error schema gains rendered bodies where its owners resolve, and
    // every shared failure property it does not declare.
    let error = &branches[2];
    assert!(error["properties"]["renderedBody"].is_object());
    assert!(error["properties"]["comments"]["items"]["properties"]["renderedBody"].is_object());
    assert!(error["properties"].get("parent").is_none());
    assert_eq!(error["properties"]["conflict"], json!({"type": "boolean"}));
    assert_eq!(error["properties"]["mutationStatus"]["type"], "string");
    assert_eq!(branches[3], shared_failure_result_schema());

    for (value, accepted) in [
        (
            json!({"key": "ABC-1", "renderedBody": {"format": "markdown", "value": "x"}}),
            true,
        ),
        (
            json!({"key": "ABC-1", "comments": [{"id": "1", "renderedBody": {"format": "text", "value": "y"}}], "parent": null}),
            true,
        ),
        (json!({"format": "markdown", "value": "# ABC-1\n"}), true),
        (
            json!({"conflict": true, "mutationStatus": "unknown", "retrySafe": false}),
            true,
        ),
        (
            json!({"executionState": "not_dispatched", "retrySafe": true, "deadlineKind": "operation"}),
            true,
        ),
        (
            json!({"limitScope": "upstream", "service": "jira", "retryAfterSeconds": 3,
                "retryAt": "2026-11-09T00:00:00Z"}),
            true,
        ),
        (
            json!({"executionState": "completed", "retrySafe": false, "mutationStatus": "applied_unverified"}),
            true,
        ),
        // Broker admission refusals are delivered without these details.
        (
            json!({"limitScope": "principal", "limit": 5, "windowSeconds": 60}),
            false,
        ),
        (
            json!({"executionState": "not_dispatched", "deadlineKind": "rate_wait"}),
            false,
        ),
        (
            json!({"hints": {"upstreamResourceOwnership": "acting_user"}}),
            true,
        ),
        (json!({"key": "ABC-1", "unexpected": 1}), false),
        (
            json!({"key": "ABC-1", "renderedBody": {"format": "native", "value": "x"}}),
            false,
        ),
        (json!({"conflict": true, "undeclared": 1}), false),
    ] {
        assert_eq!(
            check_strict_conformance(&payload, &value).is_ok(),
            accepted,
            "{value}"
        );
        // Advertised schemas stay open: every strict pass is an open pass.
        if accepted {
            assert!(valid(&payload, &value));
        }
    }
    // The shared failure branch is open as advertised.
    assert!(valid(&payload, &json!({"futureSharedField": true})));
    let mut json_only = json_action();
    json_only.response_formats.clear();
    let payload = result_payload_schema(&json_only).unwrap();
    assert!(
        !payload["anyOf"]
            .as_array()
            .unwrap()
            .contains(&markdown_result_schema())
    );
}

fn envelope(result: Option<Value>, decision: &str) -> Value {
    let mut value = json!({
        "agentRequestId": "agent-1", "brokerRequestId": "broker-1", "decision": decision,
        "service": "jira", "action": "issue.view", "resourceScopes": {"project": ["ABC"]}
    });
    if let Some(result) = result {
        value["result"] = result;
    }
    if decision != "allow" {
        value["reasonCode"] = json!("upstream_failed");
        value["reason"] = json!("failed");
        value["error"] = json!({"message": "failed"});
    }
    value
}

#[test]
fn http_mcp_output_schemas_accept_every_delivery_shape() {
    let schema = action_output_schema(&json_action(), ProjectionMode::Http).unwrap();
    assert_no_refs(&schema);
    assert_eq!(schema["type"], "object");
    assert_eq!(schema["anyOf"].as_array().unwrap().len(), 2);
    for value in [
        envelope(Some(json!({"key": "ABC-1"})), "allow"),
        envelope(None, "deny"),
        envelope(
            Some(json!({"mutationStatus": "unknown", "retrySafe": false})),
            "error",
        ),
        json!({"agentRequestId": "a", "brokerRequestId": "b", "decision": "deny", "service": "broker",
            "action": "request.admit", "resourceScopes": {}, "reasonCode": "rate_limited", "reason": "x",
            "error": {"message": "x"}}),
        json!({"error": {"code": "mcp_tool_error", "message": "unsupported argument"}}),
        json!({"error": {"message": "Broker admission failed"}, "status": 503}),
        json!({
            "error": {"code": "mcp_response_too_large", "message": "x"},
            "agentRequestId": "a", "brokerRequestId": "b", "service": "jira", "action": "issue.view",
            "brokerOutcome": {"status": 200, "decision": "allow", "reasonCode": null, "mutationStatus": "applied"},
            "execution": {"dispatched": true, "completion": "completed"},
            "resultAvailable": false, "retrySafe": false
        }),
    ] {
        assert!(valid(&schema, &value), "{value}");
    }
    for value in [
        json!({}),
        // The open shared failure branch accepts any object whose shared
        // fields are well typed; only a value no branch accepts fails.
        envelope(Some(json!({"key": 1, "retrySafe": "yes"})), "allow"),
        json!({"agentRequestId": "a", "decision": "allow"}),
        json!({"error": {"code": "mcp_tool_error"}}),
    ] {
        assert!(!valid(&schema, &value), "{value}");
    }
}

fn receipt(extra: Value) -> Value {
    let mut value = json!({
        "agentRequestId": "agent-1", "brokerRequestId": "broker-1", "decision": "allow",
        "service": "jira", "action": "issue.view", "operationStatus": "succeeded"
    });
    value
        .as_object_mut()
        .unwrap()
        .extend(extra.as_object().unwrap().clone());
    value
}

#[test]
fn stdio_output_schemas_accept_envelopes_receipts_and_local_failures() {
    let schema = action_output_schema(&json_action(), ProjectionMode::Stdio).unwrap();
    assert_no_refs(&schema);
    let saved = json!({"status": "succeeded", "path": "/tmp/out.json", "size": 10, "sha256": "ab",
        "contentType": "application/json", "sensitive": false});
    let failed = json!({"status": "failed", "path": "/tmp/out.json", "destinationReplaced": false, "error": "denied"});
    for value in [
        envelope(Some(json!({"key": "ABC-1"})), "allow"),
        envelope(None, "deny"),
        receipt(json!({"output": saved})),
        receipt(
            json!({"operationStatus": "applied_unverified", "mutationStatus": "applied_unverified",
            "retrySafe": false, "verificationStage": "readback", "safeLocators": {"id": 7}, "output": saved}),
        ),
        receipt(
            json!({"message": "Operation succeeded; writing the response output failed.", "output": failed}),
        ),
        receipt(json!({"message": "x", "metadataOutput": failed})),
    ] {
        assert!(valid(&schema, &value), "{value}");
    }
    assert!(!valid(
        &schema,
        &receipt(json!({"output": {"status": "unknown", "path": "/x"}}))
    ));

    let download = action_output_schema(&download_action(), ProjectionMode::Stdio).unwrap();
    assert_no_refs(&download);
    let branches = download["anyOf"].as_array().unwrap();
    assert!(branches[0]["properties"]["result"].is_object());
    for value in [
        receipt(
            json!({"resourceScopes": {}, "result": {"filename": "a.txt", "size": 3}, "output": saved}),
        ),
        receipt(json!({"message": "x", "output": failed})),
        envelope(Some(json!({"filename": "a.txt", "size": 3})), "allow"),
        envelope(None, "deny"),
    ] {
        assert!(valid(&download, &value), "{value}");
    }
    assert!(!valid(
        &download,
        &receipt(json!({"result": {"filename": 3, "retrySafe": "no"}, "output": saved}))
    ));
}

#[test]
fn helper_output_schemas_describe_results_receipts_and_failures() {
    let availability =
        json!({"state": "available", "requirements": [], "message": "Locally available"});
    let action = json!({"action": "issue.view", "readOnly": true, "description": "View",
        "requiredScopeTypes": ["project"], "credentialModes": ["service"], "lookupRequired": false,
        "inputSchema": {"type": "object"}, "documentation": {"examples": []}});
    let mut detail = action.clone();
    detail.as_object_mut().unwrap().extend(
        json!({"service": "jira", "io": {"type": "json"}, "responseKind": "response_envelope",
            "exitPolicy": "invoke_decision", "sensitiveInputPointers": [], "readContentFormats": ["native"],
            "resultSchemas": {"success": {"type": "object"}},
            "mcpTool": {"name": "jira_issue_view", "inputSchema": {"type": "object"}, "outputSchema": {"type": "object"}}})
        .as_object()
        .unwrap()
        .clone(),
    );
    let results = [
        (
            HelperKind::ServicesList,
            json!({"services": [{"service": "jira", "displayName": "Jira",
            "surface": "invoke", "actions": ["issue.view"], "availability": availability}]}),
        ),
        (
            HelperKind::ResourceAccessDescribe,
            json!({"service": "jira", "executionContext": "default",
            "availability": availability, "coverageSemantics": "single_target",
            "access": [{"scope": "resource", "action": "issue.view", "resourceType": "jira_project",
                "enforcement": "request", "coverage": [{"selector": {"kind": "exact", "value": "ABC"},
                "inputs": {"project": "ABC"}, "restricted": false}, {"selector": {"kind": "all"}, "restricted": true}]},
                {"scope": "unscoped", "action": "field.list"}],
            "registeredResources": {"source": "broker_configuration", "items": [{"id": "abc", "type": "jira_project",
                "value": "ABC", "displayName": "ABC", "inputs": {"project": "ABC"}}], "nextCursor": null},
            "liveListings": [{"service": "jira", "action": "project.list", "resourceType": "jira_project"}]}),
        ),
        (
            HelperKind::ActionsList,
            json!({"service": "jira", "resource": "ABC", "actions": ["issue.view"]}),
        ),
        (HelperKind::ActionsDescribe, detail),
        (
            HelperKind::ServicesDescribe,
            json!({"service": "jira", "displayName": "Jira", "surface": "invoke",
            "credentialVerificationSupported": true, "scopeTypes": ["project"],
            "resourceScopes": {"project": {"resourceType": "jira_project", "selectors": ["exact"]}},
            "actions": [action], "availability": availability, "scopedMcpReady": true,
            "limits": {"scope": "principal_service"}}),
        ),
    ];
    for (helper, value) in results {
        check_strict_conformance(&helper_result_schema(helper), &value)
            .unwrap_or_else(|problem| panic!("{helper:?}: {problem}"));
        for mode in [ProjectionMode::Http, ProjectionMode::Stdio] {
            let schema = helper_output_schema(helper, mode);
            assert_no_refs(&schema);
            assert!(valid(&schema, &value), "{helper:?} {mode:?}");
            assert!(!valid(&schema, &json!({})), "{helper:?} {mode:?}");
        }
        let http = helper_output_schema(helper, ProjectionMode::Http);
        assert!(valid(
            &http,
            &json!({"error": {"code": "mcp_tool_error", "message": "Service is required"}})
        ));
        let stdio = helper_output_schema(helper, ProjectionMode::Stdio);
        assert!(valid(
            &stdio,
            &json!({"operationStatus": "succeeded", "service": "jira",
            "output": {"status": "succeeded", "path": "/tmp/a.json", "size": 1, "sha256": "x",
                "contentType": "application/json", "sensitive": false}})
        ));
        assert!(valid(
            &stdio,
            &json!({"agentRequestId": "a", "brokerRequestId": "b", "decision": "deny",
            "service": "jira", "action": "", "resourceScopes": {}, "reasonCode": "service_action_denied",
            "reason": "service is not visible for this identity", "error": {"message": "x"}})
        ));
    }
}

#[test]
fn composed_schemas_are_compact_and_reported() {
    for (name, action) in [("json", json_action()), ("download", download_action())] {
        for mode in [ProjectionMode::Http, ProjectionMode::Stdio] {
            let Some(schema) = action_output_schema(&action, mode) else {
                continue;
            };
            let bytes = serde_json::to_vec(&schema).unwrap().len();
            println!("composed outputSchema {name} {mode:?}: {bytes} bytes");
            assert!(bytes <= MAX_OUTPUT_SCHEMA_BYTES, "{name} {mode:?}: {bytes}");
        }
    }
    for mode in [ProjectionMode::Http, ProjectionMode::Stdio] {
        for helper in [
            HelperKind::ServicesList,
            HelperKind::ResourceAccessDescribe,
            HelperKind::ActionsList,
            HelperKind::ActionsDescribe,
            HelperKind::ServicesDescribe,
        ] {
            let bytes = serde_json::to_vec(&helper_output_schema(helper, mode))
                .unwrap()
                .len();
            println!("helper outputSchema {helper:?} {mode:?}: {bytes} bytes");
            assert!(bytes <= MAX_OUTPUT_SCHEMA_BYTES);
        }
    }
}

#[test]
fn catalog_tools_details_and_openapi_share_one_composition() {
    use crate::mcp::{McpView, STDIO_MAX_CATALOG_BYTES, ToolRegistry, is_helper};
    let descriptor = agent_access_fake::fake_descriptor();
    let declared = descriptor.actions[0].result_schemas.clone().unwrap();
    let service = crate::api_service_spec(&descriptor, true).unwrap();
    let action = &service.actions[0];
    // The catalog carries the provider payload schemas as declared, and the
    // field round-trips; the version is unchanged.
    let value = serde_json::to_value(action).unwrap();
    assert_eq!(&value["resultSchemas"]["success"], declared.success());
    assert!(value["resultSchemas"].get("error").is_none());
    assert_eq!(
        &serde_json::from_value::<ApiActionSpec>(value).unwrap(),
        action
    );
    assert_eq!(crate::API_CATALOG_VERSION, "agent-access.catalog.v2");
    let mut undeclared = descriptor.clone();
    undeclared.actions[0].result_schemas = None;
    let plain = crate::api_service_spec(&undeclared, true).unwrap();
    assert!(
        serde_json::to_value(&plain.actions[0])
            .unwrap()
            .get("resultSchemas")
            .is_none()
    );
    // Service capabilities never carry them.
    assert!(
        serde_json::to_value(descriptor.capabilities())
            .unwrap()
            .to_string()
            .find("resultSchemas")
            .is_none()
    );

    let mut catalog = crate::empty_catalog(json!({}));
    catalog.services.push(service.clone());
    for mode in [ProjectionMode::Http, ProjectionMode::Stdio] {
        for view in [McpView::Aggregate, McpView::Service("fake".into())] {
            let registry =
                ToolRegistry::build(&catalog, &view, mode, STDIO_MAX_CATALOG_BYTES).unwrap();
            let definitions = registry.definitions();
            let tool = definitions
                .iter()
                .find(|tool| tool["_meta"]["agent-access/action"] == "echo")
                .unwrap();
            assert_eq!(
                tool["outputSchema"],
                action_output_schema(action, mode).unwrap()
            );
            assert_eq!(
                registry.action_detail("fake", "echo").unwrap()["outputSchema"],
                tool["outputSchema"]
            );
            // rmcp populates Tool.output_schema from the registry JSON, which
            // both transports deserialize.
            let parsed: rmcp::model::Tool = serde_json::from_value(tool.clone()).unwrap();
            assert_eq!(
                Value::Object((*parsed.output_schema.unwrap()).clone()),
                tool["outputSchema"]
            );
            for helper in definitions
                .iter()
                .filter(|tool| is_helper(tool["name"].as_str().unwrap()))
            {
                let kind = HelperKind::from_name(helper["name"].as_str().unwrap()).unwrap();
                assert_eq!(helper["outputSchema"], helper_output_schema(kind, mode));
                let parsed: rmcp::model::Tool = serde_json::from_value(helper.clone()).unwrap();
                assert!(parsed.output_schema.is_some());
            }
        }
    }
    // Without schemas, tools and details keep today's shape.
    let mut plain_catalog = crate::empty_catalog(json!({}));
    plain_catalog.services.push(plain);
    let registry = ToolRegistry::build(
        &plain_catalog,
        &McpView::Aggregate,
        ProjectionMode::Http,
        STDIO_MAX_CATALOG_BYTES,
    )
    .unwrap();
    assert!(registry.definitions()[5].get("outputSchema").is_none());
    assert!(
        registry
            .action_detail("fake", "echo")
            .unwrap()
            .get("outputSchema")
            .is_none()
    );

    // OpenAPI types the JSON envelope's result for success and errors.
    let openapi =
        crate::openapi_from_catalog(&catalog, crate::RenderAuthMode::Omit, &[], "session");
    let responses = &openapi["paths"]["/v1/invoke/fake/echo"]["post"]["responses"];
    let envelope = envelope_schema(result_payload_schema(action).unwrap());
    assert_eq!(
        responses["200"]["content"]["application/json"]["schema"],
        envelope
    );
    assert_eq!(
        responses["default"]["content"]["application/json"]["schema"],
        envelope
    );
    let plain_openapi =
        crate::openapi_from_catalog(&plain_catalog, crate::RenderAuthMode::Omit, &[], "session");
    let plain_responses = &plain_openapi["paths"]["/v1/invoke/fake/echo"]["post"]["responses"];
    assert!(plain_responses.get("default").is_none());
    assert!(
        plain_responses["200"]["content"]["application/json"]["schema"]["properties"].is_null()
    );

    // A raw download describes its metadata header's decoded envelope.
    let mut downloads = crate::empty_catalog(json!({}));
    let mut download_service = service;
    download_service.actions = vec![download_action()];
    downloads.services.push(download_service);
    let openapi =
        crate::openapi_from_catalog(&downloads, crate::RenderAuthMode::Omit, &[], "session");
    let responses = &openapi["paths"]["/v1/invoke/fake/issue.view"]["post"]["responses"];
    let header = &responses["200"]["headers"][agent_access_provider::RESULT_METADATA_HEADER];
    let envelope = envelope_schema(result_payload_schema(&download_action()).unwrap());
    assert_eq!(header["schema"]["contentMediaType"], "application/json");
    assert_eq!(header["schema"]["contentSchema"], envelope);
    assert_eq!(
        responses["4XX"]["content"]["application/json"]["schema"],
        envelope
    );
    assert!(
        responses["200"]["content"]
            .get("application/octet-stream")
            .is_some()
    );
}
