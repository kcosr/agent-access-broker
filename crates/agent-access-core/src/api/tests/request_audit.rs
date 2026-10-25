use super::*;
use agent_access_provider::{
    AuditInputProjection, AuditInputRule, AuditOverflow, AuditValueKind, RequestAudit,
    host::prepare_audit_inputs,
};

fn audit_identifier(key: &str, pointer: &str) -> AuditInputRule {
    AuditInputRule::value(key, key, pointer)
        .kind(AuditValueKind::Identifier)
        .max_bytes(128)
        .overflow(AuditOverflow::Omit)
}

fn projected_request_audit() -> Value {
    let schema = json!({"properties":{
        "id":{}, "values":{},
        "records":{"items":{"properties":{
            "id":{}, "flags":{}, "secret":{"x-agent-access-sensitive":true}
        }}}
    }});
    let declaration = AuditInputProjection::new([
        audit_identifier("id", "/id"),
        AuditInputRule::values("values", "Values", "/values").kind(AuditValueKind::Number),
        AuditInputRule::records(
            "records",
            "Records",
            "/records",
            [
                audit_identifier("recordId", "/id"),
                AuditInputRule::values("flags", "Flags", "/flags").kind(AuditValueKind::Boolean),
                AuditInputRule::presence("secretPresent", "Secret supplied", "/secret"),
            ],
        ),
    ]);
    let plan = prepare_audit_inputs(&schema, &declaration).unwrap();
    let mut numbers = (0..23).map(|value| json!(value)).collect::<Vec<_>>();
    numbers[0] = json!(i64::MIN);
    numbers[1] = Value::Null;
    numbers[2] = json!({"private":"invalid-list-canary"});
    serde_json::to_value(plan.project(&json!({
        "id":u64::MAX,
        "values":numbers,
        "records":[
            {"id":u64::MAX,"flags":[true,false],"secret":"secret-canary","extra":"unknown-canary"},
            null,
            {"id":"third","flags":[false]}
        ]
    })).unwrap()).unwrap()
}

#[test]
fn request_audit_response_schemas_accept_sdk_decimal_lists_and_record_cells() {
    let snapshot = projected_request_audit();
    assert_eq!(snapshot["status"], "partial");
    assert_eq!(snapshot["fields"][0]["encoding"], "decimalInteger");
    assert_eq!(snapshot["fields"][0]["value"], u64::MAX.to_string());
    let values = &snapshot["fields"][1];
    assert_eq!(values["totalCount"], 23);
    assert_eq!(values["limitedCount"], 3);
    assert_eq!(values["items"].as_array().unwrap().len(), 20);
    assert_eq!(values["items"][0]["value"], i64::MIN.to_string());
    assert_eq!(values["items"][0]["encoding"], "decimalInteger");
    assert_eq!(values["items"][1]["state"], "null");
    assert_eq!(values["items"][2]["state"], "invalid");
    let records = &snapshot["fields"][2];
    assert_eq!(records["columns"].as_array().unwrap().len(), 3);
    assert_eq!(
        records["rows"][0]["cells"]["recordId"]["encoding"],
        "decimalInteger"
    );
    assert_eq!(
        records["rows"][0]["cells"]["flags"]["items"][1]["value"],
        false
    );
    assert_eq!(records["rows"][0]["cells"]["secretPresent"]["value"], true);
    assert_eq!(records["rows"][1]["state"], "invalid");
    assert_eq!(records["rows"][2]["index"], 2);
    assert!(!snapshot.to_string().contains("canary"));
    assert_request_audit_response_schemas(&snapshot);

    let complete = prepare_audit_inputs(
        &json!({"properties":{"flag":{}}}),
        &AuditInputProjection::new([
            AuditInputRule::value("flag", "Flag", "/flag").kind(AuditValueKind::Boolean)
        ]),
    )
    .unwrap()
    .project(&json!({"flag":false}))
    .unwrap();
    let complete = serde_json::to_value(complete).unwrap();
    assert_eq!(complete["status"], "complete");
    assert_request_audit_response_schemas(&complete);
}

fn assert_request_audit_response_schemas(snapshot: &Value) {
    let mut catalog = empty_catalog(json!({}));
    catalog.routes = http_route_specs(&crate::tests::test_resource_types())
        .into_iter()
        .filter(|route| {
            route.required_feature == Some(RouteFeature::AuditQuery)
                && !route.route.ends_with("/options")
        })
        .collect();
    assert_eq!(catalog.routes.len(), 4);
    let openapi = openapi_from_catalog(&catalog, RenderAuthMode::Omit, &[], "session");
    for route in &catalog.routes {
        let catalog_schema = &route.result_schema.as_ref().unwrap()["properties"]["items"]["items"]
            ["properties"]["requestAudit"];
        let openapi_schema = &openapi["paths"][&route.route]["get"]["responses"]["200"]["content"]
            ["application/json"]["schema"]["properties"]["result"]["properties"]["items"]["items"]
            ["properties"]["requestAudit"];
        assert_eq!(catalog_schema, openapi_schema);
        let validator = jsonschema::validator_for(catalog_schema).unwrap();
        let errors = validator
            .iter_errors(snapshot)
            .map(|error| error.to_string())
            .collect::<Vec<_>>();
        assert!(errors.is_empty(), "{}: {errors:?}", route.route);
    }
}

#[test]
fn request_audit_response_schema_preserves_fixed_unavailable_contract() {
    // The SDK keeps the failure constructor private. Exercise its public stored
    // response type with the fixed failure representation emitted by the host.
    let unavailable: RequestAudit = serde_json::from_value(json!({
        "version":1,"declarationSha256":"a".repeat(64),"status":"unavailable",
        "fields":[],"budgetOmittedFields":0,"absentOmittedFields":0,"reason":"projectionFailed"
    }))
    .unwrap();
    let unavailable = serde_json::to_value(unavailable).unwrap();
    assert_request_audit_response_schemas(&unavailable);
    let validator = jsonschema::validator_for(&super::super::request_audit::schema()).unwrap();
    let mut no_reason = unavailable.clone();
    no_reason.as_object_mut().unwrap().remove("reason");
    assert!(!validator.is_valid(&no_reason));
    let mut leaking_failure = unavailable.clone();
    leaking_failure["reason"] = json!("private dynamic provider error");
    assert!(!validator.is_valid(&leaking_failure));
    let mut failure_with_fields = unavailable.clone();
    failure_with_fields["fields"] = projected_request_audit()["fields"].clone();
    assert!(!validator.is_valid(&failure_with_fields));
    let mut unversioned = unavailable;
    unversioned["version"] = json!(2);
    assert!(!validator.is_valid(&unversioned));

    let captured = projected_request_audit();
    let mut no_digest = captured.clone();
    no_digest
        .as_object_mut()
        .unwrap()
        .remove("declarationSha256");
    assert!(!validator.is_valid(&no_digest));
    let mut invalid_encoding = captured.clone();
    invalid_encoding["fields"][0]["encoding"] = json!("opaque");
    assert!(!validator.is_valid(&invalid_encoding));
    let mut undeclared_metadata = captured;
    undeclared_metadata["fields"][0]["pointer"] = json!("/id");
    assert!(!validator.is_valid(&undeclared_metadata));
}

#[test]
fn audit_input_metadata_preserves_catalog_capabilities_and_transport_sensitivity() {
    let plain = ActionDescriptor::new(
        "update",
        "Update item",
        json!({
            "type":"object","additionalProperties":false,"required":["id","secret"],
            "properties":{
                "id":{"type":"string"},
                "secret":{"type":"string","x-agent-access-sensitive":true}
            }
        }),
    )
    .sensitive_output("/result/token");
    let declaration = AuditInputProjection::new([
        audit_identifier("id", "/id"),
        AuditInputRule::presence("secretPresent", "Secret supplied", "/secret"),
    ]);
    prepare_audit_inputs(&plain.input_schema, &declaration).unwrap();
    let audited = plain.clone().audit_inputs(declaration.clone());
    let mut capabilities = serde_json::to_value(audited.capabilities()).unwrap();
    assert_eq!(
        capabilities.as_object_mut().unwrap().remove("auditInputs"),
        Some(json!(declaration))
    );
    assert_eq!(
        capabilities,
        serde_json::to_value(plain.capabilities()).unwrap()
    );

    let catalog_for = |descriptor: &ActionDescriptor| {
        let mut catalog = empty_catalog(json!({}));
        catalog.services.push(ApiServiceSpec {
            availability: None,
            scoped_mcp_ready: true,
            service: "example".into(),
            display_name: "Example".into(),
            surface: "invoke".into(),
            scope_types: vec![],
            resource_scopes: Default::default(),
            actions: vec![api_action_spec("example", descriptor).unwrap()],
        });
        catalog
    };
    let plain_catalog = catalog_for(&plain);
    let audited_catalog = catalog_for(&audited);
    let mut wire = serde_json::to_value(&audited_catalog).unwrap();
    let action = &mut wire["services"][0]["actions"][0];
    assert_eq!(action["sensitiveInputPointers"], json!(["/inputs/secret"]));
    assert_eq!(action["sensitiveOutputPointers"], json!(["/result/token"]));
    assert_eq!(
        action.as_object_mut().unwrap().remove("auditInputs"),
        Some(json!(declaration))
    );
    assert_eq!(wire, serde_json::to_value(&plain_catalog).unwrap());
    let round_trip: ApiCatalog =
        serde_json::from_value(serde_json::to_value(&audited_catalog).unwrap()).unwrap();
    assert_eq!(
        round_trip.services[0].actions[0].audit_inputs,
        Some(declaration)
    );

    let openapi = openapi_from_catalog(&audited_catalog, RenderAuthMode::Omit, &[], "session");
    assert_eq!(
        openapi,
        openapi_from_catalog(&plain_catalog, RenderAuthMode::Omit, &[], "session")
    );
    let operation = &openapi["paths"]["/v1/invoke/example/update"]["post"];
    assert_eq!(
        operation["x-agent-access-sensitive-output-pointers"],
        json!(["/result/token"])
    );
    assert_eq!(
        operation["requestBody"]["content"]["application/json"]["schema"]["properties"]["inputs"]["properties"]
            ["secret"]["x-agent-access-sensitive"],
        true
    );
    let send = send_schema_from_catalog(&audited_catalog);
    assert_eq!(send, send_schema_from_catalog(&plain_catalog));
    assert_eq!(
        send["oneOf"][0]["x-agent-access-sensitive-pointers"],
        json!(["/inputs/secret"])
    );
    assert_eq!(
        send["oneOf"][0]["x-agent-access-sensitive-output-pointers"],
        json!(["/result/token"])
    );
    assert!(
        send["oneOf"][0]["properties"]
            .get("secretSources")
            .is_some()
    );

    for view in [
        crate::mcp::McpView::Aggregate,
        crate::mcp::McpView::Service("example".into()),
    ] {
        for mode in [
            crate::mcp::ProjectionMode::Http,
            crate::mcp::ProjectionMode::Stdio,
        ] {
            let registry = |catalog: &ApiCatalog| {
                crate::mcp::ToolRegistry::build(
                    catalog,
                    &view,
                    mode,
                    crate::mcp::STDIO_MAX_CATALOG_BYTES,
                )
                .unwrap()
            };
            let tools = registry(&audited_catalog).definitions();
            assert_eq!(tools, registry(&plain_catalog).definitions());
            let tool = tools
                .iter()
                .find(|tool| tool["_meta"]["agent-access/action"] == "update")
                .unwrap();
            assert_eq!(
                tool["_meta"]["agent-access/sensitive-output-pointers"],
                json!(["/result/token"])
            );
            assert_eq!(
                tool["inputSchema"]["properties"]["inputs"]["properties"]["secret"]["x-agent-access-sensitive"],
                true
            );
            assert_eq!(
                tool["inputSchema"]["properties"]
                    .get("secretSources")
                    .is_some(),
                mode == crate::mcp::ProjectionMode::Stdio
            );
        }
    }
}
