use crate::*;
use serde_json::{Value, json};

fn options(authentication: GatewayAuthenticationSelection) -> GatewayCompileOptions {
    GatewayCompileOptions {
        endpoint: "https://api.example.test/api".into(),
        document_base: "https://api.example.test/openapi.json".into(),
        authentication,
    }
}
fn source() -> Value {
    json!({"openapi":"3.1.1","servers":[{"url":"https://api.example.test/api"}],"paths":{
        "/items/{id}":{"parameters":[{"name":"id","in":"path","required":true,"schema":{"type":"string"}}],"get":{"operationId":"item_read","responses":{"200":{"description":"Item","content":{"application/json":{"schema":{"type":"object"}}}}}}},
        "/items/admin":{"get":{"operationId":"item_admin","responses":{"200":{"description":"Admin"}}}}}
    })
}
fn compile(
    value: &Value,
    authentication: GatewayAuthenticationSelection,
) -> Result<GatewayCompilation, String> {
    compile_gateway_document(
        &serde_json::to_vec(value).unwrap(),
        &options(authentication),
    )
}

#[test]
fn openapi_anonymous_compilation_keeps_source_identity_and_complete_guard_universe() {
    let result = compile(&source(), GatewayAuthenticationSelection::Anonymous).unwrap();
    assert_eq!(result.version, "3.1.1");
    assert_eq!(
        result.metadata,
        json!({"openapiVersion":"3.1.1","title":null,"version":null,
            "apiBaseUrl":"https://api.example.test/api","securitySchemes":[]})
    );
    assert_eq!(result.operations.len(), 2);
    for operation in result.operations {
        let plan = operation.plan.unwrap();
        assert_eq!(plan.source, operation.source);
        assert_eq!(plan.security.kind, "anonymous");
        result.routes.validate_plan(&plan).unwrap();
    }
    assert_eq!(
        result
            .routes
            .select("GET", "/items/admin")
            .unwrap()
            .unwrap()
            .template,
        "/items/admin"
    );
}

#[test]
fn static_selection_never_falls_back_to_anonymous_or_another_security_alternative() {
    let mut doc = source();
    doc["components"] = json!({"securitySchemes":{"key":{"type":"apiKey","in":"header","name":"X-Api-Key"},"bearer":{"type":"http","scheme":"bearer"},"basic":{"type":"http","scheme":"basic"}}});
    doc["security"] = json!([{}, {"key":[]}, {"bearer":[]}, {"basic":[]}]);
    for (scheme, kind) in [
        ("key", "raw_header"),
        ("bearer", "bearer"),
        ("basic", "basic"),
    ] {
        let result = compile(
            &doc,
            GatewayAuthenticationSelection::Static {
                scheme: Some(scheme.into()),
            },
        )
        .unwrap();
        assert!(
            result
                .operations
                .iter()
                .all(|op| op.plan.as_ref().is_some_and(|p| p.security.kind == kind))
        );
    }
    let anonymous = compile(&doc, GatewayAuthenticationSelection::Anonymous).unwrap();
    assert!(
        anonymous
            .operations
            .iter()
            .all(|op| op.plan.as_ref().unwrap().security.kind == "anonymous")
    );
    doc["paths"]["/items/admin"]["get"]["security"] = json!([]);
    let selected = compile(
        &doc,
        GatewayAuthenticationSelection::Static {
            scheme: Some("key".into()),
        },
    )
    .unwrap();
    assert!(
        selected
            .operations
            .iter()
            .find(|op| op.action == "item_admin")
            .unwrap()
            .plan
            .is_none()
    );
    let draft = compile(
        &doc,
        GatewayAuthenticationSelection::Static { scheme: None },
    )
    .unwrap();
    assert_eq!(
        draft.metadata["securitySchemes"].as_array().unwrap().len(),
        3
    );
    assert!(draft.operations.iter().all(|op| op.plan.is_none()));
}

#[test]
fn compound_query_cookie_and_oauth_authentication_are_not_approximated() {
    for declaration in [
        json!({"type":"apiKey","in":"query","name":"api_key"}),
        json!({"type":"apiKey","in":"cookie","name":"session"}),
        json!({"type":"oauth2","flows":{}}),
    ] {
        let mut doc = source();
        doc["components"] = json!({"securitySchemes":{"selected":declaration}});
        doc["security"] = json!([{"selected":[]}]);
        assert!(
            compile(
                &doc,
                GatewayAuthenticationSelection::Static {
                    scheme: Some("selected".into())
                }
            )
            .unwrap()
            .operations
            .iter()
            .all(|op| op.plan.is_none())
        );
        assert!(
            compile(&doc, GatewayAuthenticationSelection::Anonymous)
                .unwrap()
                .operations
                .iter()
                .all(|op| op.plan.is_none())
        );
    }
    let mut doc = source();
    doc["components"] = json!({"securitySchemes":{"key":{"type":"apiKey","in":"header","name":"X-Key"},"second":{"type":"http","scheme":"basic"}}});
    doc["security"] = json!([{"key":[],"second":[]}]);
    assert!(
        compile(
            &doc,
            GatewayAuthenticationSelection::Static {
                scheme: Some("key".into())
            }
        )
        .unwrap()
        .operations
        .iter()
        .all(|op| op.plan.is_none())
    );
}

#[test]
fn swagger_static_basic_raw_body_and_header_response_compile_without_json_envelopes() {
    let doc = json!({"swagger":"2.0","host":"api.example.test","basePath":"/api","schemes":["https"],
        "securityDefinitions":{"basic":{"type":"basic"}},"security":[{"basic":[]}],"consumes":["application/octet-stream"],"produces":["application/octet-stream"],
        "paths":{"/files/{id}":{"parameters":[{"name":"id","in":"path","type":"string","required":true}],"put":{"operationId":"file_put","parameters":[{"name":"payload","in":"body","required":true,"schema":{"type":"string","format":"binary"}}],"responses":{"200":{"description":"bytes","schema":{"type":"file"},"headers":{"X-Api-Version":{"type":"string","maxLength":32}}}}}}}
    });
    let result = compile(
        &doc,
        GatewayAuthenticationSelection::Static {
            scheme: Some("basic".into()),
        },
    )
    .unwrap();
    let plan = result.operations[0].plan.as_ref().unwrap();
    assert_eq!(plan.security.kind, "basic");
    assert_eq!(
        plan.request_body.as_ref().unwrap().media_types,
        ["application/octet-stream"]
    );
    assert_eq!(plan.responses["200"].headers[0].name, "X-Api-Version");
    assert_eq!(
        plan.responses["200"].content_types,
        ["application/octet-stream"]
    );
}

#[test]
fn swagger_query_array_and_exclusive_integer_semantics_are_preserved() {
    let doc = json!({"swagger":"2.0","host":"api.example.test","basePath":"/api","schemes":["https"],"paths":{"/items":{"get":{"parameters":[
        {"name":"tag","in":"query","type":"array","items":{"type":"string"},"collectionFormat":"multi"},
        {"name":"count","in":"query","type":"integer","minimum":1,"exclusiveMinimum":true}],"responses":{"200":{"description":"ok"}}}}}});
    let result = compile(&doc, GatewayAuthenticationSelection::Anonymous).unwrap();
    let plan = result.operations[0].plan.as_ref().unwrap();
    let selected = result.routes.select("GET", "/items").unwrap().unwrap();
    assert!(
        plan.validate_request_parameters(&selected, Some("count=1"), &http::HeaderMap::new())
            .is_err()
    );
    let request = plan
        .validate_request_parameters(
            &selected,
            Some("count=2&tag=z&tag=a"),
            &http::HeaderMap::new(),
        )
        .unwrap();
    assert_eq!(request.relative_target, "/items?count=2&tag=z&tag=a");
}

#[test]
fn local_typed_references_work_and_external_or_recursive_parameter_refs_are_rejected() {
    let mut doc = source();
    doc["components"] = json!({"parameters":{"ID":{"name":"id","in":"path","required":true,"schema":{"$ref":"#/components/schemas/ID"}}},"schemas":{"ID":{"type":"string","maxLength":32}}});
    doc["paths"]["/items/{id}"]["parameters"] = json!([{"$ref":"#/components/parameters/ID"}]);
    let result = compile(&doc, GatewayAuthenticationSelection::Anonymous).unwrap();
    assert!(result.operations.iter().all(|op| op.plan.is_some()));
    doc["components"]["schemas"]["ID"] = json!({"$ref":"https://SENTINEL.example/schema"});
    let result = compile(&doc, GatewayAuthenticationSelection::Anonymous).unwrap();
    let error = result
        .operations
        .iter()
        .find(|op| op.action == "item_read")
        .unwrap()
        .unsupported_reason
        .as_ref()
        .unwrap();
    assert!(!error.contains("SENTINEL"));
    doc["components"]["schemas"]["ID"] = json!({"$ref":"#/components/schemas/ID"});
    assert!(
        compile(&doc, GatewayAuthenticationSelection::Anonymous)
            .unwrap()
            .operations
            .iter()
            .find(|op| op.action == "item_read")
            .unwrap()
            .plan
            .is_none()
    );
}

#[test]
fn unsafe_or_conflicting_source_guards_abort_discovery_and_unsupported_methods_still_reserve_paths()
{
    for path in ["/items/{id}/bad-{part}", "/items/{name}", "/items/%2fadmin"] {
        let mut doc = source();
        doc["paths"][path] = json!({"get":{"responses":{"200":{"description":"ok"}}}});
        assert!(compile(&doc, GatewayAuthenticationSelection::Anonymous).is_err());
    }
    let mut doc = source();
    doc["paths"]["/items/admin"] =
        json!({"trace":{"operationId":"trace_admin","responses":{"200":{"description":"ok"}}}});
    let result = compile(&doc, GatewayAuthenticationSelection::Anonymous).unwrap();
    assert!(
        result
            .operations
            .iter()
            .find(|op| op.action == "trace_admin")
            .unwrap()
            .plan
            .is_none()
    );
    let selected = result
        .routes
        .select("GET", "/items/admin")
        .unwrap()
        .unwrap();
    assert_eq!(selected.template, "/items/admin");
    assert!(selected.route.is_none());
}

#[test]
fn duplicate_members_versions_and_source_limits_fail_without_supplied_values_in_errors() {
    let bytes = br#"{"openapi":"3.1.1","paths":{},"paths":{"SENTINEL":{}}}"#;
    let error =
        compile_gateway_document(bytes, &options(GatewayAuthenticationSelection::Anonymous))
            .err()
            .unwrap();
    assert!(error.contains("duplicate"));
    assert!(!error.contains("SENTINEL"));
    for version in ["3.0.3", "3.2.0", "3.1.SENTINEL"] {
        let mut doc = source();
        doc["openapi"] = json!(version);
        assert!(compile(&doc, GatewayAuthenticationSelection::Anonymous).is_err());
    }
    let mut doc = source();
    doc["swagger"] = json!("2.0");
    assert!(compile(&doc, GatewayAuthenticationSelection::Anonymous).is_err());
    assert!(
        compile_gateway_document(
            &vec![b' '; GATEWAY_MAX_DOCUMENT_BYTES + 1],
            &options(GatewayAuthenticationSelection::Anonymous)
        )
        .is_err()
    );
}

#[test]
fn unapproved_server_keeps_preview_unsupported_and_relative_upload_server_uses_approved_base() {
    let mut doc = source();
    doc["paths"]["/items/admin"]["get"]["servers"] =
        json!([{"url":"https://SENTINEL.example/api"}]);
    let result = compile(&doc, GatewayAuthenticationSelection::Anonymous).unwrap();
    assert!(
        result
            .operations
            .iter()
            .find(|op| op.action == "item_admin")
            .unwrap()
            .plan
            .is_none()
    );
    doc["paths"]["/items/admin"]["get"]
        .as_object_mut()
        .unwrap()
        .remove("servers");
    doc["servers"] = json!([{"url":"/api"}]);
    let mut opts = options(GatewayAuthenticationSelection::Anonymous);
    opts.document_base = opts.endpoint.clone();
    assert!(
        compile_gateway_document(&serde_json::to_vec(&doc).unwrap(), &opts)
            .unwrap()
            .operations
            .iter()
            .all(|op| op.plan.is_some())
    );
}

#[test]
fn field_schema_is_documentation_but_body_media_and_presence_remain_enforced() {
    let mut doc = source();
    doc["paths"]["/items/{id}"]["put"] = json!({"requestBody":{"required":true,"content":{"application/json":{"schema":{"type":"object","required":["secret"],"additionalProperties":false}}}},"responses":{"204":{"description":"done"}}});
    let result = compile(&doc, GatewayAuthenticationSelection::Anonymous).unwrap();
    let plan = result
        .operations
        .iter()
        .find(|op| op.plan.as_ref().is_some_and(|p| p.method == "PUT"))
        .unwrap()
        .plan
        .as_ref()
        .unwrap();
    plan.validate_body(true, Some("application/json")).unwrap();
    assert!(plan.validate_body(false, Some("application/json")).is_err());
    doc["paths"]["/items/{id}"]["put"]["requestBody"]["content"] =
        json!({"multipart/form-data":{"schema":{"type":"object"}}});
    assert!(
        compile(&doc, GatewayAuthenticationSelection::Anonymous)
            .unwrap()
            .operations
            .iter()
            .find(|op| op.source["method"] == "PUT")
            .unwrap()
            .plan
            .is_none()
    );
}

#[test]
fn declared_header_changes_are_part_of_accepted_plan_and_reserved_names_are_unsupported() {
    let mut doc = source();
    doc["paths"]["/items/admin"]["get"]["responses"]["200"]["headers"] =
        json!({"X-Api-Version":{"schema":{"type":"string","maxLength":32}}});
    let before = compile(&doc, GatewayAuthenticationSelection::Anonymous)
        .unwrap()
        .operations
        .into_iter()
        .find(|op| op.action == "item_admin")
        .unwrap()
        .plan
        .unwrap();
    doc["paths"]["/items/admin"]["get"]["responses"]["200"]["headers"]["X-Api-Version"]["schema"]
        ["maxLength"] = json!(64);
    let after = compile(&doc, GatewayAuthenticationSelection::Anonymous)
        .unwrap()
        .operations
        .into_iter()
        .find(|op| op.action == "item_admin")
        .unwrap()
        .plan
        .unwrap();
    assert_ne!(
        serde_json::to_vec(&before).unwrap(),
        serde_json::to_vec(&after).unwrap()
    );
    doc["paths"]["/items/admin"]["get"]["responses"]["200"]["headers"] =
        json!({"WWW-Authenticate":{"schema":{"type":"string"}}});
    assert!(
        compile(&doc, GatewayAuthenticationSelection::Anonymous)
            .unwrap()
            .operations
            .iter()
            .find(|op| op.action == "item_admin")
            .unwrap()
            .plan
            .is_none()
    );
}

#[test]
fn duplicate_operation_ids_have_no_executable_plan_but_distinct_fallback_source_guards() {
    let mut doc = source();
    doc["paths"]["/items/admin"]["get"]["operationId"] = json!("item_read");
    let result = compile(&doc, GatewayAuthenticationSelection::Anonymous).unwrap();
    assert!(
        result
            .operations
            .iter()
            .all(|op| op.plan.is_none() && op.source.get("method").is_some())
    );
    assert_eq!(result.routes.paths.len(), 2);
}

#[test]
fn first_release_v1_wire_and_canonical_hashes_remain_frozen() {
    use sha2::{Digest, Sha256};
    let hashes: Value = serde_json::from_str(include_str!("fixtures/v1-hashes.json")).unwrap();
    let source = include_bytes!("fixtures/v1-source.json");
    for (name, bytes, authentication) in [
        (
            "v1-anonymous-plan.json",
            include_bytes!("fixtures/v1-anonymous-plan.json").as_slice(),
            GatewayAuthenticationSelection::Anonymous,
        ),
        (
            "v1-static-plan.json",
            include_bytes!("fixtures/v1-static-plan.json").as_slice(),
            GatewayAuthenticationSelection::Static {
                scheme: Some("inventory_key".into()),
            },
        ),
    ] {
        let historical: GatewayPlanV1 = serde_json::from_slice(bytes).unwrap();
        historical.validate().unwrap();
        assert_eq!(serde_json::to_vec(&historical).unwrap(), bytes);
        let canonical = serde_json::to_vec(&serde_json::to_value(&historical).unwrap()).unwrap();
        assert_eq!(
            format!("{:x}", Sha256::digest(bytes)),
            hashes[name]["wireSha256"]
        );
        assert_eq!(
            format!("{:x}", Sha256::digest(&canonical)),
            hashes[name]["canonicalSha256"]
        );
        let current = compile_gateway_document(source, &options(authentication)).unwrap();
        assert_eq!(current.operations[0].plan.as_ref().unwrap(), &historical);
    }
    let bytes = include_bytes!("fixtures/v1-retained-routes.json");
    let historical: GatewayRouteManifestV1 = serde_json::from_slice(bytes).unwrap();
    historical.validate().unwrap();
    assert_eq!(serde_json::to_vec(&historical).unwrap(), bytes);
    assert_eq!(
        format!("{:x}", Sha256::digest(bytes)),
        hashes["v1-retained-routes.json"]["wireSha256"]
    );
    let canonical = serde_json::to_vec(&serde_json::to_value(&historical).unwrap()).unwrap();
    assert_eq!(
        format!("{:x}", Sha256::digest(&canonical)),
        hashes["v1-retained-routes.json"]["canonicalSha256"]
    );
    // Derive the retained manifest from the real source compiler and refresh
    // merge. The historical bytes above are read-only expectations, never a
    // source for constructing the candidate under test.
    let mut prior_source: Value = serde_json::from_slice(source).unwrap();
    prior_source["paths"]["/items/admin"] = json!({"get":{
        "operationId":"inventory_admin","responses":{"200":{"description":"Admin"}}
    }});
    let prior = compile_gateway_document(
        &serde_json::to_vec(&prior_source).unwrap(),
        &options(GatewayAuthenticationSelection::Anonymous),
    )
    .unwrap();
    let mut current =
        compile_gateway_document(source, &options(GatewayAuthenticationSelection::Anonymous))
            .unwrap();
    current.routes.merge_retained(&prior.routes).unwrap();
    assert_eq!(current.routes, historical);
    assert_eq!(serde_json::to_vec(&current.routes).unwrap(), bytes);
    assert_eq!(
        serde_json::to_vec(&serde_json::to_value(&current.routes).unwrap()).unwrap(),
        canonical,
    );
    let selected = historical.select("GET", "/items/admin").unwrap().unwrap();
    assert_eq!(selected.template, "/items/admin");
    assert!(!selected.route.unwrap().current);
}

#[test]
fn operation_and_path_guard_limits_reject_complete_candidates() {
    let mut doc = source();
    doc["paths"] = json!({});
    for index in 0..=GATEWAY_MAX_OPERATIONS {
        doc["paths"][format!("/p{index}")] =
            json!({"get":{"responses":{"200":{"description":"ok"}}}});
    }
    assert!(
        compile(&doc, GatewayAuthenticationSelection::Anonymous)
            .unwrap_err()
            .contains("operation limit")
    );
    doc["paths"] = json!({});
    for index in 0..=GATEWAY_MAX_PATHS {
        doc["paths"][format!("/p{index}")] = json!({});
    }
    assert!(
        compile(&doc, GatewayAuthenticationSelection::Anonymous)
            .unwrap_err()
            .contains("path guard limit")
    );
}

#[test]
fn endpoint_validation_does_not_erase_dot_segments_before_admission() {
    for endpoint in [
        "https://api.example.test/a/../api",
        "https://api.example.test/a/%2E%2e/api",
        "https://api.example.test/a/%252e/api",
    ] {
        assert!(validate_endpoint(endpoint).is_err());
    }
}

#[test]
fn anonymous_mode_cannot_forward_another_declared_security_scheme_as_a_parameter() {
    for location in ["header", "query"] {
        let mut doc = source();
        doc["components"] = json!({"securitySchemes":{"unused":{"type":"apiKey","in":location,"name":"X-Api-Key"}}});
        doc["paths"]["/items/admin"]["get"]["parameters"] =
            json!([{"name":"X-Api-Key","in":location,"schema":{"type":"string"}}]);
        let compiled = compile(&doc, GatewayAuthenticationSelection::Anonymous).unwrap();
        assert!(
            compiled
                .operations
                .iter()
                .find(|operation| operation.action == "item_admin")
                .unwrap()
                .plan
                .is_none()
        );
    }
}

#[test]
fn neutral_json_decoder_retains_explicit_limits_duplicate_checks_and_safe_diagnostics() {
    assert_eq!(
        decode_bounded_document_json(br#"{"value":[1,true,null]}"#, 128, 3).unwrap(),
        json!({"value":[1,true,null]})
    );
    assert_eq!(
        decode_bounded_document_json(b"{}", 1, 64).unwrap_err(),
        "definition exceeds JSON byte limit"
    );
    assert_eq!(
        decode_bounded_document_json(br#"{"a":{"b":0}}"#, 128, 1).unwrap_err(),
        "definition exceeds JSON depth limit"
    );
    assert_eq!(
        decode_bounded_document_json(br#"{"SENTINEL":1,"SENTINEL":2}"#, 128, 64).unwrap_err(),
        "duplicate JSON member in definition"
    );
    assert_eq!(
        decode_bounded_document_json(br#"{} {}"#, 128, 64).unwrap_err(),
        "definition must contain exactly one JSON value"
    );
    assert_eq!(
        decode_bounded_document_json(br#"{"SENTINEL": invalid}"#, 128, 64).unwrap_err(),
        "definition must be bounded JSON"
    );
}

#[test]
fn missing_path_required_flag_has_a_specific_value_free_diagnostic_in_both_dialects() {
    let mut openapi = source();
    openapi["paths"]["/items/{id}"]["parameters"][0]
        .as_object_mut()
        .unwrap()
        .remove("required");
    let swagger = json!({"swagger":"2.0","host":"api.example.test","basePath":"/api","schemes":["https"],
        "paths":{"/items/{id}":{"get":{"parameters":[{"name":"id","in":"path","type":"string"}],"responses":{"200":{"description":"ok"}}}}}});
    for document in [openapi, swagger] {
        let compiled = compile(&document, GatewayAuthenticationSelection::Anonymous).unwrap();
        let unsupported = compiled
            .operations
            .iter()
            .find(|op| op.plan.is_none())
            .unwrap();
        assert_eq!(
            unsupported.unsupported_reason.as_deref(),
            Some("path parameters must declare required: true")
        );
    }
}

#[test]
fn declared_client_identity_and_routing_headers_are_unsupported_at_discovery() {
    for name in [
        "X-Real-IP",
        "True-Client-IP",
        "CF-Connecting-IP",
        "Refresh",
        "Alt-Svc",
        "Strict-Transport-Security",
    ] {
        for response in [false, true] {
            let mut doc = source();
            if response {
                doc["paths"]["/items/admin"]["get"]["responses"]["200"]["headers"] =
                    json!({name:{"schema":{"type":"string"}}});
            } else {
                doc["paths"]["/items/admin"]["get"]["parameters"] =
                    json!([{"name":name,"in":"header","schema":{"type":"string"}}]);
            }
            let compiled = compile(&doc, GatewayAuthenticationSelection::Anonymous).unwrap();
            assert!(
                compiled
                    .operations
                    .iter()
                    .find(|op| op.action == "item_admin")
                    .unwrap()
                    .plan
                    .is_none()
            );
        }
    }
}

#[test]
fn source_semicolon_paths_fail_complete_discovery_in_both_dialects() {
    for path in ["/items/admin;x", "/items/..;/comments"] {
        for mut document in [source(), json!({"swagger":"2.0","paths":{}})] {
            document["paths"][path] = json!({"get":{"responses":{"200":{"description":"ok"}}}});
            assert_eq!(
                compile(&document, GatewayAuthenticationSelection::Anonymous).unwrap_err(),
                "gateway path contains an unsafe component"
            );
        }
    }
}
