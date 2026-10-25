use super::*;
use agent_access_provider::test_support::basic_credential;

#[path = "uploads.rs"]
mod uploads;

fn basic_definition() -> ImportedServiceDefinition {
    let mut def = definition(
        "https://api.example.test/api",
        "https://docs.example.test/spec.json",
    );
    for binding in &mut def.execution_bindings {
        binding.delivery = ImportedCredentialDelivery::Basic;
    }
    def
}
fn swagger() -> Value {
    json!({"swagger":"2.0","info":{"title":"Synthetic","version":"3.1.99"},"host":"api.example.test","basePath":"/api","schemes":["https"],"securityDefinitions":{"access":{"type":"basic"}},"security":[{"access":[]}],"consumes":["application/json","application/x-www-form-urlencoded"],"produces":["application/json"],"paths":{"/items":{"post":{"operationId":"items","parameters":[{"name":"query","in":"formData","type":"string","required":true},{"name":"page","in":"formData","type":"integer","minimum":1}],"responses":{"200":{"description":"Empty"}}}}}})
}
fn row(doc: Value, def: &ImportedServiceDefinition) -> ImportedDiscoveredTool {
    let doc = Document::new(doc, def).unwrap();
    let (path, method) = &doc.operations[0];
    doc.operation(def, path, method)
}
fn compiled(doc: Value, def: &ImportedServiceDefinition) -> CompiledAction {
    let row = row(doc, def);
    assert!(
        row.unsupported_reason.is_none(),
        "{:?}",
        row.unsupported_reason
    );
    CompiledAction::new(&row.definition).unwrap()
}
fn equivalent_openapi() -> Value {
    json!({"openapi":"3.1.1","info":{"version":"3.1.99"},"servers":[{"url":"https://api.example.test/api"}],"components":{"securitySchemes":{"access":{"type":"http","scheme":"basic"}}},"security":[{"access":[]}],"paths":{"/items":{"post":{"operationId":"items","requestBody":{"required":true,"content":{"application/x-www-form-urlencoded":{"schema":{"type":"object","properties":{"query":{"type":"string"},"page":{"type":"integer","minimum":1}},"required":["query"],"additionalProperties":false}}}},"responses":{"200":{"description":"Empty"}}}}}})
}
#[test]
fn old_openapi_actions_and_preview_manifest_bytes_are_unchanged() {
    // Captured by the unmodified b1b94045 parser. Full byte equality also freezes
    // the manifest/action SHA-256 inputs; this fixture is never regenerated.
    let fixtures: Vec<Value> = serde_json::from_str(include_str!(
        "../fixtures/openapi31-baseline-contracts.json"
    ))
    .unwrap();
    for fixture in fixtures {
        let def: ImportedServiceDefinition =
            serde_json::from_value(fixture["definition"].clone()).unwrap();
        let doc = Document::new(
            serde_json::from_str(include_str!("../fixtures/openapi31-baseline-source.json"))
                .unwrap(),
            &def,
        )
        .unwrap();
        let tools = doc
            .operations
            .iter()
            .map(|(p, m)| doc.operation(&def, p, m))
            .collect::<Vec<_>>();
        for (tool, expected) in tools.iter().zip(fixture["actionBytes"].as_array().unwrap()) {
            assert!(tool.unsupported_reason.is_none());
            CompiledAction::new(&tool.definition).unwrap();
            assert_eq!(
                serde_json::to_string(&tool.definition).unwrap(),
                expected.as_str().unwrap()
            );
        }
        let discovery = ImportedDiscovery {
            protocol_version: doc.version,
            metadata: doc.metadata,
            tools,
            service_metadata: None,
            resource_type_changes: vec![],
        };
        assert_eq!(
            serde_json::to_string(&discovery).unwrap(),
            fixture["discoveryBytes"].as_str().unwrap()
        );
    }
}
#[test]
fn supplied_synthetic_fixture_compiles_all_fifteen_operations() {
    let mut def = basic_definition();
    def.connection_settings
        .insert("securityScheme".into(), "basicAuth".into());
    let doc = Document::new(
        serde_json::from_str(include_str!("../fixtures/swagger2-synthetic.json")).unwrap(),
        &def,
    )
    .unwrap();
    assert_eq!(doc.operations.len(), 15);
    assert_eq!(doc.version, "2.0");
    let mut counts = [0; 3];
    for (path, method) in &doc.operations {
        let row = doc.operation(&def, path, method);
        assert!(
            row.unsupported_reason.is_none(),
            "{method} {path}: {:?}",
            row.unsupported_reason
        );
        let action = CompiledAction::new(&row.definition).unwrap();
        assert!(!action.definition.read_only);
        let category = if action.plan.form_body.is_some() {
            1
        } else if action.plan.request_body {
            0
        } else {
            2
        };
        counts[category] += 1;
    }
    assert_eq!(counts, [9, 3, 3]);
}
#[test]
fn equivalent_form_readers_freeze_identical_contracts_and_encode_exactly() {
    let def = basic_definition();
    let a = compiled(swagger(), &def);
    let b = compiled(equivalent_openapi(), &def);
    assert_eq!(a.definition.input_schema, b.definition.input_schema);
    assert_eq!(a.definition.annotations, b.definition.annotations);
    for action in [a, b] {
        let prepared = action
            .request(
                &Url::parse(&def.endpoint).unwrap(),
                &json!({"body":{"query":"a b+c%&=,雪","page":1.0}}),
            )
            .unwrap();
        let (media, bytes) = prepared.body.unwrap();
        assert_eq!(media, "application/x-www-form-urlencoded");
        assert_eq!(
            String::from_utf8(bytes).unwrap(),
            "page=1&query=a+b%2Bc%25%26%3D%2C%E9%9B%AA"
        );
        for input in [
            json!({}),
            json!({"body":null}),
            json!({"body":{"query":null}}),
            json!({"body":{"query":"x","extra":1}}),
            json!({"body":{"query":"x","page":0}}),
        ] {
            assert!(
                action
                    .request(&Url::parse(&def.endpoint).unwrap(), &input)
                    .is_err()
            );
        }
    }
}
#[test]
fn optional_form_absence_empty_object_and_empty_string_are_distinct() {
    let def = basic_definition();
    let mut doc = swagger();
    doc["paths"]["/items"]["post"]["parameters"][0]["required"] = json!(false);
    let action = compiled(doc, &def);
    let base = Url::parse(&def.endpoint).unwrap();
    assert!(action.request(&base, &json!({})).unwrap().body.is_none());
    assert_eq!(
        action
            .request(&base, &json!({"body":{}}))
            .unwrap()
            .body
            .unwrap()
            .1,
        b""
    );
    assert_eq!(
        action
            .request(&base, &json!({"body":{"query":""}}))
            .unwrap()
            .body
            .unwrap()
            .1,
        b"query="
    );
    let mut doc = equivalent_openapi();
    doc["paths"]["/items"]["post"]["requestBody"]["required"] = json!(false);
    let action = compiled(doc, &def);
    assert!(action.request(&base, &json!({})).is_ok());
    assert!(action.request(&base, &json!({"body":{}})).is_err());
}
#[test]
fn version_markers_and_duplicate_members_are_rejected_before_discovery() {
    for bytes in [
        br#"{"swagger":"2.0","swagger":"2.0"}"#.as_slice(),
        br#"{"openapi":"3.1.1","paths":{"/a":{"get":{},"get":{}}}}"#,
    ] {
        assert!(crate::json::decode(bytes).is_err());
    }
    let def = basic_definition();
    for marker in [
        json!({}),
        json!({"swagger":2.0}),
        json!({"openapi":"3.0.3"}),
        json!({"swagger":"2.0","openapi":"3.1.1"}),
        json!({"openapi":"3.1."}),
        json!({"swagger":"2.1"}),
    ] {
        let mut doc = swagger();
        doc.as_object_mut().unwrap().remove("swagger");
        doc.as_object_mut()
            .unwrap()
            .extend(marker.as_object().unwrap().clone());
        assert!(Document::new(doc, &def).is_err());
    }
    assert_eq!(
        Document::new(swagger(), &def).unwrap().metadata["version"],
        "3.1.99"
    );
}
#[test]
fn media_inheritance_security_and_destination_overrides_fail_closed() {
    let def = basic_definition();
    for (key, value) in [
        ("consumes", json!([])),
        (
            "consumes",
            json!(["application/x-www-form-urlencoded; charset=UTF-8"]),
        ),
        ("security", json!([])),
        ("security", json!([{"access":[],"other":[]}])),
        ("schemes", json!([])),
        ("schemes", json!(["http"])),
    ] {
        let mut doc = swagger();
        doc["paths"]["/items"]["post"][key] = value;
        assert!(row(doc, &def).unsupported_reason.is_some(), "{key}");
    }
    let mut doc = swagger();
    doc["schemes"] = json!(["http", "https"]);
    assert!(row(doc, &def).unsupported_reason.is_none());
    let mut doc = swagger();
    doc["paths"]["/items"]["post"]["consumes"] = json!([
        "application/x-www-form-urlencoded; charset=UTF-8",
        "application/x-www-form-urlencoded"
    ]);
    assert!(row(doc, &def).unsupported_reason.is_none());
    let mut doc = swagger();
    let op = doc["paths"]["/items"]["post"].as_object_mut().unwrap();
    op.remove("parameters");
    op.insert("consumes".into(), json!({"inert":"value"}));
    doc["paths"]["/items"]["get"] = doc["paths"]["/items"]["post"].take();
    doc["paths"]["/items"]
        .as_object_mut()
        .unwrap()
        .remove("post");
    assert!(row(doc, &def).unsupported_reason.is_none());
    for (key, value) in [
        ("host", json!("user@api.example.test")),
        ("host", json!("api.example.test/escape")),
        ("basePath", json!("/api/../else")),
        ("basePath", json!("/api?query")),
    ] {
        let mut doc = swagger();
        doc[key] = value;
        assert!(row(doc, &def).unsupported_reason.is_some());
    }
    let mut doc = swagger();
    for key in ["host", "basePath", "schemes"] {
        doc.as_object_mut().unwrap().remove(key);
    }
    let def = definition(
        "https://docs.example.test",
        "https://docs.example.test/spec.json",
    );
    let mut def = def;
    for b in &mut def.execution_bindings {
        b.delivery = ImportedCredentialDelivery::Basic;
    }
    assert!(row(doc, &def).unsupported_reason.is_none());
}
#[test]
fn swagger_json_dialect_handles_arrays_bounds_literals_and_typed_namespaces() {
    let def = basic_definition();
    let mut doc = swagger();
    doc["definitions"] = json!({"Shared":{"type":"array","items":{"type":"object","properties":{"n":{"type":"number","minimum":0,"exclusiveMinimum":true},"flag":{"type":"string","enum":["Y",2]}},"required":["n","flag"]},"minItems":1,"example":{"$ref":"https://literal.example.test"}}});
    doc["parameters"] = json!({"Shared":{"in":"body","name":"arbitrary","required":true,"schema":{"$ref":"#/definitions/Shared"}}});
    doc["responses"] = json!({"Shared":{"description":"Empty"}});
    let op = &mut doc["paths"]["/items"]["post"];
    op["parameters"] = json!([{"$ref":"#/parameters/Shared"}]);
    op["responses"] = json!({"200":{"$ref":"#/responses/Shared"}});
    let action = compiled(doc.clone(), &def);
    let base = Url::parse(&def.endpoint).unwrap();
    assert!(
        action
            .request(&base, &json!({"body":[{"n":1,"flag":"Y","open":"kept"}]}))
            .is_ok()
    );
    for input in [
        json!({"body":[]}),
        json!({"body":[{"n":0,"flag":"Y"}]}),
        json!({"body":[{"n":1,"flag":2}]}),
    ] {
        assert!(action.request(&base, &input).is_err());
    }
    assert_eq!(
        action.definition.input_schema["$defs"]["Shared"]["example"]["$ref"],
        "https://literal.example.test"
    );
    for schema in [
        json!({"type":"number","exclusiveMinimum":true}),
        json!({"type":"number","minimum":0,"exclusiveMinimum":1}),
        json!({"type":"string","x-nullable":true}),
        json!({"type":"string","readOnly":true}),
        json!({"type":"object","discriminator":"kind"}),
        json!({"$ref":"#/definitions/Shared","type":"string"}),
        json!({"$ref":"#/parameters/Shared"}),
        json!({"$ref":"https://api.example.test/schema"}),
    ] {
        let mut bad = doc.clone();
        bad["parameters"]["Shared"]["schema"] = schema;
        assert!(row(bad, &def).unsupported_reason.is_some());
    }
    let mut cyclic = doc.clone();
    cyclic["definitions"]["Shared"] =
        json!({"type":"object","properties":{"next":{"$ref":"#/definitions/Shared"}}});
    assert!(row(cyclic, &def).unsupported_reason.is_some());
    let mut annotation = doc;
    annotation["parameters"]["Shared"]["schema"] = json!({"$ref":"#/definitions/Shared","description":"ignored","title":"ignored","x-note":"ignored"});
    assert!(row(annotation, &def).unsupported_reason.is_none());
}
#[test]
fn frozen_form_plans_reject_untrusted_shape_and_schema_changes() {
    let def = basic_definition();
    let original = compiled(swagger(), &def).definition;
    for form in [
        Value::Null,
        json!({}),
        json!({"fields":[]}),
        json!({"fields":[{"name":"query","valueType":"string","required":true},{"name":"page","valueType":"integer","required":false}]}),
        json!({"fields":[{"name":"page","valueType":"integer","required":false},{"name":"page","valueType":"integer","required":false}]}),
        json!({"fields":[{"name":"page","valueType":"integer","required":false,"extra":true}]}),
        json!({"fields":[],"extra":true}),
    ] {
        let mut action = original.clone();
        action.annotations["openapi"]["formBody"] = form;
        assert!(CompiledAction::new(&action).is_err());
    }
    let mut action = original.clone();
    action.annotations["openapi"]["requestBody"] = json!(false);
    assert!(CompiledAction::new(&action).is_err());
    let mut action = original.clone();
    action.annotations["openapi"]["security"]["header"] = Value::Null;
    assert!(CompiledAction::new(&action).is_err());
    for schema in [
        json!({"type":"object","properties":{"page":{"type":"integer"},"query":{"type":"string"}},"required":["query"]}),
        json!({"type":"object","properties":{"page":{"type":"number"},"query":{"type":"string"}},"required":["query"],"additionalProperties":false}),
        json!({"type":"object","properties":{"page":{"type":"integer"},"query":{"type":"string"}},"required":["query","query"],"additionalProperties":false}),
    ] {
        let mut action = original.clone();
        action.input_schema["properties"]["body"] = schema;
        assert!(CompiledAction::new(&action).is_err());
    }
}
#[test]
fn openapi_form_profile_rejects_nondefault_encoding_and_content_semantics() {
    let def = basic_definition();
    for encoding in [
        Value::Null,
        json!({"unknown":{}}),
        json!({"query":null}),
        json!({"query":{"explode":false}}),
        json!({"query":{"explode":"true"}}),
        json!({"query":{"style":"simple"}}),
        json!({"query":{"allowReserved":true}}),
        json!({"query":{"contentType":"text/plain"}}),
        json!({"query":{"headers":{"X-Test":{}}}}),
        json!({"query":{"unexpected":1}}),
    ] {
        let mut doc = equivalent_openapi();
        doc["paths"]["/items"]["post"]["requestBody"]["content"]["application/x-www-form-urlencoded"]
            ["encoding"] = encoding;
        assert!(row(doc, &def).unsupported_reason.is_some());
    }
    for encoding in [
        json!({}),
        json!({"query":{}}),
        json!({"query":{"style":"form","explode":true,"allowReserved":false,"headers":{}}}),
    ] {
        let mut doc = equivalent_openapi();
        doc["paths"]["/items"]["post"]["requestBody"]["content"]["application/x-www-form-urlencoded"]
            ["encoding"] = encoding;
        assert!(row(doc, &def).unsupported_reason.is_none());
    }
    for property in [
        json!({"type":["string","null"]}),
        json!({"type":"array","items":{"type":"string"}}),
        json!({"type":"object"}),
        json!({"type":"string","contentEncoding":"base64"}),
        json!({"type":"string","contentMediaType":"text/plain"}),
        json!({"type":"string","contentSchema":{}}),
    ] {
        let mut doc = equivalent_openapi();
        doc["paths"]["/items"]["post"]["requestBody"]["content"]["application/x-www-form-urlencoded"]
            ["schema"]["properties"]["query"] = property;
        assert!(row(doc, &def).unsupported_reason.is_some());
    }
}
#[tokio::test]
async fn basic_definition_and_execution_use_separate_origins_and_form_wire() {
    let api = Fixture::new(json!({}), 204, Value::Null, Duration::ZERO).await;
    let mut source = swagger();
    source["host"] = json!(
        Url::parse(&api.base).unwrap()[url::Position::BeforeHost..url::Position::AfterPort]
            .to_owned()
    );
    source["schemes"] = json!(["http"]);
    source["paths"]["/items"]["post"]["responses"] = json!({"204":{"description":"Empty"}});
    let docs = Fixture::new(source, 200, Value::Null, Duration::ZERO).await;
    let mut def = basic_definition();
    def.endpoint = format!("{}/api", api.base);
    def.connection_settings.insert(
        "definitionUrl".into(),
        format!("{}/definition.json", docs.base),
    );
    def.connection_settings
        .insert("definitionAuthKind".into(), "basic".into());
    def.discovery = ImportedDiscoveryCredential::Slot;
    let host = test_host();
    let discovered = OpenApiAdapter
        .discover(
            &def,
            &ImportedDiscoveryAuthentication::Static(basic_credential("docs", "docs-secret")),
            None,
            &ImportedAdapterContext::default(),
            &host.context(),
        )
        .await
        .unwrap();
    assert_eq!(discovered.protocol_version, "2.0");
    let mut action = discovered.tools[0].definition.clone();
    action.action = "item.update".into();
    let provider = OpenApiAdapter
        .build(
            &def,
            &[action],
            None,
            &ImportedAdapterContext::default(),
            &host.context(),
        )
        .unwrap()
        .provider();
    let invoke = |inputs| {
        InvocationBuilder::new("example", "item.update")
            .inputs(inputs)
            .credential(basic_credential("api", "api-secret"))
            .build()
    };
    assert!(
        provider
            .invoke(invoke(json!({"body":{"query":null}})))
            .await
            .is_err()
    );
    assert_eq!(api.call_count(), 0);
    provider
        .invoke(invoke(json!({"body":{"query":"a + 雪","page":2}})))
        .await
        .unwrap();
    assert_eq!(api.call_count(), 1);
    let requests = api.state.calls.lock().unwrap();
    assert_eq!(
        requests[0].headers["authorization"],
        "Basic YXBpOmFwaS1zZWNyZXQ="
    );
    assert_eq!(
        requests[0].headers["content-type"],
        "application/x-www-form-urlencoded"
    );
    assert_eq!(requests[0].body.as_ref(), b"page=2&query=a+%2B+%E9%9B%AA");
    let documents = docs.state.calls.lock().unwrap();
    assert_eq!(documents.len(), 1);
    assert_eq!(
        documents[0].headers["authorization"],
        "Basic ZG9jczpkb2NzLXNlY3JldA=="
    );
}

#[test]
fn form_limits_apply_after_percent_expansion_and_keep_scalar_formatting() {
    let def = basic_definition();
    let mut doc = swagger();
    let parameters = (0..128)
        .map(|i| json!({"name":format!("field{i:03}"),"in":"formData","type":"string"}))
        .collect::<Vec<_>>();
    doc["paths"]["/items"]["post"]["parameters"] = json!(parameters);
    let action = compiled(doc.clone(), &def);
    let base = Url::parse(&def.endpoint).unwrap();
    let body = (0..128)
        .map(|i| (format!("field{i:03}"), json!("&".repeat(4096))))
        .collect::<serde_json::Map<_, _>>();
    let inputs = json!({"body":body});
    assert!(serde_json::to_vec(&inputs).unwrap().len() < 1024 * 1024);
    assert!(action.request(&base, &inputs).is_err());
    doc["paths"]["/items"]["post"]["parameters"]
        .as_array_mut()
        .unwrap()
        .push(json!({"name":"overflow","in":"formData","type":"string"}));
    assert!(row(doc, &def).unsupported_reason.is_some());
    let mut doc = swagger();
    doc["paths"]["/items"]["post"]["parameters"] = json!([{"in":"formData","name":"b","type":"boolean"},{"in":"formData","name":"n","type":"number"},{"in":"formData","name":"i","type":"integer"},{"in":"formData","name":"csv","type":"string"}]);
    let action = compiled(doc, &def);
    assert_eq!(
        action
            .request(
                &base,
                &json!({"body":{"b":false,"n":1.25,"i":1.0,"csv":"a,b"}})
            )
            .unwrap()
            .body
            .unwrap()
            .1,
        b"b=false&csv=a%2Cb&i=1&n=1.25"
    );
}
#[test]
fn typed_references_pointer_escapes_parameter_overrides_and_repeated_paths() {
    let def = basic_definition();
    let mut doc = swagger();
    doc["definitions"] = json!({"escaped/name~":{"type":"string","minLength":2}});
    doc["parameters"] = json!({"wire-name":{"in":"path","name":"id","required":true,"type":"string"},"query":{"name":"tags","in":"query","type":"array","items":{"type":"string"},"collectionFormat":"multi"}});
    let op = doc["paths"]["/items"]["post"].clone();
    doc["paths"] = json!({"/pairs/{id}/related/{id}":{"parameters":[{"$ref":"#/parameters/wire-name"},{"name":"X-Count","in":"header","type":"integer"}],"post":op}});
    let op = &mut doc["paths"]["/pairs/{id}/related/{id}"]["post"];
    op["parameters"] = json!([{"$ref":"#/parameters/query"},{"name":"x-count","in":"header","required":true,"type":"integer"},{"in":"body","name":"ignored","schema":{"$ref":"#/definitions/escaped~1name~0"}}]);
    let action = compiled(doc.clone(), &def);
    let request=action.request(&Url::parse(&def.endpoint).unwrap(),&json!({"path":{"id":"a b"},"query":{"tags":["a,b","x y"]},"headers":{"x-count":2},"body":"ok"})).unwrap();
    assert_eq!(
        request.url.as_str(),
        "https://api.example.test/api/pairs/a%20b/related/a%20b?tags=a%2Cb&tags=x%20y"
    );
    assert_eq!(request.headers["x-count"], "2");
    for parameter in [
        json!({"$ref":"#/responses/query"}),
        json!({"$ref":"#/parameters/missing"}),
        json!({"name":"extra","in":"path","required":true,"type":"string"}),
        json!({"name":"id","in":"path","required":false,"type":"string"}),
        json!({"name":"Authorization","in":"header","type":"string"}),
    ] {
        let mut bad = doc.clone();
        bad["paths"]["/pairs/{id}/related/{id}"]["post"]["parameters"] = json!([parameter]);
        assert!(row(bad, &def).unsupported_reason.is_some());
    }
    let mut duplicate = doc.clone();
    duplicate["paths"]["/pairs/{id}/related/{id}"]["post"]["parameters"] = json!([{"name":"x-a","in":"header","type":"string"},{"name":"X-A","in":"header","type":"string"}]);
    assert!(row(duplicate, &def).unsupported_reason.is_some());
    let mut cycle = doc;
    cycle["parameters"]["query"] = json!({"$ref":"#/parameters/query"});
    assert!(row(cycle, &def).unsupported_reason.is_some());
}
#[test]
fn schema_and_operation_limits_and_reference_form_content_are_bounded() {
    let def = basic_definition();
    let mut deep = json!("leaf");
    for _ in 0..66 {
        deep = json!([deep]);
    }
    assert!(crate::json::decode(&serde_json::to_vec(&deep).unwrap()).is_err());
    let mut doc = swagger();
    let operation = doc["paths"]["/items"].clone();
    doc["paths"] = Value::Object(
        (0..513)
            .map(|i| (format!("/p{i}"), operation.clone()))
            .collect(),
    );
    assert!(Document::new(doc, &def).is_err());
    let mut doc = equivalent_openapi();
    doc["components"]["schemas"] = json!({"Form":{"type":"object","additionalProperties":false,"properties":{"query":{"$ref":"#/components/schemas/Field"},"page":{"type":"integer","minimum":1}},"required":["query"]},"Field":{"type":"string"}});
    doc["paths"]["/items"]["post"]["requestBody"]["content"]["application/x-www-form-urlencoded"]
        ["schema"] = json!({"$ref":"#/components/schemas/Form"});
    assert!(row(doc.clone(), &def).unsupported_reason.is_none());
    doc["components"]["schemas"]["Field"]["contentEncoding"] = json!("base64");
    assert!(row(doc, &def).unsupported_reason.is_some());
}
#[test]
fn supported_json_alternative_is_frozen_and_invalid_json_does_not_fall_back_to_form() {
    let def = basic_definition();
    let mut doc = equivalent_openapi();
    let content = &mut doc["paths"]["/items"]["post"]["requestBody"]["content"];
    content["application/json"] = json!({"schema":{"type":"array","items":{"type":"string"}}});
    let action = compiled(doc.clone(), &def);
    assert!(action.plan.form_body.is_none());
    doc["paths"]["/items"]["post"]["requestBody"]["content"]["application/json"]["schema"] =
        json!({"type":"not-a-type"});
    assert!(row(doc, &def).unsupported_reason.is_some());
    let mut doc = swagger();
    doc["paths"]["/items"]["post"]["parameters"] =
        json!([{"name":"body","in":"body","schema":{"type":"array","items":{"type":"integer"}}}]);
    for media in [
        json!([]),
        json!(["application/problem+json"]),
        json!(["application/json; charset=UTF-8"]),
    ] {
        let mut bad = doc.clone();
        bad["paths"]["/items"]["post"]["consumes"] = media;
        assert!(row(bad, &def).unsupported_reason.is_some());
    }
    doc["paths"]["/items"]["post"]["responses"] = json!({"200":{"schema":{"type":"object"}}});
    for media in [json!([]), json!(["application/json; charset=UTF-8"])] {
        let mut bad = doc.clone();
        bad["paths"]["/items"]["post"]["produces"] = media;
        assert!(row(bad, &def).unsupported_reason.is_some());
    }
    doc["paths"]["/items"]["post"]["produces"] = json!(["text/plain", "application/problem+json"]);
    assert!(row(doc, &def).unsupported_reason.is_none());
}

#[test]
fn response_media_rejects_parameters_and_whitespace_in_both_source_readers() {
    let def = basic_definition();
    for (media, supported) in [
        ("application/json", true),
        ("application/problem+json", true),
        ("application/vnd.example+json", true),
        ("application/problem;version=1+json", false),
        ("application/problem +json", false),
        ("application/problem\t+json", false),
        ("application/json; charset=UTF-8", false),
        ("application/problem+json; version=1", false),
    ] {
        for mut source in [swagger(), equivalent_openapi()] {
            let is_swagger = source.get("swagger").is_some();
            let responses = if is_swagger {
                source["produces"] = json!([media]);
                json!({"200":{"description":"JSON","schema":{"type":"object"}}})
            } else {
                json!({"200":{"description":"JSON","content":{(media):{"schema":{"type":"object"}}}}})
            };
            source["paths"]["/items"]["post"]["responses"] = responses;
            let discovered = row(source, &def);
            assert_eq!(
                discovered.unsupported_reason.is_none(),
                supported,
                "Swagger={is_swagger}, media={media:?}: {:?}",
                discovered.unsupported_reason
            );
            if supported {
                let action = CompiledAction::new(&discovered.definition).unwrap();
                assert_eq!(
                    action.plan.responses["200"].content_type.as_deref(),
                    Some(media)
                );
            }
        }
    }
}

#[test]
fn frozen_legacy_response_plans_reject_parameters_and_whitespace() {
    let fixtures: Vec<Value> = serde_json::from_str(include_str!(
        "../fixtures/openapi31-baseline-contracts.json"
    ))
    .unwrap();
    for fixture in fixtures {
        let original = fixture["actionBytes"]
            .as_array()
            .unwrap()
            .iter()
            .map(|bytes| {
                serde_json::from_str::<ImportedActionDefinition>(bytes.as_str().unwrap()).unwrap()
            })
            .find(|action| action.source["operationId"] == "create")
            .unwrap();
        assert_eq!(
            original.annotations["openapi"]["responses"]["default"]["contentType"],
            "application/problem+json"
        );
        CompiledAction::new(&original).unwrap();
        for media in [
            "application/problem;version=1+json",
            "application/problem +json",
            "application/problem\t+json",
        ] {
            let mut changed = original.clone();
            changed.annotations["openapi"]["responses"]["default"]["contentType"] = json!(media);
            // Earlier source admission accepted these suffixes; offline loading
            // rejected controls but admitted parameters/spaces. Both now agree.
            match CompiledAction::new(&changed) {
                Ok(_) => panic!("loaded unsupported frozen response media {media:?}"),
                Err(reason) => assert_eq!(reason, "unsupported response media contract"),
            }
        }
        let mut valid_suffix = original;
        valid_suffix.annotations["openapi"]["responses"]["default"]["contentType"] =
            json!("application/vnd.example+json");
        CompiledAction::new(&valid_suffix).unwrap();
    }
}

#[tokio::test]
async fn both_readers_send_equivalent_json_delete_and_form_requests_once() {
    for form in [false, true] {
        let fixture = Fixture::new(json!({}), 204, Value::Null, Duration::ZERO).await;
        let mut def = basic_definition();
        def.endpoint = format!("{}/api", fixture.base);
        let host = test_host();
        for mut source in [swagger(), equivalent_openapi()] {
            let swagger = source.get("swagger").is_some();
            let mut operation = source["paths"]["/items"]["post"].clone();
            operation["responses"] = json!({"204":{"description":"Empty"}});
            if !form {
                if swagger {
                    operation["parameters"] = json!([{"name":"ignored","in":"body","required":true,"schema":{"type":"array","items":{"type":"integer"},"minItems":1}}]);
                } else {
                    operation["requestBody"] = json!({"required":true,"content":{"application/json":{"schema":{"type":"array","items":{"type":"integer"},"minItems":1}}}});
                }
            }
            source["paths"] = json!({"/items":{"delete":operation}});
            if swagger {
                source["host"] = json!(
                    Url::parse(&fixture.base).unwrap()
                        [url::Position::BeforeHost..url::Position::AfterPort]
                        .to_owned()
                );
                source["schemes"] = json!(["http"]);
            } else {
                source["servers"] = json!([{"url":def.endpoint}]);
            }
            let mut action = compiled(source, &def).definition;
            action.action = "item.update".into();
            let provider = OpenApiAdapter
                .build(
                    &def,
                    &[action],
                    None,
                    &ImportedAdapterContext::default(),
                    &host.context(),
                )
                .unwrap()
                .provider();
            let inputs = if form {
                json!({"body":{"page":1,"query":"x + 雪"}})
            } else {
                json!({"body":[1,2,3]})
            };
            provider
                .invoke(
                    InvocationBuilder::new("example", "item.update")
                        .inputs(inputs)
                        .credential(basic_credential("api", "api-secret"))
                        .build(),
                )
                .await
                .unwrap();
        }
        let calls = fixture.state.calls.lock().unwrap();
        assert_eq!(calls.len(), 2);
        assert_eq!(calls[0].method, Method::DELETE);
        assert_eq!(calls[0].path, calls[1].path);
        assert_eq!(calls[0].body, calls[1].body);
        assert_eq!(
            calls[0].headers["content-type"],
            calls[1].headers["content-type"]
        );
    }
}

#[test]
fn swagger_booleans_are_only_additional_properties_flags() {
    let def = basic_definition();
    for schema in [
        json!({"type":"object","properties":{"value":true}}),
        json!({"type":"array","items":false}),
        json!({"allOf":[true]}),
        json!({"$ref":"#/definitions/Boolean"}),
    ] {
        let mut doc = swagger();
        doc["definitions"] = json!({"Boolean":true});
        doc["paths"]["/items"]["post"]["parameters"] =
            json!([{"name":"body","in":"body","schema":schema}]);
        assert!(
            row(doc, &def)
                .unsupported_reason
                .unwrap()
                .contains("Swagger schemas must be objects")
        );
    }
    for additional in [json!(true), json!(false), json!({"type":"string"})] {
        let mut doc = swagger();
        doc["paths"]["/items"]["post"]["parameters"] = json!([{"name":"body","in":"body","schema":{"type":"object","additionalProperties":additional}}]);
        assert!(row(doc, &def).unsupported_reason.is_none());
    }
}
#[tokio::test]
async fn duplicate_json_member_discovery_reports_a_fixed_category_without_source_values() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let router = Router::new().fallback(any(|| async {
        (
            [("content-type", "application/json")],
            r#"{"swagger":"2.0","paths":{"secret-source-name":{},"secret-source-name":{}}}"#,
        )
    }));
    let task = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let mut def = basic_definition();
    def.connection_settings.insert(
        "definitionUrl".into(),
        format!("http://{address}/definition.json"),
    );
    let error = OpenApiAdapter
        .discover(
            &def,
            &ImportedDiscoveryAuthentication::Anonymous,
            None,
            &ImportedAdapterContext::default(),
            &test_host().context(),
        )
        .await
        .expect_err("duplicate source must fail");
    let AdapterDiscoveryError::Failed(error) = error else {
        panic!("expected upstream protocol failure");
    };
    assert_eq!(error.reason_code(), ReasonCode::UpstreamProtocolFailed);
    let message = error.message;
    assert_eq!(message, "duplicate JSON member in definition");
    assert!(!message.contains("secret-source-name"));
    task.abort();
}

#[test]
fn forms_accept_long_and_control_containing_values_without_relaxing_parameters() {
    let def = basic_definition();
    let action = compiled(swagger(), &def);
    let base = Url::parse(&def.endpoint).unwrap();
    let long = "a".repeat(8192);
    let prepared = action
        .request(&base, &json!({"body":{"query":long}}))
        .unwrap();
    assert_eq!(prepared.body.unwrap().1.len(), 8198);
    let prepared = action
        .request(
            &base,
            &json!({"body":{"query":"line1\nline2\r\t\u{0000}雪"}}),
        )
        .unwrap();
    assert_eq!(
        prepared.body.unwrap().1,
        b"query=line1%0Aline2%0D%09%00%E9%9B%AA"
    );
    let mut doc = swagger();
    doc["paths"]["/items"]["post"]["parameters"]
        .as_array_mut()
        .unwrap()
        .push(json!({"name":"filter","in":"query","type":"string"}));
    let action = compiled(doc, &def);
    for value in ["a".repeat(4097), "a\nb".to_owned()] {
        assert!(
            action
                .request(
                    &base,
                    &json!({"body":{"query":"ok"},"query":{"filter":value}})
                )
                .is_err()
        );
    }
    assert!(
        action
            .request(&base, &json!({"body":{"query":"&".repeat(400_000)}}))
            .is_err()
    );
}

#[test]
fn swagger_local_schema_pointer_siblings_are_not_mistaken_for_cycles() {
    let def = basic_definition();
    let mut doc = swagger();
    doc["definitions"] = json!({"Object":{"type":"object","properties":{"alias":{"type":"string"},"value":{"$ref":"#/definitions/Object/properties/alias"}},"required":["value"]}});
    doc["paths"]["/items"]["post"]["parameters"] =
        json!([{"name":"body","in":"body","schema":{"$ref":"#/definitions/Object"}}]);
    let action = compiled(doc, &def);
    assert!(
        action
            .request(
                &Url::parse(&def.endpoint).unwrap(),
                &json!({"body":{"value":"ok"}})
            )
            .is_ok()
    );
}

#[tokio::test]
async fn optional_empty_form_has_content_type_only_when_body_is_present() {
    let fixture = Fixture::new(json!({}), 204, Value::Null, Duration::ZERO).await;
    let mut def = basic_definition();
    def.endpoint = format!("{}/api", fixture.base);
    let mut source = equivalent_openapi();
    source["servers"] = json!([{"url":def.endpoint}]);
    let operation = &mut source["paths"]["/items"]["post"];
    operation["responses"] = json!({"204":{"description":"Empty"}});
    operation["requestBody"]["required"] = json!(false);
    operation["requestBody"]["content"]["application/x-www-form-urlencoded"]["schema"]["required"] =
        json!([]);
    let mut action = compiled(source, &def).definition;
    action.action = "item.update".into();
    let provider = OpenApiAdapter
        .build(
            &def,
            &[action],
            None,
            &ImportedAdapterContext::default(),
            &test_host().context(),
        )
        .unwrap()
        .provider();
    for inputs in [json!({}), json!({"body":{}})] {
        provider
            .invoke(
                InvocationBuilder::new("example", "item.update")
                    .inputs(inputs)
                    .credential(basic_credential("api", "api-secret"))
                    .build(),
            )
            .await
            .unwrap();
    }
    let calls = fixture.state.calls.lock().unwrap();
    assert_eq!(calls.len(), 2);
    assert!(!calls[0].headers.contains_key("content-type"));
    assert!(calls[0].body.is_empty());
    assert_eq!(
        calls[1].headers["content-type"],
        "application/x-www-form-urlencoded"
    );
    assert!(calls[1].body.is_empty());
}
