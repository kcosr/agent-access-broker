use super::*;
use serde_json::json;

fn text(key: &str, pointer: &str) -> AuditInputRule {
    AuditInputRule::value(key, key, pointer)
        .kind(AuditValueKind::Text)
        .max_bytes(1024)
        .overflow(AuditOverflow::Prefix)
}

#[test]
fn prepared_plan_captures_requested_facts_without_schema_value_validation() {
    let schema = json!({"properties":{"title":{"type":"string","enum":["approved"]},"flag":{"type":"boolean"}}});
    let plan = prepare_audit_inputs(
        &schema,
        &AuditInputProjection::new([
            text("title", "/title"),
            AuditInputRule::value("flag", "Flag", "/flag").kind(AuditValueKind::Boolean),
        ]),
    )
    .unwrap();
    let captured = serde_json::to_value(
        plan.project(&json!({"title":"different", "flag":false}))
            .unwrap(),
    )
    .unwrap();
    assert_eq!(captured["status"], "complete");
    assert_eq!(captured["fields"][0]["value"], "different");
    assert_eq!(captured["fields"][1]["value"], false);
}

#[test]
fn sensitive_value_is_vetoed_while_explicit_presence_is_allowed() {
    let schema = json!({"properties":{"secret":{"x-agent-access-sensitive":true}}});
    assert!(
        prepare_audit_inputs(
            &schema,
            &AuditInputProjection::new([text("secret", "/secret")])
        )
        .is_err()
    );
    let plan = prepare_audit_inputs(
        &schema,
        &AuditInputProjection::new([AuditInputRule::presence(
            "secret",
            "Secret supplied",
            "/secret",
        )]),
    )
    .unwrap();
    let encoded =
        serde_json::to_string(&plan.project(&json!({"secret":"canary_secret_material"}))).unwrap();
    assert!(!encoded.contains("canary_secret_material"));
    assert!(encoded.contains("\"value\":true"));
}

#[test]
fn compiled_omissions_produce_no_snapshot() {
    let plan = prepare_audit_inputs(
        &json!({"properties":{"body":{}}}),
        &AuditInputProjection::new([AuditInputRule::omit("body", "/body")]),
    )
    .unwrap();
    assert!(plan.project(&json!({"body":"private"})).is_none());
}

fn projected(
    schema: Value,
    rules: impl IntoIterator<Item = AuditInputRule>,
    inputs: Value,
) -> Value {
    let plan = prepare_audit_inputs(&schema, &AuditInputProjection::new(rules)).unwrap();
    serde_json::to_value(plan.project(&inputs).unwrap()).unwrap()
}

fn identity(key: &str, pointer: &str) -> AuditInputRule {
    AuditInputRule::value(key, key, pointer)
        .kind(AuditValueKind::Identifier)
        .max_bytes(1024)
        .overflow(AuditOverflow::Omit)
}

#[test]
fn missing_null_false_zero_empty_and_malformed_ancestors_remain_distinct() {
    let schema = json!({"properties":{"missing":{},"null":{},"false":{},"zero":{},"empty":{},"list":{},"present":{},"nested":{"properties":{"leaf":{}}}}});
    let value = projected(
        schema,
        [
            text("missing", "/missing"),
            text("null", "/null"),
            AuditInputRule::value("false", "False", "/false").kind(AuditValueKind::Boolean),
            AuditInputRule::value("zero", "Zero", "/zero").kind(AuditValueKind::Number),
            text("empty", "/empty"),
            AuditInputRule::values("list", "List", "/list").kind(AuditValueKind::Number),
            AuditInputRule::presence("present", "Present", "/present"),
            text("nested", "/nested/leaf"),
        ],
        json!({"null":null,"false":false,"zero":0,"empty":"","list":[],"present":null,"nested":7}),
    );
    let fields = value["fields"].as_array().unwrap();
    assert_eq!(fields[0]["state"], "absent");
    assert_eq!(fields[0]["supplied"], false);
    assert_eq!(fields[1]["state"], "null");
    assert_eq!(fields[1]["supplied"], true);
    assert_eq!(fields[2]["value"], false);
    assert_eq!(fields[3]["value"], 0);
    assert_eq!(fields[4]["value"], "");
    assert_eq!(fields[5]["items"], json!([]));
    assert_eq!(fields[5]["totalCount"], 0);
    assert_eq!(fields[6]["value"], true);
    assert_eq!(fields[7]["state"], "invalid");
    assert!(fields[7]["supplied"].is_null());
    assert_eq!(value["status"], "partial");
}

#[test]
fn audit_representation_ignores_patterns_ranges_conditionals_and_null_prohibition() {
    let schema = json!({"properties":{"text":{"type":"string","enum":["allowed"],"pattern":"^allowed$","maxLength":1},"number":{"type":"integer","minimum":100},"nullable":{"type":"string"}},"if":{"properties":{"number":{"const":1}}},"then":{"properties":{"text":{"const":"different"}}}});
    let snapshot = projected(
        schema,
        [
            text("text", "/text"),
            AuditInputRule::value("number", "Number", "/number").kind(AuditValueKind::Number),
            text("nullable", "/nullable"),
        ],
        json!({"text":"requested business text","number":0.25,"nullable":null}),
    );
    assert_eq!(snapshot["status"], "complete");
    assert_eq!(snapshot["fields"][0]["value"], "requested business text");
    assert_eq!(snapshot["fields"][1]["value"], 0.25);
    assert_eq!(snapshot["fields"][2]["state"], "null");
}

#[test]
fn typed_shapes_reject_coercions_and_keep_independently_valid_fields() {
    let snapshot = projected(
        json!({"properties":{"text":{},"number":{},"boolean":{},"bytes":{},"list":{},"good":{}}}),
        [
            text("text", "/text"),
            AuditInputRule::value("number", "Number", "/number").kind(AuditValueKind::Number),
            AuditInputRule::value("boolean", "Boolean", "/boolean").kind(AuditValueKind::Boolean),
            AuditInputRule::value("bytes", "Bytes", "/bytes").kind(AuditValueKind::Bytes),
            AuditInputRule::values("list", "List", "/list").kind(AuditValueKind::Number),
            text("good", "/good"),
        ],
        json!({"text":{"canary":"private"},"number":"42","boolean":0,"bytes":-1,"list":{},"good":"retained"}),
    );
    for field in &snapshot["fields"].as_array().unwrap()[..5] {
        assert_eq!(field["state"], "invalid");
        assert!(field.get("value").is_none());
    }
    assert_eq!(snapshot["fields"][5]["value"], "retained");
    assert!(!snapshot.to_string().contains("canary"));
}

#[test]
fn exact_escaped_and_numeric_named_properties_never_index_arrays() {
    let schema = json!({"properties":{"a/b":{"properties":{"~":{"properties":{"123":{"properties":{"*":{}}}}}}}}});
    let rule = text("literal", "/a~1b/~0/123/*");
    let good = projected(
        schema.clone(),
        [rule.clone()],
        json!({"a/b":{"~":{"123":{"*":"literal"}}}}),
    );
    assert_eq!(good["fields"][0]["value"], "literal");
    let invalid = projected(schema, [rule], json!({"a/b":{"~":[{"*":"canary"}]}}));
    assert_eq!(invalid["fields"][0]["state"], "invalid");
    assert!(invalid["fields"][0]["supplied"].is_null());
}

#[test]
fn utf8_caps_clip_only_text_and_do_not_copy_overlong_identities() {
    for (input, expected, original) in
        [("é", "é", None), ("éé", "éé", None), ("ééé", "éé", Some(6))]
    {
        let snapshot = projected(
            json!({"properties":{"text":{},"id":{}}}),
            [
                text("text", "/text").max_bytes(5),
                identity("id", "/id").max_bytes(5),
            ],
            json!({"text":input,"id":input}),
        );
        assert_eq!(snapshot["fields"][0]["value"], expected);
        if let Some(original) = original {
            assert_eq!(snapshot["fields"][0]["originalBytes"], original);
            assert_eq!(snapshot["fields"][0]["truncated"], true);
            assert_eq!(snapshot["fields"][1]["state"], "tooLarge");
            assert!(snapshot["fields"][1].get("originalBytes").is_none());
        } else {
            assert!(snapshot["fields"][0].get("truncated").is_none());
        }
    }
    let huge = projected(
        json!({"properties":{"text":{}}}),
        [text("text", "/text").max_bytes(4)],
        json!({"text":"a".repeat(1_000_000)}),
    );
    assert_eq!(huge["fields"][0]["value"], "aaaa");
    assert_eq!(huge["fields"][0]["originalBytes"], 1_000_000);
}

#[test]
fn integer_encoding_is_lossless_at_safe_boundaries_and_i64_u64_extremes() {
    let schema = json!({"properties":{"id":{},"number":{},"bytes":{}}});
    for (value, encoded) in [
        (json!(-9_007_199_254_740_991_i64), None),
        (json!(9_007_199_254_740_991_u64), None),
        (json!(-9_007_199_254_740_992_i64), Some("-9007199254740992")),
        (json!(9_007_199_254_740_992_u64), Some("9007199254740992")),
        (json!(i64::MIN), Some("-9223372036854775808")),
        (json!(u64::MAX), Some("18446744073709551615")),
    ] {
        let snapshot = projected(
            schema.clone(),
            [
                identity("id", "/id").max_bytes(1),
                AuditInputRule::value("number", "Number", "/number").kind(AuditValueKind::Number),
            ],
            json!({"id":value,"number":value}),
        );
        for field in snapshot["fields"].as_array().unwrap() {
            assert_eq!(field["state"], "captured");
            if let Some(encoded) = encoded {
                assert_eq!(field["value"], encoded);
                assert_eq!(field["encoding"], "decimalInteger");
            } else {
                assert_eq!(field["value"], value);
                assert!(field.get("encoding").is_none());
            }
        }
        let decoded: RequestAudit = serde_json::from_value(snapshot.clone()).unwrap();
        assert_eq!(serde_json::to_value(decoded).unwrap(), snapshot);
    }
    for source in ["1.0", "1e20", "18446744073709551616", "-0"] {
        let number: Value = serde_json::from_str(source).unwrap();
        let snapshot = projected(
            schema.clone(),
            [
                identity("id", "/id"),
                AuditInputRule::value("number", "Number", "/number").kind(AuditValueKind::Number),
            ],
            json!({"id":number,"number":number}),
        );
        assert_eq!(snapshot["fields"][0]["state"], "invalid", "{source}");
        assert_eq!(snapshot["fields"][1]["state"], "captured", "{source}");
        assert!(snapshot["fields"][1].get("encoding").is_none());
    }
    let source_string = projected(
        schema,
        [identity("id", "/id").max_bytes(1)],
        json!({"id":"99"}),
    );
    assert_eq!(source_string["fields"][0]["state"], "tooLarge");
}

#[test]
fn scalar_lists_preserve_first_twenty_positions_and_separate_invalid_and_limited_counts() {
    let inputs: Vec<_> = (0..23)
        .map(|index| match index {
            1 => Value::Null,
            2 => json!({"canary":"hidden"}),
            3 => json!(u64::MAX),
            _ => json!(index),
        })
        .collect();
    let snapshot = projected(
        json!({"properties":{"ids":{}}}),
        [AuditInputRule::values("ids", "IDs", "/ids")
            .kind(AuditValueKind::Identifier)
            .max_bytes(1)
            .overflow(AuditOverflow::Omit)],
        json!({"ids":inputs}),
    );
    let field = &snapshot["fields"][0];
    assert_eq!(field["totalCount"], 23);
    assert_eq!(field["limitedCount"], 3);
    assert_eq!(field["invalidCount"], 1);
    assert_eq!(field["budgetOmittedCount"], 0);
    assert_eq!(field["items"].as_array().unwrap().len(), 20);
    assert_eq!(field["items"][1]["state"], "null");
    assert_eq!(field["items"][2]["state"], "invalid");
    assert_eq!(field["items"][3]["encoding"], "decimalInteger");
    assert_eq!(field["items"][19]["index"], 19);
    assert!(!snapshot.to_string().contains("canary"));
}

#[test]
fn records_preserve_row_association_and_static_columns_without_opaque_siblings() {
    let schema = json!({"properties":{"rows":{"items":{"properties":{"path":{},"id":{},"body":{"x-agent-access-sensitive":true},"flags":{}}}}}});
    let projection = AuditInputRule::records(
        "rows",
        "Rows",
        "/rows",
        [
            text("path", "/path"),
            identity("id", "/id"),
            AuditInputRule::presence("body", "Body supplied", "/body"),
            AuditInputRule::values("flags", "Flags", "/flags").kind(AuditValueKind::Boolean),
        ],
    );
    let snapshot = projected(
        schema,
        [projection],
        json!({"rows":[{"path":"one","id":u64::MAX,"body":"canary_body","unknown":"canary_unknown","flags":[true,false]},null,{"path":12,"id":"two"}]}),
    );
    let field = &snapshot["fields"][0];
    assert_eq!(field["columns"].as_array().unwrap().len(), 4);
    assert_eq!(field["invalidCount"], 1);
    assert_eq!(field["rows"][0]["index"], 0);
    assert_eq!(
        field["rows"][0]["cells"]["id"]["encoding"],
        "decimalInteger"
    );
    assert_eq!(
        field["rows"][0]["cells"]["flags"]["items"][1]["value"],
        false
    );
    assert_eq!(field["rows"][1]["state"], "invalid");
    assert!(field["rows"][1].get("cells").is_none());
    assert_eq!(field["rows"][2]["cells"]["path"]["state"], "invalid");
    assert!(!snapshot.to_string().contains("canary"));
}

#[test]
fn summaries_capture_only_explicit_presence_array_count_and_utf8_length() {
    let snapshot = projected(
        json!({"properties":{"body":{},"url":{},"token":{"x-agent-access-sensitive":true},"payload":{},"omit":{},"missing":{}}}),
        [
            AuditInputRule::utf8_byte_count("body", "Body bytes", "/body"),
            AuditInputRule::presence("url", "URL supplied", "/url"),
            AuditInputRule::presence("token", "Token supplied", "/token"),
            AuditInputRule::item_count("payload", "Items", "/payload"),
            AuditInputRule::omit("omit", "/omit"),
            AuditInputRule::presence("missing", "Missing supplied", "/missing"),
        ],
        json!({"body":"é秘密","url":"https://private.example/path?secret=canary","token":"canary_token","payload":[{"canary":"secret"},2],"omit":"canary_omitted"}),
    );
    assert_eq!(snapshot["status"], "complete");
    assert_eq!(snapshot["fields"][0]["value"], 8);
    assert_eq!(snapshot["fields"][1]["value"], true);
    assert_eq!(snapshot["fields"][2]["value"], true);
    assert_eq!(snapshot["fields"][3]["value"], 2);
    assert_eq!(snapshot["fields"][4]["value"], false);
    assert!(!snapshot.to_string().contains("canary"));
    assert!(!snapshot.to_string().contains("private.example"));
    assert!(!snapshot.to_string().contains("秘密"));
}

#[test]
fn structural_checks_follow_named_composed_and_referenced_properties_only() {
    let schema = json!({"$defs":{"leaf":{"properties":{"child":{}}}},"allOf":[{"properties":{"selected":{"$ref":"#/$defs/leaf"}}}],"additionalProperties":true});
    assert!(
        prepare_audit_inputs(
            &schema,
            &AuditInputProjection::new([text("child", "/selected/child")])
        )
        .is_ok()
    );
    assert!(
        prepare_audit_inputs(
            &schema,
            &AuditInputProjection::new([text("unknown", "/unknown")])
        )
        .is_err()
    );
    assert!(
        prepare_audit_inputs(
            &json!({"patternProperties":{".*":{}}}),
            &AuditInputProjection::new([text("unknown", "/unknown")])
        )
        .is_err()
    );
}

#[test]
fn sensitivity_unions_compositions_dependencies_refs_and_property_applicators() {
    for keyword in ["allOf", "anyOf", "oneOf"] {
        let mut schema = json!({"properties":{"selected":{}}});
        schema[keyword] = json!([{"properties":{"selected":{"x-agent-access-sensitive":true}}}]);
        assert!(
            prepare_audit_inputs(
                &schema,
                &AuditInputProjection::new([text("selected", "/selected")])
            )
            .is_err(),
            "{keyword}"
        );
    }
    for keyword in ["if", "then", "else", "not"] {
        let mut schema = json!({"properties":{"selected":{}}});
        schema[keyword] = json!({"properties":{"selected":{"x-agent-access-sensitive":true}}});
        assert!(
            prepare_audit_inputs(
                &schema,
                &AuditInputProjection::new([text("selected", "/selected")])
            )
            .is_err(),
            "{keyword}"
        );
    }
    for keyword in ["dependentSchemas", "dependencies"] {
        let mut schema = json!({"properties":{"selected":{}}});
        schema[keyword] = json!({"unusedCondition":{"properties":{"selected":{"x-agent-access-sensitive":true}}}});
        assert!(
            prepare_audit_inputs(
                &schema,
                &AuditInputProjection::new([text("selected", "/selected")])
            )
            .is_err(),
            "{keyword}"
        );
    }
    for keyword in ["additionalProperties", "unevaluatedProperties"] {
        let mut schema = json!({"properties":{"selected":{}}});
        schema[keyword] = json!({"x-agent-access-sensitive":true});
        assert!(
            prepare_audit_inputs(
                &schema,
                &AuditInputProjection::new([text("selected", "/selected")])
            )
            .is_err(),
            "{keyword}"
        );
    }
    let schema = json!({"properties":{"selected":{}},"patternProperties":{"pattern-is-not-evaluated":{"x-agent-access-sensitive":true}}});
    assert!(
        prepare_audit_inputs(
            &schema,
            &AuditInputProjection::new([text("selected", "/selected")])
        )
        .is_err()
    );
    let schema = json!({"$defs":{"secret":{"x-agent-access-sensitive":true}},"properties":{"selected":{"$ref":"#/$defs/secret"}}});
    assert!(
        prepare_audit_inputs(
            &schema,
            &AuditInputProjection::new([text("selected", "/selected")])
        )
        .is_err()
    );
}

#[test]
fn refs_are_exact_local_pointers_with_bounded_expansion_and_no_guessed_scopes() {
    for reference in [
        "#named",
        "https://example.test/schema",
        "#/$defs/missing",
        "#/$defs/a~2b",
        "#/$defs/nested",
    ] {
        let schema = json!({"$defs":{"named":{"$anchor":"named"},"nested":{"$id":"other","type":"string"}},"properties":{"selected":{"$ref":reference}}});
        assert!(
            prepare_audit_inputs(
                &schema,
                &AuditInputProjection::new([text("selected", "/selected")])
            )
            .is_err(),
            "{reference}"
        );
    }
    let schema = json!({"$defs":{"a/b":{"type":"string"}},"properties":{"selected":{"$ref":"#/$defs/a~1b"}}});
    assert!(
        prepare_audit_inputs(
            &schema,
            &AuditInputProjection::new([text("selected", "/selected")])
        )
        .is_ok()
    );
    let cyclic = json!({"$defs":{"cycle":{"$ref":"#/$defs/cycle"}},"properties":{"selected":{"$ref":"#/$defs/cycle"}}});
    assert!(
        prepare_audit_inputs(
            &cyclic,
            &AuditInputProjection::new([text("selected", "/selected")])
        )
        .is_err()
    );
    for keyword in ["$dynamicRef", "$recursiveRef"] {
        let mut schema = json!({"properties":{"selected":{}}});
        schema["properties"]["selected"][keyword] = json!("#anything");
        assert!(
            prepare_audit_inputs(
                &schema,
                &AuditInputProjection::new([text("selected", "/selected")])
            )
            .is_err()
        );
        assert!(
            prepare_audit_inputs(
                &schema,
                &AuditInputProjection::new([AuditInputRule::presence(
                    "selected",
                    "Selected",
                    "/selected"
                )])
            )
            .is_ok()
        );
    }
}

#[test]
fn descendant_sensitivity_blocks_malformed_scalar_capture_without_blocking_safe_siblings() {
    let schema = json!({"properties":{"object":{"properties":{"secret":{"x-agent-access-sensitive":true},"safe":{}}}}});
    assert!(
        prepare_audit_inputs(
            &schema,
            &AuditInputProjection::new([text("object", "/object")])
        )
        .is_err()
    );
    assert!(
        prepare_audit_inputs(
            &schema,
            &AuditInputProjection::new([AuditInputRule::utf8_byte_count(
                "object", "Bytes", "/object"
            )])
        )
        .is_err()
    );
    assert!(
        prepare_audit_inputs(
            &schema,
            &AuditInputProjection::new([text("safe", "/object/safe")])
        )
        .is_ok()
    );
    assert!(
        prepare_audit_inputs(
            &schema,
            &AuditInputProjection::new([AuditInputRule::presence(
                "object",
                "Object supplied",
                "/object"
            )])
        )
        .is_ok()
    );
}

#[test]
fn arrays_union_all_item_dialects_but_counts_ignore_sensitive_child_siblings() {
    for keyword in [
        "items",
        "prefixItems",
        "additionalItems",
        "unevaluatedItems",
        "contains",
    ] {
        let mut schema = json!({"properties":{"array":{}}});
        schema["properties"]["array"][keyword] = if keyword == "prefixItems" {
            json!([{"x-agent-access-sensitive":true}])
        } else {
            json!({"x-agent-access-sensitive":true})
        };
        assert!(
            prepare_audit_inputs(
                &schema,
                &AuditInputProjection::new([AuditInputRule::item_count(
                    "array", "Count", "/array"
                )])
            )
            .is_err(),
            "{keyword}"
        );
    }
    let tuple = json!({"properties":{"array":{"items":[{}, {"x-agent-access-sensitive":true}]}}});
    assert!(
        prepare_audit_inputs(
            &tuple,
            &AuditInputProjection::new([AuditInputRule::item_count("array", "Count", "/array")])
        )
        .is_err()
    );
    let safe = json!({"properties":{"array":{"items":{"properties":{"secret":{"x-agent-access-sensitive":true},"safe":{}}}}}});
    assert!(
        prepare_audit_inputs(
            &safe,
            &AuditInputProjection::new([AuditInputRule::item_count("array", "Count", "/array")])
        )
        .is_ok()
    );
    assert!(
        prepare_audit_inputs(
            &safe,
            &AuditInputProjection::new([AuditInputRule::records(
                "array",
                "Rows",
                "/array",
                [text("safe", "/safe")]
            )])
        )
        .is_ok()
    );
    let unsafe_items = json!({"properties":{"array":{"items":{"x-agent-access-sensitive":true,"properties":{"safe":{}}}}}});
    assert!(
        prepare_audit_inputs(
            &unsafe_items,
            &AuditInputProjection::new([AuditInputRule::records(
                "array",
                "Rows",
                "/array",
                [text("safe", "/safe")]
            )])
        )
        .is_err()
    );
}

#[test]
fn property_names_are_not_values_and_content_schema_uses_exact_selected_boundary() {
    let names =
        json!({"properties":{"selected":{"propertyNames":{"x-agent-access-sensitive":true}}}});
    assert!(
        prepare_audit_inputs(
            &names,
            &AuditInputProjection::new([text("selected", "/selected")])
        )
        .is_ok()
    );
    assert!(
        prepare_audit_inputs(
            &names,
            &AuditInputProjection::new([AuditInputRule::item_count(
                "selected",
                "Count",
                "/selected"
            )])
        )
        .is_ok()
    );
    let schema = json!({"properties":{"parent":{"contentSchema":{},"properties":{"safe":{},"opaque":{"contentSchema":{}}}}}});
    assert!(
        prepare_audit_inputs(
            &schema,
            &AuditInputProjection::new([text("safe", "/parent/safe")])
        )
        .is_ok()
    );
    assert!(
        prepare_audit_inputs(
            &schema,
            &AuditInputProjection::new([text("parent", "/parent")])
        )
        .is_err()
    );
    assert!(
        prepare_audit_inputs(
            &schema,
            &AuditInputProjection::new([AuditInputRule::utf8_byte_count(
                "parent", "Bytes", "/parent"
            )])
        )
        .is_err()
    );
    assert!(
        prepare_audit_inputs(
            &schema,
            &AuditInputProjection::new([AuditInputRule::item_count(
                "opaque",
                "Count",
                "/parent/opaque"
            )])
        )
        .is_err()
    );
    assert!(
        prepare_audit_inputs(
            &schema,
            &AuditInputProjection::new([AuditInputRule::presence(
                "opaque",
                "Opaque supplied",
                "/parent/opaque"
            )])
        )
        .is_ok()
    );
}

#[test]
fn root_header_heuristic_is_exact_and_does_not_generalize_nested_headers() {
    let schema = json!({"properties":{"headers":{"properties":{"Authorization":{},"X-Plain":{}}},"nested":{"properties":{"headers":{"properties":{"Authorization":{}}}}}}});
    assert!(
        prepare_audit_inputs(
            &schema,
            &AuditInputProjection::new([text("secret", "/headers/Authorization")])
        )
        .is_err()
    );
    assert!(
        prepare_audit_inputs(
            &schema,
            &AuditInputProjection::new([text("plain", "/headers/X-Plain")])
        )
        .is_ok()
    );
    assert!(
        prepare_audit_inputs(
            &schema,
            &AuditInputProjection::new([text("nested", "/nested/headers/Authorization")])
        )
        .is_ok()
    );
    assert!(
        prepare_audit_inputs(
            &schema,
            &AuditInputProjection::new([text("headers", "/headers")])
        )
        .is_err()
    );
}

fn root_header_schema_variants(headers: Value) -> Vec<(String, Value)> {
    let root = json!({"properties":{"headers":headers}});
    let mut variants = vec![
        (
            "header reference".into(),
            json!({"$defs":{"headers":headers},"properties":{"headers":{"$ref":"#/$defs/headers"}}}),
        ),
        (
            "root reference".into(),
            json!({"$defs":{"input":root},"$ref":"#/$defs/input"}),
        ),
    ];
    for keyword in ["allOf", "anyOf", "oneOf"] {
        variants.push((
            format!("header {keyword}"),
            json!({"properties":{"headers":{keyword:[headers]}}}),
        ));
        variants.push((format!("root {keyword}"), json!({keyword:[root]})));
    }
    for keyword in ["if", "then", "else", "not"] {
        variants.push((
            format!("header {keyword}"),
            json!({"properties":{"headers":{keyword:headers}}}),
        ));
    }
    for keyword in ["dependentSchemas", "dependencies"] {
        variants.push((
            format!("header {keyword}"),
            json!({"properties":{"headers":{keyword:{"condition":headers}}}}),
        ));
    }
    variants
}

#[test]
fn root_header_sensitivity_follows_instance_paths_through_refs_and_compositions() {
    let headers = json!({"properties":{"Authorization":{"properties":{"nested":{}}},"X-Plain":{}}});
    for (name, schema) in root_header_schema_variants(headers) {
        for pointer in ["/headers/Authorization", "/headers/Authorization/nested"] {
            for rule in [
                text("secret", pointer),
                AuditInputRule::utf8_byte_count("secret", "Secret bytes", pointer),
                AuditInputRule::item_count("secret", "Secret count", pointer),
            ] {
                let error =
                    prepare_audit_inputs(&schema, &AuditInputProjection::new([rule])).unwrap_err();
                assert!(error.contains("sensitive root header"), "{name}: {error}");
            }
            for rule in [
                AuditInputRule::presence("secret", "Secret supplied", pointer),
                AuditInputRule::omit("secret", pointer),
            ] {
                assert!(
                    prepare_audit_inputs(&schema, &AuditInputProjection::new([rule])).is_ok(),
                    "{name}: {pointer}"
                );
            }
        }
        let snapshot = projected(
            schema,
            [text("plain", "/headers/X-Plain")],
            json!({"headers":{"X-Plain":"retained","Authorization":"private"}}),
        );
        assert_eq!(snapshot["fields"][0]["value"], "retained", "{name}");
    }
}

#[test]
fn expanded_root_headers_reject_malformed_scalar_value_and_byte_count_capture() {
    for (name, schema) in
        root_header_schema_variants(json!({"properties":{"Authorization":{},"X-Plain":{}}}))
    {
        for rule in [
            text("headers", "/headers"),
            AuditInputRule::utf8_byte_count("headers", "Header bytes", "/headers"),
        ] {
            let error =
                prepare_audit_inputs(&schema, &AuditInputProjection::new([rule])).unwrap_err();
            assert!(error.contains("sensitive root header"), "{name}: {error}");
        }
        let snapshot = projected(
            schema,
            [AuditInputRule::presence(
                "headers",
                "Headers supplied",
                "/headers",
            )],
            json!({"headers":"malformed_private_header_scalar"}),
        );
        assert_eq!(snapshot["fields"][0]["value"], true, "{name}");
        assert!(
            !snapshot
                .to_string()
                .contains("malformed_private_header_scalar")
        );
    }
}

#[test]
fn records_preserve_root_header_sensitivity_without_generalizing_item_paths() {
    let headers = json!({"properties":{"Authorization":{"items":{"properties":{"safe":{}}}}}});
    for (name, schema) in root_header_schema_variants(headers) {
        let rule = AuditInputRule::records(
            "headers",
            "Header records",
            "/headers/Authorization",
            [text("safe", "/safe")],
        );
        let error = prepare_audit_inputs(&schema, &AuditInputProjection::new([rule])).unwrap_err();
        assert!(error.contains("sensitive root header"), "{name}: {error}");
    }
    let schema = json!({"$defs":{"headers":{"allOf":[{"properties":{"Authorization":{}}}]}},"properties":{"nested":{"properties":{"headers":{"$ref":"#/$defs/headers"}}},"rows":{"items":{"properties":{"headers":{"$ref":"#/$defs/headers"}}}},"headers":{"properties":{"Authorization":{}},"items":{"properties":{"safe":{}}}}}});
    let snapshot = projected(
        schema,
        [
            text("nested", "/nested/headers/Authorization"),
            AuditInputRule::records(
                "rows",
                "Rows",
                "/rows",
                [text("row_header", "/headers/Authorization")],
            ),
            AuditInputRule::records(
                "headers",
                "Rows at headers",
                "/headers",
                [text("safe", "/safe")],
            ),
        ],
        json!({"nested":{"headers":{"Authorization":"nested field"}},"rows":[{"headers":{"Authorization":"row field"}}],"headers":[{"safe":"safe field"}]}),
    );
    assert_eq!(snapshot["fields"][0]["value"], "nested field");
    assert_eq!(
        snapshot["fields"][1]["rows"][0]["cells"]["row_header"]["value"],
        "row field"
    );
    assert_eq!(
        snapshot["fields"][2]["rows"][0]["cells"]["safe"]["value"],
        "safe field"
    );
}

#[test]
fn digest_is_canonical_but_rules_array_order_and_schema_contract_change_it() {
    let a = prepare_audit_inputs(
        &json!({"properties":{"a":{},"b":{}}}),
        &AuditInputProjection::new([text("a", "/a"), text("b", "/b")]),
    )
    .unwrap();
    let b = prepare_audit_inputs(
        &serde_json::from_str("{\"properties\":{\"b\":{},\"a\":{}}}").unwrap(),
        &AuditInputProjection::new([text("a", "/a"), text("b", "/b")]),
    )
    .unwrap();
    assert_eq!(a.declaration_sha256(), b.declaration_sha256());
    assert_eq!(a.declaration_sha256().len(), 64);
    let reordered = prepare_audit_inputs(
        &json!({"properties":{"a":{},"b":{}}}),
        &AuditInputProjection::new([text("b", "/b"), text("a", "/a")]),
    )
    .unwrap();
    assert_ne!(a.declaration_sha256(), reordered.declaration_sha256());
    let changed = prepare_audit_inputs(
        &json!({"properties":{"a":{"description":"changed"},"b":{}}}),
        &AuditInputProjection::new([text("a", "/a"), text("b", "/b")]),
    )
    .unwrap();
    assert_ne!(a.declaration_sha256(), changed.declaration_sha256());
}

#[test]
fn limits_enforce_rule_count_metadata_pointer_and_string_cap_boundaries() {
    for count in [63, 64, 65] {
        let schema = json!({"properties": (0..count).map(|index| (format!("f{index}"),json!({}))).collect::<serde_json::Map<_,_>>()});
        let projection = AuditInputProjection::new((0..count).map(|index| {
            AuditInputRule::presence(format!("f{index}"), "Supplied", format!("/f{index}"))
        }));
        assert_eq!(
            prepare_audit_inputs(&schema, &projection).is_ok(),
            count <= 64,
            "{count}"
        );
    }
    for len in [63, 64, 65] {
        let projection =
            AuditInputProjection::new([AuditInputRule::presence("k".repeat(len), "Label", "/x")]);
        assert_eq!(
            prepare_audit_inputs(&json!({"properties":{"x":{}}}), &projection).is_ok(),
            len <= 64
        );
    }
    for len in [79, 80, 81] {
        let projection =
            AuditInputProjection::new([AuditInputRule::presence("k", "L".repeat(len), "/x")]);
        assert_eq!(
            prepare_audit_inputs(&json!({"properties":{"x":{}}}), &projection).is_ok(),
            len <= 80
        );
    }
    for len in [1023, 1024, 1025] {
        let name = "x".repeat(len - 1);
        let schema = json!({"properties":{name.clone():{}}});
        assert_eq!(
            prepare_audit_inputs(
                &schema,
                &AuditInputProjection::new([text("field", &format!("/{name}"))])
            )
            .is_ok(),
            len <= 1024
        );
    }
    for cap in [0, 1, 4095, 4096, 4097] {
        assert_eq!(
            prepare_audit_inputs(
                &json!({"properties":{"x":{}}}),
                &AuditInputProjection::new([text("x", "/x").max_bytes(cap)])
            )
            .is_ok(),
            (1..=4096).contains(&cap)
        );
    }
}

#[test]
fn traversal_budgets_fail_closed_at_reference_and_schema_node_boundaries() {
    for count in [63, 64, 65] {
        let mut definitions = serde_json::Map::new();
        for index in 0..count {
            definitions.insert(
                format!("d{index}"),
                if index + 1 == count {
                    json!({})
                } else {
                    json!({"$ref":format!("#/$defs/d{}",index+1)})
                },
            );
        }
        let schema = json!({"$defs":definitions,"properties":{"selected":{"$ref":"#/$defs/d0"}}});
        assert_eq!(
            prepare_audit_inputs(
                &schema,
                &AuditInputProjection::new([text("selected", "/selected")])
            )
            .is_ok(),
            count <= 64,
            "refs {count}"
        );
    }
    for branches in [4093, 4094, 4095] {
        let schema = json!({"properties":{"selected":{"allOf":vec![json!({});branches]}}});
        assert_eq!(
            prepare_audit_inputs(
                &schema,
                &AuditInputProjection::new([text("selected", "/selected")])
            )
            .is_ok(),
            branches <= 4094,
            "nodes {}",
            branches + 2
        );
    }
}

#[test]
fn known_absent_placeholders_never_displace_supplied_values_or_make_status_partial() {
    let mut properties = serde_json::Map::new();
    let mut rules = Vec::new();
    let mut inputs = serde_json::Map::new();
    for index in 0..64 {
        let name = format!("f{index}");
        properties.insert(name.clone(), json!({}));
        let key = format!("{name}{}", "k".repeat(64 - name.len()));
        rules.push(
            AuditInputRule::value(key, "L".repeat(80), format!("/{name}"))
                .kind(AuditValueKind::Text)
                .max_bytes(4096)
                .overflow(AuditOverflow::Prefix),
        );
        if index >= 61 {
            inputs.insert(name, json!("x".repeat(4096)));
        }
    }
    let snapshot = projected(
        json!({"properties":properties}),
        rules,
        Value::Object(inputs),
    );
    assert_eq!(snapshot["status"], "complete");
    assert_eq!(snapshot["budgetOmittedFields"], 0);
    assert!(snapshot["absentOmittedFields"].as_u64().unwrap() > 0);
    for index in 61..64 {
        assert!(snapshot["fields"].as_array().unwrap().iter().any(|field| {
            field["key"]
                .as_str()
                .unwrap()
                .starts_with(&format!("f{index}k"))
                && field["value"] == "x".repeat(4096)
        }));
    }
    assert!(serde_json::to_vec(&snapshot).unwrap().len() <= 16_384);
}

#[test]
fn budget_priority_is_presence_then_tier_but_output_stays_declaration_order() {
    let names = [
        ("raw", AuditDisplay::Raw),
        ("detail", AuditDisplay::Detail),
        ("primaryOne", AuditDisplay::Primary),
        ("primaryTwo", AuditDisplay::Primary),
        ("detailLater", AuditDisplay::Detail),
    ];
    let properties = names
        .iter()
        .map(|(name, _)| (name.to_string(), json!({})))
        .collect::<serde_json::Map<_, _>>();
    let inputs = names
        .iter()
        .map(|(name, _)| (name.to_string(), json!("x".repeat(4096))))
        .collect::<serde_json::Map<_, _>>();
    let rules = names.iter().map(|(name, display)| {
        text(name, &format!("/{name}"))
            .max_bytes(4096)
            .display(*display)
    });
    let snapshot = projected(
        json!({"properties":properties}),
        rules,
        Value::Object(inputs),
    );
    let fields = snapshot["fields"].as_array().unwrap();
    assert_eq!(
        fields
            .iter()
            .map(|field| field["key"].as_str().unwrap())
            .collect::<Vec<_>>(),
        names.iter().map(|(name, _)| *name).collect::<Vec<_>>()
    );
    for index in [1, 2, 3] {
        assert_eq!(fields[index]["state"], "captured");
    }
    for index in [0, 4] {
        assert_eq!(fields[index]["state"], "budget");
        assert_eq!(fields[index]["supplied"], true);
    }
    assert_eq!(snapshot["status"], "partial");
}

#[test]
fn json_escape_overhead_is_budgeted_before_copy_and_later_fields_still_fit() {
    let snapshot = projected(
        json!({"properties":{"escaped":{},"later":{}}}),
        [
            text("escaped", "/escaped").max_bytes(4096),
            text("later", "/later"),
        ],
        json!({"escaped":"\0".repeat(4096),"later":"retained"}),
    );
    assert_eq!(snapshot["fields"][0]["state"], "budget");
    assert!(snapshot["fields"][0].get("value").is_none());
    assert_eq!(snapshot["fields"][1]["value"], "retained");
    assert!(serde_json::to_vec(&snapshot).unwrap().len() <= 16_384);
    let plan = prepare_audit_inputs(
        &json!({"properties":{"escaped":{}}}),
        &AuditInputProjection::new([text("escaped", "/escaped").max_bytes(4096)]),
    )
    .unwrap();
    let input = json!({"escaped":"\n\\\"é".repeat(2000)});
    assert_eq!(plan.project(&input), plan.project(&input));
}

#[test]
fn budgeted_samples_keep_original_indices_and_do_not_fill_from_suffix() {
    let mut inputs = vec![json!("x".repeat(4096)); 21];
    inputs[5] = json!("small");
    inputs[20] = json!("suffix-canary");
    let snapshot = projected(
        json!({"properties":{"values":{}}}),
        [AuditInputRule::values("values", "Values", "/values")
            .kind(AuditValueKind::Text)
            .max_bytes(4096)
            .overflow(AuditOverflow::Prefix)],
        json!({"values":inputs}),
    );
    let field = &snapshot["fields"][0];
    let items = field["items"].as_array().unwrap();
    assert!(
        items
            .iter()
            .any(|item| item["index"] == 5 && item["value"] == "small")
    );
    assert!(!items.iter().any(|item| item["index"] == 20));
    assert!(field["budgetOmittedCount"].as_u64().unwrap() > 0);
    assert_eq!(field["limitedCount"], 1);
    assert_eq!(
        field["totalCount"].as_u64().unwrap(),
        items.len() as u64
            + field["limitedCount"].as_u64().unwrap()
            + field["budgetOmittedCount"].as_u64().unwrap()
    );
    assert!(!snapshot.to_string().contains("suffix-canary"));
}

#[test]
fn atomic_rows_stop_at_first_unfittable_cell_and_later_positions_remain_eligible() {
    let schema = json!({"properties":{"rows":{"items":{"properties":{"first":{},"later":{}}}}}});
    let rule = AuditInputRule::records(
        "rows",
        "Rows",
        "/rows",
        [
            text("first", "/first").max_bytes(4096),
            text("later", "/later").max_bytes(4096),
        ],
    );
    let plan = prepare_audit_inputs(&schema, &AuditInputProjection::new([rule])).unwrap();
    project::reset_cells_visited();
    let snapshot=serde_json::to_value(plan.project(&json!({"rows":[{"first":"\0".repeat(4096),"later":"never-inspected"},{"first":"small","later":"retained"}]})).unwrap()).unwrap();
    assert_eq!(
        project::cells_visited(),
        3,
        "first row must stop after its first cell"
    );
    let field = &snapshot["fields"][0];
    assert_eq!(field["budgetOmittedCount"], 1);
    assert_eq!(field["rows"].as_array().unwrap().len(), 1);
    assert_eq!(field["rows"][0]["index"], 1);
    assert_eq!(field["rows"][0]["cells"]["later"]["value"], "retained");
    assert!(!snapshot.to_string().contains("never-inspected"));
}

#[test]
fn literal_id_names_in_definition_and_property_maps_do_not_create_resource_scopes() {
    let schema = json!({"$defs":{"$id":{},"safe":{"properties":{"$id":{},"leaf":{}}}},"properties":{"selected":{"$ref":"#/$defs/safe/properties/leaf"}}});
    assert!(
        prepare_audit_inputs(
            &schema,
            &AuditInputProjection::new([text("selected", "/selected")])
        )
        .is_ok()
    );
}

#[test]
fn percent_encoded_reference_fragments_cannot_select_a_different_literal_definition() {
    let schema = json!({"$defs":{"secret":{"x-agent-access-sensitive":true},"%73ecret":{}},"properties":{"selected":{"$ref":"#/$defs/%73ecret"}}});
    assert!(
        prepare_audit_inputs(
            &schema,
            &AuditInputProjection::new([text("selected", "/selected")])
        )
        .is_err()
    );
}
