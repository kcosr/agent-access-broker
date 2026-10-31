use super::*;
use serde_json::json;
use std::collections::BTreeMap;

const SECRET: &str = "secret-value-123";

fn denial() -> ProviderError {
    ProviderError::deny(
        ReasonCode::InputInvalid,
        "demo.item.list inputs are invalid",
    )
}

/// The message `explain` gives `inputs` under `schema`.
fn message(schema: Value, inputs: Value) -> String {
    explain("demo", "item.list", &schema, &inputs, denial()).message
}

fn list_schema() -> Value {
    json!({
        "type": "object",
        "oneOf": [{ "required": ["issue"] }, { "required": ["url"] }],
        "properties": {
            "issue": { "type": "string" },
            "url": { "type": "string" },
            "maxResults": { "type": "integer", "minimum": 1, "maximum": 100 },
            "startAt": { "type": "integer", "minimum": 0 },
            "orderBy": { "type": "string", "enum": ["created", "-created", "+created"] }
        },
        "additionalProperties": false
    })
}

const LIST_ALLOWED: &str = "allowed: issue, maxResults, orderBy, startAt, url";

#[test]
fn unknown_identifier_property_is_named_with_the_allowed_properties() {
    assert_eq!(
        message(
            list_schema(),
            json!({"issue": "DEMO-1", "readContentFormat": "markdown"})
        ),
        format!(
            "demo.item.list inputs are invalid: inputs.readContentFormat is not allowed; {LIST_ALLOWED}"
        )
    );
    assert_eq!(
        message(
            list_schema(),
            json!({"issue": "DEMO-1", "alpha": 1, "beta": 2})
        ),
        format!(
            "demo.item.list inputs are invalid: inputs.alpha and inputs.beta are not allowed; {LIST_ALLOWED}"
        )
    );
}

#[test]
fn unknown_property_that_is_not_an_identifier_is_not_echoed() {
    let explained = message(list_schema(), json!({"issue": "DEMO-1", SECRET: true}));
    assert_eq!(
        explained,
        format!(
            "demo.item.list inputs are invalid: an unexpected property in inputs is not allowed; {LIST_ALLOWED}"
        )
    );
    let explained = message(
        list_schema(),
        json!({"issue": "DEMO-1", SECRET: true, "x-y": 1, "extra": 2}),
    );
    assert_eq!(
        explained,
        format!(
            "demo.item.list inputs are invalid: inputs.extra and 2 other unexpected properties are not allowed; {LIST_ALLOWED}"
        )
    );
    let explained = message(
        list_schema(),
        json!({"issue": "DEMO-1", "a-b": 1, "c d": 2}),
    );
    assert!(explained.contains("2 unexpected properties in inputs are not allowed"));
    assert!(!explained.contains("a-b") && !explained.contains("c d"));
    // A name longer than an identifier allows is not echoed either.
    let long = format!("a{}", "b".repeat(64));
    let explained = message(list_schema(), json!({"issue": "DEMO-1", long.clone(): 1}));
    assert!(explained.contains("an unexpected property in inputs is not allowed"));
    assert!(!explained.contains(&long));
}

#[test]
fn an_object_without_declared_properties_allows_none() {
    let schema = json!({"type": "object", "additionalProperties": false});
    assert_eq!(
        message(schema.clone(), json!({"extra": 1})),
        "demo.item.list inputs are invalid: inputs.extra is not allowed; allowed: none"
    );
    assert_eq!(
        message(schema, json!({"extra": 1, SECRET: 2})),
        "demo.item.list inputs are invalid: inputs.extra and 1 other unexpected property are not allowed; allowed: none"
    );
    // Pattern properties cannot be listed, so no list is given.
    let schema = json!({
        "type": "object",
        "properties": {"name": {"type": "string"}},
        "patternProperties": {"^x_": {"type": "string"}},
        "additionalProperties": false
    });
    assert_eq!(
        message(schema, json!({"extra": 1})),
        "demo.item.list inputs are invalid: inputs.extra is not allowed"
    );
}

#[test]
fn missing_required_properties_are_named_at_their_path() {
    let schema = json!({
        "type": "object",
        "required": ["query"],
        "properties": {
            "query": {
                "type": "object",
                "required": ["type", "value"],
                "properties": {
                    "type": { "type": "string", "enum": ["cql", "text"] },
                    "value": { "type": "string" }
                },
                "additionalProperties": false
            }
        },
        "additionalProperties": false
    });
    assert_eq!(
        message(schema.clone(), json!({"query": {"value": "title"}})),
        "demo.item.list inputs are invalid: inputs.query.type is required"
    );
    assert_eq!(
        message(schema, json!({})),
        "demo.item.list inputs are invalid: inputs.query is required"
    );
}

#[test]
fn type_mismatches_name_the_expected_types() {
    assert_eq!(
        message(
            list_schema(),
            json!({"issue": "DEMO-1", "maxResults": SECRET})
        ),
        "demo.item.list inputs are invalid: inputs.maxResults must be an integer"
    );
    let schema = json!({
        "type": "object",
        "properties": {"due": {"type": ["string", "null"]}, "tags": {"type": "array"}}
    });
    assert_eq!(
        message(schema.clone(), json!({"due": 5})),
        "demo.item.list inputs are invalid: inputs.due must be a string or null"
    );
    assert_eq!(
        message(schema, json!({"tags": {"secret": SECRET}})),
        "demo.item.list inputs are invalid: inputs.tags must be an array"
    );
    assert_eq!(
        message(json!({"type": "object"}), json!(SECRET)),
        "demo.item.list inputs are invalid: inputs must be an object"
    );
}

#[test]
fn enum_and_const_failures_list_schema_values_only() {
    assert_eq!(
        message(list_schema(), json!({"issue": "DEMO-1", "orderBy": SECRET})),
        "demo.item.list inputs are invalid: inputs.orderBy must be one of: created, -created, +created"
    );
    let schema = json!({
        "type": "object",
        "properties": {
            "mode": {"const": "exact"},
            "level": {"enum": [1, 2, "high water", null]},
            "shape": {"const": {"kind": "a".repeat(80)}}
        }
    });
    assert_eq!(
        message(schema.clone(), json!({"mode": SECRET})),
        "demo.item.list inputs are invalid: inputs.mode must be exact"
    );
    assert_eq!(
        message(schema.clone(), json!({"level": SECRET})),
        "demo.item.list inputs are invalid: inputs.level must be one of: 1, 2, \"high water\", null"
    );
    assert_eq!(
        message(schema, json!({"shape": SECRET})),
        "demo.item.list inputs are invalid: inputs.shape must be the documented constant; see the action's input schema"
    );
    let many: Vec<String> = (0..15).map(|index| format!("v{index}")).collect();
    let explained = message(
        json!({"type": "object", "properties": {"pick": {"enum": many}}}),
        json!({"pick": SECRET}),
    );
    assert!(explained.ends_with("v10, v11, and 3 more"), "{explained}");
}

#[test]
fn bounds_state_the_schema_limit_not_the_value() {
    let schema = json!({
        "type": "object",
        "properties": {
            "count": {"type": "integer", "minimum": 1, "maximum": 100},
            "ratio": {"type": "number", "exclusiveMinimum": 0, "exclusiveMaximum": 1, "multipleOf": 0.5},
            "title": {"type": "string", "minLength": 1, "maxLength": 8},
            "key": {"type": "string", "pattern": "^[A-Z]+$"},
            "labels": {"type": "array", "minItems": 1, "maxItems": 2, "uniqueItems": true},
            "fields": {"type": "object", "minProperties": 1, "maxProperties": 1}
        }
    });
    let cases = [
        (json!({"count": 0}), "inputs.count must be at least 1"),
        (json!({"count": 1000}), "inputs.count must be at most 100"),
        (json!({"ratio": 0}), "inputs.ratio must be greater than 0"),
        (json!({"ratio": 1}), "inputs.ratio must be less than 1"),
        (
            json!({"ratio": 0.3}),
            "inputs.ratio must be a multiple of 0.5",
        ),
        (
            json!({"title": ""}),
            "inputs.title must be at least 1 character long",
        ),
        (
            json!({"title": SECRET}),
            "inputs.title must be at most 8 characters long",
        ),
        (
            json!({"key": SECRET}),
            "inputs.key does not match the required format",
        ),
        (
            json!({"labels": []}),
            "inputs.labels must contain at least 1 item",
        ),
        (
            json!({"labels": ["a", "b", "c"]}),
            "inputs.labels must contain at most 2 items",
        ),
        (
            json!({"labels": [SECRET, SECRET]}),
            "inputs.labels must not contain duplicate items",
        ),
        (
            json!({"fields": {}}),
            "inputs.fields must contain at least 1 property",
        ),
        (
            json!({"fields": {"a": 1, "b": 2}}),
            "inputs.fields must contain at most 1 property",
        ),
    ];
    for (inputs, expected) in cases {
        assert_eq!(
            message(schema.clone(), inputs),
            format!("demo.item.list inputs are invalid: {expected}")
        );
    }
}

#[test]
fn formats_name_the_schema_format() {
    // Draft 7 validates formats by default.
    let schema = json!({
        "$schema": "http://json-schema.org/draft-07/schema#",
        "type": "object",
        "properties": {"since": {"type": "string", "format": "date"}}
    });
    assert_eq!(
        message(schema, json!({"since": SECRET})),
        "demo.item.list inputs are invalid: inputs.since must be a valid date"
    );
}

#[test]
fn one_of_locator_forms_are_named() {
    assert_eq!(
        message(list_schema(), json!({})),
        "demo.item.list inputs are invalid: inputs must include issue or url"
    );
    assert_eq!(
        message(list_schema(), json!({"issue": "DEMO-1", "url": SECRET})),
        "demo.item.list inputs are invalid: inputs must include only one of: issue, url"
    );
    let schema = json!({
        "type": "object",
        "anyOf": [{"required": ["summary"]}, {"required": ["content", "contentFormat"]}]
    });
    assert_eq!(
        message(schema, json!({})),
        "demo.item.list inputs are invalid: inputs must include summary or both content and contentFormat"
    );
}

#[test]
fn one_of_reports_the_form_whose_discriminator_matches() {
    let schema = json!({
        "type": "object",
        "required": ["query"],
        "properties": {
            "query": {
                "oneOf": [
                    {
                        "type": "object",
                        "required": ["type", "value"],
                        "properties": {"type": {"const": "cql"}, "value": {"type": "string"}},
                        "additionalProperties": false
                    },
                    {
                        "type": "object",
                        "required": ["type", "terms"],
                        "properties": {"type": {"const": "text"}, "terms": {"type": "array"}},
                        "additionalProperties": false
                    }
                ]
            }
        }
    });
    assert_eq!(
        message(schema.clone(), json!({"query": {"type": "text"}})),
        "demo.item.list inputs are invalid: inputs.query.terms is required"
    );
    assert_eq!(
        message(
            schema.clone(),
            json!({"query": {"type": "cql", "value": 7}})
        ),
        "demo.item.list inputs are invalid: inputs.query.value must be a string"
    );
    // Without a discriminator, every form's missing properties are named.
    assert_eq!(
        message(schema.clone(), json!({"query": {}})),
        "demo.item.list inputs are invalid: inputs.query must include both type and value or both type and terms"
    );
    // An unknown discriminator matches no form.
    let explained = message(schema, json!({"query": {"type": SECRET, "value": "x"}}));
    assert_eq!(
        explained,
        "demo.item.list inputs are invalid: inputs.query must match one of the documented forms; see the action's input schema"
    );
}

#[test]
fn a_forbidding_form_yields_to_the_one_partly_satisfied() {
    let schema = json!({
        "type": "object",
        "properties": {"content": {}, "contentFormat": {"enum": ["markdown", "plain_text"]}},
        "oneOf": [
            {"required": ["content", "contentFormat"]},
            {"not": {"anyOf": [{"required": ["content"]}, {"required": ["contentFormat"]}]}}
        ]
    });
    assert_eq!(
        message(schema, json!({"content": SECRET})),
        "demo.item.list inputs are invalid: inputs.contentFormat is required"
    );
}

#[test]
fn alternative_types_are_combined() {
    let schema = json!({
        "type": "object",
        "properties": {"id": {"anyOf": [{"type": "string"}, {"type": "integer"}]}}
    });
    assert_eq!(
        message(schema, json!({"id": [SECRET]})),
        "demo.item.list inputs are invalid: inputs.id must be a string or an integer"
    );
}

#[test]
fn conditional_requirements_report_the_underlying_failure() {
    let schema = json!({
        "type": "object",
        "properties": {"contentFormat": {"enum": ["adf", "markdown"]}, "content": {}},
        "allOf": [
            {
                "if": {"properties": {"contentFormat": {"const": "adf"}}, "required": ["contentFormat"]},
                "then": {"properties": {"content": {"type": "object"}}}
            }
        ]
    });
    assert_eq!(
        message(schema, json!({"contentFormat": "adf", "content": SECRET})),
        "demo.item.list inputs are invalid: inputs.content must be an object"
    );
}

#[test]
fn forbidden_combinations_name_their_properties() {
    let schema = json!({
        "type": "object",
        "properties": {"parentId": {"type": "string"}, "parentUrl": {"type": "string"}, "internal": {}},
        "allOf": [
            {"not": {"required": ["parentId", "parentUrl"]}},
            {"if": {"required": ["parentId"]}, "then": {"not": {"required": ["internal"]}}}
        ]
    });
    assert_eq!(
        message(
            schema.clone(),
            json!({"parentId": "1", "parentUrl": SECRET})
        ),
        "demo.item.list inputs are invalid: inputs must not include both parentId and parentUrl"
    );
    assert_eq!(
        message(schema, json!({"parentId": "1", "internal": SECRET})),
        "demo.item.list inputs are invalid: inputs.internal is not allowed with these inputs"
    );
    let schema = json!({"type": "object", "not": {"properties": {"a": {"const": 1}}}});
    assert_eq!(
        message(schema, json!({"a": 1})),
        "demo.item.list inputs are invalid: inputs combines inputs in a way the action does not allow; see the action's input schema"
    );
}

#[test]
fn paths_index_arrays_and_hide_keys_that_may_not_be_shown() {
    let schema = json!({
        "type": "object",
        "properties": {
            "items": {"type": "array", "items": {"type": "object", "required": ["id"], "properties": {"id": {"type": "string"}}}},
            "labels": {"type": "object", "additionalProperties": {"type": "string"}},
            "a/b": {"type": "object", "properties": {"c~d": {"type": "string"}}}
        }
    });
    assert_eq!(
        message(schema.clone(), json!({"items": [{"id": "1"}, {}]})),
        "demo.item.list inputs are invalid: inputs.items[1].id is required"
    );
    let explained = message(schema.clone(), json!({"labels": {SECRET: 5, "team": true}}));
    assert_eq!(
        explained,
        "demo.item.list inputs are invalid: inputs.labels.<key> must be a string; inputs.labels.team must be a string"
    );
    // Declared names are shown whatever their characters.
    assert_eq!(
        message(schema, json!({"a/b": {"c~d": 1}})),
        "demo.item.list inputs are invalid: inputs.a/b.c~d must be a string"
    );
}

#[test]
fn at_most_three_problems_are_named() {
    let schema = json!({
        "type": "object",
        "required": ["a", "b", "c", "d", "e"],
        "properties": {"a": {}, "b": {}, "c": {}, "d": {}, "e": {}}
    });
    let explained = message(schema, json!({}));
    assert_eq!(
        explained,
        "demo.item.list inputs are invalid: inputs.a is required; inputs.b is required; inputs.c is required; and 2 more"
    );
}

#[test]
fn mixed_problems_are_each_named() {
    let explained = message(list_schema(), json!({"extra": 1, "maxResults": "ten"}));
    assert!(explained.starts_with("demo.item.list inputs are invalid: "));
    for problem in [
        format!("inputs.extra is not allowed; {LIST_ALLOWED}"),
        "inputs.maxResults must be an integer".to_owned(),
        "inputs must include issue or url".to_owned(),
    ] {
        assert!(explained.contains(&problem), "{explained}");
    }
}

#[test]
fn inputs_the_schema_accepts_keep_the_provider_message() {
    let error = ProviderError::deny(
        ReasonCode::InputInvalid,
        "demo.item.list maxResults must be greater than zero",
    );
    let explained = explain(
        "demo",
        "item.list",
        &list_schema(),
        &json!({"issue": "DEMO-1", "maxResults": 5}),
        error.clone(),
    );
    assert_eq!(explained, error);
}

#[test]
fn only_a_provider_input_denial_is_reworded() {
    let inputs = json!({"extra": SECRET});
    for error in [
        ProviderError::error(ReasonCode::InputInvalid, "kept"),
        ProviderError::deny(ReasonCode::LocatorInvalid, "kept"),
        agent_access_provider::host::port_failure(
            agent_access_provider::host::HostPort::DelegatedLease,
            ProviderError::deny(ReasonCode::InputInvalid, "kept"),
        ),
    ] {
        assert_eq!(
            explain("demo", "item.list", &list_schema(), &inputs, error.clone()),
            error
        );
    }
}

#[test]
fn an_explanation_changes_only_the_message() {
    let error = denial()
        .with_result(json!({"hint": "kept"}))
        .with_audit(json!({"operation": "item.list"}))
        .with_upstream(Some(400), Some(3))
        .with_internal_diagnostic_code("kept");
    let explained = explain(
        "demo",
        "item.list",
        &list_schema(),
        &json!({"extra": 1}),
        error.clone(),
    );
    assert_ne!(explained.message, error.message);
    let mut restored = explained.clone();
    restored.message = error.message.clone();
    assert_eq!(restored, error);
    assert_eq!(explained.reason_code(), ReasonCode::InputInvalid);
    assert_eq!(explained.decision(), Decision::Deny);
}

#[test]
fn an_uncompilable_schema_keeps_the_provider_message() {
    let schema = json!({"type": "object", "$id": "https://example.com/schema", "required": ["a"]});
    assert_eq!(message(schema, json!({})), denial().message);
    let schema =
        json!({"type": "object", "properties": {"a": {"$ref": "https://example.com/other"}}});
    assert_eq!(message(schema, json!({"a": 1})), denial().message);
}

#[test]
fn errors_inside_local_references_are_explained() {
    let schema = json!({
        "type": "object",
        "$defs": {"entry": {"type": "object", "properties": {"name": {"type": "string"}}, "additionalProperties": false}},
        "properties": {"entry": {"$ref": "#/$defs/entry"}}
    });
    let explained = message(schema, json!({"entry": {"name": 1, "other": SECRET}}));
    assert!(
        explained.contains("inputs.entry.name must be a string"),
        "{explained}"
    );
    assert!(
        explained.contains("inputs.entry.other is not allowed"),
        "{explained}"
    );
}

/// Secret-like values supplied in wrong-type fields, as unexpected values
/// and as non-identifier keys never reach a message.
#[test]
fn supplied_values_never_appear_in_an_explanation() {
    let schema = json!({
        "type": "object",
        "required": ["query"],
        "properties": {
            "query": {
                "type": "object",
                "required": ["type", "value"],
                "properties": {
                    "type": {"enum": ["cql", "text"]},
                    "value": {"type": "string", "maxLength": 4, "pattern": "^[a-z]+$"}
                },
                "additionalProperties": false
            },
            "maxResults": {"type": "integer"},
            "spaces": {"type": "array", "items": {"type": "string"}, "uniqueItems": true},
            "labels": {"type": "object", "additionalProperties": {"type": "integer"}},
            "id": {"anyOf": [{"type": "string", "minLength": 20}, {"type": "integer"}]},
            "mode": {"const": "exact"}
        },
        "additionalProperties": false
    });
    let inputs = json!({
        "query": {"type": SECRET, "value": SECRET, SECRET: SECRET},
        "maxResults": SECRET,
        "spaces": [SECRET, SECRET, 1],
        "labels": {SECRET: SECRET, "other": SECRET},
        "id": SECRET,
        "mode": SECRET,
        SECRET: {"nested": SECRET},
        "token": SECRET,
    });
    let compiled = BoundedImportSchema::compile(&schema).unwrap();
    let explainer = Explainer::new(&schema, &inputs);
    let mut problems = Vec::new();
    for error in compiled.validator().iter_errors(&inputs) {
        explainer.describe(&error, &mut problems);
    }
    assert!(problems.len() > 8, "{problems:?}");
    for problem in &problems {
        assert!(!problem.contains("secret"), "{problem}");
    }
    let explained = message(schema, inputs);
    assert!(!explained.contains("secret"), "{explained}");
}

/// Every action schema of the native providers this crate tests against.
fn native_schemas() -> Vec<(String, Value)> {
    let gitlab: agent_access_gitlab::GitlabProviderConfig = toml::from_str(
        "api_base_url = \"https://gitlab.example.com/api/v4\"\nweb_base_url = \"https://gitlab.example.com\"",
    )
    .unwrap();
    let cloudbees: agent_access_cloudbees_ci::CloudbeesCiProviderConfig =
        toml::from_str("[controllers.team]\nbase_url = \"https://ci.example.com\"").unwrap();
    [
        agent_access_jira::jira_descriptor(
            &toml::from_str("tenant_host = \"example.atlassian.net\"").unwrap(),
        ),
        agent_access_confluence::confluence_descriptor(
            &toml::from_str("tenant_host = \"example.atlassian.net\"").unwrap(),
        ),
        agent_access_gitlab::gitlab_descriptor(&gitlab),
        agent_access_cloudbees_ci::cloudbees_ci_descriptor(&cloudbees),
    ]
    .into_iter()
    .flat_map(|descriptor| {
        let service = descriptor.service.clone();
        descriptor
            .actions
            .into_iter()
            .map(move |action| (format!("{service}.{}", action.action), action.input_schema))
    })
    .collect()
}

/// The most values an input within the footprint budget can carry.
const MOST_VALUES: u64 = MAX_INPUT_FOOTPRINT / VALUE_FOOTPRINT;

#[test]
fn native_schemas_fit_the_budget() {
    let schemas = native_schemas();
    assert!(schemas.len() > 150, "{}", schemas.len());
    for (action, schema) in schemas {
        let positions = SchemaCost::of(&schema, 1).unwrap();
        let errors = SchemaCost::of(&schema, MOST_VALUES).unwrap();
        assert!(
            positions.copied <= MAX_COPIED_ERRORS,
            "{action}: {positions:?}"
        );
        assert!(
            errors.returned + errors.held <= MAX_SCHEMA_ERRORS,
            "{action}: {errors:?}"
        );
    }
}

#[test]
fn the_most_expensive_native_schemas_are_still_explained() {
    let schemas: BTreeMap<String, Value> = native_schemas().into_iter().collect();
    let explain_native = |action: &str, inputs: Value| {
        let (service, action) = action.split_once('.').unwrap();
        explain(
            service,
            action,
            &schemas[&format!("{service}.{action}")],
            &inputs,
            denial(),
        )
        .message
    };
    assert_eq!(
        explain_native(
            "gitlab.merge_request.draft_note.add",
            json!({
                "project": "group/project",
                "iid": 7,
                "content": "x".repeat(16 * 1024),
                "contentFormat": "markdown",
                "position": {"positionType": "text", "oldPath": "a.rs", "newPath": "a.rs", "newLine": 4},
                "extra": true
            })
        ),
        "gitlab.merge_request.draft_note.add inputs are invalid: inputs.extra is not allowed; \
         allowed: content, contentFormat, expectedHeadSha, iid, inReplyToDiscussionId, position, \
         project, resolveDiscussion; inputs.expectedHeadSha is required"
    );
    assert_eq!(
        explain_native(
            "jira.comment.list",
            json!({"issue": "DEMO-1", "maxResults": "ten"})
        ),
        "jira.comment.list inputs are invalid: inputs.maxResults must be an integer"
    );
}

/// An input whose footprint passes the budget is never validated.
#[test]
fn a_large_input_keeps_the_provider_message() {
    let started = std::time::Instant::now();
    let inputs = json!({"issue": "DEMO-1", "padding": "x".repeat(MAX_INPUT_FOOTPRINT as usize)});
    assert_eq!(message(list_schema(), inputs), denial().message);
    let mut many = InputSize::default();
    assert!(!many.fits(&json!(vec![Value::Null; 100_000])));
    assert!(many.values <= MOST_VALUES + 1, "{}", many.values);
    assert!(started.elapsed() < std::time::Duration::from_secs(5));
}

/// The branches of an `anyOf` each copy the input into their errors, so a
/// schema with many failing branches is never validated, however small the
/// input, and a large input never reaches the schema at all.
#[test]
fn many_failing_branches_keep_the_provider_message_without_validating() {
    let names: Vec<String> = (0..10_000).map(|index| format!("p{index}")).collect();
    let wide = json!({"type": "object", "anyOf": [{"required": names}, {"required": ["q"]}]});
    let branches: Vec<Value> = (0..10_000)
        .map(|index| json!({"required": [format!("p{index}")]}))
        .collect();
    let many = json!({"type": "object", "anyOf": branches});
    for schema in [wide, many] {
        let started = std::time::Instant::now();
        assert_eq!(message(schema.clone(), json!({"r": 1})), denial().message);
        let padded = json!({"padding": "x".repeat(512 * 1024)});
        assert_eq!(message(schema, padded), denial().message);
        assert!(started.elapsed() < std::time::Duration::from_secs(5));
    }
}

#[test]
fn schema_cost_counts_copies_by_position_and_errors_by_location() {
    // `additionalProperties: false` reports every unexpected member at once.
    let flat = json!({"type": "object", "required": ["a", "b"], "additionalProperties": false});
    assert_eq!(
        SchemaCost::of(&flat, 100),
        Some(SchemaCost {
            returned: 4,
            held: 0,
            copied: 0
        })
    );
    // Each branch error is held and copied; a nested alternative's errors
    // are copied once more only as its own error.
    let nested = json!({"anyOf": [
        {"required": ["a"]},
        {"oneOf": [{"required": ["b"]}, {"type": "string"}]}
    ]});
    assert_eq!(
        SchemaCost::of(&nested, 1),
        Some(SchemaCost {
            returned: 1,
            held: 4,
            copied: 4
        })
    );
    // Items are judged once per value, but their copies are disjoint.
    let items =
        json!({"type": "array", "items": {"anyOf": [{"type": "string"}, {"type": "integer"}]}});
    assert_eq!(
        SchemaCost::of(&items, 1),
        Some(SchemaCost {
            returned: 2,
            held: 2,
            copied: 2
        })
    );
    assert_eq!(
        SchemaCost::of(&items, 50),
        Some(SchemaCost {
            returned: 51,
            held: 100,
            copied: 100
        })
    );
    // A reference costs its target at every use.
    let referenced = json!({
        "$defs": {"pair": {"anyOf": [{"required": ["a"]}, {"required": ["b"]}]}},
        "allOf": [{"$ref": "#/$defs/pair"}, {"$ref": "#/$defs/pair"}]
    });
    assert_eq!(
        SchemaCost::of(&referenced, 1),
        Some(SchemaCost {
            returned: 2,
            held: 4,
            copied: 4
        })
    );
    // A cycle or a reference outside the document has no bound.
    let cyclic = json!({"$defs": {"node": {"properties": {"child": {"$ref": "#/$defs/node"}}}},
        "$ref": "#/$defs/node"});
    assert_eq!(SchemaCost::of(&cyclic, 1), None);
    let external = json!({"$ref": "https://example.com/schema"});
    assert_eq!(SchemaCost::of(&external, 1), None);
    assert_eq!(message(cyclic, json!({"child": 1})), denial().message);
}
