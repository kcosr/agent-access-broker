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

/// One action under a named configuration. Configuration identity is part of
/// the case so collecting the cases cannot silently replace another variant.
struct NativeSchemaCase {
    configuration: &'static str,
    service: String,
    action: agent_access_provider::ActionDescriptor,
}

impl NativeSchemaCase {
    fn key(&self) -> (&'static str, &str, &str) {
        (self.configuration, &self.service, &self.action.action)
    }

    fn label(&self) -> String {
        format!(
            "{}/{}.{}",
            self.configuration, self.service, self.action.action
        )
    }
}

/// Shipped native actions under the configurations that change availability,
/// accepted content formats, search routes, and optional schema constraints.
/// Search requests with omitted or explicit engines share each descriptor.
fn native_service_descriptors() -> Vec<(&'static str, agent_access_provider::ServiceDescriptor)> {
    fn validated_descriptor(
        configuration: &str,
        config: &dyn agent_access_provider::BackendConfig,
    ) -> agent_access_provider::ServiceDescriptor {
        use agent_access_provider::{
            CredentialSource, ProviderLimits, ServiceCredentialKinds, ValidationContext,
        };
        let credentials = match config.kind() {
            "jira" | "confluence" | "cloudbees_ci" => ServiceCredentialKinds::default()
                .with_service(Some(CredentialSource::static_kind("basic_api_token"))),
            "gitlab" => ServiceCredentialKinds::default()
                .with_service(Some(CredentialSource::static_kind("bearer_token"))),
            "gmail" => ServiceCredentialKinds::default().with_per_user_delegated(true),
            "teams" => ServiceCredentialKinds::default(),
            other => panic!("missing synthetic validation context for {other}"),
        };
        let limits = ProviderLimits::default();
        let context = ValidationContext::new("production", "managed", &limits, credentials);
        let mut errors = Vec::new();
        config.validate(&context, &mut errors);
        assert!(
            errors.is_empty(),
            "{configuration}/{}: {errors:?}",
            config.kind()
        );
        let descriptor = config.descriptor();
        descriptor
            .validate()
            .unwrap_or_else(|errors| panic!("{configuration}/{}: {errors:?}", descriptor.service));
        descriptor
    }

    let jira = |configuration, settings: &str| {
        let config: agent_access_jira::JiraProviderConfig = toml::from_str(&format!(
            r#"tenant_host = "example.atlassian.net"
allowed_upstream_hosts = ["https://example.atlassian.net/**"]
{settings}"#
        ))
        .unwrap();
        validated_descriptor(configuration, &config)
    };
    let confluence = |configuration, settings: &str| {
        let config: agent_access_confluence::ConfluenceProviderConfig = toml::from_str(&format!(
            r#"tenant_host = "example.atlassian.net"
allowed_upstream_hosts = ["https://example.atlassian.net/**"]
{settings}"#
        ))
        .unwrap();
        validated_descriptor(configuration, &config)
    };
    let cloudbees: agent_access_cloudbees_ci::CloudbeesCiProviderConfig = toml::from_str(
        r#"allowed_upstream_hosts = ["https://ci.example.com/**"]
[controllers.team]
base_url = "https://ci.example.com/"
"#,
    )
    .unwrap();
    let teams: agent_access_teams::TeamsConfig = toml::from_str(
        r#"allowed_upstream_hosts = ["https://example.environment.api.powerplatform.com/**"]"#,
    )
    .unwrap();
    let mut descriptors = vec![
        ("default", jira("default", "")),
        (
            "comments-enabled",
            jira("comments-enabled", "[content]\ncomment_formats = [\"adf\"]"),
        ),
        (
            "all-enabled",
            jira(
                "all-enabled",
                r#"[content]
comment_formats = ["adf"]
[attachments]
media_types = ["text/plain", "application/json"]
[comments]
allowed_visibility = [{ type = "role", value = "Developers" }]
"#,
            ),
        ),
        ("default", confluence("default", "")),
        (
            "content-disabled",
            confluence(
                "content-disabled",
                r#"[content]
page_formats = []
blog_formats = []
comment_formats = []
"#,
            ),
        ),
        (
            "pages-text-only",
            confluence("pages-text-only", "[content]\npage_formats = [\"storage\"]"),
        ),
        (
            "pages-object-only",
            confluence(
                "pages-object-only",
                "[content]\npage_formats = [\"atlas_doc_format\"]",
            ),
        ),
        (
            "all-enabled",
            confluence(
                "all-enabled",
                r#"[content]
page_formats = ["storage", "atlas_doc_format"]
blog_formats = ["storage"]
comment_formats = ["storage"]
[attachments]
media_types = ["text/plain", "application/json"]
"#,
            ),
        ),
        ("default", validated_descriptor("default", &cloudbees)),
        (
            "default",
            validated_descriptor("default", &agent_access_gmail::GmailConfig::default()),
        ),
        ("default", validated_descriptor("default", &teams)),
    ];
    let gitlab_default: agent_access_gitlab::GitlabProviderConfig = toml::from_str(
        r#"api_base_url = "https://gitlab.example.com/api/v4"
web_base_url = "https://gitlab.example.com"
allowed_upstream_hosts = ["https://gitlab.example.com/**"]"#,
    )
    .unwrap();
    // Start from the provider's complete default category set, rather than
    // maintaining another list which could omit a newly supported category.
    let categories = gitlab_default
        .search
        .engines
        .basic
        .project_categories
        .clone();
    for configuration in [
        "default",
        "search-disabled",
        "project-only",
        "instance-only",
        "both",
        "mixed",
        "zoekt-default",
        "all-enabled",
    ] {
        let mut config = gitlab_default.clone();
        match configuration {
            "default" => {}
            "search-disabled" => {
                config.search.engines.basic.project_categories.clear();
                config.search.engines.basic.instance_categories.clear();
            }
            "project-only" => config.search.engines.basic.instance_categories.clear(),
            "instance-only" | "both" => {
                config.search.engines.basic.project_categories.clear();
                config.search.engines.basic.instance_categories.clear();
                config.search.default_engine = "advanced".into();
                config.search.engines.advanced.instance_categories = categories.clone();
                if configuration == "both" {
                    config.search.engines.advanced.project_categories = categories.clone();
                }
            }
            "mixed" => {
                config.search.engines.advanced.instance_categories = categories.clone();
                config.search.engines.zoekt.project_categories = vec!["code".into()];
            }
            "zoekt-default" => {
                config.search.engines.basic.project_categories.clear();
                config.search.engines.basic.instance_categories.clear();
                config.search.default_engine = "zoekt".into();
                config.search.engines.zoekt.project_categories = vec!["code".into()];
                config.search.engines.zoekt.instance_categories = vec!["code".into()];
            }
            "all-enabled" => {
                config.search.default_engine = "advanced".into();
                config.search.engines.advanced.project_categories = categories.clone();
                config.search.engines.advanced.instance_categories = categories.clone();
                config.search.engines.zoekt.project_categories = vec!["code".into()];
                config.search.engines.zoekt.instance_categories = vec!["code".into()];
                config.provisioning.enabled = true;
                config.provisioning.max_access_level = 40;
                config.provisioning.max_token_lifetime_days = 365;
                config.provisioning.allowed_token_scopes = [
                    "api",
                    "read_api",
                    "read_repository",
                    "write_repository",
                    "read_registry",
                    "write_registry",
                    "self_rotate",
                ]
                .map(str::to_string)
                .into();
                config.webhooks.allowed_destinations = vec!["https://hooks.example.com/*".into()];
                config.webhooks.allow_disable_ssl_verification = true;
                config.attachments.media_types =
                    vec!["text/plain".into(), "application/json".into()];
            }
            _ => unreachable!("known schema configuration"),
        }
        descriptors.push((configuration, validated_descriptor(configuration, &config)));
    }
    descriptors
}

fn native_schemas() -> Vec<NativeSchemaCase> {
    let mut keys = std::collections::BTreeSet::new();
    native_service_descriptors()
        .into_iter()
        .flat_map(|(configuration, descriptor)| {
            let service = descriptor.service;
            descriptor
                .actions
                .into_iter()
                .map(move |action| NativeSchemaCase {
                    configuration,
                    service: service.clone(),
                    action,
                })
        })
        .inspect(|case| {
            let key = (
                case.configuration,
                case.service.clone(),
                case.action.action.clone(),
            );
            assert!(keys.insert(key), "duplicate schema case {}", case.label());
        })
        .collect()
}

#[test]
fn native_schema_cases_cover_optional_actions_and_content_formats() {
    let cases = native_schemas();
    let schema = |configuration, service, action| {
        &cases
            .iter()
            .find(|case| case.key() == (configuration, service, action))
            .unwrap_or_else(|| panic!("missing schema {configuration}/{service}.{action}"))
            .action
            .input_schema
    };
    assert!(
        !cases
            .iter()
            .any(|case| case.key() == ("default", "jira", "comment.add"))
    );
    assert_eq!(
        schema("comments-enabled", "jira", "comment.add")["properties"]["contentFormat"]["enum"],
        json!(["adf", "markdown", "plain_text"])
    );
    assert!(
        !cases
            .iter()
            .any(|case| case.key() == ("default", "confluence", "page.create"))
    );
    assert_eq!(
        schema("pages-object-only", "confluence", "page.create")["properties"]["contentFormat"]["enum"],
        json!(["atlas_doc_format"])
    );
    assert_eq!(
        schema("pages-text-only", "confluence", "page.create")["properties"]["contentFormat"]["enum"],
        json!(["storage", "markdown", "plain_text"])
    );
    assert_eq!(
        schema("all-enabled", "confluence", "page.create")["properties"]["contentFormat"]["enum"],
        json!(["storage", "atlas_doc_format", "markdown", "plain_text"])
    );
    for configuration in [
        "project-only",
        "instance-only",
        "both",
        "mixed",
        "zoekt-default",
        "all-enabled",
    ] {
        let search = schema(configuration, "gitlab", "search.code");
        assert!(
            search["properties"]["engine"]["enum"]
                .as_array()
                .is_some_and(|engines| !engines.is_empty())
        );
    }
    assert_eq!(
        schema("zoekt-default", "gitlab", "search.code")["properties"]["engine"]["default"],
        "zoekt"
    );
    assert!(
        !cases
            .iter()
            .any(|case| case.configuration == "search-disabled"
                && case.service == "gitlab"
                && case.action.action.starts_with("search."))
    );
}

#[test]
fn native_schemas_have_plain_roots() {
    const RELATIONAL: &[&str] = &["oneOf", "anyOf", "allOf", "if", "then", "else", "not"];

    let cases = native_schemas();
    for case in cases {
        let schema = &case.action.input_schema;
        let properties = schema["properties"]
            .as_object()
            .unwrap_or_else(|| panic!("{} must declare root properties", case.label()));
        if let agent_access_provider::ActionIo::MultipartUpload { plan } = &case.action.io {
            for locator in &plan.locator_inputs {
                assert!(
                    properties.contains_key(locator),
                    "{} upload locator {locator} must be a root property",
                    case.label()
                );
            }
        }
        assert_eq!(schema["type"], "object", "{} root type", case.label());
        for keyword in RELATIONAL {
            assert!(
                schema.get(keyword).is_none(),
                "{} root must not contain {keyword}",
                case.label()
            );
        }
        if case.service == "teams" {
            let content = &properties["content"];
            assert_eq!(content["type"], "object", "{} content", case.label());
            assert_ne!(content["additionalProperties"], false);
            assert!(content.get("required").is_none());
            for keyword in RELATIONAL {
                assert!(
                    content.get(*keyword).is_none(),
                    "{} content: {keyword}",
                    case.label()
                );
            }
            let fields = content["properties"].as_object().unwrap();
            assert_eq!(fields.len(), 7);
            for name in ["title", "text", "summary", "attachments", "@context"] {
                let field = fields[name].as_object().unwrap();
                assert_eq!(
                    field.len(),
                    1,
                    "{} content.{name} must allow extension values",
                    case.label()
                );
                assert!(
                    field["description"]
                        .as_str()
                        .is_some_and(|text| !text.is_empty())
                );
            }
            assert_eq!(fields["type"]["const"], "message");
            assert_eq!(fields["@type"]["const"], "MessageCard");
        }
        if case.service == "gitlab"
            && matches!(
                case.action.action.as_str(),
                "merge_request.discussion.inline.add"
                    | "merge_request.draft_note.add"
                    | "merge_request.draft_note.update"
            )
        {
            let position = &properties["position"];
            let range = &position["properties"]["lineRange"];
            for (name, object, fields) in [
                (
                    "position",
                    position,
                    &[
                        "positionType",
                        "oldPath",
                        "newPath",
                        "oldLine",
                        "newLine",
                        "lineRange",
                        "width",
                        "height",
                        "x",
                        "y",
                    ][..],
                ),
                ("position.lineRange", range, &["start", "end"][..]),
                (
                    "position.lineRange.start",
                    &range["properties"]["start"],
                    &["oldLine", "newLine"][..],
                ),
                (
                    "position.lineRange.end",
                    &range["properties"]["end"],
                    &["oldLine", "newLine"][..],
                ),
            ] {
                assert_eq!(object["type"], "object", "{} {name}", case.label());
                for field in fields {
                    assert!(
                        object["properties"].get(*field).is_some(),
                        "{} {name}.{field} must remain visible",
                        case.label()
                    );
                }
                for keyword in RELATIONAL {
                    assert!(
                        object.get(*keyword).is_none(),
                        "{} {name} must not contain {keyword}",
                        case.label()
                    );
                }
            }
            assert_eq!(
                position["properties"]["positionType"]["enum"],
                json!(["text", "file", "image"]),
                "{} position types",
                case.label()
            );
        }
    }
}

/// The most values an input within the footprint budget can carry.
const MOST_VALUES: u64 = MAX_INPUT_FOOTPRINT / VALUE_FOOTPRINT;

/// The most bytes of `const` and `enum` values one native schema may hold:
/// the validator clones them into errors.
const MAX_CONSTANT_BYTES_PER_SCHEMA: usize = 4 * 1024;
/// The largest `not`, `if` or `contains` subschema, serialized: the
/// validator evaluates them in full and the budget does not count them.
const MAX_DECIDING_SUBSCHEMA_BYTES: usize = 1024;

/// What one schema holds beyond the budget's reach.
#[derive(Debug, Default)]
struct DiagnosticProfile {
    references: usize,
    constant_bytes: usize,
    largest_deciding_subschema: usize,
}

impl DiagnosticProfile {
    fn of(schema: &Value) -> Self {
        let mut profile = Self::default();
        profile.walk(schema);
        profile
    }

    fn walk(&mut self, node: &Value) {
        match node {
            Value::Object(keywords) => {
                for (keyword, value) in keywords {
                    match keyword.as_str() {
                        "$ref" | "$dynamicRef" | "$recursiveRef" => self.references += 1,
                        "const" | "enum" => {
                            self.constant_bytes += serde_json::to_string(value).unwrap().len();
                            continue;
                        }
                        "default" | "examples" => continue,
                        "not" | "if" | "contains" => {
                            self.largest_deciding_subschema = self
                                .largest_deciding_subschema
                                .max(serde_json::to_string(value).unwrap().len());
                        }
                        _ => {}
                    }
                    self.walk(value);
                }
            }
            Value::Array(items) => items.iter().for_each(|item| self.walk(item)),
            _ => {}
        }
    }
}

/// Explanations run only for native actions, whose schemas are written in
/// Broker code. Every shipped one stays within this diagnostic profile, so
/// a schema that could make explaining expensive fails here: no references,
/// a few KiB of constants, small `not`/`if`/`contains` subschemas, and the
/// budget at the largest input it admits.
#[test]
fn native_schemas_fit_the_diagnostic_profile() {
    let schemas = native_schemas();
    assert!(schemas.len() > 200, "{}", schemas.len());
    for case in schemas {
        let action = case.label();
        let schema = case.action.input_schema;
        let profile = DiagnosticProfile::of(&schema);
        assert_eq!(profile.references, 0, "{action}");
        assert!(
            profile.constant_bytes <= MAX_CONSTANT_BYTES_PER_SCHEMA,
            "{action}: {profile:?}"
        );
        assert!(
            profile.largest_deciding_subschema <= MAX_DECIDING_SUBSCHEMA_BYTES,
            "{action}: {profile:?}"
        );
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
    let schemas: BTreeMap<(String, String), Value> = native_schemas()
        .into_iter()
        .filter(|case| case.configuration == "default")
        .map(|case| ((case.service, case.action.action), case.action.input_schema))
        .collect();
    let explain_native = |action: &str, inputs: Value| {
        let (service, action) = action.split_once('.').unwrap();
        explain(
            service,
            action,
            &schemas[&(service.to_string(), action.to_string())],
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
                "position": {"positionType": "text", "oldPath": "a.rs", "newPath": "a.rs", "newLine": 0}
            })
        ),
        "gitlab.merge_request.draft_note.add inputs are invalid: inputs.position.newLine must be at least 1"
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
