//! View-only custom-field projection. Jira implementation IDs, rather than
//! generic JSON types, determine which values are safe to disclose.
use super::JiraBackendError;
use agent_access_content::{ContentRenderError, render_adf_bounded_with_budget};
use agent_access_provider::presentation::{ReadContentFormat, RenderBudget};
use agent_access_provider::{ProviderError, ReasonCode};
use serde_json::{Map, Value, json};

const FIELD_PREFIX: &str = "customfield_";
const IMPLEMENTATION_PREFIX: &str = "com.atlassian.jira.plugin.system.customfieldtypes:";

#[derive(Clone, Copy)]
enum FieldType {
    Text,
    Url,
    Number,
    Date,
    Datetime,
    Adf,
    Option,
    Options,
    CascadingOption,
    User,
    Users,
    Labels,
}

impl FieldType {
    fn from_schema(schema: &Value) -> Option<Self> {
        let schema = schema.as_object()?;
        let implementation = schema
            .get("custom")?
            .as_str()?
            .strip_prefix(IMPLEMENTATION_PREFIX)?;
        let (kind, expected_type, expected_items) = match implementation {
            "textfield" => (Self::Text, "string", None),
            "url" => (Self::Url, "string", None),
            "float" => (Self::Number, "number", None),
            "datepicker" => (Self::Date, "date", None),
            "datetime" => (Self::Datetime, "datetime", None),
            // Cloud v3 represents textarea values as ADF, despite the
            // field schema retaining the generic string type.
            "textarea" => (Self::Adf, "string", None),
            "select" | "radiobuttons" => (Self::Option, "option", None),
            "multiselect" | "multicheckboxes" => (Self::Options, "array", Some("option")),
            "cascadingselect" => (Self::CascadingOption, "option-with-child", None),
            "userpicker" => (Self::User, "user", None),
            "multiuserpicker" => (Self::Users, "array", Some("user")),
            "labels" => (Self::Labels, "array", Some("string")),
            _ => return None,
        };
        if schema.get("type").and_then(Value::as_str) != Some(expected_type) {
            return None;
        }
        if let Some(expected_items) = expected_items
            && schema.get("items").and_then(Value::as_str) != Some(expected_items)
        {
            return None;
        }
        Some(kind)
    }

    fn name(self) -> &'static str {
        match self {
            Self::Text => "text",
            Self::Url => "url",
            Self::Number => "number",
            Self::Date => "date",
            Self::Datetime => "datetime",
            Self::Adf => "adf",
            Self::Option => "option",
            Self::Options => "options",
            Self::CascadingOption => "cascadingOption",
            Self::User => "user",
            Self::Users => "users",
            Self::Labels => "labels",
        }
    }

    fn project(self, value: &Value) -> Option<Value> {
        if value.is_null() {
            return Some(Value::Null);
        }
        match self {
            Self::Text | Self::Url | Self::Date | Self::Datetime => {
                value.is_string().then(|| value.clone())
            }
            Self::Number => value.is_number().then(|| value.clone()),
            // Full ADF validation happens after source-issue confirmation,
            // sharing one budget with the description and other ADF fields.
            Self::Adf => value.is_object().then(|| value.clone()),
            Self::Option => project_option(value),
            Self::Options => project_array(value, project_option),
            Self::CascadingOption => {
                let mut projected = project_option(value)?;
                projected["child"] = match value.get("child") {
                    None | Some(Value::Null) => Value::Null,
                    Some(child) => project_option(child)?,
                };
                Some(projected)
            }
            Self::User => project_user(value),
            Self::Users => project_array(value, project_user),
            Self::Labels => project_array(value, |label| label.is_string().then(|| label.clone())),
        }
    }
}

fn project_option(value: &Value) -> Option<Value> {
    Some(json!({
        "id": value.get("id")?.as_str()?,
        "value": value.get("value")?.as_str()?,
    }))
}

fn project_user(value: &Value) -> Option<Value> {
    let account_id = value.get("accountId")?.as_str()?;
    let display_name = match value.get("displayName") {
        None | Some(Value::Null) => None,
        Some(name) => Some(name.as_str()?),
    };
    Some(json!({"accountId": account_id, "displayName": display_name}))
}

fn project_array(value: &Value, project: fn(&Value) -> Option<Value>) -> Option<Value> {
    value
        .as_array()?
        .iter()
        .map(project)
        .collect::<Option<Vec<_>>>()
        .map(Value::Array)
}

/// Only canonical IDs in `fields` identify returned custom-field values.
/// Metadata for other fields is neither exposed nor used to create entries.
pub(super) fn custom_fields_from_value(value: &Value) -> Result<Vec<Value>, JiraBackendError> {
    let fields = value
        .get("fields")
        .and_then(Value::as_object)
        .ok_or_else(|| JiraBackendError::Protocol("issue fields missing".to_string()))?;
    let names = metadata_map(value, "names")?;
    let schemas = metadata_map(value, "schema")?;
    let mut fields = fields
        .iter()
        .filter(|(id, _)| is_custom_field_id(id))
        .collect::<Vec<_>>();
    // Canonical suffixes have no leading zeroes. Length then lexical order
    // gives numeric order without an integer width limit or parse overflow.
    fields.sort_unstable_by(|(left, _), (right, _)| {
        left.len().cmp(&right.len()).then_with(|| left.cmp(right))
    });

    Ok(fields
        .into_iter()
        .map(|(id, raw)| {
            let name = names
                .and_then(|names| names.get(id))
                .and_then(Value::as_str);
            let kind = schemas
                .and_then(|schemas| schemas.get(id))
                .and_then(FieldType::from_schema);
            let projected = kind.and_then(|kind| kind.project(raw));
            let status = match (kind, projected.as_ref()) {
                (None, _) => "unsupported",
                (Some(_), None) => "withheld",
                (Some(_), Some(_)) => "supported",
            };
            let mut field = json!({
                "id": id,
                "name": name,
                "type": kind.map(FieldType::name),
                "status": status,
            });
            if let Some(projected) = projected {
                field["value"] = projected;
            } else if is_empty_sentinel(raw) {
                // Empty sentinels disclose no content and distinguish a
                // returned empty value from an absent field, for every status.
                field["value"] = raw.clone();
            }
            field
        })
        .collect())
}

fn metadata_map<'a>(
    value: &'a Value,
    key: &str,
) -> Result<Option<&'a Map<String, Value>>, JiraBackendError> {
    match value.get(key) {
        None => Ok(None),
        Some(Value::Object(map)) => Ok(Some(map)),
        Some(_) => Err(JiraBackendError::Protocol(
            "issue field metadata must be an object".to_string(),
        )),
    }
}

fn is_custom_field_id(id: &str) -> bool {
    let Some(suffix) = id.strip_prefix(FIELD_PREFIX) else {
        return false;
    };
    matches!(suffix.as_bytes().first(), Some(b'1'..=b'9'))
        && suffix.bytes().all(|byte| byte.is_ascii_digit())
}

fn is_empty_sentinel(value: &Value) -> bool {
    value.is_null() || value.as_array().is_some_and(Vec::is_empty)
}

/// Preflight the complete view even for native JSON. Only malformed custom
/// documents are withheld; all size and complexity failures abort the view.
pub(super) fn preflight_issue_view_content(
    description: Option<&Value>,
    custom_fields: &mut [Value],
    max_body_bytes: u64,
) -> Result<(), ProviderError> {
    let mut budget = RenderBudget::default();
    if let Some(description) = description {
        preflight_adf(description, max_body_bytes, &mut budget).map_err(|_| {
            ProviderError::error(
                ReasonCode::UpstreamProtocolFailed,
                "Jira issue description response was invalid",
            )
        })?;
    }
    preflight_custom_adf(custom_fields, max_body_bytes, &mut budget)
}

fn preflight_custom_adf(
    fields: &mut [Value],
    max_body_bytes: u64,
    budget: &mut RenderBudget,
) -> Result<(), ProviderError> {
    for field in fields {
        if field["status"] != "supported" || field["type"] != "adf" {
            continue;
        }
        let Some(document) = field.get("value").filter(|value| !value.is_null()) else {
            continue;
        };
        let mut trial =
            RenderBudget::with_limits(budget.remaining_nodes(), budget.remaining_work_units());
        match preflight_adf(document, max_body_bytes, &mut trial) {
            Ok(()) => *budget = trial,
            Err(ContentRenderError::MalformedDocument) => {
                field["status"] = json!("withheld");
                field
                    .as_object_mut()
                    .expect("projected custom field")
                    .remove("value");
            }
            Err(_) => {
                return Err(ProviderError::error(
                    ReasonCode::UpstreamProtocolFailed,
                    "Jira issue rich content exceeded a response limit",
                ));
            }
        }
    }
    Ok(())
}

fn preflight_adf(
    document: &Value,
    max_body_bytes: u64,
    budget: &mut RenderBudget,
) -> Result<(), ContentRenderError> {
    render_adf_bounded_with_budget(
        document,
        ReadContentFormat::Native,
        max_body_bytes,
        max_body_bytes,
        budget,
    )
    .map(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn schema(implementation: &str, kind: &str, items: Option<&str>) -> Value {
        let mut schema = json!({
            "custom": format!("{IMPLEMENTATION_PREFIX}{implementation}"),
            "type": kind,
        });
        if let Some(items) = items {
            schema["items"] = json!(items);
        }
        schema
    }

    fn one_field(schema: Value, value: Value) -> Value {
        json!({
            "fields": {"customfield_1": value},
            "names": {"customfield_1": "Display name"},
            "schema": {"customfield_1": schema},
        })
    }

    fn project(schema: Value, value: Value) -> Value {
        custom_fields_from_value(&one_field(schema, value))
            .unwrap()
            .remove(0)
    }

    fn adf(text: &str) -> Value {
        json!({"type": "doc", "version": 1, "content": [
            {"type": "paragraph", "content": [{"type": "text", "text": text}]}
        ]})
    }

    fn adf_field(document: Value) -> Value {
        project(schema("textarea", "string", None), document)
    }

    #[test]
    fn projects_every_supported_implementation_and_preserves_json_types() {
        let option = json!({"id": "12", "value": "High"});
        let user = json!({"accountId": "account-a", "displayName": "Sample User"});
        let cases = [
            ("textfield", "string", None, "text", json!("plain")),
            ("url", "string", None, "url", json!("javascript:alert(1)")),
            ("float", "number", None, "number", json!(0)),
            ("float", "number", None, "number", json!(3.25)),
            ("datepicker", "date", None, "date", json!("2026-10-23")),
            (
                "datetime",
                "datetime",
                None,
                "datetime",
                json!("2026-10-23T12:00:00.000+0000"),
            ),
            ("textarea", "string", None, "adf", adf("Rich content")),
            ("select", "option", None, "option", option.clone()),
            ("radiobuttons", "option", None, "option", option.clone()),
            (
                "multiselect",
                "array",
                Some("option"),
                "options",
                json!([option.clone()]),
            ),
            (
                "multicheckboxes",
                "array",
                Some("option"),
                "options",
                json!([option.clone()]),
            ),
            (
                "cascadingselect",
                "option-with-child",
                None,
                "cascadingOption",
                json!({"id": "1", "value": "Parent", "child": option}),
            ),
            ("userpicker", "user", None, "user", user.clone()),
            (
                "multiuserpicker",
                "array",
                Some("user"),
                "users",
                json!([user]),
            ),
            (
                "labels",
                "array",
                Some("string"),
                "labels",
                json!(["triaged", "release-ready"]),
            ),
        ];
        for (implementation, kind, items, normalized, value) in cases {
            let field = project(schema(implementation, kind, items), value.clone());
            assert_eq!(
                field,
                json!({
                    "id": "customfield_1", "name": "Display name", "type": normalized,
                    "status": "supported", "value": value,
                }),
                "{implementation}"
            );
            assert_eq!(
                project(schema(implementation, kind, items), Value::Null)["value"],
                Value::Null,
                "{implementation} accepts null"
            );
        }
    }

    #[test]
    fn labels_require_the_exact_implementation_and_schema() {
        let cases = [
            json!({"type": "array", "items": "string"}),
            json!({"custom": "app:labels", "type": "array", "items": "string"}),
            schema("label", "array", Some("string")),
            schema("labels", "string", None),
            schema("labels", "array", None),
            schema("labels", "array", Some("option")),
        ];
        for schema in cases {
            let field = project(schema, json!(["private"]));
            assert_eq!(field["status"], "unsupported");
            assert_eq!(field["type"], Value::Null);
            assert!(field.get("value").is_none());
        }
    }

    #[test]
    fn labels_preserve_strings_order_duplicates_null_and_empty_values() {
        for value in [
            Value::Null,
            json!([]),
            json!(["z", "", "snow 雪", "z", "`literal`"]),
        ] {
            let field = project(schema("labels", "array", Some("string")), value.clone());
            assert_eq!(field["type"], "labels");
            assert_eq!(field["status"], "supported");
            assert_eq!(field["value"], value);
        }
        for invalid in [
            json!("private"),
            json!({"private": true}),
            json!(42),
            json!(["valid", null]),
            json!(["valid", 42]),
            json!(["valid", {"private": true}]),
        ] {
            let field = project(schema("labels", "array", Some("string")), invalid);
            assert_eq!(field["type"], "labels");
            assert_eq!(field["status"], "withheld");
            assert!(field.get("value").is_none());
        }
    }

    #[test]
    fn projects_only_returned_canonical_ids_in_numeric_order() {
        let input = json!({
            "fields": {
                "customfield_100": null,
                "customfield_2": [],
                "customfield_10": null,
                "customfield_999999999999999999999999999999999999999999": null,
                "customfield_01": "private", "customfield_0": "private",
                "customfield_": "private", "customfield_-1": "private",
                "customfield_1.0": "private", "customfield_1x": "private",
                "customfield_٢": "private", "summary": "private",
                "parent": {"key": "PRIVATE-1"}
            },
            "names": {"customfield_2": "Duplicate", "customfield_10": "Duplicate", "customfield_3": "Not returned"},
            "schema": {"customfield_3": schema("textfield", "string", None)}
        });
        let fields = custom_fields_from_value(&input).unwrap();
        assert_eq!(
            fields
                .iter()
                .map(|field| field["id"].as_str().unwrap())
                .collect::<Vec<_>>(),
            [
                "customfield_2",
                "customfield_10",
                "customfield_100",
                "customfield_999999999999999999999999999999999999999999"
            ]
        );
        assert_eq!(fields[0]["name"], "Duplicate");
        assert_eq!(fields[1]["name"], "Duplicate");
        assert_eq!(fields[2]["name"], Value::Null);
        assert_eq!(fields[0]["value"], json!([]));
        assert!(fields.iter().all(|field| field["status"] == "unsupported"));
        assert!(!serde_json::to_string(&fields).unwrap().contains("private"));
    }

    #[test]
    fn absent_metadata_keeps_entries_but_never_exposes_nonempty_values() {
        let fields = custom_fields_from_value(&json!({"fields": {
            "customfield_1": "private", "customfield_2": null,
            "customfield_3": [], "customfield_4": ""
        }}))
        .unwrap();
        assert_eq!(
            fields[0],
            json!({"id": "customfield_1", "name": null, "type": null, "status": "unsupported"})
        );
        assert!(fields[1].get("value").unwrap().is_null());
        assert_eq!(fields[2]["value"], json!([]));
        assert!(fields[3].get("value").is_none());
    }

    #[test]
    fn metadata_maps_are_structural_but_individual_bad_metadata_is_isolated() {
        for key in ["names", "schema"] {
            for invalid in [Value::Null, json!([]), json!("private"), json!(3)] {
                let mut input = one_field(schema("textfield", "string", None), json!("private"));
                input[key] = invalid;
                let error = custom_fields_from_value(&input).unwrap_err();
                assert!(!error.to_string().contains("private"));
            }
        }
        for invalid_name in [Value::Null, json!([]), json!({"private": true}), json!(3)] {
            let mut input = one_field(schema("textfield", "string", None), json!("okay"));
            input["names"]["customfield_1"] = invalid_name;
            let field = custom_fields_from_value(&input).unwrap().remove(0);
            assert_eq!(field["name"], Value::Null);
            assert_eq!(field["status"], "supported");
            assert_eq!(field["value"], "okay");
        }
        for invalid_schema in [
            Value::Null,
            json!([]),
            json!("private"),
            json!({"type": "string"}),
        ] {
            let field = project(invalid_schema, json!("private"));
            assert_eq!(field["status"], "unsupported");
            assert!(field["type"].is_null());
            assert!(field.get("value").is_none());
        }
    }

    #[test]
    fn unknown_implementations_and_mismatched_schemas_never_fall_back_to_json_type() {
        let cases = [
            (
                json!({"custom": "com.pyxis.greenhopper.jira:gh-epic-link", "type": "string"}),
                json!("PRIVATE-1"),
            ),
            (
                json!({"custom": "com.pyxis.greenhopper.jira:gh-sprint", "type": "array", "items": "string"}),
                json!(["private sprint metadata"]),
            ),
            (
                schema("grouppicker", "group", None),
                json!({"name": "private group"}),
            ),
            (
                schema("project", "project", None),
                json!({"key": "PRIVATE"}),
            ),
            (
                schema("version", "version", None),
                json!({"name": "private version"}),
            ),
            (schema("unknown", "string", None), json!("private")),
            (
                json!({"custom": "app:textfield", "type": "string"}),
                json!("private"),
            ),
            (
                schema("textfield", "object", None),
                json!({"private": true}),
            ),
            (schema("textarea", "object", None), adf("private")),
            (schema("float", "string", None), json!("private")),
            (
                schema("multiselect", "array", Some("user")),
                json!([{"accountId": "private"}]),
            ),
            (
                schema("multiuserpicker", "array", None),
                json!([{"accountId": "private"}]),
            ),
            (
                schema("cascadingselect", "option", None),
                json!({"id": "private", "value": "private"}),
            ),
        ];
        for (schema, value) in cases {
            let field = project(schema.clone(), value);
            assert_eq!(field["status"], "unsupported", "{schema}");
            assert!(field.get("value").is_none(), "{schema}");
            for empty in [Value::Null, json!([])] {
                let field = project(schema.clone(), empty.clone());
                assert_eq!(field["status"], "unsupported");
                assert_eq!(field["value"], empty);
            }
        }
    }

    #[test]
    fn options_and_users_expose_only_the_typed_projection() {
        let option = json!({"id": "1", "value": "Visible", "self": "private", "child": {"value": "private"}});
        let selected = project(schema("select", "option", None), option.clone());
        assert_eq!(selected["value"], json!({"id": "1", "value": "Visible"}));
        let cascading = project(
            schema("cascadingselect", "option-with-child", None),
            json!({
                "id": "2", "value": "Parent", "self": "private", "child": option
            }),
        );
        assert_eq!(
            cascading["value"],
            json!({"id": "2", "value": "Parent", "child": {"id": "1", "value": "Visible"}})
        );
        let parent_only = project(
            schema("cascadingselect", "option-with-child", None),
            json!({"id": "2", "value": "Parent"}),
        );
        assert!(parent_only["value"]["child"].is_null());

        let user = json!({
            "accountId": "account-a", "displayName": "Visible User",
            "self": "private", "emailAddress": "private@example.invalid",
            "avatarUrls": {"48x48": "private"}, "groups": ["private"],
            "project": {"key": "PRIVATE"}
        });
        let users = project(
            schema("multiuserpicker", "array", Some("user")),
            json!([user]),
        );
        assert_eq!(
            users["value"],
            json!([{"accountId": "account-a", "displayName": "Visible User"}])
        );
        assert_eq!(
            project(
                schema("userpicker", "user", None),
                json!({"accountId": "account-b"})
            )["value"],
            json!({"accountId": "account-b", "displayName": null})
        );
        assert!(
            !serde_json::to_string(&[selected, cascading, parent_only, users])
                .unwrap()
                .contains("private")
        );
    }

    #[test]
    fn malformed_recognized_values_withhold_the_whole_field() {
        let cases = [
            ("textfield", "string", None, json!({"private": true})),
            ("float", "number", None, json!("42")),
            ("float", "number", None, json!(false)),
            ("datepicker", "date", None, json!(3)),
            ("datetime", "datetime", None, json!(true)),
            ("textarea", "string", None, json!("private")),
            (
                "select",
                "option",
                None,
                json!({"id": 3, "value": "private"}),
            ),
            ("select", "option", None, json!({"id": "3"})),
            (
                "multiselect",
                "array",
                Some("option"),
                json!([{"id": "3", "value": "valid"}, {"id": "4", "value": false}]),
            ),
            ("multicheckboxes", "array", Some("option"), json!([null])),
            (
                "cascadingselect",
                "option-with-child",
                None,
                json!({"id": "3", "value": "valid", "child": {"id": "4"}}),
            ),
            (
                "userpicker",
                "user",
                None,
                json!({"displayName": "private"}),
            ),
            (
                "userpicker",
                "user",
                None,
                json!({"accountId": "a", "displayName": 42}),
            ),
            (
                "multiuserpicker",
                "array",
                Some("user"),
                json!([{"accountId": "valid"}, {"accountId": 3}]),
            ),
        ];
        for (implementation, kind, items, value) in cases {
            let field = project(schema(implementation, kind, items), value);
            assert_eq!(field["status"], "withheld", "{implementation}");
            assert!(!field["type"].is_null(), "{implementation}");
            assert!(field.get("value").is_none(), "{implementation}");
        }
        let empty_scalar = project(schema("textfield", "string", None), json!([]));
        assert_eq!(empty_scalar["status"], "withheld");
        assert_eq!(empty_scalar["value"], json!([]));
        for implementation in ["multiselect", "multicheckboxes"] {
            let empty = project(schema(implementation, "array", Some("option")), json!([]));
            assert_eq!(empty["status"], "supported");
            assert_eq!(empty["value"], json!([]));
        }
    }

    #[test]
    fn adf_preflight_withholds_malformed_fields_and_skips_null_without_a_budget_charge() {
        let valid = adf("Valid");
        let mut malformed = adf("Private malformed content");
        malformed["content"][0]["content"]
            .as_array_mut()
            .unwrap()
            .push(json!({"type": "text", "text": 42}));
        let mut fields = vec![
            adf_field(malformed),
            adf_field(Value::Null),
            adf_field(valid.clone()),
        ];
        let mut expected_budget = RenderBudget::default();
        preflight_adf(&valid, 4096, &mut expected_budget).unwrap();
        let mut budget = RenderBudget::default();
        preflight_custom_adf(&mut fields, 4096, &mut budget).unwrap();
        assert_eq!(fields[0]["status"], "withheld");
        assert!(fields[0].get("value").is_none());
        assert_eq!(fields[1]["status"], "supported");
        assert!(fields[1]["value"].is_null());
        assert_eq!(fields[2]["value"], valid);
        assert_eq!(budget.remaining_nodes(), expected_budget.remaining_nodes());
        assert_eq!(
            budget.remaining_work_units(),
            expected_budget.remaining_work_units()
        );
    }

    #[test]
    fn malformed_description_fails_even_when_custom_fields_are_valid() {
        let description =
            json!({"type": "doc", "version": 1, "content": [{"type": "text", "text": 42}]});
        let mut fields = vec![adf_field(adf("Valid"))];
        let error =
            preflight_issue_view_content(Some(&description), &mut fields, 4096).unwrap_err();
        assert_eq!(error.reason_code(), ReasonCode::UpstreamProtocolFailed);
        assert_eq!(fields[0]["status"], "supported");
    }

    #[test]
    fn adf_size_and_shared_complexity_fail_the_view_without_withholding_valid_values() {
        let mut fields = vec![adf_field(adf(&"private".repeat(100)))];
        let error = preflight_issue_view_content(None, &mut fields, 128).unwrap_err();
        assert_eq!(error.reason_code(), ReasonCode::UpstreamProtocolFailed);
        assert!(!error.message.contains("private"));
        assert_eq!(fields[0]["status"], "supported");
        assert!(fields[0].get("value").is_some());

        let document = adf("valid");
        let mut measured = RenderBudget::default();
        preflight_adf(&document, 4096, &mut measured).unwrap();
        let used_nodes = RenderBudget::default().remaining_nodes() - measured.remaining_nodes();
        let mut budget = RenderBudget::with_limits(used_nodes, usize::MAX);
        let mut fields = vec![adf_field(document.clone()), adf_field(document)];
        let error = preflight_custom_adf(&mut fields, 4096, &mut budget).unwrap_err();
        assert_eq!(error.reason_code(), ReasonCode::UpstreamProtocolFailed);
        assert!(
            fields
                .iter()
                .all(|field| field["status"] == "supported" && field.get("value").is_some())
        );
    }

    #[test]
    fn default_preflight_budget_is_shared_with_the_description() {
        // Each document fits the per-document limits and content byte cap;
        // three together exceed the unchanged request-wide node budget.
        let document = json!({"type": "doc", "version": 1, "content":
            vec![json!({"type": "paragraph"}); 50_000]
        });
        let cap = serde_json::to_vec(&document).unwrap().len() as u64;
        let mut fields = vec![adf_field(document.clone())];
        preflight_issue_view_content(Some(&document), &mut fields, cap).unwrap();
        fields.push(adf_field(document.clone()));
        let error = preflight_issue_view_content(Some(&document), &mut fields, cap).unwrap_err();
        assert_eq!(error.reason_code(), ReasonCode::UpstreamProtocolFailed);
        assert!(fields.iter().all(|field| field["status"] == "supported"));
    }
}
