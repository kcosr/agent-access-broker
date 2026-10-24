//! Allowlisted standard context and guarded references for detailed issue views.
use super::{JiraBackendError, is_issue_key};
use serde::Serialize;
use serde_json::{Map, Value};

/// Context returned only by `issue.view`, separate from search and write readbacks.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct JiraIssueViewContext {
    pub resolution: Option<JiraIssueViewNamedValue>,
    pub resolution_date: Option<String>,
    pub due_date: Option<String>,
    pub components: Option<Vec<JiraIssueViewNamedValue>>,
    pub fix_versions: Option<Vec<JiraIssueViewNamedValue>>,
    pub affected_versions: Option<Vec<JiraIssueViewNamedValue>>,
    pub status_category: Option<JiraIssueViewStatusCategory>,
    /// A missing parent becomes JSON null only for universally authorized views.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent: Option<JiraIssueViewReference>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subtasks: Option<Vec<JiraIssueViewReference>>,
}

/// A resolution, component, or version with all other upstream metadata removed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct JiraIssueViewNamedValue {
    pub id: String,
    pub name: Option<String>,
}

/// Jira's category key is preserved without assuming a fixed category enum.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct JiraIssueViewStatusCategory {
    pub id: u64,
    pub key: String,
    pub name: Option<String>,
}

/// Embedded hierarchy metadata; no target lookup or ancestry inference occurs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct JiraIssueViewReference {
    pub key: String,
    pub summary: Option<String>,
    pub issue_type: Option<String>,
}

pub(super) fn issue_view_context_from_value(
    value: &Value,
    include_issue_references: bool,
) -> Result<JiraIssueViewContext, JiraBackendError> {
    let fields = object(value.get("fields").ok_or_else(invalid_context)?)?;
    let status = nullable(fields.get("status"), object)?;
    let mut context = JiraIssueViewContext {
        resolution: nullable(fields.get("resolution"), named_value)?,
        resolution_date: nullable(fields.get("resolutiondate"), string_value)?,
        due_date: nullable(fields.get("duedate"), string_value)?,
        components: nullable(fields.get("components"), named_values)?,
        fix_versions: nullable(fields.get("fixVersions"), named_values)?,
        affected_versions: nullable(fields.get("versions"), named_values)?,
        status_category: nullable(
            status.and_then(|status| status.get("statusCategory")),
            status_category,
        )?,
        parent: None,
        subtasks: None,
    };
    // Restricted responses may contain unsolicited hierarchy. Do not inspect it.
    if include_issue_references {
        context.parent = nullable(fields.get("parent"), reference)?;
        context.subtasks = fields.get("subtasks").map(references).transpose()?;
    }
    Ok(context)
}

fn nullable<'a, T>(
    value: Option<&'a Value>,
    project: impl FnOnce(&'a Value) -> Result<T, JiraBackendError>,
) -> Result<Option<T>, JiraBackendError> {
    match value {
        None | Some(Value::Null) => Ok(None),
        Some(value) => project(value).map(Some),
    }
}

fn object(value: &Value) -> Result<&Map<String, Value>, JiraBackendError> {
    value.as_object().ok_or_else(invalid_context)
}

fn string_value(value: &Value) -> Result<String, JiraBackendError> {
    value
        .as_str()
        .map(str::to_owned)
        .ok_or_else(invalid_context)
}

fn required_string(object: &Map<String, Value>, key: &str) -> Result<String, JiraBackendError> {
    object
        .get(key)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
        .ok_or_else(invalid_context)
}

fn named_value(value: &Value) -> Result<JiraIssueViewNamedValue, JiraBackendError> {
    let value = object(value)?;
    Ok(JiraIssueViewNamedValue {
        id: required_string(value, "id")?,
        name: nullable(value.get("name"), string_value)?,
    })
}

fn named_values(value: &Value) -> Result<Vec<JiraIssueViewNamedValue>, JiraBackendError> {
    value
        .as_array()
        .ok_or_else(invalid_context)?
        .iter()
        .map(named_value)
        .collect()
}

fn status_category(value: &Value) -> Result<JiraIssueViewStatusCategory, JiraBackendError> {
    let value = object(value)?;
    Ok(JiraIssueViewStatusCategory {
        id: value
            .get("id")
            .and_then(Value::as_u64)
            .ok_or_else(invalid_context)?,
        key: required_string(value, "key")?,
        name: nullable(value.get("name"), string_value)?,
    })
}

fn reference(value: &Value) -> Result<JiraIssueViewReference, JiraBackendError> {
    let value = object(value)?;
    let key = required_string(value, "key")?;
    if !is_issue_key(&key) {
        return Err(invalid_context());
    }
    let fields = nullable(value.get("fields"), object)?;
    let issue_type = nullable(fields.and_then(|fields| fields.get("issuetype")), object)?;
    Ok(JiraIssueViewReference {
        key,
        summary: nullable(
            fields.and_then(|fields| fields.get("summary")),
            string_value,
        )?,
        issue_type: nullable(issue_type.and_then(|kind| kind.get("name")), string_value)?,
    })
}

fn references(value: &Value) -> Result<Vec<JiraIssueViewReference>, JiraBackendError> {
    value
        .as_array()
        .ok_or_else(invalid_context)?
        .iter()
        .map(reference)
        .collect()
}

fn invalid_context() -> JiraBackendError {
    JiraBackendError::Protocol("Jira issue context response was invalid".to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn project(fields: Value, include_issue_references: bool) -> JiraIssueViewContext {
        issue_view_context_from_value(&json!({"fields": fields}), include_issue_references).unwrap()
    }

    fn assert_invalid(fields: Value) {
        let error = issue_view_context_from_value(&json!({"fields": fields}), true).unwrap_err();
        assert!(matches!(error, JiraBackendError::Protocol(_)));
        assert_eq!(error.to_string(), invalid_context().to_string());
        assert!(!error.to_string().contains("private"));
    }

    #[test]
    fn standard_context_is_allowlisted_and_preserves_dates_order_and_duplicates() {
        let named = json!({"id": "12", "name": "Release", "description": "private", "self": "private", "lead": {"emailAddress": "private"}});
        let context = project(
            json!({
                "resolution": named,
                "resolutiondate": "2026-10-23T13:00:00.000+0530",
                "duedate": "2026-10-24",
                "components": [named, {"id": "second"}, named],
                "fixVersions": [named, named],
                "versions": [named],
                "status": {"id": "private", "statusCategory": {"id": 0, "key": "custom-key", "name": "Category", "colorName": "private", "self": "private"}},
            }),
            false,
        );
        assert_eq!(
            json!(context),
            json!({
                "resolution": {"id": "12", "name": "Release"},
                "resolutionDate": "2026-10-23T13:00:00.000+0530",
                "dueDate": "2026-10-24",
                "components": [{"id": "12", "name": "Release"}, {"id": "second", "name": null}, {"id": "12", "name": "Release"}],
                "fixVersions": [{"id": "12", "name": "Release"}, {"id": "12", "name": "Release"}],
                "affectedVersions": [{"id": "12", "name": "Release"}],
                "statusCategory": {"id": 0, "key": "custom-key", "name": "Category"},
            })
        );
    }

    #[test]
    fn standard_absent_and_null_values_match_but_empty_arrays_are_preserved() {
        let absent = project(json!({}), true);
        let nulls = project(
            json!({
                "resolution": null, "resolutiondate": null, "duedate": null,
                "components": null, "fixVersions": null, "versions": null,
                "status": null, "parent": null,
            }),
            true,
        );
        assert_eq!(absent, JiraIssueViewContext::default());
        assert_eq!(nulls, absent);
        assert_eq!(
            json!(absent),
            json!({
                "resolution": null, "resolutionDate": null, "dueDate": null,
                "components": null, "fixVersions": null, "affectedVersions": null,
                "statusCategory": null,
            })
        );
        assert_eq!(project(json!({"status": {}}), true), absent);
        assert_eq!(
            project(json!({"status": {"statusCategory": null}}), true),
            absent
        );
        let empty = project(
            json!({"components": [], "fixVersions": [], "versions": [], "subtasks": []}),
            true,
        );
        assert_eq!(empty.components, Some(vec![]));
        assert_eq!(empty.fix_versions, Some(vec![]));
        assert_eq!(empty.affected_versions, Some(vec![]));
        assert_eq!(empty.subtasks, Some(vec![]));
        assert!(empty.parent.is_none());
    }

    #[test]
    fn standard_context_rejects_malformed_values_without_echoing_payloads() {
        for invalid in [
            json!({}),
            json!({"id": ""}),
            json!({"id": 12}),
            json!({"id": null}),
            json!({"id": "12", "name": false}),
            json!("private"),
            json!([]),
        ] {
            assert_invalid(json!({"resolution": invalid}));
            for field in ["components", "fixVersions", "versions"] {
                assert_invalid(json!({field: [{"id": "good"}, invalid]}));
            }
        }
        for field in ["components", "fixVersions", "versions"] {
            for invalid in [json!({}), json!(false), json!("private"), json!([null])] {
                assert_invalid(json!({field: invalid}));
            }
        }
        for field in ["resolutiondate", "duedate"] {
            for invalid in [
                json!({"private": true}),
                json!(123),
                json!(false),
                json!([]),
            ] {
                assert_invalid(json!({field: invalid}));
            }
        }
        for invalid in [json!("private"), json!([]), json!(false)] {
            assert_invalid(json!({"status": invalid}));
            assert_invalid(json!({"status": {"statusCategory": invalid}}));
        }
        for invalid in [
            json!({}),
            json!({"id": -1, "key": "private"}),
            json!({"id": 1.5, "key": "private"}),
            json!({"id": "1", "key": "private"}),
            json!({"id": 1, "key": ""}),
            json!({"id": 1, "key": 3}),
            json!({"id": 1, "key": "valid", "name": {"private": true}}),
        ] {
            assert_invalid(json!({"status": {"statusCategory": invalid}}));
        }
    }

    #[test]
    fn optional_names_preserve_empty_strings_and_null() {
        for name in [json!(""), json!("Name"), Value::Null] {
            let context = project(
                json!({
                    "resolution": {"id": "r", "name": name},
                    "status": {"statusCategory": {"id": 1, "key": "k", "name": name}},
                }),
                true,
            );
            assert_eq!(json!(context.resolution.unwrap())["name"], name);
            assert_eq!(json!(context.status_category.unwrap())["name"], name);
        }
        let context = project(
            json!({"status": {"statusCategory": {"id": 1, "key": "k"}}}),
            true,
        );
        assert!(context.status_category.unwrap().name.is_none());
    }

    #[test]
    fn hierarchy_projects_only_canonical_reference_metadata_in_order() {
        let reference = json!({
            "id": "private", "key": "OTHER-12", "self": "private",
            "summary": "private", "issueType": "private",
            "fields": {"summary": "Parent summary", "issuetype": {"name": "Epic", "hierarchyLevel": 1, "id": "private"}, "project": {"key": "PRIVATE"}, "status": {"name": "private"}},
        });
        let context = project(
            json!({
                "parent": reference, "subtasks": [reference, {"key": "PROJ-2"}, reference],
                "epic": {"key": "PRIVATE-1"}, "customfield_100": "PRIVATE-2",
            }),
            true,
        );
        let reference =
            json!({"key": "OTHER-12", "summary": "Parent summary", "issueType": "Epic"});
        assert_eq!(json!(context.parent), reference);
        assert_eq!(
            json!(context.subtasks),
            json!([reference, {"key": "PROJ-2", "summary": null, "issueType": null}, reference])
        );
        assert!(!serde_json::to_string(&context).unwrap().contains("private"));
        assert!(
            project(
                json!({"epic": {"key": "PRIVATE-1"}, "customfield_100": "PRIVATE-2"}),
                true
            )
            .parent
            .is_none()
        );
    }

    #[test]
    fn hierarchy_optional_containers_and_metadata_preserve_unavailable_values() {
        for fields in [
            Value::Null,
            json!({}),
            json!({"summary": null, "issuetype": null}),
            json!({"issuetype": {}}),
            json!({"issuetype": {"name": null}}),
        ] {
            let context = project(json!({"parent": {"key": "PROJ-1", "fields": fields}}), true);
            assert_eq!(
                json!(context.parent),
                json!({"key": "PROJ-1", "summary": null, "issueType": null})
            );
        }
        let context = project(
            json!({"parent": {"key": "PROJ-1", "fields": {"summary": "", "issuetype": {"name": ""}}}}),
            true,
        );
        assert_eq!(
            json!(context.parent),
            json!({"key": "PROJ-1", "summary": "", "issueType": ""})
        );
    }

    #[test]
    fn malformed_hierarchy_is_rejected_only_when_disclosure_is_eligible() {
        let malformed = [
            json!({}),
            json!("private"),
            json!([]),
            json!({"key": 12}),
            json!({"key": "private-1"}),
            json!({"key": "PROJ-0"}),
            json!({"key": "PROJ-1/private"}),
            json!({"key": "PROJ-1", "fields": []}),
            json!({"key": "PROJ-1", "fields": {"summary": 42}}),
            json!({"key": "PROJ-1", "fields": {"issuetype": "private"}}),
            json!({"key": "PROJ-1", "fields": {"issuetype": {"name": false}}}),
        ];
        for invalid in malformed {
            assert_invalid(json!({"parent": invalid}));
            assert_invalid(json!({"subtasks": [{"key": "PROJ-1"}, invalid]}));
            assert_eq!(
                project(json!({"parent": invalid, "subtasks": [invalid]}), false),
                JiraIssueViewContext::default()
            );
        }
        for invalid in [
            Value::Null,
            json!({"private": true}),
            json!("private"),
            json!([null]),
        ] {
            assert_invalid(json!({"subtasks": invalid}));
            assert_eq!(
                project(json!({"subtasks": invalid}), false),
                JiraIssueViewContext::default()
            );
        }
    }
}
