//! Operator-only diagnostics for rejected search results. Never retain raw
//! upstream identifiers or query/page-token values in these diagnostics.
use super::{EffectiveSearchScope, JiraIssue, is_issue_key, issue_key_project, sha256_hex};
use serde_json::{Value, json};

pub(super) fn rejected_issue(
    issue: &JiraIssue,
    scope: &EffectiveSearchScope,
    issue_index: usize,
) -> Option<(&'static str, Value)> {
    let key_valid = is_issue_key(&issue.key);
    let project_matches = issue_key_project(&issue.key) == issue.project;
    let project_authorized = scope.authorizes_value(&issue.project);
    // Preserve the existing validation and precedence. Evaluate every check so
    // operators can distinguish overlapping failures without another replay.
    let code = if !key_valid {
        "jira_search_issue_key_invalid"
    } else if !project_matches {
        "jira_search_issue_project_mismatch"
    } else if !project_authorized {
        "jira_search_project_unauthorized"
    } else {
        return None;
    };
    Some((
        code,
        json!({
            "issueIndex": issue_index,
            "issueKeyValid": key_valid,
            "keyProjectMatches": project_matches,
            "projectAuthorized": project_authorized,
            "issueKey": identifier_shape(&issue.key),
            "reportedProject": identifier_shape(&issue.project),
        }),
    ))
}

fn identifier_shape(value: &str) -> Value {
    const MAX_SHAPE_CHARS: usize = 64;
    let shape: String = value
        .chars()
        .take(MAX_SHAPE_CHARS)
        .map(|ch| match ch {
            'A'..='Z' => 'A',
            'a'..='z' => 'a',
            '0'..='9' => '9',
            '-' => '-',
            '_' => '_',
            _ => '?',
        })
        .collect();
    json!({
        "shape": shape,
        "shapeTruncated": value.chars().nth(MAX_SHAPE_CHARS).is_some(),
        "byteLength": value.len(),
        "sha256": sha256_hex(value.as_bytes()),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identifier_diagnostics_mask_and_bound_untrusted_values() {
        let value = format!("Secret_42-\n雪{}", "x".repeat(100));
        let diagnostic = identifier_shape(&value);
        let shape = diagnostic["shape"].as_str().unwrap();
        assert!(shape.starts_with("Aaaaaa_99-??"));
        assert_eq!(shape.len(), 64);
        assert_eq!(diagnostic["shapeTruncated"], true);
        assert_eq!(diagnostic["byteLength"], value.len());
        assert_eq!(diagnostic["sha256"], sha256_hex(value.as_bytes()));
        assert!(!diagnostic.to_string().contains("Secret"));
        assert_eq!(identifier_shape("")["shape"], "");
        assert_eq!(identifier_shape(&"P".repeat(64))["shapeTruncated"], false);
        assert_eq!(identifier_shape(&"P".repeat(65))["shapeTruncated"], true);
    }
}
