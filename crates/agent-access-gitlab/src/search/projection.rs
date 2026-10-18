//! Allowlisted, current-owner projections. URLs carry no authority.
use super::*;
use serde_json::Map;

pub(super) struct Project {
    pub id: u64,
    pub path: String,
    pub archived: Option<bool>,
}
impl Project {
    pub fn parse(value: &Value) -> Result<Self, ProviderError> {
        let id = positive(value, "id")?;
        let path = string(value, "path_with_namespace")?;
        if !is_canonical_repository_path(path) {
            return Err(protocol());
        }
        let archived = match value.get("archived") {
            None | Some(Value::Null) => None,
            Some(value) => Some(value.as_bool().ok_or_else(protocol)?),
        };
        Ok(Self {
            id,
            path: path.to_owned(),
            archived,
        })
    }
}
pub(super) fn positive(value: &Value, key: &str) -> Result<u64, ProviderError> {
    value
        .get(key)
        .and_then(Value::as_u64)
        .filter(|v| *v > 0)
        .ok_or_else(protocol)
}
fn string<'a>(value: &'a Value, key: &str) -> Result<&'a str, ProviderError> {
    value
        .get(key)
        .and_then(Value::as_str)
        .filter(|v| !v.is_empty())
        .ok_or_else(protocol)
}
fn optional_string<'a>(value: &'a Value, key: &str) -> Result<Option<&'a str>, ProviderError> {
    match value.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(v) => v.as_str().map(Some).ok_or_else(protocol),
    }
}
fn preview(output: &mut Map<String, Value>, key: &str, text: Option<&str>) {
    let Some(text) = text else {
        return;
    };
    let mut end = text.len().min(4096);
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    output.insert(key.into(), json!(&text[..end]));
    output.insert("previewTruncated".into(), json!(end < text.len()));
}
fn field(
    output: &mut Map<String, Value>,
    name: &str,
    value: &Value,
    source: &str,
) -> Result<(), ProviderError> {
    if let Some(text) = optional_string(value, source)? {
        output.insert(name.into(), json!(text));
    }
    Ok(())
}
fn sha(value: &str) -> bool {
    matches!(value.len(), 40 | 64) && value.bytes().all(|v| v.is_ascii_hexdigit())
}
fn relative_path(path: &str) -> bool {
    !path.is_empty()
        && path.len() <= 4096
        && !path.contains('\0')
        && path
            .split('/')
            .all(|segment| !segment.is_empty() && segment != "." && segment != "..")
}
fn ref_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 1024
        && !value.chars().any(char::is_control)
        && !value.contains(['\\', '?'])
        && value
            .split('/')
            .all(|s| !s.is_empty() && s != "." && s != "..")
}
fn expected_url(config: &GitlabProviderConfig, project: &Project, route: &[&str]) -> Option<Url> {
    // Legal Git path data can contain controls, but it is not safe locator
    // material. Keep the projected data and omit only its optional locator.
    if route
        .iter()
        .any(|segment| segment.chars().any(char::is_control))
    {
        return None;
    }
    let mut url = Url::parse(&config.web_base_url).ok()?;
    if !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return None;
    }
    url.path_segments_mut()
        .ok()?
        .pop_if_empty()
        .extend(project.path.split('/'))
        .extend(route.iter().copied());
    Some(url)
}
fn valid_url(value: &str, expected: &Url) -> bool {
    let Ok(url) = Url::parse(value) else {
        return false;
    };
    if url.origin() != expected.origin()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment() != expected.fragment()
    {
        return false;
    }
    // Decode each segment separately. Encoded slashes may only appear where the
    // confirmed structured object itself has a slash inside that one segment.
    let segments = |url: &Url| -> Option<Vec<String>> {
        url.path_segments()?
            .map(|v| {
                percent_encoding::percent_decode_str(v)
                    .decode_utf8()
                    .ok()
                    .map(|v| v.into_owned())
            })
            .collect()
    };
    segments(&url).is_some_and(|parts| Some(parts) == segments(expected))
}
fn locator(
    output: &mut Map<String, Value>,
    value: &Value,
    config: &GitlabProviderConfig,
    project: &Project,
    route: &[&str],
    fragment: Option<String>,
) {
    let Some(mut expected) = expected_url(config, project, route) else {
        return;
    };
    expected.set_fragment(fragment.as_deref());
    // A supplied, contradictory locator is omitted. Missing locators may be
    // constructed only from this category's confirmed structured identifiers.
    match value.get("web_url") {
        None | Some(Value::Null) => {
            output.insert("webUrl".into(), json!(expected.as_str()));
        }
        Some(Value::String(raw)) if valid_url(raw, &expected) => {
            output.insert("webUrl".into(), json!(expected.as_str()));
        }
        _ => {}
    }
}
fn base(project: &Project) -> Map<String, Value> {
    Map::from_iter([
        ("project".into(), json!(project.path)),
        ("projectId".into(), json!(project.id)),
    ])
}
pub(super) fn project_item(
    value: &Value,
    project: &Project,
    config: &GitlabProviderConfig,
) -> Result<Value, ProviderError> {
    let mut out = base(project);
    out.insert("id".into(), json!(project.id));
    field(&mut out, "name", value, "name")?;
    field(&mut out, "defaultBranch", value, "default_branch")?;
    field(&mut out, "visibility", value, "visibility")?;
    if let Some(archived) = project.archived {
        out.insert("archived".into(), json!(archived));
    }
    preview(
        &mut out,
        "description",
        optional_string(value, "description")?,
    );
    locator(&mut out, value, config, project, &[], None);
    Ok(Value::Object(out))
}

pub(super) fn owner(action: &str, value: &Value) -> Result<Option<u64>, ProviderError> {
    if !value.is_object() {
        return Err(protocol());
    }
    if action == "search.wiki" && value.get("group_id").is_some_and(|v| !v.is_null()) {
        positive(value, "group_id")?;
        if value.get("project_id").is_some_and(|v| !v.is_null()) {
            return Err(protocol());
        }
        return Ok(None);
    }
    if action == "search.comments" {
        let kind = string(value, "noteable_type")?;
        if !["Issue", "MergeRequest", "Commit", "Snippet"].contains(&kind) {
            return Err(protocol());
        }
        // Project-less snippet notes are a recognized personal-snippet kind.
        if kind == "Snippet" && value.get("project_id").is_none_or(Value::is_null) {
            return Ok(None);
        }
    }
    let project = positive(value, "project_id")?;
    if action == "search.merge_requests"
        && value.get("target_project_id").is_some_and(|v| !v.is_null())
        && positive(value, "target_project_id")? != project
    {
        return Err(protocol());
    }
    Ok(Some(project))
}
pub(super) fn content_item(
    action: &str,
    value: &Value,
    project: &Project,
    config: &GitlabProviderConfig,
) -> Result<Value, ProviderError> {
    let mut out = base(project);
    match action {
        "search.issues" | "search.merge_requests" => {
            let id = positive(value, "id")?;
            let iid = positive(value, "iid")?;
            out.insert("id".into(), json!(id));
            out.insert("iid".into(), json!(iid));
            out.insert("title".into(), json!(string(value, "title")?));
            out.insert("state".into(), json!(string(value, "state")?));
            preview(
                &mut out,
                "descriptionPreview",
                optional_string(value, "description")?,
            );
            let category = if action == "search.issues" {
                "issues"
            } else {
                "merge_requests"
            };
            locator(
                &mut out,
                value,
                config,
                project,
                &["-", category, &iid.to_string()],
                None,
            );
        }
        "search.code" => {
            let path = string(value, "path")?;
            if !relative_path(path) {
                return Err(protocol());
            }
            out.insert("path".into(), json!(path));
            let reference = optional_string(value, "ref")?;
            if let Some(reference) = reference {
                if !ref_name(reference) {
                    return Err(protocol());
                }
                out.insert("ref".into(), json!(reference));
            }
            if let Some(start) = value.get("startline") {
                let start = start.as_u64().filter(|v| *v > 0).ok_or_else(protocol)?;
                out.insert("startLine".into(), json!(start));
            }
            preview(&mut out, "snippet", optional_string(value, "data")?);
            out.insert("snippetSource".into(), json!("upstream"));
            if let Some(reference) = reference {
                let mut route = vec!["-", "blob", reference];
                route.extend(path.split('/'));
                locator(&mut out, value, config, project, &route, None);
            }
        }
        "search.commits" => {
            let id = string(value, "id")?;
            if !sha(id) {
                return Err(protocol());
            }
            out.insert("id".into(), json!(id));
            // Git commits may deliberately have an empty message and title.
            let title = value
                .get("title")
                .and_then(Value::as_str)
                .ok_or_else(protocol)?;
            out.insert("title".into(), json!(title));
            preview(
                &mut out,
                "messagePreview",
                optional_string(value, "message")?,
            );
            locator(&mut out, value, config, project, &["-", "commit", id], None);
        }
        "search.wiki" => {
            let path = optional_string(value, "path")?;
            if let Some(path) = path {
                if !relative_path(path) {
                    return Err(protocol());
                }
                out.insert("path".into(), json!(path));
            }
            field(&mut out, "title", value, "title")?;
            preview(&mut out, "snippet", optional_string(value, "data")?);
            out.insert("snippetSource".into(), json!("upstream"));
            // Wiki file paths may have format extensions or home-page aliases;
            // only a supplied locator with the exact reviewed path is retained.
            if let Some(path) = path
                && value.get("web_url").is_some_and(Value::is_string)
            {
                let mut route = vec!["-", "wikis"];
                route.extend(path.split('/'));
                locator(&mut out, value, config, project, &route, None);
            }
        }
        "search.comments" => {
            let id = positive(value, "id")?;
            let kind = string(value, "noteable_type")?;
            if !["Issue", "MergeRequest", "Commit", "Snippet"].contains(&kind) {
                return Err(protocol());
            }
            out.insert("id".into(), json!(id));
            out.insert("parentKind".into(), json!(kind));
            preview(&mut out, "bodyPreview", optional_string(value, "body")?);
            let parent = match kind {
                "Issue" | "MergeRequest" => value
                    .get("noteable_iid")
                    .and_then(Value::as_u64)
                    .filter(|v| *v > 0)
                    .map(|v| v.to_string()),
                "Snippet" => value
                    .get("noteable_id")
                    .and_then(Value::as_u64)
                    .filter(|v| *v > 0)
                    .map(|v| v.to_string()),
                // The Search API entity exposes no reviewed parent SHA. Its
                // commit_id is an MR diff-note field, not a Commit parent.
                "Commit" => None,
                _ => None,
            };
            if let Some(parent) = parent {
                let route = match kind {
                    "Issue" => "issues",
                    "MergeRequest" => "merge_requests",
                    "Snippet" => "snippets",
                    _ => "commit",
                };
                locator(
                    &mut out,
                    value,
                    config,
                    project,
                    &["-", route, &parent],
                    Some(format!("note_{id}")),
                );
            }
        }
        _ => return Err(protocol()),
    }
    Ok(Value::Object(out))
}
