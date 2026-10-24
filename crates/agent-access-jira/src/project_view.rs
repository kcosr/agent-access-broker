//! Bounded project search discovery using the selected execution credential.
use super::*;

#[cfg(test)]
#[path = "project_view_tests.rs"]
mod tests;

const ITEM_LIMIT: usize = 100;
const TEXT_LIMIT: usize = 4096;
const SECTIONS: [&str; 5] = ["fields", "versions", "components", "issueTypes", "statuses"];

pub(crate) fn descriptor() -> ActionDescriptor {
    jira_read_action("project.view", "Inspect an authorized Jira project and discover searchable fields and metadata", json!({
        "type":"object", "additionalProperties":false, "required":["project"],
        "properties":{
            "project":{"type":"string","pattern":JIRA_PROJECT_KEY_PATTERN},
            "include":{"type":"array","uniqueItems":true,"maxItems":5,"default":["fields"],"items":{"type":"string","enum":SECTIONS}},
            "query":{"type":"string","minLength":1,"maxLength":256,"description":"Case-insensitive name, ID or JQL reference substring filter for included collections"}
        }
    }))
    .sensitive_output("/result/project/name")
    .sensitive_output("/result/project/description")
    .sensitive_output("/result/fields/items")
    .sensitive_output("/result/versions/items")
    .sensitive_output("/result/components/items")
    .sensitive_output("/result/issueTypes/items")
    .sensitive_output("/result/statuses/items")
    .documentation(json!({
        "discovery":"Project identity is always returned. include defaults to fields; [] requests identity only. Other sections are versions, components, issueTypes and statuses. This is a searchable field catalog, not an inventory of every field context, allowed value, or creation requirement. System fields are site-wide; Jira restricts custom fields to the project.",
        "fields":"Each field has id, name, jqlReference, types and operators. Custom field IDs use customfield_N and JQL references use cf[N]. Operators are the intersection of Jira's reported capabilities and Broker's restricted JQL grammar. Types retain Jira's type names. Text matching (~) is not whole-value equality. Searches remain separately authorized.",
        "limits":"Each included collection contains at most 100 items, with count and truncated. query filters names, IDs and JQL references before the cap; narrow it when truncated is true. Names and descriptions are limited to 4096 UTF-8 bytes, with previewTruncated on shortened objects. HTTP responses and the combined result remain subject to the provider byte cap. No automatic pagination or field-option enumeration occurs.",
        "authorization":"Uses the selected execution credential and Browse Projects access. The current project key must equal the authorized key before any field or status discovery. No lookup credential or create/admin metadata API is used.",
        "examples":[{"project":"PROJ"},{"project":"PROJ","include":["fields","versions"],"query":"external"}]
    }))
}

pub(crate) struct Inputs {
    pub(crate) project: String,
    include: BTreeSet<String>,
    query: Option<String>,
}

fn invalid() -> ProviderError {
    ProviderError::deny(
        ReasonCode::InputInvalid,
        "jira.project.view inputs are invalid",
    )
}

fn protocol() -> ProviderError {
    ProviderError::error(
        ReasonCode::UpstreamProtocolFailed,
        "Jira project discovery response protocol error",
    )
}

pub(crate) fn parse_inputs(value: &Value) -> Result<Inputs, ProviderError> {
    let object = value.as_object().ok_or_else(invalid)?;
    if object
        .keys()
        .any(|key| !matches!(key.as_str(), "project" | "include" | "query"))
    {
        return Err(invalid());
    }
    let project = object
        .get("project")
        .and_then(Value::as_str)
        .filter(|value| is_project_key(value))
        .ok_or_else(invalid)?
        .to_string();
    let mut include = BTreeSet::new();
    match object.get("include") {
        None => {
            include.insert("fields".to_string());
        }
        Some(value) => {
            let values = value.as_array().ok_or_else(invalid)?;
            if values.len() > SECTIONS.len() {
                return Err(invalid());
            }
            for value in values {
                let section = value
                    .as_str()
                    .filter(|section| SECTIONS.contains(section))
                    .ok_or_else(invalid)?;
                if !include.insert(section.to_string()) {
                    return Err(invalid());
                }
            }
        }
    }
    let query = object
        .get("query")
        .map(|value| -> Result<String, ProviderError> {
            let query = value
                .as_str()
                .filter(|query| {
                    !query.trim().is_empty()
                        && query.len() <= 256
                        && !query.chars().any(char::is_control)
                })
                .ok_or_else(invalid)?;
            Ok(query.trim().to_lowercase())
        })
        .transpose()?;
    Ok(Inputs {
        project,
        include,
        query,
    })
}

impl JiraProvider {
    pub(crate) async fn invoke_project_view(
        &self,
        request: ProviderInvocation,
    ) -> Result<ProviderResult, ProviderError> {
        if !request.body_parts().is_empty() {
            return Err(invalid());
        }
        let input = parse_inputs(request.inputs())?;
        ensure_authorized_project_scope(&input.project, request.resource_scopes()?)?;
        let credential = self.execution_credential(request.admitted())?;
        let started = Instant::now();
        let response = self
            .backend
            .project_details(
                &input.project,
                input.include.contains("issueTypes"),
                &credential,
            )
            .await
            .map_err(jira_backend_error)?;
        let project = &response.value;
        // Jira resolves former project keys. Never use a renamed project ID to
        // ask the field endpoint: it ignores invalid IDs and could widen discovery.
        let key = required_string(project, "key")?;
        if key != input.project {
            return Err(ProviderError::deny(
                ReasonCode::ScopeUnresolved,
                "Jira project no longer matches the authorized key",
            ));
        }
        let id = decimal_id(project, "id")?;
        let project_id = id.parse::<u64>().map_err(|_| protocol())?;
        if project_id > i64::MAX as u64 {
            return Err(protocol());
        }
        let mut identity = named_item(project)?;
        identity["key"] = json!(key);
        identity["webUrl"] = json!(format!("https://{}/browse/{key}", self.config.tenant_host));
        preview(&mut identity);
        let mut result = json!({"operation":"project.view","project":identity});
        let mut last_status = response.status;
        for section in &input.include {
            let items = match section.as_str() {
                "fields" => {
                    let fields = self
                        .backend
                        .project_search_fields(project_id, &credential)
                        .await
                        .map_err(jira_backend_error)?;
                    last_status = fields.status;
                    searchable_fields(&fields.value)?
                }
                "statuses" => {
                    let statuses = self
                        .backend
                        .project_statuses(project_id, &credential)
                        .await
                        .map_err(jira_backend_error)?;
                    last_status = statuses.status;
                    project_statuses(&statuses.value)?
                }
                _ => metadata_items(project, section)?,
            };
            result[section] = collection(items, input.query.as_deref())?;
        }
        enforce_result_size(&result, self.limits.max_upstream_response_bytes)?;
        Ok(ProviderResult::new(result)
            .with_audit(json!({"provider":"jira","operation":"project.view","project":input.project,"include":input.include,"credentialMode":request.credential_mode(),"egressProxy":self.backend.egress_proxy_audit(&credential)}))
            .with_upstream(Some(last_status), Some(elapsed_ms(started)))
            .with_object_ids(json!({"project":input.project,"projectId":id})))
    }
}

impl HttpJiraBackend {
    pub(crate) async fn project_view_value(
        &self,
        path: &str,
        expand: Option<&str>,
        body: Option<Value>,
        credential: &AtlassianCredential,
    ) -> Result<JiraBackendResponse<Value>, JiraBackendError> {
        let mut url = self
            .api_base(credential)?
            .join(path)
            .map_err(|_| JiraBackendError::Protocol("invalid project discovery URL".to_string()))?;
        if let Some(expand) = expand {
            url.query_pairs_mut().append_pair("expand", expand);
        }
        let started = Instant::now();
        let client = self.request_client(credential)?;
        let mut request = client
            .request(
                if body.is_some() {
                    Method::POST
                } else {
                    Method::GET
                },
                url,
            )
            .header("Accept", "application/json");
        if let Some(body) = body {
            request = request.json(&body);
        }
        let response = backend::send_jira_request(
            client,
            credential,
            request,
            UpstreamCall::new("project.view"),
        )
        .await?;
        let status = response.status().as_u16();
        let value =
            backend::jira_response_value(response, self.limits.max_upstream_response_bytes).await?;
        Ok(JiraBackendResponse {
            value,
            status,
            duration_ms: elapsed_ms(started),
        })
    }
}

fn required_string<'a>(value: &'a Value, key: &str) -> Result<&'a str, ProviderError> {
    value
        .get(key)
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(protocol)
}

fn decimal_id(value: &Value, key: &str) -> Result<String, ProviderError> {
    let id = required_string(value, key)?;
    if id.len() > 20
        || id.starts_with('0')
        || !id.bytes().all(|c| c.is_ascii_digit())
        || id.parse::<u64>().is_err()
    {
        return Err(protocol());
    }
    Ok(id.to_string())
}

fn named_item(value: &Value) -> Result<Value, ProviderError> {
    let description = match value.get("description") {
        None => "",
        Some(value) => value.as_str().ok_or_else(protocol)?,
    };
    Ok(
        json!({"id":decimal_id(value,"id")?,"name":required_string(value,"name")?,"description":description}),
    )
}

fn metadata_items(project: &Value, section: &str) -> Result<Vec<Value>, ProviderError> {
    let values = project
        .get(section)
        .and_then(Value::as_array)
        .ok_or_else(protocol)?;
    values
        .iter()
        .map(|value| {
            let mut item = named_item(value)?;
            match section {
                "versions" => {
                    for field in ["released", "archived"] {
                        item[field] = json!(
                            value
                                .get(field)
                                .and_then(Value::as_bool)
                                .ok_or_else(protocol)?
                        );
                    }
                    for field in ["releaseDate", "startDate"] {
                        if let Some(date) = value.get(field) {
                            let date = date
                                .as_str()
                                .filter(|date| {
                                    date.len() == 10
                                        && date.bytes().enumerate().all(|(index, c)| {
                                            if matches!(index, 4 | 7) {
                                                c == b'-'
                                            } else {
                                                c.is_ascii_digit()
                                            }
                                        })
                                })
                                .ok_or_else(protocol)?;
                            item[field] = json!(date);
                        }
                    }
                }
                "issueTypes" => {
                    item["subtask"] = json!(
                        value
                            .get("subtask")
                            .and_then(Value::as_bool)
                            .ok_or_else(protocol)?
                    );
                }
                "components" => {}
                _ => return Err(protocol()),
            }
            Ok(item)
        })
        .collect()
}

fn project_statuses(value: &Value) -> Result<Vec<Value>, ProviderError> {
    let mut items = vec![];
    for issue_type in value.as_array().ok_or_else(protocol)? {
        decimal_id(issue_type, "id")?;
        for status in issue_type
            .get("statuses")
            .and_then(Value::as_array)
            .ok_or_else(protocol)?
        {
            let mut item = named_item(status)?;
            if let Some(category) = status.get("statusCategory") {
                let id = category
                    .get("id")
                    .and_then(Value::as_u64)
                    .filter(|id| *id > 0)
                    .ok_or_else(protocol)?;
                let key = required_string(category, "key")?;
                if key.len() > 256 {
                    return Err(protocol());
                }
                item["statusCategory"] =
                    json!({"id":id,"key":key,"name":required_string(category,"name")?});
            }
            items.push(item);
        }
    }
    Ok(items)
}

fn searchable_fields(value: &Value) -> Result<Vec<Value>, ProviderError> {
    let values = value
        .get("visibleFieldNames")
        .and_then(Value::as_array)
        .ok_or_else(protocol)?;
    let mut items = vec![];
    for value in values {
        let searchable = match value.get("searchable") {
            None | Some(Value::String(_)) => value.get("searchable").and_then(Value::as_str),
            _ => return Err(protocol()),
        };
        match searchable {
            Some("false") => continue,
            None | Some("true") => {}
            _ => return Err(protocol()),
        }
        let reference = match value.get("cfid") {
            Some(value) => value.as_str().ok_or_else(protocol)?,
            None => required_string(value, "value")?,
        };
        let Some((reference, supported)) = jql::jql_field_capabilities(reference) else {
            continue;
        };
        // A custom descriptor must carry an explicit cf[N] identity; human names
        // and collapsed fields are deliberately never interpreted as aliases.
        if value.get("cfid").is_some() && !reference.starts_with("cf[") {
            return Err(protocol());
        }
        let id = if let Some(id) = reference
            .strip_prefix("cf[")
            .and_then(|id| id.strip_suffix(']'))
        {
            format!("customfield_{id}")
        } else {
            match reference.as_str() {
                "component" => "components",
                "fixVersion" => "fixVersions",
                "affectedVersion" => "versions",
                other => other,
            }
            .to_string()
        };
        let reported = string_array(value, "operators", 32, 32)?;
        let reported: BTreeSet<_> = reported
            .iter()
            .map(
                |operator| match operator.trim().to_ascii_uppercase().as_str() {
                    "IS" => "IS EMPTY".to_string(),
                    "IS NOT" => "IS NOT EMPTY".to_string(),
                    other => other.to_string(),
                },
            )
            .collect();
        let operators: Vec<_> = supported
            .into_iter()
            .filter(|operator| reported.contains(*operator))
            .collect();
        if operators.is_empty() {
            continue;
        }
        let types = string_array(value, "types", 16, 256)?;
        if types.is_empty() {
            return Err(protocol());
        }
        items.push(json!({"id":id,"name":required_string(value,"displayName")?,"jqlReference":reference,"types":types,"operators":operators}));
    }
    Ok(items)
}

fn string_array<'a>(
    value: &'a Value,
    field: &str,
    count_limit: usize,
    length_limit: usize,
) -> Result<Vec<&'a str>, ProviderError> {
    let items = value
        .get(field)
        .and_then(Value::as_array)
        .filter(|items| items.len() <= count_limit)
        .ok_or_else(protocol)?;
    items
        .iter()
        .map(|item| {
            item.as_str()
                .filter(|item| {
                    !item.is_empty()
                        && item.len() <= length_limit
                        && !item.chars().any(char::is_control)
                })
                .ok_or_else(protocol)
        })
        .collect()
}

fn collection(items: Vec<Value>, query: Option<&str>) -> Result<Value, ProviderError> {
    let mut seen = BTreeMap::new();
    let mut selected = vec![];
    let mut truncated = false;
    for mut item in items {
        let id = required_string(&item, "id")?.to_string();
        if let Some(previous) = seen.insert(id, item.clone()) {
            if previous != item {
                return Err(protocol());
            }
            continue;
        }
        if query.is_some_and(|query| {
            !["name", "id", "jqlReference"]
                .iter()
                .filter_map(|field| item.get(field).and_then(Value::as_str))
                .any(|text| text.to_lowercase().contains(query))
        }) {
            continue;
        }
        if selected.len() == ITEM_LIMIT {
            truncated = true;
            continue;
        }
        preview(&mut item);
        selected.push(item);
    }
    Ok(json!({"count":selected.len(),"items":selected,"truncated":truncated}))
}

fn preview(value: &mut Value) {
    let mut truncated = false;
    for field in ["name", "description"] {
        if let Some(Value::String(text)) = value.get_mut(field)
            && text.len() > TEXT_LIMIT
        {
            let mut end = TEXT_LIMIT;
            while !text.is_char_boundary(end) {
                end -= 1;
            }
            text.truncate(end);
            truncated = true;
        }
    }
    if let Some(category) = value.get_mut("statusCategory") {
        preview(category);
    }
    if truncated {
        value["previewTruncated"] = json!(true);
    }
}
