//! Issue-specific workflow discovery and one explicitly selected transition.
use super::*;

pub(super) const RESPONSE_BYTE_LIMIT: u64 = 1024 * 1024;
const ITEM_LIMIT: usize = 100;
const TEXT_LIMIT: usize = 1024;
const ID_LIMIT: usize = 64;

pub(super) static UNAVAILABLE: ProviderReasonDefinition = ProviderReasonDefinition::deny(
    "jira_transition_unavailable",
    ProviderFailureStatus::Conflict,
);
pub(super) static REJECTED: ProviderReasonDefinition = ProviderReasonDefinition::deny(
    "jira_transition_rejected",
    ProviderFailureStatus::BadRequest,
);

pub(super) fn descriptors() -> [ActionDescriptor; 2] {
    let locator = json!({"type":["string","null"], "description":"Issue key. Give exactly one non-null issue or url."});
    let url = json!({"type":["string","null"], "description":"Issue web URL. Give exactly one non-null issue or url."});
    let id = json!({"type":"string", "pattern":"^[1-9][0-9]*$", "maxLength":ID_LIMIT});
    [
        jira_read_action(
            "issue.transition.list",
            "List the workflow transitions currently available for a Jira issue",
            json!({
                "type":"object", "additionalProperties":false,
                "properties":{
                    "issue":locator, "url":url,
                    "includeFields":{"type":"boolean", "default":false, "description":"Include bounded transition-screen requirements and resolution choices. Requirements do not guarantee that Jira will accept a transition."}
                }
            }),
        )
        .lookup(LookupRequirement::ScopeResolution)
        .audit_input("issue", "Issue")
        .audit_input("url", "URL")
        .audit_input("includeFields", "Include fields")
        .sensitive_output("/result/currentStatus")
        .sensitive_output("/result/transitions"),
        jira_action(
            "issue.transition.apply",
            "Apply one available Jira workflow transition to an explicitly selected destination status",
            json!({
                "type":"object", "additionalProperties":false,
                "required":["transitionId","toStatusId"],
                "properties":{
                    "issue":locator, "url":url,
                    "transitionId":with_description(&id, "Transition ID from issue.transition.list for this issue."),
                    "toStatusId":with_description(&id, "Destination status ID from the selected transition. Rechecked before sending; not an atomic guard."),
                    "expectedIssueId":with_description(&id, "Optional immutable issue ID to confirm before writing."),
                    "expectedStatusId":with_description(&id, "Optional current-status check before writing. Does not establish safe replay after an uncertain result."),
                    "resolutionId":with_description(&id, "Optional resolution ID. The only submitted transition-screen field; Jira validates whether it is allowed and required.")
                }
            }),
        )
        .lookup(LookupRequirement::ScopeResolution)
        .audit_input("issue", "Issue")
        .audit_input("url", "URL")
        .audit_input("transitionId", "Transition ID")
        .audit_input("toStatusId", "Destination status ID")
        .audit_input("expectedIssueId", "Expected issue ID")
        .audit_input("expectedStatusId", "Expected status ID")
        .audit_input("resolutionId", "Resolution ID")
        .sensitive_output("/result/verification/observedStatus"),
    ]
}

fn with_description(schema: &Value, description: &str) -> Value {
    let mut schema = schema.clone();
    schema["description"] = json!(description);
    schema
}

pub(super) struct ListInputs {
    pub(super) locator: IssueLocator,
    include_fields: bool,
}

pub(super) fn parse_list(
    inputs: &Value,
    config: &JiraProviderConfig,
) -> Result<ListInputs, ProviderError> {
    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase", deny_unknown_fields)]
    struct Raw {
        issue: Option<String>,
        url: Option<String>,
        #[serde(default)]
        include_fields: bool,
    }
    let raw: Raw = serde_json::from_value(inputs.clone())
        .map_err(|_| invalid("jira.issue.transition.list inputs are invalid"))?;
    Ok(ListInputs {
        locator: issue_locator_from_optional(
            raw.issue,
            raw.url,
            config,
            "jira.issue.transition.list",
            ("issue", "url"),
        )?,
        include_fields: raw.include_fields,
    })
}

pub(super) struct ApplyInputs {
    pub(super) locator: IssueLocator,
    transition_id: String,
    to_status_id: String,
    expected_issue_id: Option<String>,
    expected_status_id: Option<String>,
    resolution_id: Option<String>,
}

pub(super) fn parse_apply(
    inputs: &Value,
    config: &JiraProviderConfig,
) -> Result<ApplyInputs, ProviderError> {
    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase", deny_unknown_fields)]
    struct Raw {
        issue: Option<String>,
        url: Option<String>,
        transition_id: String,
        to_status_id: String,
        expected_issue_id: Option<String>,
        expected_status_id: Option<String>,
        resolution_id: Option<String>,
    }
    for key in [
        "transitionId",
        "toStatusId",
        "expectedIssueId",
        "expectedStatusId",
        "resolutionId",
    ] {
        if let Some(value) = inputs.get(key)
            && !value.as_str().is_some_and(is_id)
        {
            return Err(invalid(
                "Jira transition IDs and status, issue and resolution IDs must be positive decimal strings of at most 64 bytes",
            ));
        }
    }
    let raw: Raw = serde_json::from_value(inputs.clone()).map_err(|_| {
        invalid("jira.issue.transition.apply requires transitionId, toStatusId and valid inputs")
    })?;
    Ok(ApplyInputs {
        locator: issue_locator_from_optional(
            raw.issue,
            raw.url,
            config,
            "jira.issue.transition.apply",
            ("issue", "url"),
        )?,
        transition_id: raw.transition_id,
        to_status_id: raw.to_status_id,
        expected_issue_id: raw.expected_issue_id,
        expected_status_id: raw.expected_status_id,
        resolution_id: raw.resolution_id,
    })
}

fn invalid(message: &'static str) -> ProviderError {
    ProviderError::deny(ReasonCode::InputInvalid, message)
}

fn protocol() -> ProviderError {
    ProviderError::error(
        ReasonCode::UpstreamProtocolFailed,
        "Jira transition metadata is malformed or exceeds its bounds",
    )
}

fn unavailable() -> ProviderError {
    ProviderError::domain(
        &UNAVAILABLE,
        "Jira transition is unavailable or its destination or expected current status changed; rediscover before choosing a transition",
    )
}

fn is_id(value: &str) -> bool {
    value.len() <= ID_LIMIT
        && matches!(value.as_bytes().first(), Some(b'1'..=b'9'))
        && value.bytes().all(|byte| byte.is_ascii_digit())
}

fn id(value: &Value) -> Result<&str, ProviderError> {
    value
        .as_str()
        .filter(|value| is_id(value))
        .ok_or_else(protocol)
}

fn name(value: &Value) -> Result<&str, ProviderError> {
    value
        .as_str()
        .filter(|value| !value.is_empty() && value.len() <= TEXT_LIMIT)
        .ok_or_else(protocol)
}

fn status(value: &Value) -> Result<Value, ProviderError> {
    let category = match value.get("statusCategory") {
        None | Some(Value::Null) => Value::Null,
        Some(category) => json!({
            "id":category.get("id").and_then(Value::as_u64).ok_or_else(protocol)?,
            "key":name(&category["key"])?,
            "name":name(&category["name"])?,
        }),
    };
    Ok(json!({"id":id(&value["id"])?, "name":name(&value["name"])?, "statusCategory":category}))
}

fn confirmed_status(value: Value, expected: &JiraIssueMetadata) -> Result<Value, ProviderError> {
    let metadata = backend::issue_metadata_from_value(value.clone()).map_err(jira_backend_error)?;
    if !is_id(&metadata.id)
        || !is_issue_key(&metadata.key)
        || issue_key_project(&metadata.key) != metadata.project
    {
        return Err(protocol());
    }
    if metadata.id != expected.id
        || metadata.key != expected.key
        || metadata.project != expected.project
    {
        return Err(ProviderError::deny(
            ReasonCode::ScopeUnresolved,
            "Jira issue response did not match confirmed metadata",
        ));
    }
    status(&value["fields"]["status"])
}

fn optional_bool(value: &Value, key: &str) -> Result<Value, ProviderError> {
    match value.get(key) {
        None => Ok(Value::Null),
        Some(Value::Bool(value)) => Ok(json!(value)),
        _ => Err(protocol()),
    }
}

fn transition(value: &Value, include_fields: bool) -> Result<Value, ProviderError> {
    let mut result = json!({
        "id":id(&value["id"])?, "name":name(&value["name"])?,
        "to":status(&value["to"])?, "hasScreen":optional_bool(value, "hasScreen")?,
    });
    if include_fields {
        let fields = match value.get("fields") {
            None | Some(Value::Null) => {
                result["fields"] = Value::Null;
                return Ok(result);
            }
            Some(fields) => fields.as_object().ok_or_else(protocol)?,
        };
        let mut items = Vec::new();
        // Keep the one supported submitted field discoverable even on large screens.
        let ordered = fields
            .get("resolution")
            .map(|field| ("resolution", field))
            .into_iter()
            .chain(
                fields
                    .iter()
                    .filter(|(key, _)| key.as_str() != "resolution")
                    .map(|(key, field)| (key.as_str(), field)),
            );
        for (key, field) in ordered.take(ITEM_LIMIT) {
            if key.is_empty()
                || key.len() > 128
                || !key.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
            {
                return Err(protocol());
            }
            let mut item = json!({
                "id":key, "name":name(&field["name"])?,
                "required":field.get("required").and_then(Value::as_bool).ok_or_else(protocol)?,
                "hasDefaultValue":optional_bool(field, "hasDefaultValue")?,
                "brokerInput":if key == "resolution" { json!("resolutionId") } else { Value::Null },
            });
            if key == "resolution"
                && let Some(choices) = field.get("allowedValues")
            {
                let choices = choices.as_array().ok_or_else(protocol)?;
                let values = choices
                    .iter()
                    .take(ITEM_LIMIT)
                    .map(|choice| {
                        Ok(json!({"id":id(&choice["id"])?, "name":name(&choice["name"])?}))
                    })
                    .collect::<Result<Vec<_>, ProviderError>>()?;
                item["allowedValues"] = collection(values, choices.len());
            }
            items.push(item);
        }
        result["fields"] = collection(items, fields.len());
    }
    Ok(result)
}

fn collection(items: Vec<Value>, total: usize) -> Value {
    json!({"count":items.len(), "truncated":total > items.len(), "items":items})
}

fn transitions(value: &Value) -> Result<&Vec<Value>, ProviderError> {
    value
        .get("transitions")
        .and_then(Value::as_array)
        .ok_or_else(protocol)
}

impl JiraProvider {
    pub(super) async fn invoke_transition_list(
        &self,
        request: ProviderInvocation,
    ) -> Result<ProviderResult, ProviderError> {
        let inputs = parse_list(request.inputs(), &self.config)?;
        let credential = self.execution_credential(request.admitted())?;
        let lookup = self.lookup_credential(request.admitted())?;
        let confirmed = self
            .confirm_authorized_issue(&inputs.locator, &lookup, request.resource_scopes()?)
            .await?;
        let metadata = confirmed.value;
        if !is_id(&metadata.id) {
            return Err(protocol());
        }
        let current = self
            .backend
            .issue_status(&metadata.id, &credential)
            .await
            .map_err(jira_backend_error)?;
        let current_status = confirmed_status(current.value, &metadata)?;
        let response = self
            .backend
            .issue_transitions(&metadata.id, inputs.include_fields, None, &credential)
            .await
            .map_err(jira_backend_error)?;
        let values = transitions(&response.value)?;
        let mut seen = BTreeSet::new();
        let items = values
            .iter()
            .take(ITEM_LIMIT)
            .map(|value| {
                let item = transition(value, inputs.include_fields)?;
                if !seen.insert(item["id"].as_str().ok_or_else(protocol)?.to_owned()) {
                    return Err(protocol());
                }
                Ok(item)
            })
            .collect::<Result<Vec<_>, ProviderError>>()?;
        let result = json!({
            "operation":"issue.transition.list", "issue":issue_metadata_result(&metadata, &self.config),
            "currentStatus":current_status, "count":items.len(), "truncated":values.len() > items.len(), "transitions":items,
        });
        enforce_result_size(&result, self.limits.max_upstream_response_bytes)?;
        Ok(ProviderResult::new(result)
            .with_audit(json!({"provider":"jira", "operation":"issue.transition.list", "issueId":metadata.id, "issueKey":metadata.key, "project":metadata.project, "includeFields":inputs.include_fields, "credentialMode":request.credential_mode(), "egressProxy":self.backend.egress_proxy_audit(&credential)}))
            .with_upstream(Some(response.status), Some(confirmed.duration_ms + current.duration_ms + response.duration_ms))
            .with_object_ids(json!({"issueId":metadata.id, "issueKey":metadata.key})))
    }

    pub(super) async fn invoke_transition_apply(
        &self,
        request: ProviderInvocation,
    ) -> Result<ProviderResult, ProviderError> {
        let inputs = parse_apply(request.inputs(), &self.config)?;
        let credential = self.execution_credential(request.admitted())?;
        let lookup = self.lookup_credential(request.admitted())?;
        let confirmed = self
            .confirm_authorized_issue(&inputs.locator, &lookup, request.resource_scopes()?)
            .await?;
        let metadata = confirmed.value;
        if !is_id(&metadata.id) {
            return Err(protocol());
        }
        if inputs
            .expected_issue_id
            .as_ref()
            .is_some_and(|id| id != &metadata.id)
        {
            return Err(ProviderError::deny(
                ReasonCode::ScopeUnresolved,
                "Jira issue identity no longer matches expectedIssueId",
            ));
        }
        let current = self
            .backend
            .issue_status(&metadata.id, &credential)
            .await
            .map_err(jira_backend_error)?;
        let from = confirmed_status(current.value, &metadata)?;
        if inputs
            .expected_status_id
            .as_deref()
            .is_some_and(|expected| from["id"] != expected)
        {
            return Err(unavailable());
        }
        let offered = self
            .backend
            .issue_transitions(
                &metadata.id,
                false,
                Some(&inputs.transition_id),
                &credential,
            )
            .await
            .map_err(jira_backend_error)?;
        let choices = transitions(&offered.value)?;
        if choices.len() > 1 {
            return Err(protocol());
        }
        let selected = choices.first().ok_or_else(unavailable)?;
        if id(&selected["id"])? != inputs.transition_id
            || id(&selected["to"]["id"])? != inputs.to_status_id
        {
            return Err(unavailable());
        }
        if optional_bool(selected, "isAvailable")? == Value::Bool(false) {
            return Err(unavailable());
        }
        let write = JiraWrite::new(
            json!({"issueId":metadata.id, "issueKey":metadata.key, "transitionId":inputs.transition_id, "toStatusId":inputs.to_status_id}),
        );
        let response = self.backend.transition_issue(&metadata.id, &inputs.transition_id, inputs.resolution_id.as_deref(), &credential).await.map_err(|error| match error {
            JiraBackendError::HttpStatus(status @ (400 | 422)) | JiraBackendError::Validation { status: status @ (400 | 422), .. } => ProviderError::domain(&REJECTED, "Jira rejected the transition; check workflow permissions, requirements and any resolution value. Other submitted transition fields are not supported").with_upstream(Some(status), None),
            JiraBackendError::HttpStatus(409) => unavailable().with_upstream(Some(409), None),
            error => write.failed(error),
        })?;
        after_accepted_write("post_transition_readback", write.locators(), async {
            let readback = self.backend.issue_status(&metadata.id, &credential).await.map_err(jira_backend_error)?;
            let observed = confirmed_status(readback.value, &metadata)?;
            let verification = if observed["id"] == inputs.to_status_id { "matched" } else { "differs" };
            let result = json!({
                "operation":"issue.transition.apply", "issue":issue_metadata_result(&metadata, &self.config),
                "status":"transitioned", "transitionId":inputs.transition_id, "fromStatusId":from["id"], "toStatusId":inputs.to_status_id,
                "verification":{"status":verification, "observedStatus":observed},
            });
            enforce_result_size(&result, self.limits.max_upstream_response_bytes)?;
            Ok(ProviderResult::new(result)
                .with_audit(json!({"provider":"jira", "operation":"issue.transition.apply", "issueId":metadata.id, "issueKey":metadata.key, "project":metadata.project, "transitionId":inputs.transition_id, "fromStatusId":from["id"], "toStatusId":inputs.to_status_id, "observedStatusId":observed["id"], "verificationStatus":verification, "changedFields":if inputs.resolution_id.is_some() { vec!["resolution"] } else { vec![] }, "credentialMode":request.credential_mode(), "egressProxy":self.backend.egress_proxy_audit(&credential)}))
                .with_upstream(Some(response.status), Some(confirmed.duration_ms + current.duration_ms + offered.duration_ms + response.duration_ms + readback.duration_ms))
                .with_object_ids(write.locators()))
        }).await
    }
}
