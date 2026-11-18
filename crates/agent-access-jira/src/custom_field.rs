//! Acknowledgement-only writes to one operator-allowlisted custom field.
use super::*;

pub(super) static NOT_ALLOWED: ProviderReasonDefinition = ProviderReasonDefinition::deny(
    "jira_custom_field_not_allowed",
    ProviderFailureStatus::Forbidden,
);
pub(super) static REJECTED: ProviderReasonDefinition = ProviderReasonDefinition::deny(
    "jira_custom_field_rejected",
    ProviderFailureStatus::BadRequest,
);

pub(super) fn descriptor(config: &JiraCustomFieldsConfig) -> ActionDescriptor {
    jira_action(
        "issue.custom_field.set",
        "Set or clear one allowlisted Jira custom field using its JSON value",
        json!({
            "type": "object",
            "required": ["fieldId", "value"],
            "properties": {
                "issue": {"type": ["string", "null"], "description": "Issue key. Give exactly one non-null issue or url."},
                "url": {"type": ["string", "null"], "description": "Issue web URL. Give exactly one non-null issue or url."},
                "fieldId": {"type": "string", "pattern": "^customfield_[1-9][0-9]*$", "description": "Configured writable custom-field ID."},
                "expectedIssueId": {"type": "string", "pattern": "^[1-9][0-9]*$", "description": "Optional immutable Jira issue ID to confirm before writing when a remembered issue key may have moved or been reused."},
                "value": {"description": "Required JSON value, including null to clear if Jira permits it. Sent without conversion. Its serialized JSON must fit content.max_body_bytes. Jira validates the field type, context and editability."}
            },
            "additionalProperties": false
        }),
    )
    .lookup(LookupRequirement::ScopeResolution)
    .documentation(json!({"allowedFieldIds": config.allowed_field_ids}))
    .audit_input("issue", "Issue")
    .audit_input("url", "URL")
    .audit_input("fieldId", "Field ID")
}

pub(super) struct Inputs {
    pub(super) locator: IssueLocator,
    field_id: String,
    value: Value,
    expected_issue_id: Option<String>,
}

pub(super) fn parse_inputs(
    inputs: &Value,
    config: &JiraProviderConfig,
) -> Result<Inputs, ProviderError> {
    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase", deny_unknown_fields)]
    struct RawInputs {
        issue: Option<String>,
        url: Option<String>,
        field_id: String,
        value: Value,
        expected_issue_id: Option<String>,
    }
    // Value's deserializer accepts a missing property as null; presence must be
    // checked separately so clearing is explicit on every invocation surface.
    if inputs.get("value").is_none() {
        return Err(invalid("jira.issue.custom_field.set requires value"));
    }
    if inputs
        .get("expectedIssueId")
        .is_some_and(|value| !value.is_string())
    {
        return Err(invalid(
            "jira.issue.custom_field.set expectedIssueId must be a positive decimal string",
        ));
    }
    let raw: RawInputs = serde_json::from_value(inputs.clone())
        .map_err(|_| invalid("jira.issue.custom_field.set inputs are invalid"))?;
    if !custom_fields::is_custom_field_id(&raw.field_id) {
        return Err(invalid(
            "jira.issue.custom_field.set fieldId must be a canonical custom-field ID",
        ));
    }
    if raw
        .expected_issue_id
        .as_ref()
        .is_some_and(|id| !is_decimal_id(id))
    {
        return Err(invalid(
            "jira.issue.custom_field.set expectedIssueId must be a positive decimal string",
        ));
    }
    Ok(Inputs {
        locator: issue_locator_from_optional(
            raw.issue,
            raw.url,
            config,
            "jira.issue.custom_field.set",
            ("issue", "url"),
        )?,
        field_id: raw.field_id,
        value: raw.value,
        expected_issue_id: raw.expected_issue_id,
    })
}

fn invalid(message: &'static str) -> ProviderError {
    ProviderError::deny(ReasonCode::InputInvalid, message)
}

fn is_decimal_id(value: &str) -> bool {
    matches!(value.as_bytes().first(), Some(b'1'..=b'9'))
        && value.bytes().all(|byte| byte.is_ascii_digit())
}

pub(super) fn scope_locator(
    inputs: &Value,
    config: &JiraProviderConfig,
) -> Result<IssueLocator, ProviderError> {
    // Operator allowlist refusals belong after authorization: the host conceals
    // domain errors from this pre-policy lookup hook as scope_unresolved.
    Ok(parse_inputs(inputs, config)?.locator)
}

impl JiraProvider {
    pub(super) async fn invoke_issue_custom_field_set(
        &self,
        request: ProviderInvocation,
    ) -> Result<ProviderResult, ProviderError> {
        let inputs = parse_inputs(request.inputs(), &self.config)?;
        // Body-size failures are concealed during pre-policy lookup. Check the
        // content limit here so an authorized caller receives body_size_denied.
        let bytes = serde_json::to_vec(&inputs.value)
            .map_err(|_| invalid("jira.issue.custom_field.set value must be JSON"))?;
        if bytes.len() as u64 > self.config.content.max_body_bytes {
            return Err(ProviderError::deny(
                ReasonCode::BodySizeDenied,
                "Jira custom-field value exceeds the configured content body limit",
            ));
        }
        if !self
            .config
            .custom_fields
            .allowed_field_ids
            .contains(&inputs.field_id)
        {
            return Err(ProviderError::domain(
                &NOT_ALLOWED,
                "Jira custom field is not allowlisted for writes",
            ));
        }
        let credential = &self.execution_credential(request.admitted())?;
        let lookup_credential = &self.lookup_credential(request.admitted())?;
        let metadata_response = self
            .confirm_authorized_issue(
                &inputs.locator,
                lookup_credential,
                request.resource_scopes()?,
            )
            .await?;
        let metadata = metadata_response.value;
        if !is_decimal_id(&metadata.id) {
            return Err(ProviderError::error(
                ReasonCode::UpstreamProtocolFailed,
                "Jira issue returned an invalid immutable ID",
            ));
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
        let write = JiraWrite::new(json!({
            "issueId": metadata.id, "issueKey": metadata.key, "fieldId": inputs.field_id,
        }));
        // The confirmed immutable ID prevents a reused key redirecting this
        // write. Jira owns the selected field's value and editability rules.
        let response = self.backend.set_issue_custom_field(&metadata.id, &inputs.field_id, &inputs.value, credential).await
            .map_err(|error| match error {
                JiraBackendError::HttpStatus(status @ (400 | 422)) | JiraBackendError::Validation {status: status @ (400 | 422), ..} => ProviderError::domain(&REJECTED, "Jira rejected the custom-field update; check the field value, context and issue editability").with_upstream(Some(status), None),
                error => write.failed(error),
            })?;
        after_accepted_write("mutation_response", write.locators(), async {
            let result = json!({
                "operation": "issue.custom_field.set",
                "issue": issue_metadata_result(&metadata, &self.config),
                "fieldId": inputs.field_id,
                "status": "set",
            });
            enforce_result_size(&result, self.limits.max_upstream_response_bytes)?;
            Ok(ProviderResult::new(result)
                .with_audit(json!({
                    "provider": "jira", "operation": "issue.custom_field.set",
                    "issueKey": metadata.key, "project": metadata.project,
                    "fieldId": inputs.field_id,
                    "credentialMode": request.credential_mode(),
                    "egressProxy": self.backend.egress_proxy_audit(credential),
                }))
                .with_upstream(
                    Some(response.status),
                    Some(metadata_response.duration_ms + response.duration_ms),
                )
                .with_object_ids(write.locators()))
        })
        .await
    }
}
