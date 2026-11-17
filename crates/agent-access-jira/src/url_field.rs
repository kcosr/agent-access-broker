//! One configured URL custom field, with an explicit read-before-write guard.
//! Jira does not offer an atomic compare-and-set contract for this operation.
use super::*;

pub(super) const MAX_URL_CHARACTERS: usize = 255;

pub(super) static NOT_ALLOWED: ProviderReasonDefinition = ProviderReasonDefinition::deny(
    "jira_url_field_not_allowed",
    ProviderFailureStatus::Forbidden,
);
pub(super) static NOT_SETTABLE: ProviderReasonDefinition = ProviderReasonDefinition::deny(
    "jira_url_field_not_settable",
    ProviderFailureStatus::BadRequest,
);
pub(super) static CONFLICT: ProviderReasonDefinition =
    ProviderReasonDefinition::deny("jira_url_field_conflict", ProviderFailureStatus::Conflict);

pub(super) fn descriptor(config: &JiraUrlFieldsConfig) -> ActionDescriptor {
    jira_action(
        "issue.url_field.set",
        "Set one allowlisted Jira URL custom field after checking its current value",
        json!({
            "type": "object",
            "required": ["fieldId", "value", "expectedValue"],
            "properties": {
                "issue": {"type": "string", "description": "Issue key. Give exactly one of issue or url."},
                "url": {"type": "string", "description": "Issue web URL. Give exactly one of issue or url."},
                "fieldId": {"type": "string", "pattern": "^customfield_[1-9][0-9]*$", "description": "Configured writable URL custom-field ID."},
                "expectedIssueId": {"type": "string", "pattern": "^[1-9][0-9]*$", "description": "Optional immutable Jira issue ID to confirm before writing when a remembered issue key may have moved or been reused."},
                "value": {"type": "string", "minLength": 1, "maxLength": MAX_URL_CHARACTERS, "description": "Absolute HTTP or HTTPS URL, without credentials, whitespace or control characters. The exact supplied value is stored."},
                "expectedValue": {"type": ["string", "null"], "maxLength": MAX_URL_CHARACTERS, "description": "Required current value to check before writing; null requires an unset field. A field already equal to value succeeds without writing. This read/check/write guard is not atomic against other Jira writers."}
            },
            "additionalProperties": false
        }),
    )
    .lookup(LookupRequirement::ScopeResolution)
    .sensitive_output("/result/field/value")
    .sensitive_output("/result/field/name")
    .documentation(json!({"allowedFieldIds": config.allowed_field_ids}))
    .audit_input("issue", "Issue")
    .audit_input("url", "URL")
    .audit_input("fieldId", "Field ID")
}

pub(super) struct Inputs {
    pub(super) locator: IssueLocator,
    field_id: String,
    value: String,
    expected_value: Option<String>,
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
        value: String,
        expected_value: Option<String>,
        expected_issue_id: Option<String>,
    }
    if inputs.get("expectedValue").is_none() {
        return Err(invalid("jira.issue.url_field.set requires expectedValue"));
    }
    if inputs
        .get("expectedIssueId")
        .is_some_and(|value| !value.is_string())
    {
        return Err(invalid(
            "jira.issue.url_field.set expectedIssueId must be a positive decimal string",
        ));
    }
    let raw: RawInputs = serde_json::from_value(inputs.clone())
        .map_err(|_| invalid("jira.issue.url_field.set inputs are invalid"))?;
    if !custom_fields::is_custom_field_id(&raw.field_id) {
        return Err(invalid(
            "jira.issue.url_field.set fieldId must be a canonical custom-field ID",
        ));
    }
    validate_url(&raw.value)?;
    if raw
        .expected_issue_id
        .as_ref()
        .is_some_and(|id| !is_decimal_id(id))
    {
        return Err(invalid(
            "jira.issue.url_field.set expectedIssueId must be a positive decimal string",
        ));
    }
    if raw.expected_value.as_ref().is_some_and(|value| {
        value.chars().count() > MAX_URL_CHARACTERS || value.chars().any(char::is_control)
    }) {
        return Err(invalid(
            "jira.issue.url_field.set expectedValue must be null or at most 255 characters without controls",
        ));
    }
    Ok(Inputs {
        locator: issue_locator_from_optional(
            raw.issue,
            raw.url,
            config,
            "jira.issue.url_field.set",
            ("issue", "url"),
        )?,
        field_id: raw.field_id,
        value: raw.value,
        expected_value: raw.expected_value,
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

fn validate_url(value: &str) -> Result<(), ProviderError> {
    let parsed = Url::parse(value).ok();
    if value.is_empty()
        || value.chars().count() > MAX_URL_CHARACTERS
        || value
            .chars()
            .any(|character| character.is_whitespace() || character.is_control())
        || value.contains('\\')
        || !value.split_once("://").is_some_and(|(scheme, _)| {
            scheme.eq_ignore_ascii_case("http") || scheme.eq_ignore_ascii_case("https")
        })
        || !parsed.as_ref().is_some_and(|url| {
            matches!(url.scheme(), "http" | "https")
                && url.host_str().is_some()
                && url.username().is_empty()
                && url.password().is_none()
        })
    {
        return Err(invalid(
            "jira.issue.url_field.set value must be an absolute HTTP(S) URL of at most 255 characters without credentials, whitespace or controls",
        ));
    }
    Ok(())
}

fn require_allowed(inputs: &Inputs, config: &JiraProviderConfig) -> Result<(), ProviderError> {
    if !config
        .url_fields
        .allowed_field_ids
        .contains(&inputs.field_id)
    {
        return Err(ProviderError::domain(
            &NOT_ALLOWED,
            "Jira URL custom field is not allowlisted for writes",
        ));
    }
    Ok(())
}

pub(super) fn scope_locator(
    inputs: &Value,
    config: &JiraProviderConfig,
) -> Result<IssueLocator, ProviderError> {
    let inputs = parse_inputs(inputs, config)?;
    require_allowed(&inputs, config)?;
    Ok(inputs.locator)
}

struct Field {
    name: Option<String>,
    value: Option<String>,
}

fn parse_field(
    value: Value,
    field_id: &str,
    expected_issue: &JiraIssueMetadata,
) -> Result<Field, ProviderError> {
    let issue = issue_metadata_from_value(value.clone()).map_err(jira_backend_error)?;
    if issue.id != expected_issue.id
        || issue.key != expected_issue.key
        || issue.project != expected_issue.project
    {
        return Err(ProviderError::deny(
            ReasonCode::ScopeUnresolved,
            "Jira URL custom-field response did not match the authorized issue",
        ));
    }
    let Some(field) = value.get("fields").and_then(|fields| fields.get(field_id)) else {
        return Err(ProviderError::domain(
            &NOT_SETTABLE,
            "Jira URL custom field is unavailable for the issue",
        ));
    };
    let schema = value
        .get("schema")
        .and_then(|schemas| schemas.get(field_id));
    if !schema.is_some_and(|schema| {
        schema.get("custom").and_then(Value::as_str)
            == Some("com.atlassian.jira.plugin.system.customfieldtypes:url")
            && schema.get("type").and_then(Value::as_str) == Some("string")
    }) {
        return Err(ProviderError::domain(
            &NOT_SETTABLE,
            "Jira custom field is not a built-in URL field",
        ));
    }
    let current = match field {
        Value::Null => None,
        Value::String(value) => Some(value.clone()),
        _ => {
            return Err(ProviderError::error(
                ReasonCode::UpstreamProtocolFailed,
                "Jira URL custom field returned an invalid value",
            ));
        }
    };
    let name = match value.get("names").and_then(|names| names.get(field_id)) {
        None | Some(Value::Null) => None,
        Some(Value::String(name)) => Some(name.clone()),
        _ => {
            return Err(ProviderError::error(
                ReasonCode::UpstreamProtocolFailed,
                "Jira URL custom field returned an invalid name",
            ));
        }
    };
    Ok(Field {
        name,
        value: current,
    })
}

impl JiraProvider {
    pub(super) async fn invoke_issue_url_field_set(
        &self,
        request: ProviderInvocation,
    ) -> Result<ProviderResult, ProviderError> {
        let inputs = parse_inputs(request.inputs(), &self.config)?;
        require_allowed(&inputs, &self.config)?;
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
        // Once the key resolves, use its immutable ID for field reads and the
        // mutation so a reused key cannot redirect the write to another issue.
        let before_response = self
            .backend
            .issue_url_field(&metadata.id, &inputs.field_id, credential)
            .await
            .map_err(jira_backend_error)?;
        let before = parse_field(before_response.value, &inputs.field_id, &metadata)?;
        let duration = metadata_response.duration_ms + before_response.duration_ms;
        if before.value.as_deref() == Some(inputs.value.as_str()) {
            return self.url_field_result(
                &request,
                &metadata,
                &inputs,
                before,
                false,
                (before_response.status, duration),
            );
        }
        if before.value != inputs.expected_value {
            return Err(ProviderError::domain(
                &CONFLICT,
                "Jira URL custom field no longer matches expectedValue",
            ));
        }
        let write = JiraWrite::new(json!({
            "issueId": metadata.id, "issueKey": metadata.key, "fieldId": inputs.field_id,
        }));
        let updated = self.backend.set_issue_url_field(&metadata.id, &inputs.field_id, &inputs.value, credential).await
            .map_err(|error| match error {
                JiraBackendError::Forbidden => ProviderError::domain(&NOT_SETTABLE, "Jira did not permit updating the URL custom field").with_upstream(Some(403), None),
                JiraBackendError::HttpStatus(status @ (400 | 422)) | JiraBackendError::Validation {status: status @ (400 | 422), ..} => ProviderError::domain(&NOT_SETTABLE, "Jira rejected the URL custom-field update; check field association and issue editability").with_upstream(Some(status), None),
                error => write.failed(error),
            })?;
        after_accepted_write("post_url_field_readback", write.locators(), async {
            let readback = self
                .backend
                .issue_url_field(&metadata.id, &inputs.field_id, credential)
                .await
                .map_err(jira_backend_error)?;
            let field = parse_field(readback.value, &inputs.field_id, &metadata)?;
            if field.value.as_deref() != Some(inputs.value.as_str()) {
                return Err(ProviderError::deny(
                    ReasonCode::VerificationMismatch,
                    "Jira URL custom-field readback did not match the requested value",
                ));
            }
            self.url_field_result(
                &request,
                &metadata,
                &inputs,
                field,
                true,
                (
                    updated.status,
                    duration + updated.duration_ms + readback.duration_ms,
                ),
            )
        })
        .await
    }

    fn url_field_result(
        &self,
        request: &ProviderInvocation,
        issue: &JiraIssueMetadata,
        inputs: &Inputs,
        field: Field,
        changed: bool,
        upstream: (u16, u64),
    ) -> Result<ProviderResult, ProviderError> {
        let result = json!({
            "operation": "issue.url_field.set",
            "issue": issue_metadata_result(issue, &self.config),
            "field": {"id": inputs.field_id, "name": field.name, "type": "url", "value": field.value},
            "changed": changed,
        });
        enforce_result_size(&result, self.limits.max_upstream_response_bytes)?;
        Ok(ProviderResult::new(result)
            .with_audit(json!({
                "provider": "jira", "operation": "issue.url_field.set",
                "issueKey": issue.key, "project": issue.project,
                "fieldId": inputs.field_id, "changed": changed,
                "credentialMode": request.credential_mode(),
                "egressProxy": self.backend.egress_proxy_audit(&self.execution_credential(request.admitted())?),
            }))
            .with_upstream(Some(upstream.0), Some(upstream.1))
            .with_object_ids(json!({"issueId": issue.id, "issueKey": issue.key, "fieldId": inputs.field_id})))
    }
}
