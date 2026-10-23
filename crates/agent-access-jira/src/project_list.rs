//! Live project enumeration, filtered against normalized action authority.
use super::*;
use std::sync::atomic::{AtomicBool, Ordering};

#[cfg(test)]
mod tests;

const TOKENS: ContinuationFamily = ContinuationFamily::new(
    "jira",
    "project-list",
    1,
    ContinuationLifetime::StableWhenConfigured,
    8,
)
.confidential()
.fixed_payload_length()
.expires_after(Duration::from_secs(900));

pub(crate) fn descriptor(config: &JiraListingConfig) -> ActionDescriptor {
    jira_read_action("project.list", "List live Jira projects within effective project grants", json!({
        "type":"object", "additionalProperties":false,
        "properties": {
            "maxResults":{"type":"integer", "minimum":1, "maximum":config.max_results},
            "pageToken":{"type":"string", "minLength":1, "maxLength":TOKENS.max_token_bytes()}
        }
    }))
    .native_search(NativeSearchEnforcement::ResultFiltered)
    .sensitive_output("/result/items")
    .sensitive_output("/result/nextPageToken")
    .documentation(json!({
        "listing":"Enumerates visible live projects in key order and filters current project keys through this action's effective grants. Archived and deleted projects are excluded. Listing permission grants no issue access. No query or registered project is required.",
        "pagination":"Use nextPageToken as pageToken with unchanged maxResults. more and scan_budget require continuation, including empty pages; neither promises another authorized result. exhausted ends this credential's observed stream, without snapshot guarantees. Tokens are confidential, expire 15 minutes after first issuance, and reject changed authority or inputs.",
        "limits":"The listing configuration bounds candidate pages, HTTP attempts including OAuth replay, and scanned bytes. Oversized result pages fail; start a new listing with a smaller maxResults.",
        "previews":"Names are limited to 4096 UTF-8 bytes with previewTruncated when shortened. count is the released item count, never an upstream total."
    }))
}

fn invalid() -> ProviderError {
    ProviderError::deny(
        ReasonCode::InputInvalid,
        "Jira project listing inputs or continuation are invalid",
    )
}
fn protocol() -> ProviderError {
    ProviderError::error(
        ReasonCode::UpstreamProtocolFailed,
        "Jira project listing response protocol error",
    )
}
fn backend_protocol() -> JiraBackendError {
    JiraBackendError::Protocol("Jira project listing response protocol error".to_string())
}
fn token_error(error: ContinuationError) -> ProviderError {
    match error {
        ContinuationError::Invalid
        | ContinuationError::UnsupportedVersion
        | ContinuationError::Expired
        | ContinuationError::UpstreamQueryChanged
        | ContinuationError::TokenTooLarge { .. } => invalid(),
        _ => protocol(),
    }
}

pub(crate) struct Inputs {
    max_results: u32,
    page_token: Option<String>,
}
pub(crate) fn parse_inputs(
    value: &Value,
    config: &JiraListingConfig,
) -> Result<Inputs, ProviderError> {
    let object = value.as_object().ok_or_else(invalid)?;
    if object
        .keys()
        .any(|key| !matches!(key.as_str(), "maxResults" | "pageToken"))
    {
        return Err(invalid());
    }
    let max_results = match object.get("maxResults") {
        None => config.max_results,
        Some(value) => u32::try_from(value.as_u64().ok_or_else(invalid)?).map_err(|_| invalid())?,
    };
    if max_results == 0 || max_results > config.max_results || max_results > 100 {
        return Err(invalid());
    }
    let page_token = object
        .get("pageToken")
        .map(|value| {
            let token = value.as_str().ok_or_else(invalid)?;
            if token.is_empty() || token.len() > TOKENS.max_token_bytes() || !token.is_ascii() {
                return Err(invalid());
            }
            Ok(token.to_string())
        })
        .transpose()?;
    Ok(Inputs {
        max_results,
        page_token,
    })
}

fn listing_binding(
    provider: &JiraProvider,
    request: &ProviderInvocation,
    max_results: u32,
    scope: &SearchAuthorizationScope,
    family: ContinuationFamily,
) -> Result<ContinuationBinding, ProviderError> {
    let profile = serde_json::to_vec(&(
        &provider.search_configuration,
        &provider.config.listing,
        provider.limits.max_upstream_response_bytes,
    ))
    .map_err(|_| protocol())?;
    let profile: [u8; 32] = Sha256::digest(profile).into();
    let scope = serde_json::to_string(scope).map_err(|_| protocol())?;
    Ok(bind_atlassian_access(
        family.bind(request.context(), profile),
        request.execution(),
        provider.config.cloud_id.as_deref(),
    )?
    .number("maxResults", u64::from(max_results))
    .text("scope", &scope))
}

impl JiraProvider {
    pub(crate) async fn invoke_project_list(
        &self,
        request: ProviderInvocation,
    ) -> Result<ProviderResult, ProviderError> {
        if !request.body_parts().is_empty() {
            return Err(invalid());
        }
        let started = Instant::now();
        let input = parse_inputs(request.inputs(), &self.config.listing)?;
        let authority = search_authorization(&request)?;
        if authority.scope_type != "project" {
            return Err(ProviderError::error(
                ReasonCode::UpstreamProtocolFailed,
                "Jira project listing authority has the wrong scope",
            ));
        }
        if authority.scope.is_empty() {
            return Err(ProviderError::deny(
                ReasonCode::ServiceActionDenied,
                "Jira project listing has no project authority",
            ));
        }
        let credential = self.execution_credential(request.admitted())?;
        let binding = listing_binding(self, &request, input.max_results, &authority.scope, TOKENS)?;
        let opened = input
            .page_token
            .as_deref()
            .map(|token| {
                self.listing_signer
                    .open_confidential(&binding, token)
                    .map_err(token_error)
            })
            .transpose()?;
        let expiry = self
            .listing_signer
            .deadline(&binding)
            .map_err(token_error)?;
        let mut position = match &opened {
            Some(opened) => u64::from_be_bytes(opened.payload().try_into().map_err(|_| invalid())?),
            None => 0,
        };
        let requests = UpstreamRequestBudget::new(self.config.listing.max_upstream_requests);
        let bytes = SharedBodyBudget::new(self.config.listing.max_scan_bytes);
        let replay_used = Arc::new(AtomicBool::new(false));
        let delegated = matches!(request.execution(), ExecutionAccess::Delegated(_));
        let mut pages = 0;
        let (items, next, status) = loop {
            let reservation = 1 + u32::from(delegated && !replay_used.load(Ordering::Acquire));
            if pages >= self.config.listing.max_candidate_pages
                || requests.remaining_requests() < reservation
            {
                if pages == 0 {
                    return Err(ProviderError::error(
                        ReasonCode::UpstreamProtocolFailed,
                        "Jira project listing work budget cannot start a complete page",
                    ));
                }
                break (vec![], Some(position), "scan_budget");
            }
            let response = self
                .backend
                .project_list(
                    JiraProjectListRequest {
                        start_at: position,
                        max_results: input.max_results,
                        requests: requests.clone(),
                        bytes: bytes.clone(),
                        replay_used: replay_used.clone(),
                    },
                    &credential,
                )
                .await
                .map_err(jira_backend_error)?;
            let (candidates, next) = page(&response.value, position, input.max_results)?;
            let mut items = vec![];
            // Offset pages may repeat entries after concurrent creation or
            // rename. Only contradictory identities within one page are invalid.
            let mut seen_ids = BTreeSet::new();
            let mut seen_keys = BTreeSet::new();
            for candidate in candidates {
                let id = candidate
                    .get("id")
                    .and_then(Value::as_str)
                    .filter(|id| valid_id(id))
                    .ok_or_else(protocol)?;
                let key = candidate
                    .get("key")
                    .and_then(Value::as_str)
                    .filter(|key| is_project_key(key))
                    .ok_or_else(protocol)?;
                if !seen_ids.insert(id.to_string()) || !seen_keys.insert(key.to_string()) {
                    return Err(protocol());
                }
                if !authority.scope.matches(key) {
                    continue;
                }
                items.push(project_item(candidate, id, key, &self.config.tenant_host)?);
            }
            pages += 1;
            match next {
                None => break (items, None, "exhausted"),
                Some(next) if !items.is_empty() => break (items, Some(next), "more"),
                Some(next) => position = next,
            }
        };
        let token = next
            .map(|position: u64| {
                if let Some(opened) = &opened {
                    self.listing_signer
                        .seal_resumed(&binding, &position.to_be_bytes(), opened)
                } else {
                    self.listing_signer
                        .seal_until(&binding, &position.to_be_bytes(), expiry)
                }
                .map_err(token_error)
            })
            .transpose()?;
        let audit = json!({"jira":{
            "operation":"project.list", "projects":items.iter().filter_map(|item| item.get("key")).collect::<Vec<_>>(),
            "returnedCount":items.len(), "scanStatus":status, "continuationPresent":token.is_some(),
            "egressProxy":self.backend.egress_proxy_audit(&credential)
        }});
        let mut result = json!({"items":items, "count":items.len(), "maxResults":input.max_results, "scanStatus":status});
        if let Some(token) = token {
            result["nextPageToken"] = json!(token);
        }
        enforce_result_size(&result, self.limits.max_upstream_response_bytes)?;
        Ok(ProviderResult::new(result)
            .with_audit(audit)
            .with_upstream(Some(200), Some(elapsed_ms(started))))
    }
}

fn valid_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 128
        && !id.starts_with('0')
        && id.bytes().all(|byte| byte.is_ascii_digit())
}

fn page(
    value: &Value,
    position: u64,
    requested: u32,
) -> Result<(&Vec<Value>, Option<u64>), ProviderError> {
    let start = value
        .get("startAt")
        .and_then(Value::as_u64)
        .ok_or_else(protocol)?;
    let limit = value
        .get("maxResults")
        .and_then(Value::as_u64)
        .ok_or_else(protocol)?;
    let last = value
        .get("isLast")
        .and_then(Value::as_bool)
        .ok_or_else(protocol)?;
    let values = value
        .get("values")
        .and_then(Value::as_array)
        .ok_or_else(protocol)?;
    if start != position
        || limit == 0
        || limit > u64::from(requested)
        || values.len() as u64 > limit
    {
        return Err(protocol());
    }
    if last {
        return Ok((values, None));
    }
    if values.is_empty() {
        return Err(protocol());
    }
    let next = start
        .checked_add(values.len() as u64)
        .ok_or_else(protocol)?;
    // Jira's informational link is never followed; only corroborate an offset it supplies.
    if let Some(link) = value.get("nextPage") {
        let link = link.as_str().ok_or_else(protocol)?;
        let base = Url::parse("https://pagination.invalid/").expect("static URL");
        if let Ok(url) = base.join(link) {
            let offsets: Vec<_> = url
                .query_pairs()
                .filter(|(key, _)| key == "startAt")
                .collect();
            if offsets.len() > 1
                || offsets
                    .first()
                    .is_some_and(|(_, value)| value.parse::<u64>().ok() != Some(next))
            {
                return Err(protocol());
            }
        }
    }
    Ok((values, Some(next)))
}

fn project_item(value: &Value, id: &str, key: &str, tenant: &str) -> Result<Value, ProviderError> {
    let name = value
        .get("name")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .ok_or_else(protocol)?;
    let mut end = name.len().min(4096);
    while !name.is_char_boundary(end) {
        end -= 1;
    }
    let mut item = json!({"id":id,"key":key,"name":&name[..end],"webUrl":format!("https://{tenant}/browse/{key}")});
    if end < name.len() {
        item["previewTruncated"] = json!(true);
    }
    if let Some(kind) = value.get("projectTypeKey") {
        let kind = kind
            .as_str()
            .filter(|s| {
                !s.is_empty()
                    && s.len() <= 64
                    && s.bytes().all(|b| b.is_ascii_alphabetic() || b == b'_')
            })
            .ok_or_else(protocol)?;
        item["projectTypeKey"] = json!(kind);
    }
    Ok(item)
}

impl HttpJiraBackend {
    pub(crate) async fn project_list_page(
        &self,
        request: JiraProjectListRequest,
        credential: &AtlassianCredential,
    ) -> Result<JiraBackendResponse<Value>, JiraBackendError> {
        let clients = self.client_for(credential)?;
        let client = &clients.single_attempt_client;
        let mut url = clients
            .api_base
            .join("project/search")
            .map_err(|_| backend_protocol())?;
        url.query_pairs_mut()
            .append_pair("startAt", &request.start_at.to_string())
            .append_pair("maxResults", &request.max_results.to_string())
            .append_pair("orderBy", "key")
            .append_pair("status", "live");
        let started = Instant::now();
        let mut attempt = 1;
        loop {
            let presented = credential.present().await?;
            let mut response = client
                .send(
                    client
                        .request(Method::GET, url.clone())
                        .header("Accept", "application/json"),
                    UpstreamCall::new("project.list")
                        .with_attempt(attempt)
                        .with_authorization(presented.authorization())
                        .with_request_budget(&request.requests),
                )
                .await
                .map_err(|error| {
                    if matches!(error, UpstreamError::RequestBudgetExceeded) {
                        backend_protocol()
                    } else {
                        jira_upstream_error(error)
                    }
                })?;
            let status = response.status().as_u16();
            let status_result =
                validate_jira_body_response(&response, self.limits.max_upstream_response_bytes);
            let trace = take_upstream_trace(&mut response);
            if status == 401 && presented.is_delegated() {
                credential.mark_rejected(&presented, "Jira")?;
            }
            let body = read_bounded_body_with_budget(
                response,
                self.limits.max_upstream_response_bytes,
                None,
                Some(&request.bytes),
            )
            .await
            .map_err(|error| match error {
                BodyReadError::TooLarge => JiraBackendError::ResponseTooLarge,
                BodyReadError::IdleTimeout
                | BodyReadError::Transport {
                    timed_out: true, ..
                } => JiraBackendError::Timeout,
                BodyReadError::Transport {
                    timed_out: false, ..
                } => JiraBackendError::Transport(String::new()),
                _ => backend_protocol(),
            });
            if let Some(trace) = trace {
                trace.complete(
                    body.as_ref()
                        .err()
                        .or(status_result.as_ref().err())
                        .map(jira_backend_reason_code)
                        .map(Into::into),
                );
            }
            let body = body?;
            if status == 401 && presented.is_delegated() {
                let replay = request
                    .replay_used
                    .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
                    .is_ok();
                credential
                    .recover_rejected(replay.then_some(()), "Jira")
                    .await?;
                attempt += 1;
                continue;
            }
            status_result?;
            let value = serde_json::from_slice(&body).map_err(|_| backend_protocol())?;
            return Ok(JiraBackendResponse {
                value,
                status,
                duration_ms: elapsed_ms(started),
            });
        }
    }
}
