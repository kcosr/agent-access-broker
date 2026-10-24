//! Live current-space enumeration under normalized action authority.
use super::*;
use std::sync::atomic::{AtomicBool, Ordering};

#[cfg(test)]
mod tests;

const TOKENS: ContinuationFamily = ContinuationFamily::new(
    "confluence",
    "space-list",
    1,
    ContinuationLifetime::StableWhenConfigured,
    0,
)
.confidential()
.expires_after(Duration::from_secs(900));
const POSITION_PREFIX: usize = 33;

fn family(limits: &ProviderLimits) -> ContinuationFamily {
    let cap = usize::try_from(limits.max_upstream_response_bytes).unwrap_or(usize::MAX);
    TOKENS.with_max_payload_bytes(TOKENS.max_payload_bytes_within(cap))
}

pub(crate) fn descriptor(config: &ConfluenceListingConfig) -> ActionDescriptor {
    confluence_read_action("space.list", "List current Confluence spaces within effective space grants", json!({
        "type":"object", "additionalProperties":false,
        "properties": {
            "maxResults":{"type":"integer", "minimum":1, "maximum":config.max_results},
            "pageToken":{"type":"string", "minLength":1}
        }
    }))
    .native_search(NativeSearchEnforcement::ResultFiltered)
    .sensitive_output("/result/items")
    .sensitive_output("/result/nextPageToken")
    .documentation(json!({
        "listing":"Enumerates current visible spaces of every type, including personal spaces. Authorizes canonical keys, never URL aliases. Listing permission grants no content access. No query or registered space is required.",
        "pagination":"Reuse nextPageToken as pageToken with unchanged maxResults. more and scan_budget require continuation, including empty pages; neither promises another authorized item. exhausted ends this credential's observed stream, without snapshot guarantees. Confidential tokens expire 15 minutes after first issuance and reject changed authority or inputs.",
        "limits":"Listing configuration bounds candidate pages, HTTP attempts including one shared OAuth replay, and scanned bytes. Response and result byte caps also apply. Oversized pages fail; start fresh with smaller maxResults.",
        "previews":"Names are limited to 4096 UTF-8 bytes with previewTruncated when shortened. count is the released item count, never an upstream total."
    }))
}
fn invalid() -> ProviderError {
    ProviderError::deny(
        ReasonCode::InputInvalid,
        "Confluence space listing inputs or continuation are invalid",
    )
}
fn protocol() -> ProviderError {
    ProviderError::error(
        ReasonCode::UpstreamProtocolFailed,
        "Confluence space listing response protocol error",
    )
}
fn response_protocol(diagnostic: &'static str) -> ProviderError {
    protocol().with_internal_diagnostic_code(diagnostic)
}
fn backend_protocol() -> ConfluenceBackendError {
    ConfluenceBackendError::Protocol("Confluence space listing response protocol error".into())
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
    config: &ConfluenceListingConfig,
    limits: &ProviderLimits,
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
            if token.is_empty()
                || token.len() > family(limits).max_token_bytes()
                || !token.is_ascii()
            {
                return Err(invalid());
            }
            Ok(token.to_owned())
        })
        .transpose()?;
    Ok(Inputs {
        max_results,
        page_token,
    })
}

struct Position {
    cursor: String,
    predecessor: [u8; 32],
}
impl Position {
    fn open(payload: &[u8]) -> Result<Self, ProviderError> {
        if payload.len() <= POSITION_PREFIX || payload[0] != 1 {
            return Err(invalid());
        }
        Ok(Self {
            predecessor: payload[1..POSITION_PREFIX]
                .try_into()
                .map_err(|_| invalid())?,
            cursor: std::str::from_utf8(&payload[POSITION_PREFIX..])
                .map_err(|_| invalid())?
                .to_owned(),
        })
    }
    fn payload(&self) -> Vec<u8> {
        let mut payload = Vec::with_capacity(POSITION_PREFIX + self.cursor.len());
        payload.push(1);
        payload.extend_from_slice(&self.predecessor);
        payload.extend_from_slice(self.cursor.as_bytes());
        payload
    }
}
fn cursor_digest(cursor: &str) -> [u8; 32] {
    Sha256::digest(cursor.as_bytes()).into()
}
fn listing_binding(
    provider: &ConfluenceProvider,
    request: &ProviderInvocation,
    max_results: u32,
    scope: &SearchAuthorizationScope,
    family: ContinuationFamily,
) -> Result<ContinuationBinding, ProviderError> {
    let profile = serde_json::to_vec(&(
        provider.config.site().route_fingerprint(),
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

impl ConfluenceProvider {
    pub(crate) async fn invoke_space_list(
        &self,
        request: ProviderInvocation,
    ) -> Result<ProviderResult, ProviderError> {
        if !request.body_parts().is_empty() {
            return Err(invalid());
        }
        let started = Instant::now();
        let input = parse_inputs(request.inputs(), &self.config.listing, &self.limits)?;
        let authority = search_authorization(&request)?;
        if authority.scope_type != "space" {
            return Err(protocol());
        }
        if authority.scope.is_empty() {
            return Err(ProviderError::deny(
                ReasonCode::ServiceActionDenied,
                "Confluence space listing has no space authority",
            ));
        }
        let credential = self.execution_credential(request.admitted())?;
        let family = family(&self.limits);
        let binding = listing_binding(self, &request, input.max_results, &authority.scope, family)?;
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
        let mut position = opened
            .as_ref()
            .map(|token| Position::open(token.payload()))
            .transpose()?;
        let mut seen = BTreeSet::new();
        if let Some(position) = &position {
            seen.insert(cursor_digest(&position.cursor));
            seen.insert(position.predecessor);
        }
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
                        "Confluence space listing work budget cannot start a complete page",
                    ));
                }
                break (vec![], position, "scan_budget");
            }
            let response = self
                .backend
                .space_list(
                    ConfluenceSpaceListRequest {
                        cursor: position.as_ref().map(|position| position.cursor.clone()),
                        max_results: input.max_results,
                        requests: requests.clone(),
                        bytes: bytes.clone(),
                        replay_used: replay_used.clone(),
                    },
                    &credential,
                )
                .await
                .map_err(confluence_backend_error)?;
            let candidates = response
                .value
                .value
                .get("results")
                .and_then(Value::as_array)
                .ok_or_else(|| response_protocol("confluence_space_list_results_invalid"))?;
            if candidates.len() > input.max_results as usize {
                return Err(response_protocol("confluence_space_list_results_oversized"));
            }
            let next = response
                .value
                .next_cursor
                .map(|cursor| {
                    if cursor.is_empty()
                        || cursor.len() > family.max_payload_bytes().saturating_sub(POSITION_PREFIX)
                    {
                        return Err(response_protocol("confluence_space_list_cursor_invalid"));
                    }
                    if !seen.insert(cursor_digest(&cursor)) {
                        return Err(response_protocol("confluence_space_list_cursor_repeated"));
                    }
                    Ok(Position {
                        cursor,
                        predecessor: position
                            .as_ref()
                            .map(|position| cursor_digest(&position.cursor))
                            .unwrap_or([0; 32]),
                    })
                })
                .transpose()?;
            let mut items = vec![];
            let mut ids = BTreeSet::new();
            let mut keys = BTreeSet::new();
            for candidate in candidates {
                let id = candidate
                    .get("id")
                    .and_then(Value::as_str)
                    .filter(|id| is_page_id(id))
                    .ok_or_else(|| response_protocol("confluence_space_list_id_invalid"))?;
                let key = candidate
                    .get("key")
                    .and_then(Value::as_str)
                    .filter(|key| is_space_key(key))
                    .ok_or_else(|| response_protocol("confluence_space_list_key_invalid"))?;
                if !ids.insert(id) {
                    return Err(response_protocol("confluence_space_list_duplicate_id"));
                }
                if !keys.insert(key) {
                    return Err(response_protocol("confluence_space_list_duplicate_key"));
                }
                if !authority.scope.matches(key) {
                    continue;
                }
                items.push(space_item(candidate, id, key, &self.config)?);
            }
            pages += 1;
            match next {
                None => break (items, None, "exhausted"),
                Some(next) if !items.is_empty() => break (items, Some(next), "more"),
                Some(next) => position = Some(next),
            }
        };
        let token = next
            .map(|position| {
                let payload = position.payload();
                if let Some(opened) = &opened {
                    self.listing_signer.seal_resumed(&binding, &payload, opened)
                } else {
                    self.listing_signer.seal_until(&binding, &payload, expiry)
                }
                .map_err(token_error)
            })
            .transpose()?;
        let audit = json!({"confluence": {"operation":"space.list", "spaces":items.iter().filter_map(|item|item.get("key")).collect::<Vec<_>>(), "returnedCount":items.len(), "scanStatus":status, "continuationPresent":token.is_some(), "egressProxy":self.backend.egress_proxy_audit(&credential)}});
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

fn space_item(
    value: &Value,
    id: &str,
    key: &str,
    config: &ConfluenceProviderConfig,
) -> Result<Value, ProviderError> {
    let name = value
        .get("name")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| response_protocol("confluence_space_list_name_invalid"))?;
    let kind = value
        .get("type")
        .and_then(Value::as_str)
        .filter(|s| {
            !s.is_empty()
                && s.len() <= 64
                && s.bytes().all(|b| b.is_ascii_alphabetic() || b == b'_')
        })
        .ok_or_else(|| response_protocol("confluence_space_list_type_invalid"))?;
    if value.get("status").and_then(Value::as_str) != Some("current") {
        return Err(response_protocol("confluence_space_list_status_invalid"));
    }
    let mut end = name.len().min(4096);
    while !name.is_char_boundary(end) {
        end -= 1;
    }
    let raw_url = value.pointer("/_links/webui").and_then(Value::as_str);
    let names = ConfluenceSpaceUrlNames::new(
        key,
        value.get("currentActiveAlias").and_then(Value::as_str),
        raw_url,
        config,
    );
    let web_url = space_browser_url(raw_url, &names, config, &mut BrowserUrlFallbacks::default())?;
    let mut item = json!({"id":id,"key":key,"name":&name[..end],"type":kind,"status":"current","webUrl":web_url});
    if end < name.len() {
        item["previewTruncated"] = json!(true);
    }
    Ok(item)
}

fn next_cursor(
    current: &Url,
    site: &Url,
    value: &Value,
    headers: &reqwest::header::HeaderMap,
    allowlist: &[String],
) -> Result<Option<String>, ConfluenceBackendError> {
    let body_next = match value.get("_links") {
        None => None,
        Some(links) => links
            .as_object()
            .ok_or_else(backend_protocol)?
            .get("next")
            .map(|next| next.as_str().ok_or_else(backend_protocol))
            .transpose()?,
    };
    let header_next = comment_next_links_from_headers(headers).map_err(|_| backend_protocol())?;
    let mut cursor: Option<String> = None;
    for raw in body_next
        .into_iter()
        .chain(header_next.iter().map(String::as_str))
    {
        let parsed = Url::parse(raw)
            .or_else(|_| current.join(raw))
            .map_err(|_| backend_protocol())?;
        if !parsed.username().is_empty()
            || parsed.password().is_some()
            || parsed.fragment().is_some()
        {
            return Err(backend_protocol());
        }
        let mut fields = BTreeSet::new();
        for (key, _) in parsed.query_pairs() {
            if !fields.insert(key.into_owned()) {
                return Err(backend_protocol());
            }
        }
        let next = next_page_cursor(
            current,
            site,
            raw,
            allowlist,
            "space",
            &["limit", "status", "sort"],
        )
        .map_err(|_| backend_protocol())?;
        if cursor.as_ref().is_some_and(|cursor| cursor != &next) {
            return Err(backend_protocol());
        }
        cursor = Some(next);
    }
    Ok(cursor)
}

impl HttpConfluenceBackend {
    pub(crate) async fn space_list_page(
        &self,
        request: ConfluenceSpaceListRequest,
        credential: &AtlassianCredential,
    ) -> Result<ConfluenceBackendResponse<ConfluenceSpaceListPage>, ConfluenceBackendError> {
        let clients = self.client_for(credential)?;
        let client = &clients.single_attempt_client;
        let mut url = self
            .api_v2_base(credential)?
            .join("spaces")
            .map_err(|_| backend_protocol())?;
        url.query_pairs_mut()
            .append_pair("limit", &request.max_results.to_string())
            .append_pair("status", "current");
        if let Some(cursor) = &request.cursor {
            url.query_pairs_mut().append_pair("cursor", cursor);
        }
        let started = Instant::now();
        let mut attempt = 1;
        loop {
            let presented = credential.present().await?;
            let mut response = client
                .send(
                    client
                        .request(Method::GET, url.clone())
                        .header("Accept", "application/json"),
                    UpstreamCall::new("space.list")
                        .with_attempt(attempt)
                        .with_authorization(presented.authorization())
                        .with_request_budget(&request.requests),
                )
                .await
                .map_err(|error| {
                    if matches!(error, UpstreamError::RequestBudgetExceeded) {
                        backend_protocol()
                    } else {
                        confluence_upstream_error(error)
                    }
                })?;
            let status = response.status().as_u16();
            let status_result = validate_confluence_body_response(
                &response,
                self.limits.max_upstream_response_bytes,
            );
            let headers = response.headers().clone();
            let trace = take_upstream_trace(&mut response);
            if status == 401 && presented.is_delegated() {
                credential.mark_rejected(&presented, "Confluence")?;
            }
            let body = read_bounded_body_with_budget(
                response,
                self.limits.max_upstream_response_bytes,
                None,
                Some(&request.bytes),
            )
            .await
            .map_err(|error| match error {
                BodyReadError::TooLarge => ConfluenceBackendError::ResponseTooLarge,
                BodyReadError::IdleTimeout
                | BodyReadError::Transport {
                    timed_out: true, ..
                } => ConfluenceBackendError::Timeout,
                BodyReadError::Transport {
                    timed_out: false, ..
                } => ConfluenceBackendError::Transport(String::new()),
                _ => backend_protocol(),
            });
            if let Some(trace) = trace {
                trace.complete(
                    body.as_ref()
                        .err()
                        .or(status_result.as_ref().err())
                        .map(confluence_backend_reason_code)
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
                    .recover_rejected(replay.then_some(()), "Confluence")
                    .await?;
                attempt += 1;
                continue;
            }
            status_result?;
            let value: Value = serde_json::from_slice(&body).map_err(|_| backend_protocol())?;
            let next_cursor = next_cursor(
                &url,
                &clients.site_base,
                &value,
                &headers,
                &self.config.allowed_upstream_hosts,
            )?;
            return Ok(ConfluenceBackendResponse {
                value: ConfluenceSpaceListPage { value, next_cursor },
                status,
                duration_ms: elapsed_ms(started),
            });
        }
    }
}
