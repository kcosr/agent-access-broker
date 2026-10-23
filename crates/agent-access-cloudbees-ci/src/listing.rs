//! Bounded depth-first live job enumeration with confidential traversal state.
use super::*;
use agent_access_provider::{
    ContinuationError, ContinuationFamily, ContinuationLifetime, NativeSearchEnforcement,
    ResourceSelector, SearchAuthorizationScope, SharedBodyBudget, UpstreamRequestBudget,
    read_bounded_body_with_budget,
};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::{BTreeSet, VecDeque};

#[cfg(test)]
mod tests;

const PAYLOAD_BYTES: usize = 8192;
const MAX_DEPTH: usize = 64;
const TOKENS: ContinuationFamily = ContinuationFamily::new(
    "cloudbees_ci",
    "job-list",
    1,
    ContinuationLifetime::StableWhenConfigured,
    PAYLOAD_BYTES,
)
.confidential()
.fixed_payload_length()
.expires_after(Duration::from_secs(900));
const MIN_RESULT_BYTES: u64 = TOKENS.max_token_bytes() as u64 + 512;

/// Independent work bounds for live recursive job listing.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct CloudbeesCiListingConfig {
    pub max_results: u32,
    pub max_candidate_pages: u32,
    pub max_upstream_requests: u32,
    pub max_scan_bytes: u64,
}
impl Default for CloudbeesCiListingConfig {
    fn default() -> Self {
        Self {
            max_results: 50,
            max_candidate_pages: 32,
            max_upstream_requests: 64,
            max_scan_bytes: 16 * 1024 * 1024,
        }
    }
}
impl CloudbeesCiListingConfig {
    pub(super) fn validate(&self, limits: &ProviderLimits, errors: &mut Vec<String>) {
        if !(1..=100).contains(&self.max_results)
            || self.max_candidate_pages == 0
            || self.max_upstream_requests == 0
            || self.max_scan_bytes == 0
        {
            errors.push("providers.cloudbees_ci.listing requires max_results in 1..=100 and positive work budgets".into());
        }
        if limits.max_upstream_response_bytes < MIN_RESULT_BYTES {
            errors.push(format!("CloudBees CI job listing requires limits.max_upstream_response_bytes >= {MIN_RESULT_BYTES}"));
        }
    }
}
pub(super) fn fingerprint(config: &CloudbeesCiProviderConfig, limits: &ProviderLimits) -> String {
    let routes: BTreeMap<_, _> = config
        .controllers
        .iter()
        .map(|(alias, route)| (alias, (&route.base_url, &route.web_base_url)))
        .collect();
    format!("{:x}", Sha256::digest(serde_json::to_vec(&json!({
        "controllers":routes,"listing":config.listing,"allowlist":config.allowed_upstream_hosts,
        "proxy":config.egress_proxy.as_ref().map(|p| (&p.url, &p.username_ref, &p.password_ref)),
        "timeout":limits.request_timeout_ms,"resultLimit":limits.max_upstream_response_bytes
    })).expect("serializable listing configuration")))
}
pub(super) fn descriptor(config: &CloudbeesCiListingConfig) -> ActionDescriptor {
    ActionDescriptor::new("job.list", "List live CloudBees CI jobs within effective grants", json!({
        "type":"object","additionalProperties":false,"required":["controller"],
        "properties":{
            "controller":{"type":"string","minLength":1},
            "folder":{"type":"string","minLength":1},
            "maxResults":{"type":"integer","minimum":1,"maximum":config.max_results},
            "pageToken":{"type":"string","minLength":1,"maxLength":TOKENS.max_token_bytes()}
        }
    })).scope("job").credential_modes(["service","per_user"]).read_only()
    .native_search(NativeSearchEnforcement::ResultFiltered)
    .sensitive_output("/result/items").sensitive_output("/result/nextPageToken")
    .documentation(json!({
        "listing":"Recursively enumerates jobs and containers from a configured controller and optional canonical folder. The starting container is excluded. Permission to list grants no inspection or build access. Only effective authorized items are released; denied parents may be traversed to reach allowed children.",
        "pagination":"Pass nextPageToken as pageToken with unchanged controller, folder and maxResults. more and scan_budget require continuation, even for empty pages, without promising another authorized item. exhausted ends this credential's observed stream, not a snapshot. upstream_window is terminal incomplete coverage.",
        "limits":"Bounded candidate pages, HTTP attempts and scanned bytes. Depth is limited to 64 below the root and traversal state to 8192 bytes; exceeding either or Jenkins' signed 32-bit range ends with upstream_window. Confidential fixed-length tokens expire 15 minutes after original issuance and reject changed authority or inputs.",
        "projection":"Only canonical identity, name, displayName, kind and an optional verified webUrl. displayName is limited to 4096 UTF-8 bytes with previewTruncated. count is the released count, never an upstream total. JSON output only."
    }))
}
fn invalid() -> ProviderError {
    ProviderError::deny(
        ReasonCode::InputInvalid,
        "CloudBees CI listing inputs or continuation are invalid",
    )
}
fn protocol() -> ProviderError {
    ProviderError::error(
        ReasonCode::UpstreamProtocolFailed,
        "CloudBees CI listing response protocol error",
    )
}
fn denied() -> ProviderError {
    ProviderError::deny(
        ReasonCode::ServiceActionDenied,
        "CloudBees CI listing has no descendant authority",
    )
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
pub(super) struct Inputs {
    controller: String,
    folder: String,
    max_results: u32,
    page_token: Option<String>,
}
pub(super) fn parse_inputs(
    provider: &CloudbeesCiProvider,
    value: &Value,
) -> Result<Inputs, ProviderError> {
    let object = value.as_object().ok_or_else(invalid)?;
    if object.keys().any(|key| {
        !matches!(
            key.as_str(),
            "controller" | "folder" | "maxResults" | "pageToken"
        )
    }) {
        return Err(invalid());
    }
    let controller = object
        .get("controller")
        .and_then(Value::as_str)
        .filter(|s| provider.controllers.contains_key(*s))
        .ok_or_else(invalid)?;
    let folder = match object.get("folder") {
        None => "",
        Some(value) => value
            .as_str()
            .filter(|s| {
                !s.is_empty() && is_cloudbees_ci_resource_path(&format!("{controller}/{s}"), false)
            })
            .ok_or_else(invalid)?,
    };
    let max_results = match object.get("maxResults") {
        None => provider.listing.max_results,
        Some(value) => u32::try_from(value.as_u64().ok_or_else(invalid)?).map_err(|_| invalid())?,
    };
    if max_results == 0 || max_results > provider.listing.max_results || max_results > 100 {
        return Err(invalid());
    }
    let page_token = object
        .get("pageToken")
        .map(|value| {
            value
                .as_str()
                .filter(|s| !s.is_empty() && s.len() <= TOKENS.max_token_bytes() && s.is_ascii())
                .map(str::to_owned)
                .ok_or_else(invalid)
        })
        .transpose()?;
    Ok(Inputs {
        controller: controller.into(),
        folder: folder.into(),
        max_results,
        page_token,
    })
}
fn component_valid(component: &str) -> bool {
    !component.contains('/') && is_cloudbees_ci_resource_path(&format!("ci/{component}"), false)
}
fn descendants(scope: &SearchAuthorizationScope, root: &str) -> bool {
    !scope
        .intersection(&SearchAuthorizationScope::from_selectors(
            vec![ResourceSelector::Namespace { value: root.into() }],
            vec![],
        ))
        .is_empty()
}
struct Candidate {
    name: String,
    job: String,
    container: bool,
    value: Value,
}
struct Page {
    candidates: VecDeque<Candidate>,
    short: bool,
}
struct Frame {
    component: String,
    offset: u32,
    page: Option<Page>,
}
impl Frame {
    fn new(component: String) -> Self {
        Self {
            component,
            offset: 0,
            page: None,
        }
    }
}
fn encode(frames: &[Frame]) -> Option<Vec<u8>> {
    if frames.is_empty() || frames.len() > MAX_DEPTH + 1 {
        return None;
    }
    let mut bytes = vec![1, frames.len() as u8];
    for frame in frames {
        bytes.extend_from_slice(&u16::try_from(frame.component.len()).ok()?.to_be_bytes());
        bytes.extend_from_slice(frame.component.as_bytes());
        bytes.extend_from_slice(&frame.offset.to_be_bytes());
        if bytes.len() > PAYLOAD_BYTES {
            return None;
        }
    }
    bytes.resize(PAYLOAD_BYTES, 0);
    Some(bytes)
}
fn decode(bytes: &[u8]) -> Result<Vec<Frame>, ProviderError> {
    if bytes.len() != PAYLOAD_BYTES || bytes[0] != 1 || !(1..=65).contains(&bytes[1]) {
        return Err(invalid());
    }
    let mut rest = &bytes[2..];
    let mut frames = vec![];
    for index in 0..bytes[1] {
        let (length, tail) = rest.split_at_checked(2).ok_or_else(invalid)?;
        let length = u16::from_be_bytes(length.try_into().map_err(|_| invalid())?) as usize;
        let (component, tail) = tail.split_at_checked(length).ok_or_else(invalid)?;
        let component = std::str::from_utf8(component).map_err(|_| invalid())?;
        let (offset, tail) = tail.split_at_checked(4).ok_or_else(invalid)?;
        let offset = u32::from_be_bytes(offset.try_into().map_err(|_| invalid())?);
        if (index == 0 && !component.is_empty())
            || (index > 0 && !component_valid(component))
            || offset > i32::MAX as u32
        {
            return Err(invalid());
        }
        frames.push(Frame {
            component: component.into(),
            offset,
            page: None,
        });
        rest = tail;
    }
    if rest.iter().any(|b| *b != 0) {
        return Err(invalid());
    }
    Ok(frames)
}
fn frame_path(input: &Inputs, frames: &[Frame]) -> String {
    std::iter::once(input.folder.as_str())
        .filter(|s| !s.is_empty())
        .chain(frames.iter().skip(1).map(|f| f.component.as_str()))
        .collect::<Vec<_>>()
        .join("/")
}
fn resource(controller: &str, job: &str) -> String {
    if job.is_empty() {
        controller.into()
    } else {
        format!("{controller}/{job}")
    }
}
fn parse_page(value: Value, parent: &str, size: u32) -> Result<Page, ProviderError> {
    let values = value
        .get("jobs")
        .and_then(Value::as_array)
        .filter(|v| v.len() <= size as usize)
        .ok_or_else(protocol)?;
    let mut names = BTreeSet::new();
    let mut candidates = VecDeque::new();
    for value in values {
        let name = value
            .get("name")
            .and_then(Value::as_str)
            .filter(|s| component_valid(s))
            .ok_or_else(protocol)?;
        let job = if parent.is_empty() {
            name.into()
        } else {
            format!("{parent}/{name}")
        };
        if value.get("fullName").and_then(Value::as_str) != Some(&job) || !names.insert(name) {
            return Err(protocol());
        }
        let container = match value.get("jobs") {
            None => false,
            Some(Value::Array(_)) => true,
            _ => return Err(protocol()),
        };
        candidates.push_back(Candidate {
            name: name.into(),
            job,
            container,
            value: value.clone(),
        });
    }
    Ok(Page {
        candidates,
        short: values.len() < size as usize,
    })
}
fn item(
    controller: &Controller,
    alias: &str,
    candidate: &Candidate,
) -> Result<Value, ProviderError> {
    let display = candidate
        .value
        .get("displayName")
        .and_then(Value::as_str)
        .ok_or_else(protocol)?;
    let mut end = display.len().min(4096);
    while !display.is_char_boundary(end) {
        end -= 1;
    }
    let mut value = json!({"controller":alias,"job":candidate.job,"resource":resource(alias,&candidate.job),
        "name":candidate.name,"displayName":&display[..end],"kind":if candidate.container {"container"} else {"job"}});
    if end < display.len() {
        value["previewTruncated"] = json!(true);
    }
    if let Some(url) = CloudbeesCiProvider::verified_web_url(
        controller,
        candidate.value.get("url").and_then(Value::as_str),
        &candidate.job,
        None,
    ) {
        value["webUrl"] = json!(url);
    }
    Ok(value)
}
fn listing_binding(
    provider: &CloudbeesCiProvider,
    request: &ProviderInvocation,
    input: &Inputs,
    scope: &SearchAuthorizationScope,
) -> Result<agent_access_provider::ContinuationBinding, ProviderError> {
    let credential = request
        .execution()
        .static_credential()
        .ok_or_else(credential_invalid)?;
    Ok(TOKENS
        .bind(request.context(), &provider.listing_fingerprint)
        .text("controller", &input.controller)
        .text("folder", &input.folder)
        .number("maxResults", u64::from(input.max_results))
        .text(
            "scope",
            &serde_json::to_string(scope).map_err(|_| protocol())?,
        )
        .text("credentialKind", credential.kind().as_str())
        .optional_text("credentialProfile", credential.profile()))
}

impl CloudbeesCiProvider {
    async fn listing_page(
        &self,
        controller: &Controller,
        credential: &ExecutionCredential,
        job: &str,
        range: (u32, u32),
        requests: &UpstreamRequestBudget,
        bytes: &SharedBodyBudget,
    ) -> Result<Page, ProviderError> {
        let base = if job.is_empty() {
            controller.base.clone()
        } else {
            Self::job_url(&controller.base, job)
        };
        let (offset, size) = range;
        let tree = format!(
            "jobs[name,fullName,displayName,url,_class,jobs[name]{{0,0}}]{{{offset},{}}}",
            offset + size
        );
        let url = Self::tree(Self::append(base, &["api", "json"]), &tree);
        let fetch = async {
            let authorization = basic_authorization(credential)?;
            let mut response = controller
                .listing_client
                .send(
                    controller
                        .listing_client
                        .request(Method::GET, url)
                        .header("Accept", "application/json"),
                    UpstreamCall::new("job.list")
                        .with_authorization(&authorization)
                        .with_request_budget(requests),
                )
                .await
                .map_err(|error| send_failure(error, None))?;
            complete_upstream_trace(&mut response, None);
            let status = response.status();
            let headers = response.headers().clone();
            let status_error = || match status {
                StatusCode::UNAUTHORIZED => ProviderError::error(
                    ReasonCode::UpstreamUnauthorized,
                    "CloudBees CI listing credential was rejected",
                ),
                StatusCode::FORBIDDEN => ProviderError::error(
                    ReasonCode::UpstreamForbidden,
                    "CloudBees CI listing was denied",
                ),
                StatusCode::TOO_MANY_REQUESTS => rate_limited(&headers),
                _ => ProviderError::error(
                    ReasonCode::UpstreamFailed,
                    "CloudBees CI listing request failed",
                ),
            };
            let body =
                read_bounded_body_with_budget(response, self.response_limit, None, Some(bytes))
                    .await
                    .map_err(|error| match error {
                        BodyReadError::IdleTimeout
                        | BodyReadError::Transport {
                            timed_out: true, ..
                        } => ProviderError::error(
                            ReasonCode::UpstreamTimeout,
                            "CloudBees CI listing timed out",
                        ),
                        BodyReadError::TooLarge | BodyReadError::BudgetExceeded => {
                            if status.is_success() {
                                listing_too_large()
                            } else {
                                status_error()
                            }
                        }
                        BodyReadError::Transport {
                            timed_out: false, ..
                        } => ProviderError::error(
                            ReasonCode::UpstreamConnectionFailed,
                            "CloudBees CI listing response could not be read",
                        ),
                        _ => protocol(),
                    })?;
            if !status.is_success() {
                return Err(status_error());
            }
            parse_page(
                serde_json::from_slice(&body).map_err(|_| protocol())?,
                job,
                size,
            )
        };
        tokio::time::timeout(self.request_timeout, fetch)
            .await
            .map_err(|_| {
                ProviderError::error(
                    ReasonCode::UpstreamTimeout,
                    "CloudBees CI listing timed out",
                )
            })?
    }
    pub(super) async fn invoke_job_list(
        &self,
        request: ProviderInvocation,
    ) -> Result<ProviderResult, ProviderError> {
        let started = Instant::now();
        let input = parse_inputs(self, request.inputs())?;
        let authority = request.search_authorization().map_err(|_| protocol())?;
        if authority.scope_type != "job" {
            return Err(protocol());
        }
        if !descendants(
            &authority.scope,
            &resource(&input.controller, &input.folder),
        ) {
            return Err(denied());
        }
        let credential = request
            .execution()
            .static_credential()
            .ok_or_else(credential_invalid)?;
        let binding = listing_binding(self, &request, &input, &authority.scope)?;
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
        let mut frames = opened
            .as_ref()
            .map(|token| decode(token.payload()))
            .transpose()?
            .unwrap_or_else(|| vec![Frame::new(String::new())]);
        let controller = &self.controllers[&input.controller];
        let requests = UpstreamRequestBudget::new(self.listing.max_upstream_requests);
        let bytes = SharedBodyBudget::new(self.listing.max_scan_bytes);
        let mut pages = 0;
        let mut items = Vec::new();
        let mut item_bytes = 2u64;
        let status = loop {
            // Drop known exhausted frames before deciding whether continuation is needed.
            let mut boundary = false;
            while let Some(frame) = frames.last_mut() {
                let Some(page) = &frame.page else {
                    break;
                };
                if !page.candidates.is_empty() {
                    break;
                }
                boundary = true;
                if page.short {
                    frames.pop();
                } else {
                    frame.page = None;
                    break;
                }
            }
            if frames.is_empty() {
                break "exhausted";
            }
            if items.len() >= input.max_results as usize || (boundary && !items.is_empty()) {
                break "more";
            }
            let job = frame_path(&input, &frames);
            if frames.last().expect("nonempty").page.is_none() {
                // Continuation paths are authenticated, but re-check reachability before every fetch.
                if !descendants(&authority.scope, &resource(&input.controller, &job)) {
                    return Err(denied());
                }
                let offset = frames.last().expect("nonempty").offset;
                if offset
                    .checked_add(input.max_results)
                    .is_none_or(|upper| upper > i32::MAX as u32)
                {
                    break "upstream_window";
                }
                if pages >= self.listing.max_candidate_pages || requests.remaining_requests() == 0 {
                    break "scan_budget";
                }
                let page = self
                    .listing_page(
                        controller,
                        credential,
                        &job,
                        (offset, input.max_results),
                        &requests,
                        &bytes,
                    )
                    .await?;
                pages += 1;
                frames.last_mut().expect("nonempty").page = Some(page);
                continue;
            }
            let candidate = frames
                .last()
                .and_then(|f| f.page.as_ref())
                .and_then(|p| p.candidates.front())
                .expect("nonempty page");
            let allowed = authority
                .scope
                .matches(&resource(&input.controller, &candidate.job));
            let value = if allowed {
                Some(item(controller, &input.controller, candidate)?)
            } else {
                None
            };
            if let Some(value) = &value {
                let added = serde_json::to_vec(value).map_err(|_| protocol())?.len() as u64 + 1;
                if item_bytes
                    .saturating_add(added)
                    .saturating_add(MIN_RESULT_BYTES)
                    > self.result_limit
                {
                    if items.is_empty() {
                        return Err(listing_too_large());
                    }
                    break "more";
                }
                item_bytes += added;
            }
            let descend = candidate.container
                && descendants(
                    &authority.scope,
                    &resource(&input.controller, &candidate.job),
                );
            let name = candidate.name.clone();
            let frame = frames.last_mut().expect("nonempty");
            frame.offset += 1;
            frame
                .page
                .as_mut()
                .expect("buffered")
                .candidates
                .pop_front();
            if let Some(value) = value {
                items.push(value);
            }
            if descend {
                frames.push(Frame::new(name));
                if encode(&frames).is_none() {
                    break "upstream_window";
                }
            }
        };
        let token = if matches!(status, "more" | "scan_budget") {
            let payload = encode(&frames).ok_or_else(protocol)?;
            Some(
                if let Some(opened) = &opened {
                    self.listing_signer.seal_resumed(&binding, &payload, opened)
                } else {
                    self.listing_signer.seal_until(&binding, &payload, expiry)
                }
                .map_err(token_error)?,
            )
        } else {
            None
        };
        let audit = json!({"cloudbees_ci":{"operation":"job.list","jobs":items.iter().map(|i| &i["resource"]).collect::<Vec<_>>(),
            "returnedCount":items.len(),"scanStatus":status,"continuationPresent":token.is_some(),"egressProxy":controller.listing_client.egress_route().audit_value()}});
        let mut result = json!({"items":items,"count":items.len(),"maxResults":input.max_results,"scanStatus":status});
        if let Some(token) = token {
            result["nextPageToken"] = json!(token);
        }
        if serde_json::to_vec(&result).map_err(|_| protocol())?.len() as u64 > self.result_limit {
            return Err(listing_too_large());
        }
        Ok(ProviderResult::new(result)
            .with_audit(audit)
            .with_upstream(Some(200), Some(started.elapsed().as_millis() as u64)))
    }
}

fn listing_too_large() -> ProviderError {
    ProviderError::error(
        ReasonCode::UpstreamProtocolFailed,
        "CloudBees CI listing exceeds the byte limit; restart with a smaller maxResults",
    )
}
