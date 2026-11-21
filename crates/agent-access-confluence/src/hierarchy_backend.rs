//! Bounded current-location observations. These are facts, never policy decisions.
use super::*;
use std::sync::Mutex;

tokio::task_local! {
    static ACTIVE_METADATA_BUDGET: ConfluenceMetadataBudget;
}

pub(super) fn current_metadata_budget() -> Option<ConfluenceMetadataBudget> {
    ACTIVE_METADATA_BUDGET.try_with(Clone::clone).ok()
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "lowercase")]
pub enum ConfluenceNodeKind {
    Page,
    Folder,
    Database,
    Whiteboard,
    Embed,
}

impl ConfluenceNodeKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Page => "page",
            Self::Folder => "folder",
            Self::Database => "database",
            Self::Whiteboard => "whiteboard",
            Self::Embed => "embed",
        }
    }

    pub(crate) fn endpoint(self) -> &'static str {
        match self {
            Self::Page => "pages",
            Self::Folder => "folders",
            Self::Database => "databases",
            Self::Whiteboard => "whiteboards",
            Self::Embed => "embeds",
        }
    }

    pub(crate) fn parse(value: &str) -> Option<Self> {
        match value {
            "page" => Some(Self::Page),
            "folder" => Some(Self::Folder),
            "database" => Some(Self::Database),
            "whiteboard" => Some(Self::Whiteboard),
            "embed" => Some(Self::Embed),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum ConfluenceContentStatus {
    Current,
    Draft,
}

impl ConfluenceContentStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Current => "current",
            Self::Draft => "draft",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(deny_unknown_fields)]
pub struct ConfluenceParent {
    pub kind: ConfluenceNodeKind,
    pub id: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfluenceNode {
    pub id: String,
    pub kind: ConfluenceNodeKind,
    pub space_id: String,
    pub parent: Option<ConfluenceParent>,
    pub status: ConfluenceContentStatus,
    pub version: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfluenceRegularPage {
    pub node: ConfluenceNode,
    pub title: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfluenceBlogLocation {
    pub id: String,
    pub space_id: String,
    pub status: ConfluenceContentStatus,
    pub version: u64,
}

/// One operation's shared HTTP metadata counters. Cloning never resets them.
#[derive(Debug, Clone)]
pub struct ConfluenceMetadataBudget {
    limits: ConfluenceContentAccessConfig,
    state: Arc<Mutex<MetadataBudgetState>>,
    parent: Option<Arc<ConfluenceMetadataBudget>>,
}

#[derive(Debug, Default)]
struct MetadataBudgetState {
    requests: u32,
    bytes: u64,
    exhausted: bool,
}

impl ConfluenceMetadataBudget {
    pub fn new(limits: &ConfluenceContentAccessConfig) -> Self {
        Self {
            limits: limits.clone(),
            state: Arc::new(Mutex::new(MetadataBudgetState::default())),
            parent: None,
        }
    }

    /// A fresh metadata child of a search's total request/byte budget. The
    /// immutable parent chain is acyclic; each ancestor receives one charge.
    pub fn with_parent(limits: &ConfluenceContentAccessConfig, parent: &Self) -> Self {
        Self {
            limits: limits.clone(),
            state: Arc::new(Mutex::new(MetadataBudgetState::default())),
            parent: Some(Arc::new(parent.clone())),
        }
    }

    /// Attach this operation's counters to an existing authorization-metadata
    /// future. The guard ends with the future and never installs global state.
    pub async fn scope<F: std::future::Future>(&self, future: F) -> F::Output {
        ACTIVE_METADATA_BUDGET.scope(self.clone(), future).await
    }

    /// Charge immediately before each HTTP attempt, including credential recovery.
    pub fn charge_request(&self) -> Result<(), ConfluenceBackendError> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| ConfluenceBackendError::ScopeUnresolved)?;
        if state.exhausted
            || state.requests >= self.limits.max_metadata_requests
            || state.bytes >= self.limits.max_metadata_bytes
        {
            state.exhausted = true;
            return Err(ConfluenceBackendError::ScopeUnresolved);
        }
        if let Some(parent) = &self.parent
            && let Err(error) = parent.charge_request()
        {
            state.exhausted = true;
            return Err(error);
        }
        state.requests += 1;
        Ok(())
    }

    /// Charge bytes as read, before JSON parsing or response-shape validation.
    pub fn charge_bytes(&self, bytes: u64) -> Result<(), ConfluenceBackendError> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| ConfluenceBackendError::ScopeUnresolved)?;
        let total = state.bytes.checked_add(bytes);
        if state.exhausted || total.is_none_or(|total| total > self.limits.max_metadata_bytes) {
            state.exhausted = true;
            return Err(ConfluenceBackendError::ScopeUnresolved);
        }
        if let Some(parent) = &self.parent
            && let Err(error) = parent.charge_bytes(bytes)
        {
            state.exhausted = true;
            return Err(error);
        }
        state.bytes = total.ok_or(ConfluenceBackendError::ScopeUnresolved)?;
        Ok(())
    }

    pub fn usage(&self) -> Result<(u32, u64), ConfluenceBackendError> {
        let state = self
            .state
            .lock()
            .map_err(|_| ConfluenceBackendError::ScopeUnresolved)?;
        Ok((state.requests, state.bytes))
    }

    pub fn remaining_requests(&self) -> Result<u32, ConfluenceBackendError> {
        let remaining = {
            let state = self
                .state
                .lock()
                .map_err(|_| ConfluenceBackendError::ScopeUnresolved)?;
            if state.exhausted || state.bytes >= self.limits.max_metadata_bytes {
                0
            } else {
                self.limits
                    .max_metadata_requests
                    .saturating_sub(state.requests)
            }
        };
        Ok(if let Some(parent) = &self.parent {
            remaining.min(parent.remaining_requests()?)
        } else {
            remaining
        })
    }

    pub fn remaining_bytes(&self) -> Result<u64, ConfluenceBackendError> {
        let remaining = {
            let state = self
                .state
                .lock()
                .map_err(|_| ConfluenceBackendError::ScopeUnresolved)?;
            if state.exhausted {
                0
            } else {
                self.limits.max_metadata_bytes.saturating_sub(state.bytes)
            }
        };
        Ok(if let Some(parent) = &self.parent {
            remaining.min(parent.remaining_bytes()?)
        } else {
            remaining
        })
    }
}

pub(crate) fn numeric_content_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 20
        && !id.starts_with('0')
        && id.bytes().all(|b| b.is_ascii_digit())
}

pub(super) fn malformed_metadata() -> ConfluenceBackendError {
    ConfluenceBackendError::Protocol(
        "Confluence content-location metadata is malformed".to_string(),
    )
}

fn check_status(
    value: &Value,
    expected: ConfluenceContentStatus,
) -> Result<(), ConfluenceBackendError> {
    let actual = value
        .get("status")
        .and_then(Value::as_str)
        .ok_or_else(malformed_metadata)?;
    if actual == expected.as_str() {
        Ok(())
    } else {
        Err(ConfluenceBackendError::ScopeUnresolved)
    }
}

fn required_id<'a>(value: &'a Value, key: &str) -> Result<&'a str, ConfluenceBackendError> {
    value
        .get(key)
        .and_then(Value::as_str)
        .filter(|id| numeric_content_id(id))
        .ok_or_else(malformed_metadata)
}

/// Only explicit paired nulls terminate a walk. Optional/missing API fields
/// remain unresolved until an adapter-specific root contract is qualified.
pub(crate) fn strict_parent(
    value: &Value,
) -> Result<Option<ConfluenceParent>, ConfluenceBackendError> {
    match (value.get("parentId"), value.get("parentType")) {
        (Some(Value::Null), Some(Value::Null)) => Ok(None),
        (Some(Value::String(id)), Some(Value::String(kind))) if numeric_content_id(id) => {
            let kind =
                ConfluenceNodeKind::parse(kind).ok_or(ConfluenceBackendError::ScopeUnresolved)?;
            Ok(Some(ConfluenceParent {
                id: id.clone(),
                kind,
            }))
        }
        (None, _) | (_, None) => Err(ConfluenceBackendError::ScopeUnresolved),
        _ => Err(malformed_metadata()),
    }
}

pub(super) fn check_optional_type(
    value: &Value,
    expected: &str,
) -> Result<(), ConfluenceBackendError> {
    match value.get("type") {
        None => Ok(()), // The typed endpoint itself supplies the content kind.
        Some(Value::String(kind)) if kind == expected => Ok(()),
        _ => Err(malformed_metadata()),
    }
}

pub(crate) fn node_from_value(
    value: &Value,
    kind: ConfluenceNodeKind,
    expected_id: &str,
    status: ConfluenceContentStatus,
    require_parent: bool,
) -> Result<ConfluenceNode, ConfluenceBackendError> {
    if !numeric_content_id(expected_id)
        || (kind != ConfluenceNodeKind::Page && status != ConfluenceContentStatus::Current)
    {
        return Err(ConfluenceBackendError::ScopeUnresolved);
    }
    check_optional_type(value, kind.as_str())?;
    let id = required_id(value, "id")?;
    if id != expected_id {
        return Err(malformed_metadata());
    }
    check_status(value, status)?;
    let space_id = required_id(value, "spaceId")?;
    // None in container-only mode means no parent observation was requested;
    // it is never used as root termination for a complete-lineage proof.
    let parent = if require_parent {
        strict_parent(value)?
    } else {
        None
    };
    if parent.as_ref().is_some_and(|parent| parent.id == id) {
        return Err(ConfluenceBackendError::ScopeUnresolved);
    }
    let version = match value.pointer("/version/number") {
        Some(number) => Some(number.as_u64().ok_or_else(malformed_metadata)?),
        None if kind != ConfluenceNodeKind::Page => None,
        None => return Err(malformed_metadata()),
    };
    if version == Some(0) && status == ConfluenceContentStatus::Current {
        return Err(malformed_metadata());
    }
    Ok(ConfluenceNode {
        id: id.to_string(),
        kind,
        space_id: space_id.to_string(),
        parent,
        status,
        version,
    })
}

pub(crate) fn regular_page_from_results(
    value: &Value,
    expected_id: &str,
    require_parent: bool,
) -> Result<ConfluenceRegularPage, ConfluenceBackendError> {
    match value.pointer("/_links/next") {
        None | Some(Value::Null) => {}
        Some(Value::String(next)) if next.is_empty() => {}
        _ => return Err(malformed_metadata()),
    }
    let results = value
        .get("results")
        .and_then(Value::as_array)
        .ok_or_else(malformed_metadata)?;
    if results.is_empty() {
        return Err(ConfluenceBackendError::ScopeUnresolved);
    }
    if results.len() != 1 {
        return Err(malformed_metadata());
    }
    let page = &results[0];
    match page.get("subtype") {
        None | Some(Value::Null) => {}
        Some(Value::String(subtype)) if subtype == "page" => {}
        Some(Value::String(_)) => return Err(ConfluenceBackendError::ScopeUnresolved),
        _ => return Err(malformed_metadata()),
    }
    let node = node_from_value(
        page,
        ConfluenceNodeKind::Page,
        expected_id,
        ConfluenceContentStatus::Current,
        require_parent,
    )?;
    let title = page
        .get("title")
        .and_then(Value::as_str)
        .ok_or_else(malformed_metadata)?
        .to_string();
    Ok(ConfluenceRegularPage { node, title })
}

pub(super) fn blog_location_from_value(
    value: &Value,
    expected_id: &str,
    status: ConfluenceContentStatus,
) -> Result<ConfluenceBlogLocation, ConfluenceBackendError> {
    check_optional_type(value, "blogpost")?;
    let id = required_id(value, "id")?;
    if !numeric_content_id(expected_id) {
        return Err(ConfluenceBackendError::ScopeUnresolved);
    }
    if id != expected_id {
        return Err(malformed_metadata());
    }
    check_status(value, status)?;
    let space_id = required_id(value, "spaceId")?;
    let version = value
        .pointer("/version/number")
        .and_then(Value::as_u64)
        .filter(|version| *version > 0 || status == ConfluenceContentStatus::Draft)
        .ok_or_else(malformed_metadata)?;
    Ok(ConfluenceBlogLocation {
        id: id.to_string(),
        space_id: space_id.to_string(),
        status,
        version,
    })
}

impl HttpConfluenceBackend {
    pub(super) async fn location_json(
        &self,
        url: Url,
        credential: &AtlassianCredential,
        budget: &ConfluenceMetadataBudget,
        operation: &'static str,
    ) -> Result<ConfluenceBackendResponse<Value>, ConfluenceBackendError> {
        let started = Instant::now();
        let client = self.request_client(credential)?;
        let mut response = send_confluence_request_with_budget(
            client,
            credential,
            client
                .request(Method::GET, url)
                .header("Accept", "application/json"),
            UpstreamCall::new(operation),
            Some(budget),
        )
        .await?;
        let status = response.status().as_u16();
        let trace = take_upstream_trace(&mut response);
        let result =
            read_location_json(response, self.limits.max_upstream_response_bytes, budget).await;
        complete_confluence_trace(trace, &result);
        Ok(ConfluenceBackendResponse {
            value: result?,
            status,
            duration_ms: elapsed_ms(started),
        })
    }
}

async fn read_location_json(
    response: reqwest::Response,
    byte_cap: u64,
    budget: &ConfluenceMetadataBudget,
) -> Result<Value, ConfluenceBackendError> {
    let bytes = read_metadata_body(response, byte_cap, budget).await?;
    serde_json::from_slice(&bytes).map_err(|_| malformed_metadata())
}

pub(super) async fn read_metadata_body(
    mut response: reqwest::Response,
    byte_cap: u64,
    budget: &ConfluenceMetadataBudget,
) -> Result<Vec<u8>, ConfluenceBackendError> {
    validate_confluence_body_response(&response, byte_cap)?;
    let mut bytes = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(|error| {
        if error.is_timeout() {
            ConfluenceBackendError::Timeout
        } else {
            ConfluenceBackendError::Transport("metadata response read failed".to_string())
        }
    })? {
        budget.charge_bytes(chunk.len() as u64)?;
        if (bytes.len() as u64)
            .checked_add(chunk.len() as u64)
            .is_none_or(|total| total > byte_cap)
        {
            return Err(ConfluenceBackendError::ResponseTooLarge);
        }
        bytes.extend_from_slice(&chunk);
    }
    Ok(bytes)
}

#[cfg(test)]
#[path = "hierarchy_backend_tests.rs"]
mod tests;
