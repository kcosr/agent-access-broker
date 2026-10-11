//! Host-controlled HTTP, operation fences, and redacted SDK lifecycle messages.
//!
//! Raw arguments/results, error bodies, session authority, and upstream instructions
//! remain here. The SDK sees sanitized successes and opaque transport failures.
pub use crate::protocol::PROTOCOL_VERSION;
pub(crate) use crate::protocol::protocol_error;
use crate::{
    protocol::{
        LEGACY_PROTOCOL_VERSION, LegacyReason, Lifecycle, ProbeSelection, classify_probe,
        eligible_probe_status, validate_initialize, validate_reply,
    },
    schema::encode_header,
};
use agent_access_provider::{
    DelegatedCredential, InvocationScope, ProviderError, ProviderFinalizationContext, ReasonCode,
    UpstreamCall, UpstreamClient, UpstreamError, UpstreamRetryAfter, complete_upstream_trace,
    current_provider_finalization, upstream_rate_limited,
};
use http::{HeaderMap, HeaderValue};
use rmcp::{
    RoleClient,
    model::ServerJsonRpcMessage,
    service::{RxJsonRpcMessage, TxJsonRpcMessage},
    transport::Transport,
};
use serde_json::{Value, json};
use std::{
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::{sync::mpsc, time::Instant};
use tokio_util::sync::CancellationToken;
use url::Url;

#[derive(Clone)]
pub(crate) struct WireClient {
    pub client: Arc<UpstreamClient>,
    pub endpoint: Url,
    pub service: String,
    pub max_bytes: u64,
}

pub(crate) struct CallArguments {
    pub name: String,
    pub arguments: Value,
    pub modern_arguments: Value,
    pub headers: HeaderMap,
}

#[derive(Default)]
pub(crate) struct WireState {
    pub cursor: Option<String>,
    pub result: Option<Value>,
    pub error: Option<ProviderError>,
    pub call_dispatched: bool,
    pub closed: bool,
    pub protocol_version: Option<&'static str>,
    pub status: Option<u16>,
    cleanup: bool,
    call_attempted: bool,
    legacy_started: bool,
    probe_outcome: Option<ProbeOutcome>,
    session: Option<HeaderValue>,
    probe_session: Option<HeaderValue>,
    unauthorized: bool,
    session_expired: bool,
    locally_interrupted: bool,
    #[cfg(test)]
    dispatch_pause: Option<Arc<(std::sync::Barrier, std::sync::Barrier)>>,
}

#[derive(Clone, Copy)]
enum ProbeOutcome {
    Current,
    Legacy(LegacyReason),
    Terminal,
}

/// One owner spans both startup attempts and cleanup. Dropping the provider future
/// closes the shared dispatch gate before cancelling every child attempt.
pub(crate) struct Operation {
    context: Arc<OperationContext>,
    pub state: Arc<Mutex<WireState>>,
}

struct OperationContext {
    wire: WireClient,
    auth: HeaderMap,
    delegated: Option<(DelegatedCredential, String)>,
    call: Option<Arc<CallArguments>>,
    state: Arc<Mutex<WireState>>,
    parent: CancellationToken,
    deadline: Instant,
    finalization: Option<ProviderFinalizationContext>,
    scope: InvocationScope,
}

impl Operation {
    pub fn new(
        wire: WireClient,
        auth: HeaderMap,
        delegated: Option<(DelegatedCredential, String)>,
        call: Option<CallArguments>,
        timeout: Duration,
    ) -> Self {
        let state = Arc::new(Mutex::new(WireState::default()));
        let finalization = current_provider_finalization();
        let local_deadline = Instant::now() + timeout;
        let deadline = finalization
            .as_ref()
            .and_then(ProviderFinalizationContext::deadline)
            .map_or(local_deadline, |host| host.min(local_deadline));
        Self {
            context: Arc::new(OperationContext {
                wire,
                auth,
                delegated,
                call: call.map(Arc::new),
                state: state.clone(),
                parent: CancellationToken::new(),
                deadline,
                finalization,
                scope: InvocationScope::current(),
            }),
            state,
        }
    }

    pub fn attempt(&self, lifecycle: Lifecycle) -> (HostTransport, CancellationToken) {
        let (sender, receiver) = mpsc::channel(1);
        let cancel = self.context.parent.child_token();
        (
            HostTransport {
                context: self.context.clone(),
                attempt: Arc::new(Attempt {
                    lifecycle,
                    stage: Mutex::new(match lifecycle {
                        Lifecycle::Discover => Stage::Probe,
                        Lifecycle::Initialize => Stage::Initialize,
                    }),
                    cancel: cancel.clone(),
                }),
                sender,
                receiver,
            },
            cancel,
        )
    }

    pub fn begin_legacy(&self) -> Result<bool, ProviderError> {
        let mut state = self.state.lock().expect("wire state");
        self.context.admit(&mut state, false)?;
        if !matches!(state.probe_outcome, Some(ProbeOutcome::Legacy(_))) {
            return Ok(false);
        }
        if state.legacy_started || state.call_attempted {
            return Err(protocol_error());
        }
        state.legacy_started = true;
        state.status = None;
        state.error = None;
        state.result = None;
        Ok(true)
    }

    pub fn error(&self) -> ProviderError {
        let state = self.state.lock().expect("wire state");
        let mut error = state.error.clone().unwrap_or_else(|| {
            // Admission can observe the deadline and close the gate before its
            // caller records a send error. Recover that local outcome without
            // letting a late worker mutate finalized accounting.
            if Instant::now() >= self.context.deadline {
                ProviderError::error(
                    ReasonCode::UpstreamTimeout,
                    "imported MCP operation exceeded its deadline",
                )
            } else if self.context.parent.is_cancelled() {
                cancelled()
            } else {
                protocol_error()
            }
        });
        if state.legacy_started
            && let Some(ProbeOutcome::Legacy(reason)) = state.probe_outcome
        {
            error.message = format!(
                "{} (MCP {PROTOCOL_VERSION} probe: {}; attempted {LEGACY_PROTOCOL_VERSION})",
                error.message,
                reason.label(),
            );
        }
        error.with_upstream(state.status, None)
    }

    /// Cleanup has its own bounded tail inside the original deadline. Once the
    /// main future has returned an outcome, expiry cannot replace that outcome.
    pub async fn run<T>(
        &self,
        work: impl Future<Output = Result<T, ProviderError>>,
        timeout_message: &'static str,
    ) -> Result<T, ProviderError> {
        let outcome = tokio::select! {
            biased;
            _ = self.context.parent.cancelled() => {
                self.context.mark_locally_interrupted();
                Err(cancelled())
            },
            _ = tokio::time::sleep_until(self.context.deadline) => {
                self.context.mark_locally_interrupted();
                Err(ProviderError::error(ReasonCode::UpstreamTimeout, timeout_message))
            },
            result = work => result,
        };
        // The normalized main outcome is now owned by this future. Only its
        // interruptible cleanup remains; no result is published through the host
        // marker. Its guard also clears if the execution future is dropped.
        let _finalization = self
            .context
            .finalization
            .as_ref()
            .map(ProviderFinalizationContext::enter_finalization);
        self.cleanup().await;
        self.close();
        outcome
    }

    async fn cleanup(&self) {
        let candidates = {
            let mut state = self.state.lock().expect("wire state");
            if self.context.admit(&mut state, false).is_err()
                || state.unauthorized
                || state.session_expired
                || state.locally_interrupted
            {
                return;
            }
            state.cleanup = true;
            let mut ids = Vec::with_capacity(2);
            if let Some(id) = &state.session {
                ids.push(id.clone());
            }
            if let Some(id) = &state.probe_session
                && !ids.contains(id)
            {
                ids.push(id.clone());
            }
            ids
        };
        let deadline = self
            .context
            .deadline
            .min(Instant::now() + Duration::from_secs(2));
        let cleanup = async {
            for session in candidates {
                // Revalidate separately for every DELETE; cleanup cannot change
                // normal-operation status or OAuth access-version rejection.
                let _ = self.context.delete_session(session).await;
            }
        };
        let completion = async {
            tokio::select! {
                biased;
                _ = self.context.parent.cancelled() => {},
                _ = tokio::time::sleep_until(deadline) => {},
                _ = self.context.scope.clone().run(cleanup) => {},
            }
        };
        tokio::pin!(completion);
        std::future::poll_fn(|cx| {
            // The host's timer can wake before this timer entry is processed.
            // Check the clock outside select!, which can also yield for the
            // cooperative budget, so the host's one final poll always finishes
            // expired cleanup without polling credential or network work again.
            if Instant::now() >= deadline {
                std::task::Poll::Ready(())
            } else {
                completion.as_mut().poll(cx)
            }
        })
        .await;
    }

    fn close(&self) {
        self.state.lock().expect("wire state").closed = true;
        self.context.parent.cancel();
    }
}

impl Drop for Operation {
    fn drop(&mut self) {
        self.close();
    }
}

impl OperationContext {
    fn mark_locally_interrupted(&self) {
        let mut state = self.state.lock().expect("wire state");
        if !state.closed && !state.cleanup {
            state.locally_interrupted = true;
        }
    }

    /// Check at dispatch under the deadline handler's lock, including after
    /// asynchronous credential work. Cleanup admits only DELETEs.
    fn admit(&self, state: &mut WireState, cleanup: bool) -> Result<(), ProviderError> {
        if Instant::now() >= self.deadline {
            state.closed = true;
            return Err(ProviderError::error(
                ReasonCode::UpstreamTimeout,
                "imported MCP operation exceeded its deadline before dispatch",
            ));
        }
        if self.parent.is_cancelled() {
            state.closed = true;
        }
        if state.closed || state.cleanup != cleanup {
            return Err(cancelled());
        }
        Ok(())
    }

    async fn authentication(&self) -> Result<(HeaderMap, Option<String>), ProviderError> {
        let mut headers = self.auth.clone();
        let mut sent_version = None;
        if let Some((credential, resource)) = &self.delegated {
            credential.revalidate().await?;
            let access = credential.access();
            if access.target != *resource
                || access.audience != *resource
                || access.version.is_empty()
                || !crate::valid_token(&access.token)
            {
                return Err(crate::credential_error());
            }
            let mut bearer = HeaderValue::from_str(&format!("Bearer {}", access.token))
                .map_err(|_| crate::credential_error())?;
            bearer.set_sensitive(true);
            headers.insert("authorization", bearer);
            sent_version = Some(access.version);
        }
        Ok((headers, sent_version))
    }

    async fn post(
        &self,
        body: Value,
        headers: HeaderMap,
        method: &str,
        sent_version: Option<String>,
    ) -> Result<HttpReply, ProviderError> {
        let session_attached = headers.contains_key("mcp-session-id");
        let request = self
            .wire
            .client
            .request(reqwest::Method::POST, self.wire.endpoint.clone())
            .headers(headers)
            .header("accept", "application/json, text/event-stream")
            .json(&body);
        #[cfg(test)]
        {
            let pause = self
                .state
                .lock()
                .expect("wire state")
                .dispatch_pause
                .clone();
            if let Some(pause) = pause {
                pause.0.wait();
                pause.1.wait();
            }
        }
        {
            let mut state = self.state.lock().expect("wire state");
            self.admit(&mut state, false)?;
            state.status = None;
            if method == "tools/call" {
                state.call_dispatched = true;
            }
        }
        let mut response = self
            .wire
            .client
            .send(request, UpstreamCall::new(method))
            .await
            .map_err(|error| {
                if matches!(
                    error,
                    UpstreamError::Timeout
                        | UpstreamError::NotSent {
                            timed_out: true,
                            ..
                        }
                ) {
                    self.mark_locally_interrupted();
                }
                if method == "tools/call"
                    && matches!(
                        error,
                        UpstreamError::NotAllowed | UpstreamError::NotSent { .. }
                    )
                {
                    self.state.lock().expect("wire state").call_dispatched = false;
                }
                ProviderError::error(
                    error.reason_code(),
                    "imported MCP request could not complete",
                )
            })?;
        let status = response.status().as_u16();
        {
            let mut state = self.state.lock().expect("wire state");
            if !state.closed && !state.cleanup {
                state.status = Some(status);
                state.unauthorized |= status == 401;
                state.session_expired |= status == 404 && session_attached;
            }
        }
        if status == 401
            && let (Some((credential, _)), Some(version)) = (&self.delegated, sent_version)
        {
            // Only normal-operation 401s reject this exact access version. No
            // refresh or replay here; cleanup never runs this code.
            let _ = credential.mark_rejected(&version);
        }
        let outcome = self.read_response(&mut response, method).await;
        complete_upstream_trace(&mut response, outcome.as_ref().err().map(|e| e.reason_code));
        outcome
    }

    async fn read_response(
        &self,
        response: &mut reqwest::Response,
        method: &str,
    ) -> Result<HttpReply, ProviderError> {
        let status = response.status().as_u16();
        let probe = method == "server/discover";
        let acknowledgement = method == "notifications/initialized";
        let headers = response.headers().clone();
        if probe && status != 200 && eligible_probe_status(status) {
            if headers.contains_key("www-authenticate") {
                return Err(self.status_error(status, &headers));
            }
            let body = read_bytes(response, self.wire.max_bytes, &self.state).await?;
            return Ok(HttpReply {
                status,
                headers,
                value: serde_json::from_slice(&body).ok(),
            });
        }
        if acknowledgement && matches!(status, 200 | 202 | 204) {
            let body = read_bytes(response, self.wire.max_bytes, &self.state).await?;
            if status == 200 && !body.is_empty() {
                return Err(protocol_error());
            }
            return Ok(HttpReply {
                status,
                headers,
                value: None,
            });
        }
        if status != 200 {
            return Err(self.status_error(status, &headers));
        }
        let content_type = headers
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.split(';').next())
            .unwrap_or("")
            .trim()
            .to_ascii_lowercase();
        let value: Value = match content_type.as_str() {
            "application/json" => {
                let body = read_bytes(response, self.wire.max_bytes, &self.state).await?;
                serde_json::from_slice(&body).map_err(|_| protocol_error())?
            }
            "text/event-stream" => read_sse(response, self.wire.max_bytes, &self.state).await?,
            _ => return Err(protocol_error()),
        };
        if probe && headers.contains_key("www-authenticate") && value.get("error").is_some() {
            return Err(protocol_error());
        }
        Ok(HttpReply {
            status,
            headers,
            value: Some(value),
        })
    }

    fn status_error(&self, status: u16, headers: &HeaderMap) -> ProviderError {
        let reason = match status {
            401 => ReasonCode::UpstreamUnauthorized,
            403 => ReasonCode::UpstreamForbidden,
            429 => ReasonCode::UpstreamRateLimited,
            300..=399 | 400 | 404 | 405 | 406 => ReasonCode::UpstreamProtocolFailed,
            _ => ReasonCode::UpstreamFailed,
        };
        let error = if status == 429 {
            upstream_rate_limited(
                &self.wire.service,
                UpstreamRetryAfter::from_headers(headers),
            )
        } else {
            ProviderError::error(reason, "upstream rejected the imported MCP request")
        };
        error.with_upstream(Some(status), None)
    }

    async fn delete_session(&self, session: HeaderValue) -> Result<(), ProviderError> {
        {
            let mut state = self.state.lock().expect("wire state");
            self.admit(&mut state, true)?;
            if state.unauthorized || state.session_expired {
                return Ok(());
            }
        }
        let (mut headers, _) = self.authentication().await?;
        headers.insert("mcp-session-id", session);
        headers.insert(
            "mcp-protocol-version",
            HeaderValue::from_static(LEGACY_PROTOCOL_VERSION),
        );
        let request = self
            .wire
            .client
            .request(reqwest::Method::DELETE, self.wire.endpoint.clone())
            .headers(headers)
            .header("accept", "application/json, text/event-stream");
        {
            let mut state = self.state.lock().expect("wire state");
            self.admit(&mut state, true)?;
            if state.unauthorized || state.session_expired {
                return Ok(());
            }
        }
        // No normal-operation accounting or token rejection on this path.
        if let Ok(mut response) = self
            .wire
            .client
            .send(request, UpstreamCall::new("session/delete"))
            .await
        {
            let reason = (!response.status().is_success()).then(|| {
                self.status_error(response.status().as_u16(), response.headers())
                    .reason_code
            });
            complete_upstream_trace(&mut response, reason);
        }
        Ok(())
    }
}

struct HttpReply {
    status: u16,
    headers: HeaderMap,
    value: Option<Value>,
}

#[derive(Clone, Copy)]
enum Stage {
    Probe,
    Initialize,
    Acknowledge,
    Ready,
    Sending,
}

struct Attempt {
    lifecycle: Lifecycle,
    stage: Mutex<Stage>,
    cancel: CancellationToken,
}

pub(crate) struct HostTransport {
    context: Arc<OperationContext>,
    attempt: Arc<Attempt>,
    sender: mpsc::Sender<ServerJsonRpcMessage>,
    receiver: mpsc::Receiver<ServerJsonRpcMessage>,
}

#[derive(Debug, thiserror::Error)]
#[error("imported MCP transport failed")]
pub(crate) struct TransportError;

impl Drop for HostTransport {
    fn drop(&mut self) {
        self.attempt.cancel.cancel();
    }
}

impl Transport<RoleClient> for HostTransport {
    type Error = TransportError;

    fn send(
        &mut self,
        item: TxJsonRpcMessage<RoleClient>,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send + 'static {
        let context = self.context.clone();
        let attempt = self.attempt.clone();
        let sender = self.sender.clone();
        async move {
            let operation = send_message(&context, &attempt, item);
            let result = tokio::select! {
                biased;
                _ = attempt.cancel.cancelled() => {
                    context.mark_locally_interrupted();
                    Err(cancelled())
                },
                result = tokio::time::timeout_at(context.deadline, context.scope.clone().run(operation)) => {
                    result.unwrap_or_else(|_| {
                        context.mark_locally_interrupted();
                        Err(ProviderError::error(ReasonCode::UpstreamTimeout, "imported MCP request exceeded its deadline"))
                    })
                }
            };
            match result {
                Ok(Some(message)) => sender.send(message).await.map_err(|_| TransportError),
                Ok(None) => Ok(()),
                Err(error) => {
                    let mut state = context.state.lock().expect("wire state");
                    if !state.closed && !state.cleanup {
                        if attempt.lifecycle == Lifecycle::Discover && state.probe_outcome.is_none()
                        {
                            state.probe_outcome = Some(ProbeOutcome::Terminal);
                        }
                        state.error = Some(error.with_upstream(state.status, None));
                    }
                    Err(TransportError)
                }
            }
        }
    }

    async fn receive(&mut self) -> Option<RxJsonRpcMessage<RoleClient>> {
        tokio::select! { result = self.receiver.recv() => result, _ = self.attempt.cancel.cancelled() => None }
    }

    async fn close(&mut self) -> Result<(), Self::Error> {
        self.attempt.cancel.cancel();
        self.receiver.close();
        Ok(())
    }
}

async fn send_message(
    context: &OperationContext,
    attempt: &Attempt,
    item: TxJsonRpcMessage<RoleClient>,
) -> Result<Option<ServerJsonRpcMessage>, ProviderError> {
    let mut request = serde_json::to_value(item).map_err(|_| protocol_error())?;
    // Never turn SDK cancellation into a network POST, including legacy
    // request-drop notifications. Only this request/attempt is cancelled.
    if request.get("id").is_none()
        && request.get("method").and_then(Value::as_str) == Some("notifications/cancelled")
    {
        return Ok(None);
    }
    let method = request
        .get("method")
        .and_then(Value::as_str)
        .ok_or_else(protocol_error)?
        .to_owned();
    {
        let mut stage = attempt.stage.lock().expect("attempt stage");
        if !matches!(
            (*stage, method.as_str()),
            (Stage::Probe, "server/discover")
                | (Stage::Initialize, "initialize")
                | (Stage::Acknowledge, "notifications/initialized")
                | (Stage::Ready, "tools/list" | "tools/call")
        ) {
            return Err(protocol_error());
        }
        *stage = Stage::Sending;
    }
    let acknowledgement = method == "notifications/initialized";
    let id = if acknowledgement {
        if request.get("id").is_some() {
            return Err(protocol_error());
        }
        None
    } else {
        Some(
            request
                .get("id")
                .filter(|id| id.is_number() || id.is_string())
                .cloned()
                .ok_or_else(protocol_error)?,
        )
    };
    if acknowledgement {
        request = json!({"jsonrpc":"2.0", "method":"notifications/initialized"});
    }
    {
        let mut state = context.state.lock().expect("wire state");
        context.admit(&mut state, false)?;
        state.status = None;
        if method == "tools/call" {
            if state.call_attempted {
                return Err(protocol_error());
            }
            state.call_attempted = true;
        }
    }
    let (mut headers, sent_version) = context.authentication().await?;
    let modern = attempt.lifecycle == Lifecycle::Discover;
    if modern {
        headers.insert(
            "mcp-protocol-version",
            HeaderValue::from_static(PROTOCOL_VERSION),
        );
        headers.insert(
            "mcp-method",
            HeaderValue::from_str(&method).map_err(|_| protocol_error())?,
        );
    } else if method != "initialize" {
        headers.insert(
            "mcp-protocol-version",
            HeaderValue::from_static(LEGACY_PROTOCOL_VERSION),
        );
        if let Some(session) = context.state.lock().expect("wire state").session.clone() {
            headers.insert("mcp-session-id", session);
        }
    }
    if !acknowledgement {
        let params = request
            .as_object_mut()
            .ok_or_else(protocol_error)?
            .entry("params")
            .or_insert_with(|| json!({}));
        let params = params.as_object_mut().ok_or_else(protocol_error)?;
        if modern {
            params.insert("_meta".into(), json!({
                "io.modelcontextprotocol/protocolVersion": PROTOCOL_VERSION,
                "io.modelcontextprotocol/clientInfo": {"name":"agent-access-broker", "version": env!("CARGO_PKG_VERSION")},
                "io.modelcontextprotocol/clientCapabilities": {}
            }));
        } else {
            params.remove("_meta");
        }
        if method == "tools/list" {
            match context.state.lock().expect("wire state").cursor.clone() {
                Some(cursor) => {
                    params.insert("cursor".into(), Value::String(cursor));
                }
                None => {
                    params.remove("cursor");
                }
            }
        }
        if method == "tools/call" {
            let call = context.call.as_ref().ok_or_else(protocol_error)?;
            params.insert("name".into(), Value::String(call.name.clone()));
            params.insert(
                "arguments".into(),
                if modern {
                    call.modern_arguments.clone()
                } else {
                    call.arguments.clone()
                },
            );
            if modern {
                let mut name = HeaderValue::from_str(&encode_header(&call.name))
                    .map_err(|_| protocol_error())?;
                name.set_sensitive(true);
                headers.insert("mcp-name", name);
                headers.extend(call.headers.clone());
            }
        }
    }
    let reply = context
        .post(request, headers, &method, sent_version)
        .await?;
    if acknowledgement {
        context.state.lock().expect("wire state").protocol_version = Some(LEGACY_PROTOCOL_VERSION);
        *attempt.stage.lock().expect("attempt stage") = Stage::Ready;
        return Ok(None);
    }
    let id = id.ok_or_else(protocol_error)?;
    let result = if method == "server/discover" {
        match classify_probe(reply.status, reply.value, &id)? {
            ProbeSelection::Current(result) => {
                let mut state = context.state.lock().expect("wire state");
                state.protocol_version = Some(PROTOCOL_VERSION);
                state.probe_outcome = Some(ProbeOutcome::Current);
                result
            }
            ProbeSelection::Legacy(reason) => {
                if reply.headers.contains_key("www-authenticate") {
                    return Err(protocol_error());
                }
                let mut state = context.state.lock().expect("wire state");
                state.probe_outcome = Some(ProbeOutcome::Legacy(reason));
                if eligible_probe_status(reply.status) {
                    state.probe_session = session_header(&reply.headers).ok().flatten();
                }
                return Err(ProviderError::error(
                    ReasonCode::UpstreamProtocolFailed,
                    "MCP current discovery requires the previous initialization lifecycle",
                ));
            }
        }
    } else {
        validate_reply(reply.value.ok_or_else(protocol_error)?, &id)?
    };
    let sanitized = match method.as_str() {
        "server/discover" => {
            json!({"resultType":"complete","supportedVersions":[PROTOCOL_VERSION], "capabilities":{"tools":{}}, "ttlMs":0,"cacheScope":"private"})
        }
        "initialize" => {
            // Correlation and a successful envelope precede session retention;
            // later capability/version validation can still require cleanup.
            context.state.lock().expect("wire state").session = session_header(&reply.headers)?;
            validate_initialize(&result)?;
            json!({"protocolVersion":LEGACY_PROTOCOL_VERSION,"capabilities":{"tools":{}},"serverInfo":{"name":"imported-mcp","version":"redacted"}})
        }
        "tools/list" => {
            if !result.get("tools").is_some_and(Value::is_array)
                || result.get("nextCursor").is_some_and(|v| !v.is_string())
                || result.get("ttlMs").is_some_and(|v| v.as_i64().is_none())
                || result
                    .get("cacheScope")
                    .is_some_and(|v| !matches!(v.as_str(), Some("private" | "public")))
            {
                return Err(protocol_error());
            }
            json!({"resultType":"complete","tools":[],"ttlMs":0,"cacheScope":"private"})
        }
        _ => json!({"resultType":"complete","content":[],"isError":false}),
    };
    context.state.lock().expect("wire state").result = Some(result);
    *attempt.stage.lock().expect("attempt stage") = if method == "initialize" {
        Stage::Acknowledge
    } else {
        Stage::Ready
    };
    let message = serde_json::from_value(json!({"jsonrpc":"2.0", "id":id,"result":sanitized}))
        .map_err(|_| protocol_error())?;
    Ok(Some(message))
}

fn session_header(headers: &HeaderMap) -> Result<Option<HeaderValue>, ProviderError> {
    let mut values = headers.get_all("mcp-session-id").iter();
    let Some(value) = values.next() else {
        return Ok(None);
    };
    if values.next().is_some()
        || value.is_empty()
        || value.as_bytes().len() > 4096
        || !value
            .as_bytes()
            .iter()
            .all(|byte| (0x21..=0x7e).contains(byte))
    {
        return Err(protocol_error());
    }
    let mut value = value.clone();
    value.set_sensitive(true);
    Ok(Some(value))
}

fn cancelled() -> ProviderError {
    ProviderError::error(
        ReasonCode::OperationCancelled,
        "imported MCP request was cancelled before dispatch",
    )
}

fn body_error(error: reqwest::Error, state: &Mutex<WireState>) -> ProviderError {
    if error.is_timeout() {
        let mut state = state.lock().expect("wire state");
        if !state.closed && !state.cleanup {
            state.locally_interrupted = true;
        }
    }
    ProviderError::error(
        if error.is_timeout() {
            ReasonCode::UpstreamTimeout
        } else {
            ReasonCode::UpstreamConnectionFailed
        },
        "imported MCP response could not be read",
    )
}

async fn read_bytes(
    response: &mut reqwest::Response,
    max_bytes: u64,
    state: &Mutex<WireState>,
) -> Result<Vec<u8>, ProviderError> {
    if response
        .content_length()
        .is_some_and(|length| length > max_bytes)
    {
        return Err(protocol_error());
    }
    let mut body = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|error| body_error(error, state))?
    {
        if body.len() as u64 + chunk.len() as u64 > max_bytes {
            return Err(protocol_error());
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

async fn read_sse(
    response: &mut reqwest::Response,
    max_bytes: u64,
    state: &Mutex<WireState>,
) -> Result<Value, ProviderError> {
    if response
        .content_length()
        .is_some_and(|length| length > max_bytes)
    {
        return Err(protocol_error());
    }
    let mut decoder = SseDecoder::default();
    let mut bytes = 0_u64;
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|error| body_error(error, state))?
    {
        bytes = bytes
            .checked_add(chunk.len() as u64)
            .filter(|v| *v <= max_bytes)
            .ok_or_else(protocol_error)?;
        if let Some(reply) = decoder.push(&chunk)? {
            return Ok(reply);
        }
    }
    Err(protocol_error())
}

/// Bounded by the entire HTTP response budget, including comments and notifications.
#[derive(Default)]
struct SseDecoder {
    line: Vec<u8>,
    data: String,
    after_cr: bool,
    initial: bool,
}

impl SseDecoder {
    fn push(&mut self, chunk: &[u8]) -> Result<Option<Value>, ProviderError> {
        for byte in chunk {
            if self.after_cr && *byte == b'\n' {
                self.after_cr = false;
                continue;
            }
            self.after_cr = false;
            if matches!(*byte, b'\r' | b'\n') {
                self.after_cr = *byte == b'\r';
                if self.line.is_empty() {
                    if self.data.trim().is_empty() {
                        self.data.clear();
                        continue;
                    }
                    let data = std::mem::take(&mut self.data);
                    let message: Value =
                        serde_json::from_str(&data).map_err(|_| protocol_error())?;
                    if message.get("method").is_some() {
                        if message.get("id").is_some()
                            || message.get("jsonrpc").and_then(Value::as_str) != Some("2.0")
                        {
                            return Err(protocol_error());
                        }
                        // No notifications enter SDK logs, callbacks, or cache state.
                        continue;
                    }
                    return Ok(Some(message));
                }
                let bytes = std::mem::take(&mut self.line);
                let line = std::str::from_utf8(&bytes).map_err(|_| protocol_error())?;
                let line = if !self.initial {
                    self.initial = true;
                    line.trim_start_matches('\u{feff}')
                } else {
                    line
                };
                if let Some(value) = line.strip_prefix("data:") {
                    if !self.data.is_empty() {
                        self.data.push('\n');
                    }
                    self.data.push_str(value.strip_prefix(' ').unwrap_or(value));
                } else if line == "data" {
                    self.data.push('\n');
                }
            } else {
                self.line.push(*byte);
            }
        }
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn operation(endpoint: &str, timeout: Duration) -> Operation {
        use agent_access_provider::{
            BuildContext, EgressProxyEnvironment, EgressProxyRuntimeConfig,
            ImportedServiceDefinition, ProviderLimits, test_support,
        };
        let definition: ImportedServiceDefinition = serde_json::from_value(json!({"service":"race","displayName":"Race","adapterKind":"mcp_http","endpoint":endpoint,"executionBindings":[{"ownerMode":"service","mechanism":"static_token","delivery":{"kind":"bearer"},"status":"configured"}],"discovery":{"kind":"execution"}})).unwrap();
        let limits = ProviderLimits::default();
        let egress = EgressProxyRuntimeConfig::new(Arc::new(EgressProxyEnvironment::empty()), None);
        let tls = test_support::test_outbound_tls();
        let wire = crate::make_wire(
            &definition,
            &BuildContext {
                limits: &limits,
                egress: &egress,
                outbound_tls: &tls,
                attribution: Default::default(),
                stable_signing_key: None,
            },
        )
        .unwrap();
        Operation::new(wire, HeaderMap::new(), None, None, timeout)
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn deadline_closes_dispatch_gate_while_another_worker_prepares_a_send() {
        let received = Arc::new(AtomicUsize::new(0));
        let counter = received.clone();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://{}/mcp", listener.local_addr().unwrap());
        let app = axum::Router::new().route(
            "/mcp",
            axum::routing::post(move || {
                let counter = counter.clone();
                async move {
                    counter.fetch_add(1, Ordering::SeqCst);
                    axum::Json(json!({"jsonrpc":"2.0","id":1,"result":{"content":[]}}))
                }
            }),
        );
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        for method in ["server/discover", "initialize", "tools/call"] {
            let operation = operation(&endpoint, Duration::from_secs(60));
            if method != "server/discover" {
                operation.state.lock().unwrap().probe_outcome =
                    Some(ProbeOutcome::Legacy(LegacyReason::HttpRejection));
                let (mut probe, _) = operation.attempt(Lifecycle::Discover);
                probe.close().await.unwrap();
                assert!(operation.begin_legacy().unwrap());
            }
            let pause = Arc::new((std::sync::Barrier::new(2), std::sync::Barrier::new(2)));
            operation.state.lock().unwrap().dispatch_pause = Some(pause.clone());
            let context = operation.context.clone();
            let send = tokio::spawn(async move {
                context
                    .post(
                        json!({"jsonrpc":"2.0","id":1,"method":method,"params":{}}),
                        HeaderMap::new(),
                        method,
                        None,
                    )
                    .await
            });
            let entered = pause.clone();
            tokio::task::spawn_blocking(move || entered.0.wait())
                .await
                .unwrap();
            // Deadline/cancellation closes the operation on this worker while a
            // different send worker has prepared its body but not admitted it.
            operation.close();
            pause.1.wait();
            let result = send.await.unwrap();
            assert_eq!(
                result.err().unwrap().reason_code,
                ReasonCode::OperationCancelled
            );
            assert_eq!(received.load(Ordering::SeqCst), 0);
            assert!(!operation.state.lock().unwrap().call_dispatched);
            assert!(operation.begin_legacy().is_err());
        }
        server.abort();
    }

    #[tokio::test]
    async fn closing_an_attempt_does_not_reopen_or_close_shared_operation_fences() {
        let operation = operation("http://127.0.0.1:9/mcp", Duration::from_secs(60));
        {
            let mut state = operation.state.lock().unwrap();
            state.probe_outcome = Some(ProbeOutcome::Legacy(LegacyReason::HttpRejection));
            state.status = Some(404);
            state.error = Some(protocol_error());
        }
        let (mut current, current_cancel) = operation.attempt(Lifecycle::Discover);
        current.close().await.unwrap();
        assert!(current_cancel.is_cancelled());
        assert!(!operation.context.parent.is_cancelled());
        assert!(!operation.state.lock().unwrap().closed);
        assert!(operation.begin_legacy().unwrap());
        {
            let state = operation.state.lock().unwrap();
            assert!(state.status.is_none());
            assert!(state.error.is_none());
        }
        let (mut legacy, legacy_cancel) = operation.attempt(Lifecycle::Initialize);
        assert!(Arc::ptr_eq(&current.context.state, &legacy.context.state));
        assert!(!legacy_cancel.is_cancelled());
        assert!(operation.begin_legacy().is_err());
        legacy.close().await.unwrap();
        assert!(!operation.state.lock().unwrap().closed);
        operation.close();
        assert!(operation.state.lock().unwrap().closed);
        assert!(operation.begin_legacy().is_err());
    }

    #[tokio::test]
    async fn unrecorded_admission_deadlines_and_cancellation_keep_their_reason() {
        let expired = operation("http://127.0.0.1:9/mcp", Duration::ZERO);
        {
            let mut state = expired.state.lock().unwrap();
            assert_eq!(
                expired
                    .context
                    .admit(&mut state, false)
                    .unwrap_err()
                    .reason_code,
                ReasonCode::UpstreamTimeout
            );
            assert!(state.closed);
            assert!(state.error.is_none());
        }
        assert_eq!(expired.error().reason_code, ReasonCode::UpstreamTimeout);
        let cancelled = operation("http://127.0.0.1:9/mcp", Duration::from_secs(60));
        cancelled.close();
        assert_eq!(
            cancelled.error().reason_code,
            ReasonCode::OperationCancelled
        );
        for operation in [&expired, &cancelled] {
            let mut state = operation.state.lock().unwrap();
            state.error = Some(ProviderError::error(
                ReasonCode::UpstreamForbidden,
                "rejected",
            ));
            state.status = Some(403);
            drop(state);
            let error = operation.error();
            assert_eq!(error.reason_code, ReasonCode::UpstreamForbidden);
            assert_eq!(error.upstream_status, Some(403));
        }
    }

    #[tokio::test]
    async fn inherited_deadline_fences_every_dispatch_and_never_extends_local_budget() {
        use agent_access_provider::with_provider_finalization;
        let host = Instant::now();
        with_provider_finalization(ProviderFinalizationContext::new(Some(host)), async {
            let operation = operation("http://127.0.0.1:9/mcp", Duration::from_secs(60));
            assert_eq!(operation.context.deadline, host);
            for method in ["server/discover", "initialize", "tools/call"] {
                let error = operation
                    .context
                    .post(
                        json!({"jsonrpc":"2.0","id":1,"method":method,"params":{}}),
                        HeaderMap::new(),
                        method,
                        None,
                    )
                    .await
                    .err()
                    .unwrap();
                assert_eq!(error.reason_code, ReasonCode::UpstreamTimeout, "{method}");
            }
            let error = operation
                .context
                .delete_session(HeaderValue::from_static("private-session"))
                .await
                .unwrap_err();
            assert_eq!(error.reason_code, ReasonCode::UpstreamTimeout);
            assert!(operation.begin_legacy().is_err());
            let state = operation.state.lock().unwrap();
            assert!(state.closed);
            assert!(!state.call_dispatched);
        })
        .await;
        let host = Instant::now() + Duration::from_secs(60);
        with_provider_finalization(ProviderFinalizationContext::new(Some(host)), async {
            let operation = operation("http://127.0.0.1:9/mcp", Duration::ZERO);
            assert!(operation.context.deadline < host);
            assert!(
                operation
                    .context
                    .admit(&mut operation.state.lock().unwrap(), false)
                    .is_err()
            );
        })
        .await;
    }

    #[tokio::test]
    async fn cancellation_notifications_are_local_for_both_lifecycles() {
        for lifecycle in [Lifecycle::Discover, Lifecycle::Initialize] {
            let operation = operation("http://127.0.0.1:9/mcp", Duration::from_secs(60));
            let (mut transport, _) = operation.attempt(lifecycle);
            let notification = serde_json::from_value(json!({"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":1}})).unwrap();
            transport.send(notification).await.unwrap();
            let state = operation.state.lock().unwrap();
            assert!(state.status.is_none());
            assert!(state.error.is_none());
            assert!(!state.call_dispatched);
        }
    }

    #[tokio::test]
    async fn cleanup_deadline_preserves_the_known_operation_outcome() {
        use agent_access_provider::with_provider_finalization;
        let received = Arc::new(AtomicUsize::new(0));
        let counter = received.clone();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://{}/mcp", listener.local_addr().unwrap());
        let app = axum::Router::new().route(
            "/mcp",
            axum::routing::delete(move || {
                let counter = counter.clone();
                async move {
                    counter.fetch_add(1, Ordering::SeqCst);
                    tokio::time::sleep(Duration::from_secs(5)).await;
                    axum::http::StatusCode::NO_CONTENT
                }
            }),
        );
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let finalization =
            ProviderFinalizationContext::new(Some(Instant::now() + Duration::from_millis(250)));
        let operation = with_provider_finalization(finalization.clone(), async {
            operation(&endpoint, Duration::from_secs(60))
        })
        .await;
        {
            let mut state = operation.state.lock().unwrap();
            state.session = Some(HeaderValue::from_static("private-session"));
            state.status = Some(200);
            state.call_dispatched = true;
        }
        let result = tokio::time::timeout(
            Duration::from_secs(1),
            operation.run(async { Ok(42) }, "deadline"),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(result, 42);
        assert!(!finalization.is_finalizing());
        assert_eq!(received.load(Ordering::SeqCst), 1);
        let state = operation.state.lock().unwrap();
        assert!(state.closed);
        assert_eq!(state.status, Some(200));
        assert!(state.call_dispatched);
        server.abort();
    }

    #[tokio::test(flavor = "current_thread")]
    async fn expired_cleanup_finishes_in_one_poll_before_its_timer_is_fired() {
        use futures_util::FutureExt;
        use tokio::sync::{Notify, Semaphore};

        let received = Arc::new(AtomicUsize::new(0));
        let started = Arc::new(Semaphore::new(0));
        let release = Arc::new(Notify::new());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://{}/mcp", listener.local_addr().unwrap());
        let app = axum::Router::new().route(
            "/mcp",
            axum::routing::delete({
                let received = received.clone();
                let started = started.clone();
                let release = release.clone();
                move || {
                    let received = received.clone();
                    let started = started.clone();
                    let release = release.clone();
                    async move {
                        received.fetch_add(1, Ordering::SeqCst);
                        started.add_permits(1);
                        release.notified().await;
                        axum::http::StatusCode::NO_CONTENT
                    }
                }
            }),
        );
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let operation = operation(&endpoint, Duration::from_secs(1));
        {
            let mut state = operation.state.lock().unwrap();
            state.session = Some(HeaderValue::from_static("main-session"));
            state.probe_session = Some(HeaderValue::from_static("probe-session"));
            state.status = Some(200);
            state.call_dispatched = true;
        }
        let work = operation.run(async { Ok(42) }, "deadline");
        tokio::pin!(work);
        tokio::select! {
            biased;
            permit = started.acquire() => permit.unwrap().forget(),
            result = &mut work => panic!("cleanup finished before its first DELETE: {result:?}"),
        }

        let deadline = operation.context.deadline;
        let timer = tokio::time::sleep_until(deadline);
        tokio::pin!(timer);
        assert!(timer.as_mut().now_or_never().is_none());
        // Intentionally block this sole runtime thread: wall time expires, but
        // neither registered timer can be processed by the driver yet.
        std::thread::sleep(
            deadline.saturating_duration_since(Instant::now()) + Duration::from_millis(20),
        );
        assert!(Instant::now() >= deadline);
        assert!(timer.as_mut().now_or_never().is_none());
        assert_eq!(work.as_mut().now_or_never().unwrap().unwrap(), 42);
        {
            let state = operation.state.lock().unwrap();
            assert!(state.closed);
            assert_eq!(state.status, Some(200));
            assert!(state.call_dispatched);
        }
        assert_eq!(received.load(Ordering::SeqCst), 1);
        release.notify_one();
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert_eq!(
            received.load(Ordering::SeqCst),
            1,
            "no probe-session DELETE after expiry"
        );
        server.abort();
    }

    #[test]
    fn sse_fragmented_comments_notifications_and_response() {
        let bytes = b":keepalive\r\ndata: \r\n\r\ndata: {\"jsonrpc\":\"2.0\",\"method\":\"notifications/progress\",\"params\":{}}\r\n\r\ndata: {\"jsonrpc\":\"2.0\",\"id\":2,\"result\":{}}\n\n";
        let mut decoder = SseDecoder::default();
        let mut result = None;
        for byte in bytes {
            result = decoder.push(&[*byte]).unwrap().or(result);
        }
        assert_eq!(result.unwrap()["id"], 2);
    }

    #[test]
    fn correlation_and_complete_discriminator_are_required() {
        assert!(validate_reply(json!({"jsonrpc":"2.0","id":3,"result":{}}), &json!(3)).is_ok());
        for reply in [
            json!({"jsonrpc":"2.0","id":4,"result":{}}),
            json!({"jsonrpc":"2.0","id":3,"result":{"resultType":"input_required"}}),
            json!({"jsonrpc":"2.0","id":3,"result":{},"error":{}}),
        ] {
            assert!(validate_reply(reply, &json!(3)).is_err());
        }
    }
}
