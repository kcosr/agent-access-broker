use crate::host::HostPort;
use crate::{Decision, ProviderReason, ProviderReasonDefinition, ReasonCode};
use bytes::Bytes;
use futures_util::{Stream, StreamExt, stream};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use thiserror::Error;

/// A successful outcome: its JSON result or a streamed body, with optional
/// audit data and upstream facts.
///
/// Equality compares the public fields and the ordered secret-output pointers,
/// never the protected secret values. Providers can compare synthetic secret
/// values only with the feature-gated `test_support::secret_outputs_match`.
///
/// The public fields are the data the host reads. Build a result with
/// [`Self::new`] and the `with_*` methods:
///
/// ```
/// use agent_access_provider::ProviderResult;
/// use serde_json::json;
///
/// let result = ProviderResult::new(json!({"id": "42"}))
///     .with_audit(json!({"operation": "item.view"}))
///     .with_upstream(Some(200), Some(12));
/// assert_eq!(result.upstream_status, Some(200));
/// assert!(result.stream.is_none());
/// ```
#[non_exhaustive]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProviderResult {
    pub result: Value,
    /// Secret values travel separately from ordinary result JSON. Only the
    /// host extraction port reads them; serde never reads or writes them.
    #[serde(skip)]
    pub(crate) secret_outputs: Vec<crate::secret::SecretOutputValue>,
    #[serde(skip)]
    pub stream: Option<ProviderResultStream>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub audit: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub upstream_status: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub upstream_duration_ms: Option<u64>,
    /// Safe, non-secret object locators, such as upstream IDs, for audit and
    /// recovery. Never include credentials, secret values or secret references.
    ///
    /// Temporary-secret outcome receipts inspect at most 32 object fields and
    /// retain only string, number or boolean values. Keys are limited to 64
    /// UTF-8 bytes and string values to 256; neither may contain control
    /// characters. Unsupported fields are omitted. If the retained object
    /// exceeds 4 KiB of serialized JSON, the entire `objectIds` block is omitted
    /// without failing secret capture. Callers must not rely on receipts
    /// retaining every locator or arbitrary metadata.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub object_ids: Option<Value>,
}

impl PartialEq for ProviderResult {
    fn eq(&self, other: &Self) -> bool {
        self.result == other.result
            && self.stream == other.stream
            && self.audit == other.audit
            && self.upstream_status == other.upstream_status
            && self.upstream_duration_ms == other.upstream_duration_ms
            && self.object_ids == other.object_ids
            && self
                .secret_outputs
                .iter()
                .map(|output| output.pointer())
                .eq(other.secret_outputs.iter().map(|output| output.pointer()))
    }
}

impl ProviderResult {
    /// A result carrying `result`, with no streamed body, audit data or
    /// upstream facts.
    pub fn new(result: Value) -> Self {
        Self {
            result,
            secret_outputs: Vec::new(),
            stream: None,
            audit: None,
            upstream_status: None,
            upstream_duration_ms: None,
            object_ids: None,
        }
    }

    /// Streams `stream` as the response body; `result` becomes its metadata.
    pub fn with_stream(mut self, stream: ProviderResultStream) -> Self {
        self.stream = Some(stream);
        self
    }

    /// Supplies one declared transferable secret, at an envelope-relative
    /// `/result/...` pointer. Keep that property absent from ordinary result
    /// JSON; the host inserts its configured raw value or protected reference.
    /// The host rejects undeclared, duplicate, missing required or oversized
    /// values. The owned string is zeroized when this sidecar is dropped.
    pub fn with_secret_output(mut self, pointer: impl Into<String>, value: String) -> Self {
        self.secret_outputs
            .push(crate::secret::SecretOutputValue::new(pointer.into(), value));
        self
    }

    pub fn with_audit(mut self, audit: Value) -> Self {
        self.audit = Some(audit);
        self
    }

    pub fn with_upstream(mut self, status: Option<u16>, duration_ms: Option<u64>) -> Self {
        self.upstream_status = status;
        self.upstream_duration_ms = duration_ms;
        self
    }

    /// Supplies safe, non-secret locators subject to the receipt-retention
    /// contract documented on [`Self::object_ids`].
    pub fn with_object_ids(mut self, object_ids: Value) -> Self {
        self.object_ids = Some(object_ids);
        self
    }
}

/// A result body: its content type and its bytes, in memory or streamed.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq)]
pub struct ProviderResultStream {
    pub content_type: String,
    pub source: ProviderResultStreamSource,
}

impl ProviderResultStream {
    pub fn from_bytes(content_type: impl Into<String>, bytes: Vec<u8>) -> Self {
        Self {
            content_type: content_type.into(),
            source: ProviderResultStreamSource::Memory(bytes),
        }
    }

    pub fn from_stream(
        content_type: impl Into<String>,
        stream: impl Stream<Item = Result<Bytes, ProviderStreamError>> + Send + 'static,
    ) -> Self {
        Self {
            content_type: content_type.into(),
            source: ProviderResultStreamSource::Stream(Arc::new(Mutex::new(Some(Box::pin(
                stream,
            ))))),
        }
    }

    /// Streams `response`'s body as a raw download within `download`'s
    /// bounds. Each failure after the headers is a late, code-only
    /// [`ProviderStreamError`]:
    ///
    /// - no chunk within the idle timeout, or the client's own deadline
    ///   expiring, is `upstream_timeout`;
    /// - another failed read is `upstream_connection_failed`;
    /// - more bytes than the cap is the download's cap reason;
    /// - a body that overruns the expected size, or ends short of it, is
    ///   `upstream_protocol_failed`.
    ///
    /// Messages name the download by its label and carry no URL or upstream
    /// detail. Reject a declared `Content-Length` over the cap before calling
    /// this, while the failure can still be an ordinary provider error.
    pub fn from_bounded_response(
        content_type: impl Into<String>,
        response: reqwest::Response,
        download: BoundedDownload,
    ) -> Self {
        let BoundedDownload {
            label,
            byte_cap,
            cap_reason,
            idle_timeout,
            expected_size,
        } = download;
        let chunks =
            stream::try_unfold((response, 0_u64), move |(mut response, size)| async move {
                let chunk = tokio::time::timeout(idle_timeout, response.chunk())
                    .await
                    .map_err(|_| {
                        ProviderStreamError::new(
                            ReasonCode::UpstreamTimeout,
                            format!("{label} stalled"),
                        )
                    })?
                    .map_err(|error| {
                        let reason = if error.is_timeout() {
                            ReasonCode::UpstreamTimeout
                        } else {
                            ReasonCode::UpstreamConnectionFailed
                        };
                        ProviderStreamError::new(reason, format!("{label} failed"))
                    })?;
                let Some(chunk) = chunk else {
                    return Ok(None);
                };
                let size = size
                    .checked_add(chunk.len() as u64)
                    .filter(|size| *size <= byte_cap)
                    .ok_or_else(|| {
                        ProviderStreamError::new(
                            cap_reason,
                            format!("{label} exceeded the download limit"),
                        )
                    })?;
                Ok(Some((chunk, (response, size))))
            });
        let stream = Self::from_stream(content_type, chunks);
        match expected_size {
            Some(expected_size) => stream.with_expected_size(
                expected_size,
                format!("{label} size did not match Content-Length"),
            ),
            None => stream,
        }
    }

    pub fn with_expected_size(
        self,
        expected_size: u64,
        mismatch_message: impl Into<String>,
    ) -> Self {
        let mismatch_message = mismatch_message.into();
        let ProviderResultStream {
            content_type,
            source,
        } = self;
        let source = match source {
            ProviderResultStreamSource::Memory(bytes) => {
                if bytes.len() as u64 == expected_size {
                    ProviderResultStreamSource::Memory(bytes)
                } else {
                    ProviderResultStreamSource::Stream(Arc::new(Mutex::new(Some(Box::pin(
                        stream::iter([Err(ProviderStreamError::new(
                            ReasonCode::UpstreamProtocolFailed,
                            mismatch_message,
                        ))]),
                    )))))
                }
            }
            ProviderResultStreamSource::Stream(stream) => {
                let message = mismatch_message;
                let wrapped =
                    stream
                        .lock()
                        .ok()
                        .and_then(|mut stream| stream.take())
                        .map(|stream| {
                            Box::pin(expected_size_stream(stream, expected_size, message))
                                as ProviderByteStream
                        });
                ProviderResultStreamSource::Stream(Arc::new(Mutex::new(wrapped)))
            }
        };
        Self {
            content_type,
            source,
        }
    }

    /// Whether the body can still be read: in-memory bodies always can, a
    /// stream only until it has been taken.
    pub fn is_ready(&self) -> bool {
        match &self.source {
            ProviderResultStreamSource::Memory(_) => true,
            ProviderResultStreamSource::Stream(stream) => stream
                .lock()
                .map(|stream| stream.is_some())
                .unwrap_or(false),
        }
    }

    pub fn is_streaming(&self) -> bool {
        matches!(self.source, ProviderResultStreamSource::Stream(_))
    }

    /// Wraps a streaming body; in-memory bodies are returned unchanged.
    pub fn map_byte_stream(
        self,
        wrap: impl FnOnce(ProviderByteStream) -> ProviderByteStream,
    ) -> Self {
        let ProviderResultStream {
            content_type,
            source,
        } = self;
        let source = match source {
            ProviderResultStreamSource::Memory(bytes) => ProviderResultStreamSource::Memory(bytes),
            ProviderResultStreamSource::Stream(stream) => {
                let wrapped = stream
                    .lock()
                    .ok()
                    .and_then(|mut stream| stream.take())
                    .map(wrap);
                ProviderResultStreamSource::Stream(Arc::new(Mutex::new(wrapped)))
            }
        };
        Self {
            content_type,
            source,
        }
    }

    #[cfg(any(test, feature = "test-support"))]
    pub fn memory_len(&self) -> Option<usize> {
        match &self.source {
            ProviderResultStreamSource::Memory(bytes) => Some(bytes.len()),
            ProviderResultStreamSource::Stream(_) => None,
        }
    }
}

/// How [`ProviderResultStream::from_bounded_response`] bounds a raw
/// download after its headers arrived.
#[non_exhaustive]
#[derive(Debug, Clone, Copy)]
pub struct BoundedDownload {
    label: &'static str,
    byte_cap: u64,
    cap_reason: ProviderReason,
    idle_timeout: Duration,
    expected_size: Option<u64>,
}

impl BoundedDownload {
    /// A download of at most `byte_cap` bytes, failing with `cap_reason`
    /// beyond it, that fails once no chunk arrives for `idle_timeout`.
    /// `label` names it in failure messages, such as `"Notes attachment
    /// download"`.
    ///
    /// The cap reason must be one a late stream may report: a standard one
    /// [`ReasonCode::permits_late_stream`] admits, such as
    /// `upstream_protocol_failed` or `attachment_size_denied`, or one of the
    /// backend's domain reasons.
    pub fn new(
        label: &'static str,
        byte_cap: u64,
        cap_reason: impl Into<ProviderReason>,
        idle_timeout: Duration,
    ) -> Self {
        Self {
            label,
            byte_cap,
            cap_reason: cap_reason.into(),
            idle_timeout,
            expected_size: None,
        }
    }

    /// The body must be exactly `expected_size` bytes when it is known,
    /// usually the response's `Content-Length`.
    pub fn with_expected_size(mut self, expected_size: Option<u64>) -> Self {
        self.expected_size = expected_size;
        self
    }
}

pub type ProviderByteStream =
    Pin<Box<dyn Stream<Item = Result<Bytes, ProviderStreamError>> + Send + 'static>>;

/// A failure after a result stream started. It carries only a reason code:
/// the host keeps its own late-failure decision and committed response, and
/// classifies delivery and the final audit record with this code. Standard
/// codes come from the late-stream subset
/// ([`ReasonCode::permits_late_stream`]); a backend may also use one of its
/// registered domain reasons.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[error("{reason_code:?}: {message}")]
pub struct ProviderStreamError {
    pub reason_code: ProviderReason,
    pub message: String,
}

impl ProviderStreamError {
    pub fn new(reason_code: impl Into<ProviderReason>, message: impl Into<String>) -> Self {
        Self {
            reason_code: reason_code.into(),
            message: message.into(),
        }
    }
}

/// Where a result body's bytes are: in memory, or a stream the host takes
/// once.
///
/// Intentionally exhaustive: the host must deliver every source, so a new
/// one is an incompatible change.
pub enum ProviderResultStreamSource {
    Memory(Vec<u8>),
    Stream(Arc<Mutex<Option<ProviderByteStream>>>),
}

fn expected_size_stream(
    stream: ProviderByteStream,
    expected_size: u64,
    mismatch_message: String,
) -> impl Stream<Item = Result<Bytes, ProviderStreamError>> + Send + 'static {
    stream::try_unfold(
        (stream, 0_u64, mismatch_message),
        move |(mut stream, size, mismatch_message)| async move {
            let Some(chunk) = stream.next().await.transpose()? else {
                if size != expected_size {
                    return Err(ProviderStreamError::new(
                        ReasonCode::UpstreamProtocolFailed,
                        mismatch_message,
                    ));
                }
                return Ok(None);
            };
            let next_size = size.checked_add(chunk.len() as u64).ok_or_else(|| {
                ProviderStreamError::new(ReasonCode::UpstreamProtocolFailed, &mismatch_message)
            })?;
            if next_size > expected_size {
                return Err(ProviderStreamError::new(
                    ReasonCode::UpstreamProtocolFailed,
                    mismatch_message,
                ));
            }
            Ok(Some((chunk, (stream, next_size, mismatch_message))))
        },
    )
}

impl Clone for ProviderResultStreamSource {
    fn clone(&self) -> Self {
        match self {
            Self::Memory(bytes) => Self::Memory(bytes.clone()),
            Self::Stream(stream) => Self::Stream(Arc::clone(stream)),
        }
    }
}

impl std::fmt::Debug for ProviderResultStreamSource {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Memory(bytes) => formatter
                .debug_tuple("Memory")
                .field(&format_args!("{} bytes", bytes.len()))
                .finish(),
            Self::Stream(_) => formatter.debug_tuple("Stream").finish(),
        }
    }
}

impl PartialEq for ProviderResultStreamSource {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Memory(left), Self::Memory(right)) => left == right,
            (Self::Stream(left), Self::Stream(right)) => Arc::ptr_eq(left, right),
            _ => false,
        }
    }
}

impl Eq for ProviderResultStream {}

impl Eq for ProviderResultStreamSource {}

/// A failed outcome: its decision, reason and message, with optional partial
/// result, audit data and upstream facts.
///
/// The decision and reason are fixed at construction. A standard reason
/// takes the decision its constructor names; a domain reason
/// ([`Self::domain`]) and a host port's failure ([`crate::host::port_failure`])
/// fix their own, so later edits to the public fields cannot change them.
/// The Broker checks the reason a provider reports against its contract.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderError {
    pub(crate) decision: Decision,
    pub(crate) reason_code: ProviderReason,
    pub message: String,
    pub result: Option<Box<Value>>,
    pub audit: Option<Box<Value>>,
    pub upstream_status: Option<u16>,
    pub upstream_duration_ms: Option<u64>,
    pub object_ids: Option<Box<Value>>,
    /// Bounded, provider-defined code logged when the broker cannot append
    /// the failure's audit record. Never sent to callers.
    pub internal_diagnostic_code: Option<&'static str>,
}

impl ProviderError {
    /// An outcome reported through the error path with `decision = allow`.
    /// The only one a provider may report is `verification_mismatch` from an
    /// invocation, with its verification result.
    pub fn allow(reason_code: ReasonCode, message: impl Into<String>) -> Self {
        Self::with_reason(Decision::Allow, reason_code.into(), message)
    }

    pub fn allow_with_result(
        reason_code: ReasonCode,
        message: impl Into<String>,
        result: Value,
    ) -> Self {
        Self::allow(reason_code, message).with_result(result)
    }

    /// A denial with a standard reason. Providers may use only the standard
    /// reasons [`ReasonCode::permits_provider_failure`] admits for the hook.
    pub fn deny(reason_code: ReasonCode, message: impl Into<String>) -> Self {
        Self::with_reason(Decision::Deny, reason_code.into(), message)
    }

    /// An error with a standard reason. Providers may use only the standard
    /// reasons [`ReasonCode::permits_provider_failure`] admits for the hook.
    pub fn error(reason_code: ReasonCode, message: impl Into<String>) -> Self {
        Self::with_reason(Decision::Error, reason_code.into(), message)
    }

    /// A failure with one of the backend's registered domain reasons. Its
    /// decision and HTTP status are the definition's.
    pub fn domain(
        definition: &'static ProviderReasonDefinition,
        message: impl Into<String>,
    ) -> Self {
        Self::with_reason(definition.decision(), definition.into(), message)
    }

    fn with_reason(
        decision: Decision,
        reason_code: ProviderReason,
        message: impl Into<String>,
    ) -> Self {
        Self {
            decision,
            reason_code,
            message: message.into(),
            result: None,
            audit: None,
            upstream_status: None,
            upstream_duration_ms: None,
            object_ids: None,
            internal_diagnostic_code: None,
        }
    }

    pub(crate) fn into_host_origin(mut self, port: HostPort) -> Self {
        if let Some(code) = self.reason_code.standard()
            && self.reason_code.host_port().is_none()
            && let Some(reason_code) = ProviderReason::host(port, &self.decision, code)
        {
            self.reason_code = reason_code;
        }
        self
    }

    pub fn decision(&self) -> Decision {
        self.decision.clone()
    }

    pub fn reason_code(&self) -> ProviderReason {
        self.reason_code
    }

    pub fn with_audit(mut self, audit: Value) -> Self {
        self.audit = Some(Box::new(audit));
        self
    }

    pub fn with_result(mut self, result: Value) -> Self {
        self.result = Some(Box::new(result));
        self
    }

    pub fn with_upstream(mut self, status: Option<u16>, duration_ms: Option<u64>) -> Self {
        self.upstream_status = status;
        self.upstream_duration_ms = duration_ms;
        self
    }

    pub fn with_object_ids(mut self, object_ids: Value) -> Self {
        self.object_ids = Some(Box::new(object_ids));
        self
    }

    pub fn with_internal_diagnostic_code(mut self, diagnostic_code: &'static str) -> Self {
        self.internal_diagnostic_code = Some(diagnostic_code);
        self
    }
}

/// A credential verification an upstream answered: its status, duration and
/// audit data.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderCredentialVerification {
    pub upstream_status: u16,
    pub upstream_duration_ms: u64,
    pub audit: Value,
}

impl ProviderCredentialVerification {
    pub fn new(upstream_status: u16, upstream_duration_ms: u64, audit: Value) -> Self {
        Self {
            upstream_status,
            upstream_duration_ms,
            audit,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers::path;
    use wiremock::{Mock, MockServer, ResponseTemplate};

    /// The bytes a stream yields before it ends or fails.
    async fn drain(stream: ProviderResultStream) -> (Vec<u8>, Option<ProviderStreamError>) {
        let ProviderResultStreamSource::Stream(stream) = stream.source else {
            panic!("bounded downloads stream");
        };
        let mut stream = stream.lock().unwrap().take().unwrap();
        let mut bytes = Vec::new();
        while let Some(item) = stream.next().await {
            match item {
                Ok(chunk) => bytes.extend_from_slice(&chunk),
                Err(error) => return (bytes, Some(error)),
            }
        }
        (bytes, None)
    }

    #[tokio::test]
    async fn bounded_downloads_fail_late_with_their_cap_reason_and_expected_size() {
        let server = MockServer::start().await;
        Mock::given(path("/blob"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(b"12345678".to_vec()))
            .mount(&server)
            .await;
        let fetch = || async {
            reqwest::Client::builder()
                .no_proxy()
                .build()
                .unwrap()
                .get(format!("{}/blob", server.uri()))
                .send()
                .await
                .unwrap()
        };
        let idle = Duration::from_secs(10);
        let download = |byte_cap, expected_size| {
            BoundedDownload::new(
                "Example download",
                byte_cap,
                ReasonCode::AttachmentSizeDenied,
                idle,
            )
            .with_expected_size(expected_size)
        };

        let complete = ProviderResultStream::from_bounded_response(
            "application/octet-stream",
            fetch().await,
            download(8, Some(8)),
        );
        assert_eq!(complete.content_type, "application/octet-stream");
        assert_eq!(drain(complete).await, (b"12345678".to_vec(), None));

        let cases = [
            // Over the cap: the download's own reason.
            (
                download(4, None),
                ReasonCode::AttachmentSizeDenied,
                "Example download exceeded the download limit",
            ),
            // Past the expected size: fails before the excess is delivered.
            (
                download(1024, Some(4)),
                ReasonCode::UpstreamProtocolFailed,
                "Example download size did not match Content-Length",
            ),
            // Short of the expected size: fails at the end.
            (
                download(1024, Some(10)),
                ReasonCode::UpstreamProtocolFailed,
                "Example download size did not match Content-Length",
            ),
        ];
        for (download, reason, message) in cases {
            let stream = ProviderResultStream::from_bounded_response(
                "application/octet-stream",
                fetch().await,
                download,
            );
            let (bytes, failure) = drain(stream).await;
            let failure = failure.expect("the download fails late");
            assert_eq!(
                failure.reason_code,
                ProviderReason::from(reason),
                "{failure:?}"
            );
            assert!(reason.permits_late_stream());
            assert_eq!(failure.message, message);
            let expected_size = download.expected_size.unwrap_or(u64::MAX);
            assert!(bytes.len() as u64 <= expected_size.min(download.byte_cap));
        }
    }
}
