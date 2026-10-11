use crate::{Decision, ReasonCode};
use bytes::Bytes;
use futures_util::{Stream, StreamExt, stream};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use thiserror::Error;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ProviderResult {
    pub result: Value,
    #[serde(skip)]
    pub stream: Option<ProviderResultStream>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub audit: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub upstream_status: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub upstream_duration_ms: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub object_ids: Option<Value>,
}

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

pub type ProviderByteStream =
    Pin<Box<dyn Stream<Item = Result<Bytes, ProviderStreamError>> + Send + 'static>>;

#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[error("{reason_code:?}: {message}")]
pub struct ProviderStreamError {
    pub reason_code: ReasonCode,
    pub message: String,
}

impl ProviderStreamError {
    pub fn new(reason_code: ReasonCode, message: impl Into<String>) -> Self {
        Self {
            reason_code,
            message: message.into(),
        }
    }
}

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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderError {
    pub decision: Decision,
    pub reason_code: ReasonCode,
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
    pub fn allow(reason_code: ReasonCode, message: impl Into<String>) -> Self {
        Self {
            decision: Decision::Allow,
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

    pub fn allow_with_result(
        reason_code: ReasonCode,
        message: impl Into<String>,
        result: Value,
    ) -> Self {
        Self::allow(reason_code, message).with_result(result)
    }

    pub fn deny(reason_code: ReasonCode, message: impl Into<String>) -> Self {
        Self {
            decision: Decision::Deny,
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

    pub fn error(reason_code: ReasonCode, message: impl Into<String>) -> Self {
        Self {
            decision: Decision::Error,
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderCredentialVerification {
    pub upstream_status: u16,
    pub upstream_duration_ms: u64,
    pub audit: Value,
}
