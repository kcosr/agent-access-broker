//! Buffered command downloads. Protocol fields borrow the captured document;
//! in particular, a content string is never unescaped or copied. The JSON
//! scanner's escaped-key and nesting scratch is limited by an allocation-free
//! preflight to fixed metadata overhead. Its errors are static and its scratch
//! is dropped before the fallible file allocation. Payload owners have no
//! Debug output.
use crate::mapping::CompiledAction;
use crate::response::{self, InvokeOutcome, Violation};
use agent_access_core::imports::{CommandBudgetLease, CommandSecrets};
use agent_access_provider::ProviderResultStream;
use base64::{Engine as _, engine::general_purpose::STANDARD};
use bytes::Bytes;
use serde::de::{self, DeserializeSeed, MapAccess, Visitor};
use serde_json::{Map, Value, json, value::RawValue};
use sha2::{Digest, Sha256};
use std::fmt;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use tokio::time::Instant;

const OVERHEAD: usize = 16_384;
const RESULT_BYTES: usize = 2_048;
const STRING_BYTES: usize = 1_024;
const ELEMENTS: usize = 256;
const DEPTH: usize = 8;
const CHUNK_BYTES: usize = 64 * 1024;
// Every legal metadata key has at most STRING_BYTES UTF-8 bytes; a JSON
// Unicode escape expands that representation by at most six. Protocol and
// receipt keys are shorter. All valid response structures fit this depth.
const RAW_KEY_BYTES: usize = STRING_BYTES * 6;
const SCAN_DEPTH: usize = 16;

/// Shared by the waiting future and worker, including abandonment of the
/// waiting future. This is not process registration or a second budget.
pub(crate) struct Control {
    canceled: AtomicBool,
    deadline: Instant,
}

impl Control {
    pub(crate) fn new(deadline: Instant) -> Self {
        Self {
            canceled: AtomicBool::new(false),
            deadline,
        }
    }

    pub(crate) fn cancel(&self) {
        self.canceled.store(true, Ordering::Release);
    }

    fn check(&self) -> Result<(), Error> {
        if self.canceled.load(Ordering::Acquire) || Instant::now() >= self.deadline {
            Err(Error::Stopped)
        } else {
            Ok(())
        }
    }
}

#[derive(Debug)]
pub(crate) enum Error {
    Violation(Violation),
    Stopped,
    WorkerFailed,
}

struct CancelOnDrop(Arc<Control>);
impl Drop for CancelOnDrop {
    fn drop(&mut self) {
        self.0.cancel();
    }
}

/// Aborting or timing out the waiter requests cancellation but leaves the
/// lease with the actual worker, including an uninterruptible bounded scan.
pub(crate) async fn run_worker<T: Send + 'static>(
    lease: CommandBudgetLease,
    deadline: Instant,
    work: impl FnOnce(&Control) -> Result<T, Error> + Send + 'static,
) -> Result<T, Error> {
    let control = Arc::new(Control::new(deadline));
    let _cancel = CancelOnDrop(control.clone());
    let worker_control = control.clone();
    let worker = tokio::task::spawn_blocking(move || {
        worker_control.check()?;
        let result = work(&worker_control);
        let verdict = worker_control.check();
        drop(lease);
        verdict?;
        result
    });
    let result = tokio::time::timeout_at(deadline, worker)
        .await
        .map_err(|_| Error::Stopped)?
        .map_err(|_| Error::WorkerFailed)?;
    control.check()?;
    result
}

impl From<Violation> for Error {
    fn from(value: Violation) -> Self {
        Self::Violation(value)
    }
}

/// Validate on a blocking worker. The final check prevents a scan/validator
/// that finished after cancellation from publishing either a file or verdict.
#[allow(clippy::too_many_arguments)]
pub(crate) fn invoke(
    service: &str,
    action: &CompiledAction,
    read_only: bool,
    stdout: &[u8],
    secrets: &CommandSecrets,
    cap: usize,
    control: &Control,
) -> Result<InvokeOutcome, Error> {
    control.check()?;
    let outcome = parse(service, action, read_only, stdout, secrets, cap, control);
    control.check()?;
    outcome
}

#[allow(clippy::too_many_arguments)]
fn parse(
    service: &str,
    action: &CompiledAction,
    read_only: bool,
    stdout: &[u8],
    secrets: &CommandSecrets,
    cap: usize,
    control: &Control,
) -> Result<InvokeOutcome, Error> {
    let text = std::str::from_utf8(stdout).map_err(|_| Violation("invalid_json"))?;
    preflight(text.as_bytes())?;
    control.check()?;
    let envelope = raw_object(text, &["ok", "result", "download", "receipt", "error"])?;
    control.check()?;
    let ok = match envelope.required("ok")?.get() {
        "true" => true,
        "false" => false,
        _ => return Err(Violation("response_shape").into()),
    };
    if !ok {
        if envelope.get("result").is_some() || envelope.get("download").is_some() {
            return Err(Violation("response_shape").into());
        }
        check_overhead(stdout.len(), 0)?;
        raw_object(
            envelope.required("error")?.get(),
            &["code", "message", "retryAfterSeconds"],
        )?;
        validate_receipt(&envelope)?;
        // Existing error codes, safe messages, receipts and retry metadata are
        // shared with JSON actions, after duplicate/overhead checks above.
        return Ok(response::invoke(
            service, action, read_only, stdout, secrets,
        )?);
    }
    if envelope.get("error").is_some() {
        return Err(Violation("response_shape").into());
    }
    let download = raw_object(
        envelope.required("download")?.get(),
        &["content", "filename", "contentType", "size", "sha256"],
    )?;
    control.check()?;
    let token = download.required("content")?.get().as_bytes();
    let encoded = token
        .strip_prefix(b"\"")
        .and_then(|token| token.strip_suffix(b"\""))
        .ok_or(Violation("download_content"))?;
    check_overhead(stdout.len(), encoded.len())?;
    for chunk in encoded.chunks(CHUNK_BYTES) {
        control.check()?;
        if chunk.iter().any(|byte| !byte.is_ascii() || *byte == b'\\') {
            return Err(Violation("download_content").into());
        }
    }

    // All remaining owned metadata is bounded by J before it is parsed.
    let result_raw = envelope.required("result")?;
    if result_raw.get().len() > RESULT_BYTES {
        return Err(Violation("download_result_limit").into());
    }
    let result: Value =
        serde_json::from_str(result_raw.get()).map_err(|_| Violation("invalid_json"))?;
    if !result.is_object() {
        return Err(Violation("download_result_shape").into());
    }
    let mut count = 0;
    validate_metadata(&result, 1, &mut count)?;
    if serde_json::to_vec(&result)
        .map_err(|_| Violation("download_result_shape"))?
        .len()
        > RESULT_BYTES
    {
        return Err(Violation("download_result_limit").into());
    }
    validate_receipt(&envelope)?;
    let mut ordinary = Map::from_iter([
        ("ok".to_owned(), json!(true)),
        ("result".to_owned(), result),
    ]);
    if let Some(receipt) = envelope.get("receipt") {
        ordinary.insert(
            "receipt".into(),
            serde_json::from_str(receipt.get()).map_err(|_| Violation("invalid_receipt"))?,
        );
    }
    let ordinary = serde_json::to_vec(&ordinary).map_err(|_| Violation("response_shape"))?;
    let mut outcome = match response::invoke(service, action, read_only, &ordinary, secrets)? {
        Ok(outcome) => outcome,
        Err(error) => return Ok(Err(error)),
    };
    let filename: String = serde_json::from_str(download.required("filename")?.get())
        .map_err(|_| Violation("download_filename"))?;
    if filename.is_empty()
        || filename.len() > 255
        || filename == "."
        || filename == ".."
        || filename
            .chars()
            .any(|ch| ch.is_control() || ch == '/' || ch == '\\')
    {
        return Err(Violation("download_filename").into());
    }
    let content_type: String = serde_json::from_str(download.required("contentType")?.get())
        .map_err(|_| Violation("download_content_type"))?;
    if content_type.is_empty()
        || content_type.len() > 255
        || !content_type.is_ascii()
        || content_type.bytes().any(|ch| ch.is_ascii_control())
        || content_type.parse::<mime_guess::Mime>().is_err()
        || http::HeaderValue::from_str(&content_type).is_err()
    {
        return Err(Violation("download_content_type").into());
    }
    if secrets.found_in(&filename) || secrets.found_in(&content_type) {
        return Err(Violation("secret_in_download_metadata").into());
    }
    let declared_size = download
        .get("size")
        .map(|raw| serde_json::from_str::<u64>(raw.get()).map_err(|_| Violation("download_size")))
        .transpose()?;
    let declared_hash = download
        .get("sha256")
        .map(|raw| {
            let hash: String =
                serde_json::from_str(raw.get()).map_err(|_| Violation("download_sha256"))?;
            if hash.len() != 64 || !hash.bytes().all(|ch| ch.is_ascii_hexdigit()) {
                return Err(Violation("download_sha256"));
            }
            Ok(hash)
        })
        .transpose()?;

    let length = decoded_length(encoded)?;
    if length > cap {
        return Err(Violation("download_limit").into());
    }
    control.check()?;
    let mut decoded = Vec::new();
    decoded
        .try_reserve_exact(length)
        .map_err(|_| Violation("download_allocation"))?;
    if decoded.capacity() > cap {
        return Err(Violation("download_allocation").into());
    }
    decoded.resize(length, 0);
    let mut offset = 0;
    let mut hash = Sha256::new();
    for chunk in encoded.chunks(CHUNK_BYTES) {
        control.check()?;
        let written = STANDARD
            .decode_slice(chunk, &mut decoded[offset..])
            .map_err(|_| Violation("download_base64"))?;
        // Only the final quartet may contain padding.
        if offset + written < length && chunk.contains(&b'=') {
            return Err(Violation("download_base64").into());
        }
        hash.update(&decoded[offset..offset + written]);
        offset += written;
    }
    control.check()?;
    let size = u64::try_from(length).map_err(|_| Violation("download_size"))?;
    if offset != length || declared_size.is_some_and(|declared| declared != size) {
        return Err(Violation("download_size").into());
    }
    let digest = format!("{:x}", hash.finalize());
    if declared_hash.is_some_and(|declared| !declared.eq_ignore_ascii_case(&digest)) {
        return Err(Violation("download_sha256").into());
    }
    outcome.result["filename"] = json!(filename);
    outcome.result["contentType"] = json!(content_type);
    outcome.result["size"] = json!(size);
    outcome.result["sha256"] = json!(digest);
    let chunks = futures_util::stream::unfold(Bytes::from(decoded), |mut bytes| async move {
        if bytes.is_empty() {
            None
        } else {
            let chunk = bytes.split_to(bytes.len().min(CHUNK_BYTES));
            Some((Ok(chunk), bytes))
        }
    });
    Ok(Ok(outcome.with_stream(ProviderResultStream::from_stream(
        content_type,
        chunks,
    ))))
}

fn check_overhead(total: usize, encoded: usize) -> Result<(), Violation> {
    if total
        .checked_sub(encoded)
        .is_none_or(|overhead| overhead > OVERHEAD)
    {
        Err(Violation("download_envelope_limit"))
    } else {
        Ok(())
    }
}

/// Bound allocations made internally by serde_json before asking it to check
/// JSON syntax. Large captured/decoded buffers use fallible allocation; the
/// parser must not acquire another configured-size buffer infallibly for a
/// malicious escaped key or deeply nested raw value. This scan allocates
/// nothing and does not decode any string (particularly the file content).
fn preflight(bytes: &[u8]) -> Result<(), Violation> {
    let mut depth = 0_usize;
    let mut index = 0;
    while index < bytes.len() {
        match bytes[index] {
            b'{' | b'[' => {
                depth += 1;
                if depth > SCAN_DEPTH {
                    return Err(Violation("response_shape"));
                }
            }
            b'}' | b']' => {
                depth = depth.checked_sub(1).ok_or(Violation("invalid_json"))?;
            }
            b'"' => {
                index += 1;
                let start = index;
                let mut escaped = false;
                loop {
                    match bytes.get(index) {
                        Some(b'\\') => {
                            escaped = true;
                            index += 2;
                        }
                        Some(b'"') => break,
                        Some(_) => index += 1,
                        None => return Err(Violation("invalid_json")),
                    }
                    // A malformed map may omit the colon after a key. Its
                    // escaped identifier must still never grow parser scratch
                    // with the configured payload limit. Every valid escaped
                    // string is bounded metadata; content forbids escapes.
                    if escaped && index - start > RAW_KEY_BYTES {
                        return Err(Violation("response_shape"));
                    }
                }
                let mut next = index + 1;
                while bytes
                    .get(next)
                    .is_some_and(|byte| matches!(byte, b' ' | b'\r' | b'\n' | b'\t'))
                {
                    next += 1;
                }
                if bytes.get(next) == Some(&b':') && index - start > RAW_KEY_BYTES {
                    return Err(Violation("response_shape"));
                }
            }
            _ => {}
        }
        index += 1;
    }
    if depth != 0 {
        return Err(Violation("invalid_json"));
    }
    Ok(())
}

fn decoded_length(encoded: &[u8]) -> Result<usize, Violation> {
    if !encoded.len().is_multiple_of(4) {
        return Err(Violation("download_base64"));
    }
    let padding = encoded
        .iter()
        .rev()
        .take_while(|byte| **byte == b'=')
        .take(3)
        .count();
    if padding > 2 {
        return Err(Violation("download_base64"));
    }
    (encoded.len() / 4)
        .checked_mul(3)
        .and_then(|length| length.checked_sub(padding))
        .ok_or(Violation("download_base64"))
}

fn validate_metadata(value: &Value, depth: usize, count: &mut usize) -> Result<(), Violation> {
    if depth > DEPTH && matches!(value, Value::Object(_) | Value::Array(_)) {
        return Err(Violation("download_result_limit"));
    }
    let children: Box<dyn Iterator<Item = &Value> + '_> = match value {
        Value::Object(map) => {
            if map.keys().any(|key| key.len() > STRING_BYTES) {
                return Err(Violation("download_result_limit"));
            }
            *count += map.len();
            Box::new(map.values())
        }
        Value::Array(array) => {
            *count += array.len();
            Box::new(array.iter())
        }
        Value::String(string) if string.len() > STRING_BYTES => {
            return Err(Violation("download_result_limit"));
        }
        _ => return Ok(()),
    };
    if *count > ELEMENTS {
        return Err(Violation("download_result_limit"));
    }
    for child in children {
        validate_metadata(child, depth + 1, count)?;
    }
    Ok(())
}

fn validate_receipt(envelope: &RawFields<'_>) -> Result<(), Violation> {
    if let Some(receipt) = envelope.get("receipt") {
        raw_object(
            receipt.get(),
            &["mutationStatus", "verificationStage", "safeLocators"],
        )?;
    }
    Ok(())
}

/// Fixed-size protocol maps reject unknown/duplicate keys without storing
/// their text or formatting it into an error. Values borrow the input even
/// when they are escaped strings; only bounded metadata is later unescaped.
struct RawFields<'a> {
    names: &'static [&'static str],
    values: [Option<&'a RawValue>; 5],
}

impl<'a> RawFields<'a> {
    fn get(&self, name: &str) -> Option<&'a RawValue> {
        self.names
            .iter()
            .position(|candidate| *candidate == name)
            .and_then(|index| self.values[index])
    }
    fn required(&self, name: &str) -> Result<&'a RawValue, Violation> {
        self.get(name).ok_or(Violation("response_shape"))
    }
}

fn raw_object<'a>(
    text: &'a str,
    names: &'static [&'static str],
) -> Result<RawFields<'a>, Violation> {
    // deserialize_map's generic wrong-type diagnostic can format an entire
    // string value. Reject the shape first, without allocating that string.
    if text
        .trim_start_matches([' ', '\t', '\r', '\n'])
        .as_bytes()
        .first()
        != Some(&b'{')
    {
        return Err(Violation("response_shape"));
    }
    let mut deserializer = serde_json::Deserializer::from_str(text);
    let result = FieldsSeed(names)
        .deserialize(&mut deserializer)
        .map_err(|_| Violation("response_shape"))?;
    deserializer.end().map_err(|_| Violation("invalid_json"))?;
    Ok(result)
}

struct FieldsSeed(&'static [&'static str]);
impl<'de> DeserializeSeed<'de> for FieldsSeed {
    type Value = RawFields<'de>;
    fn deserialize<D: de::Deserializer<'de>>(
        self,
        deserializer: D,
    ) -> Result<Self::Value, D::Error> {
        deserializer.deserialize_map(self)
    }
}
impl<'de> Visitor<'de> for FieldsSeed {
    type Value = RawFields<'de>;
    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a command protocol object")
    }
    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
        let mut fields = RawFields {
            names: self.0,
            values: [None; 5],
        };
        while let Some(index) = map.next_key_seed(KeySeed(self.0))? {
            if fields.values[index].is_some() {
                return Err(de::Error::custom("duplicate protocol field"));
            }
            fields.values[index] = Some(map.next_value()?);
        }
        Ok(fields)
    }
}
struct KeySeed(&'static [&'static str]);
impl<'de> DeserializeSeed<'de> for KeySeed {
    type Value = usize;
    fn deserialize<D: de::Deserializer<'de>>(self, deserializer: D) -> Result<usize, D::Error> {
        deserializer.deserialize_identifier(self)
    }
}
impl Visitor<'_> for KeySeed {
    type Value = usize;
    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a protocol field")
    }
    fn visit_str<E: de::Error>(self, value: &str) -> Result<usize, E> {
        self.0
            .iter()
            .position(|name| *name == value)
            .ok_or_else(|| E::custom("unknown protocol field"))
    }
}

#[cfg(test)]
mod tests;
