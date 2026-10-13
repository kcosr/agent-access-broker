//! Local response destinations shared by CLI and stdio MCP.
use anyhow::{Context, Result};
use serde::Serialize;
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use std::io::Write;
use std::path::{Path, PathBuf};

/// A private temporary file beside the destination, replaced only on commit.
pub(crate) struct AtomicOutput {
    file: tempfile::NamedTempFile,
    destination: PathBuf,
}

impl AtomicOutput {
    pub(crate) fn new(path: &Path) -> Result<Self> {
        match std::fs::metadata(path) {
            Ok(metadata) if metadata.is_dir() => {
                anyhow::bail!("output destination is a directory: {}", path.display())
            }
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(error).with_context(|| {
                    format!("cannot inspect output destination {}", path.display())
                });
            }
        }
        let parent = parent_directory(path);
        let file = tempfile::NamedTempFile::new_in(parent)
            .with_context(|| format!("failed to create temporary output for {}", path.display()))?;
        Ok(Self {
            file,
            destination: path.to_owned(),
        })
    }

    pub(crate) fn write_response(
        mut self,
        bytes: &[u8],
        content_type: &str,
        sensitive: bool,
    ) -> Result<FileOutput> {
        self.write_all(bytes)
            .context("failed to write response output")?;
        let path = self.destination.clone();
        self.commit()?;
        Ok(FileOutput::new(
            &path,
            bytes.len() as u64,
            format!("{:x}", Sha256::digest(bytes)),
            content_type,
            sensitive,
        ))
    }

    pub(crate) fn commit(self) -> Result<()> {
        self.commit_with_directory_sync(|_parent| {
            #[cfg(unix)]
            std::fs::File::open(_parent)?.sync_all()?;
            Ok(())
        })
    }

    fn commit_with_directory_sync(
        mut self,
        sync_directory: impl FnOnce(&Path) -> std::io::Result<()>,
    ) -> Result<()> {
        self.file.flush().context("failed to flush output")?;
        self.file
            .as_file()
            .sync_all()
            .context("failed to sync output")?;
        self.file
            .persist(&self.destination)
            .map_err(|error| error.error)
            .with_context(|| format!("failed to replace {}", self.destination.display()))?;
        sync_directory(parent_directory(&self.destination)).map_err(|source| {
            DestinationReplaced {
                path: self.destination.clone(),
                source,
            }
        })?;
        Ok(())
    }
}

/// A file destination reserved before an operation; Drop removes an unused reservation.
pub(crate) struct ResponseOutput {
    file: AtomicOutput,
    sensitive_outputs: Vec<String>,
}

impl ResponseOutput {
    pub(crate) fn prepare(
        path: Option<&Path>,
        sensitive_outputs: &[String],
    ) -> Result<Option<Self>> {
        path.filter(|path| *path != Path::new("-"))
            .map(|path| {
                Ok(Self {
                    file: AtomicOutput::new(path)?,
                    sensitive_outputs: sensitive_outputs.to_vec(),
                })
            })
            .transpose()
    }

    pub(crate) fn into_file(self) -> AtomicOutput {
        self.file
    }

    pub(crate) fn save(self, envelope: &Value, bytes: &[u8], content_type: &str) -> Result<Value> {
        let path = self.file.destination.clone();
        let output = self
            .file
            .write_response(bytes, content_type, !self.sensitive_outputs.is_empty())
            .map_err(|error| {
                LocalOutputFailure::response(envelope, &path, error, &self.sensitive_outputs)
            })?;
        Ok(receipt(envelope, &output, false, &self.sensitive_outputs))
    }

    pub(crate) fn save_json(self, envelope: &Value) -> Result<Value> {
        let mut bytes = serde_json::to_vec_pretty(envelope)?;
        bytes.push(b'\n');
        self.save(envelope, &bytes, "application/json")
    }
}

#[derive(Debug)]
struct DestinationReplaced {
    path: PathBuf,
    source: std::io::Error,
}

impl std::fmt::Display for DestinationReplaced {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "output was replaced but its parent directory could not be synced: {}: {}",
            self.path.display(),
            self.source
        )
    }
}

impl std::error::Error for DestinationReplaced {}

/// Records a known successful operation without retaining its response payload.
#[derive(Debug)]
pub(crate) struct LocalOutputFailure {
    pub(crate) details: Value,
}

impl LocalOutputFailure {
    pub(crate) fn response(
        envelope: &Value,
        path: &Path,
        error: anyhow::Error,
        sensitive_outputs: &[String],
    ) -> Self {
        Self::new(
            operation_fields(envelope, sensitive_outputs),
            path,
            error,
            false,
        )
    }

    pub(crate) fn metadata(receipt: &Value, path: &Path, error: anyhow::Error) -> Self {
        let mut fields = identifiers(receipt);
        for key in [
            "operationStatus",
            "mutationStatus",
            "retrySafe",
            "verificationStage",
            "safeLocators",
            "output",
        ] {
            if let Some(value) = receipt.get(key) {
                fields.insert(key.into(), value.clone());
            }
        }
        Self::new(fields, path, error, true)
    }

    fn new(
        mut details: Map<String, Value>,
        path: &Path,
        error: anyhow::Error,
        metadata: bool,
    ) -> Self {
        let status = details
            .get("operationStatus")
            .and_then(Value::as_str)
            .unwrap_or("unknown");
        let operation = match status {
            "succeeded" => "Operation succeeded",
            "applied_unverified" => "Mutation was applied but remains unverified",
            _ => "Operation outcome requires reconciliation",
        };
        let target = if metadata {
            "output metadata"
        } else {
            "the response output"
        };
        details.insert(
            "message".into(),
            json!(format!(
                "{operation}; writing {target} failed. Do not repeat the operation to retry saving."
            )),
        );
        details.insert(if metadata { "metadataOutput" } else { "output" }.into(), json!({
            "status":"failed", "path":path.to_string_lossy(),
            "destinationReplaced":error.is::<DestinationReplaced>(), "error":format!("{error:#}")
        }));
        Self {
            details: Value::Object(details),
        }
    }
}

impl std::fmt::Display for LocalOutputFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{}", self.details)
    }
}

impl std::error::Error for LocalOutputFailure {}

impl Write for AtomicOutput {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.file.write(bytes)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.file.flush()
    }
}

fn parent_directory(path: &Path) -> &Path {
    path.parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct FileOutput {
    pub(crate) status: &'static str,
    pub(crate) path: String,
    pub(crate) size: u64,
    pub(crate) sha256: String,
    pub(crate) content_type: String,
    pub(crate) sensitive: bool,
}

impl FileOutput {
    pub(crate) fn new(
        path: &Path,
        size: u64,
        sha256: String,
        content_type: &str,
        sensitive: bool,
    ) -> Self {
        Self {
            status: "succeeded",
            path: path.to_string_lossy().into_owned(),
            size,
            sha256,
            content_type: content_type.to_owned(),
            sensitive,
        }
    }
}

#[cfg(test)]
pub(crate) fn write_file(
    path: &Path,
    bytes: &[u8],
    content_type: &str,
    sensitive: bool,
) -> Result<FileOutput> {
    AtomicOutput::new(path)?.write_response(bytes, content_type, sensitive)
}

/// Compact output metadata preserves bounded, non-sensitive mutation reconciliation fields.
pub(crate) fn receipt(
    envelope: &Value,
    output: &FileOutput,
    preserve_result: bool,
    sensitive_outputs: &[String],
) -> Value {
    let mut result = if preserve_result {
        envelope.as_object().cloned().unwrap_or_default()
    } else {
        Map::new()
    };
    result.extend(operation_fields(envelope, sensitive_outputs));
    result.insert(
        "output".into(),
        serde_json::to_value(output).expect("file output is serializable"),
    );
    Value::Object(result)
}

fn operation_fields(envelope: &Value, sensitive_outputs: &[String]) -> Map<String, Value> {
    let mut fields = identifiers(envelope);
    let mutation = envelope.pointer("/result/mutationStatus");
    let status = match mutation.and_then(Value::as_str) {
        None if mutation.is_none() => "succeeded",
        Some("applied" | "applied_verified") => "succeeded",
        Some("applied_unverified") => "applied_unverified",
        Some("not_applied") => "not_applied",
        _ => "unknown",
    };
    fields.insert("operationStatus".into(), json!(status));
    for key in [
        "mutationStatus",
        "retrySafe",
        "verificationStage",
        "safeLocators",
    ] {
        let pointer = format!("/result/{key}");
        if sensitive_outputs
            .iter()
            .any(|sensitive| pointers_overlap(sensitive, &pointer))
        {
            continue;
        }
        let Some(value) = envelope.pointer(&pointer) else {
            continue;
        };
        let valid = match key {
            "mutationStatus" => matches!(
                value.as_str(),
                Some("applied" | "applied_verified" | "applied_unverified" | "not_applied")
            ),
            "retrySafe" => value.is_boolean(),
            "verificationStage" => value.as_str().is_some_and(|value| value.len() <= 128),
            "safeLocators" => {
                value.is_object()
                    && bounded_locator(value, 0)
                    && serde_json::to_vec(value).is_ok_and(|bytes| bytes.len() <= 4096)
            }
            _ => false,
        };
        if valid {
            fields.insert(key.into(), value.clone());
        }
    }
    fields
}

fn pointers_overlap(left: &str, right: &str) -> bool {
    left.split('/')
        .zip(right.split('/'))
        .all(|(left, right)| left == right || left == "*" || right == "*")
}

fn bounded_locator(value: &Value, depth: usize) -> bool {
    match value {
        Value::String(value) => value.len() <= 512,
        Value::Number(_) | Value::Bool(_) | Value::Null => true,
        Value::Object(values) => {
            depth < 2
                && values.len() <= 16
                && values
                    .iter()
                    .all(|(key, value)| key.len() <= 64 && bounded_locator(value, depth + 1))
        }
        Value::Array(values) => {
            depth < 2
                && values.len() <= 16
                && values.iter().all(|value| bounded_locator(value, depth + 1))
        }
    }
}

fn identifiers(envelope: &Value) -> Map<String, Value> {
    let mut fields = Map::new();
    for key in [
        "agentRequestId",
        "brokerRequestId",
        "decision",
        "service",
        "action",
        "reasonCode",
    ] {
        if let Some(value) = envelope.get(key).filter(|value| value.is_string()) {
            fields.insert(key.to_owned(), value.clone());
        }
    }
    fields
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn final_directory_sync_failure_reports_replacement_without_response_payload() {
        let directory = tempfile::tempdir().unwrap();
        let destination = directory.path().join("result");
        std::fs::write(&destination, "original").unwrap();
        let mut output = AtomicOutput::new(&destination).unwrap();
        output.write_all(b"replacement").unwrap();
        let error = output
            .commit_with_directory_sync(|_| {
                Err(std::io::Error::other("forced directory sync failure"))
            })
            .unwrap_err();
        let failure = LocalOutputFailure::response(
            &json!({"decision":"allow", "brokerRequestId":"request", "result":{"secret":"not-retained"}}),
            &destination,
            error,
            &[],
        );
        assert_eq!(std::fs::read(&destination).unwrap(), b"replacement");
        assert_eq!(failure.details["operationStatus"], "succeeded");
        assert_eq!(failure.details["output"]["status"], "failed");
        assert_eq!(failure.details["output"]["destinationReplaced"], true);
        assert_eq!(failure.details["brokerRequestId"], "request");
        assert!(!failure.to_string().contains("not-retained"));
    }

    #[test]
    fn metadata_failure_keeps_successful_response_receipt_and_distinct_failure_status() {
        let directory = tempfile::tempdir().unwrap();
        let destination = directory.path().join("response.json");
        let written = write_file(&destination, b"{}", "application/json", true).unwrap();
        let receipt = receipt(
            &json!({"decision":"allow", "agentRequestId":"agent"}),
            &written,
            false,
            &[],
        );
        let metadata = directory.path().join("missing/metadata.json");
        let error = write_file(&metadata, b"{}", "application/json", false).unwrap_err();
        let failure = LocalOutputFailure::metadata(&receipt, &metadata, error);
        assert_eq!(failure.details["output"]["status"], "succeeded");
        assert_eq!(failure.details["metadataOutput"]["status"], "failed");
        assert_eq!(failure.details["operationStatus"], "succeeded");
        assert_eq!(std::fs::read(&destination).unwrap(), b"{}");
    }

    #[test]
    fn compact_outcomes_preserve_uncertainty_without_sensitive_or_unbounded_fields() {
        let envelope = json!({"decision":"allow","brokerRequestId":"request","result":{
            "mutationStatus":"applied_unverified","retrySafe":false,"verificationStage":"mutation_response",
            "safeLocators":{"job":"ci/build","secret":"declared-sensitive"},"issuedToken":"never-retained"
        }});
        let output = FileOutput::new(
            Path::new("saved.json"),
            2,
            "digest".into(),
            "application/json",
            true,
        );
        let compact = receipt(
            &envelope,
            &output,
            false,
            &[
                "/result/safeLocators/secret".into(),
                "/result/issuedToken".into(),
            ],
        );
        assert_eq!(compact["operationStatus"], "applied_unverified");
        assert_eq!(compact["mutationStatus"], "applied_unverified");
        assert_eq!(compact["retrySafe"], false);
        assert!(compact.get("safeLocators").is_none());
        assert!(!compact.to_string().contains("declared-sensitive"));
        assert!(!compact.to_string().contains("never-retained"));
        let metadata = LocalOutputFailure::metadata(
            &compact,
            Path::new("metadata.json"),
            anyhow::anyhow!("forced failure"),
        );
        assert_eq!(metadata.details["operationStatus"], "applied_unverified");
        assert_eq!(metadata.details["verificationStage"], "mutation_response");
        assert_eq!(metadata.details["metadataOutput"]["status"], "failed");
        assert!(
            !metadata.details["message"]
                .as_str()
                .unwrap()
                .contains("Operation succeeded")
        );
        let mut unknown = envelope.clone();
        unknown["result"]["mutationStatus"] = json!("future-private-status");
        unknown["result"]["safeLocators"] = json!({"oversized":"x".repeat(5000)});
        let compact = receipt(&unknown, &output, false, &[]);
        assert_eq!(compact["operationStatus"], "unknown");
        assert!(compact.get("mutationStatus").is_none());
        assert!(compact.get("safeLocators").is_none());
        let wildcard = receipt(&envelope, &output, false, &["/result/*".into()]);
        for field in [
            "mutationStatus",
            "retrySafe",
            "verificationStage",
            "safeLocators",
        ] {
            assert!(wildcard.get(field).is_none());
        }
        assert_eq!(wildcard["operationStatus"], "applied_unverified");
    }

    #[test]
    fn provider_failure_receipts_keep_their_operation_status_and_retry_safety() {
        let output = FileOutput::new(
            Path::new("saved.json"),
            2,
            "digest".into(),
            "application/json",
            false,
        );
        for (mutation, retry_safe, operation) in [
            ("unknown", false, "unknown"),
            ("not_applied", true, "not_applied"),
        ] {
            let envelope = json!({
                "decision": "error",
                "reasonCode": "upstream_timeout",
                "brokerRequestId": "request",
                "result": {"mutationStatus": mutation, "retrySafe": retry_safe},
            });
            let compact = receipt(&envelope, &output, false, &[]);
            assert_eq!(compact["operationStatus"], operation, "{mutation}");
            assert_eq!(compact["retrySafe"], retry_safe, "{mutation}");
            assert_eq!(compact["reasonCode"], "upstream_timeout");
            // `unknown` is reported through `operationStatus` alone.
            assert_eq!(
                compact.get("mutationStatus"),
                (mutation == "not_applied").then_some(&json!("not_applied"))
            );
            let failure = LocalOutputFailure::response(
                &envelope,
                Path::new("saved.json"),
                anyhow::anyhow!("forced failure"),
                &[],
            );
            assert_eq!(failure.details["operationStatus"], operation);
            assert_eq!(failure.details["retrySafe"], retry_safe);
            assert!(
                failure.details["message"]
                    .as_str()
                    .unwrap()
                    .starts_with("Operation outcome requires reconciliation")
            );
        }
    }

    #[test]
    fn abandoned_output_preserves_existing_destination_and_removes_temporary_file() {
        let directory = tempfile::tempdir().unwrap();
        let destination = directory.path().join("result");
        std::fs::write(&destination, b"original").unwrap();
        {
            let mut output = AtomicOutput::new(&destination).unwrap();
            output.write_all(b"incomplete").unwrap();
        }
        assert_eq!(std::fs::read(&destination).unwrap(), b"original");
        assert_eq!(std::fs::read_dir(directory.path()).unwrap().count(), 1);
    }

    #[test]
    fn completed_output_is_private_and_receipt_excludes_payload() {
        let directory = tempfile::tempdir().unwrap();
        let destination = directory.path().join("result");
        let output = write_file(&destination, b"abc", "text/plain", true).unwrap();
        assert_eq!(std::fs::read(&destination).unwrap(), b"abc");
        assert_eq!(
            output.sha256,
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(&destination)
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o600
            );
        }
        let envelope = json!({"decision":"allow","brokerRequestId":"request","result":{"secret":"value"},"reason":"body content","resourceScopes":{"large":"data"},"unknown":"payload"});
        let saved = receipt(&envelope, &output, false, &[]);
        assert_eq!(saved["decision"], "allow");
        assert_eq!(saved["brokerRequestId"], "request");
        assert_eq!(saved["output"]["size"], 3);
        assert_eq!(saved["output"]["sensitive"], true);
        for key in ["result", "reason", "resourceScopes", "unknown"] {
            assert!(saved.get(key).is_none());
        }
        assert_eq!(
            receipt(&envelope, &output, true, &[])["result"],
            envelope["result"]
        );
    }
}
