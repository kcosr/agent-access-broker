//! How the Broker reads the one JSON document a command printed before
//! exiting 0.
//!
//! `{"ok": true, "result": ..., "receipt"?: {"safeLocators"}}` succeeds: the
//! result reaches the caller as `result.upstreamCommand`, which the import
//! marks sensitive, and a write-capable action reports `applied_unverified`
//! with the locators given. `{"ok": false, "error": {"code", "message",
//! "retryAfterSeconds"?}, "receipt"?}` fails with the code's Broker reason
//! and the command's message; a write reports the receipt's status, or
//! `unknown` without one. `retrySafe` always follows from the status.
//!
//! Anything else is a contract violation, which the caller reports as
//! `operation_failed` with an `unknown` write receipt: an empty, invalid or
//! trailing document, an unknown field or code, a message over 1,024 bytes or
//! with control characters other than tab, a receipt on a read or of the
//! wrong shape, an invalid locator, a message, verification stage or locator
//! containing a credential or proxy secret the request supplied (see
//! [`CommandSecrets`]), and a result the action's output schema rejects.
//! Private resource attribute values are not checked. Violations never
//! expose the document.
use crate::mapping::CompiledAction;
use agent_access_core::imports::CommandSecrets;
use agent_access_provider::{
    MutationReceipt, ProviderError, ProviderResult, ReasonCode, UPSTREAM_RETRY_AFTER_MAX_SECONDS,
    UpstreamRetryAfter,
};
use serde_json::{Map, Value, json};

/// The longest `message` a command may give, in bytes.
const MAX_MESSAGE_BYTES: usize = 1024;
/// Most `safeLocators` entries.
const MAX_LOCATORS: usize = 16;
/// Longest locator key, in bytes.
const MAX_LOCATOR_KEY_BYTES: usize = 64;
/// Longest locator string value, in bytes.
const MAX_LOCATOR_VALUE_BYTES: usize = 256;
/// Largest encoded `safeLocators` object, in bytes.
const MAX_LOCATORS_BYTES: usize = 1024;
/// The verification stage of an `applied_unverified` receipt that names none.
const DEFAULT_VERIFICATION_STAGE: &str = "command_response";

/// A broken command contract, named by the category its log line reports.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Violation(pub(crate) &'static str);

impl Violation {
    pub(crate) fn category(self) -> &'static str {
        self.0
    }
}

/// The outcome of an `invoke` response that keeps the command contract.
pub(crate) type InvokeOutcome = Result<ProviderResult, ProviderError>;

/// Reads the response of `action`, a write-capable action unless
/// `read_only`, to a call of `service` whose request supplied `secrets`.
pub(crate) fn invoke(
    service: &str,
    action: &CompiledAction,
    read_only: bool,
    stdout: &[u8],
    secrets: &CommandSecrets,
) -> Result<InvokeOutcome, Violation> {
    let mut document = document(stdout)?;
    let receipt = document.remove("receipt");
    if read_only && receipt.is_some() {
        return Err(Violation("receipt_on_read"));
    }
    match ok(&document)? {
        true => {
            only(&document, &["ok", "result"], "response_shape")?;
            let result = document
                .remove("result")
                .ok_or(Violation("response_shape"))?;
            if action
                .output
                .as_ref()
                .is_some_and(|schema| !schema.is_valid(&result))
            {
                return Err(Violation("output_schema"));
            }
            let locators = receipt
                .map(|receipt| {
                    let receipt = object(receipt, "invalid_receipt")?;
                    only(&receipt, &["safeLocators"], "invalid_receipt")?;
                    let locators = receipt
                        .get("safeLocators")
                        .ok_or(Violation("invalid_receipt"))?;
                    safe_locators(locators, secrets)
                })
                .transpose()?;
            let mut value = json!({"upstreamCommand": result});
            if !read_only {
                value["mutationStatus"] = json!("applied_unverified");
                value["retrySafe"] = json!(false);
                if let Some(locators) = locators {
                    value["safeLocators"] = locators;
                }
            }
            Ok(Ok(ProviderResult::new(value)))
        }
        false => {
            only(&document, &["ok", "error"], "response_shape")?;
            let mut error = command_error(service, document.remove("error"), secrets)?;
            if !read_only {
                let receipt = match receipt {
                    None => MutationReceipt::unknown(),
                    Some(receipt) => failure_receipt(receipt, secrets)?,
                };
                error = error.with_mutation_receipt(receipt);
            }
            Ok(Err(error))
        }
    }
}

/// Reads the response of a `verify` run: `Ok(())` for a verified
/// credential, the command's error for a failed one. A receipt is a
/// violation: verification writes nothing.
pub(crate) fn verify(
    service: &str,
    stdout: &[u8],
    secrets: &CommandSecrets,
) -> Result<Result<(), ProviderError>, Violation> {
    let mut document = document(stdout)?;
    match ok(&document)? {
        true => {
            only(&document, &["ok", "result"], "response_shape")?;
            Ok(Ok(()))
        }
        false => {
            only(&document, &["ok", "error"], "response_shape")?;
            Ok(Err(command_error(
                service,
                document.remove("error"),
                secrets,
            )?))
        }
    }
}

/// The one JSON object a command printed, with trailing whitespace allowed.
fn document(stdout: &[u8]) -> Result<Map<String, Value>, Violation> {
    if stdout.iter().all(u8::is_ascii_whitespace) {
        return Err(Violation("empty_response"));
    }
    let value = serde_json::from_slice::<Value>(stdout).map_err(|_| Violation("invalid_json"))?;
    object(value, "response_shape")
}

fn object(value: Value, violation: &'static str) -> Result<Map<String, Value>, Violation> {
    match value {
        Value::Object(map) => Ok(map),
        _ => Err(Violation(violation)),
    }
}

fn ok(document: &Map<String, Value>) -> Result<bool, Violation> {
    document
        .get("ok")
        .and_then(Value::as_bool)
        .ok_or(Violation("response_shape"))
}

/// Rejects fields of `map` outside `allowed` as `violation`.
fn only(
    map: &Map<String, Value>,
    allowed: &[&str],
    violation: &'static str,
) -> Result<(), Violation> {
    if map.keys().all(|key| allowed.contains(&key.as_str())) {
        Ok(())
    } else {
        Err(Violation(violation))
    }
}

/// The Broker failure of a command's `error`: its code's reason and
/// decision, its message, and for `upstream_rate_limited` the upstream
/// rate-limit result with the wait it gave.
fn command_error(
    service: &str,
    error: Option<Value>,
    secrets: &CommandSecrets,
) -> Result<ProviderError, Violation> {
    let error = object(error.ok_or(Violation("response_shape"))?, "response_shape")?;
    only(
        &error,
        &["code", "message", "retryAfterSeconds"],
        "response_shape",
    )?;
    let code = error
        .get("code")
        .and_then(Value::as_str)
        .ok_or(Violation("response_shape"))?;
    let (reason, deny) = reason(code).ok_or(Violation("unknown_code"))?;
    let message = error
        .get("message")
        .and_then(Value::as_str)
        .filter(|message| valid_message(message))
        .ok_or(Violation("invalid_message"))?;
    if secrets.found_in(message) {
        return Err(Violation("secret_in_message"));
    }
    let retry_after = error
        .get("retryAfterSeconds")
        .map(|seconds| {
            seconds
                .as_u64()
                .filter(|seconds| {
                    reason == ReasonCode::UpstreamRateLimited
                        && (1..=UPSTREAM_RETRY_AFTER_MAX_SECONDS).contains(seconds)
                })
                .map(UpstreamRetryAfter::after_seconds)
                .ok_or(Violation("invalid_retry_after"))
        })
        .transpose()?;
    let failure = if deny {
        ProviderError::deny(reason, message)
    } else {
        ProviderError::error(reason, message)
    };
    Ok(if reason == ReasonCode::UpstreamRateLimited {
        failure.with_upstream_rate_limit(service, retry_after)
    } else {
        failure
    })
}

/// The Broker reason of a command error `code`, and whether it is a denial.
fn reason(code: &str) -> Option<(ReasonCode, bool)> {
    Some(match code {
        "input_invalid" => (ReasonCode::InputInvalid, true),
        "resource_not_found" => (ReasonCode::ResourceNotFound, true),
        "resource_forbidden" => (ReasonCode::ServiceActionDenied, true),
        "conflict" => (ReasonCode::VersionConflict, true),
        "upstream_unauthorized" => (ReasonCode::UpstreamUnauthorized, false),
        "upstream_forbidden" => (ReasonCode::UpstreamForbidden, false),
        "upstream_rate_limited" => (ReasonCode::UpstreamRateLimited, false),
        "upstream_unreachable" => (ReasonCode::UpstreamConnectionFailed, false),
        "upstream_timeout" => (ReasonCode::UpstreamTimeout, false),
        "upstream_failed" => (ReasonCode::UpstreamFailed, false),
        _ => return None,
    })
}

/// A caller-facing message: at most 1,024 bytes, with no control
/// characters except tab.
fn valid_message(message: &str) -> bool {
    message.len() <= MAX_MESSAGE_BYTES
        && !message
            .chars()
            .any(|character| character.is_control() && character != '\t')
}

/// The receipt of a failed write: `{"mutationStatus": "not_applied"}`,
/// `{"mutationStatus": "unknown"}`, or `{"mutationStatus":
/// "applied_unverified", "verificationStage"?, "safeLocators"?}`.
fn failure_receipt(receipt: Value, secrets: &CommandSecrets) -> Result<MutationReceipt, Violation> {
    let receipt = object(receipt, "invalid_receipt")?;
    let status = receipt
        .get("mutationStatus")
        .and_then(Value::as_str)
        .ok_or(Violation("invalid_receipt"))?;
    match status {
        "not_applied" | "unknown" => {
            if receipt.len() != 1 {
                return Err(Violation("invalid_receipt"));
            }
            Ok(if status == "not_applied" {
                MutationReceipt::not_applied()
            } else {
                MutationReceipt::unknown()
            })
        }
        "applied_unverified" => {
            only(
                &receipt,
                &["mutationStatus", "verificationStage", "safeLocators"],
                "invalid_receipt",
            )?;
            let stage = match receipt.get("verificationStage") {
                None => DEFAULT_VERIFICATION_STAGE,
                Some(stage) => stage
                    .as_str()
                    .filter(|stage| verification_stage(stage))
                    .ok_or(Violation("invalid_receipt"))?,
            };
            if secrets.found_in(stage) {
                return Err(Violation("secret_in_receipt"));
            }
            let locators = match receipt.get("safeLocators") {
                None => json!({}),
                Some(locators) => safe_locators(locators, secrets)?,
            };
            Ok(MutationReceipt::applied_unverified(stage, locators))
        }
        _ => Err(Violation("invalid_receipt")),
    }
}

/// `^[a-z][a-z0-9_]{0,63}$`.
fn verification_stage(stage: &str) -> bool {
    let mut bytes = stage.bytes();
    stage.len() <= 64
        && bytes.next().is_some_and(|first| first.is_ascii_lowercase())
        && bytes.all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
}

/// A receipt's `safeLocators`: a flat object of at most 16 entries with
/// keys of 1–64 bytes and string (at most 256 bytes) or integer values, at
/// most 1 KiB encoded, none of which contains a secret the request supplied.
fn safe_locators(locators: &Value, secrets: &CommandSecrets) -> Result<Value, Violation> {
    let map = locators.as_object().ok_or(Violation("invalid_locator"))?;
    if map.len() > MAX_LOCATORS
        || serde_json::to_vec(locators).map_or(true, |bytes| bytes.len() > MAX_LOCATORS_BYTES)
    {
        return Err(Violation("invalid_locator"));
    }
    for (key, value) in map {
        if key.is_empty() || key.len() > MAX_LOCATOR_KEY_BYTES {
            return Err(Violation("invalid_locator"));
        }
        let text = match value {
            Value::String(text) if text.len() <= MAX_LOCATOR_VALUE_BYTES => text.clone(),
            Value::Number(number) if number.is_i64() || number.is_u64() => number.to_string(),
            _ => return Err(Violation("invalid_locator")),
        };
        if secrets.found_in(key) || secrets.found_in(&text) {
            return Err(Violation("secret_in_locator"));
        }
    }
    Ok(locators.clone())
}

#[cfg(test)]
mod tests {
    use super::*;
    use agent_access_core::imports::{BoundedImportSchema, ImportedActionAuthority};

    fn action(output: Option<Value>) -> CompiledAction {
        CompiledAction {
            read_only: false,
            download: false,
            input: BoundedImportSchema::compile(&json!({"type": "object"})).unwrap(),
            output: output.map(|schema| BoundedImportSchema::compile(&schema).unwrap()),
            authority: ImportedActionAuthority::default(),
        }
    }

    /// A request's credential and proxy secrets: a token, a token shaped
    /// like a verification stage and a proxy password.
    fn secrets() -> CommandSecrets {
        let mut secrets = CommandSecrets::new();
        secrets.insert("pat-example");
        secrets.insert("stage_token_value");
        secrets.insert("proxy-pass/5e");
        secrets
    }

    fn write(document: Value) -> Result<InvokeOutcome, Violation> {
        invoke(
            "tickets",
            &action(Some(json!({"type": "object", "required": ["key"]}))),
            false,
            document.to_string().as_bytes(),
            &secrets(),
        )
    }

    fn read(document: &str) -> Result<InvokeOutcome, Violation> {
        invoke(
            "tickets",
            &action(None),
            true,
            document.as_bytes(),
            &secrets(),
        )
    }

    fn failure(outcome: Result<InvokeOutcome, Violation>) -> ProviderError {
        outcome.unwrap().unwrap_err()
    }

    #[test]
    fn successes_return_the_result_under_the_sensitive_pointer() {
        let result = read("  {\"ok\": true, \"result\": {\"issue\": {\"key\": \"OPS-42\"}}}\n\n")
            .unwrap()
            .unwrap();
        assert_eq!(
            result.result,
            json!({"upstreamCommand": {"issue": {"key": "OPS-42"}}})
        );
        // Any JSON result, including null, without an output schema.
        let result = read(r#"{"ok": true, "result": null}"#).unwrap().unwrap();
        assert_eq!(result.result, json!({"upstreamCommand": null}));

        let written = write(json!({"ok": true, "result": {"key": "OPS-43"},
            "receipt": {"safeLocators": {"issue": "OPS-43", "number": 43}}}))
        .unwrap()
        .unwrap();
        assert_eq!(
            written.result,
            json!({"upstreamCommand": {"key": "OPS-43"}, "mutationStatus": "applied_unverified",
                "retrySafe": false, "safeLocators": {"issue": "OPS-43", "number": 43}})
        );
        let written = write(json!({"ok": true, "result": {"key": "OPS-44"}}))
            .unwrap()
            .unwrap();
        assert_eq!(
            written.result,
            json!({"upstreamCommand": {"key": "OPS-44"}, "mutationStatus": "applied_unverified",
                "retrySafe": false})
        );
    }

    #[test]
    fn error_codes_map_to_broker_reasons_with_the_command_message() {
        for (code, reason, decision, status) in [
            ("input_invalid", ReasonCode::InputInvalid, "deny", 400),
            (
                "resource_not_found",
                ReasonCode::ResourceNotFound,
                "deny",
                404,
            ),
            (
                "resource_forbidden",
                ReasonCode::ServiceActionDenied,
                "deny",
                403,
            ),
            ("conflict", ReasonCode::VersionConflict, "deny", 409),
            (
                "upstream_unauthorized",
                ReasonCode::UpstreamUnauthorized,
                "error",
                424,
            ),
            (
                "upstream_forbidden",
                ReasonCode::UpstreamForbidden,
                "error",
                424,
            ),
            (
                "upstream_rate_limited",
                ReasonCode::UpstreamRateLimited,
                "error",
                429,
            ),
            (
                "upstream_unreachable",
                ReasonCode::UpstreamConnectionFailed,
                "error",
                502,
            ),
            (
                "upstream_timeout",
                ReasonCode::UpstreamTimeout,
                "error",
                504,
            ),
            ("upstream_failed", ReasonCode::UpstreamFailed, "error", 424),
        ] {
            let error = failure(read(
                &json!({"ok": false, "error": {"code": code, "message": "Tab\tis fine."}})
                    .to_string(),
            ));
            assert_eq!(error.reason_code(), reason, "{code}");
            assert_eq!(
                serde_json::to_value(error.decision()).unwrap(),
                decision,
                "{code}"
            );
            assert_eq!(reason.http_status(), status, "{code}");
            assert_eq!(error.message, "Tab\tis fine.", "{code}");
            assert!(
                code == "upstream_rate_limited" || error.result.is_none(),
                "{code}"
            );
        }
        // Verification reads errors the same way.
        let error = verify(
            "tickets",
            br#"{"ok": false, "error": {"code": "upstream_unauthorized", "message": "Bad token."}}"#, &secrets())
        .unwrap()
        .unwrap_err();
        assert_eq!(error.reason_code(), ReasonCode::UpstreamUnauthorized);
        assert!(
            verify("tickets", br#"{"ok": true}"#, &secrets())
                .unwrap()
                .is_ok()
        );
        assert!(
            verify(
                "tickets",
                br#"{"ok": true, "result": {"user": "svc"}}"#,
                &secrets()
            )
            .unwrap()
            .is_ok()
        );
    }

    #[test]
    fn rate_limits_carry_the_upstream_result_and_wait() {
        let error = failure(read(
            r#"{"ok": false, "error": {"code": "upstream_rate_limited", "message": "Slow down.", "retryAfterSeconds": 30}}"#,
        ));
        let result = error.result.as_deref().unwrap();
        assert_eq!(result["limitScope"], "upstream");
        assert_eq!(result["service"], "tickets");
        assert_eq!(result["retryAfterSeconds"], 30);
        assert!(result["retryAt"].is_string());
        assert_eq!(error.message, "Slow down.");
        let error = failure(read(
            r#"{"ok": false, "error": {"code": "upstream_rate_limited", "message": "Slow down."}}"#,
        ));
        let result = error.result.as_deref().unwrap();
        assert_eq!(result["limitScope"], "upstream");
        assert!(result.get("retryAfterSeconds").is_none());
        for invalid in [
            json!({"code": "upstream_rate_limited", "message": "x", "retryAfterSeconds": 0}),
            json!({"code": "upstream_rate_limited", "message": "x", "retryAfterSeconds": 86_401}),
            json!({"code": "upstream_rate_limited", "message": "x", "retryAfterSeconds": 1.5}),
            json!({"code": "upstream_rate_limited", "message": "x", "retryAfterSeconds": "30"}),
            json!({"code": "upstream_failed", "message": "x", "retryAfterSeconds": 30}),
        ] {
            assert_eq!(
                read(&json!({"ok": false, "error": invalid}).to_string()).unwrap_err(),
                Violation("invalid_retry_after"),
                "{invalid}"
            );
        }
        // A write keeps its receipt beside the rate-limit result.
        let error = failure(write(json!({"ok": false,
            "error": {"code": "upstream_rate_limited", "message": "x", "retryAfterSeconds": 5},
            "receipt": {"mutationStatus": "not_applied"}})));
        let result = error.result.as_deref().unwrap();
        assert_eq!(result["mutationStatus"], "not_applied");
        assert_eq!(result["retrySafe"], true);
        assert_eq!(result["retryAfterSeconds"], 5);
    }

    #[test]
    fn failed_writes_report_the_receipt_or_unknown() {
        let receipt = |document: Value| {
            failure(write(document))
                .result
                .map(|result| *result)
                .unwrap()
        };
        let error = json!({"code": "conflict", "message": "Changed."});
        assert_eq!(
            receipt(json!({"ok": false, "error": error})),
            json!({"mutationStatus": "unknown", "retrySafe": false})
        );
        assert_eq!(
            receipt(
                json!({"ok": false, "error": error, "receipt": {"mutationStatus": "not_applied"}})
            ),
            json!({"mutationStatus": "not_applied", "retrySafe": true})
        );
        assert_eq!(
            receipt(json!({"ok": false, "error": error, "receipt": {"mutationStatus": "unknown"}})),
            json!({"mutationStatus": "unknown", "retrySafe": false})
        );
        assert_eq!(
            receipt(json!({"ok": false, "error": error,
                "receipt": {"mutationStatus": "applied_unverified"}})),
            json!({"mutationStatus": "applied_unverified", "retrySafe": false,
                "verificationStage": "command_response", "safeLocators": {}})
        );
        assert_eq!(
            receipt(json!({"ok": false, "error": error,
                "receipt": {"mutationStatus": "applied_unverified", "verificationStage": "post_write_read",
                    "safeLocators": {"issue": "OPS-45"}}})),
            json!({"mutationStatus": "applied_unverified", "retrySafe": false,
                "verificationStage": "post_write_read", "safeLocators": {"issue": "OPS-45"}})
        );
        // Reads never carry a receipt.
        let error = failure(read(&json!({"ok": false, "error": error}).to_string()));
        assert!(error.result.is_none());
    }

    #[test]
    fn malformed_documents_are_contract_violations() {
        for (document, violation) in [
            ("", "empty_response"),
            (" \n\t", "empty_response"),
            ("not json", "invalid_json"),
            (
                r#"{"ok": true, "result": {}} {"ok": true, "result": {}}"#,
                "invalid_json",
            ),
            (r#"{"ok": true, "result": {}} trailing"#, "invalid_json"),
            ("[]", "response_shape"),
            (r#"{"result": {}}"#, "response_shape"),
            (r#"{"ok": "true", "result": {}}"#, "response_shape"),
            (r#"{"ok": true}"#, "response_shape"),
            (
                r#"{"ok": true, "result": {}, "extra": 1}"#,
                "response_shape",
            ),
            (
                r#"{"ok": true, "result": {}, "error": {}}"#,
                "response_shape",
            ),
            (r#"{"ok": false}"#, "response_shape"),
            (r#"{"ok": false, "error": "failed"}"#, "response_shape"),
            (
                r#"{"ok": false, "error": {"code": "input_invalid"}}"#,
                "invalid_message",
            ),
            (
                r#"{"ok": false, "error": {"code": "input_invalid", "message": "a\nb"}}"#,
                "invalid_message",
            ),
            (
                r#"{"ok": false, "error": {"code": "input_invalid", "message": "\u001b[31m"}}"#,
                "invalid_message",
            ),
            (
                r#"{"ok": false, "error": {"code": "input_invalid", "message": 7}}"#,
                "invalid_message",
            ),
            (
                r#"{"ok": false, "error": {"code": "teapot", "message": "x"}}"#,
                "unknown_code",
            ),
            (
                r#"{"ok": false, "error": {"code": "input_invalid", "message": "x", "detail": 1}}"#,
                "response_shape",
            ),
            (
                r#"{"ok": false, "error": {"message": "x"}}"#,
                "response_shape",
            ),
            (
                r#"{"ok": false, "error": {"code": "input_invalid", "message": "x"}, "result": {}}"#,
                "response_shape",
            ),
            (
                r#"{"ok": true, "result": {}, "receipt": {}}"#,
                "receipt_on_read",
            ),
        ] {
            assert_eq!(
                read(document).unwrap_err(),
                Violation(violation),
                "{document}"
            );
        }
        let long = "x".repeat(MAX_MESSAGE_BYTES + 1);
        assert_eq!(
            read(
                &json!({"ok": false, "error": {"code": "input_invalid", "message": long}})
                    .to_string()
            )
            .unwrap_err(),
            Violation("invalid_message")
        );
        let longest = "é".repeat(MAX_MESSAGE_BYTES / 2);
        assert_eq!(
            failure(read(
                &json!({"ok": false, "error": {"code": "input_invalid", "message": longest}})
                    .to_string()
            ))
            .message,
            longest
        );
        assert_eq!(
            verify(
                "tickets",
                br#"{"ok": true, "receipt": {"mutationStatus": "unknown"}}"#,
                &secrets()
            )
            .unwrap_err(),
            Violation("response_shape")
        );
        assert_eq!(
            verify("tickets", b"", &secrets()).unwrap_err(),
            Violation("empty_response")
        );
    }

    #[test]
    fn results_must_match_the_output_schema() {
        assert_eq!(
            write(json!({"ok": true, "result": {"id": 1}})).unwrap_err(),
            Violation("output_schema")
        );
        assert_eq!(
            write(json!({"ok": true, "result": []})).unwrap_err(),
            Violation("output_schema")
        );
    }

    #[test]
    fn receipts_and_locators_are_bounded_and_never_echo_supplied_secrets() {
        let ok =
            |receipt: Value| write(json!({"ok": true, "result": {"key": "K"}, "receipt": receipt}));
        let failed = |receipt: Value| {
            write(
                json!({"ok": false, "error": {"code": "upstream_failed", "message": "x"},
                "receipt": receipt}),
            )
        };
        for (receipt, violation) in [
            (json!({}), "invalid_receipt"),
            (
                json!({"safeLocators": {}, "retrySafe": true}),
                "invalid_receipt",
            ),
            (
                json!({"safeLocators": {}, "mutationStatus": "applied_unverified"}),
                "invalid_receipt",
            ),
            (json!("receipt"), "invalid_receipt"),
            (json!({"safeLocators": []}), "invalid_locator"),
            (
                json!({"safeLocators": {"nested": {"a": 1}}}),
                "invalid_locator",
            ),
            (json!({"safeLocators": {"float": 1.5}}), "invalid_locator"),
            (json!({"safeLocators": {"flag": true}}), "invalid_locator"),
            (json!({"safeLocators": {"": "x"}}), "invalid_locator"),
            (
                json!({"safeLocators": {"k".repeat(65): "x"}}),
                "invalid_locator",
            ),
            (
                json!({"safeLocators": {"v": "x".repeat(257)}}),
                "invalid_locator",
            ),
            (
                json!({"safeLocators": {"token": "Bearer pat-example"}}),
                "secret_in_locator",
            ),
            (
                json!({"safeLocators": {"proxy": "https://svc:proxy-pass/5e@proxy.example"}}),
                "secret_in_locator",
            ),
            (
                json!({"safeLocators": {"pat-example": 1}}),
                "secret_in_locator",
            ),
        ] {
            assert_eq!(
                ok(receipt.clone()).unwrap_err(),
                Violation(violation),
                "{receipt}"
            );
        }
        let many = (0..17)
            .map(|index| (format!("k{index}"), json!(index)))
            .collect::<Map<_, _>>();
        assert_eq!(
            ok(json!({"safeLocators": many})).unwrap_err(),
            Violation("invalid_locator")
        );
        let large = (0..8)
            .map(|index| (format!("k{index}"), json!("x".repeat(150))))
            .collect::<Map<_, _>>();
        assert_eq!(
            ok(json!({"safeLocators": large})).unwrap_err(),
            Violation("invalid_locator")
        );
        let bounded = (0..16)
            .map(|index| (format!("k{index}"), json!(index)))
            .collect::<Map<_, _>>();
        assert!(ok(json!({"safeLocators": bounded})).unwrap().is_ok());
        assert!(
            ok(json!({"safeLocators": {"n": -5, "big": u64::MAX}}))
                .unwrap()
                .is_ok()
        );

        for receipt in [
            json!({"mutationStatus": "applied"}),
            json!({"mutationStatus": "not_applied", "retrySafe": true}),
            json!({"mutationStatus": "unknown", "safeLocators": {}}),
            json!({"mutationStatus": "applied_unverified", "retrySafe": false}),
            json!({"mutationStatus": "applied_unverified", "verificationStage": "Bad"}),
            json!({"mutationStatus": "applied_unverified", "verificationStage": "x".repeat(65)}),
            json!({"safeLocators": {}}),
        ] {
            assert_eq!(
                failed(receipt.clone()).unwrap_err(),
                Violation("invalid_receipt"),
                "{receipt}"
            );
        }
        assert_eq!(
            failed(json!({"mutationStatus": "applied_unverified",
                "safeLocators": {"secret": "x-pat-example-y"}}))
            .unwrap_err(),
            Violation("secret_in_locator")
        );
        assert!(verification_stage(&"a".repeat(64)));
        assert!(verification_stage("a1_b"));
        assert!(!verification_stage("1a"));
        assert!(!verification_stage(""));
    }

    #[test]
    fn messages_stages_and_locators_never_echo_supplied_secrets() {
        let message = |message: &str| {
            json!({"ok": false, "error": {"code": "upstream_failed", "message": message}})
                .to_string()
        };
        // A credential or proxy secret anywhere in a message is a violation,
        // for invocation and verification alike.
        for echoed in [
            "Token pat-example was rejected.",
            "pat-example",
            "Proxy proxy-pass/5e refused.",
        ] {
            assert_eq!(
                read(&message(echoed)).unwrap_err(),
                Violation("secret_in_message"),
                "{echoed}"
            );
            assert_eq!(
                verify("tickets", message(echoed).as_bytes(), &secrets()).unwrap_err(),
                Violation("secret_in_message"),
                "{echoed}"
            );
        }
        // So is a verification stage naming one.
        assert_eq!(
            write(
                json!({"ok": false, "error": {"code": "upstream_failed", "message": "x"},
                "receipt": {"mutationStatus": "applied_unverified",
                    "verificationStage": "stage_token_value"}})
            )
            .unwrap_err(),
            Violation("secret_in_receipt")
        );
        // And a locator key or value containing one.
        for locators in [
            json!({"note": "x-pat-example-y"}),
            json!({"pat-example": 1}),
            json!({"proxy": "proxy-pass/5e"}),
        ] {
            assert_eq!(
                write(json!({"ok": true, "result": {"key": "K"},
                    "receipt": {"safeLocators": locators}}))
                .unwrap_err(),
                Violation("secret_in_locator"),
                "{locators}"
            );
        }
    }

    #[test]
    fn messages_stages_and_locators_may_name_attribute_values() {
        // Private resource attribute values, long such as an issue key or
        // short such as a region, are not supplied secrets: a reply may name
        // them anywhere, for invocation and verification alike.
        for text in ["HELPDESK-1849 in eu is read-only.", "HELPDESK-1849", "eu"] {
            let document =
                json!({"ok": false, "error": {"code": "upstream_failed", "message": text}})
                    .to_string();
            assert_eq!(failure(read(&document)).message, text);
            assert_eq!(
                verify("tickets", document.as_bytes(), &secrets())
                    .unwrap()
                    .unwrap_err()
                    .message,
                text
            );
        }
        let failed = failure(write(json!({"ok": false,
            "error": {"code": "upstream_failed", "message": "HELPDESK-1849 in eu"},
            "receipt": {"mutationStatus": "applied_unverified", "verificationStage": "eu",
                "safeLocators": {"issue": "HELPDESK-1849", "eu": "eu"}}})));
        assert_eq!(
            failed.result.as_deref().unwrap(),
            &json!({"mutationStatus": "applied_unverified", "retrySafe": false,
                "verificationStage": "eu",
                "safeLocators": {"issue": "HELPDESK-1849", "eu": "eu"}})
        );
        let written = write(json!({"ok": true, "result": {"key": "HELPDESK-1849"},
            "receipt": {"safeLocators": {"issue": "HELPDESK-1849", "region": "eu"}}}))
        .unwrap()
        .unwrap();
        assert_eq!(
            written.result["safeLocators"],
            json!({"issue": "HELPDESK-1849", "region": "eu"})
        );
    }
}
