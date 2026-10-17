//! Transferable secrets cross the provider boundary in a private SDK sidecar.
//! Admission reserves encrypted storage; completion captures it before any
//! formatting, serialization or audit acknowledgement can fail.
use super::*;
use crate::managed_store::{
    SecretOutputCapture, SecretOutputReservation, SecretOutputReservationBatch,
    SecretReferenceLimits, SecretReservationOutcome, SecretReservationRequest,
};
use zeroize::{Zeroize, Zeroizing};

#[derive(Clone, Default)]
pub(super) struct PreparedSecretOutputs {
    descriptors: Vec<SecretOutputDescriptor>,
    sensitive_output_pointers: Vec<String>,
    reservation: Option<SecretOutputReservationBatch>,
    operation_deadline: Option<tokio::time::Instant>,
    dispatched: Arc<AtomicBool>,
    contaminated_error: Arc<AtomicBool>,
}

impl PreparedSecretOutputs {
    pub(super) fn operation_deadline(&self) -> Option<tokio::time::Instant> {
        self.operation_deadline
    }

    pub(super) fn bound_operation_deadline(&mut self, deadline: Option<tokio::time::Instant>) {
        if !self.descriptors.is_empty() {
            self.operation_deadline = self.operation_deadline.into_iter().chain(deadline).min();
        }
    }

    pub(super) fn dispatched(&self) -> bool {
        self.dispatched.load(Ordering::SeqCst)
    }

    pub(super) fn mark_dispatched(&self) {
        self.dispatched.store(true, Ordering::SeqCst);
        if let Some(reservation) = &self.reservation {
            reservation.mark_dispatched();
        }
    }

    /// Preserve evidence of a malformed error before generic hook contract
    /// enforcement can replace its result. A raw declared output poisons every
    /// provider-visible diagnostic, including message and object IDs.
    pub(super) fn sanitize_provider_error(&self, mut error: ProviderError) -> ProviderError {
        let contaminated = self.contaminated_error.load(Ordering::SeqCst)
            || error.result.as_deref().is_some_and(|result| {
                self.descriptors.iter().any(|descriptor| {
                    result
                        .pointer(result_pointer(descriptor.pointer()))
                        .is_some()
                })
            });
        if contaminated {
            self.contaminated_error.store(true, Ordering::SeqCst);
            if let Some(result) = error.result.as_deref_mut() {
                zeroize_json(result);
            }
            if let Some(audit) = error.audit.as_deref_mut() {
                zeroize_json(audit);
            }
            if let Some(ids) = error.object_ids.as_deref_mut() {
                zeroize_json(ids);
            }
            error.message.zeroize();
            error.message =
                "the provider returned an invalid secret outcome; do not repeat issuance".into();
            error.result = None;
            error.audit = None;
            error.object_ids = None;
            error.internal_diagnostic_code = None;
        }
        error
    }

    /// Safe completion evidence is retained when an acknowledged upstream
    /// outcome cannot receive its required audit acknowledgement. Raw delivery
    /// mode still never returns plaintext in an error receipt.
    pub(super) fn audit_failure_evidence(
        &self,
        outcome: &Result<ProviderResult, ProviderError>,
    ) -> Option<Value> {
        if self.descriptors.is_empty() {
            return None;
        }
        let mut result = match outcome {
            Ok(result) => result.result.clone(),
            Err(error) => error
                .result
                .as_deref()
                .cloned()
                .unwrap_or_else(|| json!({})),
        };
        for descriptor in &self.descriptors {
            let pointer = result_pointer(descriptor.pointer());
            if result
                .pointer(pointer)
                .is_some_and(|value| !is_reference_value(value))
            {
                remove_pointer(&mut result, pointer);
            }
        }
        self.add_receipt(&mut result);
        Some(result)
    }

    fn add_receipt(&self, result: &mut Value) {
        if let Some(reservation) = &self.reservation {
            ensure_object(result).insert(
                "secretReceipt".into(),
                json!({
                    "receiptId": reservation.receipt_id(),
                    "expiresAt": reservation.expires_at(),
                }),
            );
        }
    }
}

impl BrokerRuntime {
    /// One producer budget covers preparation and sequential upstream calls on
    /// every transport. Reference-mode configuration requires a longer TTL.
    pub(super) fn secret_output_operation_deadline(
        &self,
        service: &str,
        action: &str,
    ) -> Option<tokio::time::Instant> {
        self.action_descriptor(service, action)
            .filter(|action| !action.secret_outputs.is_empty())
            .map(|_| {
                tokio::time::Instant::now()
                    + Duration::from_millis(self.config.mcp.operation_timeout_ms)
            })
    }

    /// Discovery checks only the admitted identity's non-secret auth category.
    /// Final reservation still proves the exact live token/attested origin.
    pub(super) fn can_hold_secret_references(&self, identity: &IdentityContext) -> bool {
        identity.authenticated
            && identity.source.as_ref().is_some_and(|source| {
                source.token_class == Some(BrokerTokenClass::AgentInvoke)
                    && match source.kind.as_str() {
                        "broker_tokens" => source.token_id.is_some(),
                        "trusted_user" | "forwarded_identity" => identity.caller_id.is_some(),
                        _ => false,
                    }
            })
    }

    pub(super) fn prepare_secret_references(
        &self,
        context: &FinalizeContext,
        action: &ActionDescriptor,
        inputs: &mut Value,
        proof: Option<&crate::AttestedIdentityProof>,
    ) -> Result<PreparedSecretOutputs, ProviderError> {
        if action.secret_outputs.is_empty() && action.secret_inputs.is_empty() {
            return Ok(PreparedSecretOutputs::default());
        }
        let reference_mode = self.config.secret_outputs.mode == crate::SecretOutputMode::Reference;
        let has_reference_inputs = action.secret_inputs.iter().any(|descriptor| {
            inputs
                .pointer(input_pointer(descriptor.pointer()))
                .is_some_and(Value::is_object)
        });
        let needs_store =
            has_reference_inputs || (reference_mode && !action.secret_outputs.is_empty());
        let material = if needs_store {
            let execution_context = context
                .execution_context
                .as_ref()
                .ok_or_else(reference_denied)?;
            let store = self
                .managed_store
                .as_ref()
                .ok_or_else(reference_unavailable)?;
            let ring = self
                .credential_key_ring
                .as_ref()
                .ok_or_else(reference_unavailable)?;
            let origin = self
                .secret_reference_origin(&context.identity, execution_context, proof)
                .map_err(|_| reference_denied())?;
            Some((store, ring, origin))
        } else {
            None
        };

        // Keep each decrypted value zeroizing while the whole request is
        // checked. No partial plaintext request reaches a scope hook or error.
        let mut resolved = Vec::new();
        for descriptor in &action.secret_inputs {
            let pointer = input_pointer(descriptor.pointer());
            let Some(value) = inputs.pointer(pointer) else {
                continue;
            };
            if !value.is_object() {
                continue;
            }
            let reference = parse_reference(value)?;
            let (store, ring, current_origin) = material.as_ref().ok_or_else(reference_denied)?;
            let value = store
                .resolve_secret_reference(ring, reference, |conn, origin| {
                    self.check_secret_reference_owner_conn(conn, origin, current_origin)
                })
                .map_err(reference_error)?;
            resolved.push((pointer.to_owned(), Zeroizing::new(value)));
        }
        for (pointer, value) in &resolved {
            let slot = inputs
                .pointer_mut(pointer)
                .ok_or_else(reference_input_invalid)?;
            *slot = Value::String(value.to_string());
        }
        if !action.secret_inputs.is_empty()
            && action.validate_literal_secret_inputs(inputs).is_err()
        {
            clear_resolved_inputs(inputs, &resolved);
            return Err(reference_input_invalid());
        }
        // Anchor the fallback before reservation for direct prepared-invocation
        // users. Admission supplies its earlier whole-operation deadline.
        let operation_deadline =
            self.secret_output_operation_deadline(&context.service, &context.action);
        let reservation = if reference_mode && !action.secret_outputs.is_empty() {
            let (store, ring, origin) = material.ok_or_else(reference_denied)?;
            let config = &self.config.secret_outputs;
            match store.reserve_secret_outputs(
                ring,
                SecretReservationRequest {
                    broker_request_id: context.broker_request_id.clone(),
                    origin,
                    execution_context: context
                        .execution_context
                        .as_ref()
                        .ok_or_else(reference_denied)?
                        .as_str()
                        .to_owned(),
                    service: context.service.clone(),
                    action: context.action.clone(),
                    outputs: action
                        .secret_outputs
                        .iter()
                        .map(|descriptor| SecretOutputReservation {
                            pointer: descriptor.pointer().to_owned(),
                            max_bytes: descriptor.max_bytes() as usize,
                        })
                        .collect(),
                },
                &SecretReferenceLimits {
                    ttl_seconds: config.ttl_seconds,
                    max_refs_per_principal: config.max_refs_per_principal,
                    max_refs_total: config.max_refs_total,
                    max_bytes_per_principal: config.max_bytes_per_principal,
                    max_bytes_total: config.max_bytes_total,
                    receipt_retention_seconds: config.receipt_retention_seconds,
                    max_receipts_total: config.max_receipts_total,
                },
                |conn, origin| self.check_secret_reference_origin_conn(conn, origin),
            ) {
                Ok(reservation) => Some(reservation),
                Err(error) => {
                    clear_resolved_inputs(inputs, &resolved);
                    return Err(reference_error(error));
                }
            }
        } else {
            None
        };
        Ok(PreparedSecretOutputs {
            descriptors: action.secret_outputs.clone(),
            sensitive_output_pointers: action.sensitive_output_pointers.clone(),
            reservation,
            operation_deadline,
            dispatched: Arc::new(AtomicBool::new(false)),
            contaminated_error: Arc::new(AtomicBool::new(false)),
        })
    }

    pub(super) fn complete_secret_outputs(
        &self,
        prepared: &PreparedSecretOutputs,
        outcome: Result<ProviderResult, ProviderError>,
    ) -> Result<ProviderResult, ProviderError> {
        let mut result = match outcome {
            Ok(result) => result,
            Err(error) => {
                let mut error = prepared.sanitize_provider_error(error);
                if prepared.contaminated_error.load(Ordering::SeqCst) {
                    error = ProviderError::error(ReasonCode::SecretCaptureFailed,error.message)
                        .with_upstream(error.upstream_status,error.upstream_duration_ms)
                        .with_audit(json!({"executionState":"unknown","retrySafe":false,"secretCaptureStatus":"failed"}));
                }
                if !prepared.descriptors.is_empty() {
                    let execution_state = if !prepared.dispatched.load(Ordering::SeqCst) {
                        "not_dispatched"
                    } else {
                        "unknown"
                    };
                    let mut safe = receipt_metadata(
                        error.result.as_deref(),
                        error.object_ids.as_deref(),
                        execution_state,
                        &prepared.sensitive_output_pointers,
                    );
                    if let (Some(store), Some(reservation)) =
                        (&self.managed_store, &prepared.reservation)
                    {
                        let terminal = if execution_state == "not_dispatched" {
                            SecretReservationOutcome::NotDispatched
                        } else {
                            // A transport/protocol/provider error after dispatch
                            // cannot prove an issuing operation did nothing.
                            SecretReservationOutcome::Unknown
                        };
                        // Even a failed acknowledgement cannot authorize replay.
                        let _ =
                            store.finish_secret_reservation(reservation, terminal, safe.clone());
                    }
                    prepared.add_receipt(&mut safe);
                    if let Some(result) = error.result.as_deref_mut() {
                        zeroize_json(result);
                    }
                    error.result = Some(Box::new(safe));
                }
                return Err(error);
            }
        };
        let values = agent_access_provider::host::take_secret_outputs(&mut result);
        if prepared.descriptors.is_empty() && values.is_empty() {
            return Ok(result);
        }
        if contains_sidecar_copy(&result, &values)
            || prepared.descriptors.iter().any(|descriptor| {
                result
                    .result
                    .pointer(result_pointer(descriptor.pointer()))
                    .is_some()
            })
        {
            // A contract bug may have copied the secret anywhere in the
            // ordinary outcome. None of that data is trustworthy as a receipt.
            zeroize_json(&mut result.result);
            if let Some(audit) = &mut result.audit {
                zeroize_json(audit);
            }
            if let Some(ids) = &mut result.object_ids {
                zeroize_json(ids);
            }
            result.result = json!({});
            result.audit = None;
            result.object_ids = None;
            return Err(self.secret_capture_failure(prepared, result));
        }
        let mut seen = BTreeSet::new();
        let valid = values.iter().all(|value| {
            prepared
                .descriptors
                .iter()
                .find(|descriptor| descriptor.pointer() == value.pointer())
                .is_some_and(|descriptor| {
                    !value.value().is_empty()
                        && value.value().len() as u64 <= descriptor.max_bytes()
                        && seen.insert(value.pointer())
                })
        }) && prepared.descriptors.iter().all(|descriptor| {
            (!descriptor.is_required() || seen.contains(descriptor.pointer()))
                && result
                    .result
                    .pointer(result_pointer(descriptor.pointer()))
                    .is_none()
                && (!seen.contains(descriptor.pointer())
                    || pointer_parent_is_object(
                        &result.result,
                        result_pointer(descriptor.pointer()),
                    ))
        }) && result.stream.is_none();
        // Provider contract violations never fall back to extracting a raw
        // property: remove it before keeping the safe issuance metadata.
        for descriptor in &prepared.descriptors {
            remove_pointer(&mut result.result, result_pointer(descriptor.pointer()));
        }
        if !valid {
            return Err(self.secret_capture_failure(prepared, result));
        }
        if let Some(reservation) = &prepared.reservation {
            let captured = match (&self.managed_store, &self.credential_key_ring) {
                (Some(store), Some(ring)) => store.capture_secret_outputs(
                    ring,
                    reservation,
                    values
                        .iter()
                        .map(|value| SecretOutputCapture {
                            pointer: value.pointer().to_owned(),
                            value: value.value().to_owned(),
                        })
                        .collect(),
                    receipt_metadata(
                        Some(&result.result),
                        result.object_ids.as_ref(),
                        "completed",
                        &prepared.sensitive_output_pointers,
                    ),
                ),
                _ => return Err(self.secret_capture_failure(prepared, result)),
            };
            match captured {
                Ok(references) => {
                    for reference in references {
                        if !insert_pointer(
                            &mut result.result,
                            result_pointer(&reference.pointer),
                            json!({
                                "secretRef": reference.secret_ref, "expiresAt": reference.expires_at,
                            }),
                        ) {
                            return Err(self.secret_capture_failure(prepared, result));
                        }
                    }
                }
                Err(_) => return Err(self.secret_capture_failure(prepared, result)),
            }
            prepared.add_receipt(&mut result.result);
        } else {
            for value in &values {
                if !insert_pointer(
                    &mut result.result,
                    result_pointer(value.pointer()),
                    json!(value.value()),
                ) {
                    return Err(self.secret_capture_failure(prepared, result));
                }
            }
        }
        Ok(result)
    }

    fn secret_capture_failure(
        &self,
        prepared: &PreparedSecretOutputs,
        mut result: ProviderResult,
    ) -> ProviderError {
        for descriptor in &prepared.descriptors {
            remove_pointer(&mut result.result, result_pointer(descriptor.pointer()));
        }
        let fields = ensure_object(&mut result.result);
        fields.insert("executionState".into(), json!("completed"));
        fields.insert("retrySafe".into(), json!(false));
        fields.insert("secretCaptureStatus".into(), json!("failed"));
        if let (Some(store), Some(reservation)) = (&self.managed_store, &prepared.reservation) {
            let _ = store.finish_secret_reservation(
                reservation,
                SecretReservationOutcome::CaptureFailed,
                receipt_metadata(
                    Some(&result.result),
                    result.object_ids.as_ref(),
                    "completed",
                    &prepared.sensitive_output_pointers,
                ),
            );
        }
        prepared.add_receipt(&mut result.result);
        ProviderError::error(
            ReasonCode::SecretCaptureFailed,
            "the provider completed but its secret could not be captured; do not repeat issuance",
        )
        .with_result(result.result)
        .with_audit(
            json!({"executionState":"completed","retrySafe":false,"secretCaptureStatus":"failed"}),
        )
        .with_upstream(result.upstream_status, result.upstream_duration_ms)
    }
}

pub(super) fn validate_reference_inputs(
    action: &ActionDescriptor,
    inputs: &Value,
) -> Result<(), ProviderError> {
    reject_undeclared_references(inputs, "/inputs", action)?;
    if action.secret_inputs.is_empty() {
        return Ok(());
    }
    let schema = action
        .reference_input_schema()
        .map_err(|_| reference_input_invalid())?;
    let validator = jsonschema::validator_for(&schema).map_err(|_| reference_input_invalid())?;
    if validator.is_valid(inputs) {
        Ok(())
    } else {
        Err(reference_input_invalid())
    }
}

fn reject_undeclared_references(
    value: &Value,
    pointer: &str,
    action: &ActionDescriptor,
) -> Result<(), ProviderError> {
    match value {
        Value::Object(object) => {
            if object
                .get("secretRef")
                .and_then(Value::as_str)
                .is_some_and(is_secret_reference_capability)
            {
                if parse_reference(value).is_err()
                    || !action
                        .secret_inputs
                        .iter()
                        .any(|input| input.pointer() == pointer)
                {
                    return Err(reference_input_invalid());
                }
                return Ok(());
            }
            for (key, value) in object {
                if is_secret_reference_capability(key) {
                    return Err(reference_input_invalid());
                }
                let pointer = format!("{pointer}/{}", key.replace('~', "~0").replace('/', "~1"));
                reject_undeclared_references(value, &pointer, action)?;
            }
        }
        Value::Array(values) => {
            for (index, value) in values.iter().enumerate() {
                reject_undeclared_references(value, &format!("{pointer}/{index}"), action)?;
            }
        }
        Value::String(value) if is_secret_reference_capability(value) => {
            return Err(reference_input_invalid());
        }
        _ => {}
    }
    Ok(())
}

/// Only bounded locators explicitly declared safe by the provider and known
/// outcome fields survive in durable receipts. Ordinary result/audit data may
/// contain unrelated sensitive information and is never persisted here.
fn receipt_metadata(
    result: Option<&Value>,
    object_ids: Option<&Value>,
    execution_state: &str,
    sensitive_outputs: &[String],
) -> Value {
    let public_field = |field: &str| {
        let pointer = format!("/result/{field}");
        !sensitive_outputs
            .iter()
            .any(|sensitive| pointers_overlap(sensitive, &pointer))
    };
    let mut metadata = json!({"executionState":execution_state,"retrySafe":false});
    if let Some(status) = result
        .and_then(|result| result.get("mutationStatus"))
        .and_then(Value::as_str)
        && matches!(
            status,
            "applied" | "applied_verified" | "applied_unverified" | "not_applied" | "unknown"
        )
        && public_field("mutationStatus")
    {
        metadata["mutationStatus"] = json!(status);
    }
    // These are canonical SDK MutationReceipt fields. Keeping their bounded
    // safe projection preserves the caller's recovery instructions without
    // retaining the error's arbitrary result data.
    if let Some(stage) = result
        .and_then(|result| result.get("verificationStage"))
        .and_then(Value::as_str)
        && !stage.is_empty()
        && stage.len() <= 128
        && !stage.chars().any(char::is_control)
        && public_field("verificationStage")
    {
        metadata["verificationStage"] = json!(stage);
    }
    if let Some(locators) = result.and_then(|result| result.get("safeLocators"))
        && public_field("safeLocators")
        && locators.is_object()
        && bounded_receipt_locator(locators, 0)
        && json_within_receipt_bound(locators)
    {
        metadata["safeLocators"] = locators.clone();
    }
    if let Some(ids) = object_ids.and_then(Value::as_object) {
        let ids: serde_json::Map<String, Value> = ids
            .iter()
            .take(32)
            .filter(|(key, value)| {
                key.len() <= 64
                    && !key.chars().any(char::is_control)
                    && match value {
                        Value::String(value) => {
                            value.len() <= 256 && !value.chars().any(char::is_control)
                        }
                        Value::Number(_) | Value::Bool(_) => true,
                        _ => false,
                    }
            })
            .map(|(key, value)| (key.clone(), value.clone()))
            .collect();
        let ids = Value::Object(ids);
        if ids.as_object().is_some_and(|ids| !ids.is_empty()) && json_within_receipt_bound(&ids) {
            metadata["objectIds"] = ids;
        }
    }
    metadata
}

fn json_within_receipt_bound(value: &Value) -> bool {
    serde_json::to_vec(value).is_ok_and(|encoded| encoded.len() <= 4096)
}
fn bounded_receipt_locator(value: &Value, depth: usize) -> bool {
    match value {
        Value::String(value) => value.len() <= 512 && !value.chars().any(char::is_control),
        Value::Number(_) | Value::Bool(_) | Value::Null => true,
        Value::Object(values) => {
            depth < 2
                && values.len() <= 16
                && values.iter().all(|(key, value)| {
                    key.len() <= 64
                        && !key.chars().any(char::is_control)
                        && bounded_receipt_locator(value, depth + 1)
                })
        }
        Value::Array(values) => {
            depth < 2
                && values.len() <= 16
                && values
                    .iter()
                    .all(|value| bounded_receipt_locator(value, depth + 1))
        }
    }
}
fn pointers_overlap(left: &str, right: &str) -> bool {
    left.split('/')
        .zip(right.split('/'))
        .all(|(left, right)| left == right || left == "*" || right == "*")
}

fn contains_sidecar_copy(
    result: &ProviderResult,
    secrets: &[agent_access_provider::host::SecretOutputValue],
) -> bool {
    secrets.iter().any(|secret| {
        if secret.value().is_empty() {
            return false;
        }
        let encoded =
            Zeroizing::new(serde_json::to_string(secret.value()).expect("string serialization"));
        let escaped = &encoded[1..encoded.len() - 1];
        let contains = |value: &Value| {
            contains_string(value, secret.value()) || contains_string(value, escaped)
        };
        contains(&result.result)
            || result.audit.as_ref().is_some_and(contains)
            || result.object_ids.as_ref().is_some_and(contains)
    })
}
fn contains_string(value: &Value, needle: &str) -> bool {
    match value {
        Value::String(value) => value.contains(needle),
        Value::Object(object) => object
            .iter()
            .any(|(key, value)| key.contains(needle) || contains_string(value, needle)),
        Value::Array(values) => values.iter().any(|value| contains_string(value, needle)),
        _ => false,
    }
}
fn zeroize_json(value: &mut Value) {
    match value {
        Value::String(value) => value.zeroize(),
        Value::Array(values) => values.iter_mut().for_each(zeroize_json),
        Value::Object(values) => {
            for (mut key, mut value) in std::mem::take(values) {
                key.zeroize();
                zeroize_json(&mut value);
            }
        }
        _ => {}
    }
}

fn reference_error(error: ManagedStoreError) -> ProviderError {
    let message = match &error {
        ManagedStoreError::SecretReferenceExpired => {
            "secret reference expired; do not repeat the issuing operation"
        }
        ManagedStoreError::SecretReferenceNotFound => "secret reference is unavailable",
        ManagedStoreError::SecretReferenceDenied => "secret reference use is not authorized",
        ManagedStoreError::SecretReferenceCapacity => {
            "temporary secret capacity is exhausted; provider was not invoked"
        }
        _ => "temporary secret storage is unavailable",
    };
    ProviderError::error(error.reason_code(), message)
}
fn reference_denied() -> ProviderError {
    ProviderError::deny(
        ReasonCode::SecretReferenceDenied,
        "secret references require a managed broker token or a current attested managed identity",
    )
}
fn reference_unavailable() -> ProviderError {
    ProviderError::error(
        ReasonCode::ManagedStoreUnavailable,
        "temporary secret storage is unavailable",
    )
}
fn reference_input_invalid() -> ProviderError {
    ProviderError::error(
        ReasonCode::InputInvalid,
        "secret input does not satisfy the action contract",
    )
}
fn input_pointer(pointer: &str) -> &str {
    pointer.strip_prefix("/inputs").unwrap_or("")
}
fn result_pointer(pointer: &str) -> &str {
    pointer.strip_prefix("/result").unwrap_or("")
}
fn is_reference_value(value: &Value) -> bool {
    parse_reference(value).is_ok()
}
fn parse_reference(value: &Value) -> Result<&str, ProviderError> {
    let object = value.as_object().ok_or_else(reference_input_invalid)?;
    if object
        .keys()
        .any(|key| key != "secretRef" && key != "expiresAt")
        || object
            .get("expiresAt")
            .is_some_and(|value| value.as_str().is_none_or(|value| value.len() > 64))
    {
        return Err(reference_input_invalid());
    }
    let reference = object
        .get("secretRef")
        .and_then(Value::as_str)
        .ok_or_else(reference_input_invalid)?;
    if !is_secret_reference_capability(reference) {
        return Err(reference_input_invalid());
    }
    Ok(reference)
}
fn is_secret_reference_capability(value: &str) -> bool {
    value.len() == 46
        && value.starts_with("sr_")
        && value[3..]
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-')
}
fn clear_resolved_inputs(inputs: &mut Value, resolved: &[(String, Zeroizing<String>)]) {
    for (pointer, _) in resolved {
        if let Some(value) = inputs.pointer_mut(pointer) {
            if let Value::String(secret) = value {
                secret.zeroize();
            }
            *value = Value::Null;
        }
    }
}
fn ensure_object(value: &mut Value) -> &mut serde_json::Map<String, Value> {
    if !value.is_object() {
        *value = json!({"providerResult": std::mem::take(value)});
    }
    value.as_object_mut().expect("normalized object")
}
fn pointer_parts(pointer: &str) -> Option<(&str, String)> {
    let (parent, key) = pointer.rsplit_once('/')?;
    Some((parent, key.replace("~1", "/").replace("~0", "~")))
}
fn pointer_parent_is_object(value: &Value, pointer: &str) -> bool {
    pointer_parts(pointer)
        .is_some_and(|(parent, _)| object_pointer(value, parent).is_some_and(Value::is_object))
}
fn insert_pointer(value: &mut Value, pointer: &str, inserted: Value) -> bool {
    let Some((parent, key)) = pointer_parts(pointer) else {
        return false;
    };
    let Some(parent) = object_pointer_mut(value, parent).and_then(Value::as_object_mut) else {
        return false;
    };
    parent.insert(key, inserted);
    true
}
fn remove_pointer(value: &mut Value, pointer: &str) {
    if let Some((parent, key)) = pointer_parts(pointer)
        && let Some(parent) = object_pointer_mut(value, parent).and_then(Value::as_object_mut)
        && let Some(mut value) = parent.remove(&key)
        && let Value::String(secret) = &mut value
    {
        secret.zeroize();
    }
}

fn object_pointer<'a>(mut value: &'a Value, pointer: &str) -> Option<&'a Value> {
    if pointer.is_empty() {
        return Some(value);
    }
    for key in pointer.strip_prefix('/')?.split('/') {
        value = value
            .as_object()?
            .get(&key.replace("~1", "/").replace("~0", "~"))?;
    }
    Some(value)
}
fn object_pointer_mut<'a>(mut value: &'a mut Value, pointer: &str) -> Option<&'a mut Value> {
    if pointer.is_empty() {
        return Some(value);
    }
    for key in pointer.strip_prefix('/')?.split('/') {
        value = value
            .as_object_mut()?
            .get_mut(&key.replace("~1", "/").replace("~0", "~"))?;
    }
    Some(value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use base64::Engine;
    use std::sync::atomic::AtomicUsize;

    struct SecretProvider {
        calls: AtomicUsize,
        sequential_steps: AtomicUsize,
        step_delay_ms: std::sync::atomic::AtomicU64,
        scope_delay_ms: std::sync::atomic::AtomicU64,
        observed_deadline: Mutex<Option<tokio::time::Instant>>,
        inputs: Mutex<Vec<String>>,
        token: String,
        pending: bool,
        failure: Mutex<Option<ReasonCode>>,
        finalize_at_deadline: AtomicBool,
        leak: std::sync::atomic::AtomicU8,
    }
    #[async_trait]
    impl Provider for SecretProvider {
        async fn resolve_scopes(
            &self,
            request: ScopeRequest<'_>,
        ) -> Result<ScopeResolution, ProviderError> {
            let delay = self.scope_delay_ms.load(Ordering::SeqCst);
            if delay > 0 {
                tokio::time::sleep(Duration::from_millis(delay)).await;
            }
            // Scope hooks inspect only resource selectors. Declared secret
            // payloads remain structured references until after authorization.
            let project = request.inputs()["project"]
                .as_str()
                .ok_or_else(reference_input_invalid)?;
            Ok(ScopeResolution::resources(BTreeMap::from([(
                "project".into(),
                vec![project.into()],
            )])))
        }
        async fn invoke(
            &self,
            request: ProviderInvocation,
        ) -> Result<ProviderResult, ProviderError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            *self.observed_deadline.lock().unwrap() =
                current_provider_finalization().and_then(|context| context.deadline());
            let delay = self.step_delay_ms.load(Ordering::SeqCst);
            if delay > 0 {
                // Each upstream round trip fits its per-request limit; their
                // combined duration must still fit the whole producer budget.
                for _ in 0..3 {
                    tokio::time::sleep(Duration::from_millis(delay)).await;
                    self.sequential_steps.fetch_add(1, Ordering::SeqCst);
                }
            }
            self.inputs
                .lock()
                .unwrap()
                .push(request.inputs()["message"].as_str().unwrap().to_owned());
            if self.pending {
                std::future::pending::<()>().await;
            }
            if let Some(reason) = *self.failure.lock().unwrap() {
                return Err(ProviderError::error(reason, "synthetic upstream failure")
                    .with_result(json!({"mutationStatus":"applied_unverified","tokenId":42})));
            }
            if self.finalize_at_deadline.load(Ordering::SeqCst) {
                let finalization = current_provider_finalization().unwrap();
                let _guard = finalization.enter_finalization();
                std::future::poll_fn(|_| {
                    if tokio::time::Instant::now() >= finalization.deadline().unwrap() {
                        std::task::Poll::Ready(())
                    } else {
                        std::task::Poll::Pending
                    }
                })
                .await;
            }
            let mut result =
                ProviderResult::new(json!({"accessToken":{"id":42},"mutationStatus":"applied"}))
                    .with_secret_output("/result/issuedToken", self.token.clone())
                    .with_object_ids(json!({"tokenId":42}))
                    .with_audit(json!({"tokenId":42}));
            match self.leak.load(Ordering::SeqCst) {
                1 => {
                    result.result["accidentalCopy"] = json!(format!("prefix {} suffix", self.token))
                }
                2 => {
                    result.audit =
                        Some(json!({"accidentalCopy":serde_json::to_string(&self.token).unwrap()}))
                }
                3 => result.object_ids = Some(json!({self.token.clone():42})),
                _ => {}
            }
            Ok(result)
        }
    }
    fn fixture(
        mode: crate::SecretOutputMode,
        max_bytes: u64,
        pending: bool,
    ) -> (
        tempfile::TempDir,
        BrokerRuntime,
        IdentityContext,
        Arc<SecretProvider>,
    ) {
        fixture_with_secret(mode, max_bytes, pending, "synthetic-one-time-token")
    }
    fn fixture_with_secret(
        mode: crate::SecretOutputMode,
        max_bytes: u64,
        pending: bool,
        token: &str,
    ) -> (
        tempfile::TempDir,
        BrokerRuntime,
        IdentityContext,
        Arc<SecretProvider>,
    ) {
        let dir = tempfile::tempdir().unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
        }
        let hash_key = dir.path().join("hash-key");
        fs::write(
            &hash_key,
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([24_u8; 32]),
        )
        .unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&hash_key, fs::Permissions::from_mode(0o600)).unwrap();
        }
        let mut config = super::super::tests::base_fake_config();
        config.secret_outputs.mode = mode;
        config.secret_outputs.max_refs_per_principal = 1;
        config.credentials.service.clear();
        config.identity.mode = "required".into();
        config.identity.authority = "managed".into();
        config.identity.groups.clear();
        config.identity.sources = vec![crate::IdentitySourceConfig {
            name: "broker".into(),
            kind: "broker_tokens".into(),
            header: "Authorization".into(),
            scheme: "Bearer".into(),
            principals: vec![],
        }];
        config.broker_tokens = Some(crate::BrokerTokensConfig {
            hash_key_ref: format!("file:{}", hash_key.display()),
            ..Default::default()
        });
        config.managed_store = Some(crate::ManagedStoreConfig {
            kind: "sqlite".into(),
            path: dir.path().join("store.sqlite").display().to_string(),
            auto_migrate: true,
            require_registered_principal_for_invocation: false,
        });
        config.audit = Some(crate::AuditConfig::new(
            crate::AuditStoreType::Jsonl,
            dir.path().join("audit.jsonl").display().to_string(),
        ));
        let grant = config.policy.grants[0].clone();
        config.policy.grants.clear();
        let provider = Arc::new(SecretProvider {
            calls: AtomicUsize::new(0),
            sequential_steps: AtomicUsize::new(0),
            step_delay_ms: std::sync::atomic::AtomicU64::new(0),
            scope_delay_ms: std::sync::atomic::AtomicU64::new(0),
            observed_deadline: Mutex::new(None),
            inputs: Mutex::new(vec![]),
            token: token.into(),
            pending,
            failure: Mutex::new(None),
            finalize_at_deadline: AtomicBool::new(false),
            leak: std::sync::atomic::AtomicU8::new(0),
        });
        let mut descriptor = agent_access_fake::fake_descriptor();
        descriptor.actions[0] = descriptor.actions[0]
            .clone()
            .secret_output(SecretOutputDescriptor::new(
                "/result/issuedToken",
                max_bytes,
            ))
            .secret_input(SecretInputDescriptor::new("/inputs/message"));
        let runtime = BrokerRuntime::with_providers(
            config,
            [ServiceProvider::new(descriptor, provider.clone())],
        )
        .unwrap();
        let store = runtime.managed_store.as_ref().unwrap();
        store
            .create_or_update_principal(crate::PrincipalWriteRequest {
                role: crate::PrincipalRole::User,
                self_service_enabled: None,
                principal_id: "alice".into(),
                kind: "user".into(),
                display_name: None,
                email: None,
                external_subject: None,
                created_by: "test".into(),
            })
            .unwrap();
        let token = store
            .issue_broker_token(
                runtime.broker_token_hasher.as_ref().unwrap(),
                crate::BrokerTokenIssueRequest {
                    principal_id: "alice".into(),
                    name: "secret-test".into(),
                    token_class: BrokerTokenClass::AgentInvoke,
                    scopes: json!({"allowedExecutionContexts":["default"]}),
                    expires_at: None,
                    created_by: "test".into(),
                },
            )
            .unwrap();
        let mut headers = HeaderMap::new();
        headers.insert(
            "Authorization",
            format!("Bearer {}", token.token).parse().unwrap(),
        );
        let identity = runtime.resolve_identity(&headers).unwrap();
        let mut config = (*runtime.config).clone();
        let mut grant = grant;
        grant.subjects = vec!["user:alice".into()];
        config.policy.grants = vec![grant];
        runtime
            .policy_snapshot
            .store(Arc::new(PolicySnapshot::from_config(&config, 1)));
        (dir, runtime, identity, provider)
    }
    fn context(identity: IdentityContext) -> GovernedOperationContext {
        GovernedOperationContext {
            operation: OperationContext {
                agent_request_id: "secret-test".into(),
                broker_request_id: Uuid::new_v4().to_string(),
                identity,
                service: "fake".into(),
                action: "echo".into(),
                source: SourceContext::unknown(),
            },
            execution_context: ExecutionContext::new("default").unwrap(),
        }
    }
    fn request(message: Value) -> InvokeRequest {
        serde_json::from_value(json!({"inputs":{"project":"TEST","message":message}})).unwrap()
    }

    #[tokio::test]
    async fn owned_capture_returns_reference_and_quota_blocks_second_dispatch() {
        let (dir, runtime, identity, provider) =
            fixture(crate::SecretOutputMode::Reference, 128, false);
        let response = runtime
            .invoke_owned_json(
                context(identity.clone()),
                request(json!("literal")),
                InvocationControl::default(),
            )
            .await;
        assert_eq!(response.status, 200, "{:?}", response.envelope);
        let value = response.envelope.result.unwrap();
        assert!(is_reference_value(&value["issuedToken"]));
        assert!(!value.to_string().contains(&provider.token));
        let origin = runtime
            .secret_reference_origin(&identity, &ExecutionContext::new("default").unwrap(), None)
            .unwrap();
        let value = runtime
            .managed_store
            .as_ref()
            .unwrap()
            .resolve_secret_reference(
                runtime.credential_key_ring.as_ref().unwrap(),
                value["issuedToken"]["secretRef"].as_str().unwrap(),
                |conn, stored| runtime.check_secret_reference_owner_conn(conn, stored, &origin),
            )
            .unwrap();
        assert_eq!(value, provider.token);
        let response = runtime
            .invoke_owned_json(
                context(identity),
                request(json!("literal")),
                InvocationControl::default(),
            )
            .await;
        assert_eq!(
            response.envelope.reason_code,
            Some(ReasonCode::SecretReferenceCapacity.into())
        );
        assert_eq!(provider.calls.load(Ordering::SeqCst), 1);
        let audit = fs::read_to_string(dir.path().join("audit.jsonl")).unwrap();
        assert!(!audit.contains(&provider.token));
        assert!(!audit.contains("sr_"));
    }

    #[tokio::test]
    async fn raw_mode_materializes_sidecar_without_secret_error_evidence() {
        let (_dir, runtime, identity, provider) = fixture(crate::SecretOutputMode::Raw, 128, false);
        let response = runtime
            .invoke_owned_json(
                context(identity),
                request(json!("literal")),
                InvocationControl::default(),
            )
            .await;
        assert_eq!(response.status, 200, "{:?}", response.envelope);
        assert_eq!(
            response.envelope.result.unwrap()["issuedToken"],
            provider.token
        );
        let prepared = PreparedSecretOutputs {
            descriptors: vec![SecretOutputDescriptor::new("/result/issuedToken", 128)],
            ..Default::default()
        };
        let evidence = prepared
            .audit_failure_evidence(&Ok(ProviderResult::new(
                json!({"issuedToken":provider.token,"id":42}),
            )))
            .unwrap();
        assert!(evidence.get("issuedToken").is_none());
        assert_eq!(evidence["id"], 42);
    }

    #[tokio::test]
    async fn oversized_sidecar_fails_closed_with_safe_completed_receipt() {
        let (_dir, runtime, identity, provider) =
            fixture(crate::SecretOutputMode::Reference, 4, false);
        let response = runtime
            .invoke_owned_json(
                context(identity),
                request(json!("literal")),
                InvocationControl::default(),
            )
            .await;
        assert_eq!(
            response.envelope.reason_code,
            Some(ReasonCode::SecretCaptureFailed.into())
        );
        let result = response.envelope.result.unwrap();
        assert_eq!(result["executionState"], "completed");
        assert_eq!(result["retrySafe"], false);
        assert_eq!(result["accessToken"]["id"], 42);
        assert!(!result.to_string().contains(&provider.token));
        assert_eq!(provider.calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn deadline_finishes_reserved_output_as_unknown_without_replay() {
        let (_dir, runtime, identity, provider) =
            fixture(crate::SecretOutputMode::Reference, 128, true);
        let response = runtime
            .invoke_owned_json(
                context(identity),
                request(json!("literal")),
                InvocationControl::new(Some(Duration::from_millis(100))),
            )
            .await;
        assert_eq!(
            response.envelope.reason_code,
            Some(ReasonCode::OperationTimeout.into())
        );
        let result = response.envelope.result.unwrap();
        assert_eq!(result["executionState"], "unknown");
        assert_eq!(result["retrySafe"], false);
        assert!(result["secretReceipt"]["receiptId"].is_string());
        assert_eq!(provider.calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn producer_budget_bounds_sequential_calls_on_owned_and_direct_paths() {
        for mode in [
            crate::SecretOutputMode::Reference,
            crate::SecretOutputMode::Raw,
        ] {
            for direct in [false, true] {
                let (_dir, mut runtime, identity, provider) = fixture(mode, 128, false);
                Arc::make_mut(&mut runtime.config).mcp.operation_timeout_ms = 300;
                provider.step_delay_ms.store(125, Ordering::SeqCst);
                let response = if direct {
                    runtime
                        .invoke(context(identity), request(json!("literal")))
                        .await
                } else {
                    runtime
                        .invoke_owned_json(
                            context(identity),
                            request(json!("literal")),
                            InvocationControl::default(),
                        )
                        .await
                };
                assert_eq!(
                    response.envelope.reason_code,
                    Some(ReasonCode::OperationTimeout.into())
                );
                assert_eq!(provider.calls.load(Ordering::SeqCst), 1);
                assert!(provider.sequential_steps.load(Ordering::SeqCst) < 3);
                let result = response.envelope.result.unwrap();
                assert_eq!(result["executionState"], "unknown");
                assert_eq!(result["retrySafe"], false);
                assert!(!result.to_string().contains(&provider.token));
            }
        }
    }

    #[tokio::test]
    async fn producer_budget_includes_scope_preparation_on_owned_and_direct_paths() {
        for direct in [false, true] {
            let (_dir, mut runtime, identity, provider) =
                fixture(crate::SecretOutputMode::Reference, 128, false);
            Arc::make_mut(&mut runtime.config).mcp.operation_timeout_ms = 100;
            provider.scope_delay_ms.store(300, Ordering::SeqCst);
            let response = if direct {
                runtime
                    .invoke(context(identity), request(json!("literal")))
                    .await
            } else {
                runtime
                    .invoke_owned_json(
                        context(identity),
                        request(json!("literal")),
                        InvocationControl::default(),
                    )
                    .await
            };
            assert_eq!(
                response.envelope.reason_code,
                Some(ReasonCode::OperationTimeout.into())
            );
            assert_eq!(provider.calls.load(Ordering::SeqCst), 0);
            assert_eq!(
                response.envelope.result.unwrap()["executionState"],
                "not_dispatched"
            );
        }
    }

    #[tokio::test]
    async fn earlier_caller_deadline_and_supervisor_state_are_preserved() {
        let (_dir, mut runtime, identity, provider) =
            fixture(crate::SecretOutputMode::Reference, 128, true);
        Arc::make_mut(&mut runtime.config).mcp.operation_timeout_ms = 1_000;
        let control = InvocationControl::new(Some(Duration::from_millis(100)));
        let latest_caller_deadline = tokio::time::Instant::now() + Duration::from_millis(100);
        let response = runtime
            .invoke_owned_json(
                context(identity),
                request(json!("literal")),
                control.clone(),
            )
            .await;
        assert_eq!(
            response.envelope.reason_code,
            Some(ReasonCode::OperationTimeout.into())
        );
        assert!(provider.observed_deadline.lock().unwrap().unwrap() <= latest_caller_deadline);
        assert!(control.dispatched());
        assert!(!control.completed());
    }

    #[tokio::test]
    async fn prepared_producer_cannot_dispatch_after_its_admission_deadline() {
        let (_dir, mut runtime, identity, provider) =
            fixture(crate::SecretOutputMode::Reference, 128, false);
        Arc::make_mut(&mut runtime.config).mcp.operation_timeout_ms = 100;
        let prepared = runtime
            .begin_invoke(context(identity), request(json!("literal")))
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_millis(150)).await;
        let response = runtime.finish_prepared_invoke(prepared, vec![]).await;
        assert_eq!(
            response.envelope.reason_code,
            Some(ReasonCode::OperationTimeout.into())
        );
        assert_eq!(provider.calls.load(Ordering::SeqCst), 0);
        assert_eq!(
            response.envelope.result.unwrap()["executionState"],
            "not_dispatched"
        );
    }

    #[tokio::test]
    async fn known_sidecar_is_captured_after_the_deadline_final_poll() {
        let (_dir, runtime, identity, provider) =
            fixture(crate::SecretOutputMode::Reference, 128, false);
        provider.finalize_at_deadline.store(true, Ordering::SeqCst);
        let response = runtime
            .invoke_owned_json(
                context(identity),
                request(json!("literal")),
                InvocationControl::new(Some(Duration::from_millis(100))),
            )
            .await;
        assert_eq!(response.status, 200, "{:?}", response.envelope);
        assert!(is_reference_value(
            &response.envelope.result.unwrap()["issuedToken"]
        ));
        assert_eq!(provider.calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn dispatched_transport_and_protocol_errors_retain_unknown_receipts() {
        for reason in [
            ReasonCode::UpstreamConnectionFailed,
            ReasonCode::UpstreamTimeout,
            ReasonCode::UpstreamProtocolFailed,
        ] {
            let (_dir, runtime, identity, provider) =
                fixture(crate::SecretOutputMode::Reference, 128, false);
            *provider.failure.lock().unwrap() = Some(reason);
            let response = runtime
                .invoke_owned_json(
                    context(identity.clone()),
                    request(json!("literal")),
                    InvocationControl::default(),
                )
                .await;
            let result = response.envelope.result.unwrap();
            assert_eq!(result["executionState"], "unknown");
            assert_eq!(result["retrySafe"], false);
            assert_eq!(result["mutationStatus"], "applied_unverified");
            let origin = runtime
                .secret_reference_origin(
                    &identity,
                    &ExecutionContext::new("default").unwrap(),
                    None,
                )
                .unwrap();
            let receipt = runtime
                .managed_store
                .as_ref()
                .unwrap()
                .secret_reference_receipt(
                    runtime.credential_key_ring.as_ref().unwrap(),
                    result["secretReceipt"]["receiptId"].as_str().unwrap(),
                    |conn, stored| runtime.check_secret_reference_owner_conn(conn, stored, &origin),
                )
                .unwrap();
            assert_eq!(receipt.outcome, "unknown");
            assert_eq!(provider.calls.load(Ordering::SeqCst), 1);
        }
    }

    #[tokio::test]
    async fn native_reference_input_resolves_after_policy_and_revalidates_literal_schema() {
        let (_dir, mut runtime, identity, provider) =
            fixture(crate::SecretOutputMode::Reference, 128, false);
        let response = runtime
            .invoke_owned_json(
                context(identity.clone()),
                request(json!("literal")),
                InvocationControl::default(),
            )
            .await;
        assert_eq!(response.status, 200, "{:?}", response.envelope);
        let reference = response.envelope.result.unwrap()["issuedToken"].clone();
        Arc::make_mut(&mut runtime.config)
            .secret_outputs
            .max_refs_per_principal = 4;
        let response = runtime
            .invoke_owned_json(
                context(identity.clone()),
                request(reference.clone()),
                InvocationControl::default(),
            )
            .await;
        assert_eq!(response.status, 200, "{:?}", response.envelope);
        assert_eq!(
            provider.inputs.lock().unwrap().as_slice(),
            &["literal", provider.token.as_str()]
        );
        let descriptor = Arc::make_mut(
            Arc::make_mut(&mut runtime.services)
                .get_mut("fake")
                .unwrap(),
        );
        descriptor.actions[0].input_schema["properties"]["message"]["maxLength"] = json!(7);
        let response = runtime
            .invoke_owned_json(
                context(identity.clone()),
                request(reference.clone()),
                InvocationControl::default(),
            )
            .await;
        assert_eq!(
            response.envelope.reason_code,
            Some(ReasonCode::InputInvalid.into())
        );
        assert_eq!(provider.calls.load(Ordering::SeqCst), 2);
        let mut policy = (*runtime.config).clone();
        policy.policy.grants.clear();
        runtime
            .policy_snapshot
            .store(Arc::new(PolicySnapshot::from_config(&policy, 2)));
        let response = runtime
            .invoke_owned_json(
                context(identity),
                request(reference),
                InvocationControl::default(),
            )
            .await;
        assert_eq!(
            response.envelope.reason_code,
            Some(ReasonCode::ServiceActionDenied.into())
        );
        assert_eq!(provider.calls.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn undeclared_reference_input_never_reaches_provider() {
        let (_dir, runtime, identity, provider) = fixture(crate::SecretOutputMode::Raw, 128, false);
        let request = InvokeRequest::new(
            json!({"project":{"secretRef":format!("sr_{}","a".repeat(43))},"message":"literal"}),
        );
        let response = runtime
            .invoke_owned_json(context(identity), request, InvocationControl::default())
            .await;
        assert_eq!(
            response.envelope.reason_code,
            Some(ReasonCode::InputInvalid.into())
        );
        assert_eq!(provider.calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn duplicated_sidecar_secrets_are_never_returned_audited_or_persisted() {
        for mode in [
            crate::SecretOutputMode::Reference,
            crate::SecretOutputMode::Raw,
        ] {
            for leak in 1..=3 {
                let (dir, runtime, identity, provider) =
                    fixture_with_secret(mode, 128, false, "synthetic-\"token\n-sensitive");
                provider.leak.store(leak, Ordering::SeqCst);
                let response = runtime
                    .invoke_owned_json(
                        context(identity.clone()),
                        request(json!("literal")),
                        InvocationControl::default(),
                    )
                    .await;
                assert_eq!(
                    response.envelope.reason_code,
                    Some(ReasonCode::SecretCaptureFailed.into())
                );
                let result = response.envelope.result.unwrap();
                assert_eq!(result["retrySafe"], false);
                assert_eq!(result["executionState"], "completed");
                assert!(result.get("accessToken").is_none());
                assert!(result.get("accidentalCopy").is_none());
                assert!(!result.to_string().contains("synthetic"));
                let audit = fs::read_to_string(dir.path().join("audit.jsonl")).unwrap();
                assert!(!audit.contains("synthetic"));
                if mode == crate::SecretOutputMode::Reference {
                    let origin = runtime
                        .secret_reference_origin(
                            &identity,
                            &ExecutionContext::new("default").unwrap(),
                            None,
                        )
                        .unwrap();
                    let receipt = runtime
                        .managed_store
                        .as_ref()
                        .unwrap()
                        .secret_reference_receipt(
                            runtime.credential_key_ring.as_ref().unwrap(),
                            result["secretReceipt"]["receiptId"].as_str().unwrap(),
                            |conn, stored| {
                                runtime.check_secret_reference_owner_conn(conn, stored, &origin)
                            },
                        )
                        .unwrap();
                    assert_eq!(receipt.outcome, "capture_failed");
                    assert!(!receipt.metadata.to_string().contains("synthetic"));
                    assert!(receipt.metadata.get("accessToken").is_none());
                }
            }
        }
    }

    #[tokio::test]
    async fn ordinary_json_secret_without_sidecar_is_discarded_entirely() {
        let (_dir, runtime, _identity, _provider) =
            fixture(crate::SecretOutputMode::Raw, 128, false);
        let prepared = PreparedSecretOutputs {
            descriptors: vec![SecretOutputDescriptor::new("/result/issuedToken", 128)],
            ..Default::default()
        };
        let result = ProviderResult::new(
            json!({"issuedToken":"accidental-raw-secret","copy":"accidental-raw-secret","safeId":42}),
        );
        let error = runtime
            .complete_secret_outputs(&prepared, Ok(result))
            .unwrap_err();
        assert_eq!(error.reason_code(), ReasonCode::SecretCaptureFailed);
        let result = error.result.unwrap();
        assert!(result.get("safeId").is_none());
        assert!(!result.to_string().contains("accidental"));
        assert_eq!(result["retrySafe"], false);
    }

    #[tokio::test]
    async fn uncontaminated_error_retains_canonical_mutation_receipt_fields() {
        let (_dir, runtime, _identity, _provider) =
            fixture(crate::SecretOutputMode::Raw, 128, false);
        let prepared = PreparedSecretOutputs {
            descriptors: vec![SecretOutputDescriptor::new("/result/issuedToken", 128)],
            ..Default::default()
        };
        prepared.mark_dispatched();
        let error = ProviderError::error(
            ReasonCode::MutationVerificationFailed,
            "mutation response could not be verified",
        )
        .with_result(json!({"otherSensitiveData":"not retained"}))
        .with_mutation_receipt(MutationReceipt::applied_unverified(
            "mutation_response",
            json!({"tokenId":10,"userId":70}),
        ))
        .with_object_ids(json!({"tokenId":10,"userId":70}));
        let error = runtime
            .complete_secret_outputs(&prepared, Err(error))
            .unwrap_err();
        assert_eq!(error.reason_code(), ReasonCode::MutationVerificationFailed);
        let result = error.result.unwrap();
        assert_eq!(result["mutationStatus"], "applied_unverified");
        assert_eq!(result["verificationStage"], "mutation_response");
        assert_eq!(result["safeLocators"], json!({"tokenId":10,"userId":70}));
        assert_eq!(result["retrySafe"], false);
        assert!(result.get("otherSensitiveData").is_none());
    }

    #[test]
    fn receipt_projection_omits_sensitive_or_unbounded_mutation_fields() {
        let result = json!({"verificationStage":"mutation_response","safeLocators":{"tokenId":42,"sensitive":"must not be retained"}});
        let metadata = receipt_metadata(
            Some(&result),
            None,
            "unknown",
            &["/result/safeLocators/sensitive".into()],
        );
        assert_eq!(metadata["verificationStage"], "mutation_response");
        assert!(metadata.get("safeLocators").is_none());
        let oversized = json!({"safeLocators":{"tokenId":42,"large":"x".repeat(513)}});
        assert!(
            receipt_metadata(Some(&oversized), None, "unknown", &[])
                .get("safeLocators")
                .is_none()
        );
        let ids = Value::Object(
            (0..32)
                .map(|index| (index.to_string(), json!("\\".repeat(256))))
                .collect(),
        );
        assert!(
            receipt_metadata(None, Some(&ids), "completed", &[])
                .get("objectIds")
                .is_none()
        );
    }

    #[test]
    fn durable_metadata_keeps_only_bounded_safe_locators_and_known_outcomes() {
        let result = json!({"mutationStatus":"applied","otherSensitiveData":"not retained"});
        let ids = json!({"tokenId":42,"nested":{"unsafe":"ignored"},"large":"x".repeat(257)});
        let metadata = receipt_metadata(Some(&result), Some(&ids), "completed", &[]);
        assert_eq!(
            metadata,
            json!({"executionState":"completed","retrySafe":false,"mutationStatus":"applied","objectIds":{"tokenId":42}})
        );
    }

    #[tokio::test]
    async fn producer_discovery_hides_unsupported_origins_only_in_reference_mode() {
        let (_dir, mut runtime, identity, _provider) =
            fixture(crate::SecretOutputMode::Reference, 128, false);
        let visible = |runtime: &BrokerRuntime, identity: &IdentityContext| {
            runtime
                .service_discovery(identity, &ExecutionContext::new("default").unwrap(), "fake")
                .is_some_and(|service| {
                    service
                        .actions(None, None, None)
                        .unwrap()
                        .actions
                        .contains(&"echo".into())
                })
        };
        assert!(visible(&runtime, &identity));
        let mut static_identity = identity.clone();
        let source = static_identity.source.as_mut().unwrap();
        source.kind = "static".into();
        source.token_class = None;
        source.token_id = None;
        assert!(!visible(&runtime, &static_identity));
        Arc::make_mut(&mut runtime.config).secret_outputs.mode = crate::SecretOutputMode::Raw;
        assert!(visible(&runtime, &static_identity));
        let mut config = (*runtime.config).clone();
        // Admit anonymous discovery before testing the secret delivery filter;
        // the fixture otherwise requires managed authentication globally.
        config.identity.mode = "anonymous".into();
        Arc::make_mut(&mut runtime.config).identity.mode = "anonymous".into();
        // Reuse the fake fixture's resource grant for the anonymous caller.
        config.policy.grants = super::super::tests::base_fake_config().policy.grants;
        runtime
            .policy_snapshot
            .store(Arc::new(PolicySnapshot::from_config(&config, 3)));
        assert!(visible(&runtime, &IdentityContext::anonymous()));
        Arc::make_mut(&mut runtime.config).secret_outputs.mode = crate::SecretOutputMode::Reference;
        assert!(!visible(&runtime, &IdentityContext::anonymous()));
        assert_eq!(runtime.api_services_all()[0].actions.len(), 1);
    }

    #[tokio::test]
    async fn error_with_raw_declared_output_discards_all_provider_diagnostics() {
        let (_dir, runtime, _identity, _provider) =
            fixture(crate::SecretOutputMode::Raw, 128, false);
        let prepared = PreparedSecretOutputs {
            descriptors: vec![SecretOutputDescriptor::new("/result/issuedToken", 128)],
            ..Default::default()
        };
        prepared.mark_dispatched();
        let error =
            ProviderError::error(ReasonCode::UpstreamProtocolFailed, "raw-token in message")
                .with_result(json!({"issuedToken":"raw-token","copy":"raw-token"}))
                .with_audit(json!({"copy":"raw-token"}))
                .with_object_ids(json!({"copy":"raw-token"}));
        let error = runtime
            .complete_secret_outputs(&prepared, Err(error))
            .unwrap_err();
        assert_eq!(error.reason_code(), ReasonCode::SecretCaptureFailed);
        assert!(!error.message.contains("raw-token"));
        assert!(
            !error
                .result
                .as_ref()
                .unwrap()
                .to_string()
                .contains("raw-token")
        );
        assert!(
            !error
                .audit
                .as_ref()
                .unwrap()
                .to_string()
                .contains("raw-token")
        );
        assert!(error.object_ids.is_none());
        assert_eq!(error.result.unwrap()["executionState"], "unknown");
    }

    #[test]
    fn undeclared_reference_shapes_are_rejected_before_scope_hooks() {
        let action = ActionDescriptor::new("send", "Send", json!({"type":"object"}));
        assert!(
            validate_reference_inputs(
                &action,
                &json!({"anything":[{"secretRef":format!("sr_{}","a".repeat(43))}]})
            )
            .is_err()
        );
        assert!(validate_reference_inputs(&action, &json!({"ordinary":"value"})).is_ok());
        assert!(
            validate_reference_inputs(&action, &json!({"envFrom":[{"secretRef":{"name":"db"}}]}))
                .is_ok()
        );
        assert!(
            validate_reference_inputs(&action, &json!({"secretRef":"ordinary-provider-name"}))
                .is_ok()
        );
        assert!(
            validate_reference_inputs(
                &action,
                &json!({"secretRef":format!("sr_{}","a".repeat(43)),"extra":"field"})
            )
            .is_err()
        );
    }

    #[test]
    fn bare_capabilities_are_rejected_everywhere_except_strict_declared_objects() {
        let action = ActionDescriptor::new("send", "Send", json!({"type":"object"}));
        let handle = format!("sr_{}", "a".repeat(43));
        for input in [
            json!({"ordinary": &handle}),
            json!({"nested": [{"ordinary": &handle}]}),
            json!({"nested": [&handle]}),
            json!({handle.clone(): "ordinary"}),
        ] {
            assert!(validate_reference_inputs(&action, &input).is_err());
        }
        assert!(validate_reference_inputs(&action, &json!({"ordinary":"sr_short"})).is_ok());
        let action = ActionDescriptor::new(
            "send",
            "Send",
            json!({"type":"object","properties":{"token":{"type":"string"}}}),
        )
        .secret_input(SecretInputDescriptor::new("/inputs/token"));
        assert!(
            validate_reference_inputs(&action, &json!({"token":{"secretRef": &handle}})).is_ok()
        );
        assert!(
            validate_reference_inputs(
                &action,
                &json!({"token":{"secretRef": &handle,"expiresAt":"2026-10-17T12:00:00Z"}})
            )
            .is_ok()
        );
        assert!(
            validate_reference_inputs(
                &action,
                &json!({"token":{"secretRef": &handle,"extra":"field"}})
            )
            .is_err()
        );
    }

    #[tokio::test]
    async fn bare_capability_at_ordinary_input_never_reaches_provider() {
        let (_dir, runtime, identity, provider) = fixture(crate::SecretOutputMode::Raw, 128, false);
        let response = runtime
            .invoke_owned_json(
                context(identity),
                InvokeRequest::new(
                    json!({"project":format!("sr_{}", "a".repeat(43)),"message":"literal"}),
                ),
                InvocationControl::default(),
            )
            .await;
        assert_eq!(
            response.envelope.reason_code,
            Some(ReasonCode::InputInvalid.into())
        );
        assert_eq!(provider.calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn literal_broker_capability_at_declared_input_never_reaches_provider() {
        let (_dir, runtime, identity, provider) = fixture(crate::SecretOutputMode::Raw, 128, false);
        let response = runtime
            .invoke_owned_json(
                context(identity),
                request(json!(format!("sr_{}", "a".repeat(43)))),
                InvocationControl::default(),
            )
            .await;
        assert_eq!(
            response.envelope.reason_code,
            Some(ReasonCode::InputInvalid.into())
        );
        assert_eq!(provider.calls.load(Ordering::SeqCst), 0);
        let action = runtime.action_descriptor("fake", "echo").unwrap();
        assert!(
            validate_reference_inputs(
                action,
                &json!({"project":"TEST","message":{"secretRef":{"name":"db"}}})
            )
            .is_err()
        );
        assert!(
            validate_reference_inputs(
                action,
                &json!({"project":"TEST","message":"ordinary-secret-literal"})
            )
            .is_ok()
        );
    }

    #[test]
    fn output_pointer_helpers_do_not_traverse_arrays() {
        let mut value = json!({"nested":[{}]});
        assert!(!insert_pointer(
            &mut value,
            "/nested/0/token",
            json!("secret")
        ));
        assert!(!pointer_parent_is_object(&value, "/nested/0/token"));
        let mut value = json!({"a/b":{"~token":1}});
        assert!(insert_pointer(&mut value, "/a~1b/~0token", json!(2)));
        assert_eq!(value["a/b"]["~token"], 2);
    }
}
