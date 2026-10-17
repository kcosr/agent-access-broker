//! Durable temporary secret capture and the atomic credential-storage sink.
//!
//! References are reusable but never bearer authority by themselves. Every read
//! requires a host authorization callback inside the same transaction. Plaintext
//! and capabilities have no Debug or general serialization implementation.
use super::*;
use crate::runtime::secret_reference_identity::SecretReferenceOrigin;
use std::sync::atomic::{AtomicU8, Ordering};
use zeroize::{Zeroize, Zeroizing};

const MAX_ORIGIN_BYTES: usize = 16 * 1024;
const MAX_METADATA_BYTES: usize = 16 * 1024;
const MAX_OUTPUTS: usize = 64;
const MAX_OUTPUT_BYTES: usize = 1024 * 1024;

#[derive(Debug, Clone)]
pub(crate) struct SecretReferenceLimits {
    pub ttl_seconds: u64,
    pub max_refs_per_principal: u64,
    pub max_refs_total: u64,
    pub max_bytes_per_principal: u64,
    pub max_bytes_total: u64,
    pub receipt_retention_seconds: u64,
    pub max_receipts_total: u64,
}

pub(crate) struct SecretReservationRequest {
    pub broker_request_id: String,
    pub origin: SecretReferenceOrigin,
    pub execution_context: String,
    pub service: String,
    pub action: String,
    pub outputs: Vec<SecretOutputReservation>,
}

#[derive(Debug, Clone)]
pub(crate) struct SecretOutputReservation {
    pub pointer: String,
    pub max_bytes: usize,
}

pub(crate) struct SecretOutputCapture {
    pub pointer: String,
    pub value: String,
}
impl Drop for SecretOutputCapture {
    fn drop(&mut self) {
        self.value.zeroize();
    }
}

/// The only capability-bearing output. Its fields may be copied into an
/// authorized response, but the object itself never enters logs or receipts.
pub(crate) struct CapturedSecretReference {
    pub pointer: String,
    pub secret_ref: String,
    pub expires_at: String,
}

#[derive(Debug, Clone, Copy)]
pub(crate) enum SecretReservationOutcome {
    NotDispatched,
    Unknown,
    CaptureFailed,
}
impl SecretReservationOutcome {
    fn as_str(self) -> &'static str {
        match self {
            Self::NotDispatched => "not_dispatched",
            Self::Unknown => "unknown",
            Self::CaptureFailed => "capture_failed",
        }
    }
}

struct ReservedSlot {
    pointer: String,
    max_bytes: usize,
    secret_ref: String,
    reference_hash: String,
}
impl Drop for ReservedSlot {
    fn drop(&mut self) {
        self.secret_ref.zeroize();
    }
}

struct ReservationState {
    store: ManagedStore,
    receipt_id: String,
    expires_at: String,
    slots: Vec<ReservedSlot>,
    // 0 reserved, 1 provider dispatch admitted, 2 terminal outcome committed.
    state: AtomicU8,
}
impl Drop for ReservationState {
    fn drop(&mut self) {
        let outcome = match self.state.load(Ordering::Acquire) {
            0 => SecretReservationOutcome::NotDispatched,
            1 => SecretReservationOutcome::Unknown,
            _ => return,
        };
        // This drop owns no store lock. It covers cancellation after a blocking
        // reservation commit and before its join result reaches the caller.
        // If storage is unavailable, the fixed deadline still bounds retention.
        let _ = self.store.finish_secret_reservation_id(
            &self.receipt_id,
            outcome,
            &serde_json::json!({"retrySafe": false}),
        );
    }
}

#[derive(Clone)]
pub(crate) struct SecretOutputReservationBatch(Arc<ReservationState>);
impl std::fmt::Debug for SecretOutputReservationBatch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SecretOutputReservationBatch")
            .field("receipt_id", &self.0.receipt_id)
            .finish_non_exhaustive()
    }
}
impl SecretOutputReservationBatch {
    pub fn receipt_id(&self) -> &str {
        &self.0.receipt_id
    }
    pub fn expires_at(&self) -> &str {
        &self.0.expires_at
    }
    pub fn mark_dispatched(&self) {
        let _ = self
            .0
            .state
            .compare_exchange(0, 1, Ordering::AcqRel, Ordering::Acquire);
    }
}

/// Non-capability provenance suitable for a management completion audit.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SecretReferenceUse {
    pub receipt_id: String,
    pub origin: Value,
    pub service: String,
    pub action: String,
    pub pointer: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SecretCredentialWriteResult {
    pub credential: CredentialMetadata,
    pub references: Vec<SecretReferenceUse>,
}

/// Outcome evidence contains no reference capability and no secret value.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct SecretReferenceReceipt {
    pub receipt_id: String,
    pub broker_request_id: String,
    pub principal: String,
    pub service: String,
    pub action: String,
    pub created_at: String,
    pub expires_at: String,
    pub outcome: String,
    pub metadata: Value,
}

struct ReceiptRow {
    receipt: SecretReferenceReceipt,
    execution_context: String,
    retain_until: String,
    origin_key_id: String,
    origin_nonce: Vec<u8>,
    origin_ciphertext: Vec<u8>,
}
struct MaterialRow {
    reference_hash: String,
    receipt_id: String,
    pointer: String,
    max_bytes: i64,
    state: String,
    key_id: Option<String>,
    nonce: Option<Vec<u8>>,
    ciphertext: Option<Vec<u8>>,
}

impl ManagedStore {
    pub(crate) fn reserve_secret_outputs(
        &self,
        ring: &CredentialKeyRing,
        request: SecretReservationRequest,
        limits: &SecretReferenceLimits,
        authorize: impl Fn(&Connection, &SecretReferenceOrigin) -> Result<(), ManagedStoreError>,
    ) -> Result<SecretOutputReservationBatch, ManagedStoreError> {
        validate_reservation(&request, limits)?;
        let now = Utc::now();
        let expires = now + Duration::seconds(limits.ttl_seconds as i64);
        let retain = expires + Duration::seconds(limits.receipt_retention_seconds as i64);
        let receipt_id = Uuid::new_v4().to_string();
        let mut row = ReceiptRow {
            receipt: SecretReferenceReceipt {
                receipt_id: receipt_id.clone(),
                broker_request_id: request.broker_request_id,
                principal: request.origin.principal().to_string(),
                service: request.service,
                action: request.action,
                created_at: normalized_timestamp(now),
                expires_at: normalized_timestamp(expires),
                outcome: "reserved".into(),
                metadata: serde_json::json!({}),
            },
            execution_context: request.execution_context,
            retain_until: normalized_timestamp(retain),
            origin_key_id: ring.active_key_id().to_string(),
            origin_nonce: Vec::new(),
            origin_ciphertext: Vec::new(),
        };
        let origin = Zeroizing::new(request.origin.encode()?);
        if origin.len() > MAX_ORIGIN_BYTES {
            return Err(input_invalid("secret reference origin exceeds its limit"));
        }
        let encrypted = encrypt_bytes(ring, &row.origin_key_id, &origin_aad(&row), &origin)?;
        row.origin_nonce = encrypted.nonce;
        row.origin_ciphertext = encrypted.ciphertext;
        let slots = request
            .outputs
            .into_iter()
            .map(|output| {
                let mut random = [0_u8; 32];
                OsRng.fill_bytes(&mut random);
                let secret_ref = format!("sr_{}", URL_SAFE_NO_PAD.encode(random));
                ReservedSlot {
                    pointer: output.pointer,
                    max_bytes: output.max_bytes,
                    reference_hash: sha256_hex(secret_ref.as_bytes()),
                    secret_ref,
                }
            })
            .collect::<Vec<_>>();
        let mut conn = self.connection.lock().unwrap();
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sql_unavailable)?;
        authorize(&tx, &request.origin)?;
        cleanup_conn(&tx, &row.receipt.created_at)?;
        check_capacity(&tx, &row.receipt.principal, &slots, limits)?;
        tx.execute(
            "INSERT INTO secret_reference_receipts(receipt_id,broker_request_id,principal_id,execution_context,service,action,created_at,expires_at,retain_until,outcome,metadata_json,origin_key_id,origin_nonce,origin_ciphertext) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,'reserved','{}',?10,?11,?12)",
            params![receipt_id,row.receipt.broker_request_id,row.receipt.principal,row.execution_context,row.receipt.service,row.receipt.action,row.receipt.created_at,row.receipt.expires_at,row.retain_until,row.origin_key_id,row.origin_nonce,row.origin_ciphertext],
        ).map_err(sql_unavailable)?;
        for slot in &slots {
            tx.execute(
                "INSERT INTO secret_reference_material(reference_hash,receipt_id,output_pointer,max_bytes,charged_bytes,state) VALUES(?1,?2,?3,?4,?4,'reserved')",
                params![slot.reference_hash,receipt_id,slot.pointer,slot.max_bytes as i64],
            ).map_err(sql_unavailable)?;
        }
        tx.commit().map_err(sql_unavailable)?;
        Ok(SecretOutputReservationBatch(Arc::new(ReservationState {
            store: self.clone(),
            receipt_id,
            expires_at: row.receipt.expires_at,
            slots,
            state: AtomicU8::new(0),
        })))
    }

    pub(crate) fn capture_secret_outputs(
        &self,
        ring: &CredentialKeyRing,
        batch: &SecretOutputReservationBatch,
        captures: Vec<SecretOutputCapture>,
        safe_metadata: Value,
    ) -> Result<Vec<CapturedSecretReference>, ManagedStoreError> {
        let mut seen = BTreeSet::new();
        for capture in &captures {
            let slot = batch
                .0
                .slots
                .iter()
                .find(|slot| slot.pointer == capture.pointer)
                .ok_or_else(|| input_invalid("captured secret output was not reserved"))?;
            if !seen.insert(&capture.pointer)
                || capture.value.is_empty()
                || capture.value.len() > slot.max_bytes
            {
                return Err(input_invalid(
                    "captured secret output is invalid or exceeds its reservation",
                ));
            }
        }
        // Provider metadata must never prevent retention of an already-issued
        // secret. Omit unsafe evidence while preserving the completed capture.
        let metadata = if captures
            .iter()
            .any(|capture| metadata_contains_secret(&safe_metadata, &capture.value))
        {
            omitted_metadata("completed")
        } else {
            metadata_json(&safe_metadata).unwrap_or_else(|_| omitted_metadata("completed"))
        };
        let mut conn = self.connection.lock().unwrap();
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sql_unavailable)?;
        let receipt = receipt_row(&tx, batch.receipt_id())?;
        if receipt.receipt.outcome != "reserved" {
            return Err(ManagedStoreError::SecretReferenceStateConflict);
        }
        if timestamp_is_past(Some(&receipt.receipt.expires_at)) {
            return Err(ManagedStoreError::SecretReferenceExpired);
        }
        let mut result = Vec::new();
        for capture in &captures {
            let slot = batch
                .0
                .slots
                .iter()
                .find(|slot| slot.pointer == capture.pointer)
                .expect("checked reservation");
            let mut material = material_row(&tx, &slot.reference_hash)?;
            if material.state != "reserved"
                || material.receipt_id != batch.receipt_id()
                || material.pointer != slot.pointer
            {
                return Err(ManagedStoreError::SecretReferenceStateConflict);
            }
            material.key_id = Some(ring.active_key_id().into());
            let encrypted = encrypt_bytes(
                ring,
                ring.active_key_id(),
                &material_aad(&receipt, &material)?,
                capture.value.as_bytes(),
            )?;
            tx.execute(
                "UPDATE secret_reference_material SET state='captured',charged_bytes=?2,key_id=?3,nonce=?4,ciphertext=?5 WHERE reference_hash=?1 AND state='reserved'",
                params![slot.reference_hash,capture.value.len() as i64,encrypted.key_id,encrypted.nonce,encrypted.ciphertext],
            ).map_err(sql_unavailable)?;
            result.push(CapturedSecretReference {
                pointer: slot.pointer.clone(),
                secret_ref: slot.secret_ref.clone(),
                expires_at: receipt.receipt.expires_at.clone(),
            });
        }
        // Optional outputs that did not materialize consume no capacity.
        tx.execute("UPDATE secret_reference_material SET state='released',charged_bytes=0 WHERE receipt_id=?1 AND state='reserved'", [batch.receipt_id()]).map_err(sql_unavailable)?;
        tx.execute("UPDATE secret_reference_receipts SET outcome='captured',metadata_json=?2 WHERE receipt_id=?1", params![batch.receipt_id(),metadata]).map_err(sql_unavailable)?;
        tx.commit().map_err(sql_unavailable)?;
        batch.0.state.store(2, Ordering::Release);
        Ok(result)
    }

    pub(crate) fn finish_secret_reservation(
        &self,
        batch: &SecretOutputReservationBatch,
        outcome: SecretReservationOutcome,
        safe_metadata: Value,
    ) -> Result<(), ManagedStoreError> {
        self.finish_secret_reservation_id(batch.receipt_id(), outcome, &safe_metadata)?;
        batch.0.state.store(2, Ordering::Release);
        Ok(())
    }

    fn finish_secret_reservation_id(
        &self,
        receipt_id: &str,
        outcome: SecretReservationOutcome,
        safe_metadata: &Value,
    ) -> Result<(), ManagedStoreError> {
        let metadata = metadata_json(safe_metadata).unwrap_or_else(|_| {
            omitted_metadata(match outcome {
                SecretReservationOutcome::NotDispatched => "not_dispatched",
                SecretReservationOutcome::CaptureFailed => "completed",
                SecretReservationOutcome::Unknown => "unknown",
            })
        });
        let mut conn = self.connection.lock().unwrap();
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sql_unavailable)?;
        // Never erase a successfully captured value after a late response/audit
        // failure. Only an unfinished reservation can transition here.
        tx.execute("UPDATE secret_reference_receipts SET outcome=CASE WHEN outcome='expired' THEN 'expired' ELSE ?2 END,metadata_json=?3 WHERE receipt_id=?1 AND (outcome='reserved' OR (outcome='expired' AND metadata_json='{}'))", params![receipt_id,outcome.as_str(),metadata]).map_err(sql_unavailable)?;
        tx.execute("UPDATE secret_reference_material SET state='released',charged_bytes=0 WHERE receipt_id=?1 AND state='reserved'", [receipt_id]).map_err(sql_unavailable)?;
        tx.commit().map_err(sql_unavailable)?;
        Ok(())
    }

    pub(crate) fn resolve_secret_reference(
        &self,
        ring: &CredentialKeyRing,
        reference: &str,
        authorize: impl Fn(&Connection, &SecretReferenceOrigin) -> Result<(), ManagedStoreError>,
    ) -> Result<String, ManagedStoreError> {
        let mut conn = self.connection.lock().unwrap();
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sql_unavailable)?;
        let (value, _) = resolve_conn(&tx, ring, reference, &authorize)?;
        tx.commit().map_err(sql_unavailable)?;
        Ok(value)
    }

    #[cfg(test)]
    pub(crate) fn secret_reference_receipt(
        &self,
        ring: &CredentialKeyRing,
        receipt_id: &str,
        authorize: impl Fn(&Connection, &SecretReferenceOrigin) -> Result<(), ManagedStoreError>,
    ) -> Result<SecretReferenceReceipt, ManagedStoreError> {
        validate_uuid_id(receipt_id, "receiptId")?;
        let mut conn = self.connection.lock().unwrap();
        let tx = conn.transaction().map_err(sql_unavailable)?;
        let row = receipt_row(&tx, receipt_id)?;
        let origin = decrypt_origin(ring, &row)?;
        authorize(&tx, &origin)?;
        let mut result = row.receipt;
        if matches!(result.outcome.as_str(), "reserved" | "captured")
            && timestamp_is_past(Some(&result.expires_at))
        {
            result.outcome = "expired".into();
        }
        tx.commit().map_err(sql_unavailable)?;
        Ok(result)
    }

    /// Resolve references only in declared credential secret fields.
    /// Write authority is checked for literals and references alike. Origin
    /// authority is checked only when resolving a reference. Callbacks must not
    /// acquire this store's lock again; they share the durable write transaction.
    pub(crate) fn upsert_user_credential_with_secret_references(
        &self,
        ring: &CredentialKeyRing,
        mut request: CredentialWriteRequest,
        purpose: CredentialManagementPurpose,
        authorize_write: impl Fn(&Connection) -> Result<(), ManagedStoreError>,
        authorize_origin: impl Fn(&Connection, &SecretReferenceOrigin) -> Result<(), ManagedStoreError>,
    ) -> Result<SecretCredentialWriteResult, ManagedStoreError> {
        validate_credential_write_request(&request)?;
        validate_credential_metadata(&request.metadata)?;
        let object = request
            .secret
            .as_object()
            .ok_or_else(|| input_invalid("credential secret must be an object"))?;
        let reference = match object.get("token") {
            Some(Value::Object(reference)) => Some(parse_reference_input(reference)?),
            Some(Value::String(token)) if reference_hash(token).is_ok() => {
                return Err(input_invalid(
                    "secret reference handles must use a secretRef object",
                ));
            }
            _ => None,
        };
        // Unsupported fields cannot hide nested reference envelopes. The
        // ordinary credential validator checks required and unknown fields.
        if object
            .iter()
            .any(|(name, value)| name != "token" && value.is_object())
        {
            return Err(input_invalid(
                "secret references are accepted only in the token field",
            ));
        }
        let mut conn = self.connection.lock().unwrap();
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sql_unavailable)?;
        purpose.check_active_owner(&tx, &request.owner_principal_id)?;
        authorize_write(&tx)?;
        let mut references = Vec::new();
        if let Some(reference) = reference {
            let (value, usage) = resolve_conn(&tx, ring, &reference, &authorize_origin)?;
            request.secret["token"] = Value::String(value);
            references.push(usage);
        }
        let credential = upsert_user_credential_conn(&tx, ring, request, purpose)?;
        tx.commit().map_err(sql_unavailable)?;
        Ok(SecretCredentialWriteResult {
            credential,
            references,
        })
    }

    /// Expiry is enforced on reads even when this maintenance pass has not run.
    pub(crate) fn cleanup_secret_references(&self) -> Result<u64, ManagedStoreError> {
        let mut conn = self.connection.lock().unwrap();
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sql_unavailable)?;
        let changed = cleanup_conn(&tx, &normalized_now_string())?;
        tx.commit().map_err(sql_unavailable)?;
        Ok(changed)
    }

    /// The host must own the store's exclusive process state lock before a
    /// cold start. Reload candidates share live operations and must pass false.
    pub(crate) fn prepare_secret_references_for_runtime(
        &self,
        cold_start: bool,
    ) -> Result<(), ManagedStoreError> {
        let mut conn = self.connection.lock().unwrap();
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sql_unavailable)?;
        if cold_start {
            // No operation from the previous process can finish. Dispatch may
            // already have happened, so keep unknown, non-retryable evidence
            // while freeing capacity without ever creating a usable handle.
            tx.execute(
                "UPDATE secret_reference_material SET state='released',charged_bytes=0
                 WHERE state='reserved' AND receipt_id IN
                 (SELECT receipt_id FROM secret_reference_receipts WHERE outcome='reserved')",
                [],
            )
            .map_err(sql_unavailable)?;
            tx.execute(
                "UPDATE secret_reference_receipts SET outcome='unknown',metadata_json=?1 WHERE outcome='reserved'",
                [serde_json::json!({"executionState":"unknown","retrySafe":false}).to_string()],
            )
            .map_err(sql_unavailable)?;
        }
        cleanup_conn(&tx, &normalized_now_string())?;
        tx.commit().map_err(sql_unavailable)?;
        Ok(())
    }
}

fn validate_reservation(
    request: &SecretReservationRequest,
    limits: &SecretReferenceLimits,
) -> Result<(), ManagedStoreError> {
    validate_principal_id(request.origin.principal())?;
    if request.broker_request_id.is_empty()
        || request.broker_request_id.len() > 256
        || !is_service_name(&request.service)
        || request.action.is_empty()
        || request.action.len() > 256
        || !is_valid_execution_context_value(&request.execution_context)
        || request.outputs.is_empty()
        || request.outputs.len() > MAX_OUTPUTS
        || !(1..=86400).contains(&limits.ttl_seconds)
        || limits.receipt_retention_seconds > 30 * 86400
        || [
            limits.max_refs_per_principal,
            limits.max_refs_total,
            limits.max_bytes_per_principal,
            limits.max_bytes_total,
            limits.max_receipts_total,
        ]
        .contains(&0)
    {
        return Err(input_invalid("secret reservation settings are invalid"));
    }
    let mut pointers = BTreeSet::new();
    for output in &request.outputs {
        if !output.pointer.starts_with("/result/")
            || output.pointer.len() > 1024
            || output.max_bytes == 0
            || output.max_bytes > MAX_OUTPUT_BYTES
            || !pointers.insert(&output.pointer)
        {
            return Err(input_invalid("secret output reservation is invalid"));
        }
    }
    Ok(())
}

fn check_capacity(
    conn: &Connection,
    principal: &str,
    slots: &[ReservedSlot],
    limits: &SecretReferenceLimits,
) -> Result<(), ManagedStoreError> {
    let (total_count,total_bytes,own_count,own_bytes): (i64,i64,i64,i64) = conn.query_row(
        "SELECT COUNT(*),COALESCE(SUM(m.charged_bytes),0),COALESCE(SUM(CASE WHEN r.principal_id=?1 THEN 1 ELSE 0 END),0),COALESCE(SUM(CASE WHEN r.principal_id=?1 THEN m.charged_bytes ELSE 0 END),0) FROM secret_reference_material m JOIN secret_reference_receipts r USING(receipt_id) WHERE m.state IN ('reserved','captured')",
        [principal], |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?)),
    ).map_err(sql_unavailable)?;
    let count = slots.len() as u64;
    let bytes = slots.iter().map(|slot| slot.max_bytes as u64).sum::<u64>();
    let (receipts, own_receipts): (i64, i64) = conn
        .query_row(
            "SELECT COUNT(*),COALESCE(SUM(CASE WHEN principal_id=?1 THEN 1 ELSE 0 END),0) FROM secret_reference_receipts",
            [principal],
            |row| Ok((row.get(0)?,row.get(1)?)),
        )
        .map_err(sql_unavailable)?;
    if receipts as u64 >= limits.max_receipts_total
        || own_receipts as u64 >= limits.max_refs_per_principal.saturating_mul(10)
        || (total_count as u64).saturating_add(count) > limits.max_refs_total
        || (own_count as u64).saturating_add(count) > limits.max_refs_per_principal
        || (total_bytes as u64).saturating_add(bytes) > limits.max_bytes_total
        || (own_bytes as u64).saturating_add(bytes) > limits.max_bytes_per_principal
    {
        return Err(ManagedStoreError::SecretReferenceCapacity);
    }
    Ok(())
}

fn metadata_contains_secret(value: &Value, secret: &str) -> bool {
    match value {
        Value::String(value) => value.contains(secret),
        Value::Object(object) => object
            .iter()
            .any(|(key, value)| key.contains(secret) || metadata_contains_secret(value, secret)),
        Value::Array(array) => array
            .iter()
            .any(|value| metadata_contains_secret(value, secret)),
        _ => false,
    }
}

fn metadata_json(value: &Value) -> Result<String, ManagedStoreError> {
    fn contains_capability(value: &str) -> bool {
        value.match_indices("sr_").any(|(start, _)| {
            value
                .get(start..start + 46)
                .is_some_and(|candidate| reference_hash(candidate).is_ok())
        })
    }
    fn contains_reference(value: &Value) -> bool {
        match value {
            Value::String(value) => contains_capability(value),
            Value::Object(object) => object
                .iter()
                .any(|(key, value)| contains_capability(key) || contains_reference(value)),
            Value::Array(array) => array.iter().any(contains_reference),
            _ => false,
        }
    }
    let raw =
        serde_json::to_string(value).map_err(|_| input_invalid("receipt metadata is invalid"))?;
    if !value.is_object() || raw.len() > MAX_METADATA_BYTES || contains_reference(value) {
        return Err(input_invalid(
            "receipt metadata is invalid or exceeds its limit",
        ));
    }
    Ok(raw)
}

fn omitted_metadata(execution_state: &str) -> String {
    serde_json::json!({
        "executionState":execution_state,"retrySafe":false,"metadataOmitted":true
    })
    .to_string()
}

fn reference_hash(reference: &str) -> Result<String, ManagedStoreError> {
    let raw = reference
        .strip_prefix("sr_")
        .ok_or_else(|| input_invalid("secret reference is invalid"))?;
    if raw.len() != 43 {
        return Err(input_invalid("secret reference is invalid"));
    }
    let bytes = URL_SAFE_NO_PAD
        .decode(raw)
        .map_err(|_| input_invalid("secret reference is invalid"))?;
    if bytes.len() != 32 || URL_SAFE_NO_PAD.encode(&bytes) != raw {
        return Err(input_invalid("secret reference is invalid"));
    }
    Ok(sha256_hex(reference.as_bytes()))
}

fn parse_reference_input(
    object: &serde_json::Map<String, Value>,
) -> Result<String, ManagedStoreError> {
    if object
        .keys()
        .any(|key| key != "secretRef" && key != "expiresAt")
        || object
            .get("expiresAt")
            .is_some_and(|value| !value.is_string())
    {
        return Err(input_invalid("secret reference input is invalid"));
    }
    let reference = object
        .get("secretRef")
        .and_then(Value::as_str)
        .ok_or_else(|| input_invalid("secret reference input is invalid"))?;
    reference_hash(reference)?;
    Ok(reference.into())
}

fn resolve_conn(
    conn: &Connection,
    ring: &CredentialKeyRing,
    reference: &str,
    authorize: &impl Fn(&Connection, &SecretReferenceOrigin) -> Result<(), ManagedStoreError>,
) -> Result<(String, SecretReferenceUse), ManagedStoreError> {
    let material = material_row(conn, &reference_hash(reference)?)?;
    let receipt = receipt_row(conn, &material.receipt_id)?;
    let origin = decrypt_origin(ring, &receipt)?;
    authorize(conn, &origin)?;
    if timestamp_is_past(Some(&receipt.receipt.expires_at)) || material.state == "expired" {
        return Err(ManagedStoreError::SecretReferenceExpired);
    }
    if material.state != "captured" || receipt.receipt.outcome != "captured" {
        return Err(ManagedStoreError::SecretReferenceNotFound);
    }
    let value = decrypt_material(ring, &receipt, &material)?;
    let usage = SecretReferenceUse {
        receipt_id: receipt.receipt.receipt_id,
        origin: origin.audit_metadata(),
        service: receipt.receipt.service,
        action: receipt.receipt.action,
        pointer: material.pointer,
    };
    Ok((
        String::from_utf8(value.to_vec())
            .map_err(|_| ManagedStoreError::CredentialDecryptFailed)?,
        usage,
    ))
}

fn receipt_row(conn: &Connection, id: &str) -> Result<ReceiptRow, ManagedStoreError> {
    conn.query_row("SELECT receipt_id,broker_request_id,principal_id,execution_context,service,action,created_at,expires_at,retain_until,outcome,metadata_json,origin_key_id,origin_nonce,origin_ciphertext FROM secret_reference_receipts WHERE receipt_id=?1", [id], |row| {
        let metadata: String = row.get(10)?;
        Ok(ReceiptRow {
            receipt: SecretReferenceReceipt {
                receipt_id: row.get(0)?, broker_request_id: row.get(1)?, principal: row.get(2)?,
                service: row.get(4)?,action:row.get(5)?,created_at:row.get(6)?,expires_at:row.get(7)?,outcome:row.get(9)?,
                metadata:serde_json::from_str(&metadata).map_err(|e| rusqlite::Error::FromSqlConversionFailure(10,Type::Text,Box::new(e)))?,
            },
            execution_context:row.get(3)?,retain_until:row.get(8)?,origin_key_id:row.get(11)?,origin_nonce:row.get(12)?,origin_ciphertext:row.get(13)?,
        })
    }).optional().map_err(sql_unavailable)?.ok_or(ManagedStoreError::SecretReferenceNotFound)
}

fn material_row(conn: &Connection, hash: &str) -> Result<MaterialRow, ManagedStoreError> {
    conn.query_row("SELECT reference_hash,receipt_id,output_pointer,max_bytes,state,key_id,nonce,ciphertext FROM secret_reference_material WHERE reference_hash=?1",[hash],|row| Ok(MaterialRow {
        reference_hash:row.get(0)?,receipt_id:row.get(1)?,pointer:row.get(2)?,max_bytes:row.get(3)?,state:row.get(4)?,key_id:row.get(5)?,nonce:row.get(6)?,ciphertext:row.get(7)?,
    })).optional().map_err(sql_unavailable)?.ok_or(ManagedStoreError::SecretReferenceNotFound)
}

fn origin_aad(row: &ReceiptRow) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!([
        "agent-access/secret-reference-origin/v1",
        row.receipt.receipt_id,
        row.receipt.broker_request_id,
        row.receipt.principal,
        row.execution_context,
        row.receipt.service,
        row.receipt.action,
        row.receipt.created_at,
        row.receipt.expires_at,
        row.retain_until,
        row.origin_key_id,
    ]))
    .expect("fixed origin AAD serializes")
}
fn material_aad(receipt: &ReceiptRow, row: &MaterialRow) -> Result<Vec<u8>, ManagedStoreError> {
    let key = row
        .key_id
        .as_ref()
        .ok_or(ManagedStoreError::CredentialDecryptFailed)?;
    Ok(serde_json::to_vec(&serde_json::json!([
        "agent-access/secret-reference-material/v1",
        row.reference_hash,
        row.receipt_id,
        row.pointer,
        row.max_bytes,
        receipt.receipt.principal,
        receipt.execution_context,
        receipt.receipt.service,
        receipt.receipt.action,
        receipt.receipt.created_at,
        receipt.receipt.expires_at,
        key,
    ]))
    .expect("fixed material AAD serializes"))
}

fn encrypt_bytes(
    ring: &CredentialKeyRing,
    key: &str,
    aad: &[u8],
    plaintext: &[u8],
) -> Result<EncryptedSecret, ManagedStoreError> {
    let key_bytes = ring
        .keys
        .get(key)
        .ok_or_else(|| ManagedStoreError::EncryptionKeyMissing(key.into()))?;
    let cipher = Aes256Gcm::new_from_slice(key_bytes)
        .map_err(|_| ManagedStoreError::CredentialEncryptFailed)?;
    let mut nonce = [0_u8; 12];
    OsRng.fill_bytes(&mut nonce);
    let ciphertext = cipher
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| ManagedStoreError::CredentialEncryptFailed)?;
    Ok(EncryptedSecret {
        key_id: key.into(),
        nonce: nonce.to_vec(),
        ciphertext,
    })
}
fn decrypt_bytes(
    ring: &CredentialKeyRing,
    key: &str,
    nonce: &[u8],
    ciphertext: &[u8],
    aad: &[u8],
) -> Result<Zeroizing<Vec<u8>>, ManagedStoreError> {
    let key_bytes = ring
        .keys
        .get(key)
        .ok_or_else(|| ManagedStoreError::EncryptionKeyMissing(key.into()))?;
    let cipher = Aes256Gcm::new_from_slice(key_bytes)
        .map_err(|_| ManagedStoreError::CredentialDecryptFailed)?;
    let nonce: [u8; 12] = nonce
        .try_into()
        .map_err(|_| ManagedStoreError::CredentialDecryptFailed)?;
    Ok(Zeroizing::new(
        cipher
            .decrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: ciphertext,
                    aad,
                },
            )
            .map_err(|_| ManagedStoreError::CredentialDecryptFailed)?,
    ))
}
fn decrypt_origin(
    ring: &CredentialKeyRing,
    row: &ReceiptRow,
) -> Result<SecretReferenceOrigin, ManagedStoreError> {
    let plaintext = decrypt_bytes(
        ring,
        &row.origin_key_id,
        &row.origin_nonce,
        &row.origin_ciphertext,
        &origin_aad(row),
    )?;
    let origin = SecretReferenceOrigin::decode(&plaintext)?;
    if origin.principal() != row.receipt.principal {
        return Err(ManagedStoreError::CredentialDecryptFailed);
    }
    Ok(origin)
}
fn decrypt_material(
    ring: &CredentialKeyRing,
    receipt: &ReceiptRow,
    row: &MaterialRow,
) -> Result<Zeroizing<Vec<u8>>, ManagedStoreError> {
    let plaintext = decrypt_bytes(
        ring,
        row.key_id
            .as_deref()
            .ok_or(ManagedStoreError::CredentialDecryptFailed)?,
        row.nonce
            .as_deref()
            .ok_or(ManagedStoreError::CredentialDecryptFailed)?,
        row.ciphertext
            .as_deref()
            .ok_or(ManagedStoreError::CredentialDecryptFailed)?,
        &material_aad(receipt, row)?,
    )?;
    if plaintext.is_empty()
        || plaintext.len() > row.max_bytes as usize
        || std::str::from_utf8(&plaintext).is_err()
    {
        return Err(ManagedStoreError::CredentialDecryptFailed);
    }
    Ok(plaintext)
}

fn caller_contract_aad(caller: &str, generation: i64, active: bool, key: &str) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!([
        "agent-access/secret-reference-caller-contract/v1",
        caller,
        generation,
        active,
        key,
    ]))
    .expect("fixed caller contract AAD serializes")
}

pub(super) fn encrypt_caller_contract(
    ring: &CredentialKeyRing,
    key: &str,
    caller: &str,
    generation: i64,
    active: bool,
    contract: &[u8; 32],
) -> Result<EncryptedSecret, ManagedStoreError> {
    encrypt_bytes(
        ring,
        key,
        &caller_contract_aad(caller, generation, active, key),
        contract,
    )
}

pub(super) fn decrypt_caller_contract(
    ring: &CredentialKeyRing,
    key: &str,
    caller: &str,
    generation: i64,
    active: bool,
    nonce: &[u8],
    ciphertext: &[u8],
) -> Result<Zeroizing<Vec<u8>>, ManagedStoreError> {
    let plaintext = decrypt_bytes(
        ring,
        key,
        nonce,
        ciphertext,
        &caller_contract_aad(caller, generation, active, key),
    )?;
    if plaintext.len() != 32 {
        return Err(ManagedStoreError::CredentialDecryptFailed);
    }
    Ok(plaintext)
}

struct CallerContractRow {
    caller: String,
    key_id: String,
    nonce: Vec<u8>,
    ciphertext: Vec<u8>,
    generation: i64,
    active: bool,
}

fn caller_contract_rows(conn: &Connection) -> Result<Vec<CallerContractRow>, ManagedStoreError> {
    let mut statement = conn
        .prepare("SELECT caller,key_id,nonce,ciphertext,generation,active FROM secret_reference_caller_generations ORDER BY caller")
        .map_err(sql_unavailable)?;
    collect_rows(
        statement
            .query_map([], |row| {
                Ok(CallerContractRow {
                    caller: row.get(0)?,
                    key_id: row.get(1)?,
                    nonce: row.get(2)?,
                    ciphertext: row.get(3)?,
                    generation: row.get(4)?,
                    active: row.get(5)?,
                })
            })
            .map_err(sql_unavailable)?,
    )
}

fn cleanup_conn(conn: &Connection, now: &str) -> Result<u64, ManagedStoreError> {
    let expired=conn.execute("UPDATE secret_reference_material SET state='expired',charged_bytes=0,key_id=NULL,nonce=NULL,ciphertext=NULL WHERE state IN ('reserved','captured') AND receipt_id IN (SELECT receipt_id FROM secret_reference_receipts WHERE expires_at<=?1)",[now]).map_err(sql_unavailable)?;
    conn.execute("UPDATE secret_reference_receipts SET outcome='expired' WHERE outcome IN ('reserved','captured') AND expires_at<=?1",[now]).map_err(sql_unavailable)?;
    let pruned = conn
        .execute(
            "DELETE FROM secret_reference_receipts WHERE retain_until<=?1",
            [now],
        )
        .map_err(sql_unavailable)?;
    Ok((expired + pruned) as u64)
}

pub(super) fn validate_structure(conn: &Connection) -> Result<(), ManagedStoreError> {
    let expected = Connection::open_in_memory().map_err(sql_unavailable)?;
    for migration in MANAGED_STORE_MIGRATIONS {
        expected
            .execute_batch(migration.sql)
            .map_err(sql_unavailable)?;
        if migration.version == MANAGED_STORE_SECRET_REFERENCES_VERSION {
            break;
        }
    }
    compare_schema(conn, &expected)?;
    run_foreign_key_check(conn)?;
    run_quick_check(conn)?;
    identity_access::check_integrity(conn)?;
    check_secret_material_ready(conn, None)?;
    check_policy_revision_ready(conn)
}

pub(super) fn check_ready(
    conn: &Connection,
    ring: Option<&CredentialKeyRing>,
) -> Result<(), ManagedStoreError> {
    for row in caller_contract_rows(conn)? {
        let ring =
            ring.ok_or_else(|| ManagedStoreError::EncryptionKeyMissing(row.key_id.clone()))?;
        decrypt_caller_contract(
            ring,
            &row.key_id,
            &row.caller,
            row.generation,
            row.active,
            &row.nonce,
            &row.ciphertext,
        )?;
    }
    let ids = receipt_ids(conn)?;
    for id in ids {
        let row = receipt_row(conn, &id)?;
        let ring =
            ring.ok_or_else(|| ManagedStoreError::EncryptionKeyMissing(row.origin_key_id.clone()))?;
        decrypt_origin(ring, &row)?;
        metadata_json(&row.receipt.metadata)?;
        for hash in material_hashes(conn, &id)? {
            let material = material_row(conn, &hash)?;
            if material.state == "captured" {
                decrypt_material(ring, &row, &material)?;
            }
        }
    }
    Ok(())
}

pub(super) fn rewrap(
    conn: &mut Connection,
    ring: &CredentialKeyRing,
    from: &str,
    to: &str,
) -> Result<u64, ManagedStoreError> {
    let tx = conn.transaction().map_err(sql_unavailable)?;
    let mut count = 0;
    for row in caller_contract_rows(&tx)? {
        if row.key_id != from {
            continue;
        }
        let plaintext = decrypt_caller_contract(
            ring,
            from,
            &row.caller,
            row.generation,
            row.active,
            &row.nonce,
            &row.ciphertext,
        )?;
        let contract: &[u8; 32] = plaintext
            .as_slice()
            .try_into()
            .map_err(|_| ManagedStoreError::CredentialDecryptFailed)?;
        let encrypted =
            encrypt_caller_contract(ring, to, &row.caller, row.generation, row.active, contract)?;
        tx.execute("UPDATE secret_reference_caller_generations SET key_id=?2,nonce=?3,ciphertext=?4 WHERE caller=?1", params![row.caller,to,encrypted.nonce,encrypted.ciphertext]).map_err(sql_unavailable)?;
        count += 1;
    }
    for id in receipt_ids(&tx)? {
        let mut receipt = receipt_row(&tx, &id)?;
        if receipt.origin_key_id == from {
            let plaintext = decrypt_bytes(
                ring,
                from,
                &receipt.origin_nonce,
                &receipt.origin_ciphertext,
                &origin_aad(&receipt),
            )?;
            receipt.origin_key_id = to.into();
            let encrypted = encrypt_bytes(ring, to, &origin_aad(&receipt), &plaintext)?;
            tx.execute("UPDATE secret_reference_receipts SET origin_key_id=?2,origin_nonce=?3,origin_ciphertext=?4 WHERE receipt_id=?1",params![id,to,encrypted.nonce,encrypted.ciphertext]).map_err(sql_unavailable)?;
            count += 1;
        }
        for hash in material_hashes(&tx, &id)? {
            let mut material = material_row(&tx, &hash)?;
            if material.key_id.as_deref() == Some(from) {
                let plaintext = decrypt_material(ring, &receipt, &material)?;
                material.key_id = Some(to.into());
                let encrypted =
                    encrypt_bytes(ring, to, &material_aad(&receipt, &material)?, &plaintext)?;
                tx.execute("UPDATE secret_reference_material SET key_id=?2,nonce=?3,ciphertext=?4 WHERE reference_hash=?1",params![hash,to,encrypted.nonce,encrypted.ciphertext]).map_err(sql_unavailable)?;
                count += 1;
            }
        }
    }
    tx.commit().map_err(sql_unavailable)?;
    Ok(count)
}
fn receipt_ids(conn: &Connection) -> Result<Vec<String>, ManagedStoreError> {
    let mut statement = conn
        .prepare("SELECT receipt_id FROM secret_reference_receipts ORDER BY receipt_id")
        .map_err(sql_unavailable)?;
    collect_rows(
        statement
            .query_map([], |row| row.get(0))
            .map_err(sql_unavailable)?,
    )
}
fn material_hashes(conn: &Connection, receipt_id: &str) -> Result<Vec<String>, ManagedStoreError> {
    let mut statement=conn.prepare("SELECT reference_hash FROM secret_reference_material WHERE receipt_id=?1 ORDER BY reference_hash").map_err(sql_unavailable)?;
    collect_rows(
        statement
            .query_map([receipt_id], |row| row.get(0))
            .map_err(sql_unavailable)?,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const SECRET: &str = "gitlab-issued-token-private-sentinel";

    fn fixture() -> (tempfile::TempDir, ManagedStore, CredentialKeyRing) {
        let temp = tempfile::TempDir::new().unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
        }
        let store = ManagedStore::open(
            &ManagedStoreConfig {
                kind: "sqlite".into(),
                path: temp.path().join("store.sqlite").display().to_string(),
                auto_migrate: true,
                require_registered_principal_for_invocation: false,
            },
            ManagedStoreOpenMode::Startup,
        )
        .unwrap();
        let ring = CredentialKeyRing {
            active_key: "old".into(),
            keys: Arc::new(BTreeMap::from([
                ("old".into(), [7; 32]),
                ("new".into(), [8; 32]),
            ])),
        };
        for principal in ["alice", "destination"] {
            store
                .create_principal(PrincipalWriteRequest {
                    principal_id: principal.into(),
                    kind: "user".into(),
                    role: PrincipalRole::User,
                    self_service_enabled: Some(true),
                    display_name: None,
                    email: None,
                    external_subject: None,
                    created_by: "admin".into(),
                })
                .unwrap();
        }
        (temp, store, ring)
    }
    fn limits() -> SecretReferenceLimits {
        SecretReferenceLimits {
            ttl_seconds: 14400,
            max_refs_per_principal: 100,
            max_refs_total: 10000,
            max_bytes_per_principal: 1048576,
            max_bytes_total: 67108864,
            receipt_retention_seconds: 7 * 86400,
            max_receipts_total: 100000,
        }
    }
    fn origin(principal: &str) -> SecretReferenceOrigin {
        SecretReferenceOrigin::decode(&serde_json::to_vec(&json!({
            "version":1,"principal":principal,"execution_context":"internal",
            "authentication":{"kind":"broker_token","source":"tokens","header":"authorization","scheme":"Bearer","token_id":"00000000-0000-4000-8000-000000000001","verifier_binding":vec![8_u8;32]},
            "caller":null,
        })).unwrap()).unwrap()
    }
    fn request(principal: &str) -> SecretReservationRequest {
        SecretReservationRequest {
            broker_request_id: Uuid::new_v4().to_string(),
            origin: origin(principal),
            execution_context: "internal".into(),
            service: "gitlab".into(),
            action: "project_token.create".into(),
            outputs: vec![SecretOutputReservation {
                pointer: "/result/issuedToken".into(),
                max_bytes: 128,
            }],
        }
    }
    fn authorize_alice(
        _: &Connection,
        origin: &SecretReferenceOrigin,
    ) -> Result<(), ManagedStoreError> {
        if origin.principal() == "alice" {
            Ok(())
        } else {
            Err(ManagedStoreError::SecretReferenceDenied)
        }
    }
    fn capture(
        store: &ManagedStore,
        ring: &CredentialKeyRing,
        batch: &SecretOutputReservationBatch,
    ) -> CapturedSecretReference {
        batch.mark_dispatched();
        store
            .capture_secret_outputs(
                ring,
                batch,
                vec![SecretOutputCapture {
                    pointer: "/result/issuedToken".into(),
                    value: SECRET.into(),
                }],
                json!({"tokenId":42,"userId":123}),
            )
            .unwrap()
            .remove(0)
    }
    fn credential(reference: &str, owner: &str) -> CredentialWriteRequest {
        CredentialWriteRequest {
            owner_principal_id: owner.into(),
            service: "gitlab-connection".into(),
            name: "default".into(),
            profile: "gitlab-api-token".into(),
            credential_kind: "bearer_token".into(),
            secret: json!({"token":{"secretRef":reference,"expiresAt":"2099-01-01T00:00:00Z"}}),
            metadata: json!({}),
            actor: "admin".into(),
        }
    }

    #[test]
    fn capture_is_encrypted_reusable_and_survives_reopen() {
        let (temp, store, ring) = fixture();
        let batch = store
            .reserve_secret_outputs(&ring, request("alice"), &limits(), |_, _| Ok(()))
            .unwrap();
        let receipt_id = batch.receipt_id().to_string();
        let reference = capture(&store, &ring, &batch);
        assert_eq!(reference.secret_ref.len(), 46);
        for _ in 0..2 {
            assert_eq!(
                store
                    .resolve_secret_reference(&ring, &reference.secret_ref, authorize_alice)
                    .unwrap(),
                SECRET
            );
        }
        let receipt = store
            .secret_reference_receipt(&ring, &receipt_id, authorize_alice)
            .unwrap();
        assert_eq!(receipt.outcome, "captured");
        assert_eq!(receipt.metadata, json!({"tokenId":42,"userId":123}));
        let serialized = serde_json::to_string(&receipt).unwrap();
        assert!(!serialized.contains(SECRET));
        assert!(!serialized.contains(&reference.secret_ref));
        assert!(!format!("{batch:?}").contains(&reference.secret_ref));
        drop(batch);
        drop(store);
        for entry in fs::read_dir(temp.path()).unwrap() {
            let entry = entry.unwrap();
            if entry.path().is_file() {
                let bytes = fs::read(entry.path()).unwrap();
                assert!(
                    !bytes
                        .windows(SECRET.len())
                        .any(|value| value == SECRET.as_bytes())
                );
                assert!(
                    !bytes
                        .windows(reference.secret_ref.len())
                        .any(|value| value == reference.secret_ref.as_bytes())
                );
            }
        }
        let reopened = ManagedStore::open(
            &ManagedStoreConfig {
                kind: "sqlite".into(),
                path: temp.path().join("store.sqlite").display().to_string(),
                auto_migrate: false,
                require_registered_principal_for_invocation: false,
            },
            ManagedStoreOpenMode::Startup,
        )
        .unwrap();
        reopened.check_ready(Some(&ring)).unwrap();
        assert_eq!(
            reopened
                .resolve_secret_reference(&ring, &reference.secret_ref, authorize_alice)
                .unwrap(),
            SECRET
        );
    }

    #[test]
    fn migration_preserves_existing_credential_ciphertext_and_requires_opt_in() {
        let temp = tempfile::TempDir::new().unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
        }
        let mut config = ManagedStoreConfig {
            kind: "sqlite".into(),
            path: temp.path().join("store.sqlite").display().to_string(),
            auto_migrate: true,
            require_registered_principal_for_invocation: false,
        };
        let previous = ManagedStore::open_with_catalog(
            &config,
            ManagedStoreOpenMode::Startup,
            ManagedStoreMigrationCatalog {
                migrations: &MANAGED_STORE_MIGRATIONS[..MANAGED_STORE_MIGRATIONS.len() - 1],
            },
        )
        .unwrap();
        previous
            .create_principal(PrincipalWriteRequest {
                principal_id: "alice".into(),
                kind: "user".into(),
                role: PrincipalRole::User,
                self_service_enabled: Some(true),
                display_name: None,
                email: None,
                external_subject: None,
                created_by: "admin".into(),
            })
            .unwrap();
        let ring = CredentialKeyRing {
            active_key: "old".into(),
            keys: Arc::new(BTreeMap::from([("old".into(), [7; 32])])),
        };
        let mut request = credential("unused", "alice");
        request.secret = json!({"token":SECRET});
        previous
            .upsert_user_credential(&ring, request, CredentialManagementPurpose::Administrative)
            .unwrap();
        let snapshot = |store: &ManagedStore| {
            store.connection.lock().unwrap().query_row("SELECT hex(secret_ciphertext)||'|'||hex(secret_nonce)||'|'||key_id FROM credential_secret_material",[],|row|row.get::<_,String>(0)).unwrap()
        };
        let before = snapshot(&previous);
        drop(previous);
        config.auto_migrate = false;
        assert!(matches!(
            ManagedStore::open(&config, ManagedStoreOpenMode::Startup),
            Err(ManagedStoreError::MigrationRequired)
        ));
        config.auto_migrate = true;
        let migrated = ManagedStore::open(&config, ManagedStoreOpenMode::Startup).unwrap();
        assert!(migrated.migration_applied_this_open(MANAGED_STORE_SECRET_REFERENCES_VERSION));
        assert_eq!(snapshot(&migrated), before);
        migrated.check_ready(Some(&ring)).unwrap();
        assert_eq!(
            migrated.status().unwrap().schema_version,
            MANAGED_STORE_SECRET_REFERENCES_VERSION
        );
    }

    #[test]
    fn reservation_capacity_precedes_capture_and_optional_outputs_release_it() {
        let (_temp, store, ring) = fixture();
        let mut limited = limits();
        limited.max_refs_total = 2;
        limited.max_refs_per_principal = 2;
        limited.max_bytes_total = 256;
        let mut first = request("alice");
        first.outputs.push(SecretOutputReservation {
            pointer: "/result/optionalToken".into(),
            max_bytes: 128,
        });
        let batch = store
            .reserve_secret_outputs(&ring, first, &limited, |_, _| Ok(()))
            .unwrap();
        assert!(matches!(
            store.reserve_secret_outputs(&ring, request("alice"), &limited, |_, _| Ok(())),
            Err(ManagedStoreError::SecretReferenceCapacity)
        ));
        capture(&store, &ring, &batch);
        let next = store
            .reserve_secret_outputs(&ring, request("alice"), &limited, |_, _| Ok(()))
            .unwrap();
        drop(next);
        // Dropping a pre-dispatch reservation immediately releases its charge.
        store
            .reserve_secret_outputs(&ring, request("alice"), &limited, |_, _| Ok(()))
            .unwrap();
    }

    #[test]
    fn dropped_dispatched_reservation_keeps_unknown_nonretryable_receipt() {
        let (_temp, store, ring) = fixture();
        let batch = store
            .reserve_secret_outputs(&ring, request("alice"), &limits(), |_, _| Ok(()))
            .unwrap();
        let receipt_id = batch.receipt_id().to_string();
        batch.mark_dispatched();
        drop(batch);
        let receipt = store
            .secret_reference_receipt(&ring, &receipt_id, authorize_alice)
            .unwrap();
        assert_eq!(receipt.outcome, "unknown");
        assert_eq!(receipt.metadata["retrySafe"], false);
        assert_eq!(
            store
                .connection
                .lock()
                .unwrap()
                .query_row(
                    "SELECT SUM(charged_bytes) FROM secret_reference_material WHERE receipt_id=?1",
                    [receipt_id],
                    |row| row.get::<_, i64>(0)
                )
                .unwrap(),
            0
        );
    }

    #[test]
    fn capture_validation_is_atomic() {
        let (_temp, store, ring) = fixture();
        let batch = store
            .reserve_secret_outputs(&ring, request("alice"), &limits(), |_, _| Ok(()))
            .unwrap();
        let result = store.capture_secret_outputs(
            &ring,
            &batch,
            vec![
                SecretOutputCapture {
                    pointer: "/result/issuedToken".into(),
                    value: SECRET.into(),
                },
                SecretOutputCapture {
                    pointer: "/result/issuedToken".into(),
                    value: SECRET.into(),
                },
            ],
            json!({"tokenId":42}),
        );
        assert!(matches!(result, Err(ManagedStoreError::InputInvalid(_))));
        assert_eq!(
            store
                .secret_reference_receipt(&ring, batch.receipt_id(), authorize_alice)
                .unwrap()
                .outcome,
            "reserved"
        );
        store
            .finish_secret_reservation(
                &batch,
                SecretReservationOutcome::CaptureFailed,
                json!({"tokenId":42,"retrySafe":false}),
            )
            .unwrap();
        let receipt = store
            .secret_reference_receipt(&ring, batch.receipt_id(), authorize_alice)
            .unwrap();
        assert_eq!(receipt.outcome, "capture_failed");
        assert_eq!(receipt.metadata["tokenId"], 42);
    }

    #[test]
    fn capture_preserves_issued_secrets_when_receipt_metadata_must_be_omitted() {
        let (_temp, store, ring) = fixture();
        let capability = format!("sr_{}", URL_SAFE_NO_PAD.encode([42_u8; 32]));
        let safe = json!({"safeLocators":{"secretRef":"db-credentials"}});
        let cases = [
            (safe.clone(), false),
            (Value::Null, true),
            (json!({"oversized":"x".repeat(MAX_METADATA_BYTES)}), true),
            (json!({"accidentalSecret":SECRET}), true),
            (json!({"secretRef":capability}), true),
            (json!({"other":format!("prefix {capability} suffix")}), true),
            (
                json!({(capability.clone()):"capability in a property name"}),
                true,
            ),
        ];
        for (metadata, omitted) in cases {
            let batch = store
                .reserve_secret_outputs(&ring, request("alice"), &limits(), |_, _| Ok(()))
                .unwrap();
            batch.mark_dispatched();
            let reference = store
                .capture_secret_outputs(
                    &ring,
                    &batch,
                    vec![SecretOutputCapture {
                        pointer: "/result/issuedToken".into(),
                        value: SECRET.into(),
                    }],
                    metadata,
                )
                .unwrap()
                .remove(0);
            assert_eq!(
                store
                    .resolve_secret_reference(&ring, &reference.secret_ref, authorize_alice)
                    .unwrap(),
                SECRET
            );
            let receipt = store
                .secret_reference_receipt(&ring, batch.receipt_id(), authorize_alice)
                .unwrap();
            assert_eq!(receipt.outcome, "captured");
            assert_eq!(
                receipt.metadata,
                if omitted {
                    json!({"executionState":"completed","retrySafe":false,"metadataOmitted":true})
                } else {
                    safe.clone()
                }
            );
            let encoded = serde_json::to_string(&receipt).unwrap();
            assert!(!encoded.contains(SECRET));
            assert!(!encoded.contains(&capability));
            assert!(!encoded.contains(&reference.secret_ref));
        }
    }

    #[test]
    fn expired_material_is_erased_but_receipt_remains_and_cannot_slide() {
        let (_temp, store, ring) = fixture();
        let batch = store
            .reserve_secret_outputs(&ring, request("alice"), &limits(), |_, _| Ok(()))
            .unwrap();
        let reference = capture(&store, &ring, &batch);
        let deadline = reference.expires_at.clone();
        store
            .resolve_secret_reference(&ring, &reference.secret_ref, authorize_alice)
            .unwrap();
        assert_eq!(
            store
                .secret_reference_receipt(&ring, batch.receipt_id(), authorize_alice)
                .unwrap()
                .expires_at,
            deadline
        );
        let future = normalized_timestamp(Utc::now() + Duration::seconds(14401));
        cleanup_conn(&store.connection.lock().unwrap(), &future).unwrap();
        assert!(matches!(
            store.resolve_secret_reference(&ring, &reference.secret_ref, authorize_alice),
            Err(ManagedStoreError::SecretReferenceExpired)
        ));
        let receipt = store
            .secret_reference_receipt(&ring, batch.receipt_id(), authorize_alice)
            .unwrap();
        assert_eq!(receipt.outcome, "expired");
        assert_eq!(receipt.metadata["tokenId"], 42);
        let material = material_row(
            &store.connection.lock().unwrap(),
            &reference_hash(&reference.secret_ref).unwrap(),
        )
        .unwrap();
        assert!(material.ciphertext.is_none());
        assert!(material.nonce.is_none());
        assert!(material.key_id.is_none());
    }

    #[test]
    fn expiration_during_provider_work_keeps_late_completion_evidence() {
        let (_temp, store, ring) = fixture();
        let batch = store
            .reserve_secret_outputs(&ring, request("alice"), &limits(), |_, _| Ok(()))
            .unwrap();
        batch.mark_dispatched();
        let future = normalized_timestamp(Utc::now() + Duration::seconds(14401));
        cleanup_conn(&store.connection.lock().unwrap(), &future).unwrap();
        store
            .finish_secret_reservation(
                &batch,
                SecretReservationOutcome::CaptureFailed,
                json!({"tokenId":42,"executionState":"completed","retrySafe":false}),
            )
            .unwrap();
        let receipt = store
            .secret_reference_receipt(&ring, batch.receipt_id(), authorize_alice)
            .unwrap();
        assert_eq!(receipt.outcome, "expired");
        assert_eq!(receipt.metadata["tokenId"], 42);
        assert_eq!(receipt.metadata["executionState"], "completed");
        assert_eq!(receipt.metadata["retrySafe"], false);
    }

    #[test]
    fn cold_start_recovers_abandoned_reservations_but_reload_preserves_live_work() {
        let (temp, store, ring) = fixture();
        let mut limited = limits();
        limited.max_refs_per_principal = 2;
        limited.max_refs_total = 2;
        let completed = store
            .reserve_secret_outputs(&ring, request("alice"), &limited, |_, _| Ok(()))
            .unwrap();
        let captured = capture(&store, &ring, &completed);
        drop(completed);
        let pending = store
            .reserve_secret_outputs(&ring, request("alice"), &limited, |_, _| Ok(()))
            .unwrap();
        pending.mark_dispatched();
        let receipt_id = pending.receipt_id().to_string();
        let never_delivered_reference = pending.0.slots[0].secret_ref.clone();
        let config = ManagedStoreConfig {
            kind: "sqlite".into(),
            path: temp.path().join("store.sqlite").display().to_string(),
            auto_migrate: false,
            require_registered_principal_for_invocation: false,
        };

        let reloaded = ManagedStore::open(&config, ManagedStoreOpenMode::Reload).unwrap();
        reloaded
            .prepare_secret_references_for_runtime(false)
            .unwrap();
        let receipt = reloaded
            .secret_reference_receipt(&ring, &receipt_id, authorize_alice)
            .unwrap();
        assert_eq!(receipt.outcome, "reserved");
        assert_eq!(receipt.metadata, json!({}));
        assert!(matches!(
            reloaded.reserve_secret_outputs(&ring, request("alice"), &limited, |_, _| Ok(())),
            Err(ManagedStoreError::SecretReferenceCapacity)
        ));

        // Simulate abrupt process loss, where Rust destructors cannot write a
        // terminal outcome. No live operation survives into the reopened store.
        pending.0.state.store(2, Ordering::Release);
        drop(pending);
        drop(reloaded);
        drop(store);
        let restarted = ManagedStore::open(&config, ManagedStoreOpenMode::Startup).unwrap();
        restarted
            .prepare_secret_references_for_runtime(true)
            .unwrap();
        let receipt = restarted
            .secret_reference_receipt(&ring, &receipt_id, authorize_alice)
            .unwrap();
        assert_eq!(receipt.outcome, "unknown");
        assert_eq!(
            receipt.metadata,
            json!({"executionState":"unknown","retrySafe":false})
        );
        let material = material_row(
            &restarted.connection.lock().unwrap(),
            &reference_hash(&never_delivered_reference).unwrap(),
        )
        .unwrap();
        assert_eq!(material.state, "released");
        assert!(material.ciphertext.is_none());
        assert!(matches!(
            restarted.resolve_secret_reference(&ring, &never_delivered_reference, authorize_alice),
            Err(ManagedStoreError::SecretReferenceNotFound)
        ));
        let replacement = restarted
            .reserve_secret_outputs(&ring, request("alice"), &limited, |_, _| Ok(()))
            .unwrap();
        drop(replacement);
        assert_eq!(
            restarted
                .resolve_secret_reference(&ring, &captured.secret_ref, authorize_alice)
                .unwrap(),
            SECRET
        );
        assert_eq!(restarted.active_credential_key_ids().unwrap(), vec!["old"]);
        restarted.check_ready(Some(&ring)).unwrap();
        assert!(matches!(
            restarted.check_ready(None),
            Err(ManagedStoreError::EncryptionKeyMissing(_))
        ));
        // A second start preserves the same evidence and cannot revive a slot.
        restarted
            .prepare_secret_references_for_runtime(true)
            .unwrap();
        assert_eq!(
            restarted
                .secret_reference_receipt(&ring, &receipt_id, authorize_alice)
                .unwrap()
                .metadata,
            receipt.metadata
        );
    }

    #[test]
    fn all_retained_encryption_participates_in_readiness_and_rewrap() {
        let (_temp, store, ring) = fixture();
        for (caller, generation, active) in [("live", 1, true), ("removed", 2, false)] {
            let encrypted =
                encrypt_caller_contract(&ring, "old", caller, generation, active, &[97; 32])
                    .unwrap();
            store.connection.lock().unwrap().execute(
                "INSERT INTO secret_reference_caller_generations(caller,key_id,nonce,ciphertext,generation,active) VALUES(?1,?2,?3,?4,?5,?6)",
                params![caller,encrypted.key_id,encrypted.nonce,encrypted.ciphertext,generation,active],
            ).unwrap();
        }
        let batch = store
            .reserve_secret_outputs(&ring, request("alice"), &limits(), |_, _| Ok(()))
            .unwrap();
        let reference = capture(&store, &ring, &batch);
        assert_eq!(store.active_credential_key_ids().unwrap(), vec!["old"]);
        assert!(matches!(
            store.check_ready(None),
            Err(ManagedStoreError::EncryptionKeyMissing(_))
        ));
        let wrong = CredentialKeyRing {
            active_key: "old".into(),
            keys: Arc::new(BTreeMap::from([("old".into(), [1; 32])])),
        };
        assert!(matches!(
            store.check_ready(Some(&wrong)),
            Err(ManagedStoreError::CredentialDecryptFailed)
        ));
        let summary = store
            .rewrap_credentials(&ring, "old", "new", "admin")
            .unwrap();
        assert_eq!(summary.rewrapped, 4);
        assert_eq!(store.active_credential_key_ids().unwrap(), vec!["new"]);
        let new_only = CredentialKeyRing {
            active_key: "new".into(),
            keys: Arc::new(BTreeMap::from([("new".into(), [8; 32])])),
        };
        store.check_ready(Some(&new_only)).unwrap();
        assert_eq!(
            store
                .resolve_secret_reference(&new_only, &reference.secret_ref, authorize_alice)
                .unwrap(),
            SECRET
        );
        assert_eq!(reference.expires_at, batch.expires_at());
        for row in caller_contract_rows(&store.connection.lock().unwrap()).unwrap() {
            assert_eq!(
                decrypt_caller_contract(
                    &new_only,
                    &row.key_id,
                    &row.caller,
                    row.generation,
                    row.active,
                    &row.nonce,
                    &row.ciphertext
                )
                .unwrap()
                .as_slice(),
                &[97; 32]
            );
            assert!(matches!(
                decrypt_caller_contract(
                    &new_only,
                    &row.key_id,
                    &row.caller,
                    row.generation + 1,
                    row.active,
                    &row.nonce,
                    &row.ciphertext
                ),
                Err(ManagedStoreError::CredentialDecryptFailed)
            ));
            assert!(matches!(
                decrypt_caller_contract(
                    &new_only,
                    &row.key_id,
                    &row.caller,
                    row.generation,
                    !row.active,
                    &row.nonce,
                    &row.ciphertext
                ),
                Err(ManagedStoreError::CredentialDecryptFailed)
            ));
        }
    }

    #[test]
    fn ciphertext_cannot_be_moved_between_output_fields_or_origins() {
        let (_temp, store, ring) = fixture();
        let batch = store
            .reserve_secret_outputs(&ring, request("alice"), &limits(), |_, _| Ok(()))
            .unwrap();
        let reference = capture(&store, &ring, &batch);
        store.connection.lock().unwrap().execute("UPDATE secret_reference_material SET output_pointer='/result/other' WHERE reference_hash=?1",[reference_hash(&reference.secret_ref).unwrap()]).unwrap();
        assert!(matches!(
            store.resolve_secret_reference(&ring, &reference.secret_ref, authorize_alice),
            Err(ManagedStoreError::CredentialDecryptFailed)
        ));
    }

    #[test]
    fn credential_import_is_atomic_reusable_and_uses_transaction_authority() {
        let (_temp, store, ring) = fixture();
        let batch = store
            .reserve_secret_outputs(&ring, request("alice"), &limits(), |_, _| Ok(()))
            .unwrap();
        let reference = capture(&store, &ring, &batch);
        let denied = store.upsert_user_credential_with_secret_references(
            &ring,
            credential(&reference.secret_ref, "destination"),
            CredentialManagementPurpose::Administrative,
            |_| Ok(()),
            |_, _| Err(ManagedStoreError::SecretReferenceDenied),
        );
        assert!(matches!(
            denied,
            Err(ManagedStoreError::SecretReferenceDenied)
        ));
        assert!(matches!(
            store.credential_by_tuple("destination", "gitlab-connection", "default"),
            Err(ManagedStoreError::CredentialNotFound)
        ));
        let result = store
            .upsert_user_credential_with_secret_references(
                &ring,
                credential(&reference.secret_ref, "destination"),
                CredentialManagementPurpose::Administrative,
                |_| Ok(()),
                |conn, origin| {
                    assert_eq!(origin.principal(), "alice");
                    assert!(!conn.is_autocommit(), "origin check shares transaction");
                    Ok(())
                },
            )
            .unwrap();
        assert_eq!(result.references.len(), 1);
        assert_eq!(result.references[0].receipt_id, batch.receipt_id());
        assert_eq!(result.credential.owner_principal, "destination");
        assert!(!serde_json::to_string(&result).unwrap().contains(SECRET));
        assert!(
            !serde_json::to_string(&result)
                .unwrap()
                .contains(&reference.secret_ref)
        );
        assert_eq!(
            store
                .resolve_secret_reference(&ring, &reference.secret_ref, authorize_alice)
                .unwrap(),
            SECRET
        );
        let conn = store.connection.lock().unwrap();
        let row =
            encrypted_credential_by_tuple(&conn, "destination", "gitlab-connection", "default")
                .unwrap();
        let stored = ring
            .decrypt(
                &row.key_id,
                &row.secret_nonce,
                &row.secret_ciphertext,
                &credential_aad(&row),
            )
            .unwrap();
        assert_eq!(stored["token"], SECRET);
    }

    #[test]
    fn failed_credential_material_write_rolls_back_without_consuming_reference() {
        let (_temp, store, ring) = fixture();
        let batch = store
            .reserve_secret_outputs(&ring, request("alice"), &limits(), |_, _| Ok(()))
            .unwrap();
        let reference = capture(&store, &ring, &batch);
        store.connection.lock().unwrap().execute_batch(
            "CREATE TEMP TRIGGER reject_test_credential_material BEFORE INSERT ON credential_secret_material BEGIN SELECT RAISE(ABORT,'test material write failure'); END;",
        ).unwrap();
        let result = store.upsert_user_credential_with_secret_references(
            &ring,
            credential(&reference.secret_ref, "destination"),
            CredentialManagementPurpose::Administrative,
            |_| Ok(()),
            authorize_alice,
        );
        assert!(matches!(result, Err(ManagedStoreError::Unavailable(_))));
        assert!(matches!(
            store.credential_by_tuple("destination", "gitlab-connection", "default"),
            Err(ManagedStoreError::CredentialNotFound)
        ));
        assert_eq!(
            store
                .resolve_secret_reference(&ring, &reference.secret_ref, authorize_alice)
                .unwrap(),
            SECRET
        );
        store
            .connection
            .lock()
            .unwrap()
            .execute_batch("DROP TRIGGER reject_test_credential_material;")
            .unwrap();
        store
            .upsert_user_credential_with_secret_references(
                &ring,
                credential(&reference.secret_ref, "destination"),
                CredentialManagementPurpose::Administrative,
                |_| Ok(()),
                authorize_alice,
            )
            .unwrap();
    }

    #[test]
    fn reference_inputs_reject_wrong_fields_unknown_keys_and_foreign_origins() {
        let (_temp, store, ring) = fixture();
        let batch = store
            .reserve_secret_outputs(&ring, request("destination"), &limits(), |_, _| Ok(()))
            .unwrap();
        let reference = capture(&store, &ring, &batch);
        assert!(matches!(
            store.resolve_secret_reference(&ring, &reference.secret_ref, authorize_alice),
            Err(ManagedStoreError::SecretReferenceDenied)
        ));
        let mut write = credential(&reference.secret_ref, "destination");
        write.secret["token"]["extra"] = json!(true);
        assert!(matches!(
            store.upsert_user_credential_with_secret_references(
                &ring,
                write,
                CredentialManagementPurpose::Administrative,
                |_| Ok(()),
                |_, _| Ok(())
            ),
            Err(ManagedStoreError::InputInvalid(_))
        ));
        let mut write = credential(&reference.secret_ref, "destination");
        write.secret["username"] = json!({"secretRef":reference.secret_ref});
        assert!(matches!(
            store.upsert_user_credential_with_secret_references(
                &ring,
                write,
                CredentialManagementPurpose::Administrative,
                |_| Ok(()),
                |_, _| Ok(())
            ),
            Err(ManagedStoreError::InputInvalid(_))
        ));
    }

    #[test]
    fn bare_capabilities_cannot_be_installed_as_literal_credentials() {
        let (_temp, store, ring) = fixture();
        let batch = store
            .reserve_secret_outputs(&ring, request("alice"), &limits(), |_, _| Ok(()))
            .unwrap();
        let live = capture(&store, &ring, &batch);
        let absent = format!("sr_{}", URL_SAFE_NO_PAD.encode([42_u8; 32]));
        for handle in [&live.secret_ref, &absent] {
            let mut write = credential(handle, "destination");
            write.secret = json!({"token":handle});
            let error = store
                .upsert_user_credential_with_secret_references(
                    &ring,
                    write,
                    CredentialManagementPurpose::Administrative,
                    |_| Ok(()),
                    |_, _| panic!("bare capabilities must fail before reference resolution"),
                )
                .unwrap_err();
            assert!(matches!(error, ManagedStoreError::InputInvalid(message)
                if message == "secret reference handles must use a secretRef object"));
            assert!(matches!(
                store.credential_by_tuple("destination", "gitlab-connection", "default"),
                Err(ManagedStoreError::CredentialNotFound)
            ));
        }
        for literal in ["ordinary-token", "sr_not-a-broker-capability"] {
            let mut write = credential("unused", "destination");
            write.secret = json!({"token":literal});
            let installed = store
                .upsert_user_credential_with_secret_references(
                    &ring,
                    write,
                    CredentialManagementPurpose::Administrative,
                    |_| Ok(()),
                    |_, _| panic!("ordinary literals do not resolve references"),
                )
                .unwrap();
            assert!(installed.references.is_empty());
        }
    }

    #[test]
    fn literal_credential_write_requires_authority_inside_its_transaction() {
        let (_temp, store, ring) = fixture();
        let mut write = credential("unused", "destination");
        write.secret = json!({"token":"literal-connection-token"});
        let result = store.upsert_user_credential_with_secret_references(
            &ring,
            write,
            CredentialManagementPurpose::Administrative,
            |conn| {
                assert!(
                    !conn.is_autocommit(),
                    "write authority shares the transaction"
                );
                Err(ManagedStoreError::BrokerTokenRevoked)
            },
            |_, _| panic!("literal credentials have no reference origin"),
        );
        assert!(matches!(result, Err(ManagedStoreError::BrokerTokenRevoked)));
        assert!(matches!(
            store.credential_by_tuple("destination", "gitlab-connection", "default"),
            Err(ManagedStoreError::CredentialNotFound)
        ));
    }

    #[test]
    fn retained_receipt_count_is_bounded_before_new_dispatch() {
        let (_temp, store, ring) = fixture();
        let mut bounded = limits();
        bounded.max_receipts_total = 1;
        let batch = store
            .reserve_secret_outputs(&ring, request("alice"), &bounded, |_, _| Ok(()))
            .unwrap();
        store
            .finish_secret_reservation(
                &batch,
                SecretReservationOutcome::Unknown,
                json!({"retrySafe":false}),
            )
            .unwrap();
        assert!(matches!(
            store.reserve_secret_outputs(&ring, request("alice"), &bounded, |_, _| Ok(())),
            Err(ManagedStoreError::SecretReferenceCapacity)
        ));
        let future = normalized_timestamp(Utc::now() + Duration::days(8));
        cleanup_conn(&store.connection.lock().unwrap(), &future).unwrap();
        store
            .reserve_secret_outputs(&ring, request("alice"), &bounded, |_, _| Ok(()))
            .unwrap();
    }

    #[test]
    fn one_principal_cannot_fill_the_global_receipt_allowance() {
        let (_temp, store, ring) = fixture();
        let mut bounded = limits();
        bounded.max_refs_per_principal = 1;
        for _ in 0..10 {
            let batch = store
                .reserve_secret_outputs(&ring, request("alice"), &bounded, |_, _| Ok(()))
                .unwrap();
            drop(batch);
        }
        assert!(matches!(
            store.reserve_secret_outputs(&ring, request("alice"), &bounded, |_, _| Ok(())),
            Err(ManagedStoreError::SecretReferenceCapacity)
        ));
        store
            .reserve_secret_outputs(&ring, request("destination"), &bounded, |_, _| Ok(()))
            .unwrap();
    }
}
