//! Fixed, bounded transferable-secret contracts. This module declares values
//! and schemas only; the host owns reference storage and authorization.
use crate::{ActionDescriptor, ActionIo};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::fmt;
use zeroize::Zeroizing;

const MAX_FIELDS: usize = 16;
const MAX_POINTER_BYTES: usize = 1024;
const MAX_POINTER_DEPTH: usize = 16;
const MAX_SECRET_BYTES: u64 = 1024 * 1024;

/// A transferable string output, identified by a fixed envelope-relative
/// `/result/...` JSON pointer. The provider returns its value in the protected
/// result sidecar. The host reserves `max_bytes` before dispatch, then supplies
/// a raw string or a reference according to deployment policy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SecretOutputDescriptor {
    pointer: String,
    max_bytes: u64,
    required: bool,
}

impl SecretOutputDescriptor {
    /// Declares one required output with a positive UTF-8 byte bound of at
    /// most one MiB. Descriptor validation checks the pointer and bound.
    pub fn new(pointer: impl Into<String>, max_bytes: u64) -> Self {
        Self {
            pointer: pointer.into(),
            max_bytes,
            required: true,
        }
    }

    /// Allows successful outcomes to omit this secret. Its capacity is still
    /// reserved because the host cannot predict whether the provider issues it.
    pub fn optional(mut self) -> Self {
        self.required = false;
        self
    }

    pub fn pointer(&self) -> &str {
        &self.pointer
    }

    pub const fn max_bytes(&self) -> u64 {
        self.max_bytes
    }

    pub const fn is_required(&self) -> bool {
        self.required
    }
}

/// A string payload field accepting a literal or a host-resolved secret
/// reference. Its pointer starts at `/inputs`, names only fixed object
/// properties, and must lead to an unambiguous `type: "string"` schema.
/// Scope resolution cannot depend on this field's value.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SecretInputDescriptor {
    pointer: String,
}

impl SecretInputDescriptor {
    pub fn new(pointer: impl Into<String>) -> Self {
        Self {
            pointer: pointer.into(),
        }
    }

    pub fn pointer(&self) -> &str {
        &self.pointer
    }
}

/// A contract error with fixed diagnostics. It never contains a secret input,
/// output, reference, or JSON-schema validation error that could echo a value.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum SecretContractError {
    #[error("secret pointer must name bounded fixed object properties under its declared root")]
    InvalidPointer,
    #[error("secret field count or output byte bound exceeds the supported limits")]
    InvalidBounds,
    #[error("secret pointers must not be duplicated or overlap")]
    OverlappingPointers,
    #[error("secret contracts require JSON invocation I/O")]
    UnsupportedIo,
    #[error("transferable secret outputs cannot declare response presentation")]
    UnsupportedPresentation,
    #[error("secret input must have an unambiguous fixed-property string schema")]
    InvalidInputSchema,
    #[error("secret output must also be marked sensitive")]
    MissingSensitiveOutput,
    #[error("secret input must also be marked writeOnly")]
    MissingSensitiveInput,
    #[error("resolved inputs do not satisfy the action's literal schema")]
    InvalidInputValue,
}

/// One protected provider output. The host takes these values through
/// [`crate::host::take_secret_outputs`], validates the declared contract and
/// materializes the configured delivery. Plaintext is zeroized on drop and is
/// never included in Debug or serde representations of a provider result.
///
/// Only the host reads `value`; linked provider code uses
/// [`crate::ProviderResult::with_secret_output`] to supply it. Provider tests
/// use the feature-gated `test_support::secret_outputs_match` inspector.
/// This type has no equality implementation, including under `test-support`:
///
/// ```compile_fail
/// use agent_access_provider::host::SecretOutputValue;
/// fn requires_equality<T: PartialEq>() {}
/// requires_equality::<SecretOutputValue>();
/// ```
#[derive(Clone)]
pub struct SecretOutputValue {
    pointer: String,
    value: Zeroizing<String>,
}

impl SecretOutputValue {
    pub(crate) fn new(pointer: String, value: String) -> Self {
        Self {
            pointer,
            value: Zeroizing::new(value),
        }
    }

    pub fn pointer(&self) -> &str {
        &self.pointer
    }

    /// Host-only access to the value being captured or deliberately delivered
    /// raw. Do not copy it into logs, audit, errors, or ordinary provider JSON.
    pub fn value(&self) -> &str {
        self.value.as_str()
    }
}

impl fmt::Debug for SecretOutputValue {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SecretOutputValue")
            .field("pointer", &self.pointer)
            .field("value", &"[REDACTED]")
            .finish()
    }
}

/// Decode fixed object-property paths, never JSON Pointer's array indexing.
fn property_path(pointer: &str, root: &str) -> Result<Vec<String>, SecretContractError> {
    if pointer.len() > MAX_POINTER_BYTES {
        return Err(SecretContractError::InvalidPointer);
    }
    let relative = pointer
        .strip_prefix(root)
        .and_then(|value| value.strip_prefix('/'))
        .ok_or(SecretContractError::InvalidPointer)?;
    let mut path = Vec::new();
    for part in relative.split('/') {
        let mut property = String::new();
        let mut chars = part.chars();
        while let Some(ch) = chars.next() {
            match ch {
                '~' => match chars.next() {
                    Some('0') => property.push('~'),
                    Some('1') => property.push('/'),
                    _ => return Err(SecretContractError::InvalidPointer),
                },
                ch => property.push(ch),
            }
        }
        if property.is_empty() || property == "*" || property.chars().any(char::is_control) {
            return Err(SecretContractError::InvalidPointer);
        }
        path.push(property);
    }
    if path.len() > MAX_POINTER_DEPTH {
        return Err(SecretContractError::InvalidPointer);
    }
    Ok(path)
}

fn unique_paths<'a>(
    pointers: impl Iterator<Item = &'a str>,
    root: &str,
) -> Result<(), SecretContractError> {
    let mut paths: Vec<Vec<String>> = Vec::new();
    for pointer in pointers {
        let path = property_path(pointer, root)?;
        if paths
            .iter()
            .any(|previous| path.starts_with(previous) || previous.starts_with(&path))
        {
            return Err(SecretContractError::OverlappingPointers);
        }
        paths.push(path);
    }
    Ok(())
}

fn fixed_schema_node(schema: &Value, expected_type: &str) -> Result<(), SecretContractError> {
    let object = schema
        .as_object()
        .ok_or(SecretContractError::InvalidInputSchema)?;
    if object.get("type").and_then(Value::as_str) != Some(expected_type)
        || [
            "$ref",
            "$dynamicRef",
            "$recursiveRef",
            "allOf",
            "anyOf",
            "oneOf",
            "not",
            "if",
            "then",
            "else",
            "dependentSchemas",
            "dependencies",
            "patternProperties",
            "unevaluatedProperties",
            "const",
            "enum",
        ]
        .iter()
        .any(|keyword| {
            // Literal leaf enum/const constraints are preserved and checked
            // after resolution. On ancestors they constrain the whole object.
            object.contains_key(*keyword)
                && !(expected_type == "string" && matches!(*keyword, "const" | "enum"))
        })
    {
        return Err(SecretContractError::InvalidInputSchema);
    }
    Ok(())
}

fn input_schema_path(schema: &Value, pointer: &str) -> Result<String, SecretContractError> {
    let path = property_path(pointer, "/inputs")?;
    let mut node = schema;
    let mut schema_pointer = String::new();
    for property in path {
        fixed_schema_node(node, "object")?;
        node = node
            .get("properties")
            .and_then(Value::as_object)
            .and_then(|properties| properties.get(&property))
            .ok_or(SecretContractError::InvalidInputSchema)?;
        schema_pointer.push_str("/properties/");
        schema_pointer.push_str(&property.replace('~', "~0").replace('/', "~1"));
    }
    fixed_schema_node(node, "string")?;
    Ok(schema_pointer)
}

pub(crate) fn mark_sensitive_input(schema: &mut Value, pointer: &str) {
    if let Ok(schema_pointer) = input_schema_path(schema, pointer)
        && let Some(field) = schema
            .pointer_mut(&schema_pointer)
            .and_then(Value::as_object_mut)
    {
        field.insert("writeOnly".into(), Value::Bool(true));
    }
}

pub(crate) fn validate_secret_contract(
    action: &ActionDescriptor,
) -> Result<(), SecretContractError> {
    if action.secret_inputs.is_empty() && action.secret_outputs.is_empty() {
        return Ok(());
    }
    if !matches!(action.io, ActionIo::Json) {
        return Err(SecretContractError::UnsupportedIo);
    }
    if !action.secret_outputs.is_empty() && action.presentation.is_some() {
        return Err(SecretContractError::UnsupportedPresentation);
    }
    if action.secret_inputs.len() > MAX_FIELDS
        || action.secret_outputs.len() > MAX_FIELDS
        || action
            .secret_outputs
            .iter()
            .any(|output| output.max_bytes == 0 || output.max_bytes > MAX_SECRET_BYTES)
    {
        return Err(SecretContractError::InvalidBounds);
    }
    unique_paths(
        action.secret_outputs.iter().map(|output| output.pointer()),
        "/result",
    )?;
    unique_paths(
        action.secret_inputs.iter().map(|input| input.pointer()),
        "/inputs",
    )?;
    for output in &action.secret_outputs {
        if !action
            .sensitive_output_pointers
            .iter()
            .any(|p| p == output.pointer())
        {
            return Err(SecretContractError::MissingSensitiveOutput);
        }
    }
    for input in &action.secret_inputs {
        let path = input_schema_path(&action.input_schema, input.pointer())?;
        if action
            .input_schema
            .pointer(&path)
            .and_then(|field| field.get("writeOnly"))
            != Some(&Value::Bool(true))
        {
            return Err(SecretContractError::MissingSensitiveInput);
        }
    }
    Ok(())
}

pub(crate) fn reference_input_schema(
    action: &ActionDescriptor,
) -> Result<Value, SecretContractError> {
    validate_secret_contract(action)?;
    let mut schema = action.input_schema.clone();
    for input in &action.secret_inputs {
        let path = input_schema_path(&action.input_schema, input.pointer())?;
        let field = schema
            .pointer_mut(&path)
            .ok_or(SecretContractError::InvalidInputSchema)?;
        *field = json!({
            "oneOf": [field.clone(), {
                "type": "object",
                "required": ["secretRef"],
                "properties": {
                    "secretRef": {
                        "type": "string",
                        "pattern": "^sr_[A-Za-z0-9_-]{43}$",
                        "minLength": 46,
                        "maxLength": 46
                    },
                    "expiresAt": {
                        "type": "string", "format": "date-time", "maxLength": 64,
                        "description": "Informational expiry; the Broker's stored deadline is authoritative."
                    }
                },
                "additionalProperties": false
            }],
            "writeOnly": true
        });
    }
    Ok(schema)
}

pub(crate) fn validate_literal_inputs(
    action: &ActionDescriptor,
    inputs: &Value,
) -> Result<(), SecretContractError> {
    validate_secret_contract(action)?;
    let validator = jsonschema::validator_for(&action.input_schema)
        .map_err(|_| SecretContractError::InvalidInputSchema)?;
    if validator.is_valid(inputs) {
        Ok(())
    } else {
        Err(SecretContractError::InvalidInputValue)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ProviderResult, ServiceDescriptor};

    fn input_action() -> ActionDescriptor {
        ActionDescriptor::new(
            "key.store",
            "Store a key",
            json!({
                "type": "object", "required": ["destination", "credentials"],
                "properties": {
                    "destination": {"type": "string"},
                    "credentials": {
                        "type": "object", "required": ["token"],
                        "properties": {"token": {
                            "type": "string", "minLength": 6, "maxLength": 20,
                            "pattern": "^key_[a-z]+$", "enum": ["key_alpha", "key_beta"]
                        }},
                        "additionalProperties": false
                    }
                },
                "additionalProperties": false
            }),
        )
        .credential_modes(["service"])
        .secret_input(SecretInputDescriptor::new("/inputs/credentials/token"))
    }

    fn output_action() -> ActionDescriptor {
        ActionDescriptor::new("key.create", "Issue a key", json!({"type": "object"}))
            .credential_modes(["service"])
            .secret_output(SecretOutputDescriptor::new("/result/issuedToken", 8192))
    }

    #[test]
    fn result_sidecar_never_serializes_or_exposes_plaintext_in_debug() {
        let secret = "synthetic-private-output-012345";
        let mut result = ProviderResult::new(json!({"id": 17}))
            .with_secret_output("/result/issuedToken", secret.to_owned());
        let encoded = serde_json::to_value(&result).unwrap();
        assert_eq!(encoded["result"], json!({"id": 17}));
        assert!(!encoded.to_string().contains(secret));
        assert!(!format!("{result:?}").contains(secret));
        assert!(format!("{result:?}").contains("REDACTED"));
        let mut decoded: ProviderResult = serde_json::from_value(json!({
            "result": {"id": 17},
            "secretOutputs": [{"pointer": "/result/issuedToken", "value": secret}]
        }))
        .unwrap();
        assert!(crate::host::take_secret_outputs(&mut decoded).is_empty());
        let captured = crate::host::take_secret_outputs(&mut result);
        assert_eq!(captured.len(), 1);
        assert_eq!(captured[0].pointer(), "/result/issuedToken");
        assert_eq!(captured[0].value(), secret);
        assert!(crate::host::take_secret_outputs(&mut result).is_empty());
    }

    #[test]
    fn result_equality_ignores_secret_values_but_compares_pointer_order() {
        let result = ProviderResult::new(json!({"id": 17}))
            .with_secret_output("/result/first", "synthetic-alpha".into())
            .with_secret_output("/result/second", "synthetic-beta".into());
        let other_values = ProviderResult::new(json!({"id": 17}))
            .with_secret_output("/result/first", "different-value-of-another-length".into())
            .with_secret_output("/result/second", String::new());
        assert_eq!(result, other_values);
        assert_ne!(result, ProviderResult::new(json!({"id": 17})));
        let reordered = ProviderResult::new(json!({"id": 17}))
            .with_secret_output("/result/second", "synthetic-beta".into())
            .with_secret_output("/result/first", "synthetic-alpha".into());
        assert_ne!(result, reordered);
        let changed_pointer = ProviderResult::new(json!({"id": 17}))
            .with_secret_output("/result/first", "synthetic-alpha".into())
            .with_secret_output("/result/third", "synthetic-beta".into());
        assert_ne!(result, changed_pointer);
    }

    #[test]
    fn result_equality_preserves_all_public_field_comparisons() {
        let result = ProviderResult::new(json!({"id": 17}))
            .with_secret_output("/result/issuedToken", "synthetic-alpha".into());
        assert_eq!(result, result.clone());
        let mut changed_result = result.clone();
        changed_result.result = json!({"id": 18});
        assert_ne!(result, changed_result);
        assert_ne!(result, result.clone().with_audit(json!({"id": 17})));
        assert_ne!(result, result.clone().with_object_ids(json!({"id": 17})));
        assert_ne!(result, result.clone().with_upstream(Some(200), None));
        assert_ne!(result, result.clone().with_upstream(None, Some(1)));
        assert_ne!(
            result,
            result
                .clone()
                .with_stream(crate::ProviderResultStream::from_bytes(
                    "application/octet-stream".into(),
                    vec![1],
                ))
        );
    }

    #[test]
    fn provider_test_inspector_compares_without_revealing_or_draining_secrets() {
        use crate::test_support::secret_outputs_match;
        let result = ProviderResult::new(json!({"id": 17}))
            .with_secret_output("/result/first", "synthetic-alpha".into())
            .with_secret_output("/result/second", "synthetic-beta".into());
        assert!(secret_outputs_match(
            &result,
            &[
                ("/result/second", "synthetic-beta"),
                ("/result/first", "synthetic-alpha"),
            ]
        ));
        assert!(!secret_outputs_match(&result, &[]));
        assert!(!secret_outputs_match(
            &result,
            &[
                ("/result/first", "synthetic-alpha"),
                ("/result/second", "synthetic-incorrect"),
            ]
        ));
        assert!(!secret_outputs_match(
            &result,
            &[
                ("/result/first", "synthetic-alpha"),
                ("/result/first", "synthetic-alpha"),
            ]
        ));
        let duplicate = ProviderResult::new(json!({}))
            .with_secret_output("/result/first", "synthetic-alpha".into())
            .with_secret_output("/result/first", "synthetic-alpha".into());
        assert!(!secret_outputs_match(
            &duplicate,
            &[
                ("/result/first", "synthetic-alpha"),
                ("/result/second", "synthetic-alpha"),
            ]
        ));
        assert_eq!(result.secret_outputs.len(), 2);
    }

    #[test]
    fn reference_schema_is_precise_and_preserves_literal_validation() {
        let action = input_action();
        let original = action.input_schema.clone();
        let schema = action.reference_input_schema().unwrap();
        assert_eq!(action.input_schema, original);
        let validator = jsonschema::validator_for(&schema).unwrap();
        let reference = json!({"secretRef": format!("sr_{}", "A".repeat(43))});
        let request = json!({"destination": "project", "credentials": {"token": reference}});
        assert!(validator.is_valid(&request));
        let mut with_expiry = request.clone();
        with_expiry["credentials"]["token"]["expiresAt"] = json!("2026-10-17T12:00:00Z");
        assert!(validator.is_valid(&with_expiry));
        with_expiry["credentials"]["token"]["extend"] = json!(true);
        assert!(!validator.is_valid(&with_expiry));
        assert!(action.validate_literal_secret_inputs(&request).is_err());
        let literal = json!({"destination": "project", "credentials": {"token": "key_alpha"}});
        assert!(validator.is_valid(&literal));
        assert!(action.validate_literal_secret_inputs(&literal).is_ok());
        for bad in [
            "key_gamma",
            "bad",
            "key_A",
            "key_abcdefghijklmnopqrstuvwxyz",
        ] {
            let invalid = json!({"destination": "project", "credentials": {"token": bad}});
            assert!(!validator.is_valid(&invalid));
            assert_eq!(
                action.validate_literal_secret_inputs(&invalid),
                Err(SecretContractError::InvalidInputValue)
            );
        }
        let mut undeclared = literal;
        undeclared["destination"] = reference;
        assert!(!validator.is_valid(&undeclared));
    }

    #[test]
    fn descriptor_validates_bounds_fixed_paths_and_automatic_sensitivity() {
        let action = output_action();
        assert_eq!(action.sensitive_output_pointers, ["/result/issuedToken"]);
        assert!(action.secret_outputs[0].is_required());
        assert!(
            !SecretOutputDescriptor::new("/result/token", 1)
                .optional()
                .is_required()
        );
        ServiceDescriptor::new("example", "Example")
            .with_actions(vec![action])
            .validate()
            .unwrap();
        let input = input_action();
        assert_eq!(
            input.input_schema["properties"]["credentials"]["properties"]["token"]["writeOnly"],
            true
        );
        for pointer in [
            "/token",
            "/result",
            "/result/",
            "/result/*",
            "/result/a~2b",
            "/results/a",
        ] {
            let action = ActionDescriptor::new("key.create", "Issue", json!({"type":"object"}))
                .secret_output(SecretOutputDescriptor::new(pointer, 1));
            assert_eq!(
                validate_secret_contract(&action),
                Err(SecretContractError::InvalidPointer)
            );
        }
        for max_bytes in [0, MAX_SECRET_BYTES + 1] {
            let mut action = output_action();
            action.secret_outputs[0] =
                SecretOutputDescriptor::new("/result/issuedToken", max_bytes);
            assert_eq!(
                validate_secret_contract(&action),
                Err(SecretContractError::InvalidBounds)
            );
        }
        let overlap = output_action()
            .secret_output(SecretOutputDescriptor::new("/result/issuedToken/child", 1));
        assert_eq!(
            validate_secret_contract(&overlap),
            Err(SecretContractError::OverlappingPointers)
        );
        let duplicate =
            input_action().secret_input(SecretInputDescriptor::new("/inputs/credentials/token"));
        assert_eq!(
            validate_secret_contract(&duplicate),
            Err(SecretContractError::OverlappingPointers)
        );
        assert_eq!(
            validate_secret_contract(&output_action().raw_download()),
            Err(SecretContractError::UnsupportedIo)
        );
    }

    #[test]
    fn escaped_object_properties_work_but_arrays_and_compositions_fail_closed() {
        let action = ActionDescriptor::new("key.store", "Store", json!({
            "type":"object", "properties":{"a/b":{"type":"object","properties":{"t~k":{"type":"string"}}}}
        })).secret_input(SecretInputDescriptor::new("/inputs/a~1b/t~0k"));
        assert!(action.reference_input_schema().is_ok());
        for schema in [
            json!({"type":"object","properties":{"token":{"type":"array","items":{"type":"string"}}}}),
            json!({"type":"object","properties":{"token":{"oneOf":[{"type":"string"},{"type":"null"}]}}}),
            json!({"type":"object","properties":{"token":{"type":"string","$ref":"#/$defs/s"}},"$defs":{"s":{"type":"string"}}}),
            json!({"type":"object","properties":{"token":{"type":"string"}},"if":{"required":["token"]},"then":{"properties":{"token":{"const":"private"}}}}),
        ] {
            let action = ActionDescriptor::new("key.store", "Store", schema)
                .secret_input(SecretInputDescriptor::new("/inputs/token"));
            assert_eq!(
                action.reference_input_schema(),
                Err(SecretContractError::InvalidInputSchema)
            );
        }
    }

    #[test]
    fn presentation_and_manually_bypassed_sensitivity_are_rejected() {
        let mut action = output_action();
        action.presentation = Some(crate::presentation::ActionPresentation::new(&[], None));
        assert_eq!(
            validate_secret_contract(&action),
            Err(SecretContractError::UnsupportedPresentation)
        );
        action.presentation = None;
        action.sensitive_output_pointers.clear();
        assert_eq!(
            validate_secret_contract(&action),
            Err(SecretContractError::MissingSensitiveOutput)
        );
        let mut input = input_action();
        input.input_schema["properties"]["credentials"]["properties"]["token"]
            .as_object_mut()
            .unwrap()
            .remove("writeOnly");
        assert_eq!(
            validate_secret_contract(&input),
            Err(SecretContractError::MissingSensitiveInput)
        );
        let mut many = output_action();
        for index in 0..MAX_FIELDS {
            many = many.secret_output(SecretOutputDescriptor::new(
                format!("/result/token{index}"),
                1,
            ));
        }
        assert_eq!(
            validate_secret_contract(&many),
            Err(SecretContractError::InvalidBounds)
        );
    }

    #[test]
    fn sensitive_output_does_not_imply_transferable_secret() {
        let action = ActionDescriptor::new("item.read", "Read", json!({"type":"object"}))
            .credential_modes(["service"])
            .sensitive_output("/result/content");
        assert!(action.secret_outputs.is_empty());
        assert!(validate_secret_contract(&action).is_ok());
    }

    #[test]
    fn secret_reasons_are_host_only_with_distinct_statuses() {
        for (reason, status) in [
            (crate::ReasonCode::SecretReferenceNotFound, 404),
            (crate::ReasonCode::SecretReferenceExpired, 403),
            (crate::ReasonCode::SecretReferenceDenied, 403),
            (crate::ReasonCode::SecretReferenceCapacity, 429),
            (crate::ReasonCode::SecretCaptureFailed, 503),
        ] {
            assert_eq!(reason.http_status(), status);
            assert!(!reason.is_provider_emittable());
            assert!(
                !reason.permits_provider_failure(
                    &crate::Decision::Error,
                    crate::HookPhase::Invocation
                )
            );
            assert!(!reason.permits_late_stream());
        }
    }
}
