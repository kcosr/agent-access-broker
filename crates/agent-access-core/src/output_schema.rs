//! Output schemas composed from catalog actions. One composition serves both
//! MCP transports, action details, OpenAPI responses and the test-support
//! runtime check. It reads only [`ApiActionSpec`], so the stdio adapter
//! composes from the catalog JSON exactly as HTTP MCP composes from its
//! runtime catalog.
//!
//! The result payload of an action is the union of complete object branches:
//! its success schema with the optional `renderedBody` at each declared body
//! owner, the whole-result Markdown export when the action offers it, its
//! provider error schema (with the same rendered bodies) merged with the
//! shared failure properties, and the shared failure schema. Each MCP
//! projection wraps that payload in the delivery shapes its transport
//! actually returns. Nothing composed here contains a `$ref`.
use crate::ApiActionSpec;
use crate::mcp::{HelperKind, ProjectionMode};
use agent_access_provider::presentation::{inject_rendered_body_schema, markdown_result_schema};
use agent_access_provider::{
    ActionIo, shared_failure_result_schema, with_shared_failure_properties,
};
use serde_json::{Value, json};

/// The largest composed MCP `outputSchema` of one tool, in compact JSON bytes.
pub const MAX_OUTPUT_SCHEMA_BYTES: usize = 16_384;

/// Rendered-body owner pointers relative to the result.
fn body_owners(action: &ApiActionSpec) -> impl Iterator<Item = &str> {
    action
        .rendered_body_owners
        .iter()
        .filter_map(|pointer| pointer.strip_prefix("/result"))
}

/// The union every `result` of `action` follows, or `None` when the action
/// declares no result schemas.
pub fn result_payload_schema(action: &ApiActionSpec) -> Option<Value> {
    let schemas = action.result_schemas.as_ref()?;
    let mut success = schemas.success.clone();
    for owner in body_owners(action) {
        // Descriptor validation proved every owner resolves in the success
        // schema; an older catalog that does not is still described.
        let _ = inject_rendered_body_schema(&mut success, owner);
    }
    let mut branches = vec![success];
    if action
        .response_formats
        .iter()
        .any(|format| format == "markdown")
    {
        branches.push(markdown_result_schema());
    }
    if let Some(error) = &schemas.error {
        let mut error = error.clone();
        for owner in body_owners(action) {
            // Presentation also runs on allow-with-result errors, but an
            // error result need not carry the body owners at all.
            let _ = inject_rendered_body_schema(&mut error, owner);
        }
        branches.push(with_shared_failure_properties(&error));
    }
    branches.push(shared_failure_result_schema());
    Some(json!({
        "type": "object",
        "description": "The action payload on allow; retry, receipt or execution details on failure.",
        "anyOf": branches
    }))
}

fn string() -> Value {
    json!({"type": "string"})
}

fn strings() -> Value {
    json!({"type": "array", "items": {"type": "string"}})
}

const DECISIONS: [&str; 3] = ["allow", "deny", "error"];

/// The Broker invocation envelope with `result` typed as `result`.
pub fn envelope_schema(result: Value) -> Value {
    json!({
        "type": "object",
        "description": "Broker response. Check decision and error before using result; on allow, result holds the action payload.",
        "properties": {
            "agentRequestId": string(),
            "brokerRequestId": string(),
            "decision": {"type": "string", "enum": DECISIONS},
            "service": string(),
            "action": string(),
            "resourceScopes": {"type": "object", "additionalProperties": strings()},
            "reasonCode": string(),
            "reason": string(),
            "result": result,
            "error": {"type": "object", "properties": {"message": string()}, "required": ["message"]}
        },
        "required": ["agentRequestId", "brokerRequestId", "decision", "service", "action", "resourceScopes"]
    })
}

/// An HTTP MCP tool, admission or delivery failure that carries no action
/// result.
fn http_failure_schema() -> Value {
    json!({
        "type": "object",
        "description": "HTTP MCP tool or delivery failure; no action result is returned. Do not repeat an operation only to recover its output.",
        "properties": {
            "error": {"type": "object", "properties": {"code": string(), "message": string()}, "required": ["message"]},
            "agentRequestId": string(),
            "brokerRequestId": string(),
            "service": string(),
            "action": string(),
            "brokerOutcome": {"type": "object", "properties": {
                "status": {"type": "integer"},
                "decision": {"type": "string", "enum": DECISIONS},
                "reasonCode": {"type": ["string", "null"]},
                "mutationStatus": string()
            }, "required": ["status", "decision", "reasonCode"]},
            "execution": {"type": "object", "properties": {
                "dispatched": {"type": "boolean"},
                "completion": {"type": "string", "enum": ["completed", "unknown", "not_started"]}
            }, "required": ["dispatched", "completion"]},
            "resultAvailable": {"type": "boolean"},
            "retrySafe": {"type": "boolean"},
            "status": {"type": "integer"}
        },
        "required": ["error"]
    })
}

fn file_output_schema() -> Value {
    json!({"type": "object", "properties": {
        "status": {"type": "string", "enum": ["succeeded", "failed"]},
        "path": string(),
        "size": {"type": "integer"},
        "sha256": string(),
        "contentType": string(),
        "sensitive": {"type": "boolean"},
        "destinationReplaced": {"type": "boolean"},
        "error": string()
    }, "required": ["status", "path"]})
}

/// A stdio receipt for a response saved through `outputPath`, or for a save
/// that failed. A download receipt also keeps the metadata envelope, whose
/// `result` is typed as `download_result`.
fn file_receipt_schema(download_result: Option<Value>) -> Value {
    let mut properties = json!({
        "agentRequestId": string(),
        "brokerRequestId": string(),
        "decision": {"type": "string", "enum": DECISIONS},
        "service": string(),
        "action": string(),
        "reasonCode": string(),
        "operationStatus": {"type": "string", "enum": ["succeeded", "applied_unverified", "not_applied", "unknown"]},
        "mutationStatus": string(),
        "retrySafe": {"type": "boolean"},
        "verificationStage": string(),
        "safeLocators": {"type": "object"},
        "message": string(),
        "output": file_output_schema(),
        "metadataOutput": file_output_schema()
    });
    let description = match download_result {
        Some(result) => {
            properties["resourceScopes"] =
                json!({"type": "object", "additionalProperties": strings()});
            properties["reason"] = string();
            properties["result"] = result;
            "Local download receipt: output describes the saved file or the failed save; result holds the download metadata."
        }
        None => {
            "Local file receipt: output describes the saved response or the failed save; the result is not repeated."
        }
    };
    json!({
        "type": "object",
        "description": description,
        "properties": properties,
        "required": ["operationStatus"]
    })
}

fn branches(branches: Vec<Value>) -> Value {
    json!({"type": "object", "anyOf": branches})
}

/// The MCP `outputSchema` of `action` on the `mode` transport, or `None`
/// when the action declares no result schemas or `mode` does not serve it.
pub fn action_output_schema(action: &ApiActionSpec, mode: ProjectionMode) -> Option<Value> {
    if !crate::mcp::action_eligible(action, mode) {
        return None;
    }
    let payload = result_payload_schema(action)?;
    Some(match (mode, &action.io) {
        (ProjectionMode::Http, _) => {
            branches(vec![envelope_schema(payload), http_failure_schema()])
        }
        (ProjectionMode::Stdio, ActionIo::RawDownload { .. }) => branches(vec![
            file_receipt_schema(Some(payload.clone())),
            envelope_schema(payload),
        ]),
        (ProjectionMode::Stdio, _) => {
            branches(vec![envelope_schema(payload), file_receipt_schema(None)])
        }
    })
}

fn availability_schema() -> Value {
    json!({"type": "object", "properties": {
        "state": {"type": "string", "enum": ["available", "partial", "unavailable", "unknown"]},
        "requirements": {"type": "array", "items": {"type": "object", "properties": {
            "reason": string(),
            "credentialMode": string(),
            "resolution": {"type": "string", "enum": ["user", "administrator"]}
        }, "required": ["reason", "credentialMode", "resolution"]}},
        "message": string()
    }, "required": ["state", "requirements", "message"]})
}

fn action_capabilities_properties() -> Value {
    json!({
        "action": string(),
        "readOnly": {"type": "boolean"},
        "description": string(),
        "documentation": {"type": "object", "description": "Extended usage guidance."},
        "requiredScopeTypes": strings(),
        "listingOf": string(),
        "companionReadActions": strings(),
        "credentialModes": strings(),
        "lookupRequired": {"type": "boolean"},
        "upstreamResourceOwnership": string(),
        "inputSchema": {"type": "object", "description": "JSON Schema of the action inputs."}
    })
}

/// The success object of one discovery helper.
pub fn helper_result_schema(helper: HelperKind) -> Value {
    match helper {
        HelperKind::ServicesList => json!({"type": "object", "properties": {
            "services": {"type": "array", "items": {"type": "object", "properties": {
                "service": string(),
                "displayName": string(),
                "surface": string(),
                "actions": strings(),
                "availability": availability_schema()
            }, "required": ["service", "displayName", "surface", "actions", "availability"]}}
        }, "required": ["services"]}),
        HelperKind::ResourceAccessDescribe => json!({"type": "object", "properties": {
            "service": string(),
            "executionContext": string(),
            "availability": availability_schema(),
            "coverageSemantics": {"type": "string", "enum": ["single_target"]},
            "access": {"type": "array", "items": {"type": "object", "properties": {
                "scope": {"type": "string", "enum": ["resource", "unscoped"]},
                "action": string(),
                "resourceType": string(),
                "enforcement": {"type": "string", "enum": ["request", "results", "command"]},
                "coverage": {"type": "array", "items": {"type": "object", "properties": {
                    "selector": {"type": "object", "properties": {
                        "kind": {"type": "string", "enum": ["exact", "namespace", "all"]},
                        "value": string()
                    }, "required": ["kind"]},
                    "inputs": {"type": "object"},
                    "restricted": {"type": "boolean"}
                }, "required": ["selector", "restricted"]}}
            }, "required": ["scope", "action"]}},
            "registeredResources": {"type": "object", "properties": {
                "source": {"type": "string", "enum": ["broker_configuration"]},
                "items": {"type": "array", "items": {"type": "object", "properties": {
                    "id": string(),
                    "type": string(),
                    "value": string(),
                    "displayName": string(),
                    "inputs": {"type": "object"}
                }, "required": ["id", "type", "value"]}},
                "nextCursor": {"type": ["string", "null"]}
            }, "required": ["source", "items", "nextCursor"]},
            "liveListings": {"type": "array", "items": {"type": "object", "properties": {
                "service": string(),
                "action": string(),
                "resourceType": string()
            }, "required": ["service", "action", "resourceType"]}}
        }, "required": ["service", "executionContext", "availability", "coverageSemantics", "access", "registeredResources"]}),
        HelperKind::ActionsList => json!({"type": "object", "properties": {
            "service": string(),
            "resource": string(),
            "actions": strings()
        }, "required": ["service", "actions"]}),
        HelperKind::ActionsDescribe => {
            let mut properties = action_capabilities_properties();
            let extra = json!({
                "service": string(),
                "sensitiveInputPointers": strings(),
                "sensitiveOutputPointers": strings(),
                "io": {"type": "object", "properties": {"type": string()}, "required": ["type"]},
                "responseKind": string(),
                "exitPolicy": string(),
                "readContentFormats": strings(),
                "responseFormats": strings(),
                "renderedBodyOwners": strings(),
                "optionalRenderedBodyOwnerPrefixes": strings(),
                "resultSchemas": {
                    "type": "object",
                    "description": "Provider payload schemas; present when this connection has no tool for the action.",
                    "properties": {"success": {"type": "object"}, "error": {"type": "object"}},
                    "required": ["success"]
                },
                "mcpTool": {"type": "object", "properties": {
                    "name": string(),
                    "inputSchema": {"type": "object"},
                    "outputSchema": {"type": "object"}
                }, "required": ["name", "inputSchema"]},
                "mcpToolUnavailable": {"type": "string", "enum": ["name_conflict", "name_too_long", "reserved_name"]}
            });
            properties
                .as_object_mut()
                .expect("static properties")
                .extend(extra.as_object().expect("static properties").clone());
            json!({"type": "object", "properties": properties, "required": [
                "service", "action", "readOnly", "description", "requiredScopeTypes",
                "credentialModes", "inputSchema", "io", "responseKind", "exitPolicy"
            ]})
        }
        HelperKind::ServicesDescribe => json!({"type": "object", "properties": {
            "service": string(),
            "displayName": string(),
            "surface": string(),
            "gatewayKind": string(),
            "brokerHosts": strings(),
            "credentialVerificationInputs": strings(),
            "credentialVerificationSupported": {"type": "boolean"},
            "scopeTypes": strings(),
            "resourceScopes": {"type": "object", "additionalProperties": {"type": "object", "properties": {
                "resourceType": string(),
                "selectors": strings()
            }, "required": ["resourceType", "selectors"]}},
            "actions": {"type": "array", "items": {
                "type": "object",
                "properties": action_capabilities_properties(),
                "required": ["action", "readOnly", "description", "requiredScopeTypes", "credentialModes", "inputSchema"]
            }},
            "availability": availability_schema(),
            "scopedMcpReady": {"type": "boolean"},
            "limits": {"type": "object", "description": "The caller's live invocation limits; absent for anonymous callers."}
        }, "required": ["service", "displayName", "surface", "credentialVerificationSupported", "scopeTypes", "actions", "availability"]}),
    }
}

/// The MCP `outputSchema` of a discovery helper on the `mode` transport.
pub fn helper_output_schema(helper: HelperKind, mode: ProjectionMode) -> Value {
    let mut helper_schema = helper_result_schema(helper);
    helper_schema["description"] = json!("Discovery result.");
    match mode {
        ProjectionMode::Http => branches(vec![helper_schema, http_failure_schema()]),
        ProjectionMode::Stdio => branches(vec![
            helper_schema,
            file_receipt_schema(None),
            envelope_schema(shared_failure_result_schema()),
        ]),
    }
}

#[cfg(test)]
mod tests;
