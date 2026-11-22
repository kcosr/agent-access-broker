//! The result schemas of every imported OpenAPI operation: the
//! `upstreamHttp` wrapper `OpenApiProvider::invoke` builds and the write
//! receipt fields it adds. The status is any integer and the body an open
//! leaf, whatever responses the operation declares, so a refresh or
//! acceptance never invalidates a client's cached validator.
use agent_access_provider::ActionResultSchemas;
use serde_json::{Value, json};

fn upstream_http(description: &str) -> Value {
    json!({
        "type": "object",
        "description": description,
        "properties": {
            "status": {"type": "integer", "description": "The upstream HTTP status."},
            "body": {"description": "The decoded JSON response body; null when the response had none."}
        },
        "required": ["status", "body"]
    })
}

pub(crate) fn result_schemas() -> ActionResultSchemas {
    ActionResultSchemas::new(json!({
        "type": "object",
        "properties": {
            "upstreamHttp": upstream_http("The upstream response."),
            "mutationStatus": {"const": "applied_unverified", "description": "Present for writes: the operation completed, but its effect is unverified."},
            "retrySafe": {"const": false, "description": "Present for writes."}
        },
        "required": ["upstreamHttp"]
    }))
    .with_error(json!({
        "type": "object",
        "properties": {
            "upstreamHttp": upstream_http("The upstream error response, when its body matched the operation's declared response."),
            "operationDispatched": {"type": "boolean", "description": "Present for writes: whether the request may have been sent."}
        }
    }))
}
