//! The server's compact receipt after a completed mutation cannot be presented.
#[path = "jira_catalog.rs"]
mod jira_catalog;

use serde_json::{Value, json};

pub fn catalog() -> Value {
    let mut catalog = jira_catalog::catalog();
    catalog["services"][0]["actions"]
        .as_array_mut()
        .unwrap()
        .retain(|action| action["action"] == "issue.update");
    catalog
}

pub fn inputs() -> Value {
    json!({"issue":"PROJ-1","summary":"Updated title"})
}

pub fn receipt() -> Value {
    let message = "The mutation completed, but its response could not be produced. Do not repeat the operation.";
    json!({
        "agentRequestId":"agent", "brokerRequestId":"broker",
        "service":"jira", "action":"issue.update", "decision":"error",
        "reasonCode":"upstream_protocol_failed", "reason":message,
        "resourceScopes":{"project":["PROJ"]}, "error":{"message":message},
        "result":{"mutationStatus":"applied","retrySafe":false}
    })
}
