//! MCP delivery checks shared by the wire tests: every tool result's
//! `structuredContent` must validate against the tool's advertised
//! `outputSchema` (as advertised, not strictly), and a discovery helper's
//! successful result must also match its typed result schema strictly.
//!
//! When `AGENT_ACCESS_TEST_MCP_CAPTURE` names an absolute file path, every
//! listed tool and every tool result is appended to it as one JSON line for
//! client-acceptance checks outside the repository. Unset means no capture.
use serde_json::{Value, json};
use std::io::Write;

const CAPTURE_ENV: &str = "AGENT_ACCESS_TEST_MCP_CAPTURE";

fn capture(record: Value) {
    let Some(path) = std::env::var_os(CAPTURE_ENV) else {
        return;
    };
    let path = std::path::PathBuf::from(path);
    assert!(
        path.is_absolute(),
        "{CAPTURE_ENV} must name an absolute file path"
    );
    let mut line = serde_json::to_vec(&record).unwrap();
    line.push(b'\n');
    // One append-mode write per record, so parallel tests interleave lines.
    std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .and_then(|mut file| file.write_all(&line))
        .unwrap_or_else(|error| panic!("cannot append to {CAPTURE_ENV}: {error}"));
}

/// Captures each listed tool definition.
pub(in crate::tests) fn capture_tools(transport: &str, tools: &[Value]) {
    for tool in tools {
        let mut record = json!({
            "kind": "tool", "transport": transport, "name": tool["name"],
            "description": tool["description"], "inputSchema": tool["inputSchema"],
        });
        if let Some(schema) = tool.get("outputSchema") {
            record["outputSchema"] = schema.clone();
        }
        capture(record);
    }
}

/// Captures one `tools/call` JSON-RPC response and checks its structured
/// content against `tool`'s advertised output schema.
pub(in crate::tests) fn check_call(
    transport: &str,
    name: &str,
    tool: Option<&Value>,
    response: &Value,
) {
    let Some(result) = response.get("result") else {
        return;
    };
    let structured = result.get("structuredContent");
    let mut record = json!({
        "kind": "result", "transport": transport, "name": name,
        "isError": result.get("isError").and_then(Value::as_bool).unwrap_or(false),
    });
    if let Some(structured) = structured {
        record["structuredContent"] = structured.clone();
    }
    capture(record);
    let (Some(structured), Some(schema)) =
        (structured, tool.and_then(|tool| tool.get("outputSchema")))
    else {
        return;
    };
    check_structured(name, schema, structured);
    if result.get("isError").and_then(Value::as_bool) != Some(true)
        && let Some(helper) = agent_access_core::mcp::HelperKind::from_name(name)
        && let Err(problem) = agent_access_provider::test_support::check_strict_conformance(
            &agent_access_core::output_schema::helper_result_schema(helper),
            structured,
        )
    {
        panic!(
            "{name} helper result does not match its result schema strictly: {problem}\n{structured}"
        );
    }
}

/// Validates `structured` against the advertised `schema`.
pub(in crate::tests) fn check_structured(name: &str, schema: &Value, structured: &Value) {
    let validator = jsonschema::validator_for(schema)
        .unwrap_or_else(|error| panic!("{name} advertises an invalid outputSchema: {error}"));
    let problems = validator
        .iter_errors(structured)
        .map(|error| {
            format!(
                "at {} (schema {}): {error}",
                error.instance_path(),
                error.schema_path()
            )
        })
        .collect::<Vec<_>>();
    assert!(
        problems.is_empty(),
        "{name} structuredContent does not match its advertised outputSchema: {}\n{structured}",
        problems.join("; ")
    );
}
