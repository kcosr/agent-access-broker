//! MCP delivery checks shared by the wire tests. Each listing and result
//! belongs to one connection whose output-schema selection the test states
//! explicitly. With `on`, every helper must advertise an `outputSchema` and
//! every tool result's `structuredContent` must validate against the tool's
//! advertised schema (as advertised, not strictly); a result for a tool the
//! connection never listed or projected fails rather than skipping. With
//! `off`, no tool may advertise one. Independently of the selection, a
//! discovery helper's successful result must match its typed result schema
//! strictly.
//!
//! When `AGENT_ACCESS_TEST_MCP_CAPTURE` names an absolute file path, every
//! listed tool and every tool result is appended to it as one JSON line for
//! client-acceptance checks outside the repository. Unset means no capture.
//! Each record carries the test process ID, the transport, the connection
//! (the MCP session), its endpoint path and the effective selection, so a
//! probe pairs results with the definitions that connection advertised.
use agent_access_core::mcp::{HelperKind, OutputSchemas, is_helper};
use serde_json::{Value, json};
use std::io::Write;

const CAPTURE_ENV: &str = "AGENT_ACCESS_TEST_MCP_CAPTURE";

/// One connection's listings and results, as a client sees them.
pub(in crate::tests) struct Connection<'a> {
    /// The MCP session ID.
    pub(in crate::tests) id: &'a str,
    /// The endpoint path, without its query.
    pub(in crate::tests) path: &'a str,
    /// The effective selection: the requested value, or the default when omitted.
    pub(in crate::tests) output_schemas: OutputSchemas,
}

fn capture(connection: &Connection<'_>, mut record: Value) {
    let Some(path) = std::env::var_os(CAPTURE_ENV) else {
        return;
    };
    // Tools and results pair within one test process and connection:
    // different tests and connections can serve different definitions
    // under the same tool name.
    record["pid"] = json!(std::process::id());
    record["transport"] = json!("http");
    record["connection"] = json!(connection.id);
    record["view"] = json!(connection.path);
    record["outputSchemas"] = json!(connection.output_schemas);
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

/// Checks one advertised definition against its connection's selection.
pub(in crate::tests) fn check_definition(output_schemas: OutputSchemas, tool: &Value) {
    let name = tool["name"].as_str().unwrap_or_default();
    match output_schemas {
        OutputSchemas::Off => assert!(
            tool.get("outputSchema").is_none(),
            "{name} advertises an outputSchema without on selected"
        ),
        OutputSchemas::On => assert!(
            !is_helper(name) || tool.get("outputSchema").is_some(),
            "helper {name} advertises no outputSchema with on selected"
        ),
    }
}

/// Checks and captures each listed tool definition.
pub(in crate::tests) fn capture_tools(connection: &Connection<'_>, tools: &[Value]) {
    for tool in tools {
        check_definition(connection.output_schemas, tool);
        let mut record = json!({
            "kind": "tool", "name": tool["name"],
            "description": tool["description"], "inputSchema": tool["inputSchema"],
            "outputSchemaAdvertised": tool.get("outputSchema").is_some(),
        });
        if let Some(schema) = tool.get("outputSchema") {
            record["outputSchema"] = schema.clone();
        }
        capture(connection, record);
    }
}

/// Captures one `tools/call` JSON-RPC response and checks it against `tool`,
/// the definition `connection` advertised for `name`.
pub(in crate::tests) fn check_call(
    connection: &Connection<'_>,
    name: &str,
    tool: Option<&Value>,
    response: &Value,
) {
    let Some(result) = response.get("result") else {
        return;
    };
    let structured = result.get("structuredContent");
    let is_error = result.get("isError").and_then(Value::as_bool) == Some(true);
    let mut record = json!({"kind": "result", "name": name, "isError": is_error});
    if let Some(structured) = structured {
        record["structuredContent"] = structured.clone();
    }
    capture(connection, record);
    let Some(structured) = structured else {
        return;
    };
    // The helper result contract holds whatever the connection advertises.
    if !is_error
        && let Some(helper) = HelperKind::from_name(name)
        && let Err(problem) = agent_access_provider::test_support::check_strict_conformance(
            &agent_access_core::output_schema::helper_result_schema(helper),
            structured,
        )
    {
        panic!(
            "{name} helper result does not match its result schema strictly: {problem}\n{structured}"
        );
    }
    let tool = tool.unwrap_or_else(|| {
        panic!(
            "{name} returned structuredContent on a connection that never listed or projected it"
        )
    });
    check_definition(connection.output_schemas, tool);
    // A tool whose action declares no result schemas advertises none.
    if let Some(schema) = tool.get("outputSchema") {
        check_structured(name, schema, structured);
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
