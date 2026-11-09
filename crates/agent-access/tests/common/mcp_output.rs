//! Stdio MCP delivery checks shared by the subprocess harnesses: every tool
//! result's `structuredContent` must validate against the tool's advertised
//! `outputSchema` (as advertised, not strictly), covering envelopes, file
//! receipts, local output failures and helper results.
//!
//! When `AGENT_ACCESS_TEST_MCP_CAPTURE` names an absolute file path, every
//! listed tool and every tool result is appended to it as one JSON line for
//! client-acceptance checks outside the repository. Unset means no capture.
#![allow(dead_code)]
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::io::Write;

const CAPTURE_ENV: &str = "AGENT_ACCESS_TEST_MCP_CAPTURE";

fn capture(mut record: Value) {
    let Some(path) = std::env::var_os(CAPTURE_ENV) else {
        return;
    };
    // Tools and results pair within one test process: different tests can
    // serve different catalogs under the same tool name.
    record["pid"] = json!(std::process::id());
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

/// The tool definitions a stdio MCP process advertised, by name.
#[derive(Default)]
pub struct AdvertisedTools(BTreeMap<String, Value>);

impl AdvertisedTools {
    /// Whether a `tools/call` of `name` can be checked without listing:
    /// helpers have static output schemas on every view.
    pub fn knows(&self, name: &str) -> bool {
        self.0.contains_key(name) || agent_access_core::mcp::is_helper(name)
    }

    /// Records and captures the tools of one `tools/list` response.
    pub fn record_listing(&mut self, response: &Value) {
        let Some(tools) = response["result"]["tools"].as_array() else {
            return;
        };
        for tool in tools {
            let mut record = json!({
                "kind": "tool", "transport": "stdio", "name": tool["name"],
                "description": tool["description"], "inputSchema": tool["inputSchema"],
            });
            if let Some(schema) = tool.get("outputSchema") {
                record["outputSchema"] = schema.clone();
            }
            capture(record);
            if let Some(name) = tool["name"].as_str() {
                self.0.insert(name.to_owned(), tool.clone());
            }
        }
    }

    fn output_schema(&self, name: &str) -> Option<Value> {
        if let Some(tool) = self.0.get(name) {
            return tool.get("outputSchema").cloned();
        }
        agent_access_core::mcp::helper_definitions(agent_access_core::mcp::ProjectionMode::Stdio)
            .into_iter()
            .find(|tool| tool["name"] == name)
            .and_then(|tool| tool.get("outputSchema").cloned())
    }

    /// Captures one `tools/call` response and checks its structured content
    /// against the tool's advertised output schema.
    pub fn check_call(&self, name: &str, response: &Value) {
        let Some(result) = response.get("result") else {
            return;
        };
        let structured = result.get("structuredContent");
        let mut record = json!({
            "kind": "result", "transport": "stdio", "name": name,
            "isError": result.get("isError").and_then(Value::as_bool).unwrap_or(false),
        });
        if let Some(structured) = structured {
            record["structuredContent"] = structured.clone();
        }
        capture(record);
        let (Some(structured), Some(schema)) = (structured, self.output_schema(name)) else {
            return;
        };
        let validator = jsonschema::validator_for(&schema)
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
}
