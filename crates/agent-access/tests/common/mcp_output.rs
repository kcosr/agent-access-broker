//! Stdio MCP delivery checks shared by the subprocess harnesses. Each
//! harness states its process's `--output-schemas` selection explicitly.
//! With `on`, every helper must advertise an `outputSchema` and every tool
//! result's `structuredContent` must validate against the tool's advertised
//! schema (as advertised, not strictly), covering envelopes, file receipts,
//! local output failures and helper results; a result for a tool the
//! connection never listed fails rather than skipping. With `off`, no tool
//! may advertise one.
//!
//! When `AGENT_ACCESS_TEST_MCP_CAPTURE` names an absolute file path, every
//! listed tool and every tool result is appended to it as one JSON line for
//! client-acceptance checks outside the repository. Unset means no capture.
//! Each record carries the test process ID, the transport, the connection
//! (one per subprocess), its view and the effective selection, so a probe
//! pairs results with the definitions that connection advertised.
#![allow(dead_code)]
use agent_access_core::mcp::{OutputSchemas, ProjectionMode, helper_definitions, is_helper};
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::io::Write;
use std::sync::atomic::{AtomicU64, Ordering};

const CAPTURE_ENV: &str = "AGENT_ACCESS_TEST_MCP_CAPTURE";

/// The `mcp serve` arguments selecting `selection`; `None` omits the option.
pub fn output_schema_arguments(selection: Option<OutputSchemas>) -> Vec<&'static str> {
    match selection {
        Some(mode) => vec!["--output-schemas", mode.as_str()],
        None => Vec::new(),
    }
}

/// The tool definitions one stdio MCP process advertised, by name.
pub struct AdvertisedTools {
    output_schemas: OutputSchemas,
    connection: String,
    view: Option<String>,
    tools: BTreeMap<String, Value>,
}

impl AdvertisedTools {
    /// A process started with `selection` (`None`: the option omitted) on
    /// `view` (`None`: the aggregate view).
    pub fn new(selection: Option<OutputSchemas>, view: Option<&str>) -> Self {
        static CONNECTIONS: AtomicU64 = AtomicU64::new(0);
        Self {
            output_schemas: selection.unwrap_or(OutputSchemas::CONNECTION_DEFAULT),
            connection: format!(
                "stdio-{}-{}",
                std::process::id(),
                CONNECTIONS.fetch_add(1, Ordering::Relaxed)
            ),
            view: view.map(str::to_owned),
            tools: BTreeMap::new(),
        }
    }

    /// The effective selection of this process.
    pub fn output_schemas(&self) -> OutputSchemas {
        self.output_schemas
    }

    /// Whether a `tools/call` of `name` can be checked without listing.
    /// Helpers are static per transport and selection, so their expected
    /// definitions are this selection's projection.
    pub fn knows(&self, name: &str) -> bool {
        self.tools.contains_key(name) || is_helper(name)
    }

    fn capture(&self, mut record: Value) {
        let Some(path) = std::env::var_os(CAPTURE_ENV) else {
            return;
        };
        // Tools and results pair within one test process and connection:
        // different tests and processes can serve different definitions
        // under the same tool name.
        record["pid"] = json!(std::process::id());
        record["transport"] = json!("stdio");
        record["connection"] = json!(self.connection);
        record["view"] = json!(self.view.as_deref().unwrap_or("aggregate"));
        record["outputSchemas"] = json!(self.output_schemas);
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

    fn check_definition(&self, tool: &Value) {
        let name = tool["name"].as_str().unwrap_or_default();
        match self.output_schemas {
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

    /// Checks, records and captures the tools of one `tools/list` response.
    pub fn record_listing(&mut self, response: &Value) {
        let Some(tools) = response["result"]["tools"].as_array() else {
            return;
        };
        for tool in tools {
            self.check_definition(tool);
            let mut record = json!({
                "kind": "tool", "name": tool["name"],
                "description": tool["description"], "inputSchema": tool["inputSchema"],
                "outputSchemaAdvertised": tool.get("outputSchema").is_some(),
            });
            if let Some(schema) = tool.get("outputSchema") {
                record["outputSchema"] = schema.clone();
            }
            self.capture(record);
            if let Some(name) = tool["name"].as_str() {
                self.tools.insert(name.to_owned(), tool.clone());
            }
        }
    }

    /// The definition this process advertised for `name`: as listed, or for
    /// an unlisted helper, this selection's static helper projection.
    fn definition(&self, name: &str) -> Option<Value> {
        if let Some(tool) = self.tools.get(name) {
            return Some(tool.clone());
        }
        helper_definitions(ProjectionMode::Stdio, self.output_schemas)
            .into_iter()
            .find(|tool| tool["name"] == name)
    }

    /// Captures one `tools/call` response and checks its structured content
    /// against the tool's advertised output schema.
    pub fn check_call(&self, name: &str, response: &Value) {
        let Some(result) = response.get("result") else {
            return;
        };
        let structured = result.get("structuredContent");
        let mut record = json!({
            "kind": "result", "name": name,
            "isError": result.get("isError").and_then(Value::as_bool).unwrap_or(false),
        });
        if let Some(structured) = structured {
            record["structuredContent"] = structured.clone();
        }
        self.capture(record);
        let Some(structured) = structured else {
            return;
        };
        let tool = self.definition(name).unwrap_or_else(|| {
            panic!("{name} returned structuredContent on a connection that never listed it")
        });
        self.check_definition(&tool);
        // A tool whose action declares no result schemas advertises none.
        let Some(schema) = tool.get("outputSchema") else {
            return;
        };
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
}
