//! Guarded stdio MCP client for native collection acceptance tests.
#[path = "mcp_output.rs"]
mod mcp_output;

use serde_json::{Value, json};
use std::{
    io::{BufRead, BufReader, Write},
    process::{Child, ChildStdin, Command, Stdio},
};
pub struct StdioMcp {
    child: Child,
    stdin: Option<ChildStdin>,
    responses: tokio::sync::mpsc::UnboundedReceiver<String>,
    next_id: u64,
    tools: mcp_output::AdvertisedTools,
}

impl StdioMcp {
    pub fn start(mut command: Command) -> Self {
        for (key, _) in std::env::vars_os() {
            if key.to_string_lossy().starts_with("AGENT_ACCESS_") {
                command.env_remove(key);
            }
        }
        let mut child = command
            .args(["mcp", "serve"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let stdin = child.stdin.take();
        let stdout = child.stdout.take().unwrap();
        let (sender, responses) = tokio::sync::mpsc::unbounded_channel();
        std::thread::spawn(move || {
            for line in BufReader::new(stdout).lines() {
                let Ok(line) = line else { break };
                if sender.send(line).is_err() {
                    break;
                }
            }
        });
        Self {
            child,
            stdin,
            responses,
            next_id: 1,
            tools: Default::default(),
        }
    }

    fn send(&mut self, value: Value) {
        let stdin = self.stdin.as_mut().unwrap();
        serde_json::to_writer(&mut *stdin, &value).unwrap();
        stdin.write_all(b"\n").unwrap();
        stdin.flush().unwrap();
    }

    pub fn notify(&mut self, method: &str, params: Value) {
        self.send(json!({"jsonrpc":"2.0","method":method,"params":params}));
    }

    /// Sends one request. A `tools/call` result's structured content is
    /// checked against the tool's advertised output schema, listing the
    /// tools first, as a client would, when the tool was not listed yet.
    pub async fn request(&mut self, method: &str, params: Value) -> Value {
        let call = (method == "tools/call")
            .then(|| params["name"].as_str().unwrap_or_default().to_owned());
        if let Some(name) = &call
            && !self.tools.knows(name)
        {
            self.list_advertised_tools().await;
        }
        let response = self.send_request(method, params).await;
        match &call {
            Some(name) => self.tools.check_call(name, &response),
            None if method == "tools/list" => self.tools.record_listing(&response),
            None => {}
        }
        response
    }

    async fn list_advertised_tools(&mut self) {
        let mut params = json!({});
        loop {
            let page = self.send_request("tools/list", params).await;
            self.tools.record_listing(&page);
            match page["result"]["nextCursor"].as_str() {
                Some(cursor) => params = json!({"cursor": cursor}),
                None => break,
            }
        }
    }

    async fn send_request(&mut self, method: &str, params: Value) -> Value {
        let id = self.next_id;
        self.next_id += 1;
        self.send(json!({"jsonrpc":"2.0","id":id,"method":method,"params":params}));
        tokio::time::timeout(std::time::Duration::from_secs(15), async {
            loop {
                let line = self.responses.recv().await.expect("stdio MCP closed");
                let value: Value = serde_json::from_str(&line).unwrap();
                if value["id"] == id {
                    return value;
                }
                assert!(
                    value.get("id").is_none(),
                    "unexpected MCP response: {value}"
                );
            }
        })
        .await
        .expect("stdio MCP response timed out")
    }

    pub async fn finish(mut self) {
        self.stdin.take();
        tokio::time::timeout(std::time::Duration::from_secs(15), async {
            loop {
                if let Some(status) = self.child.try_wait().unwrap() {
                    assert!(status.success(), "stdio MCP failed: {status}");
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("stdio MCP did not exit");
    }
}

impl Drop for StdioMcp {
    fn drop(&mut self) {
        self.stdin.take();
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}
