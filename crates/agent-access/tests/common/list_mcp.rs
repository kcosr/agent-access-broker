//! Guarded stdio MCP client for native collection acceptance tests.
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

    pub async fn request(&mut self, method: &str, params: Value) -> Value {
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
