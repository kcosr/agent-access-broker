//! The shipped stdio wrapper's handling of nonconforming SDK input.
use super::*;

fn start(directory: &tempfile::TempDir) -> McpProcess {
    let config = directory.path().join("client.toml");
    std::fs::write(
        &config,
        "[service]\nurl = 'http://127.0.0.1:9'\n[identity]\ndisabled = true\n",
    )
    .unwrap();
    McpProcess::start(&config)
}

async fn next_message(process: &mut McpProcess) -> Value {
    let line = tokio::time::timeout(RPC_TIMEOUT, process.messages.recv())
        .await
        .expect("MCP reply timed out")
        .expect("MCP stdout closed");
    serde_json::from_str(&line).expect("MCP stdout must contain JSON")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn first_request_without_metadata_keeps_waiting_for_initialization() {
    let directory = tempfile::tempdir().unwrap();
    let mut process = start(&directory);
    let response = process.send_request("tools/list", json!({})).await;
    assert_eq!(response["error"]["code"], -32602, "{response}");
    assert!(
        response["error"]["message"]
            .as_str()
            .unwrap()
            .contains("_meta")
    );
    process.initialize().await;
    assert_eq!(
        process.send_request("ping", json!({})).await["result"],
        json!({})
    );
    process.finish().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn method_with_result_or_error_is_an_invalid_request_even_when_null() {
    let directory = tempfile::tempdir().unwrap();
    let mut process = start(&directory);
    process.initialize().await;
    for field in ["result", "error"] {
        for value in [Value::Null, json!({"secret":"must-not-be-echoed"})] {
            let mut message = json!({"jsonrpc":"2.0","id":900,"method":"ping"});
            message[field] = value;
            process.send(message);
            let response = next_message(&mut process).await;
            assert_eq!(response["error"]["code"], -32600, "{response}");
            assert_eq!(response["error"]["message"], "Invalid request");
            assert!(!response.to_string().contains("must-not-be-echoed"));
        }
    }
    assert_eq!(
        process.send_request("ping", json!({})).await["result"],
        json!({})
    );
    process.finish().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn exact_sixteen_mib_frame_is_dropped_without_reply_and_stdio_survives() {
    const LIMIT: usize = 16 * 1024 * 1024;
    let directory = tempfile::tempdir().unwrap();
    let mut process = start(&directory);
    process.initialize().await;
    for (id, length) in [(900, LIMIT - 1), (901, LIMIT)] {
        let mut frame =
            serde_json::to_vec(&json!({"jsonrpc":"2.0","id":id,"method":"ping"})).unwrap();
        // JSON permits trailing whitespace; only the transport frame length changes.
        frame.resize(length, b' ');
        let stdin = process.stdin.as_mut().unwrap();
        stdin.write_all(&frame).unwrap();
        stdin.write_all(b"\n").unwrap();
        stdin.flush().unwrap();
        if length < LIMIT {
            let response = next_message(&mut process).await;
            assert_eq!(response["id"], id);
            assert_eq!(response["result"], json!({}));
        }
    }
    // A reply for id 901 would fail send_request's unexpected-response assertion.
    assert_eq!(
        process.send_request("ping", json!({})).await["result"],
        json!({})
    );
    process.stdin.take();
    assert!(
        tokio::time::timeout(RPC_TIMEOUT, process.messages.recv())
            .await
            .unwrap()
            .is_none()
    );
    process.finish().await;
}
