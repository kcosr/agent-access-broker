//! Authenticated broker redirects never send an identity token to another origin.
use std::process::Command;
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{method, path},
};

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn broker_redirects_are_rejected_for_json_upload_and_download() {
    let target = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200).set_body_string("redirect target"))
        .mount(&target)
        .await;
    let temporary = tempfile::tempdir().unwrap();
    let config = temporary.path().join("client.toml");
    std::fs::write(&config, "[identity]\ndisabled = false\nheader = \"X-Agent-Access-Identity-Token\"\nscheme = \"raw\"\n").unwrap();
    let upload = temporary.path().join("upload.txt");
    let download = temporary.path().join("download.txt");
    std::fs::write(&upload, "fixture upload").unwrap();
    std::fs::write(&download, "existing destination").unwrap();
    for status in [301, 302, 303, 307, 308] {
        for (route, args) in [
            (
                "/v1/invoke/jira/issue.view",
                vec!["jira", "issue", "view", "PROJ-1"],
            ),
            (
                "/v1/invoke/jira/attachment.add",
                vec![
                    "jira",
                    "issue",
                    "attach",
                    "PROJ-1",
                    upload.to_str().unwrap(),
                ],
            ),
            (
                "/v1/invoke/jira/attachment.download",
                vec![
                    "jira",
                    "issue",
                    "attachment",
                    "download",
                    "PROJ-1",
                    "10001",
                    "--output",
                    download.to_str().unwrap(),
                ],
            ),
        ] {
            let broker = MockServer::start().await;
            Mock::given(method("POST"))
                .and(path(route))
                .respond_with(ResponseTemplate::new(status).insert_header(
                    "Location",
                    format!("{}/private-destination?secret=never-print", target.uri()),
                ))
                .expect(1)
                .mount(&broker)
                .await;
            let mut command = Command::new(env!("CARGO_BIN_EXE_agent-access"));
            for (key, _) in std::env::vars_os() {
                if key.to_string_lossy().starts_with("AGENT_ACCESS_") {
                    command.env_remove(key);
                }
            }
            let output = command
                .args([
                    "--config",
                    config.to_str().unwrap(),
                    "--url",
                    &broker.uri(),
                    "--token-value",
                    "synthetic-identity-token",
                ])
                .args(args)
                .output()
                .unwrap();
            let stderr = String::from_utf8_lossy(&output.stderr);
            assert_eq!(output.status.code(), Some(5), "{status} {route}: {stderr}");
            assert!(
                stderr.contains(&format!("HTTP {status}; redirects are disabled")),
                "{route}: {stderr}"
            );
            assert!(!stderr.contains("private-destination"), "{stderr}");
            assert!(!stderr.contains("never-print"), "{stderr}");
            assert!(!stderr.contains("synthetic-identity-token"), "{stderr}");
            broker.verify().await;
            let requests = broker.received_requests().await.unwrap();
            assert_eq!(requests.len(), 1, "{route}");
            assert_eq!(
                requests[0].headers["x-agent-access-identity-token"],
                "synthetic-identity-token"
            );
            assert!(
                target.received_requests().await.unwrap().is_empty(),
                "redirect reached another origin: {status} {route}"
            );
            assert_eq!(std::fs::read(&download).unwrap(), b"existing destination");
        }
    }
}
