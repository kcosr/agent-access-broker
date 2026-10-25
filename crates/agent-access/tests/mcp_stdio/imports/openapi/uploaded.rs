//! Uploaded documents use the ordinary accepted plans and invocation surfaces.
use super::*;
use sha2::{Digest, Sha256};

const DOCUMENT_LIMIT: usize = 4 * 1024 * 1024;

fn upload(config: &Path, document: &Path, current: &Value) -> Value {
    let (version, revision) = versions(current);
    run(
        config,
        &[
            "admin",
            "imports",
            "upload-document",
            "readers",
            "--document-file",
            document.to_str().unwrap(),
            "--expected-version",
            &version,
            "--expected-catalog-revision",
            &revision,
        ],
    )
}

fn accept_request(current: &Value, manifest_hash: &Value) -> Value {
    let (version, revision) = versions(current);
    json!({
        "expectedVersion":version.parse::<u64>().unwrap(),
        "expectedCatalogRevision":revision.parse::<u64>().unwrap(),
        "manifestHash":manifest_hash,
        "confirmAffectedGrants":true,
        "selections":[
            {"source":{"operationId":"readItem"},"action":"item.read","readOnly":true},
            {"source":{"operationId":"searchItems"},"action":"item.search","readOnly":true}
        ]
    })
}

fn accept(directory: &FixtureDir, config: &Path, current: &Value) -> Value {
    let request = write_request(
        directory.path(),
        "accept-upload.json",
        accept_request(current, &current["result"]["preview"]["manifestHash"]),
    );
    run(
        config,
        &[
            "admin",
            "imports",
            "accept",
            "readers",
            "--request-file",
            &request,
        ],
    )
}

fn action<'a>(detail: &'a Value, id: &str) -> &'a Value {
    detail["result"]["service"]["actions"]
        .as_array()
        .unwrap()
        .iter()
        .find(|action| action["definition"]["action"] == id)
        .unwrap()
}

fn assert_generation_unchanged(before: &Value, after: &Value) {
    assert_eq!(after["result"]["service"], before["result"]["service"]);
    assert_eq!(
        after["result"]["catalogRevision"],
        before["result"]["catalogRevision"]
    );
}

fn assert_document_metadata(detail: &Value, filename: &str, bytes: &[u8]) {
    assert_eq!(
        detail["result"]["service"]["document"],
        json!({
            "filename":filename,
            "byteLength":bytes.len(),
            "sha256":format!("{:x}", Sha256::digest(bytes))
        })
    );
}

fn assert_cli_form(config: &Path, requests: &ApiRequests, updated: bool) {
    let mut inputs = form_inputs();
    if updated {
        inputs["body"]["revision"] = json!("2");
    }
    let before = requests.len();
    let result = run(
        config,
        &[
            "invoke",
            "readers.item.search",
            "--input-json",
            &inputs.to_string(),
        ],
    );
    assert_eq!(result["result"]["upstreamHttp"]["body"]["value"], PAYLOAD);
    if updated {
        assert_eq!(requests.len(), before + 1);
        let request = requests.last();
        assert_eq!(request.method, "POST");
        assert_eq!(request.path, "/api/search");
        assert_eq!(
            request.authorization,
            Some(basic(SERVICE_USER, SERVICE_SECRET))
        );
        assert_eq!(
            request.content_type.as_deref(),
            Some("application/x-www-form-urlencoded")
        );
        assert_eq!(request.body, [FORM_BYTES, b"&revision=2"].concat());
    } else {
        assert_form_request(requests, before, false);
    }
}

fn changed_form_document(swagger: bool, endpoint: &str) -> Value {
    let mut changed = document(swagger, endpoint);
    let operation = &mut changed["paths"]["/search"]["post"];
    if swagger {
        operation["parameters"]
            .as_array_mut()
            .unwrap()
            .push(json!({"in":"formData","name":"revision","required":true,"type":"string"}));
    } else {
        let schema =
            &mut operation["requestBody"]["content"]["application/x-www-form-urlencoded"]["schema"];
        schema["properties"]["revision"] = json!({"type":"string"});
        schema["required"]
            .as_array_mut()
            .unwrap()
            .push(json!("revision"));
    }
    changed
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn swagger_upload_preserves_generations_and_restarts_without_document_access() {
    exercise_uploaded_document(true).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn openapi_upload_preserves_generations_and_restarts_without_document_access() {
    exercise_uploaded_document(false).await;
}

async fn exercise_uploaded_document(swagger: bool) {
    let requests = ApiRequests::default();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("http://{}/api", listener.local_addr().unwrap());
    let api = Router::new()
        .fallback(api_call)
        .with_state(requests.clone());
    let _api = ServerTask(tokio::spawn(async move {
        axum::serve(listener, api).await.unwrap()
    }));
    let application = isolated_broker();
    let directory = application.directory().clone();
    let base = application.public_url();
    directory
        .secret_file("key", URL_SAFE_NO_PAD.encode([68u8; 32]))
        .unwrap();
    let hash = directory
        .secret_file("hash", URL_SAFE_NO_PAD.encode([69u8; 32]))
        .unwrap();
    let (admin, agent, _, _) = seed_import_identities(&directory, &hash);
    let admin_config = config_file(directory.path(), "admin", &base, &admin);
    let agent_config = config_file(directory.path(), "agent", &base, &agent);
    // There is no document listener or document URL. Only the actual API is
    // permitted, and its recorder observes every arrival, including bad auth.
    let permissions = ImportPermissions {
        allowed_kinds: vec!["openapi_http".into()],
        allowed_endpoints: vec![endpoint.clone()],
    };
    let broker = application
        .config_document(import_document(
            &directory,
            &permissions,
            &format!("{base}/mcp"),
        ))
        .start()
        .await
        .unwrap();
    let request = write_request(
        directory.path(),
        "create-upload.json",
        json!({
            "service":"readers","displayName":"Uploaded operations","adapterKind":"openapi_http",
            "endpoint":endpoint,"connectionSettings":{"definitionSource":"upload","securityScheme":"access"},
            "executionBindings":[{"ownerMode":"service","mechanism":"static_token","delivery":{"kind":"basic"},"status":"configured"}],
            "discovery":{"kind":"anonymous"}
        }),
    );
    let created = run(
        &admin_config,
        &["admin", "imports", "create", "--request-file", &request],
    );
    assert_input_contract(&created["result"], false);
    let secret = directory
        .secret_file("service.secret", format!("{SERVICE_SECRET}\n"))
        .unwrap();
    let (version, revision) = versions(&created);
    let current = run(
        &admin_config,
        &[
            "admin",
            "imports",
            "credentials",
            "put",
            "readers",
            "execution",
            "--expected-version",
            &version,
            "--expected-catalog-revision",
            &revision,
            "--username",
            SERVICE_USER,
            "--secret-file",
            secret.to_str().unwrap(),
        ],
    );
    let source = directory.join("uploaded.json");
    let serialized = serde_json::to_vec(&document(swagger, &endpoint)).unwrap();
    // Whitespace is deliberately significant to the uploaded-byte metadata.
    let original = [b" \n".as_slice(), serialized.as_slice(), b"\r\n"].concat();
    std::fs::write(&source, &original).unwrap();
    let preview = upload(&admin_config, &source, &current);
    assert_document_metadata(&preview, "uploaded.json", &original);
    assert!(!preview.to_string().contains(source.to_str().unwrap()));
    let original_manifest_hash = preview["result"]["preview"]["manifestHash"].clone();
    assert!(original_manifest_hash.is_string(), "{preview}");
    assert_eq!(
        preview["result"]["preview"]["manifest"]["tools"]
            .as_array()
            .unwrap()
            .len(),
        7
    );
    assert_input_contract(&preview["result"], false);
    let accepted = accept(&directory, &admin_config, &preview);
    let (version, revision) = versions(&accepted);
    run(
        &admin_config,
        &[
            "admin",
            "imports",
            "status",
            "readers",
            "enabled",
            "--expected-version",
            &version,
            "--expected-catalog-revision",
            &revision,
        ],
    );
    grant(
        &admin_config,
        "agent",
        "readers",
        "service",
        &["item.read", "item.search"],
    );
    assert_eq!(
        requests.len(),
        0,
        "upload and publication never fetch a document or call the API"
    );
    assert_cli_form(&agent_config, &requests, false);

    let mut http = HttpMcp::start(&base, &agent, true).await;
    let before = requests.len();
    let read = http
        .call(
            "tools/call",
            json!({"name":"readItem","arguments":{"inputs":{"path":{"id":"ABC-12"}}}}),
        )
        .await;
    assert_eq!(read["result"]["isError"], false, "{read}");
    assert_read_request(&requests, before, false);
    let mut stdio = McpProcess::start_scoped(&agent_config, "readers");
    stdio.initialize().await;
    let before = requests.len();
    let form = stdio
        .request(
            "tools/call",
            json!({"name":"searchItems","arguments":{"inputs":form_inputs()}}),
        )
        .await;
    assert_eq!(form["result"]["isError"], false, "{form}");
    assert_form_request(&requests, before, false);
    stdio.finish().await;

    let current = run(&admin_config, &["admin", "imports", "get", "readers"]);
    let retained_preview = run(&admin_config, &["admin", "imports", "preview", "readers"]);
    let (version, revision) = versions(&current);
    let duplicate = [b"{\"info\":{},".as_slice(), &serialized[1..]].concat();
    for (name, bytes) in [
        ("malformed.json", b"{".as_slice()),
        ("duplicate.json", duplicate.as_slice()),
    ] {
        let path = directory.join(name);
        std::fs::write(&path, bytes).unwrap();
        let before = requests.len();
        let rejected = command(&admin_config)
            .args([
                "admin",
                "imports",
                "upload-document",
                "readers",
                "--document-file",
                path.to_str().unwrap(),
                "--expected-version",
                &version,
                "--expected-catalog-revision",
                &revision,
            ])
            .output()
            .unwrap();
        assert!(!rejected.status.success(), "{name} must be rejected");
        let after = run(&admin_config, &["admin", "imports", "get", "readers"]);
        assert_generation_unchanged(&current, &after);
        let after_preview = run(&admin_config, &["admin", "imports", "preview", "readers"]);
        assert_eq!(
            after_preview["result"]["preview"],
            retained_preview["result"]["preview"]
        );
        assert_eq!(requests.len(), before, "rejected {name} must not dispatch");
        assert_cli_form(&agent_config, &requests, false);
    }
    // Exercise the Broker's body limit directly, independently of any local
    // CLI size check. Trailing whitespace keeps this otherwise valid JSON.
    let mut oversized = original.clone();
    oversized.resize(DOCUMENT_LIMIT + 1, b' ');
    let before = requests.len();
    let rejected = reqwest::Client::new()
        .put(format!("{base}/v1/admin/imports/readers/document"))
        .query(&[
            ("expectedVersion", version.as_str()),
            ("expectedCatalogRevision", revision.as_str()),
            ("filename", "oversize.json"),
        ])
        .bearer_auth(&admin)
        .header(
            "X-Agent-Access-Request-Id",
            uuid::Uuid::new_v4().to_string(),
        )
        .header("content-type", "application/json")
        .body(oversized)
        .send()
        .await
        .unwrap();
    assert!(!rejected.status().is_success());
    let after = run(&admin_config, &["admin", "imports", "get", "readers"]);
    assert_generation_unchanged(&current, &after);
    let after_preview = run(&admin_config, &["admin", "imports", "preview", "readers"]);
    assert_eq!(
        after_preview["result"]["preview"],
        retained_preview["result"]["preview"]
    );
    assert_eq!(
        requests.len(),
        before,
        "oversize rejection must not dispatch"
    );
    assert_cli_form(&agent_config, &requests, false);

    let replacement = directory.join("replacement.json");
    let replacement_bytes =
        serde_json::to_vec_pretty(&changed_form_document(swagger, &endpoint)).unwrap();
    std::fs::write(&replacement, &replacement_bytes).unwrap();
    let before = requests.len();
    let replaced = upload(&admin_config, &replacement, &current);
    assert_document_metadata(&replaced, "replacement.json", &replacement_bytes);
    assert_ne!(
        replaced["result"]["preview"]["manifestHash"],
        original_manifest_hash
    );
    assert_eq!(action(&replaced, "item.search")["status"], "quarantined");
    assert_eq!(
        action(&replaced, "item.read"),
        action(&current, "item.read")
    );
    assert_eq!(
        requests.len(),
        before,
        "source replacement must compile offline"
    );
    let stale_request = write_request(
        directory.path(),
        "stale-upload-accept.json",
        accept_request(&replaced, &original_manifest_hash),
    );
    let stale = command(&admin_config)
        .args([
            "admin",
            "imports",
            "accept",
            "readers",
            "--request-file",
            &stale_request,
        ])
        .output()
        .unwrap();
    assert!(
        !stale.status.success(),
        "a current version fence cannot revive a stale manifest"
    );
    let after = run(&admin_config, &["admin", "imports", "get", "readers"]);
    assert_generation_unchanged(&replaced, &after);
    let after_preview = run(&admin_config, &["admin", "imports", "preview", "readers"]);
    assert_eq!(
        after_preview["result"]["preview"],
        replaced["result"]["preview"]
    );
    let denied = command(&agent_config)
        .args([
            "invoke",
            "readers.item.search",
            "--input-json",
            &form_inputs().to_string(),
        ])
        .output()
        .unwrap();
    assert!(!denied.status.success());
    let denied = http
        .call(
            "tools/call",
            json!({"name":"searchItems","arguments":{"inputs":form_inputs()}}),
        )
        .await;
    assert!(
        denied.get("error").is_some() || denied["result"]["isError"] == true,
        "{denied}"
    );
    assert_eq!(
        requests.len(),
        before,
        "stale acceptance and cached quarantined tools never dispatch"
    );
    let read = http
        .call(
            "tools/call",
            json!({"name":"readItem","arguments":{"inputs":{"path":{"id":"ABC-12"}}}}),
        )
        .await;
    assert_eq!(read["result"]["isError"], false, "{read}");
    assert_read_request(&requests, before, false);
    let accepted = accept(&directory, &admin_config, &replaced);
    assert_eq!(action(&accepted, "item.search")["status"], "enabled");
    let before = requests.len();
    let denied = command(&agent_config)
        .args([
            "invoke",
            "readers.item.search",
            "--input-json",
            &form_inputs().to_string(),
        ])
        .output()
        .unwrap();
    assert!(
        !denied.status.success(),
        "the replacement requires its new input"
    );
    assert_eq!(requests.len(), before);
    assert_cli_form(&agent_config, &requests, true);

    // Delete both caller-side files before restart and an explicit rediscovery.
    // The persisted upload is the only document source available from here.
    std::fs::remove_file(&source).unwrap();
    std::fs::remove_file(&replacement).unwrap();
    let retained = run(&admin_config, &["admin", "imports", "get", "readers"]);
    drop(http);
    stop(broker).await;
    let application = isolated_broker().in_directory(directory.clone());
    let base = application.public_url();
    let before = requests.len();
    let broker = application
        .config_document(import_document(
            &directory,
            &permissions,
            &format!("{base}/mcp"),
        ))
        .start()
        .await
        .unwrap();
    assert_eq!(
        requests.len(),
        before,
        "startup loads plans without document or API I/O"
    );
    let admin_config = config_file(directory.path(), "restarted-admin", &base, &admin);
    let agent_config = config_file(directory.path(), "restarted-agent", &base, &agent);
    let restarted = run(&admin_config, &["admin", "imports", "get", "readers"]);
    assert_generation_unchanged(&retained, &restarted);
    assert_document_metadata(&restarted, "replacement.json", &replacement_bytes);
    assert_cli_form(&agent_config, &requests, true);
    let before = requests.len();
    let (version, revision) = versions(&restarted);
    let discovered = run(
        &admin_config,
        &[
            "admin",
            "imports",
            "discover",
            "readers",
            "--expected-version",
            &version,
            "--expected-catalog-revision",
            &revision,
        ],
    );
    assert_eq!(
        discovered["result"]["preview"]["manifestHash"],
        replaced["result"]["preview"]["manifestHash"]
    );
    assert_eq!(action(&discovered, "item.search")["status"], "enabled");
    assert_eq!(
        requests.len(),
        before,
        "rediscovery compiles retained bytes without network access"
    );
    let mut stdio = McpProcess::start_scoped(&agent_config, "readers");
    stdio.initialize().await;
    let mut inputs = form_inputs();
    inputs["body"]["revision"] = json!("2");
    let result = stdio
        .request(
            "tools/call",
            json!({"name":"searchItems","arguments":{"inputs":inputs}}),
        )
        .await;
    assert_eq!(result["result"]["isError"], false, "{result}");
    assert_eq!(requests.len(), before + 1);
    assert_eq!(requests.last().body, [FORM_BYTES, b"&revision=2"].concat());
    stdio.finish().await;
    stop(broker).await;
}
