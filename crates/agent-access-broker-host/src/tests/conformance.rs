//! Backend-contract acceptance: the test-only conformance backend
//! (`agent-access-conformance`) is registered beside the linked backends and
//! served by every broker surface: configuration, validation, discovery,
//! runtime specs, invocation (JSON, Markdown, raw download, multipart
//! upload), MCP, private resource attributes under managed policy, and the
//! portal's resource, grant, and attribute helpers. Nothing outside its crate
//! and the registration list knows about it.
use super::mcp;
use super::*;
use agent_access_conformance::{
    CONFORMANCE_BACKEND, CONFORMANCE_ENDPOINT_RESOURCE, CONFORMANCE_ITEM_RESOURCE,
    ConformanceConfig,
};
use agent_access_core::{
    BackendRegistry, ConfigError, ProvidersConfig, parse_broker_config_raw, validate_broker_config,
};
use sha2::{Digest, Sha256};
use wiremock::matchers::{body_bytes, header as header_is, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const UPSTREAM_TOKEN: &str = "conformance-upstream-token";
const IDENTITY_TOKEN: &str = "conformance-identity-token";
const PORTAL_FIXTURE: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../apps/portal/unit/conformance.fixture.json"
);

/// The linked backends plus the conformance backend.
fn registry() -> Arc<BackendRegistry> {
    let linked = crate::backend_registry();
    let registrations = linked
        .registrations()
        .chain([&CONFORMANCE_BACKEND])
        .collect::<Vec<_>>();
    Arc::new(BackendRegistry::new(registrations).unwrap())
}

/// A broker serving the conformance backend at `base_url`, with its secrets
/// in `dir`.
fn broker_toml(base_url: &str, dir: &Path) -> String {
    format!(
        r#"
[deployment]
environment = "development"
enable_fake_service = true

[identity]
mode = "required"
authority = "toml"

[[identity.sources]]
name = "conformance"
type = "static_principals"
header = "Authorization"
scheme = "Bearer"

[[identity.sources.principals]]
principal = "conformance-user"
token_refs = ["file:{dir}/identity-token"]

[providers.conformance]
base_url = "{base_url}"
allowed_upstream_hosts = ["{base_url}/**"]
max_upload_bytes = 4096

[credentials.service.conformance]
type = "bearer_token"
token_ref = "file:{dir}/upstream-token"

[policy]
authority = "toml"
default_decision = "deny"

[[policy.resources]]
id = "shelf-one"
resource_type = "conformance_item"
selector = {{ kind = "namespace", value = "shelf-one" }}
allowed_execution_contexts = ["default"]

[[policy.grants]]
subjects = ["user:conformance-user"]
service = "conformance"
actions = ["item.view", "item.download", "item.upload"]
resources = {{ resource_ids = ["shelf-one"] }}
credential_mode = "service"
"#,
        dir = dir.display()
    )
}

fn validation_errors(config: &BrokerConfig) -> Vec<String> {
    match validate_broker_config(config) {
        Err(ConfigError::Invalid { errors }) => errors,
        other => panic!("expected invalid configuration, got {other:?}"),
    }
}

struct Conformance {
    _dir: tempfile::TempDir,
    server: MockServer,
    app: Router,
}

async fn conformance() -> Conformance {
    let dir = tempfile::tempdir().unwrap();
    create_private_dir(dir.path());
    std::fs::write(dir.path().join("upstream-token"), UPSTREAM_TOKEN).unwrap();
    std::fs::write(dir.path().join("identity-token"), IDENTITY_TOKEN).unwrap();
    let server = MockServer::start().await;
    let mut config = parse_broker_config_raw(
        "conformance.toml",
        &broker_toml(&server.uri(), dir.path()),
        &registry(),
    )
    .unwrap();
    config.limits.upload_spool_dir = dir.path().join("spool").display().to_string();
    validate_broker_config(&config).unwrap();
    let app = build_router(BrokerRuntime::new(config).unwrap(), broker_build_status());
    Conformance {
        _dir: dir,
        server,
        app,
    }
}

impl Conformance {
    async fn item(&self, item: &str, title: &str, body: &str) {
        Mock::given(method("GET"))
            .and(path(format!("/items/{item}")))
            .and(header_is(
                "authorization",
                format!("Bearer {UPSTREAM_TOKEN}").as_str(),
            ))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(json!({"title": title, "body": body})),
            )
            .mount(&self.server)
            .await;
    }

    async fn invoke(
        &self,
        action: &str,
        request: Value,
        accept: Option<&str>,
    ) -> axum::response::Response {
        let mut builder = Request::builder()
            .method(Method::POST)
            .uri(format!("/v1/invoke/conformance/{action}"))
            .extension(ConnectInfo(
                "127.0.0.1:44100".parse::<SocketAddr>().unwrap(),
            ))
            .header(REQUEST_ID_HEADER, format!("conformance-{action}"))
            .header(AUTHORIZATION, format!("Bearer {IDENTITY_TOKEN}"))
            .header(CONTENT_TYPE, "application/json");
        if let Some(accept) = accept {
            builder = builder.header(ACCEPT, accept);
        }
        self.app
            .clone()
            .oneshot(builder.body(Body::from(request.to_string())).unwrap())
            .await
            .unwrap()
    }

    async fn get(&self, uri: &str) -> Value {
        let authorization = format!("Bearer {IDENTITY_TOKEN}");
        let response = governed_get(
            self.app.clone(),
            uri,
            "conformance-spec",
            &[("Authorization", authorization.as_str())],
        )
        .await;
        let status = response.status();
        let body = response_json(response).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        body
    }
}

#[test]
fn conformance_backend_configures_through_its_registration_alone() {
    let base = "https://conformance.example.test";
    let raw = broker_toml(base, Path::new("/nonexistent"));
    let parse = |raw: &str| parse_broker_config_raw("conformance.toml", raw, &registry());

    let config = parse(&raw).unwrap();
    assert!(config.providers.get::<ConformanceConfig>().is_some());
    validate_broker_config(&config).unwrap();

    // The linked broker does not know the kind; typed configuration rejects
    // unknown fields.
    let linked = parse_broker_config_raw(
        "conformance.toml",
        &raw,
        &Arc::new(crate::backend_registry()),
    )
    .unwrap_err();
    assert!(linked.to_string().contains("conformance"), "{linked}");
    let unknown = parse(&raw.replace(
        "max_upload_bytes = 4096",
        "max_upload_bytes = 4096\nsurprise = true",
    ))
    .unwrap_err();
    assert!(unknown.to_string().contains("surprise"), "{unknown}");

    // The backend validates its own table, under its own configuration path.
    let invalid = parse(
        &raw.replace(&format!("\"{base}\""), "\"ftp://conformance.example.test\"")
            .replace(&format!("[\"{base}/**\"]"), "[]")
            .replace("max_upload_bytes = 4096", "max_upload_bytes = 0"),
    )
    .unwrap();
    let errors = validation_errors(&invalid);
    for expected in [
        "providers.conformance.base_url must use https, except loopback http in non-production",
        "providers.conformance.allowed_upstream_hosts must not be empty",
        "providers.conformance.max_upload_bytes must be between 1 and limits.max_http_body_bytes",
    ] {
        assert!(errors.iter().any(|error| error == expected), "{errors:?}");
    }

    // Development fixtures need the development switch.
    let production =
        parse(&raw.replace("enable_fake_service = true", "enable_fake_service = false")).unwrap();
    assert!(
        validation_errors(&production).iter().any(|error| error
            == "providers.conformance is a development backend and requires deployment.enable_fake_service")
    );

    // Its resource type's grammar governs resource entries.
    let entry = parse(&raw.replace(
        "selector = { kind = \"namespace\", value = \"shelf-one\" }",
        "selector = { kind = \"exact\", value = \"shelf-one\" }",
    ))
    .unwrap();
    assert!(
        validation_errors(&entry)
            .iter()
            .any(|error| error.contains("shelf-one") && error.contains("conformance_item")),
        "{:?}",
        validation_errors(&entry)
    );

    // Its managed credential profile is the only one per-user credentials may name.
    let managed = |profile: &str| {
        let mut config = parse(&raw).unwrap();
        config.credentials.per_user.insert(
            "conformance".into(),
            CredentialConfig {
                kind: "managed_store".into(),
                profile: Some(profile.into()),
                username_ref: None,
                token_ref: None,
                provider: None,
                path: None,
                read_only: None,
                credential_name: None,
            },
        );
        config
    };
    let profile_errors = |profile: &str| match validate_broker_config(&managed(profile)) {
        Err(ConfigError::Invalid { errors }) => errors,
        _ => Vec::new(),
    };
    let supported = profile_errors("api_token");
    let unsupported = profile_errors("missing")
        .into_iter()
        .filter(|error| !supported.contains(error))
        .collect::<Vec<_>>();
    assert!(
        supported.iter().all(|error| !error.contains("api_token")),
        "{supported:?}"
    );
    assert!(
        unsupported.len() == 1 && unsupported[0].contains("missing"),
        "{unsupported:?}"
    );
}

#[tokio::test]
async fn conformance_actions_reach_every_discovery_surface() {
    let fixture = conformance().await;

    let catalog = fixture.get("/v1/spec/catalog").await;
    let service = catalog["services"]
        .as_array()
        .unwrap()
        .iter()
        .find(|entry| entry["service"] == "conformance")
        .unwrap();
    assert_eq!(
        service["resourceScopes"]["item"]["resourceType"],
        "conformance_item"
    );
    let action = |name: &str| {
        service["actions"]
            .as_array()
            .unwrap()
            .iter()
            .find(|entry| entry["action"] == name)
            .unwrap_or_else(|| panic!("catalog lacks {name}: {service}"))
            .clone()
    };
    let view = action("item.view");
    assert_eq!(view["io"]["type"], "json");
    assert_eq!(view["responseFormats"], json!(["json", "markdown"]));
    assert_eq!(view["renderedBodyOwners"], json!(["/result/item"]));
    assert_eq!(action("item.download")["io"]["type"], "raw_download");
    assert_eq!(action("item.upload")["io"]["type"], "multipart_upload");
    assert_eq!(action("item.upload")["io"]["plan"]["maxFiles"], 1);

    // OpenAPI projects each invocation shape: JSON with presentation
    // options, a raw stream with its metadata header, and multipart upload.
    let openapi = fixture.get("/v1/spec/openapi.json").await;
    let operation =
        |action: &str| openapi["paths"][format!("/v1/invoke/conformance/{action}")]["post"].clone();
    let view = operation("item.view");
    let view_request = &view["requestBody"]["content"]["application/json"]["schema"];
    assert_eq!(
        view_request["properties"]["inputs"]["required"],
        json!(["item"])
    );
    assert_eq!(
        view_request["properties"]["responseFormat"]["enum"],
        json!(["json", "markdown"])
    );
    assert_eq!(
        view_request["properties"]["readContentFormat"]["enum"],
        json!(["native", "markdown", "text"])
    );
    assert!(
        view["responses"]["200"]["content"]
            .get("application/json")
            .is_some()
    );
    let download = operation("item.download");
    let raw = &download["responses"]["200"];
    assert_eq!(
        raw["content"]["application/octet-stream"]["schema"],
        json!({"type": "string", "format": "binary"})
    );
    assert!(
        raw["headers"].get(RESULT_METADATA_HEADER).is_some(),
        "{raw}"
    );
    let upload = operation("item.upload");
    let multipart = &upload["requestBody"]["content"]["multipart/form-data"];
    assert_eq!(multipart["schema"]["required"], json!(["request"]));
    assert_eq!(
        multipart["schema"]["properties"]["request"]["contentSchema"]["properties"]["inputs"]["required"],
        json!(["item", "attachments"])
    );
    assert_eq!(multipart["x-agent-access-upload-plan"]["maxFiles"], 1);

    // The send schema accepts each shape's request and rejects its
    // malformed variants.
    let send_schema = fixture.get("/v1/spec/send-schema.json").await;
    let send = jsonschema::validator_for(&send_schema).unwrap();
    let request = |action: &str, extra: Value| {
        let mut request = json!({
            "version": "agent-access.send.v1", "kind": "invoke",
            "service": "conformance", "action": action,
            "inputs": {"item": "shelf-one/item-one"}
        });
        request
            .as_object_mut()
            .unwrap()
            .extend(extra.as_object().unwrap().clone());
        request
    };
    let upload_file = json!({"files": [{"role": "attachment", "path": "notes.txt"}]});
    let stream = json!({"responseMode": "stream", "output": {"type": "stdout"}});
    for (valid, request) in [
        (
            true,
            request("item.view", json!({"responseFormat": "markdown"})),
        ),
        (
            false,
            request("item.view", json!({"responseFormat": "html"})),
        ),
        (true, request("item.download", stream.clone())),
        (false, request("item.download", json!({}))),
        (
            false,
            request(
                "item.download",
                json!({"responseMode": "stream", "output": {"type": "stdout"}, "responseFormat": "markdown"}),
            ),
        ),
        (true, request("item.upload", upload_file.clone())),
        (false, request("item.upload", json!({}))),
        (
            false,
            request(
                "item.upload",
                json!({"files": [
                    {"role": "attachment", "path": "one.txt"}, {"role": "attachment", "path": "two.txt"}
                ]}),
            ),
        ),
    ] {
        assert_eq!(send.is_valid(&request), valid, "{request}");
    }

    let actions = fixture
        .get("/v1/services/conformance/actions?resource=shelf-one%2Fitem-one")
        .await;
    assert_eq!(
        actions["actions"],
        json!(["item.download", "item.upload", "item.view"])
    );
    let outside = fixture
        .get("/v1/services/conformance/actions?resource=shelf-two%2Fitem-one")
        .await;
    assert_eq!(outside["actions"], json!([]));
}

#[tokio::test]
async fn conformance_actions_move_json_markdown_downloads_and_uploads() {
    let fixture = conformance().await;
    fixture
        .item("shelf-one/item-one", "Item One", "Body *text*")
        .await;

    let view = fixture
        .invoke(
            "item.view",
            json!({"inputs": {"item": "shelf-one/item-one"}}),
            None,
        )
        .await;
    let body = response_json(view).await;
    assert_eq!(body["decision"], "allow", "{body}");
    assert_eq!(body["result"]["item"]["title"], "Item One");
    let text = response_json(
        fixture
            .invoke(
                "item.view",
                json!({"inputs": {"item": "shelf-one/item-one"}, "readContentFormat": "text"}),
                None,
            )
            .await,
    )
    .await;
    assert_eq!(
        text["result"]["item"]["renderedBody"],
        json!({"format": "text", "value": "Body *text*"})
    );
    let markdown = fixture
        .invoke(
            "item.view",
            json!({"inputs": {"item": "shelf-one/item-one"}, "responseFormat": "markdown"}),
            None,
        )
        .await;
    let markdown = response_json(markdown).await;
    assert_eq!(
        markdown["result"],
        json!({"format": "markdown", "value": "# Item One\n\nItem: `shelf-one/item-one`\n\nBody \\*text\\*\n"})
    );

    Mock::given(method("GET"))
        .and(path("/items/shelf-one/item-one/content"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("content-type", "text/plain")
                .set_body_bytes("downloaded bytes"),
        )
        .mount(&fixture.server)
        .await;
    let download = fixture
        .invoke(
            "item.download",
            json!({"inputs": {"item": "shelf-one/item-one"}}),
            Some(RAW_RESULT_MIME),
        )
        .await;
    assert_eq!(download.status(), StatusCode::OK);
    assert_eq!(download.headers()[CONTENT_TYPE], "text/plain");
    let metadata: Value = serde_json::from_slice(
        &BASE64
            .decode(download.headers()[RESULT_METADATA_HEADER].to_str().unwrap())
            .unwrap(),
    )
    .unwrap();
    assert_eq!(metadata["result"]["size"], 16);
    let bytes = axum::body::to_bytes(download.into_body(), usize::MAX)
        .await
        .unwrap();
    assert_eq!(&bytes[..], b"downloaded bytes");

    let content = b"uploaded bytes";
    let sha256 = Sha256::digest(content)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    Mock::given(method("PUT"))
        .and(path("/items/shelf-one/item-one/content"))
        .and(body_bytes(content.to_vec()))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"revision": 2})))
        .mount(&fixture.server)
        .await;
    let boundary = "conformance-boundary";
    let request = json!({"inputs": {"item": "shelf-one/item-one", "attachments": [{
        "field": "file", "filename": "notes.txt", "contentType": "text/plain",
        "size": content.len(), "sha256": sha256
    }]}});
    let multipart = format!(
        "--{boundary}\r\nContent-Disposition: form-data; name=\"request\"\r\nContent-Type: application/json\r\n\r\n{request}\r\n\
         --{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"notes.txt\"\r\nContent-Type: text/plain\r\n\r\n{}\r\n\
         --{boundary}--\r\n",
        std::str::from_utf8(content).unwrap()
    );
    let upload = fixture
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/v1/invoke/conformance/item.upload")
                .extension(ConnectInfo(
                    "127.0.0.1:44100".parse::<SocketAddr>().unwrap(),
                ))
                .header(REQUEST_ID_HEADER, "conformance-upload")
                .header(AUTHORIZATION, format!("Bearer {IDENTITY_TOKEN}"))
                .header(
                    CONTENT_TYPE,
                    format!("multipart/form-data; boundary={boundary}"),
                )
                .body(Body::from(multipart))
                .unwrap(),
        )
        .await
        .unwrap();
    let upload = response_json(upload).await;
    assert_eq!(upload["decision"], "allow", "{upload}");
    assert_eq!(upload["result"]["revision"], 2);
    assert_eq!(upload["result"]["sha256"], sha256);

    // Policy covers the shelf, not its neighbours; a denied item never
    // reaches the upstream.
    let requests_before = fixture.server.received_requests().await.unwrap().len();
    let denied = response_json(
        fixture
            .invoke(
                "item.view",
                json!({"inputs": {"item": "shelf-two/item-one"}}),
                None,
            )
            .await,
    )
    .await;
    assert_eq!(denied["decision"], "deny", "{denied}");
    assert_eq!(
        fixture.server.received_requests().await.unwrap().len(),
        requests_before
    );
}

#[tokio::test]
async fn conformance_upstream_rejections_keep_their_deny_outcomes_through_enforcement() {
    let fixture = conformance().await;
    for (item, status, reason) in [
        ("shelf-one/item-one", 401, "upstream_unauthorized"),
        ("shelf-one/item-two", 403, "upstream_forbidden"),
    ] {
        Mock::given(method("GET"))
            .and(path(format!("/items/{item}")))
            .respond_with(ResponseTemplate::new(status))
            .mount(&fixture.server)
            .await;
        let response = fixture
            .invoke("item.view", json!({"inputs": {"item": item}}), None)
            .await;
        assert_eq!(response.status(), StatusCode::FAILED_DEPENDENCY);
        let body = response_json(response).await;
        assert_eq!(body["decision"], "deny", "{body}");
        assert_eq!(body["reasonCode"], reason, "{body}");
    }
}

#[tokio::test]
async fn conformance_actions_are_mcp_tools_and_resource_types_are_published() {
    let server = MockServer::start().await;
    let dir = tempfile::tempdir().unwrap();
    let token = dir.path().join("token");
    std::fs::write(&token, UPSTREAM_TOKEN).unwrap();
    let base = server.uri();
    let fixture = mcp::Fixture::new(|config| {
        config.providers = ProvidersConfig::new(registry())
            .with(agent_access_fake::FakeProviderConfig::default())
            .with(ConformanceConfig {
                base_url: base.clone(),
                allowed_upstream_hosts: vec![format!("{base}/**")],
                egress_proxy: None,
                max_upload_bytes: 4096,
                endpoints: false,
                shelves: vec!["shelf-one".into(), "shelf-two".into()],
            });
        config.credentials.service.insert(
            "conformance".into(),
            CredentialConfig {
                kind: "bearer_token".into(),
                token_ref: Some(format!("file:{}", token.display())),
                username_ref: None,
                provider: None,
                path: None,
                read_only: None,
                credential_name: None,
                profile: None,
            },
        );
        config.policy.resources.push(ResourceDefinition {
            id: "shelf-one".into(),
            display_name: None,
            resource_type: CONFORMANCE_ITEM_RESOURCE.id.clone(),
            selector: ResourceSelector::Namespace {
                value: "shelf-one".into(),
            },
            allowed_execution_contexts: vec!["default".into()],
            enabled: true,
        });
        config.policy.resources.push(ResourceDefinition {
            id: "item-one".into(),
            display_name: None,
            resource_type: CONFORMANCE_ITEM_RESOURCE.id.clone(),
            selector: ResourceSelector::Exact {
                value: "shelf-one/item-one".into(),
            },
            allowed_execution_contexts: vec!["default".into()],
            enabled: true,
        });
        config.policy.grants.push(PolicyGrantConfig {
            subjects: vec!["user:mcp-user".into()],
            service: "conformance".into(),
            actions: vec!["item.view".into()],
            resources: ResourceSelection {
                resource_ids: vec!["shelf-one".into(), "item-one".into()],
                resource_group_ids: vec![],
            },
            execution_contexts: None,
            credential_mode: "service".into(),
            priority: None,
        });
        // Every item except one shelf and one item, for downloads.
        for (id, selector) in [
            ("all-items", ResourceSelector::All),
            (
                "shelf-two",
                ResourceSelector::Namespace {
                    value: "shelf-two".into(),
                },
            ),
            (
                "withheld-item",
                ResourceSelector::Exact {
                    value: "shelf-one/withheld".into(),
                },
            ),
        ] {
            config.policy.resources.push(ResourceDefinition {
                id: id.into(),
                display_name: None,
                resource_type: CONFORMANCE_ITEM_RESOURCE.id.clone(),
                selector,
                allowed_execution_contexts: vec!["default".into()],
                enabled: true,
            });
        }
        config
            .policy
            .resource_groups
            .push(agent_access_core::ResourceGroupDefinition {
                id: "public-items".into(),
                name: "Public items".into(),
                included_resource_ids: vec!["all-items".into()],
                excluded_resource_ids: vec!["shelf-two".into(), "withheld-item".into()],
            });
        config.policy.grants.push(PolicyGrantConfig {
            subjects: vec!["user:mcp-user".into()],
            service: "conformance".into(),
            actions: vec!["item.download".into()],
            resources: ResourceSelection {
                resource_ids: vec![],
                resource_group_ids: vec!["public-items".into()],
            },
            execution_contexts: None,
            credential_mode: "service".into(),
            priority: None,
        });
    });
    Mock::given(method("GET"))
        .and(path("/items/shelf-one/item-one"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(json!({"title": "Item One", "body": "text"})),
        )
        .mount(&server)
        .await;

    let session = fixture.initialize().await;
    let listing = fixture.rpc(&session, 2, "tools/list", json!({})).await;
    let tool = agent_access_core::mcp::tool_name("conformance", "item.view");
    assert!(
        listing["result"]["tools"]
            .as_array()
            .unwrap()
            .iter()
            .any(|entry| entry["name"] == tool.as_str()),
        "{listing}"
    );
    let resources = fixture
        .call(
            &session,
            3,
            "resources_list",
            json!({"service": "conformance"}),
        )
        .await;
    let resources = mcp::structured(&resources).clone();
    // Registered items carry the inputs that address them. Coverage reports
    // the reachable configured shelf, restricted by the download grant's
    // exclusions, without naming the withheld shelf.
    assert_eq!(
        resources,
        json!({
            "service": "conformance",
            "resources": [
                {"id": "item-one", "type": "conformance_item", "value": "shelf-one/item-one",
                    "inputs": {"item": "shelf-one/item-one"}},
                {"id": "withheld-item", "type": "conformance_item", "value": "shelf-one/withheld",
                    "inputs": {"item": "shelf-one/withheld"}}
            ],
            "coverage": [{
                "type": "conformance_item",
                "selector": {"kind": "namespace", "value": "shelf-one"},
                "restricted": true
            }],
            "nextCursor": null
        })
    );
    // HTTP and service-scoped MCP discovery return the same document.
    let http = fixture
        .app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/v1/services/conformance/resources")
                .extension(ConnectInfo(
                    "127.0.0.1:45000".parse::<SocketAddr>().unwrap(),
                ))
                .header(REQUEST_ID_HEADER, "conformance-resources")
                .header(AUTHORIZATION, format!("Bearer {}", mcp::TOKEN_A))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(http.status(), StatusCode::OK);
    assert_eq!(response_json(http).await, resources);
    let scoped = mcp::scoped::initialize(&fixture, "/mcp/conformance", mcp::TOKEN_A).await;
    let scoped_resources = mcp::scoped::call(
        &fixture,
        "/mcp/conformance",
        &scoped,
        2,
        "resources_list",
        json!({"service": "conformance"}),
    )
    .await;
    assert_eq!(mcp::structured(&scoped_resources), &resources);
    let called = fixture
        .call(
            &session,
            4,
            &tool,
            json!({"inputs": {"item": "shelf-one/item-one"}}),
        )
        .await;
    assert_eq!(
        mcp::structured(&called)["result"]["item"]["title"],
        "Item One"
    );

    let types = fixture
        .app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/v1/resource-types")
                .extension(ConnectInfo(
                    "127.0.0.1:45000".parse::<SocketAddr>().unwrap(),
                ))
                .header(REQUEST_ID_HEADER, "conformance-resource-types")
                .header(AUTHORIZATION, format!("Bearer {}", mcp::TOKEN_A))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let types = response_json(types).await;
    assert!(
        types["resourceTypes"]
            .as_array()
            .unwrap()
            .iter()
            .any(|entry| entry
                == &serde_json::to_value(CONFORMANCE_ITEM_RESOURCE.metadata()).unwrap()),
        "{types}"
    );
}

/// The portal unit tests exercise the conformance backend's resource type
/// and grant catalog from this fixture; regenerate it with
/// `UPDATE_PORTAL_FIXTURES=1`.
#[test]
fn conformance_portal_fixture_matches_the_broker() {
    let config = parse_broker_config_raw(
        "conformance.toml",
        &broker_toml(
            "https://conformance.example.test",
            Path::new("/nonexistent"),
        ),
        &registry(),
    )
    .unwrap();
    let descriptor =
        agent_access_conformance::conformance_descriptor(config.providers.get().unwrap());
    let fixture = json!({
        "resourceType": CONFORMANCE_ITEM_RESOURCE.metadata(),
        "endpointType": CONFORMANCE_ENDPOINT_RESOURCE.metadata(),
        "service": crate::handlers::management::policy::service_catalog(&config.credentials, descriptor.capabilities(), Some(&descriptor.credentials)),
    });
    let rendered = format!("{}\n", serde_json::to_string_pretty(&fixture).unwrap());
    if std::env::var_os("UPDATE_PORTAL_FIXTURES").is_some() {
        std::fs::write(PORTAL_FIXTURE, &rendered).unwrap();
    }
    assert_eq!(
        std::fs::read_to_string(PORTAL_FIXTURE).unwrap_or_default(),
        rendered,
        "the portal's conformance fixture is stale; rerun with UPDATE_PORTAL_FIXTURES=1"
    );
}

const ENDPOINT_KEY: &str = "endpoint-key-sentinel-0123456789";
const REPLACED_KEY: &str = "replaced-key-sentinel-9876543210";

/// A managed-policy broker serving the conformance backend with endpoints
/// enabled: private attributes live in the managed resource catalog.
struct ManagedConformance {
    dir: tempfile::TempDir,
    server: MockServer,
    app: Router,
    admin_token: String,
    agent_token: String,
}

fn managed_toml(base_url: &str, dir: &Path, authority: &str) -> String {
    format!(
        r#"
[deployment]
environment = "development"
enable_fake_service = true

[identity]
mode = "required"
authority = "managed"

[[identity.sources]]
name = "broker"
type = "broker_tokens"
header = "Authorization"
scheme = "Bearer"

[managed_store]
type = "sqlite"
path = "{dir}/store.sqlite"
auto_migrate = true

[credential_encryption]
active_key = "k1"

[[credential_encryption.keys]]
id = "k1"
provider = "file"
path = "{dir}/encryption-key"

[broker_tokens]
hash_key_ref = "file:{dir}/hash-key"

[management]
enabled = true

[audit]
type = "jsonl"
path = "{dir}/audit.jsonl"

[limits]
upload_spool_dir = "{dir}/spool"

[providers.conformance]
base_url = "{base_url}"
allowed_upstream_hosts = ["{base_url}/**"]
endpoints = true

[credentials.service.conformance]
type = "bearer_token"
token_ref = "file:{dir}/upstream-token"

[policy]
authority = "{authority}"
default_decision = "deny"
"#,
        dir = dir.display()
    )
}

async fn managed_conformance() -> ManagedConformance {
    let dir = tempfile::tempdir().unwrap();
    create_private_dir(dir.path());
    std::fs::write(dir.path().join("upstream-token"), UPSTREAM_TOKEN).unwrap();
    for (name, byte) in [("encryption-key", 41_u8), ("hash-key", 42)] {
        std::fs::write(
            dir.path().join(name),
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([byte; 32]),
        )
        .unwrap();
    }
    let server = MockServer::start().await;
    let config = parse_broker_config_raw(
        "managed-conformance.toml",
        &managed_toml(&server.uri(), dir.path(), "managed"),
        &registry(),
    )
    .unwrap();
    validate_broker_config(&config).unwrap();
    let store = agent_access_core::ManagedStore::open(
        config.managed_store.as_ref().unwrap(),
        agent_access_core::ManagedStoreOpenMode::Startup,
    )
    .unwrap();
    for principal in ["admin", "alice"] {
        store
            .create_principal(PrincipalWriteRequest {
                role: agent_access_core::PrincipalRole::User,
                self_service_enabled: None,
                principal_id: principal.into(),
                kind: "user".into(),
                display_name: None,
                email: None,
                external_subject: None,
                created_by: "test".into(),
            })
            .unwrap();
    }
    store
        .patch_principal_access(agent_access_core::PrincipalAccessPatchRequest {
            principal_id: ("admin").into(),
            role: Some(agent_access_core::PrincipalRole::Admin),
            self_service_enabled: None,
            actor: ("test").into(),
        })
        .unwrap();
    let runtime = BrokerRuntime::new(config).unwrap();
    let issue = |principal: &str, class, scopes: Value| {
        store
            .issue_broker_token(
                runtime.broker_token_hasher().unwrap(),
                agent_access_core::BrokerTokenIssueRequest {
                    principal_id: principal.into(),
                    name: "conformance".into(),
                    token_class: class,
                    scopes,
                    expires_at: None,
                    created_by: "test".into(),
                },
            )
            .unwrap()
            .token
    };
    let admin_token = issue(
        "admin",
        agent_access_core::BrokerTokenClass::Admin,
        json!({}),
    );
    let agent_token = issue(
        "alice",
        agent_access_core::BrokerTokenClass::AgentInvoke,
        json!({"allowedExecutionContexts": ["default"]}),
    );
    ManagedConformance {
        dir,
        server,
        app: build_router(runtime, broker_build_status()),
        admin_token,
        agent_token,
    }
}

impl ManagedConformance {
    async fn request(
        &self,
        token: &str,
        method: Method,
        uri: &str,
        body: Option<Value>,
    ) -> (StatusCode, Value) {
        let response = authed_json_request(
            self.app.clone(),
            method,
            uri,
            "managed-conformance",
            "Authorization",
            format!("Bearer {token}"),
            body.map(|body| body.to_string()).as_deref(),
        )
        .await;
        (response.status(), response_json(response).await)
    }

    async fn ping(&self, endpoint: &str) -> Value {
        self.request(
            &self.agent_token,
            Method::POST,
            "/v1/invoke/conformance/endpoint.ping",
            Some(json!({"inputs": {"endpoint": endpoint, "message": "hello"}})),
        )
        .await
        .1
    }

    async fn expect_ping(&self, key: &str, receipt: &str) {
        self.server.reset().await;
        Mock::given(method("POST"))
            .and(path("/endpoints/alerts/ping"))
            .and(header_is("x-endpoint-key", key))
            .and(header_is(
                "authorization",
                format!("Bearer {UPSTREAM_TOKEN}").as_str(),
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"receipt": receipt})))
            .expect(1)
            .mount(&self.server)
            .await;
    }

    /// Everything the broker persisted or logged, as bytes.
    fn persisted(&self) -> Vec<u8> {
        ["store.sqlite", "store.sqlite-wal", "audit.jsonl"]
            .iter()
            .filter_map(|name| std::fs::read(self.dir.path().join(name)).ok())
            .flatten()
            .collect()
    }
}

fn contains(haystack: &[u8], needle: &str) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle.as_bytes())
}

#[test]
fn private_attributes_need_managed_policy() {
    let config = parse_broker_config_raw(
        "managed-conformance.toml",
        &managed_toml(
            "https://conformance.example.test",
            Path::new("/nonexistent"),
            "toml",
        ),
        &registry(),
    )
    .unwrap();
    assert!(
        validation_errors(&config).iter().any(|error| error
            == "conformance.endpoint.ping private resource attributes require managed policy"),
        "{:?}",
        validation_errors(&config)
    );
}

/// A backend's private attribute is set, stored, revealed, replaced, and
/// consumed through the host's generic machinery: the key reaches the
/// upstream only for an authorized invocation of exactly its endpoint.
#[tokio::test]
async fn conformance_private_attributes_reach_only_the_authorized_invocation() {
    let fixture = managed_conformance().await;
    let admin = fixture.admin_token.clone();
    let endpoint = |id: &str, attributes: Value| {
        json!({"id": id, "resourceType": CONFORMANCE_ENDPOINT_RESOURCE.id,
            "selector": {"kind": "exact", "value": id},
            "allowedExecutionContexts": ["default"], "attributes": attributes})
    };

    // The type's own rules: the key is required and must be well formed.
    for attributes in [
        json!({}),
        json!({"signingKey": "short"}),
        json!({"unknown": ENDPOINT_KEY}),
    ] {
        let (status, body) = fixture
            .request(
                &admin,
                Method::POST,
                "/v1/admin/policy/resources",
                Some(endpoint("alerts", attributes)),
            )
            .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    }
    for id in ["alerts", "other"] {
        let (status, body) = fixture
            .request(
                &admin,
                Method::POST,
                "/v1/admin/policy/resources",
                Some(endpoint(id, json!({"signingKey": ENDPOINT_KEY}))),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(
            body["result"]["record"]["configuredAttributes"],
            json!(["signingKey"])
        );
        assert!(!body.to_string().contains(ENDPOINT_KEY));
    }
    let (status, body) = fixture
        .request(
            &admin,
            Method::POST,
            "/v1/admin/policy/grants",
            Some(
                json!({"subjects": ["user:alice"], "executionContexts": ["default"],
                "service": "conformance", "actions": ["endpoint.ping"],
                "resources": {"resourceIds": ["alerts"], "resourceGroupIds": []},
                "credentialMode": "service"}),
            ),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");

    // The authorized endpoint's key reaches the upstream, once.
    fixture.expect_ping(ENDPOINT_KEY, "r-1").await;
    let pinged = fixture.ping("alerts").await;
    assert_eq!(pinged["decision"], "allow", "{pinged}");
    assert_eq!(
        pinged["result"],
        json!({"endpoint": "alerts", "receipt": "r-1"})
    );
    fixture.server.verify().await;

    // Another endpoint's key is never resolved for a caller not granted it.
    fixture.server.reset().await;
    let denied = fixture.ping("other").await;
    assert_eq!(denied["decision"], "deny", "{denied}");
    assert!(fixture.server.received_requests().await.unwrap().is_empty());

    // Ordinary reads name the attribute but never show it; an admin reveal does.
    let (_, record) = fixture
        .request(
            &admin,
            Method::GET,
            "/v1/admin/policy/resources/alerts",
            None,
        )
        .await;
    assert!(!record.to_string().contains(ENDPOINT_KEY), "{record}");
    let (status, revealed) = fixture
        .request(
            &admin,
            Method::POST,
            "/v1/admin/policy/resources/alerts/attributes/signingKey/reveal",
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{revealed}");
    assert_eq!(revealed["result"]["value"], ENDPOINT_KEY);

    // A replacement takes effect on the next invocation.
    let (status, body) = fixture
        .request(
            &admin,
            Method::PATCH,
            "/v1/admin/policy/resources/alerts",
            Some(json!({"expectedVersion": 1, "attributes": {"signingKey": REPLACED_KEY}})),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    fixture.expect_ping(REPLACED_KEY, "r-2").await;
    assert_eq!(fixture.ping("alerts").await["result"]["receipt"], "r-2");
    fixture.server.verify().await;

    // Keys are encrypted at rest and never audited.
    let persisted = fixture.persisted();
    assert!(!persisted.is_empty());
    for key in [ENDPOINT_KEY, REPLACED_KEY] {
        assert!(!contains(&persisted, key), "{key} persisted in plaintext");
    }
}
