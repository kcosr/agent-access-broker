//! Raw uploads share discovery publication, review, admission and browser authority.
use super::*;
use agent_access_core::imports::IMPORT_MAX_DOCUMENT_BYTES;
use sha2::{Digest, Sha256};

const PRIVATE_SOURCE_MARKER: &str = "synthetic-private-source-marker";

fn upload_definition(endpoint: &str) -> imports::ImportedServiceDefinition {
    let mut definition = definition();
    definition.service = "documents".into();
    definition.adapter_kind = "openapi_http".into();
    definition.endpoint = endpoint.into();
    definition.discovery = ImportedDiscoveryCredential::Anonymous;
    definition.connection_settings = BTreeMap::from([
        ("definitionSource".into(), "upload".into()),
        ("securityScheme".into(), "access".into()),
    ]);
    definition
}

fn document(changed: bool) -> Vec<u8> {
    let parameters = if changed {
        json!([{"name":"query","in":"query","required":true,"schema":{"type":"string"}}])
    } else {
        json!([])
    };
    serde_json::to_vec_pretty(&json!({
        "openapi":"3.1.1", "info":{"title":"Inventory","version":"1"},
        "x-private-source-marker":PRIVATE_SOURCE_MARKER,
        "components":{"securitySchemes":{"access":{"type":"http","scheme":"bearer"}}},
        "security":[{"access":[]}],
        "paths":{"/items":{"get":{"operationId":"read_item","parameters":parameters,
            "responses":{"204":{"description":"Empty"}}}}}
    }))
    .unwrap()
}

fn configure(fixture: &mut Fixture, endpoint: &str) {
    fixture
        .config
        .imports
        .allowed_kinds
        .push("openapi_http".into());
    fixture
        .config
        .imports
        .allowed_endpoints
        .push(endpoint.into());
}

async fn create(app: &Router, token: &str, endpoint: &str) -> Value {
    let (status, response) = request(
        app,
        token,
        Method::POST,
        "/v1/admin/imports",
        Some(json!(upload_definition(endpoint))),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{response}");
    assert!(response["result"]["service"].get("document").is_none());
    response["result"].clone()
}

fn upload_path(current: &Value) -> String {
    format!(
        "/v1/admin/imports/documents/document?expectedVersion={}&expectedCatalogRevision={}",
        current["service"]["version"], current["catalogRevision"]
    )
}

fn raw_request(
    path: &str,
    body: Vec<u8>,
    token: Option<&str>,
    content_type: &str,
) -> Request<Body> {
    let mut request = Request::builder()
        .method(Method::PUT)
        .uri(path)
        .extension(ConnectInfo(
            "127.0.0.1:41320".parse::<SocketAddr>().unwrap(),
        ))
        .header(REQUEST_ID_HEADER, "import-document-upload")
        .header(CONTENT_TYPE, content_type);
    if let Some(token) = token {
        request = request.header("Authorization", format!("Bearer {token}"));
    }
    request.body(Body::from(body)).unwrap()
}

async fn upload(app: &Router, token: &str, current: &Value, bytes: Vec<u8>) -> (StatusCode, Value) {
    let response = app
        .clone()
        .oneshot(raw_request(
            &format!("{}&filename=inventory.json", upload_path(current)),
            bytes,
            Some(token),
            "application/json",
        ))
        .await
        .unwrap();
    (response.status(), response_json(response).await)
}

#[tokio::test]
async fn exact_upload_replaces_preview_quarantines_and_rediscovers_after_restart_without_http() {
    let api = wiremock::MockServer::start().await;
    let endpoint = format!("{}/api", api.uri());
    let mut fixture = fixture();
    configure(&mut fixture, &endpoint);
    let token = admin_token(&fixture);
    let broker = import_broker(&fixture.config).await;
    let app = broker.app();
    let created = create(&app, &token, &endpoint).await;
    let (status, missing) = request(
        &app,
        &token,
        Method::POST,
        "/v1/admin/imports/documents/discover",
        Some(versions(&created)),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{missing}");
    assert_eq!(detail(&app, &token, "documents").await, created);

    let bytes = document(false);
    let (status, discovered) = upload(&app, &token, &created, bytes.clone()).await;
    assert_eq!(status, StatusCode::OK, "{discovered}");
    let metadata = json!({"filename":"inventory.json", "byteLength":bytes.len(),
        "sha256":format!("{:x}", Sha256::digest(&bytes))});
    assert_eq!(discovered["result"]["service"]["document"], metadata);
    assert_eq!(discovered["result"]["service"]["actions"], json!([]));
    assert!(!discovered.to_string().contains(PRIVATE_SOURCE_MARKER));
    let (status, accepted) =
        accept_preview(&app, &token, "documents", &discovered["result"], false).await;
    assert_eq!(status, StatusCode::OK, "{accepted}");
    let action_name = accepted["result"]["service"]["actions"][0]["definition"]["action"].clone();
    let before = detail(&app, &token, "documents").await;
    let previous_preview = broker
        .runtime()
        .managed_store()
        .unwrap()
        .imported_preview("documents")
        .unwrap();
    let invalid =
        format!(r#"{{"openapi":"3.1.1","openapi":"{PRIVATE_SOURCE_MARKER}"}}"#).into_bytes();
    let (status, rejected) = upload(&app, &token, &before, invalid).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{rejected}");
    assert_eq!(rejected["reasonCode"], "input_invalid");
    assert_eq!(rejected["decision"], "deny");
    assert!(!rejected.to_string().contains(PRIVATE_SOURCE_MARKER));
    assert_eq!(detail(&app, &token, "documents").await, before);
    assert_eq!(
        serde_json::to_value(
            broker
                .runtime()
                .managed_store()
                .unwrap()
                .imported_preview("documents")
                .unwrap()
        )
        .unwrap(),
        serde_json::to_value(previous_preview).unwrap()
    );

    let changed = document(true);
    let (status, replaced) = upload(&app, &token, &before, changed.clone()).await;
    assert_eq!(status, StatusCode::OK, "{replaced}");
    assert_eq!(
        replaced["result"]["service"]["actions"][0]["status"],
        "quarantined"
    );
    assert_eq!(
        replaced["result"]["service"]["actions"][0]["definition"]["action"],
        action_name
    );
    assert_eq!(
        replaced["result"]["service"]["document"]["sha256"],
        format!("{:x}", Sha256::digest(&changed))
    );
    assert_eq!(
        upload(&app, &token, &before, bytes).await.0,
        StatusCode::CONFLICT
    );
    let (status, accepted) =
        accept_preview(&app, &token, "documents", &replaced["result"], false).await;
    assert_eq!(status, StatusCode::OK, "{accepted}");
    assert_eq!(
        accepted["result"]["service"]["actions"][0]["definition"]["action"],
        action_name
    );
    assert_eq!(
        accepted["result"]["service"]["actions"][0]["status"],
        "enabled"
    );
    let (_, listed) = request(&app, &token, Method::GET, "/v1/admin/imports", None).await;
    assert!(!listed.to_string().contains(PRIVATE_SOURCE_MARKER));
    drop(app);
    broker.stop().await;

    let broker = import_broker(&fixture.config).await;
    let app = broker.app();
    let current = detail(&app, &token, "documents").await;
    assert_eq!(
        current["service"]["document"],
        accepted["result"]["service"]["document"]
    );
    let (status, rediscovered) = request(
        &app,
        &token,
        Method::POST,
        "/v1/admin/imports/documents/discover",
        Some(versions(&current)),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{rediscovered}");
    assert_eq!(
        rediscovered["result"]["preview"]["manifest"],
        replaced["result"]["preview"]["manifest"]
    );
    assert!(api.received_requests().await.unwrap().is_empty());
    let audit = std::fs::read_to_string(&fixture.config.audit.as_ref().unwrap().path).unwrap();
    assert!(!audit.contains(PRIVATE_SOURCE_MARKER));
    let completion = audit
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).unwrap())
        .find(|row| {
            row["providerAudit"]["management"]["operation"] == "admin.imports.document.upload"
                && row["providerAudit"]["management"]["phase"] == "success"
                && row["providerAudit"]["management"]["target"]["quarantinedActions"]
                    == json!([action_name])
        })
        .unwrap();
    assert_eq!(
        completion["providerAudit"]["management"]["target"]["manifestHash"],
        replaced["result"]["preview"]["manifestHash"]
    );
    drop(app);
    broker.stop().await;
}

#[tokio::test]
async fn upload_rejects_bad_metadata_media_source_and_versions_without_mutation() {
    let mut fixture = fixture();
    let endpoint = "https://api.example.test/api";
    configure(&mut fixture, endpoint);
    let token = admin_token(&fixture);
    let broker = import_broker(&fixture.config).await;
    let app = broker.app();
    let created = create(&app, &token, endpoint).await;
    let path = upload_path(&created);
    let cases = [
        (
            format!("{path}&filename=..%2Fsecret.json"),
            document(false),
            "application/json",
        ),
        (
            format!("{path}&filename=.."),
            document(false),
            "application/json",
        ),
        (
            format!("{path}&filename=bad%00.json"),
            document(false),
            "application/json",
        ),
        (
            format!("{path}&filename={}", "x".repeat(256)),
            document(false),
            "application/json",
        ),
        (
            format!("{path}&expectedVersion=1"),
            document(false),
            "application/json",
        ),
        (
            format!("{path}&unknown={PRIVATE_SOURCE_MARKER}"),
            document(false),
            "application/json",
        ),
        (path.clone(), vec![0xff], "application/json"),
        (path.clone(), Vec::new(), "application/json"),
        (path.clone(), document(false), "application/yaml"),
        (
            path.clone(),
            document(false),
            "application/json; charset=utf-8",
        ),
        (
            "/v1/admin/imports/documents/document?expectedVersion=1".into(),
            document(false),
            "application/json",
        ),
    ];
    for (path, bytes, media) in cases {
        let response = app
            .clone()
            .oneshot(raw_request(&path, bytes, Some(&token), media))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{path}");
        assert!(
            !response_json(response)
                .await
                .to_string()
                .contains(PRIVATE_SOURCE_MARKER)
        );
        assert_eq!(detail(&app, &token, "documents").await, created);
    }
    let mut duplicate_media = raw_request(&path, document(false), Some(&token), "application/json");
    duplicate_media
        .headers_mut()
        .append(CONTENT_TYPE, "application/json".parse().unwrap());
    assert_eq!(
        app.clone().oneshot(duplicate_media).await.unwrap().status(),
        StatusCode::BAD_REQUEST
    );
    let other = detail(&app, &token, "observability").await;
    let response = app
        .clone()
        .oneshot(raw_request(
            &upload_path(&other).replace("/documents/", "/observability/"),
            document(false),
            Some(&token),
            "application/json",
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(detail(&app, &token, "documents").await, created);
    for (key, value) in [
        ("definitionUrl", "https://docs.example.test/spec.json"),
        ("definitionAuthKind", "none"),
        ("definitionAuthHeader", "X-Document-Key"),
    ] {
        let mut definition = upload_definition(endpoint);
        definition.service = "invalid_source".into();
        definition
            .connection_settings
            .insert(key.into(), value.into());
        let (status, response) = request(
            &app,
            &token,
            Method::POST,
            "/v1/admin/imports",
            Some(json!(definition)),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{response}");
        assert!(
            broker
                .runtime()
                .imported_catalog()
                .service("invalid_source")
                .is_none()
        );
        assert_eq!(detail(&app, &token, "documents").await, created);
    }
    drop(app);
    broker.stop().await;
}

#[tokio::test]
async fn upload_requires_admin_and_browser_csrf_before_publication() {
    let mut fixture = fixture();
    let endpoint = "https://api.example.test/api";
    configure(&mut fixture, endpoint);
    let key = fixture
        .config
        .broker_tokens
        .as_ref()
        .unwrap()
        .hash_key_ref
        .clone();
    fixture.config.browser_auth = BrowserAuthConfig {
        enabled: true,
        public_origin: Some("http://localhost".into()),
        csrf_key_ref: Some(key.clone()),
        local_password: LocalPasswordConfig {
            enabled: true,
            pepper_ref: Some(key),
            ..Default::default()
        },
        ..Default::default()
    };
    fixture
        .runtime
        .managed_store()
        .unwrap()
        .patch_principal_access(PrincipalAccessPatchRequest {
            principal_id: "bob".into(),
            role: Some(PrincipalRole::Auditor),
            self_service_enabled: None,
            actor: "admin".into(),
        })
        .unwrap();
    let token = admin_token(&fixture);
    let auditor = admin_token_for(&fixture, "bob");
    let broker = import_broker(&fixture.config).await;
    let app = broker.app();
    let created = create(&app, &token, endpoint).await;
    let path = upload_path(&created);
    for (token, expected) in [
        (None, StatusCode::UNAUTHORIZED),
        (
            Some(fixture.tokens["alice"].as_str()),
            StatusCode::FORBIDDEN,
        ),
        (Some(auditor.as_str()), StatusCode::FORBIDDEN),
    ] {
        assert_eq!(
            app.clone()
                .oneshot(raw_request(
                    &path,
                    document(false),
                    token,
                    "application/json"
                ))
                .await
                .unwrap()
                .status(),
            expected
        );
        assert_eq!(
            detail(&app, &admin_token(&fixture), "documents").await,
            created
        );
    }
    let (cookie, csrf) = {
        let runtime = broker.runtime();
        let store = runtime.managed_store().unwrap();
        let local = store
            .enable_local_password(
                runtime.local_password_hasher().unwrap(),
                LocalPasswordWriteRequest {
                    principal_id: "admin".into(),
                    password: "synthetic-password".into(),
                    min_password_length: 8,
                    password_change_required: false,
                    actor: "admin".into(),
                },
            )
            .unwrap();
        let session = store
            .issue_browser_session(
                runtime.broker_token_hasher().unwrap(),
                BrowserSessionIssueRequest {
                    principal_id: "admin".into(),
                    login_method: "local_password".into(),
                    login_method_id: Some(local.method.login_method_id),
                    ttl_seconds: 3600,
                    password_change_required: false,
                    created_by: "admin".into(),
                },
            )
            .unwrap();
        (
            format!(
                "{}={}",
                fixture.config.browser_auth.session_cookie_name, session.token
            ),
            runtime
                .browser_csrf_key()
                .unwrap()
                .token_for_session(&session.record.token_id)
                .unwrap(),
        )
    };
    for with_csrf in [false, true] {
        let mut request = raw_request(&path, document(false), None, "application/json");
        request
            .headers_mut()
            .insert("Host", "localhost".parse().unwrap());
        request
            .headers_mut()
            .insert("Origin", "http://localhost".parse().unwrap());
        request
            .headers_mut()
            .insert("Cookie", cookie.parse().unwrap());
        if with_csrf {
            request
                .headers_mut()
                .insert("X-Agent-Access-CSRF", csrf.parse().unwrap());
        }
        let response = app.clone().oneshot(request).await.unwrap();
        assert_eq!(
            response.status(),
            if with_csrf {
                StatusCode::OK
            } else {
                StatusCode::FORBIDDEN
            }
        );
        if !with_csrf {
            assert_eq!(detail(&app, &token, "documents").await, created);
        }
    }
    drop(app);
    broker.stop().await;
}

#[tokio::test]
async fn upload_limit_accepts_exact_four_mib_and_respects_smaller_operator_cap() {
    for cap in [IMPORT_MAX_DOCUMENT_BYTES + 1, 2048] {
        let mut fixture = fixture();
        let endpoint = "https://api.example.test/api";
        configure(&mut fixture, endpoint);
        fixture.config.limits.max_http_body_bytes = cap as u64;
        let token = admin_token(&fixture);
        let broker = import_broker(&fixture.config).await;
        let app = broker.app();
        let created = create(&app, &token, endpoint).await;
        let mut bytes = document(false);
        bytes.resize(IMPORT_MAX_DOCUMENT_BYTES, b' ');
        if cap > IMPORT_MAX_DOCUMENT_BYTES {
            for authorization in [None, Some("synthetic-invalid-admin-token")] {
                let anonymous = app
                    .clone()
                    .oneshot(raw_request(
                        &upload_path(&created),
                        bytes[..1024 * 1024 + 1].to_vec(),
                        authorization,
                        "application/json",
                    ))
                    .await
                    .unwrap();
                assert_eq!(anonymous.status(), StatusCode::PAYLOAD_TOO_LARGE);
                assert_eq!(detail(&app, &token, "documents").await, created);
            }
            let (status, accepted) = upload(&app, &token, &created, bytes.clone()).await;
            assert_eq!(status, StatusCode::OK, "{accepted}");
            assert_eq!(
                accepted["result"]["service"]["document"]["byteLength"],
                IMPORT_MAX_DOCUMENT_BYTES
            );
        }
        let current = detail(&app, &token, "documents").await;
        bytes.resize(
            if cap > IMPORT_MAX_DOCUMENT_BYTES {
                IMPORT_MAX_DOCUMENT_BYTES + 1
            } else {
                cap + 1
            },
            b' ',
        );
        let response = app
            .clone()
            .oneshot(raw_request(
                &upload_path(&current),
                bytes,
                Some(&token),
                "application/json",
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
        assert_eq!(detail(&app, &token, "documents").await, current);
        drop(app);
        broker.stop().await;
    }
}

#[tokio::test]
async fn uploaded_document_discovery_byte_limit_returns_caller_denial_without_mutation() {
    let mut fixture = fixture();
    let endpoint = "https://api.example.test/api";
    configure(&mut fixture, endpoint);
    let mut bytes = document(false);
    let limit = bytes.len();
    fixture.config.limits.max_upstream_response_bytes = limit as u64;
    let token = admin_token(&fixture);
    let broker = import_broker(&fixture.config).await;
    let app = broker.app();
    let created = create(&app, &token, endpoint).await;
    bytes.push(b'\n');
    let (status, rejected) = upload(&app, &token, &created, bytes).await;
    assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE, "{rejected}");
    assert_eq!(rejected["reasonCode"], "body_size_denied");
    assert_eq!(rejected["decision"], "deny");
    assert!(!rejected.to_string().contains(PRIVATE_SOURCE_MARKER));
    assert_eq!(detail(&app, &token, "documents").await, created);
    assert!(
        broker
            .runtime()
            .managed_store()
            .unwrap()
            .imported_preview("documents")
            .unwrap()
            .is_none()
    );
    drop(app);
    broker.stop().await;
}

#[tokio::test]
async fn empty_draft_source_transition_drops_uploaded_metadata_and_gate_still_applies() {
    let mut fixture = fixture();
    let endpoint = "https://api.example.test/api";
    configure(&mut fixture, endpoint);
    fixture
        .config
        .imports
        .allowed_endpoints
        .push("https://docs.example.test/spec.json".into());
    let token = admin_token(&fixture);
    let broker = import_broker(&fixture.config).await;
    let app = broker.app();
    let created = create(&app, &token, endpoint).await;
    let (status, uploaded) = upload(&app, &token, &created, document(false)).await;
    assert_eq!(status, StatusCode::OK, "{uploaded}");
    let mut definition = upload_definition(endpoint);
    definition.connection_settings.remove("definitionSource");
    definition.connection_settings.insert(
        "definitionUrl".into(),
        "https://docs.example.test/spec.json".into(),
    );
    let mut body = versions(&uploaded["result"]);
    body["definition"] = json!(definition);
    let (status, switched) = request(
        &app,
        &token,
        Method::PATCH,
        "/v1/admin/imports/documents",
        Some(body),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{switched}");
    assert!(switched["result"]["service"].get("document").is_none());
    assert_eq!(
        upload(&app, &token, &switched["result"], document(false))
            .await
            .0,
        StatusCode::BAD_REQUEST
    );
    let mut body = versions(&switched["result"]);
    body["definition"] = json!(upload_definition(endpoint));
    let (status, returned) = request(
        &app,
        &token,
        Method::PATCH,
        "/v1/admin/imports/documents",
        Some(body),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{returned}");
    assert!(returned["result"]["service"].get("document").is_none());
    let (status, missing) = request(
        &app,
        &token,
        Method::POST,
        "/v1/admin/imports/documents/discover",
        Some(versions(&returned["result"])),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{missing}");
    drop(app);
    broker.stop().await;

    fixture.config.imports.enabled = false;
    let broker = import_broker(&fixture.config).await;
    let app = broker.app();
    let current = detail(&app, &token, "documents").await;
    assert!(
        !upload(&app, &token, &current, document(false))
            .await
            .0
            .is_success()
    );
    assert_eq!(detail(&app, &token, "documents").await, current);
    drop(app);
    broker.stop().await;
}
