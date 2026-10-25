use super::*;

fn uploaded(mut definition: ImportedServiceDefinition) -> ImportedServiceDefinition {
    definition.connection_settings.remove("definitionUrl");
    definition
        .connection_settings
        .insert("definitionSource".into(), "upload".into());
    definition
}

#[test]
fn upload_mode_has_no_document_destination_or_discovery_credential() {
    let definition = uploaded(basic_definition());
    OpenApiAdapter.validate_definition(&definition).unwrap();
    assert_eq!(
        OpenApiAdapter.discovery_source(&definition).unwrap(),
        ImportedDiscoverySource::StoredDocument
    );
    assert!(
        OpenApiAdapter
            .additional_destinations(&definition)
            .unwrap()
            .is_empty()
    );
    let contract = OpenApiAdapter
        .credential_contract(&definition, &ImportedAdapterContext::default())
        .unwrap();
    assert!(
        contract
            .requirement(ImportedCredentialPurpose::Discovery)
            .is_none()
    );
    assert!(
        contract
            .requirement(ImportedCredentialPurpose::Execution)
            .is_some()
    );

    for (key, value) in [
        ("definitionUrl", "https://docs.example.test/spec.json"),
        ("definitionAuthKind", "none"),
        ("definitionAuthKind", "basic"),
        ("definitionAuthHeader", "X-Key"),
        ("definitionSource", "url"),
        ("definitionSource", "file"),
        ("definitionSource", ""),
    ] {
        let mut invalid = definition.clone();
        invalid.connection_settings.insert(key.into(), value.into());
        assert!(
            OpenApiAdapter.validate_definition(&invalid).is_err(),
            "{key}={value}"
        );
    }
    for discovery in [
        ImportedDiscoveryCredential::Execution,
        ImportedDiscoveryCredential::Slot,
        ImportedDiscoveryCredential::PerUser {
            principal: "alice".into(),
        },
    ] {
        let mut invalid = definition.clone();
        invalid.discovery = discovery;
        assert!(OpenApiAdapter.validate_definition(&invalid).is_err());
    }
    let url = basic_definition();
    assert_eq!(
        OpenApiAdapter.discovery_source(&url).unwrap(),
        ImportedDiscoverySource::Remote
    );
    assert_eq!(
        OpenApiAdapter.additional_destinations(&url).unwrap(),
        ["https://docs.example.test/spec.json"]
    );
}

#[tokio::test]
async fn uploaded_bytes_share_url_plans_and_execute_offline_without_document_http() {
    for mut source in [swagger(), equivalent_openapi()] {
        // Both source locations have the API's origin. Explicit /api plus the
        // same source defaults must produce exactly the same accepted plans.
        for key in ["host", "schemes", "servers"] {
            source.as_object_mut().unwrap().remove(key);
        }
        source["paths"]["/items"]["post"]["responses"] = json!({"204":{"description":"Empty"}});
        let fixture = Fixture::new(source.clone(), 204, Value::Null, Duration::ZERO).await;
        let mut definition = basic_definition();
        definition.endpoint = format!("{}/api", fixture.base);
        definition.connection_settings.insert(
            "definitionUrl".into(),
            format!("{}/definition.json", fixture.base),
        );
        let host = test_host();
        let remote = OpenApiAdapter
            .discover(
                &definition,
                &ImportedDiscoveryAuthentication::Anonymous,
                None,
                &ImportedAdapterContext::default(),
                &host.context(),
            )
            .await
            .unwrap();
        assert_eq!(fixture.call_count(), 1);
        let definition = uploaded(definition);
        let bytes = serde_json::to_vec(&source).unwrap();
        let local = OpenApiAdapter
            .discover(
                &definition,
                &ImportedDiscoveryAuthentication::Anonymous,
                None,
                &ImportedAdapterContext::default().with_document(&bytes),
                &host.context(),
            )
            .await
            .unwrap();
        assert_eq!(
            fixture.call_count(),
            1,
            "upload discovery must make no HTTP request"
        );
        assert_eq!(
            serde_json::to_vec(&local).unwrap(),
            serde_json::to_vec(&remote).unwrap()
        );
        let action = local.tools.into_iter().next().unwrap();
        assert!(action.unsupported_reason.is_none());
        // Accepted execution needs no retained source bytes, including after a
        // fresh offline build. Only the API invocation may make another request.
        let provider = OpenApiAdapter
            .build(
                &definition,
                &[action.definition],
                None,
                &ImportedAdapterContext::default(),
                &host.context(),
            )
            .unwrap()
            .provider();
        assert_eq!(fixture.call_count(), 1);
        provider
            .invoke(
                InvocationBuilder::new("example", "items")
                    .inputs(json!({"body":{"query":"upload + 雪","page":2}}))
                    .credential(basic_credential("api-user", "api-secret"))
                    .build(),
            )
            .await
            .unwrap();
        let calls = fixture.state.calls.lock().unwrap();
        assert_eq!(calls.len(), 2);
        assert_eq!(calls[1].path, "/api/items");
        assert_eq!(calls[1].method, Method::POST);
        assert_eq!(
            calls[1].headers["content-type"],
            "application/x-www-form-urlencoded"
        );
        assert_eq!(calls[1].body.as_ref(), b"page=2&query=upload+%2B+%E9%9B%AA");
    }
}

#[tokio::test]
async fn uploads_reject_missing_mismatched_or_credentialed_inputs_without_http() {
    let fixture = Fixture::new(swagger(), 204, Value::Null, Duration::ZERO).await;
    let mut url = basic_definition();
    url.endpoint = format!("{}/api", fixture.base);
    url.connection_settings.insert(
        "definitionUrl".into(),
        format!("{}/definition.json", fixture.base),
    );
    let upload = uploaded(url.clone());
    let host = test_host();
    let bytes = serde_json::to_vec(&swagger()).unwrap();
    for (definition, document, authentication, transport) in [
        (
            &upload,
            None,
            ImportedDiscoveryAuthentication::Anonymous,
            None,
        ),
        (
            &url,
            Some(bytes.as_slice()),
            ImportedDiscoveryAuthentication::Anonymous,
            None,
        ),
        (
            &upload,
            Some(bytes.as_slice()),
            ImportedDiscoveryAuthentication::Static(basic_credential("document", "secret")),
            None,
        ),
        (
            &upload,
            Some(bytes.as_slice()),
            ImportedDiscoveryAuthentication::Anonymous,
            Some(basic_credential("transport", "secret")),
        ),
    ] {
        let import = match document {
            Some(bytes) => ImportedAdapterContext::default().with_document(bytes),
            None => ImportedAdapterContext::default(),
        };
        assert!(
            OpenApiAdapter
                .discover(
                    definition,
                    &authentication,
                    transport,
                    &import,
                    &host.context()
                )
                .await
                .is_err()
        );
        assert_eq!(fixture.call_count(), 0);
    }
}

#[tokio::test]
async fn uploads_use_original_json_bytes_and_the_same_document_limits() {
    let definition = uploaded(basic_definition());
    let host = test_host();
    let mut at_limit = serde_json::to_vec(&swagger()).unwrap();
    at_limit.resize(256 * 1024, b' ');
    let valid = OpenApiAdapter
        .discover(
            &definition,
            &ImportedDiscoveryAuthentication::Anonymous,
            None,
            &ImportedAdapterContext::default().with_document(&at_limit),
            &host.context(),
        )
        .await
        .unwrap();
    assert!(valid.tools[0].unsupported_reason.is_none());

    let mut over_limit = at_limit;
    over_limit.push(b' ');
    let mut deep = json!("literal");
    for _ in 0..66 {
        deep = json!([deep]);
    }
    for (bytes, reason, diagnostic) in [
        (
            br#"{"swagger":"2.0","swagger":"2.0","private":"do-not-echo"}"#.to_vec(),
            ReasonCode::InputInvalid,
            "duplicate JSON member in definition",
        ),
        (
            vec![0xff],
            ReasonCode::InputInvalid,
            "definition must be bounded JSON",
        ),
        (
            serde_json::to_vec(&deep).unwrap(),
            ReasonCode::InputInvalid,
            "definition exceeds JSON depth limit",
        ),
        (
            over_limit,
            ReasonCode::BodySizeDenied,
            "OpenAPI definition exceeds the discovery byte limit",
        ),
    ] {
        let error = OpenApiAdapter
            .discover(
                &definition,
                &ImportedDiscoveryAuthentication::Anonymous,
                None,
                &ImportedAdapterContext::default().with_document(&bytes),
                &host.context(),
            )
            .await
            .unwrap_err();
        let AdapterDiscoveryError::Failed(error) = error else {
            panic!("unexpected configuration error")
        };
        assert_eq!(error.reason_code(), reason);
        assert_eq!(error.decision(), Decision::Deny);
        assert!(
            reason.permits_provider_failure(&error.decision(), HookPhase::CredentialVerification)
        );
        assert_eq!(error.message, diagnostic);
        assert!(!error.message.contains("do-not-echo"));
    }
    let large_host = test_support::TestHost::with_limits(
        ProviderLimits::default().with_max_upstream_response_bytes(8 * 1024 * 1024),
    );
    let mut bytes = serde_json::to_vec(&swagger()).unwrap();
    bytes.resize(IMPORT_MAX_DOCUMENT_BYTES + 1, b' ');
    let error = OpenApiAdapter
        .discover(
            &definition,
            &ImportedDiscoveryAuthentication::Anonymous,
            None,
            &ImportedAdapterContext::default().with_document(&bytes),
            &large_host.context(),
        )
        .await
        .unwrap_err();
    let AdapterDiscoveryError::Failed(error) = error else {
        panic!("unexpected configuration error")
    };
    assert_eq!(error.reason_code(), ReasonCode::BodySizeDenied);
    assert_eq!(error.decision(), Decision::Deny);
    assert_eq!(
        error.message,
        "OpenAPI definition exceeds the discovery byte limit"
    );
}

#[test]
fn uploaded_destinations_resolve_against_the_approved_api_base_and_keep_security_checks() {
    let definition = uploaded(basic_definition());
    let mut swagger_source = swagger();
    swagger_source.as_object_mut().unwrap().remove("host");
    swagger_source.as_object_mut().unwrap().remove("schemes");
    assert!(
        row(swagger_source.clone(), &definition)
            .unsupported_reason
            .is_none()
    );
    for (key, value) in [
        ("host", json!("other.example.test")),
        ("schemes", json!(["http"])),
        ("basePath", json!("/other")),
        ("security", json!([])),
    ] {
        let mut invalid = swagger_source.clone();
        invalid[key] = value;
        assert!(
            row(invalid, &definition).unsupported_reason.is_some(),
            "{key}"
        );
    }
    let source = equivalent_openapi();
    for servers in [
        None,
        Some(json!([{"url":"/api"}])),
        Some(json!([{"url":"api"}])),
    ] {
        let mut valid = source.clone();
        match servers {
            Some(servers) => valid["servers"] = servers,
            None => {
                valid.as_object_mut().unwrap().remove("servers");
            }
        }
        assert!(row(valid, &definition).unsupported_reason.is_none());
    }
    for server in ["https://other.example.test/api", "/other"] {
        let mut invalid = source.clone();
        invalid["servers"] = json!([{"url":server}]);
        assert!(row(invalid, &definition).unsupported_reason.is_some());
    }
    let mut invalid = source.clone();
    invalid["security"] = json!([]);
    assert!(row(invalid, &definition).unsupported_reason.is_some());
    let mut invalid = source;
    invalid["paths"]["/items"]["post"]["requestBody"]["content"]["application/x-www-form-urlencoded"]
        ["schema"] = json!({"$ref":"https://other.example.test/schema.json"});
    assert!(row(invalid, &definition).unsupported_reason.is_some());
}

#[tokio::test]
async fn uploaded_input_failures_are_client_errors_while_url_failures_remain_upstream_errors() {
    let mut excessive_operations = swagger();
    let operation = excessive_operations["paths"]["/items"].clone();
    excessive_operations["paths"] = Value::Object(
        (0..513)
            .map(|index| (format!("/item{index}"), operation.clone()))
            .collect(),
    );
    let mut excessive_manifest = swagger();
    excessive_manifest["definitions"] =
        json!({"Expanded":{"type":"object","description":"x".repeat(100 * 1024)}});
    excessive_manifest["paths"] = Value::Object(
        (0..180).map(|index| (format!("/item{index}"), json!({"post":{
            "parameters":[{"in":"body","name":"body","schema":{"$ref":"#/definitions/Expanded"}}],
            "responses":{"204":{"description":"Empty"}}
        }}))).collect(),
    );
    let manifest_bytes = serde_json::to_vec(&excessive_manifest).unwrap();
    assert!(manifest_bytes.len() < 256 * 1024);
    assert!(
        row(excessive_manifest, &basic_definition())
            .unsupported_reason
            .is_none()
    );
    let mut excessive_bytes = serde_json::to_vec(&swagger()).unwrap();
    excessive_bytes.resize(256 * 1024 + 1, b' ');
    for (bytes, upload_reason, diagnostic) in [
        (
            b"{".to_vec(),
            ReasonCode::InputInvalid,
            "definition must be bounded JSON",
        ),
        (
            br#"{"swagger":"2.0","swagger":"2.0"}"#.to_vec(),
            ReasonCode::InputInvalid,
            "duplicate JSON member in definition",
        ),
        (
            br#"{"openapi":"3.0.3","paths":{}}"#.to_vec(),
            ReasonCode::InputInvalid,
            "definition requires exactly one supported version marker: swagger 2.0 or openapi 3.1.x",
        ),
        (
            serde_json::to_vec(&excessive_operations).unwrap(),
            ReasonCode::InputInvalid,
            "definition exceeds 512 operations",
        ),
        (
            manifest_bytes,
            ReasonCode::InputInvalid,
            "OpenAPI discovery exceeds the imported manifest size budget",
        ),
        (
            excessive_bytes,
            ReasonCode::BodySizeDenied,
            "OpenAPI definition exceeds the discovery byte limit",
        ),
    ] {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let requests = Arc::new(AtomicUsize::new(0));
        let observed = requests.clone();
        let served = bytes.clone();
        let router = Router::new().fallback(any(move || {
            let observed = observed.clone();
            let body = served.clone();
            async move {
                observed.fetch_add(1, Ordering::SeqCst);
                ([("content-type", "application/json")], body)
            }
        }));
        let task = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
        let mut definition = basic_definition();
        definition.connection_settings.insert(
            "definitionUrl".into(),
            format!("http://{address}/definition.json"),
        );
        let host = test_host();
        let error = OpenApiAdapter
            .discover(
                &uploaded(definition.clone()),
                &ImportedDiscoveryAuthentication::Anonymous,
                None,
                &ImportedAdapterContext::default().with_document(&bytes),
                &host.context(),
            )
            .await
            .unwrap_err();
        let AdapterDiscoveryError::Failed(error) = error else {
            panic!("unexpected configuration error")
        };
        assert_eq!(requests.load(Ordering::SeqCst), 0);
        assert_eq!(error.reason_code(), upload_reason);
        assert_eq!(error.decision(), Decision::Deny);
        assert_eq!(
            error.reason_code().http_status(),
            if upload_reason == ReasonCode::BodySizeDenied {
                413
            } else {
                400
            }
        );
        assert_eq!(error.message, diagnostic);
        assert!(
            upload_reason
                .permits_provider_failure(&error.decision(), HookPhase::CredentialVerification)
        );

        let error = OpenApiAdapter
            .discover(
                &definition,
                &ImportedDiscoveryAuthentication::Anonymous,
                None,
                &ImportedAdapterContext::default(),
                &host.context(),
            )
            .await
            .unwrap_err();
        let AdapterDiscoveryError::Failed(error) = error else {
            panic!("unexpected configuration error")
        };
        assert_eq!(requests.load(Ordering::SeqCst), 1);
        assert_eq!(error.reason_code(), ReasonCode::UpstreamProtocolFailed);
        assert_eq!(error.decision(), Decision::Error);
        assert_eq!(error.reason_code().http_status(), 502);
        assert!(
            ReasonCode::UpstreamProtocolFailed
                .permits_provider_failure(&error.decision(), HookPhase::CredentialVerification)
        );
        if upload_reason != ReasonCode::BodySizeDenied {
            assert_eq!(error.message, diagnostic);
        }
        task.abort();
    }
}
