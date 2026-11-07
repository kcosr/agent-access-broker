use super::*;

#[tokio::test]
async fn openapi_gateway_missing_linked_protocol_preserves_import_and_reserved_host_on_restart() {
    let upstream = Upstream::start().await;
    let fixture = Fixture::ready(&upstream, UpstreamAuth::Anonymous, &["read_item"]).await;
    let before = fixture.detail().await;
    let response = fixture
        .gateway(Method::GET, "/items/alpha", "before-module-removal")
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    response.bytes().await.unwrap();
    let missing = fixture
        .gateway(
            Method::GET,
            "/not-in-document",
            "before-module-missing-route",
        )
        .send()
        .await
        .unwrap();
    assert_eq!(missing.status(), StatusCode::NOT_FOUND);
    let missing_body = missing.bytes().await.unwrap();
    let fixture = fixture.restart_without_gateway().await;
    let after = fixture.detail().await;
    assert_eq!(after["catalogRevision"], before["catalogRevision"]);
    assert_eq!(after["service"]["actions"], before["service"]["actions"]);
    assert_eq!(after["service"]["status"], "enabled");
    let response = fixture
        .gateway(Method::GET, "/items/alpha", "missing-linked-module")
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    assert_eq!(
        response.headers()[REASON_CODE_HEADER],
        "gateway_rule_not_found"
    );
    assert_eq!(response.bytes().await.unwrap(), missing_body);
    assert_eq!(upstream.api_requests().len(), 1);
    fixture.stop().await;
}

#[tokio::test]
async fn openapi_gateway_future_route_envelope_stays_unavailable_and_reserved_offline() {
    use agent_access_core::imports::ImportedGatewayRouteCandidate;

    const UNAVAILABLE: &str =
        "The retained gateway route manifest version is not supported by this broker.";
    let upstream = Upstream::start().await;
    let fixture = Fixture::ready(&upstream, UpstreamAuth::Anonymous, &["read_item"]).await;
    let before = fixture.detail().await;
    assert_eq!(before["available"], true);
    let original_grants = serde_json::to_value(
        fixture
            .broker
            .runtime()
            .managed_store()
            .unwrap()
            .policy_grants()
            .unwrap(),
    )
    .unwrap();
    let missing = fixture
        .gateway(Method::GET, "/not-in-document", "before-future-envelope")
        .send()
        .await
        .unwrap();
    assert_eq!(missing.status(), StatusCode::NOT_FOUND);
    let missing_body = missing.bytes().await.unwrap();
    assert!(upstream.api_requests().is_empty());
    let Fixture {
        seed,
        broker,
        client,
        admin,
        agent,
        ..
    } = fixture;
    broker.stop().await;
    // Neither startup nor reload may fetch a source or contact this origin.
    drop(upstream);

    let database = &seed.config.managed_store.as_ref().unwrap().path;
    let connection = rusqlite::Connection::open(database).unwrap();
    let (json, generation): (String, i64) = connection
        .query_row(
            "SELECT manifest_json,generation FROM imported_gateway_routes WHERE service=?1",
            [SERVICE],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    let mut candidate: ImportedGatewayRouteCandidate = serde_json::from_str(&json).unwrap();
    assert_eq!(candidate.version, 1);
    assert!(generation > 0);
    let retained_data = candidate.data.clone();
    candidate.version = 2;
    let encoded = String::from_utf8(candidate.encoded().unwrap()).unwrap();
    let content_hash = candidate.content_hash().unwrap();
    assert_eq!(connection.execute(
        "UPDATE imported_gateway_routes SET manifest_json=?1,content_hash=?2 WHERE service=?3",
        rusqlite::params![encoded, content_hash, SERVICE],
    ).unwrap(), 1);
    drop(connection);

    let broker = TestBroker::start_with(
        TestBroker::config_builder(&seed.config)
            .gateway_listener()
            .unwrap()
            .shutdown_timeout(Duration::from_secs(5)),
    )
    .await;
    for (label, reload) in [("future-restart", false), ("future-reload", true)] {
        if reload {
            let mut config = seed.config.clone();
            config.mcp.session_idle_timeout_ms -= 1;
            broker.reload_config(&config).await;
        }
        let response = client
            .get(format!(
                "{}/v1/admin/imports/{SERVICE}",
                broker.running().public_url()
            ))
            .bearer_auth(&admin)
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let result: Value = response.json().await.unwrap();
        let after = &result["result"];
        assert_eq!(after["available"], false);
        assert_eq!(after["unavailableReason"], UNAVAILABLE);
        assert_eq!(after["catalogRevision"], before["catalogRevision"]);
        assert_eq!(after["service"]["status"], "enabled");
        assert_eq!(after["service"]["version"], before["service"]["version"]);
        assert_eq!(after["service"]["actions"], before["service"]["actions"]);
        let runtime = broker.runtime();
        assert_eq!(
            serde_json::to_value(runtime.managed_store().unwrap().policy_grants().unwrap())
                .unwrap(),
            original_grants
        );
        let routes = runtime
            .imported_catalog()
            .service(SERVICE)
            .unwrap()
            .gateway_routes
            .as_ref()
            .unwrap();
        assert_eq!(routes.manifest.version, 2);
        assert_eq!(routes.manifest.data, retained_data);
        assert_eq!(routes.generation, generation as u64);
        assert_eq!(routes.content_hash, content_hash);

        for (index, path) in ["/items/alpha", "/items/private", "/not-in-document"]
            .into_iter()
            .enumerate()
        {
            let id = format!("{label}-{index}");
            let response = client
                .get(format!(
                    "http://{}{path}",
                    broker.running().gateway_addr().unwrap()
                ))
                .header(HOST, GATEWAY_HOST)
                .bearer_auth(&agent)
                .header(REQUEST_ID_HEADER, &id)
                .send()
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::NOT_FOUND);
            assert_eq!(
                response.headers()[REASON_CODE_HEADER],
                "gateway_rule_not_found"
            );
            assert!(response.headers().get("allow").is_none());
            assert_eq!(response.bytes().await.unwrap(), missing_body);
            let records = tokio::time::timeout(Duration::from_secs(5), async {
                loop {
                    let records =
                        read_audit_records(Path::new(&seed.config.audit.as_ref().unwrap().path))
                            .into_iter()
                            .filter(|record| record["agentRequestId"] == id)
                            .collect::<Vec<_>>();
                    if !records.is_empty() {
                        break records;
                    }
                    tokio::time::sleep(Duration::from_millis(5)).await;
                }
            })
            .await
            .expect("unavailable route denial is audited");
            assert_eq!(records.len(), 1);
            assert_eq!(records[0]["action"], "gateway.classify");
            assert_eq!(records[0]["reasonCode"], "gateway_rule_not_found");
            assert_ne!(records[0]["providerAudit"]["gateway"]["phase"], "started");
        }
        let unmatched = client
            .get(format!(
                "http://{}/items/alpha",
                broker.running().gateway_addr().unwrap()
            ))
            .header(HOST, "unreserved.gateway.example.test")
            .bearer_auth(&agent)
            .header(REQUEST_ID_HEADER, format!("{label}-unmatched"))
            .send()
            .await
            .unwrap();
        assert_eq!(unmatched.status(), StatusCode::NOT_FOUND);
        assert_eq!(
            unmatched.headers()[REASON_CODE_HEADER],
            "gateway_host_unmatched"
        );
        unmatched.bytes().await.unwrap();
        drop(runtime);
    }
    broker.stop().await;
}

#[tokio::test]
async fn openapi_gateway_new_unaccepted_literal_narrows_template_without_quarantining_it() {
    let upstream = Upstream::start().await;
    let fixture = Fixture::start(&upstream, |_| {}).await;
    let mut original = document(
        Dialect::OpenApi31,
        UpstreamAuth::Anonymous,
        &upstream.endpoint(),
    );
    original["paths"]
        .as_object_mut()
        .unwrap()
        .remove("/items/private");
    let preview = fixture
        .create_and_discover(DefinitionSource::Upload, UpstreamAuth::Anonymous, &original)
        .await;
    fixture.accept(&preview, &["read_item"]).await;
    fixture.enable().await;
    fixture.grant(&["read_item"]).await;
    let response = fixture
        .gateway(Method::GET, "/items/private", "template-before-literal")
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    response.bytes().await.unwrap();
    let expanded = document(
        Dialect::OpenApi31,
        UpstreamAuth::Anonymous,
        &upstream.endpoint(),
    );
    let preview = fixture.upload(&expanded).await;
    assert!(
        preview["service"]["actions"]
            .as_array()
            .unwrap()
            .iter()
            .any(|action| action["definition"]["action"] == "read_item"
                && action["status"] == "enabled")
    );
    for (label, document) in [("new-literal", expanded), ("removed-literal", original)] {
        if label == "removed-literal" {
            fixture.upload(&document).await;
        }
        let before = upstream.api_requests().len();
        let response = fixture
            .gateway(Method::GET, "/items/private", label)
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        assert_eq!(
            response.headers()[REASON_CODE_HEADER],
            "gateway_rule_not_found"
        );
        assert_eq!(upstream.api_requests().len(), before);
        let response = fixture
            .gateway(Method::GET, "/items/ordinary", &format!("{label}-template"))
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        response.bytes().await.unwrap();
        assert_eq!(upstream.api_requests().len(), before + 1);
    }
    fixture.stop().await;
}

#[tokio::test]
async fn openapi_gateway_case_variants_cannot_bypass_more_specific_literal_guards() {
    let upstream = Upstream::start().await;
    let fixture = Fixture::start(&upstream, |_| {}).await;
    let mut source = document(
        Dialect::OpenApi31,
        UpstreamAuth::Anonymous,
        &upstream.endpoint(),
    );
    let guard = source["paths"]
        .as_object_mut()
        .unwrap()
        .remove("/items/private")
        .unwrap();
    source["paths"]["/items/admin"] = guard;
    let mut broad = source["paths"]["/items/{id}"]["get"].clone();
    broad["operationId"] = json!("read_collection_item");
    broad["parameters"].as_array_mut().unwrap().push(json!({
        "name":"collection","in":"path","required":true,
        "schema":{"type":"string","minLength":1,"maxLength":64}
    }));
    source["paths"]["/{collection}/{id}"] = json!({"get":broad});
    let preview = fixture
        .create_and_discover(DefinitionSource::Upload, UpstreamAuth::Anonymous, &source)
        .await;
    fixture
        .accept(&preview, &["read_item", "read_collection_item"])
        .await;
    fixture.enable().await;
    fixture.grant(&["read_item", "read_collection_item"]).await;
    let mut generic_body = None;
    for (index, path) in [
        "/items/admin",
        "/items/ADMIN",
        "/items/aDmIn",
        "/ITEMS/admin",
        "/ItEmS/aDmIn",
        "/items/%41DMIN",
        "/ITEMS/ordinary",
    ]
    .into_iter()
    .enumerate()
    {
        let response = fixture
            .gateway(Method::GET, path, &format!("case-guard-{index}"))
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND, "{path}");
        assert_eq!(
            response.headers()[REASON_CODE_HEADER],
            "gateway_rule_not_found",
            "{path}"
        );
        assert!(response.headers().get("allow").is_none());
        let body = response.bytes().await.unwrap();
        if let Some(expected) = &generic_body {
            assert_eq!(&body, expected, "{path}");
        } else {
            generic_body = Some(body);
        }
        assert!(upstream.api_requests().is_empty(), "{path}");
    }
    // Ordinary parameter values and less-specific routes retain their exact
    // case. The guard prevents alias dispatch; it never rewrites a request.
    for (index, path, action) in [
        (0, "/items/ALPHA", "read_item"),
        (1, "/OTHER/ordinary", "read_collection_item"),
    ] {
        let id = format!("case-ordinary-{index}");
        let response = fixture
            .gateway(Method::GET, path, &id)
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body: Value = response.json().await.unwrap();
        assert_eq!(body["path"], format!("/api{path}"));
        assert_eq!(upstream.api_requests()[index].path, format!("/api{path}"));
        assert_eq!(fixture.terminal(&id).await["action"], action);
    }
    assert_eq!(upstream.api_requests().len(), 2);
    fixture.stop().await;
}

#[tokio::test]
async fn openapi_gateway_configured_identity_headers_cannot_become_upstream_parameters() {
    fn add_identity_source(config: &mut BrokerConfig) {
        config.identity.sources.push(IdentitySourceConfig {
            name: "synthetic_header".into(),
            kind: "broker_tokens".into(),
            header: "X-Broker-Token".into(),
            scheme: "Bearer".into(),
            principals: vec![],
        });
    }
    for configured_before_discovery in [true, false] {
        let upstream = Upstream::start().await;
        let fixture = Fixture::start(&upstream, |config| {
            if configured_before_discovery {
                add_identity_source(config);
            }
        })
        .await;
        let mut source = document(
            Dialect::OpenApi31,
            UpstreamAuth::Anonymous,
            &upstream.endpoint(),
        );
        source["paths"]["/items/{id}"]["get"]["parameters"]
            .as_array_mut()
            .unwrap()
            .push(json!({
                "name":"x-bRoKeR-tOkEn","in":"header","schema":{"type":"string","maxLength":256}
            }));
        let preview = fixture
            .create_and_discover(DefinitionSource::Upload, UpstreamAuth::Anonymous, &source)
            .await;
        let tools = preview["preview"]["manifest"]["tools"].as_array().unwrap();
        let declared = tools
            .iter()
            .find(|tool| tool["definition"]["action"] == "read_item")
            .unwrap();
        if configured_before_discovery {
            assert!(
                declared["unsupportedReason"]
                    .as_str()
                    .is_some_and(|reason| !reason.is_empty()),
                "{declared}"
            );
            let ordinary = tools
                .iter()
                .find(|tool| tool["definition"]["action"] == "private_item")
                .unwrap();
            assert!(ordinary.get("unsupportedReason").is_none_or(Value::is_null));
            let mut request = versions(&preview);
            request["manifestHash"] = preview["preview"]["manifestHash"].clone();
            request["confirmAffectedGrants"] = json!(true);
            request["selections"] = json!([{
                "source":declared["definition"]["source"],"action":"read_item","readOnly":true
            }]);
            let (status, _) = fixture
                .admin_request(
                    Method::POST,
                    "/v1/admin/imports/inventory/accept",
                    Some(request),
                )
                .await;
            assert_eq!(status, StatusCode::BAD_REQUEST);
            assert!(
                fixture.detail().await["service"]["actions"]
                    .as_array()
                    .unwrap()
                    .is_empty()
            );
            fixture.accept(&preview, &["private_item"]).await;
            fixture.enable().await;
            fixture.grant(&["private_item"]).await;
            let supplied = format!("Bearer {}", fixture.agent);
            let response = fixture
                .gateway(Method::GET, "/items/private", "undeclared-identity-header")
                .header("X-Broker-Token", &supplied)
                .send()
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK);
            response.bytes().await.unwrap();
            assert_eq!(upstream.api_requests().len(), 1);
            assert!(
                !upstream.api_requests()[0]
                    .headers
                    .contains_key("x-broker-token")
            );
            assert!(
                !upstream.api_requests()[0]
                    .headers
                    .contains_key(AUTHORIZATION)
            );
            let terminal = fixture.terminal("undeclared-identity-header").await;
            assert!(!terminal.to_string().contains(&fixture.agent));
        } else {
            assert!(declared.get("unsupportedReason").is_none_or(Value::is_null));
            fixture.accept(&preview, &["read_item"]).await;
            fixture.enable().await;
            fixture.grant(&["read_item"]).await;
            let response = fixture
                .gateway(Method::GET, "/items/alpha", "ordinary-header-before-reload")
                .header("X-Broker-Token", "synthetic-ordinary-parameter")
                .send()
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK);
            response.bytes().await.unwrap();
            assert_eq!(upstream.api_requests().len(), 1);
            assert_eq!(
                upstream.api_requests()[0].headers["x-broker-token"],
                "synthetic-ordinary-parameter"
            );
            let before = fixture.detail().await;
            let grants = serde_json::to_value(
                fixture
                    .broker
                    .runtime()
                    .managed_store()
                    .unwrap()
                    .policy_grants()
                    .unwrap(),
            )
            .unwrap();
            let missing = fixture
                .gateway(
                    Method::GET,
                    "/not-in-document",
                    "before-identity-header-reload",
                )
                .send()
                .await
                .unwrap();
            assert_eq!(missing.status(), StatusCode::NOT_FOUND);
            let missing_body = missing.bytes().await.unwrap();
            let mut config = fixture.seed.config.clone();
            add_identity_source(&mut config);
            fixture.broker.reload_config(&config).await;
            let after = fixture.detail().await;
            assert_eq!(after["available"], false);
            assert!(
                after["unavailableReason"]
                    .as_str()
                    .is_some_and(|reason| !reason.is_empty())
            );
            assert_eq!(after["catalogRevision"], before["catalogRevision"]);
            assert_eq!(after["service"]["actions"], before["service"]["actions"]);
            assert_eq!(
                serde_json::to_value(
                    fixture
                        .broker
                        .runtime()
                        .managed_store()
                        .unwrap()
                        .policy_grants()
                        .unwrap()
                )
                .unwrap(),
                grants
            );
            let response = fixture
                .gateway(Method::GET, "/items/alpha", "retained-identity-header")
                .send()
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::NOT_FOUND);
            assert_eq!(
                response.headers()[REASON_CODE_HEADER],
                "gateway_rule_not_found"
            );
            assert_eq!(response.bytes().await.unwrap(), missing_body);
            assert_eq!(
                upstream.api_requests().len(),
                1,
                "retained identity-header action must not dispatch"
            );
        }
        fixture.stop().await;
    }
}

#[tokio::test]
async fn openapi_gateway_operator_binding_reserves_a_host_before_an_import_is_created() {
    let upstream = Upstream::start().await;
    let fixture = Fixture::start(&upstream, |_| {}).await;
    let response = fixture
        .gateway(Method::GET, "/items/alpha", "reserved-empty-binding")
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    assert_eq!(
        response.headers()[REASON_CODE_HEADER],
        "gateway_rule_not_found"
    );
    let unavailable_body = response.bytes().await.unwrap();
    assert!(upstream.api_requests().is_empty());
    let source = document(
        Dialect::OpenApi31,
        UpstreamAuth::Anonymous,
        &upstream.endpoint(),
    );
    let preview = fixture
        .create_and_discover(DefinitionSource::Upload, UpstreamAuth::Anonymous, &source)
        .await;
    fixture.accept(&preview, &["read_item"]).await;
    fixture.enable().await;
    fixture.grant(&["read_item"]).await;
    let response = fixture
        .gateway(
            Method::GET,
            "/not-in-document",
            "active-binding-missing-route",
        )
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    assert_eq!(
        response.headers()[REASON_CODE_HEADER],
        "gateway_rule_not_found"
    );
    assert_eq!(response.bytes().await.unwrap(), unavailable_body);
    let mut disabled = versions(&fixture.detail().await);
    disabled["status"] = json!("disabled");
    disabled["confirm"] = json!(true);
    fixture
        .admin_ok(
            Method::POST,
            "/v1/admin/imports/inventory/status",
            Some(disabled),
        )
        .await;
    let response = fixture
        .gateway(Method::GET, "/items/alpha", "disabled-binding-route")
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    assert_eq!(
        response.headers()[REASON_CODE_HEADER],
        "gateway_rule_not_found"
    );
    assert_eq!(response.bytes().await.unwrap(), unavailable_body);
    assert!(upstream.api_requests().is_empty());
    fixture.stop().await;
}

#[tokio::test]
async fn openapi_gateway_refresh_keeps_unaccepted_removed_and_retired_routes_as_denial_guards() {
    let upstream = Upstream::start().await;
    let fixture = Fixture::ready(
        &upstream,
        UpstreamAuth::Anonymous,
        &["read_item", "private_item"],
    )
    .await;
    let response = fixture
        .gateway(Method::GET, "/items/private", "literal-enabled")
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    response.bytes().await.unwrap();
    let mut changed = document(
        Dialect::OpenApi31,
        UpstreamAuth::Anonymous,
        &upstream.endpoint(),
    );
    changed["paths"]
        .as_object_mut()
        .unwrap()
        .remove("/items/private");
    changed["paths"]["/items/new"] =
        json!({"get":{"operationId":"new_item","responses":{"200":{"description":"New"}}}});
    let preview = fixture.upload(&changed).await;
    assert!(
        preview["service"]["actions"]
            .as_array()
            .unwrap()
            .iter()
            .any(|action| action["definition"]["action"] == "private_item"
                && action["status"] == "quarantined")
    );
    fixture.accept(&preview, &["read_item"]).await;
    let before = upstream.api_requests().len();
    for path in ["/items/private", "/items/new"] {
        let response = fixture
            .gateway(Method::GET, path, "retained-guard")
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        assert_eq!(
            response.headers()[REASON_CODE_HEADER],
            "gateway_rule_not_found"
        );
    }
    assert_eq!(upstream.api_requests().len(), before);
    let response = fixture
        .gateway(Method::GET, "/items/ordinary", "template-still-enabled")
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    response.bytes().await.unwrap();

    let mut retired = versions(&fixture.detail().await);
    retired["status"] = json!("retired");
    retired["confirm"] = json!(true);
    fixture
        .admin_ok(
            Method::POST,
            "/v1/admin/imports/inventory/actions/private_item/status",
            Some(retired),
        )
        .await;
    let response = fixture
        .gateway(Method::GET, "/items/private", "retired-literal")
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    assert_eq!(upstream.api_requests().len(), before + 1);
    fixture.stop().await;
}

#[tokio::test]
async fn openapi_gateway_changed_operation_is_quarantined_until_explicit_reacceptance() {
    let upstream = Upstream::start().await;
    let fixture = Fixture::ready(&upstream, UpstreamAuth::Anonymous, &["read_item"]).await;
    let mut changed = document(
        Dialect::OpenApi31,
        UpstreamAuth::Anonymous,
        &upstream.endpoint(),
    );
    changed["paths"]["/items/{id}"]["get"]["parameters"].as_array_mut().unwrap().push(
        json!({"name":"revision","in":"query","required":true,"schema":{"type":"integer","minimum":1}}));
    let preview = fixture.upload(&changed).await;
    let response = fixture
        .gateway(Method::GET, "/items/alpha?revision=1", "quarantined")
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    assert!(upstream.api_requests().is_empty());
    fixture.accept(&preview, &["read_item"]).await;
    let response = fixture
        .gateway(Method::GET, "/items/alpha", "missing-new-required")
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let response = fixture
        .gateway(Method::GET, "/items/alpha?revision=1", "reaccepted")
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    response.bytes().await.unwrap();
    assert_eq!(upstream.api_requests().len(), 1);
    fixture.stop().await;
}

#[tokio::test]
async fn openapi_gateway_binding_host_changes_and_removal_preserve_accepted_authority() {
    const NEXT_HOST: &str = "inventory-next.gateway.example.test";
    let upstream = Upstream::start().await;
    let fixture = Fixture::ready(&upstream, UpstreamAuth::Anonymous, &["read_item"]).await;
    let before = fixture.detail().await;
    let mut config = fixture.seed.config.clone();
    config
        .imports
        .gateway_bindings
        .get_mut(SERVICE)
        .unwrap()
        .broker_hosts = vec![NEXT_HOST.into()];
    fixture.broker.reload_config(&config).await;
    let after = fixture.detail().await;
    assert_eq!(after["catalogRevision"], before["catalogRevision"]);
    assert_eq!(after["service"]["version"], before["service"]["version"]);
    assert_eq!(after["service"]["actions"], before["service"]["actions"]);
    let response = fixture
        .gateway(Method::GET, "/items/alpha", "old-host-unmatched")
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    assert_eq!(
        response.headers()[REASON_CODE_HEADER],
        "gateway_host_unmatched"
    );
    assert!(upstream.api_requests().is_empty());
    let response = fixture
        .gateway_on_host(
            NEXT_HOST,
            Method::GET,
            "/items/alpha",
            "new-host-existing-authority",
        )
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    response.bytes().await.unwrap();
    assert_eq!(upstream.api_requests().len(), 1);

    config.imports.gateway_bindings.remove(SERVICE);
    fixture.broker.reload_config(&config).await;
    let after = fixture.detail().await;
    assert_eq!(after["catalogRevision"], before["catalogRevision"]);
    assert_eq!(after["service"]["actions"], before["service"]["actions"]);
    assert_eq!(after["service"]["status"], "enabled");
    let response = fixture
        .gateway_on_host(NEXT_HOST, Method::GET, "/items/alpha", "binding-removed")
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    assert_eq!(
        response.headers()[REASON_CODE_HEADER],
        "gateway_host_unmatched"
    );
    assert_eq!(upstream.api_requests().len(), 1);

    fixture.broker.reload_config(&fixture.seed.config).await;
    let response = fixture
        .gateway(Method::GET, "/items/alpha", "binding-restored")
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    response.bytes().await.unwrap();
    assert_eq!(upstream.api_requests().len(), 2);
    fixture.stop().await;
}

#[tokio::test]
async fn openapi_gateway_binding_reload_cancels_queued_work_before_dispatch() {
    for remove in [false, true] {
        let upstream = Upstream::start().await;
        let fixture = Fixture::ready_with(
            &upstream,
            UpstreamAuth::Anonymous,
            &["read_item"],
            |config| {
                config.limits.request_body_timeout_ms = 30_000;
                config.limits.invocations.default =
                    Some(agent_access_core::InvocationLimitConfig {
                        requests: 1,
                        window: "10s".into(),
                        max_wait: Some("20s".into()),
                    });
            },
        )
        .await;
        let response = fixture
            .gateway(Method::GET, "/items/alpha", "binding-queue-seed")
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        response.bytes().await.unwrap();
        let request = fixture.gateway(Method::GET, "/items/alpha", "binding-queue-waiter");
        let pending = tokio::spawn(async move { request.send().await.unwrap() });
        fixture.wait_for_queue("alice", 1).await;
        let mut config = fixture.seed.config.clone();
        if remove {
            config.imports.gateway_bindings.remove(SERVICE);
        } else {
            config
                .imports
                .gateway_bindings
                .get_mut(SERVICE)
                .unwrap()
                .broker_hosts = vec!["inventory-next.gateway.example.test".into()];
        }
        fixture.broker.reload_config(&config).await;
        let response = tokio::time::timeout(Duration::from_secs(5), pending)
            .await
            .unwrap()
            .unwrap();
        assert!(!response.status().is_success());
        assert_eq!(
            response.headers()[REASON_CODE_HEADER],
            "operation_cancelled"
        );
        response.bytes().await.unwrap();
        assert_eq!(upstream.api_requests().len(), 1);
        let terminal = fixture.terminal("binding-queue-waiter").await;
        assert_eq!(terminal["reasonCode"], "operation_cancelled");
        fixture.stop().await;
    }
}
