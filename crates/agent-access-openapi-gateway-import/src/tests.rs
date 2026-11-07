use super::*;
use agent_access_provider::test_support::{TestHost, basic_credential};
use serde_json::Value;

fn definition(authentication: &str) -> ImportedServiceDefinition {
    ImportedServiceDefinition {
        service: "inventory".into(),
        display_name: "Inventory".into(),
        adapter_kind: "openapi_gateway".into(),
        endpoint: "https://api.example/api".into(),
        connection_settings: BTreeMap::from([
            ("definitionSource".into(), "upload".into()),
            ("executionAuthentication".into(), authentication.into()),
        ]),
        execution_bindings: if authentication == "static" {
            vec![ImportedCredentialBinding::token(
                ImportedCredentialMode::Service,
                ImportedCredentialDelivery::Bearer,
            )]
        } else {
            vec![]
        },
        discovery: ImportedDiscoveryCredential::Anonymous,
        transport_auth: false,
        invocation_limit: None,
    }
}
fn document() -> Value {
    json!({"openapi":"3.1.0","info":{"title":"Inventory","version":"1"},"servers":[{"url":"https://api.example/api"}],
    "paths":{
        "/items/{id}":{"get":{"operationId":"read_item","parameters":[{"name":"id","in":"path","required":true,"schema":{"type":"string"}}],"responses":{"200":{"description":"ok"}}}},
        "/items/admin":{"delete":{"operationId":"delete_admin","responses":{"204":{"description":"deleted"}}}}
    }})
}
async fn discover(
    definition: &ImportedServiceDefinition,
    document: &Value,
    old: Option<&ImportedGatewayRouteRecord>,
) -> ImportedDiscovery {
    let bytes = serde_json::to_vec(document).unwrap();
    OpenApiGatewayAdapter
        .discover(
            definition,
            &ImportedDiscoveryAuthentication::Anonymous,
            None,
            &ImportedAdapterContext::default()
                .with_document(&bytes)
                .with_gateway_routes(old),
            &TestHost::default().context(),
        )
        .await
        .unwrap()
}

#[test]
fn explicit_anonymous_contract_is_distinct_from_missing_static_credentials() {
    let anonymous = definition("anonymous");
    let adapter = OpenApiGatewayAdapter;
    adapter.validate_definition(&anonymous).unwrap();
    assert!(adapter.supports_credential_free_execution());
    let contract = adapter
        .credential_contract(&anonymous, &ImportedAdapterContext::default())
        .unwrap();
    assert!(
        contract
            .requirement(ImportedCredentialPurpose::Execution)
            .is_none()
    );
    let mut invalid = anonymous.clone();
    invalid
        .connection_settings
        .remove("executionAuthentication");
    assert!(adapter.validate_definition(&invalid).is_err());
    invalid = anonymous.clone();
    invalid
        .connection_settings
        .insert("securityScheme".into(), "api_key".into());
    assert!(adapter.validate_definition(&invalid).is_err());
    invalid = anonymous.clone();
    invalid.execution_bindings = definition("static").execution_bindings;
    assert!(adapter.validate_definition(&invalid).is_err());
    invalid = definition("static");
    invalid.execution_bindings.clear();
    assert!(adapter.validate_definition(&invalid).is_err());
    invalid = definition("static");
    invalid.execution_bindings[0].mechanism = ImportedAuthMechanism::Oauth;
    assert!(adapter.validate_definition(&invalid).is_err());
    invalid = anonymous;
    invalid.transport_auth = true;
    assert!(adapter.validate_definition(&invalid).is_err());
}

#[tokio::test]
async fn complete_discovery_preserves_removed_literal_guards_and_has_no_automatic_read_classification()
 {
    let definition = definition("anonymous");
    let first = discover(&definition, &document(), None).await;
    assert_eq!(first.tools.len(), 2);
    assert!(
        first
            .tools
            .iter()
            .all(|tool| !tool.definition.read_only && tool.read_only_hint.is_none())
    );
    let old =
        ImportedGatewayRouteRecord::next(None, first.gateway_routes.clone().unwrap()).unwrap();
    let mut next_document = document();
    next_document["paths"]
        .as_object_mut()
        .unwrap()
        .remove("/items/admin");
    let next = discover(&definition, &next_document, Some(&old)).await;
    let routes: GatewayRouteManifestV1 =
        serde_json::from_value(next.gateway_routes.unwrap().data).unwrap();
    let selected = routes.select("GET", "/items/admin").unwrap().unwrap();
    assert_eq!(selected.template, "/items/admin");
    assert!(selected.route.is_none());
    let removed = routes.select("DELETE", "/items/admin").unwrap().unwrap();
    assert!(!removed.route.unwrap().current);
    assert!(
        next.metadata
            .to_string()
            .contains(GATEWAY_TEMPLATE_COVERAGE_NOTICE)
    );
}

#[tokio::test]
async fn gateway_build_is_offline_and_checks_each_accepted_static_binding() {
    for (scheme, schema, delivery) in [
        (
            "basic",
            json!({"type":"http","scheme":"basic"}),
            ImportedCredentialDelivery::Basic,
        ),
        (
            "bearer",
            json!({"type":"http","scheme":"bearer"}),
            ImportedCredentialDelivery::Bearer,
        ),
        (
            "api_key",
            json!({"type":"apiKey","in":"header","name":"X-Api-Key"}),
            ImportedCredentialDelivery::RawHeader {
                name: "X-Api-Key".into(),
            },
        ),
    ] {
        let mut definition = definition("static");
        definition
            .connection_settings
            .insert("securityScheme".into(), scheme.into());
        definition.execution_bindings = vec![
            ImportedCredentialBinding::token(ImportedCredentialMode::Service, delivery.clone()),
            ImportedCredentialBinding::token(ImportedCredentialMode::PerUser, delivery.clone()),
        ];
        let mut doc = document();
        doc["components"] = json!({"securitySchemes":{scheme:schema}});
        doc["security"] = json!([{scheme:[]}]);
        let discovery = discover(&definition, &doc, None).await;
        assert!(
            discovery
                .tools
                .iter()
                .all(|tool| tool.unsupported_reason.is_none()),
            "{scheme}"
        );
        let actions = discovery
            .tools
            .into_iter()
            .map(|tool| tool.definition)
            .collect::<Vec<_>>();
        let host = TestHost::default();
        let built = OpenApiGatewayAdapter
            .build(
                &definition,
                &actions,
                None,
                &ImportedAdapterContext::default(),
                &host.context(),
            )
            .unwrap();
        assert!(built.provider().is_none());
        assert!(host.built_clients().is_empty());
        assert!(matches!(built, ImportedProvider::Gateway { plans, .. } if plans.len() == 2));
        definition
            .execution_bindings
            .iter_mut()
            .for_each(|binding| {
                binding.delivery = if delivery == ImportedCredentialDelivery::Basic {
                    ImportedCredentialDelivery::Bearer
                } else {
                    ImportedCredentialDelivery::Basic
                }
            });
        assert!(
            OpenApiGatewayAdapter
                .build(
                    &definition,
                    &actions,
                    None,
                    &ImportedAdapterContext::default(),
                    &host.context()
                )
                .is_err()
        );
    }
}

#[tokio::test]
async fn static_selection_never_uses_anonymous_security_alternative() {
    let mut definition = definition("static");
    definition
        .connection_settings
        .insert("securityScheme".into(), "token".into());
    let mut doc = document();
    doc["components"] = json!({"securitySchemes":{"token":{"type":"http","scheme":"bearer"}}});
    doc["security"] = json!([{}, {"token":[]}]);
    let discovery = discover(&definition, &doc, None).await;
    assert!(
        discovery.tools.iter().all(
            |tool| tool.definition.annotations["openapiGateway"]["security"]["kind"] == "bearer"
        )
    );
    let anonymous = discover(&self::definition("anonymous"), &doc, None).await;
    assert!(anonymous.tools.iter().all(
        |tool| tool.definition.annotations["openapiGateway"]["security"]["kind"] == "anonymous"
    ));
    doc["security"] = json!([{ "token": [] }]);
    let incompatible = discover(&self::definition("anonymous"), &doc, None).await;
    assert!(
        incompatible
            .tools
            .iter()
            .all(|tool| tool.unsupported_reason.is_some())
    );
}

#[tokio::test]
async fn upload_and_plan_corruption_fail_closed_without_source_disclosure() {
    let definition = definition("anonymous");
    let bytes = br#"{"openapi":"3.1.0","paths":{},"paths":{"/private-marker":{}}}"#;
    let failure = OpenApiGatewayAdapter
        .discover(
            &definition,
            &ImportedDiscoveryAuthentication::Anonymous,
            None,
            &ImportedAdapterContext::default().with_document(bytes),
            &TestHost::default().context(),
        )
        .await
        .unwrap_err();
    assert!(!format!("{failure:?}").contains("private-marker"));
    let discovery = discover(&definition, &document(), None).await;
    let mut action = discovery.tools[0].definition.clone();
    action.annotations["openapiGateway"]["version"] = json!(99);
    assert!(OpenApiGatewayAdapter.validate_action(&action).is_err());
    let mut action = discovery.tools[0].definition.clone();
    action.source = json!({"operationId":"unaccepted"});
    assert!(OpenApiGatewayAdapter.validate_action(&action).is_err());
    let mut action = discovery.tools[0].definition.clone();
    action.annotations["openapi"] = json!({});
    assert!(OpenApiGatewayAdapter.validate_action(&action).is_err());
}

#[tokio::test]
async fn remote_document_uses_dedicated_basic_slot_and_rejects_redirects() {
    use axum::{
        Router,
        http::{HeaderMap, StatusCode},
        response::IntoResponse,
        routing::get,
    };
    use std::sync::{Arc, Mutex};
    let seen = Arc::new(Mutex::new(Vec::new()));
    let requests = seen.clone();
    let app = Router::new()
        .route(
            "/definition",
            get(move |headers: HeaderMap| {
                let requests = requests.clone();
                async move {
                    requests.lock().unwrap().push(
                        headers
                            .get("authorization")
                            .unwrap()
                            .to_str()
                            .unwrap()
                            .to_string(),
                    );
                    axum::Json(document()).into_response()
                }
            }),
        )
        .route(
            "/redirect",
            get(|| async { (StatusCode::FOUND, [("location", "/definition")]) }),
        );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let task = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    let mut definition = definition("anonymous");
    definition.connection_settings.remove("definitionSource");
    definition
        .connection_settings
        .insert("definitionUrl".into(), format!("{base}/definition"));
    definition
        .connection_settings
        .insert("definitionAuthKind".into(), "basic".into());
    definition.discovery = ImportedDiscoveryCredential::Slot;
    let authentication =
        ImportedDiscoveryAuthentication::Static(basic_credential("document-reader", "test-token"));
    let discovery = OpenApiGatewayAdapter
        .discover(
            &definition,
            &authentication,
            None,
            &ImportedAdapterContext::default(),
            &TestHost::default().context(),
        )
        .await
        .unwrap();
    assert_eq!(discovery.tools.len(), 2);
    assert_eq!(
        *seen.lock().unwrap(),
        ["Basic ZG9jdW1lbnQtcmVhZGVyOnRlc3QtdG9rZW4="]
    );
    definition
        .connection_settings
        .insert("definitionUrl".into(), format!("{base}/redirect"));
    assert!(
        OpenApiGatewayAdapter
            .discover(
                &definition,
                &authentication,
                None,
                &ImportedAdapterContext::default(),
                &TestHost::default().context()
            )
            .await
            .is_err()
    );
    assert_eq!(seen.lock().unwrap().len(), 1);
    task.abort();
}
