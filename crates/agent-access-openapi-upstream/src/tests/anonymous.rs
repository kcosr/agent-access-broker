use super::*;

fn anonymous_definition() -> ImportedServiceDefinition {
    let mut def = definition("https://api.example/api", "https://docs.example/spec.json");
    def.execution_bindings.clear();
    def.connection_settings.remove("securityScheme");
    def
}
fn documents() -> Vec<Value> {
    vec![
        document(),
        json!({
            "swagger":"2.0", "info":{"title":"Anonymous API","version":"1"},
            "host":"api.example", "basePath":"/api", "schemes":["https"],
            "securityDefinitions":{"access":{"type":"basic"}}, "security":[{"access":[]}],
            "paths":{"/items/{id}":{"post":{
                "operationId":"update_item",
                "parameters":[{"name":"id","in":"path","type":"string","required":true}],
                "responses":{"204":{"description":"Empty"}}
            }}}
        }),
    ]
}

#[test]
fn anonymous_is_an_explicit_binding_contract_without_a_selected_scheme() {
    let def = anonymous_definition();
    assert!(OpenApiAdapter.supports_credential_free_execution());
    OpenApiAdapter.validate_definition(&def).unwrap();
    let contract = OpenApiAdapter
        .credential_contract(&def, &ImportedAdapterContext::default())
        .unwrap();
    contract.validate(&def).unwrap();
    for scheme in ["access", ""] {
        let mut invalid = def.clone();
        invalid
            .connection_settings
            .insert("securityScheme".into(), scheme.into());
        assert!(OpenApiAdapter.validate_definition(&invalid).is_err());
    }
    let mut wire = serde_json::to_value(&def).unwrap();
    wire.as_object_mut().unwrap().remove("executionBindings");
    assert!(serde_json::from_value::<ImportedServiceDefinition>(wire).is_err());
}

#[test]
fn both_formats_apply_effective_security_without_malformed_or_authenticated_fallback() {
    let def = anonymous_definition();
    for original in documents() {
        for security in [
            None,
            Some(json!([])),
            Some(json!([{}])),
            Some(json!([{}, {"access":[]}])),
        ] {
            let mut doc = original.clone();
            doc.as_object_mut().unwrap().remove("security");
            if let Some(security) = security {
                doc["security"] = security;
            }
            let row = discovered(doc, &def);
            assert!(
                row.unsupported_reason.is_none(),
                "{:?}",
                row.unsupported_reason
            );
            assert_eq!(
                row.definition.annotations["openapi"]["security"],
                json!({"kind":"anonymous"})
            );
            CompiledAction::new(&row.definition).unwrap();
        }
        for security in [
            json!(null),
            json!({}),
            json!("none"),
            json!([null]),
            json!([{}, null]),
            json!([{"access":"wrong"}]),
            json!([{"access":[]}]),
            json!([{"a":[],"b":[]}]),
        ] {
            let mut doc = original.clone();
            doc["security"] = security;
            assert!(discovered(doc, &def).unsupported_reason.is_some());
        }
        let mut doc = original.clone();
        doc["paths"]["/items/{id}"]["post"]["security"] = json!([]);
        assert!(discovered(doc.clone(), &def).unsupported_reason.is_none());
        doc["security"] = json!([]);
        doc["paths"]["/items/{id}"]["post"]["security"] = json!([{"access":[]}]);
        assert!(discovered(doc.clone(), &def).unsupported_reason.is_some());
        doc["paths"]["/items/{id}"]["post"]["security"] = Value::Null;
        assert!(discovered(doc, &def).unsupported_reason.is_some());
    }
}

#[test]
fn static_selection_ignores_unselected_security_alternatives_in_both_formats() {
    for original in documents() {
        let mut def = definition("https://api.example/api", "https://docs.example/spec.json");
        if original.get("swagger").is_some() {
            for binding in &mut def.execution_bindings {
                binding.delivery = ImportedCredentialDelivery::Basic;
            }
        }
        let baseline = discovered(original.clone(), &def);
        assert!(baseline.unsupported_reason.is_none());
        for alternatives in [
            vec![json!({"access":[]}), json!({"oauth":vec!["scope";65]})],
            vec![json!({"access":[]}), json!({"oauth":[""]})],
            vec![json!({"access":[]}), json!(null)],
            vec![json!({"access":[]}); 65],
        ] {
            let mut doc = original.clone();
            doc["security"] = json!(alternatives);
            let row = discovered(doc, &def);
            assert!(
                row.unsupported_reason.is_none(),
                "{:?}",
                row.unsupported_reason
            );
            assert_eq!(row.definition, baseline.definition);
        }
        // Anonymous admission still validates all alternatives, even beside {}.
        let mut doc = original;
        doc["security"] = json!([{}, {"oauth":vec!["scope";65]}]);
        assert!(
            discovered(doc, &anonymous_definition())
                .unsupported_reason
                .is_some()
        );
    }
}

#[test]
fn anonymous_parameters_cannot_carry_declared_api_keys() {
    let def = anonymous_definition();
    for mut doc in documents() {
        doc["security"] = json!([]);
        let swagger = doc.get("swagger").is_some();
        for location in ["query", "header"] {
            let mut doc = doc.clone();
            let carrier = json!({"type":"apiKey", "in":location, "name":"X-Key"});
            if swagger {
                doc["securityDefinitions"]["key"] = carrier;
            } else {
                doc["components"]["securitySchemes"]["key"] = carrier;
            }
            let name = if location == "header" {
                "x-key"
            } else {
                "X-Key"
            };
            let mut parameter = json!({"name":name,"in":location});
            if swagger {
                parameter["type"] = json!("string");
            } else {
                parameter["schema"] = json!({"type":"string"});
            }
            doc["paths"]["/items/{id}"]["post"]["parameters"]
                .as_array_mut()
                .unwrap()
                .push(parameter);
            assert!(
                discovered(doc, &def)
                    .unsupported_reason
                    .unwrap()
                    .contains("credential carrier")
            );
        }
    }
}

#[test]
fn frozen_anonymous_plans_reject_static_fields_and_definition_mismatches() {
    let def = anonymous_definition();
    let mut doc = document();
    doc["security"] = json!([]);
    let action = discovered(doc, &def).definition;
    let host = test_host();
    OpenApiAdapter
        .build(
            &def,
            std::slice::from_ref(&action),
            None,
            &ImportedAdapterContext::default(),
            &host.context(),
        )
        .unwrap();
    for (key, value) in [
        ("scheme", json!("access")),
        ("scheme", Value::Null),
        ("header", json!("X-Key")),
        ("header", Value::Null),
    ] {
        let mut action = action.clone();
        action.annotations["openapi"]["security"][key] = value;
        assert!(CompiledAction::new(&action).is_err(), "accepted {key}");
    }
    let static_def = definition("https://api.example/api", "https://docs.example/spec.json");
    assert!(
        OpenApiAdapter
            .build(
                &static_def,
                &[action],
                None,
                &ImportedAdapterContext::default(),
                &host.context()
            )
            .is_err()
    );
    assert!(
        OpenApiAdapter
            .build(
                &def,
                &[super::action(&static_def)],
                None,
                &ImportedAdapterContext::default(),
                &host.context()
            )
            .is_err()
    );
}

#[tokio::test]
async fn private_document_credentials_do_not_reach_anonymous_api_and_unexpected_credentials_are_refused()
 {
    let mut doc = document();
    doc["security"] = json!([]);
    let fixture = Fixture::new(doc, 200, json!({"value":"done"}), Duration::ZERO).await;
    let mut def = fixture.definition();
    def.execution_bindings.clear();
    def.connection_settings.remove("securityScheme");
    def.discovery = ImportedDiscoveryCredential::Slot;
    def.connection_settings
        .insert("definitionAuthKind".into(), "bearer".into());
    let host = test_host();
    let discovery = OpenApiAdapter
        .discover(
            &def,
            &ImportedDiscoveryAuthentication::Static(credential("document-secret")),
            None,
            &ImportedAdapterContext::default(),
            &host.context(),
        )
        .await
        .unwrap();
    assert!(discovery.tools[0].unsupported_reason.is_none());
    let mut action = discovery.tools[0].definition.clone();
    action.action = "item.update".into();
    let provider = OpenApiAdapter
        .build(
            &def,
            &[action],
            None,
            &ImportedAdapterContext::default(),
            &host.context(),
        )
        .unwrap()
        .provider()
        .unwrap();
    for invocation in [
        invocation(input()),
        InvocationBuilder::new("example", "item.update")
            .inputs(input())
            .credential_mode(CredentialMode::PerUser)
            .build(),
    ] {
        assert!(provider.invoke(invocation).await.is_err());
    }
    assert_eq!(fixture.call_count(), 1);
    provider
        .invoke(
            InvocationBuilder::new("example", "item.update")
                .inputs(input())
                .identity(InvocationIdentity::new("alice", true))
                .build(),
        )
        .await
        .unwrap();
    let calls = fixture.state.calls.lock().unwrap();
    assert_eq!(calls.len(), 2);
    assert_eq!(calls[0].headers["authorization"], "Bearer document-secret");
    assert!(!calls[1].headers.contains_key("authorization"));
    assert!(!calls[1].headers.contains_key("cookie"));
}

#[tokio::test]
async fn optional_auth_keeps_selected_static_credentials_and_never_retries_anonymously() {
    let mut doc = document();
    doc["security"] = json!([{}, {"access":[]}]);
    let fixture = Fixture::new(doc.clone(), 401, json!({"error":"denied"}), Duration::ZERO).await;
    let def = fixture.definition();
    let host = test_host();
    let mut action = discovered(doc, &def).definition;
    action.action = "item.update".into();
    assert_eq!(action.annotations["openapi"]["security"]["kind"], "bearer");
    let provider = OpenApiAdapter
        .build(
            &def,
            &[action],
            None,
            &ImportedAdapterContext::default(),
            &host.context(),
        )
        .unwrap()
        .provider()
        .unwrap();
    assert!(
        provider
            .invoke(
                InvocationBuilder::new("example", "item.update")
                    .inputs(input())
                    .build()
            )
            .await
            .is_err()
    );
    assert_eq!(fixture.call_count(), 0);
    assert!(provider.invoke(invocation(input())).await.is_err());
    let calls = fixture.state.calls.lock().unwrap();
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].headers["authorization"], "Bearer api-secret");
}
