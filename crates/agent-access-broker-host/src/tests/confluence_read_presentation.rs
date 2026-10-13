use super::*;
use agent_access_confluence::ConfluenceProviderConfig;
use agent_access_provider::{ScopeRequest, ScopeResolution};

const EMBEDDED_ACTIONS: &[&str] = &[
    "blog.draft.view",
    "blog.footer_comment.add",
    "blog.footer_comment.list",
    "blog.footer_comment.reply.add",
    "blog.footer_comment.reply.list",
    "blog.footer_comment.update",
    "blog.footer_comment.view",
    "blog.inline_comment.list",
    "blog.inline_comment.reply.add",
    "blog.inline_comment.reply.list",
    "blog.inline_comment.update",
    "blog.inline_comment.view",
    "blog.view",
    "page.draft.view",
    "page.footer_comment.add",
    "page.footer_comment.list",
    "page.footer_comment.reply.add",
    "page.footer_comment.reply.list",
    "page.footer_comment.update",
    "page.footer_comment.view",
    "page.inline_comment.list",
    "page.inline_comment.reply.add",
    "page.inline_comment.reply.list",
    "page.inline_comment.update",
    "page.inline_comment.view",
    "page.view",
];

const WHOLE_ACTIONS: &[&str] = &[
    "attachment.list",
    "blog.attachment.list",
    "blog.draft.attachment.list",
    "blog.draft.verify",
    "blog.draft.view",
    "blog.footer_comment.list",
    "blog.footer_comment.reply.list",
    "blog.footer_comment.view",
    "blog.inline_comment.list",
    "blog.inline_comment.reply.list",
    "blog.inline_comment.view",
    "blog.search",
    "blog.verify",
    "blog.view",
    "page.draft.attachment.list",
    "page.draft.verify",
    "page.draft.view",
    "page.footer_comment.list",
    "page.footer_comment.reply.list",
    "page.footer_comment.view",
    "page.inline_comment.list",
    "page.inline_comment.reply.list",
    "page.inline_comment.view",
    "page.view",
    "search",
    "verify",
];

const NATIVE_SENTINEL: &str = "CONFLUENCEREADNATIVESENTINEL8C5E32";

#[tokio::test]
async fn confluence_read_capabilities_are_consistent_across_runtime_specs() {
    let fixture = spec_agent_fixture(&["confluence"], false).await;
    let app = fixture.app;
    let token = fixture.agent_token;

    let catalog = spec_get(
        app.clone(),
        "/v1/spec/catalog",
        "confluence-read-catalog",
        Some(&token),
    )
    .await;
    assert_eq!(catalog.status(), StatusCode::OK);
    let catalog = response_json(catalog).await;

    let openapi = spec_get(
        app.clone(),
        "/v1/spec/openapi.json",
        "confluence-read-openapi",
        Some(&token),
    )
    .await;
    assert_eq!(openapi.status(), StatusCode::OK);
    let openapi = response_json(openapi).await;

    let send_schema = spec_get(
        app,
        "/v1/spec/send-schema.json",
        "confluence-read-send-schema",
        Some(&token),
    )
    .await;
    assert_eq!(send_schema.status(), StatusCode::OK);
    let send_schema = response_json(send_schema).await;

    let actions = catalog["services"]
        .as_array()
        .unwrap()
        .iter()
        .find(|service| service["service"] == "confluence")
        .and_then(|service| service["actions"].as_array())
        .expect("Confluence catalog actions");
    let advertised_embedded = actions
        .iter()
        .filter(|action| action.get("readContentFormats").is_some())
        .map(|action| action["action"].as_str().unwrap())
        .collect::<BTreeSet<_>>();
    let advertised_whole = actions
        .iter()
        .filter(|action| action.get("responseFormats").is_some())
        .map(|action| action["action"].as_str().unwrap())
        .collect::<BTreeSet<_>>();
    assert_eq!(
        advertised_embedded,
        EMBEDDED_ACTIONS.iter().copied().collect()
    );
    assert_eq!(advertised_whole, WHOLE_ACTIONS.iter().copied().collect());

    for action in actions {
        let action_name = action["action"].as_str().unwrap();
        let supports_embedded = EMBEDDED_ACTIONS.contains(&action_name);
        let supports_whole = WHOLE_ACTIONS.contains(&action_name);
        assert_optional_format_enum(
            action.get("readContentFormats"),
            supports_embedded,
            json!(["native", "markdown", "text"]),
            &format!("catalog confluence.{action_name} readContentFormats"),
        );
        assert_optional_format_enum(
            action.get("responseFormats"),
            supports_whole,
            json!(["json", "markdown"]),
            &format!("catalog confluence.{action_name} responseFormats"),
        );

        let request_content = &openapi["paths"][format!("/v1/invoke/confluence/{action_name}")]["post"]
            ["requestBody"]["content"];
        let properties = if request_content.get("application/json").is_some() {
            &request_content["application/json"]["schema"]["properties"]
        } else {
            &request_content["multipart/form-data"]["schema"]["properties"]["request"]["contentSchema"]
                ["properties"]
        };
        assert_response_option_enums(
            properties,
            supports_embedded,
            supports_whole,
            &format!("OpenAPI confluence.{action_name}"),
        );

        let send_variant = send_action_variant(&send_schema, "confluence", action_name);
        assert_response_option_enums(
            &send_variant["properties"],
            supports_embedded,
            supports_whole,
            &format!("send schema confluence.{action_name}"),
        );
        assert_eq!(
            send_variant["additionalProperties"], false,
            "send invoke envelope must be closed for confluence.{action_name}"
        );
    }
}

#[tokio::test]
async fn confluence_formats_transform_success_and_mismatch_and_reject_before_provider_access() {
    let fixture = presentation_fixture("").await;

    let unsupported = presentation_request(
        fixture.app.clone(),
        "confluence-read-unsupported",
        "search",
        json!({
            "inputs": { "query": { "type": "text", "value": "fixture" } },
            "readContentFormat": "markdown"
        }),
    )
    .await;
    assert_eq!(unsupported.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);
    let unsupported = response_json(unsupported).await;
    assert_eq!(unsupported["decision"], "deny");
    assert_eq!(unsupported["reasonCode"], "response_format_unsupported");
    assert_eq!(fixture.scope_resolutions.load(Ordering::SeqCst), 0);
    assert_eq!(fixture.invocations.load(Ordering::SeqCst), 0);

    let embedded = presentation_request(
        fixture.app.clone(),
        "confluence-read-embedded",
        "page.view",
        json!({
            "inputs": { "pageId": "1007" },
            "readContentFormat": "markdown"
        }),
    )
    .await;
    let embedded_status = embedded.status();
    let embedded = response_json(embedded).await;
    assert_eq!(embedded_status, StatusCode::OK, "{embedded}");
    assert_eq!(
        embedded["result"]["body"]["storage"]["value"],
        format!("<p>{NATIVE_SENTINEL}</p>")
    );
    assert_eq!(embedded["result"]["renderedBody"]["format"], "markdown");
    assert_eq!(embedded["result"]["renderedBody"]["value"], NATIVE_SENTINEL);

    let whole = presentation_request(
        fixture.app.clone(),
        "confluence-read-whole",
        "page.view",
        json!({
            "inputs": { "pageId": "1007" },
            "responseFormat": "markdown"
        }),
    )
    .await;
    let whole_status = whole.status();
    let whole = response_json(whole).await;
    assert_eq!(whole_status, StatusCode::OK, "{whole}");
    assert_eq!(whole["result"]["format"], "markdown");
    let whole_markdown = whole["result"]["value"].as_str().unwrap();
    assert!(whole_markdown.contains("Normalized Confluence fixture"));
    assert!(whole_markdown.contains(NATIVE_SENTINEL));
    assert!(!whole_markdown.contains("<p>"));
    assert!(whole_markdown.ends_with('\n'));

    let mismatch = presentation_request(
        fixture.app.clone(),
        "confluence-read-mismatch",
        "verify",
        json!({
            "inputs": { "pageId": "1007" },
            "responseFormat": "markdown"
        }),
    )
    .await;
    assert_eq!(mismatch.status(), StatusCode::CONFLICT);
    let mismatch = response_json(mismatch).await;
    assert_eq!(mismatch["decision"], "allow");
    assert_eq!(mismatch["reasonCode"], "verification_mismatch");
    assert_eq!(mismatch["result"]["format"], "markdown");
    assert!(
        mismatch["result"]["value"]
            .as_str()
            .unwrap()
            .contains("mismatch")
    );

    assert_eq!(fixture.scope_resolutions.load(Ordering::SeqCst), 3);
    assert_eq!(fixture.invocations.load(Ordering::SeqCst), 3);
}

#[tokio::test(flavor = "current_thread")]
async fn confluence_rendered_content_is_absent_from_tracing_audit_and_errors() {
    let captured = install_trace_capture().start();

    let audit_path = temp_path("confluence-normalized-read.audit.jsonl");
    let fixture = presentation_fixture(audit_path.to_str().unwrap()).await;
    let malformed = captured
        .run(presentation_request(
            fixture.app,
            "confluence-read-malformed-adf",
            "page.view",
            json!({
                "inputs": { "pageId": "malformed-adf" },
                "readContentFormat": "markdown"
            }),
        ))
        .await;
    assert_eq!(malformed.status(), StatusCode::BAD_GATEWAY);
    let malformed = response_json(malformed).await;
    assert_eq!(malformed["reasonCode"], "upstream_protocol_failed");
    assert!(!malformed.to_string().contains(NATIVE_SENTINEL));

    let events = captured.take_events();
    // The capture observed the request, so the sentinel check covers it.
    event_by_name_and_agent(&events, "invoke_completed", "confluence-read-malformed-adf");
    let events = serde_json::to_string(&events).unwrap();
    assert!(!events.contains(NATIVE_SENTINEL));
    let audit = std::fs::read_to_string(&audit_path).unwrap();
    assert!(!audit.contains(NATIVE_SENTINEL));
    for record in read_audit_records(&audit_path) {
        assert!(
            !record["providerAudit"]
                .to_string()
                .contains(NATIVE_SENTINEL)
        );
        assert!(!record["objectIds"].to_string().contains(NATIVE_SENTINEL));
    }
}

fn assert_response_option_enums(
    properties: &Value,
    supports_embedded: bool,
    supports_whole: bool,
    context: &str,
) {
    assert_eq!(
        properties["readContentFormat"]["enum"],
        if supports_embedded {
            json!(["native", "markdown", "text"])
        } else {
            json!(["native"])
        },
        "{context} readContentFormat"
    );
    assert_eq!(
        properties["responseFormat"]["enum"],
        if supports_whole {
            json!(["json", "markdown"])
        } else {
            json!(["json"])
        },
        "{context} responseFormat"
    );
}

fn confluence_provider_config() -> ConfluenceProviderConfig {
    ConfluenceProviderConfig {
        tenant_host: "example.atlassian.net".to_string(),
        cloud_id: None,
        egress_proxy: None,
        allowed_upstream_hosts: vec![
            "https://example.atlassian.net/wiki/api/v2/**".to_string(),
            "https://example.atlassian.net/wiki/rest/api/**".to_string(),
        ],
        attachments: agent_access_provider::AttachmentLimitsConfig::default(),
        content: agent_access_confluence::ConfluenceContentConfig {
            page_formats: vec!["storage".to_string(), "atlas_doc_format".to_string()],
            ..agent_access_confluence::ConfluenceContentConfig::default()
        },
        search: agent_access_provider::SearchLimitsConfig::default(),
    }
}

fn confluence_broker_config(audit_file: &str) -> BrokerConfig {
    let provider_config = confluence_provider_config();
    let mut config = fake_config(audit_file);
    config.deployment.enable_fake_service = false;
    config.providers.remove("fake");
    config.providers.insert(provider_config.clone());
    config.credentials.service.insert(
        "confluence".to_string(),
        CredentialConfig {
            kind: "basic_api_token".to_string(),
            username_ref: Some(synthetic_credential_ref()),
            token_ref: Some(synthetic_credential_ref()),
            provider: None,
            path: None,
            read_only: None,
            credential_name: None,
            profile: None,
        },
    );
    config.credentials.lookup.insert(
        "confluence".to_string(),
        CredentialConfig {
            kind: "basic_api_token".to_string(),
            username_ref: Some(synthetic_credential_ref()),
            token_ref: Some(synthetic_credential_ref()),
            provider: None,
            path: None,
            read_only: Some(true),
            credential_name: None,
            profile: None,
        },
    );
    let actions = agent_access_confluence::confluence_descriptor(&provider_config)
        .actions
        .into_iter()
        .map(|action| action.action)
        .collect();
    config.policy.grants = vec![PolicyGrantConfig {
        subjects: vec!["group:anonymous".to_string()],
        execution_contexts: None,
        service: "confluence".to_string(),
        actions,
        resources: selected_resources(&[("space", &["ENG"])]),
        credential_mode: "service".to_string(),
        priority: None,
    }];
    config
}

struct PresentationFixture {
    _broker: TestBroker,
    app: Router,
    scope_resolutions: Arc<AtomicUsize>,
    invocations: Arc<AtomicUsize>,
}

struct TestConfluenceReadPresentationProvider {
    scope_resolutions: Arc<AtomicUsize>,
    invocations: Arc<AtomicUsize>,
}

async fn presentation_fixture(audit_file: &str) -> PresentationFixture {
    let scope_resolutions = Arc::new(AtomicUsize::new(0));
    let invocations = Arc::new(AtomicUsize::new(0));
    let provider = TestConfluenceReadPresentationProvider {
        scope_resolutions: scope_resolutions.clone(),
        invocations: invocations.clone(),
    };
    let mut config = confluence_broker_config(audit_file);
    config.policy.grants[0].actions = vec![
        "page.view".to_string(),
        "search".to_string(),
        "verify".to_string(),
    ];
    let broker = TestBroker::start_with_providers(&config, vec![Arc::new(provider)]).await;
    PresentationFixture {
        app: broker.app(),
        _broker: broker,
        scope_resolutions,
        invocations,
    }
}

async fn presentation_request(
    app: Router,
    request_id: &str,
    action: &str,
    body: Value,
) -> axum::response::Response {
    app.oneshot(
        Request::builder()
            .method(Method::POST)
            .uri(format!("/v1/invoke/confluence/{action}"))
            .extension(ConnectInfo(
                "127.0.0.1:43141".parse::<SocketAddr>().unwrap(),
            ))
            .header(REQUEST_ID_HEADER, request_id)
            .header(CONTENT_TYPE, "application/json")
            .body(Body::from(body.to_string()))
            .unwrap(),
    )
    .await
    .unwrap()
}

impl agent_access_provider::test_support::DescribedProvider
    for TestConfluenceReadPresentationProvider
{
    fn descriptor(&self) -> ServiceDescriptor {
        let action = |action: &str, schema: Value| {
            ActionDescriptor::new(
                action,
                format!("Confluence normalized read test action {action}"),
                schema,
            )
            .read_only()
            .scope("space")
            .credential_modes(["service"])
            .presentation(backend_presentation("confluence", action))
        };
        ServiceDescriptor {
            service: "confluence".to_string(),
            display_name: "Confluence Normalized Read Test Provider".to_string(),
            surface: ServiceSurface::Invoke,
            resource_scopes: fixture_scope_capabilities("space"),
            actions: vec![
                action(
                    "page.view",
                    json!({
                        "type": "object",
                        "required": ["pageId"],
                        "properties": { "pageId": { "type": "string" } },
                        "additionalProperties": false
                    }),
                ),
                action(
                    "search",
                    json!({
                        "type": "object",
                        "required": ["query"],
                        "properties": {
                            "query": {
                                "type": "object",
                                "required": ["type", "value"],
                                "properties": {
                                    "type": { "type": "string", "enum": ["text"] },
                                    "value": { "type": "string" }
                                },
                                "additionalProperties": false
                            }
                        },
                        "additionalProperties": false
                    }),
                )
                .search_contained(),
                action(
                    "verify",
                    json!({
                        "type": "object",
                        "required": ["pageId"],
                        "properties": { "pageId": { "type": "string" } },
                        "additionalProperties": false
                    }),
                ),
            ],
            credentials: CredentialDescriptor::without_execution_credential(),
            presentation_body_limit: Some(confluence_provider_config().content.max_body_bytes),
        }
    }
}

impl TestConfluenceReadPresentationProvider {
    fn local_scopes(&self, action: &str, _inputs: &Value) -> Result<ResourceScopes, ProviderError> {
        assert!(matches!(action, "page.view" | "search" | "verify"));
        self.scope_resolutions.fetch_add(1, Ordering::SeqCst);
        Ok(ResourceScopes::from([(
            "space".to_string(),
            vec!["ENG".to_string()],
        )]))
    }
}

#[async_trait::async_trait]
impl Provider for TestConfluenceReadPresentationProvider {
    async fn resolve_scopes(
        &self,
        request: ScopeRequest<'_>,
    ) -> Result<ScopeResolution, ProviderError> {
        self.local_scopes(request.action(), request.inputs())
            .map(ScopeResolution::resources)
    }

    async fn invoke(&self, request: ProviderInvocation) -> Result<ProviderResult, ProviderError> {
        self.invocations.fetch_add(1, Ordering::SeqCst);
        let safe_audit = json!({
            "provider": "confluence",
            "operation": request.action(),
            "space": "ENG"
        });
        if request.action() == "verify" {
            return Err(ProviderError::allow_with_result(
                ReasonCode::VerificationMismatch,
                "Confluence verification mismatch",
                json!({
                    "verification": {
                        "status": "mismatch",
                        "checked": [{ "type": "version", "expected": 8 }],
                        "mismatch": { "type": "version", "expected": 8, "actual": 7 }
                    },
                    "pageId": "1007",
                    "space": "ENG"
                }),
            )
            .with_audit(safe_audit)
            .with_object_ids(json!({ "pageId": "1007" })));
        }
        assert_eq!(request.action(), "page.view");
        let malformed_adf = request.inputs()["pageId"] == "malformed-adf";
        let body = if malformed_adf {
            json!({
                "atlas_doc_format": {
                    "representation": "atlas_doc_format",
                    "value": format!("{{{NATIVE_SENTINEL}")
                },
                "storage": {
                    "representation": "storage",
                    "value": "<p>lower priority fallback must not be used</p>"
                }
            })
        } else {
            json!({
                "storage": {
                    "representation": "storage",
                    "value": format!("<p>{NATIVE_SENTINEL}</p>")
                }
            })
        };
        Ok(ProviderResult::new(json!({
            "id": "1007",
            "title": "Normalized Confluence fixture",
            "space": "ENG",
            "spaceUrl": "https://example.atlassian.net/wiki/spaces/ENG",
            "version": 7,
            "createdAt": "2026-08-20T12:00:00Z",
            "updatedAt": "2026-08-29T12:00:00Z",
            "createdBy": {
                "displayName": "Fixture Author",
                "accountId": "author-account-id"
            },
            "updatedBy": {
                "displayName": "Fixture Editor",
                "accountId": "editor-account-id"
            },
            "body": body,
            "webUrl": "https://example.atlassian.net/wiki/spaces/ENG/pages/1007"
        }))
        .with_audit(safe_audit)
        .with_upstream(Some(200), Some(6))
        .with_object_ids(json!({ "pageId": "1007" })))
    }
}
