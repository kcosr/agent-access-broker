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
    let advertised = actions
        .iter()
        .filter(|action| action.get("outputContentFormats").is_some())
        .map(|action| action["action"].as_str().unwrap())
        .collect::<BTreeSet<_>>();
    assert_eq!(advertised, EMBEDDED_ACTIONS.iter().copied().collect());
    for action in actions {
        let name = action["action"].as_str().unwrap();
        let formats = if name == "page.view" {
            Some(json!(["markdown", "text", "adf", "storage"]))
        } else if EMBEDDED_ACTIONS.contains(&name) {
            Some(json!(["markdown", "text", "storage"]))
        } else {
            None
        };
        assert_eq!(
            action.get("outputContentFormats"),
            formats.as_ref(),
            "{name}"
        );
        for removed in [
            "readContentFormats",
            "responseFormats",
            "renderedBodyOwners",
            "optionalRenderedBodyOwnerPrefixes",
        ] {
            assert!(action.get(removed).is_none(), "{name} {removed}");
        }
        if formats.is_some() {
            assert_eq!(action["defaultOutputContentFormat"], "markdown");
            assert_eq!(
                action["nativeOutputContentFormat"],
                if name == "page.view" {
                    "adf"
                } else {
                    "storage"
                }
            );
            let fields = action["bodyFields"].as_array().unwrap();
            assert_eq!(fields.len(), 1);
            assert_eq!(fields[0]["field"], "body");
            assert!(
                fields[0]["ownerPath"]
                    .as_str()
                    .unwrap()
                    .starts_with("/result")
            );
            let optional = matches!(name, "page.view" | "blog.view")
                || (name.contains("comment")
                    && (name.ends_with(".list") || name.ends_with(".view")));
            assert_eq!(fields[0]["optional"], optional, "{name}");
        } else {
            assert!(action.get("bodyFields").is_none());
        }
        let request_content = &openapi["paths"][format!("/v1/invoke/confluence/{name}")]["post"]["requestBody"]
            ["content"];
        let properties = if request_content.get("application/json").is_some() {
            &request_content["application/json"]["schema"]["properties"]
        } else {
            &request_content["multipart/form-data"]["schema"]["properties"]["request"]["contentSchema"]
                ["properties"]
        };
        assert_response_option_enums(properties, formats.as_ref(), &format!("OpenAPI {name}"));
        let send_variant = send_action_variant(&send_schema, "confluence", name);
        assert_response_option_enums(
            &send_variant["properties"],
            formats.as_ref(),
            &format!("send {name}"),
        );
        assert_eq!(send_variant["additionalProperties"], false);
    }
}

#[tokio::test]
async fn confluence_formats_select_bodies_keep_metadata_and_reject_before_provider_access() {
    let fixture = presentation_fixture("").await;
    for body in [
        json!({"inputs":{"query":{"type":"text","value":"fixture"}},"outputContentFormat":"markdown"}),
        json!({"inputs":{"query":{"type":"text","value":"fixture"}},"outputContentFormat":"adf"}),
    ] {
        let response = presentation_request(
            fixture.app.clone(),
            "confluence-unsupported",
            "search",
            body,
        )
        .await;
        assert_eq!(response.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);
        assert_eq!(
            response_json(response).await["reasonCode"],
            "response_format_unsupported"
        );
    }
    assert_eq!(fixture.scope_resolutions.load(Ordering::SeqCst), 0);
    assert_eq!(fixture.invocations.load(Ordering::SeqCst), 0);
    for (id, control, expected_format) in [
        ("default", json!({}), "markdown"),
        ("text", json!({"outputContentFormat":"text"}), "text"),
        (
            "storage",
            json!({"outputContentFormat":"storage"}),
            "storage",
        ),
        (
            "preferred",
            json!({"preferredOutputContentFormat":"text"}),
            "text",
        ),
        (
            "exact-wins",
            json!({"outputContentFormat":"storage","preferredOutputContentFormat":"text"}),
            "storage",
        ),
    ] {
        let mut body = control;
        body["inputs"] = json!({"pageId":"1007"});
        let response = presentation_request(fixture.app.clone(), id, "page.view", body).await;
        assert_eq!(response.status(), StatusCode::OK);
        let response = response_json(response).await;
        assert_eq!(response["result"]["body"]["format"], expected_format);
        assert_eq!(response["result"]["body"].as_object().unwrap().len(), 2);
        assert_eq!(response["result"]["version"], 7);
        assert!(response["result"].get("renderedBody").is_none());
        assert_eq!(
            response["result"]["body"]["value"],
            if expected_format == "storage" {
                format!("<p>{NATIVE_SENTINEL}</p>")
            } else {
                NATIVE_SENTINEL.to_string()
            }
        );
    }
    let missing = presentation_request(
        fixture.app.clone(),
        "missing-native",
        "page.view",
        json!({"inputs":{"pageId":"1007"},"outputContentFormat":"adf"}),
    )
    .await;
    assert_eq!(missing.status(), StatusCode::OK);
    assert!(response_json(missing).await["result"].get("body").is_none());
    let mismatch = presentation_request(
        fixture.app.clone(),
        "confluence-mismatch",
        "verify",
        json!({"inputs":{"pageId":"1007"},"preferredOutputContentFormat":"markdown"}),
    )
    .await;
    assert_eq!(mismatch.status(), StatusCode::CONFLICT);
    let mismatch = response_json(mismatch).await;
    assert_eq!(mismatch["decision"], "allow");
    assert_eq!(mismatch["reasonCode"], "verification_mismatch");
    assert_eq!(mismatch["result"]["verification"]["status"], "mismatch");
    assert_eq!(fixture.scope_resolutions.load(Ordering::SeqCst), 7);
    assert_eq!(fixture.invocations.load(Ordering::SeqCst), 7);
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
                "outputContentFormat": "markdown"
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
    require_audit_request(
        &audit_path,
        "confluence-read-malformed-adf",
        "confluence",
        "page.view",
    );
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

fn assert_response_option_enums(properties: &Value, formats: Option<&Value>, context: &str) {
    assert_eq!(
        properties
            .get("outputContentFormat")
            .and_then(|p| p.get("enum")),
        formats,
        "{context}"
    );
    assert_eq!(
        properties["preferredOutputContentFormat"]["enum"],
        json!(["markdown", "text", "adf", "storage"]),
        "{context}"
    );
    for control in ["outputContentFormat", "preferredOutputContentFormat"] {
        assert!(properties[control].get("default").is_none(), "{context}");
    }
    assert!(properties.get("readContentFormat").is_none(), "{context}");
    assert!(properties.get("responseFormat").is_none(), "{context}");
}

fn confluence_provider_config() -> ConfluenceProviderConfig {
    ConfluenceProviderConfig {
        content_access: Default::default(),
        content_search: Default::default(),
        listing: Default::default(),
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
            max_body_bytes: 1024,
            ..agent_access_confluence::ConfluenceContentConfig::default()
        },
        search: agent_access_provider::SearchLimitsConfig::default(),
    }
}

fn confluence_broker_config(audit_file: &str) -> BrokerConfig {
    let provider_config = confluence_provider_config();
    let mut config = fake_config(audit_file);
    config.deployment.enable_fake_service = false;
    config.limits.max_upstream_response_bytes = 2048;
    config.providers.remove("fake");
    config.credentials.service.remove("fake");
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
            connection: None,
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
            connection: None,
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
        "page.footer_comment.add".to_string(),
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
            let descriptor = ActionDescriptor::new(
                action,
                format!("Confluence normalized read test action {action}"),
                schema,
            )
            .scope("space")
            .credential_modes(["service"])
            .presentation(backend_presentation("confluence", action));
            if action == "page.footer_comment.add" {
                descriptor
            } else {
                descriptor.read_only()
            }
        };
        ServiceDescriptor::new("confluence", "Confluence Normalized Read Test Provider")
            .with_resource_scopes(fixture_scope_capabilities("space"))
            .with_actions(vec![
                action(
                    "page.footer_comment.add",
                    json!({
                        "type":"object","required":["pageId"],
                        "properties":{"pageId":{"type":"string"}},"additionalProperties":false
                    }),
                ),
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
                .native_search(agent_access_provider::NativeSearchEnforcement::UpstreamConstrained),
                action(
                    "verify",
                    json!({
                        "type": "object",
                        "required": ["pageId"],
                        "properties": { "pageId": { "type": "string" } },
                        "additionalProperties": false
                    }),
                ),
            ])
            .with_credentials(CredentialDescriptor::without_execution_credential())
            .with_presentation_body_limit(confluence_provider_config().content.max_body_bytes)
    }
}

impl TestConfluenceReadPresentationProvider {
    fn local_scopes(&self, action: &str, _inputs: &Value) -> Result<ResourceScopes, ProviderError> {
        assert!(matches!(
            action,
            "page.view" | "search" | "verify" | "page.footer_comment.add"
        ));
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
        if request.action() == "page.footer_comment.add" {
            let mode = request.inputs()["pageId"].as_str().unwrap();
            let body = if mode == "selection-failure" {
                "<ac:link>".to_string()
            } else {
                format!("<p>{NATIVE_SENTINEL}</p>")
            };
            let mut result = json!({"comment":{"commentId":"5001","body":{
                "storage":{"representation":"storage","value":body}
            }}});
            if mode == "size-failure" {
                result["metadata"] = json!("x".repeat(4096));
            }
            return Ok(ProviderResult::new(result)
                .with_presentation_recovery_receipt(
                    agent_access_provider::MutationReceipt::applied(),
                )
                .with_audit(safe_audit)
                .with_upstream(Some(201), Some(6))
                .with_object_ids(json!({"commentId":"5001"})));
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

const PRESENTATION_RECOVERY_MESSAGE: &str =
    "The mutation completed, but its response could not be produced. Do not repeat the operation.";

fn assert_completed_presentation_failure(value: &Value) {
    assert_eq!(value["reasonCode"], "upstream_protocol_failed", "{value}");
    assert_eq!(value["reason"], PRESENTATION_RECOVERY_MESSAGE, "{value}");
    if value.get("error").is_some() {
        assert_eq!(
            value["error"]["message"], PRESENTATION_RECOVERY_MESSAGE,
            "{value}"
        );
    }
    assert_eq!(
        value["result"],
        json!({"mutationStatus":"applied","retrySafe":false}),
        "{value}"
    );
    assert!(!value.to_string().contains(NATIVE_SENTINEL));
    assert!(!value.to_string().contains("<ac:link>"));
}

#[tokio::test]
async fn confluence_completed_writes_keep_receipts_on_selection_and_final_size_failure_over_http() {
    let audit_path = temp_path("confluence-output-recovery.audit.jsonl");
    let fixture = presentation_fixture(audit_path.to_str().unwrap()).await;
    for mode in ["selection-failure", "size-failure"] {
        let response = presentation_request(
            fixture.app.clone(),
            mode,
            "page.footer_comment.add",
            json!({"inputs":{"pageId":mode}}),
        )
        .await;
        assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
        assert_completed_presentation_failure(&response_json(response).await);
        let records =
            require_audit_request(&audit_path, mode, "confluence", "page.footer_comment.add");
        let record = records
            .iter()
            .find(|record| record["upstreamStatus"] == 201)
            .unwrap();
        assert_eq!(
            record["providerAudit"]["operation"],
            "page.footer_comment.add"
        );
        assert_eq!(record["upstreamStatus"], 201);
        assert_eq!(record["objectIds"]["commentId"], "5001");
    }
    assert_eq!(fixture.invocations.load(Ordering::SeqCst), 2);
    assert_eq!(fixture.scope_resolutions.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn confluence_completed_writes_keep_receipts_on_selection_and_final_size_failure_over_mcp() {
    let invocations = Arc::new(AtomicUsize::new(0));
    let provider = TestConfluenceReadPresentationProvider {
        invocations: invocations.clone(),
        scope_resolutions: Arc::new(AtomicUsize::new(0)),
    };
    let fixture = mcp::Fixture::with_providers(
        |config| {
            let confluence = confluence_broker_config("");
            config.deployment.enable_fake_service = false;
            config.providers = confluence.providers;
            config.credentials = confluence.credentials;
            config.policy.grants = confluence.policy.grants;
            config.policy.grants[0].subjects = vec!["user:mcp-user".into()];
            config.policy.grants[0].actions = vec!["page.footer_comment.add".into()];
            config.limits.max_upstream_response_bytes = 2048;
        },
        vec![Arc::new(provider)],
    )
    .await;
    let session = fixture.initialize().await;
    for (id, mode) in ["selection-failure", "size-failure"]
        .into_iter()
        .enumerate()
    {
        let result = fixture
            .call(
                &session,
                100 + id as u64,
                &agent_access_core::mcp::tool_name("confluence", "page.footer_comment.add"),
                json!({"inputs":{"pageId":mode}}),
            )
            .await;
        assert_eq!(result["result"]["isError"], true, "{result}");
        let structured = &result["result"]["structuredContent"];
        assert_completed_presentation_failure(structured);
        let text = result["result"]["content"][0]["text"].as_str().unwrap();
        assert_eq!(serde_json::from_str::<Value>(text).unwrap(), *structured);
    }
    assert_eq!(invocations.load(Ordering::SeqCst), 2);
    let records = read_audit_records(&fixture.audit_path);
    let completed = records
        .iter()
        .filter(|record| {
            record["action"] == "page.footer_comment.add" && record["upstreamStatus"] == 201
        })
        .collect::<Vec<_>>();
    assert_eq!(completed.len(), 2);
    assert!(
        completed
            .iter()
            .all(|record| record["providerAudit"]["operation"] == "page.footer_comment.add")
    );
}

// Each reload constructs this synthetic upstream from the actual configured
// Confluence descriptor. The host still parses, validates and publishes the
// configuration through its production reload path.
struct ReloadPresentationProvider {
    page_formats: Vec<agent_access_provider::presentation::OutputContentFormat>,
    comments_enabled: bool,
    invocations: Arc<AtomicUsize>,
    scope_resolutions: Arc<AtomicUsize>,
}

#[async_trait::async_trait]
impl Provider for ReloadPresentationProvider {
    async fn resolve_scopes(
        &self,
        request: ScopeRequest<'_>,
    ) -> Result<ScopeResolution, ProviderError> {
        use agent_access_provider::{
            ContainmentEvidence, ContainmentIdentity, ContainmentObligation, ContentLocation,
            ResourceContainer,
        };
        assert!(matches!(
            request.action(),
            "page.view" | "page.footer_comment.view"
        ));
        self.scope_resolutions.fetch_add(1, Ordering::SeqCst);
        Ok(ScopeResolution::containment(ContainmentEvidence::new(
            "page",
            "https://example.atlassian.net",
            vec![ContainmentObligation::Content(ContentLocation::new(
                ContainmentIdentity::new(
                    agent_access_confluence::CONFLUENCE_CONTENT_RESOURCE
                        .id()
                        .clone(),
                    "page",
                    "https://example.atlassian.net/wiki/content/page/1007",
                ),
                vec![ResourceContainer::new(
                    CONFLUENCE_SPACE_RESOURCE.id().clone(),
                    "ENG",
                )],
                request.containment_evidence_level(),
            ))],
        ))
        .with_state(ProviderState::new(())))
    }

    async fn invoke(&self, request: ProviderInvocation) -> Result<ProviderResult, ProviderError> {
        use agent_access_provider::presentation::OutputContentFormat;
        self.invocations.fetch_add(1, Ordering::SeqCst);
        assert!(request.inputs().get("bodyFormat").is_none());
        let mut result = json!({"id":"1007","version":7});
        let mut body = serde_json::Map::new();
        if request.action() == "page.footer_comment.view" {
            result = json!({"comment":{"commentId":"5001","version":3}});
            if self.comments_enabled {
                result["comment"]["body"] = json!({
                    "storage":{"representation":"storage","value":"<p>Reload comment</p>"}
                });
            }
        } else {
            assert_eq!(request.action(), "page.view");
            if self.page_formats.contains(&OutputContentFormat::Storage) {
                body.insert(
                    "storage".into(),
                    json!({
                        "representation":"storage","value":"<p>Reload page</p>"
                    }),
                );
            }
            if self.page_formats.contains(&OutputContentFormat::Adf) {
                body.insert(
                    "atlas_doc_format".into(),
                    json!({
                        "representation":"atlas_doc_format",
                        "value":json!({"type":"doc","version":1,"content":[
                            {"type":"paragraph","content":[{"type":"text","text":"Reload page"}]}
                        ]}).to_string()
                    }),
                );
            }
            if !body.is_empty() {
                result["body"] = Value::Object(body);
            }
        }
        Ok(ProviderResult::new(result))
    }
}

#[tokio::test]
async fn confluence_config_reload_reselects_preferences_and_can_disable_read_bodies() {
    use agent_access_provider::presentation::OutputContentFormat;
    let mut provider_config = confluence_provider_config();
    provider_config.content.page_formats = vec!["storage".into()];
    let mut config = confluence_broker_config("");
    config.providers.insert(provider_config.clone());
    config.policy.grants[0].actions = vec!["page.view".into(), "page.footer_comment.view".into()];
    let invocations = Arc::new(AtomicUsize::new(0));
    let scope_resolutions = Arc::new(AtomicUsize::new(0));
    let fixture_invocations = invocations.clone();
    let fixture_scopes = scope_resolutions.clone();
    let broker = TestBroker::start_with(TestBroker::config_builder(&config).provider_fixture(
        "confluence",
        ProviderFixture::factory(move |context| {
            let action = |name: &str| {
                context
                    .descriptor()
                    .actions
                    .iter()
                    .find(|action| action.action == name)
                    .unwrap()
            };
            agent_access_provider::ServiceProvider::new(
                context.descriptor().clone(),
                Arc::new(ReloadPresentationProvider {
                    page_formats: action("page.view")
                        .presentation
                        .map(|presentation| presentation.output_content_formats().to_vec())
                        .unwrap_or_default(),
                    comments_enabled: action("page.footer_comment.view").presentation.is_some(),
                    invocations: fixture_invocations.clone(),
                    scope_resolutions: fixture_scopes.clone(),
                }),
            )
        }),
    ))
    .await;
    let unsupported = presentation_request(
        broker.app(),
        "unsupported-before-expand",
        "page.view",
        json!({"inputs":{"pageId":"1007"},"outputContentFormat":"adf"}),
    )
    .await;
    assert_eq!(unsupported.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);
    assert_eq!(
        response_json(unsupported).await["reasonCode"],
        "response_format_unsupported"
    );
    assert_eq!(invocations.load(Ordering::SeqCst), 0);
    assert_eq!(scope_resolutions.load(Ordering::SeqCst), 0);
    let request = || json!({"inputs":{"pageId":"1007"},"preferredOutputContentFormat":"adf"});
    let response =
        presentation_request(broker.app(), "before-expand", "page.view", request()).await;
    let status = response.status();
    let response = response_json(response).await;
    assert_eq!(status, StatusCode::OK, "{response}");
    assert_eq!(response["result"]["body"]["format"], "storage");

    provider_config
        .content
        .page_formats
        .push("atlas_doc_format".into());
    config.providers.insert(provider_config.clone());
    broker.reload_config(&config).await;
    let response = presentation_request(broker.app(), "after-expand", "page.view", request()).await;
    let status = response.status();
    let response = response_json(response).await;
    assert_eq!(status, StatusCode::OK, "{response}");
    assert_eq!(response["result"]["body"]["format"], "adf");
    assert_eq!(response["result"]["body"]["value"]["type"], "doc");
    assert_eq!(response["result"]["version"], 7);

    let response = presentation_request(
        broker.app(),
        "before-disable-comment",
        "page.footer_comment.view",
        json!({"inputs":{"commentId":"5001"},"preferredOutputContentFormat":"text"}),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response_json(response).await["result"]["comment"]["body"]["format"],
        "text"
    );
    provider_config.content.page_formats.clear();
    provider_config.content.comment_formats.clear();
    // A valid configured preference remains harmless on body-free reads.
    provider_config.content.preferred_output_format = Some(OutputContentFormat::Adf);
    config.providers.insert(provider_config);
    broker.reload_config(&config).await;
    for (action, inputs, pointer) in [
        ("page.view", json!({"pageId":"1007"}), "/body"),
        (
            "page.footer_comment.view",
            json!({"commentId":"5001"}),
            "/comment/body",
        ),
    ] {
        let response = presentation_request(
            broker.app(),
            "after-disable",
            action,
            json!({"inputs":inputs,"preferredOutputContentFormat":"text"}),
        )
        .await;
        let status = response.status();
        let response = response_json(response).await;
        assert_eq!(status, StatusCode::OK, "{response}");
        assert!(response["result"].pointer(pointer).is_none(), "{response}");
    }
    assert_eq!(invocations.load(Ordering::SeqCst), 5);
    assert_eq!(scope_resolutions.load(Ordering::SeqCst), 5);
    broker.stop().await;
}
