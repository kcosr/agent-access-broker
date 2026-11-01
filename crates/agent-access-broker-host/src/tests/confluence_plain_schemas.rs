//! Plain Confluence schemas across discovery surfaces, with the production
//! provider retaining responsibility for relationships and content formats.
use super::input_explanations::invoke;
use super::mcp::{Fixture, TOKEN_A, structured};
use super::*;
use agent_access_confluence::{
    AtlassianCredential, ConfluenceAttachment, ConfluenceAttachmentContent,
    ConfluenceAttachmentUpload, ConfluenceBackend, ConfluenceBackendError,
    ConfluenceBackendResponse, ConfluencePage, ConfluencePageCreateRequest,
    ConfluencePageUpdateRequest, ConfluenceProvider, ConfluenceProviderConfig,
    ConfluenceSearchPage, ConfluenceSearchRequest, ConfluenceSpace, ConfluenceSpaceListPage,
    ConfluenceSpaceListRequest,
};
use agent_access_core::ApiCatalog;
use agent_access_core::mcp::{ProjectionMode, project_catalog, tool_name};
use agent_access_provider::ActionIo;

const PAGE_URL: &str = "https://example.atlassian.net/wiki/spaces/ENG/pages/123456/Runbook";
const BLOG_URL: &str =
    "https://example.atlassian.net/wiki/spaces/ENG/blog/2026/01/01/654321/Update";
const SECRET: &str = "private-confluence-content-sentinel";

fn provider_config() -> ConfluenceProviderConfig {
    serde_json::from_value(json!({
        "tenant_host": "example.atlassian.net",
        "allowed_upstream_hosts": [
            "https://example.atlassian.net/wiki/api/v2/**",
            "https://example.atlassian.net/wiki/rest/api/**"
        ],
        "content": {"page_formats": ["storage", "atlas_doc_format"]}
    }))
    .unwrap()
}

async fn fixture() -> Fixture {
    Fixture::start(
        |config| {
            let mut credential = config.credentials.service["fake"].clone();
            credential.kind = "basic_api_token".into();
            credential.username_ref = credential.token_ref.clone();
            let mut lookup = credential.clone();
            lookup.read_only = Some(true);
            config
                .credentials
                .service
                .insert("confluence".into(), credential);
            config
                .credentials
                .lookup
                .insert("confluence".into(), lookup);
            config.broker_tokens = Some(agent_access_core::BrokerTokensConfig {
                hash_key_ref: format!(
                    "file:{}",
                    config.credential_encryption.as_ref().unwrap().keys[0]
                        .path
                        .as_ref()
                        .unwrap()
                ),
                ..Default::default()
            });
            let provider_config = provider_config();
            let actions = agent_access_confluence::confluence_descriptor(&provider_config)
                .actions
                .into_iter()
                .map(|action| action.action)
                .collect();
            config.providers.insert(provider_config);
            config.policy.grants = vec![PolicyGrantConfig {
                subjects: vec!["user:mcp-user".into()],
                execution_contexts: None,
                service: "confluence".into(),
                actions,
                resources: selected_resources(&[("space", &["ENG"])]),
                credential_mode: "service".into(),
                priority: None,
            }];
        },
        |application| {
            application.provider_fixture(
                "confluence",
                ProviderFixture::factory(|context| {
                    let config = provider_config();
                    agent_access_provider::ServiceProvider::new(
                        agent_access_confluence::confluence_descriptor(&config),
                        Arc::new(ConfluenceProvider::with_backend_and_signing_key(
                            config,
                            context.build_context().limits().clone(),
                            Arc::new(ReadBackend),
                            context
                                .build_context()
                                .stable_signing_key()
                                .unwrap()
                                .clone(),
                        )),
                    )
                }),
            )
        },
    )
    .await
}

/// Only page reads and the space lookup before content preparation are served.
/// Every mutation is an assertion failure, including writes after bad content.
struct ReadBackend;

fn page() -> ConfluencePage {
    ConfluencePage {
        id: "123456".into(),
        title: "Runbook".into(),
        space: "ENG".into(),
        web_url: None,
        space_web_url: None,
        space_alias: None,
        status: Some("current".into()),
        version: 1,
        created_at: None,
        updated_at: None,
        created_by: None,
        updated_by: None,
        bodies: BTreeMap::from([("storage".into(), "<p>Runbook</p>".into())]),
    }
}

#[async_trait::async_trait]
impl ConfluenceBackend for ReadBackend {
    async fn space_list(
        &self,
        _: ConfluenceSpaceListRequest,
        _: &AtlassianCredential,
    ) -> Result<ConfluenceBackendResponse<ConfluenceSpaceListPage>, ConfluenceBackendError> {
        panic!("space listing is not exercised")
    }

    async fn page_metadata(
        &self,
        page_id: &str,
        _: &AtlassianCredential,
    ) -> Result<ConfluenceBackendResponse<ConfluencePage>, ConfluenceBackendError> {
        assert_eq!(page_id, "123456");
        Ok(ConfluenceBackendResponse {
            value: page(),
            status: 200,
            duration_ms: 1,
        })
    }

    async fn page(
        &self,
        page_id: &str,
        credential: &AtlassianCredential,
    ) -> Result<ConfluenceBackendResponse<ConfluencePage>, ConfluenceBackendError> {
        self.page_metadata(page_id, credential).await
    }

    async fn space_by_key(
        &self,
        space: &str,
        _: &AtlassianCredential,
    ) -> Result<ConfluenceBackendResponse<ConfluenceSpace>, ConfluenceBackendError> {
        assert_eq!(space, "ENG");
        Ok(ConfluenceBackendResponse {
            value: ConfluenceSpace {
                id: "7".into(),
                key: "ENG".into(),
                web_url: None,
                alias: None,
                status: Some("current".into()),
                homepage_id: None,
            },
            status: 200,
            duration_ms: 1,
        })
    }

    async fn search(
        &self,
        _: ConfluenceSearchRequest,
        _: &AtlassianCredential,
    ) -> Result<ConfluenceBackendResponse<ConfluenceSearchPage>, ConfluenceBackendError> {
        panic!("search is not exercised")
    }

    async fn create_page(
        &self,
        _: ConfluencePageCreateRequest,
        _: &AtlassianCredential,
    ) -> Result<ConfluenceBackendResponse<ConfluencePage>, ConfluenceBackendError> {
        panic!("invalid content must not create a page")
    }

    async fn update_page(
        &self,
        _: ConfluencePageUpdateRequest,
        _: &AtlassianCredential,
    ) -> Result<ConfluenceBackendResponse<ConfluencePage>, ConfluenceBackendError> {
        panic!("page update is not exercised")
    }

    async fn add_attachment(
        &self,
        _: &str,
        _: ConfluenceAttachmentUpload,
        _: &AtlassianCredential,
    ) -> Result<ConfluenceBackendResponse<ConfluenceAttachment>, ConfluenceBackendError> {
        panic!("attachment upload is not exercised")
    }

    async fn page_attachments(
        &self,
        _: &str,
        _: &AtlassianCredential,
    ) -> Result<ConfluenceBackendResponse<Vec<ConfluenceAttachment>>, ConfluenceBackendError> {
        panic!("attachment membership is not exercised")
    }

    async fn attachment_content(
        &self,
        _: &str,
        _: &str,
        _: &AtlassianCredential,
    ) -> Result<ConfluenceBackendResponse<ConfluenceAttachmentContent>, ConfluenceBackendError>
    {
        panic!("attachment download is not exercised")
    }
}

async fn spec(fixture: &Fixture, name: &str) -> Value {
    let response = spec_get(
        fixture.app.clone(),
        &format!("/v1/spec/{name}"),
        &format!("confluence-plain-{name}"),
        Some(TOKEN_A),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    response_json(response).await
}

fn requires(schema: &Value, field: &str) -> bool {
    schema["required"]
        .as_array()
        .is_some_and(|required| required.iter().any(|value| value == field))
}

fn tool<'a>(tools: &'a [Value], action: &str) -> &'a Value {
    let name = tool_name("confluence", action);
    tools.iter().find(|tool| tool["name"] == name).unwrap()
}

#[tokio::test]
async fn confluence_plain_inputs_project_through_stdio_http_send_and_openapi() {
    let fixture = fixture().await;
    let catalog_value = spec(&fixture, "catalog").await;
    let catalog: ApiCatalog = serde_json::from_value(catalog_value.clone()).unwrap();
    let openapi = spec(&fixture, "openapi.json").await;
    let send = spec(&fixture, "send-schema.json").await;
    let stdio = project_catalog(&catalog, ProjectionMode::Stdio).unwrap();
    let session = fixture.initialize().await;
    let listing = fixture.rpc(&session, 2, "tools/list", json!({})).await;
    assert!(listing["result"].get("nextCursor").is_none());
    let http = listing["result"]["tools"].as_array().unwrap();
    let confluence = catalog
        .services
        .iter()
        .find(|service| service.service == "confluence")
        .unwrap();
    assert_eq!(confluence.actions.len(), 64);
    let mut uploads = Vec::new();
    for action in &confluence.actions {
        let schema = &action.input_schema;
        assert_eq!(schema["type"], "object", "{}", action.action);
        assert_eq!(schema["additionalProperties"], false, "{}", action.action);
        for keyword in ["oneOf", "anyOf", "allOf", "if", "then", "else", "not"] {
            assert!(
                schema.get(keyword).is_none(),
                "{}: {keyword}",
                action.action
            );
        }
        let stdio_arguments = &tool(&stdio, &action.action)["inputSchema"];
        let stdio_inputs = &stdio_arguments["properties"]["inputs"];
        let send_variant = send_action_variant(&send, "confluence", &action.action);
        let operation =
            &openapi["paths"][format!("/v1/invoke/confluence/{}", action.action)]["post"];
        let content = &operation["requestBody"]["content"];
        let mut local_schema = schema.clone();
        let openapi_inputs = if let ActionIo::MultipartUpload { plan } = &action.io {
            uploads.push(action.action.as_str());
            let locators: &[&str] = match action.action.as_str() {
                "attachment.add" => &["pageId"],
                "blog.attachment.add" => &["blogId"],
                "page.draft.attachment.add" => &["pageId", "draftHandle"],
                "blog.draft.attachment.add" => &["blogId", "draftHandle"],
                other => panic!("unexpected Confluence upload {other}"),
            };
            assert_eq!(*plan, attachment_upload_plan(locators, None));
            assert_eq!(plan.metadata_pointer, "/attachments");
            for locator in locators {
                assert_eq!(schema["properties"][*locator]["type"], "string");
                assert!(requires(schema, locator));
            }
            assert!(requires(schema, "attachments"));
            local_schema["properties"]
                .as_object_mut()
                .unwrap()
                .remove("attachments");
            local_schema["required"]
                .as_array_mut()
                .unwrap()
                .retain(|field| field != "attachments");
            assert!(requires(stdio_arguments, "files"));
            assert!(requires(send_variant, "files"));
            assert_eq!(stdio_arguments["properties"]["files"]["minItems"], 1);
            &content["multipart/form-data"]["schema"]["properties"]["request"]["contentSchema"]["properties"]
                ["inputs"]
        } else {
            &content["application/json"]["schema"]["properties"]["inputs"]
        };
        assert_eq!(openapi_inputs, schema, "OpenAPI {}", action.action);
        assert_eq!(
            &send_variant["properties"]["inputs"], &local_schema,
            "send {}",
            action.action
        );
        for key in ["type", "properties", "required", "additionalProperties"] {
            assert_eq!(
                stdio_inputs.get(key),
                local_schema.get(key),
                "stdio {}: {key}",
                action.action
            );
        }
        let has_required_inputs = local_schema["required"]
            .as_array()
            .is_some_and(|fields| !fields.is_empty());
        assert_eq!(
            requires(send_variant, "inputs"),
            has_required_inputs,
            "send {}",
            action.action
        );
        assert!(!requires(stdio_arguments, "inputs"));
        assert_eq!(
            stdio_arguments["properties"]["requestFile"]["type"],
            "string"
        );
        if matches!(action.io, ActionIo::Json) {
            let http_arguments = &tool(http, &action.action)["inputSchema"];
            assert_eq!(
                &http_arguments["properties"]["inputs"], schema,
                "HTTP MCP {}",
                action.action
            );
            assert!(requires(http_arguments, "inputs"));
        } else {
            assert!(
                !http
                    .iter()
                    .any(|tool| tool["name"] == tool_name("confluence", &action.action))
            );
        }
    }
    uploads.sort_unstable();
    assert_eq!(
        uploads,
        [
            "attachment.add",
            "blog.attachment.add",
            "blog.draft.attachment.add",
            "page.draft.attachment.add"
        ]
    );

    for (action, id) in [
        ("page.view", "pageId"),
        ("attachment.list", "pageId"),
        ("blog.view", "blogId"),
        ("blog.attachment.list", "blogId"),
    ] {
        let schema = &catalog_action(&catalog_value, "confluence", action)["inputSchema"];
        for field in [id, "url"] {
            assert_eq!(schema["properties"][field]["type"], "string");
            assert!(!requires(schema, field));
            assert!(
                schema["properties"][field]["description"]
                    .as_str()
                    .unwrap()
                    .contains(&format!("Give exactly one of {id} or url."))
            );
        }
    }
    let create = &catalog_action(&catalog_value, "confluence", "page.create")["inputSchema"];
    assert_eq!(
        create["properties"]["content"]["type"],
        json!(["string", "object"])
    );
    assert!(
        create["properties"]["content"]
            .get("additionalProperties")
            .is_none()
    );
    for action in [
        "blog.create",
        "page.draft.create",
        "page.footer_comment.add",
    ] {
        let schema = &catalog_action(&catalog_value, "confluence", action)["inputSchema"];
        assert_eq!(schema["properties"]["content"]["type"], "string");
        assert!(requires(schema, "content"));
        assert!(requires(schema, "contentFormat"));
    }
    let send_validator = jsonschema::validator_for(&send).unwrap();
    for action in [
        "page.view",
        "attachment.list",
        "blog.view",
        "blog.attachment.list",
    ] {
        let mut request = json!({"version": "agent-access.send.v1", "kind": "invoke", "service": "confluence", "action": action});
        assert!(send_validator.is_valid(&request));
        request["inputs"] = json!({});
        assert!(send_validator.is_valid(&request));
        request["inputs"] = json!(null);
        assert!(!send_validator.is_valid(&request));
    }
    for action in ["page.create", "page.move"] {
        let mut request = json!({"version": "agent-access.send.v1", "kind": "invoke", "service": "confluence", "action": action});
        assert!(!send_validator.is_valid(&request));
        request["inputs"] = json!({});
        assert!(!send_validator.is_valid(&request));
    }
}

fn assert_denial_audit(fixture: &Fixture, envelope: &Value, action: &str, inputs: &Value) {
    let records = require_audit_request(
        &fixture.audit_path,
        envelope["agentRequestId"].as_str().unwrap(),
        "confluence",
        action,
    );
    assert_eq!(records.len(), 1);
    let record = &records[0];
    assert_eq!(record["decision"], "deny");
    assert_eq!(record["reasonCode"], envelope["reasonCode"]);
    assert!(record.get("upstreamStatus").is_none(), "{record}");
    assert!(record.get("objectIds").is_none(), "{record}");
    assert_eq!(record["providerAudit"]["admission"]["outcome"], "admitted");
    assert_eq!(record["providerAudit"]["admission"]["waited"], false);
    let fields: &[(&str, &str)] = match action {
        "page.create" | "page.draft.create" => &[
            ("space", "Space"),
            ("title", "Title"),
            ("parentPageId", "Parent page ID"),
            ("parentUrl", "Parent URL"),
        ],
        "page.move" => &[
            ("pageId", "Page ID"),
            ("url", "URL"),
            ("position", "Position"),
            ("targetPageId", "Target page ID"),
            ("targetUrl", "Target URL"),
        ],
        "page.view" | "attachment.list" => &[("pageId", "Page ID"), ("url", "URL")],
        "blog.view" | "blog.attachment.list" => &[("blogId", "Blog post ID"), ("url", "URL")],
        other => panic!("unhandled audit declaration {other}"),
    };
    let expected: Vec<Value> = fields
        .iter()
        .filter_map(|(input, label)| {
            inputs
                .get(input)
                .map(|value| json!({"input": input, "label": label, "value": value}))
        })
        .collect();
    assert_eq!(
        record
            .get("auditInputs")
            .cloned()
            .unwrap_or_else(|| json!([])),
        json!(expected)
    );
}

#[tokio::test]
async fn confluence_schema_accepts_relations_that_the_provider_still_refuses() {
    let fixture = fixture().await;
    let catalog = spec(&fixture, "catalog").await;
    let session = fixture.initialize().await;
    let cases = [
        (
            "page.view",
            json!({}),
            "confluence.page.view requires pageId or url",
        ),
        (
            "page.view",
            json!({"pageId": "123456", "url": PAGE_URL}),
            "confluence.page.view accepts pageId or url, not both",
        ),
        (
            "attachment.list",
            json!({}),
            "confluence.attachment.list requires pageId or url",
        ),
        (
            "attachment.list",
            json!({"pageId": "123456", "url": PAGE_URL}),
            "confluence.attachment.list accepts pageId or url, not both",
        ),
        (
            "blog.view",
            json!({}),
            "confluence.blog.view requires blogId or url",
        ),
        (
            "blog.view",
            json!({"blogId": "654321", "url": BLOG_URL}),
            "confluence.blog.view accepts blogId or url, not both",
        ),
        (
            "blog.attachment.list",
            json!({}),
            "confluence.blog.attachment.list requires blogId or url",
        ),
        (
            "blog.attachment.list",
            json!({"blogId": "654321", "url": BLOG_URL}),
            "confluence.blog.attachment.list accepts blogId or url, not both",
        ),
        (
            "page.move",
            json!({"position": "append", "targetPageId": "987654"}),
            "confluence.page.move requires pageId or url",
        ),
        (
            "page.move",
            json!({"pageId": "123456", "url": PAGE_URL, "position": "append", "targetPageId": "987654"}),
            "confluence.page.move accepts pageId or url, not both",
        ),
        (
            "page.move",
            json!({"pageId": "123456", "position": "append"}),
            "confluence.page.move requires targetPageId or targetUrl",
        ),
        (
            "page.move",
            json!({"pageId": "123456", "position": "append", "targetPageId": "987654", "targetUrl": PAGE_URL}),
            "confluence.page.move accepts targetPageId or targetUrl, not both",
        ),
        (
            "page.create",
            json!({"space": "ENG", "title": "Runbook", "parentPageId": "123456", "parentUrl": PAGE_URL, "content": SECRET, "contentFormat": "storage"}),
            "confluence.page.create accepts parentPageId or parentUrl, not both",
        ),
        (
            "page.draft.create",
            json!({"space": "ENG", "title": "Runbook", "parentPageId": "123456", "parentUrl": PAGE_URL, "content": SECRET, "contentFormat": "storage"}),
            "confluence.page.draft.create accepts parentPageId or parentUrl, not both",
        ),
        (
            "page.create",
            json!({"space": "ENG", "title": "Runbook", "content": SECRET, "contentFormat": "atlas_doc_format"}),
            "page.create content must be an object for atlas_doc_format",
        ),
        (
            "page.create",
            json!({"space": "ENG", "title": "Runbook", "content": {"extension": SECRET}, "contentFormat": "storage"}),
            "page.create content must be a string for storage",
        ),
    ];
    for (index, (action, inputs, expected)) in cases.into_iter().enumerate() {
        let schema = &catalog_action(&catalog, "confluence", action)["inputSchema"];
        assert!(
            jsonschema::validator_for(schema).unwrap().is_valid(&inputs),
            "{action}: {inputs}"
        );
        let response = invoke(
            &fixture,
            &format!("confluence-plain-refusal-{index}"),
            "confluence",
            action,
            inputs.clone(),
        )
        .await;
        assert_eq!(response["reason"], expected);
        let called = fixture
            .call(
                &session,
                10 + index as u64,
                &tool_name("confluence", action),
                json!({"inputs": inputs}),
            )
            .await;
        let envelope = structured(&called);
        assert_eq!(called["result"]["isError"], true);
        assert_eq!(envelope["reason"], expected);
        assert_eq!(envelope["reasonCode"], "input_invalid");
        assert_eq!(envelope["decision"], "deny");
        assert!(envelope.get("result").is_none());
        for envelope in [&response, envelope] {
            assert!(!envelope.to_string().contains(SECRET));
            assert_denial_audit(&fixture, envelope, action, &inputs);
        }
    }
    assert!(!read_audit_text(&fixture.audit_path).contains(SECRET));
}

#[tokio::test]
async fn confluence_retained_constraints_still_explain_input_denials() {
    let fixture = fixture().await;
    let catalog = spec(&fixture, "catalog").await;
    let session = fixture.initialize().await;
    for (index, (action, inputs, expected)) in [
        ("page.view", json!({"pageId": 7}), "confluence.page.view inputs are invalid: inputs.pageId must be a string"),
        ("page.move", json!({"position": "beside"}), "confluence.page.move inputs are invalid: inputs.position must be one of: before, after, append"),
        ("page.create", json!({"space": "ENG", "title": "Runbook", "contentFormat": "storage"}), "confluence.page.create inputs are invalid: inputs.content is required"),
        ("page.create", json!({"space": "ENG", "title": "Runbook", "content": SECRET}), "confluence.page.create inputs are invalid: inputs.contentFormat is required"),
    ].into_iter().enumerate() {
        let schema = &catalog_action(&catalog, "confluence", action)["inputSchema"];
        assert!(!jsonschema::validator_for(schema).unwrap().is_valid(&inputs));
        let response = invoke(&fixture, &format!("confluence-plain-explanation-{index}"), "confluence", action, inputs.clone()).await;
        let called = fixture.call(&session, 10 + index as u64, &tool_name("confluence", action), json!({"inputs": inputs})).await;
        assert_eq!(called["result"]["isError"], true);
        for envelope in [&response, structured(&called)] {
            assert_eq!(envelope["reason"], expected);
            assert_eq!(envelope["reasonCode"], "input_invalid");
            assert_eq!(envelope["decision"], "deny");
            assert!(envelope.get("result").is_none());
            assert!(!envelope.to_string().contains(SECRET));
            assert_denial_audit(&fixture, envelope, action, &inputs);
        }
    }
    assert!(!read_audit_text(&fixture.audit_path).contains(SECRET));
}

async fn http_invoke(
    fixture: &Fixture,
    action: &str,
    request_id: &str,
    body: Value,
) -> axum::response::Response {
    fixture
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri(format!("/v1/invoke/confluence/{action}"))
                .extension(ConnectInfo(
                    "127.0.0.1:45010".parse::<SocketAddr>().unwrap(),
                ))
                .header(AUTHORIZATION, format!("Bearer {TOKEN_A}"))
                .header(CONTENT_TYPE, "application/json")
                .header(REQUEST_ID_HEADER, request_id)
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap()
}

#[tokio::test]
async fn confluence_locator_alternatives_nulls_and_omitted_inputs_keep_runtime_behavior() {
    let fixture = fixture().await;
    let session = fixture.initialize().await;
    for (index, inputs) in [
        json!({"pageId": "123456"}),
        json!({"url": PAGE_URL}),
        json!({"pageId": "123456", "url": null}),
        json!({"pageId": null, "url": PAGE_URL}),
    ]
    .into_iter()
    .enumerate()
    {
        let response = http_invoke(
            &fixture,
            "page.view",
            &format!("confluence-plain-locator-{index}"),
            json!({"inputs": inputs}),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        let response = response_json(response).await;
        let called = fixture
            .call(
                &session,
                10 + index as u64,
                &tool_name("confluence", "page.view"),
                json!({"inputs": inputs}),
            )
            .await;
        assert_eq!(called["result"]["isError"], false);
        for envelope in [&response, structured(&called)] {
            assert_eq!(envelope["decision"], "allow");
            assert_eq!(envelope["result"]["id"], "123456");
            assert_eq!(envelope["result"]["space"], "ENG");
        }
    }
    // JSON invoke defaults omitted inputs to {}, while HTTP MCP requires an
    // explicit object before the provider can inspect its locator fields.
    let response = http_invoke(
        &fixture,
        "page.view",
        "confluence-plain-omitted-inputs",
        json!({}),
    )
    .await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        response_json(response).await["reason"],
        "confluence.page.view requires pageId or url"
    );
    for arguments in [json!({}), json!({"inputs": null}), json!({"inputs": []})] {
        let result = fixture
            .call(
                &session,
                30,
                &tool_name("confluence", "page.view"),
                arguments,
            )
            .await;
        assert_eq!(result["result"]["isError"], true);
        assert_eq!(
            structured(&result),
            &json!({"error": {
                "code": "mcp_tool_error", "message": "inputs is required and must be a JSON object"
            }})
        );
    }
}

#[tokio::test]
async fn confluence_content_denials_keep_non_input_reasons_and_statuses() {
    let fixture = fixture().await;
    let session = fixture.initialize().await;
    for (index, (format, content, status, reason_code, message)) in [
        (
            "unsupported",
            json!(SECRET),
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "body_format_unsupported",
            "page.create contentFormat is unsupported",
        ),
        (
            "plain_text",
            json!("  "),
            StatusCode::BAD_REQUEST,
            "body_malformed",
            "Confluence normalized content must not be empty or whitespace-only",
        ),
    ]
    .into_iter()
    .enumerate()
    {
        let inputs = json!({"space": "ENG", "title": "Runbook", "content": content, "contentFormat": format});
        let response = http_invoke(
            &fixture,
            "page.create",
            &format!("confluence-plain-content-{index}"),
            json!({"inputs": inputs}),
        )
        .await;
        assert_eq!(response.status(), status);
        let response = response_json(response).await;
        let called = fixture
            .call(
                &session,
                10 + index as u64,
                &tool_name("confluence", "page.create"),
                json!({"inputs": inputs}),
            )
            .await;
        assert_eq!(called["result"]["isError"], true);
        for envelope in [&response, structured(&called)] {
            assert_eq!(envelope["decision"], "deny");
            assert_eq!(envelope["reasonCode"], reason_code);
            assert_eq!(envelope["reason"], message);
            assert!(envelope.get("result").is_none());
            assert!(!envelope.to_string().contains(SECRET));
            assert_denial_audit(&fixture, envelope, "page.create", &inputs);
        }
    }
    assert!(!read_audit_text(&fixture.audit_path).contains(SECRET));
}
