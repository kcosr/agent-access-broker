use super::*;

struct NormalizedReadBackend {
    page: ConfluencePage,
    comments: BTreeMap<String, ConfluenceComment>,
    calls: Mutex<Vec<&'static str>>,
}

impl NormalizedReadBackend {
    fn take_calls(&self) -> Vec<&'static str> {
        std::mem::take(&mut *self.calls.lock().unwrap())
    }
}

#[async_trait]
impl ConfluenceBackend for NormalizedReadBackend {
    async fn search(
        &self,
        _request: ConfluenceSearchRequest,
        _credential: &agent_access_provider::ExecutionCredential,
    ) -> Result<ConfluenceBackendResponse<ConfluenceSearchPage>, ConfluenceBackendError> {
        Err(ConfluenceBackendError::Protocol(
            "search is not used by normalized read tests".to_string(),
        ))
    }

    async fn create_page(
        &self,
        _request: ConfluencePageCreateRequest,
        _credential: &agent_access_provider::ExecutionCredential,
    ) -> Result<ConfluenceBackendResponse<ConfluencePage>, ConfluenceBackendError> {
        Err(ConfluenceBackendError::Protocol(
            "page creation is not used by normalized read tests".to_string(),
        ))
    }

    async fn update_page(
        &self,
        _request: ConfluencePageUpdateRequest,
        _credential: &agent_access_provider::ExecutionCredential,
    ) -> Result<ConfluenceBackendResponse<ConfluencePage>, ConfluenceBackendError> {
        Err(ConfluenceBackendError::Protocol(
            "page updates are not used by normalized read tests".to_string(),
        ))
    }

    async fn add_attachment(
        &self,
        _page_id: &str,
        _attachment: ConfluenceAttachmentUpload,
        _credential: &agent_access_provider::ExecutionCredential,
    ) -> Result<ConfluenceBackendResponse<ConfluenceAttachment>, ConfluenceBackendError> {
        Err(ConfluenceBackendError::Protocol(
            "attachment upload is not used by normalized read tests".to_string(),
        ))
    }

    async fn page_attachments(
        &self,
        _page_id: &str,
        _credential: &agent_access_provider::ExecutionCredential,
    ) -> Result<ConfluenceBackendResponse<Vec<ConfluenceAttachment>>, ConfluenceBackendError> {
        Err(ConfluenceBackendError::Protocol(
            "attachment listing is not used by normalized read tests".to_string(),
        ))
    }

    async fn attachment_content(
        &self,
        _page_id: &str,
        _attachment_id: &str,
        _credential: &agent_access_provider::ExecutionCredential,
    ) -> Result<ConfluenceBackendResponse<ConfluenceAttachmentContent>, ConfluenceBackendError>
    {
        Err(ConfluenceBackendError::Protocol(
            "attachment download is not used by normalized read tests".to_string(),
        ))
    }

    async fn page_metadata(
        &self,
        page_id: &str,
        _credential: &agent_access_provider::ExecutionCredential,
    ) -> Result<ConfluenceBackendResponse<ConfluencePage>, ConfluenceBackendError> {
        self.calls.lock().unwrap().push("page_metadata");
        if page_id != self.page.id {
            return Err(ConfluenceBackendError::NotFound);
        }
        Ok(ConfluenceBackendResponse {
            value: self.page.clone(),
            status: 200,
            duration_ms: 1,
        })
    }

    async fn page(
        &self,
        page_id: &str,
        _credential: &agent_access_provider::ExecutionCredential,
    ) -> Result<ConfluenceBackendResponse<ConfluencePage>, ConfluenceBackendError> {
        self.calls.lock().unwrap().push("page");
        if page_id != self.page.id {
            return Err(ConfluenceBackendError::NotFound);
        }
        Ok(ConfluenceBackendResponse {
            value: self.page.clone(),
            status: 200,
            duration_ms: 1,
        })
    }

    async fn comment(
        &self,
        kind: ConfluenceCommentKind,
        comment_id: &str,
        _body_format: Option<&str>,
        _credential: &agent_access_provider::ExecutionCredential,
    ) -> Result<ConfluenceBackendResponse<ConfluenceComment>, ConfluenceBackendError> {
        self.calls.lock().unwrap().push("comment");
        let comment = self
            .comments
            .get(comment_id)
            .filter(|comment| comment.kind == kind)
            .cloned()
            .ok_or(ConfluenceBackendError::NotFound)?;
        Ok(ConfluenceBackendResponse {
            value: comment,
            status: 200,
            duration_ms: 1,
        })
    }

    async fn comments_page(
        &self,
        request: ConfluenceCommentListRequest,
        _credential: &agent_access_provider::ExecutionCredential,
    ) -> Result<ConfluenceBackendResponse<ConfluenceCommentListPage>, ConfluenceBackendError> {
        self.calls.lock().unwrap().push("comments_page");
        let comments = self
            .comments
            .values()
            .filter(|comment| {
                comment.kind == request.kind
                    && comment.parent_comment_id.is_none()
                    && match request.container_type {
                        ConfluenceCommentContainerType::Page => {
                            comment.page_id.as_deref() == Some(request.container_id.as_str())
                        }
                        ConfluenceCommentContainerType::Blog => {
                            comment.blog_id.as_deref() == Some(request.container_id.as_str())
                        }
                    }
            })
            .take(request.max_results as usize)
            .cloned()
            .collect();
        Ok(ConfluenceBackendResponse {
            value: ConfluenceCommentListPage {
                comments,
                next_cursor: None,
            },
            status: 200,
            duration_ms: 1,
        })
    }

    async fn comment_replies_page(
        &self,
        kind: ConfluenceCommentKind,
        comment_id: &str,
        _body_format: Option<&str>,
        max_results: u32,
        _cursor: Option<&str>,
        _credential: &agent_access_provider::ExecutionCredential,
    ) -> Result<ConfluenceBackendResponse<ConfluenceCommentListPage>, ConfluenceBackendError> {
        self.calls.lock().unwrap().push("comment_replies_page");
        let comments = self
            .comments
            .values()
            .filter(|comment| {
                comment.kind == kind && comment.parent_comment_id.as_deref() == Some(comment_id)
            })
            .take(max_results as usize)
            .cloned()
            .collect();
        Ok(ConfluenceBackendResponse {
            value: ConfluenceCommentListPage {
                comments,
                next_cursor: None,
            },
            status: 200,
            duration_ms: 1,
        })
    }
}

fn normalized_page(bodies: BTreeMap<String, String>) -> ConfluencePage {
    ConfluencePage {
        id: "123456".to_string(),
        title: "Normalized read page".to_string(),
        space: "ENG".to_string(),
        web_url: None,
        space_web_url: None,
        status: Some("current".to_string()),
        version: 7,
        created_at: Some("2026-08-29T10:00:00Z".to_string()),
        updated_at: Some("2026-08-29T11:00:00Z".to_string()),
        created_by: None,
        updated_by: None,
        bodies,
    }
}

fn normalized_comment(id: &str, parent_comment_id: Option<&str>, body: &str) -> ConfluenceComment {
    ConfluenceComment {
        id: id.to_string(),
        kind: ConfluenceCommentKind::Footer,
        page_id: parent_comment_id.is_none().then(|| "123456".to_string()),
        blog_id: None,
        parent_comment_id: parent_comment_id.map(ToString::to_string),
        status: Some("current".to_string()),
        resolution_status: None,
        version: Some(1),
        author: Some(ConfluenceCommentAuthor {
            account_id: Some("author-1".to_string()),
            display_name: Some("Author One".to_string()),
        }),
        created_at: Some("2026-08-29T10:00:00Z".to_string()),
        updated_at: None,
        bodies: BTreeMap::from([("storage".to_string(), body.to_string())]),
    }
}

async fn normalized_runtime(
    backend: Arc<NormalizedReadBackend>,
    audit_name: &str,
) -> (String, tokio::task::JoinHandle<()>) {
    let audit_path = temp_path(audit_name);
    let config = confluence_config(&audit_path);
    let provider =
        confluence_provider_with_backend(&config, confluence_provider_config(2), backend);
    let runtime = agent_access_core::BrokerRuntime::with_providers(config, vec![provider]).unwrap();
    start_broker(runtime).await
}

async fn invoke(
    base_url: &str,
    action: &str,
    request_id: &str,
    body: serde_json::Value,
) -> (reqwest::StatusCode, serde_json::Value) {
    let response = reqwest::Client::new()
        .post(format!("{base_url}/v1/invoke/confluence/{action}"))
        .header("X-Agent-Access-Request-Id", request_id)
        .json(&body)
        .send()
        .await
        .unwrap();
    let status = response.status();
    let body = response.json().await.unwrap();
    (status, body)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn page_read_formats_prefer_adf_preserve_native_and_do_not_refetch() {
    const STORAGE: &str = "<p>storage fallback sentinel</p>";
    const ADF_TEXT: &str = "atlas preferred sentinel";
    let adf = serde_json::json!({
        "type": "doc",
        "version": 1,
        "content": [{
            "type": "paragraph",
            "content": [{"type": "text", "text": ADF_TEXT}]
        }]
    })
    .to_string();
    let backend = Arc::new(NormalizedReadBackend {
        page: normalized_page(BTreeMap::from([
            ("storage".to_string(), STORAGE.to_string()),
            ("atlas_doc_format".to_string(), adf.clone()),
        ])),
        comments: BTreeMap::new(),
        calls: Mutex::new(Vec::new()),
    });
    let (base_url, server) = normalized_runtime(backend.clone(), "normalized-page.audit").await;

    let (native_status, native) = invoke(
        &base_url,
        "page.view",
        "confluence-native-page",
        serde_json::json!({"inputs":{"pageId":"123456"}}),
    )
    .await;
    assert_eq!(native_status, reqwest::StatusCode::OK, "{native}");
    assert_eq!(native["result"]["body"]["storage"]["value"], STORAGE);
    assert_eq!(native["result"]["body"]["atlas_doc_format"]["value"], adf);
    assert!(native["result"].get("renderedBody").is_none());
    let native_calls = backend.take_calls();
    assert_eq!(native_calls, vec!["page_metadata", "page"]);

    let (embedded_status, embedded) = invoke(
        &base_url,
        "page.view",
        "confluence-embedded-page",
        serde_json::json!({
            "inputs":{"pageId":"123456"},
            "readContentFormat":"markdown"
        }),
    )
    .await;
    assert_eq!(embedded_status, reqwest::StatusCode::OK, "{embedded}");
    assert_eq!(
        embedded["result"]["renderedBody"],
        serde_json::json!({"format":"markdown", "value":ADF_TEXT})
    );
    assert_eq!(embedded["result"]["body"]["storage"]["value"], STORAGE);
    assert_eq!(backend.take_calls(), native_calls);

    let (markdown_status, markdown) = invoke(
        &base_url,
        "page.view",
        "confluence-markdown-page",
        serde_json::json!({
            "inputs":{"pageId":"123456"},
            "responseFormat":"markdown"
        }),
    )
    .await;
    assert_eq!(markdown_status, reqwest::StatusCode::OK, "{markdown}");
    let value = markdown["result"]["value"].as_str().unwrap();
    assert_eq!(markdown["result"]["format"], "markdown");
    assert!(value.contains("Normalized read page"));
    assert!(value.contains(ADF_TEXT));
    assert!(!value.contains(STORAGE));
    assert!(!value.contains("atlas_doc_format"));
    assert!(!value.contains("\"type\":\"doc\""));
    assert_eq!(backend.take_calls(), native_calls);

    server.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn malformed_preferred_adf_fails_without_storage_fallback() {
    const STORAGE: &str = "<p>must not become a fallback</p>";
    let backend = Arc::new(NormalizedReadBackend {
        page: normalized_page(BTreeMap::from([
            ("storage".to_string(), STORAGE.to_string()),
            ("atlas_doc_format".to_string(), "{not-json".to_string()),
        ])),
        comments: BTreeMap::new(),
        calls: Mutex::new(Vec::new()),
    });
    let (base_url, server) =
        normalized_runtime(backend.clone(), "malformed-normalized-page.audit").await;

    let (status, body) = invoke(
        &base_url,
        "page.view",
        "confluence-malformed-adf",
        serde_json::json!({
            "inputs":{"pageId":"123456"},
            "readContentFormat":"markdown"
        }),
    )
    .await;
    assert_eq!(status, reqwest::StatusCode::BAD_GATEWAY, "{body}");
    assert_eq!(body["reasonCode"], "upstream_protocol_failed");
    assert!(!body.to_string().contains(STORAGE));
    assert_eq!(backend.take_calls(), vec!["page_metadata", "page"]);

    server.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn comment_owner_and_collection_paths_render_without_extra_provider_calls() {
    const ROOT_BODY: &str = "<p>root comment <strong>sentinel</strong></p>";
    const REPLY_BODY: &str = "<p>reply comment sentinel</p>";
    let backend = Arc::new(NormalizedReadBackend {
        page: normalized_page(BTreeMap::new()),
        comments: BTreeMap::from([
            (
                "5001".to_string(),
                normalized_comment("5001", None, ROOT_BODY),
            ),
            (
                "5002".to_string(),
                normalized_comment("5002", Some("5001"), REPLY_BODY),
            ),
        ]),
        calls: Mutex::new(Vec::new()),
    });
    let (base_url, server) = normalized_runtime(backend.clone(), "normalized-comments.audit").await;

    let list_inputs = serde_json::json!({
        "pageId":"123456",
        "bodyFormat":"storage",
        "maxResults":2
    });
    let (native_status, native) = invoke(
        &base_url,
        "page.footer_comment.list",
        "confluence-native-comment-list",
        serde_json::json!({"inputs":list_inputs.clone()}),
    )
    .await;
    assert_eq!(native_status, reqwest::StatusCode::OK, "{native}");
    assert_eq!(
        native["result"]["comments"][0]["body"]["storage"]["value"],
        ROOT_BODY
    );
    assert!(
        native["result"]["comments"][0]
            .get("renderedBody")
            .is_none()
    );
    let native_list_calls = backend.take_calls();

    let (embedded_status, embedded) = invoke(
        &base_url,
        "page.footer_comment.list",
        "confluence-embedded-comment-list",
        serde_json::json!({
            "inputs":list_inputs.clone(),
            "readContentFormat":"markdown"
        }),
    )
    .await;
    assert_eq!(embedded_status, reqwest::StatusCode::OK, "{embedded}");
    assert_eq!(
        embedded["result"]["comments"][0]["renderedBody"],
        serde_json::json!({"format":"markdown", "value":"root comment **sentinel**"})
    );
    assert_eq!(backend.take_calls(), native_list_calls);

    let (whole_status, whole) = invoke(
        &base_url,
        "page.footer_comment.list",
        "confluence-markdown-comment-list",
        serde_json::json!({
            "inputs":list_inputs,
            "responseFormat":"markdown"
        }),
    )
    .await;
    assert_eq!(whole_status, reqwest::StatusCode::OK, "{whole}");
    let whole_value = whole["result"]["value"].as_str().unwrap();
    assert!(whole_value.contains("root comment **sentinel**"));
    assert!(!whole_value.contains(ROOT_BODY));
    assert_eq!(backend.take_calls(), native_list_calls);

    let view_inputs = serde_json::json!({"commentId":"5001", "bodyFormat":"storage"});
    let (native_view_status, native_view) = invoke(
        &base_url,
        "page.footer_comment.view",
        "confluence-native-comment-view",
        serde_json::json!({"inputs":view_inputs.clone()}),
    )
    .await;
    assert_eq!(native_view_status, reqwest::StatusCode::OK, "{native_view}");
    let native_view_calls = backend.take_calls();

    let (view_status, view) = invoke(
        &base_url,
        "page.footer_comment.view",
        "confluence-embedded-comment-view",
        serde_json::json!({
            "inputs":view_inputs,
            "readContentFormat":"text"
        }),
    )
    .await;
    assert_eq!(view_status, reqwest::StatusCode::OK, "{view}");
    assert_eq!(
        view["result"]["comment"]["renderedBody"],
        serde_json::json!({"format":"text", "value":"root comment sentinel"})
    );
    assert_eq!(backend.take_calls(), native_view_calls);

    let reply_inputs =
        serde_json::json!({"commentId":"5001", "bodyFormat":"storage", "maxResults":2});
    let (native_reply_status, native_replies) = invoke(
        &base_url,
        "page.footer_comment.reply.list",
        "confluence-native-reply-list",
        serde_json::json!({"inputs":reply_inputs.clone()}),
    )
    .await;
    assert_eq!(
        native_reply_status,
        reqwest::StatusCode::OK,
        "{native_replies}"
    );
    let native_reply_calls = backend.take_calls();

    let (reply_status, replies) = invoke(
        &base_url,
        "page.footer_comment.reply.list",
        "confluence-embedded-reply-list",
        serde_json::json!({
            "inputs":reply_inputs,
            "readContentFormat":"markdown"
        }),
    )
    .await;
    assert_eq!(reply_status, reqwest::StatusCode::OK, "{replies}");
    assert_eq!(
        replies["result"]["comments"][0]["renderedBody"],
        serde_json::json!({"format":"markdown", "value":"reply comment sentinel"})
    );
    assert_eq!(backend.take_calls(), native_reply_calls);

    server.abort();
}
