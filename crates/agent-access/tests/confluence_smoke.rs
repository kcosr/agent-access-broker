use agent_access_broker_host::test_support::{
    FixtureDir, IsolatedBroker, ProviderFixture, RunningBroker,
};
use agent_access_confluence::{
    CONFLUENCE_SPACE_RESOURCE, ConfluenceAttachment, ConfluenceAttachmentContent,
    ConfluenceAttachmentListPage, ConfluenceAttachmentUpload, ConfluenceBackend,
    ConfluenceBackendError, ConfluenceBackendResponse, ConfluenceBlog, ConfluenceBlogCreateRequest,
    ConfluenceBlogUpdateRequest, ConfluenceComment, ConfluenceCommentAuthor,
    ConfluenceCommentContainerType, ConfluenceCommentCreateRequest, ConfluenceCommentKind,
    ConfluenceCommentListPage, ConfluenceCommentListRequest, ConfluenceCommentUpdateRequest,
    ConfluenceDraftContent, ConfluenceDraftCreateRequest, ConfluenceDraftUpdateRequest,
    ConfluencePage, ConfluencePageAncestor, ConfluencePageChild, ConfluencePageCreateRequest,
    ConfluencePageHierarchy, ConfluencePageMovePosition, ConfluencePageUpdateRequest,
    ConfluenceProvider, ConfluenceProviderConfig, ConfluenceSearchBlog, ConfluenceSearchPage,
    ConfluenceSearchRequest, ConfluenceSpace,
};
use agent_access_provider::SearchLimitsConfig;
use async_trait::async_trait;
use base64::Engine as _;
use std::collections::BTreeMap;
use std::process::Command;
use std::sync::{Arc, Mutex};

/// The Confluence provider (`confluence_provider_config(2)`) around
/// `backend`, paired with its configuration's descriptor and signing with the
/// stable key the broker derives from its token hash key for Confluence.
fn confluence_fixture(backend: Arc<dyn ConfluenceBackend>) -> ProviderFixture {
    ProviderFixture::factory(move |context| {
        let provider_config = confluence_provider_config(2);
        let signing_key = context
            .build_context()
            .stable_signing_key()
            .expect("[broker_tokens] configures the stable signing key")
            .clone();
        agent_access_provider::ServiceProvider::new(
            agent_access_confluence::confluence_descriptor(&provider_config),
            Arc::new(ConfluenceProvider::with_backend_and_signing_key(
                provider_config,
                agent_access_provider::ProviderLimits::default(),
                backend.clone(),
                signing_key,
            )),
        )
    })
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cli_invokes_confluence_read_actions_against_stubbed_backend() {
    let backend = Arc::new(StubConfluenceBackend {
        page: ConfluencePage {
            id: "123456".to_string(),
            title: "Deploy Runbook".to_string(),
            space: "ENG".to_string(),
            web_url: None,
            space_web_url: None,
            status: Some("current".to_string()),
            version: 7,
            created_at: Some("2026-06-01T10:00:00.000Z".to_string()),
            updated_at: Some("2026-06-02T11:00:00.000Z".to_string()),
            created_by: Some(ConfluenceCommentAuthor {
                account_id: Some("creator-1".to_string()),
                display_name: Some("Creator One".to_string()),
            }),
            updated_by: Some(ConfluenceCommentAuthor {
                account_id: Some("editor-1".to_string()),
                display_name: Some("Editor One".to_string()),
            }),
            bodies: BTreeMap::from([(
                "storage".to_string(),
                "<p>private deploy steps</p>".to_string(),
            )]),
        },
        search_page: Mutex::new(Some(ConfluenceSearchPage {
            pages: vec![ConfluencePage {
                id: "123456".to_string(),
                title: "Deploy Runbook".to_string(),
                space: "ENG".to_string(),
                web_url: None,
                space_web_url: None,
                status: Some("current".to_string()),
                version: 7,
                created_at: Some("2026-06-01T10:00:00.000Z".to_string()),
                updated_at: Some("2026-06-02T11:00:00.000Z".to_string()),
                created_by: Some(ConfluenceCommentAuthor {
                    account_id: Some("creator-1".to_string()),
                    display_name: Some("Creator One".to_string()),
                }),
                updated_by: Some(ConfluenceCommentAuthor {
                    account_id: Some("editor-1".to_string()),
                    display_name: Some("Editor One".to_string()),
                }),
                bodies: BTreeMap::new(),
            }],
            max_results: 2,
            next_page_token: Some("cursor-2".to_string()),
        })),
        last_search: Mutex::new(None),
        metadata_calls: Mutex::new(0),
    });
    let broker = start_broker(CONFLUENCE_ACTIONS, backend.clone()).await;
    let base_url = broker.public_url();

    let page = Command::new(env!("CARGO_BIN_EXE_agent-access"))
        .args([
            "--url",
            &base_url,
            "--no-token",
            "confluence",
            "page",
            "view",
            "123456",
        ])
        .output()
        .unwrap();
    assert!(
        page.status.success(),
        "page view failed: stdout={} stderr={}",
        String::from_utf8_lossy(&page.stdout),
        String::from_utf8_lossy(&page.stderr)
    );
    let page_json: serde_json::Value = serde_json::from_slice(&page.stdout).unwrap();
    assert_eq!(page_json["decision"], "allow");
    assert_eq!(page_json["result"]["id"], "123456");
    assert_eq!(page_json["result"]["space"], "ENG");
    assert_eq!(page_json["result"]["createdAt"], "2026-06-01T10:00:00.000Z");
    assert_eq!(
        page_json["result"]["createdBy"]["displayName"],
        "Creator One"
    );
    assert_eq!(page_json["result"]["updatedBy"]["accountId"], "editor-1");
    assert_eq!(
        page_json["result"]["webUrl"],
        "https://example.atlassian.net/wiki/pages/viewpage.action?pageId=123456"
    );
    assert_eq!(
        page_json["result"]["spaceUrl"],
        "https://example.atlassian.net/wiki/spaces/ENG"
    );
    assert_eq!(
        page_json["result"]["body"]["storage"]["value"],
        "<p>private deploy steps</p>"
    );

    let page_by_url = Command::new(env!("CARGO_BIN_EXE_agent-access"))
        .args([
            "--url",
            &base_url,
            "--no-token",
            "confluence",
            "page",
            "view",
            "--page-url",
            "https://example.atlassian.net/wiki/pages/viewpage.action?pageId=123456",
        ])
        .output()
        .unwrap();
    assert!(
        page_by_url.status.success(),
        "page view by locator URL failed: stdout={} stderr={}",
        String::from_utf8_lossy(&page_by_url.stdout),
        String::from_utf8_lossy(&page_by_url.stderr)
    );
    let page_by_url_json: serde_json::Value = serde_json::from_slice(&page_by_url.stdout).unwrap();
    assert_eq!(page_by_url_json["result"]["id"], "123456");
    assert_eq!(page_by_url_json["resourceScopes"]["space"][0], "ENG");

    let search = Command::new(env!("CARGO_BIN_EXE_agent-access"))
        .args([
            "--url",
            &base_url,
            "--no-token",
            "confluence",
            "page",
            "search",
            "--text",
            "runbook",
            "--max-results",
            "100",
        ])
        .output()
        .unwrap();
    assert!(
        search.status.success(),
        "search failed: stdout={} stderr={}",
        String::from_utf8_lossy(&search.stdout),
        String::from_utf8_lossy(&search.stderr)
    );
    let search_json: serde_json::Value = serde_json::from_slice(&search.stdout).unwrap();
    assert_eq!(search_json["decision"], "allow");
    assert_eq!(search_json["result"]["pages"][0]["id"], "123456");
    assert_eq!(
        search_json["result"]["pages"][0]["updatedAt"],
        "2026-06-02T11:00:00.000Z"
    );
    assert_eq!(
        search_json["result"]["pages"][0]["updatedBy"]["displayName"],
        "Editor One"
    );
    assert!(search_json["result"]["pages"][0].get("body").is_none());
    assert_eq!(
        search_json["result"]["pages"][0]["webUrl"],
        "https://example.atlassian.net/wiki/pages/viewpage.action?pageId=123456"
    );
    assert_eq!(
        search_json["result"]["pages"][0]["spaceUrl"],
        "https://example.atlassian.net/wiki/spaces/ENG"
    );
    assert_eq!(search_json["result"]["nextPageToken"], "cursor-2");
    let last_search = backend
        .last_search
        .lock()
        .unwrap()
        .as_ref()
        .unwrap()
        .clone();
    assert_eq!(
        last_search.cql,
        r#"(title ~ "runbook") AND space IN (ENG) AND type = page"#
    );
    assert_eq!(last_search.spaces, vec!["ENG"]);
    assert_eq!(last_search.max_results, 2);

    let mismatch = Command::new(env!("CARGO_BIN_EXE_agent-access"))
        .args([
            "--url",
            &base_url,
            "--no-token",
            "confluence",
            "page",
            "view",
            "--page-url",
            "https://example.atlassian.net/wiki/spaces/OPS/pages/123456/Runbook",
        ])
        .output()
        .unwrap();
    assert!(!mismatch.status.success());
    let mismatch_json: serde_json::Value = serde_json::from_slice(&mismatch.stdout).unwrap();
    assert_eq!(mismatch_json["decision"], "deny");
    assert_eq!(mismatch_json["reasonCode"], "scope_unresolved");
    assert_eq!(
        mismatch_json["resourceScopes"].as_object().unwrap().len(),
        0
    );

    let audit = broker.audit().unwrap().text();
    assert!(audit.contains("\"service\":\"confluence\""));
    assert!(audit.contains("\"action\":\"page.view\""));
    assert!(audit.contains("\"action\":\"search\""));
    assert!(audit.contains("\"objectIds\""));
    assert!(audit.contains("\"returnedUrlFields\":[\"webUrl\",\"spaceUrl\"]"));
    assert!(!audit.contains("https://example.atlassian.net/wiki/pages/viewpage.action"));
    assert!(!audit.contains("https://example.atlassian.net/wiki/spaces/ENG"));
    assert!(!audit.contains("private deploy steps"));
    assert!(!audit.contains("<p>"));

    stop(broker).await;

    let denied_backend = Arc::new(StubConfluenceBackend {
        page: ConfluencePage {
            id: "654321".to_string(),
            title: "Hidden Runbook".to_string(),
            space: "OPS".to_string(),
            web_url: None,
            space_web_url: None,
            status: Some("current".to_string()),
            version: 1,
            created_at: None,
            updated_at: None,
            created_by: None,
            updated_by: None,
            bodies: BTreeMap::new(),
        },
        search_page: Mutex::new(Some(ConfluenceSearchPage {
            pages: vec![],
            max_results: 2,
            next_page_token: None,
        })),
        last_search: Mutex::new(None),
        metadata_calls: Mutex::new(0),
    });
    let denied_broker = start_broker(CONFLUENCE_ACTIONS, denied_backend).await;
    let denied_base_url = denied_broker.public_url();
    let denied = Command::new(env!("CARGO_BIN_EXE_agent-access"))
        .args([
            "--url",
            &denied_base_url,
            "--no-token",
            "confluence",
            "page",
            "view",
            "--page-url",
            "https://example.atlassian.net/wiki/pages/viewpage.action?pageId=654321",
        ])
        .output()
        .unwrap();
    assert!(!denied.status.success());
    let denied_json: serde_json::Value = serde_json::from_slice(&denied.stdout).unwrap();
    assert_eq!(denied_json["decision"], "deny");
    assert_eq!(denied_json["reasonCode"], "scope_unresolved");
    assert_eq!(
        denied_json["reason"],
        "resource scope is not authorized or unavailable"
    );
    assert_eq!(denied_json["resourceScopes"].as_object().unwrap().len(), 0);
    let denied_audit = denied_broker.audit().unwrap().text();
    assert!(denied_audit.contains("\"space\":[\"OPS\"]"));
    stop(denied_broker).await;

    let no_grant_backend = Arc::new(StubConfluenceBackend {
        page: ConfluencePage {
            id: "777777".to_string(),
            title: "No Grant".to_string(),
            space: "ENG".to_string(),
            web_url: None,
            space_web_url: None,
            status: Some("current".to_string()),
            version: 1,
            created_at: None,
            updated_at: None,
            created_by: None,
            updated_by: None,
            bodies: BTreeMap::new(),
        },
        search_page: Mutex::new(Some(ConfluenceSearchPage {
            pages: vec![],
            max_results: 2,
            next_page_token: None,
        })),
        last_search: Mutex::new(None),
        metadata_calls: Mutex::new(0),
    });
    let no_grant_broker = start_broker(&["search"], no_grant_backend.clone()).await;
    let no_grant_base_url = no_grant_broker.public_url();
    let no_grant = Command::new(env!("CARGO_BIN_EXE_agent-access"))
        .args([
            "--url",
            &no_grant_base_url,
            "--no-token",
            "confluence",
            "page",
            "view",
            "--page-url",
            "https://example.atlassian.net/wiki/pages/viewpage.action?pageId=777777",
        ])
        .output()
        .unwrap();
    assert!(!no_grant.status.success());
    let no_grant_json: serde_json::Value = serde_json::from_slice(&no_grant.stdout).unwrap();
    assert_eq!(no_grant_json["decision"], "deny");
    assert_eq!(no_grant_json["reasonCode"], "scope_unresolved");
    assert_eq!(
        no_grant_json["reason"],
        "resource scope is not authorized or unavailable"
    );
    assert_eq!(
        no_grant_json["resourceScopes"].as_object().unwrap().len(),
        0
    );
    assert_eq!(*no_grant_backend.metadata_calls.lock().unwrap(), 0);
    stop(no_grant_broker).await;

    let page_only_backend = Arc::new(StubConfluenceBackend {
        page: ConfluencePage {
            id: "888888".to_string(),
            title: "Page Only".to_string(),
            space: "ENG".to_string(),
            web_url: None,
            space_web_url: None,
            status: Some("current".to_string()),
            version: 1,
            created_at: None,
            updated_at: None,
            created_by: None,
            updated_by: None,
            bodies: BTreeMap::new(),
        },
        search_page: Mutex::new(Some(ConfluenceSearchPage {
            pages: vec![],
            max_results: 2,
            next_page_token: None,
        })),
        last_search: Mutex::new(None),
        metadata_calls: Mutex::new(0),
    });
    let page_only_broker = start_broker(&["page.view"], page_only_backend.clone()).await;
    let page_only_base_url = page_only_broker.public_url();
    let page_only_blog = Command::new(env!("CARGO_BIN_EXE_agent-access"))
        .args([
            "--url",
            &page_only_base_url,
            "--no-token",
            "confluence",
            "blog",
            "view",
            "888888",
        ])
        .output()
        .unwrap();
    assert!(!page_only_blog.status.success());
    let page_only_blog_json: serde_json::Value =
        serde_json::from_slice(&page_only_blog.stdout).unwrap();
    assert_eq!(page_only_blog_json["decision"], "deny");
    assert_eq!(page_only_blog_json["reasonCode"], "scope_unresolved");
    assert_eq!(*page_only_backend.metadata_calls.lock().unwrap(), 0);
    stop(page_only_broker).await;

    let blog_only_backend = Arc::new(StubConfluenceBackend {
        page: ConfluencePage {
            id: "999999".to_string(),
            title: "Blog Only".to_string(),
            space: "ENG".to_string(),
            web_url: None,
            space_web_url: None,
            status: Some("current".to_string()),
            version: 1,
            created_at: None,
            updated_at: None,
            created_by: None,
            updated_by: None,
            bodies: BTreeMap::new(),
        },
        search_page: Mutex::new(Some(ConfluenceSearchPage {
            pages: vec![],
            max_results: 2,
            next_page_token: None,
        })),
        last_search: Mutex::new(None),
        metadata_calls: Mutex::new(0),
    });
    let blog_only_broker = start_broker(&["blog.view"], blog_only_backend.clone()).await;
    let blog_only_base_url = blog_only_broker.public_url();
    let blog_only_page = Command::new(env!("CARGO_BIN_EXE_agent-access"))
        .args([
            "--url",
            &blog_only_base_url,
            "--no-token",
            "confluence",
            "page",
            "view",
            "999999",
        ])
        .output()
        .unwrap();
    assert!(!blog_only_page.status.success());
    let blog_only_page_json: serde_json::Value =
        serde_json::from_slice(&blog_only_page.stdout).unwrap();
    assert_eq!(blog_only_page_json["decision"], "deny");
    assert_eq!(blog_only_page_json["reasonCode"], "scope_unresolved");
    assert_eq!(*blog_only_backend.metadata_calls.lock().unwrap(), 0);
    stop(blog_only_broker).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cli_invokes_confluence_write_stream_and_verify_actions_against_stubbed_backend() {
    let storage_body_path = temp_path("confluence-body.storage.html");
    let markdown_body_path = temp_path("confluence-body.md");
    let atlas_body_path = temp_path("confluence-body.adf.json");
    let update_body_path = temp_path("confluence-update.storage.html");
    let comment_body_path = temp_path("confluence-comment.storage.html");
    let comment_update_body_path = temp_path("confluence-comment-update.storage.html");
    let attachment_path = temp_path("confluence-diagram.txt");
    let download_path = temp_path("confluence-download.txt");
    let blog_download_path = temp_path("confluence-blog-download.txt");
    let page_draft_download_path = temp_path("confluence-page-draft-download.txt");
    let blog_draft_download_path = temp_path("confluence-blog-draft-download.txt");
    std::fs::write(&storage_body_path, "<p>create secret body</p>").unwrap();
    std::fs::write(
        &markdown_body_path,
        "## normalized markdown sentinel 6f74d1\n\n- completed",
    )
    .unwrap();
    std::fs::write(
        &atlas_body_path,
        r#"{"version":1,"type":"doc","content":[{"type":"paragraph","content":[{"type":"text","text":"native atlas sentinel 29ca81"}]}]}"#,
    )
    .unwrap();
    std::fs::write(&update_body_path, "<p>updated secret body</p>").unwrap();
    std::fs::write(&comment_body_path, "<p>comment secret body</p>").unwrap();
    std::fs::write(
        &comment_update_body_path,
        "<p>comment updated secret body</p>",
    )
    .unwrap();
    std::fs::write(&attachment_path, b"diagram secret bytes").unwrap();

    let backend = Arc::new(WriteStubConfluenceBackend {
        spaces: Mutex::new(BTreeMap::from([(
            "98765".to_string(),
            ConfluenceSpace {
                id: "98765".to_string(),
                key: "ENG".to_string(),
                web_url: None,
                status: Some("current".to_string()),
                homepage_id: Some("123456".to_string()),
            },
        )])),
        pages: Mutex::new(BTreeMap::from([
            (
                "123456".to_string(),
                ConfluencePage {
                    id: "123456".to_string(),
                    title: "Deploy Runbook".to_string(),
                    space: "ENG".to_string(),
                    web_url: None,
                    space_web_url: None,
                    status: Some("current".to_string()),
                    version: 7,
                    created_at: None,
                    updated_at: None,
                    created_by: None,
                    updated_by: None,
                    bodies: BTreeMap::new(),
                },
            ),
            (
                "654321".to_string(),
                ConfluencePage {
                    id: "654321".to_string(),
                    title: "Operations".to_string(),
                    space: "ENG".to_string(),
                    web_url: None,
                    space_web_url: None,
                    status: Some("current".to_string()),
                    version: 2,
                    created_at: None,
                    updated_at: None,
                    created_by: None,
                    updated_by: None,
                    bodies: BTreeMap::new(),
                },
            ),
        ])),
        page_parents: Mutex::new(BTreeMap::from([
            ("123456".to_string(), None),
            ("654321".to_string(), Some("123456".to_string())),
        ])),
        page_orders: Mutex::new(BTreeMap::from([(
            "123456".to_string(),
            vec!["654321".to_string()],
        )])),
        blogs: Mutex::new(BTreeMap::from([(
            "222222".to_string(),
            ConfluenceBlog {
                id: "222222".to_string(),
                title: "Deploy Notes".to_string(),
                space: "ENG".to_string(),
                space_id: "98765".to_string(),
                web_url: None,
                space_web_url: None,
                status: Some("current".to_string()),
                version: 4,
                created_at: None,
                updated_at: None,
                created_by: None,
                updated_by: None,
                bodies: BTreeMap::from([(
                    "storage".to_string(),
                    "<p>blog secret body</p>".to_string(),
                )]),
            },
        )])),
        page_drafts: Mutex::new(BTreeMap::new()),
        blog_drafts: Mutex::new(BTreeMap::new()),
        attachments: Mutex::new(BTreeMap::new()),
        blog_attachments: Mutex::new(BTreeMap::new()),
        page_draft_attachments: Mutex::new(BTreeMap::new()),
        blog_draft_attachments: Mutex::new(BTreeMap::new()),
        attachment_content: Mutex::new(BTreeMap::new()),
        blog_attachment_content: Mutex::new(BTreeMap::new()),
        page_draft_attachment_content: Mutex::new(BTreeMap::new()),
        blog_draft_attachment_content: Mutex::new(BTreeMap::new()),
        comments: Mutex::new(BTreeMap::from([
            (
                "5001".to_string(),
                confluence_comment(
                    "5001",
                    ConfluenceCommentKind::Footer,
                    Some("123456"),
                    None,
                    None,
                    "<p>page footer comment</p>",
                ),
            ),
            (
                "5002".to_string(),
                confluence_comment(
                    "5002",
                    ConfluenceCommentKind::Footer,
                    None,
                    None,
                    Some("5001"),
                    "<p>page footer reply</p>",
                ),
            ),
            (
                "6001".to_string(),
                confluence_comment(
                    "6001",
                    ConfluenceCommentKind::Inline,
                    Some("123456"),
                    None,
                    None,
                    "<p>page inline comment</p>",
                ),
            ),
            (
                "6002".to_string(),
                confluence_comment(
                    "6002",
                    ConfluenceCommentKind::Inline,
                    None,
                    None,
                    Some("6001"),
                    "<p>page inline reply</p>",
                ),
            ),
            (
                "7001".to_string(),
                confluence_comment(
                    "7001",
                    ConfluenceCommentKind::Footer,
                    None,
                    Some("222222"),
                    None,
                    "<p>blog footer comment</p>",
                ),
            ),
            (
                "7002".to_string(),
                confluence_comment(
                    "7002",
                    ConfluenceCommentKind::Footer,
                    None,
                    None,
                    Some("7001"),
                    "<p>blog footer reply</p>",
                ),
            ),
            (
                "8001".to_string(),
                confluence_comment(
                    "8001",
                    ConfluenceCommentKind::Inline,
                    None,
                    Some("222222"),
                    None,
                    "<p>blog inline comment</p>",
                ),
            ),
            (
                "8002".to_string(),
                confluence_comment(
                    "8002",
                    ConfluenceCommentKind::Inline,
                    None,
                    None,
                    Some("8001"),
                    "<p>blog inline reply</p>",
                ),
            ),
        ])),
        next_page_id: Mutex::new(900001),
        next_blog_id: Mutex::new(800001),
        next_attachment_id: Mutex::new(123),
        next_comment_id: Mutex::new(9001),
    });
    let broker = start_broker(CONFLUENCE_ACTIONS, backend.clone()).await;
    let base_url = broker.public_url();

    let create = Command::new(env!("CARGO_BIN_EXE_agent-access"))
        .args([
            "--url",
            &base_url,
            "--no-token",
            "confluence",
            "page",
            "create",
            "--space",
            "ENG",
            "--title",
            "Created Page",
            "--parent",
            "123456",
            "--content-file",
            storage_body_path.to_str().unwrap(),
            "--content-format",
            "storage",
        ])
        .output()
        .unwrap();
    assert!(
        create.status.success(),
        "create failed: stdout={} stderr={}",
        String::from_utf8_lossy(&create.stdout),
        String::from_utf8_lossy(&create.stderr)
    );
    let create_json: serde_json::Value = serde_json::from_slice(&create.stdout).unwrap();
    assert_eq!(create_json["decision"], "allow");
    assert_eq!(create_json["result"]["pageId"], "900001");
    assert_eq!(create_json["result"]["parentPageId"], "123456");
    assert_eq!(create_json["result"]["placement"], "requested_parent");
    assert_eq!(create_json["result"]["verification"]["status"], "matched");
    assert_eq!(
        create_json["result"]["webUrl"],
        "https://example.atlassian.net/wiki/pages/viewpage.action?pageId=900001"
    );
    assert_eq!(
        create_json["result"]["spaceUrl"],
        "https://example.atlassian.net/wiki/spaces/ENG"
    );

    let page_move = Command::new(env!("CARGO_BIN_EXE_agent-access"))
        .args([
            "--url",
            &base_url,
            "--no-token",
            "confluence",
            "page",
            "move",
            "900001",
            "--position",
            "append",
            "--target",
            "654321",
        ])
        .output()
        .unwrap();
    assert!(
        page_move.status.success(),
        "page move failed: stdout={} stderr={}",
        String::from_utf8_lossy(&page_move.stdout),
        String::from_utf8_lossy(&page_move.stderr)
    );
    let page_move_json: serde_json::Value = serde_json::from_slice(&page_move.stdout).unwrap();
    assert_eq!(page_move_json["result"]["operation"], "page.move");
    assert_eq!(page_move_json["result"]["pageId"], "900001");
    assert_eq!(page_move_json["result"]["position"], "append");
    assert_eq!(page_move_json["result"]["targetPageId"], "654321");
    assert_eq!(page_move_json["result"]["previousParentId"], "123456");
    assert_eq!(page_move_json["result"]["previousParentType"], "page");
    assert_eq!(page_move_json["result"]["parentPageId"], "654321");
    assert_eq!(page_move_json["result"]["childPosition"], 0);
    assert_eq!(
        page_move_json["result"]["verification"]["status"],
        "matched"
    );

    let update = Command::new(env!("CARGO_BIN_EXE_agent-access"))
        .args([
            "--url",
            &base_url,
            "--no-token",
            "confluence",
            "page",
            "update",
            "123456",
            "--base-version",
            "7",
            "--content",
            "normalized plain text sentinel 82bd40 * literal",
            "--content-format",
            "plain_text",
        ])
        .output()
        .unwrap();
    assert!(
        update.status.success(),
        "update failed: stdout={} stderr={}",
        String::from_utf8_lossy(&update.stdout),
        String::from_utf8_lossy(&update.stderr)
    );
    let update_json: serde_json::Value = serde_json::from_slice(&update.stdout).unwrap();
    assert_eq!(update_json["result"]["version"], 8);
    assert_eq!(
        update_json["result"]["webUrl"],
        "https://example.atlassian.net/wiki/pages/viewpage.action?pageId=123456"
    );
    assert_eq!(
        update_json["result"]["spaceUrl"],
        "https://example.atlassian.net/wiki/spaces/ENG"
    );

    let conflict = Command::new(env!("CARGO_BIN_EXE_agent-access"))
        .args([
            "--url",
            &base_url,
            "--no-token",
            "confluence",
            "page",
            "update",
            "123456",
            "--base-version",
            "7",
            "--content-file",
            atlas_body_path.to_str().unwrap(),
            "--content-format",
            "atlas_doc_format",
        ])
        .output()
        .unwrap();
    assert_eq!(conflict.status.code(), Some(2));
    let conflict_json: serde_json::Value = serde_json::from_slice(&conflict.stdout).unwrap();
    assert_eq!(conflict_json["decision"], "error");
    assert_eq!(conflict_json["reasonCode"], "version_conflict");
    assert_eq!(conflict_json["result"]["currentVersion"], 8);

    let attach = Command::new(env!("CARGO_BIN_EXE_agent-access"))
        .args([
            "--url",
            &base_url,
            "--no-token",
            "confluence",
            "page",
            "attach",
            "123456",
            "--content-type",
            "text/plain",
            attachment_path.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        attach.status.success(),
        "attach failed: stdout={} stderr={}",
        String::from_utf8_lossy(&attach.stdout),
        String::from_utf8_lossy(&attach.stderr)
    );
    let attach_json: serde_json::Value = serde_json::from_slice(&attach.stdout).unwrap();
    assert_eq!(
        attach_json["result"]["attachments"][0]["attachmentId"],
        "att123"
    );

    let list = Command::new(env!("CARGO_BIN_EXE_agent-access"))
        .args([
            "--url",
            &base_url,
            "--no-token",
            "confluence",
            "page",
            "attachment",
            "list",
            "123456",
        ])
        .output()
        .unwrap();
    assert!(
        list.status.success(),
        "attachment list failed: stdout={} stderr={}",
        String::from_utf8_lossy(&list.stdout),
        String::from_utf8_lossy(&list.stderr)
    );
    let list_json: serde_json::Value = serde_json::from_slice(&list.stdout).unwrap();
    let listed_attachment_id = list_json["result"]["attachments"][0]["attachmentId"]
        .as_str()
        .unwrap();
    assert_eq!(listed_attachment_id, "att123");

    let download = Command::new(env!("CARGO_BIN_EXE_agent-access"))
        .args([
            "--url",
            &base_url,
            "--no-token",
            "confluence",
            "page",
            "attachment",
            "download",
            "123456",
            "--attachment-id",
            listed_attachment_id,
            "--output",
            download_path.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        download.status.success(),
        "download failed: stdout={} stderr={}",
        String::from_utf8_lossy(&download.stdout),
        String::from_utf8_lossy(&download.stderr)
    );
    assert_eq!(
        std::fs::read_to_string(&download_path).unwrap(),
        "diagram secret bytes"
    );
    let download_json: serde_json::Value = serde_json::from_slice(&download.stdout).unwrap();
    assert!(download_json["result"].get("contentBase64").is_none());

    let verify_mismatch = Command::new(env!("CARGO_BIN_EXE_agent-access"))
        .args([
            "--url",
            &base_url,
            "--no-token",
            "confluence",
            "page",
            "verify",
            "123456",
            "--expect-version",
            "99",
        ])
        .output()
        .unwrap();
    assert_eq!(verify_mismatch.status.code(), Some(2));
    let verify_mismatch_json: serde_json::Value =
        serde_json::from_slice(&verify_mismatch.stdout).unwrap();
    assert_eq!(verify_mismatch_json["decision"], "allow");
    assert_eq!(verify_mismatch_json["reasonCode"], "verification_mismatch");

    let verify = Command::new(env!("CARGO_BIN_EXE_agent-access"))
        .args([
            "--url",
            &base_url,
            "--no-token",
            "confluence",
            "page",
            "verify",
            "123456",
            "--expect-version",
            "8",
            "--expect-attachment-id",
            "att123",
        ])
        .output()
        .unwrap();
    assert!(
        verify.status.success(),
        "verify failed: stdout={} stderr={}",
        String::from_utf8_lossy(&verify.stdout),
        String::from_utf8_lossy(&verify.stderr)
    );
    let verify_json: serde_json::Value = serde_json::from_slice(&verify.stdout).unwrap();
    assert_eq!(verify_json["result"]["verification"]["status"], "matched");

    let page_footer_list = Command::new(env!("CARGO_BIN_EXE_agent-access"))
        .args([
            "--url",
            &base_url,
            "--no-token",
            "confluence",
            "page",
            "footer-comment",
            "list",
            "123456",
            "--body-format",
            "storage",
        ])
        .output()
        .unwrap();
    assert!(
        page_footer_list.status.success(),
        "page footer comment list failed: stdout={} stderr={}",
        String::from_utf8_lossy(&page_footer_list.stdout),
        String::from_utf8_lossy(&page_footer_list.stderr)
    );
    let page_footer_list_json: serde_json::Value =
        serde_json::from_slice(&page_footer_list.stdout).unwrap();
    assert_eq!(
        page_footer_list_json["result"]["comments"][0]["commentId"],
        "5001"
    );
    assert_eq!(
        page_footer_list_json["result"]["comments"][0]["body"]["storage"]["value"],
        "<p>page footer comment</p>"
    );

    let page_footer_view = Command::new(env!("CARGO_BIN_EXE_agent-access"))
        .args([
            "--url",
            &base_url,
            "--no-token",
            "confluence",
            "page",
            "footer-comment",
            "view",
            "5001",
            "--body-format",
            "storage",
        ])
        .output()
        .unwrap();
    assert!(
        page_footer_view.status.success(),
        "page footer comment view failed: stdout={} stderr={}",
        String::from_utf8_lossy(&page_footer_view.stdout),
        String::from_utf8_lossy(&page_footer_view.stderr)
    );
    let page_footer_view_json: serde_json::Value =
        serde_json::from_slice(&page_footer_view.stdout).unwrap();
    assert_eq!(
        page_footer_view_json["result"]["comment"]["pageId"],
        "123456"
    );

    let page_footer_add = Command::new(env!("CARGO_BIN_EXE_agent-access"))
        .args([
            "--url",
            &base_url,
            "--no-token",
            "confluence",
            "page",
            "footer-comment",
            "add",
            "123456",
            "--content-file",
            comment_body_path.to_str().unwrap(),
            "--content-format",
            "storage",
        ])
        .output()
        .unwrap();
    assert!(
        page_footer_add.status.success(),
        "page footer comment add failed: stdout={} stderr={}",
        String::from_utf8_lossy(&page_footer_add.stdout),
        String::from_utf8_lossy(&page_footer_add.stderr)
    );
    let page_footer_add_json: serde_json::Value =
        serde_json::from_slice(&page_footer_add.stdout).unwrap();
    assert_eq!(
        page_footer_add_json["result"]["comment"]["body"]["storage"]["value"],
        "<p>comment secret body</p>"
    );

    let page_footer_replies = Command::new(env!("CARGO_BIN_EXE_agent-access"))
        .args([
            "--url",
            &base_url,
            "--no-token",
            "confluence",
            "page",
            "footer-comment",
            "replies",
            "5001",
            "--body-format",
            "storage",
        ])
        .output()
        .unwrap();
    assert!(
        page_footer_replies.status.success(),
        "page footer comment replies failed: stdout={} stderr={}",
        String::from_utf8_lossy(&page_footer_replies.stdout),
        String::from_utf8_lossy(&page_footer_replies.stderr)
    );
    let page_footer_replies_json: serde_json::Value =
        serde_json::from_slice(&page_footer_replies.stdout).unwrap();
    assert_eq!(
        page_footer_replies_json["result"]["comments"][0]["commentId"],
        "5002"
    );

    let page_footer_reply = Command::new(env!("CARGO_BIN_EXE_agent-access"))
        .args([
            "--url",
            &base_url,
            "--no-token",
            "confluence",
            "page",
            "footer-comment",
            "reply",
            "5001",
            "--content-file",
            comment_body_path.to_str().unwrap(),
            "--content-format",
            "storage",
        ])
        .output()
        .unwrap();
    assert!(
        page_footer_reply.status.success(),
        "page footer comment reply failed: stdout={} stderr={}",
        String::from_utf8_lossy(&page_footer_reply.stdout),
        String::from_utf8_lossy(&page_footer_reply.stderr)
    );
    let page_footer_reply_json: serde_json::Value =
        serde_json::from_slice(&page_footer_reply.stdout).unwrap();
    assert_eq!(
        page_footer_reply_json["result"]["comment"]["parentCommentId"],
        "5001"
    );

    let page_footer_update = Command::new(env!("CARGO_BIN_EXE_agent-access"))
        .args([
            "--url",
            &base_url,
            "--no-token",
            "confluence",
            "page",
            "footer-comment",
            "update",
            "5002",
            "--base-version",
            "1",
            "--content-file",
            comment_update_body_path.to_str().unwrap(),
            "--content-format",
            "storage",
        ])
        .output()
        .unwrap();
    assert!(
        page_footer_update.status.success(),
        "page footer comment update failed: stdout={} stderr={}",
        String::from_utf8_lossy(&page_footer_update.stdout),
        String::from_utf8_lossy(&page_footer_update.stderr)
    );
    let page_footer_update_json: serde_json::Value =
        serde_json::from_slice(&page_footer_update.stdout).unwrap();
    assert_eq!(
        page_footer_update_json["result"]["comment"]["body"]["storage"]["value"],
        "<p>comment updated secret body</p>"
    );
    assert_eq!(page_footer_update_json["result"]["version"], 2);

    let page_inline_list = Command::new(env!("CARGO_BIN_EXE_agent-access"))
        .args([
            "--url",
            &base_url,
            "--no-token",
            "confluence",
            "page",
            "inline-comment",
            "list",
            "123456",
            "--body-format",
            "storage",
            "--resolution-status",
            "open",
        ])
        .output()
        .unwrap();
    assert!(
        page_inline_list.status.success(),
        "page inline comment list failed: stdout={} stderr={}",
        String::from_utf8_lossy(&page_inline_list.stdout),
        String::from_utf8_lossy(&page_inline_list.stderr)
    );
    let page_inline_list_json: serde_json::Value =
        serde_json::from_slice(&page_inline_list.stdout).unwrap();
    assert_eq!(
        page_inline_list_json["result"]["comments"][0]["commentId"],
        "6001"
    );

    let page_inline_view = Command::new(env!("CARGO_BIN_EXE_agent-access"))
        .args([
            "--url",
            &base_url,
            "--no-token",
            "confluence",
            "page",
            "inline-comment",
            "view",
            "6001",
            "--body-format",
            "storage",
        ])
        .output()
        .unwrap();
    assert!(
        page_inline_view.status.success(),
        "page inline comment view failed: stdout={} stderr={}",
        String::from_utf8_lossy(&page_inline_view.stdout),
        String::from_utf8_lossy(&page_inline_view.stderr)
    );
    let page_inline_view_json: serde_json::Value =
        serde_json::from_slice(&page_inline_view.stdout).unwrap();
    assert_eq!(
        page_inline_view_json["result"]["comment"]["resolutionStatus"],
        "open"
    );

    let page_inline_update = Command::new(env!("CARGO_BIN_EXE_agent-access"))
        .args([
            "--url",
            &base_url,
            "--no-token",
            "confluence",
            "page",
            "inline-comment",
            "update",
            "6001",
            "--base-version",
            "1",
            "--content",
            "normalized page inline update sentinel 23ee90",
            "--content-format",
            "plain_text",
        ])
        .output()
        .unwrap();
    assert!(
        page_inline_update.status.success(),
        "page inline comment update failed: stdout={} stderr={}",
        String::from_utf8_lossy(&page_inline_update.stdout),
        String::from_utf8_lossy(&page_inline_update.stderr)
    );
    let page_inline_update_json: serde_json::Value =
        serde_json::from_slice(&page_inline_update.stdout).unwrap();
    assert_eq!(page_inline_update_json["result"]["version"], 2);

    let page_inline_replies = Command::new(env!("CARGO_BIN_EXE_agent-access"))
        .args([
            "--url",
            &base_url,
            "--no-token",
            "confluence",
            "page",
            "inline-comment",
            "replies",
            "6001",
            "--body-format",
            "storage",
        ])
        .output()
        .unwrap();
    assert!(
        page_inline_replies.status.success(),
        "page inline comment replies failed: stdout={} stderr={}",
        String::from_utf8_lossy(&page_inline_replies.stdout),
        String::from_utf8_lossy(&page_inline_replies.stderr)
    );
    let page_inline_replies_json: serde_json::Value =
        serde_json::from_slice(&page_inline_replies.stdout).unwrap();
    assert_eq!(
        page_inline_replies_json["result"]["comments"][0]["commentId"],
        "6002"
    );

    let page_inline_reply = Command::new(env!("CARGO_BIN_EXE_agent-access"))
        .args([
            "--url",
            &base_url,
            "--no-token",
            "confluence",
            "page",
            "inline-comment",
            "reply",
            "6001",
            "--content-file",
            comment_body_path.to_str().unwrap(),
            "--content-format",
            "storage",
        ])
        .output()
        .unwrap();
    assert!(
        page_inline_reply.status.success(),
        "page inline comment reply failed: stdout={} stderr={}",
        String::from_utf8_lossy(&page_inline_reply.stdout),
        String::from_utf8_lossy(&page_inline_reply.stderr)
    );
    let page_inline_reply_json: serde_json::Value =
        serde_json::from_slice(&page_inline_reply.stdout).unwrap();
    assert_eq!(
        page_inline_reply_json["result"]["comment"]["parentCommentId"],
        "6001"
    );

    let page_inline_delete = Command::new(env!("CARGO_BIN_EXE_agent-access"))
        .args([
            "--url",
            &base_url,
            "--no-token",
            "confluence",
            "page",
            "inline-comment",
            "delete",
            "6002",
        ])
        .output()
        .unwrap();
    assert!(
        page_inline_delete.status.success(),
        "page inline comment delete failed: stdout={} stderr={}",
        String::from_utf8_lossy(&page_inline_delete.stdout),
        String::from_utf8_lossy(&page_inline_delete.stderr)
    );
    let page_inline_delete_json: serde_json::Value =
        serde_json::from_slice(&page_inline_delete.stdout).unwrap();
    assert_eq!(page_inline_delete_json["result"]["status"], "deleted");

    let blog_view = Command::new(env!("CARGO_BIN_EXE_agent-access"))
        .args([
            "--url",
            &base_url,
            "--no-token",
            "confluence",
            "blog",
            "view",
            "222222",
        ])
        .output()
        .unwrap();
    assert!(
        blog_view.status.success(),
        "blog view failed: stdout={} stderr={}",
        String::from_utf8_lossy(&blog_view.stdout),
        String::from_utf8_lossy(&blog_view.stderr)
    );
    let blog_view_json: serde_json::Value = serde_json::from_slice(&blog_view.stdout).unwrap();
    assert_eq!(blog_view_json["result"]["blogId"], "222222");
    assert_eq!(
        blog_view_json["result"]["webUrl"],
        "https://example.atlassian.net/wiki/pages/viewpage.action?pageId=222222"
    );
    assert_eq!(
        blog_view_json["result"]["spaceUrl"],
        "https://example.atlassian.net/wiki/spaces/ENG"
    );
    assert_eq!(
        blog_view_json["result"]["body"]["storage"],
        "<p>blog secret body</p>"
    );

    let blog_view_by_url = Command::new(env!("CARGO_BIN_EXE_agent-access"))
        .args([
            "--url",
            &base_url,
            "--no-token",
            "confluence",
            "blog",
            "view",
            "--blog-url",
            "https://example.atlassian.net/wiki/spaces/ENG/blog/2026/06/28/222222/12345",
        ])
        .output()
        .unwrap();
    assert!(
        blog_view_by_url.status.success(),
        "blog view by URL failed: stdout={} stderr={}",
        String::from_utf8_lossy(&blog_view_by_url.stdout),
        String::from_utf8_lossy(&blog_view_by_url.stderr)
    );
    let blog_view_by_url_json: serde_json::Value =
        serde_json::from_slice(&blog_view_by_url.stdout).unwrap();
    assert_eq!(blog_view_by_url_json["result"]["blogId"], "222222");

    let blog_search = Command::new(env!("CARGO_BIN_EXE_agent-access"))
        .args([
            "--url",
            &base_url,
            "--no-token",
            "confluence",
            "blog",
            "search",
            "--text",
            "deploy",
            "--space",
            "ENG",
        ])
        .output()
        .unwrap();
    assert!(
        blog_search.status.success(),
        "blog search failed: stdout={} stderr={}",
        String::from_utf8_lossy(&blog_search.stdout),
        String::from_utf8_lossy(&blog_search.stderr)
    );
    let blog_search_json: serde_json::Value = serde_json::from_slice(&blog_search.stdout).unwrap();
    assert_eq!(blog_search_json["result"]["blogs"][0]["blogId"], "222222");
    assert_eq!(
        blog_search_json["result"]["blogs"][0]["webUrl"],
        "https://example.atlassian.net/wiki/pages/viewpage.action?pageId=222222"
    );
    assert_eq!(
        blog_search_json["result"]["blogs"][0]["spaceUrl"],
        "https://example.atlassian.net/wiki/spaces/ENG"
    );

    let blog_create = Command::new(env!("CARGO_BIN_EXE_agent-access"))
        .args([
            "--url",
            &base_url,
            "--no-token",
            "confluence",
            "blog",
            "create",
            "--space",
            "ENG",
            "--title",
            "Created Blog",
            "--content-file",
            markdown_body_path.to_str().unwrap(),
            "--content-format",
            "markdown",
        ])
        .output()
        .unwrap();
    assert!(
        blog_create.status.success(),
        "blog create failed: stdout={} stderr={}",
        String::from_utf8_lossy(&blog_create.stdout),
        String::from_utf8_lossy(&blog_create.stderr)
    );
    let blog_create_json: serde_json::Value = serde_json::from_slice(&blog_create.stdout).unwrap();
    assert_eq!(blog_create_json["result"]["blogId"], "800001");
    assert_eq!(
        blog_create_json["result"]["webUrl"],
        "https://example.atlassian.net/wiki/pages/viewpage.action?pageId=800001"
    );
    assert_eq!(
        blog_create_json["result"]["spaceUrl"],
        "https://example.atlassian.net/wiki/spaces/ENG"
    );

    let blog_update = Command::new(env!("CARGO_BIN_EXE_agent-access"))
        .args([
            "--url",
            &base_url,
            "--no-token",
            "confluence",
            "blog",
            "update",
            "222222",
            "--base-version",
            "4",
            "--content",
            "normalized blog plain text sentinel 470ac3",
            "--content-format",
            "plain_text",
            "--version-message",
            "smoke update",
        ])
        .output()
        .unwrap();
    assert!(
        blog_update.status.success(),
        "blog update failed: stdout={} stderr={}",
        String::from_utf8_lossy(&blog_update.stdout),
        String::from_utf8_lossy(&blog_update.stderr)
    );
    let blog_update_json: serde_json::Value = serde_json::from_slice(&blog_update.stdout).unwrap();
    assert_eq!(blog_update_json["result"]["version"], 5);
    assert_eq!(
        blog_update_json["result"]["webUrl"],
        "https://example.atlassian.net/wiki/pages/viewpage.action?pageId=222222"
    );

    let blog_attach = Command::new(env!("CARGO_BIN_EXE_agent-access"))
        .args([
            "--url",
            &base_url,
            "--no-token",
            "confluence",
            "blog",
            "attach",
            "222222",
            "--content-type",
            "text/plain",
            attachment_path.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        blog_attach.status.success(),
        "blog attach failed: stdout={} stderr={}",
        String::from_utf8_lossy(&blog_attach.stdout),
        String::from_utf8_lossy(&blog_attach.stderr)
    );
    let blog_attach_json: serde_json::Value = serde_json::from_slice(&blog_attach.stdout).unwrap();
    let blog_attachment_id = blog_attach_json["result"]["attachments"][0]["attachmentId"]
        .as_str()
        .unwrap();

    let blog_list = Command::new(env!("CARGO_BIN_EXE_agent-access"))
        .args([
            "--url",
            &base_url,
            "--no-token",
            "confluence",
            "blog",
            "attachment",
            "list",
            "222222",
        ])
        .output()
        .unwrap();
    assert!(
        blog_list.status.success(),
        "blog attachment list failed: stdout={} stderr={}",
        String::from_utf8_lossy(&blog_list.stdout),
        String::from_utf8_lossy(&blog_list.stderr)
    );
    let blog_list_json: serde_json::Value = serde_json::from_slice(&blog_list.stdout).unwrap();
    assert_eq!(
        blog_list_json["result"]["attachments"][0]["attachmentId"],
        blog_attachment_id
    );

    let blog_list_by_url = Command::new(env!("CARGO_BIN_EXE_agent-access"))
        .args([
            "--url",
            &base_url,
            "--no-token",
            "confluence",
            "blog",
            "attachment",
            "list",
            "--blog-url",
            "https://example.atlassian.net/wiki/spaces/ENG/blog/2026/06/28/222222/Release+Notes",
        ])
        .output()
        .unwrap();
    assert!(
        blog_list_by_url.status.success(),
        "blog attachment list by URL failed: stdout={} stderr={}",
        String::from_utf8_lossy(&blog_list_by_url.stdout),
        String::from_utf8_lossy(&blog_list_by_url.stderr)
    );
    let blog_list_by_url_json: serde_json::Value =
        serde_json::from_slice(&blog_list_by_url.stdout).unwrap();
    assert_eq!(
        blog_list_by_url_json["result"]["attachments"][0]["attachmentId"],
        blog_attachment_id
    );

    let blog_download = Command::new(env!("CARGO_BIN_EXE_agent-access"))
        .args([
            "--url",
            &base_url,
            "--no-token",
            "confluence",
            "blog",
            "attachment",
            "download",
            "222222",
            "--attachment-id",
            blog_attachment_id,
            "--output",
            blog_download_path.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        blog_download.status.success(),
        "blog attachment download failed: stdout={} stderr={}",
        String::from_utf8_lossy(&blog_download.stdout),
        String::from_utf8_lossy(&blog_download.stderr)
    );
    assert_eq!(
        std::fs::read_to_string(&blog_download_path).unwrap(),
        "diagram secret bytes"
    );

    let blog_verify = Command::new(env!("CARGO_BIN_EXE_agent-access"))
        .args([
            "--url",
            &base_url,
            "--no-token",
            "confluence",
            "blog",
            "verify",
            "222222",
            "--expect-version",
            "5",
            "--expect-attachment-id",
            blog_attachment_id,
        ])
        .output()
        .unwrap();
    assert!(
        blog_verify.status.success(),
        "blog verify failed: stdout={} stderr={}",
        String::from_utf8_lossy(&blog_verify.stdout),
        String::from_utf8_lossy(&blog_verify.stderr)
    );
    let blog_verify_json: serde_json::Value = serde_json::from_slice(&blog_verify.stdout).unwrap();
    assert_eq!(
        blog_verify_json["result"]["verification"]["status"],
        "matched"
    );

    let blog_footer_list = Command::new(env!("CARGO_BIN_EXE_agent-access"))
        .args([
            "--url",
            &base_url,
            "--no-token",
            "confluence",
            "blog",
            "footer-comment",
            "list",
            "222222",
            "--body-format",
            "storage",
        ])
        .output()
        .unwrap();
    assert!(
        blog_footer_list.status.success(),
        "blog footer comment list failed: stdout={} stderr={}",
        String::from_utf8_lossy(&blog_footer_list.stdout),
        String::from_utf8_lossy(&blog_footer_list.stderr)
    );
    let blog_footer_list_json: serde_json::Value =
        serde_json::from_slice(&blog_footer_list.stdout).unwrap();
    assert_eq!(
        blog_footer_list_json["result"]["comments"][0]["commentId"],
        "7001"
    );

    let blog_footer_view = Command::new(env!("CARGO_BIN_EXE_agent-access"))
        .args([
            "--url",
            &base_url,
            "--no-token",
            "confluence",
            "blog",
            "footer-comment",
            "view",
            "7001",
            "--body-format",
            "storage",
        ])
        .output()
        .unwrap();
    assert!(
        blog_footer_view.status.success(),
        "blog footer comment view failed: stdout={} stderr={}",
        String::from_utf8_lossy(&blog_footer_view.stdout),
        String::from_utf8_lossy(&blog_footer_view.stderr)
    );
    let blog_footer_view_json: serde_json::Value =
        serde_json::from_slice(&blog_footer_view.stdout).unwrap();
    assert_eq!(
        blog_footer_view_json["result"]["comment"]["blogId"],
        "222222"
    );

    let blog_footer_add = Command::new(env!("CARGO_BIN_EXE_agent-access"))
        .args([
            "--url",
            &base_url,
            "--no-token",
            "confluence",
            "blog",
            "footer-comment",
            "add",
            "222222",
            "--content",
            "normalized page inline **reply** sentinel 715cab",
            "--content-format",
            "markdown",
        ])
        .output()
        .unwrap();
    assert!(
        blog_footer_add.status.success(),
        "blog footer comment add failed: stdout={} stderr={}",
        String::from_utf8_lossy(&blog_footer_add.stdout),
        String::from_utf8_lossy(&blog_footer_add.stderr)
    );
    let blog_footer_add_json: serde_json::Value =
        serde_json::from_slice(&blog_footer_add.stdout).unwrap();
    let blog_footer_add_body =
        blog_footer_add_json["result"]["comment"]["body"]["storage"]["value"]
            .as_str()
            .unwrap();
    assert!(
        blog_footer_add_body.contains("normalized page inline")
            && blog_footer_add_body.contains("reply")
            && !blog_footer_add_body.contains("**")
    );

    let blog_footer_replies = Command::new(env!("CARGO_BIN_EXE_agent-access"))
        .args([
            "--url",
            &base_url,
            "--no-token",
            "confluence",
            "blog",
            "footer-comment",
            "replies",
            "7001",
            "--body-format",
            "storage",
        ])
        .output()
        .unwrap();
    assert!(
        blog_footer_replies.status.success(),
        "blog footer comment replies failed: stdout={} stderr={}",
        String::from_utf8_lossy(&blog_footer_replies.stdout),
        String::from_utf8_lossy(&blog_footer_replies.stderr)
    );
    let blog_footer_replies_json: serde_json::Value =
        serde_json::from_slice(&blog_footer_replies.stdout).unwrap();
    assert_eq!(
        blog_footer_replies_json["result"]["comments"][0]["commentId"],
        "7002"
    );

    let blog_footer_reply = Command::new(env!("CARGO_BIN_EXE_agent-access"))
        .args([
            "--url",
            &base_url,
            "--no-token",
            "confluence",
            "blog",
            "footer-comment",
            "reply",
            "7001",
            "--content-file",
            comment_body_path.to_str().unwrap(),
            "--content-format",
            "storage",
        ])
        .output()
        .unwrap();
    assert!(
        blog_footer_reply.status.success(),
        "blog footer comment reply failed: stdout={} stderr={}",
        String::from_utf8_lossy(&blog_footer_reply.stdout),
        String::from_utf8_lossy(&blog_footer_reply.stderr)
    );
    let blog_footer_reply_json: serde_json::Value =
        serde_json::from_slice(&blog_footer_reply.stdout).unwrap();
    assert_eq!(
        blog_footer_reply_json["result"]["comment"]["parentCommentId"],
        "7001"
    );

    let blog_footer_update = Command::new(env!("CARGO_BIN_EXE_agent-access"))
        .args([
            "--url",
            &base_url,
            "--no-token",
            "confluence",
            "blog",
            "footer-comment",
            "update",
            "7002",
            "--base-version",
            "1",
            "--content-file",
            comment_update_body_path.to_str().unwrap(),
            "--content-format",
            "storage",
        ])
        .output()
        .unwrap();
    assert!(
        blog_footer_update.status.success(),
        "blog footer comment update failed: stdout={} stderr={}",
        String::from_utf8_lossy(&blog_footer_update.stdout),
        String::from_utf8_lossy(&blog_footer_update.stderr)
    );
    let blog_footer_update_json: serde_json::Value =
        serde_json::from_slice(&blog_footer_update.stdout).unwrap();
    assert_eq!(
        blog_footer_update_json["result"]["comment"]["body"]["storage"]["value"],
        "<p>comment updated secret body</p>"
    );
    assert_eq!(blog_footer_update_json["result"]["version"], 2);

    let blog_inline_list = Command::new(env!("CARGO_BIN_EXE_agent-access"))
        .args([
            "--url",
            &base_url,
            "--no-token",
            "confluence",
            "blog",
            "inline-comment",
            "list",
            "222222",
            "--body-format",
            "storage",
            "--resolution-status",
            "open",
        ])
        .output()
        .unwrap();
    assert!(
        blog_inline_list.status.success(),
        "blog inline comment list failed: stdout={} stderr={}",
        String::from_utf8_lossy(&blog_inline_list.stdout),
        String::from_utf8_lossy(&blog_inline_list.stderr)
    );
    let blog_inline_list_json: serde_json::Value =
        serde_json::from_slice(&blog_inline_list.stdout).unwrap();
    assert_eq!(
        blog_inline_list_json["result"]["comments"][0]["commentId"],
        "8001"
    );

    let blog_inline_view = Command::new(env!("CARGO_BIN_EXE_agent-access"))
        .args([
            "--url",
            &base_url,
            "--no-token",
            "confluence",
            "blog",
            "inline-comment",
            "view",
            "8001",
            "--body-format",
            "storage",
        ])
        .output()
        .unwrap();
    assert!(
        blog_inline_view.status.success(),
        "blog inline comment view failed: stdout={} stderr={}",
        String::from_utf8_lossy(&blog_inline_view.stdout),
        String::from_utf8_lossy(&blog_inline_view.stderr)
    );
    let blog_inline_view_json: serde_json::Value =
        serde_json::from_slice(&blog_inline_view.stdout).unwrap();
    assert_eq!(
        blog_inline_view_json["result"]["comment"]["resolutionStatus"],
        "open"
    );

    let blog_inline_update = Command::new(env!("CARGO_BIN_EXE_agent-access"))
        .args([
            "--url",
            &base_url,
            "--no-token",
            "confluence",
            "blog",
            "inline-comment",
            "update",
            "8001",
            "--base-version",
            "1",
            "--content",
            "normalized **blog inline update** sentinel af9105",
            "--content-format",
            "markdown",
        ])
        .output()
        .unwrap();
    assert!(
        blog_inline_update.status.success(),
        "blog inline comment update failed: stdout={} stderr={}",
        String::from_utf8_lossy(&blog_inline_update.stdout),
        String::from_utf8_lossy(&blog_inline_update.stderr)
    );
    let blog_inline_update_json: serde_json::Value =
        serde_json::from_slice(&blog_inline_update.stdout).unwrap();
    assert_eq!(blog_inline_update_json["result"]["version"], 2);

    let blog_inline_replies = Command::new(env!("CARGO_BIN_EXE_agent-access"))
        .args([
            "--url",
            &base_url,
            "--no-token",
            "confluence",
            "blog",
            "inline-comment",
            "replies",
            "8001",
            "--body-format",
            "storage",
        ])
        .output()
        .unwrap();
    assert!(
        blog_inline_replies.status.success(),
        "blog inline comment replies failed: stdout={} stderr={}",
        String::from_utf8_lossy(&blog_inline_replies.stdout),
        String::from_utf8_lossy(&blog_inline_replies.stderr)
    );
    let blog_inline_replies_json: serde_json::Value =
        serde_json::from_slice(&blog_inline_replies.stdout).unwrap();
    assert_eq!(
        blog_inline_replies_json["result"]["comments"][0]["commentId"],
        "8002"
    );

    let blog_inline_reply = Command::new(env!("CARGO_BIN_EXE_agent-access"))
        .args([
            "--url",
            &base_url,
            "--no-token",
            "confluence",
            "blog",
            "inline-comment",
            "reply",
            "8001",
            "--content-file",
            comment_body_path.to_str().unwrap(),
            "--content-format",
            "storage",
        ])
        .output()
        .unwrap();
    assert!(
        blog_inline_reply.status.success(),
        "blog inline comment reply failed: stdout={} stderr={}",
        String::from_utf8_lossy(&blog_inline_reply.stdout),
        String::from_utf8_lossy(&blog_inline_reply.stderr)
    );
    let blog_inline_reply_json: serde_json::Value =
        serde_json::from_slice(&blog_inline_reply.stdout).unwrap();
    assert_eq!(
        blog_inline_reply_json["result"]["comment"]["parentCommentId"],
        "8001"
    );

    let blog_inline_delete = Command::new(env!("CARGO_BIN_EXE_agent-access"))
        .args([
            "--url",
            &base_url,
            "--no-token",
            "confluence",
            "blog",
            "inline-comment",
            "delete",
            "8002",
        ])
        .output()
        .unwrap();
    assert!(
        blog_inline_delete.status.success(),
        "blog inline comment delete failed: stdout={} stderr={}",
        String::from_utf8_lossy(&blog_inline_delete.stdout),
        String::from_utf8_lossy(&blog_inline_delete.stderr)
    );
    let blog_inline_delete_json: serde_json::Value =
        serde_json::from_slice(&blog_inline_delete.stdout).unwrap();
    assert_eq!(blog_inline_delete_json["result"]["status"], "deleted");

    let page_draft_create = Command::new(env!("CARGO_BIN_EXE_agent-access"))
        .args([
            "--url",
            &base_url,
            "--no-token",
            "confluence",
            "page",
            "draft",
            "create",
            "--space",
            "ENG",
            "--title",
            "Draft Page",
            "--parent-url",
            "https://example.atlassian.net/wiki/spaces/ENG/pages/654321/Operations",
            "--content-file",
            storage_body_path.to_str().unwrap(),
            "--content-format",
            "storage",
        ])
        .output()
        .unwrap();
    assert!(
        page_draft_create.status.success(),
        "page draft create failed: stdout={} stderr={}",
        String::from_utf8_lossy(&page_draft_create.stdout),
        String::from_utf8_lossy(&page_draft_create.stderr)
    );
    let page_draft_create_json: serde_json::Value =
        serde_json::from_slice(&page_draft_create.stdout).unwrap();
    let page_draft_id = page_draft_create_json["result"]["pageId"]
        .as_str()
        .unwrap()
        .to_string();
    let page_draft_handle = page_draft_create_json["result"]["draftHandle"]
        .as_str()
        .unwrap()
        .to_string();
    assert!(page_draft_handle.starts_with("aab_confluence_draft_v2_"));
    assert_eq!(page_draft_create_json["result"]["status"], "draft");
    assert_eq!(page_draft_create_json["result"]["parentPageId"], "654321");

    let page_draft_view = Command::new(env!("CARGO_BIN_EXE_agent-access"))
        .args([
            "--url",
            &base_url,
            "--no-token",
            "confluence",
            "page",
            "draft",
            "view",
            &page_draft_id,
            "--draft-handle",
            &page_draft_handle,
            "--body-format",
            "storage",
        ])
        .output()
        .unwrap();
    assert!(
        page_draft_view.status.success(),
        "page draft view failed: stdout={} stderr={}",
        String::from_utf8_lossy(&page_draft_view.stdout),
        String::from_utf8_lossy(&page_draft_view.stderr)
    );
    let page_draft_view_json: serde_json::Value =
        serde_json::from_slice(&page_draft_view.stdout).unwrap();
    assert_eq!(
        page_draft_view_json["result"]["body"]["storage"]["value"],
        "<p>create secret body</p>"
    );

    let page_draft_attach = Command::new(env!("CARGO_BIN_EXE_agent-access"))
        .args([
            "--url",
            &base_url,
            "--no-token",
            "confluence",
            "page",
            "draft",
            "attach",
            &page_draft_id,
            "--draft-handle",
            &page_draft_handle,
            "--content-type",
            "text/plain",
            attachment_path.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        page_draft_attach.status.success(),
        "page draft attach failed: stdout={} stderr={}",
        String::from_utf8_lossy(&page_draft_attach.stdout),
        String::from_utf8_lossy(&page_draft_attach.stderr)
    );
    let page_draft_attach_json: serde_json::Value =
        serde_json::from_slice(&page_draft_attach.stdout).unwrap();
    let page_draft_attachment_id =
        page_draft_attach_json["result"]["attachments"][0]["attachmentId"]
            .as_str()
            .unwrap()
            .to_string();

    let page_draft_list = Command::new(env!("CARGO_BIN_EXE_agent-access"))
        .args([
            "--url",
            &base_url,
            "--no-token",
            "confluence",
            "page",
            "draft",
            "attachment",
            "list",
            &page_draft_id,
            "--draft-handle",
            &page_draft_handle,
        ])
        .output()
        .unwrap();
    assert!(
        page_draft_list.status.success(),
        "page draft attachment list failed: stdout={} stderr={}",
        String::from_utf8_lossy(&page_draft_list.stdout),
        String::from_utf8_lossy(&page_draft_list.stderr)
    );
    let page_draft_list_json: serde_json::Value =
        serde_json::from_slice(&page_draft_list.stdout).unwrap();
    assert_eq!(
        page_draft_list_json["result"]["attachments"][0]["attachmentId"],
        page_draft_attachment_id
    );

    let page_draft_download = Command::new(env!("CARGO_BIN_EXE_agent-access"))
        .args([
            "--url",
            &base_url,
            "--no-token",
            "confluence",
            "page",
            "draft",
            "attachment",
            "download",
            &page_draft_id,
            "--draft-handle",
            &page_draft_handle,
            "--attachment-id",
            &page_draft_attachment_id,
            "--output",
            page_draft_download_path.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        page_draft_download.status.success(),
        "page draft attachment download failed: stdout={} stderr={}",
        String::from_utf8_lossy(&page_draft_download.stdout),
        String::from_utf8_lossy(&page_draft_download.stderr)
    );
    assert_eq!(
        std::fs::read_to_string(&page_draft_download_path).unwrap(),
        "diagram secret bytes"
    );

    let page_draft_verify = Command::new(env!("CARGO_BIN_EXE_agent-access"))
        .args([
            "--url",
            &base_url,
            "--no-token",
            "confluence",
            "page",
            "draft",
            "verify",
            &page_draft_id,
            "--draft-handle",
            &page_draft_handle,
            "--expect-version",
            "1",
            "--expect-title",
            "Draft Page",
            "--expect-attachment-id",
            &page_draft_attachment_id,
        ])
        .output()
        .unwrap();
    assert!(
        page_draft_verify.status.success(),
        "page draft verify failed: stdout={} stderr={}",
        String::from_utf8_lossy(&page_draft_verify.stdout),
        String::from_utf8_lossy(&page_draft_verify.stderr)
    );

    let page_draft_update = Command::new(env!("CARGO_BIN_EXE_agent-access"))
        .args([
            "--url",
            &base_url,
            "--no-token",
            "confluence",
            "page",
            "draft",
            "update",
            &page_draft_id,
            "--draft-handle",
            &page_draft_handle,
            "--title",
            "Updated Draft Page",
            "--content-file",
            markdown_body_path.to_str().unwrap(),
            "--content-format",
            "markdown",
        ])
        .output()
        .unwrap();
    assert!(
        page_draft_update.status.success(),
        "page draft update failed: stdout={} stderr={}",
        String::from_utf8_lossy(&page_draft_update.stdout),
        String::from_utf8_lossy(&page_draft_update.stderr)
    );

    let page_draft_publish = Command::new(env!("CARGO_BIN_EXE_agent-access"))
        .args([
            "--url",
            &base_url,
            "--no-token",
            "confluence",
            "page",
            "draft",
            "publish",
            &page_draft_id,
            "--draft-handle",
            &page_draft_handle,
            "--body-format",
            "storage",
        ])
        .output()
        .unwrap();
    assert!(
        page_draft_publish.status.success(),
        "page draft publish failed: stdout={} stderr={}",
        String::from_utf8_lossy(&page_draft_publish.stdout),
        String::from_utf8_lossy(&page_draft_publish.stderr)
    );
    let page_draft_publish_json: serde_json::Value =
        serde_json::from_slice(&page_draft_publish.stdout).unwrap();
    assert_eq!(page_draft_publish_json["result"]["status"], "current");
    assert_eq!(
        page_draft_publish_json["result"]["publishedAttachmentIds"][0],
        page_draft_attachment_id
    );

    let staged_page_draft = Command::new(env!("CARGO_BIN_EXE_agent-access"))
        .args([
            "--url",
            &base_url,
            "--no-token",
            "confluence",
            "page",
            "draft",
            "stage",
            "123456",
            "--base-version",
            "8",
            "--content-file",
            update_body_path.to_str().unwrap(),
            "--content-format",
            "storage",
        ])
        .output()
        .unwrap();
    assert!(
        staged_page_draft.status.success(),
        "staged page draft failed: stdout={} stderr={}",
        String::from_utf8_lossy(&staged_page_draft.stdout),
        String::from_utf8_lossy(&staged_page_draft.stderr)
    );
    let staged_page_draft_json: serde_json::Value =
        serde_json::from_slice(&staged_page_draft.stdout).unwrap();
    let staged_page_draft_handle = staged_page_draft_json["result"]["draftHandle"]
        .as_str()
        .unwrap()
        .to_string();

    let staged_page_attach = Command::new(env!("CARGO_BIN_EXE_agent-access"))
        .args([
            "--url",
            &base_url,
            "--no-token",
            "confluence",
            "page",
            "draft",
            "attach",
            "123456",
            "--draft-handle",
            &staged_page_draft_handle,
            "--content-type",
            "text/plain",
            attachment_path.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(!staged_page_attach.status.success());
    let staged_page_attach_json: serde_json::Value =
        serde_json::from_slice(&staged_page_attach.stdout).unwrap();
    assert_eq!(
        staged_page_attach_json["reasonCode"],
        "service_action_denied"
    );

    let blog_draft_create = Command::new(env!("CARGO_BIN_EXE_agent-access"))
        .args([
            "--url",
            &base_url,
            "--no-token",
            "confluence",
            "blog",
            "draft",
            "create",
            "--space",
            "ENG",
            "--title",
            "Draft Blog",
            "--content",
            "normalized blog draft plain text sentinel d4107a",
            "--content-format",
            "plain_text",
        ])
        .output()
        .unwrap();
    assert!(
        blog_draft_create.status.success(),
        "blog draft create failed: stdout={} stderr={}",
        String::from_utf8_lossy(&blog_draft_create.stdout),
        String::from_utf8_lossy(&blog_draft_create.stderr)
    );
    let blog_draft_create_json: serde_json::Value =
        serde_json::from_slice(&blog_draft_create.stdout).unwrap();
    let blog_draft_id = blog_draft_create_json["result"]["blogId"]
        .as_str()
        .unwrap()
        .to_string();
    let blog_draft_handle = blog_draft_create_json["result"]["draftHandle"]
        .as_str()
        .unwrap()
        .to_string();

    let blog_draft_attach = Command::new(env!("CARGO_BIN_EXE_agent-access"))
        .args([
            "--url",
            &base_url,
            "--no-token",
            "confluence",
            "blog",
            "draft",
            "attach",
            &blog_draft_id,
            "--draft-handle",
            &blog_draft_handle,
            "--content-type",
            "text/plain",
            attachment_path.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        blog_draft_attach.status.success(),
        "blog draft attach failed: stdout={} stderr={}",
        String::from_utf8_lossy(&blog_draft_attach.stdout),
        String::from_utf8_lossy(&blog_draft_attach.stderr)
    );
    let blog_draft_attach_json: serde_json::Value =
        serde_json::from_slice(&blog_draft_attach.stdout).unwrap();
    let blog_draft_attachment_id =
        blog_draft_attach_json["result"]["attachments"][0]["attachmentId"]
            .as_str()
            .unwrap()
            .to_string();

    let blog_draft_list = Command::new(env!("CARGO_BIN_EXE_agent-access"))
        .args([
            "--url",
            &base_url,
            "--no-token",
            "confluence",
            "blog",
            "draft",
            "attachment",
            "list",
            &blog_draft_id,
            "--draft-handle",
            &blog_draft_handle,
        ])
        .output()
        .unwrap();
    assert!(
        blog_draft_list.status.success(),
        "blog draft attachment list failed: stdout={} stderr={}",
        String::from_utf8_lossy(&blog_draft_list.stdout),
        String::from_utf8_lossy(&blog_draft_list.stderr)
    );
    let blog_draft_list_json: serde_json::Value =
        serde_json::from_slice(&blog_draft_list.stdout).unwrap();
    assert_eq!(
        blog_draft_list_json["result"]["attachments"][0]["attachmentId"],
        blog_draft_attachment_id
    );

    let blog_draft_download = Command::new(env!("CARGO_BIN_EXE_agent-access"))
        .args([
            "--url",
            &base_url,
            "--no-token",
            "confluence",
            "blog",
            "draft",
            "attachment",
            "download",
            &blog_draft_id,
            "--draft-handle",
            &blog_draft_handle,
            "--attachment-id",
            &blog_draft_attachment_id,
            "--output",
            blog_draft_download_path.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        blog_draft_download.status.success(),
        "blog draft attachment download failed: stdout={} stderr={}",
        String::from_utf8_lossy(&blog_draft_download.stdout),
        String::from_utf8_lossy(&blog_draft_download.stderr)
    );
    assert_eq!(
        std::fs::read_to_string(&blog_draft_download_path).unwrap(),
        "diagram secret bytes"
    );

    let blog_draft_verify = Command::new(env!("CARGO_BIN_EXE_agent-access"))
        .args([
            "--url",
            &base_url,
            "--no-token",
            "confluence",
            "blog",
            "draft",
            "verify",
            &blog_draft_id,
            "--draft-handle",
            &blog_draft_handle,
            "--expect-version",
            "1",
            "--expect-title",
            "Draft Blog",
            "--expect-attachment-id",
            &blog_draft_attachment_id,
        ])
        .output()
        .unwrap();
    assert!(
        blog_draft_verify.status.success(),
        "blog draft verify failed: stdout={} stderr={}",
        String::from_utf8_lossy(&blog_draft_verify.stdout),
        String::from_utf8_lossy(&blog_draft_verify.stderr)
    );

    let blog_draft_update = Command::new(env!("CARGO_BIN_EXE_agent-access"))
        .args([
            "--url",
            &base_url,
            "--no-token",
            "confluence",
            "blog",
            "draft",
            "update",
            &blog_draft_id,
            "--draft-handle",
            &blog_draft_handle,
            "--title",
            "Updated Draft Blog",
            "--content-file",
            markdown_body_path.to_str().unwrap(),
            "--content-format",
            "markdown",
        ])
        .output()
        .unwrap();
    assert!(
        blog_draft_update.status.success(),
        "blog draft update failed: stdout={} stderr={}",
        String::from_utf8_lossy(&blog_draft_update.stdout),
        String::from_utf8_lossy(&blog_draft_update.stderr)
    );

    let staged_blog_draft = Command::new(env!("CARGO_BIN_EXE_agent-access"))
        .args([
            "--url",
            &base_url,
            "--no-token",
            "confluence",
            "blog",
            "draft",
            "stage",
            "222222",
            "--base-version",
            "5",
            "--content",
            "normalized blog stage plain text sentinel db824e",
            "--content-format",
            "plain_text",
        ])
        .output()
        .unwrap();
    assert!(
        staged_blog_draft.status.success(),
        "staged blog draft failed: stdout={} stderr={}",
        String::from_utf8_lossy(&staged_blog_draft.stdout),
        String::from_utf8_lossy(&staged_blog_draft.stderr)
    );

    let blog_draft_publish = Command::new(env!("CARGO_BIN_EXE_agent-access"))
        .args([
            "--url",
            &base_url,
            "--no-token",
            "confluence",
            "blog",
            "draft",
            "publish",
            &blog_draft_id,
            "--draft-handle",
            &blog_draft_handle,
            "--body-format",
            "storage",
        ])
        .output()
        .unwrap();
    assert!(
        blog_draft_publish.status.success(),
        "blog draft publish failed: stdout={} stderr={}",
        String::from_utf8_lossy(&blog_draft_publish.stdout),
        String::from_utf8_lossy(&blog_draft_publish.stderr)
    );
    let blog_draft_publish_json: serde_json::Value =
        serde_json::from_slice(&blog_draft_publish.stdout).unwrap();
    assert_eq!(blog_draft_publish_json["result"]["status"], "current");
    assert_eq!(
        blog_draft_publish_json["result"]["publishedAttachmentIds"][0],
        blog_draft_attachment_id
    );

    let audit = broker.audit().unwrap().text();
    assert!(audit.contains("\"action\":\"page.create\""));
    assert!(audit.contains("\"action\":\"page.move\""));
    assert!(audit.contains("\"action\":\"page.update\""));
    assert!(audit.contains("\"action\":\"page.draft.create\""));
    assert!(audit.contains("\"action\":\"page.draft.stage\""));
    assert!(audit.contains("\"action\":\"page.draft.view\""));
    assert!(audit.contains("\"action\":\"page.draft.update\""));
    assert!(audit.contains("\"action\":\"page.draft.publish\""));
    assert!(audit.contains("\"action\":\"page.draft.verify\""));
    assert!(audit.contains("\"action\":\"page.draft.attachment.add\""));
    assert!(audit.contains("\"action\":\"page.draft.attachment.list\""));
    assert!(audit.contains("\"action\":\"page.draft.attachment.download\""));
    assert!(audit.contains("\"action\":\"attachment.add\""));
    assert!(audit.contains("\"action\":\"attachment.list\""));
    assert!(audit.contains("\"action\":\"attachment.download\""));
    assert!(audit.contains("\"action\":\"page.footer_comment.list\""));
    assert!(audit.contains("\"action\":\"page.footer_comment.view\""));
    assert!(audit.contains("\"action\":\"page.footer_comment.add\""));
    assert!(audit.contains("\"action\":\"page.footer_comment.update\""));
    assert!(audit.contains("\"action\":\"page.footer_comment.reply.list\""));
    assert!(audit.contains("\"action\":\"page.footer_comment.reply.add\""));
    assert!(audit.contains("\"action\":\"page.inline_comment.list\""));
    assert!(audit.contains("\"action\":\"page.inline_comment.view\""));
    assert!(audit.contains("\"action\":\"page.inline_comment.update\""));
    assert!(audit.contains("\"action\":\"page.inline_comment.delete\""));
    assert!(audit.contains("\"action\":\"page.inline_comment.reply.list\""));
    assert!(audit.contains("\"action\":\"page.inline_comment.reply.add\""));
    assert!(audit.contains("\"action\":\"verify\""));
    assert!(audit.contains("\"action\":\"blog.create\""));
    assert!(audit.contains("\"action\":\"blog.update\""));
    assert!(audit.contains("\"action\":\"blog.draft.create\""));
    assert!(audit.contains("\"action\":\"blog.draft.stage\""));
    assert!(audit.contains("\"action\":\"blog.draft.update\""));
    assert!(audit.contains("\"action\":\"blog.draft.verify\""));
    assert!(audit.contains("\"action\":\"blog.draft.publish\""));
    assert!(audit.contains("\"action\":\"blog.draft.attachment.add\""));
    assert!(audit.contains("\"action\":\"blog.draft.attachment.list\""));
    assert!(audit.contains("\"action\":\"blog.draft.attachment.download\""));
    assert!(audit.contains("\"action\":\"blog.attachment.add\""));
    assert!(audit.contains("\"action\":\"blog.attachment.list\""));
    assert!(audit.contains("\"action\":\"blog.attachment.download\""));
    assert!(audit.contains("\"action\":\"blog.footer_comment.list\""));
    assert!(audit.contains("\"action\":\"blog.footer_comment.view\""));
    assert!(audit.contains("\"action\":\"blog.footer_comment.add\""));
    assert!(audit.contains("\"action\":\"blog.footer_comment.update\""));
    assert!(audit.contains("\"action\":\"blog.footer_comment.reply.list\""));
    assert!(audit.contains("\"action\":\"blog.footer_comment.reply.add\""));
    assert!(audit.contains("\"action\":\"blog.inline_comment.list\""));
    assert!(audit.contains("\"action\":\"blog.inline_comment.view\""));
    assert!(audit.contains("\"action\":\"blog.inline_comment.update\""));
    assert!(audit.contains("\"action\":\"blog.inline_comment.delete\""));
    assert!(audit.contains("\"action\":\"blog.inline_comment.reply.list\""));
    assert!(audit.contains("\"action\":\"blog.inline_comment.reply.add\""));
    assert!(audit.contains("\"action\":\"blog.verify\""));
    assert!(audit.contains("\"returnedUrlFields\":[\"webUrl\",\"spaceUrl\"]"));
    assert!(!audit.contains("https://example.atlassian.net/wiki/pages/viewpage.action"));
    assert!(!audit.contains("https://example.atlassian.net/wiki/spaces/ENG"));
    assert!(!audit.contains("create secret body"));
    assert!(!audit.contains("updated secret body"));
    assert!(!audit.contains("comment secret body"));
    assert!(!audit.contains("comment updated secret body"));
    assert!(!audit.contains("page footer comment"));
    assert!(!audit.contains("page footer reply"));
    assert!(!audit.contains("page inline comment"));
    assert!(!audit.contains("page inline reply"));
    assert!(!audit.contains("blog footer comment"));
    assert!(!audit.contains("blog footer reply"));
    assert!(!audit.contains("blog inline comment"));
    assert!(!audit.contains("blog inline reply"));
    assert!(!audit.contains("blog secret body"));
    assert!(!audit.contains("diagram secret bytes"));
    assert!(!audit.contains("aab_confluence_draft_v2_"));
    for sentinel in [
        "normalized markdown sentinel 6f74d1",
        "native atlas sentinel 29ca81",
        "normalized plain text sentinel 82bd40",
        "normalized blog plain text sentinel 470ac3",
        "normalized page inline",
        "normalized page inline update sentinel 23ee90",
        "normalized **blog inline update** sentinel af9105",
        "normalized blog draft plain text sentinel d4107a",
        "normalized blog stage plain text sentinel db824e",
    ] {
        assert!(!audit.contains(sentinel));
    }

    stop(broker).await;
}

#[test]
fn cli_confluence_content_sources_are_explicit_and_legacy_flags_are_rejected() {
    let content_path = temp_path("confluence-content-source-conflict.md");
    std::fs::write(&content_path, "file content").unwrap();

    let missing_format = Command::new(env!("CARGO_BIN_EXE_agent-access"))
        .args([
            "--url",
            "http://127.0.0.1:9",
            "--no-token",
            "confluence",
            "page",
            "update",
            "123456",
            "--base-version",
            "1",
            "--content",
            "content without a format",
        ])
        .output()
        .unwrap();
    assert_eq!(missing_format.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&missing_format.stderr).contains("required"));

    let format_without_content = Command::new(env!("CARGO_BIN_EXE_agent-access"))
        .args([
            "--url",
            "http://127.0.0.1:9",
            "--no-token",
            "confluence",
            "page",
            "update",
            "123456",
            "--base-version",
            "1",
            "--content-format",
            "markdown",
        ])
        .output()
        .unwrap();
    assert_eq!(format_without_content.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&format_without_content.stderr).contains("required"));

    let source_conflict = Command::new(env!("CARGO_BIN_EXE_agent-access"))
        .args([
            "--url",
            "http://127.0.0.1:9",
            "--no-token",
            "confluence",
            "blog",
            "create",
            "--space",
            "ENG",
            "--title",
            "conflict",
            "--content",
            "inline content",
            "--content-file",
            content_path.to_str().unwrap(),
            "--content-format",
            "markdown",
        ])
        .output()
        .unwrap();
    assert_eq!(source_conflict.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&source_conflict.stderr).contains("cannot be used with"));

    let malformed_atlas = Command::new(env!("CARGO_BIN_EXE_agent-access"))
        .args([
            "--url",
            "http://127.0.0.1:9",
            "--no-token",
            "confluence",
            "page",
            "create",
            "--space",
            "ENG",
            "--title",
            "malformed atlas",
            "--content",
            "{not-json",
            "--content-format",
            "atlas_doc_format",
        ])
        .output()
        .unwrap();
    assert_eq!(malformed_atlas.status.code(), Some(3));
    assert!(String::from_utf8_lossy(&malformed_atlas.stderr).contains("JSON"));

    for removed_flag in ["--body-file", "--body-format"] {
        let removed = Command::new(env!("CARGO_BIN_EXE_agent-access"))
            .args([
                "--url",
                "http://127.0.0.1:9",
                "--no-token",
                "confluence",
                "page",
                "update",
                "123456",
                "--base-version",
                "1",
                removed_flag,
                content_path.to_str().unwrap(),
            ])
            .output()
            .unwrap();
        assert!(
            !removed.status.success(),
            "removed flag {removed_flag} survived"
        );
        assert!(String::from_utf8_lossy(&removed.stderr).contains("unexpected argument"));
    }
}

struct StubConfluenceBackend {
    page: ConfluencePage,
    search_page: Mutex<Option<ConfluenceSearchPage>>,
    last_search: Mutex<Option<ConfluenceSearchRequest>>,
    metadata_calls: Mutex<u32>,
}

#[async_trait]
impl ConfluenceBackend for StubConfluenceBackend {
    async fn page_metadata(
        &self,
        page_id: &str,
        _credential: &agent_access_provider::ExecutionCredential,
    ) -> Result<ConfluenceBackendResponse<ConfluencePage>, ConfluenceBackendError> {
        *self.metadata_calls.lock().unwrap() += 1;
        if page_id != self.page.id {
            return Err(ConfluenceBackendError::NotFound);
        }
        Ok(ConfluenceBackendResponse {
            value: self.page.clone(),
            status: 200,
            duration_ms: 3,
        })
    }

    async fn page(
        &self,
        page_id: &str,
        _credential: &agent_access_provider::ExecutionCredential,
    ) -> Result<ConfluenceBackendResponse<ConfluencePage>, ConfluenceBackendError> {
        if page_id != self.page.id {
            return Err(ConfluenceBackendError::NotFound);
        }
        Ok(ConfluenceBackendResponse {
            value: self.page.clone(),
            status: 200,
            duration_ms: 4,
        })
    }

    async fn search(
        &self,
        request: ConfluenceSearchRequest,
        _credential: &agent_access_provider::ExecutionCredential,
    ) -> Result<ConfluenceBackendResponse<ConfluenceSearchPage>, ConfluenceBackendError> {
        *self.last_search.lock().unwrap() = Some(request);
        Ok(ConfluenceBackendResponse {
            value: self.search_page.lock().unwrap().take().unwrap(),
            status: 200,
            duration_ms: 5,
        })
    }

    async fn create_page(
        &self,
        _request: ConfluencePageCreateRequest,
        _credential: &agent_access_provider::ExecutionCredential,
    ) -> Result<ConfluenceBackendResponse<ConfluencePage>, ConfluenceBackendError> {
        Err(ConfluenceBackendError::Protocol(
            "read stub does not create pages".to_string(),
        ))
    }

    async fn update_page(
        &self,
        _request: ConfluencePageUpdateRequest,
        _credential: &agent_access_provider::ExecutionCredential,
    ) -> Result<ConfluenceBackendResponse<ConfluencePage>, ConfluenceBackendError> {
        Err(ConfluenceBackendError::Protocol(
            "read stub does not update pages".to_string(),
        ))
    }

    async fn add_attachment(
        &self,
        _page_id: &str,
        _attachment: ConfluenceAttachmentUpload,
        _credential: &agent_access_provider::ExecutionCredential,
    ) -> Result<ConfluenceBackendResponse<ConfluenceAttachment>, ConfluenceBackendError> {
        Err(ConfluenceBackendError::Protocol(
            "read stub does not add attachments".to_string(),
        ))
    }

    async fn page_attachments(
        &self,
        _page_id: &str,
        _credential: &agent_access_provider::ExecutionCredential,
    ) -> Result<ConfluenceBackendResponse<Vec<ConfluenceAttachment>>, ConfluenceBackendError> {
        Err(ConfluenceBackendError::Protocol(
            "read stub does not list attachments".to_string(),
        ))
    }

    async fn page_attachments_page(
        &self,
        _page_id: &str,
        _max_results: u32,
        _next_position: Option<&str>,
        _credential: &agent_access_provider::ExecutionCredential,
    ) -> Result<ConfluenceBackendResponse<ConfluenceAttachmentListPage>, ConfluenceBackendError>
    {
        Err(ConfluenceBackendError::Protocol(
            "read stub does not list attachments".to_string(),
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
            "read stub does not download attachments".to_string(),
        ))
    }
}

struct WriteStubConfluenceBackend {
    spaces: Mutex<BTreeMap<String, ConfluenceSpace>>,
    pages: Mutex<BTreeMap<String, ConfluencePage>>,
    page_parents: Mutex<BTreeMap<String, Option<String>>>,
    page_orders: Mutex<BTreeMap<String, Vec<String>>>,
    blogs: Mutex<BTreeMap<String, ConfluenceBlog>>,
    page_drafts: Mutex<BTreeMap<String, ConfluenceDraftContent>>,
    blog_drafts: Mutex<BTreeMap<String, ConfluenceDraftContent>>,
    attachments: Mutex<BTreeMap<String, Vec<ConfluenceAttachment>>>,
    blog_attachments: Mutex<BTreeMap<String, Vec<ConfluenceAttachment>>>,
    page_draft_attachments: Mutex<BTreeMap<String, Vec<ConfluenceAttachment>>>,
    blog_draft_attachments: Mutex<BTreeMap<String, Vec<ConfluenceAttachment>>>,
    attachment_content: Mutex<BTreeMap<String, ConfluenceAttachmentContent>>,
    blog_attachment_content: Mutex<BTreeMap<String, ConfluenceAttachmentContent>>,
    page_draft_attachment_content: Mutex<BTreeMap<String, ConfluenceAttachmentContent>>,
    blog_draft_attachment_content: Mutex<BTreeMap<String, ConfluenceAttachmentContent>>,
    comments: Mutex<BTreeMap<String, ConfluenceComment>>,
    next_page_id: Mutex<u64>,
    next_blog_id: Mutex<u64>,
    next_attachment_id: Mutex<u64>,
    next_comment_id: Mutex<u64>,
}

impl WriteStubConfluenceBackend {
    fn space_for_id(&self, space_id: &str) -> Result<ConfluenceSpace, ConfluenceBackendError> {
        self.spaces
            .lock()
            .unwrap()
            .get(space_id)
            .cloned()
            .ok_or(ConfluenceBackendError::NotFound)
    }

    fn draft_content(
        content_type: &str,
        id: String,
        title: String,
        space: &ConfluenceSpace,
        parent_page_id: Option<String>,
        status: &str,
        body: agent_access_confluence::ConfluencePageBody,
    ) -> ConfluenceDraftContent {
        ConfluenceDraftContent {
            id,
            title,
            content_type: content_type.to_string(),
            space: space.key.clone(),
            space_id: space.id.clone(),
            parent_page_id,
            web_url: None,
            space_web_url: None,
            status: Some(status.to_string()),
            version: 1,
            created_at: None,
            updated_at: None,
            created_by: None,
            updated_by: None,
            bodies: BTreeMap::from([(body.representation, body.value)]),
        }
    }
}

#[async_trait]
impl ConfluenceBackend for WriteStubConfluenceBackend {
    async fn page_metadata(
        &self,
        page_id: &str,
        _credential: &agent_access_provider::ExecutionCredential,
    ) -> Result<ConfluenceBackendResponse<ConfluencePage>, ConfluenceBackendError> {
        let page = self
            .pages
            .lock()
            .unwrap()
            .get(page_id)
            .cloned()
            .ok_or(ConfluenceBackendError::NotFound)?;
        Ok(ConfluenceBackendResponse {
            value: page,
            status: 200,
            duration_ms: 3,
        })
    }

    async fn page(
        &self,
        page_id: &str,
        credential: &agent_access_provider::ExecutionCredential,
    ) -> Result<ConfluenceBackendResponse<ConfluencePage>, ConfluenceBackendError> {
        self.page_metadata(page_id, credential).await
    }

    async fn page_hierarchy(
        &self,
        page_id: &str,
        get_draft: bool,
        _credential: &agent_access_provider::ExecutionCredential,
    ) -> Result<ConfluenceBackendResponse<ConfluencePageHierarchy>, ConfluenceBackendError> {
        let (space, status, version) = if get_draft {
            let drafts = self.page_drafts.lock().unwrap();
            let draft = drafts
                .get(page_id)
                .ok_or(ConfluenceBackendError::NotFound)?;
            (draft.space.clone(), "draft".to_string(), draft.version)
        } else {
            let pages = self.pages.lock().unwrap();
            let page = pages.get(page_id).ok_or(ConfluenceBackendError::NotFound)?;
            (
                page.space.clone(),
                page.status.clone().unwrap_or_else(|| "current".to_string()),
                page.version,
            )
        };
        let space_id = self
            .spaces
            .lock()
            .unwrap()
            .values()
            .find(|candidate| candidate.key == space)
            .map(|space| space.id.clone())
            .ok_or(ConfluenceBackendError::NotFound)?;
        let parent_page_id = self
            .page_parents
            .lock()
            .unwrap()
            .get(page_id)
            .cloned()
            .flatten();
        Ok(ConfluenceBackendResponse {
            value: ConfluencePageHierarchy {
                id: page_id.to_string(),
                space_id,
                parent_type: parent_page_id.as_ref().map(|_| "page".to_string()),
                parent_page_id,
                status,
                version,
            },
            status: 200,
            duration_ms: 2,
        })
    }

    async fn page_ancestors(
        &self,
        page_id: &str,
        _credential: &agent_access_provider::ExecutionCredential,
    ) -> Result<ConfluenceBackendResponse<Vec<ConfluencePageAncestor>>, ConfluenceBackendError>
    {
        if !self.pages.lock().unwrap().contains_key(page_id) {
            return Err(ConfluenceBackendError::NotFound);
        }
        let parents = self.page_parents.lock().unwrap();
        let mut ancestors = Vec::new();
        let mut cursor = parents.get(page_id).cloned().flatten();
        while let Some(parent_id) = cursor {
            if ancestors
                .iter()
                .any(|ancestor: &ConfluencePageAncestor| ancestor.id == parent_id)
            {
                return Err(ConfluenceBackendError::Protocol(
                    "page hierarchy contains a cycle".to_string(),
                ));
            }
            ancestors.push(ConfluencePageAncestor {
                id: parent_id.clone(),
                content_type: "page".to_string(),
            });
            cursor = parents.get(&parent_id).cloned().flatten();
        }
        Ok(ConfluenceBackendResponse {
            value: ancestors,
            status: 200,
            duration_ms: 2,
        })
    }

    async fn page_direct_children(
        &self,
        page_id: &str,
        _credential: &agent_access_provider::ExecutionCredential,
    ) -> Result<ConfluenceBackendResponse<Vec<ConfluencePageChild>>, ConfluenceBackendError> {
        if !self.pages.lock().unwrap().contains_key(page_id) {
            return Err(ConfluenceBackendError::NotFound);
        }
        let children = self
            .page_orders
            .lock()
            .unwrap()
            .get(page_id)
            .cloned()
            .unwrap_or_default()
            .into_iter()
            .enumerate()
            .map(|(position, id)| ConfluencePageChild {
                id,
                content_type: "page".to_string(),
                status: "current".to_string(),
                child_position: position as u64,
            })
            .collect();
        Ok(ConfluenceBackendResponse {
            value: children,
            status: 200,
            duration_ms: 2,
        })
    }

    async fn move_page(
        &self,
        page_id: &str,
        position: ConfluencePageMovePosition,
        target_page_id: &str,
        _credential: &agent_access_provider::ExecutionCredential,
    ) -> Result<ConfluenceBackendResponse<String>, ConfluenceBackendError> {
        let pages = self.pages.lock().unwrap();
        if !pages.contains_key(page_id) || !pages.contains_key(target_page_id) {
            return Err(ConfluenceBackendError::NotFound);
        }
        drop(pages);
        let parent_page_id = match position {
            ConfluencePageMovePosition::Append => target_page_id.to_string(),
            ConfluencePageMovePosition::Before | ConfluencePageMovePosition::After => self
                .page_parents
                .lock()
                .unwrap()
                .get(target_page_id)
                .cloned()
                .flatten()
                .ok_or(ConfluenceBackendError::NotFound)?,
        };
        let mut orders = self.page_orders.lock().unwrap();
        for siblings in orders.values_mut() {
            siblings.retain(|id| id != page_id);
        }
        let siblings = orders.entry(parent_page_id.clone()).or_default();
        match position {
            ConfluencePageMovePosition::Append => siblings.push(page_id.to_string()),
            ConfluencePageMovePosition::Before | ConfluencePageMovePosition::After => {
                let target_index = siblings
                    .iter()
                    .position(|id| id == target_page_id)
                    .ok_or(ConfluenceBackendError::NotFound)?;
                let insert_index = if position == ConfluencePageMovePosition::Before {
                    target_index
                } else {
                    target_index + 1
                };
                siblings.insert(insert_index, page_id.to_string());
            }
        }
        drop(orders);
        self.page_parents
            .lock()
            .unwrap()
            .insert(page_id.to_string(), Some(parent_page_id));
        Ok(ConfluenceBackendResponse {
            value: page_id.to_string(),
            status: 200,
            duration_ms: 3,
        })
    }

    async fn space_by_key(
        &self,
        space: &str,
        _credential: &agent_access_provider::ExecutionCredential,
    ) -> Result<ConfluenceBackendResponse<ConfluenceSpace>, ConfluenceBackendError> {
        let space = self
            .spaces
            .lock()
            .unwrap()
            .values()
            .find(|candidate| candidate.key == space)
            .cloned()
            .ok_or(ConfluenceBackendError::NotFound)?;
        Ok(ConfluenceBackendResponse {
            value: space,
            status: 200,
            duration_ms: 2,
        })
    }

    async fn space_by_id(
        &self,
        space_id: &str,
        _credential: &agent_access_provider::ExecutionCredential,
    ) -> Result<ConfluenceBackendResponse<ConfluenceSpace>, ConfluenceBackendError> {
        let space = self
            .spaces
            .lock()
            .unwrap()
            .get(space_id)
            .cloned()
            .ok_or(ConfluenceBackendError::NotFound)?;
        Ok(ConfluenceBackendResponse {
            value: space,
            status: 200,
            duration_ms: 2,
        })
    }

    async fn blog_metadata(
        &self,
        blog_id: &str,
        _credential: &agent_access_provider::ExecutionCredential,
    ) -> Result<ConfluenceBackendResponse<ConfluenceBlog>, ConfluenceBackendError> {
        let mut blog = self
            .blogs
            .lock()
            .unwrap()
            .get(blog_id)
            .cloned()
            .ok_or(ConfluenceBackendError::NotFound)?;
        blog.space.clear();
        Ok(ConfluenceBackendResponse {
            value: blog,
            status: 200,
            duration_ms: 3,
        })
    }

    async fn blog(
        &self,
        blog_id: &str,
        credential: &agent_access_provider::ExecutionCredential,
    ) -> Result<ConfluenceBackendResponse<ConfluenceBlog>, ConfluenceBackendError> {
        self.blog_metadata(blog_id, credential).await
    }

    async fn search(
        &self,
        _request: ConfluenceSearchRequest,
        _credential: &agent_access_provider::ExecutionCredential,
    ) -> Result<ConfluenceBackendResponse<ConfluenceSearchPage>, ConfluenceBackendError> {
        Ok(ConfluenceBackendResponse {
            value: ConfluenceSearchPage {
                pages: vec![],
                max_results: 0,
                next_page_token: None,
            },
            status: 200,
            duration_ms: 1,
        })
    }

    async fn search_blogs(
        &self,
        request: ConfluenceSearchRequest,
        _credential: &agent_access_provider::ExecutionCredential,
    ) -> Result<ConfluenceBackendResponse<ConfluenceSearchBlog>, ConfluenceBackendError> {
        let blogs = self
            .blogs
            .lock()
            .unwrap()
            .values()
            .map(|blog| agent_access_confluence::ConfluenceBlogSummary {
                id: blog.id.clone(),
                title: blog.title.clone(),
                space: blog.space.clone(),
                web_url: blog.web_url.clone(),
                space_web_url: blog.space_web_url.clone(),
                status: blog.status.clone(),
                version: blog.version,
                created_at: None,
                updated_at: None,
                created_by: None,
                updated_by: None,
            })
            .collect::<Vec<_>>();
        Ok(ConfluenceBackendResponse {
            value: ConfluenceSearchBlog {
                blogs,
                max_results: request.max_results,
                next_page_token: None,
            },
            status: 200,
            duration_ms: 4,
        })
    }

    async fn create_page(
        &self,
        request: ConfluencePageCreateRequest,
        _credential: &agent_access_provider::ExecutionCredential,
    ) -> Result<ConfluenceBackendResponse<ConfluencePage>, ConfluenceBackendError> {
        let space = self.space_for_id(&request.space_id)?;
        if space.key != request.space {
            return Err(ConfluenceBackendError::Protocol(
                "space id and key mismatch".to_string(),
            ));
        }
        let parent_page_id = request
            .parent_page_id
            .clone()
            .or_else(|| space.homepage_id.clone())
            .ok_or_else(|| {
                ConfluenceBackendError::Protocol("space homepage missing".to_string())
            })?;
        let mut next = self.next_page_id.lock().unwrap();
        let id = next.to_string();
        *next += 1;
        let page = ConfluencePage {
            id: id.clone(),
            title: request.title,
            space: request.space,
            web_url: None,
            space_web_url: None,
            status: Some("current".to_string()),
            version: 1,
            created_at: None,
            updated_at: None,
            created_by: None,
            updated_by: None,
            bodies: BTreeMap::from([(request.body.representation, request.body.value)]),
        };
        self.pages.lock().unwrap().insert(id, page.clone());
        self.page_parents
            .lock()
            .unwrap()
            .insert(page.id.clone(), Some(parent_page_id.clone()));
        self.page_orders
            .lock()
            .unwrap()
            .entry(parent_page_id)
            .or_default()
            .push(page.id.clone());
        Ok(ConfluenceBackendResponse {
            value: page,
            status: 200,
            duration_ms: 7,
        })
    }

    async fn update_page(
        &self,
        request: ConfluencePageUpdateRequest,
        _credential: &agent_access_provider::ExecutionCredential,
    ) -> Result<ConfluenceBackendResponse<ConfluencePage>, ConfluenceBackendError> {
        let mut pages = self.pages.lock().unwrap();
        let page = pages
            .get_mut(&request.page_id)
            .ok_or(ConfluenceBackendError::NotFound)?;
        if page.space != request.space {
            return Err(ConfluenceBackendError::Protocol(
                "space mismatch".to_string(),
            ));
        }
        if page.version != request.base_version {
            return Err(ConfluenceBackendError::Conflict);
        }
        page.title = request.title;
        page.version = request.base_version + 1;
        page.bodies
            .insert(request.body.representation, request.body.value);
        Ok(ConfluenceBackendResponse {
            value: page.clone(),
            status: 200,
            duration_ms: 8,
        })
    }

    async fn create_page_draft(
        &self,
        request: ConfluenceDraftCreateRequest,
        _credential: &agent_access_provider::ExecutionCredential,
    ) -> Result<ConfluenceBackendResponse<ConfluenceDraftContent>, ConfluenceBackendError> {
        let space = self.space_for_id(&request.space_id)?;
        let mut next = self.next_page_id.lock().unwrap();
        let id = next.to_string();
        *next += 1;
        let parent_page_id = request
            .parent_page_id
            .or_else(|| space.homepage_id.clone())
            .ok_or_else(|| {
                ConfluenceBackendError::Protocol("space homepage missing".to_string())
            })?;
        let draft = Self::draft_content(
            "page",
            id.clone(),
            request.title,
            &space,
            Some(parent_page_id.clone()),
            "draft",
            request.body,
        );
        self.page_parents
            .lock()
            .unwrap()
            .insert(id.clone(), Some(parent_page_id));
        self.page_drafts.lock().unwrap().insert(id, draft.clone());
        Ok(ConfluenceBackendResponse {
            value: draft,
            status: 200,
            duration_ms: 7,
        })
    }

    async fn draft_page(
        &self,
        page_id: &str,
        _body_format: Option<&str>,
        _credential: &agent_access_provider::ExecutionCredential,
    ) -> Result<ConfluenceBackendResponse<ConfluenceDraftContent>, ConfluenceBackendError> {
        let draft = self
            .page_drafts
            .lock()
            .unwrap()
            .get(page_id)
            .cloned()
            .ok_or(ConfluenceBackendError::NotFound)?;
        Ok(ConfluenceBackendResponse {
            value: draft,
            status: 200,
            duration_ms: 4,
        })
    }

    async fn update_page_draft(
        &self,
        request: ConfluenceDraftUpdateRequest,
        _credential: &agent_access_provider::ExecutionCredential,
    ) -> Result<ConfluenceBackendResponse<ConfluenceDraftContent>, ConfluenceBackendError> {
        let space = self.space_for_id(&request.space_id)?;
        if request.status == "draft" {
            if !self
                .page_drafts
                .lock()
                .unwrap()
                .contains_key(&request.content_id)
                && !self.pages.lock().unwrap().contains_key(&request.content_id)
            {
                return Err(ConfluenceBackendError::NotFound);
            }
            let draft = Self::draft_content(
                "page",
                request.content_id.clone(),
                request.title,
                &space,
                self.page_parents
                    .lock()
                    .unwrap()
                    .get(&request.content_id)
                    .cloned()
                    .flatten(),
                "draft",
                request.body,
            );
            self.page_drafts
                .lock()
                .unwrap()
                .insert(request.content_id, draft.clone());
            return Ok(ConfluenceBackendResponse {
                value: draft,
                status: 200,
                duration_ms: 8,
            });
        }
        if request.status == "current" {
            let draft = self
                .page_drafts
                .lock()
                .unwrap()
                .remove(&request.content_id)
                .ok_or(ConfluenceBackendError::NotFound)?;
            let page = ConfluencePage {
                id: draft.id.clone(),
                title: request.title.clone(),
                space: space.key.clone(),
                web_url: None,
                space_web_url: None,
                status: Some("current".to_string()),
                version: 1,
                created_at: None,
                updated_at: None,
                created_by: None,
                updated_by: None,
                bodies: BTreeMap::from([(
                    request.body.representation.clone(),
                    request.body.value.clone(),
                )]),
            };
            self.pages.lock().unwrap().insert(page.id.clone(), page);
            if let Some(attachments) = self
                .page_draft_attachments
                .lock()
                .unwrap()
                .remove(&request.content_id)
            {
                let attachment_ids = attachments
                    .iter()
                    .map(|attachment| attachment.id.clone())
                    .collect::<Vec<_>>();
                self.attachments
                    .lock()
                    .unwrap()
                    .entry(request.content_id.clone())
                    .or_default()
                    .extend(attachments);
                let mut draft_content = self.page_draft_attachment_content.lock().unwrap();
                let mut current_content = self.attachment_content.lock().unwrap();
                for attachment_id in attachment_ids {
                    if let Some(content) = draft_content.remove(&attachment_id) {
                        current_content.insert(attachment_id, content);
                    }
                }
            }
            let mut draft_content = Self::draft_content(
                "page",
                request.content_id,
                request.title,
                &space,
                draft.parent_page_id,
                "current",
                request.body,
            );
            draft_content.version = 1;
            return Ok(ConfluenceBackendResponse {
                value: draft_content,
                status: 200,
                duration_ms: 8,
            });
        }
        Err(ConfluenceBackendError::Protocol(
            "unsupported page draft status".to_string(),
        ))
    }

    async fn discard_page_draft(
        &self,
        page_id: &str,
        _credential: &agent_access_provider::ExecutionCredential,
    ) -> Result<ConfluenceBackendResponse<()>, ConfluenceBackendError> {
        self.page_drafts
            .lock()
            .unwrap()
            .remove(page_id)
            .ok_or(ConfluenceBackendError::NotFound)?;
        self.page_parents.lock().unwrap().remove(page_id);
        self.page_draft_attachments.lock().unwrap().remove(page_id);
        Ok(ConfluenceBackendResponse {
            value: (),
            status: 204,
            duration_ms: 5,
        })
    }

    async fn create_blog(
        &self,
        request: ConfluenceBlogCreateRequest,
        _credential: &agent_access_provider::ExecutionCredential,
    ) -> Result<ConfluenceBackendResponse<ConfluenceBlog>, ConfluenceBackendError> {
        let mut next = self.next_blog_id.lock().unwrap();
        let id = next.to_string();
        *next += 1;
        let blog = ConfluenceBlog {
            id: id.clone(),
            title: request.title,
            space: request.space,
            space_id: request.space_id,
            web_url: None,
            space_web_url: None,
            status: Some("current".to_string()),
            version: 1,
            created_at: None,
            updated_at: None,
            created_by: None,
            updated_by: None,
            bodies: BTreeMap::from([(request.body.representation, request.body.value)]),
        };
        self.blogs.lock().unwrap().insert(id, blog.clone());
        Ok(ConfluenceBackendResponse {
            value: blog,
            status: 200,
            duration_ms: 7,
        })
    }

    async fn update_blog(
        &self,
        request: ConfluenceBlogUpdateRequest,
        _credential: &agent_access_provider::ExecutionCredential,
    ) -> Result<ConfluenceBackendResponse<ConfluenceBlog>, ConfluenceBackendError> {
        let mut blogs = self.blogs.lock().unwrap();
        let blog = blogs
            .get_mut(&request.blog_id)
            .ok_or(ConfluenceBackendError::NotFound)?;
        if blog.version != request.base_version {
            return Err(ConfluenceBackendError::Conflict);
        }
        blog.title = request.title;
        blog.version = request.base_version + 1;
        blog.bodies
            .insert(request.body.representation, request.body.value);
        Ok(ConfluenceBackendResponse {
            value: blog.clone(),
            status: 200,
            duration_ms: 8,
        })
    }

    async fn create_blog_draft(
        &self,
        request: ConfluenceDraftCreateRequest,
        _credential: &agent_access_provider::ExecutionCredential,
    ) -> Result<ConfluenceBackendResponse<ConfluenceDraftContent>, ConfluenceBackendError> {
        let space = self.space_for_id(&request.space_id)?;
        let mut next = self.next_blog_id.lock().unwrap();
        let id = next.to_string();
        *next += 1;
        let draft = Self::draft_content(
            "blog",
            id.clone(),
            request.title,
            &space,
            None,
            "draft",
            request.body,
        );
        self.blog_drafts.lock().unwrap().insert(id, draft.clone());
        Ok(ConfluenceBackendResponse {
            value: draft,
            status: 200,
            duration_ms: 7,
        })
    }

    async fn draft_blog(
        &self,
        blog_id: &str,
        _body_format: Option<&str>,
        _credential: &agent_access_provider::ExecutionCredential,
    ) -> Result<ConfluenceBackendResponse<ConfluenceDraftContent>, ConfluenceBackendError> {
        let draft = self
            .blog_drafts
            .lock()
            .unwrap()
            .get(blog_id)
            .cloned()
            .ok_or(ConfluenceBackendError::NotFound)?;
        Ok(ConfluenceBackendResponse {
            value: draft,
            status: 200,
            duration_ms: 4,
        })
    }

    async fn update_blog_draft(
        &self,
        request: ConfluenceDraftUpdateRequest,
        _credential: &agent_access_provider::ExecutionCredential,
    ) -> Result<ConfluenceBackendResponse<ConfluenceDraftContent>, ConfluenceBackendError> {
        let space = self.space_for_id(&request.space_id)?;
        if request.status == "draft" {
            if !self
                .blog_drafts
                .lock()
                .unwrap()
                .contains_key(&request.content_id)
                && !self.blogs.lock().unwrap().contains_key(&request.content_id)
            {
                return Err(ConfluenceBackendError::NotFound);
            }
            let draft = Self::draft_content(
                "blog",
                request.content_id.clone(),
                request.title,
                &space,
                None,
                "draft",
                request.body,
            );
            self.blog_drafts
                .lock()
                .unwrap()
                .insert(request.content_id, draft.clone());
            return Ok(ConfluenceBackendResponse {
                value: draft,
                status: 200,
                duration_ms: 8,
            });
        }
        if request.status == "current" {
            let draft = self
                .blog_drafts
                .lock()
                .unwrap()
                .remove(&request.content_id)
                .ok_or(ConfluenceBackendError::NotFound)?;
            let blog = ConfluenceBlog {
                id: draft.id.clone(),
                title: request.title.clone(),
                space: space.key.clone(),
                space_id: space.id.clone(),
                web_url: None,
                space_web_url: None,
                status: Some("current".to_string()),
                version: 1,
                created_at: None,
                updated_at: None,
                created_by: None,
                updated_by: None,
                bodies: BTreeMap::from([(
                    request.body.representation.clone(),
                    request.body.value.clone(),
                )]),
            };
            self.blogs.lock().unwrap().insert(blog.id.clone(), blog);
            if let Some(attachments) = self
                .blog_draft_attachments
                .lock()
                .unwrap()
                .remove(&request.content_id)
            {
                let attachment_ids = attachments
                    .iter()
                    .map(|attachment| attachment.id.clone())
                    .collect::<Vec<_>>();
                self.blog_attachments
                    .lock()
                    .unwrap()
                    .entry(request.content_id.clone())
                    .or_default()
                    .extend(attachments);
                let mut draft_content = self.blog_draft_attachment_content.lock().unwrap();
                let mut current_content = self.blog_attachment_content.lock().unwrap();
                for attachment_id in attachment_ids {
                    if let Some(content) = draft_content.remove(&attachment_id) {
                        current_content.insert(attachment_id, content);
                    }
                }
            }
            let mut draft_content = Self::draft_content(
                "blog",
                request.content_id,
                request.title,
                &space,
                None,
                "current",
                request.body,
            );
            draft_content.version = 1;
            return Ok(ConfluenceBackendResponse {
                value: draft_content,
                status: 200,
                duration_ms: 8,
            });
        }
        Err(ConfluenceBackendError::Protocol(
            "unsupported blog draft status".to_string(),
        ))
    }

    async fn discard_blog_draft(
        &self,
        blog_id: &str,
        _credential: &agent_access_provider::ExecutionCredential,
    ) -> Result<ConfluenceBackendResponse<()>, ConfluenceBackendError> {
        self.blog_drafts
            .lock()
            .unwrap()
            .remove(blog_id)
            .ok_or(ConfluenceBackendError::NotFound)?;
        self.blog_draft_attachments.lock().unwrap().remove(blog_id);
        Ok(ConfluenceBackendResponse {
            value: (),
            status: 204,
            duration_ms: 5,
        })
    }

    async fn add_attachment(
        &self,
        page_id: &str,
        attachment: ConfluenceAttachmentUpload,
        _credential: &agent_access_provider::ExecutionCredential,
    ) -> Result<ConfluenceBackendResponse<ConfluenceAttachment>, ConfluenceBackendError> {
        if !self.pages.lock().unwrap().contains_key(page_id) {
            return Err(ConfluenceBackendError::NotFound);
        }
        let mut next = self.next_attachment_id.lock().unwrap();
        let id = format!("att{next}");
        *next += 1;
        let metadata = ConfluenceAttachment {
            id: id.clone(),
            page_id: page_id.to_string(),
            filename: attachment.filename.clone(),
            size: attachment.size,
            content_type: attachment.content_type.clone(),
        };
        self.attachments
            .lock()
            .unwrap()
            .entry(page_id.to_string())
            .or_default()
            .push(metadata.clone());
        let bytes = attachment.read_bytes().unwrap();
        self.attachment_content.lock().unwrap().insert(
            id,
            ConfluenceAttachmentContent::from_bytes(
                attachment.filename,
                attachment.content_type,
                bytes,
            ),
        );
        Ok(ConfluenceBackendResponse {
            value: metadata,
            status: 200,
            duration_ms: 9,
        })
    }

    async fn add_blog_attachment(
        &self,
        blog_id: &str,
        attachment: ConfluenceAttachmentUpload,
        _credential: &agent_access_provider::ExecutionCredential,
    ) -> Result<ConfluenceBackendResponse<ConfluenceAttachment>, ConfluenceBackendError> {
        if !self.blogs.lock().unwrap().contains_key(blog_id) {
            return Err(ConfluenceBackendError::NotFound);
        }
        let mut next = self.next_attachment_id.lock().unwrap();
        let id = format!("att{next}");
        *next += 1;
        let metadata = ConfluenceAttachment {
            id: id.clone(),
            page_id: blog_id.to_string(),
            filename: attachment.filename.clone(),
            size: attachment.size,
            content_type: attachment.content_type.clone(),
        };
        self.blog_attachments
            .lock()
            .unwrap()
            .entry(blog_id.to_string())
            .or_default()
            .push(metadata.clone());
        let bytes = attachment.read_bytes().unwrap();
        self.blog_attachment_content.lock().unwrap().insert(
            id,
            ConfluenceAttachmentContent::from_bytes(
                attachment.filename,
                attachment.content_type,
                bytes,
            ),
        );
        Ok(ConfluenceBackendResponse {
            value: metadata,
            status: 200,
            duration_ms: 9,
        })
    }

    async fn add_page_draft_attachment(
        &self,
        page_id: &str,
        attachment: ConfluenceAttachmentUpload,
        _credential: &agent_access_provider::ExecutionCredential,
    ) -> Result<ConfluenceBackendResponse<ConfluenceAttachment>, ConfluenceBackendError> {
        if !self.page_drafts.lock().unwrap().contains_key(page_id) {
            return Err(ConfluenceBackendError::NotFound);
        }
        let mut next = self.next_attachment_id.lock().unwrap();
        let id = format!("att{next}");
        *next += 1;
        let metadata = ConfluenceAttachment {
            id: id.clone(),
            page_id: page_id.to_string(),
            filename: attachment.filename.clone(),
            size: attachment.size,
            content_type: attachment.content_type.clone(),
        };
        self.page_draft_attachments
            .lock()
            .unwrap()
            .entry(page_id.to_string())
            .or_default()
            .push(metadata.clone());
        let bytes = attachment.read_bytes().unwrap();
        self.page_draft_attachment_content.lock().unwrap().insert(
            id,
            ConfluenceAttachmentContent::from_bytes(
                attachment.filename,
                attachment.content_type,
                bytes,
            ),
        );
        Ok(ConfluenceBackendResponse {
            value: metadata,
            status: 200,
            duration_ms: 9,
        })
    }

    async fn add_blog_draft_attachment(
        &self,
        blog_id: &str,
        attachment: ConfluenceAttachmentUpload,
        _credential: &agent_access_provider::ExecutionCredential,
    ) -> Result<ConfluenceBackendResponse<ConfluenceAttachment>, ConfluenceBackendError> {
        if !self.blog_drafts.lock().unwrap().contains_key(blog_id) {
            return Err(ConfluenceBackendError::NotFound);
        }
        let mut next = self.next_attachment_id.lock().unwrap();
        let id = format!("att{next}");
        *next += 1;
        let metadata = ConfluenceAttachment {
            id: id.clone(),
            page_id: blog_id.to_string(),
            filename: attachment.filename.clone(),
            size: attachment.size,
            content_type: attachment.content_type.clone(),
        };
        self.blog_draft_attachments
            .lock()
            .unwrap()
            .entry(blog_id.to_string())
            .or_default()
            .push(metadata.clone());
        let bytes = attachment.read_bytes().unwrap();
        self.blog_draft_attachment_content.lock().unwrap().insert(
            id,
            ConfluenceAttachmentContent::from_bytes(
                attachment.filename,
                attachment.content_type,
                bytes,
            ),
        );
        Ok(ConfluenceBackendResponse {
            value: metadata,
            status: 200,
            duration_ms: 9,
        })
    }

    async fn page_attachments(
        &self,
        page_id: &str,
        _credential: &agent_access_provider::ExecutionCredential,
    ) -> Result<ConfluenceBackendResponse<Vec<ConfluenceAttachment>>, ConfluenceBackendError> {
        if !self.pages.lock().unwrap().contains_key(page_id) {
            return Err(ConfluenceBackendError::NotFound);
        }
        Ok(ConfluenceBackendResponse {
            value: self
                .attachments
                .lock()
                .unwrap()
                .get(page_id)
                .cloned()
                .unwrap_or_default(),
            status: 200,
            duration_ms: 5,
        })
    }

    async fn page_attachments_page(
        &self,
        page_id: &str,
        max_results: u32,
        next_position: Option<&str>,
        _credential: &agent_access_provider::ExecutionCredential,
    ) -> Result<ConfluenceBackendResponse<ConfluenceAttachmentListPage>, ConfluenceBackendError>
    {
        if !self.pages.lock().unwrap().contains_key(page_id) {
            return Err(ConfluenceBackendError::NotFound);
        }
        let start = next_position
            .and_then(|position| position.strip_prefix("start="))
            .and_then(|value| value.parse::<usize>().ok())
            .unwrap_or(0);
        let attachments = self
            .attachments
            .lock()
            .unwrap()
            .get(page_id)
            .cloned()
            .unwrap_or_default();
        let max_results = max_results as usize;
        let page = attachments
            .iter()
            .skip(start)
            .take(max_results)
            .cloned()
            .collect::<Vec<_>>();
        let next_start = start + page.len();
        let next_position = (next_start < attachments.len()).then(|| format!("start={next_start}"));
        Ok(ConfluenceBackendResponse {
            value: ConfluenceAttachmentListPage {
                attachments: page,
                next_position,
            },
            status: 200,
            duration_ms: 5,
        })
    }

    async fn blog_attachments_page(
        &self,
        blog_id: &str,
        max_results: u32,
        next_position: Option<&str>,
        _credential: &agent_access_provider::ExecutionCredential,
    ) -> Result<ConfluenceBackendResponse<ConfluenceAttachmentListPage>, ConfluenceBackendError>
    {
        if !self.blogs.lock().unwrap().contains_key(blog_id) {
            return Err(ConfluenceBackendError::NotFound);
        }
        let start = next_position
            .and_then(|position| position.strip_prefix("start="))
            .and_then(|value| value.parse::<usize>().ok())
            .unwrap_or(0);
        let attachments = self
            .blog_attachments
            .lock()
            .unwrap()
            .get(blog_id)
            .cloned()
            .unwrap_or_default();
        let max_results = max_results as usize;
        let page = attachments
            .iter()
            .skip(start)
            .take(max_results)
            .cloned()
            .collect::<Vec<_>>();
        let next_start = start + page.len();
        let next_position = (next_start < attachments.len()).then(|| format!("start={next_start}"));
        Ok(ConfluenceBackendResponse {
            value: ConfluenceAttachmentListPage {
                attachments: page,
                next_position,
            },
            status: 200,
            duration_ms: 5,
        })
    }

    async fn page_draft_attachments_page(
        &self,
        page_id: &str,
        max_results: u32,
        next_position: Option<&str>,
        _credential: &agent_access_provider::ExecutionCredential,
    ) -> Result<ConfluenceBackendResponse<ConfluenceAttachmentListPage>, ConfluenceBackendError>
    {
        if !self.page_drafts.lock().unwrap().contains_key(page_id) {
            return Err(ConfluenceBackendError::NotFound);
        }
        let start = next_position
            .and_then(|position| position.strip_prefix("start="))
            .and_then(|value| value.parse::<usize>().ok())
            .unwrap_or(0);
        let attachments = self
            .page_draft_attachments
            .lock()
            .unwrap()
            .get(page_id)
            .cloned()
            .unwrap_or_default();
        let max_results = max_results as usize;
        let page = attachments
            .iter()
            .skip(start)
            .take(max_results)
            .cloned()
            .collect::<Vec<_>>();
        let next_start = start + page.len();
        let next_position = (next_start < attachments.len()).then(|| format!("start={next_start}"));
        Ok(ConfluenceBackendResponse {
            value: ConfluenceAttachmentListPage {
                attachments: page,
                next_position,
            },
            status: 200,
            duration_ms: 5,
        })
    }

    async fn blog_draft_attachments_page(
        &self,
        blog_id: &str,
        max_results: u32,
        next_position: Option<&str>,
        _credential: &agent_access_provider::ExecutionCredential,
    ) -> Result<ConfluenceBackendResponse<ConfluenceAttachmentListPage>, ConfluenceBackendError>
    {
        if !self.blog_drafts.lock().unwrap().contains_key(blog_id) {
            return Err(ConfluenceBackendError::NotFound);
        }
        let start = next_position
            .and_then(|position| position.strip_prefix("start="))
            .and_then(|value| value.parse::<usize>().ok())
            .unwrap_or(0);
        let attachments = self
            .blog_draft_attachments
            .lock()
            .unwrap()
            .get(blog_id)
            .cloned()
            .unwrap_or_default();
        let max_results = max_results as usize;
        let page = attachments
            .iter()
            .skip(start)
            .take(max_results)
            .cloned()
            .collect::<Vec<_>>();
        let next_start = start + page.len();
        let next_position = (next_start < attachments.len()).then(|| format!("start={next_start}"));
        Ok(ConfluenceBackendResponse {
            value: ConfluenceAttachmentListPage {
                attachments: page,
                next_position,
            },
            status: 200,
            duration_ms: 5,
        })
    }

    async fn blog_attachments(
        &self,
        blog_id: &str,
        _credential: &agent_access_provider::ExecutionCredential,
    ) -> Result<ConfluenceBackendResponse<Vec<ConfluenceAttachment>>, ConfluenceBackendError> {
        if !self.blogs.lock().unwrap().contains_key(blog_id) {
            return Err(ConfluenceBackendError::NotFound);
        }
        Ok(ConfluenceBackendResponse {
            value: self
                .blog_attachments
                .lock()
                .unwrap()
                .get(blog_id)
                .cloned()
                .unwrap_or_default(),
            status: 200,
            duration_ms: 5,
        })
    }

    async fn attachment_content(
        &self,
        _page_id: &str,
        attachment_id: &str,
        _credential: &agent_access_provider::ExecutionCredential,
    ) -> Result<ConfluenceBackendResponse<ConfluenceAttachmentContent>, ConfluenceBackendError>
    {
        let content = self
            .attachment_content
            .lock()
            .unwrap()
            .get(attachment_id)
            .cloned()
            .ok_or(ConfluenceBackendError::NotFound)?;
        Ok(ConfluenceBackendResponse {
            value: content,
            status: 200,
            duration_ms: 6,
        })
    }

    async fn blog_attachment_content(
        &self,
        _blog_id: &str,
        attachment_id: &str,
        _credential: &agent_access_provider::ExecutionCredential,
    ) -> Result<ConfluenceBackendResponse<ConfluenceAttachmentContent>, ConfluenceBackendError>
    {
        let content = self
            .blog_attachment_content
            .lock()
            .unwrap()
            .get(attachment_id)
            .cloned()
            .ok_or(ConfluenceBackendError::NotFound)?;
        Ok(ConfluenceBackendResponse {
            value: content,
            status: 200,
            duration_ms: 6,
        })
    }

    async fn page_draft_attachment_content(
        &self,
        _page_id: &str,
        attachment_id: &str,
        _credential: &agent_access_provider::ExecutionCredential,
    ) -> Result<ConfluenceBackendResponse<ConfluenceAttachmentContent>, ConfluenceBackendError>
    {
        let content = self
            .page_draft_attachment_content
            .lock()
            .unwrap()
            .get(attachment_id)
            .cloned()
            .ok_or(ConfluenceBackendError::NotFound)?;
        Ok(ConfluenceBackendResponse {
            value: content,
            status: 200,
            duration_ms: 6,
        })
    }

    async fn blog_draft_attachment_content(
        &self,
        _blog_id: &str,
        attachment_id: &str,
        _credential: &agent_access_provider::ExecutionCredential,
    ) -> Result<ConfluenceBackendResponse<ConfluenceAttachmentContent>, ConfluenceBackendError>
    {
        let content = self
            .blog_draft_attachment_content
            .lock()
            .unwrap()
            .get(attachment_id)
            .cloned()
            .ok_or(ConfluenceBackendError::NotFound)?;
        Ok(ConfluenceBackendResponse {
            value: content,
            status: 200,
            duration_ms: 6,
        })
    }

    async fn comment(
        &self,
        kind: ConfluenceCommentKind,
        comment_id: &str,
        _body_format: Option<&str>,
        _credential: &agent_access_provider::ExecutionCredential,
    ) -> Result<ConfluenceBackendResponse<ConfluenceComment>, ConfluenceBackendError> {
        let comment = self
            .comments
            .lock()
            .unwrap()
            .get(comment_id)
            .cloned()
            .ok_or(ConfluenceBackendError::NotFound)?;
        if comment.kind != kind {
            return Err(ConfluenceBackendError::NotFound);
        }
        Ok(ConfluenceBackendResponse {
            value: comment,
            status: 200,
            duration_ms: 4,
        })
    }

    async fn comments_page(
        &self,
        request: ConfluenceCommentListRequest,
        _credential: &agent_access_provider::ExecutionCredential,
    ) -> Result<ConfluenceBackendResponse<ConfluenceCommentListPage>, ConfluenceBackendError> {
        let comments = self
            .comments
            .lock()
            .unwrap()
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
            .collect::<Vec<_>>();
        Ok(ConfluenceBackendResponse {
            value: ConfluenceCommentListPage {
                comments,
                next_cursor: None,
            },
            status: 200,
            duration_ms: 5,
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
        let comments = self
            .comments
            .lock()
            .unwrap()
            .values()
            .filter(|comment| {
                comment.kind == kind && comment.parent_comment_id.as_deref() == Some(comment_id)
            })
            .take(max_results as usize)
            .cloned()
            .collect::<Vec<_>>();
        Ok(ConfluenceBackendResponse {
            value: ConfluenceCommentListPage {
                comments,
                next_cursor: None,
            },
            status: 200,
            duration_ms: 5,
        })
    }

    async fn add_comment(
        &self,
        request: ConfluenceCommentCreateRequest,
        _credential: &agent_access_provider::ExecutionCredential,
    ) -> Result<ConfluenceBackendResponse<ConfluenceComment>, ConfluenceBackendError> {
        if let Some(page_id) = request.page_id.as_deref()
            && !self.pages.lock().unwrap().contains_key(page_id)
        {
            return Err(ConfluenceBackendError::NotFound);
        }
        if let Some(blog_id) = request.blog_id.as_deref()
            && !self.blogs.lock().unwrap().contains_key(blog_id)
        {
            return Err(ConfluenceBackendError::NotFound);
        }
        if let Some(parent_comment_id) = request.parent_comment_id.as_deref()
            && !self
                .comments
                .lock()
                .unwrap()
                .contains_key(parent_comment_id)
        {
            return Err(ConfluenceBackendError::NotFound);
        }
        let mut next = self.next_comment_id.lock().unwrap();
        let id = next.to_string();
        *next += 1;
        let comment = ConfluenceComment {
            id: id.clone(),
            kind: request.kind,
            page_id: request.page_id,
            blog_id: request.blog_id,
            parent_comment_id: request.parent_comment_id,
            status: Some("current".to_string()),
            resolution_status: (request.kind == ConfluenceCommentKind::Inline)
                .then(|| "open".to_string()),
            version: Some(1),
            author: None,
            created_at: None,
            updated_at: None,
            bodies: BTreeMap::from([(request.body.representation, request.body.value)]),
        };
        self.comments.lock().unwrap().insert(id, comment.clone());
        Ok(ConfluenceBackendResponse {
            value: comment,
            status: 200,
            duration_ms: 6,
        })
    }

    async fn update_comment(
        &self,
        request: ConfluenceCommentUpdateRequest,
        _credential: &agent_access_provider::ExecutionCredential,
    ) -> Result<ConfluenceBackendResponse<ConfluenceComment>, ConfluenceBackendError> {
        let mut comments = self.comments.lock().unwrap();
        let comment = comments
            .get_mut(&request.comment_id)
            .ok_or(ConfluenceBackendError::NotFound)?;
        if comment.kind != request.kind {
            return Err(ConfluenceBackendError::NotFound);
        }
        if comment.version != Some(request.base_version) {
            return Err(ConfluenceBackendError::Conflict);
        }
        comment.version = Some(request.base_version + 1);
        comment.updated_at = Some("2026-01-01T00:00:00Z".to_string());
        comment
            .bodies
            .insert(request.body.representation, request.body.value);
        Ok(ConfluenceBackendResponse {
            value: comment.clone(),
            status: 200,
            duration_ms: 6,
        })
    }

    async fn delete_comment(
        &self,
        kind: ConfluenceCommentKind,
        comment_id: &str,
        _credential: &agent_access_provider::ExecutionCredential,
    ) -> Result<ConfluenceBackendResponse<()>, ConfluenceBackendError> {
        let mut comments = self.comments.lock().unwrap();
        let comment = comments
            .get(comment_id)
            .ok_or(ConfluenceBackendError::NotFound)?;
        if comment.kind != kind {
            return Err(ConfluenceBackendError::NotFound);
        }
        comments.remove(comment_id);
        Ok(ConfluenceBackendResponse {
            value: (),
            status: 204,
            duration_ms: 5,
        })
    }
}

/// Starts the broker assembly on the Confluence configuration whose grant
/// allows `actions`, serving the Confluence provider around `backend` in
/// place of the one its configuration would build.
async fn start_broker<B>(actions: &[&str], backend: Arc<B>) -> RunningBroker
where
    B: ConfluenceBackend + 'static,
{
    let application = IsolatedBroker::new(
        agent_access_broker::composition().unwrap(),
        agent_access_broker::build_identity(),
    )
    .unwrap();
    let document = confluence_document(application.directory(), actions);
    application
        .config_document(document)
        .provider_fixture("confluence", confluence_fixture(backend))
        .start()
        .await
        .unwrap()
}

async fn stop(broker: RunningBroker) {
    broker.shutdown();
    broker.join().await.unwrap();
}

/// A TOML basic string holding `value`.
fn toml_string(value: impl std::fmt::Display) -> String {
    serde_json::to_string(&value.to_string()).unwrap()
}

/// A `file:` secret reference to a new private file in `directory`.
fn secret_ref(directory: &FixtureDir, name: &str, contents: &str) -> String {
    let path = directory.secret_file(name, contents).unwrap();
    toml_string(format_args!("file:{}", path.display()))
}

/// Every Confluence action the smokes call.
const CONFLUENCE_ACTIONS: &[&str] = &[
    "page.view",
    "search",
    "page.create",
    "page.move",
    "page.update",
    "page.draft.create",
    "page.draft.stage",
    "page.draft.view",
    "page.draft.update",
    "page.draft.publish",
    "page.draft.discard",
    "page.draft.verify",
    "page.draft.attachment.add",
    "page.draft.attachment.download",
    "page.draft.attachment.list",
    "attachment.add",
    "attachment.download",
    "attachment.list",
    "page.footer_comment.list",
    "page.footer_comment.view",
    "page.footer_comment.add",
    "page.footer_comment.update",
    "page.footer_comment.delete",
    "page.footer_comment.reply.list",
    "page.footer_comment.reply.add",
    "page.inline_comment.list",
    "page.inline_comment.view",
    "page.inline_comment.update",
    "page.inline_comment.delete",
    "page.inline_comment.reply.list",
    "page.inline_comment.reply.add",
    "verify",
    "blog.view",
    "blog.search",
    "blog.create",
    "blog.update",
    "blog.draft.create",
    "blog.draft.stage",
    "blog.draft.view",
    "blog.draft.update",
    "blog.draft.publish",
    "blog.draft.discard",
    "blog.draft.verify",
    "blog.draft.attachment.add",
    "blog.draft.attachment.download",
    "blog.draft.attachment.list",
    "blog.attachment.add",
    "blog.attachment.download",
    "blog.attachment.list",
    "blog.footer_comment.list",
    "blog.footer_comment.view",
    "blog.footer_comment.add",
    "blog.footer_comment.update",
    "blog.footer_comment.delete",
    "blog.footer_comment.reply.list",
    "blog.footer_comment.reply.add",
    "blog.inline_comment.list",
    "blog.inline_comment.view",
    "blog.inline_comment.update",
    "blog.inline_comment.delete",
    "blog.inline_comment.reply.list",
    "blog.inline_comment.reply.add",
    "blog.verify",
];

/// Anonymous callers; the Confluence provider (`confluence_provider_config(2)`)
/// with its service and read-only lookup credentials; the broker token hash
/// key, which signs its cursors and draft handles; the ENG space resource
/// with an anonymous service-credential grant of `actions` on it; and JSONL
/// audit in `audit.jsonl`.
fn confluence_document(directory: &FixtureDir, actions: &[&str]) -> String {
    format!(
        r#"
[identity]
mode = "anonymous"
authority = "toml"

[credentials.service.confluence]
type = "basic_api_token"
username_ref = {service_username}
token_ref = {service_token}

[credentials.lookup.confluence]
type = "basic_api_token"
username_ref = {lookup_username}
token_ref = {lookup_token}
read_only = true

[broker_tokens]
hash_key_ref = {hash_key}

[providers.confluence]
tenant_host = "example.atlassian.net"
allowed_upstream_hosts = ["https://example.atlassian.net/wiki/rest/api/**"]
attachments = {{ media_types = ["text/plain"] }}
content = {{ page_formats = ["storage", "atlas_doc_format"] }}
search = {{ max_results = 2 }}

[policy]
authority = "toml"
default_decision = "deny"

[[policy.resources]]
id = "space-eng"
resource_type = "{resource_type}"
selector = {{ kind = "exact", value = "ENG" }}
allowed_execution_contexts = ["default"]

[[policy.grants]]
subjects = ["group:anonymous"]
service = "confluence"
actions = {actions}
resources = {{ resource_ids = ["space-eng"] }}
credential_mode = "service"

[limits]
upload_spool_dir = {spool}

[audit]
type = "jsonl"
path = {audit}
"#,
        service_username = secret_ref(directory, "confluence-username.txt", "service@example.com"),
        service_token = secret_ref(directory, "confluence-token.txt", "confluence-token"),
        lookup_username = secret_ref(
            directory,
            "confluence-lookup-username.txt",
            "lookup@example.com"
        ),
        lookup_token = secret_ref(
            directory,
            "confluence-lookup-token.txt",
            "confluence-lookup-token"
        ),
        hash_key = secret_ref(
            directory,
            "confluence-broker-token-hash-key.txt",
            &base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([9_u8; 32]),
        ),
        resource_type = CONFLUENCE_SPACE_RESOURCE.id().as_str(),
        actions = serde_json::to_string(actions).unwrap(),
        spool = toml_string(directory.join("upload-spool").display()),
        audit = toml_string(directory.join("audit.jsonl").display()),
    )
}

fn confluence_provider_config(max_results: u32) -> ConfluenceProviderConfig {
    ConfluenceProviderConfig {
        tenant_host: "example.atlassian.net".to_string(),
        cloud_id: None,
        egress_proxy: None,
        allowed_upstream_hosts: vec!["https://example.atlassian.net/wiki/rest/api/**".to_string()],
        attachments: agent_access_provider::AttachmentLimitsConfig {
            media_types: vec!["text/plain".to_string()],
            ..agent_access_provider::AttachmentLimitsConfig::default()
        },
        content: agent_access_confluence::ConfluenceContentConfig {
            page_formats: vec!["storage".to_string(), "atlas_doc_format".to_string()],
            ..agent_access_confluence::ConfluenceContentConfig::default()
        },
        search: SearchLimitsConfig { max_results },
    }
}

fn confluence_comment(
    id: &str,
    kind: ConfluenceCommentKind,
    page_id: Option<&str>,
    blog_id: Option<&str>,
    parent_comment_id: Option<&str>,
    body: &str,
) -> ConfluenceComment {
    ConfluenceComment {
        id: id.to_string(),
        kind,
        page_id: page_id.map(ToString::to_string),
        blog_id: blog_id.map(ToString::to_string),
        parent_comment_id: parent_comment_id.map(ToString::to_string),
        status: Some("current".to_string()),
        resolution_status: (kind == ConfluenceCommentKind::Inline).then(|| "open".to_string()),
        version: Some(1),
        author: None,
        created_at: None,
        updated_at: None,
        bodies: BTreeMap::from([("storage".to_string(), body.to_string())]),
    }
}

fn temp_path(name: &str) -> std::path::PathBuf {
    let mut dir = std::env::temp_dir();
    dir.push(format!("agent-access-confluence-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&dir).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    dir.join(name)
}

#[path = "confluence_smoke/normalized_reads.rs"]
mod confluence_normalized_reads;
