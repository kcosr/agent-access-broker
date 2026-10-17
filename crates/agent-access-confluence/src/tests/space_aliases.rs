//! Spaces whose URL alias differs from their key: Confluence Cloud lets an
//! administrator change a space's URL while the API keeps the key. Here the
//! space `RAILS` is served under `/spaces/VLABS`.
use super::*;

const PAGE_ID: &str = "44867030046";
const BLOG_ID: &str = "44867030100";
const SPACE_ID: &str = "98765";
const ALIASED_PAGE_LINK: &str = "/spaces/VLABS/pages/44867030046/Deployed+RAILS+Models";
const ALIASED_BLOG_LINK: &str = "/spaces/VLABS/blog/2026/10/01/44867030100/Release+notes";
const SITE: &str = "https://example.atlassian.net/wiki";

/// The v1 content shape `content/search` and `content/{id}` return with
/// `expand=space,version,history`.
fn v1_content(kind: &str, id: &str, title: &str, link: &str, space: (&str, &str)) -> Value {
    json!({
        "id": id,
        "type": kind,
        "status": "current",
        "title": title,
        "space": { "key": space.0, "_links": { "webui": space.1 } },
        "version": { "number": 3 },
        "body": { "storage": { "value": "<p>body</p>" } },
        "_links": { "webui": link }
    })
}

fn rails_page(link: &str) -> Value {
    v1_content(
        "page",
        PAGE_ID,
        "Deployed RAILS Models",
        link,
        ("RAILS", "/spaces/VLABS"),
    )
}

fn alias_invocation(action: &str, inputs: Value) -> ProviderInvocation {
    let search = matches!(action, "search" | "blog.search");
    let mut resource_scopes = ResourceScopes::new();
    if !search {
        resource_scopes.insert("space".to_string(), vec!["RAILS".to_string()]);
    }
    let builder = InvocationBuilder::new("confluence", action)
        .inputs(inputs)
        .resources(resource_scopes)
        .credential(credential())
        .lookup_credential(credential());
    if search {
        builder.search(confluence_search_preflight(["ENG", "RAILS"]))
    } else {
        builder
    }
    .build()
}

fn alias_provider(server: &MockServer) -> ConfluenceProvider {
    let mut config = confluence_config();
    config.search.max_results = 10;
    ConfluenceProvider::with_backend(
        config,
        ProviderLimits::default(),
        Arc::new(http_confluence_backend_for_server(server)),
    )
}

fn lookup() -> AtlassianCredential {
    AtlassianCredential::from_static(credential())
}

async fn mount_json(server: &MockServer, route: String, body: Value) {
    Mock::given(method("GET"))
        .and(path(route))
        .respond_with(ResponseTemplate::new(200).set_body_json(body))
        .mount(server)
        .await;
}

#[test]
fn space_url_names_take_the_reported_alias_or_the_space_link() {
    let config = confluence_config();
    let alias = |reported: Option<&str>, link: Option<&str>| {
        ConfluenceSpaceUrlNames::new("RAILS", reported, link, &config).alias
    };
    for link in [
        "/spaces/VLABS",
        "/spaces/VLABS/overview",
        "/wiki/spaces/VLABS",
        "spaces/VLABS",
        "https://example.atlassian.net/wiki/spaces/VLABS",
    ] {
        assert_eq!(alias(None, Some(link)).as_deref(), Some("VLABS"), "{link}");
    }
    // A lowercase alias is well formed; it stays case-exact.
    assert_eq!(alias(None, Some("/spaces/vlabs")).as_deref(), Some("vlabs"));
    for link in [
        "/spaces/RAILS",
        "/spaces/VLABS/pages/44867030046/Title",
        "/spaces/VLABS/home",
        "/spaces/VLABS?x=1",
        "/spaces/VLABS#top",
        "/spaces/~VLABS",
        "/spaces/V%20LABS",
        "https://other.example/wiki/spaces/VLABS",
        "https://example.atlassian.net:443/wiki/spaces/VLABS",
        "http://example.atlassian.net/wiki/spaces/VLABS",
        "/rest/api/space/VLABS",
    ] {
        assert_eq!(alias(None, Some(link)), None, "{link}");
    }
    assert_eq!(alias(Some("VLABS"), None).as_deref(), Some("VLABS"));
    assert_eq!(
        alias(Some("VLABS"), Some("/spaces/OTHER")).as_deref(),
        Some("VLABS")
    );
    assert_eq!(
        alias(Some("V LABS"), Some("/spaces/VLABS")).as_deref(),
        Some("VLABS")
    );
    assert_eq!(alias(Some("RAILS"), None), None);

    let names = ConfluenceSpaceUrlNames::new("RAILS", Some("VLABS"), None, &config);
    assert!(names.names("RAILS"));
    assert!(names.names("VLABS"));
    assert!(!names.names("vlabs"));
    assert!(!names.names("OTHER"));
}

#[test]
fn v2_space_parser_reads_a_well_formed_current_active_alias() {
    let space = |alias: Value| {
        space_from_value(json!({
            "id": SPACE_ID,
            "key": "RAILS",
            "status": "current",
            "currentActiveAlias": alias,
            "_links": { "webui": "/spaces/VLABS" }
        }))
        .unwrap()
    };
    let aliased = space(json!("VLABS"));
    assert_eq!(aliased.key, "RAILS");
    assert_eq!(aliased.alias.as_deref(), Some("VLABS"));
    assert_eq!(aliased.web_url.as_deref(), Some("/spaces/VLABS"));
    for unusable in [
        json!("RAILS"),
        json!("V LABS"),
        json!(""),
        json!(null),
        json!(7),
    ] {
        assert_eq!(space(unusable.clone()).alias, None, "{unusable}");
    }
}

/// The production failure: `text ~ "Qwen"` returned pages from `RAILS`,
/// linked under `/spaces/VLABS`, and one rejected link failed the search.
#[tokio::test]
async fn search_returns_aliased_links_and_replaces_a_foreign_one_without_failing() {
    let server = MockServer::start().await;
    mount_json(
        &server,
        "/wiki/rest/api/content/search".to_string(),
        json!({
            "results": [
                { "content": rails_page(ALIASED_PAGE_LINK) },
                { "content": v1_content(
                    "page",
                    "44867030047",
                    "Unrelated Title",
                    "/spaces/OTHER/pages/44867030047/Unrelated+Title",
                    ("RAILS", "/spaces/VLABS"),
                ) },
                { "content": v1_content(
                    "page",
                    "123456",
                    "Runbook",
                    "/spaces/ENG/pages/123456/Runbook",
                    ("ENG", "/spaces/ENG"),
                ) },
            ]
        }),
    )
    .await;
    let result = alias_provider(&server)
        .invoke(alias_invocation(
            "search",
            json!({
                "query": {
                    "type": "cql",
                    "value": r#"text ~ "Qwen" ORDER BY lastModified DESC"#
                },
                "maxResults": 3
            }),
        ))
        .await
        .unwrap();

    let pages = &result.result["pages"];
    assert_eq!(pages[0]["space"], "RAILS");
    assert_eq!(pages[0]["webUrl"], format!("{SITE}{ALIASED_PAGE_LINK}"));
    assert_eq!(pages[0]["spaceUrl"], format!("{SITE}/spaces/VLABS"));
    assert_eq!(pages[1]["space"], "RAILS");
    assert_eq!(
        pages[1]["webUrl"],
        format!("{SITE}/pages/viewpage.action?pageId=44867030047")
    );
    assert_eq!(pages[1]["spaceUrl"], format!("{SITE}/spaces/VLABS"));
    assert_eq!(
        pages[2]["webUrl"],
        format!("{SITE}/spaces/ENG/pages/123456/Runbook")
    );
    assert_eq!(pages[2]["spaceUrl"], format!("{SITE}/spaces/ENG"));

    let audit = result.audit.as_ref().unwrap();
    assert_eq!(audit["observedSpaces"], json!(["ENG", "RAILS"]));
    assert_eq!(
        audit["browserUrlFallbacks"],
        json!({
            "count": 1,
            "entries": [{
                "field": "webUrl",
                "rule": "space_mismatch",
                "linkShape": "/spaces/{s}/pages/{n}/{s}",
            }],
        })
    );
    let audit = audit.to_string();
    for private in ["OTHER", "Unrelated", "44867030047", "VLABS"] {
        assert!(!audit.contains(private), "{private} in {audit}");
    }
}

#[tokio::test]
async fn blog_search_returns_aliased_links_and_replaces_a_foreign_one_without_failing() {
    let server = MockServer::start().await;
    mount_json(
        &server,
        "/wiki/rest/api/content/search".to_string(),
        json!({
            "results": [
                { "content": v1_content(
                    "blogpost",
                    BLOG_ID,
                    "Release notes",
                    ALIASED_BLOG_LINK,
                    ("RAILS", "/spaces/VLABS/overview"),
                ) },
                { "content": v1_content(
                    "blogpost",
                    "44867030101",
                    "Other notes",
                    "/spaces/OTHER/blog/2026/10/02/44867030101/Other+notes",
                    ("RAILS", "/spaces/VLABS"),
                ) },
            ]
        }),
    )
    .await;
    let result = alias_provider(&server)
        .invoke(alias_invocation(
            "blog.search",
            json!({
                "query": { "type": "cql", "value": r#"text ~ "Qwen""# },
                "maxResults": 2
            }),
        ))
        .await
        .unwrap();

    let blogs = &result.result["blogs"];
    assert_eq!(blogs[0]["space"], "RAILS");
    assert_eq!(blogs[0]["webUrl"], format!("{SITE}{ALIASED_BLOG_LINK}"));
    assert_eq!(
        blogs[0]["spaceUrl"],
        format!("{SITE}/spaces/VLABS/overview")
    );
    assert_eq!(
        blogs[1]["webUrl"],
        format!("{SITE}/pages/viewpage.action?pageId=44867030101")
    );
    let fallbacks = &result.audit.as_ref().unwrap()["browserUrlFallbacks"];
    assert_eq!(fallbacks["count"], 1);
    assert_eq!(fallbacks["entries"][0]["rule"], "space_mismatch");
    assert_eq!(
        fallbacks["entries"][0]["linkShape"],
        "/spaces/{s}/blog/{n}/{n}/{n}/{n}/{s}"
    );
}

/// A page URL naming the space's alias resolves to the page's space key; the
/// alias is never a scope.
#[tokio::test]
async fn page_url_locators_with_an_alias_scope_the_space_key() {
    let server = MockServer::start().await;
    mount_json(
        &server,
        format!("/wiki/rest/api/content/{PAGE_ID}"),
        rails_page(ALIASED_PAGE_LINK),
    )
    .await;
    mount_json(
        &server,
        "/wiki/api/v2/spaces".to_string(),
        json!({
            "results": [{
                "id": SPACE_ID,
                "key": "RAILS",
                "status": "current",
                "homepageId": "55555",
                "currentActiveAlias": "VLABS",
                "_links": { "webui": "/spaces/VLABS" }
            }]
        }),
    )
    .await;
    let provider = alias_provider(&server);
    let aliased_url = format!("{SITE}{ALIASED_PAGE_LINK}");
    let key_url = format!("{SITE}/spaces/RAILS/pages/{PAGE_ID}/Deployed+RAILS+Models");
    for url in [&aliased_url, &key_url] {
        for (action, inputs) in [
            ("page.view", json!({ "url": url })),
            ("attachment.list", json!({ "url": url })),
            (
                "page.create",
                json!({
                    "space": "RAILS",
                    "title": "Child",
                    "contentFormat": "storage",
                    "content": "<p>child</p>",
                    "parentUrl": url,
                }),
            ),
        ] {
            let scopes = provider
                .lookup_scopes(action, &inputs, Some(&lookup()))
                .await
                .unwrap_or_else(|error| panic!("{action} {url}: {error:?}"));
            assert_eq!(scopes["space"], vec!["RAILS"], "{action} {url}");
        }
    }

    // Neither the key nor the alias: the locator fails closed.
    let foreign_url = format!("{SITE}/spaces/OTHER/pages/{PAGE_ID}/Deployed+RAILS+Models");
    let lowercase_url = format!("{SITE}/spaces/vlabs/pages/{PAGE_ID}/Deployed+RAILS+Models");
    for url in [&foreign_url, &lowercase_url] {
        let error = provider
            .lookup_scopes("page.view", &json!({ "url": url }), Some(&lookup()))
            .await
            .unwrap_err();
        assert_eq!(error.decision(), Decision::Deny, "{url}");
        assert_eq!(error.reason_code(), ReasonCode::ScopeUnresolved, "{url}");
        assert_eq!(
            error.message,
            "Confluence page URL space is neither the page's space key nor its URL alias"
        );
    }

    // Without a lookup the URL's space segment is never taken as a scope.
    let error = provider
        .local_scopes("page.view", &json!({ "url": aliased_url }))
        .unwrap_err();
    assert_eq!(error.reason_code(), ReasonCode::ScopeUnresolved);
    assert_eq!(
        error.message,
        format!("Confluence page {PAGE_ID} scope requires lookup confirmation")
    );

    let view = provider
        .invoke(alias_invocation("page.view", json!({ "url": aliased_url })))
        .await
        .unwrap();
    assert_eq!(view.result["space"], "RAILS");
    assert_eq!(view.result["webUrl"], format!("{SITE}{ALIASED_PAGE_LINK}"));
    assert_eq!(view.result["spaceUrl"], format!("{SITE}/spaces/VLABS"));
    assert!(
        view.audit
            .as_ref()
            .unwrap()
            .get("browserUrlFallbacks")
            .is_none()
    );
}

/// Space-only URLs are not page or blog locators: no locator names a space
/// without content, so an alias is never resolved to a space by itself.
#[test]
fn space_only_urls_are_not_content_locators() {
    let config = confluence_config();
    for url in [
        format!("{SITE}/spaces/VLABS"),
        format!("{SITE}/spaces/VLABS/overview"),
        format!("{SITE}/spaces/VLABS/pages"),
    ] {
        let page = page_locator_from_inputs(&json!({ "url": url }), &config).unwrap_err();
        assert_eq!(page.reason_code(), ReasonCode::LocatorInvalid, "{url}");
        let blog = parse_blog_view_inputs(&json!({ "url": url }), &config).unwrap_err();
        assert_eq!(blog.reason_code(), ReasonCode::LocatorInvalid, "{url}");
    }
    let page = page_locator_from_inputs(
        &json!({ "url": format!("{SITE}/spaces/vlabs/pages/{PAGE_ID}/Title") }),
        &config,
    )
    .unwrap();
    assert_eq!(page.url_space.as_deref(), Some("vlabs"));
    for segment in ["V%20LABS", "%7Evlabs", "-vlabs"] {
        let url = format!("{SITE}/spaces/{segment}/pages/{PAGE_ID}/Title");
        let error = page_locator_from_inputs(&json!({ "url": url }), &config).unwrap_err();
        assert_eq!(error.reason_code(), ReasonCode::InputInvalid, "{segment}");
    }
}

/// A blog's space comes from its v2 space object, whose `currentActiveAlias`
/// names the alias even when the space carries no browser link.
#[tokio::test]
async fn blog_url_locators_and_reads_use_the_v2_space_alias() {
    for space_link in [Some("/spaces/VLABS"), None] {
        let server = MockServer::start().await;
        mount_json(
            &server,
            format!("/wiki/api/v2/blogposts/{BLOG_ID}"),
            json!({
                "id": BLOG_ID,
                "type": "blogpost",
                "status": "current",
                "title": "Release notes",
                "spaceId": SPACE_ID,
                "version": { "number": 2 },
                "body": { "storage": { "value": "<p>notes</p>" } },
                "_links": { "webui": ALIASED_BLOG_LINK }
            }),
        )
        .await;
        let mut space = json!({
            "id": SPACE_ID,
            "key": "RAILS",
            "status": "current",
            "currentActiveAlias": "VLABS"
        });
        if let Some(link) = space_link {
            space["_links"] = json!({ "webui": link });
        }
        mount_json(&server, format!("/wiki/api/v2/spaces/{SPACE_ID}"), space).await;
        let provider = alias_provider(&server);
        let aliased_url = format!("{SITE}{ALIASED_BLOG_LINK}");
        for action in ["blog.view", "blog.attachment.list"] {
            let scopes = provider
                .lookup_scopes(action, &json!({ "url": aliased_url }), Some(&lookup()))
                .await
                .unwrap();
            assert_eq!(scopes["space"], vec!["RAILS"], "{action} {space_link:?}");
        }
        let foreign_url = format!("{SITE}/spaces/OTHER/blog/2026/10/01/{BLOG_ID}/Release+notes");
        let error = provider
            .lookup_scopes("blog.view", &json!({ "url": foreign_url }), Some(&lookup()))
            .await
            .unwrap_err();
        assert_eq!(error.reason_code(), ReasonCode::LocatorInvalid);
        assert_eq!(
            error.message,
            "Confluence blog URL space is neither the resolved blog's space key nor its URL alias"
        );

        let view = provider
            .invoke(alias_invocation("blog.view", json!({ "url": aliased_url })))
            .await
            .unwrap();
        assert_eq!(view.result["space"], "RAILS");
        assert_eq!(view.result["webUrl"], format!("{SITE}{ALIASED_BLOG_LINK}"));
        let space_url = match space_link {
            Some(_) => format!("{SITE}/spaces/VLABS"),
            None => format!("{SITE}/spaces/RAILS"),
        };
        assert_eq!(view.result["spaceUrl"], space_url);
        assert!(
            view.audit
                .as_ref()
                .unwrap()
                .get("browserUrlFallbacks")
                .is_none()
        );
    }
}

#[test]
fn page_blog_and_draft_results_accept_aliased_links() {
    let config = confluence_config();
    let mut fallbacks = BrowserUrlFallbacks::default();
    let page = page_from_value(rails_page(ALIASED_PAGE_LINK)).unwrap();
    let view =
        page_view_result(&page, &config.content.page_formats, &config, &mut fallbacks).unwrap();
    assert_eq!(view["webUrl"], format!("{SITE}{ALIASED_PAGE_LINK}"));

    let mut blog = blog_from_value(json!({
        "id": BLOG_ID,
        "type": "blogpost",
        "status": "current",
        "title": "Release notes",
        "spaceId": SPACE_ID,
        "version": { "number": 2 },
        "_links": { "webui": ALIASED_BLOG_LINK }
    }))
    .unwrap();
    blog.space = "RAILS".to_string();
    blog.space_alias = Some("VLABS".to_string());
    blog.space_web_url = Some("/spaces/VLABS/overview".to_string());
    let view = blog_view_result(&blog, &config, &mut fallbacks).unwrap();
    assert_eq!(view["webUrl"], format!("{SITE}{ALIASED_BLOG_LINK}"));
    assert_eq!(view["spaceUrl"], format!("{SITE}/spaces/VLABS/overview"));

    for content_type in [
        ConfluenceDraftContentType::Page,
        ConfluenceDraftContentType::Blog,
    ] {
        let mut draft = draft_content(PAGE_ID, content_type);
        draft.space = "RAILS".to_string();
        draft.space_alias = Some("VLABS".to_string());
        draft.space_web_url = Some("/spaces/VLABS".to_string());
        let result = draft_content_result(
            "draft.test",
            &draft,
            content_type,
            None,
            None,
            &config,
            &mut fallbacks,
        )
        .unwrap();
        assert_eq!(result["space"], "RAILS");
        assert_eq!(result["spaceUrl"], format!("{SITE}/spaces/VLABS"));
        assert_eq!(
            result["webUrl"],
            format!("{SITE}/pages/viewpage.action?pageId={PAGE_ID}")
        );
    }
    assert_eq!(fallbacks.count, 0);
}

#[test]
fn fallback_audit_keeps_a_bounded_count_and_sample() {
    let config = confluence_config();
    let mut fallbacks = BrowserUrlFallbacks::default();
    for id in 0..(MAX_BROWSER_URL_FALLBACK_ENTRIES + 5) {
        fallbacks.record(
            "webUrl",
            BrowserUrlRule::Space,
            &format!("/spaces/OTHER/pages/{id}/Secret+Title"),
            &config,
        );
    }
    let audit = fallbacks.into_audit(json!({}));
    assert_eq!(
        audit["browserUrlFallbacks"]["count"],
        MAX_BROWSER_URL_FALLBACK_ENTRIES + 5
    );
    assert_eq!(
        audit["browserUrlFallbacks"]["entries"]
            .as_array()
            .unwrap()
            .len(),
        MAX_BROWSER_URL_FALLBACK_ENTRIES
    );
    assert!(!audit.to_string().contains("Secret"));
    let long = format!("/spaces/A/{}", "x/".repeat(40));
    assert!(browser_link_shape(&long, &config).ends_with("/..."));
}
