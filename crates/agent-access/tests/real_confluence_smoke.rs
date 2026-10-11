use std::process::Command;

#[test]
#[ignore = "requires a live broker configured for Confluence and real credentials"]
fn real_broker_confluence_read_smoke() {
    let broker_url = std::env::var("AGENT_ACCESS_REAL_BROKER_URL")
        .unwrap_or_else(|_| "http://127.0.0.1:8787".to_string());
    let page_id = std::env::var("AGENT_ACCESS_REAL_CONFLUENCE_PAGE_ID")
        .expect("AGENT_ACCESS_REAL_CONFLUENCE_PAGE_ID is required");
    let space = std::env::var("AGENT_ACCESS_REAL_CONFLUENCE_SPACE")
        .expect("AGENT_ACCESS_REAL_CONFLUENCE_SPACE is required");
    let cql = std::env::var("AGENT_ACCESS_REAL_CONFLUENCE_CQL")
        .unwrap_or_else(|_| format!("space = {space} and type = page"));

    let page = Command::new(env!("CARGO_BIN_EXE_agent-access"))
        .args(["--url", &broker_url, "confluence", "page", "view", &page_id])
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
    assert_eq!(page_json["result"]["id"], page_id);
    assert_eq!(page_json["result"]["space"], space);
    assert_browser_url(&page_json["result"]["webUrl"], "page view webUrl");
    assert_browser_url(&page_json["result"]["spaceUrl"], "page view spaceUrl");

    if let Ok(page_url) = std::env::var("AGENT_ACCESS_REAL_CONFLUENCE_PAGE_URL") {
        let page_by_url = Command::new(env!("CARGO_BIN_EXE_agent-access"))
            .args([
                "--url",
                &broker_url,
                "confluence",
                "page",
                "view",
                "--page-url",
                &page_url,
            ])
            .output()
            .unwrap();
        assert!(
            page_by_url.status.success(),
            "page view by URL failed: stdout={} stderr={}",
            String::from_utf8_lossy(&page_by_url.stdout),
            String::from_utf8_lossy(&page_by_url.stderr)
        );
        let page_by_url_json: serde_json::Value =
            serde_json::from_slice(&page_by_url.stdout).unwrap();
        assert_eq!(page_by_url_json["decision"], "allow");
        assert_eq!(page_by_url_json["result"]["space"], space);
    }

    let search = Command::new(env!("CARGO_BIN_EXE_agent-access"))
        .args([
            "--url",
            &broker_url,
            "confluence",
            "page",
            "search",
            "--space",
            &space,
            "--cql",
            &cql,
            "--max-results",
            "5",
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
    let pages = search_json["result"]["pages"]
        .as_array()
        .expect("page search result must include pages");
    let first_page = pages
        .first()
        .expect("page search must return at least one page for URL smoke coverage");
    assert_browser_url(&first_page["webUrl"], "page search webUrl");
    assert_browser_url(&first_page["spaceUrl"], "page search spaceUrl");

    let attachments = Command::new(env!("CARGO_BIN_EXE_agent-access"))
        .args([
            "--url",
            &broker_url,
            "confluence",
            "page",
            "attachment",
            "list",
            &page_id,
        ])
        .output()
        .unwrap();
    assert_success("real Confluence attachment list", &attachments);
    let attachments_json: serde_json::Value = serde_json::from_slice(&attachments.stdout).unwrap();
    assert_eq!(attachments_json["decision"], "allow");
    assert!(
        attachments_json["result"]["attachments"]
            .as_array()
            .is_some()
    );
}

#[test]
#[ignore = "requires a live broker configured for Confluence and mutates real pages"]
fn real_broker_confluence_write_stream_verify_smoke() {
    let broker_url = std::env::var("AGENT_ACCESS_REAL_BROKER_URL")
        .unwrap_or_else(|_| "http://127.0.0.1:8787".to_string());
    let space = std::env::var("AGENT_ACCESS_REAL_CONFLUENCE_SPACE")
        .expect("AGENT_ACCESS_REAL_CONFLUENCE_SPACE is required");
    let create_title = std::env::var("AGENT_ACCESS_REAL_CONFLUENCE_CREATE_TITLE")
        .expect("AGENT_ACCESS_REAL_CONFLUENCE_CREATE_TITLE is required");
    let create_content_file = std::env::var("AGENT_ACCESS_REAL_CONFLUENCE_CREATE_CONTENT_FILE")
        .expect("AGENT_ACCESS_REAL_CONFLUENCE_CREATE_CONTENT_FILE is required");
    let create_content_format = std::env::var("AGENT_ACCESS_REAL_CONFLUENCE_CREATE_CONTENT_FORMAT")
        .expect("AGENT_ACCESS_REAL_CONFLUENCE_CREATE_CONTENT_FORMAT is required");
    let update_page_id = std::env::var("AGENT_ACCESS_REAL_CONFLUENCE_UPDATE_PAGE_ID")
        .expect("AGENT_ACCESS_REAL_CONFLUENCE_UPDATE_PAGE_ID is required");
    let update_base_version = std::env::var("AGENT_ACCESS_REAL_CONFLUENCE_UPDATE_BASE_VERSION")
        .expect("AGENT_ACCESS_REAL_CONFLUENCE_UPDATE_BASE_VERSION is required");
    let update_content_file = std::env::var("AGENT_ACCESS_REAL_CONFLUENCE_UPDATE_CONTENT_FILE")
        .expect("AGENT_ACCESS_REAL_CONFLUENCE_UPDATE_CONTENT_FILE is required");
    let update_content_format = std::env::var("AGENT_ACCESS_REAL_CONFLUENCE_UPDATE_CONTENT_FORMAT")
        .expect("AGENT_ACCESS_REAL_CONFLUENCE_UPDATE_CONTENT_FORMAT is required");
    let attachment_file = std::env::var("AGENT_ACCESS_REAL_CONFLUENCE_ATTACHMENT_FILE")
        .expect("AGENT_ACCESS_REAL_CONFLUENCE_ATTACHMENT_FILE is required");
    let attachment_content_type =
        std::env::var("AGENT_ACCESS_REAL_CONFLUENCE_ATTACHMENT_CONTENT_TYPE")
            .unwrap_or_else(|_| "text/plain".to_string());
    let download_path = std::env::temp_dir().join(format!(
        "agent-access-real-confluence-download-{}",
        uuid::Uuid::new_v4()
    ));

    let create = Command::new(env!("CARGO_BIN_EXE_agent-access"))
        .args([
            "--url",
            &broker_url,
            "confluence",
            "page",
            "create",
            "--space",
            &space,
            "--title",
            &create_title,
            "--content-file",
            &create_content_file,
            "--content-format",
            &create_content_format,
        ])
        .output()
        .unwrap();
    assert_success("real Confluence create", &create);
    let create_json: serde_json::Value = serde_json::from_slice(&create.stdout).unwrap();
    assert_eq!(create_json["decision"], "allow");
    assert!(create_json["result"]["pageId"].as_str().is_some());
    assert_browser_url(&create_json["result"]["webUrl"], "page create webUrl");
    assert_browser_url(&create_json["result"]["spaceUrl"], "page create spaceUrl");

    let update = Command::new(env!("CARGO_BIN_EXE_agent-access"))
        .args([
            "--url",
            &broker_url,
            "confluence",
            "page",
            "update",
            &update_page_id,
            "--base-version",
            &update_base_version,
            "--content-file",
            &update_content_file,
            "--content-format",
            &update_content_format,
        ])
        .output()
        .unwrap();
    assert_success("real Confluence update", &update);
    let update_json: serde_json::Value = serde_json::from_slice(&update.stdout).unwrap();
    let updated_version = update_json["result"]["version"]
        .as_u64()
        .expect("update result must include version");
    assert_browser_url(&update_json["result"]["webUrl"], "page update webUrl");
    assert_browser_url(&update_json["result"]["spaceUrl"], "page update spaceUrl");

    let attach = Command::new(env!("CARGO_BIN_EXE_agent-access"))
        .args([
            "--url",
            &broker_url,
            "confluence",
            "page",
            "attach",
            &update_page_id,
            "--content-type",
            &attachment_content_type,
            &attachment_file,
        ])
        .output()
        .unwrap();
    assert_success("real Confluence attach", &attach);
    let attach_json: serde_json::Value = serde_json::from_slice(&attach.stdout).unwrap();
    let attachment_id = attach_json["result"]["attachments"][0]["attachmentId"]
        .as_str()
        .expect("attachment result must include attachmentId");

    let list = Command::new(env!("CARGO_BIN_EXE_agent-access"))
        .args([
            "--url",
            &broker_url,
            "confluence",
            "page",
            "attachment",
            "list",
            &update_page_id,
        ])
        .output()
        .unwrap();
    assert_success("real Confluence attachment list", &list);
    let list_json: serde_json::Value = serde_json::from_slice(&list.stdout).unwrap();
    assert!(
        attachment_list_contains(&list_json, attachment_id),
        "uploaded attachment id {attachment_id} missing from list response: {}",
        list_json
    );

    let download = Command::new(env!("CARGO_BIN_EXE_agent-access"))
        .args([
            "--url",
            &broker_url,
            "confluence",
            "page",
            "attachment",
            "download",
            &update_page_id,
            "--attachment-id",
            attachment_id,
            "--output",
            download_path.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert_success("real Confluence download", &download);
    assert_eq!(
        std::fs::read(&download_path).expect("downloaded attachment should be readable"),
        std::fs::read(&attachment_file).expect("uploaded attachment fixture should be readable")
    );

    let verify = Command::new(env!("CARGO_BIN_EXE_agent-access"))
        .args([
            "--url",
            &broker_url,
            "confluence",
            "page",
            "verify",
            &update_page_id,
            "--expect-version",
            &updated_version.to_string(),
            "--expect-attachment-id",
            attachment_id,
        ])
        .output()
        .unwrap();
    assert_success("real Confluence verify", &verify);
}

#[test]
#[ignore = "requires a live broker configured for Confluence blogs and mutates real blog posts"]
fn real_broker_confluence_blog_smoke() {
    let broker_url = std::env::var("AGENT_ACCESS_REAL_BROKER_URL")
        .unwrap_or_else(|_| "http://127.0.0.1:8787".to_string());
    let space = std::env::var("AGENT_ACCESS_REAL_CONFLUENCE_SPACE")
        .expect("AGENT_ACCESS_REAL_CONFLUENCE_SPACE is required");
    let blog_id = std::env::var("AGENT_ACCESS_REAL_CONFLUENCE_BLOG_ID")
        .expect("AGENT_ACCESS_REAL_CONFLUENCE_BLOG_ID is required");
    let blog_cql = std::env::var("AGENT_ACCESS_REAL_CONFLUENCE_BLOG_CQL")
        .unwrap_or_else(|_| format!("space = {space} and type = blogpost"));
    let create_title = std::env::var("AGENT_ACCESS_REAL_CONFLUENCE_BLOG_CREATE_TITLE")
        .expect("AGENT_ACCESS_REAL_CONFLUENCE_BLOG_CREATE_TITLE is required");
    let create_content_file =
        std::env::var("AGENT_ACCESS_REAL_CONFLUENCE_BLOG_CREATE_CONTENT_FILE")
            .expect("AGENT_ACCESS_REAL_CONFLUENCE_BLOG_CREATE_CONTENT_FILE is required");
    let create_content_format =
        std::env::var("AGENT_ACCESS_REAL_CONFLUENCE_BLOG_CREATE_CONTENT_FORMAT")
            .expect("AGENT_ACCESS_REAL_CONFLUENCE_BLOG_CREATE_CONTENT_FORMAT is required");
    let update_base_version =
        std::env::var("AGENT_ACCESS_REAL_CONFLUENCE_BLOG_UPDATE_BASE_VERSION")
            .expect("AGENT_ACCESS_REAL_CONFLUENCE_BLOG_UPDATE_BASE_VERSION is required");
    let update_content_file =
        std::env::var("AGENT_ACCESS_REAL_CONFLUENCE_BLOG_UPDATE_CONTENT_FILE")
            .expect("AGENT_ACCESS_REAL_CONFLUENCE_BLOG_UPDATE_CONTENT_FILE is required");
    let update_content_format =
        std::env::var("AGENT_ACCESS_REAL_CONFLUENCE_BLOG_UPDATE_CONTENT_FORMAT")
            .expect("AGENT_ACCESS_REAL_CONFLUENCE_BLOG_UPDATE_CONTENT_FORMAT is required");
    let attachment_file = std::env::var("AGENT_ACCESS_REAL_CONFLUENCE_BLOG_ATTACHMENT_FILE")
        .expect("AGENT_ACCESS_REAL_CONFLUENCE_BLOG_ATTACHMENT_FILE is required");
    let attachment_content_type =
        std::env::var("AGENT_ACCESS_REAL_CONFLUENCE_BLOG_ATTACHMENT_CONTENT_TYPE")
            .unwrap_or_else(|_| "text/plain".to_string());
    let download_path = std::env::temp_dir().join(format!(
        "agent-access-real-confluence-blog-download-{}",
        uuid::Uuid::new_v4()
    ));

    let view = Command::new(env!("CARGO_BIN_EXE_agent-access"))
        .args(["--url", &broker_url, "confluence", "blog", "view", &blog_id])
        .output()
        .unwrap();
    assert_success("real Confluence blog view", &view);
    let view_json: serde_json::Value = serde_json::from_slice(&view.stdout).unwrap();
    assert_eq!(view_json["decision"], "allow");
    assert_eq!(view_json["result"]["blogId"], blog_id);
    assert_eq!(view_json["result"]["space"], space);
    let blog_web_url = assert_browser_url(&view_json["result"]["webUrl"], "blog view webUrl");
    assert_browser_url(&view_json["result"]["spaceUrl"], "blog view spaceUrl");
    let blog_viewpage_url = viewpage_url_from_browser_url(&blog_web_url, &blog_id);
    maybe_probe_blog_viewpage_url(&blog_viewpage_url, &blog_id);

    let view_by_url = Command::new(env!("CARGO_BIN_EXE_agent-access"))
        .args([
            "--url",
            &broker_url,
            "confluence",
            "blog",
            "view",
            "--blog-url",
            &blog_viewpage_url,
        ])
        .output()
        .unwrap();
    assert_success("real Confluence blog view by URL", &view_by_url);
    let view_by_url_json: serde_json::Value = serde_json::from_slice(&view_by_url.stdout).unwrap();
    assert_eq!(view_by_url_json["decision"], "allow");
    assert_eq!(view_by_url_json["result"]["blogId"], blog_id);

    let search = Command::new(env!("CARGO_BIN_EXE_agent-access"))
        .args([
            "--url",
            &broker_url,
            "confluence",
            "blog",
            "search",
            "--space",
            &space,
            "--cql",
            &blog_cql,
            "--max-results",
            "5",
        ])
        .output()
        .unwrap();
    assert_success("real Confluence blog search", &search);
    let search_json: serde_json::Value = serde_json::from_slice(&search.stdout).unwrap();
    assert_eq!(search_json["decision"], "allow");
    let blogs = search_json["result"]["blogs"]
        .as_array()
        .expect("blog search result must include blogs");
    let first_blog = blogs
        .first()
        .expect("blog search must return at least one blog for URL smoke coverage");
    assert_browser_url(&first_blog["webUrl"], "blog search webUrl");
    assert_browser_url(&first_blog["spaceUrl"], "blog search spaceUrl");

    let create = Command::new(env!("CARGO_BIN_EXE_agent-access"))
        .args([
            "--url",
            &broker_url,
            "confluence",
            "blog",
            "create",
            "--space",
            &space,
            "--title",
            &create_title,
            "--content-file",
            &create_content_file,
            "--content-format",
            &create_content_format,
        ])
        .output()
        .unwrap();
    assert_success("real Confluence blog create", &create);
    let create_json: serde_json::Value = serde_json::from_slice(&create.stdout).unwrap();
    assert_eq!(create_json["decision"], "allow");
    assert!(create_json["result"]["blogId"].as_str().is_some());
    assert_browser_url(&create_json["result"]["webUrl"], "blog create webUrl");
    assert_browser_url(&create_json["result"]["spaceUrl"], "blog create spaceUrl");

    let update = Command::new(env!("CARGO_BIN_EXE_agent-access"))
        .args([
            "--url",
            &broker_url,
            "confluence",
            "blog",
            "update",
            &blog_id,
            "--base-version",
            &update_base_version,
            "--content-file",
            &update_content_file,
            "--content-format",
            &update_content_format,
        ])
        .output()
        .unwrap();
    assert_success("real Confluence blog update", &update);
    let update_json: serde_json::Value = serde_json::from_slice(&update.stdout).unwrap();
    let updated_version = update_json["result"]["version"]
        .as_u64()
        .expect("blog update result must include version");
    assert_browser_url(&update_json["result"]["webUrl"], "blog update webUrl");
    assert_browser_url(&update_json["result"]["spaceUrl"], "blog update spaceUrl");

    let attach = Command::new(env!("CARGO_BIN_EXE_agent-access"))
        .args([
            "--url",
            &broker_url,
            "confluence",
            "blog",
            "attach",
            &blog_id,
            "--content-type",
            &attachment_content_type,
            &attachment_file,
        ])
        .output()
        .unwrap();
    assert_success("real Confluence blog attach", &attach);
    let attach_json: serde_json::Value = serde_json::from_slice(&attach.stdout).unwrap();
    let attachment_id = attach_json["result"]["attachments"][0]["attachmentId"]
        .as_str()
        .expect("blog attachment result must include attachmentId");

    let list = Command::new(env!("CARGO_BIN_EXE_agent-access"))
        .args([
            "--url",
            &broker_url,
            "confluence",
            "blog",
            "attachment",
            "list",
            &blog_id,
        ])
        .output()
        .unwrap();
    assert_success("real Confluence blog attachment list", &list);
    let list_json: serde_json::Value = serde_json::from_slice(&list.stdout).unwrap();
    assert!(
        attachment_list_contains(&list_json, attachment_id),
        "uploaded blog attachment id {attachment_id} missing from list response: {}",
        list_json
    );

    let list_by_url = Command::new(env!("CARGO_BIN_EXE_agent-access"))
        .args([
            "--url",
            &broker_url,
            "confluence",
            "blog",
            "attachment",
            "list",
            "--blog-url",
            &blog_viewpage_url,
        ])
        .output()
        .unwrap();
    assert_success("real Confluence blog attachment list by URL", &list_by_url);

    let download = Command::new(env!("CARGO_BIN_EXE_agent-access"))
        .args([
            "--url",
            &broker_url,
            "confluence",
            "blog",
            "attachment",
            "download",
            &blog_id,
            "--attachment-id",
            attachment_id,
            "--output",
            download_path.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert_success("real Confluence blog attachment download", &download);
    assert_eq!(
        std::fs::read(&download_path).expect("downloaded blog attachment should be readable"),
        std::fs::read(&attachment_file)
            .expect("uploaded blog attachment fixture should be readable")
    );

    let verify = Command::new(env!("CARGO_BIN_EXE_agent-access"))
        .args([
            "--url",
            &broker_url,
            "confluence",
            "blog",
            "verify",
            &blog_id,
            "--expect-version",
            &updated_version.to_string(),
            "--expect-attachment-id",
            attachment_id,
        ])
        .output()
        .unwrap();
    assert_success("real Confluence blog verify", &verify);
}

fn assert_success(label: &str, output: &std::process::Output) {
    assert!(
        output.status.success(),
        "{label} failed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn assert_browser_url(value: &serde_json::Value, label: &str) -> String {
    let raw = value
        .as_str()
        .unwrap_or_else(|| panic!("{label} must be a string"));
    let url = url::Url::parse(raw).unwrap_or_else(|error| panic!("{label} is invalid: {error}"));
    assert_eq!(url.scheme(), "https", "{label} must use https");
    assert!(
        url.host_str().is_some(),
        "{label} must include a tenant host"
    );
    assert!(
        url.path().starts_with("/wiki/"),
        "{label} must be a Confluence browser URL"
    );
    if let Ok(expected_host) = std::env::var("AGENT_ACCESS_REAL_CONFLUENCE_TENANT_HOST") {
        assert_eq!(url.host_str(), Some(expected_host.as_str()));
    }
    raw.to_string()
}

fn viewpage_url_from_browser_url(raw: &str, content_id: &str) -> String {
    let url = url::Url::parse(raw).expect("browser URL should already be validated");
    format!(
        "https://{}/wiki/pages/viewpage.action?pageId={content_id}",
        url.host_str().expect("browser URL must include host")
    )
}

fn maybe_probe_blog_viewpage_url(raw: &str, blog_id: &str) {
    if !env_flag("AGENT_ACCESS_REAL_CONFLUENCE_PROBE_BROWSER_URLS") {
        return;
    }
    let runtime =
        tokio::runtime::Runtime::new().expect("browser URL probe runtime should initialize");
    runtime.block_on(async {
        let start_url =
            url::Url::parse(raw).expect("blog viewpage URL should already be validated");
        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .expect("browser URL probe client should initialize");
        let response = client
            .get(start_url.clone())
            .send()
            .await
            .unwrap_or_else(|error| panic!("blog viewpage URL probe failed: {error}"));
        let status = response.status();
        if status.is_success() {
            assert_blog_probe_url_carries_id(response.url(), &start_url, blog_id);
            return;
        }
        if status.is_redirection() {
            let location = response
                .headers()
                .get(reqwest::header::LOCATION)
                .and_then(|value| value.to_str().ok())
                .unwrap_or_else(|| {
                    panic!("blog viewpage URL redirect for {blog_id} omitted Location")
                });
            let redirect_url = start_url
                .join(location)
                .unwrap_or_else(|error| panic!("blog viewpage redirect URL is invalid: {error}"));
            assert_blog_probe_url_carries_id(&redirect_url, &start_url, blog_id);
            return;
        }
        panic!("blog viewpage URL for {blog_id} did not resolve successfully: status={status}");
    });
}

fn assert_blog_probe_url_carries_id(url: &url::Url, start_url: &url::Url, blog_id: &str) {
    assert_eq!(url.scheme(), "https");
    assert_eq!(url.host_str(), start_url.host_str());
    assert!(
        browser_content_url_carries_id(url, blog_id),
        "blog viewpage URL for {blog_id} resolved without a matching content ID: {url}"
    );
}

fn browser_content_url_carries_id(url: &url::Url, content_id: &str) -> bool {
    let Some(segments) = url
        .path_segments()
        .map(|segments| segments.collect::<Vec<_>>())
    else {
        return false;
    };
    if segments.as_slice() == ["wiki", "pages", "viewpage.action"] {
        let pairs = url.query_pairs().collect::<Vec<_>>();
        return pairs.len() == 1 && pairs[0].0 == "pageId" && pairs[0].1 == content_id;
    }
    if url.query().is_some() {
        return false;
    }
    segments.len() >= 5
        && segments[0] == "wiki"
        && segments[1] == "spaces"
        && matches!(segments[3], "pages" | "blog")
        && segments[4..].contains(&content_id)
}

fn env_flag(name: &str) -> bool {
    matches!(
        std::env::var(name).as_deref(),
        Ok("1" | "true" | "TRUE" | "yes" | "YES")
    )
}

fn attachment_list_contains(value: &serde_json::Value, attachment_id: &str) -> bool {
    value["result"]["attachments"]
        .as_array()
        .map(|attachments| {
            attachments
                .iter()
                .any(|attachment| attachment["attachmentId"] == attachment_id)
        })
        .unwrap_or(false)
}
