use super::*;
use serde_json::{Value, json};

const SITE: &str = "https://example.atlassian.net";

fn vector(
    id: &str,
    declared_site: &str,
    url: &str,
    coverage: &str,
    parsed: Value,
    result: Value,
) -> Value {
    json!({"id":id,"declaredSite":declared_site,"url":url,"coverage":coverage,
        "expectedParsed":parsed,"expectedResult":result})
}

/// Independent expected outcomes are checked before this corpus is exported for
/// portal parity tests. Neither client-side guesses nor normalized test output
/// determines the expected persisted identity.
fn vectors() -> Value {
    let mut cases = Vec::new();
    for (name, path, kind, identity) in [
        ("space", "/wiki/spaces/ENG", "space", "ENG"),
        (
            "space-overview",
            "/wiki/spaces/ENG/overview/",
            "space",
            "ENG",
        ),
        (
            "space-personal",
            "/wiki/spaces/~user.name@example.com",
            "space",
            "~user.name@example.com",
        ),
        ("page", "/wiki/spaces/ENG/pages/123", "page", "123"),
        (
            "page-alias",
            "/wiki/spaces/new-alias/pages/123/Title",
            "page",
            "123",
        ),
        (
            "page-stale-space",
            "/wiki/spaces/OLD/pages/123/Old-title/",
            "page",
            "123",
        ),
        (
            "page-unicode-title",
            "/wiki/spaces/ENG/pages/123/日本語",
            "page",
            "123",
        ),
        (
            "page-encoded-title",
            "/wiki/spaces/ENG/pages/123/Hello%20there",
            "page",
            "123",
        ),
        (
            "page-personal",
            "/wiki/spaces/~user.name@example.com/pages/123",
            "page",
            "123",
        ),
        ("page-short-key", "/wiki/spaces/x/pages/123", "page", "123"),
        (
            "page-numeric-key",
            "/wiki/spaces/1/pages/123",
            "page",
            "123",
        ),
        (
            "page-max-id",
            "/wiki/spaces/ENG/pages/12345678901234567890",
            "page",
            "12345678901234567890",
        ),
        ("folder", "/wiki/spaces/ENG/folder/456/", "folder", "456"),
        (
            "folder-title",
            "/wiki/spaces/ENG/folder/456/Runbooks",
            "folder",
            "456",
        ),
        (
            "folder-plus-title",
            "/wiki/spaces/ENG/folder/456/Operations+Runbooks",
            "folder",
            "456",
        ),
        (
            "folder-encoded-title",
            "/wiki/spaces/ENG/folder/456/Operations%20Runbooks/",
            "folder",
            "456",
        ),
        (
            "folder-unicode-title",
            "/wiki/spaces/OLD/folder/456/日本語",
            "folder",
            "456",
        ),
        ("blog", "/wiki/spaces/ENG/blog/789", "blog", "789"),
        (
            "blog-title",
            "/wiki/spaces/ENG/blog/789/Release/",
            "blog",
            "789",
        ),
        (
            "blog-date",
            "/wiki/spaces/ENG/blog/2026/11/20/789/Release",
            "blog",
            "789",
        ),
        (
            "blog-date-unpadded",
            "/wiki/spaces/ENG/blog/2026/1/2/789",
            "blog",
            "789",
        ),
        (
            "blog-date-padded",
            "/wiki/spaces/ENG/blog/2026/01/02/789/Title",
            "blog",
            "789",
        ),
    ] {
        for coverage in ["space", "exact", "subtree", "all", "namespace"] {
            let parsed = if kind == "space" {
                json!({"kind":kind,"spaceKey":identity})
            } else {
                json!({"kind":kind,"id":identity})
            };
            let allowed = matches!(
                (kind, coverage),
                ("space", "space") | ("page" | "blog", "exact") | ("page" | "folder", "subtree")
            );
            let result = if allowed {
                json!({"accepted": {
                    "resourceType":if kind == "space" {"confluence_space"} else {"confluence_content"},
                    "selector":{"kind":if coverage == "space" {"exact"} else {coverage},
                        "value":if kind == "space" {identity.to_owned()} else {format!("{SITE}/wiki/content/{kind}/{identity}")}},
                    "locationKind":kind,"verification":"not_checked"}})
            } else {
                json!({"rejectedField":"coverage"})
            };
            cases.push(vector(
                &format!("{name}-{coverage}"),
                SITE,
                &format!("{SITE}{path}"),
                coverage,
                parsed,
                result,
            ));
        }
    }
    for (name, path, id) in [
        (
            "blog-date-leading-plus",
            "/wiki/spaces/ENG/blog/2026/+5/+6/789/Title",
            "789",
        ),
        (
            "blog-year-like-id-and-title",
            "/wiki/spaces/ENG/blog/2026/5",
            "2026",
        ),
    ] {
        cases.push(vector(name, SITE, &format!("{SITE}{path}"), "exact",
            json!({"kind":"blog","id":id}), json!({"accepted":{
                "resourceType":"confluence_content", "selector":{"kind":"exact","value":format!("{SITE}/wiki/content/blog/{id}")},
                "locationKind":"blog","verification":"not_checked"}})));
    }
    for (name, path) in [
        ("blog-date-without-id", "/wiki/spaces/ENG/blog/2026/11/20"),
        (
            "blog-three-segment-nondate",
            "/wiki/spaces/ENG/blog/789/Title/Extra",
        ),
    ] {
        cases.push(vector(
            name,
            SITE,
            &format!("{SITE}{path}"),
            "exact",
            Value::Null,
            json!({"rejectedField":"url"}),
        ));
    }
    for (name, origin) in [
        ("host-case", "https://EXAMPLE.atlassian.net"),
        ("host-dot", "https://example.atlassian.net."),
        ("scheme-case", "HTTPS://example.atlassian.net"),
    ] {
        cases.push(vector(name, SITE, &format!("{origin}/wiki/spaces/ENG/pages/123"), "exact",
            json!({"kind":"page","id":"123"}), json!({"accepted":{
                "resourceType":"confluence_content","selector":{"kind":"exact","value":format!("{SITE}/wiki/content/page/123")},"locationKind":"page","verification":"not_checked"}})));
    }
    for (name, key) in [
        ("max-key", "A".repeat(255)),
        ("max-personal", format!("~A{}", "x".repeat(253))),
    ] {
        cases.push(vector(name, SITE, &format!("{SITE}/wiki/spaces/{key}/pages/123"), "exact",
            json!({"kind":"page","id":"123"}), json!({"accepted":{
                "resourceType":"confluence_content","selector":{"kind":"exact","value":format!("{SITE}/wiki/content/page/123")},"locationKind":"page","verification":"not_checked"}})));
    }
    let mut invalid = vec![
        (
            "http",
            "http://example.atlassian.net/wiki/spaces/ENG/pages/1".into(),
        ),
        (
            "wrong-site",
            "https://other.atlassian.net/wiki/spaces/ENG/pages/1".into(),
        ),
        (
            "credentials",
            "https://user:secret@example.atlassian.net/wiki/spaces/ENG/pages/1".into(),
        ),
        (
            "empty-user",
            "https://@example.atlassian.net/wiki/spaces/ENG/pages/1".into(),
        ),
        (
            "port",
            "https://example.atlassian.net:443/wiki/spaces/ENG/pages/1".into(),
        ),
        ("ipv4", "https://127.0.0.1/wiki/spaces/ENG/pages/1".into()),
        ("ipv6", "https://[::1]/wiki/spaces/ENG/pages/1".into()),
    ];
    for (name, path) in [
        ("dot", "/wiki/spaces/ENG/../ENG/pages/1"),
        ("encoded-dot", "/wiki/spaces/ENG/%2e%2e/ENG/pages/1"),
        ("encoded-slash", "/wiki/spaces/ENG/pages/1/Title%2Fextra"),
        (
            "encoded-backslash",
            "/wiki/spaces/ENG/pages/1/Title%5cextra",
        ),
        ("encoded-query", "/wiki/spaces/ENG/pages/1/Title%3Fextra"),
        ("encoded-fragment", "/wiki/spaces/ENG/pages/1/Title%23extra"),
        ("invalid-percent", "/wiki/spaces/ENG/pages/1/Title%XY"),
        ("encoded-key", "/wiki/spaces/%45NG/pages/1"),
        ("unicode-key", "/wiki/spaces/日本/pages/1"),
        ("empty-key", "/wiki/spaces//pages/1"),
        ("unsupported-key", "/wiki/spaces/ENG.dot/pages/1"),
        ("personal-empty", "/wiki/spaces/~/pages/1"),
        ("zero-id", "/wiki/spaces/ENG/pages/0"),
        ("leading-zero-id", "/wiki/spaces/ENG/pages/01"),
        ("long-id", "/wiki/spaces/ENG/pages/123456789012345678901"),
        ("query", "/wiki/spaces/ENG/pages/1?"),
        ("fragment", "/wiki/spaces/ENG/pages/1#"),
        ("extra-tail", "/wiki/spaces/ENG/pages/1/a/b"),
        ("folder-extra-tail", "/wiki/spaces/ENG/folder/1/title/extra"),
        (
            "folder-title-encoded-slash",
            "/wiki/spaces/ENG/folder/1/Title%2Fextra",
        ),
        (
            "folder-title-encoded-dot",
            "/wiki/spaces/ENG/folder/1/%2e%2e",
        ),
        ("bad-date", "/wiki/spaces/ENG/blog/2026/13/20/1/title"),
        ("backslash", "/wiki/spaces/ENG/pages/1\\title"),
        ("control", "/wiki/spaces/ENG/pages/1/ti\ttle"),
        ("encoded-control", "/wiki/spaces/ENG/pages/1/Title%00"),
        ("shortlink", "/wiki/x/share"),
        ("legacy", "/wiki/pages/viewpage.action?pageId=1"),
        ("identity-not-browser-url", "/wiki/content/page/1"),
    ] {
        invalid.push((name, format!("{SITE}{path}")));
    }
    invalid.push((
        "oversize-key",
        format!("{SITE}/wiki/spaces/{}/pages/1", "A".repeat(256)),
    ));
    invalid.push((
        "oversize-personal",
        format!("{SITE}/wiki/spaces/~A{}/pages/1", "x".repeat(254)),
    ));
    invalid.push((
        "leading-control",
        format!("\t{SITE}/wiki/spaces/ENG/pages/123"),
    ));
    invalid.push((
        "trailing-control",
        format!("{SITE}/wiki/spaces/ENG/pages/123\n"),
    ));
    for (name, url) in invalid {
        cases.push(vector(
            name,
            SITE,
            &url,
            "exact",
            Value::Null,
            json!({"rejectedField":"url"}),
        ));
    }
    cases.push(vector("surrounding-spaces",SITE,&format!("  {SITE}/wiki/spaces/ENG/pages/123  "),"exact",
        json!({"kind":"page","id":"123"}),json!({"accepted":{
            "resourceType":"confluence_content","selector":{"kind":"exact","value":format!("{SITE}/wiki/content/page/123")},
            "locationKind":"page","verification":"not_checked"}})));
    for declared in [
        "",
        "http://example.atlassian.net",
        "https://EXAMPLE.atlassian.net",
        "https://example.atlassian.net/wiki",
    ] {
        cases.push(vector(
            &format!("invalid-service-{}", cases.len()),
            declared,
            &format!("{SITE}/wiki/spaces/ENG/pages/123"),
            "exact",
            Value::Null,
            json!({"rejectedField":"service"}),
        ));
    }
    json!({"version":1,"cases":cases})
}

fn actual_parsed(case: &Value) -> Value {
    let url = case["url"].as_str().unwrap();
    let declared = case["declaredSite"].as_str().unwrap();
    let Ok(location) = parse_browser_location(url) else {
        return Value::Null;
    };
    if location.site_origin != declared {
        return Value::Null;
    }
    if location.kind == ContentLocationKind::Space {
        json!({"kind":"space","spaceKey":location.space_key})
    } else {
        json!({"kind":location.kind.as_str(),"id":location.id.unwrap()})
    }
}

fn verify_vectors(corpus: &Value) {
    for case in corpus["cases"].as_array().unwrap() {
        assert_eq!(
            actual_parsed(case),
            case["expectedParsed"],
            "parsed {}",
            case["id"]
        );
        let result = normalize_location(&LocationNormalizationRequest::new(
            case["declaredSite"].as_str().unwrap(),
            case["url"].as_str().unwrap(),
            case["coverage"].as_str().unwrap(),
        ));
        let actual = match result {
            Ok(result) => json!({"accepted":result}),
            Err(error) => json!({"rejectedField":error.field()}),
        };
        assert_eq!(actual, case["expectedResult"], "normalized {}", case["id"]);
    }
}

#[test]
fn browser_location_corpus_matches_authoritative_normalizer() {
    let expected = vectors();
    verify_vectors(&expected);
    let checked_in: Value = serde_json::from_str(include_str!(
        "../../tests/fixtures/location-normalization.json"
    ))
    .unwrap();
    assert_eq!(
        checked_in, expected,
        "regenerate the reviewed fixture with export_location_normalization_fixture"
    );
}

#[test]
#[ignore = "explicit export of reviewed URL parity vectors"]
fn export_location_normalization_fixture() {
    let corpus = vectors();
    verify_vectors(&corpus);
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/location-normalization.json");
    std::fs::write(
        path,
        format!("{}\n", serde_json::to_string_pretty(&corpus).unwrap()),
    )
    .unwrap();
}

#[test]
fn strict_identities_reject_browser_routes_decoration_and_unsupported_coverage() {
    let page = format!("{SITE}/wiki/content/page/123");
    let folder = format!("{SITE}/wiki/content/folder/123");
    let blog = format!("{SITE}/wiki/content/blog/123");
    assert!(is_exact_content_location(&page));
    assert!(is_subtree_content_location(&page));
    assert!(is_subtree_content_location(&folder));
    assert!(is_exact_content_location(&blog));
    assert!(!is_exact_content_location(&folder));
    assert!(!is_subtree_content_location(&blog));
    for value in [
        format!("{page}/"),
        format!("{page}/title"),
        format!("{folder}/Runbooks"),
        page.replace("example", "EXAMPLE"),
        format!("{SITE}/wiki/spaces/ENG/pages/123"),
        format!("{SITE}/wiki/content/page/01"),
    ] {
        assert!(!is_content_location(&value), "{value}");
    }
    assert!(project_selector(&ResourceSelector::All).is_err());
    let projection = project_selector(&ResourceSelector::Subtree { value: folder }).unwrap();
    assert_eq!(
        serde_json::to_value(projection).unwrap(),
        json!({"siteOrigin":SITE,"rootKind":"folder"})
    );
}

#[test]
fn folder_parent_urls_ignore_titles_but_preserve_site_and_space_assertions() {
    for suffix in ["", "/Operations+Runbooks", "/Operations%20Runbooks/"] {
        let url = format!("{SITE}/wiki/spaces/ENG/folder/67890{suffix}");
        let parent = parse_creation_parent_url(&url, "example.atlassian.net").unwrap();
        assert_eq!(parent.kind, ContentLocationKind::Folder);
        assert_eq!(parent.id.as_deref(), Some("67890"));
        assert_eq!(parent.space_key, "ENG");
        assert_eq!(parent.site_origin, SITE);
        assert!(parse_creation_parent_url(&url, "other.atlassian.net").is_err());
    }
}

#[test]
fn content_identity_ignores_browser_space_while_space_identity_preserves_case() {
    let normalize = |key: &str, tail: &str, coverage: &str| {
        normalize_location(&LocationNormalizationRequest::new(
            SITE,
            &format!("{SITE}/wiki/spaces/{key}{tail}"),
            coverage,
        ))
        .unwrap()
    };
    assert_eq!(
        serde_json::to_value(normalize("OLD", "/pages/123/A", "exact")).unwrap(),
        serde_json::to_value(normalize("NewAlias", "/pages/123/B", "exact")).unwrap()
    );
    assert_ne!(
        serde_json::to_value(normalize("ENG", "", "space")).unwrap(),
        serde_json::to_value(normalize("Eng", "", "space")).unwrap()
    );
}
