use super::*;

#[test]
fn ordinary_space_keys_preserve_case_through_catalog_lookup_and_urls() {
    let config = confluence_config();
    for key in ["A", "a", "0", "123", "7Ops", "eng", "TeamDocs", "Docs_2-A"] {
        assert_eq!(validate_space_key(key).unwrap(), key);
        assert!(CONFLUENCE_SPACE_RESOURCE.is_canonical_target(key));
        let resolved = crate::backend::space_from_value(json!({
            "id":"123", "key":key, "name":"Space", "status":"current"
        }))
        .unwrap();
        assert_eq!(resolved.key, key);
        let url = format!("https://example.atlassian.net/wiki/spaces/{key}/pages/123/Notes");
        assert_eq!(
            page_locator_from_url(&url, &config)
                .unwrap()
                .url_space
                .as_deref(),
            Some(key)
        );
        assert_eq!(
            space_browser_url(
                None,
                &key_only(key),
                &config,
                &mut BrowserUrlFallbacks::default()
            )
            .unwrap(),
            format!("https://example.atlassian.net/wiki/spaces/{key}")
        );
        assert_eq!(
            parse_cql_spaces(&format!("space = \"{key}\"")).unwrap(),
            BTreeSet::from([key.to_string()])
        );
    }
    for key in ["a".repeat(255), format!("0{}", "x".repeat(254))] {
        assert_eq!(validate_space_key(&key).unwrap(), key);
        assert!(CONFLUENCE_SPACE_RESOURCE.is_canonical_target(&key));
    }
    for key in [
        "",
        "_Docs",
        "-Docs",
        "Team/Docs",
        "Team\\Docs",
        "Team Docs",
        "Team%44ocs",
        "Team?x",
        "Team#x",
        "Team\"",
        "Team'",
        "Team*",
        "Téam",
        "Team\n",
    ] {
        assert!(validate_space_key(key).is_err(), "accepted {key:?}");
        assert!(
            !CONFLUENCE_SPACE_RESOURCE.is_canonical_target(key),
            "accepted {key:?}"
        );
    }
    assert!(validate_space_key(&"a".repeat(256)).is_err());
}

#[test]
fn ordinary_space_keys_remain_exact_in_search_authority() {
    let scope = EffectiveSearchScope::Finite(BTreeSet::from(["TeamDocs".to_string()]));
    assert!(scope.authorizes_value("TeamDocs"));
    assert!(!scope.authorizes_value("TEAMDOCS"));
    assert!(!scope.authorizes_value("teamdocs"));
    let query = build_confluence_search_query(
        &ConfluenceSearchQueryInput::Cql {
            value: String::new(),
        },
        &scope,
        &SearchLimitsConfig::default(),
    )
    .unwrap();
    assert_eq!(query.cql, "space IN (TeamDocs) AND type = page");
    let scope = EffectiveSearchScope::AllExcept(BTreeSet::from(["TeamDocs".to_string()]));
    assert!(!scope.authorizes_value("TeamDocs"));
    assert!(scope.authorizes_value("TEAMDOCS"));
}
