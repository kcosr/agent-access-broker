use super::*;
use agent_access_provider::test_support::basic_credential;
use agent_access_provider::test_support::{TestHost, bearer_credential};
use wiremock::matchers::{method, path, query_param};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn node(kind: ConfluenceNodeKind) -> Value {
    json!({"id":"123", "type":kind.as_str(), "spaceId":"10", "status":"current",
        "parentId":null, "parentType":null, "title":"Fixture", "version":{"number":7}})
}

fn access() -> AtlassianCredential {
    AtlassianCredential::from_static(basic_credential("fixture@example.invalid", "test-token"))
}

fn backend(server: &MockServer) -> HttpConfluenceBackend {
    let config = serde_json::from_value(json!({
        "tenant_host":"example.atlassian.net", "allowed_upstream_hosts":[format!("{}/**", server.uri())]
    })).unwrap();
    HttpConfluenceBackend::new_with_api_base(
        config,
        ProviderLimits::default(),
        Url::parse(&format!("{}/wiki/rest/api/", server.uri())).unwrap(),
    )
}

#[test]
fn all_five_adapters_require_explicit_root_and_current_state() {
    for kind in [
        ConfluenceNodeKind::Page,
        ConfluenceNodeKind::Folder,
        ConfluenceNodeKind::Database,
        ConfluenceNodeKind::Whiteboard,
        ConfluenceNodeKind::Embed,
    ] {
        let value = node(kind);
        assert!(
            node_from_value(&value, kind, "123", ConfluenceContentStatus::Current, true).is_ok()
        );
        for field in ["parentId", "parentType", "status", "spaceId", "id"] {
            let mut invalid = value.clone();
            invalid.as_object_mut().unwrap().remove(field);
            assert_eq!(
                node_from_value(
                    &invalid,
                    kind,
                    "123",
                    ConfluenceContentStatus::Current,
                    true
                ),
                Err(if matches!(field, "parentId" | "parentType") {
                    ConfluenceBackendError::ScopeUnresolved
                } else {
                    malformed_metadata()
                }),
                "missing {field} for {kind:?}"
            );
        }
        for status in ["archived", "trashed", "draft", "unknown"] {
            let mut invalid = value.clone();
            invalid["status"] = json!(status);
            assert!(
                node_from_value(
                    &invalid,
                    kind,
                    "123",
                    ConfluenceContentStatus::Current,
                    true
                )
                .is_err()
            );
        }
    }
}

#[test]
fn parent_observations_are_typed_numeric_paired_and_not_self_edges() {
    for parent_kind in [
        ConfluenceNodeKind::Page,
        ConfluenceNodeKind::Folder,
        ConfluenceNodeKind::Database,
        ConfluenceNodeKind::Whiteboard,
        ConfluenceNodeKind::Embed,
    ] {
        let mut value = node(ConfluenceNodeKind::Page);
        value["parentId"] = json!("456");
        value["parentType"] = json!(parent_kind.as_str());
        let observed = node_from_value(
            &value,
            ConfluenceNodeKind::Page,
            "123",
            ConfluenceContentStatus::Current,
            true,
        )
        .unwrap();
        assert_eq!(
            observed.parent,
            Some(ConfluenceParent {
                kind: parent_kind,
                id: "456".into()
            })
        );
    }
    for (id, kind) in [
        (json!(null), json!("page")),
        (json!("456"), json!(null)),
        (json!("456"), json!("blogpost")),
        (json!("0456"), json!("page")),
        (json!("123"), json!("folder")),
        (json!(456), json!("page")),
    ] {
        let mut value = node(ConfluenceNodeKind::Page);
        value["parentId"] = id;
        value["parentType"] = kind;
        assert!(
            node_from_value(
                &value,
                ConfluenceNodeKind::Page,
                "123",
                ConfluenceContentStatus::Current,
                true
            )
            .is_err()
        );
    }
}

#[test]
fn node_identity_and_optional_type_are_not_coerced() {
    for (field, replacement) in [
        ("id", json!("999")),
        ("id", json!(123)),
        ("spaceId", json!("010")),
        ("type", json!("folder")),
        ("type", json!(null)),
        ("type", json!(false)),
        ("status", json!(null)),
    ] {
        let mut value = node(ConfluenceNodeKind::Page);
        value[field] = replacement;
        assert!(
            node_from_value(
                &value,
                ConfluenceNodeKind::Page,
                "123",
                ConfluenceContentStatus::Current,
                true
            )
            .is_err()
        );
    }
    let mut value = node(ConfluenceNodeKind::Page);
    value.as_object_mut().unwrap().remove("type");
    value["subtype"] = json!({"unknown":"ignored-for-subtype-neutral-read"});
    assert!(
        node_from_value(
            &value,
            ConfluenceNodeKind::Page,
            "123",
            ConfluenceContentStatus::Current,
            true
        )
        .is_ok()
    );
    value["subtype"] = json!("live");
    assert!(
        node_from_value(
            &value,
            ConfluenceNodeKind::Page,
            "123",
            ConfluenceContentStatus::Current,
            true
        )
        .is_ok()
    );
}

#[test]
fn regular_page_query_accepts_only_one_matching_regular_result() {
    for subtype in [None, Some(Value::Null), Some(json!("page"))] {
        let mut value = node(ConfluenceNodeKind::Page);
        if let Some(subtype) = subtype {
            value["subtype"] = subtype;
        }
        assert!(regular_page_from_results(&json!({"results":[value]}), "123", true).is_ok());
    }
    for subtype in [json!("live"), json!("unknown"), json!(false), json!({})] {
        let mut value = node(ConfluenceNodeKind::Page);
        value["subtype"] = subtype;
        assert!(regular_page_from_results(&json!({"results":[value]}), "123", true).is_err());
    }
    let value = node(ConfluenceNodeKind::Page);
    for results in [
        json!([]),
        json!([value.clone(), value.clone()]),
        json!(null),
    ] {
        assert!(regular_page_from_results(&json!({"results":results}), "123", true).is_err());
    }
    assert!(regular_page_from_results(&value, "123", true).is_err());
    assert!(regular_page_from_results(&json!({"results":[value]}), "999", true).is_err());
}

#[test]
fn named_drafts_do_not_become_current_nodes_or_invent_blog_ancestry() {
    let mut value = node(ConfluenceNodeKind::Page);
    value["status"] = json!("draft");
    value["version"]["number"] = json!(0);
    assert!(
        node_from_value(
            &value,
            ConfluenceNodeKind::Page,
            "123",
            ConfluenceContentStatus::Draft,
            true
        )
        .is_ok()
    );
    assert!(
        node_from_value(
            &value,
            ConfluenceNodeKind::Folder,
            "123",
            ConfluenceContentStatus::Draft,
            true
        )
        .is_err()
    );
    value["type"] = json!("blogpost");
    value.as_object_mut().unwrap().remove("parentId");
    value.as_object_mut().unwrap().remove("parentType");
    assert!(blog_location_from_value(&value, "123", ConfluenceContentStatus::Draft).is_ok());
    assert!(blog_location_from_value(&value, "123", ConfluenceContentStatus::Current).is_err());
}

#[test]
fn metadata_budget_clones_share_and_never_reopen_exhausted_work() {
    let budget = ConfluenceMetadataBudget::new(&ConfluenceContentAccessConfig {
        max_metadata_requests: 2,
        max_metadata_bytes: 10,
    });
    let next_pass = budget.clone();
    budget.charge_request().unwrap();
    next_pass.charge_request().unwrap();
    budget.charge_bytes(5).unwrap();
    next_pass.charge_bytes(5).unwrap();
    assert_eq!(budget.usage().unwrap(), (2, 10));
    assert_eq!(
        next_pass.charge_request(),
        Err(ConfluenceBackendError::ScopeUnresolved)
    );
    assert_eq!(
        budget.charge_bytes(0),
        Err(ConfluenceBackendError::ScopeUnresolved)
    );
}

#[test]
fn container_only_regular_metadata_does_not_claim_or_require_parent_observations() {
    let mut page = node(ConfluenceNodeKind::Page);
    page.as_object_mut().unwrap().remove("parentId");
    page.as_object_mut().unwrap().remove("parentType");
    let results = json!({"results":[page]});
    let regular = regular_page_from_results(&results, "123", false).unwrap();
    assert!(regular.node.parent.is_none());
    assert!(regular_page_from_results(&results, "123", true).is_err());
}

#[test]
fn metadata_child_charges_total_scan_once_and_reserves_against_both_limits() {
    let scan = ConfluenceMetadataBudget::new(&ConfluenceContentAccessConfig {
        max_metadata_requests: 4,
        max_metadata_bytes: 40,
    });
    let metadata = ConfluenceMetadataBudget::with_parent(
        &ConfluenceContentAccessConfig {
            max_metadata_requests: 3,
            max_metadata_bytes: 30,
        },
        &scan,
    );
    scan.charge_request().unwrap();
    scan.charge_bytes(12).unwrap();
    metadata.charge_request().unwrap();
    metadata.charge_bytes(10).unwrap();
    let clone = metadata.clone();
    clone.charge_request().unwrap();
    clone.charge_bytes(8).unwrap();
    assert_eq!(scan.usage().unwrap(), (3, 30));
    assert_eq!(metadata.usage().unwrap(), (2, 18));
    assert_eq!(clone.remaining_requests().unwrap(), 1);
    assert_eq!(clone.remaining_bytes().unwrap(), 10);
    metadata.charge_request().unwrap();
    metadata.charge_bytes(10).unwrap();
    assert_eq!(scan.usage().unwrap(), (4, 40));
    assert_eq!(metadata.usage().unwrap(), (3, 28));
    assert_eq!(metadata.remaining_requests().unwrap(), 0);
    assert_eq!(metadata.remaining_bytes().unwrap(), 0);
    assert_eq!(
        metadata.charge_request(),
        Err(ConfluenceBackendError::ScopeUnresolved)
    );
}

#[tokio::test]
async fn explicit_metadata_child_inside_scan_scope_is_not_double_charged() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/wiki/api/v2/pages/123"))
        .respond_with(ResponseTemplate::new(200).set_body_json(node(ConfluenceNodeKind::Page)))
        .expect(1)
        .mount(&server)
        .await;
    let scan = ConfluenceMetadataBudget::new(&Default::default());
    let metadata = ConfluenceMetadataBudget::with_parent(&Default::default(), &scan);
    let backend = backend(&server);
    let credential = access();
    scan.scope(backend.hierarchy_node(
        ConfluenceNodeKind::Page,
        "123",
        ConfluenceContentStatus::Current,
        true,
        &credential,
        &metadata,
    ))
    .await
    .unwrap();
    assert_eq!(scan.usage().unwrap(), metadata.usage().unwrap());
    assert_eq!(scan.usage().unwrap().0, 1);
    assert!(scan.usage().unwrap().1 > 0);
}

#[test]
fn update_result_uses_exact_v2_sources_without_owner_or_v1_aliases() {
    let request = ConfluencePageUpdateRequest {
        page_id: "123".into(),
        space: "ENG".into(),
        space_id: "10".into(),
        title: "Updated".into(),
        base_version: 6,
        body: ConfluencePageBody {
            representation: "storage".into(),
            value: "<p>body</p>".into(),
        },
    };
    let mut value = node(ConfluenceNodeKind::Page);
    value["createdAt"] = json!("2026-01-01T00:00:00Z");
    value["version"]["createdAt"] = json!("2026-01-02T00:00:00Z");
    value["authorId"] = json!("creator");
    value["version"]["authorId"] = json!("editor");
    value["ownerId"] = json!("owner-must-not-become-creator");
    value["createdBy"] = json!({"accountId":"v1-creator","displayName":"private name"});
    value["version"]["by"] = json!({"accountId":"v1-editor","displayName":"private name"});
    value["updatedAt"] = json!("wrong-update-time");
    value["history"] = json!({"createdDate":"wrong-created-time"});
    let page = page_update_response(value.clone(), &request).unwrap();
    assert_eq!(page.created_at.as_deref(), Some("2026-01-01T00:00:00Z"));
    assert_eq!(page.updated_at.as_deref(), Some("2026-01-02T00:00:00Z"));
    assert_eq!(
        page.created_by,
        Some(ConfluenceCommentAuthor {
            account_id: Some("creator".into()),
            display_name: None
        })
    );
    assert_eq!(
        page.updated_by,
        Some(ConfluenceCommentAuthor {
            account_id: Some("editor".into()),
            display_name: None
        })
    );
    for field in ["createdAt", "authorId"] {
        value.as_object_mut().unwrap().remove(field);
    }
    for field in ["createdAt", "authorId"] {
        value["version"].as_object_mut().unwrap().remove(field);
    }
    let page = page_update_response(value.clone(), &request).unwrap();
    assert!(
        page.created_at.is_none()
            && page.updated_at.is_none()
            && page.created_by.is_none()
            && page.updated_by.is_none()
    );
    for path in [
        "/createdAt",
        "/authorId",
        "/version/createdAt",
        "/version/authorId",
    ] {
        for malformed in [Value::Null, json!(false), json!({}), json!([]), json!(42)] {
            let mut value = value.clone();
            let (container, key) = path.rsplit_once('/').unwrap();
            if container.is_empty() {
                value[key] = malformed;
            } else {
                value.pointer_mut(container).unwrap()[key] = malformed;
            }
            assert!(
                page_update_response(value, &request).is_err(),
                "malformed {path}"
            );
        }
    }
}

#[tokio::test]
async fn typed_gets_and_regular_filter_use_actual_http_and_shared_counters() {
    let server = MockServer::start().await;
    for kind in [
        ConfluenceNodeKind::Page,
        ConfluenceNodeKind::Folder,
        ConfluenceNodeKind::Database,
        ConfluenceNodeKind::Whiteboard,
        ConfluenceNodeKind::Embed,
    ] {
        Mock::given(method("GET"))
            .and(path(format!("/wiki/api/v2/{}/123", kind.endpoint())))
            .respond_with(ResponseTemplate::new(200).set_body_json(node(kind)))
            .expect(1)
            .mount(&server)
            .await;
    }
    Mock::given(method("GET"))
        .and(path("/wiki/api/v2/pages"))
        .and(query_param("id", "123"))
        .and(query_param("status", "current"))
        .and(query_param("subtype", "page"))
        .and(query_param("limit", "1"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(json!({"results":[node(ConfluenceNodeKind::Page)]})),
        )
        .expect(1)
        .mount(&server)
        .await;
    let backend = backend(&server);
    let credential = access();
    let budget = ConfluenceMetadataBudget::new(&Default::default());
    for kind in [
        ConfluenceNodeKind::Page,
        ConfluenceNodeKind::Folder,
        ConfluenceNodeKind::Database,
        ConfluenceNodeKind::Whiteboard,
        ConfluenceNodeKind::Embed,
    ] {
        backend
            .hierarchy_node(
                kind,
                "123",
                ConfluenceContentStatus::Current,
                true,
                &credential,
                &budget,
            )
            .await
            .unwrap();
    }
    backend
        .regular_page_metadata("123", true, &credential, &budget)
        .await
        .unwrap();
    let requests = server.received_requests().await.unwrap();
    assert_eq!(requests.len(), 6);
    assert!(
        requests
            .iter()
            .all(|request| request.method.as_str() == "GET")
    );
    assert_eq!(budget.usage().unwrap().0, 6);
    assert!(budget.usage().unwrap().1 > 0);
}

#[tokio::test]
async fn byte_exhaustion_blocks_followup_without_reset_or_write() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/wiki/api/v2/pages/123"))
        .respond_with(ResponseTemplate::new(200).set_body_json(node(ConfluenceNodeKind::Page)))
        .expect(1)
        .mount(&server)
        .await;
    let backend = backend(&server);
    let credential = access();
    let budget = ConfluenceMetadataBudget::new(&ConfluenceContentAccessConfig {
        max_metadata_requests: 10,
        max_metadata_bytes: 8,
    });
    for _ in 0..2 {
        assert_eq!(
            backend
                .hierarchy_node(
                    ConfluenceNodeKind::Page,
                    "123",
                    ConfluenceContentStatus::Current,
                    true,
                    &credential,
                    &budget
                )
                .await,
            Err(ConfluenceBackendError::ScopeUnresolved)
        );
    }
    assert_eq!(server.received_requests().await.unwrap().len(), 1);
}

#[tokio::test]
async fn scoped_old_metadata_counts_real_body_and_does_not_leak_scope() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/wiki/api/v2/spaces/10"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(json!({"id":"10","key":"ENG","status":"current"})),
        )
        .expect(2)
        .mount(&server)
        .await;
    let backend = backend(&server);
    let credential = access();
    let budget = ConfluenceMetadataBudget::new(&ConfluenceContentAccessConfig {
        max_metadata_requests: 1,
        max_metadata_bytes: 4096,
    });
    budget
        .scope(backend.space_by_id("10", &credential))
        .await
        .unwrap();
    assert_eq!(budget.usage().unwrap().0, 1);
    assert!(budget.usage().unwrap().1 > 0);
    assert_eq!(
        budget.scope(backend.space_by_id("10", &credential)).await,
        Err(ConfluenceBackendError::ScopeUnresolved)
    );
    backend.space_by_id("10", &credential).await.unwrap();
    assert_eq!(budget.usage().unwrap().0, 1);
}

fn search_request(cql: String, cursor: Option<String>) -> ConfluenceSearchRequest {
    ConfluenceSearchRequest {
        cql,
        max_results: 1,
        next_page_token: cursor,
    }
}

#[tokio::test]
async fn search_bounds_match_transport_encoding_at_below_and_above_ceiling() {
    let server = MockServer::start().await;
    let mut backend = backend(&server);
    let credential = access();
    let request = search_request(
        "type = page AND title ~ \"é~*\"".into(),
        Some("cursor +/%é".into()),
    );
    let url = backend.search_request_url(&request, &credential).unwrap();
    let target_len = url.path().len() + 1 + url.query().unwrap().len();
    assert!(url.as_str().contains("%C3%A9%7E*"));
    backend
        .config
        .content_search
        .max_encoded_request_target_bytes = target_len as u32;
    assert!(backend.search_request_url(&request, &credential).is_ok());
    backend
        .config
        .content_search
        .max_encoded_request_target_bytes = target_len as u32 + 1;
    assert!(backend.search_request_url(&request, &credential).is_ok());
    backend
        .config
        .content_search
        .max_encoded_request_target_bytes = target_len as u32 - 1;
    assert_eq!(
        backend.search_request_url(&request, &credential),
        Err(ConfluenceBackendError::ScopeUnresolved)
    );
    assert_eq!(
        backend.search(request, &credential).await,
        Err(ConfluenceBackendError::ScopeUnresolved)
    );
    assert!(server.received_requests().await.unwrap().is_empty());
}

#[tokio::test]
async fn absolute_uri_limit_is_checked_separately_from_target() {
    let server = MockServer::start().await;
    let mut backend = backend(&server);
    let credential = access();
    backend
        .config
        .content_search
        .max_encoded_request_target_bytes = 65_534;
    let small = search_request("a".into(), None);
    let url = backend.search_request_url(&small, &credential).unwrap();
    let count = 65_534 - url.as_str().len() + 1;
    let at = search_request("a".repeat(count), None);
    assert_eq!(
        backend
            .search_request_url(&at, &credential)
            .unwrap()
            .as_str()
            .len(),
        65_534
    );
    let over = search_request("a".repeat(count + 1), None);
    assert_eq!(
        backend.search_request_url(&over, &credential),
        Err(ConfluenceBackendError::ScopeUnresolved)
    );
}

#[tokio::test]
async fn gateway_search_counts_its_intermediary_path_before_dispatch() {
    let server = MockServer::start().await;
    let config = serde_json::from_value(json!({
        "tenant_host":"example.atlassian.net",
        "cloud_id":"11111111-2222-4333-8444-555555555555",
        "allowed_upstream_hosts":[format!("{}/**",server.uri()),"https://api.atlassian.com/ex/confluence/**"]
    })).unwrap();
    let mut backend = HttpConfluenceBackend::new_with_api_base(
        config,
        ProviderLimits::default(),
        Url::parse(&format!("{}/wiki/rest/api/", server.uri())).unwrap(),
    )
    .with_gateway_origin(&server.uri(), &TestHost::default())
    .unwrap();
    let request = search_request("type = page".into(), Some("opaque +/%cursor".into()));
    let direct = backend.search_request_url(&request, &access()).unwrap();
    let credential = AtlassianCredential::from_static(bearer_credential("test-gateway-token"));
    let gateway = backend.search_request_url(&request, &credential).unwrap();
    let extra = "/ex/confluence/11111111-2222-4333-8444-555555555555".len();
    assert_eq!(gateway.path().len(), direct.path().len() + extra);
    let direct_size = direct.path().len() + 1 + direct.query().unwrap().len();
    backend
        .config
        .content_search
        .max_encoded_request_target_bytes = direct_size as u32;
    assert!(backend.search_request_url(&request, &access()).is_ok());
    assert_eq!(
        backend.search(request, &credential).await,
        Err(ConfluenceBackendError::ScopeUnresolved)
    );
    assert!(server.received_requests().await.unwrap().is_empty());
}

#[tokio::test]
async fn length_rejection_is_value_free_single_attempt_and_400_is_not_guessed() {
    for status in [400, 414] {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/wiki/rest/api/content/search"))
            .respond_with(ResponseTemplate::new(status).set_body_string("private query text"))
            .expect(1)
            .mount(&server)
            .await;
        let backend = backend(&server);
        let result = backend
            .search(search_request("type = page".into(), None), &access())
            .await;
        let expected = if status == 414 {
            ConfluenceBackendError::ScopeUnresolved
        } else {
            ConfluenceBackendError::HttpStatus(400)
        };
        assert_eq!(result, Err(expected));
        assert_eq!(server.received_requests().await.unwrap().len(), 1);
    }
}

#[tokio::test]
async fn page_update_uses_v2_and_rejects_wrong_identity_as_accepted_unreadable() {
    for returned_id in ["123", "999"] {
        let server = MockServer::start().await;
        let mut response = node(ConfluenceNodeKind::Page);
        response["id"] = json!(returned_id);
        response["version"]["number"] = json!(8);
        Mock::given(method("PUT"))
            .and(path("/wiki/api/v2/pages/123"))
            .respond_with(ResponseTemplate::new(200).set_body_json(response))
            .expect(1)
            .mount(&server)
            .await;
        let backend = backend(&server);
        let request = ConfluencePageUpdateRequest {
            page_id: "123".into(),
            space: "ENG".into(),
            space_id: "10".into(),
            title: "Updated".into(),
            base_version: 7,
            body: ConfluencePageBody {
                representation: "storage".into(),
                value: "<p>body</p>".into(),
            },
        };
        let result = backend.update_page(request, &access()).await;
        if returned_id == "123" {
            assert_eq!(result.unwrap().value.version, 8);
        } else {
            assert!(matches!(
                result,
                Err(ConfluenceBackendError::AcceptedUnreadable(_))
            ));
        }
        let requests = server.received_requests().await.unwrap();
        let body: Value = requests[0].body_json().unwrap();
        assert_eq!(body["status"], "current");
        assert_eq!(body["version"]["number"], 8);
        assert_eq!(body["body"]["representation"], "storage");
        assert!(body.get("space").is_none());
        assert!(body.get("parentId").is_none());
    }
}

#[tokio::test]
async fn folder_create_sends_typed_placement_and_requires_matching_accepted_parent() {
    for returned_kind in ["folder", "page"] {
        let server = MockServer::start().await;
        let mut value = node(ConfluenceNodeKind::Page);
        value["parentId"] = json!("456");
        value["parentType"] = json!(returned_kind);
        Mock::given(method("POST"))
            .and(path("/wiki/api/v2/pages"))
            .respond_with(ResponseTemplate::new(200).set_body_json(value))
            .expect(1)
            .mount(&server)
            .await;
        let backend = backend(&server);
        let request = ConfluencePageCreateRequest {
            space: "ENG".into(),
            space_id: "10".into(),
            title: "Created".into(),
            parent: Some(ConfluenceParent {
                kind: ConfluenceNodeKind::Folder,
                id: "456".into(),
            }),
            body: ConfluencePageBody {
                representation: "storage".into(),
                value: "<p>body</p>".into(),
            },
        };
        let mut invalid = request.clone();
        invalid.parent = None;
        assert_eq!(
            backend.create_page(invalid, &access()).await,
            Err(ConfluenceBackendError::ScopeUnresolved)
        );
        assert!(server.received_requests().await.unwrap().is_empty());
        let result = backend.create_page(request, &access()).await;
        if returned_kind == "folder" {
            assert_eq!(result.unwrap().value.id, "123");
        } else {
            assert!(matches!(
                result,
                Err(ConfluenceBackendError::AcceptedUnreadable(_))
            ));
        }
        let requests = server.received_requests().await.unwrap();
        let body: Value = requests[0].body_json().unwrap();
        assert_eq!(body["parentId"], "456");
        assert!(body.get("parentPageId").is_none());
    }
}

#[tokio::test]
async fn malformed_metadata_consumes_bytes_and_cannot_reopen_budget() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/wiki/api/v2/pages/123"))
        .respond_with(ResponseTemplate::new(200).set_body_string("{malformed"))
        .expect(1)
        .mount(&server)
        .await;
    let backend = backend(&server);
    let budget = ConfluenceMetadataBudget::new(&ConfluenceContentAccessConfig {
        max_metadata_requests: 1,
        max_metadata_bytes: 1024,
    });
    assert_eq!(
        backend
            .hierarchy_node(
                ConfluenceNodeKind::Page,
                "123",
                ConfluenceContentStatus::Current,
                true,
                &access(),
                &budget
            )
            .await,
        Err(malformed_metadata())
    );
    assert_eq!(budget.usage().unwrap(), (1, 10));
    assert_eq!(
        backend
            .hierarchy_node(
                ConfluenceNodeKind::Page,
                "123",
                ConfluenceContentStatus::Current,
                true,
                &access(),
                &budget
            )
            .await,
        Err(ConfluenceBackendError::ScopeUnresolved)
    );
    assert_eq!(server.received_requests().await.unwrap().len(), 1);
}

#[test]
fn accepted_update_identity_state_space_and_version_are_all_required() {
    let request = ConfluencePageUpdateRequest {
        page_id: "123".into(),
        space: "ENG".into(),
        space_id: "10".into(),
        title: "Updated".into(),
        base_version: 6,
        body: ConfluencePageBody {
            representation: "storage".into(),
            value: "<p>body</p>".into(),
        },
    };
    for (path, replacement) in [
        ("/id", json!("999")),
        ("/spaceId", json!("11")),
        ("/status", json!("draft")),
        ("/version/number", json!(8)),
        ("/type", json!(null)),
    ] {
        let mut value = node(ConfluenceNodeKind::Page);
        *value.pointer_mut(path).unwrap() = replacement;
        assert!(
            page_update_response(value, &request).is_err(),
            "invalid {path}"
        );
    }
    assert!(page_update_response(node(ConfluenceNodeKind::Page), &request).is_ok());
    let mut overflow = request;
    overflow.base_version = u64::MAX;
    assert_eq!(
        page_update_request_body(&overflow),
        Err(ConfluenceBackendError::ScopeUnresolved)
    );
}

#[test]
fn search_rows_require_current_typed_unique_bounded_content() {
    let valid = json!({"id":"123","type":"page","status":"current","title":"Notes",
        "space":{"key":"ENG"},"version":{"number":1}});
    assert!(search_page_from_value(json!({"results":[valid.clone()]}), 1).is_ok());
    assert!(search_page_from_value(json!({"results":[{"content":valid.clone()}]}), 1).is_ok());
    for (field, replacement) in [
        ("id", json!("0123")),
        ("id", json!(123)),
        ("type", json!("blogpost")),
        ("status", json!("draft")),
        ("space", json!({"key":"ENG OTHER"})),
        ("version", json!({"number":0})),
        ("version", json!({"number":"1"})),
    ] {
        let mut invalid = valid.clone();
        invalid[field] = replacement;
        assert!(
            search_page_from_value(json!({"results":[invalid]}), 1).is_err(),
            "{field}"
        );
    }
    for field in ["id", "type", "status", "space", "version"] {
        let mut invalid = valid.clone();
        invalid.as_object_mut().unwrap().remove(field);
        assert!(
            search_page_from_value(json!({"results":[invalid]}), 1).is_err(),
            "missing {field}"
        );
    }
    for results in [
        json!([valid.clone(), valid.clone()]),
        json!([null]),
        json!([{"content":null}]),
        json!(null),
    ] {
        assert!(search_page_from_value(json!({"results":results}), 2).is_err());
    }
    let mut other = valid.clone();
    other["id"] = json!("124");
    assert!(search_page_from_value(json!({"results":[valid.clone(),other]}), 1).is_err());
    assert!(search_page_from_value(json!({"results":[]}), 0).is_err());
    let mut blog = valid;
    blog["type"] = json!("blogpost");
    assert!(search_blog_from_value(json!({"results":[blog.clone()]}), 1).is_ok());
    assert!(search_page_from_value(json!({"results":[blog]}), 1).is_err());
}

#[test]
fn malformed_search_next_never_claims_collection_exhaustion() {
    assert_eq!(
        search_page_from_value(json!({"results":[]}), 1)
            .unwrap()
            .next_page_token,
        None
    );
    for next in [
        json!(null),
        json!(false),
        json!(""),
        json!("?start=2"),
        json!("?cursor="),
        json!("?cursor=A&cursor=B"),
        json!("?cursor=%GG"),
        json!("?cursor=%FF"),
        json!("?cursor=A%00"),
        json!("https://other.example/next?cursor=A"),
        json!("//other.example/next?cursor=A"),
        json!("?cursor=A#fragment"),
    ] {
        assert!(
            search_page_from_value(json!({"results":[],"_links":{"next":next}}), 1).is_err(),
            "{next}"
        );
    }
    for links in [json!(null), json!([]), json!("bad")] {
        assert!(search_page_from_value(json!({"results":[],"_links":links}), 1).is_err());
    }
    assert_eq!(search_page_from_value(json!({"results":[],"_links":{"next":"/wiki/rest/api/content/search?cursor=A%2BB%3D&limit=1"}}),1).unwrap().next_page_token.as_deref(),Some("A+B="));
}
