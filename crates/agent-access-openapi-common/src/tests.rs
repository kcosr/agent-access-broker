use crate::*;
use http::{HeaderMap, HeaderValue};
use serde_json::json;
use std::collections::BTreeMap;

fn plan(path: &str) -> GatewayPlanV1 {
    GatewayPlanV1 {
        version: 1,
        source: json!({"method":"GET","path":path}),
        method: "GET".into(),
        path: path.into(),
        security: GatewaySecurityV1 {
            kind: "anonymous".into(),
            scheme: None,
            header: None,
        },
        parameters: validate_path_template(path)
            .unwrap()
            .into_iter()
            .map(|name| GatewayParameterV1 {
                name,
                location: "path".into(),
                required: true,
                style: "simple".into(),
                explode: false,
                schema: json!({"type":"string","minLength":1}),
            })
            .collect(),
        request_body: None,
        responses: BTreeMap::from([(
            "200".into(),
            GatewayResponseV1 {
                headers: Vec::new(),
                content_types: vec!["application/json".into()],
            },
        )]),
    }
}

fn manifest(paths: &[&str]) -> GatewayRouteManifestV1 {
    GatewayRouteManifestV1 {
        version: 1,
        paths: paths
            .iter()
            .map(|path| {
                (
                    path.to_string(),
                    GatewayPathV1 {
                        methods: BTreeMap::from([(
                            "GET".into(),
                            GatewayRouteV1 {
                                source: json!({"method":"GET","path":path}),
                                current: true,
                                supported: true,
                            },
                        )]),
                    },
                )
            })
            .collect(),
    }
}

#[test]
fn literal_guard_wins_before_method_or_action_state() {
    let mut routes = manifest(&["/items/{id}", "/items/admin"]);
    routes
        .paths
        .get_mut("/items/admin")
        .unwrap()
        .methods
        .get_mut("GET")
        .unwrap()
        .supported = false;
    routes.validate().unwrap();
    let get = routes.select("GET", "/items/admin").unwrap().unwrap();
    assert_eq!(get.template, "/items/admin");
    assert!(!get.route.unwrap().supported);
    let post = routes.select("POST", "/items/admin").unwrap().unwrap();
    assert_eq!(post.template, "/items/admin");
    assert!(post.route.is_none());
    assert!(routes.validate_plan(&plan("/items/admin")).is_err());
}

#[test]
fn removed_path_remains_a_guard_after_refresh() {
    let old = manifest(&["/items/{id}", "/items/admin"]);
    let mut current = manifest(&["/items/{id}"]);
    current.merge_retained(&old).unwrap();
    assert!(
        !current
            .select("GET", "/items/admin")
            .unwrap()
            .unwrap()
            .route
            .unwrap()
            .current
    );
    assert!(
        current
            .select("GET", "/items/ordinary")
            .unwrap()
            .unwrap()
            .route
            .unwrap()
            .current
    );
}

#[test]
fn equivalent_and_incomparable_templates_are_rejected_including_history() {
    for paths in [
        vec!["/items/{id}", "/items/{name}"],
        vec!["/items/{id}/edit", "/items/admin/{verb}"],
    ] {
        assert!(manifest(&paths).validate().is_err());
    }
    let old = manifest(&["/items/{id}"]);
    let mut new = manifest(&["/items/{name}"]);
    let before = new.clone();
    assert!(new.merge_retained(&old).is_err());
    assert_eq!(new, before);
}

#[test]
fn nested_specificity_and_trailing_slash_remain_distinct() {
    let routes = manifest(&[
        "/{kind}/{id}",
        "/items/{id}",
        "/items/admin",
        "/items/admin/",
    ]);
    routes.validate().unwrap();
    assert_eq!(
        routes.select("GET", "/items/a").unwrap().unwrap().template,
        "/items/{id}"
    );
    assert_eq!(
        routes
            .select("GET", "/items/admin/")
            .unwrap()
            .unwrap()
            .template,
        "/items/admin/"
    );
}

#[test]
fn path_normalization_rejects_second_decode_and_preserves_safe_components() {
    let routes = manifest(&["/items/{id}"]);
    for path in [
        "/items/%",
        "/items/%GG",
        "/items/%2fadmin",
        "/items/%5cadmin",
        "/items/%252fadmin",
        "/items/..",
        "/items/%2e",
        "/items/a\\b",
        "/items/%00",
        "/items//a",
    ] {
        assert!(routes.select("GET", path).is_err(), "{path}");
    }
    let found = routes.select("GET", "/items/a%20b").unwrap().unwrap();
    assert_eq!(found.parameters["id"], "a b");
    assert_eq!(found.canonical_path, "/items/a%20b");
    assert_eq!(canonical_path("/caf%C3%A9/").unwrap(), "/caf%C3%A9/");
}

#[test]
fn parameter_names_must_exactly_match_the_template() {
    let mut plan = plan("/items/{id}");
    plan.validate().unwrap();
    plan.parameters[0].name = "other".into();
    assert!(plan.validate().is_err());
    for path in [
        "/prefix-{id}",
        "/{id}/{id}",
        "/{id:.*}",
        "/items/*",
        "/items/%61",
    ] {
        assert!(validate_path_template(path).is_err());
    }
}

#[test]
fn query_reconstruction_rejects_unknown_duplicate_and_invalid_scalar_values() {
    let routes = manifest(&["/items/{id}"]);
    let selected = routes.select("GET", "/items/a").unwrap().unwrap();
    let mut plan = plan("/items/{id}");
    plan.parameters.push(GatewayParameterV1 {
        name: "count".into(),
        location: "query".into(),
        required: false,
        style: "form".into(),
        explode: true,
        schema: json!({"type":"integer","minimum":1,"maximum":5}),
    });
    plan.validate().unwrap();
    for query in [
        "secret=SENTINEL",
        "count=1&count=2",
        "count=0",
        "count=x",
        "count=%XX",
    ] {
        let error = plan
            .validate_request_parameters(&selected, Some(query), &HeaderMap::new())
            .err()
            .unwrap();
        assert!(!error.contains("SENTINEL"));
    }
    let result = plan
        .validate_request_parameters(&selected, Some("count=2"), &HeaderMap::new())
        .unwrap();
    assert_eq!(result.relative_target, "/items/a?count=2");
    assert_eq!(result.present_parameters, ["count", "id"]);
}

#[test]
fn query_arrays_preserve_order_empty_values_and_escaped_commas() {
    let routes = manifest(&["/items"]);
    let selected = routes.select("GET", "/items").unwrap().unwrap();
    let mut plan = plan("/items");
    plan.parameters.push(GatewayParameterV1 {
        name: "tag".into(),
        location: "query".into(),
        required: true,
        style: "form".into(),
        explode: true,
        schema: json!({"type":"array","items":{"type":"string"},"maxItems":4}),
    });
    plan.validate().unwrap();
    let result = plan
        .validate_request_parameters(&selected, Some("tag=z&tag=&tag=a%2Cb"), &HeaderMap::new())
        .unwrap();
    assert_eq!(result.relative_target, "/items?tag=z&tag=&tag=a%2Cb");
    plan.parameters[0].explode = false;
    let result = plan
        .validate_request_parameters(&selected, Some("tag=z,,a%2Cb"), &HeaderMap::new())
        .unwrap();
    assert_eq!(result.relative_target, "/items?tag=z,,a%2Cb");
}

#[test]
fn common_headers_are_finite_and_single_byte_range_is_validated() {
    let routes = manifest(&["/file"]);
    let selected = routes.select("GET", "/file").unwrap().unwrap();
    let plan = plan("/file");
    let mut headers = HeaderMap::new();
    headers.insert("accept-encoding", HeaderValue::from_static("gzip"));
    headers.insert("x-unknown", HeaderValue::from_static("SENTINEL"));
    headers.insert("range", HeaderValue::from_static("bytes=3-9"));
    let result = plan
        .validate_request_parameters(&selected, None, &headers)
        .unwrap();
    assert_eq!(result.headers.len(), 1);
    for value in [
        "bytes=1-2,4-5",
        "items=1-2",
        "bytes=9-3",
        "bytes=-0",
        "bytes=+1-2",
    ] {
        headers.insert("range", HeaderValue::from_str(value).unwrap());
        assert!(
            plan.validate_request_parameters(&selected, None, &headers)
                .is_err()
        );
    }
}

#[test]
fn declared_response_header_schema_and_status_precedence_are_enforced() {
    let mut plan = plan("/file");
    plan.responses
        .get_mut("200")
        .unwrap()
        .headers
        .push(GatewayResponseHeaderV1 {
            name: "X-Api-Version".into(),
            schema: json!({"type":"integer","minimum":1,"maximum":3}),
        });
    plan.responses.insert(
        "2XX".into(),
        GatewayResponseV1 {
            headers: Vec::new(),
            content_types: Vec::new(),
        },
    );
    plan.validate().unwrap();
    let mut headers = HeaderMap::new();
    headers.insert("x-api-version", HeaderValue::from_static("2"));
    headers.insert("set-cookie", HeaderValue::from_static("SENTINEL"));
    assert_eq!(plan.response_headers(200, &headers).unwrap().len(), 1);
    assert!(plan.response_headers(201, &headers).unwrap().is_empty());
    headers.insert("x-api-version", HeaderValue::from_static("4"));
    assert!(plan.response_headers(200, &headers).unwrap().is_empty());
}

#[test]
fn invalid_optional_response_values_are_omitted_without_failing_error_responses() {
    let mut plan = plan("/file");
    plan.responses.insert(
        "4XX".into(),
        GatewayResponseV1 {
            headers: vec![
                GatewayResponseHeaderV1 {
                    name: "X-Api-Version".into(),
                    schema: json!({"type":"integer","maximum":3}),
                },
                GatewayResponseHeaderV1 {
                    name: "ETag".into(),
                    schema: json!({"type":"string","maxLength":3}),
                },
                GatewayResponseHeaderV1 {
                    name: "Retry-After".into(),
                    schema: json!({"type":"string"}),
                },
            ],
            content_types: vec!["application/json".into()],
        },
    );
    plan.validate().unwrap();
    let mut headers = HeaderMap::new();
    headers.insert("content-type", HeaderValue::from_static("application/json"));
    headers.insert("x-api-version", HeaderValue::from_static("4"));
    headers.insert(
        "retry-after",
        HeaderValue::from_static("SENTINEL_INVALID_DELAY"),
    );
    headers.insert("etag", HeaderValue::from_static("SENTINEL_LONG_ETAG"));
    headers.insert(
        "content-disposition",
        HeaderValue::from_str(&"a".repeat(4097)).unwrap(),
    );
    for status in [429, 404, 500] {
        let filtered = plan.response_headers(status, &headers).unwrap();
        assert_eq!(filtered["content-type"], "application/json");
        assert!(!filtered.contains_key("retry-after"));
        assert!(!filtered.contains_key("content-disposition"));
        assert!(!filtered.contains_key("x-api-version"));
        if status < 500 {
            assert!(!filtered.contains_key("etag"));
        }
    }
    headers.insert("retry-after", HeaderValue::from_static("12"));
    assert_eq!(
        plan.response_headers(429, &headers).unwrap()["retry-after"],
        "12"
    );
}

#[test]
fn repeated_selected_response_headers_still_fail() {
    let mut plan = plan("/file");
    plan.responses.insert(
        "default".into(),
        GatewayResponseV1 {
            headers: vec![GatewayResponseHeaderV1 {
                name: "X-Api-Version".into(),
                schema: json!({"type":"string"}),
            }],
            content_types: Vec::new(),
        },
    );
    plan.validate().unwrap();
    for name in ["retry-after", "x-api-version"] {
        let mut headers = HeaderMap::new();
        headers.append(name, HeaderValue::from_static("1"));
        headers.append(name, HeaderValue::from_static("2"));
        assert!(plan.response_headers(429, &headers).is_err());
    }
}

#[test]
fn nonascii_optional_response_values_are_omitted_without_discarding_body_metadata() {
    let mut plan = plan("/file");
    plan.responses.insert(
        "default".into(),
        GatewayResponseV1 {
            headers: vec![GatewayResponseHeaderV1 {
                name: "X-Api-Version".into(),
                schema: json!({"type":"string"}),
            }],
            content_types: Vec::new(),
        },
    );
    plan.validate().unwrap();
    let mut headers = HeaderMap::new();
    headers.insert("content-type", HeaderValue::from_static("application/pdf"));
    headers.insert(
        "content-disposition",
        HeaderValue::from_bytes(b"attachment; filename=\"r\xc3\xa9sum\xc3\xa9.pdf\"").unwrap(),
    );
    headers.insert("x-api-version", HeaderValue::from_bytes(&[0xff]).unwrap());
    for status in [200, 404, 429, 500] {
        let filtered = plan.response_headers(status, &headers).unwrap();
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered["content-type"], "application/pdf");
    }
}

#[test]
fn body_profile_checks_presence_media_and_empty_semantics_without_json_validation() {
    let mut plan = plan("/items");
    plan.method = "POST".into();
    plan.source = json!({"method":"POST","path":"/items"});
    plan.request_body = Some(GatewayRequestBodyV1 {
        required: true,
        media_types: vec!["application/json".into()],
    });
    plan.validate().unwrap();
    assert!(plan.validate_body(false, Some("application/json")).is_err());
    assert!(plan.validate_body(true, None).is_err());
    assert!(plan.validate_body(true, Some("text/plain")).is_err());
    plan.validate_body(true, Some("application/json; charset=utf-8"))
        .unwrap();
    plan.method = "GET".into();
    plan.source = json!({"method":"GET","path":"/items"});
    assert!(plan.validate().is_err());
}

#[test]
fn restored_plan_rejects_unknown_fields_versions_and_credential_header_collisions() {
    let plan = plan("/file");
    let mut encoded = serde_json::to_value(&plan).unwrap();
    encoded["future"] = json!(true);
    assert!(serde_json::from_value::<GatewayPlanV1>(encoded).is_err());
    let mut plan = plan;
    plan.version = 2;
    assert!(plan.validate().is_err());
    for name in [
        "Authorization",
        "X-AW-Identity-Token-SHA256",
        "WWW-Authenticate",
        "Set-Cookie",
        "Connection",
        "X-Forwarded-For",
        "X-Original-Url",
        "X-Real-IP",
        "True-Client-IP",
        "CF-Connecting-IP",
        "X-Client-IP",
        "X-Cluster-Client-IP",
        "Fastly-Client-IP",
        "Refresh",
        "Alt-Svc",
        "Strict-Transport-Security",
        "Via",
        "Expect",
        "Max-Forwards",
    ] {
        assert!(validate_declared_header(name).is_err());
    }
}

#[test]
fn canonical_paths_preserve_raw_pchar_and_literal_custom_verbs() {
    for path in [
        "/v1/name:cancel",
        "/a@b",
        "/x=y;z",
        "/a+b",
        "/tags/a,b",
        "/!$&'()*+,;=:@",
    ] {
        assert_eq!(canonical_path(path).unwrap(), path);
    }
    let path = "/jobs/{id}/action:run";
    let routes = manifest(&[path]);
    routes.validate().unwrap();
    let selected = routes
        .select("GET", "/jobs/id@kind+tag/action:run")
        .unwrap()
        .unwrap();
    let request = plan(path)
        .validate_request_parameters(&selected, None, &HeaderMap::new())
        .unwrap();
    assert_eq!(request.relative_target, "/jobs/id%40kind%2Btag/action:run");
    assert_eq!(canonical_path("/a%3Ab/").unwrap(), "/a:b/");
    assert!(canonical_path("/a%252fb").is_err());
}

#[test]
fn path_parameter_semicolons_cannot_bypass_literal_guards_or_form_traversal_segments() {
    let routes = manifest(&["/items/{id}", "/items/admin", "/items/{id}/{child}"]);
    let matcher = routes.matcher().unwrap();
    for path in [
        "/items/admin;x",
        "/items/admin%3Bx",
        "/items/admin%3bx",
        "/items/..;",
        "/items/..%3B",
        "/items/..;/comments",
        "/items/%2e%2e%3B/comments",
        "/items/ordinary/..;",
        "/items/admin;SENTINEL",
    ] {
        let error = matcher.select("GET", path).err().unwrap();
        assert_eq!(error, "gateway path parameter contains an unsafe component");
        assert_eq!(routes.select("GET", path).err().unwrap(), error);
        assert!(!error.contains("SENTINEL"));
    }
    let guard = matcher.select("POST", "/items/admin").unwrap().unwrap();
    assert_eq!(guard.template, "/items/admin");
    assert!(guard.route.is_none());
}

#[test]
fn declared_literal_pchar_is_distinct_from_encoded_parameter_values() {
    let routes = manifest(&[
        "/items/{id}",
        "/items/admin:action@kind+tag=x",
        "/jobs/{id}/action:run",
    ]);
    let matcher = routes.matcher().unwrap();
    let literal = matcher
        .select("GET", "/items/admin:action@kind+tag=x")
        .unwrap()
        .unwrap();
    assert_eq!(literal.template, "/items/admin:action@kind+tag=x");
    assert_eq!(literal.canonical_path, "/items/admin:action@kind+tag=x");
    assert_eq!(
        matcher
            .select("GET", "/items/admin%3Aaction%40kind%2Btag%3Dx")
            .unwrap()
            .unwrap()
            .template,
        "/items/admin:action@kind+tag=x"
    );
    for path in ["/jobs/a@b+c=d/action:run", "/jobs/a%40b%2Bc%3Dd/action:run"] {
        let selected = matcher.select("GET", path).unwrap().unwrap();
        assert_eq!(selected.parameters["id"], "a@b+c=d");
        assert_eq!(selected.canonical_path, "/jobs/a%40b%2Bc%3Dd/action:run");
        let request = plan("/jobs/{id}/action:run")
            .validate_request_parameters(&selected, None, &HeaderMap::new())
            .unwrap();
        assert_eq!(request.relative_target, selected.canonical_path);
    }
}

#[test]
fn source_and_retained_guards_reject_literal_semicolon_components() {
    for path in [
        "/items/admin;x",
        "/items/..;/comments",
        "/items/{id;variant}",
    ] {
        let routes = manifest(&["/items/{id}", path]);
        assert_eq!(
            routes.validate().unwrap_err(),
            "matrix/path parameters are unsupported in gateway source paths"
        );
        assert!(routes.matcher().is_err());
        let mut current = manifest(&["/items/{id}"]);
        let before = current.clone();
        assert!(current.merge_retained(&routes).is_err());
        assert_eq!(current, before);
    }
}

#[test]
fn compiled_matcher_preserves_guard_precedence_methods_and_immutable_snapshot() {
    let mut routes = manifest(&[
        "/{kind}/{id}",
        "/items/{id}",
        "/items/admin",
        "/items/admin/",
        "/jobs/{id}/action:run",
    ]);
    routes
        .paths
        .get_mut("/items/admin")
        .unwrap()
        .methods
        .get_mut("GET")
        .unwrap()
        .current = false;
    let matcher = routes.matcher().unwrap();
    for path in [
        "/items/admin",
        "/items/admin/",
        "/items/ordinary",
        "/kinds/a%20b",
        "/jobs/id@kind/action:run",
        "/no/such/path",
        "/",
        "/items/%2f",
    ] {
        for method in ["GET", "POST", "HEAD"] {
            match (routes.select(method, path), matcher.select(method, path)) {
                (Ok(Some(left)), Ok(Some(right))) => {
                    assert_eq!(left.template, right.template);
                    assert_eq!(left.canonical_path, right.canonical_path);
                    assert_eq!(left.parameters, right.parameters);
                    assert_eq!(left.route, right.route);
                }
                (Ok(None), Ok(None)) => {}
                (Err(left), Err(right)) => assert_eq!(left, right),
                _ => panic!("compiled route selection differs"),
            }
        }
    }
    routes.paths.remove("/items/admin");
    let selected = matcher.select("GET", "/items/admin").unwrap().unwrap();
    assert_eq!(selected.template, "/items/admin");
    assert!(!selected.route.unwrap().current);
    assert!(
        manifest(&["/items/{id}", "/items/{name}"])
            .matcher()
            .is_err()
    );
}

#[test]
fn numeric_enum_and_unique_items_compare_values_across_json_number_representations() {
    let schema = json!({"type":"number","enum":[1.0,2.5]});
    crate::schema::validate_schema(&schema, false).unwrap();
    for value in ["1", "1.0", "1e0", "2.50"] {
        crate::schema::scalar(value, &schema).unwrap();
    }
    assert!(crate::schema::scalar("2", &schema).is_err());
    let schema = json!({"type":"array","uniqueItems":true,"items":{"type":"number"}});
    crate::schema::validate_schema(&schema, true).unwrap();
    for values in [["1", "1.0"], ["0", "-0.0"], ["2.50", "2.5"]] {
        assert!(crate::schema::array(&values.map(str::to_owned), &schema).is_err());
    }
    crate::schema::array(
        &["9007199254740993".into(), "9007199254740992.0".into()],
        &schema,
    )
    .unwrap();
    let strings = json!({"type":"array","uniqueItems":true,"items":{"type":"string"}});
    crate::schema::array(&["1".into(), "1.0".into()], &strings).unwrap();
}

#[test]
fn mixed_number_comparisons_do_not_round_large_integer_values() {
    let schema = json!({"type":"number","enum":[9007199254740992.0]});
    crate::schema::scalar("9007199254740992", &schema).unwrap();
    assert!(crate::schema::scalar("9007199254740993", &schema).is_err());
    let schema = json!({"type":"number","maximum":9007199254740992.0});
    assert!(crate::schema::scalar("9007199254740993", &schema).is_err());
    let schema = json!({"type":"number","minimum":-1.5,"maximum":1.5});
    for value in ["-1", "0", "1"] {
        crate::schema::scalar(value, &schema).unwrap();
    }
    for value in ["-2", "2"] {
        assert!(crate::schema::scalar(value, &schema).is_err());
    }
}

#[test]
fn integer_bounds_do_not_lose_precision_above_f64_exact_range() {
    let schema = json!({"type":"integer","maximum":9007199254740992u64});
    crate::schema::validate_schema(&schema, false).unwrap();
    crate::schema::scalar("9007199254740992", &schema).unwrap();
    assert!(crate::schema::scalar("9007199254740993", &schema).is_err());
}

#[test]
fn number_integer_bounds_and_multiples_remain_exact_above_f64_precision() {
    let schema = json!({"type":"number","maximum":9007199254740992u64});
    crate::schema::validate_schema(&schema, false).unwrap();
    crate::schema::scalar("9007199254740992", &schema).unwrap();
    assert!(crate::schema::scalar("9007199254740993", &schema).is_err());
    let schema = json!({"type":"number","minimum":9007199254740993u64});
    crate::schema::scalar("9007199254740993", &schema).unwrap();
    assert!(crate::schema::scalar("9007199254740992", &schema).is_err());
    let schema = json!({"type":"number","multipleOf":2});
    crate::schema::scalar("9007199254740992", &schema).unwrap();
    assert!(crate::schema::scalar("9007199254740993", &schema).is_err());
}

#[test]
fn overflowing_numeric_multiple_ratio_is_rejected() {
    let schema = json!({"type":"number","multipleOf":1e-308});
    crate::schema::validate_schema(&schema, false).unwrap();
    assert!(crate::schema::scalar("1e308", &schema).is_err());
}
