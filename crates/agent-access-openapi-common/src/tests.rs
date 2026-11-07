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
    assert!(plan.response_headers(200, &headers).is_err());
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
    ] {
        assert!(validate_declared_header(name).is_err());
    }
}

#[test]
fn integer_bounds_do_not_lose_precision_above_f64_exact_range() {
    let schema = json!({"type":"integer","maximum":9007199254740992u64});
    crate::schema::validate_schema(&schema, false).unwrap();
    crate::schema::scalar("9007199254740992", &schema).unwrap();
    assert!(crate::schema::scalar("9007199254740993", &schema).is_err());
}
