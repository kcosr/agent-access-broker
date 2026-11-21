use super::*;
use agent_access_provider::{ProviderError, ReasonCode};
use serde_json::json;
use std::collections::BTreeSet;

#[path = "../../tests/fixtures/custom_fields.rs"]
mod custom_fields_fixture;

fn adf(text: &str) -> Value {
    json!({"type":"doc","version":1,"content":[{
        "type":"paragraph","content":[{"type":"text","text":text}]
    }]})
}

fn select(
    action: &str,
    result: &mut Value,
    format: OutputContentFormat,
    body_limit: u64,
    result_limit: u64,
) -> Result<(), ProviderError> {
    let resolved = resolve_response_options(
        presentation(action),
        None,
        ResponseOptions::new(Some(format), None),
    )?;
    present_result(&resolved, result, body_limit, result_limit)
}

#[test]
fn descriptors_cover_exact_body_actions_and_concrete_formats() {
    let config = serde_json::from_value(
        json!({"tenant_host":"example.atlassian.net", "content":{"comment_formats":["adf"]}}),
    )
    .unwrap();
    let descriptor = crate::jira_descriptor(&config);
    let actual = descriptor
        .actions
        .iter()
        .filter(|a| a.presentation.is_some())
        .map(|a| a.action.as_str())
        .collect::<BTreeSet<_>>();
    assert_eq!(
        actual,
        BTreeSet::from([
            "issue.view",
            "issue.create",
            "issue.update",
            "comment.view",
            "comment.add",
            "comment.reply",
            "comment.update",
            "comment.list",
        ])
    );
    for action in descriptor
        .actions
        .iter()
        .filter(|a| a.presentation.is_some())
    {
        let body = action.presentation.as_ref().unwrap();
        body.validate().unwrap();
        assert_eq!(body.output_content_formats(), FORMATS);
        assert_eq!(
            body.native_output_content_format(),
            OutputContentFormat::Adf
        );
        assert_eq!(
            response_capabilities(Some(body), None).default_output_content_format,
            Some(OutputContentFormat::Markdown)
        );
        assert_eq!(
            response_capabilities(Some(body), Some(OutputContentFormat::Storage))
                .default_output_content_format,
            Some(OutputContentFormat::Adf)
        );
    }
    let fields = presentation("issue.view").unwrap().body_fields();
    assert_eq!(fields[0].owner_path, "/result");
    assert_eq!(fields[0].field, "description");
    assert_eq!(fields[1].field, "value");
    assert_eq!(fields[1].owner_equals.as_ref().unwrap()["type"], "adf");
    assert_eq!(fields[2].optional_owner_prefixes, ["/result/commentPage"]);
}

#[test]
fn selection_replaces_only_declared_bodies_in_compound_issue_results() {
    let source = json!({
        "key":"PROJ-1", "summary":"Keep **metadata**", "description":adf("issue body"),
        "customFields":[
            {"id":"customfield_1","type":"adf","status":"supported","value":adf("custom body")},
            {"id":"customfield_2","type":"string","status":"supported","value":"plain value"},
            {"id":"customfield_3","type":"adf","status":"withheld"},
            {"id":"customfield_4","type":"adf","status":"unsupported","value":{"untrusted":"not ADF"}},
            {"id":"customfield_5","type":"adf","status":"supported","value":null}
        ],
        "commentPage":{"comments":[
            {"commentId":"1","body":adf("comment body")},
            {"commentId":"2","parentCommentId":"1","body":adf("")}
        ],"nextStartAt":2,"total":null,"isLast":null,"limitedBy":"body_bytes"}
    });
    for format in FORMATS {
        let mut result = source.clone();
        select("issue.view", &mut result, *format, 4096, 65536).unwrap();
        for pointer in [
            "/description",
            "/customFields/0/value",
            "/commentPage/comments/0/body",
            "/commentPage/comments/1/body",
        ] {
            let native = source.pointer(pointer).unwrap();
            let selected = result.pointer(pointer).unwrap();
            assert_eq!(selected["format"], format.as_str());
            assert_eq!(selected.as_object().unwrap().len(), 2);
            if *format == OutputContentFormat::Adf {
                assert_eq!(selected["value"], *native);
            } else {
                assert!(selected["value"].is_string());
            }
            *result.pointer_mut(pointer).unwrap() = native.clone();
        }
        assert_eq!(result, source);
        assert!(!result.to_string().contains("renderedBody"));
    }
}

#[test]
fn comments_and_mutation_readbacks_keep_null_missing_and_empty_distinct() {
    for action in [
        "comment.view",
        "comment.add",
        "comment.reply",
        "comment.update",
    ] {
        for source in [json!({"comment":{}}), json!({"comment":{"body":null}})] {
            let mut result = source.clone();
            select(
                action,
                &mut result,
                OutputContentFormat::Markdown,
                4096,
                65536,
            )
            .unwrap();
            assert_eq!(result, source);
        }
        let mut result = json!({"operation":action,"comment":{"body":adf("")}});
        select(action, &mut result, OutputContentFormat::Text, 4096, 65536).unwrap();
        assert_eq!(
            result["comment"]["body"],
            json!({"format":"text","value":""})
        );
    }
    for action in ["issue.create", "issue.update"] {
        let mut result = json!({"operation":action,"issue":{"description":adf("description")}});
        select(
            action,
            &mut result,
            OutputContentFormat::Markdown,
            4096,
            65536,
        )
        .unwrap();
        assert_eq!(
            result["issue"]["description"],
            json!({"format":"markdown","value":"description"})
        );
        assert_eq!(result["operation"], action);
    }
    let source = json!({"comments":[{"commentId":"1"},{"commentId":"2"}],"includeBodies":false,"nextStartAt":2});
    let mut result = source.clone();
    select(
        "comment.list",
        &mut result,
        OutputContentFormat::Markdown,
        4096,
        65536,
    )
    .unwrap();
    assert_eq!(result, source);
}

#[test]
fn absent_issue_comment_page_is_allowed_but_present_structure_is_validated() {
    for format in FORMATS {
        let mut result = json!({"description":null,"customFields":[]});
        select("issue.view", &mut result, *format, 4096, 65536).unwrap();
        assert!(result.get("commentPage").is_none());
        for page in [
            Value::Null,
            json!({}),
            json!({"comments":null}),
            json!({"comments":[null]}),
        ] {
            let mut invalid = json!({"description":null,"customFields":[],"commentPage":page});
            assert_eq!(
                select("issue.view", &mut invalid, *format, 4096, 65536)
                    .unwrap_err()
                    .reason_code(),
                ReasonCode::UpstreamProtocolFailed
            );
        }
    }
}

#[test]
fn malformed_source_and_exact_size_limits_fail_without_body_leakage() {
    for format in FORMATS {
        for body in [
            json!({"type":"not-a-doc","secret":"private-source"}),
            adf(&"x".repeat(4096)),
        ] {
            let mut result = json!({"comment":{"body":body}});
            let error = select("comment.view", &mut result, *format, 128, 65536).unwrap_err();
            assert_eq!(error.reason_code(), ReasonCode::UpstreamProtocolFailed);
            assert_eq!(error.message, RENDER_FAILURE_MESSAGE);
            assert!(error.result.is_none());
        }
        let source = json!({"comment":{"body":adf("exact bytes")}});
        let mut selected = source.clone();
        select("comment.view", &mut selected, *format, 4096, 65536).unwrap();
        let exact = serde_json::to_vec(&selected).unwrap().len() as u64;
        select("comment.view", &mut source.clone(), *format, 4096, exact).unwrap();
        assert!(
            select(
                "comment.view",
                &mut source.clone(),
                *format,
                4096,
                exact - 1
            )
            .is_err()
        );
    }
    assert_eq!(
        select(
            "issue.view",
            &mut json!({}),
            OutputContentFormat::Storage,
            4096,
            65536
        )
        .unwrap_err()
        .reason_code(),
        ReasonCode::ResponseFormatUnsupported
    );
    assert_eq!(
        select(
            "search",
            &mut json!({}),
            OutputContentFormat::Markdown,
            4096,
            65536
        )
        .unwrap_err()
        .reason_code(),
        ReasonCode::ResponseFormatUnsupported
    );
}

#[test]
fn compound_bodies_share_the_request_complexity_budget() {
    let large = json!({"type":"doc","version":1,"content":vec![json!({"type":"paragraph","content":[]}); 50_000]});
    for format in FORMATS {
        let mut single = json!({"comment":{"body":large}});
        select(
            "comment.view",
            &mut single,
            *format,
            4 * 1024 * 1024,
            32 * 1024 * 1024,
        )
        .unwrap();
        let mut compound = json!({"description":large,"customFields":[{"status":"supported","type":"adf","value":large}],"commentPage":{"comments":[{"body":large}]}});
        assert_eq!(
            select(
                "issue.view",
                &mut compound,
                *format,
                4 * 1024 * 1024,
                32 * 1024 * 1024
            )
            .unwrap_err()
            .reason_code(),
            ReasonCode::UpstreamProtocolFailed
        );
    }
}

#[test]
fn realistic_multi_mib_custom_fields_retain_every_value_without_duplicate_bodies() {
    let source = custom_fields_fixture::realistic_issue_view();
    assert_eq!(source["customFields"].as_array().unwrap().len(), 256);
    for format in FORMATS {
        let mut result = source.clone();
        select(
            "issue.view",
            &mut result,
            *format,
            1024 * 1024,
            16 * 1024 * 1024,
        )
        .unwrap();
        assert_eq!(result["description"]["format"], format.as_str());
        for (original, actual) in source["customFields"]
            .as_array()
            .unwrap()
            .iter()
            .zip(result["customFields"].as_array().unwrap())
        {
            if original["type"] == "adf" {
                let expected = select_adf_bounded_with_budget(
                    &original["value"],
                    *format,
                    1024 * 1024,
                    1024 * 1024,
                    &mut RenderBudget::default(),
                )
                .unwrap()
                .into_value();
                assert_eq!(actual["value"], expected);
                let mut unchanged = actual.clone();
                unchanged["value"] = original["value"].clone();
                assert_eq!(&unchanged, original);
            } else {
                assert_eq!(actual, original);
            }
        }
        assert!(!result.to_string().contains("renderedBody"));
    }
}
