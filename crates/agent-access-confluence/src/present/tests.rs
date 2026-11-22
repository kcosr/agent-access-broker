use super::*;
use agent_access_provider::{ProviderError, ReasonCode};
use serde_json::json;
use std::collections::BTreeSet;

fn config() -> ConfluenceContentConfig {
    ConfluenceContentConfig {
        page_formats: vec!["storage".into(), "atlas_doc_format".into()],
        ..Default::default()
    }
}

fn adf(text: &str) -> Value {
    json!({"type":"doc","version":1,"content":[
        {"type":"paragraph","content":[{"type":"text","text":text}]}
    ]})
}

fn storage(source: &str) -> Value {
    json!({"storage":{"representation":"storage","value":source}})
}

fn adf_body(text: &str) -> Value {
    json!({"atlas_doc_format":{"representation":"atlas_doc_format", "value":adf(text).to_string()}})
}

fn select(
    action: &str,
    config: &ConfluenceContentConfig,
    mut result: Value,
    exact: Option<OutputContentFormat>,
    preferred: Option<OutputContentFormat>,
    body_limit: u64,
    result_limit: u64,
) -> Result<Value, ProviderError> {
    let resolved = resolve_response_options(
        presentation(action, config),
        config.preferred_output_format,
        ResponseOptions::new(exact, preferred),
    )?;
    present_result(&resolved, &mut result, body_limit, result_limit)?;
    Ok(result)
}

#[test]
fn registry_covers_all_twenty_six_body_actions_and_no_metadata_only_actions() {
    let descriptor = crate::confluence_descriptor(&crate::tests::confluence_config());
    let actual = descriptor
        .actions
        .iter()
        .filter(|a| a.presentation.is_some())
        .map(|a| a.action.as_str())
        .collect::<BTreeSet<_>>();
    let expected = [
        "page.view",
        "blog.view",
        "page.draft.view",
        "blog.draft.view",
        "page.footer_comment.list",
        "page.footer_comment.view",
        "page.footer_comment.reply.list",
        "page.inline_comment.list",
        "page.inline_comment.view",
        "page.inline_comment.reply.list",
        "blog.footer_comment.list",
        "blog.footer_comment.view",
        "blog.footer_comment.reply.list",
        "blog.inline_comment.list",
        "blog.inline_comment.view",
        "blog.inline_comment.reply.list",
        "page.footer_comment.add",
        "blog.footer_comment.add",
        "page.footer_comment.update",
        "page.inline_comment.update",
        "blog.footer_comment.update",
        "blog.inline_comment.update",
        "page.footer_comment.reply.add",
        "page.inline_comment.reply.add",
        "blog.footer_comment.reply.add",
        "blog.inline_comment.reply.add",
    ]
    .into_iter()
    .collect::<BTreeSet<_>>();
    assert_eq!(actual, expected);
    assert_eq!(actual.len(), 26);
    for action in &descriptor.actions {
        if let Some(presentation) = action.presentation {
            presentation.validate().unwrap();
            let fields = presentation.body_fields();
            assert_eq!(fields.len(), 1, "{}", action.action);
            let field = &fields[0];
            assert_eq!(field.field, "body");
            assert!(field.optional_owner_prefixes.is_empty());
            assert!(field.nullable_owner_prefixes.is_empty());
            assert_eq!(
                field.optional,
                action.action == "page.view"
                    || action.action == "blog.view"
                    || (action.read_only && action.action.contains("comment")),
                "{}",
                action.action
            );
        }
    }
    for action in [
        "search",
        "space.list",
        "verify",
        "blog.search",
        "blog.verify",
        "page.draft.verify",
        "blog.draft.verify",
        "attachment.list",
        "blog.attachment.list",
        "page.draft.attachment.list",
        "blog.draft.attachment.list",
        "page.create",
    ] {
        assert!(presentation(action, &config()).is_none(), "{action}");
    }
}

#[test]
fn every_action_selects_only_one_body_at_its_semantic_path() {
    for (action, kind) in BODY_ACTIONS {
        for format in presentation(action, &config())
            .unwrap()
            .output_content_formats()
        {
            let body = if *format == OutputContentFormat::Adf {
                adf_body("Selected body")
            } else {
                storage("<p>Selected body</p>")
            };
            let mut original = match kind {
                BodyKind::Page | BodyKind::Draft => json!({"id":"10","version":7,"body":body}),
                BodyKind::Blog => json!({"blogId":"20","body":{"storage":"<p>Selected body</p>"}}),
                BodyKind::CommentRead | BodyKind::CommentWrite => {
                    json!({"comment":{"commentId":"30","body":body}})
                }
                BodyKind::Comments => json!({"comments":[{"commentId":"30","body":body}],
                    "count":1,"nextPageToken":"opaque-token","hasMore":true}),
            };
            let mut result = select(
                action,
                &config(),
                original.clone(),
                Some(*format),
                None,
                4096,
                16384,
            )
            .unwrap();
            let pointer = match kind {
                BodyKind::Page | BodyKind::Blog | BodyKind::Draft => "/body",
                BodyKind::CommentRead | BodyKind::CommentWrite => "/comment/body",
                BodyKind::Comments => "/comments/0/body",
            };
            let selected = result.pointer(pointer).unwrap();
            assert_eq!(selected["format"], format.as_str(), "{action}");
            assert_eq!(selected.as_object().unwrap().len(), 2, "{action}");
            if *format == OutputContentFormat::Adf {
                assert_eq!(selected["value"], adf("Selected body"));
            } else if *format == OutputContentFormat::Storage {
                assert_eq!(selected["value"], "<p>Selected body</p>");
            } else {
                assert_eq!(selected["value"], "Selected body");
            }
            *original.pointer_mut(pointer).unwrap() = Value::Null;
            *result.pointer_mut(pointer).unwrap() = Value::Null;
            assert_eq!(original, result, "{action} metadata changed");
        }
    }
}

#[test]
fn configured_capabilities_and_preferences_resolve_without_lower_tier_cascade() {
    for (sources, formats, native) in [
        (
            vec!["atlas_doc_format".into()],
            ADF_FORMATS,
            OutputContentFormat::Adf,
        ),
        (
            vec!["storage".into()],
            STORAGE_FORMATS,
            OutputContentFormat::Storage,
        ),
        (
            vec!["storage".into(), "atlas_doc_format".into()],
            ALL_FORMATS,
            OutputContentFormat::Adf,
        ),
    ] {
        let mut config = config();
        config.page_formats = sources;
        config.preferred_output_format = Some(OutputContentFormat::Text);
        let p = presentation("page.view", &config).unwrap();
        assert_eq!(p.output_content_formats(), formats);
        assert_eq!(p.native_output_content_format(), native);
        assert_eq!(
            resolve_response_options(Some(p), None, ResponseOptions::default())
                .unwrap()
                .output_content_format(),
            Some(OutputContentFormat::Markdown)
        );
        assert_eq!(
            resolve_response_options(
                Some(p),
                config.preferred_output_format,
                ResponseOptions::default()
            )
            .unwrap()
            .output_content_format(),
            Some(OutputContentFormat::Text)
        );
        let unavailable = if native == OutputContentFormat::Adf {
            OutputContentFormat::Storage
        } else {
            OutputContentFormat::Adf
        };
        if !formats.contains(&unavailable) {
            assert_eq!(
                resolve_response_options(
                    Some(p),
                    config.preferred_output_format,
                    ResponseOptions::new(None, Some(unavailable))
                )
                .unwrap()
                .output_content_format(),
                Some(native)
            );
            let error = resolve_response_options(
                Some(p),
                None,
                ResponseOptions::new(Some(unavailable), None),
            )
            .err()
            .unwrap();
            assert_eq!(error.reason_code(), ReasonCode::ResponseFormatUnsupported);
        }
    }
    let mut empty = config();
    empty.page_formats.clear();
    empty.comment_formats.clear();
    empty.blog_formats.clear();
    for action in [
        "page.view",
        "page.footer_comment.view",
        "blog.inline_comment.reply.list",
    ] {
        assert!(presentation(action, &empty).is_none());
    }
    for action in ["blog.view", "page.draft.view", "blog.draft.view"] {
        assert_eq!(
            presentation(action, &empty)
                .unwrap()
                .output_content_formats(),
            STORAGE_FORMATS
        );
    }
}

#[test]
fn optional_source_absence_never_changes_a_resolved_native_format() {
    for (body, missing) in [
        (storage("<p>Storage</p>"), OutputContentFormat::Adf),
        (adf_body("ADF"), OutputContentFormat::Storage),
    ] {
        for exact in [true, false] {
            let result = select(
                "page.view",
                &config(),
                json!({"id":"10","body":body}),
                exact.then_some(missing),
                (!exact).then_some(missing),
                4096,
                16384,
            )
            .unwrap();
            assert_eq!(result, json!({"id":"10"}));
        }
    }
    for action in ["page.view", "blog.view"] {
        assert_eq!(
            select(
                action,
                &config(),
                json!({"id":"10","body":{}}),
                None,
                None,
                4096,
                16384
            )
            .unwrap(),
            json!({"id":"10"})
        );
        assert_eq!(
            select(
                action,
                &config(),
                json!({"id":"10"}),
                None,
                None,
                4096,
                16384
            )
            .unwrap(),
            json!({"id":"10"})
        );
    }
    let empty = select(
        "page.view",
        &config(),
        json!({"body":storage("")}),
        None,
        None,
        4096,
        16384,
    )
    .unwrap();
    assert_eq!(empty["body"], json!({"format":"markdown","value":""}));
    for action in ["page.draft.view", "blog.draft.view"] {
        assert!(
            select(
                action,
                &config(),
                json!({"body":{}}),
                None,
                None,
                4096,
                16384
            )
            .is_err()
        );
    }
    assert!(
        select(
            "page.footer_comment.add",
            &config(),
            json!({"comment":{"body":{}}}),
            None,
            None,
            4096,
            16384
        )
        .is_err()
    );
}

#[test]
fn every_configured_source_is_validated_even_when_unselected_or_native_is_absent() {
    for format in ALL_FORMATS {
        for mut body in [
            json!({"atlas_doc_format":{"representation":"atlas_doc_format","value":"{invalid"},
                "storage":{"representation":"storage","value":"<p>valid</p>"}}),
            json!({"atlas_doc_format":{"representation":"atlas_doc_format","value":adf("valid").to_string()},
                "storage":{"representation":"storage","value":"<ac:link>"}}),
        ] {
            let error = select(
                "page.view",
                &config(),
                json!({"body":body}),
                Some(*format),
                None,
                4096,
                16384,
            )
            .unwrap_err();
            assert_eq!(error.reason_code(), ReasonCode::UpstreamProtocolFailed);
            assert!(!format!("{error:?}").contains("{invalid"));
            body.as_object_mut().unwrap().remove("atlas_doc_format");
            if *format == OutputContentFormat::Adf && body["storage"]["value"] == "<ac:link>" {
                assert!(
                    select(
                        "page.view",
                        &config(),
                        json!({"body":body}),
                        Some(*format),
                        None,
                        4096,
                        16384
                    )
                    .is_err()
                );
            }
        }
    }
    let mut both = adf_body("ADF wins");
    both.as_object_mut()
        .unwrap()
        .extend(storage("<p>Other body</p>").as_object().unwrap().clone());
    assert_eq!(
        select(
            "page.view",
            &config(),
            json!({"body":both}),
            None,
            None,
            4096,
            16384
        )
        .unwrap()["body"]["value"],
        "ADF wins"
    );
}

#[test]
fn source_selection_and_final_result_limits_remain_independent() {
    let body = storage(&format!("<p>{}</p>", "*".repeat(64)));
    let native = select(
        "page.view",
        &config(),
        json!({"body":body}),
        Some(OutputContentFormat::Storage),
        None,
        80,
        4096,
    )
    .unwrap();
    assert_eq!(native["body"]["format"], "storage");
    assert!(
        select(
            "page.view",
            &config(),
            json!({"body":body}),
            None,
            None,
            80,
            4096
        )
        .is_err()
    );
    assert!(
        select(
            "page.view",
            &config(),
            json!({"body":body}),
            Some(OutputContentFormat::Storage),
            None,
            32,
            4096
        )
        .is_err()
    );
    assert!(
        select(
            "page.view",
            &config(),
            json!({"metadata":"x".repeat(500),"body":storage("<p>x</p>")}),
            None,
            None,
            1024,
            100
        )
        .is_err()
    );
    let mut budget = RenderBudget::with_limits(1, 1000);
    assert!(
        ConfluenceBodyMap
            .select(
                &adf_body("too much structure"),
                OutputContentFormat::Adf,
                4096,
                &mut budget
            )
            .is_err()
    );
}
