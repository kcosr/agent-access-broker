use super::*;

const SENTINEL: &str = "PRIVATE_INPUT_SENTINEL";
const HEAD: &str = "1111111111111111111111111111111111111111";

fn assert_input_denial(error: ProviderError, message: &str) {
    assert_eq!(error.reason_code(), ReasonCode::InputInvalid);
    assert_eq!(error.decision(), Decision::Deny);
    assert_eq!(error.message, message);
    assert!(!error.message.contains(SENTINEL));
    assert!(error.result.is_none());
    assert!(error.audit.is_none());
    assert!(error.upstream_status.is_none());
    assert!(error.upstream_duration_ms.is_none());
    assert!(error.object_ids.is_none());
    assert!(error.internal_diagnostic_code.is_none());
}

fn with_fields(mut base: Value, fields: Value) -> Value {
    base.as_object_mut()
        .unwrap()
        .extend(fields.as_object().unwrap().clone());
    base
}

fn file_position() -> Value {
    json!({"positionType":"file", "oldPath":"a.rs", "newPath":"a.rs"})
}

#[test]
fn project_locators_preserve_presence_types_and_action_context() {
    let config = config();
    for action in ["gitlab project.view", "gitlab project.upload"] {
        for (input, suffix) in [
            (json!({}), "requires project or url"),
            (
                json!({"project":SENTINEL, "url":SENTINEL}),
                "accepts project or url, not both",
            ),
            (
                json!({"project":"team/service", "url":null}),
                "accepts project or url, not both",
            ),
            (
                json!({"project":null, "url":null}),
                "accepts project or url, not both",
            ),
        ] {
            assert_input_denial(
                parse_project_locator_for_action(&input, &config, action)
                    .err()
                    .unwrap(),
                &format!("{action} {suffix}"),
            );
        }
        for (input, message) in [
            (json!({"project":null}), "project must be a string"),
            (json!({"url":null}), "url must be a string"),
            (json!({"project":7}), "project must be a string"),
            (json!({"url":false}), "url must be a string"),
        ] {
            assert_input_denial(
                parse_project_locator_for_action(&input, &config, action)
                    .err()
                    .unwrap(),
                message,
            );
        }
        for input in [
            json!({"project":" /team/service/ "}),
            json!({"url":"https://gitlab.example.com/team/service"}),
        ] {
            assert_eq!(
                parse_project_locator_for_action(&input, &config, action)
                    .unwrap()
                    .project,
                "team/service"
            );
        }
    }
    // Locator-invalid outcomes remain separate from input-invalid explanations.
    assert_eq!(
        parse_project_locator(&json!({"project":SENTINEL}), &config)
            .err()
            .unwrap()
            .reason_code(),
        ReasonCode::LocatorInvalid
    );
}

#[test]
fn numbered_locators_preserve_every_presence_tuple_and_numeric_strings() {
    let config = config();
    for (action, segment) in [
        ("gitlab issue.view", "issues"),
        ("gitlab merge_request.view", "merge_requests"),
    ] {
        let url = format!("https://gitlab.example.com/team/service/-/{segment}/7");
        for (input, suffix) in [
            (json!({}), "requires project with iid or url"),
            (
                json!({"project":"team/service"}),
                "requires project and iid together",
            ),
            (json!({"iid":7}), "requires project and iid together"),
            (
                json!({"project":SENTINEL,"url":url}),
                "accepts project with iid or url, not both",
            ),
            (
                json!({"iid":null,"url":url}),
                "accepts project with iid or url, not both",
            ),
            (
                json!({"project":null,"iid":null,"url":null}),
                "accepts project with iid or url, not both",
            ),
        ] {
            assert_input_denial(
                parse_numbered_object_locator(&input, &config, segment, action)
                    .err()
                    .unwrap(),
                &format!("{action} {suffix}"),
            );
        }
        for input in [
            json!({"project":"team/service","iid":7}),
            json!({"project":"team/service","iid":"7"}),
            json!({"url":url}),
        ] {
            let (project, iid) =
                parse_numbered_object_locator(&input, &config, segment, action).unwrap();
            assert_eq!((project.project.as_str(), iid), ("team/service", 7));
        }
        for iid in [
            Value::Null,
            json!(false),
            json!(0),
            json!("0"),
            json!(SENTINEL),
        ] {
            assert_input_denial(
                parse_numbered_object_locator(
                    &json!({"project":"team/service","iid":iid}),
                    &config,
                    segment,
                    action,
                )
                .err()
                .unwrap(),
                "iid must be a positive integer",
            );
        }
    }
}

#[test]
fn upload_metadata_precedes_locator_and_policy_checks_stay_separate() {
    let config = config();
    let (valid, _) = upload_fixture();
    let mut missing_locator = valid.clone();
    missing_locator.as_object_mut().unwrap().remove("project");
    assert_input_denial(
        parse_project_upload_inputs(&missing_locator, &config)
            .err()
            .unwrap(),
        "gitlab project.upload requires project or url",
    );
    let mut both = valid.clone();
    both["url"] = json!(SENTINEL);
    assert_input_denial(
        parse_project_upload_inputs(&both, &config).err().unwrap(),
        "gitlab project.upload accepts project or url, not both",
    );
    for attachments in [
        Value::Null,
        json!([]),
        json!([{}, {}]),
        json!([{"field":SENTINEL}]),
    ] {
        assert_input_denial(
            parse_project_upload_inputs(&json!({"attachments":attachments}), &config)
                .err()
                .unwrap(),
            "gitlab project.upload attachments must contain one metadata object with field, filename, contentType, size and sha256",
        );
    }
    for (field, value, message) in [
        (
            "field",
            json!("\n"),
            "gitlab project.upload attachments.field must be non-empty and contain no control characters",
        ),
        (
            "filename",
            json!(format!("../{SENTINEL}")),
            "gitlab project.upload attachments.filename must be a non-empty filename without path separators, dot components or control characters",
        ),
        (
            "sha256",
            json!(SENTINEL),
            "gitlab project.upload attachments.sha256 must contain exactly 64 lowercase hexadecimal characters",
        ),
    ] {
        let mut input = missing_locator.clone();
        input["attachments"][0][field] = value;
        assert_input_denial(
            parse_project_upload_inputs(&input, &config).err().unwrap(),
            message,
        );
    }
    for (field, value, reason) in [
        ("size", json!(0), ReasonCode::AttachmentSizeDenied),
        (
            "contentType",
            json!("invalid mime type"),
            ReasonCode::AttachmentMediaTypeDenied,
        ),
    ] {
        let mut input = valid.clone();
        input["attachments"][0][field] = value;
        assert!(parse_project_upload_inputs(&input, &config).is_ok());
        assert_eq!(
            parse_admitted_project_upload_inputs(&input, &config)
                .err()
                .unwrap()
                .reason_code(),
            reason
        );
    }
}

#[test]
fn converted_optional_content_actions_preserve_pairs_and_non_input_reasons() {
    let cases = [
        (
            "issue.create",
            json!({"project":"team/service","title":"title"}),
        ),
        (
            "issue.update",
            json!({"project":"team/service","iid":7,"title":"title"}),
        ),
        (
            "merge_request.create",
            json!({"project":"team/service","sourceBranch":"topic","targetBranch":"main","title":"title"}),
        ),
        (
            "merge_request.update",
            json!({"project":"team/service","iid":7,"title":"title"}),
        ),
        (
            "merge_request.draft_note.update",
            json!({"project":"team/service","iid":7,"draftNoteId":2,"expectedHeadSha":HEAD,"position":file_position()}),
        ),
        (
            "merge_request.draft_note.publish_all",
            json!({"project":"team/service","iid":7}),
        ),
        (
            "merge_request.review.submit",
            json!({"project":"team/service","iid":7,"reviewerState":"reviewed"}),
        ),
    ];
    let parse = |action: &str, input: &Value| -> Result<(), ProviderError> {
        match action {
            "issue.create" => parse_issue_create_inputs(input, 1024).map(|_| ()),
            "issue.update" => parse_issue_update_inputs(input, 1024).map(|_| ()),
            "merge_request.create" => parse_merge_request_create_inputs(input, 1024).map(|_| ()),
            "merge_request.update" => parse_merge_request_update_inputs(input, 1024).map(|_| ()),
            "merge_request.draft_note.update" => {
                parse_draft_note_update_inputs(input, 1024).map(|_| ())
            }
            "merge_request.draft_note.publish_all" => {
                parse_draft_publication_inputs(input, 1024, false).map(|_| ())
            }
            "merge_request.review.submit" => {
                parse_draft_publication_inputs(input, 1024, true).map(|_| ())
            }
            _ => unreachable!(),
        }
    };
    for (action, base) in cases {
        assert!(parse(action, &base).is_ok(), "{action}");
        for fields in [
            json!({"content":SENTINEL}),
            json!({"contentFormat":"markdown"}),
            json!({"content":null}),
        ] {
            assert_input_denial(
                parse(action, &with_fields(base.clone(), fields)).unwrap_err(),
                &format!("gitlab {action} requires content and contentFormat together"),
            );
        }
        for format in ["markdown", "plain_text"] {
            assert!(
                parse(
                    action,
                    &with_fields(base.clone(), json!({"content":"", "contentFormat":format}))
                )
                .is_ok(),
                "{action}: {format}"
            );
        }
        for (fields, reason) in [
            (
                json!({"content":SENTINEL,"contentFormat":"html"}),
                ReasonCode::BodyFormatUnsupported,
            ),
            (
                json!({"content":"x".repeat(1025),"contentFormat":"markdown"}),
                ReasonCode::BodySizeDenied,
            ),
        ] {
            let error = parse(action, &with_fields(base.clone(), fields)).unwrap_err();
            assert_eq!(error.reason_code(), reason, "{action}");
            assert!(!error.message.contains(SENTINEL));
        }
        for (fields, message) in [
            (
                json!({"content":null,"contentFormat":"markdown"}),
                "content must be a string",
            ),
            (
                json!({"content":SENTINEL,"contentFormat":null}),
                "contentFormat must be a string",
            ),
        ] {
            assert_input_denial(
                parse(action, &with_fields(base.clone(), fields)).unwrap_err(),
                message,
            );
        }
    }
}

#[test]
fn draft_add_modes_preserve_false_empty_reply_and_relational_precedence() {
    let base =
        json!({"project":"team/service","iid":7,"content":SENTINEL,"contentFormat":"markdown"});
    for fields in [
        json!({}),
        json!({"expectedHeadSha":HEAD,"position":file_position()}),
        json!({"inReplyToDiscussionId":"d"}),
        json!({"inReplyToDiscussionId":"","resolveDiscussion":false}),
        json!({"inReplyToDiscussionId":"d","resolveDiscussion":true}),
    ] {
        assert!(parse_draft_note_add_inputs(&with_fields(base.clone(), fields), 1024).is_ok());
    }
    for (fields, message) in [
        (
            json!({"position":file_position()}),
            "gitlab merge_request.draft_note.add requires position and expectedHeadSha together",
        ),
        (
            json!({"expectedHeadSha":HEAD,"inReplyToDiscussionId":SENTINEL,"resolveDiscussion":false}),
            "gitlab merge_request.draft_note.add requires position and expectedHeadSha together",
        ),
        (
            json!({"expectedHeadSha":HEAD,"position":file_position(),"inReplyToDiscussionId":SENTINEL}),
            "gitlab merge_request.draft_note.add accepts position with expectedHeadSha or inReplyToDiscussionId, not both",
        ),
        (
            json!({"resolveDiscussion":false}),
            "gitlab merge_request.draft_note.add resolveDiscussion requires inReplyToDiscussionId",
        ),
        (
            json!({"expectedHeadSha":HEAD,"position":file_position(),"resolveDiscussion":true}),
            "gitlab merge_request.draft_note.add resolveDiscussion requires inReplyToDiscussionId",
        ),
        (
            json!({"expectedHeadSha":null}),
            "expectedHeadSha must be a string",
        ),
        (
            json!({"inReplyToDiscussionId":null}),
            "inReplyToDiscussionId must be a string",
        ),
        (
            json!({"resolveDiscussion":null}),
            "resolveDiscussion must be a boolean",
        ),
    ] {
        assert_input_denial(
            parse_draft_note_add_inputs(&with_fields(base.clone(), fields), 1024)
                .err()
                .unwrap(),
            message,
        );
    }
}

#[test]
fn draft_update_requires_a_complete_pair_and_preserves_body_first_validation() {
    let base = json!({"project":"team/service","iid":7,"draftNoteId":2});
    for fields in [
        json!({"content":"","contentFormat":"plain_text"}),
        json!({"position":file_position(),"expectedHeadSha":HEAD}),
        json!({"content":SENTINEL,"contentFormat":"markdown","position":file_position(),"expectedHeadSha":HEAD}),
    ] {
        assert!(parse_draft_note_update_inputs(&with_fields(base.clone(), fields), 1024).is_ok());
    }
    for (fields, message) in [
        (
            json!({}),
            "gitlab merge_request.draft_note.update requires content with contentFormat or position with expectedHeadSha",
        ),
        (
            json!({"position":file_position()}),
            "gitlab merge_request.draft_note.update requires position and expectedHeadSha together",
        ),
        (
            json!({"expectedHeadSha":HEAD}),
            "gitlab merge_request.draft_note.update requires position and expectedHeadSha together",
        ),
        (
            json!({"content":SENTINEL,"position":null}),
            "gitlab merge_request.draft_note.update requires content and contentFormat together",
        ),
        (
            json!({"content":SENTINEL,"contentFormat":"markdown","expectedHeadSha":HEAD}),
            "gitlab merge_request.draft_note.update requires position and expectedHeadSha together",
        ),
    ] {
        assert_input_denial(
            parse_draft_note_update_inputs(&with_fields(base.clone(), fields), 1024)
                .err()
                .unwrap(),
            message,
        );
    }
}

#[test]
fn publication_internal_requires_summary_even_when_false() {
    for review in [false, true] {
        let mut base = json!({"project":"team/service","iid":7});
        if review {
            base["reviewerState"] = json!("reviewed");
        }
        let action = if review {
            "merge_request.review.submit"
        } else {
            "merge_request.draft_note.publish_all"
        };
        assert!(parse_draft_publication_inputs(&base, 1024, review).is_ok());
        for internal in [false, true] {
            assert_input_denial(
                parse_draft_publication_inputs(
                    &with_fields(base.clone(), json!({"internal":internal})),
                    1024,
                    review,
                )
                .err()
                .unwrap(),
                &format!("gitlab {action} internal requires content and contentFormat"),
            );
            let parsed = parse_draft_publication_inputs(
                &with_fields(
                    base.clone(),
                    json!({"internal":internal,"content":"","contentFormat":"markdown"}),
                ),
                1024,
                review,
            )
            .unwrap();
            assert_eq!(parsed.internal, Some(internal));
            assert_eq!(parsed.summary.as_deref(), Some(""));
        }
        assert_input_denial(
            parse_draft_publication_inputs(
                &with_fields(base.clone(), json!({"internal":null})),
                1024,
                review,
            )
            .err()
            .unwrap(),
            "internal must be a boolean",
        );
    }
}

#[test]
fn position_relations_retain_all_modes_and_field_validation_order() {
    for fields in [
        json!({"positionType":"text","oldLine":1}),
        json!({"positionType":"text","newLine":2}),
        json!({"positionType":"text","oldLine":1,"newLine":2}),
        json!({"positionType":"text","lineRange":{"start":{"oldLine":1},"end":{"oldLine":2,"newLine":3}}}),
        json!({"positionType":"file"}),
        json!({"positionType":"image","width":10,"height":20,"x":0,"y":0}),
    ] {
        assert!(parse_position_input(Some(&with_fields(file_position(), fields))).is_ok());
    }
    for fields in [
        json!({"positionType":"text"}),
        json!({"positionType":"text","width":2,"oldLine":1}),
        json!({"positionType":"text","oldLine":1,"lineRange":{"start":{"newLine":1},"end":{"newLine":2}}}),
    ] {
        assert_input_denial(
            parse_position_input(Some(&with_fields(file_position(), fields)))
                .err()
                .unwrap(),
            "positionType text requires oldLine or newLine, or lineRange without top-level oldLine or newLine; width, height, x and y are not accepted",
        );
    }
    for fields in [
        json!({"oldLine":1}),
        json!({"width":2}),
        json!({"lineRange":{"start":{"oldLine":1},"end":{"newLine":2}}}),
    ] {
        assert_input_denial(
            parse_position_input(Some(&with_fields(file_position(), fields)))
                .err()
                .unwrap(),
            "positionType file does not accept oldLine, newLine, lineRange, width, height, x or y",
        );
    }
    for fields in [
        json!({"positionType":"image","width":10,"height":20,"x":0}),
        json!({"positionType":"image","width":10,"height":20,"x":0,"y":0,"newLine":1}),
    ] {
        assert_input_denial(
            parse_position_input(Some(&with_fields(file_position(), fields)))
                .err()
                .unwrap(),
            "positionType image requires width, height, x and y and does not accept oldLine, newLine or lineRange",
        );
    }
    // Scalar validation still precedes variant checks, including unknown variants.
    for (fields, message) in [
        (
            json!({"positionType":SENTINEL}),
            "position.positionType must be text, file or image",
        ),
        (
            json!({"positionType":SENTINEL,"oldLine":null}),
            "oldLine must be a positive integer",
        ),
        (
            json!({"positionType":"file","oldLine":"1"}),
            "oldLine must be a positive integer",
        ),
        (
            json!({"positionType":"text","width":null}),
            "width must be a positive integer",
        ),
        (
            json!({"positionType":"file","x":-1}),
            "x must be a non-negative integer",
        ),
    ] {
        assert_input_denial(
            parse_position_input(Some(&with_fields(file_position(), fields)))
                .err()
                .unwrap(),
            message,
        );
    }
}

#[test]
fn multiline_endpoints_preserve_required_objects_and_line_alternatives() {
    for (range, message) in [
        (
            json!({}),
            "position.lineRange.start must be an object with oldLine or newLine",
        ),
        (
            json!({"start":null,"end":{"newLine":2}}),
            "position.lineRange.start must be an object with oldLine or newLine",
        ),
        (
            json!({"start":{},"end":{}}),
            "position.lineRange.start requires oldLine or newLine",
        ),
        (
            json!({"start":{"oldLine":1}}),
            "position.lineRange.end must be an object with oldLine or newLine",
        ),
        (
            json!({"start":{"oldLine":1},"end":{}}),
            "position.lineRange.end requires oldLine or newLine",
        ),
        (
            json!({"start":{"oldLine":null},"end":{"newLine":2}}),
            "oldLine must be a positive integer",
        ),
        (
            json!({"start":{"oldLine":1,"unexpected":SENTINEL},"end":{"newLine":2}}),
            "position.lineRange.start accepts only oldLine or newLine input fields",
        ),
    ] {
        assert_input_denial(parse_line_range_input(&range).err().unwrap(), message);
    }
    for start in [
        json!({"oldLine":1}),
        json!({"newLine":1}),
        json!({"oldLine":1,"newLine":1}),
    ] {
        for end in [
            json!({"oldLine":2}),
            json!({"newLine":2}),
            json!({"oldLine":2,"newLine":2}),
        ] {
            assert!(parse_line_range_input(&json!({"start":start,"end":end})).is_ok());
        }
    }
}

#[test]
fn webhook_update_keeps_false_null_mutations_and_value_dependent_token_conflict() {
    let base = json!({"project":"team/service","webhookId":3});
    let empty_message = "gitlab webhook.update requires at least one of url, events, name, description, enableSslVerification, branchFilterStrategy, pushEventsBranchFilter, customWebhookTemplate, token, signingToken or clearToken: true; confirmDestinationReset does not count";
    for fields in [
        json!({}),
        json!({"clearToken":false}),
        json!({"confirmDestinationReset":false}),
        json!({"confirmDestinationReset":true}),
    ] {
        assert_input_denial(
            parse_webhook_write_inputs(&with_fields(base.clone(), fields), false, 1024)
                .err()
                .unwrap(),
            empty_message,
        );
    }
    for fields in [
        json!({"url":"https://hooks.example.com/endpoint"}),
        json!({"events":[]}),
        json!({"name":null}),
        json!({"description":null}),
        json!({"customWebhookTemplate":null}),
        json!({"enableSslVerification":false}),
        json!({"branchFilterStrategy":"all_branches"}),
        json!({"pushEventsBranchFilter":""}),
        json!({"token":SENTINEL,"clearToken":false}),
        json!({"clearToken":true}),
        json!({"signingToken":format!("whsec_{}=", "A".repeat(43))}),
    ] {
        assert!(
            parse_webhook_write_inputs(&with_fields(base.clone(), fields.clone()), false, 1024)
                .is_ok(),
            "{fields:?}"
        );
    }
    assert_input_denial(
        parse_webhook_write_inputs(
            &with_fields(base.clone(), json!({"token":SENTINEL,"clearToken":true})),
            false,
            1024,
        )
        .err()
        .unwrap(),
        "gitlab webhook.update token and clearToken: true cannot be combined",
    );
    assert_input_denial(
        parse_webhook_write_inputs(&with_fields(base, json!({"clearToken":null})), false, 1024)
            .err()
            .unwrap(),
        "clearToken must be a boolean",
    );
    // Retain the published scalar constraint even though the parser accepts false.
    assert_eq!(
        webhook_update_schema()["properties"]["clearToken"]["const"],
        true
    );
    assert_eq!(
        webhook_update_schema()["properties"]["token"]["x-agent-access-sensitive"],
        true
    );
    assert_eq!(
        webhook_update_schema()["properties"]["signingToken"]["x-agent-access-sensitive"],
        true
    );
}
