use super::*;
use serde_json::json;

fn settings(preferred: Option<OutputContentFormat>) -> ResolvedCliSettings {
    ResolvedCliSettings {
        url: "http://127.0.0.1:8787".into(),
        request_timeout_ms: 30_000,
        tls: Default::default(),
        token: None,
        token_from_literal_arg: false,
        identity_header: "X-Agent-Access-Identity-Token".into(),
        identity_scheme: "raw".into(),
        allow_insecure_broker_http: false,
        preferred_output_content_format: preferred,
    }
}

#[test]
fn exact_content_flags_are_closed_and_retired_invocation_flags_are_rejected() {
    for format in ["markdown", "text", "adf", "storage"] {
        for prefix in [
            vec!["invoke", "jira.issue.view"],
            vec!["jira", "issue", "view", "SBC-1"],
            vec!["confluence", "page", "view", "123"],
        ] {
            let mut args = vec!["agent-access"];
            args.extend(prefix);
            args.extend(["--output-content-format", format]);
            Cli::try_parse_from(args).unwrap();
        }
    }
    for flag in ["--read-content-format", "--output-format"] {
        assert!(
            Cli::try_parse_from([
                "agent-access",
                "invoke",
                "jira.issue.view",
                flag,
                "markdown"
            ])
            .is_err()
        );
    }
    for format in ["native", "json", "plain_text", "html"] {
        assert!(
            Cli::try_parse_from([
                "agent-access",
                "invoke",
                "jira.issue.view",
                "--output-content-format",
                format
            ])
            .is_err()
        );
    }
    Cli::try_parse_from(["agent-access", "spec", "catalog", "--output-format", "json"]).unwrap();
    assert!(
        Cli::try_parse_from(["agent-access", "spec", "catalog", "--output-format", "yaml"])
            .is_err()
    );
}

#[test]
fn undiscovered_action_preserves_preference_and_refuses_exact_selection() {
    let settings = settings(Some(OutputContentFormat::Storage));
    let options = resolve_response_options(&settings, None, None, "jira.issue.view").unwrap();
    assert_eq!(options.output_content_format, None);
    assert_eq!(
        options.preferred_output_content_format,
        Some(OutputContentFormat::Storage)
    );
    let error = resolve_response_options(
        &settings,
        Some(OutputContentFormat::Adf),
        None,
        "jira.issue.view",
    )
    .unwrap_err();
    assert!(error.to_string().contains("does not expose action"));
}

#[test]
fn selected_content_validation_preserves_completion_and_never_copies_rejected_content() {
    let fields = [BodyField::new("/result", "description").nullable()];
    for body in [
        json!({"format":"adf","value":"PRIVATE"}),
        json!({"format":"unknown","value":"PRIVATE"}),
        json!({"format":"markdown","value":42}),
        json!({"format":"text","value":"PRIVATE","extra":true}),
    ] {
        let value = json!({"decision":"allow", "agentRequestId":"agent", "brokerRequestId":"broker", "service":"jira", "action":"issue.update", "result":{"description":body,"mutationStatus":"applied","retrySafe":false,"safeLocators":{"issueId":"42"}}});
        let error = validate_invoke_result(200, &value, None, &fields, &[]).unwrap_err();
        let failure = error
            .downcast_ref::<output::ResponseContentFailure>()
            .unwrap();
        assert_eq!(failure.details["reasonCode"], "response_content_invalid");
        assert_eq!(failure.details["operationStatus"], "succeeded");
        assert_eq!(failure.details["mutationStatus"], "applied");
        assert_eq!(failure.details["retrySafe"], false);
        assert_eq!(failure.details["brokerRequestId"], "broker");
        assert_eq!(failure.details["safeLocators"]["issueId"], "42");
        assert!(failure.details.get("output").is_none());
        assert!(!failure.details.to_string().contains("PRIVATE"));
    }
}

#[test]
fn preference_accepts_new_native_format_and_optional_absence_after_reload() {
    let fields = [BodyField::new("/result", "body").optional()];
    let native = json!({"decision":"allow","result":{"body":{"format":"adf","value":{"type":"doc","version":1,"content":[]}}}});
    validate_invoke_result(200, &native, None, &fields, &[]).unwrap();
    assert!(
        validate_invoke_result(
            200,
            &native,
            Some(OutputContentFormat::Storage),
            &fields,
            &[]
        )
        .is_err()
    );
    validate_invoke_result(
        200,
        &json!({"decision":"allow","result":{"title":"metadata"}}),
        None,
        &fields,
        &[],
    )
    .unwrap();
    assert!(
        validate_invoke_result(
            200,
            &json!({"decision":"allow","result":{"body":{}}}),
            None,
            &fields,
            &[]
        )
        .is_err()
    );
}

#[test]
fn compact_error_receipts_bypass_success_body_validation() {
    let receipt = json!({"decision":"allow","reasonCode":"body_size_denied","result":{"mutationStatus":"applied","retrySafe":false}});
    validate_invoke_result(
        413,
        &receipt,
        Some(OutputContentFormat::Markdown),
        &[BodyField::new("/result", "body")],
        &[],
    )
    .unwrap();

    for (mutation, retry_safe) in [
        ("unknown", false),
        ("not_applied", true),
        ("applied", false),
        ("applied_unverified", false),
        ("applied_verified", false),
    ] {
        let receipt = json!({"decision":"allow","reasonCode":"verification_mismatch","reason":"Original provider outcome","result":{"mutationStatus":mutation,"retrySafe":retry_safe,"verificationStage":"readback","safeLocators":{"id":"42"}}});
        let original = receipt.clone();
        validate_invoke_result(
            200,
            &receipt,
            Some(OutputContentFormat::Markdown),
            &[BodyField::new("/result", "body")],
            &[],
        )
        .unwrap();
        assert_eq!(receipt, original);
    }
}

#[test]
fn only_recognized_bounded_compact_receipts_bypass_content_validation() {
    let base = json!({"decision":"allow","reasonCode":"verification_mismatch","result":{"mutationStatus":"unknown","retrySafe":false}});
    for (path, value) in [
        ("/result/mutationStatus", json!("future-status")),
        ("/result/retrySafe", json!(true)),
        ("/result/safeLocators", json!({"id":"x".repeat(513)})),
        ("/result/verificationStage", json!("x".repeat(129))),
        ("/result/body", json!({"format":"markdown","value":42})),
        ("/reasonCode", json!(null)),
    ] {
        let mut receipt = base.clone();
        let (owner, field) = path.rsplit_once('/').unwrap();
        receipt.pointer_mut(owner).unwrap()[field] = value;
        assert!(
            validate_invoke_result(
                200,
                &receipt,
                None,
                &[BodyField::new("/result", "body")],
                &[],
            )
            .is_err(),
            "{path}"
        );
    }
}

#[test]
fn send_selectors_reject_explicit_null_retired_names_and_unknown_formats() {
    for name in ["outputContentFormat", "preferredOutputContentFormat"] {
        for value in [json!(null), json!("native"), json!(false), json!(2)] {
            let mut request = json!({"version":SEND_SCHEMA_VERSION,"kind":"invoke","service":"jira","action":"issue.view","inputs":{}});
            request[name] = value;
            assert!(parse_send_request(request).is_err());
        }
    }
    for name in ["readContentFormat", "responseFormat"] {
        let mut request = json!({"version":SEND_SCHEMA_VERSION,"kind":"invoke","service":"jira","action":"issue.view","inputs":{}});
        request[name] = json!("markdown");
        assert!(parse_send_request(request).is_err());
    }
}

#[test]
fn invalid_content_receipt_bounds_ids_and_omits_sensitive_reconciliation_metadata() {
    let value = json!({"decision":"allow","brokerRequestId":"x".repeat(1_000_000),"result":{"mutationStatus":"applied","retrySafe":false,"safeLocators":{"id":"PRIVATE"}}});
    let failure = output::ResponseContentFailure::new(&value, &["/result/safeLocators".into()]);
    assert!(failure.details.to_string().len() < 1024);
    assert!(failure.details.get("brokerRequestId").is_none());
    assert!(failure.details.get("safeLocators").is_none());
}
