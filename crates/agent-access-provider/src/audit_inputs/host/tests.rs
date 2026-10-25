use super::*;
use serde_json::json;

fn text(key: &str, pointer: &str) -> AuditInputRule {
    AuditInputRule::value(key, key, pointer)
        .kind(AuditValueKind::Text)
        .max_bytes(1024)
        .overflow(AuditOverflow::Prefix)
}

#[test]
fn prepared_plan_captures_requested_facts_without_schema_value_validation() {
    let schema = json!({"properties":{"title":{"type":"string","enum":["approved"]},"flag":{"type":"boolean"}}});
    let plan = prepare_audit_inputs(
        &schema,
        &AuditInputProjection::new([
            text("title", "/title"),
            AuditInputRule::value("flag", "Flag", "/flag").kind(AuditValueKind::Boolean),
        ]),
    )
    .unwrap();
    let captured = serde_json::to_value(
        plan.project(&json!({"title":"different", "flag":false}))
            .unwrap(),
    )
    .unwrap();
    assert_eq!(captured["status"], "complete");
    assert_eq!(captured["fields"][0]["value"], "different");
    assert_eq!(captured["fields"][1]["value"], false);
}

#[test]
fn sensitive_value_is_vetoed_while_explicit_presence_is_allowed() {
    let schema = json!({"properties":{"secret":{"x-agent-access-sensitive":true}}});
    assert!(
        prepare_audit_inputs(
            &schema,
            &AuditInputProjection::new([text("secret", "/secret")])
        )
        .is_err()
    );
    let plan = prepare_audit_inputs(
        &schema,
        &AuditInputProjection::new([AuditInputRule::presence(
            "secret",
            "Secret supplied",
            "/secret",
        )]),
    )
    .unwrap();
    let encoded =
        serde_json::to_string(&plan.project(&json!({"secret":"canary_secret_material"}))).unwrap();
    assert!(!encoded.contains("canary_secret_material"));
    assert!(encoded.contains("\"value\":true"));
}

#[test]
fn compiled_omissions_produce_no_snapshot() {
    let plan = prepare_audit_inputs(
        &json!({"properties":{"body":{}}}),
        &AuditInputProjection::new([AuditInputRule::omit("body", "/body")]),
    )
    .unwrap();
    assert!(plan.project(&json!({"body":"private"})).is_none());
}
