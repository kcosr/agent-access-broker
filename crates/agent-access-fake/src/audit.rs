//! Development providers exercise the same bounded capture contract as native providers.
use agent_access_provider::{
    AuditDisplay, AuditInputProjection, AuditInputRule, AuditOverflow, AuditRole, AuditValueKind,
};

fn target(key: &str, label: &str, pointer: &str) -> AuditInputRule {
    AuditInputRule::value(key, label, pointer)
        .kind(AuditValueKind::Identifier)
        .role(AuditRole::Target)
        .display(AuditDisplay::Primary)
        .max_bytes(1024)
        .overflow(AuditOverflow::Omit)
}

pub(super) fn echo() -> AuditInputProjection {
    AuditInputProjection::new([
        target("project", "Project", "/project"),
        AuditInputRule::utf8_byte_count("message", "Echo message bytes", "/message"),
    ])
}

pub(super) fn records(with_id: bool) -> AuditInputProjection {
    let mut rules = vec![target("collection", "Collection", "/collection")];
    if with_id {
        rules.push(target("id", "Record ID", "/id"));
    }
    AuditInputProjection::new(rules)
}

#[cfg(test)]
#[path = "../../agent-access-conformance/src/audit_inventory_test.rs"]
mod inventory;

#[cfg(test)]
mod tests {
    use super::inventory::*;
    use agent_access_provider::test_support::InvocationBuilder;
    use agent_access_provider::{BackendConfig, Provider};
    use serde_json::json;
    use std::collections::BTreeMap;

    #[test]
    fn audit_inventory_maximal_covers_fake_and_oauth_fixture_arguments() {
        let mut descriptor = crate::fake_descriptor();
        // Service qualification avoids collisions while retaining canonical IDs
        // in each provider's runtime descriptors.
        for action in &mut descriptor.actions {
            action.action = format!("fake.{}", action.action);
        }
        let mut oauth = crate::OAuthStubProviderConfig {
            base_url: "http://127.0.0.1:8099".into(),
        }
        .descriptor();
        for action in &mut oauth.actions {
            action.action = format!("oauth_stub.{}", action.action);
        }
        descriptor.actions.extend(oauth.actions);
        check_inventory(
            &descriptor,
            concat!(env!("CARGO_MANIFEST_DIR"), "/audit-input-inventory.json"),
            &["oauth_stub.account.view"],
            |action, pointer| match (action, pointer) {
                ("fake.echo", "/project") => ("fixture.project", ""),
                ("fake.echo", "/message") => (
                    "content.echo",
                    "Arbitrary echo body; UTF-8 byte count only, never text or hash.",
                ),
                ("oauth_stub.record.list" | "oauth_stub.record.view", "/collection") => {
                    ("fixture.collection", "")
                }
                ("oauth_stub.record.view", "/id") => ("fixture.record.id", ""),
                _ => panic!("unreviewed semantic element {action} {pointer}"),
            },
        );
        for action in &descriptor.actions {
            let input = match action.action.as_str() {
                "fake.echo" => json!({"project":"TEST","message":"秘密🙂"}),
                "oauth_stub.record.list" => json!({"collection":"records"}),
                "oauth_stub.record.view" => json!({"collection":"records","id":"record_42"}),
                "oauth_stub.account.view" => {
                    assert!(action.audit_inputs.is_none());
                    continue;
                }
                _ => unreachable!(),
            };
            let snapshot = assert_sample(action, &input);
            if action.action == "fake.echo" {
                assert_eq!(field(&snapshot, "message")["value"], 10);
                assert!(!snapshot.to_string().contains("秘密"));
            }
        }
    }

    #[tokio::test]
    async fn echo_keeps_result_but_no_longer_duplicates_request_summary() {
        let result = crate::FakeProvider
            .invoke(
                InvocationBuilder::new("fake", "echo")
                    .inputs(json!({"project":"TEST","message":"秘密🙂"}))
                    .resources(BTreeMap::from([("project".into(), vec!["TEST".into()])]))
                    .build(),
            )
            .await
            .unwrap();
        assert_eq!(result.result["message"], "秘密🙂");
        assert_eq!(
            result.audit,
            Some(json!({"provider":"fake","operation":"echo"}))
        );
    }

    #[test]
    fn echo_message_summary_distinguishes_empty_null_absent_and_wrong_shape() {
        let descriptor = crate::fake_descriptor();
        let echo = action(&descriptor, "echo");
        let empty = assert_sample(echo, &json!({"project":"TEST","message":""}));
        assert_eq!(field(&empty, "message")["value"], 0);
        for (input, state) in [
            (json!({"message":null}), "null"),
            (json!({}), "absent"),
            (json!({"message":{"secret":"PRIVATE_ECHO"}}), "invalid"),
        ] {
            let snapshot = project(echo, &input);
            assert_eq!(field(&snapshot, "message")["state"], state);
            assert!(field(&snapshot, "message").get("value").is_none());
            assert!(!snapshot.to_string().contains("PRIVATE_ECHO"));
        }
    }
}
