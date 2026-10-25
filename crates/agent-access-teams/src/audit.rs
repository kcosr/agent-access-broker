//! Notification text, title, and card trees are one opaque content element.
use agent_access_provider::{
    AuditDisplay, AuditInputProjection, AuditInputRule, AuditOverflow, AuditRole, AuditValueKind,
};

pub(super) fn projection() -> AuditInputProjection {
    AuditInputProjection::new([
        AuditInputRule::value("destination", "Destination", "/destination")
            .kind(AuditValueKind::Identifier)
            .role(AuditRole::Target)
            .display(AuditDisplay::Primary)
            .max_bytes(1024)
            .overflow(AuditOverflow::Omit),
        AuditInputRule::value("contentFormat", "Content format", "/contentFormat")
            .kind(AuditValueKind::Text)
            .max_bytes(1024)
            .overflow(AuditOverflow::Omit),
        AuditInputRule::presence("content", "Notification content supplied", "/content")
            .role(AuditRole::Change),
    ])
}

#[cfg(test)]
#[path = "../../agent-access-conformance/src/audit_inventory_test.rs"]
mod inventory;

#[cfg(test)]
mod tests {
    use super::inventory::*;
    use serde_json::json;

    #[test]
    fn audit_inventory_maximal_treats_all_notification_content_as_opaque() {
        check_inventory(
            &crate::descriptor(),
            concat!(env!("CARGO_MANIFEST_DIR"), "/audit-input-inventory.json"),
            &[],
            |action, pointer| {
                assert_eq!(action, "notification.send");
                match pointer {
                    "/destination" => ("notification.destination", ""),
                    "/contentFormat" => ("content.format", ""),
                    "/content" => (
                        "content.notification",
                        "Entire notification body including title, text, card fields and arbitrary descendants is presence-only; no serialized size.",
                    ),
                    _ => panic!("unreviewed semantic element {pointer}"),
                }
            },
        );
    }

    #[test]
    fn simple_and_microsoft_content_never_enters_capture() {
        let descriptor = crate::descriptor();
        let action = action(&descriptor, "notification.send");
        for (format, content) in [
            (
                "simple",
                json!({"title":"PRIVATE_TITLE","text":"PRIVATE_BODY"}),
            ),
            (
                "microsoft",
                json!({"@type":"MessageCard","@context":"https://schema.org/extensions","summary":"PRIVATE_SUMMARY","text":"PRIVATE_BODY","sections":[{"facts":[{"value":"PRIVATE_FACT"}]}]}),
            ),
            (
                "microsoft",
                json!({"type":"message","attachments":[{"contentType":"application/vnd.microsoft.card.adaptive","content":{"type":"AdaptiveCard","version":"1.2","body":[{"type":"TextBlock","text":"PRIVATE_BODY"}]}}]}),
            ),
        ] {
            let snapshot = assert_sample(
                action,
                &json!({"destination":"release-alerts","contentFormat":format,"content":content}),
            );
            assert_eq!(field(&snapshot, "destination")["value"], "release-alerts");
            assert_eq!(field(&snapshot, "contentFormat")["value"], format);
            assert_eq!(field(&snapshot, "content")["value"], true);
            assert!(!snapshot.to_string().contains("PRIVATE_"));
            assert_eq!(snapshot["fields"].as_array().unwrap().len(), 3);
        }
        let null = project(action, &json!({"content":null}));
        assert_eq!(field(&null, "content")["value"], true);
        let absent = project(action, &json!({}));
        assert_eq!(field(&absent, "content")["value"], false);
        let mut changed = action.clone();
        changed.input_schema["properties"]["newTitle"] = json!({"type":"string"});
        assert!(
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| assert_coverage(&changed)))
                .is_err()
        );
    }
}
