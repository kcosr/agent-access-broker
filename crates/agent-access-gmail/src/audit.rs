//! Only original mailbox selectors and controls are captured; mail content is output.
use agent_access_provider::{
    AuditDisplay, AuditInputProjection, AuditInputRule, AuditOverflow, AuditRole, AuditValueKind,
};

pub(super) fn search() -> AuditInputProjection {
    AuditInputProjection::new([
        AuditInputRule::value("query", "Mail query", "/query")
            .kind(AuditValueKind::Query)
            .display(AuditDisplay::Primary)
            .max_bytes(4096)
            .overflow(AuditOverflow::Prefix),
        AuditInputRule::value("maxResults", "Requested result limit", "/maxResults")
            .kind(AuditValueKind::Number),
        AuditInputRule::presence("pageToken", "Page token supplied", "/pageToken"),
        AuditInputRule::value(
            "includeSpamTrash",
            "Include spam and trash",
            "/includeSpamTrash",
        )
        .kind(AuditValueKind::Boolean),
    ])
}

pub(super) fn target(entity: &str) -> AuditInputProjection {
    let label = match entity {
        "message" => "Message ID",
        "thread" => "Thread ID",
        _ => panic!("unreviewed Gmail audit target: {entity}"),
    };
    AuditInputProjection::new([AuditInputRule::value("id", label, "/id")
        .kind(AuditValueKind::Identifier)
        .role(AuditRole::Target)
        .display(AuditDisplay::Primary)
        .max_bytes(1024)
        .overflow(AuditOverflow::Omit)])
}

#[cfg(test)]
#[path = "../../agent-access-conformance/src/audit_inventory_test.rs"]
mod inventory;

#[cfg(test)]
mod tests {
    use super::inventory::*;
    use serde_json::json;

    fn semantic(action: &str, pointer: &str) -> (&'static str, &'static str) {
        match (action, pointer) {
            ("message.search", "/query") => ("query.gmail", ""),
            ("message.search", "/maxResults") => ("control.result_limit", ""),
            ("message.search", "/includeSpamTrash") => ("mail.include_spam_trash", ""),
            ("message.search", "/pageToken") => (
                "continuation.token",
                "Opaque page token; presence only, never value, length or hash.",
            ),
            ("message.view" | "message.archive" | "message.trash" | "message.restore", "/id") => {
                ("mail.message.id", "")
            }
            ("thread.view" | "thread.archive" | "thread.trash" | "thread.restore", "/id") => {
                ("mail.thread.id", "")
            }
            _ => panic!("unreviewed semantic element {action} {pointer}"),
        }
    }

    #[test]
    fn audit_inventory_maximal_includes_explicit_no_argument_actions() {
        let descriptor = crate::descriptor();
        check_inventory(
            &descriptor,
            concat!(env!("CARGO_MANIFEST_DIR"), "/audit-input-inventory.json"),
            &["account.view", "label.list"],
            semantic,
        );
        for action in &descriptor.actions {
            if matches!(action.action.as_str(), "account.view" | "label.list") {
                continue;
            }
            let input = if action.action == "message.search" {
                json!({"query":"label:inbox from:person@example.test","maxResults":3,"includeSpamTrash":false,"pageToken":"private-continuation"})
            } else {
                json!({"id":"message_42"})
            };
            let snapshot = assert_sample(action, &input);
            assert!(!snapshot.to_string().contains("private-continuation"));
            if action.action == "message.search" {
                assert_eq!(field(&snapshot, "includeSpamTrash")["value"], false);
            }
        }
    }

    #[test]
    fn defaults_null_and_bad_shapes_are_not_reinterpreted() {
        let descriptor = crate::descriptor();
        let search = action(&descriptor, "message.search");
        let snapshot = assert_sample(search, &json!({}));
        for key in ["query", "maxResults", "pageToken", "includeSpamTrash"] {
            assert_eq!(field(&snapshot, key)["state"], "absent");
        }
        let snapshot = project(
            search,
            &json!({"query":null,"maxResults":[],"includeSpamTrash":false,"pageToken":null,"snippet":"never a request field"}),
        );
        assert_eq!(field(&snapshot, "query")["state"], "null");
        assert_eq!(field(&snapshot, "maxResults")["state"], "invalid");
        assert_eq!(field(&snapshot, "pageToken")["value"], true);
        assert!(!snapshot.to_string().contains("never a request field"));
        let mut changed = search.clone();
        changed.input_schema["properties"]["subject"] = json!({"type":"string"});
        assert!(
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| assert_coverage(&changed)))
                .is_err()
        );
    }
}
