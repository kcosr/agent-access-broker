//! Maintained SDK example: explicit targets, a string summary, and correlated
//! upload records with an explicitly omitted caller-supplied content digest.
use agent_access_provider::{
    AuditDisplay, AuditInputProjection, AuditInputRule, AuditOverflow, AuditRole, AuditValueKind,
};

fn identity(key: &str, label: &str, pointer: &str, kind: AuditValueKind) -> AuditInputRule {
    AuditInputRule::value(key, label, pointer)
        .kind(kind)
        .role(AuditRole::Target)
        .display(AuditDisplay::Primary)
        .max_bytes(1024)
        .overflow(AuditOverflow::Omit)
}

pub(super) fn item(upload: bool) -> AuditInputProjection {
    let mut rules = vec![identity("item", "Item", "/item", AuditValueKind::Path)];
    if upload {
        rules.push(
            AuditInputRule::records(
                "attachments",
                "Attachments",
                "/attachments",
                [
                    AuditInputRule::omit("field", "/field"),
                    identity("filename", "Filename", "/filename", AuditValueKind::Path),
                    AuditInputRule::value("contentType", "Media type", "/contentType")
                        .kind(AuditValueKind::Text)
                        .max_bytes(1024)
                        .overflow(AuditOverflow::Omit),
                    AuditInputRule::value("size", "Supplied size", "/size")
                        .kind(AuditValueKind::Bytes),
                    AuditInputRule::omit("sha256", "/sha256"),
                ],
            )
            .role(AuditRole::Change)
            .display(AuditDisplay::Primary),
        );
    }
    AuditInputProjection::new(rules)
}

pub(super) fn ping() -> AuditInputProjection {
    AuditInputProjection::new([
        identity(
            "endpoint",
            "Endpoint",
            "/endpoint",
            AuditValueKind::Identifier,
        ),
        AuditInputRule::utf8_byte_count("message", "Ping message bytes", "/message")
            .role(AuditRole::Change),
    ])
}

#[cfg(test)]
#[path = "audit_inventory_test.rs"]
mod inventory;

#[cfg(test)]
mod tests {
    use super::inventory::*;
    use crate::{ConformanceConfig, conformance_descriptor};
    use serde_json::json;

    fn config(endpoints: bool, max_upload_bytes: u64) -> ConformanceConfig {
        ConformanceConfig {
            base_url: "https://conformance.example.test/".into(),
            allowed_upstream_hosts: vec!["conformance.example.test".into()],
            egress_proxy: None,
            max_upload_bytes,
            endpoints,
            shelves: vec![],
        }
    }

    fn semantic(_: &str, pointer: &str) -> (&'static str, &'static str) {
        match pointer {
            "/item" => ("fixture.item.path", ""),
            "/endpoint" => ("fixture.endpoint", ""),
            "/message" => (
                "content.notification",
                "Arbitrary ping body; UTF-8 byte count only, never text or hash.",
            ),
            "/attachments" => ("upload.attachments", ""),
            "/attachments[]/field" => (
                "upload.transport_field",
                "Internal multipart correlation field; not content identity.",
            ),
            "/attachments[]/filename" => ("upload.filename", ""),
            "/attachments[]/contentType" => ("upload.media_type", ""),
            "/attachments[]/size" => ("upload.supplied_bytes", ""),
            "/attachments[]/sha256" => (
                "content.fingerprint",
                "Requested upload digest is excluded; no new content fingerprinting.",
            ),
            _ => panic!("unreviewed semantic element {pointer}"),
        }
    }

    #[test]
    fn audit_inventory_maximal_and_conditional_endpoint_surface() {
        check_inventory(
            &conformance_descriptor(&config(true, 1024 * 1024)),
            concat!(env!("CARGO_MANIFEST_DIR"), "/audit-input-inventory.json"),
            &["item.list"],
            semantic,
        );
        for configuration in [
            config(false, 1),
            config(false, 1024 * 1024),
            config(true, 1),
        ] {
            let descriptor = conformance_descriptor(&configuration);
            assert_eq!(
                descriptor
                    .actions
                    .iter()
                    .any(|action| action.action == "endpoint.ping"),
                configuration.endpoints
            );
            for action in &descriptor.actions {
                assert_coverage(action);
            }
        }
    }

    #[test]
    fn maintained_surface_projects_correlated_upload_metadata_and_message_size() {
        let descriptor = conformance_descriptor(&config(true, 1024 * 1024));
        for action in &descriptor.actions {
            let inputs = match action.action.as_str() {
                "item.view" | "item.download" => json!({"item":"shelf-one/item-one"}),
                "item.upload" => {
                    json!({"item":"shelf-one/item-one","attachments":[{"field":"upload-file","filename":"report.txt","contentType":"text/plain","size":11,"sha256":"a".repeat(64)}]})
                }
                "endpoint.ping" => json!({"endpoint":"alerts","message":"private🙂"}),
                "item.list" => {
                    assert!(action.audit_inputs.is_none());
                    continue;
                }
                _ => unreachable!(),
            };
            let snapshot = assert_sample(action, &inputs);
            let encoded = snapshot.to_string();
            assert!(!encoded.contains(&"a".repeat(64)));
            assert!(!encoded.contains("upload-file"));
            assert!(!encoded.contains("private🙂"));
            if action.action == "endpoint.ping" {
                assert_eq!(field(&snapshot, "message")["value"], 11);
            }
            if action.action == "item.upload" {
                assert!(encoded.contains("report.txt"));
                assert_eq!(field(&snapshot, "attachments")["rows"][0]["index"], 0);
                assert!(!encoded.contains("sha256"));
            }
        }
    }

    #[test]
    fn added_upload_children_require_an_explicit_classification() {
        let descriptor = conformance_descriptor(&config(true, 1024));
        let mut upload = action(&descriptor, "item.upload").clone();
        upload.input_schema["properties"]["attachments"]["items"]["properties"]["description"] =
            json!({"type":"string"});
        assert!(
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| assert_coverage(&upload)))
                .is_err()
        );
        let mut download = action(&descriptor, "item.download").clone();
        download.input_schema["properties"]["item"] = json!({"oneOf":[
            {"type":"string"},
            {"type":"object","properties":{"privateLocator":{"type":"string"}}}
        ]});
        assert!(
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| assert_coverage(&download)))
                .is_err()
        );
    }
}
