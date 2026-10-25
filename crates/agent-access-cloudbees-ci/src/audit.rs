//! Reviewed original-input projections. Locator URLs and opaque cursors are
//! presence-only; normalized targets remain provider outcome facts.
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

fn number(key: &str, label: &str, pointer: &str) -> AuditInputRule {
    AuditInputRule::value(key, label, pointer).kind(AuditValueKind::Number)
}

pub(super) fn projection(action: &str) -> AuditInputProjection {
    let controller = || {
        identity(
            "controller",
            "Controller",
            "/controller",
            AuditValueKind::Identifier,
        )
    };
    if action == "job.list" {
        return AuditInputProjection::new([
            controller(),
            identity("folder", "Folder", "/folder", AuditValueKind::Path),
            number("maxResults", "Requested result limit", "/maxResults"),
            AuditInputRule::presence("pageToken", "Page token supplied", "/pageToken"),
        ]);
    }
    let mut rules = vec![
        controller(),
        identity("job", "Job", "/job", AuditValueKind::Path),
        AuditInputRule::presence("url", "Locator URL supplied", "/url"),
    ];
    match action {
        "job.view" | "build.list" | "build.trigger" | "queue.view" => {}
        "build.view"
        | "build.tests.view"
        | "build.artifact.list"
        | "build.artifact.download"
        | "build.log.read"
        | "build.log.download"
        | "build.tests.details"
        | "build.tests.download"
        | "build.pipeline.view"
        | "build.pipeline.node.view"
        | "build.pipeline.node.log.read"
        | "build.pending-inputs.list" => {
            rules.push(identity(
                "buildNumber",
                "Build number",
                "/buildNumber",
                AuditValueKind::Identifier,
            ));
            rules.push(identity(
                "buildSelector",
                "Build selector",
                "/buildSelector",
                AuditValueKind::Identifier,
            ));
        }
        _ => panic!("unreviewed CloudBees CI audit action: {action}"),
    }
    match action {
        "build.list" | "build.tests.details" => rules.push(number(
            "maxResults",
            "Requested result limit",
            "/maxResults",
        )),
        "queue.view" => rules.push(identity(
            "queueId",
            "Queue ID",
            "/queueId",
            AuditValueKind::Identifier,
        )),
        "build.pipeline.node.view" | "build.pipeline.node.log.read" => rules.push(identity(
            "nodeId",
            "Pipeline node ID",
            "/nodeId",
            AuditValueKind::Identifier,
        )),
        "build.artifact.download" => rules.push(identity(
            "artifactPath",
            "Artifact path",
            "/artifactPath",
            AuditValueKind::Path,
        )),
        "build.log.read" => rules.extend([
            AuditInputRule::value("mode", "Log mode", "/mode")
                .kind(AuditValueKind::Text)
                .max_bytes(1024)
                .overflow(AuditOverflow::Omit),
            number("maxBytes", "Requested byte limit", "/maxBytes"),
            AuditInputRule::presence("cursor", "Log cursor supplied", "/cursor"),
            AuditInputRule::value("query", "Log query", "/query")
                .kind(AuditValueKind::Query)
                .display(AuditDisplay::Primary)
                .max_bytes(4096)
                .overflow(AuditOverflow::Prefix),
            number("maxMatches", "Requested match limit", "/maxMatches"),
        ]),
        _ => {}
    }
    AuditInputProjection::new(rules)
}

#[cfg(test)]
#[path = "../../agent-access-conformance/src/audit_inventory_test.rs"]
mod inventory;

#[cfg(test)]
mod tests {
    use super::inventory::*;
    use crate::{CloudbeesCiListingConfig, cloudbees_ci_service_descriptor};
    use serde_json::{Value, json};

    fn semantic(_: &str, pointer: &str) -> (&'static str, &'static str) {
        match pointer {
            "/controller" => ("ci.controller", ""),
            "/job" => ("ci.job.path", ""),
            "/folder" => ("ci.folder.path", ""),
            "/url" => (
                "locator.url",
                "Only supplied state; raw URL may contain unrelated paths, query or fragment.",
            ),
            "/buildNumber" => ("ci.build.id", ""),
            "/buildSelector" => ("ci.build.selector", ""),
            "/queueId" => ("ci.queue.id", ""),
            "/nodeId" => ("ci.pipeline.node.id", ""),
            "/artifactPath" => ("ci.artifact.path", ""),
            "/maxResults" => ("control.result_limit", ""),
            "/maxBytes" => ("control.byte_limit", ""),
            "/maxMatches" => ("control.match_limit", ""),
            "/mode" => ("ci.log.mode", ""),
            "/query" => ("query.literal", ""),
            "/cursor" | "/pageToken" => (
                "continuation.token",
                "Opaque continuation; presence only, never value, length or hash.",
            ),
            _ => panic!("unreviewed semantic element {pointer}"),
        }
    }

    #[test]
    fn audit_inventory_maximal_and_minimal_configurations() {
        let maximal = CloudbeesCiListingConfig {
            max_results: 100,
            ..Default::default()
        };
        check_inventory(
            &cloudbees_ci_service_descriptor(&maximal),
            concat!(env!("CARGO_MANIFEST_DIR"), "/audit-input-inventory.json"),
            &[],
            semantic,
        );
        for config in [
            CloudbeesCiListingConfig::default(),
            CloudbeesCiListingConfig {
                max_results: 1,
                ..Default::default()
            },
        ] {
            for action in cloudbees_ci_service_descriptor(&config).actions {
                assert_coverage(&action);
            }
        }
    }

    fn sample(name: &str) -> Value {
        if name == "job.list" {
            return json!({"controller":"team-ci","folder":"payments","maxResults":1,"pageToken":"opaque-page"});
        }
        let mut input = json!({"controller":"team-ci","job":"payments/build-api"});
        if !matches!(
            name,
            "job.view" | "build.list" | "build.trigger" | "queue.view"
        ) {
            input["buildNumber"] = json!(41);
        }
        match name {
            "build.list" | "build.tests.details" => input["maxResults"] = json!(1),
            "queue.view" => input["queueId"] = json!(i64::MAX),
            "build.pipeline.node.view" | "build.pipeline.node.log.read" => input["nodeId"] = json!("17"),
            "build.artifact.download" => input["artifactPath"] = json!("dist/report.xml"),
            "build.log.read" => input.as_object_mut().unwrap().extend(json!({"mode":"search","query":"failure\ncontext","maxBytes":1024,"maxMatches":2,"cursor":"opaque-log"}).as_object().unwrap().clone()),
            _ => {}
        }
        input
    }

    #[test]
    fn every_action_projects_schema_valid_samples_and_locator_alternatives() {
        let descriptor = cloudbees_ci_service_descriptor(&CloudbeesCiListingConfig::default());
        for action in &descriptor.actions {
            let input = sample(&action.action);
            let captured = assert_sample(action, &input);
            assert_eq!(field(&captured, "controller")["value"], "team-ci");
            if action.action == "queue.view" {
                assert_eq!(field(&captured, "queueId")["value"], i64::MAX.to_string());
                assert_eq!(field(&captured, "queueId")["encoding"], "decimalInteger");
            }
            if action.action == "job.list" {
                assert_eq!(field(&captured, "pageToken")["value"], true);
                continue;
            }
            let mut url_input = input.clone();
            let object = url_input.as_object_mut().unwrap();
            object.remove("controller");
            object.remove("job");
            let build = object.remove("buildNumber").is_some();
            object.remove("cursor");
            object.insert("url".into(), json!(if build { "https://ci.example.test/team-ci/job/payments/job/build-api/lastFailedBuild/console?private=secret" } else { "https://ci.example.test/team-ci/job/payments/job/build-api/?private=secret" }));
            let captured = assert_sample(action, &url_input);
            assert_eq!(field(&captured, "url")["value"], true);
            assert!(!captured.to_string().contains("private=secret"));
            if build {
                let mut selector_input = input;
                let object = selector_input.as_object_mut().unwrap();
                object.remove("buildNumber");
                object.remove("cursor");
                object.insert("buildSelector".into(), json!("lastFailedBuild"));
                let captured = assert_sample(action, &selector_input);
                assert_eq!(
                    field(&captured, "buildSelector")["value"],
                    "lastFailedBuild"
                );
            }
        }
    }

    #[test]
    fn omitted_controls_and_large_targets_preserve_requested_meaning() {
        let descriptor = cloudbees_ci_service_descriptor(&CloudbeesCiListingConfig::default());
        let log = action(&descriptor, "build.log.read");
        let captured = assert_sample(
            log,
            &json!({"controller":"team-ci","job":"payments/build-api","buildNumber":41}),
        );
        for key in ["mode", "query", "maxBytes", "maxMatches", "cursor"] {
            assert_eq!(field(&captured, key)["state"], "absent");
        }
        let captured = project(
            log,
            &json!({"controller":"x".repeat(1025),"job":"payments/build-api","buildNumber":41,"query":"z".repeat(5000)}),
        );
        assert_eq!(field(&captured, "controller")["state"], "tooLarge");
        assert!(field(&captured, "controller").get("value").is_none());
        assert_eq!(
            field(&captured, "query")["value"].as_str().unwrap().len(),
            4096
        );
        let mut changed = log.clone();
        changed.input_schema["properties"]["newControl"] = json!({"type":"boolean"});
        assert!(
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| assert_coverage(&changed)))
                .is_err()
        );
    }
}
