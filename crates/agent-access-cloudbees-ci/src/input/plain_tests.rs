//! Published schemas describe fields; local parsing owns their relationships.
use super::*;
use crate::tests::{invocation, provider};
use agent_access_provider::Decision;
use wiremock::MockServer;

fn build(extra: Value) -> Value {
    let mut value = json!({"controller":"team-ci","job":"payments/build-api","buildNumber":42});
    value
        .as_object_mut()
        .unwrap()
        .extend(extra.as_object().unwrap().clone());
    value
}

fn assert_denial(error: &ProviderError, category: &str, field: Option<&str>, message: &str) {
    assert_eq!(error.reason_code(), ReasonCode::InputInvalid);
    assert_eq!(error.reason_code().http_status(), 400);
    assert_eq!(error.decision(), Decision::Deny);
    let mut result = json!({"inputCategory": category});
    if let Some(field) = field {
        result["field"] = json!(field);
    }
    assert_eq!(error.result.as_deref(), Some(&result));
    assert_eq!(error.message, message);
    assert!(error.audit.is_none());
    assert!(error.upstream_status.is_none());
    assert!(error.upstream_duration_ms.is_none());
    assert!(error.object_ids.is_none());
    assert!(error.internal_diagnostic_code.is_none());
}

#[tokio::test]
async fn all_plain_actions_keep_explicit_and_url_locator_acceptance_without_lookup() {
    let server = MockServer::start().await;
    let ci = provider(&server);
    let job_url = format!("{}/team-ci/job/payments/job/build-api/", server.uri());
    let descriptor = cloudbees_ci_service_descriptor(&Default::default());
    let mut checked = 0;
    for action in descriptor
        .actions
        .iter()
        .filter(|action| action.action != "job.list")
    {
        let name = action.action.as_str();
        let is_build =
            name.starts_with("build.") && !matches!(name, "build.list" | "build.trigger");
        let validator = jsonschema::validator_for(&action.input_schema).unwrap();
        let mut explicit = json!({"controller":"team-ci","job":"payments/build-api"});
        let mut job = json!({"url":job_url});
        if is_build {
            explicit["buildNumber"] = json!(42);
            job["buildNumber"] = json!(42);
        }
        for mut value in [
            explicit,
            job,
            json!({"url":format!("{job_url}42/")}),
            json!({"url":format!("{job_url}lastFailedBuild/")}),
        ] {
            match name {
                "queue.view" => value["queueId"] = json!(7),
                "build.artifact.download" => value["artifactPath"] = json!("dist/application.zip"),
                "build.pipeline.node.view" | "build.pipeline.node.log.read" => {
                    value["nodeId"] = json!("7")
                }
                _ => {}
            }
            assert!(validator.is_valid(&value), "{name} {value}");
            let parsed = ci.parse(name, &value).unwrap();
            assert_eq!(parsed.controller, "team-ci");
            assert_eq!(parsed.job, "payments/build-api");
            if is_build {
                assert_ne!(
                    parsed.build_number.is_some(),
                    parsed.build_selector.is_some()
                );
            } else {
                assert_eq!((parsed.build_number, parsed.build_selector), (None, None));
            }
            assert!(ci.local_scopes(name, &value).is_ok(), "{name} {value}");
        }
        checked += 1;
    }
    assert_eq!(checked, 16);
    assert!(server.received_requests().await.unwrap().is_empty());
}

#[tokio::test]
async fn locator_and_build_precedence_preserves_full_denials_before_network() {
    let server = MockServer::start().await;
    let ci = provider(&server);
    let job_url = format!("{}/team-ci/job/payments/job/build-api/", server.uri());
    let build_url = format!("{job_url}42/");
    let missing = "pass controller and job, or a job or build url";
    let mixed = "pass either url or controller and job, not both";
    let no_build = "this action needs a build: pass buildNumber or buildSelector, or a build url";
    let url_build =
        "url already names a build; omit buildNumber and buildSelector, or pass a job url";
    let number = "buildNumber must be a positive integer up to 4294967295; use buildSelector for permalinks such as lastFailedBuild";
    let selectors = "buildSelector must be one of lastBuild, lastCompletedBuild, lastFailedBuild, lastSuccessfulBuild, lastStableBuild, lastUnstableBuild, lastUnsuccessfulBuild";
    // Schema expectations are deliberately separate from parser outcomes.
    // Null alternative keys remain present for conflict/precedence checks.
    for (action, value, schema_valid, category, field, message) in [
        (
            "job.view",
            json!({}),
            true,
            "locator_missing",
            "controller",
            missing,
        ),
        (
            "job.view",
            json!({"job":"payments/build-api"}),
            true,
            "locator_missing",
            "controller",
            missing,
        ),
        (
            "job.view",
            json!({"controller":"team-ci"}),
            true,
            "locator_missing",
            "job",
            "job is required with controller; or pass a job or build url instead",
        ),
        (
            "job.view",
            json!({"url":job_url,"controller":"team-ci"}),
            true,
            "locator_conflict",
            "url",
            mixed,
        ),
        (
            "job.view",
            json!({"url":null,"controller":null}),
            false,
            "locator_conflict",
            "url",
            mixed,
        ),
        (
            "job.view",
            json!({"url":"https://unconfigured.example/job/a/","job":null}),
            false,
            "locator_conflict",
            "url",
            mixed,
        ),
        (
            "job.view",
            json!({"controller":null,"job":"payments/build-api"}),
            false,
            "value_invalid",
            "controller",
            "controller must be a string",
        ),
        (
            "job.view",
            json!({"controller":"team-ci","job":null}),
            false,
            "value_invalid",
            "job",
            "job must be a string",
        ),
        (
            "job.view",
            json!({"url":null}),
            false,
            "url_invalid",
            "url",
            "url must be a string",
        ),
        (
            "job.view",
            json!({"url":null,"extra":"do-not-echo"}),
            false,
            "unknown_field",
            "extra",
            "unknown input extra for job.view; accepted inputs: controller, job, url",
        ),
        (
            "job.view",
            json!({"url":null,"buildNumber":1}),
            false,
            "unknown_field",
            "buildNumber",
            "unknown input buildNumber for job.view; accepted inputs: controller, job, url",
        ),
        (
            "build.view",
            json!({"url":job_url}),
            true,
            "build_missing",
            "buildNumber",
            no_build,
        ),
        (
            "build.view",
            json!({"controller":"team-ci","job":"payments/build-api"}),
            true,
            "build_missing",
            "buildNumber",
            no_build,
        ),
        (
            "build.view",
            build(json!({"buildSelector":"lastBuild"})),
            true,
            "build_conflict",
            "buildSelector",
            "pass buildNumber or buildSelector, not both",
        ),
        (
            "build.view",
            json!({"url":build_url,"buildNumber":42}),
            true,
            "build_conflict",
            "buildNumber",
            url_build,
        ),
        (
            "build.view",
            json!({"url":build_url,"buildSelector":"lastBuild"}),
            true,
            "build_conflict",
            "buildSelector",
            url_build,
        ),
        (
            "build.view",
            json!({"url":build_url,"buildNumber":null,"buildSelector":"latest"}),
            false,
            "value_invalid",
            "buildNumber",
            number,
        ),
        (
            "build.view",
            json!({"url":build_url,"buildNumber":"42","buildSelector":"lastBuild"}),
            false,
            "value_invalid",
            "buildNumber",
            "buildNumber must be a JSON integer, not a string",
        ),
        (
            "build.view",
            json!({"url":build_url,"buildNumber":0}),
            false,
            "value_invalid",
            "buildNumber",
            number,
        ),
        (
            "build.view",
            json!({"url":build_url,"buildNumber":4_294_967_296_u64}),
            false,
            "value_invalid",
            "buildNumber",
            number,
        ),
        (
            "build.view",
            json!({"url":build_url,"buildNumber":42,"buildSelector":"latest"}),
            false,
            "value_invalid",
            "buildSelector",
            selectors,
        ),
        (
            "build.view",
            json!({"url":build_url,"buildNumber":42,"buildSelector":null}),
            false,
            "value_invalid",
            "buildSelector",
            selectors,
        ),
        (
            "build.view",
            json!({"url":build_url,"buildNumber":42,"buildSelector":7}),
            false,
            "value_invalid",
            "buildSelector",
            "buildSelector is a Jenkins permalink name; pass a numeric build as buildNumber",
        ),
    ] {
        assert_eq!(
            jsonschema::validator_for(&schema(action))
                .unwrap()
                .is_valid(&value),
            schema_valid,
            "schema {action} {value}"
        );
        for error in [
            ci.parse(action, &value).unwrap_err(),
            ci.local_scopes(action, &value).unwrap_err(),
            ci.invoke(invocation(action, value.clone()))
                .await
                .unwrap_err(),
        ] {
            assert_denial(&error, category, Some(field), message);
            assert!(!error.message.contains("do-not-echo"));
            assert!(!error.message.contains("unconfigured.example"));
        }
    }
    // Unsafe or oversized unknown names stay omitted even when the locator is
    // independently malformed; only the pre-existing bounded names are shown.
    for key in ["private\nname".to_owned(), "x".repeat(65)] {
        let value = json!({(key.clone()):"do-not-echo","url":null});
        let error = ci.local_scopes("job.view", &value).unwrap_err();
        assert_denial(
            &error,
            "unknown_field",
            None,
            "unknown input for job.view; accepted inputs: controller, job, url",
        );
        assert!(!error.message.contains(&key));
        assert!(!error.message.contains("do-not-echo"));
    }
    assert!(server.received_requests().await.unwrap().is_empty());
}

#[tokio::test]
async fn log_relationships_keep_type_and_option_error_precedence() {
    let server = MockServer::start().await;
    let ci = provider(&server);
    let selector_cursor = "a log cursor continues a numeric build; pass the buildNumber returned with nextCursor instead of buildSelector or a permalink url";
    let query_required = "mode search needs a nonempty literal query of at most 256 UTF-8 bytes";
    let cursor_tail =
        "tail reads have no cursor; continue a head or search read with the same mode";
    let cursor_shape = "cursor must be the nextCursor value from a previous head or search read";
    let validator = jsonschema::validator_for(&schema("build.log.read")).unwrap();
    let mut cases = vec![
        (
            json!({"mode":"search"}),
            true,
            "value_invalid",
            "query",
            query_required,
        ),
        (
            json!({"query":"needle"}),
            true,
            "option_conflict",
            "query",
            "query applies only to mode search",
        ),
        (
            json!({"maxMatches":2}),
            true,
            "option_conflict",
            "maxMatches",
            "maxMatches applies only to mode search",
        ),
        (
            json!({"mode":"head","maxMatches":null}),
            false,
            "option_conflict",
            "maxMatches",
            "maxMatches applies only to mode search",
        ),
        (
            json!({"mode":"head","maxMatches":false}),
            false,
            "option_conflict",
            "maxMatches",
            "maxMatches applies only to mode search",
        ),
        (
            json!({"mode":"head","query":null}),
            false,
            "value_invalid",
            "query",
            "query must be a string",
        ),
        (
            json!({"mode":"head","query":false}),
            false,
            "value_invalid",
            "query",
            "query must be a string",
        ),
        (
            json!({"cursor":null,"query":null}),
            false,
            "value_invalid",
            "cursor",
            "cursor must be a string",
        ),
        (
            json!({"cursor":""}),
            false,
            "value_invalid",
            "cursor",
            cursor_shape,
        ),
        (
            json!({"mode":"head","cursor":"x".repeat(109)}),
            false,
            "value_invalid",
            "cursor",
            cursor_shape,
        ),
        (
            json!({"cursor":"x"}),
            true,
            "option_conflict",
            "cursor",
            cursor_tail,
        ),
        (
            json!({"mode":"tail","cursor":"x","query":null}),
            false,
            "value_invalid",
            "query",
            "query must be a string",
        ),
        (
            json!({"mode":"tail","cursor":"x","query":"needle"}),
            true,
            "option_conflict",
            "cursor",
            cursor_tail,
        ),
        (
            json!({"mode":"search","maxBytes":1}),
            false,
            "value_invalid",
            "query",
            query_required,
        ),
        (
            json!({"mode":"head","maxBytes":1}),
            false,
            "value_invalid",
            "maxBytes",
            "maxBytes must be an integer from 1024 to 65536",
        ),
        (
            json!({"mode":"search","query":"needle","maxBytes":1,"maxMatches":0}),
            false,
            "value_invalid",
            "maxBytes",
            "maxBytes must be an integer from 1024 to 65536",
        ),
        (
            json!({"mode":"search","query":"needle","maxMatches":0}),
            false,
            "value_invalid",
            "maxMatches",
            "maxMatches must be an integer from 1 to 100",
        ),
    ]
    .into_iter()
    .map(|(extra, valid, category, field, message)| (build(extra), valid, category, field, message))
    .collect::<Vec<_>>();
    for locator in [
        json!({"controller":"team-ci","job":"payments/build-api","buildSelector":"lastBuild"}),
        json!({"url":format!("{}/team-ci/job/payments/job/build-api/lastBuild/",server.uri())}),
    ] {
        let mut value = locator;
        value["mode"] = json!("head");
        value["cursor"] = json!("x");
        cases.push((
            value.clone(),
            true,
            "option_conflict",
            "cursor",
            selector_cursor,
        ));
        value["maxBytes"] = json!(1);
        cases.push((
            value,
            false,
            "value_invalid",
            "maxBytes",
            "maxBytes must be an integer from 1024 to 65536",
        ));
    }
    for (value, schema_valid, category, field, message) in cases {
        assert_eq!(validator.is_valid(&value), schema_valid, "schema {value}");
        for error in [
            ci.parse("build.log.read", &value).unwrap_err(),
            ci.local_scopes("build.log.read", &value).unwrap_err(),
            ci.invoke(invocation("build.log.read", value.clone()))
                .await
                .unwrap_err(),
        ] {
            assert_denial(&error, category, Some(field), message);
        }
    }
    for options in [
        json!({}),
        json!({"mode":"tail"}),
        json!({"mode":"head"}),
        json!({"mode":"search","query":"needle","maxMatches":1}),
        json!({"mode":"head","cursor":"x"}),
        json!({"mode":"search","query":"needle","cursor":"x"}),
    ] {
        let value = build(options);
        assert!(validator.is_valid(&value));
        assert!(ci.parse("build.log.read", &value).is_ok());
        assert!(ci.local_scopes("build.log.read", &value).is_ok());
    }
    assert!(server.received_requests().await.unwrap().is_empty());
}

#[tokio::test]
async fn byte_limits_remain_stricter_than_published_character_bounds() {
    let server = MockServer::start().await;
    let ci = provider(&server);
    let validator = jsonschema::validator_for(&schema("build.log.read")).unwrap();
    for (field, count, accepted, message) in [
        (
            "query",
            128,
            true,
            "mode search needs a nonempty literal query of at most 256 UTF-8 bytes",
        ),
        (
            "query",
            129,
            false,
            "mode search needs a nonempty literal query of at most 256 UTF-8 bytes",
        ),
        (
            "cursor",
            54,
            true,
            "cursor must be the nextCursor value from a previous head or search read",
        ),
        (
            "cursor",
            55,
            false,
            "cursor must be the nextCursor value from a previous head or search read",
        ),
    ] {
        let mut value = build(json!({"mode":if field == "query" {"search"} else {"head"}}));
        value[field] = json!("é".repeat(count));
        assert!(validator.is_valid(&value), "schema {field} {count}");
        let parsed = ci.parse("build.log.read", &value);
        assert_eq!(parsed.is_ok(), accepted, "parse {field} {count}");
        if let Err(error) = parsed {
            assert_denial(&error, "value_invalid", Some(field), message);
        }
    }
    // Syntactic acceptance above does not establish a valid signed cursor.
    assert!(server.received_requests().await.unwrap().is_empty());
}

#[tokio::test]
async fn syntactic_cursor_acceptance_keeps_late_denial_uncategorized_and_offline() {
    let server = MockServer::start().await;
    let ci = provider(&server);
    let value = build(json!({"mode":"head","cursor":"x"}));
    assert!(ci.local_scopes("build.log.read", &value).is_ok());
    let error = ci
        .invoke(invocation("build.log.read", value))
        .await
        .unwrap_err();
    assert_eq!(error.reason_code(), ReasonCode::InputInvalid);
    assert_eq!(error.decision(), Decision::Deny);
    assert_eq!(error.reason_code().http_status(), 400);
    assert_eq!(
        error.message,
        "Invalid or expired log cursor, changed request context, or rewritten/truncated log prefix; start a new read without the cursor"
    );
    assert!(error.result.is_none());
    assert!(error.audit.is_none());
    assert!(error.upstream_status.is_none());
    assert!(error.upstream_duration_ms.is_none());
    assert!(error.object_ids.is_none());
    assert!(server.received_requests().await.unwrap().is_empty());
}
