use serde_json::{Value, json};
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

const WEBHOOK_READ_TEST: &str = "real_broker_gitlab_webhook_read_smoke";
const WEBHOOK_LIFECYCLE_TEST: &str = "real_broker_gitlab_throwaway_webhook_lifecycle_smoke";
const INLINE_REPLY_TEST: &str = "real_broker_gitlab_throwaway_inline_reply_smoke";
const DRAFT_REVIEW_TEST: &str = "real_broker_gitlab_throwaway_draft_review_submit_smoke";
const APPROVE_UNAPPROVE_TEST: &str = "real_broker_gitlab_throwaway_formal_approve_unapprove_smoke";
const SUGGESTION_APPLY_TEST: &str = "real_broker_gitlab_throwaway_single_suggestion_apply_smoke";
const WEBHOOK_LIFECYCLE_CONFIRMATION: &str = "throwaway-webhook-lifecycle";
const INLINE_REPLY_CONFIRMATION: &str = "throwaway-inline-reply";
const DRAFT_REVIEW_CONFIRMATION: &str = "throwaway-draft-review";
const APPROVE_UNAPPROVE_CONFIRMATION: &str = "throwaway-approve-unapprove";
const SUGGESTION_APPLY_CONFIRMATION: &str = "throwaway-single-suggestion";

#[test]
#[ignore = "requires a live broker, real GitLab credentials, and one configured existing project webhook; run this exact test with --exact"]
fn real_broker_gitlab_webhook_read_smoke() {
    require_exact_test_invocation(WEBHOOK_READ_TEST);
    let broker_url = required_env("AGENT_ACCESS_REAL_BROKER_URL");
    let project = required_env("AGENT_ACCESS_REAL_GITLAB_WEBHOOK_PROJECT");
    let webhook_id = required_u64_env("AGENT_ACCESS_REAL_GITLAB_WEBHOOK_ID");
    let project_id = assert_project_preflight(&broker_url, &project);

    let hooks = invoke_gitlab(
        &broker_url,
        "webhook.list",
        json!({"project": project, "maxResults": 20}),
    );
    let hooks = array_at(&hooks, &["result", "webhooks"]);
    assert!(
        hooks
            .iter()
            .any(|webhook| webhook["id"].as_u64() == Some(webhook_id)),
        "configured webhook must appear in the first bounded list page"
    );

    let webhook = invoke_gitlab(
        &broker_url,
        "webhook.view",
        json!({"project": project, "webhookId": webhook_id}),
    );
    let webhook = object_at(&webhook, &["result", "webhook"]);
    assert_webhook_identity(webhook, webhook_id, project_id);
}

#[test]
#[ignore = "creates, delivers, resends, and deletes only one explicitly confirmed disposable GitLab webhook; run this exact test with --exact"]
fn real_broker_gitlab_throwaway_webhook_lifecycle_smoke() {
    require_exact_test_invocation(WEBHOOK_LIFECYCLE_TEST);
    require_confirmation(
        "AGENT_ACCESS_REAL_GITLAB_WEBHOOK_LIFECYCLE_CONFIRM",
        WEBHOOK_LIFECYCLE_CONFIRMATION,
    );
    let broker_url = required_env("AGENT_ACCESS_REAL_BROKER_URL");
    let project = required_env("AGENT_ACCESS_REAL_GITLAB_WEBHOOK_MUTATION_PROJECT");
    let receiver_url = required_env("AGENT_ACCESS_REAL_GITLAB_WEBHOOK_RECEIVER_URL");
    assert!(
        receiver_url.starts_with("https://") || receiver_url.starts_with("http://"),
        "AGENT_ACCESS_REAL_GITLAB_WEBHOOK_RECEIVER_URL must be an explicit HTTP(S) URL"
    );
    let project_id = assert_project_preflight(&broker_url, &project);

    let create = invoke_gitlab(
        &broker_url,
        "webhook.create",
        json!({
            "project": project,
            "url": receiver_url,
            "events": ["push"],
            "name": "Agent Access disposable live smoke",
            "description": "Deleted by the exact-filtered webhook lifecycle smoke"
        }),
    );
    let create = object_at(&create, &["result"]);
    assert_applied_mutation(create);
    let webhook_id = required_json_u64(create, "webhookId");
    let created = object_at_value(&create["webhook"], "created webhook");
    assert_webhook_identity(created, webhook_id, project_id);
    assert!(created["url"].as_str() == Some(receiver_url.as_str()));

    let mut cleanup = DisposableWebhook::new(&broker_url, &project, webhook_id);
    let header_key = "X-Agent-Access-Live-Smoke";
    let header_value = format!("disposable-{}", std::process::id());
    let set_header = invoke_gitlab(
        &broker_url,
        "webhook.custom_header.set",
        json!({
            "project": project,
            "webhookId": webhook_id,
            "key": header_key,
            "value": header_value
        }),
    );
    let set_header = object_at(&set_header, &["result"]);
    assert_applied_mutation(set_header);
    assert!(set_header["webhookId"].as_u64() == Some(webhook_id));
    assert!(set_header["key"].as_str() == Some(header_key));

    let configured = invoke_gitlab(
        &broker_url,
        "webhook.view",
        json!({"project": project, "webhookId": webhook_id}),
    );
    let configured = object_at(&configured, &["result", "webhook"]);
    assert_webhook_identity(configured, webhook_id, project_id);
    assert!(
        configured["customHeaders"]
            .as_array()
            .is_some_and(|headers| headers.iter().any(|header| {
                header["key"]
                    .as_str()
                    .is_some_and(|key| key.eq_ignore_ascii_case(header_key))
            })),
        "custom-header set must be visible by key without exposing its value"
    );

    let test_delivery = invoke_gitlab(
        &broker_url,
        "webhook.test",
        json!({"project": project, "webhookId": webhook_id, "event": "push"}),
    );
    let test_delivery = object_at(&test_delivery, &["result"]);
    assert_applied_mutation(test_delivery);
    assert!(test_delivery["webhookId"].as_u64() == Some(webhook_id));
    object_at_value(&test_delivery["attempt"], "test delivery attempt");

    let event = wait_for_webhook_event(&broker_url, &project, webhook_id);
    let webhook_event_id = required_json_u64(&event, "id");
    assert!(event["requestDataTruncated"].is_boolean());
    assert!(event["responseBodyTruncated"].is_boolean());
    let request_headers = object_at_value(&event["requestHeaders"], "event.requestHeaders");
    assert!(
        request_headers
            .as_object()
            .is_some_and(|headers| headers.iter().any(|(key, value)| {
                key.eq_ignore_ascii_case(header_key) && value.as_str() == Some("[REDACTED]")
            })),
        "delivery history must redact the configured custom-header value"
    );

    let resend = invoke_gitlab(
        &broker_url,
        "webhook.event.resend",
        json!({
            "project": project,
            "webhookId": webhook_id,
            "webhookEventId": webhook_event_id
        }),
    );
    let resend = object_at(&resend, &["result"]);
    assert_applied_mutation(resend);
    assert!(resend["webhookId"].as_u64() == Some(webhook_id));
    assert!(resend["webhookEventId"].as_u64() == Some(webhook_event_id));
    object_at_value(&resend["attempt"], "resend delivery attempt");

    let delete_header = invoke_gitlab(
        &broker_url,
        "webhook.custom_header.delete",
        json!({"project": project, "webhookId": webhook_id, "key": header_key}),
    );
    let delete_header = object_at(&delete_header, &["result"]);
    assert_applied_mutation(delete_header);
    assert!(delete_header["webhookId"].as_u64() == Some(webhook_id));
    assert!(delete_header["key"].as_str() == Some(header_key));

    let delete = invoke_gitlab(
        &broker_url,
        "webhook.delete",
        json!({"project": project, "webhookId": webhook_id}),
    );
    let delete = object_at(&delete, &["result"]);
    assert_applied_mutation(delete);
    assert!(delete["webhookId"].as_u64() == Some(webhook_id));
    cleanup.disarm();
}

#[test]
#[ignore = "requires a live broker, real GitLab credentials, and a configured positioned MR discussion"]
fn real_broker_gitlab_merge_request_review_context_read_smoke() {
    let broker_url = required_env("AGENT_ACCESS_REAL_BROKER_URL");
    let project = required_env("AGENT_ACCESS_REAL_GITLAB_PROJECT");
    let iid = required_u64_env("AGENT_ACCESS_REAL_GITLAB_MERGE_REQUEST_IID");
    let discussion_id = required_env("AGENT_ACCESS_REAL_GITLAB_POSITIONED_DISCUSSION_ID");

    let merge_request = invoke_gitlab(
        &broker_url,
        "merge_request.view",
        json!({"project": project, "iid": iid}),
    );
    let merge_request = object_at(&merge_request, &["result", "mergeRequest"]);
    assert!(merge_request["iid"].as_u64() == Some(iid));
    assert!(merge_request["project"].as_str() == Some(project.as_str()));
    assert_full_sha(&merge_request["sha"], "merge request sha");
    let current_diff_refs = object_at_value(&merge_request["diffRefs"], "merge request diffRefs");
    assert_full_sha(&current_diff_refs["baseSha"], "diffRefs.baseSha");
    assert_full_sha(&current_diff_refs["startSha"], "diffRefs.startSha");
    assert_full_sha(&current_diff_refs["headSha"], "diffRefs.headSha");

    let diffs = invoke_gitlab(
        &broker_url,
        "merge_request.diff.list",
        json!({"project": project, "iid": iid, "maxResults": 20}),
    );
    let diffs = array_at(&diffs, &["result", "diffs"]);
    assert!(
        !diffs.is_empty(),
        "configured MR must contain at least one diff"
    );
    for diff in diffs {
        assert_nonempty_string(&diff["oldPath"], "diff.oldPath");
        assert_nonempty_string(&diff["newPath"], "diff.newPath");
        assert_optional_bool(&diff["collapsed"], "diff.collapsed");
        assert_optional_bool(&diff["tooLarge"], "diff.tooLarge");
    }

    let versions = invoke_gitlab(
        &broker_url,
        "merge_request.diff_version.list",
        json!({"project": project, "iid": iid, "maxResults": 20}),
    );
    let versions = array_at(&versions, &["result", "diffVersions"]);
    let latest_version = versions
        .first()
        .expect("configured MR must contain at least one diff version");
    let version_id = latest_version["id"]
        .as_u64()
        .expect("diff version id must be a positive integer");
    assert!(version_id > 0, "diff version id must be positive");
    assert_full_sha(
        &latest_version["headCommitSha"],
        "diff version headCommitSha",
    );
    assert_full_sha(
        &latest_version["baseCommitSha"],
        "diff version baseCommitSha",
    );
    assert_full_sha(
        &latest_version["startCommitSha"],
        "diff version startCommitSha",
    );

    let version = invoke_gitlab(
        &broker_url,
        "merge_request.diff_version.view",
        json!({"project": project, "iid": iid, "diffVersionId": version_id}),
    );
    let version = object_at(&version, &["result", "diffVersion"]);
    assert!(version["id"].as_u64() == Some(version_id));
    assert!(version["commits"].as_array().is_some());
    assert!(version["diffs"].as_array().is_some());

    let discussion = invoke_gitlab(
        &broker_url,
        "merge_request.discussion.view",
        json!({"project": project, "iid": iid, "discussionId": discussion_id}),
    );
    let discussion = object_at(&discussion, &["result", "discussion"]);
    assert_nonempty_string(&discussion["id"], "discussion.id");
    let notes = discussion["notes"]
        .as_array()
        .expect("discussion notes must be an array");
    let positioned_note = notes
        .iter()
        .find(|note| note["position"].is_object())
        .expect("configured discussion must contain a positioned note");
    assert_nonempty_string(&positioned_note["type"], "positioned note.type");
    assert_diff_position(&positioned_note["position"]);

    let discussion_summaries = invoke_gitlab(
        &broker_url,
        "merge_request.discussion.list",
        json!({"project": project, "iid": iid, "maxResults": 20, "projection": "summary"}),
    );
    assert_eq!(discussion_summaries["result"]["projection"], "summary");
    for discussion in array_at(&discussion_summaries, &["result", "discussions"]) {
        assert!(discussion["noteCount"].as_u64().is_some());
        for note in discussion["notes"]
            .as_array()
            .expect("summary discussion notes must be an array")
        {
            assert!(note.get("body").is_none());
            assert!(note.get("renderedBody").is_none());
            assert!(note.get("suggestions").is_none());
        }
    }

    let note_id = positioned_note["id"]
        .as_u64()
        .expect("positioned note id must be a positive integer");
    let exact_note = invoke_gitlab(
        &broker_url,
        "merge_request.note.view",
        json!({"project": project, "iid": iid, "noteId": note_id}),
    );
    let exact_note = object_at(&exact_note, &["result", "note"]);
    assert!(exact_note["id"].as_u64() == Some(note_id));
}

#[test]
#[ignore = "requires a live broker, real GitLab credentials, and a configured MR with approval API access"]
fn real_broker_gitlab_merge_request_approval_read_smoke() {
    let broker_url = required_env("AGENT_ACCESS_REAL_BROKER_URL");
    let project = required_env("AGENT_ACCESS_REAL_GITLAB_PROJECT");
    let iid = required_u64_env("AGENT_ACCESS_REAL_GITLAB_MERGE_REQUEST_IID");

    let response = invoke_gitlab(
        &broker_url,
        "merge_request.approval.view",
        json!({"project": project, "iid": iid}),
    );
    let approval = object_at(&response, &["result", "approval"]);
    assert_optional_u64(&approval["approvalsRequired"], "approval.approvalsRequired");
    assert_optional_u64(&approval["approvalsLeft"], "approval.approvalsLeft");
    assert_optional_bool(&approval["approved"], "approval.approved");
    assert!(approval["approvedBy"].as_array().is_some());
    assert_optional_bool(&approval["userHasApproved"], "approval.userHasApproved");
    assert_optional_bool(&approval["userCanApprove"], "approval.userCanApprove");
}

#[test]
#[ignore = "requires a live broker, real GitLab credentials, a Premium/Ultimate MR, and a configured approval rule"]
fn real_broker_gitlab_merge_request_approval_rule_read_smoke() {
    let broker_url = required_env("AGENT_ACCESS_REAL_BROKER_URL");
    let project = required_env("AGENT_ACCESS_REAL_GITLAB_PROJECT");
    let iid = required_u64_env("AGENT_ACCESS_REAL_GITLAB_MERGE_REQUEST_IID");
    let rule_id = required_u64_env("AGENT_ACCESS_REAL_GITLAB_APPROVAL_RULE_ID");

    let state = invoke_gitlab(
        &broker_url,
        "merge_request.approval_state.view",
        json!({"project": project, "iid": iid}),
    );
    let state = object_at(&state, &["result", "approvalState"]);
    assert_optional_bool(
        &state["approvalRulesOverwritten"],
        "approvalState.approvalRulesOverwritten",
    );
    assert!(state["rules"].as_array().is_some());

    let rules = invoke_gitlab(
        &broker_url,
        "merge_request.approval_rule.list",
        json!({"project": project, "iid": iid, "maxResults": 20}),
    );
    let rules = array_at(&rules, &["result", "approvalRules"]);
    assert!(
        rules
            .iter()
            .any(|rule| rule["id"].as_u64() == Some(rule_id)),
        "configured approval rule must appear in the scoped rule list"
    );

    let rule = invoke_gitlab(
        &broker_url,
        "merge_request.approval_rule.view",
        json!({"project": project, "iid": iid, "approvalRuleId": rule_id}),
    );
    let rule = object_at(&rule, &["result", "approvalRule"]);
    assert!(rule["id"].as_u64() == Some(rule_id));
    assert_nonempty_string(&rule["name"], "approvalRule.name");
    assert!(rule["approvalsRequired"].as_u64().is_some());
}

#[test]
#[ignore = "requires a live broker, real GitLab credentials, and a configured unapplied suggestion"]
fn real_broker_gitlab_merge_request_suggestion_read_smoke() {
    let target = ReviewMutationTarget::load_and_preflight();
    let locator = SuggestionLocator::load();
    let suggestion = read_configured_suggestion(&target, &locator);
    assert!(suggestion["applicable"].as_bool() == Some(true));
    assert!(suggestion["applied"].as_bool() == Some(false));
}

#[test]
#[ignore = "mutates only an explicitly confirmed throwaway GitLab MR; run this exact test with --exact"]
fn real_broker_gitlab_throwaway_inline_reply_smoke() {
    require_exact_test_invocation(INLINE_REPLY_TEST);
    require_confirmation(
        "AGENT_ACCESS_REAL_GITLAB_INLINE_REPLY_CONFIRM",
        INLINE_REPLY_CONFIRMATION,
    );
    let target = MutationTarget::load_and_preflight();
    let content = mutation_content();

    let inline = invoke_gitlab(
        &target.broker_url,
        "merge_request.discussion.inline.add",
        target.positioned_inputs(&content),
    );
    let inline_result = object_at(&inline, &["result"]);
    assert_applied_mutation(inline_result);
    let discussion_id = required_json_string(inline_result, "discussionId");
    let note_id = required_json_u64(inline_result, "noteId");
    let discussion = object_at_value(&inline_result["discussion"], "created discussion");
    assert!(discussion["id"].as_str() == Some(discussion_id));
    let created_note = discussion["notes"]
        .as_array()
        .and_then(|notes| {
            notes
                .iter()
                .find(|note| note["id"].as_u64() == Some(note_id))
        })
        .expect("created discussion must contain the verified created note");
    assert_diff_position(&created_note["position"]);

    let reply = invoke_gitlab(
        &target.broker_url,
        "merge_request.discussion.note.add",
        json!({
            "project": target.project,
            "iid": target.iid,
            "discussionId": discussion_id,
            "content": content,
            "contentFormat": "markdown"
        }),
    );
    let reply_result = object_at(&reply, &["result"]);
    assert_applied_mutation(reply_result);
    assert!(reply_result["discussionId"].as_str() == Some(discussion_id));
    assert!(reply_result["noteId"].as_u64().is_some_and(|id| id > 0));
    assert!(reply_result["note"].is_object());
}

#[test]
#[ignore = "creates and submits drafts only on an explicitly confirmed throwaway GitLab MR; run this exact test with --exact"]
fn real_broker_gitlab_throwaway_draft_review_submit_smoke() {
    require_exact_test_invocation(DRAFT_REVIEW_TEST);
    require_confirmation(
        "AGENT_ACCESS_REAL_GITLAB_DRAFT_REVIEW_CONFIRM",
        DRAFT_REVIEW_CONFIRMATION,
    );
    let target = MutationTarget::load_and_preflight();
    let content = mutation_content();
    let reviewer_state = required_env("AGENT_ACCESS_REAL_GITLAB_REVIEWER_STATE");
    assert!(
        matches!(reviewer_state.as_str(), "reviewed" | "requestedChanges"),
        "AGENT_ACCESS_REAL_GITLAB_REVIEWER_STATE must be reviewed or requestedChanges"
    );

    let single_draft = invoke_gitlab(
        &target.broker_url,
        "merge_request.draft_note.add",
        target.positioned_inputs(&content),
    );
    let single_draft_result = object_at(&single_draft, &["result"]);
    assert_applied_mutation(single_draft_result);
    let single_draft_id = required_json_u64(single_draft_result, "draftNoteId");
    let single_publish = invoke_gitlab(
        &target.broker_url,
        "merge_request.draft_note.publish",
        json!({
            "project": target.project,
            "iid": target.iid,
            "draftNoteId": single_draft_id
        }),
    );
    let single_publish_result = object_at(&single_publish, &["result"]);
    assert_applied_mutation(single_publish_result);
    let discussion_id = required_json_string(single_publish_result, "discussionId");
    let note_id = required_json_u64(single_publish_result, "noteId");
    let discussion = invoke_gitlab(
        &target.broker_url,
        "merge_request.discussion.view",
        json!({
            "project": target.project,
            "iid": target.iid,
            "discussionId": discussion_id
        }),
    );
    let published_note = object_at(&discussion, &["result", "discussion"])["notes"]
        .as_array()
        .and_then(|notes| {
            notes
                .iter()
                .find(|note| note["id"].as_u64() == Some(note_id))
        })
        .expect("published draft note must be readable through returned locators");
    assert_diff_position(&published_note["position"]);

    let reply_draft = invoke_gitlab(
        &target.broker_url,
        "merge_request.draft_note.add",
        json!({
            "project": target.project,
            "iid": target.iid,
            "inReplyToDiscussionId": discussion_id,
            "content": content,
            "contentFormat": "markdown"
        }),
    );
    let reply_draft_result = object_at(&reply_draft, &["result"]);
    assert_applied_mutation(reply_draft_result);
    let reply_draft_id = required_json_u64(reply_draft_result, "draftNoteId");
    let reply_publish = invoke_gitlab(
        &target.broker_url,
        "merge_request.draft_note.publish",
        json!({
            "project": target.project,
            "iid": target.iid,
            "draftNoteId": reply_draft_id
        }),
    );
    let reply_publish_result = object_at(&reply_publish, &["result"]);
    assert_applied_mutation(reply_publish_result);
    assert_eq!(
        required_json_string(reply_publish_result, "discussionId"),
        discussion_id
    );
    let reply_note_id = required_json_u64(reply_publish_result, "noteId");
    let reply_discussion = invoke_gitlab(
        &target.broker_url,
        "merge_request.discussion.view",
        json!({
            "project": target.project,
            "iid": target.iid,
            "discussionId": discussion_id
        }),
    );
    object_at(&reply_discussion, &["result", "discussion"])["notes"]
        .as_array()
        .and_then(|notes| {
            notes
                .iter()
                .find(|note| note["id"].as_u64() == Some(reply_note_id))
        })
        .expect("published reply draft must be readable through returned locators");

    let publish_all_draft = invoke_gitlab(
        &target.broker_url,
        "merge_request.draft_note.add",
        target.positioned_inputs(&content),
    );
    let publish_all_draft_result = object_at(&publish_all_draft, &["result"]);
    assert_applied_mutation(publish_all_draft_result);
    let publish_all_draft_id = required_json_u64(publish_all_draft_result, "draftNoteId");
    let publish_all_draft_note = object_at_value(
        &publish_all_draft_result["draftNote"],
        "created publish-all draft note",
    );
    assert!(publish_all_draft_note["id"].as_u64() == Some(publish_all_draft_id));
    assert_diff_position(&publish_all_draft_note["position"]);

    let draft_view = invoke_gitlab(
        &target.broker_url,
        "merge_request.draft_note.view",
        json!({
            "project": target.project,
            "iid": target.iid,
            "draftNoteId": publish_all_draft_id
        }),
    );
    let viewed_draft = object_at(&draft_view, &["result", "draftNote"]);
    assert!(viewed_draft["id"].as_u64() == Some(publish_all_draft_id));
    assert_diff_position(&viewed_draft["position"]);

    let publish_all = invoke_gitlab(
        &target.broker_url,
        "merge_request.draft_note.publish_all",
        json!({"project": target.project, "iid": target.iid}),
    );
    let publish_all_result = object_at(&publish_all, &["result"]);
    assert_applied_mutation(publish_all_result);
    assert_id_array_contains(
        publish_all_result,
        "publishedDraftNoteIds",
        publish_all_draft_id,
    );

    let review_draft = invoke_gitlab(
        &target.broker_url,
        "merge_request.draft_note.add",
        target.positioned_inputs(&content),
    );
    let review_draft_result = object_at(&review_draft, &["result"]);
    assert_applied_mutation(review_draft_result);
    let review_draft_id = required_json_u64(review_draft_result, "draftNoteId");
    assert_diff_position(&review_draft_result["draftNote"]["position"]);

    let submit = invoke_gitlab(
        &target.broker_url,
        "merge_request.review.submit",
        json!({
            "project": target.project,
            "iid": target.iid,
            "reviewerState": reviewer_state
        }),
    );
    let submit_result = object_at(&submit, &["result"]);
    assert_applied_mutation(submit_result);
    assert!(submit_result["reviewerState"].as_str() == Some(reviewer_state.as_str()));
    assert_id_array_contains(submit_result, "publishedDraftNoteIds", review_draft_id);
}

#[test]
#[ignore = "approves then unapproves only an explicitly confirmed throwaway GitLab MR; run this exact test with --exact"]
fn real_broker_gitlab_throwaway_formal_approve_unapprove_smoke() {
    require_exact_test_invocation(APPROVE_UNAPPROVE_TEST);
    require_confirmation(
        "AGENT_ACCESS_REAL_GITLAB_APPROVE_UNAPPROVE_CONFIRM",
        APPROVE_UNAPPROVE_CONFIRMATION,
    );
    let target = ReviewMutationTarget::load_and_preflight();
    let before = invoke_gitlab(
        &target.broker_url,
        "merge_request.approval.view",
        json!({"project": target.project, "iid": target.iid}),
    );
    let before = object_at(&before, &["result", "approval"]);
    assert!(
        before["userHasApproved"].as_bool() == Some(false),
        "refusing mutation: the execution credential must not already have approved the MR"
    );
    assert!(
        before["userCanApprove"].as_bool() != Some(false),
        "refusing mutation: GitLab reports that the execution credential cannot approve"
    );

    let approve = invoke_gitlab(
        &target.broker_url,
        "merge_request.approve",
        json!({
            "project": target.project,
            "iid": target.iid,
            "headSha": target.expected_head_sha
        }),
    );
    let approve = object_at(&approve, &["result"]);
    assert_applied_mutation(approve);
    assert!(required_json_u64(approve, "userId") > 0);
    assert!(approve["headSha"].as_str() == Some(target.expected_head_sha.as_str()));

    let unapprove = invoke_gitlab(
        &target.broker_url,
        "merge_request.unapprove",
        json!({"project": target.project, "iid": target.iid}),
    );
    let unapprove = object_at(&unapprove, &["result"]);
    assert_applied_mutation(unapprove);
    assert!(unapprove["userId"].as_u64() == approve["userId"].as_u64());
}

#[test]
#[ignore = "commits one configured suggestion only on an explicitly confirmed throwaway GitLab source branch; run this exact test with --exact"]
fn real_broker_gitlab_throwaway_single_suggestion_apply_smoke() {
    require_exact_test_invocation(SUGGESTION_APPLY_TEST);
    require_confirmation(
        "AGENT_ACCESS_REAL_GITLAB_SUGGESTION_APPLY_CONFIRM",
        SUGGESTION_APPLY_CONFIRMATION,
    );
    let target = ReviewMutationTarget::load_and_preflight();
    let locator = SuggestionLocator::load();
    let suggestion = read_configured_suggestion(&target, &locator);
    assert!(suggestion["applicable"].as_bool() == Some(true));
    assert!(suggestion["applied"].as_bool() == Some(false));

    let source_project = required_env("AGENT_ACCESS_REAL_GITLAB_MUTATION_SOURCE_PROJECT");
    let source = invoke_gitlab(
        &target.broker_url,
        "project.view",
        json!({"project": source_project}),
    );
    let source = object_at(&source, &["result", "project"]);
    assert!(
        source["pathWithNamespace"].as_str() == Some(source_project.as_str()),
        "source project preflight did not resolve the configured canonical path"
    );
    let merge_request = invoke_gitlab(
        &target.broker_url,
        "merge_request.view",
        json!({"project": target.project, "iid": target.iid}),
    );
    let merge_request = object_at(&merge_request, &["result", "mergeRequest"]);
    assert!(
        merge_request["sourceProjectId"].as_u64() == source["id"].as_u64(),
        "configured source project must own the throwaway MR source branch"
    );

    let response = invoke_gitlab(
        &target.broker_url,
        "merge_request.suggestion.apply",
        json!({
            "project": target.project,
            "iid": target.iid,
            "expectedHeadSha": target.expected_head_sha,
            "discussionId": locator.discussion_id,
            "noteId": locator.note_id,
            "suggestionId": locator.suggestion_id
        }),
    );
    let result = object_at(&response, &["result"]);
    assert_applied_mutation(result);
    assert_id_array_contains(result, "suggestionIds", locator.suggestion_id);
}

struct SuggestionLocator {
    discussion_id: String,
    note_id: u64,
    suggestion_id: u64,
}

impl SuggestionLocator {
    fn load() -> Self {
        Self {
            discussion_id: required_env("AGENT_ACCESS_REAL_GITLAB_SUGGESTION_DISCUSSION_ID"),
            note_id: required_u64_env("AGENT_ACCESS_REAL_GITLAB_SUGGESTION_NOTE_ID"),
            suggestion_id: required_u64_env("AGENT_ACCESS_REAL_GITLAB_SUGGESTION_ID"),
        }
    }
}

fn read_configured_suggestion(target: &ReviewMutationTarget, locator: &SuggestionLocator) -> Value {
    let response = invoke_gitlab(
        &target.broker_url,
        "merge_request.discussion.view",
        json!({
            "project": target.project,
            "iid": target.iid,
            "discussionId": locator.discussion_id
        }),
    );
    let discussion = object_at(&response, &["result", "discussion"]);
    let note = discussion["notes"]
        .as_array()
        .and_then(|notes| {
            notes
                .iter()
                .find(|note| note["id"].as_u64() == Some(locator.note_id))
        })
        .expect("configured suggestion note must belong to the configured discussion");
    assert!(
        note["position"]["headSha"].as_str() == Some(target.expected_head_sha.as_str()),
        "configured suggestion must belong to the expected source-branch head"
    );
    note["suggestions"]
        .as_array()
        .and_then(|suggestions| {
            suggestions
                .iter()
                .find(|suggestion| suggestion["id"].as_u64() == Some(locator.suggestion_id))
        })
        .cloned()
        .expect("configured suggestion must belong to the configured note")
}

struct ReviewMutationTarget {
    broker_url: String,
    project: String,
    iid: u64,
    source_branch: String,
    expected_head_sha: String,
}

impl ReviewMutationTarget {
    fn load_and_preflight() -> Self {
        let target = Self {
            broker_url: required_env("AGENT_ACCESS_REAL_BROKER_URL"),
            project: required_env("AGENT_ACCESS_REAL_GITLAB_MUTATION_PROJECT"),
            iid: required_u64_env("AGENT_ACCESS_REAL_GITLAB_MUTATION_MERGE_REQUEST_IID"),
            source_branch: required_env("AGENT_ACCESS_REAL_GITLAB_MUTATION_SOURCE_BRANCH"),
            expected_head_sha: required_env("AGENT_ACCESS_REAL_GITLAB_MUTATION_EXPECTED_HEAD_SHA"),
        };
        assert_sha_string(&target.expected_head_sha, "configured expected head SHA");

        let response = invoke_gitlab(
            &target.broker_url,
            "merge_request.view",
            json!({"project": target.project, "iid": target.iid}),
        );
        let merge_request = object_at(&response, &["result", "mergeRequest"]);
        assert!(
            merge_request["project"].as_str() == Some(target.project.as_str()),
            "mutation project preflight did not match"
        );
        assert!(
            merge_request["iid"].as_u64() == Some(target.iid),
            "mutation MR IID preflight did not match"
        );
        assert!(
            merge_request["sourceBranch"].as_str() == Some(target.source_branch.as_str()),
            "mutation source branch preflight did not match"
        );
        assert!(
            merge_request["sha"].as_str() == Some(target.expected_head_sha.as_str()),
            "mutation expected head SHA is stale"
        );
        let diff_refs = object_at_value(&merge_request["diffRefs"], "mutation MR diffRefs");
        assert!(
            diff_refs["headSha"].as_str() == Some(target.expected_head_sha.as_str()),
            "mutation MR diffRefs head did not match"
        );
        assert!(
            merge_request["preparedAt"].as_str().is_some(),
            "mutation MR diff is not prepared"
        );
        assert!(
            merge_request["detailedMergeStatus"].as_str() != Some("preparing"),
            "mutation MR is still preparing"
        );
        target
    }
}

struct MutationTarget {
    broker_url: String,
    project: String,
    iid: u64,
    source_branch: String,
    expected_head_sha: String,
    old_path: String,
    new_path: String,
    new_line: u64,
}

impl MutationTarget {
    fn load_and_preflight() -> Self {
        let target = Self {
            broker_url: required_env("AGENT_ACCESS_REAL_BROKER_URL"),
            project: required_env("AGENT_ACCESS_REAL_GITLAB_MUTATION_PROJECT"),
            iid: required_u64_env("AGENT_ACCESS_REAL_GITLAB_MUTATION_MERGE_REQUEST_IID"),
            source_branch: required_env("AGENT_ACCESS_REAL_GITLAB_MUTATION_SOURCE_BRANCH"),
            expected_head_sha: required_env("AGENT_ACCESS_REAL_GITLAB_MUTATION_EXPECTED_HEAD_SHA"),
            old_path: required_env("AGENT_ACCESS_REAL_GITLAB_MUTATION_OLD_PATH"),
            new_path: required_env("AGENT_ACCESS_REAL_GITLAB_MUTATION_NEW_PATH"),
            new_line: required_u64_env("AGENT_ACCESS_REAL_GITLAB_MUTATION_NEW_LINE"),
        };
        assert_sha_string(&target.expected_head_sha, "configured expected head SHA");

        let response = invoke_gitlab(
            &target.broker_url,
            "merge_request.view",
            json!({"project": target.project, "iid": target.iid}),
        );
        let merge_request = object_at(&response, &["result", "mergeRequest"]);
        assert!(
            merge_request["project"].as_str() == Some(target.project.as_str()),
            "mutation project preflight did not match"
        );
        assert!(
            merge_request["iid"].as_u64() == Some(target.iid),
            "mutation MR IID preflight did not match"
        );
        assert!(
            merge_request["sourceBranch"].as_str() == Some(target.source_branch.as_str()),
            "mutation source branch preflight did not match"
        );
        assert!(
            merge_request["sha"].as_str() == Some(target.expected_head_sha.as_str()),
            "mutation expected head SHA is stale"
        );
        let diff_refs = object_at_value(&merge_request["diffRefs"], "mutation MR diffRefs");
        assert!(
            diff_refs["headSha"].as_str() == Some(target.expected_head_sha.as_str()),
            "mutation MR diffRefs head did not match"
        );
        assert!(
            merge_request["preparedAt"].as_str().is_some(),
            "mutation MR diff is not prepared"
        );
        assert!(
            merge_request["detailedMergeStatus"].as_str() != Some("preparing"),
            "mutation MR is still preparing"
        );
        target
    }

    fn positioned_inputs(&self, content: &str) -> Value {
        json!({
            "project": self.project,
            "iid": self.iid,
            "expectedHeadSha": self.expected_head_sha,
            "content": content,
            "contentFormat": "markdown",
            "position": {
                "positionType": "text",
                "oldPath": self.old_path,
                "newPath": self.new_path,
                "newLine": self.new_line
            }
        })
    }
}

fn invoke_gitlab(broker_url: &str, action: &str, inputs: Value) -> Value {
    let input = TempJsonInput::new(&inputs);
    let output = Command::new(env!("CARGO_BIN_EXE_agent-access"))
        .args(["--url", broker_url, "invoke"])
        .arg(format!("gitlab.{action}"))
        .args(["--input-file", input.path_str()])
        .output()
        .expect("agent-access process must start");
    assert_success(action, &output);
    let response: Value = serde_json::from_slice(&output.stdout)
        .unwrap_or_else(|_| panic!("{action} returned invalid JSON"));
    assert!(
        response["decision"].as_str() == Some("allow"),
        "{action} did not return an allow decision"
    );
    response
}

fn assert_project_preflight(broker_url: &str, project: &str) -> u64 {
    let response = invoke_gitlab(broker_url, "project.view", json!({"project": project}));
    let resolved = object_at(&response, &["result", "project"]);
    assert!(
        resolved["pathWithNamespace"].as_str() == Some(project),
        "webhook project preflight did not resolve the configured canonical path"
    );
    required_json_u64(resolved, "id")
}

fn assert_webhook_identity(webhook: &Value, webhook_id: u64, project_id: u64) {
    assert!(webhook["id"].as_u64() == Some(webhook_id));
    assert!(
        webhook["projectId"].is_null() || webhook["projectId"].as_u64() == Some(project_id),
        "webhook.projectId must be absent or match the preflight project"
    );
    assert_nonempty_string(&webhook["url"], "webhook.url");
    assert!(webhook["events"].as_array().is_some());
    assert!(webhook.get("token").is_none());
    assert!(webhook.get("signingToken").is_none());
}

fn wait_for_webhook_event(broker_url: &str, project: &str, webhook_id: u64) -> Value {
    for attempt in 0..10 {
        let response = invoke_gitlab(
            broker_url,
            "webhook.event.list",
            json!({"project": project, "webhookId": webhook_id, "maxResults": 20}),
        );
        if let Some(event) = array_at(&response, &["result", "events"]).first().cloned() {
            return event;
        }
        if attempt < 9 {
            std::thread::sleep(Duration::from_secs(1));
        }
    }
    panic!("GitLab did not expose the test delivery in bounded webhook event history");
}

struct DisposableWebhook {
    broker_url: String,
    project: String,
    webhook_id: u64,
    armed: bool,
}

impl DisposableWebhook {
    fn new(broker_url: &str, project: &str, webhook_id: u64) -> Self {
        Self {
            broker_url: broker_url.to_string(),
            project: project.to_string(),
            webhook_id,
            armed: true,
        }
    }

    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for DisposableWebhook {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        let _ = std::panic::catch_unwind(|| {
            let inputs = json!({
                "project": self.project,
                "webhookId": self.webhook_id
            });
            let input = TempJsonInput::new(&inputs);
            let _ = Command::new(env!("CARGO_BIN_EXE_agent-access"))
                .args(["--url", self.broker_url.as_str(), "invoke"])
                .arg("gitlab.webhook.delete")
                .args(["--input-file", input.path_str()])
                .output();
        });
    }
}

fn assert_success(action: &str, output: &Output) {
    assert!(
        output.status.success(),
        "{action} failed with status {:?}; response content is intentionally suppressed",
        output.status.code()
    );
}

fn mutation_content() -> String {
    let path = required_env("AGENT_ACCESS_REAL_GITLAB_MUTATION_CONTENT_FILE");
    let content = std::fs::read_to_string(path)
        .expect("AGENT_ACCESS_REAL_GITLAB_MUTATION_CONTENT_FILE must be readable UTF-8");
    assert!(
        !content.trim().is_empty(),
        "GitLab mutation content file must not be empty"
    );
    assert!(
        content.len() <= 4_096,
        "GitLab mutation smoke content must not exceed 4096 bytes"
    );
    content
}

fn require_exact_test_invocation(expected_test: &str) {
    let args = std::env::args().collect::<Vec<_>>();
    assert!(
        args.iter().any(|arg| arg == "--exact") && args.iter().any(|arg| arg == expected_test),
        "refusing mutation: run only {expected_test} with the test harness --exact flag"
    );
}

fn require_confirmation(name: &str, expected: &str) {
    assert!(
        std::env::var(name).as_deref() == Ok(expected),
        "refusing mutation: {name} must equal the documented throwaway confirmation value"
    );
}

fn required_env(name: &str) -> String {
    let value = std::env::var(name).unwrap_or_else(|_| panic!("{name} must be set"));
    assert!(!value.trim().is_empty(), "{name} must not be empty");
    value
}

fn required_u64_env(name: &str) -> u64 {
    let raw = required_env(name);
    let value = raw
        .parse::<u64>()
        .unwrap_or_else(|_| panic!("{name} must be a positive integer"));
    assert!(value > 0, "{name} must be positive");
    value
}

fn object_at<'a>(value: &'a Value, path: &[&str]) -> &'a Value {
    let mut current = value;
    for segment in path {
        current = &current[*segment];
    }
    object_at_value(current, &path.join("."))
}

fn object_at_value<'a>(value: &'a Value, label: &str) -> &'a Value {
    assert!(value.is_object(), "{label} must be an object");
    value
}

fn array_at<'a>(value: &'a Value, path: &[&str]) -> &'a Vec<Value> {
    let mut current = value;
    for segment in path {
        current = &current[*segment];
    }
    current
        .as_array()
        .unwrap_or_else(|| panic!("{} must be an array", path.join(".")))
}

fn required_json_string<'a>(value: &'a Value, field: &str) -> &'a str {
    value[field]
        .as_str()
        .filter(|text| !text.is_empty())
        .unwrap_or_else(|| panic!("{field} must be a non-empty string"))
}

fn required_json_u64(value: &Value, field: &str) -> u64 {
    let result = value[field]
        .as_u64()
        .unwrap_or_else(|| panic!("{field} must be a positive integer"));
    assert!(result > 0, "{field} must be positive");
    result
}

fn assert_applied_mutation(result: &Value) {
    assert!(result["mutationStatus"].as_str() == Some("applied"));
    assert!(result["retrySafe"].as_bool() == Some(false));
}

fn assert_id_array_contains(value: &Value, field: &str, expected_id: u64) {
    let ids = value[field]
        .as_array()
        .unwrap_or_else(|| panic!("{field} must be an array"));
    assert!(
        ids.iter().any(|id| id.as_u64() == Some(expected_id)),
        "{field} must contain the draft created by this smoke"
    );
}

fn assert_diff_position(value: &Value) {
    let position = object_at_value(value, "note.position");
    assert_full_sha(&position["baseSha"], "position.baseSha");
    assert_full_sha(&position["startSha"], "position.startSha");
    assert_full_sha(&position["headSha"], "position.headSha");
    assert_nonempty_string(&position["oldPath"], "position.oldPath");
    assert_nonempty_string(&position["newPath"], "position.newPath");
    assert!(
        position["positionType"].as_str() == Some("text"),
        "configured note must carry a text diff position"
    );

    if let Some(line_range) = position["lineRange"].as_object() {
        assert_line_range_point(&line_range["start"], "lineRange.start");
        assert_line_range_point(&line_range["end"], "lineRange.end");
        assert!(
            positive_line(&position["oldLine"]) || positive_line(&position["newLine"]),
            "multiline position must preserve its top-level anchor"
        );
    } else {
        assert!(
            positive_line(&position["oldLine"]) || positive_line(&position["newLine"]),
            "text position must preserve an old or new line number"
        );
    }
}

fn assert_line_range_point(value: &Value, label: &str) {
    let point = object_at_value(value, label);
    assert_nonempty_string(&point["lineCode"], &format!("{label}.lineCode"));
    assert!(
        matches!(point["type"].as_str(), Some("old" | "new")),
        "{label}.type must be old or new"
    );
    assert!(
        positive_line(&point["oldLine"]) || positive_line(&point["newLine"]),
        "{label} must preserve an old or new line number"
    );
}

fn positive_line(value: &Value) -> bool {
    value.as_u64().is_some_and(|line| line > 0)
}

fn assert_full_sha(value: &Value, label: &str) {
    let sha = value
        .as_str()
        .unwrap_or_else(|| panic!("{label} must be a string"));
    assert_sha_string(sha, label);
}

fn assert_sha_string(sha: &str, label: &str) {
    assert!(
        sha.len() == 40 && sha.bytes().all(|byte| byte.is_ascii_hexdigit()),
        "{label} must be a full 40-character hexadecimal SHA"
    );
}

fn assert_nonempty_string(value: &Value, label: &str) {
    assert!(
        value.as_str().is_some_and(|text| !text.is_empty()),
        "{label} must be a non-empty string"
    );
}

fn assert_optional_bool(value: &Value, label: &str) {
    assert!(
        value.is_null() || value.is_boolean(),
        "{label} must be boolean or null"
    );
}

fn assert_optional_u64(value: &Value, label: &str) {
    assert!(
        value.is_null() || value.is_u64(),
        "{label} must be an unsigned integer or null"
    );
}

struct TempJsonInput {
    path: PathBuf,
    _file: File,
}

impl TempJsonInput {
    fn new(value: &Value) -> Self {
        static NEXT_ID: AtomicU64 = AtomicU64::new(1);
        let path = std::env::temp_dir().join(format!(
            "agent-access-real-gitlab-input-{}-{}.json",
            std::process::id(),
            NEXT_ID.fetch_add(1, Ordering::Relaxed)
        ));
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options
            .open(&path)
            .expect("temporary GitLab invoke input must be created");
        serde_json::to_writer(&mut file, value)
            .expect("temporary GitLab invoke input must be serialized");
        file.flush()
            .expect("temporary GitLab invoke input must be flushed");
        Self { path, _file: file }
    }

    fn path_str(&self) -> &str {
        self.path
            .to_str()
            .expect("temporary GitLab invoke input path must be UTF-8")
    }
}

impl Drop for TempJsonInput {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}
