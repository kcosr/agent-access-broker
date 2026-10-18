/// The GitLab provider around `backend`, paired with its configuration's
/// descriptor.
fn gitlab_service(
    config: agent_access_gitlab::GitlabProviderConfig,
    backend: Arc<dyn agent_access_gitlab::GitlabBackend>,
) -> agent_access_provider::ServiceProvider {
    agent_access_provider::ServiceProvider::new(
        agent_access_gitlab::gitlab_descriptor(&config),
        Arc::new(GitlabProvider::with_backend(config, backend)),
    )
}

#[path = "gitlab_smoke/provisioning.rs"]
mod provisioning;
use agent_access_provider::test_support::bearer_credential;

use agent_access_broker_host::test_support::{
    FixtureDir, IsolatedBroker, ProviderFixture, RunningBroker,
};
use agent_access_gitlab::{
    GitlabApprovalMutationRequest, GitlabApprovalRule, GitlabApprovalRuleListRequest,
    GitlabApprovalRuleSource, GitlabApprovalState, GitlabApprovalSummary, GitlabApprovalUser,
    GitlabBackend, GitlabBackendError, GitlabBackendResponse, GitlabBranch,
    GitlabBranchCreateRequest, GitlabBranchListRequest, GitlabCommit, GitlabCommitCreateRequest,
    GitlabCommitListRequest, GitlabCommitSummary, GitlabContentConfig, GitlabDiffFile,
    GitlabDiffVersion, GitlabDiffVersionSummary, GitlabDiscussion, GitlabDiscussionListRequest,
    GitlabDiscussionNoteDeleteRequest, GitlabDiscussionNoteUpdateRequest,
    GitlabDiscussionReplyRequest, GitlabDiscussionStateChange, GitlabDiscussionStateChangeRequest,
    GitlabDraftBulkPublishRequest, GitlabDraftNote, GitlabDraftNoteCreateRequest,
    GitlabDraftNoteListRequest, GitlabDraftNoteObjectRequest, GitlabDraftNoteUpdateRequest,
    GitlabFile, GitlabFileDeleteRequest, GitlabFileMutation, GitlabFileRequest,
    GitlabFileWriteRequest, GitlabIssue, GitlabIssueCreateRequest, GitlabIssueNoteCreateRequest,
    GitlabIssueSearchRequest, GitlabIssueUpdateRequest, GitlabJob, GitlabJobListRequest,
    GitlabMergeRequest, GitlabMergeRequestCreateRequest, GitlabMergeRequestListRequest,
    GitlabMergeRequestMergeRequest, GitlabMergeRequestObjectRequest,
    GitlabMergeRequestSearchRequest, GitlabMergeRequestUpdateRequest, GitlabMilestoneSummary,
    GitlabNote, GitlabNoteCreateRequest, GitlabNoteDeleteRequest, GitlabNoteListRequest,
    GitlabNoteUpdateRequest, GitlabPage, GitlabPipeline, GitlabPipelineListRequest,
    GitlabPipelineRunRequest, GitlabPositionedDiscussionCreateRequest, GitlabProject,
    GitlabProjectUpload, GitlabProtectedBranch, GitlabProtectedBranchAccessLevel,
    GitlabProtectedBranchListRequest, GitlabProvider, GitlabProviderConfig, GitlabRawFile,
    GitlabReviewSummaryNoteRequest, GitlabReviewer, GitlabServerVersion,
    GitlabSuggestionApplyRequest, GitlabUser, GitlabUserSummary, GitlabWebhook,
    GitlabWebhookCustomHeaderRequest, GitlabWebhookDeliveryAttempt, GitlabWebhookDeliveryEvent,
    GitlabWebhookEvent, GitlabWebhookEventListRequest, GitlabWebhookListRequest,
    GitlabWebhookNamedSecret, GitlabWebhookWriteRequest, GitlabWebhooksConfig,
};
use agent_access_provider::{GIT_REPOSITORY_RESOURCE, ProviderResultStream};
use async_trait::async_trait;
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::pin::Pin;
use std::process::Command;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cli_uploads_gitlab_project_html_through_typed_and_send_commands() {
    let upload_path = temp_path("session.html");
    let send_path = upload_path.parent().unwrap().join("upload.json");
    let contents = b"<!doctype html><title>private-agent-session-content</title>";
    std::fs::write(&upload_path, contents).unwrap();
    let backend = stub_backend();
    let mut document = gitlab_per_user_document();
    for grant in &mut document.grants {
        grant.credential_mode = "service".to_string();
    }
    let broker = start_broker(
        &document,
        gitlab_service(gitlab_provider_config(2), backend.clone()),
    )
    .await;
    let base_url = broker.public_url();

    for locator in [
        vec!["sip/service"],
        vec!["--project-url", "https://gitlab.example.com/sip/service"],
    ] {
        let upload = gitlab_cli(&base_url)
            .args(["gitlab", "project", "upload"])
            .args(locator)
            .args([
                "--file",
                upload_path.to_str().unwrap(),
                "--content-type",
                "text/html",
            ])
            .output()
            .unwrap();
        assert_success("typed project upload", &upload);
        let value: serde_json::Value = serde_json::from_slice(&upload.stdout).unwrap();
        assert_eq!(value["decision"], "allow");
        assert_eq!(value["action"], "project.upload");
        assert_eq!(value["resourceScopes"]["repository"][0], "sip/service");
        assert_eq!(value["result"]["upload"]["id"], 101);
        assert_eq!(
            value["result"]["upload"]["url"],
            "/uploads/0123456789abcdef0123456789abcdef/session.html"
        );
        assert_eq!(
            value["result"]["upload"]["markdown"],
            "[session](/uploads/0123456789abcdef0123456789abcdef/session.html)"
        );
    }

    std::fs::write(
        &send_path,
        serde_json::to_vec(&serde_json::json!({
            "version": "agent-access.send.v1",
            "kind": "invoke",
            "service": "gitlab",
            "action": "project.upload",
            "inputs": {"project": "sip/service"},
            "files": [{"role": "attachment", "path": upload_path, "contentType": "text/html"}]
        }))
        .unwrap(),
    )
    .unwrap();
    let send = gitlab_cli(&base_url)
        .args(["send", "--request-file", send_path.to_str().unwrap()])
        .output()
        .unwrap();
    assert_success("send project upload", &send);
    let value: serde_json::Value = serde_json::from_slice(&send.stdout).unwrap();
    assert_eq!(
        value["result"]["upload"]["fullPath"],
        "/-/project/42/uploads/0123456789abcdef0123456789abcdef/session.html"
    );
    {
        let uploads = backend.uploaded_projects.lock().unwrap();
        assert_eq!(uploads.len(), 3);
        for (project_id, upload) in uploads.iter() {
            assert_eq!(*project_id, 42);
            assert_eq!(upload.file_name.as_deref(), Some("session.html"));
            assert_eq!(upload.content_type.as_deref(), Some("text/html"));
            assert_eq!(upload.bytes, contents);
        }
    }
    let observations = backend.credential_observations.lock().unwrap().clone();
    let writes: Vec<_> = observations
        .iter()
        .filter(|entry| entry.operation == "upload_project")
        .collect();
    assert_eq!(writes.len(), 3);
    assert!(
        writes
            .iter()
            .all(|entry| entry.credential == bearer_credential("gitlab-service-token"))
    );
    let audit = broker.audit().unwrap().text();
    assert!(audit.contains("project.upload"));
    for secret in [
        "private-agent-session-content",
        "gitlab-service-token",
        "gitlab-lookup-token",
        "gitlab-per-user-token",
        "agent-token",
        "0123456789abcdef0123456789abcdef",
    ] {
        assert!(!audit.contains(secret), "audit leaked {secret}");
    }
    stop(broker).await;
    std::fs::remove_dir_all(upload_path.parent().unwrap()).unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cli_gitlab_project_upload_enforces_grants_and_file_limits() {
    let upload_path = temp_path("session.html");
    std::fs::write(&upload_path, b"<html>private-agent-session-content</html>").unwrap();
    for case in ["repository", "action", "size", "media_type"] {
        let backend = stub_backend();
        let mut document = gitlab_document();
        let mut provider_config = gitlab_provider_config(2);
        if case == "action" {
            document.grants[0]
                .actions
                .retain(|action| action != "project.upload");
        } else if case == "size" {
            provider_config.attachments.max_bytes = 8;
        } else if case == "media_type" {
            provider_config.attachments.media_types = vec!["text/plain".to_string()];
        }
        document.provider = provider_config.clone();
        let broker =
            start_broker(&document, gitlab_service(provider_config, backend.clone())).await;
        let base_url = broker.public_url();
        let project = if case == "repository" {
            "secret/service"
        } else {
            "sip/service"
        };
        let upload = Command::new(env!("CARGO_BIN_EXE_agent-access"))
            .args(["--url", &base_url, "--no-token"])
            .args([
                "gitlab",
                "project",
                "upload",
                project,
                "--file",
                upload_path.to_str().unwrap(),
                "--content-type",
                "text/html",
            ])
            .output()
            .unwrap();
        assert!(
            !upload.status.success(),
            "{case} upload unexpectedly succeeded"
        );
        let value: serde_json::Value = serde_json::from_slice(&upload.stdout).unwrap();
        assert_ne!(value["decision"], "allow", "{case}: {value}");
        assert!(
            backend.uploaded_projects.lock().unwrap().is_empty(),
            "{case} reached upstream upload"
        );
        let audit = broker.audit().unwrap();
        audit.require_action("gitlab", "project.upload");
        let audit = audit.text();
        assert!(!audit.contains("private-agent-session-content"));
        assert!(!audit.contains("gitlab-service-token"));
        stop(broker).await;
    }
    std::fs::remove_dir_all(upload_path.parent().unwrap()).unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cli_invokes_gitlab_read_actions_against_stubbed_backend() {
    let backend = stub_backend();
    let broker = start_broker(
        &gitlab_document(),
        gitlab_service(gitlab_provider_config(2), backend.clone()),
    )
    .await;
    let base_url = broker.public_url();

    let project = Command::new(env!("CARGO_BIN_EXE_agent-access"))
        .args([
            "--url",
            &base_url,
            "--no-token",
            "gitlab",
            "project",
            "view",
            "sip/service",
        ])
        .output()
        .unwrap();
    assert_success("project view", &project);
    let project_json: serde_json::Value = serde_json::from_slice(&project.stdout).unwrap();
    assert_eq!(project_json["decision"], "allow");
    assert_eq!(
        project_json["result"]["project"]["pathWithNamespace"],
        "sip/service"
    );
    assert_eq!(
        project_json["resourceScopes"]["repository"][0],
        "sip/service"
    );

    let issue = Command::new(env!("CARGO_BIN_EXE_agent-access"))
        .args([
            "--url",
            &base_url,
            "--no-token",
            "gitlab",
            "issue",
            "view",
            "--issue-url",
            "https://gitlab.example.com/sip/service/-/issues/7",
        ])
        .output()
        .unwrap();
    assert_success("issue view", &issue);
    let issue_json: serde_json::Value = serde_json::from_slice(&issue.stdout).unwrap();
    assert_eq!(issue_json["result"]["issue"]["iid"], 7);
    assert_eq!(issue_json["result"]["issue"]["title"], "visible issue");
    assert_eq!(
        issue_json["result"]["issue"]["description"],
        "issue context"
    );
    assert_eq!(
        issue_json["result"]["issue"]["createdAt"],
        "2026-06-01T10:00:00.000Z"
    );
    assert_eq!(issue_json["result"]["issue"]["author"]["username"], "alice");
    assert_eq!(
        issue_json["result"]["issue"]["assignees"][0]["username"],
        "bob"
    );
    assert_eq!(issue_json["result"]["issue"]["milestone"]["title"], "M1");

    let issue_search = Command::new(env!("CARGO_BIN_EXE_agent-access"))
        .args([
            "--url",
            &base_url,
            "--no-token",
            "gitlab",
            "issue",
            "search",
            "sip/service",
            "--state",
            "opened",
            "--label",
            "bug",
            "--search",
            "visible",
            "--max-results",
            "100",
        ])
        .output()
        .unwrap();
    assert_success("issue search", &issue_search);
    let issue_search_json: serde_json::Value =
        serde_json::from_slice(&issue_search.stdout).unwrap();
    assert_eq!(
        issue_search_json["result"]["issues"][0]["project"],
        "sip/service"
    );
    assert_eq!(
        issue_search_json["result"]["issues"][0]["updatedAt"],
        "2026-06-02T11:00:00.000Z"
    );
    assert_eq!(
        issue_search_json["result"]["issues"][0]["labels"][1],
        "triaged"
    );
    assert_eq!(issue_search_json["result"]["count"], 1);
    assert_eq!(issue_search_json["result"]["maxResults"], 2);
    assert_eq!(issue_search_json["result"]["isLast"], false);
    let issue_next_page_token = issue_search_json["result"]["nextPageToken"]
        .as_str()
        .unwrap();
    let issue_search_second_page = Command::new(env!("CARGO_BIN_EXE_agent-access"))
        .args([
            "--url",
            &base_url,
            "--no-token",
            "gitlab",
            "issue",
            "search",
            "sip/service",
            "--state",
            "opened",
            "--label",
            "bug",
            "--search",
            "visible",
            "--max-results",
            "100",
            "--page-token",
            issue_next_page_token,
        ])
        .output()
        .unwrap();
    assert_success("issue search second page", &issue_search_second_page);
    let issue_second_page_json: serde_json::Value =
        serde_json::from_slice(&issue_search_second_page.stdout).unwrap();
    assert_eq!(issue_second_page_json["result"]["isLast"], true);
    assert!(issue_second_page_json["result"]["nextPageToken"].is_null());
    let last_issue_search = backend.last_issue_search.lock().unwrap().clone().unwrap();
    assert_eq!(last_issue_search.project_id, 42);
    assert_eq!(last_issue_search.request.max_results, 2);
    assert_eq!(last_issue_search.request.page, 2);
    assert_eq!(last_issue_search.request.labels, vec!["bug".to_string()]);

    let merge_request = Command::new(env!("CARGO_BIN_EXE_agent-access"))
        .args([
            "--url",
            &base_url,
            "--no-token",
            "gitlab",
            "merge-request",
            "view",
            "sip/service",
            "5",
        ])
        .output()
        .unwrap();
    assert_success("merge request view", &merge_request);
    let merge_request_json: serde_json::Value =
        serde_json::from_slice(&merge_request.stdout).unwrap();
    assert_eq!(
        merge_request_json["result"]["mergeRequest"]["title"],
        "visible merge request"
    );
    assert_eq!(
        merge_request_json["result"]["mergeRequest"]["description"],
        "merge request context"
    );
    assert_eq!(
        merge_request_json["result"]["mergeRequest"]["createdAt"],
        "2026-06-03T12:00:00.000Z"
    );
    assert_eq!(
        merge_request_json["result"]["mergeRequest"]["reviewers"][0]["username"],
        "carol"
    );
    assert_eq!(merge_request_json["result"]["mergeRequest"]["draft"], true);
    assert_eq!(
        merge_request_json["result"]["mergeRequest"]["diffRefs"]["headSha"],
        TEST_SHA
    );
    assert_eq!(
        merge_request_json["result"]["mergeRequest"]["headPipeline"]["id"],
        901
    );

    let merge_request_search = Command::new(env!("CARGO_BIN_EXE_agent-access"))
        .args([
            "--url",
            &base_url,
            "--no-token",
            "gitlab",
            "merge-request",
            "search",
            "sip/service",
            "--state",
            "opened",
            "--source-branch",
            "feature/rest",
            "--max-results",
            "100",
        ])
        .output()
        .unwrap();
    assert_success("merge request search", &merge_request_search);
    let merge_request_search_json: serde_json::Value =
        serde_json::from_slice(&merge_request_search.stdout).unwrap();
    assert_eq!(
        merge_request_search_json["result"]["mergeRequests"][0]["updatedAt"],
        "2026-06-04T13:00:00.000Z"
    );
    assert_eq!(
        merge_request_search_json["result"]["mergeRequests"][0]["labels"][0],
        "review"
    );
    assert_eq!(merge_request_search_json["result"]["count"], 1);
    assert_eq!(merge_request_search_json["result"]["maxResults"], 2);
    assert_eq!(merge_request_search_json["result"]["isLast"], false);
    let merge_request_next_page_token = merge_request_search_json["result"]["nextPageToken"]
        .as_str()
        .unwrap();
    let merge_request_search_second_page = Command::new(env!("CARGO_BIN_EXE_agent-access"))
        .args([
            "--url",
            &base_url,
            "--no-token",
            "gitlab",
            "merge-request",
            "search",
            "sip/service",
            "--state",
            "opened",
            "--source-branch",
            "feature/rest",
            "--max-results",
            "100",
            "--page-token",
            merge_request_next_page_token,
        ])
        .output()
        .unwrap();
    assert_success(
        "merge request search second page",
        &merge_request_search_second_page,
    );
    let merge_request_second_page_json: serde_json::Value =
        serde_json::from_slice(&merge_request_search_second_page.stdout).unwrap();
    assert_eq!(merge_request_second_page_json["result"]["isLast"], true);
    assert!(merge_request_second_page_json["result"]["nextPageToken"].is_null());
    let last_merge_request_search = backend
        .last_merge_request_search
        .lock()
        .unwrap()
        .clone()
        .unwrap();
    assert_eq!(last_merge_request_search.project_id, 42);
    assert_eq!(last_merge_request_search.request.max_results, 2);
    assert_eq!(last_merge_request_search.request.page, 2);
    assert_eq!(
        last_merge_request_search.request.source_branch.as_deref(),
        Some("feature/rest")
    );

    let branch_list = Command::new(env!("CARGO_BIN_EXE_agent-access"))
        .args([
            "--url",
            &base_url,
            "--no-token",
            "gitlab",
            "branch",
            "list",
            "sip/service",
            "--search",
            "main",
        ])
        .output()
        .unwrap();
    assert_success("branch list", &branch_list);
    let branch_list_json: serde_json::Value = serde_json::from_slice(&branch_list.stdout).unwrap();
    assert_eq!(branch_list_json["result"]["branches"][0]["name"], "main");
    let last_branch_list = backend.last_branch_list.lock().unwrap().clone().unwrap();
    assert_eq!(last_branch_list.project_id, 42);
    assert_eq!(last_branch_list.request.search.as_deref(), Some("main"));

    let branch = Command::new(env!("CARGO_BIN_EXE_agent-access"))
        .args([
            "--url",
            &base_url,
            "--no-token",
            "gitlab",
            "branch",
            "view",
            "sip/service",
            "main",
        ])
        .output()
        .unwrap();
    assert_success("branch view", &branch);
    let branch_json: serde_json::Value = serde_json::from_slice(&branch.stdout).unwrap();
    assert_eq!(branch_json["result"]["branch"]["name"], "main");

    let commit_list = Command::new(env!("CARGO_BIN_EXE_agent-access"))
        .args([
            "--url",
            &base_url,
            "--no-token",
            "gitlab",
            "commit",
            "list",
            "sip/service",
            "--ref-name",
            "main",
            "--first-parent",
            "true",
            "--max-results",
            "100",
        ])
        .output()
        .unwrap();
    assert_success("commit list", &commit_list);
    let commit_list_json: serde_json::Value = serde_json::from_slice(&commit_list.stdout).unwrap();
    assert_eq!(commit_list_json["result"]["commits"][0]["id"], TEST_SHA);
    let last_commit_list = backend.last_commit_list.lock().unwrap().clone().unwrap();
    assert_eq!(last_commit_list.project_id, 42);
    assert_eq!(last_commit_list.request.max_results, 2);
    assert_eq!(last_commit_list.request.first_parent, Some(true));

    let commit = Command::new(env!("CARGO_BIN_EXE_agent-access"))
        .args([
            "--url",
            &base_url,
            "--no-token",
            "gitlab",
            "commit",
            "view",
            "sip/service",
            TEST_SHA,
        ])
        .output()
        .unwrap();
    assert_success("commit view", &commit);
    let commit_json: serde_json::Value = serde_json::from_slice(&commit.stdout).unwrap();
    assert_eq!(commit_json["result"]["commit"]["title"], "initial commit");

    let denied = Command::new(env!("CARGO_BIN_EXE_agent-access"))
        .args([
            "--url",
            &base_url,
            "--no-token",
            "gitlab",
            "project",
            "view",
            "secret/service",
        ])
        .output()
        .unwrap();
    assert_eq!(
        denied.status.code(),
        Some(2),
        "denied project view: stdout={} stderr={}",
        String::from_utf8_lossy(&denied.stdout),
        String::from_utf8_lossy(&denied.stderr)
    );
    let denied_json: serde_json::Value = serde_json::from_slice(&denied.stdout).unwrap();
    assert_eq!(denied_json["decision"], "deny");
    assert_eq!(denied_json["reasonCode"], "scope_unresolved");
    assert!(!String::from_utf8_lossy(&denied.stdout).contains("secret"));

    let audit = broker.audit().unwrap().text();
    assert!(audit.contains("\"service\":\"gitlab\""));
    assert!(audit.contains("\"action\":\"project.view\""));
    assert!(audit.contains("\"action\":\"issue.view\""));
    assert!(audit.contains("\"action\":\"merge_request.search\""));
    assert!(audit.contains("\"repository\":[\"sip/service\"]"));
    assert!(!audit.contains("visible issue"));
    assert!(!audit.contains("visible merge request"));

    stop(broker).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cli_invokes_all_gitlab_webhook_actions_and_preserves_secret_files() {
    let backend = stub_backend();
    let broker = start_broker(
        &gitlab_document(),
        gitlab_service(gitlab_provider_config(20), backend.clone()),
    )
    .await;
    let base_url = broker.public_url();

    let run = |args: &[&str]| {
        let output = Command::new(env!("CARGO_BIN_EXE_agent-access"))
            .args(["--url", &base_url, "--no-token", "gitlab", "webhook"])
            .args(args)
            .output()
            .unwrap();
        assert_success(&args.join(" "), &output);
        output
    };

    run(&["list", "sip/service", "--max-results", "20"]);
    run(&["view", "sip/service", "42"]);

    let signing_token_path = temp_path("gitlab-webhook-signing-token.txt");
    let signing_token = "whsec_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
    std::fs::write(&signing_token_path, signing_token).unwrap();
    let create = Command::new(env!("CARGO_BIN_EXE_agent-access"))
        .args([
            "--url",
            &base_url,
            "--no-token",
            "gitlab",
            "webhook",
            "create",
            "sip/service",
            "--destination-url",
            "https://hooks.example.com/new",
            "--event",
            "push",
            "--secret-token-env",
            "WEBHOOK_CLI_TOKEN",
            "--signing-token-file",
            signing_token_path.to_str().unwrap(),
        ])
        .env("WEBHOOK_CLI_TOKEN", "legacy-token")
        .output()
        .unwrap();
    assert!(
        create.status.success(),
        "webhook create failed: stdout={} stderr={} audit={}",
        String::from_utf8_lossy(&create.stdout),
        String::from_utf8_lossy(&create.stderr),
        broker.audit().unwrap().text(),
    );
    assert!(!String::from_utf8_lossy(&create.stdout).contains("legacy-token"));
    let write = backend.last_webhook_write.lock().unwrap().clone().unwrap();
    assert_eq!(write.token.as_deref(), Some("legacy-token"));
    assert_eq!(write.signing_token.as_deref(), Some(signing_token));

    run(&[
        "update",
        "sip/service",
        "43",
        "--clear-events",
        "--clear-description",
    ]);
    let write = backend.last_webhook_write.lock().unwrap().clone().unwrap();
    assert_eq!(write.events, Some(Vec::new()));
    assert_eq!(write.description, Some(None));

    run(&["test", "sip/service", "43", "--event", "push"]);
    run(&[
        "event",
        "list",
        "sip/service",
        "43",
        "--status",
        "successful",
        "--max-results",
        "20",
    ]);
    run(&["event", "resend", "sip/service", "43", "9001"]);

    let header_path = temp_path("gitlab-webhook-header.txt");
    std::fs::write(&header_path, "Bearer receiver-secret").unwrap();
    run(&[
        "custom-header",
        "set",
        "sip/service",
        "43",
        "Authorization",
        "--value-file",
        header_path.to_str().unwrap(),
    ]);
    assert_eq!(
        backend
            .last_webhook_header
            .lock()
            .unwrap()
            .as_ref()
            .and_then(|request| request.value.as_deref()),
        Some("Bearer receiver-secret")
    );
    run(&[
        "custom-header",
        "delete",
        "sip/service",
        "43",
        "Authorization",
    ]);
    run(&["delete", "sip/service", "43"]);
    assert!(!backend.webhooks.lock().unwrap().contains_key(&43));

    stop(broker).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn broker_exposes_gitlab_merge_request_review_reads_against_stubbed_backend() {
    let raw_diff_path = temp_path("gitlab-review.diff");
    let backend = stub_backend();
    let broker = start_broker(
        &gitlab_document(),
        gitlab_service(gitlab_provider_config(2), backend.clone()),
    )
    .await;
    let base_url = broker.public_url();
    let client = reqwest::Client::new();

    let discussion = invoke_gitlab(
        &client,
        &base_url,
        "merge_request.discussion.view",
        "gitlab-review-discussion-view",
        serde_json::json!({
            "inputs": {
                "project": "sip/service",
                "iid": 5,
                "discussionId": "discussion-1"
            }
        }),
    )
    .await;
    let note = &discussion["result"]["discussion"]["notes"][0];
    assert_eq!(note["type"], "DiffNote");
    assert_eq!(note["commitId"], TEST_SHA);
    assert_eq!(note["position"]["headSha"], TEST_SHA);
    assert_eq!(note["position"]["oldPath"], "src/old.rs");
    assert_eq!(note["position"]["newPath"], "src/new.rs");
    assert_eq!(note["position"]["oldLine"], 31);
    assert_eq!(note["position"]["newLine"], 34);
    assert_eq!(note["position"]["lineRange"]["start"]["type"], "old");
    assert_eq!(note["position"]["lineRange"]["end"]["type"], "new");
    assert_eq!(note["resolvedAt"], "2026-06-05T14:00:00.000Z");
    assert_eq!(note["suggestions"][0]["toContent"], "safe_call()");

    let reviewers = invoke_gitlab(
        &client,
        &base_url,
        "merge_request.reviewer.list",
        "gitlab-review-reviewer-list",
        serde_json::json!({"inputs":{"project":"sip/service","iid":5,"maxResults":100}}),
    )
    .await;
    assert_eq!(
        reviewers["result"]["reviewers"][0]["user"]["username"],
        "carol"
    );
    assert_eq!(
        reviewers["result"]["reviewers"][0]["state"],
        "requested_changes"
    );
    assert_eq!(reviewers["result"]["count"], 1);
    assert_eq!(reviewers["result"]["maxResults"], 2);
    assert_eq!(reviewers["result"]["isLast"], false);
    let reviewer_page_token = reviewers["result"]["nextPageToken"]
        .as_str()
        .unwrap()
        .to_string();
    let reviewers_second_page = invoke_gitlab(
        &client,
        &base_url,
        "merge_request.reviewer.list",
        "gitlab-review-reviewer-list-page-2",
        serde_json::json!({
            "inputs": {
                "project": "sip/service",
                "iid": 5,
                "maxResults": 100,
                "pageToken": reviewer_page_token
            }
        }),
    )
    .await;
    assert_eq!(reviewers_second_page["result"]["isLast"], true);
    assert!(reviewers_second_page["result"]["nextPageToken"].is_null());
    let observed_reviewer_page = backend
        .last_merge_request_reviewer_list
        .lock()
        .unwrap()
        .clone()
        .unwrap();
    assert_eq!(observed_reviewer_page.project_id, 42);
    assert_eq!(observed_reviewer_page.request.page, 2);

    let commits = invoke_gitlab(
        &client,
        &base_url,
        "merge_request.commit.list",
        "gitlab-review-commit-list",
        serde_json::json!({"inputs":{"project":"sip/service","iid":5,"maxResults":2}}),
    )
    .await;
    assert_eq!(commits["result"]["commits"][0]["id"], TEST_SHA);

    let pipelines = invoke_gitlab(
        &client,
        &base_url,
        "merge_request.pipeline.list",
        "gitlab-review-pipeline-list",
        serde_json::json!({"inputs":{"project":"sip/service","iid":5,"maxResults":2}}),
    )
    .await;
    assert_eq!(pipelines["result"]["pipelines"][0]["id"], 901);
    assert_eq!(pipelines["result"]["pipelines"][0]["ref"], "feature/rest");

    let diffs = invoke_gitlab(
        &client,
        &base_url,
        "merge_request.diff.list",
        "gitlab-review-diff-list",
        serde_json::json!({"inputs":{"project":"sip/service","iid":5,"maxResults":2}}),
    )
    .await;
    assert_eq!(diffs["result"]["diffs"][0]["oldPath"], "src/old.rs");
    assert_eq!(diffs["result"]["diffs"][0]["newPath"], "src/new.rs");
    assert_eq!(diffs["result"]["diffs"][0]["renamedFile"], true);
    assert_eq!(diffs["result"]["diffs"][0]["collapsed"], false);
    assert_eq!(diffs["result"]["diffs"][0]["tooLarge"], false);

    let versions = invoke_gitlab(
        &client,
        &base_url,
        "merge_request.diff_version.list",
        "gitlab-review-diff-version-list",
        serde_json::json!({"inputs":{"project":"sip/service","iid":5,"maxResults":2}}),
    )
    .await;
    assert_eq!(versions["result"]["diffVersions"][0]["id"], 77);
    assert_eq!(
        versions["result"]["diffVersions"][0]["headCommitSha"],
        TEST_SHA
    );
    assert_eq!(versions["result"]["diffVersions"][0]["state"], "collected");

    let version = invoke_gitlab(
        &client,
        &base_url,
        "merge_request.diff_version.view",
        "gitlab-review-diff-version-view",
        serde_json::json!({"inputs":{"project":"sip/service","iid":5,"diffVersionId":77}}),
    )
    .await;
    assert_eq!(version["result"]["diffVersion"]["id"], 77);
    assert_eq!(
        version["result"]["diffVersion"]["commits"][0]["id"],
        TEST_SHA
    );
    assert_eq!(
        version["result"]["diffVersion"]["diffs"][0]["newPath"],
        "src/new.rs"
    );
    let observed_version = backend
        .last_merge_request_diff_version_view
        .lock()
        .unwrap()
        .clone()
        .unwrap();
    assert_eq!(observed_version.project_id, 42);
    assert_eq!(observed_version.request.object_id, 77);

    let raw_diff = gitlab_cli(&base_url)
        .args([
            "gitlab",
            "merge-request",
            "diff-raw",
            "sip/service",
            "5",
            "--output",
            raw_diff_path.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert_success("merge request raw diff", &raw_diff);
    assert_eq!(
        std::fs::read(&raw_diff_path).unwrap(),
        b"diff --git a/src/old.rs b/src/new.rs\n"
    );
    let raw_diff_json: serde_json::Value = serde_json::from_slice(&raw_diff.stdout).unwrap();
    assert_eq!(raw_diff_json["result"]["iid"], 5);
    assert_eq!(raw_diff_json["result"]["headShaAtPreflight"], TEST_SHA);
    assert_eq!(raw_diff_json["result"]["contentType"], "text/x-diff");

    let audit = broker.audit().unwrap().text();
    for action in [
        "merge_request.discussion.view",
        "merge_request.reviewer.list",
        "merge_request.commit.list",
        "merge_request.pipeline.list",
        "merge_request.diff.list",
        "merge_request.diff_version.list",
        "merge_request.diff_version.view",
        "merge_request.diff.raw.download",
    ] {
        assert!(audit.contains(&format!("\"action\":\"{action}\"")));
    }
    assert!(!audit.contains("unsafe_call()"));
    assert!(!audit.contains("safe_call()"));
    assert!(!audit.contains("@@ -31,3 +34,3 @@"));
    assert!(!audit.contains("diff --git a/src/old.rs b/src/new.rs"));
    assert!(!audit.contains(&reviewer_page_token));

    stop(broker).await;
}

/// The Broker stops a raw download at `limits.max_download_bytes` even when
/// the provider streams past it: the CLI reports the truncated download as a
/// failure and keeps the existing destination, and the terminal audit record
/// keeps the overflow. A body exactly at the limit downloads.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn broker_download_limit_fails_a_raw_diff_streamed_past_it() {
    let output_path = temp_path("gitlab-download-limit.diff");
    std::fs::write(&output_path, b"original").unwrap();
    let backend = stub_backend();
    backend.streamed_raw_diffs.lock().unwrap().extend([
        // 16 bytes: the first chunk fits the 12-byte limit, the second
        // would pass it.
        vec![&b"0123456789"[..], &b"abcdef"[..]],
        // Exactly 12 bytes.
        vec![&b"0123456789"[..], &b"ab"[..]],
    ]);
    let mut provider_config = gitlab_provider_config(2);
    provider_config.content.max_raw_download_bytes = 12;
    let mut document = gitlab_document();
    document.provider = provider_config.clone();
    document.max_download_bytes = Some(12);
    let broker = start_broker(&document, gitlab_service(provider_config, backend)).await;
    let audit = broker.audit().unwrap();
    let base_url = broker.public_url();
    let diff_raw = || {
        gitlab_cli(&base_url)
            .args([
                "gitlab",
                "merge-request",
                "diff-raw",
                "sip/service",
                "5",
                "--output",
                output_path.to_str().unwrap(),
            ])
            .output()
            .unwrap()
    };

    let overrun = diff_raw();
    assert_eq!(
        overrun.status.code(),
        Some(5),
        "an overrun download must fail as a transfer: stdout={} stderr={}",
        String::from_utf8_lossy(&overrun.stdout),
        String::from_utf8_lossy(&overrun.stderr)
    );
    assert!(overrun.stdout.is_empty(), "no download receipt is printed");
    assert_eq!(std::fs::read(&output_path).unwrap(), b"original");

    let at_limit = diff_raw();
    assert_success("raw diff at the download limit", &at_limit);
    assert_eq!(std::fs::read(&output_path).unwrap(), b"0123456789ab");
    stop(broker).await;

    let terminal = audit
        .require_action("gitlab", "merge_request.diff.raw.download")
        .into_iter()
        .filter(|record| record["providerAudit"]["streamPhase"] != "started")
        .collect::<Vec<_>>();
    assert_eq!(terminal.len(), 2, "{terminal:?}");
    let failed = terminal
        .iter()
        .find(|record| record["providerAudit"]["streamPhase"] == "failed")
        .expect("the overrun's terminal record");
    assert_eq!(failed["decision"], "error");
    assert_eq!(failed["reasonCode"], "attachment_size_denied");
    assert_eq!(
        failed["providerAudit"]["streamMessage"],
        "raw download exceeded the download limit"
    );
    // Only the chunk within the limit was delivered.
    assert_eq!(failed["providerAudit"]["streamBytes"], 10);
    assert_eq!(
        failed["providerAudit"]["streamSha256"],
        "84d89877f0d4041efb6bf91a16f0248f2fd573e6af05c19f96bedb9f882f7882"
    );
    let completed = terminal
        .iter()
        .find(|record| record["providerAudit"]["streamPhase"] == "completed")
        .expect("the at-limit download's terminal record");
    assert_eq!(completed["providerAudit"]["streamBytes"], 12);
    assert_eq!(
        completed["providerAudit"]["streamSha256"],
        "d407ad901895723f32d31e6515f5284beb4c01e70e56720d65099da4771f3193"
    );
    std::fs::remove_file(output_path).unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cli_and_http_cover_gitlab_approval_and_suggestion_workflows() {
    let backend = stub_backend();
    let broker = start_broker(
        &gitlab_per_user_document(),
        gitlab_service(gitlab_provider_config(2), backend.clone()),
    )
    .await;
    let base_url = broker.public_url();

    let approval = gitlab_cli(&base_url)
        .args([
            "gitlab",
            "merge-request",
            "view-approval",
            "sip/service",
            "5",
        ])
        .output()
        .unwrap();
    assert_success("view approval", &approval);
    let approval_json: serde_json::Value = serde_json::from_slice(&approval.stdout).unwrap();
    assert_eq!(approval_json["result"]["approval"]["approved"], false);
    assert_eq!(
        approval_json["result"]["approval"]["userHasApproved"],
        false
    );
    assert_eq!(approval_json["result"]["approval"]["userCanApprove"], true);

    let approval_state = gitlab_cli(&base_url)
        .args([
            "gitlab",
            "merge-request",
            "view-approval-state",
            "sip/service",
            "5",
        ])
        .output()
        .unwrap();
    assert_success("view approval state", &approval_state);
    let state_json: serde_json::Value = serde_json::from_slice(&approval_state.stdout).unwrap();
    assert_eq!(
        state_json["result"]["approvalState"]["approvalRulesOverwritten"],
        true
    );
    assert_eq!(
        state_json["result"]["approvalState"]["rules"][0]["sourceRule"]["approvalsRequired"],
        2
    );

    let rules = gitlab_cli(&base_url)
        .args([
            "gitlab",
            "merge-request",
            "list-approval-rules",
            "sip/service",
            "5",
            "--max-results",
            "2",
        ])
        .output()
        .unwrap();
    assert_success("list approval rules", &rules);
    let rules_json: serde_json::Value = serde_json::from_slice(&rules.stdout).unwrap();
    assert_eq!(rules_json["result"]["approvalRules"][0]["codeOwner"], true);
    assert_eq!(rules_json["result"]["count"], 1);

    let rule = gitlab_cli(&base_url)
        .args([
            "gitlab",
            "merge-request",
            "view-approval-rule",
            "sip/service",
            "5",
            "71",
        ])
        .output()
        .unwrap();
    assert_success("view approval rule", &rule);
    let rule_json: serde_json::Value = serde_json::from_slice(&rule.stdout).unwrap();
    assert_eq!(rule_json["result"]["approvalRule"]["id"], 71);
    assert_eq!(rule_json["result"]["approvalRule"]["section"], "Security");

    let client = reqwest::Client::new();
    let approve = gitlab_cli(&base_url)
        .args([
            "gitlab",
            "merge-request",
            "approve",
            "sip/service",
            "5",
            "--head-sha",
            TEST_SHA,
        ])
        .output()
        .unwrap();
    assert_success("approve merge request", &approve);
    let approve_json: serde_json::Value = serde_json::from_slice(&approve.stdout).unwrap();
    assert_eq!(approve_json["result"]["mutationStatus"], "applied");
    assert_eq!(approve_json["result"]["approved"], true);
    let observed_approval = backend
        .last_approval_mutation
        .lock()
        .unwrap()
        .clone()
        .unwrap();
    assert_eq!(observed_approval.iid, 5);
    assert_eq!(observed_approval.head_sha.as_deref(), Some(TEST_SHA));

    *backend.aggregate_approval_override.lock().unwrap() = Some(false);
    let writes_before = backend_operation_count(&backend, "set_merge_request_approval");
    let (status, already_approved) = invoke_gitlab_outcome(
        &client,
        &base_url,
        "merge_request.approve",
        "gitlab-approve-already-approved",
        serde_json::json!({"inputs":{
            "project":"sip/service", "iid":5, "headSha":TEST_SHA
        }}),
    )
    .await;
    assert_eq!(status, reqwest::StatusCode::CONFLICT, "{already_approved}");
    assert_eq!(already_approved["reasonCode"], "version_conflict");
    assert_eq!(
        backend_operation_count(&backend, "set_merge_request_approval"),
        writes_before
    );
    let actor_specific = invoke_gitlab(
        &client,
        &base_url,
        "merge_request.approval.view",
        "gitlab-approved-actor-aggregate-false",
        serde_json::json!({"inputs":{"project":"sip/service","iid":5}}),
    )
    .await;
    assert_eq!(actor_specific["result"]["approval"]["approved"], false);
    assert_eq!(
        actor_specific["result"]["approval"]["userHasApproved"],
        true
    );
    *backend.aggregate_approval_override.lock().unwrap() = None;

    let unapprove = gitlab_cli(&base_url)
        .args(["gitlab", "merge-request", "unapprove", "sip/service", "5"])
        .output()
        .unwrap();
    assert_success("unapprove merge request", &unapprove);
    let unapprove_json: serde_json::Value = serde_json::from_slice(&unapprove.stdout).unwrap();
    assert_eq!(unapprove_json["result"]["approved"], false);
    assert!(
        backend
            .last_approval_mutation
            .lock()
            .unwrap()
            .as_ref()
            .unwrap()
            .head_sha
            .is_none()
    );

    *backend.aggregate_approval_override.lock().unwrap() = Some(true);
    let writes_before = backend_operation_count(&backend, "set_merge_request_approval");
    let (status, not_approved) = invoke_gitlab_outcome(
        &client,
        &base_url,
        "merge_request.unapprove",
        "gitlab-unapprove-not-approved",
        serde_json::json!({"inputs":{"project":"sip/service","iid":5}}),
    )
    .await;
    assert_eq!(status, reqwest::StatusCode::CONFLICT, "{not_approved}");
    assert_eq!(not_approved["reasonCode"], "version_conflict");
    assert_eq!(
        backend_operation_count(&backend, "set_merge_request_approval"),
        writes_before
    );
    let actor_specific = invoke_gitlab(
        &client,
        &base_url,
        "merge_request.approval.view",
        "gitlab-unapproved-actor-aggregate-true",
        serde_json::json!({"inputs":{"project":"sip/service","iid":5}}),
    )
    .await;
    assert_eq!(actor_specific["result"]["approval"]["approved"], true);
    assert_eq!(
        actor_specific["result"]["approval"]["userHasApproved"],
        false
    );
    *backend.aggregate_approval_override.lock().unwrap() = None;

    let single_input = format!(
        r#"{{"project":"sip/service","iid":5,"expectedHeadSha":"{TEST_SHA}","discussionId":"discussion-1","noteId":900,"suggestionId":456,"commitMessage":"Apply review suggestion"}}"#
    );
    let discussion_reads_before = backend_operation_count(&backend, "merge_request_discussion");
    let single = gitlab_cli(&base_url)
        .args([
            "invoke",
            "gitlab.merge_request.suggestion.apply",
            "--input-json",
            &single_input,
        ])
        .output()
        .unwrap();
    assert_success("invoke suggestion apply", &single);
    let single: serde_json::Value = serde_json::from_slice(&single.stdout).unwrap();
    assert_eq!(single["result"]["mutationStatus"], "applied");
    assert_eq!(single["result"]["suggestionIds"], serde_json::json!([456]));
    assert!(single["result"].get("commitId").is_none());
    let observed_single = backend
        .last_suggestion_apply
        .lock()
        .unwrap()
        .clone()
        .unwrap();
    assert_eq!(observed_single.suggestion_ids, vec![456]);
    assert_eq!(
        observed_single.commit_message.as_deref(),
        Some("Apply review suggestion")
    );
    assert_eq!(
        backend_operation_count(&backend, "merge_request_discussion"),
        discussion_reads_before + 2,
        "suggestion apply must perform one scoped preflight and one post-mutation readback"
    );

    *backend.suggestions_applied.lock().unwrap() = false;
    let send_path = temp_path("gitlab-suggestion-send.json");
    std::fs::write(
        &send_path,
        format!(
            r#"{{"version":"agent-access.send.v1","kind":"invoke","service":"gitlab","action":"merge_request.suggestion.batch_apply","inputs":{{"project":"sip/service","iid":5,"expectedHeadSha":"{TEST_SHA}","suggestions":[{{"discussionId":"discussion-1","noteId":900,"suggestionId":456}},{{"discussionId":"discussion-1","noteId":900,"suggestionId":457}}]}}}}"#
        ),
    )
    .unwrap();
    let batch = gitlab_cli(&base_url)
        .args(["send", "--request-file", send_path.to_str().unwrap()])
        .output()
        .unwrap();
    assert_success("send suggestion batch", &batch);
    let batch_json: serde_json::Value = serde_json::from_slice(&batch.stdout).unwrap();
    assert_eq!(
        batch_json["result"]["suggestionIds"],
        serde_json::json!([456, 457])
    );

    *backend.suggestions_applied.lock().unwrap() = false;
    *backend.retain_unapplied_suggestions.lock().unwrap() = true;
    let (status, failed) = invoke_gitlab_outcome(
        &client,
        &base_url,
        "merge_request.suggestion.apply",
        "gitlab-suggestion-unverified",
        serde_json::json!({"inputs":{
            "project":"sip/service", "iid":5, "expectedHeadSha":TEST_SHA,
            "discussionId":"discussion-1", "noteId":900, "suggestionId":456
        }}),
    )
    .await;
    assert_mutation_verification_failure(
        status,
        &failed,
        "mutation_readback",
        serde_json::json!({"suggestionIds":[456]}),
    );

    let approve_audit = provider_gitlab_audit_for_action(&broker, "merge_request.approve");
    assert_eq!(approve_audit["mergeRequestIid"], 5);
    assert_eq!(approve_audit["userId"], 3);
    assert_eq!(approve_audit["approved"], true);
    assert_eq!(approve_audit["expectedHeadSha"], TEST_SHA);
    assert_eq!(approve_audit["provenHeadSha"], TEST_SHA);
    assert_eq!(approve_audit["diffVersionId"], 77);
    let unapprove_audit = provider_gitlab_audit_for_action(&broker, "merge_request.unapprove");
    assert_eq!(unapprove_audit["mergeRequestIid"], 5);
    assert_eq!(unapprove_audit["userId"], 3);
    assert_eq!(unapprove_audit["approved"], false);
    for absent in ["expectedHeadSha", "provenHeadSha", "diffVersionId"] {
        assert!(unapprove_audit.get(absent).is_none(), "{unapprove_audit}");
    }

    let audit = broker.audit().unwrap().text();
    assert!(!audit.contains("Apply review suggestion"));
    assert!(!audit.contains("safe_call()"));
    stop(broker).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn gitlab_approval_follows_diff_version_pagination_past_page_ten() {
    let backend = stub_backend();
    *backend.approval_diff_match_page.lock().unwrap() = 11;
    let broker = start_broker(
        &gitlab_per_user_document(),
        gitlab_service(gitlab_provider_config(2), backend.clone()),
    )
    .await;
    let base_url = broker.public_url();
    let (status, body) = invoke_gitlab_outcome(
        &reqwest::Client::new(),
        &base_url,
        "merge_request.approve",
        "gitlab-approval-page-eleven",
        serde_json::json!({"inputs":{
            "project":"sip/service", "iid":5, "headSha":TEST_SHA
        }}),
    )
    .await;
    assert_eq!(status, reqwest::StatusCode::OK, "{body}");
    assert_eq!(body["result"]["approved"], true);
    assert_eq!(
        backend_operation_count(&backend, "merge_request_diff_versions"),
        11
    );
    assert_eq!(
        backend_operation_count(&backend, "set_merge_request_approval"),
        1
    );
    stop(broker).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn gitlab_approval_gates_and_ambiguous_readbacks_fail_closed() {
    let backend = stub_backend();
    let broker = start_broker(
        &gitlab_per_user_document(),
        gitlab_service(gitlab_provider_config(2), backend.clone()),
    )
    .await;
    let base_url = broker.public_url();
    let client = reqwest::Client::new();

    for (label, prepared_at, status, diff_state, patch_id) in [
        (
            "unprepared",
            None,
            Some("mergeable"),
            "collected",
            Some(TEST_PATCH_ID_SHA),
        ),
        (
            "preparing",
            Some("ready"),
            Some("preparing"),
            "collected",
            Some(TEST_PATCH_ID_SHA),
        ),
        (
            "checking",
            Some("ready"),
            Some("checking"),
            "collected",
            Some(TEST_PATCH_ID_SHA),
        ),
        (
            "syncing",
            Some("ready"),
            Some("approvals_syncing"),
            "collected",
            Some(TEST_PATCH_ID_SHA),
        ),
        (
            "uncollected",
            Some("ready"),
            Some("mergeable"),
            "overflow",
            Some(TEST_PATCH_ID_SHA),
        ),
        (
            "null-patch",
            Some("ready"),
            Some("mergeable"),
            "collected",
            None,
        ),
    ] {
        *backend.merge_request_prepared_at.lock().unwrap() = prepared_at.map(str::to_string);
        *backend.merge_request_detailed_status.lock().unwrap() = status.map(str::to_string);
        *backend.diff_version_state.lock().unwrap() = diff_state.to_string();
        *backend.approval_patch_id_sha.lock().unwrap() = patch_id.map(str::to_string);
        *backend.actor_formally_approved.lock().unwrap() = false;
        let writes_before = backend_operation_count(&backend, "set_merge_request_approval");
        let (response_status, body) = invoke_gitlab_outcome(
            &client,
            &base_url,
            "merge_request.approve",
            &format!("gitlab-approval-gate-{label}"),
            serde_json::json!({"inputs":{
                "project":"sip/service", "iid":5, "headSha":TEST_SHA
            }}),
        )
        .await;
        assert_eq!(
            response_status,
            reqwest::StatusCode::CONFLICT,
            "{label}: {body}"
        );
        assert_eq!(body["reasonCode"], "version_conflict", "{label}: {body}");
        assert_eq!(
            backend_operation_count(&backend, "set_merge_request_approval"),
            writes_before,
            "{label} crossed the mutation boundary"
        );
    }

    *backend.merge_request_prepared_at.lock().unwrap() = Some("ready".to_string());
    *backend.merge_request_detailed_status.lock().unwrap() = Some("mergeable".to_string());
    *backend.diff_version_state.lock().unwrap() = "collected".to_string();
    *backend.approval_patch_id_sha.lock().unwrap() = Some(TEST_PATCH_ID_SHA.to_string());
    for mode in ["contradictory_user_flag", "duplicate_actor"] {
        *backend.actor_formally_approved.lock().unwrap() = false;
        *backend.approval_readback_mode.lock().unwrap() = mode.to_string();
        let (status, body) = invoke_gitlab_outcome(
            &client,
            &base_url,
            "merge_request.approve",
            &format!("gitlab-approval-readback-{mode}"),
            serde_json::json!({"inputs":{
                "project":"sip/service", "iid":5, "headSha":TEST_SHA
            }}),
        )
        .await;
        assert_mutation_verification_failure(
            status,
            &body,
            "mutation_readback",
            serde_json::json!({}),
        );
    }
    *backend.approval_readback_mode.lock().unwrap() = "normal".to_string();

    for (mode, expected_reason) in [
        ("fail_unchanged", "upstream_failed"),
        ("fail_after_apply", "mutation_verification_failed"),
    ] {
        *backend.actor_formally_approved.lock().unwrap() = false;
        *backend.approval_mutation_mode.lock().unwrap() = mode.to_string();
        let (status, body) = invoke_gitlab_outcome(
            &client,
            &base_url,
            "merge_request.approve",
            &format!("gitlab-approval-ambiguous-{mode}"),
            serde_json::json!({"inputs":{
                "project":"sip/service", "iid":5, "headSha":TEST_SHA
            }}),
        )
        .await;
        if mode == "fail_after_apply" {
            assert_mutation_verification_failure(
                status,
                &body,
                "mutation_readback",
                serde_json::json!({}),
            );
        } else {
            assert_eq!(status, reqwest::StatusCode::FAILED_DEPENDENCY, "{body}");
            assert_eq!(body["reasonCode"], expected_reason);
        }
    }
    stop(broker).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn gitlab_fork_suggestions_require_one_covering_grant_and_pin_numeric_source_identity() {
    for case in [
        "target_only",
        "source_only",
        "split_grants",
        "covering_grant",
    ] {
        let backend = stub_backend();
        *backend.fork_lookup_source_project_id.lock().unwrap() = Some(141);
        *backend.fork_execution_source_project_id.lock().unwrap() = Some(141);
        let mut document = gitlab_per_user_document();
        let grant = &mut document.grants[0];
        grant.actions = vec!["merge_request.suggestion.apply".to_string()];
        grant.resources = match case {
            "target_only" | "split_grants" => resource_ids(&["repository-sip-service"]),
            "source_only" => resource_ids(&["repository-fork-service"]),
            "covering_grant" => {
                resource_ids(&["repository-sip-service", "repository-fork-service"])
            }
            _ => unreachable!(),
        };
        if case == "split_grants" {
            let mut source_grant = grant.clone();
            source_grant.resources = resource_ids(&["repository-fork-service"]);
            document.grants.push(source_grant);
        }
        let broker = start_broker(
            &document,
            gitlab_service(gitlab_provider_config(2), backend.clone()),
        )
        .await;
        let base_url = broker.public_url();
        let (status, body) = invoke_gitlab_outcome(
            &reqwest::Client::new(),
            &base_url,
            "merge_request.suggestion.apply",
            &format!("gitlab-fork-suggestion-{case}"),
            serde_json::json!({"inputs":{
                "project":"sip/service", "iid":5, "expectedHeadSha":TEST_SHA,
                "discussionId":"discussion-1", "noteId":900, "suggestionId":456
            }}),
        )
        .await;
        if case == "covering_grant" {
            assert_eq!(status, reqwest::StatusCode::OK, "{body}");
            assert_eq!(
                body["resourceScopes"]["repository"],
                serde_json::json!(["fork/service", "sip/service"])
            );
            assert_eq!(backend_operation_count(&backend, "apply_suggestions"), 1);
            let audit = broker.audit().unwrap().text();
            assert!(audit.contains("\"sourceProjectId\":141"));
            assert!(audit.contains(&format!("\"expectedHeadSha\":\"{TEST_SHA}\"")));
            assert!(audit.contains(&format!("\"provenHeadSha\":\"{TEST_SHA}\"")));
        } else {
            assert_eq!(status, reqwest::StatusCode::FORBIDDEN, "{case}: {body}");
            assert_eq!(body["reasonCode"], "scope_unresolved", "{case}: {body}");
            assert!(body["resourceScopes"].as_object().unwrap().is_empty());
            assert_eq!(backend_operation_count(&backend, "apply_suggestions"), 0);
        }
        stop(broker).await;
    }

    let backend = stub_backend();
    *backend.fork_lookup_source_project_id.lock().unwrap() = Some(141);
    *backend.fork_execution_source_project_id.lock().unwrap() = Some(142);
    *backend.fork_source_drift_after_first_read.lock().unwrap() = true;
    let mut document = gitlab_per_user_document();
    document.grants[0].actions = vec!["merge_request.suggestion.apply".to_string()];
    document.grants[0].resources =
        resource_ids(&["repository-sip-service", "repository-fork-service"]);
    let broker = start_broker(
        &document,
        gitlab_service(gitlab_provider_config(2), backend.clone()),
    )
    .await;
    let base_url = broker.public_url();
    let (status, body) = invoke_gitlab_outcome(
        &reqwest::Client::new(),
        &base_url,
        "merge_request.suggestion.apply",
        "gitlab-fork-suggestion-numeric-drift",
        serde_json::json!({"inputs":{
            "project":"sip/service", "iid":5, "expectedHeadSha":TEST_SHA,
            "discussionId":"discussion-1", "noteId":900, "suggestionId":456
        }}),
    )
    .await;
    assert_eq!(status, reqwest::StatusCode::FORBIDDEN, "{body}");
    assert_eq!(body["reasonCode"], "scope_unresolved");
    assert!(body["result"]["hints"].is_null());
    assert_eq!(backend_operation_count(&backend, "apply_suggestions"), 0);
    stop(broker).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn gitlab_merge_request_review_read_catalog_is_policy_narrowed() {
    let backend = stub_backend();
    let mut document = gitlab_per_user_document();
    document.grants[0].actions = vec![
        "merge_request.reviewer.list".to_string(),
        "merge_request.draft_note.list".to_string(),
    ];
    let broker = start_broker(
        &document,
        gitlab_service(gitlab_provider_config(2), backend.clone()),
    )
    .await;
    let base_url = broker.public_url();

    let response = reqwest::Client::new()
        .get(format!("{base_url}/v1/spec/catalog"))
        .header("X-Agent-Access-Request-Id", "gitlab-review-narrow-catalog")
        .header("X-Agent-Access-Identity-Token", "agent-token")
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), reqwest::StatusCode::OK);
    let catalog: serde_json::Value = response.json().await.unwrap();
    let gitlab_actions = catalog["services"]
        .as_array()
        .unwrap()
        .iter()
        .find(|service| service["service"] == "gitlab")
        .and_then(|service| service["actions"].as_array())
        .unwrap()
        .iter()
        .collect::<Vec<_>>();
    assert_eq!(gitlab_actions.len(), 2);
    let drafts = gitlab_actions
        .iter()
        .find(|action| action["action"] == "merge_request.draft_note.list")
        .unwrap();
    assert_eq!(drafts["upstreamResourceOwnership"], "acting_user");
    let reviewers = gitlab_actions
        .iter()
        .find(|action| action["action"] == "merge_request.reviewer.list")
        .unwrap();
    assert!(reviewers.get("upstreamResourceOwnership").is_none());
    assert!(backend.credential_observations.lock().unwrap().is_empty());

    stop(broker).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn broker_exposes_gitlab_positioned_discussions_replies_and_verification() {
    let backend = stub_backend();
    let broker = start_broker(
        &gitlab_document(),
        gitlab_service(gitlab_provider_config(2), backend.clone()),
    )
    .await;
    let base_url = broker.public_url();
    let client = reqwest::Client::new();

    let typed = gitlab_cli(&base_url)
        .args([
            "gitlab",
            "merge-request",
            "inline-discussion",
            "sip/service",
            "5",
            "--expected-head-sha",
            TEST_SHA,
            "--position-type",
            "text",
            "--old-path",
            "src/old.rs",
            "--new-path",
            "src/new.rs",
            "--new-line",
            "34",
            "--content",
            "typed added-line secret",
            "--content-format",
            "markdown",
        ])
        .output()
        .unwrap();
    assert_success("typed inline discussion", &typed);
    let typed_json: serde_json::Value = serde_json::from_slice(&typed.stdout).unwrap();
    assert_eq!(typed_json["result"]["mutationStatus"], "applied");
    assert_eq!(
        typed_json["result"]["discussion"]["notes"][0]["position"]["newLine"],
        34
    );

    let cases = [
        serde_json::json!({
            "positionType":"text", "oldPath":"src/old.rs", "newPath":"src/new.rs",
            "oldLine":31
        }),
        serde_json::json!({
            "positionType":"text", "oldPath":"src/old.rs", "newPath":"src/new.rs",
            "oldLine":31, "newLine":34
        }),
        serde_json::json!({
            "positionType":"text", "oldPath":"src/old.rs", "newPath":"src/new.rs",
            "lineRange":{"start":{"oldLine":31},"end":{"newLine":34}}
        }),
        serde_json::json!({
            "positionType":"file", "oldPath":"src/old.rs", "newPath":"src/new.rs"
        }),
        serde_json::json!({
            "positionType":"image", "oldPath":"diagram-old.png", "newPath":"diagram.png",
            "width":640, "height":480, "x":12, "y":24
        }),
    ];
    for (index, position) in cases.into_iter().enumerate() {
        let response = invoke_gitlab(
            &client,
            &base_url,
            "merge_request.discussion.inline.add",
            &format!("gitlab-inline-position-{index}"),
            serde_json::json!({
                "inputs":{
                    "project":"sip/service",
                    "iid":5,
                    "expectedHeadSha":TEST_SHA,
                    "content":format!("position secret {index}"),
                    "contentFormat":"markdown",
                    "position":position
                }
            }),
        )
        .await;
        assert_eq!(response["result"]["mutationStatus"], "applied");
        assert_eq!(response["result"]["retrySafe"], false);
    }
    let observed_inline = backend
        .last_inline_discussion_add
        .lock()
        .unwrap()
        .clone()
        .unwrap();
    assert_eq!(observed_inline.project_id, 42);
    assert_eq!(observed_inline.request.position.position_type, "image");
    assert_eq!(observed_inline.request.position.width, Some(640));
    assert_eq!(observed_inline.request.position.x, Some(12));

    let reply = invoke_gitlab(
        &client,
        &base_url,
        "merge_request.discussion.note.add",
        "gitlab-outdated-discussion-reply",
        serde_json::json!({
            "inputs":{
                "project":"sip/service",
                "iid":5,
                "discussionId":"discussion-outdated",
                "content":"outdated thread reply secret",
                "contentFormat":"markdown"
            }
        }),
    )
    .await;
    assert_eq!(reply["result"]["mutationStatus"], "applied");
    assert_eq!(reply["result"]["discussionId"], "discussion-outdated");
    assert_eq!(reply["result"]["note"]["id"], 911);
    let observed_reply = backend
        .last_discussion_reply_add
        .lock()
        .unwrap()
        .clone()
        .unwrap();
    assert_eq!(observed_reply.project_id, 42);
    assert_eq!(observed_reply.request.discussion_id, "discussion-outdated");

    let stale = client
        .post(format!(
            "{base_url}/v1/invoke/gitlab/merge_request.discussion.inline.add"
        ))
        .header("X-Agent-Access-Request-Id", "gitlab-inline-stale")
        .json(&serde_json::json!({
            "inputs":{
                "project":"sip/service", "iid":5,
                "expectedHeadSha":"eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
                "content":"stale secret", "contentFormat":"markdown",
                "position":{"positionType":"text","oldPath":"src/old.rs","newPath":"src/new.rs","newLine":34}
            }
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(stale.status(), reqwest::StatusCode::CONFLICT);
    let stale: serde_json::Value = stale.json().await.unwrap();
    assert_eq!(stale["reasonCode"], "version_conflict");

    *backend.malformed_inline_response.lock().unwrap() = true;
    let unverified = client
        .post(format!(
            "{base_url}/v1/invoke/gitlab/merge_request.discussion.inline.add"
        ))
        .header("X-Agent-Access-Request-Id", "gitlab-inline-unverified")
        .json(&serde_json::json!({
            "inputs":{
                "project":"sip/service", "iid":5, "expectedHeadSha":TEST_SHA,
                "content":"unverified secret", "contentFormat":"markdown",
                "position":{"positionType":"text","oldPath":"src/old.rs","newPath":"src/new.rs","newLine":34}
            }
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(unverified.status(), reqwest::StatusCode::CONFLICT);
    let unverified: serde_json::Value = unverified.json().await.unwrap();
    assert_eq!(unverified["reasonCode"], "mutation_verification_failed");
    assert_eq!(unverified["result"]["mutationStatus"], "applied_unverified");
    assert_eq!(unverified["result"]["retrySafe"], false);

    let audit = broker.audit().unwrap().text();
    assert!(audit.contains("\"action\":\"merge_request.discussion.inline.add\""));
    assert!(audit.contains("\"action\":\"merge_request.discussion.note.add\""));
    for secret in [
        "typed added-line secret",
        "position secret",
        "outdated thread reply secret",
        "stale secret",
        "unverified secret",
    ] {
        assert!(!audit.contains(secret));
    }

    stop(broker).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn broker_exposes_gitlab_draft_lifecycle_and_review_submission_across_callers() {
    let backend = stub_backend();
    backend
        .draft_notes
        .lock()
        .unwrap()
        .push(draft_note_fixture(802, "second pending draft", None));
    *backend.next_draft_note_id.lock().unwrap() = 803;
    let mut document = gitlab_per_user_document();
    document.grants[0].credential_mode = "service".to_string();
    let broker = start_broker(
        &document,
        gitlab_service(gitlab_provider_config(1), backend.clone()),
    )
    .await;
    let base_url = broker.public_url();
    let client = reqwest::Client::new();

    let first_page = gitlab_cli(&base_url)
        .args([
            "gitlab",
            "merge-request",
            "list-draft-notes",
            "sip/service",
            "5",
            "--max-results",
            "1",
            "--projection",
            "summary",
        ])
        .output()
        .unwrap();
    assert_success("typed draft list", &first_page);
    let first_page: serde_json::Value = serde_json::from_slice(&first_page.stdout).unwrap();
    assert_eq!(first_page["result"]["draftNotes"][0]["id"], 801);
    assert_eq!(first_page["result"]["projection"], "summary");
    assert!(first_page["result"]["draftNotes"][0].get("body").is_none());
    assert!(
        first_page["result"]["draftNotes"][0]
            .get("lineCode")
            .is_none()
    );
    assert_eq!(first_page["result"]["count"], 1);
    assert_eq!(first_page["result"]["isLast"], false);
    assert_review_context(&first_page, "service", "shared");
    assert_eq!(backend_operation_count(&backend, "current_user"), 1);
    let page_token = first_page["result"]["nextPageToken"].as_str().unwrap();

    let second_page = gitlab_cli(&base_url)
        .args([
            "invoke",
            "gitlab.merge_request.draft_note.list",
            "--input-json",
            &format!(
                r#"{{"project":"sip/service","iid":5,"maxResults":1,"projection":"summary","pageToken":"{page_token}"}}"#
            ),
        ])
        .output()
        .unwrap();
    assert_success("generic draft list second page", &second_page);
    let second_page: serde_json::Value = serde_json::from_slice(&second_page.stdout).unwrap();
    assert_eq!(second_page["result"]["draftNotes"][0]["id"], 802);
    assert_eq!(second_page["result"]["isLast"], true);
    assert_review_context(&second_page, "service", "shared");
    assert_eq!(
        backend_operation_count(&backend, "merge_request_draft_notes"),
        2
    );

    *backend.current_user_id.lock().unwrap() = 4;
    let draft_reads_before_actor_rotation =
        backend_operation_count(&backend, "merge_request_draft_notes");
    let actor_rotated = client
        .post(format!(
            "{base_url}/v1/invoke/gitlab/merge_request.draft_note.list"
        ))
        .header(
            "X-Agent-Access-Request-Id",
            "gitlab-draft-page-token-actor-rotation",
        )
        .header("X-Agent-Access-Identity-Token", "agent-token")
        .json(&serde_json::json!({
            "inputs": {
                "project": "sip/service",
                "iid": 5,
                "maxResults": 1,
                "projection": "summary",
                "pageToken": page_token
            }
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(actor_rotated.status(), reqwest::StatusCode::BAD_REQUEST);
    let actor_rotated: serde_json::Value = actor_rotated.json().await.unwrap();
    assert_eq!(actor_rotated["reasonCode"], "input_invalid");
    assert!(actor_rotated["result"]["reviewContext"].is_null());
    assert_eq!(
        backend_operation_count(&backend, "merge_request_draft_notes"),
        draft_reads_before_actor_rotation
    );
    *backend.current_user_id.lock().unwrap() = 3;

    let view_path = temp_path("gitlab-draft-view-send.json");
    std::fs::write(
        &view_path,
        r#"{"version":"agent-access.send.v1","kind":"invoke","service":"gitlab","action":"merge_request.draft_note.view","inputs":{"project":"sip/service","iid":5,"draftNoteId":801}}"#,
    )
    .unwrap();
    let view = gitlab_cli(&base_url)
        .args(["send", "--request-file", view_path.to_str().unwrap()])
        .output()
        .unwrap();
    assert_success("send draft view", &view);
    let view: serde_json::Value = serde_json::from_slice(&view.stdout).unwrap();
    assert_eq!(view["result"]["draftNote"]["id"], 801);
    assert_review_context(&view, "service", "shared");

    let text_list = gitlab_cli(&base_url)
        .args([
            "gitlab",
            "merge-request",
            "list-draft-notes",
            "sip/service",
            "5",
            "--max-results",
            "20",
            "--read-content-format",
            "text",
        ])
        .output()
        .unwrap();
    assert_success("typed unpositioned draft text list", &text_list);
    let text_list: serde_json::Value = serde_json::from_slice(&text_list.stdout).unwrap();
    let unpositioned = text_list["result"]["draftNotes"]
        .as_array()
        .unwrap()
        .iter()
        .find(|draft| draft["id"] == 801)
        .unwrap();
    assert!(unpositioned["position"].is_null());
    assert_eq!(unpositioned["renderedBody"]["format"], "text");

    let text_view = gitlab_cli(&base_url)
        .args([
            "gitlab",
            "merge-request",
            "view-draft-note",
            "sip/service",
            "5",
            "802",
            "--read-content-format",
            "text",
        ])
        .output()
        .unwrap();
    assert_success("typed unpositioned draft text view", &text_view);
    let text_view: serde_json::Value = serde_json::from_slice(&text_view.stdout).unwrap();
    assert!(text_view["result"]["draftNote"]["position"].is_null());
    assert_eq!(
        text_view["result"]["draftNote"]["renderedBody"]["format"],
        "text"
    );

    let general = gitlab_cli(&base_url)
        .args([
            "invoke",
            "gitlab.merge_request.draft_note.add",
            "--input-json",
            r#"{"project":"sip/service","iid":5,"content":"general draft secret","contentFormat":"markdown"}"#,
        ])
        .output()
        .unwrap();
    assert_success("generic general draft add", &general);
    let general: serde_json::Value = serde_json::from_slice(&general.stdout).unwrap();
    assert_eq!(general["result"]["draftNoteId"], 803);
    assert_eq!(general["result"]["mutationStatus"], "applied");
    assert_review_context(&general, "service", "shared");

    let reply_path = temp_path("gitlab-draft-reply-send.json");
    std::fs::write(
        &reply_path,
        r#"{"version":"agent-access.send.v1","kind":"invoke","service":"gitlab","action":"merge_request.draft_note.add","inputs":{"project":"sip/service","iid":5,"inReplyToDiscussionId":"discussion-outdated","resolveDiscussion":true,"content":"reply draft secret","contentFormat":"markdown"}}"#,
    )
    .unwrap();
    let reply = gitlab_cli(&base_url)
        .args(["send", "--request-file", reply_path.to_str().unwrap()])
        .output()
        .unwrap();
    assert_success("send reply draft add", &reply);
    let reply: serde_json::Value = serde_json::from_slice(&reply.stdout).unwrap();
    assert_eq!(reply["result"]["draftNoteId"], 804);
    assert_eq!(
        reply["result"]["draftNote"]["discussionId"],
        "discussion-outdated"
    );
    assert_eq!(reply["result"]["draftNote"]["resolveDiscussion"], true);

    let positioned = invoke_gitlab(
        &client,
        &base_url,
        "merge_request.draft_note.add",
        "gitlab-positioned-draft-add",
        serde_json::json!({
            "inputs":{
                "project":"sip/service", "iid":5, "expectedHeadSha":TEST_SHA,
                "content":"positioned draft secret", "contentFormat":"markdown",
                "position":{
                    "positionType":"text", "oldPath":"src/old.rs",
                    "newPath":"src/new.rs", "newLine":34
                }
            }
        }),
    )
    .await;
    assert_eq!(positioned["result"]["draftNoteId"], 805);
    assert_eq!(positioned["result"]["draftNote"]["position"]["newLine"], 34);

    let stale_position = client
        .post(format!(
            "{base_url}/v1/invoke/gitlab/merge_request.draft_note.add"
        ))
        .header("X-Agent-Access-Request-Id", "gitlab-positioned-draft-stale")
        .header("X-Agent-Access-Identity-Token", "agent-token")
        .json(&serde_json::json!({
            "inputs":{
                "project":"sip/service", "iid":5,
                "expectedHeadSha":"eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
                "content":"stale draft secret", "contentFormat":"markdown",
                "position":{
                    "positionType":"text", "oldPath":"src/old.rs",
                    "newPath":"src/new.rs", "newLine":34
                }
            }
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(stale_position.status(), reqwest::StatusCode::CONFLICT);
    let stale_position: serde_json::Value = stale_position.json().await.unwrap();
    assert_eq!(stale_position["reasonCode"], "version_conflict");

    let reply_position = client
        .post(format!(
            "{base_url}/v1/invoke/gitlab/merge_request.draft_note.update"
        ))
        .header("X-Agent-Access-Request-Id", "gitlab-reply-draft-position")
        .header("X-Agent-Access-Identity-Token", "agent-token")
        .json(&serde_json::json!({
            "inputs":{
                "project":"sip/service", "iid":5, "draftNoteId":804,
                "expectedHeadSha":TEST_SHA,
                "position":{
                    "positionType":"text", "oldPath":"src/old.rs",
                    "newPath":"src/new.rs", "newLine":34
                }
            }
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(reply_position.status(), reqwest::StatusCode::BAD_REQUEST);
    let reply_position: serde_json::Value = reply_position.json().await.unwrap();
    assert_eq!(reply_position["reasonCode"], "input_invalid");

    let update = gitlab_cli(&base_url)
        .args([
            "gitlab",
            "merge-request",
            "update-draft-note",
            "sip/service",
            "5",
            "803",
            "--content",
            "updated draft secret",
            "--content-format",
            "markdown",
        ])
        .output()
        .unwrap();
    assert_success("typed draft update", &update);
    let update: serde_json::Value = serde_json::from_slice(&update.stdout).unwrap();
    assert_eq!(update["result"]["draftNoteId"], 803);
    assert_eq!(
        update["result"]["draftNote"]["body"],
        "updated draft secret"
    );
    assert_review_context(&update, "service", "shared");

    let positioned_update = gitlab_cli(&base_url)
        .args([
            "gitlab",
            "merge-request",
            "update-draft-note",
            "sip/service",
            "5",
            "805",
            "--content",
            "edited positioned draft secret",
            "--content-format",
            "markdown",
        ])
        .output()
        .unwrap();
    assert_success("typed positioned draft body update", &positioned_update);
    let positioned_update: serde_json::Value =
        serde_json::from_slice(&positioned_update.stdout).unwrap();
    assert_eq!(
        positioned_update["result"]["draftNote"]["body"],
        "edited positioned draft secret"
    );
    assert_eq!(
        positioned_update["result"]["draftNote"]["position"]["newLine"],
        34
    );
    assert_eq!(
        backend
            .last_draft_note_update
            .lock()
            .unwrap()
            .as_ref()
            .and_then(|request| request.position.as_ref())
            .and_then(|position| position.new_line),
        Some(34)
    );

    let position_only_update = gitlab_cli(&base_url)
        .args([
            "gitlab",
            "merge-request",
            "update-draft-note",
            "sip/service",
            "5",
            "805",
            "--expected-head-sha",
            TEST_SHA,
            "--position-type",
            "text",
            "--old-path",
            "src/old.rs",
            "--new-path",
            "src/new.rs",
            "--new-line",
            "34",
        ])
        .output()
        .unwrap();
    assert_success(
        "typed positioned draft position-only update",
        &position_only_update,
    );
    let position_only_update: serde_json::Value =
        serde_json::from_slice(&position_only_update.stdout).unwrap();
    assert_eq!(
        position_only_update["result"]["draftNote"]["body"],
        "edited positioned draft secret"
    );
    assert_eq!(
        position_only_update["result"]["draftNote"]["position"]["newLine"],
        34
    );
    {
        let last_update = backend.last_draft_note_update.lock().unwrap();
        let last_update = last_update.as_ref().unwrap();
        assert_eq!(last_update.body, "edited positioned draft secret");
        assert_eq!(
            last_update
                .position
                .as_ref()
                .and_then(|position| position.new_line),
            Some(34)
        );
    }

    let deleted = invoke_gitlab(
        &client,
        &base_url,
        "merge_request.draft_note.delete",
        "gitlab-draft-delete",
        serde_json::json!({"inputs":{"project":"sip/service","iid":5,"draftNoteId":804}}),
    )
    .await;
    assert_eq!(deleted["result"]["draftNoteId"], 804);
    assert_eq!(deleted["result"]["deleted"], true);
    assert_eq!(deleted["result"]["mutationStatus"], "applied");
    assert_review_context(&deleted, "service", "shared");

    let published = gitlab_cli(&base_url)
        .args([
            "gitlab",
            "merge-request",
            "publish-draft-note",
            "sip/service",
            "5",
            "803",
        ])
        .output()
        .unwrap();
    assert_success("typed single draft publish", &published);
    let published: serde_json::Value = serde_json::from_slice(&published.stdout).unwrap();
    assert_eq!(published["result"]["draftNoteId"], 803);
    assert_eq!(published["result"]["published"], true);
    assert_eq!(published["result"]["discussionId"], "published-draft-803");
    assert_eq!(published["result"]["noteId"], 12803);
    assert_review_context(&published, "service", "shared");

    let reply_draft = invoke_gitlab(
        &client,
        &base_url,
        "merge_request.draft_note.add",
        "gitlab-positioned-reply-draft-add",
        serde_json::json!({"inputs":{
            "project":"sip/service","iid":5,
            "inReplyToDiscussionId":"discussion-outdated",
            "content":"positioned reply publication secret","contentFormat":"markdown"
        }}),
    )
    .await;
    assert_eq!(reply_draft["result"]["draftNoteId"], 806);
    let reply_published = invoke_gitlab(
        &client,
        &base_url,
        "merge_request.draft_note.publish",
        "gitlab-positioned-reply-draft-publish",
        serde_json::json!({"inputs":{
            "project":"sip/service","iid":5,"draftNoteId":806
        }}),
    )
    .await;
    assert_eq!(
        reply_published["result"]["discussionId"],
        "discussion-outdated"
    );
    assert_eq!(reply_published["result"]["noteId"], 12806);
    assert_review_context(&reply_published, "service", "shared");
    {
        let discussions = backend.published_discussions.lock().unwrap();
        let discussion = discussions
            .iter()
            .find(|discussion| discussion.id == "discussion-outdated")
            .unwrap();
        assert_eq!(discussion.notes.len(), 2);
        assert!(discussion.notes[0].position.is_some());
        assert_eq!(discussion.notes[1].position, None);
    }

    let publish_all = gitlab_cli(&base_url)
        .args([
            "gitlab",
            "merge-request",
            "publish-all",
            "sip/service",
            "5",
            "--content",
            "publish all summary secret",
            "--content-format",
            "markdown",
            "--internal",
            "true",
        ])
        .output()
        .unwrap();
    assert_success("typed publish all", &publish_all);
    let publish_all: serde_json::Value = serde_json::from_slice(&publish_all.stdout).unwrap();
    assert_eq!(
        publish_all["result"]["publishedDraftNoteIds"],
        serde_json::json!([801, 802, 805])
    );
    assert_eq!(publish_all["result"]["summaryNoteId"], 990);
    assert_eq!(publish_all["result"]["mutationStatus"], "applied");
    assert_review_context(&publish_all, "service", "shared");

    let empty_drafts = invoke_gitlab(
        &client,
        &base_url,
        "merge_request.draft_note.list",
        "gitlab-empty-draft-list-context",
        serde_json::json!({"inputs":{"project":"sip/service","iid":5}}),
    )
    .await;
    assert_eq!(empty_drafts["result"]["draftNotes"], serde_json::json!([]));
    assert_review_context(&empty_drafts, "service", "shared");

    let reviewed = gitlab_cli(&base_url)
        .args([
            "gitlab",
            "merge-request",
            "submit-review",
            "sip/service",
            "5",
            "--reviewer-state",
            "reviewed",
            "--content",
            "zero draft review summary secret",
            "--content-format",
            "markdown",
        ])
        .output()
        .unwrap();
    assert_success("typed zero-draft reviewed submission", &reviewed);
    let reviewed: serde_json::Value = serde_json::from_slice(&reviewed.stdout).unwrap();
    assert_eq!(
        reviewed["result"]["publishedDraftNoteIds"],
        serde_json::json!([])
    );
    assert_eq!(reviewed["result"]["reviewerState"], "reviewed");
    assert_eq!(reviewed["result"]["summaryNoteId"], 990);
    assert_review_context(&reviewed, "service", "shared");

    let requested_changes = invoke_gitlab(
        &client,
        &base_url,
        "merge_request.review.submit",
        "gitlab-zero-draft-requested-changes",
        serde_json::json!({
            "inputs":{
                "project":"sip/service", "iid":5, "reviewerState":"requestedChanges"
            }
        }),
    )
    .await;
    assert_eq!(
        requested_changes["result"]["publishedDraftNoteIds"],
        serde_json::json!([])
    );
    assert_eq!(
        requested_changes["result"]["reviewerState"],
        "requestedChanges"
    );
    assert!(requested_changes["result"]["summaryNoteId"].is_null());

    backend.draft_notes.lock().unwrap().push(draft_note_fixture(
        806,
        "failure-path draft secret",
        None,
    ));
    *backend.fail_bulk_publish_after_apply.lock().unwrap() = true;
    let unverified = client
        .post(format!(
            "{base_url}/v1/invoke/gitlab/merge_request.review.submit"
        ))
        .header(
            "X-Agent-Access-Request-Id",
            "gitlab-review-submit-unverified",
        )
        .header("X-Agent-Access-Identity-Token", "agent-token")
        .json(&serde_json::json!({
            "inputs":{"project":"sip/service","iid":5,"reviewerState":"reviewed"}
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(unverified.status(), reqwest::StatusCode::CONFLICT);
    let unverified: serde_json::Value = unverified.json().await.unwrap();
    assert_eq!(unverified["reasonCode"], "mutation_verification_failed");
    assert_eq!(unverified["result"]["mutationStatus"], "applied_unverified");
    assert_eq!(unverified["result"]["retrySafe"], false);
    assert!(unverified["result"]["reviewContext"].is_null());
    assert_eq!(
        unverified["result"]["safeLocators"]["draftNoteIds"],
        serde_json::json!([806])
    );

    let observed_reply = backend
        .last_draft_note_create
        .lock()
        .unwrap()
        .clone()
        .unwrap();
    assert_eq!(observed_reply.iid, 5);
    let observed_bulk = backend
        .last_draft_bulk_publish
        .lock()
        .unwrap()
        .clone()
        .unwrap();
    assert_eq!(observed_bulk.reviewer_state.as_deref(), Some("reviewed"));
    let observed_summary = backend.last_review_summary.lock().unwrap().clone().unwrap();
    assert_eq!(observed_summary.iid, 5);

    let service_mutations = backend
        .credential_observations
        .lock()
        .unwrap()
        .iter()
        .filter(|observation| {
            matches!(
                observation.operation.as_str(),
                "create_merge_request_draft_note"
                    | "update_merge_request_draft_note"
                    | "delete_merge_request_draft_note"
                    | "publish_merge_request_draft_note"
                    | "bulk_publish_merge_request_draft_notes"
                    | "create_merge_request_review_summary"
            )
        })
        .map(|observation| observation.credential.clone())
        .collect::<Vec<_>>();
    assert!(!service_mutations.is_empty());
    assert!(
        service_mutations
            .iter()
            .all(|credential| *credential == bearer_credential("gitlab-service-token"))
    );

    let audit = broker.audit().unwrap().text();
    for forbidden in [
        "reviewContext",
        "credentialBinding",
        "upstreamActor",
        "Carol",
    ] {
        assert!(!audit.contains(forbidden), "audit contained {forbidden}");
    }
    for action in [
        "merge_request.draft_note.list",
        "merge_request.draft_note.view",
        "merge_request.draft_note.add",
        "merge_request.draft_note.update",
        "merge_request.draft_note.delete",
        "merge_request.draft_note.publish",
        "merge_request.draft_note.publish_all",
        "merge_request.review.submit",
    ] {
        assert!(audit.contains(&format!("\"action\":\"{action}\"")));
    }
    let review_audit = provider_gitlab_audit_for_action(&broker, "merge_request.review.submit");
    assert_eq!(review_audit["mergeRequestIid"], 5);
    assert_eq!(review_audit["userId"], 3);
    assert_eq!(review_audit["reviewerState"], "reviewed");
    assert_eq!(review_audit["draftNoteIds"], serde_json::json!([]));
    assert_eq!(review_audit["draftNoteCount"], 0);
    assert_eq!(review_audit["provenHeadSha"], TEST_SHA);
    assert_eq!(review_audit["summaryNoteId"], 990);
    for absent in ["body", "summary", "content"] {
        assert!(review_audit.get(absent).is_none(), "{review_audit}");
    }
    for secret in [
        "pending review draft",
        "second pending draft",
        "general draft secret",
        "reply draft secret",
        "positioned draft secret",
        "stale draft secret",
        "updated draft secret",
        "publish all summary secret",
        "zero draft review summary secret",
        "failure-path draft secret",
    ] {
        assert!(!audit.contains(secret));
    }

    stop(broker).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn gitlab_review_mutations_use_per_user_identity_and_policy_narrows_the_catalog() {
    let backend = stub_backend();
    backend.draft_notes.lock().unwrap().push(draft_note_fixture(
        802,
        "second per-user draft",
        None,
    ));
    *backend.next_draft_note_id.lock().unwrap() = 803;
    let broker = start_broker(
        &gitlab_per_user_document(),
        gitlab_service(gitlab_provider_config(2), backend.clone()),
    )
    .await;
    let base_url = broker.public_url();
    let client = reqwest::Client::new();

    let (status, first_page) = invoke_gitlab_outcome(
        &client,
        &base_url,
        "merge_request.draft_note.list",
        "gitlab-per-user-page-token-first",
        serde_json::json!({"inputs":{
            "project":"sip/service","iid":5,"maxResults":1,"projection":"summary"
        }}),
    )
    .await;
    assert_eq!(status, reqwest::StatusCode::OK, "{first_page}");
    assert_review_context(&first_page, "per_user", "principal");
    let page_token = first_page["result"]["nextPageToken"]
        .as_str()
        .unwrap()
        .to_string();
    let reads_before_rotation = backend_operation_count(&backend, "merge_request_draft_notes");
    *backend.current_user_id.lock().unwrap() = 4;
    let (status, rotated) = invoke_gitlab_outcome(
        &client,
        &base_url,
        "merge_request.draft_note.list",
        "gitlab-per-user-page-token-actor-rotation",
        serde_json::json!({"inputs":{
            "project":"sip/service","iid":5,"maxResults":1,"projection":"summary",
            "pageToken":page_token
        }}),
    )
    .await;
    assert_eq!(status, reqwest::StatusCode::BAD_REQUEST, "{rotated}");
    assert_eq!(rotated["reasonCode"], "input_invalid");
    assert!(rotated["result"]["reviewContext"].is_null());
    assert_eq!(
        backend_operation_count(&backend, "merge_request_draft_notes"),
        reads_before_rotation
    );
    *backend.current_user_id.lock().unwrap() = 3;

    let reply = gitlab_cli(&base_url)
        .args([
            "gitlab",
            "merge-request",
            "reply-discussion",
            "sip/service",
            "5",
            "discussion-outdated",
            "--content",
            "per-user reply secret",
            "--content-format",
            "markdown",
        ])
        .output()
        .unwrap();
    assert_success("per-user discussion reply", &reply);
    let reply: serde_json::Value = serde_json::from_slice(&reply.stdout).unwrap();
    assert_eq!(reply["result"]["discussionId"], "discussion-outdated");

    let draft = gitlab_cli(&base_url)
        .args([
            "gitlab",
            "merge-request",
            "add-draft-note",
            "sip/service",
            "5",
            "--content",
            "per-user draft secret",
            "--content-format",
            "markdown",
        ])
        .output()
        .unwrap();
    assert_success("per-user draft add", &draft);
    let draft: serde_json::Value = serde_json::from_slice(&draft.stdout).unwrap();
    assert_eq!(draft["result"]["mutationStatus"], "applied");
    assert_review_context(&draft, "per_user", "principal");

    {
        let observations = backend.credential_observations.lock().unwrap();
        for operation in [
            "current_user",
            "merge_request",
            "merge_request_discussion",
            "create_merge_request_discussion_note",
            "merge_request_draft_note",
            "create_merge_request_draft_note",
        ] {
            let matching = observations
                .iter()
                .filter(|observation| observation.operation == operation)
                .collect::<Vec<_>>();
            assert!(
                !matching.is_empty(),
                "missing backend operation {operation}"
            );
            assert!(matching.iter().all(|observation| {
                observation.credential == bearer_credential("gitlab-per-user-token")
            }));
        }
        let project_lookups = observations
            .iter()
            .filter(|observation| observation.operation == "project")
            .collect::<Vec<_>>();
        assert!(!project_lookups.is_empty(), "missing GitLab project lookup");
        assert!(project_lookups.iter().all(|observation| {
            observation.credential == bearer_credential("gitlab-per-user-token")
        }));
    }

    let audit = broker.audit().unwrap();
    audit.require_action("gitlab", "merge_request.discussion.note.add");
    audit.require_action("gitlab", "merge_request.draft_note.add");
    let audit = audit.text();
    assert!(!audit.contains("per-user reply secret"));
    assert!(!audit.contains("per-user draft secret"));
    stop(broker).await;

    let narrowed_backend = stub_backend();
    let mut document = gitlab_per_user_document();
    document.grants[0].actions = vec!["merge_request.discussion.inline.add".to_string()];
    let broker = start_broker(
        &document,
        gitlab_service(gitlab_provider_config(2), narrowed_backend.clone()),
    )
    .await;
    let base_url = broker.public_url();
    let catalog = client
        .get(format!("{base_url}/v1/spec/catalog"))
        .header("X-Agent-Access-Request-Id", "gitlab-review-write-catalog")
        .header("X-Agent-Access-Identity-Token", "agent-token")
        .send()
        .await
        .unwrap();
    assert_eq!(catalog.status(), reqwest::StatusCode::OK);
    let catalog: serde_json::Value = catalog.json().await.unwrap();
    let actions = catalog["services"]
        .as_array()
        .unwrap()
        .iter()
        .find(|service| service["service"] == "gitlab")
        .and_then(|service| service["actions"].as_array())
        .unwrap()
        .iter()
        .map(|action| action["action"].as_str().unwrap())
        .collect::<Vec<_>>();
    assert_eq!(actions, vec!["merge_request.discussion.inline.add"]);
    let inline = catalog["services"]
        .as_array()
        .unwrap()
        .iter()
        .find(|service| service["service"] == "gitlab")
        .and_then(|service| service["actions"].as_array())
        .unwrap()
        .first()
        .unwrap();
    assert!(inline.get("upstreamResourceOwnership").is_none());
    assert!(
        narrowed_backend
            .credential_observations
            .lock()
            .unwrap()
            .is_empty()
    );

    let denied = client
        .post(format!(
            "{base_url}/v1/invoke/gitlab/merge_request.draft_note.add"
        ))
        .header("X-Agent-Access-Request-Id", "gitlab-review-policy-denied")
        .header("X-Agent-Access-Identity-Token", "agent-token")
        .json(&serde_json::json!({
            "inputs":{
                "project":"sip/service", "iid":5,
                "content":"policy-denied secret", "contentFormat":"markdown"
            }
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(denied.status(), reqwest::StatusCode::FORBIDDEN);
    assert!(
        narrowed_backend
            .credential_observations
            .lock()
            .unwrap()
            .is_empty()
    );
    let narrowed_audit = broker.audit().unwrap();
    narrowed_audit.require_request(
        "gitlab-review-policy-denied",
        "gitlab",
        "merge_request.draft_note.add",
    );
    let narrowed_audit = narrowed_audit.text();
    assert!(!narrowed_audit.contains("policy-denied secret"));

    stop(broker).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn gitlab_review_preflights_reject_unproven_identity_and_scope_without_writes() {
    let backend = stub_backend();
    let broker = start_broker(
        &gitlab_per_user_document(),
        gitlab_service(gitlab_provider_config(2), backend.clone()),
    )
    .await;
    let base_url = broker.public_url();
    let client = reqwest::Client::new();

    let (status, body) = invoke_gitlab_outcome(
        &client,
        &base_url,
        "merge_request.draft_note.update",
        "gitlab-malformed-actor-owned-input",
        serde_json::json!({"inputs":{
            "project":"sip/service","iid":5,
            "content":"malformed secret","contentFormat":"markdown"
        }}),
    )
    .await;
    assert_eq!(status, reqwest::StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(body["reasonCode"], "input_invalid");
    assert!(body["result"]["hints"].is_null());

    backend.draft_notes.lock().unwrap()[0].author_user_id = Some(4);
    let (status, body) = invoke_gitlab_outcome(
        &client,
        &base_url,
        "merge_request.draft_note.update",
        "gitlab-wrong-draft-owner",
        serde_json::json!({"inputs":{
            "project":"sip/service","iid":5,"draftNoteId":801,
            "content":"owner mismatch secret","contentFormat":"markdown"
        }}),
    )
    .await;
    assert_eq!(status, reqwest::StatusCode::FORBIDDEN, "{body}");
    assert_eq!(body["reasonCode"], "scope_unresolved");
    assert_eq!(
        body["result"]["hints"]["upstreamResourceOwnership"],
        "acting_user"
    );
    assert_eq!(
        backend_operation_count(&backend, "update_merge_request_draft_note"),
        0
    );

    {
        let mut drafts = backend.draft_notes.lock().unwrap();
        drafts[0].author_user_id = Some(3);
        drafts[0].merge_request_id = Some(501);
    }
    let (status, body) = invoke_gitlab_outcome(
        &client,
        &base_url,
        "merge_request.draft_note.delete",
        "gitlab-wrong-draft-merge-request",
        serde_json::json!({"inputs":{
            "project":"sip/service","iid":5,"draftNoteId":801
        }}),
    )
    .await;
    assert_eq!(status, reqwest::StatusCode::FORBIDDEN, "{body}");
    assert_eq!(body["reasonCode"], "scope_unresolved");
    assert_eq!(
        backend_operation_count(&backend, "delete_merge_request_draft_note"),
        0
    );
    backend.draft_notes.lock().unwrap()[0].merge_request_id = Some(500);

    *backend.discussion_proof_mismatch.lock().unwrap() = true;
    for (action, request_id, extra_inputs, write_operation) in [
        (
            "merge_request.discussion.note.add",
            "gitlab-reply-proof-mismatch",
            serde_json::json!({
                "discussionId":"discussion-outdated",
                "content":"reply mismatch secret","contentFormat":"markdown"
            }),
            "create_merge_request_discussion_note",
        ),
        (
            "merge_request.draft_note.add",
            "gitlab-draft-reply-proof-mismatch",
            serde_json::json!({
                "inReplyToDiscussionId":"discussion-outdated",
                "content":"draft reply mismatch secret","contentFormat":"markdown"
            }),
            "create_merge_request_draft_note",
        ),
    ] {
        let mut inputs = extra_inputs.as_object().unwrap().clone();
        inputs.insert("project".to_string(), serde_json::json!("sip/service"));
        inputs.insert("iid".to_string(), serde_json::json!(5));
        let before = backend_operation_count(&backend, write_operation);
        let (status, body) = invoke_gitlab_outcome(
            &client,
            &base_url,
            action,
            request_id,
            serde_json::json!({"inputs":inputs}),
        )
        .await;
        assert_eq!(status, reqwest::StatusCode::FORBIDDEN, "{body}");
        assert_eq!(body["reasonCode"], "scope_unresolved");
        assert_eq!(backend_operation_count(&backend, write_operation), before);
    }
    *backend.discussion_proof_mismatch.lock().unwrap() = false;

    *backend.current_user_id.lock().unwrap() = 0;
    let writes_before = backend_operation_count(&backend, "create_merge_request_draft_note");
    let (status, body) = invoke_gitlab_outcome(
        &client,
        &base_url,
        "merge_request.draft_note.add",
        "gitlab-invalid-current-user",
        serde_json::json!({"inputs":{
            "project":"sip/service","iid":5,
            "content":"invalid actor secret","contentFormat":"markdown"
        }}),
    )
    .await;
    assert_eq!(status, reqwest::StatusCode::BAD_GATEWAY, "{body}");
    assert_eq!(body["reasonCode"], "upstream_protocol_failed");
    assert_eq!(
        backend_operation_count(&backend, "create_merge_request_draft_note"),
        writes_before
    );
    *backend.current_user_id.lock().unwrap() = 3;

    *backend.current_user_username.lock().unwrap() = "   ".to_string();
    let writes_before = backend_operation_count(&backend, "create_merge_request_draft_note");
    let (status, body) = invoke_gitlab_outcome(
        &client,
        &base_url,
        "merge_request.draft_note.add",
        "gitlab-empty-current-username",
        serde_json::json!({"inputs":{
            "project":"sip/service","iid":5,
            "content":"invalid username secret","contentFormat":"markdown"
        }}),
    )
    .await;
    assert_eq!(status, reqwest::StatusCode::BAD_GATEWAY, "{body}");
    assert_eq!(body["reasonCode"], "upstream_protocol_failed");
    assert!(body["result"]["reviewContext"].is_null());
    assert_eq!(
        backend_operation_count(&backend, "create_merge_request_draft_note"),
        writes_before
    );
    *backend.current_user_username.lock().unwrap() = "carol".to_string();

    *backend.fail_gitlab_version.lock().unwrap() = true;
    let bulk_writes_before =
        backend_operation_count(&backend, "bulk_publish_merge_request_draft_notes");
    let (status, body) = invoke_gitlab_outcome(
        &client,
        &base_url,
        "merge_request.review.submit",
        "gitlab-review-version-backend-protocol-failure",
        serde_json::json!({"inputs":{
            "project":"sip/service","iid":5,"reviewerState":"reviewed"
        }}),
    )
    .await;
    assert_eq!(status, reqwest::StatusCode::BAD_GATEWAY, "{body}");
    assert_eq!(body["reasonCode"], "upstream_protocol_failed");
    assert_eq!(
        backend_operation_count(&backend, "bulk_publish_merge_request_draft_notes"),
        bulk_writes_before
    );
    *backend.fail_gitlab_version.lock().unwrap() = false;

    for (mode, version, reviewer_state, approved, expected_status, expected_reason) in [
        (
            "absent",
            "19.2.0-ee",
            "requested_changes",
            false,
            409,
            "version_conflict",
        ),
        (
            "duplicate",
            "19.2.0-ee",
            "requested_changes",
            false,
            502,
            "upstream_protocol_failed",
        ),
        (
            "normal",
            "19.2.0-ee",
            "requested_changes",
            true,
            409,
            "version_conflict",
        ),
        (
            "normal",
            "19.1.0-ee",
            "requested_changes",
            false,
            424,
            "upstream_failed",
        ),
        (
            "normal",
            "not-a-version",
            "requested_changes",
            false,
            502,
            "upstream_protocol_failed",
        ),
        (
            "normal",
            "19.2.0-ee",
            "approved",
            false,
            409,
            "version_conflict",
        ),
    ] {
        *backend.reviewer_fixture_mode.lock().unwrap() = mode.to_string();
        *backend.gitlab_version_value.lock().unwrap() = version.to_string();
        *backend.reviewer_state.lock().unwrap() = reviewer_state.to_string();
        *backend.actor_formally_approved.lock().unwrap() = approved;
        let before = backend_operation_count(&backend, "bulk_publish_merge_request_draft_notes");
        let (status, body) = invoke_gitlab_outcome(
            &client,
            &base_url,
            "merge_request.review.submit",
            &format!("gitlab-review-preflight-{mode}-{version}-{reviewer_state}"),
            serde_json::json!({"inputs":{
                "project":"sip/service","iid":5,"reviewerState":"reviewed"
            }}),
        )
        .await;
        assert_eq!(status.as_u16(), expected_status, "{body}");
        assert_eq!(body["reasonCode"], expected_reason);
        assert_eq!(
            backend_operation_count(&backend, "bulk_publish_merge_request_draft_notes"),
            before
        );
    }

    let audit = broker.audit().unwrap();
    for (request_id, action) in [
        (
            "gitlab-wrong-draft-owner",
            "merge_request.draft_note.update",
        ),
        (
            "gitlab-invalid-current-user",
            "merge_request.draft_note.add",
        ),
    ] {
        audit.require_request(request_id, "gitlab", action);
    }
    let audit = audit.text();
    for secret in [
        "owner mismatch secret",
        "reply mismatch secret",
        "draft reply mismatch secret",
        "invalid actor secret",
    ] {
        assert!(!audit.contains(secret));
    }
    stop(broker).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn gitlab_review_verification_failures_expose_only_action_specific_safe_state() {
    let backend = stub_backend();
    let broker = start_broker(
        &gitlab_per_user_document(),
        gitlab_service(gitlab_provider_config(2), backend.clone()),
    )
    .await;
    let base_url = broker.public_url();
    let client = reqwest::Client::new();

    let success = invoke_gitlab(
        &client,
        &base_url,
        "merge_request.draft_note.add",
        "gitlab-verification-success-contract",
        serde_json::json!({"inputs":{
            "project":"sip/service","iid":5,
            "content":"verified success secret","contentFormat":"markdown"
        }}),
    )
    .await;
    assert_eq!(success["result"]["mutationStatus"], "applied");
    assert_eq!(success["result"]["retrySafe"], false);
    assert_eq!(success["result"]["draftNoteId"], 802);

    *backend.malformed_inline_response.lock().unwrap() = true;
    let outcome = invoke_gitlab_outcome(
        &client,
        &base_url,
        "merge_request.discussion.inline.add",
        "gitlab-inline-readback-stage",
        serde_json::json!({"inputs":{
            "project":"sip/service","iid":5,"expectedHeadSha":TEST_SHA,
            "content":"inline verification secret","contentFormat":"markdown",
            "position":{
                "positionType":"text","oldPath":"src/old.rs",
                "newPath":"src/new.rs","newLine":34
            }
        }}),
    )
    .await;
    assert_mutation_verification_failure(
        outcome.0,
        &outcome.1,
        "mutation_readback",
        serde_json::json!({"discussionId":"discussion-inline","noteId":910}),
    );
    *backend.malformed_inline_response.lock().unwrap() = false;

    *backend.malformed_draft_update_readback.lock().unwrap() = true;
    let outcome = invoke_gitlab_outcome(
        &client,
        &base_url,
        "merge_request.draft_note.update",
        "gitlab-draft-update-readback-stage",
        serde_json::json!({"inputs":{
            "project":"sip/service","iid":5,"draftNoteId":801,
            "content":"update verification secret","contentFormat":"markdown"
        }}),
    )
    .await;
    assert_mutation_verification_failure(
        outcome.0,
        &outcome.1,
        "mutation_readback",
        serde_json::json!({"draftNoteIds":[801]}),
    );
    *backend.malformed_draft_update_readback.lock().unwrap() = false;

    backend.draft_notes.lock().unwrap().push(draft_note_fixture(
        805,
        "position preservation secret",
        Some(draft_position_fixture()),
    ));
    *backend.drop_draft_position_on_update.lock().unwrap() = true;
    let outcome = invoke_gitlab_outcome(
        &client,
        &base_url,
        "merge_request.draft_note.update",
        "gitlab-draft-position-readback-stage",
        serde_json::json!({"inputs":{
            "project":"sip/service","iid":5,"draftNoteId":805,
            "content":"position loss secret","contentFormat":"markdown"
        }}),
    )
    .await;
    assert_mutation_verification_failure(
        outcome.0,
        &outcome.1,
        "mutation_readback",
        serde_json::json!({"draftNoteIds":[805]}),
    );
    *backend.drop_draft_position_on_update.lock().unwrap() = false;
    backend
        .draft_notes
        .lock()
        .unwrap()
        .retain(|draft| draft.id != 805);

    let mut incomplete_position = draft_position_fixture();
    incomplete_position.base_sha = None;
    backend.draft_notes.lock().unwrap().push(draft_note_fixture(
        806,
        "incomplete position secret",
        Some(incomplete_position),
    ));
    let update_writes = backend_operation_count(&backend, "update_merge_request_draft_note");
    let (status, body) = invoke_gitlab_outcome(
        &client,
        &base_url,
        "merge_request.draft_note.update",
        "gitlab-draft-position-replay-preflight",
        serde_json::json!({"inputs":{
            "project":"sip/service","iid":5,"draftNoteId":806,
            "content":"unsafe replay secret","contentFormat":"markdown"
        }}),
    )
    .await;
    assert_eq!(status, reqwest::StatusCode::CONFLICT, "{body}");
    assert_eq!(body["reasonCode"], "version_conflict");
    assert!(
        body["reason"]
            .as_str()
            .is_some_and(|message| message.contains("replacement position")),
        "{body}"
    );
    assert_eq!(
        backend_operation_count(&backend, "update_merge_request_draft_note"),
        update_writes
    );
    backend
        .draft_notes
        .lock()
        .unwrap()
        .retain(|draft| draft.id != 806);

    *backend.retain_deleted_draft.lock().unwrap() = true;
    let outcome = invoke_gitlab_outcome(
        &client,
        &base_url,
        "merge_request.draft_note.delete",
        "gitlab-draft-delete-absence-stage",
        serde_json::json!({"inputs":{
            "project":"sip/service","iid":5,"draftNoteId":801
        }}),
    )
    .await;
    assert_mutation_verification_failure(
        outcome.0,
        &outcome.1,
        "draft_absence_readback",
        serde_json::json!({"draftNoteIds":[801]}),
    );
    *backend.retain_deleted_draft.lock().unwrap() = false;

    *backend.retain_published_draft.lock().unwrap() = true;
    let outcome = invoke_gitlab_outcome(
        &client,
        &base_url,
        "merge_request.draft_note.publish",
        "gitlab-draft-publish-absence-stage",
        serde_json::json!({"inputs":{
            "project":"sip/service","iid":5,"draftNoteId":801
        }}),
    )
    .await;
    assert_mutation_verification_failure(
        outcome.0,
        &outcome.1,
        "draft_absence_readback",
        serde_json::json!({
            "draftNoteIds":[801],
            "discussionId":"published-draft-801",
            "noteId":12801
        }),
    );
    *backend.retain_published_draft.lock().unwrap() = false;

    *backend.fail_bulk_publish_without_apply.lock().unwrap() = true;
    let (status, body) = invoke_gitlab_outcome(
        &client,
        &base_url,
        "merge_request.draft_note.publish_all",
        "gitlab-bulk-publish-proven-unchanged",
        serde_json::json!({"inputs":{"project":"sip/service","iid":5}}),
    )
    .await;
    assert_eq!(status, reqwest::StatusCode::FAILED_DEPENDENCY, "{body}");
    assert_eq!(body["reasonCode"], "upstream_failed");
    assert!(body.get("result").is_none(), "{body}");
    assert_eq!(
        backend
            .draft_notes
            .lock()
            .unwrap()
            .iter()
            .map(|draft| draft.id)
            .collect::<Vec<_>>(),
        vec![801, 802]
    );
    *backend.fail_bulk_publish_without_apply.lock().unwrap() = false;

    *backend.fail_bulk_publish_after_apply.lock().unwrap() = true;
    let outcome = invoke_gitlab_outcome(
        &client,
        &base_url,
        "merge_request.draft_note.publish_all",
        "gitlab-bulk-publish-readback-stage",
        serde_json::json!({"inputs":{"project":"sip/service","iid":5}}),
    )
    .await;
    assert_mutation_verification_failure(
        outcome.0,
        &outcome.1,
        "bulk_publish_readback",
        serde_json::json!({"draftNoteIds":[801,802]}),
    );
    *backend.fail_bulk_publish_after_apply.lock().unwrap() = false;

    backend
        .draft_notes
        .lock()
        .unwrap()
        .push(draft_note_fixture(803, "reviewer-stage draft", None));
    *backend.skip_reviewer_state_update.lock().unwrap() = true;
    let outcome = invoke_gitlab_outcome(
        &client,
        &base_url,
        "merge_request.review.submit",
        "gitlab-reviewer-readback-stage",
        serde_json::json!({"inputs":{
            "project":"sip/service","iid":5,"reviewerState":"reviewed"
        }}),
    )
    .await;
    assert_mutation_verification_failure(
        outcome.0,
        &outcome.1,
        "reviewer_state_readback",
        serde_json::json!({"draftNoteIds":[803]}),
    );
    *backend.skip_reviewer_state_update.lock().unwrap() = false;

    backend
        .draft_notes
        .lock()
        .unwrap()
        .push(draft_note_fixture(804, "summary-stage draft", None));
    *backend.malformed_review_summary.lock().unwrap() = true;
    let outcome = invoke_gitlab_outcome(
        &client,
        &base_url,
        "merge_request.draft_note.publish_all",
        "gitlab-summary-response-stage",
        serde_json::json!({"inputs":{
            "project":"sip/service","iid":5,
            "content":"summary verification secret","contentFormat":"markdown"
        }}),
    )
    .await;
    assert_mutation_verification_failure(
        outcome.0,
        &outcome.1,
        "summary_note_response",
        serde_json::json!({"noteId":990,"draftNoteIds":[804]}),
    );

    let audit = broker.audit().unwrap();
    for (request_id, action) in [
        (
            "gitlab-verification-success-contract",
            "merge_request.draft_note.add",
        ),
        (
            "gitlab-inline-readback-stage",
            "merge_request.discussion.inline.add",
        ),
        (
            "gitlab-draft-update-readback-stage",
            "merge_request.draft_note.update",
        ),
        (
            "gitlab-draft-position-readback-stage",
            "merge_request.draft_note.update",
        ),
        (
            "gitlab-draft-position-replay-preflight",
            "merge_request.draft_note.update",
        ),
        (
            "gitlab-summary-response-stage",
            "merge_request.draft_note.publish_all",
        ),
    ] {
        audit.require_request(request_id, "gitlab", action);
    }
    let audit = audit.text();
    for secret in [
        "verified success secret",
        "inline verification secret",
        "update verification secret",
        "position preservation secret",
        "position loss secret",
        "incomplete position secret",
        "unsafe replay secret",
        "reviewer-stage draft",
        "summary-stage draft",
        "summary verification secret",
    ] {
        assert!(!audit.contains(secret));
    }
    stop(broker).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn single_draft_publication_enforces_snapshot_bounds_before_and_after_mutation() {
    let backend = stub_backend();
    let broker = start_broker(
        &gitlab_per_user_document(),
        gitlab_service(gitlab_provider_config(2), backend.clone()),
    )
    .await;
    let base_url = broker.public_url();
    let client = reqwest::Client::new();

    for mode in ["too_many", "invalid_next", "endless"] {
        *backend.discussion_pagination_mode.lock().unwrap() = mode.to_string();
        let writes = backend_operation_count(&backend, "publish_merge_request_draft_note");
        let (status, body) = invoke_gitlab_outcome(
            &client,
            &base_url,
            "merge_request.draft_note.publish",
            &format!("gitlab-publish-pre-{mode}"),
            serde_json::json!({"inputs":{
                "project":"sip/service","iid":5,"draftNoteId":801
            }}),
        )
        .await;
        assert_eq!(status, reqwest::StatusCode::BAD_GATEWAY, "{body}");
        assert_eq!(body["reasonCode"], "upstream_protocol_failed");
        assert_eq!(
            body["error"]["message"],
            match mode {
                "too_many" => "GitLab returned more paginated items than requested",
                "endless" => {
                    "GitLab discussion snapshot exceeded the 10-page publication verification limit"
                }
                _ => "GitLab published note readback was malformed",
            }
        );
        assert_eq!(
            backend_operation_count(&backend, "publish_merge_request_draft_note"),
            writes
        );
    }

    *backend.discussion_pagination_mode.lock().unwrap() = "invalid_after_publish".to_string();
    let outcome = invoke_gitlab_outcome(
        &client,
        &base_url,
        "merge_request.draft_note.publish",
        "gitlab-publish-post-invalid-next",
        serde_json::json!({"inputs":{
            "project":"sip/service","iid":5,"draftNoteId":801
        }}),
    )
    .await;
    assert_mutation_verification_failure(
        outcome.0,
        &outcome.1,
        "published_note_readback",
        serde_json::json!({"draftNoteIds":[801]}),
    );
    assert_eq!(
        backend_operation_count(&backend, "publish_merge_request_draft_note"),
        1
    );

    stop(broker).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn gitlab_review_positions_and_write_failures_preserve_retry_contracts() {
    let backend = stub_backend();
    let broker = start_broker(
        &gitlab_per_user_document(),
        gitlab_service(gitlab_provider_config(2), backend.clone()),
    )
    .await;
    let base_url = broker.public_url();
    let client = reqwest::Client::new();

    let inline_writes = backend_operation_count(&backend, "create_merge_request_inline_discussion");
    let (status, rejected_image) = invoke_gitlab_outcome(
        &client,
        &base_url,
        "merge_request.discussion.inline.add",
        "gitlab-fractional-image-position",
        serde_json::json!({"inputs":{
            "project":"sip/service","iid":5,"expectedHeadSha":TEST_SHA,
            "content":"fractional image secret\r\n","contentFormat":"markdown",
            "position":{
                "positionType":"image","oldPath":"diagram-old.png","newPath":"diagram.png",
                "width":640,"height":480,"x":12.5,"y":24.25
            }
        }}),
    )
    .await;
    assert_eq!(status, reqwest::StatusCode::BAD_REQUEST, "{rejected_image}");
    assert_eq!(rejected_image["reasonCode"], "input_invalid");
    assert_eq!(
        backend_operation_count(&backend, "create_merge_request_inline_discussion"),
        inline_writes
    );

    let image = invoke_gitlab(
        &client,
        &base_url,
        "merge_request.discussion.inline.add",
        "gitlab-integer-image-position",
        serde_json::json!({"inputs":{
            "project":"sip/service","iid":5,"expectedHeadSha":TEST_SHA,
            "content":"integer image secret\r\n","contentFormat":"markdown",
            "position":{
                "positionType":"image","oldPath":"diagram-old.png","newPath":"diagram.png",
                "width":640,"height":480,"x":12,"y":24
            }
        }}),
    )
    .await;
    assert_eq!(image["result"]["retrySafe"], false);
    assert_eq!(
        image["result"]["discussion"]["notes"][0]["position"]["x"],
        12
    );
    assert_eq!(
        image["result"]["discussion"]["notes"][0]["position"]["y"],
        24
    );
    let observed = backend
        .last_inline_discussion_add
        .lock()
        .unwrap()
        .clone()
        .unwrap();
    assert_eq!(observed.request.position.x, Some(12));
    assert_eq!(observed.request.position.y, Some(24));

    let normalized_reply = invoke_gitlab(
        &client,
        &base_url,
        "merge_request.discussion.note.add",
        "gitlab-normalized-reply-readback",
        serde_json::json!({"inputs":{
            "project":"sip/service","iid":5,"discussionId":"discussion-outdated",
            "content":"normalized reply secret\r\n","contentFormat":"markdown"
        }}),
    )
    .await;
    assert_eq!(normalized_reply["result"]["mutationStatus"], "applied");

    let normalized_summary = invoke_gitlab(
        &client,
        &base_url,
        "merge_request.review.submit",
        "gitlab-normalized-summary-readback",
        serde_json::json!({"inputs":{
            "project":"sip/service","iid":5,"reviewerState":"reviewed",
            "content":"normalized summary secret\r\n","contentFormat":"markdown"
        }}),
    )
    .await;
    assert_eq!(normalized_summary["result"]["mutationStatus"], "applied");

    for (state, expected_status, expected_reason, expected_category) in [
        ("overflow", 400, "input_invalid", Some("patch_unavailable")),
        (
            "without_files",
            400,
            "input_invalid",
            Some("patch_unavailable"),
        ),
        ("preparing", 409, "version_conflict", None),
    ] {
        *backend.diff_version_state.lock().unwrap() = state.to_string();
        let writes_before =
            backend_operation_count(&backend, "create_merge_request_inline_discussion");
        let (status, body) = invoke_gitlab_outcome(
            &client,
            &base_url,
            "merge_request.discussion.inline.add",
            &format!("gitlab-diff-version-state-{state}"),
            serde_json::json!({"inputs":{
                "project":"sip/service","iid":5,"expectedHeadSha":TEST_SHA,
                "content":"version state secret","contentFormat":"markdown",
                "position":{
                    "positionType":"text","oldPath":"src/old.rs","newPath":"src/new.rs",
                    "lineRange":{"start":{"oldLine":31},"end":{"newLine":34}}
                }
            }}),
        )
        .await;
        assert_eq!(status.as_u16(), expected_status, "{body}");
        assert_eq!(body["reasonCode"], expected_reason);
        if let Some(category) = expected_category {
            assert_eq!(body["result"]["inputCategory"], category);
        } else {
            assert!(body["result"].is_null());
        }
        assert_eq!(
            backend_operation_count(&backend, "create_merge_request_inline_discussion"),
            writes_before
        );
    }
    *backend.diff_version_state.lock().unwrap() = "collected".to_string();

    *backend.fail_discussion_reply_write.lock().unwrap() = true;
    let outcome = invoke_gitlab_outcome(
        &client,
        &base_url,
        "merge_request.discussion.note.add",
        "gitlab-reply-upstream-5xx",
        serde_json::json!({"inputs":{
            "project":"sip/service","iid":5,"discussionId":"discussion-outdated",
            "content":"write failure secret","contentFormat":"markdown"
        }}),
    )
    .await;
    assert_mutation_verification_failure(
        outcome.0,
        &outcome.1,
        "mutation_response",
        serde_json::json!({"discussionId":"discussion-outdated"}),
    );

    let bulk_writes = backend_operation_count(&backend, "bulk_publish_merge_request_draft_notes");
    let (status, body) = invoke_gitlab_outcome(
        &client,
        &base_url,
        "merge_request.review.submit",
        "gitlab-review-quick-action-body",
        serde_json::json!({"inputs":{
            "project":"sip/service","iid":5,"reviewerState":"reviewed",
            "content":"/approve\nlooks good","contentFormat":"markdown"
        }}),
    )
    .await;
    assert_eq!(status, reqwest::StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(body["reasonCode"], "input_invalid");
    assert_eq!(
        backend_operation_count(&backend, "bulk_publish_merge_request_draft_notes"),
        bulk_writes
    );

    let audit = broker.audit().unwrap();
    for (request_id, action) in [
        (
            "gitlab-fractional-image-position",
            "merge_request.discussion.inline.add",
        ),
        (
            "gitlab-integer-image-position",
            "merge_request.discussion.inline.add",
        ),
        (
            "gitlab-normalized-reply-readback",
            "merge_request.discussion.note.add",
        ),
        (
            "gitlab-normalized-summary-readback",
            "merge_request.review.submit",
        ),
        (
            "gitlab-reply-upstream-5xx",
            "merge_request.discussion.note.add",
        ),
        (
            "gitlab-review-quick-action-body",
            "merge_request.review.submit",
        ),
    ] {
        audit.require_request(request_id, "gitlab", action);
    }
    let audit = audit.text();
    for secret in [
        "fractional image secret",
        "integer image secret",
        "normalized reply secret",
        "normalized summary secret",
        "version state secret",
        "write failure secret",
        "/approve",
        "looks good",
    ] {
        assert!(!audit.contains(secret));
    }
    stop(broker).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn gitlab_normalized_reads_cover_all_callers_nested_content_and_pagination() {
    const ISSUE_BODY: &str = "issue context";
    const MERGE_REQUEST_BODY: &str = "merge request context";
    const ISSUE_NOTE_BODY: &str = "existing issue note";
    const DISCUSSION_BODY: &str = "existing discussion";
    const CREATED_NOTE_BODY: &str = "created issue note";
    const RESOLVED_DISCUSSION_BODY: &str = "state changed discussion";

    let backend = stub_backend();
    let broker = start_broker(
        &gitlab_per_user_document(),
        gitlab_service(gitlab_provider_config(2), backend.clone()),
    )
    .await;
    let base_url = broker.public_url();

    let native = gitlab_cli(&base_url)
        .args(["gitlab", "issue", "view", "sip/service", "7"])
        .output()
        .unwrap();
    assert_success("native issue view", &native);
    let native_json: serde_json::Value = serde_json::from_slice(&native.stdout).unwrap();
    assert_eq!(native_json["result"]["issue"]["description"], ISSUE_BODY);
    assert!(native_json["result"]["issue"].get("renderedBody").is_none());
    let native_operations = take_backend_operations(&backend);

    let embedded = gitlab_cli(&base_url)
        .args([
            "gitlab",
            "issue",
            "view",
            "sip/service",
            "7",
            "--read-content-format",
            "markdown",
        ])
        .output()
        .unwrap();
    assert_success("typed embedded issue view", &embedded);
    let mut embedded_json: serde_json::Value = serde_json::from_slice(&embedded.stdout).unwrap();
    assert_eq!(
        embedded_json["result"]["issue"]["renderedBody"],
        serde_json::json!({"format":"markdown", "value":ISSUE_BODY})
    );
    embedded_json["result"]["issue"]
        .as_object_mut()
        .unwrap()
        .remove("renderedBody");
    assert_eq!(embedded_json["result"], native_json["result"]);
    assert_eq!(take_backend_operations(&backend), native_operations);

    let whole = gitlab_cli(&base_url)
        .args([
            "gitlab",
            "issue",
            "view",
            "sip/service",
            "7",
            "--output-format",
            "markdown",
        ])
        .output()
        .unwrap();
    assert_success("typed Markdown issue view", &whole);
    let whole_stdout = String::from_utf8(whole.stdout).unwrap();
    assert!(whole.stderr.is_empty());
    assert!(whole_stdout.starts_with("# GitLab issue "));
    assert!(whole_stdout.contains(ISSUE_BODY));
    assert!(!whole_stdout.contains("\"decision\""));
    assert!(!whole_stdout.contains("\"description\""));
    assert_eq!(take_backend_operations(&backend), native_operations);

    let generic = gitlab_cli(&base_url)
        .args([
            "invoke",
            "gitlab.merge_request.view",
            "--input-json",
            r#"{"project":"sip/service","iid":5}"#,
            "--read-content-format",
            "text",
        ])
        .output()
        .unwrap();
    assert_success("generic embedded merge request view", &generic);
    let generic_json: serde_json::Value = serde_json::from_slice(&generic.stdout).unwrap();
    assert_eq!(
        generic_json["result"]["mergeRequest"]["renderedBody"],
        serde_json::json!({"format":"text", "value":MERGE_REQUEST_BODY})
    );
    assert_eq!(
        generic_json["result"]["mergeRequest"]["description"],
        MERGE_REQUEST_BODY
    );
    take_backend_operations(&backend);

    let client = reqwest::Client::new();
    let merge_request_search = invoke_gitlab(
        &client,
        &base_url,
        "merge_request.search",
        "gitlab-direct-merge-request-search",
        serde_json::json!({
            "inputs":{"project":"sip/service","maxResults":2},
            "readContentFormat":"markdown"
        }),
    )
    .await;
    assert_eq!(
        merge_request_search["result"]["mergeRequests"][0]["renderedBody"],
        serde_json::json!({"format":"markdown", "value":MERGE_REQUEST_BODY})
    );
    assert_eq!(
        merge_request_search["result"]["mergeRequests"][0]["description"],
        MERGE_REQUEST_BODY
    );
    take_backend_operations(&backend);

    let send_path = temp_path("gitlab-normalized-read-send.json");
    std::fs::write(
        &send_path,
        r#"{"version":"agent-access.send.v1","kind":"invoke","service":"gitlab","action":"issue.note.list","inputs":{"project":"sip/service","iid":7,"maxResults":2},"readContentFormat":"markdown"}"#,
    )
    .unwrap();
    let send = gitlab_cli(&base_url)
        .args(["send", "--request-file", send_path.to_str().unwrap()])
        .output()
        .unwrap();
    assert_success("send embedded issue notes", &send);
    let send_json: serde_json::Value = serde_json::from_slice(&send.stdout).unwrap();
    assert_eq!(
        send_json["result"]["notes"][0]["renderedBody"],
        serde_json::json!({"format":"markdown", "value":ISSUE_NOTE_BODY})
    );
    assert_eq!(send_json["result"]["notes"][0]["body"], ISSUE_NOTE_BODY);
    take_backend_operations(&backend);

    let discussion = invoke_gitlab(
        &client,
        &base_url,
        "merge_request.discussion.list",
        "gitlab-direct-discussion-list",
        serde_json::json!({
            "inputs":{"project":"sip/service","iid":5,"maxResults":2},
            "readContentFormat":"markdown"
        }),
    )
    .await;
    assert_eq!(discussion["decision"], "allow");
    assert_eq!(
        discussion["result"]["discussions"][0]["notes"][0]["renderedBody"],
        serde_json::json!({"format":"markdown", "value":DISCUSSION_BODY})
    );
    assert_eq!(
        discussion["result"]["discussions"][0]["notes"][0]["body"],
        DISCUSSION_BODY
    );
    let review_note = &discussion["result"]["discussions"][0]["notes"][0];
    assert_eq!(review_note["type"], "DiffNote");
    assert_eq!(review_note["position"]["oldPath"], "src/old.rs");
    assert_eq!(review_note["position"]["newPath"], "src/new.rs");
    assert_eq!(review_note["position"]["oldLine"], 31);
    assert_eq!(review_note["position"]["newLine"], 34);
    assert_eq!(
        review_note["position"]["lineRange"]["end"]["lineCode"],
        "line-code-33-36"
    );
    assert_eq!(review_note["resolvedBy"]["username"], "reviewer");
    assert_eq!(review_note["suggestions"][0]["id"], 456);
    assert_eq!(review_note["suggestions"][0]["applicable"], true);
    take_backend_operations(&backend);

    let resolved = invoke_gitlab(
        &client,
        &base_url,
        "merge_request.discussion.resolve",
        "gitlab-direct-discussion-resolve",
        serde_json::json!({
            "inputs":{
                "project":"sip/service",
                "iid":5,
                "discussionId":"discussion-1"
            },
            "readContentFormat":"markdown"
        }),
    )
    .await;
    assert_eq!(
        resolved["result"]["discussion"]["notes"][0]["renderedBody"],
        serde_json::json!({"format":"markdown", "value":RESOLVED_DISCUSSION_BODY})
    );
    assert_eq!(
        resolved["result"]["discussion"]["notes"][0]["body"],
        RESOLVED_DISCUSSION_BODY
    );
    take_backend_operations(&backend);

    let mutation = invoke_gitlab(
        &client,
        &base_url,
        "issue.note.add",
        "gitlab-direct-note-add",
        serde_json::json!({
            "inputs":{
                "project":"sip/service",
                "iid":7,
                "content":"caller supplied note",
                "contentFormat":"markdown"
            },
            "readContentFormat":"markdown"
        }),
    )
    .await;
    assert_eq!(mutation["decision"], "allow");
    assert_eq!(
        mutation["result"]["note"]["renderedBody"],
        serde_json::json!({"format":"markdown", "value":CREATED_NOTE_BODY})
    );
    assert_eq!(mutation["result"]["note"]["body"], CREATED_NOTE_BODY);
    take_backend_operations(&backend);

    let rejected_source = "unsupported whole mutation source sentinel";
    let unsupported = client
        .post(format!("{base_url}/v1/invoke/gitlab/issue.note.add"))
        .header(
            "X-Agent-Access-Request-Id",
            "gitlab-mutation-markdown-unsupported",
        )
        .header("X-Agent-Access-Identity-Token", "agent-token")
        .json(&serde_json::json!({
            "inputs":{
                "project":"sip/service",
                "iid":7,
                "content":rejected_source,
                "contentFormat":"markdown"
            },
            "responseFormat":"markdown"
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(
        unsupported.status(),
        reqwest::StatusCode::UNSUPPORTED_MEDIA_TYPE
    );
    let unsupported: serde_json::Value = unsupported.json().await.unwrap();
    assert_eq!(unsupported["reasonCode"], "response_format_unsupported");
    assert!(!unsupported.to_string().contains(rejected_source));
    assert!(take_backend_operations(&backend).is_empty());

    let first_page = invoke_gitlab(
        &client,
        &base_url,
        "issue.search",
        "gitlab-direct-search-native",
        serde_json::json!({
            "inputs":{"project":"sip/service","maxResults":2},
            "readContentFormat":"markdown"
        }),
    )
    .await;
    assert_eq!(
        first_page["result"]["issues"][0]["renderedBody"],
        serde_json::json!({"format":"markdown", "value":ISSUE_BODY})
    );
    let page_token = first_page["result"]["nextPageToken"]
        .as_str()
        .expect("native search continuation token")
        .to_string();
    let first_page_operations = take_backend_operations(&backend);
    let second_page = invoke_gitlab(
        &client,
        &base_url,
        "issue.search",
        "gitlab-direct-search-markdown",
        serde_json::json!({
            "inputs":{
                "project":"sip/service",
                "maxResults":2,
                "pageToken":page_token
            },
            "responseFormat":"markdown"
        }),
    )
    .await;
    assert_eq!(second_page["result"]["format"], "markdown");
    let search_markdown = second_page["result"]["value"].as_str().unwrap();
    assert!(search_markdown.starts_with("# GitLab issues"));
    assert!(search_markdown.contains(ISSUE_BODY));
    assert!(!search_markdown.contains("\"issues\""));
    assert_eq!(take_backend_operations(&backend), first_page_operations);
    assert_eq!(
        backend
            .last_issue_search
            .lock()
            .unwrap()
            .as_ref()
            .unwrap()
            .request
            .page,
        2
    );

    let audit = broker.audit().unwrap();
    audit.require_action("gitlab", "issue.view");
    for (request_id, action) in [
        ("gitlab-direct-merge-request-search", "merge_request.search"),
        (
            "gitlab-direct-discussion-list",
            "merge_request.discussion.list",
        ),
        (
            "gitlab-direct-discussion-resolve",
            "merge_request.discussion.resolve",
        ),
        ("gitlab-direct-note-add", "issue.note.add"),
        ("gitlab-mutation-markdown-unsupported", "issue.note.add"),
        ("gitlab-direct-search-native", "issue.search"),
        ("gitlab-direct-search-markdown", "issue.search"),
    ] {
        audit.require_request(request_id, "gitlab", action);
    }
    let audit = audit.text();
    for secret in [
        ISSUE_BODY,
        MERGE_REQUEST_BODY,
        ISSUE_NOTE_BODY,
        DISCUSSION_BODY,
        CREATED_NOTE_BODY,
        RESOLVED_DISCUSSION_BODY,
        "caller supplied note",
        rejected_source,
        page_token.as_str(),
    ] {
        assert!(!audit.contains(secret), "audit leaked {secret}");
    }

    stop(broker).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn gitlab_normalized_read_failures_are_atomic_bounded_and_secret() {
    const OVERSIZED_NOTE_SENTINEL: &str = "oversized-note-sentinel-8b31d7";
    const OVERSIZED_DISCUSSION_SENTINEL: &str = "oversized-discussion-sentinel-4c62a9";
    const MALFORMED_BASE64_SENTINEL: &str = "malformed-base64-sentinel-1e73bf***";
    const FILE_BASE64_SENTINEL: &str = "ZmlsZS1tYXJrZG93bi1zZW50aW5lbC05ZjhjMmU=";
    const FILE_DECODED_SENTINEL: &str = "file-markdown-sentinel-9f8c2e";
    const FINAL_CAP_SENTINEL: &str = "final-result-cap-sentinel-6a04cd";

    let backend = stub_backend();
    let mut provider_config = gitlab_provider_config(2);
    provider_config.content.max_body_bytes = 64;
    let mut document = gitlab_per_user_document();
    document.provider = provider_config.clone();
    let broker = start_broker(&document, gitlab_service(provider_config, backend.clone())).await;
    let base_url = broker.public_url();

    *backend.issue_note_body.lock().unwrap() =
        Some(format!("{OVERSIZED_NOTE_SENTINEL}{}", "n".repeat(64)));
    let oversized_note = gitlab_cli(&base_url)
        .args(["gitlab", "issue", "list-comments", "sip/service", "7"])
        .output()
        .unwrap();
    assert_atomic_cli_error(
        "oversized native issue note",
        &oversized_note,
        OVERSIZED_NOTE_SENTINEL,
    );
    assert_eq!(
        take_backend_operations(&backend),
        ["project", "project", "issue", "issue_notes"]
    );

    *backend.discussion_body.lock().unwrap() =
        Some(format!("{OVERSIZED_DISCUSSION_SENTINEL}{}", "d".repeat(64)));
    let client = reqwest::Client::new();
    let oversized_discussion = client
        .post(format!(
            "{base_url}/v1/invoke/gitlab/merge_request.discussion.list"
        ))
        .header(
            "X-Agent-Access-Request-Id",
            "gitlab-oversized-discussion-native",
        )
        .header("X-Agent-Access-Identity-Token", "agent-token")
        .json(&serde_json::json!({
            "inputs":{"project":"sip/service","iid":5,"maxResults":2},
            "readContentFormat":"native"
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(
        oversized_discussion.status(),
        reqwest::StatusCode::BAD_GATEWAY
    );
    let oversized_discussion: serde_json::Value = oversized_discussion.json().await.unwrap();
    assert_eq!(
        oversized_discussion["reasonCode"],
        "upstream_protocol_failed"
    );
    assert!(
        !oversized_discussion
            .to_string()
            .contains(OVERSIZED_DISCUSSION_SENTINEL)
    );
    assert_eq!(
        take_backend_operations(&backend),
        [
            "project",
            "project",
            "merge_request",
            "merge_request_discussions_page"
        ]
    );

    {
        let mut files = backend.files.lock().unwrap();
        let file = files
            .get_mut(&("main".to_string(), "README.md".to_string()))
            .unwrap();
        file.content = Some(MALFORMED_BASE64_SENTINEL.to_string());
        file.size = 1;
    }
    let malformed_file = gitlab_cli(&base_url)
        .args([
            "gitlab",
            "file",
            "view",
            "sip/service",
            "--path",
            "README.md",
            "--ref",
            "main",
            "--output-format",
            "markdown",
        ])
        .output()
        .unwrap();
    assert_atomic_cli_error(
        "malformed base64 whole-result Markdown",
        &malformed_file,
        MALFORMED_BASE64_SENTINEL,
    );
    assert_eq!(
        take_backend_operations(&backend),
        ["project", "project", "file"]
    );

    {
        let mut files = backend.files.lock().unwrap();
        let file = files
            .get_mut(&("main".to_string(), "README.md".to_string()))
            .unwrap();
        file.content = Some(FILE_BASE64_SENTINEL.to_string());
        file.size = FILE_DECODED_SENTINEL.len() as u64;
    }
    let file_markdown = gitlab_cli(&base_url)
        .args([
            "gitlab",
            "file",
            "view",
            "sip/service",
            "--path",
            "README.md",
            "--ref",
            "main",
            "--output-format",
            "markdown",
        ])
        .output()
        .unwrap();
    assert_success("base64 file whole-result Markdown", &file_markdown);
    let file_markdown = String::from_utf8(file_markdown.stdout).unwrap();
    assert!(file_markdown.contains(FILE_BASE64_SENTINEL));
    assert!(!file_markdown.contains(FILE_DECODED_SENTINEL));
    assert_eq!(
        take_backend_operations(&backend),
        ["project", "project", "file"]
    );

    let audit = broker.audit().unwrap();
    audit.require_action("gitlab", "issue.note.list");
    audit.require_request(
        "gitlab-oversized-discussion-native",
        "gitlab",
        "merge_request.discussion.list",
    );
    audit.require_action("gitlab", "file.view");
    let audit = audit.text();
    for sentinel in [
        OVERSIZED_NOTE_SENTINEL,
        OVERSIZED_DISCUSSION_SENTINEL,
        MALFORMED_BASE64_SENTINEL,
        FILE_BASE64_SENTINEL,
        FILE_DECODED_SENTINEL,
    ] {
        assert!(!audit.contains(sentinel), "audit leaked {sentinel}");
    }

    stop(broker).await;

    let mut capped_backend = stub_backend();
    Arc::get_mut(&mut capped_backend)
        .unwrap()
        .projects
        .get_mut("sip/service")
        .unwrap()
        .name = Some(FINAL_CAP_SENTINEL.to_string());
    let provider_config = gitlab_provider_config(2);
    let mut capped_document = gitlab_per_user_document();
    capped_document.max_upstream_response_bytes = Some(64);
    let capped_broker = start_broker(
        &capped_document,
        gitlab_service(provider_config, capped_backend.clone()),
    )
    .await;
    let capped_base_url = capped_broker.public_url();
    let capped = gitlab_cli(&capped_base_url)
        .args(["gitlab", "project", "view", "sip/service"])
        .output()
        .unwrap();
    assert_atomic_cli_error(
        "final serialized GitLab result cap",
        &capped,
        FINAL_CAP_SENTINEL,
    );
    assert_eq!(
        take_backend_operations(&capped_backend),
        ["project", "project", "project"]
    );
    // The capped broker has its own audit store.
    let capped_audit = capped_broker.audit().unwrap();
    capped_audit.require_action("gitlab", "project.view");
    assert!(!capped_audit.text().contains(FINAL_CAP_SENTINEL));
    stop(capped_broker).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn gitlab_inline_file_over_one_mib_works_over_http_and_cli() {
    let content_path = temp_path("gitlab-large-inline.txt");
    let content = "x".repeat(1024 * 1024 + 128);
    std::fs::write(&content_path, &content).unwrap();
    let backend = stub_backend();
    let broker = start_broker(
        &gitlab_document(),
        gitlab_service(gitlab_provider_config(2), backend.clone()),
    )
    .await;
    let base_url = broker.public_url();
    let response = reqwest::Client::new().post(format!("{base_url}/v1/invoke/gitlab/file.create"))
        .header(agent_access_provider::REQUEST_ID_HEADER, "large-inline-http")
        .json(&serde_json::json!({"inputs": {"project": "sip/service", "path": "docs/large-http.txt", "branch": "feature/rest", "content": content, "commitMessage": "Add large file"}}))
        .send().await.unwrap();
    let status = response.status();
    let value: serde_json::Value = response.json().await.unwrap();
    assert_eq!(status, reqwest::StatusCode::OK, "{value}");
    assert_eq!(
        backend
            .last_file_create
            .lock()
            .unwrap()
            .as_ref()
            .unwrap()
            .decoded_content_bytes,
        content.len() as u64
    );
    let output = Command::new(env!("CARGO_BIN_EXE_agent-access"))
        .args([
            "--url",
            &base_url,
            "--no-token",
            "gitlab",
            "file",
            "create",
            "sip/service",
            "--path",
            "docs/large-cli.txt",
            "--branch",
            "feature/rest",
            "--content-file",
            content_path.to_str().unwrap(),
            "--message",
            "Add large file",
        ])
        .output()
        .unwrap();
    assert_success("large inline file create", &output);
    assert_eq!(
        backend
            .last_file_create
            .lock()
            .unwrap()
            .as_ref()
            .unwrap()
            .decoded_content_bytes,
        content.len() as u64
    );
    stop(broker).await;
    std::fs::remove_file(content_path).unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cli_invokes_gitlab_repository_write_and_raw_file_actions_against_stubbed_backend() {
    let content_path = temp_path("gitlab-file-content.md");
    let raw_output_path = temp_path("gitlab-raw-readme.txt");
    let actions_path = temp_path("gitlab-commit-actions.json");
    let many_actions_path = temp_path("gitlab-many-commit-actions.json");
    std::fs::write(&content_path, "file secret content").unwrap();

    let backend = stub_backend();
    let broker = start_broker(
        &gitlab_document(),
        gitlab_service(gitlab_provider_config(2), backend.clone()),
    )
    .await;
    let base_url = broker.public_url();

    let branch_create = Command::new(env!("CARGO_BIN_EXE_agent-access"))
        .args([
            "--url",
            &base_url,
            "--no-token",
            "gitlab",
            "branch",
            "create",
            "sip/service",
            "work/docs",
            "--ref",
            "main",
        ])
        .output()
        .unwrap();
    assert_success("branch create", &branch_create);
    let observed_branch = backend.last_branch_create.lock().unwrap().clone().unwrap();
    assert_eq!(observed_branch.branch, "work/docs");
    assert_eq!(observed_branch.ref_name, "main");

    let branch_create_from_short_sha = Command::new(env!("CARGO_BIN_EXE_agent-access"))
        .args([
            "--url",
            &base_url,
            "--no-token",
            "gitlab",
            "branch",
            "create",
            "sip/service",
            "work/from-short-sha",
            "--ref",
            "01234567",
        ])
        .output()
        .unwrap();
    assert_success(
        "branch create from short sha",
        &branch_create_from_short_sha,
    );
    let observed_branch = backend.last_branch_create.lock().unwrap().clone().unwrap();
    assert_eq!(observed_branch.branch, "work/from-short-sha");
    assert_eq!(observed_branch.ref_name, "01234567");

    let branch_default_denied = Command::new(env!("CARGO_BIN_EXE_agent-access"))
        .args([
            "--url",
            &base_url,
            "--no-token",
            "gitlab",
            "branch",
            "create",
            "sip/service",
            "main",
            "--ref",
            "main",
        ])
        .output()
        .unwrap();
    assert!(
        !branch_default_denied.status.success(),
        "default branch create unexpectedly succeeded: stdout={} stderr={}",
        String::from_utf8_lossy(&branch_default_denied.stdout),
        String::from_utf8_lossy(&branch_default_denied.stderr)
    );
    let denied_json: serde_json::Value =
        serde_json::from_slice(&branch_default_denied.stdout).unwrap();
    assert_eq!(denied_json["reasonCode"], "git_ref_denied");

    let branch_wildcard_denied = Command::new(env!("CARGO_BIN_EXE_agent-access"))
        .args([
            "--url",
            &base_url,
            "--no-token",
            "gitlab",
            "branch",
            "create",
            "sip/service",
            "release/next",
            "--ref",
            "main",
        ])
        .output()
        .unwrap();
    assert!(
        !branch_wildcard_denied.status.success(),
        "wildcard protected branch create unexpectedly succeeded: stdout={} stderr={}",
        String::from_utf8_lossy(&branch_wildcard_denied.stdout),
        String::from_utf8_lossy(&branch_wildcard_denied.stderr)
    );
    let denied_json: serde_json::Value =
        serde_json::from_slice(&branch_wildcard_denied.stdout).unwrap();
    assert_eq!(denied_json["reasonCode"], "git_ref_denied");

    let file_view = Command::new(env!("CARGO_BIN_EXE_agent-access"))
        .args([
            "--url",
            &base_url,
            "--no-token",
            "gitlab",
            "file",
            "view",
            "sip/service",
            "--path",
            "README.md",
            "--ref",
            "main",
        ])
        .output()
        .unwrap();
    assert_success("file view", &file_view);
    let file_view_json: serde_json::Value = serde_json::from_slice(&file_view.stdout).unwrap();
    assert_eq!(file_view_json["result"]["file"]["filePath"], "README.md");
    assert_eq!(
        file_view_json["result"]["file"]["contentBase64"],
        "cmVhZG1lIGNvbnRlbnRz"
    );

    let file_raw = Command::new(env!("CARGO_BIN_EXE_agent-access"))
        .args([
            "--url",
            &base_url,
            "--no-token",
            "gitlab",
            "file",
            "raw",
            "sip/service",
            "--path",
            "README.md",
            "--ref",
            "main",
            "--output",
            raw_output_path.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert_success("file raw download", &file_raw);
    assert_eq!(std::fs::read(&raw_output_path).unwrap(), b"readme contents");
    let raw_json: serde_json::Value = serde_json::from_slice(&file_raw.stdout).unwrap();
    assert_eq!(raw_json["result"]["path"], "README.md");
    assert_eq!(raw_json["result"]["size"], 15);
    assert_eq!(raw_json["result"]["resolvedRef"], TEST_SHA);

    let file_raw_stdout = Command::new(env!("CARGO_BIN_EXE_agent-access"))
        .args([
            "--url",
            &base_url,
            "--no-token",
            "gitlab",
            "file",
            "raw",
            "sip/service",
            "--path",
            "README.md",
            "--ref",
            "main",
            "--output",
            "-",
        ])
        .output()
        .unwrap();
    assert_success("file raw download to stdout", &file_raw_stdout);
    assert_eq!(file_raw_stdout.stdout, b"readme contents");

    let file_update_missing_last_commit = Command::new(env!("CARGO_BIN_EXE_agent-access"))
        .args([
            "--url",
            &base_url,
            "--no-token",
            "gitlab",
            "file",
            "update",
            "sip/service",
            "--path",
            "docs/existing.md",
            "--branch",
            "feature/rest",
            "--content-file",
            content_path.to_str().unwrap(),
            "--message",
            "Update docs",
        ])
        .output()
        .unwrap();
    assert!(
        !file_update_missing_last_commit.status.success(),
        "file update without lastCommitId unexpectedly succeeded: stdout={} stderr={}",
        String::from_utf8_lossy(&file_update_missing_last_commit.stdout),
        String::from_utf8_lossy(&file_update_missing_last_commit.stderr)
    );
    let update_denied_json: serde_json::Value =
        serde_json::from_slice(&file_update_missing_last_commit.stdout).unwrap();
    assert_eq!(update_denied_json["reasonCode"], "version_conflict");

    let file_update = Command::new(env!("CARGO_BIN_EXE_agent-access"))
        .args([
            "--url",
            &base_url,
            "--no-token",
            "gitlab",
            "file",
            "update",
            "sip/service",
            "--path",
            "docs/existing.md",
            "--branch",
            "feature/rest",
            "--content-file",
            content_path.to_str().unwrap(),
            "--message",
            "Update docs",
            "--last-commit-id",
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        ])
        .output()
        .unwrap();
    assert_success("file update", &file_update);
    let observed_update = backend.last_file_update.lock().unwrap().clone().unwrap();
    assert_eq!(observed_update.path, "docs/existing.md");
    assert_eq!(observed_update.decoded_content_bytes, 19);

    let file_update_from_start_branch = Command::new(env!("CARGO_BIN_EXE_agent-access"))
        .args([
            "--url",
            &base_url,
            "--no-token",
            "gitlab",
            "file",
            "update",
            "sip/service",
            "--path",
            "docs/from-main.md",
            "--branch",
            "feature/from-main",
            "--content-file",
            content_path.to_str().unwrap(),
            "--message",
            "Update docs on new branch",
            "--last-commit-id",
            "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
            "--start-branch",
            "main",
        ])
        .output()
        .unwrap();
    assert_success(
        "file update from start branch",
        &file_update_from_start_branch,
    );
    let observed_update = backend.last_file_update.lock().unwrap().clone().unwrap();
    assert_eq!(observed_update.path, "docs/from-main.md");
    assert_eq!(observed_update.branch, "feature/from-main");
    assert_eq!(observed_update.start_branch.as_deref(), Some("main"));

    let file_create = Command::new(env!("CARGO_BIN_EXE_agent-access"))
        .args([
            "--url",
            &base_url,
            "--no-token",
            "gitlab",
            "file",
            "create",
            "sip/service",
            "--path",
            "docs/new.md",
            "--branch",
            "feature/rest",
            "--content-file",
            content_path.to_str().unwrap(),
            "--message",
            "Add docs",
        ])
        .output()
        .unwrap();
    assert_success("file create", &file_create);
    let observed_create = backend.last_file_create.lock().unwrap().clone().unwrap();
    assert_eq!(observed_create.path, "docs/new.md");

    std::fs::write(
        &actions_path,
        serde_json::to_vec_pretty(&serde_json::json!([
            {
                "action": "update",
                "filePath": "docs/existing.md",
                "content": "batch content",
                "lastCommitId": "dddddddddddddddddddddddddddddddddddddddd"
            },
            {
                "action": "create",
                "filePath": "docs/commit-new.md",
                "content": "new file"
            }
        ]))
        .unwrap(),
    )
    .unwrap();
    let commit_create = Command::new(env!("CARGO_BIN_EXE_agent-access"))
        .args([
            "--url",
            &base_url,
            "--no-token",
            "gitlab",
            "commit",
            "create",
            "sip/service",
            "--branch",
            "feature/rest",
            "--message",
            "Batch docs update",
            "--actions-file",
            actions_path.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert_success("commit create", &commit_create);
    let observed_commit = backend.last_commit_create.lock().unwrap().clone().unwrap();
    assert_eq!(observed_commit.actions.len(), 2);

    let commit_create_short_start_sha = Command::new(env!("CARGO_BIN_EXE_agent-access"))
        .args([
            "--url",
            &base_url,
            "--no-token",
            "gitlab",
            "commit",
            "create",
            "sip/service",
            "--branch",
            "feature/short-sha",
            "--start-sha",
            "abc123",
            "--message",
            "Short sha",
            "--actions-file",
            actions_path.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        !commit_create_short_start_sha.status.success(),
        "commit create short startSha unexpectedly succeeded: stdout={} stderr={}",
        String::from_utf8_lossy(&commit_create_short_start_sha.stdout),
        String::from_utf8_lossy(&commit_create_short_start_sha.stderr)
    );
    let short_sha_json: serde_json::Value =
        serde_json::from_slice(&commit_create_short_start_sha.stdout).unwrap();
    assert_eq!(short_sha_json["reasonCode"], "input_invalid");

    std::fs::write(
        &actions_path,
        serde_json::to_vec_pretty(&serde_json::json!([
            {
                "action": "create",
                "filePath": "docs/from-main.md",
                "content": "conflicting file"
            }
        ]))
        .unwrap(),
    )
    .unwrap();
    let commit_create_conflict_from_start_branch = Command::new(env!("CARGO_BIN_EXE_agent-access"))
        .args([
            "--url",
            &base_url,
            "--no-token",
            "gitlab",
            "commit",
            "create",
            "sip/service",
            "--branch",
            "feature/conflict-from-main",
            "--start-branch",
            "main",
            "--message",
            "Conflicting docs update",
            "--actions-file",
            actions_path.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        !commit_create_conflict_from_start_branch.status.success(),
        "commit create conflict from start branch unexpectedly succeeded: stdout={} stderr={}",
        String::from_utf8_lossy(&commit_create_conflict_from_start_branch.stdout),
        String::from_utf8_lossy(&commit_create_conflict_from_start_branch.stderr)
    );
    let conflict_json: serde_json::Value =
        serde_json::from_slice(&commit_create_conflict_from_start_branch.stdout).unwrap();
    assert_eq!(conflict_json["reasonCode"], "version_conflict");

    std::fs::write(
        &actions_path,
        serde_json::to_vec_pretty(&serde_json::json!([
            {
                "action": "update",
                "filePath": "docs/from-main.md",
                "content": "updated from main",
                "lastCommitId": "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
            }
        ]))
        .unwrap(),
    )
    .unwrap();
    let commit_create_update_from_start_branch = Command::new(env!("CARGO_BIN_EXE_agent-access"))
        .args([
            "--url",
            &base_url,
            "--no-token",
            "gitlab",
            "commit",
            "create",
            "sip/service",
            "--branch",
            "feature/update-from-main",
            "--start-branch",
            "main",
            "--message",
            "Update docs from main",
            "--actions-file",
            actions_path.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert_success(
        "commit create update from start branch",
        &commit_create_update_from_start_branch,
    );
    let observed_commit = backend.last_commit_create.lock().unwrap().clone().unwrap();
    assert_eq!(observed_commit.branch, "feature/update-from-main");
    assert_eq!(observed_commit.start_branch.as_deref(), Some("main"));

    let many_actions = (0..26)
        .map(|index| {
            serde_json::json!({
                "action": "create",
                "filePath": format!("docs/many-{index}.md"),
                "content": "too many"
            })
        })
        .collect::<Vec<_>>();
    std::fs::write(
        &many_actions_path,
        serde_json::to_vec_pretty(&many_actions).unwrap(),
    )
    .unwrap();
    let commit_too_many_actions = Command::new(env!("CARGO_BIN_EXE_agent-access"))
        .args([
            "--url",
            &base_url,
            "--no-token",
            "gitlab",
            "commit",
            "create",
            "sip/service",
            "--branch",
            "feature/rest",
            "--message",
            "Too many docs",
            "--actions-file",
            many_actions_path.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        !commit_too_many_actions.status.success(),
        "commit create over action limit unexpectedly succeeded: stdout={} stderr={}",
        String::from_utf8_lossy(&commit_too_many_actions.stdout),
        String::from_utf8_lossy(&commit_too_many_actions.stderr)
    );
    let too_many_json: serde_json::Value =
        serde_json::from_slice(&commit_too_many_actions.stdout).unwrap();
    assert_eq!(too_many_json["reasonCode"], "input_invalid");

    let audit = broker.audit().unwrap().text();
    assert!(audit.contains("\"action\":\"file.raw.download\""));
    assert!(audit.contains("\"action\":\"commit.create\""));
    assert!(!audit.contains("file secret content"));
    assert!(!audit.contains("readme contents"));

    stop(broker).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cli_invokes_gitlab_ci_actions_against_stubbed_backend() {
    let trace_output_path = temp_path("gitlab-job-trace.txt");

    let backend = stub_backend();
    let broker = start_broker(
        &gitlab_document(),
        gitlab_service(gitlab_provider_config(2), backend.clone()),
    )
    .await;
    let base_url = broker.public_url();

    let pipeline_list = Command::new(env!("CARGO_BIN_EXE_agent-access"))
        .args([
            "--url",
            &base_url,
            "--no-token",
            "gitlab",
            "pipeline",
            "list",
            "sip/service",
            "--ref",
            "feature/rest",
            "--status",
            "success",
            "--max-results",
            "2",
        ])
        .output()
        .unwrap();
    assert_success("pipeline list", &pipeline_list);
    let pipeline_list_json: serde_json::Value =
        serde_json::from_slice(&pipeline_list.stdout).unwrap();
    assert_eq!(pipeline_list_json["result"]["pipelines"][0]["id"], 321);
    let observed_pipeline_list = backend.last_pipeline_list.lock().unwrap().clone().unwrap();
    assert_eq!(observed_pipeline_list.project_id, 42);
    assert_eq!(
        observed_pipeline_list.request.ref_name.as_deref(),
        Some("feature/rest")
    );
    assert_eq!(
        observed_pipeline_list.request.status.as_deref(),
        Some("success")
    );
    assert_eq!(observed_pipeline_list.request.max_results, 2);

    let pipeline_view = Command::new(env!("CARGO_BIN_EXE_agent-access"))
        .args([
            "--url",
            &base_url,
            "--no-token",
            "gitlab",
            "pipeline",
            "view",
            "sip/service",
            "321",
        ])
        .output()
        .unwrap();
    assert_success("pipeline view", &pipeline_view);

    let pipeline_run = Command::new(env!("CARGO_BIN_EXE_agent-access"))
        .args([
            "--url",
            &base_url,
            "--no-token",
            "gitlab",
            "pipeline",
            "run",
            "sip/service",
            "--ref",
            "feature/rest",
        ])
        .output()
        .unwrap();
    assert_success("pipeline run", &pipeline_run);
    let observed_pipeline_run = backend.last_pipeline_run.lock().unwrap().clone().unwrap();
    assert_eq!(observed_pipeline_run.ref_name, "feature/rest");

    let pipeline_run_main = Command::new(env!("CARGO_BIN_EXE_agent-access"))
        .args([
            "--url",
            &base_url,
            "--no-token",
            "gitlab",
            "pipeline",
            "run",
            "sip/service",
            "--ref",
            "main",
        ])
        .output()
        .unwrap();
    assert!(
        !pipeline_run_main.status.success(),
        "pipeline run on main unexpectedly succeeded: stdout={} stderr={}",
        String::from_utf8_lossy(&pipeline_run_main.stdout),
        String::from_utf8_lossy(&pipeline_run_main.stderr)
    );
    let pipeline_run_main_json: serde_json::Value =
        serde_json::from_slice(&pipeline_run_main.stdout).unwrap();
    assert_eq!(pipeline_run_main_json["reasonCode"], "git_ref_denied");

    let pipeline_run_release = Command::new(env!("CARGO_BIN_EXE_agent-access"))
        .args([
            "--url",
            &base_url,
            "--no-token",
            "gitlab",
            "pipeline",
            "run",
            "sip/service",
            "--ref",
            "release/next",
        ])
        .output()
        .unwrap();
    assert!(
        !pipeline_run_release.status.success(),
        "pipeline run on protected wildcard unexpectedly succeeded: stdout={} stderr={}",
        String::from_utf8_lossy(&pipeline_run_release.stdout),
        String::from_utf8_lossy(&pipeline_run_release.stderr)
    );
    let pipeline_run_release_json: serde_json::Value =
        serde_json::from_slice(&pipeline_run_release.stdout).unwrap();
    assert_eq!(pipeline_run_release_json["reasonCode"], "git_ref_denied");

    for (label, command, action) in [
        ("pipeline retry", "retry", "retry_pipeline"),
        ("pipeline cancel", "cancel", "cancel_pipeline"),
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_agent-access"))
            .args([
                "--url",
                &base_url,
                "--no-token",
                "gitlab",
                "pipeline",
                command,
                "sip/service",
                "321",
            ])
            .output()
            .unwrap();
        assert_success(label, &output);
        assert!(
            backend
                .credential_observations
                .lock()
                .unwrap()
                .iter()
                .any(|observation| observation.operation == action)
        );
    }

    let job_list = Command::new(env!("CARGO_BIN_EXE_agent-access"))
        .args([
            "--url",
            &base_url,
            "--no-token",
            "gitlab",
            "job",
            "list",
            "sip/service",
            "--pipeline-id",
            "321",
            "--scope",
            "preparing",
            "--max-results",
            "2",
        ])
        .output()
        .unwrap();
    assert_success("job list", &job_list);
    let observed_job_list = backend.last_job_list.lock().unwrap().clone().unwrap();
    assert_eq!(observed_job_list.project_id, 42);
    assert_eq!(observed_job_list.request.pipeline_id, Some(321));
    assert_eq!(
        observed_job_list.request.scope.as_deref(),
        Some("preparing")
    );
    assert_eq!(observed_job_list.request.max_results, 2);

    let job_view = Command::new(env!("CARGO_BIN_EXE_agent-access"))
        .args([
            "--url",
            &base_url,
            "--no-token",
            "gitlab",
            "job",
            "view",
            "sip/service",
            "9001",
        ])
        .output()
        .unwrap();
    assert_success("job view", &job_view);

    let job_trace = Command::new(env!("CARGO_BIN_EXE_agent-access"))
        .args([
            "--url",
            &base_url,
            "--no-token",
            "gitlab",
            "job",
            "trace",
            "sip/service",
            "9001",
            "--output",
            trace_output_path.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert_success("job trace download", &job_trace);
    assert_eq!(
        std::fs::read(&trace_output_path).unwrap(),
        b"job trace contents"
    );
    let trace_json: serde_json::Value = serde_json::from_slice(&job_trace.stdout).unwrap();
    assert_eq!(trace_json["result"]["jobId"], 9001);
    assert_eq!(trace_json["result"]["pipelineId"], 321);

    for (label, command, action) in [
        ("job retry", "retry", "retry_job"),
        ("job cancel", "cancel", "cancel_job"),
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_agent-access"))
            .args([
                "--url",
                &base_url,
                "--no-token",
                "gitlab",
                "job",
                command,
                "sip/service",
                "9001",
            ])
            .output()
            .unwrap();
        assert_success(label, &output);
        assert!(
            backend
                .credential_observations
                .lock()
                .unwrap()
                .iter()
                .any(|observation| observation.operation == action)
        );
    }

    let job_play = Command::new(env!("CARGO_BIN_EXE_agent-access"))
        .args([
            "--url",
            &base_url,
            "--no-token",
            "gitlab",
            "job",
            "play",
            "sip/service",
            "9002",
        ])
        .output()
        .unwrap();
    assert_success("job play", &job_play);

    let job_play_main = Command::new(env!("CARGO_BIN_EXE_agent-access"))
        .args([
            "--url",
            &base_url,
            "--no-token",
            "gitlab",
            "job",
            "play",
            "sip/service",
            "9003",
        ])
        .output()
        .unwrap();
    assert!(
        !job_play_main.status.success(),
        "job play on main unexpectedly succeeded: stdout={} stderr={}",
        String::from_utf8_lossy(&job_play_main.stdout),
        String::from_utf8_lossy(&job_play_main.stderr)
    );
    let job_play_main_json: serde_json::Value =
        serde_json::from_slice(&job_play_main.stdout).unwrap();
    assert_eq!(job_play_main_json["reasonCode"], "git_ref_denied");

    let job_play_mismatched_ref = Command::new(env!("CARGO_BIN_EXE_agent-access"))
        .args([
            "--url",
            &base_url,
            "--no-token",
            "gitlab",
            "job",
            "play",
            "sip/service",
            "9004",
        ])
        .output()
        .unwrap();
    assert!(
        !job_play_mismatched_ref.status.success(),
        "job play with mismatched refs unexpectedly succeeded: stdout={} stderr={}",
        String::from_utf8_lossy(&job_play_mismatched_ref.stdout),
        String::from_utf8_lossy(&job_play_mismatched_ref.stderr)
    );
    let job_play_mismatched_ref_json: serde_json::Value =
        serde_json::from_slice(&job_play_mismatched_ref.stdout).unwrap();
    assert_eq!(
        job_play_mismatched_ref_json["reasonCode"],
        "upstream_protocol_failed"
    );

    let job_play_release = Command::new(env!("CARGO_BIN_EXE_agent-access"))
        .args([
            "--url",
            &base_url,
            "--no-token",
            "gitlab",
            "job",
            "play",
            "sip/service",
            "9005",
        ])
        .output()
        .unwrap();
    assert!(
        !job_play_release.status.success(),
        "job play on protected wildcard unexpectedly succeeded: stdout={} stderr={}",
        String::from_utf8_lossy(&job_play_release.stdout),
        String::from_utf8_lossy(&job_play_release.stderr)
    );
    let job_play_release_json: serde_json::Value =
        serde_json::from_slice(&job_play_release.stdout).unwrap();
    assert_eq!(job_play_release_json["reasonCode"], "git_ref_denied");

    let audit = broker.audit().unwrap().text();
    assert!(audit.contains("\"action\":\"job.trace.download\""));
    assert!(audit.contains("\"pipeline\":\"sip/service:pipeline/321\""));
    assert!(audit.contains("\"pipeline\":\"sip/service:pipeline/322\""));
    assert!(audit.contains("\"job\":\"sip/service:job/9001\""));
    assert!(audit.contains("\"job\":\"sip/service:job/9002\""));
    assert!(audit.contains("\"denialReason\":\"project_default_branch\""));
    assert!(audit.contains("\"denialReason\":\"protected_branch_rule\""));
    assert!(!audit.contains("job trace contents"));

    stop(broker).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cli_invokes_gitlab_protected_branch_and_mr_merge_actions_against_stubbed_backend() {
    let merge_message_path = temp_path("gitlab-merge-message.md");
    let squash_message_path = temp_path("gitlab-squash-message.md");
    std::fs::write(&merge_message_path, "merge secret message").unwrap();
    std::fs::write(&squash_message_path, "squash secret message").unwrap();

    let backend = stub_backend();
    let broker = start_broker(
        &gitlab_document(),
        gitlab_service(gitlab_provider_config(2), backend.clone()),
    )
    .await;
    let base_url = broker.public_url();

    *backend.protected_branch_list_has_next_page.lock().unwrap() = true;
    let protected_branch_list_overflow = Command::new(env!("CARGO_BIN_EXE_agent-access"))
        .args([
            "--url",
            &base_url,
            "--no-token",
            "gitlab",
            "protected-branch",
            "list",
            "sip/service",
            "--max-results",
            "1",
        ])
        .output()
        .unwrap();
    assert_success(
        "protected branch list with upstream next page",
        &protected_branch_list_overflow,
    );
    let protected_branch_list_overflow_json: serde_json::Value =
        serde_json::from_slice(&protected_branch_list_overflow.stdout).unwrap();
    assert_eq!(
        protected_branch_list_overflow_json["result"]["protectedBranches"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    *backend.protected_branch_list_has_next_page.lock().unwrap() = false;

    let protected_branch_list = Command::new(env!("CARGO_BIN_EXE_agent-access"))
        .args([
            "--url",
            &base_url,
            "--no-token",
            "gitlab",
            "protected-branch",
            "list",
            "sip/service",
            "--search",
            "main",
            "--max-results",
            "1",
        ])
        .output()
        .unwrap();
    assert_success("protected branch list", &protected_branch_list);
    let protected_branch_list_json: serde_json::Value =
        serde_json::from_slice(&protected_branch_list.stdout).unwrap();
    assert_eq!(
        protected_branch_list_json["result"]["protectedBranches"][0]["name"],
        "main"
    );

    let protected_branch_view = Command::new(env!("CARGO_BIN_EXE_agent-access"))
        .args([
            "--url",
            &base_url,
            "--no-token",
            "gitlab",
            "protected-branch",
            "view",
            "sip/service",
            "release/*",
        ])
        .output()
        .unwrap();
    assert_success("protected branch view", &protected_branch_view);
    let protected_branch_view_json: serde_json::Value =
        serde_json::from_slice(&protected_branch_view.stdout).unwrap();
    assert_eq!(
        protected_branch_view_json["result"]["protectedBranch"]["name"],
        "release/*"
    );

    let protected_branch_verify = Command::new(env!("CARGO_BIN_EXE_agent-access"))
        .args([
            "--url",
            &base_url,
            "--no-token",
            "gitlab",
            "protected-branch",
            "verify",
            "sip/service",
            "--required-pattern",
            "release/next",
        ])
        .output()
        .unwrap();
    assert_success("protected branch verify", &protected_branch_verify);
    let protected_branch_verify_json: serde_json::Value =
        serde_json::from_slice(&protected_branch_verify.stdout).unwrap();
    let checks = protected_branch_verify_json["result"]["protectedBranchVerification"]["checks"]
        .as_array()
        .unwrap();
    assert!(
        checks
            .iter()
            .any(|check| check["pattern"] == "main" && check["covered"] == true)
    );
    assert!(checks.iter().any(|check| check["pattern"] == "release/next"
        && check["covered"] == true
        && check["matchedRule"] == "release/*"));

    let merge_request_missing_sha = Command::new(env!("CARGO_BIN_EXE_agent-access"))
        .args([
            "--url",
            &base_url,
            "--no-token",
            "invoke",
            "gitlab.merge_request.merge",
            "--input-json",
            r#"{"project":"sip/service","iid":5}"#,
        ])
        .output()
        .unwrap();
    assert!(
        !merge_request_missing_sha.status.success(),
        "merge request merge without sha unexpectedly succeeded: stdout={} stderr={}",
        String::from_utf8_lossy(&merge_request_missing_sha.stdout),
        String::from_utf8_lossy(&merge_request_missing_sha.stderr)
    );
    let missing_sha_json: serde_json::Value =
        serde_json::from_slice(&merge_request_missing_sha.stdout).unwrap();
    assert_eq!(missing_sha_json["reasonCode"], "input_invalid");

    let merge_request_short_sha = Command::new(env!("CARGO_BIN_EXE_agent-access"))
        .args([
            "--url",
            &base_url,
            "--no-token",
            "invoke",
            "gitlab.merge_request.merge",
            "--input-json",
            r#"{"project":"sip/service","iid":5,"sha":"abcdef1"}"#,
        ])
        .output()
        .unwrap();
    assert!(
        !merge_request_short_sha.status.success(),
        "merge request merge with short sha unexpectedly succeeded: stdout={} stderr={}",
        String::from_utf8_lossy(&merge_request_short_sha.stdout),
        String::from_utf8_lossy(&merge_request_short_sha.stderr)
    );
    let short_sha_json: serde_json::Value =
        serde_json::from_slice(&merge_request_short_sha.stdout).unwrap();
    assert_eq!(short_sha_json["reasonCode"], "input_invalid");
    assert!(
        short_sha_json["reason"]
            .as_str()
            .is_some_and(|reason| reason.contains("sha") && !reason.contains("startSha")),
        "invalid merge sha reason should mention sha, not startSha: {short_sha_json}"
    );

    *backend.merge_response_description.lock().unwrap() = Some("x".repeat(4096));
    let merge_request_merge = Command::new(env!("CARGO_BIN_EXE_agent-access"))
        .args([
            "--url",
            &base_url,
            "--no-token",
            "gitlab",
            "merge-request",
            "merge",
            "sip/service",
            "5",
            "--sha",
            TEST_SHA,
            "--squash",
            "true",
            "--should-remove-source-branch",
            "true",
            "--merge-commit-message-file",
            merge_message_path.to_str().unwrap(),
            "--squash-commit-message-file",
            squash_message_path.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert_success("merge request merge", &merge_request_merge);
    let merge_request_merge_json: serde_json::Value =
        serde_json::from_slice(&merge_request_merge.stdout).unwrap();
    assert_eq!(
        merge_request_merge_json["result"]["mergeRequest"]["state"],
        "merged"
    );
    assert!(
        merge_request_merge_json["result"]["mergeRequest"]["description"].is_null(),
        "merge responses must not return merge-request description content"
    );
    let observed_merge = backend
        .last_merge_request_merge
        .lock()
        .unwrap()
        .clone()
        .unwrap();
    assert_eq!(observed_merge.project_id, 42);
    assert_eq!(observed_merge.request.iid, 5);
    assert_eq!(observed_merge.request.sha, TEST_SHA);
    assert_eq!(observed_merge.request.squash, Some(true));
    assert_eq!(
        observed_merge.request.should_remove_source_branch,
        Some(true)
    );
    assert_eq!(
        observed_merge.request.merge_commit_message.as_deref(),
        Some("merge secret message")
    );
    assert_eq!(
        observed_merge.request.squash_commit_message.as_deref(),
        Some("squash secret message")
    );

    let merge_request_stale_sha = Command::new(env!("CARGO_BIN_EXE_agent-access"))
        .args([
            "--url",
            &base_url,
            "--no-token",
            "gitlab",
            "merge-request",
            "merge",
            "sip/service",
            "5",
            "--sha",
            "1111111111111111111111111111111111111111",
        ])
        .output()
        .unwrap();
    assert!(
        !merge_request_stale_sha.status.success(),
        "merge request merge with stale sha unexpectedly succeeded: stdout={} stderr={}",
        String::from_utf8_lossy(&merge_request_stale_sha.stdout),
        String::from_utf8_lossy(&merge_request_stale_sha.stderr)
    );
    let stale_sha_json: serde_json::Value =
        serde_json::from_slice(&merge_request_stale_sha.stdout).unwrap();
    assert_eq!(stale_sha_json["reasonCode"], "version_conflict");

    *backend.merge_conflict_after_preflight.lock().unwrap() = true;
    let merge_request_preflight_race = Command::new(env!("CARGO_BIN_EXE_agent-access"))
        .args([
            "--url",
            &base_url,
            "--no-token",
            "gitlab",
            "merge-request",
            "merge",
            "sip/service",
            "5",
            "--sha",
            TEST_SHA,
        ])
        .output()
        .unwrap();
    assert!(
        !merge_request_preflight_race.status.success(),
        "merge request merge with upstream conflict unexpectedly succeeded: stdout={} stderr={}",
        String::from_utf8_lossy(&merge_request_preflight_race.stdout),
        String::from_utf8_lossy(&merge_request_preflight_race.stderr)
    );
    let preflight_race_json: serde_json::Value =
        serde_json::from_slice(&merge_request_preflight_race.stdout).unwrap();
    assert_eq!(preflight_race_json["reasonCode"], "version_conflict");

    let audit = broker.audit().unwrap().text();
    assert!(audit.contains("\"action\":\"protected_branch.verify\""));
    assert!(audit.contains("\"action\":\"merge_request.merge\""));
    assert!(audit.contains("\"mergeRequest\":\"sip/service!5\""));
    assert!(!audit.contains("merge secret message"));
    assert!(!audit.contains("squash secret message"));
    assert!(!audit.contains(&"x".repeat(4096)));

    stop(broker).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cli_invokes_gitlab_collaboration_write_actions_against_stubbed_backend() {
    let issue_description_path = temp_path("gitlab-issue-description.md");
    let issue_note_path = temp_path("gitlab-issue-note.md");
    let issue_note_update_path = temp_path("gitlab-issue-note-update.md");
    let merge_request_description_path = temp_path("gitlab-mr-description.md");
    let merge_request_note_path = temp_path("gitlab-mr-note.md");
    let merge_request_note_update_path = temp_path("gitlab-mr-note-update.md");
    let merge_request_discussion_path = temp_path("gitlab-mr-discussion.md");
    let merge_request_discussion_note_update_path =
        temp_path("gitlab-mr-discussion-note-update.md");
    std::fs::write(&issue_description_path, "issue secret description").unwrap();
    std::fs::write(&issue_note_path, "issue secret note").unwrap();
    std::fs::write(&issue_note_update_path, "issue updated @alice #12 <raw>").unwrap();
    std::fs::write(&merge_request_description_path, "mr secret description").unwrap();
    std::fs::write(&merge_request_note_path, "mr secret note").unwrap();
    std::fs::write(
        &merge_request_note_update_path,
        "mr updated @bob !17 https://example.test",
    )
    .unwrap();
    std::fs::write(&merge_request_discussion_path, "mr secret discussion").unwrap();
    std::fs::write(
        &merge_request_discussion_note_update_path,
        "discussion updated [label](https://example.test)",
    )
    .unwrap();

    let backend = stub_backend();
    let document = gitlab_document();
    let broker = start_broker(
        &document,
        gitlab_service(gitlab_provider_config(2), backend.clone()),
    )
    .await;
    let base_url = broker.public_url();

    let issue_create = Command::new(env!("CARGO_BIN_EXE_agent-access"))
        .args([
            "--url",
            &base_url,
            "--no-token",
            "gitlab",
            "issue",
            "create",
            "sip/service",
            "--title",
            "Created issue",
            "--content-file",
            issue_description_path.to_str().unwrap(),
            "--content-format",
            "markdown",
            "--label",
            "bug",
            "--assignee-id",
            "101",
            "--confidential",
            "true",
        ])
        .output()
        .unwrap();
    assert_success("issue create", &issue_create);
    let issue_create_json: serde_json::Value =
        serde_json::from_slice(&issue_create.stdout).unwrap();
    assert_eq!(issue_create_json["result"]["issue"]["iid"], 8);
    let observed = backend.last_issue_create.lock().unwrap().clone().unwrap();
    assert_eq!(observed.project_id, 42);
    assert_eq!(observed.request.title, "Created issue");
    assert_eq!(
        observed.request.description.as_deref(),
        Some("issue secret description")
    );
    assert_eq!(observed.request.assignee_ids, vec![101]);
    assert_eq!(observed.request.confidential, Some(true));
    assert_credential_observations(
        &backend,
        &[
            ("project", "gitlab-lookup-token"),
            ("project", "gitlab-lookup-token"),
            ("create_issue", "gitlab-service-token"),
        ],
    );
    backend.credential_observations.lock().unwrap().clear();

    let issue_update = Command::new(env!("CARGO_BIN_EXE_agent-access"))
        .args([
            "--url",
            &base_url,
            "--no-token",
            "gitlab",
            "issue",
            "update",
            "sip/service",
            "7",
            "--state-event",
            "close",
            "--add-label",
            "triaged",
            "--content",
            "issue update literal @alice #12 <tag>",
            "--content-format",
            "plain_text",
        ])
        .output()
        .unwrap();
    assert_success("issue update", &issue_update);
    let observed = backend.last_issue_update.lock().unwrap().clone().unwrap();
    assert_eq!(observed.project_id, 42);
    assert_eq!(observed.request.iid, 7);
    assert_eq!(observed.request.state_event.as_deref(), Some("close"));
    assert_eq!(observed.request.add_labels, vec!["triaged".to_string()]);
    assert_eq!(
        observed.request.description.as_deref(),
        Some("issue update literal \\@alice \\#12 \\<tag\\>")
    );

    let issue_comment = Command::new(env!("CARGO_BIN_EXE_agent-access"))
        .args([
            "--url",
            &base_url,
            "--no-token",
            "gitlab",
            "issue",
            "comment",
            "sip/service",
            "7",
            "--content-file",
            issue_note_path.to_str().unwrap(),
            "--content-format",
            "markdown",
            "--confidential",
            "false",
        ])
        .output()
        .unwrap();
    assert_success("issue comment", &issue_comment);
    let observed = backend.last_issue_note_add.lock().unwrap().clone().unwrap();
    assert_eq!(observed.project_id, 42);
    assert_eq!(observed.request.iid, 7);
    assert_eq!(observed.request.body, "issue secret note");
    assert_eq!(observed.request.confidential, Some(false));

    let issue_update_comment = Command::new(env!("CARGO_BIN_EXE_agent-access"))
        .args([
            "--url",
            &base_url,
            "--no-token",
            "gitlab",
            "issue",
            "update-comment",
            "sip/service",
            "7",
            "701",
            "--content-file",
            issue_note_update_path.to_str().unwrap(),
            "--content-format",
            "plain_text",
        ])
        .output()
        .unwrap();
    assert_success("issue update-comment", &issue_update_comment);
    let observed = backend
        .last_issue_note_update
        .lock()
        .unwrap()
        .clone()
        .unwrap();
    assert_eq!(observed.project_id, 42);
    assert_eq!(observed.request.iid, 7);
    assert_eq!(observed.request.note_id, 701);
    assert_eq!(
        observed.request.body,
        "issue updated \\@alice \\#12 \\<raw\\>"
    );

    backend.credential_observations.lock().unwrap().clear();
    let issue_view_comment = Command::new(env!("CARGO_BIN_EXE_agent-access"))
        .args([
            "--url",
            &base_url,
            "--no-token",
            "gitlab",
            "issue",
            "view-comment",
            "sip/service",
            "7",
            "701",
        ])
        .output()
        .unwrap();
    assert_success("issue view-comment", &issue_view_comment);
    let issue_view_comment: serde_json::Value =
        serde_json::from_slice(&issue_view_comment.stdout).unwrap();
    assert_eq!(issue_view_comment["result"]["note"]["id"], 701);

    backend.credential_observations.lock().unwrap().clear();
    let issue_delete_comment = Command::new(env!("CARGO_BIN_EXE_agent-access"))
        .args([
            "--url",
            &base_url,
            "--no-token",
            "gitlab",
            "issue",
            "delete-comment",
            "sip/service",
            "7",
            "701",
        ])
        .output()
        .unwrap();
    assert_success("issue delete-comment", &issue_delete_comment);
    let issue_delete_json: serde_json::Value =
        serde_json::from_slice(&issue_delete_comment.stdout).unwrap();
    assert_eq!(issue_delete_json["result"]["deleted"], true);
    let observed = backend
        .last_issue_note_delete
        .lock()
        .unwrap()
        .clone()
        .unwrap();
    assert_eq!(observed.project_id, 42);
    assert_eq!(observed.request.iid, 7);
    assert_eq!(observed.request.note_id, 701);
    assert_credential_observations(
        &backend,
        &[
            ("project", "gitlab-lookup-token"),
            ("project", "gitlab-lookup-token"),
            ("issue", "gitlab-lookup-token"),
            ("issue_note", "gitlab-service-token"),
            ("delete_issue_note", "gitlab-service-token"),
        ],
    );
    backend.credential_observations.lock().unwrap().clear();

    let issue_comments = Command::new(env!("CARGO_BIN_EXE_agent-access"))
        .args([
            "--url",
            &base_url,
            "--no-token",
            "gitlab",
            "issue",
            "list-comments",
            "sip/service",
            "7",
            "--max-results",
            "100",
            "--projection",
            "summary",
        ])
        .output()
        .unwrap();
    assert_success("issue list-comments", &issue_comments);
    let issue_comments_json: serde_json::Value =
        serde_json::from_slice(&issue_comments.stdout).unwrap();
    assert_eq!(issue_comments_json["result"]["count"], 1);
    assert_eq!(issue_comments_json["result"]["projection"], "summary");
    assert!(
        issue_comments_json["result"]["notes"][0]
            .get("body")
            .is_none()
    );
    assert_eq!(issue_comments_json["result"]["maxResults"], 2);
    assert_eq!(issue_comments_json["result"]["isLast"], false);
    assert!(
        issue_comments_json["result"]["nextPageToken"]
            .as_str()
            .is_some()
    );
    assert_eq!(
        issue_comments_json["result"]["notes"][0]["authorUserId"],
        314
    );
    let observed = backend
        .last_issue_note_list
        .lock()
        .unwrap()
        .clone()
        .unwrap();
    assert_eq!(observed.project_id, 42);
    assert_eq!(observed.request.max_results, 2);
    let issue_comments_second_page = Command::new(env!("CARGO_BIN_EXE_agent-access"))
        .args([
            "--url",
            &base_url,
            "--no-token",
            "gitlab",
            "issue",
            "list-comments",
            "sip/service",
            "7",
            "--max-results",
            "100",
            "--page-token",
            issue_comments_json["result"]["nextPageToken"]
                .as_str()
                .unwrap(),
            "--projection",
            "summary",
        ])
        .output()
        .unwrap();
    assert_success(
        "issue list-comments second page",
        &issue_comments_second_page,
    );
    let observed = backend
        .last_issue_note_list
        .lock()
        .unwrap()
        .clone()
        .unwrap();
    assert_eq!(observed.request.page, 2);

    backend.credential_observations.lock().unwrap().clear();
    let merge_request_create = Command::new(env!("CARGO_BIN_EXE_agent-access"))
        .args([
            "--url",
            &base_url,
            "--no-token",
            "gitlab",
            "merge-request",
            "create",
            "sip/service",
            "--source-branch",
            "feature/rest",
            "--target-branch",
            "main",
            "--title",
            "Created MR",
            "--content-file",
            merge_request_description_path.to_str().unwrap(),
            "--content-format",
            "markdown",
            "--label",
            "docs",
            "--assignee-id",
            "201",
            "--reviewer-id",
            "202",
            "--remove-source-branch",
            "true",
            "--squash",
            "false",
            "--draft",
            "true",
        ])
        .output()
        .unwrap();
    assert_success("merge request create", &merge_request_create);
    let observed = backend
        .last_merge_request_create
        .lock()
        .unwrap()
        .clone()
        .unwrap();
    assert_eq!(observed.project_id, 42);
    assert_eq!(observed.request.source_branch, "feature/rest");
    assert_eq!(observed.request.target_branch, "main");
    assert_eq!(observed.request.title, "Created MR");
    assert_eq!(
        observed.request.description.as_deref(),
        Some("mr secret description")
    );
    assert_eq!(observed.request.assignee_ids, vec![201]);
    assert_eq!(observed.request.reviewer_ids, vec![202]);
    assert_eq!(observed.request.draft, Some(true));
    assert_credential_observations(
        &backend,
        &[
            ("project", "gitlab-lookup-token"),
            ("project", "gitlab-lookup-token"),
            ("branch", "gitlab-lookup-token"),
            ("branch", "gitlab-lookup-token"),
            ("create_merge_request", "gitlab-service-token"),
        ],
    );
    backend.credential_observations.lock().unwrap().clear();

    let merge_request_update = Command::new(env!("CARGO_BIN_EXE_agent-access"))
        .args([
            "--url",
            &base_url,
            "--no-token",
            "gitlab",
            "merge-request",
            "update",
            "sip/service",
            "5",
            "--target-branch",
            "main",
            "--remove-label",
            "draft",
            "--squash",
            "true",
            "--content",
            "merge update literal @bob !17 https://example.test",
            "--content-format",
            "plain_text",
        ])
        .output()
        .unwrap();
    assert_success("merge request update", &merge_request_update);
    let observed = backend
        .last_merge_request_update
        .lock()
        .unwrap()
        .clone()
        .unwrap();
    assert_eq!(observed.project_id, 42);
    assert_eq!(observed.request.iid, 5);
    assert_eq!(observed.request.remove_labels, vec!["draft".to_string()]);
    assert_eq!(observed.request.squash, Some(true));
    assert_eq!(
        observed.request.description.as_deref(),
        Some("merge update literal \\@bob \\!17 https\\:\\/\\/example\\.test")
    );

    let merge_request_comment = Command::new(env!("CARGO_BIN_EXE_agent-access"))
        .args([
            "--url",
            &base_url,
            "--no-token",
            "gitlab",
            "merge-request",
            "comment",
            "sip/service",
            "5",
            "--content-file",
            merge_request_note_path.to_str().unwrap(),
            "--content-format",
            "markdown",
        ])
        .output()
        .unwrap();
    assert_success("merge request comment", &merge_request_comment);
    let observed = backend
        .last_merge_request_note_add
        .lock()
        .unwrap()
        .clone()
        .unwrap();
    assert_eq!(observed.project_id, 42);
    assert_eq!(observed.request.body, "mr secret note");

    let merge_request_update_comment = Command::new(env!("CARGO_BIN_EXE_agent-access"))
        .args([
            "--url",
            &base_url,
            "--no-token",
            "gitlab",
            "merge-request",
            "update-comment",
            "sip/service",
            "5",
            "501",
            "--content-file",
            merge_request_note_update_path.to_str().unwrap(),
            "--content-format",
            "plain_text",
        ])
        .output()
        .unwrap();
    assert_success(
        "merge request update-comment",
        &merge_request_update_comment,
    );
    let observed = backend
        .last_merge_request_note_update
        .lock()
        .unwrap()
        .clone()
        .unwrap();
    assert_eq!(observed.project_id, 42);
    assert_eq!(observed.request.iid, 5);
    assert_eq!(observed.request.note_id, 501);
    assert_eq!(
        observed.request.body,
        "mr updated \\@bob \\!17 https\\:\\/\\/example\\.test"
    );

    let merge_request_view_comment = Command::new(env!("CARGO_BIN_EXE_agent-access"))
        .args([
            "--url",
            &base_url,
            "--no-token",
            "gitlab",
            "merge-request",
            "view-comment",
            "sip/service",
            "5",
            "501",
        ])
        .output()
        .unwrap();
    assert_success("merge request view-comment", &merge_request_view_comment);
    let merge_request_view_comment: serde_json::Value =
        serde_json::from_slice(&merge_request_view_comment.stdout).unwrap();
    assert_eq!(merge_request_view_comment["result"]["note"]["id"], 501);

    let merge_request_delete_comment = Command::new(env!("CARGO_BIN_EXE_agent-access"))
        .args([
            "--url",
            &base_url,
            "--no-token",
            "gitlab",
            "merge-request",
            "delete-comment",
            "sip/service",
            "5",
            "501",
        ])
        .output()
        .unwrap();
    assert_success(
        "merge request delete-comment",
        &merge_request_delete_comment,
    );
    let observed = backend
        .last_merge_request_note_delete
        .lock()
        .unwrap()
        .clone()
        .unwrap();
    assert_eq!(observed.project_id, 42);
    assert_eq!(observed.request.iid, 5);
    assert_eq!(observed.request.note_id, 501);

    let merge_request_comments = Command::new(env!("CARGO_BIN_EXE_agent-access"))
        .args([
            "--url",
            &base_url,
            "--no-token",
            "gitlab",
            "merge-request",
            "list-comments",
            "sip/service",
            "5",
            "--max-results",
            "100",
            "--projection",
            "summary",
        ])
        .output()
        .unwrap();
    assert_success("merge request list-comments", &merge_request_comments);
    let merge_request_comments_json: serde_json::Value =
        serde_json::from_slice(&merge_request_comments.stdout).unwrap();
    assert_eq!(merge_request_comments_json["result"]["count"], 1);
    assert_eq!(
        merge_request_comments_json["result"]["projection"],
        "summary"
    );
    assert!(
        merge_request_comments_json["result"]["notes"][0]
            .get("body")
            .is_none()
    );
    assert_eq!(merge_request_comments_json["result"]["maxResults"], 2);
    assert_eq!(merge_request_comments_json["result"]["isLast"], false);
    assert!(
        merge_request_comments_json["result"]["nextPageToken"]
            .as_str()
            .is_some()
    );
    assert_eq!(
        merge_request_comments_json["result"]["notes"][0]["authorUserId"],
        314
    );
    let observed = backend
        .last_merge_request_note_list
        .lock()
        .unwrap()
        .clone()
        .unwrap();
    assert_eq!(observed.project_id, 42);
    assert_eq!(observed.request.max_results, 2);
    let merge_request_comments_second_page = Command::new(env!("CARGO_BIN_EXE_agent-access"))
        .args([
            "--url",
            &base_url,
            "--no-token",
            "gitlab",
            "merge-request",
            "list-comments",
            "sip/service",
            "5",
            "--max-results",
            "100",
            "--page-token",
            merge_request_comments_json["result"]["nextPageToken"]
                .as_str()
                .unwrap(),
            "--projection",
            "summary",
        ])
        .output()
        .unwrap();
    assert_success(
        "merge request list-comments second page",
        &merge_request_comments_second_page,
    );
    let observed = backend
        .last_merge_request_note_list
        .lock()
        .unwrap()
        .clone()
        .unwrap();
    assert_eq!(observed.request.page, 2);

    let discussion = Command::new(env!("CARGO_BIN_EXE_agent-access"))
        .args([
            "--url",
            &base_url,
            "--no-token",
            "gitlab",
            "merge-request",
            "discussion",
            "sip/service",
            "5",
            "--content-file",
            merge_request_discussion_path.to_str().unwrap(),
            "--content-format",
            "markdown",
        ])
        .output()
        .unwrap();
    assert_success("merge request discussion", &discussion);
    let observed = backend
        .last_merge_request_discussion_add
        .lock()
        .unwrap()
        .clone()
        .unwrap();
    assert_eq!(observed.project_id, 42);
    assert_eq!(observed.request.body, "mr secret discussion");

    let discussion_note_update = Command::new(env!("CARGO_BIN_EXE_agent-access"))
        .args([
            "--url",
            &base_url,
            "--no-token",
            "gitlab",
            "merge-request",
            "update-discussion-note",
            "sip/service",
            "5",
            "discussion-1",
            "900",
            "--content-file",
            merge_request_discussion_note_update_path.to_str().unwrap(),
            "--content-format",
            "plain_text",
        ])
        .output()
        .unwrap();
    assert_success(
        "merge request update-discussion-note",
        &discussion_note_update,
    );
    let observed = backend
        .last_merge_request_discussion_note_update
        .lock()
        .unwrap()
        .clone()
        .unwrap();
    assert_eq!(observed.project_id, 42);
    assert_eq!(observed.request.iid, 5);
    assert_eq!(observed.request.discussion_id, "discussion-1");
    assert_eq!(observed.request.note_id, 900);
    assert_eq!(
        observed.request.body,
        "discussion updated \\[label\\]\\(https\\:\\/\\/example\\.test\\)"
    );

    backend.credential_observations.lock().unwrap().clear();
    let discussion_note_delete = Command::new(env!("CARGO_BIN_EXE_agent-access"))
        .args([
            "--url",
            &base_url,
            "--no-token",
            "gitlab",
            "merge-request",
            "delete-discussion-note",
            "sip/service",
            "5",
            "discussion-1",
            "900",
        ])
        .output()
        .unwrap();
    assert_success(
        "merge request delete-discussion-note",
        &discussion_note_delete,
    );
    let observed = backend
        .last_merge_request_discussion_note_delete
        .lock()
        .unwrap()
        .clone()
        .unwrap();
    assert_eq!(observed.project_id, 42);
    assert_eq!(observed.request.iid, 5);
    assert_eq!(observed.request.discussion_id, "discussion-1");
    assert_eq!(observed.request.note_id, 900);
    assert_credential_observations(
        &backend,
        &[
            ("project", "gitlab-lookup-token"),
            ("project", "gitlab-lookup-token"),
            ("merge_request", "gitlab-lookup-token"),
            ("merge_request_discussion", "gitlab-service-token"),
            (
                "delete_merge_request_discussion_note",
                "gitlab-service-token",
            ),
        ],
    );
    backend.credential_observations.lock().unwrap().clear();

    let discussion_resolve = Command::new(env!("CARGO_BIN_EXE_agent-access"))
        .args([
            "--url",
            &base_url,
            "--no-token",
            "gitlab",
            "merge-request",
            "resolve-discussion",
            "sip/service",
            "5",
            "discussion-1",
        ])
        .output()
        .unwrap();
    assert_success("merge request resolve-discussion", &discussion_resolve);
    let observed = backend
        .last_merge_request_discussion_state_change
        .lock()
        .unwrap()
        .clone()
        .unwrap();
    assert_eq!(observed.project_id, 42);
    assert_eq!(observed.request.iid, 5);
    assert_eq!(observed.request.discussion_id, "discussion-1");
    assert_eq!(
        observed.request.change,
        GitlabDiscussionStateChange::Resolve
    );

    let discussion_reopen = Command::new(env!("CARGO_BIN_EXE_agent-access"))
        .args([
            "--url",
            &base_url,
            "--no-token",
            "gitlab",
            "merge-request",
            "reopen-discussion",
            "sip/service",
            "5",
            "discussion-1",
        ])
        .output()
        .unwrap();
    assert_success("merge request reopen-discussion", &discussion_reopen);
    let observed = backend
        .last_merge_request_discussion_state_change
        .lock()
        .unwrap()
        .clone()
        .unwrap();
    assert_eq!(observed.project_id, 42);
    assert_eq!(observed.request.change, GitlabDiscussionStateChange::Reopen);

    let discussions = Command::new(env!("CARGO_BIN_EXE_agent-access"))
        .args([
            "--url",
            &base_url,
            "--no-token",
            "gitlab",
            "merge-request",
            "list-discussions",
            "sip/service",
            "5",
            "--max-results",
            "100",
            "--projection",
            "summary",
        ])
        .output()
        .unwrap();
    assert_success("merge request list-discussions", &discussions);
    let discussions_json: serde_json::Value = serde_json::from_slice(&discussions.stdout).unwrap();
    assert_eq!(discussions_json["result"]["count"], 1);
    assert_eq!(discussions_json["result"]["projection"], "summary");
    assert_eq!(discussions_json["result"]["discussions"][0]["noteCount"], 1);
    assert!(
        discussions_json["result"]["discussions"][0]["notes"][0]
            .get("body")
            .is_none()
    );
    assert_eq!(discussions_json["result"]["maxResults"], 2);
    assert_eq!(discussions_json["result"]["isLast"], false);
    let next_page_token = discussions_json["result"]["nextPageToken"]
        .as_str()
        .unwrap();
    let observed = backend
        .last_merge_request_discussion_list
        .lock()
        .unwrap()
        .clone()
        .unwrap();
    assert_eq!(observed.project_id, 42);
    assert_eq!(observed.request.max_results, 2);

    let discussions_second_page = Command::new(env!("CARGO_BIN_EXE_agent-access"))
        .args([
            "--url",
            &base_url,
            "--no-token",
            "gitlab",
            "merge-request",
            "list-discussions",
            "sip/service",
            "5",
            "--max-results",
            "100",
            "--page-token",
            next_page_token,
            "--projection",
            "summary",
        ])
        .output()
        .unwrap();
    assert_success(
        "merge request list-discussions second page",
        &discussions_second_page,
    );
    let discussions_second_page_json: serde_json::Value =
        serde_json::from_slice(&discussions_second_page.stdout).unwrap();
    assert_eq!(discussions_second_page_json["result"]["isLast"], true);
    assert!(discussions_second_page_json["result"]["nextPageToken"].is_null());
    let observed = backend
        .last_merge_request_discussion_list
        .lock()
        .unwrap()
        .clone()
        .unwrap();
    assert_eq!(observed.request.page, 2);

    let audit = broker.audit().unwrap().text();
    assert!(audit.contains("\"action\":\"issue.create\""));
    assert!(audit.contains("\"action\":\"issue.note.add\""));
    assert!(audit.contains("\"action\":\"issue.note.update\""));
    assert!(audit.contains("\"action\":\"issue.note.delete\""));
    assert!(audit.contains("\"action\":\"merge_request.create\""));
    assert!(audit.contains("\"action\":\"merge_request.note.update\""));
    assert!(audit.contains("\"action\":\"merge_request.note.delete\""));
    assert!(audit.contains("\"action\":\"merge_request.discussion.add\""));
    assert!(audit.contains("\"action\":\"merge_request.discussion.note.update\""));
    assert!(audit.contains("\"action\":\"merge_request.discussion.note.delete\""));
    assert!(audit.contains("\"action\":\"merge_request.discussion.resolve\""));
    assert!(audit.contains("\"action\":\"merge_request.discussion.reopen\""));
    assert!(audit.contains("\"requestBody\""));
    assert!(audit.contains("\"textByteCounts\""));
    assert!(audit.contains("\"jsonFields\""));
    assert!(audit.contains("\"contentFormat\":\"markdown\""));
    assert!(audit.contains("\"contentFormat\":\"plain_text\""));
    assert!(!audit.contains("issue secret description"));
    assert!(!audit.contains("issue secret note"));
    assert!(!audit.contains("issue updated @alice #12 <raw>"));
    assert!(!audit.contains("issue preflight secret body"));
    assert!(!audit.contains("issue update literal @alice #12 <tag>"));
    assert!(!audit.contains("mr secret description"));
    assert!(!audit.contains("mr secret note"));
    assert!(!audit.contains("mr updated @bob !17 https://example.test"));
    assert!(!audit.contains("merge request preflight secret body"));
    assert!(!audit.contains("merge update literal @bob !17 https://example.test"));
    assert!(!audit.contains("mr secret discussion"));
    assert!(!audit.contains("discussion updated [label](https://example.test)"));
    assert!(!audit.contains("discussion preflight secret body"));

    stop(broker).await;
}

#[test]
fn cli_gitlab_normalized_content_flags_are_strict() {
    let content_path = temp_path("gitlab-content-source-conflict.md");
    std::fs::write(&content_path, "file content").unwrap();

    let missing_format = Command::new(env!("CARGO_BIN_EXE_agent-access"))
        .args([
            "--url",
            "http://127.0.0.1:9",
            "--no-token",
            "gitlab",
            "issue",
            "update",
            "sip/service",
            "7",
            "--content",
            "content without a format",
        ])
        .output()
        .unwrap();
    assert_eq!(missing_format.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&missing_format.stderr).contains("required"));

    let format_without_content = Command::new(env!("CARGO_BIN_EXE_agent-access"))
        .args([
            "--url",
            "http://127.0.0.1:9",
            "--no-token",
            "gitlab",
            "issue",
            "update",
            "sip/service",
            "7",
            "--content-format",
            "markdown",
        ])
        .output()
        .unwrap();
    assert_eq!(format_without_content.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&format_without_content.stderr).contains("required"));

    let source_conflict = Command::new(env!("CARGO_BIN_EXE_agent-access"))
        .args([
            "--url",
            "http://127.0.0.1:9",
            "--no-token",
            "gitlab",
            "issue",
            "comment",
            "sip/service",
            "7",
            "--content",
            "inline content",
            "--content-file",
            content_path.to_str().unwrap(),
            "--content-format",
            "markdown",
        ])
        .output()
        .unwrap();
    assert_eq!(source_conflict.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&source_conflict.stderr).contains("cannot be used with"));

    for removed_flag in ["--description-file", "--body-file"] {
        let removed = Command::new(env!("CARGO_BIN_EXE_agent-access"))
            .args([
                "--url",
                "http://127.0.0.1:9",
                "--no-token",
                "gitlab",
                "issue",
                "update",
                "sip/service",
                "7",
                removed_flag,
                content_path.to_str().unwrap(),
            ])
            .output()
            .unwrap();
        assert!(
            !removed.status.success(),
            "removed flag {removed_flag} survived"
        );
        assert!(String::from_utf8_lossy(&removed.stderr).contains("unexpected argument"));
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cli_invokes_gitlab_per_user_collaboration_writes_against_stubbed_backend() {
    let issue_note_path = temp_path("gitlab-per-user-issue-note.md");
    let issue_note_update_path = temp_path("gitlab-per-user-issue-note-update.md");
    let merge_request_description_path = temp_path("gitlab-per-user-mr-description.md");
    let merge_request_note_update_path = temp_path("gitlab-per-user-mr-note-update.md");
    let discussion_note_update_path = temp_path("gitlab-per-user-discussion-note-update.md");
    std::fs::write(&issue_note_path, "per-user issue secret note").unwrap();
    std::fs::write(
        &issue_note_update_path,
        "per-user issue updated secret note",
    )
    .unwrap();
    std::fs::write(
        &merge_request_description_path,
        "per-user mr secret description",
    )
    .unwrap();
    std::fs::write(
        &merge_request_note_update_path,
        "per-user mr updated secret note",
    )
    .unwrap();
    std::fs::write(
        &discussion_note_update_path,
        "per-user discussion updated secret note",
    )
    .unwrap();

    let backend = stub_backend();
    let broker = start_broker(
        &gitlab_per_user_document(),
        gitlab_service(gitlab_provider_config(2), backend.clone()),
    )
    .await;
    let base_url = broker.public_url();

    let issue_comment = Command::new(env!("CARGO_BIN_EXE_agent-access"))
        .args([
            "--url",
            &base_url,
            "--token-value",
            "agent-token",
            "--identity-header",
            "X-Agent-Access-Identity-Token",
            "--identity-scheme",
            "raw",
            "gitlab",
            "issue",
            "comment",
            "sip/service",
            "7",
            "--content-file",
            issue_note_path.to_str().unwrap(),
            "--content-format",
            "markdown",
        ])
        .output()
        .unwrap();
    assert_success("per-user issue comment", &issue_comment);
    assert_credential_observations(
        &backend,
        &[
            ("project", "gitlab-per-user-token"),
            ("project", "gitlab-per-user-token"),
            ("issue", "gitlab-per-user-token"),
            ("create_issue_note", "gitlab-per-user-token"),
        ],
    );

    backend.credential_observations.lock().unwrap().clear();
    let issue_update_comment = Command::new(env!("CARGO_BIN_EXE_agent-access"))
        .args([
            "--url",
            &base_url,
            "--token-value",
            "agent-token",
            "--identity-header",
            "X-Agent-Access-Identity-Token",
            "--identity-scheme",
            "raw",
            "gitlab",
            "issue",
            "update-comment",
            "sip/service",
            "7",
            "701",
            "--content-file",
            issue_note_update_path.to_str().unwrap(),
            "--content-format",
            "plain_text",
        ])
        .output()
        .unwrap();
    assert_success("per-user issue update-comment", &issue_update_comment);
    assert_credential_observations(
        &backend,
        &[
            ("project", "gitlab-per-user-token"),
            ("project", "gitlab-per-user-token"),
            ("issue", "gitlab-per-user-token"),
            ("update_issue_note", "gitlab-per-user-token"),
        ],
    );

    backend.credential_observations.lock().unwrap().clear();
    let issue_delete_comment = Command::new(env!("CARGO_BIN_EXE_agent-access"))
        .args([
            "--url",
            &base_url,
            "--token-value",
            "agent-token",
            "--identity-header",
            "X-Agent-Access-Identity-Token",
            "--identity-scheme",
            "raw",
            "gitlab",
            "issue",
            "delete-comment",
            "sip/service",
            "7",
            "701",
        ])
        .output()
        .unwrap();
    assert_success("per-user issue delete-comment", &issue_delete_comment);
    assert_credential_observations(
        &backend,
        &[
            ("project", "gitlab-per-user-token"),
            ("project", "gitlab-per-user-token"),
            ("issue", "gitlab-per-user-token"),
            ("issue_note", "gitlab-per-user-token"),
            ("delete_issue_note", "gitlab-per-user-token"),
        ],
    );

    backend.credential_observations.lock().unwrap().clear();
    let merge_request_create = Command::new(env!("CARGO_BIN_EXE_agent-access"))
        .args([
            "--url",
            &base_url,
            "--token-value",
            "agent-token",
            "--identity-header",
            "X-Agent-Access-Identity-Token",
            "--identity-scheme",
            "raw",
            "gitlab",
            "merge-request",
            "create",
            "sip/service",
            "--source-branch",
            "feature/rest",
            "--target-branch",
            "main",
            "--title",
            "Per-user MR",
            "--content-file",
            merge_request_description_path.to_str().unwrap(),
            "--content-format",
            "markdown",
        ])
        .output()
        .unwrap();
    assert_success("per-user merge request create", &merge_request_create);
    assert_credential_observations(
        &backend,
        &[
            ("project", "gitlab-per-user-token"),
            ("project", "gitlab-per-user-token"),
            ("branch", "gitlab-per-user-token"),
            ("branch", "gitlab-per-user-token"),
            ("create_merge_request", "gitlab-per-user-token"),
        ],
    );

    backend.credential_observations.lock().unwrap().clear();
    let merge_request_update_comment = Command::new(env!("CARGO_BIN_EXE_agent-access"))
        .args([
            "--url",
            &base_url,
            "--token-value",
            "agent-token",
            "--identity-header",
            "X-Agent-Access-Identity-Token",
            "--identity-scheme",
            "raw",
            "gitlab",
            "merge-request",
            "update-comment",
            "sip/service",
            "5",
            "501",
            "--content-file",
            merge_request_note_update_path.to_str().unwrap(),
            "--content-format",
            "plain_text",
        ])
        .output()
        .unwrap();
    assert_success(
        "per-user merge request update-comment",
        &merge_request_update_comment,
    );
    assert_credential_observations(
        &backend,
        &[
            ("project", "gitlab-per-user-token"),
            ("project", "gitlab-per-user-token"),
            ("merge_request", "gitlab-per-user-token"),
            ("update_merge_request_note", "gitlab-per-user-token"),
        ],
    );

    backend.credential_observations.lock().unwrap().clear();
    let merge_request_delete_comment = Command::new(env!("CARGO_BIN_EXE_agent-access"))
        .args([
            "--url",
            &base_url,
            "--token-value",
            "agent-token",
            "--identity-header",
            "X-Agent-Access-Identity-Token",
            "--identity-scheme",
            "raw",
            "gitlab",
            "merge-request",
            "delete-comment",
            "sip/service",
            "5",
            "501",
        ])
        .output()
        .unwrap();
    assert_success(
        "per-user merge request delete-comment",
        &merge_request_delete_comment,
    );
    assert_credential_observations(
        &backend,
        &[
            ("project", "gitlab-per-user-token"),
            ("project", "gitlab-per-user-token"),
            ("merge_request", "gitlab-per-user-token"),
            ("merge_request_note", "gitlab-per-user-token"),
            ("delete_merge_request_note", "gitlab-per-user-token"),
        ],
    );

    backend.credential_observations.lock().unwrap().clear();
    let discussion_note_update = Command::new(env!("CARGO_BIN_EXE_agent-access"))
        .args([
            "--url",
            &base_url,
            "--token-value",
            "agent-token",
            "--identity-header",
            "X-Agent-Access-Identity-Token",
            "--identity-scheme",
            "raw",
            "gitlab",
            "merge-request",
            "update-discussion-note",
            "sip/service",
            "5",
            "discussion-1",
            "900",
            "--content-file",
            discussion_note_update_path.to_str().unwrap(),
            "--content-format",
            "plain_text",
        ])
        .output()
        .unwrap();
    assert_success(
        "per-user merge request update-discussion-note",
        &discussion_note_update,
    );
    assert_credential_observations(
        &backend,
        &[
            ("project", "gitlab-per-user-token"),
            ("project", "gitlab-per-user-token"),
            ("merge_request", "gitlab-per-user-token"),
            ("merge_request_discussion", "gitlab-per-user-token"),
            (
                "update_merge_request_discussion_note",
                "gitlab-per-user-token",
            ),
        ],
    );

    backend.credential_observations.lock().unwrap().clear();
    let discussion_note_delete = Command::new(env!("CARGO_BIN_EXE_agent-access"))
        .args([
            "--url",
            &base_url,
            "--token-value",
            "agent-token",
            "--identity-header",
            "X-Agent-Access-Identity-Token",
            "--identity-scheme",
            "raw",
            "gitlab",
            "merge-request",
            "delete-discussion-note",
            "sip/service",
            "5",
            "discussion-1",
            "900",
        ])
        .output()
        .unwrap();
    assert_success(
        "per-user merge request delete-discussion-note",
        &discussion_note_delete,
    );
    assert_credential_observations(
        &backend,
        &[
            ("project", "gitlab-per-user-token"),
            ("project", "gitlab-per-user-token"),
            ("merge_request", "gitlab-per-user-token"),
            ("merge_request_discussion", "gitlab-per-user-token"),
            (
                "delete_merge_request_discussion_note",
                "gitlab-per-user-token",
            ),
        ],
    );

    backend.credential_observations.lock().unwrap().clear();
    let discussion_resolve = Command::new(env!("CARGO_BIN_EXE_agent-access"))
        .args([
            "--url",
            &base_url,
            "--token-value",
            "agent-token",
            "--identity-header",
            "X-Agent-Access-Identity-Token",
            "--identity-scheme",
            "raw",
            "gitlab",
            "merge-request",
            "resolve-discussion",
            "sip/service",
            "5",
            "discussion-1",
        ])
        .output()
        .unwrap();
    assert_success(
        "per-user merge request resolve-discussion",
        &discussion_resolve,
    );
    assert_credential_observations(
        &backend,
        &[
            ("project", "gitlab-per-user-token"),
            ("project", "gitlab-per-user-token"),
            ("merge_request", "gitlab-per-user-token"),
            (
                "set_merge_request_discussion_resolved",
                "gitlab-per-user-token",
            ),
        ],
    );

    backend.credential_observations.lock().unwrap().clear();
    let discussion_reopen = Command::new(env!("CARGO_BIN_EXE_agent-access"))
        .args([
            "--url",
            &base_url,
            "--token-value",
            "agent-token",
            "--identity-header",
            "X-Agent-Access-Identity-Token",
            "--identity-scheme",
            "raw",
            "gitlab",
            "merge-request",
            "reopen-discussion",
            "sip/service",
            "5",
            "discussion-1",
        ])
        .output()
        .unwrap();
    assert_success(
        "per-user merge request reopen-discussion",
        &discussion_reopen,
    );
    assert_credential_observations(
        &backend,
        &[
            ("project", "gitlab-per-user-token"),
            ("project", "gitlab-per-user-token"),
            ("merge_request", "gitlab-per-user-token"),
            (
                "set_merge_request_discussion_resolved",
                "gitlab-per-user-token",
            ),
        ],
    );

    backend.credential_observations.lock().unwrap().clear();
    let reviewers = Command::new(env!("CARGO_BIN_EXE_agent-access"))
        .args([
            "--url",
            &base_url,
            "--token-value",
            "agent-token",
            "--identity-header",
            "X-Agent-Access-Identity-Token",
            "--identity-scheme",
            "raw",
            "gitlab",
            "merge-request",
            "list-reviewers",
            "sip/service",
            "5",
            "--max-results",
            "2",
        ])
        .output()
        .unwrap();
    assert_success("per-user merge request list-reviewers", &reviewers);
    let reviewer_json: serde_json::Value = serde_json::from_slice(&reviewers.stdout).unwrap();
    assert_eq!(
        reviewer_json["result"]["reviewers"][0]["state"],
        "requested_changes"
    );
    {
        let reviewer_observations = backend.credential_observations.lock().unwrap();
        assert!(
            reviewer_observations
                .iter()
                .any(|observation| observation.operation == "merge_request_reviewers")
        );
        assert!(reviewer_observations.iter().all(|observation| {
            observation.credential == bearer_credential("gitlab-per-user-token")
        }));
    }

    let audit = broker.audit().unwrap().text();
    assert!(audit.contains("\"credentialMode\":\"per_user\""));
    assert!(!audit.contains("agent-token"));
    assert!(!audit.contains("gitlab-per-user-token"));
    assert!(!audit.contains("per-user issue secret note"));
    assert!(!audit.contains("per-user issue updated secret note"));
    assert!(!audit.contains("per-user mr secret description"));
    assert!(!audit.contains("per-user mr updated secret note"));
    assert!(!audit.contains("per-user discussion updated secret note"));

    stop(broker).await;
}

const TEST_BASE_SHA: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const TEST_START_SHA: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const TEST_SHA: &str = "0123456789abcdef0123456789abcdef01234567";
const TEST_PATCH_ID_SHA: &str = "cccccccccccccccccccccccccccccccccccccccc";

#[derive(Clone)]
struct ObservedIssueSearch {
    project_id: u64,
    request: GitlabIssueSearchRequest,
}

#[derive(Clone)]
struct ObservedIssueCreate {
    project_id: u64,
    request: GitlabIssueCreateRequest,
}

#[derive(Clone)]
struct ObservedIssueUpdate {
    project_id: u64,
    request: GitlabIssueUpdateRequest,
}

#[derive(Clone)]
struct ObservedIssueNoteList {
    project_id: u64,
    request: GitlabNoteListRequest,
}

#[derive(Clone)]
struct ObservedIssueNoteAdd {
    project_id: u64,
    request: GitlabIssueNoteCreateRequest,
}

#[derive(Clone)]
struct ObservedIssueNoteUpdate {
    project_id: u64,
    request: GitlabNoteUpdateRequest,
}

#[derive(Clone)]
struct ObservedIssueNoteDelete {
    project_id: u64,
    request: GitlabNoteDeleteRequest,
}

#[derive(Clone)]
struct ObservedMergeRequestSearch {
    project_id: u64,
    request: GitlabMergeRequestSearchRequest,
}

#[derive(Clone)]
struct ObservedMergeRequestCreate {
    project_id: u64,
    request: GitlabMergeRequestCreateRequest,
}

#[derive(Clone)]
struct ObservedMergeRequestUpdate {
    project_id: u64,
    request: GitlabMergeRequestUpdateRequest,
}

#[derive(Clone)]
struct ObservedMergeRequestNoteList {
    project_id: u64,
    request: GitlabNoteListRequest,
}

#[derive(Clone)]
struct ObservedMergeRequestNoteAdd {
    project_id: u64,
    request: GitlabNoteCreateRequest,
}

#[derive(Clone)]
struct ObservedMergeRequestNoteUpdate {
    project_id: u64,
    request: GitlabNoteUpdateRequest,
}

#[derive(Clone)]
struct ObservedMergeRequestNoteDelete {
    project_id: u64,
    request: GitlabNoteDeleteRequest,
}

#[derive(Clone)]
struct ObservedMergeRequestDiscussionList {
    project_id: u64,
    request: GitlabDiscussionListRequest,
}

#[derive(Clone)]
struct ObservedMergeRequestList {
    project_id: u64,
    request: GitlabMergeRequestListRequest,
}

#[derive(Clone)]
struct ObservedMergeRequestObject {
    project_id: u64,
    request: GitlabMergeRequestObjectRequest,
}

#[derive(Clone)]
struct ObservedMergeRequestDiscussionAdd {
    project_id: u64,
    request: GitlabNoteCreateRequest,
}

#[derive(Clone)]
struct ObservedInlineDiscussionAdd {
    project_id: u64,
    request: GitlabPositionedDiscussionCreateRequest,
}

#[derive(Clone)]
struct ObservedDiscussionReplyAdd {
    project_id: u64,
    request: GitlabDiscussionReplyRequest,
}

#[derive(Clone)]
struct ObservedMergeRequestDiscussionNoteUpdate {
    project_id: u64,
    request: GitlabDiscussionNoteUpdateRequest,
}

#[derive(Clone)]
struct ObservedMergeRequestDiscussionNoteDelete {
    project_id: u64,
    request: GitlabDiscussionNoteDeleteRequest,
}

#[derive(Clone)]
struct ObservedMergeRequestDiscussionStateChange {
    project_id: u64,
    request: GitlabDiscussionStateChangeRequest,
}

#[derive(Clone)]
struct ObservedMergeRequestMerge {
    project_id: u64,
    request: GitlabMergeRequestMergeRequest,
}

#[derive(Clone)]
struct ObservedBranchList {
    project_id: u64,
    request: GitlabBranchListRequest,
}

#[derive(Clone)]
struct ObservedCommitList {
    project_id: u64,
    request: GitlabCommitListRequest,
}

#[derive(Clone)]
struct ObservedPipelineList {
    project_id: u64,
    request: GitlabPipelineListRequest,
}

#[derive(Clone)]
struct ObservedJobList {
    project_id: u64,
    request: GitlabJobListRequest,
}

/// One credential the stub backend received. GitLab credentials are bearer
/// tokens and compare by material, so tests check which one arrived without
/// reading it.
#[derive(Clone)]
struct CredentialObservation {
    operation: String,
    credential: agent_access_provider::ExecutionCredential,
}

struct StubGitlabBackend {
    projects: BTreeMap<String, GitlabProject>,
    uploaded_projects: Mutex<Vec<(u64, agent_access_provider::BrokerBodyPart)>>,
    branches: Mutex<BTreeMap<String, GitlabBranch>>,
    files: Mutex<BTreeMap<(String, String), GitlabFile>>,
    issue_note_body: Mutex<Option<String>>,
    discussion_body: Mutex<Option<String>>,
    published_discussions: Mutex<Vec<GitlabDiscussion>>,
    discussion_pagination_mode: Mutex<String>,
    draft_notes: Mutex<Vec<GitlabDraftNote>>,
    next_draft_note_id: Mutex<u64>,
    current_user_id: Mutex<u64>,
    current_user_username: Mutex<String>,
    reviewer_state: Mutex<String>,
    reviewer_fixture_mode: Mutex<String>,
    gitlab_version_value: Mutex<String>,
    fail_gitlab_version: Mutex<bool>,
    diff_version_state: Mutex<String>,
    approval_diff_match_page: Mutex<u32>,
    approval_patch_id_sha: Mutex<Option<String>>,
    merge_request_prepared_at: Mutex<Option<String>>,
    merge_request_detailed_status: Mutex<Option<String>>,
    approval_readback_mode: Mutex<String>,
    approval_mutation_mode: Mutex<String>,
    actor_formally_approved: Mutex<bool>,
    aggregate_approval_override: Mutex<Option<bool>>,
    fork_lookup_source_project_id: Mutex<Option<u64>>,
    fork_execution_source_project_id: Mutex<Option<u64>>,
    fork_source_drift_after_first_read: Mutex<bool>,
    merge_request_read_count: Mutex<u64>,
    suggestions_applied: Mutex<bool>,
    retain_unapplied_suggestions: Mutex<bool>,
    discussion_proof_mismatch: Mutex<bool>,
    malformed_inline_response: Mutex<bool>,
    fail_discussion_reply_write: Mutex<bool>,
    malformed_draft_update_readback: Mutex<bool>,
    drop_draft_position_on_update: Mutex<bool>,
    retain_deleted_draft: Mutex<bool>,
    retain_published_draft: Mutex<bool>,
    fail_bulk_publish_without_apply: Mutex<bool>,
    fail_bulk_publish_after_apply: Mutex<bool>,
    skip_reviewer_state_update: Mutex<bool>,
    malformed_review_summary: Mutex<bool>,
    protected_branches: Mutex<Vec<GitlabProtectedBranch>>,
    protected_branch_list_has_next_page: Mutex<bool>,
    merge_response_description: Mutex<Option<String>>,
    merge_conflict_after_preflight: Mutex<bool>,
    credential_observations: Mutex<Vec<CredentialObservation>>,
    last_issue_search: Mutex<Option<ObservedIssueSearch>>,
    last_issue_create: Mutex<Option<ObservedIssueCreate>>,
    last_issue_update: Mutex<Option<ObservedIssueUpdate>>,
    last_issue_note_list: Mutex<Option<ObservedIssueNoteList>>,
    last_issue_note_add: Mutex<Option<ObservedIssueNoteAdd>>,
    last_issue_note_update: Mutex<Option<ObservedIssueNoteUpdate>>,
    last_issue_note_delete: Mutex<Option<ObservedIssueNoteDelete>>,
    last_merge_request_search: Mutex<Option<ObservedMergeRequestSearch>>,
    last_merge_request_create: Mutex<Option<ObservedMergeRequestCreate>>,
    last_merge_request_update: Mutex<Option<ObservedMergeRequestUpdate>>,
    last_merge_request_note_list: Mutex<Option<ObservedMergeRequestNoteList>>,
    last_merge_request_note_add: Mutex<Option<ObservedMergeRequestNoteAdd>>,
    last_merge_request_note_update: Mutex<Option<ObservedMergeRequestNoteUpdate>>,
    last_merge_request_note_delete: Mutex<Option<ObservedMergeRequestNoteDelete>>,
    last_merge_request_discussion_list: Mutex<Option<ObservedMergeRequestDiscussionList>>,
    last_merge_request_reviewer_list: Mutex<Option<ObservedMergeRequestList>>,
    last_merge_request_commit_list: Mutex<Option<ObservedMergeRequestList>>,
    last_merge_request_pipeline_list: Mutex<Option<ObservedMergeRequestList>>,
    last_merge_request_diff_list: Mutex<Option<ObservedMergeRequestList>>,
    last_merge_request_diff_version_list: Mutex<Option<ObservedMergeRequestList>>,
    last_merge_request_diff_version_view: Mutex<Option<ObservedMergeRequestObject>>,
    last_merge_request_discussion_add: Mutex<Option<ObservedMergeRequestDiscussionAdd>>,
    last_inline_discussion_add: Mutex<Option<ObservedInlineDiscussionAdd>>,
    last_discussion_reply_add: Mutex<Option<ObservedDiscussionReplyAdd>>,
    last_draft_note_create: Mutex<Option<GitlabDraftNoteCreateRequest>>,
    last_draft_note_update: Mutex<Option<GitlabDraftNoteUpdateRequest>>,
    last_draft_bulk_publish: Mutex<Option<GitlabDraftBulkPublishRequest>>,
    last_review_summary: Mutex<Option<GitlabReviewSummaryNoteRequest>>,
    last_approval_mutation: Mutex<Option<GitlabApprovalMutationRequest>>,
    last_suggestion_apply: Mutex<Option<GitlabSuggestionApplyRequest>>,
    last_merge_request_discussion_note_update:
        Mutex<Option<ObservedMergeRequestDiscussionNoteUpdate>>,
    last_merge_request_discussion_note_delete:
        Mutex<Option<ObservedMergeRequestDiscussionNoteDelete>>,
    last_merge_request_discussion_state_change:
        Mutex<Option<ObservedMergeRequestDiscussionStateChange>>,
    last_merge_request_merge: Mutex<Option<ObservedMergeRequestMerge>>,
    last_branch_list: Mutex<Option<ObservedBranchList>>,
    last_branch_create: Mutex<Option<GitlabBranchCreateRequest>>,
    last_file_create: Mutex<Option<GitlabFileWriteRequest>>,
    last_file_update: Mutex<Option<GitlabFileWriteRequest>>,
    last_file_delete: Mutex<Option<GitlabFileDeleteRequest>>,
    last_commit_list: Mutex<Option<ObservedCommitList>>,
    last_commit_create: Mutex<Option<GitlabCommitCreateRequest>>,
    last_pipeline_list: Mutex<Option<ObservedPipelineList>>,
    last_pipeline_run: Mutex<Option<GitlabPipelineRunRequest>>,
    last_job_list: Mutex<Option<ObservedJobList>>,
    webhooks: Mutex<BTreeMap<u64, GitlabWebhook>>,
    next_webhook_id: Mutex<u64>,
    last_webhook_write: Mutex<Option<GitlabWebhookWriteRequest>>,
    last_webhook_header: Mutex<Option<GitlabWebhookCustomHeaderRequest>>,
    /// Raw diffs served in turn before the fixed diff: each a live stream of
    /// these chunks with no declared size, which ignores the byte cap.
    streamed_raw_diffs: Mutex<VecDeque<Vec<&'static [u8]>>>,
}

/// A live body yielding its chunks one by one.
struct ChunkStream(VecDeque<bytes::Bytes>);

impl agent_access_provider::deps::futures_core::Stream for ChunkStream {
    type Item = Result<bytes::Bytes, agent_access_provider::ProviderStreamError>;

    fn poll_next(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        Poll::Ready(self.0.pop_front().map(Ok))
    }
}

impl StubGitlabBackend {
    fn record_credential(
        &self,
        operation: &str,
        credential: &agent_access_gitlab::GitlabCredential,
    ) {
        self.credential_observations
            .lock()
            .unwrap()
            .push(CredentialObservation {
                operation: operation.to_string(),
                credential: credential
                    .static_credential()
                    .expect("the GitLab smoke presents static tokens")
                    .clone(),
            });
    }
}

#[async_trait]
impl GitlabBackend for StubGitlabBackend {
    async fn upload_project(
        &self,
        project_id: u64,
        mut upload: agent_access_provider::BrokerBodyPart,
        credential: &agent_access_gitlab::GitlabCredential,
    ) -> Result<GitlabBackendResponse<GitlabProjectUpload>, GitlabBackendError> {
        self.record_credential("upload_project", credential);
        if let Some(path) = upload.temp_file_path() {
            upload.bytes = std::fs::read(path).unwrap();
        }
        upload.temp_file = None;
        self.uploaded_projects
            .lock()
            .unwrap()
            .push((project_id, upload));
        Ok(GitlabBackendResponse {
            value: GitlabProjectUpload {
                id: Some(101),
                alt: "session".to_string(),
                url: "/uploads/0123456789abcdef0123456789abcdef/session.html".to_string(),
                full_path: "/-/project/42/uploads/0123456789abcdef0123456789abcdef/session.html"
                    .to_string(),
                markdown: "[session](/uploads/0123456789abcdef0123456789abcdef/session.html)"
                    .to_string(),
            },
            status: 201,
            duration_ms: 2,
        })
    }

    async fn current_user(
        &self,
        credential: &agent_access_gitlab::GitlabCredential,
    ) -> Result<GitlabBackendResponse<GitlabUser>, GitlabBackendError> {
        self.record_credential("current_user", credential);
        Ok(GitlabBackendResponse {
            value: GitlabUser {
                id: *self.current_user_id.lock().unwrap(),
                username: self.current_user_username.lock().unwrap().clone(),
                name: Some("Carol".to_string()),
            },
            status: 200,
            duration_ms: 1,
        })
    }

    async fn project(
        &self,
        project: &str,
        credential: &agent_access_gitlab::GitlabCredential,
    ) -> Result<GitlabBackendResponse<GitlabProject>, GitlabBackendError> {
        self.record_credential("project", credential);
        let project = self
            .projects
            .get(project)
            .cloned()
            .ok_or(GitlabBackendError::NotFound)?;
        Ok(GitlabBackendResponse {
            value: project,
            status: 200,
            duration_ms: 2,
        })
    }

    async fn webhooks(
        &self,
        _project_id: u64,
        request: GitlabWebhookListRequest,
        _credential: &agent_access_gitlab::GitlabCredential,
    ) -> Result<GitlabBackendResponse<GitlabPage<GitlabWebhook>>, GitlabBackendError> {
        let items = self
            .webhooks
            .lock()
            .unwrap()
            .values()
            .take(request.max_results as usize)
            .cloned()
            .collect();
        Ok(GitlabBackendResponse {
            value: GitlabPage {
                items,
                next_page: None,
            },
            status: 200,
            duration_ms: 1,
        })
    }

    async fn webhook(
        &self,
        _project_id: u64,
        webhook_id: u64,
        _credential: &agent_access_gitlab::GitlabCredential,
    ) -> Result<GitlabBackendResponse<GitlabWebhook>, GitlabBackendError> {
        let value = self
            .webhooks
            .lock()
            .unwrap()
            .get(&webhook_id)
            .cloned()
            .ok_or(GitlabBackendError::NotFound)?;
        Ok(GitlabBackendResponse {
            value,
            status: 200,
            duration_ms: 1,
        })
    }

    async fn create_webhook(
        &self,
        _project_id: u64,
        request: GitlabWebhookWriteRequest,
        _credential: &agent_access_gitlab::GitlabCredential,
    ) -> Result<GitlabBackendResponse<GitlabWebhook>, GitlabBackendError> {
        *self.last_webhook_write.lock().unwrap() = Some(request.clone());
        let mut next_id = self.next_webhook_id.lock().unwrap();
        let mut hook = webhook_fixture(*next_id);
        *next_id += 1;
        apply_webhook_write(&mut hook, &request);
        self.webhooks.lock().unwrap().insert(hook.id, hook.clone());
        Ok(GitlabBackendResponse {
            value: hook,
            status: 201,
            duration_ms: 1,
        })
    }

    async fn update_webhook(
        &self,
        _project_id: u64,
        webhook_id: u64,
        request: GitlabWebhookWriteRequest,
        _credential: &agent_access_gitlab::GitlabCredential,
    ) -> Result<GitlabBackendResponse<GitlabWebhook>, GitlabBackendError> {
        *self.last_webhook_write.lock().unwrap() = Some(request.clone());
        let mut hooks = self.webhooks.lock().unwrap();
        let hook = hooks
            .get_mut(&webhook_id)
            .ok_or(GitlabBackendError::NotFound)?;
        apply_webhook_write(hook, &request);
        Ok(GitlabBackendResponse {
            value: hook.clone(),
            status: 200,
            duration_ms: 1,
        })
    }

    async fn delete_webhook(
        &self,
        _project_id: u64,
        webhook_id: u64,
        _credential: &agent_access_gitlab::GitlabCredential,
    ) -> Result<GitlabBackendResponse<()>, GitlabBackendError> {
        self.webhooks.lock().unwrap().remove(&webhook_id);
        Ok(GitlabBackendResponse {
            value: (),
            status: 204,
            duration_ms: 1,
        })
    }

    async fn test_webhook(
        &self,
        _project_id: u64,
        _webhook_id: u64,
        _trigger: &str,
        _credential: &agent_access_gitlab::GitlabCredential,
    ) -> Result<GitlabBackendResponse<GitlabWebhookDeliveryAttempt>, GitlabBackendError> {
        Ok(GitlabBackendResponse {
            value: GitlabWebhookDeliveryAttempt {
                message: Some("201 Created".to_string()),
                response_status: Some(201),
            },
            status: 201,
            duration_ms: 1,
        })
    }

    async fn webhook_events(
        &self,
        _project_id: u64,
        _request: GitlabWebhookEventListRequest,
        _redacted_header_names: &BTreeSet<String>,
        _field_byte_cap: u64,
        _credential: &agent_access_gitlab::GitlabCredential,
    ) -> Result<GitlabBackendResponse<GitlabPage<GitlabWebhookDeliveryEvent>>, GitlabBackendError>
    {
        Ok(GitlabBackendResponse {
            value: GitlabPage {
                items: vec![GitlabWebhookDeliveryEvent {
                    id: 9001,
                    trigger: Some("push_hooks".to_string()),
                    created_at: Some("2026-08-30T12:01:00Z".to_string()),
                    execution_duration: Some(0.1),
                    response_status: Some("201".to_string()),
                    request_headers: BTreeMap::new(),
                    request_data: Some(serde_json::json!({"object_kind":"push"})),
                    request_data_truncated: false,
                    response_headers: BTreeMap::new(),
                    response_body: Some("ok".to_string()),
                    response_body_truncated: false,
                }],
                next_page: None,
            },
            status: 200,
            duration_ms: 1,
        })
    }

    async fn resend_webhook_event(
        &self,
        _project_id: u64,
        _webhook_id: u64,
        _webhook_event_id: u64,
        _credential: &agent_access_gitlab::GitlabCredential,
    ) -> Result<GitlabBackendResponse<GitlabWebhookDeliveryAttempt>, GitlabBackendError> {
        Ok(GitlabBackendResponse {
            value: GitlabWebhookDeliveryAttempt {
                message: None,
                response_status: Some(202),
            },
            status: 202,
            duration_ms: 1,
        })
    }

    async fn set_webhook_custom_header(
        &self,
        _project_id: u64,
        request: GitlabWebhookCustomHeaderRequest,
        _credential: &agent_access_gitlab::GitlabCredential,
    ) -> Result<GitlabBackendResponse<()>, GitlabBackendError> {
        *self.last_webhook_header.lock().unwrap() = Some(request.clone());
        if let Some(hook) = self.webhooks.lock().unwrap().get_mut(&request.webhook_id) {
            let headers = hook.custom_headers.get_or_insert_default();
            if !headers.iter().any(|header| header.key == request.key) {
                headers.push(GitlabWebhookNamedSecret {
                    key: request.key.clone(),
                });
            }
        }
        Ok(GitlabBackendResponse {
            value: (),
            status: 204,
            duration_ms: 1,
        })
    }

    async fn delete_webhook_custom_header(
        &self,
        _project_id: u64,
        request: GitlabWebhookCustomHeaderRequest,
        _credential: &agent_access_gitlab::GitlabCredential,
    ) -> Result<GitlabBackendResponse<()>, GitlabBackendError> {
        *self.last_webhook_header.lock().unwrap() = Some(request.clone());
        if let Some(hook) = self.webhooks.lock().unwrap().get_mut(&request.webhook_id)
            && let Some(headers) = hook.custom_headers.as_mut()
        {
            headers.retain(|header| header.key != request.key);
        }
        Ok(GitlabBackendResponse {
            value: (),
            status: 204,
            duration_ms: 1,
        })
    }

    async fn issue(
        &self,
        project_id: u64,
        iid: u64,
        credential: &agent_access_gitlab::GitlabCredential,
    ) -> Result<GitlabBackendResponse<GitlabIssue>, GitlabBackendError> {
        self.record_credential("issue", credential);
        if project_id != 42 || iid != 7 {
            return Err(GitlabBackendError::NotFound);
        }
        Ok(GitlabBackendResponse {
            value: GitlabIssue {
                id: Some(700),
                iid,
                project_id,
                title: Some("visible issue".to_string()),
                description: Some("issue context".to_string()),
                state: Some("opened".to_string()),
                created_at: Some("2026-06-01T10:00:00.000Z".to_string()),
                updated_at: Some("2026-06-02T11:00:00.000Z".to_string()),
                author: Some(gitlab_user(1, "alice", "Alice")),
                assignees: Some(vec![gitlab_user(2, "bob", "Bob")]),
                labels: Some(vec!["bug".to_string(), "triaged".to_string()]),
                milestone: Some(gitlab_milestone("M1")),
                web_url: Some("https://gitlab.example.com/sip/service/-/issues/7".to_string()),
                project: None,
            },
            status: 200,
            duration_ms: 3,
        })
    }

    async fn issues(
        &self,
        project_id: u64,
        request: GitlabIssueSearchRequest,
        credential: &agent_access_gitlab::GitlabCredential,
    ) -> Result<GitlabBackendResponse<GitlabPage<GitlabIssue>>, GitlabBackendError> {
        self.record_credential("issues", credential);
        let next_page = (request.page == 1).then_some(2);
        *self.last_issue_search.lock().unwrap() = Some(ObservedIssueSearch {
            project_id,
            request,
        });
        Ok(GitlabBackendResponse {
            value: GitlabPage {
                items: vec![GitlabIssue {
                    id: Some(700),
                    iid: 7,
                    project_id,
                    title: Some("visible issue".to_string()),
                    description: Some("issue context".to_string()),
                    state: Some("opened".to_string()),
                    created_at: Some("2026-06-01T10:00:00.000Z".to_string()),
                    updated_at: Some("2026-06-02T11:00:00.000Z".to_string()),
                    author: Some(gitlab_user(1, "alice", "Alice")),
                    assignees: Some(vec![gitlab_user(2, "bob", "Bob")]),
                    labels: Some(vec!["bug".to_string(), "triaged".to_string()]),
                    milestone: Some(gitlab_milestone("M1")),
                    web_url: Some("https://gitlab.example.com/sip/service/-/issues/7".to_string()),
                    project: None,
                }],
                next_page,
            },
            status: 200,
            duration_ms: 4,
        })
    }

    async fn create_issue(
        &self,
        project_id: u64,
        request: GitlabIssueCreateRequest,
        credential: &agent_access_gitlab::GitlabCredential,
    ) -> Result<GitlabBackendResponse<GitlabIssue>, GitlabBackendError> {
        self.record_credential("create_issue", credential);
        *self.last_issue_create.lock().unwrap() = Some(ObservedIssueCreate {
            project_id,
            request,
        });
        Ok(GitlabBackendResponse {
            value: issue(project_id, 8, "created issue"),
            status: 201,
            duration_ms: 11,
        })
    }

    async fn update_issue(
        &self,
        project_id: u64,
        request: GitlabIssueUpdateRequest,
        credential: &agent_access_gitlab::GitlabCredential,
    ) -> Result<GitlabBackendResponse<GitlabIssue>, GitlabBackendError> {
        self.record_credential("update_issue", credential);
        *self.last_issue_update.lock().unwrap() = Some(ObservedIssueUpdate {
            project_id,
            request,
        });
        Ok(GitlabBackendResponse {
            value: issue(project_id, 7, "updated issue"),
            status: 200,
            duration_ms: 12,
        })
    }

    async fn issue_notes(
        &self,
        project_id: u64,
        request: GitlabNoteListRequest,
        credential: &agent_access_gitlab::GitlabCredential,
    ) -> Result<GitlabBackendResponse<GitlabPage<GitlabNote>>, GitlabBackendError> {
        self.record_credential("issue_notes", credential);
        let next_page = (request.page == 1).then_some(2);
        *self.last_issue_note_list.lock().unwrap() = Some(ObservedIssueNoteList {
            project_id,
            request: request.clone(),
        });
        Ok(GitlabBackendResponse {
            value: GitlabPage {
                items: vec![issue_note(
                    701,
                    self.issue_note_body
                        .lock()
                        .unwrap()
                        .as_deref()
                        .unwrap_or("existing issue note"),
                    request.iid,
                )],
                next_page,
            },
            status: 200,
            duration_ms: 13,
        })
    }

    async fn create_issue_note(
        &self,
        project_id: u64,
        request: GitlabIssueNoteCreateRequest,
        credential: &agent_access_gitlab::GitlabCredential,
    ) -> Result<GitlabBackendResponse<GitlabNote>, GitlabBackendError> {
        self.record_credential("create_issue_note", credential);
        *self.last_issue_note_add.lock().unwrap() = Some(ObservedIssueNoteAdd {
            project_id,
            request: request.clone(),
        });
        Ok(GitlabBackendResponse {
            value: issue_note(702, "created issue note", request.iid),
            status: 201,
            duration_ms: 14,
        })
    }

    async fn issue_note(
        &self,
        project_id: u64,
        request: GitlabNoteDeleteRequest,
        credential: &agent_access_gitlab::GitlabCredential,
    ) -> Result<GitlabBackendResponse<GitlabNote>, GitlabBackendError> {
        self.record_credential("issue_note", credential);
        if project_id != 42 || request.iid != 7 || request.note_id != 701 {
            return Err(GitlabBackendError::NotFound);
        }
        Ok(GitlabBackendResponse {
            value: issue_note(request.note_id, "issue preflight secret body", request.iid),
            status: 200,
            duration_ms: 21,
        })
    }

    async fn update_issue_note(
        &self,
        project_id: u64,
        request: GitlabNoteUpdateRequest,
        credential: &agent_access_gitlab::GitlabCredential,
    ) -> Result<GitlabBackendResponse<GitlabNote>, GitlabBackendError> {
        self.record_credential("update_issue_note", credential);
        *self.last_issue_note_update.lock().unwrap() = Some(ObservedIssueNoteUpdate {
            project_id,
            request: request.clone(),
        });
        Ok(GitlabBackendResponse {
            value: issue_note(request.note_id, "updated issue note", request.iid),
            status: 200,
            duration_ms: 22,
        })
    }

    async fn delete_issue_note(
        &self,
        project_id: u64,
        request: GitlabNoteDeleteRequest,
        credential: &agent_access_gitlab::GitlabCredential,
    ) -> Result<GitlabBackendResponse<()>, GitlabBackendError> {
        self.record_credential("delete_issue_note", credential);
        *self.last_issue_note_delete.lock().unwrap() = Some(ObservedIssueNoteDelete {
            project_id,
            request,
        });
        Ok(GitlabBackendResponse {
            value: (),
            status: 204,
            duration_ms: 23,
        })
    }

    async fn merge_request(
        &self,
        project_id: u64,
        iid: u64,
        credential: &agent_access_gitlab::GitlabCredential,
    ) -> Result<GitlabBackendResponse<GitlabMergeRequest>, GitlabBackendError> {
        self.record_credential("merge_request", credential);
        if project_id != 42 || iid != 5 {
            return Err(GitlabBackendError::NotFound);
        }
        let mut read_count = self.merge_request_read_count.lock().unwrap();
        *read_count += 1;
        let source_project_id = if *self.fork_source_drift_after_first_read.lock().unwrap() {
            if *read_count == 1 {
                *self.fork_lookup_source_project_id.lock().unwrap()
            } else {
                *self.fork_execution_source_project_id.lock().unwrap()
            }
        } else if credential.static_credential() == Some(&bearer_credential("gitlab-lookup-token"))
        {
            *self.fork_lookup_source_project_id.lock().unwrap()
        } else {
            *self.fork_execution_source_project_id.lock().unwrap()
        }
        .unwrap_or(42);
        Ok(GitlabBackendResponse {
            value: GitlabMergeRequest {
                id: Some(500),
                iid,
                project_id,
                title: Some("visible merge request".to_string()),
                description: Some("merge request context".to_string()),
                state: Some("opened".to_string()),
                source_branch: Some("feature/rest".to_string()),
                target_branch: Some("main".to_string()),
                sha: Some(TEST_SHA.to_string()),
                merge_status: Some("can_be_merged".to_string()),
                detailed_merge_status: self.merge_request_detailed_status.lock().unwrap().clone(),
                merge_commit_sha: None,
                squash_commit_sha: None,
                source_project_id: Some(source_project_id),
                target_project_id: Some(42),
                diff_refs: Some(agent_access_gitlab::GitlabDiffRefs {
                    base_sha: Some(TEST_BASE_SHA.to_string()),
                    start_sha: TEST_START_SHA.to_string(),
                    head_sha: TEST_SHA.to_string(),
                }),
                changes_count: Some("3".to_string()),
                user_notes_count: Some(2),
                discussion_locked: Some(false),
                blocking_discussions_resolved: Some(false),
                has_conflicts: Some(false),
                prepared_at: self.merge_request_prepared_at.lock().unwrap().clone(),
                head_pipeline: Some(agent_access_gitlab::GitlabPipelineSummary {
                    id: 901,
                    sha: Some(TEST_SHA.to_string()),
                    ref_name: Some("feature/rest".to_string()),
                    status: Some("success".to_string()),
                    web_url: Some(
                        "https://gitlab.example.com/sip/service/-/pipelines/901".to_string(),
                    ),
                }),
                created_at: Some("2026-06-03T12:00:00.000Z".to_string()),
                updated_at: Some("2026-06-04T13:00:00.000Z".to_string()),
                author: Some(gitlab_user(1, "alice", "Alice")),
                assignees: Some(vec![gitlab_user(2, "bob", "Bob")]),
                reviewers: Some(vec![gitlab_user(3, "carol", "Carol")]),
                labels: Some(vec!["review".to_string()]),
                milestone: Some(gitlab_milestone("M2")),
                draft: Some(true),
                web_url: Some(
                    "https://gitlab.example.com/sip/service/-/merge_requests/5".to_string(),
                ),
                project: None,
            },
            status: 200,
            duration_ms: 5,
        })
    }

    async fn merge_requests(
        &self,
        project_id: u64,
        request: GitlabMergeRequestSearchRequest,
        credential: &agent_access_gitlab::GitlabCredential,
    ) -> Result<GitlabBackendResponse<GitlabPage<GitlabMergeRequest>>, GitlabBackendError> {
        self.record_credential("merge_requests", credential);
        let next_page = (request.page == 1).then_some(2);
        *self.last_merge_request_search.lock().unwrap() = Some(ObservedMergeRequestSearch {
            project_id,
            request,
        });
        Ok(GitlabBackendResponse {
            value: GitlabPage {
                items: vec![GitlabMergeRequest {
                    id: Some(500),
                    iid: 5,
                    project_id,
                    title: Some("visible merge request".to_string()),
                    description: Some("merge request context".to_string()),
                    state: Some("opened".to_string()),
                    source_branch: Some("feature/rest".to_string()),
                    target_branch: Some("main".to_string()),
                    sha: Some(TEST_SHA.to_string()),
                    merge_status: Some("can_be_merged".to_string()),
                    detailed_merge_status: Some("mergeable".to_string()),
                    merge_commit_sha: None,
                    squash_commit_sha: None,
                    source_project_id: Some(42),
                    target_project_id: Some(42),
                    diff_refs: Some(agent_access_gitlab::GitlabDiffRefs {
                        base_sha: Some(TEST_BASE_SHA.to_string()),
                        start_sha: TEST_START_SHA.to_string(),
                        head_sha: TEST_SHA.to_string(),
                    }),
                    changes_count: Some("3".to_string()),
                    user_notes_count: Some(2),
                    discussion_locked: Some(false),
                    blocking_discussions_resolved: Some(false),
                    has_conflicts: Some(false),
                    prepared_at: Some("2026-06-03T12:01:00.000Z".to_string()),
                    head_pipeline: None,
                    created_at: Some("2026-06-03T12:00:00.000Z".to_string()),
                    updated_at: Some("2026-06-04T13:00:00.000Z".to_string()),
                    author: Some(gitlab_user(1, "alice", "Alice")),
                    assignees: Some(vec![gitlab_user(2, "bob", "Bob")]),
                    reviewers: Some(vec![gitlab_user(3, "carol", "Carol")]),
                    labels: Some(vec!["review".to_string()]),
                    milestone: Some(gitlab_milestone("M2")),
                    draft: Some(true),
                    web_url: Some(
                        "https://gitlab.example.com/sip/service/-/merge_requests/5".to_string(),
                    ),
                    project: None,
                }],
                next_page,
            },
            status: 200,
            duration_ms: 6,
        })
    }

    async fn create_merge_request(
        &self,
        project_id: u64,
        request: GitlabMergeRequestCreateRequest,
        credential: &agent_access_gitlab::GitlabCredential,
    ) -> Result<GitlabBackendResponse<GitlabMergeRequest>, GitlabBackendError> {
        self.record_credential("create_merge_request", credential);
        *self.last_merge_request_create.lock().unwrap() = Some(ObservedMergeRequestCreate {
            project_id,
            request,
        });
        Ok(GitlabBackendResponse {
            value: merge_request(project_id, 6, "created merge request"),
            status: 201,
            duration_ms: 15,
        })
    }

    async fn update_merge_request(
        &self,
        project_id: u64,
        request: GitlabMergeRequestUpdateRequest,
        credential: &agent_access_gitlab::GitlabCredential,
    ) -> Result<GitlabBackendResponse<GitlabMergeRequest>, GitlabBackendError> {
        self.record_credential("update_merge_request", credential);
        *self.last_merge_request_update.lock().unwrap() = Some(ObservedMergeRequestUpdate {
            project_id,
            request,
        });
        Ok(GitlabBackendResponse {
            value: merge_request(project_id, 5, "updated merge request"),
            status: 200,
            duration_ms: 16,
        })
    }

    async fn merge_request_notes(
        &self,
        project_id: u64,
        request: GitlabNoteListRequest,
        credential: &agent_access_gitlab::GitlabCredential,
    ) -> Result<GitlabBackendResponse<GitlabPage<GitlabNote>>, GitlabBackendError> {
        self.record_credential("merge_request_notes", credential);
        let next_page = (request.page == 1).then_some(2);
        *self.last_merge_request_note_list.lock().unwrap() = Some(ObservedMergeRequestNoteList {
            project_id,
            request: request.clone(),
        });
        Ok(GitlabBackendResponse {
            value: GitlabPage {
                items: vec![merge_request_note(
                    501,
                    "existing merge request note",
                    request.iid,
                )],
                next_page,
            },
            status: 200,
            duration_ms: 17,
        })
    }

    async fn create_merge_request_note(
        &self,
        project_id: u64,
        request: GitlabNoteCreateRequest,
        credential: &agent_access_gitlab::GitlabCredential,
    ) -> Result<GitlabBackendResponse<GitlabNote>, GitlabBackendError> {
        self.record_credential("create_merge_request_note", credential);
        *self.last_merge_request_note_add.lock().unwrap() = Some(ObservedMergeRequestNoteAdd {
            project_id,
            request: request.clone(),
        });
        Ok(GitlabBackendResponse {
            value: merge_request_note(502, "created merge request note", request.iid),
            status: 201,
            duration_ms: 18,
        })
    }

    async fn merge_request_note(
        &self,
        project_id: u64,
        request: GitlabNoteDeleteRequest,
        credential: &agent_access_gitlab::GitlabCredential,
    ) -> Result<GitlabBackendResponse<GitlabNote>, GitlabBackendError> {
        self.record_credential("merge_request_note", credential);
        if project_id != 42 || request.iid != 5 || request.note_id != 501 {
            return Err(GitlabBackendError::NotFound);
        }
        Ok(GitlabBackendResponse {
            value: merge_request_note(
                request.note_id,
                "merge request preflight secret body",
                request.iid,
            ),
            status: 200,
            duration_ms: 24,
        })
    }

    async fn update_merge_request_note(
        &self,
        project_id: u64,
        request: GitlabNoteUpdateRequest,
        credential: &agent_access_gitlab::GitlabCredential,
    ) -> Result<GitlabBackendResponse<GitlabNote>, GitlabBackendError> {
        self.record_credential("update_merge_request_note", credential);
        *self.last_merge_request_note_update.lock().unwrap() =
            Some(ObservedMergeRequestNoteUpdate {
                project_id,
                request: request.clone(),
            });
        Ok(GitlabBackendResponse {
            value: merge_request_note(request.note_id, "updated merge request note", request.iid),
            status: 200,
            duration_ms: 25,
        })
    }

    async fn delete_merge_request_note(
        &self,
        project_id: u64,
        request: GitlabNoteDeleteRequest,
        credential: &agent_access_gitlab::GitlabCredential,
    ) -> Result<GitlabBackendResponse<()>, GitlabBackendError> {
        self.record_credential("delete_merge_request_note", credential);
        *self.last_merge_request_note_delete.lock().unwrap() =
            Some(ObservedMergeRequestNoteDelete {
                project_id,
                request,
            });
        Ok(GitlabBackendResponse {
            value: (),
            status: 204,
            duration_ms: 26,
        })
    }

    async fn merge_request_discussions_page(
        &self,
        project_id: u64,
        request: GitlabDiscussionListRequest,
        credential: &agent_access_gitlab::GitlabCredential,
    ) -> Result<GitlabBackendResponse<GitlabPage<GitlabDiscussion>>, GitlabBackendError> {
        self.record_credential("merge_request_discussions_page", credential);
        *self.last_merge_request_discussion_list.lock().unwrap() =
            Some(ObservedMergeRequestDiscussionList {
                project_id,
                request: request.clone(),
            });
        let mut items = vec![discussion(
            "discussion-1",
            self.discussion_body
                .lock()
                .unwrap()
                .as_deref()
                .unwrap_or("existing discussion"),
            request.iid,
        )];
        items.extend(self.published_discussions.lock().unwrap().clone());
        let mode = self.discussion_pagination_mode.lock().unwrap().clone();
        if mode == "too_many" {
            items = (0..=100)
                .map(|offset| {
                    let mut item = discussion(
                        &format!("discussion-{offset}"),
                        "bounded discussion",
                        request.iid,
                    );
                    item.notes[0].id = 20_000 + offset;
                    item
                })
                .collect();
        }
        let has_published = !self.published_discussions.lock().unwrap().is_empty();
        let next_page = match mode.as_str() {
            "invalid_next" => Some(request.page + 2),
            "endless" => Some(request.page + 1),
            "invalid_after_publish" if has_published => Some(request.page + 2),
            _ => (request.page == 1).then_some(2),
        };
        Ok(GitlabBackendResponse {
            value: GitlabPage { items, next_page },
            status: 200,
            duration_ms: 19,
        })
    }

    async fn create_merge_request_inline_discussion(
        &self,
        project_id: u64,
        request: GitlabPositionedDiscussionCreateRequest,
        credential: &agent_access_gitlab::GitlabCredential,
    ) -> Result<GitlabBackendResponse<GitlabDiscussion>, GitlabBackendError> {
        self.record_credential("create_merge_request_inline_discussion", credential);
        *self.last_inline_discussion_add.lock().unwrap() = Some(ObservedInlineDiscussionAdd {
            project_id,
            request: request.clone(),
        });
        let stored_body = gitlab_stored_note_body(&request.body);
        let mut created = discussion("discussion-inline", &stored_body, request.iid);
        created.notes[0].id = 910;
        created.notes[0].position = Some(request.position);
        if *self.malformed_inline_response.lock().unwrap() {
            created.notes[0].position.as_mut().unwrap().new_path = "src/wrong.rs".to_string();
        }
        Ok(GitlabBackendResponse {
            value: created,
            status: 201,
            duration_ms: 38,
        })
    }

    async fn create_merge_request_discussion_note(
        &self,
        project_id: u64,
        request: GitlabDiscussionReplyRequest,
        credential: &agent_access_gitlab::GitlabCredential,
    ) -> Result<GitlabBackendResponse<GitlabNote>, GitlabBackendError> {
        self.record_credential("create_merge_request_discussion_note", credential);
        if *self.fail_discussion_reply_write.lock().unwrap() {
            return Err(GitlabBackendError::HttpStatus(500));
        }
        *self.last_discussion_reply_add.lock().unwrap() = Some(ObservedDiscussionReplyAdd {
            project_id,
            request: request.clone(),
        });
        let stored_body = gitlab_stored_note_body(&request.body);
        let mut note = merge_request_note(911, &stored_body, request.iid);
        note.note_type = Some("DiscussionNote".to_string());
        Ok(GitlabBackendResponse {
            value: note,
            status: 201,
            duration_ms: 39,
        })
    }

    async fn merge_request_draft_notes(
        &self,
        project_id: u64,
        request: GitlabDraftNoteListRequest,
        credential: &agent_access_gitlab::GitlabCredential,
    ) -> Result<GitlabBackendResponse<GitlabPage<GitlabDraftNote>>, GitlabBackendError> {
        self.record_credential("merge_request_draft_notes", credential);
        if project_id != 42 || request.iid != 5 {
            return Err(GitlabBackendError::NotFound);
        }
        Ok(GitlabBackendResponse {
            value: GitlabPage {
                items: self.draft_notes.lock().unwrap().clone(),
                next_page: None,
            },
            status: 200,
            duration_ms: 40,
        })
    }

    async fn merge_request_draft_note(
        &self,
        project_id: u64,
        request: GitlabDraftNoteObjectRequest,
        credential: &agent_access_gitlab::GitlabCredential,
    ) -> Result<GitlabBackendResponse<GitlabDraftNote>, GitlabBackendError> {
        self.record_credential("merge_request_draft_note", credential);
        if project_id != 42 || request.iid != 5 {
            return Err(GitlabBackendError::NotFound);
        }
        let draft = self
            .draft_notes
            .lock()
            .unwrap()
            .iter()
            .find(|draft| draft.id == request.draft_note_id)
            .cloned()
            .ok_or(GitlabBackendError::NotFound)?;
        Ok(GitlabBackendResponse {
            value: draft,
            status: 200,
            duration_ms: 41,
        })
    }

    async fn create_merge_request_draft_note(
        &self,
        project_id: u64,
        request: GitlabDraftNoteCreateRequest,
        credential: &agent_access_gitlab::GitlabCredential,
    ) -> Result<GitlabBackendResponse<GitlabDraftNote>, GitlabBackendError> {
        self.record_credential("create_merge_request_draft_note", credential);
        if project_id != 42 || request.iid != 5 {
            return Err(GitlabBackendError::NotFound);
        }
        *self.last_draft_note_create.lock().unwrap() = Some(request.clone());
        let mut next_id = self.next_draft_note_id.lock().unwrap();
        let stored_body = gitlab_stored_note_body(&request.body);
        let mut draft = draft_note_fixture(*next_id, &stored_body, request.position);
        *next_id += 1;
        draft.discussion_id = request.in_reply_to_discussion_id;
        draft.resolve_discussion = request.resolve_discussion;
        self.draft_notes.lock().unwrap().push(draft.clone());
        Ok(GitlabBackendResponse {
            value: draft,
            status: 201,
            duration_ms: 42,
        })
    }

    async fn update_merge_request_draft_note(
        &self,
        project_id: u64,
        request: GitlabDraftNoteUpdateRequest,
        credential: &agent_access_gitlab::GitlabCredential,
    ) -> Result<GitlabBackendResponse<GitlabDraftNote>, GitlabBackendError> {
        self.record_credential("update_merge_request_draft_note", credential);
        if project_id != 42 || request.iid != 5 {
            return Err(GitlabBackendError::NotFound);
        }
        *self.last_draft_note_update.lock().unwrap() = Some(request.clone());
        let mut drafts = self.draft_notes.lock().unwrap();
        let draft = drafts
            .iter_mut()
            .find(|draft| draft.id == request.draft_note_id)
            .ok_or(GitlabBackendError::NotFound)?;
        if !*self.malformed_draft_update_readback.lock().unwrap() {
            draft.body = Some(gitlab_stored_note_body(&request.body));
        }
        // GitLab updates both fields unconditionally, so an omitted position
        // clears a previously positioned draft.
        if *self.drop_draft_position_on_update.lock().unwrap() {
            draft.commit_id = None;
            draft.position = None;
        } else {
            draft.commit_id = request
                .position
                .as_ref()
                .map(|position| position.head_sha.clone());
            draft.position = request.position;
        }
        Ok(GitlabBackendResponse {
            value: draft.clone(),
            status: 200,
            duration_ms: 43,
        })
    }

    async fn delete_merge_request_draft_note(
        &self,
        project_id: u64,
        request: GitlabDraftNoteObjectRequest,
        credential: &agent_access_gitlab::GitlabCredential,
    ) -> Result<GitlabBackendResponse<()>, GitlabBackendError> {
        self.record_credential("delete_merge_request_draft_note", credential);
        if project_id != 42 || request.iid != 5 {
            return Err(GitlabBackendError::NotFound);
        }
        if !*self.retain_deleted_draft.lock().unwrap() {
            self.draft_notes
                .lock()
                .unwrap()
                .retain(|draft| draft.id != request.draft_note_id);
        }
        Ok(GitlabBackendResponse {
            value: (),
            status: 204,
            duration_ms: 44,
        })
    }

    async fn publish_merge_request_draft_note(
        &self,
        project_id: u64,
        request: GitlabDraftNoteObjectRequest,
        credential: &agent_access_gitlab::GitlabCredential,
    ) -> Result<GitlabBackendResponse<()>, GitlabBackendError> {
        self.record_credential("publish_merge_request_draft_note", credential);
        if project_id != 42 || request.iid != 5 {
            return Err(GitlabBackendError::NotFound);
        }
        let draft = self
            .draft_notes
            .lock()
            .unwrap()
            .iter()
            .find(|draft| draft.id == request.draft_note_id)
            .cloned()
            .ok_or(GitlabBackendError::NotFound)?;
        let note_id = 12_000 + draft.id;
        let stored_body = gitlab_stored_note_body(draft.body.as_deref().unwrap_or_default());
        let mut note = merge_request_note(note_id, &stored_body, request.iid);
        note.author_user_id = Some(*self.current_user_id.lock().unwrap());
        note.author_username = Some(self.current_user_username.lock().unwrap().clone());
        note.system = Some(false);
        let published = if let Some(discussion_id) = &draft.discussion_id {
            let mut discussion = live_shaped_discussion(
                discussion_id,
                900,
                "discussion preflight secret body",
                request.iid,
                Some(true),
            );
            if discussion_id == "discussion-outdated" {
                discussion.notes[0].position.as_mut().unwrap().head_sha =
                    "dddddddddddddddddddddddddddddddddddddddd".to_string();
            }
            note.note_type = Some("DiscussionNote".to_string());
            note.position = None;
            discussion.notes.push(note);
            discussion
        } else {
            note.note_type = draft.position.as_ref().map(|_| "DiffNote".to_string());
            note.position = draft.position.clone();
            GitlabDiscussion {
                id: format!("published-draft-{}", draft.id),
                individual_note: Some(false),
                notes: vec![note],
            }
        };
        self.published_discussions.lock().unwrap().push(published);
        if !*self.retain_published_draft.lock().unwrap() {
            self.draft_notes
                .lock()
                .unwrap()
                .retain(|draft| draft.id != request.draft_note_id);
        }
        Ok(GitlabBackendResponse {
            value: (),
            status: 204,
            duration_ms: 45,
        })
    }

    async fn bulk_publish_merge_request_draft_notes(
        &self,
        project_id: u64,
        request: GitlabDraftBulkPublishRequest,
        credential: &agent_access_gitlab::GitlabCredential,
    ) -> Result<GitlabBackendResponse<()>, GitlabBackendError> {
        self.record_credential("bulk_publish_merge_request_draft_notes", credential);
        if project_id != 42 || request.iid != 5 {
            return Err(GitlabBackendError::NotFound);
        }
        *self.last_draft_bulk_publish.lock().unwrap() = Some(request.clone());
        if *self.fail_bulk_publish_without_apply.lock().unwrap() {
            return Err(GitlabBackendError::HttpStatus(500));
        }
        self.draft_notes.lock().unwrap().clear();
        if let Some(reviewer_state) = request.reviewer_state
            && !*self.skip_reviewer_state_update.lock().unwrap()
        {
            *self.reviewer_state.lock().unwrap() = reviewer_state;
        }
        if *self.fail_bulk_publish_after_apply.lock().unwrap() {
            return Err(GitlabBackendError::HttpStatus(500));
        }
        Ok(GitlabBackendResponse {
            value: (),
            status: 204,
            duration_ms: 46,
        })
    }

    async fn create_merge_request_review_summary(
        &self,
        project_id: u64,
        request: GitlabReviewSummaryNoteRequest,
        credential: &agent_access_gitlab::GitlabCredential,
    ) -> Result<GitlabBackendResponse<GitlabNote>, GitlabBackendError> {
        self.record_credential("create_merge_request_review_summary", credential);
        if project_id != 42 || request.iid != 5 {
            return Err(GitlabBackendError::NotFound);
        }
        *self.last_review_summary.lock().unwrap() = Some(request.clone());
        let body = if *self.malformed_review_summary.lock().unwrap() {
            "mismatched review summary".to_string()
        } else {
            gitlab_stored_note_body(&request.body)
        };
        Ok(GitlabBackendResponse {
            value: merge_request_note(990, &body, request.iid),
            status: 201,
            duration_ms: 47,
        })
    }

    async fn gitlab_version(
        &self,
        credential: &agent_access_gitlab::GitlabCredential,
    ) -> Result<GitlabBackendResponse<GitlabServerVersion>, GitlabBackendError> {
        self.record_credential("gitlab_version", credential);
        if *self.fail_gitlab_version.lock().unwrap() {
            return Err(GitlabBackendError::Protocol(
                "stub GitLab version response failure".to_string(),
            ));
        }
        Ok(GitlabBackendResponse {
            value: GitlabServerVersion {
                version: self.gitlab_version_value.lock().unwrap().clone(),
            },
            status: 200,
            duration_ms: 48,
        })
    }

    async fn merge_request_approval_summary(
        &self,
        project_id: u64,
        iid: u64,
        credential: &agent_access_gitlab::GitlabCredential,
    ) -> Result<GitlabBackendResponse<GitlabApprovalSummary>, GitlabBackendError> {
        self.record_credential("merge_request_approval_summary", credential);
        if project_id != 42 || iid != 5 {
            return Err(GitlabBackendError::NotFound);
        }
        let actor_approved = *self.actor_formally_approved.lock().unwrap();
        let readback_mode = self.approval_readback_mode.lock().unwrap().clone();
        let mut approved_by = if actor_approved {
            vec![GitlabApprovalUser {
                user: gitlab_user(3, "carol", "Carol"),
                approved_at: Some("2026-06-03T12:40:00.000Z".to_string()),
            }]
        } else {
            vec![]
        };
        if actor_approved && readback_mode == "duplicate_actor" {
            approved_by.push(approved_by[0].clone());
        }
        let user_has_approved = if actor_approved && readback_mode == "contradictory_user_flag" {
            false
        } else {
            actor_approved
        };
        Ok(GitlabBackendResponse {
            value: GitlabApprovalSummary {
                approvals_required: Some(1),
                approvals_left: Some(if approved_by.is_empty() { 1 } else { 0 }),
                approved: Some(
                    self.aggregate_approval_override
                        .lock()
                        .unwrap()
                        .unwrap_or(!approved_by.is_empty()),
                ),
                approved_by,
                user_has_approved: Some(user_has_approved),
                user_can_approve: Some(true),
            },
            status: 200,
            duration_ms: 49,
        })
    }

    async fn merge_request_approval_state(
        &self,
        project_id: u64,
        iid: u64,
        credential: &agent_access_gitlab::GitlabCredential,
    ) -> Result<GitlabBackendResponse<GitlabApprovalState>, GitlabBackendError> {
        self.record_credential("merge_request_approval_state", credential);
        if project_id != 42 || iid != 5 {
            return Err(GitlabBackendError::NotFound);
        }
        Ok(GitlabBackendResponse {
            value: GitlabApprovalState {
                approval_rules_overwritten: Some(true),
                rules: vec![approval_rule_fixture()],
            },
            status: 200,
            duration_ms: 50,
        })
    }

    async fn merge_request_approval_rules(
        &self,
        project_id: u64,
        request: GitlabApprovalRuleListRequest,
        credential: &agent_access_gitlab::GitlabCredential,
    ) -> Result<GitlabBackendResponse<GitlabPage<GitlabApprovalRule>>, GitlabBackendError> {
        self.record_credential("merge_request_approval_rules", credential);
        if project_id != 42 || request.iid != 5 {
            return Err(GitlabBackendError::NotFound);
        }
        Ok(GitlabBackendResponse {
            value: GitlabPage {
                items: vec![approval_rule_fixture()],
                next_page: None,
            },
            status: 200,
            duration_ms: 51,
        })
    }

    async fn merge_request_approval_rule(
        &self,
        project_id: u64,
        iid: u64,
        rule_id: u64,
        credential: &agent_access_gitlab::GitlabCredential,
    ) -> Result<GitlabBackendResponse<GitlabApprovalRule>, GitlabBackendError> {
        self.record_credential("merge_request_approval_rule", credential);
        if project_id != 42 || iid != 5 || rule_id != 71 {
            return Err(GitlabBackendError::NotFound);
        }
        Ok(GitlabBackendResponse {
            value: approval_rule_fixture(),
            status: 200,
            duration_ms: 52,
        })
    }

    async fn set_merge_request_approval(
        &self,
        project_id: u64,
        request: GitlabApprovalMutationRequest,
        credential: &agent_access_gitlab::GitlabCredential,
    ) -> Result<GitlabBackendResponse<GitlabApprovalSummary>, GitlabBackendError> {
        self.record_credential("set_merge_request_approval", credential);
        if project_id != 42 || request.iid != 5 {
            return Err(GitlabBackendError::NotFound);
        }
        *self.last_approval_mutation.lock().unwrap() = Some(request.clone());
        let approved = request.head_sha.is_some();
        let mutation_mode = self.approval_mutation_mode.lock().unwrap().clone();
        if mutation_mode == "fail_unchanged" {
            return Err(GitlabBackendError::HttpStatus(500));
        }
        *self.actor_formally_approved.lock().unwrap() = approved;
        if mutation_mode == "fail_after_apply" {
            return Err(GitlabBackendError::HttpStatus(500));
        }
        Ok(GitlabBackendResponse {
            value: GitlabApprovalSummary {
                approvals_required: Some(1),
                approvals_left: Some(if approved { 0 } else { 1 }),
                approved: Some(approved),
                approved_by: if approved {
                    vec![GitlabApprovalUser {
                        user: gitlab_user(3, "carol", "Carol"),
                        approved_at: Some("2026-06-03T12:40:00.000Z".to_string()),
                    }]
                } else {
                    Vec::new()
                },
                user_has_approved: Some(approved),
                user_can_approve: Some(true),
            },
            status: 201,
            duration_ms: 53,
        })
    }

    async fn apply_suggestions(
        &self,
        request: GitlabSuggestionApplyRequest,
        credential: &agent_access_gitlab::GitlabCredential,
    ) -> Result<GitlabBackendResponse<Vec<agent_access_gitlab::GitlabSuggestion>>, GitlabBackendError>
    {
        self.record_credential("apply_suggestions", credential);
        *self.last_suggestion_apply.lock().unwrap() = Some(request.clone());
        if !*self.retain_unapplied_suggestions.lock().unwrap() {
            *self.suggestions_applied.lock().unwrap() = true;
        }
        // GitLab can return stale in-memory entities after its update_all.
        let suggestions = request
            .suggestion_ids
            .iter()
            .copied()
            .map(|id| suggestion_fixture(id, false))
            .collect();
        Ok(GitlabBackendResponse {
            value: suggestions,
            status: 200,
            duration_ms: 54,
        })
    }

    async fn merge_request_reviewers(
        &self,
        project_id: u64,
        request: GitlabMergeRequestListRequest,
        credential: &agent_access_gitlab::GitlabCredential,
    ) -> Result<GitlabBackendResponse<GitlabPage<GitlabReviewer>>, GitlabBackendError> {
        self.record_credential("merge_request_reviewers", credential);
        *self.last_merge_request_reviewer_list.lock().unwrap() = Some(ObservedMergeRequestList {
            project_id,
            request: request.clone(),
        });
        let fixture_mode = self.reviewer_fixture_mode.lock().unwrap().clone();
        let reviewer = GitlabReviewer {
            user: gitlab_user(3, "carol", "Carol"),
            state: self.reviewer_state.lock().unwrap().clone(),
            created_at: Some("2026-06-03T12:30:00.000Z".to_string()),
        };
        let items = match fixture_mode.as_str() {
            "absent" => vec![],
            "duplicate" => vec![reviewer.clone(), reviewer],
            _ => vec![reviewer],
        };
        Ok(GitlabBackendResponse {
            value: GitlabPage {
                items,
                next_page: (request.page == 1 && request.max_results < 100).then_some(2),
            },
            status: 200,
            duration_ms: 31,
        })
    }

    async fn merge_request_commits(
        &self,
        project_id: u64,
        request: GitlabMergeRequestListRequest,
        credential: &agent_access_gitlab::GitlabCredential,
    ) -> Result<GitlabBackendResponse<GitlabPage<GitlabCommit>>, GitlabBackendError> {
        self.record_credential("merge_request_commits", credential);
        *self.last_merge_request_commit_list.lock().unwrap() = Some(ObservedMergeRequestList {
            project_id,
            request: request.clone(),
        });
        Ok(GitlabBackendResponse {
            value: GitlabPage {
                items: vec![test_commit()],
                next_page: (request.page == 1).then_some(2),
            },
            status: 200,
            duration_ms: 32,
        })
    }

    async fn merge_request_pipelines(
        &self,
        project_id: u64,
        request: GitlabMergeRequestListRequest,
        credential: &agent_access_gitlab::GitlabCredential,
    ) -> Result<GitlabBackendResponse<GitlabPage<GitlabPipeline>>, GitlabBackendError> {
        self.record_credential("merge_request_pipelines", credential);
        *self.last_merge_request_pipeline_list.lock().unwrap() = Some(ObservedMergeRequestList {
            project_id,
            request: request.clone(),
        });
        Ok(GitlabBackendResponse {
            value: GitlabPage {
                items: vec![pipeline_fixture(901, "feature/rest", "success")],
                next_page: (request.page == 1).then_some(2),
            },
            status: 200,
            duration_ms: 33,
        })
    }

    async fn merge_request_diffs(
        &self,
        project_id: u64,
        request: GitlabMergeRequestListRequest,
        credential: &agent_access_gitlab::GitlabCredential,
    ) -> Result<GitlabBackendResponse<GitlabPage<GitlabDiffFile>>, GitlabBackendError> {
        self.record_credential("merge_request_diffs", credential);
        *self.last_merge_request_diff_list.lock().unwrap() = Some(ObservedMergeRequestList {
            project_id,
            request: request.clone(),
        });
        Ok(GitlabBackendResponse {
            value: GitlabPage {
                items: (request.page == 1)
                    .then(diff_file_fixture)
                    .into_iter()
                    .collect(),
                next_page: (request.page == 1).then_some(2),
            },
            status: 200,
            duration_ms: 34,
        })
    }

    async fn merge_request_raw_diffs(
        &self,
        project_id: u64,
        iid: u64,
        _byte_cap: u64,
        credential: &agent_access_gitlab::GitlabCredential,
    ) -> Result<GitlabBackendResponse<GitlabRawFile>, GitlabBackendError> {
        self.record_credential("merge_request_raw_diffs", credential);
        if project_id != 42 || iid != 5 {
            return Err(GitlabBackendError::NotFound);
        }
        if let Some(chunks) = self.streamed_raw_diffs.lock().unwrap().pop_front() {
            let chunks = chunks.into_iter().map(bytes::Bytes::from_static).collect();
            return Ok(GitlabBackendResponse {
                value: GitlabRawFile {
                    size: None,
                    content_type: "text/x-diff".to_string(),
                    stream: ProviderResultStream::from_stream("text/x-diff", ChunkStream(chunks)),
                },
                status: 200,
                duration_ms: 35,
            });
        }
        let bytes = b"diff --git a/src/old.rs b/src/new.rs\n".to_vec();
        Ok(GitlabBackendResponse {
            value: GitlabRawFile {
                size: Some(bytes.len() as u64),
                content_type: "text/x-diff".to_string(),
                stream: ProviderResultStream::from_bytes("text/x-diff", bytes),
            },
            status: 200,
            duration_ms: 35,
        })
    }

    async fn merge_request_diff_versions(
        &self,
        project_id: u64,
        request: GitlabMergeRequestListRequest,
        credential: &agent_access_gitlab::GitlabCredential,
    ) -> Result<GitlabBackendResponse<GitlabPage<GitlabDiffVersionSummary>>, GitlabBackendError>
    {
        self.record_credential("merge_request_diff_versions", credential);
        *self.last_merge_request_diff_version_list.lock().unwrap() =
            Some(ObservedMergeRequestList {
                project_id,
                request: request.clone(),
            });
        let mut version = diff_version_summary_fixture();
        version.state = Some(self.diff_version_state.lock().unwrap().clone());
        version.patch_id_sha = self.approval_patch_id_sha.lock().unwrap().clone();
        let match_page = *self.approval_diff_match_page.lock().unwrap();
        let (items, next_page) = if request.page < match_page {
            (Vec::new(), Some(request.page + 1))
        } else {
            (vec![version], None)
        };
        Ok(GitlabBackendResponse {
            value: GitlabPage { items, next_page },
            status: 200,
            duration_ms: 36,
        })
    }

    async fn merge_request_diff_version(
        &self,
        project_id: u64,
        request: GitlabMergeRequestObjectRequest,
        credential: &agent_access_gitlab::GitlabCredential,
    ) -> Result<GitlabBackendResponse<GitlabDiffVersion>, GitlabBackendError> {
        self.record_credential("merge_request_diff_version", credential);
        if project_id != 42 || request.iid != 5 || request.object_id != 77 {
            return Err(GitlabBackendError::NotFound);
        }
        *self.last_merge_request_diff_version_view.lock().unwrap() =
            Some(ObservedMergeRequestObject {
                project_id,
                request,
            });
        Ok(GitlabBackendResponse {
            value: diff_version_fixture(true),
            status: 200,
            duration_ms: 37,
        })
    }

    async fn create_merge_request_discussion(
        &self,
        project_id: u64,
        request: GitlabNoteCreateRequest,
        credential: &agent_access_gitlab::GitlabCredential,
    ) -> Result<GitlabBackendResponse<GitlabDiscussion>, GitlabBackendError> {
        self.record_credential("create_merge_request_discussion", credential);
        *self.last_merge_request_discussion_add.lock().unwrap() =
            Some(ObservedMergeRequestDiscussionAdd {
                project_id,
                request: request.clone(),
            });
        Ok(GitlabBackendResponse {
            value: discussion("discussion-2", "created discussion", request.iid),
            status: 201,
            duration_ms: 20,
        })
    }

    async fn merge_request_discussion(
        &self,
        project_id: u64,
        iid: u64,
        discussion_id: &str,
        credential: &agent_access_gitlab::GitlabCredential,
    ) -> Result<GitlabBackendResponse<GitlabDiscussion>, GitlabBackendError> {
        self.record_credential("merge_request_discussion", credential);
        if let Some(value) = self
            .published_discussions
            .lock()
            .unwrap()
            .iter()
            .find(|discussion| discussion.id == discussion_id)
            .cloned()
        {
            return Ok(GitlabBackendResponse {
                value,
                status: 200,
                duration_ms: 27,
            });
        }
        if project_id != 42
            || iid != 5
            || !matches!(discussion_id, "discussion-1" | "discussion-outdated")
        {
            return Err(GitlabBackendError::NotFound);
        }
        let mut value = live_shaped_discussion(
            discussion_id,
            900,
            "discussion preflight secret body",
            iid,
            Some(true),
        );
        if discussion_id == "discussion-outdated" {
            value.notes[0].position.as_mut().unwrap().head_sha =
                "dddddddddddddddddddddddddddddddddddddddd".to_string();
        }
        let applied = *self.suggestions_applied.lock().unwrap();
        for suggestion in &mut value.notes[0].suggestions {
            suggestion.applied = applied;
            suggestion.applicable = !applied;
        }
        if *self.discussion_proof_mismatch.lock().unwrap() {
            value.id = "discussion-mismatch".to_string();
        }
        if let Some(reply) = self.last_discussion_reply_add.lock().unwrap().as_ref()
            && reply.request.discussion_id == discussion_id
        {
            let mut note = merge_request_note(911, &reply.request.body, iid);
            note.note_type = Some("DiscussionNote".to_string());
            value.notes.push(note);
        }
        Ok(GitlabBackendResponse {
            value,
            status: 200,
            duration_ms: 27,
        })
    }

    async fn update_merge_request_discussion_note(
        &self,
        project_id: u64,
        request: GitlabDiscussionNoteUpdateRequest,
        credential: &agent_access_gitlab::GitlabCredential,
    ) -> Result<GitlabBackendResponse<GitlabNote>, GitlabBackendError> {
        self.record_credential("update_merge_request_discussion_note", credential);
        *self
            .last_merge_request_discussion_note_update
            .lock()
            .unwrap() = Some(ObservedMergeRequestDiscussionNoteUpdate {
            project_id,
            request: request.clone(),
        });
        Ok(GitlabBackendResponse {
            value: merge_request_note(request.note_id, "updated discussion note", request.iid),
            status: 200,
            duration_ms: 28,
        })
    }

    async fn delete_merge_request_discussion_note(
        &self,
        project_id: u64,
        request: GitlabDiscussionNoteDeleteRequest,
        credential: &agent_access_gitlab::GitlabCredential,
    ) -> Result<GitlabBackendResponse<()>, GitlabBackendError> {
        self.record_credential("delete_merge_request_discussion_note", credential);
        *self
            .last_merge_request_discussion_note_delete
            .lock()
            .unwrap() = Some(ObservedMergeRequestDiscussionNoteDelete {
            project_id,
            request,
        });
        Ok(GitlabBackendResponse {
            value: (),
            status: 204,
            duration_ms: 29,
        })
    }

    async fn set_merge_request_discussion_resolved(
        &self,
        project_id: u64,
        request: GitlabDiscussionStateChangeRequest,
        credential: &agent_access_gitlab::GitlabCredential,
    ) -> Result<GitlabBackendResponse<GitlabDiscussion>, GitlabBackendError> {
        self.record_credential("set_merge_request_discussion_resolved", credential);
        *self
            .last_merge_request_discussion_state_change
            .lock()
            .unwrap() = Some(ObservedMergeRequestDiscussionStateChange {
            project_id,
            request: request.clone(),
        });
        Ok(GitlabBackendResponse {
            value: live_shaped_discussion(
                &request.discussion_id,
                900,
                "state changed discussion",
                request.iid,
                Some(matches!(
                    request.change,
                    GitlabDiscussionStateChange::Resolve
                )),
            ),
            status: 200,
            duration_ms: 30,
        })
    }

    async fn merge_merge_request(
        &self,
        project_id: u64,
        request: GitlabMergeRequestMergeRequest,
        credential: &agent_access_gitlab::GitlabCredential,
    ) -> Result<GitlabBackendResponse<GitlabMergeRequest>, GitlabBackendError> {
        self.record_credential("merge_merge_request", credential);
        if project_id != 42 || request.iid != 5 {
            return Err(GitlabBackendError::NotFound);
        }
        if *self.merge_conflict_after_preflight.lock().unwrap() {
            return Err(GitlabBackendError::HttpStatus(409));
        }
        *self.last_merge_request_merge.lock().unwrap() = Some(ObservedMergeRequestMerge {
            project_id,
            request,
        });
        let mut merged = merge_request(project_id, 5, "merged merge request");
        if let Some(description) = self.merge_response_description.lock().unwrap().clone() {
            merged.description = Some(description);
        }
        merged.state = Some("merged".to_string());
        merged.merge_status = Some("can_be_merged".to_string());
        merged.detailed_merge_status = Some("merged".to_string());
        merged.merge_commit_sha = Some(TEST_SHA.to_string());
        Ok(GitlabBackendResponse {
            value: merged,
            status: 200,
            duration_ms: 21,
        })
    }

    async fn branches(
        &self,
        project_id: u64,
        request: GitlabBranchListRequest,
        credential: &agent_access_gitlab::GitlabCredential,
    ) -> Result<GitlabBackendResponse<Vec<GitlabBranch>>, GitlabBackendError> {
        self.record_credential("branches", credential);
        *self.last_branch_list.lock().unwrap() = Some(ObservedBranchList {
            project_id,
            request,
        });
        let branches = {
            let branches = self.branches.lock().unwrap();
            ["main", "feature/rest", "work/docs"]
                .iter()
                .filter_map(|branch| branches.get(*branch).cloned())
                .collect::<Vec<_>>()
        };
        Ok(GitlabBackendResponse {
            value: branches,
            status: 200,
            duration_ms: 7,
        })
    }

    async fn branch(
        &self,
        project_id: u64,
        branch: &str,
        credential: &agent_access_gitlab::GitlabCredential,
    ) -> Result<GitlabBackendResponse<GitlabBranch>, GitlabBackendError> {
        self.record_credential("branch", credential);
        let branch = self
            .branches
            .lock()
            .unwrap()
            .get(branch)
            .cloned()
            .filter(|_| project_id == 42)
            .ok_or(GitlabBackendError::NotFound)?;
        Ok(GitlabBackendResponse {
            value: branch,
            status: 200,
            duration_ms: 8,
        })
    }

    async fn create_branch(
        &self,
        project_id: u64,
        request: GitlabBranchCreateRequest,
        credential: &agent_access_gitlab::GitlabCredential,
    ) -> Result<GitlabBackendResponse<GitlabBranch>, GitlabBackendError> {
        self.record_credential("create_branch", credential);
        if project_id != 42 {
            return Err(GitlabBackendError::NotFound);
        }
        *self.last_branch_create.lock().unwrap() = Some(request.clone());
        let branch = branch_fixture(&request.branch);
        self.branches
            .lock()
            .unwrap()
            .insert(branch.name.clone(), branch.clone());
        Ok(GitlabBackendResponse {
            value: branch,
            status: 201,
            duration_ms: 8,
        })
    }

    async fn protected_branches(
        &self,
        project_id: u64,
        request: GitlabProtectedBranchListRequest,
        credential: &agent_access_gitlab::GitlabCredential,
    ) -> Result<GitlabBackendResponse<Vec<GitlabProtectedBranch>>, GitlabBackendError> {
        self.record_credential("protected_branches", credential);
        if project_id != 42 {
            return Err(GitlabBackendError::NotFound);
        }
        if request.fail_on_next_page && *self.protected_branch_list_has_next_page.lock().unwrap() {
            return Err(GitlabBackendError::Protocol(
                "GitLab protected branch rule list exceeded one page".to_string(),
            ));
        }
        let value = self
            .protected_branches
            .lock()
            .unwrap()
            .iter()
            .filter(|branch| {
                request
                    .search
                    .as_deref()
                    .is_none_or(|search| branch.name.contains(search))
            })
            .take(request.max_results as usize)
            .cloned()
            .collect();
        Ok(GitlabBackendResponse {
            value,
            status: 200,
            duration_ms: 8,
        })
    }

    async fn protected_branch(
        &self,
        project_id: u64,
        name: &str,
        credential: &agent_access_gitlab::GitlabCredential,
    ) -> Result<GitlabBackendResponse<GitlabProtectedBranch>, GitlabBackendError> {
        self.record_credential("protected_branch", credential);
        let branch = self
            .protected_branches
            .lock()
            .unwrap()
            .iter()
            .find(|branch| branch.name == name && project_id == 42)
            .cloned()
            .ok_or(GitlabBackendError::NotFound)?;
        Ok(GitlabBackendResponse {
            value: branch,
            status: 200,
            duration_ms: 9,
        })
    }

    async fn file(
        &self,
        project_id: u64,
        request: GitlabFileRequest,
        credential: &agent_access_gitlab::GitlabCredential,
    ) -> Result<GitlabBackendResponse<GitlabFile>, GitlabBackendError> {
        self.record_credential("file", credential);
        if project_id != 42 {
            return Err(GitlabBackendError::NotFound);
        }
        let file = self
            .files
            .lock()
            .unwrap()
            .get(&(request.ref_name, request.path))
            .cloned()
            .ok_or(GitlabBackendError::NotFound)?;
        Ok(GitlabBackendResponse {
            value: file,
            status: 200,
            duration_ms: 8,
        })
    }

    async fn raw_file(
        &self,
        project_id: u64,
        request: GitlabFileRequest,
        _byte_cap: u64,
        credential: &agent_access_gitlab::GitlabCredential,
    ) -> Result<GitlabBackendResponse<GitlabRawFile>, GitlabBackendError> {
        self.record_credential("raw_file", credential);
        if project_id != 42 || request.path != "README.md" || request.ref_name != TEST_SHA {
            return Err(GitlabBackendError::NotFound);
        }
        Ok(GitlabBackendResponse {
            value: GitlabRawFile {
                size: Some(15),
                content_type: "text/plain".to_string(),
                stream: ProviderResultStream::from_bytes("text/plain", b"readme contents".to_vec()),
            },
            status: 200,
            duration_ms: 8,
        })
    }

    async fn create_file(
        &self,
        project_id: u64,
        request: GitlabFileWriteRequest,
        credential: &agent_access_gitlab::GitlabCredential,
    ) -> Result<GitlabBackendResponse<GitlabFileMutation>, GitlabBackendError> {
        self.record_credential("create_file", credential);
        if project_id != 42 {
            return Err(GitlabBackendError::NotFound);
        }
        *self.last_file_create.lock().unwrap() = Some(request.clone());
        self.files.lock().unwrap().insert(
            (request.branch.clone(), request.path.clone()),
            file_fixture(&request.path, &request.branch, "created-file-sha"),
        );
        Ok(GitlabBackendResponse {
            value: GitlabFileMutation {
                file_path: request.path,
                branch: request.branch,
            },
            status: 201,
            duration_ms: 8,
        })
    }

    async fn update_file(
        &self,
        project_id: u64,
        request: GitlabFileWriteRequest,
        credential: &agent_access_gitlab::GitlabCredential,
    ) -> Result<GitlabBackendResponse<GitlabFileMutation>, GitlabBackendError> {
        self.record_credential("update_file", credential);
        if project_id != 42 {
            return Err(GitlabBackendError::NotFound);
        }
        *self.last_file_update.lock().unwrap() = Some(request.clone());
        self.files.lock().unwrap().insert(
            (request.branch.clone(), request.path.clone()),
            file_fixture(
                &request.path,
                &request.branch,
                "dddddddddddddddddddddddddddddddddddddddd",
            ),
        );
        Ok(GitlabBackendResponse {
            value: GitlabFileMutation {
                file_path: request.path,
                branch: request.branch,
            },
            status: 200,
            duration_ms: 8,
        })
    }

    async fn delete_file(
        &self,
        project_id: u64,
        request: GitlabFileDeleteRequest,
        credential: &agent_access_gitlab::GitlabCredential,
    ) -> Result<GitlabBackendResponse<GitlabFileMutation>, GitlabBackendError> {
        self.record_credential("delete_file", credential);
        if project_id != 42 {
            return Err(GitlabBackendError::NotFound);
        }
        *self.last_file_delete.lock().unwrap() = Some(request.clone());
        self.files
            .lock()
            .unwrap()
            .remove(&(request.branch.clone(), request.path.clone()));
        Ok(GitlabBackendResponse {
            value: GitlabFileMutation {
                file_path: request.path,
                branch: request.branch,
            },
            status: 200,
            duration_ms: 8,
        })
    }

    async fn commits(
        &self,
        project_id: u64,
        request: GitlabCommitListRequest,
        credential: &agent_access_gitlab::GitlabCredential,
    ) -> Result<GitlabBackendResponse<Vec<GitlabCommit>>, GitlabBackendError> {
        self.record_credential("commits", credential);
        *self.last_commit_list.lock().unwrap() = Some(ObservedCommitList {
            project_id,
            request,
        });
        Ok(GitlabBackendResponse {
            value: vec![test_commit()],
            status: 200,
            duration_ms: 9,
        })
    }

    async fn commit(
        &self,
        project_id: u64,
        sha: &str,
        credential: &agent_access_gitlab::GitlabCredential,
    ) -> Result<GitlabBackendResponse<GitlabCommit>, GitlabBackendError> {
        self.record_credential("commit", credential);
        if project_id != 42 || !matches!(sha, TEST_SHA | "01234567") {
            return Err(GitlabBackendError::NotFound);
        }
        Ok(GitlabBackendResponse {
            value: test_commit(),
            status: 200,
            duration_ms: 10,
        })
    }

    async fn create_commit(
        &self,
        project_id: u64,
        request: GitlabCommitCreateRequest,
        credential: &agent_access_gitlab::GitlabCredential,
    ) -> Result<GitlabBackendResponse<GitlabCommit>, GitlabBackendError> {
        self.record_credential("create_commit", credential);
        if project_id != 42 {
            return Err(GitlabBackendError::NotFound);
        }
        *self.last_commit_create.lock().unwrap() = Some(request);
        let mut commit = test_commit();
        commit.id = "1111111111111111111111111111111111111111".to_string();
        commit.title = Some("created commit".to_string());
        Ok(GitlabBackendResponse {
            value: commit,
            status: 201,
            duration_ms: 10,
        })
    }

    async fn pipelines(
        &self,
        project_id: u64,
        request: GitlabPipelineListRequest,
        credential: &agent_access_gitlab::GitlabCredential,
    ) -> Result<GitlabBackendResponse<Vec<GitlabPipeline>>, GitlabBackendError> {
        self.record_credential("pipelines", credential);
        *self.last_pipeline_list.lock().unwrap() = Some(ObservedPipelineList {
            project_id,
            request,
        });
        if project_id != 42 {
            return Err(GitlabBackendError::NotFound);
        }
        Ok(GitlabBackendResponse {
            value: vec![pipeline_fixture(321, "feature/rest", "success")],
            status: 200,
            duration_ms: 21,
        })
    }

    async fn pipeline(
        &self,
        project_id: u64,
        pipeline_id: u64,
        credential: &agent_access_gitlab::GitlabCredential,
    ) -> Result<GitlabBackendResponse<GitlabPipeline>, GitlabBackendError> {
        self.record_credential("pipeline", credential);
        if project_id != 42 {
            return Err(GitlabBackendError::NotFound);
        }
        let pipeline = match pipeline_id {
            321 => pipeline_fixture(321, "feature/rest", "success"),
            323 => pipeline_fixture(323, "main", "manual"),
            324 => pipeline_fixture(324, "main", "manual"),
            325 => pipeline_fixture(325, "release/next", "manual"),
            _ => return Err(GitlabBackendError::NotFound),
        };
        Ok(GitlabBackendResponse {
            value: pipeline,
            status: 200,
            duration_ms: 22,
        })
    }

    async fn run_pipeline(
        &self,
        project_id: u64,
        request: GitlabPipelineRunRequest,
        credential: &agent_access_gitlab::GitlabCredential,
    ) -> Result<GitlabBackendResponse<GitlabPipeline>, GitlabBackendError> {
        self.record_credential("run_pipeline", credential);
        if project_id != 42 {
            return Err(GitlabBackendError::NotFound);
        }
        *self.last_pipeline_run.lock().unwrap() = Some(request.clone());
        Ok(GitlabBackendResponse {
            value: pipeline_fixture(322, &request.ref_name, "pending"),
            status: 201,
            duration_ms: 23,
        })
    }

    async fn retry_pipeline(
        &self,
        project_id: u64,
        pipeline_id: u64,
        credential: &agent_access_gitlab::GitlabCredential,
    ) -> Result<GitlabBackendResponse<GitlabPipeline>, GitlabBackendError> {
        self.record_credential("retry_pipeline", credential);
        if project_id != 42 || pipeline_id != 321 {
            return Err(GitlabBackendError::NotFound);
        }
        Ok(GitlabBackendResponse {
            value: pipeline_fixture(321, "feature/rest", "pending"),
            status: 201,
            duration_ms: 24,
        })
    }

    async fn cancel_pipeline(
        &self,
        project_id: u64,
        pipeline_id: u64,
        credential: &agent_access_gitlab::GitlabCredential,
    ) -> Result<GitlabBackendResponse<GitlabPipeline>, GitlabBackendError> {
        self.record_credential("cancel_pipeline", credential);
        if project_id != 42 || pipeline_id != 321 {
            return Err(GitlabBackendError::NotFound);
        }
        Ok(GitlabBackendResponse {
            value: pipeline_fixture(321, "feature/rest", "canceled"),
            status: 201,
            duration_ms: 25,
        })
    }

    async fn jobs(
        &self,
        project_id: u64,
        request: GitlabJobListRequest,
        credential: &agent_access_gitlab::GitlabCredential,
    ) -> Result<GitlabBackendResponse<Vec<GitlabJob>>, GitlabBackendError> {
        self.record_credential("jobs", credential);
        *self.last_job_list.lock().unwrap() = Some(ObservedJobList {
            project_id,
            request,
        });
        if project_id != 42 {
            return Err(GitlabBackendError::NotFound);
        }
        Ok(GitlabBackendResponse {
            value: vec![job_fixture(9001, 321, "feature/rest", "failed")],
            status: 200,
            duration_ms: 26,
        })
    }

    async fn job(
        &self,
        project_id: u64,
        job_id: u64,
        credential: &agent_access_gitlab::GitlabCredential,
    ) -> Result<GitlabBackendResponse<GitlabJob>, GitlabBackendError> {
        self.record_credential("job", credential);
        if project_id != 42 {
            return Err(GitlabBackendError::NotFound);
        }
        let job = match job_id {
            9001 => job_fixture(9001, 321, "feature/rest", "failed"),
            9002 => job_fixture(9002, 321, "feature/rest", "manual"),
            9003 => job_fixture(9003, 323, "main", "manual"),
            9004 => job_fixture(9004, 324, "feature/rest", "manual"),
            9005 => job_fixture(9005, 325, "release/next", "manual"),
            _ => return Err(GitlabBackendError::NotFound),
        };
        Ok(GitlabBackendResponse {
            value: job,
            status: 200,
            duration_ms: 27,
        })
    }

    async fn job_trace(
        &self,
        project_id: u64,
        job_id: u64,
        _byte_cap: u64,
        credential: &agent_access_gitlab::GitlabCredential,
    ) -> Result<GitlabBackendResponse<GitlabRawFile>, GitlabBackendError> {
        self.record_credential("job_trace", credential);
        if project_id != 42 || job_id != 9001 {
            return Err(GitlabBackendError::NotFound);
        }
        Ok(GitlabBackendResponse {
            value: GitlabRawFile {
                size: None,
                content_type: "text/plain".to_string(),
                stream: ProviderResultStream::from_bytes(
                    "text/plain",
                    b"job trace contents".to_vec(),
                ),
            },
            status: 200,
            duration_ms: 28,
        })
    }

    async fn retry_job(
        &self,
        project_id: u64,
        job_id: u64,
        credential: &agent_access_gitlab::GitlabCredential,
    ) -> Result<GitlabBackendResponse<GitlabJob>, GitlabBackendError> {
        self.record_credential("retry_job", credential);
        if project_id != 42 || job_id != 9001 {
            return Err(GitlabBackendError::NotFound);
        }
        Ok(GitlabBackendResponse {
            value: job_fixture(9001, 321, "feature/rest", "pending"),
            status: 201,
            duration_ms: 29,
        })
    }

    async fn cancel_job(
        &self,
        project_id: u64,
        job_id: u64,
        credential: &agent_access_gitlab::GitlabCredential,
    ) -> Result<GitlabBackendResponse<GitlabJob>, GitlabBackendError> {
        self.record_credential("cancel_job", credential);
        if project_id != 42 || job_id != 9001 {
            return Err(GitlabBackendError::NotFound);
        }
        Ok(GitlabBackendResponse {
            value: job_fixture(9001, 321, "feature/rest", "canceled"),
            status: 201,
            duration_ms: 30,
        })
    }

    async fn play_job(
        &self,
        project_id: u64,
        job_id: u64,
        credential: &agent_access_gitlab::GitlabCredential,
    ) -> Result<GitlabBackendResponse<GitlabJob>, GitlabBackendError> {
        self.record_credential("play_job", credential);
        if project_id != 42 || job_id != 9002 {
            return Err(GitlabBackendError::NotFound);
        }
        Ok(GitlabBackendResponse {
            value: job_fixture(9002, 321, "feature/rest", "pending"),
            status: 201,
            duration_ms: 31,
        })
    }
}

fn branch_fixture(name: &str) -> GitlabBranch {
    GitlabBranch {
        name: name.to_string(),
        merged: Some(false),
        protected: Some(name == "main"),
        default: Some(name == "main"),
        web_url: Some(format!(
            "https://gitlab.example.com/sip/service/-/tree/{name}"
        )),
        commit: Some(GitlabCommitSummary {
            id: TEST_SHA.to_string(),
            short_id: Some("01234567".to_string()),
            title: Some("initial commit".to_string()),
        }),
    }
}

fn protected_branch_access_level(description: &str) -> GitlabProtectedBranchAccessLevel {
    GitlabProtectedBranchAccessLevel {
        access_level: None,
        access_level_description: Some(description.to_string()),
        user_id: None,
        group_id: None,
        deploy_key_id: None,
    }
}

fn file_fixture(path: &str, ref_name: &str, last_commit_id: &str) -> GitlabFile {
    GitlabFile {
        file_name: path.rsplit('/').next().unwrap_or(path).to_string(),
        file_path: path.to_string(),
        size: 15,
        encoding: Some("base64".to_string()),
        content: Some("cmVhZG1lIGNvbnRlbnRz".to_string()),
        content_sha256: None,
        ref_name: Some(ref_name.to_string()),
        blob_id: Some("blob-id".to_string()),
        commit_id: Some(TEST_SHA.to_string()),
        last_commit_id: Some(last_commit_id.to_string()),
        execute_filemode: Some(false),
    }
}

fn gitlab_user(id: u64, username: &str, name: &str) -> GitlabUserSummary {
    GitlabUserSummary {
        id: Some(id),
        username: Some(username.to_string()),
        name: Some(name.to_string()),
        web_url: Some(format!("https://gitlab.example.com/{username}")),
    }
}

fn gitlab_milestone(title: &str) -> GitlabMilestoneSummary {
    GitlabMilestoneSummary {
        id: Some(300),
        iid: Some(3),
        title: Some(title.to_string()),
        state: Some("active".to_string()),
        due_date: Some("2026-07-01".to_string()),
    }
}

fn issue(project_id: u64, iid: u64, title: &str) -> GitlabIssue {
    GitlabIssue {
        id: Some(700 + iid),
        iid,
        project_id,
        title: Some(title.to_string()),
        description: Some(format!("{title} description")),
        state: Some("opened".to_string()),
        created_at: None,
        updated_at: None,
        author: None,
        assignees: None,
        labels: None,
        milestone: None,
        web_url: Some(format!(
            "https://gitlab.example.com/sip/service/-/issues/{iid}"
        )),
        project: None,
    }
}

fn merge_request(project_id: u64, iid: u64, title: &str) -> GitlabMergeRequest {
    GitlabMergeRequest {
        id: Some(500 + iid),
        iid,
        project_id,
        title: Some(title.to_string()),
        description: Some(format!("{title} description")),
        state: Some("opened".to_string()),
        source_branch: Some("feature/rest".to_string()),
        target_branch: Some("main".to_string()),
        sha: Some(TEST_SHA.to_string()),
        merge_status: Some("can_be_merged".to_string()),
        detailed_merge_status: Some("mergeable".to_string()),
        merge_commit_sha: None,
        squash_commit_sha: None,
        source_project_id: Some(project_id),
        target_project_id: Some(project_id),
        diff_refs: Some(agent_access_gitlab::GitlabDiffRefs {
            base_sha: Some(TEST_BASE_SHA.to_string()),
            start_sha: TEST_START_SHA.to_string(),
            head_sha: TEST_SHA.to_string(),
        }),
        changes_count: Some("1".to_string()),
        user_notes_count: Some(0),
        discussion_locked: Some(false),
        blocking_discussions_resolved: Some(true),
        has_conflicts: Some(false),
        prepared_at: Some("2026-01-01T00:00:00Z".to_string()),
        head_pipeline: None,
        created_at: None,
        updated_at: None,
        author: None,
        assignees: None,
        reviewers: None,
        labels: None,
        milestone: None,
        draft: None,
        web_url: Some(format!(
            "https://gitlab.example.com/sip/service/-/merge_requests/{iid}"
        )),
        project: None,
    }
}

fn issue_note(id: u64, body: &str, iid: u64) -> GitlabNote {
    note(id, body, "Issue", iid)
}

fn merge_request_note(id: u64, body: &str, iid: u64) -> GitlabNote {
    note(id, body, "MergeRequest", iid)
}

fn gitlab_stored_note_body(body: &str) -> String {
    body.chars()
        .filter(|character| *character != '\r')
        .collect::<String>()
        .trim_end()
        .to_string()
}

fn draft_note_fixture(
    id: u64,
    body: &str,
    position: Option<agent_access_gitlab::GitlabDiffPosition>,
) -> GitlabDraftNote {
    GitlabDraftNote {
        id,
        body: Some(body.to_string()),
        author_user_id: Some(3),
        merge_request_id: Some(500),
        resolve_discussion: None,
        discussion_id: None,
        commit_id: position.as_ref().map(|position| position.head_sha.clone()),
        position,
    }
}

fn draft_position_fixture() -> agent_access_gitlab::GitlabDiffPosition {
    agent_access_gitlab::GitlabDiffPosition {
        position_type: "text".to_string(),
        base_sha: Some(TEST_BASE_SHA.to_string()),
        start_sha: TEST_START_SHA.to_string(),
        head_sha: TEST_SHA.to_string(),
        old_path: "src/old.rs".to_string(),
        new_path: "src/new.rs".to_string(),
        old_line: None,
        new_line: Some(34),
        line_range: None,
        width: None,
        height: None,
        x: None,
        y: None,
    }
}

fn note(id: u64, body: &str, noteable_type: &str, noteable_iid: u64) -> GitlabNote {
    GitlabNote {
        id,
        body: Some(body.to_string()),
        noteable_type: Some(noteable_type.to_string()),
        noteable_iid: Some(noteable_iid),
        noteable_id: Some(if noteable_type == "Issue" { 700 } else { 500 }),
        project_id: Some(42),
        resolved: None,
        resolvable: None,
        note_type: None,
        commit_id: None,
        position: None,
        resolved_by: None,
        resolved_at: None,
        suggestions: Vec::new(),
        author_user_id: Some(314),
        author_username: Some("service-user".to_string()),
        created_at: Some("2026-01-01T00:00:00Z".to_string()),
        updated_at: Some("2026-01-01T00:00:00Z".to_string()),
        system: Some(false),
        confidential: Some(false),
    }
}

fn discussion(id: &str, body: &str, iid: u64) -> GitlabDiscussion {
    let mut note = merge_request_note(900, body, iid);
    note.note_type = Some("DiffNote".to_string());
    note.commit_id = Some(TEST_SHA.to_string());
    note.resolvable = Some(true);
    note.resolved = Some(true);
    note.resolved_by = Some(gitlab_user(17, "reviewer", "Review User"));
    note.resolved_at = Some("2026-06-05T14:00:00.000Z".to_string());
    note.position = Some(agent_access_gitlab::GitlabDiffPosition {
        position_type: "text".to_string(),
        base_sha: Some(TEST_BASE_SHA.to_string()),
        start_sha: TEST_START_SHA.to_string(),
        head_sha: TEST_SHA.to_string(),
        old_path: "src/old.rs".to_string(),
        new_path: "src/new.rs".to_string(),
        old_line: Some(31),
        new_line: Some(34),
        line_range: Some(agent_access_gitlab::GitlabLineRange {
            start: agent_access_gitlab::GitlabLineRangePoint {
                line_code: "line-code-31-34".to_string(),
                line_type: Some("old".to_string()),
                old_line: Some(31),
                new_line: Some(34),
            },
            end: agent_access_gitlab::GitlabLineRangePoint {
                line_code: "line-code-33-36".to_string(),
                line_type: Some("new".to_string()),
                old_line: Some(33),
                new_line: Some(36),
            },
        }),
        width: None,
        height: None,
        x: None,
        y: None,
    });
    note.suggestions = vec![
        agent_access_gitlab::GitlabSuggestion {
            id: 456,
            from_line: 34,
            to_line: 36,
            applicable: true,
            applied: false,
            from_content: "unsafe_call()".to_string(),
            to_content: "safe_call()".to_string(),
        },
        suggestion_fixture(457, false),
    ];
    GitlabDiscussion {
        id: id.to_string(),
        individual_note: Some(true),
        notes: vec![note],
    }
}

fn suggestion_fixture(id: u64, applied: bool) -> agent_access_gitlab::GitlabSuggestion {
    agent_access_gitlab::GitlabSuggestion {
        id,
        from_line: 34,
        to_line: 36,
        applicable: !applied,
        applied,
        from_content: "unsafe_call()".to_string(),
        to_content: "safe_call()".to_string(),
    }
}

fn approval_rule_fixture() -> GitlabApprovalRule {
    GitlabApprovalRule {
        id: 71,
        name: "Security approval".to_string(),
        rule_type: Some("regular".to_string()),
        approvals_required: 1,
        approved: Some(false),
        eligible_approvers: vec![gitlab_user(3, "carol", "Carol")],
        approved_by: Vec::new(),
        users: vec![gitlab_user(3, "carol", "Carol")],
        groups: Vec::new(),
        overridden: Some(false),
        contains_hidden_groups: Some(false),
        code_owner: Some(true),
        section: Some("Security".to_string()),
        source_rule: Some(GitlabApprovalRuleSource {
            approvals_required: 2,
        }),
    }
}

fn live_shaped_discussion(
    id: &str,
    note_id: u64,
    body: &str,
    iid: u64,
    resolved: Option<bool>,
) -> GitlabDiscussion {
    let mut value = discussion(id, body, iid);
    let note = &mut value.notes[0];
    note.id = note_id;
    note.noteable_iid = None;
    note.resolvable = resolved.map(|_| true);
    note.resolved = resolved;
    value
}

fn test_commit() -> GitlabCommit {
    GitlabCommit {
        id: TEST_SHA.to_string(),
        short_id: Some("01234567".to_string()),
        title: Some("initial commit".to_string()),
        message: Some("initial commit\n".to_string()),
        author_name: Some("Example User".to_string()),
        authored_date: Some("2026-01-01T00:00:00Z".to_string()),
        committed_date: Some("2026-01-01T00:00:00Z".to_string()),
        web_url: Some(format!(
            "https://gitlab.example.com/sip/service/-/commit/{TEST_SHA}"
        )),
    }
}

fn diff_file_fixture() -> GitlabDiffFile {
    GitlabDiffFile {
        old_path: "src/old.rs".to_string(),
        new_path: "src/new.rs".to_string(),
        old_mode: Some("100644".to_string()),
        new_mode: Some("100644".to_string()),
        diff: Some("@@ -31,3 +34,3 @@\n-unsafe_call()\n+safe_call()".to_string()),
        new_file: Some(false),
        renamed_file: Some(true),
        deleted_file: Some(false),
        generated_file: Some(false),
        collapsed: Some(false),
        too_large: Some(false),
    }
}

fn diff_version_fixture(include_contents: bool) -> GitlabDiffVersion {
    GitlabDiffVersion {
        id: 77,
        merge_request_id: 500,
        head_commit_sha: TEST_SHA.to_string(),
        base_commit_sha: TEST_BASE_SHA.to_string(),
        start_commit_sha: TEST_START_SHA.to_string(),
        created_at: Some("2026-06-03T12:01:00.000Z".to_string()),
        state: Some("collected".to_string()),
        real_size: Some("1".to_string()),
        patch_id_sha: Some("cccccccccccccccccccccccccccccccccccccccc".to_string()),
        commits: if include_contents {
            vec![test_commit()]
        } else {
            Vec::new()
        },
        diffs: if include_contents {
            vec![diff_file_fixture()]
        } else {
            Vec::new()
        },
    }
}

fn diff_version_summary_fixture() -> GitlabDiffVersionSummary {
    GitlabDiffVersionSummary {
        id: 77,
        merge_request_id: 500,
        head_commit_sha: TEST_SHA.to_string(),
        base_commit_sha: TEST_BASE_SHA.to_string(),
        start_commit_sha: TEST_START_SHA.to_string(),
        created_at: Some("2026-06-03T12:01:00.000Z".to_string()),
        state: Some("collected".to_string()),
        real_size: Some("1".to_string()),
        patch_id_sha: Some("cccccccccccccccccccccccccccccccccccccccc".to_string()),
    }
}

fn pipeline_fixture(id: u64, ref_name: &str, status: &str) -> GitlabPipeline {
    GitlabPipeline {
        id,
        iid: Some(id - 300),
        project_id: 42,
        ref_name: Some(ref_name.to_string()),
        sha: Some(TEST_SHA.to_string()),
        status: Some(status.to_string()),
        source: Some("push".to_string()),
        web_url: Some(format!(
            "https://gitlab.example.com/sip/service/-/pipelines/{id}"
        )),
        created_at: Some("2026-01-01T00:00:00Z".to_string()),
        updated_at: Some("2026-01-01T00:01:00Z".to_string()),
    }
}

fn job_fixture(id: u64, pipeline_id: u64, ref_name: &str, status: &str) -> GitlabJob {
    GitlabJob {
        id,
        name: Some("test".to_string()),
        status: Some(status.to_string()),
        stage: Some("test".to_string()),
        ref_name: Some(ref_name.to_string()),
        pipeline_id: Some(pipeline_id),
        project_id: Some(42),
        trace_size: Some(18),
        web_url: Some(format!(
            "https://gitlab.example.com/sip/service/-/jobs/{id}"
        )),
        created_at: Some("2026-01-01T00:00:00Z".to_string()),
        started_at: Some("2026-01-01T00:01:00Z".to_string()),
        finished_at: Some("2026-01-01T00:02:00Z".to_string()),
    }
}

fn gitlab_cli(base_url: &str) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_agent-access"));
    command.args([
        "--url",
        base_url,
        "--token-value",
        "agent-token",
        "--identity-header",
        "X-Agent-Access-Identity-Token",
        "--identity-scheme",
        "raw",
    ]);
    command
}

fn take_backend_operations(backend: &StubGitlabBackend) -> Vec<String> {
    std::mem::take(&mut *backend.credential_observations.lock().unwrap())
        .into_iter()
        .map(|observation| observation.operation)
        .collect()
}

async fn invoke_gitlab(
    client: &reqwest::Client,
    base_url: &str,
    action: &str,
    request_id: &str,
    body: serde_json::Value,
) -> serde_json::Value {
    let (status, body) = invoke_gitlab_outcome(client, base_url, action, request_id, body).await;
    assert_eq!(status, reqwest::StatusCode::OK, "{action}: {body}");
    body
}

async fn invoke_gitlab_outcome(
    client: &reqwest::Client,
    base_url: &str,
    action: &str,
    request_id: &str,
    body: serde_json::Value,
) -> (reqwest::StatusCode, serde_json::Value) {
    let response = client
        .post(format!("{base_url}/v1/invoke/gitlab/{action}"))
        .header("X-Agent-Access-Request-Id", request_id)
        .header("X-Agent-Access-Identity-Token", "agent-token")
        .json(&body)
        .send()
        .await
        .unwrap();
    let status = response.status();
    let body = response.json::<serde_json::Value>().await.unwrap();
    (status, body)
}

fn backend_operation_count(backend: &StubGitlabBackend, operation: &str) -> usize {
    backend
        .credential_observations
        .lock()
        .unwrap()
        .iter()
        .filter(|observation| observation.operation == operation)
        .count()
}

fn assert_review_context(response: &serde_json::Value, mode: &str, binding: &str) {
    assert_eq!(
        response["result"]["reviewContext"],
        serde_json::json!({
            "credentialMode": mode,
            "credentialBinding": binding,
            "upstreamActor": { "id": 3, "username": "carol" }
        })
    );
}

fn provider_gitlab_audit_for_action(broker: &RunningBroker, action: &str) -> serde_json::Value {
    broker
        .audit()
        .unwrap()
        .records()
        .into_iter()
        .find_map(|record| {
            (record["action"] == action && record["providerAudit"]["gitlab"].is_object())
                .then(|| record["providerAudit"]["gitlab"].clone())
        })
        .unwrap_or_else(|| panic!("missing GitLab provider audit for {action}"))
}

fn assert_mutation_verification_failure(
    status: reqwest::StatusCode,
    body: &serde_json::Value,
    stage: &str,
    safe_locators: serde_json::Value,
) {
    assert_eq!(status, reqwest::StatusCode::CONFLICT, "{body}");
    assert_eq!(body["decision"], "error");
    assert_eq!(body["reasonCode"], "mutation_verification_failed");
    assert_eq!(
        body["error"],
        serde_json::json!({"message":"upstream mutation could not be fully verified"})
    );
    assert_eq!(
        body["result"],
        serde_json::json!({
            "mutationStatus":"applied_unverified",
            "retrySafe":false,
            "verificationStage":stage,
            "safeLocators":safe_locators
        })
    );
}

/// Starts the broker assembly on `document`, serving `gitlab` in place of
/// the GitLab provider its configuration would build.
async fn start_broker(
    document: &GitlabDocument,
    gitlab: agent_access_provider::ServiceProvider,
) -> RunningBroker {
    start_isolated_broker(document, Some(gitlab)).await
}

/// Starts the broker assembly on `document` with the GitLab provider its
/// configuration builds.
async fn start_registered_broker(document: &GitlabDocument) -> RunningBroker {
    start_isolated_broker(document, None).await
}

async fn start_isolated_broker(
    document: &GitlabDocument,
    gitlab: Option<agent_access_provider::ServiceProvider>,
) -> RunningBroker {
    let application = IsolatedBroker::new(
        agent_access_broker::composition().unwrap(),
        agent_access_broker::build_identity(),
    )
    .unwrap();
    let config = document.render(application.directory());
    let application = application.config_document(config);
    let application = match gitlab {
        Some(gitlab) => application.provider_fixture("gitlab", ProviderFixture::instance(gitlab)),
        None => application,
    };
    application.start().await.unwrap()
}

async fn stop(broker: RunningBroker) {
    broker.shutdown();
    broker.join().await.unwrap();
}

/// Who may call the broker.
#[derive(Clone, Copy, Debug)]
enum GitlabCallers {
    /// Anonymous callers.
    Anonymous,
    /// The static principal `agent-one`, identified by `agent-token` and a
    /// member of group `agents`, whose own GitLab credential is
    /// `gitlab-per-user-token`.
    AgentOne,
}

/// One `[[policy.grants]]` entry for the GitLab service.
#[derive(Clone, Debug)]
struct GitlabGrant {
    subjects: Vec<String>,
    actions: Vec<String>,
    /// Resource entry IDs.
    resources: Vec<String>,
    credential_mode: String,
}

/// A broker configuration for the GitLab smokes. [`GitlabDocument::render`]
/// writes it as a TOML document with the GitLab service credential
/// `gitlab-service-token`, the read-only lookup credential
/// `gitlab-lookup-token`, the `sip/service` and `fork/service` repository
/// resources, JSONL audit and an upload spool, all in the fixture directory.
#[derive(Clone, Debug)]
struct GitlabDocument {
    callers: GitlabCallers,
    /// `[providers.gitlab]`.
    provider: GitlabProviderConfig,
    grants: Vec<GitlabGrant>,
    /// `limits.max_upstream_response_bytes`, when not the default.
    max_upstream_response_bytes: Option<u64>,
    /// `limits.max_download_bytes`, when not the default.
    max_download_bytes: Option<u64>,
    /// `limits.invocations.default`: requests per window.
    default_invocation_limit: Option<(u64, &'static str)>,
}

/// Anonymous callers use the service credential for every GitLab action on
/// `sip/service`.
fn gitlab_document() -> GitlabDocument {
    GitlabDocument {
        callers: GitlabCallers::Anonymous,
        provider: gitlab_provider_config(2),
        grants: vec![GitlabGrant {
            subjects: vec!["group:anonymous".to_string()],
            actions: gitlab_actions(),
            resources: resource_ids(&["repository-sip-service"]),
            credential_mode: "service".to_string(),
        }],
        max_upstream_response_bytes: None,
        max_download_bytes: None,
        default_invocation_limit: None,
    }
}

/// `agent-one` uses its own credential for every GitLab action on
/// `sip/service`.
fn gitlab_per_user_document() -> GitlabDocument {
    let mut document = gitlab_document();
    document.callers = GitlabCallers::AgentOne;
    for grant in &mut document.grants {
        grant.subjects = vec!["user:agent-one".to_string()];
        grant.credential_mode = "per_user".to_string();
    }
    document
}

fn gitlab_actions() -> Vec<String> {
    [
        "project.view",
        "project.upload",
        "issue.view",
        "issue.search",
        "issue.create",
        "issue.update",
        "issue.note.list",
        "issue.note.view",
        "issue.note.add",
        "issue.note.update",
        "issue.note.delete",
        "merge_request.view",
        "merge_request.search",
        "merge_request.create",
        "merge_request.update",
        "merge_request.note.list",
        "merge_request.note.view",
        "merge_request.note.add",
        "merge_request.note.update",
        "merge_request.note.delete",
        "merge_request.reviewer.list",
        "merge_request.commit.list",
        "merge_request.pipeline.list",
        "merge_request.diff.list",
        "merge_request.diff.raw.download",
        "merge_request.diff_version.list",
        "merge_request.diff_version.view",
        "merge_request.discussion.list",
        "merge_request.discussion.view",
        "merge_request.discussion.add",
        "merge_request.discussion.inline.add",
        "merge_request.discussion.note.add",
        "merge_request.draft_note.list",
        "merge_request.draft_note.view",
        "merge_request.draft_note.add",
        "merge_request.draft_note.update",
        "merge_request.draft_note.delete",
        "merge_request.draft_note.publish",
        "merge_request.draft_note.publish_all",
        "merge_request.review.submit",
        "merge_request.approval.view",
        "merge_request.approval_state.view",
        "merge_request.approval_rule.list",
        "merge_request.approval_rule.view",
        "merge_request.approve",
        "merge_request.unapprove",
        "merge_request.suggestion.apply",
        "merge_request.suggestion.batch_apply",
        "merge_request.discussion.note.update",
        "merge_request.discussion.note.delete",
        "merge_request.discussion.resolve",
        "merge_request.discussion.reopen",
        "merge_request.merge",
        "branch.list",
        "branch.view",
        "branch.create",
        "protected_branch.list",
        "protected_branch.view",
        "protected_branch.verify",
        "file.view",
        "file.raw.download",
        "file.create",
        "file.update",
        "file.delete",
        "commit.list",
        "commit.view",
        "commit.create",
        "pipeline.list",
        "pipeline.view",
        "pipeline.run",
        "pipeline.retry",
        "pipeline.cancel",
        "job.list",
        "job.view",
        "job.trace.download",
        "job.retry",
        "job.cancel",
        "job.play",
        "webhook.list",
        "webhook.view",
        "webhook.create",
        "webhook.update",
        "webhook.delete",
        "webhook.test",
        "webhook.event.list",
        "webhook.event.resend",
        "webhook.custom_header.set",
        "webhook.custom_header.delete",
    ]
    .into_iter()
    .map(ToString::to_string)
    .collect()
}

fn resource_ids(ids: &[&str]) -> Vec<String> {
    ids.iter().map(ToString::to_string).collect()
}

impl GitlabDocument {
    /// The TOML document, writing its secrets privately to `directory`.
    fn render(&self, directory: &FixtureDir) -> String {
        let mut document = format!(
            r#"
[secret_outputs]
mode = "raw"

[credentials.service.gitlab]
type = "bearer_token"
token_ref = {service_token}

[credentials.lookup.gitlab]
type = "bearer_token"
token_ref = {lookup_token}
read_only = true
"#,
            service_token = secret_ref(
                directory,
                "gitlab-service-token.txt",
                "gitlab-service-token"
            ),
            lookup_token = secret_ref(directory, "gitlab-lookup-token.txt", "gitlab-lookup-token"),
        );
        match self.callers {
            GitlabCallers::Anonymous => document.push_str(
                r#"
[identity]
mode = "anonymous"
authority = "toml"
"#,
            ),
            GitlabCallers::AgentOne => {
                let token = directory
                    .secret_file("gitlab-per-user-token.txt", "gitlab-per-user-token")
                    .unwrap();
                let credentials = serde_json::json!({"credentials": [{
                    "principal": "agent-one",
                    "type": "bearer_token",
                    "token_ref": format!("file:{}", token.display()),
                }]});
                let store = directory
                    .secret_file("gitlab-per-user-store.json", credentials.to_string())
                    .unwrap();
                document.push_str(&format!(
                    r#"
[credentials.per_user.gitlab]
type = "secret_store"
provider = "local_file"
path = {store}

[identity]
mode = "required"
authority = "toml"

[[identity.sources]]
name = "local"
type = "static_principals"
header = "X-Agent-Access-Identity-Token"
scheme = "raw"

[[identity.sources.principals]]
principal = "agent-one"
token_refs = [{agent_token}]

[[identity.groups]]
id = "agents"
status = "active"
members = ["agent-one"]
"#,
                    store = toml_string(store.display()),
                    agent_token = secret_ref(directory, "gitlab-agent-token.txt", "agent-token"),
                ));
            }
        }
        document.push_str(&gitlab_provider_toml(&self.provider));
        document.push_str(&format!(
            r#"
[limits]
upload_spool_dir = {spool}
"#,
            spool = toml_string(directory.join("upload-spool").display()),
        ));
        if let Some(bytes) = self.max_upstream_response_bytes {
            document.push_str(&format!("max_upstream_response_bytes = {bytes}\n"));
        }
        if let Some(bytes) = self.max_download_bytes {
            document.push_str(&format!("max_download_bytes = {bytes}\n"));
        }
        if let Some((requests, window)) = self.default_invocation_limit {
            document.push_str(&format!(
                r#"
[limits.invocations.default]
requests = {requests}
window = {window}
"#,
                window = toml_string(window),
            ));
        }
        document.push_str(&format!(
            r#"
[audit]
type = "jsonl"
path = {audit}

[policy]
authority = "toml"
default_decision = "deny"

[[policy.resources]]
id = "repository-sip-service"
resource_type = {resource_type}
selector = {{ kind = "exact", value = "sip/service" }}
allowed_execution_contexts = ["default"]

[[policy.resources]]
id = "repository-fork-service"
resource_type = {resource_type}
selector = {{ kind = "exact", value = "fork/service" }}
allowed_execution_contexts = ["default"]
"#,
            audit = toml_string(directory.join("audit.jsonl").display()),
            resource_type = toml_string(GIT_REPOSITORY_RESOURCE.id().as_str()),
        ));
        for grant in &self.grants {
            document.push_str(&format!(
                r#"
[[policy.grants]]
subjects = {subjects}
service = "gitlab"
actions = {actions}
resources = {{ resource_ids = {resources} }}
credential_mode = {credential_mode}
"#,
                subjects = toml_strings(&grant.subjects),
                actions = toml_strings(&grant.actions),
                resources = toml_strings(&grant.resources),
                credential_mode = toml_string(&grant.credential_mode),
            ));
        }
        document
    }
}

/// `[providers.gitlab]` with every setting of `config`.
fn gitlab_provider_toml(config: &GitlabProviderConfig) -> String {
    let GitlabProviderConfig {
        provisioning,
        attachments,
        api_base_url,
        web_base_url,
        egress_proxy,
        allowed_upstream_hosts,
        webhooks,
        content,
        search,
    } = config;
    assert!(
        egress_proxy.is_none(),
        "the GitLab smokes configure no egress proxy"
    );
    format!(
        r#"
[providers.gitlab]
api_base_url = {api_base_url}
web_base_url = {web_base_url}
allowed_upstream_hosts = {allowed_upstream_hosts}
provisioning = {{ enabled = {enabled}, max_role = {max_role}, max_token_lifetime_days = {max_token_lifetime_days}, allowed_token_scopes = {allowed_token_scopes} }}
attachments = {{ max_bytes = {max_bytes}, max_total_bytes = {max_total_bytes}, media_types = {media_types} }}
webhooks = {{ allowed_destinations = {allowed_destinations}, allow_disable_ssl_verification = {allow_disable_ssl_verification} }}
content = {{ max_body_bytes = {max_body_bytes}, max_commit_actions = {max_commit_actions}, max_file_bytes = {max_file_bytes}, max_raw_download_bytes = {max_raw_download_bytes} }}
search = {{ max_results = {max_results}, default_engine = {default_engine}, max_candidate_pages = {max_candidate_pages}, max_upstream_requests = {max_upstream_requests}, max_scan_bytes = {max_scan_bytes}, engines = {{ basic = {{ project_categories = {basic_project_categories}, instance_categories = {basic_instance_categories} }}, advanced = {{ project_categories = {advanced_project_categories}, instance_categories = {advanced_instance_categories} }}, zoekt = {{ project_categories = {zoekt_project_categories}, instance_categories = {zoekt_instance_categories} }} }} }}
"#,
        api_base_url = toml_string(api_base_url),
        web_base_url = toml_string(web_base_url),
        allowed_upstream_hosts = toml_strings(allowed_upstream_hosts),
        enabled = provisioning.enabled,
        max_role = toml_string(provisioning.max_role.as_str()),
        max_token_lifetime_days = provisioning.max_token_lifetime_days,
        allowed_token_scopes = toml_strings(&provisioning.allowed_token_scopes),
        max_bytes = attachments.max_bytes,
        max_total_bytes = attachments.max_total_bytes,
        media_types = toml_strings(&attachments.media_types),
        allowed_destinations = toml_strings(&webhooks.allowed_destinations),
        allow_disable_ssl_verification = webhooks.allow_disable_ssl_verification,
        max_body_bytes = content.max_body_bytes,
        max_commit_actions = content.max_commit_actions,
        max_file_bytes = content.max_file_bytes,
        max_raw_download_bytes = content.max_raw_download_bytes,
        max_results = search.max_results,
        default_engine = toml_string(&search.default_engine),
        max_candidate_pages = search.max_candidate_pages,
        max_upstream_requests = search.max_upstream_requests,
        max_scan_bytes = search.max_scan_bytes,
        basic_project_categories = toml_strings(&search.engines.basic.project_categories),
        basic_instance_categories = toml_strings(&search.engines.basic.instance_categories),
        advanced_project_categories = toml_strings(&search.engines.advanced.project_categories),
        advanced_instance_categories = toml_strings(&search.engines.advanced.instance_categories),
        zoekt_project_categories = toml_strings(&search.engines.zoekt.project_categories),
        zoekt_instance_categories = toml_strings(&search.engines.zoekt.instance_categories),
    )
}

/// A TOML basic string holding `value`.
fn toml_string(value: impl std::fmt::Display) -> String {
    serde_json::to_string(&value.to_string()).unwrap()
}

/// A TOML array of basic strings.
fn toml_strings(values: &[String]) -> String {
    serde_json::to_string(values).unwrap()
}

/// A `file:` secret reference to a new private file in `directory`.
fn secret_ref(directory: &FixtureDir, name: &str, contents: &str) -> String {
    let path = directory.secret_file(name, contents).unwrap();
    toml_string(format_args!("file:{}", path.display()))
}

fn gitlab_provider_config(max_results: u32) -> GitlabProviderConfig {
    GitlabProviderConfig {
        provisioning: agent_access_gitlab::GitlabProvisioningConfig::default(),
        api_base_url: "https://gitlab.example.com/api/v4".to_string(),
        web_base_url: "https://gitlab.example.com".to_string(),
        egress_proxy: None,
        allowed_upstream_hosts: vec!["https://gitlab.example.com/api/v4/**".to_string()],
        webhooks: GitlabWebhooksConfig {
            allowed_destinations: vec!["https://hooks.example.com/**".to_string()],
            allow_disable_ssl_verification: false,
        },
        attachments: Default::default(),
        content: GitlabContentConfig::default(),
        search: agent_access_gitlab::GitlabSearchConfig {
            max_results,
            ..Default::default()
        },
    }
}

fn assert_success(label: &str, output: &std::process::Output) {
    assert!(
        output.status.success(),
        "{label} failed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn assert_atomic_cli_error(label: &str, output: &std::process::Output, secret: &str) {
    assert!(
        !output.status.success(),
        "{label} unexpectedly succeeded: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let value: serde_json::Value = serde_json::from_slice(&output.stdout)
        .unwrap_or_else(|error| panic!("{label} emitted partial/non-JSON stdout: {error}"));
    assert_eq!(value["reasonCode"], "upstream_protocol_failed", "{label}");
    assert!(!value.to_string().contains(secret), "{label} leaked secret");
    assert!(
        !String::from_utf8_lossy(&output.stderr).contains(secret),
        "{label} leaked secret to stderr"
    );
}

/// Asserts the operations the stub backend served and the bearer token each
/// one received.
fn assert_credential_observations(backend: &StubGitlabBackend, expected: &[(&str, &str)]) {
    let actual = backend
        .credential_observations
        .lock()
        .unwrap()
        .iter()
        .map(|observation| {
            (
                observation.operation.clone(),
                observation.credential.clone(),
            )
        })
        .collect::<Vec<_>>();
    let expected = expected
        .iter()
        .map(|(operation, token)| (operation.to_string(), bearer_credential(token)))
        .collect::<Vec<_>>();
    assert_eq!(actual, expected);
}

#[path = "support/temp_dirs.rs"]
mod temp_dirs;
use temp_dirs::temp_path;

fn stub_backend() -> Arc<StubGitlabBackend> {
    Arc::new(StubGitlabBackend {
        uploaded_projects: Mutex::new(Vec::new()),
        projects: BTreeMap::from([
            (
                "sip/service".to_string(),
                GitlabProject {
                    id: 42,
                    path_with_namespace: "sip/service".to_string(),
                    name: Some("service".to_string()),
                    web_url: Some("https://gitlab.example.com/sip/service".to_string()),
                    default_branch: Some("main".to_string()),
                    visibility: Some("private".to_string()),
                    archived: Some(false),
                    description: None,
                    last_activity_at: None,
                    star_count: None,
                },
            ),
            (
                "secret/service".to_string(),
                GitlabProject {
                    id: 99,
                    path_with_namespace: "secret/service".to_string(),
                    name: Some("secret".to_string()),
                    web_url: Some("https://gitlab.example.com/secret/service".to_string()),
                    default_branch: Some("main".to_string()),
                    visibility: Some("private".to_string()),
                    archived: Some(false),
                    description: None,
                    last_activity_at: None,
                    star_count: None,
                },
            ),
            (
                "141".to_string(),
                GitlabProject {
                    id: 141,
                    path_with_namespace: "fork/service".to_string(),
                    name: Some("fork".to_string()),
                    web_url: Some("https://gitlab.example.com/fork/service".to_string()),
                    default_branch: Some("feature/rest".to_string()),
                    visibility: Some("private".to_string()),
                    archived: Some(false),
                    description: None,
                    last_activity_at: None,
                    star_count: None,
                },
            ),
            (
                "142".to_string(),
                GitlabProject {
                    id: 142,
                    path_with_namespace: "fork/service".to_string(),
                    name: Some("fork".to_string()),
                    web_url: Some("https://gitlab.example.com/fork/service".to_string()),
                    default_branch: Some("feature/rest".to_string()),
                    visibility: Some("private".to_string()),
                    archived: Some(false),
                    description: None,
                    last_activity_at: None,
                    star_count: None,
                },
            ),
        ]),
        branches: Mutex::new(BTreeMap::from([
            ("main".to_string(), branch_fixture("main")),
            ("feature/rest".to_string(), branch_fixture("feature/rest")),
            ("release/next".to_string(), branch_fixture("release/next")),
        ])),
        files: Mutex::new(BTreeMap::from([
            (
                ("main".to_string(), "README.md".to_string()),
                file_fixture(
                    "README.md",
                    "main",
                    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                ),
            ),
            (
                ("main".to_string(), "docs/from-main.md".to_string()),
                file_fixture(
                    "docs/from-main.md",
                    "main",
                    "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
                ),
            ),
            (
                ("feature/rest".to_string(), "docs/existing.md".to_string()),
                file_fixture(
                    "docs/existing.md",
                    "feature/rest",
                    "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                ),
            ),
            (
                ("feature/rest".to_string(), "docs/old.md".to_string()),
                file_fixture(
                    "docs/old.md",
                    "feature/rest",
                    "cccccccccccccccccccccccccccccccccccccccc",
                ),
            ),
        ])),
        issue_note_body: Mutex::new(None),
        discussion_body: Mutex::new(None),
        published_discussions: Mutex::new(Vec::new()),
        discussion_pagination_mode: Mutex::new("normal".to_string()),
        draft_notes: Mutex::new(vec![draft_note_fixture(801, "pending review draft", None)]),
        next_draft_note_id: Mutex::new(802),
        current_user_id: Mutex::new(3),
        current_user_username: Mutex::new("carol".to_string()),
        reviewer_state: Mutex::new("requested_changes".to_string()),
        reviewer_fixture_mode: Mutex::new("normal".to_string()),
        gitlab_version_value: Mutex::new("19.2.0-ee".to_string()),
        fail_gitlab_version: Mutex::new(false),
        diff_version_state: Mutex::new("collected".to_string()),
        approval_diff_match_page: Mutex::new(1),
        approval_patch_id_sha: Mutex::new(Some(TEST_PATCH_ID_SHA.to_string())),
        merge_request_prepared_at: Mutex::new(Some("2026-06-03T12:01:00.000Z".to_string())),
        merge_request_detailed_status: Mutex::new(Some("mergeable".to_string())),
        approval_readback_mode: Mutex::new("normal".to_string()),
        approval_mutation_mode: Mutex::new("normal".to_string()),
        actor_formally_approved: Mutex::new(false),
        aggregate_approval_override: Mutex::new(None),
        fork_lookup_source_project_id: Mutex::new(None),
        fork_execution_source_project_id: Mutex::new(None),
        fork_source_drift_after_first_read: Mutex::new(false),
        merge_request_read_count: Mutex::new(0),
        suggestions_applied: Mutex::new(false),
        retain_unapplied_suggestions: Mutex::new(false),
        discussion_proof_mismatch: Mutex::new(false),
        malformed_inline_response: Mutex::new(false),
        fail_discussion_reply_write: Mutex::new(false),
        malformed_draft_update_readback: Mutex::new(false),
        drop_draft_position_on_update: Mutex::new(false),
        retain_deleted_draft: Mutex::new(false),
        retain_published_draft: Mutex::new(false),
        fail_bulk_publish_without_apply: Mutex::new(false),
        fail_bulk_publish_after_apply: Mutex::new(false),
        skip_reviewer_state_update: Mutex::new(false),
        malformed_review_summary: Mutex::new(false),
        protected_branches: Mutex::new(vec![
            GitlabProtectedBranch {
                id: Some(1),
                name: "main".to_string(),
                allow_force_push: Some(false),
                code_owner_approval_required: Some(false),
                inherited: Some(false),
                push_access_levels: vec![protected_branch_access_level("Maintainers")],
                merge_access_levels: vec![protected_branch_access_level(
                    "Developers + Maintainers",
                )],
                unprotect_access_levels: vec![protected_branch_access_level("Maintainers")],
            },
            GitlabProtectedBranch {
                id: Some(2),
                name: "release/*".to_string(),
                allow_force_push: Some(false),
                code_owner_approval_required: Some(false),
                inherited: Some(false),
                push_access_levels: vec![protected_branch_access_level("No one")],
                merge_access_levels: vec![protected_branch_access_level("Maintainers")],
                unprotect_access_levels: vec![protected_branch_access_level("Maintainers")],
            },
        ]),
        protected_branch_list_has_next_page: Mutex::new(false),
        merge_response_description: Mutex::new(None),
        merge_conflict_after_preflight: Mutex::new(false),
        credential_observations: Mutex::new(vec![]),
        last_issue_search: Mutex::new(None),
        last_issue_create: Mutex::new(None),
        last_issue_update: Mutex::new(None),
        last_issue_note_list: Mutex::new(None),
        last_issue_note_add: Mutex::new(None),
        last_issue_note_update: Mutex::new(None),
        last_issue_note_delete: Mutex::new(None),
        last_merge_request_search: Mutex::new(None),
        last_merge_request_create: Mutex::new(None),
        last_merge_request_update: Mutex::new(None),
        last_merge_request_note_list: Mutex::new(None),
        last_merge_request_note_add: Mutex::new(None),
        last_merge_request_note_update: Mutex::new(None),
        last_merge_request_note_delete: Mutex::new(None),
        last_merge_request_discussion_list: Mutex::new(None),
        last_merge_request_reviewer_list: Mutex::new(None),
        last_merge_request_commit_list: Mutex::new(None),
        last_merge_request_pipeline_list: Mutex::new(None),
        last_merge_request_diff_list: Mutex::new(None),
        last_merge_request_diff_version_list: Mutex::new(None),
        last_merge_request_diff_version_view: Mutex::new(None),
        last_merge_request_discussion_add: Mutex::new(None),
        last_inline_discussion_add: Mutex::new(None),
        last_discussion_reply_add: Mutex::new(None),
        last_draft_note_create: Mutex::new(None),
        last_draft_note_update: Mutex::new(None),
        last_draft_bulk_publish: Mutex::new(None),
        last_review_summary: Mutex::new(None),
        last_approval_mutation: Mutex::new(None),
        last_suggestion_apply: Mutex::new(None),
        last_merge_request_discussion_note_update: Mutex::new(None),
        last_merge_request_discussion_note_delete: Mutex::new(None),
        last_merge_request_discussion_state_change: Mutex::new(None),
        last_merge_request_merge: Mutex::new(None),
        last_branch_list: Mutex::new(None),
        last_branch_create: Mutex::new(None),
        last_file_create: Mutex::new(None),
        last_file_update: Mutex::new(None),
        last_file_delete: Mutex::new(None),
        last_commit_list: Mutex::new(None),
        last_commit_create: Mutex::new(None),
        last_pipeline_list: Mutex::new(None),
        last_pipeline_run: Mutex::new(None),
        last_job_list: Mutex::new(None),
        webhooks: Mutex::new(BTreeMap::from([(42, webhook_fixture(42))])),
        next_webhook_id: Mutex::new(43),
        last_webhook_write: Mutex::new(None),
        last_webhook_header: Mutex::new(None),
        streamed_raw_diffs: Mutex::new(VecDeque::new()),
    })
}

fn webhook_fixture(id: u64) -> GitlabWebhook {
    GitlabWebhook {
        id,
        project_id: Some(42),
        url: "https://hooks.example.com/events".to_string(),
        name: Some("Agent receiver".to_string()),
        description: Some("CLI smoke".to_string()),
        created_at: Some("2026-08-30T12:00:00Z".to_string()),
        enable_ssl_verification: Some(true),
        alert_status: None,
        disabled_until: None,
        events: vec![GitlabWebhookEvent::Push],
        branch_filter_strategy: None,
        push_events_branch_filter: None,
        custom_webhook_template: None,
        custom_headers: Some(Vec::new()),
        url_variables: Some(Vec::new()),
        token_present: Some(false),
        signing_token_present: Some(false),
    }
}

fn apply_webhook_write(hook: &mut GitlabWebhook, request: &GitlabWebhookWriteRequest) {
    hook.url.clone_from(&request.url);
    if let Some(events) = &request.events {
        hook.events.clone_from(events);
    }
    if let Some(name) = &request.name {
        hook.name.clone_from(name);
    }
    if let Some(description) = &request.description {
        hook.description.clone_from(description);
    }
    if let Some(enable_ssl_verification) = request.enable_ssl_verification {
        hook.enable_ssl_verification = Some(enable_ssl_verification);
    }
    if let Some(branch_filter_strategy) = &request.branch_filter_strategy {
        hook.branch_filter_strategy = Some(branch_filter_strategy.clone());
    }
    if let Some(push_events_branch_filter) = &request.push_events_branch_filter {
        hook.push_events_branch_filter = Some(push_events_branch_filter.clone());
    }
    if let Some(custom_webhook_template) = &request.custom_webhook_template {
        hook.custom_webhook_template
            .clone_from(custom_webhook_template);
    }
    if request.token.is_some() {
        hook.token_present = Some(true);
    }
    if request.signing_token.is_some() {
        hook.signing_token_present = Some(true);
    }
}
