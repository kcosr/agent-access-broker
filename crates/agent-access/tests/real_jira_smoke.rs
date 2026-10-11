use std::process::Command;

#[test]
#[ignore = "requires a live broker configured for Jira and real credentials"]
fn real_broker_jira_read_smoke() {
    let broker_url = required_env("AGENT_ACCESS_REAL_BROKER_URL");
    let issue = required_env("AGENT_ACCESS_REAL_JIRA_ISSUE");
    let project = required_env("AGENT_ACCESS_REAL_JIRA_PROJECT");
    let comment_id = required_env("AGENT_ACCESS_REAL_JIRA_COMMENT_ID");

    let issue_view = Command::new(env!("CARGO_BIN_EXE_agent-access"))
        .args(["--url", &broker_url, "jira", "issue", "view", &issue])
        .output()
        .unwrap();
    assert!(
        issue_view.status.success(),
        "real Jira issue view failed: stdout={} stderr={}",
        String::from_utf8_lossy(&issue_view.stdout),
        String::from_utf8_lossy(&issue_view.stderr)
    );

    let search = Command::new(env!("CARGO_BIN_EXE_agent-access"))
        .args([
            "--url",
            &broker_url,
            "jira",
            "issue",
            "search",
            "--project",
            &project,
            "--jql",
            &format!("key = {issue}"),
            "--max-results",
            "1",
        ])
        .output()
        .unwrap();
    assert!(
        search.status.success(),
        "real Jira search failed: stdout={} stderr={}",
        String::from_utf8_lossy(&search.stdout),
        String::from_utf8_lossy(&search.stderr)
    );

    let attachments = Command::new(env!("CARGO_BIN_EXE_agent-access"))
        .args([
            "--url",
            &broker_url,
            "jira",
            "issue",
            "attachment",
            "list",
            &issue,
        ])
        .output()
        .unwrap();
    assert_success("real Jira attachment list", &attachments);
    let attachments_json: serde_json::Value = serde_json::from_slice(&attachments.stdout).unwrap();
    assert_eq!(attachments_json["decision"], "allow");
    assert!(
        attachments_json["result"]["attachments"]
            .as_array()
            .is_some()
    );

    let comments = Command::new(env!("CARGO_BIN_EXE_agent-access"))
        .args([
            "--url",
            &broker_url,
            "jira",
            "issue",
            "comment",
            "list",
            "--issue",
            &issue,
        ])
        .output()
        .unwrap();
    assert_success("real Jira comment list", &comments);
    let comments_json: serde_json::Value = serde_json::from_slice(&comments.stdout).unwrap();
    assert!(comments_json["result"]["comments"].as_array().is_some());

    let comment = Command::new(env!("CARGO_BIN_EXE_agent-access"))
        .args([
            "--url",
            &broker_url,
            "jira",
            "issue",
            "comment",
            "view",
            &comment_id,
            "--issue",
            &issue,
        ])
        .output()
        .unwrap();
    assert_success("real Jira comment view", &comment);
}

#[test]
#[ignore = "requires a live broker configured for Jira write credentials and mutates the issue"]
fn real_broker_jira_write_stream_verify_smoke() {
    let broker_url = required_env("AGENT_ACCESS_REAL_BROKER_URL");
    let issue = required_env("AGENT_ACCESS_REAL_JIRA_ISSUE");
    let comment_content_file = required_env("AGENT_ACCESS_REAL_JIRA_COMMENT_CONTENT_FILE");
    let comment_content_format = required_env("AGENT_ACCESS_REAL_JIRA_COMMENT_CONTENT_FORMAT");
    let attachment_file = required_env("AGENT_ACCESS_REAL_JIRA_ATTACHMENT_FILE");
    let attachment_content_type = required_env("AGENT_ACCESS_REAL_JIRA_ATTACHMENT_CONTENT_TYPE");

    let comment = Command::new(env!("CARGO_BIN_EXE_agent-access"))
        .args([
            "--url",
            &broker_url,
            "jira",
            "issue",
            "comment",
            "add",
            "--issue",
            &issue,
            "--content-file",
            &comment_content_file,
            "--content-format",
            &comment_content_format,
        ])
        .output()
        .unwrap();
    assert_success("real Jira comment add", &comment);
    let comment_json: serde_json::Value = serde_json::from_slice(&comment.stdout).unwrap();
    let comment_id = json_str(&comment_json, &["result", "comment", "commentId"]);

    let reply = Command::new(env!("CARGO_BIN_EXE_agent-access"))
        .args([
            "--url",
            &broker_url,
            "jira",
            "issue",
            "comment",
            "reply",
            &comment_id,
            "--issue",
            &issue,
            "--content-file",
            &comment_content_file,
            "--content-format",
            &comment_content_format,
        ])
        .output()
        .unwrap();
    assert_success("real Jira comment reply", &reply);
    let reply_json: serde_json::Value = serde_json::from_slice(&reply.stdout).unwrap();
    let reply_id = json_str(&reply_json, &["result", "comment", "commentId"]);
    assert_eq!(
        json_str(&reply_json, &["result", "comment", "parentCommentId"]),
        comment_id.as_str()
    );

    let update = Command::new(env!("CARGO_BIN_EXE_agent-access"))
        .args([
            "--url",
            &broker_url,
            "jira",
            "issue",
            "comment",
            "update",
            &comment_id,
            "--issue",
            &issue,
            "--content-file",
            &comment_content_file,
            "--content-format",
            &comment_content_format,
            "--notify-users",
            "false",
        ])
        .output()
        .unwrap();
    assert_success("real Jira comment update", &update);

    let property_value_path = std::env::temp_dir().join(format!(
        "agent-access-real-jira-comment-property-{}.json",
        std::process::id()
    ));
    std::fs::write(&property_value_path, r#"{"status":"real-smoke"}"#).unwrap();
    let property_key = "agent-access.real-smoke";
    let property_set = Command::new(env!("CARGO_BIN_EXE_agent-access"))
        .args([
            "--url",
            &broker_url,
            "jira",
            "issue",
            "comment",
            "property",
            "set",
            &comment_id,
            property_key,
            "--issue",
            &issue,
            "--value-file",
            property_value_path.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert_success("real Jira comment property set", &property_set);

    let property_get = Command::new(env!("CARGO_BIN_EXE_agent-access"))
        .args([
            "--url",
            &broker_url,
            "jira",
            "issue",
            "comment",
            "property",
            "get",
            &comment_id,
            property_key,
            "--issue",
            &issue,
        ])
        .output()
        .unwrap();
    assert_success("real Jira comment property get", &property_get);

    let property_delete = Command::new(env!("CARGO_BIN_EXE_agent-access"))
        .args([
            "--url",
            &broker_url,
            "jira",
            "issue",
            "comment",
            "property",
            "delete",
            &comment_id,
            property_key,
            "--issue",
            &issue,
        ])
        .output()
        .unwrap();
    assert_success("real Jira comment property delete", &property_delete);
    std::fs::remove_file(property_value_path).unwrap();

    let upload = Command::new(env!("CARGO_BIN_EXE_agent-access"))
        .args([
            "--url",
            &broker_url,
            "jira",
            "issue",
            "attach",
            &issue,
            &attachment_file,
            "--content-type",
            &attachment_content_type,
        ])
        .output()
        .unwrap();
    assert_success("real Jira attachment add", &upload);
    let upload_json: serde_json::Value = serde_json::from_slice(&upload.stdout).unwrap();
    let attachment_id = json_str(
        &upload_json,
        &["result", "attachments", "0", "attachmentId"],
    );

    let list = Command::new(env!("CARGO_BIN_EXE_agent-access"))
        .args([
            "--url",
            &broker_url,
            "jira",
            "issue",
            "attachment",
            "list",
            &issue,
        ])
        .output()
        .unwrap();
    assert_success("real Jira attachment list", &list);
    let list_json: serde_json::Value = serde_json::from_slice(&list.stdout).unwrap();
    assert!(
        attachment_list_contains(&list_json, &attachment_id),
        "uploaded attachment id {attachment_id} missing from list response: {}",
        list_json
    );

    let verify = Command::new(env!("CARGO_BIN_EXE_agent-access"))
        .args([
            "--url",
            &broker_url,
            "jira",
            "issue",
            "verify",
            &issue,
            "--expect-comment-id",
            &comment_id,
            "--expect-attachment-id",
            &attachment_id,
        ])
        .output()
        .unwrap();
    assert_success("real Jira verify", &verify);

    let output_path = std::env::temp_dir().join(format!(
        "agent-access-real-jira-download-{}-{attachment_id}",
        std::process::id()
    ));
    let download = Command::new(env!("CARGO_BIN_EXE_agent-access"))
        .args([
            "--url",
            &broker_url,
            "jira",
            "issue",
            "attachment",
            "download",
            &issue,
            &attachment_id,
            "--output",
            output_path.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert_success("real Jira attachment download", &download);
    let downloaded = std::fs::read(&output_path).unwrap();
    let uploaded = std::fs::read(&attachment_file).unwrap();
    assert_eq!(downloaded, uploaded, "downloaded attachment differed");
    std::fs::remove_file(output_path).unwrap();

    let delete_reply = Command::new(env!("CARGO_BIN_EXE_agent-access"))
        .args([
            "--url",
            &broker_url,
            "jira",
            "issue",
            "comment",
            "delete",
            &reply_id,
            "--issue",
            &issue,
        ])
        .output()
        .unwrap();
    assert_success("real Jira reply delete", &delete_reply);

    let delete = Command::new(env!("CARGO_BIN_EXE_agent-access"))
        .args([
            "--url",
            &broker_url,
            "jira",
            "issue",
            "comment",
            "delete",
            &comment_id,
            "--issue",
            &issue,
        ])
        .output()
        .unwrap();
    assert_success("real Jira comment delete", &delete);
}

#[test]
#[ignore = "requires a live broker configured for Jira issue-update credentials and mutates the issue"]
fn real_broker_jira_issue_update_smoke() {
    let broker_url = required_env("AGENT_ACCESS_REAL_BROKER_URL");
    let issue = required_env("AGENT_ACCESS_REAL_JIRA_UPDATE_ISSUE");
    let content_file = required_env("AGENT_ACCESS_REAL_JIRA_UPDATE_CONTENT_FILE");
    let content_format = required_env("AGENT_ACCESS_REAL_JIRA_UPDATE_CONTENT_FORMAT");

    let original = Command::new(env!("CARGO_BIN_EXE_agent-access"))
        .args(["--url", &broker_url, "jira", "issue", "view", &issue])
        .output()
        .unwrap();
    assert_success("real Jira issue update original view", &original);
    let original_json: serde_json::Value = serde_json::from_slice(&original.stdout).unwrap();
    let original_summary = json_str(&original_json, &["result", "summary"]);
    assert!(original_json["result"].get("description").is_some());

    let updated_summary = format!("agent-access real smoke summary {}", std::process::id());
    let summary_update = Command::new(env!("CARGO_BIN_EXE_agent-access"))
        .args([
            "--url",
            &broker_url,
            "jira",
            "issue",
            "update",
            &issue,
            "--summary",
            &updated_summary,
        ])
        .output()
        .unwrap();
    assert_success("real Jira issue summary update", &summary_update);
    let summary_json: serde_json::Value = serde_json::from_slice(&summary_update.stdout).unwrap();
    assert_eq!(
        summary_json["result"]["changedFields"],
        serde_json::json!(["summary"])
    );
    assert!(summary_json["result"]["issue"]["webUrl"].as_str().is_some());

    let restore = Command::new(env!("CARGO_BIN_EXE_agent-access"))
        .args([
            "--url",
            &broker_url,
            "jira",
            "issue",
            "update",
            &issue,
            "--summary",
            &original_summary,
        ])
        .output()
        .unwrap();
    assert_success("real Jira issue summary restore", &restore);

    let description_update = Command::new(env!("CARGO_BIN_EXE_agent-access"))
        .args([
            "--url",
            &broker_url,
            "jira",
            "issue",
            "update",
            &issue,
            "--content-file",
            &content_file,
            "--content-format",
            &content_format,
        ])
        .output()
        .unwrap();
    assert_success("real Jira issue description update", &description_update);
    let description_json: serde_json::Value =
        serde_json::from_slice(&description_update.stdout).unwrap();
    assert_eq!(
        description_json["result"]["changedFields"],
        serde_json::json!(["description"])
    );
    assert!(
        description_json["result"]["issue"]["webUrl"]
            .as_str()
            .is_some()
    );
    assert_eq!(
        description_json["result"]["issue"]["description"]["type"],
        "doc"
    );
    assert!(description_json["result"].get("description").is_none());
}

#[test]
#[ignore = "requires a live broker configured for Jira issue-create credentials and mutates the project"]
fn real_broker_jira_issue_create_smoke() {
    let broker_url = required_env("AGENT_ACCESS_REAL_BROKER_URL");
    let project = required_env("AGENT_ACCESS_REAL_JIRA_CREATE_PROJECT");
    let issue_type_id = required_env("AGENT_ACCESS_REAL_JIRA_CREATE_ISSUE_TYPE_ID");
    let content_file = required_env("AGENT_ACCESS_REAL_JIRA_CREATE_CONTENT_FILE");
    let content_format = required_env("AGENT_ACCESS_REAL_JIRA_CREATE_CONTENT_FORMAT");
    let run_id = std::process::id();

    // Verify the real Cloud metadata contract before either create is dispatched.
    let mut start_at = 0_u32;
    let mut found = false;
    let mut complete = false;
    for _ in 0..100 {
        let discovery = Command::new(env!("CARGO_BIN_EXE_agent-access"))
            .args([
                "--url",
                &broker_url,
                "jira",
                "issue-type",
                "list",
                "--project",
                &project,
                "--start-at",
                &start_at.to_string(),
                "--max-results",
                "100",
            ])
            .output()
            .unwrap();
        assert_success("real Jira issue-type discovery", &discovery);
        let response: serde_json::Value = serde_json::from_slice(&discovery.stdout).unwrap();
        let result = &response["result"];
        assert_eq!(result["project"], project);
        assert_eq!(result["startAt"], start_at);
        for issue_type in result["issueTypes"].as_array().expect("issue type array") {
            let id = issue_type["id"]
                .as_str()
                .expect("decimal-string issue type ID");
            assert!(!id.is_empty() && id.bytes().all(|byte| byte.is_ascii_digit()));
            assert!(
                !issue_type["name"]
                    .as_str()
                    .expect("issue type name")
                    .trim()
                    .is_empty()
            );
            assert!(issue_type["description"].is_string());
            assert!(issue_type["subtask"].is_boolean());
            found |= id == issue_type_id;
        }
        if result["isLast"].as_bool().expect("last-page marker") {
            assert!(result["nextStartAt"].is_null());
            complete = true;
            break;
        }
        let next = result["nextStartAt"].as_u64().expect("next-page offset");
        let next = u32::try_from(next).expect("bounded next-page offset");
        assert!(next > start_at, "issue-type pagination must advance");
        start_at = next;
    }
    assert!(
        complete,
        "issue-type discovery exceeded 100 pages; no create was dispatched"
    );
    assert!(
        found,
        "configured issue type was not returned by project discovery; no create was dispatched"
    );

    let summary = format!("agent-access real create smoke summary {run_id}");
    let summary_create = Command::new(env!("CARGO_BIN_EXE_agent-access"))
        .args([
            "--url",
            &broker_url,
            "jira",
            "issue",
            "create",
            "--project",
            &project,
            "--issue-type-id",
            &issue_type_id,
            "--summary",
            &summary,
        ])
        .output()
        .unwrap();
    assert_success("real Jira issue summary create", &summary_create);
    let summary_json: serde_json::Value = serde_json::from_slice(&summary_create.stdout).unwrap();
    assert_created_issue(&summary_json, &project, &summary);
    assert!(summary_json["result"]["issue"]["description"].is_null());

    let described_summary = format!("agent-access real create smoke content {run_id}");
    let described_create = Command::new(env!("CARGO_BIN_EXE_agent-access"))
        .args([
            "--url",
            &broker_url,
            "jira",
            "issue",
            "create",
            "--project",
            &project,
            "--issue-type-id",
            &issue_type_id,
            "--summary",
            &described_summary,
            "--content-file",
            &content_file,
            "--content-format",
            &content_format,
        ])
        .output()
        .unwrap();
    assert_success("real Jira issue content create", &described_create);
    let described_json: serde_json::Value =
        serde_json::from_slice(&described_create.stdout).unwrap();
    assert_created_issue(&described_json, &project, &described_summary);
    assert_eq!(
        described_json["result"]["issue"]["description"]["type"],
        "doc"
    );
}

#[test]
#[ignore = "requires a live broker configured for Jira issue dependency credentials and mutates two issues"]
fn real_broker_jira_issue_dependency_smoke() {
    let broker_url = required_env("AGENT_ACCESS_REAL_BROKER_URL");
    let blocking_issue = required_env("AGENT_ACCESS_REAL_JIRA_DEPENDENCY_BLOCKING_ISSUE");
    let blocked_issue = required_env("AGENT_ACCESS_REAL_JIRA_DEPENDENCY_BLOCKED_ISSUE");

    let dependency = Command::new(env!("CARGO_BIN_EXE_agent-access"))
        .args([
            "--url",
            &broker_url,
            "jira",
            "issue",
            "dependency",
            "add",
            "--blocking",
            &blocking_issue,
            "--blocked",
            &blocked_issue,
        ])
        .output()
        .unwrap();
    assert_success("real Jira issue dependency add", &dependency);
    let dependency_json: serde_json::Value = serde_json::from_slice(&dependency.stdout).unwrap();
    assert_eq!(
        dependency_json["result"]["operation"],
        "issue.dependency.add"
    );
    assert_eq!(dependency_json["result"]["status"], "present");
    assert_eq!(
        dependency_json["result"]["verification"]["status"],
        "matched"
    );
    assert_eq!(
        json_str(&dependency_json, &["result", "blockingIssue", "key"]),
        blocking_issue
    );
    assert_eq!(
        json_str(&dependency_json, &["result", "blockedIssue", "key"]),
        blocked_issue
    );
}

#[test]
#[ignore = "requires a live broker configured for Jira issue parent credentials and mutates the child issue"]
fn real_broker_jira_issue_parent_smoke() {
    let broker_url = required_env("AGENT_ACCESS_REAL_BROKER_URL");
    let mut exercised = Vec::new();

    if let Some((child_issue, parent_issue)) = optional_env_pair(
        "AGENT_ACCESS_REAL_JIRA_PARENT_STANDARD_ISSUE",
        "AGENT_ACCESS_REAL_JIRA_PARENT_EPIC_ISSUE",
    ) {
        exercise_jira_parent_case(
            &broker_url,
            "standard issue to Epic",
            &child_issue,
            &parent_issue,
        );
        exercised.push("standard issue to Epic");
    }

    if let Some((child_issue, parent_issue)) = optional_env_pair(
        "AGENT_ACCESS_REAL_JIRA_PARENT_SUBTASK_ISSUE",
        "AGENT_ACCESS_REAL_JIRA_PARENT_SUBTASK_PARENT_ISSUE",
    ) {
        exercise_jira_parent_case(
            &broker_url,
            "subtask to parent issue",
            &child_issue,
            &parent_issue,
        );
        exercised.push("subtask to parent issue");
    }

    assert!(
        !exercised.is_empty(),
        "set AGENT_ACCESS_REAL_JIRA_PARENT_STANDARD_ISSUE plus \
         AGENT_ACCESS_REAL_JIRA_PARENT_EPIC_ISSUE, or \
         AGENT_ACCESS_REAL_JIRA_PARENT_SUBTASK_ISSUE plus \
         AGENT_ACCESS_REAL_JIRA_PARENT_SUBTASK_PARENT_ISSUE"
    );
    eprintln!(
        "real Jira issue parent smoke exercised: {}",
        exercised.join(", ")
    );
}

fn exercise_jira_parent_case(broker_url: &str, label: &str, child_issue: &str, parent_issue: &str) {
    let parent = Command::new(env!("CARGO_BIN_EXE_agent-access"))
        .args([
            "--url",
            broker_url,
            "jira",
            "issue",
            "parent",
            "set",
            child_issue,
            "--parent",
            parent_issue,
        ])
        .output()
        .unwrap();
    assert_success(&format!("real Jira issue parent set ({label})"), &parent);
    let parent_json: serde_json::Value = serde_json::from_slice(&parent.stdout).unwrap();
    assert_eq!(parent_json["result"]["operation"], "issue.parent.set");
    assert_eq!(parent_json["result"]["verification"]["status"], "matched");
    assert_eq!(
        json_str(&parent_json, &["result", "issue", "key"]),
        child_issue
    );
    assert_eq!(
        json_str(&parent_json, &["result", "parentIssue", "key"]),
        parent_issue
    );
}

#[test]
#[ignore = "requires a live broker configured for Jira child-create credentials and mutates the project"]
fn real_broker_jira_issue_child_create_smoke() {
    let broker_url = required_env("AGENT_ACCESS_REAL_BROKER_URL");
    let run_id = std::process::id();
    let mut exercised = Vec::new();

    if let Some((project, issue_type_id, parent_issue)) = optional_env_triple(
        "AGENT_ACCESS_REAL_JIRA_CHILD_STANDARD_PROJECT",
        "AGENT_ACCESS_REAL_JIRA_CHILD_STANDARD_ISSUE_TYPE_ID",
        "AGENT_ACCESS_REAL_JIRA_CHILD_EPIC_ISSUE",
    ) {
        exercise_jira_child_create_case(
            &broker_url,
            "standard issue under Epic",
            &project,
            &issue_type_id,
            &parent_issue,
            &format!("agent-access real child Epic smoke {run_id}"),
        );
        exercised.push("standard issue under Epic");
    }

    if let Some((project, issue_type_id, parent_issue)) = optional_env_triple(
        "AGENT_ACCESS_REAL_JIRA_CHILD_SUBTASK_PROJECT",
        "AGENT_ACCESS_REAL_JIRA_CHILD_SUBTASK_ISSUE_TYPE_ID",
        "AGENT_ACCESS_REAL_JIRA_CHILD_SUBTASK_PARENT_ISSUE",
    ) {
        exercise_jira_child_create_case(
            &broker_url,
            "subtask under parent issue",
            &project,
            &issue_type_id,
            &parent_issue,
            &format!("agent-access real child subtask smoke {run_id}"),
        );
        exercised.push("subtask under parent issue");
    }

    assert!(
        !exercised.is_empty(),
        "set AGENT_ACCESS_REAL_JIRA_CHILD_STANDARD_PROJECT, \
         AGENT_ACCESS_REAL_JIRA_CHILD_STANDARD_ISSUE_TYPE_ID, and \
         AGENT_ACCESS_REAL_JIRA_CHILD_EPIC_ISSUE; or \
         AGENT_ACCESS_REAL_JIRA_CHILD_SUBTASK_PROJECT, \
         AGENT_ACCESS_REAL_JIRA_CHILD_SUBTASK_ISSUE_TYPE_ID, and \
         AGENT_ACCESS_REAL_JIRA_CHILD_SUBTASK_PARENT_ISSUE"
    );
    eprintln!(
        "real Jira issue child-create smoke exercised: {}",
        exercised.join(", ")
    );
}

fn exercise_jira_child_create_case(
    broker_url: &str,
    label: &str,
    project: &str,
    issue_type_id: &str,
    parent_issue: &str,
    summary: &str,
) {
    let child = Command::new(env!("CARGO_BIN_EXE_agent-access"))
        .args([
            "--url",
            broker_url,
            "jira",
            "issue",
            "child",
            "create",
            "--project",
            project,
            "--issue-type-id",
            issue_type_id,
            "--summary",
            summary,
            "--parent",
            parent_issue,
        ])
        .output()
        .unwrap();
    assert_success(&format!("real Jira issue child create ({label})"), &child);
    let child_json: serde_json::Value = serde_json::from_slice(&child.stdout).unwrap();
    assert_eq!(child_json["result"]["operation"], "issue.child.create");
    assert_eq!(child_json["result"]["verification"]["status"], "matched");
    assert_eq!(
        json_str(&child_json, &["result", "parentIssue", "key"]),
        parent_issue
    );
    let key = json_str(&child_json, &["result", "issue", "key"]);
    assert!(
        key.starts_with(&format!("{project}-")),
        "created child key {key} was not in project {project}"
    );
}

#[test]
#[ignore = "requires a live broker configured for Jira per-user credentials and mutates the issue"]
fn real_broker_jira_per_user_smoke() {
    let broker_url = required_env("AGENT_ACCESS_REAL_BROKER_URL");
    let token_source = per_user_token_source();
    let issue = required_env("AGENT_ACCESS_REAL_JIRA_PER_USER_ISSUE");
    let project = required_env("AGENT_ACCESS_REAL_JIRA_PER_USER_PROJECT");
    let comment_content_file = required_env("AGENT_ACCESS_REAL_JIRA_PER_USER_COMMENT_CONTENT_FILE");
    let comment_content_format =
        required_env("AGENT_ACCESS_REAL_JIRA_PER_USER_COMMENT_CONTENT_FORMAT");
    let attachment_file = required_env("AGENT_ACCESS_REAL_JIRA_PER_USER_ATTACHMENT_FILE");
    let attachment_content_type =
        required_env("AGENT_ACCESS_REAL_JIRA_PER_USER_ATTACHMENT_CONTENT_TYPE");

    let mut issue_view_command = per_user_command(&broker_url, &token_source);
    let issue_view = issue_view_command
        .args(["jira", "issue", "view", &issue])
        .output()
        .unwrap();
    assert_success("real Jira per-user issue view", &issue_view);

    let jql = format!("key = {issue}");
    let mut search_command = per_user_command(&broker_url, &token_source);
    let search = search_command
        .args([
            "jira",
            "issue",
            "search",
            "--project",
            &project,
            "--jql",
            &jql,
            "--max-results",
            "1",
        ])
        .output()
        .unwrap();
    assert_success("real Jira per-user search", &search);

    let mut comment_command = per_user_command(&broker_url, &token_source);
    let comment = comment_command
        .args([
            "jira",
            "issue",
            "comment",
            "add",
            "--issue",
            &issue,
            "--content-file",
            &comment_content_file,
            "--content-format",
            &comment_content_format,
        ])
        .output()
        .unwrap();
    assert_success("real Jira per-user comment add", &comment);
    let comment_json: serde_json::Value = serde_json::from_slice(&comment.stdout).unwrap();
    let comment_id = json_str(&comment_json, &["result", "comment", "commentId"]);

    let mut comment_view_command = per_user_command(&broker_url, &token_source);
    let comment_view = comment_view_command
        .args([
            "jira",
            "issue",
            "comment",
            "view",
            &comment_id,
            "--issue",
            &issue,
        ])
        .output()
        .unwrap();
    assert_success("real Jira per-user comment view", &comment_view);

    let mut upload_command = per_user_command(&broker_url, &token_source);
    let upload = upload_command
        .args([
            "jira",
            "issue",
            "attach",
            &issue,
            &attachment_file,
            "--content-type",
            &attachment_content_type,
        ])
        .output()
        .unwrap();
    assert_success("real Jira per-user attachment add", &upload);
    let upload_json: serde_json::Value = serde_json::from_slice(&upload.stdout).unwrap();
    let attachment_id = json_str(
        &upload_json,
        &["result", "attachments", "0", "attachmentId"],
    );

    let mut list_command = per_user_command(&broker_url, &token_source);
    let list = list_command
        .args(["jira", "issue", "attachment", "list", &issue])
        .output()
        .unwrap();
    assert_success("real Jira per-user attachment list", &list);
    let list_json: serde_json::Value = serde_json::from_slice(&list.stdout).unwrap();
    assert!(
        attachment_list_contains(&list_json, &attachment_id),
        "uploaded per-user attachment id {attachment_id} missing from list response: {}",
        list_json
    );

    let mut verify_command = per_user_command(&broker_url, &token_source);
    let verify = verify_command
        .args([
            "jira",
            "issue",
            "verify",
            &issue,
            "--expect-comment-id",
            &comment_id,
            "--expect-attachment-id",
            &attachment_id,
        ])
        .output()
        .unwrap();
    assert_success("real Jira per-user verify", &verify);

    let output_path = std::env::temp_dir().join(format!(
        "agent-access-real-jira-per-user-download-{}-{attachment_id}",
        std::process::id()
    ));
    let mut download_command = per_user_command(&broker_url, &token_source);
    let download = download_command
        .args([
            "jira",
            "issue",
            "attachment",
            "download",
            &issue,
            &attachment_id,
            "--output",
            output_path.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert_success("real Jira per-user attachment download", &download);
    let downloaded = std::fs::read(&output_path).unwrap();
    let uploaded = std::fs::read(&attachment_file).unwrap();
    assert_eq!(downloaded, uploaded, "downloaded attachment differed");
    std::fs::remove_file(output_path).unwrap();
}

enum TokenSource {
    Env(String),
    File(String),
}

fn per_user_token_source() -> TokenSource {
    if let Ok(name) = std::env::var("AGENT_ACCESS_REAL_JIRA_PER_USER_TOKEN_ENV")
        && !name.trim().is_empty()
    {
        return TokenSource::Env(name);
    }
    if let Ok(path) = std::env::var("AGENT_ACCESS_REAL_JIRA_PER_USER_TOKEN_FILE")
        && !path.trim().is_empty()
    {
        return TokenSource::File(path);
    }
    panic!(
        "AGENT_ACCESS_REAL_JIRA_PER_USER_TOKEN_ENV or AGENT_ACCESS_REAL_JIRA_PER_USER_TOKEN_FILE must be set"
    );
}

fn per_user_command(broker_url: &str, token_source: &TokenSource) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_agent-access"));
    command.args(["--url", broker_url]);
    match token_source {
        TokenSource::Env(name) => {
            command.args(["--token-env", name]);
        }
        TokenSource::File(path) => {
            command.args(["--token-file", path]);
        }
    }
    command
}

fn required_env(name: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| panic!("{name} must be set"))
}

fn optional_env_pair(first: &str, second: &str) -> Option<(String, String)> {
    match (std::env::var(first), std::env::var(second)) {
        (Ok(first_value), Ok(second_value)) => Some((first_value, second_value)),
        (Err(_), Err(_)) => None,
        (Ok(_), Err(_)) => panic!("{second} must be set when {first} is set"),
        (Err(_), Ok(_)) => panic!("{first} must be set when {second} is set"),
    }
}

fn optional_env_triple(first: &str, second: &str, third: &str) -> Option<(String, String, String)> {
    match (
        std::env::var(first),
        std::env::var(second),
        std::env::var(third),
    ) {
        (Ok(first_value), Ok(second_value), Ok(third_value)) => {
            Some((first_value, second_value, third_value))
        }
        (Err(_), Err(_), Err(_)) => None,
        _ => panic!("{first}, {second}, and {third} must be set together"),
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

fn json_str(value: &serde_json::Value, path: &[&str]) -> String {
    let mut current = value;
    for segment in path {
        current = if let Ok(index) = segment.parse::<usize>() {
            &current[index]
        } else {
            &current[*segment]
        };
    }
    current
        .as_str()
        .unwrap_or_else(|| panic!("missing JSON string at {}", path.join(".")))
        .to_string()
}

fn assert_created_issue(value: &serde_json::Value, project: &str, summary: &str) {
    assert_eq!(value["decision"], "allow");
    assert_eq!(value["result"]["operation"], "issue.create");
    assert!(value["result"].get("rawCreateResponse").is_none());
    let issue = &value["result"]["issue"];
    let key = json_str(issue, &["key"]);
    assert!(
        key.starts_with(&format!("{project}-")),
        "created key {key} was not in project {project}"
    );
    assert_eq!(issue["project"], project);
    assert_eq!(issue["summary"], summary);
    assert!(issue["status"].as_str().is_some());
    assert!(issue["issueType"].as_str().is_some());
    assert!(issue["webUrl"].as_str().is_some());
    assert!(issue.get("self").is_none());
}

fn attachment_list_contains(value: &serde_json::Value, attachment_id: &str) -> bool {
    value["result"]["attachments"]
        .as_array()
        .map(|attachments| {
            attachments
                .iter()
                .any(|attachment| attachment["attachmentId"] == attachment_id)
        })
        .unwrap_or(false)
}
