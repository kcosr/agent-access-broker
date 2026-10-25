//! Reviewed input facts for GitLab actions. Every selector is explicit; new schema
//! properties require an inventory decision and coverage test update.
use super::*;

pub(crate) fn projection(action: &str) -> AuditInputProjection {
    let rules = match action {
        "branch.create" => vec![
            AuditInputRule::value("project", "Project", "/project")
                .kind(AuditValueKind::Identifier)
                .role(AuditRole::Target)
                .display(AuditDisplay::Primary)
                .max_bytes(1024)
                .overflow(AuditOverflow::Omit),
            AuditInputRule::value("branch", "Branch", "/branch")
                .kind(AuditValueKind::Identifier)
                .role(AuditRole::Target)
                .display(AuditDisplay::Primary)
                .max_bytes(1024)
                .overflow(AuditOverflow::Omit),
            AuditInputRule::value("ref", "Ref", "/ref")
                .kind(AuditValueKind::Identifier)
                .role(AuditRole::Target)
                .display(AuditDisplay::Primary)
                .max_bytes(1024)
                .overflow(AuditOverflow::Omit),
        ],
        "branch.list" => vec![
            AuditInputRule::value("project", "Project", "/project")
                .kind(AuditValueKind::Identifier)
                .role(AuditRole::Target)
                .display(AuditDisplay::Primary)
                .max_bytes(1024)
                .overflow(AuditOverflow::Omit),
            AuditInputRule::value("search", "Search", "/search")
                .kind(AuditValueKind::Query)
                .role(AuditRole::Fact)
                .display(AuditDisplay::Primary)
                .max_bytes(4096)
                .overflow(AuditOverflow::Prefix),
            AuditInputRule::value("maxResults", "Max Results", "/maxResults")
                .kind(AuditValueKind::Number)
                .role(AuditRole::Fact)
                .display(AuditDisplay::Detail),
            AuditInputRule::value("regex", "Regex", "/regex")
                .kind(AuditValueKind::Query)
                .role(AuditRole::Fact)
                .display(AuditDisplay::Primary)
                .max_bytes(4096)
                .overflow(AuditOverflow::Prefix),
        ],
        "branch.view" => vec![
            AuditInputRule::value("project", "Project", "/project")
                .kind(AuditValueKind::Identifier)
                .role(AuditRole::Target)
                .display(AuditDisplay::Primary)
                .max_bytes(1024)
                .overflow(AuditOverflow::Omit),
            AuditInputRule::value("branch", "Branch", "/branch")
                .kind(AuditValueKind::Identifier)
                .role(AuditRole::Target)
                .display(AuditDisplay::Primary)
                .max_bytes(1024)
                .overflow(AuditOverflow::Omit),
        ],
        "commit.create" => vec![
            AuditInputRule::value("project", "Project", "/project")
                .kind(AuditValueKind::Identifier)
                .role(AuditRole::Target)
                .display(AuditDisplay::Primary)
                .max_bytes(1024)
                .overflow(AuditOverflow::Omit),
            AuditInputRule::value("branch", "Branch", "/branch")
                .kind(AuditValueKind::Identifier)
                .role(AuditRole::Target)
                .display(AuditDisplay::Primary)
                .max_bytes(1024)
                .overflow(AuditOverflow::Omit),
            AuditInputRule::records(
                "actions",
                "Actions",
                "/actions",
                [
                    AuditInputRule::value("action", "Action", "/action")
                        .kind(AuditValueKind::Text)
                        .role(AuditRole::Change)
                        .display(AuditDisplay::Detail)
                        .max_bytes(64)
                        .overflow(AuditOverflow::Omit),
                    AuditInputRule::utf8_byte_count("content", "Content", "/content")
                        .role(AuditRole::Change)
                        .display(AuditDisplay::Detail),
                    AuditInputRule::value("encoding", "Encoding", "/encoding")
                        .kind(AuditValueKind::Text)
                        .role(AuditRole::Change)
                        .display(AuditDisplay::Detail)
                        .max_bytes(64)
                        .overflow(AuditOverflow::Omit),
                    AuditInputRule::value(
                        "executeFilemode",
                        "Execute Filemode",
                        "/executeFilemode",
                    )
                    .kind(AuditValueKind::Boolean)
                    .role(AuditRole::Change)
                    .display(AuditDisplay::Detail),
                    AuditInputRule::value("filePath", "File Path", "/filePath")
                        .kind(AuditValueKind::Path)
                        .role(AuditRole::Target)
                        .display(AuditDisplay::Primary)
                        .max_bytes(1024)
                        .overflow(AuditOverflow::Omit),
                    AuditInputRule::value("lastCommitId", "Last Commit Id", "/lastCommitId")
                        .kind(AuditValueKind::Identifier)
                        .role(AuditRole::Target)
                        .display(AuditDisplay::Primary)
                        .max_bytes(1024)
                        .overflow(AuditOverflow::Omit),
                    AuditInputRule::value("previousPath", "Previous Path", "/previousPath")
                        .kind(AuditValueKind::Path)
                        .role(AuditRole::Target)
                        .display(AuditDisplay::Primary)
                        .max_bytes(1024)
                        .overflow(AuditOverflow::Omit),
                ],
            )
            .role(AuditRole::Change)
            .display(AuditDisplay::Primary),
            AuditInputRule::value("authorEmail", "Author Email", "/authorEmail")
                .kind(AuditValueKind::Email)
                .role(AuditRole::Change)
                .display(AuditDisplay::Detail)
                .max_bytes(1024)
                .overflow(AuditOverflow::Omit),
            AuditInputRule::value("authorName", "Author Name", "/authorName")
                .kind(AuditValueKind::Identifier)
                .role(AuditRole::Change)
                .display(AuditDisplay::Primary)
                .max_bytes(1024)
                .overflow(AuditOverflow::Omit),
            AuditInputRule::utf8_byte_count("commitMessage", "Commit Message", "/commitMessage")
                .role(AuditRole::Change)
                .display(AuditDisplay::Detail),
            AuditInputRule::value("startBranch", "Start Branch", "/startBranch")
                .kind(AuditValueKind::Identifier)
                .role(AuditRole::Change)
                .display(AuditDisplay::Detail)
                .max_bytes(1024)
                .overflow(AuditOverflow::Omit),
            AuditInputRule::value("startSha", "Start Sha", "/startSha")
                .kind(AuditValueKind::Identifier)
                .role(AuditRole::Target)
                .display(AuditDisplay::Primary)
                .max_bytes(1024)
                .overflow(AuditOverflow::Omit),
        ],
        "commit.list" => vec![
            AuditInputRule::value("project", "Project", "/project")
                .kind(AuditValueKind::Identifier)
                .role(AuditRole::Target)
                .display(AuditDisplay::Primary)
                .max_bytes(1024)
                .overflow(AuditOverflow::Omit),
            AuditInputRule::value("path", "Path", "/path")
                .kind(AuditValueKind::Path)
                .role(AuditRole::Target)
                .display(AuditDisplay::Primary)
                .max_bytes(1024)
                .overflow(AuditOverflow::Omit),
            AuditInputRule::value("firstParent", "First Parent", "/firstParent")
                .kind(AuditValueKind::Boolean)
                .role(AuditRole::Fact)
                .display(AuditDisplay::Detail),
            AuditInputRule::value("maxResults", "Max Results", "/maxResults")
                .kind(AuditValueKind::Number)
                .role(AuditRole::Fact)
                .display(AuditDisplay::Detail),
            AuditInputRule::value("refName", "Ref Name", "/refName")
                .kind(AuditValueKind::Identifier)
                .role(AuditRole::Target)
                .display(AuditDisplay::Primary)
                .max_bytes(1024)
                .overflow(AuditOverflow::Omit),
            AuditInputRule::value("since", "Since", "/since")
                .kind(AuditValueKind::Date)
                .role(AuditRole::Fact)
                .display(AuditDisplay::Detail)
                .max_bytes(1024)
                .overflow(AuditOverflow::Omit),
            AuditInputRule::value("until", "Until", "/until")
                .kind(AuditValueKind::Date)
                .role(AuditRole::Fact)
                .display(AuditDisplay::Detail)
                .max_bytes(1024)
                .overflow(AuditOverflow::Omit),
        ],
        "commit.view" => vec![
            AuditInputRule::value("project", "Project", "/project")
                .kind(AuditValueKind::Identifier)
                .role(AuditRole::Target)
                .display(AuditDisplay::Primary)
                .max_bytes(1024)
                .overflow(AuditOverflow::Omit),
            AuditInputRule::value("sha", "Sha", "/sha")
                .kind(AuditValueKind::Identifier)
                .role(AuditRole::Target)
                .display(AuditDisplay::Primary)
                .max_bytes(1024)
                .overflow(AuditOverflow::Omit),
        ],
        "file.create" => vec![
            AuditInputRule::value("project", "Project", "/project")
                .kind(AuditValueKind::Identifier)
                .role(AuditRole::Target)
                .display(AuditDisplay::Primary)
                .max_bytes(1024)
                .overflow(AuditOverflow::Omit),
            AuditInputRule::value("path", "Path", "/path")
                .kind(AuditValueKind::Path)
                .role(AuditRole::Target)
                .display(AuditDisplay::Primary)
                .max_bytes(1024)
                .overflow(AuditOverflow::Omit),
            AuditInputRule::value("branch", "Branch", "/branch")
                .kind(AuditValueKind::Identifier)
                .role(AuditRole::Target)
                .display(AuditDisplay::Primary)
                .max_bytes(1024)
                .overflow(AuditOverflow::Omit),
            AuditInputRule::value("authorEmail", "Author Email", "/authorEmail")
                .kind(AuditValueKind::Email)
                .role(AuditRole::Change)
                .display(AuditDisplay::Detail)
                .max_bytes(1024)
                .overflow(AuditOverflow::Omit),
            AuditInputRule::value("authorName", "Author Name", "/authorName")
                .kind(AuditValueKind::Identifier)
                .role(AuditRole::Change)
                .display(AuditDisplay::Primary)
                .max_bytes(1024)
                .overflow(AuditOverflow::Omit),
            AuditInputRule::utf8_byte_count("commitMessage", "Commit Message", "/commitMessage")
                .role(AuditRole::Change)
                .display(AuditDisplay::Detail),
            AuditInputRule::utf8_byte_count("content", "Content", "/content")
                .role(AuditRole::Change)
                .display(AuditDisplay::Detail),
            AuditInputRule::value("encoding", "Encoding", "/encoding")
                .kind(AuditValueKind::Text)
                .role(AuditRole::Change)
                .display(AuditDisplay::Detail)
                .max_bytes(64)
                .overflow(AuditOverflow::Omit),
            AuditInputRule::value("executeFilemode", "Execute Filemode", "/executeFilemode")
                .kind(AuditValueKind::Boolean)
                .role(AuditRole::Change)
                .display(AuditDisplay::Detail),
            AuditInputRule::value("startBranch", "Start Branch", "/startBranch")
                .kind(AuditValueKind::Identifier)
                .role(AuditRole::Change)
                .display(AuditDisplay::Detail)
                .max_bytes(1024)
                .overflow(AuditOverflow::Omit),
        ],
        "file.delete" => vec![
            AuditInputRule::value("project", "Project", "/project")
                .kind(AuditValueKind::Identifier)
                .role(AuditRole::Target)
                .display(AuditDisplay::Primary)
                .max_bytes(1024)
                .overflow(AuditOverflow::Omit),
            AuditInputRule::value("path", "Path", "/path")
                .kind(AuditValueKind::Path)
                .role(AuditRole::Target)
                .display(AuditDisplay::Primary)
                .max_bytes(1024)
                .overflow(AuditOverflow::Omit),
            AuditInputRule::value("branch", "Branch", "/branch")
                .kind(AuditValueKind::Identifier)
                .role(AuditRole::Target)
                .display(AuditDisplay::Primary)
                .max_bytes(1024)
                .overflow(AuditOverflow::Omit),
            AuditInputRule::value("authorEmail", "Author Email", "/authorEmail")
                .kind(AuditValueKind::Email)
                .role(AuditRole::Fact)
                .display(AuditDisplay::Detail)
                .max_bytes(1024)
                .overflow(AuditOverflow::Omit),
            AuditInputRule::value("authorName", "Author Name", "/authorName")
                .kind(AuditValueKind::Identifier)
                .role(AuditRole::Change)
                .display(AuditDisplay::Primary)
                .max_bytes(1024)
                .overflow(AuditOverflow::Omit),
            AuditInputRule::utf8_byte_count("commitMessage", "Commit Message", "/commitMessage")
                .role(AuditRole::Change)
                .display(AuditDisplay::Detail),
            AuditInputRule::value("lastCommitId", "Last Commit Id", "/lastCommitId")
                .kind(AuditValueKind::Identifier)
                .role(AuditRole::Target)
                .display(AuditDisplay::Primary)
                .max_bytes(1024)
                .overflow(AuditOverflow::Omit),
            AuditInputRule::value("startBranch", "Start Branch", "/startBranch")
                .kind(AuditValueKind::Identifier)
                .role(AuditRole::Fact)
                .display(AuditDisplay::Detail)
                .max_bytes(1024)
                .overflow(AuditOverflow::Omit),
        ],
        "file.raw.download" | "file.view" => vec![
            AuditInputRule::value("project", "Project", "/project")
                .kind(AuditValueKind::Identifier)
                .role(AuditRole::Target)
                .display(AuditDisplay::Primary)
                .max_bytes(1024)
                .overflow(AuditOverflow::Omit),
            AuditInputRule::value("path", "Path", "/path")
                .kind(AuditValueKind::Path)
                .role(AuditRole::Target)
                .display(AuditDisplay::Primary)
                .max_bytes(1024)
                .overflow(AuditOverflow::Omit),
            AuditInputRule::value("ref", "Ref", "/ref")
                .kind(AuditValueKind::Identifier)
                .role(AuditRole::Target)
                .display(AuditDisplay::Primary)
                .max_bytes(1024)
                .overflow(AuditOverflow::Omit),
        ],
        "file.update" => vec![
            AuditInputRule::value("project", "Project", "/project")
                .kind(AuditValueKind::Identifier)
                .role(AuditRole::Target)
                .display(AuditDisplay::Primary)
                .max_bytes(1024)
                .overflow(AuditOverflow::Omit),
            AuditInputRule::value("path", "Path", "/path")
                .kind(AuditValueKind::Path)
                .role(AuditRole::Target)
                .display(AuditDisplay::Primary)
                .max_bytes(1024)
                .overflow(AuditOverflow::Omit),
            AuditInputRule::value("branch", "Branch", "/branch")
                .kind(AuditValueKind::Identifier)
                .role(AuditRole::Target)
                .display(AuditDisplay::Primary)
                .max_bytes(1024)
                .overflow(AuditOverflow::Omit),
            AuditInputRule::value("authorEmail", "Author Email", "/authorEmail")
                .kind(AuditValueKind::Email)
                .role(AuditRole::Change)
                .display(AuditDisplay::Detail)
                .max_bytes(1024)
                .overflow(AuditOverflow::Omit),
            AuditInputRule::value("authorName", "Author Name", "/authorName")
                .kind(AuditValueKind::Identifier)
                .role(AuditRole::Change)
                .display(AuditDisplay::Primary)
                .max_bytes(1024)
                .overflow(AuditOverflow::Omit),
            AuditInputRule::utf8_byte_count("commitMessage", "Commit Message", "/commitMessage")
                .role(AuditRole::Change)
                .display(AuditDisplay::Detail),
            AuditInputRule::utf8_byte_count("content", "Content", "/content")
                .role(AuditRole::Change)
                .display(AuditDisplay::Detail),
            AuditInputRule::value("encoding", "Encoding", "/encoding")
                .kind(AuditValueKind::Text)
                .role(AuditRole::Change)
                .display(AuditDisplay::Detail)
                .max_bytes(64)
                .overflow(AuditOverflow::Omit),
            AuditInputRule::value("executeFilemode", "Execute Filemode", "/executeFilemode")
                .kind(AuditValueKind::Boolean)
                .role(AuditRole::Change)
                .display(AuditDisplay::Detail),
            AuditInputRule::value("lastCommitId", "Last Commit Id", "/lastCommitId")
                .kind(AuditValueKind::Identifier)
                .role(AuditRole::Target)
                .display(AuditDisplay::Primary)
                .max_bytes(1024)
                .overflow(AuditOverflow::Omit),
            AuditInputRule::value("startBranch", "Start Branch", "/startBranch")
                .kind(AuditValueKind::Identifier)
                .role(AuditRole::Change)
                .display(AuditDisplay::Detail)
                .max_bytes(1024)
                .overflow(AuditOverflow::Omit),
        ],
        "issue.create" => vec![
            AuditInputRule::value("project", "Project", "/project")
                .kind(AuditValueKind::Identifier)
                .role(AuditRole::Target)
                .display(AuditDisplay::Primary)
                .max_bytes(1024)
                .overflow(AuditOverflow::Omit),
            AuditInputRule::value("title", "Title", "/title")
                .kind(AuditValueKind::Text)
                .role(AuditRole::Change)
                .display(AuditDisplay::Primary)
                .max_bytes(1024)
                .overflow(AuditOverflow::Prefix),
            AuditInputRule::values("assignees", "Assignees", "/assignees")
                .kind(AuditValueKind::Identifier)
                .role(AuditRole::Change)
                .display(AuditDisplay::Detail)
                .max_bytes(1024)
                .overflow(AuditOverflow::Omit),
            AuditInputRule::value("confidential", "Confidential", "/confidential")
                .kind(AuditValueKind::Boolean)
                .role(AuditRole::Change)
                .display(AuditDisplay::Detail),
            AuditInputRule::utf8_byte_count("content", "Content", "/content")
                .role(AuditRole::Change)
                .display(AuditDisplay::Detail),
            AuditInputRule::value("contentFormat", "Content Format", "/contentFormat")
                .kind(AuditValueKind::Text)
                .role(AuditRole::Change)
                .display(AuditDisplay::Detail)
                .max_bytes(64)
                .overflow(AuditOverflow::Omit),
            AuditInputRule::values("labels", "Labels", "/labels")
                .kind(AuditValueKind::Identifier)
                .role(AuditRole::Change)
                .display(AuditDisplay::Detail)
                .max_bytes(1024)
                .overflow(AuditOverflow::Omit),
            AuditInputRule::value("milestone", "Milestone", "/milestone")
                .kind(AuditValueKind::Identifier)
                .role(AuditRole::Change)
                .display(AuditDisplay::Detail)
                .max_bytes(1024)
                .overflow(AuditOverflow::Omit),
        ],
        "issue.note.add" => vec![
            AuditInputRule::value("project", "Project", "/project")
                .kind(AuditValueKind::Identifier)
                .role(AuditRole::Target)
                .display(AuditDisplay::Primary)
                .max_bytes(1024)
                .overflow(AuditOverflow::Omit),
            AuditInputRule::value("iid", "Iid", "/iid")
                .kind(AuditValueKind::Identifier)
                .role(AuditRole::Target)
                .display(AuditDisplay::Primary)
                .max_bytes(1024)
                .overflow(AuditOverflow::Omit),
            AuditInputRule::value("confidential", "Confidential", "/confidential")
                .kind(AuditValueKind::Boolean)
                .role(AuditRole::Change)
                .display(AuditDisplay::Detail),
            AuditInputRule::utf8_byte_count("content", "Content", "/content")
                .role(AuditRole::Change)
                .display(AuditDisplay::Detail),
            AuditInputRule::value("contentFormat", "Content Format", "/contentFormat")
                .kind(AuditValueKind::Text)
                .role(AuditRole::Change)
                .display(AuditDisplay::Detail)
                .max_bytes(64)
                .overflow(AuditOverflow::Omit),
        ],
        "issue.note.delete"
        | "issue.note.view"
        | "merge_request.note.delete"
        | "merge_request.note.view" => vec![
            AuditInputRule::value("project", "Project", "/project")
                .kind(AuditValueKind::Identifier)
                .role(AuditRole::Target)
                .display(AuditDisplay::Primary)
                .max_bytes(1024)
                .overflow(AuditOverflow::Omit),
            AuditInputRule::value("iid", "Iid", "/iid")
                .kind(AuditValueKind::Identifier)
                .role(AuditRole::Target)
                .display(AuditDisplay::Primary)
                .max_bytes(1024)
                .overflow(AuditOverflow::Omit),
            AuditInputRule::value("noteId", "Note Id", "/noteId")
                .kind(AuditValueKind::Identifier)
                .role(AuditRole::Target)
                .display(AuditDisplay::Primary)
                .max_bytes(1024)
                .overflow(AuditOverflow::Omit),
        ],
        "issue.note.list" | "merge_request.note.list" => vec![
            AuditInputRule::value("project", "Project", "/project")
                .kind(AuditValueKind::Identifier)
                .role(AuditRole::Target)
                .display(AuditDisplay::Primary)
                .max_bytes(1024)
                .overflow(AuditOverflow::Omit),
            AuditInputRule::value("iid", "Iid", "/iid")
                .kind(AuditValueKind::Identifier)
                .role(AuditRole::Target)
                .display(AuditDisplay::Primary)
                .max_bytes(1024)
                .overflow(AuditOverflow::Omit),
            AuditInputRule::value("maxResults", "Max Results", "/maxResults")
                .kind(AuditValueKind::Number)
                .role(AuditRole::Fact)
                .display(AuditDisplay::Detail),
            AuditInputRule::value("orderBy", "Order By", "/orderBy")
                .kind(AuditValueKind::Text)
                .role(AuditRole::Fact)
                .display(AuditDisplay::Detail)
                .max_bytes(64)
                .overflow(AuditOverflow::Omit),
            AuditInputRule::presence("pageToken", "Page Token", "/pageToken")
                .role(AuditRole::Fact)
                .display(AuditDisplay::Detail),
            AuditInputRule::value("projection", "Projection", "/projection")
                .kind(AuditValueKind::Text)
                .role(AuditRole::Fact)
                .display(AuditDisplay::Detail)
                .max_bytes(64)
                .overflow(AuditOverflow::Omit),
            AuditInputRule::value("sort", "Sort", "/sort")
                .kind(AuditValueKind::Text)
                .role(AuditRole::Fact)
                .display(AuditDisplay::Detail)
                .max_bytes(64)
                .overflow(AuditOverflow::Omit),
        ],
        "issue.note.update" | "merge_request.note.update" => vec![
            AuditInputRule::value("project", "Project", "/project")
                .kind(AuditValueKind::Identifier)
                .role(AuditRole::Target)
                .display(AuditDisplay::Primary)
                .max_bytes(1024)
                .overflow(AuditOverflow::Omit),
            AuditInputRule::value("iid", "Iid", "/iid")
                .kind(AuditValueKind::Identifier)
                .role(AuditRole::Target)
                .display(AuditDisplay::Primary)
                .max_bytes(1024)
                .overflow(AuditOverflow::Omit),
            AuditInputRule::utf8_byte_count("content", "Content", "/content")
                .role(AuditRole::Change)
                .display(AuditDisplay::Detail),
            AuditInputRule::value("contentFormat", "Content Format", "/contentFormat")
                .kind(AuditValueKind::Text)
                .role(AuditRole::Change)
                .display(AuditDisplay::Detail)
                .max_bytes(64)
                .overflow(AuditOverflow::Omit),
            AuditInputRule::value("noteId", "Note Id", "/noteId")
                .kind(AuditValueKind::Identifier)
                .role(AuditRole::Target)
                .display(AuditDisplay::Primary)
                .max_bytes(1024)
                .overflow(AuditOverflow::Omit),
        ],
        "issue.search" => vec![
            AuditInputRule::value("project", "Project", "/project")
                .kind(AuditValueKind::Identifier)
                .role(AuditRole::Target)
                .display(AuditDisplay::Primary)
                .max_bytes(1024)
                .overflow(AuditOverflow::Omit),
            AuditInputRule::value("search", "Search", "/search")
                .kind(AuditValueKind::Query)
                .role(AuditRole::Fact)
                .display(AuditDisplay::Primary)
                .max_bytes(4096)
                .overflow(AuditOverflow::Prefix),
            AuditInputRule::value("assignee", "Assignee", "/assignee")
                .kind(AuditValueKind::Identifier)
                .role(AuditRole::Fact)
                .display(AuditDisplay::Detail)
                .max_bytes(1024)
                .overflow(AuditOverflow::Omit),
            AuditInputRule::value("author", "Author", "/author")
                .kind(AuditValueKind::Identifier)
                .role(AuditRole::Fact)
                .display(AuditDisplay::Detail)
                .max_bytes(1024)
                .overflow(AuditOverflow::Omit),
            AuditInputRule::value("createdAfter", "Created After", "/createdAfter")
                .kind(AuditValueKind::Date)
                .role(AuditRole::Fact)
                .display(AuditDisplay::Detail)
                .max_bytes(1024)
                .overflow(AuditOverflow::Omit),
            AuditInputRule::values("labels", "Labels", "/labels")
                .kind(AuditValueKind::Identifier)
                .role(AuditRole::Fact)
                .display(AuditDisplay::Detail)
                .max_bytes(1024)
                .overflow(AuditOverflow::Omit),
            AuditInputRule::value("maxResults", "Max Results", "/maxResults")
                .kind(AuditValueKind::Number)
                .role(AuditRole::Fact)
                .display(AuditDisplay::Detail),
            AuditInputRule::value("milestone", "Milestone", "/milestone")
                .kind(AuditValueKind::Identifier)
                .role(AuditRole::Fact)
                .display(AuditDisplay::Detail)
                .max_bytes(1024)
                .overflow(AuditOverflow::Omit),
            AuditInputRule::value("orderBy", "Order By", "/orderBy")
                .kind(AuditValueKind::Text)
                .role(AuditRole::Fact)
                .display(AuditDisplay::Detail)
                .max_bytes(64)
                .overflow(AuditOverflow::Omit),
            AuditInputRule::presence("pageToken", "Page Token", "/pageToken")
                .role(AuditRole::Fact)
                .display(AuditDisplay::Detail),
            AuditInputRule::value("sort", "Sort", "/sort")
                .kind(AuditValueKind::Text)
                .role(AuditRole::Fact)
                .display(AuditDisplay::Detail)
                .max_bytes(64)
                .overflow(AuditOverflow::Omit),
            AuditInputRule::value("state", "State", "/state")
                .kind(AuditValueKind::Text)
                .role(AuditRole::Fact)
                .display(AuditDisplay::Detail)
                .max_bytes(64)
                .overflow(AuditOverflow::Omit),
            AuditInputRule::value("updatedAfter", "Updated After", "/updatedAfter")
                .kind(AuditValueKind::Date)
                .role(AuditRole::Fact)
                .display(AuditDisplay::Detail)
                .max_bytes(1024)
                .overflow(AuditOverflow::Omit),
        ],
        "issue.update" => vec![
            AuditInputRule::value("project", "Project", "/project")
                .kind(AuditValueKind::Identifier)
                .role(AuditRole::Target)
                .display(AuditDisplay::Primary)
                .max_bytes(1024)
                .overflow(AuditOverflow::Omit),
            AuditInputRule::value("iid", "Iid", "/iid")
                .kind(AuditValueKind::Identifier)
                .role(AuditRole::Target)
                .display(AuditDisplay::Primary)
                .max_bytes(1024)
                .overflow(AuditOverflow::Omit),
            AuditInputRule::value("title", "Title", "/title")
                .kind(AuditValueKind::Text)
                .role(AuditRole::Change)
                .display(AuditDisplay::Primary)
                .max_bytes(1024)
                .overflow(AuditOverflow::Prefix),
            AuditInputRule::values("addLabels", "Add Labels", "/addLabels")
                .kind(AuditValueKind::Identifier)
                .role(AuditRole::Change)
                .display(AuditDisplay::Detail)
                .max_bytes(1024)
                .overflow(AuditOverflow::Omit),
            AuditInputRule::values("assignees", "Assignees", "/assignees")
                .kind(AuditValueKind::Identifier)
                .role(AuditRole::Change)
                .display(AuditDisplay::Detail)
                .max_bytes(1024)
                .overflow(AuditOverflow::Omit),
            AuditInputRule::value("confidential", "Confidential", "/confidential")
                .kind(AuditValueKind::Boolean)
                .role(AuditRole::Change)
                .display(AuditDisplay::Detail),
            AuditInputRule::utf8_byte_count("content", "Content", "/content")
                .role(AuditRole::Change)
                .display(AuditDisplay::Detail),
            AuditInputRule::value("contentFormat", "Content Format", "/contentFormat")
                .kind(AuditValueKind::Text)
                .role(AuditRole::Change)
                .display(AuditDisplay::Detail)
                .max_bytes(64)
                .overflow(AuditOverflow::Omit),
            AuditInputRule::values("labels", "Labels", "/labels")
                .kind(AuditValueKind::Identifier)
                .role(AuditRole::Change)
                .display(AuditDisplay::Detail)
                .max_bytes(1024)
                .overflow(AuditOverflow::Omit),
            AuditInputRule::value("milestone", "Milestone", "/milestone")
                .kind(AuditValueKind::Identifier)
                .role(AuditRole::Change)
                .display(AuditDisplay::Detail)
                .max_bytes(1024)
                .overflow(AuditOverflow::Omit),
            AuditInputRule::values("removeLabels", "Remove Labels", "/removeLabels")
                .kind(AuditValueKind::Identifier)
                .role(AuditRole::Change)
                .display(AuditDisplay::Detail)
                .max_bytes(1024)
                .overflow(AuditOverflow::Omit),
            AuditInputRule::value("stateEvent", "State Event", "/stateEvent")
                .kind(AuditValueKind::Text)
                .role(AuditRole::Change)
                .display(AuditDisplay::Detail)
                .max_bytes(64)
                .overflow(AuditOverflow::Omit),
        ],
        "issue.view" | "merge_request.view" => vec![
            AuditInputRule::value("project", "Project", "/project")
                .kind(AuditValueKind::Identifier)
                .role(AuditRole::Target)
                .display(AuditDisplay::Primary)
                .max_bytes(1024)
                .overflow(AuditOverflow::Omit),
            AuditInputRule::value("iid", "Iid", "/iid")
                .kind(AuditValueKind::Identifier)
                .role(AuditRole::Target)
                .display(AuditDisplay::Primary)
                .max_bytes(1024)
                .overflow(AuditOverflow::Omit),
            AuditInputRule::presence("url", "Url", "/url")
                .role(AuditRole::Fact)
                .display(AuditDisplay::Detail),
        ],
        "job.cancel" | "job.play" | "job.retry" | "job.trace.download" | "job.view" => vec![
            AuditInputRule::value("project", "Project", "/project")
                .kind(AuditValueKind::Identifier)
                .role(AuditRole::Target)
                .display(AuditDisplay::Primary)
                .max_bytes(1024)
                .overflow(AuditOverflow::Omit),
            AuditInputRule::value("jobId", "Job Id", "/jobId")
                .kind(AuditValueKind::Identifier)
                .role(AuditRole::Target)
                .display(AuditDisplay::Primary)
                .max_bytes(1024)
                .overflow(AuditOverflow::Omit),
        ],
        "job.list" => vec![
            AuditInputRule::value("project", "Project", "/project")
                .kind(AuditValueKind::Identifier)
                .role(AuditRole::Target)
                .display(AuditDisplay::Primary)
                .max_bytes(1024)
                .overflow(AuditOverflow::Omit),
            AuditInputRule::value("maxResults", "Max Results", "/maxResults")
                .kind(AuditValueKind::Number)
                .role(AuditRole::Fact)
                .display(AuditDisplay::Detail),
            AuditInputRule::value("pipelineId", "Pipeline Id", "/pipelineId")
                .kind(AuditValueKind::Identifier)
                .role(AuditRole::Target)
                .display(AuditDisplay::Primary)
                .max_bytes(1024)
                .overflow(AuditOverflow::Omit),
            AuditInputRule::value("scope", "Scope", "/scope")
                .kind(AuditValueKind::Text)
                .role(AuditRole::Fact)
                .display(AuditDisplay::Detail)
                .max_bytes(64)
                .overflow(AuditOverflow::Omit),
        ],
        "merge_request.approval.view"
        | "merge_request.approval_state.view"
        | "merge_request.diff.raw.download"
        | "merge_request.unapprove" => vec![
            AuditInputRule::value("project", "Project", "/project")
                .kind(AuditValueKind::Identifier)
                .role(AuditRole::Target)
                .display(AuditDisplay::Primary)
                .max_bytes(1024)
                .overflow(AuditOverflow::Omit),
            AuditInputRule::value("iid", "Iid", "/iid")
                .kind(AuditValueKind::Identifier)
                .role(AuditRole::Target)
                .display(AuditDisplay::Primary)
                .max_bytes(1024)
                .overflow(AuditOverflow::Omit),
        ],
        "merge_request.approval_rule.list"
        | "merge_request.commit.list"
        | "merge_request.diff_version.list"
        | "merge_request.pipeline.list"
        | "merge_request.reviewer.list" => vec![
            AuditInputRule::value("project", "Project", "/project")
                .kind(AuditValueKind::Identifier)
                .role(AuditRole::Target)
                .display(AuditDisplay::Primary)
                .max_bytes(1024)
                .overflow(AuditOverflow::Omit),
            AuditInputRule::value("iid", "Iid", "/iid")
                .kind(AuditValueKind::Identifier)
                .role(AuditRole::Target)
                .display(AuditDisplay::Primary)
                .max_bytes(1024)
                .overflow(AuditOverflow::Omit),
            AuditInputRule::value("maxResults", "Max Results", "/maxResults")
                .kind(AuditValueKind::Number)
                .role(AuditRole::Fact)
                .display(AuditDisplay::Detail),
            AuditInputRule::presence("pageToken", "Page Token", "/pageToken")
                .role(AuditRole::Fact)
                .display(AuditDisplay::Detail),
        ],
        "merge_request.approval_rule.view" => vec![
            AuditInputRule::value("project", "Project", "/project")
                .kind(AuditValueKind::Identifier)
                .role(AuditRole::Target)
                .display(AuditDisplay::Primary)
                .max_bytes(1024)
                .overflow(AuditOverflow::Omit),
            AuditInputRule::value("iid", "Iid", "/iid")
                .kind(AuditValueKind::Identifier)
                .role(AuditRole::Target)
                .display(AuditDisplay::Primary)
                .max_bytes(1024)
                .overflow(AuditOverflow::Omit),
            AuditInputRule::value("approvalRuleId", "Approval Rule Id", "/approvalRuleId")
                .kind(AuditValueKind::Identifier)
                .role(AuditRole::Target)
                .display(AuditDisplay::Primary)
                .max_bytes(1024)
                .overflow(AuditOverflow::Omit),
        ],
        "merge_request.approve" => vec![
            AuditInputRule::value("project", "Project", "/project")
                .kind(AuditValueKind::Identifier)
                .role(AuditRole::Target)
                .display(AuditDisplay::Primary)
                .max_bytes(1024)
                .overflow(AuditOverflow::Omit),
            AuditInputRule::value("iid", "Iid", "/iid")
                .kind(AuditValueKind::Identifier)
                .role(AuditRole::Target)
                .display(AuditDisplay::Primary)
                .max_bytes(1024)
                .overflow(AuditOverflow::Omit),
            AuditInputRule::value("headSha", "Head Sha", "/headSha")
                .kind(AuditValueKind::Identifier)
                .role(AuditRole::Target)
                .display(AuditDisplay::Primary)
                .max_bytes(1024)
                .overflow(AuditOverflow::Omit),
        ],
        "merge_request.create" => vec![
            AuditInputRule::value("project", "Project", "/project")
                .kind(AuditValueKind::Identifier)
                .role(AuditRole::Target)
                .display(AuditDisplay::Primary)
                .max_bytes(1024)
                .overflow(AuditOverflow::Omit),
            AuditInputRule::value("title", "Title", "/title")
                .kind(AuditValueKind::Text)
                .role(AuditRole::Change)
                .display(AuditDisplay::Primary)
                .max_bytes(1024)
                .overflow(AuditOverflow::Prefix),
            AuditInputRule::values("assignees", "Assignees", "/assignees")
                .kind(AuditValueKind::Identifier)
                .role(AuditRole::Change)
                .display(AuditDisplay::Detail)
                .max_bytes(1024)
                .overflow(AuditOverflow::Omit),
            AuditInputRule::utf8_byte_count("content", "Content", "/content")
                .role(AuditRole::Change)
                .display(AuditDisplay::Detail),
            AuditInputRule::value("contentFormat", "Content Format", "/contentFormat")
                .kind(AuditValueKind::Text)
                .role(AuditRole::Change)
                .display(AuditDisplay::Detail)
                .max_bytes(64)
                .overflow(AuditOverflow::Omit),
            AuditInputRule::value("draft", "Draft", "/draft")
                .kind(AuditValueKind::Boolean)
                .role(AuditRole::Change)
                .display(AuditDisplay::Detail),
            AuditInputRule::values("labels", "Labels", "/labels")
                .kind(AuditValueKind::Identifier)
                .role(AuditRole::Change)
                .display(AuditDisplay::Detail)
                .max_bytes(1024)
                .overflow(AuditOverflow::Omit),
            AuditInputRule::value(
                "removeSourceBranch",
                "Remove Source Branch",
                "/removeSourceBranch",
            )
            .kind(AuditValueKind::Boolean)
            .role(AuditRole::Change)
            .display(AuditDisplay::Detail),
            AuditInputRule::values("reviewers", "Reviewers", "/reviewers")
                .kind(AuditValueKind::Identifier)
                .role(AuditRole::Change)
                .display(AuditDisplay::Detail)
                .max_bytes(1024)
                .overflow(AuditOverflow::Omit),
            AuditInputRule::value("sourceBranch", "Source Branch", "/sourceBranch")
                .kind(AuditValueKind::Identifier)
                .role(AuditRole::Change)
                .display(AuditDisplay::Detail)
                .max_bytes(1024)
                .overflow(AuditOverflow::Omit),
            AuditInputRule::value("squash", "Squash", "/squash")
                .kind(AuditValueKind::Boolean)
                .role(AuditRole::Change)
                .display(AuditDisplay::Detail),
            AuditInputRule::value("targetBranch", "Target Branch", "/targetBranch")
                .kind(AuditValueKind::Identifier)
                .role(AuditRole::Change)
                .display(AuditDisplay::Detail)
                .max_bytes(1024)
                .overflow(AuditOverflow::Omit),
        ],
        "merge_request.diff.list" => vec![
            AuditInputRule::value("project", "Project", "/project")
                .kind(AuditValueKind::Identifier)
                .role(AuditRole::Target)
                .display(AuditDisplay::Primary)
                .max_bytes(1024)
                .overflow(AuditOverflow::Omit),
            AuditInputRule::value("iid", "Iid", "/iid")
                .kind(AuditValueKind::Identifier)
                .role(AuditRole::Target)
                .display(AuditDisplay::Primary)
                .max_bytes(1024)
                .overflow(AuditOverflow::Omit),
            AuditInputRule::value("maxResults", "Max Results", "/maxResults")
                .kind(AuditValueKind::Number)
                .role(AuditRole::Fact)
                .display(AuditDisplay::Detail),
            AuditInputRule::presence("pageToken", "Page Token", "/pageToken")
                .role(AuditRole::Fact)
                .display(AuditDisplay::Detail),
            AuditInputRule::value("unidiff", "Unidiff", "/unidiff")
                .kind(AuditValueKind::Boolean)
                .role(AuditRole::Fact)
                .display(AuditDisplay::Detail),
        ],
        "merge_request.diff_version.view" => vec![
            AuditInputRule::value("project", "Project", "/project")
                .kind(AuditValueKind::Identifier)
                .role(AuditRole::Target)
                .display(AuditDisplay::Primary)
                .max_bytes(1024)
                .overflow(AuditOverflow::Omit),
            AuditInputRule::value("iid", "Iid", "/iid")
                .kind(AuditValueKind::Identifier)
                .role(AuditRole::Target)
                .display(AuditDisplay::Primary)
                .max_bytes(1024)
                .overflow(AuditOverflow::Omit),
            AuditInputRule::value("diffVersionId", "Diff Version Id", "/diffVersionId")
                .kind(AuditValueKind::Identifier)
                .role(AuditRole::Target)
                .display(AuditDisplay::Primary)
                .max_bytes(1024)
                .overflow(AuditOverflow::Omit),
            AuditInputRule::value("unidiff", "Unidiff", "/unidiff")
                .kind(AuditValueKind::Boolean)
                .role(AuditRole::Fact)
                .display(AuditDisplay::Detail),
        ],
        "merge_request.discussion.add" | "merge_request.note.add" => vec![
            AuditInputRule::value("project", "Project", "/project")
                .kind(AuditValueKind::Identifier)
                .role(AuditRole::Target)
                .display(AuditDisplay::Primary)
                .max_bytes(1024)
                .overflow(AuditOverflow::Omit),
            AuditInputRule::value("iid", "Iid", "/iid")
                .kind(AuditValueKind::Identifier)
                .role(AuditRole::Target)
                .display(AuditDisplay::Primary)
                .max_bytes(1024)
                .overflow(AuditOverflow::Omit),
            AuditInputRule::utf8_byte_count("content", "Content", "/content")
                .role(AuditRole::Change)
                .display(AuditDisplay::Detail),
            AuditInputRule::value("contentFormat", "Content Format", "/contentFormat")
                .kind(AuditValueKind::Text)
                .role(AuditRole::Change)
                .display(AuditDisplay::Detail)
                .max_bytes(64)
                .overflow(AuditOverflow::Omit),
        ],
        "merge_request.discussion.inline.add" => vec![
            AuditInputRule::value("project", "Project", "/project")
                .kind(AuditValueKind::Identifier)
                .role(AuditRole::Target)
                .display(AuditDisplay::Primary)
                .max_bytes(1024)
                .overflow(AuditOverflow::Omit),
            AuditInputRule::value("iid", "Iid", "/iid")
                .kind(AuditValueKind::Identifier)
                .role(AuditRole::Target)
                .display(AuditDisplay::Primary)
                .max_bytes(1024)
                .overflow(AuditOverflow::Omit),
            AuditInputRule::value("expectedHeadSha", "Expected Head Sha", "/expectedHeadSha")
                .kind(AuditValueKind::Identifier)
                .role(AuditRole::Target)
                .display(AuditDisplay::Primary)
                .max_bytes(1024)
                .overflow(AuditOverflow::Omit),
            AuditInputRule::utf8_byte_count("content", "Content", "/content")
                .role(AuditRole::Change)
                .display(AuditDisplay::Detail),
            AuditInputRule::value("contentFormat", "Content Format", "/contentFormat")
                .kind(AuditValueKind::Text)
                .role(AuditRole::Change)
                .display(AuditDisplay::Detail)
                .max_bytes(64)
                .overflow(AuditOverflow::Omit),
            AuditInputRule::value("position.height", "Height", "/position/height")
                .kind(AuditValueKind::Number)
                .role(AuditRole::Change)
                .display(AuditDisplay::Detail),
            AuditInputRule::value(
                "position.lineRange.end.newLine",
                "New Line",
                "/position/lineRange/end/newLine",
            )
            .kind(AuditValueKind::Number)
            .role(AuditRole::Change)
            .display(AuditDisplay::Detail),
            AuditInputRule::value(
                "position.lineRange.end.oldLine",
                "Old Line",
                "/position/lineRange/end/oldLine",
            )
            .kind(AuditValueKind::Number)
            .role(AuditRole::Change)
            .display(AuditDisplay::Detail),
            AuditInputRule::value(
                "position.lineRange.start.newLine",
                "New Line",
                "/position/lineRange/start/newLine",
            )
            .kind(AuditValueKind::Number)
            .role(AuditRole::Change)
            .display(AuditDisplay::Detail),
            AuditInputRule::value(
                "position.lineRange.start.oldLine",
                "Old Line",
                "/position/lineRange/start/oldLine",
            )
            .kind(AuditValueKind::Number)
            .role(AuditRole::Change)
            .display(AuditDisplay::Detail),
            AuditInputRule::value("position.newLine", "New Line", "/position/newLine")
                .kind(AuditValueKind::Number)
                .role(AuditRole::Change)
                .display(AuditDisplay::Detail),
            AuditInputRule::value("position.newPath", "New Path", "/position/newPath")
                .kind(AuditValueKind::Path)
                .role(AuditRole::Target)
                .display(AuditDisplay::Primary)
                .max_bytes(1024)
                .overflow(AuditOverflow::Omit),
            AuditInputRule::value("position.oldLine", "Old Line", "/position/oldLine")
                .kind(AuditValueKind::Number)
                .role(AuditRole::Change)
                .display(AuditDisplay::Detail),
            AuditInputRule::value("position.oldPath", "Old Path", "/position/oldPath")
                .kind(AuditValueKind::Path)
                .role(AuditRole::Target)
                .display(AuditDisplay::Primary)
                .max_bytes(1024)
                .overflow(AuditOverflow::Omit),
            AuditInputRule::value(
                "position.positionType",
                "Position Type",
                "/position/positionType",
            )
            .kind(AuditValueKind::Text)
            .role(AuditRole::Change)
            .display(AuditDisplay::Detail)
            .max_bytes(64)
            .overflow(AuditOverflow::Omit),
            AuditInputRule::value("position.width", "Width", "/position/width")
                .kind(AuditValueKind::Number)
                .role(AuditRole::Change)
                .display(AuditDisplay::Detail),
            AuditInputRule::value("position.x", "X", "/position/x")
                .kind(AuditValueKind::Number)
                .role(AuditRole::Change)
                .display(AuditDisplay::Detail),
            AuditInputRule::value("position.y", "Y", "/position/y")
                .kind(AuditValueKind::Number)
                .role(AuditRole::Change)
                .display(AuditDisplay::Detail),
        ],
        "merge_request.discussion.list" | "merge_request.draft_note.list" => vec![
            AuditInputRule::value("project", "Project", "/project")
                .kind(AuditValueKind::Identifier)
                .role(AuditRole::Target)
                .display(AuditDisplay::Primary)
                .max_bytes(1024)
                .overflow(AuditOverflow::Omit),
            AuditInputRule::value("iid", "Iid", "/iid")
                .kind(AuditValueKind::Identifier)
                .role(AuditRole::Target)
                .display(AuditDisplay::Primary)
                .max_bytes(1024)
                .overflow(AuditOverflow::Omit),
            AuditInputRule::value("maxResults", "Max Results", "/maxResults")
                .kind(AuditValueKind::Number)
                .role(AuditRole::Fact)
                .display(AuditDisplay::Detail),
            AuditInputRule::presence("pageToken", "Page Token", "/pageToken")
                .role(AuditRole::Fact)
                .display(AuditDisplay::Detail),
            AuditInputRule::value("projection", "Projection", "/projection")
                .kind(AuditValueKind::Text)
                .role(AuditRole::Fact)
                .display(AuditDisplay::Detail)
                .max_bytes(64)
                .overflow(AuditOverflow::Omit),
        ],
        "merge_request.discussion.note.add" => vec![
            AuditInputRule::value("project", "Project", "/project")
                .kind(AuditValueKind::Identifier)
                .role(AuditRole::Target)
                .display(AuditDisplay::Primary)
                .max_bytes(1024)
                .overflow(AuditOverflow::Omit),
            AuditInputRule::value("iid", "Iid", "/iid")
                .kind(AuditValueKind::Identifier)
                .role(AuditRole::Target)
                .display(AuditDisplay::Primary)
                .max_bytes(1024)
                .overflow(AuditOverflow::Omit),
            AuditInputRule::utf8_byte_count("content", "Content", "/content")
                .role(AuditRole::Change)
                .display(AuditDisplay::Detail),
            AuditInputRule::value("contentFormat", "Content Format", "/contentFormat")
                .kind(AuditValueKind::Text)
                .role(AuditRole::Change)
                .display(AuditDisplay::Detail)
                .max_bytes(64)
                .overflow(AuditOverflow::Omit),
            AuditInputRule::value("discussionId", "Discussion Id", "/discussionId")
                .kind(AuditValueKind::Identifier)
                .role(AuditRole::Target)
                .display(AuditDisplay::Primary)
                .max_bytes(1024)
                .overflow(AuditOverflow::Omit),
        ],
        "merge_request.discussion.note.delete" => vec![
            AuditInputRule::value("project", "Project", "/project")
                .kind(AuditValueKind::Identifier)
                .role(AuditRole::Target)
                .display(AuditDisplay::Primary)
                .max_bytes(1024)
                .overflow(AuditOverflow::Omit),
            AuditInputRule::value("iid", "Iid", "/iid")
                .kind(AuditValueKind::Identifier)
                .role(AuditRole::Target)
                .display(AuditDisplay::Primary)
                .max_bytes(1024)
                .overflow(AuditOverflow::Omit),
            AuditInputRule::value("discussionId", "Discussion Id", "/discussionId")
                .kind(AuditValueKind::Identifier)
                .role(AuditRole::Target)
                .display(AuditDisplay::Primary)
                .max_bytes(1024)
                .overflow(AuditOverflow::Omit),
            AuditInputRule::value("noteId", "Note Id", "/noteId")
                .kind(AuditValueKind::Identifier)
                .role(AuditRole::Target)
                .display(AuditDisplay::Primary)
                .max_bytes(1024)
                .overflow(AuditOverflow::Omit),
        ],
        "merge_request.discussion.note.update" => vec![
            AuditInputRule::value("project", "Project", "/project")
                .kind(AuditValueKind::Identifier)
                .role(AuditRole::Target)
                .display(AuditDisplay::Primary)
                .max_bytes(1024)
                .overflow(AuditOverflow::Omit),
            AuditInputRule::value("iid", "Iid", "/iid")
                .kind(AuditValueKind::Identifier)
                .role(AuditRole::Target)
                .display(AuditDisplay::Primary)
                .max_bytes(1024)
                .overflow(AuditOverflow::Omit),
            AuditInputRule::utf8_byte_count("content", "Content", "/content")
                .role(AuditRole::Change)
                .display(AuditDisplay::Detail),
            AuditInputRule::value("contentFormat", "Content Format", "/contentFormat")
                .kind(AuditValueKind::Text)
                .role(AuditRole::Change)
                .display(AuditDisplay::Detail)
                .max_bytes(64)
                .overflow(AuditOverflow::Omit),
            AuditInputRule::value("discussionId", "Discussion Id", "/discussionId")
                .kind(AuditValueKind::Identifier)
                .role(AuditRole::Target)
                .display(AuditDisplay::Primary)
                .max_bytes(1024)
                .overflow(AuditOverflow::Omit),
            AuditInputRule::value("noteId", "Note Id", "/noteId")
                .kind(AuditValueKind::Identifier)
                .role(AuditRole::Target)
                .display(AuditDisplay::Primary)
                .max_bytes(1024)
                .overflow(AuditOverflow::Omit),
        ],
        "merge_request.discussion.reopen"
        | "merge_request.discussion.resolve"
        | "merge_request.discussion.view" => vec![
            AuditInputRule::value("project", "Project", "/project")
                .kind(AuditValueKind::Identifier)
                .role(AuditRole::Target)
                .display(AuditDisplay::Primary)
                .max_bytes(1024)
                .overflow(AuditOverflow::Omit),
            AuditInputRule::value("iid", "Iid", "/iid")
                .kind(AuditValueKind::Identifier)
                .role(AuditRole::Target)
                .display(AuditDisplay::Primary)
                .max_bytes(1024)
                .overflow(AuditOverflow::Omit),
            AuditInputRule::value("discussionId", "Discussion Id", "/discussionId")
                .kind(AuditValueKind::Identifier)
                .role(AuditRole::Target)
                .display(AuditDisplay::Primary)
                .max_bytes(1024)
                .overflow(AuditOverflow::Omit),
        ],
        "merge_request.draft_note.add" => vec![
            AuditInputRule::value("project", "Project", "/project")
                .kind(AuditValueKind::Identifier)
                .role(AuditRole::Target)
                .display(AuditDisplay::Primary)
                .max_bytes(1024)
                .overflow(AuditOverflow::Omit),
            AuditInputRule::value("iid", "Iid", "/iid")
                .kind(AuditValueKind::Identifier)
                .role(AuditRole::Target)
                .display(AuditDisplay::Primary)
                .max_bytes(1024)
                .overflow(AuditOverflow::Omit),
            AuditInputRule::value("expectedHeadSha", "Expected Head Sha", "/expectedHeadSha")
                .kind(AuditValueKind::Identifier)
                .role(AuditRole::Target)
                .display(AuditDisplay::Primary)
                .max_bytes(1024)
                .overflow(AuditOverflow::Omit),
            AuditInputRule::utf8_byte_count("content", "Content", "/content")
                .role(AuditRole::Change)
                .display(AuditDisplay::Detail),
            AuditInputRule::value("contentFormat", "Content Format", "/contentFormat")
                .kind(AuditValueKind::Text)
                .role(AuditRole::Change)
                .display(AuditDisplay::Detail)
                .max_bytes(64)
                .overflow(AuditOverflow::Omit),
            AuditInputRule::value(
                "inReplyToDiscussionId",
                "In Reply To Discussion Id",
                "/inReplyToDiscussionId",
            )
            .kind(AuditValueKind::Identifier)
            .role(AuditRole::Target)
            .display(AuditDisplay::Primary)
            .max_bytes(1024)
            .overflow(AuditOverflow::Omit),
            AuditInputRule::value("position.height", "Height", "/position/height")
                .kind(AuditValueKind::Number)
                .role(AuditRole::Change)
                .display(AuditDisplay::Detail),
            AuditInputRule::value(
                "position.lineRange.end.newLine",
                "New Line",
                "/position/lineRange/end/newLine",
            )
            .kind(AuditValueKind::Number)
            .role(AuditRole::Change)
            .display(AuditDisplay::Detail),
            AuditInputRule::value(
                "position.lineRange.end.oldLine",
                "Old Line",
                "/position/lineRange/end/oldLine",
            )
            .kind(AuditValueKind::Number)
            .role(AuditRole::Change)
            .display(AuditDisplay::Detail),
            AuditInputRule::value(
                "position.lineRange.start.newLine",
                "New Line",
                "/position/lineRange/start/newLine",
            )
            .kind(AuditValueKind::Number)
            .role(AuditRole::Change)
            .display(AuditDisplay::Detail),
            AuditInputRule::value(
                "position.lineRange.start.oldLine",
                "Old Line",
                "/position/lineRange/start/oldLine",
            )
            .kind(AuditValueKind::Number)
            .role(AuditRole::Change)
            .display(AuditDisplay::Detail),
            AuditInputRule::value("position.newLine", "New Line", "/position/newLine")
                .kind(AuditValueKind::Number)
                .role(AuditRole::Change)
                .display(AuditDisplay::Detail),
            AuditInputRule::value("position.newPath", "New Path", "/position/newPath")
                .kind(AuditValueKind::Path)
                .role(AuditRole::Target)
                .display(AuditDisplay::Primary)
                .max_bytes(1024)
                .overflow(AuditOverflow::Omit),
            AuditInputRule::value("position.oldLine", "Old Line", "/position/oldLine")
                .kind(AuditValueKind::Number)
                .role(AuditRole::Change)
                .display(AuditDisplay::Detail),
            AuditInputRule::value("position.oldPath", "Old Path", "/position/oldPath")
                .kind(AuditValueKind::Path)
                .role(AuditRole::Target)
                .display(AuditDisplay::Primary)
                .max_bytes(1024)
                .overflow(AuditOverflow::Omit),
            AuditInputRule::value(
                "position.positionType",
                "Position Type",
                "/position/positionType",
            )
            .kind(AuditValueKind::Text)
            .role(AuditRole::Change)
            .display(AuditDisplay::Detail)
            .max_bytes(64)
            .overflow(AuditOverflow::Omit),
            AuditInputRule::value("position.width", "Width", "/position/width")
                .kind(AuditValueKind::Number)
                .role(AuditRole::Change)
                .display(AuditDisplay::Detail),
            AuditInputRule::value("position.x", "X", "/position/x")
                .kind(AuditValueKind::Number)
                .role(AuditRole::Change)
                .display(AuditDisplay::Detail),
            AuditInputRule::value("position.y", "Y", "/position/y")
                .kind(AuditValueKind::Number)
                .role(AuditRole::Change)
                .display(AuditDisplay::Detail),
            AuditInputRule::value(
                "resolveDiscussion",
                "Resolve Discussion",
                "/resolveDiscussion",
            )
            .kind(AuditValueKind::Boolean)
            .role(AuditRole::Change)
            .display(AuditDisplay::Detail),
        ],
        "merge_request.draft_note.delete"
        | "merge_request.draft_note.publish"
        | "merge_request.draft_note.view" => vec![
            AuditInputRule::value("project", "Project", "/project")
                .kind(AuditValueKind::Identifier)
                .role(AuditRole::Target)
                .display(AuditDisplay::Primary)
                .max_bytes(1024)
                .overflow(AuditOverflow::Omit),
            AuditInputRule::value("iid", "Iid", "/iid")
                .kind(AuditValueKind::Identifier)
                .role(AuditRole::Target)
                .display(AuditDisplay::Primary)
                .max_bytes(1024)
                .overflow(AuditOverflow::Omit),
            AuditInputRule::value("draftNoteId", "Draft Note Id", "/draftNoteId")
                .kind(AuditValueKind::Identifier)
                .role(AuditRole::Target)
                .display(AuditDisplay::Primary)
                .max_bytes(1024)
                .overflow(AuditOverflow::Omit),
        ],
        "merge_request.draft_note.publish_all" => vec![
            AuditInputRule::value("project", "Project", "/project")
                .kind(AuditValueKind::Identifier)
                .role(AuditRole::Target)
                .display(AuditDisplay::Primary)
                .max_bytes(1024)
                .overflow(AuditOverflow::Omit),
            AuditInputRule::value("iid", "Iid", "/iid")
                .kind(AuditValueKind::Identifier)
                .role(AuditRole::Target)
                .display(AuditDisplay::Primary)
                .max_bytes(1024)
                .overflow(AuditOverflow::Omit),
            AuditInputRule::utf8_byte_count("content", "Content", "/content")
                .role(AuditRole::Change)
                .display(AuditDisplay::Detail),
            AuditInputRule::value("contentFormat", "Content Format", "/contentFormat")
                .kind(AuditValueKind::Text)
                .role(AuditRole::Change)
                .display(AuditDisplay::Detail)
                .max_bytes(64)
                .overflow(AuditOverflow::Omit),
            AuditInputRule::value("internal", "Internal", "/internal")
                .kind(AuditValueKind::Boolean)
                .role(AuditRole::Change)
                .display(AuditDisplay::Detail),
        ],
        "merge_request.draft_note.update" => vec![
            AuditInputRule::value("project", "Project", "/project")
                .kind(AuditValueKind::Identifier)
                .role(AuditRole::Target)
                .display(AuditDisplay::Primary)
                .max_bytes(1024)
                .overflow(AuditOverflow::Omit),
            AuditInputRule::value("iid", "Iid", "/iid")
                .kind(AuditValueKind::Identifier)
                .role(AuditRole::Target)
                .display(AuditDisplay::Primary)
                .max_bytes(1024)
                .overflow(AuditOverflow::Omit),
            AuditInputRule::value("expectedHeadSha", "Expected Head Sha", "/expectedHeadSha")
                .kind(AuditValueKind::Identifier)
                .role(AuditRole::Target)
                .display(AuditDisplay::Primary)
                .max_bytes(1024)
                .overflow(AuditOverflow::Omit),
            AuditInputRule::utf8_byte_count("content", "Content", "/content")
                .role(AuditRole::Change)
                .display(AuditDisplay::Detail),
            AuditInputRule::value("contentFormat", "Content Format", "/contentFormat")
                .kind(AuditValueKind::Text)
                .role(AuditRole::Change)
                .display(AuditDisplay::Detail)
                .max_bytes(64)
                .overflow(AuditOverflow::Omit),
            AuditInputRule::value("draftNoteId", "Draft Note Id", "/draftNoteId")
                .kind(AuditValueKind::Identifier)
                .role(AuditRole::Target)
                .display(AuditDisplay::Primary)
                .max_bytes(1024)
                .overflow(AuditOverflow::Omit),
            AuditInputRule::value("position.height", "Height", "/position/height")
                .kind(AuditValueKind::Number)
                .role(AuditRole::Change)
                .display(AuditDisplay::Detail),
            AuditInputRule::value(
                "position.lineRange.end.newLine",
                "New Line",
                "/position/lineRange/end/newLine",
            )
            .kind(AuditValueKind::Number)
            .role(AuditRole::Change)
            .display(AuditDisplay::Detail),
            AuditInputRule::value(
                "position.lineRange.end.oldLine",
                "Old Line",
                "/position/lineRange/end/oldLine",
            )
            .kind(AuditValueKind::Number)
            .role(AuditRole::Change)
            .display(AuditDisplay::Detail),
            AuditInputRule::value(
                "position.lineRange.start.newLine",
                "New Line",
                "/position/lineRange/start/newLine",
            )
            .kind(AuditValueKind::Number)
            .role(AuditRole::Change)
            .display(AuditDisplay::Detail),
            AuditInputRule::value(
                "position.lineRange.start.oldLine",
                "Old Line",
                "/position/lineRange/start/oldLine",
            )
            .kind(AuditValueKind::Number)
            .role(AuditRole::Change)
            .display(AuditDisplay::Detail),
            AuditInputRule::value("position.newLine", "New Line", "/position/newLine")
                .kind(AuditValueKind::Number)
                .role(AuditRole::Change)
                .display(AuditDisplay::Detail),
            AuditInputRule::value("position.newPath", "New Path", "/position/newPath")
                .kind(AuditValueKind::Path)
                .role(AuditRole::Target)
                .display(AuditDisplay::Primary)
                .max_bytes(1024)
                .overflow(AuditOverflow::Omit),
            AuditInputRule::value("position.oldLine", "Old Line", "/position/oldLine")
                .kind(AuditValueKind::Number)
                .role(AuditRole::Change)
                .display(AuditDisplay::Detail),
            AuditInputRule::value("position.oldPath", "Old Path", "/position/oldPath")
                .kind(AuditValueKind::Path)
                .role(AuditRole::Target)
                .display(AuditDisplay::Primary)
                .max_bytes(1024)
                .overflow(AuditOverflow::Omit),
            AuditInputRule::value(
                "position.positionType",
                "Position Type",
                "/position/positionType",
            )
            .kind(AuditValueKind::Text)
            .role(AuditRole::Change)
            .display(AuditDisplay::Detail)
            .max_bytes(64)
            .overflow(AuditOverflow::Omit),
            AuditInputRule::value("position.width", "Width", "/position/width")
                .kind(AuditValueKind::Number)
                .role(AuditRole::Change)
                .display(AuditDisplay::Detail),
            AuditInputRule::value("position.x", "X", "/position/x")
                .kind(AuditValueKind::Number)
                .role(AuditRole::Change)
                .display(AuditDisplay::Detail),
            AuditInputRule::value("position.y", "Y", "/position/y")
                .kind(AuditValueKind::Number)
                .role(AuditRole::Change)
                .display(AuditDisplay::Detail),
        ],
        "merge_request.merge" => vec![
            AuditInputRule::value("project", "Project", "/project")
                .kind(AuditValueKind::Identifier)
                .role(AuditRole::Target)
                .display(AuditDisplay::Primary)
                .max_bytes(1024)
                .overflow(AuditOverflow::Omit),
            AuditInputRule::value("iid", "Iid", "/iid")
                .kind(AuditValueKind::Identifier)
                .role(AuditRole::Target)
                .display(AuditDisplay::Primary)
                .max_bytes(1024)
                .overflow(AuditOverflow::Omit),
            AuditInputRule::value("sha", "Sha", "/sha")
                .kind(AuditValueKind::Identifier)
                .role(AuditRole::Target)
                .display(AuditDisplay::Primary)
                .max_bytes(1024)
                .overflow(AuditOverflow::Omit),
            AuditInputRule::utf8_byte_count(
                "mergeCommitMessage",
                "Merge Commit Message",
                "/mergeCommitMessage",
            )
            .role(AuditRole::Change)
            .display(AuditDisplay::Detail),
            AuditInputRule::value(
                "shouldRemoveSourceBranch",
                "Should Remove Source Branch",
                "/shouldRemoveSourceBranch",
            )
            .kind(AuditValueKind::Boolean)
            .role(AuditRole::Change)
            .display(AuditDisplay::Detail),
            AuditInputRule::value("squash", "Squash", "/squash")
                .kind(AuditValueKind::Boolean)
                .role(AuditRole::Change)
                .display(AuditDisplay::Detail),
            AuditInputRule::utf8_byte_count(
                "squashCommitMessage",
                "Squash Commit Message",
                "/squashCommitMessage",
            )
            .role(AuditRole::Change)
            .display(AuditDisplay::Detail),
        ],
        "merge_request.review.submit" => vec![
            AuditInputRule::value("project", "Project", "/project")
                .kind(AuditValueKind::Identifier)
                .role(AuditRole::Target)
                .display(AuditDisplay::Primary)
                .max_bytes(1024)
                .overflow(AuditOverflow::Omit),
            AuditInputRule::value("iid", "Iid", "/iid")
                .kind(AuditValueKind::Identifier)
                .role(AuditRole::Target)
                .display(AuditDisplay::Primary)
                .max_bytes(1024)
                .overflow(AuditOverflow::Omit),
            AuditInputRule::utf8_byte_count("content", "Content", "/content")
                .role(AuditRole::Change)
                .display(AuditDisplay::Detail),
            AuditInputRule::value("contentFormat", "Content Format", "/contentFormat")
                .kind(AuditValueKind::Text)
                .role(AuditRole::Change)
                .display(AuditDisplay::Detail)
                .max_bytes(64)
                .overflow(AuditOverflow::Omit),
            AuditInputRule::value("internal", "Internal", "/internal")
                .kind(AuditValueKind::Boolean)
                .role(AuditRole::Change)
                .display(AuditDisplay::Detail),
            AuditInputRule::value("reviewerState", "Reviewer State", "/reviewerState")
                .kind(AuditValueKind::Text)
                .role(AuditRole::Change)
                .display(AuditDisplay::Detail)
                .max_bytes(64)
                .overflow(AuditOverflow::Omit),
        ],
        "merge_request.search" => vec![
            AuditInputRule::value("project", "Project", "/project")
                .kind(AuditValueKind::Identifier)
                .role(AuditRole::Target)
                .display(AuditDisplay::Primary)
                .max_bytes(1024)
                .overflow(AuditOverflow::Omit),
            AuditInputRule::value("search", "Search", "/search")
                .kind(AuditValueKind::Query)
                .role(AuditRole::Fact)
                .display(AuditDisplay::Primary)
                .max_bytes(4096)
                .overflow(AuditOverflow::Prefix),
            AuditInputRule::value("assignee", "Assignee", "/assignee")
                .kind(AuditValueKind::Identifier)
                .role(AuditRole::Fact)
                .display(AuditDisplay::Detail)
                .max_bytes(1024)
                .overflow(AuditOverflow::Omit),
            AuditInputRule::value("author", "Author", "/author")
                .kind(AuditValueKind::Identifier)
                .role(AuditRole::Fact)
                .display(AuditDisplay::Detail)
                .max_bytes(1024)
                .overflow(AuditOverflow::Omit),
            AuditInputRule::value("createdAfter", "Created After", "/createdAfter")
                .kind(AuditValueKind::Date)
                .role(AuditRole::Fact)
                .display(AuditDisplay::Detail)
                .max_bytes(1024)
                .overflow(AuditOverflow::Omit),
            AuditInputRule::values("labels", "Labels", "/labels")
                .kind(AuditValueKind::Identifier)
                .role(AuditRole::Fact)
                .display(AuditDisplay::Detail)
                .max_bytes(1024)
                .overflow(AuditOverflow::Omit),
            AuditInputRule::value("maxResults", "Max Results", "/maxResults")
                .kind(AuditValueKind::Number)
                .role(AuditRole::Fact)
                .display(AuditDisplay::Detail),
            AuditInputRule::value("milestone", "Milestone", "/milestone")
                .kind(AuditValueKind::Identifier)
                .role(AuditRole::Fact)
                .display(AuditDisplay::Detail)
                .max_bytes(1024)
                .overflow(AuditOverflow::Omit),
            AuditInputRule::value("orderBy", "Order By", "/orderBy")
                .kind(AuditValueKind::Text)
                .role(AuditRole::Fact)
                .display(AuditDisplay::Detail)
                .max_bytes(64)
                .overflow(AuditOverflow::Omit),
            AuditInputRule::presence("pageToken", "Page Token", "/pageToken")
                .role(AuditRole::Fact)
                .display(AuditDisplay::Detail),
            AuditInputRule::value("reviewer", "Reviewer", "/reviewer")
                .kind(AuditValueKind::Identifier)
                .role(AuditRole::Fact)
                .display(AuditDisplay::Detail)
                .max_bytes(1024)
                .overflow(AuditOverflow::Omit),
            AuditInputRule::value("sort", "Sort", "/sort")
                .kind(AuditValueKind::Text)
                .role(AuditRole::Fact)
                .display(AuditDisplay::Detail)
                .max_bytes(64)
                .overflow(AuditOverflow::Omit),
            AuditInputRule::value("sourceBranch", "Source Branch", "/sourceBranch")
                .kind(AuditValueKind::Identifier)
                .role(AuditRole::Fact)
                .display(AuditDisplay::Detail)
                .max_bytes(1024)
                .overflow(AuditOverflow::Omit),
            AuditInputRule::value("state", "State", "/state")
                .kind(AuditValueKind::Text)
                .role(AuditRole::Fact)
                .display(AuditDisplay::Detail)
                .max_bytes(64)
                .overflow(AuditOverflow::Omit),
            AuditInputRule::value("targetBranch", "Target Branch", "/targetBranch")
                .kind(AuditValueKind::Identifier)
                .role(AuditRole::Fact)
                .display(AuditDisplay::Detail)
                .max_bytes(1024)
                .overflow(AuditOverflow::Omit),
            AuditInputRule::value("updatedAfter", "Updated After", "/updatedAfter")
                .kind(AuditValueKind::Date)
                .role(AuditRole::Fact)
                .display(AuditDisplay::Detail)
                .max_bytes(1024)
                .overflow(AuditOverflow::Omit),
        ],
        "merge_request.suggestion.apply" => vec![
            AuditInputRule::value("project", "Project", "/project")
                .kind(AuditValueKind::Identifier)
                .role(AuditRole::Target)
                .display(AuditDisplay::Primary)
                .max_bytes(1024)
                .overflow(AuditOverflow::Omit),
            AuditInputRule::value("iid", "Iid", "/iid")
                .kind(AuditValueKind::Identifier)
                .role(AuditRole::Target)
                .display(AuditDisplay::Primary)
                .max_bytes(1024)
                .overflow(AuditOverflow::Omit),
            AuditInputRule::value("expectedHeadSha", "Expected Head Sha", "/expectedHeadSha")
                .kind(AuditValueKind::Identifier)
                .role(AuditRole::Target)
                .display(AuditDisplay::Primary)
                .max_bytes(1024)
                .overflow(AuditOverflow::Omit),
            AuditInputRule::utf8_byte_count("commitMessage", "Commit Message", "/commitMessage")
                .role(AuditRole::Change)
                .display(AuditDisplay::Detail),
            AuditInputRule::value("discussionId", "Discussion Id", "/discussionId")
                .kind(AuditValueKind::Identifier)
                .role(AuditRole::Target)
                .display(AuditDisplay::Primary)
                .max_bytes(1024)
                .overflow(AuditOverflow::Omit),
            AuditInputRule::value("noteId", "Note Id", "/noteId")
                .kind(AuditValueKind::Identifier)
                .role(AuditRole::Target)
                .display(AuditDisplay::Primary)
                .max_bytes(1024)
                .overflow(AuditOverflow::Omit),
            AuditInputRule::value("suggestionId", "Suggestion Id", "/suggestionId")
                .kind(AuditValueKind::Identifier)
                .role(AuditRole::Target)
                .display(AuditDisplay::Primary)
                .max_bytes(1024)
                .overflow(AuditOverflow::Omit),
        ],
        "merge_request.suggestion.batch_apply" => vec![
            AuditInputRule::value("project", "Project", "/project")
                .kind(AuditValueKind::Identifier)
                .role(AuditRole::Target)
                .display(AuditDisplay::Primary)
                .max_bytes(1024)
                .overflow(AuditOverflow::Omit),
            AuditInputRule::value("iid", "Iid", "/iid")
                .kind(AuditValueKind::Identifier)
                .role(AuditRole::Target)
                .display(AuditDisplay::Primary)
                .max_bytes(1024)
                .overflow(AuditOverflow::Omit),
            AuditInputRule::value("expectedHeadSha", "Expected Head Sha", "/expectedHeadSha")
                .kind(AuditValueKind::Identifier)
                .role(AuditRole::Target)
                .display(AuditDisplay::Primary)
                .max_bytes(1024)
                .overflow(AuditOverflow::Omit),
            AuditInputRule::utf8_byte_count("commitMessage", "Commit Message", "/commitMessage")
                .role(AuditRole::Change)
                .display(AuditDisplay::Detail),
            AuditInputRule::records(
                "suggestions",
                "Suggestions",
                "/suggestions",
                [
                    AuditInputRule::value("discussionId", "Discussion Id", "/discussionId")
                        .kind(AuditValueKind::Identifier)
                        .role(AuditRole::Target)
                        .display(AuditDisplay::Primary)
                        .max_bytes(1024)
                        .overflow(AuditOverflow::Omit),
                    AuditInputRule::value("noteId", "Note Id", "/noteId")
                        .kind(AuditValueKind::Identifier)
                        .role(AuditRole::Target)
                        .display(AuditDisplay::Primary)
                        .max_bytes(1024)
                        .overflow(AuditOverflow::Omit),
                    AuditInputRule::value("suggestionId", "Suggestion Id", "/suggestionId")
                        .kind(AuditValueKind::Identifier)
                        .role(AuditRole::Target)
                        .display(AuditDisplay::Primary)
                        .max_bytes(1024)
                        .overflow(AuditOverflow::Omit),
                ],
            )
            .role(AuditRole::Fact)
            .display(AuditDisplay::Primary),
        ],
        "merge_request.update" => vec![
            AuditInputRule::value("project", "Project", "/project")
                .kind(AuditValueKind::Identifier)
                .role(AuditRole::Target)
                .display(AuditDisplay::Primary)
                .max_bytes(1024)
                .overflow(AuditOverflow::Omit),
            AuditInputRule::value("iid", "Iid", "/iid")
                .kind(AuditValueKind::Identifier)
                .role(AuditRole::Target)
                .display(AuditDisplay::Primary)
                .max_bytes(1024)
                .overflow(AuditOverflow::Omit),
            AuditInputRule::value("title", "Title", "/title")
                .kind(AuditValueKind::Text)
                .role(AuditRole::Change)
                .display(AuditDisplay::Primary)
                .max_bytes(1024)
                .overflow(AuditOverflow::Prefix),
            AuditInputRule::values("addLabels", "Add Labels", "/addLabels")
                .kind(AuditValueKind::Identifier)
                .role(AuditRole::Change)
                .display(AuditDisplay::Detail)
                .max_bytes(1024)
                .overflow(AuditOverflow::Omit),
            AuditInputRule::values("assignees", "Assignees", "/assignees")
                .kind(AuditValueKind::Identifier)
                .role(AuditRole::Change)
                .display(AuditDisplay::Detail)
                .max_bytes(1024)
                .overflow(AuditOverflow::Omit),
            AuditInputRule::utf8_byte_count("content", "Content", "/content")
                .role(AuditRole::Change)
                .display(AuditDisplay::Detail),
            AuditInputRule::value("contentFormat", "Content Format", "/contentFormat")
                .kind(AuditValueKind::Text)
                .role(AuditRole::Change)
                .display(AuditDisplay::Detail)
                .max_bytes(64)
                .overflow(AuditOverflow::Omit),
            AuditInputRule::values("labels", "Labels", "/labels")
                .kind(AuditValueKind::Identifier)
                .role(AuditRole::Change)
                .display(AuditDisplay::Detail)
                .max_bytes(1024)
                .overflow(AuditOverflow::Omit),
            AuditInputRule::values("removeLabels", "Remove Labels", "/removeLabels")
                .kind(AuditValueKind::Identifier)
                .role(AuditRole::Change)
                .display(AuditDisplay::Detail)
                .max_bytes(1024)
                .overflow(AuditOverflow::Omit),
            AuditInputRule::value(
                "removeSourceBranch",
                "Remove Source Branch",
                "/removeSourceBranch",
            )
            .kind(AuditValueKind::Boolean)
            .role(AuditRole::Change)
            .display(AuditDisplay::Detail),
            AuditInputRule::values("reviewers", "Reviewers", "/reviewers")
                .kind(AuditValueKind::Identifier)
                .role(AuditRole::Change)
                .display(AuditDisplay::Detail)
                .max_bytes(1024)
                .overflow(AuditOverflow::Omit),
            AuditInputRule::value("squash", "Squash", "/squash")
                .kind(AuditValueKind::Boolean)
                .role(AuditRole::Change)
                .display(AuditDisplay::Detail),
            AuditInputRule::value("stateEvent", "State Event", "/stateEvent")
                .kind(AuditValueKind::Text)
                .role(AuditRole::Change)
                .display(AuditDisplay::Detail)
                .max_bytes(64)
                .overflow(AuditOverflow::Omit),
            AuditInputRule::value("targetBranch", "Target Branch", "/targetBranch")
                .kind(AuditValueKind::Identifier)
                .role(AuditRole::Change)
                .display(AuditDisplay::Detail)
                .max_bytes(1024)
                .overflow(AuditOverflow::Omit),
        ],
        "pipeline.cancel" | "pipeline.retry" | "pipeline.view" => vec![
            AuditInputRule::value("project", "Project", "/project")
                .kind(AuditValueKind::Identifier)
                .role(AuditRole::Target)
                .display(AuditDisplay::Primary)
                .max_bytes(1024)
                .overflow(AuditOverflow::Omit),
            AuditInputRule::value("pipelineId", "Pipeline Id", "/pipelineId")
                .kind(AuditValueKind::Identifier)
                .role(AuditRole::Target)
                .display(AuditDisplay::Primary)
                .max_bytes(1024)
                .overflow(AuditOverflow::Omit),
        ],
        "pipeline.list" => vec![
            AuditInputRule::value("project", "Project", "/project")
                .kind(AuditValueKind::Identifier)
                .role(AuditRole::Target)
                .display(AuditDisplay::Primary)
                .max_bytes(1024)
                .overflow(AuditOverflow::Omit),
            AuditInputRule::value("ref", "Ref", "/ref")
                .kind(AuditValueKind::Identifier)
                .role(AuditRole::Target)
                .display(AuditDisplay::Primary)
                .max_bytes(1024)
                .overflow(AuditOverflow::Omit),
            AuditInputRule::value("sha", "Sha", "/sha")
                .kind(AuditValueKind::Identifier)
                .role(AuditRole::Target)
                .display(AuditDisplay::Primary)
                .max_bytes(1024)
                .overflow(AuditOverflow::Omit),
            AuditInputRule::value("maxResults", "Max Results", "/maxResults")
                .kind(AuditValueKind::Number)
                .role(AuditRole::Fact)
                .display(AuditDisplay::Detail),
            AuditInputRule::value("source", "Source", "/source")
                .kind(AuditValueKind::Text)
                .role(AuditRole::Fact)
                .display(AuditDisplay::Detail)
                .max_bytes(64)
                .overflow(AuditOverflow::Omit),
            AuditInputRule::value("status", "Status", "/status")
                .kind(AuditValueKind::Text)
                .role(AuditRole::Fact)
                .display(AuditDisplay::Detail)
                .max_bytes(64)
                .overflow(AuditOverflow::Omit),
            AuditInputRule::value("updatedAfter", "Updated After", "/updatedAfter")
                .kind(AuditValueKind::Date)
                .role(AuditRole::Fact)
                .display(AuditDisplay::Detail)
                .max_bytes(1024)
                .overflow(AuditOverflow::Omit),
            AuditInputRule::value("updatedBefore", "Updated Before", "/updatedBefore")
                .kind(AuditValueKind::Date)
                .role(AuditRole::Fact)
                .display(AuditDisplay::Detail)
                .max_bytes(1024)
                .overflow(AuditOverflow::Omit),
        ],
        "pipeline.run" => vec![
            AuditInputRule::value("project", "Project", "/project")
                .kind(AuditValueKind::Identifier)
                .role(AuditRole::Target)
                .display(AuditDisplay::Primary)
                .max_bytes(1024)
                .overflow(AuditOverflow::Omit),
            AuditInputRule::value("ref", "Ref", "/ref")
                .kind(AuditValueKind::Identifier)
                .role(AuditRole::Target)
                .display(AuditDisplay::Primary)
                .max_bytes(1024)
                .overflow(AuditOverflow::Omit),
        ],
        "project.access_token.create" => vec![
            AuditInputRule::value("project", "Project", "/project")
                .kind(AuditValueKind::Identifier)
                .role(AuditRole::Target)
                .display(AuditDisplay::Primary)
                .max_bytes(1024)
                .overflow(AuditOverflow::Omit),
            AuditInputRule::value("accessLevel", "Access Level", "/accessLevel")
                .kind(AuditValueKind::Number)
                .role(AuditRole::Change)
                .display(AuditDisplay::Detail),
            AuditInputRule::value("expiresAt", "Expires At", "/expiresAt")
                .kind(AuditValueKind::Date)
                .role(AuditRole::Change)
                .display(AuditDisplay::Detail)
                .max_bytes(1024)
                .overflow(AuditOverflow::Omit),
            AuditInputRule::value("name", "Name", "/name")
                .kind(AuditValueKind::Identifier)
                .role(AuditRole::Change)
                .display(AuditDisplay::Primary)
                .max_bytes(1024)
                .overflow(AuditOverflow::Omit),
            AuditInputRule::values("scopes", "Scopes", "/scopes")
                .kind(AuditValueKind::Text)
                .role(AuditRole::Change)
                .display(AuditDisplay::Detail)
                .max_bytes(64)
                .overflow(AuditOverflow::Omit),
        ],
        "project.access_token.list" | "service_account.list" | "webhook.list" => vec![
            AuditInputRule::value("project", "Project", "/project")
                .kind(AuditValueKind::Identifier)
                .role(AuditRole::Target)
                .display(AuditDisplay::Primary)
                .max_bytes(1024)
                .overflow(AuditOverflow::Omit),
            AuditInputRule::value("maxResults", "Max Results", "/maxResults")
                .kind(AuditValueKind::Number)
                .role(AuditRole::Fact)
                .display(AuditDisplay::Detail),
            AuditInputRule::presence("pageToken", "Page Token", "/pageToken")
                .role(AuditRole::Fact)
                .display(AuditDisplay::Detail),
        ],
        "project.access_token.revoke" | "project.access_token.view" => vec![
            AuditInputRule::value("project", "Project", "/project")
                .kind(AuditValueKind::Identifier)
                .role(AuditRole::Target)
                .display(AuditDisplay::Primary)
                .max_bytes(1024)
                .overflow(AuditOverflow::Omit),
            AuditInputRule::value("tokenId", "Token Id", "/tokenId")
                .kind(AuditValueKind::Identifier)
                .role(AuditRole::Target)
                .display(AuditDisplay::Primary)
                .max_bytes(1024)
                .overflow(AuditOverflow::Omit),
        ],
        "project.access_token.rotate" => vec![
            AuditInputRule::value("project", "Project", "/project")
                .kind(AuditValueKind::Identifier)
                .role(AuditRole::Target)
                .display(AuditDisplay::Primary)
                .max_bytes(1024)
                .overflow(AuditOverflow::Omit),
            AuditInputRule::value("expiresAt", "Expires At", "/expiresAt")
                .kind(AuditValueKind::Date)
                .role(AuditRole::Change)
                .display(AuditDisplay::Detail)
                .max_bytes(1024)
                .overflow(AuditOverflow::Omit),
            AuditInputRule::value("tokenId", "Token Id", "/tokenId")
                .kind(AuditValueKind::Identifier)
                .role(AuditRole::Target)
                .display(AuditDisplay::Primary)
                .max_bytes(1024)
                .overflow(AuditOverflow::Omit),
        ],
        "project.list" => vec![
            AuditInputRule::value("maxResults", "Max Results", "/maxResults")
                .kind(AuditValueKind::Number)
                .role(AuditRole::Fact)
                .display(AuditDisplay::Detail),
            AuditInputRule::presence("pageToken", "Page Token", "/pageToken")
                .role(AuditRole::Fact)
                .display(AuditDisplay::Detail),
        ],
        "project.search" => vec![
            AuditInputRule::value("search", "Search", "/search")
                .kind(AuditValueKind::Query)
                .role(AuditRole::Fact)
                .display(AuditDisplay::Primary)
                .max_bytes(4096)
                .overflow(AuditOverflow::Prefix),
            AuditInputRule::value("archived", "Archived", "/archived")
                .kind(AuditValueKind::Boolean)
                .role(AuditRole::Fact)
                .display(AuditDisplay::Detail),
            AuditInputRule::value(
                "includeNamespaces",
                "Include Namespaces",
                "/includeNamespaces",
            )
            .kind(AuditValueKind::Boolean)
            .role(AuditRole::Fact)
            .display(AuditDisplay::Detail),
            AuditInputRule::value("maxResults", "Max Results", "/maxResults")
                .kind(AuditValueKind::Number)
                .role(AuditRole::Fact)
                .display(AuditDisplay::Detail),
            AuditInputRule::presence("pageToken", "Page Token", "/pageToken")
                .role(AuditRole::Fact)
                .display(AuditDisplay::Detail),
        ],
        "project.upload" => vec![
            AuditInputRule::value("project", "Project", "/project")
                .kind(AuditValueKind::Identifier)
                .role(AuditRole::Target)
                .display(AuditDisplay::Primary)
                .max_bytes(1024)
                .overflow(AuditOverflow::Omit),
            AuditInputRule::records(
                "attachments",
                "Attachments",
                "/attachments",
                [
                    AuditInputRule::value("contentType", "Content Type", "/contentType")
                        .kind(AuditValueKind::Text)
                        .role(AuditRole::Fact)
                        .display(AuditDisplay::Detail)
                        .max_bytes(1024)
                        .overflow(AuditOverflow::Omit),
                    AuditInputRule::omit("field", "/field"),
                    AuditInputRule::value("filename", "Filename", "/filename")
                        .kind(AuditValueKind::Path)
                        .role(AuditRole::Target)
                        .display(AuditDisplay::Primary)
                        .max_bytes(1024)
                        .overflow(AuditOverflow::Omit),
                    AuditInputRule::omit("sha256", "/sha256"),
                    AuditInputRule::value("size", "Size", "/size")
                        .kind(AuditValueKind::Bytes)
                        .role(AuditRole::Fact)
                        .display(AuditDisplay::Detail),
                ],
            )
            .role(AuditRole::Fact)
            .display(AuditDisplay::Primary),
            AuditInputRule::presence("url", "Url", "/url")
                .role(AuditRole::Fact)
                .display(AuditDisplay::Detail),
        ],
        "project.view" => vec![
            AuditInputRule::value("project", "Project", "/project")
                .kind(AuditValueKind::Identifier)
                .role(AuditRole::Target)
                .display(AuditDisplay::Primary)
                .max_bytes(1024)
                .overflow(AuditOverflow::Omit),
            AuditInputRule::presence("url", "Url", "/url")
                .role(AuditRole::Fact)
                .display(AuditDisplay::Detail),
        ],
        "protected_branch.list" => vec![
            AuditInputRule::value("project", "Project", "/project")
                .kind(AuditValueKind::Identifier)
                .role(AuditRole::Target)
                .display(AuditDisplay::Primary)
                .max_bytes(1024)
                .overflow(AuditOverflow::Omit),
            AuditInputRule::value("search", "Search", "/search")
                .kind(AuditValueKind::Query)
                .role(AuditRole::Fact)
                .display(AuditDisplay::Primary)
                .max_bytes(4096)
                .overflow(AuditOverflow::Prefix),
            AuditInputRule::value("maxResults", "Max Results", "/maxResults")
                .kind(AuditValueKind::Number)
                .role(AuditRole::Fact)
                .display(AuditDisplay::Detail),
        ],
        "protected_branch.verify" => vec![
            AuditInputRule::value("project", "Project", "/project")
                .kind(AuditValueKind::Identifier)
                .role(AuditRole::Target)
                .display(AuditDisplay::Primary)
                .max_bytes(1024)
                .overflow(AuditOverflow::Omit),
            AuditInputRule::values("requiredPatterns", "Required Patterns", "/requiredPatterns")
                .kind(AuditValueKind::Identifier)
                .role(AuditRole::Fact)
                .display(AuditDisplay::Detail)
                .max_bytes(1024)
                .overflow(AuditOverflow::Omit),
        ],
        "protected_branch.view" => vec![
            AuditInputRule::value("project", "Project", "/project")
                .kind(AuditValueKind::Identifier)
                .role(AuditRole::Target)
                .display(AuditDisplay::Primary)
                .max_bytes(1024)
                .overflow(AuditOverflow::Omit),
            AuditInputRule::value(
                "branchOrWildcardName",
                "Branch Or Wildcard Name",
                "/branchOrWildcardName",
            )
            .kind(AuditValueKind::Identifier)
            .role(AuditRole::Fact)
            .display(AuditDisplay::Detail)
            .max_bytes(1024)
            .overflow(AuditOverflow::Omit),
        ],
        "search.code"
        | "search.comments"
        | "search.commits"
        | "search.issues"
        | "search.merge_requests"
        | "search.wiki" => vec![
            AuditInputRule::value("project", "Project", "/project")
                .kind(AuditValueKind::Identifier)
                .role(AuditRole::Target)
                .display(AuditDisplay::Primary)
                .max_bytes(1024)
                .overflow(AuditOverflow::Omit),
            AuditInputRule::value("search", "Search", "/search")
                .kind(AuditValueKind::Query)
                .role(AuditRole::Fact)
                .display(AuditDisplay::Primary)
                .max_bytes(4096)
                .overflow(AuditOverflow::Prefix),
            AuditInputRule::value("engine", "Engine", "/engine")
                .kind(AuditValueKind::Text)
                .role(AuditRole::Fact)
                .display(AuditDisplay::Detail)
                .max_bytes(64)
                .overflow(AuditOverflow::Omit),
            AuditInputRule::value("maxResults", "Max Results", "/maxResults")
                .kind(AuditValueKind::Number)
                .role(AuditRole::Fact)
                .display(AuditDisplay::Detail),
            AuditInputRule::presence("pageToken", "Page Token", "/pageToken")
                .role(AuditRole::Fact)
                .display(AuditDisplay::Detail),
        ],
        "service_account.create" => vec![
            AuditInputRule::value("project", "Project", "/project")
                .kind(AuditValueKind::Identifier)
                .role(AuditRole::Target)
                .display(AuditDisplay::Primary)
                .max_bytes(1024)
                .overflow(AuditOverflow::Omit),
            AuditInputRule::value("name", "Name", "/name")
                .kind(AuditValueKind::Identifier)
                .role(AuditRole::Change)
                .display(AuditDisplay::Primary)
                .max_bytes(1024)
                .overflow(AuditOverflow::Omit),
            AuditInputRule::value("username", "Username", "/username")
                .kind(AuditValueKind::Identifier)
                .role(AuditRole::Change)
                .display(AuditDisplay::Detail)
                .max_bytes(1024)
                .overflow(AuditOverflow::Omit),
        ],
        "service_account.delete" | "service_account.view" => vec![
            AuditInputRule::value("project", "Project", "/project")
                .kind(AuditValueKind::Identifier)
                .role(AuditRole::Target)
                .display(AuditDisplay::Primary)
                .max_bytes(1024)
                .overflow(AuditOverflow::Omit),
            AuditInputRule::value("userId", "User Id", "/userId")
                .kind(AuditValueKind::Identifier)
                .role(AuditRole::Target)
                .display(AuditDisplay::Primary)
                .max_bytes(1024)
                .overflow(AuditOverflow::Omit),
        ],
        "service_account.member.set" => vec![
            AuditInputRule::value("project", "Project", "/project")
                .kind(AuditValueKind::Identifier)
                .role(AuditRole::Target)
                .display(AuditDisplay::Primary)
                .max_bytes(1024)
                .overflow(AuditOverflow::Omit),
            AuditInputRule::value("accessLevel", "Access Level", "/accessLevel")
                .kind(AuditValueKind::Number)
                .role(AuditRole::Change)
                .display(AuditDisplay::Detail),
            AuditInputRule::value("userId", "User Id", "/userId")
                .kind(AuditValueKind::Identifier)
                .role(AuditRole::Target)
                .display(AuditDisplay::Primary)
                .max_bytes(1024)
                .overflow(AuditOverflow::Omit),
        ],
        "service_account.token.create" => vec![
            AuditInputRule::value("project", "Project", "/project")
                .kind(AuditValueKind::Identifier)
                .role(AuditRole::Target)
                .display(AuditDisplay::Primary)
                .max_bytes(1024)
                .overflow(AuditOverflow::Omit),
            AuditInputRule::value("expiresAt", "Expires At", "/expiresAt")
                .kind(AuditValueKind::Date)
                .role(AuditRole::Change)
                .display(AuditDisplay::Detail)
                .max_bytes(1024)
                .overflow(AuditOverflow::Omit),
            AuditInputRule::value("name", "Name", "/name")
                .kind(AuditValueKind::Identifier)
                .role(AuditRole::Change)
                .display(AuditDisplay::Primary)
                .max_bytes(1024)
                .overflow(AuditOverflow::Omit),
            AuditInputRule::values("scopes", "Scopes", "/scopes")
                .kind(AuditValueKind::Text)
                .role(AuditRole::Change)
                .display(AuditDisplay::Detail)
                .max_bytes(64)
                .overflow(AuditOverflow::Omit),
            AuditInputRule::value("userId", "User Id", "/userId")
                .kind(AuditValueKind::Identifier)
                .role(AuditRole::Target)
                .display(AuditDisplay::Primary)
                .max_bytes(1024)
                .overflow(AuditOverflow::Omit),
        ],
        "service_account.token.list" => vec![
            AuditInputRule::value("project", "Project", "/project")
                .kind(AuditValueKind::Identifier)
                .role(AuditRole::Target)
                .display(AuditDisplay::Primary)
                .max_bytes(1024)
                .overflow(AuditOverflow::Omit),
            AuditInputRule::value("maxResults", "Max Results", "/maxResults")
                .kind(AuditValueKind::Number)
                .role(AuditRole::Fact)
                .display(AuditDisplay::Detail),
            AuditInputRule::presence("pageToken", "Page Token", "/pageToken")
                .role(AuditRole::Fact)
                .display(AuditDisplay::Detail),
            AuditInputRule::value("userId", "User Id", "/userId")
                .kind(AuditValueKind::Identifier)
                .role(AuditRole::Target)
                .display(AuditDisplay::Primary)
                .max_bytes(1024)
                .overflow(AuditOverflow::Omit),
        ],
        "service_account.token.revoke" => vec![
            AuditInputRule::value("project", "Project", "/project")
                .kind(AuditValueKind::Identifier)
                .role(AuditRole::Target)
                .display(AuditDisplay::Primary)
                .max_bytes(1024)
                .overflow(AuditOverflow::Omit),
            AuditInputRule::value("tokenId", "Token Id", "/tokenId")
                .kind(AuditValueKind::Identifier)
                .role(AuditRole::Target)
                .display(AuditDisplay::Primary)
                .max_bytes(1024)
                .overflow(AuditOverflow::Omit),
            AuditInputRule::value("userId", "User Id", "/userId")
                .kind(AuditValueKind::Identifier)
                .role(AuditRole::Target)
                .display(AuditDisplay::Primary)
                .max_bytes(1024)
                .overflow(AuditOverflow::Omit),
        ],
        "service_account.token.rotate" => vec![
            AuditInputRule::value("project", "Project", "/project")
                .kind(AuditValueKind::Identifier)
                .role(AuditRole::Target)
                .display(AuditDisplay::Primary)
                .max_bytes(1024)
                .overflow(AuditOverflow::Omit),
            AuditInputRule::value("expiresAt", "Expires At", "/expiresAt")
                .kind(AuditValueKind::Date)
                .role(AuditRole::Change)
                .display(AuditDisplay::Detail)
                .max_bytes(1024)
                .overflow(AuditOverflow::Omit),
            AuditInputRule::value("tokenId", "Token Id", "/tokenId")
                .kind(AuditValueKind::Identifier)
                .role(AuditRole::Target)
                .display(AuditDisplay::Primary)
                .max_bytes(1024)
                .overflow(AuditOverflow::Omit),
            AuditInputRule::value("userId", "User Id", "/userId")
                .kind(AuditValueKind::Identifier)
                .role(AuditRole::Target)
                .display(AuditDisplay::Primary)
                .max_bytes(1024)
                .overflow(AuditOverflow::Omit),
        ],
        "webhook.create" => vec![
            AuditInputRule::value("project", "Project", "/project")
                .kind(AuditValueKind::Identifier)
                .role(AuditRole::Target)
                .display(AuditDisplay::Primary)
                .max_bytes(1024)
                .overflow(AuditOverflow::Omit),
            AuditInputRule::value(
                "branchFilterStrategy",
                "Branch Filter Strategy",
                "/branchFilterStrategy",
            )
            .kind(AuditValueKind::Text)
            .role(AuditRole::Change)
            .display(AuditDisplay::Detail)
            .max_bytes(64)
            .overflow(AuditOverflow::Omit),
            AuditInputRule::utf8_byte_count(
                "customWebhookTemplate",
                "Custom Webhook Template",
                "/customWebhookTemplate",
            )
            .role(AuditRole::Change)
            .display(AuditDisplay::Detail),
            AuditInputRule::utf8_byte_count("description", "Description", "/description")
                .role(AuditRole::Change)
                .display(AuditDisplay::Detail),
            AuditInputRule::value(
                "enableSslVerification",
                "Enable Ssl Verification",
                "/enableSslVerification",
            )
            .kind(AuditValueKind::Boolean)
            .role(AuditRole::Change)
            .display(AuditDisplay::Detail),
            AuditInputRule::values("events", "Events", "/events")
                .kind(AuditValueKind::Text)
                .role(AuditRole::Change)
                .display(AuditDisplay::Detail)
                .max_bytes(64)
                .overflow(AuditOverflow::Omit),
            AuditInputRule::value("name", "Name", "/name")
                .kind(AuditValueKind::Identifier)
                .role(AuditRole::Change)
                .display(AuditDisplay::Primary)
                .max_bytes(1024)
                .overflow(AuditOverflow::Omit),
            AuditInputRule::value(
                "pushEventsBranchFilter",
                "Push Events Branch Filter",
                "/pushEventsBranchFilter",
            )
            .kind(AuditValueKind::Query)
            .role(AuditRole::Change)
            .display(AuditDisplay::Primary)
            .max_bytes(4096)
            .overflow(AuditOverflow::Prefix),
            AuditInputRule::presence("signingToken", "Signing Token", "/signingToken")
                .role(AuditRole::Change)
                .display(AuditDisplay::Detail),
            AuditInputRule::presence("token", "Token", "/token")
                .role(AuditRole::Change)
                .display(AuditDisplay::Detail),
            AuditInputRule::presence("url", "Url", "/url")
                .role(AuditRole::Change)
                .display(AuditDisplay::Detail),
        ],
        "webhook.custom_header.delete" => vec![
            AuditInputRule::value("project", "Project", "/project")
                .kind(AuditValueKind::Identifier)
                .role(AuditRole::Target)
                .display(AuditDisplay::Primary)
                .max_bytes(1024)
                .overflow(AuditOverflow::Omit),
            AuditInputRule::value("key", "Key", "/key")
                .kind(AuditValueKind::Identifier)
                .role(AuditRole::Target)
                .display(AuditDisplay::Primary)
                .max_bytes(1024)
                .overflow(AuditOverflow::Omit),
            AuditInputRule::value("webhookId", "Webhook Id", "/webhookId")
                .kind(AuditValueKind::Identifier)
                .role(AuditRole::Target)
                .display(AuditDisplay::Primary)
                .max_bytes(1024)
                .overflow(AuditOverflow::Omit),
        ],
        "webhook.custom_header.set" => vec![
            AuditInputRule::value("project", "Project", "/project")
                .kind(AuditValueKind::Identifier)
                .role(AuditRole::Target)
                .display(AuditDisplay::Primary)
                .max_bytes(1024)
                .overflow(AuditOverflow::Omit),
            AuditInputRule::value("key", "Key", "/key")
                .kind(AuditValueKind::Identifier)
                .role(AuditRole::Target)
                .display(AuditDisplay::Primary)
                .max_bytes(1024)
                .overflow(AuditOverflow::Omit),
            AuditInputRule::presence("value", "Value", "/value")
                .role(AuditRole::Change)
                .display(AuditDisplay::Detail),
            AuditInputRule::value("webhookId", "Webhook Id", "/webhookId")
                .kind(AuditValueKind::Identifier)
                .role(AuditRole::Target)
                .display(AuditDisplay::Primary)
                .max_bytes(1024)
                .overflow(AuditOverflow::Omit),
        ],
        "webhook.delete" | "webhook.view" => vec![
            AuditInputRule::value("project", "Project", "/project")
                .kind(AuditValueKind::Identifier)
                .role(AuditRole::Target)
                .display(AuditDisplay::Primary)
                .max_bytes(1024)
                .overflow(AuditOverflow::Omit),
            AuditInputRule::value("webhookId", "Webhook Id", "/webhookId")
                .kind(AuditValueKind::Identifier)
                .role(AuditRole::Target)
                .display(AuditDisplay::Primary)
                .max_bytes(1024)
                .overflow(AuditOverflow::Omit),
        ],
        "webhook.event.list" => vec![
            AuditInputRule::value("project", "Project", "/project")
                .kind(AuditValueKind::Identifier)
                .role(AuditRole::Target)
                .display(AuditDisplay::Primary)
                .max_bytes(1024)
                .overflow(AuditOverflow::Omit),
            AuditInputRule::value("maxResults", "Max Results", "/maxResults")
                .kind(AuditValueKind::Number)
                .role(AuditRole::Fact)
                .display(AuditDisplay::Detail),
            AuditInputRule::presence("pageToken", "Page Token", "/pageToken")
                .role(AuditRole::Fact)
                .display(AuditDisplay::Detail),
            AuditInputRule::value("status", "Status", "/status")
                .kind(AuditValueKind::Text)
                .role(AuditRole::Fact)
                .display(AuditDisplay::Detail)
                .max_bytes(64)
                .overflow(AuditOverflow::Omit),
            AuditInputRule::value("webhookId", "Webhook Id", "/webhookId")
                .kind(AuditValueKind::Identifier)
                .role(AuditRole::Target)
                .display(AuditDisplay::Primary)
                .max_bytes(1024)
                .overflow(AuditOverflow::Omit),
        ],
        "webhook.event.resend" => vec![
            AuditInputRule::value("project", "Project", "/project")
                .kind(AuditValueKind::Identifier)
                .role(AuditRole::Target)
                .display(AuditDisplay::Primary)
                .max_bytes(1024)
                .overflow(AuditOverflow::Omit),
            AuditInputRule::value("webhookEventId", "Webhook Event Id", "/webhookEventId")
                .kind(AuditValueKind::Identifier)
                .role(AuditRole::Target)
                .display(AuditDisplay::Primary)
                .max_bytes(1024)
                .overflow(AuditOverflow::Omit),
            AuditInputRule::value("webhookId", "Webhook Id", "/webhookId")
                .kind(AuditValueKind::Identifier)
                .role(AuditRole::Target)
                .display(AuditDisplay::Primary)
                .max_bytes(1024)
                .overflow(AuditOverflow::Omit),
        ],
        "webhook.test" => vec![
            AuditInputRule::value("project", "Project", "/project")
                .kind(AuditValueKind::Identifier)
                .role(AuditRole::Target)
                .display(AuditDisplay::Primary)
                .max_bytes(1024)
                .overflow(AuditOverflow::Omit),
            AuditInputRule::value("event", "Event", "/event")
                .kind(AuditValueKind::Text)
                .role(AuditRole::Fact)
                .display(AuditDisplay::Detail)
                .max_bytes(64)
                .overflow(AuditOverflow::Omit),
            AuditInputRule::value("webhookId", "Webhook Id", "/webhookId")
                .kind(AuditValueKind::Identifier)
                .role(AuditRole::Target)
                .display(AuditDisplay::Primary)
                .max_bytes(1024)
                .overflow(AuditOverflow::Omit),
        ],
        "webhook.update" => vec![
            AuditInputRule::value("project", "Project", "/project")
                .kind(AuditValueKind::Identifier)
                .role(AuditRole::Target)
                .display(AuditDisplay::Primary)
                .max_bytes(1024)
                .overflow(AuditOverflow::Omit),
            AuditInputRule::value(
                "branchFilterStrategy",
                "Branch Filter Strategy",
                "/branchFilterStrategy",
            )
            .kind(AuditValueKind::Text)
            .role(AuditRole::Change)
            .display(AuditDisplay::Detail)
            .max_bytes(64)
            .overflow(AuditOverflow::Omit),
            AuditInputRule::value("clearToken", "Clear Token", "/clearToken")
                .kind(AuditValueKind::Boolean)
                .role(AuditRole::Change)
                .display(AuditDisplay::Detail),
            AuditInputRule::value(
                "confirmDestinationReset",
                "Confirm Destination Reset",
                "/confirmDestinationReset",
            )
            .kind(AuditValueKind::Boolean)
            .role(AuditRole::Change)
            .display(AuditDisplay::Detail),
            AuditInputRule::utf8_byte_count(
                "customWebhookTemplate",
                "Custom Webhook Template",
                "/customWebhookTemplate",
            )
            .role(AuditRole::Change)
            .display(AuditDisplay::Detail),
            AuditInputRule::utf8_byte_count("description", "Description", "/description")
                .role(AuditRole::Change)
                .display(AuditDisplay::Detail),
            AuditInputRule::value(
                "enableSslVerification",
                "Enable Ssl Verification",
                "/enableSslVerification",
            )
            .kind(AuditValueKind::Boolean)
            .role(AuditRole::Change)
            .display(AuditDisplay::Detail),
            AuditInputRule::values("events", "Events", "/events")
                .kind(AuditValueKind::Text)
                .role(AuditRole::Change)
                .display(AuditDisplay::Detail)
                .max_bytes(64)
                .overflow(AuditOverflow::Omit),
            AuditInputRule::value("name", "Name", "/name")
                .kind(AuditValueKind::Identifier)
                .role(AuditRole::Change)
                .display(AuditDisplay::Primary)
                .max_bytes(1024)
                .overflow(AuditOverflow::Omit),
            AuditInputRule::value(
                "pushEventsBranchFilter",
                "Push Events Branch Filter",
                "/pushEventsBranchFilter",
            )
            .kind(AuditValueKind::Query)
            .role(AuditRole::Change)
            .display(AuditDisplay::Primary)
            .max_bytes(4096)
            .overflow(AuditOverflow::Prefix),
            AuditInputRule::presence("signingToken", "Signing Token", "/signingToken")
                .role(AuditRole::Change)
                .display(AuditDisplay::Detail),
            AuditInputRule::presence("token", "Token", "/token")
                .role(AuditRole::Change)
                .display(AuditDisplay::Detail),
            AuditInputRule::presence("url", "Url", "/url")
                .role(AuditRole::Change)
                .display(AuditDisplay::Detail),
            AuditInputRule::value("webhookId", "Webhook Id", "/webhookId")
                .kind(AuditValueKind::Identifier)
                .role(AuditRole::Target)
                .display(AuditDisplay::Primary)
                .max_bytes(1024)
                .overflow(AuditOverflow::Omit),
        ],
        _ => panic!("GitLab action has no reviewed audit inventory: {action}"),
    };
    AuditInputProjection::new(rules)
}

#[cfg(test)]
mod tests;
