//! GitLab response presentation: which results carry embedded upstream
//! bodies, how those bodies render, and the whole-result Markdown templates.
use agent_access_content::{
    render_gitlab_markdown_bounded_with_budget, render_gitlab_markdown_fragment_bounded_with_budget,
};
use agent_access_provider::presentation::*;
use serde_json::{Map, Value};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WholeRenderer {
    NativeSearch,
    Project,
    Issue,
    IssueList,
    NoteList,
    Note,
    MergeRequest,
    MergeRequestList,
    ReviewerList,
    MergeRequestCommitList,
    MergeRequestPipelineList,
    DiffList,
    DiffVersionList,
    DiffVersion,
    Discussion,
    DiscussionList,
    DraftNote,
    DraftNoteList,
    Approval,
    ApprovalState,
    ApprovalRule,
    ApprovalRuleList,
    Branch,
    BranchList,
    ProtectedBranch,
    ProtectedBranchList,
    ProtectedBranchVerify,
    File,
    Commit,
    CommitList,
    Pipeline,
    PipelineList,
    Job,
    JobList,
}

#[derive(Debug, Clone, Copy)]
struct ResultDescriptor {
    action: &'static str,
    embedded_bodies: &'static [EmbeddedBody],
    whole: Option<WholeRenderer>,
}

const NO_BODIES: &[EmbeddedBody] = &[];

const GITLAB_ISSUE_DESCRIPTION: &[EmbeddedBody] = &[EmbeddedBody::new(
    &[BodyPathSegment::Field("issue")],
    &GitlabMarkdownBody("description"),
)];

const GITLAB_ISSUE_DESCRIPTIONS: &[EmbeddedBody] = &[EmbeddedBody::new(
    &[BodyPathSegment::Field("issues"), BodyPathSegment::Each],
    &GitlabMarkdownBody("description"),
)];

const GITLAB_MERGE_REQUEST_DESCRIPTION: &[EmbeddedBody] = &[EmbeddedBody::new(
    &[BodyPathSegment::Field("mergeRequest")],
    &GitlabMarkdownBody("description"),
)];

const GITLAB_MERGE_REQUEST_DESCRIPTIONS: &[EmbeddedBody] = &[EmbeddedBody::new(
    &[
        BodyPathSegment::Field("mergeRequests"),
        BodyPathSegment::Each,
    ],
    &GitlabMarkdownBody("description"),
)];

const GITLAB_NOTE_BODY: &[EmbeddedBody] = &[EmbeddedBody::new(
    &[BodyPathSegment::Field("note")],
    &GitlabMarkdownBody("body"),
)];

const GITLAB_NOTE_BODIES: &[EmbeddedBody] = &[EmbeddedBody::new(
    &[BodyPathSegment::Field("notes"), BodyPathSegment::Each],
    &GitlabMarkdownBody("body"),
)];

const GITLAB_DISCUSSION_NOTES: &[EmbeddedBody] = &[EmbeddedBody::new(
    &[
        BodyPathSegment::Field("discussion"),
        BodyPathSegment::Field("notes"),
        BodyPathSegment::Each,
    ],
    &GitlabMarkdownBody("body"),
)];

const GITLAB_DISCUSSION_LIST_NOTES: &[EmbeddedBody] = &[EmbeddedBody::new(
    &[
        BodyPathSegment::Field("discussions"),
        BodyPathSegment::Each,
        BodyPathSegment::Field("notes"),
        BodyPathSegment::Each,
    ],
    &GitlabMarkdownBody("body"),
)];

const GITLAB_DISCUSSION_VIEW_NOTES: &[EmbeddedBody] = &[EmbeddedBody::new(
    &[
        BodyPathSegment::Field("discussion"),
        BodyPathSegment::Field("notes"),
        BodyPathSegment::Each,
    ],
    &GitlabMarkdownBody("body"),
)];

const GITLAB_DRAFT_NOTE_BODY: &[EmbeddedBody] = &[EmbeddedBody::new(
    &[BodyPathSegment::Field("draftNote")],
    &GitlabMarkdownBody("body"),
)];

const GITLAB_DRAFT_NOTE_BODIES: &[EmbeddedBody] = &[EmbeddedBody::new(
    &[BodyPathSegment::Field("draftNotes"), BodyPathSegment::Each],
    &GitlabMarkdownBody("body"),
)];

const RESULT_DESCRIPTORS: &[ResultDescriptor] = &[
    ResultDescriptor {
        action: "project.search",
        embedded_bodies: NO_BODIES,
        whole: Some(WholeRenderer::NativeSearch),
    },
    ResultDescriptor {
        action: "search.issues",
        embedded_bodies: NO_BODIES,
        whole: Some(WholeRenderer::NativeSearch),
    },
    ResultDescriptor {
        action: "search.merge_requests",
        embedded_bodies: NO_BODIES,
        whole: Some(WholeRenderer::NativeSearch),
    },
    ResultDescriptor {
        action: "search.code",
        embedded_bodies: NO_BODIES,
        whole: Some(WholeRenderer::NativeSearch),
    },
    ResultDescriptor {
        action: "search.commits",
        embedded_bodies: NO_BODIES,
        whole: Some(WholeRenderer::NativeSearch),
    },
    ResultDescriptor {
        action: "search.wiki",
        embedded_bodies: NO_BODIES,
        whole: Some(WholeRenderer::NativeSearch),
    },
    ResultDescriptor {
        action: "search.comments",
        embedded_bodies: NO_BODIES,
        whole: Some(WholeRenderer::NativeSearch),
    },
    ResultDescriptor {
        action: "project.view",
        embedded_bodies: NO_BODIES,
        whole: Some(WholeRenderer::Project),
    },
    ResultDescriptor {
        action: "issue.view",
        embedded_bodies: GITLAB_ISSUE_DESCRIPTION,
        whole: Some(WholeRenderer::Issue),
    },
    ResultDescriptor {
        action: "issue.search",
        embedded_bodies: GITLAB_ISSUE_DESCRIPTIONS,
        whole: Some(WholeRenderer::IssueList),
    },
    ResultDescriptor {
        action: "issue.create",
        embedded_bodies: GITLAB_ISSUE_DESCRIPTION,
        whole: None,
    },
    ResultDescriptor {
        action: "issue.update",
        embedded_bodies: GITLAB_ISSUE_DESCRIPTION,
        whole: None,
    },
    ResultDescriptor {
        action: "issue.note.list",
        embedded_bodies: GITLAB_NOTE_BODIES,
        whole: Some(WholeRenderer::NoteList),
    },
    ResultDescriptor {
        action: "issue.note.view",
        embedded_bodies: GITLAB_NOTE_BODY,
        whole: Some(WholeRenderer::Note),
    },
    ResultDescriptor {
        action: "issue.note.add",
        embedded_bodies: GITLAB_NOTE_BODY,
        whole: None,
    },
    ResultDescriptor {
        action: "issue.note.update",
        embedded_bodies: GITLAB_NOTE_BODY,
        whole: None,
    },
    ResultDescriptor {
        action: "merge_request.view",
        embedded_bodies: GITLAB_MERGE_REQUEST_DESCRIPTION,
        whole: Some(WholeRenderer::MergeRequest),
    },
    ResultDescriptor {
        action: "merge_request.search",
        embedded_bodies: GITLAB_MERGE_REQUEST_DESCRIPTIONS,
        whole: Some(WholeRenderer::MergeRequestList),
    },
    ResultDescriptor {
        action: "merge_request.create",
        embedded_bodies: GITLAB_MERGE_REQUEST_DESCRIPTION,
        whole: None,
    },
    ResultDescriptor {
        action: "merge_request.update",
        embedded_bodies: GITLAB_MERGE_REQUEST_DESCRIPTION,
        whole: None,
    },
    ResultDescriptor {
        action: "merge_request.note.list",
        embedded_bodies: GITLAB_NOTE_BODIES,
        whole: Some(WholeRenderer::NoteList),
    },
    ResultDescriptor {
        action: "merge_request.note.view",
        embedded_bodies: GITLAB_NOTE_BODY,
        whole: Some(WholeRenderer::Note),
    },
    ResultDescriptor {
        action: "merge_request.note.add",
        embedded_bodies: GITLAB_NOTE_BODY,
        whole: None,
    },
    ResultDescriptor {
        action: "merge_request.note.update",
        embedded_bodies: GITLAB_NOTE_BODY,
        whole: None,
    },
    ResultDescriptor {
        action: "merge_request.discussion.list",
        embedded_bodies: GITLAB_DISCUSSION_LIST_NOTES,
        whole: Some(WholeRenderer::DiscussionList),
    },
    ResultDescriptor {
        action: "merge_request.discussion.view",
        embedded_bodies: GITLAB_DISCUSSION_VIEW_NOTES,
        whole: Some(WholeRenderer::Discussion),
    },
    ResultDescriptor {
        action: "merge_request.discussion.inline.add",
        embedded_bodies: GITLAB_DISCUSSION_NOTES,
        whole: None,
    },
    ResultDescriptor {
        action: "merge_request.discussion.note.add",
        embedded_bodies: GITLAB_NOTE_BODY,
        whole: None,
    },
    ResultDescriptor {
        action: "merge_request.draft_note.list",
        embedded_bodies: GITLAB_DRAFT_NOTE_BODIES,
        whole: Some(WholeRenderer::DraftNoteList),
    },
    ResultDescriptor {
        action: "merge_request.draft_note.view",
        embedded_bodies: GITLAB_DRAFT_NOTE_BODY,
        whole: Some(WholeRenderer::DraftNote),
    },
    ResultDescriptor {
        action: "merge_request.draft_note.add",
        embedded_bodies: GITLAB_DRAFT_NOTE_BODY,
        whole: None,
    },
    ResultDescriptor {
        action: "merge_request.draft_note.update",
        embedded_bodies: GITLAB_DRAFT_NOTE_BODY,
        whole: None,
    },
    ResultDescriptor {
        action: "webhook.list",
        embedded_bodies: NO_BODIES,
        whole: None,
    },
    ResultDescriptor {
        action: "webhook.view",
        embedded_bodies: NO_BODIES,
        whole: None,
    },
    ResultDescriptor {
        action: "webhook.create",
        embedded_bodies: NO_BODIES,
        whole: None,
    },
    ResultDescriptor {
        action: "webhook.update",
        embedded_bodies: NO_BODIES,
        whole: None,
    },
    ResultDescriptor {
        action: "webhook.delete",
        embedded_bodies: NO_BODIES,
        whole: None,
    },
    ResultDescriptor {
        action: "webhook.test",
        embedded_bodies: NO_BODIES,
        whole: None,
    },
    ResultDescriptor {
        action: "webhook.event.list",
        embedded_bodies: NO_BODIES,
        whole: None,
    },
    ResultDescriptor {
        action: "webhook.event.resend",
        embedded_bodies: NO_BODIES,
        whole: None,
    },
    ResultDescriptor {
        action: "webhook.custom_header.set",
        embedded_bodies: NO_BODIES,
        whole: None,
    },
    ResultDescriptor {
        action: "webhook.custom_header.delete",
        embedded_bodies: NO_BODIES,
        whole: None,
    },
    ResultDescriptor {
        action: "merge_request.approval.view",
        embedded_bodies: NO_BODIES,
        whole: Some(WholeRenderer::Approval),
    },
    ResultDescriptor {
        action: "merge_request.approval_state.view",
        embedded_bodies: NO_BODIES,
        whole: Some(WholeRenderer::ApprovalState),
    },
    ResultDescriptor {
        action: "merge_request.approval_rule.list",
        embedded_bodies: NO_BODIES,
        whole: Some(WholeRenderer::ApprovalRuleList),
    },
    ResultDescriptor {
        action: "merge_request.approval_rule.view",
        embedded_bodies: NO_BODIES,
        whole: Some(WholeRenderer::ApprovalRule),
    },
    ResultDescriptor {
        action: "merge_request.reviewer.list",
        embedded_bodies: NO_BODIES,
        whole: Some(WholeRenderer::ReviewerList),
    },
    ResultDescriptor {
        action: "merge_request.commit.list",
        embedded_bodies: NO_BODIES,
        whole: Some(WholeRenderer::MergeRequestCommitList),
    },
    ResultDescriptor {
        action: "merge_request.pipeline.list",
        embedded_bodies: NO_BODIES,
        whole: Some(WholeRenderer::MergeRequestPipelineList),
    },
    ResultDescriptor {
        action: "merge_request.diff.list",
        embedded_bodies: NO_BODIES,
        whole: Some(WholeRenderer::DiffList),
    },
    ResultDescriptor {
        action: "merge_request.diff_version.list",
        embedded_bodies: NO_BODIES,
        whole: Some(WholeRenderer::DiffVersionList),
    },
    ResultDescriptor {
        action: "merge_request.diff_version.view",
        embedded_bodies: NO_BODIES,
        whole: Some(WholeRenderer::DiffVersion),
    },
    ResultDescriptor {
        action: "merge_request.discussion.add",
        embedded_bodies: GITLAB_DISCUSSION_NOTES,
        whole: None,
    },
    ResultDescriptor {
        action: "merge_request.discussion.note.update",
        embedded_bodies: GITLAB_NOTE_BODY,
        whole: None,
    },
    ResultDescriptor {
        action: "merge_request.discussion.resolve",
        embedded_bodies: GITLAB_DISCUSSION_NOTES,
        whole: None,
    },
    ResultDescriptor {
        action: "merge_request.discussion.reopen",
        embedded_bodies: GITLAB_DISCUSSION_NOTES,
        whole: None,
    },
    ResultDescriptor {
        action: "branch.list",
        embedded_bodies: NO_BODIES,
        whole: Some(WholeRenderer::BranchList),
    },
    ResultDescriptor {
        action: "branch.view",
        embedded_bodies: NO_BODIES,
        whole: Some(WholeRenderer::Branch),
    },
    ResultDescriptor {
        action: "protected_branch.list",
        embedded_bodies: NO_BODIES,
        whole: Some(WholeRenderer::ProtectedBranchList),
    },
    ResultDescriptor {
        action: "protected_branch.view",
        embedded_bodies: NO_BODIES,
        whole: Some(WholeRenderer::ProtectedBranch),
    },
    ResultDescriptor {
        action: "protected_branch.verify",
        embedded_bodies: NO_BODIES,
        whole: Some(WholeRenderer::ProtectedBranchVerify),
    },
    ResultDescriptor {
        action: "file.view",
        embedded_bodies: NO_BODIES,
        whole: Some(WholeRenderer::File),
    },
    ResultDescriptor {
        action: "commit.list",
        embedded_bodies: NO_BODIES,
        whole: Some(WholeRenderer::CommitList),
    },
    ResultDescriptor {
        action: "commit.view",
        embedded_bodies: NO_BODIES,
        whole: Some(WholeRenderer::Commit),
    },
    ResultDescriptor {
        action: "pipeline.list",
        embedded_bodies: NO_BODIES,
        whole: Some(WholeRenderer::PipelineList),
    },
    ResultDescriptor {
        action: "pipeline.view",
        embedded_bodies: NO_BODIES,
        whole: Some(WholeRenderer::Pipeline),
    },
    ResultDescriptor {
        action: "job.list",
        embedded_bodies: NO_BODIES,
        whole: Some(WholeRenderer::JobList),
    },
    ResultDescriptor {
        action: "job.view",
        embedded_bodies: NO_BODIES,
        whole: Some(WholeRenderer::Job),
    },
];

/// The presentation of `action`'s results, if it has one.
pub(super) fn presentation(action: &str) -> Option<ActionPresentation> {
    descriptor(action).map(|descriptor| {
        ActionPresentation::new(
            descriptor.embedded_bodies,
            descriptor
                .whole
                .as_ref()
                .map(|whole| whole as &'static dyn WholeResultRenderer),
        )
    })
}

fn descriptor(action: &str) -> Option<&'static ResultDescriptor> {
    RESULT_DESCRIPTORS
        .iter()
        .find(|descriptor| descriptor.action == action)
}

/// GitLab Markdown in a named field of each owner.
struct GitlabMarkdownBody(&'static str);

impl EmbeddedBodyCodec for GitlabMarkdownBody {
    fn render(
        &self,
        owner: &Map<String, Value>,
        format: ReadContentFormat,
        max_body_bytes: u64,
        budget: &mut RenderBudget,
    ) -> Result<Option<RenderedBody>, RenderError> {
        let Some(native) = owner.get(self.0).filter(|native| !native.is_null()) else {
            return Ok(None);
        };
        render_gitlab_markdown_bounded_with_budget(
            native.as_str().ok_or(RenderError)?,
            format,
            max_body_bytes,
            max_body_bytes,
            budget,
        )
        .map_err(|_| RenderError)
    }
}

impl WholeResultRenderer for WholeRenderer {
    fn render(&self, result: &Value, context: &mut RenderContext) -> Result<(), RenderError> {
        let RenderContext {
            out,
            max_body_bytes,
            budget,
            ..
        } = context;
        let max_body_bytes = *max_body_bytes;
        match *self {
            WholeRenderer::NativeSearch => render_native_search(result, out, budget)?,
            WholeRenderer::Project => render_gitlab_project_view(result, out, budget)?,
            WholeRenderer::Issue => render_gitlab_issue_view(result, out, max_body_bytes, budget)?,
            WholeRenderer::IssueList => {
                render_gitlab_issue_list(result, out, max_body_bytes, budget)?
            }
            WholeRenderer::NoteList => {
                render_gitlab_note_list(result, out, max_body_bytes, budget)?
            }
            WholeRenderer::Note => render_gitlab_note_view(result, out, max_body_bytes, budget)?,
            WholeRenderer::MergeRequest => {
                render_gitlab_merge_request_view(result, out, max_body_bytes, budget)?
            }
            WholeRenderer::MergeRequestList => {
                render_gitlab_merge_request_list(result, out, max_body_bytes, budget)?
            }
            WholeRenderer::ReviewerList => render_gitlab_reviewer_list(result, out, budget)?,
            WholeRenderer::MergeRequestCommitList => {
                render_gitlab_merge_request_commit_list(result, out, budget)?
            }
            WholeRenderer::MergeRequestPipelineList => {
                render_gitlab_merge_request_pipeline_list(result, out, budget)?
            }
            WholeRenderer::DiffList => render_gitlab_diff_list(result, out, budget)?,
            WholeRenderer::DiffVersionList => render_gitlab_diff_version_list(result, out, budget)?,
            WholeRenderer::DiffVersion => render_gitlab_diff_version_view(result, out, budget)?,
            WholeRenderer::Discussion => {
                render_gitlab_discussion_view(result, out, max_body_bytes, budget)?
            }
            WholeRenderer::DiscussionList => {
                render_gitlab_discussion_list(result, out, max_body_bytes, budget)?
            }
            WholeRenderer::DraftNote => {
                render_gitlab_draft_note_view(result, out, max_body_bytes, budget)?
            }
            WholeRenderer::DraftNoteList => {
                render_gitlab_draft_note_list(result, out, max_body_bytes, budget)?
            }
            WholeRenderer::Approval => render_gitlab_approval(result, out, budget)?,
            WholeRenderer::ApprovalState => render_gitlab_approval_state(result, out, budget)?,
            WholeRenderer::ApprovalRule => render_gitlab_approval_rule_view(result, out, budget)?,
            WholeRenderer::ApprovalRuleList => {
                render_gitlab_approval_rule_list(result, out, budget)?
            }
            WholeRenderer::Branch => render_gitlab_branch_view(result, out, budget)?,
            WholeRenderer::BranchList => render_gitlab_branch_list(result, out, budget)?,
            WholeRenderer::ProtectedBranch => {
                render_gitlab_protected_branch_view(result, out, budget)?
            }
            WholeRenderer::ProtectedBranchList => {
                render_gitlab_protected_branch_list(result, out, budget)?
            }
            WholeRenderer::ProtectedBranchVerify => {
                render_gitlab_protected_branch_verify(result, out, budget)?
            }
            WholeRenderer::File => render_gitlab_file_view(result, out, budget)?,
            WholeRenderer::Commit => render_gitlab_commit_view(result, out, budget)?,
            WholeRenderer::CommitList => render_gitlab_commit_list(result, out, budget)?,
            WholeRenderer::Pipeline => render_gitlab_pipeline_view(result, out, budget)?,
            WholeRenderer::PipelineList => render_gitlab_pipeline_list(result, out, budget)?,
            WholeRenderer::Job => render_gitlab_job_view(result, out, budget)?,
            WholeRenderer::JobList => render_gitlab_job_list(result, out, budget)?,
        }
        Ok(())
    }
}

fn render_gitlab_project_view(
    value: &Value,
    out: &mut MarkdownWriter,
    budget: &mut PresentationBudget,
) -> Result<(), RenderError> {
    let project = as_object(required(as_object(value)?, "project")?)?;
    budget.charge_work(project.len())?;
    out.push("# GitLab project ")?;
    out.push_code(required_scalar(project, "pathWithNamespace")?)?;
    if let Some(name) = optional_scalar(project, "name")? {
        out.push(" — ")?;
        out.push_heading_text(name)?;
    }
    out.push("\n")?;
    gitlab_project_fields(project, out)
}

fn gitlab_project_fields(
    project: &Map<String, Value>,
    out: &mut MarkdownWriter,
) -> Result<(), RenderError> {
    let id = optional_display(project, "id")?;
    let archived = optional_display(project, "archived")?;
    code_fields(
        out,
        &[
            ("Project ID", id.as_deref()),
            ("Path", optional_scalar(project, "pathWithNamespace")?),
            ("Default branch", optional_scalar(project, "defaultBranch")?),
        ],
    )?;
    fields(
        out,
        &[
            ("Name", optional_scalar(project, "name")?),
            ("Visibility", optional_scalar(project, "visibility")?),
            ("Archived", archived.as_deref()),
        ],
    )?;
    if let Some(url) = optional_scalar(project, "webUrl")? {
        field_url(out, "URL", url)?;
    }
    Ok(())
}

fn render_gitlab_issue_view(
    value: &Value,
    out: &mut MarkdownWriter,
    max_body_bytes: u64,
    budget: &mut PresentationBudget,
) -> Result<(), RenderError> {
    let issue = as_object(required(as_object(value)?, "issue")?)?;
    render_gitlab_issue(issue, "# GitLab issue ", "## ", out, max_body_bytes, budget)
}

fn render_gitlab_issue_list(
    value: &Value,
    out: &mut MarkdownWriter,
    max_body_bytes: u64,
    budget: &mut PresentationBudget,
) -> Result<(), RenderError> {
    let object = as_object(value)?;
    let issues = array(required(object, "issues")?)?;
    budget.charge_work(object.len().saturating_add(issues.len()))?;
    out.push("# GitLab issues\n")?;
    gitlab_count_field(object, issues.len(), out)?;
    if issues.is_empty() {
        out.push("\nNo results.\n")?;
    }
    for issue in issues {
        out.push("\n")?;
        render_gitlab_issue(
            as_object(issue)?,
            "## Issue ",
            "### ",
            out,
            max_body_bytes,
            budget,
        )?;
    }
    gitlab_pagination_fields(object, out)
}

fn render_gitlab_issue(
    issue: &Map<String, Value>,
    heading: &str,
    body_heading: &str,
    out: &mut MarkdownWriter,
    max_body_bytes: u64,
    budget: &mut PresentationBudget,
) -> Result<(), RenderError> {
    budget.charge_work(issue.len())?;
    let iid = required_display(issue, "iid")?;
    out.push(heading)?;
    if let Some(project) = optional_scalar(issue, "project")? {
        out.push_code(project)?;
        out.push("#")?;
    }
    out.push_code(&iid)?;
    if let Some(title) = optional_scalar(issue, "title")? {
        out.push(" — ")?;
        out.push_heading_text(title)?;
    }
    out.push("\n")?;
    let id = optional_display(issue, "id")?;
    let project_id = optional_display(issue, "projectId")?;
    code_fields(
        out,
        &[
            ("Issue ID", id.as_deref()),
            ("Issue IID", Some(iid.as_str())),
            ("Project ID", project_id.as_deref()),
            ("Project", optional_scalar(issue, "project")?),
            ("Created", optional_scalar(issue, "createdAt")?),
            ("Updated", optional_scalar(issue, "updatedAt")?),
        ],
    )?;
    fields(out, &[("State", optional_scalar(issue, "state")?)])?;
    if let Some(url) = optional_scalar(issue, "webUrl")? {
        field_url(out, "URL", url)?;
    }
    gitlab_user_field(issue, "author", "Author", out)?;
    gitlab_user_list(issue, "assignees", "Assignees", out, budget)?;
    gitlab_string_list(issue, "labels", "Labels", out, budget)?;
    gitlab_milestone(issue, out)?;
    render_gitlab_body(
        issue,
        "description",
        "Description",
        body_heading,
        out,
        max_body_bytes,
        budget,
    )
}

fn render_gitlab_merge_request_view(
    value: &Value,
    out: &mut MarkdownWriter,
    max_body_bytes: u64,
    budget: &mut PresentationBudget,
) -> Result<(), RenderError> {
    let merge_request = as_object(required(as_object(value)?, "mergeRequest")?)?;
    render_gitlab_merge_request(
        merge_request,
        "# GitLab merge request ",
        "## ",
        out,
        max_body_bytes,
        budget,
    )
}

fn render_gitlab_merge_request_list(
    value: &Value,
    out: &mut MarkdownWriter,
    max_body_bytes: u64,
    budget: &mut PresentationBudget,
) -> Result<(), RenderError> {
    let object = as_object(value)?;
    let merge_requests = array(required(object, "mergeRequests")?)?;
    budget.charge_work(object.len().saturating_add(merge_requests.len()))?;
    out.push("# GitLab merge requests\n")?;
    gitlab_count_field(object, merge_requests.len(), out)?;
    if merge_requests.is_empty() {
        out.push("\nNo results.\n")?;
    }
    for merge_request in merge_requests {
        out.push("\n")?;
        render_gitlab_merge_request(
            as_object(merge_request)?,
            "## Merge request ",
            "### ",
            out,
            max_body_bytes,
            budget,
        )?;
    }
    gitlab_pagination_fields(object, out)
}

fn render_gitlab_merge_request(
    merge_request: &Map<String, Value>,
    heading: &str,
    body_heading: &str,
    out: &mut MarkdownWriter,
    max_body_bytes: u64,
    budget: &mut PresentationBudget,
) -> Result<(), RenderError> {
    budget.charge_work(merge_request.len())?;
    out.push(heading)?;
    if let Some(project) = optional_scalar(merge_request, "project")? {
        out.push_code(project)?;
        out.push("!")?;
    }
    let iid = required_display(merge_request, "iid")?;
    out.push_code(&iid)?;
    if let Some(title) = optional_scalar(merge_request, "title")? {
        out.push(" — ")?;
        out.push_heading_text(title)?;
    }
    out.push("\n")?;
    let id = optional_display(merge_request, "id")?;
    let project_id = optional_display(merge_request, "projectId")?;
    let source_project_id = optional_display(merge_request, "sourceProjectId")?;
    let target_project_id = optional_display(merge_request, "targetProjectId")?;
    let changes_count = optional_display(merge_request, "changesCount")?;
    let user_notes_count = optional_display(merge_request, "userNotesCount")?;
    let draft = optional_display(merge_request, "draft")?;
    let discussion_locked = optional_display(merge_request, "discussionLocked")?;
    let blocking_discussions_resolved =
        optional_display(merge_request, "blockingDiscussionsResolved")?;
    let has_conflicts = optional_display(merge_request, "hasConflicts")?;
    code_fields(
        out,
        &[
            ("Merge request ID", id.as_deref()),
            ("Merge request IID", Some(iid.as_str())),
            ("Project ID", project_id.as_deref()),
            ("Source project ID", source_project_id.as_deref()),
            ("Target project ID", target_project_id.as_deref()),
            ("Project", optional_scalar(merge_request, "project")?),
            (
                "Source branch",
                optional_scalar(merge_request, "sourceBranch")?,
            ),
            (
                "Target branch",
                optional_scalar(merge_request, "targetBranch")?,
            ),
            ("SHA", optional_scalar(merge_request, "sha")?),
            (
                "Squash commit SHA",
                optional_scalar(merge_request, "squashCommitSha")?,
            ),
            (
                "Merge commit SHA",
                optional_scalar(merge_request, "mergeCommitSha")?,
            ),
            ("Changes count", changes_count.as_deref()),
            ("User notes count", user_notes_count.as_deref()),
            ("Prepared", optional_scalar(merge_request, "preparedAt")?),
            ("Created", optional_scalar(merge_request, "createdAt")?),
            ("Updated", optional_scalar(merge_request, "updatedAt")?),
        ],
    )?;
    fields(
        out,
        &[
            ("State", optional_scalar(merge_request, "state")?),
            (
                "Merge status",
                optional_scalar(merge_request, "mergeStatus")?,
            ),
            (
                "Detailed merge status",
                optional_scalar(merge_request, "detailedMergeStatus")?,
            ),
            ("Draft", draft.as_deref()),
            ("Discussion locked", discussion_locked.as_deref()),
            (
                "Blocking discussions resolved",
                blocking_discussions_resolved.as_deref(),
            ),
            ("Has conflicts", has_conflicts.as_deref()),
        ],
    )?;
    if let Some(diff_refs) = merge_request
        .get("diffRefs")
        .filter(|value| !value.is_null())
    {
        let diff_refs = as_object(diff_refs)?;
        code_fields(
            out,
            &[
                ("Diff base SHA", optional_scalar(diff_refs, "baseSha")?),
                ("Diff start SHA", optional_scalar(diff_refs, "startSha")?),
                ("Diff head SHA", optional_scalar(diff_refs, "headSha")?),
            ],
        )?;
    }
    if let Some(url) = optional_scalar(merge_request, "webUrl")? {
        field_url(out, "URL", url)?;
    }
    gitlab_user_field(merge_request, "author", "Author", out)?;
    gitlab_user_list(merge_request, "assignees", "Assignees", out, budget)?;
    gitlab_user_list(merge_request, "reviewers", "Reviewers", out, budget)?;
    gitlab_string_list(merge_request, "labels", "Labels", out, budget)?;
    gitlab_milestone(merge_request, out)?;
    if let Some(pipeline) = merge_request
        .get("headPipeline")
        .filter(|value| !value.is_null())
    {
        out.push("\n")?;
        render_gitlab_pipeline(as_object(pipeline)?, body_heading, out, budget)?;
    }
    render_gitlab_body(
        merge_request,
        "description",
        "Description",
        body_heading,
        out,
        max_body_bytes,
        budget,
    )
}

fn render_gitlab_note_list(
    value: &Value,
    out: &mut MarkdownWriter,
    max_body_bytes: u64,
    budget: &mut PresentationBudget,
) -> Result<(), RenderError> {
    let object = as_object(value)?;
    let notes = array(required(object, "notes")?)?;
    budget.charge_work(object.len().saturating_add(notes.len()))?;
    out.push("# GitLab notes\n")?;
    if let Some(projection) = optional_scalar(object, "projection")? {
        field(out, "Projection", projection)?;
    }
    gitlab_count_field(object, notes.len(), out)?;
    if notes.is_empty() {
        out.push("\nNo results.\n")?;
    }
    for note in notes {
        out.push("\n")?;
        render_gitlab_note(as_object(note)?, "## ", "### ", out, max_body_bytes, budget)?;
    }
    gitlab_pagination_fields(object, out)
}

fn render_gitlab_note_view(
    value: &Value,
    out: &mut MarkdownWriter,
    max_body_bytes: u64,
    budget: &mut PresentationBudget,
) -> Result<(), RenderError> {
    render_gitlab_note(
        as_object(required(as_object(value)?, "note")?)?,
        "# ",
        "## ",
        out,
        max_body_bytes,
        budget,
    )
}

fn render_gitlab_discussion_list(
    value: &Value,
    out: &mut MarkdownWriter,
    max_body_bytes: u64,
    budget: &mut PresentationBudget,
) -> Result<(), RenderError> {
    let object = as_object(value)?;
    let discussions = array(required(object, "discussions")?)?;
    budget.charge_work(object.len().saturating_add(discussions.len()))?;
    out.push("# GitLab merge request discussions\n")?;
    if let Some(projection) = optional_scalar(object, "projection")? {
        field(out, "Projection", projection)?;
    }
    gitlab_count_field(object, discussions.len(), out)?;
    if discussions.is_empty() {
        out.push("\nNo results.\n")?;
    }
    for discussion in discussions {
        out.push("\n")?;
        render_gitlab_discussion(
            as_object(discussion)?,
            "## ",
            "### ",
            "#### ",
            out,
            max_body_bytes,
            budget,
        )?;
    }
    gitlab_pagination_fields(object, out)
}

fn render_gitlab_discussion_view(
    value: &Value,
    out: &mut MarkdownWriter,
    max_body_bytes: u64,
    budget: &mut PresentationBudget,
) -> Result<(), RenderError> {
    render_gitlab_discussion(
        as_object(required(as_object(value)?, "discussion")?)?,
        "# ",
        "## ",
        "### ",
        out,
        max_body_bytes,
        budget,
    )
}

#[allow(clippy::too_many_arguments)]
fn render_gitlab_discussion(
    discussion: &Map<String, Value>,
    heading: &str,
    note_heading: &str,
    body_heading: &str,
    out: &mut MarkdownWriter,
    max_body_bytes: u64,
    budget: &mut PresentationBudget,
) -> Result<(), RenderError> {
    budget.charge_work(discussion.len())?;
    out.push(heading)?;
    out.push("Discussion ")?;
    out.push_code(required_scalar(discussion, "id")?)?;
    out.push("\n")?;
    if let Some(individual) = optional_display(discussion, "individualNote")? {
        field(out, "Individual note", &individual)?;
    }
    let notes = array(required(discussion, "notes")?)?;
    budget.charge_work(notes.len())?;
    field(out, "Note count", &notes.len().to_string())?;
    if notes.is_empty() {
        out.push("\nNo notes.\n")?;
    }
    for note in notes {
        out.push("\n")?;
        render_gitlab_note(
            as_object(note)?,
            note_heading,
            body_heading,
            out,
            max_body_bytes,
            budget,
        )?;
    }
    Ok(())
}

fn render_gitlab_draft_note_view(
    value: &Value,
    out: &mut MarkdownWriter,
    max_body_bytes: u64,
    budget: &mut PresentationBudget,
) -> Result<(), RenderError> {
    render_gitlab_draft_note(
        as_object(required(as_object(value)?, "draftNote")?)?,
        "# ",
        "## ",
        out,
        max_body_bytes,
        budget,
    )
}

fn render_gitlab_draft_note_list(
    value: &Value,
    out: &mut MarkdownWriter,
    max_body_bytes: u64,
    budget: &mut PresentationBudget,
) -> Result<(), RenderError> {
    let object = as_object(value)?;
    let draft_notes = array(required(object, "draftNotes")?)?;
    budget.charge_work(object.len().saturating_add(draft_notes.len()))?;
    out.push("# GitLab merge request draft notes\n")?;
    if let Some(projection) = optional_scalar(object, "projection")? {
        field(out, "Projection", projection)?;
    }
    gitlab_count_field(object, draft_notes.len(), out)?;
    if draft_notes.is_empty() {
        out.push("\nNo results.\n")?;
    }
    for draft_note in draft_notes {
        out.push("\n")?;
        render_gitlab_draft_note(
            as_object(draft_note)?,
            "## ",
            "### ",
            out,
            max_body_bytes,
            budget,
        )?;
    }
    gitlab_pagination_fields(object, out)
}

fn render_gitlab_draft_note(
    draft_note: &Map<String, Value>,
    heading: &str,
    body_heading: &str,
    out: &mut MarkdownWriter,
    max_body_bytes: u64,
    budget: &mut PresentationBudget,
) -> Result<(), RenderError> {
    budget.charge_work(draft_note.len())?;
    let id = required_display(draft_note, "id")?;
    out.push(heading)?;
    out.push("Draft note ")?;
    out.push_code(&id)?;
    out.push("\n")?;
    let author_user_id = optional_display(draft_note, "authorUserId")?;
    let merge_request_id = optional_display(draft_note, "mergeRequestId")?;
    let resolve_discussion = optional_display(draft_note, "resolveDiscussion")?;
    code_fields(
        out,
        &[
            ("Draft note ID", Some(id.as_str())),
            ("Author user ID", author_user_id.as_deref()),
            ("Merge request ID", merge_request_id.as_deref()),
            (
                "Discussion ID",
                optional_scalar(draft_note, "discussionId")?,
            ),
            ("Commit ID", optional_scalar(draft_note, "commitId")?),
        ],
    )?;
    fields(
        out,
        &[("Resolve discussion", resolve_discussion.as_deref())],
    )?;
    if let Some(position) = draft_note.get("position").filter(|value| !value.is_null()) {
        render_gitlab_position(as_object(position)?, body_heading, out, budget)?;
    }
    render_gitlab_body(
        draft_note,
        "body",
        "Body",
        body_heading,
        out,
        max_body_bytes,
        budget,
    )
}

fn render_gitlab_note(
    note: &Map<String, Value>,
    heading: &str,
    body_heading: &str,
    out: &mut MarkdownWriter,
    max_body_bytes: u64,
    budget: &mut PresentationBudget,
) -> Result<(), RenderError> {
    budget.charge_work(note.len())?;
    out.push(heading)?;
    out.push("Note ")?;
    out.push_code(&required_display(note, "id")?)?;
    out.push("\n")?;
    let noteable_iid = optional_display(note, "noteableIid")?;
    let noteable_id = optional_display(note, "noteableId")?;
    let project_id = optional_display(note, "projectId")?;
    let author_user_id = optional_display(note, "authorUserId")?;
    let resolved = optional_display(note, "resolved")?;
    let resolvable = optional_display(note, "resolvable")?;
    let system = optional_display(note, "system")?;
    let confidential = optional_display(note, "confidential")?;
    code_fields(
        out,
        &[
            ("Noteable IID", noteable_iid.as_deref()),
            ("Noteable ID", noteable_id.as_deref()),
            ("Project ID", project_id.as_deref()),
            ("Author user ID", author_user_id.as_deref()),
            ("Author username", optional_scalar(note, "authorUsername")?),
            ("Note type", optional_scalar(note, "type")?),
            ("Commit ID", optional_scalar(note, "commitId")?),
            ("Created", optional_scalar(note, "createdAt")?),
            ("Updated", optional_scalar(note, "updatedAt")?),
        ],
    )?;
    fields(
        out,
        &[
            ("Noteable type", optional_scalar(note, "noteableType")?),
            ("Resolved", resolved.as_deref()),
            ("Resolvable", resolvable.as_deref()),
            ("System", system.as_deref()),
            ("Confidential", confidential.as_deref()),
        ],
    )?;
    gitlab_user_field(note, "resolvedBy", "Resolved by", out)?;
    if let Some(resolved_at) = optional_scalar(note, "resolvedAt")? {
        field_code(out, "Resolved at", resolved_at)?;
    }
    if let Some(position) = note.get("position").filter(|value| !value.is_null()) {
        render_gitlab_position(as_object(position)?, body_heading, out, budget)?;
    }
    if let Some(suggestions) = note.get("suggestions").filter(|value| !value.is_null()) {
        render_gitlab_suggestions(array(suggestions)?, body_heading, out, budget)?;
    }
    render_gitlab_body(
        note,
        "body",
        "Body",
        body_heading,
        out,
        max_body_bytes,
        budget,
    )
}

fn render_gitlab_position(
    position: &Map<String, Value>,
    heading: &str,
    out: &mut MarkdownWriter,
    budget: &mut PresentationBudget,
) -> Result<(), RenderError> {
    budget.charge_work(position.len())?;
    out.push("\n")?;
    out.push(heading)?;
    out.push("Position\n")?;
    let old_line = optional_display(position, "oldLine")?;
    let new_line = optional_display(position, "newLine")?;
    let width = optional_display(position, "width")?;
    let height = optional_display(position, "height")?;
    let x = optional_display(position, "x")?;
    let y = optional_display(position, "y")?;
    code_fields(
        out,
        &[
            ("Position type", optional_scalar(position, "positionType")?),
            ("Base SHA", optional_scalar(position, "baseSha")?),
            ("Start SHA", optional_scalar(position, "startSha")?),
            ("Head SHA", optional_scalar(position, "headSha")?),
            ("Old path", optional_scalar(position, "oldPath")?),
            ("New path", optional_scalar(position, "newPath")?),
            ("Old line", old_line.as_deref()),
            ("New line", new_line.as_deref()),
            ("Image width", width.as_deref()),
            ("Image height", height.as_deref()),
            ("Image x", x.as_deref()),
            ("Image y", y.as_deref()),
        ],
    )?;
    if let Some(line_range) = position.get("lineRange").filter(|value| !value.is_null()) {
        let line_range = as_object(line_range)?;
        for (key, label) in [("start", "Range start"), ("end", "Range end")] {
            let endpoint = as_object(required(line_range, key)?)?;
            budget.charge_work(endpoint.len())?;
            let old_line = optional_display(endpoint, "oldLine")?;
            let new_line = optional_display(endpoint, "newLine")?;
            out.push("- ")?;
            out.push(label)?;
            out.push(": ")?;
            let mut separator = "";
            for (part_label, value) in [
                ("line code", optional_scalar(endpoint, "lineCode")?),
                ("type", optional_scalar(endpoint, "type")?),
                ("old line", old_line.as_deref()),
                ("new line", new_line.as_deref()),
            ] {
                if let Some(value) = value {
                    out.push(separator)?;
                    out.push(part_label)?;
                    out.push(" ")?;
                    out.push_code(value)?;
                    separator = "; ";
                }
            }
            if separator.is_empty() {
                out.push("No details.")?;
            }
            out.push("\n")?;
        }
    }
    Ok(())
}

fn render_gitlab_suggestions(
    suggestions: &[Value],
    heading: &str,
    out: &mut MarkdownWriter,
    budget: &mut PresentationBudget,
) -> Result<(), RenderError> {
    budget.charge_work(suggestions.len())?;
    out.push("\n")?;
    out.push(heading)?;
    out.push("Suggestions\n")?;
    if suggestions.is_empty() {
        out.push("\nNo suggestions.\n")?;
    }
    for suggestion in suggestions {
        let suggestion = as_object(suggestion)?;
        budget.charge_work(suggestion.len())?;
        let id = required_display(suggestion, "id")?;
        out.push("\n")?;
        out.push(heading)?;
        out.push("# Suggestion ")?;
        out.push_code(&id)?;
        out.push("\n")?;
        let from_line = optional_display(suggestion, "fromLine")?;
        let to_line = optional_display(suggestion, "toLine")?;
        let applicable = optional_display(suggestion, "applicable")?;
        let applied = optional_display(suggestion, "applied")?;
        code_fields(
            out,
            &[
                ("Suggestion ID", Some(id.as_str())),
                ("From line", from_line.as_deref()),
                ("To line", to_line.as_deref()),
            ],
        )?;
        fields(
            out,
            &[
                ("Applicable", applicable.as_deref()),
                ("Applied", applied.as_deref()),
            ],
        )?;
        for (key, label) in [("fromContent", "Source"), ("toContent", "Replacement")] {
            if let Some(content) = optional_scalar(suggestion, key)? {
                budget.charge_fenced_literal_work(content.len())?;
                let content = normalize_fenced_text_literal(content);
                let fence = fence_for(&content, '`');
                out.push("\n")?;
                out.push(heading)?;
                out.push("## ")?;
                out.push(label)?;
                out.push("\n\n")?;
                out.push(&fence)?;
                out.push("text\n")?;
                out.push(&content)?;
                out.push("\n")?;
                out.push(&fence)?;
                out.push("\n")?;
            }
        }
    }
    Ok(())
}

fn render_gitlab_body(
    owner: &Map<String, Value>,
    field_name: &str,
    label: &str,
    heading: &str,
    out: &mut MarkdownWriter,
    max_body_bytes: u64,
    budget: &mut PresentationBudget,
) -> Result<(), RenderError> {
    let Some(body) = owner.get(field_name).filter(|body| !body.is_null()) else {
        return Ok(());
    };
    let body = body.as_str().ok_or(RenderError)?;
    let heading_level_offset = heading
        .strip_suffix(' ')
        .filter(|marker| !marker.is_empty() && marker.len() <= 6)
        .filter(|marker| marker.bytes().all(|byte| byte == b'#'))
        .map(str::len)
        .ok_or(RenderError)?;
    let rendered = if body.is_empty() {
        String::new()
    } else {
        render_gitlab_markdown_fragment_bounded_with_budget(
            body,
            max_body_bytes,
            max_body_bytes,
            &mut budget.rich_content,
            heading_level_offset,
        )
        .map_err(|_| RenderError)?
    };
    out.push("\n")?;
    out.push(heading)?;
    out.push(label)?;
    out.push("\n\n")?;
    if !rendered.is_empty() {
        out.push(&rendered)?;
        out.push("\n")?;
    }
    Ok(())
}

fn gitlab_count_field(
    object: &Map<String, Value>,
    actual_count: usize,
    out: &mut MarkdownWriter,
) -> Result<(), RenderError> {
    let count = required_display(object, "count")?;
    if count != actual_count.to_string() {
        return Err(RenderError);
    }
    field(out, "Count", &count)
}

fn gitlab_pagination_fields(
    object: &Map<String, Value>,
    out: &mut MarkdownWriter,
) -> Result<(), RenderError> {
    let max_results = required_display(object, "maxResults")?;
    let is_last = required_display(object, "isLast")?;
    out.push("\n## Pagination\n")?;
    fields(
        out,
        &[
            ("Maximum results", Some(max_results.as_str())),
            ("Last page", Some(is_last.as_str())),
        ],
    )?;
    if let Some(token) = optional_scalar(object, "nextPageToken")? {
        field_code(out, "Next page token", token)?;
    }
    Ok(())
}

fn gitlab_user_field(
    owner: &Map<String, Value>,
    key: &str,
    label: &str,
    out: &mut MarkdownWriter,
) -> Result<(), RenderError> {
    let Some(user) = owner.get(key).filter(|value| !value.is_null()) else {
        return Ok(());
    };
    field_raw(out, label, &gitlab_user_summary(user)?)
}

fn gitlab_user_summary(value: &Value) -> Result<String, RenderError> {
    let user = as_object(value)?;
    let mut parts = Vec::new();
    if let Some(name) = optional_scalar(user, "name")? {
        parts.push(escaped(name));
    }
    if let Some(username) = optional_scalar(user, "username")? {
        parts.push(format!("@{}", escaped(username)));
    }
    if let Some(id) = optional_display(user, "id")? {
        parts.push(format!("ID: {}", code_span(&id)));
    }
    if let Some(url) = optional_scalar(user, "webUrl")? {
        parts.push(safe_autolink(url).unwrap_or_else(|| code_span(url)));
    }
    Ok(if parts.is_empty() {
        "(no details)".to_string()
    } else {
        parts.join("; ")
    })
}

fn gitlab_user_list(
    owner: &Map<String, Value>,
    key: &str,
    label: &str,
    out: &mut MarkdownWriter,
    budget: &mut PresentationBudget,
) -> Result<(), RenderError> {
    let Some(users) = owner.get(key).filter(|value| !value.is_null()) else {
        return Ok(());
    };
    let users = array(users)?;
    budget.charge_work(users.len())?;
    out.push("- ")?;
    out.push(label)?;
    out.push(": ")?;
    if users.is_empty() {
        out.push("No items.")?;
    } else {
        for (index, user) in users.iter().enumerate() {
            if index > 0 {
                out.push("; ")?;
            }
            out.push(&gitlab_user_summary(user)?)?;
        }
    }
    out.push("\n")
}

fn gitlab_string_list(
    owner: &Map<String, Value>,
    key: &str,
    label: &str,
    out: &mut MarkdownWriter,
    budget: &mut PresentationBudget,
) -> Result<(), RenderError> {
    let Some(values) = owner.get(key).filter(|value| !value.is_null()) else {
        return Ok(());
    };
    let values = array(values)?;
    budget.charge_work(values.len())?;
    out.push("- ")?;
    out.push(label)?;
    out.push(": ")?;
    if values.is_empty() {
        out.push("No items.")?;
    } else {
        for (index, value) in values.iter().enumerate() {
            if index > 0 {
                out.push(", ")?;
            }
            out.push_escaped(scalar(value)?)?;
        }
    }
    out.push("\n")
}

fn gitlab_milestone(
    owner: &Map<String, Value>,
    out: &mut MarkdownWriter,
) -> Result<(), RenderError> {
    let Some(milestone) = owner.get("milestone").filter(|value| !value.is_null()) else {
        return Ok(());
    };
    let milestone = as_object(milestone)?;
    out.push("- Milestone: ")?;
    out.push_escaped(optional_scalar(milestone, "title")?.unwrap_or("(untitled)"))?;
    let id = optional_display(milestone, "id")?;
    let iid = optional_display(milestone, "iid")?;
    for (label, value) in [
        ("ID", id.as_deref()),
        ("IID", iid.as_deref()),
        ("state", optional_scalar(milestone, "state")?),
        ("due", optional_scalar(milestone, "dueDate")?),
    ] {
        if let Some(value) = value {
            out.push("; ")?;
            out.push(label)?;
            out.push(": ")?;
            out.push_code(value)?;
        }
    }
    out.push("\n")
}

fn render_gitlab_reviewer_list(
    value: &Value,
    out: &mut MarkdownWriter,
    budget: &mut PresentationBudget,
) -> Result<(), RenderError> {
    let object = as_object(value)?;
    let reviewers = array(required(object, "reviewers")?)?;
    budget.charge_work(object.len().saturating_add(reviewers.len()))?;
    out.push("# GitLab merge request reviewers\n")?;
    gitlab_count_field(object, reviewers.len(), out)?;
    if reviewers.is_empty() {
        out.push("\nNo results.\n")?;
    }
    for reviewer in reviewers {
        let reviewer = as_object(reviewer)?;
        budget.charge_work(reviewer.len())?;
        out.push("\n## Reviewer")?;
        if let Some(user) = reviewer.get("user").filter(|value| !value.is_null()) {
            let user = as_object(user)?;
            if let Some(username) = optional_scalar(user, "username")? {
                out.push(" ")?;
                out.push_code(username)?;
            }
        }
        out.push("\n")?;
        gitlab_user_field(reviewer, "user", "User", out)?;
        code_fields(
            out,
            &[("Assigned", optional_scalar(reviewer, "createdAt")?)],
        )?;
        fields(
            out,
            &[("Reviewer state", optional_scalar(reviewer, "state")?)],
        )?;
    }
    gitlab_pagination_fields(object, out)
}

fn render_gitlab_approval(
    value: &Value,
    out: &mut MarkdownWriter,
    budget: &mut PresentationBudget,
) -> Result<(), RenderError> {
    let approval = as_object(required(as_object(value)?, "approval")?)?;
    budget.charge_work(approval.len())?;
    out.push("# GitLab merge request approval\n")?;
    let approvals_required = optional_display(approval, "approvalsRequired")?;
    let approvals_left = optional_display(approval, "approvalsLeft")?;
    let approved = optional_display(approval, "approved")?;
    let user_has_approved = optional_display(approval, "userHasApproved")?;
    let user_can_approve = optional_display(approval, "userCanApprove")?;
    fields(
        out,
        &[
            ("Approvals required", approvals_required.as_deref()),
            ("Approvals left", approvals_left.as_deref()),
            ("Aggregate approved", approved.as_deref()),
            ("Acting user has approved", user_has_approved.as_deref()),
            ("Acting user can approve", user_can_approve.as_deref()),
        ],
    )?;
    let approved_by = array(required(approval, "approvedBy")?)?;
    budget.charge_work(approved_by.len())?;
    out.push("\n## Approved by\n")?;
    field(out, "Count", &approved_by.len().to_string())?;
    if approved_by.is_empty() {
        out.push("\nNo approvals.\n")?;
    }
    for entry in approved_by {
        let entry = as_object(entry)?;
        budget.charge_work(entry.len())?;
        out.push("\n### Approval\n")?;
        gitlab_user_field(entry, "user", "User", out)?;
        code_fields(
            out,
            &[("Approved at", optional_scalar(entry, "approvedAt")?)],
        )?;
    }
    Ok(())
}

fn render_gitlab_approval_state(
    value: &Value,
    out: &mut MarkdownWriter,
    budget: &mut PresentationBudget,
) -> Result<(), RenderError> {
    let state = as_object(required(as_object(value)?, "approvalState")?)?;
    budget.charge_work(state.len())?;
    out.push("# GitLab merge request approval state\n")?;
    let overwritten = optional_display(state, "approvalRulesOverwritten")?;
    fields(
        out,
        &[("Approval rules overwritten", overwritten.as_deref())],
    )?;
    let rules = array(required(state, "rules")?)?;
    budget.charge_work(rules.len())?;
    field(out, "Rule count", &rules.len().to_string())?;
    if rules.is_empty() {
        out.push("\nNo approval rules.\n")?;
    }
    for rule in rules {
        out.push("\n")?;
        render_gitlab_approval_rule(as_object(rule)?, "## ", out, budget)?;
    }
    Ok(())
}

fn render_gitlab_approval_rule_view(
    value: &Value,
    out: &mut MarkdownWriter,
    budget: &mut PresentationBudget,
) -> Result<(), RenderError> {
    let rule = as_object(required(as_object(value)?, "approvalRule")?)?;
    render_gitlab_approval_rule(rule, "# ", out, budget)
}

fn render_gitlab_approval_rule_list(
    value: &Value,
    out: &mut MarkdownWriter,
    budget: &mut PresentationBudget,
) -> Result<(), RenderError> {
    let object = as_object(value)?;
    let rules = array(required(object, "approvalRules")?)?;
    budget.charge_work(object.len().saturating_add(rules.len()))?;
    out.push("# GitLab merge request approval rules\n")?;
    gitlab_count_field(object, rules.len(), out)?;
    if rules.is_empty() {
        out.push("\nNo results.\n")?;
    }
    for rule in rules {
        out.push("\n")?;
        render_gitlab_approval_rule(as_object(rule)?, "## ", out, budget)?;
    }
    gitlab_pagination_fields(object, out)
}

fn render_gitlab_approval_rule(
    rule: &Map<String, Value>,
    heading: &str,
    out: &mut MarkdownWriter,
    budget: &mut PresentationBudget,
) -> Result<(), RenderError> {
    budget.charge_work(rule.len())?;
    let id = required_display(rule, "id")?;
    out.push(heading)?;
    out.push("Approval rule ")?;
    out.push_code(&id)?;
    out.push("\n")?;
    let approvals_required = required_display(rule, "approvalsRequired")?;
    let approved = optional_display(rule, "approved")?;
    let overridden = optional_display(rule, "overridden")?;
    let hidden = optional_display(rule, "containsHiddenGroups")?;
    let code_owner = optional_display(rule, "codeOwner")?;
    fields(
        out,
        &[
            ("Name", Some(required_scalar(rule, "name")?)),
            ("Rule type", optional_scalar(rule, "ruleType")?),
            ("Approvals required", Some(approvals_required.as_str())),
            ("Approved", approved.as_deref()),
            ("Overridden", overridden.as_deref()),
            ("Contains hidden groups", hidden.as_deref()),
            ("Code owner", code_owner.as_deref()),
            ("Section", optional_scalar(rule, "section")?),
        ],
    )?;
    code_fields(out, &[("Rule ID", Some(id.as_str()))])?;
    for (key, label) in [
        ("eligibleApprovers", "Eligible approvers"),
        ("approvedBy", "Approved by"),
        ("users", "Users"),
    ] {
        gitlab_user_list(rule, key, label, out, budget)?;
    }
    gitlab_group_list(rule, "groups", "Groups", out, budget)?;
    if let Some(source) = rule.get("sourceRule").filter(|value| !value.is_null()) {
        let source = as_object(source)?;
        budget.charge_work(source.len())?;
        let required = required_display(source, "approvalsRequired")?;
        field(out, "Source rule approvals required", &required)?;
    }
    Ok(())
}

fn gitlab_group_list(
    owner: &Map<String, Value>,
    key: &str,
    label: &str,
    out: &mut MarkdownWriter,
    budget: &mut PresentationBudget,
) -> Result<(), RenderError> {
    let groups = array(required(owner, key)?)?;
    budget.charge_work(groups.len())?;
    out.push("- ")?;
    out.push(label)?;
    out.push(": ")?;
    if groups.is_empty() {
        out.push("No items.")?;
    }
    for (index, group) in groups.iter().enumerate() {
        if index > 0 {
            out.push("; ")?;
        }
        let group = as_object(group)?;
        let mut parts = Vec::new();
        if let Some(name) = optional_scalar(group, "name")? {
            parts.push(escaped(name));
        }
        if let Some(path) = optional_scalar(group, "fullPath")?.or(optional_scalar(group, "path")?)
        {
            parts.push(code_span(path));
        }
        if let Some(id) = optional_display(group, "id")? {
            parts.push(format!("ID: {}", code_span(&id)));
        }
        out.push(&if parts.is_empty() {
            "(no details)".to_string()
        } else {
            parts.join("; ")
        })?;
    }
    out.push("\n")
}

fn render_gitlab_merge_request_commit_list(
    value: &Value,
    out: &mut MarkdownWriter,
    budget: &mut PresentationBudget,
) -> Result<(), RenderError> {
    let object = as_object(value)?;
    let commits = array(required(object, "commits")?)?;
    budget.charge_work(object.len().saturating_add(commits.len()))?;
    out.push("# GitLab merge request commits\n")?;
    gitlab_count_field(object, commits.len(), out)?;
    if commits.is_empty() {
        out.push("\nNo results.\n")?;
    }
    for commit in commits {
        out.push("\n")?;
        render_gitlab_commit(as_object(commit)?, "## ", out, budget)?;
    }
    gitlab_pagination_fields(object, out)
}

fn render_gitlab_merge_request_pipeline_list(
    value: &Value,
    out: &mut MarkdownWriter,
    budget: &mut PresentationBudget,
) -> Result<(), RenderError> {
    let object = as_object(value)?;
    let pipelines = array(required(object, "pipelines")?)?;
    budget.charge_work(object.len().saturating_add(pipelines.len()))?;
    out.push("# GitLab merge request pipelines\n")?;
    gitlab_count_field(object, pipelines.len(), out)?;
    if pipelines.is_empty() {
        out.push("\nNo results.\n")?;
    }
    for pipeline in pipelines {
        out.push("\n")?;
        render_gitlab_pipeline(as_object(pipeline)?, "## ", out, budget)?;
    }
    gitlab_pagination_fields(object, out)
}

fn render_gitlab_diff_list(
    value: &Value,
    out: &mut MarkdownWriter,
    budget: &mut PresentationBudget,
) -> Result<(), RenderError> {
    let object = as_object(value)?;
    let diffs = array(required(object, "diffs")?)?;
    budget.charge_work(object.len().saturating_add(diffs.len()))?;
    out.push("# GitLab merge request diffs\n")?;
    gitlab_count_field(object, diffs.len(), out)?;
    if diffs.is_empty() {
        out.push("\nNo results.\n")?;
    }
    for diff in diffs {
        out.push("\n")?;
        render_gitlab_diff(as_object(diff)?, "## ", "### ", out, budget)?;
    }
    gitlab_pagination_fields(object, out)
}

fn render_gitlab_diff(
    diff: &Map<String, Value>,
    heading: &str,
    patch_heading: &str,
    out: &mut MarkdownWriter,
    budget: &mut PresentationBudget,
) -> Result<(), RenderError> {
    budget.charge_work(diff.len())?;
    out.push(heading)?;
    out.push("Diff ")?;
    let old_path = optional_scalar(diff, "oldPath")?;
    let new_path = optional_scalar(diff, "newPath")?;
    out.push_code(new_path.or(old_path).unwrap_or("(unknown path)"))?;
    out.push("\n")?;
    code_fields(
        out,
        &[
            ("Old path", old_path),
            ("New path", new_path),
            ("Old mode", optional_scalar(diff, "oldMode")?),
            ("New mode", optional_scalar(diff, "newMode")?),
        ],
    )?;
    let new_file = optional_display(diff, "newFile")?;
    let renamed_file = optional_display(diff, "renamedFile")?;
    let deleted_file = optional_display(diff, "deletedFile")?;
    let generated_file = optional_display(diff, "generatedFile")?;
    let collapsed = optional_display(diff, "collapsed")?;
    let too_large = optional_display(diff, "tooLarge")?;
    fields(
        out,
        &[
            ("New file", new_file.as_deref()),
            ("Renamed file", renamed_file.as_deref()),
            ("Deleted file", deleted_file.as_deref()),
            ("Generated file", generated_file.as_deref()),
            ("Collapsed", collapsed.as_deref()),
            ("Too large", too_large.as_deref()),
        ],
    )?;
    if let Some(patch) = optional_scalar(diff, "diff")? {
        budget.charge_fenced_literal_work(patch.len())?;
        let patch = normalize_fenced_text_literal(patch);
        let fence = fence_for(&patch, '`');
        out.push("\n")?;
        out.push(patch_heading)?;
        out.push("Patch\n\n")?;
        out.push(&fence)?;
        out.push("diff\n")?;
        out.push(&patch)?;
        out.push("\n")?;
        out.push(&fence)?;
        out.push("\n")?;
    }
    Ok(())
}

fn render_gitlab_diff_version_list(
    value: &Value,
    out: &mut MarkdownWriter,
    budget: &mut PresentationBudget,
) -> Result<(), RenderError> {
    let object = as_object(value)?;
    let versions = array(required(object, "diffVersions")?)?;
    budget.charge_work(object.len().saturating_add(versions.len()))?;
    out.push("# GitLab merge request diff versions\n")?;
    gitlab_count_field(object, versions.len(), out)?;
    if versions.is_empty() {
        out.push("\nNo results.\n")?;
    }
    for version in versions {
        out.push("\n")?;
        render_gitlab_diff_version_metadata(as_object(version)?, "## ", out, budget)?;
    }
    gitlab_pagination_fields(object, out)
}

fn render_gitlab_diff_version_view(
    value: &Value,
    out: &mut MarkdownWriter,
    budget: &mut PresentationBudget,
) -> Result<(), RenderError> {
    let version = as_object(required(as_object(value)?, "diffVersion")?)?;
    render_gitlab_diff_version_metadata(version, "# ", out, budget)?;
    let commits = array(required(version, "commits")?)?;
    budget.charge_work(commits.len())?;
    out.push("\n## Commits\n")?;
    field(out, "Commit count", &commits.len().to_string())?;
    if commits.is_empty() {
        out.push("\nNo commits.\n")?;
    }
    for commit in commits {
        out.push("\n")?;
        render_gitlab_commit(as_object(commit)?, "### ", out, budget)?;
    }
    let diffs = array(required(version, "diffs")?)?;
    budget.charge_work(diffs.len())?;
    out.push("\n## Diffs\n")?;
    field(out, "Diff count", &diffs.len().to_string())?;
    if diffs.is_empty() {
        out.push("\nNo diffs.\n")?;
    }
    for diff in diffs {
        out.push("\n")?;
        render_gitlab_diff(as_object(diff)?, "### ", "#### ", out, budget)?;
    }
    Ok(())
}

fn render_gitlab_diff_version_metadata(
    version: &Map<String, Value>,
    heading: &str,
    out: &mut MarkdownWriter,
    budget: &mut PresentationBudget,
) -> Result<(), RenderError> {
    budget.charge_work(version.len())?;
    let id = required_display(version, "id")?;
    out.push(heading)?;
    out.push("Diff version ")?;
    out.push_code(&id)?;
    out.push("\n")?;
    let merge_request_id = optional_display(version, "mergeRequestId")?;
    let real_size = optional_display(version, "realSize")?;
    code_fields(
        out,
        &[
            ("Diff version ID", Some(id.as_str())),
            ("Merge request ID", merge_request_id.as_deref()),
            (
                "Head commit SHA",
                optional_scalar(version, "headCommitSha")?,
            ),
            (
                "Base commit SHA",
                optional_scalar(version, "baseCommitSha")?,
            ),
            (
                "Start commit SHA",
                optional_scalar(version, "startCommitSha")?,
            ),
            ("Patch ID SHA", optional_scalar(version, "patchIdSha")?),
            ("Created", optional_scalar(version, "createdAt")?),
            ("Real size", real_size.as_deref()),
        ],
    )?;
    fields(out, &[("State", optional_scalar(version, "state")?)])
}

fn render_gitlab_branch_view(
    value: &Value,
    out: &mut MarkdownWriter,
    budget: &mut PresentationBudget,
) -> Result<(), RenderError> {
    let branch = as_object(required(as_object(value)?, "branch")?)?;
    render_gitlab_branch(branch, "# ", out, budget)
}

fn render_gitlab_branch_list(
    value: &Value,
    out: &mut MarkdownWriter,
    budget: &mut PresentationBudget,
) -> Result<(), RenderError> {
    let branches = array(required(as_object(value)?, "branches")?)?;
    budget.charge_work(branches.len())?;
    out.push("# GitLab branches\n")?;
    field(out, "Count", &branches.len().to_string())?;
    if branches.is_empty() {
        out.push("\nNo results.\n")?;
    }
    for branch in branches {
        out.push("\n")?;
        render_gitlab_branch(as_object(branch)?, "## ", out, budget)?;
    }
    Ok(())
}

fn render_gitlab_branch(
    branch: &Map<String, Value>,
    heading: &str,
    out: &mut MarkdownWriter,
    budget: &mut PresentationBudget,
) -> Result<(), RenderError> {
    budget.charge_work(branch.len())?;
    out.push(heading)?;
    out.push("Branch ")?;
    out.push_code(required_scalar(branch, "name")?)?;
    out.push("\n")?;
    let merged = optional_display(branch, "merged")?;
    let protected = optional_display(branch, "protected")?;
    let default = optional_display(branch, "default")?;
    fields(
        out,
        &[
            ("Merged", merged.as_deref()),
            ("Protected", protected.as_deref()),
            ("Default", default.as_deref()),
        ],
    )?;
    if let Some(url) = optional_scalar(branch, "webUrl")? {
        field_url(out, "URL", url)?;
    }
    if let Some(commit) = branch.get("commit").filter(|value| !value.is_null()) {
        let commit = as_object(commit)?;
        out.push("\n### Commit\n")?;
        code_fields(
            out,
            &[
                ("ID", Some(required_scalar(commit, "id")?)),
                ("Short ID", optional_scalar(commit, "shortId")?),
            ],
        )?;
        fields(out, &[("Title", optional_scalar(commit, "title")?)])?;
    }
    Ok(())
}

fn render_gitlab_protected_branch_view(
    value: &Value,
    out: &mut MarkdownWriter,
    budget: &mut PresentationBudget,
) -> Result<(), RenderError> {
    let branch = as_object(required(as_object(value)?, "protectedBranch")?)?;
    render_gitlab_protected_branch(branch, "# ", out, budget)
}

fn render_gitlab_protected_branch_list(
    value: &Value,
    out: &mut MarkdownWriter,
    budget: &mut PresentationBudget,
) -> Result<(), RenderError> {
    let branches = array(required(as_object(value)?, "protectedBranches")?)?;
    budget.charge_work(branches.len())?;
    out.push("# GitLab protected branches\n")?;
    field(out, "Count", &branches.len().to_string())?;
    if branches.is_empty() {
        out.push("\nNo results.\n")?;
    }
    for branch in branches {
        out.push("\n")?;
        render_gitlab_protected_branch(as_object(branch)?, "## ", out, budget)?;
    }
    Ok(())
}

fn render_gitlab_protected_branch(
    branch: &Map<String, Value>,
    heading: &str,
    out: &mut MarkdownWriter,
    budget: &mut PresentationBudget,
) -> Result<(), RenderError> {
    budget.charge_work(branch.len())?;
    out.push(heading)?;
    out.push("Protected branch ")?;
    out.push_code(required_scalar(branch, "name")?)?;
    out.push("\n")?;
    let id = optional_display(branch, "id")?;
    let force_push = optional_display(branch, "allowForcePush")?;
    let code_owner = optional_display(branch, "codeOwnerApprovalRequired")?;
    let inherited = optional_display(branch, "inherited")?;
    code_fields(out, &[("Rule ID", id.as_deref())])?;
    fields(
        out,
        &[
            ("Allow force push", force_push.as_deref()),
            ("Code-owner approval required", code_owner.as_deref()),
            ("Inherited", inherited.as_deref()),
        ],
    )?;
    gitlab_access_levels(
        branch,
        "pushAccessLevels",
        "Push access levels",
        out,
        budget,
    )?;
    gitlab_access_levels(
        branch,
        "mergeAccessLevels",
        "Merge access levels",
        out,
        budget,
    )?;
    gitlab_access_levels(
        branch,
        "unprotectAccessLevels",
        "Unprotect access levels",
        out,
        budget,
    )
}

fn gitlab_access_levels(
    owner: &Map<String, Value>,
    key: &str,
    label: &str,
    out: &mut MarkdownWriter,
    budget: &mut PresentationBudget,
) -> Result<(), RenderError> {
    let levels = array(required(owner, key)?)?;
    budget.charge_work(levels.len())?;
    out.push("\n### ")?;
    out.push(label)?;
    out.push("\n")?;
    if levels.is_empty() {
        out.push("No items.\n")?;
    }
    for level in levels {
        let level = as_object(level)?;
        let access_level = optional_display(level, "accessLevel")?;
        let user_id = optional_display(level, "userId")?;
        let group_id = optional_display(level, "groupId")?;
        let deploy_key_id = optional_display(level, "deployKeyId")?;
        out.push("- Access level")?;
        if let Some(value) = access_level.as_deref() {
            out.push(" ")?;
            out.push_code(value)?;
        }
        if let Some(description) = optional_scalar(level, "accessLevelDescription")? {
            out.push(": ")?;
            out.push_escaped(description)?;
        }
        for (name, value) in [
            ("user ID", user_id.as_deref()),
            ("group ID", group_id.as_deref()),
            ("deploy key ID", deploy_key_id.as_deref()),
        ] {
            if let Some(value) = value {
                out.push("; ")?;
                out.push(name)?;
                out.push(": ")?;
                out.push_code(value)?;
            }
        }
        out.push("\n")?;
    }
    Ok(())
}

fn render_gitlab_protected_branch_verify(
    value: &Value,
    out: &mut MarkdownWriter,
    budget: &mut PresentationBudget,
) -> Result<(), RenderError> {
    let verification = as_object(required(as_object(value)?, "protectedBranchVerification")?)?;
    let checks = array(required(verification, "checks")?)?;
    budget.charge_work(verification.len().saturating_add(checks.len()))?;
    out.push("# GitLab protected-branch verification\n")?;
    let project_id = optional_display(verification, "projectId")?;
    code_fields(
        out,
        &[
            ("Project", optional_scalar(verification, "project")?),
            ("Project ID", project_id.as_deref()),
            (
                "Default branch",
                optional_scalar(verification, "defaultBranch")?,
            ),
        ],
    )?;
    field(out, "Check count", &checks.len().to_string())?;
    if checks.is_empty() {
        out.push("\nNo results.\n")?;
    }
    for check in checks {
        let check = as_object(check)?;
        out.push("\n## Pattern ")?;
        out.push_code(required_scalar(check, "pattern")?)?;
        out.push("\n")?;
        let covered = optional_display(check, "covered")?;
        fields(out, &[("Covered", covered.as_deref())])?;
        code_fields(
            out,
            &[("Matched rule", optional_scalar(check, "matchedRule")?)],
        )?;
        gitlab_access_levels(check, "pushAccessLevels", "Push access levels", out, budget)?;
        gitlab_access_levels(
            check,
            "mergeAccessLevels",
            "Merge access levels",
            out,
            budget,
        )?;
    }
    Ok(())
}

fn render_gitlab_file_view(
    value: &Value,
    out: &mut MarkdownWriter,
    budget: &mut PresentationBudget,
) -> Result<(), RenderError> {
    let file = as_object(required(as_object(value)?, "file")?)?;
    budget.charge_work(file.len())?;
    out.push("# GitLab file ")?;
    out.push_code(required_scalar(file, "filePath")?)?;
    out.push("\n")?;
    let size = optional_display(file, "size")?;
    let executable = optional_display(file, "executeFilemode")?;
    code_fields(
        out,
        &[
            ("File name", optional_scalar(file, "fileName")?),
            ("File path", optional_scalar(file, "filePath")?),
            ("Size", size.as_deref()),
            ("Encoding", optional_scalar(file, "encoding")?),
            ("Content SHA-256", optional_scalar(file, "contentSha256")?),
            ("Ref", optional_scalar(file, "ref")?),
            ("Blob ID", optional_scalar(file, "blobId")?),
            ("Commit ID", optional_scalar(file, "commitId")?),
            ("Last commit ID", optional_scalar(file, "lastCommitId")?),
        ],
    )?;
    fields(out, &[("Executable", executable.as_deref())])?;
    if let Some(content) = optional_scalar(file, "contentBase64")? {
        budget.charge_fenced_literal_work(content.len())?;
        let fence = fence_for(content, '`');
        out.push("\n## Content (base64)\n\n")?;
        out.push(&fence)?;
        out.push("base64\n")?;
        out.push(content)?;
        out.push("\n")?;
        out.push(&fence)?;
        out.push("\n")?;
    }
    Ok(())
}

fn render_gitlab_commit_view(
    value: &Value,
    out: &mut MarkdownWriter,
    budget: &mut PresentationBudget,
) -> Result<(), RenderError> {
    render_gitlab_commit(
        as_object(required(as_object(value)?, "commit")?)?,
        "# ",
        out,
        budget,
    )
}

fn render_gitlab_commit_list(
    value: &Value,
    out: &mut MarkdownWriter,
    budget: &mut PresentationBudget,
) -> Result<(), RenderError> {
    let commits = array(required(as_object(value)?, "commits")?)?;
    budget.charge_work(commits.len())?;
    out.push("# GitLab commits\n")?;
    field(out, "Count", &commits.len().to_string())?;
    if commits.is_empty() {
        out.push("\nNo results.\n")?;
    }
    for commit in commits {
        out.push("\n")?;
        render_gitlab_commit(as_object(commit)?, "## ", out, budget)?;
    }
    Ok(())
}

fn render_gitlab_commit(
    commit: &Map<String, Value>,
    heading: &str,
    out: &mut MarkdownWriter,
    budget: &mut PresentationBudget,
) -> Result<(), RenderError> {
    budget.charge_work(commit.len())?;
    out.push(heading)?;
    out.push("Commit ")?;
    out.push_code(required_scalar(commit, "id")?)?;
    if let Some(title) = optional_scalar(commit, "title")? {
        out.push(" — ")?;
        out.push_heading_text(title)?;
    }
    out.push("\n")?;
    code_fields(
        out,
        &[
            ("Short ID", optional_scalar(commit, "shortId")?),
            ("Authored", optional_scalar(commit, "authoredDate")?),
            ("Committed", optional_scalar(commit, "committedDate")?),
        ],
    )?;
    fields(out, &[("Author", optional_scalar(commit, "authorName")?)])?;
    if let Some(url) = optional_scalar(commit, "webUrl")? {
        field_url(out, "URL", url)?;
    }
    if let Some(message) = optional_scalar(commit, "message")? {
        budget.charge_fenced_literal_work(message.len())?;
        let message = normalize_fenced_text_literal(message);
        let fence = fence_for(&message, '`');
        out.push("\n### Message\n\n")?;
        out.push(&fence)?;
        out.push("text\n")?;
        out.push(&message)?;
        out.push("\n")?;
        out.push(&fence)?;
        out.push("\n")?;
    }
    Ok(())
}

fn render_gitlab_pipeline_view(
    value: &Value,
    out: &mut MarkdownWriter,
    budget: &mut PresentationBudget,
) -> Result<(), RenderError> {
    render_gitlab_pipeline(
        as_object(required(as_object(value)?, "pipeline")?)?,
        "# ",
        out,
        budget,
    )
}

fn render_gitlab_pipeline_list(
    value: &Value,
    out: &mut MarkdownWriter,
    budget: &mut PresentationBudget,
) -> Result<(), RenderError> {
    let pipelines = array(required(as_object(value)?, "pipelines")?)?;
    budget.charge_work(pipelines.len())?;
    out.push("# GitLab pipelines\n")?;
    field(out, "Count", &pipelines.len().to_string())?;
    if pipelines.is_empty() {
        out.push("\nNo results.\n")?;
    }
    for pipeline in pipelines {
        out.push("\n")?;
        render_gitlab_pipeline(as_object(pipeline)?, "## ", out, budget)?;
    }
    Ok(())
}

fn render_gitlab_pipeline(
    pipeline: &Map<String, Value>,
    heading: &str,
    out: &mut MarkdownWriter,
    budget: &mut PresentationBudget,
) -> Result<(), RenderError> {
    budget.charge_work(pipeline.len())?;
    let id = required_display(pipeline, "id")?;
    out.push(heading)?;
    out.push("Pipeline ")?;
    out.push_code(&id)?;
    out.push("\n")?;
    let iid = optional_display(pipeline, "iid")?;
    let project_id = optional_display(pipeline, "projectId")?;
    code_fields(
        out,
        &[
            ("Pipeline ID", Some(id.as_str())),
            ("Pipeline IID", iid.as_deref()),
            ("Project ID", project_id.as_deref()),
            ("Ref", optional_scalar(pipeline, "ref")?),
            ("SHA", optional_scalar(pipeline, "sha")?),
            ("Created", optional_scalar(pipeline, "createdAt")?),
            ("Updated", optional_scalar(pipeline, "updatedAt")?),
        ],
    )?;
    fields(
        out,
        &[
            ("Status", optional_scalar(pipeline, "status")?),
            ("Source", optional_scalar(pipeline, "source")?),
        ],
    )?;
    if let Some(url) = optional_scalar(pipeline, "webUrl")? {
        field_url(out, "URL", url)?;
    }
    Ok(())
}

fn render_gitlab_job_view(
    value: &Value,
    out: &mut MarkdownWriter,
    budget: &mut PresentationBudget,
) -> Result<(), RenderError> {
    render_gitlab_job(
        as_object(required(as_object(value)?, "job")?)?,
        "# ",
        out,
        budget,
    )
}

fn render_gitlab_job_list(
    value: &Value,
    out: &mut MarkdownWriter,
    budget: &mut PresentationBudget,
) -> Result<(), RenderError> {
    let jobs = array(required(as_object(value)?, "jobs")?)?;
    budget.charge_work(jobs.len())?;
    out.push("# GitLab jobs\n")?;
    field(out, "Count", &jobs.len().to_string())?;
    if jobs.is_empty() {
        out.push("\nNo results.\n")?;
    }
    for job in jobs {
        out.push("\n")?;
        render_gitlab_job(as_object(job)?, "## ", out, budget)?;
    }
    Ok(())
}

fn render_gitlab_job(
    job: &Map<String, Value>,
    heading: &str,
    out: &mut MarkdownWriter,
    budget: &mut PresentationBudget,
) -> Result<(), RenderError> {
    budget.charge_work(job.len())?;
    let id = required_display(job, "id")?;
    out.push(heading)?;
    out.push("Job ")?;
    out.push_code(&id)?;
    if let Some(name) = optional_scalar(job, "name")? {
        out.push(" — ")?;
        out.push_heading_text(name)?;
    }
    out.push("\n")?;
    let pipeline_id = optional_display(job, "pipelineId")?;
    let project_id = optional_display(job, "projectId")?;
    let trace_size = optional_display(job, "traceSize")?;
    code_fields(
        out,
        &[
            ("Job ID", Some(id.as_str())),
            ("Ref", optional_scalar(job, "ref")?),
            ("Pipeline ID", pipeline_id.as_deref()),
            ("Project ID", project_id.as_deref()),
            ("Trace size", trace_size.as_deref()),
            ("Created", optional_scalar(job, "createdAt")?),
            ("Started", optional_scalar(job, "startedAt")?),
            ("Finished", optional_scalar(job, "finishedAt")?),
        ],
    )?;
    fields(
        out,
        &[
            ("Status", optional_scalar(job, "status")?),
            ("Stage", optional_scalar(job, "stage")?),
        ],
    )?;
    if let Some(url) = optional_scalar(job, "webUrl")? {
        field_url(out, "URL", url)?;
    }
    Ok(())
}

fn required_display(object: &Map<String, Value>, key: &str) -> Result<String, RenderError> {
    optional_display(object, key)?.ok_or(RenderError)
}

#[cfg(test)]
mod tests {
    use super::*;
    use agent_access_provider::{ProviderError, ReasonCode};
    use serde_json::json;

    fn present_provider_result(
        action: &str,
        result: &mut Value,
        options: ResponseOptions,
        max_body_bytes: u64,
        max_result_bytes: u64,
    ) -> Result<(), ProviderError> {
        present_result(
            presentation(action).as_ref(),
            result,
            options,
            max_body_bytes,
            max_result_bytes,
        )
    }

    fn response_capabilities(action: &str) -> ResponseCapabilities {
        agent_access_provider::presentation::response_capabilities(presentation(action).as_ref())
    }

    #[test]
    fn registry_has_exact_gitlab_coverage_and_derived_capabilities() {
        let embedded = RESULT_DESCRIPTORS
            .iter()
            .filter(|descriptor| !descriptor.embedded_bodies.is_empty())
            .map(|descriptor| descriptor.action)
            .collect::<std::collections::BTreeSet<_>>();
        assert_eq!(
            embedded,
            [
                "issue.create",
                "issue.note.add",
                "issue.note.list",
                "issue.note.update",
                "issue.note.view",
                "issue.search",
                "issue.update",
                "issue.view",
                "merge_request.create",
                "merge_request.discussion.add",
                "merge_request.discussion.inline.add",
                "merge_request.discussion.list",
                "merge_request.discussion.note.add",
                "merge_request.discussion.view",
                "merge_request.discussion.note.update",
                "merge_request.discussion.reopen",
                "merge_request.discussion.resolve",
                "merge_request.draft_note.add",
                "merge_request.draft_note.list",
                "merge_request.draft_note.update",
                "merge_request.draft_note.view",
                "merge_request.note.add",
                "merge_request.note.list",
                "merge_request.note.update",
                "merge_request.note.view",
                "merge_request.search",
                "merge_request.update",
                "merge_request.view",
            ]
            .into_iter()
            .collect()
        );
        let whole = RESULT_DESCRIPTORS
            .iter()
            .filter(|descriptor| descriptor.whole.is_some())
            .map(|descriptor| descriptor.action)
            .collect::<std::collections::BTreeSet<_>>();
        assert_eq!(
            whole,
            [
                "branch.list",
                "branch.view",
                "commit.list",
                "commit.view",
                "file.view",
                "issue.note.list",
                "issue.note.view",
                "issue.search",
                "issue.view",
                "job.list",
                "job.view",
                "merge_request.approval.view",
                "merge_request.approval_rule.list",
                "merge_request.approval_rule.view",
                "merge_request.approval_state.view",
                "merge_request.discussion.list",
                "merge_request.discussion.view",
                "merge_request.reviewer.list",
                "merge_request.commit.list",
                "merge_request.pipeline.list",
                "merge_request.diff.list",
                "merge_request.diff_version.list",
                "merge_request.diff_version.view",
                "merge_request.draft_note.list",
                "merge_request.draft_note.view",
                "merge_request.note.list",
                "merge_request.note.view",
                "merge_request.search",
                "merge_request.view",
                "pipeline.list",
                "pipeline.view",
                "project.view",
                "project.search",
                "search.issues",
                "search.merge_requests",
                "search.code",
                "search.commits",
                "search.wiki",
                "search.comments",
                "protected_branch.list",
                "protected_branch.verify",
                "protected_branch.view",
            ]
            .into_iter()
            .collect()
        );
        assert_eq!(
            response_capabilities("issue.view"),
            ResponseCapabilities::new(Some(READ_CONTENT_FORMATS), Some(RESPONSE_FORMATS))
        );
        assert_eq!(
            response_capabilities("issue.create"),
            ResponseCapabilities::new(Some(READ_CONTENT_FORMATS), None)
        );
        assert_eq!(
            response_capabilities("project.view"),
            ResponseCapabilities::new(None, Some(RESPONSE_FORMATS))
        );
        assert_eq!(
            response_capabilities("merge_request.draft_note.view"),
            ResponseCapabilities::new(Some(READ_CONTENT_FORMATS), Some(RESPONSE_FORMATS))
        );
        assert_eq!(
            response_capabilities("merge_request.draft_note.add"),
            ResponseCapabilities::new(Some(READ_CONTENT_FORMATS), None)
        );
        for excluded in [
            "file.raw.download",
            "job.trace.download",
            "merge_request.diff.raw.download",
            "merge_request.draft_note.delete",
            "merge_request.draft_note.publish",
            "merge_request.draft_note.publish_all",
            "merge_request.merge",
            "merge_request.review.submit",
            "pipeline.run",
        ] {
            assert_eq!(
                response_capabilities(excluded),
                ResponseCapabilities::new(None, None)
            );
        }
        for action in [
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
        ] {
            assert!(
                descriptor(action).is_some(),
                "gitlab.{action} must be explicitly classified by the presentation registry"
            );
            assert_eq!(
                response_capabilities(action),
                ResponseCapabilities::new(None, None)
            );
        }
    }

    fn gitlab_user_fixture() -> Value {
        json!({"id":7,"username":"ada","name":"Ada","webUrl":"https://gitlab.test/ada"})
    }

    fn gitlab_issue_fixture() -> Value {
        json!({
            "id":100,"iid":1,"projectId":9,"project":"group/repo","title":"Issue *title*",
            "description":"# Body\n\n- item","state":"opened","webUrl":"https://gitlab.test/group/repo/-/issues/1",
            "createdAt":"2026-08-01","updatedAt":"2026-08-02","author":gitlab_user_fixture(),
            "assignees":[gitlab_user_fixture()],"labels":["bug","P1"],
            "milestone":{"id":3,"iid":4,"title":"M1","state":"active","dueDate":"2026-09-01"}
        })
    }

    fn gitlab_merge_request_fixture() -> Value {
        json!({
            "id":200,"iid":2,"projectId":9,"project":"group/repo","title":"MR title",
            "description":"MR **body**","state":"opened","sourceBranch":"feature/x","targetBranch":"main",
            "sha":"abc","mergeStatus":"can_be_merged","detailedMergeStatus":"mergeable",
            "sourceProjectId":9,"targetProjectId":9,
            "diffRefs":{"baseSha":"base","startSha":"start","headSha":"abc"},
            "squashCommitSha":"squash","mergeCommitSha":"def","changesCount":"2","userNotesCount":3,
            "discussionLocked":false,"blockingDiscussionsResolved":true,"hasConflicts":false,
            "preparedAt":"2026-08-01T00:00:00Z","webUrl":"https://gitlab.test/group/repo/-/merge_requests/2",
            "createdAt":"2026-08-01","updatedAt":"2026-08-02","author":gitlab_user_fixture(),
            "assignees":[gitlab_user_fixture()],"reviewers":[],"labels":["review"],
            "milestone":{"id":3,"iid":4,"title":"M1","state":"active","dueDate":"2026-09-01"},
            "draft":false,"headPipeline":{"id":50,"ref":"feature/x","sha":"abc","status":"success",
                "webUrl":"https://gitlab.test/pipelines/50"}
        })
    }

    fn gitlab_note_fixture() -> Value {
        json!({
            "id":30,"body":"Note <script>bad()</script> **body**","type":"DiffNote","noteableType":"MergeRequest",
            "noteableIid":1,"noteableId":100,"projectId":9,"resolved":false,"resolvable":true,
            "authorUserId":7,"authorUsername":"ada","createdAt":"2026-08-01","updatedAt":"2026-08-02",
            "system":false,"confidential":false,"commitId":"commit",
            "resolvedBy":gitlab_user_fixture(),"resolvedAt":"2026-08-02T01:00:00Z",
            "position":{"positionType":"text","baseSha":"base","startSha":"start","headSha":"head",
                "oldPath":"src/old.rs","newPath":"src/new.rs","oldLine":31,"newLine":34,
                "lineRange":{"start":{"lineCode":"path_31_34","type":"old","oldLine":31,"newLine":34},
                    "end":{"lineCode":"path_32_35","type":"new","newLine":35}}},
            "suggestions":[{"id":91,"fromLine":34,"toLine":35,"applicable":true,"applied":false,
                "fromContent":"old\n```collision","toContent":"new code"}]
        })
    }

    fn gitlab_nullable_position_note_fixture() -> Value {
        let mut note = gitlab_note_fixture();
        note["position"]["baseSha"] = Value::Null;
        note["position"]["lineRange"]["start"]["type"] = Value::Null;
        note
    }

    fn gitlab_draft_note_fixture() -> Value {
        json!({
            "id":77,
            "body":"Draft <script>bad()</script> **body**",
            "authorUserId":7,
            "mergeRequestId":200,
            "resolveDiscussion":true,
            "discussionId":"discussion`id",
            "commitId":"historical-head",
            "position":{
                "positionType":"text",
                "baseSha":"base",
                "startSha":"start",
                "headSha":"historical-head",
                "oldPath":"src/old.rs",
                "newPath":"src/new.rs",
                "oldLine":31,
                "newLine":34,
                "lineRange":{
                    "start":{"lineCode":"path_31_34","type":"old","oldLine":31,"newLine":34},
                    "end":{"lineCode":"path_32_35","type":"new","newLine":35}
                }
            }
        })
    }

    fn gitlab_note_summary_fixture() -> Value {
        json!({
            "id":701,
            "authorUserId":314,
            "authorUsername":"review-bot",
            "createdAt":"2026-08-30T12:00:00Z",
            "updatedAt":"2026-08-30T12:01:00Z",
            "system":false,
            "confidential":false,
            "resolved":false,
            "resolvable":true,
            "type":"DiffNote",
            "commitId":"historical-head",
            "position":{
                "positionType":"text",
                "baseSha":"base",
                "startSha":"start",
                "headSha":"historical-head",
                "oldPath":"src/old.rs",
                "newPath":"src/new.rs",
                "oldLine":109,
                "newLine":108
            }
        })
    }

    fn gitlab_summary_collection_fixtures() -> Vec<(&'static str, Value, &'static str)> {
        vec![
            (
                "issue.note.list",
                json!({
                    "projection":"summary",
                    "notes":[gitlab_note_summary_fixture()],
                    "count":1,
                    "maxResults":20,
                    "isLast":true,
                    "nextPageToken":null
                }),
                "## Note `701`",
            ),
            (
                "merge_request.discussion.list",
                json!({
                    "projection":"summary",
                    "discussions":[{
                        "id":"discussion-1",
                        "individualNote":false,
                        "noteCount":1,
                        "notes":[gitlab_note_summary_fixture()]
                    }],
                    "count":1,
                    "maxResults":20,
                    "isLast":true,
                    "nextPageToken":null
                }),
                "## Discussion `discussion-1`",
            ),
            (
                "merge_request.draft_note.list",
                json!({
                    "projection":"summary",
                    "draftNotes":[{
                        "id":11964,
                        "authorUserId":314,
                        "mergeRequestId":500,
                        "resolveDiscussion":false,
                        "discussionId":"discussion-1",
                        "commitId":"historical-head",
                        "position":{
                            "positionType":"text",
                            "baseSha":"base",
                            "startSha":"start",
                            "headSha":"historical-head",
                            "oldPath":"src/old.rs",
                            "newPath":"src/new.rs",
                            "oldLine":109,
                            "newLine":108
                        }
                    }],
                    "count":1,
                    "maxResults":20,
                    "isLast":true,
                    "nextPageToken":null
                }),
                "## Draft note `11964`",
            ),
        ]
    }

    fn assert_gitlab_summary_has_no_rich_content(value: &Value) {
        match value {
            Value::Array(values) => {
                for value in values {
                    assert_gitlab_summary_has_no_rich_content(value);
                }
            }
            Value::Object(object) => {
                for forbidden in ["body", "renderedBody", "suggestion", "suggestions"] {
                    assert!(
                        !object.contains_key(forbidden),
                        "summary leaked {forbidden}: {value}"
                    );
                }
                for value in object.values() {
                    assert_gitlab_summary_has_no_rich_content(value);
                }
            }
            _ => {}
        }
    }

    fn gitlab_diff_fixture() -> Value {
        json!({
            "oldPath":"src/old.rs","newPath":"src/new.rs","oldMode":"100644","newMode":"100755",
            "diff":"@@ -31 +34 @@\n-old\n+```new","newFile":false,"renamedFile":true,
            "deletedFile":false,"generatedFile":false,"collapsed":false,"tooLarge":false
        })
    }

    fn gitlab_diff_version_fixture(include_content: bool) -> Value {
        let mut version = json!({
            "id":12,"mergeRequestId":200,"headCommitSha":"head","baseCommitSha":"base",
            "startCommitSha":"start","createdAt":"2026-08-01","state":"collected",
            "realSize":"1","patchIdSha":"patch"
        });
        if include_content {
            version["commits"] = json!([{
                "id":"abcdef","shortId":"abcdef","title":"Title","message":"message",
                "authorName":"Ada","authoredDate":"2026-08-01","committedDate":"2026-08-02"
            }]);
            version["diffs"] = json!([gitlab_diff_fixture()]);
        }
        version
    }

    fn gitlab_access_level_fixture() -> Value {
        json!({
            "accessLevel":40,"accessLevelDescription":"Maintainers","userId":7,
            "groupId":8,"deployKeyId":9
        })
    }

    fn gitlab_protected_branch_fixture() -> Value {
        json!({
            "id":4,"name":"main","allowForcePush":false,"codeOwnerApprovalRequired":true,
            "inherited":false,"pushAccessLevels":[gitlab_access_level_fixture()],
            "mergeAccessLevels":[],"unprotectAccessLevels":[gitlab_access_level_fixture()]
        })
    }

    fn gitlab_whole_fixture(renderer: WholeRenderer) -> Value {
        match renderer {
            WholeRenderer::NativeSearch => {
                json!({"items":[{"project":"group/repo","id":12,"title":"Found","bodyPreview":"Preview","previewTruncated":false}],"count":1,"maxResults":20,"scanStatus":"more","nextPageToken":"opaque-token"})
            }
            WholeRenderer::Project => json!({"project":{
                "id":9,"pathWithNamespace":"group/repo","name":"Repo","webUrl":"https://gitlab.test/group/repo",
                "defaultBranch":"main","visibility":"private","archived":false
            }}),
            WholeRenderer::Issue => json!({"issue":gitlab_issue_fixture()}),
            WholeRenderer::IssueList => json!({
                "issues":[gitlab_issue_fixture()],"count":1,"maxResults":20,"isLast":false,"nextPageToken":"opaque`token"
            }),
            WholeRenderer::NoteList => json!({
                "notes":[gitlab_note_fixture()],"count":1,"maxResults":20,"isLast":false,"nextPageToken":"next"
            }),
            WholeRenderer::Note => json!({"note":gitlab_note_fixture()}),
            WholeRenderer::MergeRequest => {
                json!({"mergeRequest":gitlab_merge_request_fixture()})
            }
            WholeRenderer::MergeRequestList => json!({
                "mergeRequests":[gitlab_merge_request_fixture()],"count":1,"maxResults":20,
                "isLast":true,"nextPageToken":null
            }),
            WholeRenderer::ReviewerList => json!({
                "reviewers":[{"user":gitlab_user_fixture(),"state":"requested_changes","createdAt":"2026-08-01"}],
                "count":1,"maxResults":20,"isLast":true,"nextPageToken":null
            }),
            WholeRenderer::MergeRequestCommitList => json!({"commits":[{
                "id":"abcdef","shortId":"abcdef","title":"Title","message":"message\n```collision",
                "authorName":"Ada","authoredDate":"2026-08-01","committedDate":"2026-08-02",
                "webUrl":"https://gitlab.test/group/repo/-/commit/abcdef"
            }],"count":1,"maxResults":20,"isLast":true,"nextPageToken":null}),
            WholeRenderer::MergeRequestPipelineList => json!({"pipelines":[{
                "id":50,"iid":5,"projectId":9,"ref":"main","sha":"abcdef","status":"success",
                "source":"merge_request_event","webUrl":"https://gitlab.test/pipelines/50",
                "createdAt":"2026-08-01","updatedAt":"2026-08-02"
            }],"count":1,"maxResults":20,"isLast":true,"nextPageToken":null}),
            WholeRenderer::DiffList => json!({
                "diffs":[gitlab_diff_fixture()],"count":1,"maxResults":20,"isLast":true,"nextPageToken":null
            }),
            WholeRenderer::DiffVersionList => json!({
                "diffVersions":[gitlab_diff_version_fixture(false)],"count":1,"maxResults":20,
                "isLast":true,"nextPageToken":null
            }),
            WholeRenderer::DiffVersion => json!({
                "diffVersion":gitlab_diff_version_fixture(true)
            }),
            WholeRenderer::Discussion | WholeRenderer::DiscussionList => {
                let discussion = json!({
                    "id":"discussion-1","individualNote":false,"notes":[gitlab_note_fixture()]
                });
                if renderer == WholeRenderer::Discussion {
                    json!({"discussion":discussion})
                } else {
                    json!({"discussions":[discussion],"count":1,"maxResults":20,
                        "isLast":true,"nextPageToken":null})
                }
            }
            WholeRenderer::DraftNote => json!({
                "draftNote":gitlab_draft_note_fixture()
            }),
            WholeRenderer::DraftNoteList => json!({
                "draftNotes":[gitlab_draft_note_fixture()],"count":1,"maxResults":20,
                "isLast":false,"nextPageToken":"draft-page"
            }),
            WholeRenderer::Approval => json!({"approval":{
                "approvalsRequired":2,"approvalsLeft":1,"approved":false,
                "userHasApproved":true,"userCanApprove":false,
                "approvedBy":[{"user":gitlab_user_fixture(),"approvedAt":"2026-08-01"}]
            }}),
            WholeRenderer::ApprovalState => json!({"approvalState":{
                "approvalRulesOverwritten":true,"rules":[gitlab_approval_rule_fixture()]
            }}),
            WholeRenderer::ApprovalRule => json!({
                "approvalRule":gitlab_approval_rule_fixture()
            }),
            WholeRenderer::ApprovalRuleList => json!({
                "approvalRules":[gitlab_approval_rule_fixture()],"count":1,"maxResults":20,
                "isLast":false,"nextPageToken":"approval-rule-page"
            }),
            WholeRenderer::Branch => json!({"branch":{
                "name":"main","merged":false,"protected":true,"default":true,
                "webUrl":"https://gitlab.test/group/repo/-/tree/main",
                "commit":{"id":"abc","shortId":"abc","title":"Commit title"}
            }}),
            WholeRenderer::BranchList => json!({"branches":[{
                "name":"main","merged":false,"protected":true,"default":true,
                "webUrl":"https://gitlab.test/group/repo/-/tree/main",
                "commit":{"id":"abc","shortId":"abc","title":"Commit title"}
            }]}),
            WholeRenderer::ProtectedBranch => {
                json!({"protectedBranch":gitlab_protected_branch_fixture()})
            }
            WholeRenderer::ProtectedBranchList => {
                json!({"protectedBranches":[gitlab_protected_branch_fixture()]})
            }
            WholeRenderer::ProtectedBranchVerify => json!({"protectedBranchVerification":{
                "project":"group/repo","projectId":9,"defaultBranch":"main","checks":[{
                    "pattern":"main","covered":true,"matchedRule":"main",
                    "pushAccessLevels":[gitlab_access_level_fixture()],"mergeAccessLevels":[]
                }]
            }}),
            WholeRenderer::File => json!({"file":{
                "fileName":"README.md","filePath":"docs/README.md","size":4,"encoding":"base64",
                "contentBase64":"YWJj```ZA==","contentSha256":"sha256","ref":"main","blobId":"blob",
                "commitId":"commit","lastCommitId":"last","executeFilemode":false
            }}),
            WholeRenderer::Commit => json!({"commit":{
                "id":"abcdef","shortId":"abcdef","title":"Title","message":"message\n```collision",
                "authorName":"Ada","authoredDate":"2026-08-01","committedDate":"2026-08-02",
                "webUrl":"https://gitlab.test/group/repo/-/commit/abcdef"
            }}),
            WholeRenderer::CommitList => json!({"commits":[{
                "id":"abcdef","shortId":"abcdef","title":"Title","message":"message\n```collision",
                "authorName":"Ada","authoredDate":"2026-08-01","committedDate":"2026-08-02",
                "webUrl":"https://gitlab.test/group/repo/-/commit/abcdef"
            }]}),
            WholeRenderer::Pipeline => json!({"pipeline":{
                "id":50,"iid":5,"projectId":9,"ref":"main","sha":"abcdef","status":"success",
                "source":"push","webUrl":"https://gitlab.test/pipelines/50",
                "createdAt":"2026-08-01","updatedAt":"2026-08-02"
            }}),
            WholeRenderer::PipelineList => json!({"pipelines":[{
                "id":50,"iid":5,"projectId":9,"ref":"main","sha":"abcdef","status":"success",
                "source":"push","webUrl":"https://gitlab.test/pipelines/50",
                "createdAt":"2026-08-01","updatedAt":"2026-08-02"
            }]}),
            WholeRenderer::Job => json!({"job":{
                "id":60,"name":"test","status":"success","stage":"verify","ref":"main",
                "pipelineId":50,"projectId":9,"traceSize":123,"webUrl":"https://gitlab.test/jobs/60",
                "createdAt":"2026-08-01","startedAt":"2026-08-01T01:00:00Z","finishedAt":"2026-08-01T02:00:00Z"
            }}),
            WholeRenderer::JobList => json!({"jobs":[{
                "id":60,"name":"test","status":"success","stage":"verify","ref":"main",
                "pipelineId":50,"projectId":9,"traceSize":123,"webUrl":"https://gitlab.test/jobs/60",
                "createdAt":"2026-08-01","startedAt":"2026-08-01T01:00:00Z","finishedAt":"2026-08-01T02:00:00Z"
            }]}),
        }
    }

    fn gitlab_approval_rule_fixture() -> Value {
        json!({
            "id":81,"name":"Security","ruleType":"regular","approvalsRequired":2,
            "approved":false,"eligibleApprovers":[gitlab_user_fixture()],
            "approvedBy":[gitlab_user_fixture()],"users":[gitlab_user_fixture()],
            "groups":[{"id":7,"name":"Security","path":"security","fullPath":"group/security"}],
            "overridden":true,"containsHiddenGroups":false,"codeOwner":true,
            "section":"Backend","sourceRule":{"approvalsRequired":3}
        })
    }

    fn assert_gitlab_whole_semantics(renderer: WholeRenderer, markdown: &str) {
        let expected: &[&str] = match renderer {
            WholeRenderer::NativeSearch => &[
                "GitLab search",
                "group/repo",
                "Found",
                "Preview",
                "Continuation",
                "opaque-token",
            ],
            WholeRenderer::Project => &[
                "Project ID",
                "Path",
                "Default branch",
                "Name",
                "Visibility",
                "Archived",
                "URL",
            ],
            WholeRenderer::Issue | WholeRenderer::IssueList => &[
                "Issue ID",
                "Issue IID",
                "Project ID",
                "Project",
                "Created",
                "Updated",
                "State",
                "URL",
                "Author",
                "Assignees",
                "Labels",
                "Milestone",
                "ID",
                "IID",
                "state",
                "due",
                "Description",
            ],
            WholeRenderer::Note
            | WholeRenderer::NoteList
            | WholeRenderer::Discussion
            | WholeRenderer::DiscussionList => &[
                "Noteable IID",
                "Noteable ID",
                "Project ID",
                "Author user ID",
                "Author username",
                "Commit ID",
                "Created",
                "Updated",
                "Note type",
                "Noteable type",
                "Resolved",
                "Resolvable",
                "System",
                "Confidential",
                "Resolved by",
                "Resolved at",
                "Position type",
                "Base SHA",
                "Start SHA",
                "Head SHA",
                "Old path",
                "New path",
                "Old line",
                "New line",
                "Range start",
                "Range end",
                "Suggestion ID",
                "Applicable",
                "Applied",
                "Source",
                "Replacement",
                "Body",
            ],
            WholeRenderer::DraftNote | WholeRenderer::DraftNoteList => &[
                "Draft note ID",
                "Author user ID",
                "Merge request ID",
                "Discussion ID",
                "Commit ID",
                "Resolve discussion",
                "Position type",
                "Base SHA",
                "Start SHA",
                "Head SHA",
                "Old path",
                "New path",
                "Old line",
                "New line",
                "Range start",
                "Range end",
                "Body",
            ],
            WholeRenderer::MergeRequest | WholeRenderer::MergeRequestList => &[
                "Merge request ID",
                "Merge request IID",
                "Project ID",
                "Source project ID",
                "Target project ID",
                "Project",
                "Source branch",
                "Target branch",
                "SHA",
                "Squash commit SHA",
                "Merge commit SHA",
                "Changes count",
                "User notes count",
                "Prepared",
                "Created",
                "Updated",
                "State",
                "Merge status",
                "Detailed merge status",
                "Draft",
                "Discussion locked",
                "Blocking discussions resolved",
                "Has conflicts",
                "Diff base SHA",
                "Diff start SHA",
                "Diff head SHA",
                "URL",
                "Author",
                "Assignees",
                "Reviewers",
                "Labels",
                "Milestone",
                "Description",
            ],
            WholeRenderer::ReviewerList => &["User", "Assigned", "Reviewer state"],
            WholeRenderer::Approval => &[
                "Approvals required",
                "Approvals left",
                "Aggregate approved",
                "Acting user has approved",
                "Acting user can approve",
                "Approved by",
                "Approved at",
                "User",
            ],
            WholeRenderer::ApprovalState => &[
                "Approval rules overwritten",
                "Rule count",
                "Approval rule",
                "Approvals required",
                "Eligible approvers",
                "Approved by",
                "Code owner",
                "Source rule approvals required",
            ],
            WholeRenderer::ApprovalRule | WholeRenderer::ApprovalRuleList => &[
                "Approval rule",
                "Rule ID",
                "Name",
                "Rule type",
                "Approvals required",
                "Approved",
                "Overridden",
                "Contains hidden groups",
                "Code owner",
                "Section",
                "Eligible approvers",
                "Approved by",
                "Users",
                "Groups",
                "Source rule approvals required",
            ],
            WholeRenderer::MergeRequestCommitList => &[
                "Short ID",
                "Authored",
                "Committed",
                "Author",
                "URL",
                "Message",
            ],
            WholeRenderer::MergeRequestPipelineList => &[
                "Pipeline ID",
                "Pipeline IID",
                "Project ID",
                "Ref",
                "SHA",
                "Created",
                "Updated",
                "Status",
                "Source",
                "URL",
            ],
            WholeRenderer::DiffList => &[
                "Old path",
                "New path",
                "Old mode",
                "New mode",
                "New file",
                "Renamed file",
                "Deleted file",
                "Generated file",
                "Collapsed",
                "Too large",
                "Patch",
            ],
            WholeRenderer::DiffVersionList => &[
                "Diff version ID",
                "Merge request ID",
                "Head commit SHA",
                "Base commit SHA",
                "Start commit SHA",
                "Patch ID SHA",
                "Created",
                "Real size",
                "State",
            ],
            WholeRenderer::DiffVersion => &[
                "Diff version ID",
                "Merge request ID",
                "Head commit SHA",
                "Base commit SHA",
                "Start commit SHA",
                "Patch ID SHA",
                "Created",
                "Real size",
                "State",
                "Commit count",
                "Diff count",
                "Message",
                "Patch",
            ],
            WholeRenderer::Branch | WholeRenderer::BranchList => &[
                "Merged",
                "Protected",
                "Default",
                "URL",
                "Commit",
                "ID",
                "Short ID",
                "Title",
            ],
            WholeRenderer::ProtectedBranch | WholeRenderer::ProtectedBranchList => &[
                "Rule ID",
                "Allow force push",
                "Code-owner approval required",
                "Inherited",
                "Push access levels",
                "Merge access levels",
                "Unprotect access levels",
                "Maintainers",
                "user ID",
                "group ID",
                "deploy key ID",
            ],
            WholeRenderer::ProtectedBranchVerify => &[
                "Project",
                "Project ID",
                "Default branch",
                "Check count",
                "Pattern",
                "Covered",
                "Matched rule",
                "Push access levels",
                "Merge access levels",
            ],
            WholeRenderer::File => &[
                "File name",
                "File path",
                "Size",
                "Encoding",
                "Content SHA-256",
                "Ref",
                "Blob ID",
                "Commit ID",
                "Last commit ID",
                "Executable",
                "Content (base64)",
            ],
            WholeRenderer::Commit | WholeRenderer::CommitList => &[
                "Short ID",
                "Authored",
                "Committed",
                "Author",
                "URL",
                "Message",
            ],
            WholeRenderer::Pipeline | WholeRenderer::PipelineList => &[
                "Pipeline ID",
                "Pipeline IID",
                "Project ID",
                "Ref",
                "SHA",
                "Created",
                "Updated",
                "Status",
                "Source",
                "URL",
            ],
            WholeRenderer::Job | WholeRenderer::JobList => &[
                "Job ID",
                "Ref",
                "Pipeline ID",
                "Project ID",
                "Trace size",
                "Created",
                "Started",
                "Finished",
                "Status",
                "Stage",
                "URL",
            ],
        };
        for field in expected {
            assert!(
                markdown.contains(field),
                "missing {field:?} from {renderer:?}: {markdown}"
            );
        }
        if matches!(
            renderer,
            WholeRenderer::IssueList
                | WholeRenderer::MergeRequestList
                | WholeRenderer::NoteList
                | WholeRenderer::ReviewerList
                | WholeRenderer::MergeRequestCommitList
                | WholeRenderer::MergeRequestPipelineList
                | WholeRenderer::DiffList
                | WholeRenderer::DiffVersionList
                | WholeRenderer::DiscussionList
                | WholeRenderer::DraftNoteList
                | WholeRenderer::ApprovalRuleList
        ) {
            for field in ["Count", "Maximum results", "Last page"] {
                assert!(markdown.contains(field), "missing {field:?}: {markdown}");
            }
        }
        if renderer == WholeRenderer::IssueList {
            assert!(markdown.contains("Next page token"));
        }
        if matches!(
            renderer,
            WholeRenderer::Discussion | WholeRenderer::DiscussionList
        ) {
            assert!(markdown.contains("Individual note"));
            assert!(markdown.contains("Note count"));
        }
    }

    #[test]
    fn gitlab_embedded_rendering_is_exact_and_uses_declared_nested_owners() {
        let native = "# heading\n\n<script>bad()</script>";
        let mut issues = json!({"issues":[gitlab_issue_fixture()]});
        issues["issues"][0]["description"] = json!(native);
        present_provider_result(
            "issue.search",
            &mut issues,
            ResponseOptions::new(ReadContentFormat::Markdown, ResponseFormat::Json),
            4096,
            16384,
        )
        .unwrap();
        assert_eq!(issues["issues"][0]["description"], native);
        assert_eq!(issues["issues"][0]["renderedBody"]["value"], native);

        let mut discussions = json!({"discussions":[{
            "id":"d1","individualNote":false,"notes":[gitlab_note_fixture(),gitlab_note_fixture()]
        }]});
        present_provider_result(
            "merge_request.discussion.list",
            &mut discussions,
            ResponseOptions::new(ReadContentFormat::Text, ResponseFormat::Json),
            4096,
            16384,
        )
        .unwrap();
        for note in discussions["discussions"][0]["notes"].as_array().unwrap() {
            assert_eq!(note["renderedBody"]["format"], "text");
            assert!(
                !note["renderedBody"]["value"]
                    .as_str()
                    .unwrap()
                    .contains("<script>")
            );
        }

        let mut discussion = json!({"discussion":{
            "id":"d1","individualNote":false,"notes":[gitlab_note_fixture()]
        }});
        present_provider_result(
            "merge_request.discussion.view",
            &mut discussion,
            ResponseOptions::new(ReadContentFormat::Markdown, ResponseFormat::Json),
            4096,
            16384,
        )
        .unwrap();
        assert_eq!(
            discussion["discussion"]["notes"][0]["renderedBody"]["format"],
            "markdown"
        );
        assert_eq!(
            discussion["discussion"]["notes"][0]["position"]["newLine"],
            34
        );

        let mut empty = json!({"issue":{
            "iid":1,"projectId":9,"project":"group/repo","description":""
        }});
        let mut empty_whole = json!({"issue":{
            "iid":1,"projectId":9,"project":"group/repo","description":""
        }});
        present_provider_result(
            "issue.view",
            &mut empty,
            ResponseOptions::new(ReadContentFormat::Markdown, ResponseFormat::Json),
            4096,
            16384,
        )
        .unwrap();
        assert_eq!(empty["issue"]["renderedBody"]["value"], "");

        present_provider_result(
            "issue.view",
            &mut empty_whole,
            ResponseOptions::new(ReadContentFormat::Native, ResponseFormat::Markdown),
            4096,
            16384,
        )
        .unwrap();
        let markdown = empty_whole["value"].as_str().unwrap();
        let (_, after_description) = markdown
            .rsplit_once("## Description")
            .unwrap_or_else(|| panic!("missing empty Description section: {markdown:?}"));
        assert_eq!(
            after_description, "\n",
            "empty body must leave one empty Description section: {markdown:?}"
        );
        assert_eq!(markdown.matches("## Description").count(), 1);
        assert!(markdown.ends_with('\n'));
        assert!(!markdown.ends_with("\n\n"));
        assert!(!markdown.contains("No content."));
    }

    #[test]
    fn gitlab_summary_collections_treat_read_content_format_as_a_no_op() {
        for format in [ReadContentFormat::Text, ReadContentFormat::Markdown] {
            for (action, source, _) in gitlab_summary_collection_fixtures() {
                let mut result = source.clone();
                present_provider_result(
                    action,
                    &mut result,
                    ResponseOptions::new(format, ResponseFormat::Json),
                    4096,
                    65536,
                )
                .unwrap_or_else(|error| panic!("{action} with {format:?}: {error:?}"));
                assert_eq!(result, source, "{action} with {format:?}");
                assert_gitlab_summary_has_no_rich_content(&result);
            }
        }
    }

    #[test]
    fn gitlab_summary_collections_render_body_free_markdown() {
        for (action, mut result, item_heading) in gitlab_summary_collection_fixtures() {
            present_provider_result(
                action,
                &mut result,
                ResponseOptions::new(ReadContentFormat::Native, ResponseFormat::Markdown),
                4096,
                65536,
            )
            .unwrap_or_else(|error| panic!("{action}: {error:?}"));
            assert_eq!(result["format"], "markdown", "{action}");
            let markdown = result["value"].as_str().unwrap();
            assert!(
                markdown.contains("- Projection: summary"),
                "{action}: {markdown}"
            );
            assert!(markdown.contains(item_heading), "{action}: {markdown}");
            for forbidden in [
                "## Body",
                "### Body",
                "#### Body",
                "Suggestion",
                "suggestion",
                "renderedBody",
            ] {
                assert!(
                    !markdown.contains(forbidden),
                    "{action} leaked {forbidden:?}: {markdown}"
                );
            }
        }
    }

    #[test]
    fn gitlab_m2_embedded_rendering_preserves_verified_results_and_exact_owners() {
        let mut inline = json!({
            "mutationStatus":"applied","retrySafe":false,
            "discussionId":"discussion-1","noteId":30,
            "discussion":{"id":"discussion-1","individualNote":false,"notes":[gitlab_note_fixture()]}
        });
        present_provider_result(
            "merge_request.discussion.inline.add",
            &mut inline,
            ResponseOptions::new(ReadContentFormat::Text, ResponseFormat::Json),
            4096,
            65536,
        )
        .unwrap();
        assert_eq!(inline["mutationStatus"], "applied");
        assert_eq!(inline["retrySafe"], false);
        assert_eq!(inline["discussionId"], "discussion-1");
        assert_eq!(inline["noteId"], 30);
        assert_eq!(
            inline["discussion"]["notes"][0]["position"]["headSha"],
            "head"
        );
        assert_eq!(inline["discussion"]["notes"][0]["suggestions"][0]["id"], 91);
        assert_eq!(
            inline["discussion"]["notes"][0]["renderedBody"]["format"],
            "text"
        );
        assert!(
            !inline["discussion"]["notes"][0]["renderedBody"]["value"]
                .as_str()
                .unwrap()
                .contains("<script>")
        );

        let mut reply = json!({
            "mutationStatus":"applied","retrySafe":false,
            "discussionId":"discussion-1","noteId":30,"note":gitlab_note_fixture()
        });
        present_provider_result(
            "merge_request.discussion.note.add",
            &mut reply,
            ResponseOptions::new(ReadContentFormat::Markdown, ResponseFormat::Json),
            4096,
            65536,
        )
        .unwrap();
        assert_eq!(reply["note"]["renderedBody"]["format"], "markdown");
        assert_eq!(reply["note"]["position"]["newPath"], "src/new.rs");

        let mut drafts = json!({
            "draftNotes":[gitlab_draft_note_fixture()],"count":1,"maxResults":20,
            "isLast":true,"nextPageToken":null
        });
        present_provider_result(
            "merge_request.draft_note.list",
            &mut drafts,
            ResponseOptions::new(ReadContentFormat::Text, ResponseFormat::Json),
            4096,
            65536,
        )
        .unwrap();
        assert_eq!(drafts["draftNotes"][0]["renderedBody"]["format"], "text");
        assert_eq!(
            drafts["draftNotes"][0]["position"]["headSha"],
            "historical-head"
        );
        assert_eq!(drafts["count"], 1);

        let mut view = json!({"draftNote":gitlab_draft_note_fixture()});
        present_provider_result(
            "merge_request.draft_note.view",
            &mut view,
            ResponseOptions::new(ReadContentFormat::Markdown, ResponseFormat::Json),
            4096,
            65536,
        )
        .unwrap();
        assert_eq!(view["draftNote"]["renderedBody"]["format"], "markdown");
        assert_eq!(view["draftNote"]["position"]["headSha"], "historical-head");

        let mut unpositioned = gitlab_draft_note_fixture();
        unpositioned["position"] = Value::Null;
        for (action, mut result, pointer) in [
            (
                "merge_request.draft_note.list",
                json!({
                    "draftNotes":[unpositioned.clone()],"count":1,"maxResults":20,
                    "isLast":true,"nextPageToken":null
                }),
                "/draftNotes/0",
            ),
            (
                "merge_request.draft_note.view",
                json!({"draftNote":unpositioned.clone()}),
                "/draftNote",
            ),
        ] {
            present_provider_result(
                action,
                &mut result,
                ResponseOptions::new(ReadContentFormat::Text, ResponseFormat::Json),
                4096,
                65536,
            )
            .unwrap();
            let draft = result.pointer(pointer).unwrap();
            assert!(draft["position"].is_null());
            assert_eq!(draft["renderedBody"]["format"], "text");
            assert!(draft["renderedBody"]["value"].is_string());
        }

        for action in [
            "merge_request.draft_note.add",
            "merge_request.draft_note.update",
        ] {
            let mut result = json!({
                "mutationStatus":"applied","retrySafe":false,"draftNoteId":77,
                "draftNote":gitlab_draft_note_fixture()
            });
            present_provider_result(
                action,
                &mut result,
                ResponseOptions::new(ReadContentFormat::Markdown, ResponseFormat::Json),
                4096,
                65536,
            )
            .unwrap_or_else(|error| panic!("{action}: {error:?}"));
            assert_eq!(result["draftNoteId"], 77, "{action}");
            assert_eq!(result["draftNote"]["id"], 77, "{action}");
            assert_eq!(
                result["draftNote"]["renderedBody"]["format"], "markdown",
                "{action}"
            );
            assert_eq!(
                result["draftNote"]["position"]["lineRange"]["end"]["newLine"], 35,
                "{action}"
            );
        }
    }

    #[test]
    fn gitlab_m2_bodyless_verified_results_remain_exact_bounded_json() {
        for (action, source) in [
            (
                "merge_request.draft_note.delete",
                json!({
                    "mutationStatus":"applied","retrySafe":false,
                    "draftNoteId":77,"deleted":true
                }),
            ),
            (
                "merge_request.draft_note.publish",
                json!({
                    "mutationStatus":"applied","retrySafe":false,
                    "draftNoteId":77,"published":true
                }),
            ),
            (
                "merge_request.draft_note.publish_all",
                json!({
                    "mutationStatus":"applied","retrySafe":false,
                    "publishedDraftNoteIds":[77,78],"summaryNoteId":30
                }),
            ),
            (
                "merge_request.review.submit",
                json!({
                    "mutationStatus":"applied","retrySafe":false,
                    "publishedDraftNoteIds":[77,78],"summaryNoteId":30,
                    "reviewerState":"requested_changes"
                }),
            ),
        ] {
            let mut result = source.clone();
            present_provider_result(action, &mut result, ResponseOptions::default(), 4096, 65536)
                .unwrap_or_else(|error| panic!("{action}: {error:?}"));
            assert_eq!(result, source, "{action}");
            assert_eq!(result["mutationStatus"], "applied", "{action}");
            assert_eq!(result["retrySafe"], false, "{action}");

            let exact = serde_json::to_vec(&source).unwrap().len() as u64;
            let mut exactly_bounded = source.clone();
            present_provider_result(
                action,
                &mut exactly_bounded,
                ResponseOptions::default(),
                4096,
                exact,
            )
            .unwrap_or_else(|error| panic!("exact bound {action}: {error:?}"));
            assert_eq!(exactly_bounded, source, "{action}");

            let mut too_small = source;
            let error = present_provider_result(
                action,
                &mut too_small,
                ResponseOptions::default(),
                4096,
                exact - 1,
            )
            .unwrap_err();
            assert_eq!(error.reason_code(), ReasonCode::UpstreamProtocolFailed);
            assert_eq!(error.message, RENDER_FAILURE_MESSAGE);
        }
    }

    #[test]
    fn every_gitlab_whole_template_is_complete_bounded_and_has_one_terminal_lf() {
        for descriptor in RESULT_DESCRIPTORS
            .iter()
            .filter(|descriptor| descriptor.whole.is_some())
        {
            let renderer = descriptor.whole.unwrap();
            let source = gitlab_whole_fixture(renderer);
            let mut result = source.clone();
            present_provider_result(
                descriptor.action,
                &mut result,
                ResponseOptions::new(ReadContentFormat::Native, ResponseFormat::Markdown),
                4096,
                65536,
            )
            .unwrap_or_else(|error| panic!("{}: {error:?}", descriptor.action));
            let markdown = result["value"].as_str().unwrap();
            assert!(markdown.ends_with('\n'), "{}", descriptor.action);
            assert!(!markdown.ends_with("\n\n"), "{}", descriptor.action);
            assert!(!markdown.contains("<script>"), "{}", descriptor.action);
            assert_gitlab_whole_semantics(renderer, markdown);

            let exact = serde_json::to_vec(&result).unwrap().len() as u64;
            let mut exactly_bounded = source;
            present_provider_result(
                descriptor.action,
                &mut exactly_bounded,
                ResponseOptions::new(ReadContentFormat::Native, ResponseFormat::Markdown),
                4096,
                exact,
            )
            .unwrap_or_else(|error| panic!("exact bound {}: {error:?}", descriptor.action));
            assert_eq!(exactly_bounded, result, "{}", descriptor.action);
        }
    }

    #[test]
    fn gitlab_whole_templates_preserve_sensitive_literals_and_fail_atomically() {
        let mut file = gitlab_whole_fixture(WholeRenderer::File);
        present_provider_result(
            "file.view",
            &mut file,
            ResponseOptions::new(ReadContentFormat::Native, ResponseFormat::Markdown),
            4096,
            16384,
        )
        .unwrap();
        let markdown = file["value"].as_str().unwrap();
        assert!(markdown.contains("````base64\nYWJj```ZA==\n````"));

        let mut commit = gitlab_whole_fixture(WholeRenderer::Commit);
        present_provider_result(
            "commit.view",
            &mut commit,
            ResponseOptions::new(ReadContentFormat::Native, ResponseFormat::Markdown),
            4096,
            16384,
        )
        .unwrap();
        assert!(
            commit["value"]
                .as_str()
                .unwrap()
                .contains("````text\nmessage\n```collision\n````")
        );

        for mut malformed in [
            json!({"issue":{"iid":1,"projectId":9,"description":5}}),
            json!({"discussions":[{"id":"d","notes":{}}]}),
        ] {
            let action = if malformed.get("issue").is_some() {
                "issue.view"
            } else {
                "merge_request.discussion.list"
            };
            let error = present_provider_result(
                action,
                &mut malformed,
                ResponseOptions::new(ReadContentFormat::Native, ResponseFormat::Markdown),
                4096,
                16384,
            )
            .unwrap_err();
            assert_eq!(error.reason_code(), ReasonCode::UpstreamProtocolFailed);
            assert_eq!(error.message, RENDER_FAILURE_MESSAGE);
        }

        let mut too_large = gitlab_whole_fixture(WholeRenderer::Issue);
        let error = present_provider_result(
            "issue.view",
            &mut too_large,
            ResponseOptions::new(ReadContentFormat::Native, ResponseFormat::Markdown),
            4096,
            16,
        )
        .unwrap_err();
        assert_eq!(error.reason_code(), ReasonCode::UpstreamProtocolFailed);
        assert_eq!(error.message, RENDER_FAILURE_MESSAGE);
    }

    #[test]
    fn gitlab_body_lists_emit_pagination_after_all_returned_content() {
        for (action, renderer, item_marker) in [
            ("issue.search", WholeRenderer::IssueList, "## Issue "),
            (
                "merge_request.search",
                WholeRenderer::MergeRequestList,
                "## Merge request ",
            ),
            ("issue.note.list", WholeRenderer::NoteList, "## Note "),
            (
                "merge_request.draft_note.list",
                WholeRenderer::DraftNoteList,
                "## Draft note ",
            ),
        ] {
            let mut result = gitlab_whole_fixture(renderer);
            present_provider_result(
                action,
                &mut result,
                ResponseOptions::new(ReadContentFormat::Native, ResponseFormat::Markdown),
                4096,
                65536,
            )
            .unwrap();
            let markdown = result["value"].as_str().unwrap();
            let pagination = markdown.rfind("## Pagination").unwrap();
            assert!(markdown.find("- Count:").unwrap() < pagination, "{action}");
            assert!(
                markdown.rfind(item_marker).unwrap() < pagination,
                "{action}"
            );
            assert_eq!(markdown.matches("## Pagination").count(), 1, "{action}");
        }
    }

    #[test]
    fn gitlab_large_fenced_literals_use_chunked_presentation_work() {
        let literal = "a".repeat(MAX_PRESENTATION_WORK_UNITS + 1);
        let max_result_bytes = literal.len() as u64 + 8192;
        for (action, mut result) in [
            (
                "file.view",
                json!({"file":{"filePath":"large.bin","contentBase64":literal}}),
            ),
            (
                "commit.view",
                json!({"commit":{"id":"abcdef","message":literal}}),
            ),
            (
                "merge_request.diff.list",
                json!({
                    "diffs":[{"oldPath":"large.txt","newPath":"large.txt","diff":literal}],
                    "count":1,"maxResults":20,"isLast":true,"nextPageToken":null
                }),
            ),
        ] {
            present_provider_result(
                action,
                &mut result,
                ResponseOptions::new(ReadContentFormat::Native, ResponseFormat::Markdown),
                max_result_bytes,
                max_result_bytes,
            )
            .unwrap_or_else(|error| panic!("{action}: {error:?}"));
            assert!(result["value"].as_str().unwrap().contains(&literal));
        }
    }

    #[test]
    fn gitlab_commit_messages_normalize_line_endings_and_unsafe_controls() {
        let mut result = json!({"commit":{
            "id":"abcdef",
            "message":"first\r\nsecond\rthird\tkept\u{0}unsafe\u{7f}"
        }});
        present_provider_result(
            "commit.view",
            &mut result,
            ResponseOptions::new(ReadContentFormat::Native, ResponseFormat::Markdown),
            4096,
            16384,
        )
        .unwrap();
        let markdown = result["value"].as_str().unwrap();
        assert!(markdown.contains("text\nfirst\nsecond\nthird\tkept unsafe \n"));
        assert!(!markdown.contains('\r'));
        assert!(!markdown.contains('\0'));
        assert!(!markdown.contains('\u{7f}'));
    }

    #[test]
    fn gitlab_whole_body_headings_are_demoted_below_template_sections() {
        let body = "# Provider heading\n\n## Secondary provider heading\n\n###### Deep heading";
        let mut issue_view = gitlab_whole_fixture(WholeRenderer::Issue);
        issue_view["issue"]["description"] = json!(body);
        let mut issue_search = gitlab_whole_fixture(WholeRenderer::IssueList);
        issue_search["issues"][0]["description"] = json!(body);
        let mut note_list = gitlab_whole_fixture(WholeRenderer::NoteList);
        note_list["notes"][0]["body"] = json!(body);
        let mut discussion_list = gitlab_whole_fixture(WholeRenderer::DiscussionList);
        discussion_list["discussions"][0]["notes"][0]["body"] = json!(body);
        let mut draft_view = gitlab_whole_fixture(WholeRenderer::DraftNote);
        draft_view["draftNote"]["body"] = json!(body);
        let mut draft_list = gitlab_whole_fixture(WholeRenderer::DraftNoteList);
        draft_list["draftNotes"][0]["body"] = json!(body);
        for (action, mut result, section_label) in [
            ("issue.view", issue_view, "Description"),
            ("issue.search", issue_search, "Description"),
            ("issue.note.list", note_list, "Body"),
            ("merge_request.discussion.list", discussion_list, "Body"),
            ("merge_request.draft_note.view", draft_view, "Body"),
            ("merge_request.draft_note.list", draft_list, "Body"),
        ] {
            present_provider_result(
                action,
                &mut result,
                ResponseOptions::new(ReadContentFormat::Native, ResponseFormat::Markdown),
                4096,
                16384,
            )
            .unwrap_or_else(|error| panic!("{action}: {error:?}"));
            let markdown = result["value"].as_str().unwrap();
            let heading_level = |label: &str| {
                markdown
                    .lines()
                    .find_map(|line| {
                        let marker = line.strip_suffix(label)?.strip_suffix(' ')?;
                        marker
                            .bytes()
                            .all(|byte| byte == b'#')
                            .then_some(marker.len())
                    })
                    .unwrap_or_else(|| panic!("{action}: missing heading {label:?}: {markdown}"))
            };
            let section_level = heading_level(section_label);
            for body_heading in [
                "Provider heading",
                "Secondary provider heading",
                "Deep heading",
            ] {
                assert!(
                    heading_level(body_heading) > section_level,
                    "{action}: body heading {body_heading:?} must be below {section_label:?}: {markdown}"
                );
            }
        }
    }

    #[test]
    fn gitlab_whole_lists_render_explicit_empty_collections() {
        for (action, mut result) in [
            (
                "issue.search",
                json!({"issues":[],"count":0,"maxResults":20,"isLast":true,"nextPageToken":null}),
            ),
            (
                "issue.note.list",
                json!({"notes":[],"count":0,"maxResults":20,"isLast":true,"nextPageToken":null}),
            ),
            (
                "merge_request.search",
                json!({"mergeRequests":[],"count":0,"maxResults":20,"isLast":true,"nextPageToken":null}),
            ),
            (
                "merge_request.note.list",
                json!({"notes":[],"count":0,"maxResults":20,"isLast":true,"nextPageToken":null}),
            ),
            (
                "merge_request.discussion.list",
                json!({"discussions":[],"count":0,"maxResults":20,"isLast":true,"nextPageToken":null}),
            ),
            (
                "merge_request.reviewer.list",
                json!({"reviewers":[],"count":0,"maxResults":20,"isLast":true,"nextPageToken":null}),
            ),
            (
                "merge_request.commit.list",
                json!({"commits":[],"count":0,"maxResults":20,"isLast":true,"nextPageToken":null}),
            ),
            (
                "merge_request.pipeline.list",
                json!({"pipelines":[],"count":0,"maxResults":20,"isLast":true,"nextPageToken":null}),
            ),
            (
                "merge_request.diff.list",
                json!({"diffs":[],"count":0,"maxResults":20,"isLast":true,"nextPageToken":null}),
            ),
            (
                "merge_request.diff_version.list",
                json!({"diffVersions":[],"count":0,"maxResults":20,"isLast":true,"nextPageToken":null}),
            ),
            (
                "merge_request.draft_note.list",
                json!({"draftNotes":[],"count":0,"maxResults":20,"isLast":true,"nextPageToken":null}),
            ),
            ("branch.list", json!({"branches":[]})),
            ("protected_branch.list", json!({"protectedBranches":[]})),
            ("commit.list", json!({"commits":[]})),
            ("pipeline.list", json!({"pipelines":[]})),
            ("job.list", json!({"jobs":[]})),
        ] {
            present_provider_result(
                action,
                &mut result,
                ResponseOptions::new(ReadContentFormat::Native, ResponseFormat::Markdown),
                4096,
                16384,
            )
            .unwrap_or_else(|error| panic!("{action}: {error:?}"));
            assert!(
                result["value"].as_str().unwrap().contains("No results."),
                "{action}: {}",
                result["value"]
            );
        }

        let mut no_notes = json!({"discussions":[{
            "id":"discussion-1","individualNote":false,"notes":[]
        }],"count":1,"maxResults":20,"isLast":true,"nextPageToken":null});
        present_provider_result(
            "merge_request.discussion.list",
            &mut no_notes,
            ResponseOptions::new(ReadContentFormat::Native, ResponseFormat::Markdown),
            4096,
            16384,
        )
        .unwrap();
        assert!(no_notes["value"].as_str().unwrap().contains("No notes."));
    }

    #[test]
    fn gitlab_review_markdown_preserves_exact_anchor_and_collision_safe_literals() {
        let mut result = gitlab_whole_fixture(WholeRenderer::Discussion);
        present_provider_result(
            "merge_request.discussion.view",
            &mut result,
            ResponseOptions::new(ReadContentFormat::Native, ResponseFormat::Markdown),
            4096,
            65536,
        )
        .unwrap();
        let markdown = result["value"].as_str().unwrap();
        for exact in [
            "`DiffNote`",
            "`commit`",
            "`base`",
            "`start`",
            "`head`",
            "`src/old.rs`",
            "`src/new.rs`",
            "`31`",
            "`34`",
            "`path_31_34`",
            "`path_32_35`",
            "`91`",
        ] {
            assert!(markdown.contains(exact), "missing {exact:?}: {markdown}");
        }
        assert!(markdown.contains("````text\nold\n```collision\n````"));

        let mut diffs = gitlab_whole_fixture(WholeRenderer::DiffList);
        present_provider_result(
            "merge_request.diff.list",
            &mut diffs,
            ResponseOptions::new(ReadContentFormat::Native, ResponseFormat::Markdown),
            4096,
            65536,
        )
        .unwrap();
        assert!(
            diffs["value"]
                .as_str()
                .unwrap()
                .contains("````diff\n@@ -31 +34 @@\n-old\n+```new\n````")
        );
    }

    #[test]
    fn gitlab_review_markdown_preserves_image_coordinates() {
        let mut result = gitlab_whole_fixture(WholeRenderer::Discussion);
        result["discussion"]["notes"][0]["position"] = json!({
            "positionType":"image",
            "baseSha":"base",
            "startSha":"start",
            "headSha":"head",
            "oldPath":"diagram-old.png",
            "newPath":"diagram.png",
            "width":640,
            "height":480,
            "x":12,
            "y":24
        });
        present_provider_result(
            "merge_request.discussion.view",
            &mut result,
            ResponseOptions::new(ReadContentFormat::Native, ResponseFormat::Markdown),
            4096,
            65536,
        )
        .unwrap();
        let markdown = result["value"].as_str().unwrap();
        for exact in [
            "Position type: `image`",
            "Image width: `640`",
            "Image height: `480`",
            "Image x: `12`",
            "Image y: `24`",
        ] {
            assert!(markdown.contains(exact), "missing {exact:?}: {markdown}");
        }
    }

    #[test]
    fn gitlab_review_markdown_omits_nullable_position_metadata_without_null_literals() {
        let mut result = json!({"discussion":{
            "id":"discussion-optional-position",
            "individualNote":false,
            "notes":[gitlab_nullable_position_note_fixture()]
        }});
        present_provider_result(
            "merge_request.discussion.view",
            &mut result,
            ResponseOptions::new(ReadContentFormat::Native, ResponseFormat::Markdown),
            4096,
            65536,
        )
        .unwrap();
        let markdown = result["value"].as_str().unwrap();
        for exact in [
            "Start SHA: `start`",
            "Head SHA: `head`",
            "Range start: line code `path_31_34`; old line `31`; new line `34`",
            "Range end: line code `path_32_35`; type `new`; new line `35`",
        ] {
            assert!(markdown.contains(exact), "missing {exact:?}: {markdown}");
        }
        assert!(!markdown.contains("Base SHA:"), "{markdown}");
        assert!(!markdown.contains("null"), "{markdown}");
    }

    #[test]
    fn gitlab_draft_markdown_exposes_historical_position_and_omits_nullable_fields() {
        let mut result = gitlab_whole_fixture(WholeRenderer::DraftNote);
        present_provider_result(
            "merge_request.draft_note.view",
            &mut result,
            ResponseOptions::new(ReadContentFormat::Native, ResponseFormat::Markdown),
            4096,
            65536,
        )
        .unwrap();
        let markdown = result["value"].as_str().unwrap();
        for exact in [
            "Draft note `77`",
            "Discussion ID: ``discussion`id``",
            "Commit ID: `historical-head`",
            "Head SHA: `historical-head`",
            "Old path: `src/old.rs`",
            "New path: `src/new.rs`",
            "Range start: line code `path_31_34`; type `old`; old line `31`; new line `34`",
            "Range end: line code `path_32_35`; type `new`; new line `35`",
            "## Body",
        ] {
            assert!(markdown.contains(exact), "missing {exact:?}: {markdown}");
        }
        assert!(!markdown.contains("<script>"), "{markdown}");

        let mut draft = gitlab_draft_note_fixture();
        for key in [
            "body",
            "authorUserId",
            "mergeRequestId",
            "resolveDiscussion",
            "discussionId",
            "commitId",
            "position",
        ] {
            draft[key] = Value::Null;
        }
        let mut nullable = json!({"draftNote":draft});
        present_provider_result(
            "merge_request.draft_note.view",
            &mut nullable,
            ResponseOptions::new(ReadContentFormat::Native, ResponseFormat::Markdown),
            4096,
            65536,
        )
        .unwrap();
        let markdown = nullable["value"].as_str().unwrap();
        assert!(markdown.contains("Draft note `77`"), "{markdown}");
        assert!(!markdown.contains("Body"), "{markdown}");
        assert!(!markdown.contains("null"), "{markdown}");
    }

    #[test]
    fn gitlab_merge_request_markdown_exposes_review_readiness_and_diff_identity() {
        let mut result = gitlab_whole_fixture(WholeRenderer::MergeRequest);
        present_provider_result(
            "merge_request.view",
            &mut result,
            ResponseOptions::new(ReadContentFormat::Native, ResponseFormat::Markdown),
            4096,
            65536,
        )
        .unwrap();
        let markdown = result["value"].as_str().unwrap();
        for exact in [
            "Diff base SHA: `base`",
            "Diff start SHA: `start`",
            "Diff head SHA: `abc`",
            "Changes count: `2`",
            "User notes count: `3`",
            "Blocking discussions resolved: true",
            "Has conflicts: false",
            "Pipeline `50`",
        ] {
            assert!(markdown.contains(exact), "missing {exact:?}: {markdown}");
        }
    }
}

fn render_native_search(
    value: &Value,
    out: &mut MarkdownWriter,
    budget: &mut PresentationBudget,
) -> Result<(), RenderError> {
    let result = as_object(value)?;
    let items = array(required(result, "items")?)?;
    budget.charge_work(result.len().saturating_add(items.len()))?;
    out.push("# GitLab search\n")?;
    if items.is_empty() {
        if result.get("nextPageToken").is_some() {
            out.push("No matching authorized items in this page; continue the search.\n")?;
        } else {
            out.push("No matching authorized items in this page.\n")?;
        }
    }
    for item in items {
        let item = as_object(item)?;
        budget.charge_work(item.len())?;
        out.push("\n## ")?;
        out.push_code(required_scalar(item, "project")?)?;
        if let Some(title) = optional_scalar(item, "title")?
            .or(optional_scalar(item, "name")?)
            .or(optional_scalar(item, "path")?)
        {
            out.push(" — ")?;
            out.push_heading_text(title)?;
        }
        out.push("\n")?;
        for (name, label) in [
            ("id", "ID"),
            ("iid", "IID"),
            ("state", "State"),
            ("parentKind", "Parent"),
            ("ref", "Ref"),
            ("startLine", "Starting line"),
        ] {
            if let Some(value) = optional_display(item, name)? {
                field_code(out, label, &value)?;
            }
        }
        if let Some(url) = optional_scalar(item, "webUrl")? {
            field_url(out, "URL", url)?;
        }
        for name in [
            "description",
            "descriptionPreview",
            "messagePreview",
            "bodyPreview",
            "snippet",
        ] {
            if let Some(text) = optional_scalar(item, name)? {
                if name == "snippet" {
                    out.push("\nUpstream snippet:\n\n")?;
                } else {
                    out.push("\n")?;
                }
                out.push_escaped(text)?;
                out.push("\n")?;
            }
        }
        if item.get("previewTruncated").and_then(Value::as_bool) == Some(true) {
            out.push("\nPreview truncated.\n")?;
        }
    }
    if result.get("scanStatus").and_then(Value::as_str) == Some("upstream_window") {
        out.push("\nSearch coverage is incomplete: the upstream retrieval window was reached.\n")?;
    }
    if let Some(token) = optional_scalar(result, "nextPageToken")? {
        out.push("\nContinuation (another authorized match is not guaranteed):\n\n")?;
        out.push_code(token)?;
        out.push("\n")?;
    }
    Ok(())
}
