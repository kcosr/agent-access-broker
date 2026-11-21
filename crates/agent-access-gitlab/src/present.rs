//! Selected rich-content fields in structured GitLab results.
use agent_access_content::select_gitlab_markdown_bounded_with_budget;
use agent_access_provider::presentation::*;
use serde_json::Value;

const FORMATS: &[OutputContentFormat] = &[OutputContentFormat::Markdown, OutputContentFormat::Text];

const GITLAB_ISSUE_DESCRIPTION: &[EmbeddedBody] = &[EmbeddedBody::new(
    &[BodyPathSegment::Field("issue")],
    "description",
    &GitlabMarkdownBody,
)
.optional()
.nullable()];

const GITLAB_ISSUE_DESCRIPTIONS: &[EmbeddedBody] = &[EmbeddedBody::new(
    &[BodyPathSegment::Field("issues"), BodyPathSegment::Each],
    "description",
    &GitlabMarkdownBody,
)
.optional()
.nullable()];

const GITLAB_MERGE_REQUEST_DESCRIPTION: &[EmbeddedBody] = &[EmbeddedBody::new(
    &[BodyPathSegment::Field("mergeRequest")],
    "description",
    &GitlabMarkdownBody,
)
.optional()
.nullable()];

const GITLAB_MERGE_REQUEST_DESCRIPTIONS: &[EmbeddedBody] = &[EmbeddedBody::new(
    &[
        BodyPathSegment::Field("mergeRequests"),
        BodyPathSegment::Each,
    ],
    "description",
    &GitlabMarkdownBody,
)
.optional()
.nullable()];

const GITLAB_NOTE_BODY: &[EmbeddedBody] = &[EmbeddedBody::new(
    &[BodyPathSegment::Field("note")],
    "body",
    &GitlabMarkdownBody,
)
.optional()
.nullable()];

const GITLAB_NOTE_BODIES: &[EmbeddedBody] = &[EmbeddedBody::new(
    &[BodyPathSegment::Field("notes"), BodyPathSegment::Each],
    "body",
    &GitlabMarkdownBody,
)
.optional()
.nullable()];

const GITLAB_DISCUSSION_NOTES: &[EmbeddedBody] = &[EmbeddedBody::new(
    &[
        BodyPathSegment::Field("discussion"),
        BodyPathSegment::Field("notes"),
        BodyPathSegment::Each,
    ],
    "body",
    &GitlabMarkdownBody,
)
.optional()
.nullable()];

const GITLAB_DISCUSSION_LIST_NOTES: &[EmbeddedBody] = &[EmbeddedBody::new(
    &[
        BodyPathSegment::Field("discussions"),
        BodyPathSegment::Each,
        BodyPathSegment::Field("notes"),
        BodyPathSegment::Each,
    ],
    "body",
    &GitlabMarkdownBody,
)
.optional()
.nullable()];

const GITLAB_DISCUSSION_VIEW_NOTES: &[EmbeddedBody] = &[EmbeddedBody::new(
    &[
        BodyPathSegment::Field("discussion"),
        BodyPathSegment::Field("notes"),
        BodyPathSegment::Each,
    ],
    "body",
    &GitlabMarkdownBody,
)
.optional()
.nullable()];

const GITLAB_DRAFT_NOTE_BODY: &[EmbeddedBody] = &[EmbeddedBody::new(
    &[BodyPathSegment::Field("draftNote")],
    "body",
    &GitlabMarkdownBody,
)
.optional()
.nullable()];

const GITLAB_DRAFT_NOTE_BODIES: &[EmbeddedBody] = &[EmbeddedBody::new(
    &[BodyPathSegment::Field("draftNotes"), BodyPathSegment::Each],
    "body",
    &GitlabMarkdownBody,
)
.optional()
.nullable()];

pub(super) fn presentation(action: &str) -> Option<ActionPresentation> {
    let bodies = match action {
        "issue.view" => GITLAB_ISSUE_DESCRIPTION,
        "issue.search" => GITLAB_ISSUE_DESCRIPTIONS,
        "issue.create" => GITLAB_ISSUE_DESCRIPTION,
        "issue.update" => GITLAB_ISSUE_DESCRIPTION,
        "issue.note.list" => GITLAB_NOTE_BODIES,
        "issue.note.view" => GITLAB_NOTE_BODY,
        "issue.note.add" => GITLAB_NOTE_BODY,
        "issue.note.update" => GITLAB_NOTE_BODY,
        "merge_request.view" => GITLAB_MERGE_REQUEST_DESCRIPTION,
        "merge_request.search" => GITLAB_MERGE_REQUEST_DESCRIPTIONS,
        "merge_request.create" => GITLAB_MERGE_REQUEST_DESCRIPTION,
        "merge_request.update" => GITLAB_MERGE_REQUEST_DESCRIPTION,
        "merge_request.note.list" => GITLAB_NOTE_BODIES,
        "merge_request.note.view" => GITLAB_NOTE_BODY,
        "merge_request.note.add" => GITLAB_NOTE_BODY,
        "merge_request.note.update" => GITLAB_NOTE_BODY,
        "merge_request.discussion.list" => GITLAB_DISCUSSION_LIST_NOTES,
        "merge_request.discussion.view" => GITLAB_DISCUSSION_VIEW_NOTES,
        "merge_request.discussion.inline.add" => GITLAB_DISCUSSION_NOTES,
        "merge_request.discussion.note.add" => GITLAB_NOTE_BODY,
        "merge_request.draft_note.list" => GITLAB_DRAFT_NOTE_BODIES,
        "merge_request.draft_note.view" => GITLAB_DRAFT_NOTE_BODY,
        "merge_request.draft_note.add" => GITLAB_DRAFT_NOTE_BODY,
        "merge_request.draft_note.update" => GITLAB_DRAFT_NOTE_BODY,
        "merge_request.discussion.add" => GITLAB_DISCUSSION_NOTES,
        "merge_request.discussion.note.update" => GITLAB_NOTE_BODY,
        "merge_request.discussion.resolve" => GITLAB_DISCUSSION_NOTES,
        "merge_request.discussion.reopen" => GITLAB_DISCUSSION_NOTES,
        _ => return None,
    };
    Some(ActionPresentation::new(
        bodies,
        FORMATS,
        OutputContentFormat::Markdown,
    ))
}

struct GitlabMarkdownBody;

impl EmbeddedBodyCodec for GitlabMarkdownBody {
    fn supported_formats(&self) -> &'static [OutputContentFormat] {
        FORMATS
    }

    fn select(
        &self,
        source: &Value,
        format: OutputContentFormat,
        max_body_bytes: u64,
        budget: &mut RenderBudget,
    ) -> Result<Option<SelectedContent>, RenderError> {
        select_gitlab_markdown_bounded_with_budget(
            source.as_str().ok_or(RenderError)?,
            format,
            max_body_bytes,
            max_body_bytes,
            budget,
        )
        .map(Some)
        .map_err(|_| RenderError)
    }
}

#[cfg(test)]
mod tests;
