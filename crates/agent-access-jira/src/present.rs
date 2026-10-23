//! Jira response presentation: which results carry embedded upstream
//! bodies, how those bodies render, and the whole-result Markdown templates.
use agent_access_content::render_adf_bounded_with_budget;
use agent_access_provider::presentation::*;
use serde_json::{Map, Value};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WholeRenderer {
    ProjectList,
    IssueTypeList,
    Issue,
    Search,
    CommentList,
    Comment,
    PropertyList,
    Property,
    AttachmentList,
    Verify,
}

#[derive(Debug, Clone, Copy)]
struct ResultDescriptor {
    action: &'static str,
    embedded_bodies: &'static [EmbeddedBody],
    whole: Option<WholeRenderer>,
}

const NO_BODIES: &[EmbeddedBody] = &[];

const ISSUE_DESCRIPTION: &[EmbeddedBody] = &[EmbeddedBody::new(&[], &AdfBody("description"))];

const NESTED_ISSUE_DESCRIPTION: &[EmbeddedBody] = &[EmbeddedBody::new(
    &[BodyPathSegment::Field("issue")],
    &AdfBody("description"),
)];

const COMMENT_BODY: &[EmbeddedBody] = &[EmbeddedBody::new(
    &[BodyPathSegment::Field("comment")],
    &AdfBody("body"),
)];

const RESULT_DESCRIPTORS: &[ResultDescriptor] = &[
    ResultDescriptor {
        action: "project.list",
        embedded_bodies: NO_BODIES,
        whole: Some(WholeRenderer::ProjectList),
    },
    ResultDescriptor {
        action: "issue_type.list",
        embedded_bodies: NO_BODIES,
        whole: Some(WholeRenderer::IssueTypeList),
    },
    ResultDescriptor {
        action: "issue.view",
        embedded_bodies: ISSUE_DESCRIPTION,
        whole: Some(WholeRenderer::Issue),
    },
    ResultDescriptor {
        action: "issue.create",
        embedded_bodies: NESTED_ISSUE_DESCRIPTION,
        whole: None,
    },
    ResultDescriptor {
        action: "issue.update",
        embedded_bodies: NESTED_ISSUE_DESCRIPTION,
        whole: None,
    },
    ResultDescriptor {
        action: "comment.view",
        embedded_bodies: COMMENT_BODY,
        whole: Some(WholeRenderer::Comment),
    },
    ResultDescriptor {
        action: "comment.add",
        embedded_bodies: COMMENT_BODY,
        whole: None,
    },
    ResultDescriptor {
        action: "comment.reply",
        embedded_bodies: COMMENT_BODY,
        whole: None,
    },
    ResultDescriptor {
        action: "comment.update",
        embedded_bodies: COMMENT_BODY,
        whole: None,
    },
    ResultDescriptor {
        action: "search",
        embedded_bodies: NO_BODIES,
        whole: Some(WholeRenderer::Search),
    },
    ResultDescriptor {
        action: "comment.list",
        embedded_bodies: NO_BODIES,
        whole: Some(WholeRenderer::CommentList),
    },
    ResultDescriptor {
        action: "comment.property.list",
        embedded_bodies: NO_BODIES,
        whole: Some(WholeRenderer::PropertyList),
    },
    ResultDescriptor {
        action: "comment.property.get",
        embedded_bodies: NO_BODIES,
        whole: Some(WholeRenderer::Property),
    },
    ResultDescriptor {
        action: "attachment.list",
        embedded_bodies: NO_BODIES,
        whole: Some(WholeRenderer::AttachmentList),
    },
    ResultDescriptor {
        action: "verify",
        embedded_bodies: NO_BODIES,
        whole: Some(WholeRenderer::Verify),
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

/// An ADF document in a named field of each owner.
struct AdfBody(&'static str);

impl EmbeddedBodyCodec for AdfBody {
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
        render_adf_bounded_with_budget(native, format, max_body_bytes, max_body_bytes, budget)
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
            WholeRenderer::ProjectList => render_project_list(result, out, budget)?,
            WholeRenderer::IssueTypeList => render_issue_type_list(result, out, budget)?,
            WholeRenderer::Issue => render_issue(result, true, "# ", out, max_body_bytes, budget)?,
            WholeRenderer::Search => render_search(result, out, budget)?,
            WholeRenderer::CommentList => render_comment_list(result, out, budget)?,
            WholeRenderer::Comment => render_comment_view(result, out, max_body_bytes, budget)?,
            WholeRenderer::PropertyList => render_property_list(result, out, budget)?,
            WholeRenderer::Property => render_property(result, out, budget)?,
            WholeRenderer::AttachmentList => render_attachment_list(result, out, budget)?,
            WholeRenderer::Verify => render_verify(result, out, budget)?,
        }
        Ok(())
    }
}

fn render_issue(
    value: &Value,
    include_description: bool,
    heading: &str,
    out: &mut MarkdownWriter,
    max_body_bytes: u64,
    budget: &mut PresentationBudget,
) -> Result<(), RenderError> {
    let object = as_object(value)?;
    budget.charge_work(object.len())?;
    let key = required_scalar(object, "key")?;
    let summary = optional_scalar(object, "summary")?;
    out.push(heading)?;
    out.push_code(key)?;
    if let Some(summary) = summary {
        out.push(" — ")?;
        out.push_heading_text(summary)?;
    }
    out.push("\n")?;
    code_fields(
        out,
        &[
            ("ID", optional_scalar(object, "id")?),
            ("Project", optional_scalar(object, "project")?),
        ],
    )?;
    fields(
        out,
        &[
            ("Status", optional_scalar(object, "status")?),
            ("Issue type", optional_scalar(object, "issueType")?),
        ],
    )?;
    if let Some(priority) = object.get("priority").filter(|value| !value.is_null()) {
        field_raw(out, "Priority", &render_named_object(priority)?)?;
    }
    for (label, key) in [
        ("Assignee", "assignee"),
        ("Reporter", "reporter"),
        ("Creator", "creator"),
    ] {
        if let Some(user) = object.get(key).filter(|value| !value.is_null()) {
            field_raw(out, label, &render_user(user)?)?;
        }
    }
    if let Some(labels) = object.get("labels").filter(|value| !value.is_null()) {
        let labels = array(labels)?;
        budget.charge_work(labels.len())?;
        let labels = labels.iter().map(scalar).collect::<Result<Vec<_>, _>>()?;
        out.push("- Labels: ")?;
        for (index, label) in labels.iter().enumerate() {
            if index > 0 {
                out.push(", ")?;
            }
            out.push_code(label)?;
        }
        out.push("\n")?;
    }
    code_fields(
        out,
        &[
            ("Created", optional_scalar(object, "created")?),
            ("Updated", optional_scalar(object, "updated")?),
        ],
    )?;
    if let Some(url) = optional_scalar(object, "webUrl")? {
        field_url(out, "URL", url)?;
    }
    if include_description && let Some(links) = object.get("issueLinks") {
        let links = array(links)?;
        budget.charge_work(links.len())?;
        out.push("\n## Issue links\n\n")?;
        if links.is_empty() {
            out.push("None.\n")?;
        }
        for link in links {
            let link = as_object(link)?;
            budget.charge_work(link.len())?;
            out.push("- This issue ")?;
            out.push_escaped(required_scalar(link, "relationship")?)?;
            out.push(" ")?;
            out.push_code(required_scalar(link, "key")?)?;
            out.push(" (type: ")?;
            out.push_escaped(required_scalar(link, "type")?)?;
            out.push("; direction: ")?;
            out.push_escaped(required_scalar(link, "direction")?)?;
            if let Some(issue_type) = optional_scalar(link, "issueType")? {
                out.push("; issue type: ")?;
                out.push_escaped(issue_type)?;
            }
            out.push(")")?;
            if let Some(summary) = optional_scalar(link, "summary")? {
                out.push(" — ")?;
                out.push_escaped(summary)?;
            }
            out.push("\n")?;
        }
    }
    if include_description
        && let Some(description) = object.get("description").filter(|value| !value.is_null())
    {
        let rendered = render_adf_bounded_with_budget(
            description,
            ReadContentFormat::Markdown,
            max_body_bytes,
            max_body_bytes,
            &mut budget.rich_content,
        )
        .map_err(|_| RenderError)?
        .ok_or(RenderError)?;
        out.push("\n## Description\n\n")?;
        out.push(&rendered.value)?;
        out.push("\n")?;
    }
    Ok(())
}

fn render_issue_type_list(
    value: &Value,
    out: &mut MarkdownWriter,
    budget: &mut PresentationBudget,
) -> Result<(), RenderError> {
    let object = as_object(value)?;
    let issue_types = array(required(object, "issueTypes")?)?;
    budget.charge_work(issue_types.len().saturating_add(object.len()))?;
    out.push("# Jira issue types for ")?;
    out.push_code(required_scalar(object, "project")?)?;
    out.push("\n")?;
    field(out, "Count", &issue_types.len().to_string())?;
    if issue_types.is_empty() {
        out.push("\nNo results.\n")?;
    }
    for issue_type in issue_types {
        let item = as_object(issue_type)?;
        budget.charge_work(item.len())?;
        out.push("\n## ")?;
        out.push_heading_text(required_scalar(item, "name")?)?;
        out.push("\n")?;
        code_fields(out, &[("ID", Some(required_scalar(item, "id")?))])?;
        let subtask = optional_display(item, "subtask")?;
        field(out, "Subtask", subtask.as_deref().ok_or(RenderError)?)?;
        field(out, "Description", required_scalar(item, "description")?)?;
    }
    out.push("\n## Pagination\n")?;
    for (label, key) in [
        ("Start at", "startAt"),
        ("Maximum results", "maxResults"),
        ("Total", "total"),
        ("Last page", "isLast"),
        ("Next start at", "nextStartAt"),
    ] {
        if let Some(value) = optional_display(object, key)? {
            field(out, label, &value)?;
        }
    }
    Ok(())
}

fn render_project_list(
    value: &Value,
    out: &mut MarkdownWriter,
    budget: &mut PresentationBudget,
) -> Result<(), RenderError> {
    let object = as_object(value)?;
    let items = array(required(object, "items")?)?;
    budget.charge_work(items.len().saturating_add(object.len()))?;
    out.push("# Jira projects\n\n")?;
    field(out, "Count", &items.len().to_string())?;
    for item in items {
        let item = as_object(item)?;
        budget.charge_work(item.len())?;
        out.push("\n## ")?;
        out.push_heading_text(scalar(required(item, "key")?)?)?;
        out.push("\n\n")?;
        for (key, label) in [
            ("id", "ID"),
            ("name", "Name"),
            ("projectTypeKey", "Project type"),
            ("webUrl", "Web URL"),
            ("previewTruncated", "Preview truncated"),
        ] {
            if let Some(value) = optional_display(item, key)? {
                field(out, label, &value)?;
            }
        }
    }
    out.push("\n## Pagination\n\n")?;
    for (key, label) in [
        ("maxResults", "Maximum results"),
        ("scanStatus", "Scan status"),
    ] {
        if let Some(value) = optional_display(object, key)? {
            field(out, label, &value)?;
        }
    }
    if let Some(token) = optional_scalar(object, "nextPageToken")? {
        out.push("- Next page token: ")?;
        out.push_code(token)?;
        out.push("\n")?;
    }
    Ok(())
}

fn render_search(
    value: &Value,
    out: &mut MarkdownWriter,
    budget: &mut PresentationBudget,
) -> Result<(), RenderError> {
    let object = as_object(value)?;
    let issues = array(required(object, "issues")?)?;
    budget.charge_work(issues.len().saturating_add(object.len()))?;
    out.push("# Jira issue search\n\n")?;
    field(out, "Count", &issues.len().to_string())?;
    if issues.is_empty() {
        out.push("\nNo results.\n")?;
    } else {
        for issue in issues {
            out.push("\n")?;
            render_issue(issue, false, "## ", out, 0, budget)?;
        }
    }
    out.push("\n## Pagination\n")?;
    let maximum_results = optional_display(object, "maxResults")?;
    let start_at = optional_display(object, "startAt")?;
    let total = optional_display(object, "total")?;
    let last_page = optional_display(object, "isLast")?;
    fields(
        out,
        &[
            ("Maximum results", maximum_results.as_deref()),
            ("Start at", start_at.as_deref()),
            ("Total", total.as_deref()),
            ("Last page", last_page.as_deref()),
        ],
    )?;
    if let Some(token) = optional_scalar(object, "nextPageToken")? {
        out.push("- Next page token: ")?;
        out.push_code(token)?;
        out.push("\n")?;
    }
    Ok(())
}

fn render_comment_list(
    value: &Value,
    out: &mut MarkdownWriter,
    budget: &mut PresentationBudget,
) -> Result<(), RenderError> {
    let object = as_object(value)?;
    let issue = as_object(required(object, "issue")?)?;
    let comments = array(required(object, "comments")?)?;
    budget.charge_work(comments.len().saturating_add(object.len()))?;
    out.push("# Jira comments for ")?;
    out.push_code(required_scalar(issue, "key")?)?;
    out.push("\n")?;
    render_issue_metadata(issue, out)?;
    field(out, "Count", &comments.len().to_string())?;
    if comments.is_empty() {
        out.push("\nNo results.\n")?;
    }
    for comment in comments {
        out.push("\n")?;
        render_comment_summary(comment, out)?;
    }
    out.push("\n## Pagination\n")?;
    let start_at = optional_display(object, "startAt")?;
    let maximum_results = optional_display(object, "maxResults")?;
    let total = optional_display(object, "total")?;
    fields(
        out,
        &[
            ("Start at", start_at.as_deref()),
            ("Maximum results", maximum_results.as_deref()),
            ("Total", total.as_deref()),
        ],
    )
}

fn render_comment_view(
    value: &Value,
    out: &mut MarkdownWriter,
    max_body_bytes: u64,
    budget: &mut PresentationBudget,
) -> Result<(), RenderError> {
    let object = as_object(value)?;
    let issue = as_object(required(object, "issue")?)?;
    let comment = as_object(required(object, "comment")?)?;
    budget.charge_work(object.len().saturating_add(comment.len()))?;
    out.push("# Jira comment ")?;
    out.push_code(required_scalar(comment, "commentId")?)?;
    out.push(" on ")?;
    out.push_code(required_scalar(issue, "key")?)?;
    out.push("\n")?;
    render_issue_metadata(issue, out)?;
    render_comment_fields(comment, out)?;
    if let Some(body) = comment.get("body").filter(|value| !value.is_null()) {
        let rendered = render_adf_bounded_with_budget(
            body,
            ReadContentFormat::Markdown,
            max_body_bytes,
            max_body_bytes,
            &mut budget.rich_content,
        )
        .map_err(|_| RenderError)?
        .ok_or(RenderError)?;
        out.push("\n## Body\n\n")?;
        out.push(&rendered.value)?;
        out.push("\n")?;
    }
    Ok(())
}

fn render_property_list(
    value: &Value,
    out: &mut MarkdownWriter,
    budget: &mut PresentationBudget,
) -> Result<(), RenderError> {
    let object = as_object(value)?;
    let issue = as_object(required(object, "issue")?)?;
    let keys = array(required(object, "keys")?)?;
    budget.charge_work(keys.len().saturating_add(object.len()))?;
    out.push("# Jira comment properties\n")?;
    render_issue_metadata(issue, out)?;
    field_code(out, "Comment ID", required_scalar(object, "commentId")?)?;
    field(out, "Count", &keys.len().to_string())?;
    if keys.is_empty() {
        out.push("\nNo results.\n")?;
    } else {
        out.push("\n## Keys\n")?;
        for key in keys {
            out.push("- ")?;
            out.push_code(required_scalar(as_object(key)?, "key")?)?;
            out.push("\n")?;
        }
    }
    Ok(())
}

fn render_property(
    value: &Value,
    out: &mut MarkdownWriter,
    budget: &mut PresentationBudget,
) -> Result<(), RenderError> {
    let object = as_object(value)?;
    let issue = as_object(required(object, "issue")?)?;
    budget.charge_work(object.len())?;
    out.push("# Jira comment property ")?;
    out.push_code(required_scalar(object, "propertyKey")?)?;
    out.push("\n")?;
    render_issue_metadata(issue, out)?;
    field_code(out, "Comment ID", required_scalar(object, "commentId")?)?;
    let json =
        serialize_json_pretty_bounded(object.get("value").ok_or(RenderError)?, out.remaining())?;
    let fence = fence_for(&json, '`');
    out.push("\n## Value\n\n")?;
    out.push(&fence)?;
    out.push("json\n")?;
    out.push(&json)?;
    out.push("\n")?;
    out.push(&fence)?;
    out.push("\n")
}

fn render_attachment_list(
    value: &Value,
    out: &mut MarkdownWriter,
    budget: &mut PresentationBudget,
) -> Result<(), RenderError> {
    let object = as_object(value)?;
    let issue = as_object(required(object, "issue")?)?;
    let attachments = array(required(object, "attachments")?)?;
    budget.charge_work(attachments.len().saturating_add(object.len()))?;
    out.push("# Jira attachments\n")?;
    render_issue_metadata(issue, out)?;
    field(out, "Count", &attachments.len().to_string())?;
    if attachments.is_empty() {
        out.push("\nNo results.\n")?;
    }
    for attachment in attachments {
        let attachment = as_object(attachment)?;
        let size = optional_display(attachment, "size")?;
        out.push("\n## ")?;
        out.push_heading_text(required_scalar(attachment, "filename")?)?;
        out.push("\n")?;
        code_fields(
            out,
            &[
                (
                    "Attachment ID",
                    optional_scalar(attachment, "attachmentId")?,
                ),
                ("Size", size.as_deref()),
                ("Content type", optional_scalar(attachment, "contentType")?),
            ],
        )?;
    }
    Ok(())
}

fn render_verify(
    value: &Value,
    out: &mut MarkdownWriter,
    budget: &mut PresentationBudget,
) -> Result<(), RenderError> {
    let object = as_object(value)?;
    let verification = as_object(required(object, "verification")?)?;
    let checked = array(required(verification, "checked")?)?;
    budget.charge_work(checked.len().saturating_add(verification.len()))?;
    out.push("# Jira verification for ")?;
    out.push_code(required_scalar(object, "issueKey")?)?;
    out.push("\n")?;
    field_code(out, "Project", required_scalar(object, "project")?)?;
    field(out, "Status", required_scalar(verification, "status")?)?;
    out.push("\n## Checked\n")?;
    if checked.is_empty() {
        out.push("No items.\n")?;
    }
    for item in checked {
        render_typed_id(item, "- ", out)?;
    }
    if let Some(mismatch) = verification
        .get("mismatch")
        .filter(|value| !value.is_null())
    {
        out.push("\n## Mismatch\n")?;
        render_typed_id(mismatch, "- ", out)?;
    }
    Ok(())
}

fn render_typed_id(
    value: &Value,
    prefix: &str,
    out: &mut MarkdownWriter,
) -> Result<(), RenderError> {
    let value = as_object(value)?;
    out.push(prefix)?;
    out.push_escaped(required_scalar(value, "type")?)?;
    out.push(": ")?;
    out.push_code(required_scalar(value, "id")?)?;
    out.push("\n")
}

fn render_issue_metadata(
    issue: &Map<String, Value>,
    out: &mut MarkdownWriter,
) -> Result<(), RenderError> {
    code_fields(
        out,
        &[
            ("Issue ID", optional_scalar(issue, "id")?),
            ("Issue key", optional_scalar(issue, "key")?),
            ("Project", optional_scalar(issue, "project")?),
        ],
    )?;
    if let Some(url) = optional_scalar(issue, "webUrl")? {
        field_url(out, "URL", url)?;
    }
    Ok(())
}

fn render_comment_summary(value: &Value, out: &mut MarkdownWriter) -> Result<(), RenderError> {
    let comment = as_object(value)?;
    out.push("## Comment ")?;
    out.push_code(required_scalar(comment, "commentId")?)?;
    out.push("\n")?;
    render_comment_fields(comment, out)
}

fn render_comment_fields(
    comment: &Map<String, Value>,
    out: &mut MarkdownWriter,
) -> Result<(), RenderError> {
    code_fields(
        out,
        &[
            (
                "Parent comment ID",
                optional_scalar(comment, "parentCommentId")?,
            ),
            ("Created", optional_scalar(comment, "created")?),
            ("Updated", optional_scalar(comment, "updated")?),
        ],
    )?;
    if let Some(author) = comment.get("author").filter(|value| !value.is_null()) {
        field_raw(out, "Author", &render_user(author)?)?;
    }
    if let Some(visibility) = comment.get("visibility").filter(|value| !value.is_null()) {
        let visibility = as_object(visibility)?;
        fields(
            out,
            &[
                ("Visibility type", optional_scalar(visibility, "type")?),
                ("Visibility value", optional_scalar(visibility, "value")?),
                (
                    "Visibility identifier",
                    optional_scalar(visibility, "identifier")?,
                ),
            ],
        )?;
    }
    Ok(())
}

fn render_user(value: &Value) -> Result<String, RenderError> {
    let object = as_object(value)?;
    let display = optional_scalar(object, "displayName")?;
    let account = optional_scalar(object, "accountId")?;
    Ok(match (display, account) {
        (Some(display), Some(account)) => {
            format!("{} (account ID: {})", escaped(display), code_span(account))
        }
        (Some(display), None) => escaped(display),
        (None, Some(account)) => format!("account ID: {}", code_span(account)),
        (None, None) => String::new(),
    })
}

fn render_named_object(value: &Value) -> Result<String, RenderError> {
    let object = as_object(value)?;
    let name = optional_scalar(object, "name")?;
    let id = optional_scalar(object, "id")?;
    Ok(match (name, id) {
        (Some(name), Some(id)) => format!("{} (ID: {})", escaped(name), code_span(id)),
        (Some(name), None) => escaped(name),
        (None, Some(id)) => format!("ID: {}", code_span(id)),
        (None, None) => String::new(),
    })
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

    fn adf(text: &str) -> Value {
        json!({
            "type": "doc",
            "version": 1,
            "content": [{"type": "paragraph", "content": [{"type": "text", "text": text}]}]
        })
    }

    #[test]
    fn registry_has_exact_jira_coverage_and_derived_capabilities() {
        let embedded = RESULT_DESCRIPTORS
            .iter()
            .filter(|descriptor| !descriptor.embedded_bodies.is_empty())
            .map(|descriptor| descriptor.action)
            .collect::<Vec<_>>();
        assert_eq!(
            embedded,
            [
                "issue.view",
                "issue.create",
                "issue.update",
                "comment.view",
                "comment.add",
                "comment.reply",
                "comment.update",
            ]
        );
        let whole = RESULT_DESCRIPTORS
            .iter()
            .filter(|descriptor| descriptor.whole.is_some())
            .map(|descriptor| descriptor.action)
            .collect::<Vec<_>>();
        assert_eq!(
            whole,
            [
                "project.list",
                "issue_type.list",
                "issue.view",
                "comment.view",
                "search",
                "comment.list",
                "comment.property.list",
                "comment.property.get",
                "attachment.list",
                "verify",
            ]
        );
        assert_eq!(
            response_capabilities("issue.view"),
            ResponseCapabilities::new(Some(READ_CONTENT_FORMATS), Some(RESPONSE_FORMATS))
        );
        assert_eq!(
            response_capabilities("issue.delete"),
            ResponseCapabilities::new(None, None)
        );
    }

    #[test]
    fn embedded_rendering_preserves_native_and_places_companion_at_owner() {
        let native = adf("hello *world*");
        let mut result =
            json!({"operation":"comment.add", "comment":{"commentId":"7", "body":native}});
        present_provider_result(
            "comment.add",
            &mut result,
            ResponseOptions::new(ReadContentFormat::Markdown, ResponseFormat::Json),
            4096,
            16384,
        )
        .unwrap();
        assert_eq!(result["comment"]["body"], adf("hello *world*"));
        assert_eq!(
            result["comment"]["renderedBody"],
            json!({"format":"markdown", "value":"hello \\*world\\*"})
        );
    }

    #[test]
    fn native_mode_validates_declared_content_and_omits_companion() {
        let mut result = json!({"description":{"type":"not-a-doc"}});
        let error = present_provider_result(
            "issue.view",
            &mut result,
            ResponseOptions::default(),
            4096,
            16384,
        )
        .unwrap_err();
        assert_eq!(error.reason_code(), ReasonCode::UpstreamProtocolFailed);
        assert_eq!(error.message, RENDER_FAILURE_MESSAGE);
    }

    #[test]
    fn issue_markdown_is_complete_deterministic_and_keeps_present_empty_body() {
        let mut result = json!({
            "id":"100", "key":"SBC-1", "project":"SBC", "summary":"Ship *it*",
            "status":"Open", "issueType":"Task", "priority":{"id":"3","name":"High"},
            "assignee":{"displayName":"Ada","accountId":"a`b"}, "reporter":null,
            "creator":{"accountId":"creator"}, "labels":["one","two"],
            "created":"2026-08-01", "updated":"2026-08-02",
            "webUrl":"https://example.test/browse/SBC-1", "description":adf("")
        });
        present_provider_result(
            "issue.view",
            &mut result,
            ResponseOptions::new(ReadContentFormat::Native, ResponseFormat::Markdown),
            4096,
            16384,
        )
        .unwrap();
        let text = result["value"].as_str().unwrap();
        assert!(text.starts_with("# `SBC-1` — Ship \\*it\\*\n"));
        assert!(text.contains("- Priority: High (ID: `3`)\n"));
        assert!(text.contains("- Assignee: Ada (account ID: ``a`b``)\n"));
        assert!(text.ends_with("\n## Description\n"));
        assert_eq!(result["format"], "markdown");
    }

    #[test]
    fn whole_markdown_charges_rendered_adf_once_at_the_final_document_bound() {
        let source = json!({
            "id":"100", "key":"SBC-1", "summary":"Near the result limit",
            "description":adf(&"x".repeat(1024))
        });
        let mut generously_bounded = source.clone();
        present_provider_result(
            "issue.view",
            &mut generously_bounded,
            ResponseOptions::new(ReadContentFormat::Native, ResponseFormat::Markdown),
            4096,
            16384,
        )
        .unwrap();
        let exact_serialized_bytes = serde_json::to_vec(&generously_bounded).unwrap().len() as u64;

        let mut exactly_bounded = source;
        present_provider_result(
            "issue.view",
            &mut exactly_bounded,
            ResponseOptions::new(ReadContentFormat::Native, ResponseFormat::Markdown),
            4096,
            exact_serialized_bytes,
        )
        .unwrap();
        assert_eq!(exactly_bounded, generously_bounded);
    }

    #[test]
    fn issue_type_markdown_keeps_ids_descriptions_and_pagination_without_markup_injection() {
        let source = json!({
            "project":"PROJ", "issueTypes":[
                {"id":"10001","name":"Bug\n## forged","description":"Fix *errors*\n## injected","subtask":false},
                {"id":"10002","name":"Subtask","description":"","subtask":true}
            ],
            "startAt":0, "maxResults":2, "total":3, "isLast":false, "nextStartAt":2
        });
        let options = ResponseOptions::new(ReadContentFormat::Native, ResponseFormat::Markdown);
        let mut result = source.clone();
        present_provider_result("issue_type.list", &mut result, options, 4096, 16384).unwrap();
        let markdown = result["value"].as_str().unwrap();
        assert!(markdown.starts_with("# Jira issue types for `PROJ`\n"));
        assert!(markdown.contains("- ID: `10001`\n"));
        assert!(markdown.contains("- ID: `10002`\n"));
        assert!(markdown.contains("- Subtask: true\n"));
        assert!(markdown.contains("Fix \\*errors\\*"));
        assert!(markdown.contains("- Next start at: 2\n"));
        assert!(markdown.contains("- Last page: false\n"));
        assert!(!markdown.contains("\n## forged"));
        assert!(!markdown.contains("\n## injected"));
        let mut result = source;
        let error =
            present_provider_result("issue_type.list", &mut result, options, 4096, 32).unwrap_err();
        assert_eq!(error.reason_code(), ReasonCode::UpstreamProtocolFailed);
    }

    #[test]
    fn every_whole_markdown_template_has_exactly_one_terminal_lf() {
        let cases = [
            ("issue_type.list", json!({"project":"PROJ","issueTypes":[]})),
            ("issue.view", json!({"key":"SBC-1","description":adf("")})),
            (
                "comment.view",
                json!({"issue":{"key":"SBC-1"},"comment":{"commentId":"7","body":adf("")}}),
            ),
            ("search", json!({"issues":[]})),
            (
                "comment.list",
                json!({"issue":{"key":"SBC-1"},"comments":[]}),
            ),
            (
                "comment.property.list",
                json!({"issue":{"key":"SBC-1"},"commentId":"7","keys":[]}),
            ),
            (
                "comment.property.get",
                json!({"issue":{"key":"SBC-1"},"commentId":"7","propertyKey":"key","value":{}}),
            ),
            (
                "attachment.list",
                json!({"issue":{"key":"SBC-1"},"attachments":[]}),
            ),
            (
                "verify",
                json!({"issueKey":"SBC-1","project":"SBC","verification":{"status":"matched","checked":[]}}),
            ),
        ];

        for (action, mut result) in cases {
            present_provider_result(
                action,
                &mut result,
                ResponseOptions::new(ReadContentFormat::Native, ResponseFormat::Markdown),
                4096,
                16384,
            )
            .unwrap();
            let markdown = result["value"].as_str().unwrap();
            assert!(markdown.ends_with('\n'), "{action} lacks a terminal LF");
            assert!(
                !markdown.ends_with("\n\n"),
                "{action} has more than one terminal LF"
            );
        }
    }

    #[test]
    fn search_renders_issue_entries_as_subsections() {
        let mut result = json!({
            "issues":[
                {"key":"SBC-1","summary":"First"},
                {"key":"SBC-2","summary":"Second"}
            ]
        });
        present_provider_result(
            "search",
            &mut result,
            ResponseOptions::new(ReadContentFormat::Native, ResponseFormat::Markdown),
            4096,
            16384,
        )
        .unwrap();
        let markdown = result["value"].as_str().unwrap();
        assert_eq!(
            markdown
                .lines()
                .filter(|line| line.starts_with("# "))
                .count(),
            1
        );
        assert!(markdown.contains("\n## `SBC-1` — First\n"));
        assert!(markdown.contains("\n## `SBC-2` — Second\n"));
    }

    #[test]
    fn property_json_and_tokens_use_collision_safe_delimiters() {
        let mut property = json!({
            "issue":{"id":"1","key":"SBC-1","project":"SBC","webUrl":"https://example.test"},
            "commentId":"7", "propertyKey":"key", "value":{"literal":"```"}
        });
        present_provider_result(
            "comment.property.get",
            &mut property,
            ResponseOptions::new(ReadContentFormat::Native, ResponseFormat::Markdown),
            4096,
            16384,
        )
        .unwrap();
        assert!(property["value"].as_str().unwrap().contains("````json\n"));

        let mut search = json!({"issues":[],"maxResults":1,"startAt":0,"total":0,"isLast":false,"nextPageToken":"a`b"});
        present_provider_result(
            "search",
            &mut search,
            ResponseOptions::new(ReadContentFormat::Native, ResponseFormat::Markdown),
            4096,
            16384,
        )
        .unwrap();
        assert!(search["value"].as_str().unwrap().contains("``a`b``"));
    }

    #[test]
    fn property_json_preserves_a_present_null_value() {
        let mut property = json!({
            "issue":{"key":"SBC-1"}, "commentId":"7", "propertyKey":"key", "value":null
        });
        present_provider_result(
            "comment.property.get",
            &mut property,
            ResponseOptions::new(ReadContentFormat::Native, ResponseFormat::Markdown),
            4096,
            16384,
        )
        .unwrap();
        assert!(
            property["value"]
                .as_str()
                .unwrap()
                .contains("```json\nnull\n```")
        );
    }

    #[test]
    fn metadata_is_copyable_and_cannot_inject_markdown_structure() {
        let mut issue = json!({
            "id":"100-1", "key":"SBC-1", "project":"SBC.PROJECT",
            "summary":"Ship-it (v1.2)\r\n## forged", "status":"Open\n- forged: yes",
            "labels":["release-1.2", "bad\n## forged"],
            "created":"2026-08-29T01:02:03.000-0500",
            "updated":"2026-08-29T02:03:04.000-0500",
            "webUrl":"https://example.test/browse/SBC-1?x=1",
            "assignee":{"displayName":"Ada\n## forged","accountId":"acct\r\nforged"},
            "description":adf("")
        });
        present_provider_result(
            "issue.view",
            &mut issue,
            ResponseOptions::new(ReadContentFormat::Native, ResponseFormat::Markdown),
            4096,
            16384,
        )
        .unwrap();
        let markdown = issue["value"].as_str().unwrap();
        assert!(markdown.starts_with("# `SBC-1` — Ship-it (v1.2) ## forged\n"));
        assert!(markdown.contains("- ID: `100-1`\n"));
        assert!(markdown.contains("- Project: `SBC.PROJECT`\n"));
        assert!(markdown.contains("- Created: `2026-08-29T01:02:03.000-0500`\n"));
        assert!(markdown.contains("- URL: <https://example.test/browse/SBC-1?x=1>\n"));
        assert!(markdown.contains("- Labels: `release-1.2`, `bad ## forged`\n"));
        assert!(!markdown.contains("\n## forged\n"));
        assert!(!markdown.contains("SBC\\-1"));

        let mut unsafe_url = json!({
            "key":"SBC-2", "webUrl":"https://example.test/path\n## forged"
        });
        present_provider_result(
            "issue.view",
            &mut unsafe_url,
            ResponseOptions::new(ReadContentFormat::Native, ResponseFormat::Markdown),
            4096,
            16384,
        )
        .unwrap();
        assert!(
            unsafe_url["value"]
                .as_str()
                .unwrap()
                .contains("- URL: `https://example.test/path ## forged`\n")
        );

        let mut credential_url = json!({
            "key":"SBC-3", "webUrl":"https://user:secret@example.test/browse/SBC-3"
        });
        present_provider_result(
            "issue.view",
            &mut credential_url,
            ResponseOptions::new(ReadContentFormat::Native, ResponseFormat::Markdown),
            4096,
            16384,
        )
        .unwrap();
        assert!(
            credential_url["value"]
                .as_str()
                .unwrap()
                .contains("- URL: `https://user:secret@example.test/browse/SBC-3`\n")
        );
    }

    #[test]
    fn heading_metadata_preserves_trailing_hash_runs() {
        let mut issue = json!({
            "key":"SBC-4", "summary":"Fix flaky retry #"
        });
        present_provider_result(
            "issue.view",
            &mut issue,
            ResponseOptions::new(ReadContentFormat::Native, ResponseFormat::Markdown),
            4096,
            16384,
        )
        .unwrap();
        assert!(
            issue["value"]
                .as_str()
                .unwrap()
                .starts_with("# `SBC-4` — Fix flaky retry \\#\n")
        );

        let mut hash_only_issue = json!({"key":"SBC-5", "summary":"#"});
        present_provider_result(
            "issue.view",
            &mut hash_only_issue,
            ResponseOptions::new(ReadContentFormat::Native, ResponseFormat::Markdown),
            4096,
            16384,
        )
        .unwrap();
        assert!(
            hash_only_issue["value"]
                .as_str()
                .unwrap()
                .starts_with("# `SBC-5` — \\#\n")
        );

        let mut attachments = json!({
            "issue":{"key":"SBC-4"},
            "attachments":[{"filename":"notes ##"}, {"filename":"###"}]
        });
        present_provider_result(
            "attachment.list",
            &mut attachments,
            ResponseOptions::new(ReadContentFormat::Native, ResponseFormat::Markdown),
            4096,
            16384,
        )
        .unwrap();
        assert!(
            attachments["value"]
                .as_str()
                .unwrap()
                .contains("## notes \\#\\#\n")
        );
        assert!(
            attachments["value"]
                .as_str()
                .unwrap()
                .contains("## \\#\\#\\#\n")
        );
    }

    #[test]
    fn verify_template_accepts_matched_and_allow_with_result_mismatch_shapes() {
        for (status, mismatch) in [
            ("matched", None),
            ("mismatch", Some(json!({"type":"comment","id":"9"}))),
        ] {
            let mut verification =
                json!({"status":status,"checked":[{"type":"attachment","id":"8"}]});
            if let Some(mismatch) = mismatch {
                verification["mismatch"] = mismatch;
            }
            let mut result =
                json!({"issueKey":"SBC-1","project":"SBC","verification":verification});
            present_provider_result(
                "verify",
                &mut result,
                ResponseOptions::new(ReadContentFormat::Native, ResponseFormat::Markdown),
                4096,
                16384,
            )
            .unwrap();
            let text = result["value"].as_str().unwrap();
            assert!(text.contains(&format!("- Status: {status}")));
            if status == "mismatch" {
                assert!(text.contains("## Mismatch"));
            }
        }
    }

    #[test]
    fn invalid_combinations_unsupported_actions_and_final_bounds_fail_closed() {
        let error = validate_response_options(
            presentation("issue.view").as_ref(),
            ResponseOptions::new(ReadContentFormat::Text, ResponseFormat::Markdown),
        )
        .unwrap_err();
        assert_eq!(error.reason_code(), ReasonCode::InputInvalid);

        let error = validate_response_options(
            presentation("issue.delete").as_ref(),
            ResponseOptions::new(ReadContentFormat::Native, ResponseFormat::Markdown),
        )
        .unwrap_err();
        assert_eq!(error.reason_code(), ReasonCode::ResponseFormatUnsupported);

        let mut result = json!({"id":"1","key":"SBC-1","description":adf("body")});
        let error = present_provider_result(
            "issue.view",
            &mut result,
            ResponseOptions::new(ReadContentFormat::Native, ResponseFormat::Markdown),
            4096,
            16,
        )
        .unwrap_err();
        assert_eq!(error.reason_code(), ReasonCode::UpstreamProtocolFailed);
        assert_eq!(error.message, RENDER_FAILURE_MESSAGE);
    }

    #[test]
    fn missing_or_null_body_has_no_companion_but_present_empty_has_one() {
        for body in [None, Some(Value::Null)] {
            let mut result = json!({"comment":{"commentId":"1"}});
            if let Some(body) = body {
                result["comment"]["body"] = body;
            }
            present_provider_result(
                "comment.view",
                &mut result,
                ResponseOptions::new(ReadContentFormat::Text, ResponseFormat::Json),
                4096,
                16384,
            )
            .unwrap();
            assert!(result["comment"].get("renderedBody").is_none());
        }
        let mut result = json!({"comment":{"commentId":"1","body":adf("")}});
        present_provider_result(
            "comment.view",
            &mut result,
            ResponseOptions::new(ReadContentFormat::Text, ResponseFormat::Json),
            4096,
            16384,
        )
        .unwrap();
        assert_eq!(result["comment"]["renderedBody"]["value"], "");
    }
}
