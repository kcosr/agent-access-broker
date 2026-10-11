//! Confluence response presentation: which results carry embedded upstream
//! bodies, how those bodies render, and the whole-result Markdown templates.
use agent_access_content::{
    render_confluence_adf_bounded_with_budget, render_confluence_storage_bounded_with_budget,
};
use agent_access_provider::presentation::*;
use serde_json::{Map, Value};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WholeRenderer {
    Content(ConfluenceContentKind),
    Search(ConfluenceContentKind),
    Verify(ConfluenceContentKind),
    AttachmentList(ConfluenceContentKind),
    CommentList,
    Comment,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ConfluenceContentKind {
    Page,
    Blog,
    PageDraft,
    BlogDraft,
}

#[derive(Debug, Clone, Copy)]
struct ResultDescriptor {
    action: &'static str,
    embedded_bodies: &'static [EmbeddedBody],
    whole: Option<WholeRenderer>,
}

const NO_BODIES: &[EmbeddedBody] = &[];

const CONFLUENCE_ROOT_BODY: &[EmbeddedBody] = &[EmbeddedBody {
    owner_path: &[],
    codec: &ConfluenceBodyMap,
}];

const CONFLUENCE_BLOG_BODY: &[EmbeddedBody] = &[EmbeddedBody {
    owner_path: &[],
    codec: &ConfluenceBlogStorage,
}];

const CONFLUENCE_COMMENT_BODY: &[EmbeddedBody] = &[EmbeddedBody {
    owner_path: &[BodyPathSegment::Field("comment")],
    codec: &ConfluenceBodyMap,
}];

const CONFLUENCE_COMMENT_BODIES: &[EmbeddedBody] = &[EmbeddedBody {
    owner_path: &[BodyPathSegment::Field("comments"), BodyPathSegment::Each],
    codec: &ConfluenceBodyMap,
}];

const RESULT_DESCRIPTORS: &[ResultDescriptor] = &[
    ResultDescriptor {
        action: "page.view",
        embedded_bodies: CONFLUENCE_ROOT_BODY,
        whole: Some(WholeRenderer::Content(ConfluenceContentKind::Page)),
    },
    ResultDescriptor {
        action: "blog.view",
        embedded_bodies: CONFLUENCE_BLOG_BODY,
        whole: Some(WholeRenderer::Content(ConfluenceContentKind::Blog)),
    },
    ResultDescriptor {
        action: "page.draft.view",
        embedded_bodies: CONFLUENCE_ROOT_BODY,
        whole: Some(WholeRenderer::Content(ConfluenceContentKind::PageDraft)),
    },
    ResultDescriptor {
        action: "blog.draft.view",
        embedded_bodies: CONFLUENCE_ROOT_BODY,
        whole: Some(WholeRenderer::Content(ConfluenceContentKind::BlogDraft)),
    },
    ResultDescriptor {
        action: "search",
        embedded_bodies: NO_BODIES,
        whole: Some(WholeRenderer::Search(ConfluenceContentKind::Page)),
    },
    ResultDescriptor {
        action: "blog.search",
        embedded_bodies: NO_BODIES,
        whole: Some(WholeRenderer::Search(ConfluenceContentKind::Blog)),
    },
    ResultDescriptor {
        action: "verify",
        embedded_bodies: NO_BODIES,
        whole: Some(WholeRenderer::Verify(ConfluenceContentKind::Page)),
    },
    ResultDescriptor {
        action: "blog.verify",
        embedded_bodies: NO_BODIES,
        whole: Some(WholeRenderer::Verify(ConfluenceContentKind::Blog)),
    },
    ResultDescriptor {
        action: "page.draft.verify",
        embedded_bodies: NO_BODIES,
        whole: Some(WholeRenderer::Verify(ConfluenceContentKind::PageDraft)),
    },
    ResultDescriptor {
        action: "blog.draft.verify",
        embedded_bodies: NO_BODIES,
        whole: Some(WholeRenderer::Verify(ConfluenceContentKind::BlogDraft)),
    },
    ResultDescriptor {
        action: "attachment.list",
        embedded_bodies: NO_BODIES,
        whole: Some(WholeRenderer::AttachmentList(ConfluenceContentKind::Page)),
    },
    ResultDescriptor {
        action: "blog.attachment.list",
        embedded_bodies: NO_BODIES,
        whole: Some(WholeRenderer::AttachmentList(ConfluenceContentKind::Blog)),
    },
    ResultDescriptor {
        action: "page.draft.attachment.list",
        embedded_bodies: NO_BODIES,
        whole: Some(WholeRenderer::AttachmentList(
            ConfluenceContentKind::PageDraft,
        )),
    },
    ResultDescriptor {
        action: "blog.draft.attachment.list",
        embedded_bodies: NO_BODIES,
        whole: Some(WholeRenderer::AttachmentList(
            ConfluenceContentKind::BlogDraft,
        )),
    },
    ResultDescriptor {
        action: "page.footer_comment.list",
        embedded_bodies: CONFLUENCE_COMMENT_BODIES,
        whole: Some(WholeRenderer::CommentList),
    },
    ResultDescriptor {
        action: "page.footer_comment.view",
        embedded_bodies: CONFLUENCE_COMMENT_BODY,
        whole: Some(WholeRenderer::Comment),
    },
    ResultDescriptor {
        action: "page.footer_comment.reply.list",
        embedded_bodies: CONFLUENCE_COMMENT_BODIES,
        whole: Some(WholeRenderer::CommentList),
    },
    ResultDescriptor {
        action: "page.inline_comment.list",
        embedded_bodies: CONFLUENCE_COMMENT_BODIES,
        whole: Some(WholeRenderer::CommentList),
    },
    ResultDescriptor {
        action: "page.inline_comment.view",
        embedded_bodies: CONFLUENCE_COMMENT_BODY,
        whole: Some(WholeRenderer::Comment),
    },
    ResultDescriptor {
        action: "page.inline_comment.reply.list",
        embedded_bodies: CONFLUENCE_COMMENT_BODIES,
        whole: Some(WholeRenderer::CommentList),
    },
    ResultDescriptor {
        action: "blog.footer_comment.list",
        embedded_bodies: CONFLUENCE_COMMENT_BODIES,
        whole: Some(WholeRenderer::CommentList),
    },
    ResultDescriptor {
        action: "blog.footer_comment.view",
        embedded_bodies: CONFLUENCE_COMMENT_BODY,
        whole: Some(WholeRenderer::Comment),
    },
    ResultDescriptor {
        action: "blog.footer_comment.reply.list",
        embedded_bodies: CONFLUENCE_COMMENT_BODIES,
        whole: Some(WholeRenderer::CommentList),
    },
    ResultDescriptor {
        action: "blog.inline_comment.list",
        embedded_bodies: CONFLUENCE_COMMENT_BODIES,
        whole: Some(WholeRenderer::CommentList),
    },
    ResultDescriptor {
        action: "blog.inline_comment.view",
        embedded_bodies: CONFLUENCE_COMMENT_BODY,
        whole: Some(WholeRenderer::Comment),
    },
    ResultDescriptor {
        action: "blog.inline_comment.reply.list",
        embedded_bodies: CONFLUENCE_COMMENT_BODIES,
        whole: Some(WholeRenderer::CommentList),
    },
    ResultDescriptor {
        action: "page.footer_comment.add",
        embedded_bodies: CONFLUENCE_COMMENT_BODY,
        whole: None,
    },
    ResultDescriptor {
        action: "blog.footer_comment.add",
        embedded_bodies: CONFLUENCE_COMMENT_BODY,
        whole: None,
    },
    ResultDescriptor {
        action: "page.footer_comment.update",
        embedded_bodies: CONFLUENCE_COMMENT_BODY,
        whole: None,
    },
    ResultDescriptor {
        action: "page.inline_comment.update",
        embedded_bodies: CONFLUENCE_COMMENT_BODY,
        whole: None,
    },
    ResultDescriptor {
        action: "blog.footer_comment.update",
        embedded_bodies: CONFLUENCE_COMMENT_BODY,
        whole: None,
    },
    ResultDescriptor {
        action: "blog.inline_comment.update",
        embedded_bodies: CONFLUENCE_COMMENT_BODY,
        whole: None,
    },
    ResultDescriptor {
        action: "page.footer_comment.reply.add",
        embedded_bodies: CONFLUENCE_COMMENT_BODY,
        whole: None,
    },
    ResultDescriptor {
        action: "page.inline_comment.reply.add",
        embedded_bodies: CONFLUENCE_COMMENT_BODY,
        whole: None,
    },
    ResultDescriptor {
        action: "blog.footer_comment.reply.add",
        embedded_bodies: CONFLUENCE_COMMENT_BODY,
        whole: None,
    },
    ResultDescriptor {
        action: "blog.inline_comment.reply.add",
        embedded_bodies: CONFLUENCE_COMMENT_BODY,
        whole: None,
    },
];

/// The presentation of `action`'s results, if it has one.
pub(super) fn presentation(action: &str) -> Option<ActionPresentation> {
    descriptor(action).map(|descriptor| ActionPresentation {
        embedded_bodies: descriptor.embedded_bodies,
        whole: descriptor
            .whole
            .as_ref()
            .map(|whole| whole as &'static dyn WholeResultRenderer),
    })
}

fn descriptor(action: &str) -> Option<&'static ResultDescriptor> {
    RESULT_DESCRIPTORS
        .iter()
        .find(|descriptor| descriptor.action == action)
}

/// A Confluence `body` map carrying `atlas_doc_format` and/or `storage`
/// representations; ADF wins when both are present.
struct ConfluenceBodyMap;

impl EmbeddedBodyCodec for ConfluenceBodyMap {
    fn render(
        &self,
        owner: &Map<String, Value>,
        format: ReadContentFormat,
        max_body_bytes: u64,
        budget: &mut RenderBudget,
    ) -> Result<Option<RenderedBody>, RenderError> {
        render_confluence_body_map(owner, format, max_body_bytes, budget)
    }
}

/// A blog `body` whose `storage` field holds storage-format XHTML.
struct ConfluenceBlogStorage;

impl EmbeddedBodyCodec for ConfluenceBlogStorage {
    fn render(
        &self,
        owner: &Map<String, Value>,
        format: ReadContentFormat,
        max_body_bytes: u64,
        budget: &mut RenderBudget,
    ) -> Result<Option<RenderedBody>, RenderError> {
        render_confluence_blog_storage(owner, format, max_body_bytes, budget)
    }
}

impl WholeResultRenderer for WholeRenderer {
    fn render(&self, result: &Value, context: &mut RenderContext) -> Result<(), RenderError> {
        let RenderContext {
            out,
            max_body_bytes,
            budget,
        } = context;
        let max_body_bytes = *max_body_bytes;
        match *self {
            WholeRenderer::Content(kind) => {
                render_confluence_content(result, kind, out, max_body_bytes, budget)?
            }
            WholeRenderer::Search(kind) => render_confluence_search(result, kind, out, budget)?,
            WholeRenderer::Verify(kind) => render_confluence_verify(result, kind, out, budget)?,
            WholeRenderer::AttachmentList(kind) => {
                render_confluence_attachment_list(result, kind, out, budget)?
            }
            WholeRenderer::CommentList => {
                render_confluence_comment_list(result, out, max_body_bytes, budget)?
            }
            WholeRenderer::Comment => {
                render_confluence_comment_view(result, out, max_body_bytes, budget)?
            }
        }
        Ok(())
    }
}

fn render_confluence_body_map(
    owner: &Map<String, Value>,
    format: ReadContentFormat,
    max_body_bytes: u64,
    budget: &mut RenderBudget,
) -> Result<Option<RenderedBody>, RenderError> {
    let Some(body) = owner.get("body").filter(|body| !body.is_null()) else {
        return Ok(None);
    };
    let body = body.as_object().ok_or(RenderError)?;
    let adf = body
        .get("atlas_doc_format")
        .map(|value| confluence_representation_value(value, "atlas_doc_format"))
        .transpose()?;
    let storage = body
        .get("storage")
        .map(|value| confluence_representation_value(value, "storage"))
        .transpose()?;
    if adf.is_none() && storage.is_none() {
        return Ok(None);
    }

    let rendered_adf = adf
        .map(|source| {
            render_confluence_adf_bounded_with_budget(
                source,
                format,
                max_body_bytes,
                max_body_bytes,
                budget,
            )
            .map_err(|_| RenderError)
        })
        .transpose()?;
    let rendered_storage = storage
        .map(|source| {
            render_confluence_storage_bounded_with_budget(
                source,
                if adf.is_some() {
                    ReadContentFormat::Native
                } else {
                    format
                },
                max_body_bytes,
                max_body_bytes,
                budget,
            )
            .map_err(|_| RenderError)
        })
        .transpose()?;
    Ok(rendered_adf
        .flatten()
        .or_else(|| rendered_storage.flatten()))
}

fn confluence_representation_value<'a>(
    value: &'a Value,
    expected: &str,
) -> Result<&'a str, RenderError> {
    let value = value.as_object().ok_or(RenderError)?;
    if required_scalar(value, "representation")? != expected {
        return Err(RenderError);
    }
    required_scalar(value, "value")
}

fn render_confluence_blog_storage(
    owner: &Map<String, Value>,
    format: ReadContentFormat,
    max_body_bytes: u64,
    budget: &mut RenderBudget,
) -> Result<Option<RenderedBody>, RenderError> {
    let Some(body) = owner.get("body").filter(|body| !body.is_null()) else {
        return Ok(None);
    };
    let body = body.as_object().ok_or(RenderError)?;
    let Some(source) = body.get("storage") else {
        return Ok(None);
    };
    render_confluence_storage_bounded_with_budget(
        source.as_str().ok_or(RenderError)?,
        format,
        max_body_bytes,
        max_body_bytes,
        budget,
    )
    .map_err(|_| RenderError)
}

fn render_confluence_content(
    value: &Value,
    kind: ConfluenceContentKind,
    out: &mut MarkdownWriter,
    max_body_bytes: u64,
    budget: &mut PresentationBudget,
) -> Result<(), RenderError> {
    let object = as_object(value)?;
    budget.charge_work(object.len())?;
    let id_field = confluence_id_field(kind);
    let id = required_scalar(object, id_field)?;
    out.push("# Confluence ")?;
    out.push(confluence_kind_label(kind))?;
    out.push(" ")?;
    out.push_code(id)?;
    if let Some(title) = optional_scalar(object, "title")? {
        out.push(" — ")?;
        out.push_heading_text(title)?;
    }
    out.push("\n")?;
    confluence_operation_and_scope_fields(object, out)?;
    fields(
        out,
        &[
            ("Content type", optional_scalar(object, "contentType")?),
            ("Lifecycle", optional_scalar(object, "lifecycle")?),
            ("Status", optional_scalar(object, "status")?),
            ("Draft origin", optional_scalar(object, "draftOrigin")?),
        ],
    )?;
    let version = optional_display(object, "version")?;
    code_fields(
        out,
        &[
            ("Parent page ID", optional_scalar(object, "parentPageId")?),
            ("Version", version.as_deref()),
            ("Created", optional_scalar(object, "createdAt")?),
            ("Updated", optional_scalar(object, "updatedAt")?),
            ("Draft handle", optional_scalar(object, "draftHandle")?),
        ],
    )?;
    confluence_actor_fields(object, out)?;
    confluence_url_fields(object, out)?;
    if object.get("body").is_some_and(|body| !body.is_null()) {
        let rendered = match kind {
            ConfluenceContentKind::Blog => render_confluence_blog_storage(
                object,
                ReadContentFormat::Markdown,
                max_body_bytes,
                &mut budget.rich_content,
            )?,
            _ => render_confluence_body_map(
                object,
                ReadContentFormat::Markdown,
                max_body_bytes,
                &mut budget.rich_content,
            )?,
        };
        if let Some(rendered) = rendered {
            out.push("\n## Body\n\n")?;
            out.push(&rendered.value)?;
            out.push("\n")?;
        }
    }
    Ok(())
}

fn render_confluence_search(
    value: &Value,
    kind: ConfluenceContentKind,
    out: &mut MarkdownWriter,
    budget: &mut PresentationBudget,
) -> Result<(), RenderError> {
    let object = as_object(value)?;
    let collection_field = if kind == ConfluenceContentKind::Blog {
        "blogs"
    } else {
        "pages"
    };
    let values = array(required(object, collection_field)?)?;
    budget.charge_work(values.len().saturating_add(object.len()))?;
    out.push("# Confluence ")?;
    out.push(if kind == ConfluenceContentKind::Blog {
        "blog search"
    } else {
        "page search"
    })?;
    out.push("\n\n")?;
    let actual_count = values.len().to_string();
    let declared_count = optional_display(object, "count")?;
    field(
        out,
        "Count",
        declared_count.as_deref().unwrap_or(&actual_count),
    )?;
    if let Some(operation) = optional_scalar(object, "operation")? {
        field_code(out, "Operation", operation)?;
    }
    if values.is_empty() {
        out.push("\nNo results.\n")?;
    }
    for item in values {
        let item = as_object(item)?;
        let id = required_scalar(item, confluence_id_field(kind))?;
        out.push("\n## ")?;
        out.push_code(id)?;
        if let Some(title) = optional_scalar(item, "title")? {
            out.push(" — ")?;
            out.push_heading_text(title)?;
        }
        out.push("\n")?;
        confluence_operation_and_scope_fields(item, out)?;
        fields(out, &[("Status", optional_scalar(item, "status")?)])?;
        let version = optional_display(item, "version")?;
        code_fields(
            out,
            &[
                ("Version", version.as_deref()),
                ("Created", optional_scalar(item, "createdAt")?),
                ("Updated", optional_scalar(item, "updatedAt")?),
            ],
        )?;
        confluence_actor_fields(item, out)?;
        confluence_url_fields(item, out)?;
    }
    out.push("\n## Pagination\n")?;
    let maximum_results = optional_display(object, "maxResults")?;
    code_fields(out, &[("Maximum results", maximum_results.as_deref())])?;
    if let Some(token) = optional_scalar(object, "nextPageToken")? {
        field_code(out, "Next page token", token)?;
    }
    Ok(())
}

fn render_confluence_verify(
    value: &Value,
    kind: ConfluenceContentKind,
    out: &mut MarkdownWriter,
    budget: &mut PresentationBudget,
) -> Result<(), RenderError> {
    let object = as_object(value)?;
    let verification = as_object(required(object, "verification")?)?;
    let checked = array(required(verification, "checked")?)?;
    budget.charge_work(checked.len().saturating_add(object.len()))?;
    out.push("# Confluence ")?;
    out.push(confluence_kind_label(kind))?;
    out.push(" verification for ")?;
    out.push_code(required_scalar(object, confluence_verify_id_field(kind))?)?;
    out.push("\n")?;
    confluence_operation_and_scope_fields(object, out)?;
    fields(
        out,
        &[
            ("Lifecycle", optional_scalar(object, "lifecycle")?),
            ("Content status", optional_scalar(object, "status")?),
            ("Status", Some(required_scalar(verification, "status")?)),
        ],
    )?;
    out.push("\n## Checked\n")?;
    if checked.is_empty() {
        out.push("No items.\n")?;
    }
    for item in checked {
        render_confluence_verification_item(item, "- ", out)?;
    }
    if let Some(mismatch) = verification
        .get("mismatch")
        .filter(|value| !value.is_null())
    {
        out.push("\n## Mismatch\n")?;
        render_confluence_verification_item(mismatch, "- ", out)?;
    }
    Ok(())
}

fn render_confluence_verification_item(
    value: &Value,
    prefix: &str,
    out: &mut MarkdownWriter,
) -> Result<(), RenderError> {
    let object = as_object(value)?;
    out.push(prefix)?;
    out.push_escaped(required_scalar(object, "type")?)?;
    out.push("\n")?;
    for (label, key) in [
        ("ID", "id"),
        ("Version", "version"),
        ("Expected", "expected"),
        ("Actual", "actual"),
        ("Parent status", "parentStatus"),
    ] {
        if let Some(value) = optional_display(object, key)? {
            out.push("  - ")?;
            out.push(label)?;
            out.push(": ")?;
            out.push_code(&value)?;
            out.push("\n")?;
        }
    }
    Ok(())
}

fn render_confluence_attachment_list(
    value: &Value,
    kind: ConfluenceContentKind,
    out: &mut MarkdownWriter,
    budget: &mut PresentationBudget,
) -> Result<(), RenderError> {
    let object = as_object(value)?;
    let attachments = array(required(object, "attachments")?)?;
    budget.charge_work(attachments.len().saturating_add(object.len()))?;
    out.push("# Confluence ")?;
    out.push(confluence_kind_label(kind))?;
    out.push(" attachments\n")?;
    if let Some(operation) = optional_scalar(object, "operation")? {
        field_code(out, "Operation", operation)?;
    }
    let owner_field = if matches!(
        kind,
        ConfluenceContentKind::Blog | ConfluenceContentKind::BlogDraft
    ) {
        "blog"
    } else {
        "page"
    };
    let owner = as_object(required(object, owner_field)?)?;
    confluence_operation_and_scope_fields(owner, out)?;
    fields(out, &[("Status", optional_scalar(owner, "status")?)])?;
    let actual_count = attachments.len().to_string();
    let count = optional_display(object, "count")?;
    field(out, "Count", count.as_deref().unwrap_or(&actual_count))?;
    if attachments.is_empty() {
        out.push("\nNo results.\n")?;
    }
    for attachment in attachments {
        let attachment = as_object(attachment)?;
        out.push("\n## ")?;
        if let Some(filename) = optional_scalar(attachment, "filename")? {
            out.push_heading_text(filename)?;
        } else {
            out.push("Attachment ")?;
            out.push_code(required_scalar(attachment, "attachmentId")?)?;
        }
        out.push("\n")?;
        let size = optional_display(attachment, "size")?;
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
        fields(
            out,
            &[(
                "Parent status",
                optional_scalar(attachment, "parentStatus")?,
            )],
        )?;
    }
    out.push("\n## Pagination\n")?;
    let has_more = optional_display(object, "hasMore")?;
    fields(out, &[("Has more", has_more.as_deref())])?;
    if let Some(token) = optional_scalar(object, "nextPageToken")? {
        field_code(out, "Next page token", token)?;
    }
    Ok(())
}

fn render_confluence_comment_list(
    value: &Value,
    out: &mut MarkdownWriter,
    max_body_bytes: u64,
    budget: &mut PresentationBudget,
) -> Result<(), RenderError> {
    let object = as_object(value)?;
    let comments = array(required(object, "comments")?)?;
    budget.charge_work(comments.len().saturating_add(object.len()))?;
    out.push("# Confluence comments\n\n")?;
    let actual_count = comments.len().to_string();
    let count = optional_display(object, "count")?;
    field(out, "Count", count.as_deref().unwrap_or(&actual_count))?;
    if comments.is_empty() {
        out.push("\nNo results.\n")?;
    }
    for comment in comments {
        out.push("\n")?;
        render_confluence_comment(comment, "## ", out, max_body_bytes, budget)?;
    }
    out.push("\n## Pagination\n")?;
    let has_more = optional_display(object, "hasMore")?;
    fields(out, &[("Has more", has_more.as_deref())])?;
    if let Some(token) = optional_scalar(object, "nextPageToken")? {
        field_code(out, "Next page token", token)?;
    }
    Ok(())
}

fn render_confluence_comment_view(
    value: &Value,
    out: &mut MarkdownWriter,
    max_body_bytes: u64,
    budget: &mut PresentationBudget,
) -> Result<(), RenderError> {
    let object = as_object(value)?;
    budget.charge_work(object.len())?;
    render_confluence_comment(
        required(object, "comment")?,
        "# Confluence ",
        out,
        max_body_bytes,
        budget,
    )
}

fn render_confluence_comment(
    value: &Value,
    heading: &str,
    out: &mut MarkdownWriter,
    max_body_bytes: u64,
    budget: &mut PresentationBudget,
) -> Result<(), RenderError> {
    let comment = as_object(value)?;
    budget.charge_work(comment.len())?;
    out.push(heading)?;
    out.push("comment ")?;
    out.push_code(required_scalar(comment, "commentId")?)?;
    out.push("\n")?;
    let version = optional_display(comment, "version")?;
    code_fields(
        out,
        &[
            ("Page ID", optional_scalar(comment, "pageId")?),
            ("Blog ID", optional_scalar(comment, "blogId")?),
            (
                "Parent comment ID",
                optional_scalar(comment, "parentCommentId")?,
            ),
            ("Space", optional_scalar(comment, "space")?),
            ("Space ID", optional_scalar(comment, "spaceId")?),
            ("Version", version.as_deref()),
            ("Created", optional_scalar(comment, "createdAt")?),
            ("Updated", optional_scalar(comment, "updatedAt")?),
        ],
    )?;
    fields(
        out,
        &[
            ("Kind", optional_scalar(comment, "kind")?),
            ("Container type", optional_scalar(comment, "containerType")?),
            ("Status", optional_scalar(comment, "status")?),
            (
                "Resolution status",
                optional_scalar(comment, "resolutionStatus")?,
            ),
        ],
    )?;
    if let Some(author) = comment.get("author").filter(|value| !value.is_null()) {
        field_raw(out, "Author", &render_confluence_actor(author)?)?;
    }
    if let Some(rendered) = render_confluence_body_map(
        comment,
        ReadContentFormat::Markdown,
        max_body_bytes,
        &mut budget.rich_content,
    )? {
        out.push("\n### Body\n\n")?;
        out.push(&rendered.value)?;
        out.push("\n")?;
    }
    Ok(())
}

fn confluence_id_field(kind: ConfluenceContentKind) -> &'static str {
    match kind {
        ConfluenceContentKind::Page => "id",
        ConfluenceContentKind::PageDraft => "pageId",
        ConfluenceContentKind::Blog | ConfluenceContentKind::BlogDraft => "blogId",
    }
}

fn confluence_verify_id_field(kind: ConfluenceContentKind) -> &'static str {
    match kind {
        ConfluenceContentKind::Page | ConfluenceContentKind::PageDraft => "pageId",
        ConfluenceContentKind::Blog | ConfluenceContentKind::BlogDraft => "blogId",
    }
}

fn confluence_kind_label(kind: ConfluenceContentKind) -> &'static str {
    match kind {
        ConfluenceContentKind::Page => "page",
        ConfluenceContentKind::Blog => "blog",
        ConfluenceContentKind::PageDraft => "page draft",
        ConfluenceContentKind::BlogDraft => "blog draft",
    }
}

fn confluence_operation_and_scope_fields(
    object: &Map<String, Value>,
    out: &mut MarkdownWriter,
) -> Result<(), RenderError> {
    let page_id = optional_scalar(object, "pageId")?;
    let page_id = match page_id {
        Some(value) => Some(value),
        None => optional_scalar(object, "id")?,
    };
    code_fields(
        out,
        &[
            ("Operation", optional_scalar(object, "operation")?),
            ("Page ID", page_id),
            ("Blog ID", optional_scalar(object, "blogId")?),
            ("Space", optional_scalar(object, "space")?),
            ("Space ID", optional_scalar(object, "spaceId")?),
        ],
    )
}

fn confluence_actor_fields(
    object: &Map<String, Value>,
    out: &mut MarkdownWriter,
) -> Result<(), RenderError> {
    for (label, key) in [("Created by", "createdBy"), ("Updated by", "updatedBy")] {
        if let Some(actor) = object.get(key).filter(|value| !value.is_null()) {
            field_raw(out, label, &render_confluence_actor(actor)?)?;
        }
    }
    Ok(())
}

fn render_confluence_actor(value: &Value) -> Result<String, RenderError> {
    let actor = as_object(value)?;
    let display = optional_scalar(actor, "displayName")?;
    let account = optional_scalar(actor, "accountId")?;
    Ok(match (display, account) {
        (Some(display), Some(account)) => {
            format!("{} (account ID: {})", escaped(display), code_span(account))
        }
        (Some(display), None) => escaped(display),
        (None, Some(account)) => format!("account ID: {}", code_span(account)),
        (None, None) => String::new(),
    })
}

fn confluence_url_fields(
    object: &Map<String, Value>,
    out: &mut MarkdownWriter,
) -> Result<(), RenderError> {
    for (label, key) in [("URL", "webUrl"), ("Space URL", "spaceUrl")] {
        if let Some(url) = optional_scalar(object, key)? {
            field_url(out, label, url)?;
        }
    }
    Ok(())
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

    fn adf(text: &str) -> Value {
        json!({
            "type": "doc",
            "version": 1,
            "content": [{"type": "paragraph", "content": [{"type": "text", "text": text}]}]
        })
    }

    fn response_capabilities(action: &str) -> ResponseCapabilities {
        agent_access_provider::presentation::response_capabilities(presentation(action).as_ref())
    }

    #[test]
    fn registry_has_exact_confluence_coverage_and_derived_capabilities() {
        let embedded = RESULT_DESCRIPTORS
            .iter()
            .filter(|descriptor| !descriptor.embedded_bodies.is_empty())
            .map(|descriptor| descriptor.action)
            .collect::<std::collections::BTreeSet<_>>();
        assert_eq!(
            embedded,
            [
                "blog.draft.view",
                "blog.footer_comment.add",
                "blog.footer_comment.list",
                "blog.footer_comment.reply.add",
                "blog.footer_comment.reply.list",
                "blog.footer_comment.update",
                "blog.footer_comment.view",
                "blog.inline_comment.list",
                "blog.inline_comment.reply.add",
                "blog.inline_comment.reply.list",
                "blog.inline_comment.update",
                "blog.inline_comment.view",
                "blog.view",
                "page.draft.view",
                "page.footer_comment.add",
                "page.footer_comment.list",
                "page.footer_comment.reply.add",
                "page.footer_comment.reply.list",
                "page.footer_comment.update",
                "page.footer_comment.view",
                "page.inline_comment.list",
                "page.inline_comment.reply.add",
                "page.inline_comment.reply.list",
                "page.inline_comment.update",
                "page.inline_comment.view",
                "page.view",
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
                "attachment.list",
                "blog.attachment.list",
                "blog.draft.attachment.list",
                "blog.draft.verify",
                "blog.draft.view",
                "blog.footer_comment.list",
                "blog.footer_comment.reply.list",
                "blog.footer_comment.view",
                "blog.inline_comment.list",
                "blog.inline_comment.reply.list",
                "blog.inline_comment.view",
                "blog.search",
                "blog.verify",
                "blog.view",
                "page.draft.attachment.list",
                "page.draft.verify",
                "page.draft.view",
                "page.footer_comment.list",
                "page.footer_comment.reply.list",
                "page.footer_comment.view",
                "page.inline_comment.list",
                "page.inline_comment.reply.list",
                "page.inline_comment.view",
                "page.view",
                "search",
                "verify",
            ]
            .into_iter()
            .collect()
        );
        assert_eq!(
            response_capabilities("page.footer_comment.view"),
            ResponseCapabilities {
                read_content_formats: Some(READ_CONTENT_FORMATS),
                response_formats: Some(RESPONSE_FORMATS),
            }
        );
        assert_eq!(
            response_capabilities("page.footer_comment.add"),
            ResponseCapabilities {
                read_content_formats: Some(READ_CONTENT_FORMATS),
                response_formats: None,
            }
        );
        assert_eq!(
            response_capabilities("page.footer_comment.delete"),
            ResponseCapabilities {
                read_content_formats: None,
                response_formats: None,
            }
        );
    }

    fn confluence_storage_body(source: &str) -> Value {
        json!({
            "storage": {"representation":"storage", "value":source}
        })
    }

    #[test]
    fn confluence_embedded_rendering_handles_root_wrapped_collection_and_bare_blog() {
        let mut page = json!({
            "id":"10", "body":confluence_storage_body("<p>Page <strong>body</strong></p>")
        });
        present_provider_result(
            "page.view",
            &mut page,
            ResponseOptions {
                read_content_format: ReadContentFormat::Markdown,
                response_format: ResponseFormat::Json,
            },
            4096,
            16384,
        )
        .unwrap();
        assert_eq!(page["renderedBody"]["format"], "markdown");
        assert!(
            page["renderedBody"]["value"]
                .as_str()
                .unwrap()
                .contains("Page")
        );
        assert_eq!(
            page["body"],
            confluence_storage_body("<p>Page <strong>body</strong></p>")
        );

        let mut comments = json!({"comments":[
            {"commentId":"1","body":confluence_storage_body("<p>one</p>")},
            {"commentId":"2","body":{}}
        ]});
        present_provider_result(
            "page.footer_comment.list",
            &mut comments,
            ResponseOptions {
                read_content_format: ReadContentFormat::Text,
                response_format: ResponseFormat::Json,
            },
            4096,
            16384,
        )
        .unwrap();
        assert_eq!(comments["comments"][0]["renderedBody"]["value"], "one");
        assert!(comments["comments"][1].get("renderedBody").is_none());

        let mut blog = json!({"blogId":"20","body":{"storage":"<p>blog</p>"}});
        present_provider_result(
            "blog.view",
            &mut blog,
            ResponseOptions {
                read_content_format: ReadContentFormat::Markdown,
                response_format: ResponseFormat::Json,
            },
            4096,
            16384,
        )
        .unwrap();
        assert_eq!(blog["renderedBody"]["value"], "blog");
        assert_eq!(blog["body"]["storage"], "<p>blog</p>");
    }

    #[test]
    fn confluence_adf_priority_validates_every_present_representation_without_fallback() {
        let serialized_adf = serde_json::to_string(&adf("ADF wins")).unwrap();
        let mut result = json!({
            "id":"10",
            "body":{
                "storage":{"representation":"storage","value":"<p>storage loses</p>"},
                "atlas_doc_format":{"representation":"atlas_doc_format","value":serialized_adf}
            }
        });
        present_provider_result(
            "page.view",
            &mut result,
            ResponseOptions {
                read_content_format: ReadContentFormat::Markdown,
                response_format: ResponseFormat::Json,
            },
            4096,
            16384,
        )
        .unwrap();
        assert_eq!(result["renderedBody"]["value"], "ADF wins");

        for body in [
            json!({
                "atlas_doc_format":{"representation":"atlas_doc_format","value":"{invalid"},
                "storage":{"representation":"storage","value":"<p>valid fallback</p>"}
            }),
            json!({
                "atlas_doc_format":{"representation":"atlas_doc_format","value":serde_json::to_string(&adf("valid")).unwrap()},
                "storage":{"representation":"wrong","value":"<p>otherwise valid</p>"}
            }),
        ] {
            let mut result = json!({"id":"10","body":body});
            let error = present_provider_result(
                "page.view",
                &mut result,
                ResponseOptions {
                    read_content_format: ReadContentFormat::Markdown,
                    response_format: ResponseFormat::Json,
                },
                4096,
                16384,
            )
            .unwrap_err();
            assert_eq!(error.reason_code, ReasonCode::UpstreamProtocolFailed);
        }
    }

    #[test]
    fn confluence_empty_body_map_is_absent_and_native_mode_is_shape_preserving() {
        let mut empty = json!({"id":"10","body":{}});
        present_provider_result(
            "page.view",
            &mut empty,
            ResponseOptions {
                read_content_format: ReadContentFormat::Text,
                response_format: ResponseFormat::Json,
            },
            4096,
            16384,
        )
        .unwrap();
        assert!(empty.get("renderedBody").is_none());

        let mut native = json!({
            "id":"10", "body":confluence_storage_body("<p>native</p>")
        });
        let expected = native.clone();
        present_provider_result(
            "page.view",
            &mut native,
            ResponseOptions::default(),
            4096,
            16384,
        )
        .unwrap();
        assert_eq!(native, expected);

        let mut collision = json!({
            "id":"10",
            "body":confluence_storage_body("<p>native</p>"),
            "renderedBody":{"format":"markdown","value":"forged"}
        });
        let error = present_provider_result(
            "page.view",
            &mut collision,
            ResponseOptions {
                read_content_format: ReadContentFormat::Markdown,
                response_format: ResponseFormat::Json,
            },
            4096,
            16384,
        )
        .unwrap_err();
        assert_eq!(error.reason_code, ReasonCode::UpstreamProtocolFailed);
    }

    fn confluence_whole_fixture(renderer: WholeRenderer) -> Value {
        match renderer {
            WholeRenderer::Content(kind) => {
                let mut value = json!({
                    "title":"Title", "space":"SPACE", "spaceId":"99",
                    "spaceUrl":"https://example.test/spaces/SPACE",
                    "webUrl":"https://example.test/content/10", "version":2,
                    "createdAt":"2026-08-01", "updatedAt":"2026-08-02",
                    "createdBy":{"displayName":"Ada","accountId":"a1"},
                    "updatedBy":{"accountId":"a2"},
                    "operation":match kind {
                        ConfluenceContentKind::Page => "page.view",
                        ConfluenceContentKind::Blog => "blog.view",
                        ConfluenceContentKind::PageDraft => "page.draft.view",
                        ConfluenceContentKind::BlogDraft => "blog.draft.view",
                    },
                    "contentType":if matches!(kind, ConfluenceContentKind::Blog | ConfluenceContentKind::BlogDraft) { "blog" } else { "page" },
                    "lifecycle":if matches!(kind, ConfluenceContentKind::PageDraft | ConfluenceContentKind::BlogDraft) { "draft" } else { "current" },
                    "status":if matches!(kind, ConfluenceContentKind::PageDraft | ConfluenceContentKind::BlogDraft) { "draft" } else { "current" }
                });
                value[confluence_id_field(kind)] = json!("10");
                if matches!(
                    kind,
                    ConfluenceContentKind::PageDraft | ConfluenceContentKind::BlogDraft
                ) {
                    value["parentPageId"] = json!("9");
                    value["draftHandle"] = json!("opaque-handle");
                    value["draftOrigin"] = json!("broker_managed");
                }
                value["body"] = if kind == ConfluenceContentKind::Blog {
                    json!({"storage":"<p>body</p>"})
                } else {
                    confluence_storage_body("<p>body</p>")
                };
                value
            }
            WholeRenderer::Search(kind) => {
                let mut item = json!({
                    "title":"Title", "space":"SPACE",
                    "spaceId":"99",
                    "spaceUrl":"https://example.test/spaces/SPACE",
                    "webUrl":"https://example.test/content/10", "status":"current",
                    "version":2, "createdAt":"2026-08-01", "updatedAt":"2026-08-02",
                    "createdBy":{"displayName":"Ada","accountId":"a1"},
                    "updatedBy":{"accountId":"a2"}
                });
                item[confluence_id_field(kind)] = json!("10");
                if kind == ConfluenceContentKind::Blog {
                    json!({"operation":"blog.search","blogs":[item],"count":1,"maxResults":25,"nextPageToken":"opaque-token"})
                } else {
                    json!({"operation":"search","pages":[item],"count":1,"maxResults":25,"nextPageToken":"opaque-token"})
                }
            }
            WholeRenderer::Verify(kind) => {
                let mut value = json!({
                    "operation":match kind {
                        ConfluenceContentKind::Page => "verify",
                        ConfluenceContentKind::Blog => "blog.verify",
                        ConfluenceContentKind::PageDraft => "page.draft.verify",
                        ConfluenceContentKind::BlogDraft => "blog.draft.verify",
                    },
                    "space":"SPACE", "spaceId":"99",
                    "lifecycle":if matches!(kind, ConfluenceContentKind::PageDraft | ConfluenceContentKind::BlogDraft) { "draft" } else { "current" },
                    "status":if matches!(kind, ConfluenceContentKind::PageDraft | ConfluenceContentKind::BlogDraft) { "draft" } else { "current" },
                    "verification":{
                        "status":"mismatch",
                        "checked":[{"type":"version","id":"10","version":2,"expected":"2","actual":"1","parentStatus":"current"}],
                        "mismatch":{"type":"attachment","id":"77","version":3,"expected":"current","actual":"draft","parentStatus":"draft"}
                    }
                });
                value[confluence_verify_id_field(kind)] = json!("10");
                value
            }
            WholeRenderer::AttachmentList(kind) => {
                let owner_field = if matches!(
                    kind,
                    ConfluenceContentKind::Blog | ConfluenceContentKind::BlogDraft
                ) {
                    "blog"
                } else {
                    "page"
                };
                let draft = matches!(
                    kind,
                    ConfluenceContentKind::PageDraft | ConfluenceContentKind::BlogDraft
                );
                let owner = if matches!(
                    kind,
                    ConfluenceContentKind::Blog | ConfluenceContentKind::BlogDraft
                ) {
                    json!({"blogId":"10","space":"SPACE","spaceId":"99","status":if draft { "draft" } else { "current" }})
                } else {
                    json!({"id":"10","space":"SPACE","spaceId":"99","status":if draft { "draft" } else { "current" }})
                };
                let mut value = json!({
                    "operation":match kind {
                        ConfluenceContentKind::Page => "attachment.list",
                        ConfluenceContentKind::Blog => "blog.attachment.list",
                        ConfluenceContentKind::PageDraft => "page.draft.attachment.list",
                        ConfluenceContentKind::BlogDraft => "blog.draft.attachment.list",
                    },
                    "attachments":[{
                        "attachmentId":"77","filename":"notes.txt","size":12,
                        "contentType":"text/plain","parentStatus":if draft { "draft" } else { "current" }
                    }],
                    "count":1,"hasMore":true,"nextPageToken":"opaque-token"
                });
                value[owner_field] = owner;
                value
            }
            WholeRenderer::CommentList => json!({
                "comments":[{
                    "commentId":"1","kind":"footer","containerType":"page",
                    "space":"SPACE","pageId":"10","status":"current",
                    "resolutionStatus":"open","version":2,
                    "author":{"displayName":"Ada","accountId":"a1"},
                    "createdAt":"2026-08-01","updatedAt":"2026-08-02",
                    "parentCommentId":"0","body":confluence_storage_body("<p>body</p>")
                }],
                "count":1,"hasMore":true,"nextPageToken":"opaque-token"
            }),
            WholeRenderer::Comment => json!({
                "comment":{
                    "commentId":"1","kind":"footer","containerType":"page",
                    "space":"SPACE","spaceId":"99","pageId":"10",
                    "parentCommentId":"0","status":"current",
                    "resolutionStatus":"open","version":2,
                    "author":{"displayName":"Ada","accountId":"a1"},
                    "createdAt":"2026-08-01","updatedAt":"2026-08-02",
                    "body":confluence_storage_body("<p>body</p>")
                }
            }),
        }
    }

    fn assert_confluence_whole_semantics(renderer: WholeRenderer, markdown: &str, action: &str) {
        let mut expected = Vec::new();
        match renderer {
            WholeRenderer::Content(kind) => {
                expected.extend([
                    format!("# Confluence {} `10` — Title", confluence_kind_label(kind)),
                    "- Space: `SPACE`".to_string(),
                    "- Space ID: `99`".to_string(),
                    format!(
                        "- Content type: {}",
                        if matches!(
                            kind,
                            ConfluenceContentKind::Blog | ConfluenceContentKind::BlogDraft
                        ) {
                            "blog"
                        } else {
                            "page"
                        }
                    ),
                    format!(
                        "- Lifecycle: {}",
                        if matches!(
                            kind,
                            ConfluenceContentKind::PageDraft | ConfluenceContentKind::BlogDraft
                        ) {
                            "draft"
                        } else {
                            "current"
                        }
                    ),
                    format!(
                        "- Status: {}",
                        if matches!(
                            kind,
                            ConfluenceContentKind::PageDraft | ConfluenceContentKind::BlogDraft
                        ) {
                            "draft"
                        } else {
                            "current"
                        }
                    ),
                    "- Version: `2`".to_string(),
                    "- Created: `2026-08-01`".to_string(),
                    "- Updated: `2026-08-02`".to_string(),
                    "- Created by: Ada (account ID: `a1`)".to_string(),
                    "- Updated by: account ID: `a2`".to_string(),
                    "- URL: <https://example.test/content/10>".to_string(),
                    "- Space URL: <https://example.test/spaces/SPACE>".to_string(),
                    "## Body\n\nbody".to_string(),
                ]);
                expected.push(
                    match kind {
                        ConfluenceContentKind::Page => "- Operation: `page.view`",
                        ConfluenceContentKind::Blog => "- Operation: `blog.view`",
                        ConfluenceContentKind::PageDraft => "- Operation: `page.draft.view`",
                        ConfluenceContentKind::BlogDraft => "- Operation: `blog.draft.view`",
                    }
                    .to_string(),
                );
                expected.push(
                    if matches!(
                        kind,
                        ConfluenceContentKind::Blog | ConfluenceContentKind::BlogDraft
                    ) {
                        "- Blog ID: `10`"
                    } else {
                        "- Page ID: `10`"
                    }
                    .to_string(),
                );
                if matches!(
                    kind,
                    ConfluenceContentKind::PageDraft | ConfluenceContentKind::BlogDraft
                ) {
                    expected.extend([
                        "- Parent page ID: `9`".to_string(),
                        "- Draft handle: `opaque-handle`".to_string(),
                        "- Draft origin: broker\\_managed".to_string(),
                    ]);
                }
            }
            WholeRenderer::Search(kind) => {
                expected.extend([
                    format!(
                        "# Confluence {} search",
                        if kind == ConfluenceContentKind::Blog {
                            "blog"
                        } else {
                            "page"
                        }
                    ),
                    "- Count: 1".to_string(),
                    format!(
                        "- Operation: `{}`",
                        if kind == ConfluenceContentKind::Blog {
                            "blog.search"
                        } else {
                            "search"
                        }
                    ),
                    "## `10` — Title".to_string(),
                    "- Space: `SPACE`".to_string(),
                    "- Space ID: `99`".to_string(),
                    "- Status: current".to_string(),
                    "- Version: `2`".to_string(),
                    "- Created: `2026-08-01`".to_string(),
                    "- Updated: `2026-08-02`".to_string(),
                    "- Created by: Ada (account ID: `a1`)".to_string(),
                    "- Updated by: account ID: `a2`".to_string(),
                    "- URL: <https://example.test/content/10>".to_string(),
                    "- Space URL: <https://example.test/spaces/SPACE>".to_string(),
                    "## Pagination".to_string(),
                    "- Maximum results: `25`".to_string(),
                    "- Next page token: `opaque-token`".to_string(),
                ]);
                expected.push(
                    if kind == ConfluenceContentKind::Blog {
                        "- Blog ID: `10`"
                    } else {
                        "- Page ID: `10`"
                    }
                    .to_string(),
                );
            }
            WholeRenderer::Verify(kind) => {
                let lifecycle = if matches!(
                    kind,
                    ConfluenceContentKind::PageDraft | ConfluenceContentKind::BlogDraft
                ) {
                    "draft"
                } else {
                    "current"
                };
                expected.extend([
                    format!(
                        "# Confluence {} verification for `10`",
                        confluence_kind_label(kind)
                    ),
                    format!(
                        "- Operation: `{}`",
                        match kind {
                            ConfluenceContentKind::Page => "verify",
                            ConfluenceContentKind::Blog => "blog.verify",
                            ConfluenceContentKind::PageDraft => "page.draft.verify",
                            ConfluenceContentKind::BlogDraft => "blog.draft.verify",
                        }
                    ),
                    "- Space: `SPACE`".to_string(),
                    "- Space ID: `99`".to_string(),
                    format!("- Lifecycle: {lifecycle}"),
                    format!("- Content status: {lifecycle}"),
                    "- Status: mismatch".to_string(),
                    "## Checked\n- version".to_string(),
                    "  - ID: `10`".to_string(),
                    "  - Version: `2`".to_string(),
                    "  - Expected: `2`".to_string(),
                    "  - Actual: `1`".to_string(),
                    "  - Parent status: `current`".to_string(),
                    "## Mismatch\n- attachment".to_string(),
                    "  - ID: `77`".to_string(),
                    "  - Version: `3`".to_string(),
                    "  - Expected: `current`".to_string(),
                    "  - Actual: `draft`".to_string(),
                    "  - Parent status: `draft`".to_string(),
                ]);
            }
            WholeRenderer::AttachmentList(kind) => {
                let draft = matches!(
                    kind,
                    ConfluenceContentKind::PageDraft | ConfluenceContentKind::BlogDraft
                );
                expected.extend([
                    format!("# Confluence {} attachments", confluence_kind_label(kind)),
                    format!(
                        "- Operation: `{}`",
                        match kind {
                            ConfluenceContentKind::Page => "attachment.list",
                            ConfluenceContentKind::Blog => "blog.attachment.list",
                            ConfluenceContentKind::PageDraft => "page.draft.attachment.list",
                            ConfluenceContentKind::BlogDraft => {
                                "blog.draft.attachment.list"
                            }
                        }
                    ),
                    "- Space: `SPACE`".to_string(),
                    "- Space ID: `99`".to_string(),
                    format!("- Status: {}", if draft { "draft" } else { "current" }),
                    "- Count: 1".to_string(),
                    "## notes.txt".to_string(),
                    "- Attachment ID: `77`".to_string(),
                    "- Size: `12`".to_string(),
                    "- Content type: `text/plain`".to_string(),
                    format!(
                        "- Parent status: {}",
                        if draft { "draft" } else { "current" }
                    ),
                    "## Pagination".to_string(),
                    "- Has more: true".to_string(),
                    "- Next page token: `opaque-token`".to_string(),
                ]);
                expected.push(
                    if matches!(
                        kind,
                        ConfluenceContentKind::Blog | ConfluenceContentKind::BlogDraft
                    ) {
                        "- Blog ID: `10`"
                    } else {
                        "- Page ID: `10`"
                    }
                    .to_string(),
                );
            }
            WholeRenderer::CommentList | WholeRenderer::Comment => {
                expected.extend([
                    "comment `1`".to_string(),
                    "- Parent comment ID: `0`".to_string(),
                    "- Space: `SPACE`".to_string(),
                    "- Version: `2`".to_string(),
                    "- Created: `2026-08-01`".to_string(),
                    "- Updated: `2026-08-02`".to_string(),
                    "- Kind: footer".to_string(),
                    format!(
                        "- Container type: {}",
                        if action.starts_with("blog.") {
                            "blog"
                        } else {
                            "page"
                        }
                    ),
                    "- Status: current".to_string(),
                    "- Resolution status: open".to_string(),
                    "- Author: Ada (account ID: `a1`)".to_string(),
                    "### Body\n\nbody".to_string(),
                ]);
                if action.starts_with("blog.") {
                    expected.extend([
                        "- Blog ID: `10`".to_string(),
                        "- Space ID: `99`".to_string(),
                    ]);
                } else {
                    expected.push("- Page ID: `10`".to_string());
                }
                if renderer == WholeRenderer::CommentList {
                    expected.extend([
                        "# Confluence comments".to_string(),
                        "- Count: 1".to_string(),
                        "## Pagination".to_string(),
                        "- Has more: true".to_string(),
                        "- Next page token: `opaque-token`".to_string(),
                    ]);
                } else {
                    expected.push("# Confluence comment `1`".to_string());
                }
            }
        }

        for fragment in expected {
            assert!(
                markdown.contains(&fragment),
                "{action} missing {fragment:?} from {markdown}"
            );
        }
        assert!(
            !markdown.contains("<p>"),
            "{action} leaked storage HTML into {markdown}"
        );
    }

    #[test]
    fn every_confluence_whole_template_is_bounded_and_has_one_terminal_lf() {
        for descriptor in RESULT_DESCRIPTORS
            .iter()
            .filter(|descriptor| descriptor.whole.is_some())
        {
            let renderer = descriptor.whole.unwrap();
            let mut result = confluence_whole_fixture(renderer);
            if matches!(
                renderer,
                WholeRenderer::CommentList | WholeRenderer::Comment
            ) {
                let comment = if renderer == WholeRenderer::CommentList {
                    &mut result["comments"][0]
                } else {
                    &mut result["comment"]
                };
                let comment = comment.as_object_mut().unwrap();
                if descriptor.action.starts_with("blog.") {
                    comment.remove("pageId");
                    comment.insert("blogId".to_string(), json!("10"));
                    comment.insert("spaceId".to_string(), json!("99"));
                    comment.insert("containerType".to_string(), json!("blog"));
                } else {
                    comment.remove("spaceId");
                }
            }
            present_provider_result(
                descriptor.action,
                &mut result,
                ResponseOptions {
                    read_content_format: ReadContentFormat::Native,
                    response_format: ResponseFormat::Markdown,
                },
                4096,
                16384,
            )
            .unwrap();
            let markdown = result["value"].as_str().unwrap();
            assert!(
                markdown.ends_with('\n'),
                "{} lacks terminal LF",
                descriptor.action
            );
            assert!(
                !markdown.ends_with("\n\n"),
                "{} has multiple terminal LFs",
                descriptor.action
            );
            assert_confluence_whole_semantics(renderer, markdown, descriptor.action);
        }
    }

    #[test]
    fn confluence_empty_collections_are_explicit() {
        for (action, mut result) in [
            ("search", json!({"pages":[],"maxResults":25})),
            (
                "attachment.list",
                json!({"page":{"id":"10","space":"SPACE"},"attachments":[],"count":0,"hasMore":false}),
            ),
            (
                "page.footer_comment.list",
                json!({"comments":[],"count":0,"hasMore":false}),
            ),
        ] {
            present_provider_result(
                action,
                &mut result,
                ResponseOptions {
                    read_content_format: ReadContentFormat::Native,
                    response_format: ResponseFormat::Markdown,
                },
                4096,
                16384,
            )
            .unwrap();
            assert!(result["value"].as_str().unwrap().contains("No results."));
        }
    }

    #[test]
    fn confluence_whole_templates_include_modeled_metadata_and_convert_bodies_in_place() {
        let mut page =
            confluence_whole_fixture(WholeRenderer::Content(ConfluenceContentKind::Page));
        present_provider_result(
            "page.view",
            &mut page,
            ResponseOptions {
                read_content_format: ReadContentFormat::Native,
                response_format: ResponseFormat::Markdown,
            },
            4096,
            16384,
        )
        .unwrap();
        let markdown = page["value"].as_str().unwrap();
        for expected in [
            "# Confluence page `10` — Title",
            "- Space: `SPACE`",
            "- Version: `2`",
            "- Created by: Ada (account ID: `a1`)",
            "- URL: <https://example.test/content/10>",
            "## Body\n\nbody",
        ] {
            assert!(
                markdown.contains(expected),
                "missing {expected:?} from {markdown}"
            );
        }
        assert!(!markdown.contains("<p>"));

        let mut mismatch = json!({
            "pageId":"10", "space":"SPACE",
            "verification":{
                "status":"mismatch",
                "checked":[{"type":"pageVersion","version":2}],
                "mismatch":{"type":"attachment","id":"77","parentStatus":"draft"}
            }
        });
        present_provider_result(
            "verify",
            &mut mismatch,
            ResponseOptions {
                read_content_format: ReadContentFormat::Native,
                response_format: ResponseFormat::Markdown,
            },
            4096,
            16384,
        )
        .unwrap();
        let markdown = mismatch["value"].as_str().unwrap();
        assert!(markdown.contains("- Status: mismatch"));
        assert!(markdown.contains("## Mismatch\n- attachment\n  - ID: `77`"));
        assert!(markdown.contains("  - Parent status: `draft`"));
    }
}
