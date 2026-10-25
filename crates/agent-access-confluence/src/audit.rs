//! Reviewed original-input classifications. New schema fields require an explicit rule.
use agent_access_provider::{
    AuditDisplay, AuditInputProjection, AuditInputRule, AuditOverflow, AuditRole, AuditValueKind,
};

struct Field {
    rule: AuditInputRule,
    #[cfg(test)]
    element: &'static str,
    #[cfg(test)]
    reason: Option<&'static str>,
    #[cfg(test)]
    children: Vec<Field>,
}

fn field(rule: AuditInputRule, _element: &'static str, _reason: Option<&'static str>) -> Field {
    Field {
        rule,
        #[cfg(test)]
        element: _element,
        #[cfg(test)]
        reason: _reason,
        #[cfg(test)]
        children: Vec::new(),
    }
}
fn id(key: &str, label: &str, pointer: &str) -> Field {
    field(
        AuditInputRule::value(key, label, pointer)
            .kind(AuditValueKind::Identifier)
            .role(AuditRole::Target)
            .display(AuditDisplay::Primary)
            .max_bytes(1024)
            .overflow(AuditOverflow::Omit),
        "object.identity",
        None,
    )
}
fn ids(key: &str, label: &str, pointer: &str) -> Field {
    field(
        AuditInputRule::values(key, label, pointer)
            .kind(AuditValueKind::Identifier)
            .display(AuditDisplay::Primary)
            .max_bytes(1024)
            .overflow(AuditOverflow::Omit),
        "selection.identities",
        None,
    )
}
fn control(key: &str, label: &str, pointer: &str) -> Field {
    field(
        AuditInputRule::value(key, label, pointer)
            .kind(AuditValueKind::Text)
            .max_bytes(1024)
            .overflow(AuditOverflow::Omit),
        "operation.control",
        None,
    )
}
fn number(key: &str, label: &str, pointer: &str) -> Field {
    field(
        AuditInputRule::value(key, label, pointer).kind(AuditValueKind::Number),
        "operation.number",
        None,
    )
}
fn title(key: &str, label: &str, pointer: &str) -> Field {
    field(
        AuditInputRule::value(key, label, pointer)
            .kind(AuditValueKind::Text)
            .role(AuditRole::Change)
            .display(AuditDisplay::Primary)
            .max_bytes(1024)
            .overflow(AuditOverflow::Prefix),
        "object.title",
        None,
    )
}
fn query(key: &str, label: &str, pointer: &str) -> Field {
    field(
        AuditInputRule::value(key, label, pointer)
            .kind(AuditValueKind::Query)
            .display(AuditDisplay::Primary)
            .max_bytes(4096)
            .overflow(AuditOverflow::Prefix),
        "search.query",
        None,
    )
}
fn presence(
    key: &str,
    label: &str,
    pointer: &str,
    element: &'static str,
    reason: &'static str,
) -> Field {
    let rule = AuditInputRule::presence(key, label, pointer);
    let rule = if element == "content.body" || element == "property.opaque" {
        rule.role(AuditRole::Change)
    } else {
        rule
    };
    field(rule, element, Some(reason))
}
fn attachments() -> Field {
    let children = [
        field(
            AuditInputRule::value("filename", "Filename", "/filename")
                .kind(AuditValueKind::Path)
                .display(AuditDisplay::Primary)
                .max_bytes(1024)
                .overflow(AuditOverflow::Omit),
            "attachment.filename",
            None,
        ),
        field(
            AuditInputRule::value("contentType", "Media type", "/contentType")
                .kind(AuditValueKind::Text)
                .max_bytes(1024)
                .overflow(AuditOverflow::Omit),
            "attachment.media_type",
            None,
        ),
        field(
            AuditInputRule::value("size", "Size", "/size").kind(AuditValueKind::Bytes),
            "attachment.size",
            None,
        ),
        field(
            AuditInputRule::omit("field", "/field"),
            "transport.multipart_field",
            Some("Multipart field names are transport details, excluded from audit."),
        ),
        field(
            AuditInputRule::omit("sha256", "/sha256"),
            "content.fingerprint",
            Some("Requested content hashes are excluded; no body fingerprinting."),
        ),
    ];
    Field {
        rule: AuditInputRule::records(
            "attachments",
            "Attachments",
            "/attachments",
            children.iter().map(|field| field.rule.clone()),
        )
        .role(AuditRole::Change)
        .display(AuditDisplay::Primary),
        #[cfg(test)]
        element: "attachment.metadata",
        #[cfg(test)]
        reason: None,
        #[cfg(test)]
        children: children.into_iter().collect(),
    }
}

pub(super) fn projection(action: &str) -> AuditInputProjection {
    AuditInputProjection::new(fields(action).into_iter().map(|field| field.rule))
}

fn fields(action: &str) -> Vec<Field> {
    match action {
        "space.list" => vec![
            number("maxResults", "Max results", "/maxResults"),
            presence(
                "pageToken",
                "pageToken supplied",
                "/pageToken",
                "continuation.opaque",
                "Opaque continuations and handles have no captured value or length.",
            ),
        ],
        "page.view" => vec![
            id("pageId", "Page", "/pageId"),
            presence(
                "url",
                "url supplied",
                "/url",
                "locator.url",
                "Raw locator URLs can contain confidential paths or query parameters.",
            ),
        ],
        "search" => vec![
            control("query.type", "Query type", "/query/type"),
            query("query.value", "Query", "/query/value"),
            ids("spaces", "Spaces", "/spaces"),
            number("maxResults", "Max results", "/maxResults"),
            presence(
                "nextPageToken",
                "nextPageToken supplied",
                "/nextPageToken",
                "continuation.opaque",
                "Opaque continuations and handles have no captured value or length.",
            ),
        ],
        "page.create" => vec![
            id("space", "Space", "/space"),
            title("title", "Title", "/title"),
            id("parentPageId", "Parent page", "/parentPageId"),
            presence(
                "parentUrl",
                "parentUrl supplied",
                "/parentUrl",
                "locator.url",
                "Raw locator URLs can contain confidential paths or query parameters.",
            ),
            control("contentFormat", "Content format", "/contentFormat"),
            presence(
                "content",
                "content supplied",
                "/content",
                "content.body",
                "Polymorphic body content is excluded; provider processing byte counts remain.",
            ),
        ],
        "page.update" => vec![
            id("pageId", "Page", "/pageId"),
            number("baseVersion", "Base version", "/baseVersion"),
            title("title", "Title", "/title"),
            control("contentFormat", "Content format", "/contentFormat"),
            presence(
                "content",
                "content supplied",
                "/content",
                "content.body",
                "Polymorphic body content is excluded; provider processing byte counts remain.",
            ),
        ],
        "attachment.add" => vec![id("pageId", "Page", "/pageId"), attachments()],
        "attachment.download" => vec![
            id("pageId", "Page", "/pageId"),
            id("attachmentId", "Attachment", "/attachmentId"),
        ],
        "attachment.list" => vec![
            id("pageId", "Page", "/pageId"),
            presence(
                "url",
                "url supplied",
                "/url",
                "locator.url",
                "Raw locator URLs can contain confidential paths or query parameters.",
            ),
            number("maxResults", "Max results", "/maxResults"),
            presence(
                "nextPageToken",
                "nextPageToken supplied",
                "/nextPageToken",
                "continuation.opaque",
                "Opaque continuations and handles have no captured value or length.",
            ),
        ],
        "verify" => vec![
            id("pageId", "Page", "/pageId"),
            number("expectVersion", "Expect version", "/expectVersion"),
            expected_title("expectTitle", "Expect title", "/expectTitle"),
            id(
                "expectAttachmentId",
                "Expected attachment",
                "/expectAttachmentId",
            ),
        ],
        "page.draft.create" => vec![
            id("space", "Space", "/space"),
            title("title", "Title", "/title"),
            id("parentPageId", "Parent page", "/parentPageId"),
            presence(
                "parentUrl",
                "parentUrl supplied",
                "/parentUrl",
                "locator.url",
                "Raw locator URLs can contain confidential paths or query parameters.",
            ),
            control("contentFormat", "Content format", "/contentFormat"),
            presence(
                "content",
                "content supplied",
                "/content",
                "content.body",
                "Polymorphic body content is excluded; provider processing byte counts remain.",
            ),
        ],
        "page.draft.stage" => vec![
            id("pageId", "Page", "/pageId"),
            number("baseVersion", "Base version", "/baseVersion"),
            title("title", "Title", "/title"),
            control("contentFormat", "Content format", "/contentFormat"),
            presence(
                "content",
                "content supplied",
                "/content",
                "content.body",
                "Polymorphic body content is excluded; provider processing byte counts remain.",
            ),
        ],
        "page.draft.view" => vec![
            id("pageId", "Page", "/pageId"),
            presence(
                "draftHandle",
                "draftHandle supplied",
                "/draftHandle",
                "continuation.opaque",
                "Opaque continuations and handles have no captured value or length.",
            ),
            control("bodyFormat", "Body format", "/bodyFormat"),
        ],
        "page.draft.publish" => vec![
            id("pageId", "Page", "/pageId"),
            presence(
                "draftHandle",
                "draftHandle supplied",
                "/draftHandle",
                "continuation.opaque",
                "Opaque continuations and handles have no captured value or length.",
            ),
            control("bodyFormat", "Body format", "/bodyFormat"),
        ],
        "page.draft.update" => vec![
            id("pageId", "Page", "/pageId"),
            presence(
                "draftHandle",
                "draftHandle supplied",
                "/draftHandle",
                "continuation.opaque",
                "Opaque continuations and handles have no captured value or length.",
            ),
            title("title", "Title", "/title"),
            control("contentFormat", "Content format", "/contentFormat"),
            presence(
                "content",
                "content supplied",
                "/content",
                "content.body",
                "Polymorphic body content is excluded; provider processing byte counts remain.",
            ),
        ],
        "page.draft.discard" => vec![
            id("pageId", "Page", "/pageId"),
            presence(
                "draftHandle",
                "draftHandle supplied",
                "/draftHandle",
                "continuation.opaque",
                "Opaque continuations and handles have no captured value or length.",
            ),
        ],
        "page.draft.verify" => vec![
            id("pageId", "Page", "/pageId"),
            presence(
                "draftHandle",
                "draftHandle supplied",
                "/draftHandle",
                "continuation.opaque",
                "Opaque continuations and handles have no captured value or length.",
            ),
            number("expectVersion", "Expect version", "/expectVersion"),
            expected_title("expectTitle", "Expect title", "/expectTitle"),
            id(
                "expectAttachmentId",
                "Expected attachment",
                "/expectAttachmentId",
            ),
        ],
        "page.draft.attachment.add" => vec![
            id("pageId", "Page", "/pageId"),
            presence(
                "draftHandle",
                "draftHandle supplied",
                "/draftHandle",
                "continuation.opaque",
                "Opaque continuations and handles have no captured value or length.",
            ),
            attachments(),
        ],
        "page.draft.attachment.download" => vec![
            id("pageId", "Page", "/pageId"),
            presence(
                "draftHandle",
                "draftHandle supplied",
                "/draftHandle",
                "continuation.opaque",
                "Opaque continuations and handles have no captured value or length.",
            ),
            id("attachmentId", "Attachment", "/attachmentId"),
        ],
        "page.draft.attachment.list" => vec![
            id("pageId", "Page", "/pageId"),
            presence(
                "draftHandle",
                "draftHandle supplied",
                "/draftHandle",
                "continuation.opaque",
                "Opaque continuations and handles have no captured value or length.",
            ),
            number("maxResults", "Max results", "/maxResults"),
            presence(
                "nextPageToken",
                "nextPageToken supplied",
                "/nextPageToken",
                "continuation.opaque",
                "Opaque continuations and handles have no captured value or length.",
            ),
        ],
        "page.footer_comment.list" => vec![
            id("pageId", "Page", "/pageId"),
            control("bodyFormat", "Body format", "/bodyFormat"),
            control("sort", "Sort", "/sort"),
            number("maxResults", "Max results", "/maxResults"),
            presence(
                "nextPageToken",
                "nextPageToken supplied",
                "/nextPageToken",
                "continuation.opaque",
                "Opaque continuations and handles have no captured value or length.",
            ),
        ],
        "page.footer_comment.view" => vec![
            id("commentId", "Comment", "/commentId"),
            control("bodyFormat", "Body format", "/bodyFormat"),
        ],
        "page.footer_comment.update" => vec![
            id("commentId", "Comment", "/commentId"),
            number("baseVersion", "Base version", "/baseVersion"),
            control("contentFormat", "Content format", "/contentFormat"),
            presence(
                "content",
                "content supplied",
                "/content",
                "content.body",
                "Polymorphic body content is excluded; provider processing byte counts remain.",
            ),
        ],
        "page.footer_comment.delete" => vec![id("commentId", "Comment", "/commentId")],
        "page.footer_comment.add" => vec![
            id("pageId", "Page", "/pageId"),
            control("contentFormat", "Content format", "/contentFormat"),
            presence(
                "content",
                "content supplied",
                "/content",
                "content.body",
                "Polymorphic body content is excluded; provider processing byte counts remain.",
            ),
        ],
        "page.footer_comment.reply.list" => vec![
            id("commentId", "Parent comment", "/commentId"),
            control("bodyFormat", "Body format", "/bodyFormat"),
            number("maxResults", "Max results", "/maxResults"),
            presence(
                "nextPageToken",
                "nextPageToken supplied",
                "/nextPageToken",
                "continuation.opaque",
                "Opaque continuations and handles have no captured value or length.",
            ),
        ],
        "page.footer_comment.reply.add" => vec![
            id("commentId", "Parent comment", "/commentId"),
            control("contentFormat", "Content format", "/contentFormat"),
            presence(
                "content",
                "content supplied",
                "/content",
                "content.body",
                "Polymorphic body content is excluded; provider processing byte counts remain.",
            ),
        ],
        "page.inline_comment.list" => vec![
            id("pageId", "Page", "/pageId"),
            control("bodyFormat", "Body format", "/bodyFormat"),
            control("sort", "Sort", "/sort"),
            number("maxResults", "Max results", "/maxResults"),
            presence(
                "nextPageToken",
                "nextPageToken supplied",
                "/nextPageToken",
                "continuation.opaque",
                "Opaque continuations and handles have no captured value or length.",
            ),
            control("resolutionStatus", "Resolution status", "/resolutionStatus"),
        ],
        "page.inline_comment.view" => vec![
            id("commentId", "Comment", "/commentId"),
            control("bodyFormat", "Body format", "/bodyFormat"),
        ],
        "page.inline_comment.update" => vec![
            id("commentId", "Comment", "/commentId"),
            number("baseVersion", "Base version", "/baseVersion"),
            control("contentFormat", "Content format", "/contentFormat"),
            presence(
                "content",
                "content supplied",
                "/content",
                "content.body",
                "Polymorphic body content is excluded; provider processing byte counts remain.",
            ),
        ],
        "page.inline_comment.delete" => vec![id("commentId", "Comment", "/commentId")],
        "page.inline_comment.reply.list" => vec![
            id("commentId", "Parent comment", "/commentId"),
            control("bodyFormat", "Body format", "/bodyFormat"),
            number("maxResults", "Max results", "/maxResults"),
            presence(
                "nextPageToken",
                "nextPageToken supplied",
                "/nextPageToken",
                "continuation.opaque",
                "Opaque continuations and handles have no captured value or length.",
            ),
        ],
        "page.inline_comment.reply.add" => vec![
            id("commentId", "Parent comment", "/commentId"),
            control("contentFormat", "Content format", "/contentFormat"),
            presence(
                "content",
                "content supplied",
                "/content",
                "content.body",
                "Polymorphic body content is excluded; provider processing byte counts remain.",
            ),
        ],
        "blog.view" => vec![
            id("blogId", "Blog", "/blogId"),
            presence(
                "url",
                "url supplied",
                "/url",
                "locator.url",
                "Raw locator URLs can contain confidential paths or query parameters.",
            ),
        ],
        "blog.search" => vec![
            control("query.type", "Query type", "/query/type"),
            query("query.value", "Query", "/query/value"),
            ids("spaces", "Spaces", "/spaces"),
            number("maxResults", "Max results", "/maxResults"),
            presence(
                "nextPageToken",
                "nextPageToken supplied",
                "/nextPageToken",
                "continuation.opaque",
                "Opaque continuations and handles have no captured value or length.",
            ),
        ],
        "blog.create" => vec![
            id("space", "Space", "/space"),
            title("title", "Title", "/title"),
            control("contentFormat", "Content format", "/contentFormat"),
            presence(
                "content",
                "content supplied",
                "/content",
                "content.body",
                "Polymorphic body content is excluded; provider processing byte counts remain.",
            ),
        ],
        "blog.update" => vec![
            id("blogId", "Blog", "/blogId"),
            number("baseVersion", "Base version", "/baseVersion"),
            title("title", "Title", "/title"),
            byte_count(
                "versionMessage",
                "Version message bytes",
                "/versionMessage",
                "content.message",
            ),
            control("contentFormat", "Content format", "/contentFormat"),
            presence(
                "content",
                "content supplied",
                "/content",
                "content.body",
                "Polymorphic body content is excluded; provider processing byte counts remain.",
            ),
        ],
        "blog.attachment.add" => vec![id("blogId", "Blog", "/blogId"), attachments()],
        "blog.attachment.download" => vec![
            id("blogId", "Blog", "/blogId"),
            id("attachmentId", "Attachment", "/attachmentId"),
        ],
        "blog.attachment.list" => vec![
            id("blogId", "Blog", "/blogId"),
            presence(
                "url",
                "url supplied",
                "/url",
                "locator.url",
                "Raw locator URLs can contain confidential paths or query parameters.",
            ),
            number("maxResults", "Max results", "/maxResults"),
            presence(
                "nextPageToken",
                "nextPageToken supplied",
                "/nextPageToken",
                "continuation.opaque",
                "Opaque continuations and handles have no captured value or length.",
            ),
        ],
        "blog.verify" => vec![
            id("blogId", "Blog", "/blogId"),
            number("expectVersion", "Expect version", "/expectVersion"),
            expected_title("expectTitle", "Expect title", "/expectTitle"),
            id(
                "expectAttachmentId",
                "Expected attachment",
                "/expectAttachmentId",
            ),
        ],
        "blog.draft.create" => vec![
            id("space", "Space", "/space"),
            title("title", "Title", "/title"),
            control("contentFormat", "Content format", "/contentFormat"),
            presence(
                "content",
                "content supplied",
                "/content",
                "content.body",
                "Polymorphic body content is excluded; provider processing byte counts remain.",
            ),
        ],
        "blog.draft.stage" => vec![
            id("blogId", "Blog", "/blogId"),
            number("baseVersion", "Base version", "/baseVersion"),
            title("title", "Title", "/title"),
            control("contentFormat", "Content format", "/contentFormat"),
            presence(
                "content",
                "content supplied",
                "/content",
                "content.body",
                "Polymorphic body content is excluded; provider processing byte counts remain.",
            ),
        ],
        "blog.draft.view" => vec![
            id("blogId", "Blog", "/blogId"),
            presence(
                "draftHandle",
                "draftHandle supplied",
                "/draftHandle",
                "continuation.opaque",
                "Opaque continuations and handles have no captured value or length.",
            ),
            control("bodyFormat", "Body format", "/bodyFormat"),
        ],
        "blog.draft.publish" => vec![
            id("blogId", "Blog", "/blogId"),
            presence(
                "draftHandle",
                "draftHandle supplied",
                "/draftHandle",
                "continuation.opaque",
                "Opaque continuations and handles have no captured value or length.",
            ),
            control("bodyFormat", "Body format", "/bodyFormat"),
        ],
        "blog.draft.update" => vec![
            id("blogId", "Blog", "/blogId"),
            presence(
                "draftHandle",
                "draftHandle supplied",
                "/draftHandle",
                "continuation.opaque",
                "Opaque continuations and handles have no captured value or length.",
            ),
            title("title", "Title", "/title"),
            control("contentFormat", "Content format", "/contentFormat"),
            presence(
                "content",
                "content supplied",
                "/content",
                "content.body",
                "Polymorphic body content is excluded; provider processing byte counts remain.",
            ),
        ],
        "blog.draft.discard" => vec![
            id("blogId", "Blog", "/blogId"),
            presence(
                "draftHandle",
                "draftHandle supplied",
                "/draftHandle",
                "continuation.opaque",
                "Opaque continuations and handles have no captured value or length.",
            ),
        ],
        "blog.draft.verify" => vec![
            id("blogId", "Blog", "/blogId"),
            presence(
                "draftHandle",
                "draftHandle supplied",
                "/draftHandle",
                "continuation.opaque",
                "Opaque continuations and handles have no captured value or length.",
            ),
            number("expectVersion", "Expect version", "/expectVersion"),
            expected_title("expectTitle", "Expect title", "/expectTitle"),
            id(
                "expectAttachmentId",
                "Expected attachment",
                "/expectAttachmentId",
            ),
        ],
        "blog.draft.attachment.add" => vec![
            id("blogId", "Blog", "/blogId"),
            presence(
                "draftHandle",
                "draftHandle supplied",
                "/draftHandle",
                "continuation.opaque",
                "Opaque continuations and handles have no captured value or length.",
            ),
            attachments(),
        ],
        "blog.draft.attachment.download" => vec![
            id("blogId", "Blog", "/blogId"),
            presence(
                "draftHandle",
                "draftHandle supplied",
                "/draftHandle",
                "continuation.opaque",
                "Opaque continuations and handles have no captured value or length.",
            ),
            id("attachmentId", "Attachment", "/attachmentId"),
        ],
        "blog.draft.attachment.list" => vec![
            id("blogId", "Blog", "/blogId"),
            presence(
                "draftHandle",
                "draftHandle supplied",
                "/draftHandle",
                "continuation.opaque",
                "Opaque continuations and handles have no captured value or length.",
            ),
            number("maxResults", "Max results", "/maxResults"),
            presence(
                "nextPageToken",
                "nextPageToken supplied",
                "/nextPageToken",
                "continuation.opaque",
                "Opaque continuations and handles have no captured value or length.",
            ),
        ],
        "blog.footer_comment.list" => vec![
            id("blogId", "Blog", "/blogId"),
            control("bodyFormat", "Body format", "/bodyFormat"),
            control("sort", "Sort", "/sort"),
            number("maxResults", "Max results", "/maxResults"),
            presence(
                "nextPageToken",
                "nextPageToken supplied",
                "/nextPageToken",
                "continuation.opaque",
                "Opaque continuations and handles have no captured value or length.",
            ),
        ],
        "blog.footer_comment.view" => vec![
            id("commentId", "Comment", "/commentId"),
            control("bodyFormat", "Body format", "/bodyFormat"),
        ],
        "blog.footer_comment.update" => vec![
            id("commentId", "Comment", "/commentId"),
            number("baseVersion", "Base version", "/baseVersion"),
            control("contentFormat", "Content format", "/contentFormat"),
            presence(
                "content",
                "content supplied",
                "/content",
                "content.body",
                "Polymorphic body content is excluded; provider processing byte counts remain.",
            ),
        ],
        "blog.footer_comment.delete" => vec![id("commentId", "Comment", "/commentId")],
        "blog.footer_comment.add" => vec![
            id("blogId", "Blog", "/blogId"),
            control("contentFormat", "Content format", "/contentFormat"),
            presence(
                "content",
                "content supplied",
                "/content",
                "content.body",
                "Polymorphic body content is excluded; provider processing byte counts remain.",
            ),
        ],
        "blog.footer_comment.reply.list" => vec![
            id("commentId", "Parent comment", "/commentId"),
            control("bodyFormat", "Body format", "/bodyFormat"),
            number("maxResults", "Max results", "/maxResults"),
            presence(
                "nextPageToken",
                "nextPageToken supplied",
                "/nextPageToken",
                "continuation.opaque",
                "Opaque continuations and handles have no captured value or length.",
            ),
        ],
        "blog.footer_comment.reply.add" => vec![
            id("commentId", "Parent comment", "/commentId"),
            control("contentFormat", "Content format", "/contentFormat"),
            presence(
                "content",
                "content supplied",
                "/content",
                "content.body",
                "Polymorphic body content is excluded; provider processing byte counts remain.",
            ),
        ],
        "blog.inline_comment.list" => vec![
            id("blogId", "Blog", "/blogId"),
            control("bodyFormat", "Body format", "/bodyFormat"),
            control("sort", "Sort", "/sort"),
            number("maxResults", "Max results", "/maxResults"),
            presence(
                "nextPageToken",
                "nextPageToken supplied",
                "/nextPageToken",
                "continuation.opaque",
                "Opaque continuations and handles have no captured value or length.",
            ),
            control("resolutionStatus", "Resolution status", "/resolutionStatus"),
        ],
        "blog.inline_comment.view" => vec![
            id("commentId", "Comment", "/commentId"),
            control("bodyFormat", "Body format", "/bodyFormat"),
        ],
        "blog.inline_comment.update" => vec![
            id("commentId", "Comment", "/commentId"),
            number("baseVersion", "Base version", "/baseVersion"),
            control("contentFormat", "Content format", "/contentFormat"),
            presence(
                "content",
                "content supplied",
                "/content",
                "content.body",
                "Polymorphic body content is excluded; provider processing byte counts remain.",
            ),
        ],
        "blog.inline_comment.delete" => vec![id("commentId", "Comment", "/commentId")],
        "blog.inline_comment.reply.list" => vec![
            id("commentId", "Parent comment", "/commentId"),
            control("bodyFormat", "Body format", "/bodyFormat"),
            number("maxResults", "Max results", "/maxResults"),
            presence(
                "nextPageToken",
                "nextPageToken supplied",
                "/nextPageToken",
                "continuation.opaque",
                "Opaque continuations and handles have no captured value or length.",
            ),
        ],
        "blog.inline_comment.reply.add" => vec![
            id("commentId", "Parent comment", "/commentId"),
            control("contentFormat", "Content format", "/contentFormat"),
            presence(
                "content",
                "content supplied",
                "/content",
                "content.body",
                "Polymorphic body content is excluded; provider processing byte counts remain.",
            ),
        ],
        "page.move" => vec![
            id("pageId", "Page", "/pageId"),
            presence(
                "url",
                "url supplied",
                "/url",
                "locator.url",
                "Raw locator URLs can contain confidential paths or query parameters.",
            ),
            control("position", "Position", "/position"),
            id("targetPageId", "Target page", "/targetPageId"),
            presence(
                "targetUrl",
                "targetUrl supplied",
                "/targetUrl",
                "locator.url",
                "Raw locator URLs can contain confidential paths or query parameters.",
            ),
        ],
        _ => panic!("unclassified confluence action: {action}"),
    }
}

fn byte_count(key: &str, label: &str, pointer: &str, element: &'static str) -> Field {
    field(
        AuditInputRule::utf8_byte_count(key, label, pointer).role(AuditRole::Change),
        element,
        Some("Message text is excluded; only its original UTF-8 byte count is retained."),
    )
}

fn expected_title(key: &str, label: &str, pointer: &str) -> Field {
    let mut field = title(key, label, pointer);
    field.rule = field.rule.role(AuditRole::Fact);
    field
}

#[cfg(test)]
#[path = "../../agent-access-conformance/src/audit_inventory_test.rs"]
pub(super) mod inventory;
#[cfg(test)]
mod tests;
