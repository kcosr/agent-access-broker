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
fn identifier_control(key: &str, label: &str, pointer: &str) -> Field {
    field(
        AuditInputRule::value(key, label, pointer)
            .kind(AuditValueKind::Identifier)
            .role(AuditRole::Fact)
            .display(AuditDisplay::Detail)
            .max_bytes(1024)
            .overflow(AuditOverflow::Omit),
        "operation.control",
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
        "issue_type.list" => vec![
            id("project", "Project", "/project"),
            number("startAt", "Start at", "/startAt"),
            number("maxResults", "Max results", "/maxResults"),
        ],
        "project.list" => vec![
            number("maxResults", "Max results", "/maxResults"),
            presence(
                "pageToken",
                "pageToken supplied",
                "/pageToken",
                "continuation.opaque",
                "Opaque continuations and handles have no captured value or length.",
            ),
        ],
        "project.view" => vec![
            id("project", "Project", "/project"),
            field(
                AuditInputRule::values("include", "Included sections", "/include")
                    .kind(AuditValueKind::Text)
                    .max_bytes(1024)
                    .overflow(AuditOverflow::Omit),
                "operation.projection",
                None,
            ),
            query("query", "Query", "/query"),
        ],
        "issue.view" => vec![
            id("issue", "Issue", "/issue"),
            presence(
                "url",
                "url supplied",
                "/url",
                "locator.url",
                "Raw locator URLs can contain confidential paths or query parameters.",
            ),
        ],
        "issue.create" => vec![
            id("project", "Project", "/project"),
            identifier_control("issueTypeId", "Issue type", "/issueTypeId"),
            title("summary", "Summary", "/summary"),
            control("contentFormat", "Content format", "/contentFormat"),
            presence(
                "content",
                "content supplied",
                "/content",
                "content.body",
                "Polymorphic body content is excluded; provider processing byte counts remain.",
            ),
        ],
        "issue.child.create" => vec![
            id("project", "Project", "/project"),
            identifier_control("issueTypeId", "Issue type", "/issueTypeId"),
            id("parentIssue", "Parent issue", "/parentIssue"),
            presence(
                "parentUrl",
                "parentUrl supplied",
                "/parentUrl",
                "locator.url",
                "Raw locator URLs can contain confidential paths or query parameters.",
            ),
            title("summary", "Summary", "/summary"),
            control("contentFormat", "Content format", "/contentFormat"),
            presence(
                "content",
                "content supplied",
                "/content",
                "content.body",
                "Polymorphic body content is excluded; provider processing byte counts remain.",
            ),
        ],
        "issue.update" => vec![
            id("issue", "Issue", "/issue"),
            presence(
                "url",
                "url supplied",
                "/url",
                "locator.url",
                "Raw locator URLs can contain confidential paths or query parameters.",
            ),
            title("summary", "Summary", "/summary"),
            control("contentFormat", "Content format", "/contentFormat"),
            presence(
                "content",
                "content supplied",
                "/content",
                "content.body",
                "Polymorphic body content is excluded; provider processing byte counts remain.",
            ),
            boolean("notifyUsers", "Notify users", "/notifyUsers"),
        ],
        "issue.parent.set" => vec![
            id("issue", "Issue", "/issue"),
            presence(
                "url",
                "url supplied",
                "/url",
                "locator.url",
                "Raw locator URLs can contain confidential paths or query parameters.",
            ),
            id("parentIssue", "Parent issue", "/parentIssue"),
            presence(
                "parentUrl",
                "parentUrl supplied",
                "/parentUrl",
                "locator.url",
                "Raw locator URLs can contain confidential paths or query parameters.",
            ),
        ],
        "issue.dependency.add" => vec![
            id("blockingIssue", "Blocking issue", "/blockingIssue"),
            presence(
                "blockingUrl",
                "blockingUrl supplied",
                "/blockingUrl",
                "locator.url",
                "Raw locator URLs can contain confidential paths or query parameters.",
            ),
            id("blockedIssue", "Blocked issue", "/blockedIssue"),
            presence(
                "blockedUrl",
                "blockedUrl supplied",
                "/blockedUrl",
                "locator.url",
                "Raw locator URLs can contain confidential paths or query parameters.",
            ),
        ],
        "search" => vec![
            control("query.type", "Query type", "/query/type"),
            query("query.value", "Query", "/query/value"),
            ids("projects", "Projects", "/projects"),
            number("maxResults", "Max results", "/maxResults"),
            presence(
                "nextPageToken",
                "nextPageToken supplied",
                "/nextPageToken",
                "continuation.opaque",
                "Opaque continuations and handles have no captured value or length.",
            ),
        ],
        "comment.list" => vec![
            id("issue", "Issue", "/issue"),
            presence(
                "url",
                "url supplied",
                "/url",
                "locator.url",
                "Raw locator URLs can contain confidential paths or query parameters.",
            ),
            number("maxResults", "Max results", "/maxResults"),
            number("startAt", "Start at", "/startAt"),
            control("orderBy", "Order by", "/orderBy"),
        ],
        "comment.view" => vec![
            id("issue", "Issue", "/issue"),
            presence(
                "url",
                "url supplied",
                "/url",
                "locator.url",
                "Raw locator URLs can contain confidential paths or query parameters.",
            ),
            id("commentId", "Comment", "/commentId"),
        ],
        "comment.add" => vec![
            id("issue", "Issue", "/issue"),
            presence(
                "url",
                "url supplied",
                "/url",
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
            control("visibility.type", "Visibility type", "/visibility/type"),
            identifier_control(
                "visibility.value",
                "Visibility group or role",
                "/visibility/value",
            ),
            identifier_control(
                "visibility.identifier",
                "Visibility identifier",
                "/visibility/identifier",
            ),
        ],
        "comment.reply" => vec![
            id("issue", "Issue", "/issue"),
            presence(
                "url",
                "url supplied",
                "/url",
                "locator.url",
                "Raw locator URLs can contain confidential paths or query parameters.",
            ),
            id("parentCommentId", "Parent comment", "/parentCommentId"),
            control("contentFormat", "Content format", "/contentFormat"),
            presence(
                "content",
                "content supplied",
                "/content",
                "content.body",
                "Polymorphic body content is excluded; provider processing byte counts remain.",
            ),
            control("visibility.type", "Visibility type", "/visibility/type"),
            identifier_control(
                "visibility.value",
                "Visibility group or role",
                "/visibility/value",
            ),
            identifier_control(
                "visibility.identifier",
                "Visibility identifier",
                "/visibility/identifier",
            ),
        ],
        "comment.update" => vec![
            id("issue", "Issue", "/issue"),
            presence(
                "url",
                "url supplied",
                "/url",
                "locator.url",
                "Raw locator URLs can contain confidential paths or query parameters.",
            ),
            id("commentId", "Comment", "/commentId"),
            control("contentFormat", "Content format", "/contentFormat"),
            presence(
                "content",
                "content supplied",
                "/content",
                "content.body",
                "Polymorphic body content is excluded; provider processing byte counts remain.",
            ),
            control("visibilityMode", "Visibility mode", "/visibilityMode"),
            control("visibility.type", "Visibility type", "/visibility/type"),
            identifier_control(
                "visibility.value",
                "Visibility group or role",
                "/visibility/value",
            ),
            identifier_control(
                "visibility.identifier",
                "Visibility identifier",
                "/visibility/identifier",
            ),
            boolean("notifyUsers", "Notify users", "/notifyUsers"),
        ],
        "comment.delete" => vec![
            id("issue", "Issue", "/issue"),
            presence(
                "url",
                "url supplied",
                "/url",
                "locator.url",
                "Raw locator URLs can contain confidential paths or query parameters.",
            ),
            id("commentId", "Comment", "/commentId"),
        ],
        "comment.property.list" => vec![
            id("issue", "Issue", "/issue"),
            presence(
                "url",
                "url supplied",
                "/url",
                "locator.url",
                "Raw locator URLs can contain confidential paths or query parameters.",
            ),
            id("commentId", "Comment", "/commentId"),
        ],
        "comment.property.get" => vec![
            id("issue", "Issue", "/issue"),
            presence(
                "url",
                "url supplied",
                "/url",
                "locator.url",
                "Raw locator URLs can contain confidential paths or query parameters.",
            ),
            id("commentId", "Comment", "/commentId"),
            id("propertyKey", "Property key", "/propertyKey"),
        ],
        "comment.property.set" => vec![
            id("issue", "Issue", "/issue"),
            presence(
                "url",
                "url supplied",
                "/url",
                "locator.url",
                "Raw locator URLs can contain confidential paths or query parameters.",
            ),
            id("commentId", "Comment", "/commentId"),
            id("propertyKey", "Property key", "/propertyKey"),
            presence(
                "value",
                "value supplied",
                "/value",
                "property.opaque",
                "Arbitrary property values and object keys are excluded.",
            ),
        ],
        "comment.property.delete" => vec![
            id("issue", "Issue", "/issue"),
            presence(
                "url",
                "url supplied",
                "/url",
                "locator.url",
                "Raw locator URLs can contain confidential paths or query parameters.",
            ),
            id("commentId", "Comment", "/commentId"),
            id("propertyKey", "Property key", "/propertyKey"),
        ],
        "attachment.add" => vec![id("issue", "Issue", "/issue"), attachments()],
        "attachment.download" => vec![
            id("issue", "Issue", "/issue"),
            id("attachmentId", "Attachment", "/attachmentId"),
        ],
        "attachment.list" => vec![
            id("issue", "Issue", "/issue"),
            presence(
                "url",
                "url supplied",
                "/url",
                "locator.url",
                "Raw locator URLs can contain confidential paths or query parameters.",
            ),
        ],
        "verify" => vec![
            id("issue", "Issue", "/issue"),
            identifier_control("expectCommentId", "Expected comment", "/expectCommentId"),
            identifier_control(
                "expectAttachmentId",
                "Expected attachment",
                "/expectAttachmentId",
            ),
        ],
        _ => panic!("unclassified jira action: {action}"),
    }
}

fn boolean(key: &str, label: &str, pointer: &str) -> Field {
    field(
        AuditInputRule::value(key, label, pointer)
            .kind(AuditValueKind::Boolean)
            .display(AuditDisplay::Primary),
        "operation.flag",
        None,
    )
}

#[cfg(test)]
#[path = "../../agent-access-conformance/src/audit_inventory_test.rs"]
pub(super) mod inventory;
#[cfg(test)]
mod tests;
