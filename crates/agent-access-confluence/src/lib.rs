//! Confluence backend: page, blog, draft, comment, attachment, search, and
//! verification actions against Confluence Cloud, authorized against
//! `confluence_space` resources.
mod backend;
mod config;
mod continuation;
mod cql;
mod present;
#[cfg(test)]
mod tests;
mod validation;

pub use backend::*;
pub use config::*;
use continuation::*;
use cql::*;
use validation::*;

use agent_access_atlassian::{
    atlassian_credential_authorization, validate_atlassian_gateway_credential,
};
use agent_access_content::{
    ContentWriteError, markdown_to_confluence_storage_bounded,
    plain_text_to_confluence_storage_bounded,
};
use agent_access_content::{append_adf_attribution, append_confluence_storage_attribution};
#[allow(unused_imports)]
use agent_access_provider::*;
use async_trait::async_trait;
use chrono::{NaiveDate, NaiveTime};
use regex::Regex;
use reqwest::Method;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};
use thiserror::Error;
use url::Url;

const MAX_COMMENT_PARENT_DEPTH: usize = 16;
const DRAFT_ATTACHMENT_LOOKUP_PAGE_SIZE: u32 = 200;
const MAX_DRAFT_ATTACHMENT_LOOKUP_PAGES: usize = 100;
const MAX_PAGE_ANCESTOR_LOOKUP_PAGES: usize = 100;
const MAX_PAGE_DIRECT_CHILD_LOOKUP_PAGES: usize = 100;
const CONFLUENCE_ATTRIBUTION_START_MARKER: &str = "<!-- agent-access-attribution:start -->";
const CONFLUENCE_ATTRIBUTION_END_MARKER: &str = "<!-- agent-access-attribution:end -->";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ConfluenceWriteTarget {
    CurrentPage,
    PageDraft,
    Blog,
    Comment,
}

#[derive(Debug, Clone)]
struct ConfluenceContentWriteAudit {
    requested_format: String,
    native_format: String,
    source_bytes: u64,
    final_native_bytes: u64,
}

#[derive(Clone)]
pub struct ConfluenceProvider {
    config: ConfluenceProviderConfig,
    limits: ProviderLimits,
    backend: Arc<dyn ConfluenceBackend>,
    /// Seals list and search continuations and draft handles.
    continuations: ConfluenceContinuations,
    attribution: ProviderAttributionConfig,
}

impl ConfluenceProvider {
    pub(crate) fn new(
        config: ConfluenceProviderConfig,
        host: &BuildContext<'_>,
    ) -> Result<Self, ProviderBuildError> {
        let limits = host.limits().clone();
        let backend = Arc::new(HttpConfluenceBackend::new(
            config.clone(),
            limits.clone(),
            host.clients(),
        )?);
        Ok(Self {
            continuations: ConfluenceContinuations::new(
                &config,
                &limits,
                host.stable_signing_key().cloned(),
            ),
            config,
            limits,
            backend,
            attribution: host.attribution().clone(),
        })
    }

    fn from_backend(
        config: ConfluenceProviderConfig,
        limits: ProviderLimits,
        backend: Arc<dyn ConfluenceBackend>,
    ) -> Self {
        Self {
            continuations: ConfluenceContinuations::new(&config, &limits, None),
            config,
            limits,
            backend,
            attribution: ProviderAttributionConfig::default(),
        }
    }

    pub fn with_backend(
        config: ConfluenceProviderConfig,
        limits: ProviderLimits,
        backend: Arc<dyn ConfluenceBackend>,
    ) -> Self {
        Self::from_backend(config, limits, backend)
    }

    pub fn with_backend_and_signing_key(
        config: ConfluenceProviderConfig,
        limits: ProviderLimits,
        backend: Arc<dyn ConfluenceBackend>,
        stable_signing_key: Arc<dyn StableSigningKey>,
    ) -> Self {
        Self {
            continuations: ConfluenceContinuations::new(&config, &limits, Some(stable_signing_key)),
            config,
            limits,
            backend,
            attribution: ProviderAttributionConfig::default(),
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum ConfluenceDraftContentType {
    Page,
    Blog,
}

impl ConfluenceDraftContentType {
    fn as_str(self) -> &'static str {
        match self {
            Self::Page => "page",
            Self::Blog => "blog",
        }
    }

    fn id_field(self) -> &'static str {
        match self {
            Self::Page => "pageId",
            Self::Blog => "blogId",
        }
    }

    fn validate_id(self, value: &str) -> Result<String, ProviderError> {
        match self {
            Self::Page => validate_page_id(value),
            Self::Blog => validate_blog_id(value),
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum ConfluenceDraftOrigin {
    New,
    Staged,
}

impl ConfluenceDraftOrigin {
    fn as_str(self) -> &'static str {
        match self {
            Self::New => "new",
            Self::Staged => "staged",
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ConfluenceCommentKind {
    Footer,
    Inline,
}

impl ConfluenceCommentKind {
    fn as_str(self) -> &'static str {
        match self {
            Self::Footer => "footer",
            Self::Inline => "inline",
        }
    }

    fn action_segment(self) -> &'static str {
        match self {
            Self::Footer => "footer_comment",
            Self::Inline => "inline_comment",
        }
    }

    fn path_collection(self) -> &'static str {
        match self {
            Self::Footer => "footer-comments",
            Self::Inline => "inline-comments",
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ConfluenceCommentContainerType {
    Page,
    Blog,
}

impl ConfluenceCommentContainerType {
    fn as_str(self) -> &'static str {
        match self {
            Self::Page => "page",
            Self::Blog => "blog",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ConfluenceCommentOperation {
    List,
    View,
    Add,
    Update,
    Delete,
    ReplyList,
    ReplyAdd,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ConfluenceCommentAction {
    container_type: ConfluenceCommentContainerType,
    kind: ConfluenceCommentKind,
    operation: ConfluenceCommentOperation,
}

fn confluence_comment_action(action: &str) -> Option<ConfluenceCommentAction> {
    let (container_type, rest) = action.split_once('.')?;
    let container_type = match container_type {
        "page" => ConfluenceCommentContainerType::Page,
        "blog" => ConfluenceCommentContainerType::Blog,
        _ => return None,
    };
    let (kind, operation) = match rest {
        "footer_comment.list" => (
            ConfluenceCommentKind::Footer,
            ConfluenceCommentOperation::List,
        ),
        "footer_comment.view" => (
            ConfluenceCommentKind::Footer,
            ConfluenceCommentOperation::View,
        ),
        "footer_comment.add" => (
            ConfluenceCommentKind::Footer,
            ConfluenceCommentOperation::Add,
        ),
        "footer_comment.update" => (
            ConfluenceCommentKind::Footer,
            ConfluenceCommentOperation::Update,
        ),
        "footer_comment.delete" => (
            ConfluenceCommentKind::Footer,
            ConfluenceCommentOperation::Delete,
        ),
        "footer_comment.reply.list" => (
            ConfluenceCommentKind::Footer,
            ConfluenceCommentOperation::ReplyList,
        ),
        "footer_comment.reply.add" => (
            ConfluenceCommentKind::Footer,
            ConfluenceCommentOperation::ReplyAdd,
        ),
        "inline_comment.list" => (
            ConfluenceCommentKind::Inline,
            ConfluenceCommentOperation::List,
        ),
        "inline_comment.view" => (
            ConfluenceCommentKind::Inline,
            ConfluenceCommentOperation::View,
        ),
        "inline_comment.update" => (
            ConfluenceCommentKind::Inline,
            ConfluenceCommentOperation::Update,
        ),
        "inline_comment.delete" => (
            ConfluenceCommentKind::Inline,
            ConfluenceCommentOperation::Delete,
        ),
        "inline_comment.reply.list" => (
            ConfluenceCommentKind::Inline,
            ConfluenceCommentOperation::ReplyList,
        ),
        "inline_comment.reply.add" => (
            ConfluenceCommentKind::Inline,
            ConfluenceCommentOperation::ReplyAdd,
        ),
        _ => return None,
    };
    Some(ConfluenceCommentAction {
        container_type,
        kind,
        operation,
    })
}

fn confluence_draft_action(action: &str) -> bool {
    action.starts_with("page.draft.") || action.starts_with("blog.draft.")
}

/// The normalized comment list a page token belongs to, beside the admitted
/// action and caller.
#[derive(Debug, Clone, PartialEq, Eq)]
struct ConfluenceCommentListBinding {
    kind: ConfluenceCommentKind,
    container_type: ConfluenceCommentContainerType,
    container_id: String,
    comment_id: Option<String>,
    space: String,
    body_format: Option<String>,
    resolution_status: Option<String>,
    sort: Option<String>,
    max_results: u32,
}

/// Confluence spaces, identified by space key.
pub static CONFLUENCE_SPACE_RESOURCE: ResourceTypeDescriptor = ResourceTypeDescriptor::new(
    ResourceType::from_static("confluence_space"),
    "Confluence space",
    "Confluence spaces",
    "ENG",
    is_space_key,
    &[],
);

/// Confluence's authoritative service descriptor, derived from its typed
/// configuration alone.
pub fn confluence_descriptor(config: &ConfluenceProviderConfig) -> ServiceDescriptor {
    let mut credentials =
        CredentialDescriptor::default().profile("confluence-cloud-api-token", "basic_api_token");
    if config.site().uses_gateway() {
        credentials = credentials.profile("confluence-bearer-token", "bearer_token");
    }
    let mut actions = confluence_content_actions(config);
    actions.extend(confluence_draft_actions(config));
    actions.extend(confluence_comment_actions(config));
    ServiceDescriptor::new("confluence", "Confluence")
        .with_resource_scopes(BTreeMap::from([(
            "space".to_string(),
            ResourceScopeCapabilities::new(
                crate::CONFLUENCE_SPACE_RESOURCE.id().clone(),
                vec!["exact".to_string(), "all".to_string()],
            ),
        )]))
        .with_actions(
            actions
                .into_iter()
                .map(|action| {
                    let presentation = present::presentation(&action.action);
                    action.presentation(presentation)
                })
                .collect(),
        )
        .with_credentials(credentials)
        .with_presentation_body_limit(config.content.max_body_bytes)
}

/// When a Confluence action needs the broker's lookup credential. Actions
/// whose space comes from upstream content metadata resolve their scope
/// before policy; broker-managed draft actions confirm draft state only at
/// execution.
fn confluence_lookup_requirement(action: &str) -> LookupRequirement {
    if confluence_comment_action(action).is_some() {
        return LookupRequirement::ScopeResolution;
    }
    match action {
        "page.view"
        | "page.create"
        | "page.update"
        | "page.move"
        | "attachment.add"
        | "attachment.download"
        | "attachment.list"
        | "verify"
        | "blog.view"
        | "blog.update"
        | "blog.attachment.add"
        | "blog.attachment.download"
        | "blog.attachment.list"
        | "blog.verify"
        | "page.draft.create"
        | "page.draft.stage"
        | "blog.draft.stage" => LookupRequirement::ScopeResolution,
        "blog.create" => LookupRequirement::Execution,
        _ if confluence_draft_action(action) => LookupRequirement::Execution,
        _ => LookupRequirement::None,
    }
}

/// A space-scoped Confluence action with the lookup requirement its name
/// implies.
fn confluence_read_action(
    action: impl Into<String>,
    description: impl Into<String>,
    input_schema: Value,
) -> ActionDescriptor {
    confluence_action(action, description, input_schema).read_only()
}

fn confluence_action(
    action: impl Into<String>,
    description: impl Into<String>,
    input_schema: Value,
) -> ActionDescriptor {
    let action = action.into();
    let lookup = confluence_lookup_requirement(&action);
    ActionDescriptor::new(action, description, input_schema)
        .scope("space")
        .credential_modes(["service", "per_user"])
        .lookup(lookup)
}

fn confluence_body_attribution(verb: AttributionVerb) -> AttributionCapability {
    AttributionCapability::required(verb, "body", AttributionRepresentation::ConfluenceStorage)
}

fn confluence_content_actions(config: &ConfluenceProviderConfig) -> Vec<ActionDescriptor> {
    let page_write_formats = confluence_write_formats(ConfluenceWriteTarget::CurrentPage, config);
    let blog_write_formats = confluence_write_formats(ConfluenceWriteTarget::Blog, config);
    let mut actions = vec![
        confluence_read_action(
            "page.view",
            "View a Confluence page after page-to-space confirmation",
            json!({
                "type": "object",
                "oneOf": [
                    { "required": ["pageId"] },
                    { "required": ["url"] }
                ],
                "properties": {
                    "pageId": { "type": "string" },
                    "url": { "type": "string" }
                },
                "additionalProperties": false
            }),
        ),
        confluence_read_action(
            "search",
            "Search Confluence pages with CQL or title text; omitted spaces use effective authorized spaces; empty CQL and ORDER BY alone are supported",
            json!({
                "type": "object",
                "required": ["query"],
                "properties": {
                    "query": {
                        "type": "object",
                        "required": ["type", "value"],
                        "properties": {
                            "type": { "type": "string", "enum": ["cql", "text"] },
                            "value": { "type": "string", "description": "CQL filter, ORDER BY alone, or empty CQL; text mode requires nonempty title text." }
                        },
                        "additionalProperties": false
                    },
                    "spaces": {
                        "description": "Optional narrowing to authorized space keys; omit to search all effective broker-authorized spaces.",
                        "type": "array",
                        "items": { "type": "string" },
                        "minItems": 1
                    },
                    "maxResults": { "type": "integer", "minimum": 1, "description": "Page size; defaults to and is capped by the configured search limit." },
                    "nextPageToken": { "type": "string", "description": "Continuation token from the previous response; reuse the same query and spaces." }
                },
                "additionalProperties": false
            }),
        )
        .search_contained()
        .documentation(cql_documentation(ConfluenceSearchContentKind::Page)),
        confluence_action(
            "page.create",
            "Create a Confluence page in an authorized space with optional parent placement",
            required_confluence_content_schema(
                json!({
                    "type": "object",
                    "required": ["space", "title"],
                    "properties": {
                        "space": { "type": "string" },
                        "title": { "type": "string" },
                        "parentPageId": { "type": "string" },
                        "parentUrl": { "type": "string" }
                    },
                    "additionalProperties": false,
                    "not": { "required": ["parentPageId", "parentUrl"] }
                }),
                &page_write_formats,
            ),
        )
        .attribution(confluence_body_attribution(AttributionVerb::Add)),
        confluence_action(
            "page.move",
            "Move an authorized Confluence page before, after, or under another authorized page",
            json!({
                "type": "object",
                "required": ["position"],
                "allOf": [
                    {
                        "oneOf": [
                            { "required": ["pageId"] },
                            { "required": ["url"] }
                        ]
                    },
                    {
                        "oneOf": [
                            { "required": ["targetPageId"] },
                            { "required": ["targetUrl"] }
                        ]
                    }
                ],
                "properties": {
                    "pageId": { "type": "string" },
                    "url": { "type": "string" },
                    "position": {
                        "type": "string",
                        "enum": ["before", "after", "append"]
                    },
                    "targetPageId": { "type": "string" },
                    "targetUrl": { "type": "string" }
                },
                "additionalProperties": false
            }),
        ),
        confluence_action(
            "page.update",
            "Update a Confluence page after page-to-space confirmation and base-version check",
            required_confluence_content_schema(
                json!({
                    "type": "object",
                    "required": ["pageId", "baseVersion"],
                    "properties": {
                        "pageId": { "type": "string" },
                        "baseVersion": { "type": "integer", "minimum": 1 },
                        "title": { "type": "string" }
                    },
                    "additionalProperties": false
                }),
                &page_write_formats,
            ),
        )
        .attribution(confluence_body_attribution(AttributionVerb::Update)),
        confluence_action(
            "attachment.add",
            "Upload bounded Confluence page attachments after page-to-space confirmation",
            json!({
                "type": "object",
                "required": ["pageId", "attachments"],
                "properties": {
                    "pageId": { "type": "string" },
                    "attachments": {
                        "type": "array",
                        "minItems": 1,
                        "items": {
                            "type": "object",
                            "required": ["field", "filename", "contentType", "size", "sha256"],
                            "properties": {
                                "field": { "type": "string" },
                                "filename": { "type": "string" },
                                "contentType": { "type": "string" },
                                "size": { "type": "integer", "minimum": 1 },
                                "sha256": { "type": "string" }
                            },
                            "additionalProperties": false
                        }
                    }
                },
                "additionalProperties": false
            }),
        )
        .multipart_upload(attachment_upload_plan(&["pageId"], None)),
        confluence_read_action(
            "attachment.download",
            "Download a bounded Confluence page attachment after membership checks",
            json!({
                "type": "object",
                "required": ["pageId", "attachmentId"],
                "properties": {
                    "pageId": { "type": "string" },
                    "attachmentId": { "type": "string" }
                },
                "additionalProperties": false
            }),
        )
        .raw_download(),
        confluence_read_action(
            "attachment.list",
            "List bounded Confluence page attachment metadata after page-to-space confirmation",
            json!({
                "type": "object",
                "oneOf": [
                    { "required": ["pageId"] },
                    { "required": ["url"] }
                ],
                "properties": {
                    "pageId": { "type": "string" },
                    "url": { "type": "string" },
                    "maxResults": { "type": "integer", "minimum": 1 },
                    "nextPageToken": { "type": "string" }
                },
                "additionalProperties": false
            }),
        ),
        confluence_read_action(
            "verify",
            "Verify Confluence page state or attachment membership",
            json!({
                "type": "object",
                "required": ["pageId"],
                "properties": {
                    "pageId": { "type": "string" },
                    "expectVersion": { "type": "integer", "minimum": 1 },
                    "expectTitle": { "type": "string" },
                    "expectAttachmentId": { "type": "string" }
                },
                "additionalProperties": false
            }),
        ),
        confluence_read_action(
            "blog.view",
            "View a current Confluence blog post after blog-to-space confirmation",
            json!({
                "type": "object",
                "oneOf": [
                    { "required": ["blogId"] },
                    { "required": ["url"] }
                ],
                "properties": {
                    "blogId": { "type": "string" },
                    "url": { "type": "string" }
                },
                "additionalProperties": false
            }),
        ),
        confluence_read_action(
            "blog.search",
            "Search Confluence blog posts with CQL or title text; omitted spaces use effective authorized spaces; empty CQL and ORDER BY alone are supported",
            json!({
                "type": "object",
                "required": ["query"],
                "properties": {
                    "query": {
                        "type": "object",
                        "required": ["type", "value"],
                        "properties": {
                            "type": { "type": "string", "enum": ["cql", "text"] },
                            "value": { "type": "string", "description": "CQL filter, ORDER BY alone, or empty CQL; text mode requires nonempty title text." }
                        },
                        "additionalProperties": false
                    },
                    "spaces": {
                        "description": "Optional narrowing to authorized space keys; omit to search all effective broker-authorized spaces.",
                        "type": "array",
                        "items": { "type": "string" },
                        "minItems": 1
                    },
                    "maxResults": { "type": "integer", "minimum": 1, "description": "Page size; defaults to and is capped by the configured search limit." },
                    "nextPageToken": { "type": "string", "description": "Continuation token from the previous response; reuse the same query and spaces." }
                },
                "additionalProperties": false
            }),
        )
        .search_contained()
        .documentation(cql_documentation(ConfluenceSearchContentKind::BlogPost)),
        confluence_action(
            "blog.create",
            "Create a current Confluence blog post in an authorized space",
            required_confluence_content_schema(
                json!({
                    "type": "object",
                    "required": ["space", "title"],
                    "properties": {
                        "space": { "type": "string" },
                        "title": { "type": "string" }
                    },
                    "additionalProperties": false
                }),
                &blog_write_formats,
            ),
        )
        .attribution(confluence_body_attribution(AttributionVerb::Add)),
        confluence_action(
            "blog.update",
            "Update a current Confluence blog post after blog-to-space confirmation and base-version check",
            required_confluence_content_schema(
                json!({
                    "type": "object",
                    "required": ["blogId", "baseVersion"],
                    "properties": {
                        "blogId": { "type": "string" },
                        "baseVersion": { "type": "integer", "minimum": 1 },
                        "title": { "type": "string" },
                        "versionMessage": { "type": "string" }
                    },
                    "additionalProperties": false
                }),
                &blog_write_formats,
            ),
        )
        .attribution(confluence_body_attribution(AttributionVerb::Update)),
        confluence_action(
            "blog.attachment.add",
            "Upload bounded Confluence blog attachments after blog-to-space confirmation",
            json!({
                "type": "object",
                "required": ["blogId", "attachments"],
                "properties": {
                    "blogId": { "type": "string" },
                    "attachments": {
                        "type": "array",
                        "minItems": 1,
                        "items": {
                            "type": "object",
                            "required": ["field", "filename", "contentType", "size", "sha256"],
                            "properties": {
                                "field": { "type": "string" },
                                "filename": { "type": "string" },
                                "contentType": { "type": "string" },
                                "size": { "type": "integer", "minimum": 1 },
                                "sha256": { "type": "string" }
                            },
                            "additionalProperties": false
                        }
                    }
                },
                "additionalProperties": false
            }),
        )
        .multipart_upload(attachment_upload_plan(&["blogId"], None)),
        confluence_read_action(
            "blog.attachment.download",
            "Download a bounded Confluence blog attachment after membership checks",
            json!({
                "type": "object",
                "required": ["blogId", "attachmentId"],
                "properties": {
                    "blogId": { "type": "string" },
                    "attachmentId": { "type": "string" }
                },
                "additionalProperties": false
            }),
        )
        .raw_download(),
        confluence_read_action(
            "blog.attachment.list",
            "List bounded Confluence blog attachment metadata after blog-to-space confirmation",
            json!({
                "type": "object",
                "oneOf": [
                    { "required": ["blogId"] },
                    { "required": ["url"] }
                ],
                "properties": {
                    "blogId": { "type": "string" },
                    "url": { "type": "string" },
                    "maxResults": { "type": "integer", "minimum": 1 },
                    "nextPageToken": { "type": "string" }
                },
                "additionalProperties": false
            }),
        ),
        confluence_read_action(
            "blog.verify",
            "Verify Confluence blog state or attachment membership",
            json!({
                "type": "object",
                "required": ["blogId"],
                "properties": {
                    "blogId": { "type": "string" },
                    "expectVersion": { "type": "integer", "minimum": 1 },
                    "expectTitle": { "type": "string" },
                    "expectAttachmentId": { "type": "string" }
                },
                "additionalProperties": false
            }),
        ),
    ];
    actions.retain(|action| {
        if matches!(action.action.as_str(), "page.create" | "page.update") {
            !page_write_formats.is_empty()
        } else if matches!(action.action.as_str(), "blog.create" | "blog.update") {
            !blog_write_formats.is_empty()
        } else {
            true
        }
    });
    actions
}

fn confluence_draft_actions(config: &ConfluenceProviderConfig) -> Vec<ActionDescriptor> {
    let mut actions = Vec::new();
    for (prefix, id_field, write_target) in [
        ("page", "pageId", ConfluenceWriteTarget::PageDraft),
        ("blog", "blogId", ConfluenceWriteTarget::Blog),
    ] {
        let write_formats = confluence_write_formats(write_target, config);
        let content_label = if prefix == "page" {
            "page"
        } else {
            "blog post"
        };
        let mut create_properties = serde_json::Map::from_iter([
            ("space".to_string(), json!({ "type": "string" })),
            ("title".to_string(), json!({ "type": "string" })),
        ]);
        if prefix == "page" {
            create_properties.insert("parentPageId".to_string(), json!({ "type": "string" }));
            create_properties.insert("parentUrl".to_string(), json!({ "type": "string" }));
        }
        let mut create_schema = required_confluence_content_schema(
            json!({
                "type": "object",
                "required": ["space", "title"],
                "properties": Value::Object(create_properties),
                "additionalProperties": false
            }),
            &write_formats,
        );
        if prefix == "page" {
            create_schema["not"] = json!({
                "required": ["parentPageId", "parentUrl"]
            });
        }
        if !write_formats.is_empty() {
            actions.push(
                confluence_action(
                    format!("{prefix}.draft.create"),
                    format!("Create a broker-managed Confluence {content_label} draft"),
                    create_schema,
                )
                .attribution(confluence_body_attribution(AttributionVerb::Add)),
            );
        }
        if !write_formats.is_empty() {
            actions.push(
                confluence_action(
                    format!("{prefix}.draft.stage"),
                    format!("Stage a broker-managed Confluence {content_label} draft revision"),
                    required_confluence_content_schema(
                        json!({
                            "type": "object",
                            "required": [id_field, "baseVersion"],
                            "properties": {
                                id_field: { "type": "string" },
                                "baseVersion": { "type": "integer", "minimum": 1 },
                                "title": { "type": "string" }
                            },
                            "additionalProperties": false
                        }),
                        &write_formats,
                    ),
                )
                .attribution(confluence_body_attribution(AttributionVerb::Add)),
            );
        }
        for action in ["view", "publish"] {
            let descriptor = confluence_action(
                format!("{prefix}.draft.{action}"),
                format!("{action} a broker-managed Confluence {content_label} draft"),
                json!({
                    "type": "object",
                    "required": [id_field, "draftHandle", "bodyFormat"],
                    "properties": {
                        id_field: { "type": "string" },
                        "draftHandle": { "type": "string" },
                        "bodyFormat": { "type": "string", "enum": ["storage"] }
                    },
                    "additionalProperties": false
                }),
            );
            actions.push(if action == "view" {
                descriptor.read_only()
            } else {
                descriptor
            });
        }
        if !write_formats.is_empty() {
            actions.push(
                confluence_action(
                    format!("{prefix}.draft.update"),
                    format!("Update a broker-managed Confluence {content_label} draft"),
                    required_confluence_content_schema(
                        json!({
                            "type": "object",
                            "required": [id_field, "draftHandle"],
                            "properties": {
                                id_field: { "type": "string" },
                                "draftHandle": { "type": "string" },
                                "title": { "type": "string" }
                            },
                            "additionalProperties": false
                        }),
                        &write_formats,
                    ),
                )
                .attribution(confluence_body_attribution(AttributionVerb::Update)),
            );
        }
        actions.push(confluence_action(
            format!("{prefix}.draft.discard"),
            format!("Discard a broker-created Confluence {content_label} draft"),
            json!({
                "type": "object",
                "required": [id_field, "draftHandle"],
                "properties": {
                    id_field: { "type": "string" },
                    "draftHandle": { "type": "string" }
                },
                "additionalProperties": false
            }),
        ));
        actions.push(confluence_read_action(
            format!("{prefix}.draft.verify"),
            format!("Verify broker-managed Confluence {content_label} draft state"),
            json!({
                "type": "object",
                "required": [id_field, "draftHandle"],
                "properties": {
                    id_field: { "type": "string" },
                    "draftHandle": { "type": "string" },
                    "expectVersion": { "type": "integer", "minimum": 1 },
                    "expectTitle": { "type": "string" },
                    "expectAttachmentId": { "type": "string" }
                },
                "additionalProperties": false
            }),
        ));
        actions.push(
            confluence_action(
                format!("{prefix}.draft.attachment.add"),
                format!("Upload bounded attachments to a broker-created Confluence {content_label} draft"),
                json!({
                    "type": "object",
                    "required": [id_field, "draftHandle", "attachments"],
                    "properties": {
                        id_field: { "type": "string" },
                        "draftHandle": { "type": "string" },
                        "attachments": {
                            "type": "array",
                            "minItems": 1,
                            "items": {
                                "type": "object",
                                "required": ["field", "filename", "contentType", "size", "sha256"],
                                "properties": {
                                    "field": { "type": "string" },
                                    "filename": { "type": "string" },
                                    "contentType": { "type": "string" },
                                    "size": { "type": "integer", "minimum": 1 },
                                    "sha256": { "type": "string" }
                                },
                                "additionalProperties": false
                            }
                        }
                    },
                    "additionalProperties": false
                }),
            )
            .multipart_upload(attachment_upload_plan(&[id_field, "draftHandle"], None)),
        );
        actions.push(
            confluence_read_action(
                format!("{prefix}.draft.attachment.download"),
                format!(
                    "Download a bounded broker-created Confluence {content_label} draft attachment"
                ),
                json!({
                    "type": "object",
                    "required": [id_field, "draftHandle", "attachmentId"],
                    "properties": {
                        id_field: { "type": "string" },
                        "draftHandle": { "type": "string" },
                        "attachmentId": { "type": "string" }
                    },
                    "additionalProperties": false
                }),
            )
            .raw_download(),
        );
        actions.push(confluence_read_action(
            format!("{prefix}.draft.attachment.list"),
            format!("List bounded broker-created Confluence {content_label} draft attachments"),
            json!({
                "type": "object",
                "required": [id_field, "draftHandle"],
                "properties": {
                    id_field: { "type": "string" },
                    "draftHandle": { "type": "string" },
                    "maxResults": { "type": "integer", "minimum": 1 },
                    "nextPageToken": { "type": "string" }
                },
                "additionalProperties": false
            }),
        ));
    }
    actions
        .into_iter()
        .map(ActionDescriptor::requires_stable_signing_key)
        .collect()
}

fn confluence_comment_actions(config: &ConfluenceProviderConfig) -> Vec<ActionDescriptor> {
    let mut actions = Vec::new();
    let write_formats = confluence_write_formats(ConfluenceWriteTarget::Comment, config);
    for container_type in [
        ConfluenceCommentContainerType::Page,
        ConfluenceCommentContainerType::Blog,
    ] {
        let container_prefix = container_type.as_str();
        let container_id_field = match container_type {
            ConfluenceCommentContainerType::Page => "pageId",
            ConfluenceCommentContainerType::Blog => "blogId",
        };
        for kind in [ConfluenceCommentKind::Footer, ConfluenceCommentKind::Inline] {
            let family = kind.action_segment();
            let comment_label = format!("{} {}", container_prefix, family.replace('_', " "));
            let list_action = format!("{container_prefix}.{family}.list");
            let mut list_properties = serde_json::Map::from_iter([
                (container_id_field.to_string(), json!({ "type": "string" })),
                (
                    "bodyFormat".to_string(),
                    json!({ "type": "string", "enum": ["storage"] }),
                ),
                (
                    "sort".to_string(),
                    json!({
                        "type": "string",
                        "enum": ["created-date", "-created-date", "modified-date", "-modified-date"]
                    }),
                ),
                (
                    "maxResults".to_string(),
                    json!({ "type": "integer", "minimum": 1 }),
                ),
                ("nextPageToken".to_string(), json!({ "type": "string" })),
            ]);
            if kind == ConfluenceCommentKind::Inline {
                list_properties.insert(
                    "resolutionStatus".to_string(),
                    json!({
                        "type": "string",
                        "enum": ["open", "reopened", "resolved", "dangling"]
                    }),
                );
            }
            actions.push(confluence_read_action(
                list_action,
                format!("List current {comment_label}s after container-to-space confirmation"),
                json!({
                    "type": "object",
                    "required": [container_id_field],
                    "properties": list_properties,
                    "additionalProperties": false
                }),
            ));

            let view_action = format!("{container_prefix}.{family}.view");
            actions.push(confluence_read_action(
                view_action,
                format!(
                    "View a current {comment_label} after comment-to-container space confirmation"
                ),
                json!({
                    "type": "object",
                    "required": ["commentId"],
                    "properties": {
                        "commentId": { "type": "string" },
                        "bodyFormat": { "type": "string", "enum": ["storage"] }
                    },
                    "additionalProperties": false
                }),
            ));

            let update_action = format!("{container_prefix}.{family}.update");
            if !write_formats.is_empty() {
                actions.push(confluence_action(
                    update_action,
                    format!(
                        "Update a current {comment_label} after comment-to-container space confirmation"
                    ),
                    required_confluence_content_schema(
                        json!({
                            "type": "object",
                            "required": ["commentId", "baseVersion"],
                            "properties": {
                                "commentId": { "type": "string" },
                                "baseVersion": { "type": "integer", "minimum": 1 }
                            },
                            "additionalProperties": false
                        }),
                        &write_formats,
                    ),
                ));
            }

            let delete_action = format!("{container_prefix}.{family}.delete");
            actions.push(confluence_action(
                delete_action,
                format!(
                    "Delete a current {comment_label} after comment-to-container space confirmation"
                ),
                json!({
                    "type": "object",
                    "required": ["commentId"],
                    "properties": {
                        "commentId": { "type": "string" }
                    },
                    "additionalProperties": false
                }),
            ));

            if kind == ConfluenceCommentKind::Footer && !write_formats.is_empty() {
                let add_action = format!("{container_prefix}.{family}.add");
                let add_properties = serde_json::Map::from_iter([(
                    container_id_field.to_string(),
                    json!({ "type": "string" }),
                )]);
                actions.push(
                    confluence_action(
                        add_action,
                        format!("Add a storage-format {comment_label} after container-to-space confirmation"),
                        required_confluence_content_schema(
                            json!({
                                "type": "object",
                                "required": [container_id_field],
                                "properties": add_properties,
                                "additionalProperties": false
                            }),
                            &write_formats,
                        ),
                    )
                    .attribution(confluence_body_attribution(AttributionVerb::Add)),
                );
            }

            let reply_list_action = format!("{container_prefix}.{family}.reply.list");
            actions.push(confluence_read_action(
                reply_list_action,
                format!("List current replies under a {comment_label} after comment-to-container space confirmation"),
                json!({
                    "type": "object",
                    "required": ["commentId"],
                    "properties": {
                        "commentId": { "type": "string" },
                        "bodyFormat": { "type": "string", "enum": ["storage"] },
                        "maxResults": { "type": "integer", "minimum": 1 },
                        "nextPageToken": { "type": "string" }
                    },
                    "additionalProperties": false
                }),
            ));

            let reply_add_action = format!("{container_prefix}.{family}.reply.add");
            if !write_formats.is_empty() {
                actions.push(
                    confluence_action(
                        reply_add_action,
                        format!("Reply to a current {comment_label} after comment-to-container space confirmation"),
                        required_confluence_content_schema(
                            json!({
                                "type": "object",
                                "required": ["commentId"],
                                "properties": {
                                    "commentId": { "type": "string" }
                                },
                                "additionalProperties": false
                            }),
                            &write_formats,
                        ),
                    )
                    .attribution(confluence_body_attribution(AttributionVerb::Add)),
                );
            }
        }
    }
    actions
}

impl ConfluenceProvider {
    fn local_scopes(&self, action: &str, inputs: &Value) -> Result<ResourceScopes, ProviderError> {
        match action {
            "page.view" => {
                let locator = page_locator_from_inputs(inputs, &self.config)?;
                let Some(space) = locator.candidate_space else {
                    return Err(ProviderError::deny(
                        ReasonCode::ScopeUnresolved,
                        "Confluence page scope requires lookup confirmation",
                    ));
                };
                let mut scopes = ResourceScopes::new();
                scopes.insert("space".to_string(), vec![space]);
                Ok(scopes)
            }
            "search" => {
                let inputs = parse_search_inputs(inputs)?;
                let requested = requested_spaces(&inputs)?;
                let mut scopes = ResourceScopes::new();
                scopes.insert("space".to_string(), requested.into_iter().collect());
                Ok(scopes)
            }
            "page.create" => {
                let inputs = parse_page_create_inputs(inputs, &self.config)?;
                let mut scopes = ResourceScopes::new();
                scopes.insert("space".to_string(), vec![inputs.space]);
                Ok(scopes)
            }
            "page.update" => {
                let inputs = parse_page_update_inputs(inputs)?;
                Err(page_scope_requires_lookup(inputs.page_id))
            }
            "page.move" => {
                let inputs = parse_page_move_inputs(inputs, &self.config)?;
                Err(page_scope_requires_lookup(inputs.page.page_id))
            }
            "page.draft.create" => {
                let inputs = parse_page_draft_create_inputs(inputs, &self.config)?;
                let mut scopes = ResourceScopes::new();
                scopes.insert("space".to_string(), vec![inputs.space]);
                Ok(scopes)
            }
            "page.draft.stage" => {
                let inputs = parse_page_draft_stage_inputs(inputs)?;
                Err(page_scope_requires_lookup(inputs.page_id))
            }
            "attachment.add" => {
                let inputs = parse_attachment_add_inputs(inputs)?;
                Err(page_scope_requires_lookup(inputs.page_id))
            }
            "attachment.download" => {
                let inputs = parse_attachment_download_inputs(inputs)?;
                Err(page_scope_requires_lookup(inputs.page_id))
            }
            "attachment.list" => {
                let inputs = parse_attachment_list_inputs(inputs, &self.config)?;
                Err(page_scope_requires_lookup(inputs.locator.page_id))
            }
            "verify" => {
                let inputs = parse_verify_inputs(inputs)?;
                Err(page_scope_requires_lookup(inputs.page_id))
            }
            "blog.view" => {
                let inputs = parse_blog_view_inputs(inputs, &self.config)?;
                Err(blog_scope_requires_lookup(inputs.locator.blog_id))
            }
            "blog.search" => {
                let inputs = parse_search_inputs(inputs)?;
                let requested = requested_spaces(&inputs)?;
                let mut scopes = ResourceScopes::new();
                scopes.insert("space".to_string(), requested.into_iter().collect());
                Ok(scopes)
            }
            "blog.create" => {
                let inputs = parse_blog_create_inputs(inputs)?;
                let mut scopes = ResourceScopes::new();
                scopes.insert("space".to_string(), vec![inputs.space]);
                Ok(scopes)
            }
            "blog.update" => {
                let inputs = parse_blog_update_inputs(inputs)?;
                Err(blog_scope_requires_lookup(inputs.blog_id))
            }
            "blog.draft.create" => {
                let inputs = parse_blog_draft_create_inputs(inputs)?;
                let mut scopes = ResourceScopes::new();
                scopes.insert("space".to_string(), vec![inputs.space]);
                Ok(scopes)
            }
            "blog.draft.stage" => {
                let inputs = parse_blog_draft_stage_inputs(inputs)?;
                Err(blog_scope_requires_lookup(inputs.blog_id))
            }
            "blog.attachment.add" => {
                let inputs = parse_blog_attachment_add_inputs(inputs)?;
                Err(blog_scope_requires_lookup(inputs.blog_id))
            }
            "blog.attachment.download" => {
                let inputs = parse_blog_attachment_download_inputs(inputs)?;
                Err(blog_scope_requires_lookup(inputs.blog_id))
            }
            "blog.attachment.list" => {
                let inputs = parse_blog_attachment_list_inputs(inputs, &self.config)?;
                Err(blog_scope_requires_lookup(inputs.locator.blog_id))
            }
            "blog.verify" => {
                let inputs = parse_blog_verify_inputs(inputs)?;
                Err(blog_scope_requires_lookup(inputs.blog_id))
            }
            _ if confluence_comment_action(action).is_some() => {
                let comment_action = confluence_comment_action(action).expect("checked action");
                self.resolve_comment_scopes_without_lookup(comment_action, inputs)
            }
            _ => Err(ProviderError::deny(
                ReasonCode::ServiceActionDenied,
                "Confluence action is not supported",
            )),
        }
    }
}

/// The draft handle a handle-based draft action presents, with the content
/// type and ID its inputs name; `None` for every other action.
fn draft_handle_reference(
    action: &str,
    inputs: &Value,
) -> Result<Option<(ConfluenceDraftContentType, String, String)>, ProviderError> {
    let reference = match action {
        "page.draft.view" | "page.draft.publish" => {
            let inputs = parse_page_draft_body_format_inputs(action, inputs)?;
            (
                ConfluenceDraftContentType::Page,
                inputs.page_id,
                inputs.draft_handle,
            )
        }
        "page.draft.update" => {
            let inputs = parse_page_draft_update_inputs(inputs)?;
            (
                ConfluenceDraftContentType::Page,
                inputs.page_id,
                inputs.draft_handle,
            )
        }
        "page.draft.discard" => {
            let inputs = parse_page_draft_discard_inputs(inputs)?;
            (
                ConfluenceDraftContentType::Page,
                inputs.page_id,
                inputs.draft_handle,
            )
        }
        "page.draft.verify" => {
            let inputs = parse_page_draft_verify_inputs(inputs)?;
            (
                ConfluenceDraftContentType::Page,
                inputs.page_id,
                inputs.draft_handle,
            )
        }
        "page.draft.attachment.add" => {
            let inputs = parse_page_draft_attachment_add_inputs(inputs)?;
            (
                ConfluenceDraftContentType::Page,
                inputs.page_id,
                inputs.draft_handle,
            )
        }
        "page.draft.attachment.download" => {
            let inputs = parse_page_draft_attachment_download_inputs(inputs)?;
            (
                ConfluenceDraftContentType::Page,
                inputs.page_id,
                inputs.draft_handle,
            )
        }
        "page.draft.attachment.list" => {
            let inputs = parse_page_draft_attachment_list_inputs(inputs)?;
            (
                ConfluenceDraftContentType::Page,
                inputs.page_id,
                inputs.draft_handle,
            )
        }
        "blog.draft.view" | "blog.draft.publish" => {
            let inputs = parse_blog_draft_body_format_inputs(action, inputs)?;
            (
                ConfluenceDraftContentType::Blog,
                inputs.blog_id,
                inputs.draft_handle,
            )
        }
        "blog.draft.update" => {
            let inputs = parse_blog_draft_update_inputs(inputs)?;
            (
                ConfluenceDraftContentType::Blog,
                inputs.blog_id,
                inputs.draft_handle,
            )
        }
        "blog.draft.discard" => {
            let inputs = parse_blog_draft_discard_inputs(inputs)?;
            (
                ConfluenceDraftContentType::Blog,
                inputs.blog_id,
                inputs.draft_handle,
            )
        }
        "blog.draft.verify" => {
            let inputs = parse_blog_draft_verify_inputs(inputs)?;
            (
                ConfluenceDraftContentType::Blog,
                inputs.blog_id,
                inputs.draft_handle,
            )
        }
        "blog.draft.attachment.add" => {
            let inputs = parse_blog_draft_attachment_add_inputs(inputs)?;
            (
                ConfluenceDraftContentType::Blog,
                inputs.blog_id,
                inputs.draft_handle,
            )
        }
        "blog.draft.attachment.download" => {
            let inputs = parse_blog_draft_attachment_download_inputs(inputs)?;
            (
                ConfluenceDraftContentType::Blog,
                inputs.blog_id,
                inputs.draft_handle,
            )
        }
        "blog.draft.attachment.list" => {
            let inputs = parse_blog_draft_attachment_list_inputs(inputs)?;
            (
                ConfluenceDraftContentType::Blog,
                inputs.blog_id,
                inputs.draft_handle,
            )
        }
        _ => return Ok(None),
    };
    Ok(Some(reference))
}

impl ConfluenceProvider {
    async fn lookup_scopes(
        &self,
        action: &str,
        inputs: &Value,
        lookup_credential: Option<&ExecutionCredential>,
    ) -> Result<ResourceScopes, ProviderError> {
        match action {
            "page.view" => {
                let credential = required_lookup_credential(lookup_credential)?;
                let locator = page_locator_from_inputs(inputs, &self.config)?;
                let page = self
                    .confirmed_page(
                        &locator.page_id,
                        locator.candidate_space.as_deref(),
                        credential,
                    )
                    .await?;
                let mut scopes = ResourceScopes::new();
                scopes.insert("space".to_string(), vec![page.space]);
                Ok(scopes)
            }
            "page.create" => {
                let credential = required_lookup_credential(lookup_credential)?;
                let inputs = parse_page_create_inputs(inputs, &self.config)?;
                let space = self
                    .backend
                    .space_by_key(&inputs.space, credential)
                    .await
                    .map_err(confluence_backend_error)?
                    .value;
                if space.key != inputs.space {
                    return Err(ProviderError::deny(
                        ReasonCode::ScopeUnresolved,
                        "Confluence space lookup did not match the requested page-create space",
                    ));
                }
                let mut scopes = ResourceScopes::new();
                scopes.insert("space".to_string(), vec![space.key]);
                if let Some(parent) = inputs.parent {
                    let page = self
                        .confirmed_page(
                            &parent.page_id,
                            parent.candidate_space.as_deref(),
                            credential,
                        )
                        .await?;
                    validate_page_locator_space(&parent, &page.space)?;
                    if page.space != inputs.space {
                        return Err(ProviderError::deny(
                            ReasonCode::ScopeUnresolved,
                            "Confluence parent page is outside the requested create space",
                        ));
                    }
                }
                Ok(scopes)
            }
            "page.update" => {
                let credential = required_lookup_credential(lookup_credential)?;
                let inputs = parse_page_update_inputs(inputs)?;
                let page = self
                    .confirmed_page(&inputs.page_id, None, credential)
                    .await?;
                let mut scopes = ResourceScopes::new();
                scopes.insert("space".to_string(), vec![page.space]);
                Ok(scopes)
            }
            "page.move" => {
                let credential = required_lookup_credential(lookup_credential)?;
                let inputs = parse_page_move_inputs(inputs, &self.config)?;
                let page = self
                    .confirmed_page(
                        &inputs.page.page_id,
                        inputs.page.candidate_space.as_deref(),
                        credential,
                    )
                    .await?;
                let target = self
                    .confirmed_page(
                        &inputs.target.page_id,
                        inputs.target.candidate_space.as_deref(),
                        credential,
                    )
                    .await?;
                validate_page_locator_space(&inputs.page, &page.space)?;
                validate_page_locator_space(&inputs.target, &target.space)?;
                if page.id == target.id {
                    return Err(ProviderError::deny(
                        ReasonCode::InputInvalid,
                        "confluence.page.move cannot target the page being moved",
                    ));
                }
                if page.space != target.space {
                    return Err(ProviderError::deny(
                        ReasonCode::ScopeUnresolved,
                        "Confluence page moves must stay within one space",
                    ));
                }
                let space = self
                    .backend
                    .space_by_key(&page.space, credential)
                    .await
                    .map_err(confluence_backend_error)?
                    .value;
                if space.key != page.space {
                    return Err(ProviderError::deny(
                        ReasonCode::ScopeUnresolved,
                        "Confluence page move space lookup did not match the requested pages",
                    ));
                }
                let target_hierarchy = self
                    .backend
                    .page_hierarchy(&target.id, false, credential)
                    .await
                    .map_err(confluence_backend_error)?
                    .value;
                validate_current_hierarchy_identity(&target_hierarchy, &target.id, &space.id)?;
                let effective_parent_page_id = match inputs.position {
                    ConfluencePageMovePosition::Append => target.id.clone(),
                    ConfluencePageMovePosition::Before | ConfluencePageMovePosition::After => {
                        required_target_page_parent_id(&target_hierarchy)?.to_string()
                    }
                };
                let effective_parent = self
                    .confirmed_page(&effective_parent_page_id, None, credential)
                    .await?;
                if effective_parent.space != page.space {
                    return Err(ProviderError::deny(
                        ReasonCode::ScopeUnresolved,
                        "Confluence page move parent is outside the authorized space",
                    ));
                }
                let mut scopes = ResourceScopes::new();
                scopes.insert("space".to_string(), vec![page.space]);
                Ok(scopes)
            }
            "page.draft.create" => {
                let credential = required_lookup_credential(lookup_credential)?;
                let inputs = parse_page_draft_create_inputs(inputs, &self.config)?;
                let space = self
                    .backend
                    .space_by_key(&inputs.space, credential)
                    .await
                    .map_err(confluence_backend_error)?
                    .value;
                if space.key != inputs.space {
                    return Err(ProviderError::deny(
                        ReasonCode::ScopeUnresolved,
                        "Confluence space lookup did not match the requested page-draft space",
                    ));
                }
                let mut scopes = ResourceScopes::new();
                scopes.insert("space".to_string(), vec![space.key]);
                if let Some(parent) = inputs.parent {
                    let page = self
                        .confirmed_page(
                            &parent.page_id,
                            parent.candidate_space.as_deref(),
                            credential,
                        )
                        .await?;
                    validate_page_locator_space(&parent, &page.space)?;
                    if page.space != inputs.space {
                        return Err(ProviderError::deny(
                            ReasonCode::ScopeUnresolved,
                            "Confluence parent page is outside the requested draft-create space",
                        ));
                    }
                }
                Ok(scopes)
            }
            "page.draft.stage" => {
                let credential = required_lookup_credential(lookup_credential)?;
                let inputs = parse_page_draft_stage_inputs(inputs)?;
                let page = self
                    .confirmed_page(&inputs.page_id, None, credential)
                    .await?;
                let mut scopes = ResourceScopes::new();
                scopes.insert("space".to_string(), vec![page.space]);
                Ok(scopes)
            }
            "attachment.add" => {
                let credential = required_lookup_credential(lookup_credential)?;
                let inputs = parse_attachment_add_inputs(inputs)?;
                let page = self
                    .confirmed_page(&inputs.page_id, None, credential)
                    .await?;
                let mut scopes = ResourceScopes::new();
                scopes.insert("space".to_string(), vec![page.space]);
                Ok(scopes)
            }
            "attachment.download" => {
                let credential = required_lookup_credential(lookup_credential)?;
                let inputs = parse_attachment_download_inputs(inputs)?;
                let page = self
                    .confirmed_page(&inputs.page_id, None, credential)
                    .await?;
                let mut scopes = ResourceScopes::new();
                scopes.insert("space".to_string(), vec![page.space]);
                Ok(scopes)
            }
            "attachment.list" => {
                let credential = required_lookup_credential(lookup_credential)?;
                let inputs = parse_attachment_list_inputs(inputs, &self.config)?;
                let page = self
                    .confirmed_page(
                        &inputs.locator.page_id,
                        inputs.locator.candidate_space.as_deref(),
                        credential,
                    )
                    .await?;
                let mut scopes = ResourceScopes::new();
                scopes.insert("space".to_string(), vec![page.space]);
                Ok(scopes)
            }
            "verify" => {
                let credential = required_lookup_credential(lookup_credential)?;
                let inputs = parse_verify_inputs(inputs)?;
                match self
                    .backend
                    .page_metadata(&inputs.page_id, credential)
                    .await
                {
                    Ok(response) => {
                        let page = response.value;
                        if page.id != inputs.page_id {
                            return Err(ProviderError::error(
                                ReasonCode::UpstreamProtocolFailed,
                                "Confluence page metadata did not match requested page",
                            ));
                        }
                        require_current_page(&page)?;
                        let mut scopes = ResourceScopes::new();
                        scopes.insert("space".to_string(), vec![page.space]);
                        Ok(scopes)
                    }
                    Err(ConfluenceBackendError::NotFound | ConfluenceBackendError::Forbidden) => {
                        Err(page_scope_requires_lookup(inputs.page_id))
                    }
                    Err(error) => Err(confluence_backend_error(error)),
                }
            }
            "blog.view" => {
                let credential = required_lookup_credential(lookup_credential)?;
                let inputs = parse_blog_view_inputs(inputs, &self.config)?;
                let blog = self
                    .blog_scope_evidence(&inputs.locator.blog_id, credential)
                    .await?;
                validate_blog_locator_space(&inputs.locator, &blog.space)?;
                let mut scopes = ResourceScopes::new();
                scopes.insert("space".to_string(), vec![blog.space]);
                Ok(scopes)
            }
            "blog.update" => {
                let credential = required_lookup_credential(lookup_credential)?;
                let inputs = parse_blog_update_inputs(inputs)?;
                let blog = self
                    .blog_scope_evidence(&inputs.blog_id, credential)
                    .await?;
                let mut scopes = ResourceScopes::new();
                scopes.insert("space".to_string(), vec![blog.space]);
                Ok(scopes)
            }
            "blog.draft.stage" => {
                let credential = required_lookup_credential(lookup_credential)?;
                let inputs = parse_blog_draft_stage_inputs(inputs)?;
                let blog = self
                    .blog_scope_evidence(&inputs.blog_id, credential)
                    .await?;
                let mut scopes = ResourceScopes::new();
                scopes.insert("space".to_string(), vec![blog.space]);
                Ok(scopes)
            }
            "blog.attachment.add" => {
                let credential = required_lookup_credential(lookup_credential)?;
                let inputs = parse_blog_attachment_add_inputs(inputs)?;
                let blog = self
                    .blog_scope_evidence(&inputs.blog_id, credential)
                    .await?;
                let mut scopes = ResourceScopes::new();
                scopes.insert("space".to_string(), vec![blog.space]);
                Ok(scopes)
            }
            "blog.attachment.download" => {
                let credential = required_lookup_credential(lookup_credential)?;
                let inputs = parse_blog_attachment_download_inputs(inputs)?;
                let blog = self
                    .blog_scope_evidence(&inputs.blog_id, credential)
                    .await?;
                let mut scopes = ResourceScopes::new();
                scopes.insert("space".to_string(), vec![blog.space]);
                Ok(scopes)
            }
            "blog.attachment.list" => {
                let credential = required_lookup_credential(lookup_credential)?;
                let inputs = parse_blog_attachment_list_inputs(inputs, &self.config)?;
                let blog = self
                    .blog_scope_evidence(&inputs.locator.blog_id, credential)
                    .await?;
                validate_blog_locator_space(&inputs.locator, &blog.space)?;
                let mut scopes = ResourceScopes::new();
                scopes.insert("space".to_string(), vec![blog.space]);
                Ok(scopes)
            }
            "blog.verify" => {
                let credential = required_lookup_credential(lookup_credential)?;
                let inputs = parse_blog_verify_inputs(inputs)?;
                let blog = self
                    .blog_scope_evidence(&inputs.blog_id, credential)
                    .await?;
                let mut scopes = ResourceScopes::new();
                scopes.insert("space".to_string(), vec![blog.space]);
                Ok(scopes)
            }
            _ if confluence_comment_action(action).is_some() => {
                let credential = required_lookup_credential(lookup_credential)?;
                let comment_action = confluence_comment_action(action).expect("checked action");
                self.resolve_comment_scopes_with_lookup(comment_action, inputs, credential)
                    .await
            }
            _ => self.local_scopes(action, inputs),
        }
    }
}

#[async_trait]
impl Provider for ConfluenceProvider {
    async fn resolve_scopes(
        &self,
        request: ScopeRequest<'_>,
    ) -> Result<ScopeResolution, ProviderError> {
        if let Some((content_type, content_id, draft_handle)) =
            draft_handle_reference(request.action(), request.inputs())?
        {
            return self
                .draft_handle_scopes(&request, content_type, &content_id, &draft_handle)
                .map(ScopeResolution::resources);
        }
        self.lookup_scopes(
            request.action(),
            request.inputs(),
            request.lookup_credential(),
        )
        .await
        .map(ScopeResolution::resources)
    }

    async fn authorize_body_parts(
        &self,
        request: &AdmittedRequest,
        _state: Option<&ProviderState>,
    ) -> Result<BodyAdmission, ProviderError> {
        if request.action() != "attachment.add"
            && request.action() != "blog.attachment.add"
            && request.action() != "page.draft.attachment.add"
            && request.action() != "blog.draft.attachment.add"
        {
            return Err(ProviderError::deny(
                ReasonCode::BodyMalformed,
                "Confluence action does not accept multipart body parts",
            ));
        }
        let credential = lookup_credential(request)?;
        let (body_part_specs, state) = if request.action() == "attachment.add" {
            let inputs = parse_attachment_add_inputs(request.inputs())?;
            validate_attachment_metadata_inputs(&inputs.attachments, &self.config.attachments)?;
            let response = self
                .confirmed_page_response(&inputs.page_id, None, credential)
                .await?;
            (
                attachment_body_part_specs(&inputs.attachments),
                ProviderState::new(ConfluencePagePreflight {
                    page: response.value,
                    upstream_status: response.status,
                    upstream_duration_ms: response.duration_ms,
                }),
            )
        } else if request.action() == "blog.attachment.add" {
            let inputs = parse_blog_attachment_add_inputs(request.inputs())?;
            validate_attachment_metadata_inputs(&inputs.attachments, &self.config.attachments)?;
            let response = self
                .confirmed_blog_response(&inputs.blog_id, credential)
                .await?;
            (
                attachment_body_part_specs(&inputs.attachments),
                ProviderState::new(ConfluenceBlogPreflight {
                    blog: response.value,
                    upstream_status: response.status,
                    upstream_duration_ms: response.duration_ms,
                }),
            )
        } else if request.action() == "page.draft.attachment.add" {
            let inputs = parse_page_draft_attachment_add_inputs(request.inputs())?;
            validate_attachment_metadata_inputs(&inputs.attachments, &self.config.attachments)?;
            let handle = self.decode_draft_handle_for_request(
                ConfluenceDraftContentType::Page,
                &inputs.page_id,
                &inputs.draft_handle,
                request,
            )?;
            reject_staged_draft_attachment_add(&handle)?;
            let response = self
                .draft_page_response_with_space(&inputs.page_id, Some("storage"), credential)
                .await?;
            ensure_draft_content_matches_handle(&response.value, &handle)?;
            (
                attachment_body_part_specs(&inputs.attachments),
                ProviderState::new(ConfluenceDraftContentPreflight {
                    content: response.value,
                    upstream_status: response.status,
                    upstream_duration_ms: response.duration_ms,
                }),
            )
        } else {
            let inputs = parse_blog_draft_attachment_add_inputs(request.inputs())?;
            validate_attachment_metadata_inputs(&inputs.attachments, &self.config.attachments)?;
            let handle = self.decode_draft_handle_for_request(
                ConfluenceDraftContentType::Blog,
                &inputs.blog_id,
                &inputs.draft_handle,
                request,
            )?;
            reject_staged_draft_attachment_add(&handle)?;
            let response = self
                .draft_blog_response_with_space(&inputs.blog_id, Some("storage"), credential)
                .await?;
            ensure_draft_content_matches_handle(&response.value, &handle)?;
            (
                attachment_body_part_specs(&inputs.attachments),
                ProviderState::new(ConfluenceDraftContentPreflight {
                    content: response.value,
                    upstream_status: response.status,
                    upstream_duration_ms: response.duration_ms,
                }),
            )
        };
        Ok(BodyAdmission::new(
            body_part_specs,
            StateDisposition::Replace(state),
        ))
    }

    async fn verify_execution_credential(
        &self,
        credential: &ExecutionCredential,
        _correlation: &crate::CorrelationContext,
    ) -> Result<Option<ProviderCredentialVerification>, ProviderError> {
        let response = self
            .backend
            .current_user(credential)
            .await
            .map_err(confluence_backend_error)?;
        Ok(Some(ProviderCredentialVerification::new(
            response.status,
            response.duration_ms,
            json!({
                "provider": "confluence",
                "operation": "credential.verify",
                "egressProxy": self.backend.egress_proxy_audit(credential),
            }),
        )))
    }

    async fn invoke(&self, request: ProviderInvocation) -> Result<ProviderResult, ProviderError> {
        if let Some(comment_action) = confluence_comment_action(request.action()) {
            return self.invoke_comment_action(request, comment_action).await;
        }
        match request.action() {
            "page.view" => self.invoke_page_view(request).await,
            "search" => self.invoke_search(request).await,
            "page.create" => self.invoke_page_create(request).await,
            "page.update" => self.invoke_page_update(request).await,
            "page.move" => self.invoke_page_move(request).await,
            "page.draft.create" => self.invoke_page_draft_create(request).await,
            "page.draft.stage" => self.invoke_page_draft_stage(request).await,
            "page.draft.view" => self.invoke_page_draft_view(request).await,
            "page.draft.update" => self.invoke_page_draft_update(request).await,
            "page.draft.publish" => self.invoke_page_draft_publish(request).await,
            "page.draft.discard" => self.invoke_page_draft_discard(request).await,
            "page.draft.verify" => self.invoke_page_draft_verify(request).await,
            "page.draft.attachment.add" => self.invoke_page_draft_attachment_add(request).await,
            "page.draft.attachment.download" => {
                self.invoke_page_draft_attachment_download(request).await
            }
            "page.draft.attachment.list" => self.invoke_page_draft_attachment_list(request).await,
            "attachment.add" => self.invoke_attachment_add(request).await,
            "attachment.download" => self.invoke_attachment_download(request).await,
            "attachment.list" => self.invoke_attachment_list(request).await,
            "verify" => self.invoke_verify(request).await,
            "blog.view" => self.invoke_blog_view(request).await,
            "blog.search" => self.invoke_blog_search(request).await,
            "blog.create" => self.invoke_blog_create(request).await,
            "blog.update" => self.invoke_blog_update(request).await,
            "blog.draft.create" => self.invoke_blog_draft_create(request).await,
            "blog.draft.stage" => self.invoke_blog_draft_stage(request).await,
            "blog.draft.view" => self.invoke_blog_draft_view(request).await,
            "blog.draft.update" => self.invoke_blog_draft_update(request).await,
            "blog.draft.publish" => self.invoke_blog_draft_publish(request).await,
            "blog.draft.discard" => self.invoke_blog_draft_discard(request).await,
            "blog.draft.verify" => self.invoke_blog_draft_verify(request).await,
            "blog.draft.attachment.add" => self.invoke_blog_draft_attachment_add(request).await,
            "blog.draft.attachment.download" => {
                self.invoke_blog_draft_attachment_download(request).await
            }
            "blog.draft.attachment.list" => self.invoke_blog_draft_attachment_list(request).await,
            "blog.attachment.add" => self.invoke_blog_attachment_add(request).await,
            "blog.attachment.download" => self.invoke_blog_attachment_download(request).await,
            "blog.attachment.list" => self.invoke_blog_attachment_list(request).await,
            "blog.verify" => self.invoke_blog_verify(request).await,
            _ => Err(ProviderError::deny(
                ReasonCode::ServiceActionDenied,
                "Confluence action is not supported",
            )),
        }
    }
}

#[derive(Debug, Clone)]
enum ConfluenceResolvedCommentContainer {
    Page(ConfluencePage),
    Blog(ConfluenceBlog),
}

impl ConfluenceResolvedCommentContainer {
    fn id(&self) -> &str {
        match self {
            Self::Page(page) => &page.id,
            Self::Blog(blog) => &blog.id,
        }
    }

    fn space(&self) -> &str {
        match self {
            Self::Page(page) => &page.space,
            Self::Blog(blog) => &blog.space,
        }
    }
}

#[derive(Debug, Clone)]
struct ConfluenceCommentEvidence {
    target: ConfluenceComment,
    container: ConfluenceResolvedCommentContainer,
    chain: Vec<String>,
    upstream_status: Option<u16>,
    upstream_duration_ms: u64,
}

impl ConfluenceProvider {
    fn resolve_comment_scopes_without_lookup(
        &self,
        action: ConfluenceCommentAction,
        inputs: &Value,
    ) -> Result<ResourceScopes, ProviderError> {
        match action.operation {
            ConfluenceCommentOperation::List => {
                let inputs = parse_comment_list_inputs(action, inputs)?;
                match action.container_type {
                    ConfluenceCommentContainerType::Page => {
                        Err(page_scope_requires_lookup(inputs.container_id))
                    }
                    ConfluenceCommentContainerType::Blog => {
                        Err(blog_scope_requires_lookup(inputs.container_id))
                    }
                }
            }
            ConfluenceCommentOperation::Add => {
                let inputs = parse_comment_add_inputs(action, inputs)?;
                match action.container_type {
                    ConfluenceCommentContainerType::Page => {
                        Err(page_scope_requires_lookup(inputs.container_id))
                    }
                    ConfluenceCommentContainerType::Blog => {
                        Err(blog_scope_requires_lookup(inputs.container_id))
                    }
                }
            }
            ConfluenceCommentOperation::View => {
                let inputs = parse_comment_id_inputs(inputs)?;
                Err(comment_scope_requires_lookup(inputs.comment_id))
            }
            ConfluenceCommentOperation::Update => {
                let inputs = parse_comment_update_inputs(inputs)?;
                Err(comment_scope_requires_lookup(inputs.comment_id))
            }
            ConfluenceCommentOperation::Delete => {
                let inputs = parse_comment_delete_inputs(inputs)?;
                Err(comment_scope_requires_lookup(inputs.comment_id))
            }
            ConfluenceCommentOperation::ReplyList => {
                let inputs = parse_comment_reply_list_inputs(inputs)?;
                Err(comment_scope_requires_lookup(inputs.comment_id))
            }
            ConfluenceCommentOperation::ReplyAdd => {
                let inputs = parse_comment_reply_add_inputs(inputs)?;
                Err(comment_scope_requires_lookup(inputs.comment_id))
            }
        }
    }

    async fn resolve_comment_scopes_with_lookup(
        &self,
        action: ConfluenceCommentAction,
        inputs: &Value,
        credential: &ExecutionCredential,
    ) -> Result<ResourceScopes, ProviderError> {
        match action.operation {
            ConfluenceCommentOperation::List => {
                let inputs = parse_comment_list_inputs(action, inputs)?;
                let container = self
                    .confirmed_comment_container(
                        action.container_type,
                        &inputs.container_id,
                        credential,
                    )
                    .await?;
                Ok(scopes_for_comment_container(&container))
            }
            ConfluenceCommentOperation::Add => {
                let inputs = parse_comment_add_inputs(action, inputs)?;
                let container = self
                    .confirmed_comment_container(
                        action.container_type,
                        &inputs.container_id,
                        credential,
                    )
                    .await?;
                Ok(scopes_for_comment_container(&container))
            }
            ConfluenceCommentOperation::View => {
                let inputs = parse_comment_id_inputs(inputs)?;
                let evidence = self
                    .comment_container_evidence(action, &inputs.comment_id, None, credential)
                    .await?;
                Ok(scopes_for_comment_container(&evidence.container))
            }
            ConfluenceCommentOperation::Update => {
                let inputs = parse_comment_update_inputs(inputs)?;
                let evidence = self
                    .comment_container_evidence(action, &inputs.comment_id, None, credential)
                    .await?;
                Ok(scopes_for_comment_container(&evidence.container))
            }
            ConfluenceCommentOperation::Delete => {
                let inputs = parse_comment_delete_inputs(inputs)?;
                let evidence = self
                    .comment_container_evidence(action, &inputs.comment_id, None, credential)
                    .await?;
                Ok(scopes_for_comment_container(&evidence.container))
            }
            ConfluenceCommentOperation::ReplyList => {
                let inputs = parse_comment_reply_list_inputs(inputs)?;
                let evidence = self
                    .comment_container_evidence(action, &inputs.comment_id, None, credential)
                    .await?;
                Ok(scopes_for_comment_container(&evidence.container))
            }
            ConfluenceCommentOperation::ReplyAdd => {
                let inputs = parse_comment_reply_add_inputs(inputs)?;
                let evidence = self
                    .comment_container_evidence(action, &inputs.comment_id, None, credential)
                    .await?;
                Ok(scopes_for_comment_container(&evidence.container))
            }
        }
    }

    async fn confirmed_comment_container(
        &self,
        container_type: ConfluenceCommentContainerType,
        container_id: &str,
        credential: &ExecutionCredential,
    ) -> Result<ConfluenceResolvedCommentContainer, ProviderError> {
        match container_type {
            ConfluenceCommentContainerType::Page => {
                let page = self.confirmed_page(container_id, None, credential).await?;
                require_current_page(&page)?;
                Ok(ConfluenceResolvedCommentContainer::Page(page))
            }
            ConfluenceCommentContainerType::Blog => {
                let blog = self.confirmed_blog(container_id, credential).await?;
                Ok(ConfluenceResolvedCommentContainer::Blog(blog))
            }
        }
    }

    async fn comment_container_evidence(
        &self,
        action: ConfluenceCommentAction,
        comment_id: &str,
        target_body_format: Option<&str>,
        credential: &ExecutionCredential,
    ) -> Result<ConfluenceCommentEvidence, ProviderError> {
        let mut current_id = validate_comment_id(comment_id)?;
        let mut seen = BTreeSet::new();
        let mut chain = Vec::new();
        let mut target: Option<ConfluenceComment> = None;
        let mut upstream_status = None;
        let mut upstream_duration_ms = 0_u64;
        for depth in 0..=MAX_COMMENT_PARENT_DEPTH {
            if !seen.insert(current_id.clone()) {
                return Err(ProviderError::deny(
                    ReasonCode::ScopeUnresolved,
                    "Confluence comment parent chain contains a cycle",
                ));
            }
            chain.push(current_id.clone());
            let body_format = (depth == 0).then_some(target_body_format).flatten();
            let response = self
                .backend
                .comment(action.kind, &current_id, body_format, credential)
                .await
                .map_err(confluence_backend_error)?;
            if upstream_status.is_none() {
                upstream_status = Some(response.status);
            }
            upstream_duration_ms = upstream_duration_ms.saturating_add(response.duration_ms);
            let comment = response.value;
            validate_comment_identity(&comment, &current_id, action.kind)?;
            require_current_comment(&comment)?;
            if depth == 0 {
                target = Some(comment.clone());
            }
            if let Some(container_id) = comment_container_id_for_action(&comment, action)? {
                let container = self
                    .confirmed_comment_container(action.container_type, container_id, credential)
                    .await?;
                return Ok(ConfluenceCommentEvidence {
                    target: target.expect("target comment captured"),
                    container,
                    chain,
                    upstream_status,
                    upstream_duration_ms,
                });
            }
            let Some(parent_id) = comment.parent_comment_id.as_deref() else {
                return Err(ProviderError::deny(
                    ReasonCode::ScopeUnresolved,
                    "Confluence comment parent chain does not identify a page or blog",
                ));
            };
            current_id = validate_comment_id(parent_id)?;
        }
        Err(ProviderError::deny(
            ReasonCode::ScopeUnresolved,
            "Confluence comment parent chain exceeded the traversal limit",
        ))
    }

    async fn invoke_comment_action(
        &self,
        request: ProviderInvocation,
        action: ConfluenceCommentAction,
    ) -> Result<ProviderResult, ProviderError> {
        match action.operation {
            ConfluenceCommentOperation::List => self.invoke_comment_list(request, action).await,
            ConfluenceCommentOperation::View => self.invoke_comment_view(request, action).await,
            ConfluenceCommentOperation::Add => self.invoke_comment_add(request, action).await,
            ConfluenceCommentOperation::Update => self.invoke_comment_update(request, action).await,
            ConfluenceCommentOperation::Delete => self.invoke_comment_delete(request, action).await,
            ConfluenceCommentOperation::ReplyList => {
                self.invoke_comment_reply_list(request, action).await
            }
            ConfluenceCommentOperation::ReplyAdd => {
                self.invoke_comment_reply_add(request, action).await
            }
        }
    }

    fn apply_storage_attribution(
        &self,
        action: &str,
        body: &mut String,
        request: &ProviderInvocation,
    ) -> Option<Value> {
        let capability = self.attribution.capability(action)?;
        let mutation = append_confluence_storage_attribution(
            body,
            capability,
            &request.correlation().broker_request_id,
        );
        Some(mutation.audit_value())
    }

    fn prepare_write_content(
        &self,
        action: &str,
        target: ConfluenceWriteTarget,
        content_format: &str,
        content: &Value,
        request: &ProviderInvocation,
    ) -> Result<
        (
            ConfluencePageBody,
            ConfluenceContentWriteAudit,
            Option<Value>,
        ),
        ProviderError,
    > {
        let effective_formats = confluence_write_formats(target, &self.config);
        if !effective_formats
            .iter()
            .any(|format| format == content_format)
        {
            return Err(ProviderError::deny(
                ReasonCode::BodyFormatUnsupported,
                format!("{action} contentFormat is unsupported"),
            ));
        }
        let max_body_bytes = self.config.content.max_body_bytes;
        let source_bytes = match content_format {
            "atlas_doc_format" => serde_json::to_vec(content)
                .map(|bytes| bytes.len() as u64)
                .map_err(|_| {
                    ProviderError::deny(
                        ReasonCode::BodyMalformed,
                        "Confluence atlas_doc_format content is invalid",
                    )
                })?,
            "storage" | "markdown" | "plain_text" => content
                .as_str()
                .map(|value| value.len() as u64)
                .ok_or_else(|| {
                    ProviderError::deny(
                        ReasonCode::InputInvalid,
                        format!("{action} content must be a string for {content_format}"),
                    )
                })?,
            _ => unreachable!("effective content format was validated"),
        };
        if source_bytes > max_body_bytes {
            return Err(ProviderError::deny(
                ReasonCode::BodySizeDenied,
                format!("{action} source content exceeded the configured byte cap"),
            ));
        }

        let (representation, value, attribution) = if content_format == "atlas_doc_format" {
            if !content.is_object() {
                return Err(ProviderError::deny(
                    ReasonCode::InputInvalid,
                    format!("{action} content must be an object for atlas_doc_format"),
                ));
            }
            let mut native = content.clone();
            validate_atlas_doc_format_body(&native)?;
            let attribution = if let Some(capability) = self.attribution.capability(action) {
                let mut mutation = append_adf_attribution(
                    &mut native,
                    capability,
                    &request.correlation().broker_request_id,
                )?;
                mutation.representation = "adf";
                Some(mutation.audit_value())
            } else {
                None
            };
            validate_atlas_doc_format_body(&native)?;
            let value = serde_json::to_string(&native).map_err(|_| {
                ProviderError::deny(
                    ReasonCode::BodyMalformed,
                    "Confluence atlas_doc_format content is invalid",
                )
            })?;
            ("atlas_doc_format", value, attribution)
        } else {
            let source = content
                .as_str()
                .expect("normalized Confluence content type was validated");
            if matches!(content_format, "markdown" | "plain_text") && source.trim().is_empty() {
                return Err(ProviderError::deny(
                    ReasonCode::BodyMalformed,
                    "Confluence normalized content must not be empty or whitespace-only",
                ));
            }
            let mut native = match content_format {
                "storage" => source.to_string(),
                "markdown" => markdown_to_confluence_storage_bounded(source, max_body_bytes)
                    .map_err(map_confluence_content_write_error)?,
                "plain_text" => plain_text_to_confluence_storage_bounded(source, max_body_bytes)
                    .map_err(map_confluence_content_write_error)?,
                _ => unreachable!("effective content format was validated"),
            };
            validate_non_empty_storage_body(&native)?;
            let generated = matches!(content_format, "markdown" | "plain_text");
            if generated {
                validate_generated_confluence_storage(&native, false)?;
            }
            let attribution = self.apply_storage_attribution(action, &mut native, request);
            validate_non_empty_storage_body(&native)?;
            if generated {
                validate_generated_confluence_storage(&native, attribution.is_some())?;
            }
            ("storage", native, attribution)
        };
        let final_native_bytes = value.len() as u64;
        if final_native_bytes > max_body_bytes {
            return Err(ProviderError::deny(
                ReasonCode::BodySizeDenied,
                if attribution_audit_applied(attribution.as_ref()) {
                    "Confluence body exceeded the configured byte cap after broker attribution was added"
                } else {
                    "Confluence body exceeded the configured byte cap"
                },
            ));
        }
        Ok((
            ConfluencePageBody {
                representation: representation.to_string(),
                value,
            },
            ConfluenceContentWriteAudit {
                requested_format: content_format.to_string(),
                native_format: representation.to_string(),
                source_bytes,
                final_native_bytes,
            },
            attribution,
        ))
    }

    async fn invoke_comment_list(
        &self,
        request: ProviderInvocation,
        action: ConfluenceCommentAction,
    ) -> Result<ProviderResult, ProviderError> {
        let credential = invocation_credential(&request)?;
        let lookup_credential = lookup_credential(request.admitted())?;
        let inputs = parse_comment_list_inputs(action, request.inputs())?;
        let body_format =
            configured_comment_body_format(inputs.body_format.as_deref(), &self.config)?;
        let container = self
            .confirmed_comment_container(
                action.container_type,
                &inputs.container_id,
                lookup_credential,
            )
            .await?;
        ensure_authorized_comment_container(&container, request.resource_scopes()?)?;
        let max_results = capped_max_results(inputs.max_results, &self.config.search)?;
        let binding = comment_list_binding(
            action,
            &container,
            None,
            body_format.clone(),
            &inputs,
            max_results,
        );
        let cursor = inputs
            .next_page_token
            .as_deref()
            .map(|token| {
                self.continuations
                    .open_comment_page(request.context(), credential, &binding, token)
            })
            .transpose()?;
        let response = self
            .backend
            .comments_page(
                ConfluenceCommentListRequest {
                    kind: action.kind,
                    container_type: action.container_type,
                    container_id: container.id().to_string(),
                    body_format: body_format.clone(),
                    resolution_status: inputs.resolution_status.clone(),
                    sort: inputs.sort.clone(),
                    max_results,
                    cursor,
                },
                credential,
            )
            .await
            .map_err(confluence_backend_error)?;
        validate_comment_page(
            &response.value.comments,
            action,
            &container,
            true,
            max_results,
            None,
        )?;
        let next_page_token = response
            .value
            .next_cursor
            .clone()
            .map(|cursor| {
                self.continuations.seal_comment_page(
                    request.context(),
                    credential,
                    &binding,
                    &cursor,
                )
            })
            .transpose()?;
        let has_more = next_page_token.is_some();
        let result = comment_list_result(
            &response.value.comments,
            action,
            &container,
            body_format.as_deref(),
            has_more,
            next_page_token,
        )?;
        enforce_result_size(&result, self.limits.max_upstream_response_bytes)?;
        Ok(ProviderResult::new(result)
            .with_audit(comment_audit(
                &request,
                &container,
                action,
                None,
                body_format.as_deref(),
                Some(CommentAuditListMetadata {
                    result_count: response.value.comments.len(),
                    has_more,
                }),
                self.backend.egress_proxy_audit(credential),
            ))
            .with_upstream(Some(response.status), Some(response.duration_ms))
            .with_object_ids(comment_list_object_ids(
                &response.value.comments,
                &container,
            )))
    }

    async fn invoke_comment_view(
        &self,
        request: ProviderInvocation,
        action: ConfluenceCommentAction,
    ) -> Result<ProviderResult, ProviderError> {
        let credential = invocation_credential(&request)?;
        let lookup_credential = lookup_credential(request.admitted())?;
        let inputs = parse_comment_id_inputs(request.inputs())?;
        let body_format =
            configured_comment_body_format(inputs.body_format.as_deref(), &self.config)?;
        let evidence = self
            .comment_container_evidence(action, &inputs.comment_id, None, lookup_credential)
            .await?;
        ensure_authorized_comment_container(&evidence.container, request.resource_scopes()?)?;
        let execution_evidence = self
            .comment_container_evidence(
                action,
                &inputs.comment_id,
                body_format.as_deref(),
                credential,
            )
            .await?;
        ensure_matching_comment_evidence(&evidence, &execution_evidence)?;
        ensure_authorized_comment_container(
            &execution_evidence.container,
            request.resource_scopes()?,
        )?;
        let result = json!({
            "comment": comment_result(&execution_evidence.target, action, &execution_evidence.container, body_format.as_deref())?,
        });
        enforce_result_size(&result, self.limits.max_upstream_response_bytes)?;
        Ok(ProviderResult::new(result)
            .with_audit(comment_audit(
                &request,
                &execution_evidence.container,
                action,
                Some(&execution_evidence.target.id),
                body_format.as_deref(),
                None,
                self.backend.egress_proxy_audit(credential),
            ))
            .with_upstream(
                execution_evidence.upstream_status,
                Some(execution_evidence.upstream_duration_ms),
            )
            .with_object_ids(comment_object_ids(
                &execution_evidence.target,
                &execution_evidence.container,
            )))
    }

    async fn invoke_comment_add(
        &self,
        request: ProviderInvocation,
        action: ConfluenceCommentAction,
    ) -> Result<ProviderResult, ProviderError> {
        let credential = invocation_credential(&request)?;
        let lookup_credential = lookup_credential(request.admitted())?;
        let inputs = parse_comment_add_inputs(action, request.inputs())?;
        let (body, content_audit, attribution) = self.prepare_write_content(
            request.action(),
            ConfluenceWriteTarget::Comment,
            &inputs.content_format,
            &inputs.content,
            &request,
        )?;
        let container = self
            .confirmed_comment_container(
                action.container_type,
                &inputs.container_id,
                lookup_credential,
            )
            .await?;
        ensure_authorized_comment_container(&container, request.resource_scopes()?)?;
        let write = ConfluenceWrite::new(json!({ "containerId": container.id() }));
        let response = self
            .backend
            .add_comment(
                ConfluenceCommentCreateRequest {
                    kind: action.kind,
                    container_type: action.container_type,
                    page_id: (action.container_type == ConfluenceCommentContainerType::Page)
                        .then(|| container.id().to_string()),
                    blog_id: (action.container_type == ConfluenceCommentContainerType::Blog)
                        .then(|| container.id().to_string()),
                    parent_comment_id: None,
                    body,
                },
                credential,
            )
            .await
            .map_err(|error| write.failed(error))?;
        after_accepted_write("mutation_response", write.locators(), async {
            validate_created_comment(&response.value, action, &container)?;
            let result = json!({
                "comment": comment_result(&response.value, action, &container, Some("storage"))?,
            });
            enforce_result_size(&result, self.limits.max_upstream_response_bytes)?;
            let mut audit = comment_audit(
                &request,
                &container,
                action,
                Some(&response.value.id),
                Some("storage"),
                None,
                self.backend.egress_proxy_audit(credential),
            );
            merge_confluence_content_write_audit(&mut audit, &content_audit);
            merge_attribution_audit(&mut audit, attribution);
            Ok(ProviderResult::new(result)
                .with_audit(audit)
                .with_upstream(Some(response.status), Some(response.duration_ms))
                .with_object_ids(comment_object_ids(&response.value, &container)))
        })
        .await
    }

    async fn invoke_comment_update(
        &self,
        request: ProviderInvocation,
        action: ConfluenceCommentAction,
    ) -> Result<ProviderResult, ProviderError> {
        let credential = invocation_credential(&request)?;
        let lookup_credential = lookup_credential(request.admitted())?;
        let inputs = parse_comment_update_inputs(request.inputs())?;
        let next_version = next_comment_version(inputs.base_version)?;
        let (body, content_audit, _attribution) = self.prepare_write_content(
            request.action(),
            ConfluenceWriteTarget::Comment,
            &inputs.content_format,
            &inputs.content,
            &request,
        )?;
        let evidence = self
            .comment_container_evidence(action, &inputs.comment_id, None, lookup_credential)
            .await?;
        ensure_authorized_comment_container(&evidence.container, request.resource_scopes()?)?;
        ensure_comment_base_version(
            &request,
            action,
            &evidence,
            inputs.base_version,
            self.backend.egress_proxy_audit(lookup_credential),
        )?;
        let execution_evidence = self
            .comment_container_evidence(action, &inputs.comment_id, None, credential)
            .await?;
        ensure_matching_comment_evidence(&evidence, &execution_evidence)?;
        ensure_authorized_comment_container(
            &execution_evidence.container,
            request.resource_scopes()?,
        )?;
        ensure_comment_base_version(
            &request,
            action,
            &execution_evidence,
            inputs.base_version,
            self.backend.egress_proxy_audit(credential),
        )?;
        let write = ConfluenceWrite::new(json!({ "commentId": inputs.comment_id }));
        let response = match self
            .backend
            .update_comment(
                ConfluenceCommentUpdateRequest {
                    kind: action.kind,
                    comment_id: inputs.comment_id.clone(),
                    base_version: inputs.base_version,
                    body,
                },
                credential,
            )
            .await
        {
            Ok(response) => response,
            Err(ConfluenceBackendError::Conflict) => {
                return Err(upstream_comment_version_conflict_error(
                    &request,
                    action,
                    &execution_evidence,
                    inputs.base_version,
                    self.backend.egress_proxy_audit(credential),
                ));
            }
            Err(error) => return Err(write.failed(error)),
        };
        after_accepted_write("mutation_response", write.locators(), async {
        validate_comment_identity(&response.value, &inputs.comment_id, action.kind)?;
        require_current_comment(&response.value)?;
        if response.value.version != Some(next_version) {
            return Err(ProviderError::error(
                ReasonCode::UpstreamProtocolFailed,
                "Confluence updated comment version did not match the requested base version",
            ));
        }
        let updated_evidence = self
            .comment_container_evidence(action, &inputs.comment_id, Some("storage"), credential)
            .await
            .map_err(|error| {
                // The update applied: throttling must not invite a second update.
                error.unverified_after_mutation(
                    "post_update_readback",
                    json!({"commentId": inputs.comment_id, "version": next_version}),
                )
            })?;
        ensure_matching_comment_evidence(&execution_evidence, &updated_evidence)?;
        ensure_authorized_comment_container(
            &updated_evidence.container,
            request.resource_scopes()?,
        )?;
        if updated_evidence.target.version != Some(next_version) {
            return Err(ProviderError::error(
                ReasonCode::UpstreamProtocolFailed,
                "Confluence updated comment version did not match the requested base version",
            ));
        }
        let result = json!({
            "comment": comment_result(&updated_evidence.target, action, &updated_evidence.container, Some("storage"))?,
            "previousVersion": inputs.base_version,
            "version": next_version,
        });
        enforce_result_size(&result, self.limits.max_upstream_response_bytes)?;
        let mut audit = comment_audit(
            &request,
            &updated_evidence.container,
            action,
            Some(&updated_evidence.target.id),
            Some("storage"),
            None,
            self.backend.egress_proxy_audit(credential),
        );
        merge_confluence_content_write_audit(&mut audit, &content_audit);
        audit["previousVersion"] = json!(inputs.base_version);
        audit["version"] = json!(next_version);
        Ok(ProviderResult::new(result)
            .with_audit(audit)
            .with_upstream(
                Some(response.status),
                Some(
                    evidence
                        .upstream_duration_ms
                        .saturating_add(execution_evidence.upstream_duration_ms)
                        .saturating_add(response.duration_ms)
                        .saturating_add(updated_evidence.upstream_duration_ms),
                ),
            )
            .with_object_ids(comment_object_ids(
                &updated_evidence.target,
                &updated_evidence.container,
            )))
        })
        .await
    }

    async fn invoke_comment_delete(
        &self,
        request: ProviderInvocation,
        action: ConfluenceCommentAction,
    ) -> Result<ProviderResult, ProviderError> {
        let credential = invocation_credential(&request)?;
        let lookup_credential = lookup_credential(request.admitted())?;
        let inputs = parse_comment_delete_inputs(request.inputs())?;
        let evidence = self
            .comment_container_evidence(action, &inputs.comment_id, None, lookup_credential)
            .await?;
        ensure_authorized_comment_container(&evidence.container, request.resource_scopes()?)?;
        let execution_evidence = self
            .comment_container_evidence(action, &inputs.comment_id, None, credential)
            .await?;
        ensure_matching_comment_evidence(&evidence, &execution_evidence)?;
        ensure_authorized_comment_container(
            &execution_evidence.container,
            request.resource_scopes()?,
        )?;
        let write = ConfluenceWrite::new(json!({ "commentId": inputs.comment_id }));
        let response = self
            .backend
            .delete_comment(action.kind, &inputs.comment_id, credential)
            .await
            .map_err(|error| write.failed(error))?;
        after_accepted_write("mutation_response", write.locators(), async {
            let result = json!({
                "commentId": inputs.comment_id,
                "status": "deleted",
                "containerType": action.container_type.as_str(),
                "kind": action.kind.as_str(),
                "space": execution_evidence.container.space(),
            });
            enforce_result_size(&result, self.limits.max_upstream_response_bytes)?;
            Ok(ProviderResult::new(result)
                .with_audit(comment_audit(
                    &request,
                    &execution_evidence.container,
                    action,
                    Some(&execution_evidence.target.id),
                    None,
                    None,
                    self.backend.egress_proxy_audit(credential),
                ))
                .with_upstream(
                    Some(response.status),
                    Some(
                        evidence
                            .upstream_duration_ms
                            .saturating_add(execution_evidence.upstream_duration_ms)
                            .saturating_add(response.duration_ms),
                    ),
                )
                .with_object_ids(comment_object_ids(
                    &execution_evidence.target,
                    &execution_evidence.container,
                )))
        })
        .await
    }

    async fn invoke_comment_reply_list(
        &self,
        request: ProviderInvocation,
        action: ConfluenceCommentAction,
    ) -> Result<ProviderResult, ProviderError> {
        let credential = invocation_credential(&request)?;
        let lookup_credential = lookup_credential(request.admitted())?;
        let inputs = parse_comment_reply_list_inputs(request.inputs())?;
        let body_format =
            configured_comment_body_format(inputs.body_format.as_deref(), &self.config)?;
        let evidence = self
            .comment_container_evidence(action, &inputs.comment_id, None, lookup_credential)
            .await?;
        ensure_authorized_comment_container(&evidence.container, request.resource_scopes()?)?;
        let execution_evidence = self
            .comment_container_evidence(action, &inputs.comment_id, None, credential)
            .await?;
        ensure_matching_comment_evidence(&evidence, &execution_evidence)?;
        ensure_authorized_comment_container(
            &execution_evidence.container,
            request.resource_scopes()?,
        )?;
        let max_results = capped_max_results(inputs.max_results, &self.config.search)?;
        let binding = ConfluenceCommentListBinding {
            kind: action.kind,
            container_type: action.container_type,
            container_id: execution_evidence.container.id().to_string(),
            comment_id: Some(inputs.comment_id.clone()),
            space: execution_evidence.container.space().to_string(),
            body_format: body_format.clone(),
            resolution_status: None,
            sort: None,
            max_results,
        };
        let cursor = inputs
            .next_page_token
            .as_deref()
            .map(|token| {
                self.continuations
                    .open_comment_page(request.context(), credential, &binding, token)
            })
            .transpose()?;
        let response = self
            .backend
            .comment_replies_page(
                action.kind,
                &inputs.comment_id,
                body_format.as_deref(),
                max_results,
                cursor.as_deref(),
                credential,
            )
            .await
            .map_err(confluence_backend_error)?;
        validate_comment_page(
            &response.value.comments,
            action,
            &execution_evidence.container,
            false,
            max_results,
            Some(&inputs.comment_id),
        )?;
        let next_page_token = response
            .value
            .next_cursor
            .clone()
            .map(|cursor| {
                self.continuations.seal_comment_page(
                    request.context(),
                    credential,
                    &binding,
                    &cursor,
                )
            })
            .transpose()?;
        let has_more = next_page_token.is_some();
        let result = comment_list_result(
            &response.value.comments,
            action,
            &execution_evidence.container,
            body_format.as_deref(),
            has_more,
            next_page_token,
        )?;
        enforce_result_size(&result, self.limits.max_upstream_response_bytes)?;
        Ok(ProviderResult::new(result)
            .with_audit(comment_audit(
                &request,
                &execution_evidence.container,
                action,
                Some(&inputs.comment_id),
                body_format.as_deref(),
                Some(CommentAuditListMetadata {
                    result_count: response.value.comments.len(),
                    has_more,
                }),
                self.backend.egress_proxy_audit(credential),
            ))
            .with_upstream(
                Some(response.status),
                Some(
                    execution_evidence
                        .upstream_duration_ms
                        .saturating_add(response.duration_ms),
                ),
            )
            .with_object_ids(comment_list_object_ids(
                &response.value.comments,
                &execution_evidence.container,
            )))
    }

    async fn invoke_comment_reply_add(
        &self,
        request: ProviderInvocation,
        action: ConfluenceCommentAction,
    ) -> Result<ProviderResult, ProviderError> {
        let credential = invocation_credential(&request)?;
        let lookup_credential = lookup_credential(request.admitted())?;
        let inputs = parse_comment_reply_add_inputs(request.inputs())?;
        let (body, content_audit, attribution) = self.prepare_write_content(
            request.action(),
            ConfluenceWriteTarget::Comment,
            &inputs.content_format,
            &inputs.content,
            &request,
        )?;
        let evidence = self
            .comment_container_evidence(action, &inputs.comment_id, None, lookup_credential)
            .await?;
        ensure_authorized_comment_container(&evidence.container, request.resource_scopes()?)?;
        let execution_evidence = self
            .comment_container_evidence(action, &inputs.comment_id, None, credential)
            .await?;
        ensure_matching_comment_evidence(&evidence, &execution_evidence)?;
        ensure_authorized_comment_container(
            &execution_evidence.container,
            request.resource_scopes()?,
        )?;
        let write = ConfluenceWrite::new(json!({ "parentCommentId": inputs.comment_id }));
        let response = self
            .backend
            .add_comment(
                ConfluenceCommentCreateRequest {
                    kind: action.kind,
                    container_type: action.container_type,
                    page_id: None,
                    blog_id: None,
                    parent_comment_id: Some(inputs.comment_id.clone()),
                    body,
                },
                credential,
            )
            .await
            .map_err(|error| write.failed(error))?;
        after_accepted_write("mutation_response", write.locators(), async {
        validate_created_reply(
            &response.value,
            action,
            &execution_evidence.container,
            &inputs.comment_id,
        )?;
        let created_evidence = self
            .comment_container_evidence(action, &response.value.id, Some("storage"), credential)
            .await
            .map_err(|error| {
                // The reply exists: throttling must not invite a second reply.
                error.unverified_after_mutation(
                    "post_create_readback",
                    json!({
                        "commentId": response.value.id,
                        "parentCommentId": inputs.comment_id,
                    }),
                )
            })?;
        ensure_created_reply_matches_parent(
            &created_evidence,
            &execution_evidence,
            &inputs.comment_id,
        )?;
        let created_duration_ms = created_evidence.upstream_duration_ms;
        let created_comment = created_evidence.target;
        let result = json!({
            "comment": comment_result(&created_comment, action, &execution_evidence.container, Some("storage"))?,
        });
        enforce_result_size(&result, self.limits.max_upstream_response_bytes)?;
        let mut audit = comment_audit(
            &request,
            &execution_evidence.container,
            action,
            Some(&created_comment.id),
            Some("storage"),
            None,
            self.backend.egress_proxy_audit(credential),
        );
        merge_confluence_content_write_audit(&mut audit, &content_audit);
        merge_attribution_audit(&mut audit, attribution);
        Ok(ProviderResult::new(result)
            .with_audit(audit)
            .with_upstream(
                Some(response.status),
                Some(
                    execution_evidence
                        .upstream_duration_ms
                        .saturating_add(response.duration_ms)
                        .saturating_add(created_duration_ms),
                ),
            )
            .with_object_ids(comment_object_ids(
                &created_comment,
                &execution_evidence.container,
            )))
        })
        .await
    }

    async fn invoke_page_view(
        &self,
        request: ProviderInvocation,
    ) -> Result<ProviderResult, ProviderError> {
        let credential = invocation_credential(&request)?;
        let authorized_space = authorized_single_scope(request.resource_scopes()?, "space")?;
        let locator = page_locator_from_inputs(request.inputs(), &self.config)?;
        let authorized_page = locator.page_id.as_str();

        let response = self
            .backend
            .page(authorized_page, credential)
            .await
            .map_err(confluence_backend_error)?;
        let page = response.value;
        if page.id != authorized_page || page.space != authorized_space {
            return Err(ProviderError::deny(
                ReasonCode::ScopeUnresolved,
                "Confluence page response no longer matches the authorized scope",
            ));
        }
        enforce_page_body_sizes(
            &page,
            &self.config.content.page_formats,
            self.config.content.max_body_bytes,
        )?;
        let result = page_view_result(&page, &self.config.content.page_formats, &self.config)?;
        enforce_result_size(&result, self.limits.max_upstream_response_bytes)?;
        Ok(ProviderResult::new(result)
            .with_audit(json!({
                "provider": "confluence",
                "operation": "page.view",
                "pageId": page.id,
                "space": page.space,
                "returnedUrlFields": ["webUrl", "spaceUrl"],
                "credentialMode": request.credential_mode(),
                "egressProxy": self.backend.egress_proxy_audit(credential),
            }))
            .with_upstream(Some(response.status), Some(response.duration_ms))
            .with_object_ids(json!({
                "pageId": page.id,
            })))
    }

    async fn invoke_search(
        &self,
        request: ProviderInvocation,
    ) -> Result<ProviderResult, ProviderError> {
        let credential = invocation_credential(&request)?;
        let inputs = parse_search_inputs(request.inputs())?;
        let requested = requested_spaces(&inputs)?;
        let authorization = search_authorization(&request)?;
        let effective_scope = effective_search_scope(&authorization, &requested)?;
        let query =
            build_confluence_search_query(&inputs.query, &effective_scope, &self.config.search)?;
        let response_scope = query.response_scope.clone();
        let max_results = capped_max_results(inputs.max_results, &self.config.search)?;
        let pages = SearchPageRequest {
            context: request.context(),
            credential,
            query: &query,
            requested_spaces: &requested,
            max_results,
        };
        let upstream_page_token = inputs
            .next_page_token
            .as_deref()
            .map(|token| self.continuations.open_search_page(&pages, token))
            .transpose()?;
        let response = self
            .backend
            .search(
                ConfluenceSearchRequest {
                    cql: query.cql.clone(),
                    spaces: response_scope.values_for_backend(),
                    max_results,
                    next_page_token: upstream_page_token,
                },
                credential,
            )
            .await
            .map_err(confluence_backend_error)?;

        if response.value.pages.len() > max_results as usize {
            return Err(ProviderError::error(
                ReasonCode::UpstreamProtocolFailed,
                "Confluence search returned more pages than requested",
            ));
        }
        for page in &response.value.pages {
            if !is_page_id(&page.id)
                || !is_space_key(&page.space)
                || page.status.as_deref() != Some("current")
                || !response_scope.authorizes_value(&page.space)
            {
                return Err(ProviderError::deny(
                    ReasonCode::ScopeUnresolved,
                    "Confluence search returned a page outside the authorized space scope",
                ));
            }
        }
        let observed_spaces = response
            .value
            .pages
            .iter()
            .map(|page| page.space.clone())
            .collect::<BTreeSet<_>>();

        let next_page_token = response
            .value
            .next_page_token
            .as_deref()
            .map(|upstream| self.continuations.seal_search_page(&pages, upstream))
            .transpose()?;
        let result = search_result(&response.value, next_page_token.as_deref(), &self.config)?;
        enforce_result_size(&result, self.limits.max_upstream_response_bytes)?;
        Ok(ProviderResult::new(result)
            .with_audit(json!({
                "provider": "confluence",
                "operation": "search",
                "requestedSpaces": requested,
                "effectiveSearchScope": response_scope.audit_value("space"),
                "queryType": query.kind,
                "queryAstVersion": CONFLUENCE_QUERY_AST_VERSION,
                "canonicalCallerCqlHash": query.canonical_caller_cql_hash,
                "queryShape": query.query_shape,
                "textOperandHashes": query.text_operand_hashes,
                "injectedSpacePredicate": query.injected_space_predicate,
                "injectedTypePredicate": query.injected_type_predicate,
                "observedSpaces": observed_spaces,
                "returnedUrlFields": ["webUrl", "spaceUrl"],
                "sortFields": query.sort_fields,
                "maxResults": max_results,
                "resultCount": response.value.pages.len(),
                "credentialMode": request.credential_mode(),
                "egressProxy": self.backend.egress_proxy_audit(credential),
            }))
            .with_upstream(Some(response.status), Some(response.duration_ms))
            .with_object_ids(json!({
                "pageIds": response
                    .value
                    .pages
                    .iter()
                    .map(|page| page.id.clone())
                    .collect::<Vec<_>>(),
            })))
    }

    async fn invoke_page_create(
        &self,
        request: ProviderInvocation,
    ) -> Result<ProviderResult, ProviderError> {
        let credential = invocation_credential(&request)?;
        let lookup_credential = lookup_credential(request.admitted())?;
        let authorized_space = authorized_single_scope(request.resource_scopes()?, "space")?;
        let inputs = parse_page_create_inputs(request.inputs(), &self.config)?;
        if inputs.space != authorized_space {
            return Err(ProviderError::deny(
                ReasonCode::ScopeUnresolved,
                "Confluence page create scope did not match the authorized space",
            ));
        }
        let (body, content_audit, attribution) = self.prepare_write_content(
            "page.create",
            ConfluenceWriteTarget::CurrentPage,
            &inputs.content_format,
            &inputs.content,
            &request,
        )?;
        let space_response = self
            .backend
            .space_by_key(&inputs.space, lookup_credential)
            .await
            .map_err(confluence_backend_error)?;
        let space = space_response.value;
        if space.key != inputs.space {
            return Err(ProviderError::deny(
                ReasonCode::ScopeUnresolved,
                "Confluence space lookup did not match the authorized page-create space",
            ));
        }
        let requested_parent_page_id = if let Some(parent_locator) = &inputs.parent {
            let parent = self
                .confirmed_page(
                    &parent_locator.page_id,
                    parent_locator.candidate_space.as_deref(),
                    lookup_credential,
                )
                .await?;
            validate_page_locator_space(parent_locator, &parent.space)?;
            if parent.space != space.key {
                return Err(ProviderError::deny(
                    ReasonCode::ScopeUnresolved,
                    "Confluence parent page is outside the authorized create space",
                ));
            }
            Some(parent.id)
        } else {
            None
        };
        let effective_parent_page_id = requested_parent_page_id
            .clone()
            .or_else(|| space.homepage_id.clone())
            .ok_or_else(|| {
                ProviderError::error(
                    ReasonCode::UpstreamProtocolFailed,
                    "Confluence space lookup omitted the homepage required for default placement",
                )
            })?;
        let write = ConfluenceWrite::new(
            json!({ "space": inputs.space, "parentPageId": effective_parent_page_id }),
        );
        let response = match self
            .backend
            .create_page(
                ConfluencePageCreateRequest {
                    space: inputs.space.clone(),
                    space_id: space.id.clone(),
                    parent_page_id: requested_parent_page_id.clone(),
                    title: inputs.title,
                    body,
                },
                credential,
            )
            .await
        {
            Ok(response) => response,
            Err(error) => {
                let mut audit = page_placement_failure_audit_partial(
                    &request,
                    "page.create",
                    None,
                    (&space.key, &space.id, &effective_parent_page_id),
                    "create_mutation",
                    self.backend.egress_proxy_audit(credential),
                );
                audit["upstreamFailure"] = json!(sanitized_backend_reason(&error));
                return Err(write
                    .failed(error)
                    .with_audit(audit)
                    .with_object_ids(json!({
                        "parentPageId": effective_parent_page_id,
                    })));
            }
        };
        after_accepted_write("mutation_response", write.locators(), async {
        let page = response.value;
        if page.space != inputs.space {
            return Err(ProviderError::deny(
                ReasonCode::ScopeUnresolved,
                "Confluence created page did not match the authorized space",
            ));
        }
        let readback_response = match self
            .backend
            .page_hierarchy(&page.id, false, credential)
            .await
        {
            Ok(readback) => readback,
            Err(error) => {
                let mut audit = page_placement_failure_audit(
                    &request,
                    "page.create",
                    (&page.id, &space.key, &space.id, &effective_parent_page_id),
                    "post_create_readback",
                    self.backend.egress_proxy_audit(credential),
                );
                audit["upstreamFailure"] = json!(sanitized_backend_reason(&error));
                // The page exists: throttling here must not invite a second create.
                return Err(confluence_backend_error(error)
                    .unverified_after_mutation(
                        "post_create_readback",
                        json!({
                            "pageId": page.id,
                            "parentPageId": effective_parent_page_id,
                        }),
                    )
                    .with_audit(audit)
                    .with_upstream(
                        Some(response.status),
                        Some(space_response.duration_ms + response.duration_ms),
                    )
                    .with_object_ids(json!({
                        "pageId": page.id,
                        "parentPageId": effective_parent_page_id,
                    })));
            }
        };
        if let Err(error) = validate_page_hierarchy(
            &readback_response.value,
            &page.id,
            &space.id,
            &effective_parent_page_id,
            "current",
        ) {
            return Err(error
                .with_audit(page_placement_failure_audit(
                    &request,
                    "page.create",
                    (&page.id, &space.key, &space.id, &effective_parent_page_id),
                    "post_create_readback",
                    self.backend.egress_proxy_audit(credential),
                ))
                .with_upstream(
                    Some(response.status),
                    Some(
                        space_response.duration_ms
                            + response.duration_ms
                            + readback_response.duration_ms,
                    ),
                )
                .with_object_ids(json!({
                    "pageId": page.id,
                    "parentPageId": effective_parent_page_id,
                })));
        }
        let (web_url, space_url) = page_browser_urls(&page, &self.config)?;
        let result = json!({
            "pageId": page.id,
            "space": page.space,
            "spaceUrl": space_url,
            "webUrl": web_url,
            "parentPageId": effective_parent_page_id,
            "placement": if requested_parent_page_id.is_some() { "requested_parent" } else { "space_homepage" },
            "verification": { "status": "matched" },
            "version": page.version,
            "createdAt": page.created_at,
            "updatedAt": page.updated_at,
            "createdBy": page.created_by,
            "updatedBy": page.updated_by,
        });
        enforce_result_size(&result, self.limits.max_upstream_response_bytes)?;
        let mut audit = json!({
            "provider": "confluence",
            "operation": "page.create",
            "pageId": page.id,
            "space": page.space,
            "spaceId": space.id,
            "version": page.version,
            "parentPageId": effective_parent_page_id,
            "placement": if requested_parent_page_id.is_some() { "requested_parent" } else { "space_homepage" },
            "verificationStatus": "matched",
            "returnedUrlFields": ["webUrl", "spaceUrl"],
            "bodyFormat": content_audit.native_format.as_str(),
            "credentialMode": request.credential_mode(),
            "egressProxy": self.backend.egress_proxy_audit(credential),
        });
        merge_confluence_content_write_audit(&mut audit, &content_audit);
        merge_attribution_audit(&mut audit, attribution);
        Ok(ProviderResult::new(result)
            .with_audit(audit)
            .with_upstream(
                Some(response.status),
                Some(
                    space_response.duration_ms
                        + response.duration_ms
                        + readback_response.duration_ms,
                ),
            )
            .with_object_ids(json!({
                "pageId": page.id,
                "parentPageId": effective_parent_page_id,
            })))
        })
        .await
    }

    async fn invoke_page_move(
        &self,
        request: ProviderInvocation,
    ) -> Result<ProviderResult, ProviderError> {
        let credential = invocation_credential(&request)?;
        let lookup_credential = lookup_credential(request.admitted())?;
        let inputs = parse_page_move_inputs(request.inputs(), &self.config)?;
        let page_response = self
            .confirmed_page_response(
                &inputs.page.page_id,
                inputs.page.candidate_space.as_deref(),
                lookup_credential,
            )
            .await?;
        let target_response = self
            .confirmed_page_response(
                &inputs.target.page_id,
                inputs.target.candidate_space.as_deref(),
                lookup_credential,
            )
            .await?;
        let page = page_response.value;
        let target = target_response.value;
        validate_page_locator_space(&inputs.page, &page.space)?;
        validate_page_locator_space(&inputs.target, &target.space)?;
        if page.id == target.id {
            return Err(ProviderError::deny(
                ReasonCode::InputInvalid,
                "confluence.page.move cannot target the page being moved",
            ));
        }
        if page.space != target.space {
            return Err(ProviderError::deny(
                ReasonCode::ScopeUnresolved,
                "Confluence page moves must stay within one space",
            ));
        }
        ensure_authorized_space(request.resource_scopes()?, &page.space)?;
        let space_response = self
            .backend
            .space_by_key(&page.space, lookup_credential)
            .await
            .map_err(confluence_backend_error)?;
        let space = space_response.value;
        if space.key != page.space {
            return Err(ProviderError::deny(
                ReasonCode::ScopeUnresolved,
                "Confluence page hierarchy space lookup changed before mutation",
            ));
        }
        let page_hierarchy_response = self
            .backend
            .page_hierarchy(&page.id, false, lookup_credential)
            .await
            .map_err(confluence_backend_error)?;
        let target_hierarchy_response = self
            .backend
            .page_hierarchy(&target.id, false, lookup_credential)
            .await
            .map_err(confluence_backend_error)?;
        validate_current_hierarchy_identity(&page_hierarchy_response.value, &page.id, &space.id)?;
        validate_current_hierarchy_identity(
            &target_hierarchy_response.value,
            &target.id,
            &space.id,
        )?;
        let previous_parent_id = page_hierarchy_response.value.parent_page_id.clone();
        let previous_parent_type = page_hierarchy_response.value.parent_type.clone();
        let effective_parent_page_id = match inputs.position {
            ConfluencePageMovePosition::Append => target.id.clone(),
            ConfluencePageMovePosition::Before | ConfluencePageMovePosition::After => {
                required_target_page_parent_id(&target_hierarchy_response.value)?.to_string()
            }
        };
        let effective_parent_response = self
            .confirmed_page_response(&effective_parent_page_id, None, lookup_credential)
            .await?;
        if effective_parent_response.value.space != page.space {
            return Err(ProviderError::deny(
                ReasonCode::ScopeUnresolved,
                "Confluence page move parent is outside the authorized space",
            ));
        }
        let effective_parent_hierarchy_response = self
            .backend
            .page_hierarchy(&effective_parent_page_id, false, lookup_credential)
            .await
            .map_err(confluence_backend_error)?;
        validate_current_hierarchy_identity(
            &effective_parent_hierarchy_response.value,
            &effective_parent_page_id,
            &space.id,
        )?;
        if effective_parent_page_id == page.id {
            return Err(ProviderError::deny(
                ReasonCode::InputInvalid,
                "confluence.page.move would make a page its own parent",
            ));
        }
        let ancestors_response = self
            .backend
            .page_ancestors(&effective_parent_page_id, credential)
            .await
            .map_err(confluence_backend_error)?;
        if ancestors_response
            .value
            .iter()
            .any(|ancestor| ancestor.id == page.id)
        {
            return Err(ProviderError::deny(
                ReasonCode::InputInvalid,
                "confluence.page.move would create a page hierarchy cycle",
            ));
        }

        let write = ConfluenceWrite::new(
            json!({ "pageId": page.id, "targetPageId": target.id, "parentPageId": effective_parent_page_id }),
        );
        let move_response = match self
            .backend
            .move_page(&page.id, inputs.position, &target.id, credential)
            .await
        {
            Ok(response) => response,
            Err(error) => {
                let mut audit = page_move_failure_audit(
                    &request,
                    (
                        &page.id,
                        &target.id,
                        &space.key,
                        &space.id,
                        &effective_parent_page_id,
                    ),
                    inputs.position,
                    "move_mutation",
                    self.backend.egress_proxy_audit(credential),
                );
                audit["upstreamFailure"] = json!(sanitized_backend_reason(&error));
                return Err(write
                    .failed(error)
                    .with_audit(audit)
                    .with_object_ids(json!({
                        "pageId": page.id,
                        "targetPageId": target.id,
                        "parentPageId": effective_parent_page_id,
                        "previousParentId": previous_parent_id,
                        "previousParentType": previous_parent_type,
                    })));
            }
        };
        after_accepted_write("mutation_response", write.locators(), async {
            let mut upstream_duration_ms = page_response.duration_ms
                + target_response.duration_ms
                + space_response.duration_ms
                + page_hierarchy_response.duration_ms
                + target_hierarchy_response.duration_ms
                + effective_parent_response.duration_ms
                + effective_parent_hierarchy_response.duration_ms
                + ancestors_response.duration_ms
                + move_response.duration_ms;
            if move_response.value != page.id {
                return Err(ProviderError::error(
                    ReasonCode::UpstreamProtocolFailed,
                    "Confluence page move response did not match the moved page",
                )
                .with_audit(page_move_failure_audit(
                    &request,
                    (
                        &page.id,
                        &target.id,
                        &space.key,
                        &space.id,
                        &effective_parent_page_id,
                    ),
                    inputs.position,
                    "move_response",
                    self.backend.egress_proxy_audit(credential),
                ))
                .with_upstream(Some(move_response.status), Some(upstream_duration_ms))
                .with_object_ids(json!({
                    "pageId": page.id,
                    "targetPageId": target.id,
                    "parentPageId": effective_parent_page_id,
                    "previousParentId": previous_parent_id,
                    "previousParentType": previous_parent_type,
                })));
            }
            let hierarchy_readback_response = match self
                .backend
                .page_hierarchy(&page.id, false, credential)
                .await
            {
                Ok(readback) => readback,
                Err(error) => {
                    let mut audit = page_move_failure_audit(
                        &request,
                        (
                            &page.id,
                            &target.id,
                            &space.key,
                            &space.id,
                            &effective_parent_page_id,
                        ),
                        inputs.position,
                        "post_move_hierarchy_readback",
                        self.backend.egress_proxy_audit(credential),
                    );
                    audit["upstreamFailure"] = json!(sanitized_backend_reason(&error));
                    return Err(confluence_backend_error(error)
                        .unverified_after_mutation(
                            "post_move_hierarchy_readback",
                            json!({
                                "pageId": page.id,
                                "targetPageId": target.id,
                                "parentPageId": effective_parent_page_id,
                                "previousParentId": previous_parent_id,
                                "previousParentType": previous_parent_type,
                            }),
                        )
                        .with_audit(audit)
                        .with_upstream(Some(move_response.status), Some(upstream_duration_ms))
                        .with_object_ids(json!({
                            "pageId": page.id,
                            "targetPageId": target.id,
                            "parentPageId": effective_parent_page_id,
                            "previousParentId": previous_parent_id,
                            "previousParentType": previous_parent_type,
                        })));
                }
            };
            upstream_duration_ms += hierarchy_readback_response.duration_ms;
            if let Err(error) = validate_page_hierarchy(
                &hierarchy_readback_response.value,
                &page.id,
                &space.id,
                &effective_parent_page_id,
                "current",
            ) {
                return Err(error
                    .with_audit(page_move_failure_audit(
                        &request,
                        (
                            &page.id,
                            &target.id,
                            &space.key,
                            &space.id,
                            &effective_parent_page_id,
                        ),
                        inputs.position,
                        "post_move_hierarchy_readback",
                        self.backend.egress_proxy_audit(credential),
                    ))
                    .with_upstream(Some(move_response.status), Some(upstream_duration_ms))
                    .with_object_ids(json!({
                        "pageId": page.id,
                        "targetPageId": target.id,
                        "parentPageId": effective_parent_page_id,
                        "previousParentId": previous_parent_id,
                        "previousParentType": previous_parent_type,
                    })));
            }
            let children_readback_response = match self
                .backend
                .page_direct_children(&effective_parent_page_id, credential)
                .await
            {
                Ok(readback) => readback,
                Err(error) => {
                    let mut audit = page_move_failure_audit(
                        &request,
                        (
                            &page.id,
                            &target.id,
                            &space.key,
                            &space.id,
                            &effective_parent_page_id,
                        ),
                        inputs.position,
                        "post_move_order_readback",
                        self.backend.egress_proxy_audit(credential),
                    );
                    audit["upstreamFailure"] = json!(sanitized_backend_reason(&error));
                    return Err(confluence_backend_error(error)
                        .unverified_after_mutation(
                            "post_move_order_readback",
                            json!({
                                "pageId": page.id,
                                "targetPageId": target.id,
                                "parentPageId": effective_parent_page_id,
                                "previousParentId": previous_parent_id,
                                "previousParentType": previous_parent_type,
                            }),
                        )
                        .with_audit(audit)
                        .with_upstream(Some(move_response.status), Some(upstream_duration_ms))
                        .with_object_ids(json!({
                            "pageId": page.id,
                            "targetPageId": target.id,
                            "parentPageId": effective_parent_page_id,
                            "previousParentId": previous_parent_id,
                            "previousParentType": previous_parent_type,
                        })));
                }
            };
            upstream_duration_ms += children_readback_response.duration_ms;
            let (child_position, target_child_position) = match verify_page_move_order(
                &children_readback_response.value,
                &page.id,
                &target.id,
                inputs.position,
            ) {
                Ok(positions) => positions,
                Err(error) => {
                    return Err(error
                        .with_audit(page_move_failure_audit(
                            &request,
                            (
                                &page.id,
                                &target.id,
                                &space.key,
                                &space.id,
                                &effective_parent_page_id,
                            ),
                            inputs.position,
                            "post_move_order_readback",
                            self.backend.egress_proxy_audit(credential),
                        ))
                        .with_upstream(Some(move_response.status), Some(upstream_duration_ms))
                        .with_object_ids(json!({
                            "pageId": page.id,
                            "targetPageId": target.id,
                            "parentPageId": effective_parent_page_id,
                            "previousParentId": previous_parent_id,
                            "previousParentType": previous_parent_type,
                        })));
                }
            };
            let mut result = json!({
                "operation": "page.move",
                "pageId": page.id,
                "position": inputs.position.as_str(),
                "targetPageId": target.id,
                "space": space.key,
                "parentPageId": effective_parent_page_id,
                "previousParentId": previous_parent_id,
                "previousParentType": previous_parent_type,
                "childPosition": child_position,
                "verification": { "status": "matched" },
            });
            if let Some(target_child_position) = target_child_position {
                result["targetChildPosition"] = json!(target_child_position);
            }
            enforce_result_size(&result, self.limits.max_upstream_response_bytes)?;
            let mut audit = json!({
                "provider": "confluence",
                "operation": "page.move",
                "pageId": page.id,
                "position": inputs.position.as_str(),
                "targetPageId": target.id,
                "space": space.key,
                "spaceId": space.id,
                "parentPageId": effective_parent_page_id,
                "previousParentId": previous_parent_id,
                "previousParentType": previous_parent_type,
                "childPosition": child_position,
                "verificationStatus": "matched",
                "credentialMode": request.credential_mode(),
                "egressProxy": self.backend.egress_proxy_audit(credential),
            });
            if let Some(target_child_position) = target_child_position {
                audit["targetChildPosition"] = json!(target_child_position);
            }
            Ok(ProviderResult::new(result)
                .with_audit(audit)
                .with_upstream(Some(move_response.status), Some(upstream_duration_ms))
                .with_object_ids(json!({
                    "pageId": page.id,
                    "targetPageId": target.id,
                    "parentPageId": effective_parent_page_id,
                    "previousParentId": previous_parent_id,
                    "previousParentType": previous_parent_type,
                })))
        })
        .await
    }

    async fn invoke_page_update(
        &self,
        request: ProviderInvocation,
    ) -> Result<ProviderResult, ProviderError> {
        let credential = invocation_credential(&request)?;
        let inputs = parse_page_update_inputs(request.inputs())?;
        let title_override = inputs.title.clone();
        let (body, content_audit, attribution) = self.prepare_write_content(
            "page.update",
            ConfluenceWriteTarget::CurrentPage,
            &inputs.content_format,
            &inputs.content,
            &request,
        )?;
        let metadata_response = self
            .confirmed_page_response(&inputs.page_id, None, credential)
            .await?;
        let metadata = metadata_response.value;
        if metadata.version != inputs.base_version {
            return Err(version_conflict_error(
                &request,
                &metadata,
                inputs.base_version,
                metadata_response.status,
                metadata_response.duration_ms,
                self.backend.egress_proxy_audit(credential),
            ));
        }
        let write = ConfluenceWrite::new(json!({ "pageId": inputs.page_id }));
        let response = match self
            .backend
            .update_page(
                ConfluencePageUpdateRequest {
                    page_id: metadata.id.clone(),
                    space: metadata.space.clone(),
                    title: title_override.unwrap_or_else(|| metadata.title.clone()),
                    base_version: inputs.base_version,
                    body,
                },
                credential,
            )
            .await
        {
            Ok(response) => response,
            Err(ConfluenceBackendError::Conflict) => {
                return Err(upstream_version_conflict_error(
                    &request,
                    &metadata,
                    inputs.base_version,
                    self.backend.egress_proxy_audit(credential),
                ));
            }
            Err(error) => return Err(write.failed(error)),
        };
        after_accepted_write("mutation_response", write.locators(), async {
            let page = response.value;
            if page.id != metadata.id || page.space != metadata.space {
                return Err(ProviderError::deny(
                    ReasonCode::ScopeUnresolved,
                    "Confluence updated page did not match the authorized scope",
                ));
            }
            if page.version != inputs.base_version + 1 {
                return Err(ProviderError::error(
                    ReasonCode::UpstreamProtocolFailed,
                    "Confluence updated page version did not match the requested base version",
                ));
            }
            let (web_url, space_url) = page_browser_urls(&page, &self.config)?;
            let result = json!({
                "pageId": page.id,
                "space": page.space,
                "spaceUrl": space_url,
                "webUrl": web_url,
                "previousVersion": inputs.base_version,
                "version": page.version,
                "createdAt": page.created_at,
                "updatedAt": page.updated_at,
                "createdBy": page.created_by,
                "updatedBy": page.updated_by,
            });
            enforce_result_size(&result, self.limits.max_upstream_response_bytes)?;
            let mut audit = json!({
                "provider": "confluence",
                "operation": "page.update",
                "pageId": page.id,
                "space": page.space,
                "previousVersion": inputs.base_version,
                "version": page.version,
                "returnedUrlFields": ["webUrl", "spaceUrl"],
                "bodyFormat": content_audit.native_format.as_str(),
                "credentialMode": request.credential_mode(),
                "egressProxy": self.backend.egress_proxy_audit(credential),
            });
            merge_confluence_content_write_audit(&mut audit, &content_audit);
            merge_attribution_audit(&mut audit, attribution);
            Ok(ProviderResult::new(result)
                .with_audit(audit)
                .with_upstream(
                    Some(response.status),
                    Some(metadata_response.duration_ms + response.duration_ms),
                )
                .with_object_ids(json!({
                    "pageId": page.id,
                })))
        })
        .await
    }

    async fn invoke_page_draft_create(
        &self,
        request: ProviderInvocation,
    ) -> Result<ProviderResult, ProviderError> {
        let credential = invocation_credential(&request)?;
        let lookup_credential = lookup_credential(request.admitted())?;
        let authorized_space = authorized_single_scope(request.resource_scopes()?, "space")?;
        let inputs = parse_page_draft_create_inputs(request.inputs(), &self.config)?;
        if inputs.space != authorized_space {
            return Err(ProviderError::deny(
                ReasonCode::ScopeUnresolved,
                "Confluence page draft create scope did not match the authorized space",
            ));
        }
        let (body, content_audit, attribution) = self.prepare_write_content(
            "page.draft.create",
            ConfluenceWriteTarget::PageDraft,
            &inputs.content_format,
            &inputs.content,
            &request,
        )?;
        let space_response = self
            .backend
            .space_by_key(&inputs.space, lookup_credential)
            .await
            .map_err(confluence_backend_error)?;
        if space_response.value.key != inputs.space {
            return Err(ProviderError::deny(
                ReasonCode::ScopeUnresolved,
                "Confluence space lookup did not match the authorized space",
            ));
        }
        let requested_parent_page_id = if let Some(parent_locator) = &inputs.parent {
            let parent = self
                .confirmed_page(
                    &parent_locator.page_id,
                    parent_locator.candidate_space.as_deref(),
                    lookup_credential,
                )
                .await?;
            validate_page_locator_space(parent_locator, &parent.space)?;
            if parent.space != space_response.value.key {
                return Err(ProviderError::deny(
                    ReasonCode::ScopeUnresolved,
                    "Confluence parent page is outside the authorized draft-create space",
                ));
            }
            Some(parent.id)
        } else {
            None
        };
        let effective_parent_page_id = requested_parent_page_id
            .clone()
            .or_else(|| space_response.value.homepage_id.clone())
            .ok_or_else(|| {
                ProviderError::error(
                    ReasonCode::UpstreamProtocolFailed,
                    "Confluence space lookup omitted the homepage required for default draft placement",
                )
            })?;
        let write = ConfluenceWrite::new(
            json!({ "space": inputs.space, "parentPageId": effective_parent_page_id }),
        );
        let response = match self
            .backend
            .create_page_draft(
                ConfluenceDraftCreateRequest {
                    content_type: "page".to_string(),
                    space: inputs.space,
                    space_id: space_response.value.id.clone(),
                    parent_page_id: requested_parent_page_id.clone(),
                    title: inputs.title,
                    body,
                },
                credential,
            )
            .await
        {
            Ok(response) => response,
            Err(error) => {
                let mut audit = page_placement_failure_audit_partial(
                    &request,
                    "page.draft.create",
                    None,
                    (
                        &space_response.value.key,
                        &space_response.value.id,
                        &effective_parent_page_id,
                    ),
                    "create_mutation",
                    self.backend.egress_proxy_audit(credential),
                );
                audit["upstreamFailure"] = json!(sanitized_backend_reason(&error));
                return Err(write
                    .failed(error)
                    .with_audit(audit)
                    .with_object_ids(json!({
                        "parentPageId": effective_parent_page_id,
                    })));
            }
        };
        after_accepted_write("mutation_response", write.locators(), async {
            let mut draft = response.value;
            draft.space = space_response.value.key;
            draft.space_web_url = space_response.value.web_url;
            require_draft_content(&draft, ConfluenceDraftContentType::Page)?;
            if draft.space != authorized_space || draft.space_id != space_response.value.id {
                return Err(ProviderError::deny(
                    ReasonCode::ScopeUnresolved,
                    "Confluence created page draft did not match the authorized space",
                ));
            }
            if draft.parent_page_id.as_deref() != Some(effective_parent_page_id.as_str()) {
                return Err(ProviderError::error(
                    ReasonCode::UpstreamProtocolFailed,
                    "Confluence created page draft did not confirm the requested parent",
                )
                .with_audit(page_placement_failure_audit(
                    &request,
                    "page.draft.create",
                    (
                        &draft.id,
                        &draft.space,
                        &draft.space_id,
                        &effective_parent_page_id,
                    ),
                    "create_response",
                    self.backend.egress_proxy_audit(credential),
                ))
                .with_upstream(
                    Some(response.status),
                    Some(space_response.duration_ms + response.duration_ms),
                )
                .with_object_ids(json!({
                    "pageId": draft.id,
                    "parentPageId": effective_parent_page_id,
                })));
            }
            let readback_response = match self
                .backend
                .page_hierarchy(&draft.id, true, credential)
                .await
            {
                Ok(readback) => readback,
                Err(error) => {
                    let mut audit = page_placement_failure_audit(
                        &request,
                        "page.draft.create",
                        (
                            &draft.id,
                            &draft.space,
                            &draft.space_id,
                            &effective_parent_page_id,
                        ),
                        "post_create_readback",
                        self.backend.egress_proxy_audit(credential),
                    );
                    audit["upstreamFailure"] = json!(sanitized_backend_reason(&error));
                    return Err(confluence_backend_error(error)
                        .unverified_after_mutation(
                            "post_create_readback",
                            json!({
                                "pageId": draft.id,
                                "parentPageId": effective_parent_page_id,
                            }),
                        )
                        .with_audit(audit)
                        .with_upstream(
                            Some(response.status),
                            Some(space_response.duration_ms + response.duration_ms),
                        )
                        .with_object_ids(json!({
                            "pageId": draft.id,
                            "parentPageId": effective_parent_page_id,
                        })));
                }
            };
            if let Err(error) = validate_page_hierarchy(
                &readback_response.value,
                &draft.id,
                &draft.space_id,
                &effective_parent_page_id,
                "draft",
            ) {
                return Err(error
                    .with_audit(page_placement_failure_audit(
                        &request,
                        "page.draft.create",
                        (
                            &draft.id,
                            &draft.space,
                            &draft.space_id,
                            &effective_parent_page_id,
                        ),
                        "post_create_readback",
                        self.backend.egress_proxy_audit(credential),
                    ))
                    .with_upstream(
                        Some(response.status),
                        Some(
                            space_response.duration_ms
                                + response.duration_ms
                                + readback_response.duration_ms,
                        ),
                    )
                    .with_object_ids(json!({
                        "pageId": draft.id,
                        "parentPageId": effective_parent_page_id,
                    })));
            }
            let draft_handle = self.mint_draft_handle(
                ConfluenceDraftContentType::Page,
                &draft,
                ConfluenceDraftOrigin::New,
                None,
                &request,
            )?;
            let result = draft_content_result(
                "page.draft.create",
                &draft,
                ConfluenceDraftContentType::Page,
                Some(draft_handle),
                None,
                &self.config,
            )?;
            enforce_result_size(&result, self.limits.max_upstream_response_bytes)?;
            let mut audit = draft_audit(
                &request,
                "page.draft.create",
                &draft,
                ConfluenceDraftContentType::Page,
                Some("storage"),
                true,
                self.backend.egress_proxy_audit(credential),
            );
            merge_confluence_content_write_audit(&mut audit, &content_audit);
            merge_attribution_audit(&mut audit, attribution);
            Ok(ProviderResult::new(result)
                .with_audit(audit)
                .with_upstream(
                    Some(response.status),
                    Some(
                        space_response.duration_ms
                            + response.duration_ms
                            + readback_response.duration_ms,
                    ),
                )
                .with_object_ids(json!({
                    "pageId": draft.id,
                    "parentPageId": effective_parent_page_id,
                })))
        })
        .await
    }

    async fn invoke_page_draft_stage(
        &self,
        request: ProviderInvocation,
    ) -> Result<ProviderResult, ProviderError> {
        let credential = invocation_credential(&request)?;
        let lookup_credential = lookup_credential(request.admitted())?;
        let inputs = parse_page_draft_stage_inputs(request.inputs())?;
        let (body, content_audit, attribution) = self.prepare_write_content(
            "page.draft.stage",
            ConfluenceWriteTarget::PageDraft,
            &inputs.content_format,
            &inputs.content,
            &request,
        )?;
        let current_response = self
            .confirmed_page_response(&inputs.page_id, None, lookup_credential)
            .await?;
        let current = current_response.value;
        ensure_authorized_space(request.resource_scopes()?, &current.space)?;
        if current.version != inputs.base_version {
            return Err(version_conflict_error(
                &request,
                &current,
                inputs.base_version,
                current_response.status,
                current_response.duration_ms,
                self.backend.egress_proxy_audit(lookup_credential),
            ));
        }
        match self
            .draft_page_response_with_space(&inputs.page_id, Some("storage"), lookup_credential)
            .await
        {
            Ok(response) if response.value.status.as_deref() == Some("draft") => {
                return Err(draft_version_conflict_error(
                    &request,
                    &response.value,
                    ConfluenceDraftContentType::Page,
                    inputs.base_version,
                    self.backend.egress_proxy_audit(lookup_credential),
                ));
            }
            Ok(_) => {}
            Err(error) if error.reason_code() == ReasonCode::ScopeUnresolved => {}
            Err(error) => return Err(error),
        }
        let space_response = self
            .backend
            .space_by_key(&current.space, lookup_credential)
            .await
            .map_err(confluence_backend_error)?;
        let write = ConfluenceWrite::new(json!({ "pageId": inputs.page_id }));
        let response = self
            .backend
            .update_page_draft(
                ConfluenceDraftUpdateRequest {
                    content_type: "page".to_string(),
                    content_id: current.id.clone(),
                    space_id: space_response.value.id.clone(),
                    title: inputs.title.unwrap_or_else(|| current.title.clone()),
                    status: "draft".to_string(),
                    version_number: 1,
                    body,
                },
                credential,
            )
            .await
            .map_err(|error| write.failed_with(error, map_confluence_conflict))?;
        after_accepted_write("mutation_response", write.locators(), async {
            let mut draft = response.value;
            draft.space = current.space;
            draft.space_web_url = space_response.value.web_url;
            require_draft_content(&draft, ConfluenceDraftContentType::Page)?;
            require_draft_version_one(&draft)?;
            let draft_handle = self.mint_draft_handle(
                ConfluenceDraftContentType::Page,
                &draft,
                ConfluenceDraftOrigin::Staged,
                Some(inputs.base_version),
                &request,
            )?;
            let mut result = draft_content_result(
                "page.draft.stage",
                &draft,
                ConfluenceDraftContentType::Page,
                Some(draft_handle),
                None,
                &self.config,
            )?;
            result["expectedBaseVersion"] = json!(inputs.base_version);
            enforce_result_size(&result, self.limits.max_upstream_response_bytes)?;
            let mut audit = draft_audit(
                &request,
                "page.draft.stage",
                &draft,
                ConfluenceDraftContentType::Page,
                Some("storage"),
                true,
                self.backend.egress_proxy_audit(credential),
            );
            audit["expectedBaseVersion"] = json!(inputs.base_version);
            merge_confluence_content_write_audit(&mut audit, &content_audit);
            merge_attribution_audit(&mut audit, attribution);
            Ok(ProviderResult::new(result)
                .with_audit(audit)
                .with_upstream(
                    Some(response.status),
                    Some(
                        current_response
                            .duration_ms
                            .saturating_add(space_response.duration_ms)
                            .saturating_add(response.duration_ms),
                    ),
                )
                .with_object_ids(json!({ "pageId": draft.id })))
        })
        .await
    }

    async fn invoke_page_draft_view(
        &self,
        request: ProviderInvocation,
    ) -> Result<ProviderResult, ProviderError> {
        let credential = invocation_credential(&request)?;
        let lookup_credential = lookup_credential(request.admitted())?;
        let inputs = parse_page_draft_body_format_inputs(request.action(), request.inputs())?;
        let handle = self.decode_draft_handle_for_request(
            ConfluenceDraftContentType::Page,
            &inputs.page_id,
            &inputs.draft_handle,
            request.admitted(),
        )?;
        let response = self
            .draft_page_response_with_space(
                &inputs.page_id,
                Some(&inputs.body_format),
                lookup_credential,
            )
            .await?;
        ensure_draft_content_matches_handle(&response.value, &handle)?;
        enforce_draft_body_size(&response.value, &inputs.body_format, &self.config)?;
        let result = draft_content_result(
            "page.draft.view",
            &response.value,
            ConfluenceDraftContentType::Page,
            Some(inputs.draft_handle),
            Some(inputs.body_format.as_str()),
            &self.config,
        )?;
        enforce_result_size(&result, self.limits.max_upstream_response_bytes)?;
        Ok(ProviderResult::new(result)
            .with_audit(draft_audit(
                &request,
                "page.draft.view",
                &response.value,
                ConfluenceDraftContentType::Page,
                Some(inputs.body_format.as_str()),
                false,
                self.backend.egress_proxy_audit(credential),
            ))
            .with_upstream(Some(response.status), Some(response.duration_ms))
            .with_object_ids(json!({ "pageId": response.value.id })))
    }

    async fn invoke_page_draft_update(
        &self,
        request: ProviderInvocation,
    ) -> Result<ProviderResult, ProviderError> {
        let credential = invocation_credential(&request)?;
        let lookup_credential = lookup_credential(request.admitted())?;
        let inputs = parse_page_draft_update_inputs(request.inputs())?;
        let (body, content_audit, attribution) = self.prepare_write_content(
            "page.draft.update",
            ConfluenceWriteTarget::PageDraft,
            &inputs.content_format,
            &inputs.content,
            &request,
        )?;
        let handle = self.decode_draft_handle_for_request(
            ConfluenceDraftContentType::Page,
            &inputs.page_id,
            &inputs.draft_handle,
            request.admitted(),
        )?;
        let current = self
            .draft_page_response_with_space(&inputs.page_id, Some("storage"), lookup_credential)
            .await?;
        ensure_draft_content_matches_handle(&current.value, &handle)?;
        require_draft_version_one(&current.value)?;
        let write = ConfluenceWrite::new(json!({ "pageId": inputs.page_id }));
        let response = self
            .backend
            .update_page_draft(
                ConfluenceDraftUpdateRequest {
                    content_type: "page".to_string(),
                    content_id: current.value.id.clone(),
                    space_id: current.value.space_id.clone(),
                    title: inputs.title.unwrap_or_else(|| current.value.title.clone()),
                    status: "draft".to_string(),
                    version_number: 1,
                    body,
                },
                credential,
            )
            .await
            .map_err(|error| write.failed_with(error, map_confluence_conflict))?;
        after_accepted_write("mutation_response", write.locators(), async {
            let mut draft = response.value;
            draft.space = current.value.space;
            draft.space_web_url = current.value.space_web_url;
            ensure_draft_content_matches_handle(&draft, &handle)?;
            require_draft_version_one(&draft)?;
            let result = draft_content_result(
                "page.draft.update",
                &draft,
                ConfluenceDraftContentType::Page,
                Some(inputs.draft_handle),
                None,
                &self.config,
            )?;
            enforce_result_size(&result, self.limits.max_upstream_response_bytes)?;
            let mut audit = draft_audit(
                &request,
                "page.draft.update",
                &draft,
                ConfluenceDraftContentType::Page,
                Some("storage"),
                true,
                self.backend.egress_proxy_audit(credential),
            );
            merge_confluence_content_write_audit(&mut audit, &content_audit);
            merge_attribution_audit(&mut audit, attribution);
            Ok(ProviderResult::new(result)
                .with_audit(audit)
                .with_upstream(
                    Some(response.status),
                    Some(current.duration_ms + response.duration_ms),
                )
                .with_object_ids(json!({ "pageId": draft.id })))
        })
        .await
    }

    async fn invoke_page_draft_publish(
        &self,
        request: ProviderInvocation,
    ) -> Result<ProviderResult, ProviderError> {
        let credential = invocation_credential(&request)?;
        let lookup_credential = lookup_credential(request.admitted())?;
        let inputs = parse_page_draft_body_format_inputs(request.action(), request.inputs())?;
        let handle = self.decode_draft_handle_for_request(
            ConfluenceDraftContentType::Page,
            &inputs.page_id,
            &inputs.draft_handle,
            request.admitted(),
        )?;
        let draft_response = self
            .draft_page_response_with_space(
                &inputs.page_id,
                Some(&inputs.body_format),
                lookup_credential,
            )
            .await?;
        let draft = draft_response.value;
        ensure_draft_content_matches_handle(&draft, &handle)?;
        require_draft_version_one(&draft)?;
        let body = draft_body_for_publish(&draft, &inputs.body_format)?;
        let draft_attachments = if handle.origin == ConfluenceDraftOrigin::New {
            self.draft_attachments_for_page(&draft.id, lookup_credential)
                .await?
                .value
        } else {
            Vec::new()
        };
        for attachment in &draft_attachments {
            if attachment.page_id != draft.id {
                return Err(ProviderError::error(
                    ReasonCode::UpstreamProtocolFailed,
                    "Confluence page draft attachment list returned a different parent",
                ));
            }
        }
        let write = ConfluenceWrite::new(json!({ "pageId": inputs.page_id }));
        let response = self
            .backend
            .update_page_draft(
                ConfluenceDraftUpdateRequest {
                    content_type: "page".to_string(),
                    content_id: draft.id.clone(),
                    space_id: draft.space_id.clone(),
                    title: draft.title.clone(),
                    status: "current".to_string(),
                    version_number: draft_publish_version(&handle)?,
                    body,
                },
                credential,
            )
            .await
            .map_err(|error| write.failed_with(error, map_confluence_conflict))?;
        after_accepted_write("mutation_response", write.locators(), async {
            let mut published = response.value;
            published.space = draft.space.clone();
            published.space_web_url = draft.space_web_url.clone();
            require_current_draft_content(&published, ConfluenceDraftContentType::Page)?;
            if published.id != draft.id
                || published.space_id != draft.space_id
                || published.parent_page_id != handle.parent_page_id
            {
                return Err(ProviderError::error(
                    ReasonCode::UpstreamProtocolFailed,
                    "Confluence published page did not preserve the broker-managed draft placement",
                ));
            }
            let published_attachment_ids = if draft_attachments.is_empty() {
                Vec::new()
            } else {
                let current_attachments = self
                    .backend
                    .page_attachments(&published.id, lookup_credential)
                    .await
                    .map_err(|error| {
                        // The page is published: throttling must not invite a second publish.
                        confluence_backend_error(error).unverified_after_mutation(
                            "post_publish_attachment_readback",
                            json!({"pageId": published.id}),
                        )
                    })?
                    .value;
                let current_ids = current_attachments
                    .iter()
                    .map(|attachment| attachment.id.as_str())
                    .collect::<BTreeSet<_>>();
                let draft_ids = draft_attachments
                    .iter()
                    .map(|attachment| attachment.id.clone())
                    .collect::<Vec<_>>();
                if draft_ids
                    .iter()
                    .any(|id| !current_ids.contains(id.as_str()))
                {
                    return Err(ProviderError::error(
                        ReasonCode::UpstreamProtocolFailed,
                        "Confluence page draft attachments were not preserved through publish",
                    ));
                }
                draft_ids
            };
            let mut result = draft_content_result(
                "page.draft.publish",
                &published,
                ConfluenceDraftContentType::Page,
                None,
                None,
                &self.config,
            )?;
            result["draftVersion"] = json!(draft.version);
            result["publishedAttachmentIds"] = json!(published_attachment_ids);
            enforce_result_size(&result, self.limits.max_upstream_response_bytes)?;
            let mut audit = draft_audit(
                &request,
                "page.draft.publish",
                &published,
                ConfluenceDraftContentType::Page,
                Some(inputs.body_format.as_str()),
                true,
                self.backend.egress_proxy_audit(credential),
            );
            audit["lifecycle"] = json!("current");
            audit["draftVersion"] = json!(draft.version);
            audit["attachmentIds"] = json!(published_attachment_ids);
            Ok(ProviderResult::new(result)
                .with_audit(audit)
                .with_upstream(
                    Some(response.status),
                    Some(draft_response.duration_ms + response.duration_ms),
                )
                .with_object_ids(json!({
                    "pageId": published.id,
                    "attachmentIds": published_attachment_ids,
                })))
        })
        .await
    }

    async fn invoke_page_draft_discard(
        &self,
        request: ProviderInvocation,
    ) -> Result<ProviderResult, ProviderError> {
        let credential = invocation_credential(&request)?;
        let lookup_credential = lookup_credential(request.admitted())?;
        let inputs = parse_page_draft_discard_inputs(request.inputs())?;
        let handle = self.decode_draft_handle_for_request(
            ConfluenceDraftContentType::Page,
            &inputs.page_id,
            &inputs.draft_handle,
            request.admitted(),
        )?;
        reject_staged_draft_discard(&handle)?;
        let draft_response = self
            .draft_page_response_with_space(&inputs.page_id, Some("storage"), lookup_credential)
            .await?;
        let draft = draft_response.value;
        ensure_draft_content_matches_handle(&draft, &handle)?;
        require_draft_version_one(&draft)?;
        let write = ConfluenceWrite::new(json!({ "pageId": inputs.page_id }));
        let response = self
            .backend
            .discard_page_draft(&draft.id, credential)
            .await
            .map_err(|error| write.failed(error))?;
        after_accepted_write("mutation_response", write.locators(), async {
            match self
                .backend
                .draft_page(&draft.id, Some("storage"), lookup_credential)
                .await
            {
                Ok(_) => {
                    return Err(ProviderError::error(
                        ReasonCode::UpstreamProtocolFailed,
                        "Confluence page draft still exists after discard",
                    ));
                }
                Err(error)
                    if confluence_backend_reason_code(&error) == ReasonCode::ScopeUnresolved => {}
                Err(error) => {
                    return Err(confluence_backend_error(error).unverified_after_mutation(
                        "post_discard_readback",
                        json!({"pageId": draft.id}),
                    ));
                }
            }
            match self
                .backend
                .page_metadata(&draft.id, lookup_credential)
                .await
            {
                Ok(_) => {
                    return Err(ProviderError::error(
                        ReasonCode::UpstreamProtocolFailed,
                        "Confluence page draft discard created current content",
                    ));
                }
                Err(error)
                    if confluence_backend_reason_code(&error) == ReasonCode::ScopeUnresolved => {}
                Err(error) => {
                    return Err(confluence_backend_error(error).unverified_after_mutation(
                        "post_discard_readback",
                        json!({"pageId": draft.id}),
                    ));
                }
            }
            let result = json!({
                "operation": "page.draft.discard",
                "pageId": draft.id,
                "lifecycle": "draft",
                "status": "discarded",
                "space": draft.space,
                "spaceId": draft.space_id,
                "discardedVersion": draft.version,
                "discarded": true,
            });
            enforce_result_size(&result, self.limits.max_upstream_response_bytes)?;
            Ok(ProviderResult::new(result)
                .with_audit(draft_audit(
                    &request,
                    "page.draft.discard",
                    &draft,
                    ConfluenceDraftContentType::Page,
                    None,
                    true,
                    self.backend.egress_proxy_audit(credential),
                ))
                .with_upstream(
                    Some(response.status),
                    Some(draft_response.duration_ms + response.duration_ms),
                )
                .with_object_ids(json!({ "pageId": draft.id })))
        })
        .await
    }

    async fn invoke_page_draft_verify(
        &self,
        request: ProviderInvocation,
    ) -> Result<ProviderResult, ProviderError> {
        let lookup_credential = lookup_credential(request.admitted())?;
        let inputs = parse_page_draft_verify_inputs(request.inputs())?;
        let handle = self.decode_draft_handle_for_request(
            ConfluenceDraftContentType::Page,
            &inputs.page_id,
            &inputs.draft_handle,
            request.admitted(),
        )?;
        let response = self
            .draft_page_response_with_space(&inputs.page_id, Some("storage"), lookup_credential)
            .await?;
        let draft = response.value;
        ensure_draft_content_matches_handle(&draft, &handle)?;
        let mut checked = Vec::new();
        if let Some(version) = inputs.expect_version {
            if draft.version != version {
                return Err(draft_verification_mismatch_error(
                    &request,
                    &draft,
                    ConfluenceDraftContentType::Page,
                    &checked,
                    json!({"type": "pageVersion", "expected": version, "actual": draft.version}),
                    self.backend.egress_proxy_audit(lookup_credential),
                ));
            }
            checked.push(json!({"type": "pageVersion", "version": version}));
        }
        if let Some(title) = &inputs.expect_title {
            if draft.title != *title {
                return Err(draft_verification_mismatch_error(
                    &request,
                    &draft,
                    ConfluenceDraftContentType::Page,
                    &checked,
                    json!({"type": "pageTitle"}),
                    self.backend.egress_proxy_audit(lookup_credential),
                ));
            }
            checked.push(json!({"type": "pageTitle"}));
        }
        if let Some(attachment_id) = &inputs.expect_attachment_id {
            reject_staged_draft_attachment_read(&handle)?;
            match self
                .draft_attachment_for_page(&draft.id, attachment_id, lookup_credential)
                .await
            {
                Ok(_) => checked.push(
                    json!({"type": "attachment", "id": attachment_id, "parentStatus": "draft"}),
                ),
                Err(error)
                    if matches!(
                        error.reason_code().standard(),
                        Some(ReasonCode::ScopeUnresolved | ReasonCode::UpstreamForbidden)
                    ) =>
                {
                    return Err(draft_verification_mismatch_error(
                        &request,
                        &draft,
                        ConfluenceDraftContentType::Page,
                        &checked,
                        json!({"type": "attachment", "id": attachment_id}),
                        self.backend.egress_proxy_audit(lookup_credential),
                    ));
                }
                Err(error) => return Err(error),
            }
        }
        let result = json!({
            "operation": "page.draft.verify",
            "verification": {
                "status": "matched",
                "checked": checked,
            },
            "pageId": draft.id,
            "lifecycle": "draft",
            "status": draft.status,
            "space": draft.space,
            "spaceId": draft.space_id,
        });
        enforce_result_size(&result, self.limits.max_upstream_response_bytes)?;
        Ok(ProviderResult::new(result)
            .with_audit(json!({
                "provider": "confluence",
                "operation": "page.draft.verify",
                "contentType": "page",
                "lifecycle": "draft",
                "pageId": draft.id,
                "space": draft.space,
                "spaceId": draft.space_id,
                "checked": checked,
                "mutated": false,
                "draftHandleValidated": true,
                "credentialMode": request.credential_mode(),
                "egressProxy": self.backend.egress_proxy_audit(lookup_credential),
            }))
            .with_upstream(Some(response.status), Some(response.duration_ms))
            .with_object_ids(json!({
                "pageId": draft.id,
                "attachmentId": inputs.expect_attachment_id,
            })))
    }

    async fn invoke_page_draft_attachment_add(
        &self,
        request: ProviderInvocation,
    ) -> Result<ProviderResult, ProviderError> {
        let credential = invocation_credential(&request)?;
        let lookup_credential = lookup_credential(request.admitted())?;
        let inputs = parse_page_draft_attachment_add_inputs(request.inputs())?;
        let handle = self.decode_draft_handle_for_request(
            ConfluenceDraftContentType::Page,
            &inputs.page_id,
            &inputs.draft_handle,
            request.admitted(),
        )?;
        reject_staged_draft_attachment_add(&handle)?;
        let metadata_response =
            match ProviderState::optional::<ConfluenceDraftContentPreflight>(request.state())? {
                Some(preflight) => ConfluenceBackendResponse {
                    value: preflight.content.clone(),
                    status: preflight.upstream_status,
                    duration_ms: preflight.upstream_duration_ms,
                },
                None => {
                    self.draft_page_response_with_space(
                        &inputs.page_id,
                        Some("storage"),
                        lookup_credential,
                    )
                    .await?
                }
            };
        ensure_draft_content_matches_handle(&metadata_response.value, &handle)?;
        let uploads = prepare_attachment_uploads(
            &inputs.attachments,
            request.body_parts(),
            &self.config.attachments,
        )?;
        let mut successes = Vec::new();
        let mut failures = Vec::new();
        let mut audit_attachments = Vec::new();
        let mut upstream_duration_ms = metadata_response.duration_ms;
        let mut upstream_status = Some(metadata_response.status);
        // Set when Confluence throttled the upload that stopped the batch.
        let mut rate_limited = None;
        // Set when the SDK proved the upload that stopped the batch unsent.
        let mut stopped_unsent = false;
        // Set when the upload that stopped the batch may have applied.
        let mut stopped_uncertain = false;
        // Set when Confluence throttled the verification of an applied upload.
        let mut unverified_attachment_id = None;
        for (index, upload) in uploads.iter().cloned().enumerate() {
            match self
                .backend
                .add_page_draft_attachment(&metadata_response.value.id, upload, credential)
                .await
            {
                Ok(response) => {
                    upstream_duration_ms += response.duration_ms;
                    upstream_status = Some(response.status);
                    let attachment = response.value;
                    if attachment.page_id != metadata_response.value.id {
                        return Err(ProviderError::error(
                            ReasonCode::UpstreamProtocolFailed,
                            "Confluence page draft attachment upload returned mismatched parent",
                        )
                        .with_mutation_receipt(MutationReceipt::unknown()));
                    }
                    if let Err(error) = self
                        .draft_attachment_for_page(
                            &metadata_response.value.id,
                            &attachment.id,
                            lookup_credential,
                        )
                        .await
                    {
                        if error.reason_code() != ReasonCode::UpstreamRateLimited {
                            // The upload applied: repeating the batch would
                            // upload it again.
                            return Err(error.or_mutation_receipt(MutationReceipt::unknown()));
                        }
                        // The upload applied but its verification was
                        // throttled: keep the batch and report it unverified,
                        // never as a rate limit whose retry would upload the
                        // attachments again.
                        audit_attachments.push(json!({
                            "status": "unverified",
                            "attachmentId": attachment.id,
                            "size": attachment.size,
                            "contentType": attachment.content_type,
                            "reason": "upstream_rate_limited",
                        }));
                        failures.push(json!({
                            "status": "unverified",
                            "attachmentId": attachment.id,
                            "filename": attachment.filename,
                            "reason": "upstream_rate_limited",
                        }));
                        for skipped in uploads.iter().skip(index + 1) {
                            audit_attachments.push(json!({
                                "status": "skipped",
                                "size": skipped.size,
                                "contentType": skipped.content_type,
                                "reason": "not_attempted_after_previous_failure",
                            }));
                            failures.push(json!({
                                "status": "skipped",
                                "reason": "not_attempted_after_previous_failure",
                            }));
                        }
                        unverified_attachment_id = Some(attachment.id);
                        break;
                    }
                    successes.push(json!({
                        "attachmentId": attachment.id,
                        "filename": attachment.filename,
                        "contentType": attachment.content_type,
                        "size": attachment.size,
                        "parentStatus": "draft",
                    }));
                    audit_attachments.push(json!({
                        "status": "created",
                        "attachmentId": attachment.id,
                        "size": attachment.size,
                        "contentType": attachment.content_type,
                    }));
                }
                Err(error) => {
                    if let ConfluenceBackendError::RateLimited(retry_after) = &error {
                        rate_limited = Some(*retry_after);
                    }
                    stopped_unsent = matches!(error, ConfluenceBackendError::NotSent { .. });
                    stopped_uncertain = upload_may_have_applied(&error);
                    audit_attachments.push(json!({
                        "status": "failed",
                        "size": uploads[index].size,
                        "contentType": uploads[index].content_type,
                        "reason": sanitized_backend_reason(&error),
                    }));
                    failures.push(json!({
                        "status": "failed",
                        "reason": sanitized_backend_reason(&error),
                    }));
                    for skipped in uploads.iter().skip(index + 1) {
                        audit_attachments.push(json!({
                            "status": "skipped",
                            "size": skipped.size,
                            "contentType": skipped.content_type,
                            "reason": "not_attempted_after_previous_failure",
                        }));
                        failures.push(json!({
                            "status": "skipped",
                            "reason": "not_attempted_after_previous_failure",
                        }));
                    }
                    break;
                }
            }
        }
        let status = if failures.is_empty() {
            "complete"
        } else {
            "partial"
        };
        let mut attachment_ids = successes
            .iter()
            .filter_map(|value| {
                value
                    .get("attachmentId")
                    .and_then(Value::as_str)
                    .map(ToString::to_string)
            })
            .collect::<Vec<_>>();
        // An unverified upload was still created.
        attachment_ids.extend(unverified_attachment_id.clone());
        let result = json!({
            "operation": "page.draft.attachment.add",
            "status": status,
            "pageId": metadata_response.value.id,
            "space": metadata_response.value.space,
            "spaceId": metadata_response.value.space_id,
            "attachments": successes,
            "failures": failures,
        });
        let audit = json!({
            "provider": "confluence",
            "operation": "page.draft.attachment.add",
            "contentType": "page",
            "lifecycle": "draft",
            "pageId": metadata_response.value.id,
            "space": metadata_response.value.space,
            "spaceId": metadata_response.value.space_id,
            "status": status,
            "successCount": successes.len(),
            "failureCount": failures.len(),
            "attachments": audit_attachments,
            "attachmentIds": attachment_ids,
            "mutated": true,
            "draftHandleValidated": true,
            "credentialMode": request.credential_mode(),
            "egressProxy": self.backend.egress_proxy_audit(credential),
        });
        // Uploads that applied would be uploaded again by repeating the batch.
        enforce_result_size(&result, self.limits.max_upstream_response_bytes).map_err(|error| {
            if attachment_ids.is_empty() && !stopped_uncertain {
                error
            } else {
                error.or_mutation_receipt(MutationReceipt::unknown())
            }
        })?;
        let object_ids = json!({
            "pageId": metadata_response.value.id,
            "attachmentIds": attachment_ids,
        });
        if !failures.is_empty() {
            let mut error = ProviderError::error(
                ReasonCode::UpstreamFailed,
                "Confluence page draft attachment upload partially failed",
            )
            .with_result(result);
            if let Some(retry_after) = rate_limited {
                error = if attachment_ids.is_empty() {
                    error.interrupted_by_upstream_rate_limit("confluence", retry_after)
                } else {
                    // Earlier uploads applied: waiting and repeating the batch
                    // would upload them again, so this is not a rate limit.
                    error.partially_applied_before_throttling(
                        "confluence",
                        "attachment_upload",
                        object_ids.clone(),
                    )
                };
            }
            if stopped_unsent && attachment_ids.is_empty() {
                // The first upload never reached Confluence and the rest
                // were skipped, so nothing was applied.
                error = error.with_mutation_receipt(MutationReceipt::not_applied());
            }
            if unverified_attachment_id.is_some() {
                error = error.unverified_after_throttling(
                    "confluence",
                    "post_upload_readback",
                    object_ids.clone(),
                );
            }
            if !attachment_ids.is_empty() || stopped_uncertain {
                // An upload may have applied: repeating the batch could
                // upload it again.
                error = error.or_mutation_receipt(MutationReceipt::unknown());
            }
            return Err(error
                .with_audit(audit)
                .with_upstream(upstream_status, Some(upstream_duration_ms))
                .with_object_ids(object_ids));
        }
        Ok(ProviderResult::new(result)
            .with_audit(audit)
            .with_upstream(upstream_status, Some(upstream_duration_ms))
            .with_object_ids(object_ids))
    }

    async fn invoke_page_draft_attachment_list(
        &self,
        request: ProviderInvocation,
    ) -> Result<ProviderResult, ProviderError> {
        let credential = invocation_credential(&request)?;
        let lookup_credential = lookup_credential(request.admitted())?;
        let inputs = parse_page_draft_attachment_list_inputs(request.inputs())?;
        let handle = self.decode_draft_handle_for_request(
            ConfluenceDraftContentType::Page,
            &inputs.page_id,
            &inputs.draft_handle,
            request.admitted(),
        )?;
        reject_staged_draft_attachment_read(&handle)?;
        let draft = self
            .draft_page_response_with_space(&inputs.page_id, Some("storage"), lookup_credential)
            .await?;
        ensure_draft_content_matches_handle(&draft.value, &handle)?;
        let max_results = capped_max_results(inputs.max_results, &self.config.search)?;
        let next_position = inputs
            .next_page_token
            .as_deref()
            .map(|token| {
                self.continuations.open_draft_attachment_page(
                    request.context(),
                    credential,
                    &handle,
                    max_results,
                    token,
                )
            })
            .transpose()?;
        let response = self
            .backend
            .page_draft_attachments_page(
                &draft.value.id,
                max_results,
                next_position.as_deref(),
                credential,
            )
            .await
            .map_err(confluence_backend_error)?;
        let (attachments, attachment_ids) =
            draft_attachment_values(&response.value.attachments, &draft.value.id)?;
        let next_page_token = response
            .value
            .next_position
            .clone()
            .map(|position| {
                self.continuations.seal_draft_attachment_page(
                    request.context(),
                    credential,
                    &handle,
                    max_results,
                    &position,
                )
            })
            .transpose()?;
        let has_more = next_page_token.is_some();
        let result = json!({
            "operation": "page.draft.attachment.list",
            "page": {
                "id": draft.value.id,
                "space": draft.value.space,
                "spaceId": draft.value.space_id,
                "status": "draft",
            },
            "attachments": attachments,
            "count": attachments.len(),
            "hasMore": has_more,
            "nextPageToken": next_page_token,
        });
        enforce_result_size(&result, self.limits.max_upstream_response_bytes)?;
        Ok(ProviderResult::new(result)
            .with_audit(json!({
                "provider": "confluence",
                "operation": "page.draft.attachment.list",
                "contentType": "page",
                "lifecycle": "draft",
                "pageId": draft.value.id,
                "space": draft.value.space,
                "spaceId": draft.value.space_id,
                "attachmentCount": attachment_ids.len(),
                "hasMore": has_more,
                "mutated": false,
                "draftHandleValidated": true,
                "credentialMode": request.credential_mode(),
                "egressProxy": self.backend.egress_proxy_audit(credential),
            }))
            .with_upstream(
                Some(response.status),
                Some(draft.duration_ms + response.duration_ms),
            )
            .with_object_ids(json!({
                "pageId": draft.value.id,
                "attachmentIds": attachment_ids,
            })))
    }

    async fn invoke_page_draft_attachment_download(
        &self,
        request: ProviderInvocation,
    ) -> Result<ProviderResult, ProviderError> {
        let credential = invocation_credential(&request)?;
        let lookup_credential = lookup_credential(request.admitted())?;
        let inputs = parse_page_draft_attachment_download_inputs(request.inputs())?;
        let handle = self.decode_draft_handle_for_request(
            ConfluenceDraftContentType::Page,
            &inputs.page_id,
            &inputs.draft_handle,
            request.admitted(),
        )?;
        reject_staged_draft_attachment_read(&handle)?;
        let draft = self
            .draft_page_response_with_space(&inputs.page_id, Some("storage"), lookup_credential)
            .await?;
        ensure_draft_content_matches_handle(&draft.value, &handle)?;
        let attachment = self
            .draft_attachment_for_page(&draft.value.id, &inputs.attachment_id, lookup_credential)
            .await?
            .value;
        validate_download_attachment(&attachment, &self.config)?;
        let response = self
            .backend
            .page_draft_attachment_content(&draft.value.id, &inputs.attachment_id, credential)
            .await
            .map_err(confluence_backend_error)?;
        validate_download_content(&response.value, &attachment, &self.config)?;
        let content_type = response.value.content_type.clone();
        let result = json!({
            "operation": "page.draft.attachment.download",
            "pageId": draft.value.id,
            "space": draft.value.space,
            "spaceId": draft.value.space_id,
            "attachmentId": attachment.id,
            "filename": attachment.filename,
            "contentType": content_type,
            "metadataContentType": attachment.content_type,
            "size": attachment.size,
            "parentStatus": "draft",
        });
        let stream = response.value.stream.with_expected_size(
            attachment.size,
            "Confluence page draft attachment response size did not match metadata",
        );
        Ok(ProviderResult::new(result)
            .with_stream(stream)
            .with_audit(json!({
                "provider": "confluence",
                "operation": "page.draft.attachment.download",
                "contentType": "page",
                "lifecycle": "draft",
                "pageId": draft.value.id,
                "space": draft.value.space,
                "spaceId": draft.value.space_id,
                "attachmentIds": [attachment.id],
                "size": attachment.size,
                "metadataContentType": attachment.content_type,
                "mutated": false,
                "draftHandleValidated": true,
                "credentialMode": request.credential_mode(),
                "egressProxy": self.backend.egress_proxy_audit(credential),
            }))
            .with_upstream(
                Some(response.status),
                Some(draft.duration_ms + response.duration_ms),
            )
            .with_object_ids(json!({
                "pageId": draft.value.id,
                "attachmentId": attachment.id,
            })))
    }

    async fn invoke_attachment_add(
        &self,
        request: ProviderInvocation,
    ) -> Result<ProviderResult, ProviderError> {
        let credential = invocation_credential(&request)?;
        let lookup_credential = lookup_credential(request.admitted())?;
        let inputs = parse_attachment_add_inputs(request.inputs())?;
        let metadata_response =
            match ProviderState::optional::<ConfluencePagePreflight>(request.state())? {
                Some(preflight) => ConfluenceBackendResponse {
                    value: preflight.page.clone(),
                    status: preflight.upstream_status,
                    duration_ms: preflight.upstream_duration_ms,
                },
                None => {
                    self.confirmed_page_response(&inputs.page_id, None, lookup_credential)
                        .await?
                }
            };
        let page = metadata_response.value;
        let uploads = prepare_attachment_uploads(
            &inputs.attachments,
            request.body_parts(),
            &self.config.attachments,
        )?;
        let mut successes = Vec::new();
        let mut failures = Vec::new();
        let mut attachment_audit = Vec::new();
        let mut upstream_duration_ms = metadata_response.duration_ms;
        let mut upstream_status = Some(metadata_response.status);
        // Set when Confluence throttled the upload that stopped the batch.
        let mut rate_limited = None;
        // Set when the SDK proved the upload that stopped the batch unsent.
        let mut stopped_unsent = false;
        // Set when the upload that stopped the batch may have applied.
        let mut stopped_uncertain = false;
        for (index, upload) in uploads.iter().cloned().enumerate() {
            let upload_audit = attachment_upload_audit(&upload);
            match self
                .backend
                .add_attachment(&page.id, upload, credential)
                .await
            {
                Ok(response) => {
                    upstream_duration_ms += response.duration_ms;
                    upstream_status = Some(response.status);
                    successes.push(json!({
                        "attachmentId": response.value.id,
                        "filename": response.value.filename,
                        "contentType": response.value.content_type,
                        "size": response.value.size,
                    }));
                    attachment_audit.push(json!({
                        "status": "created",
                        "attachmentId": response.value.id,
                        "attachment": upload_audit,
                    }));
                }
                Err(error) => {
                    if let ConfluenceBackendError::RateLimited(retry_after) = &error {
                        rate_limited = Some(*retry_after);
                    }
                    stopped_unsent = matches!(error, ConfluenceBackendError::NotSent { .. });
                    stopped_uncertain = upload_may_have_applied(&error);
                    attachment_audit.push(json!({
                        "status": "failed",
                        "attachment": upload_audit.clone(),
                        "reason": sanitized_backend_reason(&error),
                    }));
                    failures.push(json!({
                        "status": "failed",
                        "attachment": upload_audit,
                        "reason": sanitized_backend_reason(&error),
                    }));
                    for skipped in uploads.iter().skip(index + 1) {
                        let skipped_audit = attachment_upload_audit(skipped);
                        attachment_audit.push(json!({
                            "status": "skipped",
                            "attachment": skipped_audit.clone(),
                            "reason": "not_attempted_after_previous_failure",
                        }));
                        failures.push(json!({
                            "status": "skipped",
                            "attachment": skipped_audit,
                            "reason": "not_attempted_after_previous_failure",
                        }));
                    }
                    break;
                }
            }
        }
        if successes.is_empty() && !failures.is_empty() {
            let mut error = ProviderError::error(
                ReasonCode::UpstreamFailed,
                "Confluence attachment upload failed",
            );
            if let Some(retry_after) = rate_limited {
                error = error.interrupted_by_upstream_rate_limit("confluence", retry_after);
            }
            if stopped_unsent {
                // The first upload never reached Confluence and the rest
                // were skipped, so nothing was applied.
                error = error.with_mutation_receipt(MutationReceipt::not_applied());
            } else if stopped_uncertain {
                error = error.with_mutation_receipt(MutationReceipt::unknown());
            }
            return Err(error.with_audit(json!({
                "provider": "confluence",
                "operation": "attachment.add",
                "pageId": page.id,
                "space": page.space,
                "status": "failed",
                "successCount": 0,
                "failureCount": failures.len(),
                "attachments": attachment_audit,
                "credentialMode": request.credential_mode(),
                "egressProxy": self.backend.egress_proxy_audit(credential),
            })));
        }
        let status = if failures.is_empty() {
            "complete"
        } else {
            "partial"
        };
        let result = json!({
            "status": status,
            "pageId": page.id,
            "space": page.space,
            "attachments": successes,
            "failures": failures,
        });
        // Uploads were applied: repeating the batch would upload them again.
        enforce_result_size(&result, self.limits.max_upstream_response_bytes)
            .map_err(|error| error.or_mutation_receipt(MutationReceipt::unknown()))?;
        let audit = json!({
            "provider": "confluence",
            "operation": "attachment.add",
            "pageId": page.id,
            "space": page.space,
            "status": status,
            "successCount": successes.len(),
            "failureCount": failures.len(),
            "attachments": attachment_audit,
            "credentialMode": request.credential_mode(),
            "egressProxy": self.backend.egress_proxy_audit(credential),
        });
        let object_ids = json!({
            "pageId": page.id,
            "attachmentIds": successes.iter().filter_map(|value| {
                value.get("attachmentId").and_then(Value::as_str).map(ToString::to_string)
            }).collect::<Vec<_>>(),
        });
        if !failures.is_empty() {
            let mut error = ProviderError::error(
                ReasonCode::UpstreamFailed,
                "Confluence attachment upload partially failed",
            )
            .with_result(result);
            if rate_limited.is_some() {
                // Earlier uploads applied: waiting and repeating the batch
                // would upload them again, so this is not a rate limit.
                error = error.partially_applied_before_throttling(
                    "confluence",
                    "attachment_upload",
                    object_ids.clone(),
                );
            }
            // Earlier uploads applied: repeating the batch would upload them
            // again.
            error = error.or_mutation_receipt(MutationReceipt::unknown());
            return Err(error
                .with_audit(audit)
                .with_upstream(upstream_status, Some(upstream_duration_ms))
                .with_object_ids(object_ids));
        }
        Ok(ProviderResult::new(result)
            .with_audit(audit)
            .with_upstream(upstream_status, Some(upstream_duration_ms))
            .with_object_ids(object_ids))
    }

    async fn invoke_attachment_download(
        &self,
        request: ProviderInvocation,
    ) -> Result<ProviderResult, ProviderError> {
        let credential = invocation_credential(&request)?;
        let lookup_credential = lookup_credential(request.admitted())?;
        let inputs = parse_attachment_download_inputs(request.inputs())?;
        let page = self
            .confirmed_page(&inputs.page_id, None, lookup_credential)
            .await?;
        let attachment = self
            .attachment_for_page(&page.id, &inputs.attachment_id, lookup_credential)
            .await?;
        validate_download_attachment(&attachment, &self.config)?;
        let response = self
            .backend
            .attachment_content(&page.id, &inputs.attachment_id, credential)
            .await
            .map_err(confluence_backend_error)?;
        validate_download_content(&response.value, &attachment, &self.config)?;
        if response
            .value
            .size
            .is_some_and(|size| size > self.limits.max_download_bytes)
        {
            return Err(ProviderError::deny(
                ReasonCode::AttachmentSizeDenied,
                "Confluence attachment download exceeded the configured byte cap",
            ));
        }
        let downloaded_size = attachment.size;
        if downloaded_size > self.config.attachments.max_download_bytes
            || downloaded_size > self.limits.max_download_bytes
        {
            return Err(ProviderError::deny(
                ReasonCode::AttachmentSizeDenied,
                "Confluence attachment download exceeded the configured byte cap",
            ));
        }
        let content_type = response.value.content_type.clone();
        let mut result = json!({
            "pageId": page.id,
            "space": page.space,
            "attachmentId": attachment.id,
            "filename": attachment.filename,
            "contentType": content_type,
            "metadataContentType": attachment.content_type,
            "size": downloaded_size,
        });
        if let Some(sha256) = response.value.sha256.clone() {
            result["sha256"] = json!(sha256);
        }
        let stream = response.value.stream.with_expected_size(
            downloaded_size,
            "Confluence attachment response size did not match metadata",
        );
        let mut audit = json!({
            "provider": "confluence",
            "operation": "attachment.download",
            "pageId": page.id,
            "space": page.space,
            "attachmentId": attachment.id,
            "filename": attachment.filename,
            "contentType": content_type,
            "metadataContentType": attachment.content_type,
            "size": downloaded_size,
            "credentialMode": request.credential_mode(),
            "egressProxy": self.backend.egress_proxy_audit(credential),
        });
        if let Some(sha256) = result.get("sha256").cloned() {
            audit["sha256"] = sha256;
        }
        Ok(ProviderResult::new(result)
            .with_stream(stream)
            .with_audit(audit)
            .with_upstream(Some(response.status), Some(response.duration_ms))
            .with_object_ids(json!({
                "pageId": page.id,
                "attachmentId": attachment.id,
            })))
    }

    async fn invoke_attachment_list(
        &self,
        request: ProviderInvocation,
    ) -> Result<ProviderResult, ProviderError> {
        let credential = invocation_credential(&request)?;
        let lookup_credential = lookup_credential(request.admitted())?;
        let inputs = parse_attachment_list_inputs(request.inputs(), &self.config)?;
        let page = self
            .confirmed_page(
                &inputs.locator.page_id,
                inputs.locator.candidate_space.as_deref(),
                lookup_credential,
            )
            .await?;
        let max_results = capped_max_results(inputs.max_results, &self.config.search)?;
        let next_position = inputs
            .next_page_token
            .as_deref()
            .map(|token| {
                self.continuations.open_attachment_page(
                    request.context(),
                    credential,
                    &page,
                    max_results,
                    token,
                )
            })
            .transpose()?;
        let response = self
            .backend
            .page_attachments_page(&page.id, max_results, next_position.as_deref(), credential)
            .await
            .map_err(confluence_backend_error)?;
        if response.value.attachments.len() > max_results as usize {
            return Err(ProviderError::error(
                ReasonCode::UpstreamProtocolFailed,
                "Confluence attachment list returned more attachments than requested",
            ));
        }
        let attachment_values = response
            .value
            .attachments
            .iter()
            .map(|attachment| {
                if attachment.page_id != page.id {
                    return Err(ProviderError::error(
                        ReasonCode::UpstreamProtocolFailed,
                        "Confluence attachment list returned metadata for a different page",
                    ));
                }
                Ok(json!({
                    "attachmentId": attachment.id,
                    "filename": attachment.filename,
                    "size": attachment.size,
                    "contentType": attachment.content_type,
                }))
            })
            .collect::<Result<Vec<_>, ProviderError>>()?;
        let attachment_ids = response
            .value
            .attachments
            .iter()
            .map(|attachment| attachment.id.clone())
            .collect::<Vec<_>>();
        let next_page_token = response
            .value
            .next_position
            .clone()
            .map(|position| {
                self.continuations.seal_attachment_page(
                    request.context(),
                    credential,
                    &page,
                    max_results,
                    &position,
                )
            })
            .transpose()?;
        let has_more = next_page_token.is_some();
        let count = attachment_values.len();
        let result = json!({
            "operation": "attachment.list",
            "page": {
                "id": page.id,
                "space": page.space,
            },
            "attachments": attachment_values,
            "count": count,
            "hasMore": has_more,
            "nextPageToken": next_page_token,
        });
        enforce_result_size(&result, self.limits.max_upstream_response_bytes)?;
        Ok(ProviderResult::new(result)
            .with_audit(json!({
                "provider": "confluence",
                "operation": "attachment.list",
                "pageId": page.id,
                "space": page.space,
                "attachmentCount": count,
                "hasMore": has_more,
                "credentialMode": request.credential_mode(),
                "egressProxy": self.backend.egress_proxy_audit(credential),
            }))
            .with_upstream(Some(response.status), Some(response.duration_ms))
            .with_object_ids(json!({
                "pageId": page.id,
                "attachmentIds": attachment_ids,
            })))
    }

    async fn invoke_verify(
        &self,
        request: ProviderInvocation,
    ) -> Result<ProviderResult, ProviderError> {
        let credential = invocation_credential(&request)?;
        let inputs = parse_verify_inputs(request.inputs())?;
        let page_response = match self
            .backend
            .page_metadata(&inputs.page_id, credential)
            .await
        {
            Ok(response) => response,
            Err(ConfluenceBackendError::NotFound | ConfluenceBackendError::Forbidden) => {
                return Err(page_scope_requires_lookup(inputs.page_id));
            }
            Err(error) => return Err(confluence_backend_error(error)),
        };
        let page = page_response.value;
        if page.id != inputs.page_id {
            return Err(page_scope_requires_lookup(inputs.page_id));
        }
        require_current_page(&page)?;
        let mut upstream_duration_ms = page_response.duration_ms;
        let mut upstream_status = Some(page_response.status);
        let mut checked = Vec::new();
        if let Some(version) = inputs.expect_version {
            if page.version != version {
                return Err(confluence_verification_mismatch_error(
                    &request,
                    &page,
                    &checked,
                    json!({"type": "pageVersion", "expected": version, "actual": page.version}),
                    &inputs,
                    self.backend.egress_proxy_audit(credential),
                ));
            }
            checked.push(json!({"type": "pageVersion", "version": version}));
        }
        if let Some(title) = &inputs.expect_title {
            if page.title != *title {
                return Err(confluence_verification_mismatch_error(
                    &request,
                    &page,
                    &checked,
                    json!({"type": "pageTitle"}),
                    &inputs,
                    self.backend.egress_proxy_audit(credential),
                ));
            }
            checked.push(json!({"type": "pageTitle"}));
        }
        if let Some(attachment_id) = &inputs.expect_attachment_id {
            match self
                .attachment_for_page_response(&page.id, attachment_id, credential)
                .await
            {
                Ok(response) => {
                    upstream_duration_ms += response.duration_ms;
                    upstream_status = Some(response.status);
                    checked.push(json!({"type": "attachment", "id": attachment_id}));
                }
                Err(error) if error.reason_code() == ReasonCode::ScopeUnresolved => {
                    return Err(confluence_verification_mismatch_error(
                        &request,
                        &page,
                        &checked,
                        json!({"type": "attachment", "id": attachment_id}),
                        &inputs,
                        self.backend.egress_proxy_audit(credential),
                    ));
                }
                Err(error) if error.reason_code() == ReasonCode::UpstreamForbidden => {
                    return Err(confluence_verification_mismatch_error(
                        &request,
                        &page,
                        &checked,
                        json!({"type": "attachment", "id": attachment_id}),
                        &inputs,
                        self.backend.egress_proxy_audit(credential),
                    ));
                }
                Err(error) => return Err(error),
            }
        }
        let result = json!({
            "verification": {
                "status": "matched",
                "checked": checked,
            },
            "pageId": page.id,
            "space": page.space,
        });
        enforce_result_size(&result, self.limits.max_upstream_response_bytes)?;
        Ok(ProviderResult::new(result)
            .with_audit(json!({
                "provider": "confluence",
                "operation": "verify",
                "pageId": page.id,
                "space": page.space,
                "checked": checked,
                "credentialMode": request.credential_mode(),
                "egressProxy": self.backend.egress_proxy_audit(credential),
            }))
            .with_upstream(upstream_status, Some(upstream_duration_ms))
            .with_object_ids(json!({
                "pageId": page.id,
                "attachmentId": inputs.expect_attachment_id,
            })))
    }

    async fn invoke_blog_view(
        &self,
        request: ProviderInvocation,
    ) -> Result<ProviderResult, ProviderError> {
        let credential = invocation_credential(&request)?;
        let authorized_space = authorized_single_scope(request.resource_scopes()?, "space")?;
        let inputs = parse_blog_view_inputs(request.inputs(), &self.config)?;
        let response = self
            .blog_response_with_space(&inputs.locator.blog_id, credential)
            .await?;
        let blog = response.value;
        if blog.id != inputs.locator.blog_id || blog.space != authorized_space {
            return Err(ProviderError::deny(
                ReasonCode::ScopeUnresolved,
                "Confluence blog response no longer matches the authorized scope",
            ));
        }
        validate_blog_locator_space(&inputs.locator, &blog.space)?;
        if blog.status.as_deref() != Some("current") {
            return Err(ProviderError::deny(
                ReasonCode::ScopeUnresolved,
                "Confluence blog status is not current",
            ));
        }
        enforce_blog_body_sizes(
            &blog,
            &self.config.content.blog_formats,
            self.config.content.max_body_bytes,
        )?;
        let result = blog_view_result(&blog, &self.config)?;
        enforce_result_size(&result, self.limits.max_upstream_response_bytes)?;
        Ok(ProviderResult::new(result)
            .with_audit(json!({
                "provider": "confluence",
                "operation": "blog.view",
                "blogId": blog.id,
                "space": blog.space,
                "spaceId": blog.space_id,
                "returnedUrlFields": ["webUrl", "spaceUrl"],
                "credentialMode": request.credential_mode(),
                "egressProxy": self.backend.egress_proxy_audit(credential),
            }))
            .with_upstream(Some(response.status), Some(response.duration_ms))
            .with_object_ids(json!({
                "blogId": blog.id,
            })))
    }

    async fn invoke_blog_search(
        &self,
        request: ProviderInvocation,
    ) -> Result<ProviderResult, ProviderError> {
        let credential = invocation_credential(&request)?;
        let inputs = parse_search_inputs(request.inputs())?;
        let requested = requested_spaces(&inputs)?;
        let authorization = search_authorization(&request)?;
        let effective_scope = effective_search_scope(&authorization, &requested)?;
        let query = build_confluence_blog_search_query(
            &inputs.query,
            &effective_scope,
            &self.config.search,
        )?;
        let response_scope = query.response_scope.clone();
        let max_results = capped_max_results(inputs.max_results, &self.config.search)?;
        let pages = SearchPageRequest {
            context: request.context(),
            credential,
            query: &query,
            requested_spaces: &requested,
            max_results,
        };
        let upstream_page_token = inputs
            .next_page_token
            .as_deref()
            .map(|token| self.continuations.open_search_page(&pages, token))
            .transpose()?;
        let response = self
            .backend
            .search_blogs(
                ConfluenceSearchRequest {
                    cql: query.cql.clone(),
                    spaces: response_scope.values_for_backend(),
                    max_results,
                    next_page_token: upstream_page_token,
                },
                credential,
            )
            .await
            .map_err(confluence_backend_error)?;
        if response.value.blogs.len() > max_results as usize {
            return Err(ProviderError::error(
                ReasonCode::UpstreamProtocolFailed,
                "Confluence blog search returned more blog posts than requested",
            ));
        }
        for blog in &response.value.blogs {
            if !is_blog_id(&blog.id)
                || !is_space_key(&blog.space)
                || blog.status.as_deref() != Some("current")
                || !response_scope.authorizes_value(&blog.space)
            {
                return Err(ProviderError::deny(
                    ReasonCode::ScopeUnresolved,
                    "Confluence search returned a blog outside the authorized space scope",
                ));
            }
        }
        let observed_spaces = response
            .value
            .blogs
            .iter()
            .map(|blog| blog.space.clone())
            .collect::<BTreeSet<_>>();
        let next_page_token = response
            .value
            .next_page_token
            .as_deref()
            .map(|upstream| self.continuations.seal_search_page(&pages, upstream))
            .transpose()?;
        let result = blog_search_result(&response.value, next_page_token.as_deref(), &self.config)?;
        enforce_result_size(&result, self.limits.max_upstream_response_bytes)?;
        Ok(ProviderResult::new(result).with_audit(json!({
                "provider": "confluence",
                "operation": "blog.search",
                "requestedSpaces": requested,
                "effectiveSearchScope": response_scope.audit_value("space"),
                "queryType": query.kind,
                "queryAstVersion": CONFLUENCE_QUERY_AST_VERSION,
                "canonicalCallerCqlHash": query.canonical_caller_cql_hash,
                "queryShape": query.query_shape,
                "textOperandHashes": query.text_operand_hashes,
                "injectedSpacePredicate": query.injected_space_predicate,
                "injectedTypePredicate": query.injected_type_predicate,
                "observedSpaces": observed_spaces,
                "returnedUrlFields": ["webUrl", "spaceUrl"],
                "sortFields": query.sort_fields,
                "maxResults": max_results,
                "resultCount": response.value.blogs.len(),
                "credentialMode": request.credential_mode(),
                "egressProxy": self.backend.egress_proxy_audit(credential),
            })).with_upstream(Some(response.status), Some(response.duration_ms)).with_object_ids(json!({
                "blogIds": response.value.blogs.iter().map(|blog| blog.id.clone()).collect::<Vec<_>>(),
            })))
    }

    async fn invoke_blog_create(
        &self,
        request: ProviderInvocation,
    ) -> Result<ProviderResult, ProviderError> {
        let credential = invocation_credential(&request)?;
        let lookup_credential = lookup_credential(request.admitted())?;
        let authorized_space = authorized_single_scope(request.resource_scopes()?, "space")?;
        let inputs = parse_blog_create_inputs(request.inputs())?;
        if inputs.space != authorized_space {
            return Err(ProviderError::deny(
                ReasonCode::ScopeUnresolved,
                "Confluence blog create scope did not match the authorized space",
            ));
        }
        let (body, content_audit, attribution) = self.prepare_write_content(
            "blog.create",
            ConfluenceWriteTarget::Blog,
            &inputs.content_format,
            &inputs.content,
            &request,
        )?;
        let space_response = self
            .backend
            .space_by_key(&inputs.space, lookup_credential)
            .await
            .map_err(confluence_backend_error)?;
        let space = space_response.value;
        if space.key != inputs.space {
            return Err(ProviderError::deny(
                ReasonCode::ScopeUnresolved,
                "Confluence space lookup did not match the authorized space",
            ));
        }
        let write = ConfluenceWrite::new(json!({ "space": inputs.space }));
        let response = self
            .backend
            .create_blog(
                ConfluenceBlogCreateRequest {
                    space: inputs.space.clone(),
                    space_id: space.id.clone(),
                    title: inputs.title,
                    body,
                },
                credential,
            )
            .await
            .map_err(|error| write.failed(error))?;
        after_accepted_write("mutation_response", write.locators(), async {
            let mut blog = response.value;
            blog.space = space.key;
            blog.space_web_url = space.web_url;
            if blog.space_id != space.id || blog.status.as_deref() != Some("current") {
                return Err(ProviderError::deny(
                    ReasonCode::ScopeUnresolved,
                    "Confluence created blog did not match the authorized space",
                ));
            }
            let (web_url, space_url) = blog_browser_urls(&blog, &self.config)?;
            let result = json!({
                "operation": "blog.create",
                "blogId": blog.id,
                "space": blog.space,
                "spaceId": blog.space_id,
                "spaceUrl": space_url,
                "webUrl": web_url,
                "title": blog.title,
                "status": blog.status,
                "version": blog.version,
                "createdAt": blog.created_at,
                "updatedAt": blog.updated_at,
                "createdBy": blog.created_by,
                "updatedBy": blog.updated_by,
            });
            enforce_result_size(&result, self.limits.max_upstream_response_bytes)?;
            let mut audit = json!({
                "provider": "confluence",
                "operation": "blog.create",
                "blogId": blog.id,
                "space": blog.space,
                "spaceId": blog.space_id,
                "version": blog.version,
                "returnedUrlFields": ["webUrl", "spaceUrl"],
                "bodyFormat": content_audit.native_format.as_str(),
                "credentialMode": request.credential_mode(),
                "egressProxy": self.backend.egress_proxy_audit(credential),
            });
            merge_confluence_content_write_audit(&mut audit, &content_audit);
            merge_attribution_audit(&mut audit, attribution);
            Ok(ProviderResult::new(result)
                .with_audit(audit)
                .with_upstream(
                    Some(response.status),
                    Some(space_response.duration_ms + response.duration_ms),
                )
                .with_object_ids(json!({
                    "blogId": blog.id,
                })))
        })
        .await
    }

    async fn invoke_blog_update(
        &self,
        request: ProviderInvocation,
    ) -> Result<ProviderResult, ProviderError> {
        let credential = invocation_credential(&request)?;
        let inputs = parse_blog_update_inputs(request.inputs())?;
        let (body, content_audit, attribution) = self.prepare_write_content(
            "blog.update",
            ConfluenceWriteTarget::Blog,
            &inputs.content_format,
            &inputs.content,
            &request,
        )?;
        let metadata_response = self
            .confirmed_blog_response(&inputs.blog_id, credential)
            .await?;
        let metadata = metadata_response.value;
        if metadata.version != inputs.base_version {
            return Err(blog_version_conflict_error(
                &request,
                &metadata,
                inputs.base_version,
                metadata_response.status,
                metadata_response.duration_ms,
                self.backend.egress_proxy_audit(credential),
            ));
        }
        let title = inputs.title.unwrap_or_else(|| metadata.title.clone());
        let write = ConfluenceWrite::new(json!({ "blogId": inputs.blog_id }));
        let response = match self
            .backend
            .update_blog(
                ConfluenceBlogUpdateRequest {
                    blog_id: metadata.id.clone(),
                    title,
                    base_version: inputs.base_version,
                    version_message: inputs.version_message,
                    body,
                },
                credential,
            )
            .await
        {
            Ok(response) => response,
            Err(ConfluenceBackendError::Conflict) => {
                return Err(upstream_blog_version_conflict_error(
                    &request,
                    &metadata,
                    inputs.base_version,
                    self.backend.egress_proxy_audit(credential),
                ));
            }
            Err(error) => return Err(write.failed(error)),
        };
        after_accepted_write("mutation_response", write.locators(), async {
            let mut blog = response.value;
            blog.space = metadata.space.clone();
            blog.space_web_url = metadata.space_web_url.clone();
            if blog.id != metadata.id || blog.space_id != metadata.space_id {
                return Err(ProviderError::deny(
                    ReasonCode::ScopeUnresolved,
                    "Confluence updated blog did not match the authorized scope",
                ));
            }
            if blog.status.as_deref() != Some("current") {
                return Err(ProviderError::deny(
                    ReasonCode::ScopeUnresolved,
                    "Confluence updated blog status is not current",
                ));
            }
            if blog.version != inputs.base_version + 1 {
                return Err(ProviderError::error(
                    ReasonCode::UpstreamProtocolFailed,
                    "Confluence updated blog version did not match the requested base version",
                ));
            }
            let (web_url, space_url) = blog_browser_urls(&blog, &self.config)?;
            let result = json!({
                "operation": "blog.update",
                "blogId": blog.id,
                "space": blog.space,
                "spaceId": blog.space_id,
                "spaceUrl": space_url,
                "webUrl": web_url,
                "title": blog.title,
                "status": blog.status,
                "previousVersion": inputs.base_version,
                "version": blog.version,
                "createdAt": blog.created_at,
                "updatedAt": blog.updated_at,
                "createdBy": blog.created_by,
                "updatedBy": blog.updated_by,
            });
            enforce_result_size(&result, self.limits.max_upstream_response_bytes)?;
            let mut audit = json!({
                "provider": "confluence",
                "operation": "blog.update",
                "blogId": blog.id,
                "space": blog.space,
                "spaceId": blog.space_id,
                "previousVersion": inputs.base_version,
                "version": blog.version,
                "returnedUrlFields": ["webUrl", "spaceUrl"],
                "bodyFormat": content_audit.native_format.as_str(),
                "credentialMode": request.credential_mode(),
                "egressProxy": self.backend.egress_proxy_audit(credential),
            });
            merge_confluence_content_write_audit(&mut audit, &content_audit);
            merge_attribution_audit(&mut audit, attribution);
            Ok(ProviderResult::new(result)
                .with_audit(audit)
                .with_upstream(
                    Some(response.status),
                    Some(metadata_response.duration_ms + response.duration_ms),
                )
                .with_object_ids(json!({
                    "blogId": blog.id,
                })))
        })
        .await
    }

    async fn invoke_blog_draft_create(
        &self,
        request: ProviderInvocation,
    ) -> Result<ProviderResult, ProviderError> {
        let credential = invocation_credential(&request)?;
        let lookup_credential = lookup_credential(request.admitted())?;
        let authorized_space = authorized_single_scope(request.resource_scopes()?, "space")?;
        let inputs = parse_blog_draft_create_inputs(request.inputs())?;
        if inputs.space != authorized_space {
            return Err(ProviderError::deny(
                ReasonCode::ScopeUnresolved,
                "Confluence blog draft create scope did not match the authorized space",
            ));
        }
        let (body, content_audit, attribution) = self.prepare_write_content(
            "blog.draft.create",
            ConfluenceWriteTarget::Blog,
            &inputs.content_format,
            &inputs.content,
            &request,
        )?;
        let space_response = self
            .backend
            .space_by_key(&inputs.space, lookup_credential)
            .await
            .map_err(confluence_backend_error)?;
        let write = ConfluenceWrite::new(json!({ "space": inputs.space }));
        let response = self
            .backend
            .create_blog_draft(
                ConfluenceDraftCreateRequest {
                    content_type: "blog".to_string(),
                    space: inputs.space,
                    space_id: space_response.value.id.clone(),
                    parent_page_id: None,
                    title: inputs.title,
                    body,
                },
                credential,
            )
            .await
            .map_err(|error| write.failed(error))?;
        after_accepted_write("mutation_response", write.locators(), async {
            let mut draft = response.value;
            draft.space = space_response.value.key;
            draft.space_web_url = space_response.value.web_url;
            require_draft_content(&draft, ConfluenceDraftContentType::Blog)?;
            if draft.space != authorized_space || draft.space_id != space_response.value.id {
                return Err(ProviderError::deny(
                    ReasonCode::ScopeUnresolved,
                    "Confluence created blog draft did not match the authorized space",
                ));
            }
            let draft_handle = self.mint_draft_handle(
                ConfluenceDraftContentType::Blog,
                &draft,
                ConfluenceDraftOrigin::New,
                None,
                &request,
            )?;
            let result = draft_content_result(
                "blog.draft.create",
                &draft,
                ConfluenceDraftContentType::Blog,
                Some(draft_handle),
                None,
                &self.config,
            )?;
            enforce_result_size(&result, self.limits.max_upstream_response_bytes)?;
            let mut audit = draft_audit(
                &request,
                "blog.draft.create",
                &draft,
                ConfluenceDraftContentType::Blog,
                Some("storage"),
                true,
                self.backend.egress_proxy_audit(credential),
            );
            merge_confluence_content_write_audit(&mut audit, &content_audit);
            merge_attribution_audit(&mut audit, attribution);
            Ok(ProviderResult::new(result)
                .with_audit(audit)
                .with_upstream(
                    Some(response.status),
                    Some(space_response.duration_ms + response.duration_ms),
                )
                .with_object_ids(json!({ "blogId": draft.id })))
        })
        .await
    }

    async fn invoke_blog_draft_stage(
        &self,
        request: ProviderInvocation,
    ) -> Result<ProviderResult, ProviderError> {
        let credential = invocation_credential(&request)?;
        let lookup_credential = lookup_credential(request.admitted())?;
        let inputs = parse_blog_draft_stage_inputs(request.inputs())?;
        let (body, content_audit, attribution) = self.prepare_write_content(
            "blog.draft.stage",
            ConfluenceWriteTarget::Blog,
            &inputs.content_format,
            &inputs.content,
            &request,
        )?;
        let current_response = self
            .confirmed_blog_response(&inputs.blog_id, lookup_credential)
            .await?;
        let current = current_response.value;
        ensure_authorized_space(request.resource_scopes()?, &current.space)?;
        if current.version != inputs.base_version {
            return Err(blog_version_conflict_error(
                &request,
                &current,
                inputs.base_version,
                current_response.status,
                current_response.duration_ms,
                self.backend.egress_proxy_audit(lookup_credential),
            ));
        }
        match self
            .draft_blog_response_with_space(&inputs.blog_id, Some("storage"), lookup_credential)
            .await
        {
            Ok(response) if response.value.status.as_deref() == Some("draft") => {
                return Err(draft_version_conflict_error(
                    &request,
                    &response.value,
                    ConfluenceDraftContentType::Blog,
                    inputs.base_version,
                    self.backend.egress_proxy_audit(lookup_credential),
                ));
            }
            Ok(_) => {}
            Err(error) if error.reason_code() == ReasonCode::ScopeUnresolved => {}
            Err(error) => return Err(error),
        }
        let write = ConfluenceWrite::new(json!({ "blogId": inputs.blog_id }));
        let response = self
            .backend
            .update_blog_draft(
                ConfluenceDraftUpdateRequest {
                    content_type: "blog".to_string(),
                    content_id: current.id.clone(),
                    space_id: current.space_id.clone(),
                    title: inputs.title.unwrap_or_else(|| current.title.clone()),
                    status: "draft".to_string(),
                    version_number: 1,
                    body,
                },
                credential,
            )
            .await
            .map_err(|error| write.failed_with(error, map_confluence_conflict))?;
        after_accepted_write("mutation_response", write.locators(), async {
            let mut draft = response.value;
            draft.space = current.space;
            draft.space_web_url = current.space_web_url;
            require_draft_content(&draft, ConfluenceDraftContentType::Blog)?;
            require_draft_version_one(&draft)?;
            let draft_handle = self.mint_draft_handle(
                ConfluenceDraftContentType::Blog,
                &draft,
                ConfluenceDraftOrigin::Staged,
                Some(inputs.base_version),
                &request,
            )?;
            let mut result = draft_content_result(
                "blog.draft.stage",
                &draft,
                ConfluenceDraftContentType::Blog,
                Some(draft_handle),
                None,
                &self.config,
            )?;
            result["expectedBaseVersion"] = json!(inputs.base_version);
            enforce_result_size(&result, self.limits.max_upstream_response_bytes)?;
            let mut audit = draft_audit(
                &request,
                "blog.draft.stage",
                &draft,
                ConfluenceDraftContentType::Blog,
                Some("storage"),
                true,
                self.backend.egress_proxy_audit(credential),
            );
            audit["expectedBaseVersion"] = json!(inputs.base_version);
            merge_confluence_content_write_audit(&mut audit, &content_audit);
            merge_attribution_audit(&mut audit, attribution);
            Ok(ProviderResult::new(result)
                .with_audit(audit)
                .with_upstream(
                    Some(response.status),
                    Some(current_response.duration_ms + response.duration_ms),
                )
                .with_object_ids(json!({ "blogId": draft.id })))
        })
        .await
    }

    async fn invoke_blog_draft_view(
        &self,
        request: ProviderInvocation,
    ) -> Result<ProviderResult, ProviderError> {
        let credential = invocation_credential(&request)?;
        let lookup_credential = lookup_credential(request.admitted())?;
        let inputs = parse_blog_draft_body_format_inputs(request.action(), request.inputs())?;
        let handle = self.decode_draft_handle_for_request(
            ConfluenceDraftContentType::Blog,
            &inputs.blog_id,
            &inputs.draft_handle,
            request.admitted(),
        )?;
        let response = self
            .draft_blog_response_with_space(
                &inputs.blog_id,
                Some(&inputs.body_format),
                lookup_credential,
            )
            .await?;
        ensure_draft_content_matches_handle(&response.value, &handle)?;
        enforce_draft_body_size(&response.value, &inputs.body_format, &self.config)?;
        let result = draft_content_result(
            "blog.draft.view",
            &response.value,
            ConfluenceDraftContentType::Blog,
            Some(inputs.draft_handle),
            Some(inputs.body_format.as_str()),
            &self.config,
        )?;
        enforce_result_size(&result, self.limits.max_upstream_response_bytes)?;
        Ok(ProviderResult::new(result)
            .with_audit(draft_audit(
                &request,
                "blog.draft.view",
                &response.value,
                ConfluenceDraftContentType::Blog,
                Some(inputs.body_format.as_str()),
                false,
                self.backend.egress_proxy_audit(credential),
            ))
            .with_upstream(Some(response.status), Some(response.duration_ms))
            .with_object_ids(json!({ "blogId": response.value.id })))
    }

    async fn invoke_blog_draft_update(
        &self,
        request: ProviderInvocation,
    ) -> Result<ProviderResult, ProviderError> {
        let credential = invocation_credential(&request)?;
        let lookup_credential = lookup_credential(request.admitted())?;
        let inputs = parse_blog_draft_update_inputs(request.inputs())?;
        let (body, content_audit, attribution) = self.prepare_write_content(
            "blog.draft.update",
            ConfluenceWriteTarget::Blog,
            &inputs.content_format,
            &inputs.content,
            &request,
        )?;
        let handle = self.decode_draft_handle_for_request(
            ConfluenceDraftContentType::Blog,
            &inputs.blog_id,
            &inputs.draft_handle,
            request.admitted(),
        )?;
        let current = self
            .draft_blog_response_with_space(&inputs.blog_id, Some("storage"), lookup_credential)
            .await?;
        ensure_draft_content_matches_handle(&current.value, &handle)?;
        require_draft_version_one(&current.value)?;
        let write = ConfluenceWrite::new(json!({ "blogId": inputs.blog_id }));
        let response = self
            .backend
            .update_blog_draft(
                ConfluenceDraftUpdateRequest {
                    content_type: "blog".to_string(),
                    content_id: current.value.id.clone(),
                    space_id: current.value.space_id.clone(),
                    title: inputs.title.unwrap_or_else(|| current.value.title.clone()),
                    status: "draft".to_string(),
                    version_number: 1,
                    body,
                },
                credential,
            )
            .await
            .map_err(|error| write.failed_with(error, map_confluence_conflict))?;
        after_accepted_write("mutation_response", write.locators(), async {
            let mut draft = response.value;
            draft.space = current.value.space;
            draft.space_web_url = current.value.space_web_url;
            ensure_draft_content_matches_handle(&draft, &handle)?;
            require_draft_version_one(&draft)?;
            let result = draft_content_result(
                "blog.draft.update",
                &draft,
                ConfluenceDraftContentType::Blog,
                Some(inputs.draft_handle),
                None,
                &self.config,
            )?;
            enforce_result_size(&result, self.limits.max_upstream_response_bytes)?;
            let mut audit = draft_audit(
                &request,
                "blog.draft.update",
                &draft,
                ConfluenceDraftContentType::Blog,
                Some("storage"),
                true,
                self.backend.egress_proxy_audit(credential),
            );
            merge_confluence_content_write_audit(&mut audit, &content_audit);
            merge_attribution_audit(&mut audit, attribution);
            Ok(ProviderResult::new(result)
                .with_audit(audit)
                .with_upstream(
                    Some(response.status),
                    Some(current.duration_ms + response.duration_ms),
                )
                .with_object_ids(json!({ "blogId": draft.id })))
        })
        .await
    }

    async fn invoke_blog_draft_publish(
        &self,
        request: ProviderInvocation,
    ) -> Result<ProviderResult, ProviderError> {
        let credential = invocation_credential(&request)?;
        let lookup_credential = lookup_credential(request.admitted())?;
        let inputs = parse_blog_draft_body_format_inputs(request.action(), request.inputs())?;
        let handle = self.decode_draft_handle_for_request(
            ConfluenceDraftContentType::Blog,
            &inputs.blog_id,
            &inputs.draft_handle,
            request.admitted(),
        )?;
        let draft_response = self
            .draft_blog_response_with_space(
                &inputs.blog_id,
                Some(&inputs.body_format),
                lookup_credential,
            )
            .await?;
        let draft = draft_response.value;
        ensure_draft_content_matches_handle(&draft, &handle)?;
        require_draft_version_one(&draft)?;
        let body = draft_body_for_publish(&draft, &inputs.body_format)?;
        let draft_attachments = if handle.origin == ConfluenceDraftOrigin::New {
            self.draft_attachments_for_blog(&draft.id, lookup_credential)
                .await?
                .value
        } else {
            Vec::new()
        };
        for attachment in &draft_attachments {
            if attachment.page_id != draft.id {
                return Err(ProviderError::error(
                    ReasonCode::UpstreamProtocolFailed,
                    "Confluence blog draft attachment list returned a different parent",
                ));
            }
        }
        let write = ConfluenceWrite::new(json!({ "blogId": inputs.blog_id }));
        let response = self
            .backend
            .update_blog_draft(
                ConfluenceDraftUpdateRequest {
                    content_type: "blog".to_string(),
                    content_id: draft.id.clone(),
                    space_id: draft.space_id.clone(),
                    title: draft.title.clone(),
                    status: "current".to_string(),
                    version_number: draft_publish_version(&handle)?,
                    body,
                },
                credential,
            )
            .await
            .map_err(|error| write.failed_with(error, map_confluence_conflict))?;
        after_accepted_write("mutation_response", write.locators(), async {
            let mut published = response.value;
            published.space = draft.space.clone();
            published.space_web_url = draft.space_web_url.clone();
            require_current_draft_content(&published, ConfluenceDraftContentType::Blog)?;
            if published.id != draft.id || published.space_id != draft.space_id {
                return Err(ProviderError::error(
                    ReasonCode::UpstreamProtocolFailed,
                    "Confluence published blog did not match the draft",
                ));
            }
            let published_attachment_ids = if draft_attachments.is_empty() {
                Vec::new()
            } else {
                let current_attachments = self
                    .backend
                    .blog_attachments(&published.id, lookup_credential)
                    .await
                    .map_err(|error| {
                        // The blog post is published: throttling must not invite a second publish.
                        confluence_backend_error(error).unverified_after_mutation(
                            "post_publish_attachment_readback",
                            json!({"blogId": published.id}),
                        )
                    })?
                    .value;
                let current_ids = current_attachments
                    .iter()
                    .map(|attachment| attachment.id.as_str())
                    .collect::<BTreeSet<_>>();
                let draft_ids = draft_attachments
                    .iter()
                    .map(|attachment| attachment.id.clone())
                    .collect::<Vec<_>>();
                if draft_ids
                    .iter()
                    .any(|id| !current_ids.contains(id.as_str()))
                {
                    return Err(ProviderError::error(
                        ReasonCode::UpstreamProtocolFailed,
                        "Confluence blog draft attachments were not preserved through publish",
                    ));
                }
                draft_ids
            };
            let mut result = draft_content_result(
                "blog.draft.publish",
                &published,
                ConfluenceDraftContentType::Blog,
                None,
                None,
                &self.config,
            )?;
            result["draftVersion"] = json!(draft.version);
            result["publishedAttachmentIds"] = json!(published_attachment_ids);
            enforce_result_size(&result, self.limits.max_upstream_response_bytes)?;
            let mut audit = draft_audit(
                &request,
                "blog.draft.publish",
                &published,
                ConfluenceDraftContentType::Blog,
                Some(inputs.body_format.as_str()),
                true,
                self.backend.egress_proxy_audit(credential),
            );
            audit["lifecycle"] = json!("current");
            audit["draftVersion"] = json!(draft.version);
            audit["attachmentIds"] = json!(published_attachment_ids);
            Ok(ProviderResult::new(result)
                .with_audit(audit)
                .with_upstream(
                    Some(response.status),
                    Some(draft_response.duration_ms + response.duration_ms),
                )
                .with_object_ids(json!({
                    "blogId": published.id,
                    "attachmentIds": published_attachment_ids,
                })))
        })
        .await
    }

    async fn invoke_blog_draft_discard(
        &self,
        request: ProviderInvocation,
    ) -> Result<ProviderResult, ProviderError> {
        let credential = invocation_credential(&request)?;
        let lookup_credential = lookup_credential(request.admitted())?;
        let inputs = parse_blog_draft_discard_inputs(request.inputs())?;
        let handle = self.decode_draft_handle_for_request(
            ConfluenceDraftContentType::Blog,
            &inputs.blog_id,
            &inputs.draft_handle,
            request.admitted(),
        )?;
        reject_staged_draft_discard(&handle)?;
        let draft_response = self
            .draft_blog_response_with_space(&inputs.blog_id, Some("storage"), lookup_credential)
            .await?;
        let draft = draft_response.value;
        ensure_draft_content_matches_handle(&draft, &handle)?;
        require_draft_version_one(&draft)?;
        let write = ConfluenceWrite::new(json!({ "blogId": inputs.blog_id }));
        let response = self
            .backend
            .discard_blog_draft(&draft.id, credential)
            .await
            .map_err(|error| write.failed(error))?;
        after_accepted_write("mutation_response", write.locators(), async {
            match self
                .backend
                .draft_blog(&draft.id, Some("storage"), lookup_credential)
                .await
            {
                Ok(_) => {
                    return Err(ProviderError::error(
                        ReasonCode::UpstreamProtocolFailed,
                        "Confluence blog draft still exists after discard",
                    ));
                }
                Err(error)
                    if confluence_backend_reason_code(&error) == ReasonCode::ScopeUnresolved => {}
                Err(error) => {
                    return Err(confluence_backend_error(error).unverified_after_mutation(
                        "post_discard_readback",
                        json!({"blogId": draft.id}),
                    ));
                }
            }
            match self
                .backend
                .blog_metadata(&draft.id, lookup_credential)
                .await
            {
                Ok(_) => {
                    return Err(ProviderError::error(
                        ReasonCode::UpstreamProtocolFailed,
                        "Confluence blog draft discard created current content",
                    ));
                }
                Err(error)
                    if confluence_backend_reason_code(&error) == ReasonCode::ScopeUnresolved => {}
                Err(error) => {
                    return Err(confluence_backend_error(error).unverified_after_mutation(
                        "post_discard_readback",
                        json!({"blogId": draft.id}),
                    ));
                }
            }
            let result = json!({
                "operation": "blog.draft.discard",
                "blogId": draft.id,
                "lifecycle": "draft",
                "status": "discarded",
                "space": draft.space,
                "spaceId": draft.space_id,
                "discardedVersion": draft.version,
                "discarded": true,
            });
            enforce_result_size(&result, self.limits.max_upstream_response_bytes)?;
            Ok(ProviderResult::new(result)
                .with_audit(draft_audit(
                    &request,
                    "blog.draft.discard",
                    &draft,
                    ConfluenceDraftContentType::Blog,
                    None,
                    true,
                    self.backend.egress_proxy_audit(credential),
                ))
                .with_upstream(
                    Some(response.status),
                    Some(draft_response.duration_ms + response.duration_ms),
                )
                .with_object_ids(json!({ "blogId": draft.id })))
        })
        .await
    }

    async fn invoke_blog_draft_verify(
        &self,
        request: ProviderInvocation,
    ) -> Result<ProviderResult, ProviderError> {
        let lookup_credential = lookup_credential(request.admitted())?;
        let inputs = parse_blog_draft_verify_inputs(request.inputs())?;
        let handle = self.decode_draft_handle_for_request(
            ConfluenceDraftContentType::Blog,
            &inputs.blog_id,
            &inputs.draft_handle,
            request.admitted(),
        )?;
        let response = self
            .draft_blog_response_with_space(&inputs.blog_id, Some("storage"), lookup_credential)
            .await?;
        let draft = response.value;
        ensure_draft_content_matches_handle(&draft, &handle)?;
        let mut checked = Vec::new();
        if let Some(version) = inputs.expect_version {
            if draft.version != version {
                return Err(draft_verification_mismatch_error(
                    &request,
                    &draft,
                    ConfluenceDraftContentType::Blog,
                    &checked,
                    json!({"type": "blogVersion", "expected": version, "actual": draft.version}),
                    self.backend.egress_proxy_audit(lookup_credential),
                ));
            }
            checked.push(json!({"type": "blogVersion", "version": version}));
        }
        if let Some(title) = &inputs.expect_title {
            if draft.title != *title {
                return Err(draft_verification_mismatch_error(
                    &request,
                    &draft,
                    ConfluenceDraftContentType::Blog,
                    &checked,
                    json!({"type": "blogTitle"}),
                    self.backend.egress_proxy_audit(lookup_credential),
                ));
            }
            checked.push(json!({"type": "blogTitle"}));
        }
        if let Some(attachment_id) = &inputs.expect_attachment_id {
            reject_staged_draft_attachment_read(&handle)?;
            match self
                .draft_attachment_for_blog(&draft.id, attachment_id, lookup_credential)
                .await
            {
                Ok(_) => checked.push(
                    json!({"type": "attachment", "id": attachment_id, "parentStatus": "draft"}),
                ),
                Err(error)
                    if matches!(
                        error.reason_code().standard(),
                        Some(ReasonCode::ScopeUnresolved | ReasonCode::UpstreamForbidden)
                    ) =>
                {
                    return Err(draft_verification_mismatch_error(
                        &request,
                        &draft,
                        ConfluenceDraftContentType::Blog,
                        &checked,
                        json!({"type": "attachment", "id": attachment_id}),
                        self.backend.egress_proxy_audit(lookup_credential),
                    ));
                }
                Err(error) => return Err(error),
            }
        }
        let result = json!({
            "operation": "blog.draft.verify",
            "verification": {
                "status": "matched",
                "checked": checked,
            },
            "blogId": draft.id,
            "lifecycle": "draft",
            "status": draft.status,
            "space": draft.space,
            "spaceId": draft.space_id,
        });
        enforce_result_size(&result, self.limits.max_upstream_response_bytes)?;
        Ok(ProviderResult::new(result)
            .with_audit(json!({
                "provider": "confluence",
                "operation": "blog.draft.verify",
                "contentType": "blog",
                "lifecycle": "draft",
                "blogId": draft.id,
                "space": draft.space,
                "spaceId": draft.space_id,
                "checked": checked,
                "mutated": false,
                "draftHandleValidated": true,
                "credentialMode": request.credential_mode(),
                "egressProxy": self.backend.egress_proxy_audit(lookup_credential),
            }))
            .with_upstream(Some(response.status), Some(response.duration_ms))
            .with_object_ids(json!({
                "blogId": draft.id,
                "attachmentId": inputs.expect_attachment_id,
            })))
    }

    async fn invoke_blog_draft_attachment_add(
        &self,
        request: ProviderInvocation,
    ) -> Result<ProviderResult, ProviderError> {
        let credential = invocation_credential(&request)?;
        let lookup_credential = lookup_credential(request.admitted())?;
        let inputs = parse_blog_draft_attachment_add_inputs(request.inputs())?;
        let handle = self.decode_draft_handle_for_request(
            ConfluenceDraftContentType::Blog,
            &inputs.blog_id,
            &inputs.draft_handle,
            request.admitted(),
        )?;
        reject_staged_draft_attachment_add(&handle)?;
        let metadata_response =
            match ProviderState::optional::<ConfluenceDraftContentPreflight>(request.state())? {
                Some(preflight) => ConfluenceBackendResponse {
                    value: preflight.content.clone(),
                    status: preflight.upstream_status,
                    duration_ms: preflight.upstream_duration_ms,
                },
                None => {
                    self.draft_blog_response_with_space(
                        &inputs.blog_id,
                        Some("storage"),
                        lookup_credential,
                    )
                    .await?
                }
            };
        ensure_draft_content_matches_handle(&metadata_response.value, &handle)?;
        let uploads = prepare_attachment_uploads(
            &inputs.attachments,
            request.body_parts(),
            &self.config.attachments,
        )?;
        let mut successes = Vec::new();
        let mut failures = Vec::new();
        let mut audit_attachments = Vec::new();
        let mut upstream_duration_ms = metadata_response.duration_ms;
        let mut upstream_status = Some(metadata_response.status);
        // Set when Confluence throttled the upload that stopped the batch.
        let mut rate_limited = None;
        // Set when the SDK proved the upload that stopped the batch unsent.
        let mut stopped_unsent = false;
        // Set when the upload that stopped the batch may have applied.
        let mut stopped_uncertain = false;
        // Set when Confluence throttled the verification of an applied upload.
        let mut unverified_attachment_id = None;
        for (index, upload) in uploads.iter().cloned().enumerate() {
            match self
                .backend
                .add_blog_draft_attachment(&metadata_response.value.id, upload, credential)
                .await
            {
                Ok(response) => {
                    upstream_duration_ms += response.duration_ms;
                    upstream_status = Some(response.status);
                    let attachment = response.value;
                    if attachment.page_id != metadata_response.value.id {
                        return Err(ProviderError::error(
                            ReasonCode::UpstreamProtocolFailed,
                            "Confluence blog draft attachment upload returned mismatched parent",
                        )
                        .with_mutation_receipt(MutationReceipt::unknown()));
                    }
                    if let Err(error) = self
                        .draft_attachment_for_blog(
                            &metadata_response.value.id,
                            &attachment.id,
                            lookup_credential,
                        )
                        .await
                    {
                        if error.reason_code() != ReasonCode::UpstreamRateLimited {
                            // The upload applied: repeating the batch would
                            // upload it again.
                            return Err(error.or_mutation_receipt(MutationReceipt::unknown()));
                        }
                        // The upload applied but its verification was
                        // throttled: keep the batch and report it unverified,
                        // never as a rate limit whose retry would upload the
                        // attachments again.
                        audit_attachments.push(json!({
                            "status": "unverified",
                            "attachmentId": attachment.id,
                            "size": attachment.size,
                            "contentType": attachment.content_type,
                            "reason": "upstream_rate_limited",
                        }));
                        failures.push(json!({
                            "status": "unverified",
                            "attachmentId": attachment.id,
                            "filename": attachment.filename,
                            "reason": "upstream_rate_limited",
                        }));
                        for skipped in uploads.iter().skip(index + 1) {
                            audit_attachments.push(json!({
                                "status": "skipped",
                                "size": skipped.size,
                                "contentType": skipped.content_type,
                                "reason": "not_attempted_after_previous_failure",
                            }));
                            failures.push(json!({
                                "status": "skipped",
                                "reason": "not_attempted_after_previous_failure",
                            }));
                        }
                        unverified_attachment_id = Some(attachment.id);
                        break;
                    }
                    successes.push(json!({
                        "attachmentId": attachment.id,
                        "filename": attachment.filename,
                        "contentType": attachment.content_type,
                        "size": attachment.size,
                        "parentStatus": "draft",
                    }));
                    audit_attachments.push(json!({
                        "status": "created",
                        "attachmentId": attachment.id,
                        "size": attachment.size,
                        "contentType": attachment.content_type,
                    }));
                }
                Err(error) => {
                    if let ConfluenceBackendError::RateLimited(retry_after) = &error {
                        rate_limited = Some(*retry_after);
                    }
                    stopped_unsent = matches!(error, ConfluenceBackendError::NotSent { .. });
                    stopped_uncertain = upload_may_have_applied(&error);
                    audit_attachments.push(json!({
                        "status": "failed",
                        "size": uploads[index].size,
                        "contentType": uploads[index].content_type,
                        "reason": sanitized_backend_reason(&error),
                    }));
                    failures.push(json!({
                        "status": "failed",
                        "reason": sanitized_backend_reason(&error),
                    }));
                    for skipped in uploads.iter().skip(index + 1) {
                        audit_attachments.push(json!({
                            "status": "skipped",
                            "size": skipped.size,
                            "contentType": skipped.content_type,
                            "reason": "not_attempted_after_previous_failure",
                        }));
                        failures.push(json!({
                            "status": "skipped",
                            "reason": "not_attempted_after_previous_failure",
                        }));
                    }
                    break;
                }
            }
        }
        let status = if failures.is_empty() {
            "complete"
        } else {
            "partial"
        };
        let mut attachment_ids = successes
            .iter()
            .filter_map(|value| {
                value
                    .get("attachmentId")
                    .and_then(Value::as_str)
                    .map(ToString::to_string)
            })
            .collect::<Vec<_>>();
        // An unverified upload was still created.
        attachment_ids.extend(unverified_attachment_id.clone());
        let result = json!({
            "operation": "blog.draft.attachment.add",
            "status": status,
            "blogId": metadata_response.value.id,
            "space": metadata_response.value.space,
            "spaceId": metadata_response.value.space_id,
            "attachments": successes,
            "failures": failures,
        });
        let audit = json!({
            "provider": "confluence",
            "operation": "blog.draft.attachment.add",
            "contentType": "blog",
            "lifecycle": "draft",
            "blogId": metadata_response.value.id,
            "space": metadata_response.value.space,
            "spaceId": metadata_response.value.space_id,
            "status": status,
            "successCount": successes.len(),
            "failureCount": failures.len(),
            "attachments": audit_attachments,
            "attachmentIds": attachment_ids,
            "mutated": true,
            "draftHandleValidated": true,
            "credentialMode": request.credential_mode(),
            "egressProxy": self.backend.egress_proxy_audit(credential),
        });
        // Uploads that applied would be uploaded again by repeating the batch.
        enforce_result_size(&result, self.limits.max_upstream_response_bytes).map_err(|error| {
            if attachment_ids.is_empty() && !stopped_uncertain {
                error
            } else {
                error.or_mutation_receipt(MutationReceipt::unknown())
            }
        })?;
        let object_ids = json!({
            "blogId": metadata_response.value.id,
            "attachmentIds": attachment_ids,
        });
        if !failures.is_empty() {
            let mut error = ProviderError::error(
                ReasonCode::UpstreamFailed,
                "Confluence blog draft attachment upload partially failed",
            )
            .with_result(result);
            if let Some(retry_after) = rate_limited {
                error = if attachment_ids.is_empty() {
                    error.interrupted_by_upstream_rate_limit("confluence", retry_after)
                } else {
                    // Earlier uploads applied: waiting and repeating the batch
                    // would upload them again, so this is not a rate limit.
                    error.partially_applied_before_throttling(
                        "confluence",
                        "attachment_upload",
                        object_ids.clone(),
                    )
                };
            }
            if stopped_unsent && attachment_ids.is_empty() {
                // The first upload never reached Confluence and the rest
                // were skipped, so nothing was applied.
                error = error.with_mutation_receipt(MutationReceipt::not_applied());
            }
            if unverified_attachment_id.is_some() {
                error = error.unverified_after_throttling(
                    "confluence",
                    "post_upload_readback",
                    object_ids.clone(),
                );
            }
            if !attachment_ids.is_empty() || stopped_uncertain {
                // An upload may have applied: repeating the batch could
                // upload it again.
                error = error.or_mutation_receipt(MutationReceipt::unknown());
            }
            return Err(error
                .with_audit(audit)
                .with_upstream(upstream_status, Some(upstream_duration_ms))
                .with_object_ids(object_ids));
        }
        Ok(ProviderResult::new(result)
            .with_audit(audit)
            .with_upstream(upstream_status, Some(upstream_duration_ms))
            .with_object_ids(object_ids))
    }

    async fn invoke_blog_draft_attachment_list(
        &self,
        request: ProviderInvocation,
    ) -> Result<ProviderResult, ProviderError> {
        let credential = invocation_credential(&request)?;
        let lookup_credential = lookup_credential(request.admitted())?;
        let inputs = parse_blog_draft_attachment_list_inputs(request.inputs())?;
        let handle = self.decode_draft_handle_for_request(
            ConfluenceDraftContentType::Blog,
            &inputs.blog_id,
            &inputs.draft_handle,
            request.admitted(),
        )?;
        reject_staged_draft_attachment_read(&handle)?;
        let draft = self
            .draft_blog_response_with_space(&inputs.blog_id, Some("storage"), lookup_credential)
            .await?;
        ensure_draft_content_matches_handle(&draft.value, &handle)?;
        let max_results = capped_max_results(inputs.max_results, &self.config.search)?;
        let next_position = inputs
            .next_page_token
            .as_deref()
            .map(|token| {
                self.continuations.open_draft_attachment_page(
                    request.context(),
                    credential,
                    &handle,
                    max_results,
                    token,
                )
            })
            .transpose()?;
        let response = self
            .backend
            .blog_draft_attachments_page(
                &draft.value.id,
                max_results,
                next_position.as_deref(),
                credential,
            )
            .await
            .map_err(confluence_backend_error)?;
        let (attachments, attachment_ids) =
            draft_attachment_values(&response.value.attachments, &draft.value.id)?;
        let next_page_token = response
            .value
            .next_position
            .clone()
            .map(|position| {
                self.continuations.seal_draft_attachment_page(
                    request.context(),
                    credential,
                    &handle,
                    max_results,
                    &position,
                )
            })
            .transpose()?;
        let has_more = next_page_token.is_some();
        let result = json!({
            "operation": "blog.draft.attachment.list",
            "blog": {
                "blogId": draft.value.id,
                "space": draft.value.space,
                "spaceId": draft.value.space_id,
                "status": "draft",
            },
            "attachments": attachments,
            "count": attachments.len(),
            "hasMore": has_more,
            "nextPageToken": next_page_token,
        });
        enforce_result_size(&result, self.limits.max_upstream_response_bytes)?;
        Ok(ProviderResult::new(result)
            .with_audit(json!({
                "provider": "confluence",
                "operation": "blog.draft.attachment.list",
                "contentType": "blog",
                "lifecycle": "draft",
                "blogId": draft.value.id,
                "space": draft.value.space,
                "spaceId": draft.value.space_id,
                "attachmentCount": attachment_ids.len(),
                "hasMore": has_more,
                "mutated": false,
                "draftHandleValidated": true,
                "credentialMode": request.credential_mode(),
                "egressProxy": self.backend.egress_proxy_audit(credential),
            }))
            .with_upstream(
                Some(response.status),
                Some(draft.duration_ms + response.duration_ms),
            )
            .with_object_ids(json!({
                "blogId": draft.value.id,
                "attachmentIds": attachment_ids,
            })))
    }

    async fn invoke_blog_draft_attachment_download(
        &self,
        request: ProviderInvocation,
    ) -> Result<ProviderResult, ProviderError> {
        let credential = invocation_credential(&request)?;
        let lookup_credential = lookup_credential(request.admitted())?;
        let inputs = parse_blog_draft_attachment_download_inputs(request.inputs())?;
        let handle = self.decode_draft_handle_for_request(
            ConfluenceDraftContentType::Blog,
            &inputs.blog_id,
            &inputs.draft_handle,
            request.admitted(),
        )?;
        reject_staged_draft_attachment_read(&handle)?;
        let draft = self
            .draft_blog_response_with_space(&inputs.blog_id, Some("storage"), lookup_credential)
            .await?;
        ensure_draft_content_matches_handle(&draft.value, &handle)?;
        let attachment = self
            .draft_attachment_for_blog(&draft.value.id, &inputs.attachment_id, lookup_credential)
            .await?
            .value;
        validate_download_attachment(&attachment, &self.config)?;
        let response = self
            .backend
            .blog_draft_attachment_content(&draft.value.id, &inputs.attachment_id, credential)
            .await
            .map_err(confluence_backend_error)?;
        validate_download_content(&response.value, &attachment, &self.config)?;
        let content_type = response.value.content_type.clone();
        let result = json!({
            "operation": "blog.draft.attachment.download",
            "blogId": draft.value.id,
            "space": draft.value.space,
            "spaceId": draft.value.space_id,
            "attachmentId": attachment.id,
            "filename": attachment.filename,
            "contentType": content_type,
            "metadataContentType": attachment.content_type,
            "size": attachment.size,
            "parentStatus": "draft",
        });
        let stream = response.value.stream.with_expected_size(
            attachment.size,
            "Confluence blog draft attachment response size did not match metadata",
        );
        Ok(ProviderResult::new(result)
            .with_stream(stream)
            .with_audit(json!({
                "provider": "confluence",
                "operation": "blog.draft.attachment.download",
                "contentType": "blog",
                "lifecycle": "draft",
                "blogId": draft.value.id,
                "space": draft.value.space,
                "spaceId": draft.value.space_id,
                "attachmentIds": [attachment.id],
                "size": attachment.size,
                "metadataContentType": attachment.content_type,
                "mutated": false,
                "draftHandleValidated": true,
                "credentialMode": request.credential_mode(),
                "egressProxy": self.backend.egress_proxy_audit(credential),
            }))
            .with_upstream(
                Some(response.status),
                Some(draft.duration_ms + response.duration_ms),
            )
            .with_object_ids(json!({
                "blogId": draft.value.id,
                "attachmentId": attachment.id,
            })))
    }

    async fn invoke_blog_attachment_add(
        &self,
        request: ProviderInvocation,
    ) -> Result<ProviderResult, ProviderError> {
        let credential = invocation_credential(&request)?;
        let lookup_credential = lookup_credential(request.admitted())?;
        let inputs = parse_blog_attachment_add_inputs(request.inputs())?;
        let metadata_response =
            match ProviderState::optional::<ConfluenceBlogPreflight>(request.state())? {
                Some(preflight) => ConfluenceBackendResponse {
                    value: preflight.blog.clone(),
                    status: preflight.upstream_status,
                    duration_ms: preflight.upstream_duration_ms,
                },
                None => {
                    self.confirmed_blog_response(&inputs.blog_id, lookup_credential)
                        .await?
                }
            };
        let blog = metadata_response.value;
        let uploads = prepare_attachment_uploads(
            &inputs.attachments,
            request.body_parts(),
            &self.config.attachments,
        )?;
        let mut successes = Vec::new();
        let mut failures = Vec::new();
        let mut attachment_audit = Vec::new();
        let mut upstream_duration_ms = metadata_response.duration_ms;
        let mut upstream_status = Some(metadata_response.status);
        // Set when Confluence throttled the upload that stopped the batch.
        let mut rate_limited = None;
        // Set when the SDK proved the upload that stopped the batch unsent.
        let mut stopped_unsent = false;
        // Set when the upload that stopped the batch may have applied.
        let mut stopped_uncertain = false;
        for (index, upload) in uploads.iter().cloned().enumerate() {
            let upload_audit = attachment_upload_audit(&upload);
            match self
                .backend
                .add_blog_attachment(&blog.id, upload, credential)
                .await
            {
                Ok(response) => {
                    upstream_duration_ms += response.duration_ms;
                    upstream_status = Some(response.status);
                    if response.value.page_id != blog.id {
                        return Err(ProviderError::error(
                            ReasonCode::UpstreamProtocolFailed,
                            "Confluence blog attachment upload returned mismatched parent",
                        )
                        .with_mutation_receipt(MutationReceipt::unknown()));
                    }
                    successes.push(json!({
                        "attachmentId": response.value.id,
                        "filename": response.value.filename,
                        "contentType": response.value.content_type,
                        "size": response.value.size,
                    }));
                    attachment_audit.push(json!({
                        "status": "created",
                        "attachmentId": response.value.id,
                        "attachment": upload_audit,
                    }));
                }
                Err(error) => {
                    if let ConfluenceBackendError::RateLimited(retry_after) = &error {
                        rate_limited = Some(*retry_after);
                    }
                    stopped_unsent = matches!(error, ConfluenceBackendError::NotSent { .. });
                    stopped_uncertain = upload_may_have_applied(&error);
                    attachment_audit.push(json!({
                        "status": "failed",
                        "attachment": upload_audit.clone(),
                        "reason": sanitized_backend_reason(&error),
                    }));
                    failures.push(json!({
                        "status": "failed",
                        "attachment": upload_audit,
                        "reason": sanitized_backend_reason(&error),
                    }));
                    for skipped in uploads.iter().skip(index + 1) {
                        let skipped_audit = attachment_upload_audit(skipped);
                        attachment_audit.push(json!({
                            "status": "skipped",
                            "attachment": skipped_audit.clone(),
                            "reason": "not_attempted_after_previous_failure",
                        }));
                        failures.push(json!({
                            "status": "skipped",
                            "attachment": skipped_audit,
                            "reason": "not_attempted_after_previous_failure",
                        }));
                    }
                    break;
                }
            }
        }
        if successes.is_empty() && !failures.is_empty() {
            let mut error = ProviderError::error(
                ReasonCode::UpstreamFailed,
                "Confluence blog attachment upload failed",
            );
            if let Some(retry_after) = rate_limited {
                error = error.interrupted_by_upstream_rate_limit("confluence", retry_after);
            }
            if stopped_unsent {
                // The first upload never reached Confluence and the rest
                // were skipped, so nothing was applied.
                error = error.with_mutation_receipt(MutationReceipt::not_applied());
            } else if stopped_uncertain {
                error = error.with_mutation_receipt(MutationReceipt::unknown());
            }
            return Err(error.with_audit(json!({
                "provider": "confluence",
                "operation": "blog.attachment.add",
                "blogId": blog.id,
                "space": blog.space,
                "spaceId": blog.space_id,
                "status": "failed",
                "successCount": 0,
                "failureCount": failures.len(),
                "attachments": attachment_audit,
                "credentialMode": request.credential_mode(),
                "egressProxy": self.backend.egress_proxy_audit(credential),
            })));
        }
        let status = if failures.is_empty() {
            "complete"
        } else {
            "partial"
        };
        let result = json!({
            "status": status,
            "blogId": blog.id,
            "space": blog.space,
            "spaceId": blog.space_id,
            "attachments": successes,
            "failures": failures,
        });
        // Uploads were applied: repeating the batch would upload them again.
        enforce_result_size(&result, self.limits.max_upstream_response_bytes)
            .map_err(|error| error.or_mutation_receipt(MutationReceipt::unknown()))?;
        let audit = json!({
            "provider": "confluence",
            "operation": "blog.attachment.add",
            "blogId": blog.id,
            "space": blog.space,
            "spaceId": blog.space_id,
            "status": status,
            "successCount": successes.len(),
            "failureCount": failures.len(),
            "attachments": attachment_audit,
            "credentialMode": request.credential_mode(),
            "egressProxy": self.backend.egress_proxy_audit(credential),
        });
        let object_ids = json!({
            "blogId": blog.id,
            "attachmentIds": successes.iter().filter_map(|value| {
                value.get("attachmentId").and_then(Value::as_str).map(ToString::to_string)
            }).collect::<Vec<_>>(),
        });
        if !failures.is_empty() {
            let mut error = ProviderError::error(
                ReasonCode::UpstreamFailed,
                "Confluence blog attachment upload partially failed",
            )
            .with_result(result);
            if rate_limited.is_some() {
                // Earlier uploads applied: waiting and repeating the batch
                // would upload them again, so this is not a rate limit.
                error = error.partially_applied_before_throttling(
                    "confluence",
                    "attachment_upload",
                    object_ids.clone(),
                );
            }
            // Earlier uploads applied: repeating the batch would upload them
            // again.
            error = error.or_mutation_receipt(MutationReceipt::unknown());
            return Err(error
                .with_audit(audit)
                .with_upstream(upstream_status, Some(upstream_duration_ms))
                .with_object_ids(object_ids));
        }
        Ok(ProviderResult::new(result)
            .with_audit(audit)
            .with_upstream(upstream_status, Some(upstream_duration_ms))
            .with_object_ids(object_ids))
    }

    async fn invoke_blog_attachment_download(
        &self,
        request: ProviderInvocation,
    ) -> Result<ProviderResult, ProviderError> {
        let credential = invocation_credential(&request)?;
        let lookup_credential = lookup_credential(request.admitted())?;
        let inputs = parse_blog_attachment_download_inputs(request.inputs())?;
        let blog = self
            .confirmed_blog(&inputs.blog_id, lookup_credential)
            .await?;
        let attachment = self
            .attachment_for_blog(&blog.id, &inputs.attachment_id, lookup_credential)
            .await?;
        validate_download_attachment(&attachment, &self.config)?;
        let response = self
            .backend
            .blog_attachment_content(&blog.id, &inputs.attachment_id, credential)
            .await
            .map_err(confluence_backend_error)?;
        validate_download_content(&response.value, &attachment, &self.config)?;
        if response
            .value
            .size
            .is_some_and(|size| size > self.limits.max_download_bytes)
        {
            return Err(ProviderError::deny(
                ReasonCode::AttachmentSizeDenied,
                "Confluence blog attachment download exceeded the configured byte cap",
            ));
        }
        let downloaded_size = attachment.size;
        if downloaded_size > self.config.attachments.max_download_bytes
            || downloaded_size > self.limits.max_download_bytes
        {
            return Err(ProviderError::deny(
                ReasonCode::AttachmentSizeDenied,
                "Confluence blog attachment download exceeded the configured byte cap",
            ));
        }
        let content_type = response.value.content_type.clone();
        let mut result = json!({
            "blogId": blog.id,
            "space": blog.space,
            "spaceId": blog.space_id,
            "attachmentId": attachment.id,
            "filename": attachment.filename,
            "contentType": content_type,
            "metadataContentType": attachment.content_type,
            "size": downloaded_size,
        });
        if let Some(sha256) = response.value.sha256.clone() {
            result["sha256"] = json!(sha256);
        }
        let stream = response.value.stream.with_expected_size(
            downloaded_size,
            "Confluence blog attachment response size did not match metadata",
        );
        let mut audit = json!({
            "provider": "confluence",
            "operation": "blog.attachment.download",
            "blogId": blog.id,
            "space": blog.space,
            "spaceId": blog.space_id,
            "attachmentId": attachment.id,
            "filename": attachment.filename,
            "contentType": content_type,
            "metadataContentType": attachment.content_type,
            "size": downloaded_size,
            "credentialMode": request.credential_mode(),
            "egressProxy": self.backend.egress_proxy_audit(credential),
        });
        if let Some(sha256) = result.get("sha256").cloned() {
            audit["sha256"] = sha256;
        }
        Ok(ProviderResult::new(result)
            .with_stream(stream)
            .with_audit(audit)
            .with_upstream(Some(response.status), Some(response.duration_ms))
            .with_object_ids(json!({
                "blogId": blog.id,
                "attachmentId": attachment.id,
            })))
    }

    async fn invoke_blog_attachment_list(
        &self,
        request: ProviderInvocation,
    ) -> Result<ProviderResult, ProviderError> {
        let credential = invocation_credential(&request)?;
        let lookup_credential = lookup_credential(request.admitted())?;
        let inputs = parse_blog_attachment_list_inputs(request.inputs(), &self.config)?;
        let blog = self
            .confirmed_blog(&inputs.locator.blog_id, lookup_credential)
            .await?;
        validate_blog_locator_space(&inputs.locator, &blog.space)?;
        let max_results = capped_max_results(inputs.max_results, &self.config.search)?;
        let next_position = inputs
            .next_page_token
            .as_deref()
            .map(|token| {
                self.continuations.open_blog_attachment_page(
                    request.context(),
                    credential,
                    &blog,
                    max_results,
                    token,
                )
            })
            .transpose()?;
        let response = self
            .backend
            .blog_attachments_page(&blog.id, max_results, next_position.as_deref(), credential)
            .await
            .map_err(confluence_backend_error)?;
        if response.value.attachments.len() > max_results as usize {
            return Err(ProviderError::error(
                ReasonCode::UpstreamProtocolFailed,
                "Confluence blog attachment list returned more attachments than requested",
            ));
        }
        let attachment_values = response
            .value
            .attachments
            .iter()
            .map(|attachment| {
                if attachment.page_id != blog.id {
                    return Err(ProviderError::error(
                        ReasonCode::UpstreamProtocolFailed,
                        "Confluence blog attachment list returned metadata for a different blog",
                    ));
                }
                Ok(json!({
                    "attachmentId": attachment.id,
                    "filename": attachment.filename,
                    "size": attachment.size,
                    "contentType": attachment.content_type,
                }))
            })
            .collect::<Result<Vec<_>, ProviderError>>()?;
        let attachment_ids = response
            .value
            .attachments
            .iter()
            .map(|attachment| attachment.id.clone())
            .collect::<Vec<_>>();
        let next_page_token = response
            .value
            .next_position
            .clone()
            .map(|position| {
                self.continuations.seal_blog_attachment_page(
                    request.context(),
                    credential,
                    &blog,
                    max_results,
                    &position,
                )
            })
            .transpose()?;
        let has_more = next_page_token.is_some();
        let count = attachment_values.len();
        let result = json!({
            "operation": "blog.attachment.list",
            "blog": {
                "blogId": blog.id,
                "space": blog.space,
                "spaceId": blog.space_id,
            },
            "attachments": attachment_values,
            "count": count,
            "hasMore": has_more,
            "nextPageToken": next_page_token,
        });
        enforce_result_size(&result, self.limits.max_upstream_response_bytes)?;
        Ok(ProviderResult::new(result)
            .with_audit(json!({
                "provider": "confluence",
                "operation": "blog.attachment.list",
                "blogId": blog.id,
                "space": blog.space,
                "spaceId": blog.space_id,
                "attachmentCount": count,
                "hasMore": has_more,
                "credentialMode": request.credential_mode(),
                "egressProxy": self.backend.egress_proxy_audit(credential),
            }))
            .with_upstream(Some(response.status), Some(response.duration_ms))
            .with_object_ids(json!({
                "blogId": blog.id,
                "attachmentIds": attachment_ids,
            })))
    }

    async fn invoke_blog_verify(
        &self,
        request: ProviderInvocation,
    ) -> Result<ProviderResult, ProviderError> {
        let credential = invocation_credential(&request)?;
        let inputs = parse_blog_verify_inputs(request.inputs())?;
        let blog_response = self
            .confirmed_blog_response(&inputs.blog_id, credential)
            .await?;
        let blog = blog_response.value;
        let mut upstream_duration_ms = blog_response.duration_ms;
        let mut upstream_status = Some(blog_response.status);
        let mut checked = Vec::new();
        if let Some(version) = inputs.expect_version {
            if blog.version != version {
                return Err(confluence_blog_verification_mismatch_error(
                    &request,
                    &blog,
                    &checked,
                    json!({"type": "blogVersion", "expected": version, "actual": blog.version}),
                    &inputs,
                    self.backend.egress_proxy_audit(credential),
                ));
            }
            checked.push(json!({"type": "blogVersion", "version": version}));
        }
        if let Some(title) = &inputs.expect_title {
            if blog.title != *title {
                return Err(confluence_blog_verification_mismatch_error(
                    &request,
                    &blog,
                    &checked,
                    json!({"type": "blogTitle"}),
                    &inputs,
                    self.backend.egress_proxy_audit(credential),
                ));
            }
            checked.push(json!({"type": "blogTitle"}));
        }
        if let Some(attachment_id) = &inputs.expect_attachment_id {
            match self
                .attachment_for_blog_response(&blog.id, attachment_id, credential)
                .await
            {
                Ok(response) => {
                    upstream_duration_ms += response.duration_ms;
                    upstream_status = Some(response.status);
                    checked.push(json!({"type": "attachment", "id": attachment_id}));
                }
                Err(error)
                    if matches!(
                        error.reason_code().standard(),
                        Some(ReasonCode::ScopeUnresolved | ReasonCode::UpstreamForbidden)
                    ) =>
                {
                    return Err(confluence_blog_verification_mismatch_error(
                        &request,
                        &blog,
                        &checked,
                        json!({"type": "attachment", "id": attachment_id}),
                        &inputs,
                        self.backend.egress_proxy_audit(credential),
                    ));
                }
                Err(error) => return Err(error),
            }
        }
        let result = json!({
            "verification": {
                "status": "matched",
                "checked": checked,
            },
            "blogId": blog.id,
            "space": blog.space,
            "spaceId": blog.space_id,
        });
        enforce_result_size(&result, self.limits.max_upstream_response_bytes)?;
        Ok(ProviderResult::new(result)
            .with_audit(json!({
                "provider": "confluence",
                "operation": "blog.verify",
                "blogId": blog.id,
                "space": blog.space,
                "spaceId": blog.space_id,
                "checked": checked,
                "credentialMode": request.credential_mode(),
                "egressProxy": self.backend.egress_proxy_audit(credential),
            }))
            .with_upstream(upstream_status, Some(upstream_duration_ms))
            .with_object_ids(json!({
                "blogId": blog.id,
                "attachmentId": inputs.expect_attachment_id,
            })))
    }

    /// Resolves a draft action's space from its handle before policy: the
    /// handle must be one this provider issued, in this execution context and
    /// tenant, for the content the inputs name, and ownable by the caller.
    fn draft_handle_scopes(
        &self,
        request: &ScopeRequest<'_>,
        content_type: ConfluenceDraftContentType,
        content_id: &str,
        draft_handle: &str,
    ) -> Result<ResourceScopes, ProviderError> {
        let handle = self.continuations.open_draft_handle_for_scope(
            request,
            content_type,
            content_id,
            draft_handle,
        )?;
        let mut scopes = ResourceScopes::new();
        scopes.insert("space".to_string(), vec![handle.space]);
        Ok(scopes)
    }

    /// Opens a handle after admission, for the admitted owner, and checks it
    /// names the authorized space.
    fn decode_draft_handle_for_request(
        &self,
        content_type: ConfluenceDraftContentType,
        content_id: &str,
        draft_handle: &str,
        request: &AdmittedRequest,
    ) -> Result<ConfluenceDraftHandle, ProviderError> {
        let handle = self.continuations.open_draft_handle(
            request.context(),
            content_type,
            content_id,
            draft_handle,
        )?;
        ensure_authorized_draft_handle(&handle, request.resource_scopes()?)?;
        Ok(handle)
    }

    fn mint_draft_handle(
        &self,
        content_type: ConfluenceDraftContentType,
        content: &ConfluenceDraftContent,
        origin: ConfluenceDraftOrigin,
        base_version: Option<u64>,
        request: &ProviderInvocation,
    ) -> Result<String, ProviderError> {
        let handle = ConfluenceDraftHandle::new(content_type, content, origin, base_version);
        self.continuations
            .seal_draft_handle(request.context(), &handle)
    }

    async fn draft_page_response_with_space(
        &self,
        page_id: &str,
        body_format: Option<&str>,
        credential: &ExecutionCredential,
    ) -> Result<ConfluenceBackendResponse<ConfluenceDraftContent>, ProviderError> {
        let response = self
            .backend
            .draft_page(page_id, body_format, credential)
            .await
            .map_err(confluence_backend_error)?;
        self.draft_response_with_resolved_space(response, credential)
            .await
    }

    async fn draft_blog_response_with_space(
        &self,
        blog_id: &str,
        body_format: Option<&str>,
        credential: &ExecutionCredential,
    ) -> Result<ConfluenceBackendResponse<ConfluenceDraftContent>, ProviderError> {
        let response = self
            .backend
            .draft_blog(blog_id, body_format, credential)
            .await
            .map_err(confluence_backend_error)?;
        self.draft_response_with_resolved_space(response, credential)
            .await
    }

    async fn draft_response_with_resolved_space(
        &self,
        mut response: ConfluenceBackendResponse<ConfluenceDraftContent>,
        credential: &ExecutionCredential,
    ) -> Result<ConfluenceBackendResponse<ConfluenceDraftContent>, ProviderError> {
        let space_response = self
            .backend
            .space_by_id(&response.value.space_id, credential)
            .await
            .map_err(confluence_backend_error)?;
        if space_response.value.id != response.value.space_id {
            return Err(ProviderError::error(
                ReasonCode::UpstreamProtocolFailed,
                "Confluence draft space metadata did not match requested id",
            ));
        }
        response.value.space = space_response.value.key;
        response.value.space_web_url = space_response.value.web_url;
        response.duration_ms = response
            .duration_ms
            .saturating_add(space_response.duration_ms);
        Ok(response)
    }

    async fn draft_attachment_for_page(
        &self,
        page_id: &str,
        attachment_id: &str,
        credential: &ExecutionCredential,
    ) -> Result<ConfluenceBackendResponse<ConfluenceAttachment>, ProviderError> {
        let response = self.draft_attachments_for_page(page_id, credential).await?;
        draft_attachment_from_collection(response, page_id, attachment_id)
    }

    async fn draft_attachment_for_blog(
        &self,
        blog_id: &str,
        attachment_id: &str,
        credential: &ExecutionCredential,
    ) -> Result<ConfluenceBackendResponse<ConfluenceAttachment>, ProviderError> {
        let response = self.draft_attachments_for_blog(blog_id, credential).await?;
        draft_attachment_from_collection(response, blog_id, attachment_id)
    }

    async fn draft_attachments_for_page(
        &self,
        page_id: &str,
        credential: &ExecutionCredential,
    ) -> Result<ConfluenceBackendResponse<Vec<ConfluenceAttachment>>, ProviderError> {
        let mut attachments = Vec::new();
        let mut next_position = None;
        let mut seen_positions = BTreeSet::new();
        let mut upstream_duration_ms = 0_u64;
        for _ in 0..MAX_DRAFT_ATTACHMENT_LOOKUP_PAGES {
            let response = self
                .backend
                .page_draft_attachments_page(
                    page_id,
                    DRAFT_ATTACHMENT_LOOKUP_PAGE_SIZE,
                    next_position.as_deref(),
                    credential,
                )
                .await
                .map_err(confluence_backend_error)?;
            let upstream_status = response.status;
            upstream_duration_ms = upstream_duration_ms.saturating_add(response.duration_ms);
            for attachment in response.value.attachments {
                if attachment.page_id != page_id {
                    return Err(ProviderError::error(
                        ReasonCode::UpstreamProtocolFailed,
                        "Confluence page draft attachment list returned a different parent",
                    ));
                }
                attachments.push(attachment);
            }
            let Some(position) = response.value.next_position else {
                return Ok(ConfluenceBackendResponse {
                    value: attachments,
                    status: upstream_status,
                    duration_ms: upstream_duration_ms,
                });
            };
            if !seen_positions.insert(position.clone()) {
                return Err(ProviderError::error(
                    ReasonCode::UpstreamProtocolFailed,
                    "Confluence page draft attachment pagination repeated a continuation token",
                ));
            }
            next_position = Some(position);
        }
        Err(ProviderError::error(
            ReasonCode::UpstreamProtocolFailed,
            "Confluence page draft attachment pagination limit exceeded",
        ))
    }

    async fn draft_attachments_for_blog(
        &self,
        blog_id: &str,
        credential: &ExecutionCredential,
    ) -> Result<ConfluenceBackendResponse<Vec<ConfluenceAttachment>>, ProviderError> {
        let mut attachments = Vec::new();
        let mut next_position = None;
        let mut seen_positions = BTreeSet::new();
        let mut upstream_duration_ms = 0_u64;
        for _ in 0..MAX_DRAFT_ATTACHMENT_LOOKUP_PAGES {
            let response = self
                .backend
                .blog_draft_attachments_page(
                    blog_id,
                    DRAFT_ATTACHMENT_LOOKUP_PAGE_SIZE,
                    next_position.as_deref(),
                    credential,
                )
                .await
                .map_err(confluence_backend_error)?;
            let upstream_status = response.status;
            upstream_duration_ms = upstream_duration_ms.saturating_add(response.duration_ms);
            for attachment in response.value.attachments {
                if attachment.page_id != blog_id {
                    return Err(ProviderError::error(
                        ReasonCode::UpstreamProtocolFailed,
                        "Confluence blog draft attachment list returned a different parent",
                    ));
                }
                attachments.push(attachment);
            }
            let Some(position) = response.value.next_position else {
                return Ok(ConfluenceBackendResponse {
                    value: attachments,
                    status: upstream_status,
                    duration_ms: upstream_duration_ms,
                });
            };
            if !seen_positions.insert(position.clone()) {
                return Err(ProviderError::error(
                    ReasonCode::UpstreamProtocolFailed,
                    "Confluence blog draft attachment pagination repeated a continuation token",
                ));
            }
            next_position = Some(position);
        }
        Err(ProviderError::error(
            ReasonCode::UpstreamProtocolFailed,
            "Confluence blog draft attachment pagination limit exceeded",
        ))
    }

    async fn confirmed_page(
        &self,
        page_id: &str,
        candidate_space: Option<&str>,
        credential: &ExecutionCredential,
    ) -> Result<ConfluencePage, ProviderError> {
        Ok(self
            .confirmed_page_response(page_id, candidate_space, credential)
            .await?
            .value)
    }

    async fn confirmed_page_response(
        &self,
        page_id: &str,
        candidate_space: Option<&str>,
        credential: &ExecutionCredential,
    ) -> Result<ConfluenceBackendResponse<ConfluencePage>, ProviderError> {
        let response = self
            .backend
            .page_metadata(page_id, credential)
            .await
            .map_err(confluence_backend_error)?;
        if response.value.id != page_id {
            return Err(ProviderError::error(
                ReasonCode::UpstreamProtocolFailed,
                "Confluence page metadata did not match requested page",
            ));
        }
        if let Some(candidate) = candidate_space
            && candidate != response.value.space
        {
            return Err(ProviderError::deny(
                ReasonCode::ScopeUnresolved,
                "Confluence page space did not match the requested scope",
            ));
        }
        require_current_page(&response.value)?;
        Ok(response)
    }

    async fn confirmed_blog(
        &self,
        blog_id: &str,
        credential: &ExecutionCredential,
    ) -> Result<ConfluenceBlog, ProviderError> {
        Ok(self
            .confirmed_blog_response(blog_id, credential)
            .await?
            .value)
    }

    async fn confirmed_blog_response(
        &self,
        blog_id: &str,
        credential: &ExecutionCredential,
    ) -> Result<ConfluenceBackendResponse<ConfluenceBlog>, ProviderError> {
        let response = self
            .blog_metadata_response_with_space(blog_id, credential)
            .await?;
        if response.value.id != blog_id {
            return Err(ProviderError::error(
                ReasonCode::UpstreamProtocolFailed,
                "Confluence blog metadata did not match requested blog",
            ));
        }
        if response.value.status.as_deref() != Some("current") {
            return Err(ProviderError::deny(
                ReasonCode::ScopeUnresolved,
                "Confluence blog status is not current",
            ));
        }
        Ok(response)
    }

    async fn blog_scope_evidence(
        &self,
        blog_id: &str,
        credential: &ExecutionCredential,
    ) -> Result<ConfluenceBlogScopeEvidence, ProviderError> {
        Ok(self
            .blog_scope_evidence_response(blog_id, credential)
            .await?
            .value)
    }

    async fn blog_scope_evidence_response(
        &self,
        blog_id: &str,
        credential: &ExecutionCredential,
    ) -> Result<ConfluenceBackendResponse<ConfluenceBlogScopeEvidence>, ProviderError> {
        let mut response = self
            .backend
            .blog_scope_evidence(blog_id, credential)
            .await
            .map_err(|error| blog_scope_lookup_error(blog_id, error))?;
        if response.value.id != blog_id {
            return Err(blog_scope_requires_lookup(blog_id.to_string()));
        }
        let space_response = self
            .backend
            .space_by_id(&response.value.space_id, credential)
            .await
            .map_err(|error| blog_scope_lookup_error(blog_id, error))?;
        if space_response.value.id != response.value.space_id {
            return Err(blog_scope_requires_lookup(blog_id.to_string()));
        }
        response.value.space = space_response.value.key;
        response.duration_ms = response
            .duration_ms
            .saturating_add(space_response.duration_ms);
        Ok(response)
    }

    async fn blog_metadata_response_with_space(
        &self,
        blog_id: &str,
        credential: &ExecutionCredential,
    ) -> Result<ConfluenceBackendResponse<ConfluenceBlog>, ProviderError> {
        let response = self
            .backend
            .blog_metadata(blog_id, credential)
            .await
            .map_err(confluence_backend_error)?;
        self.blog_response_with_resolved_space(response, credential)
            .await
    }

    async fn blog_response_with_space(
        &self,
        blog_id: &str,
        credential: &ExecutionCredential,
    ) -> Result<ConfluenceBackendResponse<ConfluenceBlog>, ProviderError> {
        let response = self
            .backend
            .blog(blog_id, credential)
            .await
            .map_err(confluence_backend_error)?;
        self.blog_response_with_resolved_space(response, credential)
            .await
    }

    async fn blog_response_with_resolved_space(
        &self,
        mut response: ConfluenceBackendResponse<ConfluenceBlog>,
        credential: &ExecutionCredential,
    ) -> Result<ConfluenceBackendResponse<ConfluenceBlog>, ProviderError> {
        let space_response = self
            .backend
            .space_by_id(&response.value.space_id, credential)
            .await
            .map_err(confluence_backend_error)?;
        if space_response.value.id != response.value.space_id {
            return Err(ProviderError::error(
                ReasonCode::UpstreamProtocolFailed,
                "Confluence space metadata did not match requested id",
            ));
        }
        response.value.space = space_response.value.key;
        response.value.space_web_url = space_response.value.web_url;
        response.duration_ms = response
            .duration_ms
            .saturating_add(space_response.duration_ms);
        Ok(response)
    }

    async fn attachment_for_page(
        &self,
        page_id: &str,
        attachment_id: &str,
        credential: &ExecutionCredential,
    ) -> Result<ConfluenceAttachment, ProviderError> {
        Ok(self
            .attachment_for_page_response(page_id, attachment_id, credential)
            .await?
            .value)
    }

    async fn attachment_for_page_response(
        &self,
        page_id: &str,
        attachment_id: &str,
        credential: &ExecutionCredential,
    ) -> Result<ConfluenceBackendResponse<ConfluenceAttachment>, ProviderError> {
        let response = self
            .backend
            .page_attachments(page_id, credential)
            .await
            .map_err(confluence_backend_error)?;
        let status = response.status;
        let duration_ms = response.duration_ms;
        let value = response
            .value
            .into_iter()
            .find(|attachment| attachment.id == attachment_id && attachment.page_id == page_id)
            .ok_or_else(|| {
                ProviderError::deny(
                    ReasonCode::ScopeUnresolved,
                    "Confluence attachment did not belong to the authorized page",
                )
            })?;
        Ok(ConfluenceBackendResponse {
            value,
            status,
            duration_ms,
        })
    }

    async fn attachment_for_blog(
        &self,
        blog_id: &str,
        attachment_id: &str,
        credential: &ExecutionCredential,
    ) -> Result<ConfluenceAttachment, ProviderError> {
        Ok(self
            .attachment_for_blog_response(blog_id, attachment_id, credential)
            .await?
            .value)
    }

    async fn attachment_for_blog_response(
        &self,
        blog_id: &str,
        attachment_id: &str,
        credential: &ExecutionCredential,
    ) -> Result<ConfluenceBackendResponse<ConfluenceAttachment>, ProviderError> {
        let response = self
            .backend
            .blog_attachments(blog_id, credential)
            .await
            .map_err(confluence_backend_error)?;
        let status = response.status;
        let duration_ms = response.duration_ms;
        let value = response
            .value
            .into_iter()
            .find(|attachment| attachment.id == attachment_id && attachment.page_id == blog_id)
            .ok_or_else(|| {
                ProviderError::deny(
                    ReasonCode::ScopeUnresolved,
                    "Confluence attachment did not belong to the authorized blog",
                )
            })?;
        Ok(ConfluenceBackendResponse {
            value,
            status,
            duration_ms,
        })
    }
}

fn invocation_credential(
    request: &ProviderInvocation,
) -> Result<&ExecutionCredential, ProviderError> {
    request.execution().static_credential().ok_or_else(|| {
        ProviderError::deny(
            ReasonCode::CredentialNotProvisioned,
            "selected credential material is unavailable",
        )
    })
}

fn lookup_credential(request: &AdmittedRequest) -> Result<&ExecutionCredential, ProviderError> {
    request.lookup_credential().ok_or_else(|| {
        ProviderError::deny(
            ReasonCode::CredentialNotProvisioned,
            "lookup credential material is unavailable",
        )
    })
}

fn required_lookup_credential(
    credential: Option<&ExecutionCredential>,
) -> Result<&ExecutionCredential, ProviderError> {
    credential.ok_or_else(|| {
        ProviderError::deny(
            ReasonCode::CredentialNotProvisioned,
            "lookup credential is not provisioned",
        )
    })
}

fn authorized_single_scope<'a>(
    scopes: &'a ResourceScopes,
    scope_type: &str,
) -> Result<&'a str, ProviderError> {
    let Some(values) = scopes.get(scope_type) else {
        return Err(ProviderError::deny(
            ReasonCode::ScopeUnresolved,
            format!("Confluence page view requires authorized {scope_type} scope"),
        ));
    };
    match values.as_slice() {
        [value] => Ok(value.as_str()),
        _ => Err(ProviderError::deny(
            ReasonCode::ScopeUnresolved,
            format!("Confluence page view requires exactly one authorized {scope_type} scope"),
        )),
    }
}

fn page_scope_requires_lookup(page_id: String) -> ProviderError {
    ProviderError::deny(
        ReasonCode::ScopeUnresolved,
        format!("Confluence page {page_id} scope requires lookup confirmation"),
    )
}

fn blog_scope_requires_lookup(blog_id: String) -> ProviderError {
    ProviderError::deny(
        ReasonCode::ScopeUnresolved,
        format!("Confluence blog {blog_id} scope requires lookup confirmation"),
    )
}

fn comment_scope_requires_lookup(comment_id: String) -> ProviderError {
    ProviderError::deny(
        ReasonCode::ScopeUnresolved,
        format!("Confluence comment {comment_id} scope requires lookup confirmation"),
    )
}

fn blog_scope_lookup_error(blog_id: &str, error: ConfluenceBackendError) -> ProviderError {
    match error {
        // A redirect, like an unusable response, leaves the blog
        // unconfirmed rather than failing the lookup.
        ConfluenceBackendError::Forbidden
        | ConfluenceBackendError::NotFound
        | ConfluenceBackendError::Redirected
        | ConfluenceBackendError::Protocol(_) => blog_scope_requires_lookup(blog_id.to_string()),
        other => confluence_backend_error(other),
    }
}

fn scopes_for_comment_container(container: &ConfluenceResolvedCommentContainer) -> ResourceScopes {
    let mut scopes = ResourceScopes::new();
    scopes.insert("space".to_string(), vec![container.space().to_string()]);
    scopes
}

fn require_current_page(page: &ConfluencePage) -> Result<(), ProviderError> {
    if page.status.as_deref() == Some("current") {
        Ok(())
    } else {
        Err(ProviderError::deny(
            ReasonCode::ScopeUnresolved,
            "Confluence page status is not current",
        ))
    }
}

fn require_current_comment(comment: &ConfluenceComment) -> Result<(), ProviderError> {
    if comment.status.as_deref() == Some("current") {
        Ok(())
    } else {
        Err(ProviderError::deny(
            ReasonCode::ScopeUnresolved,
            "Confluence comment status is not current",
        ))
    }
}

fn validate_comment_identity(
    comment: &ConfluenceComment,
    expected_id: &str,
    expected_kind: ConfluenceCommentKind,
) -> Result<(), ProviderError> {
    if comment.id != expected_id || comment.kind != expected_kind {
        return Err(ProviderError::error(
            ReasonCode::UpstreamProtocolFailed,
            "Confluence comment response did not match the requested comment",
        ));
    }
    let has_page = comment.page_id.is_some();
    let has_blog = comment.blog_id.is_some();
    if has_page && has_blog {
        return Err(ProviderError::error(
            ReasonCode::UpstreamProtocolFailed,
            "Confluence comment response identified multiple containers",
        ));
    }
    Ok(())
}

fn comment_container_id_for_action(
    comment: &ConfluenceComment,
    action: ConfluenceCommentAction,
) -> Result<Option<&str>, ProviderError> {
    match action.container_type {
        ConfluenceCommentContainerType::Page => {
            if comment.blog_id.is_some() {
                return Err(ProviderError::deny(
                    ReasonCode::ScopeUnresolved,
                    "Confluence page comment action resolved a blog comment",
                ));
            }
            Ok(comment.page_id.as_deref())
        }
        ConfluenceCommentContainerType::Blog => {
            if comment.page_id.is_some() {
                return Err(ProviderError::deny(
                    ReasonCode::ScopeUnresolved,
                    "Confluence blog comment action resolved a page comment",
                ));
            }
            Ok(comment.blog_id.as_deref())
        }
    }
}

#[derive(Debug)]
struct PageCreateInputs {
    space: String,
    title: String,
    content_format: String,
    content: Value,
    parent: Option<PageLocator>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PageCreateRawInputs {
    space: String,
    title: String,
    content_format: String,
    content: Value,
    parent_page_id: Option<String>,
    parent_url: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PageUpdateInputs {
    page_id: String,
    base_version: u64,
    title: Option<String>,
    content_format: String,
    content: Value,
}

#[derive(Debug)]
struct PageMoveInputs {
    page: PageLocator,
    position: ConfluencePageMovePosition,
    target: PageLocator,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfluencePageMovePosition {
    Before,
    After,
    Append,
}

impl ConfluencePageMovePosition {
    fn as_str(self) -> &'static str {
        match self {
            Self::Before => "before",
            Self::After => "after",
            Self::Append => "append",
        }
    }
}

impl TryFrom<&str> for ConfluencePageMovePosition {
    type Error = ProviderError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        match value {
            "before" => Ok(Self::Before),
            "after" => Ok(Self::After),
            "append" => Ok(Self::Append),
            _ => Err(ProviderError::deny(
                ReasonCode::InputInvalid,
                "confluence.page.move position must be before, after, or append",
            )),
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PageMoveRawInputs {
    page_id: Option<String>,
    url: Option<String>,
    position: String,
    target_page_id: Option<String>,
    target_url: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct AttachmentAddInputs {
    page_id: String,
    attachments: Vec<AttachmentInput>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct AttachmentInput {
    field: String,
    filename: String,
    content_type: String,
    size: u64,
    sha256: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct AttachmentDownloadInputs {
    page_id: String,
    attachment_id: String,
}

#[derive(Debug)]
struct AttachmentListInputs {
    locator: PageLocator,
    max_results: Option<u32>,
    next_page_token: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct AttachmentListRawInputs {
    page_id: Option<String>,
    url: Option<String>,
    max_results: Option<u32>,
    next_page_token: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct VerifyInputs {
    page_id: String,
    expect_version: Option<u64>,
    expect_title: Option<String>,
    expect_attachment_id: Option<String>,
}

#[derive(Debug)]
struct BlogViewInputs {
    locator: BlogLocator,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct BlogLocator {
    blog_id: String,
    candidate_space: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct BlogViewRawInputs {
    blog_id: Option<String>,
    url: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct BlogCreateInputs {
    space: String,
    title: String,
    content_format: String,
    content: Value,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct BlogUpdateInputs {
    blog_id: String,
    base_version: u64,
    title: Option<String>,
    content_format: String,
    content: Value,
    version_message: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct BlogAttachmentAddInputs {
    blog_id: String,
    attachments: Vec<AttachmentInput>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct BlogAttachmentDownloadInputs {
    blog_id: String,
    attachment_id: String,
}

#[derive(Debug)]
struct BlogAttachmentListInputs {
    locator: BlogLocator,
    max_results: Option<u32>,
    next_page_token: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct BlogAttachmentListRawInputs {
    blog_id: Option<String>,
    url: Option<String>,
    max_results: Option<u32>,
    next_page_token: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct BlogVerifyInputs {
    blog_id: String,
    expect_version: Option<u64>,
    expect_title: Option<String>,
    expect_attachment_id: Option<String>,
}

#[derive(Debug)]
struct PageDraftCreateInputs {
    space: String,
    title: String,
    content_format: String,
    content: Value,
    parent: Option<PageLocator>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PageDraftCreateRawInputs {
    space: String,
    title: String,
    content_format: String,
    content: Value,
    parent_page_id: Option<String>,
    parent_url: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PageDraftStageInputs {
    page_id: String,
    base_version: u64,
    title: Option<String>,
    content_format: String,
    content: Value,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PageDraftBodyFormatInputs {
    page_id: String,
    draft_handle: String,
    body_format: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PageDraftUpdateInputs {
    page_id: String,
    draft_handle: String,
    title: Option<String>,
    content_format: String,
    content: Value,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PageDraftDiscardInputs {
    page_id: String,
    draft_handle: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PageDraftVerifyInputs {
    page_id: String,
    draft_handle: String,
    expect_version: Option<u64>,
    expect_title: Option<String>,
    expect_attachment_id: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PageDraftAttachmentAddInputs {
    page_id: String,
    draft_handle: String,
    attachments: Vec<AttachmentInput>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PageDraftAttachmentListInputs {
    page_id: String,
    draft_handle: String,
    max_results: Option<u32>,
    next_page_token: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PageDraftAttachmentDownloadInputs {
    page_id: String,
    draft_handle: String,
    attachment_id: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct BlogDraftCreateInputs {
    space: String,
    title: String,
    content_format: String,
    content: Value,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct BlogDraftStageInputs {
    blog_id: String,
    base_version: u64,
    title: Option<String>,
    content_format: String,
    content: Value,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct BlogDraftBodyFormatInputs {
    blog_id: String,
    draft_handle: String,
    body_format: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct BlogDraftUpdateInputs {
    blog_id: String,
    draft_handle: String,
    title: Option<String>,
    content_format: String,
    content: Value,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct BlogDraftDiscardInputs {
    blog_id: String,
    draft_handle: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct BlogDraftVerifyInputs {
    blog_id: String,
    draft_handle: String,
    expect_version: Option<u64>,
    expect_title: Option<String>,
    expect_attachment_id: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct BlogDraftAttachmentAddInputs {
    blog_id: String,
    draft_handle: String,
    attachments: Vec<AttachmentInput>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct BlogDraftAttachmentListInputs {
    blog_id: String,
    draft_handle: String,
    max_results: Option<u32>,
    next_page_token: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct BlogDraftAttachmentDownloadInputs {
    blog_id: String,
    draft_handle: String,
    attachment_id: String,
}

#[derive(Debug, Clone)]
struct CommentListInputs {
    container_id: String,
    body_format: Option<String>,
    resolution_status: Option<String>,
    sort: Option<String>,
    max_results: Option<u32>,
    next_page_token: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PageCommentListRawInputs {
    page_id: String,
    body_format: Option<String>,
    resolution_status: Option<String>,
    sort: Option<String>,
    max_results: Option<u32>,
    next_page_token: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct BlogCommentListRawInputs {
    blog_id: String,
    body_format: Option<String>,
    resolution_status: Option<String>,
    sort: Option<String>,
    max_results: Option<u32>,
    next_page_token: Option<String>,
}

#[derive(Debug, Clone)]
struct CommentIdInputs {
    comment_id: String,
    body_format: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CommentIdRawInputs {
    comment_id: String,
    body_format: Option<String>,
}

#[derive(Debug, Clone)]
struct CommentReplyListInputs {
    comment_id: String,
    body_format: Option<String>,
    max_results: Option<u32>,
    next_page_token: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CommentReplyListRawInputs {
    comment_id: String,
    body_format: Option<String>,
    max_results: Option<u32>,
    next_page_token: Option<String>,
}

#[derive(Debug, Clone)]
struct CommentAddInputs {
    container_id: String,
    content_format: String,
    content: Value,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PageCommentAddRawInputs {
    page_id: String,
    content_format: String,
    content: Value,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct BlogCommentAddRawInputs {
    blog_id: String,
    content_format: String,
    content: Value,
}

#[derive(Debug, Clone)]
struct CommentReplyAddInputs {
    comment_id: String,
    content_format: String,
    content: Value,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CommentReplyAddRawInputs {
    comment_id: String,
    content_format: String,
    content: Value,
}

#[derive(Debug, Clone)]
struct CommentUpdateInputs {
    comment_id: String,
    base_version: u64,
    content_format: String,
    content: Value,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CommentUpdateRawInputs {
    comment_id: String,
    base_version: u64,
    content_format: String,
    content: Value,
}

#[derive(Debug, Clone)]
struct CommentDeleteInputs {
    comment_id: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CommentDeleteRawInputs {
    comment_id: String,
}

fn parse_page_create_inputs(
    inputs: &Value,
    config: &ConfluenceProviderConfig,
) -> Result<PageCreateInputs, ProviderError> {
    let parsed: PageCreateRawInputs = serde_json::from_value(inputs.clone()).map_err(|_| {
        ProviderError::deny(
            ReasonCode::InputInvalid,
            "confluence.page.create inputs are invalid",
        )
    })?;
    validate_space_key(&parsed.space)?;
    validate_page_title(&parsed.title)?;
    let parent = optional_page_locator(
        parsed.parent_page_id,
        parsed.parent_url,
        config,
        "confluence.page.create parent",
    )?;
    Ok(PageCreateInputs {
        space: parsed.space,
        title: parsed.title,
        content_format: parsed.content_format,
        content: parsed.content,
        parent,
    })
}

fn parse_page_update_inputs(inputs: &Value) -> Result<PageUpdateInputs, ProviderError> {
    let parsed: PageUpdateInputs = serde_json::from_value(inputs.clone()).map_err(|_| {
        ProviderError::deny(
            ReasonCode::InputInvalid,
            "confluence.page.update inputs are invalid",
        )
    })?;
    validate_page_id(&parsed.page_id)?;
    if parsed.base_version == 0 {
        return Err(ProviderError::deny(
            ReasonCode::InputInvalid,
            "confluence.page.update baseVersion must be greater than zero",
        ));
    }
    if let Some(title) = &parsed.title {
        validate_page_title(title)?;
    }
    Ok(parsed)
}

fn parse_page_move_inputs(
    inputs: &Value,
    config: &ConfluenceProviderConfig,
) -> Result<PageMoveInputs, ProviderError> {
    let parsed: PageMoveRawInputs = serde_json::from_value(inputs.clone()).map_err(|_| {
        ProviderError::deny(
            ReasonCode::InputInvalid,
            "confluence.page.move inputs are invalid",
        )
    })?;
    let page = required_page_locator(
        parsed.page_id,
        parsed.url,
        config,
        "confluence.page.move page",
    )?;
    let position = ConfluencePageMovePosition::try_from(parsed.position.as_str())?;
    let target = required_page_locator(
        parsed.target_page_id,
        parsed.target_url,
        config,
        "confluence.page.move target",
    )?;
    if page.page_id == target.page_id {
        return Err(ProviderError::deny(
            ReasonCode::InputInvalid,
            "confluence.page.move cannot target the page being moved",
        ));
    }
    Ok(PageMoveInputs {
        page,
        position,
        target,
    })
}

fn parse_attachment_add_inputs(inputs: &Value) -> Result<AttachmentAddInputs, ProviderError> {
    let parsed: AttachmentAddInputs = serde_json::from_value(inputs.clone()).map_err(|_| {
        ProviderError::deny(
            ReasonCode::InputInvalid,
            "confluence.attachment.add inputs are invalid",
        )
    })?;
    validate_page_id(&parsed.page_id)?;
    if parsed.attachments.is_empty() {
        return Err(ProviderError::deny(
            ReasonCode::InputInvalid,
            "confluence.attachment.add requires at least one attachment",
        ));
    }
    Ok(parsed)
}

fn parse_attachment_download_inputs(
    inputs: &Value,
) -> Result<AttachmentDownloadInputs, ProviderError> {
    let parsed: AttachmentDownloadInputs =
        serde_json::from_value(inputs.clone()).map_err(|_| {
            ProviderError::deny(
                ReasonCode::InputInvalid,
                "confluence.attachment.download inputs are invalid",
            )
        })?;
    validate_page_id(&parsed.page_id)?;
    validate_attachment_id(&parsed.attachment_id)?;
    Ok(parsed)
}

fn parse_attachment_list_inputs(
    inputs: &Value,
    config: &ConfluenceProviderConfig,
) -> Result<AttachmentListInputs, ProviderError> {
    let parsed: AttachmentListRawInputs = serde_json::from_value(inputs.clone()).map_err(|_| {
        ProviderError::deny(
            ReasonCode::InputInvalid,
            "confluence.attachment.list inputs are invalid",
        )
    })?;
    let locator = match (parsed.page_id, parsed.url) {
        (Some(page_id), None) => {
            let page_id = validate_page_id(&page_id)?;
            PageLocator {
                page_id,
                candidate_space: None,
            }
        }
        (None, Some(url)) => page_locator_from_url(&url, config)?,
        _ => {
            return Err(ProviderError::deny(
                ReasonCode::InputInvalid,
                "confluence.attachment.list requires exactly one of pageId or url",
            ));
        }
    };
    Ok(AttachmentListInputs {
        locator,
        max_results: parsed.max_results,
        next_page_token: parsed.next_page_token,
    })
}

fn parse_verify_inputs(inputs: &Value) -> Result<VerifyInputs, ProviderError> {
    let parsed: VerifyInputs = serde_json::from_value(inputs.clone()).map_err(|_| {
        ProviderError::deny(
            ReasonCode::InputInvalid,
            "confluence.verify inputs are invalid",
        )
    })?;
    validate_page_id(&parsed.page_id)?;
    if parsed.expect_version.is_none()
        && parsed.expect_title.is_none()
        && parsed.expect_attachment_id.is_none()
    {
        return Err(ProviderError::deny(
            ReasonCode::InputInvalid,
            "confluence.verify requires at least one expected value",
        ));
    }
    if parsed.expect_version == Some(0) {
        return Err(ProviderError::deny(
            ReasonCode::InputInvalid,
            "confluence.verify expectVersion must be greater than zero",
        ));
    }
    if let Some(attachment_id) = &parsed.expect_attachment_id {
        validate_attachment_id(attachment_id)?;
    }
    Ok(parsed)
}

fn parse_blog_view_inputs(
    inputs: &Value,
    config: &ConfluenceProviderConfig,
) -> Result<BlogViewInputs, ProviderError> {
    let parsed: BlogViewRawInputs = serde_json::from_value(inputs.clone()).map_err(|_| {
        ProviderError::deny(
            ReasonCode::InputInvalid,
            "confluence.blog.view inputs are invalid",
        )
    })?;
    let locator = match (parsed.blog_id, parsed.url) {
        (Some(blog_id), None) => BlogLocator {
            blog_id: validate_blog_id(&blog_id)?,
            candidate_space: None,
        },
        (None, Some(url)) => blog_locator_from_url(&url, config)?,
        _ => {
            return Err(ProviderError::deny(
                ReasonCode::InputInvalid,
                "confluence.blog.view requires exactly one of blogId or url",
            ));
        }
    };
    Ok(BlogViewInputs { locator })
}

fn parse_blog_create_inputs(inputs: &Value) -> Result<BlogCreateInputs, ProviderError> {
    let parsed: BlogCreateInputs = serde_json::from_value(inputs.clone()).map_err(|_| {
        ProviderError::deny(
            ReasonCode::InputInvalid,
            "confluence.blog.create inputs are invalid",
        )
    })?;
    validate_space_key(&parsed.space)?;
    validate_page_title(&parsed.title)?;
    Ok(parsed)
}

fn parse_blog_update_inputs(inputs: &Value) -> Result<BlogUpdateInputs, ProviderError> {
    let parsed: BlogUpdateInputs = serde_json::from_value(inputs.clone()).map_err(|_| {
        ProviderError::deny(
            ReasonCode::InputInvalid,
            "confluence.blog.update inputs are invalid",
        )
    })?;
    validate_blog_id(&parsed.blog_id)?;
    if parsed.base_version == 0 {
        return Err(ProviderError::deny(
            ReasonCode::InputInvalid,
            "confluence.blog.update baseVersion must be greater than zero",
        ));
    }
    if let Some(title) = &parsed.title {
        validate_page_title(title)?;
    }
    Ok(parsed)
}

fn parse_blog_attachment_add_inputs(
    inputs: &Value,
) -> Result<BlogAttachmentAddInputs, ProviderError> {
    let parsed: BlogAttachmentAddInputs = serde_json::from_value(inputs.clone()).map_err(|_| {
        ProviderError::deny(
            ReasonCode::InputInvalid,
            "confluence.blog.attachment.add inputs are invalid",
        )
    })?;
    validate_blog_id(&parsed.blog_id)?;
    if parsed.attachments.is_empty() {
        return Err(ProviderError::deny(
            ReasonCode::InputInvalid,
            "confluence.blog.attachment.add requires at least one attachment",
        ));
    }
    Ok(parsed)
}

fn parse_blog_attachment_download_inputs(
    inputs: &Value,
) -> Result<BlogAttachmentDownloadInputs, ProviderError> {
    let parsed: BlogAttachmentDownloadInputs =
        serde_json::from_value(inputs.clone()).map_err(|_| {
            ProviderError::deny(
                ReasonCode::InputInvalid,
                "confluence.blog.attachment.download inputs are invalid",
            )
        })?;
    validate_blog_id(&parsed.blog_id)?;
    validate_attachment_id(&parsed.attachment_id)?;
    Ok(parsed)
}

fn parse_blog_attachment_list_inputs(
    inputs: &Value,
    config: &ConfluenceProviderConfig,
) -> Result<BlogAttachmentListInputs, ProviderError> {
    let parsed: BlogAttachmentListRawInputs =
        serde_json::from_value(inputs.clone()).map_err(|_| {
            ProviderError::deny(
                ReasonCode::InputInvalid,
                "confluence.blog.attachment.list inputs are invalid",
            )
        })?;
    let locator = match (parsed.blog_id, parsed.url) {
        (Some(blog_id), None) => BlogLocator {
            blog_id: validate_blog_id(&blog_id)?,
            candidate_space: None,
        },
        (None, Some(url)) => blog_locator_from_url(&url, config)?,
        _ => {
            return Err(ProviderError::deny(
                ReasonCode::InputInvalid,
                "confluence.blog.attachment.list requires exactly one of blogId or url",
            ));
        }
    };
    Ok(BlogAttachmentListInputs {
        locator,
        max_results: parsed.max_results,
        next_page_token: parsed.next_page_token,
    })
}

fn parse_blog_verify_inputs(inputs: &Value) -> Result<BlogVerifyInputs, ProviderError> {
    let parsed: BlogVerifyInputs = serde_json::from_value(inputs.clone()).map_err(|_| {
        ProviderError::deny(
            ReasonCode::InputInvalid,
            "confluence.blog.verify inputs are invalid",
        )
    })?;
    validate_blog_id(&parsed.blog_id)?;
    if parsed.expect_version.is_none()
        && parsed.expect_title.is_none()
        && parsed.expect_attachment_id.is_none()
    {
        return Err(ProviderError::deny(
            ReasonCode::InputInvalid,
            "confluence.blog.verify requires at least one expected value",
        ));
    }
    if parsed.expect_version == Some(0) {
        return Err(ProviderError::deny(
            ReasonCode::InputInvalid,
            "confluence.blog.verify expectVersion must be greater than zero",
        ));
    }
    if let Some(attachment_id) = &parsed.expect_attachment_id {
        validate_attachment_id(attachment_id)?;
    }
    Ok(parsed)
}

fn parse_page_draft_create_inputs(
    inputs: &Value,
    config: &ConfluenceProviderConfig,
) -> Result<PageDraftCreateInputs, ProviderError> {
    let parsed: PageDraftCreateRawInputs =
        serde_json::from_value(inputs.clone()).map_err(|_| {
            ProviderError::deny(
                ReasonCode::InputInvalid,
                "confluence.page.draft.create inputs are invalid",
            )
        })?;
    validate_space_key(&parsed.space)?;
    validate_page_title(&parsed.title)?;
    let parent = optional_page_locator(
        parsed.parent_page_id,
        parsed.parent_url,
        config,
        "confluence.page.draft.create parent",
    )?;
    Ok(PageDraftCreateInputs {
        space: parsed.space,
        title: parsed.title,
        content_format: parsed.content_format,
        content: parsed.content,
        parent,
    })
}

fn parse_page_draft_stage_inputs(inputs: &Value) -> Result<PageDraftStageInputs, ProviderError> {
    let parsed: PageDraftStageInputs = serde_json::from_value(inputs.clone()).map_err(|_| {
        ProviderError::deny(
            ReasonCode::InputInvalid,
            "confluence.page.draft.stage inputs are invalid",
        )
    })?;
    validate_page_id(&parsed.page_id)?;
    if parsed.base_version == 0 {
        return Err(ProviderError::deny(
            ReasonCode::InputInvalid,
            "confluence.page.draft.stage baseVersion must be greater than zero",
        ));
    }
    if let Some(title) = &parsed.title {
        validate_page_title(title)?;
    }
    Ok(parsed)
}

fn parse_page_draft_body_format_inputs(
    action: &str,
    inputs: &Value,
) -> Result<PageDraftBodyFormatInputs, ProviderError> {
    let parsed: PageDraftBodyFormatInputs =
        serde_json::from_value(inputs.clone()).map_err(|_| {
            ProviderError::deny(
                ReasonCode::InputInvalid,
                format!("confluence.{action} inputs are invalid"),
            )
        })?;
    validate_page_id(&parsed.page_id)?;
    validate_draft_handle_input(&parsed.draft_handle)?;
    validate_page_draft_body_format(&parsed.body_format)?;
    Ok(parsed)
}

fn parse_page_draft_update_inputs(inputs: &Value) -> Result<PageDraftUpdateInputs, ProviderError> {
    let parsed: PageDraftUpdateInputs = serde_json::from_value(inputs.clone()).map_err(|_| {
        ProviderError::deny(
            ReasonCode::InputInvalid,
            "confluence.page.draft.update inputs are invalid",
        )
    })?;
    validate_page_id(&parsed.page_id)?;
    validate_draft_handle_input(&parsed.draft_handle)?;
    if let Some(title) = &parsed.title {
        validate_page_title(title)?;
    }
    Ok(parsed)
}

fn parse_page_draft_discard_inputs(
    inputs: &Value,
) -> Result<PageDraftDiscardInputs, ProviderError> {
    let parsed: PageDraftDiscardInputs = serde_json::from_value(inputs.clone()).map_err(|_| {
        ProviderError::deny(
            ReasonCode::InputInvalid,
            "confluence.page.draft.discard inputs are invalid",
        )
    })?;
    validate_page_id(&parsed.page_id)?;
    validate_draft_handle_input(&parsed.draft_handle)?;
    Ok(parsed)
}

fn parse_page_draft_verify_inputs(inputs: &Value) -> Result<PageDraftVerifyInputs, ProviderError> {
    let parsed: PageDraftVerifyInputs = serde_json::from_value(inputs.clone()).map_err(|_| {
        ProviderError::deny(
            ReasonCode::InputInvalid,
            "confluence.page.draft.verify inputs are invalid",
        )
    })?;
    validate_page_id(&parsed.page_id)?;
    validate_draft_handle_input(&parsed.draft_handle)?;
    validate_draft_verify_expectations(
        parsed.expect_version,
        parsed.expect_title.as_deref(),
        parsed.expect_attachment_id.as_deref(),
        "confluence.page.draft.verify",
    )?;
    Ok(parsed)
}

fn parse_page_draft_attachment_add_inputs(
    inputs: &Value,
) -> Result<PageDraftAttachmentAddInputs, ProviderError> {
    let parsed: PageDraftAttachmentAddInputs =
        serde_json::from_value(inputs.clone()).map_err(|_| {
            ProviderError::deny(
                ReasonCode::InputInvalid,
                "confluence.page.draft.attachment.add inputs are invalid",
            )
        })?;
    validate_page_id(&parsed.page_id)?;
    validate_draft_handle_input(&parsed.draft_handle)?;
    if parsed.attachments.is_empty() {
        return Err(ProviderError::deny(
            ReasonCode::InputInvalid,
            "confluence.page.draft.attachment.add requires at least one attachment",
        ));
    }
    Ok(parsed)
}

fn parse_page_draft_attachment_list_inputs(
    inputs: &Value,
) -> Result<PageDraftAttachmentListInputs, ProviderError> {
    let parsed: PageDraftAttachmentListInputs =
        serde_json::from_value(inputs.clone()).map_err(|_| {
            ProviderError::deny(
                ReasonCode::InputInvalid,
                "confluence.page.draft.attachment.list inputs are invalid",
            )
        })?;
    validate_page_id(&parsed.page_id)?;
    validate_draft_handle_input(&parsed.draft_handle)?;
    Ok(parsed)
}

fn parse_page_draft_attachment_download_inputs(
    inputs: &Value,
) -> Result<PageDraftAttachmentDownloadInputs, ProviderError> {
    let parsed: PageDraftAttachmentDownloadInputs = serde_json::from_value(inputs.clone())
        .map_err(|_| {
            ProviderError::deny(
                ReasonCode::InputInvalid,
                "confluence.page.draft.attachment.download inputs are invalid",
            )
        })?;
    validate_page_id(&parsed.page_id)?;
    validate_draft_handle_input(&parsed.draft_handle)?;
    validate_attachment_id(&parsed.attachment_id)?;
    Ok(parsed)
}

fn parse_blog_draft_create_inputs(inputs: &Value) -> Result<BlogDraftCreateInputs, ProviderError> {
    let parsed: BlogDraftCreateInputs = serde_json::from_value(inputs.clone()).map_err(|_| {
        ProviderError::deny(
            ReasonCode::InputInvalid,
            "confluence.blog.draft.create inputs are invalid",
        )
    })?;
    validate_space_key(&parsed.space)?;
    validate_page_title(&parsed.title)?;
    Ok(parsed)
}

fn parse_blog_draft_stage_inputs(inputs: &Value) -> Result<BlogDraftStageInputs, ProviderError> {
    let parsed: BlogDraftStageInputs = serde_json::from_value(inputs.clone()).map_err(|_| {
        ProviderError::deny(
            ReasonCode::InputInvalid,
            "confluence.blog.draft.stage inputs are invalid",
        )
    })?;
    validate_blog_id(&parsed.blog_id)?;
    if parsed.base_version == 0 {
        return Err(ProviderError::deny(
            ReasonCode::InputInvalid,
            "confluence.blog.draft.stage baseVersion must be greater than zero",
        ));
    }
    if let Some(title) = &parsed.title {
        validate_page_title(title)?;
    }
    Ok(parsed)
}

fn parse_blog_draft_body_format_inputs(
    action: &str,
    inputs: &Value,
) -> Result<BlogDraftBodyFormatInputs, ProviderError> {
    let parsed: BlogDraftBodyFormatInputs =
        serde_json::from_value(inputs.clone()).map_err(|_| {
            ProviderError::deny(
                ReasonCode::InputInvalid,
                format!("confluence.{action} inputs are invalid"),
            )
        })?;
    validate_blog_id(&parsed.blog_id)?;
    validate_draft_handle_input(&parsed.draft_handle)?;
    validate_blog_body_format(&parsed.body_format)?;
    Ok(parsed)
}

fn parse_blog_draft_update_inputs(inputs: &Value) -> Result<BlogDraftUpdateInputs, ProviderError> {
    let parsed: BlogDraftUpdateInputs = serde_json::from_value(inputs.clone()).map_err(|_| {
        ProviderError::deny(
            ReasonCode::InputInvalid,
            "confluence.blog.draft.update inputs are invalid",
        )
    })?;
    validate_blog_id(&parsed.blog_id)?;
    validate_draft_handle_input(&parsed.draft_handle)?;
    if let Some(title) = &parsed.title {
        validate_page_title(title)?;
    }
    Ok(parsed)
}

fn parse_blog_draft_discard_inputs(
    inputs: &Value,
) -> Result<BlogDraftDiscardInputs, ProviderError> {
    let parsed: BlogDraftDiscardInputs = serde_json::from_value(inputs.clone()).map_err(|_| {
        ProviderError::deny(
            ReasonCode::InputInvalid,
            "confluence.blog.draft.discard inputs are invalid",
        )
    })?;
    validate_blog_id(&parsed.blog_id)?;
    validate_draft_handle_input(&parsed.draft_handle)?;
    Ok(parsed)
}

fn parse_blog_draft_verify_inputs(inputs: &Value) -> Result<BlogDraftVerifyInputs, ProviderError> {
    let parsed: BlogDraftVerifyInputs = serde_json::from_value(inputs.clone()).map_err(|_| {
        ProviderError::deny(
            ReasonCode::InputInvalid,
            "confluence.blog.draft.verify inputs are invalid",
        )
    })?;
    validate_blog_id(&parsed.blog_id)?;
    validate_draft_handle_input(&parsed.draft_handle)?;
    validate_draft_verify_expectations(
        parsed.expect_version,
        parsed.expect_title.as_deref(),
        parsed.expect_attachment_id.as_deref(),
        "confluence.blog.draft.verify",
    )?;
    Ok(parsed)
}

fn parse_blog_draft_attachment_add_inputs(
    inputs: &Value,
) -> Result<BlogDraftAttachmentAddInputs, ProviderError> {
    let parsed: BlogDraftAttachmentAddInputs =
        serde_json::from_value(inputs.clone()).map_err(|_| {
            ProviderError::deny(
                ReasonCode::InputInvalid,
                "confluence.blog.draft.attachment.add inputs are invalid",
            )
        })?;
    validate_blog_id(&parsed.blog_id)?;
    validate_draft_handle_input(&parsed.draft_handle)?;
    if parsed.attachments.is_empty() {
        return Err(ProviderError::deny(
            ReasonCode::InputInvalid,
            "confluence.blog.draft.attachment.add requires at least one attachment",
        ));
    }
    Ok(parsed)
}

fn parse_blog_draft_attachment_list_inputs(
    inputs: &Value,
) -> Result<BlogDraftAttachmentListInputs, ProviderError> {
    let parsed: BlogDraftAttachmentListInputs =
        serde_json::from_value(inputs.clone()).map_err(|_| {
            ProviderError::deny(
                ReasonCode::InputInvalid,
                "confluence.blog.draft.attachment.list inputs are invalid",
            )
        })?;
    validate_blog_id(&parsed.blog_id)?;
    validate_draft_handle_input(&parsed.draft_handle)?;
    Ok(parsed)
}

fn parse_blog_draft_attachment_download_inputs(
    inputs: &Value,
) -> Result<BlogDraftAttachmentDownloadInputs, ProviderError> {
    let parsed: BlogDraftAttachmentDownloadInputs = serde_json::from_value(inputs.clone())
        .map_err(|_| {
            ProviderError::deny(
                ReasonCode::InputInvalid,
                "confluence.blog.draft.attachment.download inputs are invalid",
            )
        })?;
    validate_blog_id(&parsed.blog_id)?;
    validate_draft_handle_input(&parsed.draft_handle)?;
    validate_attachment_id(&parsed.attachment_id)?;
    Ok(parsed)
}

fn parse_comment_list_inputs(
    action: ConfluenceCommentAction,
    inputs: &Value,
) -> Result<CommentListInputs, ProviderError> {
    let (container_id, body_format, resolution_status, sort, max_results, next_page_token) =
        match action.container_type {
            ConfluenceCommentContainerType::Page => {
                let parsed: PageCommentListRawInputs = serde_json::from_value(inputs.clone())
                    .map_err(|_| {
                        ProviderError::deny(
                            ReasonCode::InputInvalid,
                            "confluence page comment list inputs are invalid",
                        )
                    })?;
                (
                    validate_page_id(&parsed.page_id)?,
                    parsed.body_format,
                    parsed.resolution_status,
                    parsed.sort,
                    parsed.max_results,
                    parsed.next_page_token,
                )
            }
            ConfluenceCommentContainerType::Blog => {
                let parsed: BlogCommentListRawInputs = serde_json::from_value(inputs.clone())
                    .map_err(|_| {
                        ProviderError::deny(
                            ReasonCode::InputInvalid,
                            "confluence blog comment list inputs are invalid",
                        )
                    })?;
                (
                    validate_blog_id(&parsed.blog_id)?,
                    parsed.body_format,
                    parsed.resolution_status,
                    parsed.sort,
                    parsed.max_results,
                    parsed.next_page_token,
                )
            }
        };
    if action.kind != ConfluenceCommentKind::Inline && resolution_status.is_some() {
        return Err(ProviderError::deny(
            ReasonCode::InputInvalid,
            "resolutionStatus is only supported for Confluence inline comment lists",
        ));
    }
    if let Some(format) = &body_format {
        validate_comment_read_body_format(format)?;
    }
    if let Some(status) = &resolution_status {
        validate_comment_resolution_status(status)?;
    }
    if let Some(sort) = &sort {
        validate_comment_sort(sort)?;
    }
    Ok(CommentListInputs {
        container_id,
        body_format,
        resolution_status,
        sort,
        max_results,
        next_page_token,
    })
}

fn parse_comment_id_inputs(inputs: &Value) -> Result<CommentIdInputs, ProviderError> {
    let parsed: CommentIdRawInputs = serde_json::from_value(inputs.clone()).map_err(|_| {
        ProviderError::deny(
            ReasonCode::InputInvalid,
            "confluence comment inputs are invalid",
        )
    })?;
    if let Some(format) = &parsed.body_format {
        validate_comment_read_body_format(format)?;
    }
    Ok(CommentIdInputs {
        comment_id: validate_comment_id(&parsed.comment_id)?,
        body_format: parsed.body_format,
    })
}

fn parse_comment_reply_list_inputs(
    inputs: &Value,
) -> Result<CommentReplyListInputs, ProviderError> {
    let parsed: CommentReplyListRawInputs =
        serde_json::from_value(inputs.clone()).map_err(|_| {
            ProviderError::deny(
                ReasonCode::InputInvalid,
                "confluence comment reply list inputs are invalid",
            )
        })?;
    if let Some(format) = &parsed.body_format {
        validate_comment_read_body_format(format)?;
    }
    Ok(CommentReplyListInputs {
        comment_id: validate_comment_id(&parsed.comment_id)?,
        body_format: parsed.body_format,
        max_results: parsed.max_results,
        next_page_token: parsed.next_page_token,
    })
}

fn parse_comment_add_inputs(
    action: ConfluenceCommentAction,
    inputs: &Value,
) -> Result<CommentAddInputs, ProviderError> {
    if action.kind != ConfluenceCommentKind::Footer
        || action.operation != ConfluenceCommentOperation::Add
    {
        return Err(ProviderError::deny(
            ReasonCode::ServiceActionDenied,
            "Confluence action is not supported",
        ));
    }
    let (container_id, content_format, content) = match action.container_type {
        ConfluenceCommentContainerType::Page => {
            let parsed: PageCommentAddRawInputs =
                serde_json::from_value(inputs.clone()).map_err(|_| {
                    ProviderError::deny(
                        ReasonCode::InputInvalid,
                        "confluence page footer comment add inputs are invalid",
                    )
                })?;
            (
                validate_page_id(&parsed.page_id)?,
                parsed.content_format,
                parsed.content,
            )
        }
        ConfluenceCommentContainerType::Blog => {
            let parsed: BlogCommentAddRawInputs =
                serde_json::from_value(inputs.clone()).map_err(|_| {
                    ProviderError::deny(
                        ReasonCode::InputInvalid,
                        "confluence blog footer comment add inputs are invalid",
                    )
                })?;
            (
                validate_blog_id(&parsed.blog_id)?,
                parsed.content_format,
                parsed.content,
            )
        }
    };
    Ok(CommentAddInputs {
        container_id,
        content_format,
        content,
    })
}

fn parse_comment_reply_add_inputs(inputs: &Value) -> Result<CommentReplyAddInputs, ProviderError> {
    let parsed: CommentReplyAddRawInputs =
        serde_json::from_value(inputs.clone()).map_err(|_| {
            ProviderError::deny(
                ReasonCode::InputInvalid,
                "confluence comment reply inputs are invalid",
            )
        })?;
    Ok(CommentReplyAddInputs {
        comment_id: validate_comment_id(&parsed.comment_id)?,
        content_format: parsed.content_format,
        content: parsed.content,
    })
}

fn parse_comment_update_inputs(inputs: &Value) -> Result<CommentUpdateInputs, ProviderError> {
    let parsed: CommentUpdateRawInputs = serde_json::from_value(inputs.clone()).map_err(|_| {
        ProviderError::deny(
            ReasonCode::InputInvalid,
            "confluence comment update inputs are invalid",
        )
    })?;
    if parsed.base_version == 0 {
        return Err(ProviderError::deny(
            ReasonCode::InputInvalid,
            "confluence comment update baseVersion must be greater than zero",
        ));
    }
    if parsed.base_version == u64::MAX {
        return Err(ProviderError::deny(
            ReasonCode::InputInvalid,
            "confluence comment update baseVersion is too large",
        ));
    }
    Ok(CommentUpdateInputs {
        comment_id: validate_comment_id(&parsed.comment_id)?,
        base_version: parsed.base_version,
        content_format: parsed.content_format,
        content: parsed.content,
    })
}

fn parse_comment_delete_inputs(inputs: &Value) -> Result<CommentDeleteInputs, ProviderError> {
    let parsed: CommentDeleteRawInputs = serde_json::from_value(inputs.clone()).map_err(|_| {
        ProviderError::deny(
            ReasonCode::InputInvalid,
            "confluence comment delete inputs are invalid",
        )
    })?;
    Ok(CommentDeleteInputs {
        comment_id: validate_comment_id(&parsed.comment_id)?,
    })
}

#[derive(Debug, Clone)]
struct PageLocator {
    page_id: String,
    candidate_space: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PageViewInputs {
    page_id: Option<String>,
    url: Option<String>,
}

fn page_locator_from_inputs(
    inputs: &Value,
    config: &ConfluenceProviderConfig,
) -> Result<PageLocator, ProviderError> {
    let inputs: PageViewInputs = serde_json::from_value(inputs.clone()).map_err(|_| {
        ProviderError::deny(
            ReasonCode::InputInvalid,
            "confluence.page.view inputs are invalid",
        )
    })?;
    required_page_locator(inputs.page_id, inputs.url, config, "confluence.page.view")
}

fn required_page_locator(
    page_id: Option<String>,
    url: Option<String>,
    config: &ConfluenceProviderConfig,
    context: &str,
) -> Result<PageLocator, ProviderError> {
    match (page_id, url) {
        (Some(page_id), None) => {
            let page_id = validate_page_id(&page_id)?;
            Ok(PageLocator {
                page_id,
                candidate_space: None,
            })
        }
        (None, Some(url)) => page_locator_from_url(&url, config),
        _ => Err(ProviderError::deny(
            ReasonCode::InputInvalid,
            format!("{context} requires exactly one page ID or URL locator"),
        )),
    }
}

fn optional_page_locator(
    page_id: Option<String>,
    url: Option<String>,
    config: &ConfluenceProviderConfig,
    context: &str,
) -> Result<Option<PageLocator>, ProviderError> {
    match (&page_id, &url) {
        (None, None) => Ok(None),
        (Some(_), Some(_)) => Err(ProviderError::deny(
            ReasonCode::InputInvalid,
            format!("{context} accepts only one page ID or URL locator"),
        )),
        _ => required_page_locator(page_id, url, config, context).map(Some),
    }
}

fn page_locator_from_url(
    raw: &str,
    config: &ConfluenceProviderConfig,
) -> Result<PageLocator, ProviderError> {
    let raw = raw.trim();
    if raw_url_has_explicit_authority_port(raw) {
        return Err(ProviderError::deny(
            ReasonCode::LocatorInvalid,
            "Confluence page URL tenant is not configured",
        ));
    }
    let url = Url::parse(raw).map_err(|_| {
        ProviderError::deny(ReasonCode::LocatorInvalid, "Confluence page URL is invalid")
    })?;
    if !confluence_url_has_exact_authority(&url, &config.tenant_host) {
        return Err(ProviderError::deny(
            ReasonCode::LocatorInvalid,
            "Confluence page URL tenant is not configured",
        ));
    }
    if url.fragment().is_some() {
        return Err(ProviderError::deny(
            ReasonCode::LocatorInvalid,
            "Confluence page URL must not include a fragment",
        ));
    }
    let segments = url
        .path_segments()
        .ok_or_else(|| {
            ProviderError::deny(
                ReasonCode::LocatorInvalid,
                "Confluence page URL path is invalid",
            )
        })?
        .collect::<Vec<_>>();
    if segments.len() >= 5
        && segments[0] == "wiki"
        && segments[1] == "spaces"
        && segments[3] == "pages"
    {
        if url.query().is_some() {
            return Err(ProviderError::deny(
                ReasonCode::LocatorInvalid,
                "Confluence page URL must not include query parameters",
            ));
        }
        return Ok(PageLocator {
            candidate_space: Some(validate_space_key(segments[2])?),
            page_id: validate_page_id(segments[4])?,
        });
    }
    if segments.as_slice() == ["wiki", "pages", "viewpage.action"] {
        let pairs = url.query_pairs().collect::<Vec<_>>();
        if pairs.len() != 1 || pairs[0].0 != "pageId" {
            return Err(ProviderError::deny(
                ReasonCode::LocatorInvalid,
                "Confluence viewpage URL must include only pageId",
            ));
        }
        return Ok(PageLocator {
            page_id: validate_page_id(&pairs[0].1)?,
            candidate_space: None,
        });
    }
    Err(ProviderError::deny(
        ReasonCode::LocatorInvalid,
        "Confluence page URL path is invalid",
    ))
}

fn blog_locator_from_url(
    raw: &str,
    config: &ConfluenceProviderConfig,
) -> Result<BlogLocator, ProviderError> {
    let raw = raw.trim();
    if raw_url_has_explicit_authority_port(raw) {
        return Err(ProviderError::deny(
            ReasonCode::LocatorInvalid,
            "Confluence blog URL tenant is not configured",
        ));
    }
    let url = Url::parse(raw).map_err(|_| {
        ProviderError::deny(ReasonCode::LocatorInvalid, "Confluence blog URL is invalid")
    })?;
    if !confluence_url_has_exact_authority(&url, &config.tenant_host) {
        return Err(ProviderError::deny(
            ReasonCode::LocatorInvalid,
            "Confluence blog URL tenant is not configured",
        ));
    }
    if url.fragment().is_some() {
        return Err(ProviderError::deny(
            ReasonCode::LocatorInvalid,
            "Confluence blog URL must not include a fragment",
        ));
    }
    let segments = url
        .path_segments()
        .ok_or_else(|| {
            ProviderError::deny(
                ReasonCode::LocatorInvalid,
                "Confluence blog URL path is invalid",
            )
        })?
        .collect::<Vec<_>>();
    if segments.as_slice() == ["wiki", "pages", "viewpage.action"] {
        let pairs = url.query_pairs().collect::<Vec<_>>();
        if pairs.len() != 1 || pairs[0].0 != "pageId" {
            return Err(ProviderError::deny(
                ReasonCode::LocatorInvalid,
                "Confluence blog viewpage URL must include only pageId",
            ));
        }
        let blog_id = pairs[0].1.as_ref();
        if !is_blog_id(blog_id) {
            return Err(ProviderError::deny(
                ReasonCode::LocatorInvalid,
                "Confluence blog URL must carry a numeric content ID",
            ));
        }
        return Ok(BlogLocator {
            blog_id: blog_id.to_string(),
            candidate_space: None,
        });
    }
    if segments.len() >= 5
        && segments[0] == "wiki"
        && segments[1] == "spaces"
        && segments[3] == "blog"
    {
        if url.query().is_some() {
            return Err(ProviderError::deny(
                ReasonCode::LocatorInvalid,
                "Confluence blog URL must not include query parameters",
            ));
        }
        let space = validate_space_key(segments[2])?;
        let blog_id = blog_id_from_modern_blog_segments(&segments[4..])?;
        return Ok(BlogLocator {
            blog_id,
            candidate_space: Some(space),
        });
    }
    Err(ProviderError::deny(
        ReasonCode::LocatorInvalid,
        "Confluence blog URL must carry a numeric content ID",
    ))
}

fn blog_id_from_modern_blog_segments(tail: &[&str]) -> Result<String, ProviderError> {
    let tail = modern_blog_tail_after_date(tail).map_err(|_| {
        ProviderError::deny(
            ReasonCode::LocatorInvalid,
            "Confluence blog URL date prefix is invalid",
        )
    })?;
    let Some(blog_id) = tail.first() else {
        return Err(ProviderError::deny(
            ReasonCode::LocatorInvalid,
            "Confluence blog URL must carry a numeric content ID",
        ));
    };
    if !is_blog_id(blog_id) {
        return Err(ProviderError::deny(
            ReasonCode::LocatorInvalid,
            "Confluence blog URL content ID must be the first path segment after the date",
        ));
    }
    Ok((*blog_id).to_string())
}

fn validate_blog_locator_space(
    locator: &BlogLocator,
    authoritative_space: &str,
) -> Result<(), ProviderError> {
    if let Some(candidate_space) = &locator.candidate_space
        && candidate_space != authoritative_space
    {
        return Err(ProviderError::deny(
            ReasonCode::LocatorInvalid,
            "Confluence blog URL space does not match the resolved blog",
        ));
    }
    Ok(())
}

fn validate_page_locator_space(
    locator: &PageLocator,
    authoritative_space: &str,
) -> Result<(), ProviderError> {
    if let Some(candidate_space) = &locator.candidate_space
        && candidate_space != authoritative_space
    {
        return Err(ProviderError::deny(
            ReasonCode::LocatorInvalid,
            "Confluence page URL space does not match the resolved page",
        ));
    }
    Ok(())
}

fn page_view_result(
    page: &ConfluencePage,
    allowed_formats: &[String],
    config: &ConfluenceProviderConfig,
) -> Result<Value, ProviderError> {
    let mut body = serde_json::Map::new();
    for format in allowed_formats {
        if let Some(value) = page.bodies.get(format) {
            body.insert(
                format.clone(),
                json!({
                    "representation": format,
                    "value": value,
                }),
            );
        }
    }
    let (web_url, space_url) = page_browser_urls(page, config)?;
    Ok(json!({
        "id": page.id,
        "title": page.title,
        "space": page.space,
        "spaceUrl": space_url,
        "webUrl": web_url,
        "version": page.version,
        "createdAt": page.created_at,
        "updatedAt": page.updated_at,
        "createdBy": page.created_by,
        "updatedBy": page.updated_by,
        "body": body,
    }))
}

fn enforce_page_body_sizes(
    page: &ConfluencePage,
    allowed_formats: &[String],
    byte_cap: u64,
) -> Result<(), ProviderError> {
    for format in allowed_formats {
        let Some(value) = page.bodies.get(format) else {
            continue;
        };
        if value.len() as u64 > byte_cap {
            return Err(ProviderError::error(
                ReasonCode::UpstreamProtocolFailed,
                "Confluence page body exceeded the configured byte cap",
            ));
        }
    }
    Ok(())
}

fn confluence_write_formats(
    target: ConfluenceWriteTarget,
    config: &ConfluenceProviderConfig,
) -> Vec<String> {
    let native = match target {
        ConfluenceWriteTarget::CurrentPage => &config.content.page_formats,
        ConfluenceWriteTarget::PageDraft => {
            return vec![
                "storage".to_string(),
                "markdown".to_string(),
                "plain_text".to_string(),
            ];
        }
        ConfluenceWriteTarget::Blog => &config.content.blog_formats,
        ConfluenceWriteTarget::Comment => &config.content.comment_formats,
    };
    let mut formats = Vec::new();
    if native.iter().any(|format| format == "storage") {
        formats.push("storage".to_string());
    }
    if target == ConfluenceWriteTarget::CurrentPage
        && native.iter().any(|format| format == "atlas_doc_format")
    {
        formats.push("atlas_doc_format".to_string());
    }
    if native.iter().any(|format| format == "storage") {
        formats.push("markdown".to_string());
        formats.push("plain_text".to_string());
    }
    formats
}

fn required_confluence_content_schema(mut schema: Value, formats: &[String]) -> Value {
    let object = schema
        .as_object_mut()
        .expect("Confluence action schema is an object");
    let required = object
        .get_mut("required")
        .and_then(Value::as_array_mut)
        .expect("Confluence write schema has required fields");
    required.push(json!("contentFormat"));
    required.push(json!("content"));
    let properties = object
        .get_mut("properties")
        .and_then(Value::as_object_mut)
        .expect("Confluence write schema has properties");
    properties.insert(
        "contentFormat".to_string(),
        json!({ "type": "string", "enum": formats }),
    );
    properties.insert("content".to_string(), json!({}));
    let conditions = formats
        .iter()
        .map(|format| {
            json!({
                "if": {
                    "properties": { "contentFormat": { "const": format } },
                    "required": ["contentFormat"]
                },
                "then": {
                    "properties": {
                        "content": if format == "atlas_doc_format" {
                            json!({ "type": "object" })
                        } else {
                            json!({ "type": "string" })
                        }
                    }
                }
            })
        })
        .collect::<Vec<_>>();
    object.insert("allOf".to_string(), Value::Array(conditions));
    schema
}

fn map_confluence_content_write_error(error: ContentWriteError) -> ProviderError {
    match error {
        ContentWriteError::SizeDenied => ProviderError::deny(
            ReasonCode::BodySizeDenied,
            "converted Confluence content exceeded the configured byte cap",
        ),
        ContentWriteError::ComplexityDenied | ContentWriteError::Malformed => ProviderError::deny(
            ReasonCode::BodyMalformed,
            "Confluence content could not be converted safely",
        ),
    }
}

fn validate_generated_confluence_storage(
    storage: &str,
    allow_attribution_markers: bool,
) -> Result<(), ProviderError> {
    let mut rest = storage;
    let mut open = Vec::<String>::new();
    while let Some(tag_start) = rest.find('<') {
        let text = &rest[..tag_start];
        if text
            .chars()
            .any(|ch| ch == '\0' || ch.is_control() && !matches!(ch, '\n' | '\r' | '\t'))
        {
            return Err(generated_storage_malformed());
        }
        rest = &rest[tag_start..];
        if rest.starts_with(CONFLUENCE_ATTRIBUTION_START_MARKER) {
            if !allow_attribution_markers {
                return Err(generated_storage_malformed());
            }
            rest = &rest[CONFLUENCE_ATTRIBUTION_START_MARKER.len()..];
            continue;
        }
        if rest.starts_with(CONFLUENCE_ATTRIBUTION_END_MARKER) {
            if !allow_attribution_markers {
                return Err(generated_storage_malformed());
            }
            rest = &rest[CONFLUENCE_ATTRIBUTION_END_MARKER.len()..];
            continue;
        }
        let end = rest.find('>').ok_or_else(generated_storage_malformed)?;
        let token = &rest[1..end];
        rest = &rest[end + 1..];
        if matches!(token, "hr /" | "br /") {
            continue;
        }
        if let Some(name) = token.strip_prefix('/') {
            if open.pop().as_deref() != Some(name) {
                return Err(generated_storage_malformed());
            }
            continue;
        }
        let name = if let Some(start) = token.strip_prefix("ol start=\"") {
            let number = start
                .strip_suffix('"')
                .ok_or_else(generated_storage_malformed)?;
            number
                .parse::<u64>()
                .map_err(|_| generated_storage_malformed())?;
            "ol"
        } else if let Some(href) = token.strip_prefix("a href=\"") {
            let href = href
                .strip_suffix('"')
                .ok_or_else(generated_storage_malformed)?;
            let scheme = href
                .split_once(':')
                .map(|(scheme, _)| scheme.to_ascii_lowercase())
                .ok_or_else(generated_storage_malformed)?;
            if !matches!(scheme.as_str(), "http" | "https" | "mailto") {
                return Err(generated_storage_malformed());
            }
            "a"
        } else {
            token
        };
        if !matches!(
            name,
            "p" | "h1"
                | "h2"
                | "h3"
                | "h4"
                | "h5"
                | "h6"
                | "blockquote"
                | "ul"
                | "ol"
                | "li"
                | "strong"
                | "em"
                | "s"
                | "code"
                | "pre"
                | "a"
                | "table"
                | "thead"
                | "tr"
                | "th"
                | "td"
        ) {
            return Err(generated_storage_malformed());
        }
        open.push(name.to_string());
    }
    if !rest.is_empty() && rest.contains('<') || !open.is_empty() {
        return Err(generated_storage_malformed());
    }
    Ok(())
}

fn generated_storage_malformed() -> ProviderError {
    ProviderError::deny(
        ReasonCode::BodyMalformed,
        "generated Confluence storage content failed final validation",
    )
}

fn merge_confluence_content_write_audit(audit: &mut Value, content: &ConfluenceContentWriteAudit) {
    audit["contentFormat"] = json!(content.requested_format);
    audit["nativeContentFormat"] = json!(content.native_format);
    audit["sourceContentBytes"] = json!(content.source_bytes);
    audit["finalNativeContentBytes"] = json!(content.final_native_bytes);
}

fn prepare_attachment_uploads(
    inputs: &[AttachmentInput],
    body_parts: &[BrokerBodyPart],
    config: &crate::AttachmentLimitsConfig,
) -> Result<Vec<ConfluenceAttachmentUpload>, ProviderError> {
    validate_attachment_metadata_inputs(inputs, config)?;
    let mut uploads = Vec::new();
    let mut total_size = 0_u64;
    let mut expected_fields = BTreeSet::new();
    for input in inputs {
        if !expected_fields.insert(input.field.as_str()) {
            return Err(ProviderError::deny(
                ReasonCode::InputInvalid,
                "attachment file fields must be unique",
            ));
        }
        let part = body_parts
            .iter()
            .find(|part| part.name == input.field)
            .ok_or_else(|| {
                ProviderError::deny(ReasonCode::BodyMalformed, "attachment file part is missing")
            })?;
        if part.file_name.as_deref() != Some(input.filename.as_str()) {
            return Err(ProviderError::deny(
                ReasonCode::BodyMalformed,
                "attachment filename did not match metadata",
            ));
        }
        if part.content_type.as_deref() != Some(input.content_type.as_str()) {
            return Err(ProviderError::deny(
                ReasonCode::AttachmentMediaTypeDenied,
                "attachment content type did not match metadata",
            ));
        }
        let actual_size = part.size();
        if actual_size != input.size {
            return Err(ProviderError::deny(
                ReasonCode::AttachmentIntegrityMismatch,
                "attachment size did not match metadata",
            ));
        }
        let actual_sha256 = part.sha256_hex();
        if actual_sha256 != input.sha256 {
            return Err(ProviderError::deny(
                ReasonCode::AttachmentIntegrityMismatch,
                "attachment sha256 did not match metadata",
            ));
        }
        total_size = total_size.saturating_add(actual_size);
        if total_size > config.max_total_bytes {
            return Err(ProviderError::deny(
                ReasonCode::AttachmentSizeDenied,
                "attachments exceeded the configured total byte cap",
            ));
        }
        uploads.push(ConfluenceAttachmentUpload {
            filename: input.filename.clone(),
            content_type: input.content_type.clone(),
            size: actual_size,
            bytes: part.bytes.clone(),
            temp_file: part.temp_file(),
            sha256: input.sha256.clone(),
        });
    }
    if body_parts.len() != inputs.len() {
        return Err(ProviderError::deny(
            ReasonCode::BodyMalformed,
            "unexpected attachment file part",
        ));
    }
    let mut observed_fields = BTreeSet::new();
    for part in body_parts {
        if !observed_fields.insert(part.name.as_str()) {
            return Err(ProviderError::deny(
                ReasonCode::BodyMalformed,
                "multipart file part names must be unique",
            ));
        }
    }
    Ok(uploads)
}

fn validate_attachment_metadata_inputs(
    inputs: &[AttachmentInput],
    config: &crate::AttachmentLimitsConfig,
) -> Result<(), ProviderError> {
    let mut total_size = 0_u64;
    let mut expected_fields = BTreeSet::new();
    for input in inputs {
        validate_attachment_input(input, config)?;
        if !expected_fields.insert(input.field.as_str()) {
            return Err(ProviderError::deny(
                ReasonCode::InputInvalid,
                "attachment file fields must be unique",
            ));
        }
        total_size = total_size.saturating_add(input.size);
        if total_size > config.max_total_bytes {
            return Err(ProviderError::deny(
                ReasonCode::AttachmentSizeDenied,
                "attachments exceeded the configured total byte cap",
            ));
        }
    }
    Ok(())
}

fn attachment_body_part_specs(inputs: &[AttachmentInput]) -> Vec<BrokerBodyPartSpec> {
    inputs
        .iter()
        .map(|input| {
            BrokerBodyPartSpec::new(
                input.field.clone(),
                input.filename.clone(),
                input.content_type.clone(),
                input.size,
                input.sha256.clone(),
            )
        })
        .collect()
}

fn attachment_upload_audit(upload: &ConfluenceAttachmentUpload) -> Value {
    json!({
        "filename": upload.filename.as_str(),
        "contentType": upload.content_type.as_str(),
        "size": upload.size,
        "sha256": upload.sha256.as_str(),
    })
}

fn validate_attachment_input(
    input: &AttachmentInput,
    config: &crate::AttachmentLimitsConfig,
) -> Result<(), ProviderError> {
    if input.field.trim().is_empty()
        || input.filename.trim().is_empty()
        || input.filename.contains('/')
        || input.filename.contains('\\')
    {
        return Err(ProviderError::deny(
            ReasonCode::InputInvalid,
            "attachment metadata is invalid",
        ));
    }
    if input.size == 0 || input.size > config.max_bytes {
        return Err(ProviderError::deny(
            ReasonCode::AttachmentSizeDenied,
            "attachment exceeded the configured byte cap",
        ));
    }
    if !config.media_types.contains(&input.content_type) {
        return Err(ProviderError::deny(
            ReasonCode::AttachmentMediaTypeDenied,
            "attachment content type is not allowed",
        ));
    }
    if input.sha256.len() != 64 || !input.sha256.chars().all(|ch| ch.is_ascii_hexdigit()) {
        return Err(ProviderError::deny(
            ReasonCode::InputInvalid,
            "attachment sha256 is invalid",
        ));
    }
    Ok(())
}

fn validate_download_attachment(
    attachment: &ConfluenceAttachment,
    config: &ConfluenceProviderConfig,
) -> Result<(), ProviderError> {
    if attachment.size > config.attachments.max_download_bytes {
        return Err(ProviderError::deny(
            ReasonCode::AttachmentSizeDenied,
            "Confluence attachment exceeds the configured download cap",
        ));
    }
    if !media_type_allowed(&attachment.content_type, &config.attachments.media_types) {
        return Err(ProviderError::deny(
            ReasonCode::AttachmentMediaTypeDenied,
            "Confluence attachment content type is not allowed",
        ));
    }
    Ok(())
}

fn validate_download_content(
    content: &ConfluenceAttachmentContent,
    attachment: &ConfluenceAttachment,
    config: &ConfluenceProviderConfig,
) -> Result<(), ProviderError> {
    if content
        .size
        .is_some_and(|size| size > config.attachments.max_download_bytes)
    {
        return Err(ProviderError::deny(
            ReasonCode::AttachmentSizeDenied,
            "Confluence attachment download exceeded the configured byte cap",
        ));
    }
    let Some(content_type) = media_type_essence(&content.content_type) else {
        return Err(ProviderError::deny(
            ReasonCode::AttachmentMediaTypeDenied,
            "Confluence attachment response content type is not allowed",
        ));
    };
    let Some(metadata_type) = media_type_essence(&attachment.content_type) else {
        return Err(ProviderError::deny(
            ReasonCode::AttachmentMediaTypeDenied,
            "Confluence attachment metadata content type is invalid",
        ));
    };
    if content.size.is_some_and(|size| size != attachment.size) {
        return Err(ProviderError::error(
            ReasonCode::UpstreamProtocolFailed,
            "Confluence attachment response size did not match metadata",
        ));
    }
    if content_type == "application/octet-stream"
        && media_type_allowed("application/octet-stream", &config.attachments.media_types)
        && media_type_allowed(&metadata_type, &config.attachments.media_types)
    {
        return Ok(());
    }
    if content_type != metadata_type
        || !media_type_allowed(&content_type, &config.attachments.media_types)
    {
        return Err(ProviderError::deny(
            ReasonCode::AttachmentMediaTypeDenied,
            "Confluence attachment response content type did not match metadata",
        ));
    }
    Ok(())
}

fn ensure_authorized_space(scopes: &ResourceScopes, space: &str) -> Result<(), ProviderError> {
    let authorized_space = authorized_single_scope(scopes, "space")?;
    if authorized_space != space {
        return Err(ProviderError::deny(
            ReasonCode::ScopeUnresolved,
            "Confluence content no longer matches the authorized space",
        ));
    }
    Ok(())
}

fn validate_current_hierarchy_identity(
    hierarchy: &ConfluencePageHierarchy,
    expected_page_id: &str,
    expected_space_id: &str,
) -> Result<(), ProviderError> {
    if hierarchy.id != expected_page_id || hierarchy.space_id != expected_space_id {
        return Err(ProviderError::deny(
            ReasonCode::ScopeUnresolved,
            "Confluence page hierarchy changed outside the authorized scope",
        ));
    }
    if hierarchy.status != "current" {
        return Err(ProviderError::deny(
            ReasonCode::ScopeUnresolved,
            "Confluence hierarchy mutation requires current pages",
        ));
    }
    Ok(())
}

fn required_target_page_parent_id(
    hierarchy: &ConfluencePageHierarchy,
) -> Result<&str, ProviderError> {
    if hierarchy.parent_type.as_deref() != Some("page") {
        return Err(ProviderError::deny(
            ReasonCode::InputInvalid,
            "confluence.page.move before/after requires a target with a page parent",
        ));
    }
    hierarchy.parent_page_id.as_deref().ok_or_else(|| {
        ProviderError::deny(
            ReasonCode::InputInvalid,
            "confluence.page.move before/after requires a target with a page parent",
        )
    })
}

fn validate_page_hierarchy(
    hierarchy: &ConfluencePageHierarchy,
    expected_page_id: &str,
    expected_space_id: &str,
    expected_parent_page_id: &str,
    expected_status: &str,
) -> Result<(), ProviderError> {
    if hierarchy.id != expected_page_id || hierarchy.space_id != expected_space_id {
        return Err(ProviderError::deny(
            ReasonCode::ScopeUnresolved,
            "Confluence page placement readback changed outside the authorized scope",
        ));
    }
    if hierarchy.status != expected_status
        || hierarchy.parent_page_id.as_deref() != Some(expected_parent_page_id)
        || hierarchy.parent_type.as_deref() != Some("page")
    {
        return Err(ProviderError::error(
            ReasonCode::UpstreamProtocolFailed,
            "Confluence page placement readback did not confirm the requested parent",
        ));
    }
    Ok(())
}

fn verify_page_move_order(
    children: &[ConfluencePageChild],
    page_id: &str,
    target_page_id: &str,
    position: ConfluencePageMovePosition,
) -> Result<(u64, Option<u64>), ProviderError> {
    let mut seen_ids = BTreeSet::new();
    let mut seen_positions = BTreeSet::new();
    for child in children {
        if !seen_ids.insert(child.id.as_str()) || !seen_positions.insert(child.child_position) {
            return Err(ProviderError::error(
                ReasonCode::UpstreamProtocolFailed,
                "Confluence direct-child readback contained duplicate ids or positions",
            ));
        }
    }
    let mut ordered = children.iter().collect::<Vec<_>>();
    ordered.sort_by_key(|child| child.child_position);
    let page_index = ordered
        .iter()
        .position(|child| child.id == page_id && child.content_type == "page")
        .ok_or_else(|| {
            ProviderError::error(
                ReasonCode::UpstreamProtocolFailed,
                "Confluence direct-child readback omitted the moved page",
            )
        })?;
    let child_position = ordered[page_index].child_position;
    match position {
        ConfluencePageMovePosition::Append => {
            if page_index + 1 != ordered.len() {
                return Err(ProviderError::error(
                    ReasonCode::UpstreamProtocolFailed,
                    "Confluence direct-child readback did not confirm append placement",
                ));
            }
            Ok((child_position, None))
        }
        ConfluencePageMovePosition::Before | ConfluencePageMovePosition::After => {
            let target_index = ordered
                .iter()
                .position(|child| child.id == target_page_id && child.content_type == "page")
                .ok_or_else(|| {
                    ProviderError::error(
                        ReasonCode::UpstreamProtocolFailed,
                        "Confluence direct-child readback omitted the sibling target page",
                    )
                })?;
            let adjacent = match position {
                ConfluencePageMovePosition::Before => {
                    page_index.checked_add(1) == Some(target_index)
                }
                ConfluencePageMovePosition::After => {
                    target_index.checked_add(1) == Some(page_index)
                }
                ConfluencePageMovePosition::Append => unreachable!(),
            };
            if !adjacent {
                return Err(ProviderError::error(
                    ReasonCode::UpstreamProtocolFailed,
                    "Confluence direct-child readback did not confirm sibling placement",
                ));
            }
            Ok((child_position, Some(ordered[target_index].child_position)))
        }
    }
}

fn page_move_failure_audit(
    request: &ProviderInvocation,
    target: (&str, &str, &str, &str, &str),
    position: ConfluencePageMovePosition,
    phase: &str,
    egress_proxy: Value,
) -> Value {
    let (page_id, target_page_id, space, space_id, parent_page_id) = target;
    json!({
        "provider": "confluence",
        "operation": "page.move",
        "pageId": page_id,
        "position": position.as_str(),
        "targetPageId": target_page_id,
        "space": space,
        "spaceId": space_id,
        "parentPageId": parent_page_id,
        "verificationStatus": "failed",
        "mutationPhase": phase,
        "sideEffectPossible": true,
        "credentialMode": request.credential_mode(),
        "egressProxy": egress_proxy,
    })
}

fn page_placement_failure_audit(
    request: &ProviderInvocation,
    operation: &str,
    target: (&str, &str, &str, &str),
    phase: &str,
    egress_proxy: Value,
) -> Value {
    let (page_id, space, space_id, parent_page_id) = target;
    page_placement_failure_audit_partial(
        request,
        operation,
        Some(page_id),
        (space, space_id, parent_page_id),
        phase,
        egress_proxy,
    )
}

fn page_placement_failure_audit_partial(
    request: &ProviderInvocation,
    operation: &str,
    page_id: Option<&str>,
    target: (&str, &str, &str),
    phase: &str,
    egress_proxy: Value,
) -> Value {
    let (space, space_id, parent_page_id) = target;
    let mut audit = json!({
        "provider": "confluence",
        "operation": operation,
        "space": space,
        "spaceId": space_id,
        "parentPageId": parent_page_id,
        "verificationStatus": "failed",
        "mutationPhase": phase,
        "sideEffectPossible": true,
        "credentialMode": request.credential_mode(),
        "egressProxy": egress_proxy,
    });
    if let Some(page_id) = page_id {
        audit["pageId"] = json!(page_id);
    }
    audit
}

fn ensure_authorized_draft_handle(
    handle: &ConfluenceDraftHandle,
    scopes: &ResourceScopes,
) -> Result<(), ProviderError> {
    let authorized_space = authorized_single_scope(scopes, "space")?;
    if authorized_space != handle.space {
        return Err(invalid_draft_handle_error());
    }
    Ok(())
}

fn require_draft_content(
    content: &ConfluenceDraftContent,
    content_type: ConfluenceDraftContentType,
) -> Result<(), ProviderError> {
    if content.content_type != content_type.as_str() || content.status.as_deref() != Some("draft") {
        return Err(ProviderError::deny(
            ReasonCode::ScopeUnresolved,
            "Confluence content is not the expected draft",
        ));
    }
    Ok(())
}

fn require_current_draft_content(
    content: &ConfluenceDraftContent,
    content_type: ConfluenceDraftContentType,
) -> Result<(), ProviderError> {
    if content.content_type != content_type.as_str() || content.status.as_deref() != Some("current")
    {
        return Err(ProviderError::error(
            ReasonCode::UpstreamProtocolFailed,
            "Confluence publish response is not current content",
        ));
    }
    Ok(())
}

fn require_draft_version_one(content: &ConfluenceDraftContent) -> Result<(), ProviderError> {
    if content.version == 1 {
        Ok(())
    } else {
        Err(ProviderError::error(
            ReasonCode::VersionConflict,
            "Confluence draft version conflicted with the broker-managed draft state",
        ))
    }
}

fn draft_publish_version(handle: &ConfluenceDraftHandle) -> Result<u64, ProviderError> {
    match handle.origin {
        ConfluenceDraftOrigin::New => Ok(1),
        ConfluenceDraftOrigin::Staged => handle
            .base_version
            .and_then(|version| version.checked_add(1))
            .filter(|version| *version > 1)
            .ok_or_else(invalid_draft_handle_error),
    }
}

fn ensure_draft_content_matches_handle(
    content: &ConfluenceDraftContent,
    handle: &ConfluenceDraftHandle,
) -> Result<(), ProviderError> {
    require_draft_content(content, handle.content_type)?;
    if content.id != handle.content_id
        || content.space != handle.space
        || content.space_id != handle.space_id
        || content.parent_page_id != handle.parent_page_id
    {
        return Err(ProviderError::deny(
            ReasonCode::ScopeUnresolved,
            "Confluence draft no longer matches the broker-issued draft handle",
        ));
    }
    Ok(())
}

fn reject_staged_draft_discard(handle: &ConfluenceDraftHandle) -> Result<(), ProviderError> {
    if handle.origin == ConfluenceDraftOrigin::Staged {
        return Err(ProviderError::deny(
            ReasonCode::ServiceActionDenied,
            "Confluence staged draft discard is not supported",
        ));
    }
    Ok(())
}

fn reject_staged_draft_attachment_add(handle: &ConfluenceDraftHandle) -> Result<(), ProviderError> {
    if handle.origin == ConfluenceDraftOrigin::Staged {
        return Err(ProviderError::deny(
            ReasonCode::ServiceActionDenied,
            "Confluence staged draft attachment upload is not supported",
        ));
    }
    Ok(())
}

fn reject_staged_draft_attachment_read(
    handle: &ConfluenceDraftHandle,
) -> Result<(), ProviderError> {
    if handle.origin == ConfluenceDraftOrigin::Staged {
        return Err(ProviderError::deny(
            ReasonCode::ServiceActionDenied,
            "Confluence staged draft attachment access is not supported",
        ));
    }
    Ok(())
}

fn draft_browser_urls(
    content: &ConfluenceDraftContent,
    config: &ConfluenceProviderConfig,
) -> Result<(String, String), ProviderError> {
    Ok((
        constructed_content_browser_url(&content.id, &config.tenant_host)?,
        space_browser_url(content.space_web_url.as_deref(), &content.space, config)?,
    ))
}

fn draft_content_result(
    operation: &str,
    content: &ConfluenceDraftContent,
    content_type: ConfluenceDraftContentType,
    draft_handle: Option<String>,
    body_format: Option<&str>,
    config: &ConfluenceProviderConfig,
) -> Result<Value, ProviderError> {
    let (web_url, space_url) = draft_browser_urls(content, config)?;
    let mut result = json!({
        "operation": operation,
        "contentType": content_type.as_str(),
        "space": content.space,
        "spaceId": content.space_id,
        "parentPageId": content.parent_page_id,
        "spaceUrl": space_url,
        "webUrl": web_url,
        "title": content.title,
        "lifecycle": content.status.as_deref().unwrap_or("draft"),
        "status": content.status,
        "version": content.version,
        "createdAt": content.created_at,
        "updatedAt": content.updated_at,
        "createdBy": content.created_by,
        "updatedBy": content.updated_by,
    });
    result[content_type.id_field()] = json!(content.id);
    if let Some(draft_handle) = draft_handle {
        result["draftHandle"] = json!(draft_handle);
        result["draftOrigin"] = json!("broker_managed");
    }
    if let Some(format) = body_format {
        let value = content.bodies.get(format).ok_or_else(|| {
            ProviderError::error(
                ReasonCode::UpstreamProtocolFailed,
                "Confluence draft response omitted the requested body format",
            )
        })?;
        result["body"] = json!({
            format: {
                "representation": format,
                "value": value,
            }
        });
    }
    Ok(result)
}

fn draft_audit(
    request: &ProviderInvocation,
    operation: &str,
    content: &ConfluenceDraftContent,
    content_type: ConfluenceDraftContentType,
    body_format: Option<&str>,
    mutated: bool,
    egress_proxy: Value,
) -> Value {
    let mut audit = json!({
        "provider": "confluence",
        "operation": operation,
        "contentType": content_type.as_str(),
        "lifecycle": content.status.as_deref().unwrap_or("draft"),
        "space": content.space,
        "spaceId": content.space_id,
        "parentPageId": content.parent_page_id,
        "version": content.version,
        "mutated": mutated,
        "credentialMode": request.credential_mode(),
        "egressProxy": egress_proxy,
    });
    audit[content_type.id_field()] = json!(content.id);
    if let Some(body_format) = body_format {
        audit["bodyFormat"] = json!(body_format);
    }
    audit
}

fn enforce_draft_body_size(
    content: &ConfluenceDraftContent,
    body_format: &str,
    config: &ConfluenceProviderConfig,
) -> Result<(), ProviderError> {
    let Some(value) = content.bodies.get(body_format) else {
        return Ok(());
    };
    if value.len() as u64 > config.content.max_body_bytes {
        return Err(ProviderError::error(
            ReasonCode::UpstreamProtocolFailed,
            "Confluence draft body exceeded the configured byte cap",
        ));
    }
    Ok(())
}

fn draft_body_for_publish(
    content: &ConfluenceDraftContent,
    body_format: &str,
) -> Result<ConfluencePageBody, ProviderError> {
    let value = content.bodies.get(body_format).ok_or_else(|| {
        ProviderError::error(
            ReasonCode::UpstreamProtocolFailed,
            "Confluence draft response omitted the requested body format",
        )
    })?;
    Ok(ConfluencePageBody {
        representation: body_format.to_string(),
        value: value.clone(),
    })
}

fn draft_version_conflict_error(
    request: &ProviderInvocation,
    content: &ConfluenceDraftContent,
    content_type: ConfluenceDraftContentType,
    expected_base_version: u64,
    egress_proxy: Value,
) -> ProviderError {
    ProviderError::error(
        ReasonCode::VersionConflict,
        "Confluence broker-managed draft already exists for this content",
    )
    .with_result({
        let mut result = json!({
        "space": content.space,
        "spaceId": content.space_id,
        "expectedBaseVersion": expected_base_version,
        "draftVersion": content.version,
        "lifecycle": "draft",
        });
        result[content_type.id_field()] = json!(content.id);
        result
    })
    .with_audit({
        let mut audit = json!({
            "provider": "confluence",
            "operation": request.action(),
            "contentType": content_type.as_str(),
            "space": content.space,
            "spaceId": content.space_id,
            "expectedBaseVersion": expected_base_version,
            "draftVersion": content.version,
            "credentialMode": request.credential_mode(),
            "egressProxy": egress_proxy,
        });
        audit[content_type.id_field()] = json!(content.id);
        audit
    })
    .with_object_ids({
        let mut ids = json!({});
        ids[content_type.id_field()] = json!(content.id);
        ids
    })
}

fn draft_verification_mismatch_error(
    request: &ProviderInvocation,
    content: &ConfluenceDraftContent,
    content_type: ConfluenceDraftContentType,
    checked: &[Value],
    mismatch: Value,
    egress_proxy: Value,
) -> ProviderError {
    ProviderError::allow_with_result(
        ReasonCode::VerificationMismatch,
        "Confluence draft verification mismatch",
        {
            let mut result = json!({
                "operation": request.action(),
                "verification": {
                    "status": "mismatch",
                    "checked": checked,
                    "mismatch": mismatch,
                },
                "space": content.space,
                "spaceId": content.space_id,
                "lifecycle": "draft",
            });
            result[content_type.id_field()] = json!(content.id);
            result
        },
    )
    .with_audit({
        let mut audit = json!({
            "provider": "confluence",
            "operation": request.action(),
            "contentType": content_type.as_str(),
            "space": content.space,
            "spaceId": content.space_id,
            "status": "mismatch",
            "checked": checked,
            "mismatch": mismatch,
            "credentialMode": request.credential_mode(),
            "egressProxy": egress_proxy,
        });
        audit[content_type.id_field()] = json!(content.id);
        audit
    })
    .with_object_ids({
        let mut ids = json!({});
        ids[content_type.id_field()] = json!(content.id);
        ids
    })
}

fn draft_attachment_from_collection(
    response: ConfluenceBackendResponse<Vec<ConfluenceAttachment>>,
    parent_id: &str,
    attachment_id: &str,
) -> Result<ConfluenceBackendResponse<ConfluenceAttachment>, ProviderError> {
    let attachment = response
        .value
        .into_iter()
        .find(|attachment| attachment.id == attachment_id)
        .ok_or_else(|| {
            ProviderError::deny(
                ReasonCode::ScopeUnresolved,
                "Confluence draft attachment was not found on the broker-managed draft",
            )
        })?;
    if attachment.page_id != parent_id {
        return Err(ProviderError::error(
            ReasonCode::UpstreamProtocolFailed,
            "Confluence draft attachment list returned a different parent",
        ));
    }
    Ok(ConfluenceBackendResponse {
        value: attachment,
        status: response.status,
        duration_ms: response.duration_ms,
    })
}

fn draft_attachment_values(
    attachments: &[ConfluenceAttachment],
    parent_id: &str,
) -> Result<(Vec<Value>, Vec<String>), ProviderError> {
    let mut values = Vec::with_capacity(attachments.len());
    let mut ids = Vec::with_capacity(attachments.len());
    for attachment in attachments {
        if attachment.page_id != parent_id {
            return Err(ProviderError::error(
                ReasonCode::UpstreamProtocolFailed,
                "Confluence draft attachment list returned a different parent",
            ));
        }
        ids.push(attachment.id.clone());
        values.push(json!({
            "attachmentId": attachment.id,
            "filename": attachment.filename,
            "contentType": attachment.content_type,
            "size": attachment.size,
            "parentStatus": "draft",
        }));
    }
    Ok((values, ids))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ConfluenceBrowserContentKind {
    Page,
    Blog,
}

fn page_browser_urls(
    page: &ConfluencePage,
    config: &ConfluenceProviderConfig,
) -> Result<(String, String), ProviderError> {
    Ok((
        content_browser_url(
            page.web_url.as_deref(),
            ConfluenceBrowserContentKind::Page,
            &page.id,
            &page.space,
            config,
        )?,
        space_browser_url(page.space_web_url.as_deref(), &page.space, config)?,
    ))
}

fn blog_browser_urls(
    blog: &ConfluenceBlog,
    config: &ConfluenceProviderConfig,
) -> Result<(String, String), ProviderError> {
    Ok((
        content_browser_url(
            blog.web_url.as_deref(),
            ConfluenceBrowserContentKind::Blog,
            &blog.id,
            &blog.space,
            config,
        )?,
        space_browser_url(blog.space_web_url.as_deref(), &blog.space, config)?,
    ))
}

fn blog_summary_browser_urls(
    blog: &ConfluenceBlogSummary,
    config: &ConfluenceProviderConfig,
) -> Result<(String, String), ProviderError> {
    Ok((
        content_browser_url(
            blog.web_url.as_deref(),
            ConfluenceBrowserContentKind::Blog,
            &blog.id,
            &blog.space,
            config,
        )?,
        space_browser_url(blog.space_web_url.as_deref(), &blog.space, config)?,
    ))
}

fn content_browser_url(
    raw: Option<&str>,
    kind: ConfluenceBrowserContentKind,
    expected_id: &str,
    expected_space: &str,
    config: &ConfluenceProviderConfig,
) -> Result<String, ProviderError> {
    if !is_page_id(expected_id) || !is_space_key(expected_space) {
        return Err(confluence_browser_url_protocol_error());
    }
    if let Some(raw) = raw
        && let Some(url) =
            normalize_content_browser_url(raw, kind, expected_id, expected_space, config)?
    {
        return Ok(url);
    }
    constructed_content_browser_url(expected_id, &config.tenant_host)
}

fn space_browser_url(
    raw: Option<&str>,
    expected_space: &str,
    config: &ConfluenceProviderConfig,
) -> Result<String, ProviderError> {
    if !is_space_key(expected_space) {
        return Err(confluence_browser_url_protocol_error());
    }
    if let Some(raw) = raw
        && let Some(url) = normalize_space_browser_url(raw, expected_space, config)?
    {
        return Ok(url);
    }
    constructed_space_browser_url(expected_space, &config.tenant_host)
}

fn constructed_content_browser_url(
    expected_id: &str,
    tenant_host: &str,
) -> Result<String, ProviderError> {
    Url::parse(&format!(
        "https://{tenant_host}/wiki/pages/viewpage.action?pageId={expected_id}"
    ))
    .map(|url| url.to_string())
    .map_err(|_| confluence_browser_url_protocol_error())
}

fn constructed_space_browser_url(
    expected_space: &str,
    tenant_host: &str,
) -> Result<String, ProviderError> {
    Url::parse(&format!(
        "https://{tenant_host}/wiki/spaces/{expected_space}"
    ))
    .map(|url| url.to_string())
    .map_err(|_| confluence_browser_url_protocol_error())
}

fn normalize_content_browser_url(
    raw: &str,
    _kind: ConfluenceBrowserContentKind,
    expected_id: &str,
    expected_space: &str,
    config: &ConfluenceProviderConfig,
) -> Result<Option<String>, ProviderError> {
    let url = parse_confluence_browser_url(raw, config)?;
    let segments = url
        .path_segments()
        .map(|segments| segments.collect::<Vec<_>>())
        .ok_or_else(confluence_browser_url_protocol_error)?;
    if forbidden_confluence_browser_path(&segments) {
        return Err(confluence_browser_url_protocol_error());
    }
    if segments.as_slice() == ["wiki", "pages", "viewpage.action"] {
        let pairs = url.query_pairs().collect::<Vec<_>>();
        if pairs.len() != 1 || pairs[0].0 != "pageId" {
            return Err(confluence_browser_url_protocol_error());
        }
        if pairs[0].1 != expected_id {
            return Err(confluence_browser_url_protocol_error());
        }
        return Ok(Some(url.to_string()));
    }
    if url.query().is_some() {
        return Err(confluence_browser_url_protocol_error());
    }
    if segments.len() >= 5
        && segments[0] == "wiki"
        && segments[1] == "spaces"
        && segments[3] == "pages"
    {
        if segments[2] != expected_space {
            return Err(confluence_browser_url_protocol_error());
        }
        if !is_page_id(segments[4]) {
            return Ok(None);
        }
        if segments[4] != expected_id {
            return Err(confluence_browser_url_protocol_error());
        }
        return Ok(Some(url.to_string()));
    }
    if segments.len() >= 5
        && segments[0] == "wiki"
        && segments[1] == "spaces"
        && segments[3] == "blog"
    {
        if segments[2] != expected_space {
            return Err(confluence_browser_url_protocol_error());
        }
        if blog_tail_has_matching_content_id(&segments[4..], expected_id)? {
            return Ok(Some(url.to_string()));
        }
        return Ok(None);
    }
    if segments.len() >= 3
        && segments[0] == "wiki"
        && segments[1] == "spaces"
        && segments[2] != expected_space
    {
        return Err(confluence_browser_url_protocol_error());
    }
    if segments.first() == Some(&"wiki")
        && !has_probable_content_id_mismatch(&segments, expected_id)
    {
        return Ok(None);
    }
    Err(confluence_browser_url_protocol_error())
}

fn normalize_space_browser_url(
    raw: &str,
    expected_space: &str,
    config: &ConfluenceProviderConfig,
) -> Result<Option<String>, ProviderError> {
    let url = parse_confluence_browser_url(raw, config)?;
    let segments = url
        .path_segments()
        .map(|segments| segments.collect::<Vec<_>>())
        .ok_or_else(confluence_browser_url_protocol_error)?;
    if forbidden_confluence_browser_path(&segments) || url.query().is_some() {
        return Err(confluence_browser_url_protocol_error());
    }
    match segments.as_slice() {
        ["wiki", "spaces", space] | ["wiki", "spaces", space, "overview"]
            if *space == expected_space =>
        {
            Ok(Some(url.to_string()))
        }
        ["wiki", "spaces", space, ..] if *space != expected_space => {
            Err(confluence_browser_url_protocol_error())
        }
        _ if segments.first() == Some(&"wiki") => Ok(None),
        _ => Err(confluence_browser_url_protocol_error()),
    }
}

fn parse_confluence_browser_url(
    raw: &str,
    config: &ConfluenceProviderConfig,
) -> Result<Url, ProviderError> {
    let raw = raw.trim();
    if raw.is_empty() {
        return Err(confluence_browser_url_protocol_error());
    }
    if raw_url_has_explicit_authority_port(raw) {
        return Err(confluence_browser_url_protocol_error());
    }
    if raw.starts_with("//") {
        return Err(confluence_browser_url_protocol_error());
    }
    let tenant_base = Url::parse(&format!("https://{}", config.tenant_host))
        .map_err(|_| confluence_browser_url_protocol_error())?;
    let url = match Url::parse(raw) {
        Ok(url) => url,
        Err(_) => relative_confluence_browser_url(raw, &tenant_base)?,
    };
    if !confluence_url_has_exact_authority(&url, &config.tenant_host) {
        return Err(confluence_browser_url_protocol_error());
    }
    if url.fragment().is_some() {
        return Err(confluence_browser_url_protocol_error());
    }
    Ok(url)
}

fn relative_confluence_browser_url(raw: &str, tenant_base: &Url) -> Result<Url, ProviderError> {
    let relative = raw.trim_start_matches('/');
    let allowed_browser_family = relative.starts_with("wiki/spaces/")
        || relative.starts_with("wiki/pages/viewpage.action")
        || relative.starts_with("spaces/")
        || relative.starts_with("pages/viewpage.action");
    if !allowed_browser_family {
        return Err(confluence_browser_url_protocol_error());
    }
    let path = if relative == "wiki" || relative.starts_with("wiki/") {
        format!("/{relative}")
    } else {
        format!("/wiki/{relative}")
    };
    tenant_base
        .join(&path)
        .map_err(|_| confluence_browser_url_protocol_error())
}

fn confluence_url_has_exact_authority(url: &Url, tenant_host: &str) -> bool {
    url.scheme() == "https"
        && url.host_str() == Some(tenant_host)
        && url.username().is_empty()
        && url.password().is_none()
        && url.port().is_none()
}

fn raw_url_has_explicit_authority_port(raw: &str) -> bool {
    let Some((scheme, rest)) = raw.split_once("://") else {
        return false;
    };
    if !scheme.eq_ignore_ascii_case("http") && !scheme.eq_ignore_ascii_case("https") {
        return false;
    }
    let authority_end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let authority = &rest[..authority_end];
    let host_port = authority
        .rsplit_once('@')
        .map_or(authority, |(_, host_port)| host_port);
    if let Some(after_ipv6) = host_port
        .strip_prefix('[')
        .and_then(|value| value.split_once(']'))
        .map(|(_, suffix)| suffix)
    {
        return after_ipv6.starts_with(':');
    }
    host_port.rsplit_once(':').is_some()
}

fn forbidden_confluence_browser_path(segments: &[&str]) -> bool {
    matches!(
        segments,
        ["wiki", "rest", ..] | ["wiki", "api", ..] | ["wiki", "download", ..]
    ) || segments
        .iter()
        .any(|segment| matches!(*segment, "editpage.action" | "download"))
        || segments
            .windows(2)
            .any(|window| matches!(window, ["child", "attachment"]))
}

fn blog_tail_has_matching_content_id(
    tail: &[&str],
    expected_id: &str,
) -> Result<bool, ProviderError> {
    let tail =
        modern_blog_tail_after_date(tail).map_err(|_| confluence_browser_url_protocol_error())?;
    let Some(blog_id) = tail.first() else {
        return Ok(false);
    };
    if !is_page_id(blog_id) {
        return Ok(false);
    }
    if *blog_id != expected_id {
        return Err(confluence_browser_url_protocol_error());
    }
    Ok(true)
}

fn modern_blog_tail_after_date<'a>(tail: &'a [&'a str]) -> Result<&'a [&'a str], ()> {
    if let Some(prefix) = blog_date_prefix(tail) {
        return Ok(tail.strip_prefix(prefix).unwrap_or(tail));
    }
    if blog_tail_starts_with_invalid_date_prefix(tail) {
        return Err(());
    }
    Ok(tail)
}

fn blog_date_prefix<'a>(tail: &'a [&'a str]) -> Option<&'a [&'a str]> {
    let [year, month, day, ..] = tail else {
        return None;
    };
    let valid_year = year.len() == 4 && year.chars().all(|ch| ch.is_ascii_digit());
    let valid_month = month
        .parse::<u8>()
        .is_ok_and(|value| (1..=12).contains(&value));
    let valid_day = day
        .parse::<u8>()
        .is_ok_and(|value| (1..=31).contains(&value));
    if valid_year && valid_month && valid_day {
        Some(&tail[..3])
    } else {
        None
    }
}

fn blog_tail_starts_with_invalid_date_prefix(tail: &[&str]) -> bool {
    let [year, month, day, ..] = tail else {
        return false;
    };
    year.len() == 4
        && year.chars().all(|ch| ch.is_ascii_digit())
        && month.chars().all(|ch| ch.is_ascii_digit())
        && day.chars().all(|ch| ch.is_ascii_digit())
}

fn has_probable_content_id_mismatch(segments: &[&str], expected_id: &str) -> bool {
    segments.iter().any(|segment| {
        is_page_id(segment)
            && *segment != expected_id
            && segment.len() >= 5
            && segment.len() >= expected_id.len().min(5)
    })
}

fn confluence_browser_url_protocol_error() -> ProviderError {
    ProviderError::error(
        ReasonCode::UpstreamProtocolFailed,
        "Confluence browser URL failed validation",
    )
}

/// A search page's result, carrying the sealed continuation for its
/// upstream cursor.
fn search_result(
    page: &ConfluenceSearchPage,
    next_page_token: Option<&str>,
    config: &ConfluenceProviderConfig,
) -> Result<Value, ProviderError> {
    let pages = page
        .pages
        .iter()
        .map(|page| {
            let (web_url, space_url) = page_browser_urls(page, config)?;
            Ok(json!({
                "id": page.id,
                "title": page.title,
                "space": page.space,
                "spaceUrl": space_url,
                "webUrl": web_url,
                "version": page.version,
                "createdAt": page.created_at,
                "updatedAt": page.updated_at,
                "createdBy": page.created_by,
                "updatedBy": page.updated_by,
            }))
        })
        .collect::<Result<Vec<_>, ProviderError>>()?;
    Ok(json!({
        "pages": pages,
        "maxResults": page.max_results,
        "nextPageToken": next_page_token,
    }))
}

fn blog_search_result(
    page: &ConfluenceSearchBlog,
    next_page_token: Option<&str>,
    config: &ConfluenceProviderConfig,
) -> Result<Value, ProviderError> {
    let blogs = page
        .blogs
        .iter()
        .map(|blog| {
            let (web_url, space_url) = blog_summary_browser_urls(blog, config)?;
            Ok(json!({
                "blogId": blog.id,
                "title": blog.title,
                "space": blog.space,
                "spaceUrl": space_url,
                "webUrl": web_url,
                "status": blog.status,
                "version": blog.version,
                "createdAt": blog.created_at,
                "updatedAt": blog.updated_at,
                "createdBy": blog.created_by,
                "updatedBy": blog.updated_by,
            }))
        })
        .collect::<Result<Vec<_>, ProviderError>>()?;
    Ok(json!({
        "operation": "blog.search",
        "blogs": blogs,
        "count": page.blogs.len(),
        "maxResults": page.max_results,
        "nextPageToken": next_page_token,
    }))
}

fn blog_view_result(
    blog: &ConfluenceBlog,
    config: &ConfluenceProviderConfig,
) -> Result<Value, ProviderError> {
    let mut body = serde_json::Map::new();
    if let Some(value) = blog.bodies.get("storage") {
        body.insert("storage".to_string(), json!(value));
    }
    let (web_url, space_url) = blog_browser_urls(blog, config)?;
    Ok(json!({
        "operation": "blog.view",
        "blogId": blog.id,
        "space": blog.space,
        "spaceId": blog.space_id,
        "spaceUrl": space_url,
        "webUrl": web_url,
        "title": blog.title,
        "status": blog.status,
        "version": blog.version,
        "createdAt": blog.created_at,
        "updatedAt": blog.updated_at,
        "createdBy": blog.created_by,
        "updatedBy": blog.updated_by,
        "body": body,
    }))
}

fn configured_comment_body_format(
    requested: Option<&str>,
    config: &ConfluenceProviderConfig,
) -> Result<Option<String>, ProviderError> {
    let selected = requested
        .map(ToString::to_string)
        .or_else(|| config.content.comment_formats.first().cloned());
    if let Some(format) = &selected
        && !config
            .content
            .comment_formats
            .iter()
            .any(|configured| configured == format)
    {
        return Err(ProviderError::deny(
            ReasonCode::BodyFormatUnsupported,
            "confluence comment body format is not configured",
        ));
    }
    Ok(selected)
}

fn comment_list_binding(
    action: ConfluenceCommentAction,
    container: &ConfluenceResolvedCommentContainer,
    comment_id: Option<String>,
    body_format: Option<String>,
    inputs: &CommentListInputs,
    max_results: u32,
) -> ConfluenceCommentListBinding {
    ConfluenceCommentListBinding {
        kind: action.kind,
        container_type: action.container_type,
        container_id: container.id().to_string(),
        comment_id,
        space: container.space().to_string(),
        body_format,
        resolution_status: inputs.resolution_status.clone(),
        sort: inputs.sort.clone(),
        max_results,
    }
}

fn ensure_authorized_comment_container(
    container: &ConfluenceResolvedCommentContainer,
    scopes: &ResourceScopes,
) -> Result<(), ProviderError> {
    let authorized_space = authorized_single_scope(scopes, "space")?;
    if authorized_space != container.space() {
        return Err(ProviderError::deny(
            ReasonCode::ScopeUnresolved,
            "Confluence comment container no longer matches the authorized space",
        ));
    }
    Ok(())
}

fn validate_comment_page(
    comments: &[ConfluenceComment],
    action: ConfluenceCommentAction,
    container: &ConfluenceResolvedCommentContainer,
    root_list: bool,
    max_results: u32,
    expected_parent_id: Option<&str>,
) -> Result<(), ProviderError> {
    if comments.len() > max_results as usize {
        return Err(ProviderError::error(
            ReasonCode::UpstreamProtocolFailed,
            "Confluence comment list returned more comments than requested",
        ));
    }
    for comment in comments {
        validate_comment_identity(comment, &comment.id, action.kind)?;
        require_current_comment(comment)?;
        if root_list {
            if comment.parent_comment_id.is_some() {
                return Err(ProviderError::error(
                    ReasonCode::UpstreamProtocolFailed,
                    "Confluence root comment list returned a reply",
                ));
            }
            let Some(container_id) = comment_container_id_for_action(comment, action)? else {
                return Err(ProviderError::error(
                    ReasonCode::UpstreamProtocolFailed,
                    "Confluence comment list returned a comment without the expected container",
                ));
            };
            if container_id != container.id() {
                return Err(ProviderError::deny(
                    ReasonCode::ScopeUnresolved,
                    "Confluence comment list returned a comment outside the authorized container",
                ));
            }
        } else {
            if expected_parent_id
                .is_some_and(|parent| comment.parent_comment_id.as_deref() != Some(parent))
            {
                return Err(ProviderError::error(
                    ReasonCode::UpstreamProtocolFailed,
                    "Confluence comment reply list returned a different parent",
                ));
            }
            if let Some(container_id) = comment_container_id_for_action(comment, action)?
                && container_id != container.id()
            {
                return Err(ProviderError::deny(
                    ReasonCode::ScopeUnresolved,
                    "Confluence comment reply list returned a comment outside the authorized container",
                ));
            }
        }
    }
    Ok(())
}

fn ensure_matching_comment_evidence(
    lookup: &ConfluenceCommentEvidence,
    execution: &ConfluenceCommentEvidence,
) -> Result<(), ProviderError> {
    if lookup.target.id != execution.target.id
        || lookup.target.kind != execution.target.kind
        || lookup.target.parent_comment_id != execution.target.parent_comment_id
    {
        return Err(ProviderError::deny(
            ReasonCode::ScopeUnresolved,
            "Confluence comment relationship changed after authorization lookup",
        ));
    }
    if lookup.chain != execution.chain {
        return Err(ProviderError::deny(
            ReasonCode::ScopeUnresolved,
            "Confluence comment parent chain changed after authorization lookup",
        ));
    }
    match (&lookup.container, &execution.container) {
        (
            ConfluenceResolvedCommentContainer::Page(lookup),
            ConfluenceResolvedCommentContainer::Page(execution),
        ) if lookup.id == execution.id && lookup.space == execution.space => {}
        (
            ConfluenceResolvedCommentContainer::Blog(lookup),
            ConfluenceResolvedCommentContainer::Blog(execution),
        ) if lookup.id == execution.id
            && lookup.space == execution.space
            && lookup.space_id == execution.space_id => {}
        _ => {
            return Err(ProviderError::deny(
                ReasonCode::ScopeUnresolved,
                "Confluence comment container changed after authorization lookup",
            ));
        }
    }
    Ok(())
}

fn next_comment_version(base_version: u64) -> Result<u64, ProviderError> {
    base_version.checked_add(1).ok_or_else(|| {
        ProviderError::deny(
            ReasonCode::InputInvalid,
            "confluence comment update baseVersion is too large",
        )
    })
}

fn ensure_comment_base_version(
    request: &ProviderInvocation,
    action: ConfluenceCommentAction,
    evidence: &ConfluenceCommentEvidence,
    expected_base_version: u64,
    egress_proxy: Value,
) -> Result<(), ProviderError> {
    let Some(current_version) = evidence.target.version else {
        return Err(ProviderError::error(
            ReasonCode::UpstreamProtocolFailed,
            "Confluence comment response omitted version",
        ));
    };
    if current_version != expected_base_version {
        return Err(comment_version_conflict_error(
            request,
            action,
            evidence,
            expected_base_version,
            egress_proxy,
        ));
    }
    Ok(())
}

fn comment_version_conflict_error(
    request: &ProviderInvocation,
    action: ConfluenceCommentAction,
    evidence: &ConfluenceCommentEvidence,
    expected_base_version: u64,
    egress_proxy: Value,
) -> ProviderError {
    let mut result = comment_version_conflict_result(evidence, expected_base_version);
    if let Some(current_version) = evidence.target.version {
        result["currentVersion"] = json!(current_version);
    }
    let mut audit = comment_audit(
        request,
        &evidence.container,
        action,
        Some(&evidence.target.id),
        None,
        None,
        egress_proxy,
    );
    audit["expectedBaseVersion"] = json!(expected_base_version);
    if let Some(current_version) = evidence.target.version {
        audit["currentVersion"] = json!(current_version);
    }
    ProviderError::error(
        ReasonCode::VersionConflict,
        "Confluence comment version conflicted with the supplied base version",
    )
    .with_result(result)
    .with_audit(audit)
    .with_upstream(
        evidence.upstream_status,
        Some(evidence.upstream_duration_ms),
    )
    .with_object_ids(comment_object_ids(&evidence.target, &evidence.container))
}

fn upstream_comment_version_conflict_error(
    request: &ProviderInvocation,
    action: ConfluenceCommentAction,
    evidence: &ConfluenceCommentEvidence,
    expected_base_version: u64,
    egress_proxy: Value,
) -> ProviderError {
    let mut result = comment_version_conflict_result(evidence, expected_base_version);
    let mut audit = comment_audit(
        request,
        &evidence.container,
        action,
        Some(&evidence.target.id),
        None,
        None,
        egress_proxy,
    );
    audit["expectedBaseVersion"] = json!(expected_base_version);
    audit["status"] = json!("upstream_conflict");
    result["status"] = json!("upstream_conflict");
    ProviderError::error(
        ReasonCode::VersionConflict,
        "Confluence comment version conflicted with the supplied base version",
    )
    .with_result(result)
    .with_audit(audit)
    .with_upstream(Some(409), None)
    .with_object_ids(comment_object_ids(&evidence.target, &evidence.container))
}

fn comment_version_conflict_result(
    evidence: &ConfluenceCommentEvidence,
    expected_base_version: u64,
) -> Value {
    let mut result = json!({
        "commentId": evidence.target.id,
        "kind": evidence.target.kind.as_str(),
        "space": evidence.container.space(),
        "expectedBaseVersion": expected_base_version,
    });
    match &evidence.container {
        ConfluenceResolvedCommentContainer::Page(page) => {
            result["containerType"] = json!("page");
            result["pageId"] = json!(page.id);
        }
        ConfluenceResolvedCommentContainer::Blog(blog) => {
            result["containerType"] = json!("blog");
            result["blogId"] = json!(blog.id);
            result["spaceId"] = json!(blog.space_id);
        }
    }
    result
}

fn ensure_created_reply_matches_parent(
    created: &ConfluenceCommentEvidence,
    parent: &ConfluenceCommentEvidence,
    parent_comment_id: &str,
) -> Result<(), ProviderError> {
    if created.target.parent_comment_id.as_deref() != Some(parent_comment_id) {
        return Err(ProviderError::deny(
            ReasonCode::ScopeUnresolved,
            "Confluence created reply relationship changed after creation",
        ));
    }
    match (&created.container, &parent.container) {
        (
            ConfluenceResolvedCommentContainer::Page(created),
            ConfluenceResolvedCommentContainer::Page(parent),
        ) if created.id == parent.id && created.space == parent.space => {}
        (
            ConfluenceResolvedCommentContainer::Blog(created),
            ConfluenceResolvedCommentContainer::Blog(parent),
        ) if created.id == parent.id
            && created.space == parent.space
            && created.space_id == parent.space_id => {}
        _ => {
            return Err(ProviderError::deny(
                ReasonCode::ScopeUnresolved,
                "Confluence created reply container did not match the authorized container",
            ));
        }
    }
    Ok(())
}

fn validate_created_comment(
    comment: &ConfluenceComment,
    action: ConfluenceCommentAction,
    container: &ConfluenceResolvedCommentContainer,
) -> Result<(), ProviderError> {
    validate_comment_identity(comment, &comment.id, action.kind)?;
    require_current_comment(comment)?;
    if comment.parent_comment_id.is_some() {
        return Err(ProviderError::error(
            ReasonCode::UpstreamProtocolFailed,
            "Confluence created top-level comment returned a parent comment",
        ));
    }
    let Some(container_id) = comment_container_id_for_action(comment, action)? else {
        return Err(ProviderError::error(
            ReasonCode::UpstreamProtocolFailed,
            "Confluence created comment did not identify the expected container",
        ));
    };
    if container_id != container.id() {
        return Err(ProviderError::deny(
            ReasonCode::ScopeUnresolved,
            "Confluence created comment did not match the authorized container",
        ));
    }
    Ok(())
}

fn validate_created_reply(
    comment: &ConfluenceComment,
    action: ConfluenceCommentAction,
    container: &ConfluenceResolvedCommentContainer,
    parent_comment_id: &str,
) -> Result<(), ProviderError> {
    validate_comment_identity(comment, &comment.id, action.kind)?;
    require_current_comment(comment)?;
    if comment.parent_comment_id.as_deref() != Some(parent_comment_id) {
        return Err(ProviderError::error(
            ReasonCode::UpstreamProtocolFailed,
            "Confluence created reply did not identify the requested parent comment",
        ));
    }
    if let Some(container_id) = comment_container_id_for_action(comment, action)?
        && container_id != container.id()
    {
        return Err(ProviderError::deny(
            ReasonCode::ScopeUnresolved,
            "Confluence created reply did not match the authorized container",
        ));
    }
    Ok(())
}

fn comment_list_result(
    comments: &[ConfluenceComment],
    action: ConfluenceCommentAction,
    container: &ConfluenceResolvedCommentContainer,
    body_format: Option<&str>,
    has_more: bool,
    next_page_token: Option<String>,
) -> Result<Value, ProviderError> {
    let comments = comments
        .iter()
        .map(|comment| comment_result(comment, action, container, body_format))
        .collect::<Result<Vec<_>, ProviderError>>()?;
    Ok(json!({
        "comments": comments,
        "count": comments.len(),
        "hasMore": has_more,
        "nextPageToken": next_page_token,
    }))
}

fn comment_result(
    comment: &ConfluenceComment,
    action: ConfluenceCommentAction,
    container: &ConfluenceResolvedCommentContainer,
    body_format: Option<&str>,
) -> Result<Value, ProviderError> {
    let mut body = serde_json::Map::new();
    if let Some(format) = body_format {
        let Some(value) = comment.bodies.get(format) else {
            return Err(ProviderError::error(
                ReasonCode::UpstreamProtocolFailed,
                "Confluence comment response omitted the requested body format",
            ));
        };
        body.insert(
            format.to_string(),
            json!({
                "value": value,
                "representation": format,
            }),
        );
    }
    let mut value = json!({
        "commentId": comment.id,
        "kind": action.kind.as_str(),
        "containerType": action.container_type.as_str(),
        "space": container.space(),
        "status": comment.status,
        "resolutionStatus": comment.resolution_status,
        "version": comment.version,
        "author": comment.author,
        "createdAt": comment.created_at,
        "updatedAt": comment.updated_at,
        "parentCommentId": comment.parent_comment_id,
        "body": body,
    });
    match container {
        ConfluenceResolvedCommentContainer::Page(page) => {
            value["pageId"] = json!(page.id);
        }
        ConfluenceResolvedCommentContainer::Blog(blog) => {
            value["blogId"] = json!(blog.id);
            value["spaceId"] = json!(blog.space_id);
        }
    }
    Ok(value)
}

struct CommentAuditListMetadata {
    result_count: usize,
    has_more: bool,
}

fn comment_audit(
    request: &ProviderInvocation,
    container: &ConfluenceResolvedCommentContainer,
    action: ConfluenceCommentAction,
    comment_id: Option<&str>,
    body_format: Option<&str>,
    list: Option<CommentAuditListMetadata>,
    egress_proxy: Value,
) -> Value {
    let mut audit = json!({
        "provider": "confluence",
        "operation": request.action(),
        "commentKind": action.kind.as_str(),
        "containerType": action.container_type.as_str(),
        "space": container.space(),
        "credentialMode": request.credential_mode(),
        "egressProxy": egress_proxy,
    });
    if let Some(comment_id) = comment_id {
        audit["commentId"] = json!(comment_id);
    }
    if let Some(body_format) = body_format {
        audit["bodyFormat"] = json!(body_format);
    }
    if let Some(list) = list {
        audit["resultCount"] = json!(list.result_count);
        audit["hasMore"] = json!(list.has_more);
    }
    match container {
        ConfluenceResolvedCommentContainer::Page(page) => {
            audit["pageId"] = json!(page.id);
        }
        ConfluenceResolvedCommentContainer::Blog(blog) => {
            audit["blogId"] = json!(blog.id);
            audit["spaceId"] = json!(blog.space_id);
        }
    }
    audit
}

fn comment_object_ids(
    comment: &ConfluenceComment,
    container: &ConfluenceResolvedCommentContainer,
) -> Value {
    let mut ids = json!({
        "commentId": comment.id,
    });
    match container {
        ConfluenceResolvedCommentContainer::Page(page) => {
            ids["pageId"] = json!(page.id);
        }
        ConfluenceResolvedCommentContainer::Blog(blog) => {
            ids["blogId"] = json!(blog.id);
        }
    }
    ids
}

fn comment_list_object_ids(
    comments: &[ConfluenceComment],
    container: &ConfluenceResolvedCommentContainer,
) -> Value {
    let mut ids = json!({
        "commentIds": comments.iter().map(|comment| comment.id.clone()).collect::<Vec<_>>(),
    });
    match container {
        ConfluenceResolvedCommentContainer::Page(page) => {
            ids["pageId"] = json!(page.id);
        }
        ConfluenceResolvedCommentContainer::Blog(blog) => {
            ids["blogId"] = json!(blog.id);
        }
    }
    ids
}

fn enforce_blog_body_sizes(
    blog: &ConfluenceBlog,
    allowed_formats: &[String],
    byte_cap: u64,
) -> Result<(), ProviderError> {
    for format in allowed_formats {
        let Some(value) = blog.bodies.get(format) else {
            continue;
        };
        if value.len() as u64 > byte_cap {
            return Err(ProviderError::error(
                ReasonCode::UpstreamProtocolFailed,
                "Confluence blog body exceeded the configured byte cap",
            ));
        }
    }
    Ok(())
}

fn enforce_result_size(result: &Value, byte_cap: u64) -> Result<(), ProviderError> {
    let bytes = serde_json::to_vec(result).map_err(|_| {
        ProviderError::error(
            ReasonCode::UpstreamProtocolFailed,
            "failed to measure provider response",
        )
    })?;
    if bytes.len() as u64 > byte_cap {
        return Err(ProviderError::error(
            ReasonCode::UpstreamProtocolFailed,
            "provider response exceeded the configured byte cap",
        ));
    }
    Ok(())
}

fn blog_version_conflict_error(
    request: &ProviderInvocation,
    blog: &ConfluenceBlog,
    expected_base_version: u64,
    upstream_status: u16,
    upstream_duration_ms: u64,
    egress_proxy: Value,
) -> ProviderError {
    ProviderError::error(
        ReasonCode::VersionConflict,
        "Confluence blog version conflicted with the supplied base version",
    )
    .with_result(json!({
        "blogId": blog.id,
        "space": blog.space,
        "spaceId": blog.space_id,
        "expectedBaseVersion": expected_base_version,
        "currentVersion": blog.version,
    }))
    .with_audit(json!({
        "provider": "confluence",
        "operation": "blog.update",
        "blogId": blog.id,
        "space": blog.space,
        "spaceId": blog.space_id,
        "expectedBaseVersion": expected_base_version,
        "currentVersion": blog.version,
        "credentialMode": request.credential_mode(),
        "egressProxy": egress_proxy,
    }))
    .with_upstream(Some(upstream_status), Some(upstream_duration_ms))
    .with_object_ids(json!({
        "blogId": blog.id,
    }))
}

fn upstream_blog_version_conflict_error(
    request: &ProviderInvocation,
    blog: &ConfluenceBlog,
    expected_base_version: u64,
    egress_proxy: Value,
) -> ProviderError {
    ProviderError::error(
        ReasonCode::VersionConflict,
        "Confluence blog version conflicted with the supplied base version",
    )
    .with_result(json!({
        "blogId": blog.id,
        "space": blog.space,
        "spaceId": blog.space_id,
        "expectedBaseVersion": expected_base_version,
    }))
    .with_audit(json!({
        "provider": "confluence",
        "operation": "blog.update",
        "blogId": blog.id,
        "space": blog.space,
        "spaceId": blog.space_id,
        "expectedBaseVersion": expected_base_version,
        "status": "upstream_conflict",
        "credentialMode": request.credential_mode(),
        "egressProxy": egress_proxy,
    }))
    .with_upstream(Some(409), None)
    .with_object_ids(json!({
        "blogId": blog.id,
    }))
}

fn version_conflict_error(
    request: &ProviderInvocation,
    page: &ConfluencePage,
    expected_base_version: u64,
    upstream_status: u16,
    upstream_duration_ms: u64,
    egress_proxy: Value,
) -> ProviderError {
    ProviderError::error(
        ReasonCode::VersionConflict,
        "Confluence page version conflicted with the supplied base version",
    )
    .with_result(json!({
        "pageId": page.id,
        "space": page.space,
        "expectedBaseVersion": expected_base_version,
        "currentVersion": page.version,
    }))
    .with_audit(json!({
        "provider": "confluence",
        "operation": "page.update",
        "pageId": page.id,
        "space": page.space,
        "expectedBaseVersion": expected_base_version,
        "currentVersion": page.version,
        "credentialMode": request.credential_mode(),
        "egressProxy": egress_proxy,
    }))
    .with_upstream(Some(upstream_status), Some(upstream_duration_ms))
    .with_object_ids(json!({
        "pageId": page.id,
    }))
}

fn upstream_version_conflict_error(
    request: &ProviderInvocation,
    page: &ConfluencePage,
    expected_base_version: u64,
    egress_proxy: Value,
) -> ProviderError {
    ProviderError::error(
        ReasonCode::VersionConflict,
        "Confluence page version conflicted with the supplied base version",
    )
    .with_result(json!({
        "pageId": page.id,
        "space": page.space,
        "expectedBaseVersion": expected_base_version,
    }))
    .with_audit(json!({
        "provider": "confluence",
        "operation": "page.update",
        "pageId": page.id,
        "space": page.space,
        "expectedBaseVersion": expected_base_version,
        "status": "upstream_conflict",
        "credentialMode": request.credential_mode(),
        "egressProxy": egress_proxy,
    }))
    .with_upstream(Some(409), None)
    .with_object_ids(json!({
        "pageId": page.id,
    }))
}

fn confluence_blog_verification_mismatch_result(
    blog: &ConfluenceBlog,
    checked: &[Value],
    mismatch: Value,
) -> Value {
    json!({
        "verification": {
            "status": "mismatch",
            "checked": checked,
            "mismatch": mismatch,
        },
        "blogId": blog.id,
        "space": blog.space,
        "spaceId": blog.space_id,
    })
}

fn confluence_blog_verification_mismatch_error(
    request: &ProviderInvocation,
    blog: &ConfluenceBlog,
    checked: &[Value],
    mismatch: Value,
    inputs: &BlogVerifyInputs,
    egress_proxy: Value,
) -> ProviderError {
    ProviderError::allow_with_result(
        ReasonCode::VerificationMismatch,
        "Confluence blog verification mismatch",
        confluence_blog_verification_mismatch_result(blog, checked, mismatch.clone()),
    )
    .with_audit(json!({
        "provider": "confluence",
        "operation": "blog.verify",
        "blogId": blog.id,
        "space": blog.space,
        "spaceId": blog.space_id,
        "status": "mismatch",
        "checked": checked,
        "mismatch": mismatch,
        "credentialMode": request.credential_mode(),
        "egressProxy": egress_proxy,
    }))
    .with_object_ids(json!({
        "blogId": blog.id,
        "attachmentId": inputs.expect_attachment_id,
    }))
}

fn confluence_verification_mismatch_result(
    page: &ConfluencePage,
    checked: &[Value],
    mismatch: Value,
) -> Value {
    json!({
        "verification": {
            "status": "mismatch",
            "checked": checked,
            "mismatch": mismatch,
        },
        "pageId": page.id,
        "space": page.space,
    })
}

fn confluence_verification_mismatch_error(
    request: &ProviderInvocation,
    page: &ConfluencePage,
    checked: &[Value],
    mismatch: Value,
    inputs: &VerifyInputs,
    egress_proxy: Value,
) -> ProviderError {
    ProviderError::allow_with_result(
        ReasonCode::VerificationMismatch,
        "Confluence verification mismatch",
        confluence_verification_mismatch_result(page, checked, mismatch.clone()),
    )
    .with_audit(json!({
        "provider": "confluence",
        "operation": "verify",
        "pageId": page.id,
        "space": page.space,
        "status": "mismatch",
        "checked": checked,
        "mismatch": mismatch,
        "credentialMode": request.credential_mode(),
        "egressProxy": egress_proxy,
    }))
    .with_object_ids(json!({
        "pageId": page.id,
        "attachmentId": inputs.expect_attachment_id,
    }))
}

/// The receipts of a Confluence write action's mutation request. Its failures
/// keep their ordinary reason and message.
struct ConfluenceWrite {
    /// What the write targets, from the validated request and the reads
    /// before it; never from the write's own response.
    locators: Value,
}

impl ConfluenceWrite {
    fn new(locators: Value) -> Self {
        Self { locators }
    }

    fn locators(&self) -> Value {
        self.locators.clone()
    }

    /// [`Self::failed_with`] the ordinary mapping.
    fn failed(&self, error: ConfluenceBackendError) -> ProviderError {
        self.failed_with(error, confluence_backend_error)
    }

    /// The failure of the mutation request itself, mapped by `map`:
    ///
    /// - proven unsent: `not_applied`;
    /// - no response, a 5xx a proxy may return after Confluence committed the
    ///   write, or a redirect the Broker never follows: `unknown`;
    /// - a success status whose response then failed: `applied_unverified`;
    /// - a rejection, or a failure before anything was sent: no receipt.
    fn failed_with(
        &self,
        error: ConfluenceBackendError,
        map: impl FnOnce(ConfluenceBackendError) -> ProviderError,
    ) -> ProviderError {
        let receipt = match &error {
            ConfluenceBackendError::NotSent { .. } => Some(MutationReceipt::not_applied()),
            ConfluenceBackendError::NoResponse { .. }
            | ConfluenceBackendError::Redirected
            | ConfluenceBackendError::HttpStatus(500..=599) => Some(MutationReceipt::unknown()),
            ConfluenceBackendError::AcceptedUnreadable(_) => Some(
                MutationReceipt::applied_unverified("mutation_response", self.locators()),
            ),
            ConfluenceBackendError::Unauthorized
            | ConfluenceBackendError::Forbidden
            | ConfluenceBackendError::NotFound
            | ConfluenceBackendError::Conflict
            | ConfluenceBackendError::HttpStatus(_)
            | ConfluenceBackendError::RateLimited(_)
            | ConfluenceBackendError::Validation { .. }
            | ConfluenceBackendError::Transport(_)
            | ConfluenceBackendError::Timeout
            | ConfluenceBackendError::ResponseTooLarge
            | ConfluenceBackendError::Protocol(_) => None,
        };
        let failure = map(error);
        match receipt {
            Some(receipt) => failure.with_mutation_receipt(receipt),
            None => failure,
        }
    }
}

/// Runs what follows a write Confluence accepted: a failure that reports no
/// receipt keeps its reason and gains `applied_unverified` at `stage`.
async fn after_accepted_write(
    stage: &str,
    locators: Value,
    tail: impl Future<Output = Result<ProviderResult, ProviderError>>,
) -> Result<ProviderResult, ProviderError> {
    tail.await.map_err(|error| {
        error.or_mutation_receipt(MutationReceipt::applied_unverified(stage, locators))
    })
}

/// Whether an upload that failed may still have created its attachment.
fn upload_may_have_applied(error: &ConfluenceBackendError) -> bool {
    matches!(
        error,
        ConfluenceBackendError::NoResponse { .. }
            | ConfluenceBackendError::Redirected
            | ConfluenceBackendError::HttpStatus(500..=599)
            | ConfluenceBackendError::AcceptedUnreadable(_)
    )
}

fn sanitized_backend_reason(error: &ConfluenceBackendError) -> &'static str {
    match error {
        ConfluenceBackendError::AcceptedUnreadable(error) => sanitized_backend_reason(error),
        ConfluenceBackendError::Unauthorized => "unauthorized",
        ConfluenceBackendError::Forbidden => "forbidden",
        ConfluenceBackendError::NotFound => "not_found",
        ConfluenceBackendError::Conflict | ConfluenceBackendError::HttpStatus(_) => {
            "upstream_failed"
        }
        ConfluenceBackendError::RateLimited(_) => "upstream_rate_limited",
        ConfluenceBackendError::Validation { .. } => "input_invalid",
        ConfluenceBackendError::NotSent { timed_out: false }
        | ConfluenceBackendError::NoResponse { timed_out: false }
        | ConfluenceBackendError::Transport(_) => "upstream_connection_failed",
        ConfluenceBackendError::NotSent { timed_out: true }
        | ConfluenceBackendError::NoResponse { timed_out: true }
        | ConfluenceBackendError::Timeout => "upstream_timeout",
        ConfluenceBackendError::ResponseTooLarge
        | ConfluenceBackendError::Redirected
        | ConfluenceBackendError::Protocol(_) => "upstream_protocol_failed",
    }
}

fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn media_type_allowed(value: &str, allowed: &[String]) -> bool {
    let Some(value) = media_type_essence(value) else {
        return false;
    };
    allowed
        .iter()
        .filter_map(|allowed| media_type_essence(allowed))
        .any(|allowed| allowed == value)
}

fn media_type_essence(value: &str) -> Option<String> {
    let essence = value
        .split(';')
        .next()
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase();
    (!essence.is_empty() && essence.contains('/')).then_some(essence)
}

fn validate_page_draft_body_format(value: &str) -> Result<(), ProviderError> {
    if value == "storage" {
        Ok(())
    } else {
        Err(ProviderError::deny(
            ReasonCode::BodyFormatUnsupported,
            "Confluence page draft body format is not supported",
        ))
    }
}

fn validate_blog_body_format(value: &str) -> Result<(), ProviderError> {
    if value == "storage" {
        Ok(())
    } else {
        Err(ProviderError::deny(
            ReasonCode::BodyFormatUnsupported,
            "Confluence blog body format is not supported",
        ))
    }
}

fn validate_draft_handle_input(value: &str) -> Result<(), ProviderError> {
    if value.starts_with(DRAFT_HANDLE_PREFIX) && value.len() <= DRAFT_HANDLE_MAX_BYTES {
        Ok(())
    } else {
        Err(invalid_draft_handle_error())
    }
}

fn validate_draft_verify_expectations(
    expect_version: Option<u64>,
    expect_title: Option<&str>,
    expect_attachment_id: Option<&str>,
    action: &str,
) -> Result<(), ProviderError> {
    if expect_version.is_none() && expect_title.is_none() && expect_attachment_id.is_none() {
        return Err(ProviderError::deny(
            ReasonCode::InputInvalid,
            format!("{action} requires at least one expected value"),
        ));
    }
    if expect_version == Some(0) {
        return Err(ProviderError::deny(
            ReasonCode::InputInvalid,
            format!("{action} expectVersion must be greater than zero"),
        ));
    }
    if let Some(attachment_id) = expect_attachment_id {
        validate_attachment_id(attachment_id)?;
    }
    Ok(())
}

fn validate_comment_read_body_format(value: &str) -> Result<(), ProviderError> {
    if value == "storage" {
        Ok(())
    } else {
        Err(ProviderError::deny(
            ReasonCode::BodyFormatUnsupported,
            "Confluence comment body format is not supported",
        ))
    }
}

fn validate_comment_resolution_status(value: &str) -> Result<(), ProviderError> {
    if matches!(value, "open" | "reopened" | "resolved" | "dangling") {
        Ok(())
    } else {
        Err(ProviderError::deny(
            ReasonCode::InputInvalid,
            "Confluence inline comment resolutionStatus is invalid",
        ))
    }
}

fn validate_comment_sort(value: &str) -> Result<(), ProviderError> {
    if matches!(
        value,
        "created-date" | "-created-date" | "modified-date" | "-modified-date"
    ) {
        Ok(())
    } else {
        Err(ProviderError::deny(
            ReasonCode::InputInvalid,
            "Confluence comment sort is invalid",
        ))
    }
}

fn validate_non_empty_storage_body(value: &str) -> Result<(), ProviderError> {
    if value.trim().is_empty() {
        Err(ProviderError::deny(
            ReasonCode::BodyMalformed,
            "Confluence storage body must be a non-empty string",
        ))
    } else {
        Ok(())
    }
}

fn validate_page_title(value: &str) -> Result<(), ProviderError> {
    if value.trim().is_empty() {
        Err(ProviderError::deny(
            ReasonCode::InputInvalid,
            "Confluence page title must not be empty",
        ))
    } else {
        Ok(())
    }
}

fn validate_atlas_doc_format_body(value: &Value) -> Result<(), ProviderError> {
    if value.get("type").and_then(Value::as_str) != Some("doc")
        || value.get("version").and_then(Value::as_u64) != Some(1)
        || !value.get("content").is_some_and(Value::is_array)
    {
        return Err(ProviderError::deny(
            ReasonCode::BodyMalformed,
            "atlas_doc_format body must be an Atlassian document",
        ));
    }
    Ok(())
}

fn validate_page_id(value: &str) -> Result<String, ProviderError> {
    if !is_page_id(value) {
        return Err(ProviderError::deny(
            ReasonCode::InputInvalid,
            "Confluence page ID is invalid",
        ));
    }
    Ok(value.to_string())
}

fn validate_blog_id(value: &str) -> Result<String, ProviderError> {
    if !is_blog_id(value) {
        return Err(ProviderError::deny(
            ReasonCode::InputInvalid,
            "Confluence blog ID is invalid",
        ));
    }
    Ok(value.to_string())
}

fn validate_attachment_id(value: &str) -> Result<String, ProviderError> {
    if !is_attachment_id(value) {
        return Err(ProviderError::deny(
            ReasonCode::InputInvalid,
            "Confluence attachment ID is invalid",
        ));
    }
    Ok(value.to_string())
}

fn validate_comment_id(value: &str) -> Result<String, ProviderError> {
    if !is_page_id(value) {
        return Err(ProviderError::deny(
            ReasonCode::InputInvalid,
            "Confluence comment ID is invalid",
        ));
    }
    Ok(value.to_string())
}

fn validate_space_key(value: &str) -> Result<String, ProviderError> {
    if !is_space_key(value) {
        return Err(ProviderError::deny(
            ReasonCode::InputInvalid,
            "Confluence space key is invalid",
        ));
    }
    Ok(value.to_string())
}

fn is_page_id(value: &str) -> bool {
    page_id_re().is_match(value)
}

fn is_blog_id(value: &str) -> bool {
    page_id_re().is_match(value)
}

fn is_space_key(value: &str) -> bool {
    space_key_re().is_match(value)
}

fn is_attachment_id(value: &str) -> bool {
    attachment_id_re().is_match(value)
}

fn is_confluence_content_id(value: &str) -> bool {
    attachment_id_re().is_match(value)
}

fn is_confluence_tree_content_type(value: &str) -> bool {
    matches!(
        value,
        "database" | "embed" | "folder" | "page" | "whiteboard"
    )
}

fn page_id_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"^[1-9][0-9]*$").expect("page id regex"))
}

fn attachment_id_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$").expect("attachment id regex")
    })
}

fn space_key_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        // Personal keys are literal upstream identifiers, not Broker usernames.
        // Keep both forms bounded to 255 ASCII bytes and safe as one URL segment.
        Regex::new(r"^(?:[A-Z][A-Z0-9_-]{1,254}|~[A-Za-z0-9][A-Za-z0-9._@:+-]{0,253})$")
            .expect("space key regex")
    })
}

fn cql_date_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}$").expect("CQL date regex"))
}

fn cql_datetime_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"^(?P<date>[0-9]{4}-[0-9]{2}-[0-9]{2}) (?P<time>[0-9]{2}:[0-9]{2})$")
            .expect("CQL datetime regex")
    })
}
