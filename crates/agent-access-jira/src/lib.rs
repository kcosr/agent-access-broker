//! Jira backend: issue, search, comment, attachment, and verification
//! actions against Jira Cloud, authorized against `jira_project`
//! resources.
mod backend;
mod config;
mod jql;
mod present;
mod search_continuation;
mod search_diagnostics;
#[cfg(test)]
mod tests;
mod validation;

pub use backend::*;
pub use config::*;
use jql::*;
use search_continuation::*;
use validation::*;

use agent_access_atlassian::{AtlassianAuthorization, validate_atlassian_gateway_credential};
use agent_access_content::append_adf_attribution;
use agent_access_content::{ContentWriteError, markdown_to_adf_bounded, plain_text_to_adf_bounded};
#[allow(unused_imports)]
use agent_access_provider::*;
use async_trait::async_trait;
use percent_encoding::{AsciiSet, CONTROLS, utf8_percent_encode};
use regex::Regex;
use reqwest::Method;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant, SystemTime};
use thiserror::Error;
use url::Url;

const JIRA_PROJECT_KEY_PATTERN: &str = r"^[A-Z][A-Z0-9_]+$";
const JIRA_ISSUE_KEY_PATTERN: &str = r"^[A-Z][A-Z0-9_]+-[1-9][0-9]*$";

const JIRA_PATH_SEGMENT_ENCODE_SET: &AsciiSet = &CONTROLS
    .add(b' ')
    .add(b'"')
    .add(b'#')
    .add(b'%')
    .add(b'/')
    .add(b':')
    .add(b'<')
    .add(b'>')
    .add(b'?')
    .add(b'[')
    .add(b'\\')
    .add(b']')
    .add(b'^')
    .add(b'`')
    .add(b'{')
    .add(b'|')
    .add(b'}');

#[derive(Clone)]
pub struct JiraProvider {
    config: JiraProviderConfig,
    limits: ProviderLimits,
    backend: Arc<dyn JiraBackend>,
    attribution: ProviderAttributionConfig,
    /// Search continuations, sealed with this instance's generation key.
    search_pages: SearchPages,
    search_configuration: [u8; 32],
}

impl JiraProvider {
    pub(crate) fn new(
        config: JiraProviderConfig,
        host: &BuildContext<'_>,
    ) -> Result<Self, ProviderBuildError> {
        let limits = host.limits().clone();
        let backend = Arc::new(HttpJiraBackend::new(
            config.clone(),
            limits.clone(),
            host.clients(),
        )?);
        Ok(Self {
            search_pages: SearchPages::new(&limits),
            search_configuration: config.site().route_fingerprint(),
            config,
            limits,
            backend,
            attribution: host.attribution().clone(),
        })
    }

    fn from_backend(
        config: JiraProviderConfig,
        limits: ProviderLimits,
        backend: Arc<dyn JiraBackend>,
    ) -> Self {
        Self {
            search_pages: SearchPages::new(&limits),
            search_configuration: config.site().route_fingerprint(),
            config,
            limits,
            backend,
            attribution: ProviderAttributionConfig::default(),
        }
    }

    pub fn with_backend(
        config: JiraProviderConfig,
        limits: ProviderLimits,
        backend: Arc<dyn JiraBackend>,
    ) -> Self {
        Self::from_backend(config, limits, backend)
    }
}

/// Jira projects, identified by project key.
pub static JIRA_PROJECT_RESOURCE: ResourceTypeDescriptor = ResourceTypeDescriptor::new(
    ResourceType::from_static("jira_project"),
    "Jira project",
    "Jira projects",
    "ENG",
    is_project_key,
);

/// Jira's authoritative service definition. Every action is authorized
/// against a project; comment writes are offered only while ADF comment
/// bodies are enabled.
pub fn jira_descriptor(config: &JiraProviderConfig) -> ServiceDescriptor {
    let mut actions = vec![
        jira_read_action(
            "issue_type.list",
            "List Jira issue types available for creation in an authorized project, including IDs and descriptions",
            json!({
                "type": "object",
                "required": ["project"],
                "properties": {
                    "project": { "type": "string", "pattern": JIRA_PROJECT_KEY_PATTERN, "description": "Uppercase Jira project key; underscores are supported" },
                    "startAt": { "type": "integer", "minimum": 0, "maximum": u32::MAX, "default": 0 },
                    "maxResults": { "type": "integer", "minimum": 1, "maximum": 100, "default": 50 }
                },
                "additionalProperties": false
            }),
        )
        .documentation(json!({
            "semantics": "Returns one page of creation metadata using the selected execution credential. Jira requires Create issues permission for the project. This is not a general inventory for browse-only users.",
            "pagination": "startAt defaults to 0; maxResults defaults to 50 and must be 1-100. Follow nextStartAt until it is null (isLast=true). Each page is independently authorized; metadata can change between calls.",
            "issueTypes": "Each entry contains id, name, description and subtask. IDs are decimal strings: pass id directly as issueTypeId to issue.create or issue.child.create. A missing upstream description is returned as an empty string.",
            "creation": "Discovery does not authorize a create action. Keep discovery and creation credential selection aligned. Required fields and parent hierarchy constraints can still prevent creation; the broker's create actions do not accept arbitrary custom fields."
        })),
        jira_read_action(
            "issue.view",
            "View a Jira issue and ADF description after project-scope confirmation",
            json!({
                "type": "object",
                "oneOf": [
                    { "required": ["issue"] },
                    { "required": ["url"] }
                ],
                "properties": {
                    "issue": { "type": "string" },
                    "url": { "type": "string" }
                },
                "additionalProperties": false
            }),
        )
        .lookup(LookupRequirement::ScopeResolution),
        jira_action(
            "issue.create",
            "Create a Jira issue in an authorized project with bounded summary and optional explicitly formatted content",
            json!({
                "type": "object",
                "required": ["project", "issueTypeId", "summary"],
                "allOf": [
                    {
                        "oneOf": [
                            { "required": ["content", "contentFormat"] },
                            {
                                "not": {
                                    "anyOf": [
                                        { "required": ["content"] },
                                        { "required": ["contentFormat"] }
                                    ]
                                }
                            }
                        ]
                    },
                    { "if": { "properties": { "contentFormat": { "const": "adf" } }, "required": ["contentFormat"] }, "then": { "properties": { "content": { "type": "object" } } } },
                    { "if": { "properties": { "contentFormat": { "enum": ["markdown", "plain_text"] } }, "required": ["contentFormat"] }, "then": { "properties": { "content": { "type": "string" } } } }
                ],
                "properties": {
                    "project": {
                        "type": "string",
                        "description": "Uppercase Jira project key"
                    },
                    "issueTypeId": {
                        "type": "string",
                        "description": "Decimal ID from jira.issue_type.list for this project"
                    },
                    "summary": {
                        "type": "string",
                        "description": "1-1024 UTF-8 bytes after broker validation; must not contain NUL, CR, or LF"
                    },
                    "contentFormat": { "type": "string", "enum": ["adf", "markdown", "plain_text"] },
                    "content": {}
                },
                "additionalProperties": false
            }),
        )
        .attribution(AttributionCapability::optional(
            AttributionVerb::Add,
            "description",
            AttributionRepresentation::Adf,
        )),
        jira_action(
            "issue.child.create",
            "Create a Jira issue under an authorized parent issue using Jira parent",
            json!({
                "type": "object",
                "required": ["project", "issueTypeId", "summary"],
                "oneOf": [
                    { "required": ["parentIssue"] },
                    { "required": ["parentUrl"] }
                ],
                "properties": {
                    "project": {
                        "type": "string",
                        "description": "Uppercase Jira project key"
                    },
                    "issueTypeId": {
                        "type": "string",
                        "description": "Decimal ID from jira.issue_type.list for this project"
                    },
                    "summary": {
                        "type": "string",
                        "description": "1-1024 UTF-8 bytes after broker validation; must not contain NUL, CR, or LF"
                    },
                    "parentIssue": { "type": "string" },
                    "parentUrl": { "type": "string" },
                    "contentFormat": { "type": "string", "enum": ["adf", "markdown", "plain_text"] },
                    "content": {}
                },
                "allOf": [
                    {
                        "oneOf": [
                            { "required": ["content", "contentFormat"] },
                            { "not": { "anyOf": [{ "required": ["content"] }, { "required": ["contentFormat"] }] } }
                        ]
                    },
                    { "if": { "properties": { "contentFormat": { "const": "adf" } }, "required": ["contentFormat"] }, "then": { "properties": { "content": { "type": "object" } } } },
                    { "if": { "properties": { "contentFormat": { "enum": ["markdown", "plain_text"] } }, "required": ["contentFormat"] }, "then": { "properties": { "content": { "type": "string" } } } }
                ],
                "additionalProperties": false
            }),
        )
        .lookup(LookupRequirement::ScopeResolution)
        .attribution(AttributionCapability::optional(
            AttributionVerb::Add,
            "description",
            AttributionRepresentation::Adf,
        )),
        jira_action(
            "issue.update",
            "Update a Jira issue summary and/or explicitly formatted content after project confirmation",
            json!({
                "type": "object",
                "oneOf": [
                    { "required": ["issue"] },
                    { "required": ["url"] }
                ],
                "anyOf": [{ "required": ["summary"] }, { "required": ["content", "contentFormat"] }],
                "allOf": [
                    {
                        "oneOf": [
                            { "required": ["content", "contentFormat"] },
                            { "not": { "anyOf": [{ "required": ["content"] }, { "required": ["contentFormat"] }] } }
                        ]
                    },
                    { "if": { "properties": { "contentFormat": { "const": "adf" } }, "required": ["contentFormat"] }, "then": { "properties": { "content": { "type": "object" } } } },
                    { "if": { "properties": { "contentFormat": { "enum": ["markdown", "plain_text"] } }, "required": ["contentFormat"] }, "then": { "properties": { "content": { "type": "string" } } } }
                ],
                "properties": {
                    "issue": { "type": "string" },
                    "url": { "type": "string" },
                    "summary": {
                        "type": "string",
                        "description": "1-1024 UTF-8 bytes after broker validation; must not contain NUL, CR, or LF"
                    },
                    "contentFormat": { "type": "string", "enum": ["adf", "markdown", "plain_text"] },
                    "content": {},
                    "notifyUsers": { "type": "boolean" }
                },
                "additionalProperties": false
            }),
        )
        .lookup(LookupRequirement::ScopeResolution)
        .attribution(AttributionCapability::optional(
            AttributionVerb::Update,
            "description",
            AttributionRepresentation::Adf,
        )),
        jira_action(
            "issue.parent.set",
            "Assign one authorized Jira issue to an authorized parent issue",
            json!({
                "type": "object",
                "allOf": [
                    {
                        "oneOf": [
                            { "required": ["issue"] },
                            { "required": ["url"] }
                        ]
                    },
                    {
                        "oneOf": [
                            { "required": ["parentIssue"] },
                            { "required": ["parentUrl"] }
                        ]
                    }
                ],
                "properties": {
                    "issue": { "type": "string" },
                    "url": { "type": "string" },
                    "parentIssue": { "type": "string" },
                    "parentUrl": { "type": "string" }
                },
                "additionalProperties": false
            }),
        )
        .lookup(LookupRequirement::ScopeResolution),
        jira_action(
            "issue.dependency.add",
            "Declare that one authorized Jira issue blocks another authorized Jira issue",
            json!({
                "type": "object",
                "allOf": [
                    {
                        "oneOf": [
                            { "required": ["blockingIssue"] },
                            { "required": ["blockingUrl"] }
                        ]
                    },
                    {
                        "oneOf": [
                            { "required": ["blockedIssue"] },
                            { "required": ["blockedUrl"] }
                        ]
                    }
                ],
                "properties": {
                    "blockingIssue": { "type": "string" },
                    "blockingUrl": { "type": "string" },
                    "blockedIssue": { "type": "string" },
                    "blockedUrl": { "type": "string" }
                },
                "additionalProperties": false
            }),
        )
        .lookup(LookupRequirement::ScopeResolution),
        jira_read_action(
            "search",
            "Search Jira issues using authorized projects; omit projects to use effective access. Empty or ORDER BY-only JQL requires a finite project scope.",
            json!({
                "type": "object",
                "required": ["query"],
                "properties": {
                    "query": {
                        "type": "object",
                        "required": ["type", "value"],
                        "properties": {
                            "type": { "type": "string", "enum": ["jql", "text"] },
                            "value": { "type": "string", "description": "JQL subset or nonempty plain text. Example JQL: status = Done ORDER BY updated DESC. Empty or ORDER BY-only JQL browses a finite authorized project set." }
                        },
                        "additionalProperties": false
                    },
                    "projects": {
                        "description": "Optional authorized project narrowing. Omit to use effective broker permissions, including token restrictions and exclusions.",
                        "type": "array",
                        "items": { "type": "string" },
                        "minItems": 1
                    },
                    "maxResults": { "type": "integer", "minimum": 1, "description": "Requested page size, capped by broker configuration." },
                    "nextPageToken": { "type": "string", "minLength": 1, "description": "Opaque continuation from the previous response; reuse the same query, projects, and maxResults." }
                },
                "additionalProperties": false
            }),
        )
        .search_contained()
        .documentation(jql_documentation()),
        jira_read_action(
            "comment.list",
            "List Jira issue comment metadata after project confirmation",
            json!({
                "type": "object",
                "oneOf": [
                    { "required": ["issue"] },
                    { "required": ["url"] }
                ],
                "properties": {
                    "issue": { "type": "string" },
                    "url": { "type": "string" },
                    "maxResults": { "type": "integer", "minimum": 1 },
                    "startAt": { "type": "integer", "minimum": 0 },
                    "orderBy": { "type": "string", "enum": ["created", "-created", "+created"] }
                },
                "additionalProperties": false
            }),
        )
        .lookup(LookupRequirement::ScopeResolution),
        jira_read_action(
            "comment.view",
            "View one Jira issue comment body after project confirmation",
            json!({
                "type": "object",
                "oneOf": [
                    { "required": ["issue"] },
                    { "required": ["url"] }
                ],
                "required": ["commentId"],
                "properties": {
                    "issue": { "type": "string" },
                    "url": { "type": "string" },
                    "commentId": { "type": "string" }
                },
                "additionalProperties": false
            }),
        )
        .lookup(LookupRequirement::ScopeResolution),
        jira_action(
            "comment.add",
            "Add an explicitly formatted Jira issue comment after project confirmation",
            json!({
                "type": "object",
                "oneOf": [
                    { "required": ["issue"] },
                    { "required": ["url"] }
                ],
                "required": ["contentFormat", "content"],
                "allOf": [
                    { "if": { "properties": { "contentFormat": { "const": "adf" } }, "required": ["contentFormat"] }, "then": { "properties": { "content": { "type": "object" } } } },
                    { "if": { "properties": { "contentFormat": { "enum": ["markdown", "plain_text"] } }, "required": ["contentFormat"] }, "then": { "properties": { "content": { "type": "string" } } } }
                ],
                "properties": {
                    "issue": { "type": "string" },
                    "url": { "type": "string" },
                    "contentFormat": { "type": "string", "enum": ["adf", "markdown", "plain_text"] },
                    "content": {},
                    "visibility": {
                        "type": "object",
                        "required": ["type"],
                        "properties": {
                            "type": { "type": "string", "enum": ["role", "group"] },
                            "value": { "type": "string" },
                            "identifier": { "type": "string" }
                        },
                        "additionalProperties": false
                    }
                },
                "additionalProperties": false
            }),
        )
        .lookup(LookupRequirement::ScopeResolution)
        .attribution(AttributionCapability::required(
            AttributionVerb::Add,
            "body",
            AttributionRepresentation::Adf,
        )),
        jira_action(
            "comment.reply",
            "Reply to a Jira issue comment after project confirmation",
            json!({
                "type": "object",
                "oneOf": [
                    { "required": ["issue"] },
                    { "required": ["url"] }
                ],
                "required": ["parentCommentId", "contentFormat", "content"],
                "allOf": [
                    { "if": { "properties": { "contentFormat": { "const": "adf" } }, "required": ["contentFormat"] }, "then": { "properties": { "content": { "type": "object" } } } },
                    { "if": { "properties": { "contentFormat": { "enum": ["markdown", "plain_text"] } }, "required": ["contentFormat"] }, "then": { "properties": { "content": { "type": "string" } } } }
                ],
                "properties": {
                    "issue": { "type": "string" },
                    "url": { "type": "string" },
                    "parentCommentId": { "type": "string" },
                    "contentFormat": { "type": "string", "enum": ["adf", "markdown", "plain_text"] },
                    "content": {},
                    "visibility": {
                        "type": "object",
                        "required": ["type"],
                        "properties": {
                            "type": { "type": "string", "enum": ["role", "group"] },
                            "value": { "type": "string" },
                            "identifier": { "type": "string" }
                        },
                        "additionalProperties": false
                    }
                },
                "additionalProperties": false
            }),
        )
        .lookup(LookupRequirement::ScopeResolution)
        .attribution(AttributionCapability::required(
            AttributionVerb::Add,
            "body",
            AttributionRepresentation::Adf,
        )),
        jira_action(
            "comment.update",
            "Update an explicitly formatted Jira issue comment after project confirmation",
            json!({
                "type": "object",
                "oneOf": [
                    { "required": ["issue"] },
                    { "required": ["url"] }
                ],
                "required": ["commentId", "contentFormat", "content"],
                "allOf": [
                    { "if": { "properties": { "contentFormat": { "const": "adf" } }, "required": ["contentFormat"] }, "then": { "properties": { "content": { "type": "object" } } } },
                    { "if": { "properties": { "contentFormat": { "enum": ["markdown", "plain_text"] } }, "required": ["contentFormat"] }, "then": { "properties": { "content": { "type": "string" } } } }
                ],
                "properties": {
                    "issue": { "type": "string" },
                    "url": { "type": "string" },
                    "commentId": { "type": "string" },
                    "contentFormat": { "type": "string", "enum": ["adf", "markdown", "plain_text"] },
                    "content": {},
                    "visibilityMode": { "type": "string", "enum": ["preserve", "set"] },
                    "visibility": {
                        "type": "object",
                        "required": ["type"],
                        "properties": {
                            "type": { "type": "string", "enum": ["role", "group"] },
                            "value": { "type": "string" },
                            "identifier": { "type": "string" }
                        },
                        "additionalProperties": false
                    },
                    "notifyUsers": { "type": "boolean" }
                },
                "additionalProperties": false
            }),
        )
        .lookup(LookupRequirement::ScopeResolution)
        .attribution(AttributionCapability::required(
            AttributionVerb::Update,
            "body",
            AttributionRepresentation::Adf,
        )),
        jira_action(
            "comment.delete",
            "Delete a Jira issue comment after project confirmation",
            json!({
                "type": "object",
                "oneOf": [
                    { "required": ["issue"] },
                    { "required": ["url"] }
                ],
                "required": ["commentId"],
                "properties": {
                    "issue": { "type": "string" },
                    "url": { "type": "string" },
                    "commentId": { "type": "string" }
                },
                "additionalProperties": false
            }),
        )
        .lookup(LookupRequirement::ScopeResolution),
        jira_read_action(
            "comment.property.list",
            "List broker-allowed Jira issue comment property keys",
            json!({
                "type": "object",
                "oneOf": [
                    { "required": ["issue"] },
                    { "required": ["url"] }
                ],
                "required": ["commentId"],
                "properties": {
                    "issue": { "type": "string" },
                    "url": { "type": "string" },
                    "commentId": { "type": "string" }
                },
                "additionalProperties": false
            }),
        )
        .lookup(LookupRequirement::ScopeResolution),
        jira_read_action(
            "comment.property.get",
            "Get one broker-allowed Jira issue comment property",
            json!({
                "type": "object",
                "oneOf": [
                    { "required": ["issue"] },
                    { "required": ["url"] }
                ],
                "required": ["commentId", "propertyKey"],
                "properties": {
                    "issue": { "type": "string" },
                    "url": { "type": "string" },
                    "commentId": { "type": "string" },
                    "propertyKey": { "type": "string" }
                },
                "additionalProperties": false
            }),
        )
        .lookup(LookupRequirement::ScopeResolution),
        jira_action(
            "comment.property.set",
            "Set one broker-allowed Jira issue comment property",
            json!({
                "type": "object",
                "oneOf": [
                    { "required": ["issue"] },
                    { "required": ["url"] }
                ],
                "required": ["commentId", "propertyKey", "value"],
                "properties": {
                    "issue": { "type": "string" },
                    "url": { "type": "string" },
                    "commentId": { "type": "string" },
                    "propertyKey": { "type": "string" },
                    "value": {}
                },
                "additionalProperties": false
            }),
        )
        .lookup(LookupRequirement::ScopeResolution),
        jira_action(
            "comment.property.delete",
            "Delete one broker-allowed Jira issue comment property",
            json!({
                "type": "object",
                "oneOf": [
                    { "required": ["issue"] },
                    { "required": ["url"] }
                ],
                "required": ["commentId", "propertyKey"],
                "properties": {
                    "issue": { "type": "string" },
                    "url": { "type": "string" },
                    "commentId": { "type": "string" },
                    "propertyKey": { "type": "string" }
                },
                "additionalProperties": false
            }),
        )
        .lookup(LookupRequirement::ScopeResolution),
        jira_action(
            "attachment.add",
            "Upload bounded Jira issue attachments after project confirmation",
            json!({
                "type": "object",
                "required": ["issue", "attachments"],
                "properties": {
                    "issue": { "type": "string" },
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
        .lookup(LookupRequirement::ScopeResolution)
        .multipart_upload(attachment_upload_plan(&["issue"], None)),
        jira_read_action(
            "attachment.download",
            "Download a bounded Jira issue attachment after membership checks",
            json!({
                "type": "object",
                "required": ["issue", "attachmentId"],
                "properties": {
                    "issue": { "type": "string" },
                    "attachmentId": { "type": "string" }
                },
                "additionalProperties": false
            }),
        )
        .lookup(LookupRequirement::ScopeResolution)
        .raw_download(),
        jira_read_action(
            "attachment.list",
            "List bounded Jira issue attachment metadata after project confirmation",
            json!({
                "type": "object",
                "oneOf": [
                    { "required": ["issue"] },
                    { "required": ["url"] }
                ],
                "properties": {
                    "issue": { "type": "string" },
                    "url": { "type": "string" }
                },
                "additionalProperties": false
            }),
        )
        .lookup(LookupRequirement::ScopeResolution),
        jira_read_action(
            "verify",
            "Verify Jira comment or attachment existence on an issue",
            json!({
                "type": "object",
                "required": ["issue"],
                "properties": {
                    "issue": { "type": "string" },
                    "expectCommentId": { "type": "string" },
                    "expectAttachmentId": { "type": "string" }
                },
                "additionalProperties": false
            }),
        )
        .lookup(LookupRequirement::ScopeResolution),
    ];
    if !config
        .content
        .comment_formats
        .iter()
        .any(|format| format == "adf")
    {
        actions.retain(|action| {
            !matches!(
                action.action.as_str(),
                "comment.add" | "comment.reply" | "comment.update"
            )
        });
    }
    let mut credentials =
        CredentialDescriptor::default().profile("jira-cloud-api-token", "basic_api_token");
    if config.site().uses_gateway() {
        credentials = credentials.profile("jira-bearer-token", "bearer_token");
    }
    ServiceDescriptor::new("jira", "Jira")
        .with_resource_scopes(BTreeMap::from([(
            "project".to_string(),
            ResourceScopeCapabilities::new(
                crate::JIRA_PROJECT_RESOURCE.id().clone(),
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

fn jira_read_action(action: &str, description: &str, input_schema: Value) -> ActionDescriptor {
    jira_action(action, description, input_schema).read_only()
}

fn jira_action(action: &str, description: &str, input_schema: Value) -> ActionDescriptor {
    ActionDescriptor::new(action, description, input_schema)
        .scope("project")
        .credential_modes(["service", "per_user"])
}

impl JiraProvider {
    fn local_scopes(&self, action: &str, inputs: &Value) -> Result<ResourceScopes, ProviderError> {
        match action {
            "issue_type.list" => {
                let inputs = parse_issue_type_list_inputs(inputs)?;
                Ok(BTreeMap::from([(
                    "project".to_string(),
                    vec![inputs.project],
                )]))
            }
            "issue.create" => {
                let inputs = parse_issue_create_scope_inputs(inputs)?;
                let mut scopes = ResourceScopes::new();
                scopes.insert("project".to_string(), vec![inputs.project]);
                Ok(scopes)
            }
            "issue.view"
            | "issue.update"
            | "issue.child.create"
            | "issue.parent.set"
            | "issue.dependency.add"
            | "comment.list"
            | "comment.view"
            | "comment.add"
            | "comment.reply"
            | "comment.update"
            | "comment.delete"
            | "comment.property.list"
            | "comment.property.get"
            | "comment.property.set"
            | "comment.property.delete"
            | "attachment.add"
            | "attachment.download"
            | "attachment.list"
            | "verify" => {
                if action == "issue.dependency.add" {
                    let inputs = parse_issue_dependency_add_inputs(inputs, &self.config)?;
                    Ok(merged_issue_locator_scopes([
                        &inputs.blocking,
                        &inputs.blocked,
                    ]))
                } else if action == "issue.parent.set" {
                    let inputs = parse_issue_parent_set_inputs(inputs, &self.config)?;
                    Ok(merged_issue_locator_scopes([&inputs.issue, &inputs.parent]))
                } else if action == "issue.child.create" {
                    let inputs = parse_issue_child_create_scope_inputs(inputs, &self.config)?;
                    Ok(child_create_locator_scopes(&inputs.project, &inputs.parent))
                } else {
                    let locator = issue_locator_from_inputs(inputs, &self.config)?;
                    let mut scopes = ResourceScopes::new();
                    scopes.insert("project".to_string(), vec![locator.candidate_project]);
                    Ok(scopes)
                }
            }
            "search" => {
                let inputs = parse_search_inputs(inputs)?;
                let requested = requested_projects(&inputs)?;
                let mut scopes = ResourceScopes::new();
                scopes.insert("project".to_string(), requested.into_iter().collect());
                Ok(scopes)
            }
            _ => Err(ProviderError::deny(
                ReasonCode::ServiceActionDenied,
                "Jira action is not supported",
            )),
        }
    }
}

impl JiraProvider {
    async fn lookup_scopes(
        &self,
        action: &str,
        inputs: &Value,
        lookup_credential: Option<&ExecutionCredential>,
    ) -> Result<ResourceScopes, ProviderError> {
        match action {
            "issue.view"
            | "issue.update"
            | "issue.child.create"
            | "issue.parent.set"
            | "issue.dependency.add"
            | "comment.list"
            | "comment.view"
            | "comment.add"
            | "comment.reply"
            | "comment.update"
            | "comment.delete"
            | "comment.property.list"
            | "comment.property.get"
            | "comment.property.set"
            | "comment.property.delete"
            | "attachment.add"
            | "attachment.download"
            | "attachment.list"
            | "verify" => {
                let credential = lookup_credential.ok_or_else(|| {
                    ProviderError::deny(
                        ReasonCode::CredentialNotProvisioned,
                        "lookup credential is not provisioned",
                    )
                })?;
                if action == "issue.dependency.add" {
                    let inputs = parse_issue_dependency_add_inputs(inputs, &self.config)?;
                    let (blocking, blocked, _) = self
                        .confirm_dependency_issue_metadata(&inputs, credential)
                        .await?;
                    Ok(merged_issue_metadata_scopes([&blocking, &blocked]))
                } else if action == "issue.parent.set" {
                    let inputs = parse_issue_parent_set_inputs(inputs, &self.config)?;
                    let (issue, parent, _) = self
                        .confirm_parent_set_issue_metadata(&inputs, credential)
                        .await?;
                    Ok(merged_issue_metadata_scopes([&issue, &parent]))
                } else if action == "issue.child.create" {
                    let inputs = parse_issue_child_create_scope_inputs(inputs, &self.config)?;
                    let parent_response = self
                        .confirm_issue_locator(&inputs.parent, credential)
                        .await?;
                    Ok(child_create_metadata_scopes(
                        &inputs.project,
                        &parent_response.value,
                    ))
                } else {
                    let locator = issue_locator_for_action(action, inputs, &self.config)?;
                    let response = self
                        .backend
                        .issue_metadata(&locator.issue_key, credential)
                        .await
                        .map_err(jira_backend_error)?;
                    issue_scopes_from_metadata(&response.value)
                }
            }
            "issue_type.list" | "issue.create" | "search" => self.local_scopes(action, inputs),
            _ => Err(ProviderError::deny(
                ReasonCode::ServiceActionDenied,
                "Jira action is not supported",
            )),
        }
    }
}

#[async_trait]
impl Provider for JiraProvider {
    async fn resolve_scopes(
        &self,
        request: ScopeRequest<'_>,
    ) -> Result<ScopeResolution, ProviderError> {
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
        if request.action() != "attachment.add" {
            return Err(ProviderError::deny(
                ReasonCode::BodyMalformed,
                "Jira action does not accept multipart body parts",
            ));
        }
        let credential = lookup_credential(request)?;
        let inputs = parse_attachment_add_inputs(request.inputs())?;
        validate_attachment_metadata_inputs(&inputs.attachments, &self.config.attachments)?;
        let body_part_specs = attachment_body_part_specs(&inputs.attachments);
        let response = self
            .confirm_issue_project(&inputs.issue, credential)
            .await?;
        Ok(BodyAdmission::new(
            body_part_specs,
            StateDisposition::Replace(ProviderState::new(JiraIssuePreflight {
                metadata: response.value,
                upstream_status: response.status,
                upstream_duration_ms: response.duration_ms,
            })),
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
            .map_err(jira_backend_error)?;
        Ok(Some(ProviderCredentialVerification::new(
            response.status,
            response.duration_ms,
            json!({
                "provider": "jira",
                "operation": "credential.verify",
                "egressProxy": self.backend.egress_proxy_audit(credential),
            }),
        )))
    }

    async fn invoke(&self, request: ProviderInvocation) -> Result<ProviderResult, ProviderError> {
        match request.action() {
            "issue_type.list" => self.invoke_issue_type_list(request).await,
            "issue.view" => self.invoke_issue_view(request).await,
            "issue.create" => self.invoke_issue_create(request).await,
            "issue.child.create" => self.invoke_issue_child_create(request).await,
            "issue.update" => self.invoke_issue_update(request).await,
            "issue.parent.set" => self.invoke_issue_parent_set(request).await,
            "issue.dependency.add" => self.invoke_issue_dependency_add(request).await,
            "search" => self.invoke_search(request).await,
            "comment.list" => self.invoke_comment_list(request).await,
            "comment.view" => self.invoke_comment_view(request).await,
            "comment.add" => self.invoke_comment_add(request).await,
            "comment.reply" => self.invoke_comment_reply(request).await,
            "comment.update" => self.invoke_comment_update(request).await,
            "comment.delete" => self.invoke_comment_delete(request).await,
            "comment.property.list" => self.invoke_comment_property_list(request).await,
            "comment.property.get" => self.invoke_comment_property_get(request).await,
            "comment.property.set" => self.invoke_comment_property_set(request).await,
            "comment.property.delete" => self.invoke_comment_property_delete(request).await,
            "attachment.add" => self.invoke_attachment_add(request).await,
            "attachment.download" => self.invoke_attachment_download(request).await,
            "attachment.list" => self.invoke_attachment_list(request).await,
            "verify" => self.invoke_verify(request).await,
            _ => Err(ProviderError::deny(
                ReasonCode::ServiceActionDenied,
                "Jira action is not supported",
            )),
        }
    }
}

impl JiraProvider {
    fn apply_adf_attribution(
        &self,
        action: &str,
        body: &mut Value,
        request: &ProviderInvocation,
    ) -> Result<Option<Value>, ProviderError> {
        let Some(capability) = self.attribution.capability(action) else {
            return Ok(None);
        };
        validate_adf_body(body)?;
        let mutation =
            append_adf_attribution(body, capability, &request.correlation().broker_request_id)?;
        validate_adf_body(body)?;
        Ok(Some(mutation.audit_value()))
    }

    async fn invoke_issue_type_list(
        &self,
        request: ProviderInvocation,
    ) -> Result<ProviderResult, ProviderError> {
        let inputs = parse_issue_type_list_inputs(request.inputs())?;
        ensure_authorized_project_scope(&inputs.project, request.resource_scopes()?)?;
        let credential = invocation_credential(request.admitted())?;
        let page_request = JiraIssueTypeListRequest {
            start_at: inputs.start_at,
            max_results: inputs.max_results,
        };
        let response = self
            .backend
            .issue_types(&inputs.project, page_request.clone(), credential)
            .await
            .map_err(jira_backend_error)?;
        let page = response.value;
        backend::validate_issue_type_page(&page, &page_request).map_err(jira_backend_error)?;
        // The page validator bounds the count and checks addition before projection.
        let count = page.issue_types.len() as u32;
        let next_offset = page.start_at + count;
        let next_start_at = (next_offset < page.total).then_some(next_offset);
        let result = json!({
            "operation": "issue_type.list",
            "project": inputs.project,
            "issueTypes": page.issue_types,
            "startAt": page.start_at,
            "maxResults": page.max_results,
            "total": page.total,
            "count": count,
            "isLast": next_start_at.is_none(),
            "nextStartAt": next_start_at,
        });
        enforce_result_size(&result, self.limits.max_upstream_response_bytes)?;
        Ok(ProviderResult::new(result)
            .with_audit(json!({
                "provider": "jira",
                "operation": "issue_type.list",
                "project": inputs.project,
                "startAt": page.start_at,
                "maxResults": page.max_results,
                "issueTypeCount": count,
                "credentialMode": request.credential_mode(),
                "egressProxy": self.backend.egress_proxy_audit(credential),
            }))
            .with_upstream(Some(response.status), Some(response.duration_ms))
            .with_object_ids(json!({ "project": inputs.project })))
    }

    async fn invoke_issue_view(
        &self,
        request: ProviderInvocation,
    ) -> Result<ProviderResult, ProviderError> {
        let credential = invocation_credential(request.admitted())?;
        let lookup_credential = lookup_credential(request.admitted())?;
        let locator = issue_locator_from_inputs(request.inputs(), &self.config)?;
        let metadata_response = self
            .backend
            .issue_metadata(&locator.issue_key, lookup_credential)
            .await
            .map_err(jira_backend_error)?;
        let metadata = metadata_response.value;
        if !is_issue_key(&metadata.key) || issue_key_project(&metadata.key) != metadata.project {
            return Err(ProviderError::error(
                ReasonCode::UpstreamProtocolFailed,
                "Jira issue response did not include a valid current key and project",
            ));
        }
        ensure_authorized_issue_metadata(&metadata, request.resource_scopes()?)?;
        let response = self
            .backend
            .issue(&metadata.key, credential)
            .await
            .map_err(jira_backend_error)?;
        let issue = response.value;
        if issue.id != metadata.id || issue.key != metadata.key || issue.project != metadata.project
        {
            return Err(ProviderError::deny(
                ReasonCode::ScopeUnresolved,
                "Jira issue response did not match confirmed metadata",
            ));
        }
        if !is_issue_key(&issue.key) || issue_key_project(&issue.key) != issue.project {
            return Err(ProviderError::error(
                ReasonCode::UpstreamProtocolFailed,
                "Jira issue response did not include a valid current key and project",
            ));
        }
        validate_returned_issue_description(&issue, &self.config)?;
        let result = issue_view_result(&issue, &self.config);
        enforce_result_size(&result, self.limits.max_upstream_response_bytes)?;
        Ok(ProviderResult::new(result)
            .with_audit(json!({
                "provider": "jira",
                "operation": "issue.view",
                "issueKey": issue.key,
                "project": issue.project,
                "credentialMode": request.credential_mode(),
                "egressProxy": self.backend.egress_proxy_audit(credential),
            }))
            .with_upstream(
                Some(response.status),
                Some(metadata_response.duration_ms + response.duration_ms),
            )
            .with_object_ids(json!({
                "issueId": issue.id,
                "issueKey": issue.key,
            })))
    }

    async fn invoke_issue_create(
        &self,
        request: ProviderInvocation,
    ) -> Result<ProviderResult, ProviderError> {
        let credential = invocation_credential(request.admitted())?;
        let scope_inputs = parse_issue_create_scope_inputs(request.inputs())?;
        ensure_authorized_project_scope(&scope_inputs.project, request.resource_scopes()?)?;
        let mut inputs = parse_issue_create_inputs(request.inputs(), &self.config)?;
        let description_provided = inputs.description.is_some();
        let audit_context = IssueCreateAuditContext {
            project: &inputs.project,
            issue_type_id: &inputs.issue_type_id,
            description_provided,
        };
        let attribution = if let Some(description) = inputs.description.as_mut() {
            self.apply_adf_attribution("issue.create", description, &request)?
        } else if self.attribution.capability("issue.create").is_some() {
            Some(attribution_skip_target_absent_audit())
        } else {
            None
        };
        if let (Some(description), Some(content_audit)) =
            (&inputs.description, inputs.content_audit.as_mut())
        {
            finalize_jira_content(
                description,
                content_audit,
                self.config.content.max_body_bytes,
                attribution_audit_applied(attribution.as_ref()),
            )?;
        }

        let write = JiraWrite::new(json!({ "project": inputs.project }));
        let create_response = match self
            .backend
            .create_issue(
                JiraIssueCreateRequest {
                    project: inputs.project.clone(),
                    issue_type_id: inputs.issue_type_id.clone(),
                    summary: inputs.summary,
                    parent_issue: None,
                    description: inputs.description,
                },
                credential,
            )
            .await
        {
            Ok(response) => response,
            Err(JiraBackendError::IssueCreateResponseInvalid {
                id,
                key,
                status,
                duration_ms,
            }) => {
                let partial = PartialJiraCreatedIssue { id, key };
                let mut audit = issue_create_failure_audit_partial(
                    &request,
                    &audit_context,
                    "create_response_validation",
                    &partial,
                    &self.backend.egress_proxy_audit(credential),
                );
                merge_attribution_audit(&mut audit, attribution);
                return Err(ProviderError::error(
                    ReasonCode::UpstreamProtocolFailed,
                    "Jira issue create response was invalid",
                )
                .with_audit(audit)
                .with_upstream(status, Some(duration_ms))
                .with_object_ids(issue_create_object_ids_partial(
                    partial.id.as_deref(),
                    partial.key.as_deref(),
                ))
                .with_mutation_receipt(write.receipt()));
            }
            Err(error) => return Err(write.failed(error)),
        };
        let created = create_response.value;
        let mut upstream_duration_ms = create_response.duration_ms;
        let upstream_status = create_response.status;
        if !is_issue_key(&created.key) || issue_key_project(&created.key) != inputs.project {
            let mut audit = issue_create_failure_audit(
                &request,
                &audit_context,
                "create_response_validation",
                Some(&created),
                &self.backend.egress_proxy_audit(credential),
            );
            merge_attribution_audit(&mut audit, attribution);
            return Err(ProviderError::error(
                ReasonCode::UpstreamProtocolFailed,
                "Jira issue create response did not match the authorized project",
            )
            .with_audit(audit)
            .with_upstream(Some(upstream_status), Some(upstream_duration_ms))
            .with_object_ids(issue_create_object_ids(Some(&created)))
            .with_mutation_receipt(write.receipt()));
        }

        after_accepted_write(
            "post_create_readback",
            issue_create_object_ids(Some(&created)),
            async {
                let readback_started = Instant::now();
                let readback_response = match self.backend.issue(&created.key, credential).await {
                    Ok(response) => response,
                    Err(error) => {
                        upstream_duration_ms += elapsed_ms(readback_started);
                        let mut audit = issue_create_failure_audit(
                            &request,
                            &audit_context,
                            "post_create_readback",
                            Some(&created),
                            &self.backend.egress_proxy_audit(credential),
                        );
                        audit["upstreamFailure"] = json!(sanitized_backend_reason(&error));
                        merge_attribution_audit(&mut audit, attribution);
                        // The issue exists: throttling here must not invite a second create.
                        return Err(jira_backend_error(error)
                            .unverified_after_mutation(
                                "post_create_readback",
                                issue_create_object_ids(Some(&created)),
                            )
                            .with_audit(audit)
                            .with_upstream(Some(upstream_status), Some(upstream_duration_ms))
                            .with_object_ids(issue_create_object_ids(Some(&created))));
                    }
                };
                upstream_duration_ms += readback_response.duration_ms;
                let issue = readback_response.value;
                if !is_issue_key(&issue.key) || issue_key_project(&issue.key) != issue.project {
                    let mut audit = issue_create_failure_audit(
                        &request,
                        &audit_context,
                        "post_create_readback",
                        Some(&created),
                        &self.backend.egress_proxy_audit(credential),
                    );
                    merge_attribution_audit(&mut audit, attribution);
                    return Err(ProviderError::error(
                        ReasonCode::UpstreamProtocolFailed,
                        "Jira issue response did not include a valid current key and project",
                    )
                    .with_audit(audit)
                    .with_upstream(Some(upstream_status), Some(upstream_duration_ms))
                    .with_object_ids(issue_create_object_ids(Some(&created))));
                }
                if issue.project != inputs.project
                    || issue_key_project(&issue.key) != inputs.project
                    || issue.id != created.id
                    || issue.key != created.key
                {
                    let mut audit = issue_create_failure_audit(
                        &request,
                        &audit_context,
                        "post_create_readback",
                        Some(&created),
                        &self.backend.egress_proxy_audit(credential),
                    );
                    merge_attribution_audit(&mut audit, attribution);
                    return Err(ProviderError::deny(
                        ReasonCode::ScopeUnresolved,
                        "Jira created issue readback did not match the authorized project",
                    )
                    .with_audit(audit)
                    .with_upstream(Some(upstream_status), Some(upstream_duration_ms))
                    .with_object_ids(issue_create_object_ids(Some(&created))));
                }
                if let Err(error) = validate_returned_issue_description(&issue, &self.config) {
                    let mut audit = issue_create_failure_audit(
                        &request,
                        &audit_context,
                        "post_create_readback",
                        Some(&created),
                        &self.backend.egress_proxy_audit(credential),
                    );
                    merge_attribution_audit(&mut audit, attribution);
                    return Err(error
                        .with_audit(audit)
                        .with_upstream(Some(upstream_status), Some(upstream_duration_ms))
                        .with_object_ids(issue_create_object_ids(Some(&created))));
                }
                let result = json!({
                    "operation": "issue.create",
                    "issue": issue_view_result(&issue, &self.config),
                });
                if let Err(error) =
                    enforce_result_size(&result, self.limits.max_upstream_response_bytes)
                {
                    let mut audit = issue_create_failure_audit(
                        &request,
                        &audit_context,
                        "post_create_readback",
                        Some(&created),
                        &self.backend.egress_proxy_audit(credential),
                    );
                    merge_attribution_audit(&mut audit, attribution);
                    return Err(error
                        .with_audit(audit)
                        .with_upstream(Some(upstream_status), Some(upstream_duration_ms))
                        .with_object_ids(issue_create_object_ids(Some(&created))));
                }
                let mut audit = json!({
                    "provider": "jira",
                    "operation": "issue.create",
                    "issueId": issue.id,
                    "issueKey": issue.key,
                    "project": issue.project,
                    "issueTypeId": inputs.issue_type_id,
                    "descriptionProvided": description_provided,
                    "credentialMode": request.credential_mode(),
                    "egressProxy": self.backend.egress_proxy_audit(credential),
                });
                merge_attribution_audit(&mut audit, attribution);
                merge_content_write_audit(&mut audit, inputs.content_audit.as_ref());
                Ok(ProviderResult::new(result)
                    .with_audit(audit)
                    .with_upstream(Some(upstream_status), Some(upstream_duration_ms))
                    .with_object_ids(issue_create_object_ids(Some(&created))))
            },
        )
        .await
    }

    async fn invoke_issue_child_create(
        &self,
        request: ProviderInvocation,
    ) -> Result<ProviderResult, ProviderError> {
        let credential = invocation_credential(request.admitted())?;
        let lookup_credential = lookup_credential(request.admitted())?;
        let scope_inputs = parse_issue_child_create_scope_inputs(request.inputs(), &self.config)?;
        // Reconfirm immediately before mutation instead of reusing scope-resolution
        // metadata so parent moves are caught before the create request.
        let parent_response = self
            .confirm_issue_locator(&scope_inputs.parent, lookup_credential)
            .await?;
        let parent = parent_response.value;
        let mut upstream_duration_ms = parent_response.duration_ms;
        ensure_authorized_project_scope(&scope_inputs.project, request.resource_scopes()?)?;
        ensure_authorized_issue_metadata(&parent, request.resource_scopes()?)?;
        let mut inputs = parse_issue_child_create_inputs(request.inputs(), &self.config)?;

        let description_provided = inputs.description.is_some();
        let audit_context = IssueChildCreateAuditContext {
            project: &inputs.project,
            issue_type_id: &inputs.issue_type_id,
            description_provided,
            parent: &parent,
        };
        let attribution = if let Some(description) = inputs.description.as_mut() {
            self.apply_adf_attribution("issue.child.create", description, &request)?
        } else if self.attribution.capability("issue.child.create").is_some() {
            Some(attribution_skip_target_absent_audit())
        } else {
            None
        };
        if let (Some(description), Some(content_audit)) =
            (&inputs.description, inputs.content_audit.as_mut())
        {
            finalize_jira_content(
                description,
                content_audit,
                self.config.content.max_body_bytes,
                attribution_audit_applied(attribution.as_ref()),
            )?;
        }

        let write = JiraWrite::new(
            json!({ "project": inputs.project, "parentIssueId": parent.id, "parentIssueKey": parent.key }),
        );
        let create_response = match self
            .backend
            .create_issue(
                JiraIssueCreateRequest {
                    project: inputs.project.clone(),
                    issue_type_id: inputs.issue_type_id.clone(),
                    summary: inputs.summary,
                    parent_issue: Some(parent.key.clone()),
                    description: inputs.description,
                },
                credential,
            )
            .await
        {
            Ok(response) => response,
            Err(JiraBackendError::IssueCreateResponseInvalid {
                id,
                key,
                status,
                duration_ms,
            }) => {
                let partial = PartialJiraCreatedIssue { id, key };
                let mut audit = issue_child_create_failure_audit_partial(
                    &request,
                    &audit_context,
                    "create_response_validation",
                    &partial,
                    &self.backend.egress_proxy_audit(credential),
                );
                merge_attribution_audit(&mut audit, attribution);
                return Err(ProviderError::error(
                    ReasonCode::UpstreamProtocolFailed,
                    "Jira child issue create response was invalid",
                )
                .with_audit(audit)
                .with_upstream(status, Some(upstream_duration_ms + duration_ms))
                .with_object_ids(issue_child_create_object_ids_partial(
                    partial.id.as_deref(),
                    partial.key.as_deref(),
                    &parent,
                ))
                .with_mutation_receipt(write.receipt()));
            }
            Err(error) => return Err(write.failed(error)),
        };
        let created = create_response.value;
        upstream_duration_ms += create_response.duration_ms;
        let upstream_status = create_response.status;
        if !is_issue_key(&created.key) || issue_key_project(&created.key) != inputs.project {
            let mut audit = issue_child_create_failure_audit(
                &request,
                &audit_context,
                "create_response_validation",
                Some(&created),
                &self.backend.egress_proxy_audit(credential),
            );
            merge_attribution_audit(&mut audit, attribution);
            return Err(ProviderError::error(
                ReasonCode::UpstreamProtocolFailed,
                "Jira child issue create response did not match the authorized project",
            )
            .with_audit(audit)
            .with_upstream(Some(upstream_status), Some(upstream_duration_ms))
            .with_object_ids(issue_child_create_object_ids(Some(&created), &parent))
            .with_mutation_receipt(write.receipt()));
        }

        after_accepted_write(
            "post_create_readback",
            issue_child_create_object_ids(Some(&created), &parent),
            async {
                let readback_started = Instant::now();
                let readback_response = match self.backend.issue(&created.key, credential).await {
                    Ok(response) => response,
                    Err(error) => {
                        upstream_duration_ms += elapsed_ms(readback_started);
                        let mut audit = issue_child_create_failure_audit(
                            &request,
                            &audit_context,
                            "post_create_readback",
                            Some(&created),
                            &self.backend.egress_proxy_audit(credential),
                        );
                        audit["upstreamFailure"] = json!(sanitized_backend_reason(&error));
                        merge_attribution_audit(&mut audit, attribution);
                        return Err(jira_backend_error(error)
                            .unverified_after_mutation(
                                "post_create_readback",
                                issue_child_create_object_ids(Some(&created), &parent),
                            )
                            .with_audit(audit)
                            .with_upstream(Some(upstream_status), Some(upstream_duration_ms))
                            .with_object_ids(issue_child_create_object_ids(
                                Some(&created),
                                &parent,
                            )));
                    }
                };
                upstream_duration_ms += readback_response.duration_ms;
                let issue = readback_response.value;
                if !is_issue_key(&issue.key) || issue_key_project(&issue.key) != issue.project {
                    let mut audit = issue_child_create_failure_audit(
                        &request,
                        &audit_context,
                        "post_create_readback",
                        Some(&created),
                        &self.backend.egress_proxy_audit(credential),
                    );
                    merge_attribution_audit(&mut audit, attribution);
                    return Err(ProviderError::error(
                        ReasonCode::UpstreamProtocolFailed,
                        "Jira child issue response did not include a valid current key and project",
                    )
                    .with_audit(audit)
                    .with_upstream(Some(upstream_status), Some(upstream_duration_ms))
                    .with_object_ids(issue_child_create_object_ids(Some(&created), &parent)));
                }
                if issue.project != inputs.project
                    || issue_key_project(&issue.key) != inputs.project
                    || issue.id != created.id
                    || issue.key != created.key
                {
                    let mut audit = issue_child_create_failure_audit(
                        &request,
                        &audit_context,
                        "post_create_readback",
                        Some(&created),
                        &self.backend.egress_proxy_audit(credential),
                    );
                    merge_attribution_audit(&mut audit, attribution);
                    return Err(ProviderError::deny(
                        ReasonCode::ScopeUnresolved,
                        "Jira child issue readback did not match the authorized project",
                    )
                    .with_audit(audit)
                    .with_upstream(Some(upstream_status), Some(upstream_duration_ms))
                    .with_object_ids(issue_child_create_object_ids(Some(&created), &parent)));
                }
                if let Err(error) = validate_returned_issue_description(&issue, &self.config) {
                    let mut audit = issue_child_create_failure_audit(
                        &request,
                        &audit_context,
                        "post_create_readback",
                        Some(&created),
                        &self.backend.egress_proxy_audit(credential),
                    );
                    merge_attribution_audit(&mut audit, attribution);
                    return Err(error
                        .with_audit(audit)
                        .with_upstream(Some(upstream_status), Some(upstream_duration_ms))
                        .with_object_ids(issue_child_create_object_ids(Some(&created), &parent)));
                }

                let parent_readback_started = Instant::now();
                let parent_readback_response =
                    match self.backend.issue_parent(&issue.key, credential).await {
                        Ok(response) => response,
                        Err(error) => {
                            upstream_duration_ms += elapsed_ms(parent_readback_started);
                            let mut audit = issue_child_create_failure_audit(
                                &request,
                                &audit_context,
                                "post_parent_readback",
                                Some(&created),
                                &self.backend.egress_proxy_audit(credential),
                            );
                            audit["upstreamFailure"] = json!(sanitized_backend_reason(&error));
                            merge_attribution_audit(&mut audit, attribution);
                            return Err(jira_backend_error(error)
                                .unverified_after_mutation(
                                    "post_parent_readback",
                                    issue_child_create_object_ids(Some(&created), &parent),
                                )
                                .with_audit(audit)
                                .with_upstream(Some(upstream_status), Some(upstream_duration_ms))
                                .with_object_ids(issue_child_create_object_ids(
                                    Some(&created),
                                    &parent,
                                )));
                        }
                    };
                upstream_duration_ms += parent_readback_response.duration_ms;
                let parent_readback = parent_readback_response.value;
                if !is_issue_key(&parent_readback.issue.key)
                    || issue_key_project(&parent_readback.issue.key)
                        != parent_readback.issue.project
                {
                    let mut audit = issue_child_create_failure_audit(
                        &request,
                        &audit_context,
                        "post_parent_readback",
                        Some(&created),
                        &self.backend.egress_proxy_audit(credential),
                    );
                    merge_attribution_audit(&mut audit, attribution);
                    return Err(ProviderError::error(
                ReasonCode::UpstreamProtocolFailed,
                "Jira child issue parent readback did not include a valid current key and project",
            )
            .with_audit(audit)
            .with_upstream(Some(upstream_status), Some(upstream_duration_ms))
            .with_object_ids(issue_child_create_object_ids(Some(&created), &parent)));
                }
                if parent_readback.issue.id != issue.id
                    || parent_readback.issue.key != issue.key
                    || parent_readback.issue.project != issue.project
                {
                    let mut audit = issue_child_create_failure_audit(
                        &request,
                        &audit_context,
                        "post_parent_readback",
                        Some(&created),
                        &self.backend.egress_proxy_audit(credential),
                    );
                    merge_attribution_audit(&mut audit, attribution);
                    return Err(ProviderError::deny(
                        ReasonCode::ScopeUnresolved,
                        "Jira child issue parent readback did not match created issue metadata",
                    )
                    .with_audit(audit)
                    .with_upstream(Some(upstream_status), Some(upstream_duration_ms))
                    .with_object_ids(issue_child_create_object_ids(Some(&created), &parent)));
                }
                if !issue_parent_readback_matches(&parent_readback, &parent) {
                    let mut audit = issue_child_create_failure_audit(
                        &request,
                        &audit_context,
                        "post_parent_readback",
                        Some(&created),
                        &self.backend.egress_proxy_audit(credential),
                    );
                    merge_attribution_audit(&mut audit, attribution);
                    return Err(ProviderError::error(
                        ReasonCode::UpstreamProtocolFailed,
                        "Jira child issue readback did not confirm the requested parent issue",
                    )
                    .with_audit(audit)
                    .with_upstream(Some(upstream_status), Some(upstream_duration_ms))
                    .with_object_ids(issue_child_create_object_ids(Some(&created), &parent)));
                }

                let issue_metadata = JiraIssueMetadata {
                    id: issue.id,
                    key: issue.key,
                    project: issue.project,
                };
                let result = json!({
                    "operation": "issue.child.create",
                    "issue": issue_metadata_result(&issue_metadata, &self.config),
                    "parentIssue": issue_metadata_result(&parent, &self.config),
                    "verification": { "status": "matched" },
                });
                if let Err(error) =
                    enforce_result_size(&result, self.limits.max_upstream_response_bytes)
                {
                    let mut audit = issue_child_create_failure_audit(
                        &request,
                        &audit_context,
                        "post_parent_readback",
                        Some(&created),
                        &self.backend.egress_proxy_audit(credential),
                    );
                    merge_attribution_audit(&mut audit, attribution);
                    return Err(error
                        .with_audit(audit)
                        .with_upstream(Some(upstream_status), Some(upstream_duration_ms))
                        .with_object_ids(issue_child_create_object_ids(Some(&created), &parent)));
                }
                let mut audit = json!({
                    "provider": "jira",
                    "operation": "issue.child.create",
                    "issueId": issue_metadata.id.as_str(),
                    "issueKey": issue_metadata.key.as_str(),
                    "project": issue_metadata.project.as_str(),
                    "issueTypeId": inputs.issue_type_id,
                    "parentIssueId": parent.id.as_str(),
                    "parentIssueKey": parent.key.as_str(),
                    "parentProject": parent.project.as_str(),
                    "descriptionProvided": description_provided,
                    "verificationStatus": "matched",
                    "credentialMode": request.credential_mode(),
                    "egressProxy": self.backend.egress_proxy_audit(credential),
                });
                merge_attribution_audit(&mut audit, attribution);
                merge_content_write_audit(&mut audit, inputs.content_audit.as_ref());
                Ok(ProviderResult::new(result)
                    .with_audit(audit)
                    .with_upstream(Some(upstream_status), Some(upstream_duration_ms))
                    .with_object_ids(issue_child_create_object_ids(Some(&created), &parent)))
            },
        )
        .await
    }

    async fn invoke_issue_update(
        &self,
        request: ProviderInvocation,
    ) -> Result<ProviderResult, ProviderError> {
        let credential = invocation_credential(request.admitted())?;
        let lookup_credential = lookup_credential(request.admitted())?;
        let mut inputs = parse_issue_update_inputs(request.inputs(), &self.config)?;
        let attribution = if let Some(description) = inputs.description.as_mut() {
            self.apply_adf_attribution("issue.update", description, &request)?
        } else if self.attribution.capability("issue.update").is_some() {
            Some(attribution_skip_target_absent_audit())
        } else {
            None
        };
        if let (Some(description), Some(content_audit)) =
            (&inputs.description, inputs.content_audit.as_mut())
        {
            finalize_jira_content(
                description,
                content_audit,
                self.config.content.max_body_bytes,
                attribution_audit_applied(attribution.as_ref()),
            )?;
        }
        let changed_fields = inputs.changed_fields();
        let summary_changed = inputs.summary.is_some();
        let description_changed = inputs.description.is_some();
        let metadata_response = self
            .confirm_issue_locator(&inputs.locator, lookup_credential)
            .await?;
        let metadata = metadata_response.value;
        ensure_authorized_issue_metadata(&metadata, request.resource_scopes()?)?;
        let write = JiraWrite::new(issue_create_object_ids_partial(
            Some(&metadata.id),
            Some(&metadata.key),
        ));
        let update_response = self
            .backend
            .update_issue(
                &metadata.key,
                JiraIssueUpdateRequest {
                    summary: inputs.summary,
                    description: inputs.description,
                    notify_users: inputs.notify_users,
                },
                credential,
            )
            .await
            .map_err(|error| write.failed(error))?;
        after_accepted_write(
            "post_update_readback",
            issue_create_object_ids_partial(Some(&metadata.id), Some(&metadata.key)),
            async {
                let readback_response = self
                    .backend
                    .issue(&metadata.key, credential)
                    .await
                    .map_err(|error| {
                        jira_backend_error(error).unverified_after_mutation(
                            "post_update_readback",
                            issue_create_object_ids_partial(
                                Some(&metadata.id),
                                Some(&metadata.key),
                            ),
                        )
                    })?;
                let issue = readback_response.value;
                if !is_issue_key(&issue.key) || issue_key_project(&issue.key) != issue.project {
                    return Err(ProviderError::error(
                        ReasonCode::UpstreamProtocolFailed,
                        "Jira issue response did not include a valid current key and project",
                    ));
                }
                if issue.id != metadata.id
                    || issue.key != metadata.key
                    || issue.project != metadata.project
                {
                    return Err(ProviderError::deny(
                        ReasonCode::ScopeUnresolved,
                        "Jira issue response did not match confirmed metadata",
                    ));
                }
                validate_returned_issue_description(&issue, &self.config)?;
                let result = json!({
                    "operation": "issue.update",
                    "issue": issue_view_result(&issue, &self.config),
                    "changedFields": changed_fields.clone(),
                    "notifyUsers": inputs.notify_users,
                });
                enforce_result_size(&result, self.limits.max_upstream_response_bytes)?;
                let mut audit = json!({
                    "provider": "jira",
                    "operation": "issue.update",
                    "issueKey": issue.key,
                    "project": issue.project,
                    "changedFields": changed_fields,
                    "summaryChanged": summary_changed,
                    "descriptionChanged": description_changed,
                    "notifyUsers": inputs.notify_users,
                    "credentialMode": request.credential_mode(),
                    "egressProxy": self.backend.egress_proxy_audit(credential),
                });
                merge_attribution_audit(&mut audit, attribution);
                merge_content_write_audit(&mut audit, inputs.content_audit.as_ref());
                Ok(ProviderResult::new(result)
                    .with_audit(audit)
                    .with_upstream(
                        Some(update_response.status),
                        Some(
                            metadata_response.duration_ms
                                + update_response.duration_ms
                                + readback_response.duration_ms,
                        ),
                    )
                    .with_object_ids(json!({
                        "issueId": issue.id,
                        "issueKey": issue.key,
                    })))
            },
        )
        .await
    }

    async fn invoke_issue_parent_set(
        &self,
        request: ProviderInvocation,
    ) -> Result<ProviderResult, ProviderError> {
        let credential = invocation_credential(request.admitted())?;
        let lookup_credential = lookup_credential(request.admitted())?;
        let inputs = parse_issue_parent_set_inputs(request.inputs(), &self.config)?;
        let (issue, parent, mut upstream_duration_ms) = self
            .confirm_parent_set_issue_metadata(&inputs, lookup_credential)
            .await?;
        ensure_authorized_issue_metadata(&issue, request.resource_scopes()?)?;
        ensure_authorized_issue_metadata(&parent, request.resource_scopes()?)?;

        let write = JiraWrite::new(issue_parent_set_object_ids(&issue, &parent));
        let update_response = self
            .backend
            .set_issue_parent(
                &issue.key,
                JiraIssueParentSetRequest {
                    parent_issue: parent.key.clone(),
                },
                credential,
            )
            .await
            .map_err(|error| write.failed(error))?;
        after_accepted_write(
            "post_parent_readback",
            issue_parent_set_object_ids(&issue, &parent),
            async {
                upstream_duration_ms += update_response.duration_ms;

                let readback_response = match self
                    .backend
                    .issue_parent(&issue.key, credential)
                    .await
                {
                    Ok(response) => response,
                    Err(error) => {
                        let mut audit = issue_parent_set_failure_audit(
                            &request,
                            &issue,
                            &parent,
                            "post_parent_readback",
                            &self.backend.egress_proxy_audit(credential),
                        );
                        audit["upstreamFailure"] = json!(sanitized_backend_reason(&error));
                        return Err(jira_backend_error(error)
                            .unverified_after_mutation(
                                "post_parent_readback",
                                issue_parent_set_object_ids(&issue, &parent),
                            )
                            .with_audit(audit)
                            .with_upstream(Some(update_response.status), Some(upstream_duration_ms))
                            .with_object_ids(issue_parent_set_object_ids(&issue, &parent)));
                    }
                };
                upstream_duration_ms += readback_response.duration_ms;
                let readback = readback_response.value;
                if !is_issue_key(&readback.issue.key)
                    || issue_key_project(&readback.issue.key) != readback.issue.project
                {
                    let audit = issue_parent_set_failure_audit(
                        &request,
                        &issue,
                        &parent,
                        "post_parent_readback",
                        &self.backend.egress_proxy_audit(credential),
                    );
                    return Err(ProviderError::error(
                        ReasonCode::UpstreamProtocolFailed,
                        "Jira parent readback did not include a valid current key and project",
                    )
                    .with_audit(audit)
                    .with_upstream(Some(update_response.status), Some(upstream_duration_ms))
                    .with_object_ids(issue_parent_set_object_ids(&issue, &parent)));
                }
                if readback.issue.id != issue.id
                    || readback.issue.key != issue.key
                    || readback.issue.project != issue.project
                {
                    let audit = issue_parent_set_failure_audit(
                        &request,
                        &issue,
                        &parent,
                        "post_parent_readback",
                        &self.backend.egress_proxy_audit(credential),
                    );
                    return Err(ProviderError::deny(
                        ReasonCode::ScopeUnresolved,
                        "Jira parent readback did not match confirmed child issue metadata",
                    )
                    .with_audit(audit)
                    .with_upstream(Some(update_response.status), Some(upstream_duration_ms))
                    .with_object_ids(issue_parent_set_object_ids(&issue, &parent)));
                }
                if !issue_parent_readback_matches(&readback, &parent) {
                    let audit = issue_parent_set_failure_audit(
                        &request,
                        &issue,
                        &parent,
                        "post_parent_readback",
                        &self.backend.egress_proxy_audit(credential),
                    );
                    return Err(ProviderError::error(
                        ReasonCode::UpstreamProtocolFailed,
                        "Jira parent readback did not confirm the requested parent issue",
                    )
                    .with_audit(audit)
                    .with_upstream(Some(update_response.status), Some(upstream_duration_ms))
                    .with_object_ids(issue_parent_set_object_ids(&issue, &parent)));
                }

                let result = json!({
                    "operation": "issue.parent.set",
                    "issue": issue_metadata_result(&issue, &self.config),
                    "parentIssue": issue_metadata_result(&parent, &self.config),
                    "verification": { "status": "matched" },
                });
                enforce_result_size(&result, self.limits.max_upstream_response_bytes)?;
                Ok(ProviderResult::new(result)
                    .with_audit(json!({
                        "provider": "jira",
                        "operation": "issue.parent.set",
                        "issueKey": issue.key.as_str(),
                        "project": issue.project.as_str(),
                        "parentIssueKey": parent.key.as_str(),
                        "parentProject": parent.project.as_str(),
                        "verificationStatus": "matched",
                        "credentialMode": request.credential_mode(),
                        "egressProxy": self.backend.egress_proxy_audit(credential),
                    }))
                    .with_upstream(Some(update_response.status), Some(upstream_duration_ms))
                    .with_object_ids(issue_parent_set_object_ids(&issue, &parent)))
            },
        )
        .await
    }

    async fn invoke_issue_dependency_add(
        &self,
        request: ProviderInvocation,
    ) -> Result<ProviderResult, ProviderError> {
        let credential = invocation_credential(request.admitted())?;
        let lookup_credential = lookup_credential(request.admitted())?;
        let inputs = parse_issue_dependency_add_inputs(request.inputs(), &self.config)?;
        let (blocking, blocked, mut upstream_duration_ms) = self
            .confirm_dependency_issue_metadata(&inputs, lookup_credential)
            .await?;
        ensure_authorized_issue_metadata(&blocking, request.resource_scopes()?)?;
        ensure_authorized_issue_metadata(&blocked, request.resource_scopes()?)?;

        let link_types_response = self
            .backend
            .issue_link_types(credential)
            .await
            .map_err(jira_backend_error)?;
        upstream_duration_ms += link_types_response.duration_ms;
        let link_type =
            configured_dependency_link_type(&link_types_response.value, &self.config.issue_links)?;

        let write = JiraWrite::new(issue_dependency_object_ids(&blocking, &blocked));
        let create_response = self
            .backend
            .create_issue_link(
                JiraIssueLinkCreateRequest {
                    link_type: link_type.name.clone(),
                    outward_issue: blocking.key.clone(),
                    inward_issue: blocked.key.clone(),
                },
                credential,
            )
            .await
            .map_err(|error| write.failed(error))?;
        after_accepted_write(
            "post_dependency_readback",
            issue_dependency_object_ids(&blocking, &blocked),
            async {
                upstream_duration_ms += create_response.duration_ms;

                let readback_response = match self
                    .backend
                    .issue_links(&blocking.key, credential)
                    .await
                {
                    Ok(response) => response,
                    Err(error) => {
                        let mut audit = issue_dependency_failure_audit(
                            &request,
                            &blocking,
                            &blocked,
                            &link_type,
                            "post_dependency_readback",
                            &self.backend.egress_proxy_audit(credential),
                        );
                        audit["upstreamFailure"] = json!(sanitized_backend_reason(&error));
                        return Err(jira_backend_error(error)
                            .unverified_after_mutation(
                                "post_dependency_readback",
                                issue_dependency_object_ids(&blocking, &blocked),
                            )
                            .with_audit(audit)
                            .with_upstream(Some(create_response.status), Some(upstream_duration_ms))
                            .with_object_ids(issue_dependency_object_ids(&blocking, &blocked)));
                    }
                };
                upstream_duration_ms += readback_response.duration_ms;
                let readback = readback_response.value;
                if readback.issue.id != blocking.id
                    || readback.issue.key != blocking.key
                    || readback.issue.project != blocking.project
                {
                    let audit = issue_dependency_failure_audit(
                        &request,
                        &blocking,
                        &blocked,
                        &link_type,
                        "post_dependency_readback",
                        &self.backend.egress_proxy_audit(credential),
                    );
                    return Err(ProviderError::deny(
                        ReasonCode::ScopeUnresolved,
                        "Jira dependency link readback did not match the blocking issue",
                    )
                    .with_audit(audit)
                    .with_upstream(Some(create_response.status), Some(upstream_duration_ms))
                    .with_object_ids(issue_dependency_object_ids(&blocking, &blocked)));
                }
                if !dependency_link_readback_matches(&readback, &link_type.name, &blocked.key) {
                    let audit = issue_dependency_failure_audit(
                        &request,
                        &blocking,
                        &blocked,
                        &link_type,
                        "post_dependency_readback",
                        &self.backend.egress_proxy_audit(credential),
                    );
                    return Err(ProviderError::error(
                        ReasonCode::UpstreamProtocolFailed,
                        "Jira dependency link readback did not confirm the requested relationship",
                    )
                    .with_audit(audit)
                    .with_upstream(Some(create_response.status), Some(upstream_duration_ms))
                    .with_object_ids(issue_dependency_object_ids(&blocking, &blocked)));
                }

                let result = json!({
                    "operation": "issue.dependency.add",
                    "status": "present",
                    "linkType": link_type.name.as_str(),
                    "blockingIssue": issue_metadata_result(&blocking, &self.config),
                    "blockedIssue": issue_metadata_result(&blocked, &self.config),
                    "verification": { "status": "matched" },
                });
                enforce_result_size(&result, self.limits.max_upstream_response_bytes)?;
                Ok(ProviderResult::new(result)
                    .with_audit(json!({
                        "provider": "jira",
                        "operation": "issue.dependency.add",
                        "status": "present",
                        "linkType": link_type.name.as_str(),
                        "blockingIssueKey": blocking.key.as_str(),
                        "blockingProject": blocking.project.as_str(),
                        "blockedIssueKey": blocked.key.as_str(),
                        "blockedProject": blocked.project.as_str(),
                        "verificationStatus": "matched",
                        "credentialMode": request.credential_mode(),
                        "egressProxy": self.backend.egress_proxy_audit(credential),
                    }))
                    .with_upstream(Some(create_response.status), Some(upstream_duration_ms))
                    .with_object_ids(issue_dependency_object_ids(&blocking, &blocked)))
            },
        )
        .await
    }

    async fn invoke_search(
        &self,
        request: ProviderInvocation,
    ) -> Result<ProviderResult, ProviderError> {
        let credential = request.execution().static_credential().ok_or_else(|| {
            ProviderError::deny(
                ReasonCode::CredentialNotProvisioned,
                "selected credential material is unavailable",
            )
        })?;
        let inputs = parse_search_inputs(request.inputs())?;
        let requested = requested_projects(&inputs)?;
        let authorization = search_authorization(&request)?;
        let effective_scope = effective_search_scope(&authorization, &requested)?;
        let query = build_jira_search_query(
            &inputs.query,
            &effective_scope,
            &self.config.search,
            request.credential_mode(),
        )?;
        let response_scope = query.response_scope.clone();
        let max_results = capped_max_results(inputs.max_results, &self.config.search)?;
        let pages = SearchPageRequest {
            request: &request,
            configuration: &self.search_configuration,
            credential,
            query: &query,
            requested_projects: &requested,
            max_results,
        };
        let upstream_page_token = inputs
            .next_page_token
            .as_deref()
            .map(|token| pages.open(&self.search_pages, token, SystemTime::now()))
            .transpose()?;
        let response = self
            .backend
            .search(
                JiraSearchRequest {
                    jql: query.jql.clone(),
                    projects: response_scope.values_for_backend(),
                    max_results,
                    next_page_token: upstream_page_token,
                },
                credential,
            )
            .await
            .map_err(jira_backend_error)?;

        if response.value.issues.len() > max_results as usize {
            return Err(ProviderError::error(
                ReasonCode::UpstreamProtocolFailed,
                "Jira search returned more issues than requested",
            ));
        }
        for (issue_index, issue) in response.value.issues.iter().enumerate() {
            if let Some((diagnostic_code, validation)) =
                search_diagnostics::rejected_issue(issue, &response_scope, issue_index)
            {
                return Err(ProviderError::deny(
                    ReasonCode::ScopeUnresolved,
                    "Jira search returned an issue outside the authorized project scope",
                )
                .with_internal_diagnostic_code(diagnostic_code)
                .with_upstream(Some(response.status), Some(response.duration_ms))
                .with_audit(json!({
                    "provider": "jira",
                    "operation": "search",
                    "effectiveSearchScope": response_scope.audit_value("project"),
                    "injectedScopePredicate": query.injected_scope_predicate,
                    "canonicalCallerJqlHash": query.canonical_caller_jql_hash,
                    "queryType": query.kind,
                    "pageTokenPresent": inputs.next_page_token.is_some(),
                    "maxResults": max_results,
                    "resultCount": response.value.issues.len(),
                    "searchResultValidation": validation,
                })));
            }
        }
        let observed_projects = response
            .value
            .issues
            .iter()
            .map(|issue| issue.project.clone())
            .collect::<BTreeSet<_>>();
        let next_page_token = response
            .value
            .next_page_token
            .as_deref()
            .map(|upstream| {
                pages
                    .seal(&self.search_pages, upstream, SystemTime::now())
                    .map_err(|error| {
                        error.with_upstream(Some(response.status), Some(response.duration_ms))
                    })
            })
            .transpose()?;

        let result = search_result(&response.value, next_page_token.as_deref(), &self.config);
        enforce_result_size(&result, self.limits.max_upstream_response_bytes)?;
        Ok(ProviderResult::new(result)
            .with_audit(json!({
                "provider": "jira",
                "operation": "search",
                "requestedProjects": requested,
                "effectiveSearchScope": response_scope.audit_value("project"),
                "queryType": query.kind,
                "queryAstVersion": JIRA_QUERY_AST_VERSION,
                "canonicalCallerJqlHash": query.canonical_caller_jql_hash,
                "queryShape": query.query_shape,
                "textOperandHashes": query.text_operand_hashes,
                "injectedScopePredicate": query.injected_scope_predicate,
                "observedProjects": observed_projects,
                "sortFields": query.sort_fields,
                "maxResults": max_results,
                "resultCount": response.value.issues.len(),
                "credentialMode": request.credential_mode(),
                "egressProxy": self.backend.egress_proxy_audit(credential),
            }))
            .with_upstream(Some(response.status), Some(response.duration_ms))
            .with_object_ids(json!({
                "issueKeys": response
                    .value
                    .issues
                    .iter()
                    .map(|issue| issue.key.clone())
                    .collect::<Vec<_>>(),
            })))
    }

    async fn invoke_comment_list(
        &self,
        request: ProviderInvocation,
    ) -> Result<ProviderResult, ProviderError> {
        let credential = invocation_credential(request.admitted())?;
        let lookup_credential = lookup_credential(request.admitted())?;
        let inputs = parse_comment_list_inputs(request.inputs(), &self.config)?;
        let metadata_response = self
            .confirm_issue_locator(&inputs.locator, lookup_credential)
            .await?;
        let metadata = metadata_response.value;
        let list_response = self
            .backend
            .comments(
                &metadata.key,
                JiraCommentListRequest {
                    max_results: inputs.max_results,
                    start_at: inputs.start_at,
                    order_by: inputs.order_by.clone(),
                },
                credential,
            )
            .await
            .map_err(jira_backend_error)?;
        let comments = list_response
            .value
            .comments
            .iter()
            .map(comment_summary_result)
            .collect::<Vec<_>>();
        let comment_ids = list_response
            .value
            .comments
            .iter()
            .map(|comment| comment.id.clone())
            .collect::<Vec<_>>();
        let count = comments.len();
        let result = json!({
            "operation": "comment.list",
            "issue": issue_metadata_result(&metadata, &self.config),
            "comments": comments,
            "startAt": list_response.value.start_at,
            "maxResults": list_response.value.max_results,
            "total": list_response.value.total,
            "count": count,
        });
        enforce_result_size(&result, self.limits.max_upstream_response_bytes)?;
        Ok(ProviderResult::new(result)
            .with_audit(json!({
                "provider": "jira",
                "operation": "comment.list",
                "issueKey": metadata.key,
                "project": metadata.project,
                "startAt": list_response.value.start_at,
                "maxResults": list_response.value.max_results,
                "orderBy": inputs.order_by,
                "commentCount": count,
                "credentialMode": request.credential_mode(),
                "egressProxy": self.backend.egress_proxy_audit(credential),
            }))
            .with_upstream(
                Some(list_response.status),
                Some(metadata_response.duration_ms + list_response.duration_ms),
            )
            .with_object_ids(json!({
                "issueId": metadata.id,
                "issueKey": metadata.key,
                "commentIds": comment_ids,
            })))
    }

    async fn invoke_comment_view(
        &self,
        request: ProviderInvocation,
    ) -> Result<ProviderResult, ProviderError> {
        let credential = invocation_credential(request.admitted())?;
        let lookup_credential = lookup_credential(request.admitted())?;
        let inputs = parse_comment_view_inputs(request.inputs(), &self.config)?;
        let metadata_response = self
            .confirm_issue_locator(&inputs.locator, lookup_credential)
            .await?;
        let metadata = metadata_response.value;
        let response = self
            .backend
            .comment(&metadata.key, &inputs.comment_id, credential)
            .await
            .map_err(jira_backend_error)?;
        validate_returned_comment_id(&response.value.id, Some(&inputs.comment_id))?;
        validate_returned_comment_body(&response.value, self.config.content.max_body_bytes)?;
        let result = json!({
            "operation": "comment.view",
            "issue": issue_metadata_result(&metadata, &self.config),
            "comment": comment_result(&response.value),
        });
        enforce_result_size(&result, self.limits.max_upstream_response_bytes)?;
        Ok(ProviderResult::new(result)
            .with_audit(json!({
                "provider": "jira",
                "operation": "comment.view",
                "issueKey": metadata.key,
                "project": metadata.project,
                "commentId": response.value.id,
                "credentialMode": request.credential_mode(),
                "egressProxy": self.backend.egress_proxy_audit(credential),
            }))
            .with_upstream(
                Some(response.status),
                Some(metadata_response.duration_ms + response.duration_ms),
            )
            .with_object_ids(json!({
                "issueId": metadata.id,
                "issueKey": metadata.key,
                "commentId": response.value.id,
            })))
    }

    async fn invoke_comment_add(
        &self,
        request: ProviderInvocation,
    ) -> Result<ProviderResult, ProviderError> {
        let credential = invocation_credential(request.admitted())?;
        let lookup_credential = lookup_credential(request.admitted())?;
        self.validate_configured_comment_body_format("jira.comment.add")?;
        let mut inputs = parse_comment_add_inputs(request.inputs(), &self.config)?;
        let attribution = self.apply_adf_attribution("comment.add", &mut inputs.body, &request)?;
        finalize_jira_content(
            &inputs.body,
            &mut inputs.content_audit,
            self.config.content.max_body_bytes,
            attribution_audit_applied(attribution.as_ref()),
        )?;
        let metadata_response = self
            .confirm_issue_locator(&inputs.locator, lookup_credential)
            .await?;
        let metadata = metadata_response.value;
        let visibility_restricted = inputs.visibility.is_some();
        let write = JiraWrite::new(json!({ "issueId": metadata.id, "issueKey": metadata.key }));
        let response = self
            .backend
            .add_comment(
                &metadata.key,
                JiraCommentAddRequest {
                    body: inputs.body,
                    visibility: inputs.visibility,
                    parent_id: None,
                },
                credential,
            )
            .await
            .map_err(|error| write.failed(error))?;
        after_accepted_write("mutation_response", write.locators(), async {
            validate_returned_comment_id(&response.value.id, None)?;
            validate_returned_comment_parent_id(&response.value, None)?;
            validate_returned_comment_body(&response.value, self.config.content.max_body_bytes)?;
            let result = json!({
                "operation": "comment.add",
                "issue": issue_metadata_result(&metadata, &self.config),
                "comment": comment_result(&response.value),
            });
            enforce_result_size(&result, self.limits.max_upstream_response_bytes)?;
            let mut audit = json!({
                "provider": "jira",
                "operation": "comment.add",
                "issueKey": metadata.key,
                "project": metadata.project,
                "commentId": response.value.id,
                "visibilityRestricted": visibility_restricted,
                "credentialMode": request.credential_mode(),
                "egressProxy": self.backend.egress_proxy_audit(credential),
            });
            merge_attribution_audit(&mut audit, attribution);
            merge_content_write_audit(&mut audit, Some(&inputs.content_audit));
            Ok(ProviderResult::new(result)
                .with_audit(audit)
                .with_upstream(
                    Some(response.status),
                    Some(metadata_response.duration_ms + response.duration_ms),
                )
                .with_object_ids(json!({
                    "issueId": metadata.id,
                    "issueKey": metadata.key,
                    "commentId": response.value.id,
                })))
        })
        .await
    }

    async fn invoke_comment_reply(
        &self,
        request: ProviderInvocation,
    ) -> Result<ProviderResult, ProviderError> {
        let credential = invocation_credential(request.admitted())?;
        let lookup_credential = lookup_credential(request.admitted())?;
        self.validate_configured_comment_body_format("jira.comment.reply")?;
        let mut inputs = parse_comment_reply_inputs(request.inputs(), &self.config)?;
        let requested_parent_comment_id = inputs.parent_comment_id.clone();
        let attribution =
            self.apply_adf_attribution("comment.reply", &mut inputs.body, &request)?;
        finalize_jira_content(
            &inputs.body,
            &mut inputs.content_audit,
            self.config.content.max_body_bytes,
            attribution_audit_applied(attribution.as_ref()),
        )?;
        let (metadata, parent_response, mut upstream_duration_ms) = self
            .confirm_comment_membership(
                &inputs.locator,
                &inputs.parent_comment_id,
                lookup_credential,
                credential,
            )
            .await?;
        upstream_duration_ms += parent_response.duration_ms;
        let effective_parent_comment_id =
            if let Some(root_parent_id) = parent_response.value.parent_id.as_deref() {
                let root_response = self
                    .backend
                    .comment(&metadata.key, root_parent_id, credential)
                    .await
                    .map_err(jira_backend_error)?;
                upstream_duration_ms += root_response.duration_ms;
                validate_returned_comment_id(&root_response.value.id, Some(root_parent_id))?;
                if root_response.value.parent_id.is_some() {
                    return Err(ProviderError::error(
                        ReasonCode::UpstreamProtocolFailed,
                        "Jira comment thread root was not a top-level comment",
                    ));
                }
                root_response.value.id
            } else {
                parent_response.value.id
            };
        let visibility_restricted = inputs.visibility.is_some();
        let write = JiraWrite::new(
            json!({ "issueId": metadata.id, "issueKey": metadata.key, "parentCommentId": effective_parent_comment_id }),
        );
        let response = self
            .backend
            .add_comment(
                &metadata.key,
                JiraCommentAddRequest {
                    body: inputs.body,
                    visibility: inputs.visibility,
                    parent_id: Some(effective_parent_comment_id.clone()),
                },
                credential,
            )
            .await
            .map_err(|error| write.failed(error))?;
        after_accepted_write("mutation_response", write.locators(), async {
            upstream_duration_ms += response.duration_ms;
            validate_returned_comment_id(&response.value.id, None)?;
            validate_returned_comment_parent_id(
                &response.value,
                Some(&effective_parent_comment_id),
            )?;
            validate_returned_comment_body(&response.value, self.config.content.max_body_bytes)?;
            let result = json!({
                "operation": "comment.reply",
                "issue": issue_metadata_result(&metadata, &self.config),
                "requestedParentCommentId": requested_parent_comment_id,
                "parentCommentId": effective_parent_comment_id,
                "comment": comment_result(&response.value),
            });
            enforce_result_size(&result, self.limits.max_upstream_response_bytes)?;
            let mut audit = json!({
                "provider": "jira",
                "operation": "comment.reply",
                "issueKey": metadata.key,
                "project": metadata.project,
                "commentId": response.value.id,
                "requestedParentCommentId": requested_parent_comment_id,
                "parentCommentId": effective_parent_comment_id,
                "visibilityRestricted": visibility_restricted,
                "credentialMode": request.credential_mode(),
                "egressProxy": self.backend.egress_proxy_audit(credential),
            });
            merge_attribution_audit(&mut audit, attribution);
            merge_content_write_audit(&mut audit, Some(&inputs.content_audit));
            Ok(ProviderResult::new(result)
                .with_audit(audit)
                .with_upstream(Some(response.status), Some(upstream_duration_ms))
                .with_object_ids(json!({
                    "issueId": metadata.id,
                    "issueKey": metadata.key,
                    "commentId": response.value.id,
                    "parentCommentId": effective_parent_comment_id,
                })))
        })
        .await
    }

    async fn invoke_comment_update(
        &self,
        request: ProviderInvocation,
    ) -> Result<ProviderResult, ProviderError> {
        let credential = invocation_credential(request.admitted())?;
        let lookup_credential = lookup_credential(request.admitted())?;
        self.validate_configured_comment_body_format("jira.comment.update")?;
        let mut inputs = parse_comment_update_inputs(request.inputs(), &self.config)?;
        let attribution =
            self.apply_adf_attribution("comment.update", &mut inputs.body, &request)?;
        finalize_jira_content(
            &inputs.body,
            &mut inputs.content_audit,
            self.config.content.max_body_bytes,
            attribution_audit_applied(attribution.as_ref()),
        )?;
        let metadata_response = self
            .confirm_issue_locator(&inputs.locator, lookup_credential)
            .await?;
        let metadata = metadata_response.value;
        let mut upstream_duration_ms = metadata_response.duration_ms;
        let outbound_visibility = match inputs.visibility_mode {
            CommentVisibilityMode::Set => inputs.visibility.clone(),
            CommentVisibilityMode::Preserve => {
                let current = self
                    .backend
                    .comment(&metadata.key, &inputs.comment_id, credential)
                    .await
                    .map_err(jira_backend_error)?;
                upstream_duration_ms += current.duration_ms;
                validate_returned_comment_id(&current.value.id, Some(&inputs.comment_id))?;
                current.value.visibility
            }
        };
        let visibility_restricted = outbound_visibility.is_some();
        let write = JiraWrite::new(
            json!({ "issueId": metadata.id, "issueKey": metadata.key, "commentId": inputs.comment_id }),
        );
        let response = self
            .backend
            .update_comment(
                &metadata.key,
                &inputs.comment_id,
                JiraCommentUpdateRequest {
                    body: inputs.body,
                    visibility: outbound_visibility,
                    notify_users: inputs.notify_users,
                },
                credential,
            )
            .await
            .map_err(|error| write.failed(error))?;
        after_accepted_write("mutation_response", write.locators(), async {
            upstream_duration_ms += response.duration_ms;
            validate_returned_comment_id(&response.value.id, Some(&inputs.comment_id))?;
            validate_returned_comment_body(&response.value, self.config.content.max_body_bytes)?;
            let result = json!({
                "operation": "comment.update",
                "issue": issue_metadata_result(&metadata, &self.config),
                "comment": comment_result(&response.value),
            });
            enforce_result_size(&result, self.limits.max_upstream_response_bytes)?;
            let mut audit = json!({
                "provider": "jira",
                "operation": "comment.update",
                "issueKey": metadata.key,
                "project": metadata.project,
                "commentId": response.value.id,
                "visibilityMode": inputs.visibility_mode.audit_value(),
                "visibilityRestricted": visibility_restricted,
                "notifyUsers": inputs.notify_users,
                "credentialMode": request.credential_mode(),
                "egressProxy": self.backend.egress_proxy_audit(credential),
            });
            merge_attribution_audit(&mut audit, attribution);
            merge_content_write_audit(&mut audit, Some(&inputs.content_audit));
            Ok(ProviderResult::new(result)
                .with_audit(audit)
                .with_upstream(Some(response.status), Some(upstream_duration_ms))
                .with_object_ids(json!({
                    "issueId": metadata.id,
                    "issueKey": metadata.key,
                    "commentId": response.value.id,
                })))
        })
        .await
    }

    async fn invoke_comment_delete(
        &self,
        request: ProviderInvocation,
    ) -> Result<ProviderResult, ProviderError> {
        let credential = invocation_credential(request.admitted())?;
        let lookup_credential = lookup_credential(request.admitted())?;
        let inputs = parse_comment_view_inputs(request.inputs(), &self.config)?;
        let metadata_response = self
            .confirm_issue_locator(&inputs.locator, lookup_credential)
            .await?;
        let metadata = metadata_response.value;
        let write = JiraWrite::new(
            json!({ "issueId": metadata.id, "issueKey": metadata.key, "commentId": inputs.comment_id }),
        );
        let response = self
            .backend
            .delete_comment(&metadata.key, &inputs.comment_id, credential)
            .await
            .map_err(|error| write.failed(error))?;
        after_accepted_write("mutation_response", write.locators(), async {
            let result = json!({
                "operation": "comment.delete",
                "issue": issue_metadata_result(&metadata, &self.config),
                "commentId": inputs.comment_id,
                "status": "deleted",
            });
            enforce_result_size(&result, self.limits.max_upstream_response_bytes)?;
            Ok(ProviderResult::new(result)
                .with_audit(json!({
                    "provider": "jira",
                    "operation": "comment.delete",
                    "issueKey": metadata.key,
                    "project": metadata.project,
                    "commentId": inputs.comment_id,
                    "credentialMode": request.credential_mode(),
                    "egressProxy": self.backend.egress_proxy_audit(credential),
                }))
                .with_upstream(
                    Some(response.status),
                    Some(metadata_response.duration_ms + response.duration_ms),
                )
                .with_object_ids(json!({
                    "issueId": metadata.id,
                    "issueKey": metadata.key,
                    "commentId": inputs.comment_id,
                })))
        })
        .await
    }

    async fn invoke_comment_property_list(
        &self,
        request: ProviderInvocation,
    ) -> Result<ProviderResult, ProviderError> {
        let credential = invocation_credential(request.admitted())?;
        let lookup_credential = lookup_credential(request.admitted())?;
        let inputs =
            parse_comment_property_inputs("comment.property.list", request.inputs(), &self.config)?;
        let (metadata, proof_response, metadata_duration_ms) = self
            .confirm_comment_membership(
                &inputs.locator,
                &inputs.comment_id,
                lookup_credential,
                credential,
            )
            .await?;
        let response = self
            .backend
            .comment_property_keys(&inputs.comment_id, credential)
            .await
            .map_err(jira_backend_error)?;
        let keys = response
            .value
            .keys
            .iter()
            .filter(|key| self.comment_property_key_allowed_for_return(key))
            .map(|key| json!({ "key": key }))
            .collect::<Vec<_>>();
        let count = keys.len();
        let result = json!({
            "operation": "comment.property.list",
            "issue": issue_metadata_result(&metadata, &self.config),
            "commentId": inputs.comment_id,
            "keys": keys,
            "count": count,
        });
        enforce_result_size(&result, self.limits.max_upstream_response_bytes)?;
        Ok(ProviderResult::new(result)
            .with_audit(json!({
                "provider": "jira",
                "operation": "comment.property.list",
                "issueKey": metadata.key,
                "project": metadata.project,
                "commentId": inputs.comment_id,
                "propertyCount": count,
                "credentialMode": request.credential_mode(),
                "egressProxy": self.backend.egress_proxy_audit(credential),
            }))
            .with_upstream(
                Some(response.status),
                Some(metadata_duration_ms + proof_response.duration_ms + response.duration_ms),
            )
            .with_object_ids(json!({
                "issueId": metadata.id,
                "issueKey": metadata.key,
                "commentId": inputs.comment_id,
            })))
    }

    async fn invoke_comment_property_get(
        &self,
        request: ProviderInvocation,
    ) -> Result<ProviderResult, ProviderError> {
        let credential = invocation_credential(request.admitted())?;
        let lookup_credential = lookup_credential(request.admitted())?;
        let inputs =
            parse_comment_property_inputs("comment.property.get", request.inputs(), &self.config)?;
        let property_key = inputs.property_key.as_deref().ok_or_else(|| {
            ProviderError::deny(ReasonCode::InputInvalid, "propertyKey is required")
        })?;
        let (metadata, proof_response, metadata_duration_ms) = self
            .confirm_comment_membership(
                &inputs.locator,
                &inputs.comment_id,
                lookup_credential,
                credential,
            )
            .await?;
        let response = self
            .backend
            .comment_property(&inputs.comment_id, property_key, credential)
            .await
            .map_err(jira_backend_error)?;
        let result = json!({
            "operation": "comment.property.get",
            "issue": issue_metadata_result(&metadata, &self.config),
            "commentId": inputs.comment_id,
            "propertyKey": property_key,
            "value": response.value,
        });
        enforce_result_size(&result, self.limits.max_upstream_response_bytes)?;
        Ok(ProviderResult::new(result)
            .with_audit(json!({
                "provider": "jira",
                "operation": "comment.property.get",
                "issueKey": metadata.key,
                "project": metadata.project,
                "commentId": inputs.comment_id,
                "propertyKey": property_key,
                "credentialMode": request.credential_mode(),
                "egressProxy": self.backend.egress_proxy_audit(credential),
            }))
            .with_upstream(
                Some(response.status),
                Some(metadata_duration_ms + proof_response.duration_ms + response.duration_ms),
            )
            .with_object_ids(json!({
                "issueId": metadata.id,
                "issueKey": metadata.key,
                "commentId": inputs.comment_id,
                "propertyKey": property_key,
            })))
    }

    async fn invoke_comment_property_set(
        &self,
        request: ProviderInvocation,
    ) -> Result<ProviderResult, ProviderError> {
        let credential = invocation_credential(request.admitted())?;
        let lookup_credential = lookup_credential(request.admitted())?;
        let inputs =
            parse_comment_property_inputs("comment.property.set", request.inputs(), &self.config)?;
        let property_key = inputs.property_key.as_deref().ok_or_else(|| {
            ProviderError::deny(ReasonCode::InputInvalid, "propertyKey is required")
        })?;
        let value = inputs
            .value
            .clone()
            .ok_or_else(|| ProviderError::deny(ReasonCode::InputInvalid, "value is required"))?;
        let (metadata, proof_response, metadata_duration_ms) = self
            .confirm_comment_membership(
                &inputs.locator,
                &inputs.comment_id,
                lookup_credential,
                credential,
            )
            .await?;
        let write = JiraWrite::new(
            json!({ "issueId": metadata.id, "issueKey": metadata.key, "commentId": inputs.comment_id }),
        );
        let response = self
            .backend
            .set_comment_property(&inputs.comment_id, property_key, value, credential)
            .await
            .map_err(|error| write.failed(error))?;
        after_accepted_write("mutation_response", write.locators(), async {
            let result = json!({
                "operation": "comment.property.set",
                "issue": issue_metadata_result(&metadata, &self.config),
                "commentId": inputs.comment_id,
                "propertyKey": property_key,
                "status": "set",
            });
            enforce_result_size(&result, self.limits.max_upstream_response_bytes)?;
            Ok(ProviderResult::new(result)
                .with_audit(json!({
                    "provider": "jira",
                    "operation": "comment.property.set",
                    "issueKey": metadata.key,
                    "project": metadata.project,
                    "commentId": inputs.comment_id,
                    "propertyKey": property_key,
                    "credentialMode": request.credential_mode(),
                    "egressProxy": self.backend.egress_proxy_audit(credential),
                }))
                .with_upstream(
                    Some(response.status),
                    Some(metadata_duration_ms + proof_response.duration_ms + response.duration_ms),
                )
                .with_object_ids(json!({
                    "issueId": metadata.id,
                    "issueKey": metadata.key,
                    "commentId": inputs.comment_id,
                    "propertyKey": property_key,
                })))
        })
        .await
    }

    async fn invoke_comment_property_delete(
        &self,
        request: ProviderInvocation,
    ) -> Result<ProviderResult, ProviderError> {
        let credential = invocation_credential(request.admitted())?;
        let lookup_credential = lookup_credential(request.admitted())?;
        let inputs = parse_comment_property_inputs(
            "comment.property.delete",
            request.inputs(),
            &self.config,
        )?;
        let property_key = inputs.property_key.as_deref().ok_or_else(|| {
            ProviderError::deny(ReasonCode::InputInvalid, "propertyKey is required")
        })?;
        let (metadata, proof_response, metadata_duration_ms) = self
            .confirm_comment_membership(
                &inputs.locator,
                &inputs.comment_id,
                lookup_credential,
                credential,
            )
            .await?;
        let write = JiraWrite::new(
            json!({ "issueId": metadata.id, "issueKey": metadata.key, "commentId": inputs.comment_id }),
        );
        let response = self
            .backend
            .delete_comment_property(&inputs.comment_id, property_key, credential)
            .await
            .map_err(|error| write.failed(error))?;
        after_accepted_write("mutation_response", write.locators(), async {
            let result = json!({
                "operation": "comment.property.delete",
                "issue": issue_metadata_result(&metadata, &self.config),
                "commentId": inputs.comment_id,
                "propertyKey": property_key,
                "status": "deleted",
            });
            enforce_result_size(&result, self.limits.max_upstream_response_bytes)?;
            Ok(ProviderResult::new(result)
                .with_audit(json!({
                    "provider": "jira",
                    "operation": "comment.property.delete",
                    "issueKey": metadata.key,
                    "project": metadata.project,
                    "commentId": inputs.comment_id,
                    "propertyKey": property_key,
                    "credentialMode": request.credential_mode(),
                    "egressProxy": self.backend.egress_proxy_audit(credential),
                }))
                .with_upstream(
                    Some(response.status),
                    Some(metadata_duration_ms + proof_response.duration_ms + response.duration_ms),
                )
                .with_object_ids(json!({
                    "issueId": metadata.id,
                    "issueKey": metadata.key,
                    "commentId": inputs.comment_id,
                    "propertyKey": property_key,
                })))
        })
        .await
    }

    async fn invoke_attachment_add(
        &self,
        request: ProviderInvocation,
    ) -> Result<ProviderResult, ProviderError> {
        let credential = invocation_credential(request.admitted())?;
        let lookup_credential = lookup_credential(request.admitted())?;
        let inputs = parse_attachment_add_inputs(request.inputs())?;
        let metadata_response =
            match ProviderState::optional::<JiraIssuePreflight>(request.state())? {
                Some(preflight) => JiraBackendResponse {
                    value: preflight.metadata.clone(),
                    status: preflight.upstream_status,
                    duration_ms: preflight.upstream_duration_ms,
                },
                None => {
                    self.confirm_issue_project(&inputs.issue, lookup_credential)
                        .await?
                }
            };
        let metadata = metadata_response.value;
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
        // Set when Jira throttled the upload that stopped the batch.
        let mut rate_limited = None;
        // Set when the SDK proved the upload that stopped the batch unsent.
        let mut stopped_unsent = false;
        // Set when the upload that stopped the batch may have applied.
        let mut stopped_uncertain = false;
        for (index, upload) in uploads.iter().cloned().enumerate() {
            let upload_audit = attachment_upload_audit(&upload);
            match self
                .backend
                .add_attachment(&metadata.key, upload, credential)
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
                    if let JiraBackendError::RateLimited(retry_after) = &error {
                        rate_limited = Some(*retry_after);
                    }
                    stopped_unsent = matches!(error, JiraBackendError::NotSent { .. });
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
            let mut error =
                ProviderError::error(ReasonCode::UpstreamFailed, "Jira attachment upload failed");
            if let Some(retry_after) = rate_limited {
                error = error.interrupted_by_upstream_rate_limit("jira", retry_after);
            }
            if stopped_unsent {
                // The first upload never reached Jira and the rest were
                // skipped, so nothing was applied.
                error = error.with_mutation_receipt(MutationReceipt::not_applied());
            } else if stopped_uncertain {
                error = error.with_mutation_receipt(MutationReceipt::unknown());
            }
            return Err(error.with_audit(json!({
                "provider": "jira",
                "operation": "attachment.add",
                "issueKey": metadata.key,
                "project": metadata.project,
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
            "issueKey": metadata.key,
            "project": metadata.project,
            "attachments": successes,
            "failures": failures,
        });
        // Uploads were applied: repeating the batch would upload them again.
        enforce_result_size(&result, self.limits.max_upstream_response_bytes)
            .map_err(|error| error.or_mutation_receipt(MutationReceipt::unknown()))?;
        let audit = json!({
            "provider": "jira",
            "operation": "attachment.add",
            "issueKey": metadata.key,
            "project": metadata.project,
            "status": status,
            "successCount": successes.len(),
            "failureCount": failures.len(),
            "attachments": attachment_audit,
            "credentialMode": request.credential_mode(),
            "egressProxy": self.backend.egress_proxy_audit(credential),
        });
        let object_ids = json!({
            "issueId": metadata.id,
            "issueKey": metadata.key,
            "attachmentIds": successes.iter().filter_map(|value| {
                value.get("attachmentId").and_then(Value::as_str).map(ToString::to_string)
            }).collect::<Vec<_>>(),
        });
        if !failures.is_empty() {
            let mut error = ProviderError::error(
                ReasonCode::UpstreamFailed,
                "Jira attachment upload partially failed",
            )
            .with_result(result);
            if rate_limited.is_some() {
                // Earlier uploads applied: waiting and repeating the batch would
                // upload them again, so this is not a rate limit. The partial
                // result keeps the created attachments.
                error = error.partially_applied_before_throttling(
                    "jira",
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
        let credential = invocation_credential(request.admitted())?;
        let lookup_credential = lookup_credential(request.admitted())?;
        let inputs = parse_attachment_download_inputs(request.inputs())?;
        let metadata = self
            .confirm_issue_project(&inputs.issue, lookup_credential)
            .await?
            .value;
        let attachment = self
            .attachment_for_issue(&metadata.key, &inputs.attachment_id, lookup_credential)
            .await?;
        validate_download_attachment(&attachment, &self.config)?;
        let response = self
            .backend
            .attachment_content(&inputs.attachment_id, credential)
            .await
            .map_err(jira_backend_error)?;
        validate_download_content(&response.value, &attachment, &self.config)?;
        if response
            .value
            .size
            .is_some_and(|size| size > self.limits.max_download_bytes)
        {
            return Err(ProviderError::deny(
                ReasonCode::AttachmentSizeDenied,
                "Jira attachment download exceeded the configured byte cap",
            ));
        }
        let downloaded_size = attachment.size;
        if downloaded_size > self.config.attachments.max_download_bytes
            || downloaded_size > self.limits.max_download_bytes
        {
            return Err(ProviderError::deny(
                ReasonCode::AttachmentSizeDenied,
                "Jira attachment download exceeded the configured byte cap",
            ));
        }
        let content_type = response.value.content_type.clone();
        let mut result = json!({
            "issueKey": metadata.key,
            "project": metadata.project,
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
            "Jira attachment response size did not match metadata",
        );
        let mut audit = json!({
            "provider": "jira",
            "operation": "attachment.download",
            "issueKey": metadata.key,
            "project": metadata.project,
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
                "issueId": metadata.id,
                "issueKey": metadata.key,
                "attachmentId": attachment.id,
            })))
    }

    async fn invoke_attachment_list(
        &self,
        request: ProviderInvocation,
    ) -> Result<ProviderResult, ProviderError> {
        let credential = invocation_credential(request.admitted())?;
        let lookup_credential = lookup_credential(request.admitted())?;
        let inputs = parse_attachment_list_inputs(request.inputs(), &self.config)?;
        let metadata_response = self
            .backend
            .issue_metadata(&inputs.locator.issue_key, lookup_credential)
            .await
            .map_err(jira_backend_error)?;
        let metadata = metadata_response.value;
        if !is_issue_key(&metadata.key) || issue_key_project(&metadata.key) != metadata.project {
            return Err(ProviderError::error(
                ReasonCode::UpstreamProtocolFailed,
                "Jira issue response did not include a valid current key and project",
            ));
        }
        let list_response = self
            .backend
            .issue_attachment_list(&metadata.key, credential)
            .await
            .map_err(jira_backend_error)?;
        let listed = list_response.value;
        if listed.issue.id != metadata.id
            || listed.issue.key != metadata.key
            || listed.issue.project != metadata.project
        {
            return Err(ProviderError::error(
                ReasonCode::UpstreamProtocolFailed,
                "Jira attachment list response did not match the resolved issue",
            ));
        }
        let attachments = listed
            .attachments
            .iter()
            .map(|attachment| {
                json!({
                    "attachmentId": attachment.id,
                    "filename": attachment.filename,
                    "size": attachment.size,
                    "contentType": attachment.content_type,
                })
            })
            .collect::<Vec<_>>();
        let attachment_ids = listed
            .attachments
            .iter()
            .map(|attachment| attachment.id.clone())
            .collect::<Vec<_>>();
        let count = attachments.len();
        let result = json!({
            "operation": "attachment.list",
            "issue": issue_metadata_result(&metadata, &self.config),
            "attachments": attachments,
            "count": count,
        });
        enforce_result_size(&result, self.limits.max_upstream_response_bytes)?;
        Ok(ProviderResult::new(result)
            .with_audit(json!({
                "provider": "jira",
                "operation": "attachment.list",
                "issueKey": metadata.key,
                "project": metadata.project,
                "attachmentCount": count,
                "credentialMode": request.credential_mode(),
                "egressProxy": self.backend.egress_proxy_audit(credential),
            }))
            .with_upstream(
                Some(list_response.status),
                Some(metadata_response.duration_ms + list_response.duration_ms),
            )
            .with_object_ids(json!({
                "issueId": metadata.id,
                "issueKey": metadata.key,
                "attachmentIds": attachment_ids,
            })))
    }

    async fn invoke_verify(
        &self,
        request: ProviderInvocation,
    ) -> Result<ProviderResult, ProviderError> {
        let credential = invocation_credential(request.admitted())?;
        let lookup_credential = lookup_credential(request.admitted())?;
        let inputs = parse_verify_inputs(request.inputs())?;
        let metadata_response = self
            .confirm_issue_project(&inputs.issue, lookup_credential)
            .await?;
        let mut upstream_duration_ms = metadata_response.duration_ms;
        let mut upstream_status = Some(metadata_response.status);
        let metadata = metadata_response.value;
        let mut checked = Vec::new();
        if let Some(comment_id) = &inputs.expect_comment_id {
            match self
                .backend
                .comment(&metadata.key, comment_id, credential)
                .await
            {
                Ok(response) if response.value.id == *comment_id => {
                    upstream_duration_ms += response.duration_ms;
                    upstream_status = Some(response.status);
                    checked.push(json!({"type": "comment", "id": comment_id}));
                }
                Err(JiraBackendError::NotFound) => {
                    return Err(verification_mismatch_error(
                        &request,
                        &metadata,
                        &checked,
                        json!({"type": "comment", "id": comment_id}),
                        &inputs,
                        self.backend.egress_proxy_audit(credential),
                    ));
                }
                Err(error) => return Err(jira_backend_error(error)),
                Ok(_) => {
                    return Err(verification_mismatch_error(
                        &request,
                        &metadata,
                        &checked,
                        json!({"type": "comment", "id": comment_id}),
                        &inputs,
                        self.backend.egress_proxy_audit(credential),
                    ));
                }
            }
        }
        if let Some(attachment_id) = &inputs.expect_attachment_id {
            match self
                .attachment_for_issue_response(&metadata.key, attachment_id, credential)
                .await
            {
                Ok(response) => {
                    upstream_duration_ms += response.duration_ms;
                    upstream_status = Some(response.status);
                }
                Err(error) if error.reason_code() == ReasonCode::ScopeUnresolved => {
                    return Err(verification_mismatch_error(
                        &request,
                        &metadata,
                        &checked,
                        json!({"type": "attachment", "id": attachment_id}),
                        &inputs,
                        self.backend.egress_proxy_audit(credential),
                    ));
                }
                Err(error) => return Err(error),
            }
            checked.push(json!({"type": "attachment", "id": attachment_id}));
        }
        let result = json!({
            "verification": {
                "status": "matched",
                "checked": checked,
            },
            "issueKey": metadata.key,
            "project": metadata.project,
        });
        enforce_result_size(&result, self.limits.max_upstream_response_bytes)?;
        Ok(ProviderResult::new(result)
            .with_audit(json!({
                "provider": "jira",
                "operation": "verify",
                "issueKey": metadata.key,
                "project": metadata.project,
                "checked": checked,
                "credentialMode": request.credential_mode(),
                "egressProxy": self.backend.egress_proxy_audit(credential),
            }))
            .with_upstream(upstream_status, Some(upstream_duration_ms))
            .with_object_ids(json!({
                "issueId": metadata.id,
                "issueKey": metadata.key,
                "commentId": inputs.expect_comment_id,
                "attachmentId": inputs.expect_attachment_id,
            })))
    }

    async fn confirm_issue_project(
        &self,
        issue_key: &str,
        credential: &ExecutionCredential,
    ) -> Result<JiraBackendResponse<JiraIssueMetadata>, ProviderError> {
        let locator = issue_locator_from_key(issue_key)?;
        self.confirm_issue_locator(&locator, credential).await
    }

    async fn confirm_issue_locator(
        &self,
        locator: &IssueLocator,
        credential: &ExecutionCredential,
    ) -> Result<JiraBackendResponse<JiraIssueMetadata>, ProviderError> {
        let response = self
            .backend
            .issue_metadata(&locator.issue_key, credential)
            .await
            .map_err(jira_backend_error)?;
        if !is_issue_key(&response.value.key)
            || issue_key_project(&response.value.key) != response.value.project
        {
            return Err(ProviderError::error(
                ReasonCode::UpstreamProtocolFailed,
                "Jira issue response did not include a valid current key and project",
            ));
        }
        Ok(response)
    }

    async fn confirm_dependency_issue_metadata(
        &self,
        inputs: &IssueDependencyAddInputs,
        credential: &ExecutionCredential,
    ) -> Result<(JiraIssueMetadata, JiraIssueMetadata, u64), ProviderError> {
        let blocking_response = self
            .confirm_issue_locator(&inputs.blocking, credential)
            .await?;
        let blocked_response = self
            .confirm_issue_locator(&inputs.blocked, credential)
            .await?;
        let duration_ms = blocking_response.duration_ms + blocked_response.duration_ms;
        let blocking = blocking_response.value;
        let blocked = blocked_response.value;
        if blocking.key == blocked.key {
            return Err(ProviderError::deny(
                ReasonCode::InputInvalid,
                "jira.issue.dependency.add cannot link an issue to itself",
            ));
        }
        Ok((blocking, blocked, duration_ms))
    }

    async fn confirm_parent_set_issue_metadata(
        &self,
        inputs: &IssueParentSetInputs,
        credential: &ExecutionCredential,
    ) -> Result<(JiraIssueMetadata, JiraIssueMetadata, u64), ProviderError> {
        let issue_response = self
            .confirm_issue_locator(&inputs.issue, credential)
            .await?;
        let parent_response = self
            .confirm_issue_locator(&inputs.parent, credential)
            .await?;
        let duration_ms = issue_response.duration_ms + parent_response.duration_ms;
        let issue = issue_response.value;
        let parent = parent_response.value;
        if issue.key == parent.key {
            return Err(ProviderError::deny(
                ReasonCode::InputInvalid,
                "jira.issue.parent.set cannot parent an issue to itself",
            ));
        }
        Ok((issue, parent, duration_ms))
    }

    async fn confirm_comment_membership(
        &self,
        locator: &IssueLocator,
        comment_id: &str,
        lookup_credential: &ExecutionCredential,
        credential: &ExecutionCredential,
    ) -> Result<(JiraIssueMetadata, JiraBackendResponse<JiraComment>, u64), ProviderError> {
        let metadata_response = self
            .confirm_issue_locator(locator, lookup_credential)
            .await?;
        let metadata_duration_ms = metadata_response.duration_ms;
        let metadata = metadata_response.value;
        let proof_response = self
            .backend
            .comment(&metadata.key, comment_id, credential)
            .await
            .map_err(jira_backend_error)?;
        validate_returned_comment_id(&proof_response.value.id, Some(comment_id))?;
        Ok((metadata, proof_response, metadata_duration_ms))
    }

    fn validate_configured_comment_body_format(&self, action: &str) -> Result<(), ProviderError> {
        if self
            .config
            .content
            .comment_formats
            .iter()
            .any(|format| format == "adf")
        {
            Ok(())
        } else {
            Err(ProviderError::deny(
                ReasonCode::BodyFormatUnsupported,
                format!("{action} requires configured native ADF support"),
            ))
        }
    }

    fn comment_property_key_allowed_for_return(&self, key: &str) -> bool {
        valid_jira_comment_property_key_shape(key)
            && !jira_comment_property_key_reserved(key)
            && self
                .config
                .comments
                .allowed_property_key_prefixes
                .iter()
                .any(|prefix| key.starts_with(prefix))
    }

    async fn attachment_for_issue(
        &self,
        issue_key: &str,
        attachment_id: &str,
        credential: &ExecutionCredential,
    ) -> Result<JiraAttachment, ProviderError> {
        Ok(self
            .attachment_for_issue_response(issue_key, attachment_id, credential)
            .await?
            .value)
    }

    async fn attachment_for_issue_response(
        &self,
        issue_key: &str,
        attachment_id: &str,
        credential: &ExecutionCredential,
    ) -> Result<JiraBackendResponse<JiraAttachment>, ProviderError> {
        let response = self
            .backend
            .issue_attachment_metadata(issue_key, credential)
            .await
            .map_err(jira_backend_error)?;
        let status = response.status;
        let duration_ms = response.duration_ms;
        let value = response
            .value
            .into_iter()
            .find(|attachment| attachment.id == attachment_id)
            .ok_or_else(|| {
                ProviderError::deny(
                    ReasonCode::ScopeUnresolved,
                    "Jira attachment did not belong to the authorized issue",
                )
            })?;
        Ok(JiraBackendResponse {
            value,
            status,
            duration_ms,
        })
    }
}

#[derive(Debug, Clone)]
struct IssueLocator {
    issue_key: String,
    candidate_project: String,
}

fn issue_locator_from_inputs(
    inputs: &Value,
    config: &JiraProviderConfig,
) -> Result<IssueLocator, ProviderError> {
    let object = inputs.as_object().ok_or_else(|| {
        ProviderError::deny(
            ReasonCode::InputInvalid,
            "jira.issue.view requires issue or url",
        )
    })?;
    let issue = object.get("issue").and_then(Value::as_str);
    let url = object.get("url").and_then(Value::as_str);
    match (issue, url) {
        (Some(issue), None) => issue_locator_from_key(issue),
        (None, Some(url)) => issue_locator_from_url(url, config),
        _ => Err(ProviderError::deny(
            ReasonCode::InputInvalid,
            "jira.issue.view requires exactly one of issue or url",
        )),
    }
}

fn issue_locator_for_action(
    action: &str,
    inputs: &Value,
    config: &JiraProviderConfig,
) -> Result<IssueLocator, ProviderError> {
    match action {
        "issue.view" => issue_locator_from_inputs(inputs, config),
        "issue.update" => parse_issue_update_inputs(inputs, config).map(|inputs| inputs.locator),
        "comment.list" => parse_comment_list_inputs(inputs, config).map(|inputs| inputs.locator),
        "comment.view" => parse_comment_view_inputs(inputs, config).map(|inputs| inputs.locator),
        "comment.add" => parse_comment_add_inputs(inputs, config).map(|inputs| inputs.locator),
        "comment.reply" => parse_comment_reply_inputs(inputs, config).map(|inputs| inputs.locator),
        "comment.update" => {
            parse_comment_update_inputs(inputs, config).map(|inputs| inputs.locator)
        }
        "comment.delete" => parse_comment_view_inputs(inputs, config).map(|inputs| inputs.locator),
        "comment.property.list"
        | "comment.property.get"
        | "comment.property.set"
        | "comment.property.delete" => {
            parse_comment_property_inputs(action, inputs, config).map(|inputs| inputs.locator)
        }
        "attachment.list" => {
            parse_attachment_list_inputs(inputs, config).map(|inputs| inputs.locator)
        }
        "attachment.add" | "attachment.download" | "verify" => {
            let issue = inputs.get("issue").and_then(Value::as_str).ok_or_else(|| {
                ProviderError::deny(
                    ReasonCode::InputInvalid,
                    "Jira action requires an issue key",
                )
            })?;
            issue_locator_from_key(issue)
        }
        _ => Err(ProviderError::deny(
            ReasonCode::ServiceActionDenied,
            "Jira action is not supported",
        )),
    }
}

fn issue_scopes_from_metadata(
    metadata: &JiraIssueMetadata,
) -> Result<ResourceScopes, ProviderError> {
    if !is_issue_key(&metadata.key) || issue_key_project(&metadata.key) != metadata.project {
        return Err(ProviderError::error(
            ReasonCode::UpstreamProtocolFailed,
            "Jira issue response did not include a valid current key and project",
        ));
    }
    Ok(ResourceScopes::from([(
        "project".to_string(),
        vec![metadata.project.clone()],
    )]))
}

fn merged_issue_locator_scopes<const N: usize>(locators: [&IssueLocator; N]) -> ResourceScopes {
    let mut projects = BTreeSet::new();
    for locator in locators {
        projects.insert(locator.candidate_project.clone());
    }
    ResourceScopes::from([("project".to_string(), projects.into_iter().collect())])
}

fn merged_issue_metadata_scopes<const N: usize>(
    metadata: [&JiraIssueMetadata; N],
) -> ResourceScopes {
    let mut projects = BTreeSet::new();
    for issue in metadata {
        projects.insert(issue.project.clone());
    }
    ResourceScopes::from([("project".to_string(), projects.into_iter().collect())])
}

fn child_create_locator_scopes(project: &str, parent: &IssueLocator) -> ResourceScopes {
    let mut projects = BTreeSet::new();
    projects.insert(project.to_string());
    projects.insert(parent.candidate_project.clone());
    ResourceScopes::from([("project".to_string(), projects.into_iter().collect())])
}

fn child_create_metadata_scopes(project: &str, parent: &JiraIssueMetadata) -> ResourceScopes {
    let mut projects = BTreeSet::new();
    projects.insert(project.to_string());
    projects.insert(parent.project.clone());
    ResourceScopes::from([("project".to_string(), projects.into_iter().collect())])
}

fn issue_locator_from_key(issue_key: &str) -> Result<IssueLocator, ProviderError> {
    if !is_issue_key(issue_key) {
        return Err(ProviderError::deny(
            ReasonCode::LocatorInvalid,
            "Jira issue key is invalid",
        ));
    }
    Ok(IssueLocator {
        issue_key: issue_key.to_string(),
        candidate_project: issue_key_project(issue_key),
    })
}

fn issue_locator_from_url(
    raw: &str,
    config: &JiraProviderConfig,
) -> Result<IssueLocator, ProviderError> {
    let raw = raw.trim();
    if jira_raw_url_has_explicit_authority_port(raw) {
        return Err(ProviderError::deny(
            ReasonCode::LocatorInvalid,
            "Jira issue URL tenant is not configured",
        ));
    }
    let url = Url::parse(raw).map_err(|_| {
        ProviderError::deny(ReasonCode::LocatorInvalid, "Jira issue URL is invalid")
    })?;
    if !jira_url_has_exact_authority(&url, &config.tenant_host) {
        return Err(ProviderError::deny(
            ReasonCode::LocatorInvalid,
            "Jira issue URL tenant is not configured",
        ));
    }
    if url.query().is_some() || url.fragment().is_some() {
        return Err(ProviderError::deny(
            ReasonCode::LocatorInvalid,
            "Jira issue URL must not include query or fragment components",
        ));
    }
    let mut segments = url.path_segments().ok_or_else(|| {
        ProviderError::deny(ReasonCode::LocatorInvalid, "Jira issue URL path is invalid")
    })?;
    let segments = segments.by_ref().collect::<Vec<_>>();
    match segments.as_slice() {
        ["browse", issue_key] => issue_locator_from_key(issue_key),
        _ => issue_locator_from_modern_jira_url_path(&segments).ok_or_else(|| {
            ProviderError::deny(ReasonCode::LocatorInvalid, "Jira issue URL path is invalid")
        })?,
    }
}

fn issue_locator_from_modern_jira_url_path(
    segments: &[&str],
) -> Option<Result<IssueLocator, ProviderError>> {
    if segments.first() != Some(&"jira") {
        return None;
    }
    for (index, segment) in segments.iter().enumerate() {
        if *segment != "projects" {
            continue;
        }
        if index + 3 >= segments.len()
            || segments.get(index + 2) != Some(&"issues")
            || index + 3 != segments.len() - 1
        {
            continue;
        }
        let project = segments[index + 1];
        let issue_key = segments[index + 3];
        return Some(issue_locator_from_key(issue_key).and_then(|locator| {
            if locator.candidate_project != project {
                return Err(ProviderError::deny(
                    ReasonCode::LocatorInvalid,
                    "Jira issue URL project does not match issue key",
                ));
            }
            Ok(locator)
        }));
    }
    None
}

fn jira_url_has_exact_authority(url: &Url, tenant_host: &str) -> bool {
    url.scheme() == "https"
        && url.host_str() == Some(tenant_host)
        && url.username().is_empty()
        && url.password().is_none()
        && url.port().is_none()
}

fn jira_raw_url_has_explicit_authority_port(raw: &str) -> bool {
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

const MAX_JIRA_ISSUE_SUMMARY_BYTES: usize = 1024;

#[derive(Debug, Clone)]
struct ContentWriteAudit {
    requested_format: String,
    source_bytes: u64,
    final_native_bytes: Option<u64>,
}

fn prepare_jira_content(
    action: &str,
    content_format: &str,
    content: &Value,
    max_body_bytes: u64,
) -> Result<(Value, ContentWriteAudit), ProviderError> {
    let source_bytes = match content_format {
        "adf" => serde_json::to_vec(content)
            .map(|bytes| bytes.len() as u64)
            .map_err(|_| ProviderError::deny(ReasonCode::BodyMalformed, "ADF body is invalid"))?,
        "markdown" | "plain_text" => content
            .as_str()
            .map(|value| value.len() as u64)
            .ok_or_else(|| {
                ProviderError::deny(
                    ReasonCode::InputInvalid,
                    format!("{action} content must be a string for {content_format}"),
                )
            })?,
        _ => {
            return Err(ProviderError::deny(
                ReasonCode::BodyFormatUnsupported,
                format!("{action} contentFormat is unsupported"),
            ));
        }
    };
    if source_bytes > max_body_bytes {
        return Err(ProviderError::deny(
            ReasonCode::BodySizeDenied,
            format!("{action} source content exceeded the configured byte cap"),
        ));
    }

    let body = match content_format {
        "adf" => {
            if !content.is_object() {
                return Err(ProviderError::deny(
                    ReasonCode::InputInvalid,
                    format!("{action} content must be an object for adf"),
                ));
            }
            validate_adf_body(content)?;
            content.clone()
        }
        "markdown" => markdown_to_adf_bounded(
            content
                .as_str()
                .expect("normalized content type was validated"),
            max_body_bytes,
        )
        .map_err(map_content_write_error)?,
        "plain_text" => plain_text_to_adf_bounded(
            content
                .as_str()
                .expect("normalized content type was validated"),
            max_body_bytes,
        )
        .map_err(map_content_write_error)?,
        _ => unreachable!("content format was validated"),
    };
    validate_adf_body(&body)?;
    Ok((
        body,
        ContentWriteAudit {
            requested_format: content_format.to_string(),
            source_bytes,
            final_native_bytes: None,
        },
    ))
}

fn map_content_write_error(error: ContentWriteError) -> ProviderError {
    match error {
        ContentWriteError::SizeDenied => ProviderError::deny(
            ReasonCode::BodySizeDenied,
            "converted Jira content exceeded the configured byte cap",
        ),
        ContentWriteError::ComplexityDenied | ContentWriteError::Malformed => ProviderError::deny(
            ReasonCode::BodyMalformed,
            "Jira content could not be converted safely",
        ),
    }
}

fn finalize_jira_content(
    body: &Value,
    audit: &mut ContentWriteAudit,
    max_body_bytes: u64,
    after_attribution: bool,
) -> Result<(), ProviderError> {
    validate_adf_body(body)?;
    let final_bytes = serialized_body_size(body)?;
    if final_bytes > max_body_bytes {
        let message = if after_attribution {
            "Jira body exceeded the configured byte cap after broker attribution was added"
        } else {
            "Jira body exceeded the configured byte cap"
        };
        return Err(ProviderError::deny(ReasonCode::BodySizeDenied, message));
    }
    audit.final_native_bytes = Some(final_bytes);
    Ok(())
}

fn merge_content_write_audit(audit: &mut Value, content: Option<&ContentWriteAudit>) {
    let Some(content) = content else { return };
    audit["contentFormat"] = json!(content.requested_format);
    audit["nativeContentFormat"] = json!("adf");
    audit["sourceContentBytes"] = json!(content.source_bytes);
    if let Some(final_native_bytes) = content.final_native_bytes {
        audit["finalNativeContentBytes"] = json!(final_native_bytes);
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct IssueTypeListInputs {
    project: String,
    #[serde(default)]
    start_at: u32,
    #[serde(default = "default_issue_type_max_results")]
    max_results: u32,
}

fn default_issue_type_max_results() -> u32 {
    50
}

fn parse_issue_type_list_inputs(inputs: &Value) -> Result<IssueTypeListInputs, ProviderError> {
    let mut parsed: IssueTypeListInputs = serde_json::from_value(inputs.clone()).map_err(|_| {
        ProviderError::deny(
            ReasonCode::InputInvalid,
            "jira.issue_type.list inputs are invalid",
        )
    })?;
    parsed.project = validate_project_key(&parsed.project)?;
    if !(1..=100).contains(&parsed.max_results) {
        return Err(ProviderError::deny(
            ReasonCode::InputInvalid,
            "jira.issue_type.list maxResults must be between 1 and 100",
        ));
    }
    Ok(parsed)
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct IssueCreateRawInputs {
    project: String,
    issue_type_id: String,
    summary: String,
    content_format: Option<String>,
    content: Option<Value>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct IssueChildCreateRawInputs {
    project: String,
    issue_type_id: String,
    summary: String,
    parent_issue: Option<String>,
    parent_url: Option<String>,
    content_format: Option<String>,
    content: Option<Value>,
}

#[derive(Debug)]
struct IssueCreateInputs {
    project: String,
    issue_type_id: String,
    summary: String,
    description: Option<Value>,
    content_audit: Option<ContentWriteAudit>,
}

#[derive(Debug)]
struct IssueChildCreateInputs {
    project: String,
    issue_type_id: String,
    summary: String,
    description: Option<Value>,
    content_audit: Option<ContentWriteAudit>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct IssueUpdateRawInputs {
    issue: Option<String>,
    url: Option<String>,
    summary: Option<String>,
    content_format: Option<String>,
    content: Option<Value>,
    notify_users: Option<bool>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct IssueDependencyAddRawInputs {
    blocking_issue: Option<String>,
    blocking_url: Option<String>,
    blocked_issue: Option<String>,
    blocked_url: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct IssueParentSetRawInputs {
    issue: Option<String>,
    url: Option<String>,
    parent_issue: Option<String>,
    parent_url: Option<String>,
}

#[derive(Debug)]
struct IssueDependencyAddInputs {
    blocking: IssueLocator,
    blocked: IssueLocator,
}

#[derive(Debug)]
struct IssueParentSetInputs {
    issue: IssueLocator,
    parent: IssueLocator,
}

#[derive(Debug)]
struct IssueUpdateInputs {
    locator: IssueLocator,
    summary: Option<String>,
    description: Option<Value>,
    content_audit: Option<ContentWriteAudit>,
    notify_users: Option<bool>,
}

impl IssueUpdateInputs {
    fn changed_fields(&self) -> Vec<String> {
        let mut fields = Vec::new();
        if self.summary.is_some() {
            fields.push("summary".to_string());
        }
        if self.description.is_some() {
            fields.push("description".to_string());
        }
        fields
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CommentListRawInputs {
    issue: Option<String>,
    url: Option<String>,
    max_results: Option<u32>,
    start_at: Option<u32>,
    order_by: Option<String>,
}

#[derive(Debug)]
struct CommentListInputs {
    locator: IssueLocator,
    max_results: u32,
    start_at: u32,
    order_by: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CommentViewRawInputs {
    issue: Option<String>,
    url: Option<String>,
    comment_id: String,
}

#[derive(Debug)]
struct CommentViewInputs {
    locator: IssueLocator,
    comment_id: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CommentAddRawInputs {
    issue: Option<String>,
    url: Option<String>,
    content_format: String,
    content: Value,
    visibility: Option<CommentVisibilityInput>,
}

#[derive(Debug)]
struct CommentAddInputs {
    locator: IssueLocator,
    body: Value,
    content_audit: ContentWriteAudit,
    visibility: Option<JiraCommentVisibility>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CommentReplyRawInputs {
    issue: Option<String>,
    url: Option<String>,
    parent_comment_id: String,
    content_format: String,
    content: Value,
    visibility: Option<CommentVisibilityInput>,
}

#[derive(Debug)]
struct CommentReplyInputs {
    locator: IssueLocator,
    parent_comment_id: String,
    body: Value,
    content_audit: ContentWriteAudit,
    visibility: Option<JiraCommentVisibility>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CommentUpdateRawInputs {
    issue: Option<String>,
    url: Option<String>,
    comment_id: String,
    content_format: String,
    content: Value,
    visibility_mode: Option<String>,
    visibility: Option<CommentVisibilityInput>,
    notify_users: Option<bool>,
}

#[derive(Debug)]
struct CommentUpdateInputs {
    locator: IssueLocator,
    comment_id: String,
    body: Value,
    content_audit: ContentWriteAudit,
    visibility_mode: CommentVisibilityMode,
    visibility: Option<JiraCommentVisibility>,
    notify_users: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CommentVisibilityMode {
    Preserve,
    Set,
}

impl CommentVisibilityMode {
    fn audit_value(self) -> &'static str {
        match self {
            Self::Preserve => "preserve",
            Self::Set => "set",
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CommentVisibilityInput {
    #[serde(rename = "type")]
    visibility_type: String,
    value: Option<String>,
    identifier: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CommentPropertyRawInputs {
    issue: Option<String>,
    url: Option<String>,
    comment_id: String,
    property_key: Option<String>,
    value: Option<Value>,
}

#[derive(Debug)]
struct CommentPropertyInputs {
    locator: IssueLocator,
    comment_id: String,
    property_key: Option<String>,
    value: Option<Value>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct AttachmentAddInputs {
    issue: String,
    attachments: Vec<AttachmentInput>,
}

#[derive(Debug, Deserialize)]
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
    issue: String,
    attachment_id: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct AttachmentListRawInputs {
    issue: Option<String>,
    url: Option<String>,
}

#[derive(Debug)]
struct AttachmentListInputs {
    locator: IssueLocator,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct VerifyInputs {
    issue: String,
    expect_comment_id: Option<String>,
    expect_attachment_id: Option<String>,
}

fn parse_issue_update_inputs(
    inputs: &Value,
    config: &JiraProviderConfig,
) -> Result<IssueUpdateInputs, ProviderError> {
    let object = inputs.as_object().ok_or_else(|| {
        ProviderError::deny(
            ReasonCode::InputInvalid,
            "jira.issue.update inputs are invalid",
        )
    })?;
    if object
        .get("summary")
        .is_some_and(|summary| !summary.is_string())
    {
        return Err(ProviderError::deny(
            ReasonCode::InputInvalid,
            "jira.issue.update summary must be a string",
        ));
    }
    if object
        .get("notifyUsers")
        .is_some_and(|notify_users| !notify_users.is_boolean())
    {
        return Err(ProviderError::deny(
            ReasonCode::InputInvalid,
            "jira.issue.update notifyUsers must be a boolean",
        ));
    }
    let parsed: IssueUpdateRawInputs = serde_json::from_value(inputs.clone()).map_err(|_| {
        ProviderError::deny(
            ReasonCode::InputInvalid,
            "jira.issue.update inputs are invalid",
        )
    })?;
    let _validated_content_fields = (&parsed.content_format, &parsed.content);
    let locator =
        issue_locator_from_optional(parsed.issue, parsed.url, config, "jira.issue.update")?;
    let prepared_content =
        prepare_optional_jira_content(object, "jira.issue.update", config.content.max_body_bytes)?;
    if parsed.summary.is_none() && prepared_content.is_none() {
        return Err(ProviderError::deny(
            ReasonCode::InputInvalid,
            "jira.issue.update requires summary or content with contentFormat",
        ));
    }
    if let Some(summary) = &parsed.summary {
        validate_issue_summary("jira.issue.update", summary)?;
    }
    let (description, content_audit) = prepared_content
        .map(|(body, audit)| (Some(body), Some(audit)))
        .unwrap_or((None, None));
    Ok(IssueUpdateInputs {
        locator,
        summary: parsed.summary,
        description,
        content_audit,
        notify_users: parsed.notify_users,
    })
}

fn parse_issue_dependency_add_inputs(
    inputs: &Value,
    config: &JiraProviderConfig,
) -> Result<IssueDependencyAddInputs, ProviderError> {
    let parsed: IssueDependencyAddRawInputs =
        serde_json::from_value(inputs.clone()).map_err(|_| {
            ProviderError::deny(
                ReasonCode::InputInvalid,
                "jira.issue.dependency.add inputs are invalid",
            )
        })?;
    let blocking = issue_locator_from_optional(
        parsed.blocking_issue,
        parsed.blocking_url,
        config,
        "jira.issue.dependency.add blocking locator",
    )?;
    let blocked = issue_locator_from_optional(
        parsed.blocked_issue,
        parsed.blocked_url,
        config,
        "jira.issue.dependency.add blocked locator",
    )?;
    if blocking.issue_key == blocked.issue_key {
        return Err(ProviderError::deny(
            ReasonCode::InputInvalid,
            "jira.issue.dependency.add cannot link an issue to itself",
        ));
    }
    Ok(IssueDependencyAddInputs { blocking, blocked })
}

fn parse_issue_parent_set_inputs(
    inputs: &Value,
    config: &JiraProviderConfig,
) -> Result<IssueParentSetInputs, ProviderError> {
    let parsed: IssueParentSetRawInputs = serde_json::from_value(inputs.clone()).map_err(|_| {
        ProviderError::deny(
            ReasonCode::InputInvalid,
            "jira.issue.parent.set inputs are invalid",
        )
    })?;
    let issue = issue_locator_from_optional(
        parsed.issue,
        parsed.url,
        config,
        "jira.issue.parent.set issue locator",
    )?;
    let parent = issue_locator_from_optional(
        parsed.parent_issue,
        parsed.parent_url,
        config,
        "jira.issue.parent.set parent locator",
    )?;
    if issue.issue_key == parent.issue_key {
        return Err(ProviderError::deny(
            ReasonCode::InputInvalid,
            "jira.issue.parent.set cannot parent an issue to itself",
        ));
    }
    Ok(IssueParentSetInputs { issue, parent })
}

fn parse_issue_create_inputs(
    inputs: &Value,
    config: &JiraProviderConfig,
) -> Result<IssueCreateInputs, ProviderError> {
    let object = inputs.as_object().ok_or_else(|| {
        ProviderError::deny(
            ReasonCode::InputInvalid,
            "jira.issue.create inputs are invalid",
        )
    })?;
    if object
        .get("project")
        .is_some_and(|project| !project.is_string())
    {
        return Err(ProviderError::deny(
            ReasonCode::InputInvalid,
            "jira.issue.create project must be a string",
        ));
    }
    if object
        .get("issueTypeId")
        .is_some_and(|issue_type_id| !issue_type_id.is_string())
    {
        return Err(ProviderError::deny(
            ReasonCode::InputInvalid,
            "jira.issue.create issueTypeId must be a string",
        ));
    }
    if object
        .get("summary")
        .is_some_and(|summary| !summary.is_string())
    {
        return Err(ProviderError::deny(
            ReasonCode::InputInvalid,
            "jira.issue.create summary must be a string",
        ));
    }
    let parsed: IssueCreateRawInputs = serde_json::from_value(inputs.clone()).map_err(|_| {
        ProviderError::deny(
            ReasonCode::InputInvalid,
            "jira.issue.create inputs are invalid",
        )
    })?;
    let _validated_content_fields = (&parsed.content_format, &parsed.content);
    let project = validate_project_key(&parsed.project)?;
    validate_issue_type_id("jira.issue.create", &parsed.issue_type_id)?;
    validate_issue_summary("jira.issue.create", &parsed.summary)?;
    let prepared_content =
        prepare_optional_jira_content(object, "jira.issue.create", config.content.max_body_bytes)?;
    let (description, content_audit) = prepared_content
        .map(|(body, audit)| (Some(body), Some(audit)))
        .unwrap_or((None, None));
    Ok(IssueCreateInputs {
        project,
        issue_type_id: parsed.issue_type_id,
        summary: parsed.summary,
        description,
        content_audit,
    })
}

#[derive(Debug)]
struct IssueCreateScopeInputs {
    project: String,
}

#[derive(Debug)]
struct IssueChildCreateScopeInputs {
    project: String,
    parent: IssueLocator,
}

fn parse_issue_create_scope_inputs(
    inputs: &Value,
) -> Result<IssueCreateScopeInputs, ProviderError> {
    let object = inputs.as_object().ok_or_else(|| {
        ProviderError::deny(
            ReasonCode::InputInvalid,
            "jira.issue.create inputs are invalid",
        )
    })?;
    let project = object
        .get("project")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            ProviderError::deny(
                ReasonCode::InputInvalid,
                "jira.issue.create project must be a string",
            )
        })?;
    Ok(IssueCreateScopeInputs {
        project: validate_project_key(project)?,
    })
}

fn parse_issue_child_create_scope_inputs(
    inputs: &Value,
    config: &JiraProviderConfig,
) -> Result<IssueChildCreateScopeInputs, ProviderError> {
    let object = inputs.as_object().ok_or_else(|| {
        ProviderError::deny(
            ReasonCode::InputInvalid,
            "jira.issue.child.create inputs are invalid",
        )
    })?;
    let project = object
        .get("project")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            ProviderError::deny(
                ReasonCode::InputInvalid,
                "jira.issue.child.create project must be a string",
            )
        })?;
    let parent_issue = optional_scope_string(object, "parentIssue", "jira.issue.child.create")?;
    let parent_url = optional_scope_string(object, "parentUrl", "jira.issue.child.create")?;
    let parent = issue_locator_from_optional(
        parent_issue,
        parent_url,
        config,
        "jira.issue.child.create parent locator",
    )?;
    Ok(IssueChildCreateScopeInputs {
        project: validate_project_key(project)?,
        parent,
    })
}

fn optional_scope_string(
    object: &serde_json::Map<String, Value>,
    field: &str,
    action: &str,
) -> Result<Option<String>, ProviderError> {
    object
        .get(field)
        .map(|value| {
            value.as_str().map(str::to_owned).ok_or_else(|| {
                ProviderError::deny(
                    ReasonCode::InputInvalid,
                    format!("{action} {field} must be a string"),
                )
            })
        })
        .transpose()
}

fn parse_issue_child_create_inputs(
    inputs: &Value,
    config: &JiraProviderConfig,
) -> Result<IssueChildCreateInputs, ProviderError> {
    let object = inputs.as_object().ok_or_else(|| {
        ProviderError::deny(
            ReasonCode::InputInvalid,
            "jira.issue.child.create inputs are invalid",
        )
    })?;
    if object
        .get("project")
        .is_some_and(|project| !project.is_string())
    {
        return Err(ProviderError::deny(
            ReasonCode::InputInvalid,
            "jira.issue.child.create project must be a string",
        ));
    }
    if object
        .get("issueTypeId")
        .is_some_and(|issue_type_id| !issue_type_id.is_string())
    {
        return Err(ProviderError::deny(
            ReasonCode::InputInvalid,
            "jira.issue.child.create issueTypeId must be a string",
        ));
    }
    if object
        .get("summary")
        .is_some_and(|summary| !summary.is_string())
    {
        return Err(ProviderError::deny(
            ReasonCode::InputInvalid,
            "jira.issue.child.create summary must be a string",
        ));
    }
    let parsed: IssueChildCreateRawInputs =
        serde_json::from_value(inputs.clone()).map_err(|_| {
            ProviderError::deny(
                ReasonCode::InputInvalid,
                "jira.issue.child.create inputs are invalid",
            )
        })?;
    let _validated_content_fields = (&parsed.content_format, &parsed.content);
    let project = validate_project_key(&parsed.project)?;
    validate_issue_type_id("jira.issue.child.create", &parsed.issue_type_id)?;
    validate_issue_summary("jira.issue.child.create", &parsed.summary)?;
    let prepared_content = prepare_optional_jira_content(
        object,
        "jira.issue.child.create",
        config.content.max_body_bytes,
    )?;
    let (description, content_audit) = prepared_content
        .map(|(body, audit)| (Some(body), Some(audit)))
        .unwrap_or((None, None));
    issue_locator_from_optional(
        parsed.parent_issue,
        parsed.parent_url,
        config,
        "jira.issue.child.create parent locator",
    )?;
    Ok(IssueChildCreateInputs {
        project,
        issue_type_id: parsed.issue_type_id,
        summary: parsed.summary,
        description,
        content_audit,
    })
}

fn prepare_optional_jira_content(
    object: &serde_json::Map<String, Value>,
    action: &str,
    max_body_bytes: u64,
) -> Result<Option<(Value, ContentWriteAudit)>, ProviderError> {
    match (object.get("contentFormat"), object.get("content")) {
        (None, None) => Ok(None),
        (Some(content_format), Some(content)) => {
            let content_format = content_format.as_str().ok_or_else(|| {
                ProviderError::deny(
                    ReasonCode::InputInvalid,
                    format!("{action} contentFormat must be a string"),
                )
            })?;
            if content.is_null() {
                return Err(ProviderError::deny(
                    ReasonCode::InputInvalid,
                    format!("{action} content must not be null"),
                ));
            }
            prepare_jira_content(action, content_format, content, max_body_bytes).map(Some)
        }
        _ => Err(ProviderError::deny(
            ReasonCode::InputInvalid,
            format!("{action} requires content and contentFormat together"),
        )),
    }
}

fn validate_issue_type_id(action: &str, issue_type_id: &str) -> Result<(), ProviderError> {
    if issue_type_id.is_empty() || !issue_type_id.chars().all(|ch| ch.is_ascii_digit()) {
        return Err(ProviderError::deny(
            ReasonCode::InputInvalid,
            format!("{action} issueTypeId must be a non-empty decimal id"),
        ));
    }
    Ok(())
}

fn validate_issue_summary(action: &str, summary: &str) -> Result<(), ProviderError> {
    if summary.trim().is_empty() {
        return Err(ProviderError::deny(
            ReasonCode::InputInvalid,
            format!("{action} summary must not be empty"),
        ));
    }
    if summary.contains('\0') || summary.contains('\r') || summary.contains('\n') {
        return Err(ProviderError::deny(
            ReasonCode::InputInvalid,
            format!("{action} summary must not contain NUL, CR, or LF"),
        ));
    }
    if summary.len() > MAX_JIRA_ISSUE_SUMMARY_BYTES {
        return Err(ProviderError::deny(
            ReasonCode::InputInvalid,
            format!("{action} summary exceeded the byte cap"),
        ));
    }
    Ok(())
}

fn ensure_authorized_issue_metadata(
    metadata: &JiraIssueMetadata,
    resource_scopes: &ResourceScopes,
) -> Result<(), ProviderError> {
    let project_authorized = resource_scopes
        .get("project")
        .is_some_and(|values| values.iter().any(|value| value == &metadata.project));
    if project_authorized {
        return Ok(());
    }
    Err(ProviderError::deny(
        ReasonCode::ScopeUnresolved,
        "Jira issue moved outside the authorized scope",
    ))
}

fn ensure_authorized_project_scope(
    project: &str,
    resource_scopes: &ResourceScopes,
) -> Result<(), ProviderError> {
    let project_authorized = resource_scopes
        .get("project")
        .is_some_and(|values| values.iter().any(|value| value == project));
    if project_authorized {
        return Ok(());
    }
    Err(ProviderError::deny(
        ReasonCode::ScopeUnresolved,
        "Jira project is outside the authorized scope",
    ))
}

fn parse_comment_list_inputs(
    inputs: &Value,
    config: &JiraProviderConfig,
) -> Result<CommentListInputs, ProviderError> {
    let parsed: CommentListRawInputs = serde_json::from_value(inputs.clone()).map_err(|_| {
        ProviderError::deny(
            ReasonCode::InputInvalid,
            "jira.comment.list inputs are invalid",
        )
    })?;
    let locator =
        issue_locator_from_optional(parsed.issue, parsed.url, config, "jira.comment.list")?;
    let max_results = parsed.max_results.unwrap_or(config.comments.max_results);
    if max_results == 0 {
        return Err(ProviderError::deny(
            ReasonCode::InputInvalid,
            "jira.comment.list maxResults must be greater than zero",
        ));
    }
    let max_results = max_results.min(config.comments.max_results);
    if let Some(order_by) = &parsed.order_by
        && !matches!(order_by.as_str(), "created" | "-created" | "+created")
    {
        return Err(ProviderError::deny(
            ReasonCode::InputInvalid,
            "jira.comment.list orderBy is invalid",
        ));
    }
    Ok(CommentListInputs {
        locator,
        max_results,
        start_at: parsed.start_at.unwrap_or(0),
        order_by: parsed.order_by,
    })
}

fn parse_comment_view_inputs(
    inputs: &Value,
    config: &JiraProviderConfig,
) -> Result<CommentViewInputs, ProviderError> {
    let parsed: CommentViewRawInputs = serde_json::from_value(inputs.clone()).map_err(|_| {
        ProviderError::deny(ReasonCode::InputInvalid, "jira.comment inputs are invalid")
    })?;
    let locator = issue_locator_from_optional(parsed.issue, parsed.url, config, "jira.comment")?;
    validate_numeric_id(&parsed.comment_id, "Jira comment ID")?;
    Ok(CommentViewInputs {
        locator,
        comment_id: parsed.comment_id,
    })
}

fn parse_comment_add_inputs(
    inputs: &Value,
    config: &JiraProviderConfig,
) -> Result<CommentAddInputs, ProviderError> {
    let parsed: CommentAddRawInputs = serde_json::from_value(inputs.clone()).map_err(|_| {
        ProviderError::deny(
            ReasonCode::InputInvalid,
            "jira.comment.add inputs are invalid",
        )
    })?;
    let locator =
        issue_locator_from_optional(parsed.issue, parsed.url, config, "jira.comment.add")?;
    let (body, content_audit) = prepare_jira_content(
        "jira.comment.add",
        &parsed.content_format,
        &parsed.content,
        config.content.max_body_bytes,
    )?;
    let visibility = parsed
        .visibility
        .map(|visibility| validate_comment_visibility_input(visibility, config))
        .transpose()?;
    Ok(CommentAddInputs {
        locator,
        body,
        content_audit,
        visibility,
    })
}

fn parse_comment_reply_inputs(
    inputs: &Value,
    config: &JiraProviderConfig,
) -> Result<CommentReplyInputs, ProviderError> {
    let parsed: CommentReplyRawInputs = serde_json::from_value(inputs.clone()).map_err(|_| {
        ProviderError::deny(
            ReasonCode::InputInvalid,
            "jira.comment.reply inputs are invalid",
        )
    })?;
    let locator =
        issue_locator_from_optional(parsed.issue, parsed.url, config, "jira.comment.reply")?;
    validate_numeric_id(&parsed.parent_comment_id, "Jira parent comment ID")?;
    let (body, content_audit) = prepare_jira_content(
        "jira.comment.reply",
        &parsed.content_format,
        &parsed.content,
        config.content.max_body_bytes,
    )?;
    let visibility = parsed
        .visibility
        .map(|visibility| validate_comment_visibility_input(visibility, config))
        .transpose()?;
    Ok(CommentReplyInputs {
        locator,
        parent_comment_id: parsed.parent_comment_id,
        body,
        content_audit,
        visibility,
    })
}

fn parse_comment_update_inputs(
    inputs: &Value,
    config: &JiraProviderConfig,
) -> Result<CommentUpdateInputs, ProviderError> {
    let parsed: CommentUpdateRawInputs = serde_json::from_value(inputs.clone()).map_err(|_| {
        ProviderError::deny(
            ReasonCode::InputInvalid,
            "jira.comment.update inputs are invalid",
        )
    })?;
    let locator =
        issue_locator_from_optional(parsed.issue, parsed.url, config, "jira.comment.update")?;
    validate_numeric_id(&parsed.comment_id, "Jira comment ID")?;
    let (body, content_audit) = prepare_jira_content(
        "jira.comment.update",
        &parsed.content_format,
        &parsed.content,
        config.content.max_body_bytes,
    )?;
    let visibility_mode = match parsed.visibility_mode.as_deref().unwrap_or("preserve") {
        "preserve" => CommentVisibilityMode::Preserve,
        "set" => CommentVisibilityMode::Set,
        _ => {
            return Err(ProviderError::deny(
                ReasonCode::InputInvalid,
                "jira.comment.update visibilityMode is invalid",
            ));
        }
    };
    let visibility = parsed
        .visibility
        .map(|visibility| validate_comment_visibility_input(visibility, config))
        .transpose()?;
    match (visibility_mode, visibility.as_ref()) {
        (CommentVisibilityMode::Preserve, Some(_)) => {
            return Err(ProviderError::deny(
                ReasonCode::InputInvalid,
                "jira.comment.update preserve mode must not include visibility",
            ));
        }
        (CommentVisibilityMode::Set, None) => {
            return Err(ProviderError::deny(
                ReasonCode::InputInvalid,
                "jira.comment.update set mode requires visibility",
            ));
        }
        _ => {}
    }
    Ok(CommentUpdateInputs {
        locator,
        comment_id: parsed.comment_id,
        body,
        content_audit,
        visibility_mode,
        visibility,
        notify_users: parsed.notify_users.unwrap_or(false),
    })
}

fn parse_comment_property_inputs(
    action: &str,
    inputs: &Value,
    config: &JiraProviderConfig,
) -> Result<CommentPropertyInputs, ProviderError> {
    let parsed: CommentPropertyRawInputs =
        serde_json::from_value(inputs.clone()).map_err(|_| {
            ProviderError::deny(
                ReasonCode::InputInvalid,
                "jira.comment.property inputs are invalid",
            )
        })?;
    let locator =
        issue_locator_from_optional(parsed.issue, parsed.url, config, "jira.comment.property")?;
    validate_numeric_id(&parsed.comment_id, "Jira comment ID")?;
    match action {
        "comment.property.list" => {
            if parsed.property_key.is_some() || parsed.value.is_some() {
                return Err(ProviderError::deny(
                    ReasonCode::InputInvalid,
                    "jira.comment.property.list accepts only issue locator and commentId",
                ));
            }
        }
        "comment.property.get" | "comment.property.delete" => {
            let property_key = parsed.property_key.as_deref().ok_or_else(|| {
                ProviderError::deny(
                    ReasonCode::InputInvalid,
                    "jira.comment.property action requires propertyKey",
                )
            })?;
            validate_comment_property_key(property_key, config)?;
            if parsed.value.is_some() {
                return Err(ProviderError::deny(
                    ReasonCode::InputInvalid,
                    "jira.comment.property get/delete must not include value",
                ));
            }
        }
        "comment.property.set" => {
            let property_key = parsed.property_key.as_deref().ok_or_else(|| {
                ProviderError::deny(
                    ReasonCode::InputInvalid,
                    "jira.comment.property.set requires propertyKey",
                )
            })?;
            validate_comment_property_key(property_key, config)?;
            let value = parsed.value.as_ref().ok_or_else(|| {
                ProviderError::deny(
                    ReasonCode::InputInvalid,
                    "jira.comment.property.set requires value",
                )
            })?;
            validate_comment_property_value(value, config)?;
        }
        _ => {
            return Err(ProviderError::deny(
                ReasonCode::ServiceActionDenied,
                "Jira action is not supported",
            ));
        }
    }
    Ok(CommentPropertyInputs {
        locator,
        comment_id: parsed.comment_id,
        property_key: parsed.property_key,
        value: parsed.value,
    })
}

fn issue_locator_from_optional(
    issue: Option<String>,
    url: Option<String>,
    config: &JiraProviderConfig,
    action: &str,
) -> Result<IssueLocator, ProviderError> {
    match (issue, url) {
        (Some(issue), None) => issue_locator_from_key(&issue),
        (None, Some(url)) => issue_locator_from_url(&url, config),
        _ => Err(ProviderError::deny(
            ReasonCode::InputInvalid,
            format!("{action} requires exactly one of issue or url"),
        )),
    }
}

fn validate_comment_visibility_input(
    input: CommentVisibilityInput,
    config: &JiraProviderConfig,
) -> Result<JiraCommentVisibility, ProviderError> {
    if config.comments.allowed_visibility.is_empty() {
        return Err(ProviderError::deny(
            ReasonCode::InputInvalid,
            "Jira comment visibility restrictions are not allowlisted",
        ));
    }
    match input.visibility_type.as_str() {
        "group" => {
            let identifier = input.identifier.ok_or_else(|| {
                ProviderError::deny(
                    ReasonCode::InputInvalid,
                    "Jira group comment visibility requires identifier",
                )
            })?;
            if identifier.trim().is_empty() {
                return Err(ProviderError::deny(
                    ReasonCode::InputInvalid,
                    "Jira group comment visibility identifier is invalid",
                ));
            }
            let Some(allowed) = config.comments.allowed_visibility.iter().find(|allowed| {
                allowed.visibility_type == "group"
                    && allowed.identifier.as_deref() == Some(identifier.as_str())
            }) else {
                return Err(ProviderError::deny(
                    ReasonCode::InputInvalid,
                    "Jira group comment visibility is not allowlisted",
                ));
            };
            Ok(JiraCommentVisibility {
                visibility_type: "group".to_string(),
                value: allowed.value.clone().or(input.value),
                identifier: Some(identifier),
            })
        }
        "role" => {
            let value = input.value.ok_or_else(|| {
                ProviderError::deny(
                    ReasonCode::InputInvalid,
                    "Jira role comment visibility requires value",
                )
            })?;
            if value.trim().is_empty() {
                return Err(ProviderError::deny(
                    ReasonCode::InputInvalid,
                    "Jira role comment visibility value is invalid",
                ));
            }
            let Some(allowed) = config.comments.allowed_visibility.iter().find(|allowed| {
                allowed.visibility_type == "role"
                    && allowed.value.as_deref() == Some(value.as_str())
                    && allowed
                        .identifier
                        .as_ref()
                        .is_none_or(|identifier| input.identifier.as_ref() == Some(identifier))
            }) else {
                return Err(ProviderError::deny(
                    ReasonCode::InputInvalid,
                    "Jira role comment visibility is not allowlisted",
                ));
            };
            Ok(JiraCommentVisibility {
                visibility_type: "role".to_string(),
                value: Some(value),
                identifier: allowed.identifier.clone(),
            })
        }
        _ => Err(ProviderError::deny(
            ReasonCode::InputInvalid,
            "Jira comment visibility type is invalid",
        )),
    }
}

fn validate_comment_property_key(
    property_key: &str,
    config: &JiraProviderConfig,
) -> Result<(), ProviderError> {
    if !valid_jira_comment_property_key_shape(property_key) {
        return Err(ProviderError::deny(
            ReasonCode::InputInvalid,
            "Jira comment property key is invalid",
        ));
    }
    if jira_comment_property_key_reserved(property_key) {
        return Err(ProviderError::deny(
            ReasonCode::InputInvalid,
            "Jira comment property key uses a reserved prefix",
        ));
    }
    if !config
        .comments
        .allowed_property_key_prefixes
        .iter()
        .any(|prefix| property_key.starts_with(prefix))
    {
        return Err(ProviderError::deny(
            ReasonCode::InputInvalid,
            "Jira comment property key prefix is not allowlisted",
        ));
    }
    Ok(())
}

fn valid_jira_comment_property_key_shape(property_key: &str) -> bool {
    !property_key.is_empty()
        && property_key.len() <= 255
        && property_key.is_ascii()
        && !property_key.contains('/')
        && !property_key.chars().any(char::is_whitespace)
}

fn validate_comment_property_value(
    value: &Value,
    config: &JiraProviderConfig,
) -> Result<(), ProviderError> {
    if value.is_null() {
        return Err(ProviderError::deny(
            ReasonCode::InputInvalid,
            "Jira comment property value must not be null",
        ));
    }
    let size = serde_json::to_vec(value)
        .map(|bytes| bytes.len() as u64)
        .map_err(|_| ProviderError::deny(ReasonCode::InputInvalid, "property value is invalid"))?;
    if size > config.comments.max_property_value_bytes {
        return Err(ProviderError::deny(
            ReasonCode::AttachmentSizeDenied,
            "Jira comment property value exceeded the configured byte cap",
        ));
    }
    Ok(())
}

fn jira_comment_property_key_reserved(property_key: &str) -> bool {
    let property_key = property_key.to_ascii_lowercase();
    ["sd.", "jira.", "atlassian.", "com.atlassian."]
        .iter()
        .any(|reserved| property_key.starts_with(reserved))
}

fn parse_attachment_add_inputs(inputs: &Value) -> Result<AttachmentAddInputs, ProviderError> {
    let parsed: AttachmentAddInputs = serde_json::from_value(inputs.clone()).map_err(|_| {
        ProviderError::deny(
            ReasonCode::InputInvalid,
            "jira.attachment.add inputs are invalid",
        )
    })?;
    issue_locator_from_key(&parsed.issue)?;
    if parsed.attachments.is_empty() {
        return Err(ProviderError::deny(
            ReasonCode::InputInvalid,
            "jira.attachment.add requires at least one attachment",
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
                "jira.attachment.download inputs are invalid",
            )
        })?;
    issue_locator_from_key(&parsed.issue)?;
    validate_numeric_id(&parsed.attachment_id, "Jira attachment ID")?;
    Ok(parsed)
}

fn parse_attachment_list_inputs(
    inputs: &Value,
    config: &JiraProviderConfig,
) -> Result<AttachmentListInputs, ProviderError> {
    let parsed: AttachmentListRawInputs = serde_json::from_value(inputs.clone()).map_err(|_| {
        ProviderError::deny(
            ReasonCode::InputInvalid,
            "jira.attachment.list requires exactly one of issue or url",
        )
    })?;
    let locator = match (parsed.issue, parsed.url) {
        (Some(issue), None) => issue_locator_from_key(&issue),
        (None, Some(url)) => issue_locator_from_url(&url, config),
        _ => Err(ProviderError::deny(
            ReasonCode::InputInvalid,
            "jira.attachment.list requires exactly one of issue or url",
        )),
    }?;
    Ok(AttachmentListInputs { locator })
}

fn parse_verify_inputs(inputs: &Value) -> Result<VerifyInputs, ProviderError> {
    let parsed: VerifyInputs = serde_json::from_value(inputs.clone()).map_err(|_| {
        ProviderError::deny(ReasonCode::InputInvalid, "jira.verify inputs are invalid")
    })?;
    issue_locator_from_key(&parsed.issue)?;
    if parsed.expect_comment_id.is_none() && parsed.expect_attachment_id.is_none() {
        return Err(ProviderError::deny(
            ReasonCode::InputInvalid,
            "jira.verify requires at least one expected object ID",
        ));
    }
    if let Some(id) = &parsed.expect_comment_id {
        validate_numeric_id(id, "Jira comment ID")?;
    }
    if let Some(id) = &parsed.expect_attachment_id {
        validate_numeric_id(id, "Jira attachment ID")?;
    }
    Ok(parsed)
}

fn invocation_credential(request: &AdmittedRequest) -> Result<&ExecutionCredential, ProviderError> {
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

fn serialized_body_size(value: &Value) -> Result<u64, ProviderError> {
    serde_json::to_vec(value)
        .map(|bytes| bytes.len() as u64)
        .map_err(|_| ProviderError::deny(ReasonCode::BodyMalformed, "body is invalid"))
}

fn prepare_attachment_uploads(
    inputs: &[AttachmentInput],
    body_parts: &[BrokerBodyPart],
    config: &crate::AttachmentLimitsConfig,
) -> Result<Vec<JiraAttachmentUpload>, ProviderError> {
    validate_attachment_metadata_inputs(inputs, config)?;
    let mut uploads = Vec::new();
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
        uploads.push(JiraAttachmentUpload {
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

fn attachment_upload_audit(upload: &JiraAttachmentUpload) -> Value {
    json!({
        "filename": upload.filename.as_str(),
        "contentType": upload.content_type.as_str(),
        "size": upload.size,
        "sha256": upload.sha256.as_str(),
    })
}

struct IssueCreateAuditContext<'a> {
    project: &'a str,
    issue_type_id: &'a str,
    description_provided: bool,
}

struct IssueChildCreateAuditContext<'a> {
    project: &'a str,
    issue_type_id: &'a str,
    description_provided: bool,
    parent: &'a JiraIssueMetadata,
}

fn issue_create_failure_audit(
    request: &ProviderInvocation,
    context: &IssueCreateAuditContext<'_>,
    failure_phase: &str,
    created: Option<&JiraCreatedIssue>,
    egress_proxy: &Value,
) -> Value {
    issue_create_failure_audit_partial(
        request,
        context,
        failure_phase,
        &PartialJiraCreatedIssue {
            id: created.map(|created| created.id.clone()),
            key: created.map(|created| created.key.clone()),
        },
        egress_proxy,
    )
}

fn issue_create_failure_audit_partial(
    request: &ProviderInvocation,
    context: &IssueCreateAuditContext<'_>,
    failure_phase: &str,
    created: &PartialJiraCreatedIssue,
    egress_proxy: &Value,
) -> Value {
    let mut audit = json!({
        "provider": "jira",
        "operation": "issue.create",
        "project": context.project,
        "issueTypeId": context.issue_type_id,
        "descriptionProvided": context.description_provided,
        "failurePhase": failure_phase,
        "credentialMode": request.credential_mode(),
        "egressProxy": egress_proxy,
    });
    if let Some(issue_id) = &created.id {
        audit["issueId"] = json!(issue_id);
    }
    if let Some(issue_key) = &created.key {
        audit["issueKey"] = json!(issue_key);
    }
    audit
}

fn issue_create_object_ids(created: Option<&JiraCreatedIssue>) -> Value {
    match created {
        Some(created) => json!({
            "issueId": created.id,
            "issueKey": created.key,
        }),
        None => json!({}),
    }
}

fn issue_create_object_ids_partial(issue_id: Option<&str>, issue_key: Option<&str>) -> Value {
    let mut object_ids = json!({});
    if let Some(issue_id) = issue_id {
        object_ids["issueId"] = json!(issue_id);
    }
    if let Some(issue_key) = issue_key {
        object_ids["issueKey"] = json!(issue_key);
    }
    object_ids
}

fn issue_child_create_failure_audit(
    request: &ProviderInvocation,
    context: &IssueChildCreateAuditContext<'_>,
    failure_phase: &str,
    created: Option<&JiraCreatedIssue>,
    egress_proxy: &Value,
) -> Value {
    issue_child_create_failure_audit_partial(
        request,
        context,
        failure_phase,
        &PartialJiraCreatedIssue {
            id: created.map(|created| created.id.clone()),
            key: created.map(|created| created.key.clone()),
        },
        egress_proxy,
    )
}

fn issue_child_create_failure_audit_partial(
    request: &ProviderInvocation,
    context: &IssueChildCreateAuditContext<'_>,
    failure_phase: &str,
    created: &PartialJiraCreatedIssue,
    egress_proxy: &Value,
) -> Value {
    let mut audit = json!({
        "provider": "jira",
        "operation": "issue.child.create",
        "project": context.project,
        "issueTypeId": context.issue_type_id,
        "parentIssueKey": context.parent.key,
        "parentProject": context.parent.project,
        "descriptionProvided": context.description_provided,
        "verificationStatus": "failed",
        "failurePhase": failure_phase,
        "credentialMode": request.credential_mode(),
        "egressProxy": egress_proxy,
    });
    if let Some(issue_id) = &created.id {
        audit["issueId"] = json!(issue_id);
    }
    if let Some(issue_key) = &created.key {
        audit["issueKey"] = json!(issue_key);
    }
    audit
}

fn issue_child_create_object_ids(
    created: Option<&JiraCreatedIssue>,
    parent: &JiraIssueMetadata,
) -> Value {
    match created {
        Some(created) => {
            issue_child_create_object_ids_partial(Some(&created.id), Some(&created.key), parent)
        }
        None => issue_child_create_object_ids_partial(None, None, parent),
    }
}

fn issue_child_create_object_ids_partial(
    issue_id: Option<&str>,
    issue_key: Option<&str>,
    parent: &JiraIssueMetadata,
) -> Value {
    let mut object_ids = json!({
        "parentIssueId": parent.id,
        "parentIssueKey": parent.key,
    });
    if let Some(issue_id) = issue_id {
        object_ids["issueId"] = json!(issue_id);
    }
    if let Some(issue_key) = issue_key {
        object_ids["issueKey"] = json!(issue_key);
    }
    object_ids
}

fn configured_dependency_link_type(
    link_types: &[JiraIssueLinkType],
    config: &JiraIssueLinksConfig,
) -> Result<JiraIssueLinkType, ProviderError> {
    let link_type = link_types
        .iter()
        .find(|link_type| link_type.name == config.dependency_link_type)
        .ok_or_else(|| {
            ProviderError::error(
                ReasonCode::UpstreamProtocolFailed,
                "configured Jira dependency link type was not available",
            )
        })?;
    if !link_type
        .outward
        .eq_ignore_ascii_case(&config.dependency_outward)
        || !link_type
            .inward
            .eq_ignore_ascii_case(&config.dependency_inward)
    {
        return Err(ProviderError::error(
            ReasonCode::UpstreamProtocolFailed,
            "configured Jira dependency link type direction did not match Jira",
        ));
    }
    Ok(link_type.clone())
}

fn issue_parent_readback_matches(
    readback: &JiraIssueParentReadback,
    expected_parent: &JiraIssueMetadata,
) -> bool {
    let Some(parent) = &readback.parent else {
        return false;
    };
    let key_matches = parent
        .key
        .as_deref()
        .is_none_or(|key| key == expected_parent.key);
    let id_matches = parent
        .id
        .as_deref()
        .is_none_or(|id| id == expected_parent.id);
    (parent.key.is_some() || parent.id.is_some()) && key_matches && id_matches
}

fn issue_parent_set_failure_audit(
    request: &ProviderInvocation,
    issue: &JiraIssueMetadata,
    parent: &JiraIssueMetadata,
    failure_phase: &str,
    egress_proxy: &Value,
) -> Value {
    json!({
        "provider": "jira",
        "operation": "issue.parent.set",
        "issueKey": issue.key,
        "project": issue.project,
        "parentIssueKey": parent.key,
        "parentProject": parent.project,
        "verificationStatus": "failed",
        "failurePhase": failure_phase,
        "credentialMode": request.credential_mode(),
        "egressProxy": egress_proxy,
    })
}

fn issue_parent_set_object_ids(issue: &JiraIssueMetadata, parent: &JiraIssueMetadata) -> Value {
    json!({
        "issueId": issue.id,
        "issueKey": issue.key,
        "parentIssueId": parent.id,
        "parentIssueKey": parent.key,
    })
}

fn dependency_link_readback_matches(
    readback: &JiraIssueLinks,
    link_type: &str,
    blocked_issue: &str,
) -> bool {
    readback.links.iter().any(|link| {
        link.link_type == link_type && link.outward_issue.as_deref() == Some(blocked_issue)
    })
}

fn issue_dependency_failure_audit(
    request: &ProviderInvocation,
    blocking: &JiraIssueMetadata,
    blocked: &JiraIssueMetadata,
    link_type: &JiraIssueLinkType,
    failure_phase: &str,
    egress_proxy: &Value,
) -> Value {
    json!({
        "provider": "jira",
        "operation": "issue.dependency.add",
        "linkType": link_type.name,
        "blockingIssueKey": blocking.key,
        "blockingProject": blocking.project,
        "blockedIssueKey": blocked.key,
        "blockedProject": blocked.project,
        "verificationStatus": "failed",
        "failurePhase": failure_phase,
        "credentialMode": request.credential_mode(),
        "egressProxy": egress_proxy,
    })
}

fn issue_dependency_object_ids(blocking: &JiraIssueMetadata, blocked: &JiraIssueMetadata) -> Value {
    json!({
        "blockingIssueId": blocking.id,
        "blockingIssueKey": blocking.key,
        "blockedIssueId": blocked.id,
        "blockedIssueKey": blocked.key,
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
    attachment: &JiraAttachment,
    config: &JiraProviderConfig,
) -> Result<(), ProviderError> {
    if attachment.size > config.attachments.max_download_bytes {
        return Err(ProviderError::deny(
            ReasonCode::AttachmentSizeDenied,
            "Jira attachment exceeds the configured download cap",
        ));
    }
    if !media_type_allowed(&attachment.content_type, &config.attachments.media_types) {
        return Err(ProviderError::deny(
            ReasonCode::AttachmentMediaTypeDenied,
            "Jira attachment content type is not allowed",
        ));
    }
    Ok(())
}

fn validate_download_content(
    content: &JiraAttachmentContent,
    attachment: &JiraAttachment,
    config: &JiraProviderConfig,
) -> Result<(), ProviderError> {
    if content
        .size
        .is_some_and(|size| size > config.attachments.max_download_bytes)
    {
        return Err(ProviderError::deny(
            ReasonCode::AttachmentSizeDenied,
            "Jira attachment download exceeded the configured byte cap",
        ));
    }
    let Some(content_type) = media_type_essence(&content.content_type) else {
        return Err(ProviderError::deny(
            ReasonCode::AttachmentMediaTypeDenied,
            "Jira attachment response content type is not allowed",
        ));
    };
    let Some(metadata_type) = media_type_essence(&attachment.content_type) else {
        return Err(ProviderError::deny(
            ReasonCode::AttachmentMediaTypeDenied,
            "Jira attachment metadata content type is invalid",
        ));
    };
    if content.size.is_some_and(|size| size != attachment.size) {
        return Err(ProviderError::error(
            ReasonCode::UpstreamProtocolFailed,
            "Jira attachment response size did not match metadata",
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
            "Jira attachment response content type did not match metadata",
        ));
    }
    Ok(())
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

fn issue_metadata_result(issue: &JiraIssueMetadata, config: &JiraProviderConfig) -> Value {
    json!({
        "id": issue.id,
        "key": issue.key,
        "project": issue.project,
        "webUrl": jira_issue_browser_url(&issue.key, config),
    })
}

fn comment_result(comment: &JiraComment) -> Value {
    let mut value = json!({
        "commentId": comment.id,
    });
    if let Some(parent_id) = &comment.parent_id {
        value["parentCommentId"] = json!(parent_id);
    }
    if let Some(author) = &comment.author {
        value["author"] = user_summary_result(author);
    }
    if let Some(created) = &comment.created {
        value["created"] = json!(created);
    }
    if let Some(updated) = &comment.updated {
        value["updated"] = json!(updated);
    }
    if let Some(visibility) = &comment.visibility {
        value["visibility"] = comment_visibility_result(visibility);
    }
    if let Some(body) = &comment.body {
        value["body"] = body.clone();
    }
    value
}

fn comment_summary_result(comment: &JiraCommentSummary) -> Value {
    let mut value = json!({
        "commentId": comment.id,
    });
    if let Some(parent_id) = &comment.parent_id {
        value["parentCommentId"] = json!(parent_id);
    }
    if let Some(author) = &comment.author {
        value["author"] = user_summary_result(author);
    }
    if let Some(created) = &comment.created {
        value["created"] = json!(created);
    }
    if let Some(updated) = &comment.updated {
        value["updated"] = json!(updated);
    }
    if let Some(visibility) = &comment.visibility {
        value["visibility"] = comment_visibility_result(visibility);
    }
    value
}

fn user_summary_result(user: &JiraUserSummary) -> Value {
    let mut value = json!({});
    if let Some(account_id) = &user.account_id {
        value["accountId"] = json!(account_id);
    }
    if let Some(display_name) = &user.display_name {
        value["displayName"] = json!(display_name);
    }
    value
}

fn comment_visibility_result(visibility: &JiraCommentVisibility) -> Value {
    let mut value = json!({
        "type": visibility.visibility_type,
    });
    if let Some(visibility_value) = &visibility.value {
        value["value"] = json!(visibility_value);
    }
    if let Some(identifier) = &visibility.identifier {
        value["identifier"] = json!(identifier);
    }
    value
}

fn validate_returned_comment_id(actual: &str, expected: Option<&str>) -> Result<(), ProviderError> {
    if actual.is_empty() || !actual.chars().all(|ch| ch.is_ascii_digit()) {
        return Err(ProviderError::error(
            ReasonCode::UpstreamProtocolFailed,
            "Jira comment response id is invalid",
        ));
    }
    if expected.is_some_and(|expected| expected != actual) {
        return Err(ProviderError::error(
            ReasonCode::UpstreamProtocolFailed,
            "Jira comment response id did not match the requested id",
        ));
    }
    Ok(())
}

fn validate_returned_comment_parent_id(
    comment: &JiraComment,
    expected: Option<&str>,
) -> Result<(), ProviderError> {
    match (comment.parent_id.as_deref(), expected) {
        (Some(actual), Some(expected)) if actual == expected => Ok(()),
        (None, None) => Ok(()),
        (Some(_), None) => Err(ProviderError::error(
            ReasonCode::UpstreamProtocolFailed,
            "Jira top-level comment response unexpectedly included a parent id",
        )),
        (None, Some(_)) => Err(ProviderError::error(
            ReasonCode::UpstreamProtocolFailed,
            "Jira reply response did not include a parent id",
        )),
        (Some(_), Some(_)) => Err(ProviderError::error(
            ReasonCode::UpstreamProtocolFailed,
            "Jira reply response parent id did not match the requested parent",
        )),
    }
}

fn validate_returned_comment_body(
    comment: &JiraComment,
    max_body_bytes: u64,
) -> Result<(), ProviderError> {
    if let Some(body) = &comment.body {
        validate_adf_body(body).map_err(|_| {
            ProviderError::error(
                ReasonCode::UpstreamProtocolFailed,
                "Jira comment response body was invalid",
            )
        })?;
        enforce_returned_body_size(
            body,
            max_body_bytes,
            "Jira comment response body was invalid",
        )?;
    }
    Ok(())
}

fn verification_mismatch_result(
    issue: &JiraIssueMetadata,
    checked: &[Value],
    mismatch: Value,
) -> Value {
    json!({
        "verification": {
            "status": "mismatch",
            "checked": checked,
            "mismatch": mismatch,
        },
        "issueKey": issue.key,
        "project": issue.project,
    })
}

fn verification_mismatch_error(
    request: &ProviderInvocation,
    issue: &JiraIssueMetadata,
    checked: &[Value],
    mismatch: Value,
    inputs: &VerifyInputs,
    egress_proxy: Value,
) -> ProviderError {
    ProviderError::allow_with_result(
        ReasonCode::VerificationMismatch,
        "Jira verification mismatch",
        verification_mismatch_result(issue, checked, mismatch.clone()),
    )
    .with_audit(json!({
        "provider": "jira",
        "operation": "verify",
        "issueKey": issue.key,
        "project": issue.project,
        "status": "mismatch",
        "checked": checked,
        "mismatch": mismatch,
        "credentialMode": request.credential_mode(),
        "egressProxy": egress_proxy,
    }))
    .with_object_ids(json!({
        "issueId": issue.id,
        "issueKey": issue.key,
        "commentId": inputs.expect_comment_id,
        "attachmentId": inputs.expect_attachment_id,
    }))
}

fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// The receipts of a Jira write action's mutation request. Its failures keep
/// their ordinary reason and message.
struct JiraWrite {
    /// What the write targets, from the validated request and the reads
    /// before it; never from the write's own response.
    locators: Value,
}

impl JiraWrite {
    fn new(locators: Value) -> Self {
        Self { locators }
    }

    fn locators(&self) -> Value {
        self.locators.clone()
    }

    /// The receipt of a write Jira accepted but whose response could not be
    /// read or did not match the request.
    fn receipt(&self) -> MutationReceipt {
        MutationReceipt::applied_unverified("mutation_response", self.locators())
    }

    /// The failure of the mutation request itself:
    ///
    /// - proven unsent: `not_applied`;
    /// - no response, a 5xx a proxy may return after Jira committed the
    ///   write, or a redirect the Broker never follows: `unknown`;
    /// - a success status whose response then failed: `applied_unverified`;
    /// - a rejection, or a failure before anything was sent: no receipt.
    fn failed(&self, error: JiraBackendError) -> ProviderError {
        match error {
            JiraBackendError::NotSent { .. } => {
                jira_backend_error(error).with_mutation_receipt(MutationReceipt::not_applied())
            }
            JiraBackendError::NoResponse { .. }
            | JiraBackendError::Redirected
            | JiraBackendError::HttpStatus(500..=599) => {
                jira_backend_error(error).with_mutation_receipt(MutationReceipt::unknown())
            }
            JiraBackendError::AcceptedUnreadable(_)
            | JiraBackendError::IssueCreateResponseInvalid { .. } => {
                jira_backend_error(error).with_mutation_receipt(self.receipt())
            }
            JiraBackendError::Unauthorized
            | JiraBackendError::Forbidden
            | JiraBackendError::NotFound
            | JiraBackendError::HttpStatus(_)
            | JiraBackendError::RateLimited(_)
            | JiraBackendError::Validation { .. }
            | JiraBackendError::Transport(_)
            | JiraBackendError::Timeout
            | JiraBackendError::ResponseTooLarge
            | JiraBackendError::Protocol(_) => jira_backend_error(error),
        }
    }
}

/// Whether an upload that failed may still have created its attachment.
fn upload_may_have_applied(error: &JiraBackendError) -> bool {
    matches!(
        error,
        JiraBackendError::NoResponse { .. }
            | JiraBackendError::Redirected
            | JiraBackendError::HttpStatus(500..=599)
            | JiraBackendError::AcceptedUnreadable(_)
    )
}

/// Runs what follows a write Jira accepted: a failure that reports no
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

fn sanitized_backend_reason(error: &JiraBackendError) -> &'static str {
    match error {
        JiraBackendError::AcceptedUnreadable(error) => sanitized_backend_reason(error),
        JiraBackendError::Unauthorized => "unauthorized",
        JiraBackendError::Forbidden => "forbidden",
        JiraBackendError::NotFound => "not_found",
        JiraBackendError::HttpStatus(_) => "upstream_failed",
        JiraBackendError::RateLimited(_) => "upstream_rate_limited",
        JiraBackendError::Validation { body_malformed, .. } => {
            if *body_malformed {
                "body_malformed"
            } else {
                "input_invalid"
            }
        }
        JiraBackendError::NotSent { timed_out: false }
        | JiraBackendError::NoResponse { timed_out: false }
        | JiraBackendError::Transport(_) => "upstream_connection_failed",
        JiraBackendError::NotSent { timed_out: true }
        | JiraBackendError::NoResponse { timed_out: true }
        | JiraBackendError::Timeout => "upstream_timeout",
        JiraBackendError::ResponseTooLarge
        | JiraBackendError::IssueCreateResponseInvalid { .. }
        | JiraBackendError::Redirected
        | JiraBackendError::Protocol(_) => "upstream_protocol_failed",
    }
}

fn validate_returned_issue_description(
    issue: &JiraIssue,
    config: &JiraProviderConfig,
) -> Result<(), ProviderError> {
    let Some(description) = &issue.description else {
        return Ok(());
    };
    validate_returned_adf_document(description)?;
    enforce_returned_body_size(
        description,
        config.content.max_body_bytes,
        "Jira issue description response was invalid",
    )
}

fn validate_returned_adf_document(value: &Value) -> Result<(), ProviderError> {
    if value.get("type").and_then(Value::as_str) == Some("doc")
        && value.get("version").and_then(Value::as_u64).is_some()
        && value.get("content").is_some_and(Value::is_array)
    {
        return Ok(());
    }
    Err(ProviderError::error(
        ReasonCode::UpstreamProtocolFailed,
        "Jira issue description response was invalid",
    ))
}

fn enforce_returned_body_size(
    value: &Value,
    cap: u64,
    message: &'static str,
) -> Result<(), ProviderError> {
    let size = serde_json::to_vec(value)
        .map(|bytes| bytes.len() as u64)
        .map_err(|_| ProviderError::error(ReasonCode::UpstreamProtocolFailed, message))?;
    if size > cap {
        return Err(ProviderError::error(
            ReasonCode::UpstreamProtocolFailed,
            message,
        ));
    }
    Ok(())
}

fn validate_adf_body(value: &Value) -> Result<(), ProviderError> {
    if value.get("type").and_then(Value::as_str) != Some("doc")
        || value.get("version").and_then(Value::as_u64) != Some(1)
        || !value.get("content").is_some_and(Value::is_array)
    {
        return Err(ProviderError::deny(
            ReasonCode::BodyMalformed,
            "ADF body must be a Jira document",
        ));
    }
    validate_adf_node(value)?;
    Ok(())
}

fn validate_adf_node(value: &Value) -> Result<(), ProviderError> {
    const MAX_ADF_DEPTH: usize = 128;
    const MAX_ADF_NODES: usize = 100_000;
    const MAX_ADF_WORK: usize = 1_000_000;

    let mut pending = vec![(value, 0_usize)];
    let mut nodes_seen = 0_usize;
    let mut work = 0_usize;
    while let Some((node, depth)) = pending.pop() {
        if depth > MAX_ADF_DEPTH {
            return Err(adf_malformed());
        }
        nodes_seen = nodes_seen.checked_add(1).ok_or_else(adf_malformed)?;
        if nodes_seen > MAX_ADF_NODES {
            return Err(adf_malformed());
        }
        let Some(object) = node.as_object() else {
            return Err(adf_malformed());
        };
        work = work.checked_add(object.len()).ok_or_else(adf_malformed)?;
        if work > MAX_ADF_WORK {
            return Err(adf_malformed());
        }
        let Some(node_type) = object.get("type").and_then(Value::as_str) else {
            return Err(adf_malformed());
        };
        if !allowed_adf_node_types().contains(&node_type) {
            return Err(adf_malformed());
        }
        if node_type == "text" && !object.get("text").is_some_and(Value::is_string) {
            return Err(adf_malformed());
        }
        if let Some(text) = object.get("text")
            && !text.is_string()
        {
            return Err(adf_malformed());
        }
        if let Some(attrs) = object.get("attrs")
            && !attrs.is_object()
        {
            return Err(adf_malformed());
        }
        if let Some(content) = object.get("content") {
            let Some(children) = content.as_array() else {
                return Err(adf_malformed());
            };
            work = work.checked_add(children.len()).ok_or_else(adf_malformed)?;
            if work > MAX_ADF_WORK {
                return Err(adf_malformed());
            }
            pending.extend(children.iter().rev().map(|child| (child, depth + 1)));
        }
        if let Some(marks) = object.get("marks") {
            let Some(marks) = marks.as_array() else {
                return Err(adf_malformed());
            };
            work = work.checked_add(marks.len()).ok_or_else(adf_malformed)?;
            if work > MAX_ADF_WORK {
                return Err(adf_malformed());
            }
            for mark in marks {
                validate_adf_mark(mark)?;
            }
        }
    }
    Ok(())
}

fn validate_adf_mark(value: &Value) -> Result<(), ProviderError> {
    let Some(object) = value.as_object() else {
        return Err(adf_malformed());
    };
    let Some(mark_type) = object.get("type").and_then(Value::as_str) else {
        return Err(adf_malformed());
    };
    if !allowed_adf_mark_types().contains(&mark_type) {
        return Err(adf_malformed());
    }
    if let Some(attrs) = object.get("attrs")
        && !attrs.is_object()
    {
        return Err(adf_malformed());
    }
    Ok(())
}

fn allowed_adf_node_types() -> &'static BTreeSet<&'static str> {
    static TYPES: OnceLock<BTreeSet<&'static str>> = OnceLock::new();
    TYPES.get_or_init(|| {
        [
            "blockquote",
            "bulletList",
            "codeBlock",
            "date",
            "decisionItem",
            "decisionList",
            "doc",
            "emoji",
            "expand",
            "hardBreak",
            "heading",
            "inlineCard",
            "listItem",
            "media",
            "mediaGroup",
            "mediaSingle",
            "mention",
            "nestedExpand",
            "orderedList",
            "panel",
            "paragraph",
            "rule",
            "status",
            "table",
            "tableCell",
            "tableHeader",
            "tableRow",
            "taskItem",
            "taskList",
            "text",
        ]
        .into()
    })
}

fn allowed_adf_mark_types() -> &'static BTreeSet<&'static str> {
    static TYPES: OnceLock<BTreeSet<&'static str>> = OnceLock::new();
    TYPES.get_or_init(|| {
        [
            "backgroundColor",
            "breakout",
            "code",
            "em",
            "link",
            "strike",
            "strong",
            "subsup",
            "textColor",
            "underline",
        ]
        .into()
    })
}

fn adf_malformed() -> ProviderError {
    ProviderError::deny(
        ReasonCode::BodyMalformed,
        "ADF body must be a structurally valid Jira document",
    )
}

fn validate_numeric_id(value: &str, label: &str) -> Result<(), ProviderError> {
    if !value.is_empty() && value.chars().all(|ch| ch.is_ascii_digit()) && !value.starts_with('0') {
        Ok(())
    } else {
        Err(ProviderError::deny(
            ReasonCode::InputInvalid,
            format!("{label} is invalid"),
        ))
    }
}

fn validate_project_key(value: &str) -> Result<String, ProviderError> {
    if is_project_key(value) {
        Ok(value.to_string())
    } else {
        Err(ProviderError::deny(
            ReasonCode::InputInvalid,
            "Jira project key is invalid",
        ))
    }
}

fn is_project_key(value: &str) -> bool {
    project_re().is_match(value)
}

fn is_issue_key(value: &str) -> bool {
    issue_re().is_match(value)
}

fn issue_key_project(issue_key: &str) -> String {
    issue_key
        .split_once('-')
        .map(|(project, _)| project.to_string())
        .unwrap_or_default()
}

fn project_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(JIRA_PROJECT_KEY_PATTERN).expect("project regex"))
}

fn issue_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(JIRA_ISSUE_KEY_PATTERN).expect("issue regex"))
}

fn issue_view_result(issue: &JiraIssue, config: &JiraProviderConfig) -> Value {
    json!({
        "id": issue.id,
        "key": issue.key,
        "project": issue.project,
        "webUrl": jira_issue_browser_url(&issue.key, config),
        "summary": issue.summary,
        "status": issue.status,
        "issueType": issue.issue_type,
        "description": issue.description,
        "created": issue.created,
        "updated": issue.updated,
        "creator": issue.creator,
        "reporter": issue.reporter,
        "assignee": issue.assignee,
        "priority": issue.priority,
        "labels": issue.labels,
    })
}

/// The search page result; `next_page_token` is the sealed continuation,
/// never Jira's upstream token.
fn search_result(
    page: &JiraSearchPage,
    next_page_token: Option<&str>,
    config: &JiraProviderConfig,
) -> Value {
    json!({
        "issues": page.issues.iter().map(|issue| issue_search_result(issue, config)).collect::<Vec<_>>(),
        "maxResults": page.max_results,
        "startAt": page.start_at,
        "total": page.total,
        "nextPageToken": next_page_token,
        "isLast": page.is_last,
    })
}

fn issue_search_result(issue: &JiraIssue, config: &JiraProviderConfig) -> Value {
    json!({
        "id": issue.id,
        "key": issue.key,
        "project": issue.project,
        "webUrl": jira_issue_browser_url(&issue.key, config),
        "summary": issue.summary,
        "status": issue.status,
        "issueType": issue.issue_type,
        "created": issue.created,
        "updated": issue.updated,
        "creator": issue.creator,
        "reporter": issue.reporter,
        "assignee": issue.assignee,
        "priority": issue.priority,
        "labels": issue.labels,
    })
}

fn jira_issue_browser_url(issue_key: &str, config: &JiraProviderConfig) -> String {
    format!("https://{}/browse/{}", config.tenant_host, issue_key)
}

fn enforce_result_size(value: &Value, cap: u64) -> Result<(), ProviderError> {
    let size = serde_json::to_vec(value)
        .map(|bytes| bytes.len() as u64)
        .map_err(|_| {
            ProviderError::error(
                ReasonCode::UpstreamProtocolFailed,
                "failed to measure provider response",
            )
        })?;
    if size > cap {
        return Err(ProviderError::error(
            ReasonCode::UpstreamProtocolFailed,
            "provider response exceeded the configured byte cap",
        ));
    }
    Ok(())
}
