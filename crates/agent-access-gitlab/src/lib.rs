//! GitLab backend: project, issue, merge-request, note, discussion, review,
//! branch, file, commit, pipeline, job, webhook, and provisioning actions
//! against the GitLab REST API, authorized against `git_repository`
//! resources, and the `gitlab` OAuth dialect ([`GITLAB_OAUTH_DIALECT`]).
mod access;
mod backend;
mod config;
mod oauth;
mod present;
mod provisioning;
mod search;
#[cfg(test)]
mod tests;
mod validation;

pub use access::GitlabCredential;
pub use backend::*;
pub use config::*;
pub use oauth::GITLAB_OAUTH_DIALECT;
use validation::*;

use agent_access_content::append_gitlab_markdown_attribution;
use agent_access_content::{ContentWriteError, plain_text_to_gitlab_markdown_bounded};
#[allow(unused_imports)]
use agent_access_provider::*;
use async_trait::async_trait;
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use chrono::{DateTime, Utc};
use percent_encoding::{AsciiSet, CONTROLS, utf8_percent_encode};
pub use provisioning::{
    GitlabProvisioningConfig, GitlabProvisioningOperation, GitlabProvisioningRequest,
};
pub(crate) use provisioning::{PROVISIONING_ACTIONS, issues_token};
use pulldown_cmark::{CodeBlockKind, Event, Options, Parser, Tag};
use reqwest::Method;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::time::{Duration, Instant};
use thiserror::Error;
use url::Url;

const PATH_SEGMENT_ENCODE_SET: &AsciiSet = &CONTROLS
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
const GITLAB_MAX_PER_PAGE: u32 = 100;
const GITLAB_MAX_SUGGESTIONS_PER_APPLY: usize = 100;
const GITLAB_WEBHOOK_EVENT_MAX_PER_PAGE: u32 = 20;
const GITLAB_WEBHOOK_HEADER_MAX_BYTES: usize = 8192;
/// List continuations: the next GitLab page, or the next local offset of a
/// draft-note list, for one action's exact project, filters, sort, projection
/// and page size.
const GITLAB_PAGE_TOKENS: ContinuationFamily = ContinuationFamily::new(
    "gitlab",
    "list-page",
    GITLAB_PAGE_TOKEN_VERSION,
    ContinuationLifetime::StableWhenConfigured,
    GITLAB_PAGE_TOKEN_PAYLOAD_BYTES,
)
.expires_after(Duration::from_secs(GITLAB_PAGE_TOKEN_TTL_MINUTES * 60))
.clock_skew(Duration::from_secs(GITLAB_PAGE_TOKEN_CLOCK_SKEW_SECONDS));
const GITLAB_PAGE_TOKEN_VERSION: u8 = 2;
/// The next page as a big-endian `u32`.
const GITLAB_PAGE_TOKEN_PAYLOAD_BYTES: usize = 4;
const GITLAB_PAGE_TOKEN_CLOCK_SKEW_SECONDS: u64 = 60;
const GITLAB_PAGE_TOKEN_TTL_MINUTES: u64 = 15;
const GITLAB_PAGE_TOKEN_MAX_BYTES: usize = GITLAB_PAGE_TOKENS.max_token_bytes();
const NOTE_LIST_ORDER_BY: &[&str] = &["created_at", "updated_at"];
const ISSUE_SEARCH_ORDER_BY: &[&str] = &[
    "created_at",
    "due_date",
    "label_priority",
    "milestone_due",
    "popularity",
    "priority",
    "relative_position",
    "title",
    "updated_at",
    "weight",
];
const MERGE_REQUEST_SEARCH_ORDER_BY: &[&str] = &[
    "created_at",
    "updated_at",
    "merged_at",
    "label_priority",
    "priority",
    "milestone_due",
    "popularity",
    "title",
];
const GITLAB_INLINE_FILE_JSON_OVERHEAD: u64 = 2048;
const GITLAB_DEFAULT_BRANCH_NAMES: &[&str] = &["main", "master"];
const GITLAB_COMMIT_ACTIONS: &[&str] = &["create", "update", "move", "delete", "chmod"];
const GITLAB_ISSUE_VALIDATION_FIELDS: &[&str] = &["description", "title"];
const GITLAB_MERGE_REQUEST_VALIDATION_FIELDS: &[&str] = &[
    "description",
    "merge_commit_message",
    "squash_commit_message",
    "title",
];
const GITLAB_NOTE_VALIDATION_FIELDS: &[&str] = &["body"];
const GITLAB_POSITIONED_NOTE_VALIDATION_FIELDS: &[&str] = &["body", "position", "line_code"];
const GITLAB_DRAFT_NOTE_VALIDATION_FIELDS: &[&str] = &[
    "note",
    "position",
    "in_reply_to_discussion_id",
    "resolve_discussion",
    "reviewer_state",
    "line_code",
];
const GITLAB_FILE_VALIDATION_FIELDS: &[&str] =
    &["commit_message", "content", "encoding", "execute_filemode"];
const GITLAB_COMMIT_VALIDATION_FIELDS: &[&str] = &["commit_message"];
const GITLAB_PIPELINE_STATUSES: &[&str] = &[
    "created",
    "waiting_for_resource",
    "preparing",
    "pending",
    "running",
    "success",
    "failed",
    "canceled",
    "skipped",
    "manual",
    "scheduled",
];
const GITLAB_JOB_SCOPES: &[&str] = &[
    "canceled",
    "canceling",
    "created",
    "failed",
    "manual",
    "pending",
    "preparing",
    "running",
    "scheduled",
    "skipped",
    "success",
    "waiting_for_callback",
    "waiting_for_resource",
];

#[derive(Clone)]
pub struct GitlabProvider {
    config: GitlabProviderConfig,
    config_fingerprint: String,
    /// The OAuth target of the GitLab instance `api_base_url` names, which
    /// delegated access must be pinned to; `None` when it names none.
    instance_target: Option<Arc<str>>,
    limits: ProviderLimits,
    backend: Arc<dyn GitlabBackend>,
    search_backend: Option<Arc<search::HttpSearchBackend>>,
    pagination_signer: ContinuationSigner,
    attribution: ProviderAttributionConfig,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct PublishedNoteIdentity {
    discussion_id: String,
    note_id: u64,
}

struct PublicationDiscussionSnapshot {
    notes: BTreeMap<PublishedNoteIdentity, GitlabNote>,
}

enum DraftPublicationScope {
    Reply {
        discussion_id: String,
        baseline: BTreeSet<PublishedNoteIdentity>,
    },
    Collection {
        baseline: BTreeSet<PublishedNoteIdentity>,
        expected_position: Option<Box<GitlabDiffPosition>>,
    },
}

impl GitlabProvider {
    pub(crate) fn new(
        config: GitlabProviderConfig,
        host: &BuildContext<'_>,
    ) -> Result<Self, ProviderBuildError> {
        let limits = host.limits().clone();
        let backend = Arc::new(HttpGitlabBackend::new(
            config.clone(),
            limits.clone(),
            host.clients(),
        )?);
        let search_backend = Some(Arc::new(search::HttpSearchBackend::new(
            &config,
            &limits,
            host.clients(),
        )?));
        let config_fingerprint = gitlab_config_fingerprint(&config);
        Ok(Self {
            instance_target: gitlab_instance_target(&config),
            config,
            config_fingerprint,
            limits,
            backend,
            search_backend,
            pagination_signer: ContinuationSigner::new(host.stable_signing_key().cloned()),
            attribution: host.attribution().clone(),
        })
    }

    pub fn with_backend(config: GitlabProviderConfig, backend: Arc<dyn GitlabBackend>) -> Self {
        let config_fingerprint = gitlab_config_fingerprint(&config);
        Self {
            instance_target: gitlab_instance_target(&config),
            config,
            config_fingerprint,
            limits: ProviderLimits::default(),
            backend,
            search_backend: None,
            pagination_signer: ContinuationSigner::new(None),
            attribution: ProviderAttributionConfig::default(),
        }
    }

    fn apply_markdown_attribution(
        &self,
        action: &str,
        body: &mut String,
        request: &ProviderInvocation,
    ) -> Option<Value> {
        let capability = self.attribution.capability(action)?;
        let mutation = append_gitlab_markdown_attribution(
            body,
            capability,
            &request.correlation().broker_request_id,
        );
        Some(mutation.audit_value())
    }

    fn optional_absent_attribution_audit(&self, action: &str) -> Option<Value> {
        self.attribution
            .capability(action)
            .map(|_| attribution_skip_target_absent_audit())
    }

    fn page_from_token(
        &self,
        token: Option<&str>,
        request: &ProviderInvocation,
        project: &GitlabProject,
        request_hash: &str,
        max_results: u32,
    ) -> Result<u32, ProviderError> {
        let Some(token) = token else {
            return Ok(1);
        };
        let context = GitlabPageTokenContext {
            request,
            project,
            provider_fingerprint: &self.config_fingerprint,
            request_hash,
            max_results,
        };
        decode_gitlab_page_token(&self.pagination_signer, token, &context, Utc::now())
    }

    fn next_page_token(
        &self,
        next_page: Option<u32>,
        request: &ProviderInvocation,
        project: &GitlabProject,
        request_hash: &str,
        max_results: u32,
    ) -> Result<Option<String>, ProviderError> {
        let context = GitlabPageTokenContext {
            request,
            project,
            provider_fingerprint: &self.config_fingerprint,
            request_hash,
            max_results,
        };
        next_page
            .map(|next_page| {
                encode_gitlab_page_token(&self.pagination_signer, &context, next_page, Utc::now())
            })
            .transpose()
    }
}

fn gitlab_config_fingerprint(config: &GitlabProviderConfig) -> String {
    let fields = json!({
        "apiBaseUrl": config.api_base_url,
        "webBaseUrl": config.web_base_url,
        "provisioning": { "enabled":config.provisioning.enabled, "maxAccessLevel":config.provisioning.max_access_level, "maxTokenLifetimeDays":config.provisioning.max_token_lifetime_days, "allowedTokenScopes":config.provisioning.allowed_token_scopes },
        "webhooks": {
            "allowedDestinations": config.webhooks.allowed_destinations,
            "allowDisableSslVerification": config.webhooks.allow_disable_ssl_verification,
        }
    });
    sha256_serialized(&fields)
}

fn sha256_serialized(value: &impl Serialize) -> String {
    let encoded = serde_json::to_vec(value).expect("pagination binding is serializable");
    let mut digest = Sha256::new();
    digest.update(encoded);
    format!("{:x}", digest.finalize())
}

fn merge_request_collection_request_hash(iid: u64, unidiff: Option<bool>) -> String {
    sha256_serialized(&BTreeMap::from([
        ("iid", json!(iid)),
        ("unidiff", json!(unidiff)),
    ]))
}

fn draft_note_collection_request_hash(
    request: &GitlabDraftNoteListRequest,
    actor_id: u64,
) -> String {
    sha256_serialized(&BTreeMap::from([
        ("actorUserId", json!(actor_id)),
        ("iid", json!(request.iid)),
        ("projection", json!(request.projection)),
    ]))
}

fn ensure_diff_bodies_within_cap(
    diffs: &[GitlabDiffFile],
    max_file_bytes: u64,
) -> Result<(), ProviderError> {
    if diffs.iter().any(|diff| {
        diff.diff
            .as_ref()
            .is_some_and(|patch| patch.len() as u64 > max_file_bytes)
    }) {
        return Err(ProviderError::error(
            ReasonCode::UpstreamProtocolFailed,
            "GitLab diff patch exceeded the configured file byte cap",
        ));
    }
    Ok(())
}

struct GitlabPageTokenContext<'a> {
    request: &'a ProviderInvocation,
    project: &'a GitlabProject,
    provider_fingerprint: &'a str,
    request_hash: &'a str,
    max_results: u32,
}

/// Binds a page token to the admitted context and provider configuration,
/// the execution material ([`bind_gitlab_access`]), the confirmed project
/// path and numeric ID, the hash of the action's normalized filters, sort and
/// projection, and the page size.
fn gitlab_page_token_binding(
    family: &ContinuationFamily,
    context: &GitlabPageTokenContext<'_>,
) -> Result<ContinuationBinding, ProviderError> {
    let binding = bind_gitlab_access(
        family.bind(context.request.context(), context.provider_fingerprint),
        context.request.execution(),
    )?;
    Ok(binding
        .text("project", &context.project.path_with_namespace)
        .number("projectId", context.project.id)
        .text("request", context.request_hash)
        .number("maxResults", u64::from(context.max_results)))
}

/// Binds a page token to the execution material that reaches GitLab: the
/// credential method, a static credential (a stored or service token) with
/// its kind, or delegated (OAuth) access with the lease's delegated binding
/// (the OAuth connection and its generation, never the access version),
/// target and audience. A token sealed under one method, account or
/// connection generation never opens under another; a routine refresh keeps
/// the binding, and every input is fixed by configuration or the host's
/// selection, so a token survives a restart whenever the stable key does.
/// Execution material GitLab does not accept, including none, fails closed.
fn bind_gitlab_access(
    binding: ContinuationBinding,
    access: &ExecutionAccess,
) -> Result<ContinuationBinding, ProviderError> {
    match access {
        ExecutionAccess::Static(credential) => Ok(binding
            .text("credentialMethod", "static")
            .text("credentialKind", credential.kind().as_str())),
        ExecutionAccess::Delegated(credential) => Ok(binding
            .text("credentialMethod", "delegated")
            .delegated(credential)),
        _ => Err(ProviderError::deny(
            ReasonCode::CredentialNotProvisioned,
            "selected credential material is unavailable",
        )),
    }
}

fn encode_gitlab_page_token(
    signer: &ContinuationSigner,
    context: &GitlabPageTokenContext<'_>,
    next_page: u32,
    now: DateTime<Utc>,
) -> Result<String, ProviderError> {
    if next_page < 2 {
        return Err(gitlab_page_token_error());
    }
    signer
        .seal_at(
            &gitlab_page_token_binding(&GITLAB_PAGE_TOKENS, context)?,
            &next_page.to_be_bytes(),
            now.into(),
        )
        .map_err(gitlab_page_token_failure)
}

fn decode_gitlab_page_token(
    signer: &ContinuationSigner,
    token: &str,
    context: &GitlabPageTokenContext<'_>,
    now: DateTime<Utc>,
) -> Result<u32, ProviderError> {
    let payload = signer
        .open_at(
            &gitlab_page_token_binding(&GITLAB_PAGE_TOKENS, context)?,
            token,
            now.into(),
        )
        .map_err(gitlab_page_token_failure)?;
    let next_page = <[u8; GITLAB_PAGE_TOKEN_PAYLOAD_BYTES]>::try_from(payload.as_slice())
        .map(u32::from_be_bytes)
        .map_err(|_| gitlab_page_token_error())?;
    if next_page < 2 {
        return Err(gitlab_page_token_error());
    }
    Ok(next_page)
}

fn gitlab_page_token_failure(error: ContinuationError) -> ProviderError {
    ContinuationFailures::new(
        gitlab_page_token_error(),
        |_| {
            ProviderError::error(
                ReasonCode::UpstreamProtocolFailed,
                "GitLab pagination token exceeded its size bound",
            )
        },
        ProviderError::error(
            ReasonCode::UpstreamProtocolFailed,
            "GitLab pagination signing key is unavailable",
        ),
    )
    .report(error)
}

fn gitlab_page_token_error() -> ProviderError {
    ProviderError::deny(
        ReasonCode::InputInvalid,
        "GitLab pagination token is invalid or expired",
    )
}

#[async_trait]
impl Provider for GitlabProvider {
    async fn resolve_scopes(
        &self,
        request: ScopeRequest<'_>,
    ) -> Result<ScopeResolution, ProviderError> {
        let (action, inputs) = (request.action(), request.inputs());
        let locator = project_locator_for_action(action, inputs, &self.config)?;
        let credential = &self.required_lookup_credential(request.lookup_access())?;
        let project = self
            .backend
            .project(&locator.project, credential)
            .await
            .map_err(gitlab_lookup_backend_error)?
            .value;
        if !matches!(
            action,
            "merge_request.suggestion.apply" | "merge_request.suggestion.batch_apply"
        ) {
            return Ok(ScopeResolution::resources(repository_scopes_from_project(
                &project,
            )));
        }
        let iid = parse_suggestion_apply_inputs(
            inputs,
            action == "merge_request.suggestion.batch_apply",
            self.config.content.max_body_bytes,
        )?
        .iid;
        let merge_request = self
            .backend
            .merge_request(project.id, iid, credential)
            .await
            .map_err(gitlab_lookup_backend_error)?
            .value;
        ensure_merge_request_in_project(&project, &merge_request)?;
        ensure_merge_request_repository_ids(&project, &merge_request)?;
        let source_project_id = merge_request.source_project_id.ok_or_else(|| {
            ProviderError::deny(
                ReasonCode::ScopeUnresolved,
                "GitLab merge request source project was not found or not permitted",
            )
        })?;
        if source_project_id == project.id {
            return Ok(
                ScopeResolution::resources(repository_scopes_from_project(&project)).with_state(
                    ProviderState::new(GitlabSuggestionScopePreflight {
                        target_project_id: project.id,
                        source_project_id,
                    }),
                ),
            );
        }
        let source_project = self
            .backend
            .project(&source_project_id.to_string(), credential)
            .await
            .map_err(gitlab_lookup_backend_error)?
            .value;
        if source_project.id != source_project_id {
            return Err(ProviderError::deny(
                ReasonCode::ScopeUnresolved,
                "GitLab merge request source project was not found or not permitted",
            ));
        }
        ensure_distinct_project_paths(&project, &source_project)?;
        Ok(
            ScopeResolution::resources(repository_scopes_from_projects([
                &project,
                &source_project,
            ]))
            .with_state(ProviderState::new(GitlabSuggestionScopePreflight {
                target_project_id: project.id,
                source_project_id,
            })),
        )
    }

    async fn authorize_body_parts(
        &self,
        request: &AdmittedRequest,
        _state: Option<&ProviderState>,
    ) -> Result<BodyAdmission, ProviderError> {
        if request.action() != "project.upload" {
            return Err(ProviderError::deny(
                ReasonCode::BodyMalformed,
                "GitLab action does not accept multipart body parts",
            ));
        }
        let (_, metadata) = parse_project_upload_inputs(request.inputs(), &self.config)?;
        self.lookup_project_for_invoke(request).await?;
        Ok(BodyAdmission::new(vec![metadata], StateDisposition::Keep))
    }

    async fn verify_execution_credential(
        &self,
        credential: &ExecutionCredential,
        _correlation: &crate::CorrelationContext,
    ) -> Result<Option<ProviderCredentialVerification>, ProviderError> {
        let credential = &GitlabCredential::from_static(credential.clone());
        let response = self
            .backend
            .current_user(credential)
            .await
            .map_err(gitlab_backend_error)?;
        Ok(Some(ProviderCredentialVerification::new(
            response.status,
            response.duration_ms,
            json!({
                "gitlab": {
                    "operation": "credential.verify",
                    "userId": response.value.id,
                    "username": response.value.username,
                    "egressProxy": self.backend.egress_proxy_audit(credential),
                }
            }),
        )))
    }

    async fn invoke(&self, request: ProviderInvocation) -> Result<ProviderResult, ProviderError> {
        if PROVISIONING_ACTIONS.contains(&request.action()) {
            return self.invoke_provisioning(request).await;
        }
        if search::is_search_action(request.action()) {
            return self.invoke_native_search(request).await;
        }
        match request.action() {
            "project.view" => self.invoke_project_view(request).await,
            "project.upload" => self.invoke_project_upload(request).await,
            "issue.view" => self.invoke_issue_view(request).await,
            "issue.search" => self.invoke_issue_search(request).await,
            "issue.create" => self.invoke_issue_create(request).await,
            "issue.update" => self.invoke_issue_update(request).await,
            "issue.note.list" => self.invoke_issue_note_list(request).await,
            "issue.note.view" => self.invoke_issue_note_view(request).await,
            "issue.note.add" => self.invoke_issue_note_add(request).await,
            "issue.note.update" => self.invoke_issue_note_update(request).await,
            "issue.note.delete" => self.invoke_issue_note_delete(request).await,
            "merge_request.view" => self.invoke_merge_request_view(request).await,
            "merge_request.search" => self.invoke_merge_request_search(request).await,
            "merge_request.create" => self.invoke_merge_request_create(request).await,
            "merge_request.update" => self.invoke_merge_request_update(request).await,
            "merge_request.note.list" => self.invoke_merge_request_note_list(request).await,
            "merge_request.note.view" => self.invoke_merge_request_note_view(request).await,
            "merge_request.note.add" => self.invoke_merge_request_note_add(request).await,
            "merge_request.note.update" => self.invoke_merge_request_note_update(request).await,
            "merge_request.note.delete" => self.invoke_merge_request_note_delete(request).await,
            "merge_request.discussion.list" => {
                self.invoke_merge_request_discussion_list(request).await
            }
            "merge_request.discussion.view" => {
                self.invoke_merge_request_discussion_view(request).await
            }
            "merge_request.discussion.inline.add" => {
                self.invoke_merge_request_inline_discussion_add(request)
                    .await
            }
            "merge_request.discussion.note.add" => {
                self.invoke_merge_request_discussion_note_add(request).await
            }
            "merge_request.draft_note.list" => {
                self.invoke_merge_request_draft_note_list(request).await
            }
            "merge_request.draft_note.view" => {
                self.invoke_merge_request_draft_note_view(request).await
            }
            "merge_request.draft_note.add" => {
                self.invoke_merge_request_draft_note_add(request).await
            }
            "merge_request.draft_note.update" => {
                self.invoke_merge_request_draft_note_update(request).await
            }
            "merge_request.draft_note.delete" => {
                self.invoke_merge_request_draft_note_delete(request).await
            }
            "merge_request.draft_note.publish" => {
                self.invoke_merge_request_draft_note_publish(request).await
            }
            "merge_request.draft_note.publish_all" => {
                self.invoke_merge_request_draft_note_publish_all(request)
                    .await
            }
            "merge_request.review.submit" => self.invoke_merge_request_review_submit(request).await,
            "merge_request.reviewer.list" => self.invoke_merge_request_reviewer_list(request).await,
            "merge_request.approval.view" => self.invoke_merge_request_approval_view(request).await,
            "merge_request.approval_state.view" => {
                self.invoke_merge_request_approval_state_view(request).await
            }
            "merge_request.approval_rule.list" => {
                self.invoke_merge_request_approval_rule_list(request).await
            }
            "merge_request.approval_rule.view" => {
                self.invoke_merge_request_approval_rule_view(request).await
            }
            "merge_request.approve" => {
                self.invoke_merge_request_approval_mutation(request, true)
                    .await
            }
            "merge_request.unapprove" => {
                self.invoke_merge_request_approval_mutation(request, false)
                    .await
            }
            "merge_request.suggestion.apply" => {
                self.invoke_merge_request_suggestion_apply(request, false)
                    .await
            }
            "merge_request.suggestion.batch_apply" => {
                self.invoke_merge_request_suggestion_apply(request, true)
                    .await
            }
            "merge_request.commit.list" => self.invoke_merge_request_commit_list(request).await,
            "merge_request.pipeline.list" => self.invoke_merge_request_pipeline_list(request).await,
            "merge_request.diff.list" => self.invoke_merge_request_diff_list(request).await,
            "merge_request.diff.raw.download" => {
                self.invoke_merge_request_diff_raw_download(request).await
            }
            "merge_request.diff_version.list" => {
                self.invoke_merge_request_diff_version_list(request).await
            }
            "merge_request.diff_version.view" => {
                self.invoke_merge_request_diff_version_view(request).await
            }
            "merge_request.discussion.add" => {
                self.invoke_merge_request_discussion_add(request).await
            }
            "merge_request.discussion.note.update" => {
                self.invoke_merge_request_discussion_note_update(request)
                    .await
            }
            "merge_request.discussion.note.delete" => {
                self.invoke_merge_request_discussion_note_delete(request)
                    .await
            }
            "merge_request.discussion.resolve" => {
                self.invoke_merge_request_discussion_state_change(
                    request,
                    GitlabDiscussionStateChange::Resolve,
                )
                .await
            }
            "merge_request.discussion.reopen" => {
                self.invoke_merge_request_discussion_state_change(
                    request,
                    GitlabDiscussionStateChange::Reopen,
                )
                .await
            }
            "merge_request.merge" => self.invoke_merge_request_merge(request).await,
            "branch.list" => self.invoke_branch_list(request).await,
            "branch.view" => self.invoke_branch_view(request).await,
            "branch.create" => self.invoke_branch_create(request).await,
            "protected_branch.list" => self.invoke_protected_branch_list(request).await,
            "protected_branch.view" => self.invoke_protected_branch_view(request).await,
            "protected_branch.verify" => self.invoke_protected_branch_verify(request).await,
            "file.view" => self.invoke_file_view(request).await,
            "file.raw.download" => self.invoke_file_raw_download(request).await,
            "file.create" => self.invoke_file_create(request).await,
            "file.update" => self.invoke_file_update(request).await,
            "file.delete" => self.invoke_file_delete(request).await,
            "commit.list" => self.invoke_commit_list(request).await,
            "commit.view" => self.invoke_commit_view(request).await,
            "commit.create" => self.invoke_commit_create(request).await,
            "pipeline.list" => self.invoke_pipeline_list(request).await,
            "pipeline.view" => self.invoke_pipeline_view(request).await,
            "pipeline.run" => self.invoke_pipeline_run(request).await,
            "pipeline.retry" => self.invoke_pipeline_retry(request).await,
            "pipeline.cancel" => self.invoke_pipeline_cancel(request).await,
            "job.list" => self.invoke_job_list(request).await,
            "job.view" => self.invoke_job_view(request).await,
            "job.trace.download" => self.invoke_job_trace_download(request).await,
            "job.retry" => self.invoke_job_retry(request).await,
            "job.cancel" => self.invoke_job_cancel(request).await,
            "job.play" => self.invoke_job_play(request).await,
            "webhook.list" => self.invoke_webhook_list(request).await,
            "webhook.view" => self.invoke_webhook_view(request).await,
            "webhook.create" => self.invoke_webhook_create(request).await,
            "webhook.update" => self.invoke_webhook_update(request).await,
            "webhook.delete" => self.invoke_webhook_delete(request).await,
            "webhook.test" => self.invoke_webhook_test(request).await,
            "webhook.event.list" => self.invoke_webhook_event_list(request).await,
            "webhook.event.resend" => self.invoke_webhook_event_resend(request).await,
            "webhook.custom_header.set" => self.invoke_webhook_custom_header_set(request).await,
            "webhook.custom_header.delete" => {
                self.invoke_webhook_custom_header_delete(request).await
            }
            _ => Err(ProviderError::deny(
                ReasonCode::ServiceActionDenied,
                "GitLab action is not supported",
            )),
        }
    }
}

impl GitlabProvider {
    /// Resolves the caller's project locator again for execution, to the
    /// project GitLab identifies with it now, and requires that project's
    /// current path to be one the host admitted. A project renamed, moved or
    /// transferred since scope resolution to a path the host did not admit is
    /// refused rather than acted on. Admission is by path, not project ID, so
    /// a project that took over an admitted path in between passes, as any
    /// project at that path does.
    async fn lookup_project_for_invoke(
        &self,
        request: &AdmittedRequest,
    ) -> Result<GitlabProject, ProviderError> {
        let locator = project_locator_for_action(request.action(), request.inputs(), &self.config)?;
        let credential = &self.required_lookup_credential(request.lookup_access())?;
        let project = self
            .backend
            .project(&locator.project, credential)
            .await
            .map_err(gitlab_lookup_backend_error)?
            .value;
        ensure_admitted_project(&project, request.resource_scopes()?)?;
        Ok(project)
    }

    async fn invoke_project_upload(
        &self,
        request: ProviderInvocation,
    ) -> Result<ProviderResult, ProviderError> {
        let (_, metadata) = parse_project_upload_inputs(request.inputs(), &self.config)?;
        let upload = prepare_project_upload(&metadata, request.body_parts())?;
        // Spooling can take time; re-confirm the project immediately before the
        // write rather than trusting the pre-spool lookup across that interval.
        let project = self.lookup_project_for_invoke(request.admitted()).await?;
        let credential = &self.execution_credential(&request)?;
        let write = PlainWrite::new(json!({ "project": project.path_with_namespace }));
        let response = self
            .backend
            .upload_project(project.id, upload, credential)
            .await
            .map_err(|error| write.failed(error))?;
        // Attachment URLs contain secret path segments. Keep all returned metadata
        // out of audit fields and object identifiers.
        Ok(gitlab_result(
            "project.upload",
            &project,
            None,
            response.status,
            response.duration_ms,
            json!({ "upload": response.value }),
            self.backend.egress_proxy_audit(credential),
        ))
    }

    async fn invoke_project_view(
        &self,
        request: ProviderInvocation,
    ) -> Result<ProviderResult, ProviderError> {
        let lookup_project = self.lookup_project_for_invoke(request.admitted()).await?;
        let credential = &self.execution_credential(&request)?;
        let response = self
            .backend
            .project(&lookup_project.path_with_namespace, credential)
            .await
            .map_err(gitlab_backend_error)?;
        ensure_same_project(&lookup_project, &response.value)?;
        ensure_gitlab_description_within_cap(
            "project",
            response.value.description.as_deref(),
            self.config.content.max_body_bytes,
        )?;
        Ok(gitlab_result(
            "project.view",
            &lookup_project,
            None,
            response.status,
            response.duration_ms,
            json!({ "project": response.value }),
            self.backend.egress_proxy_audit(credential),
        ))
    }

    async fn invoke_issue_view(
        &self,
        request: ProviderInvocation,
    ) -> Result<ProviderResult, ProviderError> {
        let inputs = parse_issue_view_inputs(request.inputs(), &self.config)?;
        let project = self.lookup_project_for_invoke(request.admitted()).await?;
        let credential = &self.execution_credential(&request)?;
        let response = self
            .backend
            .issue(project.id, inputs.iid, credential)
            .await
            .map_err(gitlab_backend_error)?;
        ensure_issue_in_project(&project, &response.value)?;
        ensure_issue_description_within_cap(&response.value, self.config.content.max_body_bytes)?;
        Ok(gitlab_result(
            "issue.view",
            &project,
            Some(
                json!({ "issue": format!("{}#{}", project.path_with_namespace, response.value.iid) }),
            ),
            response.status,
            response.duration_ms,
            json!({ "issue": response.value.with_project(&project) }),
            self.backend.egress_proxy_audit(credential),
        ))
    }

    async fn invoke_issue_search(
        &self,
        request: ProviderInvocation,
    ) -> Result<ProviderResult, ProviderError> {
        let inputs = parse_issue_search_inputs(request.inputs())?;
        let project = self.lookup_project_for_invoke(request.admitted()).await?;
        let page_token = inputs.page_token;
        let max_results = capped_max_results(inputs.max_results, self.config.search.max_results)?;
        let credential = &self.execution_credential(&request)?;
        let mut search = GitlabIssueSearchRequest {
            state: inputs.state,
            labels: inputs.labels,
            milestone: inputs.milestone,
            assignee: inputs.assignee,
            author: inputs.author,
            search: inputs.search,
            created_after: inputs.created_after,
            updated_after: inputs.updated_after,
            sort: inputs.sort,
            order_by: inputs.order_by,
            max_results,
            page: 1,
        };
        let request_hash = issue_search_request_hash(&search);
        search.page = self.page_from_token(
            page_token.as_deref(),
            &request,
            &project,
            &request_hash,
            max_results,
        )?;
        let response = self
            .backend
            .issues(project.id, search, credential)
            .await
            .map_err(gitlab_backend_error)?;
        let GitlabPage {
            items: issues,
            next_page,
        } = response.value;
        validate_gitlab_page_count(issues.len(), max_results)?;
        for issue in &issues {
            ensure_issue_in_project(&project, issue)?;
            ensure_issue_description_within_cap(issue, self.config.content.max_body_bytes)?;
        }
        let next_page_token =
            self.next_page_token(next_page, &request, &project, &request_hash, max_results)?;
        let count = issues.len();
        let is_last = next_page_token.is_none();
        let mut result = gitlab_result(
            "issue.search",
            &project,
            None,
            response.status,
            response.duration_ms,
            json!({
                "issues": issues.into_iter().map(|issue| issue.with_project(&project)).collect::<Vec<_>>(),
                "count": count,
                "maxResults": max_results,
                "isLast": is_last,
                "nextPageToken": next_page_token,
            }),
            self.backend.egress_proxy_audit(credential),
        );
        add_gitlab_audit_fields(
            &mut result,
            vec![("count", json!(count)), ("isLast", json!(is_last))],
        );
        Ok(result)
    }

    async fn invoke_issue_create(
        &self,
        request: ProviderInvocation,
    ) -> Result<ProviderResult, ProviderError> {
        let mut inputs =
            parse_issue_create_inputs(request.inputs(), self.config.content.max_body_bytes)?;
        let attribution = if let Some(description) = inputs.description.as_mut() {
            self.apply_markdown_attribution("issue.create", description, &request)
        } else {
            self.optional_absent_attribution_audit("issue.create")
        };
        if let Some(description) = inputs.description.as_deref() {
            enforce_bounded_text_field(
                "description",
                description,
                self.config.content.max_body_bytes,
                attribution_audit_applied(attribution.as_ref()),
            )?;
        }
        let project = self.lookup_project_for_invoke(request.admitted()).await?;
        let credential = &self.execution_credential(&request)?;
        let write = PlainWrite::new(json!({ "project": project.path_with_namespace }));
        let response = self
            .backend
            .create_issue(project.id, inputs.clone(), credential)
            .await
            .map_err(|error| write.failed(error))?;
        ensure_issue_in_project(&project, &response.value)
            .map_err(|error| write.unverified(error))?;
        ensure_issue_description_within_cap(&response.value, self.config.content.max_body_bytes)
            .map_err(|error| write.unverified(error))?;
        let mut result = gitlab_result_with_request_body_audit(
            "issue.create",
            &project,
            Some(
                json!({ "issue": format!("{}#{}", project.path_with_namespace, response.value.iid) }),
            ),
            (response.status, response.duration_ms),
            json!({ "issue": response.value.with_project(&project) }),
            self.backend.egress_proxy_audit(credential),
            request_body_audit_for_issue_create(&inputs),
        );
        add_gitlab_content_write_audit(
            &mut result,
            request.inputs(),
            inputs.description.as_deref(),
        );
        add_gitlab_attribution_audit(&mut result, attribution);
        Ok(result)
    }

    async fn invoke_issue_update(
        &self,
        request: ProviderInvocation,
    ) -> Result<ProviderResult, ProviderError> {
        let mut inputs =
            parse_issue_update_inputs(request.inputs(), self.config.content.max_body_bytes)?;
        let attribution = if let Some(description) = inputs.description.as_mut() {
            self.apply_markdown_attribution("issue.update", description, &request)
        } else {
            self.optional_absent_attribution_audit("issue.update")
        };
        if let Some(description) = inputs.description.as_deref() {
            enforce_bounded_text_field(
                "description",
                description,
                self.config.content.max_body_bytes,
                attribution_audit_applied(attribution.as_ref()),
            )?;
        }
        let project = self.lookup_project_for_invoke(request.admitted()).await?;
        let lookup_credential = &self.lookup_credential(&request)?;
        let existing = self
            .backend
            .issue(project.id, inputs.iid, lookup_credential)
            .await
            .map_err(gitlab_lookup_backend_error)?;
        ensure_issue_in_project(&project, &existing.value)?;
        let credential = &self.execution_credential(&request)?;
        let write = PlainWrite::new(
            json!({ "project": project.path_with_namespace, "issueIid": inputs.iid }),
        );
        let response = self
            .backend
            .update_issue(project.id, inputs.clone(), credential)
            .await
            .map_err(|error| write.failed(error))?;
        ensure_issue_in_project(&project, &response.value)
            .map_err(|error| write.unverified(error))?;
        ensure_issue_description_within_cap(&response.value, self.config.content.max_body_bytes)
            .map_err(|error| write.unverified(error))?;
        let mut result = gitlab_result_with_request_body_audit(
            "issue.update",
            &project,
            Some(
                json!({ "issue": format!("{}#{}", project.path_with_namespace, response.value.iid) }),
            ),
            (response.status, response.duration_ms),
            json!({ "issue": response.value.with_project(&project) }),
            self.backend.egress_proxy_audit(credential),
            request_body_audit_for_issue_update(&inputs),
        );
        add_gitlab_content_write_audit(
            &mut result,
            request.inputs(),
            inputs.description.as_deref(),
        );
        add_gitlab_attribution_audit(&mut result, attribution);
        Ok(result)
    }

    async fn invoke_issue_note_list(
        &self,
        request: ProviderInvocation,
    ) -> Result<ProviderResult, ProviderError> {
        let mut inputs = parse_note_list_inputs(request.inputs(), self.config.search.max_results)?;
        let project = self.lookup_project_for_invoke(request.admitted()).await?;
        let lookup_credential = &self.lookup_credential(&request)?;
        let issue = self
            .backend
            .issue(project.id, inputs.iid, lookup_credential)
            .await
            .map_err(gitlab_lookup_backend_error)?;
        ensure_issue_in_project(&project, &issue.value)?;
        let request_hash = note_list_request_hash(&inputs);
        inputs.page = self.page_from_token(
            inputs.page_token.as_deref(),
            &request,
            &project,
            &request_hash,
            inputs.max_results,
        )?;
        let credential = &self.execution_credential(&request)?;
        let response = self
            .backend
            .issue_notes(project.id, inputs.clone(), credential)
            .await
            .map_err(gitlab_backend_error)?;
        let GitlabPage {
            items: notes,
            next_page,
        } = response.value;
        validate_gitlab_page_count(notes.len(), inputs.max_results)?;
        ensure_notes_target_issue(&notes, inputs.iid)?;
        let next_page_token = self.next_page_token(
            next_page,
            &request,
            &project,
            &request_hash,
            inputs.max_results,
        )?;
        let count = notes.len();
        let is_last = next_page_token.is_none();
        let projection = inputs.projection;
        let notes = match projection {
            GitlabCollectionProjection::Full => json!(notes),
            GitlabCollectionProjection::Summary => {
                json!(
                    notes
                        .into_iter()
                        .map(GitlabNoteSummary::from)
                        .collect::<Vec<_>>()
                )
            }
        };
        let mut result = gitlab_result(
            "issue.note.list",
            &project,
            None,
            response.status,
            response.duration_ms,
            json!({
                "notes": notes,
                "count": count,
                "maxResults": inputs.max_results,
                "isLast": is_last,
                "nextPageToken": next_page_token,
                "projection": projection,
            }),
            self.backend.egress_proxy_audit(credential),
        );
        add_gitlab_audit_fields(
            &mut result,
            vec![("count", json!(count)), ("isLast", json!(is_last))],
        );
        Ok(result)
    }

    async fn invoke_issue_note_add(
        &self,
        request: ProviderInvocation,
    ) -> Result<ProviderResult, ProviderError> {
        let mut inputs =
            parse_issue_note_add_inputs(request.inputs(), self.config.content.max_body_bytes)?;
        let attribution =
            self.apply_markdown_attribution("issue.note.add", &mut inputs.body, &request);
        enforce_bounded_text_field(
            "body",
            &inputs.body,
            self.config.content.max_body_bytes,
            attribution_audit_applied(attribution.as_ref()),
        )?;
        let project = self.lookup_project_for_invoke(request.admitted()).await?;
        let lookup_credential = &self.lookup_credential(&request)?;
        let issue = self
            .backend
            .issue(project.id, inputs.iid, lookup_credential)
            .await
            .map_err(gitlab_lookup_backend_error)?;
        ensure_issue_in_project(&project, &issue.value)?;
        let credential = &self.execution_credential(&request)?;
        let write = PlainWrite::new(
            json!({ "project": project.path_with_namespace, "issueIid": inputs.iid }),
        );
        let response = self
            .backend
            .create_issue_note(project.id, inputs.clone(), credential)
            .await
            .map_err(|error| write.failed(error))?;
        ensure_note_target_issue(&response.value, inputs.iid)
            .map_err(|error| write.unverified(error))?;
        let mut result = gitlab_result_with_request_body_audit(
            "issue.note.add",
            &project,
            Some(json!({
                "issue": format!("{}#{}", project.path_with_namespace, issue.value.iid),
                "note": response.value.id
            })),
            (response.status, response.duration_ms),
            json!({ "note": response.value }),
            self.backend.egress_proxy_audit(credential),
            request_body_audit_for_issue_note_create(&inputs),
        );
        add_gitlab_content_write_audit(&mut result, request.inputs(), Some(&inputs.body));
        add_gitlab_attribution_audit(&mut result, attribution);
        Ok(result)
    }

    async fn invoke_issue_note_view(
        &self,
        request: ProviderInvocation,
    ) -> Result<ProviderResult, ProviderError> {
        let inputs = parse_issue_note_view_inputs(request.inputs())?;
        let project = self.lookup_project_for_invoke(request.admitted()).await?;
        let issue = self
            .backend
            .issue(project.id, inputs.iid, &self.lookup_credential(&request)?)
            .await
            .map_err(gitlab_lookup_backend_error)?;
        ensure_issue_in_project(&project, &issue.value)?;
        let credential = &self.execution_credential(&request)?;
        let response = self
            .backend
            .issue_note(project.id, inputs.clone(), credential)
            .await
            .map_err(gitlab_proof_backend_error)?;
        ensure_issue_note_consistent(
            &project,
            &issue.value,
            &response.value,
            inputs.iid,
            inputs.note_id,
        )?;
        ensure_note_body_within_cap(&response.value, self.config.content.max_body_bytes)?;
        Ok(gitlab_result(
            "issue.note.view",
            &project,
            Some(json!({
                "issue": format!("{}#{}", project.path_with_namespace, inputs.iid),
                "note": inputs.note_id
            })),
            response.status,
            response.duration_ms,
            json!({ "note": response.value }),
            self.backend.egress_proxy_audit(credential),
        ))
    }

    async fn invoke_issue_note_update(
        &self,
        request: ProviderInvocation,
    ) -> Result<ProviderResult, ProviderError> {
        let inputs =
            parse_note_update_inputs(request.inputs(), self.config.content.max_body_bytes)?;
        enforce_bounded_text_field(
            "body",
            &inputs.body,
            self.config.content.max_body_bytes,
            false,
        )?;
        let project = self.lookup_project_for_invoke(request.admitted()).await?;
        let lookup_credential = &self.lookup_credential(&request)?;
        let issue = self
            .backend
            .issue(project.id, inputs.iid, lookup_credential)
            .await
            .map_err(gitlab_lookup_backend_error)?;
        ensure_issue_in_project(&project, &issue.value)?;
        let credential = &self.execution_credential(&request)?;
        let write = PlainWrite::new(
            json!({ "project": project.path_with_namespace, "issueIid": inputs.iid, "noteId": inputs.note_id }),
        );
        let response = self
            .backend
            .update_issue_note(project.id, inputs.clone(), credential)
            .await
            .map_err(|error| write.failed(error))?;
        ensure_issue_note_consistent(
            &project,
            &issue.value,
            &response.value,
            inputs.iid,
            inputs.note_id,
        )
        .map_err(|error| write.unverified(error))?;
        let mut result = gitlab_result_with_request_body_audit(
            "issue.note.update",
            &project,
            Some(json!({
                "issue": format!("{}#{}", project.path_with_namespace, issue.value.iid),
                "note": response.value.id
            })),
            (response.status, response.duration_ms),
            json!({ "note": response.value }),
            self.backend.egress_proxy_audit(credential),
            request_body_audit_for_note_update(&inputs),
        );
        add_gitlab_audit_fields(
            &mut result,
            vec![
                ("issueIid", json!(inputs.iid)),
                ("noteId", json!(inputs.note_id)),
            ],
        );
        add_gitlab_content_write_audit(&mut result, request.inputs(), Some(&inputs.body));
        Ok(result)
    }

    async fn invoke_issue_note_delete(
        &self,
        request: ProviderInvocation,
    ) -> Result<ProviderResult, ProviderError> {
        let inputs = parse_note_delete_inputs(request.inputs())?;
        let project = self.lookup_project_for_invoke(request.admitted()).await?;
        let lookup_credential = &self.lookup_credential(&request)?;
        let issue = self
            .backend
            .issue(project.id, inputs.iid, lookup_credential)
            .await
            .map_err(gitlab_lookup_backend_error)?;
        ensure_issue_in_project(&project, &issue.value)?;
        let credential = &self.execution_credential(&request)?;
        let proof = self
            .backend
            .issue_note(project.id, inputs.clone(), credential)
            .await
            .map_err(gitlab_proof_backend_error)?;
        ensure_issue_note_consistent(
            &project,
            &issue.value,
            &proof.value,
            inputs.iid,
            inputs.note_id,
        )?;
        let write = PlainWrite::new(
            json!({ "project": project.path_with_namespace, "issueIid": inputs.iid, "noteId": inputs.note_id }),
        );
        let response = self
            .backend
            .delete_issue_note(project.id, inputs.clone(), credential)
            .await
            .map_err(|error| write.failed(error))?;
        let mut result = gitlab_result(
            "issue.note.delete",
            &project,
            Some(json!({
                "issue": format!("{}#{}", project.path_with_namespace, issue.value.iid),
                "note": inputs.note_id
            })),
            response.status,
            response.duration_ms,
            json!({
                "deleted": true,
                "project": project.path_with_namespace,
                "iid": inputs.iid,
                "noteId": inputs.note_id
            }),
            self.backend.egress_proxy_audit(credential),
        );
        add_gitlab_audit_fields(
            &mut result,
            vec![
                ("issueIid", json!(inputs.iid)),
                ("noteId", json!(inputs.note_id)),
            ],
        );
        Ok(result)
    }

    async fn invoke_merge_request_view(
        &self,
        request: ProviderInvocation,
    ) -> Result<ProviderResult, ProviderError> {
        let inputs = parse_merge_request_view_inputs(request.inputs(), &self.config)?;
        let project = self.lookup_project_for_invoke(request.admitted()).await?;
        let credential = &self.execution_credential(&request)?;
        let response = self
            .backend
            .merge_request(project.id, inputs.iid, credential)
            .await
            .map_err(gitlab_backend_error)?;
        ensure_merge_request_in_project(&project, &response.value)?;
        ensure_merge_request_description_within_cap(
            &response.value,
            self.config.content.max_body_bytes,
        )?;
        Ok(gitlab_result(
            "merge_request.view",
            &project,
            Some(
                json!({ "mergeRequest": format!("{}!{}", project.path_with_namespace, response.value.iid) }),
            ),
            response.status,
            response.duration_ms,
            json!({ "mergeRequest": response.value.with_project(&project) }),
            self.backend.egress_proxy_audit(credential),
        ))
    }

    async fn invoke_merge_request_search(
        &self,
        request: ProviderInvocation,
    ) -> Result<ProviderResult, ProviderError> {
        let inputs = parse_merge_request_search_inputs(request.inputs())?;
        let project = self.lookup_project_for_invoke(request.admitted()).await?;
        let page_token = inputs.page_token;
        let max_results = capped_max_results(inputs.max_results, self.config.search.max_results)?;
        let credential = &self.execution_credential(&request)?;
        let mut search = GitlabMergeRequestSearchRequest {
            state: inputs.state,
            source_branch: inputs.source_branch,
            target_branch: inputs.target_branch,
            labels: inputs.labels,
            milestone: inputs.milestone,
            author: inputs.author,
            assignee: inputs.assignee,
            reviewer: inputs.reviewer,
            search: inputs.search,
            created_after: inputs.created_after,
            updated_after: inputs.updated_after,
            sort: inputs.sort,
            order_by: inputs.order_by,
            max_results,
            page: 1,
        };
        let request_hash = merge_request_search_request_hash(&search);
        search.page = self.page_from_token(
            page_token.as_deref(),
            &request,
            &project,
            &request_hash,
            max_results,
        )?;
        let response = self
            .backend
            .merge_requests(project.id, search, credential)
            .await
            .map_err(gitlab_backend_error)?;
        let GitlabPage {
            items: merge_requests,
            next_page,
        } = response.value;
        validate_gitlab_page_count(merge_requests.len(), max_results)?;
        for merge_request in &merge_requests {
            ensure_merge_request_in_project(&project, merge_request)?;
            ensure_merge_request_description_within_cap(
                merge_request,
                self.config.content.max_body_bytes,
            )?;
        }
        let next_page_token =
            self.next_page_token(next_page, &request, &project, &request_hash, max_results)?;
        let count = merge_requests.len();
        let is_last = next_page_token.is_none();
        let mut result = gitlab_result(
            "merge_request.search",
            &project,
            None,
            response.status,
            response.duration_ms,
            json!({
                "mergeRequests": merge_requests.into_iter().map(|merge_request| merge_request.with_project(&project)).collect::<Vec<_>>(),
                "count": count,
                "maxResults": max_results,
                "isLast": is_last,
                "nextPageToken": next_page_token,
            }),
            self.backend.egress_proxy_audit(credential),
        );
        add_gitlab_audit_fields(
            &mut result,
            vec![("count", json!(count)), ("isLast", json!(is_last))],
        );
        Ok(result)
    }

    async fn invoke_merge_request_create(
        &self,
        request: ProviderInvocation,
    ) -> Result<ProviderResult, ProviderError> {
        let mut inputs = parse_merge_request_create_inputs(
            request.inputs(),
            self.config.content.max_body_bytes,
        )?;
        let attribution = if let Some(description) = inputs.description.as_mut() {
            self.apply_markdown_attribution("merge_request.create", description, &request)
        } else {
            self.optional_absent_attribution_audit("merge_request.create")
        };
        if let Some(description) = inputs.description.as_deref() {
            enforce_bounded_text_field(
                "description",
                description,
                self.config.content.max_body_bytes,
                attribution_audit_applied(attribution.as_ref()),
            )?;
        }
        let project = self.lookup_project_for_invoke(request.admitted()).await?;
        let lookup_credential = &self.lookup_credential(&request)?;
        self.backend
            .branch(project.id, &inputs.source_branch, lookup_credential)
            .await
            .map_err(gitlab_lookup_backend_error)?;
        self.backend
            .branch(project.id, &inputs.target_branch, lookup_credential)
            .await
            .map_err(gitlab_lookup_backend_error)?;
        let credential = &self.execution_credential(&request)?;
        let write = PlainWrite::new(
            json!({ "project": project.path_with_namespace, "sourceBranch": inputs.source_branch, "targetBranch": inputs.target_branch }),
        );
        let response = self
            .backend
            .create_merge_request(project.id, inputs.clone(), credential)
            .await
            .map_err(|error| write.failed(error))?;
        ensure_merge_request_in_project(&project, &response.value)
            .map_err(|error| write.unverified(error))?;
        ensure_merge_request_description_within_cap(
            &response.value,
            self.config.content.max_body_bytes,
        )
        .map_err(|error| write.unverified(error))?;
        let mut result = gitlab_result_with_request_body_audit(
            "merge_request.create",
            &project,
            Some(
                json!({ "mergeRequest": format!("{}!{}", project.path_with_namespace, response.value.iid) }),
            ),
            (response.status, response.duration_ms),
            json!({ "mergeRequest": response.value.with_project(&project) }),
            self.backend.egress_proxy_audit(credential),
            request_body_audit_for_merge_request_create(&inputs),
        );
        add_gitlab_content_write_audit(
            &mut result,
            request.inputs(),
            inputs.description.as_deref(),
        );
        add_gitlab_attribution_audit(&mut result, attribution);
        Ok(result)
    }

    async fn invoke_merge_request_update(
        &self,
        request: ProviderInvocation,
    ) -> Result<ProviderResult, ProviderError> {
        let mut inputs = parse_merge_request_update_inputs(
            request.inputs(),
            self.config.content.max_body_bytes,
        )?;
        let attribution = if let Some(description) = inputs.description.as_mut() {
            self.apply_markdown_attribution("merge_request.update", description, &request)
        } else {
            self.optional_absent_attribution_audit("merge_request.update")
        };
        if let Some(description) = inputs.description.as_deref() {
            enforce_bounded_text_field(
                "description",
                description,
                self.config.content.max_body_bytes,
                attribution_audit_applied(attribution.as_ref()),
            )?;
        }
        let project = self.lookup_project_for_invoke(request.admitted()).await?;
        let lookup_credential = &self.lookup_credential(&request)?;
        let existing = self
            .backend
            .merge_request(project.id, inputs.iid, lookup_credential)
            .await
            .map_err(gitlab_lookup_backend_error)?;
        ensure_merge_request_in_project(&project, &existing.value)?;
        if let Some(target_branch) = &inputs.target_branch {
            self.backend
                .branch(project.id, target_branch, lookup_credential)
                .await
                .map_err(gitlab_lookup_backend_error)?;
        }
        let credential = &self.execution_credential(&request)?;
        let write = PlainWrite::new(
            json!({ "project": project.path_with_namespace, "mergeRequestIid": inputs.iid }),
        );
        let response = self
            .backend
            .update_merge_request(project.id, inputs.clone(), credential)
            .await
            .map_err(|error| write.failed(error))?;
        ensure_merge_request_in_project(&project, &response.value)
            .map_err(|error| write.unverified(error))?;
        ensure_merge_request_description_within_cap(
            &response.value,
            self.config.content.max_body_bytes,
        )
        .map_err(|error| write.unverified(error))?;
        let mut result = gitlab_result_with_request_body_audit(
            "merge_request.update",
            &project,
            Some(
                json!({ "mergeRequest": format!("{}!{}", project.path_with_namespace, response.value.iid) }),
            ),
            (response.status, response.duration_ms),
            json!({ "mergeRequest": response.value.with_project(&project) }),
            self.backend.egress_proxy_audit(credential),
            request_body_audit_for_merge_request_update(&inputs),
        );
        add_gitlab_content_write_audit(
            &mut result,
            request.inputs(),
            inputs.description.as_deref(),
        );
        add_gitlab_attribution_audit(&mut result, attribution);
        Ok(result)
    }

    async fn invoke_merge_request_note_list(
        &self,
        request: ProviderInvocation,
    ) -> Result<ProviderResult, ProviderError> {
        let mut inputs = parse_note_list_inputs(request.inputs(), self.config.search.max_results)?;
        let project = self.lookup_project_for_invoke(request.admitted()).await?;
        let lookup_credential = &self.lookup_credential(&request)?;
        let merge_request = self
            .backend
            .merge_request(project.id, inputs.iid, lookup_credential)
            .await
            .map_err(gitlab_lookup_backend_error)?;
        ensure_merge_request_in_project(&project, &merge_request.value)?;
        let request_hash = note_list_request_hash(&inputs);
        inputs.page = self.page_from_token(
            inputs.page_token.as_deref(),
            &request,
            &project,
            &request_hash,
            inputs.max_results,
        )?;
        let credential = &self.execution_credential(&request)?;
        let response = self
            .backend
            .merge_request_notes(project.id, inputs.clone(), credential)
            .await
            .map_err(gitlab_backend_error)?;
        let GitlabPage {
            items: notes,
            next_page,
        } = response.value;
        validate_gitlab_page_count(notes.len(), inputs.max_results)?;
        ensure_notes_target_merge_request(&notes, inputs.iid)?;
        let next_page_token = self.next_page_token(
            next_page,
            &request,
            &project,
            &request_hash,
            inputs.max_results,
        )?;
        let count = notes.len();
        let is_last = next_page_token.is_none();
        let projection = inputs.projection;
        let notes = match projection {
            GitlabCollectionProjection::Full => json!(notes),
            GitlabCollectionProjection::Summary => {
                json!(
                    notes
                        .into_iter()
                        .map(GitlabNoteSummary::from)
                        .collect::<Vec<_>>()
                )
            }
        };
        let mut result = gitlab_result(
            "merge_request.note.list",
            &project,
            None,
            response.status,
            response.duration_ms,
            json!({
                "notes": notes,
                "count": count,
                "maxResults": inputs.max_results,
                "isLast": is_last,
                "nextPageToken": next_page_token,
                "projection": projection,
            }),
            self.backend.egress_proxy_audit(credential),
        );
        add_gitlab_audit_fields(
            &mut result,
            vec![("count", json!(count)), ("isLast", json!(is_last))],
        );
        Ok(result)
    }

    async fn invoke_merge_request_note_add(
        &self,
        request: ProviderInvocation,
    ) -> Result<ProviderResult, ProviderError> {
        let mut inputs =
            parse_note_add_inputs(request.inputs(), self.config.content.max_body_bytes)?;
        let attribution =
            self.apply_markdown_attribution("merge_request.note.add", &mut inputs.body, &request);
        enforce_bounded_text_field(
            "body",
            &inputs.body,
            self.config.content.max_body_bytes,
            attribution_audit_applied(attribution.as_ref()),
        )?;
        let project = self.lookup_project_for_invoke(request.admitted()).await?;
        let lookup_credential = &self.lookup_credential(&request)?;
        let merge_request = self
            .backend
            .merge_request(project.id, inputs.iid, lookup_credential)
            .await
            .map_err(gitlab_lookup_backend_error)?;
        ensure_merge_request_in_project(&project, &merge_request.value)?;
        let credential = &self.execution_credential(&request)?;
        let write = PlainWrite::new(
            json!({ "project": project.path_with_namespace, "mergeRequestIid": inputs.iid }),
        );
        let response = self
            .backend
            .create_merge_request_note(project.id, inputs.clone(), credential)
            .await
            .map_err(|error| write.failed(error))?;
        ensure_note_target_merge_request(&response.value, inputs.iid)
            .map_err(|error| write.unverified(error))?;
        let mut result = gitlab_result_with_request_body_audit(
            "merge_request.note.add",
            &project,
            Some(json!({
                "mergeRequest": format!("{}!{}", project.path_with_namespace, merge_request.value.iid),
                "note": response.value.id
            })),
            (response.status, response.duration_ms),
            json!({ "note": response.value }),
            self.backend.egress_proxy_audit(credential),
            request_body_audit_for_note_create(&inputs),
        );
        add_gitlab_content_write_audit(&mut result, request.inputs(), Some(&inputs.body));
        add_gitlab_attribution_audit(&mut result, attribution);
        Ok(result)
    }

    async fn invoke_merge_request_note_view(
        &self,
        request: ProviderInvocation,
    ) -> Result<ProviderResult, ProviderError> {
        let inputs = parse_merge_request_note_view_inputs(request.inputs())?;
        let project = self.lookup_project_for_invoke(request.admitted()).await?;
        let merge_request = self
            .backend
            .merge_request(project.id, inputs.iid, &self.lookup_credential(&request)?)
            .await
            .map_err(gitlab_lookup_backend_error)?;
        ensure_merge_request_in_project(&project, &merge_request.value)?;
        let credential = &self.execution_credential(&request)?;
        let response = self
            .backend
            .merge_request_note(project.id, inputs.clone(), credential)
            .await
            .map_err(gitlab_proof_backend_error)?;
        ensure_merge_request_note_consistent(
            &project,
            &merge_request.value,
            &response.value,
            inputs.iid,
            inputs.note_id,
        )?;
        ensure_note_body_within_cap(&response.value, self.config.content.max_body_bytes)?;
        Ok(gitlab_result(
            "merge_request.note.view",
            &project,
            Some(json!({
                "mergeRequest": format!("{}!{}", project.path_with_namespace, inputs.iid),
                "note": inputs.note_id
            })),
            response.status,
            response.duration_ms,
            json!({ "note": response.value }),
            self.backend.egress_proxy_audit(credential),
        ))
    }

    async fn invoke_merge_request_note_update(
        &self,
        request: ProviderInvocation,
    ) -> Result<ProviderResult, ProviderError> {
        let inputs =
            parse_note_update_inputs(request.inputs(), self.config.content.max_body_bytes)?;
        enforce_bounded_text_field(
            "body",
            &inputs.body,
            self.config.content.max_body_bytes,
            false,
        )?;
        let project = self.lookup_project_for_invoke(request.admitted()).await?;
        let lookup_credential = &self.lookup_credential(&request)?;
        let merge_request = self
            .backend
            .merge_request(project.id, inputs.iid, lookup_credential)
            .await
            .map_err(gitlab_lookup_backend_error)?;
        ensure_merge_request_in_project(&project, &merge_request.value)?;
        let credential = &self.execution_credential(&request)?;
        let write = PlainWrite::new(
            json!({ "project": project.path_with_namespace, "mergeRequestIid": inputs.iid, "noteId": inputs.note_id }),
        );
        let response = self
            .backend
            .update_merge_request_note(project.id, inputs.clone(), credential)
            .await
            .map_err(|error| write.failed(error))?;
        ensure_merge_request_note_consistent(
            &project,
            &merge_request.value,
            &response.value,
            inputs.iid,
            inputs.note_id,
        )
        .map_err(|error| write.unverified(error))?;
        let mut result = gitlab_result_with_request_body_audit(
            "merge_request.note.update",
            &project,
            Some(json!({
                "mergeRequest": format!("{}!{}", project.path_with_namespace, merge_request.value.iid),
                "note": response.value.id
            })),
            (response.status, response.duration_ms),
            json!({ "note": response.value }),
            self.backend.egress_proxy_audit(credential),
            request_body_audit_for_note_update(&inputs),
        );
        add_gitlab_audit_fields(
            &mut result,
            vec![
                ("mergeRequestIid", json!(inputs.iid)),
                ("noteId", json!(inputs.note_id)),
            ],
        );
        add_gitlab_content_write_audit(&mut result, request.inputs(), Some(&inputs.body));
        Ok(result)
    }

    async fn invoke_merge_request_note_delete(
        &self,
        request: ProviderInvocation,
    ) -> Result<ProviderResult, ProviderError> {
        let inputs = parse_note_delete_inputs(request.inputs())?;
        let project = self.lookup_project_for_invoke(request.admitted()).await?;
        let lookup_credential = &self.lookup_credential(&request)?;
        let merge_request = self
            .backend
            .merge_request(project.id, inputs.iid, lookup_credential)
            .await
            .map_err(gitlab_lookup_backend_error)?;
        ensure_merge_request_in_project(&project, &merge_request.value)?;
        let credential = &self.execution_credential(&request)?;
        let proof = self
            .backend
            .merge_request_note(project.id, inputs.clone(), credential)
            .await
            .map_err(gitlab_proof_backend_error)?;
        ensure_merge_request_note_consistent(
            &project,
            &merge_request.value,
            &proof.value,
            inputs.iid,
            inputs.note_id,
        )?;
        let write = PlainWrite::new(
            json!({ "project": project.path_with_namespace, "mergeRequestIid": inputs.iid, "noteId": inputs.note_id }),
        );
        let response = self
            .backend
            .delete_merge_request_note(project.id, inputs.clone(), credential)
            .await
            .map_err(|error| write.failed(error))?;
        let mut result = gitlab_result(
            "merge_request.note.delete",
            &project,
            Some(json!({
                "mergeRequest": format!("{}!{}", project.path_with_namespace, merge_request.value.iid),
                "note": inputs.note_id
            })),
            response.status,
            response.duration_ms,
            json!({
                "deleted": true,
                "project": project.path_with_namespace,
                "iid": inputs.iid,
                "noteId": inputs.note_id
            }),
            self.backend.egress_proxy_audit(credential),
        );
        add_gitlab_audit_fields(
            &mut result,
            vec![
                ("mergeRequestIid", json!(inputs.iid)),
                ("noteId", json!(inputs.note_id)),
            ],
        );
        Ok(result)
    }

    async fn invoke_merge_request_discussion_list(
        &self,
        request: ProviderInvocation,
    ) -> Result<ProviderResult, ProviderError> {
        let mut inputs =
            parse_discussion_list_inputs(request.inputs(), self.config.search.max_results)?;
        let project = self.lookup_project_for_invoke(request.admitted()).await?;
        let lookup_credential = &self.lookup_credential(&request)?;
        let merge_request = self
            .backend
            .merge_request(project.id, inputs.iid, lookup_credential)
            .await
            .map_err(gitlab_lookup_backend_error)?;
        ensure_merge_request_in_project(&project, &merge_request.value)?;
        let request_hash = discussion_list_request_hash(&inputs);
        inputs.page = self.page_from_token(
            inputs.page_token.as_deref(),
            &request,
            &project,
            &request_hash,
            inputs.max_results,
        )?;
        let credential = &self.execution_credential(&request)?;
        let response = self
            .backend
            .merge_request_discussions_page(project.id, inputs.clone(), credential)
            .await
            .map_err(gitlab_backend_error)?;
        ensure_discussions_target_merge_request(&response.value.items, inputs.iid)?;
        let projection = inputs.projection;
        let items = match projection {
            GitlabCollectionProjection::Full => response
                .value
                .items
                .into_iter()
                .map(|item| json!(item))
                .collect::<Vec<_>>(),
            GitlabCollectionProjection::Summary => response
                .value
                .items
                .into_iter()
                .map(GitlabDiscussionSummary::from)
                .map(|item| json!(item))
                .collect::<Vec<_>>(),
        };
        self.merge_request_page_result(
            &request,
            &project,
            "discussions",
            items,
            response.value.next_page,
            &request_hash,
            inputs.max_results,
            response.status,
            response.duration_ms,
            credential,
            Some(projection),
        )
    }

    async fn invoke_merge_request_discussion_view(
        &self,
        request: ProviderInvocation,
    ) -> Result<ProviderResult, ProviderError> {
        let inputs = parse_discussion_view_inputs(request.inputs())?;
        let project = self.lookup_project_for_invoke(request.admitted()).await?;
        let lookup = &self.lookup_credential(&request)?;
        let merge_request = self
            .backend
            .merge_request(project.id, inputs.iid, lookup)
            .await
            .map_err(gitlab_lookup_backend_error)?;
        ensure_merge_request_in_project(&project, &merge_request.value)?;
        let credential = &self.execution_credential(&request)?;
        let response = self
            .backend
            .merge_request_discussion(project.id, inputs.iid, &inputs.discussion_id, credential)
            .await
            .map_err(gitlab_backend_error)?;
        ensure_merge_request_discussion_consistent(
            &project,
            &merge_request.value,
            &response.value,
            inputs.iid,
            &inputs.discussion_id,
            None,
            None,
        )?;
        Ok(gitlab_result(
            "merge_request.discussion.view",
            &project,
            Some(json!({ "discussion": inputs.discussion_id })),
            response.status,
            response.duration_ms,
            json!({ "discussion": response.value }),
            self.backend.egress_proxy_audit(credential),
        ))
    }

    async fn invoke_merge_request_inline_discussion_add(
        &self,
        request: ProviderInvocation,
    ) -> Result<ProviderResult, ProviderError> {
        let mut inputs = parse_positioned_discussion_inputs(
            request.inputs(),
            self.config.content.max_body_bytes,
        )?;
        let attribution = self.apply_markdown_attribution(
            "merge_request.discussion.inline.add",
            &mut inputs.body,
            &request,
        );
        enforce_bounded_text_field(
            "body",
            &inputs.body,
            self.config.content.max_body_bytes,
            attribution_audit_applied(attribution.as_ref()),
        )?;
        let (project, merge_request) = self.review_read_project(&request, inputs.iid).await?;
        let credential = &self.execution_credential(&request)?;
        let actor = self
            .backend
            .current_user(credential)
            .await
            .map_err(gitlab_backend_error)?
            .value;
        let actor_id = required_gitlab_actor_id(&actor)?;
        let position = self
            .prepare_review_position(
                project.id,
                &merge_request,
                &inputs.expected_head_sha,
                &inputs.position,
                credential,
            )
            .await?;
        let response = self
            .backend
            .create_merge_request_inline_discussion(
                project.id,
                GitlabPositionedDiscussionCreateRequest {
                    iid: inputs.iid,
                    body: inputs.body.clone(),
                    position: position.clone(),
                },
                credential,
            )
            .await
            .map_err(|error| {
                mutation_backend_error(
                    error,
                    MutationVerificationStage::MutationResponse,
                    MutationSafeLocators::new(),
                )
            })?;
        let discussion = response.value;
        let note = discussion.notes.first().ok_or_else(|| {
            mutation_verification_failed(
                MutationVerificationStage::MutationResponse,
                MutationSafeLocators::new().with_discussion_id(discussion.id.clone()),
            )
        })?;
        if ensure_merge_request_discussion_consistent(
            &project,
            &merge_request,
            &discussion,
            inputs.iid,
            &discussion.id,
            Some(note.id),
            None,
        )
        .is_err()
            || !gitlab_note_body_matches(note.body.as_deref(), &inputs.body)
            || !position_matches_input(note.position.as_ref(), &position, &inputs.position)
        {
            return Err(mutation_verification_failed(
                MutationVerificationStage::MutationReadback,
                MutationSafeLocators::new()
                    .with_discussion_id(discussion.id.clone())
                    .with_note_id(note.id),
            ));
        }
        let discussion_id = discussion.id.clone();
        let note_id = note.id;
        let mut result = gitlab_result(
            "merge_request.discussion.inline.add",
            &project,
            Some(json!({ "discussion": discussion_id, "note": note_id })),
            response.status,
            response.duration_ms,
            json!({
                "mutationStatus": "applied",
                "retrySafe": false,
                "discussionId": discussion_id,
                "noteId": note_id,
                "discussion": discussion,
            }),
            self.backend.egress_proxy_audit(credential),
        );
        add_gitlab_content_write_audit(&mut result, request.inputs(), Some(&inputs.body));
        add_gitlab_attribution_audit(&mut result, attribution);
        let mut fields =
            review_position_audit_fields(Some(&inputs.expected_head_sha), Some(&position));
        fields.push(("discussionId", json!(discussion_id)));
        fields.push(("noteId", json!(note_id)));
        add_gitlab_review_mutation_audit(&mut result, inputs.iid, actor_id, fields);
        Ok(result)
    }

    async fn invoke_merge_request_discussion_note_add(
        &self,
        request: ProviderInvocation,
    ) -> Result<ProviderResult, ProviderError> {
        let mut inputs =
            parse_discussion_reply_inputs(request.inputs(), self.config.content.max_body_bytes)?;
        let attribution = self.apply_markdown_attribution(
            "merge_request.discussion.note.add",
            &mut inputs.body,
            &request,
        );
        enforce_bounded_text_field(
            "body",
            &inputs.body,
            self.config.content.max_body_bytes,
            attribution_audit_applied(attribution.as_ref()),
        )?;
        let (project, merge_request) = self.review_read_project(&request, inputs.iid).await?;
        let credential = &self.execution_credential(&request)?;
        let actor = self
            .backend
            .current_user(credential)
            .await
            .map_err(gitlab_backend_error)?
            .value;
        let actor_id = required_gitlab_actor_id(&actor)?;
        let proof = self
            .backend
            .merge_request_discussion(project.id, inputs.iid, &inputs.discussion_id, credential)
            .await
            .map_err(gitlab_proof_backend_error)?;
        ensure_merge_request_discussion_consistent(
            &project,
            &merge_request,
            &proof.value,
            inputs.iid,
            &inputs.discussion_id,
            None,
            None,
        )?;
        let response = self
            .backend
            .create_merge_request_discussion_note(project.id, inputs.clone(), credential)
            .await
            .map_err(|error| {
                mutation_backend_error(
                    error,
                    MutationVerificationStage::MutationResponse,
                    MutationSafeLocators::new().with_discussion_id(inputs.discussion_id.clone()),
                )
            })?;
        let note = response.value;
        let locators = MutationSafeLocators::new()
            .with_discussion_id(inputs.discussion_id.clone())
            .with_note_id(note.id);
        if !gitlab_note_body_matches(note.body.as_deref(), &inputs.body)
            || ensure_merge_request_note_consistent(
                &project,
                &merge_request,
                &note,
                inputs.iid,
                note.id,
            )
            .is_err()
        {
            return Err(mutation_verification_failed(
                MutationVerificationStage::MutationResponse,
                locators,
            ));
        }
        let readback = self
            .backend
            .merge_request_discussion(project.id, inputs.iid, &inputs.discussion_id, credential)
            .await
            .map_err(|_| {
                mutation_verification_failed(
                    MutationVerificationStage::MutationReadback,
                    locators.clone(),
                )
            })?;
        if ensure_merge_request_discussion_consistent(
            &project,
            &merge_request,
            &readback.value,
            inputs.iid,
            &inputs.discussion_id,
            Some(note.id),
            None,
        )
        .is_err()
        {
            return Err(mutation_verification_failed(
                MutationVerificationStage::MutationReadback,
                locators,
            ));
        }
        let note_id = note.id;
        let mut result = gitlab_result(
            "merge_request.discussion.note.add",
            &project,
            Some(json!({ "discussion": inputs.discussion_id, "note": note_id })),
            response.status,
            response.duration_ms,
            json!({
                "mutationStatus": "applied",
                "retrySafe": false,
                "discussionId": inputs.discussion_id,
                "noteId": note_id,
                "note": note,
            }),
            self.backend.egress_proxy_audit(credential),
        );
        add_gitlab_content_write_audit(&mut result, request.inputs(), Some(&inputs.body));
        add_gitlab_attribution_audit(&mut result, attribution);
        add_gitlab_review_mutation_audit(
            &mut result,
            inputs.iid,
            actor_id,
            vec![
                ("discussionId", json!(inputs.discussion_id)),
                ("noteId", json!(note_id)),
            ],
        );
        Ok(result)
    }

    async fn invoke_merge_request_draft_note_list(
        &self,
        request: ProviderInvocation,
    ) -> Result<ProviderResult, ProviderError> {
        let mut inputs =
            parse_draft_note_list_inputs(request.inputs(), self.config.search.max_results)?;
        let (project, merge_request) = self.review_read_project(&request, inputs.iid).await?;
        let credential = &self.execution_credential(&request)?;
        let actor = self
            .backend
            .current_user(credential)
            .await
            .map_err(gitlab_backend_error)?
            .value;
        let (actor_id, review_context) = gitlab_review_context(&request, &actor)?;
        let request_hash = draft_note_collection_request_hash(&inputs, actor_id);
        let page = self.page_from_token(
            inputs.page_token.as_deref(),
            &request,
            &project,
            &request_hash,
            inputs.max_results,
        )?;
        inputs.page = 1;
        inputs.page_token = None;
        let response = self
            .backend
            .merge_request_draft_notes(project.id, inputs.clone(), credential)
            .await
            .map_err(gitlab_backend_error)?;
        let mut all_items = response.value.items;
        ensure_drafts_consistent(&all_items, &merge_request, actor_id)?;
        all_items.sort_by_key(|draft| draft.id);
        let page_offset = page
            .saturating_sub(1)
            .checked_mul(inputs.max_results)
            .and_then(|offset| usize::try_from(offset).ok())
            .ok_or_else(gitlab_page_token_error)?;
        let page_end = page_offset
            .saturating_add(inputs.max_results as usize)
            .min(all_items.len());
        let items = all_items
            .get(page_offset..page_end)
            .unwrap_or_default()
            .to_vec();
        let next_page = if page_end < all_items.len() {
            Some(page.checked_add(1).ok_or_else(gitlab_page_token_error)?)
        } else {
            None
        };
        let projection = inputs.projection;
        let items = match projection {
            GitlabCollectionProjection::Full => items
                .into_iter()
                .map(|item| json!(item))
                .collect::<Vec<_>>(),
            GitlabCollectionProjection::Summary => items
                .into_iter()
                .map(GitlabDraftNoteSummary::from)
                .map(|item| json!(item))
                .collect::<Vec<_>>(),
        };
        let mut result = self.merge_request_page_result(
            &request,
            &project,
            "draftNotes",
            items,
            next_page,
            &request_hash,
            inputs.max_results,
            response.status,
            response.duration_ms,
            credential,
            Some(projection),
        )?;
        add_gitlab_review_context(&mut result, review_context)?;
        Ok(result)
    }

    async fn invoke_merge_request_draft_note_view(
        &self,
        request: ProviderInvocation,
    ) -> Result<ProviderResult, ProviderError> {
        let inputs = parse_draft_note_object_inputs(request.inputs())?;
        let (project, merge_request) = self.review_read_project(&request, inputs.iid).await?;
        let credential = &self.execution_credential(&request)?;
        let actor = self
            .backend
            .current_user(credential)
            .await
            .map_err(gitlab_backend_error)?
            .value;
        let (actor_id, review_context) = gitlab_review_context(&request, &actor)?;
        let response = self
            .backend
            .merge_request_draft_note(project.id, inputs.clone(), credential)
            .await
            .map_err(gitlab_backend_error)?;
        ensure_draft_consistent(
            &response.value,
            &merge_request,
            actor_id,
            inputs.draft_note_id,
        )?;
        let mut result = gitlab_result(
            "merge_request.draft_note.view",
            &project,
            Some(json!({ "draftNote": inputs.draft_note_id })),
            response.status,
            response.duration_ms,
            json!({ "draftNote": response.value }),
            self.backend.egress_proxy_audit(credential),
        );
        add_gitlab_review_context(&mut result, review_context)?;
        Ok(result)
    }

    async fn invoke_merge_request_draft_note_add(
        &self,
        request: ProviderInvocation,
    ) -> Result<ProviderResult, ProviderError> {
        let mut inputs =
            parse_draft_note_add_inputs(request.inputs(), self.config.content.max_body_bytes)?;
        let attribution = self.apply_markdown_attribution(
            "merge_request.draft_note.add",
            &mut inputs.body,
            &request,
        );
        enforce_bounded_text_field(
            "body",
            &inputs.body,
            self.config.content.max_body_bytes,
            attribution_audit_applied(attribution.as_ref()),
        )?;
        let (project, merge_request) = self.review_read_project(&request, inputs.iid).await?;
        let credential = &self.execution_credential(&request)?;
        let actor = self
            .backend
            .current_user(credential)
            .await
            .map_err(gitlab_backend_error)?
            .value;
        let (actor_id, review_context) = gitlab_review_context(&request, &actor)?;
        if let Some(discussion_id) = &inputs.in_reply_to_discussion_id {
            let discussion = self
                .backend
                .merge_request_discussion(project.id, inputs.iid, discussion_id, credential)
                .await
                .map_err(gitlab_proof_backend_error)?;
            ensure_merge_request_discussion_consistent(
                &project,
                &merge_request,
                &discussion.value,
                inputs.iid,
                discussion_id,
                None,
                None,
            )?;
        }
        let position = match (&inputs.expected_head_sha, &inputs.position) {
            (Some(head), Some(position)) => Some(
                self.prepare_review_position(
                    project.id,
                    &merge_request,
                    head,
                    position,
                    credential,
                )
                .await?,
            ),
            _ => None,
        };
        let response = self
            .backend
            .create_merge_request_draft_note(
                project.id,
                GitlabDraftNoteCreateRequest {
                    iid: inputs.iid,
                    body: inputs.body.clone(),
                    position: position.clone(),
                    in_reply_to_discussion_id: inputs.in_reply_to_discussion_id.clone(),
                    resolve_discussion: inputs.resolve_discussion,
                },
                credential,
            )
            .await
            .map_err(|error| {
                mutation_backend_error(
                    error,
                    MutationVerificationStage::MutationResponse,
                    MutationSafeLocators::new(),
                )
            })?;
        let draft_id = response.value.id;
        let readback = self
            .backend
            .merge_request_draft_note(
                project.id,
                GitlabDraftNoteObjectRequest {
                    iid: inputs.iid,
                    draft_note_id: draft_id,
                },
                credential,
            )
            .await
            .map_err(|error| draft_backend_mutation_readback_error(error, draft_id))?;
        if ensure_draft_consistent(&readback.value, &merge_request, actor_id, draft_id).is_err()
            || !gitlab_note_body_matches(readback.value.body.as_deref(), &inputs.body)
            || !optional_position_matches_input(
                readback.value.position.as_ref(),
                position.as_ref(),
                inputs.position.as_ref(),
            )
            || readback.value.discussion_id != inputs.in_reply_to_discussion_id
        {
            return Err(draft_mutation_readback_error(draft_id));
        }
        let mut result = gitlab_result(
            "merge_request.draft_note.add",
            &project,
            Some(json!({ "draftNote": draft_id })),
            response.status,
            response.duration_ms,
            json!({
                "mutationStatus": "applied",
                "retrySafe": false,
                "draftNoteId": draft_id,
                "draftNote": readback.value,
            }),
            self.backend.egress_proxy_audit(credential),
        );
        add_gitlab_content_write_audit(&mut result, request.inputs(), Some(&inputs.body));
        add_gitlab_attribution_audit(&mut result, attribution);
        let mut fields = review_position_audit_fields(
            inputs.expected_head_sha.as_deref(),
            readback.value.position.as_ref(),
        );
        fields.push(("draftNoteId", json!(draft_id)));
        if let Some(discussion_id) = &inputs.in_reply_to_discussion_id {
            fields.push(("discussionId", json!(discussion_id)));
        }
        add_gitlab_review_mutation_audit(&mut result, inputs.iid, actor_id, fields);
        add_gitlab_review_context(&mut result, review_context)?;
        Ok(result)
    }

    async fn invoke_merge_request_draft_note_update(
        &self,
        request: ProviderInvocation,
    ) -> Result<ProviderResult, ProviderError> {
        let inputs =
            parse_draft_note_update_inputs(request.inputs(), self.config.content.max_body_bytes)?;
        let (project, merge_request) = self.review_read_project(&request, inputs.iid).await?;
        let credential = &self.execution_credential(&request)?;
        let actor = self
            .backend
            .current_user(credential)
            .await
            .map_err(gitlab_backend_error)?
            .value;
        let (actor_id, review_context) = gitlab_review_context(&request, &actor)?;
        let existing = self
            .backend
            .merge_request_draft_note(
                project.id,
                GitlabDraftNoteObjectRequest {
                    iid: inputs.iid,
                    draft_note_id: inputs.draft_note_id,
                },
                credential,
            )
            .await
            .map_err(gitlab_proof_backend_error)?
            .value;
        ensure_draft_consistent(&existing, &merge_request, actor_id, inputs.draft_note_id)?;
        if existing.discussion_id.is_some() && inputs.position.is_some() {
            return Err(ProviderError::deny(
                ReasonCode::InputInvalid,
                "GitLab reply draft position cannot be replaced",
            ));
        }
        let requested_position = match (&inputs.expected_head_sha, &inputs.position) {
            (Some(head), Some(position)) => Some(
                self.prepare_review_position(
                    project.id,
                    &merge_request,
                    head,
                    position,
                    credential,
                )
                .await?,
            ),
            _ => None,
        };
        let effective_body = inputs
            .body
            .clone()
            .or_else(|| existing.body.clone())
            .ok_or_else(|| {
                ProviderError::error(
                    ReasonCode::UpstreamProtocolFailed,
                    "GitLab draft note body is missing",
                )
            })?;
        // GitLab requires `note` and writes `position` from every update
        // request, clearing an omitted position. Replay the proven current
        // value for whichever field the caller did not replace.
        let effective_position = if let Some(position) = requested_position.clone() {
            Some(position)
        } else if let Some(position) = existing.position.as_ref() {
            require_replayable_draft_position(position)?;
            Some(position.clone())
        } else {
            None
        };
        let response = self
            .backend
            .update_merge_request_draft_note(
                project.id,
                GitlabDraftNoteUpdateRequest {
                    iid: inputs.iid,
                    draft_note_id: inputs.draft_note_id,
                    body: effective_body.clone(),
                    position: effective_position.clone(),
                },
                credential,
            )
            .await
            .map_err(|error| {
                mutation_backend_error(
                    error,
                    MutationVerificationStage::MutationResponse,
                    MutationSafeLocators::new().with_draft_note_ids(vec![inputs.draft_note_id]),
                )
            })?;
        let readback = self
            .backend
            .merge_request_draft_note(
                project.id,
                GitlabDraftNoteObjectRequest {
                    iid: inputs.iid,
                    draft_note_id: inputs.draft_note_id,
                },
                credential,
            )
            .await
            .map_err(|error| draft_backend_mutation_readback_error(error, inputs.draft_note_id))?;
        if ensure_draft_consistent(
            &readback.value,
            &merge_request,
            actor_id,
            inputs.draft_note_id,
        )
        .is_err()
            || !gitlab_note_body_matches(readback.value.body.as_deref(), &effective_body)
            || if let (Some(expected), Some(input)) =
                (requested_position.as_ref(), inputs.position.as_ref())
            {
                !position_matches_input(readback.value.position.as_ref(), expected, input)
            } else {
                readback.value.position != existing.position
            }
        {
            return Err(draft_mutation_readback_error(inputs.draft_note_id));
        }
        let mut result = gitlab_result(
            "merge_request.draft_note.update",
            &project,
            Some(json!({ "draftNote": inputs.draft_note_id })),
            response.status,
            response.duration_ms,
            json!({
                "mutationStatus": "applied",
                "retrySafe": false,
                "draftNoteId": inputs.draft_note_id,
                "draftNote": readback.value,
            }),
            self.backend.egress_proxy_audit(credential),
        );
        let mut fields = review_position_audit_fields(
            inputs.expected_head_sha.as_deref(),
            readback.value.position.as_ref(),
        );
        fields.push(("draftNoteId", json!(inputs.draft_note_id)));
        add_gitlab_review_mutation_audit(&mut result, inputs.iid, actor_id, fields);
        add_gitlab_review_context(&mut result, review_context)?;
        Ok(result)
    }

    async fn invoke_merge_request_draft_note_delete(
        &self,
        request: ProviderInvocation,
    ) -> Result<ProviderResult, ProviderError> {
        self.invoke_draft_note_delete(request).await
    }

    async fn invoke_merge_request_draft_note_publish(
        &self,
        request: ProviderInvocation,
    ) -> Result<ProviderResult, ProviderError> {
        let inputs = parse_draft_note_object_inputs(request.inputs())?;
        let (project, merge_request) = self.review_read_project(&request, inputs.iid).await?;
        let credential = &self.execution_credential(&request)?;
        let actor = self
            .backend
            .current_user(credential)
            .await
            .map_err(gitlab_backend_error)?
            .value;
        let (actor_id, review_context) = gitlab_review_context(&request, &actor)?;
        let existing = self
            .backend
            .merge_request_draft_note(project.id, inputs.clone(), credential)
            .await
            .map_err(gitlab_proof_backend_error)?
            .value;
        ensure_draft_consistent(&existing, &merge_request, actor_id, inputs.draft_note_id)?;
        let body = existing.body.clone().ok_or_else(|| {
            ProviderError::error(
                ReasonCode::UpstreamProtocolFailed,
                "GitLab draft note body is missing",
            )
        })?;
        let scope = if let Some(discussion_id) = existing.discussion_id.clone() {
            if discussion_id.is_empty() {
                return Err(publication_protocol_error());
            }
            let discussion = self
                .backend
                .merge_request_discussion(project.id, inputs.iid, &discussion_id, credential)
                .await
                .map_err(gitlab_proof_backend_error)?
                .value;
            if discussion.id != discussion_id {
                return Err(publication_protocol_error());
            }
            let snapshot = publication_snapshot_from_discussions(
                &project,
                &merge_request,
                inputs.iid,
                vec![discussion],
            )?;
            DraftPublicationScope::Reply {
                discussion_id,
                baseline: snapshot.notes.into_keys().collect(),
            }
        } else {
            let snapshot = self
                .publication_discussion_snapshot(&project, &merge_request, inputs.iid, credential)
                .await?;
            DraftPublicationScope::Collection {
                baseline: snapshot.notes.into_keys().collect(),
                expected_position: existing.position.clone().map(Box::new),
            }
        };
        let draft_safe =
            MutationSafeLocators::new().with_draft_note_ids(vec![inputs.draft_note_id]);
        let response = self
            .backend
            .publish_merge_request_draft_note(project.id, inputs.clone(), credential)
            .await
            .map_err(|error| {
                mutation_backend_error(
                    error,
                    MutationVerificationStage::MutationResponse,
                    draft_safe.clone(),
                )
            })?;
        let post = match &scope {
            DraftPublicationScope::Reply { discussion_id, .. } => {
                let discussion = self
                    .backend
                    .merge_request_discussion(project.id, inputs.iid, discussion_id, credential)
                    .await
                    .map_err(|_| published_note_readback_error(draft_safe.clone()))?
                    .value;
                publication_snapshot_from_discussions(
                    &project,
                    &merge_request,
                    inputs.iid,
                    vec![discussion],
                )
                .map_err(|_| published_note_readback_error(draft_safe.clone()))?
            }
            DraftPublicationScope::Collection { .. } => self
                .publication_discussion_snapshot(&project, &merge_request, inputs.iid, credential)
                .await
                .map_err(|_| published_note_readback_error(draft_safe.clone()))?,
        };
        let (baseline, expected_position, reply_discussion_id, enforce_position) = match &scope {
            DraftPublicationScope::Reply {
                discussion_id,
                baseline,
            } => (baseline, None, Some(discussion_id.as_str()), false),
            DraftPublicationScope::Collection {
                baseline,
                expected_position,
            } => (baseline, expected_position.as_deref(), None, true),
        };
        let identity = select_published_note_candidate(
            &post.notes,
            baseline,
            reply_discussion_id,
            actor_id,
            &body,
            expected_position,
            enforce_position,
        )
        .ok_or_else(|| published_note_readback_error(draft_safe.clone()))?;
        let exact = self
            .backend
            .merge_request_discussion(project.id, inputs.iid, &identity.discussion_id, credential)
            .await
            .map_err(|_| published_note_readback_error(draft_safe.clone()))?
            .value;
        let exact = publication_snapshot_from_discussions(
            &project,
            &merge_request,
            inputs.iid,
            vec![exact],
        )
        .map_err(|_| published_note_readback_error(draft_safe.clone()))?;
        exact
            .notes
            .get(&identity)
            .filter(|note| {
                published_note_matches(note, actor_id, &body, expected_position, enforce_position)
            })
            .ok_or_else(|| published_note_readback_error(draft_safe.clone()))?;
        let proven_safe = draft_safe
            .with_discussion_id(identity.discussion_id.clone())
            .with_note_id(identity.note_id);
        let remaining = self
            .all_current_drafts(project.id, inputs.iid, credential)
            .await
            .map_err(|error| {
                mutation_readback_error(
                    error,
                    MutationVerificationStage::DraftAbsenceReadback,
                    proven_safe.clone(),
                )
            })?;
        if remaining
            .iter()
            .any(|draft| draft.id == inputs.draft_note_id)
        {
            return Err(mutation_verification_failed(
                MutationVerificationStage::DraftAbsenceReadback,
                proven_safe,
            ));
        }
        let mut result = gitlab_result(
            "merge_request.draft_note.publish",
            &project,
            Some(
                json!({ "draftNote": inputs.draft_note_id, "discussion": identity.discussion_id, "note": identity.note_id }),
            ),
            response.status,
            response.duration_ms,
            json!({ "mutationStatus": "applied", "retrySafe": false, "draftNoteId": inputs.draft_note_id, "published": true, "discussionId": identity.discussion_id, "noteId": identity.note_id }),
            self.backend.egress_proxy_audit(credential),
        );
        let mut fields = review_position_audit_fields(None, existing.position.as_ref());
        fields.push(("draftNoteId", json!(inputs.draft_note_id)));
        fields.push(("discussionId", json!(identity.discussion_id)));
        fields.push(("noteId", json!(identity.note_id)));
        add_gitlab_review_mutation_audit(&mut result, inputs.iid, actor_id, fields);
        add_gitlab_review_context(&mut result, review_context)?;
        Ok(result)
    }

    async fn invoke_draft_note_delete(
        &self,
        request: ProviderInvocation,
    ) -> Result<ProviderResult, ProviderError> {
        let inputs = parse_draft_note_object_inputs(request.inputs())?;
        let (project, merge_request) = self.review_read_project(&request, inputs.iid).await?;
        let credential = &self.execution_credential(&request)?;
        let actor = self
            .backend
            .current_user(credential)
            .await
            .map_err(gitlab_backend_error)?
            .value;
        let (actor_id, review_context) = gitlab_review_context(&request, &actor)?;
        let existing = self
            .backend
            .merge_request_draft_note(project.id, inputs.clone(), credential)
            .await
            .map_err(gitlab_proof_backend_error)?
            .value;
        ensure_draft_consistent(&existing, &merge_request, actor_id, inputs.draft_note_id)?;
        let response = self
            .backend
            .delete_merge_request_draft_note(project.id, inputs.clone(), credential)
            .await
            .map_err(|error| {
                mutation_backend_error(
                    error,
                    MutationVerificationStage::MutationResponse,
                    MutationSafeLocators::new().with_draft_note_ids(vec![inputs.draft_note_id]),
                )
            })?;
        let remaining = self
            .all_current_drafts(project.id, inputs.iid, credential)
            .await
            .map_err(|error| {
                mutation_readback_error(
                    error,
                    MutationVerificationStage::DraftAbsenceReadback,
                    MutationSafeLocators::new().with_draft_note_ids(vec![inputs.draft_note_id]),
                )
            })?;
        if remaining
            .iter()
            .any(|draft| draft.id == inputs.draft_note_id)
        {
            return Err(mutation_verification_failed(
                MutationVerificationStage::DraftAbsenceReadback,
                MutationSafeLocators::new().with_draft_note_ids(vec![inputs.draft_note_id]),
            ));
        }
        let mut result = gitlab_result(
            "merge_request.draft_note.delete",
            &project,
            Some(json!({ "draftNote": inputs.draft_note_id })),
            response.status,
            response.duration_ms,
            json!({ "mutationStatus": "applied", "retrySafe": false, "draftNoteId": inputs.draft_note_id, "deleted": true }),
            self.backend.egress_proxy_audit(credential),
        );
        let mut fields = review_position_audit_fields(None, existing.position.as_ref());
        fields.push(("draftNoteId", json!(inputs.draft_note_id)));
        if let Some(discussion_id) = &existing.discussion_id {
            fields.push(("discussionId", json!(discussion_id)));
        }
        add_gitlab_review_mutation_audit(&mut result, inputs.iid, actor_id, fields);
        add_gitlab_review_context(&mut result, review_context)?;
        Ok(result)
    }

    async fn publication_discussion_snapshot(
        &self,
        project: &GitlabProject,
        merge_request: &GitlabMergeRequest,
        iid: u64,
        credential: &GitlabCredential,
    ) -> Result<PublicationDiscussionSnapshot, ProviderError> {
        let mut snapshot = PublicationDiscussionSnapshot {
            notes: BTreeMap::new(),
        };
        let mut note_discussions = BTreeMap::<u64, String>::new();
        for page in 1..=10 {
            let response = self
                .backend
                .merge_request_discussions_page(
                    project.id,
                    GitlabDiscussionListRequest {
                        iid,
                        max_results: GITLAB_MAX_PER_PAGE,
                        projection: GitlabCollectionProjection::Full,
                        page_token: None,
                        page,
                    },
                    credential,
                )
                .await
                .map_err(gitlab_backend_error)?;
            validate_gitlab_page_count(response.value.items.len(), GITLAB_MAX_PER_PAGE)?;
            merge_publication_discussions(
                &mut snapshot,
                &mut note_discussions,
                project,
                merge_request,
                iid,
                response.value.items,
            )?;
            match response.value.next_page {
                None => return Ok(snapshot),
                Some(next_page) if next_page == page + 1 && page < 10 => {}
                Some(next_page) if next_page == page + 1 => {
                    return Err(publication_snapshot_limit_error());
                }
                Some(_) => return Err(publication_protocol_error()),
            }
        }
        Err(publication_snapshot_limit_error())
    }

    async fn all_current_drafts(
        &self,
        project_id: u64,
        iid: u64,
        credential: &GitlabCredential,
    ) -> Result<Vec<GitlabDraftNote>, ProviderError> {
        self.backend
            .merge_request_draft_notes(
                project_id,
                GitlabDraftNoteListRequest {
                    iid,
                    max_results: GITLAB_MAX_PER_PAGE,
                    projection: GitlabCollectionProjection::Full,
                    page_token: None,
                    page: 1,
                },
                credential,
            )
            .await
            .map(|response| response.value.items)
            .map_err(gitlab_backend_error)
    }

    async fn invoke_merge_request_draft_note_publish_all(
        &self,
        request: ProviderInvocation,
    ) -> Result<ProviderResult, ProviderError> {
        self.invoke_draft_bulk_publication(request, false).await
    }

    async fn invoke_merge_request_review_submit(
        &self,
        request: ProviderInvocation,
    ) -> Result<ProviderResult, ProviderError> {
        self.invoke_draft_bulk_publication(request, true).await
    }

    async fn invoke_draft_bulk_publication(
        &self,
        request: ProviderInvocation,
        review_submit: bool,
    ) -> Result<ProviderResult, ProviderError> {
        let mut inputs = parse_draft_publication_inputs(
            request.inputs(),
            self.config.content.max_body_bytes,
            review_submit,
        )?;
        let attribution = inputs.summary.as_mut().map(|summary| {
            self.apply_markdown_attribution(
                if review_submit {
                    "merge_request.review.submit"
                } else {
                    "merge_request.draft_note.publish_all"
                },
                summary,
                &request,
            )
        });
        let attribution = attribution.flatten();
        if let Some(summary) = &inputs.summary {
            enforce_bounded_text_field(
                "body",
                summary,
                self.config.content.max_body_bytes,
                attribution_audit_applied(attribution.as_ref()),
            )?;
        }
        let (project, merge_request) = self.review_read_project(&request, inputs.iid).await?;
        let credential = &self.execution_credential(&request)?;
        let actor = self
            .backend
            .current_user(credential)
            .await
            .map_err(gitlab_backend_error)?
            .value;
        let (actor_id, review_context) = gitlab_review_context(&request, &actor)?;
        let mut drafts = self
            .all_current_drafts(project.id, inputs.iid, credential)
            .await?;
        ensure_drafts_consistent(&drafts, &merge_request, actor_id)?;
        drafts.sort_by_key(|draft| draft.id);
        let snapshot = drafts.iter().map(|draft| draft.id).collect::<Vec<_>>();
        let safe = MutationSafeLocators::new().with_draft_note_ids(snapshot.clone());

        let baseline_reviewer_state = if review_submit {
            let version = self
                .backend
                .gitlab_version(credential)
                .await
                .map_err(gitlab_review_submit_version_backend_error)?
                .value;
            require_gitlab_review_submit_version(&version.version)?;
            let state = self
                .acting_reviewer_state(project.id, inputs.iid, actor_id, credential)
                .await?;
            let approvals = self
                .backend
                .merge_request_approval_summary(project.id, inputs.iid, credential)
                .await
                .map_err(gitlab_backend_error)?
                .value;
            ensure_actor_not_formally_approved(&approvals, actor_id)?;
            if state == "approved" {
                return Err(ProviderError::deny(
                    ReasonCode::VersionConflict,
                    "GitLab reviewer has a formal approval; unapprove before submitting a review",
                ));
            }
            Some(state)
        } else {
            None
        };

        let bulk = self
            .backend
            .bulk_publish_merge_request_draft_notes(
                project.id,
                GitlabDraftBulkPublishRequest {
                    iid: inputs.iid,
                    reviewer_state: inputs.reviewer_state.clone(),
                },
                credential,
            )
            .await;
        let response = match bulk {
            Ok(response) => response,
            Err(GitlabBackendError::NotSent { timed_out }) => {
                return Err(mutation_not_sent(timed_out));
            }
            // Delegated access that could not be presented, or that GitLab
            // rejected, applied nothing: the failure keeps its own reason
            // rather than reading as unverified when the probe below fails
            // the same way.
            Err(GitlabBackendError::Credential(error)) => return Err(error),
            // A write the Broker could not prepare was never sent: it keeps
            // its cause's reason whatever the probe below would find.
            Err(error @ GitlabBackendError::RequestUnbuilt(_)) => {
                return Err(gitlab_backend_error(error));
            }
            Err(error) => {
                let remaining = self
                    .all_current_drafts(project.id, inputs.iid, credential)
                    .await;
                let drafts_unchanged = remaining.as_ref().is_ok_and(|remaining| {
                    snapshot
                        .iter()
                        .all(|id| remaining.iter().any(|d| d.id == *id))
                });
                let reviewer_unchanged = if review_submit {
                    self.acting_reviewer_state(project.id, inputs.iid, actor_id, credential)
                        .await
                        .is_ok_and(|state| Some(state) == baseline_reviewer_state)
                } else {
                    true
                };
                if drafts_unchanged && reviewer_unchanged {
                    return Err(gitlab_backend_error(error));
                }
                return Err(match remaining {
                    Err(error) => mutation_readback_error(
                        error,
                        MutationVerificationStage::BulkPublishReadback,
                        safe,
                    ),
                    Ok(_) => mutation_verification_failed(
                        MutationVerificationStage::BulkPublishReadback,
                        safe,
                    ),
                });
            }
        };
        let remaining = self
            .all_current_drafts(project.id, inputs.iid, credential)
            .await
            .map_err(|error| {
                mutation_readback_error(
                    error,
                    MutationVerificationStage::BulkPublishReadback,
                    safe.clone(),
                )
            })?;
        if snapshot
            .iter()
            .any(|id| remaining.iter().any(|draft| draft.id == *id))
        {
            return Err(mutation_verification_failed(
                MutationVerificationStage::BulkPublishReadback,
                safe,
            ));
        }

        if review_submit {
            let observed = self
                .acting_reviewer_state(project.id, inputs.iid, actor_id, credential)
                .await
                .map_err(|_| {
                    mutation_verification_failed(
                        MutationVerificationStage::ReviewerStateReadback,
                        safe.clone(),
                    )
                })?;
            if Some(observed.as_str()) != inputs.reviewer_state.as_deref() {
                return Err(mutation_verification_failed(
                    MutationVerificationStage::ReviewerStateReadback,
                    safe,
                ));
            }
        }

        let summary_note_id = if let Some(summary) = &inputs.summary {
            let note = self
                .backend
                .create_merge_request_review_summary(
                    project.id,
                    GitlabReviewSummaryNoteRequest {
                        iid: inputs.iid,
                        body: summary.clone(),
                        internal: inputs.internal,
                    },
                    credential,
                )
                .await
                .map_err(|_| {
                    mutation_verification_failed(
                        MutationVerificationStage::SummaryNoteResponse,
                        safe.clone(),
                    )
                })?
                .value;
            if !gitlab_note_body_matches(note.body.as_deref(), summary)
                || ensure_merge_request_note_consistent(
                    &project,
                    &merge_request,
                    &note,
                    inputs.iid,
                    note.id,
                )
                .is_err()
            {
                return Err(mutation_verification_failed(
                    MutationVerificationStage::SummaryNoteResponse,
                    safe.clone().with_note_id(note.id),
                ));
            }
            Some(note.id)
        } else {
            None
        };

        let mut payload = serde_json::Map::from_iter([
            ("mutationStatus".to_string(), json!("applied")),
            ("retrySafe".to_string(), json!(false)),
            ("publishedDraftNoteIds".to_string(), json!(snapshot)),
        ]);
        if let Some(note_id) = summary_note_id {
            payload.insert("summaryNoteId".to_string(), json!(note_id));
        }
        if review_submit {
            payload.insert(
                "reviewerState".to_string(),
                json!(
                    if inputs.reviewer_state.as_deref() == Some("requested_changes") {
                        "requestedChanges"
                    } else {
                        "reviewed"
                    }
                ),
            );
        }
        let operation = if review_submit {
            "merge_request.review.submit"
        } else {
            "merge_request.draft_note.publish_all"
        };
        let mut result = gitlab_result(
            operation,
            &project,
            Some(
                json!({ "mergeRequest": format!("{}!{}", project.path_with_namespace, inputs.iid) }),
            ),
            response.status,
            response.duration_ms,
            Value::Object(payload),
            self.backend.egress_proxy_audit(credential),
        );
        add_gitlab_content_write_audit(&mut result, request.inputs(), inputs.summary.as_deref());
        add_gitlab_attribution_audit(&mut result, attribution);
        let mut fields = vec![
            ("draftNoteIds", json!(snapshot)),
            ("draftNoteCount", json!(snapshot.len())),
        ];
        if let Some(note_id) = summary_note_id {
            fields.push(("summaryNoteId", json!(note_id)));
        }
        if review_submit {
            fields.push((
                "reviewerState",
                json!(
                    if inputs.reviewer_state.as_deref() == Some("requested_changes") {
                        "requestedChanges"
                    } else {
                        "reviewed"
                    }
                ),
            ));
            fields.push(("provenHeadSha", json!(merge_request.sha)));
        }
        add_gitlab_review_mutation_audit(&mut result, inputs.iid, actor_id, fields);
        add_gitlab_review_context(&mut result, review_context)?;
        Ok(result)
    }

    async fn acting_reviewer_state(
        &self,
        project_id: u64,
        iid: u64,
        actor_id: u64,
        credential: &GitlabCredential,
    ) -> Result<String, ProviderError> {
        let mut found = None;
        for page in 1..=10 {
            let response = self
                .backend
                .merge_request_reviewers(
                    project_id,
                    GitlabMergeRequestListRequest {
                        iid,
                        max_results: GITLAB_MAX_PER_PAGE,
                        page_token: None,
                        page,
                        unidiff: None,
                    },
                    credential,
                )
                .await
                .map_err(gitlab_backend_error)?;
            for reviewer in response.value.items {
                let reviewer_id = reviewer.user.id.ok_or_else(|| {
                    ProviderError::error(
                        ReasonCode::UpstreamProtocolFailed,
                        "GitLab reviewer identity did not include a numeric id",
                    )
                })?;
                if reviewer_id == actor_id {
                    if found.is_some() {
                        return Err(ProviderError::error(
                            ReasonCode::UpstreamProtocolFailed,
                            "GitLab returned duplicate acting reviewer entries",
                        ));
                    }
                    found = Some(reviewer.state);
                }
            }
            if response.value.next_page.is_none() {
                break;
            }
            if page == 10 {
                return Err(ProviderError::error(
                    ReasonCode::UpstreamProtocolFailed,
                    "GitLab reviewer collection exceeded the bounded page limit",
                ));
            }
        }
        found.ok_or_else(acting_reviewer_not_assigned_error)
    }

    async fn invoke_merge_request_reviewer_list(
        &self,
        request: ProviderInvocation,
    ) -> Result<ProviderResult, ProviderError> {
        let mut inputs = parse_merge_request_list_inputs(
            request.inputs(),
            self.config.search.max_results,
            "reviewer list",
            false,
        )?;
        let (project, _) = self.review_read_project(&request, inputs.iid).await?;
        let request_hash = merge_request_collection_request_hash(inputs.iid, inputs.unidiff);
        inputs.page = self.page_from_token(
            inputs.page_token.as_deref(),
            &request,
            &project,
            &request_hash,
            inputs.max_results,
        )?;
        let credential = &self.execution_credential(&request)?;
        let response = self
            .backend
            .merge_request_reviewers(project.id, inputs.clone(), credential)
            .await
            .map_err(gitlab_backend_error)?;
        self.merge_request_page_result(
            &request,
            &project,
            "reviewers",
            response.value.items,
            response.value.next_page,
            &request_hash,
            inputs.max_results,
            response.status,
            response.duration_ms,
            credential,
            None,
        )
    }

    async fn invoke_merge_request_approval_view(
        &self,
        request: ProviderInvocation,
    ) -> Result<ProviderResult, ProviderError> {
        let inputs = parse_merge_request_subresource_inputs(request.inputs())?;
        let (project, _) = self.review_read_project(&request, inputs.iid).await?;
        let credential = &self.execution_credential(&request)?;
        let response = self
            .backend
            .merge_request_approval_summary(project.id, inputs.iid, credential)
            .await
            .map_err(gitlab_backend_error)?;
        Ok(gitlab_result(
            "merge_request.approval.view",
            &project,
            None,
            response.status,
            response.duration_ms,
            json!({ "approval": response.value }),
            self.backend.egress_proxy_audit(credential),
        ))
    }

    async fn invoke_merge_request_approval_state_view(
        &self,
        request: ProviderInvocation,
    ) -> Result<ProviderResult, ProviderError> {
        let inputs = parse_merge_request_subresource_inputs(request.inputs())?;
        let (project, _) = self.review_read_project(&request, inputs.iid).await?;
        let credential = &self.execution_credential(&request)?;
        let response = self
            .backend
            .merge_request_approval_state(project.id, inputs.iid, credential)
            .await
            .map_err(gitlab_backend_error)?;
        Ok(gitlab_result(
            "merge_request.approval_state.view",
            &project,
            None,
            response.status,
            response.duration_ms,
            json!({ "approvalState": response.value }),
            self.backend.egress_proxy_audit(credential),
        ))
    }

    async fn invoke_merge_request_approval_rule_list(
        &self,
        request: ProviderInvocation,
    ) -> Result<ProviderResult, ProviderError> {
        let parsed = parse_merge_request_list_inputs(
            request.inputs(),
            self.config.search.max_results,
            "approval rule list",
            false,
        )?;
        let mut inputs = GitlabApprovalRuleListRequest {
            iid: parsed.iid,
            max_results: parsed.max_results,
            page_token: parsed.page_token,
            page: parsed.page,
        };
        let (project, _) = self.review_read_project(&request, inputs.iid).await?;
        let request_hash = merge_request_collection_request_hash(inputs.iid, None);
        inputs.page = self.page_from_token(
            inputs.page_token.as_deref(),
            &request,
            &project,
            &request_hash,
            inputs.max_results,
        )?;
        let credential = &self.execution_credential(&request)?;
        let response = self
            .backend
            .merge_request_approval_rules(project.id, inputs.clone(), credential)
            .await
            .map_err(gitlab_backend_error)?;
        self.merge_request_page_result(
            &request,
            &project,
            "approvalRules",
            response.value.items,
            response.value.next_page,
            &request_hash,
            inputs.max_results,
            response.status,
            response.duration_ms,
            credential,
            None,
        )
    }

    async fn invoke_merge_request_approval_rule_view(
        &self,
        request: ProviderInvocation,
    ) -> Result<ProviderResult, ProviderError> {
        let inputs = parse_merge_request_object_inputs(
            request.inputs(),
            "approvalRuleId",
            "approval rule view",
        )?;
        if inputs.unidiff.is_some() {
            return Err(ProviderError::deny(
                ReasonCode::InputInvalid,
                "unidiff is not valid for approval rules",
            ));
        }
        let (project, _) = self.review_read_project(&request, inputs.iid).await?;
        let credential = &self.execution_credential(&request)?;
        let response = self
            .backend
            .merge_request_approval_rule(project.id, inputs.iid, inputs.object_id, credential)
            .await
            .map_err(gitlab_backend_error)?;
        if response.value.id != inputs.object_id {
            return Err(note_scope_mismatch_error());
        }
        Ok(gitlab_result(
            "merge_request.approval_rule.view",
            &project,
            Some(json!({ "approvalRule": inputs.object_id })),
            response.status,
            response.duration_ms,
            json!({ "approvalRule": response.value }),
            self.backend.egress_proxy_audit(credential),
        ))
    }

    async fn invoke_merge_request_approval_mutation(
        &self,
        request: ProviderInvocation,
        approve: bool,
    ) -> Result<ProviderResult, ProviderError> {
        let inputs = parse_approval_mutation_inputs(request.inputs(), approve)?;
        let lookup_project = self.lookup_project_for_invoke(request.admitted()).await?;
        let credential = &self.execution_credential(&request)?;
        let project = self
            .backend
            .project(&lookup_project.path_with_namespace, credential)
            .await
            .map_err(gitlab_proof_backend_error)?
            .value;
        ensure_same_project(&lookup_project, &project)?;
        let merge_request = self
            .backend
            .merge_request(project.id, inputs.iid, credential)
            .await
            .map_err(gitlab_proof_backend_error)?
            .value;
        ensure_merge_request_in_project(&project, &merge_request)?;
        ensure_merge_request_repository_ids(&project, &merge_request)?;
        let actor = self
            .backend
            .current_user(credential)
            .await
            .map_err(gitlab_backend_error)?
            .value;
        let actor_id = required_gitlab_actor_id(&actor)?;
        let baseline = self
            .backend
            .merge_request_approval_summary(project.id, inputs.iid, credential)
            .await
            .map_err(gitlab_backend_error)?
            .value;
        let baseline_approved = actor_has_approved(&baseline, actor_id)?;
        if baseline_approved == approve {
            return Err(ProviderError::deny(
                ReasonCode::VersionConflict,
                if approve {
                    "GitLab acting user has already approved this merge request"
                } else {
                    "GitLab acting user has not approved this merge request"
                },
            ));
        }
        let approval_diff_version_id = if approve {
            require_current_position_triplet(
                &merge_request,
                inputs.head_sha.as_deref().expect("approve sha"),
            )?;
            require_approval_readiness(&merge_request)?;
            let current = self
                .current_approval_diff_version(project.id, &merge_request, credential)
                .await?;
            if ensure_current_diff_version(&current, &merge_request).is_err()
                || current.patch_id_sha.as_deref().is_none_or(str::is_empty)
            {
                return Err(position_version_conflict());
            }
            Some(current.id)
        } else {
            None
        };
        let safe = MutationSafeLocators::new();
        let mutation = self
            .backend
            .set_merge_request_approval(project.id, inputs.clone(), credential)
            .await;
        let response = match mutation {
            Ok(response) => response,
            Err(GitlabBackendError::NotSent { timed_out }) => {
                return Err(mutation_not_sent(timed_out));
            }
            // Delegated access that could not be presented, or that GitLab
            // rejected, applied nothing: the failure keeps its own reason
            // rather than reading as unverified when the probe below fails
            // the same way.
            Err(GitlabBackendError::Credential(error)) => return Err(error),
            // A write the Broker could not prepare was never sent: it keeps
            // its cause's reason whatever the probe below would find.
            Err(error @ GitlabBackendError::RequestUnbuilt(_)) => {
                return Err(gitlab_backend_error(error));
            }
            Err(error) => {
                let unchanged = self
                    .backend
                    .merge_request_approval_summary(project.id, inputs.iid, credential)
                    .await
                    .ok()
                    .and_then(|response| actor_has_approved(&response.value, actor_id).ok())
                    == Some(baseline_approved);
                if unchanged {
                    return Err(gitlab_backend_error(error));
                }
                return Err(mutation_verification_failed(
                    MutationVerificationStage::MutationReadback,
                    safe,
                ));
            }
        };
        let observed = self
            .backend
            .merge_request_approval_summary(project.id, inputs.iid, credential)
            .await
            .map_err(|_| {
                mutation_verification_failed(
                    MutationVerificationStage::MutationReadback,
                    safe.clone(),
                )
            })?
            .value;
        let expected = approve;
        if actor_has_approved(&observed, actor_id).ok() != Some(expected)
            || observed
                .user_has_approved
                .is_some_and(|value| value != expected)
        {
            return Err(mutation_verification_failed(
                MutationVerificationStage::MutationReadback,
                safe,
            ));
        }
        let operation = if approve {
            "merge_request.approve"
        } else {
            "merge_request.unapprove"
        };
        let mut result = gitlab_result(
            operation,
            &project,
            Some(json!({
                "mergeRequest": format!("{}!{}", project.path_with_namespace, inputs.iid)
            })),
            response.status,
            response.duration_ms,
            json!({
                "mutationStatus": "applied",
                "retrySafe": false,
                "userId": actor_id,
                "headSha": inputs.head_sha,
                "approved": expected
            }),
            self.backend.egress_proxy_audit(credential),
        );
        let mut fields = vec![("approved", json!(expected))];
        if approve {
            fields.push((
                "expectedHeadSha",
                json!(inputs.head_sha.as_deref().expect("approve sha")),
            ));
            fields.push(("provenHeadSha", json!(merge_request.sha)));
            fields.push((
                "diffVersionId",
                json!(approval_diff_version_id.expect("approve diff version")),
            ));
        }
        add_gitlab_review_mutation_audit(&mut result, inputs.iid, actor_id, fields);
        Ok(result)
    }

    async fn current_approval_diff_version(
        &self,
        project_id: u64,
        merge_request: &GitlabMergeRequest,
        credential: &GitlabCredential,
    ) -> Result<GitlabDiffVersionSummary, ProviderError> {
        let refs = merge_request
            .diff_refs
            .as_ref()
            .ok_or_else(position_version_conflict)?;
        let merge_request_id = merge_request.id.ok_or_else(position_version_conflict)?;
        let mut page = 1;
        loop {
            let response = self
                .backend
                .merge_request_diff_versions(
                    project_id,
                    GitlabMergeRequestListRequest {
                        iid: merge_request.iid,
                        max_results: GITLAB_MAX_PER_PAGE,
                        page_token: None,
                        page,
                        unidiff: None,
                    },
                    credential,
                )
                .await
                .map_err(gitlab_backend_error)?;
            let next_page = response.value.next_page;
            if let Some(version) = response.value.items.into_iter().find(|version| {
                version.merge_request_id == merge_request_id
                    && Some(version.base_commit_sha.as_str()) == refs.base_sha.as_deref()
                    && version.start_commit_sha == refs.start_sha
                    && version.head_commit_sha == refs.head_sha
            }) {
                return Ok(version);
            }
            page = match next_page {
                Some(next_page) if next_page > page => next_page,
                Some(_) => {
                    return Err(gitlab_backend_error(GitlabBackendError::Protocol(
                        "GitLab diff-version pagination did not advance".to_string(),
                    )));
                }
                None => break,
            };
        }
        Err(position_version_conflict())
    }

    async fn invoke_merge_request_suggestion_apply(
        &self,
        request: ProviderInvocation,
        batch: bool,
    ) -> Result<ProviderResult, ProviderError> {
        let inputs = parse_suggestion_apply_inputs(
            request.inputs(),
            batch,
            self.config.content.max_body_bytes,
        )?;
        let scope_preflight =
            ProviderState::require::<GitlabSuggestionScopePreflight>(request.state())?;
        let lookup_project = self.lookup_project_for_invoke(request.admitted()).await?;
        let credential = &self.execution_credential(&request)?;
        let actor = self
            .backend
            .current_user(credential)
            .await
            .map_err(gitlab_backend_error)?
            .value;
        let _actor_id = required_gitlab_actor_id(&actor)?;
        let (project, merge_request, source_project) = self
            .revalidate_suggestion_scopes(
                &lookup_project,
                scope_preflight,
                inputs.iid,
                &inputs.expected_head_sha,
                request.resource_scopes()?,
                credential,
            )
            .await?;
        self.ensure_suggestions_state(&project, &merge_request, &inputs, credential, false)
            .await?;
        let suggestion_ids = inputs
            .locators
            .iter()
            .map(|locator| locator.suggestion_id)
            .collect::<Vec<_>>();
        let safe = MutationSafeLocators::new().with_suggestion_ids(suggestion_ids.clone());
        let mutation = self
            .backend
            .apply_suggestions(
                GitlabSuggestionApplyRequest {
                    suggestion_ids: suggestion_ids.clone(),
                    commit_message: inputs.commit_message.clone(),
                    batch,
                },
                credential,
            )
            .await;
        let response = match mutation {
            Ok(response) => response,
            Err(GitlabBackendError::NotSent { timed_out }) => {
                return Err(mutation_not_sent(timed_out));
            }
            // Delegated access that could not be presented, or that GitLab
            // rejected, applied nothing: the failure keeps its own reason
            // rather than reading as unverified when the probe below fails
            // the same way.
            Err(GitlabBackendError::Credential(error)) => return Err(error),
            // A write the Broker could not prepare was never sent: it keeps
            // its cause's reason whatever the probe below would find.
            Err(error @ GitlabBackendError::RequestUnbuilt(_)) => {
                return Err(gitlab_backend_error(error));
            }
            Err(error) => {
                let unchanged = self
                    .ensure_suggestions_state(&project, &merge_request, &inputs, credential, false)
                    .await
                    .is_ok();
                if unchanged {
                    return Err(gitlab_backend_error(error));
                }
                return Err(mutation_verification_failed(
                    MutationVerificationStage::MutationReadback,
                    safe,
                ));
            }
        };
        let returned = response
            .value
            .iter()
            .map(|suggestion| suggestion.id)
            .collect::<BTreeSet<_>>();
        let requested = suggestion_ids.iter().copied().collect::<BTreeSet<_>>();
        if returned != requested {
            return Err(mutation_verification_failed(
                MutationVerificationStage::MutationResponse,
                safe,
            ));
        }
        // GitLab updates applied state with update_all and can serialize stale
        // in-memory suggestions. Only fresh scoped discussion reads prove success.
        self.ensure_suggestions_state(&project, &merge_request, &inputs, credential, true)
            .await
            .map_err(|_| {
                mutation_verification_failed(
                    MutationVerificationStage::MutationReadback,
                    safe.clone(),
                )
            })?;
        let operation = if batch {
            "merge_request.suggestion.batch_apply"
        } else {
            "merge_request.suggestion.apply"
        };
        let mut result = gitlab_result(
            operation,
            &project,
            Some(json!({
                "mergeRequest": inputs.iid,
                "sourceProjectId": source_project.id,
                "suggestionIds": suggestion_ids
            })),
            response.status,
            response.duration_ms,
            json!({
                "mutationStatus": "applied",
                "retrySafe": false,
                "suggestionIds": suggestion_ids
            }),
            self.backend.egress_proxy_audit(credential),
        );
        add_gitlab_audit_fields(
            &mut result,
            vec![
                ("mergeRequest", json!(inputs.iid)),
                ("sourceProjectId", json!(source_project.id)),
                ("expectedHeadSha", json!(inputs.expected_head_sha)),
                ("provenHeadSha", json!(merge_request.sha)),
            ],
        );
        Ok(result)
    }

    async fn revalidate_suggestion_scopes(
        &self,
        lookup_project: &GitlabProject,
        scope_preflight: &GitlabSuggestionScopePreflight,
        iid: u64,
        expected_head_sha: &str,
        authorized_scopes: &ResourceScopes,
        credential: &GitlabCredential,
    ) -> Result<(GitlabProject, GitlabMergeRequest, GitlabProject), ProviderError> {
        let project = self
            .backend
            .project(&lookup_project.path_with_namespace, credential)
            .await
            .map_err(gitlab_proof_backend_error)?
            .value;
        ensure_same_project(lookup_project, &project)?;
        if project.id != scope_preflight.target_project_id {
            return Err(suggestion_scope_changed_error());
        }
        let merge_request = self
            .backend
            .merge_request(project.id, iid, credential)
            .await
            .map_err(gitlab_proof_backend_error)?
            .value;
        ensure_merge_request_in_project(&project, &merge_request)?;
        require_matching_merge_request_sha(expected_head_sha, &merge_request)?;
        ensure_merge_request_repository_ids(&project, &merge_request)?;
        let source_project_id = merge_request.source_project_id.ok_or_else(|| {
            ProviderError::deny(
                ReasonCode::ScopeUnresolved,
                "GitLab merge request source project was not found or not permitted",
            )
        })?;
        if source_project_id != scope_preflight.source_project_id {
            return Err(suggestion_scope_changed_error());
        }
        let source_project = if source_project_id == project.id {
            project.clone()
        } else {
            self.backend
                .project(&source_project_id.to_string(), credential)
                .await
                .map_err(gitlab_proof_backend_error)?
                .value
        };
        if source_project.id != source_project_id {
            return Err(ProviderError::deny(
                ReasonCode::ScopeUnresolved,
                "GitLab merge request source project was not found or not permitted",
            ));
        }
        ensure_distinct_project_paths(&project, &source_project)?;
        let observed = repository_scopes_from_projects([&project, &source_project]);
        if &observed != authorized_scopes {
            return Err(suggestion_scope_changed_error());
        }
        Ok((project, merge_request, source_project))
    }

    async fn ensure_suggestions_state(
        &self,
        project: &GitlabProject,
        merge_request: &GitlabMergeRequest,
        inputs: &GitlabSuggestionApplyInputs,
        credential: &GitlabCredential,
        expected_applied: bool,
    ) -> Result<(), ProviderError> {
        for locator in &inputs.locators {
            let discussion = self
                .backend
                .merge_request_discussion(
                    project.id,
                    inputs.iid,
                    &locator.discussion_id,
                    credential,
                )
                .await
                .map_err(gitlab_proof_backend_error)?
                .value;
            ensure_merge_request_discussion_consistent(
                project,
                merge_request,
                &discussion,
                inputs.iid,
                &locator.discussion_id,
                Some(locator.note_id),
                None,
            )?;
            let note = discussion
                .notes
                .iter()
                .find(|note| note.id == locator.note_id)
                .ok_or_else(note_scope_mismatch_error)?;
            let position = note
                .position
                .as_ref()
                .ok_or_else(note_scope_mismatch_error)?;
            if position.head_sha != inputs.expected_head_sha {
                return Err(position_input_invalid(
                    PositionInputCategory::SuggestionOutdated,
                ));
            }
            let suggestion = note
                .suggestions
                .iter()
                .find(|suggestion| suggestion.id == locator.suggestion_id)
                .ok_or_else(note_scope_mismatch_error)?;
            if suggestion.applied != expected_applied
                || (!expected_applied && !suggestion.applicable)
            {
                return Err(position_input_invalid(
                    PositionInputCategory::SuggestionOutdated,
                ));
            }
        }
        Ok(())
    }

    async fn invoke_merge_request_commit_list(
        &self,
        request: ProviderInvocation,
    ) -> Result<ProviderResult, ProviderError> {
        let mut inputs = parse_merge_request_list_inputs(
            request.inputs(),
            self.config.search.max_results,
            "commit list",
            false,
        )?;
        let (project, _) = self.review_read_project(&request, inputs.iid).await?;
        let request_hash = merge_request_collection_request_hash(inputs.iid, inputs.unidiff);
        inputs.page = self.page_from_token(
            inputs.page_token.as_deref(),
            &request,
            &project,
            &request_hash,
            inputs.max_results,
        )?;
        let credential = &self.execution_credential(&request)?;
        let response = self
            .backend
            .merge_request_commits(project.id, inputs.clone(), credential)
            .await
            .map_err(gitlab_backend_error)?;
        self.merge_request_page_result(
            &request,
            &project,
            "commits",
            response.value.items,
            response.value.next_page,
            &request_hash,
            inputs.max_results,
            response.status,
            response.duration_ms,
            credential,
            None,
        )
    }

    async fn invoke_merge_request_pipeline_list(
        &self,
        request: ProviderInvocation,
    ) -> Result<ProviderResult, ProviderError> {
        let mut inputs = parse_merge_request_list_inputs(
            request.inputs(),
            self.config.search.max_results,
            "pipeline list",
            false,
        )?;
        let (project, _) = self.review_read_project(&request, inputs.iid).await?;
        let request_hash = merge_request_collection_request_hash(inputs.iid, inputs.unidiff);
        inputs.page = self.page_from_token(
            inputs.page_token.as_deref(),
            &request,
            &project,
            &request_hash,
            inputs.max_results,
        )?;
        let credential = &self.execution_credential(&request)?;
        let response = self
            .backend
            .merge_request_pipelines(project.id, inputs.clone(), credential)
            .await
            .map_err(gitlab_backend_error)?;
        ensure_pipelines_in_project(&project, &response.value.items)?;
        self.merge_request_page_result(
            &request,
            &project,
            "pipelines",
            response.value.items,
            response.value.next_page,
            &request_hash,
            inputs.max_results,
            response.status,
            response.duration_ms,
            credential,
            None,
        )
    }

    async fn invoke_merge_request_diff_list(
        &self,
        request: ProviderInvocation,
    ) -> Result<ProviderResult, ProviderError> {
        let mut inputs = parse_merge_request_list_inputs(
            request.inputs(),
            self.config.search.max_results,
            "diff list",
            true,
        )?;
        let (project, _) = self.review_read_project(&request, inputs.iid).await?;
        let request_hash = merge_request_collection_request_hash(inputs.iid, inputs.unidiff);
        inputs.page = self.page_from_token(
            inputs.page_token.as_deref(),
            &request,
            &project,
            &request_hash,
            inputs.max_results,
        )?;
        let credential = &self.execution_credential(&request)?;
        let response = self
            .backend
            .merge_request_diffs(project.id, inputs.clone(), credential)
            .await
            .map_err(gitlab_backend_error)?;
        ensure_diff_bodies_within_cap(&response.value.items, self.config.content.max_file_bytes)?;
        self.merge_request_page_result(
            &request,
            &project,
            "diffs",
            response.value.items,
            response.value.next_page,
            &request_hash,
            inputs.max_results,
            response.status,
            response.duration_ms,
            credential,
            None,
        )
    }

    async fn invoke_merge_request_diff_version_list(
        &self,
        request: ProviderInvocation,
    ) -> Result<ProviderResult, ProviderError> {
        let mut inputs = parse_merge_request_list_inputs(
            request.inputs(),
            self.config.search.max_results,
            "diff version list",
            false,
        )?;
        let (project, merge_request) = self.review_read_project(&request, inputs.iid).await?;
        let request_hash = merge_request_collection_request_hash(inputs.iid, inputs.unidiff);
        inputs.page = self.page_from_token(
            inputs.page_token.as_deref(),
            &request,
            &project,
            &request_hash,
            inputs.max_results,
        )?;
        let credential = &self.execution_credential(&request)?;
        let response = self
            .backend
            .merge_request_diff_versions(project.id, inputs.clone(), credential)
            .await
            .map_err(gitlab_backend_error)?;
        ensure_diff_versions_target_merge_request(&merge_request, &response.value.items)?;
        self.merge_request_page_result(
            &request,
            &project,
            "diffVersions",
            response.value.items,
            response.value.next_page,
            &request_hash,
            inputs.max_results,
            response.status,
            response.duration_ms,
            credential,
            None,
        )
    }

    async fn invoke_merge_request_diff_version_view(
        &self,
        request: ProviderInvocation,
    ) -> Result<ProviderResult, ProviderError> {
        let inputs = parse_merge_request_object_inputs(
            request.inputs(),
            "diffVersionId",
            "diff version view",
        )?;
        let project = self.lookup_project_for_invoke(request.admitted()).await?;
        let preflight = self
            .backend
            .merge_request(project.id, inputs.iid, &self.lookup_credential(&request)?)
            .await
            .map_err(gitlab_lookup_backend_error)?;
        ensure_merge_request_in_project(&project, &preflight.value)?;
        let merge_request_id = preflight.value.id.ok_or_else(|| {
            ProviderError::error(
                ReasonCode::UpstreamProtocolFailed,
                "GitLab merge request id was missing",
            )
        })?;
        let credential = &self.execution_credential(&request)?;
        let response = self
            .backend
            .merge_request_diff_version(project.id, inputs.clone(), credential)
            .await
            .map_err(gitlab_backend_error)?;
        if response.value.id != inputs.object_id
            || response.value.merge_request_id != merge_request_id
        {
            return Err(ProviderError::error(
                ReasonCode::UpstreamProtocolFailed,
                "GitLab diff version did not match the requested merge request and version",
            ));
        }
        ensure_diff_bodies_within_cap(&response.value.diffs, self.config.content.max_file_bytes)?;
        Ok(gitlab_result(
            "merge_request.diff_version.view",
            &project,
            Some(json!({ "diffVersion": inputs.object_id })),
            response.status,
            response.duration_ms,
            json!({ "diffVersion": response.value }),
            self.backend.egress_proxy_audit(credential),
        ))
    }

    async fn invoke_merge_request_diff_raw_download(
        &self,
        request: ProviderInvocation,
    ) -> Result<ProviderResult, ProviderError> {
        let inputs = parse_merge_request_subresource_inputs(request.inputs())?;
        let project = self.lookup_project_for_invoke(request.admitted()).await?;
        let lookup = &self.lookup_credential(&request)?;
        let merge_request = self
            .backend
            .merge_request(project.id, inputs.iid, lookup)
            .await
            .map_err(gitlab_lookup_backend_error)?;
        ensure_merge_request_in_project(&project, &merge_request.value)?;
        let head_sha = merge_request
            .value
            .diff_refs
            .as_ref()
            .map(|refs| refs.head_sha.clone())
            .or_else(|| merge_request.value.sha.clone());
        let credential = &self.execution_credential(&request)?;
        let byte_cap = self
            .config
            .content
            .max_raw_download_bytes
            .min(self.limits.max_download_bytes);
        let response = self
            .backend
            .merge_request_raw_diffs(project.id, inputs.iid, byte_cap, credential)
            .await
            .map_err(gitlab_backend_error)?;
        let GitlabRawFile {
            size,
            content_type,
            stream,
        } = response.value;
        validate_gitlab_raw_diff_download_size(size, byte_cap)?;
        let result = json!({
            "project": project.path_with_namespace,
            "projectId": project.id,
            "iid": inputs.iid,
            "headShaAtPreflight": head_sha,
            "contentType": content_type,
            "size": size,
        });
        let stream = if let Some(size) = size {
            stream.with_expected_size(
                size,
                "GitLab raw diff response size did not match Content-Length",
            )
        } else {
            stream
        };
        Ok(ProviderResult::new(result.clone())
            .with_stream(stream)
            .with_audit(json!({
                "gitlab": {
                    "operation": "merge_request.diff.raw.download",
                    "project": project.path_with_namespace,
                    "projectId": project.id,
                    "mergeRequestIid": inputs.iid,
                    "headShaAtPreflight": head_sha,
                    "contentType": result["contentType"],
                    "size": size,
                    "egressProxy": self.backend.egress_proxy_audit(credential),
                }
            }))
            .with_upstream(Some(response.status), Some(response.duration_ms))
            .with_object_ids(json!({
                "mergeRequest": format!("{}!{}", project.path_with_namespace, inputs.iid)
            })))
    }

    async fn review_read_project(
        &self,
        request: &ProviderInvocation,
        iid: u64,
    ) -> Result<(GitlabProject, GitlabMergeRequest), ProviderError> {
        let project = self.lookup_project_for_invoke(request.admitted()).await?;
        let merge_request = self
            .backend
            .merge_request(project.id, iid, &self.lookup_credential(request)?)
            .await
            .map_err(gitlab_lookup_backend_error)?;
        ensure_merge_request_in_project(&project, &merge_request.value)?;
        Ok((project, merge_request.value))
    }

    async fn prepare_review_position(
        &self,
        project_id: u64,
        merge_request: &GitlabMergeRequest,
        expected_head_sha: &str,
        input: &GitlabPositionInput,
        credential: &GitlabCredential,
    ) -> Result<GitlabDiffPosition, ProviderError> {
        require_current_position_triplet(merge_request, expected_head_sha)?;
        let refs = merge_request
            .diff_refs
            .as_ref()
            .expect("validated diff refs");
        let mut position = GitlabDiffPosition {
            position_type: input.position_type.clone(),
            base_sha: refs.base_sha.clone(),
            start_sha: refs.start_sha.clone(),
            head_sha: refs.head_sha.clone(),
            old_path: input.old_path.clone(),
            new_path: input.new_path.clone(),
            old_line: input.old_line,
            new_line: input.new_line,
            line_range: None,
            width: input.width,
            height: input.height,
            x: input.x,
            y: input.y,
        };
        let Some(range) = &input.line_range else {
            return Ok(position);
        };

        let versions = self
            .backend
            .merge_request_diff_versions(
                project_id,
                GitlabMergeRequestListRequest {
                    iid: merge_request.iid,
                    max_results: GITLAB_MAX_PER_PAGE,
                    page_token: None,
                    page: 1,
                    unidiff: None,
                },
                credential,
            )
            .await
            .map_err(gitlab_lookup_backend_error)?;
        let latest = versions
            .value
            .items
            .first()
            .ok_or_else(position_version_conflict)?;
        ensure_current_diff_version(latest, merge_request)?;

        let mut matched = None;
        for page in 1..=10 {
            let response = self
                .backend
                .merge_request_diffs(
                    project_id,
                    GitlabMergeRequestListRequest {
                        iid: merge_request.iid,
                        max_results: GITLAB_MAX_PER_PAGE,
                        page_token: None,
                        page,
                        unidiff: None,
                    },
                    credential,
                )
                .await
                .map_err(gitlab_lookup_backend_error)?;
            ensure_diff_bodies_within_cap(
                &response.value.items,
                self.config.content.max_file_bytes,
            )?;
            for diff in response.value.items {
                if diff.old_path == input.old_path && diff.new_path == input.new_path {
                    if matched.is_some() {
                        return Err(position_input_invalid(
                            PositionInputCategory::CoordinatesUnresolved,
                        ));
                    }
                    matched = Some(diff);
                }
            }
            if response.value.next_page.is_none() {
                break;
            }
            if page == 10 {
                return Err(position_input_invalid(
                    PositionInputCategory::PatchUnavailable,
                ));
            }
        }
        let diff = matched
            .ok_or_else(|| position_input_invalid(PositionInputCategory::PatchUnavailable))?;
        if diff.collapsed == Some(true) || diff.too_large == Some(true) {
            return Err(position_input_invalid(
                PositionInputCategory::PatchUnavailable,
            ));
        }
        let patch = diff
            .diff
            .as_deref()
            .filter(|patch| !patch.is_empty())
            .ok_or_else(|| position_input_invalid(PositionInputCategory::PatchUnavailable))?;
        let canonical_path = if diff.deleted_file == Some(true) {
            &input.old_path
        } else {
            &input.new_path
        };
        let resolved = resolve_multiline_position(patch, range, canonical_path)?;
        position.old_line = resolved.end.old_line;
        position.new_line = resolved.end.new_line;
        position.line_range = Some(resolved);
        Ok(position)
    }

    #[allow(clippy::too_many_arguments)]
    fn merge_request_page_result<T: Serialize>(
        &self,
        request: &ProviderInvocation,
        project: &GitlabProject,
        collection_key: &str,
        items: Vec<T>,
        next_page: Option<u32>,
        request_hash: &str,
        max_results: u32,
        status: u16,
        duration_ms: u64,
        credential: &GitlabCredential,
        projection: Option<GitlabCollectionProjection>,
    ) -> Result<ProviderResult, ProviderError> {
        validate_gitlab_page_count(items.len(), max_results)?;
        let next_page_token =
            self.next_page_token(next_page, request, project, request_hash, max_results)?;
        let count = items.len();
        let is_last = next_page_token.is_none();
        let mut payload = serde_json::Map::new();
        payload.insert(collection_key.to_string(), json!(items));
        payload.insert("count".to_string(), json!(count));
        payload.insert("maxResults".to_string(), json!(max_results));
        payload.insert("isLast".to_string(), json!(is_last));
        payload.insert("nextPageToken".to_string(), json!(next_page_token));
        if let Some(projection) = projection {
            payload.insert("projection".to_string(), json!(projection));
        }
        let mut result = gitlab_result(
            request.action(),
            project,
            None,
            status,
            duration_ms,
            Value::Object(payload),
            self.backend.egress_proxy_audit(credential),
        );
        add_gitlab_audit_fields(
            &mut result,
            vec![("count", json!(count)), ("isLast", json!(is_last))],
        );
        Ok(result)
    }

    async fn invoke_merge_request_discussion_add(
        &self,
        request: ProviderInvocation,
    ) -> Result<ProviderResult, ProviderError> {
        let mut inputs =
            parse_note_add_inputs(request.inputs(), self.config.content.max_body_bytes)?;
        let attribution = self.apply_markdown_attribution(
            "merge_request.discussion.add",
            &mut inputs.body,
            &request,
        );
        enforce_bounded_text_field(
            "body",
            &inputs.body,
            self.config.content.max_body_bytes,
            attribution_audit_applied(attribution.as_ref()),
        )?;
        let project = self.lookup_project_for_invoke(request.admitted()).await?;
        let lookup_credential = &self.lookup_credential(&request)?;
        let merge_request = self
            .backend
            .merge_request(project.id, inputs.iid, lookup_credential)
            .await
            .map_err(gitlab_lookup_backend_error)?;
        ensure_merge_request_in_project(&project, &merge_request.value)?;
        let credential = &self.execution_credential(&request)?;
        let write = PlainWrite::new(
            json!({ "project": project.path_with_namespace, "mergeRequestIid": inputs.iid }),
        );
        let response = self
            .backend
            .create_merge_request_discussion(project.id, inputs.clone(), credential)
            .await
            .map_err(|error| write.failed(error))?;
        ensure_discussion_target_merge_request(&response.value, inputs.iid)
            .map_err(|error| write.unverified(error))?;
        let mut result = gitlab_result_with_request_body_audit(
            "merge_request.discussion.add",
            &project,
            Some(json!({
                "mergeRequest": format!("{}!{}", project.path_with_namespace, merge_request.value.iid),
                "discussion": response.value.id
            })),
            (response.status, response.duration_ms),
            json!({ "discussion": response.value }),
            self.backend.egress_proxy_audit(credential),
            request_body_audit_for_note_create(&inputs),
        );
        add_gitlab_content_write_audit(&mut result, request.inputs(), Some(&inputs.body));
        add_gitlab_attribution_audit(&mut result, attribution);
        Ok(result)
    }

    async fn invoke_merge_request_discussion_note_update(
        &self,
        request: ProviderInvocation,
    ) -> Result<ProviderResult, ProviderError> {
        let inputs = parse_discussion_note_update_inputs(
            request.inputs(),
            self.config.content.max_body_bytes,
        )?;
        enforce_bounded_text_field(
            "body",
            &inputs.body,
            self.config.content.max_body_bytes,
            false,
        )?;
        let project = self.lookup_project_for_invoke(request.admitted()).await?;
        let lookup_credential = &self.lookup_credential(&request)?;
        let merge_request = self
            .backend
            .merge_request(project.id, inputs.iid, lookup_credential)
            .await
            .map_err(gitlab_lookup_backend_error)?;
        ensure_merge_request_in_project(&project, &merge_request.value)?;
        let credential = &self.execution_credential(&request)?;
        let proof = self
            .backend
            .merge_request_discussion(project.id, inputs.iid, &inputs.discussion_id, credential)
            .await
            .map_err(gitlab_proof_backend_error)?;
        ensure_merge_request_discussion_consistent(
            &project,
            &merge_request.value,
            &proof.value,
            inputs.iid,
            &inputs.discussion_id,
            Some(inputs.note_id),
            None,
        )?;
        let write = PlainWrite::new(
            json!({ "project": project.path_with_namespace, "mergeRequestIid": inputs.iid, "discussionId": inputs.discussion_id, "noteId": inputs.note_id }),
        );
        let response = self
            .backend
            .update_merge_request_discussion_note(project.id, inputs.clone(), credential)
            .await
            .map_err(|error| write.failed(error))?;
        ensure_merge_request_note_consistent(
            &project,
            &merge_request.value,
            &response.value,
            inputs.iid,
            inputs.note_id,
        )
        .map_err(|error| write.unverified(error))?;
        let mut result = gitlab_result_with_request_body_audit(
            "merge_request.discussion.note.update",
            &project,
            Some(json!({
                "mergeRequest": format!("{}!{}", project.path_with_namespace, merge_request.value.iid),
                "discussion": inputs.discussion_id,
                "note": response.value.id
            })),
            (response.status, response.duration_ms),
            json!({ "note": response.value }),
            self.backend.egress_proxy_audit(credential),
            request_body_audit_for_discussion_note_update(&inputs),
        );
        add_gitlab_audit_fields(
            &mut result,
            vec![
                ("mergeRequestIid", json!(inputs.iid)),
                ("discussionId", json!(inputs.discussion_id)),
                ("noteId", json!(inputs.note_id)),
            ],
        );
        add_gitlab_content_write_audit(&mut result, request.inputs(), Some(&inputs.body));
        Ok(result)
    }

    async fn invoke_merge_request_discussion_note_delete(
        &self,
        request: ProviderInvocation,
    ) -> Result<ProviderResult, ProviderError> {
        let inputs = parse_discussion_note_delete_inputs(request.inputs())?;
        let project = self.lookup_project_for_invoke(request.admitted()).await?;
        let lookup_credential = &self.lookup_credential(&request)?;
        let merge_request = self
            .backend
            .merge_request(project.id, inputs.iid, lookup_credential)
            .await
            .map_err(gitlab_lookup_backend_error)?;
        ensure_merge_request_in_project(&project, &merge_request.value)?;
        let credential = &self.execution_credential(&request)?;
        let proof = self
            .backend
            .merge_request_discussion(project.id, inputs.iid, &inputs.discussion_id, credential)
            .await
            .map_err(gitlab_proof_backend_error)?;
        ensure_merge_request_discussion_consistent(
            &project,
            &merge_request.value,
            &proof.value,
            inputs.iid,
            &inputs.discussion_id,
            Some(inputs.note_id),
            None,
        )?;
        let write = PlainWrite::new(
            json!({ "project": project.path_with_namespace, "mergeRequestIid": inputs.iid, "discussionId": inputs.discussion_id, "noteId": inputs.note_id }),
        );
        let response = self
            .backend
            .delete_merge_request_discussion_note(project.id, inputs.clone(), credential)
            .await
            .map_err(|error| write.failed(error))?;
        let mut result = gitlab_result(
            "merge_request.discussion.note.delete",
            &project,
            Some(json!({
                "mergeRequest": format!("{}!{}", project.path_with_namespace, merge_request.value.iid),
                "discussion": inputs.discussion_id,
                "note": inputs.note_id
            })),
            response.status,
            response.duration_ms,
            json!({
                "deleted": true,
                "project": project.path_with_namespace,
                "iid": inputs.iid,
                "discussionId": inputs.discussion_id,
                "noteId": inputs.note_id
            }),
            self.backend.egress_proxy_audit(credential),
        );
        add_gitlab_audit_fields(
            &mut result,
            vec![
                ("mergeRequestIid", json!(inputs.iid)),
                ("discussionId", json!(inputs.discussion_id)),
                ("noteId", json!(inputs.note_id)),
            ],
        );
        Ok(result)
    }

    async fn invoke_merge_request_discussion_state_change(
        &self,
        request: ProviderInvocation,
        change: GitlabDiscussionStateChange,
    ) -> Result<ProviderResult, ProviderError> {
        let inputs = parse_discussion_state_change_inputs(request.inputs(), change)?;
        let project = self.lookup_project_for_invoke(request.admitted()).await?;
        let lookup_credential = &self.lookup_credential(&request)?;
        let merge_request = self
            .backend
            .merge_request(project.id, inputs.iid, lookup_credential)
            .await
            .map_err(gitlab_lookup_backend_error)?;
        ensure_merge_request_in_project(&project, &merge_request.value)?;
        let credential = &self.execution_credential(&request)?;
        let write = PlainWrite::new(
            json!({ "project": project.path_with_namespace, "mergeRequestIid": inputs.iid, "discussionId": inputs.discussion_id }),
        );
        let response = self
            .backend
            .set_merge_request_discussion_resolved(project.id, inputs.clone(), credential)
            .await
            .map_err(|error| write.failed(error))?;
        ensure_merge_request_discussion_consistent(
            &project,
            &merge_request.value,
            &response.value,
            inputs.iid,
            &inputs.discussion_id,
            None,
            Some(inputs.change.resolved()),
        )
        .map_err(|error| write.unverified(error))?;
        let operation = inputs.change.operation();
        let mut result = gitlab_result(
            operation,
            &project,
            Some(json!({
                "mergeRequest": format!("{}!{}", project.path_with_namespace, merge_request.value.iid),
                "discussion": inputs.discussion_id
            })),
            response.status,
            response.duration_ms,
            json!({ "discussion": response.value }),
            self.backend.egress_proxy_audit(credential),
        );
        add_gitlab_audit_fields(
            &mut result,
            vec![
                ("mergeRequestIid", json!(inputs.iid)),
                ("discussionId", json!(inputs.discussion_id)),
                ("resolved", json!(inputs.change.resolved())),
            ],
        );
        Ok(result)
    }

    async fn invoke_merge_request_merge(
        &self,
        request: ProviderInvocation,
    ) -> Result<ProviderResult, ProviderError> {
        let inputs =
            parse_merge_request_merge_inputs(request.inputs(), self.config.content.max_body_bytes)?;
        let project = self.lookup_project_for_invoke(request.admitted()).await?;
        let lookup_credential = &self.lookup_credential(&request)?;
        let existing = self
            .backend
            .merge_request(project.id, inputs.iid, lookup_credential)
            .await
            .map_err(gitlab_lookup_backend_error)?
            .value;
        ensure_merge_request_in_project(&project, &existing)?;
        require_matching_merge_request_sha(&inputs.sha, &existing)?;
        let credential = &self.execution_credential(&request)?;
        let write = PlainWrite::new(
            json!({ "project": project.path_with_namespace, "mergeRequestIid": inputs.iid }),
        );
        let response = self
            .backend
            .merge_merge_request(project.id, inputs.clone(), credential)
            .await
            .map_err(|error| gitlab_merge_backend_error(&write, error))?;
        let mut merged = response.value;
        ensure_merge_request_in_project(&project, &merged)
            .map_err(|error| write.unverified(error))?;
        let request_body_audit =
            request_body_audit_for_merge_request_merge(&inputs, &existing, &merged);
        merged.description = None;
        Ok(gitlab_result_with_request_body_audit(
            "merge_request.merge",
            &project,
            Some(
                json!({ "mergeRequest": format!("{}!{}", project.path_with_namespace, merged.iid) }),
            ),
            (response.status, response.duration_ms),
            json!({ "mergeRequest": merged.with_project(&project) }),
            self.backend.egress_proxy_audit(credential),
            request_body_audit,
        ))
    }

    async fn invoke_branch_list(
        &self,
        request: ProviderInvocation,
    ) -> Result<ProviderResult, ProviderError> {
        let inputs = parse_branch_list_inputs(request.inputs())?;
        let project = self.lookup_project_for_invoke(request.admitted()).await?;
        let credential = &self.execution_credential(&request)?;
        let response = self
            .backend
            .branches(
                project.id,
                GitlabBranchListRequest {
                    search: inputs.search,
                    regex: inputs.regex,
                    max_results: capped_max_results(
                        inputs.max_results,
                        self.config.search.max_results,
                    )?,
                },
                credential,
            )
            .await
            .map_err(gitlab_backend_error)?;
        Ok(gitlab_result(
            "branch.list",
            &project,
            None,
            response.status,
            response.duration_ms,
            json!({ "branches": response.value }),
            self.backend.egress_proxy_audit(credential),
        ))
    }

    async fn invoke_branch_view(
        &self,
        request: ProviderInvocation,
    ) -> Result<ProviderResult, ProviderError> {
        let inputs = parse_branch_view_inputs(request.inputs())?;
        let project = self.lookup_project_for_invoke(request.admitted()).await?;
        let credential = &self.execution_credential(&request)?;
        let response = self
            .backend
            .branch(project.id, &inputs.branch, credential)
            .await
            .map_err(gitlab_backend_error)?;
        Ok(gitlab_result(
            "branch.view",
            &project,
            Some(
                json!({ "branch": format!("{}:refs/heads/{}", project.path_with_namespace, response.value.name) }),
            ),
            response.status,
            response.duration_ms,
            json!({ "branch": response.value }),
            self.backend.egress_proxy_audit(credential),
        ))
    }

    async fn invoke_branch_create(
        &self,
        request: ProviderInvocation,
    ) -> Result<ProviderResult, ProviderError> {
        let inputs = parse_branch_create_inputs(request.inputs())?;
        let project = self.lookup_project_for_invoke(request.admitted()).await?;
        let lookup_credential = &self.lookup_credential(&request)?;
        self.ensure_source_ref_exists(project.id, &inputs.ref_name, lookup_credential)
            .await?;
        let safety = self
            .ensure_branch_write_allowed(&project, &inputs.branch, lookup_credential)
            .await?;
        ensure_branch_absent(
            self.backend.as_ref(),
            project.id,
            &inputs.branch,
            lookup_credential,
        )
        .await?;
        let credential = &self.execution_credential(&request)?;
        let write = PlainWrite::new(
            json!({ "project": project.path_with_namespace, "branch": inputs.branch }),
        );
        let response = self
            .backend
            .create_branch(project.id, inputs.clone(), credential)
            .await
            .map_err(|error| write.failed(error))?;
        Ok(gitlab_result_with_request_body_audit(
            "branch.create",
            &project,
            Some(json!({
                "branch": format!("{}:refs/heads/{}", project.path_with_namespace, response.value.name)
            })),
            (response.status, response.duration_ms),
            json!({ "branch": response.value }),
            self.backend.egress_proxy_audit(credential),
            branch_write_audit(&inputs.branch, Some(&inputs.ref_name), &safety),
        ))
    }

    async fn invoke_protected_branch_list(
        &self,
        request: ProviderInvocation,
    ) -> Result<ProviderResult, ProviderError> {
        let inputs = parse_protected_branch_list_inputs(request.inputs())?;
        let display_max = capped_max_results(inputs.max_results, self.config.search.max_results)?;
        let project = self.lookup_project_for_invoke(request.admitted()).await?;
        let credential = &self.execution_credential(&request)?;
        let response = self
            .backend
            .protected_branches(
                project.id,
                GitlabProtectedBranchListRequest {
                    search: inputs.search,
                    max_results: self.config.search.max_results,
                    fail_on_next_page: false,
                },
                credential,
            )
            .await
            .map_err(gitlab_backend_error)?;
        let mut protected_branches = response.value;
        protected_branches.truncate(display_max as usize);
        Ok(gitlab_result(
            "protected_branch.list",
            &project,
            None,
            response.status,
            response.duration_ms,
            json!({ "protectedBranches": protected_branches }),
            self.backend.egress_proxy_audit(credential),
        ))
    }

    async fn invoke_protected_branch_view(
        &self,
        request: ProviderInvocation,
    ) -> Result<ProviderResult, ProviderError> {
        let inputs = parse_protected_branch_view_inputs(request.inputs())?;
        let project = self.lookup_project_for_invoke(request.admitted()).await?;
        let credential = &self.execution_credential(&request)?;
        let response = self
            .backend
            .protected_branch(project.id, &inputs.name, credential)
            .await
            .map_err(gitlab_backend_error)?;
        Ok(gitlab_result(
            "protected_branch.view",
            &project,
            Some(
                json!({ "protectedBranch": gitlab_protected_branch_object_id(&project, &response.value.name) }),
            ),
            response.status,
            response.duration_ms,
            json!({ "protectedBranch": response.value }),
            self.backend.egress_proxy_audit(credential),
        ))
    }

    async fn invoke_protected_branch_verify(
        &self,
        request: ProviderInvocation,
    ) -> Result<ProviderResult, ProviderError> {
        let inputs = parse_protected_branch_verify_inputs(request.inputs())?;
        let project = self.lookup_project_for_invoke(request.admitted()).await?;
        let credential = &self.execution_credential(&request)?;
        let response = self
            .backend
            .protected_branches(
                project.id,
                GitlabProtectedBranchListRequest {
                    search: None,
                    max_results: 100,
                    fail_on_next_page: true,
                },
                credential,
            )
            .await
            .map_err(gitlab_backend_error)?;
        let verification =
            protected_branch_verification(&project, &response.value, inputs.required_patterns);
        Ok(gitlab_result(
            "protected_branch.verify",
            &project,
            None,
            response.status,
            response.duration_ms,
            json!({ "protectedBranchVerification": verification }),
            self.backend.egress_proxy_audit(credential),
        ))
    }

    async fn invoke_file_view(
        &self,
        request: ProviderInvocation,
    ) -> Result<ProviderResult, ProviderError> {
        let inputs = parse_file_view_inputs(request.inputs())?;
        let project = self.lookup_project_for_invoke(request.admitted()).await?;
        let credential = &self.execution_credential(&request)?;
        let response = self
            .backend
            .file(
                project.id,
                GitlabFileRequest {
                    path: inputs.path.clone(),
                    ref_name: inputs.ref_name.clone(),
                },
                credential,
            )
            .await
            .map_err(gitlab_backend_error)?;
        ensure_file_path_matches(&inputs.path, &response.value)?;
        let result_file = gitlab_file_inline_result(
            response.value,
            self.config.content.max_file_bytes,
            self.limits.max_upstream_response_bytes,
        )?;
        Ok(gitlab_result(
            "file.view",
            &project,
            Some(json!({
                "file": format!("{}:{}:{}", project.path_with_namespace, inputs.ref_name, inputs.path)
            })),
            response.status,
            response.duration_ms,
            json!({ "file": result_file }),
            self.backend.egress_proxy_audit(credential),
        ))
    }

    async fn invoke_file_raw_download(
        &self,
        request: ProviderInvocation,
    ) -> Result<ProviderResult, ProviderError> {
        let inputs = parse_file_view_inputs(request.inputs())?;
        let project = self.lookup_project_for_invoke(request.admitted()).await?;
        let lookup_credential = &self.lookup_credential(&request)?;
        let metadata = self
            .backend
            .file(
                project.id,
                GitlabFileRequest {
                    path: inputs.path.clone(),
                    ref_name: inputs.ref_name.clone(),
                },
                lookup_credential,
            )
            .await
            .map_err(gitlab_lookup_backend_error)?
            .value;
        ensure_file_path_matches(&inputs.path, &metadata)?;
        validate_gitlab_raw_download_size(
            metadata.size,
            self.config.content.max_raw_download_bytes,
        )?;
        let resolved_ref = required_file_commit_id(&metadata)?;
        let credential = &self.execution_credential(&request)?;
        let response = self
            .backend
            .raw_file(
                project.id,
                GitlabFileRequest {
                    path: inputs.path.clone(),
                    ref_name: resolved_ref.clone(),
                },
                self.config
                    .content
                    .max_raw_download_bytes
                    .min(self.limits.max_download_bytes),
                credential,
            )
            .await
            .map_err(gitlab_backend_error)?;
        if response
            .value
            .size
            .is_some_and(|size| size > self.config.content.max_raw_download_bytes)
        {
            return Err(ProviderError::deny(
                ReasonCode::AttachmentSizeDenied,
                "GitLab raw file download exceeded the configured byte cap",
            ));
        }
        let mut result = json!({
            "project": project.path_with_namespace,
            "projectId": project.id,
            "path": metadata.file_path,
            "ref": inputs.ref_name,
            "resolvedRef": resolved_ref,
            "contentType": response.value.content_type,
            "size": metadata.size,
        });
        if let Some(sha256) = metadata.content_sha256.clone() {
            result["sha256"] = json!(sha256);
        }
        let stream = response.value.stream.with_expected_size(
            metadata.size,
            "GitLab raw file response size did not match metadata",
        );
        let audit = json!({
            "gitlab": {
                "operation": "file.raw.download",
                "project": project.path_with_namespace,
                "namespace": project.path_with_namespace.split('/').next().unwrap_or(""),
                "projectId": project.id,
                "path": result["path"],
                "ref": result["ref"],
                "resolvedRef": result["resolvedRef"],
                "contentType": result["contentType"],
                "size": metadata.size,
                "sha256": metadata.content_sha256,
                "egressProxy": self.backend.egress_proxy_audit(credential),
            }
        });
        Ok(ProviderResult::new(result).with_stream(stream).with_audit(audit).with_upstream(Some(response.status), Some(response.duration_ms)).with_object_ids(json!({
                "file": format!("{}:{}:{}", project.path_with_namespace, inputs.ref_name, inputs.path)
            })))
    }

    async fn invoke_file_create(
        &self,
        request: ProviderInvocation,
    ) -> Result<ProviderResult, ProviderError> {
        let inputs = parse_file_create_inputs(
            request.inputs(),
            self.config.content.max_body_bytes,
            self.config.content.max_file_bytes,
        )?;
        let project = self.lookup_project_for_invoke(request.admitted()).await?;
        let lookup_credential = &self.lookup_credential(&request)?;
        let safety = self
            .ensure_branch_write_allowed(&project, &inputs.branch, lookup_credential)
            .await?;
        ensure_optional_start_branch(
            self.backend.as_ref(),
            project.id,
            inputs.start_branch.as_deref(),
            lookup_credential,
        )
        .await?;
        let preflight_ref =
            file_mutation_preflight_ref(&inputs.branch, inputs.start_branch.as_deref(), &safety);
        ensure_file_absent(
            self.backend.as_ref(),
            project.id,
            &inputs.path,
            preflight_ref,
            lookup_credential,
        )
        .await?;
        let credential = &self.execution_credential(&request)?;
        let write = PlainWrite::new(
            json!({ "project": project.path_with_namespace, "branch": inputs.branch, "path": inputs.path }),
        );
        let response = self
            .backend
            .create_file(project.id, inputs.clone(), credential)
            .await
            .map_err(|error| write.failed(error))?;
        Ok(gitlab_result_with_request_body_audit(
            "file.create",
            &project,
            Some(json!({
                "file": format!("{}:{}:{}", project.path_with_namespace, response.value.branch, response.value.file_path)
            })),
            (response.status, response.duration_ms),
            json!({ "file": response.value }),
            self.backend.egress_proxy_audit(credential),
            file_mutation_audit(&inputs, &safety),
        ))
    }

    async fn invoke_file_update(
        &self,
        request: ProviderInvocation,
    ) -> Result<ProviderResult, ProviderError> {
        let inputs = parse_file_update_inputs(
            request.inputs(),
            self.config.content.max_body_bytes,
            self.config.content.max_file_bytes,
        )?;
        let project = self.lookup_project_for_invoke(request.admitted()).await?;
        let lookup_credential = &self.lookup_credential(&request)?;
        let safety = self
            .ensure_branch_write_allowed(&project, &inputs.branch, lookup_credential)
            .await?;
        ensure_optional_start_branch(
            self.backend.as_ref(),
            project.id,
            inputs.start_branch.as_deref(),
            lookup_credential,
        )
        .await?;
        let preflight_ref =
            file_mutation_preflight_ref(&inputs.branch, inputs.start_branch.as_deref(), &safety);
        let existing = self
            .backend
            .file(
                project.id,
                GitlabFileRequest {
                    path: inputs.path.clone(),
                    ref_name: preflight_ref.to_string(),
                },
                lookup_credential,
            )
            .await
            .map_err(gitlab_lookup_backend_error)?
            .value;
        ensure_file_path_matches(&inputs.path, &existing)?;
        require_matching_last_commit_id(inputs.last_commit_id.as_deref(), &existing)?;
        let credential = &self.execution_credential(&request)?;
        let write = PlainWrite::new(
            json!({ "project": project.path_with_namespace, "branch": inputs.branch, "path": inputs.path }),
        );
        let response = self
            .backend
            .update_file(project.id, inputs.clone(), credential)
            .await
            .map_err(|error| write.failed(error))?;
        Ok(gitlab_result_with_request_body_audit(
            "file.update",
            &project,
            Some(json!({
                "file": format!("{}:{}:{}", project.path_with_namespace, response.value.branch, response.value.file_path)
            })),
            (response.status, response.duration_ms),
            json!({ "file": response.value }),
            self.backend.egress_proxy_audit(credential),
            file_mutation_audit(&inputs, &safety),
        ))
    }

    async fn invoke_file_delete(
        &self,
        request: ProviderInvocation,
    ) -> Result<ProviderResult, ProviderError> {
        let inputs =
            parse_file_delete_inputs(request.inputs(), self.config.content.max_body_bytes)?;
        let project = self.lookup_project_for_invoke(request.admitted()).await?;
        let lookup_credential = &self.lookup_credential(&request)?;
        let safety = self
            .ensure_branch_write_allowed(&project, &inputs.branch, lookup_credential)
            .await?;
        ensure_optional_start_branch(
            self.backend.as_ref(),
            project.id,
            inputs.start_branch.as_deref(),
            lookup_credential,
        )
        .await?;
        let preflight_ref =
            file_mutation_preflight_ref(&inputs.branch, inputs.start_branch.as_deref(), &safety);
        let existing = self
            .backend
            .file(
                project.id,
                GitlabFileRequest {
                    path: inputs.path.clone(),
                    ref_name: preflight_ref.to_string(),
                },
                lookup_credential,
            )
            .await
            .map_err(gitlab_lookup_backend_error)?
            .value;
        ensure_file_path_matches(&inputs.path, &existing)?;
        require_matching_last_commit_id(inputs.last_commit_id.as_deref(), &existing)?;
        let credential = &self.execution_credential(&request)?;
        let write = PlainWrite::new(
            json!({ "project": project.path_with_namespace, "branch": inputs.branch, "path": inputs.path }),
        );
        let response = self
            .backend
            .delete_file(project.id, inputs.clone(), credential)
            .await
            .map_err(|error| write.failed(error))?;
        Ok(gitlab_result_with_request_body_audit(
            "file.delete",
            &project,
            Some(json!({
                "file": format!("{}:{}:{}", project.path_with_namespace, response.value.branch, response.value.file_path)
            })),
            (response.status, response.duration_ms),
            json!({ "file": response.value }),
            self.backend.egress_proxy_audit(credential),
            file_delete_audit(&inputs, &safety),
        ))
    }

    async fn invoke_commit_list(
        &self,
        request: ProviderInvocation,
    ) -> Result<ProviderResult, ProviderError> {
        let inputs = parse_commit_list_inputs(request.inputs())?;
        let project = self.lookup_project_for_invoke(request.admitted()).await?;
        let credential = &self.execution_credential(&request)?;
        let response = self
            .backend
            .commits(
                project.id,
                GitlabCommitListRequest {
                    ref_name: inputs.ref_name,
                    path: inputs.path,
                    since: inputs.since,
                    until: inputs.until,
                    first_parent: inputs.first_parent,
                    max_results: capped_max_results(
                        inputs.max_results,
                        self.config.search.max_results,
                    )?,
                },
                credential,
            )
            .await
            .map_err(gitlab_backend_error)?;
        Ok(gitlab_result(
            "commit.list",
            &project,
            None,
            response.status,
            response.duration_ms,
            json!({ "commits": response.value }),
            self.backend.egress_proxy_audit(credential),
        ))
    }

    async fn invoke_commit_view(
        &self,
        request: ProviderInvocation,
    ) -> Result<ProviderResult, ProviderError> {
        let inputs = parse_commit_view_inputs(request.inputs())?;
        let project = self.lookup_project_for_invoke(request.admitted()).await?;
        let credential = &self.execution_credential(&request)?;
        let response = self
            .backend
            .commit(project.id, &inputs.sha, credential)
            .await
            .map_err(gitlab_backend_error)?;
        Ok(gitlab_result(
            "commit.view",
            &project,
            Some(
                json!({ "commit": format!("{}@{}", project.path_with_namespace, response.value.id) }),
            ),
            response.status,
            response.duration_ms,
            json!({ "commit": response.value }),
            self.backend.egress_proxy_audit(credential),
        ))
    }

    async fn invoke_commit_create(
        &self,
        request: ProviderInvocation,
    ) -> Result<ProviderResult, ProviderError> {
        let inputs = parse_commit_create_inputs(
            request.inputs(),
            self.config.content.max_body_bytes,
            self.config.content.max_file_bytes,
            self.config.content.max_commit_actions,
        )?;
        let project = self.lookup_project_for_invoke(request.admitted()).await?;
        let lookup_credential = &self.lookup_credential(&request)?;
        let safety = self
            .ensure_branch_write_allowed(&project, &inputs.branch, lookup_credential)
            .await?;
        ensure_commit_start_ref(
            self.backend.as_ref(),
            project.id,
            &inputs.branch,
            inputs.start_branch.as_deref(),
            inputs.start_sha.as_deref(),
            lookup_credential,
        )
        .await?;
        let preflight_ref = commit_action_preflight_ref(
            &inputs.branch,
            inputs.start_branch.as_deref(),
            inputs.start_sha.as_deref(),
            &safety,
        );
        validate_commit_action_preconditions(
            self.backend.as_ref(),
            project.id,
            preflight_ref,
            &inputs.actions,
            lookup_credential,
        )
        .await?;
        let credential = &self.execution_credential(&request)?;
        let write = PlainWrite::new(
            json!({ "project": project.path_with_namespace, "branch": inputs.branch }),
        );
        let response = self
            .backend
            .create_commit(project.id, inputs.clone(), credential)
            .await
            .map_err(|error| write.failed(error))?;
        Ok(gitlab_result_with_request_body_audit(
            "commit.create",
            &project,
            Some(json!({
                "commit": format!("{}@{}", project.path_with_namespace, response.value.id)
            })),
            (response.status, response.duration_ms),
            json!({ "commit": response.value }),
            self.backend.egress_proxy_audit(credential),
            commit_create_audit(&inputs, &safety),
        ))
    }

    async fn invoke_pipeline_list(
        &self,
        request: ProviderInvocation,
    ) -> Result<ProviderResult, ProviderError> {
        let inputs = parse_pipeline_list_inputs(request.inputs())?;
        let project = self.lookup_project_for_invoke(request.admitted()).await?;
        let credential = &self.execution_credential(&request)?;
        let response = self
            .backend
            .pipelines(
                project.id,
                GitlabPipelineListRequest {
                    ref_name: inputs.ref_name,
                    sha: inputs.sha,
                    status: inputs.status,
                    source: inputs.source,
                    updated_after: inputs.updated_after,
                    updated_before: inputs.updated_before,
                    max_results: capped_max_results(
                        inputs.max_results,
                        self.config.search.max_results,
                    )?,
                },
                credential,
            )
            .await
            .map_err(gitlab_backend_error)?;
        ensure_pipelines_in_project(&project, &response.value)?;
        Ok(gitlab_result(
            "pipeline.list",
            &project,
            None,
            response.status,
            response.duration_ms,
            json!({ "pipelines": response.value }),
            self.backend.egress_proxy_audit(credential),
        ))
    }

    async fn invoke_pipeline_view(
        &self,
        request: ProviderInvocation,
    ) -> Result<ProviderResult, ProviderError> {
        let inputs = parse_pipeline_object_inputs(request.inputs())?;
        let project = self.lookup_project_for_invoke(request.admitted()).await?;
        let credential = &self.execution_credential(&request)?;
        let response = self
            .backend
            .pipeline(project.id, inputs.pipeline_id, credential)
            .await
            .map_err(gitlab_backend_error)?;
        ensure_pipeline_in_project(&project, &response.value)?;
        Ok(gitlab_result(
            "pipeline.view",
            &project,
            Some(json!({ "pipeline": gitlab_pipeline_object_id(&project, response.value.id) })),
            response.status,
            response.duration_ms,
            json!({ "pipeline": response.value }),
            self.backend.egress_proxy_audit(credential),
        ))
    }

    async fn invoke_pipeline_run(
        &self,
        request: ProviderInvocation,
    ) -> Result<ProviderResult, ProviderError> {
        let inputs = parse_pipeline_run_inputs(request.inputs())?;
        let project = self.lookup_project_for_invoke(request.admitted()).await?;
        let lookup_credential = &self.lookup_credential(&request)?;
        let safety = self
            .ensure_ci_ref_execution_allowed(&project, &inputs.ref_name, lookup_credential)
            .await?;
        let credential = &self.execution_credential(&request)?;
        let write = PlainWrite::new(
            json!({ "project": project.path_with_namespace, "ref": inputs.ref_name }),
        );
        let response = self
            .backend
            .run_pipeline(project.id, inputs.clone(), credential)
            .await
            .map_err(|error| write.failed(error))?;
        ensure_pipeline_in_project(&project, &response.value)
            .map_err(|error| write.unverified(error))?;
        Ok(gitlab_result_with_request_body_audit(
            "pipeline.run",
            &project,
            Some(json!({ "pipeline": gitlab_pipeline_object_id(&project, response.value.id) })),
            (response.status, response.duration_ms),
            json!({ "pipeline": response.value }),
            self.backend.egress_proxy_audit(credential),
            ci_ref_audit(&inputs.ref_name, &safety),
        ))
    }

    async fn invoke_pipeline_retry(
        &self,
        request: ProviderInvocation,
    ) -> Result<ProviderResult, ProviderError> {
        self.invoke_pipeline_state_change(
            request,
            "pipeline.retry",
            GitlabPipelineStateChange::Retry,
        )
        .await
    }

    async fn invoke_pipeline_cancel(
        &self,
        request: ProviderInvocation,
    ) -> Result<ProviderResult, ProviderError> {
        self.invoke_pipeline_state_change(
            request,
            "pipeline.cancel",
            GitlabPipelineStateChange::Cancel,
        )
        .await
    }

    async fn invoke_pipeline_state_change(
        &self,
        request: ProviderInvocation,
        operation: &'static str,
        change: GitlabPipelineStateChange,
    ) -> Result<ProviderResult, ProviderError> {
        let inputs = parse_pipeline_object_inputs(request.inputs())?;
        let project = self.lookup_project_for_invoke(request.admitted()).await?;
        let lookup_credential = &self.lookup_credential(&request)?;
        let existing = self
            .backend
            .pipeline(project.id, inputs.pipeline_id, lookup_credential)
            .await
            .map_err(gitlab_lookup_backend_error)?
            .value;
        ensure_pipeline_in_project(&project, &existing)?;
        let credential = &self.execution_credential(&request)?;
        let write = PlainWrite::new(
            json!({ "project": project.path_with_namespace, "pipelineId": inputs.pipeline_id }),
        );
        let response = match change {
            GitlabPipelineStateChange::Retry => {
                self.backend
                    .retry_pipeline(project.id, inputs.pipeline_id, credential)
                    .await
            }
            GitlabPipelineStateChange::Cancel => {
                self.backend
                    .cancel_pipeline(project.id, inputs.pipeline_id, credential)
                    .await
            }
        }
        .map_err(|error| write.failed(error))?;
        ensure_pipeline_in_project(&project, &response.value)
            .map_err(|error| write.unverified(error))?;
        Ok(gitlab_result(
            operation,
            &project,
            Some(json!({ "pipeline": gitlab_pipeline_object_id(&project, response.value.id) })),
            response.status,
            response.duration_ms,
            json!({ "pipeline": response.value }),
            self.backend.egress_proxy_audit(credential),
        ))
    }

    async fn invoke_job_list(
        &self,
        request: ProviderInvocation,
    ) -> Result<ProviderResult, ProviderError> {
        let inputs = parse_job_list_inputs(request.inputs())?;
        let project = self.lookup_project_for_invoke(request.admitted()).await?;
        if let Some(pipeline_id) = inputs.pipeline_id {
            let lookup_credential = &self.lookup_credential(&request)?;
            let pipeline = self
                .backend
                .pipeline(project.id, pipeline_id, lookup_credential)
                .await
                .map_err(gitlab_lookup_backend_error)?
                .value;
            ensure_pipeline_in_project(&project, &pipeline)?;
        }
        let credential = &self.execution_credential(&request)?;
        let response = self
            .backend
            .jobs(
                project.id,
                GitlabJobListRequest {
                    pipeline_id: inputs.pipeline_id,
                    scope: inputs.scope,
                    max_results: capped_max_results(
                        inputs.max_results,
                        self.config.search.max_results,
                    )?,
                },
                credential,
            )
            .await
            .map_err(gitlab_backend_error)?;
        ensure_jobs_in_project(&project, &response.value)?;
        Ok(gitlab_result(
            "job.list",
            &project,
            None,
            response.status,
            response.duration_ms,
            json!({ "jobs": response.value }),
            self.backend.egress_proxy_audit(credential),
        ))
    }

    async fn invoke_job_view(
        &self,
        request: ProviderInvocation,
    ) -> Result<ProviderResult, ProviderError> {
        let inputs = parse_job_object_inputs(request.inputs())?;
        let project = self.lookup_project_for_invoke(request.admitted()).await?;
        let credential = &self.execution_credential(&request)?;
        let response = self
            .backend
            .job(project.id, inputs.job_id, credential)
            .await
            .map_err(gitlab_backend_error)?;
        ensure_job_in_project(&project, &response.value)?;
        Ok(gitlab_result(
            "job.view",
            &project,
            Some(json!({ "job": gitlab_job_object_id(&project, response.value.id) })),
            response.status,
            response.duration_ms,
            json!({ "job": response.value }),
            self.backend.egress_proxy_audit(credential),
        ))
    }

    async fn invoke_job_trace_download(
        &self,
        request: ProviderInvocation,
    ) -> Result<ProviderResult, ProviderError> {
        let inputs = parse_job_object_inputs(request.inputs())?;
        let project = self.lookup_project_for_invoke(request.admitted()).await?;
        let lookup_credential = &self.lookup_credential(&request)?;
        let metadata = self
            .backend
            .job(project.id, inputs.job_id, lookup_credential)
            .await
            .map_err(gitlab_lookup_backend_error)?
            .value;
        ensure_job_in_project(&project, &metadata)?;
        if let Some(trace_size) = metadata.trace_size {
            validate_gitlab_job_trace_download_size(
                trace_size,
                self.config.content.max_raw_download_bytes,
            )?;
        }
        let credential = &self.execution_credential(&request)?;
        let response = self
            .backend
            .job_trace(
                project.id,
                inputs.job_id,
                self.config
                    .content
                    .max_raw_download_bytes
                    .min(self.limits.max_download_bytes),
                credential,
            )
            .await
            .map_err(gitlab_backend_error)?;
        if response
            .value
            .size
            .is_some_and(|size| size > self.config.content.max_raw_download_bytes)
        {
            return Err(ProviderError::deny(
                ReasonCode::AttachmentSizeDenied,
                "GitLab job trace download exceeded the configured byte cap",
            ));
        }
        let size = metadata.trace_size.or(response.value.size).ok_or_else(|| {
            ProviderError::error(
                ReasonCode::UpstreamProtocolFailed,
                "GitLab job trace metadata did not include size",
            )
        })?;
        validate_gitlab_job_trace_download_size(size, self.config.content.max_raw_download_bytes)?;
        let stream = response.value.stream.with_expected_size(
            size,
            "GitLab job trace response size did not match metadata",
        );
        let result = json!({
            "project": project.path_with_namespace,
            "projectId": project.id,
            "jobId": metadata.id,
            "pipelineId": metadata.pipeline_id,
            "ref": metadata.ref_name,
            "contentType": response.value.content_type,
            "size": size,
        });
        let audit = json!({
            "gitlab": {
                "operation": "job.trace.download",
                "project": project.path_with_namespace,
                "namespace": project.path_with_namespace.split('/').next().unwrap_or(""),
                "projectId": project.id,
                "jobId": metadata.id,
                "pipelineId": metadata.pipeline_id,
                "ref": metadata.ref_name,
                "contentType": response.value.content_type,
                "size": size,
                "egressProxy": self.backend.egress_proxy_audit(credential),
            }
        });
        Ok(ProviderResult::new(result)
            .with_stream(stream)
            .with_audit(audit)
            .with_upstream(Some(response.status), Some(response.duration_ms))
            .with_object_ids(json!({ "job": gitlab_job_object_id(&project, metadata.id) })))
    }

    async fn invoke_job_retry(
        &self,
        request: ProviderInvocation,
    ) -> Result<ProviderResult, ProviderError> {
        self.invoke_job_state_change(request, "job.retry", GitlabJobStateChange::Retry)
            .await
    }

    async fn invoke_job_cancel(
        &self,
        request: ProviderInvocation,
    ) -> Result<ProviderResult, ProviderError> {
        self.invoke_job_state_change(request, "job.cancel", GitlabJobStateChange::Cancel)
            .await
    }

    async fn invoke_job_play(
        &self,
        request: ProviderInvocation,
    ) -> Result<ProviderResult, ProviderError> {
        let inputs = parse_job_object_inputs(request.inputs())?;
        let project = self.lookup_project_for_invoke(request.admitted()).await?;
        let lookup_credential = &self.lookup_credential(&request)?;
        let existing = self
            .backend
            .job(project.id, inputs.job_id, lookup_credential)
            .await
            .map_err(gitlab_lookup_backend_error)?
            .value;
        ensure_job_in_project(&project, &existing)?;
        let pipeline_id = existing.pipeline_id.ok_or_else(|| {
            ProviderError::error(
                ReasonCode::UpstreamProtocolFailed,
                "GitLab job metadata did not include pipeline id",
            )
        })?;
        let pipeline = self
            .backend
            .pipeline(project.id, pipeline_id, lookup_credential)
            .await
            .map_err(gitlab_lookup_backend_error)?
            .value;
        ensure_pipeline_in_project(&project, &pipeline)?;
        if pipeline.id != pipeline_id {
            return Err(ProviderError::error(
                ReasonCode::UpstreamProtocolFailed,
                "GitLab pipeline metadata did not match job metadata",
            ));
        }
        let ref_name = verified_job_play_ref(&existing, &pipeline)?;
        let safety = self
            .ensure_ci_ref_execution_allowed(&project, ref_name, lookup_credential)
            .await?;
        let credential = &self.execution_credential(&request)?;
        let write = PlainWrite::new(
            json!({ "project": project.path_with_namespace, "jobId": inputs.job_id }),
        );
        let response = self
            .backend
            .play_job(project.id, inputs.job_id, credential)
            .await
            .map_err(|error| write.failed(error))?;
        ensure_job_in_project(&project, &response.value)
            .map_err(|error| write.unverified(error))?;
        Ok(gitlab_result_with_request_body_audit(
            "job.play",
            &project,
            Some(json!({ "job": gitlab_job_object_id(&project, response.value.id) })),
            (response.status, response.duration_ms),
            json!({ "job": response.value }),
            self.backend.egress_proxy_audit(credential),
            ci_ref_audit(ref_name, &safety),
        ))
    }

    async fn invoke_job_state_change(
        &self,
        request: ProviderInvocation,
        operation: &'static str,
        change: GitlabJobStateChange,
    ) -> Result<ProviderResult, ProviderError> {
        let inputs = parse_job_object_inputs(request.inputs())?;
        let project = self.lookup_project_for_invoke(request.admitted()).await?;
        let lookup_credential = &self.lookup_credential(&request)?;
        let existing = self
            .backend
            .job(project.id, inputs.job_id, lookup_credential)
            .await
            .map_err(gitlab_lookup_backend_error)?
            .value;
        ensure_job_in_project(&project, &existing)?;
        let credential = &self.execution_credential(&request)?;
        let write = PlainWrite::new(
            json!({ "project": project.path_with_namespace, "jobId": inputs.job_id }),
        );
        let response = match change {
            GitlabJobStateChange::Retry => {
                self.backend
                    .retry_job(project.id, inputs.job_id, credential)
                    .await
            }
            GitlabJobStateChange::Cancel => {
                self.backend
                    .cancel_job(project.id, inputs.job_id, credential)
                    .await
            }
        }
        .map_err(|error| write.failed(error))?;
        ensure_job_in_project(&project, &response.value)
            .map_err(|error| write.unverified(error))?;
        Ok(gitlab_result(
            operation,
            &project,
            Some(json!({ "job": gitlab_job_object_id(&project, response.value.id) })),
            response.status,
            response.duration_ms,
            json!({ "job": response.value }),
            self.backend.egress_proxy_audit(credential),
        ))
    }

    async fn webhook_project_and_credential(
        &self,
        request: &ProviderInvocation,
    ) -> Result<(GitlabProject, GitlabCredential), ProviderError> {
        let lookup_project = self.lookup_project_for_invoke(request.admitted()).await?;
        let credential = self.execution_credential(request)?;
        let project = self
            .backend
            .project(&lookup_project.path_with_namespace, &credential)
            .await
            .map_err(gitlab_backend_error)?
            .value;
        ensure_same_project(&lookup_project, &project)?;
        Ok((project, credential))
    }

    async fn invoke_webhook_list(
        &self,
        request: ProviderInvocation,
    ) -> Result<ProviderResult, ProviderError> {
        let inputs = parse_webhook_list_inputs(request.inputs(), self.config.search.max_results)?;
        let (project, ref credential) = self.webhook_project_and_credential(&request).await?;
        let request_hash = sha256_serialized(&json!({ "collection": "webhooks" }));
        let page = self.page_from_token(
            inputs.page_token.as_deref(),
            &request,
            &project,
            &request_hash,
            inputs.max_results,
        )?;
        let response = self
            .backend
            .webhooks(
                project.id,
                GitlabWebhookListRequest {
                    max_results: inputs.max_results,
                    page,
                },
                credential,
            )
            .await
            .map_err(gitlab_backend_error)?;
        let GitlabPage { items, next_page } = response.value;
        validate_gitlab_page_count(items.len(), inputs.max_results)?;
        for hook in &items {
            ensure_webhook_in_project(&project, hook, hook.id)?;
            ensure_webhook_bounded(hook, self.config.content.max_body_bytes)?;
        }
        let next_page_token = self.next_page_token(
            next_page,
            &request,
            &project,
            &request_hash,
            inputs.max_results,
        )?;
        let count = items.len();
        let is_last = next_page_token.is_none();
        let mut result = gitlab_result(
            "webhook.list",
            &project,
            None,
            response.status,
            response.duration_ms,
            json!({
                "webhooks": items,
                "count": count,
                "maxResults": inputs.max_results,
                "isLast": is_last,
                "nextPageToken": next_page_token,
            }),
            self.backend.egress_proxy_audit(credential),
        );
        add_gitlab_audit_fields(
            &mut result,
            vec![("count", json!(count)), ("isLast", json!(is_last))],
        );
        Ok(result)
    }

    async fn invoke_webhook_view(
        &self,
        request: ProviderInvocation,
    ) -> Result<ProviderResult, ProviderError> {
        let inputs = parse_webhook_object_inputs(request.inputs())?;
        let (project, ref credential) = self.webhook_project_and_credential(&request).await?;
        let response = self
            .backend
            .webhook(project.id, inputs.webhook_id, credential)
            .await
            .map_err(gitlab_proof_backend_error)?;
        ensure_webhook_in_project(&project, &response.value, inputs.webhook_id)?;
        ensure_webhook_bounded(&response.value, self.config.content.max_body_bytes)?;
        Ok(gitlab_result(
            "webhook.view",
            &project,
            Some(json!({ "webhook": inputs.webhook_id })),
            response.status,
            response.duration_ms,
            json!({ "webhook": response.value }),
            self.backend.egress_proxy_audit(credential),
        ))
    }

    async fn invoke_webhook_create(
        &self,
        request: ProviderInvocation,
    ) -> Result<ProviderResult, ProviderError> {
        let inputs =
            parse_webhook_write_inputs(request.inputs(), true, self.config.content.max_body_bytes)?;
        let url = inputs.url.as_deref().expect("create URL was validated");
        let (destination, matched_pattern) = self.authorize_webhook_destination(url)?;
        let enable_ssl_verification = inputs.enable_ssl_verification.unwrap_or(true);
        self.authorize_webhook_tls(&destination, enable_ssl_verification)?;
        let (project, ref credential) = self.webhook_project_and_credential(&request).await?;
        let write = webhook_write_request(&inputs, url.to_string(), Some(enable_ssl_verification));
        let response = self
            .backend
            .create_webhook(project.id, write.clone(), credential)
            .await
            .map_err(|error| {
                mutation_backend_error(
                    error,
                    MutationVerificationStage::MutationResponse,
                    MutationSafeLocators::new(),
                )
            })?;
        let webhook_id = response.value.id;
        if webhook_id == 0 || response.value.project_id.is_some_and(|id| id != project.id) {
            return Err(mutation_verification_failed(
                MutationVerificationStage::MutationResponse,
                MutationSafeLocators::new(),
            ));
        }
        let safe = MutationSafeLocators::new().with_webhook_ids(vec![webhook_id]);
        let readback = self
            .backend
            .webhook(project.id, webhook_id, credential)
            .await
            .map_err(|error| {
                mutation_backend_error(
                    error,
                    MutationVerificationStage::MutationReadback,
                    safe.clone(),
                )
            })?;
        // The readback must also be presentable: one the Broker cannot
        // return leaves the accepted create unverified, never failed.
        ensure_webhook_in_project(&project, &readback.value, webhook_id)
            .and_then(|_| ensure_webhook_matches_write(&readback.value, &write))
            .and_then(|_| {
                ensure_webhook_bounded(&readback.value, self.config.content.max_body_bytes)
            })
            .map_err(|_| {
                mutation_verification_failed(MutationVerificationStage::MutationReadback, safe)
            })?;
        let mut result = gitlab_result(
            "webhook.create",
            &project,
            Some(json!({ "webhook": webhook_id })),
            readback.status,
            response.duration_ms.saturating_add(readback.duration_ms),
            json!({
                "mutationStatus": "applied", "retrySafe": false,
                "webhookId": webhook_id, "webhook": readback.value,
            }),
            self.backend.egress_proxy_audit(credential),
        );
        add_gitlab_audit_fields(
            &mut result,
            vec![
                ("urlChanged", json!(true)),
                ("destinationScheme", json!(destination.scheme())),
                ("matchedDestinationPatternIndex", json!(matched_pattern)),
                (
                    "eventCount",
                    json!(inputs.events.as_ref().map_or(0, Vec::len)),
                ),
            ],
        );
        Ok(result)
    }

    async fn invoke_webhook_update(
        &self,
        request: ProviderInvocation,
    ) -> Result<ProviderResult, ProviderError> {
        let inputs = parse_webhook_write_inputs(
            request.inputs(),
            false,
            self.config.content.max_body_bytes,
        )?;
        let webhook_id = inputs.webhook_id.expect("update webhook id was validated");
        let (project, ref credential) = self.webhook_project_and_credential(&request).await?;
        let existing = self
            .backend
            .webhook(project.id, webhook_id, credential)
            .await
            .map_err(gitlab_proof_backend_error)?;
        ensure_webhook_in_project(&project, &existing.value, webhook_id)?;
        ensure_webhook_bounded(&existing.value, self.config.content.max_body_bytes)?;
        let effective_url = inputs
            .url
            .clone()
            .unwrap_or_else(|| existing.value.url.clone());
        let url_changed = !canonical_webhook_urls_equal(&existing.value.url, &effective_url);
        let mut destination_audit = None;
        if url_changed {
            let (destination, matched_pattern) =
                self.authorize_webhook_destination(&effective_url)?;
            if inputs.token.is_none() && !inputs.clear_token {
                return Err(ProviderError::deny(
                    ReasonCode::InputInvalid,
                    "URL-changing webhook update requires token or clearToken=true",
                ));
            }
            let reset_headers = webhook_secret_names(existing.value.custom_headers.as_deref());
            let reset_variables = webhook_secret_names(existing.value.url_variables.as_deref());
            if (!reset_headers.is_empty() || !reset_variables.is_empty())
                && !inputs.confirm_destination_reset
            {
                return Err(ProviderError::deny(
                    ReasonCode::InputInvalid,
                    "URL-changing webhook update requires confirmDestinationReset=true",
                )
                .with_result(json!({
                    "resetConfiguration": {
                        "customHeaders": reset_headers,
                        "urlVariables": reset_variables,
                    }
                })));
            }
            let effective_tls = inputs
                .enable_ssl_verification
                .or(existing.value.enable_ssl_verification)
                .unwrap_or(true);
            self.authorize_webhook_tls(&destination, effective_tls)?;
            destination_audit = Some((destination.scheme().to_string(), matched_pattern));
        } else {
            if inputs.clear_token || inputs.confirm_destination_reset {
                return Err(ProviderError::deny(
                    ReasonCode::InputInvalid,
                    "clearToken and confirmDestinationReset require an actual URL change",
                ));
            }
            if inputs.enable_ssl_verification == Some(false)
                && existing.value.enable_ssl_verification != Some(false)
            {
                let destination = parse_webhook_destination(&effective_url)?;
                self.authorize_webhook_tls(&destination, false)?;
            }
        }
        let tls = webhook_update_tls_field(
            url_changed,
            destination_audit
                .as_ref()
                .map(|(scheme, _)| scheme.as_str()),
            existing.value.enable_ssl_verification,
            inputs.enable_ssl_verification,
        );
        let write = webhook_write_request(&inputs, effective_url, tls);
        let safe = MutationSafeLocators::new().with_webhook_ids(vec![webhook_id]);
        let response = self
            .backend
            .update_webhook(project.id, webhook_id, write.clone(), credential)
            .await
            .map_err(|error| {
                mutation_backend_error(
                    error,
                    MutationVerificationStage::MutationResponse,
                    safe.clone(),
                )
            })?;
        ensure_webhook_in_project(&project, &response.value, webhook_id).map_err(|_| {
            mutation_verification_failed(MutationVerificationStage::MutationResponse, safe.clone())
        })?;
        let readback = self
            .backend
            .webhook(project.id, webhook_id, credential)
            .await
            .map_err(|error| {
                mutation_backend_error(
                    error,
                    MutationVerificationStage::MutationReadback,
                    safe.clone(),
                )
            })?;
        // The readback must also be presentable: one the Broker cannot
        // return leaves the accepted update unverified, never failed.
        ensure_webhook_in_project(&project, &readback.value, webhook_id)
            .and_then(|_| ensure_webhook_matches_write(&readback.value, &write))
            .and_then(|_| {
                ensure_webhook_bounded(&readback.value, self.config.content.max_body_bytes)
            })
            .map_err(|_| {
                mutation_verification_failed(MutationVerificationStage::MutationReadback, safe)
            })?;
        let mut result = gitlab_result(
            "webhook.update",
            &project,
            Some(json!({ "webhook": webhook_id })),
            readback.status,
            response.duration_ms.saturating_add(readback.duration_ms),
            json!({
                "mutationStatus": "applied", "retrySafe": false,
                "webhookId": webhook_id, "webhook": readback.value,
            }),
            self.backend.egress_proxy_audit(credential),
        );
        let mut audit = vec![("urlChanged", json!(url_changed))];
        if let Some((scheme, matched_pattern)) = destination_audit {
            audit.push(("destinationScheme", json!(scheme)));
            audit.push(("matchedDestinationPatternIndex", json!(matched_pattern)));
        }
        if let Some(events) = &inputs.events {
            audit.push(("eventCount", json!(events.len())));
        }
        add_gitlab_audit_fields(&mut result, audit);
        Ok(result)
    }

    async fn invoke_webhook_delete(
        &self,
        request: ProviderInvocation,
    ) -> Result<ProviderResult, ProviderError> {
        let inputs = parse_webhook_object_inputs(request.inputs())?;
        let (project, ref credential) = self.webhook_project_and_credential(&request).await?;
        let existing = self
            .backend
            .webhook(project.id, inputs.webhook_id, credential)
            .await
            .map_err(gitlab_proof_backend_error)?;
        ensure_webhook_in_project(&project, &existing.value, inputs.webhook_id)?;
        let safe = MutationSafeLocators::new().with_webhook_ids(vec![inputs.webhook_id]);
        let response = self
            .backend
            .delete_webhook(project.id, inputs.webhook_id, credential)
            .await
            .map_err(|error| {
                mutation_backend_error(
                    error,
                    MutationVerificationStage::MutationResponse,
                    safe.clone(),
                )
            })?;
        match self
            .backend
            .webhook(project.id, inputs.webhook_id, credential)
            .await
        {
            Err(GitlabBackendError::NotFound) => {}
            _ => {
                return Err(mutation_verification_failed(
                    MutationVerificationStage::MutationReadback,
                    safe,
                ));
            }
        }
        Ok(gitlab_result(
            "webhook.delete",
            &project,
            Some(json!({ "webhook": inputs.webhook_id })),
            response.status,
            response.duration_ms,
            json!({ "mutationStatus": "applied", "retrySafe": false, "webhookId": inputs.webhook_id }),
            self.backend.egress_proxy_audit(credential),
        ))
    }

    async fn invoke_webhook_test(
        &self,
        request: ProviderInvocation,
    ) -> Result<ProviderResult, ProviderError> {
        let inputs = parse_webhook_test_inputs(request.inputs())?;
        let (project, ref credential) = self.webhook_project_and_credential(&request).await?;
        let hook = self
            .backend
            .webhook(project.id, inputs.webhook_id, credential)
            .await
            .map_err(gitlab_proof_backend_error)?;
        ensure_webhook_in_project(&project, &hook.value, inputs.webhook_id)?;
        let safe = MutationSafeLocators::new().with_webhook_ids(vec![inputs.webhook_id]);
        let response = self
            .backend
            .test_webhook(
                project.id,
                inputs.webhook_id,
                inputs
                    .event
                    .test_trigger()
                    .expect("test event was validated"),
                credential,
            )
            .await
            .map_err(|error| {
                mutation_backend_error(error, MutationVerificationStage::MutationResponse, safe)
            })?;
        let mut result = gitlab_result(
            "webhook.test",
            &project,
            Some(json!({ "webhook": inputs.webhook_id })),
            response.status,
            response.duration_ms,
            json!({
                "mutationStatus": "applied", "retrySafe": false,
                "webhookId": inputs.webhook_id, "attempt": response.value,
            }),
            self.backend.egress_proxy_audit(credential),
        );
        add_gitlab_audit_fields(&mut result, vec![("event", json!(inputs.event))]);
        Ok(result)
    }

    async fn invoke_webhook_event_list(
        &self,
        request: ProviderInvocation,
    ) -> Result<ProviderResult, ProviderError> {
        let inputs = parse_webhook_event_list_inputs(request.inputs())?;
        let (project, ref credential) = self.webhook_project_and_credential(&request).await?;
        let hook = self
            .backend
            .webhook(project.id, inputs.webhook_id, credential)
            .await
            .map_err(gitlab_proof_backend_error)?;
        ensure_webhook_in_project(&project, &hook.value, inputs.webhook_id)?;
        let request_hash = sha256_serialized(&json!({
            "webhookId": inputs.webhook_id, "status": inputs.status,
        }));
        let page = self.page_from_token(
            inputs.page_token.as_deref(),
            &request,
            &project,
            &request_hash,
            inputs.max_results,
        )?;
        let redacted = hook
            .value
            .custom_headers
            .as_deref()
            .unwrap_or_default()
            .iter()
            .map(|header| header.key.to_ascii_lowercase())
            .collect::<BTreeSet<_>>();
        let response = self
            .backend
            .webhook_events(
                project.id,
                GitlabWebhookEventListRequest {
                    webhook_id: inputs.webhook_id,
                    status: inputs.status.clone(),
                    max_results: inputs.max_results,
                    page,
                },
                &redacted,
                self.config.content.max_body_bytes,
                credential,
            )
            .await
            .map_err(gitlab_backend_error)?;
        let GitlabPage { items, next_page } = response.value;
        validate_gitlab_page_count(items.len(), inputs.max_results)?;
        let next_page_token = self.next_page_token(
            next_page,
            &request,
            &project,
            &request_hash,
            inputs.max_results,
        )?;
        let count = items.len();
        let is_last = next_page_token.is_none();
        let mut result = gitlab_result(
            "webhook.event.list",
            &project,
            Some(json!({ "webhook": inputs.webhook_id })),
            response.status,
            response.duration_ms,
            json!({
                "events": items, "count": count, "maxResults": inputs.max_results,
                "isLast": is_last, "nextPageToken": next_page_token,
            }),
            self.backend.egress_proxy_audit(credential),
        );
        add_gitlab_audit_fields(
            &mut result,
            vec![("count", json!(count)), ("isLast", json!(is_last))],
        );
        Ok(result)
    }

    async fn invoke_webhook_event_resend(
        &self,
        request: ProviderInvocation,
    ) -> Result<ProviderResult, ProviderError> {
        let inputs = parse_webhook_event_resend_inputs(request.inputs())?;
        let (project, ref credential) = self.webhook_project_and_credential(&request).await?;
        let hook = self
            .backend
            .webhook(project.id, inputs.webhook_id, credential)
            .await
            .map_err(gitlab_proof_backend_error)?;
        ensure_webhook_in_project(&project, &hook.value, inputs.webhook_id)?;
        let safe = MutationSafeLocators::new()
            .with_webhook_ids(vec![inputs.webhook_id])
            .with_webhook_event_ids(vec![inputs.webhook_event_id]);
        let response = self
            .backend
            .resend_webhook_event(
                project.id,
                inputs.webhook_id,
                inputs.webhook_event_id,
                credential,
            )
            .await
            .map_err(|error| {
                mutation_backend_error(error, MutationVerificationStage::MutationResponse, safe)
            })?;
        Ok(gitlab_result(
            "webhook.event.resend",
            &project,
            Some(json!({ "webhook": inputs.webhook_id, "webhookEvent": inputs.webhook_event_id })),
            response.status,
            response.duration_ms,
            json!({
                "mutationStatus": "applied", "retrySafe": false,
                "webhookId": inputs.webhook_id, "webhookEventId": inputs.webhook_event_id,
                "attempt": response.value,
            }),
            self.backend.egress_proxy_audit(credential),
        ))
    }

    async fn invoke_webhook_custom_header_set(
        &self,
        request: ProviderInvocation,
    ) -> Result<ProviderResult, ProviderError> {
        self.invoke_webhook_custom_header_change(request, true)
            .await
    }

    async fn invoke_webhook_custom_header_delete(
        &self,
        request: ProviderInvocation,
    ) -> Result<ProviderResult, ProviderError> {
        self.invoke_webhook_custom_header_change(request, false)
            .await
    }

    async fn invoke_webhook_custom_header_change(
        &self,
        request: ProviderInvocation,
        set: bool,
    ) -> Result<ProviderResult, ProviderError> {
        let inputs = parse_webhook_custom_header_inputs(request.inputs(), set)?;
        let (project, ref credential) = self.webhook_project_and_credential(&request).await?;
        let existing = self
            .backend
            .webhook(project.id, inputs.webhook_id, credential)
            .await
            .map_err(gitlab_proof_backend_error)?;
        ensure_webhook_in_project(&project, &existing.value, inputs.webhook_id)?;
        let safe = MutationSafeLocators::new().with_webhook_ids(vec![inputs.webhook_id]);
        let response = if set {
            self.backend
                .set_webhook_custom_header(project.id, inputs.clone(), credential)
                .await
        } else {
            self.backend
                .delete_webhook_custom_header(project.id, inputs.clone(), credential)
                .await
        }
        .map_err(|error| {
            mutation_backend_error(
                error,
                MutationVerificationStage::MutationResponse,
                safe.clone(),
            )
        })?;
        let readback = self
            .backend
            .webhook(project.id, inputs.webhook_id, credential)
            .await
            .map_err(|error| {
                mutation_backend_error(
                    error,
                    MutationVerificationStage::MutationReadback,
                    safe.clone(),
                )
            })?;
        ensure_webhook_in_project(&project, &readback.value, inputs.webhook_id).map_err(|_| {
            mutation_verification_failed(MutationVerificationStage::MutationReadback, safe.clone())
        })?;
        let present = readback
            .value
            .custom_headers
            .as_deref()
            .unwrap_or_default()
            .iter()
            .any(|header| header.key.eq_ignore_ascii_case(&inputs.key));
        if present != set {
            return Err(mutation_verification_failed(
                MutationVerificationStage::MutationReadback,
                safe,
            ));
        }
        let operation = if set {
            "webhook.custom_header.set"
        } else {
            "webhook.custom_header.delete"
        };
        Ok(gitlab_result(
            operation,
            &project,
            Some(json!({ "webhook": inputs.webhook_id })),
            response.status,
            response.duration_ms.saturating_add(readback.duration_ms),
            json!({
                "mutationStatus": "applied", "retrySafe": false,
                "webhookId": inputs.webhook_id, "key": inputs.key,
            }),
            self.backend.egress_proxy_audit(credential),
        ))
    }

    fn authorize_webhook_destination(&self, value: &str) -> Result<(Url, usize), ProviderError> {
        let destination = parse_webhook_destination(value)?;
        let matched = self
            .config
            .webhooks
            .allowed_destinations
            .iter()
            .position(|pattern| {
                url_allowed_by_patterns(&destination, std::slice::from_ref(pattern))
            });
        let Some(matched) = matched else {
            return Err(ProviderError::deny(
                ReasonCode::WebhookDestinationDenied,
                "GitLab webhook destination is denied by providers.gitlab.webhooks",
            ));
        };
        Ok((destination, matched))
    }

    fn authorize_webhook_tls(&self, destination: &Url, enabled: bool) -> Result<(), ProviderError> {
        if destination.scheme() == "https"
            && !enabled
            && !self.config.webhooks.allow_disable_ssl_verification
        {
            return Err(ProviderError::deny(
                ReasonCode::WebhookDestinationDenied,
                "GitLab webhook TLS verification policy denied this configuration",
            ));
        }
        Ok(())
    }

    async fn ensure_source_ref_exists(
        &self,
        project_id: u64,
        ref_name: &str,
        credential: &GitlabCredential,
    ) -> Result<(), ProviderError> {
        match self.backend.branch(project_id, ref_name, credential).await {
            Ok(_) => Ok(()),
            Err(GitlabBackendError::NotFound) => self
                .backend
                .commit(project_id, ref_name, credential)
                .await
                .map(|_| ())
                .map_err(gitlab_lookup_backend_error),
            Err(error) => Err(gitlab_lookup_backend_error(error)),
        }
    }

    async fn ensure_branch_write_allowed(
        &self,
        project: &GitlabProject,
        branch: &str,
        credential: &GitlabCredential,
    ) -> Result<GitlabBranchSafety, ProviderError> {
        validate_branch_name(branch)?;
        let mut safety = GitlabBranchSafety {
            branch: branch.to_string(),
            default_branch: project.default_branch.clone(),
            target_branch_exists: false,
            existing_branch_default: None,
            existing_branch_protected: None,
            matched_protected_branch: None,
        };
        if project.default_branch.as_deref() == Some(branch)
            || GITLAB_DEFAULT_BRANCH_NAMES.contains(&branch)
        {
            return Err(branch_write_denied());
        }
        match self.backend.branch(project.id, branch, credential).await {
            Ok(existing) => {
                safety.target_branch_exists = true;
                safety.existing_branch_default = existing.value.default;
                safety.existing_branch_protected = existing.value.protected;
                if existing.value.default == Some(true) || existing.value.protected == Some(true) {
                    return Err(branch_write_denied());
                }
            }
            Err(GitlabBackendError::NotFound) => {}
            Err(error) => return Err(gitlab_lookup_backend_error(error)),
        }
        let protected = self
            .backend
            .protected_branches(
                project.id,
                GitlabProtectedBranchListRequest {
                    search: None,
                    max_results: 100,
                    fail_on_next_page: true,
                },
                credential,
            )
            .await
            .map_err(gitlab_lookup_backend_error)?;
        for protected_branch in protected.value {
            if protected_branch_matches(&protected_branch.name, branch) {
                safety.matched_protected_branch = Some(protected_branch.name);
                return Err(branch_write_denied());
            }
        }
        Ok(safety)
    }

    async fn ensure_ci_ref_execution_allowed(
        &self,
        project: &GitlabProject,
        ref_name: &str,
        credential: &GitlabCredential,
    ) -> Result<GitlabCiRefSafety, ProviderError> {
        validate_branch_name(ref_name)?;
        let mut safety = GitlabCiRefSafety {
            ref_name: ref_name.to_string(),
            default_branch: project.default_branch.clone(),
            existing_branch_default: None,
            existing_branch_protected: None,
            matched_protected_branch: None,
            denial_reason: None,
        };
        if project.default_branch.as_deref() == Some(ref_name) {
            safety.denial_reason = Some("project_default_branch".to_string());
            return Err(ci_ref_execution_denied(&safety));
        }
        if GITLAB_DEFAULT_BRANCH_NAMES.contains(&ref_name) {
            safety.denial_reason = Some("reserved_default_branch_name".to_string());
            return Err(ci_ref_execution_denied(&safety));
        }
        let branch = self
            .backend
            .branch(project.id, ref_name, credential)
            .await
            .map_err(gitlab_lookup_backend_error)?;
        safety.existing_branch_default = branch.value.default;
        safety.existing_branch_protected = branch.value.protected;
        if branch.value.default == Some(true) {
            safety.denial_reason = Some("branch_default".to_string());
            return Err(ci_ref_execution_denied(&safety));
        }
        if branch.value.protected == Some(true) {
            safety.denial_reason = Some("branch_protected".to_string());
            return Err(ci_ref_execution_denied(&safety));
        }
        let protected = self
            .backend
            .protected_branches(
                project.id,
                GitlabProtectedBranchListRequest {
                    search: None,
                    max_results: 100,
                    fail_on_next_page: true,
                },
                credential,
            )
            .await
            .map_err(gitlab_lookup_backend_error)?;
        for protected_branch in protected.value {
            if protected_branch_matches(&protected_branch.name, ref_name) {
                safety.matched_protected_branch = Some(protected_branch.name);
                safety.denial_reason = Some("protected_branch_rule".to_string());
                return Err(ci_ref_execution_denied(&safety));
            }
        }
        Ok(safety)
    }
}

fn parse_webhook_destination(value: &str) -> Result<Url, ProviderError> {
    let url = Url::parse(value).map_err(|_| {
        ProviderError::deny(
            ReasonCode::InputInvalid,
            "GitLab webhook destination URL is invalid",
        )
    })?;
    if !matches!(url.scheme(), "http" | "https")
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
    {
        return Err(ProviderError::deny(
            ReasonCode::InputInvalid,
            "GitLab webhook destination URL is invalid",
        ));
    }
    Ok(url)
}

fn canonical_webhook_urls_equal(left: &str, right: &str) -> bool {
    match (Url::parse(left), Url::parse(right)) {
        (Ok(left), Ok(right)) => left.as_str() == right.as_str(),
        _ => left == right,
    }
}

fn webhook_update_tls_field(
    url_changed: bool,
    destination_scheme: Option<&str>,
    existing: Option<bool>,
    requested: Option<bool>,
) -> Option<bool> {
    if url_changed && destination_scheme == Some("https") && existing == Some(false) {
        Some(requested.unwrap_or(false))
    } else {
        requested
    }
}

fn webhook_write_request(
    inputs: &WebhookWriteInputs,
    url: String,
    enable_ssl_verification: Option<bool>,
) -> GitlabWebhookWriteRequest {
    GitlabWebhookWriteRequest {
        url,
        events: inputs.events.clone(),
        name: inputs.name.clone(),
        description: inputs.description.clone(),
        enable_ssl_verification,
        branch_filter_strategy: inputs.branch_filter_strategy.clone(),
        push_events_branch_filter: inputs.push_events_branch_filter.clone(),
        custom_webhook_template: inputs.custom_webhook_template.clone(),
        token: inputs.token.clone(),
        signing_token: inputs.signing_token.clone(),
    }
}

fn webhook_secret_names(values: Option<&[GitlabWebhookNamedSecret]>) -> Vec<String> {
    values
        .unwrap_or_default()
        .iter()
        .map(|value| value.key.clone())
        .collect()
}

fn ensure_webhook_in_project(
    project: &GitlabProject,
    webhook: &GitlabWebhook,
    webhook_id: u64,
) -> Result<(), ProviderError> {
    if webhook.id != webhook_id
        || webhook.id == 0
        || webhook.project_id.is_some_and(|id| id != project.id)
    {
        return Err(ProviderError::deny(
            ReasonCode::ScopeUnresolved,
            "GitLab webhook was not found or not permitted",
        ));
    }
    Ok(())
}

fn ensure_webhook_bounded(
    webhook: &GitlabWebhook,
    max_body_bytes: u64,
) -> Result<(), ProviderError> {
    let strings = [
        Some(webhook.url.as_str()),
        webhook.name.as_deref(),
        webhook.description.as_deref(),
        webhook.created_at.as_deref(),
        webhook.alert_status.as_deref(),
        webhook.disabled_until.as_deref(),
        webhook.branch_filter_strategy.as_deref(),
        webhook.push_events_branch_filter.as_deref(),
        webhook.custom_webhook_template.as_deref(),
    ];
    if strings
        .into_iter()
        .flatten()
        .any(|value| value.len() as u64 > max_body_bytes)
        || webhook.events.len() > GitlabWebhookEvent::ALL.len()
        || webhook.custom_headers.as_deref().unwrap_or_default().len() > 100
        || webhook.url_variables.as_deref().unwrap_or_default().len() > 100
    {
        return Err(ProviderError::error(
            ReasonCode::UpstreamProtocolFailed,
            "GitLab webhook response exceeded configured bounds",
        ));
    }
    Ok(())
}

fn ensure_webhook_matches_write(
    webhook: &GitlabWebhook,
    request: &GitlabWebhookWriteRequest,
) -> Result<(), ProviderError> {
    let matches_nullable = |observed: Option<&str>, requested: &Option<Option<String>>| {
        requested
            .as_ref()
            .is_none_or(|requested| observed == requested.as_deref())
    };
    if !canonical_webhook_urls_equal(&webhook.url, &request.url)
        || request
            .events
            .as_ref()
            .is_some_and(|events| webhook.events != *events)
        || !matches_nullable(webhook.name.as_deref(), &request.name)
        || !matches_nullable(webhook.description.as_deref(), &request.description)
        || request
            .enable_ssl_verification
            .is_some_and(|value| webhook.enable_ssl_verification != Some(value))
        || request
            .branch_filter_strategy
            .as_ref()
            .is_some_and(|value| webhook.branch_filter_strategy.as_ref() != Some(value))
        || request
            .push_events_branch_filter
            .as_ref()
            .is_some_and(|value| webhook.push_events_branch_filter.as_ref() != Some(value))
        || !matches_nullable(
            webhook.custom_webhook_template.as_deref(),
            &request.custom_webhook_template,
        )
        || request.token.is_some() && webhook.token_present == Some(false)
        || request.signing_token.is_some() && webhook.signing_token_present == Some(false)
    {
        return Err(ProviderError::error(
            ReasonCode::UpstreamProtocolFailed,
            "GitLab webhook readback did not match the requested configuration",
        ));
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum GitlabPipelineStateChange {
    Retry,
    Cancel,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum GitlabJobStateChange {
    Retry,
    Cancel,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GitlabDiscussionStateChange {
    Resolve,
    Reopen,
}

impl GitlabDiscussionStateChange {
    fn resolved(self) -> bool {
        matches!(self, Self::Resolve)
    }

    fn operation(self) -> &'static str {
        match self {
            Self::Resolve => "merge_request.discussion.resolve",
            Self::Reopen => "merge_request.discussion.reopen",
        }
    }
}

/// GitLab's authoritative service definition, derived from its typed
/// configuration alone.
pub fn gitlab_descriptor(config: &GitlabProviderConfig) -> ServiceDescriptor {
    const ADD_DESCRIPTION: AttributionCapability = AttributionCapability::optional(
        AttributionVerb::Add,
        "description",
        AttributionRepresentation::GitlabMarkdown,
    );
    const UPDATE_DESCRIPTION: AttributionCapability = AttributionCapability::optional(
        AttributionVerb::Update,
        "description",
        AttributionRepresentation::GitlabMarkdown,
    );
    const ADD_BODY: AttributionCapability = AttributionCapability::required(
        AttributionVerb::Add,
        "body",
        AttributionRepresentation::GitlabMarkdown,
    );
    let mut actions = vec![
        gitlab_action(
            "project.upload",
            "Upload one bounded attachment to an authorized GitLab project",
            project_upload_schema(&config.attachments),
        )
        .multipart_upload(attachment_upload_plan(&["project", "url"], Some(1))),
        gitlab_read_action(
            "project.view",
            "View GitLab project metadata after repository-scope confirmation",
            project_locator_schema(),
        ),
        gitlab_read_action(
            "issue.view",
            "View a GitLab issue after repository-scope confirmation",
            issue_view_schema(),
        ),
        gitlab_read_action(
            "issue.search",
            "List and filter GitLab issues within one required authorized project. Omit search text to browse; use structured filters and sorting.",
            issue_search_schema(config.search.max_results),
        )
        .documentation(gitlab_search_documentation(false, config.search.max_results)),
        gitlab_action(
            "issue.create",
            "Create a GitLab issue inside one authorized project",
            issue_create_schema(),
        )
        .attribution(ADD_DESCRIPTION),
        gitlab_action(
            "issue.update",
            "Update a GitLab issue inside one authorized project",
            issue_update_schema(),
        )
        .attribution(UPDATE_DESCRIPTION),
        gitlab_read_action(
            "issue.note.list",
            "List GitLab issue notes inside one authorized project",
            note_list_schema(config.search.max_results),
        ),
        gitlab_read_action(
            "issue.note.view",
            "View one GitLab issue note inside one authorized project",
            note_delete_schema(),
        ),
        gitlab_action(
            "issue.note.add",
            "Add a GitLab issue note inside one authorized project",
            issue_note_add_schema(),
        )
        .attribution(ADD_BODY),
        gitlab_action(
            "issue.note.update",
            "Update one GitLab issue note inside one authorized project",
            note_update_schema(),
        ),
        gitlab_action(
            "issue.note.delete",
            "Delete one GitLab issue note inside one authorized project",
            note_delete_schema(),
        ),
        gitlab_read_action(
            "merge_request.view",
            "View a GitLab merge request after repository-scope confirmation",
            merge_request_view_schema(),
        ),
        gitlab_read_action(
            "merge_request.search",
            "List and filter GitLab merge requests within one required authorized project. Omit search text to browse; use structured filters and sorting.",
            merge_request_search_schema(config.search.max_results),
        )
        .documentation(gitlab_search_documentation(true, config.search.max_results)),
        gitlab_action(
            "merge_request.create",
            "Create a GitLab merge request inside one authorized project",
            merge_request_create_schema(),
        )
        .attribution(ADD_DESCRIPTION),
        gitlab_action(
            "merge_request.update",
            "Update a GitLab merge request inside one authorized project",
            merge_request_update_schema(),
        )
        .attribution(UPDATE_DESCRIPTION),
        gitlab_read_action(
            "merge_request.note.list",
            "List GitLab merge request notes inside one authorized project",
            note_list_schema(config.search.max_results),
        ),
        gitlab_read_action(
            "merge_request.note.view",
            "View one GitLab merge request note inside one authorized project",
            note_delete_schema(),
        ),
        gitlab_action(
            "merge_request.note.add",
            "Add a GitLab merge request note inside one authorized project",
            note_add_schema(),
        )
        .attribution(ADD_BODY),
        gitlab_action(
            "merge_request.note.update",
            "Update one GitLab merge request note inside one authorized project",
            note_update_schema(),
        ),
        gitlab_action(
            "merge_request.note.delete",
            "Delete one GitLab merge request note inside one authorized project",
            note_delete_schema(),
        ),
        gitlab_read_action(
            "merge_request.discussion.list",
            "List GitLab merge request discussions inside one authorized project",
            discussion_list_schema(config.search.max_results),
        ),
        gitlab_read_action(
            "merge_request.discussion.view",
            "View one GitLab merge request discussion with exact review position metadata",
            discussion_view_schema(),
        ),
        gitlab_action(
            "merge_request.discussion.inline.add",
            "Add a current-version inline GitLab merge request discussion",
            positioned_discussion_schema(),
        )
        .attribution(ADD_BODY),
        gitlab_action(
            "merge_request.discussion.note.add",
            "Reply to one GitLab merge request discussion",
            discussion_reply_schema(),
        )
        .attribution(ADD_BODY),
        gitlab_read_action(
            "merge_request.draft_note.list",
            "List the current GitLab user's pending merge request draft notes",
            draft_note_list_schema(config.search.max_results),
        )
        .upstream_resource_ownership(UpstreamResourceOwnership::ActingUser),
        gitlab_read_action(
            "merge_request.draft_note.view",
            "View one current-owner GitLab merge request draft note",
            draft_note_object_schema(),
        )
        .upstream_resource_ownership(UpstreamResourceOwnership::ActingUser),
        gitlab_action(
            "merge_request.draft_note.add",
            "Add a general, positioned, or reply GitLab merge request draft note",
            draft_note_add_schema(),
        )
        .upstream_resource_ownership(UpstreamResourceOwnership::ActingUser)
        .attribution(ADD_BODY),
        gitlab_action(
            "merge_request.draft_note.update",
            "Update a current-owner GitLab merge request draft note",
            draft_note_update_schema(),
        )
        .upstream_resource_ownership(UpstreamResourceOwnership::ActingUser),
        gitlab_action(
            "merge_request.draft_note.delete",
            "Delete a current-owner GitLab merge request draft note",
            draft_note_object_schema(),
        )
        .upstream_resource_ownership(UpstreamResourceOwnership::ActingUser),
        gitlab_action(
            "merge_request.draft_note.publish",
            "Publish one current-owner GitLab merge request draft note",
            draft_note_object_schema(),
        )
        .upstream_resource_ownership(UpstreamResourceOwnership::ActingUser),
        gitlab_action(
            "merge_request.draft_note.publish_all",
            "Publish all current-owner GitLab merge request draft notes",
            draft_publication_schema(false),
        )
        .upstream_resource_ownership(UpstreamResourceOwnership::ActingUser)
        .attribution(ADD_BODY),
        gitlab_action(
            "merge_request.review.submit",
            "Publish current-owner drafts and set the acting reviewer's state",
            draft_publication_schema(true),
        )
        .upstream_resource_ownership(UpstreamResourceOwnership::ActingUser)
        .attribution(ADD_BODY),
        gitlab_read_action(
            "merge_request.reviewer.list",
            "List GitLab merge request reviewers and reviewer state",
            merge_request_collection_schema(config.search.max_results, false),
        ),
        gitlab_read_action(
            "merge_request.approval.view",
            "View aggregate GitLab merge request approval state",
            merge_request_subresource_schema(),
        ),
        gitlab_read_action(
            "merge_request.approval_state.view",
            "View GitLab merge request approval rule satisfaction state",
            merge_request_subresource_schema(),
        ),
        gitlab_read_action(
            "merge_request.approval_rule.list",
            "List GitLab merge request approval rules",
            merge_request_collection_schema(config.search.max_results, false),
        ),
        gitlab_read_action(
            "merge_request.approval_rule.view",
            "View one GitLab merge request approval rule",
            merge_request_approval_rule_view_schema(),
        ),
        gitlab_action(
            "merge_request.approve",
            "Approve an exact prepared GitLab merge request head",
            merge_request_approve_schema(),
        ),
        gitlab_action(
            "merge_request.unapprove",
            "Remove the acting GitLab user's merge request approval",
            merge_request_subresource_schema(),
        ),
        gitlab_action(
            "merge_request.suggestion.apply",
            "Apply one proven GitLab merge request suggestion",
            suggestion_apply_schema(false, config.content.max_body_bytes),
        ),
        gitlab_action(
            "merge_request.suggestion.batch_apply",
            "Apply up to 100 proven GitLab merge request suggestions",
            suggestion_apply_schema(true, config.content.max_body_bytes),
        ),
        gitlab_read_action(
            "merge_request.commit.list",
            "List commits belonging to one GitLab merge request",
            merge_request_collection_schema(config.search.max_results, false),
        ),
        gitlab_read_action(
            "merge_request.pipeline.list",
            "List pipelines belonging to one GitLab merge request",
            merge_request_collection_schema(config.search.max_results, false),
        ),
        gitlab_read_action(
            "merge_request.diff.list",
            "List bounded structured current diffs for one GitLab merge request",
            merge_request_collection_schema(config.search.max_results, true),
        ),
        gitlab_read_action(
            "merge_request.diff.raw.download",
            "Download the bounded raw current diff for one GitLab merge request",
            merge_request_subresource_schema(),
        )
        .raw_download(),
        gitlab_read_action(
            "merge_request.diff_version.list",
            "List historical diff versions for one GitLab merge request",
            merge_request_collection_schema(config.search.max_results, false),
        ),
        gitlab_read_action(
            "merge_request.diff_version.view",
            "View one exact GitLab merge request diff version with bounded commits and diffs",
            merge_request_diff_version_view_schema(),
        ),
        gitlab_action(
            "merge_request.discussion.add",
            "Add a general GitLab merge request discussion inside one authorized project",
            note_add_schema(),
        )
        .attribution(ADD_BODY),
        gitlab_action(
            "merge_request.discussion.note.update",
            "Update one note inside a GitLab merge request discussion",
            discussion_note_update_schema(),
        ),
        gitlab_action(
            "merge_request.discussion.note.delete",
            "Delete one note inside a GitLab merge request discussion",
            discussion_note_delete_schema(),
        ),
        gitlab_action(
            "merge_request.discussion.resolve",
            "Resolve one GitLab merge request discussion",
            discussion_state_change_schema(),
        ),
        gitlab_action(
            "merge_request.discussion.reopen",
            "Reopen one GitLab merge request discussion",
            discussion_state_change_schema(),
        ),
        gitlab_action(
            "merge_request.merge",
            "Merge one GitLab merge request through the GitLab REST API",
            merge_request_merge_schema(config.content.max_body_bytes),
        ),
        gitlab_read_action(
            "branch.list",
            "List GitLab repository branches inside one authorized project",
            branch_list_schema(config.search.max_results),
        ),
        gitlab_read_action(
            "branch.view",
            "View one GitLab repository branch inside an authorized project",
            branch_view_schema(),
        ),
        gitlab_action(
            "branch.create",
            "Create a non-default, unprotected GitLab repository branch",
            branch_create_schema(),
        ),
        gitlab_read_action(
            "protected_branch.list",
            "List GitLab protected branch rules inside one authorized project",
            protected_branch_list_schema(config.search.max_results),
        ),
        gitlab_read_action(
            "protected_branch.view",
            "View one GitLab protected branch rule inside an authorized project",
            protected_branch_view_schema(),
        ),
        gitlab_read_action(
            "protected_branch.verify",
            "Verify required GitLab protected branch rule coverage",
            protected_branch_verify_schema(),
        ),
        gitlab_read_action(
            "file.view",
            "View bounded GitLab repository file metadata and inline content",
            file_view_schema(),
        )
        .documentation(json!({
            "content":"Reads files from a project's source repository. Wiki pages are separate and cannot be read through this action. Full wiki-page reading is not currently supported by the Broker."
        })),
        gitlab_read_action(
            "file.raw.download",
            "Download a bounded GitLab repository file as a raw stream",
            file_view_schema(),
        )
        .raw_download(),
        gitlab_action(
            "file.create",
            "Create one file on a non-default, unprotected GitLab branch",
            file_create_schema(),
        ),
        gitlab_action(
            "file.update",
            "Update one file on a non-default, unprotected GitLab branch",
            file_update_schema(),
        ),
        gitlab_action(
            "file.delete",
            "Delete one file on a non-default, unprotected GitLab branch",
            file_delete_schema(),
        ),
        gitlab_read_action(
            "commit.list",
            "List GitLab repository commits inside one authorized project",
            commit_list_schema(config.search.max_results),
        ),
        gitlab_read_action(
            "commit.view",
            "View one GitLab repository commit inside an authorized project",
            commit_view_schema(),
        ),
        gitlab_action(
            "commit.create",
            "Create a bounded GitLab REST commit on a non-default, unprotected branch",
            commit_create_schema(config.content.max_commit_actions),
        ),
        gitlab_read_action(
            "pipeline.list",
            "List GitLab CI pipelines inside one authorized project",
            pipeline_list_schema(config.search.max_results),
        ),
        gitlab_read_action(
            "pipeline.view",
            "View one GitLab CI pipeline inside an authorized project",
            pipeline_object_schema("pipelineId"),
        ),
        gitlab_action(
            "pipeline.run",
            "Run a GitLab CI pipeline on a non-default, unprotected branch",
            pipeline_run_schema(),
        ),
        gitlab_action(
            "pipeline.retry",
            "Retry one GitLab CI pipeline inside an authorized project",
            pipeline_object_schema("pipelineId"),
        ),
        gitlab_action(
            "pipeline.cancel",
            "Cancel one GitLab CI pipeline inside an authorized project",
            pipeline_object_schema("pipelineId"),
        ),
        gitlab_read_action(
            "job.list",
            "List GitLab CI jobs inside one authorized project",
            job_list_schema(config.search.max_results),
        ),
        gitlab_read_action(
            "job.view",
            "View one GitLab CI job inside an authorized project",
            job_object_schema("jobId"),
        ),
        gitlab_read_action(
            "job.trace.download",
            "Download a bounded GitLab CI job trace as a raw stream",
            job_object_schema("jobId"),
        )
        .raw_download(),
        gitlab_action(
            "job.retry",
            "Retry one GitLab CI job inside an authorized project",
            job_object_schema("jobId"),
        ),
        gitlab_action(
            "job.cancel",
            "Cancel one GitLab CI job inside an authorized project",
            job_object_schema("jobId"),
        ),
        gitlab_action(
            "job.play",
            "Play one GitLab manual CI job on a non-default, unprotected branch",
            job_object_schema("jobId"),
        ),
        gitlab_read_action(
            "webhook.list",
            "List GitLab project webhooks inside one authorized project",
            webhook_list_schema(config.search.max_results),
        ),
        gitlab_read_action(
            "webhook.view",
            "View one GitLab project webhook inside one authorized project",
            webhook_object_schema(),
        ),
        gitlab_action(
            "webhook.create",
            "Create a GitLab project webhook at an operator-authorized destination",
            webhook_create_schema(),
        ),
        gitlab_action(
            "webhook.update",
            "Update one GitLab project webhook",
            webhook_update_schema(),
        ),
        gitlab_action(
            "webhook.delete",
            "Delete one GitLab project webhook",
            webhook_object_schema(),
        ),
        gitlab_action(
            "webhook.test",
            "Send one synthetic GitLab project webhook delivery",
            webhook_test_schema(),
        ),
        gitlab_read_action(
            "webhook.event.list",
            "List recent GitLab project webhook delivery records",
            webhook_event_list_schema(),
        ),
        gitlab_action(
            "webhook.event.resend",
            "Resend one GitLab project webhook delivery",
            webhook_event_resend_schema(),
        ),
        gitlab_action(
            "webhook.custom_header.set",
            "Set one masked GitLab project webhook custom header",
            webhook_custom_header_schema(true),
        ),
        gitlab_action(
            "webhook.custom_header.delete",
            "Delete one GitLab project webhook custom header",
            webhook_custom_header_schema(false),
        ),
    ];
    actions.extend(PROVISIONING_ACTIONS.iter().map(|action| {
        let schema = provisioning::provisioning_schema(action, config);
        if issues_token(action) {
            // GitLab documents project token creation and rotation as
            // personal-access-token only; service-account tokens are
            // treated alike. OAuth access never reaches them.
            gitlab_action(
                action,
                "Manage a GitLab project bot credential; result.issuedToken follows Broker secret delivery policy",
                schema,
            )
            .secret_output(SecretOutputDescriptor::new("/result/issuedToken", 8192))
            .token_only()
        } else if *action == "project.member.view" {
            gitlab_read_action(
                action,
                "Read a direct project member's username by userId, including a newly issued project token's bot user",
                schema,
            )
        } else if matches!(*action, "project.access_token.list" | "project.access_token.view" | "service_account.list" | "service_account.view" | "service_account.token.list") {
            gitlab_read_action(
                action,
                "Read GitLab project automation identities and token metadata",
                schema,
            )
        } else {
            gitlab_action(
                action,
                "Manage GitLab project automation identities and token metadata",
                schema,
            )
        }
    }));
    actions.extend(search::descriptors(config));
    let descriptor = ServiceDescriptor::new("gitlab", "GitLab")
        .with_resource_scopes(BTreeMap::from([(
            "repository".to_string(),
            ResourceScopeCapabilities::new(
                crate::GIT_REPOSITORY_RESOURCE.id().clone(),
                vec![
                    "exact".to_string(),
                    "namespace".to_string(),
                    "all".to_string(),
                ],
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
        .with_credentials(
            CredentialDescriptor::default()
                .profile("gitlab-access-token", "bearer_token")
                .delegated(
                    "Lets agents act on GitLab projects as your GitLab account. Agent access is limited by your Broker grants. GitLab's authorization page lists the broader scopes the connection grants.",
                ),
        )
        .with_presentation_body_limit(config.content.max_body_bytes);
    match gitlab_upstream_authority(&config.api_base_url) {
        Some(authority) => descriptor.with_upstream_authority(authority),
        None => descriptor,
    }
}

/// The OAuth target of the GitLab instance `api_base_url` names: what a
/// `gitlab` registration's profile targets, and what delegated access is
/// pinned to before each request.
fn gitlab_instance_target(config: &GitlabProviderConfig) -> Option<Arc<str>> {
    gitlab_upstream_authority(&config.api_base_url)
        .map(|instance| Arc::from(oauth::oauth_target(&instance)))
}

/// The GitLab instance `api_base_url` belongs to: the REST v4 API root
/// without its `/api/v4` suffix, which is also what the Git gateway's
/// `upstream_base_url` names. `None` for a URL that is not one.
fn gitlab_upstream_authority(api_base_url: &str) -> Option<UpstreamAuthority> {
    let trimmed = api_base_url.trim_end_matches('/');
    let instance = trimmed.strip_suffix("/api/v4")?;
    UpstreamAuthority::from_base_url(instance).ok()
}

/// Every GitLab action is authorized against one repository resolved from
/// upstream project metadata before policy.
fn gitlab_read_action(action: &str, description: &str, input_schema: Value) -> ActionDescriptor {
    gitlab_action(action, description, input_schema).read_only()
}

fn gitlab_action(action: &str, description: &str, input_schema: Value) -> ActionDescriptor {
    ActionDescriptor::new(action, description, input_schema)
        .scope("repository")
        .credential_modes(["service", "per_user"])
        .lookup(LookupRequirement::ScopeResolution)
}

fn project_upload_schema(limits: &crate::GitlabUploadLimitsConfig) -> Value {
    let mut schema = project_locator_schema();
    schema["required"] = json!(["attachments"]);
    schema["properties"]["attachments"] = json!({
        "type": "array", "minItems": 1, "maxItems": 1,
        "items": {
            "type": "object", "additionalProperties": false,
            "required": ["field", "filename", "contentType", "size", "sha256"],
            "properties": {
                "field": { "type": "string", "minLength": 1 },
                "filename": { "type": "string", "minLength": 1 },
                "contentType": { "type": "string" },
                "size": { "type": "integer", "minimum": 1,
                    "maximum": limits.max_bytes.min(limits.max_total_bytes) },
                "sha256": { "type": "string", "pattern": "^[0-9a-f]{64}$" }
            }
        }
    });
    if !limits.media_types.is_empty() {
        schema["properties"]["attachments"]["items"]["properties"]["contentType"]["enum"] =
            json!(limits.media_types);
    }
    schema
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct GitlabUploadMetadata {
    field: String,
    filename: String,
    content_type: String,
    size: u64,
    sha256: String,
}

fn parse_project_upload_inputs(
    inputs: &Value,
    config: &GitlabProviderConfig,
) -> Result<(ProjectLocator, BrokerBodyPartSpec), ProviderError> {
    let invalid = || {
        ProviderError::deny(
            ReasonCode::InputInvalid,
            "GitLab project upload inputs are invalid",
        )
    };
    let object = inputs.as_object().ok_or_else(invalid)?;
    reject_unknown_keys(
        object,
        &["project", "url", "attachments"],
        "GitLab project upload inputs are invalid",
    )?;
    let attachments = object
        .get("attachments")
        .and_then(Value::as_array)
        .ok_or_else(invalid)?;
    if attachments.len() != 1 {
        return Err(invalid());
    }
    let metadata: GitlabUploadMetadata =
        serde_json::from_value(attachments[0].clone()).map_err(|_| invalid())?;
    if metadata.field.trim().is_empty()
        || metadata.field.chars().any(char::is_control)
        || metadata.filename.trim().is_empty()
        || metadata.filename == "."
        || metadata.filename == ".."
        || metadata.filename.contains(['/', '\\'])
        || metadata.filename.chars().any(char::is_control)
        || metadata.sha256.len() != 64
        || !metadata
            .sha256
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(invalid());
    }
    if metadata.size == 0
        || metadata.size > config.attachments.max_bytes
        || metadata.size > config.attachments.max_total_bytes
    {
        return Err(ProviderError::deny(
            ReasonCode::AttachmentSizeDenied,
            "GitLab upload exceeded the configured byte cap",
        ));
    }
    if metadata.content_type.trim() != metadata.content_type
        || metadata.content_type.chars().any(char::is_control)
        || reqwest::multipart::Part::bytes(Vec::new())
            .mime_str(&metadata.content_type)
            .is_err()
        || (!config.attachments.media_types.is_empty()
            && !config
                .attachments
                .media_types
                .contains(&metadata.content_type))
    {
        return Err(ProviderError::deny(
            ReasonCode::AttachmentMediaTypeDenied,
            "GitLab upload content type is not allowed",
        ));
    }
    let mut locator = object.clone();
    locator.remove("attachments");
    let locator = parse_project_locator(&Value::Object(locator), config)?;
    Ok((
        locator,
        BrokerBodyPartSpec::new(
            metadata.field,
            metadata.filename,
            metadata.content_type,
            metadata.size,
            metadata.sha256,
        ),
    ))
}

fn ensure_admitted_project(
    project: &GitlabProject,
    scopes: &ResourceScopes,
) -> Result<(), ProviderError> {
    if scopes
        .get("repository")
        .is_some_and(|paths| paths.contains(&project.path_with_namespace))
    {
        return Ok(());
    }
    Err(ProviderError::deny(
        ReasonCode::ScopeUnresolved,
        "GitLab project did not match the authorized repository",
    ))
}

fn prepare_project_upload(
    metadata: &BrokerBodyPartSpec,
    parts: &[BrokerBodyPart],
) -> Result<BrokerBodyPart, ProviderError> {
    if parts.len() != 1
        || parts[0].name != metadata.name
        || parts[0].file_name.as_deref() != Some(metadata.file_name.as_str())
    {
        return Err(ProviderError::deny(
            ReasonCode::BodyMalformed,
            "GitLab upload requires exactly one matching file part",
        ));
    }
    let part = &parts[0];
    if part.content_type.as_deref() != Some(metadata.content_type.as_str()) {
        return Err(ProviderError::deny(
            ReasonCode::AttachmentMediaTypeDenied,
            "GitLab upload content type did not match metadata",
        ));
    }
    if part.size() != metadata.size || part.sha256_hex() != metadata.sha256 {
        return Err(ProviderError::deny(
            ReasonCode::AttachmentIntegrityMismatch,
            "GitLab upload size or sha256 did not match metadata",
        ));
    }
    Ok(part.clone())
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct GitlabProjectUpload {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<u64>,
    pub alt: String,
    pub url: String,
    pub full_path: String,
    pub markdown: String,
}

fn project_upload_from_value(value: Value) -> Result<GitlabProjectUpload, GitlabBackendError> {
    let invalid = || GitlabBackendError::Protocol("GitLab upload response is invalid".to_string());
    let string = |key| {
        value
            .get(key)
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
            .map(str::to_string)
            .ok_or_else(invalid)
    };
    let id = match value.get("id") {
        None => None,
        Some(id) => Some(id.as_u64().filter(|id| *id > 0).ok_or_else(invalid)?),
    };
    Ok(GitlabProjectUpload {
        id,
        alt: string("alt")?,
        url: string("url")?,
        full_path: string("full_path")?,
        markdown: string("markdown")?,
    })
}

fn project_locator_schema() -> Value {
    json!({
        "type": "object",
        "oneOf": [
            { "required": ["project"] },
            { "required": ["url"] }
        ],
        "properties": {
            "project": { "type": "string" },
            "url": { "type": "string" }
        },
        "additionalProperties": false
    })
}

fn issue_view_schema() -> Value {
    json!({
        "type": "object",
        "oneOf": [
            { "required": ["project", "iid"] },
            { "required": ["url"] }
        ],
        "properties": {
            "project": { "type": "string" },
            "iid": { "type": ["integer", "string"] },
            "url": { "type": "string" }
        },
        "additionalProperties": false
    })
}

fn issue_search_schema(max_results: u32) -> Value {
    let mut schema = search_common_schema(
        max_results,
        &["opened", "closed", "all"],
        ISSUE_SEARCH_ORDER_BY,
    );
    let properties = schema["properties"].as_object_mut().expect("schema object");
    let mut labels = string_array_schema();
    labels["description"] = json!("Label names; results must match all supplied labels.");
    properties.insert("labels".to_string(), labels);
    properties.insert(
        "milestone".to_string(),
        json!({ "type": "string", "description": "Milestone title to match." }),
    );
    properties.insert("assignee".to_string(), json!({ "type": "string", "description": "GitLab assignee username, not a numeric user ID." }));
    properties.insert("author".to_string(), json!({ "type": "string", "description": "GitLab author username, not a numeric user ID." }));
    schema
}

fn issue_create_schema() -> Value {
    let mut schema = issue_mutation_schema(false);
    schema["required"] = json!(["project", "title"]);
    schema
}

fn issue_update_schema() -> Value {
    let mut schema = issue_mutation_schema(true);
    schema["required"] = json!(["project", "iid"]);
    schema
}

fn issue_mutation_schema(update: bool) -> Value {
    let mut properties = serde_json::Map::from_iter([
        ("project".to_string(), json!({ "type": "string" })),
        ("title".to_string(), json!({ "type": "string" })),
        ("content".to_string(), json!({ "type": "string" })),
        (
            "contentFormat".to_string(),
            normalized_gitlab_content_format_schema(),
        ),
        ("labels".to_string(), string_array_schema()),
        ("milestone".to_string(), json!({ "type": "string" })),
        ("assignees".to_string(), integer_array_schema()),
        ("confidential".to_string(), json!({ "type": "boolean" })),
    ]);
    if update {
        properties.insert("iid".to_string(), json!({ "type": ["integer", "string"] }));
        properties.insert(
            "stateEvent".to_string(),
            json!({ "type": "string", "enum": ["close", "reopen"] }),
        );
        properties.insert("addLabels".to_string(), string_array_schema());
        properties.insert("removeLabels".to_string(), string_array_schema());
    }
    json!({
        "type": "object",
        "properties": properties,
        "allOf": [optional_content_pair_schema()],
        "additionalProperties": false
    })
}

fn note_list_schema(max_results: u32) -> Value {
    json!({
        "type": "object",
        "required": ["project", "iid"],
        "properties": {
            "project": { "type": "string" },
            "iid": { "type": ["integer", "string"] },
            "maxResults": { "type": "integer", "minimum": 1, "maximum": max_results },
            "pageToken": {
                "type": "string",
                "minLength": 1,
                "maxLength": GITLAB_PAGE_TOKEN_MAX_BYTES
            },
            "sort": { "type": "string", "enum": ["asc", "desc"] },
            "orderBy": { "type": "string", "enum": NOTE_LIST_ORDER_BY },
            "projection": { "type": "string", "enum": ["full", "summary"], "default": "full" }
        },
        "additionalProperties": false
    })
}

fn discussion_list_schema(max_results: u32) -> Value {
    json!({
        "type": "object",
        "required": ["project", "iid"],
        "properties": {
            "project": { "type": "string" },
            "iid": { "type": ["integer", "string"] },
            "maxResults": { "type": "integer", "minimum": 1, "maximum": max_results },
            "pageToken": {
                "type": "string",
                "minLength": 1,
                "maxLength": GITLAB_PAGE_TOKEN_MAX_BYTES
            },
            "projection": { "type": "string", "enum": ["full", "summary"], "default": "full" }
        },
        "additionalProperties": false
    })
}

fn merge_request_collection_schema(max_results: u32, allow_unidiff: bool) -> Value {
    let mut properties = serde_json::Map::from_iter([
        ("project".to_string(), json!({ "type": "string" })),
        ("iid".to_string(), json!({ "type": ["integer", "string"] })),
        (
            "maxResults".to_string(),
            json!({ "type": "integer", "minimum": 1, "maximum": max_results }),
        ),
        (
            "pageToken".to_string(),
            json!({
                "type": "string",
                "minLength": 1,
                "maxLength": GITLAB_PAGE_TOKEN_MAX_BYTES
            }),
        ),
    ]);
    if allow_unidiff {
        properties.insert("unidiff".to_string(), json!({ "type": "boolean" }));
    }
    json!({
        "type": "object",
        "required": ["project", "iid"],
        "properties": properties,
        "additionalProperties": false
    })
}

fn discussion_view_schema() -> Value {
    json!({
        "type": "object",
        "required": ["project", "iid", "discussionId"],
        "properties": {
            "project": { "type": "string" },
            "iid": { "type": ["integer", "string"] },
            "discussionId": { "type": "string", "minLength": 1 }
        },
        "additionalProperties": false
    })
}

fn position_schema() -> Value {
    let path = json!({ "type": "string", "minLength": 1 });
    let positive = json!({ "type": "integer", "minimum": 1 });
    let coordinate = json!({
        "type": "object",
        "properties": { "oldLine": positive, "newLine": positive },
        "additionalProperties": false,
        "anyOf": [
            { "required": ["oldLine"] },
            { "required": ["newLine"] }
        ]
    });
    json!({
        "oneOf": [
            {
                "type": "object",
                "required": ["positionType", "oldPath", "newPath"],
                "properties": {
                    "positionType": { "const": "text" },
                    "oldPath": path,
                    "newPath": path,
                    "oldLine": positive,
                    "newLine": positive
                },
                "additionalProperties": false,
                "anyOf": [
                    { "required": ["oldLine"] },
                    { "required": ["newLine"] }
                ]
            },
            {
                "type": "object",
                "required": ["positionType", "oldPath", "newPath", "lineRange"],
                "properties": {
                    "positionType": { "const": "text" },
                    "oldPath": path,
                    "newPath": path,
                    "lineRange": {
                        "type": "object",
                        "required": ["start", "end"],
                        "properties": { "start": coordinate, "end": coordinate },
                        "additionalProperties": false
                    }
                },
                "additionalProperties": false
            },
            {
                "type": "object",
                "required": ["positionType", "oldPath", "newPath"],
                "properties": {
                    "positionType": { "const": "file" },
                    "oldPath": path,
                    "newPath": path
                },
                "additionalProperties": false
            },
            {
                "type": "object",
                "required": ["positionType", "oldPath", "newPath", "width", "height", "x", "y"],
                "properties": {
                    "positionType": { "const": "image" },
                    "oldPath": path,
                    "newPath": path,
                    "width": positive,
                    "height": positive,
                    "x": { "type": "integer", "minimum": 0 },
                    "y": { "type": "integer", "minimum": 0 }
                },
                "additionalProperties": false
            }
        ]
    })
}

fn positioned_discussion_schema() -> Value {
    json!({
        "type": "object",
        "required": ["project", "iid", "expectedHeadSha", "content", "contentFormat", "position"],
        "properties": {
            "project": { "type": "string" },
            "iid": { "type": ["integer", "string"] },
            "expectedHeadSha": { "type": "string", "pattern": "^[0-9a-fA-F]{40}$" },
            "content": { "type": "string" },
            "contentFormat": normalized_gitlab_content_format_schema(),
            "position": position_schema()
        },
        "additionalProperties": false
    })
}

fn discussion_reply_schema() -> Value {
    json!({
        "type": "object",
        "required": ["project", "iid", "discussionId", "content", "contentFormat"],
        "properties": {
            "project": { "type": "string" },
            "iid": { "type": ["integer", "string"] },
            "discussionId": { "type": "string", "minLength": 1 },
            "content": { "type": "string" },
            "contentFormat": normalized_gitlab_content_format_schema()
        },
        "additionalProperties": false
    })
}

fn draft_note_list_schema(max_results: u32) -> Value {
    json!({
        "type": "object",
        "required": ["project", "iid"],
        "properties": {
            "project": { "type": "string" },
            "iid": { "type": ["integer", "string"] },
            "maxResults": { "type": "integer", "minimum": 1, "maximum": max_results },
            "pageToken": { "type": "string", "minLength": 1, "maxLength": GITLAB_PAGE_TOKEN_MAX_BYTES },
            "projection": { "type": "string", "enum": ["full", "summary"], "default": "full" }
        },
        "additionalProperties": false
    })
}

fn draft_note_object_schema() -> Value {
    numeric_object_schema("draftNoteId")
}

fn draft_note_add_schema() -> Value {
    json!({
        "type": "object",
        "required": ["project", "iid", "content", "contentFormat"],
        "properties": {
            "project": { "type": "string" },
            "iid": { "type": ["integer", "string"] },
            "expectedHeadSha": { "type": "string", "pattern": "^[0-9a-fA-F]{40}$" },
            "content": { "type": "string" },
            "contentFormat": normalized_gitlab_content_format_schema(),
            "position": position_schema(),
            "inReplyToDiscussionId": { "type": "string", "minLength": 1 },
            "resolveDiscussion": { "type": "boolean" }
        },
        "oneOf": [
            {
                "not": { "anyOf": [
                    { "required": ["expectedHeadSha"] },
                    { "required": ["position"] },
                    { "required": ["inReplyToDiscussionId"] },
                    { "required": ["resolveDiscussion"] }
                ] }
            },
            {
                "required": ["expectedHeadSha", "position"],
                "not": { "anyOf": [
                    { "required": ["inReplyToDiscussionId"] },
                    { "required": ["resolveDiscussion"] }
                ] }
            },
            {
                "required": ["inReplyToDiscussionId"],
                "not": { "anyOf": [
                    { "required": ["expectedHeadSha"] },
                    { "required": ["position"] }
                ] }
            }
        ],
        "additionalProperties": false
    })
}

fn draft_note_update_schema() -> Value {
    json!({
        "type": "object",
        "required": ["project", "iid", "draftNoteId"],
        "properties": {
            "project": { "type": "string" },
            "iid": { "type": ["integer", "string"] },
            "draftNoteId": { "type": ["integer", "string"] },
            "expectedHeadSha": { "type": "string", "pattern": "^[0-9a-fA-F]{40}$" },
            "content": { "type": "string" },
            "contentFormat": normalized_gitlab_content_format_schema(),
            "position": position_schema()
        },
        "allOf": [
            {
                "anyOf": [
                    { "required": ["content", "contentFormat"] },
                    { "required": ["expectedHeadSha", "position"] }
                ]
            },
            {
                "anyOf": [
                    { "required": ["content", "contentFormat"] },
                    { "not": { "anyOf": [
                        { "required": ["content"] },
                        { "required": ["contentFormat"] }
                    ] } }
                ]
            },
            {
                "anyOf": [
                    { "required": ["expectedHeadSha", "position"] },
                    { "not": { "anyOf": [
                        { "required": ["expectedHeadSha"] },
                        { "required": ["position"] }
                    ] } }
                ]
            }
        ],
        "additionalProperties": false
    })
}

fn draft_publication_schema(review_submit: bool) -> Value {
    let mut properties = serde_json::Map::from_iter([
        ("project".to_string(), json!({ "type": "string" })),
        ("iid".to_string(), json!({ "type": ["integer", "string"] })),
        ("content".to_string(), json!({ "type": "string" })),
        (
            "contentFormat".to_string(),
            normalized_gitlab_content_format_schema(),
        ),
        ("internal".to_string(), json!({ "type": "boolean" })),
    ]);
    let mut required = vec![json!("project"), json!("iid")];
    if review_submit {
        properties.insert(
            "reviewerState".to_string(),
            json!({ "type": "string", "enum": ["reviewed", "requestedChanges"] }),
        );
        required.push(json!("reviewerState"));
    }
    json!({
        "type": "object",
        "required": required,
        "properties": properties,
        "allOf": [
            optional_content_pair_schema(),
            {
                "anyOf": [
                    { "not": { "required": ["internal"] } },
                    { "required": ["content", "contentFormat"] }
                ]
            }
        ],
        "additionalProperties": false
    })
}

fn merge_request_diff_version_view_schema() -> Value {
    json!({
        "type": "object",
        "required": ["project", "iid", "diffVersionId"],
        "properties": {
            "project": { "type": "string" },
            "iid": { "type": ["integer", "string"] },
            "diffVersionId": { "type": ["integer", "string"] },
            "unidiff": { "type": "boolean" }
        },
        "additionalProperties": false
    })
}

fn issue_note_add_schema() -> Value {
    let mut schema = note_add_schema();
    let properties = schema["properties"].as_object_mut().expect("schema object");
    properties.insert("confidential".to_string(), json!({ "type": "boolean" }));
    schema
}

fn note_add_schema() -> Value {
    json!({
        "type": "object",
        "required": ["project", "iid", "content", "contentFormat"],
        "properties": {
            "project": { "type": "string" },
            "iid": { "type": ["integer", "string"] },
            "content": { "type": "string" },
            "contentFormat": normalized_gitlab_content_format_schema()
        },
        "additionalProperties": false
    })
}

fn note_update_schema() -> Value {
    json!({
        "type": "object",
        "required": ["project", "iid", "noteId", "content", "contentFormat"],
        "properties": {
            "project": { "type": "string" },
            "iid": { "type": ["integer", "string"] },
            "noteId": { "type": ["integer", "string"] },
            "content": { "type": "string" },
            "contentFormat": normalized_gitlab_content_format_schema()
        },
        "additionalProperties": false
    })
}

fn note_delete_schema() -> Value {
    json!({
        "type": "object",
        "required": ["project", "iid", "noteId"],
        "properties": {
            "project": { "type": "string" },
            "iid": { "type": ["integer", "string"] },
            "noteId": { "type": ["integer", "string"] }
        },
        "additionalProperties": false
    })
}

fn discussion_note_update_schema() -> Value {
    json!({
        "type": "object",
        "required": ["project", "iid", "discussionId", "noteId", "content", "contentFormat"],
        "properties": {
            "project": { "type": "string" },
            "iid": { "type": ["integer", "string"] },
            "discussionId": { "type": "string" },
            "noteId": { "type": ["integer", "string"] },
            "content": { "type": "string" },
            "contentFormat": normalized_gitlab_content_format_schema()
        },
        "additionalProperties": false
    })
}

fn discussion_note_delete_schema() -> Value {
    json!({
        "type": "object",
        "required": ["project", "iid", "discussionId", "noteId"],
        "properties": {
            "project": { "type": "string" },
            "iid": { "type": ["integer", "string"] },
            "discussionId": { "type": "string" },
            "noteId": { "type": ["integer", "string"] }
        },
        "additionalProperties": false
    })
}

fn discussion_state_change_schema() -> Value {
    json!({
        "type": "object",
        "required": ["project", "iid", "discussionId"],
        "properties": {
            "project": { "type": "string" },
            "iid": { "type": ["integer", "string"] },
            "discussionId": { "type": "string" }
        },
        "additionalProperties": false
    })
}

fn merge_request_view_schema() -> Value {
    issue_view_schema()
}

fn merge_request_subresource_schema() -> Value {
    json!({
        "type": "object",
        "required": ["project", "iid"],
        "properties": {
            "project": { "type": "string" },
            "iid": { "type": ["integer", "string"] }
        },
        "additionalProperties": false
    })
}

fn merge_request_approval_rule_view_schema() -> Value {
    json!({
        "type": "object",
        "required": ["project", "iid", "approvalRuleId"],
        "properties": {
            "project": { "type": "string" },
            "iid": { "type": ["integer", "string"] },
            "approvalRuleId": { "type": ["integer", "string"] }
        },
        "additionalProperties": false
    })
}

fn merge_request_approve_schema() -> Value {
    json!({
        "type": "object",
        "required": ["project", "iid", "headSha"],
        "properties": {
            "project": { "type": "string" },
            "iid": { "type": ["integer", "string"] },
            "headSha": { "type": "string", "pattern": "^[0-9a-fA-F]{40}$" }
        },
        "additionalProperties": false
    })
}

fn suggestion_apply_schema(batch: bool, max_body_bytes: u64) -> Value {
    let locator = json!({
        "type": "object",
        "required": ["discussionId", "noteId", "suggestionId"],
        "properties": {
            "discussionId": { "type": "string", "minLength": 1 },
            "noteId": { "type": ["integer", "string"] },
            "suggestionId": { "type": ["integer", "string"] }
        },
        "additionalProperties": false
    });
    let mut properties = serde_json::Map::from_iter([
        ("project".to_string(), json!({ "type": "string" })),
        ("iid".to_string(), json!({ "type": ["integer", "string"] })),
        (
            "expectedHeadSha".to_string(),
            json!({ "type": "string", "pattern": "^[0-9a-fA-F]{40}$" }),
        ),
        (
            "commitMessage".to_string(),
            json!({ "type": "string", "maxLength": max_body_bytes }),
        ),
    ]);
    let required = if batch {
        properties.insert(
            "suggestions".to_string(),
            json!({
                "type": "array", "minItems": 1, "maxItems": GITLAB_MAX_SUGGESTIONS_PER_APPLY,
                "uniqueItems": true,
                "items": locator
            }),
        );
        json!(["project", "iid", "expectedHeadSha", "suggestions"])
    } else {
        for (key, value) in locator["properties"]
            .as_object()
            .expect("locator properties")
        {
            properties.insert(key.clone(), value.clone());
        }
        json!([
            "project",
            "iid",
            "expectedHeadSha",
            "discussionId",
            "noteId",
            "suggestionId"
        ])
    };
    json!({
        "type": "object",
        "required": required,
        "properties": properties,
        "additionalProperties": false
    })
}

fn merge_request_search_schema(max_results: u32) -> Value {
    let mut schema = search_common_schema(
        max_results,
        &["opened", "closed", "locked", "merged", "all"],
        MERGE_REQUEST_SEARCH_ORDER_BY,
    );
    let properties = schema["properties"].as_object_mut().expect("schema object");
    properties.insert(
        "sourceBranch".to_string(),
        json!({ "type": "string", "description": "Exact source branch name." }),
    );
    properties.insert(
        "targetBranch".to_string(),
        json!({ "type": "string", "description": "Exact target branch name." }),
    );
    let mut labels = string_array_schema();
    labels["description"] = json!("Label names; results must match all supplied labels.");
    properties.insert("labels".to_string(), labels);
    properties.insert(
        "milestone".to_string(),
        json!({ "type": "string", "description": "Milestone title to match." }),
    );
    properties.insert("assignee".to_string(), json!({ "type": "string", "description": "GitLab assignee username, not a numeric user ID." }));
    properties.insert("author".to_string(), json!({ "type": "string", "description": "GitLab author username, not a numeric user ID." }));
    properties.insert("reviewer".to_string(), json!({ "type": "string", "description": "GitLab reviewer username, not a numeric user ID." }));
    schema
}

fn merge_request_create_schema() -> Value {
    let mut schema = merge_request_mutation_schema(false);
    schema["required"] = json!(["project", "sourceBranch", "targetBranch", "title"]);
    schema
}

fn merge_request_update_schema() -> Value {
    let mut schema = merge_request_mutation_schema(true);
    schema["required"] = json!(["project", "iid"]);
    schema
}

fn merge_request_merge_schema(max_body_bytes: u64) -> Value {
    json!({
        "type": "object",
        "required": ["project", "iid", "sha"],
        "properties": {
            "project": { "type": "string" },
            "iid": { "type": ["integer", "string"] },
            "sha": { "type": "string" },
            "squash": { "type": "boolean" },
            "shouldRemoveSourceBranch": { "type": "boolean" },
            "mergeCommitMessage": { "type": "string", "maxLength": max_body_bytes },
            "squashCommitMessage": { "type": "string", "maxLength": max_body_bytes }
        },
        "additionalProperties": false
    })
}

fn merge_request_mutation_schema(update: bool) -> Value {
    let mut properties = serde_json::Map::from_iter([
        ("project".to_string(), json!({ "type": "string" })),
        ("targetBranch".to_string(), json!({ "type": "string" })),
        ("title".to_string(), json!({ "type": "string" })),
        ("content".to_string(), json!({ "type": "string" })),
        (
            "contentFormat".to_string(),
            normalized_gitlab_content_format_schema(),
        ),
        ("labels".to_string(), string_array_schema()),
        ("assignees".to_string(), integer_array_schema()),
        ("reviewers".to_string(), integer_array_schema()),
        (
            "removeSourceBranch".to_string(),
            json!({ "type": "boolean" }),
        ),
        ("squash".to_string(), json!({ "type": "boolean" })),
    ]);
    if update {
        properties.insert("iid".to_string(), json!({ "type": ["integer", "string"] }));
        properties.insert(
            "stateEvent".to_string(),
            json!({ "type": "string", "enum": ["close", "reopen"] }),
        );
        properties.insert("addLabels".to_string(), string_array_schema());
        properties.insert("removeLabels".to_string(), string_array_schema());
    } else {
        properties.insert("sourceBranch".to_string(), json!({ "type": "string" }));
        properties.insert("draft".to_string(), json!({ "type": "boolean" }));
    }
    json!({
        "type": "object",
        "properties": properties,
        "allOf": [optional_content_pair_schema()],
        "additionalProperties": false
    })
}

fn normalized_gitlab_content_format_schema() -> Value {
    json!({ "type": "string", "enum": ["markdown", "plain_text"] })
}

fn optional_content_pair_schema() -> Value {
    json!({
        "anyOf": [
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
    })
}

/// Discovery guidance for project-local REST collections, not a query-language parser.
fn gitlab_search_documentation(merge_requests: bool, max_results: u32) -> Value {
    let schema = if merge_requests {
        merge_request_search_schema(max_results)
    } else {
        issue_search_schema(max_results)
    };
    let mut filtered = json!({
        "project": "team/service", "state": "opened", "search": "deployment",
        "updatedAfter": "2026-01-01T00:00:00Z", "orderBy": "updated_at", "sort": "desc"
    });
    if merge_requests {
        filtered["targetBranch"] = json!("main");
    }
    json!({
        "scope": "Exactly one canonical namespace/repository project path is required. Exact, namespace, and all-repository grants authorize that project; they do not select projects or turn this action into a global search. Token restrictions and exclusions still apply. The broker confirms upstream project metadata before authorization and checks returned items belong to that project.",
        "query": "This action uses structured REST filters, not JQL, CQL, or a broker query language. search matches title and description text. Omit search and any unwanted filters to list project items. Sorting uses orderBy and sort. User filters take usernames; milestone takes a title; labels are combined as an all-labels filter.",
        "states": schema["properties"]["state"]["enum"],
        "orderBy": schema["properties"]["orderBy"]["enum"],
        "sort": schema["properties"]["sort"]["enum"],
        "dates": "createdAfter and updatedAfter are inclusive ISO 8601 timestamps, for example 2026-01-01T00:00:00Z. Jira relative dates and date functions are not supported here.",
        "pagination": {
            "maxResults": max_results,
            "requestTokenField": "pageToken", "responseTokenField": "nextPageToken",
            "tokenLifetimeMinutes": GITLAB_PAGE_TOKEN_TTL_MINUTES,
            "continuation": "Pass nextPageToken as pageToken with the same action, project, filters, sort, and maxResults. Tokens are signed and bound to the execution context, principal, credential mode, confirmed project, and provider endpoint; each request is reauthorized. isLast indicates completion. Upstream offset pagination is not snapshot-isolated."
        },
        "examples": [
            {"project": "team/service"},
            {"project": "team/service", "orderBy": "updated_at", "sort": "desc"},
            filtered
        ]
    })
}

fn search_common_schema(max_results: u32, states: &[&str], order_by: &[&str]) -> Value {
    json!({
        "type": "object",
        "required": ["project"],
        "properties": {
            "project": { "type": "string", "description": "Required canonical namespace/repository path, even with all-repository access. Numeric IDs and project URLs are not search locators." },
            "state": { "type": "string", "enum": states, "description": "Filter by lifecycle state; all includes every state." },
            "search": { "type": "string", "description": "Optional text matched against titles and descriptions. Omit to browse without a text filter; supply filters and sorting in their separate fields." },
            "createdAfter": { "type": "string", "description": "Created on or after this ISO 8601 timestamp, e.g. 2026-01-01T00:00:00Z." },
            "updatedAfter": { "type": "string", "description": "Updated on or after this ISO 8601 timestamp, e.g. 2026-01-01T00:00:00Z." },
            "sort": { "type": "string", "enum": ["asc", "desc"], "description": "Sort direction for orderBy; GitLab defaults to desc." },
            "orderBy": { "type": "string", "enum": order_by, "description": "Sort field from this action's supported set; GitLab defaults to created_at." },
            "maxResults": { "type": "integer", "minimum": 1, "maximum": max_results, "description": "Requested page size, capped by broker configuration." },
            "pageToken": {
                "type": "string",
                "minLength": 1,
                "maxLength": GITLAB_PAGE_TOKEN_MAX_BYTES,
                "description": "Pass the previous response's nextPageToken, retaining the same project, filters, sorting, and maxResults."
            }
        },
        "additionalProperties": false
    })
}

fn branch_list_schema(max_results: u32) -> Value {
    json!({
        "type": "object",
        "required": ["project"],
        "properties": {
            "project": { "type": "string" },
            "search": { "type": "string" },
            "regex": { "type": "string" },
            "maxResults": { "type": "integer", "minimum": 1, "maximum": max_results }
        },
        "additionalProperties": false
    })
}

fn branch_view_schema() -> Value {
    json!({
        "type": "object",
        "required": ["project", "branch"],
        "properties": {
            "project": { "type": "string" },
            "branch": { "type": "string" }
        },
        "additionalProperties": false
    })
}

fn branch_create_schema() -> Value {
    json!({
        "type": "object",
        "required": ["project", "branch", "ref"],
        "properties": {
            "project": { "type": "string" },
            "branch": { "type": "string" },
            "ref": { "type": "string" }
        },
        "additionalProperties": false
    })
}

fn protected_branch_list_schema(max_results: u32) -> Value {
    json!({
        "type": "object",
        "required": ["project"],
        "properties": {
            "project": { "type": "string" },
            "search": { "type": "string" },
            "maxResults": { "type": "integer", "minimum": 1, "maximum": max_results }
        },
        "additionalProperties": false
    })
}

fn protected_branch_view_schema() -> Value {
    json!({
        "type": "object",
        "required": ["project", "branchOrWildcardName"],
        "properties": {
            "project": { "type": "string" },
            "branchOrWildcardName": { "type": "string" }
        },
        "additionalProperties": false
    })
}

fn protected_branch_verify_schema() -> Value {
    json!({
        "type": "object",
        "required": ["project"],
        "properties": {
            "project": { "type": "string" },
            "requiredPatterns": string_array_schema()
        },
        "additionalProperties": false
    })
}

fn file_view_schema() -> Value {
    json!({
        "type": "object",
        "required": ["project", "path", "ref"],
        "properties": {
            "project": { "type": "string" },
            "path": { "type": "string" },
            "ref": { "type": "string" }
        },
        "additionalProperties": false
    })
}

fn file_create_schema() -> Value {
    let mut schema = file_write_schema(true);
    schema["required"] = json!(["project", "path", "branch", "content", "commitMessage"]);
    schema
}

fn file_update_schema() -> Value {
    let mut schema = file_write_schema(true);
    schema["required"] = json!(["project", "path", "branch", "content", "commitMessage"]);
    schema["properties"]
        .as_object_mut()
        .expect("schema properties")
        .insert("lastCommitId".to_string(), json!({ "type": "string" }));
    schema
}

fn file_delete_schema() -> Value {
    json!({
        "type": "object",
        "required": ["project", "path", "branch", "commitMessage"],
        "properties": {
            "project": { "type": "string" },
            "path": { "type": "string" },
            "branch": { "type": "string" },
            "commitMessage": { "type": "string" },
            "startBranch": { "type": "string" },
            "authorName": { "type": "string" },
            "authorEmail": { "type": "string" },
            "lastCommitId": { "type": "string" }
        },
        "additionalProperties": false
    })
}

fn file_write_schema(include_execute_filemode: bool) -> Value {
    let mut properties = serde_json::Map::from_iter([
        ("project".to_string(), json!({ "type": "string" })),
        ("path".to_string(), json!({ "type": "string" })),
        ("branch".to_string(), json!({ "type": "string" })),
        ("content".to_string(), json!({ "type": "string" })),
        ("commitMessage".to_string(), json!({ "type": "string" })),
        ("startBranch".to_string(), json!({ "type": "string" })),
        ("authorName".to_string(), json!({ "type": "string" })),
        ("authorEmail".to_string(), json!({ "type": "string" })),
        (
            "encoding".to_string(),
            json!({ "type": "string", "enum": ["text", "base64"] }),
        ),
    ]);
    if include_execute_filemode {
        properties.insert("executeFilemode".to_string(), json!({ "type": "boolean" }));
    }
    json!({
        "type": "object",
        "properties": properties,
        "additionalProperties": false
    })
}

fn commit_list_schema(max_results: u32) -> Value {
    json!({
        "type": "object",
        "required": ["project"],
        "properties": {
            "project": { "type": "string" },
            "refName": { "type": "string" },
            "path": { "type": "string" },
            "since": { "type": "string" },
            "until": { "type": "string" },
            "firstParent": { "type": "boolean" },
            "maxResults": { "type": "integer", "minimum": 1, "maximum": max_results }
        },
        "additionalProperties": false
    })
}

fn commit_view_schema() -> Value {
    json!({
        "type": "object",
        "required": ["project", "sha"],
        "properties": {
            "project": { "type": "string" },
            "sha": { "type": "string" }
        },
        "additionalProperties": false
    })
}

fn commit_create_schema(max_actions: u32) -> Value {
    json!({
        "type": "object",
        "required": ["project", "branch", "commitMessage", "actions"],
        "properties": {
            "project": { "type": "string" },
            "branch": { "type": "string" },
            "commitMessage": { "type": "string" },
            "startBranch": { "type": "string" },
            "startSha": { "type": "string" },
            "authorName": { "type": "string" },
            "authorEmail": { "type": "string" },
            "actions": {
                "type": "array",
                "minItems": 1,
                "maxItems": max_actions,
                "items": {
                    "type": "object",
                    "required": ["action", "filePath"],
                    "properties": {
                        "action": { "type": "string", "enum": GITLAB_COMMIT_ACTIONS },
                        "filePath": { "type": "string" },
                        "previousPath": { "type": "string" },
                        "content": { "type": "string" },
                        "encoding": { "type": "string", "enum": ["text", "base64"] },
                        "executeFilemode": { "type": "boolean" },
                        "lastCommitId": { "type": "string" }
                    },
                    "additionalProperties": false
                }
            }
        },
        "additionalProperties": false
    })
}

fn pipeline_list_schema(max_results: u32) -> Value {
    json!({
        "type": "object",
        "required": ["project"],
        "properties": {
            "project": { "type": "string" },
            "ref": { "type": "string" },
            "sha": { "type": "string" },
            "status": { "type": "string", "enum": GITLAB_PIPELINE_STATUSES },
            "source": { "type": "string" },
            "updatedAfter": { "type": "string" },
            "updatedBefore": { "type": "string" },
            "maxResults": { "type": "integer", "minimum": 1, "maximum": max_results }
        },
        "additionalProperties": false
    })
}

fn pipeline_object_schema(id_field: &str) -> Value {
    numeric_object_schema(id_field)
}

fn pipeline_run_schema() -> Value {
    json!({
        "type": "object",
        "required": ["project", "ref"],
        "properties": {
            "project": { "type": "string" },
            "ref": { "type": "string" }
        },
        "additionalProperties": false
    })
}

fn job_list_schema(max_results: u32) -> Value {
    json!({
        "type": "object",
        "required": ["project"],
        "properties": {
            "project": { "type": "string" },
            "pipelineId": { "type": ["integer", "string"] },
            "scope": { "type": "string", "enum": GITLAB_JOB_SCOPES },
            "maxResults": { "type": "integer", "minimum": 1, "maximum": max_results }
        },
        "additionalProperties": false
    })
}

fn job_object_schema(id_field: &str) -> Value {
    numeric_object_schema(id_field)
}

fn numeric_object_schema(id_field: &str) -> Value {
    let mut properties =
        serde_json::Map::from_iter([("project".to_string(), json!({ "type": "string" }))]);
    properties.insert(
        id_field.to_string(),
        json!({ "type": ["integer", "string"] }),
    );
    json!({
        "type": "object",
        "required": ["project", id_field],
        "properties": properties,
        "additionalProperties": false
    })
}

fn sensitive_string_schema() -> Value {
    json!({ "type": "string", "x-agent-access-sensitive": true })
}

fn webhook_event_schema() -> Value {
    json!({ "type": "string", "enum": GitlabWebhookEvent::ALL })
}

fn webhook_test_event_schema() -> Value {
    let events = GitlabWebhookEvent::ALL
        .into_iter()
        .filter(|value| {
            let event: GitlabWebhookEvent =
                serde_json::from_value(json!(value)).expect("static webhook event is valid");
            event.test_trigger().is_some()
        })
        .collect::<Vec<_>>();
    json!({ "type": "string", "enum": events })
}

fn webhook_mutable_properties() -> serde_json::Map<String, Value> {
    serde_json::Map::from_iter([
        ("url".to_string(), json!({ "type": "string" })),
        (
            "events".to_string(),
            json!({ "type": "array", "items": webhook_event_schema(), "uniqueItems": true }),
        ),
        ("name".to_string(), json!({ "type": ["string", "null"] })),
        (
            "description".to_string(),
            json!({ "type": ["string", "null"] }),
        ),
        (
            "enableSslVerification".to_string(),
            json!({ "type": "boolean" }),
        ),
        (
            "branchFilterStrategy".to_string(),
            json!({ "type": "string", "enum": ["wildcard", "regex", "all_branches"] }),
        ),
        (
            "pushEventsBranchFilter".to_string(),
            json!({ "type": "string" }),
        ),
        (
            "customWebhookTemplate".to_string(),
            json!({ "type": ["string", "null"] }),
        ),
        ("token".to_string(), sensitive_string_schema()),
        (
            "signingToken".to_string(),
            json!({
                "type": "string",
                "pattern": "^whsec_[A-Za-z0-9+/]{43}=$",
                "maxLength": 50,
                "x-agent-access-sensitive": true
            }),
        ),
    ])
}

fn webhook_list_schema(max_results: u32) -> Value {
    json!({
        "type": "object",
        "required": ["project"],
        "properties": {
            "project": { "type": "string" },
            "maxResults": { "type": "integer", "minimum": 1, "maximum": max_results },
            "pageToken": { "type": "string", "minLength": 1, "maxLength": GITLAB_PAGE_TOKEN_MAX_BYTES }
        },
        "additionalProperties": false
    })
}

fn webhook_object_schema() -> Value {
    json!({
        "type": "object",
        "required": ["project", "webhookId"],
        "properties": {
            "project": { "type": "string" },
            "webhookId": { "type": "integer", "minimum": 1 }
        },
        "additionalProperties": false
    })
}

fn webhook_create_schema() -> Value {
    let mut properties = webhook_mutable_properties();
    properties.insert("project".to_string(), json!({ "type": "string" }));
    json!({
        "type": "object",
        "required": ["project", "url", "events"],
        "properties": properties,
        "additionalProperties": false
    })
}

fn webhook_update_schema() -> Value {
    let mut properties = webhook_mutable_properties();
    properties.insert("project".to_string(), json!({ "type": "string" }));
    properties.insert(
        "webhookId".to_string(),
        json!({ "type": "integer", "minimum": 1 }),
    );
    properties.insert(
        "clearToken".to_string(),
        json!({ "type": "boolean", "const": true }),
    );
    properties.insert(
        "confirmDestinationReset".to_string(),
        json!({ "type": "boolean" }),
    );
    json!({
        "type": "object",
        "required": ["project", "webhookId"],
        "properties": properties,
        "allOf": [
            { "not": { "required": ["token", "clearToken"] } },
            { "anyOf": [
                { "required": ["url"] }, { "required": ["events"] },
                { "required": ["name"] }, { "required": ["description"] },
                { "required": ["enableSslVerification"] },
                { "required": ["branchFilterStrategy"] },
                { "required": ["pushEventsBranchFilter"] },
                { "required": ["customWebhookTemplate"] }, { "required": ["token"] },
                { "required": ["signingToken"] }, { "required": ["clearToken"] }
            ] }
        ],
        "additionalProperties": false
    })
}

fn webhook_test_schema() -> Value {
    json!({
        "type": "object",
        "required": ["project", "webhookId", "event"],
        "properties": {
            "project": { "type": "string" },
            "webhookId": { "type": "integer", "minimum": 1 },
            "event": webhook_test_event_schema()
        },
        "additionalProperties": false
    })
}

fn webhook_event_list_schema() -> Value {
    json!({
        "type": "object",
        "required": ["project", "webhookId"],
        "properties": {
            "project": { "type": "string" },
            "webhookId": { "type": "integer", "minimum": 1 },
            "status": {
                "oneOf": [
                    { "type": "string", "enum": ["successful", "client_failure", "server_failure"] },
                    { "type": "string", "pattern": "^[0-9]{3}$" }
                ]
            },
            "maxResults": { "type": "integer", "minimum": 1, "maximum": GITLAB_WEBHOOK_EVENT_MAX_PER_PAGE },
            "pageToken": { "type": "string", "minLength": 1, "maxLength": GITLAB_PAGE_TOKEN_MAX_BYTES }
        },
        "additionalProperties": false
    })
}

fn webhook_event_resend_schema() -> Value {
    json!({
        "type": "object",
        "required": ["project", "webhookId", "webhookEventId"],
        "properties": {
            "project": { "type": "string" },
            "webhookId": { "type": "integer", "minimum": 1 },
            "webhookEventId": { "type": "integer", "minimum": 1 }
        },
        "additionalProperties": false
    })
}

fn webhook_custom_header_schema(set: bool) -> Value {
    let mut properties = serde_json::Map::from_iter([
        ("project".to_string(), json!({ "type": "string" })),
        (
            "webhookId".to_string(),
            json!({ "type": "integer", "minimum": 1 }),
        ),
        ("key".to_string(), json!({ "type": "string" })),
    ]);
    if set {
        properties.insert("value".to_string(), sensitive_string_schema());
    }
    json!({
        "type": "object",
        "required": if set { json!(["project", "webhookId", "key", "value"]) } else { json!(["project", "webhookId", "key"]) },
        "properties": properties,
        "additionalProperties": false
    })
}

fn string_array_schema() -> Value {
    json!({ "type": "array", "items": { "type": "string" }, "minItems": 1 })
}

fn integer_array_schema() -> Value {
    json!({ "type": "array", "items": { "type": ["integer", "string"] }, "minItems": 1 })
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ProjectLocator {
    project: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct IssueViewInputs {
    iid: u64,
}

#[derive(Debug, Clone, PartialEq)]
struct PositionedDiscussionInputs {
    iid: u64,
    expected_head_sha: String,
    body: String,
    position: GitlabPositionInput,
}

#[derive(Debug, Clone, PartialEq)]
struct DraftNoteAddInputs {
    iid: u64,
    expected_head_sha: Option<String>,
    body: String,
    position: Option<GitlabPositionInput>,
    in_reply_to_discussion_id: Option<String>,
    resolve_discussion: Option<bool>,
}

#[derive(Debug, Clone, PartialEq)]
struct DraftNoteUpdateInputs {
    iid: u64,
    draft_note_id: u64,
    expected_head_sha: Option<String>,
    body: Option<String>,
    position: Option<GitlabPositionInput>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct DraftPublicationInputs {
    iid: u64,
    summary: Option<String>,
    internal: Option<bool>,
    reviewer_state: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SearchInputs {
    state: Option<String>,
    labels: Vec<String>,
    milestone: Option<String>,
    assignee: Option<String>,
    author: Option<String>,
    reviewer: Option<String>,
    source_branch: Option<String>,
    target_branch: Option<String>,
    search: Option<String>,
    created_after: Option<String>,
    updated_after: Option<String>,
    sort: Option<String>,
    order_by: Option<String>,
    max_results: Option<u32>,
    page_token: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct BranchListInputs {
    search: Option<String>,
    regex: Option<String>,
    max_results: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct BranchViewInputs {
    branch: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ProtectedBranchViewInputs {
    name: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ProtectedBranchVerifyInputs {
    required_patterns: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct FileViewInputs {
    path: String,
    ref_name: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct GitlabBranchSafety {
    branch: String,
    default_branch: Option<String>,
    target_branch_exists: bool,
    existing_branch_default: Option<bool>,
    existing_branch_protected: Option<bool>,
    matched_protected_branch: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct CommitListInputs {
    ref_name: Option<String>,
    path: Option<String>,
    since: Option<String>,
    until: Option<String>,
    first_parent: Option<bool>,
    max_results: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct CommitViewInputs {
    sha: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PipelineListInputs {
    ref_name: Option<String>,
    sha: Option<String>,
    status: Option<String>,
    source: Option<String>,
    updated_after: Option<String>,
    updated_before: Option<String>,
    max_results: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PipelineObjectInputs {
    pipeline_id: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct JobListInputs {
    pipeline_id: Option<u64>,
    scope: Option<String>,
    max_results: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct JobObjectInputs {
    job_id: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct WebhookListInputs {
    max_results: u32,
    page_token: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct WebhookObjectInputs {
    webhook_id: u64,
}

#[derive(Debug, Clone, PartialEq)]
struct WebhookWriteInputs {
    webhook_id: Option<u64>,
    url: Option<String>,
    events: Option<Vec<GitlabWebhookEvent>>,
    name: Option<Option<String>>,
    description: Option<Option<String>>,
    enable_ssl_verification: Option<bool>,
    branch_filter_strategy: Option<String>,
    push_events_branch_filter: Option<String>,
    custom_webhook_template: Option<Option<String>>,
    token: Option<String>,
    signing_token: Option<String>,
    clear_token: bool,
    confirm_destination_reset: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct WebhookTestInputs {
    webhook_id: u64,
    event: GitlabWebhookEvent,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct WebhookEventListInputs {
    webhook_id: u64,
    status: Option<String>,
    max_results: u32,
    page_token: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct WebhookEventResendInputs {
    webhook_id: u64,
    webhook_event_id: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct GitlabCiRefSafety {
    ref_name: String,
    default_branch: Option<String>,
    existing_branch_default: Option<bool>,
    existing_branch_protected: Option<bool>,
    matched_protected_branch: Option<String>,
    denial_reason: Option<String>,
}

fn project_locator_for_action(
    action: &str,
    inputs: &Value,
    config: &GitlabProviderConfig,
) -> Result<ProjectLocator, ProviderError> {
    if PROVISIONING_ACTIONS.contains(&action) {
        return parse_required_project_locator(inputs);
    }
    match action {
        "project.view" => parse_project_locator(inputs, config),
        "project.upload" => parse_project_upload_inputs(inputs, config).map(|(locator, _)| locator),
        "issue.view" => parse_issue_locator(inputs, config).map(|(project, _)| project),
        "merge_request.view" => {
            parse_merge_request_locator(inputs, config).map(|(project, _)| project)
        }
        "issue.search"
        | "issue.create"
        | "issue.update"
        | "issue.note.list"
        | "issue.note.view"
        | "issue.note.add"
        | "issue.note.update"
        | "issue.note.delete"
        | "merge_request.search"
        | "merge_request.create"
        | "merge_request.update"
        | "merge_request.note.list"
        | "merge_request.note.view"
        | "merge_request.note.add"
        | "merge_request.note.update"
        | "merge_request.note.delete"
        | "merge_request.discussion.list"
        | "merge_request.discussion.view"
        | "merge_request.discussion.inline.add"
        | "merge_request.discussion.note.add"
        | "merge_request.draft_note.list"
        | "merge_request.draft_note.view"
        | "merge_request.draft_note.add"
        | "merge_request.draft_note.update"
        | "merge_request.draft_note.delete"
        | "merge_request.draft_note.publish"
        | "merge_request.draft_note.publish_all"
        | "merge_request.review.submit"
        | "merge_request.reviewer.list"
        | "merge_request.approval.view"
        | "merge_request.approval_state.view"
        | "merge_request.approval_rule.list"
        | "merge_request.approval_rule.view"
        | "merge_request.approve"
        | "merge_request.unapprove"
        | "merge_request.suggestion.apply"
        | "merge_request.suggestion.batch_apply"
        | "merge_request.commit.list"
        | "merge_request.pipeline.list"
        | "merge_request.diff.list"
        | "merge_request.diff.raw.download"
        | "merge_request.diff_version.list"
        | "merge_request.diff_version.view"
        | "merge_request.discussion.add"
        | "merge_request.discussion.note.update"
        | "merge_request.discussion.note.delete"
        | "merge_request.discussion.resolve"
        | "merge_request.discussion.reopen"
        | "merge_request.merge"
        | "branch.list"
        | "branch.view"
        | "branch.create"
        | "protected_branch.list"
        | "protected_branch.view"
        | "protected_branch.verify"
        | "file.view"
        | "file.raw.download"
        | "file.create"
        | "file.update"
        | "file.delete"
        | "commit.list"
        | "commit.view"
        | "commit.create"
        | "pipeline.list"
        | "pipeline.view"
        | "pipeline.run"
        | "pipeline.retry"
        | "pipeline.cancel"
        | "job.list"
        | "job.view"
        | "job.trace.download"
        | "job.retry"
        | "job.cancel"
        | "job.play"
        | "webhook.list"
        | "webhook.view"
        | "webhook.create"
        | "webhook.update"
        | "webhook.delete"
        | "webhook.test"
        | "webhook.event.list"
        | "webhook.event.resend"
        | "webhook.custom_header.set"
        | "webhook.custom_header.delete" => parse_required_project_locator(inputs),
        _ => Err(ProviderError::deny(
            ReasonCode::ServiceActionDenied,
            "GitLab action is not supported",
        )),
    }
}

fn parse_project_locator(
    inputs: &Value,
    config: &GitlabProviderConfig,
) -> Result<ProjectLocator, ProviderError> {
    let object = input_object(inputs, "gitlab project.view inputs are invalid")?;
    reject_unknown_keys(
        object,
        &["project", "url"],
        "gitlab project.view inputs are invalid",
    )?;
    match (object.get("project"), object.get("url")) {
        (Some(project), None) => Ok(ProjectLocator {
            project: normalize_project_path(required_input_string(project, "project")?)?,
        }),
        (None, Some(url)) => Ok(ProjectLocator {
            project: project_path_from_web_url(required_input_string(url, "url")?, config)?,
        }),
        _ => Err(ProviderError::deny(
            ReasonCode::InputInvalid,
            "gitlab project.view requires exactly one of project or url",
        )),
    }
}

fn parse_required_project_locator(inputs: &Value) -> Result<ProjectLocator, ProviderError> {
    let object = input_object(inputs, "gitlab inputs are invalid")?;
    let project = object
        .get("project")
        .ok_or_else(|| ProviderError::deny(ReasonCode::InputInvalid, "project is required"))?;
    Ok(ProjectLocator {
        project: normalize_project_path(required_input_string(project, "project")?)?,
    })
}

fn parse_issue_locator(
    inputs: &Value,
    config: &GitlabProviderConfig,
) -> Result<(ProjectLocator, u64), ProviderError> {
    parse_numbered_object_locator(
        inputs,
        config,
        "issues",
        "gitlab issue.view inputs are invalid",
    )
}

fn parse_merge_request_locator(
    inputs: &Value,
    config: &GitlabProviderConfig,
) -> Result<(ProjectLocator, u64), ProviderError> {
    parse_numbered_object_locator(
        inputs,
        config,
        "merge_requests",
        "gitlab merge_request.view inputs are invalid",
    )
}

fn parse_numbered_object_locator(
    inputs: &Value,
    config: &GitlabProviderConfig,
    object_path_segment: &str,
    error_message: &'static str,
) -> Result<(ProjectLocator, u64), ProviderError> {
    let object = input_object(inputs, error_message)?;
    reject_unknown_keys(object, &["project", "iid", "url"], error_message)?;
    match (object.get("project"), object.get("iid"), object.get("url")) {
        (Some(project), Some(iid), None) => Ok((
            ProjectLocator {
                project: normalize_project_path(required_input_string(project, "project")?)?,
            },
            required_input_u64(iid, "iid")?,
        )),
        (None, None, Some(url)) => {
            let (project, iid) = numbered_object_from_web_url(
                required_input_string(url, "url")?,
                config,
                object_path_segment,
            )?;
            Ok((ProjectLocator { project }, iid))
        }
        _ => Err(ProviderError::deny(
            ReasonCode::InputInvalid,
            "gitlab object view requires either project+iid or url",
        )),
    }
}

fn parse_issue_view_inputs(
    inputs: &Value,
    config: &GitlabProviderConfig,
) -> Result<IssueViewInputs, ProviderError> {
    let (_, iid) = parse_issue_locator(inputs, config)?;
    Ok(IssueViewInputs { iid })
}

fn parse_merge_request_view_inputs(
    inputs: &Value,
    config: &GitlabProviderConfig,
) -> Result<IssueViewInputs, ProviderError> {
    let (_, iid) = parse_merge_request_locator(inputs, config)?;
    Ok(IssueViewInputs { iid })
}

fn parse_merge_request_subresource_inputs(
    inputs: &Value,
) -> Result<IssueViewInputs, ProviderError> {
    const MESSAGE: &str = "gitlab merge request subresource inputs are invalid";
    let object = input_object(inputs, MESSAGE)?;
    reject_unknown_keys(object, &["project", "iid"], MESSAGE)?;
    let _ = required_project_field(object)?;
    Ok(IssueViewInputs {
        iid: required_object_u64(object, "iid")?,
    })
}

fn parse_approval_mutation_inputs(
    inputs: &Value,
    approve: bool,
) -> Result<GitlabApprovalMutationRequest, ProviderError> {
    const MESSAGE: &str = "gitlab approval mutation inputs are invalid";
    let object = input_object(inputs, MESSAGE)?;
    let keys = if approve {
        vec!["project", "iid", "headSha"]
    } else {
        vec!["project", "iid"]
    };
    reject_unknown_keys(object, &keys, MESSAGE)?;
    let _ = required_project_field(object)?;
    let head_sha = if approve {
        let sha = required_non_empty_string(object, "headSha")?;
        if !is_full_commit_sha(&sha) {
            return Err(ProviderError::deny(
                ReasonCode::InputInvalid,
                "headSha must be a full Git commit SHA",
            ));
        }
        Some(sha)
    } else {
        None
    };
    Ok(GitlabApprovalMutationRequest {
        iid: required_object_u64(object, "iid")?,
        head_sha,
    })
}

fn parse_suggestion_apply_inputs(
    inputs: &Value,
    batch: bool,
    max_body_bytes: u64,
) -> Result<GitlabSuggestionApplyInputs, ProviderError> {
    const MESSAGE: &str = "gitlab suggestion apply inputs are invalid";
    let object = input_object(inputs, MESSAGE)?;
    let keys = if batch {
        vec![
            "project",
            "iid",
            "expectedHeadSha",
            "suggestions",
            "commitMessage",
        ]
    } else {
        vec![
            "project",
            "iid",
            "expectedHeadSha",
            "discussionId",
            "noteId",
            "suggestionId",
            "commitMessage",
        ]
    };
    reject_unknown_keys(object, &keys, MESSAGE)?;
    let _ = required_project_field(object)?;
    let expected_head_sha = required_non_empty_string(object, "expectedHeadSha")?;
    if !is_full_commit_sha(&expected_head_sha) {
        return Err(ProviderError::deny(
            ReasonCode::InputInvalid,
            "expectedHeadSha must be a full Git commit SHA",
        ));
    }
    let parse_locator =
        |value: &Value, nested: bool| -> Result<GitlabSuggestionLocator, ProviderError> {
            let locator = input_object(value, MESSAGE)?;
            if nested {
                reject_unknown_keys(
                    locator,
                    &["discussionId", "noteId", "suggestionId"],
                    MESSAGE,
                )?;
            }
            Ok(GitlabSuggestionLocator {
                discussion_id: required_non_empty_string(locator, "discussionId")?,
                note_id: required_object_u64(locator, "noteId")?,
                suggestion_id: required_object_u64(locator, "suggestionId")?,
            })
        };
    let locators = if batch {
        let values = object
            .get("suggestions")
            .and_then(Value::as_array)
            .ok_or_else(|| ProviderError::deny(ReasonCode::InputInvalid, MESSAGE))?;
        if values.is_empty() || values.len() > GITLAB_MAX_SUGGESTIONS_PER_APPLY {
            return Err(ProviderError::deny(
                ReasonCode::InputInvalid,
                "suggestions must contain between 1 and 100 entries",
            ));
        }
        values
            .iter()
            .map(|value| parse_locator(value, true))
            .collect::<Result<Vec<_>, _>>()?
    } else {
        vec![parse_locator(inputs, false)?]
    };
    let mut scoped_locators = BTreeSet::new();
    if locators.iter().any(|locator| {
        !scoped_locators.insert((
            locator.discussion_id.as_str(),
            locator.note_id,
            locator.suggestion_id,
        ))
    }) {
        return Err(ProviderError::deny(
            ReasonCode::InputInvalid,
            "suggestion locators must be unique",
        ));
    }
    Ok(GitlabSuggestionApplyInputs {
        iid: required_object_u64(object, "iid")?,
        expected_head_sha,
        locators,
        commit_message: optional_bounded_string(
            object.get("commitMessage"),
            "commitMessage",
            max_body_bytes,
            false,
        )?,
    })
}

fn parse_issue_search_inputs(inputs: &Value) -> Result<SearchInputs, ProviderError> {
    parse_search_inputs(
        inputs,
        &[
            "project",
            "state",
            "labels",
            "milestone",
            "assignee",
            "author",
            "search",
            "createdAfter",
            "updatedAfter",
            "sort",
            "orderBy",
            "maxResults",
            "pageToken",
        ],
        false,
    )
}

fn parse_issue_create_inputs(
    inputs: &Value,
    max_body_bytes: u64,
) -> Result<GitlabIssueCreateRequest, ProviderError> {
    let object = input_object(inputs, "gitlab issue.create inputs are invalid")?;
    reject_unknown_keys(
        object,
        &[
            "project",
            "title",
            "content",
            "contentFormat",
            "labels",
            "milestone",
            "assignees",
            "confidential",
        ],
        "gitlab issue.create inputs are invalid",
    )?;
    let _ = required_project_field(object)?;
    Ok(GitlabIssueCreateRequest {
        title: required_bounded_string(object, "title", max_body_bytes, false)?,
        description: prepare_optional_gitlab_content(
            object,
            "gitlab issue.create",
            max_body_bytes,
        )?,
        labels: optional_non_empty_string_array(object.get("labels"), "labels")?,
        milestone: optional_input_string(object.get("milestone"), "milestone")?,
        assignee_ids: optional_u64_array(object.get("assignees"), "assignees")?,
        confidential: optional_input_bool(object.get("confidential"), "confidential")?,
    })
}

fn parse_issue_update_inputs(
    inputs: &Value,
    max_body_bytes: u64,
) -> Result<GitlabIssueUpdateRequest, ProviderError> {
    let object = input_object(inputs, "gitlab issue.update inputs are invalid")?;
    reject_unknown_keys(
        object,
        &[
            "project",
            "iid",
            "title",
            "content",
            "contentFormat",
            "stateEvent",
            "labels",
            "addLabels",
            "removeLabels",
            "milestone",
            "assignees",
            "confidential",
        ],
        "gitlab issue.update inputs are invalid",
    )?;
    let _ = required_project_field(object)?;
    let labels = optional_non_empty_string_array(object.get("labels"), "labels")?;
    let add_labels = optional_non_empty_string_array(object.get("addLabels"), "addLabels")?;
    let remove_labels =
        optional_non_empty_string_array(object.get("removeLabels"), "removeLabels")?;
    validate_label_update_shape(&labels, &add_labels, &remove_labels)?;
    let request = GitlabIssueUpdateRequest {
        iid: required_object_u64(object, "iid")?,
        title: optional_bounded_string(object.get("title"), "title", max_body_bytes, false)?,
        description: prepare_optional_gitlab_content(
            object,
            "gitlab issue.update",
            max_body_bytes,
        )?,
        state_event: optional_state_event(object.get("stateEvent"))?,
        labels,
        add_labels,
        remove_labels,
        milestone: optional_input_string(object.get("milestone"), "milestone")?,
        assignee_ids: optional_u64_array(object.get("assignees"), "assignees")?,
        confidential: optional_input_bool(object.get("confidential"), "confidential")?,
    };
    if request.title.is_none()
        && request.description.is_none()
        && request.state_event.is_none()
        && request.labels.is_empty()
        && request.add_labels.is_empty()
        && request.remove_labels.is_empty()
        && request.milestone.is_none()
        && request.assignee_ids.is_empty()
        && request.confidential.is_none()
    {
        return Err(ProviderError::deny(
            ReasonCode::InputInvalid,
            "gitlab issue.update requires at least one update field",
        ));
    }
    Ok(request)
}

fn parse_note_list_inputs(
    inputs: &Value,
    configured_max: u32,
) -> Result<GitlabNoteListRequest, ProviderError> {
    let object = input_object(inputs, "gitlab note list inputs are invalid")?;
    reject_unknown_keys(
        object,
        &[
            "project",
            "iid",
            "maxResults",
            "pageToken",
            "sort",
            "orderBy",
            "projection",
        ],
        "gitlab note list inputs are invalid",
    )?;
    let _ = required_project_field(object)?;
    let sort = optional_input_string(object.get("sort"), "sort")?;
    if let Some(sort) = &sort
        && !matches!(sort.as_str(), "asc" | "desc")
    {
        return Err(ProviderError::deny(
            ReasonCode::InputInvalid,
            "gitlab note list sort is unsupported",
        ));
    }
    let order_by = optional_input_string(object.get("orderBy"), "orderBy")?;
    validate_optional_enum(
        order_by.as_deref(),
        NOTE_LIST_ORDER_BY,
        "gitlab note list orderBy is unsupported",
    )?;
    Ok(GitlabNoteListRequest {
        iid: required_object_u64(object, "iid")?,
        max_results: capped_max_results(
            optional_input_u32(object.get("maxResults"), "maxResults")?,
            configured_max,
        )?,
        sort,
        order_by,
        projection: GitlabCollectionProjection::parse(
            optional_input_string(object.get("projection"), "projection")?.as_deref(),
            "gitlab note list",
        )?,
        page_token: optional_input_string(object.get("pageToken"), "pageToken")?,
        page: 1,
    })
}

fn parse_discussion_list_inputs(
    inputs: &Value,
    configured_max: u32,
) -> Result<GitlabDiscussionListRequest, ProviderError> {
    let object = input_object(inputs, "gitlab discussion list inputs are invalid")?;
    reject_unknown_keys(
        object,
        &["project", "iid", "maxResults", "pageToken", "projection"],
        "gitlab discussion list inputs are invalid",
    )?;
    let _ = required_project_field(object)?;
    Ok(GitlabDiscussionListRequest {
        iid: required_object_u64(object, "iid")?,
        max_results: capped_max_results(
            optional_input_u32(object.get("maxResults"), "maxResults")?,
            configured_max,
        )?,
        projection: GitlabCollectionProjection::parse(
            optional_input_string(object.get("projection"), "projection")?.as_deref(),
            "gitlab discussion list",
        )?,
        page_token: optional_input_string(object.get("pageToken"), "pageToken")?,
        page: 1,
    })
}

fn parse_discussion_view_inputs(
    inputs: &Value,
) -> Result<GitlabDiscussionViewInputs, ProviderError> {
    let object = input_object(inputs, "gitlab discussion view inputs are invalid")?;
    reject_unknown_keys(
        object,
        &["project", "iid", "discussionId"],
        "gitlab discussion view inputs are invalid",
    )?;
    let _ = required_project_field(object)?;
    Ok(GitlabDiscussionViewInputs {
        iid: required_object_u64(object, "iid")?,
        discussion_id: required_non_empty_string(object, "discussionId")?,
    })
}

fn parse_merge_request_list_inputs(
    inputs: &Value,
    configured_max: u32,
    _operation: &str,
    allow_unidiff: bool,
) -> Result<GitlabMergeRequestListRequest, ProviderError> {
    const MESSAGE: &str = "gitlab merge request list inputs are invalid";
    let object = input_object(inputs, MESSAGE)?;
    let mut keys = vec!["project", "iid", "maxResults", "pageToken"];
    if allow_unidiff {
        keys.push("unidiff");
    }
    reject_unknown_keys(object, &keys, MESSAGE)?;
    let _ = required_project_field(object)?;
    Ok(GitlabMergeRequestListRequest {
        iid: required_object_u64(object, "iid")?,
        max_results: capped_max_results(
            optional_input_u32(object.get("maxResults"), "maxResults")?,
            configured_max,
        )?,
        page_token: optional_input_string(object.get("pageToken"), "pageToken")?,
        page: 1,
        unidiff: if allow_unidiff {
            optional_input_bool(object.get("unidiff"), "unidiff")?
        } else {
            None
        },
    })
}

fn parse_merge_request_object_inputs(
    inputs: &Value,
    id_field: &str,
    _operation: &str,
) -> Result<GitlabMergeRequestObjectRequest, ProviderError> {
    const MESSAGE: &str = "gitlab merge request object inputs are invalid";
    let object = input_object(inputs, MESSAGE)?;
    reject_unknown_keys(object, &["project", "iid", id_field, "unidiff"], MESSAGE)?;
    let _ = required_project_field(object)?;
    Ok(GitlabMergeRequestObjectRequest {
        iid: required_object_u64(object, "iid")?,
        object_id: required_object_u64(object, id_field)?,
        unidiff: optional_input_bool(object.get("unidiff"), "unidiff")?,
    })
}

fn parse_issue_note_add_inputs(
    inputs: &Value,
    max_body_bytes: u64,
) -> Result<GitlabIssueNoteCreateRequest, ProviderError> {
    let object = input_object(inputs, "gitlab issue.note.add inputs are invalid")?;
    reject_unknown_keys(
        object,
        &["project", "iid", "content", "contentFormat", "confidential"],
        "gitlab issue.note.add inputs are invalid",
    )?;
    let _ = required_project_field(object)?;
    Ok(GitlabIssueNoteCreateRequest {
        iid: required_object_u64(object, "iid")?,
        body: prepare_required_gitlab_content(object, "gitlab issue.note.add", max_body_bytes)?,
        confidential: optional_input_bool(object.get("confidential"), "confidential")?,
    })
}

fn parse_note_add_inputs(
    inputs: &Value,
    max_body_bytes: u64,
) -> Result<GitlabNoteCreateRequest, ProviderError> {
    let object = input_object(inputs, "gitlab note add inputs are invalid")?;
    reject_unknown_keys(
        object,
        &["project", "iid", "content", "contentFormat"],
        "gitlab note add inputs are invalid",
    )?;
    let _ = required_project_field(object)?;
    Ok(GitlabNoteCreateRequest {
        iid: required_object_u64(object, "iid")?,
        body: prepare_required_gitlab_content(object, "gitlab note add", max_body_bytes)?,
    })
}

fn parse_note_update_inputs(
    inputs: &Value,
    max_body_bytes: u64,
) -> Result<GitlabNoteUpdateRequest, ProviderError> {
    let object = input_object(inputs, "gitlab note update inputs are invalid")?;
    reject_unknown_keys(
        object,
        &["project", "iid", "noteId", "content", "contentFormat"],
        "gitlab note update inputs are invalid",
    )?;
    let _ = required_project_field(object)?;
    Ok(GitlabNoteUpdateRequest {
        iid: required_object_u64(object, "iid")?,
        note_id: required_object_u64(object, "noteId")?,
        body: prepare_required_gitlab_content(object, "gitlab note update", max_body_bytes)?,
    })
}

fn parse_note_delete_inputs(inputs: &Value) -> Result<GitlabNoteDeleteRequest, ProviderError> {
    parse_note_object_inputs(inputs, "gitlab note delete inputs are invalid")
}

fn parse_issue_note_view_inputs(inputs: &Value) -> Result<GitlabNoteDeleteRequest, ProviderError> {
    parse_note_object_inputs(inputs, "gitlab issue note view inputs are invalid")
}

fn parse_merge_request_note_view_inputs(
    inputs: &Value,
) -> Result<GitlabNoteDeleteRequest, ProviderError> {
    parse_note_object_inputs(inputs, "gitlab merge request note view inputs are invalid")
}

fn parse_note_object_inputs(
    inputs: &Value,
    invalid_message: &'static str,
) -> Result<GitlabNoteDeleteRequest, ProviderError> {
    let object = input_object(inputs, invalid_message)?;
    reject_unknown_keys(object, &["project", "iid", "noteId"], invalid_message)?;
    let _ = required_project_field(object)?;
    Ok(GitlabNoteDeleteRequest {
        iid: required_object_u64(object, "iid")?,
        note_id: required_object_u64(object, "noteId")?,
    })
}

fn parse_discussion_note_update_inputs(
    inputs: &Value,
    max_body_bytes: u64,
) -> Result<GitlabDiscussionNoteUpdateRequest, ProviderError> {
    let object = input_object(inputs, "gitlab discussion note update inputs are invalid")?;
    reject_unknown_keys(
        object,
        &[
            "project",
            "iid",
            "discussionId",
            "noteId",
            "content",
            "contentFormat",
        ],
        "gitlab discussion note update inputs are invalid",
    )?;
    let _ = required_project_field(object)?;
    Ok(GitlabDiscussionNoteUpdateRequest {
        iid: required_object_u64(object, "iid")?,
        discussion_id: required_non_empty_string(object, "discussionId")?,
        note_id: required_object_u64(object, "noteId")?,
        body: prepare_required_gitlab_content(
            object,
            "gitlab discussion note update",
            max_body_bytes,
        )?,
    })
}

fn parse_discussion_note_delete_inputs(
    inputs: &Value,
) -> Result<GitlabDiscussionNoteDeleteRequest, ProviderError> {
    let object = input_object(inputs, "gitlab discussion note delete inputs are invalid")?;
    reject_unknown_keys(
        object,
        &["project", "iid", "discussionId", "noteId"],
        "gitlab discussion note delete inputs are invalid",
    )?;
    let _ = required_project_field(object)?;
    Ok(GitlabDiscussionNoteDeleteRequest {
        iid: required_object_u64(object, "iid")?,
        discussion_id: required_non_empty_string(object, "discussionId")?,
        note_id: required_object_u64(object, "noteId")?,
    })
}

fn parse_discussion_state_change_inputs(
    inputs: &Value,
    change: GitlabDiscussionStateChange,
) -> Result<GitlabDiscussionStateChangeRequest, ProviderError> {
    let object = input_object(inputs, "gitlab discussion state inputs are invalid")?;
    reject_unknown_keys(
        object,
        &["project", "iid", "discussionId"],
        "gitlab discussion state inputs are invalid",
    )?;
    let _ = required_project_field(object)?;
    Ok(GitlabDiscussionStateChangeRequest {
        iid: required_object_u64(object, "iid")?,
        discussion_id: required_non_empty_string(object, "discussionId")?,
        change,
    })
}

fn parse_positioned_discussion_inputs(
    inputs: &Value,
    max_body_bytes: u64,
) -> Result<PositionedDiscussionInputs, ProviderError> {
    const MESSAGE: &str = "gitlab inline discussion inputs are invalid";
    let object = input_object(inputs, MESSAGE)?;
    reject_unknown_keys(
        object,
        &[
            "project",
            "iid",
            "expectedHeadSha",
            "content",
            "contentFormat",
            "position",
        ],
        MESSAGE,
    )?;
    let _ = required_project_field(object)?;
    let expected_head_sha = required_object_string(object, "expectedHeadSha")?;
    validate_full_commit_sha(&expected_head_sha, "expectedHeadSha")?;
    Ok(PositionedDiscussionInputs {
        iid: required_object_u64(object, "iid")?,
        expected_head_sha,
        body: prepare_required_gitlab_content(
            object,
            "gitlab merge_request.discussion.inline.add",
            max_body_bytes,
        )?,
        position: parse_position_input(object.get("position"))?,
    })
}

fn parse_discussion_reply_inputs(
    inputs: &Value,
    max_body_bytes: u64,
) -> Result<GitlabDiscussionReplyRequest, ProviderError> {
    const MESSAGE: &str = "gitlab discussion reply inputs are invalid";
    let object = input_object(inputs, MESSAGE)?;
    reject_unknown_keys(
        object,
        &["project", "iid", "discussionId", "content", "contentFormat"],
        MESSAGE,
    )?;
    let _ = required_project_field(object)?;
    Ok(GitlabDiscussionReplyRequest {
        iid: required_object_u64(object, "iid")?,
        discussion_id: required_non_empty_string(object, "discussionId")?,
        body: prepare_required_gitlab_content(
            object,
            "gitlab merge_request.discussion.note.add",
            max_body_bytes,
        )?,
    })
}

fn parse_draft_note_list_inputs(
    inputs: &Value,
    configured_max: u32,
) -> Result<GitlabDraftNoteListRequest, ProviderError> {
    const MESSAGE: &str = "gitlab draft note list inputs are invalid";
    let object = input_object(inputs, MESSAGE)?;
    reject_unknown_keys(
        object,
        &["project", "iid", "maxResults", "pageToken", "projection"],
        MESSAGE,
    )?;
    let _ = required_project_field(object)?;
    Ok(GitlabDraftNoteListRequest {
        iid: required_object_u64(object, "iid")?,
        max_results: capped_max_results(
            optional_input_u32(object.get("maxResults"), "maxResults")?,
            configured_max,
        )?,
        projection: GitlabCollectionProjection::parse(
            optional_input_string(object.get("projection"), "projection")?.as_deref(),
            "gitlab draft note list",
        )?,
        page_token: optional_input_string(object.get("pageToken"), "pageToken")?,
        page: 1,
    })
}

fn parse_draft_note_object_inputs(
    inputs: &Value,
) -> Result<GitlabDraftNoteObjectRequest, ProviderError> {
    const MESSAGE: &str = "gitlab draft note object inputs are invalid";
    let object = input_object(inputs, MESSAGE)?;
    reject_unknown_keys(object, &["project", "iid", "draftNoteId"], MESSAGE)?;
    let _ = required_project_field(object)?;
    Ok(GitlabDraftNoteObjectRequest {
        iid: required_object_u64(object, "iid")?,
        draft_note_id: required_object_u64(object, "draftNoteId")?,
    })
}

fn parse_draft_note_add_inputs(
    inputs: &Value,
    max_body_bytes: u64,
) -> Result<DraftNoteAddInputs, ProviderError> {
    const MESSAGE: &str = "gitlab draft note add inputs are invalid";
    let object = input_object(inputs, MESSAGE)?;
    reject_unknown_keys(
        object,
        &[
            "project",
            "iid",
            "expectedHeadSha",
            "content",
            "contentFormat",
            "position",
            "inReplyToDiscussionId",
            "resolveDiscussion",
        ],
        MESSAGE,
    )?;
    let _ = required_project_field(object)?;
    let position = object
        .get("position")
        .map(|value| parse_position_input(Some(value)))
        .transpose()?;
    let expected_head_sha =
        optional_input_string(object.get("expectedHeadSha"), "expectedHeadSha")?;
    if let Some(expected_head_sha) = &expected_head_sha {
        validate_full_commit_sha(expected_head_sha, "expectedHeadSha")?;
    }
    let in_reply_to_discussion_id =
        optional_input_string(object.get("inReplyToDiscussionId"), "inReplyToDiscussionId")?;
    let resolve_discussion =
        optional_input_bool(object.get("resolveDiscussion"), "resolveDiscussion")?;
    if position.is_some() != expected_head_sha.is_some()
        || (position.is_some() && in_reply_to_discussion_id.is_some())
        || (resolve_discussion.is_some() && in_reply_to_discussion_id.is_none())
    {
        return Err(ProviderError::deny(ReasonCode::InputInvalid, MESSAGE));
    }
    Ok(DraftNoteAddInputs {
        iid: required_object_u64(object, "iid")?,
        expected_head_sha,
        body: prepare_required_gitlab_content(
            object,
            "gitlab merge_request.draft_note.add",
            max_body_bytes,
        )?,
        position,
        in_reply_to_discussion_id,
        resolve_discussion,
    })
}

fn parse_draft_note_update_inputs(
    inputs: &Value,
    max_body_bytes: u64,
) -> Result<DraftNoteUpdateInputs, ProviderError> {
    const MESSAGE: &str = "gitlab draft note update inputs are invalid";
    let object = input_object(inputs, MESSAGE)?;
    reject_unknown_keys(
        object,
        &[
            "project",
            "iid",
            "draftNoteId",
            "expectedHeadSha",
            "content",
            "contentFormat",
            "position",
        ],
        MESSAGE,
    )?;
    let _ = required_project_field(object)?;
    let body = prepare_optional_gitlab_content(
        object,
        "gitlab merge_request.draft_note.update",
        max_body_bytes,
    )?;
    let position = object
        .get("position")
        .map(|value| parse_position_input(Some(value)))
        .transpose()?;
    let expected_head_sha =
        optional_input_string(object.get("expectedHeadSha"), "expectedHeadSha")?;
    if let Some(expected_head_sha) = &expected_head_sha {
        validate_full_commit_sha(expected_head_sha, "expectedHeadSha")?;
    }
    if position.is_some() != expected_head_sha.is_some() || (position.is_none() && body.is_none()) {
        return Err(ProviderError::deny(ReasonCode::InputInvalid, MESSAGE));
    }
    Ok(DraftNoteUpdateInputs {
        iid: required_object_u64(object, "iid")?,
        draft_note_id: required_object_u64(object, "draftNoteId")?,
        expected_head_sha,
        body,
        position,
    })
}

fn parse_draft_publication_inputs(
    inputs: &Value,
    max_body_bytes: u64,
    review_submit: bool,
) -> Result<DraftPublicationInputs, ProviderError> {
    const MESSAGE: &str = "gitlab draft publication inputs are invalid";
    let object = input_object(inputs, MESSAGE)?;
    let mut keys = vec!["project", "iid", "content", "contentFormat", "internal"];
    if review_submit {
        keys.push("reviewerState");
    }
    reject_unknown_keys(object, &keys, MESSAGE)?;
    let _ = required_project_field(object)?;
    let summary = prepare_optional_gitlab_content(
        object,
        if review_submit {
            "gitlab merge_request.review.submit"
        } else {
            "gitlab merge_request.draft_note.publish_all"
        },
        max_body_bytes,
    )?;
    let internal = optional_input_bool(object.get("internal"), "internal")?;
    if internal.is_some() && summary.is_none() {
        return Err(ProviderError::deny(ReasonCode::InputInvalid, MESSAGE));
    }
    let reviewer_state = if review_submit {
        let state = required_object_string(object, "reviewerState")?;
        Some(match state.as_str() {
            "reviewed" => "reviewed".to_string(),
            "requestedChanges" => "requested_changes".to_string(),
            _ => return Err(ProviderError::deny(ReasonCode::InputInvalid, MESSAGE)),
        })
    } else {
        None
    };
    Ok(DraftPublicationInputs {
        iid: required_object_u64(object, "iid")?,
        summary,
        internal,
        reviewer_state,
    })
}

fn parse_position_input(value: Option<&Value>) -> Result<GitlabPositionInput, ProviderError> {
    const MESSAGE: &str = "gitlab position is invalid";
    let object = value
        .and_then(Value::as_object)
        .ok_or_else(|| ProviderError::deny(ReasonCode::InputInvalid, MESSAGE))?;
    reject_unknown_keys(
        object,
        &[
            "positionType",
            "oldPath",
            "newPath",
            "oldLine",
            "newLine",
            "lineRange",
            "width",
            "height",
            "x",
            "y",
        ],
        MESSAGE,
    )?;
    let position_type = required_object_string(object, "positionType")?;
    let old_path = required_non_empty_string(object, "oldPath")?;
    let new_path = required_non_empty_string(object, "newPath")?;
    validate_gitlab_file_path(&old_path)?;
    validate_gitlab_file_path(&new_path)?;
    let old_line = optional_positive_input_u64(object.get("oldLine"), "oldLine")?;
    let new_line = optional_positive_input_u64(object.get("newLine"), "newLine")?;
    let line_range = object
        .get("lineRange")
        .map(parse_line_range_input)
        .transpose()?;
    let width = optional_positive_input_u64(object.get("width"), "width")?;
    let height = optional_positive_input_u64(object.get("height"), "height")?;
    let x = optional_nonnegative_input_u64(object.get("x"), "x")?;
    let y = optional_nonnegative_input_u64(object.get("y"), "y")?;
    let has_image = width.is_some() || height.is_some() || x.is_some() || y.is_some();
    match position_type.as_str() {
        "text"
            if !has_image
                && ((line_range.is_some() && old_line.is_none() && new_line.is_none())
                    || (line_range.is_none() && (old_line.is_some() || new_line.is_some()))) => {}
        "file"
            if !has_image && old_line.is_none() && new_line.is_none() && line_range.is_none() => {}
        "image"
            if width.is_some()
                && height.is_some()
                && x.is_some()
                && y.is_some()
                && old_line.is_none()
                && new_line.is_none()
                && line_range.is_none() => {}
        _ => return Err(ProviderError::deny(ReasonCode::InputInvalid, MESSAGE)),
    }
    Ok(GitlabPositionInput {
        position_type,
        old_path,
        new_path,
        old_line,
        new_line,
        line_range,
        width,
        height,
        x,
        y,
    })
}

fn parse_line_range_input(value: &Value) -> Result<GitlabLineRangeInput, ProviderError> {
    const MESSAGE: &str = "gitlab position lineRange is invalid";
    let object = value
        .as_object()
        .ok_or_else(|| ProviderError::deny(ReasonCode::InputInvalid, MESSAGE))?;
    reject_unknown_keys(object, &["start", "end"], MESSAGE)?;
    Ok(GitlabLineRangeInput {
        start: parse_line_coordinate_input(object.get("start"), MESSAGE)?,
        end: parse_line_coordinate_input(object.get("end"), MESSAGE)?,
    })
}

fn parse_line_coordinate_input(
    value: Option<&Value>,
    message: &'static str,
) -> Result<GitlabLineCoordinateInput, ProviderError> {
    let object = value
        .and_then(Value::as_object)
        .ok_or_else(|| ProviderError::deny(ReasonCode::InputInvalid, message))?;
    reject_unknown_keys(object, &["oldLine", "newLine"], message)?;
    let old_line = optional_positive_input_u64(object.get("oldLine"), "oldLine")?;
    let new_line = optional_positive_input_u64(object.get("newLine"), "newLine")?;
    if old_line.is_none() && new_line.is_none() {
        return Err(ProviderError::deny(ReasonCode::InputInvalid, message));
    }
    Ok(GitlabLineCoordinateInput { old_line, new_line })
}

fn parse_merge_request_search_inputs(inputs: &Value) -> Result<SearchInputs, ProviderError> {
    parse_search_inputs(
        inputs,
        &[
            "project",
            "state",
            "sourceBranch",
            "targetBranch",
            "labels",
            "milestone",
            "assignee",
            "author",
            "reviewer",
            "search",
            "createdAfter",
            "updatedAfter",
            "sort",
            "orderBy",
            "maxResults",
            "pageToken",
        ],
        true,
    )
}

fn parse_merge_request_create_inputs(
    inputs: &Value,
    max_body_bytes: u64,
) -> Result<GitlabMergeRequestCreateRequest, ProviderError> {
    let object = input_object(inputs, "gitlab merge_request.create inputs are invalid")?;
    reject_unknown_keys(
        object,
        &[
            "project",
            "sourceBranch",
            "targetBranch",
            "title",
            "content",
            "contentFormat",
            "labels",
            "assignees",
            "reviewers",
            "removeSourceBranch",
            "squash",
            "draft",
        ],
        "gitlab merge_request.create inputs are invalid",
    )?;
    let _ = required_project_field(object)?;
    let source_branch = required_object_string(object, "sourceBranch")?;
    let target_branch = required_object_string(object, "targetBranch")?;
    validate_branch_name(&source_branch)?;
    validate_branch_name(&target_branch)?;
    Ok(GitlabMergeRequestCreateRequest {
        source_branch,
        target_branch,
        title: required_bounded_string(object, "title", max_body_bytes, false)?,
        description: prepare_optional_gitlab_content(
            object,
            "gitlab merge_request.create",
            max_body_bytes,
        )?,
        labels: optional_non_empty_string_array(object.get("labels"), "labels")?,
        assignee_ids: optional_u64_array(object.get("assignees"), "assignees")?,
        reviewer_ids: optional_u64_array(object.get("reviewers"), "reviewers")?,
        remove_source_branch: optional_input_bool(
            object.get("removeSourceBranch"),
            "removeSourceBranch",
        )?,
        squash: optional_input_bool(object.get("squash"), "squash")?,
        draft: optional_input_bool(object.get("draft"), "draft")?,
    })
}

fn parse_merge_request_update_inputs(
    inputs: &Value,
    max_body_bytes: u64,
) -> Result<GitlabMergeRequestUpdateRequest, ProviderError> {
    let object = input_object(inputs, "gitlab merge_request.update inputs are invalid")?;
    reject_unknown_keys(
        object,
        &[
            "project",
            "iid",
            "title",
            "content",
            "contentFormat",
            "stateEvent",
            "labels",
            "addLabels",
            "removeLabels",
            "assignees",
            "reviewers",
            "targetBranch",
            "removeSourceBranch",
            "squash",
        ],
        "gitlab merge_request.update inputs are invalid",
    )?;
    let _ = required_project_field(object)?;
    let labels = optional_non_empty_string_array(object.get("labels"), "labels")?;
    let add_labels = optional_non_empty_string_array(object.get("addLabels"), "addLabels")?;
    let remove_labels =
        optional_non_empty_string_array(object.get("removeLabels"), "removeLabels")?;
    validate_label_update_shape(&labels, &add_labels, &remove_labels)?;
    let target_branch = optional_input_string(object.get("targetBranch"), "targetBranch")?;
    if let Some(target_branch) = &target_branch {
        validate_branch_name(target_branch)?;
    }
    let request = GitlabMergeRequestUpdateRequest {
        iid: required_object_u64(object, "iid")?,
        title: optional_bounded_string(object.get("title"), "title", max_body_bytes, false)?,
        description: prepare_optional_gitlab_content(
            object,
            "gitlab merge_request.update",
            max_body_bytes,
        )?,
        state_event: optional_state_event(object.get("stateEvent"))?,
        labels,
        add_labels,
        remove_labels,
        assignee_ids: optional_u64_array(object.get("assignees"), "assignees")?,
        reviewer_ids: optional_u64_array(object.get("reviewers"), "reviewers")?,
        target_branch,
        remove_source_branch: optional_input_bool(
            object.get("removeSourceBranch"),
            "removeSourceBranch",
        )?,
        squash: optional_input_bool(object.get("squash"), "squash")?,
    };
    if request.title.is_none()
        && request.description.is_none()
        && request.state_event.is_none()
        && request.labels.is_empty()
        && request.add_labels.is_empty()
        && request.remove_labels.is_empty()
        && request.assignee_ids.is_empty()
        && request.reviewer_ids.is_empty()
        && request.target_branch.is_none()
        && request.remove_source_branch.is_none()
        && request.squash.is_none()
    {
        return Err(ProviderError::deny(
            ReasonCode::InputInvalid,
            "gitlab merge_request.update requires at least one update field",
        ));
    }
    Ok(request)
}

fn parse_merge_request_merge_inputs(
    inputs: &Value,
    max_body_bytes: u64,
) -> Result<GitlabMergeRequestMergeRequest, ProviderError> {
    let object = input_object(inputs, "gitlab merge_request.merge inputs are invalid")?;
    reject_unknown_keys(
        object,
        &[
            "project",
            "iid",
            "sha",
            "squash",
            "shouldRemoveSourceBranch",
            "mergeCommitMessage",
            "squashCommitMessage",
        ],
        "gitlab merge_request.merge inputs are invalid",
    )?;
    let _ = required_project_field(object)?;
    let sha = required_object_string(object, "sha")?;
    validate_full_commit_sha(&sha, "sha")?;
    Ok(GitlabMergeRequestMergeRequest {
        iid: required_object_u64(object, "iid")?,
        sha,
        squash: optional_input_bool(object.get("squash"), "squash")?,
        should_remove_source_branch: optional_input_bool(
            object.get("shouldRemoveSourceBranch"),
            "shouldRemoveSourceBranch",
        )?,
        merge_commit_message: optional_bounded_string(
            object.get("mergeCommitMessage"),
            "mergeCommitMessage",
            max_body_bytes,
            false,
        )?,
        squash_commit_message: optional_bounded_string(
            object.get("squashCommitMessage"),
            "squashCommitMessage",
            max_body_bytes,
            false,
        )?,
    })
}

fn parse_search_inputs(
    inputs: &Value,
    allowed_keys: &[&str],
    merge_request: bool,
) -> Result<SearchInputs, ProviderError> {
    let object = input_object(inputs, "gitlab search inputs are invalid")?;
    reject_unknown_keys(object, allowed_keys, "gitlab search inputs are invalid")?;
    let _ = object
        .get("project")
        .ok_or_else(|| ProviderError::deny(ReasonCode::InputInvalid, "project is required"))?;
    let state = optional_input_string(object.get("state"), "state")?;
    if let Some(state) = &state {
        let allowed = if merge_request {
            ["opened", "closed", "locked", "merged", "all"].as_slice()
        } else {
            ["opened", "closed", "all"].as_slice()
        };
        if !allowed.contains(&state.as_str()) {
            return Err(ProviderError::deny(
                ReasonCode::InputInvalid,
                "gitlab search state is unsupported",
            ));
        }
    }
    let sort = optional_input_string(object.get("sort"), "sort")?;
    if let Some(sort) = &sort
        && !matches!(sort.as_str(), "asc" | "desc")
    {
        return Err(ProviderError::deny(
            ReasonCode::InputInvalid,
            "gitlab search sort is unsupported",
        ));
    }
    let order_by = optional_input_string(object.get("orderBy"), "orderBy")?;
    let allowed_order_by = if merge_request {
        MERGE_REQUEST_SEARCH_ORDER_BY
    } else {
        ISSUE_SEARCH_ORDER_BY
    };
    validate_optional_enum(
        order_by.as_deref(),
        allowed_order_by,
        "gitlab search orderBy is unsupported",
    )?;
    Ok(SearchInputs {
        state,
        labels: optional_string_array(object.get("labels"), "labels")?,
        milestone: optional_input_string(object.get("milestone"), "milestone")?,
        assignee: optional_input_string(object.get("assignee"), "assignee")?,
        author: optional_input_string(object.get("author"), "author")?,
        reviewer: optional_input_string(object.get("reviewer"), "reviewer")?,
        source_branch: optional_input_string(object.get("sourceBranch"), "sourceBranch")?,
        target_branch: optional_input_string(object.get("targetBranch"), "targetBranch")?,
        search: optional_input_string(object.get("search"), "search")?,
        created_after: optional_input_string(object.get("createdAfter"), "createdAfter")?,
        updated_after: optional_input_string(object.get("updatedAfter"), "updatedAfter")?,
        sort,
        order_by,
        max_results: optional_input_u32(object.get("maxResults"), "maxResults")?,
        page_token: optional_input_string(object.get("pageToken"), "pageToken")?,
    })
}

fn validate_optional_enum(
    value: Option<&str>,
    allowed: &[&str],
    message: &'static str,
) -> Result<(), ProviderError> {
    if let Some(value) = value
        && !allowed.contains(&value)
    {
        return Err(ProviderError::deny(ReasonCode::InputInvalid, message));
    }
    Ok(())
}

fn parse_branch_list_inputs(inputs: &Value) -> Result<BranchListInputs, ProviderError> {
    let object = input_object(inputs, "gitlab branch.list inputs are invalid")?;
    reject_unknown_keys(
        object,
        &["project", "search", "regex", "maxResults"],
        "gitlab branch.list inputs are invalid",
    )?;
    let _ = object
        .get("project")
        .ok_or_else(|| ProviderError::deny(ReasonCode::InputInvalid, "project is required"))?;
    Ok(BranchListInputs {
        search: optional_input_string(object.get("search"), "search")?,
        regex: optional_input_string(object.get("regex"), "regex")?,
        max_results: optional_input_u32(object.get("maxResults"), "maxResults")?,
    })
}

fn parse_branch_view_inputs(inputs: &Value) -> Result<BranchViewInputs, ProviderError> {
    let object = input_object(inputs, "gitlab branch.view inputs are invalid")?;
    reject_unknown_keys(
        object,
        &["project", "branch"],
        "gitlab branch.view inputs are invalid",
    )?;
    let branch = required_object_string(object, "branch")?;
    validate_branch_name(&branch)?;
    Ok(BranchViewInputs { branch })
}

fn parse_protected_branch_list_inputs(inputs: &Value) -> Result<BranchListInputs, ProviderError> {
    let object = input_object(inputs, "gitlab protected_branch.list inputs are invalid")?;
    reject_unknown_keys(
        object,
        &["project", "search", "maxResults"],
        "gitlab protected_branch.list inputs are invalid",
    )?;
    let _ = required_project_field(object)?;
    Ok(BranchListInputs {
        search: optional_input_string(object.get("search"), "search")?,
        regex: None,
        max_results: optional_input_u32(object.get("maxResults"), "maxResults")?,
    })
}

fn parse_protected_branch_view_inputs(
    inputs: &Value,
) -> Result<ProtectedBranchViewInputs, ProviderError> {
    let object = input_object(inputs, "gitlab protected_branch.view inputs are invalid")?;
    reject_unknown_keys(
        object,
        &["project", "branchOrWildcardName"],
        "gitlab protected_branch.view inputs are invalid",
    )?;
    let _ = required_project_field(object)?;
    let name = required_object_string(object, "branchOrWildcardName")?;
    validate_protected_branch_rule_name(&name)?;
    Ok(ProtectedBranchViewInputs { name })
}

fn parse_protected_branch_verify_inputs(
    inputs: &Value,
) -> Result<ProtectedBranchVerifyInputs, ProviderError> {
    let object = input_object(inputs, "gitlab protected_branch.verify inputs are invalid")?;
    reject_unknown_keys(
        object,
        &["project", "requiredPatterns"],
        "gitlab protected_branch.verify inputs are invalid",
    )?;
    let _ = required_project_field(object)?;
    let required_patterns =
        optional_non_empty_string_array(object.get("requiredPatterns"), "requiredPatterns")?;
    for pattern in &required_patterns {
        validate_protected_branch_rule_name(pattern)?;
    }
    Ok(ProtectedBranchVerifyInputs { required_patterns })
}

fn parse_branch_create_inputs(inputs: &Value) -> Result<GitlabBranchCreateRequest, ProviderError> {
    let object = input_object(inputs, "gitlab branch.create inputs are invalid")?;
    reject_unknown_keys(
        object,
        &["project", "branch", "ref"],
        "gitlab branch.create inputs are invalid",
    )?;
    let _ = required_project_field(object)?;
    let branch = required_object_string(object, "branch")?;
    let ref_name = required_object_string(object, "ref")?;
    validate_branch_name(&branch)?;
    validate_ref_name(&ref_name)?;
    Ok(GitlabBranchCreateRequest { branch, ref_name })
}

fn parse_file_view_inputs(inputs: &Value) -> Result<FileViewInputs, ProviderError> {
    let object = input_object(inputs, "gitlab file inputs are invalid")?;
    reject_unknown_keys(
        object,
        &["project", "path", "ref"],
        "gitlab file inputs are invalid",
    )?;
    let _ = required_project_field(object)?;
    let path = required_object_string(object, "path")?;
    let ref_name = required_object_string(object, "ref")?;
    validate_gitlab_file_path(&path)?;
    validate_ref_name(&ref_name)?;
    Ok(FileViewInputs { path, ref_name })
}

fn parse_file_create_inputs(
    inputs: &Value,
    max_body_bytes: u64,
    max_file_bytes: u64,
) -> Result<GitlabFileWriteRequest, ProviderError> {
    parse_file_write_inputs(inputs, max_body_bytes, max_file_bytes, false)
}

fn parse_file_update_inputs(
    inputs: &Value,
    max_body_bytes: u64,
    max_file_bytes: u64,
) -> Result<GitlabFileWriteRequest, ProviderError> {
    parse_file_write_inputs(inputs, max_body_bytes, max_file_bytes, true)
}

fn parse_file_write_inputs(
    inputs: &Value,
    max_body_bytes: u64,
    max_file_bytes: u64,
    update: bool,
) -> Result<GitlabFileWriteRequest, ProviderError> {
    let object = input_object(inputs, "gitlab file write inputs are invalid")?;
    let mut allowed = vec![
        "project",
        "path",
        "branch",
        "content",
        "commitMessage",
        "startBranch",
        "authorName",
        "authorEmail",
        "encoding",
        "executeFilemode",
    ];
    if update {
        allowed.push("lastCommitId");
    }
    reject_unknown_keys(object, &allowed, "gitlab file write inputs are invalid")?;
    let _ = required_project_field(object)?;
    let path = required_object_string(object, "path")?;
    let branch = required_object_string(object, "branch")?;
    validate_gitlab_file_path(&path)?;
    validate_branch_name(&branch)?;
    let content = required_object_string(object, "content")?;
    let encoding = optional_gitlab_content_encoding(object.get("encoding"))?;
    let decoded_content_bytes =
        validate_gitlab_content_bytes(&content, encoding.as_deref(), max_file_bytes, "content")?;
    let start_branch = optional_input_string(object.get("startBranch"), "startBranch")?;
    if let Some(start_branch) = &start_branch {
        validate_branch_name(start_branch)?;
    }
    let last_commit_id = optional_last_commit_id(object.get("lastCommitId"))?;
    Ok(GitlabFileWriteRequest {
        path,
        branch,
        content,
        commit_message: required_bounded_string(object, "commitMessage", max_body_bytes, false)?,
        start_branch,
        author_name: optional_input_string(object.get("authorName"), "authorName")?,
        author_email: optional_input_string(object.get("authorEmail"), "authorEmail")?,
        encoding,
        execute_filemode: optional_input_bool(object.get("executeFilemode"), "executeFilemode")?,
        last_commit_id,
        decoded_content_bytes,
    })
}

fn parse_file_delete_inputs(
    inputs: &Value,
    max_body_bytes: u64,
) -> Result<GitlabFileDeleteRequest, ProviderError> {
    let object = input_object(inputs, "gitlab file.delete inputs are invalid")?;
    reject_unknown_keys(
        object,
        &[
            "project",
            "path",
            "branch",
            "commitMessage",
            "startBranch",
            "authorName",
            "authorEmail",
            "lastCommitId",
        ],
        "gitlab file.delete inputs are invalid",
    )?;
    let _ = required_project_field(object)?;
    let path = required_object_string(object, "path")?;
    let branch = required_object_string(object, "branch")?;
    validate_gitlab_file_path(&path)?;
    validate_branch_name(&branch)?;
    let start_branch = optional_input_string(object.get("startBranch"), "startBranch")?;
    if let Some(start_branch) = &start_branch {
        validate_branch_name(start_branch)?;
    }
    Ok(GitlabFileDeleteRequest {
        path,
        branch,
        commit_message: required_bounded_string(object, "commitMessage", max_body_bytes, false)?,
        start_branch,
        author_name: optional_input_string(object.get("authorName"), "authorName")?,
        author_email: optional_input_string(object.get("authorEmail"), "authorEmail")?,
        last_commit_id: optional_last_commit_id(object.get("lastCommitId"))?,
    })
}

fn parse_commit_list_inputs(inputs: &Value) -> Result<CommitListInputs, ProviderError> {
    let object = input_object(inputs, "gitlab commit.list inputs are invalid")?;
    reject_unknown_keys(
        object,
        &[
            "project",
            "refName",
            "path",
            "since",
            "until",
            "firstParent",
            "maxResults",
        ],
        "gitlab commit.list inputs are invalid",
    )?;
    let _ = object
        .get("project")
        .ok_or_else(|| ProviderError::deny(ReasonCode::InputInvalid, "project is required"))?;
    Ok(CommitListInputs {
        ref_name: optional_input_string(object.get("refName"), "refName")?,
        path: optional_input_string(object.get("path"), "path")?,
        since: optional_input_string(object.get("since"), "since")?,
        until: optional_input_string(object.get("until"), "until")?,
        first_parent: object
            .get("firstParent")
            .map(required_input_bool)
            .transpose()?,
        max_results: optional_input_u32(object.get("maxResults"), "maxResults")?,
    })
}

fn parse_commit_view_inputs(inputs: &Value) -> Result<CommitViewInputs, ProviderError> {
    let object = input_object(inputs, "gitlab commit.view inputs are invalid")?;
    reject_unknown_keys(
        object,
        &["project", "sha"],
        "gitlab commit.view inputs are invalid",
    )?;
    let sha = required_object_string(object, "sha")?;
    validate_commit_sha(&sha)?;
    Ok(CommitViewInputs { sha })
}

fn parse_commit_create_inputs(
    inputs: &Value,
    max_body_bytes: u64,
    max_file_bytes: u64,
    max_commit_actions: u32,
) -> Result<GitlabCommitCreateRequest, ProviderError> {
    let object = input_object(inputs, "gitlab commit.create inputs are invalid")?;
    reject_unknown_keys(
        object,
        &[
            "project",
            "branch",
            "commitMessage",
            "actions",
            "startBranch",
            "startSha",
            "authorName",
            "authorEmail",
        ],
        "gitlab commit.create inputs are invalid",
    )?;
    let _ = required_project_field(object)?;
    let branch = required_object_string(object, "branch")?;
    validate_branch_name(&branch)?;
    let start_branch = optional_input_string(object.get("startBranch"), "startBranch")?;
    if let Some(start_branch) = &start_branch {
        validate_branch_name(start_branch)?;
    }
    let start_sha = optional_input_string(object.get("startSha"), "startSha")?;
    if let Some(start_sha) = &start_sha {
        validate_full_commit_sha(start_sha, "startSha")?;
    }
    if start_branch.is_some() && start_sha.is_some() {
        return Err(ProviderError::deny(
            ReasonCode::InputInvalid,
            "gitlab commit.create accepts only one of startBranch or startSha",
        ));
    }
    let action_values = object
        .get("actions")
        .ok_or_else(|| ProviderError::deny(ReasonCode::InputInvalid, "actions is required"))?
        .as_array()
        .ok_or_else(|| ProviderError::deny(ReasonCode::InputInvalid, "actions must be an array"))?;
    if action_values.is_empty() {
        return Err(ProviderError::deny(
            ReasonCode::InputInvalid,
            "gitlab commit.create requires at least one action",
        ));
    }
    if action_values.len() as u32 > max_commit_actions {
        return Err(ProviderError::deny(
            ReasonCode::InputInvalid,
            "gitlab commit.create exceeds providers.gitlab.content.max_commit_actions",
        ));
    }
    let mut target_paths = std::collections::BTreeSet::new();
    let mut actions = Vec::with_capacity(action_values.len());
    for value in action_values {
        let action = parse_commit_action_input(value, max_file_bytes)?;
        if !target_paths.insert(action.file_path.clone()) {
            return Err(ProviderError::deny(
                ReasonCode::InputInvalid,
                "gitlab commit.create action filePath values must be unique",
            ));
        }
        actions.push(action);
    }
    Ok(GitlabCommitCreateRequest {
        branch,
        commit_message: required_bounded_string(object, "commitMessage", max_body_bytes, false)?,
        actions,
        start_branch,
        start_sha,
        author_name: optional_input_string(object.get("authorName"), "authorName")?,
        author_email: optional_input_string(object.get("authorEmail"), "authorEmail")?,
    })
}

fn parse_pipeline_list_inputs(inputs: &Value) -> Result<PipelineListInputs, ProviderError> {
    let object = input_object(inputs, "gitlab pipeline.list inputs are invalid")?;
    reject_unknown_keys(
        object,
        &[
            "project",
            "ref",
            "sha",
            "status",
            "source",
            "updatedAfter",
            "updatedBefore",
            "maxResults",
        ],
        "gitlab pipeline.list inputs are invalid",
    )?;
    let _ = required_project_field(object)?;
    let ref_name = optional_input_string(object.get("ref"), "ref")?;
    if let Some(ref_name) = &ref_name {
        validate_ref_name(ref_name)?;
    }
    let sha = optional_input_string(object.get("sha"), "sha")?;
    if let Some(sha) = &sha {
        validate_commit_sha(sha)?;
    }
    let status = optional_input_string(object.get("status"), "status")?;
    validate_optional_enum(
        status.as_deref(),
        GITLAB_PIPELINE_STATUSES,
        "gitlab pipeline.list status is unsupported",
    )?;
    Ok(PipelineListInputs {
        ref_name,
        sha,
        status,
        source: optional_input_string(object.get("source"), "source")?,
        updated_after: optional_input_string(object.get("updatedAfter"), "updatedAfter")?,
        updated_before: optional_input_string(object.get("updatedBefore"), "updatedBefore")?,
        max_results: optional_input_u32(object.get("maxResults"), "maxResults")?,
    })
}

fn parse_pipeline_object_inputs(inputs: &Value) -> Result<PipelineObjectInputs, ProviderError> {
    let object = input_object(inputs, "gitlab pipeline inputs are invalid")?;
    reject_unknown_keys(
        object,
        &["project", "pipelineId"],
        "gitlab pipeline inputs are invalid",
    )?;
    let _ = required_project_field(object)?;
    Ok(PipelineObjectInputs {
        pipeline_id: required_object_u64(object, "pipelineId")?,
    })
}

fn parse_pipeline_run_inputs(inputs: &Value) -> Result<GitlabPipelineRunRequest, ProviderError> {
    let object = input_object(inputs, "gitlab pipeline.run inputs are invalid")?;
    reject_unknown_keys(
        object,
        &["project", "ref"],
        "gitlab pipeline.run inputs are invalid",
    )?;
    let _ = required_project_field(object)?;
    let ref_name = required_object_string(object, "ref")?;
    validate_branch_name(&ref_name)?;
    Ok(GitlabPipelineRunRequest { ref_name })
}

fn parse_job_list_inputs(inputs: &Value) -> Result<JobListInputs, ProviderError> {
    let object = input_object(inputs, "gitlab job.list inputs are invalid")?;
    reject_unknown_keys(
        object,
        &["project", "pipelineId", "scope", "maxResults"],
        "gitlab job.list inputs are invalid",
    )?;
    let _ = required_project_field(object)?;
    let scope = optional_input_string(object.get("scope"), "scope")?;
    validate_optional_enum(
        scope.as_deref(),
        GITLAB_JOB_SCOPES,
        "gitlab job.list scope is unsupported",
    )?;
    Ok(JobListInputs {
        pipeline_id: object
            .get("pipelineId")
            .map(|value| required_input_u64(value, "pipelineId"))
            .transpose()?,
        scope,
        max_results: optional_input_u32(object.get("maxResults"), "maxResults")?,
    })
}

fn parse_job_object_inputs(inputs: &Value) -> Result<JobObjectInputs, ProviderError> {
    let object = input_object(inputs, "gitlab job inputs are invalid")?;
    reject_unknown_keys(
        object,
        &["project", "jobId"],
        "gitlab job inputs are invalid",
    )?;
    let _ = required_project_field(object)?;
    Ok(JobObjectInputs {
        job_id: required_object_u64(object, "jobId")?,
    })
}

fn parse_webhook_list_inputs(
    inputs: &Value,
    configured_max_results: u32,
) -> Result<WebhookListInputs, ProviderError> {
    const MESSAGE: &str = "gitlab webhook.list inputs are invalid";
    let object = input_object(inputs, MESSAGE)?;
    reject_unknown_keys(object, &["project", "maxResults", "pageToken"], MESSAGE)?;
    let _ = required_project_field(object)?;
    Ok(WebhookListInputs {
        max_results: capped_max_results(
            optional_input_u32(object.get("maxResults"), "maxResults")?,
            configured_max_results,
        )?,
        page_token: optional_webhook_page_token(object.get("pageToken"))?,
    })
}

fn parse_webhook_object_inputs(inputs: &Value) -> Result<WebhookObjectInputs, ProviderError> {
    const MESSAGE: &str = "gitlab webhook inputs are invalid";
    let object = input_object(inputs, MESSAGE)?;
    reject_unknown_keys(object, &["project", "webhookId"], MESSAGE)?;
    let _ = required_project_field(object)?;
    Ok(WebhookObjectInputs {
        webhook_id: required_webhook_id(object, "webhookId")?,
    })
}

fn parse_webhook_events(value: &Value) -> Result<Vec<GitlabWebhookEvent>, ProviderError> {
    let raw = value
        .as_array()
        .ok_or_else(|| ProviderError::deny(ReasonCode::InputInvalid, "events must be an array"))?;
    let mut events = BTreeSet::new();
    for value in raw {
        let event: GitlabWebhookEvent = serde_json::from_value(value.clone()).map_err(|_| {
            ProviderError::deny(
                ReasonCode::InputInvalid,
                "GitLab webhook event is unsupported",
            )
        })?;
        if !events.insert(event) {
            return Err(ProviderError::deny(
                ReasonCode::InputInvalid,
                "GitLab webhook events must be unique",
            ));
        }
    }
    Ok(events.into_iter().collect())
}

fn optional_nullable_bounded_string(
    value: Option<&Value>,
    key: &str,
    max_bytes: u64,
) -> Result<Option<Option<String>>, ProviderError> {
    match value {
        None => Ok(None),
        Some(Value::Null) => Ok(Some(None)),
        Some(value) => Ok(Some(Some(bounded_input_string(
            value, key, max_bytes, true,
        )?))),
    }
}

fn parse_webhook_write_inputs(
    inputs: &Value,
    create: bool,
    max_body_bytes: u64,
) -> Result<WebhookWriteInputs, ProviderError> {
    const MESSAGE: &str = "gitlab webhook mutation inputs are invalid";
    let object = input_object(inputs, MESSAGE)?;
    reject_unknown_keys(
        object,
        &[
            "project",
            "webhookId",
            "url",
            "events",
            "name",
            "description",
            "enableSslVerification",
            "branchFilterStrategy",
            "pushEventsBranchFilter",
            "customWebhookTemplate",
            "token",
            "signingToken",
            "clearToken",
            "confirmDestinationReset",
        ],
        MESSAGE,
    )?;
    let _ = required_project_field(object)?;
    let webhook_id = object
        .get("webhookId")
        .map(|value| required_webhook_id_value(value, "webhookId"))
        .transpose()?;
    if create == webhook_id.is_some() {
        return Err(ProviderError::deny(
            ReasonCode::InputInvalid,
            if create {
                "webhookId is not accepted on create"
            } else {
                "webhookId is required"
            },
        ));
    }
    let url = optional_bounded_string(object.get("url"), "url", max_body_bytes, false)?;
    let events = object.get("events").map(parse_webhook_events).transpose()?;
    if create && (url.is_none() || events.is_none()) {
        return Err(ProviderError::deny(
            ReasonCode::InputInvalid,
            "gitlab webhook.create requires url and events",
        ));
    }
    let branch_filter_strategy =
        optional_input_string(object.get("branchFilterStrategy"), "branchFilterStrategy")?;
    validate_optional_enum(
        branch_filter_strategy.as_deref(),
        &["wildcard", "regex", "all_branches"],
        "GitLab webhook branchFilterStrategy is unsupported",
    )?;
    let token = optional_bounded_string(object.get("token"), "token", max_body_bytes, false)?;
    let clear_token = optional_input_bool(object.get("clearToken"), "clearToken")?.unwrap_or(false);
    if token.is_some() && clear_token {
        return Err(ProviderError::deny(
            ReasonCode::InputInvalid,
            "token and clearToken cannot be combined",
        ));
    }
    if create
        && (object.contains_key("clearToken") || object.contains_key("confirmDestinationReset"))
    {
        return Err(ProviderError::deny(ReasonCode::InputInvalid, MESSAGE));
    }
    let mutable_count = [
        object.contains_key("url"),
        object.contains_key("events"),
        object.contains_key("name"),
        object.contains_key("description"),
        object.contains_key("enableSslVerification"),
        object.contains_key("branchFilterStrategy"),
        object.contains_key("pushEventsBranchFilter"),
        object.contains_key("customWebhookTemplate"),
        object.contains_key("token"),
        object.contains_key("signingToken"),
        clear_token,
    ]
    .into_iter()
    .filter(|present| *present)
    .count();
    if !create && mutable_count == 0 {
        return Err(ProviderError::deny(
            ReasonCode::InputInvalid,
            "gitlab webhook.update requires at least one mutable field",
        ));
    }
    Ok(WebhookWriteInputs {
        webhook_id,
        url,
        events,
        name: optional_nullable_bounded_string(object.get("name"), "name", max_body_bytes)?,
        description: optional_nullable_bounded_string(
            object.get("description"),
            "description",
            max_body_bytes,
        )?,
        enable_ssl_verification: optional_input_bool(
            object.get("enableSslVerification"),
            "enableSslVerification",
        )?,
        branch_filter_strategy,
        push_events_branch_filter: optional_bounded_string(
            object.get("pushEventsBranchFilter"),
            "pushEventsBranchFilter",
            max_body_bytes,
            true,
        )?,
        custom_webhook_template: optional_nullable_bounded_string(
            object.get("customWebhookTemplate"),
            "customWebhookTemplate",
            max_body_bytes,
        )?,
        token,
        signing_token: optional_bounded_string(
            object.get("signingToken"),
            "signingToken",
            max_body_bytes,
            false,
        )?
        .map(validate_signing_token)
        .transpose()?,
        clear_token,
        confirm_destination_reset: optional_input_bool(
            object.get("confirmDestinationReset"),
            "confirmDestinationReset",
        )?
        .unwrap_or(false),
    })
}

fn parse_webhook_test_inputs(inputs: &Value) -> Result<WebhookTestInputs, ProviderError> {
    const MESSAGE: &str = "gitlab webhook.test inputs are invalid";
    let object = input_object(inputs, MESSAGE)?;
    reject_unknown_keys(object, &["project", "webhookId", "event"], MESSAGE)?;
    let _ = required_project_field(object)?;
    let event: GitlabWebhookEvent = serde_json::from_value(
        object
            .get("event")
            .cloned()
            .ok_or_else(|| ProviderError::deny(ReasonCode::InputInvalid, "event is required"))?,
    )
    .map_err(|_| {
        ProviderError::deny(
            ReasonCode::InputInvalid,
            "GitLab webhook event is unsupported",
        )
    })?;
    if event.test_trigger().is_none() {
        return Err(ProviderError::deny(
            ReasonCode::InputInvalid,
            "GitLab webhook event cannot be tested",
        ));
    }
    Ok(WebhookTestInputs {
        webhook_id: required_webhook_id(object, "webhookId")?,
        event,
    })
}

fn parse_webhook_event_list_inputs(
    inputs: &Value,
) -> Result<WebhookEventListInputs, ProviderError> {
    const MESSAGE: &str = "gitlab webhook.event.list inputs are invalid";
    let object = input_object(inputs, MESSAGE)?;
    reject_unknown_keys(
        object,
        &["project", "webhookId", "status", "maxResults", "pageToken"],
        MESSAGE,
    )?;
    let _ = required_project_field(object)?;
    let status = optional_input_string(object.get("status"), "status")?;
    if status.as_deref().is_some_and(|value| {
        !(matches!(value, "successful" | "client_failure" | "server_failure")
            || value.len() == 3 && value.bytes().all(|byte| byte.is_ascii_digit()))
    }) {
        return Err(ProviderError::deny(
            ReasonCode::InputInvalid,
            "GitLab webhook delivery status is unsupported",
        ));
    }
    Ok(WebhookEventListInputs {
        webhook_id: required_webhook_id(object, "webhookId")?,
        status,
        max_results: capped_max_results(
            optional_input_u32(object.get("maxResults"), "maxResults")?,
            GITLAB_WEBHOOK_EVENT_MAX_PER_PAGE,
        )?,
        page_token: optional_webhook_page_token(object.get("pageToken"))?,
    })
}

fn parse_webhook_event_resend_inputs(
    inputs: &Value,
) -> Result<WebhookEventResendInputs, ProviderError> {
    const MESSAGE: &str = "gitlab webhook.event.resend inputs are invalid";
    let object = input_object(inputs, MESSAGE)?;
    reject_unknown_keys(object, &["project", "webhookId", "webhookEventId"], MESSAGE)?;
    let _ = required_project_field(object)?;
    Ok(WebhookEventResendInputs {
        webhook_id: required_webhook_id(object, "webhookId")?,
        webhook_event_id: required_webhook_id(object, "webhookEventId")?,
    })
}

fn validate_webhook_header_component(value: &str, key: &str) -> Result<(), ProviderError> {
    let lower = value.to_ascii_lowercase();
    if value.is_empty()
        || value.len() > GITLAB_WEBHOOK_HEADER_MAX_BYTES
        || value.trim() != value
        || value.chars().any(char::is_control)
        || lower.contains("%0a")
        || lower.contains("%0d")
    {
        return Err(ProviderError::deny(
            ReasonCode::InputInvalid,
            format!("GitLab webhook custom header {key} is invalid"),
        ));
    }
    Ok(())
}

fn parse_webhook_custom_header_inputs(
    inputs: &Value,
    set: bool,
) -> Result<GitlabWebhookCustomHeaderRequest, ProviderError> {
    const MESSAGE: &str = "gitlab webhook custom-header inputs are invalid";
    let object = input_object(inputs, MESSAGE)?;
    let allowed = if set {
        &["project", "webhookId", "key", "value"][..]
    } else {
        &["project", "webhookId", "key"][..]
    };
    reject_unknown_keys(object, allowed, MESSAGE)?;
    let _ = required_project_field(object)?;
    let key = required_object_string(object, "key")?;
    validate_webhook_header_component(&key, "key")?;
    let value = if set {
        let value = required_object_string(object, "value")?;
        validate_webhook_header_component(&value, "value")?;
        Some(value)
    } else {
        None
    };
    Ok(GitlabWebhookCustomHeaderRequest {
        webhook_id: required_webhook_id(object, "webhookId")?,
        key,
        value,
    })
}

fn required_webhook_id(
    object: &serde_json::Map<String, Value>,
    key: &str,
) -> Result<u64, ProviderError> {
    let value = object.get(key).ok_or_else(|| {
        ProviderError::deny(ReasonCode::InputInvalid, format!("{key} is required"))
    })?;
    required_webhook_id_value(value, key)
}

fn optional_webhook_page_token(value: Option<&Value>) -> Result<Option<String>, ProviderError> {
    let token = optional_input_string(value, "pageToken")?;
    if token
        .as_ref()
        .is_some_and(|token| token.is_empty() || token.len() > GITLAB_PAGE_TOKEN_MAX_BYTES)
    {
        return Err(ProviderError::deny(
            ReasonCode::InputInvalid,
            "pageToken is invalid",
        ));
    }
    Ok(token)
}

fn required_webhook_id_value(value: &Value, key: &str) -> Result<u64, ProviderError> {
    value.as_u64().filter(|value| *value > 0).ok_or_else(|| {
        ProviderError::deny(
            ReasonCode::InputInvalid,
            format!("{key} must be a positive JSON integer"),
        )
    })
}

fn validate_signing_token(value: String) -> Result<String, ProviderError> {
    let valid = value
        .strip_prefix("whsec_")
        .and_then(|encoded| BASE64.decode(encoded).ok())
        .is_some_and(|decoded| decoded.len() == 32);
    if !valid {
        return Err(ProviderError::deny(
            ReasonCode::InputInvalid,
            "signingToken must be a whsec_ prefixed base64-encoded 32-byte value",
        ));
    }
    Ok(value)
}

fn parse_commit_action_input(
    value: &Value,
    max_file_bytes: u64,
) -> Result<GitlabCommitActionRequest, ProviderError> {
    let object = input_object(value, "gitlab commit.create action inputs are invalid")?;
    reject_unknown_keys(
        object,
        &[
            "action",
            "filePath",
            "previousPath",
            "content",
            "encoding",
            "executeFilemode",
            "lastCommitId",
        ],
        "gitlab commit.create action inputs are invalid",
    )?;
    let action = required_object_string(object, "action")?;
    validate_optional_enum(
        Some(action.as_str()),
        GITLAB_COMMIT_ACTIONS,
        "gitlab commit.create action is unsupported",
    )?;
    let file_path = required_object_string(object, "filePath")?;
    validate_gitlab_file_path(&file_path)?;
    let previous_path = optional_input_string(object.get("previousPath"), "previousPath")?;
    if let Some(previous_path) = &previous_path {
        validate_gitlab_file_path(previous_path)?;
    }
    let encoding = optional_gitlab_content_encoding(object.get("encoding"))?;
    let content = optional_input_string(object.get("content"), "content")?;
    let decoded_content_bytes = content
        .as_ref()
        .map(|content| {
            validate_gitlab_content_bytes(content, encoding.as_deref(), max_file_bytes, "content")
        })
        .transpose()?;
    let execute_filemode = optional_input_bool(object.get("executeFilemode"), "executeFilemode")?;
    match action.as_str() {
        "create" | "update" => {
            if content.is_none() {
                return Err(ProviderError::deny(
                    ReasonCode::InputInvalid,
                    "gitlab commit.create create/update actions require content",
                ));
            }
        }
        "move" => {
            if previous_path.is_none() {
                return Err(ProviderError::deny(
                    ReasonCode::InputInvalid,
                    "gitlab commit.create move actions require previousPath",
                ));
            }
        }
        "delete" => {
            if content.is_some() || encoding.is_some() || execute_filemode.is_some() {
                return Err(ProviderError::deny(
                    ReasonCode::InputInvalid,
                    "gitlab commit.create delete actions do not accept content, encoding, or executeFilemode",
                ));
            }
        }
        "chmod" => {
            if execute_filemode.is_none() {
                return Err(ProviderError::deny(
                    ReasonCode::InputInvalid,
                    "gitlab commit.create chmod actions require executeFilemode",
                ));
            }
            if content.is_some() || encoding.is_some() {
                return Err(ProviderError::deny(
                    ReasonCode::InputInvalid,
                    "gitlab commit.create chmod actions do not accept content or encoding",
                ));
            }
        }
        _ => unreachable!("validated action"),
    }
    Ok(GitlabCommitActionRequest {
        action,
        file_path,
        previous_path,
        content,
        encoding,
        execute_filemode,
        last_commit_id: optional_last_commit_id(object.get("lastCommitId"))?,
        decoded_content_bytes,
    })
}

fn input_object<'a>(
    inputs: &'a Value,
    message: &'static str,
) -> Result<&'a serde_json::Map<String, Value>, ProviderError> {
    inputs
        .as_object()
        .ok_or_else(|| ProviderError::deny(ReasonCode::InputInvalid, message))
}

fn reject_unknown_keys(
    object: &serde_json::Map<String, Value>,
    allowed: &[&str],
    message: &'static str,
) -> Result<(), ProviderError> {
    if object.keys().any(|key| !allowed.contains(&key.as_str())) {
        return Err(ProviderError::deny(ReasonCode::InputInvalid, message));
    }
    Ok(())
}

fn required_object_string(
    object: &serde_json::Map<String, Value>,
    key: &str,
) -> Result<String, ProviderError> {
    let value = object.get(key).ok_or_else(|| {
        ProviderError::deny(ReasonCode::InputInvalid, format!("{key} is required"))
    })?;
    required_input_string(value, key).map(ToString::to_string)
}

fn required_object_u64(
    object: &serde_json::Map<String, Value>,
    key: &str,
) -> Result<u64, ProviderError> {
    let value = object.get(key).ok_or_else(|| {
        ProviderError::deny(ReasonCode::InputInvalid, format!("{key} is required"))
    })?;
    required_input_u64(value, key)
}

fn required_project_field(object: &serde_json::Map<String, Value>) -> Result<&str, ProviderError> {
    let project = object
        .get("project")
        .ok_or_else(|| ProviderError::deny(ReasonCode::InputInvalid, "project is required"))?;
    required_input_string(project, "project")
}

fn required_bounded_string(
    object: &serde_json::Map<String, Value>,
    key: &str,
    max_body_bytes: u64,
    allow_empty: bool,
) -> Result<String, ProviderError> {
    let value = object.get(key).ok_or_else(|| {
        ProviderError::deny(ReasonCode::InputInvalid, format!("{key} is required"))
    })?;
    bounded_input_string(value, key, max_body_bytes, allow_empty)
}

fn optional_bounded_string(
    value: Option<&Value>,
    key: &str,
    max_body_bytes: u64,
    allow_empty: bool,
) -> Result<Option<String>, ProviderError> {
    value
        .map(|value| bounded_input_string(value, key, max_body_bytes, allow_empty))
        .transpose()
}

fn prepare_optional_gitlab_content(
    object: &serde_json::Map<String, Value>,
    action: &str,
    max_body_bytes: u64,
) -> Result<Option<String>, ProviderError> {
    match (object.get("contentFormat"), object.get("content")) {
        (None, None) => Ok(None),
        (Some(content_format), Some(content)) => {
            prepare_gitlab_content(action, content_format, content, max_body_bytes, true).map(Some)
        }
        _ => Err(ProviderError::deny(
            ReasonCode::InputInvalid,
            format!("{action} requires content and contentFormat together"),
        )),
    }
}

fn prepare_required_gitlab_content(
    object: &serde_json::Map<String, Value>,
    action: &str,
    max_body_bytes: u64,
) -> Result<String, ProviderError> {
    let content_format = object.get("contentFormat").ok_or_else(|| {
        ProviderError::deny(
            ReasonCode::InputInvalid,
            format!("{action} contentFormat is required"),
        )
    })?;
    let content = object.get("content").ok_or_else(|| {
        ProviderError::deny(
            ReasonCode::InputInvalid,
            format!("{action} content is required"),
        )
    })?;
    prepare_gitlab_content(action, content_format, content, max_body_bytes, false)
}

fn reject_gitlab_quick_actions(body: &str) -> Result<(), ProviderError> {
    if contains_command_like_gitlab_quick_action(body) {
        return Err(ProviderError::deny(
            ReasonCode::InputInvalid,
            "GitLab content must not contain command-like quick-action lines",
        ));
    }
    Ok(())
}

fn contains_command_like_gitlab_quick_action(body: &str) -> bool {
    let mut fenced_ranges = Parser::new_ext(body, Options::empty())
        .into_offset_iter()
        .filter_map(|(event, source)| {
            matches!(
                event,
                Event::Start(Tag::CodeBlock(CodeBlockKind::Fenced(_)))
            )
            .then_some(source)
        })
        .peekable();
    let mut line_offset = 0;
    for line in body.split_inclusive('\n') {
        while fenced_ranges
            .peek()
            .is_some_and(|source| source.end <= line_offset)
        {
            fenced_ranges.next();
        }
        let in_fenced_code = fenced_ranges
            .peek()
            .is_some_and(|source| source.start <= line_offset && line_offset < source.end);
        if !in_fenced_code && is_command_like_gitlab_quick_action_line(line) {
            return true;
        }
        line_offset += line.len();
    }
    false
}

fn is_command_like_gitlab_quick_action_line(line: &str) -> bool {
    let line = line.trim_start();
    let Some(command) = line.strip_prefix('/') else {
        return false;
    };
    let bytes = command.as_bytes();
    if !bytes.first().is_some_and(u8::is_ascii_alphabetic) {
        return false;
    }
    let token_end = bytes
        .iter()
        .position(|byte| !(byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-')))
        .unwrap_or(bytes.len());
    token_end == bytes.len()
        || command[token_end..]
            .chars()
            .next()
            .is_some_and(char::is_whitespace)
}

fn prepare_gitlab_content(
    action: &str,
    content_format: &Value,
    content: &Value,
    max_body_bytes: u64,
    allow_empty: bool,
) -> Result<String, ProviderError> {
    let content_format = required_input_string(content_format, "contentFormat")?;
    if !matches!(content_format, "markdown" | "plain_text") {
        return Err(ProviderError::deny(
            ReasonCode::BodyFormatUnsupported,
            format!("{action} contentFormat is unsupported"),
        ));
    }
    let source = required_input_string(content, "content")?;
    if source.len() as u64 > max_body_bytes {
        return Err(ProviderError::deny(
            ReasonCode::BodySizeDenied,
            format!("{action} source content exceeded the configured byte cap"),
        ));
    }
    if !allow_empty && source.trim().is_empty() {
        return Err(ProviderError::deny(
            ReasonCode::InputInvalid,
            format!("{action} content must not be empty"),
        ));
    }
    let body = match content_format {
        "markdown" => Ok(source.to_string()),
        "plain_text" => plain_text_to_gitlab_markdown_bounded(source, max_body_bytes)
            .map_err(map_gitlab_content_write_error),
        _ => unreachable!("content format was validated"),
    }?;
    reject_gitlab_quick_actions(&body)?;
    Ok(body)
}

fn map_gitlab_content_write_error(error: ContentWriteError) -> ProviderError {
    match error {
        ContentWriteError::SizeDenied => ProviderError::deny(
            ReasonCode::BodySizeDenied,
            "converted GitLab content exceeded the configured byte cap",
        ),
        ContentWriteError::ComplexityDenied | ContentWriteError::Malformed => ProviderError::deny(
            ReasonCode::BodyMalformed,
            "GitLab content could not be converted safely",
        ),
    }
}

fn bounded_input_string(
    value: &Value,
    key: &str,
    max_body_bytes: u64,
    allow_empty: bool,
) -> Result<String, ProviderError> {
    let value = required_input_string(value, key)?;
    if !allow_empty && value.trim().is_empty() {
        return Err(ProviderError::deny(
            ReasonCode::InputInvalid,
            format!("{key} must not be empty"),
        ));
    }
    if value.len() as u64 > max_body_bytes {
        return Err(ProviderError::deny(
            ReasonCode::InputInvalid,
            format!("{key} exceeds providers.gitlab.content.max_body_bytes"),
        ));
    }
    Ok(value.to_string())
}

fn enforce_bounded_text_field(
    key: &str,
    value: &str,
    max_body_bytes: u64,
    after_attribution: bool,
) -> Result<(), ProviderError> {
    if value.len() as u64 > max_body_bytes {
        let message = if after_attribution {
            format!(
                "{key} exceeds providers.gitlab.content.max_body_bytes after broker attribution was added"
            )
        } else {
            format!("{key} exceeds providers.gitlab.content.max_body_bytes")
        };
        return Err(ProviderError::deny(ReasonCode::BodySizeDenied, message));
    }
    Ok(())
}

fn required_input_string<'a>(value: &'a Value, key: &str) -> Result<&'a str, ProviderError> {
    value.as_str().ok_or_else(|| {
        ProviderError::deny(ReasonCode::InputInvalid, format!("{key} must be a string"))
    })
}

fn required_non_empty_string(
    object: &serde_json::Map<String, Value>,
    key: &str,
) -> Result<String, ProviderError> {
    let value = object.get(key).ok_or_else(|| {
        ProviderError::deny(ReasonCode::InputInvalid, format!("{key} is required"))
    })?;
    let value = required_input_string(value, key)?;
    if value.trim().is_empty() {
        return Err(ProviderError::deny(
            ReasonCode::InputInvalid,
            format!("{key} must not be empty"),
        ));
    }
    Ok(value.to_string())
}

fn optional_input_string(
    value: Option<&Value>,
    key: &str,
) -> Result<Option<String>, ProviderError> {
    value
        .map(|value| required_input_string(value, key).map(ToString::to_string))
        .transpose()
}

fn required_input_u64(value: &Value, key: &str) -> Result<u64, ProviderError> {
    value
        .as_u64()
        .or_else(|| value.as_str()?.parse::<u64>().ok())
        .filter(|value| *value > 0)
        .ok_or_else(|| {
            ProviderError::deny(
                ReasonCode::InputInvalid,
                format!("{key} must be a positive integer"),
            )
        })
}

fn optional_positive_input_u64(
    value: Option<&Value>,
    key: &str,
) -> Result<Option<u64>, ProviderError> {
    value
        .map(|value| {
            value.as_u64().filter(|value| *value > 0).ok_or_else(|| {
                ProviderError::deny(
                    ReasonCode::InputInvalid,
                    format!("{key} must be a positive integer"),
                )
            })
        })
        .transpose()
}

fn optional_nonnegative_input_u64(
    value: Option<&Value>,
    key: &str,
) -> Result<Option<u64>, ProviderError> {
    value
        .map(|value| {
            value.as_u64().ok_or_else(|| {
                ProviderError::deny(
                    ReasonCode::InputInvalid,
                    format!("{key} must be a non-negative integer"),
                )
            })
        })
        .transpose()
}

fn optional_input_u32(value: Option<&Value>, key: &str) -> Result<Option<u32>, ProviderError> {
    value
        .map(|value| {
            let value = required_input_u64(value, key)?;
            u32::try_from(value).map_err(|_| {
                ProviderError::deny(
                    ReasonCode::InputInvalid,
                    format!("{key} must fit in an unsigned 32-bit integer"),
                )
            })
        })
        .transpose()
}

fn required_input_bool(value: &Value) -> Result<bool, ProviderError> {
    value.as_bool().ok_or_else(|| {
        ProviderError::deny(ReasonCode::InputInvalid, "firstParent must be a boolean")
    })
}

fn optional_input_bool(value: Option<&Value>, key: &str) -> Result<Option<bool>, ProviderError> {
    value
        .map(|value| {
            value.as_bool().ok_or_else(|| {
                ProviderError::deny(ReasonCode::InputInvalid, format!("{key} must be a boolean"))
            })
        })
        .transpose()
}

fn optional_string_array(value: Option<&Value>, key: &str) -> Result<Vec<String>, ProviderError> {
    let Some(value) = value else {
        return Ok(Vec::new());
    };
    let values = value.as_array().ok_or_else(|| {
        ProviderError::deny(ReasonCode::InputInvalid, format!("{key} must be an array"))
    })?;
    if values.is_empty() {
        return Err(ProviderError::deny(
            ReasonCode::InputInvalid,
            format!("{key} must not be empty"),
        ));
    }
    values
        .iter()
        .map(|value| required_input_string(value, key).map(ToString::to_string))
        .collect()
}

fn optional_non_empty_string_array(
    value: Option<&Value>,
    key: &str,
) -> Result<Vec<String>, ProviderError> {
    let values = optional_string_array(value, key)?;
    if values.iter().any(|value| value.trim().is_empty()) {
        return Err(ProviderError::deny(
            ReasonCode::InputInvalid,
            format!("{key} values must not be empty"),
        ));
    }
    Ok(values)
}

fn optional_u64_array(value: Option<&Value>, key: &str) -> Result<Vec<u64>, ProviderError> {
    let Some(value) = value else {
        return Ok(Vec::new());
    };
    let values = value.as_array().ok_or_else(|| {
        ProviderError::deny(ReasonCode::InputInvalid, format!("{key} must be an array"))
    })?;
    if values.is_empty() {
        return Err(ProviderError::deny(
            ReasonCode::InputInvalid,
            format!("{key} must not be empty"),
        ));
    }
    values
        .iter()
        .map(|value| required_input_u64(value, key))
        .collect()
}

fn optional_state_event(value: Option<&Value>) -> Result<Option<String>, ProviderError> {
    let state_event = optional_input_string(value, "stateEvent")?;
    if let Some(state_event) = &state_event
        && !matches!(state_event.as_str(), "close" | "reopen")
    {
        return Err(ProviderError::deny(
            ReasonCode::InputInvalid,
            "stateEvent is unsupported",
        ));
    }
    Ok(state_event)
}

fn validate_label_update_shape(
    labels: &[String],
    add_labels: &[String],
    remove_labels: &[String],
) -> Result<(), ProviderError> {
    if !labels.is_empty() && (!add_labels.is_empty() || !remove_labels.is_empty()) {
        return Err(ProviderError::deny(
            ReasonCode::InputInvalid,
            "labels cannot be combined with addLabels or removeLabels",
        ));
    }
    Ok(())
}

fn normalize_project_path(value: &str) -> Result<String, ProviderError> {
    let trimmed = value.trim().trim_matches('/');
    if trimmed.is_empty()
        || trimmed.bytes().all(|byte| byte.is_ascii_digit())
        || trimmed.split('/').count() < 2
        || !is_repository_selector_path(trimmed)
    {
        return Err(ProviderError::deny(
            ReasonCode::LocatorInvalid,
            "GitLab project locator is invalid",
        ));
    }
    Ok(trimmed.to_string())
}

fn project_path_from_web_url(
    value: &str,
    config: &GitlabProviderConfig,
) -> Result<String, ProviderError> {
    let relative = relative_gitlab_web_path_segments(value, config)?;
    let marker = relative
        .iter()
        .position(|segment| segment == "-")
        .unwrap_or(relative.len());
    normalize_project_path(&relative[..marker].join("/"))
}

fn numbered_object_from_web_url(
    value: &str,
    config: &GitlabProviderConfig,
    object_path_segment: &str,
) -> Result<(String, u64), ProviderError> {
    let relative = relative_gitlab_web_path_segments(value, config)?;
    let Some(marker) = relative.iter().position(|segment| segment == "-") else {
        return Err(ProviderError::deny(
            ReasonCode::LocatorInvalid,
            "GitLab object URL is invalid",
        ));
    };
    if relative.get(marker + 1).map(String::as_str) != Some(object_path_segment) {
        return Err(ProviderError::deny(
            ReasonCode::LocatorInvalid,
            "GitLab object URL is invalid",
        ));
    }
    let iid = relative
        .get(marker + 2)
        .and_then(|value| value.parse::<u64>().ok())
        .filter(|value| *value > 0)
        .ok_or_else(|| {
            ProviderError::deny(ReasonCode::LocatorInvalid, "GitLab object URL is invalid")
        })?;
    Ok((normalize_project_path(&relative[..marker].join("/"))?, iid))
}

fn relative_gitlab_web_path_segments(
    value: &str,
    config: &GitlabProviderConfig,
) -> Result<Vec<String>, ProviderError> {
    let url = Url::parse(value)
        .map_err(|_| ProviderError::deny(ReasonCode::LocatorInvalid, "GitLab URL is invalid"))?;
    let web_base = Url::parse(&config.web_base_url).map_err(|_| {
        ProviderError::error(
            ReasonCode::UpstreamProtocolFailed,
            "GitLab web base URL is invalid",
        )
    })?;
    if !same_origin(&url, &web_base) || url.query().is_some() || url.fragment().is_some() {
        return Err(ProviderError::deny(
            ReasonCode::LocatorInvalid,
            "GitLab URL is outside the configured instance",
        ));
    }
    let base = path_segments(&web_base);
    let path = path_segments(&url);
    if !path.starts_with(&base) {
        return Err(ProviderError::deny(
            ReasonCode::LocatorInvalid,
            "GitLab URL is outside the configured instance",
        ));
    }
    let relative = path[base.len()..].to_vec();
    if relative.is_empty() {
        return Err(ProviderError::deny(
            ReasonCode::LocatorInvalid,
            "GitLab URL path is invalid",
        ));
    }
    Ok(relative)
}

fn path_segments(url: &Url) -> Vec<String> {
    url.path_segments()
        .into_iter()
        .flatten()
        .filter(|segment| !segment.is_empty())
        .map(ToString::to_string)
        .collect()
}

fn validate_branch_name(value: &str) -> Result<(), ProviderError> {
    if value.is_empty()
        || value.starts_with('/')
        || value.ends_with('/')
        || value.starts_with('-')
        || value.starts_with("refs/")
        || value.contains("//")
        || value.contains("..")
        || value.contains('\\')
        || value.chars().any(char::is_control)
    {
        return Err(ProviderError::deny(
            ReasonCode::InputInvalid,
            "GitLab branch name is invalid",
        ));
    }
    Ok(())
}

fn validate_protected_branch_rule_name(value: &str) -> Result<(), ProviderError> {
    if value.trim().is_empty() || value.len() > 255 || value.chars().any(char::is_control) {
        return Err(ProviderError::deny(
            ReasonCode::InputInvalid,
            "GitLab protected branch rule name is invalid",
        ));
    }
    Ok(())
}

fn validate_ref_name(value: &str) -> Result<(), ProviderError> {
    if value.trim().is_empty() || value.chars().any(char::is_control) {
        return Err(ProviderError::deny(
            ReasonCode::InputInvalid,
            "GitLab ref is invalid",
        ));
    }
    Ok(())
}

fn validate_gitlab_file_path(value: &str) -> Result<(), ProviderError> {
    if value.is_empty()
        || value.starts_with('/')
        || value.ends_with('/')
        || value.contains('\\')
        || value.contains("//")
        || value.chars().any(char::is_control)
        || value
            .split('/')
            .any(|segment| segment.is_empty() || segment == "." || segment == "..")
    {
        return Err(ProviderError::deny(
            ReasonCode::InputInvalid,
            "GitLab file path is invalid",
        ));
    }
    Ok(())
}

fn validate_commit_sha(value: &str) -> Result<(), ProviderError> {
    if !(7..=64).contains(&value.len()) || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(ProviderError::deny(
            ReasonCode::InputInvalid,
            "GitLab commit sha is invalid",
        ));
    }
    Ok(())
}

fn validate_full_commit_sha(value: &str, field: &str) -> Result<(), ProviderError> {
    if !is_full_commit_sha(value) {
        return Err(ProviderError::deny(
            ReasonCode::InputInvalid,
            format!("GitLab {field} must be a full 40-character commit sha"),
        ));
    }
    Ok(())
}

fn is_full_commit_sha(value: &str) -> bool {
    value.len() == 40 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn optional_last_commit_id(value: Option<&Value>) -> Result<Option<String>, ProviderError> {
    let value = optional_input_string(value, "lastCommitId")?;
    if let Some(value) = &value {
        validate_commit_sha(value)?;
    }
    Ok(value)
}

fn optional_gitlab_content_encoding(
    value: Option<&Value>,
) -> Result<Option<String>, ProviderError> {
    let encoding = optional_input_string(value, "encoding")?;
    if let Some(encoding) = &encoding
        && !matches!(encoding.as_str(), "text" | "base64")
    {
        return Err(ProviderError::deny(
            ReasonCode::InputInvalid,
            "GitLab content encoding is unsupported",
        ));
    }
    Ok(encoding)
}

fn validate_gitlab_content_bytes(
    content: &str,
    encoding: Option<&str>,
    max_file_bytes: u64,
    field: &str,
) -> Result<u64, ProviderError> {
    let len = if encoding == Some("base64") {
        BASE64
            .decode(content)
            .map_err(|_| {
                ProviderError::deny(
                    ReasonCode::InputInvalid,
                    format!("{field} is not valid base64"),
                )
            })?
            .len() as u64
    } else {
        content.len() as u64
    };
    if len > max_file_bytes {
        return Err(ProviderError::deny(
            ReasonCode::InputInvalid,
            format!("{field} exceeds providers.gitlab.content.max_file_bytes"),
        ));
    }
    Ok(len)
}

fn validate_gitlab_raw_download_size(
    size: u64,
    max_download_bytes: u64,
) -> Result<(), ProviderError> {
    if size > max_download_bytes {
        return Err(ProviderError::deny(
            ReasonCode::AttachmentSizeDenied,
            "GitLab raw file exceeds the configured download cap",
        ));
    }
    Ok(())
}

fn validate_gitlab_raw_diff_download_size(
    size: Option<u64>,
    max_download_bytes: u64,
) -> Result<(), ProviderError> {
    if size.is_some_and(|size| size > max_download_bytes) {
        return Err(ProviderError::deny(
            ReasonCode::AttachmentSizeDenied,
            "GitLab raw diff exceeded the configured byte cap",
        ));
    }
    Ok(())
}

fn validate_gitlab_job_trace_download_size(
    size: u64,
    max_download_bytes: u64,
) -> Result<(), ProviderError> {
    if size > max_download_bytes {
        return Err(ProviderError::deny(
            ReasonCode::AttachmentSizeDenied,
            "GitLab job trace exceeds the configured download cap",
        ));
    }
    Ok(())
}

fn capped_max_results(requested: Option<u32>, configured_max: u32) -> Result<u32, ProviderError> {
    let requested = requested.unwrap_or(configured_max);
    if requested == 0 {
        return Err(ProviderError::deny(
            ReasonCode::InputInvalid,
            "maxResults must be greater than zero",
        ));
    }
    Ok(requested.min(configured_max).min(GITLAB_MAX_PER_PAGE))
}

fn repository_scopes_from_project(project: &GitlabProject) -> ResourceScopes {
    repository_scopes_from_path(&project.path_with_namespace)
}

fn repository_scopes_from_projects<'a>(
    projects: impl IntoIterator<Item = &'a GitlabProject>,
) -> ResourceScopes {
    let mut repositories = BTreeSet::new();
    for project in projects {
        repositories.insert(project.path_with_namespace.clone());
    }
    ResourceScopes::from([("repository".to_string(), repositories.into_iter().collect())])
}

fn ensure_distinct_project_paths(
    target: &GitlabProject,
    source: &GitlabProject,
) -> Result<(), ProviderError> {
    if target.id != source.id && target.path_with_namespace == source.path_with_namespace {
        return Err(suggestion_scope_changed_error());
    }
    Ok(())
}

fn suggestion_scope_changed_error() -> ProviderError {
    ProviderError::deny(
        ReasonCode::ScopeUnresolved,
        "GitLab merge request repository scope changed before suggestion apply",
    )
}

fn repository_scopes_from_path(path: &str) -> ResourceScopes {
    ResourceScopes::from([("repository".to_string(), vec![path.to_string()])])
}

fn ensure_same_project(
    expected: &GitlabProject,
    observed: &GitlabProject,
) -> Result<(), ProviderError> {
    if expected.path_with_namespace == observed.path_with_namespace && expected.id == observed.id {
        return Ok(());
    }
    Err(ProviderError::deny(
        ReasonCode::ScopeUnresolved,
        "GitLab project was not found or not permitted",
    ))
}

fn ensure_issue_in_project(
    project: &GitlabProject,
    issue: &GitlabIssue,
) -> Result<(), ProviderError> {
    if issue.project_id == project.id {
        return Ok(());
    }
    Err(ProviderError::deny(
        ReasonCode::ScopeUnresolved,
        "GitLab issue was not found or not permitted",
    ))
}

fn ensure_merge_request_in_project(
    project: &GitlabProject,
    merge_request: &GitlabMergeRequest,
) -> Result<(), ProviderError> {
    if merge_request.project_id == project.id {
        return Ok(());
    }
    Err(ProviderError::deny(
        ReasonCode::ScopeUnresolved,
        "GitLab merge request was not found or not permitted",
    ))
}

fn ensure_merge_request_repository_ids(
    project: &GitlabProject,
    merge_request: &GitlabMergeRequest,
) -> Result<(), ProviderError> {
    if merge_request
        .target_project_id
        .is_some_and(|target_project_id| target_project_id != project.id)
    {
        return Err(ProviderError::deny(
            ReasonCode::ScopeUnresolved,
            "GitLab merge request repository identity was not found or not permitted",
        ));
    }
    Ok(())
}

fn ensure_diff_versions_target_merge_request(
    merge_request: &GitlabMergeRequest,
    versions: &[GitlabDiffVersionSummary],
) -> Result<(), ProviderError> {
    let merge_request_id = merge_request.id.ok_or_else(|| {
        ProviderError::error(
            ReasonCode::UpstreamProtocolFailed,
            "GitLab merge request id was missing",
        )
    })?;
    if versions
        .iter()
        .any(|version| version.merge_request_id != merge_request_id)
    {
        return Err(ProviderError::error(
            ReasonCode::UpstreamProtocolFailed,
            "GitLab diff version did not match the requested merge request",
        ));
    }
    Ok(())
}

fn ensure_pipelines_in_project(
    project: &GitlabProject,
    pipelines: &[GitlabPipeline],
) -> Result<(), ProviderError> {
    for pipeline in pipelines {
        ensure_pipeline_in_project(project, pipeline)?;
    }
    Ok(())
}

fn ensure_pipeline_in_project(
    project: &GitlabProject,
    pipeline: &GitlabPipeline,
) -> Result<(), ProviderError> {
    if pipeline.project_id == project.id {
        return Ok(());
    }
    Err(ProviderError::deny(
        ReasonCode::ScopeUnresolved,
        "GitLab pipeline was not found or not permitted",
    ))
}

fn ensure_jobs_in_project(
    project: &GitlabProject,
    jobs: &[GitlabJob],
) -> Result<(), ProviderError> {
    for job in jobs {
        ensure_job_in_project(project, job)?;
    }
    Ok(())
}

fn ensure_job_in_project(project: &GitlabProject, job: &GitlabJob) -> Result<(), ProviderError> {
    if job.project_id == Some(project.id) {
        return Ok(());
    }
    Err(ProviderError::deny(
        ReasonCode::ScopeUnresolved,
        "GitLab job was not found or not permitted",
    ))
}

fn gitlab_pipeline_object_id(project: &GitlabProject, pipeline_id: u64) -> String {
    format!("{}:pipeline/{}", project.path_with_namespace, pipeline_id)
}

fn gitlab_job_object_id(project: &GitlabProject, job_id: u64) -> String {
    format!("{}:job/{}", project.path_with_namespace, job_id)
}

fn gitlab_protected_branch_object_id(project: &GitlabProject, name: &str) -> String {
    format!("{}:protected_branch/{}", project.path_with_namespace, name)
}

fn ensure_issue_description_within_cap(
    issue: &GitlabIssue,
    max_body_bytes: u64,
) -> Result<(), ProviderError> {
    ensure_gitlab_description_within_cap("issue", issue.description.as_deref(), max_body_bytes)
}

fn ensure_merge_request_description_within_cap(
    merge_request: &GitlabMergeRequest,
    max_body_bytes: u64,
) -> Result<(), ProviderError> {
    ensure_gitlab_description_within_cap(
        "merge request",
        merge_request.description.as_deref(),
        max_body_bytes,
    )
}

fn ensure_note_body_within_cap(
    note: &GitlabNote,
    max_body_bytes: u64,
) -> Result<(), ProviderError> {
    if note
        .body
        .as_ref()
        .is_some_and(|body| body.len() as u64 > max_body_bytes)
    {
        return Err(ProviderError::error(
            ReasonCode::UpstreamProtocolFailed,
            "GitLab note body exceeded providers.gitlab.content.max_body_bytes",
        ));
    }
    Ok(())
}

fn ensure_gitlab_description_within_cap(
    resource: &str,
    description: Option<&str>,
    max_body_bytes: u64,
) -> Result<(), ProviderError> {
    if description.is_some_and(|description| description.len() as u64 > max_body_bytes) {
        return Err(ProviderError::error(
            ReasonCode::UpstreamProtocolFailed,
            format!(
                "GitLab {resource} description exceeded providers.gitlab.content.max_body_bytes"
            ),
        ));
    }
    Ok(())
}

fn protected_branch_verification(
    project: &GitlabProject,
    rules: &[GitlabProtectedBranch],
    required_patterns: Vec<String>,
) -> Value {
    let mut required = vec![];
    if let Some(default_branch) = &project.default_branch {
        required.push(default_branch.clone());
    }
    required.extend(
        GITLAB_DEFAULT_BRANCH_NAMES
            .iter()
            .map(|value| (*value).to_string()),
    );
    required.extend(required_patterns);
    required.sort();
    required.dedup();
    let checks = required
        .into_iter()
        .map(|pattern| {
            let matched = rules
                .iter()
                .find(|rule| protected_branch_matches(&rule.name, &pattern));
            json!({
                "pattern": pattern,
                "covered": matched.is_some(),
                "matchedRule": matched.map(|rule| rule.name.clone()),
                "pushAccessLevels": matched.map(|rule| rule.push_access_levels.clone()).unwrap_or_default(),
                "mergeAccessLevels": matched.map(|rule| rule.merge_access_levels.clone()).unwrap_or_default(),
            })
        })
        .collect::<Vec<_>>();
    json!({
        "project": project.path_with_namespace,
        "projectId": project.id,
        "defaultBranch": project.default_branch.clone(),
        "checks": checks,
    })
}

fn verified_job_play_ref<'a>(
    job: &'a GitlabJob,
    pipeline: &'a GitlabPipeline,
) -> Result<&'a str, ProviderError> {
    match (job.ref_name.as_deref(), pipeline.ref_name.as_deref()) {
        (Some(job_ref), Some(pipeline_ref)) if job_ref == pipeline_ref => Ok(job_ref),
        (Some(_), Some(_)) => Err(ProviderError::error(
            ReasonCode::UpstreamProtocolFailed,
            "GitLab job and pipeline metadata refs did not match",
        )),
        (Some(job_ref), None) => Ok(job_ref),
        (None, Some(pipeline_ref)) => Ok(pipeline_ref),
        (None, None) => Err(ProviderError::error(
            ReasonCode::UpstreamProtocolFailed,
            "GitLab job metadata did not include a ref",
        )),
    }
}

fn ensure_notes_target_issue(notes: &[GitlabNote], iid: u64) -> Result<(), ProviderError> {
    for note in notes {
        ensure_note_target_issue(note, iid)?;
    }
    Ok(())
}

fn ensure_note_target_issue(note: &GitlabNote, iid: u64) -> Result<(), ProviderError> {
    ensure_note_target(note, "Issue", iid)
}

fn ensure_notes_target_merge_request(notes: &[GitlabNote], iid: u64) -> Result<(), ProviderError> {
    for note in notes {
        ensure_note_target_merge_request(note, iid)?;
    }
    Ok(())
}

fn ensure_note_target_merge_request(note: &GitlabNote, iid: u64) -> Result<(), ProviderError> {
    ensure_note_target(note, "MergeRequest", iid)
}

fn ensure_discussions_target_merge_request(
    discussions: &[GitlabDiscussion],
    iid: u64,
) -> Result<(), ProviderError> {
    for discussion in discussions {
        ensure_discussion_target_merge_request(discussion, iid)?;
    }
    Ok(())
}

fn ensure_discussion_target_merge_request(
    discussion: &GitlabDiscussion,
    iid: u64,
) -> Result<(), ProviderError> {
    if discussion.notes.is_empty() {
        return Err(note_scope_mismatch_error());
    }
    ensure_notes_target_merge_request(&discussion.notes, iid)
}

fn ensure_drafts_consistent(
    drafts: &[GitlabDraftNote],
    merge_request: &GitlabMergeRequest,
    actor_id: u64,
) -> Result<(), ProviderError> {
    for draft in drafts {
        ensure_draft_consistent(draft, merge_request, actor_id, draft.id)?;
    }
    Ok(())
}

fn required_gitlab_actor_id(actor: &GitlabUser) -> Result<u64, ProviderError> {
    if actor.id > 0 {
        Ok(actor.id)
    } else {
        Err(ProviderError::error(
            ReasonCode::UpstreamProtocolFailed,
            "GitLab current user identity did not include a valid numeric id",
        ))
    }
}

fn gitlab_review_context(
    request: &ProviderInvocation,
    actor: &GitlabUser,
) -> Result<(u64, Value), ProviderError> {
    let actor_id = required_gitlab_actor_id(actor)?;
    if actor.username.trim().is_empty() {
        return Err(ProviderError::error(
            ReasonCode::UpstreamProtocolFailed,
            "GitLab current user identity did not include a valid username",
        ));
    }
    let credential_binding = match request.credential_mode() {
        CredentialMode::Service => "shared",
        CredentialMode::PerUser => "principal",
    };
    Ok((
        actor_id,
        json!({
            "credentialMode": request.credential_mode(),
            "credentialBinding": credential_binding,
            "upstreamActor": {
                "id": actor_id,
                "username": actor.username,
            }
        }),
    ))
}

fn publication_snapshot_from_discussions(
    project: &GitlabProject,
    merge_request: &GitlabMergeRequest,
    iid: u64,
    discussions: Vec<GitlabDiscussion>,
) -> Result<PublicationDiscussionSnapshot, ProviderError> {
    let mut snapshot = PublicationDiscussionSnapshot {
        notes: BTreeMap::new(),
    };
    let mut note_discussions = BTreeMap::new();
    merge_publication_discussions(
        &mut snapshot,
        &mut note_discussions,
        project,
        merge_request,
        iid,
        discussions,
    )?;
    Ok(snapshot)
}

fn merge_publication_discussions(
    snapshot: &mut PublicationDiscussionSnapshot,
    note_discussions: &mut BTreeMap<u64, String>,
    project: &GitlabProject,
    merge_request: &GitlabMergeRequest,
    iid: u64,
    discussions: Vec<GitlabDiscussion>,
) -> Result<(), ProviderError> {
    let merge_request_id = merge_request.id.ok_or_else(publication_protocol_error)?;
    for discussion in discussions {
        if discussion.id.is_empty() || discussion.notes.is_empty() {
            return Err(publication_protocol_error());
        }
        for note in discussion.notes {
            if note.id == 0
                || note.noteable_type.as_deref() != Some("MergeRequest")
                || note
                    .noteable_iid
                    .is_some_and(|observed_iid| observed_iid != iid)
                || note.noteable_id != Some(merge_request_id)
                || note.project_id != Some(project.id)
            {
                return Err(publication_protocol_error());
            }
            if let Some(previous) = note_discussions.insert(note.id, discussion.id.clone())
                && previous != discussion.id
            {
                return Err(publication_protocol_error());
            }
            snapshot
                .notes
                .entry(PublishedNoteIdentity {
                    discussion_id: discussion.id.clone(),
                    note_id: note.id,
                })
                .or_insert(note);
        }
    }
    Ok(())
}

fn published_note_matches(
    note: &GitlabNote,
    actor_id: u64,
    body: &str,
    expected_position: Option<&GitlabDiffPosition>,
    enforce_position: bool,
) -> bool {
    note.author_user_id == Some(actor_id)
        && note.system == Some(false)
        && gitlab_note_body_matches(note.body.as_deref(), body)
        && (!enforce_position
            || semantic_gitlab_position_matches(note.position.as_ref(), expected_position))
}

fn select_published_note_candidate(
    notes: &BTreeMap<PublishedNoteIdentity, GitlabNote>,
    baseline: &BTreeSet<PublishedNoteIdentity>,
    reply_discussion_id: Option<&str>,
    actor_id: u64,
    body: &str,
    expected_position: Option<&GitlabDiffPosition>,
    enforce_position: bool,
) -> Option<PublishedNoteIdentity> {
    let mut candidates = notes.iter().filter(|(identity, note)| {
        !baseline.contains(*identity)
            && reply_discussion_id
                .is_none_or(|discussion_id| identity.discussion_id == discussion_id)
            && published_note_matches(note, actor_id, body, expected_position, enforce_position)
    });
    let (identity, _) = candidates.next()?;
    if candidates.next().is_some() {
        return None;
    }
    Some(identity.clone())
}

fn semantic_gitlab_position_matches(
    observed: Option<&GitlabDiffPosition>,
    expected: Option<&GitlabDiffPosition>,
) -> bool {
    match (observed, expected) {
        (None, None) => true,
        (Some(observed), Some(expected)) => {
            observed.position_type == expected.position_type
                && observed.base_sha == expected.base_sha
                && observed.start_sha == expected.start_sha
                && observed.head_sha == expected.head_sha
                && observed.old_path == expected.old_path
                && observed.new_path == expected.new_path
                && observed.old_line == expected.old_line
                && observed.new_line == expected.new_line
                && observed.width == expected.width
                && observed.height == expected.height
                && observed.x == expected.x
                && observed.y == expected.y
                && semantic_line_range_matches(
                    observed.line_range.as_ref(),
                    expected.line_range.as_ref(),
                )
        }
        _ => false,
    }
}

fn semantic_line_range_matches(
    observed: Option<&GitlabLineRange>,
    expected: Option<&GitlabLineRange>,
) -> bool {
    match (observed, expected) {
        (None, None) => true,
        (Some(observed), Some(expected)) => {
            observed.start.old_line == expected.start.old_line
                && observed.start.new_line == expected.start.new_line
                && observed.end.old_line == expected.end.old_line
                && observed.end.new_line == expected.end.new_line
        }
        _ => false,
    }
}

fn publication_protocol_error() -> ProviderError {
    ProviderError::error(
        ReasonCode::UpstreamProtocolFailed,
        "GitLab published note readback was malformed",
    )
}

fn publication_snapshot_limit_error() -> ProviderError {
    ProviderError::error(
        ReasonCode::UpstreamProtocolFailed,
        "GitLab discussion snapshot exceeded the 10-page publication verification limit",
    )
}

fn published_note_readback_error(locators: MutationSafeLocators) -> ProviderError {
    mutation_verification_failed(MutationVerificationStage::PublishedNoteReadback, locators)
}

fn ensure_draft_consistent(
    draft: &GitlabDraftNote,
    merge_request: &GitlabMergeRequest,
    actor_id: u64,
    draft_id: u64,
) -> Result<(), ProviderError> {
    if draft.id != draft_id
        || draft
            .merge_request_id
            .zip(merge_request.id)
            .is_some_and(|(observed, expected)| observed != expected)
        || draft
            .author_user_id
            .is_some_and(|observed| observed != actor_id)
    {
        return Err(ProviderError::deny(
            ReasonCode::ScopeUnresolved,
            "GitLab draft note was not found or not permitted",
        ));
    }
    Ok(())
}

fn position_matches_input(
    observed: Option<&GitlabDiffPosition>,
    expected: &GitlabDiffPosition,
    input: &GitlabPositionInput,
) -> bool {
    let Some(observed) = observed else {
        return false;
    };
    if observed.position_type != expected.position_type
        || observed.base_sha != expected.base_sha
        || observed.start_sha != expected.start_sha
        || observed.head_sha != expected.head_sha
        || observed.old_path != expected.old_path
        || observed.new_path != expected.new_path
        || observed.width != input.width
        || observed.height != input.height
        || observed.x != input.x
        || observed.y != input.y
    {
        return false;
    }
    if let Some(range) = &input.line_range {
        let Some(observed_range) = &observed.line_range else {
            return false;
        };
        observed.old_line == range.end.old_line
            && observed.new_line == range.end.new_line
            && observed_range.start.old_line == range.start.old_line
            && observed_range.start.new_line == range.start.new_line
            && observed_range.end.old_line == range.end.old_line
            && observed_range.end.new_line == range.end.new_line
    } else {
        observed.old_line == input.old_line
            && observed.new_line == input.new_line
            && observed.line_range.is_none()
    }
}

fn optional_position_matches_input(
    observed: Option<&GitlabDiffPosition>,
    expected: Option<&GitlabDiffPosition>,
    input: Option<&GitlabPositionInput>,
) -> bool {
    match (expected, input) {
        (Some(expected), Some(input)) => position_matches_input(observed, expected, input),
        (None, None) => true,
        _ => false,
    }
}

fn gitlab_note_body_matches(observed: Option<&str>, expected: &str) -> bool {
    observed.is_some_and(|observed| {
        normalize_gitlab_note_body(observed) == normalize_gitlab_note_body(expected)
    })
}

fn normalize_gitlab_note_body(body: &str) -> String {
    body.chars()
        .filter(|character| *character != '\r')
        .collect::<String>()
        .trim_end()
        .to_string()
}

fn draft_mutation_readback_error(draft_id: u64) -> ProviderError {
    mutation_verification_failed(
        MutationVerificationStage::MutationReadback,
        MutationSafeLocators::new().with_draft_note_ids(vec![draft_id]),
    )
}

fn draft_backend_mutation_readback_error(
    error: GitlabBackendError,
    draft_id: u64,
) -> ProviderError {
    mutation_readback_error(
        gitlab_backend_error(error),
        MutationVerificationStage::MutationReadback,
        MutationSafeLocators::new().with_draft_note_ids(vec![draft_id]),
    )
}

fn mutation_readback_error(
    error: ProviderError,
    stage: MutationVerificationStage,
    locators: MutationSafeLocators,
) -> ProviderError {
    let diagnostic_code = error.internal_diagnostic_code;
    let mut mapped = mutation_verification_failed(stage, locators);
    mapped.internal_diagnostic_code = diagnostic_code;
    mapped
}

fn mutation_backend_error(
    error: GitlabBackendError,
    stage: MutationVerificationStage,
    locators: MutationSafeLocators,
) -> ProviderError {
    match error {
        GitlabBackendError::DraftPositionShapeInvalid => mutation_verification_failed(
            stage, locators,
        )
        .with_internal_diagnostic_code(InternalDiagnosticCode::DraftPositionShapeInvalid.as_str()),
        // Every later request, such as the readback, follows a write GitLab
        // accepted. Whatever stops it leaves that write unverified: a 401,
        // 403 or 404 rejects only the readback, an unsent or unprepared
        // readback proves nothing about the write, and neither throttling
        // nor delegated access that cannot be presented (an OAuth refresh
        // throttled, busy or uncertain, or a reconnect required) may invite a
        // retry that would repeat the write.
        _ if stage != MutationVerificationStage::MutationResponse => {
            mutation_verification_failed(stage, locators)
        }
        // A write the Broker could not prepare, such as one the upstream
        // allowlist refuses, was never sent: it keeps the reason of its cause
        // without a receipt, never the receipt that cause would earn after
        // sending.
        GitlabBackendError::RequestUnbuilt(_) => gitlab_backend_error(error),
        // Only the write itself can be proven unsent.
        GitlabBackendError::NotSent { timed_out } => mutation_not_sent(timed_out),
        GitlabBackendError::NoResponse { .. }
        | GitlabBackendError::Transport(_)
        | GitlabBackendError::Timeout
        | GitlabBackendError::Protocol(_)
        | GitlabBackendError::ResponseTooLarge
        | GitlabBackendError::HttpStatus(500..=599) => {
            mutation_verification_failed(stage, locators)
        }
        // A rejection of the write itself, throttling, and delegated access
        // that could not be presented applied nothing: each keeps its own
        // reason, without a receipt.
        error => gitlab_backend_error(error),
    }
}

fn ensure_actor_not_formally_approved(
    approvals: &GitlabApprovalSummary,
    actor_id: u64,
) -> Result<(), ProviderError> {
    for approval in &approvals.approved_by {
        let approved_user_id = approval.user.id.ok_or_else(|| {
            ProviderError::error(
                ReasonCode::UpstreamProtocolFailed,
                "GitLab approval identity did not include a numeric id",
            )
        })?;
        if approved_user_id == actor_id {
            return Err(ProviderError::deny(
                ReasonCode::VersionConflict,
                "GitLab reviewer has a formal approval; unapprove before submitting a review",
            ));
        }
    }
    Ok(())
}

fn actor_has_approved(
    approvals: &GitlabApprovalSummary,
    actor_id: u64,
) -> Result<bool, ProviderError> {
    let mut found = false;
    for approval in &approvals.approved_by {
        let approved_user_id = approval.user.id.ok_or_else(|| {
            ProviderError::error(
                ReasonCode::UpstreamProtocolFailed,
                "GitLab approval identity did not include a numeric id",
            )
        })?;
        if approved_user_id == actor_id {
            if found {
                return Err(ProviderError::error(
                    ReasonCode::UpstreamProtocolFailed,
                    "GitLab returned duplicate acting-user approvals",
                ));
            }
            found = true;
        }
    }
    if approvals
        .user_has_approved
        .is_some_and(|value| value != found)
    {
        return Err(ProviderError::error(
            ReasonCode::UpstreamProtocolFailed,
            "GitLab returned contradictory acting-user approval state",
        ));
    }
    Ok(found)
}

fn require_approval_readiness(merge_request: &GitlabMergeRequest) -> Result<(), ProviderError> {
    if merge_request.prepared_at.is_none()
        || matches!(
            merge_request.detailed_merge_status.as_deref(),
            Some("preparing" | "checking" | "approvals_syncing") | None
        )
    {
        return Err(position_version_conflict());
    }
    Ok(())
}

fn acting_reviewer_not_assigned_error() -> ProviderError {
    ProviderError::deny(
        ReasonCode::VersionConflict,
        "GitLab acting user is not an assigned merge request reviewer",
    )
}

fn require_gitlab_review_submit_version(version: &str) -> Result<(), ProviderError> {
    let parsed = parse_gitlab_release_version(version).ok_or_else(|| {
        ProviderError::error(
            ReasonCode::UpstreamProtocolFailed,
            "GitLab server version metadata was malformed",
        )
    })?;
    if parsed < (19, 2, 0, true) {
        return Err(ProviderError::error(
            ReasonCode::UpstreamFailed,
            "GitLab review submission requires GitLab 19.2 or newer",
        ));
    }
    Ok(())
}

fn parse_gitlab_release_version(value: &str) -> Option<(u64, u64, u64, bool)> {
    let value = value.strip_prefix('v').unwrap_or(value);
    let (core, suffix) = value
        .split_once('-')
        .map_or((value, None), |(core, suffix)| (core, Some(suffix)));
    let mut parts = core.split('.');
    let version = (
        parts.next()?.parse().ok()?,
        parts.next()?.parse().ok()?,
        parts.next()?.parse().ok()?,
    );
    if parts.next().is_some() {
        return None;
    }
    let release = match suffix {
        None => true,
        Some("ee" | "ce") => true,
        Some(suffix) if suffix.starts_with("ee.") || suffix.starts_with("ce.") => true,
        Some(suffix) if !suffix.is_empty() => false,
        _ => return None,
    };
    Some((version.0, version.1, version.2, release))
}

fn ensure_note_target(
    note: &GitlabNote,
    expected_type: &str,
    iid: u64,
) -> Result<(), ProviderError> {
    if note.noteable_type.as_deref() == Some(expected_type) && note.noteable_iid == Some(iid) {
        return Ok(());
    }
    Err(note_scope_mismatch_error())
}

fn ensure_issue_note_consistent(
    project: &GitlabProject,
    issue: &GitlabIssue,
    note: &GitlabNote,
    iid: u64,
    note_id: u64,
) -> Result<(), ProviderError> {
    ensure_note_id(note, note_id)?;
    ensure_note_metadata_not_contradicting(note, project, "Issue", iid, issue.id)
}

fn ensure_merge_request_note_consistent(
    project: &GitlabProject,
    merge_request: &GitlabMergeRequest,
    note: &GitlabNote,
    iid: u64,
    note_id: u64,
) -> Result<(), ProviderError> {
    ensure_note_id(note, note_id)?;
    ensure_note_metadata_not_contradicting(note, project, "MergeRequest", iid, merge_request.id)
}

fn ensure_merge_request_discussion_consistent(
    project: &GitlabProject,
    merge_request: &GitlabMergeRequest,
    discussion: &GitlabDiscussion,
    iid: u64,
    discussion_id: &str,
    required_note_id: Option<u64>,
    expected_resolved: Option<bool>,
) -> Result<(), ProviderError> {
    if discussion.id != discussion_id {
        return Err(note_scope_mismatch_error());
    }
    let mut found_required_note = required_note_id.is_none();
    for note in &discussion.notes {
        ensure_note_metadata_not_contradicting(
            note,
            project,
            "MergeRequest",
            iid,
            merge_request.id,
        )?;
        if Some(note.id) == required_note_id {
            found_required_note = true;
        }
        if let Some(expected_resolved) = expected_resolved
            && note.resolvable == Some(true)
            && let Some(observed_resolved) = note.resolved
            && observed_resolved != expected_resolved
        {
            return Err(note_scope_mismatch_error());
        }
    }
    if !found_required_note {
        return Err(note_scope_mismatch_error());
    }
    Ok(())
}

fn ensure_note_id(note: &GitlabNote, note_id: u64) -> Result<(), ProviderError> {
    if note.id == note_id {
        Ok(())
    } else {
        Err(note_scope_mismatch_error())
    }
}

fn ensure_note_metadata_not_contradicting(
    note: &GitlabNote,
    project: &GitlabProject,
    expected_type: &str,
    iid: u64,
    expected_noteable_id: Option<u64>,
) -> Result<(), ProviderError> {
    if let Some(noteable_type) = note.noteable_type.as_deref()
        && noteable_type != expected_type
    {
        return Err(note_scope_mismatch_error());
    }
    if let Some(noteable_iid) = note.noteable_iid
        && noteable_iid != iid
    {
        return Err(note_scope_mismatch_error());
    }
    if let Some(project_id) = note.project_id
        && project_id != project.id
    {
        return Err(note_scope_mismatch_error());
    }
    if let (Some(expected), Some(observed)) = (expected_noteable_id, note.noteable_id)
        && observed != expected
    {
        return Err(note_scope_mismatch_error());
    }
    Ok(())
}

fn note_scope_mismatch_error() -> ProviderError {
    ProviderError::deny(
        ReasonCode::ScopeUnresolved,
        "GitLab note was not found or not permitted",
    )
}

async fn ensure_branch_absent(
    backend: &dyn GitlabBackend,
    project_id: u64,
    branch: &str,
    credential: &GitlabCredential,
) -> Result<(), ProviderError> {
    match backend.branch(project_id, branch, credential).await {
        Ok(_) => Err(ProviderError::deny(
            ReasonCode::VersionConflict,
            "GitLab branch already exists",
        )),
        Err(GitlabBackendError::NotFound) => Ok(()),
        Err(error) => Err(gitlab_lookup_backend_error(error)),
    }
}

async fn ensure_optional_start_branch(
    backend: &dyn GitlabBackend,
    project_id: u64,
    start_branch: Option<&str>,
    credential: &GitlabCredential,
) -> Result<(), ProviderError> {
    if let Some(start_branch) = start_branch {
        backend
            .branch(project_id, start_branch, credential)
            .await
            .map_err(gitlab_lookup_backend_error)?;
    }
    Ok(())
}

async fn ensure_file_absent(
    backend: &dyn GitlabBackend,
    project_id: u64,
    path: &str,
    ref_name: &str,
    credential: &GitlabCredential,
) -> Result<(), ProviderError> {
    match backend
        .file(
            project_id,
            GitlabFileRequest {
                path: path.to_string(),
                ref_name: ref_name.to_string(),
            },
            credential,
        )
        .await
    {
        Ok(_) => Err(ProviderError::deny(
            ReasonCode::VersionConflict,
            "GitLab file already exists",
        )),
        Err(GitlabBackendError::NotFound) => Ok(()),
        Err(error) => Err(gitlab_lookup_backend_error(error)),
    }
}

async fn ensure_commit_start_ref(
    backend: &dyn GitlabBackend,
    project_id: u64,
    branch: &str,
    start_branch: Option<&str>,
    start_sha: Option<&str>,
    credential: &GitlabCredential,
) -> Result<(), ProviderError> {
    match backend.branch(project_id, branch, credential).await {
        Ok(_) => {}
        Err(GitlabBackendError::NotFound) if start_branch.is_none() && start_sha.is_none() => {
            return Err(ProviderError::deny(
                ReasonCode::InputInvalid,
                "gitlab commit.create requires startBranch or startSha when creating a new branch",
            ));
        }
        Err(GitlabBackendError::NotFound) => {}
        Err(error) => return Err(gitlab_lookup_backend_error(error)),
    }
    if let Some(start_branch) = start_branch {
        backend
            .branch(project_id, start_branch, credential)
            .await
            .map_err(gitlab_lookup_backend_error)?;
    }
    if let Some(start_sha) = start_sha {
        backend
            .commit(project_id, start_sha, credential)
            .await
            .map_err(gitlab_lookup_backend_error)?;
    }
    Ok(())
}

async fn validate_commit_action_preconditions(
    backend: &dyn GitlabBackend,
    project_id: u64,
    branch: &str,
    actions: &[GitlabCommitActionRequest],
    credential: &GitlabCredential,
) -> Result<(), ProviderError> {
    for action in actions {
        match action.action.as_str() {
            "create" => {
                ensure_file_absent(backend, project_id, &action.file_path, branch, credential)
                    .await?;
            }
            "update" | "delete" | "chmod" => {
                let existing = existing_file_for_action(
                    backend,
                    project_id,
                    &action.file_path,
                    branch,
                    credential,
                )
                .await?;
                if action.action != "chmod" {
                    require_matching_last_commit_id(action.last_commit_id.as_deref(), &existing)?;
                }
            }
            "move" => {
                let previous_path = action.previous_path.as_deref().ok_or_else(|| {
                    ProviderError::deny(
                        ReasonCode::InputInvalid,
                        "gitlab commit.create move actions require previousPath",
                    )
                })?;
                let existing = existing_file_for_action(
                    backend,
                    project_id,
                    previous_path,
                    branch,
                    credential,
                )
                .await?;
                require_matching_last_commit_id(action.last_commit_id.as_deref(), &existing)?;
                if action.file_path != previous_path {
                    ensure_file_absent(backend, project_id, &action.file_path, branch, credential)
                        .await?;
                }
            }
            _ => unreachable!("validated action"),
        }
    }
    Ok(())
}

async fn existing_file_for_action(
    backend: &dyn GitlabBackend,
    project_id: u64,
    path: &str,
    ref_name: &str,
    credential: &GitlabCredential,
) -> Result<GitlabFile, ProviderError> {
    let file = backend
        .file(
            project_id,
            GitlabFileRequest {
                path: path.to_string(),
                ref_name: ref_name.to_string(),
            },
            credential,
        )
        .await
        .map_err(gitlab_lookup_backend_error)?
        .value;
    ensure_file_path_matches(path, &file)?;
    Ok(file)
}

fn require_matching_last_commit_id(
    supplied: Option<&str>,
    existing: &GitlabFile,
) -> Result<(), ProviderError> {
    let Some(expected) = existing.last_commit_id.as_deref() else {
        return Ok(());
    };
    let Some(supplied) = supplied else {
        return Err(ProviderError::deny(
            ReasonCode::VersionConflict,
            "GitLab file mutation requires lastCommitId",
        ));
    };
    if supplied != expected {
        return Err(ProviderError::deny(
            ReasonCode::VersionConflict,
            "GitLab file lastCommitId does not match current file metadata",
        ));
    }
    Ok(())
}

fn require_matching_merge_request_sha(
    supplied: &str,
    existing: &GitlabMergeRequest,
) -> Result<(), ProviderError> {
    let Some(expected) = existing.sha.as_deref() else {
        return Err(ProviderError::error(
            ReasonCode::UpstreamProtocolFailed,
            "GitLab merge request metadata did not include sha",
        ));
    };
    if supplied != expected {
        return Err(ProviderError::deny(
            ReasonCode::VersionConflict,
            "GitLab merge request sha does not match current metadata",
        ));
    }
    Ok(())
}

fn position_version_conflict() -> ProviderError {
    ProviderError::deny(
        ReasonCode::VersionConflict,
        "GitLab merge request diff position is not ready for the requested head",
    )
}

fn require_replayable_draft_position(position: &GitlabDiffPosition) -> Result<(), ProviderError> {
    if !position.base_sha.as_deref().is_some_and(is_full_commit_sha)
        || !is_full_commit_sha(&position.start_sha)
        || !is_full_commit_sha(&position.head_sha)
    {
        return Err(ProviderError::deny(
            ReasonCode::VersionConflict,
            "GitLab draft position cannot be preserved safely; retry with expectedHeadSha and a replacement position from the current diff",
        ));
    }
    Ok(())
}

fn require_current_position_triplet(
    merge_request: &GitlabMergeRequest,
    expected_head_sha: &str,
) -> Result<(), ProviderError> {
    let sha = merge_request.sha.as_deref().ok_or_else(|| {
        ProviderError::error(
            ReasonCode::UpstreamProtocolFailed,
            "GitLab merge request metadata did not include sha",
        )
    })?;
    if sha != expected_head_sha
        || merge_request.prepared_at.is_none()
        || merge_request.detailed_merge_status.as_deref() == Some("preparing")
    {
        return Err(position_version_conflict());
    }
    let refs = merge_request
        .diff_refs
        .as_ref()
        .ok_or_else(position_version_conflict)?;
    let base = refs
        .base_sha
        .as_deref()
        .ok_or_else(position_version_conflict)?;
    if !is_full_commit_sha(base)
        || !is_full_commit_sha(&refs.start_sha)
        || !is_full_commit_sha(&refs.head_sha)
        || refs.head_sha != expected_head_sha
    {
        return Err(position_version_conflict());
    }
    Ok(())
}

fn ensure_current_diff_version(
    version: &GitlabDiffVersionSummary,
    merge_request: &GitlabMergeRequest,
) -> Result<(), ProviderError> {
    let refs = merge_request
        .diff_refs
        .as_ref()
        .ok_or_else(position_version_conflict)?;
    let merge_request_id = merge_request.id.ok_or_else(position_version_conflict)?;
    match version.state.as_deref() {
        Some("collected") => {}
        Some("overflow" | "without_files") => {
            return Err(position_input_invalid(
                PositionInputCategory::PatchUnavailable,
            ));
        }
        _ => return Err(position_version_conflict()),
    }
    if version.merge_request_id != merge_request_id
        || Some(version.base_commit_sha.as_str()) != refs.base_sha.as_deref()
        || version.start_commit_sha != refs.start_sha
        || version.head_commit_sha != refs.head_sha
        || !is_full_commit_sha(&version.base_commit_sha)
        || !is_full_commit_sha(&version.start_commit_sha)
        || !is_full_commit_sha(&version.head_commit_sha)
    {
        return Err(position_version_conflict());
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ParsedPatchLineKind {
    Added,
    Removed,
    Context,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ParsedPatchLine {
    order: usize,
    old_counter: u64,
    new_counter: u64,
    old_line: Option<u64>,
    new_line: Option<u64>,
    kind: ParsedPatchLineKind,
}

fn resolve_multiline_position(
    patch: &str,
    range: &GitlabLineRangeInput,
    canonical_path: &str,
) -> Result<GitlabLineRange, ProviderError> {
    let lines = parse_unified_patch_lines(patch)?;
    let start = resolve_patch_coordinate(&lines, &range.start)?;
    let end = resolve_patch_coordinate(&lines, &range.end)?;
    if start.order > end.order {
        return Err(position_input_invalid(
            PositionInputCategory::CoordinatesUnresolved,
        ));
    }
    let path_hash = sha1_hex(canonical_path.as_bytes());
    Ok(GitlabLineRange {
        start: patch_line_range_point(start, &path_hash),
        end: patch_line_range_point(end, &path_hash),
    })
}

fn resolve_patch_coordinate<'a>(
    lines: &'a [ParsedPatchLine],
    coordinate: &GitlabLineCoordinateInput,
) -> Result<&'a ParsedPatchLine, ProviderError> {
    let matches = lines
        .iter()
        .filter(|line| line.old_line == coordinate.old_line && line.new_line == coordinate.new_line)
        .collect::<Vec<_>>();
    match matches.as_slice() {
        [line] => Ok(*line),
        _ => Err(position_input_invalid(
            PositionInputCategory::CoordinatesUnresolved,
        )),
    }
}

fn patch_line_range_point(line: &ParsedPatchLine, path_hash: &str) -> GitlabLineRangePoint {
    GitlabLineRangePoint {
        line_code: format!("{path_hash}_{}_{}", line.old_counter, line.new_counter),
        line_type: Some(
            if line.kind == ParsedPatchLineKind::Added {
                "new"
            } else {
                "old"
            }
            .to_string(),
        ),
        old_line: line.old_line,
        new_line: line.new_line,
    }
}

fn parse_unified_patch_lines(patch: &str) -> Result<Vec<ParsedPatchLine>, ProviderError> {
    let unavailable = || position_input_invalid(PositionInputCategory::PatchUnavailable);
    let mut result = Vec::new();
    let mut old_line = 0_u64;
    let mut new_line = 0_u64;
    let mut in_hunk = false;
    for raw in patch.lines() {
        if raw.starts_with("@@") {
            let rest = raw.strip_prefix("@@ -").ok_or_else(unavailable)?;
            let (ranges, _) = rest.split_once(" @@").ok_or_else(unavailable)?;
            let (old_range, new_range) = ranges.split_once(" +").ok_or_else(unavailable)?;
            old_line = parse_patch_range_start(old_range).ok_or_else(unavailable)?;
            new_line = parse_patch_range_start(new_range).ok_or_else(unavailable)?;
            in_hunk = true;
            continue;
        }
        if !in_hunk || raw.starts_with("\\ No newline at end of file") {
            continue;
        }
        let marker = raw.as_bytes().first().copied().ok_or_else(unavailable)?;
        let order = result.len();
        match marker {
            b' ' => {
                result.push(ParsedPatchLine {
                    order,
                    old_counter: old_line,
                    new_counter: new_line,
                    old_line: Some(old_line),
                    new_line: Some(new_line),
                    kind: ParsedPatchLineKind::Context,
                });
                old_line = old_line.checked_add(1).ok_or_else(unavailable)?;
                new_line = new_line.checked_add(1).ok_or_else(unavailable)?;
            }
            b'-' => {
                result.push(ParsedPatchLine {
                    order,
                    old_counter: old_line,
                    new_counter: new_line,
                    old_line: Some(old_line),
                    new_line: None,
                    kind: ParsedPatchLineKind::Removed,
                });
                old_line = old_line.checked_add(1).ok_or_else(unavailable)?;
            }
            b'+' => {
                result.push(ParsedPatchLine {
                    order,
                    old_counter: old_line,
                    new_counter: new_line,
                    old_line: None,
                    new_line: Some(new_line),
                    kind: ParsedPatchLineKind::Added,
                });
                new_line = new_line.checked_add(1).ok_or_else(unavailable)?;
            }
            _ => return Err(unavailable()),
        }
    }
    if !in_hunk || result.is_empty() {
        return Err(unavailable());
    }
    Ok(result)
}

fn parse_patch_range_start(range: &str) -> Option<u64> {
    range.split(',').next()?.parse::<u64>().ok()
}

fn sha1_hex(bytes: &[u8]) -> String {
    let bit_len = (bytes.len() as u64).wrapping_mul(8);
    let mut message = bytes.to_vec();
    message.push(0x80);
    while message.len() % 64 != 56 {
        message.push(0);
    }
    message.extend_from_slice(&bit_len.to_be_bytes());
    let mut h = [
        0x6745_2301_u32,
        0xefcd_ab89,
        0x98ba_dcfe,
        0x1032_5476,
        0xc3d2_e1f0,
    ];
    for chunk in message.as_chunks::<64>().0 {
        let mut words = [0_u32; 80];
        for (index, word) in words.iter_mut().take(16).enumerate() {
            *word = u32::from_be_bytes(chunk[index * 4..index * 4 + 4].try_into().unwrap());
        }
        for index in 16..80 {
            words[index] =
                (words[index - 3] ^ words[index - 8] ^ words[index - 14] ^ words[index - 16])
                    .rotate_left(1);
        }
        let (mut a, mut b, mut c, mut d, mut e) = (h[0], h[1], h[2], h[3], h[4]);
        for (index, word) in words.iter().enumerate() {
            let (f, k) = match index {
                0..=19 => ((b & c) | ((!b) & d), 0x5a82_7999),
                20..=39 => (b ^ c ^ d, 0x6ed9_eba1),
                40..=59 => ((b & c) | (b & d) | (c & d), 0x8f1b_bcdc),
                _ => (b ^ c ^ d, 0xca62_c1d6),
            };
            let next = a
                .rotate_left(5)
                .wrapping_add(f)
                .wrapping_add(e)
                .wrapping_add(k)
                .wrapping_add(*word);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = next;
        }
        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e);
    }
    h.iter().map(|word| format!("{word:08x}")).collect()
}

fn ensure_file_path_matches(expected: &str, observed: &GitlabFile) -> Result<(), ProviderError> {
    if observed.file_path == expected {
        return Ok(());
    }
    Err(ProviderError::deny(
        ReasonCode::ScopeUnresolved,
        "GitLab file was not found or not permitted",
    ))
}

fn required_file_commit_id(file: &GitlabFile) -> Result<String, ProviderError> {
    let commit_id = file.commit_id.as_deref().ok_or_else(|| {
        ProviderError::error(
            ReasonCode::UpstreamProtocolFailed,
            "GitLab file metadata did not include commit_id",
        )
    })?;
    if !(7..=64).contains(&commit_id.len())
        || !commit_id.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        return Err(ProviderError::error(
            ReasonCode::UpstreamProtocolFailed,
            "GitLab file metadata commit_id was invalid",
        ));
    }
    Ok(commit_id.to_string())
}

fn file_mutation_preflight_ref<'a>(
    branch: &'a str,
    start_branch: Option<&'a str>,
    safety: &GitlabBranchSafety,
) -> &'a str {
    if safety.target_branch_exists {
        branch
    } else {
        start_branch.unwrap_or(branch)
    }
}

fn commit_action_preflight_ref<'a>(
    branch: &'a str,
    start_branch: Option<&'a str>,
    start_sha: Option<&'a str>,
    safety: &GitlabBranchSafety,
) -> &'a str {
    if safety.target_branch_exists {
        branch
    } else {
        start_branch.or(start_sha).unwrap_or(branch)
    }
}

fn branch_write_denied() -> ProviderError {
    ProviderError::deny(
        ReasonCode::GitRefDenied,
        "GitLab writes to default or protected branches are denied",
    )
}

fn ci_ref_execution_denied(safety: &GitlabCiRefSafety) -> ProviderError {
    ProviderError::deny(
        ReasonCode::GitRefDenied,
        "GitLab CI execution on default or protected refs is denied",
    )
    .with_audit(json!({
        "gitlab": {
            "refSafety": ci_ref_safety_audit(safety),
            "requestBody": ci_ref_audit(&safety.ref_name, safety),
        }
    }))
}

fn protected_branch_matches(pattern: &str, branch: &str) -> bool {
    pattern == branch || glob_match(pattern, branch)
}

fn glob_match(pattern: &str, value: &str) -> bool {
    let pattern = pattern.as_bytes();
    let value = value.as_bytes();
    let (mut p, mut v) = (0, 0);
    let (mut star, mut match_after_star) = (None, 0);
    while v < value.len() {
        if p < pattern.len() && (pattern[p] == value[v]) {
            p += 1;
            v += 1;
        } else if p < pattern.len() && pattern[p] == b'*' {
            star = Some(p);
            match_after_star = v;
            p += 1;
        } else if let Some(star_index) = star {
            p = star_index + 1;
            match_after_star += 1;
            v = match_after_star;
        } else {
            return false;
        }
    }
    while p < pattern.len() && pattern[p] == b'*' {
        p += 1;
    }
    p == pattern.len()
}

fn gitlab_result(
    operation: &str,
    project: &GitlabProject,
    object_ids: Option<Value>,
    upstream_status: u16,
    upstream_duration_ms: u64,
    result: Value,
    egress_proxy: Value,
) -> ProviderResult {
    let mut provider_result = ProviderResult::new(result)
        .with_audit(json!({
            "gitlab": {
                "operation": operation,
                "project": project.path_with_namespace,
                "namespace": project.path_with_namespace.split('/').next().unwrap_or(""),
                "projectId": project.id,
                "egressProxy": egress_proxy,
            }
        }))
        .with_upstream(Some(upstream_status), Some(upstream_duration_ms));
    provider_result.object_ids = object_ids;
    provider_result
}

fn gitlab_result_with_request_body_audit(
    operation: &str,
    project: &GitlabProject,
    object_ids: Option<Value>,
    upstream: (u16, u64),
    result: Value,
    egress_proxy: Value,
    request_body: Value,
) -> ProviderResult {
    let mut result = gitlab_result(
        operation,
        project,
        object_ids,
        upstream.0,
        upstream.1,
        result,
        egress_proxy,
    );
    if let Some(Value::Object(audit)) = result.audit.as_mut()
        && let Some(Value::Object(gitlab_audit)) = audit.get_mut("gitlab")
    {
        gitlab_audit.insert("requestBody".to_string(), request_body);
    }
    result
}

fn add_gitlab_audit_fields(result: &mut ProviderResult, fields: Vec<(&'static str, Value)>) {
    if let Some(Value::Object(audit)) = result.audit.as_mut()
        && let Some(Value::Object(gitlab_audit)) = audit.get_mut("gitlab")
    {
        for (key, value) in fields {
            gitlab_audit.insert(key.to_string(), value);
        }
    }
}

fn add_gitlab_review_context(
    result: &mut ProviderResult,
    review_context: Value,
) -> Result<(), ProviderError> {
    let Value::Object(payload) = &mut result.result else {
        return Err(ProviderError::error(
            ReasonCode::UpstreamProtocolFailed,
            "GitLab provider result was malformed",
        ));
    };
    payload.insert("reviewContext".to_string(), review_context);
    Ok(())
}

fn add_gitlab_review_mutation_audit(
    result: &mut ProviderResult,
    merge_request_iid: u64,
    user_id: u64,
    mut fields: Vec<(&'static str, Value)>,
) {
    fields.insert(0, ("userId", json!(user_id)));
    fields.insert(0, ("mergeRequestIid", json!(merge_request_iid)));
    add_gitlab_audit_fields(result, fields);
}

fn review_position_audit_fields(
    expected_head_sha: Option<&str>,
    position: Option<&GitlabDiffPosition>,
) -> Vec<(&'static str, Value)> {
    let mut fields = Vec::new();
    if let Some(expected_head_sha) = expected_head_sha {
        fields.push(("expectedHeadSha", json!(expected_head_sha)));
    }
    let Some(position) = position else {
        return fields;
    };
    fields.push(("provenHeadSha", json!(position.head_sha)));
    fields.push(("positionType", json!(position.position_type)));
    if let Some(old_line) = position.old_line {
        fields.push(("oldLine", json!(old_line)));
    }
    if let Some(new_line) = position.new_line {
        fields.push(("newLine", json!(new_line)));
    }
    if let Some(range) = &position.line_range {
        if let Some(old_line) = range.start.old_line {
            fields.push(("lineRangeStartOldLine", json!(old_line)));
        }
        if let Some(new_line) = range.start.new_line {
            fields.push(("lineRangeStartNewLine", json!(new_line)));
        }
        if let Some(old_line) = range.end.old_line {
            fields.push(("lineRangeEndOldLine", json!(old_line)));
        }
        if let Some(new_line) = range.end.new_line {
            fields.push(("lineRangeEndNewLine", json!(new_line)));
        }
    }
    fields
}

fn add_gitlab_attribution_audit(result: &mut ProviderResult, attribution: Option<Value>) {
    if let Some(audit) = result.audit.as_mut() {
        merge_attribution_audit(audit, attribution);
    }
}

fn add_gitlab_content_write_audit(
    result: &mut ProviderResult,
    inputs: &Value,
    native_content: Option<&str>,
) {
    let (Some(content_format), Some(source), Some(native_content)) = (
        inputs.get("contentFormat").and_then(Value::as_str),
        inputs.get("content").and_then(Value::as_str),
        native_content,
    ) else {
        return;
    };
    add_gitlab_audit_fields(
        result,
        vec![
            ("contentFormat", json!(content_format)),
            ("nativeContentFormat", json!("markdown")),
            ("sourceContentBytes", json!(source.len() as u64)),
            (
                "finalNativeContentBytes",
                json!(native_content.len() as u64),
            ),
        ],
    );
}

fn gitlab_file_inline_result(
    file: GitlabFile,
    max_file_bytes: u64,
    max_upstream_response_bytes: u64,
) -> Result<Value, ProviderError> {
    if file.size > max_file_bytes {
        return Err(ProviderError::deny(
            ReasonCode::InputInvalid,
            "GitLab file exceeds inline content cap; use file.raw.download",
        ));
    }
    if let Some(content) = file.content.as_deref() {
        let estimated_json_bytes = (content.len() as u64)
            .saturating_add(file.file_path.len() as u64)
            .saturating_add(GITLAB_INLINE_FILE_JSON_OVERHEAD);
        if estimated_json_bytes > max_upstream_response_bytes {
            return Err(ProviderError::deny(
                ReasonCode::InputInvalid,
                "GitLab file is too large for inline JSON; use file.raw.download",
            ));
        }
        if file.encoding.as_deref() == Some("base64") {
            let decoded = BASE64.decode(content).map_err(|_| {
                ProviderError::error(
                    ReasonCode::UpstreamProtocolFailed,
                    "GitLab file content was not valid base64",
                )
            })?;
            if decoded.len() as u64 != file.size {
                return Err(ProviderError::error(
                    ReasonCode::UpstreamProtocolFailed,
                    "GitLab file content size did not match metadata",
                ));
            }
        }
    }
    Ok(json!({
        "fileName": file.file_name,
        "filePath": file.file_path,
        "size": file.size,
        "encoding": file.encoding,
        "contentBase64": file.content,
        "contentSha256": file.content_sha256,
        "ref": file.ref_name,
        "blobId": file.blob_id,
        "commitId": file.commit_id,
        "lastCommitId": file.last_commit_id,
        "executeFilemode": file.execute_filemode,
    }))
}

fn branch_write_audit(branch: &str, ref_name: Option<&str>, safety: &GitlabBranchSafety) -> Value {
    let mut audit = GitlabRequestBodyAudit::default();
    audit.add_scalar_field("branch");
    audit.add_optional_scalar_field("ref", ref_name.is_some());
    let mut value = audit.into_value();
    add_branch_safety_audit(&mut value, branch, safety);
    value
}

fn file_mutation_audit(request: &GitlabFileWriteRequest, safety: &GitlabBranchSafety) -> Value {
    let mut audit = GitlabRequestBodyAudit::default();
    audit.add_scalar_field("path");
    audit.add_scalar_field("branch");
    audit.add_text_field("commit_message", &request.commit_message);
    audit.add_optional_scalar_field("start_branch", request.start_branch.is_some());
    audit.add_optional_scalar_field("author_name", request.author_name.is_some());
    audit.add_optional_scalar_field("author_email", request.author_email.is_some());
    audit.add_optional_scalar_field("encoding", request.encoding.is_some());
    audit.add_optional_scalar_field("execute_filemode", request.execute_filemode.is_some());
    audit.add_optional_scalar_field("last_commit_id", request.last_commit_id.is_some());
    audit
        .text_byte_counts
        .insert("decoded_content", request.decoded_content_bytes);
    let mut value = audit.into_value();
    add_path_branch_audit(&mut value, &request.path, &request.branch);
    add_branch_safety_audit(&mut value, &request.branch, safety);
    value
}

fn file_delete_audit(request: &GitlabFileDeleteRequest, safety: &GitlabBranchSafety) -> Value {
    let mut audit = GitlabRequestBodyAudit::default();
    audit.add_scalar_field("path");
    audit.add_scalar_field("branch");
    audit.add_text_field("commit_message", &request.commit_message);
    audit.add_optional_scalar_field("start_branch", request.start_branch.is_some());
    audit.add_optional_scalar_field("author_name", request.author_name.is_some());
    audit.add_optional_scalar_field("author_email", request.author_email.is_some());
    audit.add_optional_scalar_field("last_commit_id", request.last_commit_id.is_some());
    let mut value = audit.into_value();
    add_path_branch_audit(&mut value, &request.path, &request.branch);
    add_branch_safety_audit(&mut value, &request.branch, safety);
    value
}

fn commit_create_audit(request: &GitlabCommitCreateRequest, safety: &GitlabBranchSafety) -> Value {
    let mut audit = GitlabRequestBodyAudit::default();
    audit.add_scalar_field("branch");
    audit.add_text_field("commit_message", &request.commit_message);
    audit.add_list_field("actions", request.actions.len());
    audit.add_optional_scalar_field("start_branch", request.start_branch.is_some());
    audit.add_optional_scalar_field("start_sha", request.start_sha.is_some());
    audit.add_optional_scalar_field("author_name", request.author_name.is_some());
    audit.add_optional_scalar_field("author_email", request.author_email.is_some());
    let mut value = audit.into_value();
    let actions = request
        .actions
        .iter()
        .map(|action| {
            json!({
                "action": action.action,
                "filePath": action.file_path,
                "previousPath": action.previous_path,
                "encoding": action.encoding,
                "executeFilemode": action.execute_filemode.is_some(),
                "lastCommitId": action.last_commit_id.is_some(),
                "decodedContentBytes": action.decoded_content_bytes,
            })
        })
        .collect::<Vec<_>>();
    value["actions"] = json!(actions);
    add_branch_safety_audit(&mut value, &request.branch, safety);
    value
}

fn ci_ref_audit(ref_name: &str, safety: &GitlabCiRefSafety) -> Value {
    let mut audit = GitlabRequestBodyAudit::default();
    audit.add_scalar_field("ref");
    let mut value = audit.into_value();
    value["ref"] = json!(ref_name);
    value["refSafety"] = ci_ref_safety_audit(safety);
    value
}

fn ci_ref_safety_audit(safety: &GitlabCiRefSafety) -> Value {
    json!({
        "ref": safety.ref_name,
        "defaultBranch": safety.default_branch,
        "existingBranchDefault": safety.existing_branch_default,
        "existingBranchProtected": safety.existing_branch_protected,
        "matchedProtectedBranch": safety.matched_protected_branch,
        "denialReason": safety.denial_reason,
    })
}

fn add_path_branch_audit(value: &mut Value, path: &str, branch: &str) {
    value["path"] = json!(path);
    value["branch"] = json!(branch);
}

fn add_branch_safety_audit(value: &mut Value, branch: &str, safety: &GitlabBranchSafety) {
    value["branch"] = json!(branch);
    value["branchSafety"] = json!({
        "branch": safety.branch,
        "defaultBranch": safety.default_branch,
        "targetBranchExists": safety.target_branch_exists,
        "existingBranchDefault": safety.existing_branch_default,
        "existingBranchProtected": safety.existing_branch_protected,
        "matchedProtectedBranch": safety.matched_protected_branch,
    });
}

fn request_body_audit_for_issue_create(request: &GitlabIssueCreateRequest) -> Value {
    let mut audit = GitlabRequestBodyAudit::default();
    audit.add_text_field("title", &request.title);
    audit.add_optional_text_field("description", request.description.as_ref());
    audit.add_list_field("labels", request.labels.len());
    audit.add_optional_scalar_field("milestone", request.milestone.is_some());
    audit.add_list_field("assignee_ids", request.assignee_ids.len());
    audit.add_optional_scalar_field("confidential", request.confidential.is_some());
    audit.into_value()
}

fn request_body_audit_for_issue_update(request: &GitlabIssueUpdateRequest) -> Value {
    let mut audit = GitlabRequestBodyAudit::default();
    audit.add_optional_text_field("title", request.title.as_ref());
    audit.add_optional_text_field("description", request.description.as_ref());
    audit.add_optional_scalar_field("state_event", request.state_event.is_some());
    audit.add_list_field("labels", request.labels.len());
    audit.add_list_field("add_labels", request.add_labels.len());
    audit.add_list_field("remove_labels", request.remove_labels.len());
    audit.add_optional_scalar_field("milestone", request.milestone.is_some());
    audit.add_list_field("assignee_ids", request.assignee_ids.len());
    audit.add_optional_scalar_field("confidential", request.confidential.is_some());
    audit.into_value()
}

fn request_body_audit_for_issue_note_create(request: &GitlabIssueNoteCreateRequest) -> Value {
    let mut audit = GitlabRequestBodyAudit::default();
    audit.add_text_field("body", &request.body);
    audit.add_optional_scalar_field("confidential", request.confidential.is_some());
    audit.into_value()
}

fn request_body_audit_for_note_create(request: &GitlabNoteCreateRequest) -> Value {
    let mut audit = GitlabRequestBodyAudit::default();
    audit.add_text_field("body", &request.body);
    audit.into_value()
}

fn request_body_audit_for_note_update(request: &GitlabNoteUpdateRequest) -> Value {
    let mut audit = GitlabRequestBodyAudit::default();
    audit.add_text_field("body", &request.body);
    audit.into_value()
}

fn request_body_audit_for_discussion_note_update(
    request: &GitlabDiscussionNoteUpdateRequest,
) -> Value {
    let mut audit = GitlabRequestBodyAudit::default();
    audit.add_text_field("body", &request.body);
    audit.into_value()
}

fn request_body_audit_for_merge_request_create(request: &GitlabMergeRequestCreateRequest) -> Value {
    let mut audit = GitlabRequestBodyAudit::default();
    audit.add_scalar_field("source_branch");
    audit.add_scalar_field("target_branch");
    audit.add_text_field("title", &request.title);
    audit.add_optional_text_field("description", request.description.as_ref());
    audit.add_list_field("labels", request.labels.len());
    audit.add_list_field("assignee_ids", request.assignee_ids.len());
    audit.add_list_field("reviewer_ids", request.reviewer_ids.len());
    audit.add_optional_scalar_field(
        "remove_source_branch",
        request.remove_source_branch.is_some(),
    );
    audit.add_optional_scalar_field("squash", request.squash.is_some());
    audit.add_optional_scalar_field("draft", request.draft.is_some());
    audit.into_value()
}

fn request_body_audit_for_merge_request_update(request: &GitlabMergeRequestUpdateRequest) -> Value {
    let mut audit = GitlabRequestBodyAudit::default();
    audit.add_optional_text_field("title", request.title.as_ref());
    audit.add_optional_text_field("description", request.description.as_ref());
    audit.add_optional_scalar_field("state_event", request.state_event.is_some());
    audit.add_list_field("labels", request.labels.len());
    audit.add_list_field("add_labels", request.add_labels.len());
    audit.add_list_field("remove_labels", request.remove_labels.len());
    audit.add_list_field("assignee_ids", request.assignee_ids.len());
    audit.add_list_field("reviewer_ids", request.reviewer_ids.len());
    audit.add_optional_scalar_field("target_branch", request.target_branch.is_some());
    audit.add_optional_scalar_field(
        "remove_source_branch",
        request.remove_source_branch.is_some(),
    );
    audit.add_optional_scalar_field("squash", request.squash.is_some());
    audit.into_value()
}

fn request_body_audit_for_merge_request_merge(
    request: &GitlabMergeRequestMergeRequest,
    existing: &GitlabMergeRequest,
    merged: &GitlabMergeRequest,
) -> Value {
    let mut audit = GitlabRequestBodyAudit::default();
    audit.add_scalar_field("iid");
    audit.add_scalar_field("sha");
    audit.add_optional_scalar_field("squash", request.squash.is_some());
    audit.add_optional_scalar_field(
        "should_remove_source_branch",
        request.should_remove_source_branch.is_some(),
    );
    audit.add_optional_text_field(
        "merge_commit_message",
        request.merge_commit_message.as_ref(),
    );
    audit.add_optional_text_field(
        "squash_commit_message",
        request.squash_commit_message.as_ref(),
    );
    let mut value = audit.into_value();
    value["iid"] = json!(request.iid);
    value["sha"] = json!(request.sha);
    value["sourceBranch"] = json!(existing.source_branch.clone());
    value["targetBranch"] = json!(existing.target_branch.clone());
    value["currentMergeStatus"] = json!(existing.merge_status.clone());
    value["currentDetailedMergeStatus"] = json!(existing.detailed_merge_status.clone());
    value["upstreamMergeStatus"] = json!(merged.merge_status.clone());
    value["upstreamDetailedMergeStatus"] = json!(merged.detailed_merge_status.clone());
    value["mergeCommitSha"] = json!(merged.merge_commit_sha.clone());
    value
}

#[derive(Default)]
struct GitlabRequestBodyAudit {
    json_fields: Vec<&'static str>,
    text_byte_counts: BTreeMap<&'static str, u64>,
    list_counts: BTreeMap<&'static str, usize>,
}

impl GitlabRequestBodyAudit {
    fn add_scalar_field(&mut self, field: &'static str) {
        self.json_fields.push(field);
    }

    fn add_optional_scalar_field(&mut self, field: &'static str, present: bool) {
        if present {
            self.add_scalar_field(field);
        }
    }

    fn add_text_field(&mut self, field: &'static str, value: &str) {
        self.add_scalar_field(field);
        self.text_byte_counts.insert(field, value.len() as u64);
    }

    fn add_optional_text_field(&mut self, field: &'static str, value: Option<&String>) {
        if let Some(value) = value {
            self.add_text_field(field, value);
        }
    }

    fn add_list_field(&mut self, field: &'static str, count: usize) {
        if count > 0 {
            self.add_scalar_field(field);
            self.list_counts.insert(field, count);
        }
    }

    fn into_value(self) -> Value {
        let mut value =
            serde_json::Map::from_iter([("jsonFields".to_string(), json!(self.json_fields))]);
        if !self.text_byte_counts.is_empty() {
            value.insert("textByteCounts".to_string(), json!(self.text_byte_counts));
        }
        if !self.list_counts.is_empty() {
            value.insert("listCounts".to_string(), json!(self.list_counts));
        }
        Value::Object(value)
    }
}

fn gitlab_lookup_backend_error(error: GitlabBackendError) -> ProviderError {
    match error {
        GitlabBackendError::NotFound | GitlabBackendError::Forbidden => ProviderError::deny(
            ReasonCode::ScopeUnresolved,
            "GitLab resource was not found or not permitted",
        ),
        other => gitlab_backend_error(other),
    }
}

fn gitlab_proof_backend_error(error: GitlabBackendError) -> ProviderError {
    match error {
        GitlabBackendError::NotFound | GitlabBackendError::Forbidden => note_scope_mismatch_error(),
        other => gitlab_backend_error(other),
    }
}

fn gitlab_merge_backend_error(write: &PlainWrite, error: GitlabBackendError) -> ProviderError {
    match error {
        GitlabBackendError::HttpStatus(409) => ProviderError::deny(
            ReasonCode::VersionConflict,
            "GitLab merge request sha does not match current metadata",
        ),
        other => write.failed(other),
    }
}

/// An action's single upstream write that the SDK proved never reached
/// GitLab: nothing was applied, so repeating the action is safe. Call it only
/// for the first write of an action, never after another write applied.
pub(crate) fn mutation_not_sent(timed_out: bool) -> ProviderError {
    ProviderError::error(
        if timed_out {
            ReasonCode::UpstreamTimeout
        } else {
            ReasonCode::UpstreamConnectionFailed
        },
        "GitLab request was not sent; nothing was applied",
    )
    .with_mutation_receipt(MutationReceipt::not_applied())
}

/// The receipts of an action's single upstream write that has no
/// verification contract. Its failures keep their ordinary reason and
/// message.
pub(crate) struct PlainWrite {
    /// What the write targets, from the validated request and the responses
    /// that preceded the write; never from the write's own response.
    locators: Value,
}

impl PlainWrite {
    pub(crate) fn new(locators: Value) -> Self {
        Self { locators }
    }

    /// The failure of the write request itself:
    ///
    /// - proven unsent: `not_applied`;
    /// - no response, a 5xx a proxy may return after GitLab committed the
    ///   write, or a redirect the Broker never follows: `unknown`;
    /// - a success status whose response then stalled, failed, exceeded the
    ///   byte cap or did not parse: `applied_unverified`;
    /// - a rejection, or a failure before anything was sent: no receipt.
    pub(crate) fn failed(&self, error: GitlabBackendError) -> ProviderError {
        match error {
            GitlabBackendError::NotSent { timed_out } => mutation_not_sent(timed_out),
            GitlabBackendError::NoResponse { .. }
            | GitlabBackendError::HttpStatus(300..=399 | 500..=599) => {
                gitlab_backend_error(error).with_mutation_receipt(MutationReceipt::unknown())
            }
            GitlabBackendError::Timeout
            | GitlabBackendError::Transport(_)
            | GitlabBackendError::ResponseTooLarge
            | GitlabBackendError::DraftPositionShapeInvalid
            | GitlabBackendError::Protocol(_) => self.unverified(gitlab_backend_error(error)),
            GitlabBackendError::RequestUnbuilt(_)
            | GitlabBackendError::Credential(_)
            | GitlabBackendError::Unauthorized
            | GitlabBackendError::Forbidden
            | GitlabBackendError::NotFound
            | GitlabBackendError::HttpStatus(_)
            | GitlabBackendError::RateLimited(_)
            | GitlabBackendError::Validation { .. } => gitlab_backend_error(error),
        }
    }

    /// A failure after GitLab accepted the write, such as a response that
    /// does not match the request: `applied_unverified` at the
    /// `mutation_response` stage.
    pub(crate) fn unverified(&self, error: ProviderError) -> ProviderError {
        error.or_mutation_receipt(MutationReceipt::applied_unverified(
            "mutation_response",
            self.locators.clone(),
        ))
    }
}

/// The failure of the version check before a review submission. Throttling,
/// and delegated access that could not be presented (an OAuth refresh
/// throttled or busy, consent pending, a reconnect required) or that GitLab
/// rejected again, keep their own reason and retry metadata; anything else is
/// a failed version discovery.
fn gitlab_review_submit_version_backend_error(error: GitlabBackendError) -> ProviderError {
    match error {
        GitlabBackendError::RateLimited(retry_after) => {
            upstream_rate_limited("gitlab", retry_after)
        }
        GitlabBackendError::Credential(error) => error,
        _ => ProviderError::error(
            ReasonCode::UpstreamProtocolFailed,
            "GitLab version discovery failed",
        ),
    }
}

fn gitlab_backend_error(error: GitlabBackendError) -> ProviderError {
    match error {
        GitlabBackendError::Unauthorized => ProviderError::error(
            ReasonCode::UpstreamUnauthorized,
            "GitLab rejected the selected credential",
        ),
        GitlabBackendError::Forbidden => ProviderError::error(
            ReasonCode::UpstreamForbidden,
            "GitLab forbade the selected credential",
        ),
        GitlabBackendError::NotFound => ProviderError::deny(
            ReasonCode::ScopeUnresolved,
            "GitLab resource was not found or not permitted",
        ),
        GitlabBackendError::HttpStatus(_) => {
            ProviderError::error(ReasonCode::UpstreamFailed, "GitLab returned non-success")
        }
        GitlabBackendError::RateLimited(retry_after) => {
            upstream_rate_limited("gitlab", retry_after)
        }
        GitlabBackendError::Validation { status, message } => ProviderError::deny(
            ReasonCode::InputInvalid,
            format!("GitLab rejected the request: {message}"),
        )
        .with_upstream(Some(status), None),
        GitlabBackendError::RequestUnbuilt(error) => gitlab_backend_error(*error),
        GitlabBackendError::NotSent { timed_out: false }
        | GitlabBackendError::NoResponse { timed_out: false }
        | GitlabBackendError::Transport(_) => ProviderError::error(
            ReasonCode::UpstreamConnectionFailed,
            "GitLab request failed",
        ),
        GitlabBackendError::NotSent { timed_out: true }
        | GitlabBackendError::NoResponse { timed_out: true }
        | GitlabBackendError::Timeout => {
            ProviderError::error(ReasonCode::UpstreamTimeout, "GitLab request timed out")
        }
        GitlabBackendError::ResponseTooLarge => ProviderError::error(
            ReasonCode::UpstreamProtocolFailed,
            "GitLab response exceeded the configured byte cap",
        ),
        GitlabBackendError::DraftPositionShapeInvalid => ProviderError::error(
            ReasonCode::UpstreamProtocolFailed,
            "GitLab response protocol error",
        )
        .with_internal_diagnostic_code(InternalDiagnosticCode::DraftPositionShapeInvalid.as_str()),
        GitlabBackendError::Protocol(_) => ProviderError::error(
            ReasonCode::UpstreamProtocolFailed,
            "GitLab response protocol error",
        ),
        GitlabBackendError::Credential(error) => error,
    }
}

fn encoded_path_segment(value: &str) -> String {
    utf8_percent_encode(value, PATH_SEGMENT_ENCODE_SET).to_string()
}

fn elapsed_ms(started: Instant) -> u64 {
    started.elapsed().as_millis().try_into().unwrap_or(u64::MAX)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InternalDiagnosticCode {
    DraftPositionShapeInvalid,
}

impl InternalDiagnosticCode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::DraftPositionShapeInvalid => "draft_position_shape_invalid",
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PositionInputCategory {
    CoordinatesUnresolved,
    PatchUnavailable,
    SuggestionOutdated,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PositionInputFailureResult {
    input_category: PositionInputCategory,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum MutationVerificationStage {
    MutationResponse,
    MutationReadback,
    PublishedNoteReadback,
    DraftAbsenceReadback,
    BulkPublishReadback,
    ReviewerStateReadback,
    SummaryNoteResponse,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MutationSafeLocators {
    #[serde(skip_serializing_if = "Option::is_none")]
    user_id: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    token_id: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    previous_token_id: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    discussion_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    note_id: Option<u64>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    draft_note_ids: Vec<u64>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    suggestion_ids: Vec<u64>,
    #[serde(
        default,
        skip_serializing_if = "Vec::is_empty",
        deserialize_with = "deserialize_bounded_webhook_locator_ids"
    )]
    webhook_ids: Vec<u64>,
    #[serde(
        default,
        skip_serializing_if = "Vec::is_empty",
        deserialize_with = "deserialize_bounded_webhook_locator_ids"
    )]
    webhook_event_ids: Vec<u64>,
}

impl MutationSafeLocators {
    const MAX_WEBHOOK_LOCATOR_IDS: usize = 100;

    pub(crate) fn with_provisioning_ids(
        mut self,
        user_id: Option<u64>,
        token_id: Option<u64>,
        previous_token_id: Option<u64>,
    ) -> Self {
        self.user_id = user_id;
        self.token_id = token_id;
        self.previous_token_id = previous_token_id;
        self
    }

    pub(crate) fn new() -> Self {
        Self::default()
    }

    pub(crate) fn with_discussion_id(mut self, discussion_id: impl Into<String>) -> Self {
        self.discussion_id = Some(discussion_id.into());
        self
    }

    pub(crate) fn with_note_id(mut self, note_id: u64) -> Self {
        self.note_id = Some(note_id);
        self
    }

    pub(crate) fn with_draft_note_ids(mut self, draft_note_ids: Vec<u64>) -> Self {
        self.draft_note_ids = draft_note_ids;
        self
    }

    #[allow(
        dead_code,
        reason = "used by the separately grantable suggestion mutations"
    )]
    pub(crate) fn with_suggestion_ids(mut self, suggestion_ids: Vec<u64>) -> Self {
        self.suggestion_ids = suggestion_ids;
        self
    }

    pub(crate) fn with_webhook_ids(mut self, webhook_ids: Vec<u64>) -> Self {
        self.webhook_ids = bounded_sorted_unique_ids(webhook_ids, Self::MAX_WEBHOOK_LOCATOR_IDS);
        self
    }

    pub(crate) fn with_webhook_event_ids(mut self, webhook_event_ids: Vec<u64>) -> Self {
        self.webhook_event_ids =
            bounded_sorted_unique_ids(webhook_event_ids, Self::MAX_WEBHOOK_LOCATOR_IDS);
        self
    }
}

fn bounded_sorted_unique_ids(mut ids: Vec<u64>, maximum: usize) -> Vec<u64> {
    ids.retain(|id| *id > 0);
    ids.sort_unstable();
    ids.dedup();
    ids.truncate(maximum);
    ids
}

fn deserialize_bounded_webhook_locator_ids<'de, D>(deserializer: D) -> Result<Vec<u64>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let ids = Vec::<u64>::deserialize(deserializer)?;
    Ok(bounded_sorted_unique_ids(
        ids,
        MutationSafeLocators::MAX_WEBHOOK_LOCATOR_IDS,
    ))
}

pub fn mutation_verification_failed(
    verification_stage: MutationVerificationStage,
    safe_locators: MutationSafeLocators,
) -> ProviderError {
    let stage = serde_json::to_value(verification_stage)
        .expect("mutation verification stage is serializable");
    ProviderError::error(
        ReasonCode::MutationVerificationFailed,
        "upstream mutation could not be fully verified",
    )
    .with_mutation_receipt(MutationReceipt::applied_unverified(
        stage
            .as_str()
            .expect("mutation verification stage serializes as a string"),
        serde_json::to_value(safe_locators).expect("mutation safe locators are serializable"),
    ))
}

pub fn position_input_invalid(input_category: PositionInputCategory) -> ProviderError {
    ProviderError::deny(ReasonCode::InputInvalid, "position is invalid").with_result(
        serde_json::to_value(PositionInputFailureResult { input_category })
            .expect("position input failure result is serializable"),
    )
}
