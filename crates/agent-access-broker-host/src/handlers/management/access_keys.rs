//! Access keys: a person's own, from a signed-in browser session, and an
//! administrator's, issued for a person or a service account and listed and
//! revoked across all accounts. An access key is for the services that
//! resolve it; nothing here makes the Broker accept one.
//!
//! The personal routes use `ManagementAccess::Account`: they depend on the
//! person's access key type setting, the type's `self_service` and the
//! person's username, not on self-service for the account or on any
//! service grant.
use super::common::*;
use super::identity_access::{committed_identity_mutation, invalid_input, parse_body};
use crate::state::AppState;
use agent_access_core::{
    AccessKeyListFilter, AccessKeyRefusal, AccessKeyRefused, AdministratorAccessKeyRequest,
    BrokerRuntime, BrokerTokenHasher, IssuedAccessKey, ManagedStore, ManagedStoreError,
    PortalAccessKeyRequest, has_broker_secret_prefix, is_access_key_id,
    is_valid_access_key_lifetime,
};
use agent_access_provider::ReasonCode;
use axum::{
    body::Bytes,
    extract::{ConnectInfo, Path, RawQuery, State},
    http::{HeaderMap, StatusCode},
    response::Response,
};
use serde::Deserialize;
use serde_json::{Value, json};
use std::net::SocketAddr;
use std::sync::Arc;
use tracing::Instrument;
use tracing::instrument::WithSubscriber;
use url::form_urlencoded;

/// A request for a token: its name, the access key types it carries and how
/// long it lasts. A JSON object: an array of the same values in order is
/// not read as one.
#[derive(Deserialize)]
#[serde(remote = "Self", rename_all = "camelCase", deny_unknown_fields)]
struct IssueBody {
    name: String,
    access_key_types: Vec<String>,
    lifetime: String,
}
agent_access_core::deserialize_object_only!(IssueBody);

impl IssueBody {
    fn contains_secret(&self) -> bool {
        has_broker_secret_prefix(&self.name)
            || self
                .access_key_types
                .iter()
                .any(|id| has_broker_secret_prefix(id))
    }
}

const ISSUE_BODY_MESSAGE: &str = "request body requires name, accessKeyTypes (a list of access key type IDs) and lifetime (a duration string or never)";

/// A person's own routes require the browser session the store re-checks at
/// a mint: a bearer token, even the person's own, is refused.
async fn personal_context(
    state: &AppState,
    remote: SocketAddr,
    headers: &HeaderMap,
    operation: &str,
) -> Result<(ManagementContext, String), Box<Response>> {
    let context =
        management_context(state, remote, headers, operation, ManagementAccess::Account).await?;
    let Some(session) = context
        .browser_session
        .as_ref()
        .map(|session| session.token_id().to_string())
    else {
        let refused = AccessKeyRefused::new(AccessKeyRefusal::SessionRequired);
        return Err(Box::new(
            management_store_error_response(
                &context,
                operation,
                None,
                ManagedStoreError::AccessKeyRefused(refused),
            )
            .await,
        ));
    };
    Ok((context, session))
}

fn hasher(context: &ManagementContext) -> Option<BrokerTokenHasher> {
    context.snapshot.runtime.broker_token_hasher().cloned()
}

async fn hasher_unavailable(context: &ManagementContext, operation: &str) -> Response {
    management_context_error_response(
        context,
        StatusCode::SERVICE_UNAVAILABLE,
        operation,
        ReasonCode::EncryptionKeyMissing,
        "broker token hash key is not configured",
        None,
    )
    .await
}

/// `includeRevoked`, `includeExpired` and, for an administrator, `principal`.
fn list_filter(
    raw_query: Option<&str>,
    principal: Option<String>,
    principal_parameter: bool,
) -> Result<AccessKeyListFilter, String> {
    let mut filter = AccessKeyListFilter {
        principal_id: principal,
        include_revoked: false,
        include_expired: false,
    };
    let mut seen = Vec::new();
    for (key, value) in form_urlencoded::parse(raw_query.unwrap_or_default().as_bytes()) {
        if seen.contains(&key.to_string()) {
            return Err("a query parameter is duplicated".into());
        }
        let flag = |value: &str| -> Result<bool, String> {
            match value {
                "true" => Ok(true),
                "false" => Ok(false),
                _ => Err("query flags must be true or false".into()),
            }
        };
        match key.as_ref() {
            "includeRevoked" => filter.include_revoked = flag(&value)?,
            "includeExpired" => filter.include_expired = flag(&value)?,
            "principal" if principal_parameter => {
                if has_broker_secret_prefix(&value) {
                    return Err("principal must be an identifier, not a Broker secret".into());
                }
                filter.principal_id = Some(value.to_string());
            }
            _ => return Err("query parameter is not supported".into()),
        }
        seen.push(key.to_string());
    }
    Ok(filter)
}

async fn list(
    context: &ManagementContext,
    operation: &str,
    target: Option<Value>,
    filter: AccessKeyListFilter,
) -> Response {
    let runtime = context.snapshot.runtime.clone();
    match management_store_call(context, move |store| {
        store.list_access_key_views(runtime.access_key_types(), &filter)
    })
    .await
    {
        Ok(tokens) => {
            management_success_response(context, operation, target, json!({"keys": tokens})).await
        }
        Err(error) => management_store_error_response(context, operation, target, error).await,
    }
}

pub(crate) async fn list_own(
    State(state): State<AppState>,
    ConnectInfo(remote): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    RawQuery(query): RawQuery,
) -> Response {
    let operation = "access_keys.list";
    let (context, _session) = match personal_context(&state, remote, &headers, operation).await {
        Ok(context) => context,
        Err(response) => return *response,
    };
    let principal = context.identity.principal.clone();
    match list_filter(query.as_deref(), Some(principal), false) {
        Ok(filter) => list(&context, operation, None, filter).await,
        Err(message) => invalid_input(&context, operation, None, &message).await,
    }
}

pub(crate) async fn options_own(
    State(state): State<AppState>,
    ConnectInfo(remote): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> Response {
    let operation = "access_keys.options";
    let (context, _session) = match personal_context(&state, remote, &headers, operation).await {
        Ok(context) => context,
        Err(response) => return *response,
    };
    let runtime = context.snapshot.runtime.clone();
    let principal = context.identity.principal.clone();
    match management_store_call(&context, move |store| {
        store.portal_access_key_options(runtime.access_key_types(), &principal)
    })
    .await
    {
        Ok(options) => {
            let result = json!({
                // The person's own name and where it stands, with the reason
                // when there is none, and what their saved email gives;
                // never who holds a name they lack.
                "accountUsername": options.account_username.as_ref().map(|view| json!({
                    "name": view.name.as_ref().map(|name| name.account_username.as_str()),
                    "state": view.state,
                    "mode": view.mode,
                    "reason": view.reason,
                    "fromEmail": view.from_email.as_ref().map(|from_email| json!({
                        "accountUsername": from_email.account_username,
                        "reason": from_email.reason,
                    })),
                })),
                "refusal": options.refusal,
                // The types the person may hold; `selfService` says which of
                // them the person may create a token of.
                "accessKeyTypes": options.access_key_types,
                // What decides whether there is anything to show a person:
                // a type they may create, a token they own, or a type they
                // may hold and a problem only an administrator can remove.
                "hasSelfServiceType": options
                    .access_key_types
                    .iter()
                    .any(|access_key_type| access_key_type.self_service),
                "hasKeys": options.has_keys,
                "problem": options.problem,
            });
            management_success_response(&context, operation, None, result).await
        }
        Err(error) => management_store_error_response(&context, operation, None, error).await,
    }
}

/// Owns a mint and its success record together, whatever becomes of the
/// request: the secret is given only after the record is written, and a
/// record that cannot be written leaves the committed token without ever
/// revealing it. The mint runs under the reload fence, so the access key types
/// and username settings it applies are those of the generation in force.
/// The success record is the mint's only audit record, so the owner holds a
/// shutdown-drain lease from before it is spawned until that record is
/// written: shutdown waits for it before the audit writers close.
async fn committed_issuance<F>(
    state: AppState,
    context: ManagementContext,
    operation: &'static str,
    target: Option<Value>,
    mint: F,
) -> Response
where
    F: FnOnce(
            &ManagedStore,
            &BrokerRuntime,
        ) -> Result<Result<IssuedAccessKey, AccessKeyRefused>, ManagedStoreError>
        + Send
        + 'static,
{
    let context = Arc::new(context);
    let owner_context = context.clone();
    let owner_target = target.clone();
    #[cfg(test)]
    let barrier = state
        .reloadable
        .access_key_mint_barrier
        .lock()
        .unwrap()
        .clone();
    let lease = state.reloadable.application_owners.register();
    let owner = tokio::spawn(
        async move {
            let _lease = lease;
            let context = owner_context;
            let response = async {
                #[cfg(test)]
                if let Some(barrier) = barrier.clone() {
                    tokio::task::spawn_blocking(move || barrier.wait())
                        .await
                        .expect("access key mint barrier");
                }
                issue_and_audit(&state, &context, operation, owner_target, mint).await
            }
            .await;
            #[cfg(test)]
            if let Some(barrier) = barrier {
                barrier.completed.notify_one();
            }
            response
        }
        .in_current_span()
        .with_current_subscriber(),
    );
    match owner.await {
        Ok(response) => response,
        Err(_) => {
            management_store_error_response(
                &context,
                operation,
                target,
                ManagedStoreError::Unavailable("access key issuance owner failed".into()),
            )
            .await
        }
    }
}

/// The owner's work: the fenced mint, its success record, then the secret.
async fn issue_and_audit<F>(
    state: &AppState,
    context: &ManagementContext,
    operation: &'static str,
    target: Option<Value>,
    mint: F,
) -> Response
where
    F: FnOnce(
            &ManagedStore,
            &BrokerRuntime,
        ) -> Result<Result<IssuedAccessKey, AccessKeyRefused>, ManagedStoreError>
        + Send
        + 'static,
{
    let runtime = context.snapshot.runtime.clone();
    let minted = management_token_store_call(state, context, move |store, _, _| {
        mint(&store, &runtime)?.map_err(ManagedStoreError::AccessKeyRefused)
    })
    .await;
    let issued = match minted {
        Ok(issued) => issued,
        Err(error) => {
            return management_store_error_response(context, operation, target, error).await;
        }
    };
    let mut success_target = issued.record.audit_details();
    success_target["name"] = json!(issued.record.name);
    let success_target = Some(success_target);
    let record =
        management_success_envelope(context, operation, success_target.clone(), Value::Null);
    if let Err(error) = append_management_audit_with_phase(
        &context.snapshot,
        &context.request_id,
        &context.broker_request_id,
        &context.identity,
        &context.source,
        &record,
        ManagementAuditExtra {
            catalog_change: None,
            phase: Some("success"),
            verification: None,
        },
    )
    .await
    {
        return management_audit_unavailable_response(
            &context.request_id,
            &context.broker_request_id,
            operation,
            &context.identity.principal,
            error,
        );
    }
    management_response(
        StatusCode::OK,
        management_success_envelope(
            context,
            operation,
            success_target,
            json!({"key": issued.key, "record": issued.record}),
        ),
    )
}

pub(crate) async fn issue_own(
    State(state): State<AppState>,
    ConnectInfo(remote): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let operation = "access_keys.issue";
    let (context, session) = match personal_context(&state, remote, &headers, operation).await {
        Ok(context) => context,
        Err(response) => return *response,
    };
    let Some(body) = parse_body::<IssueBody>(&body) else {
        return invalid_input(&context, operation, None, ISSUE_BODY_MESSAGE).await;
    };
    if !is_valid_access_key_lifetime(&body.lifetime) {
        return invalid_input(&context, operation, None, ISSUE_BODY_MESSAGE).await;
    }
    if body.contains_secret() {
        return invalid_input(
            &context,
            operation,
            None,
            "name and accessKeyTypes must not contain an access key secret",
        )
        .await;
    }
    let Some(hasher) = hasher(&context) else {
        return hasher_unavailable(&context, operation).await;
    };
    let principal = context.identity.principal.clone();
    let target = Some(json!({"principal": principal}));
    committed_issuance(state, context, operation, target, move |store, runtime| {
        store.mint_portal_access_key(
            &hasher,
            runtime.access_key_types(),
            &PortalAccessKeyRequest {
                principal_id: principal,
                session_token_id: session,
                name: body.name,
                access_key_types: body.access_key_types,
                lifetime: body.lifetime,
            },
        )
    })
    .await
}

pub(crate) async fn revoke_own(
    State(state): State<AppState>,
    Path(token): Path<String>,
    ConnectInfo(remote): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> Response {
    let operation = "access_keys.revoke";
    let (context, _session) = match personal_context(&state, remote, &headers, operation).await {
        Ok(context) => context,
        Err(response) => return *response,
    };
    let principal = context.identity.principal.clone();
    revoke(state, context, operation, token, Some(principal)).await
}

/// Revokes a token; `owner`, when given, must own it. Revocation is final,
/// and revoking a revoked token changes nothing.
async fn revoke(
    state: AppState,
    context: ManagementContext,
    operation: &'static str,
    token: String,
    owner: Option<String>,
) -> Response {
    if !is_access_key_id(&token) {
        return management_store_error_response(
            &context,
            operation,
            None,
            ManagedStoreError::AccessKeyNotFound,
        )
        .await;
    }
    let target = Some(json!({"keyId": token}));
    if let Err(response) =
        management_write_audit_preflight(&context, operation, target.clone()).await
    {
        return *response;
    }
    let actor = context.identity.principal.clone();
    committed_identity_mutation(state, context, operation, target, move |store| {
        let revocation = store
            .revoke_access_key(&token, owner.as_deref(), &actor)?
            .ok_or(ManagedStoreError::AccessKeyNotFound)?;
        let mut completion = revocation.record.audit_details();
        completion["newlyRevoked"] = json!(revocation.newly_revoked);
        Ok((
            json!({"revoked": true, "newlyRevoked": revocation.newly_revoked,
                "record": revocation.record}),
            completion,
        ))
    })
    .await
}

pub(crate) async fn admin_list(
    State(state): State<AppState>,
    ConnectInfo(remote): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    RawQuery(query): RawQuery,
) -> Response {
    let operation = "admin.access_keys.list";
    let context = match management_context(
        &state,
        remote,
        &headers,
        operation,
        ManagementAccess::AdminRead,
    )
    .await
    {
        Ok(context) => context,
        Err(response) => return *response,
    };
    match list_filter(query.as_deref(), None, true) {
        Ok(filter) => {
            let target = filter
                .principal_id
                .as_ref()
                .map(|principal| json!({"principal": principal}));
            list(&context, operation, target, filter).await
        }
        Err(message) => invalid_input(&context, operation, None, &message).await,
    }
}

pub(crate) async fn admin_issue(
    State(state): State<AppState>,
    Path(principal): Path<String>,
    ConnectInfo(remote): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let operation = "admin.principals.access_keys.issue";
    let context = match management_context(
        &state,
        remote,
        &headers,
        operation,
        ManagementAccess::AdminWrite,
    )
    .await
    {
        Ok(context) => context,
        Err(response) => return *response,
    };
    if has_broker_secret_prefix(&principal) {
        return invalid_input(
            &context,
            operation,
            None,
            "principal must be an identifier, not a Broker secret",
        )
        .await;
    }
    let target = Some(json!({"principal": principal}));
    let Some(body) = parse_body::<IssueBody>(&body) else {
        return invalid_input(&context, operation, target, ISSUE_BODY_MESSAGE).await;
    };
    if !is_valid_access_key_lifetime(&body.lifetime) {
        return invalid_input(&context, operation, target, ISSUE_BODY_MESSAGE).await;
    }
    if body.contains_secret() {
        return invalid_input(
            &context,
            operation,
            None,
            "name and accessKeyTypes must not contain an access key secret",
        )
        .await;
    }
    let Some(hasher) = hasher(&context) else {
        return hasher_unavailable(&context, operation).await;
    };
    let actor = context.identity.principal.clone();
    committed_issuance(state, context, operation, target, move |store, runtime| {
        store.mint_administrator_access_key(
            &hasher,
            runtime.access_key_types(),
            &AdministratorAccessKeyRequest {
                principal_id: principal,
                name: body.name,
                access_key_types: body.access_key_types,
                lifetime: body.lifetime,
                created_by: actor,
            },
        )
    })
    .await
}

pub(crate) async fn admin_revoke(
    State(state): State<AppState>,
    Path(token): Path<String>,
    ConnectInfo(remote): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> Response {
    let operation = "admin.access_keys.revoke";
    let context = match management_context(
        &state,
        remote,
        &headers,
        operation,
        ManagementAccess::AdminWrite,
    )
    .await
    {
        Ok(context) => context,
        Err(response) => return *response,
    };
    revoke(state, context, operation, token, None).await
}

/// The configured access key types, as the current configuration defines them.
pub(crate) async fn admin_access_key_types(
    State(state): State<AppState>,
    ConnectInfo(remote): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> Response {
    let operation = "admin.access_key_types.list";
    let context = match management_context(
        &state,
        remote,
        &headers,
        operation,
        ManagementAccess::AdminRead,
    )
    .await
    {
        Ok(context) => context,
        Err(response) => return *response,
    };
    let access_key_types = context
        .snapshot
        .runtime
        .access_key_types()
        .iter()
        .collect::<Vec<_>>();
    management_success_response(
        &context,
        operation,
        None,
        json!({"accessKeyTypes": access_key_types}),
    )
    .await
}
