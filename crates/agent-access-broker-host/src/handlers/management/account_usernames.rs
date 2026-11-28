//! Administration of usernames: the name a person is known by to the
//! services that resolve their access keys. Administrators and auditors
//! read; only an administrator's audited action sets how a name is decided,
//! sets it by hand or confirms it. Every change runs under the reload fence,
//! so it applies the `[usernames]` settings of the generation that serves
//! the request.
//!
//! The names of people who follow their email and hold none are filled in
//! after startup and reload, by [`fill_missing_after_publication`].
use super::common::*;
use super::identity_access::{committed_identity_mutation, invalid_input, parse_body};
use crate::state::{AppState, ReloadableState, RuntimeSnapshot};
use agent_access_core::{
    ACCOUNT_USERNAME_FILL_BATCH_SIZE, AccountUsernameFillBatch, AccountUsernameRefused,
    AccountUsernameSetting, AuditRecord, ManagedStoreError, PrincipalAccountUsername,
    SourceContext, has_broker_secret_prefix,
};
use agent_access_provider::{Decision, ReasonCode, ResourceScopes};
use axum::{
    body::Bytes,
    extract::{ConnectInfo, Path, State},
    http::HeaderMap,
    response::Response,
};
use chrono::Utc;
use serde::{Deserialize, Deserializer};
use serde_json::{Value, json};
use std::net::SocketAddr;
use std::sync::Arc;
use tracing::Instrument;
use tracing::instrument::WithSubscriber;

// Every body here is a JSON object: an array of the same values in order is
// not read as one.

/// `from_email`, or `manual` with an optional `accountUsername`: absent keeps the
/// name held, a string sets it, null removes it.
#[derive(Deserialize)]
#[serde(remote = "Self", rename_all = "camelCase", deny_unknown_fields)]
struct SetBody {
    mode: SetMode,
    #[serde(default, deserialize_with = "present")]
    account_username: Option<Option<String>>,
}
agent_access_core::deserialize_object_only!(SetBody);

#[derive(Clone, Copy, PartialEq, Eq)]
enum SetMode {
    FromEmail,
    Manual,
}

// A JSON string only. The derived form of an enum also reads an object with
// the variant as its one key, so `{"manual": null}` would be a mode.
impl<'de> Deserialize<'de> for SetMode {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        const MODES: &[&str] = &["from_email", "manual"];
        match String::deserialize(deserializer)?.as_str() {
            "from_email" => Ok(Self::FromEmail),
            "manual" => Ok(Self::Manual),
            other => Err(serde::de::Error::unknown_variant(other, MODES)),
        }
    }
}

/// A member that is present, null or not: `Some(None)` for an explicit null.
fn present<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Option<Option<String>>, D::Error> {
    Option::<String>::deserialize(deserializer).map(Some)
}

impl SetBody {
    /// The setting the body asks for; `None` when it names a name for a
    /// person who is to follow their email.
    fn setting(self) -> Option<AccountUsernameSetting> {
        match (self.mode, self.account_username) {
            (SetMode::FromEmail, None) => Some(AccountUsernameSetting::FromEmail),
            (SetMode::FromEmail, Some(_)) => None,
            (SetMode::Manual, None) => Some(AccountUsernameSetting::Manual),
            (SetMode::Manual, Some(None)) => Some(AccountUsernameSetting::ManualNone),
            (SetMode::Manual, Some(Some(name))) => Some(AccountUsernameSetting::ManualName(name)),
        }
    }
}

#[derive(Deserialize)]
#[serde(remote = "Self", rename_all = "camelCase", deny_unknown_fields)]
struct ConfirmBody {
    account_username: String,
}
agent_access_core::deserialize_object_only!(ConfirmBody);

/// A principal's username with extra members of one operation's result.
fn view_with(view: PrincipalAccountUsername, extra: Value) -> Value {
    let mut result = json!(view);
    if let (Value::Object(result), Value::Object(extra)) = (&mut result, extra) {
        result.extend(extra);
    }
    result
}

fn refused(refusal: impl Into<AccountUsernameRefused>) -> ManagedStoreError {
    ManagedStoreError::AccountUsernameRefused(refusal.into())
}

pub(crate) async fn admin_get(
    State(state): State<AppState>,
    Path(principal): Path<String>,
    ConnectInfo(remote): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> Response {
    let operation = "admin.principals.account_username.inspect";
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
    match management_store_call(&context, move |store| {
        store.principal_account_username(&principal)
    })
    .await
    {
        Ok(view) => management_success_response(&context, operation, target, view).await,
        Err(error) => management_store_error_response(&context, operation, target, error).await,
    }
}

pub(crate) async fn admin_list(
    State(state): State<AppState>,
    ConnectInfo(remote): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> Response {
    let operation = "admin.account_usernames.list";
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
    match management_store_call(&context, |store| store.list_principal_account_usernames()).await {
        Ok(names) => {
            management_success_response(
                &context,
                operation,
                None,
                json!({"accountUsernames": names}),
            )
            .await
        }
        Err(error) => management_store_error_response(&context, operation, None, error).await,
    }
}

pub(crate) async fn admin_set(
    State(state): State<AppState>,
    Path(principal): Path<String>,
    ConnectInfo(remote): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let operation = "admin.principals.account_username.set";
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
    let Some(setting) = parse_body::<SetBody>(&body).and_then(SetBody::setting) else {
        return invalid_input(
            &context,
            operation,
            target,
            "request body requires mode (from_email or manual); accountUsername, a string or null, is accepted with manual only",
        )
        .await;
    };
    if let Err(response) =
        management_write_audit_preflight(&context, operation, target.clone()).await
    {
        return *response;
    }
    let actor = context.identity.principal.clone();
    committed_identity_mutation(state, context, operation, target, move |store| {
        let change = store
            .set_account_username_setting(&principal, &setting, &actor)?
            .map_err(refused)?;
        let completion = change.audit_details();
        let outcome = change.outcome();
        Ok((
            view_with(change.view, json!({"accountUsernameChange": outcome})),
            completion,
        ))
    })
    .await
}

pub(crate) async fn admin_confirm(
    State(state): State<AppState>,
    Path(principal): Path<String>,
    ConnectInfo(remote): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let operation = "admin.principals.account_username.confirm";
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
    let Some(ConfirmBody { account_username }) = parse_body(&body) else {
        return invalid_input(
            &context,
            operation,
            target,
            "request body requires exactly the string accountUsername: the name the account holds now",
        )
        .await;
    };
    if let Err(response) =
        management_write_audit_preflight(&context, operation, target.clone()).await
    {
        return *response;
    }
    let actor = context.identity.principal.clone();
    committed_identity_mutation(state, context, operation, target, move |store| {
        let change = store
            .confirm_account_username(&principal, &account_username, &actor)?
            .map_err(refused)?;
        let completion = change.audit_details();
        Ok((json!(change.view), completion))
    })
    .await
}

/// Starts the fill of missing names for the generation `snapshot`, which
/// startup or a reload has just put in force. The fill names the people who
/// follow their email and hold no name: existing accounts when the feature
/// is first configured, and accounts whose domain a reload added.
///
/// It runs in its own owner, which holds a shutdown-drain lease from before
/// it is spawned until its last batch is audited. Each batch is one store
/// transaction under the reload fence and examines a bounded number of
/// accounts, named or not; the fence and the store are free between
/// batches. A later reload stops the fill, and that reload's own fill starts
/// over. A snapshot published meanwhile for the same configuration
/// generation, as a change to an imported service publishes, starts no fill
/// of its own: this one goes on under it. A failure is logged and audited
/// and never stops the Broker serving: the next reload or startup tries
/// again.
pub(crate) fn fill_missing_after_publication(
    state: &Arc<ReloadableState>,
    snapshot: Arc<RuntimeSnapshot>,
    trigger: &'static str,
) {
    // Nothing derives a name without a listed domain, so there is nothing
    // to walk.
    if snapshot.runtime.config().usernames.email_domains.is_empty()
        || snapshot.runtime.managed_store().is_none()
    {
        return;
    }
    let lease = state.application_owners.register();
    let state = state.clone();
    tokio::spawn(
        async move {
            let _lease = lease;
            fill_missing(&state, snapshot, trigger).await;
        }
        .in_current_span()
        .with_current_subscriber(),
    );
}

async fn fill_missing(
    state: &Arc<ReloadableState>,
    mut snapshot: Arc<RuntimeSnapshot>,
    trigger: &'static str,
) {
    let broker_request_id = agent_access_core::new_broker_request_id();
    #[cfg(test)]
    let batch_size = state
        .account_username_fill_batch_size
        .lock()
        .unwrap()
        .unwrap_or(ACCOUNT_USERNAME_FILL_BATCH_SIZE);
    #[cfg(not(test))]
    let batch_size = ACCOUNT_USERNAME_FILL_BATCH_SIZE;
    let actor = format!("system:{trigger}");
    let (mut after, mut examined, mut assigned) = (None::<String>, 0_usize, 0_usize);
    loop {
        #[cfg(test)]
        if after.is_some() {
            let barrier = state.account_username_fill_barrier.lock().unwrap().clone();
            if let Some(barrier) = barrier {
                tokio::task::spawn_blocking(move || barrier.wait())
                    .await
                    .expect("account-username fill barrier");
            }
        }
        let batch = {
            let (after, actor) = (after.clone(), actor.clone());
            state
                .token_store_call_from_snapshot(snapshot.clone(), move |runtime| {
                    runtime
                        .managed_store()
                        .ok_or_else(|| {
                            ManagedStoreError::Unavailable("managed store is unavailable".into())
                        })?
                        .fill_missing_account_usernames(after.as_deref(), batch_size, &actor)
                })
                .await
        };
        let batch = match batch {
            Ok(batch) => batch,
            Err(ManagedStoreError::VersionConflict) => {
                let current = state.current();
                if current.generation != snapshot.generation {
                    // A reload put a newer generation in force; its own
                    // fill takes over.
                    return;
                }
                // The same generation was published again with another
                // runtime. Nothing starts a fill for that, so this one
                // goes on under the snapshot now in force, from the batch
                // the fence refused.
                snapshot = current;
                continue;
            }
            Err(error) => {
                tracing::error!(
                    event = "account_username_fill_failed",
                    brokerRequestId = broker_request_id.as_str(),
                    configGeneration = snapshot.generation,
                    trigger,
                    reasonCode = error.reason_code().as_str(),
                    "filling in missing usernames failed; it runs again at the next reload or startup"
                );
                append_fill_record(
                    &snapshot,
                    &broker_request_id,
                    trigger,
                    Decision::Error,
                    Some(error.reason_code()),
                    json!({"trigger": trigger, "reason": "fill_failed"}),
                )
                .await;
                return;
            }
        };
        examined += batch.examined;
        assigned += batch.assigned.len();
        if !batch.assigned.is_empty() {
            append_fill_record(
                &snapshot,
                &broker_request_id,
                trigger,
                Decision::Allow,
                None,
                fill_details(trigger, &batch),
            )
            .await;
        }
        match batch.next {
            Some(next) => after = Some(next),
            None => break,
        }
    }
    if examined != 0 {
        tracing::info!(
            event = "account_usernames_filled",
            brokerRequestId = broker_request_id.as_str(),
            configGeneration = snapshot.generation,
            trigger,
            examined,
            assigned,
            "filled in the usernames of people who follow their email and held none"
        );
    }
}

/// The audit facts of one batch that named somebody: every allocation.
fn fill_details(trigger: &str, batch: &AccountUsernameFillBatch) -> Value {
    json!({
        "trigger": trigger,
        "examined": batch.examined,
        "assigned": batch.assigned.iter().map(|name| json!({
            "principal": name.principal_id,
            "derivedAccountUsername": name.audit_details(),
        })).collect::<Vec<_>>(),
    })
}

/// The names are committed (or the failure is final for this attempt), so a
/// failed append is logged.
async fn append_fill_record(
    snapshot: &RuntimeSnapshot,
    broker_request_id: &str,
    trigger: &str,
    decision: Decision,
    reason_code: Option<ReasonCode>,
    details: Value,
) {
    let record = AuditRecord {
        caller_id: None,
        search_authorization: None,
        timestamp: Utc::now().to_rfc3339(),
        agent_request_id: trigger.to_string(),
        broker_request_id: broker_request_id.to_string(),
        config_generation: Some(snapshot.generation),
        policy_generation: Some(snapshot.runtime.policy_generation()),
        principal: "system".to_string(),
        principal_subject: None,
        groups: vec!["system".to_string()],
        service: "broker".to_string(),
        action: super::audit_actions::ACCOUNT_USERNAMES_ASSIGNED.to_string(),
        resource_scopes: ResourceScopes::new(),
        matched_grant: None,
        credential_mode: Some(None),
        credential_connection: None,
        decision,
        reason_code: reason_code.map(Into::into),
        upstream_status: None,
        upstream_duration_ms: None,
        object_ids: None,
        identity_source: None,
        source: SourceContext {
            listener: trigger.to_string(),
            remote: "process".to_string(),
            proxy_chain: vec![],
            agent_request_id_generated: None,
        },
        execution_context: None,
        audit_inputs: Vec::new(),
        provider_audit: Some(json!({ "accountUsernames": details })),
    };
    if let Err(error) = snapshot.runtime.append_audit_record(&record).await {
        tracing::error!(
            event = "account_username_fill_audit_append_failed",
            brokerRequestId = broker_request_id,
            reasonCode = ReasonCode::AuditUnavailable.as_str(),
            error = %error,
            "usernames were filled in but the audit record is unavailable"
        );
    }
}
