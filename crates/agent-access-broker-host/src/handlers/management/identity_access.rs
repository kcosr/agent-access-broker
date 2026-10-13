//! The shared gate for trusted username and fingerprint identities.
use super::common::*;
use crate::state::AppState;
use agent_access_core::{ManagedStore, ManagedStoreError};
use agent_access_provider::ReasonCode;
use axum::{
    body::Bytes,
    extract::{ConnectInfo, Path, State},
    http::{HeaderMap, StatusCode},
    response::Response,
};
use serde::{Deserialize, de::DeserializeOwned};
use serde_json::{Value, json};
use std::{net::SocketAddr, sync::Arc};

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PatchBody {
    paused: bool,
    expected_version: i64,
}

pub(crate) async fn get(
    State(state): State<AppState>,
    Path(principal): Path<String>,
    ConnectInfo(remote): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> Response {
    let operation = "admin.principals.identity_access.inspect";
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
    let target = Some(json!({"principal": principal}));
    match management_store_call(&context, move |store| store.identity_access(&principal)).await {
        Ok(record) => management_success_response(&context, operation, target, record).await,
        Err(error) => management_store_error_response(&context, operation, target, error).await,
    }
}

pub(crate) async fn patch(
    State(state): State<AppState>,
    Path(principal): Path<String>,
    ConnectInfo(remote): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let operation = "admin.principals.identity_access.patch";
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
    let target = Some(json!({"principal": principal}));
    let body: PatchBody = match parse_body(&body) {
        Some(body) => body,
        None => {
            return invalid_input(
                &context,
                operation,
                target,
                "request body requires paused and a positive expectedVersion",
            )
            .await;
        }
    };
    if body.expected_version < 1 {
        return invalid_input(
            &context,
            operation,
            target,
            "expectedVersion must be a positive integer",
        )
        .await;
    }
    if let Err(response) =
        management_write_audit_preflight(&context, operation, target.clone()).await
    {
        return *response;
    }
    let actor = context.identity.principal.clone();
    committed_identity_mutation(state, context, operation, target, move |store| {
        let after = store.set_identity_access_paused(
            &principal,
            body.paused,
            body.expected_version,
            &actor,
        )?;
        // The version-checked transition determines the exact previous state.
        let previous_paused = if after.version == body.expected_version {
            after.paused
        } else {
            !after.paused
        };
        let completion = json!({"principal": after.principal_id,
            "before": {"paused": previous_paused, "version": body.expected_version},
            "after": {"paused": after.paused, "version": after.version}});
        Ok((json!(after), completion))
    })
    .await
}

/// Keep mandatory-preflight writes and their safe completion audit owned after
/// the HTTP response waiter disappears. Completion failure cannot undo a commit.
pub(super) async fn committed_identity_mutation<F>(
    state: AppState,
    context: ManagementContext,
    operation: &'static str,
    target: Option<Value>,
    mutate: F,
) -> Response
where
    F: FnOnce(ManagedStore) -> Result<(Value, Value), ManagedStoreError> + Send + 'static,
{
    let context = Arc::new(context);
    let owner_context = context.clone();
    let owner_target = target.clone();
    let owner = tokio::spawn(async move {
        let context = owner_context;
        match management_token_store_call(&state, &context, move |store, _| mutate(store)).await {
            Ok((result, completion)) => {
                management_committed_write_audit_completion(&context, operation, Some(completion))
                    .await;
                management_pre_audited_success_response(&context, operation, owner_target, result)
            }
            Err(error) => {
                management_store_error_response(&context, operation, owner_target, error).await
            }
        }
    });
    match owner.await {
        Ok(response) => response,
        Err(_) => {
            management_store_error_response(
                &context,
                operation,
                target,
                ManagedStoreError::Unavailable("identity mutation owner failed".into()),
            )
            .await
        }
    }
}

pub(super) fn parse_body<T: DeserializeOwned>(body: &[u8]) -> Option<T> {
    // Check the object shape without losing duplicate-field rejection in serde.
    serde_json::from_slice::<Value>(body)
        .ok()
        .filter(Value::is_object)?;
    serde_json::from_slice(body).ok()
}

pub(super) async fn invalid_input(
    context: &ManagementContext,
    operation: &str,
    target: Option<Value>,
    message: &str,
) -> Response {
    management_context_error_response(
        context,
        StatusCode::BAD_REQUEST,
        operation,
        ReasonCode::InputInvalid,
        message,
        target,
    )
    .await
}
