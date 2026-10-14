use super::common::*;
use super::identity_access::committed_identity_mutation;
use crate::state::AppState;
use agent_access_core::ManagedStoreError;
use axum::{
    Json,
    extract::{ConnectInfo, Path, State},
    http::{HeaderMap, HeaderValue, header::CACHE_CONTROL},
    response::{IntoResponse, Response},
};
use serde::Deserialize;
use serde_json::json;
use std::net::SocketAddr;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct TokenBody {
    token: String,
}

async fn execute(
    state: AppState,
    principal: String,
    remote: SocketAddr,
    headers: HeaderMap,
    action: &'static str,
    token: Option<String>,
) -> Response {
    let operation = match action {
        "inspect" => "admin.principals.identity_token.inspect",
        "set" => "admin.principals.identity_token.set",
        "remove" => "admin.principals.identity_token.remove",
        "reveal" => "admin.principals.identity_token.reveal",
        "generate" => "admin.principals.identity_token.generate",
        _ => unreachable!("known inventory operation"),
    };
    let context = match management_context(
        &state,
        remote,
        &headers,
        operation,
        if action == "inspect" {
            ManagementAccess::AdminRead
        } else {
            ManagementAccess::AdminWrite
        },
    )
    .await
    {
        Ok(c) => c,
        Err(r) => return *r,
    };
    let target = Some(json!({"principal":principal}));
    // Changes and reveal are audited before they run (reveal before plaintext
    // is decrypted), using only the principal target. The metadata inspect is
    // an unaudited read: only its failures are recorded.
    let preflight = !is_unaudited_read(operation);
    if preflight
        && let Err(r) = management_write_audit_preflight(&context, operation, target.clone()).await
    {
        return *r;
    }
    let key_ring = context.snapshot.runtime.credential_key_ring().cloned();
    if matches!(action, "set" | "generate" | "remove") {
        return committed_identity_mutation(state, context, operation, target, move |store| {
            let require_ring = || {
                key_ring.as_ref().ok_or_else(|| {
                    ManagedStoreError::EncryptionKeyMissing("identity token key ring".into())
                })
            };
            let metadata = match action {
                "set" => store.set_identity_token(
                    &principal,
                    token.as_deref().expect("set body"),
                    require_ring()?,
                )?,
                "generate" => store.set_identity_token(
                    &principal,
                    &uuid::Uuid::new_v4().to_string(),
                    require_ring()?,
                )?,
                "remove" => store.remove_identity_token(&principal)?,
                _ => unreachable!("inventory mutation"),
            };
            let completion = json!({"principal": principal,
                "after": {"configured": metadata.configured, "revision": metadata.revision}});
            Ok((json!(metadata), completion))
        })
        .await;
    }
    let result = management_token_store_call(&state, &context, move |store, _catalog| {
        let require_ring = || {
            key_ring.as_ref().ok_or_else(|| {
                ManagedStoreError::EncryptionKeyMissing("identity token key ring".into())
            })
        };
        match action {
            "inspect" => Ok(json!(store.identity_token_metadata(&principal)?)),
            "reveal" => {
                Ok(json!({"token":store.reveal_identity_token(&principal,require_ring()?)?}))
            }
            _ => unreachable!("known inventory operation"),
        }
    })
    .await;
    let mut response = match result {
        Ok(value) if preflight => {
            management_pre_audited_success_response(&context, operation, target, value)
        }
        Ok(value) => management_success_response(&context, operation, target, value).await,
        Err(error) => management_store_error_response(&context, operation, target, error)
            .await
            .into_response(),
    };
    response
        .headers_mut()
        .insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}
macro_rules! endpoint {
    ($name:ident,$action:literal) => {
        pub(crate) async fn $name(
            State(state): State<AppState>,
            Path(principal): Path<String>,
            ConnectInfo(remote): ConnectInfo<SocketAddr>,
            headers: HeaderMap,
        ) -> Response {
            execute(state, principal, remote, headers, $action, None).await
        }
    };
}
endpoint!(inspect, "inspect");
endpoint!(remove, "remove");
endpoint!(reveal, "reveal");
endpoint!(generate, "generate");
pub(crate) async fn set(
    State(state): State<AppState>,
    Path(principal): Path<String>,
    ConnectInfo(remote): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(body): Json<TokenBody>,
) -> Response {
    execute(state, principal, remote, headers, "set", Some(body.token)).await
}
