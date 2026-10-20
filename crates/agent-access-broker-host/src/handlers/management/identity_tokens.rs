use super::admin::deserialize_present;
use super::common::*;
use super::identity_access::{committed_identity_mutation, invalid_input, parse_body};
use crate::state::AppState;
use agent_access_core::{IdentityTokenMetadata, IdentityTokenSettingsUpdate, ManagedStoreError};
use axum::{
    Json,
    body::Bytes,
    extract::{ConnectInfo, Path, State},
    http::{HeaderMap, HeaderValue, header::CACHE_CONTROL},
    response::{IntoResponse, Response},
};
use serde::Deserialize;
use serde_json::{Value, json};
use std::net::SocketAddr;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct TokenBody {
    token: String,
}

/// A partial change to the identity token's path settings; at least one
/// setting is required.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SettingsBody {
    #[serde(default, deserialize_with = "deserialize_present")]
    enabled: Option<bool>,
    #[serde(default, deserialize_with = "deserialize_present")]
    read_only: Option<bool>,
    expected_revision: i64,
}

/// The inventory's audited path settings: never the secret or fingerprint.
fn settings(metadata: &IdentityTokenMetadata) -> Value {
    json!({"enabled": metadata.enabled, "readOnly": metadata.read_only, "revision": metadata.revision})
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
                "after": {"configured": metadata.configured, "enabled": metadata.enabled,
                    "readOnly": metadata.read_only, "revision": metadata.revision}});
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

/// Changes the identity token's Enabled and Read-only settings. The secret is
/// untouched; a change advances the inventory revision, which ends existing
/// fingerprint sessions, and a no-op writes nothing.
pub(crate) async fn patch(
    State(state): State<AppState>,
    Path(principal): Path<String>,
    ConnectInfo(remote): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let operation = "admin.principals.identity_token.patch";
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
    let body: SettingsBody = match parse_body(&body) {
        Some(body) => body,
        None => {
            return invalid_input(
                &context,
                operation,
                target,
                "request body requires boolean enabled or readOnly and a positive expectedRevision",
            )
            .await;
        }
    };
    if body.enabled.is_none() && body.read_only.is_none() {
        return invalid_input(
            &context,
            operation,
            target,
            "request body requires at least one of enabled or readOnly",
        )
        .await;
    }
    if body.expected_revision < 1 {
        return invalid_input(
            &context,
            operation,
            target,
            "expectedRevision must be a positive integer",
        )
        .await;
    }
    if let Err(response) =
        management_write_audit_preflight(&context, operation, target.clone()).await
    {
        return *response;
    }
    committed_identity_mutation(state, context, operation, target, move |store| {
        let update = IdentityTokenSettingsUpdate {
            enabled: body.enabled,
            read_only: body.read_only,
        };
        // The store reads both states inside its transaction.
        let (before, after) =
            store.update_identity_token_settings(&principal, update, body.expected_revision)?;
        let completion = json!({"principal": after.principal_id,
            "before": settings(&before), "after": settings(&after)});
        Ok((json!(after), completion))
    })
    .await
}
