//! Administrator-owned, exact namespace/name bindings for managed humans.
use super::admin::deserialize_present;
use super::common::*;
use super::identity_access::{committed_identity_mutation, invalid_input, parse_body};
use super::policy::expected_version_query;
use crate::state::AppState;
use agent_access_core::{BrokerConfig, UsernameBindingRecord, UsernameBindingUpdate};
use axum::{
    body::Bytes,
    extract::{ConnectInfo, Path, RawQuery, State},
    http::HeaderMap,
    response::Response,
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::{
    collections::{BTreeMap, BTreeSet},
    net::SocketAddr,
};

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ConfiguredNamespace {
    namespace: String,
    credential_transports: BTreeSet<&'static str>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct BindingResponse {
    #[serde(flatten)]
    binding: UsernameBindingRecord,
    namespace_available: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct PrincipalIdentityBindingsResponse {
    bindings: Vec<BindingResponse>,
    configured_namespaces: Vec<ConfiguredNamespace>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CreateBody {
    namespace: String,
    username: String,
    #[serde(default)]
    read_only: bool,
}

/// A partial settings change; at least one setting is required.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PatchBody {
    #[serde(default, deserialize_with = "deserialize_present")]
    enabled: Option<bool>,
    #[serde(default, deserialize_with = "deserialize_present")]
    read_only: Option<bool>,
    expected_version: i64,
}

fn configured_namespaces(config: &BrokerConfig) -> Vec<ConfiguredNamespace> {
    let mut namespaces = BTreeMap::<String, BTreeSet<&'static str>>::new();
    for caller in config.identity.trusted_callers.values() {
        if let Some(namespace) = &caller.username_namespace {
            namespaces
                .entry(namespace.clone())
                .or_default()
                .insert(caller.credential_transport.as_str());
        }
    }
    namespaces
        .into_iter()
        .map(|(namespace, credential_transports)| ConfiguredNamespace {
            namespace,
            credential_transports,
        })
        .collect()
}

fn response(binding: UsernameBindingRecord, namespaces: &[ConfiguredNamespace]) -> BindingResponse {
    let namespace_available = namespaces
        .iter()
        .any(|entry| entry.namespace == binding.namespace);
    BindingResponse {
        binding,
        namespace_available,
    }
}

pub(crate) async fn list(
    State(state): State<AppState>,
    Path(principal): Path<String>,
    ConnectInfo(remote): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> Response {
    let operation = "admin.principals.identity_bindings.list";
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
    let namespaces = configured_namespaces(context.snapshot.runtime.config());
    match management_store_call(&context, move |store| {
        store.list_username_bindings(&principal)
    })
    .await
    {
        Ok(bindings) => {
            let bindings = bindings
                .into_iter()
                .map(|binding| response(binding, &namespaces))
                .collect();
            management_success_response(
                &context,
                operation,
                target,
                PrincipalIdentityBindingsResponse {
                    bindings,
                    configured_namespaces: namespaces,
                },
            )
            .await
        }
        Err(error) => management_store_error_response(&context, operation, target, error).await,
    }
}

pub(crate) async fn create(
    State(state): State<AppState>,
    Path(principal): Path<String>,
    ConnectInfo(remote): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let operation = "admin.principals.identity_bindings.create";
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
    let body: CreateBody = match parse_body(&body) {
        Some(body) => body,
        None => {
            return invalid_input(
                &context,
                operation,
                target,
                "request body requires namespace and username, with an optional boolean readOnly",
            )
            .await;
        }
    };
    let namespaces = configured_namespaces(context.snapshot.runtime.config());
    if !namespaces
        .iter()
        .any(|entry| entry.namespace == body.namespace)
    {
        return invalid_input(
            &context,
            operation,
            target,
            "namespace is not currently configured",
        )
        .await;
    }
    if !agent_access_core::is_valid_identity_username(&body.username) {
        return invalid_input(
            &context,
            operation,
            target,
            "username must contain 1 to 128 ASCII letters, digits, or ._@+-",
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
        let binding = store.create_username_binding(
            &principal,
            &body.namespace,
            &body.username,
            body.read_only,
            &actor,
        )?;
        let completion = json!({"principal": binding.principal_id, "bindingId": binding.binding_id,
            "namespace": binding.namespace, "before": null, "after": settings(&binding)});
        Ok((json!(response(binding, &namespaces)), completion))
    })
    .await
}

/// The binding's audited settings: never its username.
fn settings(binding: &UsernameBindingRecord) -> serde_json::Value {
    json!({"enabled": binding.enabled, "readOnly": binding.read_only, "version": binding.version})
}

pub(crate) async fn patch(
    State(state): State<AppState>,
    Path((principal, binding)): Path<(String, String)>,
    ConnectInfo(remote): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let operation = "admin.principals.identity_bindings.patch";
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
    let target = Some(json!({"principal": principal, "bindingId": binding}));
    let body: PatchBody = match parse_body(&body) {
        Some(body) => body,
        None => {
            return invalid_input(
                &context,
                operation,
                target,
                "request body requires boolean enabled or readOnly and a positive expectedVersion",
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
    if body.expected_version < 1 {
        return invalid_input(
            &context,
            operation,
            target,
            "expectedVersion must be a positive integer",
        )
        .await;
    }
    let namespaces = configured_namespaces(context.snapshot.runtime.config());
    if let Err(response) =
        management_write_audit_preflight(&context, operation, target.clone()).await
    {
        return *response;
    }
    let actor = context.identity.principal.clone();
    committed_identity_mutation(state, context, operation, target, move |store| {
        let update = UsernameBindingUpdate { enabled: body.enabled, read_only: body.read_only };
        // The store reads both states inside its transaction; a no-op keeps the version.
        let (before, after) = store.update_username_binding(&principal, &binding, update, body.expected_version, &actor)?;
        let completion = json!({"principal": after.principal_id, "bindingId": after.binding_id, "namespace": after.namespace,
            "before": settings(&before), "after": settings(&after)});
        Ok((json!(response(after, &namespaces)), completion))
    }).await
}

pub(crate) async fn delete(
    State(state): State<AppState>,
    Path((principal, binding)): Path<(String, String)>,
    ConnectInfo(remote): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    RawQuery(query): RawQuery,
) -> Response {
    let operation = "admin.principals.identity_bindings.delete";
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
    let target = Some(json!({"principal": principal, "bindingId": binding}));
    let expected_version = match expected_version_query(query.as_deref()).and_then(|version| {
        version
            .filter(|version| *version > 0)
            .ok_or_else(|| "a positive expectedVersion is required".to_owned())
    }) {
        Ok(version) => version,
        Err(_) => {
            return invalid_input(
                &context,
                operation,
                target,
                "query requires exactly one positive expectedVersion",
            )
            .await;
        }
    };
    if let Err(response) =
        management_write_audit_preflight(&context, operation, target.clone()).await
    {
        return *response;
    }
    committed_identity_mutation(state, context, operation, target, move |store| {
        let binding = store.delete_username_binding(&principal, &binding, expected_version)?;
        let completion = json!({"principal": binding.principal_id, "bindingId": binding.binding_id,
            "namespace": binding.namespace, "before": settings(&binding), "after": null});
        Ok((json!({"deleted": true}), completion))
    })
    .await
}
