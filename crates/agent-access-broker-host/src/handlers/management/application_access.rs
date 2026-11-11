//! A person's access for registered applications: the consent page's
//! request and decision, the person's own list, and per-principal
//! administration. None of the personal routes is gated by self-service.
use super::admin::deserialize_present;
use super::common::*;
use super::identity_access::{committed_identity_mutation, invalid_input, parse_body};
use super::policy::expected_version_query;
use crate::handlers::applications::application_redirect;
use crate::state::AppState;
use agent_access_core::{
    ApplicationAccessRecord, ApplicationAccessUpdate, ApplicationConnectLevel, ManagedStoreError,
    RegisteredApplications,
};
use agent_access_provider::ReasonCode;
use axum::{
    body::Bytes,
    extract::{ConnectInfo, Path, RawQuery, State},
    http::{HeaderMap, StatusCode},
    response::Response,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::net::SocketAddr;

/// An access with its application's current registration.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct AccessResponse {
    #[serde(flatten)]
    access: ApplicationAccessRecord,
    application_name: Option<String>,
    application_available: bool,
    connect: Option<ApplicationConnectLevel>,
    effective_read_only: bool,
}

fn response(
    access: ApplicationAccessRecord,
    applications: &RegisteredApplications,
) -> AccessResponse {
    let application = applications.get(&access.application_id);
    let connect = application.map(|application| application.connect());
    AccessResponse {
        application_name: application.map(|application| application.display_name().to_string()),
        application_available: application.is_some(),
        effective_read_only: access.read_only || connect == Some(ApplicationConnectLevel::ReadOnly),
        connect,
        access,
    }
}

/// The audited settings of an access.
fn settings(access: &ApplicationAccessRecord) -> Value {
    json!({"enabled": access.enabled, "readOnly": access.read_only, "version": access.version})
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct DecisionBody {
    decision: ConsentDecision,
}

#[derive(Deserialize, Serialize, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum ConsentDecision {
    Approve,
    Cancel,
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

/// The context of a consent route: a signed-in browser session. Bearer
/// tokens cannot consent.
async fn consent_context(
    state: &AppState,
    remote: SocketAddr,
    headers: &HeaderMap,
    operation: &str,
) -> Result<ManagementContext, Box<Response>> {
    let context =
        management_context(state, remote, headers, operation, ManagementAccess::Account).await?;
    if context.browser_session.is_none() {
        return Err(Box::new(
            management_context_error_response(
                &context,
                StatusCode::FORBIDDEN,
                operation,
                ReasonCode::ManagementDenied,
                "application authorization requires a signed-in browser session",
                None,
            )
            .await,
        ));
    }
    Ok(context)
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

pub(crate) async fn authorization_inspect(
    State(state): State<AppState>,
    Path(request): Path<String>,
    ConnectInfo(remote): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> Response {
    let operation = "applications.authorizations.inspect";
    let context = match consent_context(&state, remote, &headers, operation).await {
        Ok(context) => context,
        Err(response) => return *response,
    };
    let Some(hasher) = context.snapshot.runtime.broker_token_hasher().cloned() else {
        return hasher_unavailable(&context, operation).await;
    };
    let applications = context.snapshot.runtime.applications().clone();
    let principal = context.identity.principal.clone();
    let read = management_store_call(&context, move |store| {
        let pending = store.application_authorization_request(&hasher, &request)?;
        // A request is valid only while its application is registered with
        // the request's exact redirect URI.
        let application = applications
            .get(&pending.application_id)
            .filter(|application| {
                application.accepts_redirect_uri(&pending.parameters.redirect_uri)
            })
            .ok_or(ManagedStoreError::ApplicationAuthorizationInvalid)?;
        let connect = application.connect();
        let denial = store.application_connect_denial(
            &principal,
            application.id(),
            connect != ApplicationConnectLevel::None,
        )?;
        let narrowed = store
            .list_application_access(&principal)?
            .into_iter()
            .any(|access| access.application_id == pending.application_id && access.read_only);
        Ok(json!({
            "applicationId": application.id(),
            "applicationName": application.display_name(),
            "connect": connect,
            "readOnly": narrowed || connect == ApplicationConnectLevel::ReadOnly,
            "canConnect": denial.is_none(),
            "denialReason": denial,
            "expiresAt": pending.expires_at,
        }))
    })
    .await;
    match read {
        Ok(result) => {
            let target = Some(json!({"applicationId": result["applicationId"]}));
            management_success_response(&context, operation, target, result).await
        }
        Err(error) => management_store_error_response(&context, operation, None, error).await,
    }
}

pub(crate) async fn authorization_decide(
    State(state): State<AppState>,
    Path(request): Path<String>,
    ConnectInfo(remote): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let operation = "applications.authorizations.decide";
    let context = match consent_context(&state, remote, &headers, operation).await {
        Ok(context) => context,
        Err(response) => return *response,
    };
    let Some(DecisionBody { decision }) = parse_body(&body) else {
        return invalid_input(
            &context,
            operation,
            None,
            "request body requires decision: approve or cancel",
        )
        .await;
    };
    let Some(hasher) = context.snapshot.runtime.broker_token_hasher().cloned() else {
        return hasher_unavailable(&context, operation).await;
    };
    let target = Some(json!({"decision": decision}));
    if let Err(response) =
        management_write_audit_preflight(&context, operation, target.clone()).await
    {
        return *response;
    }
    // The reload fence keeps these registrations current for the decision,
    // which the store checks the request's application and redirect URI
    // against before it approves or returns anything.
    let applications = context.snapshot.runtime.applications().clone();
    let principal = context.identity.principal.clone();
    committed_identity_mutation(state, context, operation, target, move |store| {
        let decided = store.decide_application_authorization(
            &hasher,
            &request,
            &principal,
            &|application_id| applications.registration(application_id),
            decision == ConsentDecision::Approve,
        )?;
        let parameters = &decided.parameters;
        let outcome = match &decided.code {
            Some(code) => [
                ("code", code.as_str()),
                ("state", parameters.state.as_str()),
            ],
            None => [
                ("error", "access_denied"),
                ("state", parameters.state.as_str()),
            ],
        };
        let redirect_to = application_redirect(&parameters.redirect_uri, &outcome)
            .ok_or(ManagedStoreError::ApplicationAuthorizationInvalid)?;
        let completion = json!({
            "principal": principal,
            "applicationId": decided.application_id,
            "decision": decision,
            "accessId": decided.access.as_ref().map(|access| access.access_id.as_str()),
            "revokedTokens": decided.revoked_tokens,
        });
        Ok((
            json!({"decision": decision, "redirectTo": redirect_to}),
            completion,
        ))
    })
    .await
}

pub(crate) async fn list_own(
    State(state): State<AppState>,
    ConnectInfo(remote): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> Response {
    let operation = "applications.access.list";
    let context = match management_context(
        &state,
        remote,
        &headers,
        operation,
        ManagementAccess::Account,
    )
    .await
    {
        Ok(context) => context,
        Err(response) => return *response,
    };
    let principal = context.identity.principal.clone();
    list(&context, operation, None, principal, true).await
}

/// A principal's application access. The person's own list holds only what
/// is connected; an administrator also sees an access kept, disconnected,
/// for its restriction.
async fn list(
    context: &ManagementContext,
    operation: &str,
    target: Option<Value>,
    principal: String,
    connected_only: bool,
) -> Response {
    let applications = context.snapshot.runtime.applications().clone();
    match management_store_call(context, move |store| {
        store.list_application_access(&principal)
    })
    .await
    {
        Ok(records) => {
            let access = records
                .into_iter()
                .filter(|access| access.connected || !connected_only)
                .map(|access| response(access, &applications))
                .collect::<Vec<_>>();
            management_success_response(context, operation, target, json!({"access": access})).await
        }
        Err(error) => management_store_error_response(context, operation, target, error).await,
    }
}

pub(crate) async fn remove_own(
    State(state): State<AppState>,
    Path(access): Path<String>,
    ConnectInfo(remote): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> Response {
    let operation = "applications.access.remove";
    let context = match management_context(
        &state,
        remote,
        &headers,
        operation,
        ManagementAccess::Account,
    )
    .await
    {
        Ok(context) => context,
        Err(response) => return *response,
    };
    let principal = context.identity.principal.clone();
    let target = Some(json!({"principal": principal, "accessId": access}));
    if let Err(response) =
        management_write_audit_preflight(&context, operation, target.clone()).await
    {
        return *response;
    }
    committed_identity_mutation(state, context, operation, target, move |store| {
        // The person ends their consent. A row an administrator restricted
        // stays, disconnected, so removing it cannot lift the restriction.
        let (removed, row_removed) =
            store.disconnect_application_access(&principal, &access, &principal)?;
        let after = (!row_removed).then(|| settings(&removed));
        let completion = json!({"principal": removed.principal_id, "accessId": removed.access_id,
            "applicationId": removed.application_id, "before": settings(&removed), "after": after,
            "connected": false});
        Ok((json!({"removed": true}), completion))
    })
    .await
}

pub(crate) async fn admin_list(
    State(state): State<AppState>,
    Path(principal): Path<String>,
    ConnectInfo(remote): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> Response {
    let operation = "admin.principals.application_access.list";
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
    list(&context, operation, target, principal, false).await
}

pub(crate) async fn admin_patch(
    State(state): State<AppState>,
    Path((principal, access)): Path<(String, String)>,
    ConnectInfo(remote): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let operation = "admin.principals.application_access.patch";
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
    let target = Some(json!({"principal": principal, "accessId": access}));
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
    if let Err(response) =
        management_write_audit_preflight(&context, operation, target.clone()).await
    {
        return *response;
    }
    let applications = context.snapshot.runtime.applications().clone();
    let actor = context.identity.principal.clone();
    committed_identity_mutation(state, context, operation, target, move |store| {
        let update = ApplicationAccessUpdate {
            enabled: body.enabled,
            read_only: body.read_only,
        };
        // The store reads both states in its transaction; a no-op keeps the version.
        let (before, after) = store.update_application_access(
            &principal,
            &access,
            update,
            body.expected_version,
            &actor,
        )?;
        let completion = json!({"principal": after.principal_id, "accessId": after.access_id,
            "applicationId": after.application_id, "before": settings(&before),
            "after": settings(&after)});
        Ok((json!(response(after, &applications)), completion))
    })
    .await
}

pub(crate) async fn admin_delete(
    State(state): State<AppState>,
    Path((principal, access)): Path<(String, String)>,
    ConnectInfo(remote): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    RawQuery(query): RawQuery,
) -> Response {
    let operation = "admin.principals.application_access.delete";
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
    let target = Some(json!({"principal": principal, "accessId": access}));
    let Some(expected_version) = expected_version_query(query.as_deref())
        .ok()
        .flatten()
        .filter(|version| *version > 0)
    else {
        return invalid_input(
            &context,
            operation,
            target,
            "query requires exactly one positive expectedVersion",
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
        let removed =
            store.remove_application_access(&principal, &access, expected_version, &actor)?;
        let completion = json!({"principal": removed.principal_id, "accessId": removed.access_id,
            "applicationId": removed.application_id, "before": settings(&removed), "after": null});
        Ok((json!({"removed": true}), completion))
    })
    .await
}
