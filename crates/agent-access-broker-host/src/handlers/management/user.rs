use crate::handlers::management::common::{
    AgentTokenIssueBody, CredentialPutBody, ManagementAccess, ManagementAuditExtra,
    ManagementContext, agent_token_boundary_audit, agent_token_issue_scopes,
    agent_token_list_query, append_management_audit_with_phase, credential_input_schema_query,
    is_broker_user_manage_context, management_audit_unavailable_response, management_context,
    management_context_error_response, management_pre_audited_success_response,
    management_response, management_store_call, management_store_error_response,
    management_success_envelope, management_success_response, management_write_audit_preflight,
    self_agent_token_issue_expires_at,
};
use crate::handlers::management::connections;
use crate::handlers::management::credentials::{
    ConnectionCredentialRequest, CredentialAccess, connection_input_schema, connection_verify_body,
    delete_connection_credential, get_connection_credential, put_connection_credential,
    verify_connection_credential,
};
use crate::state::AppState;
use agent_access_core::SelfAgentTokenIssueRequest;
use agent_access_provider::ReasonCode;
use axum::Json;
use axum::body::Bytes;
use axum::extract::{ConnectInfo, Path, RawQuery, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use serde_json::{Value, json};
use std::collections::BTreeSet;
use std::net::SocketAddr;

pub(crate) async fn user_tokens_list(
    State(state): State<AppState>,
    RawQuery(raw_query): RawQuery,
    ConnectInfo(remote_addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let operation = "tokens.list";
    let context = match management_context(
        &state,
        remote_addr,
        &headers,
        operation,
        ManagementAccess::UserManageToken,
    )
    .await
    {
        Ok(context) => context,
        Err(response) => return *response,
    };
    let query = match agent_token_list_query(raw_query.as_deref()) {
        Ok(query) => query,
        Err(message) => {
            return management_context_error_response(
                &context,
                StatusCode::BAD_REQUEST,
                operation,
                ReasonCode::InputInvalid,
                &message,
                None,
            )
            .await;
        }
    };
    let principal = context.identity.principal.clone();
    match management_store_call(&context, move |store| {
        store.list_self_agent_tokens(&principal, query.include_revoked, query.include_expired)
    })
    .await
    {
        Ok(tokens) => management_success_response(&context, operation, None, json!(tokens)).await,
        Err(error) => management_store_error_response(&context, operation, None, error).await,
    }
}

pub(crate) async fn user_token_options(
    State(state): State<AppState>,
    ConnectInfo(remote_addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let operation = "tokens.options";
    let context = match management_context(
        &state,
        remote_addr,
        &headers,
        operation,
        ManagementAccess::UserManageToken,
    )
    .await
    {
        Ok(context) => context,
        Err(response) => return *response,
    };
    let options = context
        .snapshot
        .runtime
        .agent_token_options_for_identity(&context.identity);
    management_success_response(&context, operation, None, json!(options)).await
}

pub(crate) async fn user_token_issue(
    State(state): State<AppState>,
    ConnectInfo(remote_addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(raw_body): Json<Value>,
) -> impl IntoResponse {
    let operation = "tokens.issue";
    let context = match management_context(
        &state,
        remote_addr,
        &headers,
        operation,
        ManagementAccess::UserManageToken,
    )
    .await
    {
        Ok(context) => context,
        Err(response) => return *response,
    };
    let body = match serde_json::from_value::<AgentTokenIssueBody>(raw_body) {
        Ok(body) => body,
        Err(error) => {
            return management_context_error_response(
                &context,
                StatusCode::BAD_REQUEST,
                operation,
                ReasonCode::InputInvalid,
                &format!("token issue body is invalid: {error}"),
                None,
            )
            .await;
        }
    };
    if body.name.trim().is_empty() {
        return management_context_error_response(
            &context,
            StatusCode::BAD_REQUEST,
            operation,
            ReasonCode::InputInvalid,
            "token name must not be empty",
            None,
        )
        .await;
    }
    let Some(hasher) = context.snapshot.runtime.broker_token_hasher().cloned() else {
        return management_context_error_response(
            &context,
            StatusCode::SERVICE_UNAVAILABLE,
            operation,
            ReasonCode::EncryptionKeyMissing,
            "broker token hash key is not configured",
            None,
        )
        .await;
    };
    let options = context
        .snapshot
        .runtime
        .agent_token_options_for_identity(&context.identity);
    if options.services.is_empty() {
        return management_context_error_response(
            &context,
            StatusCode::FORBIDDEN,
            operation,
            ReasonCode::ServiceActionDenied,
            "agent token issuance requires at least one effective invocation grant",
            Some(json!({
                "principalId": context.identity.principal.clone(),
                "tokenClass": "agent_invoke",
            })),
        )
        .await;
    }
    let scopes = match agent_token_issue_scopes(
        &context.snapshot.runtime,
        body.allowed_services.clone(),
        body.allowed_execution_contexts.clone(),
        body.service_restrictions.clone(),
        &options,
    ) {
        Ok(scopes) => scopes,
        Err(message) => {
            return management_context_error_response(
                &context,
                StatusCode::BAD_REQUEST,
                operation,
                ReasonCode::InputInvalid,
                &message,
                None,
            )
            .await;
        }
    };
    let expires_at =
        match self_agent_token_issue_expires_at(context.snapshot.runtime.config(), &body) {
            Ok(expires_at) => expires_at,
            Err(message) => {
                return management_context_error_response(
                    &context,
                    StatusCode::BAD_REQUEST,
                    operation,
                    ReasonCode::InputInvalid,
                    &message,
                    None,
                )
                .await;
            }
        };
    let principal = context.identity.principal.clone();
    let boundary = agent_token_boundary_audit(&scopes);
    let target = Some(json!({
        "principalId": principal,
        "tokenClass": "agent_invoke",
        "name": body.name.clone(),
        "boundary": boundary,
        "expiresAt": expires_at.clone(),
        "never": body.never,
    }));
    if let Err(response) =
        management_write_audit_preflight(&context, operation, target.clone()).await
    {
        return *response;
    }
    let actor = context.identity.principal.clone();
    let principal_for_store = context.identity.principal.clone();
    match super::common::management_token_store_call(&state, &context, move |store, catalog| {
        store.issue_self_agent_token_with_catalog(
            &hasher,
            SelfAgentTokenIssueRequest {
                principal_id: principal_for_store,
                name: body.name,
                scopes,
                expires_at,
                created_by: actor,
            },
            catalog.as_ref(),
        )
    })
    .await
    {
        Ok(token) => {
            let success_target = Some(json!({
                "principalId": token.record.principal_id.clone(),
                "tokenClass": "agent_invoke",
                "tokenId": token.record.token_id.clone(),
                "name": token.record.name.clone(),
                "expiresAt": token.record.expires_at.clone(),
                "boundary": agent_token_boundary_audit(&token.record.scopes),
            }));
            let audit_envelope = management_success_envelope(
                &context,
                operation,
                success_target.clone(),
                Value::Null,
            );
            if let Err(error) = append_management_audit_with_phase(
                &context.snapshot,
                &context.request_id,
                &context.broker_request_id,
                &context.identity,
                &context.source,
                &audit_envelope,
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
                management_success_envelope(&context, operation, success_target, json!(token)),
            )
        }
        Err(error) => management_store_error_response(&context, operation, target, error).await,
    }
}

pub(crate) async fn user_token_get(
    State(state): State<AppState>,
    Path(token_id): Path<String>,
    ConnectInfo(remote_addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let operation = "tokens.inspect";
    let context = match management_context(
        &state,
        remote_addr,
        &headers,
        operation,
        ManagementAccess::UserManageToken,
    )
    .await
    {
        Ok(context) => context,
        Err(response) => return *response,
    };
    let target = Some(json!({
        "principalId": context.identity.principal.clone(),
        "tokenClass": "agent_invoke",
        "tokenId": token_id
    }));
    let principal = context.identity.principal.clone();
    let token_id_for_store = token_id.clone();
    match management_store_call(&context, move |store| {
        store.self_agent_token(&principal, &token_id_for_store)
    })
    .await
    {
        Ok(token) => management_success_response(&context, operation, target, json!(token)).await,
        Err(agent_access_core::ManagedStoreError::BrokerTokenNotFound) => {
            management_context_error_response(
                &context,
                StatusCode::NOT_FOUND,
                operation,
                ReasonCode::CredentialNotFound,
                "token was not found",
                target,
            )
            .await
        }
        Err(error) => management_store_error_response(&context, operation, target, error).await,
    }
}

pub(crate) async fn user_token_revoke(
    State(state): State<AppState>,
    Path(token_id): Path<String>,
    ConnectInfo(remote_addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let operation = "tokens.revoke";
    let context = match management_context(
        &state,
        remote_addr,
        &headers,
        operation,
        ManagementAccess::UserManageToken,
    )
    .await
    {
        Ok(context) => context,
        Err(response) => return *response,
    };
    let target = Some(json!({
        "principalId": context.identity.principal.clone(),
        "tokenClass": "agent_invoke",
        "tokenId": token_id
    }));
    if let Err(response) =
        management_write_audit_preflight(&context, operation, target.clone()).await
    {
        return *response;
    }
    let principal = context.identity.principal.clone();
    let token_id_for_store = token_id.clone();
    let actor = context.identity.principal.clone();
    match management_store_call(&context, move |store| {
        store.revoke_self_agent_token(&principal, &token_id_for_store, &actor)
    })
    .await
    {
        Ok(token) => {
            management_pre_audited_success_response(&context, operation, target, json!(token))
        }
        Err(agent_access_core::ManagedStoreError::BrokerTokenNotFound) => {
            management_context_error_response(
                &context,
                StatusCode::NOT_FOUND,
                operation,
                ReasonCode::CredentialNotFound,
                "token was not found",
                target,
            )
            .await
        }
        Err(error) => management_store_error_response(&context, operation, target, error).await,
    }
}

pub(crate) async fn user_token_pause(
    State(state): State<AppState>,
    Path(token_id): Path<String>,
    ConnectInfo(remote_addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let operation = "tokens.pause";
    let context = match management_context(
        &state,
        remote_addr,
        &headers,
        operation,
        ManagementAccess::UserManageToken,
    )
    .await
    {
        Ok(context) => context,
        Err(response) => return *response,
    };
    let target = Some(json!({
        "principalId": context.identity.principal.clone(),
        "tokenClass": "agent_invoke",
        "tokenId": token_id,
        "resultingState": "Paused"
    }));
    if let Err(response) =
        management_write_audit_preflight(&context, operation, target.clone()).await
    {
        return *response;
    }
    let principal = context.identity.principal.clone();
    let token_id_for_store = token_id.clone();
    let actor = context.identity.principal.clone();
    match management_store_call(&context, move |store| {
        store.pause_principal_agent_token(
            &principal,
            &token_id_for_store,
            &actor,
            agent_access_core::AgentTokenManagementPurpose::Personal,
        )
    })
    .await
    {
        Ok(token) => {
            management_pre_audited_success_response(&context, operation, target, json!(token))
        }
        Err(agent_access_core::ManagedStoreError::BrokerTokenNotFound) => {
            management_context_error_response(
                &context,
                StatusCode::NOT_FOUND,
                operation,
                ReasonCode::CredentialNotFound,
                "token was not found",
                target,
            )
            .await
        }
        Err(error) => management_store_error_response(&context, operation, target, error).await,
    }
}

pub(crate) async fn user_token_resume(
    State(state): State<AppState>,
    Path(token_id): Path<String>,
    ConnectInfo(remote_addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let operation = "tokens.resume";
    let context = match management_context(
        &state,
        remote_addr,
        &headers,
        operation,
        ManagementAccess::UserManageToken,
    )
    .await
    {
        Ok(context) => context,
        Err(response) => return *response,
    };
    let target = Some(json!({
        "principalId": context.identity.principal.clone(),
        "tokenClass": "agent_invoke",
        "tokenId": token_id,
        "resultingState": "Active"
    }));
    if let Err(response) =
        management_write_audit_preflight(&context, operation, target.clone()).await
    {
        return *response;
    }
    let principal = context.identity.principal.clone();
    let token_id_for_store = token_id.clone();
    let actor = context.identity.principal.clone();
    match super::common::management_token_store_call(&state, &context, move |store, catalog| {
        store.resume_principal_agent_token_with_catalog(
            &principal,
            &token_id_for_store,
            &actor,
            catalog.as_ref(),
            agent_access_core::AgentTokenManagementPurpose::Personal,
        )
    })
    .await
    {
        Ok(token) => {
            management_pre_audited_success_response(&context, operation, target, json!(token))
        }
        Err(agent_access_core::ManagedStoreError::BrokerTokenNotFound) => {
            management_context_error_response(
                &context,
                StatusCode::NOT_FOUND,
                operation,
                ReasonCode::CredentialNotFound,
                "token was not found",
                target,
            )
            .await
        }
        Err(error) => management_store_error_response(&context, operation, target, error).await,
    }
}

/// How a personal caller is authorized for its own credentials: grants for
/// Broker-issued `user_manage` tokens and browser sessions, credential
/// rights for classless self-service identities.
fn personal_access(context: &ManagementContext) -> CredentialAccess {
    if is_broker_user_manage_context(context) {
        CredentialAccess::Owner
    } else {
        CredentialAccess::ClasslessOwner
    }
}

pub(crate) async fn user_credentials_list(
    State(state): State<AppState>,
    ConnectInfo(remote_addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let operation = "credentials.list";
    let context = match management_context(
        &state,
        remote_addr,
        &headers,
        operation,
        ManagementAccess::User,
    )
    .await
    {
        Ok(context) => context,
        Err(response) => return *response,
    };
    let runtime = &context.snapshot.runtime;
    let kind = context.identity.principal_kind;
    let access = personal_access(&context);
    let active = connections::active_token_rows(runtime, kind);
    let principal = context.identity.principal.clone();
    // Classless callers read what their read_metadata rights cover: the
    // active row through `(connection, default)` and a retained row through
    // its own stored service and name.
    let token_connections = active
        .iter()
        .map(|(connection, _)| connection.clone())
        .collect::<Vec<_>>();
    let stored = match management_store_call(&context, move |store| {
        let rows = store.list_credentials(Some(&principal))?;
        if access != CredentialAccess::ClasslessOwner {
            return Ok((rows, None));
        }
        let right = "credentials:self:read_metadata";
        let mut readable_connections = BTreeSet::new();
        for connection in token_connections {
            if store.has_credential_right(
                &principal,
                right,
                &connection,
                agent_access_core::CONNECTION_CREDENTIAL_NAME,
            )? {
                readable_connections.insert(connection);
            }
        }
        let mut readable_rows = Vec::new();
        for row in rows {
            if store.has_credential_right(&principal, right, &row.service, &row.name)? {
                readable_rows.push(row);
            }
        }
        Ok((readable_rows, Some(readable_connections)))
    })
    .await
    {
        Ok(stored) => stored,
        Err(error) => {
            return management_store_error_response(&context, operation, None, error).await;
        }
    };
    let (rows, readable_connections) = stored;
    let result = connections::credential_list(
        runtime,
        &context.identity,
        rows,
        readable_connections.as_ref(),
    );
    management_success_response(&context, operation, None, json!(result)).await
}

pub(crate) async fn user_credential_targets(
    State(state): State<AppState>,
    ConnectInfo(remote_addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let operation = "credentials.targets";
    let context = match management_context(
        &state,
        remote_addr,
        &headers,
        operation,
        ManagementAccess::User,
    )
    .await
    {
        Ok(context) => context,
        Err(response) => return *response,
    };
    let runtime = &context.snapshot.runtime;
    let kind = context.identity.principal_kind;
    let candidates = connections::connection_ids(runtime)
        .into_iter()
        .filter_map(|connection| {
            let entitled = connections::entitled_consumers(runtime, &context.identity, &connection);
            let target = connections::target(runtime, &connection, kind, &entitled)?;
            Some((target, !entitled.is_empty()))
        })
        .collect::<Vec<_>>();
    let targets = if personal_access(&context) == CredentialAccess::Owner {
        candidates
            .into_iter()
            .filter_map(|(target, entitled)| entitled.then_some(target))
            .collect::<Vec<_>>()
    } else {
        // Classless callers set up what their write rights cover.
        let principal = context.identity.principal.clone();
        match management_store_call(&context, move |store| {
            let mut allowed = Vec::new();
            for (target, _) in candidates {
                if store.has_credential_right(
                    &principal,
                    "credentials:self:write",
                    &target.connection,
                    agent_access_core::CONNECTION_CREDENTIAL_NAME,
                )? {
                    allowed.push(target);
                }
            }
            Ok(allowed)
        })
        .await
        {
            Ok(targets) => targets,
            Err(error) => {
                return management_store_error_response(&context, operation, None, error).await;
            }
        }
    };
    management_success_response(&context, operation, None, json!(targets)).await
}

async fn personal_context(
    state: &AppState,
    remote_addr: SocketAddr,
    headers: &HeaderMap,
    operation: &str,
) -> Result<ManagementContext, Box<axum::response::Response>> {
    management_context(
        state,
        remote_addr,
        headers,
        operation,
        ManagementAccess::User,
    )
    .await
}

fn personal_request(
    context: &ManagementContext,
    connection: String,
) -> ConnectionCredentialRequest {
    ConnectionCredentialRequest::new(
        context.identity.principal.clone(),
        connection,
        personal_access(context),
    )
}

pub(crate) async fn user_credentials_get(
    State(state): State<AppState>,
    Path(connection): Path<String>,
    ConnectInfo(remote_addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let operation = "credentials.inspect";
    let context = match personal_context(&state, remote_addr, &headers, operation).await {
        Ok(context) => context,
        Err(response) => return *response,
    };
    let request = personal_request(&context, connection);
    get_connection_credential(context, operation, request).await
}

pub(crate) async fn user_credentials_put(
    State(state): State<AppState>,
    Path(connection): Path<String>,
    ConnectInfo(remote_addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(body): Json<CredentialPutBody>,
) -> impl IntoResponse {
    let operation = "credentials.put";
    let context = match personal_context(&state, remote_addr, &headers, operation).await {
        Ok(context) => context,
        Err(response) => return *response,
    };
    let request = personal_request(&context, connection);
    put_connection_credential(state, context, operation, request, body).await
}

pub(crate) async fn user_credential_input_schema(
    State(state): State<AppState>,
    Path(connection): Path<String>,
    RawQuery(raw_query): RawQuery,
    ConnectInfo(remote_addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let operation = "credentials.input_schema";
    let context = match personal_context(&state, remote_addr, &headers, operation).await {
        Ok(context) => context,
        Err(response) => return *response,
    };
    let query = match credential_input_schema_query(raw_query.as_deref()) {
        Ok(query) => query,
        Err(message) => {
            let target = Some(connections::audit_target(
                &context.identity.principal,
                &connection,
            ));
            return management_context_error_response(
                &context,
                StatusCode::BAD_REQUEST,
                operation,
                ReasonCode::InputInvalid,
                &message,
                target,
            )
            .await;
        }
    };
    let request = personal_request(&context, connection);
    connection_input_schema(context, operation, request, query).await
}

pub(crate) async fn user_credentials_delete(
    State(state): State<AppState>,
    Path(connection): Path<String>,
    ConnectInfo(remote_addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let operation = "credentials.delete";
    let context = match personal_context(&state, remote_addr, &headers, operation).await {
        Ok(context) => context,
        Err(response) => return *response,
    };
    let request = personal_request(&context, connection);
    delete_connection_credential(context, operation, request).await
}

pub(crate) async fn user_credentials_verify(
    State(state): State<AppState>,
    Path(connection): Path<String>,
    ConnectInfo(remote_addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    body: Bytes,
) -> impl IntoResponse {
    let operation = "credentials.verify";
    let context = match personal_context(&state, remote_addr, &headers, operation).await {
        Ok(context) => context,
        Err(response) => return *response,
    };
    let body = match connection_verify_body(body) {
        Ok(body) => body,
        Err(message) => {
            let target = Some(connections::audit_target(
                &context.identity.principal,
                &connection,
            ));
            return management_context_error_response(
                &context,
                StatusCode::BAD_REQUEST,
                operation,
                ReasonCode::InputInvalid,
                &message,
                target,
            )
            .await;
        }
    };
    let request = personal_request(&context, connection);
    verify_connection_credential(context, operation, request, body).await
}

/// Deletes one of the caller's retained rows by its credential ID. The
/// active token of a connection is refused: it is deleted through its
/// connection.
pub(crate) async fn user_retained_credential_delete(
    State(state): State<AppState>,
    Path(credential_id): Path<String>,
    ConnectInfo(remote_addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let operation = "credentials.retained.delete";
    let context = match personal_context(&state, remote_addr, &headers, operation).await {
        Ok(context) => context,
        Err(response) => return *response,
    };
    let purpose = context.credential_purpose;
    let target = Some(json!({
        "principal": context.identity.principal.clone(),
        "credentialId": credential_id.clone(),
    }));
    if personal_access(&context) == CredentialAccess::ClasslessOwner {
        let principal = context.identity.principal.clone();
        let credential_id = credential_id.clone();
        if let Err(error) = management_store_call(&context, move |store| {
            let credential = store.credential_by_id(&credential_id)?;
            if credential.owner_principal != principal {
                return Err(agent_access_core::ManagedStoreError::CredentialNotFound);
            }
            store.require_credential_right(
                &principal,
                "credentials:self:delete",
                &credential.service,
                &credential.name,
            )
        })
        .await
        {
            return management_store_error_response(&context, operation, target, error).await;
        }
    }
    if let Err(response) =
        management_write_audit_preflight(&context, operation, target.clone()).await
    {
        return *response;
    }
    let active =
        connections::active_token_rows(&context.snapshot.runtime, context.identity.principal_kind);
    let principal = context.identity.principal.clone();
    match management_store_call(&context, move |store| {
        store.delete_retained_user_credential(&credential_id, &principal, &active, purpose)
    })
    .await
    {
        Ok(credential) => {
            management_pre_audited_success_response(&context, operation, target, json!(credential))
        }
        Err(error) => management_store_error_response(&context, operation, target, error).await,
    }
}
