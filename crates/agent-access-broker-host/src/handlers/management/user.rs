use crate::handlers::management::common::{
    AgentTokenIssueBody, CredentialPutBody, ManagementAccess, ManagementAuditExtra,
    agent_token_boundary_audit, agent_token_issue_scopes, agent_token_list_query,
    append_management_audit_with_phase, credential_input_schema_query, credential_targets,
    is_broker_user_manage_context, management_audit_unavailable_response, management_context,
    management_context_error_response, management_pre_audited_success_response,
    management_response, management_store_call, management_store_error_response,
    management_success_envelope, management_success_response, management_write_audit_preflight,
    self_agent_token_issue_expires_at, visible_per_user_services,
};
use crate::handlers::management::credentials::{
    PrincipalCredentialTarget, credential_input_schema_for_principal, credential_target,
    credential_verification_input_from_body, delete_credential_for_principal,
    get_credential_for_principal, put_credential_for_principal, verify_credential_for_principal,
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
    let principal = context.identity.principal.clone();
    let broker_user_manage = is_broker_user_manage_context(&context);
    match management_store_call(&context, move |store| {
        if broker_user_manage {
            store.list_credentials(Some(&principal))
        } else {
            store.list_credentials_readable_by(&principal)
        }
    })
    .await
    {
        Ok(credentials) => {
            management_success_response(&context, operation, None, json!(credentials)).await
        }
        Err(error) => management_store_error_response(&context, operation, None, error).await,
    }
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
    let broker_user_manage = is_broker_user_manage_context(&context);
    let targets = if broker_user_manage {
        let allowed_services =
            visible_per_user_services(&context.snapshot.runtime, &context.identity);
        credential_targets(&context.snapshot.runtime, Some(&allowed_services))
    } else {
        let principal = context.identity.principal.clone();
        // Credential rights are keyed by the connection a service consumes.
        let candidates = credential_targets(&context.snapshot.runtime, None)
            .into_iter()
            .map(|target| {
                let key = context
                    .snapshot
                    .runtime
                    .personal_credential_key(&target.service)
                    .unwrap_or(&target.service)
                    .to_owned();
                (key, target)
            })
            .collect::<Vec<_>>();
        match management_store_call(&context, move |store| {
            let mut allowed = Vec::new();
            for (key, target) in candidates {
                if store.has_credential_right(
                    &principal,
                    "credentials:self:write",
                    &key,
                    &target.credential_name,
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

pub(crate) async fn user_credentials_get(
    State(state): State<AppState>,
    Path((service, name)): Path<(String, String)>,
    ConnectInfo(remote_addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let operation = "credentials.inspect";
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
    let principal = context.identity.principal.clone();
    let enforce_right = !is_broker_user_manage_context(&context);
    let request = PrincipalCredentialTarget::new(principal, service, name)
        .enforce_right(enforce_right)
        .enforce_configured_target(true);
    get_credential_for_principal(
        context,
        operation,
        request,
        "credentials:self:read_metadata",
    )
    .await
}

pub(crate) async fn user_credentials_put(
    State(state): State<AppState>,
    Path((service, name)): Path<(String, String)>,
    ConnectInfo(remote_addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(body): Json<CredentialPutBody>,
) -> impl IntoResponse {
    let operation = "credentials.put";
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
    let principal = context.identity.principal.clone();
    let enforce_right = !is_broker_user_manage_context(&context);
    let request = PrincipalCredentialTarget::new(principal, service, name)
        .enforce_right(enforce_right)
        .enforce_configured_target(true);
    put_credential_for_principal(context, operation, request, body).await
}

pub(crate) async fn user_credential_input_schema(
    State(state): State<AppState>,
    Path((service, name)): Path<(String, String)>,
    RawQuery(raw_query): RawQuery,
    ConnectInfo(remote_addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let operation = "credentials.input_schema";
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
    let principal = context.identity.principal.clone();
    let enforce_right = !is_broker_user_manage_context(&context);
    let query = match credential_input_schema_query(raw_query.as_deref()) {
        Ok(query) => query,
        Err(message) => {
            let target = Some(credential_target(&principal, &service, &name));
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
    let request = PrincipalCredentialTarget::new(principal, service, name)
        .enforce_right(enforce_right)
        .enforce_configured_target(true);
    credential_input_schema_for_principal(context, operation, request, query).await
}

pub(crate) async fn user_credentials_delete(
    State(state): State<AppState>,
    Path((service, name)): Path<(String, String)>,
    ConnectInfo(remote_addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let operation = "credentials.delete";
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
    let principal = context.identity.principal.clone();
    let enforce_right = !is_broker_user_manage_context(&context);
    let request = PrincipalCredentialTarget::new(principal, service, name)
        .enforce_right(enforce_right)
        .enforce_configured_target(true);
    delete_credential_for_principal(context, operation, request).await
}

pub(crate) async fn user_credentials_verify(
    State(state): State<AppState>,
    Path((service, name)): Path<(String, String)>,
    ConnectInfo(remote_addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    body: Bytes,
) -> impl IntoResponse {
    let operation = "credentials.verify";
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
    let principal = context.identity.principal.clone();
    let target = Some(credential_target(&principal, &service, &name));
    let input = match credential_verification_input_from_body(body) {
        Ok(input) => input,
        Err(message) => {
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
    let enforce_right = !is_broker_user_manage_context(&context);
    let request = PrincipalCredentialTarget::new(principal, service, name)
        .enforce_right(enforce_right)
        .enforce_configured_target(true);
    verify_credential_for_principal(context, operation, request, input).await
}
