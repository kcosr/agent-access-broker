//! Pending Microsoft identity reservations, separate from established login methods.
use super::common::{
    ManagementAccess, ManagementContext, management_committed_write_audit_completion,
    management_context, management_pre_audited_success_response, management_store_call,
    management_store_error_response, management_success_response, management_write_audit_preflight,
};
use crate::state::AppState;
use agent_access_core::{
    ManagedStoreError, MicrosoftEnrollmentCancelRequest, MicrosoftEnrollmentCreate,
    MicrosoftEnrollmentCreateRequest, MicrosoftEnrollmentRecord, MicrosoftEnrollmentUpdateRequest,
};
use axum::Json;
use axum::extract::{ConnectInfo, Path, Query, State};
use axum::http::HeaderMap;
use axum::response::Response;
use serde::Deserialize;
use serde_json::{Value, json};
use std::net::SocketAddr;
use std::sync::Arc;
use tracing::Instrument;
use tracing::instrument::WithSubscriber;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct UpdateBody {
    enrollment_id: String,
    expected_revision: u64,
    email: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct CancelBody {
    enrollment_id: String,
    expected_revision: u64,
}

pub(super) fn audit_target(enrollment: &MicrosoftEnrollmentRecord) -> Value {
    json!({
        "principal": enrollment.principal_id,
        "provider": "microsoft",
        "tenantId": enrollment.tenant_id,
        "enrollmentId": enrollment.enrollment_id,
        "revision": enrollment.revision,
    })
}

pub(crate) async fn inspect(
    State(state): State<AppState>,
    Path(principal): Path<String>,
    ConnectInfo(remote): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> Response {
    let operation = "admin.principals.login_methods.oidc.microsoft.enrollment.inspect";
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
    let target = Some(json!({"principal": principal, "provider": "microsoft"}));
    match management_store_call(&context, move |store| {
        store.microsoft_enrollment(&principal)
    })
    .await
    {
        Ok(enrollment) => {
            management_success_response(&context, operation, target, json!(enrollment)).await
        }
        Err(error) => management_store_error_response(&context, operation, target, error).await,
    }
}

enum Mutation {
    Create(MicrosoftEnrollmentCreate),
    Update(UpdateBody),
    Cancel(CancelBody),
}

impl Mutation {
    fn operation(&self) -> &'static str {
        match self {
            Self::Create(_) => "admin.principals.login_methods.oidc.microsoft.enrollment.create",
            Self::Update(_) => "admin.principals.login_methods.oidc.microsoft.enrollment.update",
            Self::Cancel(_) => "admin.principals.login_methods.oidc.microsoft.enrollment.cancel",
        }
    }
}

pub(crate) async fn create(
    State(state): State<AppState>,
    Path(principal): Path<String>,
    ConnectInfo(remote): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(body): Json<MicrosoftEnrollmentCreate>,
) -> Response {
    write(state, principal, remote, headers, Mutation::Create(body)).await
}

pub(crate) async fn update(
    State(state): State<AppState>,
    Path(principal): Path<String>,
    ConnectInfo(remote): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(body): Json<UpdateBody>,
) -> Response {
    write(state, principal, remote, headers, Mutation::Update(body)).await
}

pub(crate) async fn cancel(
    State(state): State<AppState>,
    Path(principal): Path<String>,
    ConnectInfo(remote): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Query(body): Query<CancelBody>,
) -> Response {
    write(state, principal, remote, headers, Mutation::Cancel(body)).await
}

async fn write(
    state: AppState,
    principal: String,
    remote: SocketAddr,
    headers: HeaderMap,
    mutation: Mutation,
) -> Response {
    let operation = mutation.operation();
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
    // Neither preflight nor completion carries the match email or supplied claims.
    let target = Some(json!({"principal": principal, "provider": "microsoft"}));
    if let Err(response) =
        management_write_audit_preflight(&context, operation, target.clone()).await
    {
        return *response;
    }
    let actor = context.identity.principal.clone();
    let cancelled = matches!(mutation, Mutation::Cancel(_));
    committed_mutation(
        state,
        context,
        operation,
        target,
        cancelled,
        move |runtime| perform_mutation(runtime, principal, actor, mutation, cancelled),
    )
    .await
}

fn perform_mutation(
    runtime: agent_access_core::BrokerRuntime,
    principal: String,
    actor: String,
    mutation: Mutation,
    cancelled: bool,
) -> Result<MicrosoftEnrollmentRecord, ManagedStoreError> {
    let store = runtime
        .managed_store()
        .ok_or_else(|| ManagedStoreError::Unavailable("managed store is unavailable".into()))?;
    let provider_generation = if cancelled {
        None
    } else {
        if runtime.config().identity.authority != "managed" {
            return Err(ManagedStoreError::InputInvalid(
                "Microsoft enrollment requires identity.authority = managed".into(),
            ));
        }
        Some(
            store
                .oidc_provider_state()?
                .ok_or(ManagedStoreError::OidcProviderUnavailable)?
                .config_generation,
        )
    };
    match mutation {
        Mutation::Create(body) => {
            store.create_microsoft_enrollment(MicrosoftEnrollmentCreateRequest {
                principal_id: principal,
                email: body.email,
                provider_generation: provider_generation.expect("create provider generation"),
                actor,
            })
        }
        Mutation::Update(body) => {
            store.update_microsoft_enrollment(MicrosoftEnrollmentUpdateRequest {
                principal_id: principal,
                enrollment_id: body.enrollment_id,
                expected_revision: body.expected_revision,
                email: body.email,
                provider_generation: provider_generation.expect("update provider generation"),
                actor,
            })
        }
        Mutation::Cancel(body) => {
            store.cancel_microsoft_enrollment(MicrosoftEnrollmentCancelRequest {
                principal_id: principal,
                enrollment_id: body.enrollment_id,
                expected_revision: body.expected_revision,
                actor,
            })
        }
    }
}

pub(crate) async fn committed_mutation<F>(
    state: AppState,
    context: ManagementContext,
    operation: &'static str,
    target: Option<Value>,
    cancelled: bool,
    mutate: F,
) -> Response
where
    F: FnOnce(
            agent_access_core::BrokerRuntime,
        ) -> Result<MicrosoftEnrollmentRecord, ManagedStoreError>
        + Send
        + 'static,
{
    let context = Arc::new(context);
    let owner_context = context.clone();
    let owner_target = target.clone();
    // Keep the write and its transaction-captured completion audit alive after
    // disconnect; serialize the database commit with configuration publication.
    let owner = tokio::spawn(
        async move {
            let context = owner_context;
            let result = state
                .reloadable
                .token_store_call_from_snapshot(context.snapshot.clone(), mutate)
                .await;
            match result {
                Ok(enrollment) => {
                    management_committed_write_audit_completion(
                        &context,
                        operation,
                        Some(audit_target(&enrollment)),
                    )
                    .await;
                    management_pre_audited_success_response(
                        &context,
                        operation,
                        owner_target,
                        if cancelled {
                            json!({"cancelled": true})
                        } else {
                            json!(enrollment)
                        },
                    )
                }
                Err(error) => {
                    management_store_error_response(&context, operation, owner_target, error).await
                }
            }
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
                ManagedStoreError::Unavailable("Microsoft enrollment mutation owner failed".into()),
            )
            .await
        }
    }
}
