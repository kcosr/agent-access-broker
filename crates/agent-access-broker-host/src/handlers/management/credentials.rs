//! Management of a principal's credential connection token: inspect, put,
//! verify, input schema and delete through `{connection}` routes, for the
//! owner and for administrators, plus the owner's retained-row cleanup.
//!
//! Every connection operation requires the connection to select the token
//! method for the owner's principal kind; OAuth connections are managed
//! through the OAuth routes and a connection that offers the owner no method
//! has nothing to manage. Authorization depends on who asks
//! ([`CredentialAccess`]); verification separately runs its probe as the
//! owner, through a consumer the owner holds a `per_user` grant on.
use crate::handlers::management::common::{
    CredentialInputSchemaQuery, CredentialPutBody, ManagementContext, VerificationAudit,
    management_context_error_response, management_pre_audited_success_response,
    management_provider_error_response, management_store_call, management_store_error_response,
    management_success_response, management_verification_error_response,
    management_write_audit_preflight, management_write_audit_upstream_verification,
};
use crate::handlers::management::connections::{self, audit_target, connection_credential};
use crate::state::AppState;
use agent_access_core::{
    BrokerRuntime, CONNECTION_CREDENTIAL_NAME, ConnectionTokenProfile, CredentialVerificationInput,
    CredentialWriteRequest, IdentityContext, ManagedStoreError,
};
use agent_access_provider::{ProviderError, ReasonCode, is_service_name};
use axum::body::Bytes;
use axum::http::StatusCode;
use serde::Deserialize;
use serde_json::{Value, json};

/// Who manages a credential connection, which decides authorization.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum CredentialAccess {
    /// The owner through a Broker-issued `user_manage` token or browser
    /// session: an active `per_user` grant on a consuming service entitles
    /// setup, and the owner may always read and delete its own token.
    Owner,
    /// The owner as a classless self-service identity: credential rights on
    /// `(connection, default)` authorize each operation.
    ClasslessOwner,
    /// An administrator, or an auditor for reads, acting on a principal.
    Administrator,
}

/// One management operation on `principal`'s token for `connection`.
#[derive(Debug)]
pub(super) struct ConnectionCredentialRequest {
    principal: String,
    connection: String,
    access: CredentialAccess,
}

impl ConnectionCredentialRequest {
    pub(super) fn new(principal: String, connection: String, access: CredentialAccess) -> Self {
        Self {
            principal,
            connection,
            access,
        }
    }

    fn audit_target(&self) -> Option<Value> {
        Some(audit_target(&self.principal, &self.connection))
    }
}

/// What each operation needs: a classless owner's credential right, and
/// whether a grant-entitled owner needs a current grant on a consumer.
#[derive(Debug, Clone, Copy)]
enum Operation {
    Inspect,
    InputSchema,
    Put,
    Verify,
    Delete,
}

impl Operation {
    fn classless_right(self) -> &'static str {
        match self {
            Self::Inspect => "credentials:self:read_metadata",
            Self::InputSchema | Self::Put => "credentials:self:write",
            Self::Verify => "credentials:self:verify",
            Self::Delete => "credentials:self:delete",
        }
    }

    /// Setup needs current entitlement; reading and deleting one's own
    /// token stay available after grant loss, for cleanup.
    fn requires_entitlement(self) -> bool {
        matches!(self, Self::InputSchema | Self::Put | Self::Verify)
    }
}

/// The body of a verify route.
#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct ConnectionVerifyBody {
    /// The consuming service whose probe verifies the token.
    #[serde(default)]
    service: Option<String>,
    /// The repository a Git gateway probe fetches.
    #[serde(default)]
    repository: Option<String>,
}

pub(super) fn connection_verify_body(body: Bytes) -> Result<ConnectionVerifyBody, String> {
    if body.iter().all(u8::is_ascii_whitespace) {
        return Ok(ConnectionVerifyBody::default());
    }
    serde_json::from_slice(&body)
        .map_err(|error| format!("credential verification body is invalid: {error}"))
}

/// The token profiles the connection accepts from the owner.
struct Admitted {
    owner: IdentityContext,
    profiles: Vec<ConnectionTokenProfile>,
}

impl Admitted {
    /// The accepted profile names, for reads, verification and deletes.
    fn profile_names(&self) -> Vec<String> {
        self.profiles
            .iter()
            .map(|profile| profile.profile.clone())
            .collect()
    }

    /// The profile a put or input schema stores: `requested` when the
    /// connection accepts it, which is required when it accepts several and
    /// otherwise defaults to the only one.
    fn choose(&self, requested: Option<&str>) -> Result<&ConnectionTokenProfile, String> {
        let accepted = || {
            self.profiles
                .iter()
                .map(|profile| profile.profile.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        };
        match (requested, self.profiles.as_slice()) {
            (Some(requested), profiles) => profiles
                .iter()
                .find(|profile| profile.profile == requested)
                .ok_or_else(|| {
                    format!(
                        "credential profile is not accepted for this principal; the connection accepts {}",
                        accepted()
                    )
                }),
            (None, [only]) => Ok(only),
            (None, _) => Err(format!(
                "credential profile is required: the connection accepts {}",
                accepted()
            )),
        }
    }
}

async fn deny(
    context: &ManagementContext,
    operation: &str,
    status: StatusCode,
    reason: ReasonCode,
    message: &str,
    target: Option<Value>,
) -> Box<axum::response::Response> {
    Box::new(
        management_context_error_response(context, status, operation, reason, message, target)
            .await,
    )
}

/// The owner's identity with its stored principal kind, from which the
/// connection's method is selected and verification probes run. A disabled
/// owner still has an identity, so an administrator can read and delete its
/// token; the store refuses writes and verification for it.
pub(super) async fn credential_owner_identity(
    context: &ManagementContext,
    operation: &str,
    principal: &str,
    target: Option<Value>,
) -> Result<IdentityContext, Box<axum::response::Response>> {
    if context.snapshot.runtime.managed_store().is_some() {
        let principal_for_store = principal.to_string();
        let owner =
            match management_store_call(context, move |store| {
                let record = store.principal(&principal_for_store)?;
                let policy_groups = store.policy_groups(&principal_for_store)?;
                Ok((record, policy_groups))
            })
            .await
            {
                Ok(identity) => Some(identity),
                Err(
                    ManagedStoreError::PrincipalNotFound | ManagedStoreError::PrincipalRequired,
                ) if context.snapshot.runtime.config().identity.authority != "managed" => None,
                Err(error) => {
                    return Err(Box::new(
                        management_store_error_response(context, operation, target, error).await,
                    ));
                }
            };
        if let Some((record, policy_groups)) = owner {
            let principal_kind = record.principal_kind();
            return Ok(context.snapshot.runtime.identity_from_principal_groups(
                record.principal_id,
                principal_kind,
                record.external_subject,
                record.groups,
                Some(policy_groups),
                None,
            ));
        }
    }
    if principal == context.identity.principal {
        return Ok(context.identity.clone());
    }
    Ok(context.snapshot.runtime.identity_from_principal_groups(
        principal.to_string(),
        None,
        None,
        Vec::new(),
        None,
        None,
    ))
}

/// Checks the connection, its token method for the owner, and the caller's
/// authority for `operation`.
async fn admit(
    context: &ManagementContext,
    operation_name: &str,
    request: &ConnectionCredentialRequest,
    operation: Operation,
) -> Result<Admitted, Box<axum::response::Response>> {
    let target = request.audit_target();
    if !is_service_name(&request.connection) {
        return Err(deny(
            context,
            operation_name,
            StatusCode::BAD_REQUEST,
            ReasonCode::InputInvalid,
            "credential connection ID is invalid",
            target,
        )
        .await);
    }
    let runtime = &context.snapshot.runtime;
    if !runtime
        .effective_credentials()
        .connections
        .contains_key(&request.connection)
    {
        return Err(deny(
            context,
            operation_name,
            StatusCode::BAD_REQUEST,
            ReasonCode::InputInvalid,
            "credential connection is not configured",
            target,
        )
        .await);
    }
    let owner = match request.access {
        CredentialAccess::Administrator => {
            credential_owner_identity(context, operation_name, &request.principal, target.clone())
                .await?
        }
        CredentialAccess::Owner | CredentialAccess::ClasslessOwner => context.identity.clone(),
    };
    let Some(profiles) =
        connections::token_selection(runtime, &request.connection, owner.principal_kind)
    else {
        let message = match connections::selection(
            runtime,
            &request.connection,
            owner.principal_kind,
        ) {
            Some(agent_access_core::Selection::OAuth(_)) => {
                "credential connection uses OAuth for this principal; connect it through the OAuth connection routes"
            }
            _ => "credential connection offers no stored token for this principal",
        };
        return Err(deny(
            context,
            operation_name,
            StatusCode::BAD_REQUEST,
            ReasonCode::InputInvalid,
            message,
            target,
        )
        .await);
    };
    match request.access {
        CredentialAccess::Owner => {
            if operation.requires_entitlement()
                && connections::entitled_consumers(runtime, &owner, &request.connection).is_empty()
            {
                return Err(deny(
                    context,
                    operation_name,
                    StatusCode::FORBIDDEN,
                    ReasonCode::ServiceActionDenied,
                    "credential connection is not visible to the principal",
                    target,
                )
                .await);
            }
        }
        CredentialAccess::ClasslessOwner => {
            let principal = request.principal.clone();
            let connection = request.connection.clone();
            let right = operation.classless_right();
            if let Err(error) = management_store_call(context, move |store| {
                store.require_credential_right(
                    &principal,
                    right,
                    &connection,
                    CONNECTION_CREDENTIAL_NAME,
                )
            })
            .await
            {
                return Err(Box::new(
                    management_store_error_response(context, operation_name, target, error).await,
                ));
            }
        }
        CredentialAccess::Administrator => {}
    }
    Ok(Admitted { owner, profiles })
}

pub(super) async fn get_connection_credential(
    context: ManagementContext,
    operation: &str,
    request: ConnectionCredentialRequest,
) -> axum::response::Response {
    let target = request.audit_target();
    let admitted = match admit(&context, operation, &request, Operation::Inspect).await {
        Ok(admitted) => admitted,
        Err(response) => return *response,
    };
    let principal = request.principal.clone();
    let connection = request.connection.clone();
    let accepted = admitted.profile_names();
    match management_store_call(&context, move |store| {
        let credential =
            store.credential_by_tuple(&principal, &connection, CONNECTION_CREDENTIAL_NAME)?;
        // A row of a profile the owner's list does not accept is retained,
        // not this connection's token.
        if !accepted.contains(&credential.profile) {
            return Err(ManagedStoreError::CredentialNotFound);
        }
        Ok(credential)
    })
    .await
    {
        Ok(credential) => {
            management_success_response(
                &context,
                operation,
                target,
                connection_credential(&context.snapshot.runtime, credential),
            )
            .await
        }
        Err(error) => management_store_error_response(&context, operation, target, error).await,
    }
}

pub(super) async fn connection_input_schema(
    context: ManagementContext,
    operation: &str,
    request: ConnectionCredentialRequest,
    query: CredentialInputSchemaQuery,
) -> axum::response::Response {
    let target = request.audit_target();
    let admitted = match admit(&context, operation, &request, Operation::InputSchema).await {
        Ok(admitted) => admitted,
        Err(response) => return *response,
    };
    let profile = match admitted.choose(query.profile.as_deref()) {
        Ok(profile) => profile,
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
    let Some(schema) =
        connections::input_schema(&context.snapshot.runtime, &request.connection, profile)
    else {
        return management_context_error_response(
            &context,
            StatusCode::BAD_REQUEST,
            operation,
            ReasonCode::CredentialInvalid,
            "credential input schema is not supported",
            target,
        )
        .await;
    };
    management_success_response(&context, operation, target, json!(schema)).await
}

pub(super) async fn put_connection_credential(
    state: &AppState,
    context: ManagementContext,
    operation: &str,
    request: ConnectionCredentialRequest,
    body: CredentialPutBody,
) -> axum::response::Response {
    let purpose = context.credential_purpose;
    let target = request.audit_target();
    let admitted = match admit(&context, operation, &request, Operation::Put).await {
        Ok(admitted) => admitted,
        Err(response) => return *response,
    };
    let (profile, credential_kind) = match admitted.choose(body.profile.as_deref()) {
        Ok(profile) => (profile.profile.clone(), profile.credential_kind.to_string()),
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
    let Some(key_ring) = context.snapshot.runtime.credential_key_ring().cloned() else {
        return management_context_error_response(
            &context,
            StatusCode::SERVICE_UNAVAILABLE,
            operation,
            ReasonCode::EncryptionKeyMissing,
            "credential encryption key ring is not configured",
            target,
        )
        .await;
    };
    let contract = match context
        .snapshot
        .runtime
        .prepare_imported_connection_contract(&request.connection)
    {
        Ok(contract) => contract,
        Err(error) => {
            return management_store_error_response(&context, operation, target, error).await;
        }
    };
    if let Err(response) =
        management_write_audit_preflight(&context, operation, target.clone()).await
    {
        return *response;
    }
    let write = CredentialWriteRequest {
        owner_principal_id: request.principal.clone(),
        service: request.connection.clone(),
        name: CONNECTION_CREDENTIAL_NAME.to_string(),
        profile,
        credential_kind,
        secret: body.secret,
        metadata: body.metadata,
        actor: context.identity.principal.clone(),
    };
    let result = match contract {
        Some(contract) => {
            // The imported snapshot and publication fence stay owned until the
            // blocking write finishes, even if this response waiter is canceled.
            // Store validation also checks the prepared import definition and
            // revisions in its transaction.
            state
                .reloadable
                .token_store_call_from_snapshot(context.snapshot.clone(), move |runtime| {
                    let store = runtime.managed_store().ok_or_else(|| {
                        ManagedStoreError::Unavailable("managed store is unavailable".into())
                    })?;
                    store.upsert_imported_user_credential(&key_ring, write, purpose, &contract)
                })
                .await
        }
        None => {
            management_store_call(&context, move |store| {
                store.upsert_user_credential(&key_ring, write, purpose)
            })
            .await
        }
    };
    match result {
        Ok(credential) => management_pre_audited_success_response(
            &context,
            operation,
            target,
            connection_credential(&context.snapshot.runtime, credential),
        ),
        Err(error) => management_store_error_response(&context, operation, target, error).await,
    }
}

/// Whether a failed verification reached the upstream and found the
/// credential unusable there, so the credential records
/// `verification_failed`: the standard upstream failures, and a domain
/// reason whose fixed status is an upstream one (424, 502, 503 or 504).
/// Other domain statuses, like the standard reasons with those statuses,
/// leave the credential's verification state unchanged.
fn verification_error_records_failure(error: &ProviderError) -> bool {
    let reason = error.reason_code();
    if let Some(definition) = reason.domain() {
        return matches!(definition.status().as_u16(), 424 | 502 | 503 | 504);
    }
    matches!(
        reason.standard(),
        Some(
            ReasonCode::UpstreamUnauthorized
                | ReasonCode::UpstreamForbidden
                | ReasonCode::UpstreamFailed
                | ReasonCode::UpstreamRateLimited
                | ReasonCode::UpstreamConnectionFailed
                | ReasonCode::UpstreamTimeout
        )
    )
}

/// The consumers a verification probes, in order, as the owner: the
/// requested consumer, or by default the owner's entitled consumers that
/// take the supplied inputs (a `repository` selects Git gateways, its
/// absence the other consumers).
fn probe_candidates(
    runtime: &BrokerRuntime,
    connection: &str,
    owner: &IdentityContext,
    body: &ConnectionVerifyBody,
) -> Result<Vec<String>, ProviderError> {
    let entitled = connections::entitled_consumers(runtime, owner, connection);
    if let Some(service) = body.service.as_deref() {
        if !connections::consumers(runtime, connection)
            .iter()
            .any(|consumer| consumer == service)
        {
            return Err(ProviderError::deny(
                ReasonCode::InputInvalid,
                "verification service does not consume the credential connection",
            ));
        }
        if !entitled.iter().any(|consumer| consumer == service) {
            return Err(ProviderError::deny(
                ReasonCode::ServiceActionDenied,
                "verification requires the owner's per_user grant on the service",
            ));
        }
        return Ok(vec![service.to_string()]);
    }
    if entitled.is_empty() {
        return Err(ProviderError::deny(
            ReasonCode::ServiceActionDenied,
            "verification requires the owner's per_user grant on a consuming service",
        ));
    }
    let takes_repository = |service: &str| {
        runtime
            .service_descriptor(service)
            .is_some_and(|descriptor| {
                descriptor
                    .credential_verification_inputs()
                    .iter()
                    .any(|input| input == "repository")
            })
    };
    let wanted = body.repository.is_some();
    let candidates = entitled
        .iter()
        .filter(|service| takes_repository(service) == wanted)
        .cloned()
        .collect::<Vec<_>>();
    if candidates.is_empty() {
        return Err(ProviderError::deny(
            ReasonCode::InputInvalid,
            if wanted {
                "no consuming service the owner can verify through takes a repository"
            } else {
                "verification through this connection requires service and repository"
            },
        ));
    }
    Ok(candidates)
}

pub(super) async fn verify_connection_credential(
    context: ManagementContext,
    operation: &str,
    request: ConnectionCredentialRequest,
    body: ConnectionVerifyBody,
) -> axum::response::Response {
    let purpose = context.credential_purpose;
    let mut target = request.audit_target();
    if let (Some(Value::Object(object)), Some(service)) = (target.as_mut(), body.service.as_ref()) {
        object.insert("probeService".to_string(), json!(service));
    }
    let admitted = match admit(&context, operation, &request, Operation::Verify).await {
        Ok(admitted) => admitted,
        Err(response) => return *response,
    };
    let runtime = &context.snapshot.runtime;
    // The probe always runs as the owner: an administrator's own grants
    // never authorize it.
    let candidates = match probe_candidates(runtime, &request.connection, &admitted.owner, &body) {
        Ok(candidates) => candidates,
        Err(error) => {
            return management_provider_error_response(&context, operation, target, error).await;
        }
    };
    let input = CredentialVerificationInput {
        repository: body.repository.clone(),
    };
    // Gateways check their inputs, including the owner's repo.fetch policy
    // on the repository, before any secret is read.
    let mut inputs = Vec::with_capacity(candidates.len());
    for service in &candidates {
        let checked = if runtime.command_provider(service).is_some() {
            Ok(input.clone())
        } else {
            runtime.preflight_execution_credential_verification(
                service,
                &admitted.owner,
                input.clone(),
            )
        };
        match checked {
            Ok(checked) => inputs.push(checked),
            Err(error) => {
                return management_provider_error_response(&context, operation, target, error)
                    .await;
            }
        }
    }
    let Some(key_ring) = runtime.credential_key_ring().cloned() else {
        return management_context_error_response(
            &context,
            StatusCode::SERVICE_UNAVAILABLE,
            operation,
            ReasonCode::EncryptionKeyMissing,
            "credential encryption key ring is not configured",
            target,
        )
        .await;
    };
    if let Err(response) =
        management_write_audit_preflight(&context, operation, target.clone()).await
    {
        return *response;
    }
    let principal = request.principal.clone();
    let connection = request.connection.clone();
    let profiles = admitted.profile_names();
    let imported_requirement = match runtime.imported_connection_requirement(&connection) {
        Ok(requirement) => requirement,
        Err(error) => {
            return management_store_error_response(&context, operation, target, error).await;
        }
    };
    let candidate = match management_store_call(&context, move |store| {
        store.resolve_user_credential_for_verification_with_imported_contract(
            &key_ring,
            &principal,
            &connection,
            CONNECTION_CREDENTIAL_NAME,
            &profiles,
            purpose,
            imported_requirement.as_ref(),
        )
    })
    .await
    {
        Ok(candidate) => candidate,
        Err(error) => {
            return management_store_error_response(&context, operation, target, error).await;
        }
    };
    let correlation = agent_access_provider::CorrelationContext::new(
        context.request_id.clone(),
        context.broker_request_id.clone(),
    );
    // The first consumer whose probe answers verifies the token; a backend
    // without a probe passes to the next, and none answering leaves a local
    // check.
    let mut outcome = Ok(None);
    let mut probe_service = None;
    let mut command = false;
    for (service, input) in candidates.iter().zip(inputs) {
        command = runtime.command_provider(service).is_some();
        // A command import receives the credential's plaintext on its
        // stdin, so core rereads exactly the material resolved here rather
        // than taking it from the opaque credential.
        outcome = if command {
            runtime
                .verify_command_credential(
                    service,
                    &admitted.owner,
                    &candidate.target,
                    correlation.clone(),
                )
                .await
        } else {
            runtime
                .verify_execution_credential(
                    service,
                    &candidate.credential,
                    &admitted.owner,
                    input,
                    correlation.clone(),
                )
                .await
        };
        if !matches!(outcome, Ok(None)) || command {
            probe_service = Some(service.clone());
            break;
        }
    }
    if let (Some(Value::Object(object)), Some(service)) = (target.as_mut(), probe_service.as_ref())
    {
        object.insert("probeService".to_string(), json!(service));
    }
    let verification = match outcome {
        Ok(verification) => verification,
        Err(error) => {
            if verification_error_records_failure(&error) {
                let failure_target = candidate.target.clone();
                let provider_reason_code = error.reason_code().as_str();
                let error_code = error.reason_code().as_str().to_string();
                match management_store_call(&context, move |store| {
                    store.mark_user_credential_verification_failed_if_current(
                        &failure_target,
                        &error_code,
                        purpose,
                    )
                })
                .await
                {
                    Ok(_) | Err(ManagedStoreError::VersionConflict) => {}
                    Err(store_error) => {
                        tracing::warn!(
                            event = "credential_verification_failure_persist_failed",
                            operation,
                            agentRequestId = context.request_id.as_str(),
                            brokerRequestId = context.broker_request_id.as_str(),
                            principal = request.principal.as_str(),
                            connection = request.connection.as_str(),
                            providerReasonCode = provider_reason_code,
                            reasonCode = store_error.reason_code().as_str(),
                            error = %store_error,
                        );
                    }
                }
            }
            // A command's failed run keeps its process facts in audit.
            return if command {
                management_verification_error_response(&context, operation, target, error).await
            } else {
                management_provider_error_response(&context, operation, target, error).await
            };
        }
    };
    let verification_status = if let Some(verification) = &verification {
        if let Err(response) = management_write_audit_upstream_verification(
            &context,
            operation,
            target.clone(),
            VerificationAudit::verified(verification, command),
        )
        .await
        {
            return *response;
        }
        "upstream_verified"
    } else {
        "local_verified"
    };
    let verification_target = candidate.target;
    match management_store_call(&context, move |store| {
        store.mark_user_credential_verified_if_current(
            &verification_target,
            verification_status,
            purpose,
        )
    })
    .await
    {
        Ok(credential) => {
            let mut result = connection_credential(&context.snapshot.runtime, credential);
            if let Value::Object(object) = &mut result {
                object.insert("probeService".to_string(), json!(probe_service));
            }
            management_pre_audited_success_response(&context, operation, target, result)
        }
        Err(error) => management_store_error_response(&context, operation, target, error).await,
    }
}

pub(super) async fn delete_connection_credential(
    context: ManagementContext,
    operation: &str,
    request: ConnectionCredentialRequest,
) -> axum::response::Response {
    let purpose = context.credential_purpose;
    let target = request.audit_target();
    let admitted = match admit(&context, operation, &request, Operation::Delete).await {
        Ok(admitted) => admitted,
        Err(response) => return *response,
    };
    if let Err(response) =
        management_write_audit_preflight(&context, operation, target.clone()).await
    {
        return *response;
    }
    let principal = request.principal.clone();
    let connection = request.connection.clone();
    let profiles = admitted.profile_names();
    match management_store_call(&context, move |store| {
        store.delete_connection_credential(&principal, &connection, &profiles, purpose)
    })
    .await
    {
        Ok(credential) => management_pre_audited_success_response(
            &context,
            operation,
            target,
            connection_credential(&context.snapshot.runtime, credential),
        ),
        Err(error) => management_store_error_response(&context, operation, target, error).await,
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// Exercise the ordinary owner/admin handler after test-controlled snapshot
    /// publication, while retaining real management admission and store checks.
    pub(crate) async fn put_admitted_connection(
        state: &AppState,
        context: ManagementContext,
        principal: &str,
        connection: &str,
        body: Value,
    ) -> axum::response::Response {
        let (operation, access) = match context.credential_purpose {
            agent_access_core::CredentialManagementPurpose::Personal => {
                ("credentials.put", CredentialAccess::Owner)
            }
            agent_access_core::CredentialManagementPurpose::Administrative => (
                crate::handlers::management::audit_actions::ADMIN_CREDENTIALS_PUT,
                CredentialAccess::Administrator,
            ),
        };
        put_connection_credential(
            state,
            context,
            operation,
            ConnectionCredentialRequest::new(principal.into(), connection.into(), access),
            serde_json::from_value(body).unwrap(),
        )
        .await
    }

    #[test]
    fn verification_failure_persistence_records_upstream_auth_failures() {
        let error = ProviderError::error(
            ReasonCode::UpstreamUnauthorized,
            "upstream rejected credential",
        );

        assert!(verification_error_records_failure(&error));
    }

    #[test]
    fn verification_failure_persistence_records_upstream_throttling() {
        let error = agent_access_provider::upstream_rate_limited("jira", None)
            .with_upstream(Some(429), Some(1));

        assert!(verification_error_records_failure(&error));
    }

    #[test]
    fn verification_failure_persistence_ignores_scope_unresolved_404() {
        let error = ProviderError::deny(ReasonCode::ScopeUnresolved, "repository not found")
            .with_upstream(Some(404), Some(1));

        assert!(!verification_error_records_failure(&error));
    }

    #[test]
    fn verify_body_accepts_service_and_repository_only() {
        let body = connection_verify_body(Bytes::from_static(
            br#"{"service":"gitlab_git","repository":"team/project"}"#,
        ))
        .unwrap();
        assert_eq!(body.service.as_deref(), Some("gitlab_git"));
        assert_eq!(body.repository.as_deref(), Some("team/project"));
        assert!(connection_verify_body(Bytes::from_static(b"  ")).is_ok());
        assert!(connection_verify_body(Bytes::from_static(br#"{"name":"default"}"#)).is_err());
    }
}
