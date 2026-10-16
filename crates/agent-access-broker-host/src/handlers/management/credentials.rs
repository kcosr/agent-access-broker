use crate::handlers::management::common::{
    CredentialInputSchemaQuery, CredentialPutBody, ManagementContext, VerificationAudit,
    is_broker_user_manage_context, management_context_error_response,
    management_pre_audited_success_response, management_provider_error_response,
    management_store_call, management_store_error_response, management_success_response,
    management_verification_error_response, management_write_audit_preflight,
    management_write_audit_upstream_verification,
};
use agent_access_core::{
    BrokerRuntime, CredentialVerificationInput, CredentialWriteRequest, IdentityContext,
    ManagedStoreError,
};
use agent_access_provider::{ProviderError, ReasonCode, is_action_name, is_service_name};
use axum::body::Bytes;
use axum::http::StatusCode;
use serde_json::{Value, json};

pub(super) fn credential_target(principal: &str, service: &str, name: &str) -> Value {
    json!({
        "principal": principal,
        "service": service,
        "credential": name
    })
}

#[derive(Debug)]
pub(super) struct PrincipalCredentialTarget {
    principal: String,
    service: String,
    name: String,
    enforce_right: bool,
    enforce_configured_target: bool,
}

impl PrincipalCredentialTarget {
    pub(super) fn new(principal: String, service: String, name: String) -> Self {
        Self {
            principal,
            service,
            name,
            enforce_right: false,
            enforce_configured_target: false,
        }
    }

    pub(super) fn enforce_right(mut self, enforce: bool) -> Self {
        self.enforce_right = enforce;
        self
    }

    pub(super) fn enforce_configured_target(mut self, enforce: bool) -> Self {
        self.enforce_configured_target = enforce;
        self
    }

    fn audit_target(&self) -> Option<Value> {
        Some(credential_target(
            &self.principal,
            &self.service,
            &self.name,
        ))
    }

    /// The stored `service` column this target addresses: the ID of the
    /// credential connection the service consumes, or the route's service
    /// when it consumes none.
    fn store_service(&self, runtime: &BrokerRuntime) -> String {
        runtime
            .personal_credential_key(&self.service)
            .unwrap_or(&self.service)
            .to_owned()
    }
}

/// Whether `profile` is the service's own declared profile or its credential
/// connection's token profile.
fn profile_supported(runtime: &BrokerRuntime, service: &str, profile: &str) -> bool {
    runtime.credential_profile_kind(service, profile).is_some()
        || runtime
            .personal_token_profile(service)
            .is_some_and(|(configured, _)| configured == profile)
}

fn validate_management_service_name(service: &str) -> bool {
    is_service_name(service)
}

fn validate_management_name(name: &str) -> bool {
    is_action_name(name)
}

pub(super) fn credential_verification_input_from_body(
    body: Bytes,
) -> Result<CredentialVerificationInput, String> {
    if body.iter().all(u8::is_ascii_whitespace) {
        return Ok(CredentialVerificationInput::default());
    }
    serde_json::from_slice(&body)
        .map_err(|error| format!("credential verification body is invalid: {error}"))
}

fn credential_profile_for_put(
    runtime: &BrokerRuntime,
    service: &str,
    body: &CredentialPutBody,
) -> Result<(String, String), &'static str> {
    credential_profile_for_service(runtime, service, body.profile.as_deref())
}

fn credential_profile_for_service(
    runtime: &BrokerRuntime,
    service: &str,
    profile: Option<&str>,
) -> Result<(String, String), &'static str> {
    let configured = runtime
        .effective_credentials()
        .per_user
        .get(service)
        .ok_or("managed per_user credentials are not configured for service")?;
    if configured.kind == "connection" {
        let (configured_profile, kind) = runtime
            .personal_token_profile(service)
            .ok_or("managed per_user credentials are not configured for service")?;
        if profile.is_some_and(|profile| profile != configured_profile) {
            return Err("credential profile does not match configured managed profile");
        }
        return Ok((configured_profile.to_string(), kind.to_string()));
    }
    if configured.kind != "managed_store" {
        return Err("managed per_user credentials are not configured for service");
    }
    let configured_profile = configured
        .profile
        .as_deref()
        .ok_or("managed credential profile is not configured for service")?;
    if profile.is_some_and(|profile| profile != configured_profile) {
        return Err("credential profile does not match configured managed profile");
    }
    let profile = configured_profile.to_string();
    let kind = runtime
        .credential_profile_kind(service, &profile)
        .ok_or("credential profile is not supported for service")?;
    Ok((profile, kind.to_string()))
}

fn configured_managed_credential_name(
    runtime: &BrokerRuntime,
    service: &str,
) -> Result<String, &'static str> {
    let configured = runtime
        .effective_credentials()
        .per_user
        .get(service)
        .ok_or("managed per_user credentials are not configured for service")?;
    if configured.kind == "connection" && runtime.personal_token_profile(service).is_some() {
        return Ok(agent_access_core::CONNECTION_CREDENTIAL_NAME.to_string());
    }
    if configured.kind != "managed_store" {
        return Err("managed per_user credentials are not configured for service");
    }
    Ok(configured
        .credential_name
        .clone()
        .unwrap_or_else(|| "default".to_string()))
}

async fn enforce_user_configured_target(
    context: &ManagementContext,
    operation: &str,
    service: &str,
    name: &str,
    target: Option<Value>,
) -> Result<(), Box<axum::response::Response>> {
    let configured_name =
        match configured_managed_credential_name(&context.snapshot.runtime, service) {
            Ok(name) => name,
            Err(message) => {
                return Err(Box::new(
                    management_context_error_response(
                        context,
                        StatusCode::BAD_REQUEST,
                        operation,
                        ReasonCode::InputInvalid,
                        message,
                        target,
                    )
                    .await,
                ));
            }
        };
    if configured_name != name {
        return Err(Box::new(
            management_context_error_response(
                context,
                StatusCode::BAD_REQUEST,
                operation,
                ReasonCode::InputInvalid,
                "credential name does not match the configured managed target",
                target,
            )
            .await,
        ));
    }
    if is_broker_user_manage_context(context)
        && !context
            .snapshot
            .runtime
            .has_any_per_user_policy_for_service(&context.identity, service)
    {
        return Err(Box::new(
            management_context_error_response(
                context,
                StatusCode::FORBIDDEN,
                operation,
                ReasonCode::ServiceActionDenied,
                "credential target is not visible to the principal",
                target,
            )
            .await,
        ));
    }
    Ok(())
}

async fn credential_owner_identity(
    context: &ManagementContext,
    operation: &str,
    principal: &str,
    target: Option<Value>,
) -> Result<IdentityContext, Box<axum::response::Response>> {
    if context.snapshot.runtime.managed_store().is_some() {
        let principal_for_store = principal.to_string();
        let owner =
            match management_store_call(context, move |store| {
                let record = store.active_principal(&principal_for_store)?;
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

pub(super) async fn get_credential_for_principal(
    context: ManagementContext,
    operation: &str,
    request: PrincipalCredentialTarget,
    right: &str,
) -> axum::response::Response {
    let target = request.audit_target();
    if !validate_management_service_name(&request.service)
        || !validate_management_name(&request.name)
    {
        return management_context_error_response(
            &context,
            StatusCode::BAD_REQUEST,
            operation,
            ReasonCode::InputInvalid,
            "service or credential name is invalid",
            target,
        )
        .await;
    }
    if request.enforce_configured_target
        && let Err(response) = enforce_user_configured_target(
            &context,
            operation,
            &request.service,
            &request.name,
            target.clone(),
        )
        .await
    {
        return *response;
    }
    let principal_for_store = request.principal.clone();
    let service_for_store = request.store_service(&context.snapshot.runtime);
    let name_for_store = request.name.clone();
    let right_for_store = right.to_string();
    let enforce_right = request.enforce_right;
    match management_store_call(&context, move |store| {
        if enforce_right {
            store.require_credential_right(
                &principal_for_store,
                &right_for_store,
                &service_for_store,
                &name_for_store,
            )?;
        }
        store.credential_by_tuple(&principal_for_store, &service_for_store, &name_for_store)
    })
    .await
    {
        Ok(credential) => {
            management_success_response(&context, operation, target, json!(credential)).await
        }
        Err(error) => management_store_error_response(&context, operation, target, error).await,
    }
}

pub(super) async fn credential_input_schema_for_principal(
    context: ManagementContext,
    operation: &str,
    request: PrincipalCredentialTarget,
    query: CredentialInputSchemaQuery,
) -> axum::response::Response {
    let target = request.audit_target();
    if !validate_management_service_name(&request.service)
        || !validate_management_name(&request.name)
    {
        return management_context_error_response(
            &context,
            StatusCode::BAD_REQUEST,
            operation,
            ReasonCode::InputInvalid,
            "service or credential name is invalid",
            target,
        )
        .await;
    }
    if request.enforce_configured_target
        && let Err(response) = enforce_user_configured_target(
            &context,
            operation,
            &request.service,
            &request.name,
            target.clone(),
        )
        .await
    {
        return *response;
    }
    if request.enforce_right {
        let principal_for_store = request.principal.clone();
        let service_for_store = request.store_service(&context.snapshot.runtime);
        let name_for_store = request.name.clone();
        if let Err(error) = management_store_call(&context, move |store| {
            store.require_credential_right(
                &principal_for_store,
                "credentials:self:write",
                &service_for_store,
                &name_for_store,
            )
        })
        .await
        {
            return management_store_error_response(&context, operation, target, error).await;
        }
    }
    let (profile, credential_kind) = match credential_profile_for_service(
        &context.snapshot.runtime,
        &request.service,
        query.profile.as_deref(),
    ) {
        Ok(value) => value,
        Err(message) => {
            return management_context_error_response(
                &context,
                StatusCode::BAD_REQUEST,
                operation,
                ReasonCode::InputInvalid,
                message,
                target,
            )
            .await;
        }
    };
    let Some(schema) = context.snapshot.runtime.credential_input_schema(
        &request.service,
        &profile,
        &credential_kind,
    ) else {
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

pub(super) async fn put_credential_for_principal(
    context: ManagementContext,
    operation: &str,
    request: PrincipalCredentialTarget,
    body: CredentialPutBody,
) -> axum::response::Response {
    let purpose = context.credential_purpose;
    let target = request.audit_target();
    if !validate_management_service_name(&request.service)
        || !validate_management_name(&request.name)
    {
        return management_context_error_response(
            &context,
            StatusCode::BAD_REQUEST,
            operation,
            ReasonCode::InputInvalid,
            "service or credential name is invalid",
            target,
        )
        .await;
    }
    if request.enforce_configured_target
        && let Err(response) = enforce_user_configured_target(
            &context,
            operation,
            &request.service,
            &request.name,
            target.clone(),
        )
        .await
    {
        return *response;
    }
    if request.enforce_right {
        let principal_for_store = request.principal.clone();
        let service_for_store = request.store_service(&context.snapshot.runtime);
        let name_for_store = request.name.clone();
        if let Err(error) = management_store_call(&context, move |store| {
            store.require_credential_right(
                &principal_for_store,
                "credentials:self:write",
                &service_for_store,
                &name_for_store,
            )
        })
        .await
        {
            return management_store_error_response(&context, operation, target, error).await;
        }
    }
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
    let (profile, credential_kind) =
        match credential_profile_for_put(&context.snapshot.runtime, &request.service, &body) {
            Ok(value) => value,
            Err(message) => {
                return management_context_error_response(
                    &context,
                    StatusCode::BAD_REQUEST,
                    operation,
                    ReasonCode::InputInvalid,
                    message,
                    target,
                )
                .await;
            }
        };
    if let Err(response) =
        management_write_audit_preflight(&context, operation, target.clone()).await
    {
        return *response;
    }
    let actor = context.identity.principal.clone();
    let owner_principal_id = request.principal.clone();
    let service = request.store_service(&context.snapshot.runtime);
    let name = request.name.clone();
    match management_store_call(&context, move |store| {
        store.upsert_user_credential(
            &key_ring,
            CredentialWriteRequest {
                owner_principal_id,
                service,
                name,
                profile,
                credential_kind,
                secret: body.secret,
                metadata: body.metadata,
                actor,
            },
            purpose,
        )
    })
    .await
    {
        Ok(credential) => {
            management_pre_audited_success_response(&context, operation, target, json!(credential))
        }
        Err(error) => management_store_error_response(&context, operation, target, error).await,
    }
}

pub(super) async fn verify_credential_for_principal(
    context: ManagementContext,
    operation: &str,
    request: PrincipalCredentialTarget,
    input: CredentialVerificationInput,
) -> axum::response::Response {
    let purpose = context.credential_purpose;
    let target = request.audit_target();
    if !validate_management_service_name(&request.service)
        || !validate_management_name(&request.name)
    {
        return management_context_error_response(
            &context,
            StatusCode::BAD_REQUEST,
            operation,
            ReasonCode::InputInvalid,
            "service or credential name is invalid",
            target,
        )
        .await;
    }
    if request.enforce_configured_target
        && let Err(response) = enforce_user_configured_target(
            &context,
            operation,
            &request.service,
            &request.name,
            target.clone(),
        )
        .await
    {
        return *response;
    }
    let principal_for_store = request.principal.clone();
    let service_for_store = request.store_service(&context.snapshot.runtime);
    let name_for_store = request.name.clone();
    let enforce_right = request.enforce_right;
    let metadata = match management_store_call(&context, move |store| {
        if enforce_right {
            store.require_credential_right(
                &principal_for_store,
                "credentials:self:verify",
                &service_for_store,
                &name_for_store,
            )?;
        }
        store.credential_by_tuple(&principal_for_store, &service_for_store, &name_for_store)
    })
    .await
    {
        Ok(metadata) => metadata,
        Err(error) => {
            return management_store_error_response(&context, operation, target, error).await;
        }
    };
    if !profile_supported(
        &context.snapshot.runtime,
        &request.service,
        &metadata.profile,
    ) {
        return management_context_error_response(
            &context,
            StatusCode::BAD_REQUEST,
            operation,
            ReasonCode::CredentialInvalid,
            "credential profile is not supported for service",
            target,
        )
        .await;
    }
    let owner_identity =
        match credential_owner_identity(&context, operation, &request.principal, target.clone())
            .await
        {
            Ok(identity) => identity,
            Err(response) => return *response,
        };
    let input = match context
        .snapshot
        .runtime
        .preflight_execution_credential_verification(&request.service, &owner_identity, input)
    {
        Ok(input) => input,
        Err(error) => {
            return management_provider_error_response(&context, operation, target, error).await;
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
    if let Err(response) =
        management_write_audit_preflight(&context, operation, target.clone()).await
    {
        return *response;
    }
    let principal_for_store = request.principal.clone();
    let service_for_store = request.store_service(&context.snapshot.runtime);
    let name_for_store = request.name.clone();
    let profile = metadata.profile.clone();
    let verification_candidate = match management_store_call(&context, move |store| {
        store.resolve_user_credential_for_verification(
            &key_ring,
            &principal_for_store,
            &service_for_store,
            &name_for_store,
            &profile,
            purpose,
        )
    })
    .await
    {
        Ok(credential) => credential,
        Err(error) => {
            return management_store_error_response(&context, operation, target, error).await;
        }
    };
    let correlation = agent_access_provider::CorrelationContext::new(
        context.request_id.clone(),
        context.broker_request_id.clone(),
    );
    let runtime = &context.snapshot.runtime;
    // A command import receives the credential's plaintext on its stdin, so
    // core rereads exactly the material resolved here rather than taking it
    // from the opaque credential.
    let command = runtime.command_provider(&request.service).is_some();
    let verification = if command {
        runtime
            .verify_command_credential(
                &request.service,
                &owner_identity,
                &verification_candidate.target,
                correlation,
            )
            .await
    } else {
        runtime
            .verify_execution_credential(
                &request.service,
                &verification_candidate.credential,
                &owner_identity,
                input,
                correlation,
            )
            .await
    };
    let verification = match verification {
        Ok(verification) => verification,
        Err(error) => {
            if verification_error_records_failure(&error) {
                let failure_target = verification_candidate.target.clone();
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
                            service = request.service.as_str(),
                            credential = request.name.as_str(),
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
    let verification_target = verification_candidate.target;
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
            management_pre_audited_success_response(&context, operation, target, json!(credential))
        }
        Err(error) => management_store_error_response(&context, operation, target, error).await,
    }
}

pub(super) async fn delete_credential_for_principal(
    context: ManagementContext,
    operation: &str,
    request: PrincipalCredentialTarget,
) -> axum::response::Response {
    let purpose = context.credential_purpose;
    let target = request.audit_target();
    if !validate_management_service_name(&request.service)
        || !validate_management_name(&request.name)
    {
        return management_context_error_response(
            &context,
            StatusCode::BAD_REQUEST,
            operation,
            ReasonCode::InputInvalid,
            "service or credential name is invalid",
            target,
        )
        .await;
    }
    if request.enforce_configured_target
        && let Err(response) = enforce_user_configured_target(
            &context,
            operation,
            &request.service,
            &request.name,
            target.clone(),
        )
        .await
    {
        return *response;
    }
    if request.enforce_right {
        let principal_for_store = request.principal.clone();
        let service_for_store = request.store_service(&context.snapshot.runtime);
        let name_for_store = request.name.clone();
        if let Err(error) = management_store_call(&context, move |store| {
            store.require_credential_right(
                &principal_for_store,
                "credentials:self:delete",
                &service_for_store,
                &name_for_store,
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
    let principal_for_store = request.principal.clone();
    let service_for_store = request.store_service(&context.snapshot.runtime);
    let name_for_store = request.name.clone();
    match management_store_call(&context, move |store| {
        store.delete_user_credential(
            &principal_for_store,
            &service_for_store,
            &name_for_store,
            purpose,
        )
    })
    .await
    {
        Ok(credential) => {
            management_pre_audited_success_response(&context, operation, target, json!(credential))
        }
        Err(error) => management_store_error_response(&context, operation, target, error).await,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
