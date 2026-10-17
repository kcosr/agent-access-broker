//! Core-owned local dispatch. Neither SDK providers nor JSON can construct an
//! admitted command or a committed output capability.
pub(crate) mod descriptor;
#[cfg(test)]
mod tests;
use super::secret_reference_identity::SecretReferenceOrigin;
use super::*;
use crate::managed_store::management_commands as store;
use crate::managed_store::{
    CapturedSecretReference, SecretOutputCapture, SecretOutputReservationBatch,
};
use crate::management::{CommandError, LocalOperationOutcome, ManagementCommand};
use rusqlite::Connection;

pub(crate) const SERVICE_ID: &str = "broker_management";
pub(crate) const KIND: &str = "access_management";
pub(crate) static TARGET_INELIGIBLE: ProviderReasonDefinition = ProviderReasonDefinition::deny(
    "access_management_target_ineligible",
    ProviderFailureStatus::Forbidden,
);
pub(crate) static TARGET_EXISTS: ProviderReasonDefinition = ProviderReasonDefinition::deny(
    "access_management_target_exists",
    ProviderFailureStatus::Conflict,
);
pub(crate) static PRECONDITION_FAILED: ProviderReasonDefinition = ProviderReasonDefinition::deny(
    "access_management_precondition_failed",
    ProviderFailureStatus::Conflict,
);
pub(crate) static CONNECTION_INELIGIBLE: ProviderReasonDefinition = ProviderReasonDefinition::deny(
    "access_management_connection_ineligible",
    ProviderFailureStatus::Forbidden,
);
pub(crate) static REFERENCE_DENIED: ProviderReasonDefinition = ProviderReasonDefinition::deny(
    "access_management_reference_denied",
    ProviderFailureStatus::Forbidden,
);
pub(crate) static UNAVAILABLE: ProviderReasonDefinition = ProviderReasonDefinition::error(
    "access_management_unavailable",
    ProviderFailureStatus::ServiceUnavailable,
);
pub(crate) const DOMAIN_REASONS: &[&ProviderReasonDefinition] = &[
    &TARGET_INELIGIBLE,
    &TARGET_EXISTS,
    &PRECONDITION_FAILED,
    &CONNECTION_INELIGIBLE,
    &REFERENCE_DENIED,
    &UNAVAILABLE,
];

/// A single-use core-admitted command. Its fields and authority cannot be
/// constructed, cloned, serialized or inspected by a host adapter.
pub struct AdmittedManagementCommand {
    command: ManagementCommand,
    context: FinalizeContext,
    runtime: Arc<BrokerConfig>,
    identity_proof: Option<crate::AttestedIdentityProof>,
    origin: Option<SecretReferenceOrigin>,
    reservation: Option<SecretOutputReservationBatch>,
}
impl AdmittedManagementCommand {
    /// True only for an operation that may modify durable managed state.
    pub fn is_write(&self) -> bool {
        self.command.is_write()
    }
}

pub(crate) struct CapturedLocalOutput {
    pub(super) reservation: SecretOutputReservationBatch,
    pub(super) broker_request_id: String,
    pub(super) action: String,
    pub(super) references: Vec<CapturedSecretReference>,
}

pub(crate) fn valid_reference(value: &str) -> bool {
    super::secret_references::is_secret_reference_capability(value)
}

impl BrokerRuntime {
    pub(super) fn admit_management_command(
        &self,
        context: &FinalizeContext,
        inputs: &Value,
        proof: Option<&crate::AttestedIdentityProof>,
        outputs: &super::secret_references::PreparedSecretOutputs,
    ) -> Result<AdmittedManagementCommand, ProviderError> {
        if context.service != SERVICE_ID {
            return Err(unavailable());
        }
        let command = ManagementCommand::parse(&context.action, inputs)?;
        if command.scopes()? != context.resource_scopes {
            return Err(denied());
        }
        let execution_context = context.execution_context.as_ref().ok_or_else(denied)?;
        let identity_proof =
            if let Some(source) = context.identity.source.as_ref()
                && matches!(source.kind.as_str(), "trusted_user" | "forwarded_identity")
            {
                let proof = proof.ok_or_else(denied)?;
                if source.token_class != Some(BrokerTokenClass::AgentInvoke)
                    || source.token_id.is_some()
                    || proof.principal_id() != context.identity.principal
                    || proof.is_username() != (source.kind == "trusted_user")
                    || source.binding_id.as_deref() != proof.binding_id()
                    || source.namespace.as_deref() != proof.namespace()
                    || !context.identity.caller_id.as_ref().is_some_and(|caller| {
                        self.config.identity.trusted_callers.contains_key(caller)
                    })
                {
                    return Err(denied());
                }
                Some(proof.clone())
            } else {
                if proof.is_some() {
                    return Err(denied());
                }
                None
            };
        let origin = if matches!(
            command,
            ManagementCommand::CredentialInstall(_) | ManagementCommand::TokenCreate(_)
        ) {
            Some(
                self.secret_reference_origin(&context.identity, execution_context, proof)
                    .map_err(|_| denied())?,
            )
        } else {
            None
        };
        let reservation = outputs.local_reservation();
        if matches!(command, ManagementCommand::TokenCreate(_))
            && (self.config.secret_outputs.mode != crate::SecretOutputMode::Reference
                || reservation.is_none())
        {
            return Err(unavailable());
        }
        Ok(AdmittedManagementCommand {
            command,
            context: context.clone(),
            runtime: self.config.clone(),
            identity_proof,
            origin,
            reservation,
        })
    }

    /// Persist mandatory write intent before entering the local commit gate.
    /// This record contains canonical targets and authority, never action input.
    pub async fn preflight_management_command(
        &self,
        admitted: &AdmittedManagementCommand,
    ) -> Result<(), RuntimeError> {
        if !admitted.command.is_write() {
            return Ok(());
        }
        let context = &admitted.context;
        let identity = &context.identity;
        let record = AuditRecord {
            search_authorization: None,
            timestamp: Utc::now().to_rfc3339(),
            agent_request_id: context.agent_request_id.clone(),
            broker_request_id: context.broker_request_id.clone(),
            config_generation: self.config_generation,
            policy_generation: Some(context.policy_generation),
            principal_subject: identity.principal_subject.clone(),
            principal: identity.principal.clone(),
            groups: identity.groups.clone(),
            service: context.service.clone(),
            action: context.action.clone(),
            resource_scopes: context.resource_scopes.clone(),
            matched_grant: context.matched_grant.clone(),
            credential_mode: context.credential_mode.clone().map(Some),
            credential_connection: None,
            decision: Decision::Allow,
            reason_code: None,
            upstream_status: None,
            upstream_duration_ms: None,
            object_ids: None,
            identity_source: identity.source.clone(),
            caller_id: identity.caller_id.clone(),
            source: context.source.clone(),
            execution_context: context.execution_context.clone(),
            provider_audit: Some(
                json!({"phase":"preflight","executionState":"not_dispatched","retrySafe":false}),
            ),
        };
        self.audit.append_required(record).await
    }

    /// Execute a core-admitted capability under the host's snapshot fence.
    /// The host must retain this call and its terminal completion after dispatch.
    pub fn execute_management_command(
        &self,
        admitted: AdmittedManagementCommand,
    ) -> LocalOperationOutcome {
        let write = admitted.command.is_write();
        if let Some(reservation) = &admitted.reservation {
            reservation.mark_dispatched();
        }
        let result = self.execute_management_inner(&admitted);
        match result {
            Ok((mut value, captured)) => {
                if write {
                    value["executionState"] = json!("completed");
                    value["retrySafe"] = json!(false);
                }
                let audit = if write {
                    json!({"executionState":"completed","retrySafe":false,"command":value})
                } else {
                    json!({"readOnly":true,"command":value})
                };
                LocalOperationOutcome {
                    result: Ok(ProviderResult::new(value).with_audit(audit)),
                    captured,
                }
            }
            Err(error) => {
                let state = if matches!(error, CommandError::CommitUnknown) {
                    "unknown"
                } else if write {
                    "not_committed"
                } else {
                    "read"
                };
                let mut error = command_error(error);
                let mut evidence = error.result.take().map(|v| *v).unwrap_or_else(|| json!({}));
                if write {
                    evidence["executionState"] = json!(state);
                }
                evidence["retrySafe"] = json!(false);
                let audit = if write {
                    json!({"executionState":state,"retrySafe":false})
                } else {
                    json!({"readOnly":true,"retrySafe":false})
                };
                let error = error.with_result(evidence).with_audit(audit);
                if let (Some(store), Some(batch)) = (&self.managed_store, &admitted.reservation) {
                    let _ = store.finish_secret_reservation(
                        batch,
                        if state == "unknown" {
                            crate::managed_store::SecretReservationOutcome::Unknown
                        } else {
                            crate::managed_store::SecretReservationOutcome::CaptureFailed
                        },
                        json!({"executionState":state,"retrySafe":false}),
                    );
                }
                LocalOperationOutcome::rejected(error)
            }
        }
    }

    fn execute_management_inner(
        &self,
        admitted: &AdmittedManagementCommand,
    ) -> Result<(Value, Option<CapturedLocalOutput>), CommandError> {
        if !Arc::ptr_eq(&self.config, &admitted.runtime) {
            return Err(ManagedStoreError::VersionConflict.into());
        }
        let _policy_guard = if admitted.command.is_policy_write() {
            Some(self.managed_policy_mutation_guard()?)
        } else {
            None
        };
        let store = self
            .managed_store
            .as_ref()
            .ok_or_else(|| ManagedStoreError::Unavailable("managed store unavailable".into()))?;
        let baseline = if admitted.command.is_policy_write() {
            Some(store.policy_validation_baseline()?)
        } else {
            None
        };
        let (value, policy, references) =
            store.management_transaction(admitted.command.is_write(), |conn| {
                self.reauthorize_management_conn(conn, admitted)?;
                let actor = &admitted.context.identity.principal;
                let mut policy = None;
                let mut references = None;
                let value = match &admitted.command {
                    ManagementCommand::PrincipalCreate(v) => store
                        .create_delegated_principal_conn(
                            conn,
                            v.principal_id.clone(),
                            v.display_name.clone(),
                            actor,
                        )?,
                    ManagementCommand::SubjectAdd(v) | ManagementCommand::SubjectRemove(v) => {
                        let (value, _) = store::change_subject(
                            conn,
                            &v.principal_id,
                            &v.grant_id,
                            v.expected_version,
                            actor,
                            matches!(admitted.command, ManagementCommand::SubjectAdd(_)),
                            |grants, revision, subjects, catalog| {
                                self.validate_managed_policy_candidate_for_store(
                                    grants,
                                    revision,
                                    subjects,
                                    catalog,
                                    baseline.as_ref().expect("policy baseline"),
                                )?;
                                policy = Some(Arc::new(PolicySnapshot::from_managed(
                                    revision.generation,
                                    grants.to_vec(),
                                    catalog.clone(),
                                )));
                                Ok(())
                            },
                        )?;
                        value
                    }
                    ManagementCommand::CredentialView(v) => {
                        store::target_principal(conn, &v.principal_id, actor, false)?;
                        self.check_local_connection(&v.connection_id)?;
                        store::credential_summary(
                            conn,
                            &v.principal_id,
                            &v.connection_id,
                            "gitlab-access-token",
                            "bearer_token",
                        )?
                    }
                    ManagementCommand::CredentialInstall(v) => {
                        store::target_principal(conn, &v.principal_id, actor, true)?;
                        self.check_local_connection(&v.connection_id)?;
                        let ring = self.credential_key_ring.as_ref().ok_or_else(|| {
                            ManagedStoreError::Unavailable("credential key unavailable".into())
                        })?;
                        let origin = admitted
                            .origin
                            .as_ref()
                            .ok_or(CommandError::ReferenceDenied)?;
                        store::install_credential(
                            conn,
                            ring,
                            &v.principal_id,
                            &v.connection_id,
                            actor,
                            &v.token.secret_ref,
                            |conn, stored| {
                                self.check_secret_reference_owner_conn(conn, stored, origin)
                            },
                        )?
                    }
                    ManagementCommand::TokenCreate(v) => {
                        let (value, captured) = self.create_local_token_conn(conn, admitted, v)?;
                        references = Some(captured);
                        value
                    }
                    other => store::basic_operation(conn, other, actor)?,
                };
                Ok((value, policy, references))
            })?;
        if let Some(next) = policy {
            // Validation and snapshot construction completed before commit.
            // Retaining the policy mutex makes publication infallible here.
            self.policy_snapshot.store(next);
        }
        let captured = references.map(|references| {
            let reservation = admitted
                .reservation
                .as_ref()
                .expect("capture reservation")
                .clone();
            reservation.mark_completed();
            CapturedLocalOutput {
                reservation,
                broker_request_id: admitted.context.broker_request_id.clone(),
                action: admitted.context.action.clone(),
                references,
            }
        });
        Ok((value, captured))
    }

    fn reauthorize_management_conn(
        &self,
        conn: &Connection,
        admitted: &AdmittedManagementCommand,
    ) -> Result<(), CommandError> {
        if self.policy_generation() != admitted.context.policy_generation
            || store::policy_generation_conn(conn)? != admitted.context.policy_generation
        {
            return Err(ManagedStoreError::VersionConflict.into());
        }
        if let Some(origin) = &admitted.origin {
            self.check_secret_reference_origin_conn(conn, origin)
                .map_err(|_| CommandError::Denied)?;
        }
        if let Some(proof) = &admitted.identity_proof {
            // The host pins caller configuration at its snapshot fence. A read
            // may finish on that admitted snapshot after reload; a write holds
            // the fence through commit. Recheck the original human proof here
            // without requiring the durable caller generation used by secrets.
            proof
                .check_current_conn(conn)
                .map_err(|_| CommandError::Denied)?;
        }
        let identity = store::current_identity(conn, &admitted.context.identity)?;
        let context = admitted
            .context
            .execution_context
            .as_ref()
            .ok_or(CommandError::Denied)?;
        let snapshot = self.policy_snapshot();
        let parsed =
            parsed_agent_invoke_token_caveats(&identity).map_err(|_| CommandError::Denied)?;
        self.enforce_agent_invoke_token_caveats_with(
            parsed.as_ref(),
            SERVICE_ID,
            &admitted.context.action,
            context,
        )
        .map_err(|_| CommandError::Denied)?;
        self.enforce_agent_invoke_token_resource_caveats_with(
            &snapshot,
            context,
            parsed.as_ref(),
            SERVICE_ID,
            &admitted.context.action,
            &admitted.context.resource_scopes,
        )
        .map_err(|_| CommandError::Denied)?;
        let decision = self
            .select_policy(
                &snapshot,
                &identity,
                context,
                SERVICE_ID,
                &admitted.context.action,
                &admitted.context.resource_scopes,
            )
            .map_err(|_| CommandError::Denied)?;
        let expected = admitted
            .context
            .matched_grant
            .as_ref()
            .ok_or(CommandError::Denied)?;
        if decision.matched_grant.grant_id != expected.grant_id
            || decision.matched_grant.grant_version != expected.grant_version
            || decision.matched_grant.subject != expected.subject
        {
            return Err(CommandError::Denied);
        }
        Ok(())
    }

    fn check_local_connection(&self, id: &str) -> Result<(), CommandError> {
        let connection = self
            .effective_credentials
            .connections
            .get(id)
            .ok_or(ManagedStoreError::CredentialNotFound)?;
        if !matches!(
            crate::select(connection, Some(crate::PrincipalKind::ServiceAccount)),
            crate::Selection::Token(_)
        ) || self.connection_token_profile(id) != Some(("gitlab-access-token", "bearer_token"))
            || !self
                .effective_credentials
                .connection_consumers(id)
                .any(|service| {
                    service == "gitlab" && self.config.providers.registry().get(service).is_some()
                })
        {
            return Err(CommandError::ConnectionIneligible);
        }
        Ok(())
    }

    fn create_local_token_conn(
        &self,
        conn: &Connection,
        admitted: &AdmittedManagementCommand,
        input: &crate::management::TokenCreateInput,
    ) -> Result<(Value, Vec<CapturedSecretReference>), CommandError> {
        let actor = &admitted.context.identity.principal;
        store::target_principal(conn, &input.principal_id, actor, true)?;
        let grant = store::target_grant(conn, &input.grant_id, Some(input.expected_version))?;
        let groups = crate::managed_store::principal_policy_groups(conn, &input.principal_id)?;
        if !grant.subjects.iter().any(|subject| {
            subject == &format!("user:{}", input.principal_id)
                || subject
                    .strip_prefix("group:")
                    .is_some_and(|group| groups.iter().any(|g| g == group))
        }) {
            return Err(CommandError::Precondition("recipient_subject"));
        }
        let tokens =
            self.config.broker_tokens.as_ref().ok_or_else(|| {
                ManagedStoreError::Unavailable("token hashing unavailable".into())
            })?;
        if !tokens
            .admin_agent_invoke_ttl_options
            .iter()
            .any(|option| option.ttl_seconds() == Some(input.ttl_seconds))
        {
            return Err(ManagedStoreError::InputInvalid("token lifetime is invalid".into()).into());
        }
        let service = self
            .services
            .get(&grant.service)
            .filter(|_| grant.service != "broker" && grant.service != SERVICE_ID)
            .ok_or(CommandError::Ineligible)?;
        let scoped = !grant.resources.is_empty();
        let actions = grant
            .actions
            .iter()
            .filter(|action| {
                service
                    .action(action)
                    .is_some_and(|a| (!a.resource_scopes.is_empty()) == scoped)
            })
            .cloned()
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>();
        if actions.is_empty() {
            return Err(CommandError::Precondition("derived_authority"));
        }
        let snapshot = self.policy_snapshot();
        for context in &input.allowed_execution_contexts {
            if !grant.execution_contexts.contains(&context.to_string())
                || !self.configured_execution_contexts().contains(context)
            {
                return Err(ManagedStoreError::InputInvalid(
                    "token execution contexts are invalid".into(),
                )
                .into());
            }
            let usable = actions.iter().any(|action| {
                if !scoped {
                    return true;
                }
                self.action_resource_scopes(&grant.service, action)
                    .is_some_and(|scopes| {
                        !scopes.is_empty()
                            && scopes.iter().all(|scope| {
                                !snapshot
                                    .resources
                                    .resolve(
                                        &grant.resources,
                                        scope.resource_type.id(),
                                        context.as_str(),
                                    )
                                    .is_empty()
                            })
                    })
            });
            if !usable {
                return Err(CommandError::Precondition("derived_authority"));
            }
        }
        let caveats = AgentInvokeTokenCaveats {
            allowed_services: Some(vec![grant.service.clone()]),
            allowed_execution_contexts: Some(input.allowed_execution_contexts.clone()),
            service_restrictions: Some(BTreeMap::from([(
                grant.service.clone(),
                crate::AgentTokenServiceRestriction {
                    actions,
                    resources: scoped.then(|| grant.resources.clone()),
                },
            )])),
        };
        let scopes = serde_json::to_value(caveats)
            .map_err(|_| CommandError::Precondition("derived_authority"))?;
        AgentInvokeTokenCaveats::parse_issuance(&scopes, self.config.execution_context.as_ref())
            .map_err(|_| CommandError::Precondition("derived_authority"))?;
        store::token_id_absent(conn, &input.token_id)?;
        let ring = self
            .credential_key_ring
            .as_ref()
            .ok_or_else(|| ManagedStoreError::Unavailable("credential key unavailable".into()))?;
        let hasher = self
            .broker_token_hasher
            .as_ref()
            .ok_or_else(|| ManagedStoreError::Unavailable("token hashing unavailable".into()))?;
        let reservation = admitted
            .reservation
            .as_ref()
            .ok_or(CommandError::ReferenceDenied)?;
        let origin = admitted
            .origin
            .as_ref()
            .ok_or(CommandError::ReferenceDenied)?;
        ManagedStore::validate_local_reservation_conn(
            conn,
            ring,
            reservation,
            &admitted.context.broker_request_id,
            origin,
        )?;
        let catalog = store::resource_catalog_conn(conn)?;
        let (token, record) = ManagedStore::issue_token_conn(
            conn,
            hasher,
            crate::BrokerTokenIssueRequest {
                principal_id: input.principal_id.clone(),
                name: input.name.clone(),
                token_class: BrokerTokenClass::AgentInvoke,
                scopes,
                expires_at: None,
                created_by: actor.clone(),
            }
            .expires_after(input.ttl_seconds),
            false,
            Some(&catalog),
            &input.token_id,
        )?;
        let value = store::token_summary(&record);
        let references = ManagedStore::capture_outputs_conn(
            conn,
            ring,
            reservation,
            vec![SecretOutputCapture {
                pointer: "/result/issuedToken".into(),
                value: token.to_string(),
            }],
            json!({"executionState":"completed","retrySafe":false,"tokenId":input.token_id,"principalId":input.principal_id,"grantId":input.grant_id,"grantVersion":input.expected_version}),
        )?;
        Ok((value, references))
    }
}

pub(super) fn unavailable() -> ProviderError {
    ProviderError::domain(&UNAVAILABLE, "local management operation is unavailable")
}
fn denied() -> ProviderError {
    ProviderError::deny(
        ReasonCode::ServiceActionDenied,
        "management action is not authorized",
    )
}
fn command_error(error: CommandError) -> ProviderError {
    match error {
        CommandError::CommitUnknown => ProviderError::error(
            ReasonCode::OperationFailed,
            "management commit outcome could not be established",
        ),
        CommandError::Denied => denied(),
        CommandError::Ineligible => {
            ProviderError::domain(&TARGET_INELIGIBLE, "management target is ineligible")
        }
        CommandError::Exists | CommandError::Store(ManagedStoreError::PrincipalAlreadyExists) => {
            ProviderError::domain(&TARGET_EXISTS, "management target already exists")
        }
        CommandError::Precondition(label) => ProviderError::domain(
            &PRECONDITION_FAILED,
            "management operation precondition failed",
        )
        .with_result(json!({"precondition":label})),
        CommandError::ConnectionIneligible => ProviderError::domain(
            &CONNECTION_INELIGIBLE,
            "credential connection is ineligible",
        ),
        CommandError::ReferenceDenied => ProviderError::domain(
            &REFERENCE_DENIED,
            "secret reference is unavailable for this operation",
        ),
        CommandError::Store(ManagedStoreError::VersionConflict) => ProviderError::deny(
            ReasonCode::VersionConflict,
            "management operation version changed",
        ),
        CommandError::Store(
            ManagedStoreError::PrincipalNotFound
            | ManagedStoreError::GroupNotFound
            | ManagedStoreError::PolicyGrantNotFound
            | ManagedStoreError::CredentialNotFound
            | ManagedStoreError::BrokerTokenNotFound,
        ) => ProviderError::deny(
            ReasonCode::ResourceNotFound,
            "management resource was not found",
        ),
        CommandError::Store(
            ManagedStoreError::InputInvalid(_) | ManagedStoreError::PolicyValidationIssues(_),
        ) => ProviderError::deny(
            ReasonCode::InputInvalid,
            "management action inputs are invalid",
        ),
        CommandError::Store(_) => unavailable(),
    }
}
