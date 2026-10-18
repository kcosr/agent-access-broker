//! Shared transaction operations. Authorization is supplied by core while the
//! connection is locked; no public scope value can authorize these helpers.
use super::*;
use crate::management::{CommandError, ManagementCommand};
use serde_json::json;

type Result<T> = std::result::Result<T, CommandError>;

impl ManagedStore {
    pub(crate) fn management_transaction<T>(
        &self,
        write: bool,
        operation: impl FnOnce(&Connection) -> Result<T>,
    ) -> Result<T> {
        let mut conn = self
            .connection
            .lock()
            .map_err(|_| ManagedStoreError::Unavailable("managed store lock unavailable".into()))?;
        let tx = conn
            .transaction_with_behavior(if write {
                TransactionBehavior::Immediate
            } else {
                TransactionBehavior::Deferred
            })
            .map_err(sql_unavailable)?;
        let result = operation(&tx)?;
        tx.commit().map_err(|_| CommandError::CommitUnknown)?;
        Ok(result)
    }
    pub(crate) fn create_delegated_principal_conn(
        &self,
        conn: &Connection,
        principal_id: String,
        display_name: Option<String>,
        actor: &str,
    ) -> Result<Value> {
        if principal_id == actor {
            return Err(CommandError::Ineligible);
        }
        let record = self.create_principal_conn(
            conn,
            PrincipalWriteRequest {
                principal_id,
                kind: "service_account".into(),
                display_name,
                email: None,
                external_subject: None,
                created_by: actor.into(),
                role: PrincipalRole::User,
                self_service_enabled: Some(false),
            },
        )?;
        Ok(principal_summary(&record))
    }
}

pub(crate) fn current_identity(
    conn: &Connection,
    identity: &crate::IdentityContext,
) -> Result<crate::IdentityContext> {
    let mut current = identity.clone();
    if !identity.authenticated {
        return Err(CommandError::Denied);
    }
    let principal = principal_by_id(conn, &identity.principal).map_err(|_| CommandError::Denied)?;
    if principal.status != "active" {
        return Err(CommandError::Denied);
    }
    current.policy_groups = principal_policy_groups(conn, &identity.principal)?;
    if let Some(source) = current.source.as_mut()
        && source.kind == "broker_tokens"
    {
        let id = source.token_id.as_deref().ok_or(CommandError::Denied)?;
        let token = broker_token_by_id(conn, id).map_err(|_| CommandError::Denied)?;
        if token.principal_id != identity.principal
            || token.token_class != BrokerTokenClass::AgentInvoke
            || token.revoked_at.is_some()
            || token.paused_at.is_some()
            || timestamp_is_past(token.expires_at.as_deref())
        {
            return Err(CommandError::Denied);
        }
        source.token_scopes = Some(token.scopes);
    }
    Ok(current)
}

pub(crate) fn target_principal(
    conn: &Connection,
    id: &str,
    actor: &str,
    write: bool,
) -> Result<PrincipalRecord> {
    let principal = principal_by_id_without_groups(conn, id)?;
    if principal.kind != "service_account"
        || (write && (principal.status != "active" || id == actor))
    {
        return Err(CommandError::Ineligible);
    }
    Ok(principal)
}
pub(crate) fn target_grant(
    conn: &Connection,
    id: &str,
    version: Option<i64>,
) -> Result<ManagedPolicyGrantRecord> {
    let grant = policy_grant_by_id(conn, id)?;
    if let Some(version) = version {
        if grant.version != version {
            return Err(ManagedStoreError::VersionConflict.into());
        }
        if grant.status != "active" || grant.service == "broker_management" {
            return Err(CommandError::Ineligible);
        }
    }
    Ok(grant)
}
pub(crate) fn principal_summary(value: &PrincipalRecord) -> Value {
    json!({"principalId":value.principal_id,"displayName":value.display_name,"kind":value.kind,"role":value.role,"selfServiceEnabled":value.self_service_enabled,"status":value.status,"createdAt":value.created_at,"updatedAt":value.updated_at})
}
pub(crate) fn grant_summary(value: &ManagedPolicyGrantRecord) -> Value {
    json!({"grantId":value.grant_id,"version":value.version,"status":value.status,"description":value.description,"service":value.service,"actions":value.actions,"resources":value.resources,"executionContexts":value.execution_contexts,"credentialMode":value.credential_mode,"priority":value.priority,"livePolicy":true})
}
pub(crate) fn token_summary(value: &BrokerTokenRecord) -> Value {
    json!({"tokenId":value.token_id,"principalId":value.principal_id,"name":value.name,"tokenClass":value.token_class,"scopes":value.scopes,"createdAt":value.created_at,"expiresAt":value.expires_at,"paused":value.paused_at.is_some(),"revoked":value.revoked_at.is_some(),"expired":timestamp_is_past(value.expires_at.as_deref()),"lastUsedAt":value.last_used_at})
}

pub(crate) fn basic_operation(
    conn: &Connection,
    command: &ManagementCommand,
    actor: &str,
) -> Result<Value> {
    use ManagementCommand::*;
    match command {
        PrincipalView(v) => Ok(principal_summary(&target_principal(
            conn,
            &v.principal_id,
            actor,
            false,
        )?)),
        GroupView(v) => {
            let group = group_by_id(conn, &v.group_id)?;
            Ok(
                json!({"groupId":group.group_id,"displayName":group.display_name,"description":group.description,"status":group.status,"livePolicy":true}),
            )
        }
        MemberView(v) | MemberAdd(v) | MemberRemove(v) => {
            let write = command.is_write();
            let principal = target_principal(conn, &v.principal_id, actor, write)?;
            let group = group_by_id(conn, &v.group_id)?;
            if write {
                if group.status != "active" {
                    return Err(CommandError::Ineligible);
                }
                let protected:bool=conn.query_row("SELECT EXISTS(SELECT 1 FROM policy_grants g JOIN policy_grant_subjects s ON s.grant_id=g.grant_id WHERE g.service='broker_management' AND g.status IN ('active','disabled') AND s.subject=?1)",[format!("group:{}",v.group_id)],|row|row.get(0)).map_err(sql_unavailable)?;
                if protected {
                    return Err(CommandError::Ineligible);
                }
            }
            let changed = match command {
                MemberAdd(_) => add_group_conn(conn, &v.principal_id, &v.group_id, actor)?,
                MemberRemove(_) => remove_group_conn(conn, &v.principal_id, &v.group_id)?,
                _ => false,
            };
            let local_member:bool=conn.query_row("SELECT EXISTS(SELECT 1 FROM principal_groups WHERE principal_id=?1 AND group_id=?2)",params![v.principal_id,v.group_id],|row|row.get(0)).map_err(sql_unavailable)?;
            let effective_member =
                effective_membership_at_conn(conn, &v.principal_id, &normalized_now_string())?
                    .groups
                    .contains(&v.group_id);
            Ok(
                json!({"principalId":v.principal_id,"groupId":v.group_id,"principalStatus":principal.status,"groupStatus":group.status,"changed":changed,"localMember":local_member,"effectiveMember":effective_member}),
            )
        }
        GrantView(v) => Ok(grant_summary(&target_grant(conn, &v.grant_id, None)?)),
        SubjectView(v) => {
            let principal = target_principal(conn, &v.principal_id, actor, false)?;
            let grant = target_grant(conn, &v.grant_id, None)?;
            Ok(subject_summary(&principal, &grant, false))
        }
        TokenView(v) => {
            target_principal(conn, &v.principal_id, actor, false)?;
            // Ownership and class are part of the SELECT, never filtered after
            // a global token lookup that could disclose another owner's row.
            let token=conn.query_row("SELECT token_id, token_hash, principal_id, name, token_class, scopes_json, created_at, expires_at, revoked_at, revoked_by, paused_at, paused_by, last_used_at, created_by FROM broker_tokens WHERE token_id=?1 AND principal_id=?2 AND token_class='agent_invoke'",params![v.token_id,v.principal_id],broker_token_from_row).optional().map_err(sql_unavailable)?.ok_or(ManagedStoreError::BrokerTokenNotFound)?;
            Ok(token_summary(&token))
        }
        _ => Err(ManagedStoreError::InputInvalid("unsupported local operation".into()).into()),
    }
}

pub(super) fn add_group_conn(
    conn: &Connection,
    principal_id: &str,
    group: &str,
    actor: &str,
) -> std::result::Result<bool, ManagedStoreError> {
    validate_principal_id(principal_id)?;
    validate_group_name(group)?;
    validate_actor(actor)?;
    principal_by_id_for_membership(conn, principal_id)?;
    group_by_id(conn, group)?;
    Ok(conn.execute("INSERT OR IGNORE INTO principal_groups (principal_id,group_id,created_at,created_by) VALUES (?1,?2,?3,?4)",params![principal_id,group,now_string(),actor]).map_err(sql_unavailable)?!=0)
}
pub(super) fn remove_group_conn(
    conn: &Connection,
    principal_id: &str,
    group: &str,
) -> std::result::Result<bool, ManagedStoreError> {
    validate_principal_id(principal_id)?;
    validate_group_name(group)?;
    principal_by_id_for_membership(conn, principal_id)?;
    group_by_id(conn, group)?;
    Ok(conn
        .execute(
            "DELETE FROM principal_groups WHERE principal_id=?1 AND group_id=?2",
            params![principal_id, group],
        )
        .map_err(sql_unavailable)?
        != 0)
}
fn subject_summary(
    principal: &PrincipalRecord,
    grant: &ManagedPolicyGrantRecord,
    changed: bool,
) -> Value {
    json!({"principalId":principal.principal_id,"grantId":grant.grant_id,"principalStatus":principal.status,"grantStatus":grant.status,"directSubject":grant.subjects.contains(&format!("user:{}",principal.principal_id)),"version":grant.version,"changed":changed})
}
pub(crate) fn change_subject(
    conn: &Connection,
    principal_id: &str,
    grant_id: &str,
    expected_version: i64,
    actor: &str,
    add: bool,
    validate: impl FnOnce(
        &[ManagedPolicyGrantRecord],
        &ManagedPolicyRevision,
        &ManagedPolicySubjectCatalog,
        &ManagedResourceCatalog,
    ) -> std::result::Result<(), ManagedStoreError>,
) -> Result<(Value, ManagedPolicyMutationResult)> {
    let principal = target_principal(conn, principal_id, actor, true)?;
    let mut grant = target_grant(conn, grant_id, Some(expected_version))?;
    let subject = format!("user:{principal_id}");
    if grant.subjects.contains(&subject) == add {
        return Err(input_invalid("direct grant subject state does not permit this change").into());
    }
    if !add && grant.subjects.len() == 1 {
        return Err(CommandError::Precondition("last_subject"));
    }
    grant = mutate_grant_subject_conn(grant, &subject, actor, add, false)?;
    let active_grants = active_policy_grants_with_replacement(conn, Some(grant.clone()), None)?;
    let previous_revision = policy_revision(conn)?;
    let revision = next_policy_revision(&previous_revision, &grant.updated_at, actor)?;
    let catalog = resource_catalog(conn)?;
    let subjects = policy_subject_catalog(conn)?;
    validate_grant_resource_references(&active_grants, &catalog)?;
    validate(&active_grants, &revision, &subjects, &catalog)?;
    update_policy_grant_record(conn, &grant)?;
    update_policy_revision(conn, &revision)?;
    Ok((
        subject_summary(&principal, &grant, true),
        ManagedPolicyMutationResult {
            catalog,
            previous_revision,
            revision,
            grant,
            active_grants,
        },
    ))
}

pub(crate) fn credential_summary(
    conn: &Connection,
    principal_id: &str,
    connection: &str,
    profile: &str,
    kind: &str,
) -> Result<Value> {
    let credential = match credential_metadata_by_tuple(
        conn,
        principal_id,
        connection,
        crate::CONNECTION_CREDENTIAL_NAME,
    ) {
        Ok(v) => Some(v),
        Err(ManagedStoreError::CredentialNotFound) => None,
        Err(e) => return Err(e.into()),
    };
    Ok(match credential {
        Some(v) => {
            json!({"principalId":principal_id,"connectionId":connection,"profile":profile,"credentialKind":kind,"present":true,"status":v.status,"version":v.material_version,"lastVerifiedAt":v.last_verified_at,"verificationStatus":v.verification_status,"lastVerificationAttemptAt":v.last_verification_attempt_at,"lastVerificationErrorCode":v.last_verification_error_code})
        }
        None => {
            json!({"principalId":principal_id,"connectionId":connection,"profile":profile,"credentialKind":kind,"present":false})
        }
    })
}
pub(crate) fn install_credential(
    conn: &Connection,
    ring: &CredentialKeyRing,
    principal_id: &str,
    connection: &str,
    actor: &str,
    reference: &str,
    authorize: impl Fn(
        &Connection,
        &crate::runtime::secret_reference_identity::SecretReferenceOrigin,
    ) -> std::result::Result<(), ManagedStoreError>,
) -> Result<(Value, SecretReferenceUse)> {
    let occupied:bool=conn.query_row("SELECT EXISTS(SELECT 1 FROM credentials WHERE owner_kind='user' AND owner_principal_id=?1 AND service=?2 AND name=?3)",params![principal_id,connection,crate::CONNECTION_CREDENTIAL_NAME],|row|row.get(0)).map_err(sql_unavailable)?;
    if occupied {
        return Err(CommandError::Exists);
    }
    let (token, usage) =
        secret_references::resolve_credential_reference_conn(conn, ring, reference, &authorize)
            .map_err(|_| CommandError::ReferenceDenied)?;
    let token = zeroize::Zeroizing::new(token);
    let mut secret = json!({"token":token.as_str()});
    let result = upsert_user_credential_conn(
        conn,
        ring,
        CredentialWriteRequest {
            owner_principal_id: principal_id.into(),
            service: connection.into(),
            name: crate::CONNECTION_CREDENTIAL_NAME.into(),
            profile: "gitlab-access-token".into(),
            credential_kind: "bearer_token".into(),
            secret: secret.take(),
            metadata: json!({}),
            actor: actor.into(),
        },
        CredentialManagementPurpose::Administrative,
    );
    result?;
    let value = credential_summary(
        conn,
        principal_id,
        connection,
        "gitlab-access-token",
        "bearer_token",
    )?;
    Ok((value, usage))
}
pub(crate) fn token_id_absent(conn: &Connection, id: &str) -> Result<()> {
    let exists: bool = conn
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM broker_tokens WHERE token_id=?1)",
            [id],
            |row| row.get(0),
        )
        .map_err(sql_unavailable)?;
    if exists {
        Err(CommandError::Exists)
    } else {
        Ok(())
    }
}
pub(crate) fn resource_catalog_conn(
    conn: &Connection,
) -> std::result::Result<ManagedResourceCatalog, ManagedStoreError> {
    resource_catalog(conn)
}

/// The existing administrator and delegated adapters share subject mutation
/// semantics after independently checking their own authority and eligibility.
pub(super) fn mutate_grant_subject_conn(
    mut grant: ManagedPolicyGrantRecord,
    subject: &str,
    actor: &str,
    add: bool,
    disable_final: bool,
) -> std::result::Result<ManagedPolicyGrantRecord, ManagedStoreError> {
    if grant.subjects.iter().any(|value| value == subject) == add {
        return Err(input_invalid(if add {
            "subject is already attached to policy grant"
        } else {
            "subject is not attached to policy grant"
        }));
    }
    let now = normalized_now_string();
    if add {
        grant.subjects.push(subject.into());
    } else {
        grant.subjects.retain(|value| value != subject);
    }
    if grant.subjects.is_empty() && grant.status == "active" {
        if disable_final {
            grant.status = "disabled".into();
            grant.disabled_at = Some(now.clone());
            grant.deleted_at = None;
        } else {
            return Err(ManagedStoreError::PolicyValidationIssues(vec![PolicyValidationIssue { field:"subjects".into(),code:"empty".into(),message:"active policy grants must have at least one subject; use lastSubjectBehavior=disable_grant to remove the final subject".into() }]));
        }
    }
    grant.version += 1;
    grant.updated_at = now;
    grant.updated_by = actor.into();
    Ok(grant)
}

pub(crate) fn policy_generation_conn(
    conn: &Connection,
) -> std::result::Result<u64, ManagedStoreError> {
    Ok(policy_revision(conn)?.generation)
}

impl ManagedStore {
    pub fn create_principal_with_management_authority(
        &self,
        request: PrincipalWriteRequest,
        authority: crate::ManagementAuthority,
    ) -> std::result::Result<crate::ManagementMutation<PrincipalRecord>, ManagedStoreError> {
        let mut conn = self
            .connection
            .lock()
            .map_err(|_| ManagedStoreError::Unavailable("managed store lock unavailable".into()))?;
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sql_unavailable)?;
        let actor = authority.check_conn(&tx, crate::ManagementOperation::PrincipalCreate)?;
        if actor.principal != request.created_by {
            return Err(ManagedStoreError::ManagementDenied);
        }
        let value = self.create_principal_conn(&tx, request)?;
        let audit = json!({"principal":principal_summary(&value),"changed":true});
        tx.commit().map_err(|_| ManagedStoreError::CommitUnknown)?;
        Ok(crate::ManagementMutation { value, audit })
    }
    pub fn add_group_with_management_authority(
        &self,
        principal: &str,
        group: &str,
        actor: &str,
        authority: crate::ManagementAuthority,
    ) -> std::result::Result<crate::ManagementMutation<()>, ManagedStoreError> {
        let mut conn = self
            .connection
            .lock()
            .map_err(|_| ManagedStoreError::Unavailable("managed store lock unavailable".into()))?;
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sql_unavailable)?;
        let current = authority.check_conn(&tx, crate::ManagementOperation::GroupMemberAdd)?;
        if current.principal != actor {
            return Err(ManagedStoreError::ManagementDenied);
        }
        let changed = add_group_conn(&tx, principal, group, actor)?;
        let effective = effective_membership_at_conn(&tx, principal, &normalized_now_string())?
            .groups
            .iter()
            .any(|candidate| candidate == group);
        let audit = json!({"principalId":principal,"groupId":group,"changed":changed,"localMember":true,"effectiveMember":effective});
        tx.commit().map_err(|_| ManagedStoreError::CommitUnknown)?;
        Ok(crate::ManagementMutation { value: (), audit })
    }
    pub fn remove_local_group_with_management_authority(
        &self,
        principal: &str,
        group: &str,
        authority: crate::ManagementAuthority,
    ) -> std::result::Result<crate::ManagementMutation<LocalGroupRemovalResult>, ManagedStoreError>
    {
        let mut conn = self
            .connection
            .lock()
            .map_err(|_| ManagedStoreError::Unavailable("managed store lock unavailable".into()))?;
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sql_unavailable)?;
        authority.check_conn(&tx, crate::ManagementOperation::GroupMemberRemove)?;
        let removed = remove_group_conn(&tx, principal, group)?;
        let still_effective =
            effective_membership_at_conn(&tx, principal, &normalized_now_string())?
                .groups
                .iter()
                .any(|candidate| candidate == group);
        let audit = json!({"principalId":principal,"groupId":group,"changed":removed,"localMember":false,"effectiveMember":still_effective});
        tx.commit().map_err(|_| ManagedStoreError::CommitUnknown)?;
        Ok(crate::ManagementMutation {
            value: LocalGroupRemovalResult {
                removed,
                still_effective,
            },
            audit,
        })
    }
    pub fn issue_broker_token_with_management_authority(
        &self,
        hasher: &BrokerTokenHasher,
        request: BrokerTokenIssueRequest,
        catalog: Option<&ManagedResourceCatalog>,
        authority: crate::ManagementAuthority,
    ) -> std::result::Result<crate::ManagementMutation<IssuedBrokerToken>, ManagedStoreError> {
        self.issue_authorized_token_conn(hasher, request, catalog, authority, false)
    }
    pub fn issue_self_agent_token_with_management_authority(
        &self,
        hasher: &BrokerTokenHasher,
        request: SelfAgentTokenIssueRequest,
        catalog: Option<&ManagedResourceCatalog>,
        authority: crate::ManagementAuthority,
    ) -> std::result::Result<crate::ManagementMutation<IssuedBrokerToken>, ManagedStoreError> {
        validate_self_agent_token_issue_request(&request)?;
        self.issue_authorized_token_conn(
            hasher,
            BrokerTokenIssueRequest {
                principal_id: request.principal_id,
                name: request.name,
                token_class: BrokerTokenClass::AgentInvoke,
                scopes: request.scopes,
                expires_at: request.expires_at,
                created_by: request.created_by,
            },
            catalog,
            authority,
            true,
        )
    }
    fn issue_authorized_token_conn(
        &self,
        hasher: &BrokerTokenHasher,
        request: BrokerTokenIssueRequest,
        catalog: Option<&ManagedResourceCatalog>,
        authority: crate::ManagementAuthority,
        personal: bool,
    ) -> std::result::Result<crate::ManagementMutation<IssuedBrokerToken>, ManagedStoreError> {
        let mut conn = self
            .connection
            .lock()
            .map_err(|_| ManagedStoreError::Unavailable("managed store lock unavailable".into()))?;
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sql_unavailable)?;
        let actor = authority.check_conn(
            &tx,
            if personal {
                crate::ManagementOperation::PersonalTokenIssue
            } else {
                crate::ManagementOperation::AdminTokenIssue
            },
        )?;
        if actor.principal != request.created_by
            || (personal && actor.principal != request.principal_id)
        {
            return Err(ManagedStoreError::ManagementDenied);
        }
        let (raw, record) = Self::issue_token_conn(
            &tx,
            hasher,
            request,
            personal,
            catalog,
            &Uuid::new_v4().to_string(),
        )?;
        let audit = token_summary(&record);
        tx.commit().map_err(|_| ManagedStoreError::CommitUnknown)?;
        Ok(crate::ManagementMutation {
            value: IssuedBrokerToken {
                token: raw.to_string(),
                record,
            },
            audit,
        })
    }
    pub fn add_policy_grant_subject_with_management_authority<F>(
        &self,
        request: ManagedPolicyGrantSubjectAddRequest,
        authority: crate::ManagementAuthority,
        validate: F,
    ) -> std::result::Result<
        crate::ManagementMutation<ManagedPolicyMutationResult>,
        ManagedStoreError,
    >
    where
        F: FnMut(
            &[ManagedPolicyGrantRecord],
            &ManagedPolicyRevision,
            &ManagedPolicySubjectCatalog,
            &ManagedResourceCatalog,
        ) -> std::result::Result<(), ManagedStoreError>,
    {
        validate_policy_grant_subject_add_request(&request)?;
        self.management_subject_mutation(
            ManagedPolicyGrantSubjectRemoveRequest {
                grant_id: request.grant_id,
                expected_version: request.expected_version,
                subject: request.subject,
                last_subject_behavior: "reject".into(),
                updated_by: request.updated_by,
            },
            authority,
            true,
            validate,
        )
    }
    pub fn remove_policy_grant_subject_with_management_authority<F>(
        &self,
        request: ManagedPolicyGrantSubjectRemoveRequest,
        authority: crate::ManagementAuthority,
        validate: F,
    ) -> std::result::Result<
        crate::ManagementMutation<ManagedPolicyMutationResult>,
        ManagedStoreError,
    >
    where
        F: FnMut(
            &[ManagedPolicyGrantRecord],
            &ManagedPolicyRevision,
            &ManagedPolicySubjectCatalog,
            &ManagedResourceCatalog,
        ) -> std::result::Result<(), ManagedStoreError>,
    {
        validate_policy_grant_subject_remove_request(&request)?;
        self.management_subject_mutation(request, authority, false, validate)
    }
    fn management_subject_mutation<F>(
        &self,
        request: ManagedPolicyGrantSubjectRemoveRequest,
        authority: crate::ManagementAuthority,
        add: bool,
        validate: F,
    ) -> std::result::Result<
        crate::ManagementMutation<ManagedPolicyMutationResult>,
        ManagedStoreError,
    >
    where
        F: FnMut(
            &[ManagedPolicyGrantRecord],
            &ManagedPolicyRevision,
            &ManagedPolicySubjectCatalog,
            &ManagedResourceCatalog,
        ) -> std::result::Result<(), ManagedStoreError>,
    {
        let mut conn = self
            .connection
            .lock()
            .map_err(|_| ManagedStoreError::Unavailable("managed store lock unavailable".into()))?;
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sql_unavailable)?;
        let actor = authority.check_conn(
            &tx,
            if add {
                crate::ManagementOperation::GrantSubjectAdd
            } else {
                crate::ManagementOperation::GrantSubjectRemove
            },
        )?;
        if actor.principal != request.updated_by {
            return Err(ManagedStoreError::ManagementDenied);
        }
        let current = policy_grant_by_id(&tx, &request.grant_id)?;
        ensure_policy_management_scope(&actor.policy_write_scope, &current.service)?;
        ensure_policy_grant_version(&current, request.expected_version)?;
        if current.status == "deleted" {
            return Err(input_invalid(
                "deleted policy grants cannot have subjects changed",
            ));
        }
        let previous_version = current.version;
        let updated = mutate_grant_subject_conn(
            current,
            &request.subject,
            &request.updated_by,
            add,
            request.last_subject_behavior == "disable_grant",
        )?;
        let active_grants =
            active_policy_grants_with_replacement(&tx, Some(updated.clone()), None)?;
        let previous_revision = policy_revision(&tx)?;
        let revision =
            next_policy_revision(&previous_revision, &updated.updated_at, &updated.updated_by)?;
        let audit = json!({"grantId":updated.grant_id,"service":updated.service,"subject":request.subject,"changed":true,"attached":add,"previousVersion":previous_version,"version":updated.version,"status":updated.status});
        let inactive = (updated.status != "active").then_some(updated.clone());
        let value = finalize_policy_mutation(
            tx,
            previous_revision,
            revision,
            active_grants,
            inactive,
            validate,
            |tx, revision| {
                update_policy_grant_record(tx, &updated)?;
                update_policy_revision(tx, revision)?;
                Ok(updated.clone())
            },
        )?;
        Ok(crate::ManagementMutation { value, audit })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::management::{MembershipInput, PrincipalInput};
    fn fixture() -> (tempfile::TempDir, ManagedStore) {
        let directory = tempfile::tempdir().unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
        }
        let store = ManagedStore::open(
            &ManagedStoreConfig {
                kind: "sqlite".into(),
                path: directory.path().join("state.sqlite").display().to_string(),
                require_registered_principal_for_invocation: false,
                auto_migrate: true,
            },
            ManagedStoreOpenMode::Startup,
        )
        .unwrap();
        store
            .create_principal(PrincipalWriteRequest {
                principal_id: "worker".into(),
                kind: "service_account".into(),
                display_name: None,
                email: None,
                external_subject: None,
                created_by: "admin".into(),
                role: PrincipalRole::User,
                self_service_enabled: Some(false),
            })
            .unwrap();
        store
            .create_group(GroupWriteRequest {
                group_id: "workers".into(),
                display_name: None,
                description: None,
                created_by: "admin".into(),
            })
            .unwrap();
        (directory, store)
    }
    fn edge() -> MembershipInput {
        MembershipInput {
            principal_id: "worker".into(),
            group_id: "workers".into(),
        }
    }
    fn grant(
        store: &ManagedStore,
        service: &str,
        subjects: Vec<String>,
    ) -> ManagedPolicyGrantRecord {
        store
            .create_policy_grant(
                ManagedPolicyGrantCreateRequest {
                    grant_id: Some("target-grant".into()),
                    subjects,
                    execution_contexts: vec!["default".into()],
                    service: service.into(),
                    actions: vec!["echo".into()],
                    resources: ResourceSelection::default(),
                    credential_mode: "service".into(),
                    priority: None,
                    status: None,
                    description: None,
                    created_by: "admin".into(),
                },
                |_, _, _, _| Ok(()),
            )
            .unwrap()
            .grant
    }
    #[test]
    fn delegated_membership_noop_rechecks_protection_and_disabled_targets() {
        let (_directory, store) = fixture();
        let first = store
            .management_transaction(true, |conn| {
                basic_operation(conn, &ManagementCommand::MemberAdd(edge()), "operator")
            })
            .unwrap();
        assert_eq!(first["changed"], true);
        let noop = store
            .management_transaction(true, |conn| {
                basic_operation(conn, &ManagementCommand::MemberAdd(edge()), "operator")
            })
            .unwrap();
        assert_eq!(noop["changed"], false);
        let protected = grant(&store, "broker_management", vec!["group:workers".into()]);
        assert!(matches!(
            store.management_transaction(true, |conn| basic_operation(
                conn,
                &ManagementCommand::MemberAdd(edge()),
                "operator"
            )),
            Err(CommandError::Ineligible)
        ));
        store
            .disable_policy_grant(
                ManagedPolicyGrantStatusRequest {
                    grant_id: protected.grant_id,
                    expected_version: protected.version,
                    updated_by: "admin".into(),
                },
                |_, _, _, _| Ok(()),
            )
            .unwrap();
        for command in [
            ManagementCommand::MemberAdd(edge()),
            ManagementCommand::MemberRemove(edge()),
        ] {
            assert!(matches!(
                store.management_transaction(true, |conn| basic_operation(
                    conn, &command, "operator"
                )),
                Err(CommandError::Ineligible)
            ));
        }
        assert!(matches!(
            store.management_transaction(true, |conn| basic_operation(
                conn,
                &ManagementCommand::MemberRemove(edge()),
                "operator"
            )),
            Err(CommandError::Ineligible)
        ));
        let read = store
            .management_transaction(false, |conn| {
                basic_operation(conn, &ManagementCommand::MemberView(edge()), "operator")
            })
            .unwrap();
        assert_eq!(read["localMember"], true);
        assert!(read.get("members").is_none());
    }
    #[test]
    fn delegated_principal_create_is_insert_only_and_safe_read_omits_inventory() {
        let (_directory, store) = fixture();
        assert!(matches!(
            store.management_transaction(true, |conn| store.create_delegated_principal_conn(
                conn,
                "worker".into(),
                None,
                "operator"
            )),
            Err(CommandError::Store(
                ManagedStoreError::PrincipalAlreadyExists
            ))
        ));
        let read = store
            .management_transaction(false, |conn| {
                basic_operation(
                    conn,
                    &ManagementCommand::PrincipalView(PrincipalInput {
                        principal_id: "worker".into(),
                    }),
                    "operator",
                )
            })
            .unwrap();
        assert_eq!(read["selfServiceEnabled"], false);
        for field in ["groups", "signInMethods", "externalSubject", "createdBy"] {
            assert!(read.get(field).is_none());
        }
        assert!(matches!(
            store.management_transaction(true, |conn| basic_operation(
                conn,
                &ManagementCommand::MemberRemove(edge()),
                "worker"
            )),
            Err(CommandError::Ineligible)
        ));
    }
    #[test]
    fn delegated_subject_last_removal_rolls_back_and_never_disables() {
        let (_directory, store) = fixture();
        let record = grant(&store, "fake", vec!["user:worker".into()]);
        let error = store
            .management_transaction(true, |conn| {
                change_subject(
                    conn,
                    "worker",
                    &record.grant_id,
                    record.version,
                    "operator",
                    false,
                    |_, _, _, _| Ok(()),
                )
            })
            .unwrap_err();
        assert!(matches!(error, CommandError::Precondition("last_subject")));
        let after = store.policy_grant(&record.grant_id).unwrap();
        assert_eq!(after.status, "active");
        assert_eq!(after.version, record.version);
    }
    #[test]
    fn current_identity_reads_live_membership() {
        let (_directory, store) = fixture();
        let mut identity = crate::IdentityContext::anonymous();
        identity.principal = "worker".into();
        identity.authenticated = true;
        identity.policy_groups = vec!["stale".into()];
        store.add_group("worker", "workers", "admin").unwrap();
        let current = store
            .management_transaction(false, |conn| current_identity(conn, &identity))
            .unwrap();
        assert!(current.policy_groups.contains(&"workers".into()));
        assert!(!current.policy_groups.contains(&"stale".into()));
    }
}
