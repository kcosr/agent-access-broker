//! Sealed authority for existing HTTP management commands. This is an
//! application cooperation boundary, never part of the provider SDK.
use super::*;
use rusqlite::Connection;
use zeroize::Zeroizing;

/// The existing route contract being admitted. Choosing a variant supplies no
/// authority: core independently verifies credentials and current account state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ManagementOperation {
    PrincipalCreate,
    GroupMemberAdd,
    GroupMemberRemove,
    AdminTokenIssue,
    PersonalTokenIssue,
    GrantSubjectAdd,
    GrantSubjectRemove,
    AdminCredentialPut,
    PersonalCredentialPut,
}
impl ManagementOperation {
    pub(crate) fn personal(self) -> bool {
        matches!(self, Self::PersonalTokenIssue | Self::PersonalCredentialPut)
    }
    pub(crate) fn policy(self) -> bool {
        matches!(self, Self::GrantSubjectAdd | Self::GrantSubjectRemove)
    }
}

/// A verified, single-use management capability. It cannot be constructed from
/// an actor name or a policy scope, cloned, serialized, or inspected with Debug.
pub struct ManagementAuthority {
    runtime: BrokerRuntime,
    operation: ManagementOperation,
    identity: IdentityContext,
    authentication: ManagementAuthentication,
    caller: Option<(String, [u8; 32], i64)>,
}
pub(crate) enum ManagementAuthentication {
    Token {
        id: String,
        hash: Zeroizing<String>,
        class: BrokerTokenClass,
        browser: bool,
    },
    Static,
}
pub(crate) struct ManagementActor {
    pub(crate) principal: String,
    pub(crate) policy_write_scope: PolicyWriteScope,
}

impl ManagementAuthority {
    pub(crate) fn identity(&self) -> &IdentityContext {
        &self.identity
    }

    pub fn principal(&self) -> &str {
        &self.identity.principal
    }

    /// Snapshot identity is independent of policy generation. An unrelated
    /// managed policy edit does not invalidate an existing management request.
    pub(crate) fn check_runtime(&self, runtime: &BrokerRuntime) -> Result<(), ManagedStoreError> {
        if !Arc::ptr_eq(&self.runtime.config, &runtime.config) {
            return Err(ManagedStoreError::VersionConflict);
        }
        Ok(())
    }

    pub(crate) fn check_conn(
        &self,
        conn: &Connection,
        expected: ManagementOperation,
    ) -> Result<ManagementActor, ManagedStoreError> {
        if expected != self.operation {
            return Err(ManagedStoreError::ManagementDenied);
        }
        if let Some((name, contract, generation)) = &self.caller {
            ManagedStore::check_secret_reference_caller_conn(
                conn,
                self.runtime
                    .credential_key_ring
                    .as_ref()
                    .ok_or(ManagedStoreError::ManagementDenied)?,
                name,
                contract,
                *generation,
            )?;
        }
        crate::managed_store::management_authority::check(
            conn,
            &self.runtime,
            &self.identity,
            &self.authentication,
            expected,
        )
    }
}

impl BrokerRuntime {
    /// Verify the admitted runtime configuration while the host publication
    /// fence is held. Management intentionally does not pin policy generation.
    pub fn check_management_authority_runtime(
        &self,
        authority: &ManagementAuthority,
    ) -> Result<(), ManagedStoreError> {
        authority.check_runtime(self)
    }

    pub fn add_managed_policy_grant_subject_with_management_authority(
        &self,
        request: ManagedPolicyGrantSubjectAddRequest,
        authority: ManagementAuthority,
    ) -> Result<crate::ManagementMutation<ManagedPolicyMutationResult>, ManagedStoreError> {
        authority.check_runtime(self)?;
        let _guard = self.managed_policy_mutation_guard()?;
        let store = self.managed_policy_store()?.clone();
        let baseline = store.policy_validation_baseline()?;
        if self.policy_generation() > baseline.0.generation {
            return Err(ManagedStoreError::VersionConflict);
        }
        let mut next_snapshot = None;
        let result = store.add_policy_grant_subject_with_management_authority(
            request,
            authority,
            |grants, revision, subjects, catalog| {
                self.validate_managed_policy_candidate_for_store(
                    grants, revision, subjects, catalog, &baseline,
                )?;
                next_snapshot = Some(Arc::new(PolicySnapshot::from_managed(
                    revision.generation,
                    grants.to_vec(),
                    catalog.clone(),
                )));
                Ok(())
            },
        )?;
        // Candidate construction and every fallible check completed before
        // commit. With the core mutation mutex retained, publication cannot
        // turn a known committed change into a generic conflict response.
        self.policy_snapshot.store(
            next_snapshot.expect("committed subject mutation validated its policy snapshot"),
        );
        Ok(result)
    }

    pub fn remove_managed_policy_grant_subject_with_management_authority(
        &self,
        request: ManagedPolicyGrantSubjectRemoveRequest,
        authority: ManagementAuthority,
    ) -> Result<crate::ManagementMutation<ManagedPolicyMutationResult>, ManagedStoreError> {
        authority.check_runtime(self)?;
        let _guard = self.managed_policy_mutation_guard()?;
        let store = self.managed_policy_store()?.clone();
        let baseline = store.policy_validation_baseline()?;
        if self.policy_generation() > baseline.0.generation {
            return Err(ManagedStoreError::VersionConflict);
        }
        let mut next_snapshot = None;
        let result = store.remove_policy_grant_subject_with_management_authority(
            request,
            authority,
            |grants, revision, subjects, catalog| {
                self.validate_managed_policy_candidate_for_store(
                    grants, revision, subjects, catalog, &baseline,
                )?;
                next_snapshot = Some(Arc::new(PolicySnapshot::from_managed(
                    revision.generation,
                    grants.to_vec(),
                    catalog.clone(),
                )));
                Ok(())
            },
        )?;
        // Candidate construction and every fallible check completed before
        // commit. With the core mutation mutex retained, publication cannot
        // turn a known committed change into a generic conflict response.
        self.policy_snapshot.store(
            next_snapshot.expect("committed subject mutation validated its policy snapshot"),
        );
        Ok(result)
    }

    /// Re-verify original request credentials before sealing a capability. The
    /// host still performs its route, CSRF, browser and rate-limit admission.
    /// The returned capability independently checks current authority inside
    /// the eventual managed-store transaction.
    pub fn admit_management_authority(
        &self,
        headers: &HeaderMap,
        operation: ManagementOperation,
    ) -> Result<ManagementAuthority, ManagedStoreError> {
        if !self.config.management.enabled {
            return Err(ManagedStoreError::ManagementDenied);
        }
        let ingress = self
            .admit_ingress(headers)
            .map_err(|_| ManagedStoreError::ManagementDenied)?;
        let browser =
            if !self.has_configured_identity_header(headers) && self.config.browser_auth.enabled {
                management_browser_cookie(headers, &self.config.browser_auth.session_cookie_name)?
            } else {
                None
            };
        let (mut identity, authentication) = if let Some(raw) = browser {
            let store = self.managed_store.as_ref().ok_or_else(|| {
                ManagedStoreError::Unavailable("managed store unavailable".into())
            })?;
            let hasher = self.broker_token_hasher().ok_or_else(|| {
                ManagedStoreError::EncryptionKeyMissing("broker token verifier unavailable".into())
            })?;
            let session = store.resolve_browser_session(hasher, &raw)?;
            if session.password_change_required {
                return Err(ManagedStoreError::ManagementDenied);
            }
            let identity = self.identity_from_principal_groups(
                session.principal_id,
                Some(crate::PrincipalKind::User),
                None,
                session.groups,
                Some(session.policy_groups),
                Some(IdentitySourceAudit {
                    namespace: None,
                    binding_id: None,
                    name: "browser-session".into(),
                    kind: "broker_tokens".into(),
                    token_header: "Cookie".into(),
                    token_scheme: "cookie".into(),
                    token_class: Some(BrokerTokenClass::UserManage),
                    token_id: Some(session.token_id.clone()),
                    token_scopes: Some(session.scopes),
                }),
            );
            (
                identity,
                ManagementAuthentication::Token {
                    id: session.token_id,
                    hash: Zeroizing::new(hasher.hash(&raw)?),
                    class: BrokerTokenClass::UserManage,
                    browser: true,
                },
            )
        } else {
            let resolved = self
                .resolve_admitted_identity_with_proof(headers, &ingress)
                .map_err(|_| ManagedStoreError::ManagementDenied)?;
            // Trusted human assertions are agent_invoke identities; the existing
            // management class boundary never turns one into an administrator.
            if !resolved.identity.authenticated || resolved.proof.is_some() {
                return Err(ManagedStoreError::BrokerTokenClassDenied);
            }
            let identity = resolved.identity;
            let source = identity
                .source
                .as_ref()
                .ok_or(ManagedStoreError::ManagementDenied)?;
            let authentication = if let Some(class) = &source.token_class {
                let resolver = self
                    .identity_sources
                    .iter()
                    .find(|entry| entry.audit.name == source.name)
                    .ok_or(ManagedStoreError::ManagementDenied)?;
                let IdentitySourceResolverKind::BrokerTokens(tokens) = &resolver.resolver else {
                    return Err(ManagedStoreError::ManagementDenied);
                };
                let TokenExtraction::Token(raw) = resolver
                    .extract_token(headers)
                    .map_err(|_| ManagedStoreError::ManagementDenied)?
                else {
                    return Err(ManagedStoreError::ManagementDenied);
                };
                let raw = Zeroizing::new(raw);
                ManagementAuthentication::Token {
                    id: source
                        .token_id
                        .clone()
                        .ok_or(ManagedStoreError::ManagementDenied)?,
                    hash: Zeroizing::new(tokens.hasher.hash(&raw)?),
                    class: class.clone(),
                    browser: false,
                }
            } else {
                ManagementAuthentication::Static
            };
            (identity, authentication)
        };
        identity.caller_id = ingress.caller_id().map(str::to_owned);
        let caller = ingress
            .caller_id()
            .and_then(|id| {
                self.trusted_callers
                    .iter()
                    .filter_map(|caller| caller.secret_reference_contract())
                    .find(|(name, _, _)| *name == id)
            })
            .map(|(name, binding, generation)| (name.to_string(), *binding, generation));
        let authority = ManagementAuthority {
            runtime: self.clone(),
            operation,
            identity,
            authentication,
            caller,
        };
        self.managed_store
            .as_ref()
            .ok_or_else(|| ManagedStoreError::Unavailable("managed store unavailable".into()))?
            .check_management_admission(&authority, operation)?;
        Ok(authority)
    }
}

fn management_browser_cookie(
    headers: &HeaderMap,
    name: &str,
) -> Result<Option<Zeroizing<String>>, ManagedStoreError> {
    let mut token = None;
    for header in headers.get_all(http::header::COOKIE) {
        for part in header.as_bytes().split(|byte| *byte == b';') {
            let part = part.trim_ascii();
            let Some(separator) = part.iter().position(|byte| *byte == b'=') else {
                if part == name.as_bytes() {
                    return Err(ManagedStoreError::ManagementDenied);
                }
                continue;
            };
            let key = &part[..separator];
            if key.trim_ascii() != name.as_bytes() {
                continue;
            }
            let value = &part[separator + 1..];
            if key != name.as_bytes() || value.is_empty() || token.is_some() {
                return Err(ManagedStoreError::ManagementDenied);
            }
            token = Some(Zeroizing::new(
                std::str::from_utf8(value)
                    .map_err(|_| ManagedStoreError::ManagementDenied)?
                    .to_owned(),
            ));
        }
    }
    Ok(token)
}
