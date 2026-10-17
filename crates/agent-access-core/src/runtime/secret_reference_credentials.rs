//! Management's narrow sink for a captured token. The host admits the route and
//! holds the runtime publication fence; the store transaction rechecks both the
//! importing actor's authority and the captured token's originating identity.

use super::{BrokerRuntime, IdentityContext};
use crate::{
    BrokerTokenClass, CONNECTION_CREDENTIAL_NAME, CredentialManagementPurpose,
    CredentialWriteRequest, ManagedStore, ManagedStoreError, PrincipalRole,
    SecretCredentialWriteResult, Selection,
};

impl BrokerRuntime {
    /// Remove expired temporary secret ciphertext and elapsed safe receipts.
    /// This local maintenance operation never revokes an upstream credential.
    pub fn cleanup_secret_references(&self) -> Result<u64, ManagedStoreError> {
        match self.managed_store() {
            Some(store) => store.cleanup_secret_references(),
            None => Ok(0),
        }
    }

    /// Existing HTTP routes supply the sealed original credential. It is
    /// checked again within the same transaction that installs the credential.
    pub fn store_connection_credential_with_management_authority(
        &self,
        authority: crate::ManagementAuthority,
        request: CredentialWriteRequest,
        purpose: CredentialManagementPurpose,
    ) -> Result<crate::ManagementMutation<SecretCredentialWriteResult>, ManagedStoreError> {
        authority.check_runtime(self)?;
        let result = self.store_connection_credential_checked(
            authority.identity(),
            request,
            purpose,
            &authority,
        )?;
        let credential = &result.credential;
        let audit = serde_json::json!({"credentialId":credential.credential_id,"ownerPrincipal":credential.owner_principal,"connection":credential.service,"profile":credential.profile,"credentialKind":credential.credential_kind,"status":credential.status,"secretReferences":result.references,"changed":true});
        Ok(crate::ManagementMutation {
            value: result,
            audit,
        })
    }

    fn store_connection_credential_checked(
        &self,
        identity: &IdentityContext,
        request: CredentialWriteRequest,
        purpose: CredentialManagementPurpose,
        authority: &crate::ManagementAuthority,
    ) -> Result<SecretCredentialWriteResult, ManagedStoreError> {
        let store = self.managed_store().ok_or_else(|| {
            ManagedStoreError::Unavailable("managed store is not configured".into())
        })?;
        let key_ring = self.credential_key_ring().ok_or_else(|| {
            ManagedStoreError::EncryptionKeyMissing(
                "credential encryption key ring is not configured".into(),
            )
        })?;
        if !identity.authenticated || request.actor != identity.principal {
            return Err(ManagedStoreError::RightMissing);
        }
        if request.name != CONNECTION_CREDENTIAL_NAME {
            return Err(ManagedStoreError::InputInvalid(
                "credential connection requires the default credential name".into(),
            ));
        }
        let owner = request.owner_principal_id.clone();
        let connection = request.service.clone();
        let profile = request.profile.clone();
        let kind = request.credential_kind.clone();
        store.upsert_user_credential_with_secret_references(
            key_ring,
            request,
            purpose,
            |conn| {
                authority.check_conn(
                    conn,
                    match purpose {
                        CredentialManagementPurpose::Personal => {
                            crate::ManagementOperation::PersonalCredentialPut
                        }
                        CredentialManagementPurpose::Administrative => {
                            crate::ManagementOperation::AdminCredentialPut
                        }
                    },
                )?;
                self.check_credential_import_actor(conn, identity, &owner, &connection, purpose)?;
                let owner_kind = crate::managed_store::principal_kind_at_conn(conn, &owner)?;
                let configured = self
                    .effective_credentials()
                    .connections
                    .get(&connection)
                    .ok_or_else(|| {
                        ManagedStoreError::InputInvalid(
                            "credential connection is not configured".into(),
                        )
                    })?;
                if !matches!(crate::select(configured, owner_kind), Selection::Token(_))
                    || self.connection_token_profile(&connection)
                        != Some((profile.as_str(), kind.as_str()))
                {
                    return Err(ManagedStoreError::InputInvalid(
                        "credential connection does not select this token profile".into(),
                    ));
                }
                Ok(())
            },
            |conn, origin| {
                self.check_secret_reference_origin_conn(conn, origin)
                    .map_err(credential_reference_origin_error)?;
                if purpose == CredentialManagementPurpose::Personal
                    && origin.principal() != identity.principal
                {
                    return Err(ManagedStoreError::SecretReferenceDenied);
                }
                Ok(())
            },
        )
    }

    fn check_credential_import_actor(
        &self,
        conn: &rusqlite::Connection,
        identity: &IdentityContext,
        owner: &str,
        connection: &str,
        purpose: CredentialManagementPurpose,
    ) -> Result<(), ManagedStoreError> {
        let source = identity.source.as_ref();
        let class = source.and_then(|source| source.token_class.as_ref());
        if let Some(class) = class {
            let token_id = source
                .and_then(|source| source.token_id.as_deref())
                .ok_or(ManagedStoreError::BrokerTokenClassDenied)?;
            ManagedStore::check_secret_reference_token_conn(
                conn,
                &identity.principal,
                token_id,
                class.clone(),
            )?;
        }
        match purpose {
            CredentialManagementPurpose::Administrative => {
                let class_allowed = class == Some(&BrokerTokenClass::Admin)
                    || (class == Some(&BrokerTokenClass::UserManage)
                        && source.is_some_and(|source| source.name == "browser-session"))
                    || (class.is_none()
                        && self.config().management.allow_classless_admin_identities);
                if !class_allowed {
                    return Err(ManagedStoreError::BrokerTokenClassDenied);
                }
                if class.is_none() {
                    let config = &self.config().management;
                    if !config.admin_principals.contains(&identity.principal)
                        && !identity
                            .policy_groups
                            .iter()
                            .any(|group| config.admin_groups.contains(group))
                    {
                        return Err(ManagedStoreError::RightMissing);
                    }
                } else {
                    let authority =
                        crate::managed_store::secret_reference_management_authority_conn(
                            conn,
                            &identity.principal,
                        )?;
                    if authority.principal.kind != "user"
                        || authority.principal.role != PrincipalRole::Admin
                    {
                        return Err(ManagedStoreError::RightMissing);
                    }
                }
            }
            CredentialManagementPurpose::Personal => {
                if owner != identity.principal {
                    return Err(ManagedStoreError::RightMissing);
                }
                match class {
                    Some(&BrokerTokenClass::UserManage) => {
                        let mut entitled = false;
                        for service in self
                            .effective_credentials()
                            .connection_consumers(connection)
                        {
                            if self.has_per_user_setup_grant_at_conn(conn, owner, service)? {
                                entitled = true;
                                break;
                            }
                        }
                        if !entitled {
                            return Err(ManagedStoreError::RightMissing);
                        }
                    }
                    None if self.config().management.allow_classless_user_management => {
                        crate::managed_store::require_credential_right_conn(
                            conn,
                            owner,
                            "credentials:self:write",
                            connection,
                            CONNECTION_CREDENTIAL_NAME,
                        )?;
                    }
                    _ => return Err(ManagedStoreError::BrokerTokenClassDenied),
                }
            }
        }
        Ok(())
    }
}

fn credential_reference_origin_error(error: ManagedStoreError) -> ManagedStoreError {
    match error {
        ManagedStoreError::PrincipalRequired
        | ManagedStoreError::PrincipalNotFound
        | ManagedStoreError::PrincipalDisabled
        | ManagedStoreError::AttestedIdentityDenied
        | ManagedStoreError::BrokerTokenNotFound
        | ManagedStoreError::BrokerTokenExpired
        | ManagedStoreError::BrokerTokenRevoked
        | ManagedStoreError::BrokerTokenPaused
        | ManagedStoreError::BrokerTokenClassDenied
        | ManagedStoreError::RightMissing => ManagedStoreError::SecretReferenceDenied,
        other => other,
    }
}
