//! Deleting a principal's credential connection rows: the active
//! `(connection, default)` row through its connection, and retained rows by
//! their immutable credential ID. Both decide inside the deleting
//! transaction, so a concurrent replacement cannot turn a retained-row
//! delete into a delete of the active row.

use super::*;
use std::collections::BTreeSet;

impl ManagedStore {
    /// Deletes `owner`'s `(connection, default)` row when it has `profile`,
    /// the token profile the connection selects for the owner. A row with
    /// another profile is retained and reports `CredentialNotFound` here.
    pub fn delete_connection_credential(
        &self,
        owner_principal_id: &str,
        connection: &str,
        profile: &str,
        purpose: CredentialManagementPurpose,
    ) -> Result<CredentialMetadata, ManagedStoreError> {
        validate_principal_id(owner_principal_id)?;
        validate_service_and_name(connection, crate::CONNECTION_CREDENTIAL_NAME)?;
        let mut conn = self.connection.lock().unwrap();
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sql_unavailable)?;
        if purpose == CredentialManagementPurpose::Personal {
            require_self_service(&tx, owner_principal_id)?;
        }
        let metadata = credential_metadata_by_tuple(
            &tx,
            owner_principal_id,
            connection,
            crate::CONNECTION_CREDENTIAL_NAME,
        )?;
        if metadata.profile != profile {
            return Err(ManagedStoreError::CredentialNotFound);
        }
        tx.execute(
            "DELETE FROM credentials WHERE credential_id = ?1",
            params![metadata.credential_id],
        )
        .map_err(sql_unavailable)?;
        tx.commit().map_err(sql_unavailable)?;
        Ok(metadata)
    }

    /// Deletes `owner`'s retained row `credential_id`. `active` lists the
    /// `(connection, profile)` pairs whose `(connection, default)` row is
    /// the owner's active row under the current configuration; such a row
    /// is refused and stays stored. Another owner's row reports
    /// `CredentialNotFound`, as an unknown ID does.
    pub fn delete_retained_user_credential(
        &self,
        credential_id: &str,
        owner_principal_id: &str,
        active: &BTreeSet<(String, String)>,
        purpose: CredentialManagementPurpose,
    ) -> Result<CredentialMetadata, ManagedStoreError> {
        validate_uuid_id(credential_id, "credentialId")?;
        validate_principal_id(owner_principal_id)?;
        let mut conn = self.connection.lock().unwrap();
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sql_unavailable)?;
        if purpose == CredentialManagementPurpose::Personal {
            require_self_service(&tx, owner_principal_id)?;
        }
        let metadata = credential_metadata_by_id(&tx, credential_id)?;
        if metadata.owner_kind != "user" || metadata.owner_principal != owner_principal_id {
            return Err(ManagedStoreError::CredentialNotFound);
        }
        if metadata.name == crate::CONNECTION_CREDENTIAL_NAME
            && active.contains(&(metadata.service.clone(), metadata.profile.clone()))
        {
            return Err(ManagedStoreError::CredentialInvalid(
                "credential is the active token of its connection; delete it through the connection"
                    .to_string(),
            ));
        }
        tx.execute(
            "DELETE FROM credentials WHERE credential_id = ?1",
            params![metadata.credential_id],
        )
        .map_err(sql_unavailable)?;
        tx.commit().map_err(sql_unavailable)?;
        Ok(metadata)
    }
}
