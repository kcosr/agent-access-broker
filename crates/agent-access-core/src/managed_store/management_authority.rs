//! Transactional validation of sealed HTTP management authority.
use super::*;
use crate::runtime::management_authority::{
    ManagementActor, ManagementAuthentication, ManagementAuthority, ManagementOperation,
};

impl ManagedStore {
    pub(crate) fn check_management_admission(
        &self,
        authority: &ManagementAuthority,
        operation: ManagementOperation,
    ) -> Result<(), ManagedStoreError> {
        let conn = self
            .connection
            .lock()
            .map_err(|_| ManagedStoreError::Unavailable("managed store lock unavailable".into()))?;
        authority.check_conn(&conn, operation).map(|_| ())
    }
}

pub(crate) fn check(
    conn: &Connection,
    runtime: &crate::BrokerRuntime,
    identity: &crate::IdentityContext,
    authentication: &ManagementAuthentication,
    operation: ManagementOperation,
) -> Result<ManagementActor, ManagedStoreError> {
    let config = runtime.config();
    let (class, browser) = match authentication {
        ManagementAuthentication::Static => (None, false),
        ManagementAuthentication::Token {
            id,
            hash,
            class,
            browser,
        } => {
            let token = broker_token_by_id(conn, id)?;
            if token.principal_id != identity.principal
                || !constant_time_eq(token.token_hash.as_bytes(), hash.as_bytes())
            {
                return Err(ManagedStoreError::BrokerTokenNotFound);
            }
            if token.token_class != *class {
                return Err(ManagedStoreError::BrokerTokenClassDenied);
            }
            if token.revoked_at.is_some() {
                return Err(ManagedStoreError::BrokerTokenRevoked);
            }
            if token.paused_at.is_some() {
                return Err(ManagedStoreError::BrokerTokenPaused);
            }
            if timestamp_is_past(token.expires_at.as_deref()) {
                return Err(ManagedStoreError::BrokerTokenExpired);
            }
            if *browser {
                let session = browser_session_by_token_id(conn, id)?;
                let method = login_method_by_id(
                    conn,
                    session
                        .login_method_id
                        .as_deref()
                        .ok_or(ManagedStoreError::BrokerTokenRevoked)?,
                )?;
                if session.principal_id != identity.principal
                    || method.principal_id != identity.principal
                    || method.method != session.login_method
                    || method.status != "active"
                    || method
                        .password_set_at
                        .as_deref()
                        .is_some_and(|set| set > session.auth_time.as_str())
                {
                    return Err(ManagedStoreError::BrokerTokenRevoked);
                }
                if session.password_change_required || method.must_change_password {
                    return Err(ManagedStoreError::ManagementDenied);
                }
            }
            (Some(class), *browser)
        }
    };
    let class_allowed = if operation.personal() {
        class == Some(&BrokerTokenClass::UserManage)
            || (operation == ManagementOperation::PersonalCredentialPut
                && class.is_none()
                && config.management.allow_classless_user_management)
    } else if operation.policy() {
        matches!(
            class,
            Some(BrokerTokenClass::Admin | BrokerTokenClass::UserManage)
        ) || (class.is_none() && config.management.allow_classless_admin_identities)
    } else {
        class == Some(&BrokerTokenClass::Admin)
            || (class == Some(&BrokerTokenClass::UserManage) && browser)
            || (class.is_none() && config.management.allow_classless_admin_identities)
    };
    if !class_allowed {
        return Err(ManagedStoreError::BrokerTokenClassDenied);
    }
    if class.is_none() && !operation.personal() {
        // Preserve configured classless management where supported. A managed
        // principal, if present, must still be active; groups are read live.
        let groups = match principal_by_id(conn, &identity.principal) {
            Ok(principal) => {
                if principal.status != "active" {
                    return Err(ManagedStoreError::PrincipalDisabled);
                }
                if config.identity.authority == "managed" {
                    principal_policy_groups(conn, &identity.principal)?
                } else {
                    identity.policy_groups.clone()
                }
            }
            Err(ManagedStoreError::PrincipalNotFound) => identity.policy_groups.clone(),
            Err(error) => return Err(error),
        };
        if !config
            .management
            .admin_principals
            .contains(&identity.principal)
            && !groups
                .iter()
                .any(|group| config.management.admin_groups.contains(group))
        {
            return Err(ManagedStoreError::ManagementDenied);
        }
        return Ok(ManagementActor {
            principal: identity.principal.clone(),
            policy_write_scope: crate::PolicyWriteScope::Global,
        });
    }
    let mut authority = management_authority_conn(conn, &identity.principal)?;
    if browser && authority.principal.kind != "user" {
        return Err(ManagedStoreError::BrokerTokenRevoked);
    }
    if operation.personal() {
        if !authority.principal.self_service_enabled {
            return Err(ManagedStoreError::SelfServiceDisabled);
        }
    } else if operation.policy() {
        if class == Some(&BrokerTokenClass::Admin)
            && (authority.principal.kind != "user"
                || authority.principal.role != PrincipalRole::Admin)
        {
            return Err(ManagedStoreError::ManagementDenied);
        }
        if let crate::PolicyWriteScope::Services { services } = &mut authority.policy_write_scope {
            let configured = runtime
                .configured_service_capabilities()
                .into_iter()
                .map(|service| service.service)
                .collect::<BTreeSet<_>>();
            services.retain(|service| {
                config.policy.authority == "managed" && configured.contains(service)
            });
            if services.is_empty() {
                return Err(ManagedStoreError::ManagementDenied);
            }
        }
    } else if authority.principal.kind != "user" || authority.principal.role != PrincipalRole::Admin
    {
        return Err(ManagedStoreError::ManagementDenied);
    }
    Ok(ManagementActor {
        principal: identity.principal.clone(),
        policy_write_scope: authority.policy_write_scope,
    })
}
