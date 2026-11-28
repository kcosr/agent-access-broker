//! Access key resolution against one runtime generation.
use super::*;
use crate::AccessKeyResolution;

impl BrokerRuntime {
    /// Whose access key `raw_token` is under this generation's access key types
    /// and username settings. See `ManagedStore::resolve_access_key`.
    pub fn resolve_access_key(
        &self,
        raw_token: &str,
    ) -> Result<AccessKeyResolution, ManagedStoreError> {
        let (Some(store), Some(hasher)) = (self.managed_store(), self.broker_token_hasher()) else {
            return Err(ManagedStoreError::Unavailable(
                "access keys require managed_store and broker_tokens".into(),
            ));
        };
        store.resolve_access_key(hasher, &self.access_key_types, raw_token)
    }

    /// The response to a request that the pool or the rate of the
    /// resolution route turned away: the envelope of
    /// [`Self::admission_limit_error_response`], with no audit record. A
    /// refusal by a limit is logged by the caller.
    pub fn access_key_resolution_limit_response(
        operation: OperationContext,
        error: ProviderError,
    ) -> BrokerResponse<Value> {
        trusted_callers::PreDispatchFailure::Admission
            .apply(Self::access_key_resolution_error_response(operation, error))
    }

    /// A failed caller check on the resolution route, without an audit write.
    pub fn access_key_resolution_caller_error_response(
        operation: OperationContext,
        failure: IdentityFailure,
    ) -> BrokerResponse<Value> {
        trusted_callers::PreDispatchFailure::for_identity_failure(&failure).apply(
            Self::access_key_resolution_error_response(operation, failure.provider_error()),
        )
    }

    /// A resolution refusal or failure. Identifying a key is unaudited;
    /// the resolving service records its own decisions.
    pub fn access_key_resolution_error_response(
        operation: OperationContext,
        error: ProviderError,
    ) -> BrokerResponse<Value> {
        let reason_code = error.reason_code();
        BrokerResponse {
            retry_after_seconds: None,
            status: reason_code.http_status(),
            envelope: ResponseEnvelope {
                agent_request_id: operation.agent_request_id,
                broker_request_id: operation.broker_request_id,
                decision: error.decision(),
                service: operation.service,
                action: operation.action,
                resource_scopes: ResourceScopes::new(),
                reason_code: Some(reason_code.into()),
                reason: Some(error.message.clone()),
                result: error.result.map(|value| *value),
                error: Some(crate::ErrorBody {
                    message: error.message,
                }),
            },
            stream: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The broker-token identity source claims every `aab_` token, looks it
    /// up in the Broker token table only, and so refuses an access key as
    /// an unknown Broker token. A static source knows only its own tokens.
    #[test]
    fn identity_sources_refuse_a_live_access_key() {
        let temp = tempfile::TempDir::new().unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
        }
        let registry = crate::ConfiguredExecutionContexts::from_config(None).unwrap();
        let store = ManagedStore::open(
            &crate::ManagedStoreConfig {
                kind: "sqlite".into(),
                path: temp.path().join("store.sqlite").display().to_string(),
                auto_migrate: true,
                require_registered_principal_for_invocation: false,
            },
            &registry,
            crate::ManagedStoreOpenMode::Startup,
        )
        .unwrap();
        store
            .create_principal(
                crate::PrincipalWriteRequest {
                    principal_id: "robot".into(),
                    kind: "service_account".into(),
                    display_name: None,
                    email: None,
                    external_subject: None,
                    created_by: "admin".into(),
                    role: crate::PrincipalRole::User,
                    self_service_enabled: Some(false),
                    agent_token_issuance: Default::default(),
                },
                &registry,
            )
            .unwrap();
        let hasher = crate::test_token_hasher();
        let access_key_types = crate::AccessKeyTypes::for_test([crate::AccessKeyType {
            id: "inference".into(),
            display_name: "Inference".into(),
            description: None,
            lifetime_options: vec!["600s".into(), "1h".into()],
            default_lifetime: "1h".into(),
            self_service: false,
        }]);
        store.set_principal_access_key_types_for_test(
            "robot",
            &["inference"],
            &[],
            &access_key_types,
        );
        let issued = store
            .mint_administrator_access_key(
                &hasher,
                &access_key_types,
                &crate::AdministratorAccessKeyRequest {
                    principal_id: "robot".into(),
                    name: "nightly job".into(),
                    access_key_types: vec!["inference".into()],
                    lifetime: "600s".into(),
                    created_by: "admin".into(),
                },
            )
            .unwrap()
            .unwrap();
        assert!(
            store
                .resolve_access_key(&hasher, &access_key_types, &issued.key)
                .unwrap()
                .is_active()
        );

        let broker_tokens = BrokerTokensSource {
            store: store.clone(),
            hasher,
            execution_context: None,
        };
        assert!(matches!(
            broker_tokens.resolve(&issued.key),
            Err(IdentityFailure::BrokerTokenNotFound)
        ));
        let static_principals = StaticPrincipalsSource {
            tokens: BTreeMap::new(),
            store: Some(store),
        };
        assert!(matches!(
            static_principals.resolve(&issued.key),
            Ok(SourceResolution::NoMatch)
        ));
    }
}
