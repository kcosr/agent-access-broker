//! Authentication ownership for durable temporary secret references.
//!
//! These pins survive MCP reconnects but grant no authority themselves. The
//! consuming operation still needs its own current authorization. Management
//! sinks may explicitly authorize a different actor, but must retain the source
//! validity check, even when source and destination principals differ.
use super::*;
use crate::managed_store::AttestedSecretReferencePin;
use rusqlite::Connection;
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

/// An internal, encrypted persistence value. Never an API object or credential.
/// Only the private persistence DTO implements serialization; Debug is absent.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct SecretReferenceOrigin(OriginData);

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct OriginData {
    version: u8,
    principal: String,
    execution_context: String,
    authentication: OriginAuthentication,
    caller: Option<OriginCaller>,
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum OriginAuthentication {
    BrokerToken {
        source: String,
        header: String,
        scheme: String,
        token_id: String,
        verifier_binding: [u8; 32],
    },
    Attested {
        proof: AttestedSecretReferencePin,
    },
}

impl Drop for OriginAuthentication {
    fn drop(&mut self) {
        if let Self::BrokerToken {
            verifier_binding, ..
        } = self
        {
            verifier_binding.zeroize();
        }
    }
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct OriginCaller {
    name: String,
    generation: i64,
}

impl SecretReferenceOrigin {
    pub(crate) fn principal(&self) -> &str {
        &self.0.principal
    }

    pub(crate) fn encode(&self) -> Result<Vec<u8>, ManagedStoreError> {
        serde_json::to_vec(&self.0).map_err(|_| invalid_origin())
    }

    pub(crate) fn decode(bytes: &[u8]) -> Result<Self, ManagedStoreError> {
        let value: OriginData = serde_json::from_slice(bytes).map_err(|_| invalid_origin())?;
        if value.version != 1
            || !crate::is_safe_principal(&value.principal)
            || !crate::is_valid_execution_context_value(&value.execution_context)
            || value.caller.as_ref().is_some_and(|caller| {
                !crate::is_safe_identifier(&caller.name) || caller.generation < 1
            })
        {
            return Err(invalid_origin());
        }
        match &value.authentication {
            OriginAuthentication::BrokerToken {
                source,
                header,
                scheme,
                token_id,
                ..
            } => {
                if !crate::is_safe_identifier(source)
                    || http::header::HeaderName::from_bytes(header.as_bytes()).is_err()
                    || scheme.is_empty()
                    || uuid::Uuid::parse_str(token_id).is_err()
                {
                    return Err(invalid_origin());
                }
            }
            OriginAuthentication::Attested { proof } => {
                if !proof.valid_shape()
                    || proof.principal() != value.principal
                    || value.caller.is_none()
                {
                    return Err(invalid_origin());
                }
            }
        }
        Ok(Self(value))
    }

    /// Safe provenance for successful credential installation. Neither this
    /// metadata nor the private proof may contain a reusable reference handle.
    pub(crate) fn audit_metadata(&self) -> Value {
        let mut result = json!({"principal":self.principal()});
        match &self.0.authentication {
            OriginAuthentication::BrokerToken { token_id, .. } => {
                result["authenticationKind"] = json!("broker_tokens");
                result["tokenId"] = json!(token_id);
            }
            OriginAuthentication::Attested { proof } => {
                result["authenticationKind"] = json!(proof.authentication_kind());
            }
        }
        if let Some(caller) = &self.0.caller {
            result["callerId"] = json!(caller.name);
        }
        result
    }
}

fn invalid_origin() -> ManagedStoreError {
    ManagedStoreError::SchemaInvalid("temporary secret reference identity is invalid".into())
}

fn denied_origin() -> ManagedStoreError {
    ManagedStoreError::RightMissing
}

impl BrokerRuntime {
    /// Pin already admitted identity evidence. Attested callers must supply the
    /// original private proof, rather than reconstructing it from audit fields.
    pub(crate) fn secret_reference_origin(
        &self,
        identity: &IdentityContext,
        execution_context: &ExecutionContext,
        proof: Option<&crate::AttestedIdentityProof>,
    ) -> Result<SecretReferenceOrigin, ManagedStoreError> {
        if !identity.authenticated {
            return Err(denied_origin());
        }
        let source = identity.source.as_ref().ok_or_else(denied_origin)?;
        if source.token_class != Some(BrokerTokenClass::AgentInvoke) {
            return Err(denied_origin());
        }
        let caller = identity
            .caller_id
            .as_ref()
            .map(|name| {
                self.trusted_callers
                    .iter()
                    .find_map(|caller| {
                        let (loaded_name, _, generation) = caller.secret_reference_contract()?;
                        (loaded_name == name).then(|| OriginCaller {
                            name: name.clone(),
                            generation,
                        })
                    })
                    .ok_or_else(denied_origin)
            })
            .transpose()?;
        let authentication = if source.kind == "broker_tokens" {
            if proof.is_some() {
                return Err(denied_origin());
            }
            let verifier = self
                .secret_reference_token_source(
                    &source.name,
                    &source.token_header,
                    &source.token_scheme,
                )
                .ok_or_else(denied_origin)?;
            OriginAuthentication::BrokerToken {
                source: source.name.clone(),
                header: source.token_header.to_ascii_lowercase(),
                scheme: source.token_scheme.clone(),
                token_id: source.token_id.clone().ok_or_else(denied_origin)?,
                verifier_binding: verifier.hasher.secret_reference_key_binding(),
            }
        } else {
            let proof = proof.ok_or_else(denied_origin)?;
            let pin = proof.secret_reference_pin();
            if pin.principal() != identity.principal
                || pin.authentication_kind() != source.kind
                || source.token_id.is_some()
                || source.binding_id.as_deref() != proof.binding_id()
                || caller.is_none()
            {
                return Err(denied_origin());
            }
            OriginAuthentication::Attested { proof: pin }
        };
        Ok(SecretReferenceOrigin(OriginData {
            version: 1,
            principal: identity.principal.clone(),
            execution_context: execution_context.to_string(),
            authentication,
            caller,
        }))
    }

    fn secret_reference_token_source(
        &self,
        name: &str,
        header: &str,
        scheme: &str,
    ) -> Option<&BrokerTokensSource> {
        self.identity_sources.iter().find_map(|source| {
            if source.audit.name == name
                && source.audit.token_header.eq_ignore_ascii_case(header)
                && source.audit.token_scheme == scheme
                && let IdentitySourceResolverKind::BrokerTokens(source) = &source.resolver
            {
                Some(source)
            } else {
                None
            }
        })
    }

    /// Validate the origin in the reference/credential transaction. Management
    /// handoff uses this after independently authorizing its current actor.
    pub(crate) fn check_secret_reference_origin_conn(
        &self,
        conn: &Connection,
        origin: &SecretReferenceOrigin,
    ) -> Result<(), ManagedStoreError> {
        if let Some(expected) = &origin.0.caller {
            let (name, contract, generation) = self
                .trusted_callers
                .iter()
                .filter_map(|caller| caller.secret_reference_contract())
                .find(|(name, _, _)| *name == expected.name)
                .ok_or_else(denied_origin)?;
            if generation != expected.generation {
                return Err(denied_origin());
            }
            ManagedStore::check_secret_reference_caller_conn(
                conn,
                self.credential_key_ring
                    .as_ref()
                    .ok_or_else(denied_origin)?,
                name,
                contract,
                generation,
            )?;
        }
        match &origin.0.authentication {
            OriginAuthentication::BrokerToken {
                source,
                header,
                scheme,
                token_id,
                verifier_binding,
            } => {
                let verifier = self
                    .secret_reference_token_source(source, header, scheme)
                    .ok_or_else(denied_origin)?;
                if !bool::from(
                    verifier
                        .hasher
                        .secret_reference_key_binding()
                        .ct_eq(verifier_binding),
                ) {
                    return Err(denied_origin());
                }
                ManagedStore::check_secret_reference_token_conn(
                    conn,
                    origin.principal(),
                    token_id,
                    BrokerTokenClass::AgentInvoke,
                )
            }
            OriginAuthentication::Attested { proof } => proof.check_current_conn(conn),
        }
    }

    /// Ordinary tool use must retain the exact origin identity and execution
    /// context, even when another token resolves to the same principal.
    pub(crate) fn check_secret_reference_owner_conn(
        &self,
        conn: &Connection,
        origin: &SecretReferenceOrigin,
        current: &SecretReferenceOrigin,
    ) -> Result<(), ManagedStoreError> {
        if origin != current {
            return Err(denied_origin());
        }
        self.check_secret_reference_origin_conn(conn, origin)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;

    fn identity_runtime() -> (tempfile::TempDir, BrokerRuntime, HeaderMap, PathBuf) {
        let directory = tempfile::tempdir().unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
        }
        let key_path = directory.path().join("token-hash.key");
        write_hash_key(&key_path, 21);
        let mut config = super::super::tests::base_fake_config();
        config.identity.mode = "required".into();
        config.identity.authority = "managed".into();
        config.identity.groups.clear();
        config.identity.sources = vec![crate::IdentitySourceConfig {
            name: "broker".into(),
            kind: "broker_tokens".into(),
            header: "Authorization".into(),
            scheme: "Bearer".into(),
            principals: vec![],
        }];
        config.broker_tokens = Some(crate::BrokerTokensConfig {
            hash_key_ref: format!("file:{}", key_path.display()),
            ..Default::default()
        });
        config.managed_store = Some(crate::ManagedStoreConfig {
            kind: "sqlite".into(),
            path: directory.path().join("store.sqlite").display().to_string(),
            auto_migrate: true,
            require_registered_principal_for_invocation: false,
        });
        config.policy.grants.clear();
        let runtime = BrokerRuntime::new(config).unwrap();
        let store = runtime.managed_store.as_ref().unwrap();
        store
            .create_principal(crate::PrincipalWriteRequest {
                principal_id: "alice".into(),
                kind: "user".into(),
                role: crate::PrincipalRole::User,
                self_service_enabled: None,
                display_name: None,
                email: None,
                external_subject: None,
                created_by: "admin".into(),
            })
            .unwrap();
        let token = store
            .issue_broker_token(
                runtime.broker_token_hasher.as_ref().unwrap(),
                crate::BrokerTokenIssueRequest {
                    principal_id: "alice".into(),
                    name: "origin".into(),
                    token_class: BrokerTokenClass::AgentInvoke,
                    scopes: json!({"allowedExecutionContexts":["default"]}),
                    expires_at: None,
                    created_by: "admin".into(),
                },
            )
            .unwrap();
        let headers = HeaderMap::from_iter([(
            http::header::AUTHORIZATION,
            format!("Bearer {}", token.token).parse().unwrap(),
        )]);
        (directory, runtime, headers, key_path)
    }

    fn write_hash_key(path: &std::path::Path, value: u8) {
        fs::write(
            path,
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([value; 32]),
        )
        .unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
        }
    }

    fn check_in_reference_transaction(
        runtime: &BrokerRuntime,
        origin: SecretReferenceOrigin,
    ) -> Result<(), ManagedStoreError> {
        use crate::managed_store::{
            SecretOutputReservation, SecretReferenceLimits, SecretReservationRequest,
        };
        runtime
            .managed_store
            .as_ref()
            .unwrap()
            .reserve_secret_outputs(
                runtime.credential_key_ring.as_ref().unwrap(),
                SecretReservationRequest {
                    broker_request_id: uuid::Uuid::new_v4().to_string(),
                    origin,
                    execution_context: "default".into(),
                    service: "fake".into(),
                    action: "echo".into(),
                    outputs: vec![SecretOutputReservation {
                        pointer: "/result/secret".into(),
                        max_bytes: 32,
                    }],
                },
                &SecretReferenceLimits {
                    ttl_seconds: 3600,
                    max_refs_per_principal: 8,
                    max_refs_total: 16,
                    max_bytes_per_principal: 1024,
                    max_bytes_total: 2048,
                    receipt_retention_seconds: 3600,
                    max_receipts_total: 100,
                },
                |conn, origin| runtime.check_secret_reference_origin_conn(conn, origin),
            )
            .map(drop)
    }

    #[test]
    fn token_origin_survives_restart_and_rejects_changed_loaded_verifier_key() {
        let (_directory, runtime, headers, key_path) = identity_runtime();
        let identity = runtime.resolve_identity(&headers).unwrap();
        let origin = runtime
            .secret_reference_origin(&identity, &ExecutionContext::new("default").unwrap(), None)
            .unwrap();
        check_in_reference_transaction(&runtime, origin.clone()).unwrap();
        let config = (*runtime.config).clone();
        drop(runtime);
        let restarted = BrokerRuntime::new(config.clone()).unwrap();
        check_in_reference_transaction(&restarted, origin.clone()).unwrap();
        write_hash_key(&key_path, 22);
        let rotated = BrokerRuntime::new_for_reload(config.clone(), &restarted).unwrap();
        assert!(rotated.resolve_identity(&headers).is_err());
        assert!(check_in_reference_transaction(&rotated, origin.clone()).is_err());
        // Restoring this verifier restores the original actual bearer token too;
        // it differs intentionally from the monotonic trusted-caller ledger.
        write_hash_key(&key_path, 21);
        let restored = BrokerRuntime::new_for_reload(config, &rotated).unwrap();
        restored.resolve_identity(&headers).unwrap();
        check_in_reference_transaction(&restored, origin).unwrap();
    }

    #[test]
    fn attested_origin_survives_restart_but_loaded_caller_rotation_never_revives_it() {
        let (directory, initial, _, _) = identity_runtime();
        let caller_path = directory.path().join("caller.token");
        fs::write(&caller_path, "synthetic-original-caller-secret").unwrap();
        let mut config = (*initial.config).clone();
        config.identity.trusted_callers.insert(
            "direct".into(),
            crate::TrustedCallerConfig {
                credential_ref: format!("file:{}", caller_path.display()),
                credential_transport: crate::TrustedCallerCredentialTransport::AuthorizationUser,
                username_namespace: Some("workspace".into()),
                context_mode: crate::TrustedCallerContextMode::Fixed,
                execution_context: Some("default".into()),
                allowed_execution_contexts: None,
                allow_forwarded_identity: false,
            },
        );
        let mut runtime = BrokerRuntime::new_for_reload(config.clone(), &initial).unwrap();
        runtime.activate_runtime_authority().unwrap();
        runtime
            .managed_store
            .as_ref()
            .unwrap()
            .create_username_binding("alice", "workspace", "operator_987", "admin")
            .unwrap();
        let headers = HeaderMap::from_iter([
            (
                http::header::AUTHORIZATION,
                "Bearer synthetic-original-caller-secret".parse().unwrap(),
            ),
            (
                http::header::HeaderName::from_static("x-agent-access-user"),
                "operator_987".parse().unwrap(),
            ),
        ]);
        let resolve = |runtime: &BrokerRuntime| {
            let admission = runtime.admit_mcp_ingress(&headers).unwrap();
            runtime
                .resolve_admitted_identity_with_proof(&headers, &admission)
                .unwrap()
        };
        let admitted = resolve(&runtime);
        let context = ExecutionContext::new("default").unwrap();
        let origin = runtime
            .secret_reference_origin(&admitted.identity, &context, admitted.proof.as_ref())
            .unwrap();
        assert!(
            runtime
                .secret_reference_origin(&admitted.identity, &context, None)
                .is_err()
        );
        let encoded = origin.encode().unwrap();
        assert!(!String::from_utf8_lossy(&encoded).contains("operator_987"));
        let restarted = BrokerRuntime::new(config.clone()).unwrap();
        check_in_reference_transaction(
            &restarted,
            SecretReferenceOrigin::decode(&encoded).unwrap(),
        )
        .unwrap();
        fs::write(&caller_path, "synthetic-replacement-caller-secret").unwrap();
        let mut rejected = config.clone();
        rejected.policy.grants = super::super::tests::base_fake_config().policy.grants;
        rejected.policy.grants[0].subjects = vec!["group:missing".into()];
        let error = match BrokerRuntime::new_for_reload(rejected, &restarted) {
            Ok(_) => panic!("missing managed group must reject candidate"),
            Err(error) => error,
        };
        let RuntimeError::Config(ConfigError::Invalid { errors }) = error else {
            panic!("expected managed group validation failure");
        };
        assert!(errors.iter().any(|error| error.contains("group:missing")));
        // Both retained origins and newly admitted work remain usable after a
        // rejected candidate loaded a different secret from the same path.
        check_in_reference_transaction(&restarted, origin.clone()).unwrap();
        let fresh_active = resolve(&restarted);
        let fresh_active_origin = restarted
            .secret_reference_origin(
                &fresh_active.identity,
                &context,
                fresh_active.proof.as_ref(),
            )
            .unwrap();
        check_in_reference_transaction(&restarted, fresh_active_origin).unwrap();
        let mut rotated = BrokerRuntime::new_for_reload(config.clone(), &restarted).unwrap();
        // A fully built candidate can still fail host admission. Construction
        // alone must not mutate the accepted generation.
        check_in_reference_transaction(&restarted, origin.clone()).unwrap();
        rotated.activate_runtime_authority().unwrap();
        assert!(check_in_reference_transaction(&rotated, origin.clone()).is_err());
        fs::write(&caller_path, "synthetic-original-caller-secret").unwrap();
        let mut restored = BrokerRuntime::new_for_reload(config.clone(), &rotated).unwrap();
        restored.activate_runtime_authority().unwrap();
        assert!(check_in_reference_transaction(&restored, origin).is_err());
        let fresh = resolve(&restored);
        let fresh_origin = restored
            .secret_reference_origin(&fresh.identity, &context, fresh.proof.as_ref())
            .unwrap();
        check_in_reference_transaction(&restored, fresh_origin.clone()).unwrap();
        let mut removed_config = config.clone();
        removed_config.identity.trusted_callers.clear();
        let mut removed = BrokerRuntime::new_for_reload(removed_config, &restored).unwrap();
        removed.activate_runtime_authority().unwrap();
        let mut returned = BrokerRuntime::new_for_reload(config, &removed).unwrap();
        returned.activate_runtime_authority().unwrap();
        assert!(check_in_reference_transaction(&returned, fresh_origin).is_err());
    }

    #[test]
    fn private_origin_round_trip_preserves_owner_and_only_audit_allowlist_is_exported() {
        let origin = SecretReferenceOrigin(OriginData {
            version: 1,
            principal: "alice".into(),
            execution_context: "default".into(),
            authentication: OriginAuthentication::BrokerToken {
                source: "tokens".into(),
                header: "authorization".into(),
                scheme: "Bearer".into(),
                token_id: "00000000-0000-4000-8000-000000000001".into(),
                verifier_binding: [8; 32],
            },
            caller: Some(OriginCaller {
                name: "relay".into(),
                generation: 4,
            }),
        });
        let decoded = SecretReferenceOrigin::decode(&origin.encode().unwrap()).unwrap();
        assert!(origin == decoded);
        assert_eq!(
            decoded.audit_metadata(),
            json!({"principal":"alice","authenticationKind":"broker_tokens","tokenId":"00000000-0000-4000-8000-000000000001","callerId":"relay"})
        );
        let mut wrong_context = decoded.clone();
        wrong_context.0.execution_context = "other".into();
        assert!(origin != wrong_context);
        let mut wrong_generation = decoded;
        wrong_generation.0.caller.as_mut().unwrap().generation += 1;
        assert!(origin != wrong_generation);
    }
}
