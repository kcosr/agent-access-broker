//! Provider-owned domain reasons keep their fixed outcome through
//! management: a credential verification failure reports its registered
//! domain reason's decision, code and status in both the response and the
//! audit record, and records a failed verification only for an upstream
//! status.
use super::*;
use agent_access_core::{BackendRegistry, CredentialManagementPurpose, ProvidersConfig};
use agent_access_provider::{
    BackendConfig, BackendRegistration, BuildContext, CorrelationContext, EgressProxyConfig,
    ExecutionCredential, ProviderBuildError, ProviderCredentialVerification, ProviderFailureStatus,
    ProviderReasonDefinition, ScopeRequest, ScopeResolution, ValidationContext,
    parse_backend_config,
    test_support::{bearer_credential, credential_with_profile},
};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;

const SERVICE: &str = "verifier";
const PROFILE: &str = "verifier-token";

/// The upstream pauses verification: always error/503.
static MAINTENANCE: ProviderReasonDefinition = ProviderReasonDefinition::error(
    "verifier_maintenance",
    ProviderFailureStatus::ServiceUnavailable,
);
/// The upstream account is locked: always deny/403.
static ACCOUNT_LOCKED: ProviderReasonDefinition =
    ProviderReasonDefinition::deny("verifier_account_locked", ProviderFailureStatus::Forbidden);

static VERIFIER_BACKEND: BackendRegistration = BackendRegistration::new(
    agent_access_provider::module_metadata!(),
    SERVICE,
    parse_backend_config::<VerifierConfig>,
)
.with_domain_reasons(&[&MAINTENANCE, &ACCOUNT_LOCKED])
.development_only();

/// A backend whose credential verification fails with the domain reason
/// the stored token names; its one action is never invoked.
#[derive(Debug, Clone, Default, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct VerifierConfig {}

impl BackendConfig for VerifierConfig {
    fn kind(&self) -> &'static str {
        SERVICE
    }

    fn validate(&self, _: &ValidationContext<'_>, _: &mut Vec<String>) {}

    fn descriptor(&self) -> ServiceDescriptor {
        // One per_user action, which the owner's verification grant names.
        ServiceDescriptor::new(SERVICE, "Domain reason verifier")
            .with_actions(vec![
                ActionDescriptor::new("probe", "Never invoked", json!({"type": "object"}))
                    .credential_modes(["per_user"]),
            ])
            .with_credentials(CredentialDescriptor::default().profile(PROFILE, "bearer_token"))
    }

    fn egress_proxies(&self) -> Vec<(String, &EgressProxyConfig)> {
        vec![]
    }

    fn build(&self, _: &BuildContext<'_>) -> Result<Arc<dyn Provider>, ProviderBuildError> {
        Ok(Arc::new(self.clone()))
    }
}

#[async_trait::async_trait]
impl Provider for VerifierConfig {
    async fn resolve_scopes(&self, _: ScopeRequest<'_>) -> Result<ScopeResolution, ProviderError> {
        panic!("the verifier's action is never invoked")
    }

    async fn invoke(&self, _: ProviderInvocation) -> Result<ProviderResult, ProviderError> {
        panic!("the verifier's action is never invoked")
    }

    async fn verify_execution_credential(
        &self,
        credential: &ExecutionCredential,
        _: &CorrelationContext,
    ) -> Result<Option<ProviderCredentialVerification>, ProviderError> {
        let stored = |token: &str| credential_with_profile(bearer_credential(token), PROFILE);
        let definition = if *credential == stored("maintenance-token") {
            &MAINTENANCE
        } else if *credential == stored("locked-token") {
            &ACCOUNT_LOCKED
        } else {
            panic!("unexpected verifier credential {credential:?}")
        };
        Err(ProviderError::domain(
            definition,
            "the verifier upstream refused verification",
        ))
    }
}

#[tokio::test]
async fn credential_verification_keeps_domain_reason_outcomes() {
    let admin_token_path = temp_path("domain-reason-admin-token");
    let key_path = temp_path("domain-reason-key");
    let store_path = temp_path("domain-reason-store.sqlite");
    let audit_path = temp_path("domain-reason.audit.jsonl");
    std::fs::write(&admin_token_path, "admin-token").unwrap();
    std::fs::write(&key_path, URL_SAFE_NO_PAD.encode([9_u8; 32])).unwrap();
    let mut config =
        managed_jira_verify_config(&admin_token_path, &key_path, &store_path, &audit_path);
    // The verifier replaces Jira.
    config.credentials.per_user.clear();
    config.credentials.connections.clear();
    config.policy.grants.retain(|grant| grant.service != "jira");
    super::use_token_connection(&mut config, SERVICE, PROFILE, &[SERVICE]);
    config.policy.grants.push(PolicyGrantConfig {
        subjects: vec!["user:alice".to_string()],
        execution_contexts: None,
        service: SERVICE.to_string(),
        actions: vec!["probe".to_string()],
        resources: ResourceSelection::default(),
        credential_mode: "per_user".to_string(),
        priority: None,
    });
    let registry = BackendRegistry::new(
        crate::backend_registry()
            .registrations()
            .chain([&VERIFIER_BACKEND])
            .collect::<Vec<_>>(),
    )
    .unwrap();
    config.providers = ProvidersConfig::new(Arc::new(registry))
        .with(agent_access_fake::FakeProviderConfig::default())
        .with(VerifierConfig::default());
    let broker = TestBroker::start_config(&config).await;
    let runtime = broker.runtime();
    let store = runtime.managed_store().unwrap().clone();
    store
        .create_or_update_principal(PrincipalWriteRequest {
            role: agent_access_core::PrincipalRole::User,
            self_service_enabled: None,
            principal_id: "alice".to_string(),
            kind: "user".to_string(),
            display_name: None,
            email: None,
            external_subject: None,
            created_by: "admin".to_string(),
        })
        .unwrap();
    let app = broker.app();

    // A domain failure with an upstream status (503) records a failed
    // verification like the standard upstream failures; one with another
    // status (403) leaves the credential's verification state alone.
    for (name, token, status, decision, reason, recorded) in [
        (
            "maintenance",
            "maintenance-token",
            StatusCode::SERVICE_UNAVAILABLE,
            "error",
            "verifier_maintenance",
            true,
        ),
        (
            "locked",
            "locked-token",
            StatusCode::FORBIDDEN,
            "deny",
            "verifier_account_locked",
            false,
        ),
    ] {
        store
            .upsert_user_credential(
                runtime.credential_key_ring().unwrap(),
                CredentialWriteRequest {
                    owner_principal_id: "alice".to_string(),
                    service: SERVICE.to_string(),
                    name: "default".to_string(),
                    profile: PROFILE.to_string(),
                    credential_kind: "bearer_token".to_string(),
                    secret: json!({"token": token}),
                    metadata: json!({}),
                    actor: "admin".to_string(),
                },
                CredentialManagementPurpose::Administrative,
            )
            .unwrap();
        let request_id = format!("domain-reason-verify-{name}");
        let response = admin_request(
            app.clone(),
            Method::POST,
            &format!("/v1/admin/principals/alice/credentials/connections/{SERVICE}/verify"),
            Some(&request_id),
            Some("admin-token"),
        )
        .await;
        assert_eq!(response.status(), status, "{name}");
        let body = response_json(response).await;
        assert_eq!(body["ok"], false, "{body}");
        assert_eq!(body["decision"], decision, "{body}");
        assert_eq!(body["reasonCode"], reason, "{body}");
        assert_eq!(
            body["error"]["message"], "the verifier upstream refused verification",
            "{body}"
        );

        let audit = std::fs::read_to_string(&audit_path).unwrap();
        let outcomes = audit
            .lines()
            .map(|line| serde_json::from_str::<Value>(line).unwrap())
            .filter(|record| {
                record["agentRequestId"] == request_id.as_str()
                    && record["providerAudit"]["management"]["phase"].is_null()
            })
            .collect::<Vec<_>>();
        assert_eq!(outcomes.len(), 1, "{outcomes:?}");
        let record = &outcomes[0];
        assert_eq!(record["action"], "admin.credentials.verify", "{record}");
        assert_eq!(record["decision"], decision, "{record}");
        assert_eq!(record["reasonCode"], reason, "{record}");
        assert_eq!(
            record["providerAudit"]["management"]["reasonCode"], reason,
            "{record}"
        );
        assert_eq!(
            record["providerAudit"]["management"]["target"]["probeService"], SERVICE,
            "{record}"
        );

        let credential = store
            .credential_by_tuple("alice", SERVICE, "default")
            .unwrap();
        if recorded {
            assert_eq!(
                credential.verification_status.as_deref(),
                Some("verification_failed")
            );
            assert!(credential.last_verification_attempt_at.is_some());
            assert_eq!(
                credential.last_verification_error_code.as_deref(),
                Some("verifier_maintenance")
            );
        } else {
            assert_eq!(
                credential.verification_status.as_deref(),
                Some("not_verified")
            );
            assert!(credential.last_verification_attempt_at.is_none());
            assert!(credential.last_verification_error_code.is_none());
        }
    }
}
