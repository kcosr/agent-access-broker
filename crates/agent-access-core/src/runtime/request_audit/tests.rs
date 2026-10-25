use super::*;
use agent_access_provider::{
    AuditDisplay, AuditInputProjection, AuditInputRule, AuditOverflow, AuditRole, AuditValueKind,
    BodyAdmission, MultipartUploadSpec, ScopeRequest, ScopeResolution, StateDisposition,
};
use async_trait::async_trait;
use tempfile::TempDir;

struct CapturingProvider {
    upload: bool,
    require_credential: bool,
}

fn declaration() -> AuditInputProjection {
    AuditInputProjection::new([
        AuditInputRule::value("project", "Project", "/project")
            .kind(AuditValueKind::Identifier)
            .display(AuditDisplay::Primary)
            .role(AuditRole::Target)
            .max_bytes(1024)
            .overflow(AuditOverflow::Omit),
        AuditInputRule::value("query", "Requested query", "/query")
            .kind(AuditValueKind::Query)
            .display(AuditDisplay::Primary)
            .max_bytes(4096)
            .overflow(AuditOverflow::Prefix),
        AuditInputRule::value("filename", "Filename", "/filename")
            .kind(AuditValueKind::Path)
            .max_bytes(1024)
            .overflow(AuditOverflow::Omit),
        AuditInputRule::presence("body", "Body supplied", "/body"),
    ])
}

impl agent_access_provider::test_support::DescribedProvider for CapturingProvider {
    fn descriptor(&self) -> ServiceDescriptor {
        let mut descriptor = agent_access_fake::fake_descriptor();
        let mut action = ActionDescriptor::new(
            "echo",
            "Capture fixture",
            json!({
                "type":"object", "properties":{
                    "project":{"type":"string"}, "query":{"type":"string","enum":["approved"]},
                    "filename":{"type":"string"}, "body":{"type":"string","x-agent-access-sensitive":true}
                }
            }),
        )
        .read_only()
        .scope("project")
        .credential_modes(["service"])
        .audit_inputs(declaration());
        if self.upload {
            action.io = ActionIo::MultipartUpload {
                plan: MultipartUploadSpec::new("attachment", "/attachments", "file"),
            };
        }
        descriptor.actions = vec![action];
        if self.require_credential {
            descriptor.credentials =
                CredentialDescriptor::default().profile("token", "bearer_token");
        }
        descriptor
    }
}

#[async_trait]
impl Provider for CapturingProvider {
    async fn resolve_scopes(
        &self,
        request: ScopeRequest<'_>,
    ) -> Result<ScopeResolution, ProviderError> {
        // Deliberately validate only scope: audit checks are not a schema validator.
        let project = request.inputs()["project"].as_str().unwrap_or("DENIED");
        Ok(ScopeResolution::resources(BTreeMap::from([(
            "project".into(),
            vec![project.into()],
        )])))
    }

    async fn authorize_body_parts(
        &self,
        request: &AdmittedRequest,
        _: Option<&ProviderState>,
    ) -> Result<BodyAdmission, ProviderError> {
        if request.inputs()["filename"]
            .as_str()
            .is_some_and(|name| name.contains('/'))
        {
            return Err(ProviderError::deny(
                ReasonCode::InputInvalid,
                "invalid filename",
            ));
        }
        Ok(BodyAdmission::new(vec![], StateDisposition::Keep))
    }

    async fn invoke(&self, _: ProviderInvocation) -> Result<ProviderResult, ProviderError> {
        // Arbitrary provider metadata cannot replace the host envelope.
        Err(
            ProviderError::deny(ReasonCode::InputInvalid, "provider rejected request")
                .with_audit(json!({"requestAudit":{"fields":["provider override"]}})),
        )
    }
}

fn operation() -> GovernedOperationContext {
    GovernedOperationContext {
        admission: None,
        operation: OperationContext {
            agent_request_id: "audit-test".into(),
            broker_request_id: "audit-test-broker".into(),
            identity: IdentityContext::anonymous(),
            service: "fake".into(),
            action: "echo".into(),
            source: SourceContext::unknown(),
        },
        execution_context: ExecutionContext::new(DEFAULT_EXECUTION_CONTEXT).unwrap(),
    }
}

fn fixture(
    upload: bool,
    credential_failure: bool,
    kind: crate::AuditStoreType,
) -> (BrokerRuntime, TempDir) {
    let dir = tempfile::tempdir().unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    let mut config = super::super::tests::base_fake_config();
    if credential_failure {
        config
            .credentials
            .service
            .get_mut("fake")
            .unwrap()
            .token_ref = Some(format!(
            "file:{}",
            dir.path().join("missing-token").display()
        ));
    }
    config.audit = Some(crate::AuditConfig::new(
        kind,
        dir.path().join("audit").display().to_string(),
    ));
    config.limits.upload_spool_dir = dir.path().join("spool").display().to_string();
    let runtime = BrokerRuntime::with_providers(
        config,
        vec![Arc::new(CapturingProvider {
            upload,
            require_credential: credential_failure,
        })],
    )
    .unwrap();
    (runtime, dir)
}

fn record(dir: &TempDir, kind: crate::AuditStoreType) -> Value {
    let records = crate::test_support::read_audit_records(kind, &dir.path().join("audit"));
    assert_eq!(records.len(), 1);
    records[0].clone()
}

#[tokio::test]
async fn successful_preparation_snapshots_request_facts_before_provider_failure_in_both_stores() {
    let mut snapshots = Vec::new();
    for kind in [crate::AuditStoreType::Jsonl, crate::AuditStoreType::Sqlite] {
        let (runtime, dir) = fixture(false, false, kind);
        let prepared = runtime.begin_invoke(operation(), InvokeRequest::new(json!({
            "project":"TEST", "query":"not in the schema enum", "body":"BODY_CANARY_NEVER_CAPTURE"
        }))).await.unwrap();
        let before = serde_json::to_value(&prepared.finalize_context.request_audit).unwrap();
        let response = runtime.finish_prepared_invoke(prepared, vec![]).await;
        assert_eq!(
            response.envelope.reason_code,
            Some(ReasonCode::InputInvalid.into())
        );
        let stored = record(&dir, kind);
        assert_eq!(stored["requestAudit"], before);
        assert_eq!(
            stored["requestAudit"]["fields"][1]["value"],
            "not in the schema enum"
        );
        assert!(!stored.to_string().contains("BODY_CANARY_NEVER_CAPTURE"));
        assert!(
            !serde_json::to_value(response)
                .unwrap()
                .to_string()
                .contains("not in the schema enum")
        );
        snapshots.push(stored["requestAudit"].clone());
    }
    assert_eq!(snapshots[0], snapshots[1]);
}

#[tokio::test]
async fn denial_and_initial_credential_failure_do_not_capture_values() {
    for credential_failure in [false, true] {
        let (runtime, dir) = fixture(false, credential_failure, crate::AuditStoreType::Jsonl);
        let project = if credential_failure { "TEST" } else { "DENIED" };
        assert!(
            runtime
                .begin_invoke(
                    operation(),
                    InvokeRequest::new(json!({
                        "project":project, "query":"PRIVATE_REQUEST_CANARY"
                    }))
                )
                .await
                .is_err()
        );
        let stored = record(&dir, crate::AuditStoreType::Jsonl);
        assert!(stored.get("requestAudit").is_none());
        assert!(!stored.to_string().contains("PRIVATE_REQUEST_CANARY"));
    }
}

#[tokio::test]
async fn upload_action_without_body_admission_never_captures_local_filename() {
    let (runtime, dir) = fixture(true, false, crate::AuditStoreType::Jsonl);
    let prepared = runtime
        .begin_invoke(
            operation(),
            InvokeRequest::new(json!({
                "project":"TEST", "filename":"/home/x/secret.pdf", "query":"PRIVATE_UPLOAD_CANARY"
            })),
        )
        .await
        .unwrap();
    assert!(prepared.finalize_context.request_audit.is_none());
    // This is the JSON/HTTP-MCP path: it does not call body admission.
    runtime.finish_prepared_invoke(prepared, vec![]).await;
    let stored = record(&dir, crate::AuditStoreType::Jsonl);
    assert!(stored.get("requestAudit").is_none());
    assert!(!stored.to_string().contains("secret.pdf"));
}

#[tokio::test]
async fn upload_snapshot_is_created_only_after_successful_metadata_admission() {
    for filename in ["/home/x/secret.pdf", "report.pdf"] {
        let (runtime, dir) = fixture(true, false, crate::AuditStoreType::Jsonl);
        let prepared = runtime
            .begin_invoke(
                operation(),
                InvokeRequest::new(json!({"project":"TEST","filename":filename})),
            )
            .await
            .unwrap();
        let result = runtime.authorize_body_parts(prepared).await;
        if filename.starts_with('/') {
            assert!(result.is_err());
            assert!(
                record(&dir, crate::AuditStoreType::Jsonl)
                    .get("requestAudit")
                    .is_none()
            );
        } else {
            let prepared = result.unwrap();
            assert!(prepared.finalize_context.request_audit.is_some());
            runtime
                .fail_prepared_invoke(
                    prepared,
                    ProviderError::deny(ReasonCode::InputInvalid, "upload size mismatch"),
                )
                .await;
            assert_eq!(
                record(&dir, crate::AuditStoreType::Jsonl)["requestAudit"]["fields"][2]["value"],
                filename
            );
        }
    }
}
