use super::*;
use agent_access_provider::test_support::{
    bearer_credential, credential_token, credential_username,
};
#[path = "credential_discovery_tests.rs"]
mod credential_discovery;
#[path = "trusted_user_tests.rs"]
mod trusted_user;
use crate::{
    BrokerTokensConfig, CredentialEncryptionConfig, CredentialEncryptionKeyConfig,
    CredentialsConfig, DeploymentConfig, IdentityConfig, IdentityGroupConfig, IdentitySourceConfig,
    ManagedStoreConfig, PolicyGrantConfig, StaticPrincipalConfig,
};
use agent_access_provider::LookupRequirement;
use async_trait::async_trait;
use base64::Engine;
use futures_util::StreamExt;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Condvar, MutexGuard};
use std::time::SystemTime;
use tempfile::TempDir;
use tracing::field::{Field, Visit};
use tracing::{Event, Subscriber};
use tracing_subscriber::layer::Context as TracingLayerContext;
use tracing_subscriber::prelude::*;
use tracing_subscriber::registry::LookupSpan;

fn default_execution_context() -> ExecutionContext {
    ExecutionContext::new(DEFAULT_EXECUTION_CONTEXT)
        .expect("built-in default execution context is valid")
}

fn governed(operation: OperationContext) -> GovernedOperationContext {
    GovernedOperationContext {
        operation,
        execution_context: default_execution_context(),
    }
}

#[test]
fn invoke_request_defaults_formats_and_rejects_unknown_top_level_fields() {
    let request: InvokeRequest = serde_json::from_value(json!({
        "inputs": { "issue": "PROJ-1" }
    }))
    .unwrap();
    assert_eq!(
        request.read_content_format,
        agent_access_provider::presentation::ReadContentFormat::Native
    );
    assert_eq!(
        request.response_format,
        agent_access_provider::presentation::ResponseFormat::Json
    );

    let explicit: InvokeRequest = serde_json::from_value(json!({
        "inputs": {},
        "readContentFormat": "text",
        "responseFormat": "markdown"
    }))
    .unwrap();
    assert_eq!(
        explicit.read_content_format,
        agent_access_provider::presentation::ReadContentFormat::Text
    );
    assert_eq!(
        explicit.response_format,
        agent_access_provider::presentation::ResponseFormat::Markdown
    );

    assert!(
        serde_json::from_value::<InvokeRequest>(json!({
            "inputs": {},
            "outputFormat": "markdown"
        }))
        .is_err()
    );
}

#[tokio::test]
async fn response_options_follow_provider_action_resolution_without_provider_execution() {
    let provider = Arc::new(ResponseResolutionTraceProvider::default());
    let runtime =
        BrokerRuntime::with_providers(base_fake_config(), vec![Arc::clone(&provider)]).unwrap();

    let invoke = |action: &'static str| {
        runtime.invoke(
            governed(OperationContext {
                agent_request_id: format!("agent-{action}"),
                broker_request_id: format!("broker-{action}"),
                identity: IdentityContext::anonymous(),
                service: "fake".to_string(),
                action: action.to_string(),
                source: SourceContext::unknown(),
            }),
            InvokeRequest {
                inputs: json!({"project": "TEST", "message": "hello"}),
                response_format: agent_access_provider::presentation::ResponseFormat::Markdown,
                ..InvokeRequest::new(json!({}))
            },
        )
    };

    let unknown = invoke("missing").await;
    assert_eq!(
        unknown.envelope.reason_code,
        Some(ReasonCode::ServiceActionDenied.into())
    );

    let unsupported = invoke("echo").await;
    assert_eq!(
        unsupported.envelope.reason_code,
        Some(ReasonCode::ResponseFormatUnsupported.into())
    );
    assert_eq!(
        unsupported.status,
        ReasonCode::ResponseFormatUnsupported.http_status()
    );

    assert_eq!(provider.scope_resolutions.load(Ordering::SeqCst), 0);
    assert_eq!(provider.invocations.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn invocation_identity_admission_precedes_action_and_response_option_resolution() {
    let provider = Arc::new(ResponseResolutionTraceProvider::default());
    let runtime =
        BrokerRuntime::with_providers(base_fake_config(), vec![Arc::clone(&provider)]).unwrap();
    let denied_identity = IdentityContext {
        caller_id: None,
        principal: "broker-admin".to_string(),
        principal_subject: Some("broker-admin".to_string()),
        groups: vec![],
        policy_groups: vec![],
        authenticated: true,
        source: Some(IdentitySourceAudit {
            namespace: None,
            binding_id: None,
            name: "broker".to_string(),
            kind: "broker_tokens".to_string(),
            token_header: "Authorization".to_string(),
            token_scheme: "Bearer".to_string(),
            token_class: Some(BrokerTokenClass::Admin),
            token_id: Some("tok_admin".to_string()),
            token_scopes: None,
        }),
    };

    for action in ["missing", "echo"] {
        let response = runtime
            .invoke(
                governed(OperationContext {
                    agent_request_id: format!("agent-{action}"),
                    broker_request_id: format!("broker-{action}"),
                    identity: denied_identity.clone(),
                    service: "fake".to_string(),
                    action: action.to_string(),
                    source: SourceContext::unknown(),
                }),
                InvokeRequest {
                    inputs: json!({"project": "TEST", "message": "hello"}),
                    response_format: agent_access_provider::presentation::ResponseFormat::Markdown,
                    ..InvokeRequest::new(json!({}))
                },
            )
            .await;

        assert_eq!(
            response.envelope.reason_code,
            Some(ReasonCode::BrokerTokenClassDenied.into())
        );
        assert_eq!(
            response.status,
            ReasonCode::BrokerTokenClassDenied.http_status()
        );
    }

    for (action, allowed_action) in [("missing", "echo"), ("echo", "missing")] {
        let response = runtime
            .invoke(
                governed(OperationContext {
                    agent_request_id: format!("agent-caveat-{action}"),
                    broker_request_id: format!("broker-caveat-{action}"),
                    identity: shell_token_identity(json!({"allowedExecutionContexts": ["default"],
                        "allowedServices": ["fake"],
                        "serviceRestrictions": {
                            "fake": {
                                "actions": [allowed_action]
                            }
                        }
                    })),
                    service: "fake".to_string(),
                    action: action.to_string(),
                    source: SourceContext::unknown(),
                }),
                InvokeRequest {
                    inputs: json!({"project": "TEST", "message": "hello"}),
                    response_format: agent_access_provider::presentation::ResponseFormat::Markdown,
                    ..InvokeRequest::new(json!({}))
                },
            )
            .await;

        assert_eq!(
            response.envelope.reason_code,
            Some(ReasonCode::ServiceActionDenied.into())
        );
        assert_eq!(
            response.envelope.reason.as_deref(),
            Some("broker token is not allowed to invoke this service action")
        );
    }

    assert_eq!(provider.scope_resolutions.load(Ordering::SeqCst), 0);
    assert_eq!(provider.invocations.load(Ordering::SeqCst), 0);
}

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

#[cfg(unix)]
fn mode(path: &Path) -> u32 {
    fs::metadata(path).unwrap().permissions().mode() & 0o777
}

fn resource_selection(ids: &[&str]) -> ResourceSelection {
    ResourceSelection {
        resource_ids: ids.iter().map(|id| (*id).to_string()).collect(),
        resource_group_ids: vec![],
    }
}

fn test_resources() -> Vec<ResourceDefinition> {
    let mut resources = Vec::new();
    for (resource_type, prefix, values) in [
        (
            agent_access_jira::JIRA_PROJECT_RESOURCE.id().clone(),
            "project",
            &["TEST", "ENG", "OPS", "PROJ", "OTHER", "RESEARCH"][..],
        ),
        (
            agent_access_fake::FAKE_PROJECT_RESOURCE.id().clone(),
            "fake-project",
            &["TEST", "ENG", "OPS", "PROJ", "OTHER", "RESEARCH"][..],
        ),
        (
            agent_access_confluence::CONFLUENCE_SPACE_RESOURCE
                .id()
                .clone(),
            "space",
            &["ENG", "OPS", "RESEARCH", "TEST"][..],
        ),
        (
            agent_access_provider::GIT_REPOSITORY_RESOURCE.id().clone(),
            "repository",
            &[
                "sip/service",
                "sip/tool",
                "other/tool",
                "target/service",
                "source/contribution",
            ][..],
        ),
    ] {
        for value in values {
            resources.push(ResourceDefinition {
                id: format!("{prefix}-{}", value.replace('/', "-")),
                display_name: None,
                resource_type: resource_type.clone(),
                selector: ResourceSelector::Exact {
                    value: (*value).into(),
                },
                allowed_execution_contexts: vec![DEFAULT_EXECUTION_CONTEXT.into()],
                enabled: true,
            });
        }
        resources.push(ResourceDefinition {
            id: format!("{prefix}-all"),
            display_name: None,
            resource_type: resource_type.clone(),
            selector: ResourceSelector::All,
            allowed_execution_contexts: vec![DEFAULT_EXECUTION_CONTEXT.into()],
            enabled: true,
        });
    }
    for value in ["sip", "platform", "target", "source"] {
        resources.push(ResourceDefinition {
            id: format!("repository-namespace-{value}"),
            display_name: None,
            resource_type: agent_access_provider::GIT_REPOSITORY_RESOURCE.id().clone(),
            selector: ResourceSelector::Namespace {
                value: value.into(),
            },
            allowed_execution_contexts: vec![DEFAULT_EXECUTION_CONTEXT.into()],
            enabled: true,
        });
    }
    resources
}

fn set_resource_contexts(config: &mut BrokerConfig) {
    let contexts = config
        .execution_context
        .as_ref()
        .unwrap()
        .allowed_values
        .clone();
    for resource in &mut config.policy.resources {
        resource.allowed_execution_contexts = contexts.clone();
    }
}

fn seed_test_resource_catalog(store_path: &Path) {
    let store = ManagedStore::open(
        &ManagedStoreConfig {
            kind: "sqlite".into(),
            path: store_path.display().to_string(),
            require_registered_principal_for_invocation: false,
            auto_migrate: true,
        },
        ManagedStoreOpenMode::Startup,
    )
    .unwrap();
    drop(store);
    let conn = rusqlite::Connection::open(store_path).unwrap();
    let now = Utc::now().to_rfc3339();
    for resource in test_resources() {
        let (kind, value) = match resource.selector {
            ResourceSelector::Exact { value } => ("exact", value),
            ResourceSelector::Namespace { value } => ("namespace", value),
            ResourceSelector::All => ("all", String::new()),
        };
        conn.execute("INSERT OR IGNORE INTO resources (resource_id,resource_type,selector_kind,selector_value,allowed_execution_contexts_json,enabled,version,created_at,created_by,updated_at,updated_by) VALUES (?1,?2,?3,?4,?5,1,1,?6,'admin',?6,'admin')",rusqlite::params![resource.id,resource.resource_type.as_str(),kind,value,serde_json::to_string(&resource.allowed_execution_contexts).unwrap(),now]).unwrap();
    }
}

pub(super) const TEST_NODE_ID: &str = "runtime-test-node";

fn jsonl_audit_config(path: impl Into<String>) -> crate::AuditConfig {
    crate::AuditConfig::new(crate::AuditStoreType::Jsonl, path)
}

fn test_audit_sink(config: crate::AuditConfig) -> AuditSink {
    AuditSink::new(
        Some(&config),
        &crate::LimitsConfig::default(),
        Arc::new(AuditRuntimeRegistry::new()),
        TEST_NODE_ID,
        AuditOpenMode::Startup,
    )
    .unwrap()
}

pub(super) fn test_audit_sink_lock(sink: &AuditSink) -> Arc<Mutex<()>> {
    Arc::clone(&sink.writer.as_ref().unwrap().config.lock)
}

fn test_audit_runtime_parts(
    config: Option<crate::AuditConfig>,
) -> (AuditSink, Arc<AuditRuntimeRegistry>) {
    let registry = Arc::new(AuditRuntimeRegistry::new());
    let sink = AuditSink::new(
        config.as_ref(),
        &crate::LimitsConfig::default(),
        Arc::clone(&registry),
        TEST_NODE_ID,
        AuditOpenMode::Startup,
    )
    .unwrap();
    (sink, registry)
}

fn test_audit_sink_with_limits(
    config: crate::AuditConfig,
    limits: crate::LimitsConfig,
) -> AuditSink {
    AuditSink::new(
        Some(&config),
        &limits,
        Arc::new(AuditRuntimeRegistry::new()),
        TEST_NODE_ID,
        AuditOpenMode::Startup,
    )
    .unwrap()
}

fn runtime_with_replaced_config(runtime: &BrokerRuntime, config: BrokerConfig) -> BrokerRuntime {
    let policy_snapshot = Arc::new(ArcSwap::from_pointee(PolicySnapshot::from_config(
        &config,
        runtime.config_generation.unwrap_or(0),
    )));
    BrokerRuntime {
        effective_credentials: Arc::new(config.credentials.clone()),
        imported_catalog: runtime.imported_catalog.clone(),
        import_dispatch: runtime.import_dispatch.clone(),
        scoped_mcp: runtime.scoped_mcp.clone(),
        oauth: runtime.oauth.clone(),
        invocation_limits: Arc::new(crate::ConfiguredInvocationLimits::from_config(&config)),
        config: Arc::new(config),
        providers: Arc::clone(&runtime.providers),
        services: Arc::clone(&runtime.services),
        resource_types: Arc::clone(&runtime.resource_types),
        policy_snapshot,
        policy_mutation_lock: Arc::clone(&runtime.policy_mutation_lock),
        identity_sources: Arc::clone(&runtime.identity_sources),
        managed_store: runtime.managed_store.clone(),
        credential_key_ring: runtime.credential_key_ring.clone(),
        trusted_callers: runtime.trusted_callers.clone(),
        broker_token_hasher: runtime.broker_token_hasher.clone(),
        local_password_hasher: runtime.local_password_hasher.clone(),
        browser_csrf_key: runtime.browser_csrf_key.clone(),
        microsoft_oidc: runtime.microsoft_oidc.clone(),
        network: runtime.network.clone(),
        audit: runtime.audit.clone(),
        audit_registry: Arc::clone(&runtime.audit_registry),
        node_id: Arc::clone(&runtime.node_id),
        config_generation: runtime.config_generation,
        provider_fixtures: runtime.provider_fixtures.clone(),
    }
}

fn audit_writer_hook_test_lock() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

pub(super) struct AuditWriterHookGuard {
    _guard: MutexGuard<'static, ()>,
}

impl Drop for AuditWriterHookGuard {
    fn drop(&mut self) {
        *audit_writer_test_hook()
            .lock()
            .unwrap_or_else(|error| error.into_inner()) = None;
    }
}

pub(super) fn install_audit_writer_hook(
    hook: impl Fn(AuditWriterTestEvent) + Send + Sync + 'static,
) -> AuditWriterHookGuard {
    let guard = audit_writer_hook_test_lock()
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    *audit_writer_test_hook()
        .lock()
        .unwrap_or_else(|error| error.into_inner()) = Some(Arc::new(hook));
    AuditWriterHookGuard { _guard: guard }
}

fn release_gate(gate: &Arc<(Mutex<bool>, Condvar)>) {
    let (lock, condition) = &**gate;
    *lock.lock().unwrap() = true;
    condition.notify_all();
}

fn audit_records(path: &Path) -> Vec<Value> {
    crate::test_support::read_audit_records(crate::AuditStoreType::Jsonl, path)
}

fn stream_phase_counts(records: &[Value]) -> BTreeMap<String, usize> {
    let mut counts = BTreeMap::new();
    for phase in records.iter().filter_map(|record| {
        record
            .get("providerAudit")
            .and_then(|audit| audit.get("streamPhase"))
            .and_then(Value::as_str)
    }) {
        *counts.entry(phase.to_string()).or_insert(0) += 1;
    }
    counts
}

#[test]
fn audit_sinks_for_same_file_share_rotation_lock() {
    let shared_path = temp_path("shared-audit.jsonl");
    let shared_path_with_dot_parent = shared_path
        .parent()
        .unwrap()
        .join(".")
        .join(shared_path.file_name().unwrap());
    let other_path = temp_path("other-audit.jsonl");
    let first = test_audit_sink(jsonl_audit_config(shared_path.display().to_string()));
    let second = test_audit_sink(jsonl_audit_config(shared_path.display().to_string()));
    let equivalent = test_audit_sink(jsonl_audit_config(
        shared_path_with_dot_parent.display().to_string(),
    ));
    let other = test_audit_sink(jsonl_audit_config(other_path.display().to_string()));

    assert!(std::sync::Arc::ptr_eq(
        &test_audit_sink_lock(&first),
        &test_audit_sink_lock(&second)
    ));
    assert!(std::sync::Arc::ptr_eq(
        &test_audit_sink_lock(&first),
        &test_audit_sink_lock(&equivalent)
    ));
    assert!(!std::sync::Arc::ptr_eq(
        &test_audit_sink_lock(&first),
        &test_audit_sink_lock(&other)
    ));
}

async fn durable_append_waits_for_sync_before_ack(durability: AuditDurability) {
    let audit_path = temp_path(match durability {
        AuditDurability::Write => "durable-write-audit.jsonl",
        AuditDurability::SyncData => "durable-sync-data-audit.jsonl",
        AuditDurability::SyncAll => "durable-sync-all-audit.jsonl",
    });
    let (event_tx, event_rx) = tokio::sync::oneshot::channel();
    let event_tx = Arc::new(Mutex::new(Some(event_tx)));
    let gate = Arc::new((Mutex::new(false), Condvar::new()));
    let expected_path = audit_path.display().to_string();
    let hook_gate = Arc::clone(&gate);
    let hook_path = expected_path.clone();
    let hook_event_tx = Arc::clone(&event_tx);
    let _hook = install_audit_writer_hook(move |event| {
        if event.path == hook_path
            && matches!(
                event.kind,
                AuditWriterTestEventKind::FileSync(value) if value == durability
            )
        {
            if let Some(sender) = hook_event_tx.lock().unwrap().take() {
                let _ = sender.send(event);
            }
            let (lock, condition) = &*hook_gate;
            let mut released = lock.lock().unwrap();
            while !*released {
                released = condition.wait(released).unwrap();
            }
        }
    });
    let sink = test_audit_sink(crate::AuditConfig {
        durability,
        ..jsonl_audit_config(audit_path.display().to_string())
    });

    let mut append = tokio::spawn({
        let sink = sink.clone();
        async move { sink.append_required(test_audit_record()).await }
    });
    let event = tokio::time::timeout(Duration::from_secs(1), event_rx)
        .await
        .expect("audit writer test hook event")
        .expect("audit writer test hook sender");
    assert_eq!(event.path, expected_path);
    assert_eq!(event.kind, AuditWriterTestEventKind::FileSync(durability));
    assert!(
        tokio::time::timeout(Duration::from_millis(25), &mut append)
            .await
            .is_err()
    );
    release_gate(&gate);
    append.await.unwrap().unwrap();
    sink.shutdown_and_drain(Duration::from_secs(1))
        .await
        .unwrap();
}

#[tokio::test(flavor = "current_thread")]
async fn sync_data_durability_syncs_before_acknowledgement() {
    durable_append_waits_for_sync_before_ack(AuditDurability::SyncData).await;
}

#[tokio::test(flavor = "current_thread")]
async fn sync_all_durability_syncs_before_acknowledgement() {
    durable_append_waits_for_sync_before_ack(AuditDurability::SyncAll).await;
}

#[tokio::test(flavor = "current_thread")]
async fn durable_rotation_syncs_parent_directory() {
    let audit_path = temp_path("durable-rotation-parent-sync-audit.jsonl");
    let parent_syncs = Arc::new(AtomicUsize::new(0));
    let expected_path = audit_path.display().to_string();
    let parent_syncs_for_hook = Arc::clone(&parent_syncs);
    let hook_path = expected_path.clone();
    let _hook = install_audit_writer_hook(move |event| {
        if event.path == hook_path
            && matches!(
                event.kind,
                AuditWriterTestEventKind::ParentDirSync(AuditDurability::SyncAll)
            )
        {
            parent_syncs_for_hook.fetch_add(1, Ordering::SeqCst);
        }
    });
    let sink = test_audit_sink(crate::AuditConfig {
        rotate_bytes: Some(1),
        durability: AuditDurability::SyncAll,
        ..jsonl_audit_config(audit_path.display().to_string())
    });

    sink.append_required(test_audit_record()).await.unwrap();
    sink.append_required(test_audit_record()).await.unwrap();
    sink.shutdown_and_drain(Duration::from_secs(1))
        .await
        .unwrap();

    assert!(parent_syncs.load(Ordering::SeqCst) >= 1);
}

#[tokio::test(flavor = "current_thread")]
async fn retention_prune_runs_after_triggering_append_ack() {
    let audit_path = temp_path("post-ack-prune-audit.jsonl");
    let audit_dir = audit_path.parent().unwrap();
    let old_rotated = audit_dir.join(format!(
        "post-ack-prune-audit.jsonl.20000101T000000Z.{}",
        Uuid::new_v4()
    ));
    fs::write(&old_rotated, b"old\n").unwrap();
    let old_mtime =
        filetime::FileTime::from_system_time(SystemTime::now() - Duration::from_secs(172800));
    filetime::set_file_mtime(&old_rotated, old_mtime).unwrap();
    let (event_tx, event_rx) = tokio::sync::oneshot::channel();
    let event_tx = Arc::new(Mutex::new(Some(event_tx)));
    let gate = Arc::new((Mutex::new(false), Condvar::new()));
    let expected_path = audit_path.display().to_string();
    let hook_gate = Arc::clone(&gate);
    let hook_path = expected_path.clone();
    let hook_event_tx = Arc::clone(&event_tx);
    let _hook = install_audit_writer_hook(move |event| {
        if event.path == hook_path && event.kind == AuditWriterTestEventKind::Prune {
            if let Some(sender) = hook_event_tx.lock().unwrap().take() {
                let _ = sender.send(event);
            }
            let (lock, condition) = &*hook_gate;
            let mut released = lock.lock().unwrap();
            while !*released {
                released = condition.wait(released).unwrap();
            }
        }
    });
    let sink = test_audit_sink(crate::AuditConfig {
        retention_days: 1,
        ..jsonl_audit_config(audit_path.display().to_string())
    });

    let append = tokio::spawn({
        let sink = sink.clone();
        async move { sink.append_required(test_audit_record()).await }
    });
    let event = tokio::time::timeout(Duration::from_secs(1), event_rx)
        .await
        .expect("audit writer test hook event")
        .expect("audit writer test hook sender");
    assert_eq!(event.path, expected_path);
    assert_eq!(event.kind, AuditWriterTestEventKind::Prune);
    append.await.unwrap().unwrap();
    assert!(old_rotated.exists());
    release_gate(&gate);
    sink.shutdown_and_drain(Duration::from_secs(1))
        .await
        .unwrap();

    assert!(!old_rotated.exists());
}

/// Both audit backends, for the backend-neutral shared-writer tests.
const AUDIT_STORE_TYPES: [crate::AuditStoreType; 2] =
    [crate::AuditStoreType::Jsonl, crate::AuditStoreType::Sqlite];

/// An `[audit]` table of type `kind` at a fresh private path.
fn audit_config_for(kind: crate::AuditStoreType, name: &str) -> (crate::AuditConfig, PathBuf) {
    let path = temp_path(&format!("{name}.audit.{}", kind.as_str()));
    (
        crate::AuditConfig::new(kind, path.display().to_string()),
        path,
    )
}

#[tokio::test]
async fn audit_queue_saturation_fails_closed() {
    for kind in AUDIT_STORE_TYPES {
        let (config, _) = audit_config_for(kind, "audit-queue-saturation");
        let sink = test_audit_sink(crate::AuditConfig {
            queue_capacity: 1,
            enqueue_timeout_ms: 10,
            ..config
        });
        let writer = sink.writer.as_ref().unwrap();
        let _held = writer
            .normal_capacity
            .clone()
            .acquire_owned()
            .await
            .unwrap();

        let error = sink.append_required(test_audit_record()).await.unwrap_err();

        assert!(matches!(error, RuntimeError::Audit { .. }), "{kind:?}");
    }
}

#[tokio::test]
async fn append_failure_recovers_after_permissions_are_fixed() {
    let temp = TempDir::new().unwrap();
    let audit_parent = temp.path().join("audit-parent");
    fs::write(&audit_parent, b"not a directory").unwrap();
    let audit_path = audit_parent.join("audit.jsonl");
    let sink = test_audit_sink(jsonl_audit_config(audit_path.display().to_string()));

    let error = sink.append_required(test_audit_record()).await.unwrap_err();
    assert!(matches!(error, RuntimeError::Audit { .. }));
    fs::remove_file(&audit_parent).unwrap();
    fs::create_dir(&audit_parent).unwrap();
    #[cfg(unix)]
    fs::set_permissions(&audit_parent, fs::Permissions::from_mode(0o700)).unwrap();
    sink.append_required(test_audit_record()).await.unwrap();
    sink.shutdown_and_drain(Duration::from_secs(1))
        .await
        .unwrap();
}

#[tokio::test]
async fn writer_exit_fails_readiness_and_appends_closed() {
    for kind in AUDIT_STORE_TYPES {
        let (config, _) = audit_config_for(kind, "writer-exit");
        let sink = test_audit_sink(config);
        let writer = sink.writer.as_ref().unwrap();
        assert!(writer.sender.try_send(AuditCommand::ExitForTest).is_ok());
        let join = writer.join.lock().unwrap().take().unwrap();
        join.join().unwrap();

        assert!(sink.check_writable().await.is_err(), "{kind:?}");
        assert!(sink.append_required(test_audit_record()).await.is_err());
        assert!(
            writer
                .health
                .recorded()
                .contains(AuditFailureClass::WriterExit)
        );
        writer.health.apply(audit_jsonl::probe_success_change());
        assert!(writer.health.check().is_err());
    }
}

#[tokio::test]
async fn readiness_probe_does_not_append_audit_record() {
    for kind in AUDIT_STORE_TYPES {
        let (config, path) = audit_config_for(kind, "probe-does-not-append");
        let sink = test_audit_sink(config);

        sink.check_writable().await.unwrap();
        sink.shutdown_and_drain(Duration::from_secs(1))
            .await
            .unwrap();

        assert!(crate::test_support::read_audit_records(kind, &path).is_empty());
    }
}

#[test]
fn audit_writer_health_tracks_failure_classes_independently() {
    use AuditFailureClass::*;
    let set = AuditFailureSet::of;
    let clear = |classes: &[AuditFailureClass]| AuditHealthChange {
        mark: AuditFailureSet::EMPTY,
        clear: set(classes),
    };
    let health = AuditWriterHealth::new("test-audit".to_string());
    health.check().unwrap();

    health.mark_failure(Append);
    health.mark_failure(Prune);
    let error = health.check().unwrap_err().to_string();
    assert!(error.contains("Append, Prune"), "{error}");

    // Clearing one class keeps the others, and readiness keeps failing.
    health.apply(clear(&[Prune]));
    assert_eq!(health.recorded(), set(&[Append]));
    assert!(health.check().is_err());

    // A later failure adds its class instead of replacing the recorded ones.
    health.apply(AuditHealthChange {
        mark: set(&[Probe]),
        clear: AuditFailureSet::EMPTY,
    });
    assert_eq!(health.recorded(), set(&[Append, Probe]));

    health.apply(clear(&[Append, Probe]));
    health.check().unwrap();

    // WriterExit is sticky.
    health.mark_writer_exit();
    health.apply(clear(&AuditFailureClass::ALL));
    assert_eq!(health.recorded(), set(&[WriterExit]));
    assert!(health.check().is_err());
}

/// A storage backend that returns scripted outcomes, for testing the shared
/// writer loop independently of JSONL.
#[derive(Default)]
struct ScriptedAuditStorage {
    appends: std::collections::VecDeque<AuditStorageOutcome>,
    probes: std::collections::VecDeque<AuditStorageOutcome>,
    appended_ids: Arc<Mutex<Vec<String>>>,
    probe_inputs: Arc<Mutex<Vec<AuditFailureSet>>>,
    closed: Arc<AtomicBool>,
}

fn scripted_outcome(
    result: std::io::Result<()>,
    mark: &[AuditFailureClass],
    clear: &[AuditFailureClass],
) -> AuditStorageOutcome {
    AuditStorageOutcome {
        result,
        health: AuditHealthChange {
            mark: AuditFailureSet::of(mark),
            clear: AuditFailureSet::of(clear),
        },
    }
}

impl AuditStorage for ScriptedAuditStorage {
    fn append_batch(
        &mut self,
        entries: &[AuditAppendEntry<'_>],
        _recorded: AuditFailureSet,
    ) -> AuditAppendOutcome {
        let entries = entries
            .iter()
            .map(|entry| {
                self.appended_ids
                    .lock()
                    .unwrap()
                    .push(entry.record.audit_id.clone());
                self.appends.pop_front().expect("scripted append outcome")
            })
            .collect();
        AuditAppendOutcome {
            entries,
            health: AuditHealthChange::default(),
            maintenance_due: false,
        }
    }

    fn probe(&mut self, recorded: AuditFailureSet) -> AuditStorageOutcome {
        self.probe_inputs.lock().unwrap().push(recorded);
        self.probes.pop_front().expect("scripted probe outcome")
    }

    fn run_maintenance_slice(&mut self) -> AuditMaintenanceOutcome {
        unreachable!("scripted storage never reports maintenance as due")
    }

    fn finishes_maintenance_at_shutdown(&self) -> bool {
        true
    }

    fn close(&mut self) -> std::io::Result<()> {
        self.closed.store(true, Ordering::SeqCst);
        Ok(())
    }
}

#[tokio::test]
async fn shared_writer_applies_backend_health_changes_without_overwriting_classes() {
    use AuditFailureClass::*;
    let storage = ScriptedAuditStorage {
        appends: [
            scripted_outcome(Err(std::io::Error::other("database full")), &[Append], &[]),
            // An ordinary success that the backend does not treat as recovery.
            scripted_outcome(Ok(()), &[], &[]),
        ]
        .into(),
        probes: [
            // A failed recovery attempt records nothing new.
            scripted_outcome(Err(std::io::Error::other("recovery failed")), &[], &[]),
            scripted_outcome(Ok(()), &[], &[Append]),
        ]
        .into(),
        ..ScriptedAuditStorage::default()
    };
    let appended_ids = Arc::clone(&storage.appended_ids);
    let probe_inputs = Arc::clone(&storage.probe_inputs);
    let closed = Arc::clone(&storage.closed);
    let writer = AuditWriterHandle::start(
        AuditWriterConfig {
            path_label: "scripted-audit".to_string(),
            node_id: TEST_NODE_ID.to_string(),
            queue_capacity: 4,
            terminal_queue_capacity: 4,
            enqueue_timeout: Duration::from_secs(1),
            lock: Arc::new(Mutex::new(())),
        },
        Box::new(storage),
    );

    let error = writer
        .append_required(test_audit_record())
        .await
        .unwrap_err();
    assert!(error.to_string().contains("database full"), "{error}");
    assert_eq!(writer.health.recorded(), AuditFailureSet::of(&[Append]));
    writer.append_required(test_audit_record()).await.unwrap();
    assert_eq!(writer.health.recorded(), AuditFailureSet::of(&[Append]));
    assert!(writer.check_writable().await.is_err());
    assert_eq!(writer.health.recorded(), AuditFailureSet::of(&[Append]));
    writer.check_writable().await.unwrap();
    assert_eq!(writer.health.recorded(), AuditFailureSet::EMPTY);
    assert_eq!(
        *probe_inputs.lock().unwrap(),
        vec![AuditFailureSet::of(&[Append]); 2]
    );
    let appended_ids = appended_ids.lock().unwrap().clone();
    assert_eq!(appended_ids.len(), 2);
    assert_ne!(appended_ids[0], appended_ids[1]);

    writer.shutdown_and_drain().await.unwrap();
    assert!(closed.load(Ordering::SeqCst));
}

#[cfg(unix)]
#[tokio::test]
async fn failed_jsonl_probe_adds_probe_without_replacing_prune() {
    let temp = TempDir::new().unwrap();
    let audit_dir = temp.path().join("audit");
    fs_permissions::ensure_private_dir(&audit_dir).unwrap();
    let audit_path = audit_dir.join("audit.jsonl");
    let unremovable = audit_dir.join(format!("audit.jsonl.20000101T000000Z.{}", Uuid::new_v4()));
    fs::create_dir(&unremovable).unwrap();
    let old_mtime =
        filetime::FileTime::from_system_time(SystemTime::now() - Duration::from_secs(172800));
    filetime::set_file_mtime(&unremovable, old_mtime).unwrap();
    let sink = test_audit_sink(crate::AuditConfig {
        retention_days: 1,
        ..jsonl_audit_config(audit_path.display().to_string())
    });
    let writer = sink.writer.as_ref().unwrap();

    sink.append_required(test_audit_record()).await.unwrap();
    fs::set_permissions(&audit_dir, fs::Permissions::from_mode(0o755)).unwrap();
    assert!(sink.check_writable().await.is_err());
    assert_eq!(
        writer.health.recorded(),
        AuditFailureSet::of(&[AuditFailureClass::Prune, AuditFailureClass::Probe])
    );

    // JSONL keeps today's rule: a successful probe clears every
    // recoverable class.
    fs::set_permissions(&audit_dir, fs::Permissions::from_mode(0o700)).unwrap();
    sink.check_writable().await.unwrap();
    assert_eq!(writer.health.recorded(), AuditFailureSet::EMPTY);
    sink.shutdown_and_drain(Duration::from_secs(1))
        .await
        .unwrap();
}

#[tokio::test]
async fn terminal_reservations_do_not_consume_normal_audit_capacity() {
    for kind in AUDIT_STORE_TYPES {
        let (config, path) = audit_config_for(kind, "terminal-capacity-normal");
        let limits = crate::LimitsConfig {
            max_concurrent_requests: 1,
            ..crate::LimitsConfig::default()
        };
        let sink = test_audit_sink_with_limits(
            crate::AuditConfig {
                queue_capacity: 1,
                terminal_queue_capacity: Some(1),
                enqueue_timeout_ms: 25,
                ..config
            },
            limits,
        );
        let _terminal = sink.reserve_terminal().await.unwrap();

        sink.append_required(test_audit_record()).await.unwrap();
        sink.shutdown_and_drain(Duration::from_secs(1))
            .await
            .unwrap();

        let records = crate::test_support::read_audit_records(kind, &path);
        assert_eq!(records.len(), 1, "{kind:?}");
        assert_eq!(records[0]["agentRequestId"], "agent-req-test");
    }
}

#[tokio::test]
async fn terminal_audit_queued_before_shutdown_is_drained() {
    for kind in AUDIT_STORE_TYPES {
        let (config, path) = audit_config_for(kind, "terminal-before-shutdown");
        let sink = test_audit_sink(crate::AuditConfig {
            terminal_queue_capacity: Some(crate::LimitsConfig::default().max_concurrent_requests),
            ..config
        });
        let permit = sink.reserve_terminal().await.unwrap();
        let mut record = test_audit_record();
        record.agent_request_id = "agent-req-terminal-before-shutdown".to_string();

        permit.send(record);
        sink.shutdown_and_drain(Duration::from_secs(1))
            .await
            .unwrap();

        let records = crate::test_support::read_audit_records(kind, &path);
        assert!(
            records
                .iter()
                .any(|record| record["agentRequestId"] == "agent-req-terminal-before-shutdown"),
            "{kind:?}"
        );
    }
}

#[tokio::test]
async fn terminal_audit_after_shutdown_is_rejected_not_silently_accepted() {
    for kind in AUDIT_STORE_TYPES {
        let (config, path) = audit_config_for(kind, "terminal-after-shutdown");
        let sink = test_audit_sink(crate::AuditConfig {
            terminal_queue_capacity: Some(crate::LimitsConfig::default().max_concurrent_requests),
            ..config
        });
        let permit = sink.reserve_terminal().await.unwrap();

        sink.shutdown_and_drain(Duration::from_secs(1))
            .await
            .unwrap();
        let mut record = test_audit_record();
        record.agent_request_id = "agent-req-terminal-after-shutdown".to_string();
        permit.send(record);

        let records = crate::test_support::read_audit_records(kind, &path);
        assert!(
            !records
                .iter()
                .any(|record| record["agentRequestId"] == "agent-req-terminal-after-shutdown"),
            "{kind:?}"
        );
        assert!(
            sink.writer
                .as_ref()
                .unwrap()
                .health
                .recorded()
                .contains(AuditFailureClass::TerminalWrite)
        );
    }
}

#[tokio::test]
async fn terminal_audit_prunes_retained_files() {
    let audit_path = temp_path("terminal-retention-audit.jsonl");
    let audit_dir = audit_path.parent().unwrap();
    let old_rotated = audit_dir.join(format!(
        "terminal-retention-audit.jsonl.20000101T000000Z.{}",
        Uuid::new_v4()
    ));
    fs::write(&old_rotated, b"old\n").unwrap();
    let old_mtime =
        filetime::FileTime::from_system_time(SystemTime::now() - Duration::from_secs(172800));
    filetime::set_file_mtime(&old_rotated, old_mtime).unwrap();
    let sink = test_audit_sink(crate::AuditConfig {
        retention_days: 1,
        terminal_queue_capacity: Some(crate::LimitsConfig::default().max_concurrent_requests),
        ..jsonl_audit_config(audit_path.display().to_string())
    });
    let permit = sink.reserve_terminal().await.unwrap();
    let mut record = test_audit_record();
    record.agent_request_id = "agent-req-terminal-retention-prune".to_string();

    permit.send(record);
    sink.shutdown_and_drain(Duration::from_secs(1))
        .await
        .unwrap();

    assert!(!old_rotated.exists());
    let audit = fs::read_to_string(&audit_path).unwrap();
    assert!(audit.contains("agent-req-terminal-retention-prune"));
}

#[tokio::test]
async fn retention_prune_failure_does_not_fail_successful_append() {
    let audit_path = temp_path("prune-failure-audit.jsonl");
    let audit_dir = audit_path.parent().unwrap();
    let retained_dir = audit_dir.join(format!(
        "prune-failure-audit.jsonl.20000101T000000Z.{}",
        Uuid::new_v4()
    ));
    fs::create_dir(&retained_dir).unwrap();
    let old_mtime =
        filetime::FileTime::from_system_time(SystemTime::now() - Duration::from_secs(172800));
    filetime::set_file_mtime(&retained_dir, old_mtime).unwrap();
    let sink = test_audit_sink(crate::AuditConfig {
        retention_days: 1,
        ..jsonl_audit_config(audit_path.display().to_string())
    });

    sink.append_required(test_audit_record()).await.unwrap();

    sink.shutdown_and_drain(Duration::from_secs(1))
        .await
        .unwrap();
    assert!(retained_dir.exists());
    let error = sink.writer.as_ref().unwrap().health.check().unwrap_err();
    assert!(matches!(error, RuntimeError::Audit { .. }));
}

#[tokio::test]
async fn retention_prune_deletes_only_rotated_files() {
    let temp = TempDir::new().unwrap();
    let audit_dir = temp.path().join("audit");
    let audit_path = audit_dir.join("audit.jsonl");
    let mut config = base_fake_config();
    config.limits.upload_spool_dir = temp.path().join("spool").display().to_string();
    config.audit = Some(crate::AuditConfig {
        retention_days: 1,
        ..jsonl_audit_config(audit_path.display().to_string())
    });
    let locks = crate::StateLockSet::acquire_for_config(
        &config,
        Path::new("/tmp/retention-prune.toml"),
        &crate::StateLockHolder::new("runtime-test", "0.0.0", TEST_NODE_ID),
        None,
    )
    .unwrap();
    let lock_file = audit_dir.join("audit.jsonl.agent-access.lock");
    assert!(lock_file.exists());
    let other = audit_dir.join("audit.jsonl.notes");
    let not_rotated = audit_dir.join("audit.jsonl.20000101T000000Z.old");
    let rotated = audit_dir.join(format!("audit.jsonl.20000101T000000Z.{}", Uuid::new_v4()));
    let rotated_fraction = audit_dir.join(format!(
        "audit.jsonl.20000101T000000.123456Z.{}",
        Uuid::new_v4()
    ));
    let recent_rotated = audit_dir.join(format!("audit.jsonl.20000102T000000Z.{}", Uuid::new_v4()));
    for path in [
        &other,
        &not_rotated,
        &rotated,
        &rotated_fraction,
        &recent_rotated,
    ] {
        fs::write(path, b"old\n").unwrap();
    }
    let old_mtime =
        filetime::FileTime::from_system_time(SystemTime::now() - Duration::from_secs(3 * 86_400));
    for path in [
        &lock_file,
        &other,
        &not_rotated,
        &rotated,
        &rotated_fraction,
    ] {
        filetime::set_file_mtime(path, old_mtime).unwrap();
    }
    let sink = test_audit_sink(config.audit.clone().unwrap());

    sink.append_required(test_audit_record()).await.unwrap();
    sink.shutdown_and_drain(Duration::from_secs(1))
        .await
        .unwrap();

    assert!(lock_file.exists());
    assert!(other.exists());
    assert!(not_rotated.exists());
    assert!(recent_rotated.exists());
    assert!(!rotated.exists());
    assert!(!rotated_fraction.exists());
    sink.writer.as_ref().unwrap().health.check().unwrap();
    // The live lock still excludes a second owner of the audit path.
    let conflict = crate::StateLockSet::acquire_for_config(
        &config,
        Path::new("/tmp/retention-prune.toml"),
        &crate::StateLockHolder::new("runtime-test", "0.0.0", TEST_NODE_ID),
        None,
    )
    .unwrap_err();
    assert_eq!(conflict.kind(), crate::StateLockFailureKind::Held);
    drop(locks);
}

#[tokio::test]
async fn writer_stamps_every_record_with_a_fresh_uuid_v7_and_the_node_id() {
    for kind in AUDIT_STORE_TYPES {
        let (config, path) = audit_config_for(kind, "stamped");
        let sink = test_audit_sink(crate::AuditConfig {
            terminal_queue_capacity: Some(crate::LimitsConfig::default().max_concurrent_requests),
            ..config
        });
        let record = test_audit_record();

        sink.append_required(record.clone()).await.unwrap();
        sink.append_required(record.clone()).await.unwrap();
        sink.reserve_terminal().await.unwrap().send(record.clone());
        sink.shutdown_and_drain(Duration::from_secs(1))
            .await
            .unwrap();

        let records = crate::test_support::read_audit_records(kind, &path);
        assert_eq!(records.len(), 3, "{kind:?}");
        let audit_ids = records
            .iter()
            .map(|written| {
                assert_eq!(written["nodeId"], TEST_NODE_ID);
                assert_eq!(
                    written["brokerRequestId"],
                    record.broker_request_id.as_str()
                );
                assert_eq!(written["timestamp"], record.timestamp.as_str());
                let audit_id = Uuid::parse_str(written["auditId"].as_str().unwrap()).unwrap();
                assert_eq!(audit_id.get_version_num(), 7);
                audit_id
            })
            .collect::<BTreeSet<_>>();
        assert_eq!(audit_ids.len(), 3);
    }
}

#[test]
fn runtime_uses_the_configured_node_id_or_the_host_name() {
    let mut config = base_fake_config();
    config.deployment.node_id = Some("broker-test-1".to_string());
    let runtime = BrokerRuntime::new(config).unwrap();
    assert_eq!(runtime.node_id(), "broker-test-1");

    let runtime = BrokerRuntime::new(base_fake_config()).unwrap();
    assert_eq!(
        Ok(runtime.node_id().to_string()),
        crate::resolve_node_id(&DeploymentConfig::default())
    );
}

#[test]
fn runtime_exposes_its_audit_store_type_path_and_database_id() {
    let path = temp_path("runtime-store.audit.sqlite");
    let mut config = base_fake_config();
    config.audit = Some(crate::AuditConfig::new(
        crate::AuditStoreType::Sqlite,
        path.display().to_string(),
    ));
    let runtime = BrokerRuntime::new(config).unwrap();
    let store = runtime.audit_store().unwrap();
    assert_eq!(store.store_type(), crate::AuditStoreType::Sqlite);
    assert_eq!(store.path(), path.as_path());
    let database_id = Uuid::parse_str(store.database_id().unwrap()).unwrap();
    assert_eq!(database_id.get_version_num(), 4);
    assert_eq!(store.maintenance_failure(), None);

    let mut config = base_fake_config();
    let jsonl = temp_path("runtime-store.audit.jsonl");
    config.audit = Some(jsonl_audit_config(jsonl.display().to_string()));
    let runtime = BrokerRuntime::new(config).unwrap();
    let store = runtime.audit_store().unwrap();
    assert_eq!(store.store_type(), crate::AuditStoreType::Jsonl);
    assert_eq!(store.database_id(), None);

    assert!(
        BrokerRuntime::new(base_fake_config())
            .unwrap()
            .audit_store()
            .is_none()
    );
}

pub(super) fn test_audit_record() -> AuditRecord {
    AuditRecord {
        caller_id: None,
        search_authorization: None,
        timestamp: Utc::now().to_rfc3339(),
        agent_request_id: "agent-req-test".to_string(),
        broker_request_id: "broker-req-test".to_string(),
        config_generation: None,
        policy_generation: None,
        principal: "alice".to_string(),
        principal_subject: None,
        groups: vec!["users".to_string()],
        service: "fake".to_string(),
        action: "echo".to_string(),
        resource_scopes: BTreeMap::new(),
        matched_grant: None,
        credential_mode: None,
        decision: Decision::Allow,
        reason_code: None,
        upstream_status: None,
        upstream_duration_ms: None,
        object_ids: None,
        identity_source: None,
        source: SourceContext::unknown(),
        execution_context: None,
        provider_audit: None,
    }
}

#[test]
fn upstream_events_infer_levels_and_reason_codes_without_paths() {
    let captured = CapturedEvents::default();
    let subscriber = tracing_subscriber::registry().with(EventCaptureLayer {
        events: captured.clone(),
    });
    let _guard = tracing::subscriber::set_default(subscriber);

    emit_upstream_request_completed(
        UpstreamTrace::new(
            "jira",
            UpstreamCall::new("attachment.download"),
            "https://example.atlassian.net",
            "GET",
            "direct",
            3,
        )
        .with_status(Some(302)),
    );
    emit_upstream_request_completed(
        UpstreamTrace::new(
            "jira",
            UpstreamCall::new("issue.get"),
            "https://example.atlassian.net",
            "GET",
            "direct",
            4,
        )
        .with_status(Some(404)),
    );
    emit_upstream_request_completed(
        UpstreamTrace::new(
            "configured_http",
            UpstreamCall::new("issues.list"),
            "https://api.example.test",
            "GET",
            "direct",
            5,
        )
        .with_status(Some(500))
        .with_path_template(Some("/repos/{owner}/{repo}/issues")),
    );
    let classified = |duration_ms| {
        UpstreamTrace::new(
            "configured_http",
            UpstreamCall::new("issues.list"),
            "https://api.example.test",
            "GET",
            "direct",
            duration_ms,
        )
        .with_status(Some(200))
        .with_reason_code(Some(ReasonCode::UpstreamProtocolFailed.into()))
        .with_path_template(Some("/repos/{owner}/{repo}/issues"))
    };
    // A provider's own classification is checked against its hook.
    tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap()
        .block_on(agent_access_provider::host::with_hook_context(
            agent_access_provider::host::hook_context(
                "configured_http",
                "issues.list",
                HookPhase::Invocation,
                &[],
            ),
            async { emit_upstream_request_completed(classified(6)) },
        ));
    // Outside any provider hook it cannot be, so it is not recorded.
    emit_upstream_request_completed(classified(7));

    let events = captured.take();
    let redirect = event_by_status(&events, 302);
    assert_eq!(string_field(redirect, "level"), Some("INFO"));
    assert!(!redirect.contains_key("reasonCode"));
    assert!(!redirect.contains_key("pathTemplate"));

    let not_found = event_by_status(&events, 404);
    assert_eq!(string_field(not_found, "level"), Some("WARN"));
    assert_eq!(
        string_field(not_found, "reasonCode"),
        Some("scope_unresolved")
    );
    assert!(!not_found.contains_key("pathTemplate"));

    let failed = event_by_status(&events, 500);
    assert_eq!(string_field(failed, "level"), Some("ERROR"));
    assert_eq!(string_field(failed, "reasonCode"), Some("upstream_failed"));
    assert_eq!(
        string_field(failed, "pathTemplate"),
        Some("/repos/{owner}/{repo}/issues")
    );

    let protocol_failed = events
        .iter()
        .find(|event| number_field(event, "upstreamDurationMs") == Some(6))
        .expect("protocol failure event is captured");
    assert_eq!(string_field(protocol_failed, "level"), Some("ERROR"));
    assert_eq!(
        string_field(protocol_failed, "reasonCode"),
        Some("upstream_protocol_failed")
    );
    let unattributed = events
        .iter()
        .find(|event| number_field(event, "upstreamDurationMs") == Some(7))
        .expect("unattributed classification event is captured");
    assert_eq!(
        string_field(unattributed, "reasonCode"),
        Some("broker_provider_contract_failed")
    );
}

#[test]
fn invoke_completed_event_uses_scope_keys_and_optional_credential_mode() {
    let captured = CapturedEvents::default();
    let subscriber = tracing_subscriber::registry().with(EventCaptureLayer {
        events: captured.clone(),
    });
    let _guard = tracing::subscriber::set_default(subscriber);

    let mut record = test_audit_record();
    record.config_generation = Some(7);
    record.resource_scopes =
        BTreeMap::from([("project".to_string(), vec!["SECRET-PROJECT".to_string()])]);
    record.credential_mode = Some(Some("service".to_string()));
    emit_invoke_completed(&record, 200, 12, Some("draft_position_shape_invalid"));

    record.credential_mode = None;
    emit_invoke_completed(&record, 403, 13, None);

    let events = captured.take();
    let first = events
        .iter()
        .find(|event| number_field(event, "durationMs") == Some(12))
        .expect("first invoke event is captured");
    assert_eq!(string_field(first, "event"), Some("invoke_completed"));
    assert_eq!(string_field(first, "level"), Some("INFO"));
    assert_eq!(string_field(first, "credentialMode"), Some("service"));
    assert_eq!(
        string_field(first, "diagnosticCode"),
        Some("draft_position_shape_invalid")
    );
    assert_eq!(
        string_field(first, "agentRequestId"),
        Some("agent-req-test")
    );
    assert_eq!(
        string_field(first, "brokerRequestId"),
        Some("broker-req-test")
    );
    assert_eq!(
        string_field(first, "resourceScopeKeys"),
        Some("[\"project\"]")
    );
    assert!(
        !serde_json::to_string(first)
            .unwrap()
            .contains("SECRET-PROJECT")
    );

    let second = events
        .iter()
        .find(|event| number_field(event, "durationMs") == Some(13))
        .expect("second invoke event is captured");
    assert_eq!(string_field(second, "event"), Some("invoke_completed"));
    assert!(!second.contains_key("credentialMode"));
    assert!(!second.contains_key("diagnosticCode"));
}

#[test]
fn audit_append_failed_event_carries_private_diagnostic_and_correlation() {
    let captured = CapturedEvents::default();
    let subscriber = tracing_subscriber::registry().with(EventCaptureLayer {
        events: captured.clone(),
    });
    let _guard = tracing::subscriber::set_default(subscriber);
    let record = test_audit_record();
    let error = RuntimeError::Audit {
        path: "/tmp/redacted-audit.jsonl".to_string(),
        source: std::io::Error::other("unavailable"),
    };

    emit_audit_append_failed(
        &record,
        "node-a",
        ReasonCode::AuditUnavailable.http_status(),
        &error,
        Some("draft_position_shape_invalid"),
    );

    let events = captured.take();
    let event = events
        .iter()
        .find(|event| string_field(event, "event") == Some("audit_append_failed"))
        .expect("audit failure event is captured");
    assert_eq!(
        string_field(event, "diagnosticCode"),
        Some("draft_position_shape_invalid")
    );
    assert_eq!(string_field(event, "nodeId"), Some("node-a"));
    assert_eq!(
        string_field(event, "agentRequestId"),
        Some("agent-req-test")
    );
    assert_eq!(
        string_field(event, "brokerRequestId"),
        Some("broker-req-test")
    );
    assert!(
        !serde_json::to_string(&record)
            .unwrap()
            .contains("draft_position_shape_invalid")
    );
}

#[tokio::test]
async fn malformed_gitlab_draft_readback_diagnostic_reaches_invoke_completion_only() {
    let (response, events) = invoke_malformed_gitlab_draft_readback(false).await;

    assert_eq!(response.status, 409);
    assert_eq!(response.envelope.decision, Decision::Error);
    assert_eq!(
        response.envelope.reason_code,
        Some(ReasonCode::MutationVerificationFailed.into())
    );
    let result = response.envelope.result.as_ref().unwrap();
    assert_eq!(result["mutationStatus"], "applied_unverified");
    assert_eq!(result["retrySafe"], false);
    assert_eq!(result["verificationStage"], "mutation_readback");
    assert_eq!(result["safeLocators"]["draftNoteIds"], json!([11963]));

    let completed = events
        .iter()
        .find(|event| {
            string_field(event, "event") == Some("invoke_completed")
                && string_field(event, "brokerRequestId") == Some("broker-gitlab-malformed-draft")
        })
        .expect("GitLab invocation completion is captured");
    assert_eq!(string_field(completed, "level"), Some("ERROR"));
    assert_eq!(number_field(completed, "http.statusCode"), Some(409));
    assert_eq!(
        string_field(completed, "diagnosticCode"),
        Some("draft_position_shape_invalid")
    );
    assert_private_gitlab_diagnostic_values_absent(&response, &events);
}

#[cfg(unix)]
#[tokio::test]
async fn malformed_gitlab_draft_readback_diagnostic_survives_mandatory_audit_failure() {
    let (response, events) = invoke_malformed_gitlab_draft_readback(true).await;

    assert_eq!(response.status, 503);
    assert_eq!(response.envelope.decision, Decision::Error);
    assert_eq!(
        response.envelope.reason_code,
        Some(ReasonCode::AuditUnavailable.into())
    );
    let failed = events
        .iter()
        .find(|event| {
            string_field(event, "event") == Some("audit_append_failed")
                && string_field(event, "brokerRequestId") == Some("broker-gitlab-malformed-draft")
        })
        .expect("mandatory audit failure is captured");
    assert_eq!(string_field(failed, "level"), Some("ERROR"));
    assert_eq!(number_field(failed, "http.statusCode"), Some(503));
    assert_eq!(
        string_field(failed, "diagnosticCode"),
        Some("draft_position_shape_invalid")
    );
    assert!(!events.iter().any(|event| {
        string_field(event, "event") == Some("invoke_completed")
            && string_field(event, "brokerRequestId") == Some("broker-gitlab-malformed-draft")
    }));
    assert_private_gitlab_diagnostic_values_absent(&response, &events);
}

async fn invoke_malformed_gitlab_draft_readback(
    fail_mandatory_audit: bool,
) -> (BrokerResponse<Value>, Vec<BTreeMap<String, Value>>) {
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v4/projects/sip%2Fservice"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": 42,
            "path_with_namespace": "sip/service",
            "web_url": "https://sentinel.invalid/private-project-url"
        })))
        .expect(1..=2)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/v4/user"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": 314,
            "username": "service-user"
        })))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/v4/projects/42/merge_requests/5"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": 500,
            "iid": 5,
            "project_id": 42,
            "web_url": "https://sentinel.invalid/private-merge-request-url"
        })))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/api/v4/projects/42/merge_requests/5/draft_notes"))
        .respond_with(ResponseTemplate::new(201).set_body_json(json!({
            "id": 11963,
            "note": "sentinel-private-draft-body",
            "author_id": 314,
            "merge_request_id": 500,
            "resolve_discussion": false,
            "discussion_id": null,
            "commit_id": null,
            "line_code": "sentinel_private_line_code_110_109",
            "position": null
        })))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path(
            "/api/v4/projects/42/merge_requests/5/draft_notes/11963",
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": 11963,
            "note": "sentinel-private-draft-body",
            "author_id": 314,
            "merge_request_id": 500,
            "resolve_discussion": false,
            "discussion_id": null,
            "commit_id": null,
            "line_code": "sentinel_private_line_code_110_109",
            "position": {
                "position_type": "text",
                "head_sha": "sentinel-private-position-value",
                "new_path": "sentinel/private/path.rs"
            }
        })))
        .expect(1)
        .mount(&server)
        .await;

    let service_token_path = write_temp_secret("sentinel-private-service-token");
    let lookup_token_path = write_temp_secret("sentinel-private-lookup-token");
    let mut lookup_credential =
        fake_service_credential(format!("file:{}", lookup_token_path.display()));
    lookup_credential.read_only = Some(true);
    let provider_config = agent_access_gitlab::GitlabProviderConfig {
        provisioning: agent_access_gitlab::GitlabProvisioningConfig::default(),
        attachments: Default::default(),
        api_base_url: format!("{}/api/v4", server.uri()),
        web_base_url: server.uri(),
        egress_proxy: None,
        allowed_upstream_hosts: vec![format!("{}/api/v4/**", server.uri())],
        content: agent_access_gitlab::GitlabContentConfig::default(),
        search: agent_access_provider::SearchLimitsConfig::default(),
        webhooks: agent_access_gitlab::GitlabWebhooksConfig::default(),
    };
    let mut config = base_fake_config();
    config.providers.insert(provider_config);
    config.credentials.service.insert(
        "gitlab".to_string(),
        fake_service_credential(format!("file:{}", service_token_path.display())),
    );
    config
        .credentials
        .lookup
        .insert("gitlab".to_string(), lookup_credential);
    config.policy.grants.push(PolicyGrantConfig {
        subjects: vec!["group:anonymous".to_string()],
        service: "gitlab".to_string(),
        actions: vec!["merge_request.draft_note.add".to_string()],
        resources: resource_selection(&["repository-sip-service"]),
        execution_contexts: None,
        credential_mode: "service".to_string(),
        priority: None,
    });
    let audit_path =
        fail_mandatory_audit.then(|| temp_path("gitlab-malformed-draft-readback.audit.jsonl"));
    if let Some(audit_path) = &audit_path {
        config.audit = Some(jsonl_audit_config(audit_path.display().to_string()));
    }

    let captured = CapturedEvents::default();
    let subscriber = tracing_subscriber::registry().with(EventCaptureLayer {
        events: captured.clone(),
    });
    let _guard = tracing::subscriber::set_default(subscriber);
    let runtime = BrokerRuntime::new(config).unwrap();
    #[cfg(unix)]
    if let Some(audit_path) = &audit_path {
        fs::set_permissions(
            audit_path.parent().unwrap(),
            fs::Permissions::from_mode(0o755),
        )
        .unwrap();
    }
    let response = runtime
        .invoke(
            governed(OperationContext {
                agent_request_id: "agent-gitlab-malformed-draft".to_string(),
                broker_request_id: "broker-gitlab-malformed-draft".to_string(),
                identity: IdentityContext::anonymous(),
                service: "gitlab".to_string(),
                action: "merge_request.draft_note.add".to_string(),
                source: SourceContext::unknown(),
            }),
            InvokeRequest::new(json!({
                "project": "sip/service",
                "iid": 5,
                "content": "sentinel-private-draft-body",
                "contentFormat": "markdown"
            })),
        )
        .await;
    #[cfg(unix)]
    if let Some(audit_path) = &audit_path {
        fs::set_permissions(
            audit_path.parent().unwrap(),
            fs::Permissions::from_mode(0o700),
        )
        .unwrap();
    }
    (response, captured.take())
}

fn assert_private_gitlab_diagnostic_values_absent(
    response: &BrokerResponse<Value>,
    events: &[BTreeMap<String, Value>],
) {
    let public = serde_json::to_string(response).unwrap();
    assert!(!public.contains("draft_position_shape_invalid"));
    for private in [
        "sentinel-private-draft-body",
        "sentinel-private-position-value",
        "sentinel/private/path.rs",
        "sentinel.invalid/private-project-url",
        "sentinel.invalid/private-merge-request-url",
        "sentinel_private_line_code_110_109",
        "sentinel-private-service-token",
        "sentinel-private-lookup-token",
    ] {
        assert!(
            !public.contains(private),
            "public response leaked {private}"
        );
    }
    let logs = serde_json::to_string(events).unwrap();
    for private in [
        "sentinel-private-draft-body",
        "sentinel-private-position-value",
        "sentinel/private/path.rs",
        "sentinel.invalid/private-project-url",
        "sentinel.invalid/private-merge-request-url",
        "11963",
        "sentinel_private_line_code_110_109",
        "sentinel-private-service-token",
        "sentinel-private-lookup-token",
    ] {
        assert!(!logs.contains(private), "structured logs leaked {private}");
    }
}

#[test]
fn ownership_hint_is_limited_to_scope_unresolved_errors() {
    let mut error = ProviderError::deny(ReasonCode::ScopeUnresolved, "redacted")
        .with_result(json!({ "existing": true }));
    add_upstream_resource_ownership_hint(&mut error, UpstreamResourceOwnership::ActingUser);
    assert_eq!(
        error.result.as_deref().unwrap()["hints"]["upstreamResourceOwnership"],
        "acting_user"
    );
    assert_eq!(error.result.as_deref().unwrap()["existing"], true);

    let mut malformed = ProviderError::deny(ReasonCode::InputInvalid, "invalid");
    add_upstream_resource_ownership_hint(&mut malformed, UpstreamResourceOwnership::ActingUser);
    assert!(malformed.result.is_none());
}

fn event_by_status(events: &[BTreeMap<String, Value>], status: u64) -> &BTreeMap<String, Value> {
    events
        .iter()
        .find(|event| number_field(event, "http.statusCode") == Some(status))
        .expect("event with status is captured")
}

fn string_field<'a>(event: &'a BTreeMap<String, Value>, field: &str) -> Option<&'a str> {
    event.get(field).and_then(Value::as_str)
}

fn number_field(event: &BTreeMap<String, Value>, field: &str) -> Option<u64> {
    event.get(field).and_then(Value::as_u64)
}

#[derive(Clone, Default)]
pub(super) struct CapturedEvents {
    events: Arc<Mutex<Vec<BTreeMap<String, Value>>>>,
}

impl CapturedEvents {
    fn push(&self, event: BTreeMap<String, Value>) {
        self.events.lock().unwrap().push(event);
    }

    pub(super) fn take(&self) -> Vec<BTreeMap<String, Value>> {
        std::mem::take(&mut *self.events.lock().unwrap())
    }
}

pub(super) struct EventCaptureLayer {
    pub(super) events: CapturedEvents,
}

impl<S> tracing_subscriber::Layer<S> for EventCaptureLayer
where
    S: Subscriber + for<'a> LookupSpan<'a>,
{
    fn on_event(&self, event: &Event<'_>, _ctx: TracingLayerContext<'_, S>) {
        let mut fields = BTreeMap::new();
        fields.insert(
            "level".to_string(),
            Value::String(event.metadata().level().to_string()),
        );
        event.record(&mut JsonVisitor(&mut fields));
        self.events.push(fields);
    }
}

struct JsonVisitor<'a>(&'a mut BTreeMap<String, Value>);

impl Visit for JsonVisitor<'_> {
    fn record_str(&mut self, field: &Field, value: &str) {
        self.0
            .insert(field.name().to_string(), Value::String(value.to_string()));
    }

    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        self.0.insert(
            field.name().to_string(),
            Value::String(format!("{value:?}")),
        );
    }

    fn record_i64(&mut self, field: &Field, value: i64) {
        self.0
            .insert(field.name().to_string(), Value::Number(value.into()));
    }

    fn record_u64(&mut self, field: &Field, value: u64) {
        self.0
            .insert(field.name().to_string(), Value::Number(value.into()));
    }

    fn record_bool(&mut self, field: &Field, value: bool) {
        self.0.insert(field.name().to_string(), Value::Bool(value));
    }
}

#[cfg(unix)]
#[tokio::test]
async fn audit_sink_creates_parent_and_file_owner_only() {
    let temp = TempDir::new().unwrap();
    let audit_dir = temp.path().join("audit");
    let audit_path = audit_dir.join("audit.jsonl");
    let sink = test_audit_sink(jsonl_audit_config(audit_path.display().to_string()));
    sink.append_required(test_audit_record()).await.unwrap();

    assert_eq!(mode(&audit_dir), 0o700);
    assert_eq!(mode(&audit_path), 0o600);
}

#[cfg(unix)]
#[tokio::test]
async fn audit_sink_revalidates_parent_before_retention_prune() {
    let temp = TempDir::new().unwrap();
    let audit_dir = temp.path().join("audit");
    let audit_path = audit_dir.join("audit.jsonl");
    let sink = test_audit_sink(crate::AuditConfig {
        retention_days: 0,
        ..jsonl_audit_config(audit_path.display().to_string())
    });
    sink.append_required(test_audit_record()).await.unwrap();
    // Append acknowledges before pruning; a queued probe waits for that first prune
    // to finish before this test creates a retained file and changes permissions.
    sink.check_writable().await.unwrap();
    let old_rotated = audit_dir.join(format!("audit.jsonl.20000101T000000Z.{}", Uuid::new_v4()));
    fs::write(&old_rotated, b"old").unwrap();
    let old_mtime =
        filetime::FileTime::from_unix_time(Utc::now().timestamp().saturating_sub(86_400), 0);
    filetime::set_file_mtime(&old_rotated, old_mtime).unwrap();
    fs::set_permissions(&audit_dir, fs::Permissions::from_mode(0o755)).unwrap();

    let error = sink.append_required(test_audit_record()).await.unwrap_err();

    assert!(matches!(error, RuntimeError::Audit { .. }));
    assert!(old_rotated.exists());
}

#[cfg(unix)]
#[tokio::test]
async fn audit_sink_revalidates_parent_before_rotation() {
    let temp = TempDir::new().unwrap();
    let audit_dir = temp.path().join("audit");
    let audit_path = audit_dir.join("audit.jsonl");
    let sink = test_audit_sink(crate::AuditConfig {
        rotate_bytes: Some(1),
        ..jsonl_audit_config(audit_path.display().to_string())
    });
    sink.append_required(test_audit_record()).await.unwrap();
    fs::set_permissions(&audit_dir, fs::Permissions::from_mode(0o755)).unwrap();

    let error = sink.append_required(test_audit_record()).await.unwrap_err();

    assert!(matches!(error, RuntimeError::Audit { .. }));
    assert!(audit_path.exists());
    let has_rotated_file = fs::read_dir(&audit_dir).unwrap().any(|entry| {
        entry
            .unwrap()
            .file_name()
            .to_string_lossy()
            .starts_with("audit.jsonl.")
    });
    assert!(!has_rotated_file);
}

#[test]
fn lookup_scope_errors_preserve_safe_local_validation_only() {
    let public = public_lookup_scope_error(ProviderError::error(
        ReasonCode::UpstreamForbidden,
        "upstream forbidden",
    ));
    assert_eq!(public.reason_code(), ReasonCode::ScopeUnresolved);
    assert_eq!(
        public.message,
        "resource scope is not authorized or unavailable"
    );

    let locator = public_lookup_scope_error(ProviderError::deny(
        ReasonCode::LocatorInvalid,
        "bad locator",
    ));
    assert_eq!(locator.reason_code(), ReasonCode::LocatorInvalid);
    assert_eq!(locator.message, "bad locator");

    for reason_code in [ReasonCode::BodyMalformed, ReasonCode::BodyFormatUnsupported] {
        let validation = public_lookup_scope_error(ProviderError::deny(
            reason_code,
            "safe local body validation",
        ));
        assert_eq!(validation.reason_code(), reason_code);
        assert_eq!(validation.message, "safe local body validation");
    }

    for reason_code in [
        ReasonCode::ScopeUnresolved,
        ReasonCode::UpstreamFailed,
        ReasonCode::UpstreamForbidden,
    ] {
        let hidden =
            public_lookup_scope_error(ProviderError::error(reason_code, "upstream scope detail"));
        assert_eq!(hidden.reason_code(), ReasonCode::ScopeUnresolved);
        assert_eq!(
            hidden.message,
            "resource scope is not authorized or unavailable"
        );
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct CredentialObservation {
    operation: String,
    token: Option<String>,
}

struct LookupTraceProvider {
    observations: Arc<Mutex<Vec<CredentialObservation>>>,
    service: String,
    action: String,
    scope_type: String,
    input_name: String,
}

/// The registered resource type a trace fixture's scope name stands for.
fn fixture_resource_type(scope: &str) -> ResourceType {
    match scope {
        "project" => agent_access_jira::JIRA_PROJECT_RESOURCE.id().clone(),
        "space" => agent_access_confluence::CONFLUENCE_SPACE_RESOURCE
            .id()
            .clone(),
        "repository" => agent_access_provider::GIT_REPOSITORY_RESOURCE.id().clone(),
        "job" => agent_access_cloudbees_ci::CLOUDBEES_CI_JOB_RESOURCE
            .id()
            .clone(),
        other => panic!("no fixture resource type for scope {other}"),
    }
}

impl Default for LookupTraceProvider {
    fn default() -> Self {
        Self::new("jira", "issue.view", "project", "project")
    }
}

impl LookupTraceProvider {
    fn new(service: &str, action: &str, scope_type: &str, input_name: &str) -> Self {
        Self {
            observations: Arc::new(Mutex::new(Vec::new())),
            service: service.to_string(),
            action: action.to_string(),
            scope_type: scope_type.to_string(),
            input_name: input_name.to_string(),
        }
    }

    fn observations(&self) -> Arc<Mutex<Vec<CredentialObservation>>> {
        Arc::clone(&self.observations)
    }

    fn record(&self, operation: &str, credential: Option<&ExecutionCredential>) {
        self.observations
            .lock()
            .unwrap()
            .push(CredentialObservation {
                operation: operation.to_string(),
                token: credential.map(|credential| credential_token(credential).to_owned()),
            });
    }
}

impl agent_access_provider::test_support::DescribedProvider for LookupTraceProvider {
    fn descriptor(&self) -> ServiceDescriptor {
        let mut properties = serde_json::Map::new();
        properties.insert(self.input_name.clone(), json!({ "type": "string" }));
        properties.insert("message".to_string(), json!({ "type": "string" }));
        ServiceDescriptor::new(self.service.clone(), "Lookup Trace Provider".to_string())
            .with_resource_scopes(BTreeMap::from([(
                self.scope_type.clone(),
                ResourceScopeCapabilities::new(
                    fixture_resource_type(&self.scope_type),
                    vec!["exact".into(), "all".into()],
                ),
            )]))
            .with_actions(vec![
                ActionDescriptor::new(
                    self.action.clone(),
                    "Trace lookup credential selection",
                    json!({
                        "type": "object",
                        "required": [self.input_name.clone(), "message"],
                        "properties": properties,
                        "additionalProperties": false
                    }),
                )
                .scope(self.scope_type.clone())
                .credential_modes(["service", "per_user"])
                .lookup(LookupRequirement::ScopeResolution),
            ])
    }
}

impl LookupTraceProvider {
    fn local_scopes(&self, action: &str, inputs: &Value) -> Result<ResourceScopes, ProviderError> {
        if action != self.action.as_str() {
            return Err(ProviderError::deny(
                ReasonCode::ServiceActionDenied,
                "trace action is not supported",
            ));
        }
        let Some(scope_value) = inputs.get(&self.input_name).and_then(Value::as_str) else {
            return Err(ProviderError::deny(
                ReasonCode::InputInvalid,
                "trace action requires scope input",
            ));
        };
        Ok(BTreeMap::from([(
            self.scope_type.clone(),
            vec![scope_value.to_string()],
        )]))
    }
}

#[async_trait::async_trait]
impl Provider for LookupTraceProvider {
    async fn resolve_scopes(
        &self,
        request: ScopeRequest<'_>,
    ) -> Result<ScopeResolution, ProviderError> {
        self.record("pre_scope", request.lookup_credential());
        self.local_scopes(request.action(), request.inputs())
            .map(ScopeResolution::resources)
    }

    async fn invoke(&self, request: ProviderInvocation) -> Result<ProviderResult, ProviderError> {
        self.record("execution_lookup", request.lookup_credential());
        self.record("execution", request.execution().static_credential());
        Ok(ProviderResult::new(json!({
            "credentialMode": request.credential_mode(),
        })))
    }
}

#[derive(Default)]
struct SearchPreflightTraceProvider {
    preflights: Arc<Mutex<Vec<Value>>>,
}

impl SearchPreflightTraceProvider {
    fn preflights(&self) -> Arc<Mutex<Vec<Value>>> {
        Arc::clone(&self.preflights)
    }
}

impl agent_access_provider::test_support::DescribedProvider for SearchPreflightTraceProvider {
    fn descriptor(&self) -> ServiceDescriptor {
        ServiceDescriptor::new("jira", "Search Preflight Trace Provider")
            .with_resource_scopes(BTreeMap::from([(
                "project".into(),
                ResourceScopeCapabilities::new(
                    agent_access_jira::JIRA_PROJECT_RESOURCE.id().clone(),
                    vec!["exact".into(), "all".into()],
                ),
            )]))
            .with_actions(vec![
                ActionDescriptor::new(
                    "search",
                    "Trace search authorization preflight",
                    json!({
                        "type": "object",
                        "additionalProperties": true
                    }),
                )
                .scope("project")
                .credential_modes(["service"])
                .search_contained(),
            ])
    }
}

#[async_trait::async_trait]
impl Provider for SearchPreflightTraceProvider {
    async fn resolve_scopes(
        &self,
        _request: ScopeRequest<'_>,
    ) -> Result<ScopeResolution, ProviderError> {
        panic!("search authorization must replace ordinary scope resolution")
    }

    async fn invoke(&self, request: ProviderInvocation) -> Result<ProviderResult, ProviderError> {
        assert!(
            request.state().is_none(),
            "core never writes provider-owned state"
        );
        let search = request
            .search_authorization()
            .expect("search invocation carries search authorization");
        self.preflights
            .lock()
            .unwrap()
            .push(json!({"scopeType": search.scope_type, "scope": search.scope}));
        Ok(ProviderResult::new(json!({"issues": []})))
    }
}

struct DependencyPolicyTraceProvider {
    observations: Arc<Mutex<Vec<CredentialObservation>>>,
    action: String,
    extra_actions: Vec<String>,
}

impl Default for DependencyPolicyTraceProvider {
    fn default() -> Self {
        Self {
            observations: Arc::new(Mutex::new(Vec::new())),
            action: "issue.dependency.add".to_string(),
            extra_actions: Vec::new(),
        }
    }
}

impl DependencyPolicyTraceProvider {
    fn new(action: &str) -> Self {
        Self {
            observations: Arc::new(Mutex::new(Vec::new())),
            action: action.to_string(),
            extra_actions: Vec::new(),
        }
    }

    fn with_extra_actions(action: &str, extra_actions: &[&str]) -> Self {
        Self {
            observations: Arc::new(Mutex::new(Vec::new())),
            action: action.to_string(),
            extra_actions: extra_actions
                .iter()
                .map(|action| (*action).to_string())
                .collect(),
        }
    }

    fn observations(&self) -> Arc<Mutex<Vec<CredentialObservation>>> {
        Arc::clone(&self.observations)
    }

    fn record(&self, operation: &str, credential: Option<&ExecutionCredential>) {
        self.observations
            .lock()
            .unwrap()
            .push(CredentialObservation {
                operation: operation.to_string(),
                token: credential.map(|credential| credential_token(credential).to_owned()),
            });
    }
}

impl agent_access_provider::test_support::DescribedProvider for DependencyPolicyTraceProvider {
    fn descriptor(&self) -> ServiceDescriptor {
        let mut actions = vec![self.action.clone()];
        actions.extend(self.extra_actions.iter().cloned());
        ServiceDescriptor::new("jira", "Jira Dependency Policy Trace Provider")
            .with_resource_scopes(BTreeMap::from([(
                "project".into(),
                ResourceScopeCapabilities::new(
                    agent_access_jira::JIRA_PROJECT_RESOURCE.id().clone(),
                    vec!["exact".into(), "all".into()],
                ),
            )]))
            .with_actions(
                actions
                    .into_iter()
                    .map(|action| {
                        let lookup = if action == self.action {
                            LookupRequirement::ScopeResolution
                        } else {
                            LookupRequirement::None
                        };
                        ActionDescriptor::new(
                            action,
                            "Trace Jira relationship policy selection",
                            json!({
                                "type": "object",
                                "additionalProperties": true
                            }),
                        )
                        .scope("project")
                        .credential_modes(["service"])
                        .lookup(lookup)
                    })
                    .collect(),
            )
    }
}

impl DependencyPolicyTraceProvider {
    fn local_scopes(&self, action: &str, _inputs: &Value) -> Result<ResourceScopes, ProviderError> {
        if action != self.action {
            return Err(ProviderError::deny(
                ReasonCode::ServiceActionDenied,
                "trace action is not supported",
            ));
        }
        Ok(BTreeMap::from([
            (
                "project".to_string(),
                vec!["ENG".to_string(), "OPS".to_string()],
            ),
            (
                "issue".to_string(),
                vec!["ENG-1".to_string(), "OPS-2".to_string()],
            ),
        ]))
    }
}

#[async_trait::async_trait]
impl Provider for DependencyPolicyTraceProvider {
    async fn resolve_scopes(
        &self,
        request: ScopeRequest<'_>,
    ) -> Result<ScopeResolution, ProviderError> {
        self.record("pre_scope", request.lookup_credential());
        self.local_scopes(request.action(), request.inputs())
            .map(ScopeResolution::resources)
    }

    async fn invoke(&self, request: ProviderInvocation) -> Result<ProviderResult, ProviderError> {
        self.record("execution", request.execution().static_credential());
        Ok(ProviderResult::new(json!({"status": "present"})))
    }
}

#[tokio::test]
async fn per_user_only_lookup_backed_action_uses_user_credential_for_pre_scope_lookup() {
    let provider = Arc::new(LookupTraceProvider::default());
    let observations = provider.observations();
    let mut config = base_fake_config();
    configure_lookup_trace_jira(&mut config);
    configure_lookup_trace_per_user(&mut config, "per-user-token");
    config.credentials.service.clear();
    config.credentials.lookup.clear();
    config.policy.grants = vec![lookup_trace_grant("per_user", None, &["project-PROJ"])];
    let runtime = BrokerRuntime::with_providers(config, vec![provider]).unwrap();

    let response = invoke_lookup_trace(&runtime, "PROJ").await;

    assert_eq!(response.status, 200);
    assert_eq!(
        response.envelope.result.unwrap()["credentialMode"],
        json!("per_user")
    );
    assert_lookup_observations(
        &observations,
        &[
            ("pre_scope", "per-user-token"),
            ("execution_lookup", "per-user-token"),
            ("execution", "per-user-token"),
        ],
    );
}

#[tokio::test]
async fn confluence_per_user_only_lookup_backed_action_uses_user_credential_for_pre_scope_lookup() {
    let provider = Arc::new(LookupTraceProvider::new(
        "confluence",
        "page.view",
        "space",
        "space",
    ));
    let observations = provider.observations();
    let mut config = base_fake_config();
    configure_lookup_trace_confluence(&mut config);
    configure_lookup_trace_per_user_for_service(&mut config, "confluence", "per-user-token");
    config.credentials.service.clear();
    config.credentials.lookup.clear();
    config.policy.grants = vec![lookup_trace_grant_for_service(
        "confluence",
        "page.view",
        "per_user",
        None,
        &["space-ENG"],
    )];
    let runtime = BrokerRuntime::with_providers(config, vec![provider]).unwrap();

    let response =
        invoke_lookup_trace_for_service(&runtime, "confluence", "page.view", "space", "ENG").await;

    assert_eq!(response.status, 200);
    assert_eq!(
        response.envelope.result.unwrap()["credentialMode"],
        json!("per_user")
    );
    assert_lookup_observations(
        &observations,
        &[
            ("pre_scope", "per-user-token"),
            ("execution_lookup", "per-user-token"),
            ("execution", "per-user-token"),
        ],
    );
}

#[tokio::test]
async fn mixed_lookup_backed_action_uses_shared_lookup_then_user_execution() {
    let provider = Arc::new(LookupTraceProvider::default());
    let observations = provider.observations();
    let mut config = base_fake_config();
    configure_lookup_trace_jira(&mut config);
    configure_lookup_trace_service(&mut config, "service-token");
    configure_lookup_trace_lookup(&mut config, "lookup-token");
    configure_lookup_trace_per_user(&mut config, "per-user-token");
    config.policy.grants = vec![
        lookup_trace_grant("service", Some(10), &["project-ENG"]),
        lookup_trace_grant("per_user", Some(20), &["project-PROJ"]),
    ];
    let runtime = BrokerRuntime::with_providers(config, vec![provider]).unwrap();

    let response = invoke_lookup_trace(&runtime, "PROJ").await;

    assert_eq!(response.status, 200);
    assert_eq!(
        response.envelope.result.unwrap()["credentialMode"],
        json!("per_user")
    );
    assert_lookup_observations(
        &observations,
        &[
            ("pre_scope", "lookup-token"),
            ("execution_lookup", "per-user-token"),
            ("execution", "per-user-token"),
        ],
    );
}

#[tokio::test]
async fn service_lookup_backed_action_uses_shared_lookup_and_service_execution() {
    let provider = Arc::new(LookupTraceProvider::default());
    let observations = provider.observations();
    let mut config = base_fake_config();
    configure_lookup_trace_jira(&mut config);
    configure_lookup_trace_service(&mut config, "service-token");
    configure_lookup_trace_lookup(&mut config, "lookup-token");
    config.policy.grants = vec![lookup_trace_grant("service", None, &["project-TEST"])];
    let runtime = BrokerRuntime::with_providers(config, vec![provider]).unwrap();

    let response = invoke_lookup_trace(&runtime, "TEST").await;

    assert_eq!(response.status, 200);
    assert_eq!(
        response.envelope.result.unwrap()["credentialMode"],
        json!("service")
    );
    assert_lookup_observations(
        &observations,
        &[
            ("pre_scope", "lookup-token"),
            ("execution_lookup", "lookup-token"),
            ("execution", "service-token"),
        ],
    );
}

#[tokio::test]
async fn jira_dependency_policy_denies_when_either_resolved_project_is_outside_grant() {
    let provider = Arc::new(DependencyPolicyTraceProvider::default());
    let observations = provider.observations();
    let mut config = base_fake_config();
    configure_lookup_trace_jira(&mut config);
    configure_lookup_trace_service(&mut config, "service-token");
    configure_lookup_trace_lookup(&mut config, "lookup-token");
    config.policy.grants = vec![PolicyGrantConfig {
        subjects: vec!["group:anonymous".to_string()],
        service: "jira".to_string(),
        actions: vec!["issue.dependency.add".to_string()],
        resources: resource_selection(&["project-ENG"]),
        execution_contexts: None,
        credential_mode: "service".to_string(),
        priority: None,
    }];
    let runtime = BrokerRuntime::with_providers(config, vec![provider]).unwrap();

    let response = runtime
        .invoke(
            governed(OperationContext {
                agent_request_id: "agent-request".to_string(),
                broker_request_id: "broker-request".to_string(),
                identity: IdentityContext::anonymous(),
                service: "jira".to_string(),
                action: "issue.dependency.add".to_string(),
                source: SourceContext::unknown(),
            }),
            InvokeRequest {
                inputs: json!({"blockingIssue": "ENG-1", "blockedIssue": "OPS-2"}),
                body_parts: vec![],
                ..InvokeRequest::new(json!({}))
            },
        )
        .await;

    assert_eq!(response.status, 403);
    assert_eq!(
        response.envelope.reason_code,
        Some(ReasonCode::ScopeUnresolved.into())
    );
    assert!(
        response.envelope.resource_scopes.is_empty(),
        "lookup-backed scope denials must not disclose resolved Jira issue keys or projects"
    );
    assert_lookup_observations(&observations, &[("pre_scope", "lookup-token")]);
}

#[tokio::test]
async fn jira_parent_policy_denies_when_either_resolved_project_is_outside_grant() {
    let provider = Arc::new(DependencyPolicyTraceProvider::new("issue.parent.set"));
    let observations = provider.observations();
    let mut config = base_fake_config();
    configure_lookup_trace_jira(&mut config);
    configure_lookup_trace_service(&mut config, "service-token");
    configure_lookup_trace_lookup(&mut config, "lookup-token");
    config.policy.grants = vec![PolicyGrantConfig {
        subjects: vec!["group:anonymous".to_string()],
        service: "jira".to_string(),
        actions: vec!["issue.parent.set".to_string()],
        resources: resource_selection(&["project-ENG"]),
        execution_contexts: None,
        credential_mode: "service".to_string(),
        priority: None,
    }];
    let runtime = BrokerRuntime::with_providers(config, vec![provider]).unwrap();

    let response = runtime
        .invoke(
            governed(OperationContext {
                agent_request_id: "agent-request".to_string(),
                broker_request_id: "broker-request".to_string(),
                identity: IdentityContext::anonymous(),
                service: "jira".to_string(),
                action: "issue.parent.set".to_string(),
                source: SourceContext::unknown(),
            }),
            InvokeRequest {
                inputs: json!({"issue": "ENG-1", "parentIssue": "OPS-2"}),
                body_parts: vec![],
                ..InvokeRequest::new(json!({}))
            },
        )
        .await;

    assert_eq!(response.status, 403);
    assert_eq!(
        response.envelope.reason_code,
        Some(ReasonCode::ScopeUnresolved.into())
    );
    assert!(
        response.envelope.resource_scopes.is_empty(),
        "lookup-backed scope denials must not disclose resolved Jira issue keys or projects"
    );
    assert_lookup_observations(&observations, &[("pre_scope", "lookup-token")]);
}

#[tokio::test]
async fn jira_issue_update_grant_does_not_authorize_parent_set() {
    let provider = Arc::new(DependencyPolicyTraceProvider::with_extra_actions(
        "issue.parent.set",
        &["issue.update"],
    ));
    let observations = provider.observations();
    let mut config = base_fake_config();
    configure_lookup_trace_jira(&mut config);
    configure_lookup_trace_service(&mut config, "service-token");
    configure_lookup_trace_lookup(&mut config, "lookup-token");
    config.policy.grants = vec![PolicyGrantConfig {
        subjects: vec!["group:anonymous".to_string()],
        service: "jira".to_string(),
        actions: vec!["issue.update".to_string()],
        resources: resource_selection(&["project-ENG", "project-OPS"]),
        execution_contexts: None,
        credential_mode: "service".to_string(),
        priority: None,
    }];
    let runtime = BrokerRuntime::with_providers(config, vec![provider]).unwrap();

    let response = runtime
        .invoke(
            governed(OperationContext {
                agent_request_id: "agent-request".to_string(),
                broker_request_id: "broker-request".to_string(),
                identity: IdentityContext::anonymous(),
                service: "jira".to_string(),
                action: "issue.parent.set".to_string(),
                source: SourceContext::unknown(),
            }),
            InvokeRequest {
                inputs: json!({"issue": "ENG-1", "parentIssue": "OPS-2"}),
                body_parts: vec![],
                ..InvokeRequest::new(json!({}))
            },
        )
        .await;

    assert_eq!(response.status, 403);
    assert!(
        matches!(
            response
                .envelope
                .reason_code
                .as_ref()
                .and_then(ReasonCodeId::standard),
            Some(ReasonCode::ScopeUnresolved | ReasonCode::ServiceActionDenied)
        ),
        "unexpected denial reason: {:?}",
        response.envelope.reason_code
    );
    let observations = observations.lock().unwrap().clone();
    assert!(
        !observations
            .iter()
            .any(|observation| observation.operation == "execution"),
        "parent-set must not reach execution when only issue.update is granted"
    );
}

#[tokio::test]
async fn jira_issue_create_grant_does_not_authorize_child_create() {
    let provider = Arc::new(DependencyPolicyTraceProvider::with_extra_actions(
        "issue.child.create",
        &["issue.create"],
    ));
    let observations = provider.observations();
    let mut config = base_fake_config();
    configure_lookup_trace_jira(&mut config);
    configure_lookup_trace_service(&mut config, "service-token");
    configure_lookup_trace_lookup(&mut config, "lookup-token");
    config.policy.grants = vec![PolicyGrantConfig {
        subjects: vec!["group:anonymous".to_string()],
        service: "jira".to_string(),
        actions: vec!["issue.create".to_string()],
        resources: resource_selection(&["project-ENG", "project-OPS"]),
        execution_contexts: None,
        credential_mode: "service".to_string(),
        priority: None,
    }];
    let runtime = BrokerRuntime::with_providers(config, vec![provider]).unwrap();

    let response = runtime
        .invoke(
            governed(OperationContext {
                agent_request_id: "agent-request".to_string(),
                broker_request_id: "broker-request".to_string(),
                identity: IdentityContext::anonymous(),
                service: "jira".to_string(),
                action: "issue.child.create".to_string(),
                source: SourceContext::unknown(),
            }),
            InvokeRequest {
                inputs: json!({
                    "project": "ENG",
                    "issueTypeId": "10001",
                    "summary": "Child issue",
                    "parentIssue": "OPS-2"
                }),
                body_parts: vec![],
                ..InvokeRequest::new(json!({}))
            },
        )
        .await;

    assert_eq!(response.status, 403);
    assert!(
        matches!(
            response
                .envelope
                .reason_code
                .as_ref()
                .and_then(ReasonCodeId::standard),
            Some(ReasonCode::ScopeUnresolved | ReasonCode::ServiceActionDenied)
        ),
        "unexpected denial reason: {:?}",
        response.envelope.reason_code
    );
    let observations = observations.lock().unwrap().clone();
    assert!(
        !observations
            .iter()
            .any(|observation| observation.operation == "execution"),
        "child-create must not reach execution when only issue.create is granted"
    );
}

#[tokio::test]
async fn high_priority_per_user_wildcard_shadows_lower_service_lookup_candidate() {
    let provider = Arc::new(LookupTraceProvider::default());
    let observations = provider.observations();
    let mut config = base_fake_config();
    configure_lookup_trace_jira(&mut config);
    configure_lookup_trace_service(&mut config, "service-token");
    configure_lookup_trace_lookup(&mut config, "lookup-token");
    configure_lookup_trace_per_user(&mut config, "per-user-token");
    config.policy.grants = vec![
        lookup_trace_grant("per_user", Some(100), &["project-all"]),
        lookup_trace_grant("service", Some(10), &["project-PROJ"]),
    ];
    let runtime = BrokerRuntime::with_providers(config, vec![provider]).unwrap();

    let response = invoke_lookup_trace(&runtime, "PROJ").await;

    assert_eq!(response.status, 200);
    assert_eq!(
        response.envelope.result.unwrap()["credentialMode"],
        json!("per_user")
    );
    assert_lookup_observations(
        &observations,
        &[
            ("pre_scope", "per-user-token"),
            ("execution_lookup", "per-user-token"),
            ("execution", "per-user-token"),
        ],
    );
}

#[tokio::test]
async fn same_precedence_per_user_wildcard_and_service_finite_denies_when_scope_matches_both() {
    let provider = Arc::new(LookupTraceProvider::default());
    let observations = provider.observations();
    let mut config = base_fake_config();
    configure_lookup_trace_jira(&mut config);
    configure_lookup_trace_service(&mut config, "service-token");
    configure_lookup_trace_lookup(&mut config, "lookup-token");
    configure_lookup_trace_per_user(&mut config, "per-user-token");
    config.policy.grants = vec![
        lookup_trace_grant("per_user", None, &["project-all"]),
        lookup_trace_grant("service", None, &["project-ENG"]),
    ];
    let runtime = BrokerRuntime::with_providers(config, vec![provider]).unwrap();

    let response = invoke_lookup_trace(&runtime, "ENG").await;

    assert_eq!(response.status, 403);
    assert_eq!(
        response.envelope.reason_code,
        Some(ReasonCode::ScopeUnresolved.into())
    );
    assert!(response.envelope.resource_scopes.is_empty());
    assert_lookup_observations(&observations, &[("pre_scope", "lookup-token")]);
}

#[tokio::test]
async fn same_precedence_per_user_wildcard_and_service_finite_permits_when_scope_excludes_service()
{
    let provider = Arc::new(LookupTraceProvider::default());
    let observations = provider.observations();
    let mut config = base_fake_config();
    configure_lookup_trace_jira(&mut config);
    configure_lookup_trace_service(&mut config, "service-token");
    configure_lookup_trace_lookup(&mut config, "lookup-token");
    configure_lookup_trace_per_user(&mut config, "per-user-token");
    config.policy.grants = vec![
        lookup_trace_grant("per_user", None, &["project-all"]),
        lookup_trace_grant("service", None, &["project-ENG"]),
    ];
    let runtime = BrokerRuntime::with_providers(config, vec![provider]).unwrap();

    let response = invoke_lookup_trace(&runtime, "OPS").await;

    assert_eq!(response.status, 200);
    assert_eq!(
        response.envelope.result.unwrap()["credentialMode"],
        json!("per_user")
    );
    assert_lookup_observations(
        &observations,
        &[
            ("pre_scope", "lookup-token"),
            ("execution_lookup", "per-user-token"),
            ("execution", "per-user-token"),
        ],
    );
}

#[tokio::test]
async fn missing_per_user_lookup_credential_fails_without_shared_lookup_fallback() {
    let provider = Arc::new(LookupTraceProvider::default());
    let observations = provider.observations();
    let mut config = base_fake_config();
    configure_lookup_trace_jira(&mut config);
    configure_lookup_trace_lookup(&mut config, "lookup-token");
    configure_lookup_trace_missing_per_user(&mut config, "per-user-token");
    config.policy.grants = vec![lookup_trace_grant("per_user", None, &["project-PROJ"])];
    let runtime = BrokerRuntime::with_providers(config, vec![provider]).unwrap();

    let response = invoke_lookup_trace(&runtime, "PROJ").await;

    assert_eq!(response.status, 403);
    assert_eq!(
        response.envelope.reason_code,
        Some(ReasonCode::CredentialNotProvisioned.into())
    );
    assert!(observations.lock().unwrap().is_empty());
}

#[tokio::test]
async fn no_candidate_lookup_backed_action_denies_before_upstream_lookup() {
    let provider = Arc::new(LookupTraceProvider::default());
    let observations = provider.observations();
    let mut config = base_fake_config();
    configure_lookup_trace_jira(&mut config);
    configure_lookup_trace_service(&mut config, "service-token");
    configure_lookup_trace_lookup(&mut config, "lookup-token");
    config.policy.grants = vec![lookup_trace_grant("service", None, &["project-TEST"])];
    config.policy.grants[0].subjects = vec!["group:other".to_string()];
    let runtime = BrokerRuntime::with_providers(config, vec![provider]).unwrap();

    let response = invoke_lookup_trace(&runtime, "TEST").await;

    assert_eq!(response.status, 403);
    assert_eq!(
        response.envelope.reason_code,
        Some(ReasonCode::ScopeUnresolved.into())
    );
    assert!(response.envelope.resource_scopes.is_empty());
    assert!(observations.lock().unwrap().is_empty());
}

#[tokio::test]
async fn execution_context_mismatch_denies_before_upstream_lookup() {
    let provider = Arc::new(LookupTraceProvider::default());
    let observations = provider.observations();
    let mut config = base_fake_config();
    configure_lookup_trace_jira(&mut config);
    configure_lookup_trace_service(&mut config, "service-token");
    configure_lookup_trace_lookup(&mut config, "lookup-token");
    config.execution_context = Some(crate::ExecutionContextConfig {
        allowed_values: vec![
            DEFAULT_EXECUTION_CONTEXT.to_string(),
            "interactive".to_string(),
            "automation".to_string(),
        ],
        default_context: None,
    });
    set_resource_contexts(&mut config);
    let mut grant = lookup_trace_grant("service", None, &["project-TEST"]);
    grant.execution_contexts = Some(vec!["interactive".to_string()]);
    config.policy.grants = vec![grant];
    let runtime = BrokerRuntime::with_providers(config, vec![provider]).unwrap();

    let response = invoke_lookup_trace_in_context(&runtime, "TEST", "automation").await;

    assert_eq!(response.status, 403);
    assert_eq!(
        response.envelope.reason_code,
        Some(ReasonCode::ScopeUnresolved.into())
    );
    assert!(response.envelope.resource_scopes.is_empty());
    assert!(observations.lock().unwrap().is_empty());
}

#[tokio::test]
async fn token_execution_context_mismatch_denies_before_upstream_lookup() {
    let provider = Arc::new(LookupTraceProvider::default());
    let observations = provider.observations();
    let mut config = base_fake_config();
    configure_lookup_trace_jira(&mut config);
    configure_lookup_trace_service(&mut config, "service-token");
    configure_lookup_trace_lookup(&mut config, "lookup-token");
    config.execution_context = Some(crate::ExecutionContextConfig {
        allowed_values: vec!["interactive".to_string(), "automation".to_string()],
        default_context: None,
    });
    set_resource_contexts(&mut config);
    let mut grant = lookup_trace_grant("service", None, &["project-TEST"]);
    grant.execution_contexts = Some(vec!["automation".to_string()]);
    config.policy.grants = vec![grant];
    let runtime = BrokerRuntime::with_providers(config, vec![provider]).unwrap();
    let identity = shell_token_identity(json!({
        "allowedServices": ["jira"],
        "allowedExecutionContexts": ["interactive"]
    }));

    let response = runtime
        .invoke(
            GovernedOperationContext {
                operation: OperationContext {
                    agent_request_id: "agent-request".to_string(),
                    broker_request_id: "broker-request".to_string(),
                    identity,
                    service: "jira".to_string(),
                    action: "issue.view".to_string(),
                    source: SourceContext::unknown(),
                },
                execution_context: ExecutionContext::new("automation").unwrap(),
            },
            InvokeRequest {
                inputs: json!({"project": "TEST", "message": "hello"}),
                body_parts: vec![],
                ..InvokeRequest::new(json!({}))
            },
        )
        .await;

    assert_eq!(
        response.status,
        ReasonCode::ExecutionContextDenied.http_status()
    );
    assert_eq!(
        response.envelope.reason_code,
        Some(ReasonCode::ExecutionContextDenied.into())
    );
    assert!(observations.lock().unwrap().is_empty());
}

#[test]
fn context_binding_and_service_context_intersection_are_enforced() {
    let runtime = BrokerRuntime::new(base_fake_config()).unwrap();
    let default = default_execution_context();
    let unbound = shell_token_identity(json!({"allowedServices":["fake"]}));
    assert!(
        runtime
            .enforce_agent_invoke_token_caveats(&unbound, "fake", "echo", &default)
            .is_err()
    );
    let bound = shell_token_identity(
        json!({"allowedServices":["fake"],"allowedExecutionContexts":["interactive"]}),
    );
    assert_eq!(
        runtime
            .enforce_agent_invoke_token_caveats(&bound, "fake", "echo", &default)
            .unwrap_err()
            .reason_code(),
        ReasonCode::ExecutionContextDenied
    );
    assert_eq!(
        runtime
            .enforce_agent_invoke_token_caveats(
                &bound,
                "jira",
                "issue.view",
                &ExecutionContext::new("interactive").unwrap()
            )
            .unwrap_err()
            .reason_code(),
        ReasonCode::ServiceActionDenied
    );
}

#[tokio::test]
async fn token_action_denies_before_lookup_and_resource_denies_before_execution() {
    let provider = Arc::new(LookupTraceProvider::default());
    let observations = provider.observations();
    let mut config = base_fake_config();
    configure_lookup_trace_jira(&mut config);
    configure_lookup_trace_service(&mut config, "service-token");
    configure_lookup_trace_lookup(&mut config, "lookup-token");
    config.policy.grants = vec![lookup_trace_grant(
        "service",
        None,
        &["project-TEST", "project-OPS"],
    )];
    let runtime = BrokerRuntime::with_providers(config, vec![provider]).unwrap();
    let invoke = |identity: IdentityContext, project: &'static str| {
        runtime.invoke(
            governed(OperationContext {
                agent_request_id: "agent-request".to_string(),
                broker_request_id: "broker-request".to_string(),
                identity,
                service: "jira".to_string(),
                action: "issue.view".to_string(),
                source: SourceContext::unknown(),
            }),
            InvokeRequest {
                inputs: json!({"project": project, "message": "hello"}),
                body_parts: vec![],
                ..InvokeRequest::new(json!({}))
            },
        )
    };

    let action_denied = invoke(
        shell_token_identity(json!({"allowedExecutionContexts": ["default"],
            "allowedServices": ["jira"],
            "serviceRestrictions": {
                "jira": {"actions": ["issue.create"]}
            }
        })),
        "TEST",
    )
    .await;
    assert_eq!(
        action_denied.envelope.reason_code,
        Some(ReasonCode::ServiceActionDenied.into())
    );
    assert!(observations.lock().unwrap().is_empty());

    let resource_denied = invoke(
        shell_token_identity(json!({"allowedExecutionContexts": ["default"],
            "allowedServices": ["jira"],
            "serviceRestrictions": {
                "jira": {
                    "actions": ["issue.view"],
                    "resources": {"resourceIds": ["project-TEST"]}
                }
            }
        })),
        "OPS",
    )
    .await;
    assert_eq!(
        resource_denied.envelope.reason_code,
        Some(ReasonCode::ScopeUnresolved.into())
    );
    let normalized = lookup_scope_denial();
    assert_eq!(
        resource_denied
            .envelope
            .error
            .as_ref()
            .map(|error| error.message.as_str()),
        Some(normalized.message.as_str())
    );
    assert_eq!(
        observations.lock().unwrap().as_slice(),
        &[CredentialObservation {
            operation: "pre_scope".to_string(),
            token: Some("lookup-token".to_string()),
        }]
    );
}

#[test]
fn token_search_boundary_intersects_policy_before_provider_dispatch() {
    let mut config = base_fake_config();
    configure_lookup_trace_confluence(&mut config);
    config.policy.grants.clear();
    let runtime = BrokerRuntime::new(config).unwrap();
    let identity = shell_token_identity(json!({"allowedExecutionContexts": ["default"],
        "allowedServices": ["confluence"],
        "serviceRestrictions": {
            "confluence": {
                "actions": ["search"],
                "resources": {"resourceIds": ["space-ENG", "space-RESEARCH"]}
            }
        }
    }));
    let mut authorization = SearchAuthorizationPlan {
        scope_type: "space".to_string(),
        scope: SearchAuthorizationScope::Finite {
            values: vec!["ENG".to_string(), "OPS".to_string()],
        },
        credential_mode: "service".to_string(),
        matched_grants: Vec::new(),
    };

    runtime
        .intersect_agent_invoke_token_search_authorization(
            &identity,
            "confluence",
            "search",
            &mut authorization,
        )
        .unwrap();

    assert_eq!(
        authorization.scope,
        SearchAuthorizationScope::Finite {
            values: vec!["ENG".to_string()]
        }
    );
    runtime
        .enforce_agent_invoke_token_resource_caveats(
            &identity,
            "confluence",
            "search",
            &authorization.resource_scope_summary(),
        )
        .unwrap();
}

#[tokio::test]
async fn token_search_boundary_is_narrowed_in_provider_search_authorization() {
    let provider = Arc::new(SearchPreflightTraceProvider::default());
    let preflights = provider.preflights();
    let mut config = base_fake_config();
    configure_lookup_trace_jira(&mut config);
    configure_lookup_trace_service(&mut config, "service-token");
    config.policy.grants = vec![lookup_trace_grant_for_service(
        "jira",
        "search",
        "service",
        None,
        &["project-all"],
    )];
    let runtime = BrokerRuntime::with_providers(config, vec![provider]).unwrap();

    let response = runtime
        .invoke(
            governed(OperationContext {
                agent_request_id: "agent-request".to_string(),
                broker_request_id: "broker-request".to_string(),
                identity: shell_token_identity(json!({"allowedExecutionContexts": ["default"],
                    "allowedServices": ["jira"],
                    "serviceRestrictions": {
                        "jira": {
                            "actions": ["search"],
                            "resources": {"resourceIds": ["project-ENG"]}
                        }
                    }
                })),
                service: "jira".to_string(),
                action: "search".to_string(),
                source: SourceContext::unknown(),
            }),
            InvokeRequest {
                inputs: json!({"query": "status = Open"}),
                body_parts: vec![],
                ..InvokeRequest::new(json!({}))
            },
        )
        .await;

    assert_eq!(response.status, 200);
    let preflights = preflights.lock().unwrap();
    assert_eq!(preflights.len(), 1);
    assert_eq!(preflights[0]["scopeType"], json!("project"));
    assert_eq!(
        preflights[0]["scope"],
        json!({
            "type": "finite",
            "values": ["ENG"]
        })
    );
}

#[tokio::test]
async fn empty_token_search_intersection_denies_without_provider_invocation() {
    let provider = Arc::new(SearchPreflightTraceProvider::default());
    let preflights = provider.preflights();
    let mut config = base_fake_config();
    configure_lookup_trace_jira(&mut config);
    configure_lookup_trace_service(&mut config, "service-token");
    config.policy.grants = vec![lookup_trace_grant_for_service(
        "jira",
        "search",
        "service",
        None,
        &["project-OPS"],
    )];
    let runtime = BrokerRuntime::with_providers(config, vec![provider]).unwrap();

    let response = runtime
        .invoke(
            governed(OperationContext {
                agent_request_id: "agent-request".to_string(),
                broker_request_id: "broker-request".to_string(),
                identity: shell_token_identity(json!({"allowedExecutionContexts": ["default"],
                    "allowedServices": ["jira"],
                    "serviceRestrictions": {
                        "jira": {
                            "actions": ["search"],
                            "resources": {"resourceIds": ["project-ENG"]}
                        }
                    }
                })),
                service: "jira".to_string(),
                action: "search".to_string(),
                source: SourceContext::unknown(),
            }),
            InvokeRequest {
                inputs: json!({"query": "status = Open"}),
                body_parts: vec![],
                ..InvokeRequest::new(json!({}))
            },
        )
        .await;

    assert_eq!(
        response.envelope.reason_code,
        Some(ReasonCode::ServiceActionDenied.into())
    );
    assert!(preflights.lock().unwrap().is_empty());
}

#[test]
fn token_action_boundary_filters_caller_discovery() {
    let provider = Arc::new(DependencyPolicyTraceProvider::with_extra_actions(
        "issue.view",
        &["issue.update"],
    ));
    let mut config = base_fake_config();
    configure_lookup_trace_jira(&mut config);
    configure_lookup_trace_service(&mut config, "service-token");
    configure_lookup_trace_lookup(&mut config, "lookup-token");
    config.policy.grants = vec![PolicyGrantConfig {
        actions: vec!["issue.view".to_string(), "issue.update".to_string()],
        ..lookup_trace_grant("service", None, &["project-ENG"])
    }];
    let runtime = BrokerRuntime::with_providers(config, vec![provider]).unwrap();
    let identity = shell_token_identity(json!({"allowedExecutionContexts": ["default"],
        "allowedServices": ["jira"],
        "serviceRestrictions": {
            "jira": {"actions": ["issue.view"]}
        }
    }));

    let services = runtime.visible_services(&identity, &default_execution_context());

    assert_eq!(services.len(), 1);
    assert_eq!(services[0].service, "jira");
    assert_eq!(services[0].actions.len(), 1);
    assert_eq!(services[0].actions[0].action, "issue.view");
}

#[test]
fn stored_agent_token_caveats_reject_malformed_and_retired_contexts() {
    assert_eq!(
        normalized_stored_agent_invoke_caveats(
            &json!({"allowedExecutionContexts": ["default"], "unknown": true}),
            None,
        ),
        Err(IdentityFailure::Invalid)
    );
    let configured = crate::ExecutionContextConfig {
        allowed_values: vec!["current".to_string()],
        default_context: None,
    };
    assert_eq!(
        normalized_stored_agent_invoke_caveats(
            &json!({"allowedExecutionContexts": ["retired"]}),
            Some(&configured),
        ),
        Err(IdentityFailure::Invalid)
    );
    assert_eq!(
        normalized_stored_agent_invoke_caveats(&json!({"allowedServices":["fake"]}), None),
        Err(IdentityFailure::Invalid)
    );
}

#[test]
fn agent_token_options_preserve_configured_context_order_and_union_groups() {
    let mut config = base_fake_config();
    config.execution_context = Some(crate::ExecutionContextConfig {
        allowed_values: vec!["automation".to_string(), "interactive".to_string()],
        default_context: None,
    });
    set_resource_contexts(&mut config);
    let mut automation =
        lookup_trace_grant_for_service("fake", "echo", "service", None, &["fake-project-TEST"]);
    automation.subjects = vec!["group:agents".to_string()];
    automation.execution_contexts = Some(vec!["automation".to_string()]);
    let mut interactive = automation.clone();
    interactive.subjects = vec!["group:other".to_string()];
    interactive.execution_contexts = Some(vec!["interactive".to_string()]);
    config.policy.grants = vec![interactive, automation];
    let runtime = BrokerRuntime::new(config).unwrap();
    let identity = IdentityContext {
        policy_groups: vec!["agents".to_string(), "other".to_string()],
        groups: vec!["agents".to_string(), "other".to_string()],
        ..agent_one_identity()
    };

    let options = runtime.agent_token_options_for_identity(&identity);

    assert_eq!(
        options.execution_contexts,
        vec![
            ExecutionContext::new("automation").unwrap(),
            ExecutionContext::new("interactive").unwrap()
        ]
    );
    assert_eq!(options.services.len(), 1);
    assert_eq!(options.services[0].service, "fake");
    assert_eq!(
        options.services[0].execution_contexts,
        options.execution_contexts
    );
    assert_eq!(options.services[0].actions.len(), 1);
    let action = &options.services[0].actions[0];
    assert_eq!(action.action, "echo");
    assert_eq!(action.execution_contexts, options.execution_contexts);
    for execution_context in &options.execution_contexts {
        let clauses = &action.effective_access_by_execution_context[execution_context];
        assert!(clauses.iter().any(|boundary| boundary.matches("TEST")));
        assert!(clauses.iter().all(|boundary| !boundary.matches("OTHER")));
    }
}

#[test]
fn agent_token_options_carry_service_metadata_outside_the_default_context() {
    let mut config = base_fake_config();
    config.execution_context = Some(crate::ExecutionContextConfig {
        allowed_values: vec!["default".to_string(), "external".to_string()],
        default_context: Some("default".to_string()),
    });
    set_resource_contexts(&mut config);
    config.credentials.service.insert(
        "gitlab_git".to_string(),
        fake_service_credential("env:GITLAB_SERVICE_TOKEN"),
    );
    config
        .gateways
        .insert("gitlab_git".to_string(), git_gateway_config());
    // Every grant is in the non-default context; the default context has none.
    let mut echo =
        lookup_trace_grant_for_service("fake", "echo", "service", None, &["fake-project-TEST"]);
    echo.execution_contexts = Some(vec!["external".to_string()]);
    let mut git = lookup_trace_grant_for_service(
        "gitlab_git",
        "repo.fetch",
        "service",
        None,
        &["repository-sip-service"],
    );
    git.actions.push("repo.push".to_string());
    git.execution_contexts = Some(vec!["external".to_string()]);
    config.policy.grants = vec![echo, git];
    let runtime = BrokerRuntime::new(config).unwrap();
    let identity = agent_one_identity();
    assert!(
        runtime
            .visible_services(&identity, &default_execution_context())
            .is_empty(),
        "the identity must have no access in the configured default context"
    );

    let options = runtime.agent_token_options_for_identity(&identity);

    let external = ExecutionContext::new("external").unwrap();
    let service = |name: &str| {
        options
            .services
            .iter()
            .find(|service| service.service == name)
            .unwrap_or_else(|| panic!("{name} must be offered"))
    };
    let read_only = |service: &crate::AgentTokenServiceOption, action: &str| {
        service
            .actions
            .iter()
            .find(|candidate| candidate.action == action)
            .unwrap_or_else(|| panic!("{action} must be offered"))
            .read_only
    };
    let fake = service("fake");
    assert_eq!(fake.execution_contexts, vec![external.clone()]);
    assert_eq!(fake.display_name, "Fake Provider");
    assert!(fake.broker_hosts.is_empty());
    assert!(read_only(fake, "echo"));
    let git = service("gitlab_git");
    assert_eq!(git.execution_contexts, vec![external]);
    assert_eq!(git.display_name, "GitLab Git");
    assert_eq!(git.broker_hosts, vec!["git.example.test".to_string()]);
    assert!(read_only(git, "repo.fetch"));
    assert!(!read_only(git, "repo.push"));

    // The wire projection names the new fields in camelCase.
    let wire = serde_json::to_value(&options).unwrap();
    let wire_service = |name: &str| {
        wire["services"]
            .as_array()
            .unwrap()
            .iter()
            .find(|service| service["service"] == name)
            .unwrap()
    };
    assert_eq!(wire_service("fake")["displayName"], "Fake Provider");
    assert_eq!(wire_service("fake")["brokerHosts"], json!([]));
    assert_eq!(wire_service("fake")["actions"][0]["readOnly"], true);
    assert_eq!(wire_service("gitlab_git")["displayName"], "GitLab Git");
    assert_eq!(
        wire_service("gitlab_git")["brokerHosts"],
        json!(["git.example.test"])
    );
    let git_actions = wire_service("gitlab_git")["actions"].as_array().unwrap();
    for (action, expected) in [("repo.fetch", true), ("repo.push", false)] {
        let wire_action = git_actions
            .iter()
            .find(|candidate| candidate["action"] == action)
            .unwrap();
        assert_eq!(wire_action["readOnly"], expected, "{action}");
    }
}

#[test]
fn agent_token_options_exclude_only_same_band_wildcard_credential_overlap() {
    let provider = Arc::new(LookupTraceProvider::default());
    let mut config = base_fake_config();
    configure_lookup_trace_jira(&mut config);
    configure_lookup_trace_service(&mut config, "service-token");
    configure_lookup_trace_lookup(&mut config, "lookup-token");
    configure_lookup_trace_per_user(&mut config, "per-user-token");
    config.policy.grants = vec![
        lookup_trace_grant("per_user", None, &["project-all"]),
        lookup_trace_grant("service", None, &["project-ENG"]),
    ];
    let runtime = BrokerRuntime::with_providers(config, vec![provider]).unwrap();

    let options = runtime.agent_token_options_for_identity(&agent_one_identity());

    let clauses = &options.services[0].actions[0].effective_access_by_execution_context
        [&default_execution_context()];
    assert!(
        clauses
            .iter()
            .any(|boundary| boundary.matches("NEWPROJECT")),
        "non-overlapping resources remain usable through per-user all"
    );
    assert!(
        clauses.iter().all(|boundary| !boundary.matches("ENG")),
        "mixed credential modes in the top band must not appear usable"
    );
}

#[test]
fn search_token_options_preserve_authored_contexts_and_report_effective_precedence() {
    let provider = Arc::new(SearchPreflightTraceProvider::default());
    let mut config = base_fake_config();
    configure_lookup_trace_jira(&mut config);
    configure_lookup_trace_service(&mut config, "service-token");
    configure_lookup_trace_per_user(&mut config, "per-user-token");
    let identity_token = write_temp_secret("agent-one-token");
    config.identity = static_identity_config(
        "required",
        &identity_token,
        "agent-one",
        vec!["agents".to_string()],
    );
    config.execution_context = Some(crate::ExecutionContextConfig {
        allowed_values: vec![
            "rank".to_string(),
            "priority".to_string(),
            "missing-scope".to_string(),
            "ambiguous".to_string(),
        ],
        default_context: None,
    });
    set_resource_contexts(&mut config);
    let search_grant =
        |subject: &str, context: &str, mode: &str, priority: i32, projects: &[&str]| {
            let mut grant =
                lookup_trace_grant_for_service("jira", "search", mode, Some(priority), projects);
            grant.subjects = vec![subject.to_string()];
            grant.execution_contexts = Some(vec![context.to_string()]);
            grant
        };
    config.policy.grants = vec![
        search_grant("user:agent-one", "rank", "service", 0, &["project-ENG"]),
        search_grant("group:agents", "rank", "service", 100, &["project-OPS"]),
        search_grant("group:agents", "priority", "service", 10, &["project-ENG"]),
        search_grant("group:agents", "priority", "service", 0, &["project-OPS"]),
        search_grant(
            "group:agents",
            "missing-scope",
            "service",
            0,
            &["project-OPS"],
        ),
        search_grant("group:agents", "ambiguous", "service", 10, &["project-ENG"]),
        search_grant(
            "group:agents",
            "ambiguous",
            "per_user",
            10,
            &["project-OPS"],
        ),
    ];
    let runtime = BrokerRuntime::with_providers(config, vec![provider]).unwrap();
    let mut missing_scope = search_grant(
        "group:agents",
        "missing-scope",
        "service",
        10,
        &["project-ENG"],
    );
    missing_scope.resources = ResourceSelection::default();
    let mut policy_snapshot = runtime.policy_snapshot.load_full().as_ref().clone();
    policy_snapshot.grants.push(RuntimePolicyGrant::from_toml(
        policy_snapshot.grants.len(),
        0,
        "group:agents",
        &missing_scope,
    ));
    runtime.policy_snapshot.store(Arc::new(policy_snapshot));

    let options = runtime.agent_token_options_for_identity(&agent_one_identity());

    assert_eq!(options.services.len(), 1);
    assert_eq!(options.services[0].service, "jira");
    assert_eq!(options.services[0].actions.len(), 1);
    let action = &options.services[0].actions[0];
    assert_eq!(action.action, "search");
    assert_eq!(
        action
            .execution_contexts
            .iter()
            .map(ExecutionContext::as_str)
            .collect::<BTreeSet<_>>(),
        BTreeSet::from(["rank", "priority", "missing-scope", "ambiguous"]),
        "authored grant contexts remain selectable even when current access is empty"
    );
    let identity = agent_one_identity();
    let snapshot = runtime.policy_snapshot();
    for context in ["rank", "priority"] {
        let context = ExecutionContext::new(context).unwrap();
        let clauses = &action.effective_access_by_execution_context[&context];
        assert!(clauses.iter().any(|boundary| boundary.matches("ENG")));
        assert!(clauses.iter().all(|boundary| !boundary.matches("OPS")));
        let authorization = runtime
            .plan_search_authorization(&snapshot, &identity, &context, "jira", "search")
            .unwrap();
        assert!(authorization.scope.matches("ENG"));
        assert!(!authorization.scope.matches("OPS"));
    }
    let missing_scope = ExecutionContext::new("missing-scope").unwrap();
    let clauses = &action.effective_access_by_execution_context[&missing_scope];
    assert!(clauses.iter().any(|boundary| boundary.matches("OPS")));
    assert!(
        clauses
            .iter()
            .all(|boundary| !boundary.matches("ENG") && !boundary.matches("NEWPROJECT")),
        "an empty high-priority selection contributes no permission and does not suppress a separate matching grant"
    );
    let authorization = runtime
        .plan_search_authorization(&snapshot, &identity, &missing_scope, "jira", "search")
        .unwrap();
    assert!(authorization.scope.matches("OPS"));
    assert!(!authorization.scope.matches("ENG"));
    assert!(!authorization.scope.matches("NEWPROJECT"));

    let ambiguous = ExecutionContext::new("ambiguous").unwrap();
    assert!(
        action.effective_access_by_execution_context[&ambiguous].is_empty(),
        "mixed credential modes in the top search band provide no effective access"
    );
    assert_eq!(
        runtime
            .plan_search_authorization(&snapshot, &identity, &ambiguous, "jira", "search")
            .unwrap_err()
            .reason_code(),
        ReasonCode::ServiceActionDenied
    );
}

#[test]
fn toml_and_managed_grants_normalize_execution_contexts_identically() {
    let mut toml = lookup_trace_grant("service", None, &["project-TEST"]);
    toml.execution_contexts = Some(vec!["interactive".to_string(), "automation".to_string()]);
    let toml = RuntimePolicyGrant::from_toml(0, 0, "group:agents", &toml);
    let managed = RuntimePolicyGrant::from_managed(ManagedPolicyGrantRecord {
        grant_id: "grant-contexts".to_string(),
        grant_order: 0,
        subjects: vec!["group:agents".to_string()],
        execution_contexts: vec!["interactive".to_string(), "automation".to_string()],
        service: "jira".to_string(),
        actions: vec!["issue.view".to_string()],
        resources: resource_selection(&["project-TEST"]),
        credential_mode: "service".to_string(),
        priority: None,
        status: "active".to_string(),
        description: None,
        version: 1,
        created_at: "2026-01-01T00:00:00Z".to_string(),
        created_by: "admin".to_string(),
        updated_at: "2026-01-01T00:00:00Z".to_string(),
        updated_by: "admin".to_string(),
        disabled_at: None,
        deleted_at: None,
    });

    assert_eq!(managed.len(), 1);
    assert_eq!(toml.execution_contexts, managed[0].execution_contexts);
}

#[test]
fn omitted_toml_execution_context_normalizes_to_builtin_default() {
    let toml = RuntimePolicyGrant::from_toml(
        0,
        0,
        "group:agents",
        &lookup_trace_grant("service", None, &["project-TEST"]),
    );

    assert_eq!(toml.execution_contexts, vec![default_execution_context()]);
}

#[test]
fn runtime_startup_sweeps_stale_upload_spool_files() {
    let dir = temp_path("upload-spool");
    fs::create_dir_all(&dir).unwrap();
    #[cfg(unix)]
    fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();
    let stale = dir.join(format!("{}stale", UPLOAD_SPOOL_FILE_PREFIX));
    let unrelated = dir.join("unrelated.tmp");
    fs::write(&stale, b"stale upload").unwrap();
    fs::write(&unrelated, b"keep").unwrap();
    let mut config = base_fake_config();
    config.limits.upload_spool_dir = dir.display().to_string();

    BrokerRuntime::new(config).unwrap();

    assert!(!stale.exists());
    assert!(unrelated.exists());
}

#[cfg(unix)]
#[test]
fn runtime_startup_creates_upload_spool_owner_only() {
    let temp = TempDir::new().unwrap();
    let dir = temp.path().join("upload-spool");
    let mut config = base_fake_config();
    config.limits.upload_spool_dir = dir.display().to_string();

    BrokerRuntime::new(config).unwrap();

    assert_eq!(mode(&dir), 0o700);
}

#[test]
fn runtime_startup_preserves_live_pid_upload_spool_files() {
    let dir = temp_path("upload-spool-live");
    fs::create_dir_all(&dir).unwrap();
    #[cfg(unix)]
    fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();
    let live = dir.join(format!("{}active", upload_spool_file_prefix()));
    fs::write(&live, b"active upload").unwrap();
    let mut config = base_fake_config();
    config.limits.upload_spool_dir = dir.display().to_string();

    BrokerRuntime::new(config).unwrap();

    assert!(live.exists());
}

struct MissingStreamHandleProvider;
struct CompletedStreamProvider;
struct FailingStreamProvider;
struct PendingStreamProvider;

impl agent_access_provider::test_support::DescribedProvider for MissingStreamHandleProvider {
    fn descriptor(&self) -> ServiceDescriptor {
        agent_access_fake::fake_descriptor()
    }
}

#[async_trait::async_trait]
impl Provider for MissingStreamHandleProvider {
    async fn resolve_scopes(
        &self,
        request: ScopeRequest<'_>,
    ) -> Result<ScopeResolution, ProviderError> {
        agent_access_fake::FakeProvider
            .echo_scopes(request.action(), request.inputs())
            .map(ScopeResolution::resources)
    }

    async fn invoke(&self, request: ProviderInvocation) -> Result<ProviderResult, ProviderError> {
        // A stream whose body was already taken.
        let mut stream = ProviderResultStream::from_bytes("text/plain", Vec::new());
        stream.source = ProviderResultStreamSource::Stream(Arc::new(Mutex::new(None)));
        Ok(ProviderResult::new(json!({
            "provider": "fake",
            "action": request.action(),
        }))
        .with_stream(stream))
    }
}

impl agent_access_provider::test_support::DescribedProvider for FailingStreamProvider {
    fn descriptor(&self) -> ServiceDescriptor {
        agent_access_fake::fake_descriptor()
    }
}

#[async_trait::async_trait]
impl Provider for FailingStreamProvider {
    async fn resolve_scopes(
        &self,
        request: ScopeRequest<'_>,
    ) -> Result<ScopeResolution, ProviderError> {
        agent_access_fake::FakeProvider
            .echo_scopes(request.action(), request.inputs())
            .map(ScopeResolution::resources)
    }

    async fn invoke(&self, request: ProviderInvocation) -> Result<ProviderResult, ProviderError> {
        let stream = futures_util::stream::iter([
            Ok(Bytes::from_static(b"prefix")),
            Err(ProviderStreamError::new(
                ReasonCode::UpstreamProtocolFailed,
                "provider stream failed",
            )),
        ]);
        Ok(ProviderResult::new(json!({
            "provider": "fake",
            "action": request.action(),
        }))
        .with_stream(ProviderResultStream::from_stream("text/plain", stream))
        .with_audit(json!({
            "provider": "fake",
            "operation": "echo",
        }))
        .with_upstream(Some(200), Some(1)))
    }
}

impl agent_access_provider::test_support::DescribedProvider for CompletedStreamProvider {
    fn descriptor(&self) -> ServiceDescriptor {
        agent_access_fake::fake_descriptor()
    }
}

#[async_trait::async_trait]
impl Provider for CompletedStreamProvider {
    async fn resolve_scopes(
        &self,
        request: ScopeRequest<'_>,
    ) -> Result<ScopeResolution, ProviderError> {
        agent_access_fake::FakeProvider
            .echo_scopes(request.action(), request.inputs())
            .map(ScopeResolution::resources)
    }

    async fn invoke(&self, request: ProviderInvocation) -> Result<ProviderResult, ProviderError> {
        let stream = futures_util::stream::iter([
            Ok(Bytes::from_static(b"prefix")),
            Ok(Bytes::from_static(b"-suffix")),
        ]);
        Ok(ProviderResult::new(json!({
            "provider": "fake",
            "action": request.action(),
        }))
        .with_stream(ProviderResultStream::from_stream("text/plain", stream))
        .with_audit(json!({
            "provider": "fake",
            "operation": "echo",
        }))
        .with_upstream(Some(200), Some(1)))
    }
}

impl agent_access_provider::test_support::DescribedProvider for PendingStreamProvider {
    fn descriptor(&self) -> ServiceDescriptor {
        agent_access_fake::fake_descriptor()
    }
}

#[async_trait::async_trait]
impl Provider for PendingStreamProvider {
    async fn resolve_scopes(
        &self,
        request: ScopeRequest<'_>,
    ) -> Result<ScopeResolution, ProviderError> {
        agent_access_fake::FakeProvider
            .echo_scopes(request.action(), request.inputs())
            .map(ScopeResolution::resources)
    }

    async fn invoke(&self, request: ProviderInvocation) -> Result<ProviderResult, ProviderError> {
        let stream = futures_util::stream::once(async { Ok(Bytes::from_static(b"prefix")) })
            .chain(futures_util::stream::pending());
        Ok(ProviderResult::new(json!({
            "provider": "fake",
            "action": request.action(),
        }))
        .with_stream(ProviderResultStream::from_stream("text/plain", stream))
        .with_audit(json!({
            "provider": "fake",
            "operation": "echo",
        }))
        .with_upstream(Some(200), Some(1)))
    }
}

async fn invoke_test_stream(runtime: &BrokerRuntime) -> BrokerResponse<Value> {
    runtime
        .invoke_required_stream(
            governed(OperationContext {
                agent_request_id: "agent-request".to_string(),
                broker_request_id: "broker-request".to_string(),
                identity: IdentityContext::anonymous(),
                service: "fake".to_string(),
                action: "echo".to_string(),
                source: SourceContext::unknown(),
            }),
            InvokeRequest {
                inputs: json!({
                    "project": "TEST",
                    "message": "download",
                }),
                body_parts: vec![],
                ..InvokeRequest::new(json!({}))
            },
        )
        .await
}

#[tokio::test]
async fn provider_invocation_carries_correlation_context() {
    let runtime = BrokerRuntime::with_providers(
        base_fake_config(),
        vec![Arc::new(CorrelationCaptureProvider)],
    )
    .unwrap();

    let response = runtime
        .invoke(
            governed(OperationContext {
                agent_request_id: "agent-correlation-id".to_string(),
                broker_request_id: "broker-correlation-id".to_string(),
                identity: IdentityContext::anonymous(),
                service: "fake".to_string(),
                action: "echo".to_string(),
                source: SourceContext::unknown(),
            }),
            InvokeRequest {
                inputs: json!({
                    "project": "TEST",
                    "message": "hello",
                }),
                body_parts: vec![],
                ..InvokeRequest::new(json!({}))
            },
        )
        .await;

    assert_eq!(response.status, 200);
    assert_eq!(response.envelope.agent_request_id, "agent-correlation-id");
    assert_eq!(response.envelope.broker_request_id, "broker-correlation-id");
    let result = response.envelope.result.unwrap();
    assert_eq!(result["agentRequestId"], "agent-correlation-id");
    assert_eq!(result["brokerRequestId"], "broker-correlation-id");
}

#[tokio::test]
async fn provider_invocation_receives_the_authorized_execution_context() {
    let mut config = base_fake_config();
    config.execution_context = Some(crate::ExecutionContextConfig {
        allowed_values: vec!["internal".into(), "external".into()],
        default_context: None,
    });
    for resource in &mut config.policy.resources {
        resource.allowed_execution_contexts = vec!["internal".into(), "external".into()];
    }
    config.policy.grants[0].execution_contexts = Some(vec!["internal".into(), "external".into()]);
    let runtime =
        BrokerRuntime::with_providers(config, vec![Arc::new(CorrelationCaptureProvider)]).unwrap();
    for context in ["internal", "external"] {
        let response = runtime
            .invoke(
                GovernedOperationContext {
                    operation: OperationContext {
                        agent_request_id: "context-test".into(),
                        broker_request_id: "context-test".into(),
                        identity: IdentityContext::anonymous(),
                        service: "fake".into(),
                        action: "echo".into(),
                        source: SourceContext::unknown(),
                    },
                    execution_context: ExecutionContext::new(context).unwrap(),
                },
                InvokeRequest::new(json!({"project": "TEST", "message": "hello"})),
            )
            .await;
        assert_eq!(response.status, 200);
        assert_eq!(
            response.envelope.result.unwrap()["executionContext"],
            context
        );
    }
}

#[tokio::test]
async fn body_part_authorization_receives_provider_correlation_context() {
    let captured_correlation = Arc::new(Mutex::new(None));
    let captured_action = Arc::new(Mutex::new(None));
    let runtime = BrokerRuntime::with_providers(
        base_fake_config(),
        vec![Arc::new(BodyPartCorrelationCaptureProvider {
            captured_correlation: Arc::clone(&captured_correlation),
            captured_action: Arc::clone(&captured_action),
        })],
    )
    .unwrap();

    let prepared = runtime
        .begin_invoke(
            governed(OperationContext {
                agent_request_id: "agent-body-preflight-id".to_string(),
                broker_request_id: "broker-body-preflight-id".to_string(),
                identity: IdentityContext::anonymous(),
                service: "fake".to_string(),
                action: "echo".to_string(),
                source: SourceContext::unknown(),
            }),
            InvokeRequest {
                inputs: json!({
                    "project": "TEST",
                    "message": "upload",
                }),
                body_parts: vec![],
                ..InvokeRequest::new(json!({}))
            },
        )
        .await
        .expect("invoke preparation succeeds");
    let prepared = runtime
        .authorize_body_parts(prepared)
        .await
        .expect("body authorization succeeds");

    assert_eq!(prepared.body_part_specs().len(), 1);
    assert_eq!(
        *captured_correlation.lock().unwrap(),
        Some(CorrelationContext::new(
            "agent-body-preflight-id".to_string(),
            "broker-body-preflight-id".to_string()
        ))
    );
    assert_eq!(
        *captured_action.lock().unwrap(),
        Some(("fake".to_string(), "echo".to_string()))
    );
}

#[test]
fn injected_fake_provider_requires_explicit_opt_in() {
    let mut config = base_fake_config();
    config.deployment.enable_fake_service = false;
    config.providers.remove("fake");
    config.credentials.service.clear();
    config.policy.grants.clear();
    let spool_dir = temp_path("disabled-injected-fake-spool");
    config.limits.upload_spool_dir = spool_dir.display().to_string();

    let error =
        match BrokerRuntime::with_providers(config, vec![Arc::new(MissingStreamHandleProvider)]) {
            Ok(_) => panic!("expected injected fake provider without opt-in to fail startup"),
            Err(error) => error,
        };
    let RuntimeError::Config(error) = error else {
        panic!("expected config error for injected fake provider without opt-in");
    };

    assert!(error.errors().iter().any(|item| {
        item == "deployment.enable_fake_service must be true before registering injected fake provider"
    }));
    assert!(!spool_dir.exists());
}

#[tokio::test]
async fn required_stream_rejects_missing_provider_stream_before_allowed_audit() {
    let audit_path = temp_path("missing-stream.audit.jsonl");
    let mut config = base_fake_config();
    config.audit = Some(jsonl_audit_config(audit_path.display().to_string()));
    let runtime =
        BrokerRuntime::with_providers(config, vec![Arc::new(MissingStreamHandleProvider)]).unwrap();

    let response = runtime
        .invoke_required_stream(
            governed(OperationContext {
                agent_request_id: "agent-request".to_string(),
                broker_request_id: "broker-request".to_string(),
                identity: IdentityContext::anonymous(),
                service: "fake".to_string(),
                action: "echo".to_string(),
                source: SourceContext::unknown(),
            }),
            InvokeRequest {
                inputs: json!({
                    "project": "TEST",
                    "message": "download",
                }),
                body_parts: vec![],
                ..InvokeRequest::new(json!({}))
            },
        )
        .await;

    assert_eq!(
        response.status,
        ReasonCode::UpstreamProtocolFailed.http_status()
    );
    assert_eq!(response.envelope.decision, Decision::Error);
    assert_eq!(
        response.envelope.reason_code,
        Some(ReasonCode::UpstreamProtocolFailed.into())
    );
    assert!(response.stream.is_none());
    let audit = fs::read_to_string(audit_path).unwrap();
    assert!(audit.contains("\"decision\":\"error\""));
    assert!(audit.contains("\"reasonCode\":\"upstream_protocol_failed\""));
}

#[tokio::test]
async fn required_stream_appends_terminal_failure_audit() {
    let audit_path = temp_path("stream-terminal-failure.audit.jsonl");
    let mut config = base_fake_config();
    config.audit = Some(jsonl_audit_config(audit_path.display().to_string()));
    let runtime =
        BrokerRuntime::with_providers(config, vec![Arc::new(FailingStreamProvider)]).unwrap();

    let mut response = runtime
        .invoke_required_stream(
            governed(OperationContext {
                agent_request_id: "agent-request".to_string(),
                broker_request_id: "broker-request".to_string(),
                identity: IdentityContext::anonymous(),
                service: "fake".to_string(),
                action: "echo".to_string(),
                source: SourceContext::unknown(),
            }),
            InvokeRequest {
                inputs: json!({
                    "project": "TEST",
                    "message": "download",
                }),
                body_parts: vec![],
                ..InvokeRequest::new(json!({}))
            },
        )
        .await;

    assert_eq!(response.status, 200);
    let stream = response.stream.take().unwrap();
    let ProviderResultStreamSource::Stream(stream) = stream.source else {
        panic!("expected stream source");
    };
    let mut stream = stream.lock().unwrap().take().unwrap();
    assert_eq!(
        stream.next().await.unwrap().unwrap(),
        Bytes::from_static(b"prefix")
    );
    let error = stream.next().await.unwrap().unwrap_err();
    assert_eq!(error.reason_code, ReasonCode::UpstreamProtocolFailed);
    drop(stream);
    runtime
        .shutdown_audit(Duration::from_secs(1))
        .await
        .unwrap();

    let audit = fs::read_to_string(&audit_path).unwrap();
    assert!(audit.contains("\"streamPhase\":\"started\""));
    assert!(audit.contains("\"streamPhase\":\"failed\""));
    assert!(audit.contains("\"streamBytes\":6"));
    assert!(audit.contains("\"streamDurationMs\""));
    assert!(audit.contains("\"streamMessage\":\"provider stream failed\""));
    assert!(audit.contains("\"reasonCode\":\"upstream_protocol_failed\""));
    let records = audit_records(&audit_path);
    let phases = stream_phase_counts(&records);
    assert_eq!(phases.get("started"), Some(&1));
    assert_eq!(phases.get("failed"), Some(&1));
}

#[tokio::test]
async fn required_stream_appends_exactly_one_completed_terminal_audit() {
    let audit_path = temp_path("stream-terminal-completed.audit.jsonl");
    let mut config = base_fake_config();
    config.audit = Some(jsonl_audit_config(audit_path.display().to_string()));
    let runtime =
        BrokerRuntime::with_providers(config, vec![Arc::new(CompletedStreamProvider)]).unwrap();

    let mut response = invoke_test_stream(&runtime).await;

    assert_eq!(response.status, 200);
    let stream = response.stream.take().unwrap();
    let ProviderResultStreamSource::Stream(stream) = stream.source else {
        panic!("expected stream source");
    };
    let mut stream = stream.lock().unwrap().take().unwrap();
    assert_eq!(
        stream.next().await.unwrap().unwrap(),
        Bytes::from_static(b"prefix")
    );
    assert_eq!(
        stream.next().await.unwrap().unwrap(),
        Bytes::from_static(b"-suffix")
    );
    assert!(stream.next().await.is_none());
    drop(stream);
    runtime
        .shutdown_audit(Duration::from_secs(1))
        .await
        .unwrap();

    let records = audit_records(&audit_path);
    let phases = stream_phase_counts(&records);
    assert_eq!(phases.get("started"), Some(&1));
    assert_eq!(phases.get("completed"), Some(&1));
    assert_eq!(phases.values().sum::<usize>(), 2);
    let completed = records
        .iter()
        .find(|record| record["providerAudit"]["streamPhase"] == "completed")
        .unwrap();
    assert_eq!(completed["providerAudit"]["streamBytes"], json!(13));
    let started = records
        .iter()
        .find(|record| record["providerAudit"]["streamPhase"] == "started")
        .unwrap();
    assert_eq!(started["brokerRequestId"], completed["brokerRequestId"]);
    assert_ne!(started["auditId"], completed["auditId"]);
}

#[tokio::test]
async fn required_stream_drop_appends_exactly_one_canceled_terminal_audit() {
    let audit_path = temp_path("stream-terminal-canceled.audit.jsonl");
    let mut config = base_fake_config();
    config.audit = Some(jsonl_audit_config(audit_path.display().to_string()));
    let runtime =
        BrokerRuntime::with_providers(config, vec![Arc::new(PendingStreamProvider)]).unwrap();

    let mut response = invoke_test_stream(&runtime).await;

    assert_eq!(response.status, 200);
    let stream = response.stream.take().unwrap();
    let ProviderResultStreamSource::Stream(stream) = stream.source else {
        panic!("expected stream source");
    };
    let mut stream = stream.lock().unwrap().take().unwrap();
    assert_eq!(
        stream.next().await.unwrap().unwrap(),
        Bytes::from_static(b"prefix")
    );
    let started = Instant::now();
    drop(stream);
    assert!(started.elapsed() < Duration::from_millis(50));
    runtime
        .shutdown_audit(Duration::from_secs(1))
        .await
        .unwrap();

    let records = audit_records(&audit_path);
    let phases = stream_phase_counts(&records);
    assert_eq!(phases.get("started"), Some(&1));
    assert_eq!(phases.get("canceled"), Some(&1));
    assert_eq!(phases.values().sum::<usize>(), 2);
}

#[tokio::test]
async fn cancel_terminal_audits_enqueues_one_canceled_record_before_drain() {
    let audit_path = temp_path("stream-terminal-shutdown-canceled.audit.jsonl");
    let mut config = base_fake_config();
    config.audit = Some(jsonl_audit_config(audit_path.display().to_string()));
    let runtime =
        BrokerRuntime::with_providers(config, vec![Arc::new(PendingStreamProvider)]).unwrap();

    let mut response = invoke_test_stream(&runtime).await;

    assert_eq!(response.status, 200);
    let stream = response.stream.take().unwrap();
    let ProviderResultStreamSource::Stream(stream) = stream.source else {
        panic!("expected stream source");
    };
    let mut stream = stream.lock().unwrap().take().unwrap();
    assert_eq!(
        stream.next().await.unwrap().unwrap(),
        Bytes::from_static(b"prefix")
    );
    assert_eq!(runtime.cancel_terminal_audits(), 1);
    assert_eq!(runtime.cancel_terminal_audits(), 0);
    drop(stream);
    runtime
        .shutdown_audit(Duration::from_secs(1))
        .await
        .unwrap();

    let records = audit_records(&audit_path);
    let phases = stream_phase_counts(&records);
    assert_eq!(phases.get("started"), Some(&1));
    assert_eq!(phases.get("canceled"), Some(&1));
    assert_eq!(phases.values().sum::<usize>(), 2);
}

#[tokio::test]
async fn memory_stream_expected_size_mismatch_fails_before_bytes() {
    let stream = ProviderResultStream::from_bytes("text/plain", b"known-bad".to_vec())
        .with_expected_size(4, "download size did not match metadata");
    let ProviderResultStreamSource::Stream(stream) = stream.source else {
        panic!("expected size mismatch to become an error stream");
    };
    let mut stream = stream.lock().unwrap().take().unwrap();
    let error = stream.next().await.unwrap().unwrap_err();
    assert_eq!(error.reason_code, ReasonCode::UpstreamProtocolFailed);
    assert_eq!(error.message, "download size did not match metadata");
    assert!(stream.next().await.is_none());
}

#[tokio::test]
async fn required_static_identity_selects_policy_and_credentials() {
    let token_path = write_temp_secret("agent-access-token");
    let audit_path = temp_path("required-static-audit.jsonl");
    let mut config = base_fake_config();
    config.identity = static_identity_config(
        "required",
        &token_path,
        "agent-one",
        vec!["agents".to_string()],
    );
    config.audit = Some(jsonl_audit_config(audit_path.display().to_string()));
    config.policy.grants[0].subjects = vec!["group:agents".to_string()];

    let runtime = BrokerRuntime::new(config).unwrap();
    let mut headers = HeaderMap::new();
    headers.insert(
        "X-Agent-Access-Identity-Token",
        "agent-access-token".parse().unwrap(),
    );
    let identity = runtime.resolve_identity(&headers).unwrap();

    let response = runtime
        .invoke(
            governed(OperationContext {
                agent_request_id: "agent-request".to_string(),
                broker_request_id: "broker-request".to_string(),
                identity,
                service: "fake".to_string(),
                action: "echo".to_string(),
                source: SourceContext::unknown(),
            }),
            InvokeRequest {
                inputs: json!({"project": "TEST", "message": "hello"}),
                body_parts: vec![],
                ..InvokeRequest::new(json!({}))
            },
        )
        .await;

    assert_eq!(response.status, 200);
    assert_eq!(
        response.envelope.result.unwrap()["credentialMode"],
        json!("service")
    );
    let audit = fs::read_to_string(audit_path).unwrap();
    assert!(audit.contains("\"credentialMode\":\"service\""));
    assert!(audit.contains("\"principal\":\"agent-one\""));
    assert!(audit.contains("\"principalSubject\":\"agent-one\""));
    assert!(audit.contains("\"groups\":[\"agents\"]"));
    assert!(audit.contains(
        "\"identitySource\":{\"name\":\"local\",\"type\":\"static_principals\",\"tokenHeader\":\"X-Agent-Access-Identity-Token\",\"tokenScheme\":\"raw\"}"
    ));
    assert!(!audit.contains("agent-access-token"));
    assert!(!audit.contains("hello"));
}

#[tokio::test]
async fn registered_principal_invocation_admission_maps_missing_principal_to_required() {
    let token_path = write_temp_secret("agent-access-token");
    let store_path = temp_path("registered-principal-missing.sqlite");
    let mut config = base_fake_config();
    config.identity = static_identity_config(
        "required",
        &token_path,
        "agent-one",
        vec!["agents".to_string()],
    );
    config.policy.grants[0].subjects = vec!["group:agents".to_string()];
    config.managed_store = Some(ManagedStoreConfig {
        kind: "sqlite".to_string(),
        path: store_path.display().to_string(),
        require_registered_principal_for_invocation: true,
        auto_migrate: true,
    });

    let runtime = BrokerRuntime::new(config).unwrap();
    let mut headers = HeaderMap::new();
    headers.insert(
        "X-Agent-Access-Identity-Token",
        "agent-access-token".parse().unwrap(),
    );
    let identity = runtime.resolve_identity(&headers).unwrap();

    let response = runtime
        .invoke(
            governed(OperationContext {
                agent_request_id: "agent-request".to_string(),
                broker_request_id: "broker-request".to_string(),
                identity,
                service: "fake".to_string(),
                action: "echo".to_string(),
                source: SourceContext::unknown(),
            }),
            InvokeRequest {
                inputs: json!({"project": "TEST", "message": "hello"}),
                body_parts: vec![],
                ..InvokeRequest::new(json!({}))
            },
        )
        .await;

    assert_eq!(response.status, ReasonCode::PrincipalRequired.http_status());
    assert_eq!(response.envelope.decision, Decision::Deny);
    assert_eq!(
        response.envelope.reason_code,
        Some(ReasonCode::PrincipalRequired.into())
    );
}

#[test]
fn required_identity_rejects_missing_token() {
    let token_path = write_temp_secret("agent-access-token");
    let mut config = base_fake_config();
    config.identity = static_identity_config(
        "required",
        &token_path,
        "agent-one",
        vec!["agents".to_string()],
    );
    let runtime = BrokerRuntime::new(config).unwrap();
    assert_eq!(
        runtime.resolve_identity(&HeaderMap::new()).unwrap_err(),
        IdentityFailure::Required
    );
}

fn install_test_callers(runtime: &mut BrokerRuntime, fixed: bool, forwarding: bool) {
    let path = write_temp_secret("caller-shared-credential");
    let mut config = (*runtime.config).clone();
    config.identity.trusted_callers.insert(
        "dispatch".into(),
        crate::TrustedCallerConfig {
            credential_transport: crate::TrustedCallerCredentialTransport::CallerAuthorization,
            username_namespace: None,
            credential_ref: format!("file:{}", path.display()),
            context_mode: if fixed {
                crate::TrustedCallerContextMode::Fixed
            } else {
                crate::TrustedCallerContextMode::Asserted
            },
            execution_context: fixed.then(|| "internal".into()),
            allowed_execution_contexts: (!fixed)
                .then(|| vec!["external".into(), "internal".into()]),
            allow_forwarded_identity: forwarding,
        },
    );
    config.execution_context = Some(crate::ExecutionContextConfig {
        allowed_values: vec![
            "default".into(),
            "external".into(),
            "internal".into(),
            "personal".into(),
        ],
        default_context: Some("default".into()),
    });
    runtime.trusted_callers = load_trusted_callers(&config).unwrap();
    runtime.config = Arc::new(config);
    fs::remove_file(path).unwrap();
}

#[test]
fn trusted_callers_validate_all_assertions_without_authenticating_principals() {
    let mut runtime = BrokerRuntime::new(base_fake_config()).unwrap();
    install_test_callers(&mut runtime, false, false);
    let caller = CALLER_AUTHORIZATION_HEADER;
    let fingerprint = "x-aw-identity-token-sha256";
    let context = crate::EXECUTION_CONTEXT_HEADER;
    let valid = "Bearer caller-shared-credential";
    let cases = [
        (vec![], Ok(())),
        (vec![("authorization", "Bearer token")], Ok(())),
        (
            vec![(context, "external")],
            Err(IdentityFailure::CallerAuthenticationRequired),
        ),
        (
            vec![(fingerprint, "invalid")],
            Err(IdentityFailure::CallerAuthenticationRequired),
        ),
        (vec![(caller, valid)], Ok(())),
        (vec![(caller, valid), (context, "external")], Ok(())),
        (
            vec![(caller, valid), (context, "personal")],
            Err(IdentityFailure::ExecutionContextDenied),
        ),
        (
            vec![(caller, valid), (context, "")],
            Err(IdentityFailure::ExecutionContextInvalid),
        ),
        (
            vec![
                (caller, valid),
                (context, "external"),
                (context, "external"),
            ],
            Err(IdentityFailure::ExecutionContextInvalid),
        ),
        (
            vec![(caller, valid), (fingerprint, "invalid")],
            Err(IdentityFailure::CallerIdentityForwardingDenied),
        ),
        (
            vec![(caller, "Bearer wrong")],
            Err(IdentityFailure::CallerAuthenticationInvalid),
        ),
        (
            vec![(caller, valid), (caller, valid)],
            Err(IdentityFailure::CallerAuthenticationInvalid),
        ),
        (
            vec![(caller, "Basic caller-shared-credential")],
            Err(IdentityFailure::CallerAuthenticationInvalid),
        ),
    ];
    for (entries, expected) in cases {
        let mut headers = HeaderMap::new();
        for (name, value) in entries {
            headers.append(
                http::header::HeaderName::from_bytes(name.as_bytes()).unwrap(),
                value.parse().unwrap(),
            );
        }
        assert_eq!(runtime.admit_ingress(&headers).map(|_| ()), expected);
    }
    let mut headers = HeaderMap::new();
    headers.insert(caller, valid.parse().unwrap());
    assert_eq!(
        runtime.admit_ingress(&headers).unwrap().execution_context(),
        Err(ExecutionContextFailure::Required)
    );
    install_test_callers(&mut runtime, true, false);
    assert_eq!(
        runtime
            .admit_ingress(&headers)
            .unwrap()
            .execution_context()
            .unwrap()
            .as_str(),
        "internal"
    );
    headers.insert(context, "internal".parse().unwrap());
    assert_eq!(
        runtime.admit_ingress(&headers).map(|_| ()),
        Err(IdentityFailure::ExecutionContextInvalid)
    );
    runtime.trusted_callers = Arc::new(vec![]);
    headers.remove(caller);
    assert_eq!(
        runtime.admit_ingress(&headers).map(|_| ()),
        Err(IdentityFailure::CallerAuthenticationRequired)
    );
}

#[test]
fn caller_attestation_does_not_replace_ordinary_user_authentication() {
    let token_path = write_temp_secret("normal-broker-token");
    let mut config = base_fake_config();
    config.identity = static_identity_config("required", &token_path, "direct-user", vec![]);
    config.identity.sources[0].header = "Authorization".into();
    config.identity.sources[0].scheme = "Bearer".into();
    let mut runtime = BrokerRuntime::new(config).unwrap();
    install_test_callers(&mut runtime, false, true);
    let mut headers = HeaderMap::new();
    assert_eq!(
        runtime.resolve_identity(&headers).unwrap_err(),
        IdentityFailure::Required
    );
    headers.insert(
        "x-agent-access-caller-authorization",
        "Bearer caller-shared-credential".parse().unwrap(),
    );
    assert_eq!(
        runtime.resolve_identity(&headers).unwrap_err(),
        IdentityFailure::Required
    );
    headers.remove("x-agent-access-caller-authorization");
    headers.insert(
        "authorization",
        "Bearer normal-broker-token".parse().unwrap(),
    );
    assert_eq!(
        runtime.resolve_identity(&headers).unwrap().principal,
        "direct-user"
    );
    headers.insert(crate::EXECUTION_CONTEXT_HEADER, "internal".parse().unwrap());
    assert_eq!(
        runtime.resolve_identity(&headers).unwrap_err(),
        IdentityFailure::CallerAuthenticationRequired
    );
    headers.insert(
        "x-agent-access-caller-authorization",
        "Bearer caller-shared-credential".parse().unwrap(),
    );
    // An explicit ordinary token stays authoritative; forwarded inventory is not consulted.
    headers.insert(
        "x-aw-identity-token-sha256",
        "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            .parse()
            .unwrap(),
    );
    assert_eq!(
        runtime.resolve_identity(&headers).unwrap().principal,
        "direct-user"
    );
    headers.insert("authorization", "Bearer wrong-token".parse().unwrap());
    assert_eq!(
        runtime.resolve_identity(&headers).unwrap_err(),
        IdentityFailure::Invalid
    );
}

#[test]
fn paused_broker_token_identity_failure_has_specific_public_contract() {
    let failure = IdentityFailure::BrokerTokenPaused;
    assert_eq!(failure.reason_code(), ReasonCode::BrokerTokenPaused);
    assert_eq!(failure.reason_code().http_status(), 401);
    assert_eq!(failure.message(), "broker token is paused");
}

#[test]
fn bearer_static_identity_matches_authorization_scheme() {
    let token_path = write_temp_secret("bearer-token");
    let mut config = base_fake_config();
    config.identity = IdentityConfig {
        trusted_callers: BTreeMap::new(),
        mode: "required".to_string(),
        authority: "toml".to_string(),
        sources: vec![IdentitySourceConfig {
            name: "local".to_string(),
            kind: "static_principals".to_string(),
            header: "Authorization".to_string(),
            scheme: "Bearer".to_string(),
            principals: vec![StaticPrincipalConfig {
                principal: "agent-one".to_string(),
                token_refs: vec![format!("file:{}", token_path.display())],
            }],
        }],
        groups: vec![identity_group("agents", vec!["agent-one".to_string()])],
    };
    let runtime = BrokerRuntime::new(config).unwrap();
    let mut headers = HeaderMap::new();
    headers.insert("Authorization", "Bearer bearer-token".parse().unwrap());
    let identity = runtime.resolve_identity(&headers).unwrap();
    assert_eq!(identity.principal, "agent-one");

    let mut invalid_headers = HeaderMap::new();
    invalid_headers.insert("Authorization", "bearer-token".parse().unwrap());
    assert_eq!(
        runtime.resolve_identity(&invalid_headers).unwrap_err(),
        IdentityFailure::Invalid
    );
}

#[test]
fn optional_static_identity_falls_back_to_anonymous_and_rejects_bad_token() {
    let token_path = write_temp_secret("agent-access-token");
    let mut config = base_fake_config();
    config.identity = static_identity_config(
        "optional",
        &token_path,
        "agent-one",
        vec!["agents".to_string()],
    );
    let runtime = BrokerRuntime::new(config).unwrap();

    let anonymous = runtime.resolve_identity(&HeaderMap::new()).unwrap();
    assert_eq!(anonymous.principal, "anonymous");
    assert_eq!(anonymous.groups, vec!["anonymous"]);
    assert!(!anonymous.authenticated);

    let mut headers = HeaderMap::new();
    headers.insert("Authorization", "Bearer unrelated".parse().unwrap());
    let anonymous = runtime.resolve_identity(&headers).unwrap();
    assert_eq!(anonymous.principal, "anonymous");
    assert!(!anonymous.authenticated);

    headers.insert(
        "X-Agent-Access-Identity-Token",
        "wrong-token".parse().unwrap(),
    );
    assert_eq!(
        runtime.resolve_identity(&headers).unwrap_err(),
        IdentityFailure::Invalid
    );
}

#[test]
fn anonymous_identity_without_sources_ignores_unrelated_authorization() {
    let mut config = base_fake_config();
    config.identity.mode = "anonymous".to_string();
    config.identity.sources.clear();
    let runtime = BrokerRuntime::new(config).unwrap();
    let mut headers = HeaderMap::new();
    headers.insert("Authorization", "Bearer unrelated".parse().unwrap());
    assert!(!runtime.resolve_identity(&headers).unwrap().authenticated);
}

#[test]
fn malformed_earlier_identity_header_is_terminal_before_later_source() {
    let first_token = write_temp_secret("first-token");
    let second_token = write_temp_secret("second-token");
    let mut config = base_fake_config();
    config.identity = IdentityConfig {
        trusted_callers: BTreeMap::new(),
        mode: "required".to_string(),
        authority: "toml".to_string(),
        sources: vec![
            IdentitySourceConfig {
                name: "first".to_string(),
                kind: "static_principals".to_string(),
                header: "X-First-Identity".to_string(),
                scheme: "Bearer".to_string(),
                principals: vec![StaticPrincipalConfig {
                    principal: "first-agent".to_string(),
                    token_refs: vec![format!("file:{}", first_token.display())],
                }],
            },
            IdentitySourceConfig {
                name: "second".to_string(),
                kind: "static_principals".to_string(),
                header: "Authorization".to_string(),
                scheme: "Bearer".to_string(),
                principals: vec![StaticPrincipalConfig {
                    principal: "second-agent".to_string(),
                    token_refs: vec![format!("file:{}", second_token.display())],
                }],
            },
        ],
        groups: vec![],
    };
    let runtime = BrokerRuntime::new(config).unwrap();
    let mut headers = HeaderMap::new();
    headers.insert("X-First-Identity", "not-a-bearer-token".parse().unwrap());
    headers.insert("Authorization", "Bearer second-token".parse().unwrap());

    assert_eq!(
        runtime.resolve_identity(&headers).unwrap_err(),
        IdentityFailure::Invalid
    );
}

#[test]
fn static_principals_source_resolves_multiple_tokens_on_one_bearer_header() {
    let alice_token = write_temp_secret("alice-token");
    let admin_token = write_temp_secret("admin-token");
    let mut config = base_fake_config();
    config.identity = IdentityConfig {
        trusted_callers: BTreeMap::new(),
        mode: "required".to_string(),
        authority: "toml".to_string(),
        sources: vec![IdentitySourceConfig {
            name: "local".to_string(),
            kind: "static_principals".to_string(),
            header: "Authorization".to_string(),
            scheme: "Bearer".to_string(),
            principals: vec![
                StaticPrincipalConfig {
                    principal: "alice".to_string(),
                    token_refs: vec![format!("file:{}", alice_token.display())],
                },
                StaticPrincipalConfig {
                    principal: "demo-admin".to_string(),
                    token_refs: vec![format!("file:{}", admin_token.display())],
                },
            ],
        }],
        groups: vec![
            identity_group(
                "agent-users",
                vec!["alice".to_string(), "demo-admin".to_string()],
            ),
            identity_group("broker-admins", vec!["demo-admin".to_string()]),
        ],
    };
    let runtime = BrokerRuntime::new(config).unwrap();

    let mut alice_headers = HeaderMap::new();
    alice_headers.insert("Authorization", "Bearer alice-token".parse().unwrap());
    let alice = runtime.resolve_identity(&alice_headers).unwrap();
    assert_eq!(alice.principal, "alice");
    assert_eq!(alice.principal_subject.as_deref(), Some("alice"));
    assert_eq!(alice.groups, vec!["agent-users"]);
    assert_eq!(alice.source.as_ref().unwrap().name, "local");

    let mut admin_headers = HeaderMap::new();
    admin_headers.insert("Authorization", "Bearer admin-token".parse().unwrap());
    let admin = runtime.resolve_identity(&admin_headers).unwrap();
    assert_eq!(admin.principal, "demo-admin");
    assert_eq!(admin.groups, vec!["agent-users", "broker-admins"]);
}

#[test]
fn static_principals_source_accepts_multiple_token_refs_for_rotation() {
    let current_token = write_temp_secret("current-token");
    let previous_token = write_temp_secret("previous-token");
    let mut config = base_fake_config();
    config.identity = IdentityConfig {
        trusted_callers: BTreeMap::new(),
        mode: "required".to_string(),
        authority: "toml".to_string(),
        sources: vec![IdentitySourceConfig {
            name: "local".to_string(),
            kind: "static_principals".to_string(),
            header: "Authorization".to_string(),
            scheme: "Bearer".to_string(),
            principals: vec![StaticPrincipalConfig {
                principal: "alice".to_string(),
                token_refs: vec![
                    format!("file:{}", current_token.display()),
                    format!("file:{}", previous_token.display()),
                ],
            }],
        }],
        groups: vec![],
    };
    let runtime = BrokerRuntime::new(config).unwrap();

    for token in ["current-token", "previous-token"] {
        let mut headers = HeaderMap::new();
        headers.insert("Authorization", format!("Bearer {token}").parse().unwrap());
        let identity = runtime.resolve_identity(&headers).unwrap();
        assert_eq!(identity.principal, "alice");
    }
}

#[tokio::test]
async fn readiness_accepts_oauth_without_upstream_or_connected_users() {
    let mut config = microsoft_oidc_runtime_broker_config();
    config.browser_auth.oidc.microsoft = Default::default();
    config.credentials = Default::default();
    config.policy.grants.clear();
    let secret_path = write_temp_secret("oauth-readiness-client-secret");
    config.oauth.registrations.insert(
        "stub".into(),
        agent_access_provider::OAuthRegistrationConfig {
            adapter_settings: Default::default(),
            adapter: agent_access_provider::OAuthAdapter::new("stub"),
            base_url: "https://unreachable.example.test".into(),
            redirect_uri: "https://broker.example.test/v1/oauth/callback/stub".into(),
            client_id: "readiness-test".into(),
            client_secret_ref: format!("file:{}", secret_path.display()),
            client_auth: Default::default(),
            encoding: Default::default(),
            rotation: Default::default(),
            allow_insecure_loopback: false,
            permission_profiles: BTreeMap::from([(
                "read".into(),
                agent_access_provider::OAuthPermissionProfile {
                    scope_mode: agent_access_provider::OAuthScopeMode::Explicit,
                    scopes: Some(vec!["records.read".into(), "offline_access".into()]),
                    audience: "records-api".into(),
                    target: "workspace-one".into(),
                },
            )]),
        },
    );
    let credential = CredentialConfig {
        kind: "oauth".into(),
        provider: Some("stub".into()),
        profile: Some("read".into()),
        username_ref: None,
        token_ref: None,
        path: None,
        read_only: None,
        credential_name: None,
    };
    config
        .credentials
        .per_user
        .insert("oauth_stub".into(), credential.clone());
    config
        .providers
        .insert(agent_access_fake::OAuthStubProviderConfig {
            base_url: "http://127.0.0.1:9".into(),
        });
    let runtime = BrokerRuntime::new(config.clone()).unwrap();
    runtime.readiness().await.unwrap();
    assert!(
        check_credential_ready(
            "test",
            "oauth_stub",
            "service",
            &credential,
            true,
            &config.oauth
        )
        .is_err()
    );
    let mut missing_profile = credential.clone();
    missing_profile.profile = Some("missing".into());
    assert!(
        check_credential_ready(
            "test",
            "oauth_stub",
            "per_user",
            &missing_profile,
            true,
            &config.oauth
        )
        .is_err()
    );
    config.oauth.registrations.clear();
    assert!(
        check_credential_ready(
            "test",
            "oauth_stub",
            "per_user",
            &credential,
            true,
            &config.oauth
        )
        .is_err()
    );
}

#[test]
fn oauth_registrations_resolve_their_dialect_and_its_rules() {
    let mut config = microsoft_oidc_runtime_broker_config();
    config.browser_auth.oidc.microsoft = Default::default();
    config.credentials = Default::default();
    config.policy.grants.clear();
    let secret_path = write_temp_secret("oauth-dialect-client-secret");
    let registration = agent_access_provider::OAuthRegistrationConfig {
        adapter_settings: Default::default(),
        adapter: agent_access_provider::OAuthAdapter::new("stub"),
        base_url: "https://stub.example.test".into(),
        redirect_uri: "https://broker.example.test/v1/oauth/callback/stub".into(),
        client_id: "dialect-test".into(),
        client_secret_ref: format!("file:{}", secret_path.display()),
        client_auth: Default::default(),
        encoding: Default::default(),
        rotation: Default::default(),
        allow_insecure_loopback: false,
        permission_profiles: BTreeMap::from([(
            "read".into(),
            agent_access_provider::OAuthPermissionProfile {
                scope_mode: agent_access_provider::OAuthScopeMode::Explicit,
                scopes: Some(vec!["records.read".into(), "offline_access".into()]),
                audience: "records-api".into(),
                target: "workspace-one".into(),
            },
        )]),
    };
    config
        .oauth
        .registrations
        .insert("stub".into(), registration.clone());
    validate_broker_config(&config).unwrap();
    let errors = |config: &BrokerConfig| match validate_broker_config(config) {
        Err(ConfigError::Invalid { errors }) => errors.join("\n"),
        other => panic!("expected invalid config, got {other:?}"),
    };

    let mut unknown = config.clone();
    unknown.oauth.registrations.get_mut("stub").unwrap().adapter =
        agent_access_provider::OAuthAdapter::new("outlook");
    assert!(errors(&unknown).contains(
        "oauth.registrations.stub.adapter `outlook` is not a registered OAuth dialect (expected one of: stub)"
    ));

    let mut nested = config.clone();
    nested.oauth.registrations.get_mut("stub").unwrap().base_url =
        "https://stub.example.test/tenant/".into();
    assert!(errors(&nested).contains(
        "oauth.registrations.stub is not a valid stub registration: base_url must be an origin with no path or query"
    ));

    let mut production = config.clone();
    production.deployment.enable_fake_service = false;
    assert!(errors(&production).contains(
        "oauth.registrations.stub uses the development-only stub dialect, which requires non-production deployment.enable_fake_service"
    ));

    let mut server_default = config.clone();
    let profile = server_default
        .oauth
        .registrations
        .get_mut("stub")
        .unwrap()
        .permission_profiles
        .get_mut("read")
        .unwrap();
    profile.scope_mode = agent_access_provider::OAuthScopeMode::ServerDefault;
    profile.scopes = None;
    assert!(errors(&server_default).contains("stub does not support server_default scope mode"));

    let mut mixed = config.clone();
    mixed
        .oauth
        .registrations
        .get_mut("stub")
        .unwrap()
        .permission_profiles
        .insert(
            "default".into(),
            server_default.oauth.registrations["stub"].permission_profiles["read"].clone(),
        );
    assert!(errors(&mixed).contains(
        "oauth.registrations.stub: all permission_profiles must use the same scope_mode"
    ));
}

#[tokio::test]
async fn readiness_accepts_configured_secret_store_references() {
    let token_path = write_temp_secret("per-user-token");
    let store_body = format!(
        r#"{{"credentials":[{{"principal":"agent-one","type":"bearer_token","token_ref":"file:{}"}}]}}"#,
        token_path.display()
    );
    let store_path = write_temp_secret(&store_body);
    let mut config = base_fake_config();
    config.credentials.service.clear();
    config.credentials.per_user.insert(
        "fake".to_string(),
        CredentialConfig {
            kind: "secret_store".to_string(),
            username_ref: None,
            token_ref: None,
            provider: Some("local_file".to_string()),
            path: Some(store_path.display().to_string()),
            read_only: None,
            credential_name: None,
            profile: None,
        },
    );
    config.policy.grants[0].credential_mode = "per_user".to_string();
    let runtime = BrokerRuntime::new(config).unwrap();

    runtime.readiness().await.unwrap();
}

#[tokio::test]
async fn readiness_does_not_require_all_per_user_secret_material() {
    let missing_token = temp_path("missing-per-user-token");
    let store_body = format!(
        r#"{{"credentials":[{{"principal":"agent-one","type":"bearer_token","token_ref":"file:{}"}}]}}"#,
        missing_token.display()
    );
    let store_path = write_temp_secret(&store_body);
    let mut config = base_fake_config();
    config.credentials.service.clear();
    config.credentials.per_user.insert(
        "fake".to_string(),
        fake_per_user_credential(store_path.to_str().unwrap()),
    );
    config.policy.grants[0].credential_mode = "per_user".to_string();
    let runtime = BrokerRuntime::new(config).unwrap();

    runtime.readiness().await.unwrap();
}

#[test]
fn local_file_secret_store_resolves_per_user_material() {
    let principal_token = write_temp_secret("principal-token");
    let subject_token = write_temp_secret("subject-token");
    let store_body = format!(
        r#"{{"credentials":[{{"subject":"subject-one","type":"bearer_token","token_ref":"file:{}"}},{{"principal":"agent-one","type":"bearer_token","token_ref":"file:{}"}}]}}"#,
        subject_token.display(),
        principal_token.display()
    );
    let store_path = write_temp_secret(&store_body);
    let credential = fake_per_user_credential(store_path.to_str().unwrap());
    let identity = IdentityContext {
        caller_id: None,
        principal: "agent-one".to_string(),
        principal_subject: Some("subject-one".to_string()),
        groups: vec!["agents".to_string()],
        policy_groups: vec!["agents".to_string()],
        authenticated: true,
        source: None,
    };

    let resolved =
        load_execution_credential("fake", "per_user", &credential, Some(&identity)).unwrap();

    assert_eq!(resolved.kind().as_str(), "bearer_token");
    assert_eq!(credential_username(&resolved), None);
    assert_eq!(credential_token(&resolved), "principal-token");
}

#[test]
fn local_file_secret_store_resolves_jira_basic_api_token_by_principal_and_subject() {
    let principal_username = write_temp_secret("alice@example.com");
    let principal_token = write_temp_secret("alice-token");
    let subject_username = write_temp_secret("subject@example.com");
    let subject_token = write_temp_secret("subject-token");
    let store_body = format!(
        r#"{{"credentials":[{{"subject":"subject-one","type":"basic_api_token","username_ref":"file:{}","token_ref":"file:{}"}},{{"principal":"alice@example.com","type":"basic_api_token","username_ref":"file:{}","token_ref":"file:{}"}}]}}"#,
        subject_username.display(),
        subject_token.display(),
        principal_username.display(),
        principal_token.display()
    );
    let store_path = write_temp_secret(&store_body);
    let credential = fake_per_user_credential(store_path.to_str().unwrap());

    let principal_identity = IdentityContext {
        caller_id: None,
        principal: "alice@example.com".to_string(),
        principal_subject: Some("subject-one".to_string()),
        groups: vec!["agents".to_string()],
        policy_groups: vec!["agents".to_string()],
        authenticated: true,
        source: None,
    };
    let resolved =
        load_execution_credential("jira", "per_user", &credential, Some(&principal_identity))
            .unwrap();
    assert_eq!(resolved.kind().as_str(), "basic_api_token");
    assert_eq!(credential_username(&resolved), Some("alice@example.com"));
    assert_eq!(credential_token(&resolved), "alice-token");

    let subject_identity = IdentityContext {
        caller_id: None,
        principal: "other@example.com".to_string(),
        principal_subject: Some("subject-one".to_string()),
        groups: vec!["agents".to_string()],
        policy_groups: vec!["agents".to_string()],
        authenticated: true,
        source: None,
    };
    let resolved =
        load_execution_credential("jira", "per_user", &credential, Some(&subject_identity))
            .unwrap();
    assert_eq!(resolved.kind().as_str(), "basic_api_token");
    assert_eq!(credential_username(&resolved), Some("subject@example.com"));
    assert_eq!(credential_token(&resolved), "subject-token");
}

#[test]
fn local_file_secret_store_rejects_jira_anonymous_and_invalid_records() {
    let token_path = write_temp_secret("token");
    let store_body = format!(
        r#"{{"credentials":[{{"principal":"agent-one","type":"api_key","token_ref":"file:{}"}}]}}"#,
        token_path.display()
    );
    let store_path = write_temp_secret(&store_body);
    let credential = fake_per_user_credential(store_path.to_str().unwrap());

    let anonymous_error = load_execution_credential(
        "jira",
        "per_user",
        &credential,
        Some(&IdentityContext::anonymous()),
    )
    .unwrap_err();
    assert_eq!(
        anonymous_error.reason_code(),
        ReasonCode::CredentialNotProvisioned
    );

    let identity = IdentityContext {
        caller_id: None,
        principal: "agent-one".to_string(),
        principal_subject: None,
        groups: vec!["agents".to_string()],
        policy_groups: vec!["agents".to_string()],
        authenticated: true,
        source: None,
    };
    let invalid_error =
        load_execution_credential("jira", "per_user", &credential, Some(&identity)).unwrap_err();
    assert_eq!(invalid_error.reason_code(), ReasonCode::CredentialInvalid);
}

#[test]
fn empty_static_token_secret_fails_closed_at_startup() {
    let token_path = write_temp_secret(" \n");
    let mut config = base_fake_config();
    config.identity = static_identity_config(
        "required",
        &token_path,
        "agent-one",
        vec!["agents".to_string()],
    );

    let error = match BrokerRuntime::new(config) {
        Ok(_) => panic!("expected empty static token secret to fail startup"),
        Err(error) => error,
    };
    let RuntimeError::Config(error) = error else {
        panic!("expected config error for empty static token secret");
    };
    assert!(error.errors().iter().any(|item| {
        item == "identity.sources.local.principals.agent-one.token_refs must resolve to non-empty secrets"
    }));
}

#[test]
fn duplicate_resolved_static_tokens_fail_startup_without_leaking_secret_material() {
    let token_a = write_temp_secret("shared-token");
    let token_b = write_temp_secret("shared-token");
    let mut same_principal_config = base_fake_config();
    same_principal_config.identity = IdentityConfig {
        trusted_callers: BTreeMap::new(),
        mode: "required".to_string(),
        authority: "toml".to_string(),
        sources: vec![IdentitySourceConfig {
            name: "local".to_string(),
            kind: "static_principals".to_string(),
            header: "Authorization".to_string(),
            scheme: "Bearer".to_string(),
            principals: vec![StaticPrincipalConfig {
                principal: "alice".to_string(),
                token_refs: vec![
                    format!("file:{}", token_a.display()),
                    format!("file:{}", token_b.display()),
                ],
            }],
        }],
        groups: vec![],
    };

    let error = duplicate_static_token_error(same_principal_config);
    assert!(error.contains("duplicate resolved token value"));
    assert!(!error.contains("shared-token"));
    assert!(!error.contains(token_a.to_str().unwrap()));
    assert!(!error.contains(token_b.to_str().unwrap()));

    let token_c = write_temp_secret("same-across-sources");
    let token_d = write_temp_secret("same-across-sources");
    let mut cross_source_config = base_fake_config();
    cross_source_config.identity = IdentityConfig {
        trusted_callers: BTreeMap::new(),
        mode: "required".to_string(),
        authority: "toml".to_string(),
        sources: vec![
            static_bearer_source_config(
                "local-a",
                "alice",
                vec![format!("file:{}", token_c.display())],
            ),
            static_bearer_source_config(
                "local-b",
                "bob",
                vec![format!("file:{}", token_d.display())],
            ),
        ],
        groups: vec![],
    };

    let error = duplicate_static_token_error(cross_source_config);
    assert!(error.contains("duplicate resolved token value"));
    assert!(!error.contains("same-across-sources"));
    assert!(!error.contains(token_c.to_str().unwrap()));
    assert!(!error.contains(token_d.to_str().unwrap()));
}

#[test]
fn principal_group_identity_uses_toml_groups_for_toml_authority() {
    let token_path = write_temp_secret("alice-token");
    let mut disabled_group = identity_group("disabled", vec!["alice".to_string()]);
    disabled_group.status = "disabled".to_string();

    let mut config = base_fake_config();
    config.identity = IdentityConfig {
        trusted_callers: BTreeMap::new(),
        mode: "required".to_string(),
        authority: "toml".to_string(),
        sources: vec![static_bearer_source_config(
            "local",
            "alice",
            vec![format!("file:{}", token_path.display())],
        )],
        groups: vec![
            identity_group("active", vec!["alice".to_string()]),
            disabled_group,
        ],
    };
    let runtime = BrokerRuntime::new(config).unwrap();

    let identity = runtime.identity_from_principal_groups(
        "alice".to_string(),
        Some("external-alice".to_string()),
        vec![
            "managed-only".to_string(),
            "active".to_string(),
            "active".to_string(),
        ],
        None,
        None,
    );

    assert_eq!(identity.principal, "alice");
    assert_eq!(
        identity.principal_subject.as_deref(),
        Some("external-alice")
    );
    assert_eq!(
        identity.groups,
        vec!["active".to_string(), "disabled".to_string()]
    );
    assert_eq!(identity.policy_groups, vec!["active".to_string()]);
}

#[tokio::test]
async fn identity_failure_for_operation_is_audited() {
    let audit_path = temp_path("identity-deny.audit.jsonl");
    let mut config = base_fake_config();
    config.audit = Some(jsonl_audit_config(audit_path.display().to_string()));
    let runtime = BrokerRuntime::new(config).unwrap();

    let response = runtime
        .identity_error_response_for_operation(
            GovernedIdentityFailureContext {
                agent_request_id: "agent-request".to_string(),
                broker_request_id: "broker-request".to_string(),
                service: "fake".to_string(),
                action: "echo".to_string(),
                source: SourceContext::unknown(),
                execution_context: default_execution_context(),
            },
            IdentityFailure::Required,
        )
        .await;

    assert_eq!(response.status, 401);
    assert_eq!(response.envelope.service, "broker");
    assert_eq!(response.envelope.action, "identity.authenticate");
    assert!(response.envelope.resource_scopes.is_empty());
    assert!(response.envelope.result.is_none());
    let audit = fs::read_to_string(audit_path).unwrap();
    assert!(audit.contains("\"decision\":\"deny\""));
    assert!(audit.contains("\"reasonCode\":\"identity_required\""));
    assert!(audit.contains("\"principal\":\"unknown\""));
    assert!(!audit.contains("principalSubject"));
    assert!(audit.contains("\"executionContext\":\"default\""));
}

#[test]
fn git_http_gateways_are_registered_and_visible_in_capabilities() {
    let mut config = base_fake_config();
    config.credentials.service.insert(
        "gitlab_git".to_string(),
        fake_service_credential(format!(
            "file:{}",
            write_temp_secret("synthetic-git-token").display()
        )),
    );
    config
        .gateways
        .insert("gitlab_git".to_string(), git_gateway_config());
    config.policy.grants.push(PolicyGrantConfig {
        subjects: vec!["group:anonymous".to_string()],
        service: "gitlab_git".to_string(),
        actions: vec!["repo.fetch".to_string(), "repo.push".to_string()],
        resources: resource_selection(&["repository-sip-service"]),
        execution_contexts: None,
        credential_mode: "service".to_string(),
        priority: None,
    });

    let runtime = BrokerRuntime::new(config).unwrap();
    assert!(runtime.registered_service_names().contains("gitlab_git"));
    let services =
        runtime.visible_services(&IdentityContext::anonymous(), &default_execution_context());
    let gitlab = services
        .iter()
        .find(|service| service.service == "gitlab_git")
        .expect("gateway service should be visible");
    assert_eq!(gitlab.display_name, "GitLab Git");
    assert_eq!(gitlab.surface, "gateway");
    assert_eq!(gitlab.gateway_kind.as_deref(), Some("git_http"));
    assert_eq!(gitlab.broker_hosts, vec!["git.example.test"]);
    assert_eq!(gitlab.scope_types, vec!["repository"]);
    assert_eq!(
        gitlab.resource_scopes["repository"].selectors,
        vec!["exact", "namespace", "all"]
    );
    assert_eq!(gitlab.actions.len(), 2);
    assert_eq!(gitlab.actions[0].action, "repo.fetch");
    assert!(gitlab.actions[0].read_only);
    assert_eq!(gitlab.actions[1].action, "repo.push");
    assert!(!gitlab.actions[1].read_only);
    // Verifying a Git credential reads a repository the caller names.
    assert_eq!(gitlab.credential_verification_inputs, vec!["repository"]);
    let fake = services
        .iter()
        .find(|service| service.service == "fake")
        .expect("fake service should be visible");
    assert!(fake.credential_verification_inputs.is_empty());
    let serialized = serde_json::to_value(gitlab).unwrap();
    assert_eq!(
        serialized["credentialVerificationInputs"],
        serde_json::json!(["repository"])
    );
}

#[tokio::test]
async fn git_gateway_credential_verify_uses_upload_pack_discovery() {
    use wiremock::matchers::{header, method, path, query_param};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/sip/service.git/info/refs"))
        .and(query_param("service", "git-upload-pack"))
        .and(header("authorization", "Bearer runtime-token"))
        .and(header(REQUEST_ID_HEADER, "agent-request"))
        .and(header(BROKER_REQUEST_ID_HEADER, "broker-request"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_bytes("001e# service=git-upload-pack\n0000".as_bytes())
                .insert_header(
                    "Content-Type",
                    "application/x-git-upload-pack-advertisement",
                ),
        )
        .mount(&server)
        .await;

    let identity_token_path = write_temp_secret("agent-one-token");
    let store_path = write_temp_secret(r#"{"credentials":[]}"#);
    let mut config = base_fake_config();
    config.identity =
        static_identity_config("required", &identity_token_path, "agent-one", Vec::new());
    config.credentials.per_user.insert(
        "gitlab_git".to_string(),
        fake_per_user_credential(store_path.to_str().unwrap()),
    );
    let mut gateway = git_gateway_config();
    gateway.credential_modes = vec!["per_user".to_string()];
    config.gateways.insert("gitlab_git".to_string(), gateway);
    config.policy.grants.push(PolicyGrantConfig {
        subjects: vec!["user:agent-one".to_string()],
        service: "gitlab_git".to_string(),
        actions: vec!["repo.fetch".to_string()],
        resources: resource_selection(&["repository-sip-service"]),
        execution_contexts: None,
        credential_mode: "per_user".to_string(),
        priority: None,
    });
    let runtime = BrokerRuntime::new(config).unwrap();
    let mut runtime_config = (*runtime.config).clone();
    let gateway = runtime_config.gateways.get_mut("gitlab_git").unwrap();
    gateway.upstream_base_url = server.uri();
    gateway.allowed_upstream_hosts = vec![format!("{}/**", server.uri())];
    let runtime = runtime_with_replaced_config(&runtime, runtime_config);
    let identity = runtime.identity_from_principal_groups(
        "agent-one".to_string(),
        Some("agent-one".to_string()),
        Vec::new(),
        None,
        None,
    );
    let credential = bearer_credential("runtime-token");

    let verification = runtime
        .verify_execution_credential(
            "gitlab_git",
            &credential,
            &identity,
            CredentialVerificationInput {
                repository: Some("sip/service.git".to_string()),
            },
            CorrelationContext::new("agent-request".to_string(), "broker-request".to_string()),
        )
        .await
        .unwrap()
        .unwrap();

    assert_eq!(verification.upstream_status, 200);
    assert_eq!(
        verification.audit["gateway"]["operation"],
        "credential.verify"
    );
    assert_eq!(
        verification.audit["git"]["operation"],
        "upload-pack-discovery"
    );
    assert_eq!(verification.audit["git"]["repository"], "sip/service");
    let requests = server.received_requests().await.unwrap();
    assert_eq!(requests.len(), 1);
    assert!(requests[0].body.is_empty());
}

#[tokio::test]
async fn git_gateway_credential_verify_rejects_non_git_discovery_success() {
    use wiremock::matchers::{method, path, query_param};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/sip/service.git/info/refs"))
        .and(query_param("service", "git-upload-pack"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("Content-Type", "text/html")
                .set_body_string("<html>login</html>"),
        )
        .mount(&server)
        .await;

    let identity_token_path = write_temp_secret("agent-one-token");
    let store_path = write_temp_secret(r#"{"credentials":[]}"#);
    let mut config = base_fake_config();
    config.identity =
        static_identity_config("required", &identity_token_path, "agent-one", Vec::new());
    config.credentials.per_user.insert(
        "gitlab_git".to_string(),
        fake_per_user_credential(store_path.to_str().unwrap()),
    );
    let mut gateway = git_gateway_config();
    gateway.credential_modes = vec!["per_user".to_string()];
    config.gateways.insert("gitlab_git".to_string(), gateway);
    config.policy.grants.push(PolicyGrantConfig {
        subjects: vec!["user:agent-one".to_string()],
        service: "gitlab_git".to_string(),
        actions: vec!["repo.fetch".to_string()],
        resources: resource_selection(&["repository-sip-service"]),
        execution_contexts: None,
        credential_mode: "per_user".to_string(),
        priority: None,
    });
    let runtime = BrokerRuntime::new(config).unwrap();
    let mut runtime_config = (*runtime.config).clone();
    let gateway = runtime_config.gateways.get_mut("gitlab_git").unwrap();
    gateway.upstream_base_url = server.uri();
    gateway.allowed_upstream_hosts = vec![format!("{}/**", server.uri())];
    let runtime = runtime_with_replaced_config(&runtime, runtime_config);
    let identity = runtime.identity_from_principal_groups(
        "agent-one".to_string(),
        Some("agent-one".to_string()),
        Vec::new(),
        None,
        None,
    );
    let credential = bearer_credential("runtime-token");

    let error = runtime
        .verify_execution_credential(
            "gitlab_git",
            &credential,
            &identity,
            CredentialVerificationInput {
                repository: Some("sip/service".to_string()),
            },
            CorrelationContext::for_tests(),
        )
        .await
        .unwrap_err();

    assert_eq!(error.reason_code(), ReasonCode::UpstreamProtocolFailed);
    assert_eq!(error.upstream_status, Some(200));
    let audit = error.audit.as_ref().unwrap();
    assert_eq!(audit["git"]["repository"], "sip/service");
}

#[tokio::test]
async fn git_gateway_credential_verify_reports_upstream_throttling() {
    use wiremock::matchers::{method, path, query_param};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/sip/service.git/info/refs"))
        .and(query_param("service", "git-upload-pack"))
        .respond_with(
            ResponseTemplate::new(429)
                .insert_header("Retry-After", "120")
                .set_body_string("secret throttle detail"),
        )
        .mount(&server)
        .await;

    let identity_token_path = write_temp_secret("agent-one-token");
    let store_path = write_temp_secret(r#"{"credentials":[]}"#);
    let mut config = base_fake_config();
    config.identity =
        static_identity_config("required", &identity_token_path, "agent-one", Vec::new());
    config.credentials.per_user.insert(
        "gitlab_git".to_string(),
        fake_per_user_credential(store_path.to_str().unwrap()),
    );
    let mut gateway = git_gateway_config();
    gateway.credential_modes = vec!["per_user".to_string()];
    config.gateways.insert("gitlab_git".to_string(), gateway);
    config.policy.grants.push(PolicyGrantConfig {
        subjects: vec!["user:agent-one".to_string()],
        service: "gitlab_git".to_string(),
        actions: vec!["repo.fetch".to_string()],
        resources: resource_selection(&["repository-sip-service"]),
        execution_contexts: None,
        credential_mode: "per_user".to_string(),
        priority: None,
    });
    let runtime = BrokerRuntime::new(config).unwrap();
    let mut runtime_config = (*runtime.config).clone();
    let gateway = runtime_config.gateways.get_mut("gitlab_git").unwrap();
    gateway.upstream_base_url = server.uri();
    gateway.allowed_upstream_hosts = vec![format!("{}/**", server.uri())];
    let runtime = runtime_with_replaced_config(&runtime, runtime_config);
    let identity = runtime.identity_from_principal_groups(
        "agent-one".to_string(),
        Some("agent-one".to_string()),
        Vec::new(),
        None,
        None,
    );
    let credential = bearer_credential("runtime-token");

    let error = runtime
        .verify_execution_credential(
            "gitlab_git",
            &credential,
            &identity,
            CredentialVerificationInput {
                repository: Some("sip/service".to_string()),
            },
            CorrelationContext::for_tests(),
        )
        .await
        .unwrap_err();

    assert_eq!(error.decision(), Decision::Error);
    assert_eq!(error.reason_code(), ReasonCode::UpstreamRateLimited);
    assert_eq!(error.upstream_status, Some(429));
    assert!(!error.message.contains("secret"));
    let result = error.result.as_deref().unwrap();
    assert_eq!(result["limitScope"], "upstream");
    assert_eq!(result["service"], "gitlab_git");
    assert_eq!(result["retryAfterSeconds"], 120);
    assert_eq!(
        error.message,
        format!(
            "gitlab_git is rate limiting requests. Retry after 120s (at {}).",
            result["retryAt"].as_str().unwrap()
        )
    );
    let audit = error.audit.as_ref().unwrap();
    assert_eq!(audit["git"]["repository"], "sip/service");
}

#[tokio::test]
async fn git_gateway_credential_verify_rejects_malformed_discovery_body() {
    use wiremock::matchers::{method, path, query_param};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/sip/service.git/info/refs"))
        .and(query_param("service", "git-upload-pack"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_bytes("not a pkt-line".as_bytes())
                .insert_header(
                    "Content-Type",
                    "application/x-git-upload-pack-advertisement",
                ),
        )
        .mount(&server)
        .await;

    let identity_token_path = write_temp_secret("agent-one-token");
    let store_path = write_temp_secret(r#"{"credentials":[]}"#);
    let mut config = base_fake_config();
    config.identity =
        static_identity_config("required", &identity_token_path, "agent-one", Vec::new());
    config.credentials.per_user.insert(
        "gitlab_git".to_string(),
        fake_per_user_credential(store_path.to_str().unwrap()),
    );
    let mut gateway = git_gateway_config();
    gateway.credential_modes = vec!["per_user".to_string()];
    config.gateways.insert("gitlab_git".to_string(), gateway);
    config.policy.grants.push(PolicyGrantConfig {
        subjects: vec!["user:agent-one".to_string()],
        service: "gitlab_git".to_string(),
        actions: vec!["repo.fetch".to_string()],
        resources: resource_selection(&["repository-sip-service"]),
        execution_contexts: None,
        credential_mode: "per_user".to_string(),
        priority: None,
    });
    let runtime = BrokerRuntime::new(config).unwrap();
    let mut runtime_config = (*runtime.config).clone();
    let gateway = runtime_config.gateways.get_mut("gitlab_git").unwrap();
    gateway.upstream_base_url = server.uri();
    gateway.allowed_upstream_hosts = vec![format!("{}/**", server.uri())];
    let runtime = runtime_with_replaced_config(&runtime, runtime_config);
    let identity = runtime.identity_from_principal_groups(
        "agent-one".to_string(),
        Some("agent-one".to_string()),
        Vec::new(),
        None,
        None,
    );
    let credential = bearer_credential("runtime-token");

    let error = runtime
        .verify_execution_credential(
            "gitlab_git",
            &credential,
            &identity,
            CredentialVerificationInput {
                repository: Some("sip/service".to_string()),
            },
            CorrelationContext::for_tests(),
        )
        .await
        .unwrap_err();

    assert_eq!(error.reason_code(), ReasonCode::UpstreamProtocolFailed);
    assert_eq!(error.upstream_status, Some(200));
    let audit = error.audit.as_ref().unwrap();
    assert_eq!(audit["git"]["repository"], "sip/service");
}

#[tokio::test]
async fn git_gateway_credential_verify_times_out_waiting_for_headers() {
    use tokio::net::TcpListener;

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream_addr = listener.local_addr().unwrap();
    let upstream = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        read_test_http_headers(&mut stream).await;
        tokio::time::sleep(Duration::from_millis(150)).await;
    });
    let (runtime, identity, credential) =
        git_verify_runtime_for_upstream(format!("http://{upstream_addr}"), 40);

    let error = runtime
        .verify_execution_credential(
            "gitlab_git",
            &credential,
            &identity,
            CredentialVerificationInput {
                repository: Some("sip/service".to_string()),
            },
            CorrelationContext::for_tests(),
        )
        .await
        .unwrap_err();

    assert_eq!(error.reason_code(), ReasonCode::UpstreamTimeout);
    assert_eq!(error.upstream_status, None);
    let audit = error.audit.as_ref().unwrap();
    assert_eq!(audit["git"]["repository"], "sip/service");
    upstream.await.unwrap();
}

#[tokio::test]
async fn git_gateway_credential_verify_times_out_waiting_for_discovery_body() {
    use tokio::io::AsyncWriteExt;
    use tokio::net::TcpListener;

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream_addr = listener.local_addr().unwrap();
    let upstream = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        read_test_http_headers(&mut stream).await;
        stream
            .write_all(
                b"HTTP/1.1 200 OK\r\nContent-Type: application/x-git-upload-pack-advertisement\r\nConnection: close\r\n\r\n",
            )
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_millis(150)).await;
    });
    let (runtime, identity, credential) =
        git_verify_runtime_for_upstream(format!("http://{upstream_addr}"), 40);

    let error = runtime
        .verify_execution_credential(
            "gitlab_git",
            &credential,
            &identity,
            CredentialVerificationInput {
                repository: Some("sip/service".to_string()),
            },
            CorrelationContext::for_tests(),
        )
        .await
        .unwrap_err();

    assert_eq!(error.reason_code(), ReasonCode::UpstreamTimeout);
    assert_eq!(error.upstream_status, Some(200));
    let audit = error.audit.as_ref().unwrap();
    assert_eq!(audit["git"]["repository"], "sip/service");
    upstream.await.unwrap();
}

#[tokio::test]
async fn git_gateway_credential_verify_times_out_slow_discovery_body_drip() {
    use tokio::io::AsyncWriteExt;
    use tokio::net::TcpListener;

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream_addr = listener.local_addr().unwrap();
    let upstream = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        read_test_http_headers(&mut stream).await;
        stream
            .write_all(
                b"HTTP/1.1 200 OK\r\nContent-Type: application/x-git-upload-pack-advertisement\r\nConnection: close\r\n\r\n",
            )
            .await
            .unwrap();
        for byte in b"001e# service=git-upload-pack\n0000" {
            if stream.write_all(&[*byte]).await.is_err() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    });
    let (runtime, identity, credential) =
        git_verify_runtime_for_upstream(format!("http://{upstream_addr}"), 50);

    let error = runtime
        .verify_execution_credential(
            "gitlab_git",
            &credential,
            &identity,
            CredentialVerificationInput {
                repository: Some("sip/service".to_string()),
            },
            CorrelationContext::for_tests(),
        )
        .await
        .unwrap_err();

    assert_eq!(error.reason_code(), ReasonCode::UpstreamTimeout);
    assert_eq!(error.upstream_status, Some(200));
    let audit = error.audit.as_ref().unwrap();
    assert_eq!(audit["git"]["repository"], "sip/service");
    upstream.await.unwrap();
}

#[tokio::test]
async fn git_gateway_credential_verify_requires_per_user_policy() {
    let identity_token_path = write_temp_secret("agent-one-token");
    let mut config = base_fake_config();
    config.identity =
        static_identity_config("required", &identity_token_path, "agent-one", Vec::new());
    config.credentials.service.insert(
        "gitlab_git".to_string(),
        fake_service_credential("env:GITLAB_TOKEN"),
    );
    let mut gateway = git_gateway_config();
    gateway.credential_modes = vec!["service".to_string()];
    config.gateways.insert("gitlab_git".to_string(), gateway);
    config.policy.grants.push(PolicyGrantConfig {
        subjects: vec!["user:agent-one".to_string()],
        service: "gitlab_git".to_string(),
        actions: vec!["repo.fetch".to_string()],
        resources: resource_selection(&["repository-sip-service"]),
        execution_contexts: None,
        credential_mode: "service".to_string(),
        priority: None,
    });
    let runtime = BrokerRuntime::new(config).unwrap();
    let identity = runtime.identity_from_principal_groups(
        "agent-one".to_string(),
        Some("agent-one".to_string()),
        Vec::new(),
        None,
        None,
    );
    let credential = bearer_credential("runtime-token");

    let error = runtime
        .verify_execution_credential(
            "gitlab_git",
            &credential,
            &identity,
            CredentialVerificationInput {
                repository: Some("sip/service".to_string()),
            },
            CorrelationContext::for_tests(),
        )
        .await
        .unwrap_err();

    assert_eq!(error.reason_code(), ReasonCode::ServiceActionDenied);
    assert!(error.message.contains("per_user"));
}

#[tokio::test]
async fn gateway_operation_preparation_authorizes_policy_and_resolves_credential() {
    let token_path = write_temp_secret("git-token");
    let identity_token_path = write_temp_secret("agent-one-token");
    let audit_path = temp_path("gateway-success-audit.jsonl");
    let mut config = base_fake_config();
    config.audit = Some(jsonl_audit_config(audit_path.display().to_string()));
    config.identity.mode = "required".to_string();
    config.identity.sources = vec![IdentitySourceConfig {
        name: "local".to_string(),
        kind: "static_principals".to_string(),
        header: "Authorization".to_string(),
        scheme: "Bearer".to_string(),
        principals: vec![StaticPrincipalConfig {
            principal: "agent-one".to_string(),
            token_refs: vec![format!("file:{}", identity_token_path.display())],
        }],
    }];
    config.credentials.service.insert(
        "gitlab_git".to_string(),
        fake_service_credential(format!("file:{}", token_path.display())),
    );
    config
        .gateways
        .insert("gitlab_git".to_string(), git_gateway_config());
    config.policy.grants.push(PolicyGrantConfig {
        subjects: vec!["user:agent-one".to_string()],
        service: "gitlab_git".to_string(),
        actions: vec!["repo.fetch".to_string()],
        resources: resource_selection(&["repository-sip-service"]),
        execution_contexts: None,
        credential_mode: "service".to_string(),
        priority: None,
    });
    let runtime = BrokerRuntime::new(config)
        .unwrap()
        .with_config_generation(7);
    let identity = runtime.identity_from_principal_groups(
        "agent-one".to_string(),
        Some("agent-one".to_string()),
        vec![],
        None,
        None,
    );

    let mut prepared = runtime
        .prepare_gateway_operation(
            governed(OperationContext {
                agent_request_id: "gateway-agent-request".to_string(),
                broker_request_id: "gateway-broker-request".to_string(),
                identity,
                service: "gitlab_git".to_string(),
                action: "repo.fetch".to_string(),
                source: SourceContext::unknown(),
            }),
            ResourceScopes::from([
                ("repository".to_string(), vec!["sip/service".to_string()]),
                ("namespace".to_string(), vec!["sip".to_string()]),
            ]),
        )
        .await
        .unwrap();

    assert_eq!(prepared.service, "gitlab_git");
    assert_eq!(prepared.action, "repo.fetch");
    assert_eq!(prepared.credential_mode, "service");
    assert_eq!(prepared.credential.kind().as_str(), "bearer_token");
    assert_eq!(credential_token(&prepared.credential), "git-token");
    assert_eq!(prepared.matched_grant.subject, "user:agent-one");

    runtime
        .start_prepared_gateway_operation(
            &mut prepared,
            json!({
                "gateway": {
                    "kind": "git_http",
                    "method": "GET",
                    "upstreamOrigin": "https://gitlab.example.com",
                    "upstreamPath": "/sip/service.git/info/refs",
                    "responseBytes": 0
                }
            }),
        )
        .await
        .unwrap();
    runtime
        .complete_prepared_gateway_operation(
            prepared,
            200,
            7,
            json!({
                "gateway": {
                    "kind": "git_http",
                    "method": "GET",
                    "upstreamOrigin": "https://gitlab.example.com",
                    "upstreamPath": "/sip/service.git/info/refs",
                    "responseBytes": 32
                }
            }),
        )
        .await
        .unwrap();
    runtime
        .shutdown_audit(Duration::from_secs(1))
        .await
        .unwrap();
    let records = audit_records(&audit_path);
    let started = records
        .iter()
        .find(|record| {
            record["service"] == "gitlab_git"
                && record["action"] == "repo.fetch"
                && record["providerAudit"]["gateway"]["phase"] == "started"
        })
        .expect("gateway start should be audited before forwarding");
    assert_eq!(started["decision"], "allow");
    assert_eq!(started["configGeneration"], 7);
    assert_eq!(started["policyGeneration"], 7);
    assert_eq!(started["matchedGrant"]["configIndex"], 1);
    assert_eq!(started["matchedGrant"]["policyGeneration"], 7);
    assert_eq!(started["providerAudit"]["gateway"]["responseBytes"], 0);

    let record = records
        .iter()
        .find(|record| {
            record["service"] == "gitlab_git"
                && record["action"] == "repo.fetch"
                && record["providerAudit"]["gateway"]["responseBytes"] == 32
        })
        .expect("gateway completion should be audited");
    assert_eq!(record["decision"], "allow");
    assert_eq!(record["configGeneration"], 7);
    assert_eq!(record["policyGeneration"], 7);
    assert_eq!(record["matchedGrant"]["policyGeneration"], 7);
    assert_eq!(record["upstreamStatus"], 200);
    assert_eq!(record["upstreamDurationMs"], 7);
    assert_eq!(record["providerAudit"]["gateway"]["phase"], "completed");
    assert_eq!(record["providerAudit"]["gateway"]["responseBytes"], 32);
}

#[tokio::test]
async fn started_gateway_operation_drop_appends_canceled_terminal_audit() {
    let token_path = write_temp_secret("git-cancel-token");
    let identity_token_path = write_temp_secret("agent-cancel-token");
    let audit_path = temp_path("gateway-canceled-audit.jsonl");
    let mut config = base_fake_config();
    config.audit = Some(jsonl_audit_config(audit_path.display().to_string()));
    config.identity.mode = "required".to_string();
    config.identity.sources = vec![IdentitySourceConfig {
        name: "local".to_string(),
        kind: "static_principals".to_string(),
        header: "Authorization".to_string(),
        scheme: "Bearer".to_string(),
        principals: vec![StaticPrincipalConfig {
            principal: "agent-one".to_string(),
            token_refs: vec![format!("file:{}", identity_token_path.display())],
        }],
    }];
    config.credentials.service.insert(
        "gitlab_git".to_string(),
        fake_service_credential(format!("file:{}", token_path.display())),
    );
    config
        .gateways
        .insert("gitlab_git".to_string(), git_gateway_config());
    config.policy.grants.push(PolicyGrantConfig {
        subjects: vec!["user:agent-one".to_string()],
        service: "gitlab_git".to_string(),
        actions: vec!["repo.fetch".to_string()],
        resources: resource_selection(&["repository-sip-service"]),
        execution_contexts: None,
        credential_mode: "service".to_string(),
        priority: None,
    });
    let runtime = BrokerRuntime::new(config).unwrap();
    let identity = runtime.identity_from_principal_groups(
        "agent-one".to_string(),
        Some("agent-one".to_string()),
        vec![],
        None,
        None,
    );

    let mut prepared = runtime
        .prepare_gateway_operation(
            governed(OperationContext {
                agent_request_id: "gateway-canceled-request".to_string(),
                broker_request_id: "gateway-canceled-broker".to_string(),
                identity,
                service: "gitlab_git".to_string(),
                action: "repo.fetch".to_string(),
                source: SourceContext::unknown(),
            }),
            ResourceScopes::from([
                ("repository".to_string(), vec!["sip/service".to_string()]),
                ("namespace".to_string(), vec!["sip".to_string()]),
            ]),
        )
        .await
        .unwrap();
    runtime
        .start_prepared_gateway_operation(
            &mut prepared,
            json!({
                "gateway": {
                    "kind": "git_http",
                    "method": "GET",
                    "upstreamOrigin": "https://gitlab.example.com",
                    "upstreamPath": "/sip/service.git/info/refs",
                    "responseBytes": 0
                }
            }),
        )
        .await
        .unwrap();
    prepared.observe_gateway_response_progress(
        206,
        json!({
            "gateway": {
                "kind": "git_http",
                "method": "GET",
                "upstreamOrigin": "https://gitlab.example.com",
                "upstreamPath": "/sip/service.git/info/refs",
                "responseBytes": 17
            }
        }),
    );

    drop(prepared);
    runtime
        .shutdown_audit(Duration::from_secs(1))
        .await
        .unwrap();

    let records = audit_records(&audit_path);
    let request_records = records
        .iter()
        .filter(|record| record["agentRequestId"] == "gateway-canceled-request")
        .collect::<Vec<_>>();
    assert_eq!(request_records.len(), 2);
    assert!(request_records.iter().any(|record| {
        record["decision"] == "allow" && record["providerAudit"]["gateway"]["phase"] == "started"
    }));
    let canceled = request_records
        .iter()
        .find(|record| record["providerAudit"]["gateway"]["phase"] == "canceled")
        .expect("started gateway operation drop should append canceled terminal audit");
    assert_eq!(canceled["decision"], "error");
    assert_eq!(
        canceled["providerAudit"]["gateway"]["message"],
        "gateway forwarding was canceled before completion"
    );
    assert_eq!(canceled["providerAudit"]["gateway"]["responseBytes"], 17);
    assert_eq!(canceled["upstreamStatus"], 206);
    assert!(canceled["upstreamDurationMs"].as_u64().is_some());
}

#[tokio::test]
async fn gateway_operation_requires_classified_required_scopes_before_credentials() {
    let identity_token_path = write_temp_secret("agent-one-token");
    let missing_token_path = temp_path("missing-git-token");
    let mut config = base_fake_config();
    config.identity.mode = "required".to_string();
    config.identity.sources = vec![IdentitySourceConfig {
        name: "local".to_string(),
        kind: "static_principals".to_string(),
        header: "Authorization".to_string(),
        scheme: "Bearer".to_string(),
        principals: vec![StaticPrincipalConfig {
            principal: "agent-one".to_string(),
            token_refs: vec![format!("file:{}", identity_token_path.display())],
        }],
    }];
    config.credentials.service.insert(
        "gitlab_git".to_string(),
        fake_service_credential(format!("file:{}", missing_token_path.display())),
    );
    config
        .gateways
        .insert("gitlab_git".to_string(), git_gateway_config());
    config.policy.grants.push(PolicyGrantConfig {
        subjects: vec!["user:agent-one".to_string()],
        service: "gitlab_git".to_string(),
        actions: vec!["repo.fetch".to_string()],
        resources: resource_selection(&["repository-sip-service"]),
        execution_contexts: None,
        credential_mode: "service".to_string(),
        priority: None,
    });
    let runtime = BrokerRuntime::new(config).unwrap();
    let identity = runtime.identity_from_principal_groups(
        "agent-one".to_string(),
        Some("agent-one".to_string()),
        vec![],
        None,
        None,
    );

    let response = match runtime
        .prepare_gateway_operation(
            governed(OperationContext {
                agent_request_id: "gateway-missing-scope-agent-request".to_string(),
                broker_request_id: "gateway-missing-scope-broker-request".to_string(),
                identity,
                service: "gitlab_git".to_string(),
                action: "repo.fetch".to_string(),
                source: SourceContext::unknown(),
            }),
            ResourceScopes::from([("namespace".to_string(), vec!["sip".to_string()])]),
        )
        .await
    {
        Ok(_) => panic!("gateway operation without repository scope should be denied"),
        Err(response) => response,
    };

    assert_eq!(
        response.envelope.reason_code,
        Some(ReasonCode::GatewayScopeUnresolved.into())
    );
}

#[tokio::test]
async fn readiness_accepts_broker_token_source_with_active_managed_credentials() {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;

    let key_path = write_temp_secret(&URL_SAFE_NO_PAD.encode([7_u8; 32]));
    let hash_key_path = write_temp_secret(&URL_SAFE_NO_PAD.encode([9_u8; 32]));
    let store_path = temp_path("managed-broker-token-readiness.sqlite");
    let mut config = base_fake_config();
    config.credentials.service.clear();
    config.policy.grants.clear();
    config.identity = IdentityConfig {
        trusted_callers: BTreeMap::new(),
        mode: "required".to_string(),
        authority: "managed".to_string(),
        sources: vec![IdentitySourceConfig {
            name: "broker".to_string(),
            kind: "broker_tokens".to_string(),
            header: "Authorization".to_string(),
            scheme: "Bearer".to_string(),
            principals: vec![],
        }],
        groups: vec![],
    };
    config.managed_store = Some(ManagedStoreConfig {
        kind: "sqlite".to_string(),
        path: store_path.display().to_string(),
        require_registered_principal_for_invocation: false,
        auto_migrate: true,
    });
    config.credential_encryption = Some(CredentialEncryptionConfig {
        active_key: "k1".to_string(),
        keys: vec![CredentialEncryptionKeyConfig {
            id: "k1".to_string(),
            provider: "file".to_string(),
            env: None,
            path: Some(key_path.display().to_string()),
        }],
    });
    config.broker_tokens = Some(BrokerTokensConfig {
        hash_key_ref: format!("file:{}", hash_key_path.display()),
        default_agent_invoke_ttl: None,
        default_user_manage_ttl: None,
        default_admin_ttl: None,
        max_self_issued_agent_invoke_ttl: None,
        ..Default::default()
    });

    let runtime = BrokerRuntime::new(config).unwrap();
    let store = runtime.managed_store().unwrap();
    store
        .create_or_update_principal(crate::PrincipalWriteRequest {
            role: crate::PrincipalRole::User,
            self_service_enabled: None,
            principal_id: "alice".to_string(),
            kind: "user".to_string(),
            display_name: None,
            email: None,
            external_subject: None,
            created_by: "admin".to_string(),
        })
        .unwrap();
    store
        .upsert_user_credential(
            runtime.credential_key_ring().unwrap(),
            crate::CredentialWriteRequest {
                owner_principal_id: "alice".to_string(),
                service: "fake".to_string(),
                name: "default".to_string(),
                profile: "http-bearer-token".to_string(),
                credential_kind: "bearer_token".to_string(),
                secret: json!({"token": "managed-runtime-token"}),
                metadata: json!({}),
                actor: "admin".to_string(),
            },
            crate::CredentialManagementPurpose::Administrative,
        )
        .unwrap();

    runtime.readiness().await.unwrap();
}

#[test]
fn managed_identity_toml_policy_rejects_missing_db_group_subject() {
    let store_path = temp_path("managed-policy-missing-group.sqlite");
    let mut config = base_fake_config();
    config.identity.authority = "managed".to_string();
    config.identity.groups.clear();
    config.managed_store = Some(ManagedStoreConfig {
        kind: "sqlite".to_string(),
        path: store_path.display().to_string(),
        require_registered_principal_for_invocation: false,
        auto_migrate: true,
    });
    config.policy.grants = vec![PolicyGrantConfig {
        subjects: vec!["group:agents".to_string()],
        service: "fake".to_string(),
        actions: vec!["echo".to_string()],
        resources: resource_selection(&["fake-project-TEST"]),
        execution_contexts: None,
        credential_mode: "service".to_string(),
        priority: None,
    }];

    let error = match BrokerRuntime::new(config) {
        Ok(_) => panic!("expected config admission error"),
        Err(error) => error,
    };
    let RuntimeError::Config(ConfigError::Invalid { errors }) = error else {
        panic!("expected config admission error");
    };
    assert!(errors[0].contains("group:agents"));
}

#[test]
fn managed_identity_toml_policy_accepts_existing_db_subjects() {
    let store_path = temp_path("managed-policy-existing-subjects.sqlite");
    let mut config = base_fake_config();
    config.identity.authority = "managed".to_string();
    config.identity.groups.clear();
    config.managed_store = Some(ManagedStoreConfig {
        kind: "sqlite".to_string(),
        path: store_path.display().to_string(),
        require_registered_principal_for_invocation: false,
        auto_migrate: true,
    });
    config.policy.grants = vec![
        PolicyGrantConfig {
            subjects: vec!["group:agents".to_string()],
            service: "fake".to_string(),
            actions: vec!["echo".to_string()],
            resources: resource_selection(&["fake-project-TEST"]),
            execution_contexts: None,
            credential_mode: "service".to_string(),
            priority: None,
        },
        PolicyGrantConfig {
            subjects: vec!["user:alice".to_string()],
            service: "fake".to_string(),
            actions: vec!["echo".to_string()],
            resources: resource_selection(&["fake-project-TEST"]),
            execution_contexts: None,
            credential_mode: "service".to_string(),
            priority: None,
        },
    ];
    {
        let store = ManagedStore::open(
            config.managed_store.as_ref().unwrap(),
            ManagedStoreOpenMode::Startup,
        )
        .unwrap();
        store
            .create_group(crate::GroupWriteRequest {
                group_id: "agents".to_string(),
                display_name: None,
                description: None,
                created_by: "system".to_string(),
            })
            .unwrap();
        store
            .create_or_update_principal(crate::PrincipalWriteRequest {
                role: crate::PrincipalRole::User,
                self_service_enabled: None,
                principal_id: "alice".to_string(),
                kind: "user".to_string(),
                display_name: None,
                email: None,
                external_subject: None,
                created_by: "admin".to_string(),
            })
            .unwrap();
    }

    BrokerRuntime::new(config).unwrap();
}

#[test]
fn managed_startup_names_resources_of_unregistered_types() {
    let store_path = temp_path("managed-unregistered-type.sqlite");
    let config = managed_policy_fake_config(&store_path);
    seed_test_resource_catalog(&store_path);
    let conn = rusqlite::Connection::open(&store_path).unwrap();
    conn.execute(
        "INSERT INTO resources (resource_id,resource_type,selector_kind,selector_value,allowed_execution_contexts_json,enabled,version,created_at,created_by,updated_at,updated_by) VALUES ('retired-board','retired_board','all','','[\"default\"]',1,1,'t','admin','t','admin')",
        [],
    )
    .unwrap();
    drop(conn);

    let error = match BrokerRuntime::new(config) {
        Ok(_) => panic!("expected an unregistered stored resource type to fail startup"),
        Err(error) => error,
    };
    assert!(
        matches!(
            &error,
            RuntimeError::Config(ConfigError::Invalid { errors })
                if errors.iter().any(|error| error
                    == "resource retired-board uses unregistered resource type retired_board")
        ),
        "{error:?}"
    );
}

#[tokio::test]
async fn managed_policy_authority_loads_db_grants_and_audits_ids() {
    let store_path = temp_path("managed-policy-authority.sqlite");
    let audit_path = temp_path("managed-policy-authority.audit.jsonl");
    let token_path = write_temp_secret("fake-service-token");
    let mut config = managed_policy_fake_config(&store_path);
    config.audit = Some(jsonl_audit_config(audit_path.display().to_string()));
    config.credentials.service.insert(
        "fake".to_string(),
        fake_service_credential(format!("file:{}", token_path.display())),
    );
    seed_managed_policy_grant(
        &store_path,
        ManagedPolicyGrantSeed {
            grant_id: "grant-active",
            grant_order: 0,
            subjects: vec!["group:anonymous"],
            service: "fake",
            actions: vec!["echo"],
            resources: json!({"resourceIds":["fake-project-TEST"]}),
            credential_mode: "service",
            priority: Some(5),
            version: 2,
            generation: 7,
        },
    );

    let runtime = BrokerRuntime::new(config)
        .unwrap()
        .with_config_generation(99);
    assert_eq!(runtime.policy_generation(), 7);
    let response = runtime
        .invoke(
            governed(OperationContext {
                agent_request_id: "agent-request".to_string(),
                broker_request_id: "broker-request".to_string(),
                identity: IdentityContext::anonymous(),
                service: "fake".to_string(),
                action: "echo".to_string(),
                source: SourceContext::unknown(),
            }),
            InvokeRequest {
                inputs: json!({"project": "TEST", "message": "hello"}),
                body_parts: vec![],
                ..InvokeRequest::new(json!({}))
            },
        )
        .await;

    assert_eq!(response.status, 200);
    assert_eq!(
        response.envelope.result.unwrap()["credentialMode"],
        json!("service")
    );
    let audit = fs::read_to_string(audit_path).unwrap();
    assert!(audit.contains("\"grantId\":\"grant-active\""));
    assert!(audit.contains("\"grantVersion\":2"));
    assert!(audit.contains("\"policyGeneration\":7"));
    assert!(!audit.contains("\"configIndex\""));
}

#[test]
fn managed_policy_authority_rejects_missing_db_subject() {
    let store_path = temp_path("managed-policy-authority-missing-subject.sqlite");
    let config = managed_policy_fake_config(&store_path);
    seed_managed_policy_grant(
        &store_path,
        ManagedPolicyGrantSeed {
            grant_id: "grant-missing-group",
            grant_order: 0,
            subjects: vec!["group:agents"],
            service: "fake",
            actions: vec!["echo"],
            resources: json!({"resourceIds":["fake-project-TEST"]}),
            credential_mode: "service",
            priority: None,
            version: 1,
            generation: 1,
        },
    );

    let error = match BrokerRuntime::new(config) {
        Ok(_) => panic!("expected config admission error"),
        Err(error) => error,
    };
    let RuntimeError::Config(ConfigError::Invalid { errors }) = error else {
        panic!("expected config admission error");
    };
    assert!(errors[0].contains("group:agents"));
}

#[test]
fn microsoft_oidc_runtime_loads_redacted_local_configuration() {
    let config = microsoft_oidc_runtime_broker_config();
    let runtime = BrokerRuntime::new(config).unwrap();
    let microsoft = runtime.microsoft_oidc().expect("Microsoft OIDC runtime");

    assert_eq!(
        microsoft.tenant_id(),
        "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa1"
    );
    assert_eq!(
        microsoft.client_id(),
        "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbb2"
    );
    assert_eq!(
        microsoft.issuer_url().as_str(),
        "https://login.microsoftonline.com/aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa1/v2.0"
    );
    assert_eq!(
        microsoft.discovery_url().as_str(),
        "https://login.microsoftonline.com/aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa1/v2.0/.well-known/openid-configuration"
    );
    assert_eq!(
        microsoft.redirect_url().as_str(),
        "https://broker.example.test/v1/auth/oidc/microsoft/callback"
    );
    assert_eq!(microsoft.flow_ttl_seconds(), 600);
    assert_eq!(microsoft.max_pending_flows(), 10_000);
    assert!(microsoft.jit_provisioning());
    assert_eq!(microsoft.external_membership_ttl_seconds(), 8 * 60 * 60);
    assert_eq!(microsoft.secrets().client_secret(), "runtime-client-secret");
    assert_eq!(microsoft.secrets().flow_key(), &[9_u8; 32]);
    assert!(microsoft.config_fingerprint().starts_with("hmac-sha256:"));
    let debug = format!("{microsoft:?}");
    assert!(!debug.contains("runtime-client-secret"));
    assert!(!debug.contains("CQkJCQkJ"));
}

#[test]
fn microsoft_oidc_runtime_fingerprint_is_stable_and_tracks_secret_rotation() {
    let config = microsoft_oidc_runtime_broker_config();
    let runtime = BrokerRuntime::new(config.clone()).unwrap();
    let fingerprint = runtime
        .microsoft_oidc()
        .unwrap()
        .config_fingerprint()
        .to_string();

    let unchanged = BrokerRuntime::new_for_reload(config.clone(), &runtime).unwrap();
    assert_eq!(
        unchanged.microsoft_oidc().unwrap().config_fingerprint(),
        fingerprint
    );

    let client_secret_path = config
        .browser_auth
        .oidc
        .microsoft
        .client_secret_ref
        .as_deref()
        .unwrap()
        .strip_prefix("file:")
        .unwrap();
    fs::write(client_secret_path, "rotated-runtime-client-secret").unwrap();
    let rotated = BrokerRuntime::new_for_reload(config, &runtime).unwrap();
    assert_ne!(
        rotated.microsoft_oidc().unwrap().config_fingerprint(),
        fingerprint
    );
}

#[test]
fn microsoft_oidc_disabled_reload_does_not_resolve_provider_secrets() {
    let config = microsoft_oidc_runtime_broker_config();
    let runtime = BrokerRuntime::new(config.clone()).unwrap();
    assert!(runtime.microsoft_oidc().is_some());

    let mut disabled = config;
    disabled.browser_auth.oidc.microsoft.enabled = false;
    disabled.browser_auth.oidc.microsoft.client_secret_ref = None;
    disabled.browser_auth.oidc.microsoft.flow_key_ref = None;
    let disabled = BrokerRuntime::new_for_reload(disabled, &runtime).unwrap();
    assert!(disabled.microsoft_oidc().is_none());
}

#[test]
fn microsoft_oidc_runtime_secret_failures_are_redacted() {
    let mut config = microsoft_oidc_runtime_broker_config();
    let missing = temp_path("missing-microsoft-client-secret");
    config.browser_auth.oidc.microsoft.client_secret_ref =
        Some(format!("file:{}", missing.display()));

    let error = match BrokerRuntime::new(config) {
        Ok(_) => panic!("missing Microsoft OIDC client secret must fail"),
        Err(error) => error,
    };
    let message = error.to_string();
    assert!(message.contains("Microsoft OIDC secret material is unavailable"));
    assert!(!message.contains(&missing.display().to_string()));
}

#[test]
fn managed_policy_authority_rejects_unknown_git_repository_references() {
    let store_path = temp_path("managed-policy-authority-git-selector.sqlite");
    let token_path = write_temp_secret("git-token");
    let mut config = managed_policy_fake_config(&store_path);
    config.credentials.service.insert(
        "gitlab_git".to_string(),
        fake_service_credential(format!("file:{}", token_path.display())),
    );
    config
        .gateways
        .insert("gitlab_git".to_string(), git_gateway_config());
    seed_managed_policy_grant(
        &store_path,
        ManagedPolicyGrantSeed {
            grant_id: "grant-invalid-repository",
            grant_order: 0,
            subjects: vec!["group:anonymous"],
            service: "gitlab_git",
            actions: vec!["repo.fetch"],
            resources: json!({"resourceIds":["missing-repository"]}),
            credential_mode: "service",
            priority: None,
            version: 1,
            generation: 1,
        },
    );

    let error = match BrokerRuntime::new(config) {
        Ok(_) => panic!("expected config admission error"),
        Err(error) => error,
    };
    assert!(error.to_string().contains("missing-repository"));
}

#[test]
fn managed_policy_authority_accepts_registered_namespace_references() {
    let store_path = temp_path("managed-policy-authority-git-structured-selector.sqlite");
    let token_path = write_temp_secret("git-token");
    let mut config = managed_policy_fake_config(&store_path);
    config.credentials.service.insert(
        "gitlab_git".to_string(),
        fake_service_credential(format!("file:{}", token_path.display())),
    );
    config
        .gateways
        .insert("gitlab_git".to_string(), git_gateway_config());
    seed_managed_policy_grant(
        &store_path,
        ManagedPolicyGrantSeed {
            grant_id: "grant-repository-namespace",
            grant_order: 0,
            subjects: vec!["group:anonymous"],
            service: "gitlab_git",
            actions: vec!["repo.fetch"],
            resources: json!({"resourceIds":["repository-namespace-sip"]}),
            credential_mode: "service",
            priority: None,
            version: 1,
            generation: 1,
        },
    );

    BrokerRuntime::new(config).unwrap();
}

#[test]
fn managed_policy_authority_rejects_unknown_actions() {
    let store_path = temp_path("managed-policy-authority-unknown-action.sqlite");
    let config = managed_policy_fake_config(&store_path);
    seed_managed_policy_grant(
        &store_path,
        ManagedPolicyGrantSeed {
            grant_id: "grant-unknown-action",
            grant_order: 0,
            subjects: vec!["group:anonymous"],
            service: "fake",
            actions: vec!["missing"],
            resources: json!({"resourceIds":["fake-project-TEST"]}),
            credential_mode: "service",
            priority: None,
            version: 1,
            generation: 1,
        },
    );

    assert_runtime_config_error_contains(
        BrokerRuntime::new(config),
        "action missing is unknown for service fake",
    );
}

#[test]
fn managed_policy_authority_accepts_empty_resource_selection_as_no_access() {
    let store_path = temp_path("managed-policy-authority-missing-scopes.sqlite");
    let config = managed_policy_fake_config(&store_path);
    seed_managed_policy_grant(
        &store_path,
        ManagedPolicyGrantSeed {
            grant_id: "grant-missing-scope",
            grant_order: 0,
            subjects: vec!["group:anonymous"],
            service: "fake",
            actions: vec!["echo"],
            resources: json!({}),
            credential_mode: "service",
            priority: None,
            version: 1,
            generation: 1,
        },
    );

    let runtime = BrokerRuntime::new(config).unwrap();
    assert!(
        runtime
            .visible_services(&IdentityContext::anonymous(), &default_execution_context())
            .is_empty()
    );
}

#[test]
fn managed_policy_authority_rejects_missing_lookup_credentials() {
    let provider = Arc::new(LookupTraceProvider::default());
    let store_path = temp_path("managed-policy-authority-missing-lookup.sqlite");
    let mut config = managed_policy_fake_config(&store_path);
    configure_lookup_trace_jira(&mut config);
    configure_lookup_trace_service(&mut config, "service-token");
    seed_managed_policy_grant(
        &store_path,
        ManagedPolicyGrantSeed {
            grant_id: "grant-service-lookup",
            grant_order: 0,
            subjects: vec!["group:anonymous"],
            service: "jira",
            actions: vec!["issue.view"],
            resources: json!({"resourceIds":["project-TEST"]}),
            credential_mode: "service",
            priority: None,
            version: 1,
            generation: 1,
        },
    );

    assert_runtime_config_error_contains(
        BrokerRuntime::with_providers(config, vec![provider]),
        "service-mode lookup-backed policy requires credentials.lookup.jira",
    );
}

#[test]
fn managed_policy_authority_rejects_static_credential_mode_ambiguity() {
    let store_path = temp_path("managed-policy-authority-ambiguity.sqlite");
    let per_user_store_path = write_temp_secret(r#"{"credentials":[]}"#);
    let mut config = managed_policy_fake_config(&store_path);
    config.credentials.per_user.insert(
        "fake".to_string(),
        fake_per_user_credential(per_user_store_path.to_str().unwrap()),
    );
    seed_managed_policy_grant(
        &store_path,
        ManagedPolicyGrantSeed {
            grant_id: "grant-service-mode",
            grant_order: 0,
            subjects: vec!["group:anonymous"],
            service: "fake",
            actions: vec!["echo"],
            resources: json!({"resourceIds":["fake-project-TEST"]}),
            credential_mode: "service",
            priority: Some(10),
            version: 1,
            generation: 1,
        },
    );
    seed_managed_policy_grant(
        &store_path,
        ManagedPolicyGrantSeed {
            grant_id: "grant-per-user-mode",
            grant_order: 1,
            subjects: vec!["group:anonymous"],
            service: "fake",
            actions: vec!["echo"],
            resources: json!({"resourceIds":["fake-project-TEST"]}),
            credential_mode: "per_user",
            priority: Some(10),
            version: 1,
            generation: 1,
        },
    );

    assert_runtime_config_error_contains(
        BrokerRuntime::new(config),
        "ambiguous credential mode precedence",
    );
}

#[tokio::test]
async fn managed_policy_mutations_publish_without_runtime_reload() {
    let store_path = temp_path("managed-policy-mutation-publish.sqlite");
    let config = managed_policy_fake_config(&store_path);
    let runtime = BrokerRuntime::new(config).unwrap();

    let created = runtime
        .create_managed_policy_grant(ManagedPolicyGrantCreateRequest {
            grant_id: Some(Uuid::new_v4().to_string()),
            subjects: vec!["group:anonymous".to_string()],
            service: "fake".to_string(),
            actions: vec!["echo".to_string()],
            resources: resource_selection(&["fake-project-TEST"]),
            execution_contexts: vec![DEFAULT_EXECUTION_CONTEXT.to_string()],
            credential_mode: "service".to_string(),
            priority: Some(5),
            status: None,
            description: Some("Temporary TEST access".to_string()),
            created_by: "admin".to_string(),
        })
        .unwrap();

    assert_eq!(created.previous_revision.generation, 0);
    assert_eq!(created.revision.generation, 1);
    assert_eq!(runtime.policy_generation(), 1);
    let response = runtime
        .invoke(
            governed(OperationContext {
                agent_request_id: "agent-request".to_string(),
                broker_request_id: "broker-request".to_string(),
                identity: IdentityContext::anonymous(),
                service: "fake".to_string(),
                action: "echo".to_string(),
                source: SourceContext::unknown(),
            }),
            InvokeRequest {
                inputs: json!({"project": "TEST", "message": "hello"}),
                body_parts: vec![],
                ..InvokeRequest::new(json!({}))
            },
        )
        .await;
    assert_eq!(response.status, 200);

    let prepared = runtime
        .begin_invoke(
            governed(OperationContext {
                agent_request_id: "prepared-before-grant-disable".into(),
                broker_request_id: "broker-before-grant-disable".into(),
                identity: IdentityContext::anonymous(),
                service: "fake".into(),
                action: "echo".into(),
                source: SourceContext::unknown(),
            }),
            InvokeRequest::new(json!({"project": "TEST", "message": "already authorized"})),
        )
        .await
        .unwrap();

    let disabled = runtime
        .disable_managed_policy_grant(ManagedPolicyGrantStatusRequest {
            grant_id: created.grant.grant_id,
            expected_version: created.grant.version,
            updated_by: "admin".to_string(),
        })
        .unwrap();

    assert_eq!(disabled.previous_revision.generation, 1);
    assert_eq!(disabled.revision.generation, 2);
    assert_eq!(runtime.policy_generation(), 2);
    assert!(
        runtime
            .managed_store()
            .unwrap()
            .active_policy_grants()
            .unwrap()
            .is_empty()
    );
    // Grant changes apply to new preparations. The already prepared operation
    // retains exactly its admitted inputs and policy snapshot.
    let completed = runtime.finish_prepared_invoke(prepared, vec![]).await;
    assert_eq!(completed.status, 200);
    assert_eq!(
        completed.envelope.result.unwrap()["message"],
        "already authorized"
    );
    let response = runtime
        .invoke(
            governed(OperationContext {
                agent_request_id: "agent-request-2".to_string(),
                broker_request_id: "broker-request-2".to_string(),
                identity: IdentityContext::anonymous(),
                service: "fake".to_string(),
                action: "echo".to_string(),
                source: SourceContext::unknown(),
            }),
            InvokeRequest {
                inputs: json!({"project": "TEST", "message": "hello"}),
                body_parts: vec![],
                ..InvokeRequest::new(json!({}))
            },
        )
        .await;

    assert_eq!(response.status, 403);
    assert_eq!(
        response.envelope.reason_code,
        Some(ReasonCode::ServiceActionDenied.into())
    );
}

#[tokio::test]
async fn managed_policy_mutation_validates_non_anonymous_subject_without_relocking_store() {
    let store_path = temp_path("managed-policy-mutation-managed-group.sqlite");
    let store = ManagedStore::open(
        &ManagedStoreConfig {
            kind: "sqlite".to_string(),
            path: store_path.display().to_string(),
            require_registered_principal_for_invocation: false,
            auto_migrate: true,
        },
        ManagedStoreOpenMode::Startup,
    )
    .unwrap();
    store
        .create_group(crate::GroupWriteRequest {
            group_id: "agents".to_string(),
            display_name: None,
            description: None,
            created_by: "admin".to_string(),
        })
        .unwrap();
    drop(store);
    let config = managed_policy_fake_config(&store_path);
    let runtime = BrokerRuntime::new(config).unwrap();

    let created = runtime
        .create_managed_policy_grant(ManagedPolicyGrantCreateRequest {
            grant_id: Some(Uuid::new_v4().to_string()),
            subjects: vec!["group:agents".to_string()],
            service: "fake".to_string(),
            actions: vec!["echo".to_string()],
            resources: resource_selection(&["fake-project-TEST"]),
            execution_contexts: vec![DEFAULT_EXECUTION_CONTEXT.to_string()],
            credential_mode: "service".to_string(),
            priority: None,
            status: None,
            description: None,
            created_by: "admin".to_string(),
        })
        .unwrap();

    assert_eq!(created.grant.subjects, vec!["group:agents".to_string()]);
    assert_eq!(runtime.policy_generation(), 1);
}

#[test]
fn managed_policy_mutation_rejects_missing_subject_without_publishing() {
    let store_path = temp_path("managed-policy-mutation-missing-subject.sqlite");
    let config = managed_policy_fake_config(&store_path);
    let runtime = BrokerRuntime::new(config).unwrap();

    let error = runtime
        .create_managed_policy_grant(ManagedPolicyGrantCreateRequest {
            grant_id: Some(Uuid::new_v4().to_string()),
            subjects: vec!["group:missing".to_string()],
            service: "fake".to_string(),
            actions: vec!["echo".to_string()],
            resources: resource_selection(&["fake-project-TEST"]),
            execution_contexts: vec![DEFAULT_EXECUTION_CONTEXT.to_string()],
            credential_mode: "service".to_string(),
            priority: None,
            status: None,
            description: None,
            created_by: "admin".to_string(),
        })
        .unwrap_err();

    assert!(
        matches!(error, ManagedStoreError::PolicyValidationIssues(issues)
            if issues.iter().any(|issue|
                issue.field == "subjects[0]"
                    && issue.code == "subject_not_found"
                    && issue.message.contains("group:missing")))
    );
    assert_eq!(runtime.policy_generation(), 0);
    let store = runtime.managed_store().unwrap();
    assert_eq!(store.policy_revision().unwrap().generation, 0);
    assert!(store.active_policy_grants().unwrap().is_empty());
}

#[tokio::test]
async fn managed_policy_authority_with_no_active_grants_denies_by_default() {
    let store_path = temp_path("managed-policy-authority-empty.sqlite");
    let config = managed_policy_fake_config(&store_path);
    let runtime = BrokerRuntime::new(config).unwrap();

    let response = runtime
        .invoke(
            governed(OperationContext {
                agent_request_id: "agent-request".to_string(),
                broker_request_id: "broker-request".to_string(),
                identity: IdentityContext::anonymous(),
                service: "fake".to_string(),
                action: "echo".to_string(),
                source: SourceContext::unknown(),
            }),
            InvokeRequest {
                inputs: json!({"project": "TEST", "message": "hello"}),
                body_parts: vec![],
                ..InvokeRequest::new(json!({}))
            },
        )
        .await;

    assert_eq!(response.status, 403);
    assert_eq!(
        response.envelope.reason_code,
        Some(ReasonCode::ServiceActionDenied.into())
    );
}

#[test]
fn managed_policy_authority_rejects_reload_incompatible_with_active_grants() {
    let store_path = temp_path("managed-policy-authority-reload.sqlite");
    let config = managed_policy_fake_config(&store_path);
    seed_managed_policy_grant(
        &store_path,
        ManagedPolicyGrantSeed {
            grant_id: "grant-active",
            grant_order: 0,
            subjects: vec!["group:anonymous"],
            service: "fake",
            actions: vec!["echo"],
            resources: json!({"resourceIds":["fake-project-TEST"]}),
            credential_mode: "service",
            priority: None,
            version: 1,
            generation: 1,
        },
    );
    let runtime = BrokerRuntime::new(config.clone()).unwrap();

    let mut candidate = config;
    candidate.deployment.enable_fake_service = false;
    candidate.providers.remove("fake");
    candidate.credentials.service.remove("fake");
    assert_runtime_config_error_contains(
        BrokerRuntime::new_for_reload(candidate, &runtime),
        "references unknown service fake",
    );
    assert_eq!(runtime.policy_generation(), 1);
}

#[tokio::test]
async fn attribution_validation_failure_during_reload_preserves_active_runtime() {
    let config = base_fake_config();
    let runtime = BrokerRuntime::new(config.clone()).unwrap();
    let mut candidate = config;
    candidate
        .providers
        .insert(agent_access_jira::JiraProviderConfig {
            tenant_host: "example.atlassian.net".to_string(),
            cloud_id: None,
            egress_proxy: None,
            allowed_upstream_hosts: vec!["https://example.atlassian.net/rest/api/3/**".to_string()],
            attachments: agent_access_provider::AttachmentLimitsConfig::default(),
            content: agent_access_jira::JiraContentConfig {
                comment_formats: vec!["adf".to_string()],
                ..agent_access_jira::JiraContentConfig::default()
            },
            search: agent_access_provider::SearchLimitsConfig::default(),
            comments: agent_access_jira::JiraCommentsConfig::default(),
            issue_links: agent_access_jira::JiraIssueLinksConfig::default(),
        });
    candidate
        .attribution
        .actions
        .insert("jira".to_string(), vec!["issue.delete".to_string()]);

    assert_runtime_config_error_contains(
        BrokerRuntime::new_for_reload(candidate, &runtime),
        "attribution.actions.jira[0] must match at least one attribution-capable jira action enabled by the current configuration",
    );

    let response = runtime
        .invoke(
            governed(OperationContext {
                agent_request_id: "agent-request".to_string(),
                broker_request_id: "broker-request".to_string(),
                identity: IdentityContext::anonymous(),
                service: "fake".to_string(),
                action: "echo".to_string(),
                source: SourceContext::unknown(),
            }),
            InvokeRequest {
                inputs: json!({"project": "TEST", "message": "still active"}),
                body_parts: vec![],
                ..InvokeRequest::new(json!({}))
            },
        )
        .await;
    assert_eq!(response.status, 200);
    assert_eq!(runtime.policy_generation(), 0);
}

#[tokio::test]
async fn policy_denies_scope_outside_grant_before_credential_selection() {
    let audit_path = temp_path("policy-deny.audit.jsonl");
    let mut config = base_fake_config();
    config.audit = Some(jsonl_audit_config(audit_path.display().to_string()));
    let runtime = BrokerRuntime::new(config).unwrap();

    let response = runtime
        .invoke(
            governed(OperationContext {
                agent_request_id: "agent-request".to_string(),
                broker_request_id: "broker-request".to_string(),
                identity: IdentityContext::anonymous(),
                service: "fake".to_string(),
                action: "echo".to_string(),
                source: SourceContext::unknown(),
            }),
            InvokeRequest {
                inputs: json!({"project": "OTHER", "message": "hello"}),
                body_parts: vec![],
                ..InvokeRequest::new(json!({}))
            },
        )
        .await;

    assert_eq!(response.status, 403);
    assert_eq!(
        response.envelope.reason_code,
        Some(ReasonCode::ServiceActionDenied.into())
    );
    assert_eq!(response.envelope.resource_scopes["project"], vec!["OTHER"]);
    assert!(response.envelope.result.is_none());
    let audit = fs::read_to_string(audit_path).unwrap();
    assert!(audit.contains("\"reasonCode\":\"service_action_denied\""));
    assert!(!audit.contains("credentialMode"));
}

#[test]
fn repository_selectors_require_one_grant_to_cover_every_resolved_target() {
    let single = ResourceScopes::from([("repository".into(), vec!["sip/service".into()])]);
    for selectors in [
        vec![ResourceSelector::Exact {
            value: "sip/service".into(),
        }],
        vec![ResourceSelector::Namespace {
            value: "sip".into(),
        }],
        vec![ResourceSelector::All],
    ] {
        assert!(candidate_authorizes_scopes(
            &repository_candidate(selectors),
            &single
        ));
    }
    assert!(!candidate_authorizes_scopes(
        &repository_candidate(vec![ResourceSelector::Namespace {
            value: "platform".into()
        }]),
        &single
    ));
    let targets = ResourceScopes::from([(
        "repository".into(),
        vec!["target/service".into(), "source/contribution".into()],
    )]);
    for selectors in [
        vec![
            ResourceSelector::Exact {
                value: "target/service".into(),
            },
            ResourceSelector::Exact {
                value: "source/contribution".into(),
            },
        ],
        vec![
            ResourceSelector::Namespace {
                value: "target".into(),
            },
            ResourceSelector::Namespace {
                value: "source".into(),
            },
        ],
        vec![
            ResourceSelector::Exact {
                value: "target/service".into(),
            },
            ResourceSelector::Namespace {
                value: "source".into(),
            },
        ],
    ] {
        assert!(candidate_authorizes_scopes(
            &repository_candidate(selectors),
            &targets
        ));
    }
}

#[test]
fn repository_selector_candidate_selection_does_not_union_separate_grants() {
    let targets = ResourceScopes::from([(
        "repository".into(),
        vec!["target/service".into(), "source/contribution".into()],
    )]);
    let candidates = [
        repository_candidate(vec![ResourceSelector::Exact {
            value: "target/service".into(),
        }]),
        repository_candidate(vec![ResourceSelector::Namespace {
            value: "source".into(),
        }]),
    ];
    assert!(
        candidates
            .iter()
            .all(|candidate| !candidate_authorizes_scopes(candidate, &targets))
    );
}

#[test]
fn token_repository_selectors_require_every_resolved_repository() {
    let mut config = base_fake_config();
    config
        .gateways
        .insert("gitlab_git".into(), git_gateway_config());
    config.credentials.service.insert(
        "gitlab_git".into(),
        fake_service_credential("env:FAKE_SERVICE_TOKEN"),
    );
    let runtime = BrokerRuntime::new(config).unwrap();
    let identity = |ids: Vec<&str>| {
        shell_token_identity(
            json!({"allowedServices":["gitlab_git"],"allowedExecutionContexts":["default"],"serviceRestrictions":{"gitlab_git":{"actions":["repo.fetch"],"resources":{"resourceIds":ids}}}}),
        )
    };
    let mixed = ResourceScopes::from([(
        "repository".into(),
        vec!["sip/service".into(), "other/tool".into()],
    )]);
    let sip_only = ResourceScopes::from([(
        "repository".into(),
        vec!["sip/service".into(), "sip/tool".into()],
    )]);
    let exact = identity(vec!["repository-sip-service"]);
    let namespace = identity(vec!["repository-namespace-sip"]);
    assert!(
        runtime
            .enforce_agent_invoke_token_resource_caveats(&exact, "gitlab_git", "repo.fetch", &mixed)
            .is_err()
    );
    assert!(
        runtime
            .enforce_agent_invoke_token_resource_caveats(
                &namespace,
                "gitlab_git",
                "repo.fetch",
                &mixed
            )
            .is_err()
    );
    assert!(
        runtime
            .enforce_agent_invoke_token_resource_caveats(
                &namespace,
                "gitlab_git",
                "repo.fetch",
                &sip_only
            )
            .is_ok()
    );
    assert!(
        runtime
            .enforce_agent_invoke_token_resource_caveats(
                &exact,
                "gitlab_git",
                "repo.fetch",
                &sip_only
            )
            .is_err()
    );
    // Namespace metadata is not another target or authoritative resource identity.
    let metadata = ResourceScopes::from([
        ("repository".into(), vec!["sip/service".into()]),
        ("namespace".into(), vec!["uncovered".into()]),
    ]);
    assert!(
        runtime
            .enforce_agent_invoke_token_resource_caveats(
                &exact,
                "gitlab_git",
                "repo.fetch",
                &metadata
            )
            .is_ok()
    );
}

fn repository_candidate(included: Vec<ResourceSelector>) -> PolicyCandidate {
    PolicyCandidate {
        subject: "group:agents".into(),
        credential_mode: "service".into(),
        explicit_priority: None,
        priority: 0,
        subject_rank: 1,
        order: 0,
        subject_order: 0,
        config_index: Some(0),
        grant_id: None,
        grant_version: None,
        resources: ResourceSelection::default(),
        execution_contexts: vec![default_execution_context()],
        resource_scope: Some(ActionResourceScope {
            scope: "repository".to_string(),
            resource_type: &agent_access_provider::GIT_REPOSITORY_RESOURCE,
        }),
        boundary: ResourceBoundary {
            included,
            excluded: vec![],
        },
    }
}

#[tokio::test]
async fn policy_precedence_prefers_user_grant_over_higher_priority_group_grant() {
    let mut config = base_fake_config();
    let token_path = write_temp_secret("agent-token");
    config.identity = static_identity_config(
        "required",
        &token_path,
        "agent-one",
        vec!["agents".to_string()],
    );
    let store_path = temp_path("policy-precedence-users.json");
    config.credentials.per_user.insert(
        "fake".to_string(),
        fake_per_user_credential(store_path.to_str().unwrap()),
    );
    config.policy.grants = vec![
        PolicyGrantConfig {
            subjects: vec!["group:agents".to_string()],
            service: "fake".to_string(),
            actions: vec!["echo".to_string()],
            resources: resource_selection(&["fake-project-TEST"]),
            execution_contexts: None,
            credential_mode: "per_user".to_string(),
            priority: Some(10),
        },
        PolicyGrantConfig {
            subjects: vec!["user:agent-one".to_string()],
            service: "fake".to_string(),
            actions: vec!["echo".to_string()],
            resources: resource_selection(&["fake-project-TEST"]),
            execution_contexts: None,
            credential_mode: "service".to_string(),
            priority: None,
        },
    ];
    let runtime = BrokerRuntime::new(config).unwrap();

    let response = runtime
        .invoke(
            governed(OperationContext {
                agent_request_id: "agent-request".to_string(),
                broker_request_id: "broker-request".to_string(),
                identity: IdentityContext {
                    caller_id: None,
                    principal: "agent-one".to_string(),
                    principal_subject: Some("agent-one".to_string()),
                    groups: vec!["agents".to_string()],
                    policy_groups: vec!["agents".to_string()],
                    authenticated: true,
                    source: None,
                },
                service: "fake".to_string(),
                action: "echo".to_string(),
                source: SourceContext::unknown(),
            }),
            InvokeRequest {
                inputs: json!({"project": "TEST", "message": "hello"}),
                body_parts: vec![],
                ..InvokeRequest::new(json!({}))
            },
        )
        .await;

    assert_eq!(response.status, 200);
    assert_eq!(
        response.envelope.result.unwrap()["credentialMode"],
        json!("service")
    );
}

#[tokio::test]
async fn multi_subject_grant_authorizes_each_listed_subject_and_audits_concrete_subject() {
    let config = multi_subject_fake_config(vec!["user:agent-one", "group:agents"]);

    let user_subject = invoke_fake_echo_and_return_matched_subject(
        config.clone(),
        IdentityContext {
            caller_id: None,
            principal: "agent-one".to_string(),
            principal_subject: Some("agent-one".to_string()),
            groups: Vec::new(),
            policy_groups: Vec::new(),
            authenticated: true,
            source: None,
        },
        "multi-subject-user.audit.jsonl",
    )
    .await;
    assert_eq!(user_subject, "user:agent-one");

    let group_subject = invoke_fake_echo_and_return_matched_subject(
        config,
        IdentityContext {
            caller_id: None,
            principal: "agent-two".to_string(),
            principal_subject: Some("agent-two".to_string()),
            groups: vec!["agents".to_string()],
            policy_groups: vec!["agents".to_string()],
            authenticated: true,
            source: None,
        },
        "multi-subject-group.audit.jsonl",
    )
    .await;
    assert_eq!(group_subject, "group:agents");
}

#[tokio::test]
async fn multi_subject_grant_prefers_direct_user_subject_over_group_subject() {
    let matched_subject = invoke_fake_echo_and_return_matched_subject(
        multi_subject_fake_config(vec!["group:agents", "user:agent-one"]),
        IdentityContext {
            caller_id: None,
            principal: "agent-one".to_string(),
            principal_subject: Some("agent-one".to_string()),
            groups: vec!["agents".to_string()],
            policy_groups: vec!["agents".to_string()],
            authenticated: true,
            source: None,
        },
        "multi-subject-user-precedence.audit.jsonl",
    )
    .await;

    assert_eq!(matched_subject, "user:agent-one");
}

#[tokio::test]
async fn multi_group_subjects_in_one_grant_choose_deterministic_audit_subject() {
    let matched_subject = invoke_fake_echo_and_return_matched_subject(
        multi_subject_fake_config(vec!["group:other", "group:agents"]),
        IdentityContext {
            caller_id: None,
            principal: "agent-one".to_string(),
            principal_subject: Some("agent-one".to_string()),
            groups: vec!["agents".to_string(), "other".to_string()],
            policy_groups: vec!["agents".to_string(), "other".to_string()],
            authenticated: true,
            source: None,
        },
        "multi-subject-two-groups.audit.jsonl",
    )
    .await;

    assert_eq!(matched_subject, "group:other");
}

#[tokio::test]
async fn per_user_credential_mode_is_selected_and_unconfigured_mode_fails_closed() {
    let mut config = base_fake_config();
    let store_path = temp_path("per-user-mode-users.json");
    config.credentials.per_user.insert(
        "fake".to_string(),
        fake_per_user_credential(store_path.to_str().unwrap()),
    );
    config.policy.grants[0].credential_mode = "per_user".to_string();
    let runtime = BrokerRuntime::new(config.clone()).unwrap();

    let response = runtime
        .invoke(
            governed(OperationContext {
                agent_request_id: "agent-request".to_string(),
                broker_request_id: "broker-request".to_string(),
                identity: IdentityContext::anonymous(),
                service: "fake".to_string(),
                action: "echo".to_string(),
                source: SourceContext::unknown(),
            }),
            InvokeRequest {
                inputs: json!({"project": "TEST", "message": "hello"}),
                body_parts: vec![],
                ..InvokeRequest::new(json!({}))
            },
        )
        .await;

    assert_eq!(response.status, 200);
    assert_eq!(
        response.envelope.result.unwrap()["credentialMode"],
        json!("per_user")
    );

    let mut invalid_config = config;
    invalid_config.credentials.per_user.clear();
    let (audit, audit_registry) = test_audit_runtime_parts(None);
    let policy_snapshot = Arc::new(ArcSwap::from_pointee(PolicySnapshot::from_config(
        &invalid_config,
        0,
    )));
    let invalid_runtime = BrokerRuntime {
        effective_credentials: Arc::new(invalid_config.credentials.clone()),
        imported_catalog: runtime.imported_catalog.clone(),
        import_dispatch: runtime.import_dispatch.clone(),
        scoped_mcp: runtime.scoped_mcp.clone(),
        oauth: runtime.oauth.clone(),
        invocation_limits: runtime.invocation_limits.clone(),
        config: Arc::new(invalid_config),
        providers: runtime.providers.clone(),
        services: runtime.services.clone(),
        resource_types: runtime.resource_types.clone(),
        policy_snapshot,
        policy_mutation_lock: runtime.policy_mutation_lock.clone(),
        identity_sources: runtime.identity_sources.clone(),
        managed_store: None,
        credential_key_ring: None,
        trusted_callers: Arc::new(Vec::new()),
        broker_token_hasher: None,
        local_password_hasher: None,
        browser_csrf_key: None,
        microsoft_oidc: None,
        network: runtime.network.clone(),
        audit,
        audit_registry,
        node_id: Arc::clone(&runtime.node_id),
        config_generation: None,
        provider_fixtures: ProviderFixtureSlot::default(),
    };
    let response = invalid_runtime
        .invoke(
            governed(OperationContext {
                agent_request_id: "agent-request".to_string(),
                broker_request_id: "broker-request".to_string(),
                identity: IdentityContext::anonymous(),
                service: "fake".to_string(),
                action: "echo".to_string(),
                source: SourceContext::unknown(),
            }),
            InvokeRequest {
                inputs: json!({"project": "TEST", "message": "hello"}),
                body_parts: vec![],
                ..InvokeRequest::new(json!({}))
            },
        )
        .await;

    assert_eq!(response.status, 403);
    assert_eq!(
        response.envelope.reason_code,
        Some(ReasonCode::CredentialNotProvisioned.into())
    );
}

#[tokio::test]
async fn fake_input_schema_is_enforced_before_credential_selection() {
    let audit_path = temp_path("input-invalid.audit.jsonl");
    let mut config = base_fake_config();
    config.audit = Some(jsonl_audit_config(audit_path.display().to_string()));
    let runtime = BrokerRuntime::new(config).unwrap();

    let response = runtime
        .invoke(
            governed(OperationContext {
                agent_request_id: "agent-request".to_string(),
                broker_request_id: "broker-request".to_string(),
                identity: IdentityContext::anonymous(),
                service: "fake".to_string(),
                action: "echo".to_string(),
                source: SourceContext::unknown(),
            }),
            InvokeRequest {
                inputs: json!({"project": "TEST", "extra": true}),
                body_parts: vec![],
                ..InvokeRequest::new(json!({}))
            },
        )
        .await;

    assert_eq!(response.status, 400);
    assert_eq!(
        response.envelope.reason_code,
        Some(ReasonCode::InputInvalid.into())
    );
    let audit = fs::read_to_string(audit_path).unwrap();
    assert!(audit.contains("\"reasonCode\":\"input_invalid\""));
    assert!(!audit.contains("credentialMode"));
}

#[test]
fn split_service_action_uses_first_dot() {
    assert_eq!(
        split_service_action("fake.echo.more").unwrap(),
        ("fake".to_string(), "echo.more".to_string())
    );
    assert!(split_service_action("fake").is_err());
}

#[test]
fn cli_exit_code_mapping_matches_contract() {
    assert_eq!(cli_exit_code_for_http_status(200), 0);
    assert_eq!(cli_exit_code_for_http_status(400), 3);
    assert_eq!(cli_exit_code_for_http_status(401), 6);
    assert_eq!(cli_exit_code_for_http_status(403), 2);
    assert_eq!(cli_exit_code_for_http_status(409), 2);
    assert_eq!(cli_exit_code_for_http_status(424), 4);
    assert_eq!(cli_exit_code_for_http_status(429), 7);
    assert_eq!(cli_exit_code_for_http_status(503), 5);
    assert_eq!(cli_exit_code_for_http_status(500), 5);
}

#[test]
fn runtime_can_use_explicit_egress_environment_for_tests() {
    let environment = EgressProxyEnvironment::from_lookup(|name| {
        Ok((name == "HTTPS_PROXY").then(|| "http://proxy.example:8080".to_string()))
    })
    .unwrap();
    let runtime =
        BrokerRuntime::new_with_egress_environment(base_fake_config(), environment).unwrap();

    assert!(runtime.config().providers.get_kind("jira").is_none());
}

#[test]
fn runtime_preflights_configured_proxy_secrets_even_when_no_proxy_matches() {
    let mut config = base_fake_config();
    config.network.egress_proxy = Some(agent_access_provider::EgressProxyConfig {
        url: "https://proxy.example:8443".to_string(),
        username_ref: Some("env:AGENT_ACCESS_MISSING_PROXY_USER".to_string()),
        password_ref: Some("env:AGENT_ACCESS_MISSING_PROXY_PASSWORD".to_string()),
    });
    let environment = EgressProxyEnvironment::from_lookup(|name| {
        Ok((name == "NO_PROXY").then(|| "*".to_string()))
    })
    .unwrap();

    let error = match BrokerRuntime::new_with_egress_environment(config, environment) {
        Ok(_) => panic!("expected missing proxy secret to fail startup"),
        Err(error) => error,
    };

    assert!(matches!(
        error,
        RuntimeError::MissingEnv {
            label,
            name
        } if label == "network.egress_proxy.username_ref"
            && name == "AGENT_ACCESS_MISSING_PROXY_USER"
    ));
}

#[test]
fn runtime_preflights_gateway_proxy_secrets() {
    let mut config = base_fake_config();
    config.credentials.service.insert(
        "gitlab_git".to_string(),
        fake_service_credential("env:GITLAB_SERVICE_TOKEN"),
    );
    config.gateways.insert(
        "gitlab_git".to_string(),
        crate::GatewayConfig {
            allow_forwarded_identity: false,
            kind: "git_http".to_string(),
            display_name: "GitLab Git".to_string(),
            broker_hosts: vec!["git.example.test".to_string()],
            upstream_base_url: "https://gitlab.example.com".to_string(),
            allowed_upstream_hosts: vec!["https://gitlab.example.com/**".to_string()],
            egress_proxy: Some(agent_access_provider::EgressProxyConfig {
                url: "https://proxy.example:8443".to_string(),
                username_ref: Some("env:AGENT_ACCESS_MISSING_GATEWAY_PROXY_USER".to_string()),
                password_ref: Some("env:AGENT_ACCESS_MISSING_GATEWAY_PROXY_PASSWORD".to_string()),
            }),
            auth_modes: vec!["basic_broker_token".to_string()],
            basic_broker_token_username: "agent-access".to_string(),
            credential_modes: vec!["service".to_string()],
            redirect_policy: "none".to_string(),
            request_body_max_bytes: None,
            response_body_max_bytes: None,
            streaming_idle_timeout_ms: None,
            correlation_headers: true,
            git: Some(crate::GatewayGitConfig {
                allow_fetch: true,
                allow_push: false,
                deny_ref_patterns: vec![],
                deny_delete_refs: true,
                receive_pack_prefix_max_bytes: Some(64 * 1024),
            }),
        },
    );

    let error = match BrokerRuntime::new(config) {
        Ok(_) => panic!("expected missing gateway proxy secret to fail startup"),
        Err(error) => error,
    };

    assert!(matches!(
        error,
        RuntimeError::MissingEnv {
            label,
            name
        } if label == "gateways.gitlab_git.egress_proxy.username_ref"
            && name == "AGENT_ACCESS_MISSING_GATEWAY_PROXY_USER"
    ));
}

#[test]
fn runtime_preflights_every_provider_proxy_even_when_environment_proxy_wins() {
    let proxy = || {
        Some(agent_access_provider::EgressProxyConfig {
            url: "https://proxy.example:8443".to_string(),
            username_ref: Some("env:AGENT_ACCESS_MISSING_PROVIDER_PROXY_USER".to_string()),
            password_ref: Some("env:AGENT_ACCESS_MISSING_PROVIDER_PROXY_PASSWORD".to_string()),
        })
    };
    for provider in ["gitlab", "cloudbees_ci"] {
        let mut config = base_fake_config();
        match provider {
            "gitlab" => {
                config
                    .providers
                    .insert(agent_access_gitlab::GitlabProviderConfig {
                        provisioning: agent_access_gitlab::GitlabProvisioningConfig::default(),
                        attachments: Default::default(),
                        api_base_url: "https://gitlab.example.com/api/v4".to_string(),
                        web_base_url: "https://gitlab.example.com".to_string(),
                        egress_proxy: proxy(),
                        allowed_upstream_hosts: vec![
                            "https://gitlab.example.com/api/v4/**".to_string(),
                        ],
                        content: agent_access_gitlab::GitlabContentConfig::default(),
                        search: agent_access_provider::SearchLimitsConfig::default(),
                        webhooks: agent_access_gitlab::GitlabWebhooksConfig::default(),
                    });
            }
            _ => {
                config
                    .providers
                    .insert(agent_access_cloudbees_ci::CloudbeesCiProviderConfig {
                        max_log_scan_bytes: 16 * 1024 * 1024,
                        controllers: BTreeMap::from([(
                            "team-ci".to_string(),
                            agent_access_cloudbees_ci::CloudbeesCiControllerConfig {
                                base_url: "https://ci.example/team-ci/".to_string(),
                                web_base_url: None,
                            },
                        )]),
                        egress_proxy: proxy(),
                        allowed_upstream_hosts: vec!["https://ci.example/team-ci/**".to_string()],
                    });
            }
        }
        // The environment proxy takes precedence when a request is routed, so
        // only the startup preflight can reject the unused provider setting.
        let environment =
            EgressProxyEnvironment::from_lookup(|name| {
                Ok((name == "HTTPS_PROXY")
                    .then(|| "http://environment-proxy.example:3128".to_string()))
            })
            .unwrap();

        let error = match BrokerRuntime::new_with_egress_environment(config, environment) {
            Ok(_) => panic!("expected missing {provider} proxy secret to fail startup"),
            Err(error) => error,
        };

        let expected_label = format!("providers.{provider}.egress_proxy.username_ref");
        assert!(
            matches!(
                &error,
                RuntimeError::MissingEnv { label, name }
                    if *label == expected_label
                        && name == "AGENT_ACCESS_MISSING_PROVIDER_PROXY_USER"
            ),
            "{provider}: {error:?}"
        );
    }
}

struct NamedServiceProvider(&'static str);

impl agent_access_provider::test_support::DescribedProvider for NamedServiceProvider {
    fn descriptor(&self) -> ServiceDescriptor {
        let mut descriptor = agent_access_fake::fake_descriptor();
        descriptor.service = self.0.to_string();
        descriptor
    }
}

#[async_trait]
impl Provider for NamedServiceProvider {
    async fn resolve_scopes(
        &self,
        request: ScopeRequest<'_>,
    ) -> Result<ScopeResolution, ProviderError> {
        agent_access_fake::FakeProvider
            .echo_scopes(request.action(), request.inputs())
            .map(ScopeResolution::resources)
    }

    async fn invoke(&self, request: ProviderInvocation) -> Result<ProviderResult, ProviderError> {
        agent_access_fake::FakeProvider.invoke(request).await
    }
}

#[test]
fn runtime_rejects_duplicate_provider_service_ids() {
    let error = match BrokerRuntime::with_providers(
        base_fake_config(),
        vec![
            agent_access_fake::fake_service_provider(),
            ServiceProvider::from(Arc::new(NamedServiceProvider("fake"))),
        ],
    ) {
        Ok(_) => panic!("expected duplicate provider service to fail startup"),
        Err(error) => error,
    };

    assert!(
        matches!(
            &error,
            RuntimeError::Config(ConfigError::Invalid { errors })
                if errors == &["service fake is registered by more than one provider".to_string()]
        ),
        "{error:?}"
    );
}

#[test]
fn runtime_rejects_provider_service_that_shadows_a_gateway() {
    let mut config = base_fake_config();
    config.credentials.service.insert(
        "gitlab_git".to_string(),
        fake_service_credential("env:GITLAB_SERVICE_TOKEN"),
    );
    config.gateways.insert(
        "gitlab_git".to_string(),
        crate::GatewayConfig {
            allow_forwarded_identity: false,
            kind: "git_http".to_string(),
            display_name: "GitLab Git".to_string(),
            broker_hosts: vec!["git.example.test".to_string()],
            upstream_base_url: "https://gitlab.example.com".to_string(),
            allowed_upstream_hosts: vec!["https://gitlab.example.com/**".to_string()],
            egress_proxy: None,
            auth_modes: vec!["basic_broker_token".to_string()],
            basic_broker_token_username: "agent-access".to_string(),
            credential_modes: vec!["service".to_string()],
            redirect_policy: "none".to_string(),
            request_body_max_bytes: None,
            response_body_max_bytes: None,
            streaming_idle_timeout_ms: None,
            correlation_headers: true,
            git: Some(crate::GatewayGitConfig {
                allow_fetch: true,
                allow_push: false,
                deny_ref_patterns: vec![],
                deny_delete_refs: true,
                receive_pack_prefix_max_bytes: Some(64 * 1024),
            }),
        },
    );

    let error = match BrokerRuntime::with_providers(
        config,
        vec![Arc::new(NamedServiceProvider("gitlab_git"))],
    ) {
        Ok(_) => panic!("expected provider shadowing a gateway to fail startup"),
        Err(error) => error,
    };

    assert!(
        matches!(
            &error,
            RuntimeError::Config(ConfigError::Invalid { errors })
                if errors == &["service gitlab_git is registered by a provider and also configured as gateways.gitlab_git".to_string()]
        ),
        "{error:?}"
    );
}

#[derive(Default)]
struct ResponseResolutionTraceProvider {
    scope_resolutions: AtomicUsize,
    invocations: AtomicUsize,
}

impl agent_access_provider::test_support::DescribedProvider for ResponseResolutionTraceProvider {
    fn descriptor(&self) -> ServiceDescriptor {
        agent_access_fake::fake_descriptor()
    }
}

impl ResponseResolutionTraceProvider {
    fn local_scopes(&self, action: &str, inputs: &Value) -> Result<ResourceScopes, ProviderError> {
        self.scope_resolutions.fetch_add(1, Ordering::SeqCst);
        agent_access_fake::FakeProvider.echo_scopes(action, inputs)
    }
}

#[async_trait]
impl Provider for ResponseResolutionTraceProvider {
    async fn resolve_scopes(
        &self,
        request: ScopeRequest<'_>,
    ) -> Result<ScopeResolution, ProviderError> {
        self.local_scopes(request.action(), request.inputs())
            .map(ScopeResolution::resources)
    }

    async fn invoke(&self, request: ProviderInvocation) -> Result<ProviderResult, ProviderError> {
        self.invocations.fetch_add(1, Ordering::SeqCst);
        agent_access_fake::FakeProvider.invoke(request).await
    }
}

struct CorrelationCaptureProvider;

struct BodyPartCorrelationCaptureProvider {
    captured_correlation: Arc<Mutex<Option<CorrelationContext>>>,
    captured_action: Arc<Mutex<Option<(String, String)>>>,
}

impl agent_access_provider::test_support::DescribedProvider for CorrelationCaptureProvider {
    fn descriptor(&self) -> ServiceDescriptor {
        let mut descriptor = agent_access_fake::fake_descriptor();
        descriptor.display_name = "Correlation Capture".to_string();
        descriptor.actions = vec![
            ActionDescriptor::new(
                "echo",
                "Capture invocation correlation",
                json!({
                    "type": "object",
                    "required": ["project", "message"],
                    "properties": {
                        "project": { "type": "string" },
                        "message": { "type": "string" }
                    },
                    "additionalProperties": false
                }),
            )
            .scope("project")
            .credential_modes(["service"]),
        ];
        descriptor
    }
}

impl CorrelationCaptureProvider {
    fn local_scopes(&self, action: &str, inputs: &Value) -> Result<ResourceScopes, ProviderError> {
        if action != "echo" {
            return Err(ProviderError::deny(
                ReasonCode::ServiceActionDenied,
                "capture action is not supported",
            ));
        }
        let project = inputs
            .get("project")
            .and_then(Value::as_str)
            .ok_or_else(|| ProviderError::deny(ReasonCode::InputInvalid, "project is required"))?;
        Ok(ResourceScopes::from([(
            "project".to_string(),
            vec![project.to_string()],
        )]))
    }
}

#[async_trait]
impl Provider for CorrelationCaptureProvider {
    async fn resolve_scopes(
        &self,
        request: ScopeRequest<'_>,
    ) -> Result<ScopeResolution, ProviderError> {
        self.local_scopes(request.action(), request.inputs())
            .map(ScopeResolution::resources)
    }

    async fn invoke(&self, request: ProviderInvocation) -> Result<ProviderResult, ProviderError> {
        Ok(ProviderResult::new(json!({
            "agentRequestId": request.correlation().agent_request_id,
            "brokerRequestId": request.correlation().broker_request_id,
            "executionContext": request.execution_context(),
        })))
    }
}

impl agent_access_provider::test_support::DescribedProvider for BodyPartCorrelationCaptureProvider {
    fn descriptor(&self) -> ServiceDescriptor {
        agent_access_fake::fake_descriptor()
    }
}

#[async_trait]
impl Provider for BodyPartCorrelationCaptureProvider {
    async fn resolve_scopes(
        &self,
        request: ScopeRequest<'_>,
    ) -> Result<ScopeResolution, ProviderError> {
        agent_access_fake::FakeProvider
            .echo_scopes(request.action(), request.inputs())
            .map(ScopeResolution::resources)
    }

    async fn authorize_body_parts(
        &self,
        request: &AdmittedRequest,
        _state: Option<&ProviderState>,
    ) -> Result<BodyAdmission, ProviderError> {
        *self.captured_correlation.lock().unwrap() = current_correlation_context();
        *self.captured_action.lock().unwrap() = current_provider_action();
        assert_eq!(
            request.correlation(),
            &CorrelationContext::new(
                "agent-body-preflight-id".to_string(),
                "broker-body-preflight-id".to_string()
            )
        );
        Ok(BodyAdmission::new(
            vec![BrokerBodyPartSpec::new(
                "attachment".to_string(),
                "upload.bin".to_string(),
                "application/octet-stream".to_string(),
                7,
                "sha256".to_string(),
            )],
            StateDisposition::Keep,
        ))
    }

    async fn invoke(&self, _request: ProviderInvocation) -> Result<ProviderResult, ProviderError> {
        Ok(ProviderResult::new(json!({})))
    }
}

pub(super) fn base_fake_config() -> BrokerConfig {
    let deployment = DeploymentConfig {
        enable_fake_service: true,
        ..DeploymentConfig::default()
    };
    let key_path =
        write_temp_secret(&base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([19_u8; 32]));
    BrokerConfig {
        imports: Default::default(),
        oauth: Default::default(),
        deployment,
        network: crate::NetworkConfig::default(),
        identity: IdentityConfig {
            trusted_callers: BTreeMap::new(),
            mode: "anonymous".to_string(),
            authority: "toml".to_string(),
            sources: vec![],
            groups: vec![
                identity_group("agents", vec![]),
                identity_group("other", vec![]),
            ],
        },
        credentials: CredentialsConfig {
            imported_modes: Default::default(),
            service: BTreeMap::from([(
                "fake".to_string(),
                fake_service_credential("env:FAKE_SERVICE_TOKEN"),
            )]),
            per_user: BTreeMap::new(),
            lookup: BTreeMap::new(),
        },
        managed_store: None,
        credential_encryption: Some(CredentialEncryptionConfig {
            active_key: "fixture".into(),
            keys: vec![CredentialEncryptionKeyConfig {
                id: "fixture".into(),
                provider: "file".into(),
                env: None,
                path: Some(key_path.display().to_string()),
            }],
        }),
        management: crate::ManagementConfig::default(),
        broker_tokens: None,
        execution_context: None,
        browser_auth: crate::BrowserAuthConfig::default(),
        portal: crate::PortalConfig::default(),
        mcp: Default::default(),
        policy: crate::PolicyConfig {
            authority: "toml".to_string(),
            default_decision: "deny".to_string(),
            resources: test_resources(),
            resource_groups: vec![],
            grants: vec![PolicyGrantConfig {
                subjects: vec!["group:anonymous".to_string()],
                service: "fake".to_string(),
                actions: vec!["echo".to_string()],
                resources: resource_selection(&["fake-project-TEST"]),
                execution_contexts: None,
                credential_mode: "service".to_string(),
                priority: None,
            }],
        },
        attribution: crate::AttributionConfig::default(),
        providers: crate::ProvidersConfig::new(crate::tests::test_backend_registry())
            .with(agent_access_fake::FakeProviderConfig::default()),
        gateways: BTreeMap::new(),
        limits: crate::LimitsConfig::default(),
        audit: None,
    }
}

fn multi_subject_fake_config(subjects: Vec<&str>) -> BrokerConfig {
    let token_path = write_temp_secret("agent-token");
    let mut config = base_fake_config();
    config.identity = static_identity_config(
        "required",
        &token_path,
        "agent-one",
        vec!["agents".to_string(), "other".to_string()],
    );
    config.policy.grants = vec![PolicyGrantConfig {
        subjects: subjects.into_iter().map(ToString::to_string).collect(),
        service: "fake".to_string(),
        actions: vec!["echo".to_string()],
        resources: resource_selection(&["fake-project-TEST"]),
        execution_contexts: None,
        credential_mode: "service".to_string(),
        priority: None,
    }];
    config
}

async fn invoke_fake_echo_and_return_matched_subject(
    mut config: BrokerConfig,
    identity: IdentityContext,
    audit_name: &str,
) -> String {
    let audit_path = temp_path(audit_name);
    config.audit = Some(jsonl_audit_config(audit_path.display().to_string()));
    let runtime = BrokerRuntime::new(config).unwrap();
    let response = runtime
        .invoke(
            governed(OperationContext {
                agent_request_id: "agent-request".to_string(),
                broker_request_id: "broker-request".to_string(),
                identity,
                service: "fake".to_string(),
                action: "echo".to_string(),
                source: SourceContext::unknown(),
            }),
            InvokeRequest {
                inputs: json!({"project": "TEST", "message": "hello"}),
                body_parts: vec![],
                ..InvokeRequest::new(json!({}))
            },
        )
        .await;
    assert_eq!(response.status, 200);
    assert_eq!(
        response.envelope.result.unwrap()["credentialMode"],
        json!("service")
    );
    runtime
        .shutdown_audit(Duration::from_secs(1))
        .await
        .unwrap();
    audit_records(&audit_path)
        .into_iter()
        .find(|record| {
            record["service"] == "fake"
                && record["action"] == "echo"
                && record["decision"] == "allow"
        })
        .and_then(|record| {
            record["matchedGrant"]["subject"]
                .as_str()
                .map(ToString::to_string)
        })
        .expect("fake invoke allow audit includes matched subject")
}

fn git_gateway_config() -> crate::GatewayConfig {
    crate::GatewayConfig {
        allow_forwarded_identity: false,
        kind: "git_http".to_string(),
        display_name: "GitLab Git".to_string(),
        broker_hosts: vec!["git.example.test".to_string()],
        upstream_base_url: "https://gitlab.example.com".to_string(),
        allowed_upstream_hosts: vec!["https://gitlab.example.com/**".to_string()],
        egress_proxy: None,
        auth_modes: vec!["basic_broker_token".to_string()],
        basic_broker_token_username: "agent-access".to_string(),
        credential_modes: vec!["service".to_string()],
        redirect_policy: "none".to_string(),
        request_body_max_bytes: Some(1024 * 1024),
        response_body_max_bytes: Some(1024 * 1024),
        streaming_idle_timeout_ms: Some(30_000),
        correlation_headers: true,
        git: Some(crate::GatewayGitConfig {
            allow_fetch: true,
            allow_push: true,
            deny_ref_patterns: vec!["refs/heads/main".to_string()],
            deny_delete_refs: true,
            receive_pack_prefix_max_bytes: Some(65_536),
        }),
    }
}

fn git_verify_runtime_for_upstream(
    upstream_base_url: String,
    streaming_idle_timeout_ms: u64,
) -> (BrokerRuntime, IdentityContext, ExecutionCredential) {
    let identity_token_path = write_temp_secret("agent-one-token");
    let store_path = write_temp_secret(r#"{"credentials":[]}"#);
    let mut config = base_fake_config();
    config.identity =
        static_identity_config("required", &identity_token_path, "agent-one", Vec::new());
    config.credentials.per_user.insert(
        "gitlab_git".to_string(),
        fake_per_user_credential(store_path.to_str().unwrap()),
    );
    let mut gateway = git_gateway_config();
    gateway.credential_modes = vec!["per_user".to_string()];
    config.gateways.insert("gitlab_git".to_string(), gateway);
    config.policy.grants.push(PolicyGrantConfig {
        subjects: vec!["user:agent-one".to_string()],
        service: "gitlab_git".to_string(),
        actions: vec!["repo.fetch".to_string()],
        resources: resource_selection(&["repository-sip-service"]),
        execution_contexts: None,
        credential_mode: "per_user".to_string(),
        priority: None,
    });
    let runtime = BrokerRuntime::new(config).unwrap();
    let mut runtime_config = (*runtime.config).clone();
    let gateway = runtime_config.gateways.get_mut("gitlab_git").unwrap();
    gateway.upstream_base_url = upstream_base_url.clone();
    gateway.allowed_upstream_hosts = vec![format!("{upstream_base_url}/**")];
    gateway.streaming_idle_timeout_ms = Some(streaming_idle_timeout_ms);
    let runtime = runtime_with_replaced_config(&runtime, runtime_config);
    let identity = runtime.identity_from_principal_groups(
        "agent-one".to_string(),
        Some("agent-one".to_string()),
        Vec::new(),
        None,
        None,
    );
    let credential = bearer_credential("runtime-token");
    (runtime, identity, credential)
}

fn assert_runtime_config_error_contains(
    result: Result<BrokerRuntime, RuntimeError>,
    expected: &str,
) {
    let error = match result {
        Ok(_) => panic!("expected config admission error containing {expected:?}"),
        Err(error) => error,
    };
    let RuntimeError::Config(ConfigError::Invalid { errors }) = error else {
        panic!("expected config admission error containing {expected:?}");
    };
    assert!(
        errors.iter().any(|error| error.contains(expected)),
        "expected {expected:?} in config errors: {errors:#?}"
    );
}

struct ManagedPolicyGrantSeed<'a> {
    grant_id: &'a str,
    grant_order: i64,
    subjects: Vec<&'a str>,
    service: &'a str,
    actions: Vec<&'a str>,
    resources: Value,
    credential_mode: &'a str,
    priority: Option<i32>,
    version: i64,
    generation: u64,
}

fn managed_policy_fake_config(store_path: &Path) -> BrokerConfig {
    let mut config = base_fake_config();
    config.identity.authority = "managed".to_string();
    config.identity.groups.clear();
    config.policy.authority = "managed".to_string();
    config.policy.grants.clear();
    config.policy.resources.clear();
    config.policy.resource_groups.clear();
    seed_test_resource_catalog(store_path);
    config.managed_store = Some(ManagedStoreConfig {
        kind: "sqlite".to_string(),
        path: store_path.display().to_string(),
        require_registered_principal_for_invocation: false,
        auto_migrate: true,
    });
    config
}

fn microsoft_oidc_runtime_broker_config() -> BrokerConfig {
    let encode_key = |byte| base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([byte; 32]);
    let broker_token_key = write_temp_secret(&encode_key(1));
    let csrf_key = write_temp_secret(&encode_key(2));
    let password_pepper = write_temp_secret(&encode_key(3));
    let client_secret = write_temp_secret("runtime-client-secret");
    let flow_key = write_temp_secret(&encode_key(9));
    let mut config = base_fake_config();
    config.identity.authority = "managed".to_string();
    config.identity.groups.clear();
    config.managed_store = Some(ManagedStoreConfig {
        kind: "sqlite".to_string(),
        path: temp_path("microsoft-oidc-runtime.sqlite3")
            .display()
            .to_string(),
        require_registered_principal_for_invocation: true,
        auto_migrate: true,
    });
    config.management.enabled = true;
    config.broker_tokens = Some(BrokerTokensConfig {
        hash_key_ref: format!("file:{}", broker_token_key.display()),
        default_agent_invoke_ttl: Some("30d".to_string()),
        default_user_manage_ttl: Some("2h".to_string()),
        default_admin_ttl: Some("2h".to_string()),
        max_self_issued_agent_invoke_ttl: Some("30d".to_string()),
        ..BrokerTokensConfig::default()
    });
    config.browser_auth.enabled = true;
    config.browser_auth.public_origin = Some("https://broker.example.test".to_string());
    config.browser_auth.csrf_key_ref = Some(format!("file:{}", csrf_key.display()));
    config.browser_auth.local_password.enabled = true;
    config.browser_auth.local_password.pepper_ref =
        Some(format!("file:{}", password_pepper.display()));
    config.browser_auth.oidc.microsoft = crate::MicrosoftOidcConfig {
        enabled: true,
        tenant_id: Some("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa1".to_string()),
        client_id: Some("bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbb2".to_string()),
        client_secret_ref: Some(format!("file:{}", client_secret.display())),
        flow_key_ref: Some(format!("file:{}", flow_key.display())),
        ..crate::MicrosoftOidcConfig::default()
    };
    config
}

fn seed_managed_policy_grant(store_path: &Path, seed: ManagedPolicyGrantSeed<'_>) {
    let managed_store = ManagedStore::open(
        &ManagedStoreConfig {
            kind: "sqlite".to_string(),
            path: store_path.display().to_string(),
            require_registered_principal_for_invocation: false,
            auto_migrate: true,
        },
        ManagedStoreOpenMode::Startup,
    )
    .unwrap();
    drop(managed_store);
    let conn = rusqlite::Connection::open(store_path).unwrap();
    conn.execute_batch("PRAGMA foreign_keys = ON;").unwrap();
    let now = Utc::now().to_rfc3339();
    let actions_json = serde_json::to_string(&seed.actions).unwrap();
    let resources_json = serde_json::to_string(&seed.resources).unwrap();
    conn.execute(
        "UPDATE policy_revisions
         SET generation = ?1, updated_at = ?2, updated_by = 'admin'
         WHERE id = 1",
        rusqlite::params![i64::try_from(seed.generation).unwrap(), now],
    )
    .unwrap();
    conn.execute(
        "INSERT INTO policy_grants
         (grant_id, grant_order, service, actions_json, resources_json,
          credential_mode, priority, status, description, version, created_at, created_by,
          updated_at, updated_by, disabled_at, deleted_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 'active', NULL, ?8, ?9, 'admin', ?9, 'admin', NULL, NULL)",
        rusqlite::params![
            seed.grant_id,
            seed.grant_order,
            seed.service,
            actions_json,
            resources_json,
            seed.credential_mode,
            seed.priority,
            seed.version,
            now
        ],
    )
    .unwrap();
    for (index, subject) in seed.subjects.iter().enumerate() {
        conn.execute(
            "INSERT INTO policy_grant_subjects (grant_id, subject, subject_order)
             VALUES (?1, ?2, ?3)",
            rusqlite::params![seed.grant_id, subject, i64::try_from(index).unwrap()],
        )
        .unwrap();
    }
    conn.execute(
        "INSERT INTO policy_grant_contexts
         (grant_id, execution_context, context_order)
         VALUES (?1, ?2, 0)",
        rusqlite::params![seed.grant_id, DEFAULT_EXECUTION_CONTEXT],
    )
    .unwrap();
}

async fn read_test_http_headers(stream: &mut tokio::net::TcpStream) -> Vec<u8> {
    use tokio::io::AsyncReadExt;

    let mut request = Vec::new();
    let mut buffer = [0_u8; 1024];
    loop {
        let read = stream.read(&mut buffer).await.unwrap();
        assert_ne!(read, 0, "client closed before sending request headers");
        request.extend_from_slice(&buffer[..read]);
        if request.windows(4).any(|window| window == b"\r\n\r\n") {
            return request;
        }
    }
}

fn configure_lookup_trace_jira(config: &mut BrokerConfig) {
    config.deployment.enable_fake_service = false;
    config.providers.remove("fake");
    config
        .providers
        .insert(agent_access_jira::JiraProviderConfig {
            tenant_host: "example.atlassian.net".to_string(),
            cloud_id: None,
            egress_proxy: None,
            allowed_upstream_hosts: vec!["https://example.atlassian.net/rest/api/3/**".to_string()],
            attachments: agent_access_provider::AttachmentLimitsConfig::default(),
            content: agent_access_jira::JiraContentConfig {
                comment_formats: vec!["adf".to_string()],
                ..agent_access_jira::JiraContentConfig::default()
            },
            search: agent_access_provider::SearchLimitsConfig::default(),
            comments: agent_access_jira::JiraCommentsConfig::default(),
            issue_links: agent_access_jira::JiraIssueLinksConfig::default(),
        });
    config.credentials.service.clear();
    config.credentials.lookup.clear();
    config.credentials.per_user.clear();
}

fn configure_lookup_trace_confluence(config: &mut BrokerConfig) {
    config.deployment.enable_fake_service = false;
    config.providers.remove("fake");
    config
        .providers
        .insert(agent_access_confluence::ConfluenceProviderConfig {
            tenant_host: "example.atlassian.net".to_string(),
            cloud_id: None,
            egress_proxy: None,
            allowed_upstream_hosts: vec![
                "https://example.atlassian.net/wiki/rest/api/**".to_string(),
            ],
            attachments: agent_access_provider::AttachmentLimitsConfig::default(),
            content: agent_access_confluence::ConfluenceContentConfig {
                page_formats: vec!["storage".to_string(), "atlas_doc_format".to_string()],
                ..agent_access_confluence::ConfluenceContentConfig::default()
            },
            search: agent_access_provider::SearchLimitsConfig::default(),
        });
    config.credentials.service.clear();
    config.credentials.lookup.clear();
    config.credentials.per_user.clear();
}

fn configure_lookup_trace_service(config: &mut BrokerConfig, token: &str) {
    configure_lookup_trace_service_for_service(config, "jira", token);
}

fn configure_lookup_trace_service_for_service(
    config: &mut BrokerConfig,
    service: &str,
    token: &str,
) {
    config.credentials.service.insert(
        service.to_string(),
        lookup_trace_basic_credential(token, false),
    );
}

fn configure_lookup_trace_lookup(config: &mut BrokerConfig, token: &str) {
    configure_lookup_trace_lookup_for_service(config, "jira", token);
}

fn configure_lookup_trace_lookup_for_service(
    config: &mut BrokerConfig,
    service: &str,
    token: &str,
) {
    config.credentials.lookup.insert(
        service.to_string(),
        lookup_trace_basic_credential(token, true),
    );
}

fn configure_lookup_trace_per_user(config: &mut BrokerConfig, token: &str) {
    configure_lookup_trace_per_user_for_service(config, "jira", token);
}

fn configure_lookup_trace_missing_per_user(config: &mut BrokerConfig, token: &str) {
    let token_path = write_temp_secret(token);
    let store_body = format!(
        r#"{{"credentials":[{{"principal":"other-agent","type":"bearer_token","token_ref":"file:{}"}}]}}"#,
        token_path.display()
    );
    let store_path = write_temp_secret(&store_body);
    config.credentials.per_user.insert(
        "jira".to_string(),
        fake_per_user_credential(store_path.to_str().unwrap()),
    );
}

fn configure_lookup_trace_per_user_for_service(
    config: &mut BrokerConfig,
    service: &str,
    token: &str,
) {
    let token_path = write_temp_secret(token);
    let store_body = format!(
        r#"{{"credentials":[{{"principal":"agent-one","type":"bearer_token","token_ref":"file:{}"}}]}}"#,
        token_path.display()
    );
    let store_path = write_temp_secret(&store_body);
    config.credentials.per_user.insert(
        service.to_string(),
        fake_per_user_credential(store_path.to_str().unwrap()),
    );
}

fn lookup_trace_grant(
    mode: &str,
    priority: Option<i32>,
    resource_ids: &[&str],
) -> PolicyGrantConfig {
    lookup_trace_grant_for_service("jira", "issue.view", mode, priority, resource_ids)
}

fn lookup_trace_grant_for_service(
    service: &str,
    action: &str,
    mode: &str,
    priority: Option<i32>,
    resource_ids: &[&str],
) -> PolicyGrantConfig {
    PolicyGrantConfig {
        subjects: vec!["group:agents".to_string()],
        service: service.to_string(),
        actions: vec![action.to_string()],
        resources: resource_selection(resource_ids),
        execution_contexts: None,
        credential_mode: mode.to_string(),
        priority,
    }
}

fn lookup_trace_basic_credential(token: &str, read_only: bool) -> CredentialConfig {
    let username_path = write_temp_secret("trace@example.com");
    let token_path = write_temp_secret(token);
    CredentialConfig {
        kind: "basic_api_token".to_string(),
        username_ref: Some(format!("file:{}", username_path.display())),
        token_ref: Some(format!("file:{}", token_path.display())),
        provider: None,
        path: None,
        read_only: read_only.then_some(true),
        credential_name: None,
        profile: None,
    }
}

async fn invoke_lookup_trace(runtime: &BrokerRuntime, project: &str) -> BrokerResponse<Value> {
    invoke_lookup_trace_for_service(runtime, "jira", "issue.view", "project", project).await
}

async fn invoke_lookup_trace_in_context(
    runtime: &BrokerRuntime,
    project: &str,
    execution_context: &str,
) -> BrokerResponse<Value> {
    let mut inputs = serde_json::Map::new();
    inputs.insert("project".to_string(), json!(project));
    inputs.insert("message".to_string(), json!("hello"));
    runtime
        .invoke(
            GovernedOperationContext {
                operation: OperationContext {
                    agent_request_id: "agent-request".to_string(),
                    broker_request_id: "broker-request".to_string(),
                    identity: agent_one_identity(),
                    service: "jira".to_string(),
                    action: "issue.view".to_string(),
                    source: SourceContext::unknown(),
                },
                execution_context: ExecutionContext::new(execution_context).unwrap(),
            },
            InvokeRequest {
                inputs: Value::Object(inputs),
                body_parts: vec![],
                ..InvokeRequest::new(json!({}))
            },
        )
        .await
}

async fn invoke_lookup_trace_for_service(
    runtime: &BrokerRuntime,
    service: &str,
    action: &str,
    input_name: &str,
    value: &str,
) -> BrokerResponse<Value> {
    let mut inputs = serde_json::Map::new();
    inputs.insert(input_name.to_string(), json!(value));
    inputs.insert("message".to_string(), json!("hello"));
    runtime
        .invoke(
            governed(OperationContext {
                agent_request_id: "agent-request".to_string(),
                broker_request_id: "broker-request".to_string(),
                identity: agent_one_identity(),
                service: service.to_string(),
                action: action.to_string(),
                source: SourceContext::unknown(),
            }),
            InvokeRequest {
                inputs: Value::Object(inputs),
                body_parts: vec![],
                ..InvokeRequest::new(json!({}))
            },
        )
        .await
}

fn agent_one_identity() -> IdentityContext {
    IdentityContext {
        caller_id: None,
        principal: "agent-one".to_string(),
        principal_subject: Some("agent-one".to_string()),
        groups: vec!["agents".to_string()],
        policy_groups: vec!["agents".to_string()],
        authenticated: true,
        source: None,
    }
}

fn shell_token_identity(scopes: Value) -> IdentityContext {
    IdentityContext {
        caller_id: None,
        principal: "agent-one".to_string(),
        principal_subject: Some("agent-one".to_string()),
        groups: vec!["agents".to_string()],
        policy_groups: vec!["agents".to_string()],
        authenticated: true,
        source: Some(IdentitySourceAudit {
            namespace: None,
            binding_id: None,
            name: "broker".to_string(),
            kind: "broker_tokens".to_string(),
            token_header: "Authorization".to_string(),
            token_scheme: "Bearer".to_string(),
            token_class: Some(BrokerTokenClass::AgentInvoke),
            token_id: Some("tok_shell".to_string()),
            token_scopes: Some(scopes),
        }),
    }
}

fn assert_lookup_observations(
    observations: &Arc<Mutex<Vec<CredentialObservation>>>,
    expected: &[(&str, &str)],
) {
    let actual = observations
        .lock()
        .unwrap()
        .iter()
        .map(|observation| {
            (
                observation.operation.clone(),
                observation.token.clone().unwrap_or_default(),
            )
        })
        .collect::<Vec<_>>();
    let expected = expected
        .iter()
        .map(|(operation, token)| (operation.to_string(), token.to_string()))
        .collect::<Vec<_>>();
    assert_eq!(actual, expected);
}

fn static_identity_config(
    mode: &str,
    token_path: &std::path::Path,
    subject: &str,
    groups: Vec<String>,
) -> IdentityConfig {
    IdentityConfig {
        trusted_callers: BTreeMap::new(),
        mode: mode.to_string(),
        authority: "toml".to_string(),
        sources: vec![IdentitySourceConfig {
            name: "local".to_string(),
            kind: "static_principals".to_string(),
            header: "X-Agent-Access-Identity-Token".to_string(),
            scheme: "raw".to_string(),
            principals: vec![StaticPrincipalConfig {
                principal: subject.to_string(),
                token_refs: vec![format!("file:{}", token_path.display())],
            }],
        }],
        groups: groups
            .into_iter()
            .map(|group| identity_group(&group, vec![subject.to_string()]))
            .collect(),
    }
}

fn identity_group(id: &str, members: Vec<String>) -> IdentityGroupConfig {
    IdentityGroupConfig {
        id: id.to_string(),
        status: "active".to_string(),
        members,
    }
}

fn static_bearer_source_config(
    name: &str,
    principal: &str,
    token_refs: Vec<String>,
) -> IdentitySourceConfig {
    IdentitySourceConfig {
        name: name.to_string(),
        kind: "static_principals".to_string(),
        header: "Authorization".to_string(),
        scheme: "Bearer".to_string(),
        principals: vec![StaticPrincipalConfig {
            principal: principal.to_string(),
            token_refs,
        }],
    }
}

fn duplicate_static_token_error(config: BrokerConfig) -> String {
    let error = match BrokerRuntime::new(config) {
        Ok(_) => panic!("expected duplicate static token to fail startup"),
        Err(error) => error,
    };
    let RuntimeError::Config(error) = error else {
        panic!("expected config error for duplicate static token");
    };
    error.errors().join("\n")
}

fn fake_per_user_credential(path: &str) -> CredentialConfig {
    CredentialConfig {
        kind: "secret_store".to_string(),
        username_ref: None,
        token_ref: None,
        provider: Some("local_file".to_string()),
        path: Some(path.to_string()),
        read_only: None,
        credential_name: None,
        profile: None,
    }
}

fn write_temp_secret(value: &str) -> PathBuf {
    let path = temp_path("secret.txt");
    fs::write(&path, value).unwrap();
    path
}

pub(super) fn temp_path(name: &str) -> PathBuf {
    let mut dir = std::env::temp_dir();
    dir.push(format!("agent-access-{}", Uuid::new_v4()));
    fs::create_dir_all(&dir).unwrap();
    #[cfg(unix)]
    fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();
    dir.join(name)
}

#[test]
fn per_user_credential_onboarding_follows_authored_grants_with_no_current_access() {
    for unavailable in ["empty", "disabled", "context"] {
        let mut config = base_fake_config();
        configure_lookup_trace_jira(&mut config);
        configure_lookup_trace_per_user(&mut config, "user-token");
        config.policy.grants = vec![lookup_trace_grant("per_user", None, &["project-ENG"])];
        match unavailable {
            "empty" => config.policy.grants[0].resources = ResourceSelection::default(),
            "disabled" => {
                config
                    .policy
                    .resources
                    .iter_mut()
                    .find(|entry| entry.id == "project-ENG")
                    .unwrap()
                    .enabled = false
            }
            _ => {
                config.execution_context = Some(crate::ExecutionContextConfig {
                    allowed_values: vec!["default".into(), "external".into()],
                    default_context: None,
                });
                config
                    .policy
                    .resources
                    .iter_mut()
                    .find(|entry| entry.id == "project-ENG")
                    .unwrap()
                    .allowed_execution_contexts = vec!["external".into()];
                config.policy.grants[0].execution_contexts = Some(vec!["default".into()]);
            }
        }
        let runtime =
            BrokerRuntime::with_providers(config, vec![Arc::new(LookupTraceProvider::default())])
                .unwrap();
        assert!(
            runtime.has_any_per_user_policy_for_service(&agent_one_identity(), "jira"),
            "{unavailable}"
        );
        assert!(
            !runtime.has_any_per_user_policy_for_service(&IdentityContext::anonymous(), "jira")
        );
        assert!(
            runtime
                .agent_token_options_for_identity(&agent_one_identity())
                .services[0]
                .actions[0]
                .effective_access_by_execution_context
                .values()
                .all(Vec::is_empty)
        );
    }
}

#[test]
fn personal_setup_grant_requires_subject_service_action_and_per_user_support() {
    let runtime = BrokerRuntime::new(base_fake_config()).unwrap();
    let service = runtime.services.get("fake").unwrap();
    for (subject, target, action, mode, expected) in [
        ("user:agent-one", "fake", "echo", "per_user", true),
        ("group:agents", "fake", "echo", "per_user", true),
        ("user:someone-else", "fake", "echo", "per_user", false),
        ("group:other", "fake", "echo", "per_user", false),
        ("group:agents", "other", "echo", "per_user", false),
        ("group:agents", "fake", "missing", "per_user", false),
        ("group:agents", "fake", "echo", "service", false),
    ] {
        let grant = PolicyGrantConfig {
            subjects: vec![subject.into()],
            service: target.into(),
            actions: vec![action.into()],
            resources: ResourceSelection::default(),
            execution_contexts: Some(vec!["unavailable".into()]),
            credential_mode: mode.into(),
            priority: Some(-100),
        };
        let grants = vec![RuntimePolicyGrant::from_toml(0, 0, subject, &grant)];
        assert_eq!(
            has_per_user_setup_grant(&agent_one_identity(), service, &grants),
            expected,
            "{subject} {target} {action} {mode}"
        );
        let mut unsupported = service.as_ref().clone();
        for action in &mut unsupported.actions {
            action.credential_modes.retain(|mode| mode != "per_user");
        }
        assert!(!has_per_user_setup_grant(
            &agent_one_identity(),
            &unsupported,
            &grants
        ));
    }
}

#[test]
fn personal_setup_admission_uses_transaction_groups_and_exclusive_policy_authority() {
    for authority in ["managed", "toml"] {
        let store_path = temp_path("personal-setup-admission.sqlite");
        let mut config = managed_policy_fake_config(&store_path);
        let credentials_path = write_temp_secret(r#"{"credentials":[]}"#);
        config.credentials.per_user.insert(
            "fake".into(),
            fake_per_user_credential(credentials_path.to_str().unwrap()),
        );
        let store = ManagedStore::open(
            config.managed_store.as_ref().unwrap(),
            ManagedStoreOpenMode::Startup,
        )
        .unwrap();
        store
            .create_group(crate::GroupWriteRequest {
                group_id: "agents".into(),
                display_name: None,
                description: None,
                created_by: "admin".into(),
            })
            .unwrap();
        store
            .create_or_update_principal(crate::PrincipalWriteRequest {
                principal_id: "agent-one".into(),
                kind: "user".into(),
                role: crate::PrincipalRole::User,
                self_service_enabled: Some(true),
                display_name: None,
                email: None,
                external_subject: None,
                created_by: "admin".into(),
            })
            .unwrap();
        store.add_group("agent-one", "agents", "admin").unwrap();
        drop(store);
        seed_managed_policy_grant(
            &store_path,
            ManagedPolicyGrantSeed {
                grant_id: "personal-setup",
                grant_order: 0,
                subjects: vec!["group:agents"],
                service: "fake",
                actions: vec!["echo"],
                resources: json!({}),
                credential_mode: "per_user",
                priority: None,
                version: 1,
                generation: 1,
            },
        );
        if authority == "toml" {
            config.policy.authority = "toml".into();
            config.policy.grants = vec![PolicyGrantConfig {
                subjects: vec!["group:agents".into()],
                service: "fake".into(),
                actions: vec!["echo".into()],
                resources: ResourceSelection::default(),
                execution_contexts: None,
                credential_mode: "per_user".into(),
                priority: None,
            }];
        }
        let runtime = BrokerRuntime::new(config).unwrap();
        let mut conn = rusqlite::Connection::open(&store_path).unwrap();
        let tx = conn
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .unwrap();
        let allowed = || {
            runtime
                .has_per_user_setup_grant_at_conn(&tx, "agent-one", "fake")
                .unwrap()
        };
        assert!(allowed(), "{authority}");
        tx.execute(
            "UPDATE policy_grants SET status='disabled' WHERE grant_id='personal-setup'",
            [],
        )
        .unwrap();
        assert_eq!(allowed(), authority == "toml", "{authority}");
        tx.execute(
            "UPDATE policy_grants SET status='active' WHERE grant_id='personal-setup'",
            [],
        )
        .unwrap();
        tx.execute(
            "DELETE FROM principal_groups WHERE principal_id='agent-one'",
            [],
        )
        .unwrap();
        assert!(!allowed(), "{authority}");
        // The caller's old identity and runtime policy snapshot still have the
        // group grant. Transactional admission must not reuse either one.
        assert!(runtime.has_any_per_user_policy_for_service(&agent_one_identity(), "fake"));
        tx.execute(
            "UPDATE policy_grant_subjects SET subject='user:agent-one' WHERE grant_id='personal-setup'",
            [],
        )
        .unwrap();
        assert_eq!(allowed(), authority == "managed", "{authority}");
        assert!(
            !runtime
                .has_per_user_setup_grant_at_conn(&tx, "agent-one", "missing")
                .unwrap()
        );
    }
}

#[test]
fn personal_setup_admission_uses_toml_identity_groups_instead_of_store_membership() {
    for toml_member in [false, true] {
        let store_path = temp_path("personal-setup-toml-groups.sqlite");
        let mut config = base_fake_config();
        let identity_token_path = write_temp_secret("personal-setup-identity");
        config.identity =
            static_identity_config("required", &identity_token_path, "agent-one", Vec::new());
        let credentials_path = write_temp_secret(r#"{"credentials":[]}"#);
        config.credentials.per_user.insert(
            "fake".into(),
            fake_per_user_credential(credentials_path.to_str().unwrap()),
        );
        config.identity.groups = vec![identity_group(
            "agents",
            if toml_member {
                vec!["agent-one".into()]
            } else {
                Vec::new()
            },
        )];
        config.policy.grants = vec![PolicyGrantConfig {
            subjects: vec!["group:agents".into()],
            service: "fake".into(),
            actions: vec!["echo".into()],
            resources: ResourceSelection::default(),
            execution_contexts: None,
            credential_mode: "per_user".into(),
            priority: None,
        }];
        config.managed_store = Some(ManagedStoreConfig {
            kind: "sqlite".into(),
            path: store_path.display().to_string(),
            require_registered_principal_for_invocation: false,
            auto_migrate: true,
        });
        let store = ManagedStore::open(
            config.managed_store.as_ref().unwrap(),
            ManagedStoreOpenMode::Startup,
        )
        .unwrap();
        store
            .create_group(crate::GroupWriteRequest {
                group_id: "agents".into(),
                display_name: None,
                description: None,
                created_by: "admin".into(),
            })
            .unwrap();
        store
            .create_or_update_principal(crate::PrincipalWriteRequest {
                principal_id: "agent-one".into(),
                kind: "user".into(),
                role: crate::PrincipalRole::User,
                self_service_enabled: Some(true),
                display_name: None,
                email: None,
                external_subject: None,
                created_by: "admin".into(),
            })
            .unwrap();
        if !toml_member {
            store.add_group("agent-one", "agents", "admin").unwrap();
        }
        let runtime = BrokerRuntime::new(config).unwrap();
        let mut conn = rusqlite::Connection::open(&store_path).unwrap();
        let tx = conn
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .unwrap();
        assert_eq!(
            runtime
                .has_per_user_setup_grant_at_conn(&tx, "agent-one", "fake")
                .unwrap(),
            toml_member,
            "configured membership must win over contradictory database membership"
        );
    }
}

#[tokio::test]
async fn search_audit_preserves_exclusions_when_credential_resolution_fails() {
    let provider = Arc::new(SearchPreflightTraceProvider::default());
    let preflights = provider.preflights();
    let mut config = base_fake_config();
    configure_lookup_trace_jira(&mut config);
    configure_lookup_trace_service(&mut config, "service-token");
    let audit_path = temp_path("search-credential-failure.audit.jsonl");
    config.audit = Some(jsonl_audit_config(audit_path.display().to_string()));
    config
        .policy
        .resource_groups
        .push(crate::ResourceGroupDefinition {
            id: "all-except-eng".into(),
            name: "All except ENG".into(),
            included_resource_ids: vec!["project-all".into()],
            excluded_resource_ids: vec!["project-ENG".into()],
        });
    let mut grant = lookup_trace_grant_for_service("jira", "search", "service", None, &[]);
    grant.resources.resource_group_ids = vec!["all-except-eng".into()];
    config.policy.grants = vec![grant];
    // Configuration is valid, but the secret becomes unavailable before execution.
    let runtime = BrokerRuntime::with_providers(config, vec![provider]).unwrap();
    let token_ref = &runtime.config.credentials.service["jira"].token_ref;
    let path = token_ref.as_ref().unwrap().strip_prefix("file:").unwrap();
    fs::remove_file(path).unwrap();
    let response = runtime
        .invoke(
            governed(OperationContext {
                agent_request_id: "search-audit-failure".into(),
                broker_request_id: "search-audit-failure-broker".into(),
                identity: agent_one_identity(),
                service: "jira".into(),
                action: "search".into(),
                source: SourceContext::unknown(),
            }),
            InvokeRequest::new(json!({"query":"status = Open"})),
        )
        .await;
    assert_ne!(response.status, 200);
    assert!(preflights.lock().unwrap().is_empty());
    runtime
        .shutdown_audit(Duration::from_secs(1))
        .await
        .unwrap();
    let records = audit_records(&audit_path);
    let record = records
        .iter()
        .find(|record| record["agentRequestId"] == "search-audit-failure")
        .unwrap();
    assert_eq!(
        record["searchAuthorization"]["scope"],
        json!({"type":"all_except","excludedValues":["ENG"]})
    );
}

#[test]
fn resource_previews_resolve_hidden_and_mixed_live_references_exactly() {
    let mut config = base_fake_config();
    config
        .policy
        .resource_groups
        .push(crate::ResourceGroupDefinition {
            id: "hidden-group".into(),
            name: "Hidden".into(),
            included_resource_ids: vec!["fake-project-all".into()],
            excluded_resource_ids: vec!["fake-project-TEST".into()],
        });
    config.policy.resources.push(crate::ResourceDefinition {
        id: "foreign-repo".into(),
        display_name: None,
        resource_type: agent_access_provider::GIT_REPOSITORY_RESOURCE.id().clone(),
        selector: ResourceSelector::Exact {
            value: "foreign/repo".into(),
        },
        allowed_execution_contexts: vec!["default".into()],
        enabled: true,
    });
    config
        .policy
        .resource_groups
        .push(crate::ResourceGroupDefinition {
            id: "foreign-group".into(),
            name: "Foreign".into(),
            included_resource_ids: vec!["foreign-repo".into()],
            excluded_resource_ids: vec![],
        });
    config
        .policy
        .resources
        .iter_mut()
        .find(|resource| resource.id == "fake-project-OPS")
        .unwrap()
        .enabled = false;
    config
        .policy
        .resource_groups
        .push(crate::ResourceGroupDefinition {
            id: "empty-group".into(),
            name: "Empty".into(),
            included_resource_ids: vec![],
            excluded_resource_ids: vec![],
        });
    let runtime = BrokerRuntime::new(config).unwrap();
    let identity = IdentityContext::anonymous();
    let options = runtime.agent_token_options_for_identity(&identity);
    assert!(
        !options
            .resource_groups
            .iter()
            .any(|group| group.id == "hidden-group")
    );
    for id in ["hidden-group", "missing-group"] {
        let caveats = AgentInvokeTokenCaveats {
            allowed_services: None,
            allowed_execution_contexts: None,
            service_restrictions: Some(BTreeMap::from([(
                "fake".into(),
                crate::AgentTokenServiceRestriction {
                    actions: vec!["echo".into()],
                    resources: Some(ResourceSelection {
                        resource_ids: vec!["fake-project-TEST".into()],
                        resource_group_ids: vec![id.into()],
                    }),
                },
            )])),
        };
        assert!(
            runtime
                .preview_agent_token_access(&identity, &caveats)
                .unwrap()
                .access
                .is_empty()
        );
    }
    for (id, allows_test) in [
        ("foreign-group", true),
        ("empty-group", true),
        ("missing-group", false),
    ] {
        assert!(!options.resource_groups.iter().any(|group| group.id == id));
        let selection = ResourceSelection {
            resource_ids: vec!["fake-project-TEST".into(), "fake-project-OPS".into()],
            resource_group_ids: vec![id.into()],
        };
        let preview = runtime
            .preview_policy_resources(
                "fake",
                &["echo".into()],
                &[default_execution_context()],
                &selection,
            )
            .unwrap();
        assert_eq!(!preview.access.is_empty(), allows_test);
        let caveats = AgentInvokeTokenCaveats {
            allowed_services: None,
            allowed_execution_contexts: None,
            service_restrictions: Some(BTreeMap::from([(
                "fake".into(),
                crate::AgentTokenServiceRestriction {
                    actions: vec!["echo".into()],
                    resources: Some(selection),
                },
            )])),
        };
        let token_preview = runtime
            .preview_agent_token_access(&identity, &caveats)
            .unwrap();
        assert_eq!(!token_preview.access.is_empty(), allows_test);
        if allows_test {
            assert!(
                token_preview.access[0]
                    .clauses
                    .iter()
                    .any(|clause| clause.matches("TEST"))
            );
            assert!(
                !token_preview.access[0]
                    .clauses
                    .iter()
                    .any(|clause| clause.matches("OPS"))
            );
        }
    }
    let valid = runtime
        .preview_policy_resources(
            "fake",
            &["echo".into()],
            &[default_execution_context()],
            &resource_selection(&["fake-project-TEST"]),
        )
        .unwrap();
    assert!(!valid.access.is_empty());
}

#[test]
fn initial_admin_bootstrap_rejects_reload_candidate_without_mutating_store() {
    let path = temp_path("reload-empty-bootstrap.sqlite");
    let store = ManagedStore::open(
        &ManagedStoreConfig {
            kind: "sqlite".into(),
            path: path.display().to_string(),
            auto_migrate: true,
            require_registered_principal_for_invocation: false,
        },
        ManagedStoreOpenMode::Startup,
    )
    .unwrap();
    let mut config = base_fake_config();
    config.management.enabled = true;
    config.management.initial_admin.mode = "create_if_empty".into();
    let error = prepare_managed_admin_roles(&config, Some(&store), None, false).unwrap_err();
    assert!(error.to_string().contains("requires startup"));
    assert_eq!(store.principal_count().unwrap(), 0);
}

#[test]
fn trusted_caller_credentials_are_distinct_and_rotation_changes_private_binding() {
    let path = write_temp_secret("distinct-caller-credential");
    let mut config = base_fake_config();
    let caller = crate::TrustedCallerConfig {
        credential_transport: crate::TrustedCallerCredentialTransport::CallerAuthorization,
        username_namespace: None,
        credential_ref: format!("file:{}", path.display()),
        context_mode: crate::TrustedCallerContextMode::Fixed,
        execution_context: Some("default".into()),
        allowed_execution_contexts: None,
        allow_forwarded_identity: false,
    };
    config
        .identity
        .trusted_callers
        .insert("first".into(), caller.clone());
    let original = BrokerRuntime::new(config.clone()).unwrap();
    let mut headers = HeaderMap::new();
    headers.insert(
        CALLER_AUTHORIZATION_HEADER,
        "Bearer distinct-caller-credential".parse().unwrap(),
    );
    let admission = original.admit_ingress(&headers).unwrap();
    assert_eq!(admission.caller_id(), Some("first"));
    assert!(admission.caller_binding().is_some());
    config
        .identity
        .trusted_callers
        .insert("second".into(), caller);
    assert!(BrokerRuntime::new(config.clone()).is_err());
    config.identity.trusted_callers.remove("second");
    fs::write(&path, "rotated-caller-credential").unwrap();
    let rotated = BrokerRuntime::new(config).unwrap();
    assert_eq!(
        rotated.admit_ingress(&headers).map(|_| ()),
        Err(IdentityFailure::CallerAuthenticationInvalid)
    );
    headers.insert(
        CALLER_AUTHORIZATION_HEADER,
        "Bearer rotated-caller-credential".parse().unwrap(),
    );
    assert_ne!(
        admission.caller_binding(),
        rotated.admit_ingress(&headers).unwrap().caller_binding()
    );
    fs::remove_file(path).unwrap();
}

#[tokio::test]
async fn predispatch_admission_preserves_retry_header_metadata_without_a_result() {
    let runtime = BrokerRuntime::new(base_fake_config()).unwrap();
    for (value, expected) in [
        (json!(12), Some(12)),
        (json!(0), None),
        (json!(86401), Some(86401)),
        (json!("12"), None),
    ] {
        let response = runtime
            .admission_limit_error_response(
                OperationContext {
                    agent_request_id: "agent-admission-retry".into(),
                    broker_request_id: "broker-admission-retry".into(),
                    identity: IdentityContext::anonymous(),
                    service: "fake".into(),
                    action: "echo".into(),
                    source: SourceContext::unknown(),
                },
                ProviderError::error(ReasonCode::RateLimited, "rate limited")
                    .with_result(json!({"retryAfterSeconds": value})),
            )
            .await;
        assert_eq!(response.status, 429);
        assert_eq!(response.envelope.service, "broker");
        assert_eq!(response.envelope.action, "request.admit");
        assert!(response.envelope.result.is_none());
        assert_eq!(response.retry_after_seconds, expected);
        assert!(
            serde_json::to_value(&response)
                .unwrap()
                .get("retryAfterSeconds")
                .is_none()
        );
    }
}

#[test]
fn unrelated_authorization_still_cannot_fall_back_to_forwarded_identity() {
    let mut config = base_fake_config();
    config.identity.mode = "anonymous".into();
    config.identity.sources.clear();
    let mut runtime = BrokerRuntime::new(config).unwrap();
    install_test_callers(&mut runtime, false, true);
    let mut headers = HeaderMap::new();
    headers.insert(
        CALLER_AUTHORIZATION_HEADER,
        "Bearer caller-shared-credential".parse().unwrap(),
    );
    headers.insert(
        "x-aw-identity-token-sha256",
        "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            .parse()
            .unwrap(),
    );
    headers.insert("authorization", "Bearer unknown".parse().unwrap());
    assert_eq!(
        runtime.resolve_identity(&headers).unwrap_err(),
        IdentityFailure::Invalid
    );
}
