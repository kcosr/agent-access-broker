use crate::BrokerBuildStatus;
use crate::handlers::management::common::{
    ManagementAccess, management_context, management_context_error_response,
    management_failure_envelope, management_response, management_success_envelope,
    management_success_response,
};
use crate::observability;
use crate::state::{AppState, ReloadableState, RuntimeSnapshot};
use agent_access_core::{
    AuditConfig, AuditRecord, AuditRuntimeRegistry, AuditStoreType, BackendRegistry, BrokerConfig,
    BrokerRuntime, ConfigError, RuntimeError, SourceContext, StateLockSet, audit_file_identity_key,
    load_broker_config_with_raw, new_broker_request_id, parse_broker_config_raw, resolve_node_id,
    validate_broker_config,
};
use agent_access_provider::{Decision, ReasonCode, ResourceScopes};
use axum::body::Bytes;
use axum::extract::{ConnectInfo, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::Response;
use chrono::Utc;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::net::SocketAddr;
use std::path::{Path as FsPath, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

pub(crate) const DEFAULT_RELOAD_TIMEOUT: Duration = Duration::from_secs(30);
pub(crate) const DEFAULT_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_RELOAD_TIMEOUT: Duration = Duration::from_secs(300);
const MAX_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(300);

#[derive(Debug, Clone)]
pub(crate) struct ReloadAttemptSummary {
    trigger: ReloadTrigger,
    attempted_at: String,
    decision: AdminDecision,
    reason_code: Option<ReasonCode>,
    candidate_config_hash: Option<String>,
    previous_generation: u64,
    active_generation: u64,
    message: Option<String>,
}

pub async fn build_reloadable_state(
    config_path: PathBuf,
    backends: Arc<BackendRegistry>,
    build_status: BrokerBuildStatus,
    body_hard_cap: Option<u64>,
    reload_timeout: Duration,
    shutdown_timeout: Duration,
) -> anyhow::Result<Arc<ReloadableState>> {
    validate_reload_timeout(reload_timeout)?;
    let (config, raw) = load_broker_config_with_raw(&config_path, &backends)?;
    let startup_body_limit = config
        .limits
        .max_http_body_bytes
        .try_into()
        .unwrap_or(usize::MAX);
    let hard_cap = body_hard_cap
        .map(validate_body_hard_cap_value)
        .transpose()?
        .unwrap_or(startup_body_limit);
    if startup_body_limit > hard_cap {
        anyhow::bail!("limits.max_http_body_bytes exceeds --max-http-body-hard-cap-bytes");
    }
    validate_broker_config(&config)?;
    let node_id = resolve_node_id(&config.deployment)?;
    let hash = config_hash(&raw);
    let state_locks = StateLockSet::acquire_for_config(&config, &config_path, &node_id, None)?;
    let audit_registry = Arc::new(AuditRuntimeRegistry::new());
    let runtime = BrokerRuntime::new_with_audit_registry(config, Arc::clone(&audit_registry))
        .map_err(|error| {
            let details = match &error {
                RuntimeError::Config(ConfigError::Invalid { errors }) => Some(errors.join("; ")),
                _ => None,
            };
            let error = anyhow::Error::new(error);
            match details {
                Some(details) => error.context(details),
                None => error,
            }
        })?
        .with_config_generation(1);
    runtime.local_state_readiness().await?;
    let snapshot =
        RuntimeSnapshot::new_microsoft_oidc_candidate(1, hash, runtime, state_locks).await?;
    snapshot.reconcile_microsoft_oidc_provider()?;
    Ok(Arc::new(ReloadableState::from_snapshot(
        config_path,
        backends,
        build_status,
        snapshot,
        hard_cap,
        reload_timeout,
        shutdown_timeout,
        audit_registry,
    )))
}

struct CandidateAdmission {
    config: BrokerConfig,
    hash: String,
    state_locks: Arc<StateLockSet>,
}

fn admit_candidate_config(
    config_path: &FsPath,
    backends: &Arc<BackendRegistry>,
    body_hard_cap: usize,
    live_locks: &[Arc<StateLockSet>],
    previous_runtime: &BrokerRuntime,
    deadline: &ReloadDeadline,
) -> Result<CandidateAdmission, ReloadFailure> {
    deadline.check()?;
    let (config, hash) = load_candidate_config(config_path, backends)?;
    deadline.set_candidate_config_hash(hash.clone());
    deadline.check_with_hash(Some(hash.clone()))?;
    validate_broker_config(&config).map_err(|error| {
        ReloadFailure::new(
            AdminDecision::Deny,
            ReasonCode::ConfigValidationFailed,
            config_error_messages(error),
            Some(hash.clone()),
        )
    })?;
    deadline.check_with_hash(Some(hash.clone()))?;
    validate_candidate_timeouts(deadline, &hash)?;
    deadline.check_with_hash(Some(hash.clone()))?;
    let candidate_body_limit = config
        .limits
        .max_http_body_bytes
        .try_into()
        .unwrap_or(usize::MAX);
    if candidate_body_limit > body_hard_cap {
        return Err(ReloadFailure::new(
            AdminDecision::Error,
            ReasonCode::ConfigAdmissionFailed,
            vec!["limits.max_http_body_bytes exceeds process body hard cap".to_string()],
            Some(hash),
        ));
    }
    let node_id = admit_restart_only_settings(previous_runtime, &config).map_err(|errors| {
        ReloadFailure::new(
            AdminDecision::Error,
            ReasonCode::ConfigAdmissionFailed,
            errors,
            Some(hash.clone()),
        )
    })?;
    let state_locks =
        StateLockSet::acquire_for_config_reusing(&config, config_path, &node_id, live_locks)
            .map_err(|error| {
                ReloadFailure::new(
                    AdminDecision::Error,
                    ReasonCode::ConfigAdmissionFailed,
                    vec![error.operator_message()],
                    Some(hash.clone()),
                )
            })?;
    Ok(CandidateAdmission {
        config,
        hash,
        state_locks,
    })
}

/// Rejects changes that only a restart may make: the audit backend type
/// (including enabling or disabling audit) and the effective node ID. Returns
/// the candidate's effective node ID.
fn admit_restart_only_settings(
    previous: &BrokerRuntime,
    candidate: &BrokerConfig,
) -> Result<String, Vec<String>> {
    let mut errors = Vec::new();
    let previous_type = previous.config().audit.as_ref().map(|audit| audit.kind);
    let candidate_type = candidate.audit.as_ref().map(|audit| audit.kind);
    if previous_type != candidate_type {
        errors.push(format!(
            "changing audit.type from {} to {} requires a restart",
            audit_type_label(previous_type),
            audit_type_label(candidate_type)
        ));
    }
    let node_id = match resolve_node_id(&candidate.deployment) {
        Ok(node_id) if node_id != previous.node_id() => {
            errors.push(format!(
                "changing the effective node ID from {:?} to {:?} requires a restart",
                previous.node_id(),
                node_id
            ));
            node_id
        }
        Ok(node_id) => node_id,
        Err(error) => {
            errors.push(error.to_string());
            String::new()
        }
    };
    if errors.is_empty() {
        Ok(node_id)
    } else {
        Err(errors)
    }
}

fn audit_type_label(kind: Option<AuditStoreType>) -> String {
    match kind {
        Some(kind) => format!("\"{}\"", kind.as_str()),
        None => "disabled (no [audit])".to_string(),
    }
}

fn build_candidate_runtime(
    admission: CandidateAdmission,
    generation: u64,
    previous_runtime: BrokerRuntime,
    deadline: ReloadDeadline,
) -> Result<CandidateRuntime, ReloadFailure> {
    let CandidateAdmission {
        config,
        hash,
        state_locks,
    } = admission;
    deadline.check_with_hash(Some(hash.clone()))?;
    let runtime = BrokerRuntime::new_for_reload(config, &previous_runtime)
        .map_err(|error| runtime_admission_failure(error, Some(hash.clone())))?
        .with_config_generation(generation);
    deadline.check_with_hash(Some(hash.clone()))?;
    let snapshot = RuntimeSnapshot::new(generation, hash.clone(), runtime, state_locks);
    Ok(CandidateRuntime {
        config_hash: hash,
        snapshot,
    })
}

fn load_candidate_config(
    config_path: &FsPath,
    backends: &Arc<BackendRegistry>,
) -> Result<(BrokerConfig, String), ReloadFailure> {
    let path_label = config_path.display().to_string();
    let raw = std::fs::read_to_string(config_path).map_err(|source| {
        ReloadFailure::new(
            AdminDecision::Error,
            ReasonCode::ConfigReadFailed,
            vec![format!("failed to read {path_label}: {source}")],
            None,
        )
    })?;
    let hash = config_hash(&raw);
    let config =
        parse_broker_config_raw(path_label.clone(), &raw, backends).map_err(
            |error| match error {
                ConfigError::Parse { path, source } => ReloadFailure::new(
                    AdminDecision::Deny,
                    ReasonCode::ConfigParseFailed,
                    vec![format!("failed to parse {path}: {source}")],
                    Some(hash.clone()),
                ),
                other => config_load_failure(other),
            },
        )?;
    Ok((config, hash))
}

fn validate_candidate_timeouts(deadline: &ReloadDeadline, hash: &str) -> Result<(), ReloadFailure> {
    deadline
        .remaining()
        .ok_or_else(|| reload_timeout_failure(Some(hash.to_string())))?;
    Ok(())
}

fn config_load_failure(error: ConfigError) -> ReloadFailure {
    match error {
        ConfigError::Read { path, source } => ReloadFailure::new(
            AdminDecision::Error,
            ReasonCode::ConfigReadFailed,
            vec![format!("failed to read {path}: {source}")],
            None,
        ),
        ConfigError::Parse { path, source } => ReloadFailure::new(
            AdminDecision::Deny,
            ReasonCode::ConfigParseFailed,
            vec![format!("failed to parse {path}: {source}")],
            None,
        ),
        ConfigError::Invalid { errors } => ReloadFailure::new(
            AdminDecision::Deny,
            ReasonCode::ConfigValidationFailed,
            errors,
            None,
        ),
    }
}

fn config_error_messages(error: ConfigError) -> Vec<String> {
    match error {
        ConfigError::Invalid { errors } => errors,
        ConfigError::Read { path, source } => vec![format!("failed to read {path}: {source}")],
        ConfigError::Parse { path, source } => vec![format!("failed to parse {path}: {source}")],
    }
}

fn runtime_admission_failure(error: RuntimeError, hash: Option<String>) -> ReloadFailure {
    let errors = match error {
        RuntimeError::Config(error) => config_error_messages(error),
        error => vec![error.to_string()],
    };
    ReloadFailure::new(
        AdminDecision::Error,
        ReasonCode::ConfigAdmissionFailed,
        errors,
        hash,
    )
}

fn reload_reason_message(reason_code: ReasonCode) -> &'static str {
    match reason_code {
        ReasonCode::RequestIdMissing => "request id is required",
        ReasonCode::RequestIdInvalid => "request id is invalid",
        ReasonCode::BodyMalformed => "config reload request body must be empty",
        ReasonCode::ReloadInProgress => "reload already in progress",
        ReasonCode::ConfigReadFailed => "config file could not be read",
        ReasonCode::ConfigParseFailed => "config file could not be parsed",
        ReasonCode::ConfigValidationFailed => "config validation failed",
        ReasonCode::ConfigAdmissionFailed => "config admission failed",
        _ => "request failed",
    }
}

fn reason_status(reason_code: ReasonCode) -> StatusCode {
    StatusCode::from_u16(reason_code.http_status()).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR)
}

fn reload_listener(trigger: ReloadTrigger, source: &SourceContext) -> &'static str {
    let _ = source;
    match trigger {
        ReloadTrigger::Signal => "signal",
        ReloadTrigger::AdminHttp => "public",
    }
}

pub(crate) async fn admin_config_reload(
    State(state): State<AppState>,
    ConnectInfo(remote): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let operation = crate::handlers::management::audit_actions::CONFIG_RELOAD;
    let context = match management_context(
        &state,
        remote,
        &headers,
        operation,
        ManagementAccess::AdminWrite,
    )
    .await
    {
        Ok(context) => context,
        Err(response) => return *response,
    };
    if !body.is_empty() {
        return management_context_error_response(
            &context,
            StatusCode::BAD_REQUEST,
            operation,
            ReasonCode::BodyMalformed,
            reload_reason_message(ReasonCode::BodyMalformed),
            None,
        )
        .await;
    }
    tracing::info!(
        event = "config_reload_requested",
        listener = "public",
        operation,
        agentRequestId = context.request_id.as_str(),
        brokerRequestId = context.broker_request_id.as_str(),
        principal = context.identity.principal.as_str(),
        configGeneration = context.snapshot.generation,
    );
    let response = state
        .reloadable
        .reload(
            ReloadTrigger::AdminHttp,
            context.request_id.clone(),
            context.broker_request_id.clone(),
            context.source.clone(),
            Some(context.identity.clone()),
        )
        .await;
    if response.status == StatusCode::OK {
        return management_response(
            StatusCode::OK,
            management_success_envelope(&context, operation, None, response.result),
        );
    }
    let reason_code = response
        .reason_code
        .unwrap_or(ReasonCode::ConfigAdmissionFailed);
    management_response(
        response.status,
        management_failure_envelope(
            &context,
            operation,
            response.decision.audit_decision(),
            reason_code,
            response
                .message
                .as_deref()
                .unwrap_or_else(|| reload_reason_message(reason_code)),
            None,
        ),
    )
}

pub(crate) async fn admin_config_status(
    State(state): State<AppState>,
    ConnectInfo(remote): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> Response {
    let operation = crate::handlers::management::audit_actions::CONFIG_STATUS;
    let context = match management_context(
        &state,
        remote,
        &headers,
        operation,
        ManagementAccess::AdminRead,
    )
    .await
    {
        Ok(context) => context,
        Err(response) => return *response,
    };
    let result = state.reloadable.status_result(&context.snapshot);
    management_success_response(&context, operation, None, result).await
}

/// The audit store of a generation for `config.status` and reload results:
/// `null` when audit is disabled, the backend type, and for SQLite the most
/// recent optional maintenance failure (or `null`). The path is not exposed.
fn audit_status_json(runtime: &agent_access_core::BrokerRuntime) -> Value {
    match runtime.audit_store() {
        None => Value::Null,
        Some(store) => match store.store_type() {
            agent_access_core::AuditStoreType::Sqlite => json!({
                "type": "sqlite",
                "maintenanceFailure": store.maintenance_failure(),
            }),
            agent_access_core::AuditStoreType::Jsonl => json!({ "type": "jsonl" }),
        },
    }
}

fn reload_attempt_summary_json(summary: ReloadAttemptSummary) -> Value {
    json!({
        "trigger": summary.trigger.as_str(),
        "attemptedAt": summary.attempted_at,
        "decision": summary.decision.as_str(),
        "reasonCode": summary.reason_code.map(ReasonCode::as_str),
        "candidateConfigHash": summary.candidate_config_hash,
        "previousGeneration": summary.previous_generation,
        "activeGeneration": summary.active_generation,
        "message": summary.message,
    })
}

struct AdminAuditInput<'a> {
    agent_request_id: &'a str,
    broker_request_id: &'a str,
    trigger: ReloadTrigger,
    operation: &'a str,
    decision: AdminDecision,
    reason_code: Option<ReasonCode>,
    source: &'a SourceContext,
    identity: Option<&'a agent_access_core::IdentityContext>,
    previous_generation: u64,
    active_generation: u64,
    previous_config_hash: Option<&'a str>,
    candidate_config_hash: Option<&'a str>,
    active_config_hash: Option<&'a str>,
    errors: &'a [String],
}

fn admin_audit_record(snapshot: &RuntimeSnapshot, input: &AdminAuditInput<'_>) -> AuditRecord {
    let (principal, principal_subject, groups, identity_source) = match input.trigger {
        ReloadTrigger::AdminHttp => {
            let identity = input
                .identity
                .expect("HTTP admin audit input includes identity");
            (
                identity.principal.clone(),
                identity.principal_subject.clone(),
                identity.groups.clone(),
                identity.source.clone(),
            )
        }
        ReloadTrigger::Signal => ("system".to_string(), None, vec!["system".to_string()], None),
    };
    let provider_audit = json!({
        "admin": {
            "operation": input.operation,
            "trigger": input.trigger.as_str(),
            "previousGeneration": input.previous_generation,
            "activeGeneration": input.active_generation,
            "previousConfigHash": input.previous_config_hash,
            "candidateConfigHash": input.candidate_config_hash,
            "activeConfigHash": input.active_config_hash,
            "reasonCode": input.reason_code.map(ReasonCode::as_str),
            "errors": input.errors,
        }
    });
    AuditRecord {
        caller_id: None,
        search_authorization: None,
        timestamp: Utc::now().to_rfc3339(),
        agent_request_id: input.agent_request_id.to_string(),
        broker_request_id: input.broker_request_id.to_string(),
        config_generation: Some(snapshot.generation),
        policy_generation: Some(snapshot.runtime.policy_generation()),
        principal,
        principal_subject,
        groups,
        service: "broker".to_string(),
        action: input.operation.to_string(),
        resource_scopes: ResourceScopes::new(),
        matched_grant: None,
        credential_mode: Some(None),
        decision: input.decision.audit_decision(),
        reason_code: None,
        upstream_status: None,
        upstream_duration_ms: None,
        object_ids: None,
        identity_source,
        source: input.source.clone(),
        execution_context: None,
        provider_audit: Some(provider_audit),
    }
}

async fn append_admin_audit(
    snapshot: Arc<RuntimeSnapshot>,
    input: &AdminAuditInput<'_>,
) -> Result<(), RuntimeError> {
    let record = admin_audit_record(&snapshot, input);
    snapshot.runtime.append_audit_record(&record).await
}

async fn append_admin_audit_best_effort(
    snapshot: Arc<RuntimeSnapshot>,
    input: AdminAuditInput<'_>,
) -> Option<String> {
    if let Err(error) = append_admin_audit(snapshot.clone(), &input).await {
        log_admin_audit_failure(&snapshot, &input, &error);
        return Some(error.to_string());
    }
    None
}

fn log_admin_audit_failure(
    snapshot: &RuntimeSnapshot,
    input: &AdminAuditInput<'_>,
    error: &RuntimeError,
) {
    tracing::error!(
        event = "admin_audit_append_failed",
        operation = input.operation,
        trigger = input.trigger.as_str(),
        decision = input.decision.as_str(),
        agentRequestId = input.agent_request_id,
        brokerRequestId = input.broker_request_id,
        configGeneration = snapshot.generation,
        activeGeneration = input.active_generation,
        reasonCode = input.reason_code.map(ReasonCode::as_str).unwrap_or(""),
        error = %error,
    );
}

/// Whether the candidate writes audit to a different store: another type or
/// another path identity.
fn audit_store_changed(previous: &RuntimeSnapshot, candidate: &RuntimeSnapshot) -> bool {
    audit_store_key(previous.runtime.config().audit.as_ref())
        != audit_store_key(candidate.runtime.config().audit.as_ref())
}

fn audit_store_key(audit: Option<&AuditConfig>) -> Option<(AuditStoreType, PathBuf)> {
    audit.map(|audit| {
        (
            audit.kind,
            audit_file_identity_key(FsPath::new(&audit.path)),
        )
    })
}

fn validate_body_hard_cap_value(value: u64) -> anyhow::Result<usize> {
    if value == 0 {
        anyhow::bail!("--max-http-body-hard-cap-bytes must be non-zero");
    }
    value
        .try_into()
        .map_err(|_| anyhow::anyhow!("--max-http-body-hard-cap-bytes is too large"))
}

pub fn validate_reload_timeout(timeout: Duration) -> anyhow::Result<()> {
    if timeout.is_zero() {
        anyhow::bail!("--reload-timeout-ms must be non-zero");
    }
    if timeout > MAX_RELOAD_TIMEOUT {
        anyhow::bail!("--reload-timeout-ms must be no greater than 300000");
    }
    Ok(())
}

pub fn validate_shutdown_timeout(timeout: Duration) -> anyhow::Result<()> {
    if timeout.is_zero() {
        anyhow::bail!("--shutdown-timeout-ms must be non-zero");
    }
    if timeout > MAX_SHUTDOWN_TIMEOUT {
        anyhow::bail!("--shutdown-timeout-ms must be no greater than 300000");
    }
    Ok(())
}

fn config_hash(raw: &str) -> String {
    let digest = Sha256::digest(raw.as_bytes());
    format!("sha256:{digest:x}")
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ReloadTrigger {
    AdminHttp,
    Signal,
}

impl ReloadTrigger {
    fn as_str(self) -> &'static str {
        match self {
            Self::AdminHttp => "admin_http",
            Self::Signal => "signal",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AdminDecision {
    Allow,
    Deny,
    Error,
}

impl AdminDecision {
    fn as_str(self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::Deny => "deny",
            Self::Error => "error",
        }
    }

    fn audit_decision(self) -> Decision {
        match self {
            Self::Allow => Decision::Allow,
            Self::Deny => Decision::Deny,
            Self::Error => Decision::Error,
        }
    }
}

struct CandidateRuntime {
    config_hash: String,
    snapshot: Arc<RuntimeSnapshot>,
}

#[derive(Clone)]
struct ReloadDeadline {
    expires_at: Instant,
    cancelled: Arc<AtomicBool>,
    candidate_config_hash: Arc<Mutex<Option<String>>>,
}

impl ReloadDeadline {
    fn new(timeout: Duration) -> Self {
        Self {
            expires_at: Instant::now() + timeout,
            cancelled: Arc::new(AtomicBool::new(false)),
            candidate_config_hash: Arc::new(Mutex::new(None)),
        }
    }

    fn check(&self) -> Result<(), ReloadFailure> {
        self.check_with_hash(None)
    }

    fn check_with_hash(&self, candidate_config_hash: Option<String>) -> Result<(), ReloadFailure> {
        if self.cancelled.load(Ordering::SeqCst) || Instant::now() >= self.expires_at {
            Err(reload_timeout_failure(
                candidate_config_hash.or_else(|| self.candidate_config_hash()),
            ))
        } else {
            Ok(())
        }
    }

    fn remaining(&self) -> Option<Duration> {
        self.expires_at.checked_duration_since(Instant::now())
    }

    fn set_candidate_config_hash(&self, hash: String) {
        *self.candidate_config_hash.lock().unwrap() = Some(hash);
    }

    fn candidate_config_hash(&self) -> Option<String> {
        self.candidate_config_hash.lock().unwrap().clone()
    }

    fn cancel(&self) {
        self.cancelled.store(true, Ordering::SeqCst);
    }
}

struct ReloadFailure {
    decision: AdminDecision,
    reason_code: ReasonCode,
    pub(crate) status: StatusCode,
    errors: Vec<String>,
    candidate_config_hash: Option<String>,
    event_kind: ReloadFailureEventKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReloadFailureEventKind {
    Failed,
    Rejected,
}

impl ReloadFailure {
    fn new(
        decision: AdminDecision,
        reason_code: ReasonCode,
        errors: Vec<String>,
        candidate_config_hash: Option<String>,
    ) -> Self {
        Self {
            decision,
            reason_code,
            status: reason_status(reason_code),
            errors,
            candidate_config_hash,
            event_kind: ReloadFailureEventKind::Failed,
        }
    }

    fn rejected(
        decision: AdminDecision,
        reason_code: ReasonCode,
        errors: Vec<String>,
        candidate_config_hash: Option<String>,
    ) -> Self {
        Self {
            decision,
            reason_code,
            status: reason_status(reason_code),
            errors,
            candidate_config_hash,
            event_kind: ReloadFailureEventKind::Rejected,
        }
    }

    fn event_name(&self) -> &'static str {
        match self.event_kind {
            ReloadFailureEventKind::Failed => "config_reload_failed",
            ReloadFailureEventKind::Rejected => "config_reload_rejected",
        }
    }
}

fn reload_timeout_failure(candidate_config_hash: Option<String>) -> ReloadFailure {
    ReloadFailure::rejected(
        AdminDecision::Error,
        ReasonCode::ConfigAdmissionFailed,
        vec!["reload admission timed out".to_string()],
        candidate_config_hash,
    )
}

pub(crate) struct ConfigOperationResponse {
    pub(crate) status: StatusCode,
    decision: AdminDecision,
    reason_code: Option<ReasonCode>,
    message: Option<String>,
    pub(crate) result: Value,
}

struct ReloadFailureContext<'a> {
    active: Arc<RuntimeSnapshot>,
    trigger: ReloadTrigger,
    attempted_at: &'a str,
    started: Instant,
    agent_request_id: &'a str,
    broker_request_id: &'a str,
    source: &'a SourceContext,
    identity: Option<&'a agent_access_core::IdentityContext>,
}

struct ReloadProgressGuard<'a> {
    flag: &'a AtomicBool,
}

impl<'a> ReloadProgressGuard<'a> {
    fn new(flag: &'a AtomicBool) -> Self {
        flag.store(true, Ordering::SeqCst);
        Self { flag }
    }
}

impl Drop for ReloadProgressGuard<'_> {
    fn drop(&mut self) {
        self.flag.store(false, Ordering::SeqCst);
    }
}

impl ReloadableState {
    pub async fn reload_from_signal(&self) {
        let source = SourceContext {
            listener: "signal".to_string(),
            remote: "process".to_string(),
            proxy_chain: vec![],
            agent_request_id_generated: None,
        };
        let broker_request_id = new_broker_request_id();
        tracing::info!(
            event = "config_reload_requested",
            listener = "signal",
            operation = "config.reload",
            agentRequestId = "signal",
            brokerRequestId = broker_request_id.as_str(),
            configGeneration = self.current().generation,
        );
        let _response = self
            .reload(
                ReloadTrigger::Signal,
                "signal".to_string(),
                broker_request_id.clone(),
                source,
                None,
            )
            .await;
    }

    pub(crate) async fn reload(
        &self,
        trigger: ReloadTrigger,
        agent_request_id: String,
        broker_request_id: String,
        source: SourceContext,
        identity: Option<agent_access_core::IdentityContext>,
    ) -> ConfigOperationResponse {
        let started = Instant::now();
        let listener = reload_listener(trigger, &source);
        let attempted_at = Utc::now().to_rfc3339();
        let Ok(_mutation_guard) = self.policy_mutation_lock.try_lock() else {
            let active = self.current();
            let reason_code = ReasonCode::ReloadInProgress;
            let errors = vec![
                "another policy mutation or reload attempt is already in progress".to_string(),
            ];
            let summary = ReloadAttemptSummary {
                trigger,
                attempted_at,
                decision: AdminDecision::Error,
                reason_code: Some(reason_code),
                candidate_config_hash: None,
                previous_generation: active.generation,
                active_generation: active.generation,
                message: Some(errors[0].clone()),
            };
            self.set_last_reload_attempt(summary);
            let _ = append_admin_audit_best_effort(
                active.clone(),
                AdminAuditInput {
                    agent_request_id: &agent_request_id,
                    broker_request_id: &broker_request_id,
                    trigger,
                    operation: crate::handlers::management::audit_actions::CONFIG_RELOAD,
                    decision: AdminDecision::Error,
                    reason_code: Some(reason_code),
                    source: &source,
                    identity: identity.as_ref(),
                    previous_generation: active.generation,
                    active_generation: active.generation,
                    previous_config_hash: Some(active.config_hash.as_str()),
                    candidate_config_hash: None,
                    active_config_hash: Some(active.config_hash.as_str()),
                    errors: &errors,
                },
            )
            .await;
            observability::record_decision(AdminDecision::Error.as_str());
            observability::record_reason_code(reason_code.as_str());
            let status = reason_status(reason_code);
            observability::record_status(status.as_u16());
            tracing::warn!(
                event = "config_reload_rejected",
                listener = listener,
                operation = "config.reload",
                agentRequestId = agent_request_id.as_str(),
                brokerRequestId = broker_request_id.as_str(),
                configGeneration = active.generation,
                reasonCode = reason_code.as_str(),
                "http.statusCode" = status.as_u16(),
                durationMs = observability::elapsed_ms(started),
            );
            return ConfigOperationResponse {
                status,
                decision: AdminDecision::Error,
                reason_code: Some(reason_code),
                message: errors.first().cloned(),
                result: Value::Null,
            };
        };
        let Ok(_guard) = self.reload_lock.try_lock() else {
            let active = self.current();
            let reason_code = ReasonCode::ReloadInProgress;
            let errors = vec!["another reload attempt is already in progress".to_string()];
            let summary = ReloadAttemptSummary {
                trigger,
                attempted_at,
                decision: AdminDecision::Error,
                reason_code: Some(reason_code),
                candidate_config_hash: None,
                previous_generation: active.generation,
                active_generation: active.generation,
                message: Some(errors[0].clone()),
            };
            self.set_last_reload_attempt(summary);
            let _ = append_admin_audit_best_effort(
                active.clone(),
                AdminAuditInput {
                    agent_request_id: &agent_request_id,
                    broker_request_id: &broker_request_id,
                    trigger,
                    operation: crate::handlers::management::audit_actions::CONFIG_RELOAD,
                    decision: AdminDecision::Error,
                    reason_code: Some(reason_code),
                    source: &source,
                    identity: identity.as_ref(),
                    previous_generation: active.generation,
                    active_generation: active.generation,
                    previous_config_hash: Some(active.config_hash.as_str()),
                    candidate_config_hash: None,
                    active_config_hash: Some(active.config_hash.as_str()),
                    errors: &errors,
                },
            )
            .await;
            observability::record_decision(AdminDecision::Error.as_str());
            observability::record_reason_code(reason_code.as_str());
            let status = reason_status(reason_code);
            observability::record_status(status.as_u16());
            tracing::warn!(
                event = "config_reload_rejected",
                listener = listener,
                operation = "config.reload",
                agentRequestId = agent_request_id.as_str(),
                brokerRequestId = broker_request_id.as_str(),
                configGeneration = active.generation,
                reasonCode = reason_code.as_str(),
                "http.statusCode" = status.as_u16(),
                durationMs = observability::elapsed_ms(started),
            );
            return ConfigOperationResponse {
                status,
                decision: AdminDecision::Error,
                reason_code: Some(reason_code),
                message: errors.first().cloned(),
                result: Value::Null,
            };
        };

        let _progress = ReloadProgressGuard::new(&self.reload_in_progress);
        let active = self.current();
        let deadline = ReloadDeadline::new(self.reload_timeout);
        let candidate = self
            .build_candidate_with_timeout(
                active.generation + 1,
                active.runtime.clone(),
                deadline.clone(),
            )
            .await;

        match candidate {
            Ok(candidate) => {
                let previous_generation = active.generation;
                let previous_hash = active.config_hash.clone();
                let new_snapshot = candidate.snapshot;
                if let Err(failure) = deadline.check() {
                    self.shutdown_candidate_audit(&new_snapshot, Duration::from_millis(100))
                        .await;
                    return self
                        .reload_failure_response(
                            ReloadFailureContext {
                                active: active.clone(),
                                trigger,
                                attempted_at: &attempted_at,
                                started,
                                agent_request_id: &agent_request_id,
                                broker_request_id: &broker_request_id,
                                source: &source,
                                identity: identity.as_ref(),
                            },
                            failure,
                        )
                        .await;
                }
                let candidate_hash = candidate.config_hash;
                let changed_audit_file = audit_store_changed(&active, &new_snapshot);
                let success_audit = AdminAuditInput {
                    agent_request_id: &agent_request_id,
                    broker_request_id: &broker_request_id,
                    trigger,
                    operation: crate::handlers::management::audit_actions::CONFIG_RELOAD,
                    decision: AdminDecision::Allow,
                    reason_code: None,
                    source: &source,
                    identity: identity.as_ref(),
                    previous_generation,
                    active_generation: new_snapshot.generation,
                    previous_config_hash: Some(previous_hash.as_str()),
                    candidate_config_hash: Some(candidate_hash.as_str()),
                    active_config_hash: Some(new_snapshot.config_hash.as_str()),
                    errors: &[],
                };
                if let Err(error) = append_admin_audit(new_snapshot.clone(), &success_audit).await {
                    log_admin_audit_failure(&new_snapshot, &success_audit, &error);
                    self.shutdown_candidate_audit(&new_snapshot, self.reload_timeout)
                        .await;
                    let failure = ReloadFailure::new(
                        AdminDecision::Error,
                        ReasonCode::ConfigAdmissionFailed,
                        vec![format!("candidate audit append failed: {error}")],
                        Some(candidate_hash),
                    );
                    return self
                        .reload_failure_response(
                            ReloadFailureContext {
                                active: active.clone(),
                                trigger,
                                attempted_at: &attempted_at,
                                started,
                                agent_request_id: &agent_request_id,
                                broker_request_id: &broker_request_id,
                                source: &source,
                                identity: identity.as_ref(),
                            },
                            failure,
                        )
                        .await;
                }
                if let Err(error) = new_snapshot
                    .reconcile_microsoft_oidc_provider_with_fallback(Some(&active.runtime))
                {
                    self.shutdown_candidate_audit(&new_snapshot, self.reload_timeout)
                        .await;
                    let failure = ReloadFailure::new(
                        AdminDecision::Error,
                        ReasonCode::ConfigAdmissionFailed,
                        vec![format!(
                            "Microsoft OIDC state reconciliation failed: {error}"
                        )],
                        Some(candidate_hash),
                    );
                    return self
                        .reload_failure_response(
                            ReloadFailureContext {
                                active: active.clone(),
                                trigger,
                                attempted_at: &attempted_at,
                                started,
                                agent_request_id: &agent_request_id,
                                broker_request_id: &broker_request_id,
                                source: &source,
                                identity: identity.as_ref(),
                            },
                            failure,
                        )
                        .await;
                }
                if let Err(error) = new_snapshot.runtime.activate_oauth() {
                    self.shutdown_candidate_audit(&new_snapshot, self.reload_timeout)
                        .await;
                    let failure = ReloadFailure::new(
                        AdminDecision::Error,
                        ReasonCode::ConfigAdmissionFailed,
                        vec![format!("OAuth state reconciliation failed: {error}")],
                        Some(candidate_hash),
                    );
                    return self
                        .reload_failure_response(
                            ReloadFailureContext {
                                active: active.clone(),
                                trigger,
                                attempted_at: &attempted_at,
                                started,
                                agent_request_id: &agent_request_id,
                                broker_request_id: &broker_request_id,
                                source: &source,
                                identity: identity.as_ref(),
                            },
                            failure,
                        )
                        .await;
                }
                active.runtime.deactivate_oauth();
                active
                    .runtime
                    .retire_superseded_import_dispatch(&new_snapshot.runtime);
                let new_snapshot = self.publish_snapshot(new_snapshot);
                new_snapshot.runtime.warn_aggregate_mcp_names();
                self.active_lock_set
                    .store(Arc::clone(&new_snapshot.state_locks));
                self.track_state_lock_set(&new_snapshot.state_locks);
                let previous_audit_error = if changed_audit_file {
                    append_admin_audit_best_effort(
                        active.clone(),
                        AdminAuditInput {
                            agent_request_id: &agent_request_id,
                            broker_request_id: &broker_request_id,
                            trigger,
                            operation: crate::handlers::management::audit_actions::CONFIG_RELOAD,
                            decision: AdminDecision::Allow,
                            reason_code: None,
                            source: &source,
                            identity: identity.as_ref(),
                            previous_generation,
                            active_generation: new_snapshot.generation,
                            previous_config_hash: Some(previous_hash.as_str()),
                            candidate_config_hash: Some(candidate_hash.as_str()),
                            active_config_hash: Some(new_snapshot.config_hash.as_str()),
                            errors: &[],
                        },
                    )
                    .await
                } else {
                    None
                };
                let summary = ReloadAttemptSummary {
                    trigger,
                    attempted_at,
                    decision: AdminDecision::Allow,
                    reason_code: None,
                    candidate_config_hash: Some(candidate_hash.clone()),
                    previous_generation,
                    active_generation: new_snapshot.generation,
                    message: previous_audit_error
                        .map(|error| format!("previous audit append failed: {error}")),
                };
                self.set_last_reload_attempt(summary);
                observability::record_decision(AdminDecision::Allow.as_str());
                observability::record_status(StatusCode::OK.as_u16());
                tracing::info!(
                    event = "config_reload_completed",
                    nodeId = new_snapshot.runtime.node_id(),
                    listener = listener,
                    operation = "config.reload",
                    agentRequestId = agent_request_id.as_str(),
                    brokerRequestId = broker_request_id.as_str(),
                    configGeneration = new_snapshot.generation,
                    previousGeneration = previous_generation,
                    activeGeneration = new_snapshot.generation,
                    candidateConfigHash = candidate_hash.as_str(),
                    auditFileChanged = changed_audit_file,
                    "http.statusCode" = StatusCode::OK.as_u16(),
                    durationMs = observability::elapsed_ms(started),
                );
                ConfigOperationResponse {
                    status: StatusCode::OK,
                    decision: AdminDecision::Allow,
                    reason_code: None,
                    message: None,
                    result: json!({
                        "nodeId": new_snapshot.runtime.node_id(),
                        "audit": audit_status_json(&new_snapshot.runtime),
                        "previousGeneration": previous_generation,
                        "generation": new_snapshot.generation,
                        "policyGeneration": new_snapshot.runtime.policy_generation(),
                        "previousConfigHash": previous_hash,
                        "configHash": new_snapshot.config_hash,
                        "loadedAt": new_snapshot.loaded_at,
                        "identityAuthority": new_snapshot.runtime.config().identity.authority,
                        "policyAuthority": new_snapshot.runtime.config().policy.authority,
                        "bodyHardCapBytes": self.body_hard_cap,
                        "reloadTimeoutMs": self.reload_timeout.as_millis() as u64,
                        "shutdownTimeoutMs": self.shutdown_timeout.as_millis() as u64,
                        "lastReloadAttempt": self.last_reload_attempt().map(reload_attempt_summary_json),
                    }),
                }
            }
            Err(failure) => {
                self.reload_failure_response(
                    ReloadFailureContext {
                        active: active.clone(),
                        trigger,
                        attempted_at: &attempted_at,
                        started,
                        agent_request_id: &agent_request_id,
                        broker_request_id: &broker_request_id,
                        source: &source,
                        identity: identity.as_ref(),
                    },
                    failure,
                )
                .await
            }
        }
    }

    async fn build_candidate_with_timeout(
        &self,
        generation: u64,
        previous_runtime: BrokerRuntime,
        deadline: ReloadDeadline,
    ) -> Result<CandidateRuntime, ReloadFailure> {
        let config_path = self.config_path.clone();
        let body_hard_cap = self.body_hard_cap;
        let live_locks = self.live_state_lock_sets();
        let build_deadline = deadline.clone();
        let backends = Arc::clone(&self.backends);
        let mut build = tokio::task::spawn_blocking(move || {
            let admission = admit_candidate_config(
                &config_path,
                &backends,
                body_hard_cap,
                &live_locks,
                &previous_runtime,
                &build_deadline,
            )?;
            build_candidate_runtime(admission, generation, previous_runtime, build_deadline)
        });
        match tokio::time::timeout(self.reload_timeout, &mut build).await {
            Ok(Ok(result)) => {
                let candidate = result?;
                if let Err(failure) = deadline.check_with_hash(Some(candidate.config_hash.clone()))
                {
                    self.shutdown_candidate_audit(&candidate.snapshot, Duration::from_millis(100))
                        .await;
                    return Err(failure);
                }
                let remaining = deadline
                    .remaining()
                    .ok_or_else(|| reload_timeout_failure(Some(candidate.config_hash.clone())))?;
                match tokio::time::timeout(remaining, candidate.snapshot.runtime.readiness()).await
                {
                    Ok(Ok(())) => {
                        if let Err(failure) =
                            deadline.check_with_hash(Some(candidate.config_hash.clone()))
                        {
                            self.shutdown_candidate_audit(
                                &candidate.snapshot,
                                Duration::from_millis(100),
                            )
                            .await;
                            return Err(failure);
                        }
                        let remaining = deadline.remaining().ok_or_else(|| {
                            reload_timeout_failure(Some(candidate.config_hash.clone()))
                        })?;
                        let snapshot = &candidate.snapshot;
                        let prepared = tokio::time::timeout(
                            remaining,
                            RuntimeSnapshot::new_microsoft_oidc_candidate(
                                snapshot.generation,
                                snapshot.config_hash.clone(),
                                snapshot.runtime.clone(),
                                Arc::clone(&snapshot.state_locks),
                            ),
                        )
                        .await;
                        match prepared {
                            Ok(Ok(snapshot)) => Ok(CandidateRuntime {
                                config_hash: candidate.config_hash,
                                snapshot,
                            }),
                            Ok(Err(error)) => {
                                self.shutdown_candidate_audit(&candidate.snapshot, remaining)
                                    .await;
                                Err(ReloadFailure::new(
                                    AdminDecision::Error,
                                    ReasonCode::ConfigAdmissionFailed,
                                    vec![format!(
                                        "Microsoft OIDC runtime preparation failed: {error}"
                                    )],
                                    Some(candidate.config_hash),
                                ))
                            }
                            Err(_) => {
                                self.shutdown_candidate_audit(
                                    &candidate.snapshot,
                                    Duration::from_millis(100),
                                )
                                .await;
                                Err(reload_timeout_failure(Some(candidate.config_hash)))
                            }
                        }
                    }
                    Ok(Err(error)) => {
                        self.shutdown_candidate_audit(&candidate.snapshot, remaining)
                            .await;
                        Err(runtime_admission_failure(
                            error,
                            Some(candidate.config_hash.clone()),
                        ))
                    }
                    Err(_) => {
                        self.shutdown_candidate_audit(
                            &candidate.snapshot,
                            Duration::from_millis(100),
                        )
                        .await;
                        Err(reload_timeout_failure(Some(candidate.config_hash.clone())))
                    }
                }
            }
            Ok(Err(error)) => Err(ReloadFailure::new(
                AdminDecision::Error,
                ReasonCode::ConfigAdmissionFailed,
                vec![format!("candidate build task failed: {error}")],
                None,
            )),
            Err(_) => {
                deadline.cancel();
                let candidate_hash = deadline.candidate_config_hash();
                // Wait for candidate admission to observe cancellation so candidate-only
                // state locks are dropped before this failed reload response returns.
                let _ = build.await;
                Err(reload_timeout_failure(candidate_hash))
            }
        }
    }

    async fn shutdown_candidate_audit(&self, snapshot: &RuntimeSnapshot, timeout: Duration) {
        if let Err(error) = snapshot.runtime.shutdown_own_audit(timeout).await {
            tracing::error!(
                event = "candidate_audit_shutdown_failed",
                generation = snapshot.generation,
                configHash = snapshot.config_hash.as_str(),
                error = %error,
            );
        }
    }

    async fn reload_failure_response(
        &self,
        context: ReloadFailureContext<'_>,
        failure: ReloadFailure,
    ) -> ConfigOperationResponse {
        let summary = ReloadAttemptSummary {
            trigger: context.trigger,
            attempted_at: context.attempted_at.to_string(),
            decision: failure.decision,
            reason_code: Some(failure.reason_code),
            candidate_config_hash: failure.candidate_config_hash.clone(),
            previous_generation: context.active.generation,
            active_generation: context.active.generation,
            message: failure.errors.first().cloned(),
        };
        self.set_last_reload_attempt(summary);
        let audit_error = append_admin_audit_best_effort(
            context.active.clone(),
            AdminAuditInput {
                agent_request_id: context.agent_request_id,
                broker_request_id: context.broker_request_id,
                trigger: context.trigger,
                operation: crate::handlers::management::audit_actions::CONFIG_RELOAD,
                decision: failure.decision,
                reason_code: Some(failure.reason_code),
                source: context.source,
                identity: context.identity,
                previous_generation: context.active.generation,
                active_generation: context.active.generation,
                previous_config_hash: Some(context.active.config_hash.as_str()),
                candidate_config_hash: failure.candidate_config_hash.as_deref(),
                active_config_hash: Some(context.active.config_hash.as_str()),
                errors: &failure.errors,
            },
        )
        .await;
        let listener = reload_listener(context.trigger, context.source);
        observability::record_decision(failure.decision.as_str());
        observability::record_reason_code(failure.reason_code.as_str());
        observability::record_status(failure.status.as_u16());
        let candidate_config_hash = failure.candidate_config_hash.as_deref().unwrap_or("");
        macro_rules! emit_event {
            ($level:ident) => {{
                tracing::$level!(
                    event = failure.event_name(),
                    listener = listener,
                    operation = "config.reload",
                    agentRequestId = context.agent_request_id,
                    brokerRequestId = context.broker_request_id,
                    configGeneration = context.active.generation,
                    activeGeneration = context.active.generation,
                    candidateConfigHash = candidate_config_hash,
                    reasonCode = failure.reason_code.as_str(),
                    errorCount = failure.errors.len(),
                    "http.statusCode" = failure.status.as_u16(),
                    durationMs = observability::elapsed_ms(context.started),
                );
            }};
        }
        match failure.event_kind {
            ReloadFailureEventKind::Failed => emit_event!(error),
            ReloadFailureEventKind::Rejected => emit_event!(warn),
        }
        if let Some(error) = audit_error
            && context.trigger == ReloadTrigger::AdminHttp
        {
            let reason_code = ReasonCode::AuditUnavailable;
            let status = reason_status(reason_code);
            observability::record_decision(AdminDecision::Error.as_str());
            observability::record_reason_code(reason_code.as_str());
            observability::record_status(status.as_u16());
            return ConfigOperationResponse {
                status,
                decision: AdminDecision::Error,
                reason_code: Some(reason_code),
                message: Some(format!("audit append failed: {error}")),
                result: Value::Null,
            };
        }
        ConfigOperationResponse {
            status: failure.status,
            decision: failure.decision,
            reason_code: Some(failure.reason_code),
            message: failure.errors.first().cloned(),
            result: Value::Null,
        }
    }

    /// The `config.status` result. A successful status read is not audited.
    fn status_result(&self, snapshot: &RuntimeSnapshot) -> Value {
        json!({
            "nodeId": snapshot.runtime.node_id(),
            "audit": audit_status_json(&snapshot.runtime),
            "generation": snapshot.generation,
            "policyGeneration": snapshot.runtime.policy_generation(),
            "configHash": snapshot.config_hash,
            "loadedAt": snapshot.loaded_at,
            "identityAuthority": snapshot.runtime.config().identity.authority,
            "policyAuthority": snapshot.runtime.config().policy.authority,
            "bodyHardCapBytes": self.body_hard_cap,
            "reloadTimeoutMs": self.reload_timeout.as_millis() as u64,
            "shutdownTimeoutMs": self.shutdown_timeout.as_millis() as u64,
            "lastReloadAttempt": self.last_reload_attempt().map(reload_attempt_summary_json),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reload_timeout_failure_is_rejected_event() {
        let failure = reload_timeout_failure(Some("candidate-hash".to_string()));

        assert_eq!(failure.event_name(), "config_reload_rejected");
        assert_eq!(failure.event_kind, ReloadFailureEventKind::Rejected);
        assert_eq!(failure.reason_code, ReasonCode::ConfigAdmissionFailed);
        assert_eq!(failure.status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(
            failure.candidate_config_hash.as_deref(),
            Some("candidate-hash")
        );
    }
}
