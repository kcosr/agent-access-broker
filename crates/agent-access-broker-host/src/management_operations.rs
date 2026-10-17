//! Snapshot-bound local operations. The invocation supervisor owns completion;
//! the blocking transaction remains fenced until its outcome is known.
use crate::state::{ReloadableState, RuntimeSnapshot};
use agent_access_core::{
    AdmittedManagementCommand, InvocationControl, LocalOperationHost, LocalOperationOutcome,
};
use agent_access_provider::{ProviderError, ReasonCode};
use std::{future::Future, pin::Pin, sync::Arc};

pub(crate) struct SnapshotLocalOperations {
    state: Arc<ReloadableState>,
    snapshot: Arc<RuntimeSnapshot>,
    control: InvocationControl,
}
impl SnapshotLocalOperations {
    pub(crate) fn new(
        state: Arc<ReloadableState>,
        snapshot: Arc<RuntimeSnapshot>,
        control: InvocationControl,
    ) -> Self {
        Self {
            state,
            snapshot,
            control,
        }
    }
}
impl LocalOperationHost for SnapshotLocalOperations {
    fn execute(
        &self,
        command: AdmittedManagementCommand,
    ) -> Pin<Box<dyn Future<Output = LocalOperationOutcome> + Send + 'static>> {
        let state = self.state.clone();
        let snapshot = self.snapshot.clone();
        let control = self.control.clone();
        let write = command.is_write();
        Box::pin(async move {
            // This future is retained by the registered invocation owner after
            // its local dispatch gate. No separate detached completion is emitted.
            if write {
                let preflight = tokio::select! {
                    biased;
                    error=control.local_interrupted()=>return LocalOperationOutcome::rejected(error),
                    result=snapshot.runtime.preflight_management_command(&command)=>result,
                };
                if preflight.is_err() {
                    return LocalOperationOutcome::rejected(
                        ProviderError::error(
                            ReasonCode::AuditUnavailable,
                            "management write audit is unavailable",
                        )
                        .with_result(
                            serde_json::json!({"executionState":"not_dispatched","retrySafe":false}),
                        ),
                    );
                }
            }
            let _guard = tokio::select! {
                biased;
                error=control.local_interrupted()=>return LocalOperationOutcome::rejected(error),
                guard=state.policy_mutation_lock.lock()=>guard,
            };
            if !Arc::ptr_eq(&state.current(), &snapshot) {
                let mut error = ProviderError::deny(
                    ReasonCode::VersionConflict,
                    "management runtime changed before execution",
                );
                if write {
                    error = error.with_result(
                        serde_json::json!({"executionState":"not_dispatched","retrySafe":false}),
                    );
                }
                return LocalOperationOutcome::rejected(error);
            }
            if write && !control.begin_local_commit() {
                return LocalOperationOutcome::rejected(control.local_interrupted().await);
            }
            let runtime = snapshot.runtime.clone();
            match tokio::task::spawn_blocking(move || runtime.execute_management_command(command))
                .await
            {
                Ok(result) => result,
                Err(_) => {
                    let mut error = ProviderError::error(
                        ReasonCode::OperationFailed,
                        "local management operation outcome could not be established",
                    );
                    if write {
                        error = error.with_result(
                            serde_json::json!({"executionState":"unknown","retrySafe":false}),
                        );
                    }
                    LocalOperationOutcome::rejected(error)
                }
            }
        })
    }
}
