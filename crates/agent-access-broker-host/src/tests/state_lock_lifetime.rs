//! Managed-store writes keep their snapshot's state locks until the blocking
//! write returns, even after the application's Tokio shutdown drops the
//! write's async owner and every other holder of the snapshot: no other
//! process may take the state while the write still runs. Each entry point
//! that runs a blocking store write has its own case.
use super::{TEST_LOCK_HOLDER, fake_config, temp_path};
use crate::handlers::management::common::{
    ManagementAccess, management_context, management_store_call,
};
use crate::state::{AppState, ReloadableState, RuntimeSnapshot};
use agent_access_core::{
    BrokerConfig, BrokerRuntime, IdentityConfig, IdentitySourceConfig, ManagedStoreConfig,
    ManagementConfig, StateLockFailureKind, StateLockSet, StaticPrincipalConfig,
};
use agent_access_provider::REQUEST_ID_HEADER;
use axum::http::{HeaderMap, HeaderValue};
use std::future::Future;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::{Arc, mpsc};
use std::time::{Duration, Instant};

/// The blocking write: it reports that it started, then waits for release.
struct BlockedWrite {
    started: mpsc::Sender<()>,
    released: mpsc::Receiver<()>,
}

impl BlockedWrite {
    fn run(self) {
        self.started.send(()).unwrap();
        // A failed test drops the release sender; the write then just ends.
        let _ = self.released.recv();
    }
}

/// Submits `write` through one entry point; the returned future is its owner.
type Submit = fn(
    Arc<ReloadableState>,
    Arc<RuntimeSnapshot>,
    BlockedWrite,
) -> Pin<Box<dyn Future<Output = ()> + Send>>;

#[test]
fn token_store_write_keeps_the_state_locks_after_runtime_shutdown_drops_its_owner() {
    assert_write_keeps_the_state_locks("token-store", |state, snapshot, write| {
        Box::pin(async move {
            let _ = state
                .token_store_call_from_snapshot(snapshot, move |_runtime| {
                    write.run();
                    Ok(())
                })
                .await;
        })
    });
}

#[test]
fn managed_policy_write_keeps_the_state_locks_after_runtime_shutdown_drops_its_owner() {
    assert_write_keeps_the_state_locks("managed-policy", |state, snapshot, write| {
        Box::pin(async move {
            let _ = state
                .managed_policy_mutation_from_snapshot(snapshot, move |_runtime| {
                    write.run();
                    Ok(())
                })
                .await;
        })
    });
}

#[test]
fn import_write_keeps_the_state_locks_after_runtime_shutdown_drops_its_owner() {
    assert_write_keeps_the_state_locks("import", |state, snapshot, write| {
        Box::pin(async move {
            let _ = state
                .imported_service_mutation(snapshot, move |runtime| {
                    write.run();
                    Ok((runtime, ()))
                })
                .await;
        })
    });
}

#[test]
fn snapshot_store_call_keeps_its_own_state_locks_after_reload_and_runtime_shutdown() {
    // Local password, browser-session and OIDC flow writes run on the
    // snapshot their request took, which a reload may replace meanwhile.
    assert_write_keeps_the_state_locks("snapshot-store", |state, snapshot, write| {
        Box::pin(async move {
            state.publish_snapshot(RuntimeSnapshot::new(
                2,
                "state-lock-lifetime-replacement".into(),
                snapshot.runtime.clone(),
                StateLockSet::empty(),
            ));
            drop(state);
            let _ = snapshot
                .managed_store_call(move |_store| {
                    write.run();
                    Ok(())
                })
                .await;
        })
    });
}

#[test]
fn management_store_write_keeps_the_state_locks_after_runtime_shutdown_drops_its_owner() {
    assert_write_keeps_the_state_locks("management", |state, _snapshot, write| {
        Box::pin(async move {
            let mut headers = HeaderMap::new();
            headers.insert(ADMIN_TOKEN_HEADER, HeaderValue::from_static(ADMIN_TOKEN));
            headers.insert(
                REQUEST_ID_HEADER,
                HeaderValue::from_static("state-lock-lifetime"),
            );
            let Ok(context) = management_context(
                &AppState { reloadable: state },
                "127.0.0.1:43210".parse().unwrap(),
                &headers,
                "admin.principals.list",
                ManagementAccess::AdminRead,
            )
            .await
            else {
                panic!("the management request is admitted");
            };
            let _ = management_store_call(&context, move |_store| {
                write.run();
                Ok(())
            })
            .await;
        })
    });
}

#[test]
fn current_policy_write_keeps_the_state_locks_after_runtime_shutdown_drops_its_waiter() {
    assert_write_keeps_the_state_locks("current-policy", |state, _snapshot, write| {
        Box::pin(async move {
            let _ = state
                .managed_policy_mutation(move |_runtime| {
                    write.run();
                    Ok(())
                })
                .await;
        })
    });
}

const ADMIN_TOKEN_HEADER: &str = "X-Agent-Access-Identity-Token";
const ADMIN_TOKEN: &str = "state-lock-lifetime-admin-token";

/// Audit, upload spool and managed store state, and a configured
/// administrator for management requests.
fn lock_lifetime_config(name: &str) -> BrokerConfig {
    let audit_path = temp_path(&format!("state-lock-lifetime-{name}.audit.jsonl"));
    let store_path = temp_path(&format!("state-lock-lifetime-{name}.sqlite"));
    let admin_token = temp_path(&format!("state-lock-lifetime-{name}.admin-token"));
    std::fs::write(&admin_token, ADMIN_TOKEN).unwrap();
    let mut config = fake_config(audit_path.to_str().unwrap());
    config.identity = IdentityConfig {
        trusted_callers: Default::default(),
        mode: "required".into(),
        authority: "toml".into(),
        sources: vec![IdentitySourceConfig {
            name: "bootstrap-admin".into(),
            kind: "static_principals".into(),
            header: ADMIN_TOKEN_HEADER.into(),
            scheme: "raw".into(),
            principals: vec![StaticPrincipalConfig {
                principal: "admin".into(),
                token_refs: vec![format!("file:{}", admin_token.display())],
            }],
        }],
        groups: vec![],
    };
    config.managed_store = Some(ManagedStoreConfig {
        kind: "sqlite".into(),
        path: store_path.display().to_string(),
        require_registered_principal_for_invocation: false,
        auto_migrate: true,
    });
    config.management = ManagementConfig {
        enabled: true,
        admin_principals: vec!["admin".into()],
        allow_classless_admin_identities: true,
        ..ManagementConfig::default()
    };
    config
}

fn assert_write_keeps_the_state_locks(name: &str, submit: Submit) {
    let config_path = temp_path(&format!("state-lock-lifetime-{name}.toml"));
    let config = lock_lifetime_config(name);
    let acquire =
        || StateLockSet::acquire_for_config(&config, &config_path, &TEST_LOCK_HOLDER, None);
    let locks = acquire().unwrap();
    let runtime = BrokerRuntime::new(config.clone()).unwrap();
    let audit_registry = runtime.audit_registry();
    let snapshot = RuntimeSnapshot::new(1, "state-lock-lifetime".into(), runtime, locks);
    let state = Arc::new(ReloadableState::from_snapshot(
        PathBuf::new(),
        Arc::new(crate::backend_registry()),
        crate::broker_build_status(),
        Arc::clone(&snapshot),
        1024 * 1024,
        Duration::from_secs(1),
        Duration::from_secs(1),
        audit_registry,
    ));
    let owner_state = Arc::downgrade(&state);
    let (started, write_started) = mpsc::channel();
    let (release_write, released) = mpsc::channel::<()>();

    let tokio = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(1)
        .enable_all()
        .build()
        .unwrap();
    tokio.spawn(submit(state, snapshot, BlockedWrite { started, released }));
    write_started
        .recv_timeout(Duration::from_secs(30))
        .expect("the blocking write starts");
    // As the application does after serving: the deadline passes while the
    // write is blocked, so its async owner is dropped but the write is not.
    tokio.shutdown_timeout(Duration::from_millis(50));
    let deadline = Instant::now() + Duration::from_secs(30);
    while owner_state.upgrade().is_some() {
        assert!(Instant::now() < deadline, "the async owner was not dropped");
        std::thread::sleep(Duration::from_millis(10));
    }

    let held = acquire().expect_err("the running write keeps the state locks");
    assert_eq!(held.kind(), StateLockFailureKind::Held);

    release_write.send(()).unwrap();
    loop {
        match acquire() {
            Ok(_) => break,
            Err(error) if error.kind() == StateLockFailureKind::Held => {
                assert!(
                    Instant::now() < deadline,
                    "the finished write did not release the state locks"
                );
                std::thread::sleep(Duration::from_millis(10));
            }
            Err(error) => panic!("{error}"),
        }
    }
}
