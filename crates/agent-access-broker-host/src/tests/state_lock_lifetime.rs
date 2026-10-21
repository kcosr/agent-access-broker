//! `token_store_call_from_snapshot` keeps its snapshot's state locks until
//! the blocking store write returns, even after the application's Tokio
//! shutdown drops the write's async owner and every other holder of the
//! snapshot: no other process may take the state while the write still runs.
use super::{TEST_LOCK_HOLDER, fake_config, temp_path};
use crate::state::{ReloadableState, RuntimeSnapshot};
use agent_access_core::{BrokerRuntime, StateLockFailureKind, StateLockSet};
use std::path::PathBuf;
use std::sync::{Arc, mpsc};
use std::time::{Duration, Instant};

#[test]
fn token_store_write_keeps_the_state_locks_after_runtime_shutdown_drops_its_owner() {
    let config_path = temp_path("state-lock-lifetime.toml");
    let audit_path = temp_path("state-lock-lifetime.audit.jsonl");
    let config = fake_config(audit_path.to_str().unwrap());
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
    tokio.spawn(async move {
        let _ = state
            .token_store_call_from_snapshot(snapshot, move |_runtime| {
                started.send(()).unwrap();
                released.recv().unwrap();
                Ok(())
            })
            .await;
    });
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
