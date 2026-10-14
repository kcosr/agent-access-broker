//! Per-test temporary directories for the CLI integration tests.

use std::cell::OnceCell;
use std::path::PathBuf;

thread_local! {
    /// The calling test's temporary root; see [`temp_path`].
    static TEST_TEMP_ROOT: OnceCell<tempfile::TempDir> = const { OnceCell::new() };
}

/// `name` in a fresh private directory for the calling test.
///
/// A test's directories share one root that is removed when the test's
/// thread exits: libtest runs each test on its own thread and joins it, so
/// helpers that build fixtures need not return a guard. Call it on the
/// test's own thread; a spawned thread's exit would remove the directory
/// early.
pub fn temp_path(name: &str) -> PathBuf {
    let thread = std::thread::current();
    assert!(
        thread
            .name()
            .is_some_and(|name| name != "main" && name != "tokio-runtime-worker"),
        "temp_path must run on the test's own thread, not {:?}",
        thread.name()
    );
    TEST_TEMP_ROOT.with(|root| {
        let root = root.get_or_init(|| {
            tempfile::Builder::new()
                .prefix("agent-access-cli-test-")
                .tempdir()
                .unwrap()
        });
        let dir = root.path().join(uuid::Uuid::new_v4().to_string());
        std::fs::create_dir(&dir).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        dir.join(name)
    })
}
