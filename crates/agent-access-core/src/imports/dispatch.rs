//! A generation's opaque import dispatch fence. No lock is held across I/O.
use agent_access_provider::{ProviderError, ReasonCode};
use std::sync::{Arc, Mutex};

#[derive(Clone)]
pub struct ImportedDispatchGuard(Arc<Mutex<bool>>);
impl std::fmt::Debug for ImportedDispatchGuard {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ImportedDispatchGuard([private])")
    }
}
impl ImportedDispatchGuard {
    pub(crate) fn new() -> Self {
        Self(Arc::new(Mutex::new(true)))
    }
    pub(crate) fn retire(&self) {
        if let Ok(mut active) = self.0.lock() {
            *active = false;
        }
    }
    pub(crate) fn same(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
    }
    pub(crate) fn active(&self) -> bool {
        self.0.lock().is_ok_and(|active| *active)
    }
    /// Linearize one operation's dispatch decision with retirement. `admit`
    /// only closes the operation-local single-call gate; it must not await I/O.
    pub fn admit<T>(
        &self,
        admit: impl FnOnce() -> Result<T, ProviderError>,
    ) -> Result<T, ProviderError> {
        let active = self.0.lock().map_err(|_| unavailable())?;
        if !*active {
            return Err(unavailable());
        }
        admit()
    }
}
fn unavailable() -> ProviderError {
    ProviderError::deny(
        ReasonCode::ServiceActionDenied,
        "imported action changed or is unavailable; repeat discovery",
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn dispatch_and_retirement_share_one_order_without_holding_io() {
        let guard = ImportedDispatchGuard::new();
        let pinned = guard.clone();
        let (entered_tx, entered_rx) = std::sync::mpsc::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let worker = std::thread::spawn(move || {
            pinned.admit(|| {
                entered_tx.send(()).unwrap();
                release_rx.recv().unwrap();
                Ok(())
            })
        });
        entered_rx.recv().unwrap();
        let retired = guard.clone();
        let retirement = std::thread::spawn(move || retired.retire());
        release_tx.send(()).unwrap();
        worker.join().unwrap().unwrap();
        retirement.join().unwrap();
        let mut called = false;
        let error = guard
            .admit(|| {
                called = true;
                Ok(())
            })
            .unwrap_err();
        assert_eq!(error.reason_code(), ReasonCode::ServiceActionDenied);
        assert!(!called);
    }
}
