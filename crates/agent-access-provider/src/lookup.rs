//! Lookup access: the material the host lends an action's upstream metadata
//! lookups, before policy (scope resolution) and at execution.
use crate::{DelegatedCredential, ExecutionCredential};

/// The material the host lends one operation's upstream lookups, which
/// confirm what an input names before or after policy admits the action.
/// The host selects it for the operation's grant path; a provider uses only
/// this access for lookups, never chooses another or falls back to a shared
/// credential, and never uses it in place of execution material.
///
/// Delegated lookup access holds the operation's one [`DelegatedCredential`]:
/// the same lease that scope resolution, body admission and execution use,
/// with one recovery budget for the whole operation. Clones share that lease
/// and its budget, so copying lookup access never grants another recovery.
/// Obtain fresh access with [`DelegatedCredential::revalidated_access_for`]
/// immediately before each lookup request.
///
/// A provider that supports only some variants matches with a fallback arm
/// that rejects the others, failing closed.
#[non_exhaustive]
#[derive(Debug, Clone)]
pub enum LookupAccess {
    /// Static material: the service's shared lookup credential or the
    /// caller's personal token.
    Static(ExecutionCredential),
    /// The caller's delegated credential, sharing the operation's lease.
    Delegated(DelegatedCredential),
}

impl LookupAccess {
    pub fn static_credential(&self) -> Option<&ExecutionCredential> {
        match self {
            Self::Static(credential) => Some(credential),
            Self::Delegated(_) => None,
        }
    }

    pub fn delegated(&self) -> Option<&DelegatedCredential> {
        match self {
            Self::Delegated(credential) => Some(credential),
            Self::Static(_) => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{InvocationBuilder, ScopeRequestFixture, delegated_binding_id};
    use crate::{
        DelegatedAccess, DelegatedBindingId, DelegatedLease, ExecutionAccess, ProviderError,
        ReasonCode,
    };
    use async_trait::async_trait;
    use serde_json::json;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    /// A lease with the host's one-recovery budget per operation.
    #[derive(Default)]
    struct BudgetedLease {
        recovered: AtomicBool,
        recoveries: AtomicUsize,
    }

    #[async_trait]
    impl DelegatedLease for BudgetedLease {
        fn access(&self) -> DelegatedAccess {
            DelegatedAccess::new("lookup-secret", "target", "audience", "v1", i64::MAX)
        }
        fn binding_identity(&self) -> DelegatedBindingId {
            delegated_binding_id("lookup")
        }
        async fn revalidate(&self) -> Result<(), ProviderError> {
            Ok(())
        }
        fn mark_rejected(&self, _: &str) -> Result<(), ProviderError> {
            Ok(())
        }
        async fn recover_after_unauthorized(&self) -> Result<DelegatedAccess, ProviderError> {
            if self.recovered.swap(true, Ordering::SeqCst) {
                return Err(ProviderError::deny(
                    ReasonCode::CredentialInvalid,
                    "already recovered",
                ));
            }
            self.recoveries.fetch_add(1, Ordering::SeqCst);
            Ok(self.access())
        }
    }

    #[tokio::test]
    async fn cloned_lookup_access_shares_one_lease_and_recovery_budget() {
        let lease = Arc::new(BudgetedLease::default());
        let credential = crate::host::delegated_credential(lease.clone());
        let lookup = LookupAccess::Delegated(credential.clone());
        let copy = lookup.clone();
        let execution = ExecutionAccess::Delegated(credential);

        // A lookup's 401 recovery spends the operation's only budget: neither
        // a clone of the lookup access nor the execution material gets
        // another.
        copy.delegated()
            .unwrap()
            .recover_after_unauthorized()
            .await
            .unwrap();
        for exhausted in [lookup.delegated(), execution.delegated()] {
            let error = exhausted
                .unwrap()
                .recover_after_unauthorized()
                .await
                .unwrap_err();
            assert_eq!(error.reason_code(), ReasonCode::CredentialInvalid);
        }
        assert_eq!(lease.recoveries.load(Ordering::SeqCst), 1);
        assert_eq!(
            lookup.delegated().unwrap().binding_identity(),
            copy.delegated().unwrap().binding_identity()
        );
    }

    #[test]
    fn lookup_access_holds_one_kind_of_material_and_redacts_it() {
        let lookup = LookupAccess::Static(crate::host::bearer_credential(
            "static-lookup-secret".into(),
        ));
        assert!(lookup.static_credential().is_some());
        assert!(lookup.delegated().is_none());
        let delegated = LookupAccess::Delegated(crate::host::delegated_credential(Arc::new(
            BudgetedLease::default(),
        )));
        assert!(delegated.static_credential().is_none());
        assert!(delegated.delegated().is_some());
        let rendered = format!("{lookup:?} {delegated:?}");
        for secret in ["static-lookup-secret", "lookup-secret"] {
            assert!(!rendered.contains(secret), "{rendered}");
        }
    }

    #[test]
    fn scope_and_admitted_requests_carry_the_host_selected_lookup_access() {
        let lease = Arc::new(BudgetedLease::default());
        let credential = crate::host::delegated_credential(lease);
        let fixture =
            ScopeRequestFixture::new("svc", "act", json!({})).delegated_lookup(credential.clone());
        let request = fixture.request();
        assert!(request.lookup_access().unwrap().delegated().is_some());
        assert!(
            ScopeRequestFixture::new("svc", "act", json!({}))
                .request()
                .lookup_access()
                .is_none()
        );

        let admitted = InvocationBuilder::new("svc", "act")
            .delegated(credential.clone())
            .delegated_lookup(credential)
            .build();
        assert!(admitted.lookup_access().unwrap().delegated().is_some());
        assert!(admitted.execution().delegated().is_some());
        let cleared = InvocationBuilder::from(admitted)
            .lookup_access(None)
            .build();
        assert!(cleared.lookup_access().is_none());
    }
}
