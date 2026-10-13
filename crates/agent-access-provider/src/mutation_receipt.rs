//! Mutation receipts: what a write action's result tells its caller about
//! whether the upstream applied the write, so the caller knows whether
//! repeating the action could apply it twice.
//!
//! A receipt is a set of fields in the action's `result`: `mutationStatus`,
//! `retrySafe` and, for an applied but unverified write, the
//! `verificationStage` that failed and the `safeLocators` of what changed.
//! Build one with a [`MutationReceipt`] constructor and attach it with
//! [`ProviderError::with_mutation_receipt`] or [`MutationReceipt::write_into`].
//! Reads never carry a receipt.

use crate::ProviderError;
use serde_json::{Map, Value, json};

/// What an upstream write did, as a receipt's `mutationStatus` reports it.
///
/// Non-exhaustive: a match on it ends with an arm that treats an unknown
/// status as unsafe to retry.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MutationStatus {
    /// `not_applied`: the write's request never reached the upstream, so
    /// nothing was applied.
    NotApplied,
    /// `unknown`: the request may have reached the upstream, and no response
    /// said whether it applied.
    Unknown,
    /// `applied_unverified`: the upstream applied the write, but it could not
    /// be verified.
    AppliedUnverified,
}

impl MutationStatus {
    /// The `mutationStatus` wire value.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NotApplied => "not_applied",
            Self::Unknown => "unknown",
            Self::AppliedUnverified => "applied_unverified",
        }
    }

    /// Whether repeating the write cannot apply it twice: only when nothing
    /// was applied.
    pub const fn retry_safe(self) -> bool {
        matches!(self, Self::NotApplied)
    }
}

/// The receipt a write action's result carries: `mutationStatus`, `retrySafe`
/// and, for an applied but unverified write, `verificationStage` and
/// `safeLocators`.
///
/// Give a receipt only for an action's own write. Once an earlier write in
/// the same action applied, a later failure is never `not_applied`: report
/// what the earlier write did instead.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MutationReceipt {
    status: MutationStatus,
    verification_stage: Option<String>,
    safe_locators: Option<Value>,
}

impl MutationReceipt {
    /// The write's request never reached the upstream, as
    /// [`UpstreamError::NotSent`](crate::UpstreamError::NotSent) proves:
    /// `mutationStatus: "not_applied"` and `retrySafe: true`. Report it with
    /// the failure's own reason, such as `upstream_connection_failed`.
    pub const fn not_applied() -> Self {
        Self::with_status(MutationStatus::NotApplied)
    }

    /// The request may have reached the upstream, such as a timeout or
    /// transport failure after it was sent, and no response said whether it
    /// applied: `mutationStatus: "unknown"` and `retrySafe: false`. Report it
    /// with the failure's own reason, such as `upstream_timeout`.
    pub const fn unknown() -> Self {
        Self::with_status(MutationStatus::Unknown)
    }

    /// The upstream applied the write, but `verification_stage` could not
    /// confirm it: `mutationStatus: "applied_unverified"`, `retrySafe: false`,
    /// `verificationStage` and the `safeLocators` identifying what was created
    /// or changed. Report it as `mutation_verification_failed`.
    pub fn applied_unverified(verification_stage: impl Into<String>, safe_locators: Value) -> Self {
        Self {
            status: MutationStatus::AppliedUnverified,
            verification_stage: Some(verification_stage.into()),
            safe_locators: Some(safe_locators),
        }
    }

    const fn with_status(status: MutationStatus) -> Self {
        Self {
            status,
            verification_stage: None,
            safe_locators: None,
        }
    }

    pub fn status(&self) -> MutationStatus {
        self.status
    }

    /// Whether repeating the write cannot apply it twice.
    pub fn retry_safe(&self) -> bool {
        self.status.retry_safe()
    }

    pub fn verification_stage(&self) -> Option<&str> {
        self.verification_stage.as_deref()
    }

    pub fn safe_locators(&self) -> Option<&Value> {
        self.safe_locators.as_ref()
    }

    /// Writes the receipt into `result`, replacing any receipt fields there
    /// and keeping every other field. A result that is not a JSON object
    /// becomes one holding only the receipt.
    pub fn write_into(&self, result: &mut Value) {
        if !result.is_object() {
            *result = Value::Object(Map::new());
        }
        let Value::Object(fields) = result else {
            unreachable!("the result was just made an object");
        };
        fields.insert("mutationStatus".into(), json!(self.status.as_str()));
        fields.insert("retrySafe".into(), json!(self.retry_safe()));
        match &self.verification_stage {
            Some(stage) => fields.insert("verificationStage".into(), json!(stage)),
            None => fields.remove("verificationStage"),
        };
        match &self.safe_locators {
            Some(locators) => fields.insert("safeLocators".into(), locators.clone()),
            None => fields.remove("safeLocators"),
        };
    }
}

impl ProviderError {
    /// Attaches `receipt` to this error's result, keeping the result's other
    /// fields (see [`MutationReceipt::write_into`]). The reason, message and
    /// upstream facts are unchanged.
    pub fn with_mutation_receipt(mut self, receipt: MutationReceipt) -> Self {
        let mut result = self.result.take().map_or(Value::Null, |result| *result);
        receipt.write_into(&mut result);
        self.result = Some(Box::new(result));
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Decision, ReasonCode};

    #[test]
    fn unsent_and_unknown_receipts_state_whether_a_retry_is_safe() {
        let unsent =
            ProviderError::error(ReasonCode::UpstreamConnectionFailed, "request was not sent")
                .with_upstream(None, Some(4))
                .with_mutation_receipt(MutationReceipt::not_applied());
        assert_eq!(unsent.decision(), Decision::Error);
        assert_eq!(unsent.reason_code, ReasonCode::UpstreamConnectionFailed);
        assert_eq!(unsent.message, "request was not sent");
        assert_eq!(unsent.upstream_duration_ms, Some(4));
        assert_eq!(
            unsent.result.as_deref(),
            Some(&json!({"mutationStatus": "not_applied", "retrySafe": true}))
        );

        let unknown = ProviderError::error(ReasonCode::UpstreamTimeout, "request timed out")
            .with_mutation_receipt(MutationReceipt::unknown());
        assert_eq!(unknown.reason_code, ReasonCode::UpstreamTimeout);
        assert_eq!(
            unknown.result.as_deref(),
            Some(&json!({"mutationStatus": "unknown", "retrySafe": false}))
        );

        for (receipt, status, wire, retry_safe) in [
            (
                MutationReceipt::not_applied(),
                MutationStatus::NotApplied,
                "not_applied",
                true,
            ),
            (
                MutationReceipt::unknown(),
                MutationStatus::Unknown,
                "unknown",
                false,
            ),
            (
                MutationReceipt::applied_unverified("mutation_response", json!({})),
                MutationStatus::AppliedUnverified,
                "applied_unverified",
                false,
            ),
        ] {
            assert_eq!(receipt.status(), status);
            assert_eq!(status.as_str(), wire);
            assert_eq!(receipt.retry_safe(), retry_safe, "{wire}");
            assert_eq!(status.retry_safe(), retry_safe, "{wire}");
        }
        assert_eq!(MutationReceipt::unknown().verification_stage(), None);
        assert_eq!(MutationReceipt::unknown().safe_locators(), None);
    }

    #[test]
    fn applied_unverified_receipts_carry_the_stage_and_safe_locators() {
        let receipt = MutationReceipt::applied_unverified("post_create_readback", json!({"id": 7}));
        assert_eq!(receipt.verification_stage(), Some("post_create_readback"));
        assert_eq!(receipt.safe_locators(), Some(&json!({"id": 7})));
        let error = ProviderError::error(ReasonCode::MutationVerificationFailed, "unverified")
            .with_mutation_receipt(receipt);
        assert_eq!(
            error.result.as_deref(),
            Some(&json!({
                "mutationStatus": "applied_unverified",
                "retrySafe": false,
                "verificationStage": "post_create_readback",
                "safeLocators": {"id": 7},
            }))
        );
    }

    #[test]
    fn receipts_merge_into_results_and_replace_an_earlier_receipt() {
        let error = ProviderError::error(ReasonCode::UpstreamFailed, "failed")
            .with_result(json!({
                "upstreamHttp": {"status": 500},
                "operationDispatched": true,
            }))
            .with_mutation_receipt(MutationReceipt::unknown());
        assert_eq!(
            error.result.as_deref(),
            Some(&json!({
                "upstreamHttp": {"status": 500},
                "operationDispatched": true,
                "mutationStatus": "unknown",
                "retrySafe": false,
            }))
        );

        let mut result = json!({
            "status": "partial",
            "mutationStatus": "applied_unverified",
            "retrySafe": false,
            "verificationStage": "mutation_response",
            "safeLocators": {"id": 7},
        });
        MutationReceipt::not_applied().write_into(&mut result);
        assert_eq!(
            result,
            json!({"status": "partial", "mutationStatus": "not_applied", "retrySafe": true})
        );

        let mut scalar = json!("not an object");
        MutationReceipt::unknown().write_into(&mut scalar);
        assert_eq!(
            scalar,
            json!({"mutationStatus": "unknown", "retrySafe": false})
        );
    }
}
