//! Strict result-schema conformance of every provider outcome in unit tests.
use super::*;
use agent_access_provider::test_support::assert_result_conforms;

impl JiraProvider {
    /// Invokes `request` and asserts that its outcome conforms strictly to
    /// the action's declared result schemas. Unit tests call this instead of
    /// [`Provider::invoke`], so every stub-driven outcome is checked.
    pub(crate) async fn invoke_checked(
        &self,
        request: ProviderInvocation,
    ) -> Result<ProviderResult, ProviderError> {
        let action = request.action().to_string();
        let outcome = Provider::invoke(self, request).await;
        match schema_action(&self.config, &action) {
            Some(descriptor) => assert_result_conforms(&descriptor, &outcome),
            None => assert!(
                outcome.as_ref().is_err_and(|error| error.result.is_none()),
                "unsupported Jira action {action} returned a result"
            ),
        }
        outcome
    }
}

/// `action` as `config` publishes it, or a comment write that `config` does
/// not publish with its bundled schemas, so a refusal is still checked.
fn schema_action(config: &JiraProviderConfig, action: &str) -> Option<ActionDescriptor> {
    jira_descriptor(config).action(action).cloned().or_else(|| {
        RESULT_SCHEMAS.actions().contains(&action).then(|| {
            ActionDescriptor::new(action, action, json!({"type": "object"}))
                .result_schemas(RESULT_SCHEMAS.action(action))
        })
    })
}
