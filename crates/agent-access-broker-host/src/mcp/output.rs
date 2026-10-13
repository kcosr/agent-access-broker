//! Count before enqueueing: delivery limits must not rewrite execution outcomes.
use agent_access_core::{BrokerResponse, InvocationControl};
use rmcp::model::CallToolResult;
use serde::Serialize;
use serde_json::{Value, json};
use std::io::{self, Write};
pub(super) const WIRE_RESERVE: usize = 8192;
struct Capped {
    bytes: Vec<u8>,
    limit: usize,
}
impl Write for Capped {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.len() > self.limit.saturating_sub(self.bytes.len()) {
            return Err(io::Error::other("MCP serialization limit"));
        }
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
pub(super) fn serialize<T: Serialize>(value: &T, limit: usize) -> Result<Vec<u8>, ()> {
    let mut writer = Capped {
        bytes: Vec::new(),
        limit,
    };
    serde_json::to_writer(&mut writer, value).map_err(|_| ())?;
    Ok(writer.bytes)
}
pub(super) fn result(value: Value, error: bool, limit: usize) -> Result<CallToolResult, ()> {
    // The single value itself is checked before the SDK creates its text copy.
    serialize(&value, limit)?;
    let result = if error {
        CallToolResult::structured_error(value)
    } else {
        CallToolResult::structured(value)
    };
    serialize(&result, limit.saturating_sub(WIRE_RESERVE))?;
    Ok(result)
}
/// The Broker's message for a `rate_limited` or `upstream_rate_limited`
/// error envelope. It is complete on its own, naming the service and the
/// wait, so it becomes the tool error's text: agents often see only text.
fn rate_limit_message(envelope: &Value) -> Option<String> {
    let reason_code = envelope["reasonCode"].as_str()?;
    if reason_code != agent_access_provider::ReasonCode::RateLimited.as_str()
        && reason_code != agent_access_provider::ReasonCode::UpstreamRateLimited.as_str()
    {
        return None;
    }
    envelope["error"]["message"]
        .as_str()
        .filter(|message| !message.trim().is_empty())
        .map(str::to_owned)
}
/// Replaces an error result's text copy with the rate-limit message, keeping
/// the envelope, including `reasonCode` and the structured retry `result`, as
/// structured content.
fn with_rate_limit_text(mut result: CallToolResult, message: Option<String>) -> CallToolResult {
    if let Some(message) = message
        && result.is_error == Some(true)
    {
        result.content = vec![rmcp::model::ContentBlock::text(message)];
    }
    result
}
/// Tool error for a request the Broker refused before dispatch. A
/// `rate_limited` or `upstream_rate_limited` refusal carries its complete
/// message as the text content.
pub(super) fn admission_failure(envelope: Value, limit: usize) -> Result<CallToolResult, ()> {
    let message = rate_limit_message(&envelope);
    Ok(with_rate_limit_text(
        result(envelope, true, limit)?,
        message,
    ))
}
pub(super) fn message(message: &'static str) -> CallToolResult {
    CallToolResult::structured_error(json!({"error":{"code":"mcp_tool_error","message":message}}))
}
pub(super) fn broker(
    response: BrokerResponse<Value>,
    control: &InvocationControl,
    limit: usize,
    sensitive: &[String],
) -> CallToolResult {
    let error = response.status >= 400
        || response.envelope.error.is_some()
        || response.envelope.decision != agent_access_provider::Decision::Allow;
    let normal = serialize(&response.envelope, limit)
        .ok()
        .and_then(|bytes| serde_json::from_slice(&bytes).ok())
        .and_then(|value| {
            let message = rate_limit_message(&value);
            result(value, error, limit)
                .ok()
                .map(|result| with_rate_limit_text(result, message))
        });
    if let Some(mut normal) = normal {
        if !sensitive.is_empty() {
            normal.meta = Some(rmcp::model::MetaObject(
                json!({"agent-access/sensitive-output-pointers":sensitive})
                    .as_object()
                    .unwrap()
                    .clone(),
            ));
        }
        if serialize(&normal, limit.saturating_sub(WIRE_RESERVE)).is_ok() {
            return normal;
        }
    }
    tracing::warn!(event="mcp_delivery_failed",code="mcp_response_too_large",brokerRequestId=%response.envelope.broker_request_id,service=%response.envelope.service,action=%response.envelope.action,"Broker outcome could not fit MCP delivery budget");
    let mut outcome = json!({"status":response.status,"decision":response.envelope.decision,"reasonCode":response.envelope.reason_code});
    if let Some(status) = response
        .envelope
        .result
        .as_ref()
        .and_then(|value| value.get("mutationStatus"))
        .and_then(Value::as_str)
        .filter(|status| {
            matches!(
                *status,
                "applied" | "applied_verified" | "applied_unverified" | "not_applied"
            )
        })
    {
        outcome["mutationStatus"] = json!(status);
    }
    // Only fixed-size/status metadata is copied. Never export arbitrary result
    // locators, error strings or deliberately issued credentials in this path.
    CallToolResult::structured_error(json!({
        "error":{"code":"mcp_response_too_large","message":"Execution output could not be delivered within the MCP response limit. Do not repeat the operation to recover output."},
        "agentRequestId":response.envelope.agent_request_id,"brokerRequestId":response.envelope.broker_request_id,
        "service":response.envelope.service,"action":response.envelope.action,"brokerOutcome":outcome,
        "execution":{"dispatched":control.dispatched(),"completion":if control.completed(){"completed"}else if control.dispatched(){"unknown"}else{"not_started"}},
        "resultAvailable":false,"retrySafe":false
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn counts_escaped_text_and_structured_copy() {
        let value = json!({"body":"\\\"".repeat(2000)});
        let one = serialize(&value, 64 * 1024).unwrap().len();
        assert!(result(value.clone(), false, one + WIRE_RESERVE).is_err());
        assert!(result(value, false, 64 * 1024).is_ok());
    }
    #[test]
    fn writer_stops_before_allocating_excess() {
        assert!(serialize(&"x".repeat(100_000), 32).is_err());
    }

    // Exercise public owner state through real provider execution rather than
    // inventing test-only setters for dispatch/completion evidence.
    struct OutcomeProvider {
        stop: Option<InvocationControl>,
    }
    impl agent_access_provider::test_support::DescribedProvider for OutcomeProvider {
        fn descriptor(&self) -> agent_access_provider::ServiceDescriptor {
            agent_access_fake::fake_descriptor()
        }
    }

    #[async_trait::async_trait]
    impl agent_access_provider::Provider for OutcomeProvider {
        fn resolve_scopes(
            &self,
            action: &str,
            inputs: &Value,
        ) -> Result<agent_access_provider::ResourceScopes, agent_access_provider::ProviderError>
        {
            agent_access_fake::FakeProvider.resolve_scopes(action, inputs)
        }
        async fn invoke(
            &self,
            request: agent_access_provider::ProviderInvocation,
        ) -> Result<agent_access_provider::ProviderResult, agent_access_provider::ProviderError>
        {
            if let Some(control) = &self.stop {
                control.force_stop();
                std::future::pending().await
            } else {
                agent_access_fake::FakeProvider.invoke(request).await
            }
        }
    }
    async fn outcome(unknown: bool) -> (BrokerResponse<Value>, InvocationControl) {
        use agent_access_core::{
            BrokerRuntime, ExecutionContext, GovernedOperationContext, IdentityContext,
            OperationContext, SourceContext,
        };
        let dir = tempfile::tempdir().unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        let mut config = agent_access_core::parse_broker_config_raw(
            "output-test.toml",
            r#"
[deployment]
environment="development"
enable_fake_service=true

[providers.fake]
[identity]
mode="anonymous"
authority="toml"
[credentials.service.fake]
type="bearer_token"
token_ref="env:UNUSED_OUTPUT_TEST_TOKEN"
[policy]
authority="toml"
default_decision="deny"
[[policy.resources]]
id="test"
resource_type="fake_project"
selector={kind="exact",value="TEST"}
allowed_execution_contexts=["default"]
[[policy.grants]]
subjects=["group:anonymous"]
service="fake"
actions=["echo"]
resources={resource_ids=["test"]}
credential_mode="service"
"#,
            &std::sync::Arc::new(crate::backend_registry()),
        )
        .unwrap();
        config.audit = Some(agent_access_core::AuditConfig::new(
            agent_access_core::AuditStoreType::Jsonl,
            dir.path().join("audit.jsonl").display().to_string(),
        ));
        config.limits.upload_spool_dir = dir.path().join("spool").display().to_string();
        let control = InvocationControl::default();
        let runtime = BrokerRuntime::with_providers(
            config,
            vec![std::sync::Arc::new(OutcomeProvider {
                stop: unknown.then(|| control.clone()),
            })],
        )
        .unwrap();
        let context = GovernedOperationContext {
            operation: OperationContext {
                agent_request_id: "output-test".into(),
                broker_request_id: "output-test-broker".into(),
                identity: IdentityContext::anonymous(),
                service: "fake".into(),
                action: "echo".into(),
                source: SourceContext::unknown(),
            },
            execution_context: ExecutionContext::new("default").unwrap(),
        };
        let response = runtime
            .invoke_owned_json(
                context,
                serde_json::from_value(json!({"inputs":{"project":"TEST","message":"hello"}}))
                    .unwrap(),
                control.clone(),
            )
            .await;
        assert!(control.dispatched());
        assert_eq!(control.completed(), !unknown);
        (response, control)
    }
    #[tokio::test]
    async fn oversized_completed_outcome_keeps_only_proven_status_and_no_secret() {
        let (mut response, control) = outcome(false).await;
        for status in [
            "applied",
            "applied_verified",
            "applied_unverified",
            "not_applied",
        ] {
            response.envelope.result = Some(json!({
                "mutationStatus":status,
                "issuedToken":"TEST-SECRET-MUST-NOT-ESCAPE",
                "locator":"PRIVATE-LOCATOR",
                "body":"x".repeat(32_000),
            }));
            if status == "applied_unverified" {
                response.status = 502;
                response.envelope.reason_code =
                    Some(agent_access_provider::ReasonCode::MutationVerificationFailed);
            }
            let result = broker(
                response.clone(),
                &control,
                16_384,
                &["/result/issuedToken".into()],
            );
            assert_eq!(result.is_error, Some(true));
            let value = result.structured_content.as_ref().unwrap();
            assert_eq!(value["error"]["code"], "mcp_response_too_large");
            assert_eq!(value["brokerOutcome"]["mutationStatus"], status);
            assert_eq!(
                value["execution"],
                json!({"dispatched":true,"completion":"completed"})
            );
            assert_eq!(value["resultAvailable"], false);
            assert_eq!(value["retrySafe"], false);
            assert_eq!(value["agentRequestId"], "output-test");
            if status == "applied_unverified" {
                assert_eq!(
                    value["brokerOutcome"]["reasonCode"],
                    "mutation_verification_failed"
                );
                assert_eq!(value["brokerOutcome"]["status"], 502);
            }
            let encoded =
                String::from_utf8(serialize(&result, 16_384 - WIRE_RESERVE).unwrap()).unwrap();
            assert!(!encoded.contains("TEST-SECRET-MUST-NOT-ESCAPE"));
            assert!(!encoded.contains("PRIVATE-LOCATOR"));
            assert!(result.meta.is_none());
        }
    }
    fn text(result: &CallToolResult) -> String {
        let content = serde_json::to_value(&result.content).unwrap();
        assert_eq!(content.as_array().unwrap().len(), 1, "{content}");
        content[0]["text"].as_str().unwrap().to_owned()
    }
    #[test]
    fn admission_rate_limits_use_the_message_as_text_and_keep_the_envelope() {
        for reason in ["rate_limited", "upstream_rate_limited"] {
            let envelope = json!({
                "reasonCode": reason,
                "error": {"message": "fake is rate limiting requests. Retry after 7s (at 2026-09-25T14:03:07Z)."},
                "result": {"limitScope": "upstream", "service": "fake", "retryAfterSeconds": 7},
            });
            let result = admission_failure(envelope.clone(), 64 * 1024).unwrap();
            assert_eq!(result.is_error, Some(true));
            assert_eq!(
                text(&result),
                "fake is rate limiting requests. Retry after 7s (at 2026-09-25T14:03:07Z)."
            );
            assert_eq!(result.structured_content.as_ref(), Some(&envelope));
        }
        let other = json!({"reasonCode": "concurrency_limited", "error": {"message": "busy"}});
        let result = admission_failure(other.clone(), 64 * 1024).unwrap();
        assert_eq!(text(&result), serde_json::to_string(&other).unwrap());
    }
    #[tokio::test]
    async fn dispatched_rate_limits_use_the_message_as_text_and_keep_the_envelope() {
        let (mut response, control) = outcome(false).await;
        let message = "fake is rate limiting requests. Retry later.";
        for reason in [
            agent_access_provider::ReasonCode::UpstreamRateLimited,
            agent_access_provider::ReasonCode::RateLimited,
        ] {
            response.status = 429;
            response.envelope.decision = agent_access_provider::Decision::Error;
            response.envelope.reason_code = Some(reason);
            response.envelope.error = Some(agent_access_core::ErrorBody {
                message: message.into(),
            });
            response.envelope.result = Some(json!({"limitScope": "upstream", "service": "fake"}));
            let result = broker(response.clone(), &control, 64 * 1024, &[]);
            assert_eq!(result.is_error, Some(true));
            assert_eq!(text(&result), message);
            let value = result.structured_content.as_ref().unwrap();
            assert_eq!(value["reasonCode"], reason.as_str());
            assert_eq!(value["error"]["message"], message);
            assert_eq!(value["result"]["limitScope"], "upstream");
        }
        // Other errors keep the JSON text copy of the envelope.
        response.status = 502;
        response.envelope.reason_code = Some(agent_access_provider::ReasonCode::UpstreamFailed);
        let result = broker(response, &control, 64 * 1024, &[]);
        assert_eq!(
            serde_json::from_str::<Value>(&text(&result)).unwrap(),
            *result.structured_content.as_ref().unwrap()
        );
    }
    #[tokio::test]
    async fn oversized_unknown_outcome_does_not_infer_application_or_completion() {
        let (mut response, control) = outcome(true).await;
        response.envelope.result =
            Some(json!({"mutationStatus":"unrecognized-private-state", "body":"x".repeat(32_000)}));
        let result = broker(response, &control, 16_384, &[]);
        let value = result.structured_content.unwrap();
        assert_eq!(
            value["execution"],
            json!({"dispatched":true,"completion":"unknown"})
        );
        assert_eq!(value["brokerOutcome"]["reasonCode"], "operation_cancelled");
        assert!(value["brokerOutcome"].get("mutationStatus").is_none());
        assert_eq!(value["retrySafe"], false);
        assert_eq!(value["resultAvailable"], false);
    }
}
