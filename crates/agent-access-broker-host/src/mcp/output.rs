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
/// The only constructor for downstream tool results. Every text block is a
/// representation of data retained in structured content, including errors.
fn tool_result(
    value: Value,
    error: bool,
    include_text_copy: bool,
    text_override: Option<String>,
) -> CallToolResult {
    let mut result = if error {
        CallToolResult::error(Vec::new())
    } else {
        CallToolResult::success(Vec::new())
    };
    if include_text_copy {
        result.content.push(rmcp::model::ContentBlock::text(
            text_override.unwrap_or_else(|| value.to_string()),
        ));
    }
    result.structured_content = Some(value);
    result
}
fn bounded_result(
    value: Value,
    error: bool,
    limit: usize,
    include_text_copy: bool,
    text_override: Option<String>,
) -> Result<CallToolResult, ()> {
    // Retain the source cap, then count the representation actually delivered.
    serialize(&value, limit)?;
    let result = tool_result(value, error, include_text_copy, text_override);
    serialize(&result, limit.saturating_sub(WIRE_RESERVE))?;
    Ok(result)
}
pub(super) fn result(
    value: Value,
    error: bool,
    limit: usize,
    include_text_copy: bool,
) -> Result<CallToolResult, ()> {
    bounded_result(value, error, limit, include_text_copy, None)
}
/// Inspection failures are standard Broker errors, not partial resource lists.
pub(super) fn resource_access_too_complex(include_text_copy: bool) -> CallToolResult {
    tool_result(
        json!({
            "decision":"error", "reasonCode":"resource_access_too_complex", "result":null,
            "error":{"message":"Resource access response exceeds the result size limit."}
        }),
        true,
        include_text_copy,
        None,
    )
}

/// Preflight the structured value and optional escaped text copy before
/// allocating that copy. The final serializer still checks the complete wrapper.
pub(super) fn resource_access_result(
    value: Value,
    limit: usize,
    include_text_copy: bool,
) -> CallToolResult {
    struct Counter {
        count: usize,
        maximum: usize,
        include_text_copy: bool,
    }
    impl Write for Counter {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            let escapes = if self.include_text_copy {
                bytes
                    .iter()
                    .filter(|byte| matches!(**byte, b'"' | b'\\'))
                    .count()
            } else {
                0
            };
            self.count = bytes
                .len()
                .checked_mul(if self.include_text_copy { 2 } else { 1 })
                .and_then(|size| size.checked_add(escapes))
                .and_then(|size| self.count.checked_add(size))
                .filter(|size| *size <= self.maximum)
                .ok_or_else(|| io::Error::other("resource access MCP limit"))?;
            Ok(bytes.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    // Subtract the placeholder's bytes once per represented copy. Quotes around
    // text, resultType and any future SDK wrapper fields remain in overhead.
    let overhead = serialize(
        &tool_result(Value::Null, false, include_text_copy, None),
        1024,
    )
    .expect("fixed MCP wrapper fits")
    .len()
        - if include_text_copy { 8 } else { 4 };
    let maximum = limit
        .min(agent_access_core::RESOURCE_ACCESS_MAX_RESPONSE_BYTES)
        .saturating_sub(WIRE_RESERVE);
    let mut counter = Counter {
        count: overhead,
        maximum,
        include_text_copy,
    };
    if overhead > maximum || serde_json::to_writer(&mut counter, &value).is_err() {
        return resource_access_too_complex(include_text_copy);
    }
    result(value, false, limit, include_text_copy)
        .unwrap_or_else(|_| resource_access_too_complex(include_text_copy))
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
/// Tool error for a request the Broker refused before dispatch. Rate-limited
/// errors use their complete message for the optional text representation.
pub(super) fn admission_failure(
    envelope: Value,
    limit: usize,
    include_text_copy: bool,
) -> Result<CallToolResult, ()> {
    let message = include_text_copy
        .then(|| rate_limit_message(&envelope))
        .flatten();
    bounded_result(envelope, true, limit, include_text_copy, message)
}
pub(super) fn message(message: &str, include_text_copy: bool) -> CallToolResult {
    tool_result(
        json!({"error":{"code":"mcp_tool_error","message":message}}),
        true,
        include_text_copy,
        None,
    )
}
pub(super) fn broker(
    response: BrokerResponse<Value>,
    control: &InvocationControl,
    limit: usize,
    sensitive: &[String],
    include_text_copy: bool,
) -> CallToolResult {
    let error = response.status >= 400
        || response.envelope.error.is_some()
        || response.envelope.decision != agent_access_provider::Decision::Allow;
    let normal = serialize(&response.envelope, limit)
        .ok()
        .and_then(|bytes| serde_json::from_slice(&bytes).ok())
        .and_then(|value| {
            let message = (error && include_text_copy)
                .then(|| rate_limit_message(&value))
                .flatten();
            bounded_result(value, error, limit, include_text_copy, message).ok()
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
    tool_result(
        json!({
            "error":{"code":"mcp_response_too_large","message":"Execution output could not be delivered within the MCP response limit. Do not repeat the operation to recover output."},
            "agentRequestId":response.envelope.agent_request_id,"brokerRequestId":response.envelope.broker_request_id,
            "service":response.envelope.service,"action":response.envelope.action,"brokerOutcome":outcome,
            "execution":{"dispatched":control.dispatched(),"completion":if control.completed(){"completed"}else if control.dispatched(){"unknown"}else{"not_started"}},
            "resultAvailable":false,"retrySafe":false
        }),
        true,
        include_text_copy,
        None,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resource_access_preflight_counts_full_escaped_wrapper_and_preserves_markers() {
        let value = json!({"access":[
            {"action":"page.view","scope":"location","projectionStatus":"too_complex","reasonCode":"resource_access_too_complex"},
            {"action":"space.list","scope":"resource","coverage":[{"selector":{"kind":"exact","value":"界\n\\\""},"restricted":false}]}
        ]});
        let expected = CallToolResult::structured(value.clone());
        let exact = serde_json::to_vec(&expected).unwrap().len() + WIRE_RESERVE;
        let result = resource_access_result(value.clone(), exact, true);
        assert_eq!(result.is_error, Some(false));
        assert_eq!(result.structured_content, Some(value.clone()));
        let result = resource_access_result(value, exact - 1, true);
        assert_eq!(result.is_error, Some(true));
        let failure = result.structured_content.unwrap();
        assert_eq!(failure["decision"], "error");
        assert_eq!(failure["reasonCode"], "resource_access_too_complex");
        assert!(failure["result"].is_null());
        assert!(failure.get("access").is_none());
    }

    #[test]
    fn counts_escaped_text_and_structured_copy() {
        // The core native-documentation matrix includes this framing allowance
        // when testing every action at the minimum HTTP response setting.
        assert_eq!(WIRE_RESERVE, 8192);
        let value = json!({"documentation":{"inputExamples":[{
            "label":"DOC_SENTINEL", "inputs":{"body":"\\\"".repeat(2000), "lines":"one\ntwo"}
        }]}});
        let one = serialize(&value, 64 * 1024).unwrap().len();
        assert!(result(value.clone(), false, one + WIRE_RESERVE, true).is_err());
        let encoded = CallToolResult::structured(value.clone());
        let exact = serde_json::to_vec(&encoded).unwrap().len() + WIRE_RESERVE;
        assert!(exact > one + WIRE_RESERVE);
        assert!(result(value.clone(), false, exact - 1, true).is_err());
        let result = result(value.clone(), false, exact, true).unwrap();
        assert_eq!(result.structured_content, Some(value.clone()));
        let wire = serde_json::to_value(result).unwrap();
        assert_eq!(
            serde_json::from_str::<Value>(wire["content"][0]["text"].as_str().unwrap()).unwrap(),
            value
        );
    }
    #[test]
    fn no_text_copy_preserves_nested_content_and_counts_only_the_emitted_wrapper() {
        let value = json!({"result":{"upstreamMcp":{
            "content":[{"type":"text","text":"nested upstream \\\" content"}],
            "structuredContent":{"body":"界\n\\\"".repeat(1000)}
        }}});
        let encoded = tool_result(value.clone(), false, false, None);
        let exact = serde_json::to_vec(&encoded).unwrap().len() + WIRE_RESERVE;
        assert!(result(value.clone(), false, exact, true).is_err());
        assert!(result(value.clone(), false, exact - 1, false).is_err());
        let result = result(value.clone(), false, exact, false).unwrap();
        assert!(result.content.is_empty());
        assert_eq!(result.structured_content, Some(value));
        assert_eq!(result.is_error, Some(false));
    }

    #[test]
    fn no_text_copy_resource_access_uses_actual_wire_size_and_retains_its_own_cap() {
        let value = json!({"access":[{"selector":{"value":"界\n\\\"".repeat(1000)}}]});
        let exact = serde_json::to_vec(&tool_result(value.clone(), false, false, None))
            .unwrap()
            .len()
            + WIRE_RESERVE;
        let result = resource_access_result(value.clone(), exact, false);
        assert!(result.content.is_empty());
        assert_eq!(result.is_error, Some(false));
        assert_eq!(result.structured_content, Some(value.clone()));
        for (limit, include_text_copy) in [(exact - 1, false), (exact, true)] {
            let result = resource_access_result(value.clone(), limit, include_text_copy);
            assert_eq!(result.is_error, Some(true));
            assert_eq!(result.content.is_empty(), !include_text_copy);
            assert_eq!(
                result.structured_content.unwrap()["reasonCode"],
                "resource_access_too_complex"
            );
        }
        let result = resource_access_result(
            json!({"access":"x".repeat(agent_access_core::RESOURCE_ACCESS_MAX_RESPONSE_BYTES)}),
            agent_access_core::RESOURCE_ACCESS_MAX_RESPONSE_BYTES * 2,
            false,
        );
        assert!(result.content.is_empty());
        assert_eq!(
            result.structured_content.unwrap()["reasonCode"],
            "resource_access_too_complex"
        );
    }

    #[test]
    fn rate_limit_budget_counts_the_selected_text_without_constructing_a_json_copy() {
        for reason in ["rate_limited", "upstream_rate_limited"] {
            let envelope = json!({"reasonCode":reason,"error":{"message":"Retry later."},"result":{"details":"x".repeat(4000)}});
            for include_text_copy in [true, false] {
                let expected = tool_result(
                    envelope.clone(),
                    true,
                    include_text_copy,
                    Some("Retry later.".into()),
                );
                let exact = serde_json::to_vec(&expected).unwrap().len() + WIRE_RESERVE;
                let result = admission_failure(envelope.clone(), exact, include_text_copy).unwrap();
                assert_eq!(
                    serde_json::to_value(result).unwrap(),
                    serde_json::to_value(expected).unwrap()
                );
                assert!(admission_failure(envelope.clone(), exact - 1, include_text_copy).is_err());
            }
        }
        let result = message("Complete tool failure message", false);
        assert!(result.content.is_empty());
        assert_eq!(result.is_error, Some(true));
        assert_eq!(
            result.structured_content.unwrap()["error"]["message"],
            "Complete tool failure message"
        );
    }

    #[test]
    fn writer_stops_before_allocating_excess() {
        assert!(serialize(&"x".repeat(100_000), 32).is_err());
    }

    #[test]
    fn oauth_fixture_documentation_projects_within_the_minimum_response_budget() {
        use agent_access_core::mcp::{
            McpView, OutputSchemas, ProjectionMode, STDIO_MAX_CATALOG_BYTES, ToolRegistry,
        };
        use agent_access_provider::BackendConfig;
        let descriptor = agent_access_fake::OAuthStubProviderConfig {
            base_url: "http://127.0.0.1:8099".into(),
        }
        .descriptor();
        let mut catalog = agent_access_core::empty_catalog(json!({"principal":"synthetic-reader"}));
        catalog
            .services
            .push(agent_access_core::api_service_spec(&descriptor, true).unwrap());
        assert_eq!(catalog.services[0].actions.len(), 3);
        let openapi = agent_access_core::openapi_from_catalog(
            &catalog,
            agent_access_core::RenderAuthMode::Omit,
            &[],
            "session",
        );
        let send = agent_access_core::send_schema_from_catalog(&catalog);
        for mode in [ProjectionMode::Http, ProjectionMode::Stdio] {
            for view in [McpView::Aggregate, McpView::Service("oauth_stub".into())] {
                let registry = ToolRegistry::build(
                    &catalog,
                    &view,
                    mode,
                    OutputSchemas::On,
                    STDIO_MAX_CATALOG_BYTES,
                )
                .unwrap();
                for action in &catalog.services[0].actions {
                    let documentation = action
                        .documentation
                        .as_ref()
                        .expect("fixture action guidance");
                    assert_eq!(
                        openapi["paths"][format!("/v1/invoke/oauth_stub/{}", action.action)]["post"]
                            ["x-agent-access-documentation"],
                        *documentation
                    );
                    let variant = send["oneOf"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .find(|variant| variant["properties"]["action"]["const"] == action.action)
                        .unwrap();
                    assert_eq!(variant["x-agent-access-documentation"], *documentation);
                    let detail = registry.describe_action(
                        "oauth_stub",
                        action,
                        serde_json::to_value(action).unwrap(),
                    );
                    assert!(detail["mcpTool"].is_object());
                    assert!(detail["mcpTool"].get("documentation").is_none());
                    let response = result(detail.clone(), false, 65_536, true).unwrap();
                    assert_eq!(response.structured_content.as_ref(), Some(&detail));
                    assert_eq!(
                        serde_json::from_str::<Value>(&text(&response)).unwrap(),
                        detail
                    );
                }
            }
        }
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
        async fn resolve_scopes(
            &self,
            request: agent_access_provider::ScopeRequest<'_>,
        ) -> Result<agent_access_provider::ScopeResolution, agent_access_provider::ProviderError>
        {
            agent_access_provider::Provider::resolve_scopes(
                &agent_access_fake::FakeProvider,
                request,
            )
            .await
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
            &format!(
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
selector={{kind="exact",value="TEST"}}
allowed_execution_contexts=["default"]
[[policy.grants]]
subjects=["group:anonymous"]
service="fake"
actions=["echo"]
resources={{resource_ids=["test"]}}
credential_mode="service"
[limits]
upload_spool_dir={spool:?}
"#,
                spool = dir.path().join("spool").display().to_string()
            ),
            &std::sync::Arc::new(crate::backend_registry()),
        )
        .unwrap();
        config.audit = Some(agent_access_core::AuditConfig::new(
            agent_access_core::AuditStoreType::Jsonl,
            dir.path().join("audit.jsonl").display().to_string(),
        ));
        let control = InvocationControl::default();
        let runtime = BrokerRuntime::with_providers(
            config,
            vec![std::sync::Arc::new(OutcomeProvider {
                stop: unknown.then(|| control.clone()),
            })],
        )
        .unwrap();
        let context = GovernedOperationContext {
            admission: None,
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
            .invoke_owned(
                context,
                serde_json::from_value(json!({"inputs":{"project":"TEST","message":"hello"}}))
                    .unwrap(),
                control.clone(),
                false,
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
                    Some(agent_access_provider::ReasonCode::MutationVerificationFailed.into());
            }
            let result = broker(
                response.clone(),
                &control,
                16_384,
                &["/result/issuedToken".into()],
                true,
            );
            let without_copy = broker(
                response.clone(),
                &control,
                16_384,
                &["/result/issuedToken".into()],
                false,
            );
            assert!(without_copy.content.is_empty());
            assert_eq!(without_copy.structured_content, result.structured_content);
            assert_eq!(without_copy.is_error, result.is_error);
            assert_eq!(without_copy.meta, result.meta);
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
            let result = admission_failure(envelope.clone(), 64 * 1024, true).unwrap();
            assert_eq!(result.is_error, Some(true));
            assert_eq!(
                text(&result),
                "fake is rate limiting requests. Retry after 7s (at 2026-09-25T14:03:07Z)."
            );
            assert_eq!(result.structured_content.as_ref(), Some(&envelope));
        }
        let other = json!({"reasonCode": "concurrency_limited", "error": {"message": "busy"}});
        let result = admission_failure(other.clone(), 64 * 1024, true).unwrap();
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
            response.envelope.reason_code = Some(reason.into());
            response.envelope.error = Some(agent_access_core::ErrorBody {
                message: message.into(),
            });
            response.envelope.result = Some(json!({"limitScope": "upstream", "service": "fake"}));
            let result = broker(response.clone(), &control, 64 * 1024, &[], true);
            assert_eq!(result.is_error, Some(true));
            assert_eq!(text(&result), message);
            let without_copy = broker(response.clone(), &control, 64 * 1024, &[], false);
            assert!(without_copy.content.is_empty());
            assert_eq!(without_copy.structured_content, result.structured_content);
            assert_eq!(without_copy.is_error, result.is_error);
            let value = result.structured_content.as_ref().unwrap();
            assert_eq!(value["reasonCode"], reason.as_str());
            assert_eq!(value["error"]["message"], message);
            assert_eq!(value["result"]["limitScope"], "upstream");
        }
        // Other errors keep the JSON text copy of the envelope.
        response.status = 502;
        response.envelope.reason_code =
            Some(agent_access_provider::ReasonCode::UpstreamFailed.into());
        let result = broker(response, &control, 64 * 1024, &[], true);
        assert_eq!(
            serde_json::from_str::<Value>(&text(&result)).unwrap(),
            *result.structured_content.as_ref().unwrap()
        );
    }
    #[tokio::test]
    async fn no_text_copy_retains_result_bearing_errors_and_counts_sensitive_metadata() {
        let (mut response, control) = outcome(false).await;
        response.status = 502;
        response.envelope.decision = agent_access_provider::Decision::Error;
        response.envelope.reason_code =
            Some(agent_access_provider::ReasonCode::MutationVerificationFailed.into());
        response.envelope.result =
            Some(json!({"mutationStatus":"applied_unverified","body":"bounded original result"}));
        let pointers = ["/result/body".to_owned()];
        let mirrored = broker(response.clone(), &control, 64 * 1024, &pointers, true);
        let without_copy = broker(response.clone(), &control, 64 * 1024, &pointers, false);
        assert!(without_copy.content.is_empty());
        assert_eq!(without_copy.structured_content, mirrored.structured_content);
        assert_eq!(without_copy.is_error, Some(true));
        assert_eq!(without_copy.meta, mirrored.meta);
        assert!(without_copy.meta.is_some());
        let exact = serde_json::to_vec(&without_copy).unwrap().len() + WIRE_RESERVE;
        assert_eq!(
            broker(response.clone(), &control, exact, &pointers, false).structured_content,
            without_copy.structured_content,
        );
        let overflow = broker(response, &control, exact - 1, &pointers, false);
        assert!(overflow.content.is_empty());
        let value = overflow.structured_content.unwrap();
        assert_eq!(value["error"]["code"], "mcp_response_too_large");
        assert_eq!(
            value["brokerOutcome"]["mutationStatus"],
            "applied_unverified"
        );
    }

    #[tokio::test]
    async fn oversized_unknown_outcome_does_not_infer_application_or_completion() {
        let (mut response, control) = outcome(true).await;
        response.envelope.result =
            Some(json!({"mutationStatus":"unrecognized-private-state", "body":"x".repeat(32_000)}));
        let result = broker(response.clone(), &control, 16_384, &[], true);
        let without_copy = broker(response, &control, 16_384, &[], false);
        assert!(without_copy.content.is_empty());
        assert_eq!(without_copy.structured_content, result.structured_content);
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
