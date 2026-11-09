//! Test-support result conformance. Every invocation of an action that
//! declares result schemas is checked strictly twice: the provider's raw
//! outcome after its hook contract check, and the final `result` (after
//! presentation and the host's own failure details) against the composed
//! payload union. Actions without schemas are skipped.
//!
//! A mismatch aborts the process after writing the service, action, stage
//! and the validator's locations to stderr. Invocations run inside spawned
//! owner tasks and HTTP connection tasks whose panics are caught and turned
//! into ordinary failure responses, which a test expecting a failure could
//! accept; aborting fails the enclosing test whatever outcome it expected.
//! Nextest runs each test in its own process, so exactly that test fails.
//! Release builds never contain this module.
use super::*;

/// The environment variable that selects a conformance-abort child test;
/// see the tests below.
#[cfg(test)]
const CHILD_ENV: &str = "AGENT_ACCESS_TEST_RESULT_CONFORMANCE_CHILD";

fn fail(service: &str, action: &str, stage: &str, problem: &str) -> ! {
    eprintln!(
        "result schema conformance failed for {service}.{action} {stage}: {problem}\n\
         Every emitted field must be declared by the action's result schemas \
         (strict validation closes objects without explicit additionalProperties). \
         Aborting so the enclosing test fails whatever outcome it expected."
    );
    std::process::abort();
}

/// Checks the provider's outcome of `service`.`action` strictly against the
/// action's declared schemas.
pub(super) fn check_provider_outcome(
    service: &str,
    descriptor: Option<&ActionDescriptor>,
    outcome: &Result<ProviderResult, ProviderError>,
) {
    let Some(descriptor) = descriptor.filter(|descriptor| descriptor.result_schemas.is_some())
    else {
        return;
    };
    if let Err(problem) =
        agent_access_provider::test_support::check_result_conforms(descriptor, outcome)
    {
        fail(service, &descriptor.action, "provider outcome", &problem);
    }
}

/// Checks the final `result` of `service`.`action` strictly against its
/// composed payload union.
pub(super) fn check_final_result(
    service: &str,
    descriptor: Option<&ActionDescriptor>,
    result: Option<&Value>,
) {
    let (Some(descriptor), Some(result)) = (descriptor, result) else {
        return;
    };
    let Some(payload) = crate::api::api_action_spec(service, descriptor)
        .as_ref()
        .and_then(crate::output_schema::result_payload_schema)
    else {
        return;
    };
    if let Err(problem) =
        agent_access_provider::test_support::check_strict_conformance(&payload, result)
    {
        fail(service, &descriptor.action, "final result", &problem);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime::tests::base_fake_config;

    /// Returns a result the fake echo schema does not declare.
    struct MismatchProvider;

    impl agent_access_provider::test_support::DescribedProvider for MismatchProvider {
        fn descriptor(&self) -> ServiceDescriptor {
            agent_access_fake::fake_descriptor()
        }
    }

    #[async_trait::async_trait]
    impl Provider for MismatchProvider {
        async fn resolve_scopes(
            &self,
            request: agent_access_provider::ScopeRequest<'_>,
        ) -> Result<agent_access_provider::ScopeResolution, ProviderError> {
            agent_access_fake::FakeProvider
                .echo_scopes(request.action(), request.inputs())
                .map(agent_access_provider::ScopeResolution::resources)
        }

        async fn invoke(
            &self,
            request: ProviderInvocation,
        ) -> Result<ProviderResult, ProviderError> {
            let mut result = agent_access_fake::FakeProvider.invoke(request).await?;
            result.result["undeclaredField"] = json!(true);
            Ok(result)
        }
    }

    fn operation() -> GovernedOperationContext {
        GovernedOperationContext {
            admission: None,
            operation: OperationContext {
                agent_request_id: "agent-conformance".to_string(),
                broker_request_id: "broker-conformance".to_string(),
                identity: IdentityContext::anonymous(),
                service: "fake".to_string(),
                action: "echo".to_string(),
                source: SourceContext::unknown(),
            },
            execution_context: ExecutionContext::new(DEFAULT_EXECUTION_CONTEXT).unwrap(),
        }
    }

    /// Guarded child of the test below: inert unless the parent selected a
    /// stage. Each stage's mismatch happens inside a spawned task, and the
    /// child then asserts the success it would see if the check only
    /// panicked, so only an abort can fail it.
    #[tokio::test]
    #[ignore = "child process of mismatches_abort_the_enclosing_test_process"]
    async fn conformance_abort_child() {
        let Ok(stage) = std::env::var(CHILD_ENV) else {
            return;
        };
        let task = tokio::spawn(async move {
            match stage.as_str() {
                "provider" => {
                    let runtime = BrokerRuntime::with_providers(
                        base_fake_config(),
                        vec![Arc::new(MismatchProvider)],
                    )
                    .unwrap();
                    let response = runtime
                        .invoke(
                            operation(),
                            InvokeRequest::new(json!({"project": "TEST", "message": "hi"})),
                        )
                        .await;
                    response.status
                }
                "final" => {
                    let descriptor = agent_access_fake::fake_descriptor();
                    check_final_result(
                        "fake",
                        descriptor.action("echo"),
                        Some(&json!({"provider": "fake", "undeclaredField": true})),
                    );
                    200
                }
                other => panic!("unknown conformance child stage {other}"),
            }
        });
        // A panic in the task would surface here as a JoinError the child
        // tolerates, like an owner task's caught panic.
        let status = task.await.unwrap_or(200);
        assert_eq!(status, 200);
    }

    #[test]
    fn mismatches_abort_the_enclosing_test_process() {
        for (stage, expected) in [
            (
                "provider",
                "result schema conformance failed for fake.echo provider outcome: echo success result: at / (schema /additionalProperties)",
            ),
            (
                "final",
                "result schema conformance failed for fake.echo final result: at /",
            ),
        ] {
            let output = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "runtime::result_conformance::tests::conformance_abort_child",
                    "--ignored",
                    "--nocapture",
                    "--test-threads=1",
                ])
                .env(CHILD_ENV, stage)
                .output()
                .unwrap();
            let stderr = String::from_utf8_lossy(&output.stderr);
            assert!(!output.status.success(), "{stage}: {stderr}");
            #[cfg(unix)]
            {
                use std::os::unix::process::ExitStatusExt;
                assert_eq!(
                    output.status.signal(),
                    Some(libc::SIGABRT),
                    "{stage}: {stderr}"
                );
            }
            assert!(stderr.contains(expected), "{stage}: {stderr}");
            assert!(stderr.contains("undeclaredField"), "{stage}: {stderr}");
        }
        // Conforming outcomes and actions without schemas pass silently.
        let descriptor = agent_access_fake::fake_descriptor();
        let echo = descriptor.action("echo");
        check_final_result(
            "fake",
            echo,
            Some(
                &json!({"provider": "fake", "action": "echo", "project": "TEST",
                "message": "hi", "credentialMode": "service", "principal": "anonymous"}),
            ),
        );
        check_final_result(
            "fake",
            echo,
            Some(&json!({"executionState": "not_dispatched", "retrySafe": true})),
        );
        let mut without = descriptor.clone();
        without.actions[0].result_schemas = None;
        check_provider_outcome(
            "fake",
            without.action("echo"),
            &Ok(ProviderResult::new(json!({"anything": true}))),
        );
        check_final_result(
            "fake",
            without.action("echo"),
            Some(&json!({"anything": true})),
        );
    }
}
