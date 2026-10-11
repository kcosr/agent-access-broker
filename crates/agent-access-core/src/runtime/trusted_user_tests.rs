use super::*;
use crate::{TrustedCallerConfig, TrustedCallerContextMode, TrustedCallerCredentialTransport};

const DIRECT_SECRET: &str = "fixture-direct-caller-credential";
const RELAY_SECRET: &str = "fixture-relay-caller-credential";

struct Fixture {
    _directory: TempDir,
    runtime: BrokerRuntime,
    direct_secret_path: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let directory = TempDir::new().unwrap();
        #[cfg(unix)]
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let mut config = managed_policy_fake_config(&directory.path().join("managed.sqlite"));
        config.identity.mode = "required".into();
        let direct_secret_path = directory.path().join("direct.token");
        for (name, credential, transport, namespace) in [
            (
                "direct",
                DIRECT_SECRET,
                TrustedCallerCredentialTransport::AuthorizationUser,
                Some("linux"),
            ),
            (
                "relay",
                RELAY_SECRET,
                TrustedCallerCredentialTransport::CallerAuthorization,
                Some("linux"),
            ),
            (
                "context",
                "fixture-context-caller-credential",
                TrustedCallerCredentialTransport::CallerAuthorization,
                None,
            ),
        ] {
            let path = directory.path().join(format!("{name}.token"));
            fs::write(&path, credential).unwrap();
            config.identity.trusted_callers.insert(
                name.into(),
                TrustedCallerConfig {
                    credential_ref: format!("file:{}", path.display()),
                    credential_transport: transport,
                    username_namespace: namespace.map(str::to_owned),
                    context_mode: TrustedCallerContextMode::Fixed,
                    execution_context: Some("default".into()),
                    allowed_execution_contexts: None,
                    allow_forwarded_identity: false,
                },
            );
        }
        let runtime = BrokerRuntime::new(config).unwrap();
        let store = runtime.managed_store().unwrap();
        store
            .create_principal(crate::PrincipalWriteRequest {
                role: crate::PrincipalRole::Admin,
                self_service_enabled: None,
                principal_id: "human-alice".into(),
                kind: "user".into(),
                display_name: None,
                email: None,
                external_subject: None,
                created_by: "operator".into(),
            })
            .unwrap();
        store
            .create_username_binding("human-alice", "linux", "Alice", "operator")
            .unwrap();
        Self {
            _directory: directory,
            runtime,
            direct_secret_path,
        }
    }

    fn headers(direct: bool, username: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(USER_HEADER, username.parse().unwrap());
        let (carrier, secret) = if direct {
            ("authorization", DIRECT_SECRET)
        } else {
            (CALLER_AUTHORIZATION_HEADER, RELAY_SECRET)
        };
        headers.insert(carrier, format!("Bearer {secret}").parse().unwrap());
        headers
    }
}

#[test]
fn trusted_user_shared_bearer_parser_checks_both_carriers_exactly() {
    for carrier in ["authorization", CALLER_AUTHORIZATION_HEADER] {
        let mut headers = HeaderMap::new();
        assert_eq!(parse_assertion_bearer(&headers, carrier), Ok(None));
        for value in ["bEaReR abc+./~=_-", &format!("Bearer {}", "x".repeat(8192))] {
            headers.insert(carrier, value.parse().unwrap());
            assert!(parse_assertion_bearer(&headers, carrier).unwrap().is_some());
        }
        for value in [
            "Bearer",
            "Bearer ",
            "Basic token",
            " Bearer token",
            "Bearer  token",
            "Bearer token ",
            "Bearer first,second",
            "Bearer first\tsecond",
            &format!("Bearer {}", "x".repeat(8193)),
        ] {
            headers.insert(carrier, value.parse().unwrap());
            assert_eq!(
                parse_assertion_bearer(&headers, carrier),
                Err(IdentityFailure::AssertionInvalid),
                "{carrier} parser accepted invalid shape"
            );
        }
        headers.insert(carrier, "Bearer same".parse().unwrap());
        headers.append(carrier, "Bearer same".parse().unwrap());
        assert_eq!(
            parse_assertion_bearer(&headers, carrier),
            Err(IdentityFailure::AssertionInvalid)
        );
    }
}

#[test]
fn trusted_user_direct_and_relay_resolve_exact_human_with_invocation_authority() {
    let fixture = Fixture::new();
    for direct in [false, true] {
        let headers = Fixture::headers(direct, "Alice");
        let admission = fixture.runtime.admit_mcp_ingress(&headers).unwrap();
        assert!(admission.is_username());
        assert_eq!(admission.is_direct_username(), direct);
        let resolved = fixture
            .runtime
            .resolve_admitted_identity_with_proof(&headers, &admission)
            .unwrap();
        assert_eq!(resolved.identity.principal, "human-alice");
        assert_eq!(
            resolved.identity.caller_id.as_deref(),
            Some(if direct { "direct" } else { "relay" })
        );
        let source = resolved.identity.source.unwrap();
        assert_eq!(source.name, "trusted_user");
        assert_eq!(source.kind, "trusted_user");
        assert_eq!(source.token_header, USER_HEADER);
        assert_eq!(source.token_scheme, "asserted");
        assert_eq!(source.token_class, Some(BrokerTokenClass::AgentInvoke));
        assert_eq!(source.namespace.as_deref(), Some("linux"));
        assert!(source.binding_id.is_some());
        assert!(source.token_id.is_none());
        assert!(resolved.proof.unwrap().is_username());
        let wrong_case = Fixture::headers(direct, "alice");
        let admission = fixture.runtime.admit_mcp_ingress(&wrong_case).unwrap();
        assert_eq!(
            fixture
                .runtime
                .resolve_admitted_identity(&wrong_case, &admission)
                .unwrap_err(),
            IdentityFailure::AssertionDenied
        );
    }
}

#[test]
fn trusted_user_rejects_competing_carriers_and_malformed_subject_before_lookup() {
    let fixture = Fixture::new();
    for (name, value) in [
        (
            CALLER_AUTHORIZATION_HEADER,
            format!("Bearer {RELAY_SECRET}"),
        ),
        (
            "x-aw-identity-token-sha256",
            format!("sha256:{}", "a".repeat(64)),
        ),
        (USER_HEADER, "Alice".into()),
        ("authorization", format!("Bearer {DIRECT_SECRET}")),
    ] {
        let mut headers = Fixture::headers(true, "Alice");
        headers.append(
            http::HeaderName::from_bytes(name.as_bytes()).unwrap(),
            value.parse().unwrap(),
        );
        assert_eq!(
            fixture.runtime.admit_mcp_ingress(&headers).unwrap_err(),
            IdentityFailure::AssertionInvalid
        );
    }
    for username in [
        "",
        "Alice,alice",
        " Alice",
        "Alice ",
        "a/b",
        "%61lice",
        "älice",
        &"a".repeat(129),
    ] {
        let headers = Fixture::headers(true, username);
        assert_eq!(
            fixture.runtime.admit_mcp_ingress(&headers).unwrap_err(),
            IdentityFailure::AssertionInvalid
        );
    }
    let mut headers = Fixture::headers(true, "Alice");
    headers.insert(crate::EXECUTION_CONTEXT_HEADER, "default".parse().unwrap());
    assert_eq!(
        fixture.runtime.admit_mcp_ingress(&headers).unwrap_err(),
        IdentityFailure::ExecutionContextInvalid
    );
}

#[test]
fn trusted_user_transport_and_capability_errors_never_fall_back() {
    let fixture = Fixture::new();
    let mut missing = HeaderMap::new();
    missing.insert(USER_HEADER, "Alice".parse().unwrap());
    assert_eq!(
        fixture.runtime.admit_mcp_ingress(&missing).unwrap_err(),
        IdentityFailure::CallerAuthenticationRequired
    );
    for (carrier, secret, expected) in [
        (
            "authorization",
            RELAY_SECRET,
            IdentityFailure::CallerAuthenticationInvalid,
        ),
        (
            CALLER_AUTHORIZATION_HEADER,
            DIRECT_SECRET,
            IdentityFailure::CallerAuthenticationInvalid,
        ),
        (
            "authorization",
            "ordinary-principal-token",
            IdentityFailure::CallerAuthenticationInvalid,
        ),
        (
            CALLER_AUTHORIZATION_HEADER,
            "fixture-context-caller-credential",
            IdentityFailure::CallerUserAssertionDenied,
        ),
    ] {
        let mut headers = missing.clone();
        headers.insert(carrier, format!("Bearer {secret}").parse().unwrap());
        assert_eq!(
            fixture.runtime.admit_mcp_ingress(&headers).unwrap_err(),
            expected
        );
    }
    for direct in [true, false] {
        let mut headers = Fixture::headers(direct, "Alice");
        assert_eq!(
            fixture.runtime.admit_ingress(&headers).unwrap_err(),
            IdentityFailure::AssertionUnsupported
        );
        headers.remove(USER_HEADER);
        if !direct {
            headers.insert(
                CALLER_AUTHORIZATION_HEADER,
                format!("Bearer {DIRECT_SECRET}").parse().unwrap(),
            );
        }
        assert_eq!(
            fixture.runtime.admit_ingress(&headers).unwrap_err(),
            if direct {
                IdentityFailure::Invalid
            } else {
                IdentityFailure::CallerAuthenticationInvalid
            }
        );
    }
}

#[test]
fn trusted_user_proof_revalidation_rejects_pause_aba_and_caller_rotation() {
    let fixture = Fixture::new();
    let headers = Fixture::headers(true, "Alice");
    let admission = fixture.runtime.admit_mcp_ingress(&headers).unwrap();
    let proof = fixture
        .runtime
        .resolve_admitted_identity_with_proof(&headers, &admission)
        .unwrap()
        .proof
        .unwrap();
    let store = fixture.runtime.managed_store().unwrap();
    store
        .create_username_binding("human-alice", "linux", "Alias", "operator")
        .unwrap();
    let alias_headers = Fixture::headers(true, "Alias");
    let alias_admission = fixture.runtime.admit_mcp_ingress(&alias_headers).unwrap();
    assert_eq!(
        fixture
            .runtime
            .revalidate_admitted_identity(&proof, &alias_admission)
            .unwrap_err(),
        IdentityFailure::AssertionDenied
    );
    let gate = store.identity_access("human-alice").unwrap();
    let paused = store
        .set_identity_access_paused("human-alice", true, gate.version, "operator")
        .unwrap();
    assert_eq!(
        fixture
            .runtime
            .revalidate_admitted_identity(&proof, &admission)
            .unwrap_err(),
        IdentityFailure::AssertionDenied
    );
    store
        .set_identity_access_paused("human-alice", false, paused.version, "operator")
        .unwrap();
    assert_eq!(
        fixture
            .runtime
            .revalidate_admitted_identity(&proof, &admission)
            .unwrap_err(),
        IdentityFailure::AssertionDenied
    );
    let refreshed = fixture
        .runtime
        .resolve_admitted_identity_with_proof(&headers, &admission)
        .unwrap()
        .proof
        .unwrap();
    assert!(
        fixture
            .runtime
            .revalidate_admitted_identity(&refreshed, &admission)
            .is_ok()
    );
    let config = (*fixture.runtime.config).clone();
    fs::write(
        &fixture.direct_secret_path,
        "fixture-rotated-caller-credential",
    )
    .unwrap();
    let rotated = BrokerRuntime::new(config).unwrap();
    assert_ne!(
        rotated.caller_security_binding(),
        fixture.runtime.caller_security_binding()
    );
    assert_eq!(
        rotated
            .revalidate_admitted_identity(&refreshed, &admission)
            .unwrap_err(),
        IdentityFailure::AssertionDenied
    );
    assert!(
        !format!(
            "{proof:?} {admission:?} {:?}",
            rotated.caller_security_binding()
        )
        .contains("Alice")
    );
}

#[test]
fn trusted_user_loaded_secret_validation_rejects_ambiguous_credentials() {
    let fixture = Fixture::new();
    let mut config = (*fixture.runtime.config).clone();
    config.identity.sources = vec![static_bearer_source_config(
        "static",
        "service-principal",
        vec![format!("file:{}", fixture.direct_secret_path.display())],
    )];
    assert_runtime_config_error_contains(
        BrokerRuntime::new(config.clone()),
        "identity.sources.static.type static_principals is only valid when identity.authority = toml",
    );
    // The configured authority currently excludes static sources from managed
    // identity. Test the loaded-secret invariant independently of that earlier gate.
    let sources = load_identity_sources(&config, None, None).unwrap();
    let error = trusted_callers::validate_caller_principal_credentials(
        &fixture.runtime.trusted_callers,
        &sources,
    )
    .unwrap_err()
    .to_string();
    assert!(error.contains("collides"), "{error}");
    let distinct_path = fixture.direct_secret_path.with_file_name("principal.token");
    fs::write(&distinct_path, "fixture-distinct-principal-credential").unwrap();
    config.identity.sources[0].principals[0].token_refs =
        vec![format!("file:{}", distinct_path.display())];
    let sources = load_identity_sources(&config, None, None).unwrap();
    trusted_callers::validate_caller_principal_credentials(
        &fixture.runtime.trusted_callers,
        &sources,
    )
    .unwrap();
    for secret in [
        "aab_reserved-direct-credential",
        "fixture,comma-credential",
        &"x".repeat(8193),
    ] {
        fs::write(&fixture.direct_secret_path, secret).unwrap();
        assert!(BrokerRuntime::new((*fixture.runtime.config).clone()).is_err());
    }
}

#[test]
fn trusted_user_hop_by_hop_hygiene_includes_alternate_principal_carriers() {
    let mut config = base_fake_config();
    let token_path = write_temp_secret("fixture-principal-credential");
    let mut source = static_bearer_source_config(
        "alternate",
        "agent-one",
        vec![format!("file:{}", token_path.display())],
    );
    source.header = "x-custom-principal".into();
    config.identity.sources.push(source);
    let runtime = BrokerRuntime::new(config).unwrap();
    let mut competing = Fixture::headers(true, "Alice");
    competing.insert(
        "x-custom-principal",
        "Bearer fixture-principal-credential".parse().unwrap(),
    );
    assert_eq!(
        runtime.admit_mcp_ingress(&competing).unwrap_err(),
        IdentityFailure::AssertionInvalid
    );
    for header in ["connection", "trailer"] {
        for protected in [
            "Authorization",
            USER_HEADER,
            CALLER_AUTHORIZATION_HEADER,
            "x-aw-identity-token-sha256",
            crate::EXECUTION_CONTEXT_HEADER,
            "X-Custom-Principal",
        ] {
            let mut headers = HeaderMap::new();
            headers.insert(header, format!("keep-alive, {protected}").parse().unwrap());
            assert_eq!(
                runtime.validate_ingress_security_headers(&headers, false),
                Err(IdentityFailure::AssertionInvalid)
            );
        }
    }
    let mut headers = HeaderMap::new();
    headers.insert("trailer", "x-unrelated".parse().unwrap());
    assert!(
        runtime
            .validate_ingress_security_headers(&headers, false)
            .is_ok()
    );
    assert_eq!(
        runtime.validate_ingress_security_headers(&headers, true),
        Err(IdentityFailure::AssertionInvalid)
    );
    fs::remove_file(token_path).unwrap();
}

#[tokio::test]
async fn trusted_user_unavailable_is_canonical_retryable_admission_error() {
    let fixture = Fixture::new();
    let headers = Fixture::headers(true, "Alice");
    let admission = fixture.runtime.admit_mcp_ingress(&headers).unwrap();
    let proof = fixture
        .runtime
        .resolve_admitted_identity_with_proof(&headers, &admission)
        .unwrap()
        .proof
        .unwrap();
    let store_path = &fixture.runtime.config.managed_store.as_ref().unwrap().path;
    rusqlite::Connection::open(store_path)
        .unwrap()
        .execute_batch("DROP TABLE principal_username_bindings")
        .unwrap();
    assert_eq!(
        fixture
            .runtime
            .resolve_admitted_identity(&headers, &admission)
            .unwrap_err(),
        IdentityFailure::Unavailable
    );
    assert_eq!(
        fixture
            .runtime
            .revalidate_admitted_identity(&proof, &admission)
            .unwrap_err(),
        IdentityFailure::Unavailable
    );
    let response = fixture
        .runtime
        .ingress_error_response_for_operation(
            OperationContext {
                agent_request_id: "agent-request".into(),
                broker_request_id: "broker-request".into(),
                identity: IdentityContext::anonymous(),
                service: "fake".into(),
                action: "echo".into(),
                source: SourceContext::unknown(),
            },
            IdentityFailure::Unavailable,
        )
        .await;
    assert_eq!(response.status, 503);
    assert_eq!(response.envelope.decision, Decision::Error);
    assert_eq!(response.envelope.service, "broker");
    assert_eq!(response.envelope.action, "request.admit");
    assert_eq!(
        response.envelope.reason_code,
        Some(ReasonCode::IdentityUnavailable)
    );
    assert!(response.envelope.result.is_none());
    assert!(response.envelope.resource_scopes.is_empty());
}
