use super::*;
use agent_access_cloudbees_ci::*;
use agent_access_fake::*;
use agent_access_provider::{
    ActionDescriptor, ActionIo, BackendRegistration, GIT_REPOSITORY_RESOURCE, LookupRequirement,
    ReasonCode, ResourceType, ScopedMcpNameSource, parse_backend_config,
};
use base64::Engine as _;

pub(crate) use agent_access_provider::test_support::TEST_CERT_PEM;

/// Outbound TLS trust in only the core fixture CA
/// (`tests/fixtures/outbound-tls/ca-a.pem`).
pub(crate) fn test_outbound_tls() -> PreparedOutboundTls {
    PreparedOutboundTls::custom_from_pem(include_bytes!("../tests/fixtures/outbound-tls/ca-a.pem"))
        .expect("test CA is valid")
}

/// The backends core tests configure, in the broker binary's order: the
/// development records backend comes last, with its `stub` OAuth dialect.
pub(crate) fn test_backend_registry() -> std::sync::Arc<BackendRegistry> {
    std::sync::Arc::new(
        BackendRegistry::new([
            &agent_access_jira::JIRA_BACKEND,
            &agent_access_confluence::CONFLUENCE_BACKEND,
            &agent_access_gitlab::GITLAB_BACKEND,
            &CLOUDBEES_CI_BACKEND,
            &FAKE_BACKEND,
            &OAUTH_STUB_BACKEND,
        ])
        .expect("core backends register consistently")
        .with_oauth_dialects([&STUB_OAUTH_DIALECT])
        .expect("core OAuth dialects register consistently"),
    )
}

pub(crate) fn test_resource_types() -> ResourceTypeRegistry {
    test_backend_registry().resource_types().clone()
}

/// Parses a broker configuration with every core backend registered.
pub(crate) fn parse_test_config(raw: &str) -> Result<BrokerConfig, ConfigError> {
    parse_broker_config_raw("test.toml", raw, &test_backend_registry())
}

fn select_resources(
    config: &mut BrokerConfig,
    resource_type: ResourceType,
    selectors: &[ResourceSelector],
) -> ResourceSelection {
    let contexts = config
        .execution_context
        .as_ref()
        .map(|c| c.allowed_values.clone())
        .unwrap_or_else(|| vec!["default".to_string()]);
    let mut resource_ids = Vec::new();
    for selector in selectors {
        let id = if let Some(existing) = config
            .policy
            .resources
            .iter_mut()
            .find(|r| r.resource_type == resource_type && r.selector == *selector)
        {
            existing.allowed_execution_contexts = contexts.clone();
            existing.id.clone()
        } else {
            let id = format!("test-resource-{}", config.policy.resources.len());
            config.policy.resources.push(ResourceDefinition {
                id: id.clone(),
                display_name: None,
                resource_type: resource_type.clone(),
                selector: selector.clone(),
                allowed_execution_contexts: contexts.clone(),
                enabled: true,
            });
            id
        };
        resource_ids.push(id);
    }
    ResourceSelection {
        resource_ids,
        resource_group_ids: Vec::new(),
    }
}

fn exact(value: &str) -> ResourceSelector {
    ResourceSelector::Exact {
        value: value.to_string(),
    }
}
fn namespace(value: &str) -> ResourceSelector {
    ResourceSelector::Namespace {
        value: value.to_string(),
    }
}

#[test]
fn home_expansion_helper_expands_only_current_user_forms() {
    let home = Path::new("home-dir");

    assert_eq!(
        expand_home_with("~", Some(home), "identity.token_file").unwrap(),
        PathBuf::from("home-dir")
    );
    assert_eq!(
        expand_home_with("~/agent-access/token", Some(home), "identity.token_file").unwrap(),
        PathBuf::from("home-dir").join("agent-access").join("token")
    );
    assert_eq!(
        expand_home_with(
            "~user/agent-access/token",
            Some(home),
            "identity.token_file"
        )
        .unwrap(),
        PathBuf::from("~user/agent-access/token")
    );
    assert_eq!(
        expand_home_with("relative/path", Some(home), "identity.token_file").unwrap(),
        PathBuf::from("relative/path")
    );
    assert_eq!(
        expand_home_with("./~/literal", Some(home), "identity.token_file").unwrap(),
        PathBuf::from("./~/literal")
    );
}

#[test]
fn home_expansion_helper_fails_when_home_is_missing() {
    let error = expand_home_with("~/token", None, "AGENT_ACCESS_TOKEN_FILE").unwrap_err();
    assert_eq!(error.label(), "AGENT_ACCESS_TOKEN_FILE");
    assert_eq!(
        error.to_string(),
        "AGENT_ACCESS_TOKEN_FILE uses '~' but the current user's home directory is unavailable"
    );

    assert_eq!(
        expand_home_with("relative/token", None, "identity.token_file").unwrap(),
        PathBuf::from("relative/token")
    );
}

#[test]
fn cli_tls_config_defaults_to_verified_default_roots() {
    let config: CliConfig = toml::from_str(
        r#"
            [service]
            url = "https://broker.example"
            "#,
    )
    .unwrap();
    assert!(config.service.tls.verify_certificates);
    assert!(config.service.tls.additional_ca_cert_files.is_empty());
    assert_eq!(
        config.defaults.read_content_format,
        ReadContentFormat::Native
    );
    assert_eq!(config.defaults.output_format, ResponseFormat::Json);
}

#[test]
fn cli_defaults_parse_response_formats_and_reject_unknown_values() {
    let config: CliConfig = toml::from_str(
        r#"
            [defaults]
            read_content_format = "markdown"
            output_format = "markdown"
            "#,
    )
    .unwrap();
    assert_eq!(
        config.defaults.read_content_format,
        ReadContentFormat::Markdown
    );
    assert_eq!(config.defaults.output_format, ResponseFormat::Markdown);

    assert!(
        toml::from_str::<CliConfig>(
            r#"
                [defaults]
                read_content_format = "plain_text"
                "#
        )
        .is_err()
    );
}

#[test]
fn cli_tls_config_rejects_empty_certificate_paths_in_both_modes() {
    for verify_certificates in [true, false] {
        let config = CliConfig {
            service: CliServiceConfig {
                url: "https://broker.example".to_string(),
                tls: CliTlsConfig {
                    verify_certificates,
                    additional_ca_cert_files: vec!["  ".to_string()],
                },
            },
            identity: CliIdentityConfig::default(),
            defaults: CliDefaultsConfig::default(),
        };
        let errors = validation_errors(validate_cli_config(&config));
        assert_contains(
            &errors,
            "service.tls.additional_ca_cert_files[0] must not be empty",
        );
    }
}

#[test]
fn cli_tls_certificate_loader_ignores_missing_paths() {
    let dir = tempfile::tempdir().unwrap();
    let config = tls_config(
        true,
        &[dir.path().join("missing-ca.pem").display().to_string()],
    );

    let certificates = load_cli_tls_certificates(&config).unwrap();
    assert!(certificates.is_empty());
}

#[test]
fn cli_tls_certificate_loader_parses_valid_multi_pem_files() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("bundle.pem");
    std::fs::write(&path, format!("{TEST_CERT_PEM}\n{TEST_CERT_PEM}")).unwrap();
    let config = tls_config(true, &[path.display().to_string()]);

    let certificates = load_cli_tls_certificates(&config).unwrap();
    assert_eq!(certificates.len(), 2);
}

#[test]
fn cli_tls_certificate_loader_rejects_bad_existing_paths_and_bundles() {
    let dir = tempfile::tempdir().unwrap();
    let cases = [
        (
            "empty.pem",
            "",
            "must contain at least one CERTIFICATE PEM block",
        ),
        (
            "not-pem.pem",
            "not a PEM bundle",
            "contains text outside PEM blocks",
        ),
        (
            "private-key.pem",
            "-----BEGIN PRIVATE KEY-----\nabc\n-----END PRIVATE KEY-----\n",
            "must contain only CERTIFICATE PEM blocks",
        ),
        (
            "malformed.pem",
            "-----BEGIN CERTIFICATE-----\nabc\n-----END CERTIFICATE-----\n",
            "certificate parse failed",
        ),
        (
            "trailing-junk.pem",
            "-----BEGIN CERTIFICATE-----\nMIIBgDCCASegAwIBAgIUPHDUu9WL36yvTmFeNFZVe/qhClcwCgYIKoZIzj0EAwIw\nHTEbMBkGA1UEAwwSUnVzdGxzIFJvYnVzdCBSb290MCAXDTc1MDEwMTAwMDAwMFoY\nDzQwOTYwMTAxMDAwMDAwWjAdMRswGQYDVQQDDBJSdXN0bHMgUm9idXN0IFJvb3Qw\nWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAASW/VkDFs5iGDQvH8jaXYT4jMx66jo+\n5CWKyMt4OlTDdBfKfnmQ9LYeK/PsYfJ8wVizuSlPzXi9je8SnyYejGP3o0MwQTAP\nBgNVHQ8BAf8EBQMDB4QAMB0GA1UdDgQWBBRqY/oMENJbNo7y39iL6GW3tDs0rzAP\nBgNVHRMBAf8EBTADAQH/MAoGCCqGSM49BAMCA0cAMEQCIEUbrmSUjANju9nNpFop\nPAl9Wh8tBxI5IY+BPh466+aUAiA1/9+prypt6s3Doo0GDsnoFGJi1UBivUg1qdik\ncy4eNw==\n-----END CERTIFICATE-----\njunk",
            "contains text outside PEM blocks",
        ),
    ];

    for (file_name, contents, needle) in cases {
        let path = dir.path().join(file_name);
        std::fs::write(&path, contents).unwrap();
        let errors = config_error_messages(load_cli_tls_certificates(&tls_config(
            true,
            &[path.display().to_string()],
        )));
        assert_contains(&errors, needle);
    }

    let errors = config_error_messages(load_cli_tls_certificates(&tls_config(
        true,
        &[dir.path().display().to_string()],
    )));
    assert_contains(&errors, "must be a file, not a directory");
}

#[test]
fn cli_tls_certificate_loader_expands_current_user_home_only_when_verifying() {
    let home = tempfile::tempdir().unwrap();
    std::fs::write(home.path().join("broker-ca.pem"), TEST_CERT_PEM).unwrap();
    let config = tls_config(true, &["~/broker-ca.pem".to_string()]);

    let certificates = load_cli_tls_certificates_with_home(&config, Some(home.path())).unwrap();
    assert_eq!(certificates.len(), 1);

    let errors = config_error_messages(load_cli_tls_certificates_with_home(&config, None));
    assert_contains(
        &errors,
        "uses '~' but the current user's home directory is unavailable",
    );

    let verify_off = tls_config(false, &["~/invalid-ca.pem".to_string()]);
    let certificates = load_cli_tls_certificates_with_home(&verify_off, None).unwrap();
    assert!(certificates.is_empty());
}

#[test]
fn cli_config_validate_parses_existing_tls_files_only_when_verifying() {
    let dir = tempfile::tempdir().unwrap();
    let invalid = dir.path().join("invalid.pem");
    let missing = dir.path().join("missing.pem");
    std::fs::write(&invalid, "not a PEM bundle").unwrap();

    let verify_on = dir.path().join("verify-on.toml");
    std::fs::write(
        &verify_on,
        format!(
            r#"
                [service]
                url = "https://broker.example"

                [service.tls]
                verify_certificates = true
                additional_ca_cert_files = ["{}", "{}"]
                "#,
            missing.display(),
            invalid.display()
        ),
    )
    .unwrap();
    let errors = validation_errors(validate_cli_config_file(&verify_on));
    assert_contains(&errors, "contains text outside PEM blocks");

    let verify_off = dir.path().join("verify-off.toml");
    std::fs::write(
        &verify_off,
        format!(
            r#"
                [service]
                url = "https://broker.example"

                [service.tls]
                verify_certificates = false
                additional_ca_cert_files = ["{}"]
                "#,
            invalid.display()
        ),
    )
    .unwrap();
    validate_cli_config_file(&verify_off).unwrap();
}

#[test]
fn reason_codes_have_expected_statuses() {
    for code in ReasonCode::all() {
        assert!(code.http_status() >= 400);
    }
    assert_eq!(ReasonCode::VerificationMismatch.http_status(), 409);
    assert_eq!(ReasonCode::MutationVerificationFailed.http_status(), 409);
    assert_eq!(ReasonCode::WebhookDestinationDenied.http_status(), 403);
    assert_eq!(
        ReasonCode::WebhookDestinationDenied.as_str(),
        "webhook_destination_denied"
    );
    assert!(
        ReasonCode::all().contains(&ReasonCode::WebhookDestinationDenied),
        "webhook destination denial must remain in the published reason-code set"
    );
    assert_eq!(
        ReasonCode::MutationVerificationFailed.as_str(),
        "mutation_verification_failed"
    );
    assert_eq!(
        serde_json::to_value(ReasonCode::MutationVerificationFailed).unwrap(),
        serde_json::json!("mutation_verification_failed")
    );
    assert!(
        ReasonCode::all().contains(&ReasonCode::MutationVerificationFailed),
        "mutation verification failure must remain in the published reason-code set"
    );
    assert_eq!(ReasonCode::BrokerTokenPaused.http_status(), 401);
    assert_eq!(ReasonCode::BrokerTokenStateConflict.http_status(), 409);
    assert_eq!(
        ReasonCode::BrokerTokenPaused.as_str(),
        "broker_token_paused"
    );
    assert_eq!(
        ReasonCode::BrokerTokenStateConflict.as_str(),
        "broker_token_state_conflict"
    );
    assert_eq!(ReasonCode::BodyFormatUnsupported.http_status(), 415);
    assert_eq!(ReasonCode::ResponseFormatUnsupported.http_status(), 415);
    assert_eq!(
        ReasonCode::ResponseFormatUnsupported.as_str(),
        "response_format_unsupported"
    );
    assert_eq!(ReasonCode::BodySizeDenied.http_status(), 413);
    assert_eq!(ReasonCode::CursorSigningUnavailable.http_status(), 503);
    assert_eq!(ReasonCode::BodySizeDenied.as_str(), "body_size_denied");
    assert_eq!(
        serde_json::to_value(ReasonCode::BodySizeDenied).unwrap(),
        serde_json::json!("body_size_denied")
    );
    assert_eq!(ReasonCode::UpstreamConnectionFailed.http_status(), 502);
    assert_eq!(ReasonCode::UpstreamRateLimited.http_status(), 429);
    assert_eq!(
        ReasonCode::UpstreamRateLimited.as_str(),
        "upstream_rate_limited"
    );
    assert_eq!(
        serde_json::to_value(ReasonCode::UpstreamRateLimited).unwrap(),
        serde_json::json!("upstream_rate_limited")
    );
    assert!(
        ReasonCode::all().contains(&ReasonCode::UpstreamRateLimited),
        "upstream throttling must remain in the published reason-code set"
    );
    let execution_context_codes = [
        (
            ReasonCode::ExecutionContextRequired,
            "execution_context_required",
        ),
        (
            ReasonCode::ExecutionContextInvalid,
            "execution_context_invalid",
        ),
        (
            ReasonCode::ExecutionContextDenied,
            "execution_context_denied",
        ),
    ];
    for (code, encoded) in execution_context_codes {
        assert!(ReasonCode::all().contains(&code));
        assert_eq!(code.as_str(), encoded);
        assert_eq!(code.http_status(), 403);
        assert_eq!(
            serde_json::to_value(code).unwrap(),
            serde_json::json!(encoded)
        );
    }
    for (code, encoded, status) in [
        (
            ReasonCode::AuditQueryUnavailable,
            "audit_query_unavailable",
            404,
        ),
        (
            ReasonCode::AuditRequestNotFound,
            "audit_request_not_found",
            404,
        ),
        (ReasonCode::AuditQueryTimeout, "audit_query_timeout", 503),
    ] {
        assert!(ReasonCode::all().contains(&code));
        assert_eq!(code.as_str(), encoded);
        assert_eq!(code.http_status(), status);
        assert_eq!(
            serde_json::to_value(code).unwrap(),
            serde_json::json!(encoded)
        );
    }
    let oidc_codes = [
        (ReasonCode::OidcUnavailable, "oidc_unavailable", 503),
        (ReasonCode::OidcFlowInvalid, "oidc_flow_invalid", 400),
        (ReasonCode::OidcFlowExpired, "oidc_flow_expired", 400),
        (ReasonCode::OidcProviderDenied, "oidc_provider_denied", 401),
        (
            ReasonCode::OidcIdentityInvalid,
            "oidc_identity_invalid",
            401,
        ),
        (
            ReasonCode::OidcGroupClaimsIncomplete,
            "oidc_group_claims_incomplete",
            403,
        ),
        (
            ReasonCode::OidcAdmissionDenied,
            "oidc_admission_denied",
            403,
        ),
        (
            ReasonCode::OidcLoginMethodConflict,
            "oidc_login_method_conflict",
            409,
        ),
        (
            ReasonCode::ExternalGroupBindingNotFound,
            "external_group_binding_not_found",
            404,
        ),
        (
            ReasonCode::ExternalGroupBindingConflict,
            "external_group_binding_conflict",
            409,
        ),
    ];
    for (code, encoded, status) in oidc_codes {
        assert!(ReasonCode::all().contains(&code));
        assert_eq!(code.as_str(), encoded);
        assert_eq!(code.http_status(), status);
        assert_eq!(
            serde_json::to_value(code).unwrap(),
            serde_json::json!(encoded)
        );
    }
}

#[test]
fn response_envelope_skips_absent_reason_code_and_includes_reason() {
    let envelope = ResponseEnvelope::<serde_json::Value> {
        agent_request_id: "agent-1".to_string(),
        broker_request_id: "broker-1".to_string(),
        decision: Decision::Deny,
        service: "jira".to_string(),
        action: "issue.view".to_string(),
        resource_scopes: ResourceScopes::new(),
        reason_code: None,
        reason: Some("policy denied".to_string()),
        result: None,
        error: Some(ErrorBody {
            message: "denied".to_string(),
        }),
    };
    let value = serde_json::to_value(envelope).unwrap();
    assert!(value.get("reasonCode").is_none());
    assert_eq!(value["reason"], "policy denied");
}

#[test]
fn outbound_tls_config_defaults_and_rejects_invalid_contracts() {
    let network: NetworkConfig = toml::from_str("").unwrap();
    assert_eq!(network.outbound_tls.trust, OutboundTlsTrustMode::System);
    assert!(network.outbound_tls.ca_certificate.is_none());
    for raw in [
        "[outbound_tls]\ntrust = 'insecure'",
        "[outbound_tls]\ntrust = 'system'\nunknown = true",
    ] {
        assert!(toml::from_str::<NetworkConfig>(raw).is_err());
    }
    for raw in [
        "[outbound_tls]\ntrust = 'system'\nca_certificate = '/tmp/roots.pem'",
        "[outbound_tls]\ntrust = 'custom'",
        "[outbound_tls]\ntrust = 'system_plus_custom'",
        "[outbound_tls]\ntrust = 'custom'\nca_certificate = ''",
        "[outbound_tls]\ntrust = 'custom'\nca_certificate = 'relative.pem'",
    ] {
        let network: NetworkConfig = toml::from_str(raw).unwrap();
        let mut errors = Vec::new();
        validate_network(&network, &mut errors);
        assert!(!errors.is_empty(), "accepted {raw}");
    }
}

#[test]
fn broker_file_validation_loads_outbound_ca_bundle() {
    let directory = tempfile::tempdir().unwrap();
    let bundle = directory.path().join("roots.pem");
    let config_path = directory.path().join("broker.toml");
    let fixture =
        std::fs::read_to_string(workspace_root().join("tests/fixtures/fake-broker.toml")).unwrap();
    let mut document: toml::Value = toml::from_str(&fixture).unwrap();
    document.as_table_mut().unwrap().insert(
        "network".into(),
        toml::toml! {
            [outbound_tls]
            trust = "custom"
            ca_certificate = "placeholder"
        }
        .into(),
    );
    document["network"]["outbound_tls"]["ca_certificate"] =
        toml::Value::String(bundle.display().to_string());
    std::fs::write(&config_path, toml::to_string(&document).unwrap()).unwrap();
    // Structural validation stays free of filesystem I/O.
    validate_broker_config(&load_broker_config(&config_path, &test_backend_registry()).unwrap())
        .unwrap();
    assert!(validate_broker_config_file(&config_path, &test_backend_registry()).is_err());
    std::fs::write(&bundle, TEST_CERT_PEM).unwrap();
    validate_broker_config_file(&config_path, &test_backend_registry()).unwrap();
    std::fs::write(&bundle, "not a certificate").unwrap();
    assert!(validate_broker_config_file(&config_path, &test_backend_registry()).is_err());
}

#[test]
fn sample_configs_validate() {
    let root = workspace_root();
    validate_broker_config_file(
        root.join("agent-access-broker.sample.toml"),
        &test_backend_registry(),
    )
    .unwrap();
    validate_broker_config_file(
        root.join("agent-access-broker.production.sample.toml"),
        &test_backend_registry(),
    )
    .unwrap();
    validate_broker_config_file(
        root.join("tests/fixtures/fake-broker.toml"),
        &test_backend_registry(),
    )
    .unwrap();
    validate_cli_config_file(root.join("agent-access.sample.toml")).unwrap();
}

#[test]
fn rejects_provider_tenant_hosts_that_are_not_bare_hosts() {
    for invalid in [
        "Example.atlassian.net",
        "example.atlassian.net:443",
        "example.atlassian.net?x=1",
        "example.atlassian.net#fragment",
        " example.atlassian.net",
        "example.atlassian.net ",
        "example.atlassian.net\\path",
    ] {
        let mut config = sample_broker();
        config
            .providers
            .get_mut::<agent_access_jira::JiraProviderConfig>()
            .unwrap()
            .tenant_host = invalid.to_string();
        config
            .providers
            .get_mut::<agent_access_confluence::ConfluenceProviderConfig>()
            .unwrap()
            .tenant_host = invalid.to_string();
        let errors = validation_errors(validate_broker_config(&config));
        assert_contains(
            &errors,
            "providers.jira.tenant_host must be a lowercase, normalized bare host name",
        );
        assert_contains(
            &errors,
            "providers.confluence.tenant_host must be a lowercase, normalized bare host name",
        );
    }
}

#[test]
fn initial_admin_rejects_only_the_known_sample_password_placeholders() {
    let mut config = microsoft_oidc_broker();
    config.management.initial_admin.mode = "create_if_empty".to_string();
    config.management.initial_admin.principal_id = Some("bootstrap-admin".to_string());
    for password in [
        "change-me-on-first-login",
        "<insert-a-unique-generated-password>",
    ] {
        config.management.initial_admin.initial_password = Some(password.to_string());
        let errors = validation_errors(validate_broker_config(&config));
        assert_contains(
            &errors,
            "management.initial_admin.initial_password must replace the sample placeholder",
        );
        assert!(errors.iter().all(|error| !error.contains(password)));
    }

    // The check rejects exact documented sentinels, not a general password pattern.
    for password in [
        "generated-bootstrap-fixture-password",
        "Change-me-on-first-login",
        "prefix-change-me-on-first-login",
        "<insert-a-unique-generated-password>-suffix",
    ] {
        config.management.initial_admin.initial_password = Some(password.to_string());
        validate_broker_config(&config).unwrap();
    }
}

#[test]
fn browser_auth_validation_requires_backing_store_and_secret_refs() {
    let mut config = sample_broker();
    config.browser_auth.enabled = true;
    let errors = validate_broker_config(&config)
        .unwrap_err()
        .errors()
        .to_vec();
    assert_contains(&errors, "browser_auth.enabled requires managed_store");
    assert_contains(&errors, "browser_auth.enabled requires management.enabled");
    assert_contains(&errors, "browser_auth.enabled requires broker_tokens");
    assert_contains(
        &errors,
        "browser_auth.csrf_key_ref is required when browser_auth.enabled is true",
    );
    assert_contains(
        &errors,
        "browser_auth.local_password.enabled must be true when browser_auth.enabled is true",
    );

    config.managed_store = Some(ManagedStoreConfig {
        kind: "sqlite".to_string(),
        path: "/var/lib/agent-access-broker/managed-store.sqlite3".to_string(),
        require_registered_principal_for_invocation: true,
        auto_migrate: false,
    });
    config.management.enabled = true;
    config.broker_tokens = Some(BrokerTokensConfig {
        hash_key_ref: "env:AGENT_ACCESS_BROKER_TOKEN_HASH_KEY".to_string(),
        default_agent_invoke_ttl: Some("30d".to_string()),
        default_user_manage_ttl: Some("2h".to_string()),
        default_admin_ttl: Some("2h".to_string()),
        max_self_issued_agent_invoke_ttl: Some("30d".to_string()),
        ..Default::default()
    });
    config.browser_auth.csrf_key_ref = Some("env:AGENT_ACCESS_BROWSER_CSRF_KEY".to_string());
    config.browser_auth.local_password.enabled = true;
    config.browser_auth.local_password.pepper_ref =
        Some("env:AGENT_ACCESS_LOCAL_PASSWORD_PEPPER".to_string());

    validate_broker_config(&config).unwrap();

    let mut bad_cookie = config.clone();
    bad_cookie.browser_auth.session_cookie_name = "__host-aab_session".to_string();
    let errors = validate_broker_config(&bad_cookie)
        .unwrap_err()
        .errors()
        .to_vec();
    assert_contains(
        &errors,
        "browser_auth.session_cookie_name must not use __Host- or __Secure- prefixes",
    );

    let mut bad_return_path = config.clone();
    bad_return_path.browser_auth.allowed_return_paths = vec!["/ui/%2e%2e".to_string()];
    let errors = validate_broker_config(&bad_return_path)
        .unwrap_err()
        .errors()
        .to_vec();
    assert_contains(
        &errors,
        "browser_auth.allowed_return_paths entry \"/ui/%2e%2e\" must be a literal path without encoded characters",
    );

    let mut reserved_csrf_header = config.clone();
    reserved_csrf_header.browser_auth.csrf_header = "x-agent-access-context".to_string();
    let errors = validation_errors(validate_broker_config(&reserved_csrf_header));
    assert_contains(
        &errors,
        "browser_auth.csrf_header must not use reserved header X-Agent-Access-Context",
    );

    let mut production = config.clone();
    production.deployment.environment = "production".to_string();
    production.deployment.allow_production_anonymous = true;
    let errors = validate_broker_config(&production)
        .unwrap_err()
        .errors()
        .to_vec();
    assert_contains(
        &errors,
        "browser_auth.public_origin is required when browser_auth.enabled is true in production",
    );
    production.browser_auth.public_origin = Some("https://broker.example".to_string());
    validate_broker_config(&production).unwrap();
}

#[test]
fn microsoft_oidc_defaults_are_disabled_and_bounded() {
    let microsoft = MicrosoftOidcConfig::default();
    assert!(!microsoft.enabled);
    assert_eq!(microsoft.tenant_id, None);
    assert_eq!(microsoft.client_id, None);
    assert_eq!(microsoft.client_secret_ref, None);
    assert_eq!(microsoft.flow_key_ref, None);
    assert_eq!(microsoft.flow_ttl, "10m");
    assert_eq!(microsoft.max_pending_flows, 10_000);
    assert!(microsoft.jit_provisioning);
    assert_eq!(microsoft.external_membership_ttl, "8h");
}

#[test]
fn microsoft_oidc_accepts_the_strict_single_provider_configuration() {
    let config = microsoft_oidc_broker();
    validate_broker_config(&config).unwrap();
}

#[test]
fn microsoft_oidc_requires_managed_browser_auth_backing() {
    let mut config = microsoft_oidc_broker();
    config.browser_auth.enabled = false;
    config.identity.authority = "toml".to_string();
    config.managed_store = None;
    config.broker_tokens = None;
    config.management.enabled = false;
    config.browser_auth.local_password.enabled = false;

    let errors = validation_errors(validate_broker_config(&config));
    for expected in [
        "requires browser_auth.enabled",
        "requires identity.authority = managed",
        "requires managed_store",
        "requires broker_tokens",
        "requires management.enabled",
        "requires browser_auth.local_password.enabled",
    ] {
        assert_contains(&errors, expected);
    }
}

#[test]
fn microsoft_oidc_requires_canonical_tenant_and_client_uuids() {
    for invalid in [
        "AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE",
        "{aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee}",
        "aaaaaaaabbbbccccddddeeeeeeeeeeee",
        "not-a-uuid",
        " aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
    ] {
        let mut tenant = microsoft_oidc_broker();
        tenant.browser_auth.oidc.microsoft.tenant_id = Some(invalid.to_string());
        let errors = validation_errors(validate_broker_config(&tenant));
        assert_contains(
            &errors,
            "browser_auth.oidc.microsoft.tenant_id must be a canonical lowercase hyphenated UUID",
        );

        let mut client = microsoft_oidc_broker();
        client.browser_auth.oidc.microsoft.client_id = Some(invalid.to_string());
        let errors = validation_errors(validate_broker_config(&client));
        assert_contains(
            &errors,
            "browser_auth.oidc.microsoft.client_id must be a canonical lowercase hyphenated UUID",
        );
    }

    let mut missing = microsoft_oidc_broker();
    missing.browser_auth.oidc.microsoft.tenant_id = None;
    missing.browser_auth.oidc.microsoft.client_id = None;
    let errors = validation_errors(validate_broker_config(&missing));
    assert_contains(&errors, "browser_auth.oidc.microsoft.tenant_id is required");
    assert_contains(&errors, "browser_auth.oidc.microsoft.client_id is required");
}

#[test]
fn microsoft_oidc_validates_secret_reference_shapes() {
    for invalid in ["", "secret", "env:lowercase", "file:relative"] {
        let mut client_secret = microsoft_oidc_broker();
        client_secret.browser_auth.oidc.microsoft.client_secret_ref = Some(invalid.to_string());
        let errors = validation_errors(validate_broker_config(&client_secret));
        assert_contains(
            &errors,
            "browser_auth.oidc.microsoft.client_secret_ref must be env:NAME or file:/absolute/path",
        );

        let mut flow_key = microsoft_oidc_broker();
        flow_key.browser_auth.oidc.microsoft.flow_key_ref = Some(invalid.to_string());
        let errors = validation_errors(validate_broker_config(&flow_key));
        assert_contains(
            &errors,
            "browser_auth.oidc.microsoft.flow_key_ref must be env:NAME or file:/absolute/path",
        );
    }

    let mut missing = microsoft_oidc_broker();
    missing.browser_auth.oidc.microsoft.client_secret_ref = None;
    missing.browser_auth.oidc.microsoft.flow_key_ref = None;
    let errors = validation_errors(validate_broker_config(&missing));
    assert_contains(
        &errors,
        "browser_auth.oidc.microsoft.client_secret_ref is required",
    );
    assert_contains(
        &errors,
        "browser_auth.oidc.microsoft.flow_key_ref is required",
    );
}

#[test]
fn microsoft_oidc_enforces_flow_and_membership_bounds() {
    for ttl in ["2m", "15m"] {
        let mut config = microsoft_oidc_broker();
        config.browser_auth.oidc.microsoft.flow_ttl = ttl.to_string();
        validate_broker_config(&config).unwrap();
    }
    for ttl in ["119s", "16m", "never", "0m"] {
        let mut config = microsoft_oidc_broker();
        config.browser_auth.oidc.microsoft.flow_ttl = ttl.to_string();
        let errors = validation_errors(validate_broker_config(&config));
        assert_contains(&errors, "browser_auth.oidc.microsoft.flow_ttl");
    }

    for ttl in ["15m", "24h"] {
        let mut config = microsoft_oidc_broker();
        config.browser_auth.oidc.microsoft.external_membership_ttl = ttl.to_string();
        validate_broker_config(&config).unwrap();
    }
    for ttl in ["899s", "25h", "never", "0h"] {
        let mut config = microsoft_oidc_broker();
        config.browser_auth.oidc.microsoft.external_membership_ttl = ttl.to_string();
        let errors = validation_errors(validate_broker_config(&config));
        assert_contains(
            &errors,
            "browser_auth.oidc.microsoft.external_membership_ttl",
        );
    }

    for cap in [100, 100_000] {
        let mut config = microsoft_oidc_broker();
        config.browser_auth.oidc.microsoft.max_pending_flows = cap;
        validate_broker_config(&config).unwrap();
    }
    for cap in [0, 99, 100_001, u32::MAX] {
        let mut config = microsoft_oidc_broker();
        config.browser_auth.oidc.microsoft.max_pending_flows = cap;
        let errors = validation_errors(validate_broker_config(&config));
        assert_contains(
            &errors,
            "browser_auth.oidc.microsoft.max_pending_flows must be between 100 and 100000",
        );
    }
}

#[test]
fn microsoft_oidc_requires_https_except_loopback_development_and_test() {
    for environment in ["development", "test"] {
        for host in ["localhost", "127.0.0.1", "[::1]"] {
            let mut config = microsoft_oidc_broker();
            config.deployment.environment = environment.to_string();
            config.browser_auth.public_origin = Some(format!("http://{host}:8080"));
            validate_broker_config(&config).unwrap();
        }
    }

    for (environment, origin) in [
        ("production", "http://127.0.0.1:8080"),
        ("production", "http://[::1]:8080"),
        ("staging", "http://localhost:8080"),
        ("staging", "http://[::1]:8080"),
        ("development", "http://broker.example"),
        ("development", "http://127.0.0.2:8080"),
        ("development", "http://[::ffff:127.0.0.1]:8080"),
        ("development", "http://[2001:db8::1]:8080"),
    ] {
        let mut config = microsoft_oidc_broker();
        config.deployment.environment = environment.to_string();
        config.deployment.allow_production_anonymous = environment == "production";
        config.browser_auth.public_origin = Some(origin.to_string());
        let errors = validation_errors(validate_broker_config(&config));
        assert_contains(
            &errors,
            "browser_auth.public_origin must use https when Microsoft OIDC is enabled",
        );
    }

    let mut missing = microsoft_oidc_broker();
    missing.browser_auth.public_origin = None;
    let errors = validation_errors(validate_broker_config(&missing));
    assert_contains(
        &errors,
        "browser_auth.public_origin is required when Microsoft OIDC is enabled",
    );
}

#[test]
fn disabled_microsoft_oidc_does_not_require_provider_fields_or_secrets() {
    let mut config = sample_broker();
    config.browser_auth.oidc.microsoft = MicrosoftOidcConfig {
        enabled: false,
        tenant_id: Some("not-a-uuid".to_string()),
        client_id: None,
        client_secret_ref: Some("file:/definitely/missing".to_string()),
        flow_key_ref: None,
        flow_ttl: "invalid".to_string(),
        max_pending_flows: 0,
        jit_provisioning: true,
        external_membership_ttl: "invalid".to_string(),
    };
    validate_broker_config(&config).unwrap();
}

#[test]
fn microsoft_oidc_toml_rejects_generic_and_legacy_fields() {
    let sample =
        std::fs::read_to_string(workspace_root().join("agent-access-broker.sample.toml")).unwrap();
    for field in [
        "issuer = \"https://login.microsoftonline.com/common/v2.0\"",
        "redirect_path = \"/callback\"",
        "scopes = [\"openid\"]",
        "providers = []",
        "require_mapped_group = true",
    ] {
        let raw = format!("{sample}\n[browser_auth.oidc.microsoft]\nenabled = false\n{field}\n");
        let error = parse_test_config(&raw).unwrap_err();
        assert!(
            error.to_string().contains("unknown field"),
            "expected unknown-field error for {field:?}, got {error}"
        );
    }
}

#[test]
fn accepts_egress_proxy_config_at_global_and_service_scopes() {
    let mut config = sample_broker();
    config.network.egress_proxy = Some(EgressProxyConfig {
        url: "http://proxy.example:8080".to_string(),
        username_ref: None,
        password_ref: None,
    });
    config
        .providers
        .get_mut::<agent_access_jira::JiraProviderConfig>()
        .unwrap()
        .egress_proxy = Some(EgressProxyConfig {
        url: "https://jira-proxy.example:8443".to_string(),
        username_ref: Some("env:PROXY_USER".to_string()),
        password_ref: Some("file:/run/agent-access/proxy-password".to_string()),
    });
    config
        .providers
        .get_mut::<agent_access_confluence::ConfluenceProviderConfig>()
        .unwrap()
        .egress_proxy = Some(EgressProxyConfig {
        url: "http://confluence-proxy.example:8080".to_string(),
        username_ref: None,
        password_ref: None,
    });

    validate_broker_config(&config).unwrap();
}

#[test]
fn credential_input_schema_describes_required_basic_and_bearer_fields() {
    let basic = credential_input_schema("jira", "Jira", "jira-cloud-api-token", "basic_api_token")
        .expect("basic schema");
    assert_eq!(basic.service, "jira");
    assert_eq!(basic.profile, "jira-cloud-api-token");
    assert_eq!(basic.credential_kind, "basic_api_token");
    assert_eq!(basic.fields.len(), 2);
    assert_eq!(basic.fields[0].name, "username");
    assert!(basic.fields[0].required);
    assert!(!basic.fields[0].secret);
    assert_eq!(basic.fields[0].prompt, "Jira username");
    assert_eq!(basic.fields[1].name, "token");
    assert!(basic.fields[1].required);
    assert!(basic.fields[1].secret);
    assert_eq!(basic.fields[1].prompt, "Jira API token");

    let cloudbees = credential_input_schema(
        "cloudbees_ci",
        "CloudBees CI",
        "cloudbees-ci-api-token",
        "basic_api_token",
    )
    .expect("CloudBees CI schema");
    assert_eq!(cloudbees.fields[0].prompt, "CloudBees CI username");
    assert_eq!(cloudbees.fields[1].prompt, "CloudBees CI API token");
    assert!(cloudbees.fields[1].secret);

    let bearer = credential_input_schema("github", "github", "http-bearer-token", "bearer_token")
        .expect("bearer schema");
    assert_eq!(bearer.fields.len(), 1);
    assert_eq!(bearer.fields[0].name, "token");
    assert!(bearer.fields[0].secret);
    assert_eq!(bearer.fields[0].prompt, "github bearer token");

    assert!(credential_input_schema("jira", "Jira", "unknown", "unknown").is_none());
}

#[test]
fn cloudbees_ci_config_requires_normalized_allowlisted_controller_roots() {
    let mut config = sample_cloudbees_config();
    validate_broker_config(&config).unwrap();

    let controller = config
        .providers
        .get_mut::<agent_access_cloudbees_ci::CloudbeesCiProviderConfig>()
        .unwrap()
        .controllers
        .get_mut("team-ci")
        .unwrap();
    controller.base_url = "https://ci.example.com/team-ci".into();
    assert_contains(
        &validation_errors(validate_broker_config(&config)),
        "must be a normalized URL ending in /",
    );

    let mut config = sample_cloudbees_config();
    config
        .providers
        .get_mut::<agent_access_cloudbees_ci::CloudbeesCiProviderConfig>()
        .unwrap()
        .allowed_upstream_hosts = vec!["https://other.example.com/**".into()];
    assert_contains(
        &validation_errors(validate_broker_config(&config)),
        "is not covered by providers.cloudbees_ci.allowed_upstream_hosts",
    );

    let mut config = sample_cloudbees_config();
    let controller = config
        .providers
        .get_mut::<agent_access_cloudbees_ci::CloudbeesCiProviderConfig>()
        .unwrap()
        .controllers
        .remove("team-ci")
        .unwrap();
    config
        .providers
        .get_mut::<agent_access_cloudbees_ci::CloudbeesCiProviderConfig>()
        .unwrap()
        .controllers
        .insert("Team CI".into(), controller);
    assert_contains(
        &validation_errors(validate_broker_config(&config)),
        "has an invalid alias",
    );
}

#[test]
fn cloudbees_log_scan_budget_is_bounded_by_global_response_limit() {
    let mut config = sample_cloudbees_config();
    let cap = config.limits.max_upstream_response_bytes;
    for budget in [0, cap + 1] {
        config
            .providers
            .get_mut::<CloudbeesCiProviderConfig>()
            .unwrap()
            .max_log_scan_bytes = budget;
        assert_contains(
            &validation_errors(validate_broker_config(&config)),
            "max_log_scan_bytes must be positive and no larger than limits.max_upstream_response_bytes",
        );
    }
    config
        .providers
        .get_mut::<CloudbeesCiProviderConfig>()
        .unwrap()
        .max_log_scan_bytes = cap;
    validate_broker_config(&config).unwrap();
}

#[test]
fn cloudbees_ci_credentials_and_actions_use_job_scope() {
    let mut config = sample_cloudbees_config();
    config.credentials.service.insert(
        "cloudbees_ci".into(),
        CredentialConfig {
            kind: "basic_api_token".into(),
            username_ref: Some("env:CLOUDBEES_CI_USERNAME".into()),
            token_ref: Some("env:CLOUDBEES_CI_API_TOKEN".into()),
            provider: None,
            path: None,
            read_only: None,
            connection: None,
        },
    );
    let resources = select_resources(
        &mut config,
        CLOUDBEES_CI_JOB_RESOURCE.id().clone(),
        &[namespace("team-ci/payments")],
    );
    config.policy.grants.push(PolicyGrantConfig {
        subjects: vec!["group:anonymous".into()],
        service: "cloudbees_ci".into(),
        actions: vec!["build.artifact.download".into(), "build.trigger".into()],
        resources,
        execution_contexts: Some(vec!["default".into()]),
        credential_mode: "service".into(),
        priority: None,
    });
    validate_broker_config(&config).unwrap();
    let service = &configured_service_descriptors(&config)["cloudbees_ci"];
    assert_eq!(service.scope_types(), ["job".to_string()].into());
    for action in &service.actions {
        assert_eq!(action.required_scope_types(), ["job"]);
    }
    assert_eq!(
        service
            .action("build.artifact.download")
            .unwrap()
            .required_scope_types(),
        ["job"]
    );
    assert_eq!(
        profile_kind(&config, "cloudbees_ci", "cloudbees-ci-api-token"),
        Some("basic_api_token")
    );

    config
        .credentials
        .service
        .get_mut("cloudbees_ci")
        .unwrap()
        .kind = "bearer_token".into();
    let errors = validation_errors(validate_broker_config(&config));
    assert_contains(
        &errors,
        "credentials.service.cloudbees_ci.type must be basic_api_token",
    );
}

#[test]
fn rejects_invalid_egress_proxy_config_shapes() {
    let mut userinfo = sample_broker();
    userinfo.network.egress_proxy = Some(EgressProxyConfig {
        url: "https://user:pass@proxy.example".to_string(),
        username_ref: None,
        password_ref: None,
    });
    let errors = validation_errors(validate_broker_config(&userinfo));
    assert_contains(&errors, "must not include username or password");

    let mut path = sample_broker();
    path.network.egress_proxy = Some(EgressProxyConfig {
        url: "http://proxy.example/path".to_string(),
        username_ref: None,
        password_ref: None,
    });
    let errors = validation_errors(validate_broker_config(&path));
    assert_contains(&errors, "must be a proxy origin without a path");

    let mut cleartext_credentials = sample_broker();
    cleartext_credentials.network.egress_proxy = Some(EgressProxyConfig {
        url: "http://proxy.example".to_string(),
        username_ref: Some("env:PROXY_USER".to_string()),
        password_ref: Some("env:PROXY_PASSWORD".to_string()),
    });
    let errors = validation_errors(validate_broker_config(&cleartext_credentials));
    assert_contains(&errors, "require an https proxy URL");

    let mut half_credentials = sample_broker();
    half_credentials.network.egress_proxy = Some(EgressProxyConfig {
        url: "https://proxy.example".to_string(),
        username_ref: Some("env:PROXY_USER".to_string()),
        password_ref: None,
    });
    let errors = validation_errors(validate_broker_config(&half_credentials));
    assert_contains(&errors, "password_ref is required");

    let mut bad_secret_ref = sample_broker();
    bad_secret_ref.network.egress_proxy = Some(EgressProxyConfig {
        url: "https://proxy.example".to_string(),
        username_ref: Some("PROXY_USER".to_string()),
        password_ref: Some("env:PROXY_PASSWORD".to_string()),
    });
    let errors = validation_errors(validate_broker_config(&bad_secret_ref));
    assert_contains(
        &errors,
        "username_ref must use env:NAME or file:/absolute/path",
    );

    let mut query_fragment = sample_broker();
    query_fragment.network.egress_proxy = Some(EgressProxyConfig {
        url: "http://proxy.example?x=1#fragment".to_string(),
        username_ref: None,
        password_ref: None,
    });
    let errors = validation_errors(validate_broker_config(&query_fragment));
    assert_contains(&errors, "must not include a query");
    assert_contains(&errors, "must not include a fragment");
}

#[test]
fn egress_proxy_debug_redacts_url_userinfo_and_refs() {
    let config = EgressProxyConfig {
        url: "https://alice:s3cr3t@proxy.example:8443/path?x=1#fragment".to_string(),
        username_ref: Some("env:EGRESS_ACCOUNT".to_string()),
        password_ref: Some("env:EGRESS_SECRET".to_string()),
    };

    let debug = format!("{config:?}");
    assert!(debug.contains("https://proxy.example:8443"));
    assert!(debug.contains("<redacted>"));
    assert!(!debug.contains("alice"));
    assert!(!debug.contains("s3cr3t"));
    assert!(!debug.contains("EGRESS_ACCOUNT"));
    assert!(!debug.contains("EGRESS_SECRET"));
}

#[test]
fn rejects_unknown_config_fields() {
    let top_level = r#"
unknown = true

[identity]
mode = "anonymous"

[policy]
default_decision = "deny"

[limits]
upload_spool_dir = "upload-spool"
"#;
    assert!(parse_test_config(top_level).is_err());

    let nested = r#"
[identity]
mode = "anonymous"
legacy_header = "X-Old"

[policy]
default_decision = "deny"

[limits]
upload_spool_dir = "upload-spool"
"#;
    assert!(parse_test_config(nested).is_err());
}

#[test]
fn rejects_non_anonymous_identity_without_sources() {
    let mut config = sample_broker();
    config.identity.mode = "required".to_string();
    let errors = validation_errors(validate_broker_config(&config));
    assert_contains(&errors, "requires at least one identity source");
}

#[test]
fn rejects_removed_jwt_jwks_identity_source_type() {
    let mut config = sample_broker();
    config.identity.mode = "required".to_string();
    config.identity.sources = vec![IdentitySourceConfig {
        name: "primary".to_string(),
        kind: "jwt_jwks".to_string(),
        header: "Authorization".to_string(),
        scheme: "Bearer".to_string(),
        principals: vec![],
    }];

    let errors = validation_errors(validate_broker_config(&config));
    assert_contains(
        &errors,
        "identity.sources.primary.type jwt_jwks has been removed",
    );
}

#[test]
fn identity_sources_reject_ambiguous_header_schemes() {
    let mut mixed_scheme = sample_broker();
    mixed_scheme.identity.mode = "required".to_string();
    mixed_scheme.identity.sources = vec![
        static_source(
            "raw-local",
            "Authorization",
            "raw",
            "alice",
            vec!["file:/run/agent-access/alice.token".to_string()],
        ),
        static_source(
            "bearer-local",
            "authorization",
            "Bearer",
            "bob",
            vec!["file:/run/agent-access/bob.token".to_string()],
        ),
    ];
    let errors = validation_errors(validate_broker_config(&mixed_scheme));
    assert_contains(&errors, "already configured with scheme raw");
}

#[test]
fn identity_sources_reject_duplicate_static_principals_and_missing_managed_store() {
    let mut duplicate_principal = sample_broker();
    duplicate_principal.identity.mode = "required".to_string();
    duplicate_principal.identity.sources = vec![
        static_source(
            "local-a",
            "Authorization",
            "Bearer",
            "alice",
            vec!["file:/run/agent-access/alice-a.token".to_string()],
        ),
        static_source(
            "local-b",
            "Authorization",
            "Bearer",
            "alice",
            vec!["file:/run/agent-access/alice-b.token".to_string()],
        ),
    ];
    let errors = validation_errors(validate_broker_config(&duplicate_principal));
    assert_contains(&errors, "principal alice is duplicated");

    let mut anonymous_principal = sample_broker();
    anonymous_principal.identity.mode = "required".to_string();
    anonymous_principal.identity.sources = vec![static_source(
        "local",
        "Authorization",
        "Bearer",
        "anonymous",
        vec!["file:/run/agent-access/anonymous.token".to_string()],
    )];
    let errors = validation_errors(validate_broker_config(&anonymous_principal));
    assert_contains(&errors, "principal anonymous is invalid");

    let mut broker_tokens = sample_broker();
    broker_tokens.identity.mode = "required".to_string();
    broker_tokens.identity.authority = "managed".to_string();
    broker_tokens.identity.sources = vec![IdentitySourceConfig {
        name: "broker".to_string(),
        kind: "broker_tokens".to_string(),
        header: "Authorization".to_string(),
        scheme: "Bearer".to_string(),
        principals: vec![],
    }];
    let errors = validation_errors(validate_broker_config(&broker_tokens));
    assert_contains(
        &errors,
        "broker_tokens is required when an identity source uses broker_tokens",
    );
    assert_contains(
        &errors,
        "managed_store is required when an identity source uses broker_tokens",
    );

    let mut token_ttl = sample_broker();
    token_ttl.broker_tokens = Some(BrokerTokensConfig {
        hash_key_ref: "env:AGENT_ACCESS_BROKER_TOKEN_HASH_KEY".to_string(),
        default_agent_invoke_ttl: Some("31d".to_string()),
        default_user_manage_ttl: Some("2h".to_string()),
        default_admin_ttl: Some("8h".to_string()),
        max_self_issued_agent_invoke_ttl: Some("30d".to_string()),
        ..Default::default()
    });
    let errors = validation_errors(validate_broker_config(&token_ttl));
    assert_contains(
        &errors,
        "broker_tokens.default_agent_invoke_ttl must not exceed broker_tokens.max_self_issued_agent_invoke_ttl",
    );
}

#[test]
fn broker_token_ttl_options_are_typed_ordered_and_validated() {
    let mut config = sample_broker();
    config.broker_tokens = Some(BrokerTokensConfig {
        hash_key_ref: "env:AGENT_ACCESS_BROKER_TOKEN_HASH_KEY".to_string(),
        default_agent_invoke_ttl: Some("37m".to_string()),
        default_user_manage_ttl: Some("41m".to_string()),
        default_admin_ttl: Some("43m".to_string()),
        max_self_issued_agent_invoke_ttl: Some("5h".to_string()),
        self_agent_invoke_ttl_options: vec![
            BrokerTokenTtlOption::Ttl("37m".to_string()),
            BrokerTokenTtlOption::Ttl("5h".to_string()),
            BrokerTokenTtlOption::Never,
        ],
        admin_agent_invoke_ttl_options: vec![
            BrokerTokenTtlOption::Ttl("37m".to_string()),
            BrokerTokenTtlOption::Never,
        ],
        user_manage_ttl_options: vec![BrokerTokenTtlOption::Ttl("41m".to_string())],
        admin_ttl_options: vec![BrokerTokenTtlOption::Ttl("43m".to_string())],
    });

    validate_broker_config(&config).unwrap();
    assert_eq!(
        config
            .broker_tokens
            .as_ref()
            .unwrap()
            .self_agent_invoke_ttl_options
            .iter()
            .map(BrokerTokenTtlOption::as_str)
            .collect::<Vec<_>>(),
        vec!["37m", "5h", "never"]
    );

    let tokens = config.broker_tokens.as_mut().unwrap();
    tokens.user_manage_ttl_options = vec![BrokerTokenTtlOption::Never];
    tokens.default_agent_invoke_ttl = Some("1h".to_string());
    tokens.self_agent_invoke_ttl_options = vec![
        BrokerTokenTtlOption::Ttl("37m".to_string()),
        BrokerTokenTtlOption::Ttl("5h".to_string()),
        BrokerTokenTtlOption::Ttl("300m".to_string()),
        BrokerTokenTtlOption::Ttl("6h".to_string()),
    ];
    let errors = validation_errors(validate_broker_config(&config));
    assert_contains(
        &errors,
        "broker_tokens.user_manage_ttl_options must not contain never",
    );
    assert_contains(&errors, "contains duplicate duration option \"300m\"");
    assert_contains(
        &errors,
        "option \"6h\" exceeds broker_tokens.max_self_issued_agent_invoke_ttl",
    );
    assert_contains(
        &errors,
        "effective broker_tokens.default_agent_invoke_ttl must appear",
    );
}

#[test]
fn identity_sources_reject_authority_mismatches() {
    let mut managed_static = sample_broker();
    managed_static.identity.mode = "required".to_string();
    managed_static.identity.authority = "managed".to_string();
    managed_static.identity.sources = vec![static_source(
        "local",
        "Authorization",
        "Bearer",
        "alice",
        vec!["file:/run/agent-access/alice.token".to_string()],
    )];
    let errors = validation_errors(validate_broker_config(&managed_static));
    assert_contains(
        &errors,
        "identity.sources.local.type static_principals is only valid when identity.authority = toml",
    );

    let mut toml_broker_tokens = sample_broker();
    toml_broker_tokens.identity.mode = "required".to_string();
    toml_broker_tokens.identity.sources = vec![IdentitySourceConfig {
        name: "broker".to_string(),
        kind: "broker_tokens".to_string(),
        header: "Authorization".to_string(),
        scheme: "Bearer".to_string(),
        principals: vec![],
    }];
    let errors = validation_errors(validate_broker_config(&toml_broker_tokens));
    assert_contains(
        &errors,
        "identity.sources.broker.type broker_tokens is only valid when identity.authority = managed",
    );
}

#[test]
fn managed_policy_authority_requires_managed_store_and_rejects_toml_grants() {
    let mut config = sample_broker();
    config.identity.authority = "managed".to_string();
    config.identity.groups.clear();
    config.policy.authority = "managed".to_string();

    let errors = validation_errors(validate_broker_config(&config));
    assert_contains(&errors, "identity.authority managed requires managed_store");
    assert_contains(&errors, "policy.authority managed requires managed_store");
    assert_contains(
        &errors,
        "policy.grants must be empty when policy.authority = managed",
    );

    config.managed_store = Some(ManagedStoreConfig {
        kind: "sqlite".to_string(),
        path: "/var/lib/agent-access-broker/managed-store.sqlite3".to_string(),
        require_registered_principal_for_invocation: false,
        auto_migrate: true,
    });
    config.policy.grants.clear();
    config.policy.resources.clear();
    config.policy.resource_groups.clear();
    validate_broker_config(&config).unwrap();
}

#[test]
fn policy_grant_subjects_accept_multiple_and_reject_invalid_shapes() {
    let mut config = sample_broker();
    config.policy.grants[0].subjects =
        vec!["group:anonymous".to_string(), "user:anonymous".to_string()];
    validate_broker_config(&config).unwrap();

    let mut empty_subjects = sample_broker();
    empty_subjects.policy.grants[0].subjects.clear();
    let errors = validation_errors(validate_broker_config(&empty_subjects));
    assert_contains(&errors, "policy.grants[0].subjects must not be empty");

    let mut duplicate_subjects = sample_broker();
    duplicate_subjects.policy.grants[0].subjects =
        vec!["group:anonymous".to_string(), "group:anonymous".to_string()];
    let errors = validation_errors(validate_broker_config(&duplicate_subjects));
    assert_contains(
        &errors,
        "policy.grants[0].subjects[1] duplicates an earlier subject",
    );

    let mut too_many_subjects = sample_broker();
    too_many_subjects.identity.groups = (0..=POLICY_GRANT_MAX_SUBJECTS)
        .map(|index| IdentityGroupConfig {
            id: format!("subject-group-{index}"),
            status: "active".to_string(),
            members: Vec::new(),
        })
        .collect();
    too_many_subjects.policy.grants[0].subjects = (0..=POLICY_GRANT_MAX_SUBJECTS)
        .map(|index| format!("group:subject-group-{index}"))
        .collect();
    let errors = validation_errors(validate_broker_config(&too_many_subjects));
    assert_contains(
        &errors,
        "policy.grants[0].subjects must contain at most 256 entries",
    );
}

#[test]
fn execution_context_value_type_enforces_canonical_safe_slugs() {
    for value in ["a", "default", "workstation-1", "internal_v2"] {
        let context = ExecutionContext::new(value).unwrap();
        assert_eq!(context.as_str(), value);
        assert_eq!(serde_json::to_value(&context).unwrap(), value);
        assert_eq!(
            serde_json::from_value::<ExecutionContext>(serde_json::json!(value)).unwrap(),
            context
        );
    }
    for value in [
        "",
        "External",
        " external",
        "external ",
        "1internal",
        "internal.external",
        "internal,external",
        "*",
        "éxternal",
    ] {
        assert!(ExecutionContext::new(value).is_err(), "accepted {value:?}");
    }
    assert!(ExecutionContext::new("a".repeat(EXECUTION_CONTEXT_MAX_LENGTH + 1)).is_err());
}

#[test]
fn stored_agent_invoke_caveats_require_context_binding() {
    assert!(
        AgentInvokeTokenCaveats::parse_stored(&serde_json::json!({"allowedServices":["jira"]}))
            .is_err()
    );
    let valid = AgentInvokeTokenCaveats::parse_stored(&serde_json::json!({
        "allowedServices":["jira"], "allowedExecutionContexts":["internal"]
    }))
    .unwrap();
    assert_eq!(valid.allowed_services, Some(vec!["jira".to_string()]));
    assert!(valid.service_restrictions.is_none());
    for malformed in [
        serde_json::json!({"allowedExecutionContexts":null}),
        serde_json::json!({"allowedExecutionContexts":[]}),
        serde_json::json!({"allowedExecutionContexts":"internal"}),
        serde_json::json!({"allowedExecutionContexts":["internal","internal"]}),
        serde_json::json!({"allowedExecutionContexts":["Internal"]}),
        serde_json::json!({"allowedServices":null,"allowedExecutionContexts":["internal"]}),
        serde_json::json!({"allowedServices":[],"allowedExecutionContexts":["internal"]}),
        serde_json::json!({"allowedServices":["jira","jira"],"allowedExecutionContexts":["internal"]}),
        serde_json::json!({"allowedServices":["not a service"],"allowedExecutionContexts":["internal"]}),
        serde_json::json!({"serviceRestrictions":null,"allowedExecutionContexts":["internal"]}),
        serde_json::json!({"futureSecurityBoundary":true,"allowedExecutionContexts":["internal"]}),
    ] {
        assert!(
            AgentInvokeTokenCaveats::parse_stored(&malformed).is_err(),
            "accepted {malformed}"
        );
    }
}

#[test]
fn agent_invoke_service_restrictions_round_trip_canonically() {
    let caveats = AgentInvokeTokenCaveats::parse_stored(&serde_json::json!({
        "allowedServices":["confluence","gitlab"], "allowedExecutionContexts":["internal"],
        "serviceRestrictions":{
            "gitlab":{"actions":["project.view","commit.view"],"resources":{"resourceIds":["payments"],"resourceGroupIds":["engineering"]}},
            "confluence":{"actions":["search","page.view"],"resources":{"resourceIds":[],"resourceGroupIds":[]}}
        }
    })).unwrap();
    assert_eq!(
        caveats.to_scopes_value(),
        serde_json::json!({
            "allowedServices":["confluence","gitlab"], "allowedExecutionContexts":["internal"],
            "serviceRestrictions":{
                "gitlab":{"actions":["commit.view","project.view"],"resources":{"resourceIds":["payments"],"resourceGroupIds":["engineering"]}},
                "confluence":{"actions":["page.view","search"],"resources":{"resourceIds":[],"resourceGroupIds":[]}}
            }
        })
    );
    let follow = AgentInvokeTokenCaveats::parse_stored(&serde_json::json!({
        "allowedServices":["jira"], "allowedExecutionContexts":["internal"],
        "serviceRestrictions":{"jira":{"actions":["issue.view"]}}
    }))
    .unwrap();
    assert!(
        follow.service_restrictions.unwrap()["jira"]
            .resources
            .is_none()
    );
    assert!(
        caveats.service_restrictions.unwrap()["confluence"]
            .resources
            .is_some()
    );
}

#[test]
fn agent_invoke_service_restrictions_reject_invalid_structure() {
    for restriction in [
        serde_json::json!({"actions":[]}),
        serde_json::json!({"actions":["issue.view","issue.view"]}),
        serde_json::json!({"actions":["jira.issue.view"]}),
        serde_json::json!({"actions":["Issue View"]}),
        serde_json::json!({"actions":["issue.view"],"resources":null}),
        serde_json::json!({"actions":["issue.view"],"resources":{"resourceIds":["same","same"]}}),
        serde_json::json!({"actions":["issue.view"],"resources":{"resourceGroupIds":["same","same"]}}),
        serde_json::json!({"actions":["issue.view"],"resources":{"resourceIds":["*"]}}),
        serde_json::json!({"actions":["issue.view"],"resources":{"resourceIds":["not an id"]}}),
        serde_json::json!({"actions":["issue.view"],"resources":{"resourceIds":null}}),
        serde_json::json!({"actions":["issue.view"],"resources":{"project":["ENG"]}}),
        serde_json::json!({"actions":["issue.view"],"resourceScopes":{"project":["ENG"]}}),
        serde_json::json!({"actions":["issue.view"],"resources":{},"futureBoundary":true}),
    ] {
        let malformed = serde_json::json!({"allowedServices":["jira"],"allowedExecutionContexts":["internal"],"serviceRestrictions":{"jira":restriction}});
        assert!(
            AgentInvokeTokenCaveats::parse_stored(&malformed).is_err(),
            "accepted {malformed}"
        );
    }
    for malformed in [
        serde_json::json!({"allowedServices":["jira"],"allowedExecutionContexts":["internal"],"serviceRestrictions":{}}),
        serde_json::json!({"allowedExecutionContexts":["internal"],"serviceRestrictions":{"jira":{"actions":["issue.view"]}}}),
        serde_json::json!({"allowedServices":["jira"],"allowedExecutionContexts":["internal"],"serviceRestrictions":{"confluence":{"actions":["page.view"]}}}),
        serde_json::json!({"allowedServices":["jira"],"allowedExecutionContexts":["internal"],"serviceRestrictions":{"not a service":{"actions":["issue.view"]}}}),
    ] {
        assert!(
            AgentInvokeTokenCaveats::parse_stored(&malformed).is_err(),
            "accepted {malformed}"
        );
    }
}

#[test]
fn new_agent_invoke_caveats_are_finite_and_configured() {
    let configured = ExecutionContextConfig {
        allowed_values: vec!["workstation".to_string(), "external".to_string()],
        default_context: None,
    };
    let issued = AgentInvokeTokenCaveats::parse_issuance(
        &serde_json::json!({
            "allowedServices": ["jira", "confluence"],
            "allowedExecutionContexts": ["workstation", "external"]
        }),
        Some(&configured),
    )
    .unwrap();
    assert_eq!(
        issued.to_scopes_value(),
        serde_json::json!({
            "allowedServices": ["jira", "confluence"],
            "allowedExecutionContexts": ["workstation", "external"]
        })
    );

    assert!(matches!(
        AgentInvokeTokenCaveats::parse_issuance(
            &serde_json::json!({"allowedServices": ["jira"]}),
            Some(&configured),
        ),
        Err(AgentInvokeTokenCaveatError::ExecutionContextsRequired)
    ));
    assert!(matches!(
        AgentInvokeTokenCaveats::parse_issuance(
            &serde_json::json!({"allowedExecutionContexts": ["internal"]}),
            Some(&configured),
        ),
        Err(AgentInvokeTokenCaveatError::ExecutionContextNotConfigured { context })
            if context == "internal"
    ));
    AgentInvokeTokenCaveats::parse_issuance(
        &serde_json::json!({
            "allowedExecutionContexts": ["workstation", "external"]
        }),
        Some(&configured),
    )
    .unwrap();
    AgentInvokeTokenCaveats::parse_issuance(
        &serde_json::json!({"allowedExecutionContexts": ["external"]}),
        Some(&configured),
    )
    .unwrap();

    AgentInvokeTokenCaveats::parse_issuance(
        &serde_json::json!({"allowedExecutionContexts": ["default"]}),
        None,
    )
    .unwrap();
    assert!(matches!(
        AgentInvokeTokenCaveats::parse_issuance(
            &serde_json::json!({"allowedExecutionContexts": ["external"]}),
            None,
        ),
        Err(AgentInvokeTokenCaveatError::ExecutionContextNotConfigured { context })
            if context == "external"
    ));
}

#[test]
fn execution_context_config_validates_registry_and_fixed_header_contract() {
    let mut valid = sample_broker();
    configure_execution_contexts(
        &mut valid,
        &["default", "workstation", "internal", "external"],
        Some("default"),
        "default",
    );
    validate_broker_config(&valid).unwrap();

    let mut invalid = valid.clone();
    invalid.execution_context = Some(ExecutionContextConfig {
        allowed_values: vec![
            "External".to_string(),
            "internal".to_string(),
            "internal".to_string(),
        ],
        default_context: Some("missing".to_string()),
    });
    let errors = validation_errors(validate_broker_config(&invalid));
    assert_contains(
        &errors,
        "execution_context.allowed_values[0] must match ^[a-z][a-z0-9_-]{0,63}$",
    );
    assert_contains(
        &errors,
        "execution_context.allowed_values[2] duplicates an earlier value",
    );
    assert_contains(
        &errors,
        "execution_context.default_context must appear in execution_context.allowed_values",
    );

    let mut empty = sample_broker();
    empty.execution_context = Some(ExecutionContextConfig {
        allowed_values: Vec::new(),
        default_context: None,
    });
    let errors = validation_errors(validate_broker_config(&empty));
    assert_contains(
        &errors,
        "execution_context.allowed_values must not be empty",
    );

    let mut too_many = sample_broker();
    too_many.execution_context = Some(ExecutionContextConfig {
        allowed_values: (0..=EXECUTION_CONTEXT_MAX_VALUES)
            .map(|index| format!("context-{index}"))
            .collect(),
        default_context: None,
    });
    let errors = validation_errors(validate_broker_config(&too_many));
    assert_contains(
        &errors,
        "execution_context.allowed_values must contain at most 64 entries",
    );

    let raw = r#"
            [execution_context]
            header = "X-Other-Context"
            allowed_values = ["default"]

            [identity]
            mode = "anonymous"
            authority = "toml"

            [policy]
            authority = "toml"

            [limits]
            upload_spool_dir = "upload-spool"
        "#;
    let error = parse_test_config(raw).unwrap_err();
    assert!(error.to_string().contains("unknown field `header`"));
}

#[test]
fn execution_context_header_is_reserved_for_identity_sources() {
    let mut config = sample_broker();
    config.identity.mode = "required".to_string();
    config.identity.sources = vec![static_source(
        "reserved",
        "x-agent-access-context",
        "raw",
        "alice",
        vec!["file:/run/agent-access/alice.token".to_string()],
    )];

    let errors = validation_errors(validate_broker_config(&config));
    assert_contains(
        &errors,
        "identity.sources.reserved.header must not use reserved header X-Agent-Access-Context",
    );
}

#[test]
fn toml_grant_context_omission_is_compatibility_only() {
    let parsed = parse_test_config(
        r#"
                [execution_context]
                allowed_values = ["internal", "external"]

                [identity]
                mode = "anonymous"
                authority = "toml"

                [policy]
                authority = "toml"

                [[policy.grants]]
                subjects = ["group:anonymous"]
                service = "fake"
                execution_contexts = ["external"]
                credential_mode = "service"

                [limits]
                upload_spool_dir = "upload-spool"
            "#,
    )
    .unwrap();
    assert_eq!(
        parsed.policy.grants[0].execution_contexts.as_deref(),
        Some(["external".to_string()].as_slice())
    );

    let mut compatibility = sample_broker();
    compatibility.execution_context = None;
    for resource in &mut compatibility.policy.resources {
        resource.allowed_execution_contexts = vec!["default".to_string()];
    }
    for grant in &mut compatibility.policy.grants {
        grant.execution_contexts = None;
    }
    assert!(compatibility.execution_context.is_none());
    assert!(
        compatibility
            .policy
            .grants
            .iter()
            .all(|grant| grant.execution_contexts.is_none())
    );
    validate_broker_config(&compatibility).unwrap();

    let mut configured = compatibility.clone();
    configured.execution_context = Some(ExecutionContextConfig {
        allowed_values: vec!["default".to_string(), "external".to_string()],
        default_context: Some("default".to_string()),
    });
    let errors = validation_errors(validate_broker_config(&configured));
    assert_contains(
        &errors,
        "policy.grants[0].execution_contexts is required when execution_context is configured",
    );

    for grant in &mut configured.policy.grants {
        grant.execution_contexts = Some(vec!["default".to_string()]);
    }
    validate_broker_config(&configured).unwrap();
}

#[test]
fn toml_grant_execution_contexts_reject_invalid_lists() {
    let mut config = sample_broker();
    configure_execution_contexts(&mut config, &["internal", "external"], None, "internal");
    config.policy.grants[0].execution_contexts = Some(Vec::new());
    config.policy.grants[1].execution_contexts = Some(vec![
        "external".to_string(),
        "external".to_string(),
        "External".to_string(),
        "unknown".to_string(),
    ]);

    let errors = validation_errors(validate_broker_config(&config));
    assert_contains(
        &errors,
        "policy.grants[0].execution_contexts must not be empty",
    );
    assert_contains(
        &errors,
        "policy.grants[1].execution_contexts[1] duplicates an earlier value",
    );
    assert_contains(
        &errors,
        "policy.grants[1].execution_contexts[2] must match ^[a-z][a-z0-9_-]{0,63}$",
    );
    assert_contains(
        &errors,
        "policy.grants[1].execution_contexts[3] references unconfigured execution context unknown",
    );
}

#[test]
fn disjoint_execution_contexts_remove_static_and_containment_ambiguity() {
    let mut config = sample_broker();
    config.credentials.per_user.insert(
        "jira".to_string(),
        jira_per_user_credential("/etc/agent-access/jira-user-credentials.json"),
    );
    configure_execution_contexts(
        &mut config,
        &["internal", "external", "workstation"],
        None,
        "internal",
    );
    config.policy.grants[0].actions = vec!["search".to_string()];
    config.policy.grants[0].resources = select_resources(
        &mut config,
        agent_access_jira::JIRA_PROJECT_RESOURCE.id().clone(),
        &[ResourceSelector::All],
    );
    config.policy.grants[0].execution_contexts = Some(vec!["external".to_string()]);

    let mut per_user = config.policy.grants[0].clone();
    per_user.credential_mode = "per_user".to_string();
    per_user.execution_contexts = Some(vec!["internal".to_string()]);
    config.policy.grants.push(per_user.clone());
    validate_broker_config(&config).unwrap();

    config.policy.grants[0].execution_contexts =
        Some(vec!["external".to_string(), "workstation".to_string()]);
    config.policy.grants.last_mut().unwrap().execution_contexts =
        Some(vec!["internal".to_string(), "workstation".to_string()]);
    let errors = validation_errors(validate_broker_config(&config));
    assert_contains(&errors, "ambiguous credential mode precedence");
    assert_contains(&errors, "overlapping project scope values");
}

#[test]
fn policy_grant_toml_requires_subjects_and_rejects_singular_subject() {
    let missing_subjects = r#"
[identity]
mode = "anonymous"
authority = "toml"

[policy]
authority = "toml"
default_decision = "deny"

[[policy.grants]]
service = "jira"
actions = ["issue.view"]
resources = { resource_ids = [] }
credential_mode = "service"

[limits]
upload_spool_dir = "upload-spool"
"#;
    let error = parse_test_config(missing_subjects).unwrap_err();
    assert!(error.to_string().contains("missing field `subjects`"));

    let singular_subject = r#"
[identity]
mode = "anonymous"
authority = "toml"

[policy]
authority = "toml"
default_decision = "deny"

[[policy.grants]]
subject = "group:anonymous"
service = "jira"
actions = ["issue.view"]
resources = { resource_ids = [] }
credential_mode = "service"

[limits]
upload_spool_dir = "upload-spool"
"#;
    let error = parse_test_config(singular_subject).unwrap_err();
    assert!(error.to_string().contains("unknown field `subject`"));
}

#[test]
fn old_accepted_tokens_and_verifiers_shape_is_rejected() {
    let legacy = r#"
[identity]
mode = "required"

[[identity.accepted_tokens]]
name = "raw"
header = "X-Agent-Access-Identity-Token"
scheme = "raw"
verifier = "local"

[identity.verifiers.local]
type = "static_token"
token_ref = "file:/run/agent-access/alice.token"
subject = "alice"

[policy]
default_decision = "deny"

[limits]
upload_spool_dir = "upload-spool"
"#;
    assert!(parse_test_config(legacy).is_err());
}

#[test]
fn rejects_redundant_service_prefixed_actions() {
    let mut config = sample_broker();
    config.policy.grants[0].actions = vec!["jira.issue.view".to_string()];
    let errors = validation_errors(validate_broker_config(&config));
    assert_contains(&errors, "must not repeat service prefix");
}

#[test]
fn rejects_unknown_jira_action_grant() {
    let mut config = sample_broker();
    config.policy.grants[0].actions = vec!["transition.run".to_string()];
    let errors = validation_errors(validate_broker_config(&config));
    assert_contains(&errors, "action transition.run is unknown for service jira");
}

#[test]
fn atlassian_bearer_profiles_require_the_exact_gateway_host() {
    let mut config = sample_broker();
    let jira = config
        .providers
        .get_mut::<agent_access_jira::JiraProviderConfig>()
        .unwrap();
    jira.cloud_id = Some("11111111-2222-4333-8444-555555555555".to_string());
    jira.allowed_upstream_hosts =
        vec!["https://api.atlassian.com.example.net/ex/jira/**".to_string()];
    assert_eq!(profile_kind(&config, "jira", "jira-bearer-token"), None);

    config
        .providers
        .get_mut::<agent_access_jira::JiraProviderConfig>()
        .unwrap()
        .allowed_upstream_hosts = vec![
        "https://api.atlassian.com/ex/jira/11111111-2222-4333-8444-555555555555/**".to_string(),
    ];
    assert_eq!(
        profile_kind(&config, "jira", "jira-bearer-token"),
        Some("bearer_token")
    );
}

#[test]
fn validates_jira_comment_config_limits_and_prefixes() {
    let mut config = sample_broker();
    let comments = &mut config
        .providers
        .get_mut::<agent_access_jira::JiraProviderConfig>()
        .unwrap()
        .comments;
    comments.max_results = 0;
    comments.max_property_value_bytes = 32_769;
    comments.allowed_property_key_prefixes = vec![
        "".to_string(),
        "jira.".to_string(),
        "agent-access.".to_string(),
        "agent-access.".to_string(),
        "bad prefix".to_string(),
        "bad/prefix".to_string(),
    ];

    let errors = validation_errors(validate_broker_config(&config));
    assert_contains(
        &errors,
        "providers.jira.comments.max_results must be non-zero",
    );
    assert_contains(
        &errors,
        "providers.jira.comments.max_property_value_bytes must not exceed 32768",
    );
    assert_contains(&errors, "contains invalid prefix");
    assert_contains(&errors, "contains reserved prefix jira.");
    assert_contains(&errors, "contains duplicate prefix agent-access.");
}

#[test]
fn validates_jira_issue_link_config_and_exposes_project_scope_only() {
    let mut config = sample_broker();
    let issue_links = &mut config
        .providers
        .get_mut::<agent_access_jira::JiraProviderConfig>()
        .unwrap()
        .issue_links;
    issue_links.dependency_link_type = String::new();
    issue_links.dependency_outward = "blocks\nsecret".to_string();
    issue_links.dependency_inward = "   ".to_string();

    let errors = validation_errors(validate_broker_config(&config));
    assert_contains(
        &errors,
        "providers.jira.issue_links.dependency_link_type must not be empty",
    );
    assert_contains(
        &errors,
        "providers.jira.issue_links.dependency_outward must not contain control characters",
    );
    assert_contains(
        &errors,
        "providers.jira.issue_links.dependency_inward must not be empty",
    );

    let valid_config = sample_broker();
    let capabilities = agent_access_jira::jira_descriptor(
        valid_config
            .providers
            .get::<agent_access_jira::JiraProviderConfig>()
            .unwrap(),
    );
    assert!(!capabilities.resource_scopes.contains_key("issue"));
    assert_eq!(
        capabilities.resource_scopes["project"].resource_type,
        agent_access_jira::JIRA_PROJECT_RESOURCE.id().clone()
    );
}

#[test]
fn validates_jira_comment_visibility_allowlist_shapes() {
    let mut config = sample_broker();
    config
        .providers
        .get_mut::<agent_access_jira::JiraProviderConfig>()
        .unwrap()
        .comments
        .allowed_visibility = vec![
        agent_access_jira::JiraCommentVisibilityConfig {
            visibility_type: "group".to_string(),
            value: None,
            identifier: None,
        },
        agent_access_jira::JiraCommentVisibilityConfig {
            visibility_type: "role".to_string(),
            value: None,
            identifier: None,
        },
        agent_access_jira::JiraCommentVisibilityConfig {
            visibility_type: "team".to_string(),
            value: Some("Developers".to_string()),
            identifier: None,
        },
        agent_access_jira::JiraCommentVisibilityConfig {
            visibility_type: "role".to_string(),
            value: Some("Developers".to_string()),
            identifier: None,
        },
        agent_access_jira::JiraCommentVisibilityConfig {
            visibility_type: "role".to_string(),
            value: Some("Developers".to_string()),
            identifier: None,
        },
        agent_access_jira::JiraCommentVisibilityConfig {
            visibility_type: "group".to_string(),
            value: Some("Developers".to_string()),
            identifier: Some("group-id".to_string()),
        },
        agent_access_jira::JiraCommentVisibilityConfig {
            visibility_type: "group".to_string(),
            value: Some("Engineering".to_string()),
            identifier: Some("group-id".to_string()),
        },
    ];

    let errors = validation_errors(validate_broker_config(&config));
    assert_contains(
        &errors,
        "providers.jira.comments.allowed_visibility group entries require identifier",
    );
    assert_contains(
        &errors,
        "providers.jira.comments.allowed_visibility role entries require value",
    );
    assert_contains(
        &errors,
        "providers.jira.comments.allowed_visibility type must be role or group",
    );
    assert_contains(
        &errors,
        "providers.jira.comments.allowed_visibility contains duplicate entry",
    );
}

#[test]
fn rejects_lookup_credentials_without_read_only_proof() {
    let mut config = sample_broker();
    config.credentials.lookup.get_mut("jira").unwrap().read_only = None;
    let errors = validation_errors(validate_broker_config(&config));
    assert_contains(&errors, "read_only must be true");
}

#[test]
fn rejects_jira_scope_lookup_actions_without_lookup_credentials() {
    let mut config = sample_broker();
    config.credentials.lookup.remove("jira");
    let errors = validation_errors(validate_broker_config(&config));
    assert_contains(&errors, "requires credentials.lookup.jira");
}

#[test]
fn rejects_confluence_scope_lookup_actions_without_lookup_credentials() {
    let mut config = sample_broker();
    config.credentials.lookup.remove("confluence");
    let errors = validation_errors(validate_broker_config(&config));
    assert_contains(&errors, "requires credentials.lookup.confluence");
}

#[test]
fn rejects_confluence_draft_grants_without_stable_broker_token_hash_key() {
    let mut config = sample_broker();
    let confluence_grant = config
        .policy
        .grants
        .iter_mut()
        .find(|grant| grant.service == "confluence")
        .unwrap();
    confluence_grant.actions = vec!["page.draft.create".to_string()];

    let errors = validation_errors(validate_broker_config(&config));
    assert_contains(
        &errors,
        "policy grants for confluence.page.draft.create issue durable handles and require broker_tokens.hash_key_ref",
    );

    let dir = tempfile::tempdir().unwrap();
    let key_path = dir.path().join("broker-token-hash-key");
    std::fs::write(
        &key_path,
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([7_u8; 32]),
    )
    .unwrap();
    config.broker_tokens = Some(BrokerTokensConfig {
        hash_key_ref: format!("file:{}", key_path.display()),
        default_agent_invoke_ttl: None,
        default_user_manage_ttl: None,
        default_admin_ttl: None,
        max_self_issued_agent_invoke_ttl: None,
        ..Default::default()
    });

    validate_broker_config(&config).unwrap();
}

#[test]
fn rejects_non_https_credentialed_upstream() {
    let mut config = sample_broker();
    config
        .providers
        .get_mut::<agent_access_jira::JiraProviderConfig>()
        .unwrap()
        .allowed_upstream_hosts = vec!["http://example.atlassian.net/rest/api/3/**".to_string()];
    let errors = validation_errors(validate_broker_config(&config));
    assert_contains(&errors, "must use https");
}

#[test]
fn rejects_atlassian_gateway_with_basic_service_credentials() {
    let mut config = sample_broker();
    config
        .providers
        .get_mut::<agent_access_jira::JiraProviderConfig>()
        .unwrap()
        .allowed_upstream_hosts
        .push("https://api.atlassian.com/ex/jira/cloud/rest/api/3/**".to_string());
    let errors = validation_errors(validate_broker_config(&config));
    assert_contains(
        &errors,
        "credentials.service.jira does not resolve to a bearer_token credential",
    );
}

#[test]
fn accepts_jira_per_user_grants_when_configured() {
    let mut config = sample_broker();
    config.credentials.per_user.insert(
        "jira".to_string(),
        jira_per_user_credential("/etc/agent-access/jira-user-credentials.json"),
    );
    config.policy.grants[0].credential_mode = "per_user".to_string();

    validate_broker_config(&config).unwrap();
}

#[test]
fn rejects_the_removed_per_user_credential_types_and_fields() {
    // `credential_name` and `profile` are no longer credential fields.
    for field in [
        "credential_name = \"default\"",
        "profile = \"jira-cloud-api-token\"",
    ] {
        let raw = format!(
            "{MINIMAL_BROKER_CONFIG}\n[credentials.per_user.jira]\ntype = \"connection\"\nconnection = \"jira\"\n{field}\n"
        );
        assert!(parse_test_config(&raw).is_err(), "{field}");
    }
    // The per-user `managed_store` and `oauth` types are gone.
    for kind in ["managed_store", "oauth"] {
        let mut config = sample_broker();
        enable_test_managed_store(&mut config);
        let mut credential = connection_per_user_credential("jira");
        credential.kind = kind.to_string();
        credential.connection = None;
        config
            .credentials
            .per_user
            .insert("jira".to_string(), credential);
        let errors = validation_errors(validate_broker_config(&config));
        assert_contains(
            &errors,
            "credentials.per_user.jira.type must be connection or secret_store for per_user credentials",
        );
        assert_contains(
            &errors,
            &format!(
                "credentials.per_user.jira.type {kind} is unsupported; expected basic_api_token, bearer_token, secret_store, or connection"
            ),
        );
    }
}

#[test]
fn rejects_static_per_user_credentials() {
    for service in ["jira", "confluence"] {
        for credential in [
            CredentialConfig {
                kind: "basic_api_token".to_string(),
                username_ref: Some(format!("env:{service}_ALICE_USERNAME")),
                token_ref: Some(format!("env:{service}_ALICE_API_TOKEN")),
                provider: None,
                path: None,
                read_only: None,
                connection: None,
            },
            CredentialConfig {
                kind: "bearer_token".to_string(),
                username_ref: None,
                token_ref: Some(format!("env:{service}_ALICE_BEARER_TOKEN")),
                provider: None,
                path: None,
                read_only: None,
                connection: None,
            },
        ] {
            let mut config = sample_broker();
            config
                .credentials
                .per_user
                .insert(service.to_string(), credential);

            let errors = validation_errors(validate_broker_config(&config));
            assert_contains(
                &errors,
                &format!(
                    "credentials.per_user.{service}.type must be connection or secret_store for per_user credentials"
                ),
            );
        }
    }
}

#[test]
fn rejects_jira_per_user_grants_when_mode_is_unconfigured() {
    let mut config = sample_broker();
    config.policy.grants[0].credential_mode = "per_user".to_string();

    let errors = validation_errors(validate_broker_config(&config));
    assert_contains(
        &errors,
        "uses per_user credentials for jira but they are not configured",
    );
}

#[test]
fn accepts_jira_finite_per_user_lookup_actions_without_lookup_credentials() {
    let mut config = sample_broker();
    config.credentials.per_user.insert(
        "jira".to_string(),
        jira_per_user_credential("/etc/agent-access/jira-user-credentials.json"),
    );
    config.credentials.lookup.remove("jira");
    config.policy.grants[0].actions = vec!["issue.view".to_string()];
    config.policy.grants[0].credential_mode = "per_user".to_string();

    validate_broker_config(&config).unwrap();
}

#[test]
fn accepts_confluence_finite_per_user_lookup_actions_without_lookup_credentials() {
    let mut config = sample_broker();
    config.credentials.per_user.insert(
        "confluence".to_string(),
        jira_per_user_credential("/etc/agent-access/confluence-user-credentials.json"),
    );
    config.credentials.lookup.remove("confluence");
    config.policy.grants[1].actions = vec!["page.view".to_string()];
    config.policy.grants[1].credential_mode = "per_user".to_string();

    validate_broker_config(&config).unwrap();
}

#[test]
fn jira_comment_formats_allow_an_empty_disabled_set() {
    let mut config = sample_broker();
    config
        .providers
        .get_mut::<agent_access_jira::JiraProviderConfig>()
        .unwrap()
        .content
        .comment_formats = vec![];

    assert_format_disabled_actions_are_unavailable(config, &["jira.comment.add"]);
}

/// Disabling every write format hides the gated actions from the service
/// descriptor, so grants naming them are rejected until they are removed.
fn assert_format_disabled_actions_are_unavailable(mut config: BrokerConfig, expected: &[&str]) {
    if !expected.is_empty() {
        let errors = validation_errors(validate_broker_config(&config));
        for action in expected {
            let (service, action) = action.split_once('.').unwrap();
            assert_contains(
                &errors,
                &format!("action {action} is unknown for service {service}"),
            );
        }
    }
    let descriptors = configured_service_descriptors(&config);
    for grant in &mut config.policy.grants {
        let Some(descriptor) = descriptors.get(&grant.service) else {
            continue;
        };
        grant
            .actions
            .retain(|action| descriptor.action(action).is_some());
    }
    config
        .policy
        .grants
        .retain(|grant| !grant.actions.is_empty());
    validate_broker_config(&config).unwrap();
}

#[test]
fn jira_comment_formats_still_reject_unsupported_and_duplicate_values() {
    let mut config = sample_broker();
    config
        .providers
        .get_mut::<agent_access_jira::JiraProviderConfig>()
        .unwrap()
        .content
        .comment_formats = vec!["storage".to_string(), "adf".to_string(), "adf".to_string()];

    let errors = validation_errors(validate_broker_config(&config));
    assert_contains(
        &errors,
        "providers.jira.content.comment_formats contains unsupported format storage",
    );
    assert_contains(
        &errors,
        "providers.jira.content.comment_formats contains duplicate format adf",
    );
}

#[test]
fn confluence_content_formats_allow_empty_disabled_sets() {
    let mut config = sample_broker();
    config
        .providers
        .get_mut::<agent_access_confluence::ConfluenceProviderConfig>()
        .unwrap()
        .content
        .page_formats = vec![];
    assert_format_disabled_actions_are_unavailable(config, &[]);

    let mut config = sample_broker();
    config
        .providers
        .get_mut::<agent_access_confluence::ConfluenceProviderConfig>()
        .unwrap()
        .content
        .blog_formats = vec![];
    assert_format_disabled_actions_are_unavailable(config, &[]);

    let mut config = sample_broker();
    config
        .providers
        .get_mut::<agent_access_confluence::ConfluenceProviderConfig>()
        .unwrap()
        .content
        .comment_formats = vec![];
    assert_format_disabled_actions_are_unavailable(config, &[]);
}

#[test]
fn confluence_content_formats_still_reject_unsupported_and_duplicate_values() {
    let mut config = sample_broker();
    let content = &mut config
        .providers
        .get_mut::<agent_access_confluence::ConfluenceProviderConfig>()
        .unwrap()
        .content;
    content.page_formats = vec![
        "unsupported".to_string(),
        "storage".to_string(),
        "storage".to_string(),
    ];
    content.blog_formats = vec![
        "atlas_doc_format".to_string(),
        "storage".to_string(),
        "storage".to_string(),
    ];
    content.comment_formats = vec![
        "atlas_doc_format".to_string(),
        "storage".to_string(),
        "storage".to_string(),
    ];
    let errors = validation_errors(validate_broker_config(&config));
    assert_contains(
        &errors,
        "providers.confluence.content.page_formats contains unsupported format unsupported",
    );
    assert_contains(
        &errors,
        "providers.confluence.content.page_formats contains duplicate format storage",
    );
    assert_contains(
        &errors,
        "providers.confluence.content.blog_formats contains unsupported format atlas_doc_format",
    );
    assert_contains(
        &errors,
        "providers.confluence.content.blog_formats contains duplicate format storage",
    );
    assert_contains(
        &errors,
        "providers.confluence.content.comment_formats contains unsupported format atlas_doc_format",
    );
    assert_contains(
        &errors,
        "providers.confluence.content.comment_formats contains duplicate format storage",
    );
}

#[test]
fn service_mode_confluence_comment_actions_require_lookup_credentials() {
    let mut config = sample_broker();
    config.credentials.lookup.remove("confluence");
    config.policy.grants[1].actions = vec!["page.footer_comment.view".to_string()];
    config.policy.grants[1].credential_mode = "service".to_string();
    config.policy.grants[1].resources = select_resources(
        &mut config,
        agent_access_confluence::CONFLUENCE_SPACE_RESOURCE
            .id()
            .clone(),
        &[exact("ENG")],
    );

    let errors = validation_errors(validate_broker_config(&config));
    assert_contains(&errors, "requires credentials.lookup.confluence");
}

#[test]
fn accepts_wildcard_per_user_lookup_actions_without_lookup_credentials() {
    let mut config = sample_broker();
    config.credentials.per_user.insert(
        "jira".to_string(),
        jira_per_user_credential("/etc/agent-access/jira-user-credentials.json"),
    );
    config.credentials.lookup.remove("jira");
    config.policy.grants[0].actions = vec!["issue.view".to_string()];
    config.policy.grants[0].credential_mode = "per_user".to_string();
    config.policy.grants[0].resources = select_resources(
        &mut config,
        agent_access_jira::JIRA_PROJECT_RESOURCE.id().clone(),
        &[ResourceSelector::All],
    );
    validate_broker_config(&config).unwrap();

    let mut config = sample_broker();
    config.credentials.per_user.insert(
        "confluence".to_string(),
        jira_per_user_credential("/etc/agent-access/confluence-user-credentials.json"),
    );
    config.credentials.lookup.remove("confluence");
    config.policy.grants[1].actions = vec!["page.view".to_string()];
    config.policy.grants[1].credential_mode = "per_user".to_string();
    config.policy.grants[1].resources = select_resources(
        &mut config,
        agent_access_confluence::CONFLUENCE_SPACE_RESOURCE
            .id()
            .clone(),
        &[ResourceSelector::All],
    );
    validate_broker_config(&config).unwrap();
}

#[test]
fn rejects_shadowed_service_lookup_grant_without_lookup_credentials() {
    let mut config = sample_broker();
    config.credentials.per_user.insert(
        "jira".to_string(),
        jira_per_user_credential("/etc/agent-access/jira-user-credentials.json"),
    );
    config.credentials.lookup.remove("jira");
    config.policy.grants[0].actions = vec!["issue.view".to_string()];
    config.policy.grants[0].credential_mode = "per_user".to_string();
    config.policy.grants[0].priority = Some(100);
    config.policy.grants[0].resources = select_resources(
        &mut config,
        agent_access_jira::JIRA_PROJECT_RESOURCE.id().clone(),
        &[ResourceSelector::All],
    );

    let mut service_grant = config.policy.grants[0].clone();
    service_grant.credential_mode = "service".to_string();
    service_grant.priority = Some(10);
    service_grant.resources = select_resources(
        &mut config,
        agent_access_jira::JIRA_PROJECT_RESOURCE.id().clone(),
        &[exact("PROJ")],
    );
    config.policy.grants.push(service_grant);

    let errors = validation_errors(validate_broker_config(&config));
    assert_contains(&errors, "requires credentials.lookup.jira");
}

#[test]
fn rejects_lookup_backed_both_wildcard_mixed_modes() {
    let mut config = sample_broker();
    config.credentials.per_user.insert(
        "jira".to_string(),
        jira_per_user_credential("/etc/agent-access/jira-user-credentials.json"),
    );
    config.policy.grants[0].actions = vec!["issue.view".to_string()];
    config.policy.grants[0].resources = select_resources(
        &mut config,
        agent_access_jira::JIRA_PROJECT_RESOURCE.id().clone(),
        &[ResourceSelector::All],
    );

    let mut per_user = config.policy.grants[0].clone();
    per_user.credential_mode = "per_user".to_string();
    config.policy.grants.push(per_user);

    let errors = validation_errors(validate_broker_config(&config));
    assert_contains(&errors, "ambiguous credential mode precedence");
    assert_contains(&errors, "overlapping project scope values");
}

#[test]
fn accepts_jira_per_user_search_without_lookup_credentials() {
    let mut config = sample_broker();
    config.credentials.per_user.insert(
        "jira".to_string(),
        jira_per_user_credential("/etc/agent-access/jira-user-credentials.json"),
    );
    config.credentials.lookup.remove("jira");
    config.policy.grants[0].actions = vec!["search".to_string()];
    config.policy.grants[0].credential_mode = "per_user".to_string();

    validate_broker_config(&config).unwrap();
}

#[test]
fn accepts_disjoint_mixed_lookup_grants_when_lookup_is_configured() {
    let mut config = sample_broker();
    config.credentials.per_user.insert(
        "jira".to_string(),
        jira_per_user_credential("/etc/agent-access/jira-user-credentials.json"),
    );
    config.policy.grants[0].actions = vec!["issue.view".to_string()];
    config.policy.grants[0].credential_mode = "service".to_string();
    config.policy.grants[0].resources = select_resources(
        &mut config,
        agent_access_jira::JIRA_PROJECT_RESOURCE.id().clone(),
        &[exact("PROJ")],
    );

    let mut per_user = config.policy.grants[0].clone();
    per_user.credential_mode = "per_user".to_string();
    per_user.resources = select_resources(
        &mut config,
        agent_access_jira::JIRA_PROJECT_RESOURCE.id().clone(),
        &[exact("OPS")],
    );
    config.policy.grants.push(per_user);

    validate_broker_config(&config).unwrap();
}

#[test]
fn accepts_priority_resolved_jira_service_and_per_user_grants() {
    for (first_mode, first_priority, second_mode, second_priority) in [
        ("service", Some(10), "per_user", Some(20)),
        ("per_user", Some(20), "service", Some(10)),
    ] {
        let mut config = sample_broker();
        config.credentials.per_user.insert(
            "jira".to_string(),
            jira_per_user_credential("/etc/agent-access/jira-user-credentials.json"),
        );
        config.policy.grants[0].actions = vec!["search".to_string()];
        config.policy.grants[0].credential_mode = first_mode.to_string();
        config.policy.grants[0].priority = first_priority;

        let mut duplicate = config.policy.grants[0].clone();
        duplicate.credential_mode = second_mode.to_string();
        duplicate.priority = second_priority;
        config.policy.grants.push(duplicate);

        validate_broker_config(&config).unwrap();
    }
}

#[test]
fn accepts_typed_containment_wildcard_scopes() {
    let mut config = sample_broker();
    config.policy.grants[0].actions = vec!["search".to_string()];
    config.policy.grants[0].resources = select_resources(
        &mut config,
        agent_access_jira::JIRA_PROJECT_RESOURCE.id().clone(),
        &[ResourceSelector::All],
    );
    validate_broker_config(&config).unwrap();

    let mut config = sample_broker();
    config.policy.grants[1].actions = vec!["search".to_string()];
    config.policy.grants[1].resources = select_resources(
        &mut config,
        agent_access_confluence::CONFLUENCE_SPACE_RESOURCE
            .id()
            .clone(),
        &[ResourceSelector::All],
    );
    validate_broker_config(&config).unwrap();
}

#[test]
fn validates_resource_selectors_and_rejects_retired_child_scope_types() {
    let mut config = sample_broker();
    config.policy.grants[0].resources = select_resources(
        &mut config,
        agent_access_jira::JIRA_PROJECT_RESOURCE.id().clone(),
        &[ResourceSelector::All, exact("PROJ")],
    );
    validate_broker_config(&config).unwrap();

    let mut config = sample_broker();
    config.policy.grants[1].resources = select_resources(
        &mut config,
        agent_access_confluence::CONFLUENCE_SPACE_RESOURCE
            .id()
            .clone(),
        &[exact("eng")],
    );
    let errors = validation_errors(validate_broker_config(&config));
    assert_contains(&errors, "selector is invalid for confluence_space");

    for resource_type in ["jira_issue", "confluence_page"] {
        let mut config = sample_broker();
        config.policy.grants[0].resources = select_resources(
            &mut config,
            ResourceType::new(resource_type).unwrap(),
            &[ResourceSelector::All],
        );
        let errors = validation_errors(validate_broker_config(&config));
        assert!(
            errors.iter().any(|error| error
                .ends_with(&format!("uses unregistered resource type {resource_type}"))),
            "{errors:?}"
        );
    }
    assert!(serde_json::from_value::<ResourceType>(serde_json::json!("Jira-Issue")).is_err());
    assert!(
        serde_json::from_value::<ResourceSelector>(serde_json::json!({"kind":"all","value":"*"}))
            .is_err()
    );
}

#[test]
fn rejects_ambiguous_wildcard_and_finite_credential_mode_overlap() {
    let mut config = sample_broker();
    config.credentials.per_user.insert(
        "jira".to_string(),
        jira_per_user_credential("/etc/agent-access/jira-user-credentials.json"),
    );
    config.policy.grants[0].actions = vec!["search".to_string()];
    config.policy.grants[0].resources = select_resources(
        &mut config,
        agent_access_jira::JIRA_PROJECT_RESOURCE.id().clone(),
        &[ResourceSelector::All],
    );

    let mut duplicate = config.policy.grants[0].clone();
    duplicate.credential_mode = "per_user".to_string();
    duplicate.resources = select_resources(
        &mut config,
        agent_access_jira::JIRA_PROJECT_RESOURCE.id().clone(),
        &[exact("PROJ")],
    );
    config.policy.grants.push(duplicate);

    let errors = validation_errors(validate_broker_config(&config));
    assert_contains(&errors, "ambiguous credential mode precedence");
    assert_contains(&errors, "overlapping project scope values");
}

#[test]
fn rejects_atlassian_gateway_without_bearer_execution_credentials() {
    let mut config = sample_broker();
    config
        .providers
        .get_mut::<agent_access_jira::JiraProviderConfig>()
        .unwrap()
        .allowed_upstream_hosts
        .push("https://api.atlassian.com/ex/jira/cloud/rest/api/3/**".to_string());
    config.credentials.service.remove("jira");
    config.credentials.per_user.remove("jira");

    let errors = validation_errors(validate_broker_config(&config));
    assert_contains(
        &errors,
        "no bearer_token execution credential is configured",
    );
}

#[test]
fn rejects_atlassian_bearer_credentials_without_gateway_allowlist() {
    let mut config = sample_broker();
    let credential = config.credentials.service.get_mut("jira").unwrap();
    credential.kind = "bearer_token".to_string();
    credential.username_ref = None;

    let errors = validation_errors(validate_broker_config(&config));
    assert_contains(
        &errors,
        "credentials.service.jira.type bearer_token requires providers.jira.allowed_upstream_hosts to include api.atlassian.com",
    );
}

#[test]
fn rejects_atlassian_gateway_without_valid_cloud_id() {
    let mut config = sample_broker();
    let jira = config
        .providers
        .get_mut::<agent_access_jira::JiraProviderConfig>()
        .unwrap();
    jira.allowed_upstream_hosts
        .push("https://api.atlassian.com/ex/jira/cloud/rest/api/3/**".to_string());
    jira.cloud_id = None;
    let credential = config.credentials.service.get_mut("jira").unwrap();
    credential.kind = "bearer_token".to_string();
    credential.username_ref = None;

    let errors = validation_errors(validate_broker_config(&config));
    assert_contains(
        &errors,
        "providers.jira.cloud_id is required when api.atlassian.com is allowed",
    );

    let mut config = sample_broker();
    let jira = config
        .providers
        .get_mut::<agent_access_jira::JiraProviderConfig>()
        .unwrap();
    jira.allowed_upstream_hosts
        .push("https://api.atlassian.com/ex/jira/cloud/rest/api/3/**".to_string());
    jira.cloud_id = Some("not-a-uuid".to_string());
    let credential = config.credentials.service.get_mut("jira").unwrap();
    credential.kind = "bearer_token".to_string();
    credential.username_ref = None;

    let errors = validation_errors(validate_broker_config(&config));
    assert_contains(
        &errors,
        "providers.jira.cloud_id must be a valid Atlassian cloud UUID",
    );
}

#[test]
fn backend_validation_passes_static_and_secret_store_kinds_as_written() {
    let config = sample_broker();
    let jira = configured_provider_descriptors(&config)
        .into_iter()
        .find(|descriptor| descriptor.service == "jira")
        .unwrap();
    let resolve = |credential: CredentialConfig| {
        resolved_credential_kind(&config.credentials, &credential, &jira).map(str::to_string)
    };
    assert_eq!(
        resolve(jira_per_user_credential("/etc/agent-access/jira.json")).as_deref(),
        Some("secret_store")
    );
    let service = config.credentials.service.get("jira").unwrap().clone();
    assert_eq!(resolve(service).as_deref(), Some("basic_api_token"));
}

#[test]
fn accepts_a_shared_gitlab_connection_for_rest_and_the_git_gateway() {
    let mut config = sample_broker();
    enable_test_managed_store(&mut config);
    let mut gateway = git_http_gateway_config();
    gateway.credential_modes = vec!["per_user".to_string()];
    config.gateways.insert("gitlab_git".to_string(), gateway);
    use_connection(
        &mut config,
        "gitlab",
        ConnectionConfig {
            display_name: Some("GitLab".to_string()),
            ..token_connection("gitlab-access-token")
        },
        &["gitlab", "gitlab_git"],
    );

    validate_broker_config(&config).unwrap();
    assert_eq!(
        config
            .credentials
            .connection_consumers("gitlab")
            .collect::<Vec<_>>(),
        ["gitlab", "gitlab_git"]
    );
    let connection = config
        .credentials
        .personal_connection("gitlab_git")
        .unwrap();
    assert_eq!(connection.id, "gitlab");
    assert_eq!(
        connection.select(Some(crate::PrincipalKind::User)),
        crate::Selection::Token("gitlab-access-token")
    );
    assert!(config.credentials.personal_connection("jira").is_none());
}

#[test]
fn accepts_separate_jira_and_confluence_connections_on_product_profiles() {
    let mut config = sample_broker();
    enable_test_managed_store(&mut config);
    use_connection(
        &mut config,
        "jira",
        token_connection("jira-cloud-api-token"),
        &["jira"],
    );
    use_connection(
        &mut config,
        "confluence",
        token_connection("confluence-cloud-api-token"),
        &["confluence"],
    );
    config.policy.grants[0].credential_mode = "per_user".to_string();

    validate_broker_config(&config).unwrap();
}

#[test]
fn rejects_a_shared_connection_profile_a_consumer_does_not_declare() {
    let mut config = sample_broker();
    enable_test_managed_store(&mut config);
    use_connection(
        &mut config,
        "atlassian",
        token_connection("jira-cloud-api-token"),
        &["jira", "confluence"],
    );

    let errors = validation_errors(validate_broker_config(&config));
    assert_contains(
        &errors,
        "credentials.connections.atlassian.token_profile jira-cloud-api-token is unsupported for service confluence",
    );
    assert!(
        !errors
            .iter()
            .any(|error| error.contains("unsupported for service jira")),
        "{errors:?}"
    );
}

#[test]
fn rejects_a_gateway_connection_profile_it_cannot_present() {
    let mut config = sample_broker();
    enable_test_managed_store(&mut config);
    let mut gateway = git_http_gateway_config();
    gateway.credential_modes = vec!["per_user".to_string()];
    config.gateways.insert("gitlab_git".to_string(), gateway);
    use_connection(
        &mut config,
        "repositories",
        token_connection("not-declared-anywhere"),
        &["gitlab_git"],
    );

    let errors = validation_errors(validate_broker_config(&config));
    assert_contains(
        &errors,
        "credentials.connections.repositories.token_profile not-declared-anywhere is not a token or basic profile the gateway gitlab_git can present",
    );
}

#[test]
fn rejects_connections_without_a_method_or_with_dangling_references() {
    let mut config = sample_broker();
    enable_test_managed_store(&mut config);
    use_connection(
        &mut config,
        "empty",
        ConnectionConfig {
            display_name: Some(" ".to_string()),
            token_profile: None,
            oauth: None,
        },
        &[],
    );
    config.credentials.per_user.insert(
        "jira".to_string(),
        connection_per_user_credential("missing"),
    );
    config.credentials.per_user.insert(
        "unconfigured".to_string(),
        connection_per_user_credential("empty"),
    );
    let mut service_entry = connection_per_user_credential("empty");
    service_entry.token_ref = Some("env:TOKEN".to_string());
    config
        .credentials
        .service
        .insert("gitlab".to_string(), service_entry);
    let mut stray = jira_per_user_credential("/etc/agent-access/confluence.json");
    stray.connection = Some("empty".to_string());
    config
        .credentials
        .per_user
        .insert("confluence".to_string(), stray);

    let errors = validation_errors(validate_broker_config(&config));
    for needle in [
        "credentials.connections.empty must set token_profile, oauth, or both",
        "credentials.connections.empty.display_name must not be empty",
        "credentials.per_user.jira.connection missing must name a configured credentials.connections entry",
        "credentials.per_user.unconfigured uses a credential connection, but unconfigured is not a configured service",
        "credentials.service.gitlab.type connection is supported only for credentials.per_user",
        "credentials.service.gitlab.type connection sets only connection",
        "credentials.per_user.confluence.connection is supported only for type connection",
    ] {
        assert_contains(&errors, needle);
    }
}

#[test]
fn connection_ids_share_the_service_namespace_with_their_consumers_only() {
    let mut config = sample_broker();
    enable_test_managed_store(&mut config);
    use_connection(
        &mut config,
        "confluence",
        token_connection("jira-cloud-api-token"),
        &["jira"],
    );
    use_connection(
        &mut config,
        "broker",
        token_connection("gitlab-access-token"),
        &["gitlab"],
    );

    let errors = validation_errors(validate_broker_config(&config));
    assert_contains(
        &errors,
        "credentials.connections.confluence collides with the configured service confluence, which does not consume it",
    );
    assert_contains(
        &errors,
        "credentials.connections.broker uses an invalid connection ID",
    );

    let mut config = sample_broker();
    enable_test_managed_store(&mut config);
    let mut gateway = git_http_gateway_config();
    gateway.credential_modes = vec!["per_user".to_string()];
    config.gateways.insert("gitlab_git".to_string(), gateway);
    use_connection(
        &mut config,
        "gitlab_git",
        token_connection("gitlab-access-token"),
        &["gitlab"],
    );
    let errors = validation_errors(validate_broker_config(&config));
    assert_contains(
        &errors,
        "credentials.connections.gitlab_git collides with the configured service gitlab_git, which does not consume it",
    );
}

#[test]
fn rejects_oauth_connections_consumers_cannot_use() {
    let mut config = sample_broker();
    enable_test_managed_store(&mut config);
    let mut gateway = git_http_gateway_config();
    gateway.credential_modes = vec!["per_user".to_string()];
    config.gateways.insert("gitlab_git".to_string(), gateway);
    let oauth = |profile: &str| ConnectionOAuthConfig {
        registration: "gitlab".to_string(),
        profile: profile.to_string(),
    };
    use_connection(
        &mut config,
        "gitlab",
        ConnectionConfig {
            display_name: None,
            token_profile: Some("gitlab-access-token".to_string()),
            oauth: Some(oauth("default")),
        },
        &["gitlab", "gitlab_git"],
    );
    use_connection(
        &mut config,
        "gitlab_projects",
        ConnectionConfig {
            display_name: None,
            token_profile: None,
            oauth: Some(oauth("projects")),
        },
        &[],
    );

    let errors = validation_errors(validate_broker_config(&config));
    for needle in [
        "credentials.connections.gitlab.oauth must name a configured registration and permission profile",
        "credentials.connections.gitlab.oauth requires every consumer to accept delegated credentials, which gitlab does not",
        "credentials.connections.gitlab.oauth requires every consumer to accept delegated credentials, which gitlab_git does not",
        "credentials.connections.gitlab and credentials.connections.gitlab_projects share OAuth registration gitlab and must use the same profile",
    ] {
        assert_contains(&errors, needle);
    }
}

#[test]
fn connections_require_the_managed_store_and_credential_encryption() {
    let mut config = sample_broker();
    config.credential_encryption = None;
    use_connection(
        &mut config,
        "jira",
        token_connection("jira-cloud-api-token"),
        &["jira"],
    );

    let errors = validation_errors(validate_broker_config(&config));
    assert_contains(&errors, "credentials.connections requires managed_store");
    assert_contains(
        &errors,
        "credentials.connections requires credential_encryption",
    );
}

#[test]
fn backend_validation_resolves_connection_token_profiles() {
    let mut config = sample_broker();
    let jira = configured_provider_descriptors(&config)
        .into_iter()
        .find(|descriptor| descriptor.service == "jira")
        .unwrap();
    config
        .credentials
        .connections
        .insert("jira".to_string(), token_connection("jira-cloud-api-token"));
    config.credentials.connections.insert(
        "both".to_string(),
        ConnectionConfig {
            oauth: Some(ConnectionOAuthConfig {
                registration: "atlassian".to_string(),
                profile: "default".to_string(),
            }),
            ..token_connection("jira-cloud-api-token")
        },
    );
    config.credentials.connections.insert(
        "oauth_only".to_string(),
        ConnectionConfig {
            display_name: None,
            token_profile: None,
            oauth: Some(ConnectionOAuthConfig {
                registration: "atlassian".to_string(),
                profile: "default".to_string(),
            }),
        },
    );
    config
        .credentials
        .connections
        .insert("unknown_profile".to_string(), token_connection("unknown"));
    let resolve = |connection: &str| {
        resolved_credential_kind(
            &config.credentials,
            &connection_per_user_credential(connection),
            &jira,
        )
        .map(str::to_string)
    };

    assert_eq!(resolve("jira").as_deref(), Some("basic_api_token"));
    // The token profile's kind, even when OAuth is also configured.
    assert_eq!(resolve("both").as_deref(), Some("basic_api_token"));
    assert_eq!(resolve("oauth_only").as_deref(), Some("oauth"));
    assert_eq!(resolve("unknown_profile"), None);
    assert_eq!(resolve("missing"), None);
}

#[test]
fn accepts_atlassian_gateway_with_bearer_connection_per_user_credentials() {
    let mut config = sample_broker();
    enable_test_managed_store(&mut config);
    use_atlassian_gateway_for_jira(&mut config);
    use_connection(
        &mut config,
        "jira",
        token_connection("jira-bearer-token"),
        &["jira"],
    );
    config.policy.grants[0].credential_mode = "per_user".to_string();

    validate_broker_config(&config).unwrap();
}

#[test]
fn rejects_atlassian_gateway_with_basic_connection_per_user_credentials() {
    let mut config = sample_broker();
    enable_test_managed_store(&mut config);
    use_atlassian_gateway_for_jira(&mut config);
    use_connection(
        &mut config,
        "jira",
        token_connection("jira-cloud-api-token"),
        &["jira"],
    );

    let errors = validation_errors(validate_broker_config(&config));
    assert_contains(
        &errors,
        "credentials.per_user.jira does not resolve to a bearer_token credential",
    );
}

#[test]
fn accepts_confluence_gateway_with_bearer_connection_per_user_credentials() {
    let mut config = sample_broker();
    enable_test_managed_store(&mut config);
    config
        .providers
        .get_mut::<agent_access_confluence::ConfluenceProviderConfig>()
        .unwrap()
        .allowed_upstream_hosts
        .push(
            "https://api.atlassian.com/ex/confluence/00000000-0000-0000-0000-000000000000/wiki/**"
                .to_string(),
        );
    let credential = config.credentials.service.get_mut("confluence").unwrap();
    credential.kind = "bearer_token".to_string();
    credential.username_ref = None;
    use_connection(
        &mut config,
        "confluence",
        token_connection("confluence-bearer-token"),
        &["confluence"],
    );

    validate_broker_config(&config).unwrap();
}

#[test]
fn rejects_atlassian_gateway_with_secret_store_per_user_credentials() {
    let mut config = sample_broker();
    use_atlassian_gateway_for_jira(&mut config);
    config.credentials.per_user.insert(
        "jira".to_string(),
        jira_per_user_credential("/etc/agent-access/jira-user-credentials.json"),
    );

    let errors = validation_errors(validate_broker_config(&config));
    assert_contains(
        &errors,
        "credentials.per_user.jira does not resolve to a bearer_token credential",
    );
}

#[test]
fn rejects_invalid_allowlist_wildcards() {
    let mut config = sample_broker();
    config
        .providers
        .get_mut::<agent_access_jira::JiraProviderConfig>()
        .unwrap()
        .allowed_upstream_hosts = vec!["https://*.atlassian.net/rest/api/3/**".to_string()];
    let errors = validation_errors(validate_broker_config(&config));
    assert_contains(&errors, "must not wildcard the host");

    let mut config = sample_broker();
    config
        .providers
        .get_mut::<agent_access_jira::JiraProviderConfig>()
        .unwrap()
        .allowed_upstream_hosts =
        vec!["https://example.atlassian.net/rest/api/3/*issue".to_string()];
    let errors = validation_errors(validate_broker_config(&config));
    assert_contains(&errors, "invalid wildcard path segment");
}

#[test]
fn rejects_raw_secret_values() {
    let mut config = sample_broker();
    config
        .credentials
        .service
        .get_mut("jira")
        .unwrap()
        .token_ref = Some("literal-secret".to_string());
    let errors = validation_errors(validate_broker_config(&config));
    assert_contains(&errors, "must use env:NAME or file:/absolute/path");
}

#[test]
fn rejects_secret_store_outside_per_user_and_relative_store_paths() {
    let mut config = sample_broker();
    config.credentials.service.get_mut("jira").unwrap().kind = "secret_store".to_string();
    config.credentials.service.get_mut("jira").unwrap().provider = Some("local_file".to_string());
    config.credentials.service.get_mut("jira").unwrap().path =
        Some("/etc/agent-access/jira-users.json".to_string());
    let errors = validation_errors(validate_broker_config(&config));
    assert_contains(
        &errors,
        "secret_store is supported only for credentials.per_user",
    );

    let mut config = sample_broker();
    config.credentials.per_user.insert(
        "jira".to_string(),
        CredentialConfig {
            kind: "secret_store".to_string(),
            username_ref: None,
            token_ref: None,
            provider: Some("local_file".to_string()),
            path: Some("relative-users.json".to_string()),
            read_only: None,
            connection: None,
        },
    );
    config.policy.grants[0].credential_mode = "per_user".to_string();
    let errors = validation_errors(validate_broker_config(&config));
    assert_contains(&errors, "path must be absolute for secret_store");
}

#[test]
fn rejects_relative_managed_store_path_before_state_lock_admission() {
    let mut config = sample_broker();
    config.managed_store = Some(ManagedStoreConfig {
        kind: "sqlite".to_string(),
        path: "relative-managed.sqlite3".to_string(),
        require_registered_principal_for_invocation: false,
        auto_migrate: true,
    });

    let errors = validation_errors(validate_broker_config(&config));

    assert_contains(&errors, "managed_store.path must be absolute");
}

#[test]
fn accepts_short_absolute_file_secret_refs() {
    assert!(is_secret_ref("file:/x"));
}

#[test]
fn rejects_trust_all_proxy_and_invalid_proxy_entries() {
    let mut config = sample_broker();
    config.network.trusted_proxies = vec!["*".to_string()];
    let errors = validation_errors(validate_broker_config(&config));
    assert_contains(&errors, "cannot trust all sources");

    let mut config = sample_broker();
    config.network.trusted_proxies = vec!["::/0".to_string()];
    let errors = validation_errors(validate_broker_config(&config));
    assert_contains(&errors, "cannot trust all sources");

    let mut config = sample_broker();
    config.deployment.environment = "production".to_string();
    config.deployment.allow_production_anonymous = true;
    config.network.trusted_proxies = vec!["0.0.0.0/0".to_string()];
    let errors = validation_errors(validate_broker_config(&config));
    assert_contains(&errors, "cannot trust all sources");

    let mut config = sample_broker();
    config.network.trusted_proxies = vec!["not-an-ip".to_string()];
    let errors = validation_errors(validate_broker_config(&config));
    assert_contains(&errors, "must be an IP address or CIDR");
}

#[test]
fn management_defaults_do_not_allow_classless_admin_identities() {
    let management = ManagementConfig::default();

    assert!(!management.allow_classless_admin_identities);
    assert!(!management.allow_classless_user_management);
}

#[test]
fn management_enabled_without_store_requires_classless_admin_bootstrap() {
    let mut config = sample_broker();
    config.management.enabled = true;
    config.managed_store = None;

    let errors = validation_errors(validate_broker_config(&config));

    assert_contains(&errors, "management.enabled without managed_store requires");
}

#[test]
fn management_enabled_without_store_allows_explicit_classless_admin_bootstrap() {
    let mut config = sample_broker();
    config.management.enabled = true;
    config.management.allow_classless_admin_identities = true;
    config.management.admin_principals = vec!["admin".to_string()];
    config.managed_store = None;

    validate_broker_config(&config).unwrap();
}

#[test]
fn management_deserialization_defaults_do_not_allow_classless_admin_identities() {
    let raw = r#"
[deployment]
environment = "development"

[identity]
mode = "required"
authority = "toml"

[management]
enabled = false

[policy]
authority = "toml"
default_decision = "deny"

[limits]
upload_spool_dir = "upload-spool"
"#;
    let config = parse_test_config(raw).unwrap();

    assert!(!config.management.allow_classless_admin_identities);
    assert!(!config.management.allow_classless_user_management);
}

#[test]
fn deployment_defaults_do_not_enable_fake_service() {
    let deployment = DeploymentConfig::default();

    assert!(!deployment.enable_fake_service);
}

#[test]
fn fake_service_requires_explicit_non_production_enablement() {
    let mut config = sample_broker();
    config.credentials.service.insert(
        "fake".to_string(),
        CredentialConfig {
            kind: "bearer_token".to_string(),
            username_ref: None,
            token_ref: Some("env:FAKE_SERVICE_TOKEN".to_string()),
            provider: None,
            path: None,
            read_only: None,
            connection: None,
        },
    );
    config.policy.grants[0].service = "fake".to_string();
    config.policy.grants[0].actions = vec!["echo".to_string()];
    config.policy.grants[0].resources = select_resources(
        &mut config,
        FAKE_PROJECT_RESOURCE.id().clone(),
        &[exact("TEST")],
    );

    let errors = validation_errors(validate_broker_config(&config));
    assert_contains(&errors, "references unknown service fake");

    config.deployment.enable_fake_service = true;
    config.providers.insert(FakeProviderConfig::default());
    validate_broker_config(&config).unwrap();

    config.deployment.environment = "production".to_string();
    let errors = validation_errors(validate_broker_config(&config));
    assert_contains(
        &errors,
        "deployment.enable_fake_service is not allowed in production",
    );
}

#[test]
fn attribution_globs_validate_against_configured_provider_capabilities() {
    let mut config = sample_broker();
    config.attribution.actions.insert(
        "jira".to_string(),
        vec!["comment.*".to_string(), "issue.update".to_string()],
    );
    validate_broker_config(&config).unwrap();

    config
        .attribution
        .actions
        .insert("jira".to_string(), vec!["issue.delete".to_string()]);
    let errors = validation_errors(validate_broker_config(&config));
    assert_contains(
        &errors,
        "attribution.actions.jira[0] must match at least one attribution-capable jira action enabled by the current configuration",
    );

    for pattern in [
        "issue[.*",
        "issue].*",
        "issue{.*",
        "issue}.*",
        r"issue\.*",
        "issue/*",
    ] {
        config
            .attribution
            .actions
            .insert("jira".to_string(), vec![pattern.to_string()]);
        let errors = validation_errors(validate_broker_config(&config));
        assert_contains(
            &errors,
            "attribution.actions.jira[0] contains unsupported glob characters",
        );
    }
}

#[test]
fn attribution_patterns_match_only_actions_enabled_by_format_settings() {
    let mut config = sample_broker();
    config
        .attribution
        .actions
        .insert("jira".to_string(), vec!["comment.*".to_string()]);
    validate_broker_config(&config).unwrap();

    config
        .providers
        .get_mut::<agent_access_jira::JiraProviderConfig>()
        .unwrap()
        .content
        .comment_formats = vec![];
    let errors = validation_errors(validate_broker_config(&config));
    assert_contains(
        &errors,
        "attribution.actions.jira[0] must match at least one attribution-capable jira action enabled by the current configuration",
    );
}

#[test]
fn attribution_globs_for_unconfigured_services_are_rejected() {
    let raw = r#"
[identity]
mode = "anonymous"
authority = "toml"

[policy]
authority = "toml"
default_decision = "deny"

[attribution.actions]
gitlab = ["does.not.match"]
bitbucket = ["*"]

[limits]
upload_spool_dir = "upload-spool"
"#;
    let config = parse_test_config(raw).unwrap();

    let errors = validation_errors(validate_broker_config(&config));
    assert_contains(
        &errors,
        "attribution.actions.gitlab names a service that is not configured",
    );
    assert_contains(
        &errors,
        "attribution.actions.bitbucket names a service that is not configured",
    );
}

#[test]
fn git_http_gateway_accepts_typed_repository_resources_and_exposes_capabilities() {
    let mut config = sample_broker();
    config.credentials.service.insert(
        "gitlab_git".to_string(),
        fake_service_credential("env:GITLAB_SERVICE_TOKEN"),
    );
    config
        .gateways
        .insert("gitlab_git".to_string(), git_http_gateway_config());
    let resources = select_resources(
        &mut config,
        GIT_REPOSITORY_RESOURCE.id().clone(),
        &[
            exact("sip/service"),
            exact("platform/tool"),
            namespace("sip/platform"),
        ],
    );
    config.policy.grants.push(PolicyGrantConfig {
        subjects: vec!["group:anonymous".to_string()],
        service: "gitlab_git".to_string(),
        actions: vec!["repo.fetch".to_string(), "repo.push".to_string()],
        resources,
        execution_contexts: Some(vec!["default".to_string()]),
        credential_mode: "service".to_string(),
        priority: None,
    });
    validate_broker_config(&config).unwrap();
    let catalog = configured_service_descriptors(&config);
    let gitlab = catalog.get("gitlab_git").unwrap();
    assert_eq!(gitlab.scope_types(), ["repository".to_string()].into());
    assert_eq!(
        gitlab.action("repo.fetch").unwrap().required_scope_types(),
        vec!["repository"]
    );
    assert_eq!(
        gitlab.action("repo.push").unwrap().credential_modes,
        vec!["service"]
    );
}

#[test]
fn gitlab_rest_provider_accepts_exact_namespace_and_all_resources() {
    let mut config = sample_broker();
    let resources = select_resources(
        &mut config,
        GIT_REPOSITORY_RESOURCE.id().clone(),
        &[
            exact("sip/service"),
            exact("platform/tool"),
            namespace("ops/platform"),
        ],
    );
    config
        .policy
        .grants
        .iter_mut()
        .find(|g| g.service == "gitlab")
        .unwrap()
        .resources = resources;
    validate_broker_config(&config).unwrap();
    let catalog = configured_service_descriptors(&config);
    let gitlab = catalog.get("gitlab").unwrap();
    assert_eq!(gitlab.scope_types(), ["repository".to_string()].into());
    let capabilities = agent_access_gitlab::gitlab_descriptor(
        config
            .providers
            .get::<agent_access_gitlab::GitlabProviderConfig>()
            .unwrap(),
    );
    assert_eq!(
        capabilities.resource_scopes["repository"].resource_type,
        GIT_REPOSITORY_RESOURCE.id().clone()
    );
    assert!(
        capabilities.resource_scopes["repository"]
            .selectors
            .contains(&"all".to_string())
    );
    assert_eq!(
        gitlab
            .action("project.view")
            .unwrap()
            .required_scope_types(),
        vec!["repository"]
    );
    assert_eq!(
        gitlab
            .action("project.upload")
            .unwrap()
            .required_scope_types(),
        vec!["repository"]
    );
    assert_eq!(
        gitlab.action("project.upload").unwrap().credential_modes,
        vec!["service", "per_user"]
    );
    assert_eq!(
        gitlab
            .actions
            .iter()
            .map(|action| action.action.clone())
            .collect::<BTreeSet<_>>(),
        capabilities
            .actions
            .iter()
            .map(|a| a.action.clone())
            .collect::<BTreeSet<_>>()
    );
    assert_eq!(
        gitlab.action("commit.view").unwrap().credential_modes,
        vec!["service", "per_user"]
    );

    let resources = select_resources(
        &mut config,
        GIT_REPOSITORY_RESOURCE.id().clone(),
        &[ResourceSelector::All],
    );
    config
        .policy
        .grants
        .iter_mut()
        .find(|g| g.service == "gitlab")
        .unwrap()
        .resources = resources;
    validate_broker_config(&config).unwrap();

    config.credentials.per_user.insert(
        "gitlab".to_string(),
        jira_per_user_credential("/tmp/gitlab-user-credentials.json"),
    );
    let resources = select_resources(
        &mut config,
        GIT_REPOSITORY_RESOURCE.id().clone(),
        &[ResourceSelector::All],
    );
    config.policy.grants.push(PolicyGrantConfig {
        subjects: vec!["group:anonymous".to_string()],
        service: "gitlab".to_string(),
        actions: vec!["project.view".to_string()],
        resources,
        execution_contexts: Some(vec!["default".to_string()]),
        credential_mode: "per_user".to_string(),
        priority: None,
    });
    let errors = validation_errors(validate_broker_config(&config));
    assert_contains(&errors, "overlapping repository scope values");
}

#[test]
fn gitlab_rest_provider_validates_page_limit_and_project_allowlist() {
    let mut config = sample_broker();
    let gitlab = config
        .providers
        .get_mut::<agent_access_gitlab::GitlabProviderConfig>()
        .unwrap();
    gitlab.search.max_results = 101;
    let errors = validation_errors(validate_broker_config(&config));
    assert_contains(
        &errors,
        "providers.gitlab.search.max_results must be less than or equal to 100",
    );

    let mut config = sample_broker();
    let gitlab = config
        .providers
        .get_mut::<agent_access_gitlab::GitlabProviderConfig>()
        .unwrap();
    gitlab.allowed_upstream_hosts = vec!["https://gitlab.example.com/api/v4/user".to_string()];
    let errors = validation_errors(validate_broker_config(&config));
    assert_contains(
        &errors,
        "providers.gitlab.allowed_upstream_hosts must include providers.gitlab.api_base_url path prefix",
    );

    let mut config = sample_broker();
    let gitlab = config
        .providers
        .get_mut::<agent_access_gitlab::GitlabProviderConfig>()
        .unwrap();
    gitlab.content.max_body_bytes = 0;
    let errors = validation_errors(validate_broker_config(&config));
    assert_contains(
        &errors,
        "providers.gitlab.content.max_body_bytes must be non-zero",
    );

    let mut config = sample_broker();
    config.limits.max_http_body_bytes = 1024;
    let gitlab = config
        .providers
        .get_mut::<agent_access_gitlab::GitlabProviderConfig>()
        .unwrap();
    gitlab.content.max_body_bytes = 1025;
    let errors = validation_errors(validate_broker_config(&config));
    assert_contains(
        &errors,
        "providers.gitlab.content.max_body_bytes must be less than or equal to limits.max_http_body_bytes",
    );

    let mut config = sample_broker();
    let gitlab = config
        .providers
        .get_mut::<agent_access_gitlab::GitlabProviderConfig>()
        .unwrap();
    gitlab.content.max_commit_actions = 0;
    let errors = validation_errors(validate_broker_config(&config));
    assert_contains(
        &errors,
        "providers.gitlab.content.max_commit_actions must be non-zero",
    );

    let mut config = sample_broker();
    let gitlab = config
        .providers
        .get_mut::<agent_access_gitlab::GitlabProviderConfig>()
        .unwrap();
    gitlab.content.max_commit_actions = 101;
    let errors = validation_errors(validate_broker_config(&config));
    assert_contains(
        &errors,
        "providers.gitlab.content.max_commit_actions must be less than or equal to 100",
    );

    let mut config = sample_broker();
    let gitlab = config
        .providers
        .get_mut::<agent_access_gitlab::GitlabProviderConfig>()
        .unwrap();
    gitlab.content.max_file_bytes = 0;
    let errors = validation_errors(validate_broker_config(&config));
    assert_contains(
        &errors,
        "providers.gitlab.content.max_file_bytes must be non-zero",
    );

    let mut config = sample_broker();
    config.limits.max_http_body_bytes = 1024;
    let gitlab = config
        .providers
        .get_mut::<agent_access_gitlab::GitlabProviderConfig>()
        .unwrap();
    gitlab.content.max_file_bytes = 1025;
    let errors = validation_errors(validate_broker_config(&config));
    assert_contains(
        &errors,
        "providers.gitlab.content.max_file_bytes must be less than or equal to limits.max_http_body_bytes",
    );

    let mut config = sample_broker();
    let gitlab = config
        .providers
        .get_mut::<agent_access_gitlab::GitlabProviderConfig>()
        .unwrap();
    gitlab.content.max_raw_download_bytes = 0;
    let errors = validation_errors(validate_broker_config(&config));
    assert_contains(
        &errors,
        "providers.gitlab.content.max_raw_download_bytes must be non-zero",
    );

    let mut config = sample_broker();
    config.limits.max_download_bytes = 1024;
    let gitlab = config
        .providers
        .get_mut::<agent_access_gitlab::GitlabProviderConfig>()
        .unwrap();
    gitlab.content.max_raw_download_bytes = 1025;
    let errors = validation_errors(validate_broker_config(&config));
    assert_contains(
        &errors,
        "providers.gitlab.content.max_raw_download_bytes must be less than or equal to limits.max_download_bytes",
    );
}

#[test]
fn gitlab_webhook_destination_policy_is_optional_and_strictly_validated() {
    let config = sample_broker();
    assert!(
        config
            .providers
            .get::<agent_access_gitlab::GitlabProviderConfig>()
            .unwrap()
            .webhooks
            .allowed_destinations
            .is_empty()
    );
    validate_broker_config(&config).unwrap();

    let mut config = sample_broker();
    config
        .providers
        .get_mut::<agent_access_gitlab::GitlabProviderConfig>()
        .unwrap()
        .webhooks
        .allowed_destinations = vec![
        "https://hooks.example.com/gitlab/**".to_string(),
        "http://hooks.internal.example/**".to_string(),
        // Distinct nondefault ports are distinct destinations.
        "https://hooks.example.com:8443/gitlab/**".to_string(),
        "https://hooks.example.com:9443/gitlab/**".to_string(),
    ];
    validate_broker_config(&config).unwrap();

    let mut config = sample_broker();
    config
        .providers
        .get_mut::<agent_access_gitlab::GitlabProviderConfig>()
        .unwrap()
        .webhooks
        .allowed_destinations = vec![
        "ftp://hooks.example.com/**".to_string(),
        "https://*.example.com/**".to_string(),
        "https://user:pass@hooks.example.com/**".to_string(),
        "https://hooks.example.com/**?tenant=one".to_string(),
        "https://hooks.example.com/**#fragment".to_string(),
        "https://hooks.example.com/git*lab".to_string(),
    ];
    let errors = validation_errors(validate_broker_config(&config));
    assert_contains(&errors, "must use http or https");
    assert_contains(&errors, "must not wildcard the host");
    assert_contains(&errors, "must not include credentials");
    assert_contains(&errors, "must not include a query");
    assert_contains(&errors, "must not include a fragment");
    assert_contains(&errors, "has invalid wildcard path segment git*lab");

    let mut config = sample_broker();
    config
        .providers
        .get_mut::<agent_access_gitlab::GitlabProviderConfig>()
        .unwrap()
        .webhooks
        .allowed_destinations = vec![
        "https://HOOKS.example.com:443/gitlab/**".to_string(),
        "https://hooks.example.com/gitlab/**".to_string(),
    ];
    let errors = validation_errors(validate_broker_config(&config));
    assert_contains(&errors, "contains duplicate normalized entry");
}

#[test]
fn policy_toml_supports_typed_resource_catalog_and_references() {
    let raw = r#"
[deployment]
environment = "development"
[identity]
mode = "anonymous"
authority = "toml"
[credentials.service.gitlab_git]
type = "bearer_token"
token_ref = "env:GITLAB_SERVICE_TOKEN"
[gateways.gitlab_git]
kind = "git_http"
display_name = "GitLab Git"
broker_hosts = ["git.example.test"]
upstream_base_url = "https://gitlab.example.com"
allowed_upstream_hosts = ["https://gitlab.example.com/**"]
auth_modes = ["basic_broker_token"]
credential_modes = ["service"]
[gateways.gitlab_git.git]
allow_fetch = true
allow_push = true
deny_ref_patterns = ["refs/heads/main"]
[policy]
authority = "toml"
default_decision = "deny"
[[policy.resources]]
id = "repository"
resource_type = "git_repository"
selector = { kind = "exact", value = "sip/service" }
allowed_execution_contexts = ["default"]
[[policy.resources]]
id = "namespace"
resource_type = "git_repository"
selector = { kind = "namespace", value = "sip/platform" }
allowed_execution_contexts = ["default"]
[[policy.resource_groups]]
id = "repositories"
name = "Repositories"
included_resource_ids = ["repository", "namespace"]
[[policy.grants]]
subjects = ["group:anonymous"]
service = "gitlab_git"
actions = ["repo.fetch", "repo.push"]
credential_mode = "service"
resources = { resource_group_ids = ["repositories"] }

[limits]
upload_spool_dir = "upload-spool"
"#;
    let config: BrokerConfig = parse_test_config(raw).unwrap();
    validate_broker_config(&config).unwrap();
    assert!(
        config.gateways["gitlab_git"]
            .git
            .as_ref()
            .unwrap()
            .deny_delete_refs
    );
    assert_eq!(
        config.policy.grants[0].resources.resource_group_ids,
        vec!["repositories"]
    );
    assert_eq!(config.policy.resources[0].selector, exact("sip/service"));
    assert_eq!(
        config.policy.resources[1].selector,
        namespace("sip/platform")
    );
    assert!(config.policy.resources[0].display_name.is_none());
    assert!(
        parse_test_config(&raw.replace(
            "resources = { resource_group_ids = [\"repositories\"] }",
            "resource_scopes = { repository = [\"sip/service\"] }"
        ))
        .is_err()
    );
}

#[test]
fn git_http_gateway_rejects_invalid_gateway_and_selector_shapes() {
    let with_gateway = |gateway: GatewayConfig| {
        let mut config = sample_broker();
        config.credentials.service.insert(
            "gitlab_git".to_string(),
            fake_service_credential("env:GITLAB_SERVICE_TOKEN"),
        );
        config.gateways.insert("gitlab_git".to_string(), gateway);
        let resources = select_resources(
            &mut config,
            GIT_REPOSITORY_RESOURCE.id().clone(),
            &[exact("sip/service")],
        );
        config.policy.grants.push(PolicyGrantConfig {
            subjects: vec!["group:anonymous".to_string()],
            service: "gitlab_git".to_string(),
            actions: vec!["repo.fetch".to_string()],
            resources,
            execution_contexts: Some(vec!["default".to_string()]),
            credential_mode: "service".to_string(),
            priority: None,
        });
        config
    };
    let mut gateway = git_http_gateway_config();
    gateway.broker_hosts = vec!["*.example.test".to_string()];
    let errors = validation_errors(validate_broker_config(&with_gateway(gateway)));
    assert_contains(&errors, "must be an exact DNS host");
    let mut gateway = git_http_gateway_config();
    gateway.git = None;
    let errors = validation_errors(validate_broker_config(&with_gateway(gateway)));
    assert_contains(&errors, "gateways.gitlab_git.git is required");

    let mut config = with_gateway(git_http_gateway_config());
    let last = config.policy.grants.len() - 1;
    config.policy.grants[last].resources = select_resources(
        &mut config,
        GIT_REPOSITORY_RESOURCE.id().clone(),
        &[exact("sip%65/service")],
    );
    let errors = validation_errors(validate_broker_config(&config));
    assert_contains(&errors, "selector is invalid for git_repository");
    assert!(
        serde_json::from_value::<ResourceSelector>(
            serde_json::json!({"kind":"namespace","value":"sip","repository":"sip/service"})
        )
        .is_err()
    );
}

/// The sample configuration with `gateway` as `gitlab_git`, its service
/// credential and a `repo.fetch` grant in the `default` context.
fn config_with_git_gateway(gateway: GatewayConfig) -> BrokerConfig {
    let mut config = sample_broker();
    config.credentials.service.insert(
        "gitlab_git".to_string(),
        fake_service_credential("env:GITLAB_SERVICE_TOKEN"),
    );
    config.gateways.insert("gitlab_git".to_string(), gateway);
    let resources = select_resources(
        &mut config,
        GIT_REPOSITORY_RESOURCE.id().clone(),
        &[exact("sip/service")],
    );
    config.policy.grants.push(PolicyGrantConfig {
        subjects: vec!["group:anonymous".to_string()],
        service: "gitlab_git".to_string(),
        actions: vec!["repo.fetch".to_string()],
        resources,
        execution_contexts: Some(vec!["default".to_string()]),
        credential_mode: "service".to_string(),
        priority: None,
    });
    config
}

#[test]
fn git_http_gateway_rejects_invalid_gateway_options() {
    let config_with_gateway = config_with_git_gateway;

    let mut config = config_with_gateway(git_http_gateway_config());
    let mut duplicate = git_http_gateway_config();
    duplicate.display_name = "Duplicate Git".to_string();
    duplicate.upstream_base_url = "https://duplicate.example.com".to_string();
    duplicate.allowed_upstream_hosts = vec!["https://duplicate.example.com/**".to_string()];
    config.credentials.service.insert(
        "duplicate_git".to_string(),
        fake_service_credential("env:DUPLICATE_GIT_SERVICE_TOKEN"),
    );
    config
        .gateways
        .insert("duplicate_git".to_string(), duplicate);
    let errors = validation_errors(validate_broker_config(&config));
    assert_contains(&errors, "host git.example.test is already used");

    let mut gateway = git_http_gateway_config();
    gateway.redirect_policy = "follow".to_string();
    let errors = validation_errors(validate_broker_config(&config_with_gateway(gateway)));
    assert_contains(&errors, "redirect_policy must be none");

    let mut gateway = git_http_gateway_config();
    gateway.auth_modes = vec![];
    let errors = validation_errors(validate_broker_config(&config_with_gateway(gateway)));
    assert_contains(&errors, "auth_modes must not be empty");

    let mut gateway = git_http_gateway_config();
    gateway.auth_modes = vec!["bearer_broker_token".to_string()];
    let errors = validation_errors(validate_broker_config(&config_with_gateway(gateway)));
    assert_contains(
        &errors,
        "auth_modes contains unsupported mode bearer_broker_token",
    );

    let mut gateway = git_http_gateway_config();
    gateway.credential_modes = vec!["service".to_string(), "service".to_string()];
    let errors = validation_errors(validate_broker_config(&config_with_gateway(gateway)));
    assert_contains(&errors, "credential_modes contains duplicate mode service");

    let mut gateway = git_http_gateway_config();
    gateway.credential_modes = vec!["lookup".to_string()];
    let errors = validation_errors(validate_broker_config(&config_with_gateway(gateway)));
    assert_contains(&errors, "credential_modes contains unsupported mode lookup");

    let mut gateway = git_http_gateway_config();
    gateway.request_body_max_bytes = Some(0);
    let errors = validation_errors(validate_broker_config(&config_with_gateway(gateway)));
    assert_contains(&errors, "request_body_max_bytes must be non-zero");

    let mut config = config_with_gateway(git_http_gateway_config());
    config
        .gateways
        .get_mut("gitlab_git")
        .unwrap()
        .request_body_max_bytes = Some(config.limits.max_http_body_bytes + 1);
    let errors = validation_errors(validate_broker_config(&config));
    assert_contains(
        &errors,
        "request_body_max_bytes must not exceed limits.max_http_body_bytes",
    );

    let mut config = config_with_gateway(git_http_gateway_config());
    config
        .gateways
        .get_mut("gitlab_git")
        .unwrap()
        .response_body_max_bytes = Some(config.limits.max_upstream_response_bytes + 1);
    let errors = validation_errors(validate_broker_config(&config));
    assert_contains(
        &errors,
        "response_body_max_bytes must not exceed limits.max_upstream_response_bytes",
    );

    let mut gateway = git_http_gateway_config();
    gateway.git.as_mut().unwrap().receive_pack_prefix_max_bytes = Some(0);
    let errors = validation_errors(validate_broker_config(&config_with_gateway(gateway)));
    assert_contains(&errors, "receive_pack_prefix_max_bytes must be non-zero");
}

/// `upstream_token_auth` has one table shape: `scheme` is required, and
/// `username` is required for `basic` and rejected for `bearer`.
#[test]
fn git_http_gateway_upstream_token_auth_is_one_table_shape() {
    let sample =
        std::fs::read_to_string(workspace_root().join("agent-access-broker.sample.toml")).unwrap();
    let document = |token_auth: &str| {
        format!(
            "{sample}\n[gateways.gitlab_git]\nkind = \"git_http\"\ndisplay_name = \"GitLab Git\"\nupstream_base_url = \"https://gitlab.example.com\"\n{token_auth}\n"
        )
    };
    let parsed = |token_auth: &str| {
        parse_test_config(&document(token_auth))
            .unwrap()
            .gateways
            .remove("gitlab_git")
            .unwrap()
            .upstream_token_auth
    };
    let oauth2 = GatewayUpstreamTokenAuth::Basic {
        username: "oauth2".to_string(),
    };
    assert_eq!(parsed(""), GatewayUpstreamTokenAuth::Bearer {});
    assert_eq!(
        parsed("upstream_token_auth = { scheme = \"bearer\" }"),
        GatewayUpstreamTokenAuth::Bearer {}
    );
    assert_eq!(
        parsed("upstream_token_auth = { scheme = \"basic\", username = \"oauth2\" }"),
        oauth2
    );
    assert_eq!(
        parsed(
            "[gateways.gitlab_git.upstream_token_auth]\nscheme = \"basic\"\nusername = \"oauth2\""
        ),
        oauth2
    );
    for (token_auth, expected) in [
        (
            "upstream_token_auth = { scheme = \"basic\" }",
            "missing field `username`",
        ),
        (
            "upstream_token_auth = { scheme = \"bearer\", username = \"oauth2\" }",
            "unknown field `username`",
        ),
        (
            "upstream_token_auth = { username = \"oauth2\" }",
            "missing field `scheme`",
        ),
        (
            "upstream_token_auth = { scheme = \"digest\" }",
            "unknown variant `digest`, expected `bearer` or `basic`",
        ),
        (
            "upstream_token_auth = { scheme = \"basic\", username = \"oauth2\", password = \"secret\" }",
            "unknown field `password`",
        ),
        ("upstream_token_auth = \"basic\"", "invalid type: string"),
    ] {
        let error = parse_test_config(&document(token_auth)).unwrap_err();
        assert!(
            error.to_string().contains(expected),
            "{token_auth}: expected {expected:?}, got {error}"
        );
    }
}

#[test]
fn git_http_gateway_upstream_token_auth_validates_the_basic_username() {
    let with_username = |username: &str| {
        let mut gateway = git_http_gateway_config();
        gateway.upstream_token_auth = GatewayUpstreamTokenAuth::Basic {
            username: username.to_string(),
        };
        config_with_git_gateway(gateway)
    };
    let longest = "~".repeat(64);
    for valid in ["oauth2", "service account", longest.as_str()] {
        validate_broker_config(&with_username(valid))
            .unwrap_or_else(|error| panic!("{valid:?}: {error}"));
    }
    validate_broker_config(&config_with_git_gateway(git_http_gateway_config())).unwrap();

    let too_long = "a".repeat(65);
    for (username, problem) in [
        ("", "must not be empty"),
        ("oauth:2", "must not contain a colon"),
        ("tab\tname", "must not contain control characters"),
        ("line\nbreak", "must not contain control characters"),
        ("\u{7f}", "must not contain control characters"),
        ("uni\u{e9}code", "must be printable ASCII"),
        (too_long.as_str(), "must be at most 64 characters"),
    ] {
        let errors = validation_errors(validate_broker_config(&with_username(username)));
        assert_contains(
            &errors,
            &format!("gateways.gitlab_git.upstream_token_auth.username {problem}"),
        );
    }
}

#[test]
fn managed_store_deserialization_defaults_auto_migrate_false() {
    let config = toml::from_str::<ManagedStoreConfig>(
        r#"
type = "sqlite"
path = "/var/lib/agent-access-broker/managed-store.sqlite3"
"#,
    )
    .unwrap();

    assert!(!config.auto_migrate);
}

#[test]
fn authentication_rate_limits_default_independently_of_invocation_limits() {
    let limits: LimitsConfig = toml::from_str(
        "upload_spool_dir = \"spool\"\n[invocations]\ndefault = { requests = 7, window = \"30s\" }\n",
    )
    .unwrap();
    assert_eq!(
        limits.invocations.default,
        Some(InvocationLimitConfig {
            requests: 7,
            window: "30s".into()
        })
    );
    assert_eq!(limits.auth_requests_per_principal_per_minute, 100);
    assert_eq!(limits.auth_requests_per_source_per_minute, 300);
    let configured: LimitsConfig = toml::from_str(
        "upload_spool_dir = \"spool\"\nauth_requests_per_principal_per_minute = 4\nauth_requests_per_source_per_minute = 8\n",
    )
    .unwrap();
    assert_eq!(configured.auth_requests_per_principal_per_minute, 4);
    assert_eq!(configured.auth_requests_per_source_per_minute, 8);
    assert!(configured.invocations.default.is_none());
}

/// A minimal broker configuration without a `[limits]` table.
const LIMITS_TEST_CONFIG_PREFIX: &str = r#"
[identity]
mode = "anonymous"
authority = "toml"

[policy]
authority = "toml"
default_decision = "deny"
"#;

#[test]
fn upload_spool_dir_is_required_and_other_limits_keep_their_defaults() {
    let config = parse_test_config(&format!(
        "{LIMITS_TEST_CONFIG_PREFIX}\n[limits]\nupload_spool_dir = \"relative/spool\"\n"
    ))
    .unwrap();
    validate_broker_config(&config).unwrap();
    // A relative path is kept as written; the runtime resolves it against
    // the working directory.
    assert_eq!(config.limits.upload_spool_dir, "relative/spool");
    assert_eq!(
        format!("{:?}", config.limits),
        format!("{:?}", LimitsConfig::new("relative/spool"))
    );
    let limits = LimitsConfig::new("spool");
    assert_eq!(limits.auth_requests_per_principal_per_minute, 100);
    assert_eq!(limits.auth_requests_per_source_per_minute, 300);
    assert_eq!(limits.max_concurrent_requests, 100);
    assert_eq!(limits.max_concurrent_requests_per_principal, 10);
    assert_eq!(limits.max_http_body_bytes, 512 * 1024 * 1024);
    assert_eq!(limits.max_download_bytes, 100 * 1024 * 1024);
    assert_eq!(limits.max_upstream_response_bytes, 512 * 1024 * 1024);
    assert_eq!(limits.request_timeout_ms, 30_000);
    assert_eq!(limits.request_body_timeout_ms, 300_000);
    assert_eq!(limits.streaming_idle_timeout_ms, 30_000);
    assert_eq!(limits.upload_spool_max_bytes, 2 * 1024 * 1024 * 1024);
    assert!(limits.invocations.default.is_none());
}

#[test]
fn omitted_upload_spool_dir_fails_to_parse_naming_the_field() {
    // The `[limits]` table without the setting.
    let error = parse_test_config(&format!(
        "{LIMITS_TEST_CONFIG_PREFIX}\n[limits]\nmax_concurrent_requests = 5\n"
    ))
    .unwrap_err();
    assert!(matches!(error, ConfigError::Parse { .. }), "{error:?}");
    let message = error.to_string();
    assert!(
        message.contains("missing field `upload_spool_dir`"),
        "{message}"
    );
    assert!(message.contains("[limits]"), "{message}");

    // The whole `[limits]` table, including when only nested tables are set.
    for raw in [
        LIMITS_TEST_CONFIG_PREFIX.to_string(),
        format!(
            "{LIMITS_TEST_CONFIG_PREFIX}\n[limits.invocations]\ndefault = {{ requests = 7, window = \"30s\" }}\n"
        ),
    ] {
        let error = parse_test_config(&raw).unwrap_err();
        assert!(matches!(error, ConfigError::Parse { .. }), "{error:?}");
        let message = error.to_string();
        assert!(
            message.contains("missing field `upload_spool_dir`"),
            "{raw}: {message}"
        );
    }
    let error = parse_test_config(LIMITS_TEST_CONFIG_PREFIX).unwrap_err();
    assert!(
        error
            .to_string()
            .contains("missing field `upload_spool_dir` in table `[limits]`"),
        "{error}"
    );
}

#[test]
fn empty_upload_spool_dir_parses_but_fails_validation() {
    for value in ["", " "] {
        let config = parse_test_config(&format!(
            "{LIMITS_TEST_CONFIG_PREFIX}\n[limits]\nupload_spool_dir = {value:?}\n"
        ))
        .unwrap();
        let errors = validation_errors(validate_broker_config(&config));
        assert_contains(&errors, "limits.upload_spool_dir must be non-empty");
    }
}

#[test]
fn removed_minute_budgets_and_unknown_invocation_fields_fail_to_parse() {
    for removed in [
        "requests_per_principal_per_minute = 100\n",
        "requests_per_source_per_minute = 300\n",
        "[invocations]\nburst = 5\n",
        "[invocations]\ndefault = { requests = 5, window = \"1m\", burst = 1 }\n",
        "[invocations.services.jira]\nrequests = 5\nwindow = \"1m\"\nper = \"principal\"\n",
        "[[invocations.principal_overrides]]\nprincipal = \"alice\"\nservice = \"jira\"\nrequests = 1\nwindow = \"1m\"\ntoken = \"x\"\n",
    ] {
        let error = toml::from_str::<LimitsConfig>(removed).unwrap_err();
        assert!(
            error.to_string().contains("unknown field"),
            "{removed}: {error}"
        );
    }
}

#[test]
fn invocation_limits_validate_values_services_and_overrides() {
    let mut config = sample_broker();
    config.identity.sources = vec![static_source(
        "local",
        "Authorization",
        "Bearer",
        "alice",
        vec!["env:ALICE_TOKEN".into()],
    )];
    config.identity.mode = "required".into();
    let limit = |requests: u64, window: &str| InvocationLimitConfig {
        requests,
        window: window.into(),
    };
    let entry = |principal: &str, service: &str| PrincipalInvocationLimitConfig {
        principal: principal.into(),
        service: service.into(),
        requests: 5,
        window: "1m".into(),
    };
    config.limits.invocations = InvocationLimitsConfig {
        default: Some(limit(10, "2h")),
        services: BTreeMap::from([("jira".into(), limit(20, "1m"))]),
        principal_overrides: vec![entry("alice", "jira"), entry("anonymous", "gitlab")],
    };
    validate_broker_config(&config).unwrap();
    let resolved = ConfiguredInvocationLimits::from_config(&config);
    assert_eq!(
        resolved.service_limit("jira"),
        InvocationLimit::parse(20, "1m").unwrap()
    );
    assert_eq!(
        resolved.service_limit("confluence"),
        InvocationLimit::parse(10, "2h").unwrap()
    );
    assert_eq!(
        resolved.principal_override("alice", "jira"),
        Some(InvocationLimit::parse(5, "1m").unwrap())
    );
    assert_eq!(resolved.principal_override("alice", "gitlab"), None);
    assert_eq!(
        ConfiguredInvocationLimits::from_config(&sample_broker()).service_limit("gitlab"),
        InvocationLimit::parse(100, "1m").unwrap()
    );

    let mut invalid = config.clone();
    invalid.limits.invocations = InvocationLimitsConfig {
        default: Some(limit(0, "1m")),
        services: BTreeMap::from([
            ("jira".into(), limit(1_000_001, "1m")),
            ("confluence".into(), limit(1, "2d")),
            ("gitlab".into(), limit(1, "soon")),
            ("missing".into(), limit(1, "1m")),
        ]),
        principal_overrides: vec![
            entry("alice", "jira"),
            entry("alice", "jira"),
            entry("mallory", "jira"),
            entry("alice", "missing"),
            PrincipalInvocationLimitConfig {
                window: "0s".into(),
                ..entry("anonymous", "jira")
            },
        ],
    };
    let errors = validation_errors(validate_broker_config(&invalid));
    for needle in [
        "limits.invocations.default: requests must be an integer from 1 to 1000000",
        "limits.invocations.services.jira: requests must be an integer from 1 to 1000000",
        "limits.invocations.services.confluence: window must be between 1s and 1d",
        "limits.invocations.services.gitlab: window must use the s, m, h, or d duration syntax",
        "limits.invocations.services.missing references unknown service missing",
        "limits.invocations.principal_overrides[1] duplicates the override for principal alice and service jira",
        "limits.invocations.principal_overrides[2] references unknown principal mallory",
        "limits.invocations.principal_overrides[3] references unknown service missing",
        "limits.invocations.principal_overrides[4]: window must use the s, m, h, or d duration syntax",
    ] {
        assert_contains(&errors, needle);
    }

    let mut managed = microsoft_oidc_broker();
    managed.limits.invocations.principal_overrides = vec![entry("alice", "jira")];
    managed.limits.invocations.services = BTreeMap::from([("jira".into(), limit(5, "1m"))]);
    let errors = validation_errors(validate_broker_config(&managed));
    assert_contains(
        &errors,
        "limits.invocations.principal_overrides is only valid when identity.authority = toml",
    );
    assert!(
        !errors
            .iter()
            .any(|error| error.contains("limits.invocations.services")),
        "{errors:#?}"
    );
}

#[test]
fn rejects_invalid_limits() {
    let mut config = sample_broker();
    config.limits.auth_requests_per_principal_per_minute = 0;
    config.limits.auth_requests_per_source_per_minute = 0;
    let errors = validation_errors(validate_broker_config(&config));
    assert_contains(
        &errors,
        "limits.auth_requests_per_principal_per_minute must be non-zero",
    );
    assert_contains(
        &errors,
        "limits.auth_requests_per_source_per_minute must be non-zero",
    );

    let mut config = sample_broker();
    config.limits.max_http_body_bytes = 0;
    let errors = validation_errors(validate_broker_config(&config));
    assert_contains(&errors, "limits.max_http_body_bytes must be non-zero");

    let mut config = sample_broker();
    config.limits.request_body_timeout_ms = 0;
    let errors = validation_errors(validate_broker_config(&config));
    assert_contains(&errors, "limits.request_body_timeout_ms must be non-zero");

    let mut config = sample_broker();
    config.limits.upload_spool_dir = " ".to_string();
    let errors = validation_errors(validate_broker_config(&config));
    assert_contains(&errors, "limits.upload_spool_dir must be non-empty");

    let mut config = sample_broker();
    config.limits.upload_spool_max_bytes = 0;
    let errors = validation_errors(validate_broker_config(&config));
    assert_contains(&errors, "limits.upload_spool_max_bytes must be non-zero");

    let mut config = sample_broker();
    config
        .providers
        .get_mut::<agent_access_jira::JiraProviderConfig>()
        .unwrap()
        .attachments
        .max_bytes = config.limits.max_http_body_bytes + 1;
    let errors = validation_errors(validate_broker_config(&config));
    assert_contains(&errors, "attachments.max_bytes must not exceed");
}

#[test]
fn validates_gitlab_attachment_limits() {
    for (field, value, expected) in [
        ("max_bytes", 0, "max_bytes must be non-zero"),
        ("max_total_bytes", 0, "max_total_bytes must be non-zero"),
        (
            "max_bytes",
            60 * 1024 * 1024,
            "max_bytes must not exceed providers.gitlab.attachments.max_total_bytes",
        ),
        (
            "max_total_bytes",
            513 * 1024 * 1024,
            "max_total_bytes must not exceed limits.max_http_body_bytes",
        ),
    ] {
        let mut config = sample_broker();
        let attachments = &mut config
            .providers
            .get_mut::<agent_access_gitlab::GitlabProviderConfig>()
            .unwrap()
            .attachments;
        match field {
            "max_bytes" => attachments.max_bytes = value,
            "max_total_bytes" => attachments.max_total_bytes = value,
            _ => unreachable!(),
        }
        let errors = validation_errors(validate_broker_config(&config));
        assert_contains(&errors, &format!("providers.gitlab.attachments.{expected}"));
    }
    let mut config = sample_broker();
    config
        .providers
        .get_mut::<agent_access_gitlab::GitlabProviderConfig>()
        .unwrap()
        .attachments
        .media_types = vec!["text/html".into()];
    assert!(validate_broker_config(&config).is_ok());
    config
        .providers
        .get_mut::<agent_access_gitlab::GitlabProviderConfig>()
        .unwrap()
        .attachments
        .media_types = vec!["invalid".into()];
    let errors = validation_errors(validate_broker_config(&config));
    assert_contains(
        &errors,
        "providers.gitlab.attachments.media_types contains invalid media type",
    );
}

#[test]
fn gitlab_upload_limits_do_not_impose_an_attachment_download_cap() {
    let mut config = sample_broker();
    config.providers.remove("jira");
    config.providers.remove("confluence");
    config.limits.invocations.services.remove("jira");
    config
        .policy
        .grants
        .retain(|grant| grant.service == "gitlab");
    config.limits.max_download_bytes = 1024;
    config
        .providers
        .get_mut::<agent_access_gitlab::GitlabProviderConfig>()
        .unwrap()
        .content
        .max_raw_download_bytes = 1024;
    assert!(validate_broker_config(&config).is_ok());
}

#[test]
fn gitlab_upload_limits_reject_unused_download_setting() {
    let raw = r#"
api_base_url = "https://gitlab.example.com/api/v4"
web_base_url = "https://gitlab.example.com"
[attachments]
max_download_bytes = 1024
"#;
    let error = toml::from_str::<agent_access_gitlab::GitlabProviderConfig>(raw).unwrap_err();
    assert!(
        error
            .to_string()
            .contains("unknown field `max_download_bytes`")
    );
}

#[test]
fn validates_audit_writer_queue_settings() {
    let mut config = sample_broker();
    config.audit.as_mut().unwrap().queue_capacity = 0;
    let errors = validation_errors(validate_broker_config(&config));
    assert_contains(&errors, "audit.queue_capacity must be non-zero");

    let mut config = sample_broker();
    config.audit.as_mut().unwrap().enqueue_timeout_ms = 0;
    let errors = validation_errors(validate_broker_config(&config));
    assert_contains(&errors, "audit.enqueue_timeout_ms must be non-zero");

    let mut config = sample_broker();
    config.audit.as_mut().unwrap().terminal_queue_capacity = Some(0);
    let errors = validation_errors(validate_broker_config(&config));
    assert_contains(
        &errors,
        "audit.terminal_queue_capacity must be non-zero when set",
    );

    for kind in [AuditStoreType::Jsonl, AuditStoreType::Sqlite] {
        let mut config = sample_broker();
        config.limits.max_concurrent_requests = 4;
        config.audit = Some(AuditConfig {
            terminal_queue_capacity: Some(3),
            ..AuditConfig::new(kind, "target/audit-capacity/audit")
        });
        let errors = validation_errors(validate_broker_config(&config));
        assert_contains(
            &errors,
            "audit.terminal_queue_capacity must be at least limits.max_concurrent_requests",
        );
    }

    let mut config = sample_broker();
    config.limits.max_concurrent_requests = 4;
    config.audit.as_mut().unwrap().terminal_queue_capacity = None;
    assert_eq!(
        config
            .audit
            .as_ref()
            .unwrap()
            .effective_terminal_queue_capacity(&config.limits),
        4
    );
    validate_broker_config(&config).unwrap();

    // Without [audit] there is no writer, so no terminal capacity rule.
    let mut config = sample_broker();
    config.audit = None;
    validate_broker_config(&config).unwrap();
}

const AUDIT_TEST_CONFIG_PREFIX: &str = r#"
[deployment]
environment = "development"

[identity]
mode = "anonymous"
authority = "toml"

[policy]
authority = "toml"
default_decision = "deny"

[limits]
upload_spool_dir = "upload-spool"
"#;

fn parse_audit_test_config(audit: &str) -> Result<BrokerConfig, ConfigError> {
    parse_test_config(&format!("{AUDIT_TEST_CONFIG_PREFIX}\n{audit}"))
}

#[test]
fn audit_table_requires_type_and_path() {
    let config = parse_audit_test_config("").unwrap();
    assert!(config.audit.is_none());

    let config = parse_audit_test_config(
        r#"
[audit]
type = "sqlite"
path = "/var/lib/agent-access-broker/audit/audit.sqlite"
retention_days = 7
"#,
    )
    .unwrap();
    let audit = config.audit.as_ref().unwrap();
    assert_eq!(audit.kind, AuditStoreType::Sqlite);
    assert_eq!(
        audit.path,
        "/var/lib/agent-access-broker/audit/audit.sqlite"
    );
    assert_eq!(audit.retention_days, 7);
    assert_eq!(audit.rotate_bytes, None);
    assert_eq!(audit.queue_capacity, 1024);
    assert_eq!(audit.enqueue_timeout_ms, 1000);
    assert_eq!(audit.durability, AuditDurability::Write);
    validate_broker_config(&config).unwrap();

    let config = parse_audit_test_config(
        r#"
[audit]
type = "jsonl"
path = "relative/audit.jsonl"
"#,
    )
    .unwrap();
    let audit = config.audit.as_ref().unwrap();
    assert_eq!(audit.kind, AuditStoreType::Jsonl);
    assert_eq!(audit.effective_rotate_bytes(), 100 * 1024 * 1024);
    validate_broker_config(&config).unwrap();

    for (audit, expected) in [
        ("[audit]\npath = \"audit.jsonl\"\n", "missing field `type`"),
        ("[audit]\ntype = \"jsonl\"\n", "missing field `path`"),
        (
            "[audit]\ntype = \"postgres\"\npath = \"audit\"\n",
            "unknown variant `postgres`",
        ),
        (
            "[audit]\ntype = \"jsonl\"\npath = \"audit.jsonl\"\nunexpected = true\n",
            "unknown field `unexpected`",
        ),
    ] {
        let error = parse_audit_test_config(audit).unwrap_err().to_string();
        assert!(error.contains(expected), "{audit}: {error}");
    }
}

#[test]
fn removed_audit_file_setting_is_an_unknown_field() {
    for audit in [
        "[audit]\nfile = \"audit.jsonl\"\n",
        "[audit]\ntype = \"jsonl\"\npath = \"audit.jsonl\"\nfile = \"audit.jsonl\"\n",
    ] {
        let error = parse_audit_test_config(audit).unwrap_err().to_string();
        assert!(error.contains("unknown field `file`"), "{error}");
    }
}

#[test]
fn audit_rotate_bytes_is_jsonl_only() {
    let config = parse_audit_test_config(
        r#"
[audit]
type = "sqlite"
path = "audit.sqlite"
rotate_bytes = 1048576
"#,
    )
    .unwrap();
    let errors = validation_errors(validate_broker_config(&config));
    assert_contains(
        &errors,
        "audit.rotate_bytes is valid only with audit.type = \"jsonl\"",
    );

    let config = parse_audit_test_config(
        r#"
[audit]
type = "jsonl"
path = "audit.jsonl"
rotate_bytes = 1048576
"#,
    )
    .unwrap();
    assert_eq!(
        config.audit.as_ref().unwrap().effective_rotate_bytes(),
        1048576
    );
    validate_broker_config(&config).unwrap();

    let mut config = config;
    config.audit.as_mut().unwrap().rotate_bytes = Some(0);
    let errors = validation_errors(validate_broker_config(&config));
    assert_contains(&errors, "audit.rotate_bytes must be non-zero");
}

#[test]
fn audit_path_must_not_be_the_managed_store_database() {
    let temp = tempfile::TempDir::new().unwrap();
    let store_path = temp.path().join("managed.sqlite3");
    let equivalent = temp.path().join(".").join("managed.sqlite3");
    for kind in [AuditStoreType::Sqlite, AuditStoreType::Jsonl] {
        for audit_path in [&store_path, &equivalent] {
            let mut config = sample_broker();
            config.managed_store = Some(ManagedStoreConfig {
                kind: "sqlite".to_string(),
                path: store_path.display().to_string(),
                require_registered_principal_for_invocation: false,
                auto_migrate: true,
            });
            config.audit = Some(AuditConfig::new(kind, audit_path.display().to_string()));
            let errors = validation_errors(validate_broker_config(&config));
            assert_contains(
                &errors,
                "audit.path must not be the managed_store.path database",
            );
        }
    }

    let mut config = sample_broker();
    config.audit = Some(AuditConfig::new(AuditStoreType::Jsonl, "   "));
    let errors = validation_errors(validate_broker_config(&config));
    assert_contains(&errors, "audit.path must be non-empty");
}

#[test]
fn deployment_node_id_is_optional_and_validated_offline() {
    let config = parse_test_config(
        r#"
[deployment]
environment = "development"
node_id = "broker-prod-1"

[identity]
mode = "anonymous"
authority = "toml"

[policy]
authority = "toml"
default_decision = "deny"

[limits]
upload_spool_dir = "upload-spool"
"#,
    )
    .unwrap();
    assert_eq!(config.deployment.node_id.as_deref(), Some("broker-prod-1"));
    validate_broker_config(&config).unwrap();

    let config = parse_audit_test_config("").unwrap();
    assert_eq!(config.deployment.node_id, None);
    validate_broker_config(&config).unwrap();

    for invalid in ["", "-broker", "broker 1", "broker/1", &"a".repeat(129)] {
        let mut config = sample_broker();
        config.deployment.node_id = Some(invalid.to_string());
        let errors = validation_errors(validate_broker_config(&config));
        assert_contains(
            &errors,
            "deployment.node_id must be 1 to 128 characters matching ^[A-Za-z0-9][A-Za-z0-9._-]*$",
        );
    }
}

#[test]
fn rejects_invalid_audit_durability_value() {
    let raw = r#"
[deployment]
environment = "development"

[identity]
mode = "anonymous"

[policy]
default_decision = "deny"

[audit]
type = "jsonl"
path = "audit.jsonl"
durability = "flush_eventually"

[limits]
upload_spool_dir = "upload-spool"
"#;

    let error = parse_test_config(raw).unwrap_err();

    assert!(error.to_string().contains("unknown variant"));
    assert!(error.to_string().contains("flush_eventually"));
}

#[test]
fn rejects_invalid_service_and_action_names() {
    let mut config = sample_broker();
    config.policy.grants[0].service = "Jira".to_string();
    let errors = validation_errors(validate_broker_config(&config));
    assert_contains(&errors, "service is invalid");

    let mut config = sample_broker();
    config.policy.grants[0].actions = vec!["Issue View".to_string()];
    let errors = validation_errors(validate_broker_config(&config));
    assert_contains(&errors, "action Issue View is invalid");
}

#[test]
fn rejects_static_ambiguous_grant_precedence() {
    let mut config = sample_broker();
    config.credentials.per_user.insert(
        "jira".to_string(),
        jira_per_user_credential("/etc/agent-access/jira-user-credentials.json"),
    );
    let mut duplicate = config.policy.grants[0].clone();
    duplicate.credential_mode = "per_user".to_string();
    config.policy.grants.push(duplicate);
    let errors = validation_errors(validate_broker_config(&config));
    assert_contains(&errors, "ambiguous credential mode precedence");
}

#[test]
fn rejects_static_ambiguous_grant_precedence_with_default_and_zero_priority() {
    let mut config = sample_broker();
    config.credentials.per_user.insert(
        "jira".to_string(),
        jira_per_user_credential("/etc/agent-access/jira-user-credentials.json"),
    );
    config.policy.grants[0].actions = vec!["search".to_string()];
    config.policy.grants[0].priority = None;

    let mut duplicate = config.policy.grants[0].clone();
    duplicate.credential_mode = "per_user".to_string();
    duplicate.priority = Some(0);
    config.policy.grants.push(duplicate);

    let errors = validation_errors(validate_broker_config(&config));
    assert_contains(&errors, "ambiguous credential mode precedence");
}

#[test]
fn retired_generic_http_configuration_is_rejected() {
    let raw = r#"
[identity]
mode = "anonymous"
authority = "toml"
[policy]
authority = "toml"
[http_services.github]
display_name = "GitHub"
base_url = "https://api.github.com"

[limits]
upload_spool_dir = "upload-spool"
"#;
    let error = parse_test_config(raw).unwrap_err();
    assert!(error.to_string().contains("http_services"));
}

#[test]
fn provider_read_only_metadata_is_conservative_across_action_families() {
    let services = configured_service_descriptors(&sample_broker());
    for (service, reads, mutations) in [
        (
            "jira",
            vec![
                "issue.view",
                "search",
                "comment.view",
                "comment.property.get",
                "attachment.download",
                "verify",
            ],
            vec![
                "issue.create",
                "comment.add",
                "comment.property.set",
                "attachment.add",
            ],
        ),
        (
            "confluence",
            vec![
                "page.view",
                "search",
                "blog.view",
                "page.draft.view",
                "blog.draft.verify",
                "page.footer_comment.reply.list",
                "blog.inline_comment.view",
                "page.draft.attachment.download",
            ],
            vec![
                "page.create",
                "page.draft.publish",
                "page.draft.stage",
                "page.footer_comment.reply.add",
                "attachment.add",
            ],
        ),
        (
            "gitlab",
            vec![
                "project.view",
                "issue.search",
                "merge_request.draft_note.view",
                "protected_branch.verify",
                "file.raw.download",
                "job.trace.download",
                "webhook.event.list",
                "project.access_token.view",
                "service_account.token.list",
            ],
            vec![
                "issue.create",
                "merge_request.draft_note.publish",
                "job.play",
                "webhook.test",
                "project.upload",
                "project.access_token.create",
                "service_account.member.set",
            ],
        ),
    ] {
        let descriptor = &services[service];
        for name in reads {
            assert!(
                descriptor
                    .action(name)
                    .unwrap_or_else(|| panic!("missing {service}.{name}"))
                    .read_only,
                "read {service}.{name}"
            );
        }
        for name in mutations {
            assert!(
                !descriptor
                    .action(name)
                    .unwrap_or_else(|| panic!("missing {service}.{name}"))
                    .read_only,
                "mutation {service}.{name}"
            );
        }
        for action in &descriptor.actions {
            if matches!(action.io, ActionIo::MultipartUpload { .. })
                || !action.sensitive_output_pointers.is_empty()
            {
                assert!(
                    !action.read_only,
                    "upload/secret export {}.{}",
                    service, action.action
                );
            }
        }
    }
    let services = configured_service_descriptors(&sample_cloudbees_config());
    for action in &services["cloudbees_ci"].actions {
        assert_eq!(
            action.read_only,
            action.action != "build.trigger",
            "CloudBees {}",
            action.action
        );
    }
}

#[test]
fn configured_service_descriptors_are_valid() {
    let config = sample_broker();
    let services = configured_service_descriptors(&config);
    for service in ["jira", "confluence", "gitlab"] {
        assert!(services.contains_key(service), "{service} is configured");
    }
    for descriptor in services.values() {
        descriptor.validate().unwrap();
    }
}

#[test]
fn cli_identity_http_and_browser_origins_accept_only_exact_local_hosts() {
    let mut config = CliConfig::default();
    for host in ["localhost", "127.0.0.1", "[::1]"] {
        config.service.url = format!("http://{host}:8787");
        validate_cli_config(&config).unwrap();
        let mut errors = Vec::new();
        validate_public_origin(
            "browser_auth.public_origin",
            &config.service.url,
            &mut errors,
        );
        assert!(errors.is_empty(), "{}: {errors:?}", config.service.url);
    }
    for host in [
        "127.0.0.2",
        "[::ffff:127.0.0.1]",
        "[::2]",
        "[2001:db8::1]",
        "localhost.example",
        "broker.example",
    ] {
        config.service.url = format!("http://{host}:8787");
        let errors = validation_errors(validate_cli_config(&config));
        assert_contains(&errors, "must use https for non-local broker URLs");
        let mut errors = Vec::new();
        validate_public_origin(
            "browser_auth.public_origin",
            &config.service.url,
            &mut errors,
        );
        assert_contains(&errors, "must use https for non-local origins");
    }
}

fn sample_broker() -> BrokerConfig {
    let mut config = load_broker_config(
        workspace_root().join("agent-access-broker.sample.toml"),
        &test_backend_registry(),
    )
    .unwrap();
    config.credential_encryption = Some(CredentialEncryptionConfig {
        active_key: "fixture".into(),
        keys: vec![CredentialEncryptionKeyConfig {
            id: "fixture".into(),
            provider: "env".into(),
            env: Some("TEST_CREDENTIAL_KEY".into()),
            path: None,
        }],
    });
    config
}

fn sample_cloudbees_config() -> BrokerConfig {
    let mut config = sample_broker();
    config.providers.insert(CloudbeesCiProviderConfig {
        max_log_scan_bytes: 16 * 1024 * 1024,
        controllers: BTreeMap::from([(
            "team-ci".into(),
            CloudbeesCiControllerConfig {
                base_url: "https://ci.example.com/team-ci/".into(),
                web_base_url: Some("https://ci-public.example.com/team-ci/".into()),
            },
        )]),
        egress_proxy: None,
        allowed_upstream_hosts: vec!["https://ci.example.com/team-ci/**".into()],
    });
    config
}

fn configure_execution_contexts(
    config: &mut BrokerConfig,
    allowed_values: &[&str],
    default_context: Option<&str>,
    grant_context: &str,
) {
    config.execution_context = Some(ExecutionContextConfig {
        allowed_values: allowed_values
            .iter()
            .map(|value| (*value).to_string())
            .collect(),
        default_context: default_context.map(ToString::to_string),
    });
    for grant in &mut config.policy.grants {
        grant.execution_contexts = Some(vec![grant_context.to_string()]);
    }
    for resource in &mut config.policy.resources {
        resource.allowed_execution_contexts =
            allowed_values.iter().map(|v| (*v).to_string()).collect();
    }
}

fn microsoft_oidc_broker() -> BrokerConfig {
    let mut config = sample_broker();
    config.identity.authority = "managed".to_string();
    config.identity.groups.clear();
    config.managed_store = Some(ManagedStoreConfig {
        kind: "sqlite".to_string(),
        path: "/var/lib/agent-access-broker/managed-store.sqlite3".to_string(),
        require_registered_principal_for_invocation: true,
        auto_migrate: false,
    });
    config.management.enabled = true;
    config.broker_tokens = Some(BrokerTokensConfig {
        hash_key_ref: "env:AGENT_ACCESS_BROKER_TOKEN_HASH_KEY".to_string(),
        default_agent_invoke_ttl: Some("30d".to_string()),
        default_user_manage_ttl: Some("2h".to_string()),
        default_admin_ttl: Some("2h".to_string()),
        max_self_issued_agent_invoke_ttl: Some("30d".to_string()),
        ..Default::default()
    });
    config.browser_auth.enabled = true;
    config.browser_auth.public_origin = Some("https://broker.example".to_string());
    config.browser_auth.csrf_key_ref = Some("env:AGENT_ACCESS_BROWSER_CSRF_KEY".to_string());
    config.browser_auth.local_password.enabled = true;
    config.browser_auth.local_password.pepper_ref =
        Some("env:AGENT_ACCESS_LOCAL_PASSWORD_PEPPER".to_string());
    config.browser_auth.oidc.microsoft = MicrosoftOidcConfig {
        enabled: true,
        tenant_id: Some("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee".to_string()),
        client_id: Some("11111111-2222-3333-4444-555555555555".to_string()),
        client_secret_ref: Some("env:AGENT_ACCESS_MICROSOFT_OIDC_CLIENT_SECRET".to_string()),
        flow_key_ref: Some("env:AGENT_ACCESS_MICROSOFT_OIDC_FLOW_KEY".to_string()),
        ..Default::default()
    };
    config
}

fn git_http_gateway_config() -> GatewayConfig {
    GatewayConfig {
        allow_forwarded_identity: false,
        kind: "git_http".to_string(),
        display_name: "GitLab Git".to_string(),
        broker_hosts: vec!["git.example.test".to_string()],
        upstream_base_url: "https://gitlab.example.com".to_string(),
        allowed_upstream_hosts: vec!["https://gitlab.example.com/**".to_string()],
        egress_proxy: None,
        auth_modes: vec!["basic_broker_token".to_string()],
        basic_broker_token_username: "agent-access".to_string(),
        credential_modes: vec!["service".to_string()],
        upstream_token_auth: Default::default(),
        redirect_policy: "none".to_string(),
        request_body_max_bytes: None,
        response_body_max_bytes: None,
        streaming_idle_timeout_ms: None,
        correlation_headers: true,
        git: Some(GatewayGitConfig {
            allow_fetch: true,
            allow_push: true,
            deny_ref_patterns: vec!["refs/heads/main".to_string()],
            deny_delete_refs: true,
            receive_pack_prefix_max_bytes: Some(64 * 1024),
        }),
    }
}

fn connection_per_user_credential(connection: &str) -> CredentialConfig {
    CredentialConfig {
        kind: "connection".to_string(),
        username_ref: None,
        token_ref: None,
        provider: None,
        path: None,
        read_only: None,
        connection: Some(connection.to_string()),
    }
}

fn token_connection(profile: &str) -> ConnectionConfig {
    ConnectionConfig {
        display_name: None,
        token_profile: Some(profile.to_string()),
        oauth: None,
    }
}

/// Configures `connection` and points each consumer's per-user entry at it.
fn use_connection(
    config: &mut BrokerConfig,
    id: &str,
    connection: ConnectionConfig,
    consumers: &[&str],
) {
    config
        .credentials
        .connections
        .insert(id.to_string(), connection);
    for consumer in consumers {
        config
            .credentials
            .per_user
            .insert((*consumer).to_string(), connection_per_user_credential(id));
    }
}

fn enable_test_managed_store(config: &mut BrokerConfig) {
    config.managed_store = Some(ManagedStoreConfig {
        kind: "sqlite".to_string(),
        path: "/var/lib/agent-access-broker/managed-store.sqlite3".to_string(),
        require_registered_principal_for_invocation: false,
        auto_migrate: true,
    });
}

/// Routes the sample Jira service through the Atlassian gateway with a static
/// bearer service credential.
fn use_atlassian_gateway_for_jira(config: &mut BrokerConfig) {
    config
        .providers
        .get_mut::<agent_access_jira::JiraProviderConfig>()
        .unwrap()
        .allowed_upstream_hosts
        .push(
            "https://api.atlassian.com/ex/jira/00000000-0000-0000-0000-000000000000/rest/api/3/**"
                .to_string(),
        );
    let credential = config.credentials.service.get_mut("jira").unwrap();
    credential.kind = "bearer_token".to_string();
    credential.username_ref = None;
}

fn jira_per_user_credential(path: &str) -> CredentialConfig {
    CredentialConfig {
        kind: "secret_store".to_string(),
        username_ref: None,
        token_ref: None,
        provider: Some("local_file".to_string()),
        path: Some(path.to_string()),
        read_only: None,
        connection: None,
    }
}

fn static_source(
    name: &str,
    header: &str,
    scheme: &str,
    principal: &str,
    token_refs: Vec<String>,
) -> IdentitySourceConfig {
    IdentitySourceConfig {
        name: name.to_string(),
        kind: "static_principals".to_string(),
        header: header.to_string(),
        scheme: scheme.to_string(),
        principals: vec![StaticPrincipalConfig {
            principal: principal.to_string(),
            token_refs,
        }],
    }
}

fn profile_kind(config: &BrokerConfig, service: &str, profile: &str) -> Option<&'static str> {
    configured_service_descriptors(config)
        .get(service)
        .and_then(|descriptor| descriptor.credential_profile_kind(profile))
}

fn workspace_root() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .unwrap()
        .to_path_buf()
}

fn tls_config(verify_certificates: bool, paths: &[String]) -> CliTlsConfig {
    CliTlsConfig {
        verify_certificates,
        additional_ca_cert_files: paths.to_vec(),
    }
}

fn validation_errors(result: Result<(), ConfigError>) -> Vec<String> {
    match result {
        Ok(()) => panic!("expected validation failure"),
        Err(ConfigError::Invalid { errors }) => errors,
        Err(err) => panic!("unexpected error: {err}"),
    }
}

fn config_error_messages<T>(result: Result<T, ConfigError>) -> Vec<String> {
    match result {
        Ok(_) => panic!("expected validation failure"),
        Err(ConfigError::Invalid { errors }) => errors,
        Err(err) => panic!("unexpected error: {err}"),
    }
}

fn assert_contains(errors: &[String], needle: &str) {
    assert!(
        errors.iter().any(|error| error.contains(needle)),
        "expected error containing {needle:?}, got {errors:#?}"
    );
}

#[test]
fn resource_scopes_must_bind_registered_types_and_supported_selectors() {
    let registry = crate::tests::test_resource_types();
    let mut descriptor = agent_access_fake::fake_descriptor();
    assert!(descriptor.validate_resource_types(&registry).is_empty());

    descriptor.resource_scopes.insert(
        "issue".into(),
        agent_access_provider::ResourceScopeCapabilities::new(
            agent_access_provider::ResourceType::new("jira_issue").unwrap(),
            vec!["exact".into()],
        ),
    );
    descriptor
        .resource_scopes
        .get_mut("project")
        .unwrap()
        .selectors
        .push("namespace".into());
    assert_eq!(
        descriptor.validate_resource_types(&registry),
        [
            "service fake scope issue uses unregistered resource type jira_issue",
            "service fake scope project offers selector namespace that resource type fake_project does not support",
        ]
    );
}

const MINIMAL_BROKER_CONFIG: &str = r#"
[deployment]
environment = "development"

[identity]
mode = "anonymous"
authority = "toml"

[policy]
authority = "toml"
default_decision = "deny"

[limits]
upload_spool_dir = "upload-spool"
"#;

#[test]
fn provider_tables_for_unregistered_backends_fail_to_parse_with_their_position() {
    let raw = format!("{MINIMAL_BROKER_CONFIG}\n[providers.outlook]\ntenant = \"example\"\n");
    let error = parse_test_config(&raw).unwrap_err().to_string();
    assert!(
        error.contains(
            "unknown provider `outlook`, expected one of `jira`, `confluence`, `gitlab`, `cloudbees_ci`, `fake`, `oauth_stub`"
        ),
        "{error}"
    );
    assert!(error.contains("TOML parse error at line"), "{error}");
    assert!(error.contains("| [providers.outlook]"), "{error}");
}

#[test]
fn provider_table_fields_are_parsed_strictly_with_their_position() {
    let raw = format!(
        "{MINIMAL_BROKER_CONFIG}\n[providers.jira]\ntenant_host = \"example.atlassian.net\"\nallowed_upstream_hosts = [\"https://example.atlassian.net/rest/api/3/**\"]\nunexpected = true\n"
    );
    let error = parse_test_config(&raw).unwrap_err().to_string();
    assert!(error.contains("unknown field `unexpected`"), "{error}");
    assert!(error.contains("| unexpected = true"), "{error}");

    let error = parse_test_config(&format!("providers = 1\n{MINIMAL_BROKER_CONFIG}"))
        .unwrap_err()
        .to_string();
    assert!(
        error.contains("a table of provider configurations"),
        "{error}"
    );
}

#[test]
fn parsed_provider_tables_resolve_to_their_backend_configs() {
    let raw = format!(
        "{MINIMAL_BROKER_CONFIG}\n[providers.jira]\ntenant_host = \"example.atlassian.net\"\nallowed_upstream_hosts = [\"https://example.atlassian.net/rest/api/3/**\"]\n"
    );
    let mut config = parse_test_config(&raw).unwrap();
    assert_eq!(
        config
            .providers
            .iter()
            .map(|backend| backend.kind())
            .collect::<Vec<_>>(),
        ["jira"]
    );
    let shared = config.clone();
    config
        .providers
        .get_mut::<agent_access_jira::JiraProviderConfig>()
        .unwrap()
        .tenant_host = "other.atlassian.net".to_string();
    assert_eq!(
        config
            .providers
            .get::<agent_access_jira::JiraProviderConfig>()
            .unwrap()
            .tenant_host,
        "other.atlassian.net"
    );
    assert_eq!(
        shared
            .providers
            .get::<agent_access_jira::JiraProviderConfig>()
            .unwrap()
            .tenant_host,
        "example.atlassian.net",
        "mutating one configuration must not change its clones"
    );
}

#[test]
fn development_backends_require_the_fake_service_opt_in() {
    let raw = format!("{MINIMAL_BROKER_CONFIG}\n[providers.fake]\n");
    let config = parse_test_config(&raw).unwrap();
    assert_contains(
        validate_broker_config(&config).unwrap_err().errors(),
        "providers.fake is a development backend and requires deployment.enable_fake_service",
    );

    let enabled = raw.replace(
        "environment = \"development\"",
        "environment = \"development\"\nenable_fake_service = true",
    );
    validate_broker_config(&parse_test_config(&enabled).unwrap()).unwrap();
}

#[test]
fn the_oauth_records_fixture_is_configured_explicitly_and_only_in_development() {
    let enabled = MINIMAL_BROKER_CONFIG.replace(
        "environment = \"development\"",
        "environment = \"development\"\nenable_fake_service = true",
    );
    // A delegated binding alone no longer creates the records service.
    let binding = "\n[credentials.connections.oauth_stub]\noauth = { registration = \"stub\", profile = \"read\" }\n[credentials.per_user.oauth_stub]\ntype = \"connection\"\nconnection = \"oauth_stub\"\n";
    let config = parse_test_config(&format!("{enabled}{binding}")).unwrap();
    assert!(!configured_service_descriptors(&config).contains_key("oauth_stub"));
    assert_contains(
        validate_broker_config(&config).unwrap_err().errors(),
        "credentials.per_user.oauth_stub uses a credential connection, but oauth_stub is not a configured service",
    );

    let table = "\n[providers.oauth_stub]\nbase_url = \"http://127.0.0.1:8099\"\n";
    let config = parse_test_config(&format!("{enabled}{table}")).unwrap();
    validate_broker_config(&config).unwrap();
    let descriptor = &configured_service_descriptors(&config)["oauth_stub"];
    assert!(descriptor.credentials.delegated.is_some());

    let disabled = parse_test_config(&format!("{MINIMAL_BROKER_CONFIG}{table}")).unwrap();
    assert_contains(
        validate_broker_config(&disabled).unwrap_err().errors(),
        "providers.oauth_stub is a development backend and requires deployment.enable_fake_service",
    );
    let mut production = config.clone();
    production.deployment.environment = "production".into();
    assert_contains(
        validate_broker_config(&production).unwrap_err().errors(),
        "deployment.enable_fake_service is not allowed in production",
    );

    let named = table.replace("127.0.0.1", "localhost");
    let config = parse_test_config(&format!("{enabled}{named}")).unwrap();
    assert_contains(
        validate_broker_config(&config).unwrap_err().errors(),
        "providers.oauth_stub.base_url must be an http or https literal-IP loopback URL",
    );
    let unknown = format!("{enabled}{table}allow_insecure_loopback = true\n");
    assert!(parse_test_config(&unknown).is_err());
    assert!(parse_test_config(&format!("{enabled}\n[providers.oauth_stub]\n")).is_err());
}

#[test]
fn programmatic_provider_configs_must_name_registered_backends() {
    let mut config = parse_test_config(MINIMAL_BROKER_CONFIG).unwrap();
    config.providers = ProvidersConfig::default().with(FakeProviderConfig::default());
    config.deployment.enable_fake_service = true;
    assert_contains(
        validate_broker_config(&config).unwrap_err().errors(),
        "providers.fake is not a backend this broker supports",
    );
}

#[test]
fn backend_registries_reject_conflicting_registrations() {
    static SHADOW_FAKE: BackendRegistration = BackendRegistration::new(
        agent_access_provider::module_metadata!(),
        "fake",
        parse_backend_config::<FakeProviderConfig>,
    )
    .development_only();
    static SECOND_JIRA_TYPES: BackendRegistration = BackendRegistration::new(
        agent_access_provider::module_metadata!(),
        "jira_mirror",
        parse_backend_config::<agent_access_jira::JiraProviderConfig>,
    )
    .with_resource_types(&[&agent_access_jira::JIRA_PROJECT_RESOURCE]);
    let errors = BackendRegistry::new([&FAKE_BACKEND, &SHADOW_FAKE]).unwrap_err();
    assert_eq!(errors, ["backend kind fake is registered more than once"]);
    let errors =
        BackendRegistry::new([&agent_access_jira::JIRA_BACKEND, &SECOND_JIRA_TYPES]).unwrap_err();
    assert_eq!(
        errors,
        ["resource type jira_project is registered more than once"]
    );
}

#[test]
fn backend_registries_give_each_domain_reason_one_owner() {
    // A second module whose kind normalizes to the CloudBees prefix may
    // register its own codes, but never one CloudBees already owns.
    static SAME_PREFIX_CODE: agent_access_provider::ProviderReasonDefinition =
        agent_access_provider::ProviderReasonDefinition::deny(
            "cloudbees_ci_log_chunk_exceeded",
            agent_access_provider::ProviderFailureStatus::ContentTooLarge,
        );
    static OWN_CODE: agent_access_provider::ProviderReasonDefinition =
        agent_access_provider::ProviderReasonDefinition::error(
            "cloudbees_ci_queue_frozen",
            agent_access_provider::ProviderFailureStatus::ServiceUnavailable,
        );
    static SAME_PREFIX: BackendRegistration = BackendRegistration::new(
        agent_access_provider::module_metadata!(),
        "cloudbees-ci",
        parse_backend_config::<FakeProviderConfig>,
    )
    .with_domain_reasons(&[&OWN_CODE]);
    static CONFLICTING: BackendRegistration = BackendRegistration::new(
        agent_access_provider::module_metadata!(),
        "cloudbees-ci",
        parse_backend_config::<FakeProviderConfig>,
    )
    .with_domain_reasons(&[&SAME_PREFIX_CODE]);
    let registry = BackendRegistry::new([&CLOUDBEES_CI_BACKEND, &SAME_PREFIX]).unwrap();
    let cloudbees = registry.get("cloudbees_ci").unwrap();
    assert!(cloudbees.declares_domain_reason(&CLOUDBEES_CI_LOG_CHUNK_EXCEEDED));
    assert!(cloudbees.declares_domain_reason(&SAME_PREFIX_CODE));
    assert!(!cloudbees.declares_domain_reason(&OWN_CODE));
    assert!(!cloudbees.declares_domain_reason(
        &agent_access_provider::ProviderReasonDefinition::error(
            "cloudbees_ci_log_chunk_exceeded",
            agent_access_provider::ProviderFailureStatus::ContentTooLarge,
        )
    ));
    assert_eq!(
        BackendRegistry::new([&CLOUDBEES_CI_BACKEND, &CONFLICTING]).unwrap_err(),
        [
            "domain reason cloudbees_ci_log_chunk_exceeded is declared by backend kinds \
             cloudbees_ci and cloudbees-ci"
        ]
    );
}

#[test]
fn cloudbees_log_limits_are_its_own_deny_413_reasons() {
    assert_eq!(
        CLOUDBEES_CI_BACKEND
            .domain_reasons()
            .iter()
            .map(|reason| (
                reason.code(),
                reason.decision(),
                reason.status().as_u16(),
                cli_exit_code_for_http_status(reason.status().as_u16()),
            ))
            .collect::<Vec<_>>(),
        [
            ("cloudbees_ci_log_chunk_exceeded", Decision::Deny, 413, 2),
            ("cloudbees_ci_log_scan_exceeded", Decision::Deny, 413, 2),
        ]
    );
    for reason in CLOUDBEES_CI_BACKEND.domain_reasons() {
        assert!(
            ReasonCodeId::new(reason.code())
                .unwrap()
                .standard()
                .is_none()
        );
    }
}

#[test]
fn resource_types_follow_backend_registration_order() {
    let ids = test_resource_types()
        .ids()
        .map(|id| id.as_str().to_string())
        .collect::<Vec<_>>();
    assert_eq!(
        ids,
        [
            "git_repository",
            "jira_project",
            "confluence_space",
            "cloudbees_ci_job",
            "fake_project",
            "oauth_collection",
        ]
    );
}

#[test]
fn provider_values_that_are_not_tables_are_rejected_with_their_position() {
    for (raw, needle) in [
        (
            format!("providers = 2024-01-01\n{MINIMAL_BROKER_CONFIG}"),
            "expected a table of provider configurations",
        ),
        (
            format!("providers = 07:30:00\n{MINIMAL_BROKER_CONFIG}"),
            "expected a table of provider configurations",
        ),
        (
            format!("{MINIMAL_BROKER_CONFIG}\n[[providers.fake]]\n"),
            "a provider configuration table",
        ),
        (
            format!("{MINIMAL_BROKER_CONFIG}\n[providers]\nfake = 2024-01-01\n"),
            "expected a provider configuration table",
        ),
        (
            format!("{MINIMAL_BROKER_CONFIG}\n[providers]\njira = [1, \"x\"]\n"),
            "a provider configuration table",
        ),
    ] {
        let error = parse_test_config(&raw).unwrap_err().to_string();
        assert!(error.contains(needle), "{raw}\n{error}");
        assert!(error.contains("TOML parse error at line"), "{error}");
    }
}

#[test]
fn inline_and_dotted_provider_tables_parse_like_table_headers() {
    let enabled = MINIMAL_BROKER_CONFIG.replace(
        "environment = \"development\"",
        "environment = \"development\"\nenable_fake_service = true",
    );
    for raw in [
        format!("{enabled}\n[providers]\nfake = {{}}\n"),
        format!("providers.fake = {{}}\n{enabled}"),
    ] {
        let config = parse_test_config(&raw).unwrap();
        assert!(
            config.providers.get::<FakeProviderConfig>().is_some(),
            "{raw}"
        );
        validate_broker_config(&config).unwrap();
    }
}

#[test]
fn backend_kinds_must_be_service_names() {
    static INVALID_KIND: BackendRegistration = BackendRegistration::new(
        agent_access_provider::module_metadata!(),
        "Not A Service",
        parse_backend_config::<FakeProviderConfig>,
    )
    .development_only();
    assert_eq!(
        BackendRegistry::new([&INVALID_KIND]).unwrap_err(),
        ["backend kind Not A Service is not a valid service name"]
    );
}

#[test]
fn the_fake_service_opt_in_alone_configures_no_fake_backend() {
    let enabled = MINIMAL_BROKER_CONFIG.replace(
        "environment = \"development\"",
        "environment = \"development\"\nenable_fake_service = true",
    );
    let config = parse_test_config(&enabled).unwrap();
    assert!(config.providers.is_empty());
    assert!(!configured_service_descriptors(&config).contains_key("fake"));
}

#[test]
fn every_selected_native_kind_stays_reserved_for_gateways() {
    let gateway = |service: &str| {
        format!(
            "{MINIMAL_BROKER_CONFIG}\n[gateways.{service}]\nkind = \"git_http\"\ndisplay_name = \"Gateway\"\nbroker_hosts = [\"git.example.com\"]\nupstream_base_url = \"https://gitlab.example.com\"\nallowed_upstream_hosts = [\"https://gitlab.example.com/**\"]\n"
        )
    };
    // Development and production kinds alike, with no provider table.
    for service in ["fake", "jira", "cloudbees_ci", "oauth_stub"] {
        let config = parse_test_config(&gateway(service)).unwrap();
        assert!(config.providers.get_kind(service).is_none());
        assert_contains(
            validate_broker_config(&config).unwrap_err().errors(),
            &format!(
                "gateways.{service} collides with the selected native provider kind {service}"
            ),
        );
    }
    // A kind this build does not select stays available to a gateway.
    let config = parse_test_config(&gateway("source")).unwrap();
    assert!(validate_broker_config(&config).err().is_none_or(|error| {
        !error
            .errors()
            .iter()
            .any(|error| error.contains("collides"))
    }));
}

#[test]
fn the_broker_namespace_is_reserved_even_for_an_unconfigured_native_kind() {
    static BROKER_KIND: BackendRegistration = BackendRegistration::new(
        agent_access_provider::module_metadata!(),
        "broker",
        parse_backend_config::<FakeProviderConfig>,
    );
    assert_eq!(
        BackendRegistry::new([&FAKE_BACKEND, &BROKER_KIND]).unwrap_err(),
        ["backend kind broker is reserved for the Broker control-plane namespace"]
    );
}

#[test]
fn oauth_connections_need_consumers_that_accept_delegation() {
    let mut config = sample_broker();
    config.credentials.connections.insert(
        "records".to_string(),
        ConnectionConfig {
            display_name: None,
            token_profile: None,
            oauth: Some(ConnectionOAuthConfig {
                registration: "missing".to_string(),
                profile: "read".to_string(),
            }),
        },
    );
    config.credentials.per_user.insert(
        "records".to_string(),
        connection_per_user_credential("records"),
    );
    let delegated = |actions: Vec<ActionDescriptor>| {
        ServiceDescriptor::new("records", "Records")
            .with_actions(actions)
            .with_credentials(CredentialDescriptor::default().delegated("Read records."))
    };
    let action = |name: &str| {
        ActionDescriptor::new(name, "Read", serde_json::json!({"type": "object"}))
            .credential_modes(["per_user", "service"])
    };
    let errors = |descriptor: ServiceDescriptor| {
        let services = BTreeMap::from([("records".to_string(), Arc::new(descriptor))]);
        let mut errors = Vec::new();
        crate::connections::validate_connections(&config, &services, &mut errors);
        errors
            .into_iter()
            .filter(|error| !error.contains("configured registration"))
            .collect::<Vec<_>>()
    };

    assert!(errors(delegated(vec![action("read")])).is_empty());
    let mut static_only = delegated(vec![action("read")]);
    static_only.credentials = CredentialDescriptor::default();
    assert_eq!(
        errors(static_only),
        [
            "credentials.connections.records.oauth requires every consumer to accept delegated credentials, which records does not"
        ]
    );
    let lookups = errors(delegated(vec![
        action("read").lookup(LookupRequirement::Execution),
        action("service_read")
            .lookup(LookupRequirement::ScopeResolution)
            .credential_modes(["service"]),
    ]));
    assert_eq!(
        lookups,
        [
            "credentials.connections.records.oauth: records action read needs a per-user lookup credential, which an OAuth credential cannot provide"
        ]
    );
    // A connection is only ever a per-user credential.
    let services = BTreeMap::from([(
        "records".to_string(),
        Arc::new(delegated(vec![action("read")])),
    )]);
    let mut errors = Vec::new();
    validate_credential(
        &config,
        &services,
        "credentials.service",
        "records",
        &connection_per_user_credential("records"),
        &mut errors,
    );
    assert_eq!(
        errors,
        ["credentials.service.records.type connection is supported only for credentials.per_user"]
    );
}

#[test]
fn builtin_descriptor_validation_rejects_imported_naming_origin() {
    let mut action =
        ActionDescriptor::new("inspect", "Inspect", serde_json::json!({"type":"object"}));
    action.scoped_mcp_name_source = ScopedMcpNameSource::Imported {
        name: Some("upstream_inspect".into()),
    };
    let descriptor = ServiceDescriptor::new("fake", "Fake").with_actions(vec![action]);
    let services = BTreeMap::from([("fake".into(), Arc::new(descriptor))]);
    let mut errors = Vec::new();
    validate_service_descriptors(&services, &test_resource_types(), &mut errors);
    assert!(
        errors
            .iter()
            .any(|error| error.contains("canonical built-in MCP naming")),
        "{errors:?}"
    );
}

#[test]
fn trusted_caller_configuration_is_strict_and_context_only_callers_need_no_store() {
    let valid = format!(
        r#"{MINIMAL_BROKER_CONFIG}
[identity.trusted_callers.dispatch]
credential_ref = "file:/operator/dispatch.token"
context_mode = "asserted"
allowed_execution_contexts = ["default"]
"#
    );
    let config = parse_test_config(&valid).unwrap();
    validate_broker_config(&config).unwrap();
    for extra in ["execution_context = \"default\"", "unknown = true"] {
        let raw = format!("{valid}\n{extra}");
        assert!(
            parse_test_config(&raw)
                .and_then(|config| validate_broker_config(&config))
                .is_err()
        );
    }
    for replacement in [
        "[]",
        "[\"default\", \"default\"]",
        "[\"external\"]",
        "[\"INVALID\"]",
    ] {
        let raw = valid.replace("[\"default\"]", replacement);
        assert!(
            parse_test_config(&raw)
                .and_then(|config| validate_broker_config(&config))
                .is_err()
        );
    }
    let forwarding = format!("{valid}\nallow_forwarded_identity = true");
    assert!(validate_broker_config(&parse_test_config(&forwarding).unwrap()).is_err());
    let old = format!(
        "{MINIMAL_BROKER_CONFIG}\n[identity.managed_proxy]\ncredential_ref = \"file:/old\""
    );
    assert!(parse_test_config(&old).is_err());
    let fixed = valid.replace(
        "context_mode = \"asserted\"\nallowed_execution_contexts = [\"default\"]",
        "context_mode = \"fixed\"\nexecution_context = \"default\"",
    );
    validate_broker_config(&parse_test_config(&fixed).unwrap()).unwrap();
    let irrelevant_empty = format!("{fixed}\nallowed_execution_contexts = []");
    assert!(validate_broker_config(&parse_test_config(&irrelevant_empty).unwrap()).is_err());
    let mut required = config.clone();
    required.identity.mode = "required".into();
    required.identity.sources.clear();
    assert!(validate_broker_config(&required).is_err());
}

#[test]
fn broker_service_namespace_is_reserved_for_host_admission() {
    let mut config = parse_test_config(MINIMAL_BROKER_CONFIG).unwrap();
    config
        .gateways
        .insert("broker".into(), git_http_gateway_config());
    assert!(validate_broker_config(&config).is_err());
    let mut descriptor = agent_access_fake::fake_descriptor();
    descriptor.service = "broker".into();
    assert!(descriptor.validate().is_err());
}

#[test]
fn trusted_user_configuration_enforces_transport_namespace_and_context_contract() {
    let mut config = parse_test_config(MINIMAL_BROKER_CONFIG).unwrap();
    config.identity.authority = "managed".into();
    config.identity.mode = "required".into();
    config.managed_store = Some(ManagedStoreConfig {
        kind: "sqlite".into(),
        path: "/operator/managed.sqlite".into(),
        auto_migrate: true,
        require_registered_principal_for_invocation: false,
    });
    config.credential_encryption = Some(CredentialEncryptionConfig {
        active_key: "identity".into(),
        keys: vec![CredentialEncryptionKeyConfig {
            id: "identity".into(),
            provider: "file".into(),
            env: None,
            path: Some("/operator/identity.key".into()),
        }],
    });
    let direct: TrustedCallerConfig = toml::from_str(
        r#"
credential_ref = "file:/operator/direct.token"
credential_transport = "authorization_user"
username_namespace = "managed_linux"
context_mode = "fixed"
execution_context = "default"
"#,
    )
    .unwrap();
    config
        .identity
        .trusted_callers
        .insert("direct".into(), direct.clone());
    validate_broker_config(&config).unwrap();
    for (mutated, expected) in [
        (
            TrustedCallerConfig {
                username_namespace: None,
                ..direct.clone()
            },
            "requires username_namespace",
        ),
        (
            TrustedCallerConfig {
                username_namespace: Some("invalid namespace".into()),
                ..direct.clone()
            },
            "safe configuration identifier",
        ),
        (
            TrustedCallerConfig {
                context_mode: TrustedCallerContextMode::Asserted,
                execution_context: None,
                allowed_execution_contexts: Some(vec!["default".into()]),
                ..direct.clone()
            },
            "requires fixed context_mode",
        ),
        (
            TrustedCallerConfig {
                allow_forwarded_identity: true,
                ..direct.clone()
            },
            "forbids allow_forwarded_identity",
        ),
    ] {
        let mut invalid = config.clone();
        invalid
            .identity
            .trusted_callers
            .insert("direct".into(), mutated);
        assert_contains(
            &validation_errors(validate_broker_config(&invalid)),
            expected,
        );
    }
    let mut unmanaged = config.clone();
    unmanaged.identity.authority = "toml".into();
    assert_contains(
        &validation_errors(validate_broker_config(&unmanaged)),
        "requires managed identity and managed_store",
    );
    let mut no_store = config;
    no_store.managed_store = None;
    assert_contains(
        &validation_errors(validate_broker_config(&no_store)),
        "requires managed identity and managed_store",
    );
    assert!(
        toml::from_str::<TrustedCallerConfig>(
            r#"
credential_ref = "file:/operator/token"
credential_transport = "both"
context_mode = "fixed"
execution_context = "default"
"#
        )
        .is_err()
    );
    let legacy: TrustedCallerConfig = toml::from_str(
        r#"
credential_ref = "file:/operator/token"
context_mode = "fixed"
execution_context = "default"
"#,
    )
    .unwrap();
    assert_eq!(
        legacy.credential_transport,
        TrustedCallerCredentialTransport::CallerAuthorization
    );
    assert!(legacy.username_namespace.is_none());
}

#[test]
fn trusted_user_header_is_reserved_and_username_grammar_is_exact() {
    for name in [
        "Alice",
        "1001",
        "anonymous",
        "a.b_c-d+e@example",
        &"a".repeat(128),
    ] {
        assert!(is_valid_identity_username(name), "valid name rejected");
    }
    for name in [
        "",
        " Alice",
        "Alice ",
        "alice,bob",
        "a/b",
        "a%2Eb",
        "a:b",
        "álîce",
        &"a".repeat(129),
    ] {
        assert!(!is_valid_identity_username(name), "invalid name accepted");
    }
    for header in ["X-Agent-Access-User", "x-agent-access-user"] {
        let mut config = parse_test_config(MINIMAL_BROKER_CONFIG).unwrap();
        config.identity.sources.push(IdentitySourceConfig {
            name: "reserved".into(),
            kind: "static_principals".into(),
            header: header.into(),
            scheme: "raw".into(),
            principals: vec![],
        });
        assert_contains(
            &validation_errors(validate_broker_config(&config)),
            "must not use reserved header x-agent-access-user",
        );
        config.identity.sources.clear();
        config.browser_auth.enabled = true;
        config.browser_auth.csrf_header = header.into();
        assert_contains(
            &validation_errors(validate_broker_config(&config)),
            "must not use reserved header x-agent-access-user",
        );
    }
}
