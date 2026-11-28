//! Values with the access-key prefix are never loaded as another kind of
//! Broker credential.
use super::*;
use crate::{TrustedCallerConfig, TrustedCallerContextMode, TrustedCallerCredentialTransport};

const ACCESS_KEY: &str = "aab_ak_A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8S9t0U1v";
const MALFORMED_ACCESS_KEY: &str = "aab_ak_reserved-but-not-a-token";

fn directory() -> TempDir {
    let directory = TempDir::new().unwrap();
    #[cfg(unix)]
    fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
    directory
}

fn load_error(config: BrokerConfig) -> String {
    match BrokerRuntime::new(config) {
        Ok(_) => panic!("a credential with the access-key prefix was loaded"),
        Err(error) => format!("{error} {error:?}"),
    }
}

#[test]
fn trusted_caller_credentials_cannot_use_the_access_key_prefix_on_either_transport() {
    for value in [ACCESS_KEY, MALFORMED_ACCESS_KEY] {
        for transport in [
            TrustedCallerCredentialTransport::AuthorizationUser,
            TrustedCallerCredentialTransport::CallerAuthorization,
        ] {
            let directory = directory();
            let mut config = managed_policy_fake_config(&directory.path().join("managed.sqlite"));
            config.identity.mode = "required".into();
            let path = directory.path().join("caller.token");
            fs::write(&path, value).unwrap();
            config.identity.trusted_callers.insert(
                "proxy".into(),
                TrustedCallerConfig {
                    credential_ref: format!("file:{}", path.display()),
                    credential_transport: transport,
                    username_namespace: Some("linux".into()),
                    context_mode: TrustedCallerContextMode::Fixed,
                    execution_context: Some("default".into()),
                    allowed_execution_contexts: None,
                    allow_forwarded_identity: false,
                    allow_access_key_resolution: false,
                },
            );
            let error = load_error(config);
            assert!(error.contains("reserved"), "{error}");
            assert!(!error.contains(value), "{error}");
        }
    }
}

#[test]
fn static_principal_tokens_cannot_use_the_access_key_prefix() {
    for value in [ACCESS_KEY, MALFORMED_ACCESS_KEY] {
        let token_path = write_temp_secret(value);
        let mut config = base_fake_config();
        config.identity = static_identity_config("required", &token_path, "agent-one", Vec::new());
        let error = load_error(config);
        assert!(
            error.contains("must not use the reserved access-key prefix"),
            "{error}"
        );
        assert!(!error.contains(value), "{error}");
    }
}

#[test]
fn the_resolution_capability_is_part_of_the_caller_contract_and_admits_only_its_holder() {
    let build = |allow_access_key_resolution: bool| {
        let directory = directory();
        let mut config = managed_policy_fake_config(&directory.path().join("managed.sqlite"));
        config.identity.mode = "required".into();
        let hash_key = directory.path().join("hash.key");
        fs::write(
            &hash_key,
            base64::Engine::encode(
                &base64::engine::general_purpose::URL_SAFE_NO_PAD,
                [21_u8; 32],
            ),
        )
        .unwrap();
        config.broker_tokens = Some(BrokerTokensConfig {
            hash_key_ref: format!("file:{}", hash_key.display()),
            ..Default::default()
        });
        // Two identity sources under headers of the operator's choosing.
        config.identity.sources = ["X-Agent-Token", "X-Example-Agent-Credential"]
            .into_iter()
            .map(|header| crate::IdentitySourceConfig {
                name: header.to_ascii_lowercase(),
                kind: "broker_tokens".into(),
                header: header.into(),
                scheme: "Bearer".into(),
                principals: Vec::new(),
            })
            .collect();
        for (name, secret, capable) in [
            (
                "proxy",
                "proxy-caller-credential-0123456789",
                allow_access_key_resolution,
            ),
            ("relay", "relay-caller-credential-0123456789", false),
        ] {
            let path = directory.path().join(format!("{name}.token"));
            fs::write(&path, secret).unwrap();
            config.identity.trusted_callers.insert(
                name.into(),
                TrustedCallerConfig {
                    credential_ref: format!("file:{}", path.display()),
                    credential_transport: TrustedCallerCredentialTransport::CallerAuthorization,
                    username_namespace: Some("linux".into()),
                    context_mode: TrustedCallerContextMode::Fixed,
                    execution_context: Some("default".into()),
                    allowed_execution_contexts: None,
                    allow_forwarded_identity: false,
                    allow_access_key_resolution: capable,
                },
            );
        }
        (BrokerRuntime::new(config).unwrap(), directory)
    };
    let (with, _with_directory) = build(true);
    let (without, _without_directory) = build(false);
    // Granting or withdrawing the capability changes the caller's contract,
    // which advances the caller security epoch at publication.
    assert_ne!(
        with.caller_security_binding(),
        without.caller_security_binding()
    );

    let headers = |pairs: &[(&str, &str)]| {
        let mut headers = HeaderMap::new();
        for (name, value) in pairs {
            headers.append(
                http::header::HeaderName::from_bytes(name.as_bytes()).unwrap(),
                value.parse().unwrap(),
            );
        }
        headers
    };
    let caller = "x-agent-access-caller-authorization";
    assert_eq!(
        with.authenticate_access_key_resolution_caller(&headers(&[(
            caller,
            "Bearer proxy-caller-credential-0123456789"
        )])),
        Ok("proxy".to_string())
    );
    // A refusal names a configured caller only when its credential was
    // presented and the capability alone is missing.
    for (pairs, failure, matched) in [
        (vec![], IdentityFailure::CallerAuthenticationRequired, None),
        (
            vec![(caller, "Bearer relay-caller-credential-0123456789")],
            IdentityFailure::CallerAccessKeyResolutionDenied,
            Some("relay"),
        ),
        (
            vec![(caller, "Bearer unknown-caller-credential-0123456789")],
            IdentityFailure::CallerAuthenticationInvalid,
            None,
        ),
        (
            vec![(caller, "proxy-caller-credential-0123456789")],
            IdentityFailure::CallerAuthenticationInvalid,
            None,
        ),
        (
            vec![
                (caller, "Bearer proxy-caller-credential-0123456789"),
                (caller, "Bearer proxy-caller-credential-0123456789"),
            ],
            IdentityFailure::CallerAuthenticationInvalid,
            None,
        ),
        // The credential is a caller credential only in its own header.
        (
            vec![("authorization", "Bearer proxy-caller-credential-0123456789")],
            IdentityFailure::CallerAuthenticationRequired,
            None,
        ),
        (
            vec![
                (caller, "Bearer proxy-caller-credential-0123456789"),
                ("connection", "x-agent-access-caller-authorization"),
            ],
            IdentityFailure::AssertionInvalid,
            None,
        ),
    ] {
        assert_eq!(
            with.authenticate_access_key_resolution_caller(&headers(&pairs)),
            Err(AccessKeyResolutionCallerRefusal {
                failure,
                caller: matched.map(str::to_string),
            })
        );
    }
    assert_eq!(
        without.authenticate_access_key_resolution_caller(&headers(&[(
            caller,
            "Bearer proxy-caller-credential-0123456789"
        )])),
        Err(AccessKeyResolutionCallerRefusal {
            failure: IdentityFailure::CallerAccessKeyResolutionDenied,
            caller: Some("proxy".to_string()),
        })
    );
    // Every header under which the configuration accepts or asserts an
    // identity is forbidden: the identity sources it configures, read from
    // it, and the fixed carriers.
    let configured = with
        .config()
        .identity
        .sources
        .iter()
        .map(|source| source.header.clone())
        .collect::<Vec<_>>();
    assert_eq!(configured, ["X-Agent-Token", "X-Example-Agent-Credential"]);
    for name in configured.iter().map(String::as_str).chain([
        "authorization",
        "cookie",
        "x-aw-identity-token-sha256",
        "x-agent-access-user",
        "x-agent-access-context",
    ]) {
        assert_eq!(
            with.access_key_resolution_forbidden_header(&headers(&[(name, "value")])),
            Some(name.to_ascii_lowercase()),
            "{name}"
        );
    }
    for name in ["content-type", "x-agent-access-request-id", caller] {
        assert_eq!(
            with.access_key_resolution_forbidden_header(&headers(&[(name, "value")])),
            None,
            "{name}"
        );
    }
}

#[test]
fn startup_and_reload_refuse_to_drop_an_access_key_type_a_saved_setting_names() {
    let directory = directory();
    let mut config = managed_policy_fake_config(&directory.path().join("managed.sqlite"));
    config.identity.mode = "required".into();
    let hash_key = directory.path().join("hash.key");
    fs::write(
        &hash_key,
        base64::Engine::encode(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD,
            [21_u8; 32],
        ),
    )
    .unwrap();
    config.broker_tokens = Some(BrokerTokensConfig {
        hash_key_ref: format!("file:{}", hash_key.display()),
        ..Default::default()
    });
    config.identity.sources = vec![crate::IdentitySourceConfig {
        name: "broker".into(),
        kind: "broker_tokens".into(),
        header: "X-Agent-Token".into(),
        scheme: "Bearer".into(),
        principals: Vec::new(),
    }];
    for id in ["inference", "web-search"] {
        config.access_key_types.insert(
            id.into(),
            crate::AccessKeyTypeConfig {
                display_name: id.into(),
                description: None,
                lifetime_options: vec!["1h".into(), "30d".into()],
                default_lifetime: "30d".into(),
                self_service: true,
            },
        );
    }
    let without = |id: &str| {
        let mut config = config.clone();
        config.access_key_types.remove(id);
        config
    };
    let refusal = |result: Result<BrokerRuntime, RuntimeError>| match result {
        Err(RuntimeError::Config(crate::ConfigError::Invalid { errors })) => errors,
        Err(other) => panic!("the refusal is the configuration's: {other}"),
        Ok(_) => panic!("a type a saved setting names was dropped"),
    };

    // A robot may hold `web-search` and has a key of it; a group allows it.
    let running = BrokerRuntime::new(config.clone()).unwrap();
    let store = running.managed_store().unwrap().clone();
    let contexts = crate::ConfiguredExecutionContexts::from_config(None).unwrap();
    store
        .create_principal(
            crate::PrincipalWriteRequest {
                principal_id: "robot".into(),
                kind: "service_account".into(),
                display_name: None,
                email: None,
                external_subject: None,
                created_by: "admin".into(),
                role: crate::PrincipalRole::User,
                self_service_enabled: Some(false),
                agent_token_issuance: Default::default(),
            },
            &contexts,
        )
        .unwrap();
    let setting = crate::PrincipalAccessKeyTypes::new(vec!["web-search".into()], vec![]).unwrap();
    store
        .patch_principal_access_with_access_key_types(
            crate::PrincipalAccessPatchRequest {
                agent_token_issuance: None,
                principal_id: "robot".into(),
                role: None,
                self_service_enabled: None,
                actor: "admin".into(),
            },
            Some(crate::AccessKeyTypesWrite {
                setting: &setting,
                configured: running.access_key_types(),
            }),
            &contexts,
        )
        .unwrap();
    store
        .create_group_with_access(
            crate::GroupWriteRequest {
                group_id: "platform".into(),
                display_name: None,
                description: None,
                auto_enroll_new_microsoft_users: false,
                agent_token_issuance: Default::default(),
                created_by: "admin".into(),
            },
            Some(crate::AccessKeyTypesWrite {
                setting: &crate::GroupAccessKeyTypes::new(vec!["web-search".into()]).unwrap(),
                configured: running.access_key_types(),
            }),
            &contexts,
        )
        .unwrap();
    let issued = store
        .mint_administrator_access_key(
            running.broker_token_hasher().unwrap(),
            running.access_key_types(),
            &crate::AdministratorAccessKeyRequest {
                principal_id: "robot".into(),
                name: "nightly".into(),
                access_key_types: vec!["web-search".into()],
                lifetime: "3600s".into(),
                created_by: "admin".into(),
            },
        )
        .unwrap()
        .unwrap();
    assert!(running.resolve_access_key(&issued.key).unwrap().is_active());

    // A reload and a startup with the type removed are both refused, by the
    // configuration, in words that say what stands in the way and what to
    // do: nothing about the store being unavailable or needing a migration.
    let expected = "access key type web-search is not in [access_key_types] and is still named by \
        1 account setting (robot) and 1 group setting (platform); 1 unexpired access key carries \
        it. Take it out of those settings, or keep its table, then reload or start again: see \
        \"Retire an access key type\" in the administrator guide";
    assert_eq!(
        refusal(BrokerRuntime::new_for_reload(
            without("web-search"),
            &running
        )),
        [expected]
    );
    // The running generation is untouched by the refused reload.
    assert!(running.resolve_access_key(&issued.key).unwrap().is_active());
    drop(store);
    drop(running);
    assert_eq!(
        refusal(BrokerRuntime::new(without("web-search"))),
        [expected]
    );
    // A type nobody's setting names goes without a word.
    BrokerRuntime::new(without("inference")).unwrap();

    // With the settings cleared the type retires at startup and at reload.
    // The key that carried only that type stays, holds nothing, and holds
    // the type again once the type and the setting are back.
    let running = BrokerRuntime::new(config.clone()).unwrap();
    let store = running.managed_store().unwrap().clone();
    let cleared = crate::PrincipalAccessKeyTypes::new(vec![], vec![]).unwrap();
    store
        .patch_principal_access_with_access_key_types(
            crate::PrincipalAccessPatchRequest {
                agent_token_issuance: None,
                principal_id: "robot".into(),
                role: None,
                self_service_enabled: None,
                actor: "admin".into(),
            },
            Some(crate::AccessKeyTypesWrite {
                setting: &cleared,
                configured: running.access_key_types(),
            }),
            &contexts,
        )
        .unwrap();
    store
        .patch_group_with_access(
            crate::GroupPatchRequest {
                group_id: "platform".into(),
                display_name: None,
                description: None,
                status: None,
                auto_enroll_new_microsoft_users: None,
                agent_token_issuance: None,
                updated_by: "admin".into(),
            },
            Some(crate::AccessKeyTypesWrite {
                setting: &crate::GroupAccessKeyTypes::new(vec![]).unwrap(),
                configured: running.access_key_types(),
            }),
            &contexts,
        )
        .unwrap();
    let retired = BrokerRuntime::new_for_reload(without("web-search"), &running).unwrap();
    assert!(!retired.resolve_access_key(&issued.key).unwrap().is_active());
    drop(retired);
    drop(store);
    drop(running);
    let restarted = BrokerRuntime::new(without("web-search")).unwrap();
    assert!(
        !restarted
            .resolve_access_key(&issued.key)
            .unwrap()
            .is_active()
    );
    drop(restarted);
    let restored = BrokerRuntime::new(config).unwrap();
    assert!(
        !restored
            .resolve_access_key(&issued.key)
            .unwrap()
            .is_active()
    );
    restored
        .managed_store()
        .unwrap()
        .patch_principal_access_with_access_key_types(
            crate::PrincipalAccessPatchRequest {
                agent_token_issuance: None,
                principal_id: "robot".into(),
                role: None,
                self_service_enabled: None,
                actor: "admin".into(),
            },
            Some(crate::AccessKeyTypesWrite {
                setting: &setting,
                configured: restored.access_key_types(),
            }),
            &contexts,
        )
        .unwrap();
    assert!(
        restored
            .resolve_access_key(&issued.key)
            .unwrap()
            .is_active()
    );
}
