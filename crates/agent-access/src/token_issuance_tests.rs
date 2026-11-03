use super::*;

#[test]
fn token_issuance_permission_flags_accept_only_the_canonical_modes() {
    for command in [
        vec!["admin", "principals", "create", "alice"],
        vec!["admin", "principals", "access", "set", "alice"],
        vec!["admin", "groups", "create", "readers"],
        vec!["admin", "groups", "update", "readers"],
    ] {
        for value in ["inherit", "disabled", "read_only", "write_capable"] {
            let mut args = vec!["agent-access"];
            args.extend(command.iter().copied());
            args.extend(["--agent-token-issuance", value]);
            if matches!(value, "read_only" | "write_capable") {
                args.extend(["--agent-token-issuance-context", "arbitrary_context-1"]);
            }
            assert_eq!(
                Cli::try_parse_from(args).is_ok(),
                value != "inherit" || command[1] == "principals",
                "{command:?} {value}"
            );
        }
        for value in ["read-only", "write-capable", "ReadOnly", "true", "null", ""] {
            let mut args = vec!["agent-access"];
            args.extend(command.iter().copied());
            args.extend(["--agent-token-issuance", value]);
            assert!(Cli::try_parse_from(args).is_err(), "{command:?} {value}");
        }
    }
}

#[test]
fn issuance_context_flags_require_a_mode_and_enabled_modes_require_contexts() {
    for command in [
        vec!["admin", "principals", "create", "alice"],
        vec!["admin", "principals", "access", "set", "alice"],
        vec!["admin", "groups", "create", "readers"],
        vec!["admin", "groups", "update", "readers"],
    ] {
        let mut base = vec!["agent-access"];
        base.extend(command);
        for args in [
            vec!["--agent-token-issuance-context", "external"],
            vec!["--agent-token-issuance", "read_only"],
            vec!["--agent-token-issuance", "write_capable"],
        ] {
            assert!(Cli::try_parse_from(base.iter().copied().chain(args)).is_err());
        }
        for name in ["", "ALL", "a,b", "has space", "*", "-internal", "1internal"] {
            assert!(
                Cli::try_parse_from(base.iter().copied().chain([
                    "--agent-token-issuance",
                    "read_only",
                    "--agent-token-issuance-context",
                    name,
                ]))
                .is_err()
            );
        }
        assert!(
            Cli::try_parse_from(base.iter().copied().chain([
                "--agent-token-issuance",
                "write_capable",
                "--agent-token-issuance-context",
                "internal",
                "--agent-token-issuance-context",
                "external",
            ]))
            .is_ok()
        );
    }
}

#[test]
fn issuance_policy_payloads_are_complete_sorted_replacements_or_omitted() {
    use PrincipalAgentTokenIssuanceArg::*;
    assert_eq!(agent_token_issuance_body(None, &[]).unwrap(), None);
    for (mode, name) in [(Inherit, "inherit"), (Disabled, "disabled")] {
        assert_eq!(
            agent_token_issuance_body(Some(mode), &[]).unwrap(),
            Some(serde_json::json!({
                "mode": name, "allowedExecutionContexts": [],
            }))
        );
        assert!(agent_token_issuance_body(Some(mode), &["internal".into()]).is_err());
    }
    for (mode, name) in [(ReadOnly, "read_only"), (WriteCapable, "write_capable")] {
        assert!(agent_token_issuance_body(Some(mode), &[]).is_err());
        assert_eq!(
            agent_token_issuance_body(Some(mode), &["internal".into(), "external".into()]).unwrap(),
            Some(serde_json::json!({
                "mode": name, "allowedExecutionContexts": ["external", "internal"],
            }))
        );
    }
    assert!(agent_token_issuance_body(None, &["internal".into()]).is_err());
    for contexts in [
        vec!["internal".into(), "internal".into()],
        vec!["*".into()],
        vec!["x".repeat(65)],
        (0..65).map(|index| format!("context-{index}")).collect(),
    ] {
        assert!(agent_token_issuance_body(Some(ReadOnly), &contexts).is_err());
    }
    assert!(
        agent_token_issuance_body(
            Some(ReadOnly),
            &(0..64)
                .map(|index| format!("context-{index}"))
                .collect::<Vec<_>>()
        )
        .is_ok()
    );
}

#[test]
fn agent_token_issue_requires_an_explicit_strict_boolean() {
    for command in [
        vec!["tokens", "issue"],
        vec!["admin", "tokens", "issue", "alice"],
        vec![
            "admin",
            "tokens",
            "issue",
            "alice",
            "--token-class",
            "agent_invoke",
        ],
    ] {
        let mut args = vec!["agent-access"];
        args.extend(command);
        args.extend(["--name", "test", "--execution-context", "default"]);
        assert!(Cli::try_parse_from(&args).is_err(), "{args:?}");
        args.push("--read-only");
        assert!(Cli::try_parse_from(&args).is_err());
        for invalid in ["yes", "1", "null", "TRUE", ""] {
            let mut invalid_args = args.clone();
            invalid_args.push(invalid);
            assert!(Cli::try_parse_from(invalid_args).is_err());
        }
        for value in ["true", "false"] {
            let mut valid_args = args.clone();
            valid_args.push(value);
            assert!(Cli::try_parse_from(valid_args).is_ok());
        }
    }
}

#[test]
fn agent_token_request_bodies_preserve_explicit_boolean_and_inherited_grants() {
    for read_only in [true, false] {
        let personal = self_agent_token_issue_body(SelfAgentTokenIssueCliInput {
            name: "personal",
            ttl: &Some("7d".into()),
            expires_at: &None,
            never: false,
            services: &[],
            actions: &[],
            resource_ids: &[],
            resource_group_ids: &[],
            restricted_services: &[],
            service_restrictions_file: &None,
            execution_contexts: &["default".into()],
            read_only,
        })
        .unwrap();
        assert_eq!(personal["readOnly"], read_only);
        assert_eq!(
            personal["allowedExecutionContexts"],
            serde_json::json!(["default"])
        );
        assert!(personal.get("scopes").is_none());
        assert!(personal.get("allowedServices").is_none());
        assert!(personal.get("serviceRestrictions").is_none());
        let contexts = ["default".into()];
        let mut input = admin_input("agent_invoke", Some(read_only));
        input.execution_contexts = &contexts;
        let administrative = admin_token_issue_body(input).unwrap();
        assert_eq!(
            administrative["scopes"],
            serde_json::json!({
                "allowedExecutionContexts":["default"], "readOnly":read_only
            })
        );
        assert!(administrative.get("readOnly").is_none());
    }
    let contexts = ["default".into()];
    let mut input = admin_input("agent_invoke", None);
    input.execution_contexts = &contexts;
    assert!(
        admin_token_issue_body(input)
            .unwrap_err()
            .to_string()
            .contains("requires --read-only")
    );
}

fn admin_input(token_class: &str, read_only: Option<bool>) -> AdminTokenIssueCliInput<'_> {
    AdminTokenIssueCliInput {
        name: "administrative",
        token_class,
        ttl: &None,
        expires_at: &None,
        never: false,
        services: &[],
        actions: &[],
        resource_ids: &[],
        resource_group_ids: &[],
        restricted_services: &[],
        service_restrictions_file: &None,
        execution_contexts: &[],
        read_only,
    }
}

#[test]
fn management_token_classes_reject_both_boolean_values() {
    for token_class in ["admin", "user_manage"] {
        assert!(
            Cli::try_parse_from([
                "agent-access",
                "admin",
                "tokens",
                "issue",
                "alice",
                "--name",
                "management",
                "--token-class",
                token_class,
            ])
            .is_ok()
        );
        assert_eq!(
            admin_token_issue_body(admin_input(token_class, None)).unwrap()["scopes"],
            serde_json::json!({})
        );
        for read_only in [true, false] {
            let error =
                admin_token_issue_body(admin_input(token_class, Some(read_only))).unwrap_err();
            assert!(
                error
                    .to_string()
                    .contains("only valid with --token-class agent_invoke")
            );
        }
    }
}
