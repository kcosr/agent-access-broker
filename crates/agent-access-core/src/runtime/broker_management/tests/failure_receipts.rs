use super::*;

fn poison_store(store: &ManagedStore) {
    assert!(
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _: Result<(), CommandError> = store.management_transaction(true, |_| {
                panic!("injected managed store lock poison");
            });
        }))
        .is_err()
    );
}

#[tokio::test]
async fn local_writes_report_not_dispatched_when_transaction_cannot_start() {
    for (action, failure) in [
        ("principal.create", "missing_store"),
        ("principal.create", "read_only_store"),
        ("principal.create", "poisoned_store"),
        ("credential.install", "missing_store"),
        ("token.create", "missing_store"),
        ("token.create", "poisoned_store"),
        ("grant.subject.add", "poisoned_store"),
        ("grant.subject.add", "poisoned_policy_lock"),
    ] {
        let fixture = fixture(false);
        let reference = (action == "credential.install")
            .then(|| capture_reference(&fixture, "missing-store-private-gitlab-token"));
        let inputs = if action == "principal.create" {
            json!({"principalId":"new-worker"})
        } else if action == "credential.install" {
            json!({"principalId":"worker","connectionId":"gitlab-main","token":{"secretRef":reference.as_ref().unwrap()}})
        } else if action == "token.create" {
            token_create_input(&fixture, &Uuid::new_v4().to_string())
        } else {
            json!({"principalId":"worker","grantId":"service-access","expectedVersion":1})
        };
        let transition = Arc::new(move |mut runtime: BrokerRuntime| {
            match failure {
                "missing_store" => runtime.managed_store = None,
                "read_only_store" => runtime
                    .managed_store()
                    .unwrap()
                    .management_transaction(false, |conn| {
                        conn.pragma_update(None, "query_only", true).unwrap();
                        Ok(())
                    })
                    .unwrap(),
                "poisoned_store" => poison_store(runtime.managed_store().unwrap()),
                "poisoned_policy_lock" => {
                    assert!(
                        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                            let _guard = runtime.policy_mutation_lock.lock().unwrap();
                            panic!("injected policy lock poison");
                        }))
                        .is_err()
                    );
                }
                _ => unreachable!(),
            }
            runtime
        });
        let control = InvocationControl::default();
        let owned_control =
            control
                .clone()
                .with_local_operation_host(Arc::new(TransitionLocalHost {
                    runtime: fixture.runtime.clone(),
                    control,
                    transition,
                }));
        let response = fixture
            .runtime
            .invoke_owned_json(
                GovernedOperationContext {
                    operation: OperationContext {
                        agent_request_id: "pretransaction-failure".into(),
                        broker_request_id: Uuid::new_v4().to_string(),
                        identity: fixture.identity.clone(),
                        service: SERVICE_ID.into(),
                        action: action.into(),
                        source: SourceContext::unknown(),
                    },
                    execution_context: ExecutionContext::new("default").unwrap(),
                },
                InvokeRequest::new(inputs),
                owned_control,
            )
            .await;
        assert_eq!(response.status, 503, "{failure}: {:?}", response.envelope);
        let result = response.envelope.result.unwrap();
        assert_eq!(result["executionState"], "not_dispatched", "{failure}");
        assert_eq!(result["retrySafe"], false);
        let db = rusqlite::Connection::open(fixture.directory.path().join("store.sqlite")).unwrap();
        let (new_principals, grant_version, new_tokens): (i64, i64, i64) = db
            .query_row(
                "SELECT (SELECT COUNT(*) FROM principals WHERE principal_id='new-worker'), (SELECT version FROM policy_grants WHERE grant_id='service-access'), (SELECT COUNT(*) FROM broker_tokens WHERE principal_id='worker')",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .unwrap();
        assert_eq!(new_principals, 0, "{failure}");
        assert_eq!(grant_version, 1, "{failure}");
        assert_eq!(new_tokens, 0, "{failure}");
        let new_credentials: i64 = db
            .query_row("SELECT COUNT(*) FROM credentials", [], |row| row.get(0))
            .unwrap();
        assert_eq!(new_credentials, 0, "{failure}");
        if let Some(reference) = reference {
            assert_reference_value(&fixture, &reference, "missing-store-private-gitlab-token");
        }
        if action == "token.create" && failure == "missing_store" {
            let outcome: String = db
                .query_row(
                    "SELECT outcome FROM secret_reference_receipts WHERE action='token.create'",
                    [],
                    |row| row.get(0),
                )
                .unwrap();
            assert_eq!(outcome, "not_dispatched");
        }
        let audits: Vec<Value> = fs::read_to_string(fixture.directory.path().join("audit.jsonl"))
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str::<Value>(line).unwrap())
            .filter(|record| {
                record["action"] == action && record["providerAudit"]["phase"] != "preflight"
            })
            .collect();
        assert_eq!(audits.len(), 1, "{failure}");
        assert_eq!(
            audits[0]["providerAudit"]["executionState"], "not_dispatched",
            "{failure}"
        );
    }
}

#[test]
fn http_management_adapters_return_unavailable_for_poisoned_store() {
    use crate::ManagementOperation;
    let fixture = fixture(false);
    fixture
        .runtime
        .managed_store()
        .unwrap()
        .create_principal(PrincipalWriteRequest {
            principal_id: "http-admin".into(),
            kind: "user".into(),
            display_name: None,
            email: None,
            external_subject: None,
            created_by: "bootstrap".into(),
            role: PrincipalRole::Admin,
            self_service_enabled: Some(true),
        })
        .unwrap();
    let mut config = (*fixture.runtime.config).clone();
    config.management.enabled = true;
    let runtime = BrokerRuntime::new_for_reload(config, &fixture.runtime).unwrap();
    let store = runtime.managed_store().unwrap();
    let hasher = runtime.broker_token_hasher().unwrap();
    let headers = |token_class| {
        let issued = store
            .issue_broker_token(
                hasher,
                crate::BrokerTokenIssueRequest {
                    principal_id: "http-admin".into(),
                    name: "management lock test".into(),
                    token_class,
                    scopes: json!({}),
                    expires_at: None,
                    created_by: "http-admin".into(),
                },
            )
            .unwrap();
        HeaderMap::from_iter([(
            http::header::AUTHORIZATION,
            format!("Bearer {}", issued.token).parse().unwrap(),
        )])
    };
    let admin_headers = headers(BrokerTokenClass::Admin);
    let personal_headers = headers(BrokerTokenClass::UserManage);
    let authorities: Vec<_> = [
        ManagementOperation::PrincipalCreate,
        ManagementOperation::GroupMemberAdd,
        ManagementOperation::GroupMemberRemove,
        ManagementOperation::AdminTokenIssue,
        ManagementOperation::PersonalTokenIssue,
        ManagementOperation::GrantSubjectAdd,
        ManagementOperation::GrantSubjectRemove,
        ManagementOperation::GrantPatch,
        ManagementOperation::AdminCredentialPut,
        ManagementOperation::PersonalCredentialPut,
    ]
    .into_iter()
    .map(|operation| {
        let headers = if matches!(
            operation,
            ManagementOperation::PersonalTokenIssue | ManagementOperation::PersonalCredentialPut
        ) {
            &personal_headers
        } else {
            &admin_headers
        };
        (
            operation,
            runtime
                .admit_management_authority(headers, operation)
                .unwrap(),
        )
    })
    .collect();
    poison_store(store);
    for (operation, authority) in authorities {
        let result = match operation {
            ManagementOperation::PrincipalCreate => store
                .create_principal_with_management_authority(
                    PrincipalWriteRequest {
                        principal_id: "not-created".into(),
                        kind: "service_account".into(),
                        display_name: None,
                        email: None,
                        external_subject: None,
                        created_by: "http-admin".into(),
                        role: PrincipalRole::User,
                        self_service_enabled: Some(false),
                    },
                    authority,
                )
                .map(|_| ()),
            ManagementOperation::GroupMemberAdd => store
                .add_group_with_management_authority("worker", "workers", "http-admin", authority)
                .map(|_| ()),
            ManagementOperation::GroupMemberRemove => store
                .remove_local_group_with_management_authority("worker", "workers", authority)
                .map(|_| ()),
            ManagementOperation::AdminTokenIssue => store
                .issue_broker_token_with_management_authority(
                    hasher,
                    crate::BrokerTokenIssueRequest {
                        principal_id: "worker".into(),
                        name: "not-issued".into(),
                        token_class: BrokerTokenClass::AgentInvoke,
                        scopes: json!({"allowedServices":["fake"],"allowedExecutionContexts":["default"]}),
                        expires_at: None,
                        created_by: "http-admin".into(),
                    },
                    None,
                    authority,
                )
                .map(|_| ()),
            ManagementOperation::PersonalTokenIssue => store
                .issue_self_agent_token_with_management_authority(
                    hasher,
                    crate::SelfAgentTokenIssueRequest {
                        principal_id: "http-admin".into(),
                        name: "not-issued".into(),
                        scopes: json!({"allowedServices":["fake"],"allowedExecutionContexts":["default"]}),
                        expires_at: None,
                        created_by: "http-admin".into(),
                    },
                    None,
                    authority,
                )
                .map(|_| ()),
            ManagementOperation::GrantSubjectAdd => store
                .add_policy_grant_subject_with_management_authority(
                    ManagedPolicyGrantSubjectAddRequest {
                        grant_id: "service-access".into(),
                        expected_version: 1,
                        subject: "user:operator".into(),
                        updated_by: "http-admin".into(),
                    },
                    authority,
                    |_, _, _, _| panic!("poisoned store must not reach validation"),
                )
                .map(|_| ()),
            ManagementOperation::GrantSubjectRemove => store
                .remove_policy_grant_subject_with_management_authority(
                    ManagedPolicyGrantSubjectRemoveRequest {
                        grant_id: "service-access".into(),
                        expected_version: 1,
                        subject: "user:worker".into(),
                        last_subject_behavior: "reject".into(),
                        updated_by: "http-admin".into(),
                    },
                    authority,
                    |_, _, _, _| panic!("poisoned store must not reach validation"),
                )
                .map(|_| ()),
            ManagementOperation::GrantPatch => store
                .patch_policy_grant_with_management_authority(
                    ManagedPolicyGrantPatchRequest {
                        grant_id: "service-access".into(),
                        expected_version: 1,
                        subjects: None,
                        execution_contexts: None,
                        service: None,
                        actions: None,
                        resources: None,
                        credential_mode: None,
                        priority: None,
                        status: None,
                        description: Some(Some("not-applied".into())),
                        updated_by: "http-admin".into(),
                    },
                    authority,
                    |_, _, _, _| panic!("poisoned store must not reach validation"),
                )
                .map(|_| ()),
            ManagementOperation::AdminCredentialPut | ManagementOperation::PersonalCredentialPut => {
                let (owner, purpose) = if operation == ManagementOperation::AdminCredentialPut {
                    ("worker", crate::CredentialManagementPurpose::Administrative)
                } else {
                    ("http-admin", crate::CredentialManagementPurpose::Personal)
                };
                runtime
                    .store_connection_credential_with_management_authority(
                        authority,
                        crate::CredentialWriteRequest {
                            owner_principal_id: owner.into(),
                            service: "gitlab-main".into(),
                            name: crate::CONNECTION_CREDENTIAL_NAME.into(),
                            profile: "gitlab-access-token".into(),
                            credential_kind: "bearer_token".into(),
                            secret: json!({"token":"not-stored-private-gitlab-token"}),
                            metadata: json!({}),
                            actor: "http-admin".into(),
                        },
                        purpose,
                    )
                    .map(|_| ())
            }
        };
        assert!(
            matches!(result, Err(ManagedStoreError::Unavailable(_))),
            "{operation:?}: {result:?}"
        );
    }
    let db = rusqlite::Connection::open(fixture.directory.path().join("store.sqlite")).unwrap();
    let (new_credentials, grant_version): (i64, i64) = db
        .query_row(
            "SELECT (SELECT COUNT(*) FROM credentials), (SELECT version FROM policy_grants WHERE grant_id='service-access')",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert_eq!(new_credentials, 0);
    assert_eq!(grant_version, 1);
}
