use super::*;
use crate::{CreateResourceRequest, GroupWriteRequest, PrincipalRole, PrincipalWriteRequest};
use base64::Engine;

mod complete_scopes;

type BeforeCommit = Arc<dyn Fn(&BrokerRuntime) + Send + Sync>;

struct LocalHost {
    runtime: BrokerRuntime,
    control: InvocationControl,
    remove_actor_group: bool,
    before_commit: Option<BeforeCommit>,
    commit_barrier: Option<Arc<tokio::sync::Barrier>>,
}
impl crate::LocalOperationHost for LocalHost {
    fn execute(
        &self,
        command: AdmittedManagementCommand,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = crate::LocalOperationOutcome> + Send + 'static>,
    > {
        let runtime = self.runtime.clone();
        let control = self.control.clone();
        let remove = self.remove_actor_group;
        let before_commit = self.before_commit.clone();
        let commit_barrier = self.commit_barrier.clone();
        Box::pin(async move {
            if remove {
                runtime
                    .managed_store()
                    .unwrap()
                    .remove_group("operator", "operators")
                    .unwrap();
            }
            if let Some(before_commit) = before_commit {
                before_commit(&runtime);
            }
            if let Some(barrier) = commit_barrier {
                barrier.wait().await;
            }
            if command.is_write() {
                assert!(control.begin_local_commit());
            }
            let dispatcher = tracing::dispatcher::get_default(Clone::clone);
            tokio::task::spawn_blocking(move || {
                tracing::dispatcher::with_default(&dispatcher, || {
                    runtime.execute_management_command(command)
                })
            })
            .await
            .unwrap()
        })
    }
}
struct Fixture {
    directory: tempfile::TempDir,
    runtime: BrokerRuntime,
    identity: IdentityContext,
    identity_proof: Option<crate::AttestedIdentityProof>,
}
fn fixture(group_actor: bool) -> Fixture {
    let directory = tempfile::tempdir().unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
    }
    let key = directory.path().join("token.key");
    fs::write(
        &key,
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([31; 32]),
    )
    .unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&key, fs::Permissions::from_mode(0o600)).unwrap();
    }
    let mut config = super::super::tests::base_fake_config();
    config.identity.mode = "required".into();
    config.identity.authority = "managed".into();
    config.identity.groups.clear();
    config.identity.sources = vec![crate::IdentitySourceConfig {
        name: "tokens".into(),
        kind: "broker_tokens".into(),
        header: "Authorization".into(),
        scheme: "Bearer".into(),
        principals: vec![],
    }];
    config.credentials.service.clear();
    config
        .providers
        .insert(agent_access_gitlab::GitlabProviderConfig {
            provisioning: Default::default(),
            attachments: Default::default(),
            api_base_url: "https://gitlab.example.test/api/v4".into(),
            web_base_url: "https://gitlab.example.test".into(),
            egress_proxy: None,
            allowed_upstream_hosts: vec!["https://gitlab.example.test/api/v4/**".into()],
            webhooks: Default::default(),
            content: Default::default(),
            search: Default::default(),
        });
    config.credentials.connections.insert(
        "gitlab-main".into(),
        crate::ConnectionConfig {
            display_name: None,
            token_profile: Some("gitlab-access-token".into()),
            oauth: None,
        },
    );
    config.credentials.per_user.insert(
        "gitlab".into(),
        crate::CredentialConfig {
            kind: "connection".into(),
            username_ref: None,
            token_ref: None,
            provider: None,
            path: None,
            read_only: None,
            connection: Some("gitlab-main".into()),
        },
    );
    config.policy.authority = "managed".into();
    config.policy.grants.clear();
    config.policy.resources.clear();
    config.policy.resource_groups.clear();
    config.managed_store = Some(crate::ManagedStoreConfig {
        kind: "sqlite".into(),
        path: directory.path().join("store.sqlite").display().to_string(),
        auto_migrate: true,
        require_registered_principal_for_invocation: false,
    });
    config.broker_tokens = Some(crate::BrokerTokensConfig {
        hash_key_ref: format!("file:{}", key.display()),
        ..Default::default()
    });
    config.audit = Some(crate::AuditConfig::new(
        crate::AuditStoreType::Jsonl,
        directory.path().join("audit.jsonl").display().to_string(),
    ));
    let runtime = BrokerRuntime::new(config).unwrap();
    let store = runtime.managed_store().unwrap();
    for (id, kind) in [("operator", "user"), ("worker", "service_account")] {
        store
            .create_principal(PrincipalWriteRequest {
                principal_id: id.into(),
                kind: kind.into(),
                display_name: None,
                email: None,
                external_subject: None,
                created_by: "admin".into(),
                role: PrincipalRole::User,
                self_service_enabled: Some(false),
            })
            .unwrap();
    }
    for group in ["workers", "operators"] {
        store
            .create_group(GroupWriteRequest {
                group_id: group.into(),
                display_name: None,
                description: None,
                created_by: "admin".into(),
            })
            .unwrap();
    }
    if group_actor {
        store.add_group("operator", "operators", "admin").unwrap();
    }
    for (id, kind, target) in [
        ("worker-scope", "broker_principal", "worker"),
        ("new-worker-scope", "broker_principal", "new-worker"),
        ("group-scope", "broker_group", "workers"),
        ("grant-scope", "broker_grant", "service-access"),
        ("connection-scope", "broker_connection", "gitlab-main"),
        ("project-scope", "fake_project", "TEST"),
    ] {
        runtime
            .create_managed_resource(CreateResourceRequest {
                id: Some(id.into()),
                display_name: None,
                resource_type: ResourceType::from_static(kind),
                selector: ResourceSelector::Exact {
                    value: target.into(),
                },
                allowed_execution_contexts: vec!["default".into()],
                enabled: true,
                attributes: Default::default(),
                created_by: "admin".into(),
            })
            .unwrap();
    }
    runtime
        .create_managed_policy_grant(ManagedPolicyGrantCreateRequest {
            grant_id: Some("service-access".into()),
            subjects: vec!["user:worker".into()],
            execution_contexts: vec!["default".into()],
            service: "fake".into(),
            actions: vec!["echo".into()],
            resources: ResourceSelection {
                resource_ids: vec!["project-scope".into()],
                resource_group_ids: vec![],
            },
            credential_mode: "service".into(),
            priority: None,
            status: None,
            description: None,
            created_by: "admin".into(),
        })
        .unwrap();
    runtime
        .create_managed_policy_grant(ManagedPolicyGrantCreateRequest {
            grant_id: Some("provision".into()),
            subjects: vec![if group_actor {
                "group:operators".into()
            } else {
                "user:operator".into()
            }],
            execution_contexts: vec!["default".into()],
            service: SERVICE_ID.into(),
            actions: vec![
                "principal.create",
                "principal.view",
                "group.view",
                "group.member.add",
                "group.member.remove",
                "group.member.view",
                "grant.view",
                "grant.subject.view",
                "grant.subject.add",
                "grant.subject.remove",
                "credential.install",
                "credential.view",
                "token.create",
                "token.view",
            ]
            .into_iter()
            .map(str::to_owned)
            .collect(),
            resources: ResourceSelection {
                resource_ids: vec![
                    "worker-scope",
                    "new-worker-scope",
                    "group-scope",
                    "grant-scope",
                    "connection-scope",
                ]
                .into_iter()
                .map(str::to_owned)
                .collect(),
                resource_group_ids: vec![],
            },
            credential_mode: "service".into(),
            priority: None,
            status: None,
            description: None,
            created_by: "admin".into(),
        })
        .unwrap();
    let token=store.issue_broker_token(runtime.broker_token_hasher().unwrap(),crate::BrokerTokenIssueRequest { principal_id:"operator".into(),name:"provisioning".into(),token_class:BrokerTokenClass::AgentInvoke,scopes:json!({"allowedServices":[SERVICE_ID],"allowedExecutionContexts":["default"]}),expires_at:None,created_by:"admin".into() }).unwrap();
    let headers = HeaderMap::from_iter([(
        http::header::AUTHORIZATION,
        format!("Bearer {}", token.token).parse().unwrap(),
    )]);
    let identity = runtime.resolve_identity(&headers).unwrap();
    Fixture {
        directory,
        runtime,
        identity,
        identity_proof: None,
    }
}
async fn invoke(
    fixture: &Fixture,
    action: &str,
    inputs: Value,
    remove_actor_group: bool,
) -> BrokerResponse<Value> {
    invoke_with_commit_control(fixture, action, inputs, remove_actor_group, None, None).await
}
async fn invoke_with_commit_control(
    fixture: &Fixture,
    action: &str,
    inputs: Value,
    remove_actor_group: bool,
    before_commit: Option<BeforeCommit>,
    commit_barrier: Option<Arc<tokio::sync::Barrier>>,
) -> BrokerResponse<Value> {
    let control = InvocationControl::default().with_identity_proof(fixture.identity_proof.clone());
    let control = control
        .clone()
        .with_local_operation_host(Arc::new(LocalHost {
            runtime: fixture.runtime.clone(),
            control,
            remove_actor_group,
            before_commit,
            commit_barrier,
        }));
    fixture
        .runtime
        .invoke_owned_json(
            GovernedOperationContext {
                operation: OperationContext {
                    agent_request_id: "local-test".into(),
                    broker_request_id: Uuid::new_v4().to_string(),
                    identity: fixture.identity.clone(),
                    service: SERVICE_ID.into(),
                    action: action.into(),
                    source: SourceContext::unknown(),
                },
                execution_context: ExecutionContext::new("default").unwrap(),
            },
            InvokeRequest::new(inputs),
            control,
        )
        .await
}
#[test]
fn startup_rejects_retained_management_assignment_for_inactive_nonmanager() {
    let fixture = fixture(false);
    fixture
        .runtime
        .managed_store()
        .unwrap()
        .set_principal_enabled("operator", false)
        .unwrap();
    let db = rusqlite::Connection::open(fixture.directory.path().join("store.sqlite")).unwrap();
    db.execute(
        "INSERT INTO service_policy_management_assignments (assignment_id,service,principal_id,created_at,created_by) VALUES (?1,'broker_management','operator',?2,'test')",
        rusqlite::params![Uuid::new_v4().to_string(),chrono::Utc::now().to_rfc3339()],
    ).unwrap();
    drop(db);
    assert!(BrokerRuntime::new((*fixture.runtime.config).clone()).is_err());
}
#[tokio::test]
async fn local_dispatch_rechecks_membership_and_keeps_narrow_results() {
    let fixture = fixture(true);
    let response = invoke(
        &fixture,
        "group.member.add",
        json!({"principalId":"worker","groupId":"workers"}),
        false,
    )
    .await;
    assert_eq!(response.status, 200, "{:?}", response.envelope);
    let result = response.envelope.result.unwrap();
    assert_eq!(result["changed"], true);
    assert_eq!(result["effectiveMember"], true);
    let response = invoke(
        &fixture,
        "group.member.remove",
        json!({"principalId":"worker","groupId":"workers"}),
        true,
    )
    .await;
    assert_eq!(response.status, 403, "{:?}", response.envelope);
    assert_eq!(
        response.envelope.reason_code,
        Some(ReasonCode::ServiceActionDenied.into())
    );
    assert_eq!(
        response.envelope.result.unwrap()["executionState"],
        "not_committed"
    );
    assert!(
        fixture
            .runtime
            .managed_store()
            .unwrap()
            .groups("worker")
            .unwrap()
            .contains(&"workers".into())
    );
}
fn capture_reference(fixture: &Fixture, private_token: &str) -> String {
    use crate::managed_store::{
        SecretOutputReservation, SecretReferenceLimits, SecretReservationRequest,
    };
    let origin = fixture
        .runtime
        .secret_reference_origin(
            &fixture.identity,
            &ExecutionContext::new("default").unwrap(),
            fixture.identity_proof.as_ref(),
        )
        .unwrap();
    let store = fixture.runtime.managed_store().unwrap();
    let ring = fixture.runtime.credential_key_ring().unwrap();
    let batch = store
        .reserve_secret_outputs(
            ring,
            SecretReservationRequest {
                broker_request_id: Uuid::new_v4().to_string(),
                origin,
                execution_context: "default".into(),
                service: "gitlab".into(),
                action: "project.access_token.create".into(),
                outputs: vec![SecretOutputReservation {
                    pointer: "/result/token".into(),
                    max_bytes: 128,
                }],
            },
            &SecretReferenceLimits {
                ttl_seconds: 3600,
                max_refs_per_principal: 8,
                max_refs_total: 16,
                max_bytes_per_principal: 1024,
                max_bytes_total: 2048,
                receipt_retention_seconds: 3600,
                max_receipts_total: 100,
            },
            |conn, origin| {
                fixture
                    .runtime
                    .check_secret_reference_origin_conn(conn, origin)
            },
        )
        .unwrap();
    let mut captured = store
        .capture_secret_outputs(
            ring,
            &batch,
            vec![SecretOutputCapture {
                pointer: "/result/token".into(),
                value: private_token.into(),
            }],
            json!({"executionState":"completed"}),
        )
        .unwrap();
    captured.remove(0).secret_ref
}

#[tokio::test]
async fn credential_install_requires_original_auth_and_never_replaces_retained_slot() {
    let mut fixture = fixture(false);
    let original_identity = fixture.identity.clone();
    let private_token = "synthetic-private-gitlab-token";
    let reference = capture_reference(&fixture, private_token);
    let store = fixture.runtime.managed_store().unwrap();
    let input = json!({"principalId":"worker","connectionId":"gitlab-main","token":{"secretRef":reference}});

    let replacement=store.issue_broker_token(fixture.runtime.broker_token_hasher().unwrap(),crate::BrokerTokenIssueRequest {
        principal_id:"operator".into(),name:"other authentication".into(),token_class:BrokerTokenClass::AgentInvoke,scopes:json!({"allowedServices":[SERVICE_ID],"allowedExecutionContexts":["default"]}),expires_at:None,created_by:"admin".into(),
    }).unwrap();
    fixture.identity = fixture
        .runtime
        .resolve_identity(&HeaderMap::from_iter([(
            http::header::AUTHORIZATION,
            format!("Bearer {}", replacement.token).parse().unwrap(),
        )]))
        .unwrap();
    let denied = invoke(&fixture, "credential.install", input.clone(), false).await;
    assert_eq!(denied.status, 403, "{:?}", denied.envelope);
    assert_eq!(
        denied.envelope.reason_code.unwrap().as_str(),
        "access_management_reference_denied"
    );
    assert!(store.list_credentials(Some("worker")).unwrap().is_empty());

    fixture.identity = original_identity;
    let installed = invoke(&fixture, "credential.install", input.clone(), false).await;
    assert_eq!(installed.status, 200, "{:?}", installed.envelope);
    let installed = installed.envelope.result.unwrap();
    assert_eq!(installed["present"], true);
    assert_eq!(installed["profile"], "gitlab-access-token");
    assert!(installed["version"].is_string());
    let credential = store
        .resolve_user_credential(
            fixture.runtime.credential_key_ring().unwrap(),
            "worker",
            "gitlab-main",
            "default",
            "gitlab-access-token",
        )
        .unwrap();
    assert_eq!(
        credential,
        agent_access_provider::host::bearer_credential(private_token.into())
    );
    let db = rusqlite::Connection::open(fixture.directory.path().join("store.sqlite")).unwrap();
    db.execute(
        "UPDATE credentials SET status='disabled' WHERE owner_principal_id='worker'",
        [],
    )
    .unwrap();
    drop(db);
    let conflict = invoke(&fixture, "credential.install", input, false).await;
    assert_eq!(conflict.status, 409, "{:?}", conflict.envelope);
    assert_eq!(
        conflict.envelope.reason_code.unwrap().as_str(),
        "access_management_target_exists"
    );
    let view = invoke(
        &fixture,
        "credential.view",
        json!({"principalId":"worker","connectionId":"gitlab-main"}),
        false,
    )
    .await;
    assert_eq!(view.status, 200, "{:?}", view.envelope);
    assert_eq!(view.envelope.result.as_ref().unwrap()["status"], "disabled");
    let public = serde_json::to_string(&view.envelope).unwrap();
    let audit = fs::read_to_string(fixture.directory.path().join("audit.jsonl")).unwrap();
    for output in [public, audit] {
        assert!(!output.contains(private_token));
        assert!(!output.contains(&reference));
    }
}
#[tokio::test]
async fn local_token_create_captures_once_and_view_never_redelivers() {
    let fixture = fixture(false);
    let token_id = Uuid::new_v4().to_string();
    let ttl = fixture
        .runtime
        .config
        .broker_tokens
        .as_ref()
        .unwrap()
        .admin_agent_invoke_ttl_options
        .iter()
        .find_map(|value| value.ttl_seconds())
        .unwrap();
    let input = json!({"principalId":"worker","grantId":"service-access","expectedVersion":1,"tokenId":token_id,"name":"worker token","allowedExecutionContexts":["default"],"ttlSeconds":ttl});
    let response = invoke(&fixture, "token.create", input.clone(), false).await;
    assert_eq!(response.status, 200, "{:?}", response.envelope);
    let result = response.envelope.result.unwrap();
    let reference = result["issuedToken"]["secretRef"].as_str().unwrap();
    assert!(valid_reference(reference));
    assert!(result.get("token").is_none());
    assert!(result.get("grantId").is_none());
    let origin = fixture
        .runtime
        .secret_reference_origin(
            &fixture.identity,
            &ExecutionContext::new("default").unwrap(),
            None,
        )
        .unwrap();
    let raw = fixture
        .runtime
        .managed_store()
        .unwrap()
        .resolve_secret_reference(
            fixture.runtime.credential_key_ring().unwrap(),
            reference,
            |conn, stored| {
                fixture
                    .runtime
                    .check_secret_reference_owner_conn(conn, stored, &origin)
            },
        )
        .unwrap();
    let issued = fixture
        .runtime
        .managed_store()
        .unwrap()
        .resolve_broker_token(fixture.runtime.broker_token_hasher().unwrap(), &raw)
        .unwrap();
    assert_eq!(issued.principal_id, "worker");
    assert_eq!(issued.scopes["allowedServices"], json!(["fake"]));
    assert_eq!(
        issued.scopes["serviceRestrictions"]["fake"]["actions"],
        json!(["echo"])
    );
    let repeat = invoke(&fixture, "token.create", input, false).await;
    assert_eq!(repeat.status, 409, "{:?}", repeat.envelope);
    assert_eq!(
        repeat.envelope.reason_code.unwrap().as_str(),
        "access_management_target_exists"
    );
    assert!(
        !serde_json::to_string(&repeat.envelope.result)
            .unwrap()
            .contains(reference)
    );
    let read = invoke(
        &fixture,
        "token.view",
        json!({"principalId":"worker","tokenId":token_id}),
        false,
    )
    .await;
    assert_eq!(read.status, 200);
    let read = read.envelope.result.unwrap();
    assert_eq!(read["tokenId"], token_id);
    assert!(read.get("issuedToken").is_none());
    let audit = fs::read_to_string(fixture.directory.path().join("audit.jsonl")).unwrap();
    assert!(!audit.contains(reference));
    assert!(!audit.contains(&raw));
}

#[tokio::test]
async fn unauthorized_tuples_are_uniform_and_disabled_target_reads_remain_narrow() {
    let fixture = fixture(false);
    let known = invoke(
        &fixture,
        "group.member.add",
        json!({"principalId":"operator","groupId":"workers"}),
        false,
    )
    .await;
    let unknown = invoke(
        &fixture,
        "group.member.add",
        json!({"principalId":"unknown-worker","groupId":"workers"}),
        false,
    )
    .await;
    assert_eq!(known.status, 403);
    assert_eq!(unknown.status, known.status);
    assert_eq!(unknown.envelope.reason_code, known.envelope.reason_code);
    assert_eq!(unknown.envelope.reason, known.envelope.reason);
    fixture
        .runtime
        .managed_store()
        .unwrap()
        .set_principal_enabled("worker", false)
        .unwrap();
    let read = invoke(
        &fixture,
        "principal.view",
        json!({"principalId":"worker"}),
        false,
    )
    .await;
    assert_eq!(read.status, 200, "{:?}", read.envelope);
    let value = read.envelope.result.unwrap();
    assert_eq!(value["status"], "disabled");
    assert!(value.get("groups").is_none());
    let write = invoke(
        &fixture,
        "group.member.add",
        json!({"principalId":"worker","groupId":"workers"}),
        false,
    )
    .await;
    assert_eq!(write.status, 403);
    assert_eq!(
        write.envelope.reason_code.unwrap().as_str(),
        "access_management_target_ineligible"
    );
}

#[tokio::test]
async fn token_creation_rejects_selected_scoped_grant_without_resources() {
    let fixture = fixture(false);
    let changed = fixture
        .runtime
        .patch_managed_policy_grant(ManagedPolicyGrantPatchRequest {
            grant_id: "service-access".into(),
            expected_version: 1,
            subjects: None,
            execution_contexts: None,
            service: None,
            actions: None,
            resources: Some(ResourceSelection::default()),
            credential_mode: None,
            priority: None,
            status: None,
            description: None,
            updated_by: "admin".into(),
        })
        .unwrap();
    let ttl = fixture
        .runtime
        .config
        .broker_tokens
        .as_ref()
        .unwrap()
        .admin_agent_invoke_ttl_options
        .iter()
        .find_map(|value| value.ttl_seconds())
        .unwrap();
    let response=invoke(&fixture,"token.create",json!({"principalId":"worker","grantId":"service-access","expectedVersion":changed.grant.version,"tokenId":Uuid::new_v4().to_string(),"name":"empty authority","allowedExecutionContexts":["default"],"ttlSeconds":ttl}),false).await;
    assert_eq!(response.status, 409, "{:?}", response.envelope);
    assert_eq!(
        response.envelope.reason_code.unwrap().as_str(),
        "access_management_precondition_failed"
    );
    assert_eq!(
        response.envelope.result.unwrap()["executionState"],
        "not_committed"
    );
    assert!(
        fixture
            .runtime
            .managed_store()
            .unwrap()
            .list_broker_tokens_for_principal("worker")
            .unwrap()
            .is_empty()
    );
}

#[tokio::test]
async fn token_view_does_not_reveal_another_owner_or_revive_requester_token() {
    let fixture = fixture(false);
    let issuer_id = fixture
        .identity
        .source
        .as_ref()
        .unwrap()
        .token_id
        .as_ref()
        .unwrap();
    let foreign = invoke(
        &fixture,
        "token.view",
        json!({"principalId":"worker","tokenId":issuer_id}),
        false,
    )
    .await;
    let unknown = invoke(
        &fixture,
        "token.view",
        json!({"principalId":"worker","tokenId":Uuid::new_v4().to_string()}),
        false,
    )
    .await;
    assert_eq!(foreign.status, 404);
    assert_eq!(foreign.envelope.reason_code, unknown.envelope.reason_code);
    assert_eq!(foreign.envelope.reason, unknown.envelope.reason);
    fixture
        .runtime
        .managed_store()
        .unwrap()
        .revoke_broker_token(issuer_id, "admin")
        .unwrap();
    let response = invoke(
        &fixture,
        "principal.view",
        json!({"principalId":"worker"}),
        false,
    )
    .await;
    assert_eq!(response.status, 403, "{:?}", response.envelope);
    assert_eq!(
        response.envelope.reason_code,
        Some(ReasonCode::ServiceActionDenied.into())
    );
}

fn token_create_input(fixture: &Fixture, token_id: &str) -> Value {
    let ttl = fixture
        .runtime
        .config
        .broker_tokens
        .as_ref()
        .unwrap()
        .admin_agent_invoke_ttl_options
        .iter()
        .find_map(|value| value.ttl_seconds())
        .unwrap();
    json!({"principalId":"worker","grantId":"service-access","expectedVersion":1,"tokenId":token_id,"name":"worker token","allowedExecutionContexts":["default"],"ttlSeconds":ttl})
}

#[tokio::test]
async fn queued_token_creation_rechecks_authentication_and_both_accounts() {
    for change in [
        "revoke",
        "pause",
        "expire",
        "disable_actor",
        "disable_target",
    ] {
        let fixture = fixture(false);
        let actor_token = fixture
            .identity
            .source
            .as_ref()
            .unwrap()
            .token_id
            .clone()
            .unwrap();
        let database = fixture.directory.path().join("store.sqlite");
        let hook: BeforeCommit = Arc::new(move |runtime| {
            let store = runtime.managed_store().unwrap();
            match change {
                "revoke" => {
                    store.revoke_broker_token(&actor_token, "admin").unwrap();
                }
                "pause" => {
                    store
                        .pause_principal_agent_token(
                            "operator",
                            &actor_token,
                            "admin",
                            crate::AgentTokenManagementPurpose::Administrative,
                        )
                        .unwrap();
                }
                "expire" => {
                    rusqlite::Connection::open(&database).unwrap().execute("UPDATE broker_tokens SET expires_at='2000-01-01T00:00:00Z' WHERE token_id=?1",[&actor_token]).unwrap();
                }
                "disable_actor" => {
                    store.set_principal_enabled("operator", false).unwrap();
                }
                "disable_target" => {
                    store.set_principal_enabled("worker", false).unwrap();
                }
                _ => unreachable!(),
            }
        });
        let response = invoke_with_commit_control(
            &fixture,
            "token.create",
            token_create_input(&fixture, &Uuid::new_v4().to_string()),
            false,
            Some(hook),
            None,
        )
        .await;
        assert_eq!(response.status, 403, "{change}: {:?}", response.envelope);
        assert_eq!(
            response.envelope.result.as_ref().unwrap()["executionState"],
            "not_committed"
        );
        assert!(
            fixture
                .runtime
                .managed_store()
                .unwrap()
                .list_broker_tokens_for_principal("worker")
                .unwrap()
                .is_empty()
        );
        let db = rusqlite::Connection::open(fixture.directory.path().join("store.sqlite")).unwrap();
        let captured: i64 = db
            .query_row(
                "SELECT COUNT(*) FROM secret_reference_material WHERE state='captured'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(captured, 0, "{change}");
    }
}

#[tokio::test]
async fn queued_commands_recheck_grant_resource_and_new_group_protection() {
    for change in ["grant", "resource", "protected_group"] {
        let fixture = fixture(false);
        fixture
            .runtime
            .managed_store()
            .unwrap()
            .add_group("worker", "workers", "admin")
            .unwrap();
        let hook: BeforeCommit = Arc::new(move |runtime| match change {
            "grant" => {
                runtime
                    .patch_managed_policy_grant(ManagedPolicyGrantPatchRequest {
                        grant_id: "provision".into(),
                        expected_version: 1,
                        subjects: None,
                        execution_contexts: None,
                        service: None,
                        actions: None,
                        resources: None,
                        credential_mode: None,
                        priority: None,
                        status: None,
                        description: Some(Some("changed while queued".into())),
                        updated_by: "admin".into(),
                    })
                    .unwrap();
            }
            "resource" => {
                runtime
                    .patch_managed_resource(crate::PatchResourceRequest {
                        attributes: Default::default(),
                        id: "worker-scope".into(),
                        expected_version: 1,
                        display_name: None,
                        resource_type: None,
                        selector: None,
                        allowed_execution_contexts: None,
                        enabled: Some(false),
                        updated_by: "admin".into(),
                    })
                    .unwrap();
            }
            "protected_group" => {
                runtime
                    .create_managed_policy_grant(ManagedPolicyGrantCreateRequest {
                        grant_id: Some("new-management-authority".into()),
                        subjects: vec!["group:workers".into()],
                        execution_contexts: vec!["default".into()],
                        service: SERVICE_ID.into(),
                        actions: vec!["principal.view".into()],
                        resources: ResourceSelection {
                            resource_ids: vec!["worker-scope".into()],
                            resource_group_ids: vec![],
                        },
                        credential_mode: "service".into(),
                        priority: None,
                        status: None,
                        description: None,
                        created_by: "admin".into(),
                    })
                    .unwrap();
            }
            _ => unreachable!(),
        });
        let inputs = json!({"principalId":"worker","groupId":"workers"});
        let response = invoke_with_commit_control(
            &fixture,
            "group.member.remove",
            inputs.clone(),
            false,
            Some(hook),
            None,
        )
        .await;
        assert_eq!(response.status, 409, "{change}: {:?}", response.envelope);
        assert_eq!(
            response.envelope.reason_code,
            Some(ReasonCode::VersionConflict.into())
        );
        assert_eq!(
            response.envelope.result.as_ref().unwrap()["executionState"],
            "not_committed"
        );
        assert!(
            fixture
                .runtime
                .managed_store()
                .unwrap()
                .groups("worker")
                .unwrap()
                .contains(&"workers".into())
        );
        if change == "protected_group" {
            let subsequent = invoke(&fixture, "group.member.remove", inputs, false).await;
            assert_eq!(subsequent.status, 403, "{:?}", subsequent.envelope);
            assert_eq!(
                subsequent.envelope.reason_code.unwrap().as_str(),
                "access_management_target_ineligible"
            );
        }
    }
}

#[tokio::test]
async fn simultaneous_credential_installs_commit_one_slot_and_keep_reference_usable() {
    let fixture = fixture(false);
    let private_token = "simultaneous-install-secret";
    let reference = capture_reference(&fixture, private_token);
    let inputs = json!({"principalId":"worker","connectionId":"gitlab-main","token":{"secretRef":reference}});
    let barrier = Arc::new(tokio::sync::Barrier::new(2));
    let (first, second) = tokio::join!(
        invoke_with_commit_control(
            &fixture,
            "credential.install",
            inputs.clone(),
            false,
            None,
            Some(barrier.clone())
        ),
        invoke_with_commit_control(
            &fixture,
            "credential.install",
            inputs,
            false,
            None,
            Some(barrier)
        ),
    );
    let mut statuses = [first.status, second.status];
    statuses.sort();
    assert_eq!(statuses, [200, 409]);
    assert_eq!(
        fixture
            .runtime
            .managed_store()
            .unwrap()
            .list_credentials(Some("worker"))
            .unwrap()
            .len(),
        1
    );
    assert_reference_value(&fixture, &reference, private_token);
}

fn assert_reference_value(fixture: &Fixture, reference: &str, expected: &str) {
    let origin = fixture
        .runtime
        .secret_reference_origin(
            &fixture.identity,
            &ExecutionContext::new("default").unwrap(),
            None,
        )
        .unwrap();
    assert_eq!(
        fixture
            .runtime
            .managed_store()
            .unwrap()
            .resolve_secret_reference(
                fixture.runtime.credential_key_ring().unwrap(),
                reference,
                |conn, stored| fixture
                    .runtime
                    .check_secret_reference_owner_conn(conn, stored, &origin)
            )
            .unwrap(),
        expected
    );
}

#[tokio::test]
async fn failed_credential_storage_rolls_back_and_does_not_consume_reference() {
    let fixture = fixture(false);
    let private_token = "faulted-install-secret";
    let reference = capture_reference(&fixture, private_token);
    let db = rusqlite::Connection::open(fixture.directory.path().join("store.sqlite")).unwrap();
    db.execute_batch("CREATE TRIGGER fault_credential AFTER INSERT ON credentials BEGIN SELECT RAISE(ABORT,'injected storage failure'); END;").unwrap();
    let inputs = json!({"principalId":"worker","connectionId":"gitlab-main","token":{"secretRef":reference}});
    let response = invoke(&fixture, "credential.install", inputs.clone(), false).await;
    assert_eq!(response.status, 503, "{:?}", response.envelope);
    assert_eq!(
        response.envelope.result.as_ref().unwrap()["executionState"],
        "not_committed"
    );
    assert!(
        fixture
            .runtime
            .managed_store()
            .unwrap()
            .list_credentials(Some("worker"))
            .unwrap()
            .is_empty()
    );
    assert_reference_value(&fixture, &reference, private_token);
    db.execute_batch("DROP TRIGGER fault_credential;").unwrap();
    let retry = invoke(&fixture, "credential.install", inputs, false).await;
    assert_eq!(retry.status, 200, "{:?}", retry.envelope);
}

#[tokio::test]
async fn token_faults_never_commit_only_one_of_token_and_capture() {
    for (stage, trigger, expected_state) in [
        (
            "before_insert",
            "CREATE TRIGGER fault BEFORE INSERT ON broker_tokens BEGIN SELECT RAISE(ABORT,'before insert'); END;",
            "not_committed",
        ),
        (
            "after_insert",
            "CREATE TRIGGER fault AFTER INSERT ON broker_tokens BEGIN SELECT RAISE(ABORT,'after insert'); END;",
            "not_committed",
        ),
        (
            "after_capture",
            "CREATE TRIGGER fault AFTER UPDATE OF state ON secret_reference_material WHEN NEW.state='captured' BEGIN SELECT RAISE(ABORT,'after capture'); END;",
            "not_committed",
        ),
        (
            "after_receipt",
            "CREATE TRIGGER fault AFTER UPDATE OF outcome ON secret_reference_receipts WHEN NEW.outcome='captured' BEGIN SELECT RAISE(ABORT,'after receipt'); END;",
            "not_committed",
        ),
        (
            "commit",
            "CREATE TABLE fault_guard (id TEXT PRIMARY KEY, missing_principal TEXT REFERENCES principals(principal_id) DEFERRABLE INITIALLY DEFERRED); CREATE TRIGGER fault AFTER UPDATE OF outcome ON secret_reference_receipts WHEN NEW.outcome='captured' BEGIN INSERT INTO fault_guard VALUES ('commit','never-existing-principal'); END;",
            "unknown",
        ),
    ] {
        let fixture = fixture(false);
        let db = rusqlite::Connection::open(fixture.directory.path().join("store.sqlite")).unwrap();
        db.execute_batch(trigger).unwrap();
        let response = invoke(
            &fixture,
            "token.create",
            token_create_input(&fixture, &Uuid::new_v4().to_string()),
            false,
        )
        .await;
        assert!(response.status >= 400, "{stage}");
        assert_eq!(
            response.envelope.result.as_ref().unwrap()["executionState"],
            expected_state,
            "{stage}: {:?}",
            response.envelope
        );
        assert!(
            response
                .envelope
                .result
                .as_ref()
                .unwrap()
                .get("issuedToken")
                .is_none()
        );
        assert!(
            fixture
                .runtime
                .managed_store()
                .unwrap()
                .list_broker_tokens_for_principal("worker")
                .unwrap()
                .is_empty(),
            "{stage}"
        );
        let captured: i64 = db
            .query_row(
                "SELECT COUNT(*) FROM secret_reference_material WHERE state='captured'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(captured, 0, "{stage}");
        let outcome: String = db
            .query_row(
                "SELECT outcome FROM secret_reference_receipts WHERE action='token.create'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(
            outcome,
            if expected_state == "unknown" {
                "unknown"
            } else {
                "capture_failed"
            },
            "{stage}"
        );
    }
}

#[tokio::test]
async fn token_uuid_conflicts_cover_other_owners_and_revoked_rows_without_replay() {
    let fixture = fixture(false);
    let foreign = fixture
        .identity
        .source
        .as_ref()
        .unwrap()
        .token_id
        .as_ref()
        .unwrap();
    let response = invoke(
        &fixture,
        "token.create",
        token_create_input(&fixture, foreign),
        false,
    )
    .await;
    assert_eq!(response.status, 409, "{:?}", response.envelope);
    assert_eq!(
        response.envelope.reason_code.unwrap().as_str(),
        "access_management_target_exists"
    );
    assert!(
        response
            .envelope
            .result
            .as_ref()
            .unwrap()
            .get("issuedToken")
            .is_none()
    );
    let child = Uuid::new_v4().to_string();
    let input = token_create_input(&fixture, &child);
    let issued = invoke(&fixture, "token.create", input.clone(), false).await;
    assert_eq!(issued.status, 200, "{:?}", issued.envelope);
    fixture
        .runtime
        .managed_store()
        .unwrap()
        .revoke_broker_token(&child, "admin")
        .unwrap();
    let conflict = invoke(&fixture, "token.create", input, false).await;
    assert_eq!(conflict.status, 409, "{:?}", conflict.envelope);
    assert!(
        conflict
            .envelope
            .result
            .as_ref()
            .unwrap()
            .get("issuedToken")
            .is_none()
    );
    assert_eq!(
        fixture
            .runtime
            .managed_store()
            .unwrap()
            .list_broker_tokens_for_principal("worker")
            .unwrap()
            .len(),
        1
    );
}

#[tokio::test]
async fn queued_token_creation_rechecks_recipient_effective_subject_membership() {
    let fixture = fixture(false);
    fixture
        .runtime
        .managed_store()
        .unwrap()
        .add_group("worker", "workers", "admin")
        .unwrap();
    let grant = fixture
        .runtime
        .patch_managed_policy_grant(ManagedPolicyGrantPatchRequest {
            grant_id: "service-access".into(),
            expected_version: 1,
            subjects: Some(vec!["group:workers".into()]),
            execution_contexts: None,
            service: None,
            actions: None,
            resources: None,
            credential_mode: None,
            priority: None,
            status: None,
            description: None,
            updated_by: "admin".into(),
        })
        .unwrap();
    let mut inputs = token_create_input(&fixture, &Uuid::new_v4().to_string());
    inputs["expectedVersion"] = json!(grant.grant.version);
    let hook: BeforeCommit = Arc::new(|runtime| {
        runtime
            .managed_store()
            .unwrap()
            .remove_group("worker", "workers")
            .unwrap();
    });
    let response =
        invoke_with_commit_control(&fixture, "token.create", inputs, false, Some(hook), None).await;
    assert_eq!(response.status, 409, "{:?}", response.envelope);
    assert_eq!(
        response.envelope.reason_code.unwrap().as_str(),
        "access_management_precondition_failed"
    );
    assert_eq!(
        response.envelope.result.as_ref().unwrap()["precondition"],
        "recipient_subject"
    );
    assert!(
        fixture
            .runtime
            .managed_store()
            .unwrap()
            .list_broker_tokens_for_principal("worker")
            .unwrap()
            .is_empty()
    );
}

#[derive(Clone, Copy)]
enum PauseLocalAt {
    BeforeGate,
    AfterGate,
    AfterCommit,
}

struct PausedLocalHost {
    runtime: BrokerRuntime,
    control: InvocationControl,
    pause_at: PauseLocalAt,
    entered: Arc<tokio::sync::Semaphore>,
    resume: Arc<tokio::sync::Semaphore>,
}
impl crate::LocalOperationHost for PausedLocalHost {
    fn execute(
        &self,
        command: AdmittedManagementCommand,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = crate::LocalOperationOutcome> + Send + 'static>,
    > {
        let runtime = self.runtime.clone();
        let control = self.control.clone();
        let pause_at = self.pause_at;
        let entered = self.entered.clone();
        let resume = self.resume.clone();
        Box::pin(async move {
            runtime
                .preflight_management_command(&command)
                .await
                .unwrap();
            if matches!(pause_at, PauseLocalAt::BeforeGate) {
                entered.add_permits(1);
                tokio::select! {
                    biased;
                    error=control.local_interrupted()=>return crate::LocalOperationOutcome::rejected(error),
                    permit=resume.acquire()=>permit.unwrap().forget(),
                }
            }
            if !control.begin_local_commit() {
                return crate::LocalOperationOutcome::rejected(control.local_interrupted().await);
            }
            if matches!(pause_at, PauseLocalAt::AfterGate) {
                entered.add_permits(1);
                resume.acquire().await.unwrap().forget();
            }
            let outcome =
                tokio::task::spawn_blocking(move || runtime.execute_management_command(command))
                    .await
                    .unwrap();
            if matches!(pause_at, PauseLocalAt::AfterCommit) {
                entered.add_permits(1);
                resume.acquire().await.unwrap().forget();
            }
            outcome
        })
    }
}

fn spawn_paused_token_creation(
    fixture: &Fixture,
    token_id: &str,
    pause_at: PauseLocalAt,
) -> (
    InvocationControl,
    Arc<tokio::sync::Semaphore>,
    Arc<tokio::sync::Semaphore>,
    tokio::task::JoinHandle<BrokerResponse<Value>>,
) {
    spawn_paused_management(
        fixture,
        "token.create",
        token_create_input(fixture, token_id),
        pause_at,
    )
}

fn spawn_paused_management(
    fixture: &Fixture,
    action: &str,
    inputs: Value,
    pause_at: PauseLocalAt,
) -> (
    InvocationControl,
    Arc<tokio::sync::Semaphore>,
    Arc<tokio::sync::Semaphore>,
    tokio::task::JoinHandle<BrokerResponse<Value>>,
) {
    let control = InvocationControl::new(Some(Duration::from_secs(60)))
        .with_identity_proof(fixture.identity_proof.clone());
    let entered = Arc::new(tokio::sync::Semaphore::new(0));
    let resume = Arc::new(tokio::sync::Semaphore::new(0));
    let owned_control = control
        .clone()
        .with_local_operation_host(Arc::new(PausedLocalHost {
            runtime: fixture.runtime.clone(),
            control: control.clone(),
            pause_at,
            entered: entered.clone(),
            resume: resume.clone(),
        }));
    let runtime = fixture.runtime.clone();
    let identity = fixture.identity.clone();
    let action = action.to_owned();
    let owner = tokio::spawn(async move {
        runtime
            .invoke_owned_json(
                GovernedOperationContext {
                    operation: OperationContext {
                        agent_request_id: "lifecycle-test".into(),
                        broker_request_id: Uuid::new_v4().to_string(),
                        identity,
                        service: SERVICE_ID.into(),
                        action,
                        source: SourceContext::unknown(),
                    },
                    execution_context: ExecutionContext::new("default").unwrap(),
                },
                InvokeRequest::new(inputs),
                owned_control,
            )
            .await
    });
    (control, entered, resume, owner)
}

fn terminal_token_audits(fixture: &Fixture) -> Vec<Value> {
    fs::read_to_string(fixture.directory.path().join("audit.jsonl"))
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).unwrap())
        .filter(|record| {
            record["service"] == SERVICE_ID
                && record["action"] == "token.create"
                && record["providerAudit"]["phase"] != "preflight"
        })
        .collect()
}

#[tokio::test]
async fn local_token_cancellation_before_gate_commits_neither_token_nor_capture() {
    let fixture = fixture(false);
    let (control, entered, _resume, owner) = spawn_paused_token_creation(
        &fixture,
        &Uuid::new_v4().to_string(),
        PauseLocalAt::BeforeGate,
    );
    entered.acquire().await.unwrap().forget();
    control.cancel();
    let response = owner.await.unwrap();
    assert_eq!(
        response.envelope.reason_code,
        Some(ReasonCode::OperationCancelled.into())
    );
    assert_eq!(
        response.envelope.result.as_ref().unwrap()["executionState"],
        "not_dispatched"
    );
    assert!(!control.dispatched());
    assert!(
        fixture
            .runtime
            .managed_store()
            .unwrap()
            .list_broker_tokens_for_principal("worker")
            .unwrap()
            .is_empty()
    );
    let db = rusqlite::Connection::open(fixture.directory.path().join("store.sqlite")).unwrap();
    let captured: i64 = db
        .query_row(
            "SELECT COUNT(*) FROM secret_reference_material WHERE state='captured'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(captured, 0);
    assert_eq!(terminal_token_audits(&fixture).len(), 1);
}

#[tokio::test]
async fn local_token_owner_retains_commit_and_capture_after_gate_interruptions() {
    for interruption in ["cancel", "force_stop", "deadline"] {
        let fixture = fixture(false);
        let token_id = Uuid::new_v4().to_string();
        let (control, entered, resume, owner) =
            spawn_paused_token_creation(&fixture, &token_id, PauseLocalAt::AfterGate);
        entered.acquire().await.unwrap().forget();
        assert!(control.dispatched());
        match interruption {
            "cancel" => control.cancel(),
            "force_stop" => control.force_stop(),
            "deadline" => {
                tokio::time::pause();
                tokio::time::advance(Duration::from_secs(61)).await;
                tokio::time::resume();
            }
            _ => unreachable!(),
        }
        resume.add_permits(1);
        let response = owner.await.unwrap();
        assert_eq!(
            response.status, 200,
            "{interruption}: {:?}",
            response.envelope
        );
        assert!(control.completed());
        let result = response.envelope.result.unwrap();
        assert_eq!(result["executionState"], "completed");
        let reference = result["issuedToken"]["secretRef"].as_str().unwrap();
        let origin = fixture
            .runtime
            .secret_reference_origin(
                &fixture.identity,
                &ExecutionContext::new("default").unwrap(),
                None,
            )
            .unwrap();
        let raw = fixture
            .runtime
            .managed_store()
            .unwrap()
            .resolve_secret_reference(
                fixture.runtime.credential_key_ring().unwrap(),
                reference,
                |conn, stored| {
                    fixture
                        .runtime
                        .check_secret_reference_owner_conn(conn, stored, &origin)
                },
            )
            .unwrap();
        let token = fixture
            .runtime
            .managed_store()
            .unwrap()
            .resolve_broker_token(fixture.runtime.broker_token_hasher().unwrap(), &raw)
            .unwrap();
        assert_eq!(token.token_id, token_id);
        assert_eq!(token.principal_id, "worker");
        let audits = terminal_token_audits(&fixture);
        assert_eq!(audits.len(), 1, "{interruption}");
        assert_eq!(audits[0]["decision"], "allow");
        assert_eq!(audits[0]["providerAudit"]["executionState"], "completed");
    }
}

#[tokio::test]
async fn local_token_postcommit_audit_failure_preserves_captured_receipt_and_completed_state() {
    let fixture = fixture(false);
    let token_id = Uuid::new_v4().to_string();
    let (_control, entered, resume, owner) =
        spawn_paused_token_creation(&fixture, &token_id, PauseLocalAt::AfterCommit);
    entered.acquire().await.unwrap().forget();
    assert_eq!(
        fixture
            .runtime
            .managed_store()
            .unwrap()
            .list_broker_tokens_for_principal("worker")
            .unwrap()
            .len(),
        1
    );
    let audit_path = fixture.directory.path().join("audit.jsonl");
    fs::remove_file(&audit_path).unwrap();
    fs::create_dir(&audit_path).unwrap();
    resume.add_permits(1);
    let response = owner.await.unwrap();
    assert_eq!(
        response.envelope.reason_code,
        Some(ReasonCode::AuditUnavailable.into())
    );
    let result = response.envelope.result.unwrap();
    assert_eq!(result["executionState"], "completed");
    assert_eq!(result["retrySafe"], false);
    assert!(result["secretOutput"]["secretReceipt"]["receiptId"].is_string());
    assert!(!result.to_string().contains("secretRef"));
    let db = rusqlite::Connection::open(fixture.directory.path().join("store.sqlite")).unwrap();
    let (outcome,captured):(String,i64)=db.query_row("SELECT r.outcome,(SELECT COUNT(*) FROM secret_reference_material m WHERE m.receipt_id=r.receipt_id AND m.state='captured') FROM secret_reference_receipts r WHERE r.action='token.create'",[],|row|Ok((row.get(0)?,row.get(1)?))).unwrap();
    assert_eq!(outcome, "captured");
    assert_eq!(captured, 1);
    assert_eq!(
        fixture
            .runtime
            .managed_store()
            .unwrap()
            .list_broker_tokens_for_principal("worker")
            .unwrap()[0]
            .token_id,
        token_id
    );
}

#[tokio::test]
async fn raw_output_mode_preserves_held_reference_install_and_reference_only_metadata() {
    let mut fixture = fixture(false);
    let private_token = "held-reference-before-raw-mode";
    let reference = capture_reference(&fixture, private_token);
    let mut config = (*fixture.runtime.config).clone();
    config.secret_outputs.mode = crate::SecretOutputMode::Raw;
    fixture.runtime = BrokerRuntime::new(config).unwrap();

    let services = fixture.runtime.api_services_for_identity(
        &fixture.identity,
        &ExecutionContext::new("default").unwrap(),
    );
    let service = services
        .iter()
        .find(|service| service.service == SERVICE_ID)
        .unwrap();
    let install = service
        .actions
        .iter()
        .find(|action| action.action == "credential.install")
        .unwrap();
    assert_eq!(install.secret_input_pointers, ["/inputs/token"]);
    assert!(
        install
            .sensitive_input_pointers
            .contains(&"/inputs/token".into())
    );
    let input = json!({"principalId":"worker","connectionId":"gitlab-main","token":{"secretRef":reference}});
    let literal =
        json!({"principalId":"worker","connectionId":"gitlab-main","token":private_token});
    let schema = jsonschema::validator_for(&install.input_schema).unwrap();
    assert!(schema.is_valid(&input));
    assert!(!schema.is_valid(&literal));
    assert_eq!(
        install.input_schema["properties"]["token"]["writeOnly"],
        true
    );
    assert_eq!(
        install.input_schema["properties"]["token"]["x-agent-access-sensitive"],
        true
    );
    assert!(
        !service
            .actions
            .iter()
            .any(|action| action.action == "token.create")
    );
    let definitions = fixture.runtime.api_services_all();
    let token = definitions
        .iter()
        .find(|service| service.service == SERVICE_ID)
        .unwrap()
        .actions
        .iter()
        .find(|action| action.action == "token.create")
        .unwrap();
    assert_eq!(
        token.secret_output_mode,
        Some(crate::SecretOutputMode::Reference)
    );

    let rejected = invoke(&fixture, "credential.install", literal, false).await;
    assert_eq!(rejected.status, 400, "{:?}", rejected.envelope);
    assert!(
        fixture
            .runtime
            .managed_store()
            .unwrap()
            .list_credentials(Some("worker"))
            .unwrap()
            .is_empty()
    );
    let installed = invoke(&fixture, "credential.install", input, false).await;
    assert_eq!(installed.status, 200, "{:?}", installed.envelope);
    assert_reference_value(&fixture, &reference, private_token);
    let credential = fixture
        .runtime
        .managed_store()
        .unwrap()
        .resolve_user_credential(
            fixture.runtime.credential_key_ring().unwrap(),
            "worker",
            "gitlab-main",
            "default",
            "gitlab-access-token",
        )
        .unwrap();
    assert_eq!(
        credential,
        agent_access_provider::host::bearer_credential(private_token.into())
    );
    let unavailable = invoke(
        &fixture,
        "token.create",
        token_create_input(&fixture, &Uuid::new_v4().to_string()),
        false,
    )
    .await;
    assert!(unavailable.status >= 400, "{:?}", unavailable.envelope);
    assert!(
        fixture
            .runtime
            .managed_store()
            .unwrap()
            .list_broker_tokens_for_principal("worker")
            .unwrap()
            .is_empty()
    );
}

#[tokio::test]
async fn auditor_without_self_service_invokes_only_with_an_explicit_broker_grant() {
    let fixture = fixture(false);
    let store = fixture.runtime.managed_store().unwrap();
    store
        .patch_principal_access(crate::PrincipalAccessPatchRequest {
            principal_id: "operator".into(),
            role: Some(PrincipalRole::Auditor),
            self_service_enabled: Some(false),
            actor: "admin".into(),
        })
        .unwrap();
    let input = json!({"principalId":"worker","groupId":"workers"});
    let allowed = invoke(&fixture, "group.member.add", input.clone(), false).await;
    assert_eq!(allowed.status, 200, "{:?}", allowed.envelope);
    assert!(store.groups("worker").unwrap().contains(&"workers".into()));
    fixture
        .runtime
        .disable_managed_policy_grant(crate::ManagedPolicyGrantStatusRequest {
            grant_id: "provision".into(),
            expected_version: 1,
            updated_by: "admin".into(),
        })
        .unwrap();
    let denied = invoke(&fixture, "group.member.remove", input, false).await;
    assert_eq!(denied.status, 403, "{:?}", denied.envelope);
    assert!(store.groups("worker").unwrap().contains(&"workers".into()));
    let principal = store.principal("operator").unwrap();
    assert_eq!(principal.role, PrincipalRole::Auditor);
    assert!(!principal.self_service_enabled);
}

fn create_test_account(fixture: &Fixture, principal: &str, kind: &str) {
    fixture
        .runtime
        .managed_store()
        .unwrap()
        .create_principal(PrincipalWriteRequest {
            principal_id: principal.into(),
            kind: kind.into(),
            display_name: None,
            email: None,
            external_subject: None,
            created_by: "admin".into(),
            role: PrincipalRole::User,
            self_service_enabled: Some(false),
        })
        .unwrap();
}

fn test_agent_identity(
    fixture: &Fixture,
    principal: &str,
    name: &str,
) -> (IdentityContext, crate::BrokerTokenRecord) {
    let issued = fixture
        .runtime
        .managed_store()
        .unwrap()
        .issue_broker_token(
            fixture.runtime.broker_token_hasher().unwrap(),
            crate::BrokerTokenIssueRequest {
                principal_id: principal.into(),
                name: name.into(),
                token_class: BrokerTokenClass::AgentInvoke,
                scopes: json!({"allowedServices":["fake"],"allowedExecutionContexts":["default"]}),
                expires_at: None,
                created_by: "admin".into(),
            },
        )
        .unwrap();
    let identity = fixture
        .runtime
        .resolve_identity(&HeaderMap::from_iter([(
            http::header::AUTHORIZATION,
            format!("Bearer {}", issued.token).parse().unwrap(),
        )]))
        .unwrap();
    (identity, issued.record)
}

async fn invoke_fake_as(fixture: &Fixture, identity: &IdentityContext) -> BrokerResponse<Value> {
    fixture
        .runtime
        .invoke_owned_json(
            GovernedOperationContext {
                operation: OperationContext {
                    agent_request_id: "recipient-publication-test".into(),
                    broker_request_id: Uuid::new_v4().to_string(),
                    identity: identity.clone(),
                    service: "fake".into(),
                    action: "echo".into(),
                    source: SourceContext::unknown(),
                },
                execution_context: ExecutionContext::new("default").unwrap(),
            },
            InvokeRequest::new(json!({"project":"TEST","message":"recipient-policy-check"})),
            InvocationControl::default(),
        )
        .await
}

#[tokio::test]
async fn subject_writes_publish_after_gate_interruptions_and_stale_versions_preserve_state() {
    for interruption in ["cancel", "force_stop", "deadline"] {
        let fixture = fixture(false);
        create_test_account(&fixture, "new-worker", "service_account");
        let (recipient, _) = test_agent_identity(&fixture, "new-worker", "recipient");
        assert_eq!(invoke_fake_as(&fixture, &recipient).await.status, 403);
        for (action, expected_version, expected_allowed) in [
            ("grant.subject.add", 1, true),
            ("grant.subject.remove", 2, false),
        ] {
            let (control, entered, resume, owner) = spawn_paused_management(
                &fixture,
                action,
                json!({"principalId":"new-worker","grantId":"service-access","expectedVersion":expected_version}),
                PauseLocalAt::AfterGate,
            );
            entered.acquire().await.unwrap().forget();
            assert!(control.dispatched());
            match interruption {
                "cancel" => control.cancel(),
                "force_stop" => control.force_stop(),
                "deadline" => {
                    tokio::time::pause();
                    tokio::time::advance(Duration::from_secs(61)).await;
                    tokio::time::resume();
                }
                _ => unreachable!(),
            }
            resume.add_permits(1);
            let response = owner.await.unwrap();
            assert_eq!(
                response.status, 200,
                "{interruption} {action}: {:?}",
                response.envelope
            );
            assert_eq!(
                response.envelope.result.as_ref().unwrap()["executionState"],
                "completed"
            );
            assert!(control.completed());
            let store = fixture.runtime.managed_store().unwrap();
            let grant = store.policy_grant("service-access").unwrap();
            assert_eq!(grant.version, expected_version + 1);
            assert_eq!(grant.status, "active");
            assert_eq!(
                grant.subjects.contains(&"user:new-worker".into()),
                expected_allowed
            );
            assert_eq!(
                fixture.runtime.policy_generation(),
                store.policy_revision().unwrap().generation
            );
            let recipient_result = invoke_fake_as(&fixture, &recipient).await;
            assert_eq!(
                recipient_result.status,
                if expected_allowed { 200 } else { 403 },
                "{:?}",
                recipient_result.envelope
            );
            let audits = fs::read_to_string(fixture.directory.path().join("audit.jsonl"))
                .unwrap()
                .lines()
                .map(|line| serde_json::from_str::<Value>(line).unwrap())
                .filter(|record| {
                    record["service"] == SERVICE_ID
                        && record["action"] == action
                        && record["providerAudit"]["phase"] != "preflight"
                })
                .collect::<Vec<_>>();
            assert_eq!(audits.len(), 1, "{interruption} {action}");
            assert_eq!(audits[0]["providerAudit"]["executionState"], "completed");
        }
        let before = fixture
            .runtime
            .managed_store()
            .unwrap()
            .policy_grant("service-access")
            .unwrap();
        let generation = fixture.runtime.policy_generation();
        for action in ["grant.subject.add", "grant.subject.remove", "token.create"] {
            let input = if action == "token.create" {
                token_create_input(&fixture, &Uuid::new_v4().to_string())
            } else {
                json!({"principalId":"new-worker","grantId":"service-access","expectedVersion":1})
            };
            let response = invoke(&fixture, action, input, false).await;
            assert_eq!(response.status, 409, "{action}: {:?}", response.envelope);
            assert_eq!(
                response.envelope.reason_code,
                Some(ReasonCode::VersionConflict.into())
            );
            assert_eq!(
                response.envelope.result.as_ref().unwrap()["executionState"],
                "not_committed"
            );
        }
        assert_eq!(
            fixture
                .runtime
                .managed_store()
                .unwrap()
                .policy_grant("service-access")
                .unwrap(),
            before
        );
        assert_eq!(fixture.runtime.policy_generation(), generation);
    }
}

fn attested_fixture() -> (Fixture, PathBuf, String) {
    let mut fixture = fixture(false);
    let caller_path = fixture.directory.path().join("trusted-caller.token");
    fs::write(&caller_path, "synthetic-management-caller-original").unwrap();
    let mut config = (*fixture.runtime.config).clone();
    config.identity.trusted_callers.insert(
        "direct".into(),
        crate::TrustedCallerConfig {
            credential_ref: format!("file:{}", caller_path.display()),
            credential_transport: crate::TrustedCallerCredentialTransport::AuthorizationUser,
            username_namespace: Some("workspace".into()),
            context_mode: crate::TrustedCallerContextMode::Fixed,
            execution_context: Some("default".into()),
            allowed_execution_contexts: None,
            allow_forwarded_identity: false,
        },
    );
    let mut runtime = BrokerRuntime::new_for_reload(config, &fixture.runtime).unwrap();
    runtime.activate_runtime_authority().unwrap();
    let binding = runtime
        .managed_store()
        .unwrap()
        .create_username_binding("operator", "workspace", "provisioner", "admin")
        .unwrap();
    let headers = HeaderMap::from_iter([
        (
            http::header::AUTHORIZATION,
            "Bearer synthetic-management-caller-original"
                .parse()
                .unwrap(),
        ),
        (
            http::header::HeaderName::from_static("x-agent-access-user"),
            "provisioner".parse().unwrap(),
        ),
    ]);
    let admission = runtime.admit_mcp_ingress(&headers).unwrap();
    let admitted = runtime
        .resolve_admitted_identity_with_proof(&headers, &admission)
        .unwrap();
    assert!(admitted.proof.is_some());
    fixture.runtime = runtime;
    fixture.identity = admitted.identity;
    fixture.identity_proof = admitted.proof;
    (fixture, caller_path, binding.binding_id)
}

struct TransitionLocalHost {
    runtime: BrokerRuntime,
    control: InvocationControl,
    transition: Arc<dyn Fn(BrokerRuntime) -> BrokerRuntime + Send + Sync>,
}
impl crate::LocalOperationHost for TransitionLocalHost {
    fn execute(
        &self,
        command: AdmittedManagementCommand,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = crate::LocalOperationOutcome> + Send + 'static>,
    > {
        let runtime = self.runtime.clone();
        let control = self.control.clone();
        let transition = self.transition.clone();
        Box::pin(async move {
            // The capability has already pinned the original identity proof,
            // reference origin and runtime; mutate authority at this exact edge.
            let runtime = transition(runtime);
            assert!(control.begin_local_commit());
            tokio::task::spawn_blocking(move || runtime.execute_management_command(command))
                .await
                .unwrap()
        })
    }
}

#[tokio::test]
async fn attested_local_actions_recheck_caller_remap_restore_and_runtime_generation() {
    for action in ["credential.install", "token.create"] {
        for change in [
            "unchanged",
            "caller_rotation",
            "caller_restore",
            "identity_remap_restore",
            "runtime_reload",
        ] {
            let (fixture, caller_path, binding_id) = attested_fixture();
            create_test_account(&fixture, "other-operator", "user");
            let reference = capture_reference(&fixture, "attested-private-gitlab-value");
            let token_id = Uuid::new_v4().to_string();
            let inputs = if action == "credential.install" {
                json!({"principalId":"worker","connectionId":"gitlab-main","token":{"secretRef":reference}})
            } else {
                token_create_input(&fixture, &token_id)
            };
            let transition = Arc::new(move |runtime: BrokerRuntime| {
                match change {
                    "caller_rotation" | "caller_restore" => {
                        fs::write(&caller_path, "synthetic-management-caller-rotated").unwrap();
                        let config = (*runtime.config).clone();
                        let mut changed =
                            BrokerRuntime::new_for_reload(config.clone(), &runtime).unwrap();
                        changed.activate_runtime_authority().unwrap();
                        if change == "caller_restore" {
                            fs::write(&caller_path, "synthetic-management-caller-original")
                                .unwrap();
                            let mut restored =
                                BrokerRuntime::new_for_reload(config, &changed).unwrap();
                            restored.activate_runtime_authority().unwrap();
                        }
                    }
                    "identity_remap_restore" => {
                        let store = runtime.managed_store().unwrap();
                        store
                            .delete_username_binding("operator", &binding_id, 1)
                            .unwrap();
                        let other = store
                            .create_username_binding(
                                "other-operator",
                                "workspace",
                                "provisioner",
                                "admin",
                            )
                            .unwrap();
                        store
                            .delete_username_binding("other-operator", &other.binding_id, 1)
                            .unwrap();
                        store
                            .create_username_binding(
                                "operator",
                                "workspace",
                                "provisioner",
                                "admin",
                            )
                            .unwrap();
                    }
                    "runtime_reload" => {
                        let mut reloaded =
                            BrokerRuntime::new_for_reload((*runtime.config).clone(), &runtime)
                                .unwrap();
                        reloaded.activate_runtime_authority().unwrap();
                        return reloaded;
                    }
                    "unchanged" => {}
                    _ => unreachable!(),
                }
                runtime
            });
            let control =
                InvocationControl::default().with_identity_proof(fixture.identity_proof.clone());
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
                            agent_request_id: "attested-local-race".into(),
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
            let store = fixture.runtime.managed_store().unwrap();
            let credentials = store.list_credentials(Some("worker")).unwrap();
            let tokens = store.list_broker_tokens_for_principal("worker").unwrap();
            if change == "unchanged" {
                assert_eq!(response.status, 200, "{action}: {:?}", response.envelope);
                assert_eq!(
                    credentials.len(),
                    usize::from(action == "credential.install")
                );
                assert_eq!(tokens.len(), usize::from(action == "token.create"));
            } else {
                assert_eq!(
                    response.status,
                    if change == "runtime_reload" { 409 } else { 403 },
                    "{change} {action}: {:?}",
                    response.envelope
                );
                assert_eq!(
                    response.envelope.result.as_ref().unwrap()["executionState"],
                    "not_committed"
                );
                assert!(credentials.is_empty(), "{change} {action}");
                assert!(tokens.is_empty(), "{change} {action}");
                let db = rusqlite::Connection::open(fixture.directory.path().join("store.sqlite"))
                    .unwrap();
                let captured:i64=db.query_row("SELECT COUNT(*) FROM secret_reference_material m JOIN secret_reference_receipts r ON r.receipt_id=m.receipt_id WHERE r.action='token.create' AND m.state='captured'",[],|r|r.get(0)).unwrap();
                assert_eq!(captured, 0, "{change} {action}");
            }
            let audit = fs::read_to_string(fixture.directory.path().join("audit.jsonl")).unwrap();
            assert!(!audit.contains("attested-private-gitlab-value"));
            assert!(!audit.contains(&reference));
        }
    }
}

#[tokio::test]
async fn every_narrow_read_and_discovery_omits_unrelated_inventory_and_private_canaries() {
    use tracing::instrument::WithSubscriber;
    use tracing_subscriber::prelude::*;
    let fixture = fixture(false);
    let store = fixture.runtime.managed_store().unwrap();
    create_test_account(&fixture, "canary-unrelated-person", "user");
    store
        .patch_principal(crate::PrincipalPatchRequest {
            principal_id: "worker".into(),
            display_name: None,
            email: Some(Some("canary-private-email@example.test".into())),
            status: None,
        })
        .unwrap();
    store
        .add_group("canary-unrelated-person", "workers", "admin")
        .unwrap();
    fixture
        .runtime
        .add_managed_policy_grant_subject(crate::ManagedPolicyGrantSubjectAddRequest {
            grant_id: "service-access".into(),
            expected_version: 1,
            subject: "user:canary-unrelated-person".into(),
            updated_by: "admin".into(),
        })
        .unwrap();
    fixture
        .runtime
        .create_managed_resource(CreateResourceRequest {
            id: Some("canary-unrelated-resource".into()),
            display_name: Some("canary-unrelated-resource-label".into()),
            resource_type: ResourceType::from_static("broker_principal"),
            selector: ResourceSelector::Exact {
                value: "canary-unrelated-person".into(),
            },
            allowed_execution_contexts: vec!["default".into()],
            enabled: true,
            attributes: Default::default(),
            created_by: "admin".into(),
        })
        .unwrap();
    for owner in ["worker", "canary-unrelated-person"] {
        store
            .upsert_user_credential(
                fixture.runtime.credential_key_ring().unwrap(),
                crate::CredentialWriteRequest {
                    owner_principal_id: owner.into(),
                    service: "gitlab-main".into(),
                    name: crate::CONNECTION_CREDENTIAL_NAME.into(),
                    profile: "gitlab-access-token".into(),
                    credential_kind: "bearer_token".into(),
                    secret: json!({"token":"canary-private-credential-value"}),
                    metadata: json!({"description":"canary-private-credential-metadata"}),
                    actor: "admin".into(),
                },
                crate::CredentialManagementPurpose::Administrative,
            )
            .unwrap();
    }
    let child = store
        .issue_broker_token(
            fixture.runtime.broker_token_hasher().unwrap(),
            crate::BrokerTokenIssueRequest {
                principal_id: "worker".into(),
                name: "visible child".into(),
                token_class: BrokerTokenClass::AgentInvoke,
                scopes: json!({"allowedServices":["fake"],"allowedExecutionContexts":["default"]}),
                expires_at: None,
                created_by: "canary-private-token-creator".into(),
            },
        )
        .unwrap();
    let (_, other_token) = test_agent_identity(
        &fixture,
        "canary-unrelated-person",
        "canary-unrelated-token-name",
    );
    let reference = capture_reference(&fixture, "canary-held-reference-value");
    let db = rusqlite::Connection::open(fixture.directory.path().join("store.sqlite")).unwrap();
    let hash: String = db
        .query_row(
            "SELECT token_hash FROM broker_tokens WHERE token_id=?1",
            [&child.record.token_id],
            |row| row.get(0),
        )
        .unwrap();
    drop(db);
    let canaries = vec![
        "canary-unrelated-person".to_owned(),
        "canary-private-email@example.test".into(),
        "canary-unrelated-resource".into(),
        "canary-unrelated-resource-label".into(),
        "canary-private-credential-value".into(),
        "canary-private-credential-metadata".into(),
        "canary-private-token-creator".into(),
        "canary-unrelated-token-name".into(),
        "canary-held-reference-value".into(),
        other_token.token_id,
        child.token,
        reference,
        hash,
    ];
    let reads = [
        ("principal.view", json!({"principalId":"worker"})),
        ("group.view", json!({"groupId":"workers"})),
        (
            "group.member.view",
            json!({"principalId":"worker","groupId":"workers"}),
        ),
        ("grant.view", json!({"grantId":"service-access"})),
        (
            "grant.subject.view",
            json!({"principalId":"worker","grantId":"service-access"}),
        ),
        (
            "credential.view",
            json!({"principalId":"worker","connectionId":"gitlab-main"}),
        ),
        (
            "token.view",
            json!({"principalId":"worker","tokenId":child.record.token_id}),
        ),
    ];
    let captured = super::super::tests::CapturedEvents::default();
    let subscriber = tracing_subscriber::registry().with(super::super::tests::EventCaptureLayer {
        events: captured.clone(),
    });
    let outputs = async {
        let mut outputs = Vec::new();
        tracing::info!(test_phase = "narrow_management_reads");
        for (action, inputs) in &reads {
            let current = store.policy_grant("provision").unwrap();
            fixture
                .runtime
                .patch_managed_policy_grant(crate::ManagedPolicyGrantPatchRequest {
                    grant_id: "provision".into(),
                    expected_version: current.version,
                    subjects: None,
                    execution_contexts: None,
                    service: None,
                    actions: Some(vec![(*action).into()]),
                    resources: None,
                    credential_mode: None,
                    priority: None,
                    status: None,
                    description: None,
                    updated_by: "admin".into(),
                })
                .unwrap();
            for (requested, input) in &reads {
                let response = invoke(&fixture, requested, input.clone(), false).await;
                assert_eq!(
                    response.status,
                    if action == requested { 200 } else { 403 },
                    "allowed {action}, requested {requested}: {:?}",
                    response.envelope
                );
                outputs.push(serde_json::to_string(&response.envelope).unwrap());
                outputs.push(format!("{:?}", response.envelope));
            }
            let context = ExecutionContext::new("default").unwrap();
            let discovery = fixture
                .runtime
                .service_discovery(&fixture.identity, &context, SERVICE_ID)
                .unwrap();
            let targets = ManagementCommand::parse(action, inputs)
                .unwrap()
                .scopes()
                .unwrap();
            let actions = discovery.actions(None, None, None, Some(&targets)).unwrap();
            assert_eq!(actions.actions, vec![(*action).to_owned()]);
            outputs.push(serde_json::to_string(&actions).unwrap());
            for kind in [
                "broker_principal",
                "broker_group",
                "broker_grant",
                "broker_connection",
            ] {
                if let Ok(resources) = discovery.resources(&crate::ResourceListQuery {
                    resource_type: Some(ResourceType::from_static(kind)),
                    ..Default::default()
                }) {
                    outputs.push(serde_json::to_string(&resources).unwrap());
                }
            }
        }
        outputs
    }
    .with_subscriber(subscriber)
    .await;
    let events = captured.take();
    assert!(
        !events.is_empty(),
        "capture must observe the invocation task"
    );
    let mut observed = outputs;
    observed.push(serde_json::to_string(&events).unwrap());
    observed.push(fs::read_to_string(fixture.directory.path().join("audit.jsonl")).unwrap());
    for output in observed {
        for canary in &canaries {
            assert!(
                !output.contains(canary),
                "private canary appeared in a narrow public surface: {canary}"
            );
        }
    }
}

fn missing_reference_capability_fixture(attested: bool) -> Fixture {
    let mut fixture = fixture(false);
    let issued = fixture.runtime.managed_store().unwrap().issue_broker_token(
        fixture.runtime.broker_token_hasher().unwrap(), crate::BrokerTokenIssueRequest {
            principal_id:"operator".into(),name:"relayed management".into(),token_class:BrokerTokenClass::AgentInvoke,
            scopes:json!({"allowedServices":[SERVICE_ID],"allowedExecutionContexts":["default"]}),
            expires_at:None,created_by:"admin".into(),
        }).unwrap();
    let caller_path = fixture
        .directory
        .path()
        .join("caller-without-encryption.token");
    fs::write(&caller_path, "synthetic-caller-without-encryption").unwrap();
    let mut config = (*fixture.runtime.config).clone();
    config.identity.trusted_callers.insert(
        "relay".into(),
        crate::TrustedCallerConfig {
            credential_ref: format!("file:{}", caller_path.display()),
            credential_transport: crate::TrustedCallerCredentialTransport::CallerAuthorization,
            username_namespace: attested.then(|| "workspace".into()),
            context_mode: crate::TrustedCallerContextMode::Fixed,
            execution_context: Some("default".into()),
            allowed_execution_contexts: None,
            allow_forwarded_identity: false,
        },
    );
    // Startup currently requires encryption for any managed store. Exercise the
    // independent runtime prerequisites by constructing a validated candidate
    // before caller-generation activation, then removing its loaded key ring.
    // The identities below still come from real trusted-caller ingress.
    fixture.runtime = BrokerRuntime::new_for_reload(config, &fixture.runtime).unwrap();
    assert!(fixture.runtime.credential_key_ring().is_some());
    assert!(
        fixture
            .runtime
            .trusted_callers
            .iter()
            .all(|caller| caller.secret_reference_contract().is_none())
    );
    let mut headers = HeaderMap::from_iter([(
        http::header::HeaderName::from_static("x-agent-access-caller-authorization"),
        "Bearer synthetic-caller-without-encryption"
            .parse()
            .unwrap(),
    )]);
    if attested {
        fixture
            .runtime
            .managed_store()
            .unwrap()
            .create_username_binding("operator", "workspace", "no-encryption-user", "admin")
            .unwrap();
        headers.insert(
            http::header::HeaderName::from_static("x-agent-access-user"),
            "no-encryption-user".parse().unwrap(),
        );
    } else {
        headers.insert(
            http::header::AUTHORIZATION,
            format!("Bearer {}", issued.token).parse().unwrap(),
        );
    }
    let admission = fixture.runtime.admit_mcp_ingress(&headers).unwrap();
    let admitted = fixture
        .runtime
        .resolve_admitted_identity_with_proof(&headers, &admission)
        .unwrap();
    assert_eq!(admitted.identity.caller_id.as_deref(), Some("relay"));
    assert_eq!(admitted.proof.is_some(), attested);
    fixture.identity = admitted.identity;
    fixture.identity_proof = admitted.proof;
    // A loaded key ring alone is insufficient: caller reference authority is
    // unavailable until the candidate has an activated caller contract.
    assert!(
        !fixture
            .runtime
            .can_hold_secret_references(&fixture.identity)
    );
    for action in ["credential.install", "token.create"] {
        assert_eq!(
            fixture
                .runtime
                .broker_management_requirements(&fixture.identity, action)
                .iter()
                .map(|item| item.reason())
                .collect::<Vec<_>>(),
            ["reference_identity_unsupported"]
        );
    }
    fixture.runtime.credential_key_ring = None;
    assert!(fixture.runtime.credential_key_ring().is_none());
    fixture
}

#[tokio::test]
async fn relayed_management_keeps_nonsecret_actions_with_missing_loaded_reference_capability() {
    for attested in [false, true] {
        let fixture = missing_reference_capability_fixture(attested);
        assert!(
            !fixture
                .runtime
                .can_hold_secret_references(&fixture.identity)
        );
        let services = fixture.runtime.api_services_for_identity(
            &fixture.identity,
            &ExecutionContext::new("default").unwrap(),
        );
        let service = services
            .iter()
            .find(|service| service.service == SERVICE_ID)
            .unwrap();
        for action in ["group.view", "group.member.add"] {
            assert!(
                fixture
                    .runtime
                    .broker_management_requirements(&fixture.identity, action)
                    .is_empty()
            );
            assert!(service.actions.iter().any(|item| item.action == action));
            let inputs = if action == "group.view" {
                json!({"groupId":"workers"})
            } else {
                json!({"groupId":"workers","principalId":"worker"})
            };
            let response = invoke(&fixture, action, inputs, false).await;
            assert_eq!(
                response.status, 200,
                "attested={attested} {action}: {:?}",
                response.envelope
            );
        }
        assert!(
            fixture
                .runtime
                .managed_store()
                .unwrap()
                .groups("worker")
                .unwrap()
                .contains(&"workers".into())
        );
        for action in ["credential.install", "token.create"] {
            let requirements = fixture
                .runtime
                .broker_management_requirements(&fixture.identity, action);
            assert_eq!(
                requirements
                    .iter()
                    .map(|item| item.reason())
                    .collect::<Vec<_>>(),
                [
                    "credential_encryption_unavailable",
                    "reference_identity_unsupported"
                ]
            );
            assert!(
                requirements.iter().all(|item| matches!(
                    item,
                    crate::AvailabilityRequirement::LocalRuntime { .. }
                ))
            );
            assert!(!service.actions.iter().any(|item| item.action == action));
            let input = if action == "credential.install" {
                json!({"principalId":"worker","connectionId":"gitlab-main","token":{"secretRef":format!("sr_{}","A".repeat(43))}})
            } else {
                token_create_input(&fixture, &Uuid::new_v4().to_string())
            };
            let response = invoke(&fixture, action, input, false).await;
            assert_eq!(
                response.status, 503,
                "attested={attested} {action}: {:?}",
                response.envelope
            );
            assert_eq!(
                response.envelope.reason_code.as_ref().unwrap().as_str(),
                "access_management_unavailable"
            );
        }
        assert!(
            fixture
                .runtime
                .managed_store()
                .unwrap()
                .list_credentials(Some("worker"))
                .unwrap()
                .is_empty()
        );
        assert!(
            fixture
                .runtime
                .managed_store()
                .unwrap()
                .list_broker_tokens_for_principal("worker")
                .unwrap()
                .is_empty()
        );
    }
}

#[tokio::test]
async fn nonsecret_management_rechecks_identity_with_missing_loaded_reference_capability() {
    for attested in [false, true] {
        let mut fixture = missing_reference_capability_fixture(attested);
        fixture
            .runtime
            .managed_store()
            .unwrap()
            .add_group("worker", "workers", "admin")
            .unwrap();
        if attested {
            let proof = fixture.identity_proof.take();
            let unproven =
                invoke(&fixture, "group.view", json!({"groupId":"workers"}), false).await;
            assert_eq!(unproven.status, 403, "{:?}", unproven.envelope);
            fixture.identity_proof = proof;
        }
        let original = fixture.identity_proof.clone();
        let token_id = fixture.identity.source.as_ref().unwrap().token_id.clone();
        let transition: BeforeCommit = Arc::new(move |runtime| {
            let store = runtime.managed_store().unwrap();
            if let Some(proof) = &original {
                // Restore the same username binding value without refreshing the
                // immutable proof captured by the already admitted command.
                let binding = proof.binding_id().unwrap();
                store
                    .set_username_binding_enabled("operator", binding, false, 1, "admin")
                    .unwrap();
                store
                    .set_username_binding_enabled("operator", binding, true, 2, "admin")
                    .unwrap();
            } else {
                store
                    .revoke_broker_token(token_id.as_deref().unwrap(), "admin")
                    .unwrap();
            }
        });
        let denied = invoke_with_commit_control(
            &fixture,
            "group.member.remove",
            json!({"principalId":"worker","groupId":"workers"}),
            false,
            Some(transition),
            None,
        )
        .await;
        assert_eq!(
            denied.status, 403,
            "attested={attested}: {:?}",
            denied.envelope
        );
        assert_eq!(
            denied.envelope.result.as_ref().unwrap()["executionState"],
            "not_committed"
        );
        assert!(
            fixture
                .runtime
                .managed_store()
                .unwrap()
                .groups("worker")
                .unwrap()
                .contains(&"workers".into())
        );
    }
}
