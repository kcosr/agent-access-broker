use super::*;

const PRINCIPALS: [&str; 2] = ["worker", "new-worker"];
const PRINCIPAL_RESOURCES: [&str; 2] = ["worker-scope", "new-worker-scope"];
const SECOND_GRANT: &str = "other-provision";

#[derive(Clone, Copy, Debug)]
enum Family {
    Membership,
    Subject,
    Credential,
}

impl Family {
    fn actions(self) -> &'static [&'static str] {
        match self {
            Self::Membership => &["group.member.add", "group.member.remove"],
            Self::Subject => &["grant.subject.add", "grant.subject.remove"],
            Self::Credential => &["credential.install"],
        }
    }

    fn other_scope(self) -> &'static str {
        match self {
            Self::Membership => "group",
            Self::Subject => "grant",
            Self::Credential => "connection",
        }
    }

    fn other_type(self) -> &'static str {
        match self {
            Self::Membership => "broker_group",
            Self::Subject => "broker_grant",
            Self::Credential => "broker_connection",
        }
    }

    fn others(self) -> [&'static str; 2] {
        match self {
            Self::Membership => ["workers", "operators"],
            Self::Subject => ["service-access", "second-service-access"],
            Self::Credential => ["gitlab-main", "gitlab-secondary"],
        }
    }

    fn other_resources(self) -> [&'static str; 2] {
        match self {
            Self::Membership => ["group-scope", "other-group-scope"],
            Self::Subject => ["grant-scope", "other-grant-scope"],
            Self::Credential => ["connection-scope", "other-connection-scope"],
        }
    }
}

fn selection(ids: &[&str]) -> ResourceSelection {
    ResourceSelection {
        resource_ids: ids.iter().map(|id| (*id).into()).collect(),
        resource_group_ids: vec![],
    }
}

fn set_grant(
    fixture: &Fixture,
    id: &str,
    actions: &[&str],
    resources: ResourceSelection,
    status: &str,
) {
    let version = fixture
        .runtime
        .managed_store()
        .unwrap()
        .policy_grant(id)
        .unwrap()
        .version;
    fixture
        .runtime
        .patch_managed_policy_grant(ManagedPolicyGrantPatchRequest {
            grant_id: id.into(),
            expected_version: version,
            subjects: None,
            execution_contexts: None,
            service: None,
            actions: Some(actions.iter().map(|action| (*action).into()).collect()),
            resources: Some(resources),
            credential_mode: None,
            priority: None,
            status: Some(status.into()),
            description: None,
            updated_by: "admin".into(),
        })
        .unwrap();
}

fn set_subjects(fixture: &Fixture, grant_id: &str, subjects: Vec<String>) {
    let version = fixture
        .runtime
        .managed_store()
        .unwrap()
        .policy_grant(grant_id)
        .unwrap()
        .version;
    fixture
        .runtime
        .patch_managed_policy_grant(ManagedPolicyGrantPatchRequest {
            grant_id: grant_id.into(),
            expected_version: version,
            subjects: Some(subjects),
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
}

fn select_connection(fixture: &mut Fixture, connection: &str) {
    let mut config = (*fixture.runtime.config).clone();
    let secondary = config.credentials.connections["gitlab-main"].clone();
    config
        .credentials
        .connections
        .insert("gitlab-secondary".into(), secondary);
    config
        .credentials
        .per_user
        .get_mut("gitlab")
        .unwrap()
        .connection = Some(connection.into());
    // The native GitLab service selects one connection at a time. Exercise
    // each real eligible connection under the same persisted delegation.
    fixture.runtime = BrokerRuntime::new(config).unwrap();
}

fn matrix_fixture(family: Family) -> Fixture {
    let mut fixture = fixture(false);
    fixture
        .runtime
        .managed_store()
        .unwrap()
        .create_principal(PrincipalWriteRequest {
            principal_id: PRINCIPALS[1].into(),
            kind: "service_account".into(),
            display_name: None,
            email: None,
            external_subject: None,
            created_by: "admin".into(),
            role: PrincipalRole::User,
            self_service_enabled: Some(false),
        })
        .unwrap();
    if matches!(family, Family::Subject) {
        set_subjects(&fixture, "service-access", vec!["user:operator".into()]);
        fixture
            .runtime
            .create_managed_policy_grant(ManagedPolicyGrantCreateRequest {
                grant_id: Some(family.others()[1].into()),
                subjects: vec!["user:operator".into()],
                execution_contexts: vec!["default".into()],
                service: "fake".into(),
                actions: vec!["echo".into()],
                resources: selection(&["project-scope"]),
                credential_mode: "service".into(),
                priority: Some(1),
                status: None,
                description: None,
                created_by: "admin".into(),
            })
            .unwrap();
    }
    if matches!(family, Family::Credential) {
        select_connection(&mut fixture, "gitlab-main");
    }
    fixture
        .runtime
        .create_managed_resource(CreateResourceRequest {
            id: Some(family.other_resources()[1].into()),
            display_name: None,
            resource_type: ResourceType::from_static(family.other_type()),
            selector: ResourceSelector::Exact {
                value: family.others()[1].into(),
            },
            allowed_execution_contexts: vec!["default".into()],
            enabled: true,
            attributes: Default::default(),
            created_by: "admin".into(),
        })
        .unwrap();
    set_grant(
        &fixture,
        "provision",
        family.actions(),
        selection(&PRINCIPAL_RESOURCES),
        "active",
    );
    fixture
        .runtime
        .create_managed_policy_grant(ManagedPolicyGrantCreateRequest {
            grant_id: Some(SECOND_GRANT.into()),
            subjects: vec!["user:operator".into()],
            execution_contexts: vec!["default".into()],
            service: SERVICE_ID.into(),
            actions: family
                .actions()
                .iter()
                .map(|action| (*action).into())
                .collect(),
            resources: selection(&family.other_resources()),
            credential_mode: "service".into(),
            priority: None,
            status: None,
            description: None,
            created_by: "admin".into(),
        })
        .unwrap();
    fixture
}

fn all_resources(family: Family) -> ResourceSelection {
    let mut resources = selection(&PRINCIPAL_RESOURCES);
    resources
        .resource_ids
        .extend(family.other_resources().map(str::to_owned));
    resources
}

fn combine_grants(fixture: &Fixture, family: Family) {
    set_grant(
        fixture,
        SECOND_GRANT,
        family.actions(),
        selection(&family.other_resources()),
        "disabled",
    );
    set_grant(
        fixture,
        "provision",
        family.actions(),
        all_resources(family),
        "active",
    );
}

fn observed_state(fixture: &Fixture, family: Family, principal: &str, other: &str) -> Value {
    let store = fixture.runtime.managed_store().unwrap();
    match family {
        Family::Membership => json!(store.groups(principal).unwrap()),
        Family::Subject => json!(store.policy_grant(other).unwrap()),
        Family::Credential => json!(store.list_credentials(Some(principal)).unwrap()),
    }
}

async fn assert_tuple(
    fixture: &mut Fixture,
    family: Family,
    action: &str,
    principal_index: usize,
    other_index: usize,
    permitted: bool,
    reference: &str,
) {
    let principal = PRINCIPALS[principal_index];
    let other = family.others()[other_index];
    if matches!(family, Family::Credential) {
        select_connection(fixture, other);
    }
    let store = fixture.runtime.managed_store().unwrap();
    // Establish a real state transition for both add and remove. A denied
    // request must preserve that state, including a grant's exact version.
    match family {
        Family::Membership if action.ends_with("remove") => {
            store.add_group(principal, other, "admin").unwrap();
        }
        Family::Membership => store.remove_group(principal, other).unwrap(),
        Family::Subject => {
            let mut subjects = vec!["user:operator".into()];
            if action.ends_with("remove") {
                subjects.push(format!("user:{principal}"));
            }
            set_subjects(fixture, other, subjects);
        }
        Family::Credential => {
            if store
                .list_credentials(Some(principal))
                .unwrap()
                .iter()
                .any(|credential| credential.service == other)
            {
                store
                    .delete_connection_credential(
                        principal,
                        other,
                        "gitlab-access-token",
                        crate::CredentialManagementPurpose::Administrative,
                    )
                    .unwrap();
            }
        }
    }
    let scopes = ResourceScopes::from([
        ("principal".into(), vec![principal.into()]),
        (family.other_scope().into(), vec![other.into()]),
    ]);
    let context = ExecutionContext::new("default").unwrap();
    let discovered = fixture
        .runtime
        .service_discovery(&fixture.identity, &context, SERVICE_ID)
        .map(|service| service.actions(None, None, None, Some(&scopes)).unwrap())
        .map(|result| {
            assert_eq!(result.match_kind, crate::ActionMatchKind::CompleteTargets);
            assert!(result.resource.is_none());
            result.actions.contains(&action.to_owned())
        })
        .unwrap_or(false);
    assert_eq!(discovered, permitted, "{family:?} {action} {scopes:?}");
    let inputs = match family {
        Family::Membership => json!({"principalId":principal,"groupId":other}),
        Family::Subject => json!({
            "principalId":principal,"grantId":other,
            "expectedVersion":store.policy_grant(other).unwrap().version
        }),
        Family::Credential => {
            json!({"principalId":principal,"connectionId":other,"token":{"secretRef":reference}})
        }
    };
    let before = observed_state(fixture, family, principal, other);
    let response = invoke(fixture, action, inputs, false).await;
    assert_eq!(
        response.status,
        if permitted { 200 } else { 403 },
        "{family:?} {action} {scopes:?}: {:?}",
        response.envelope
    );
    assert_eq!(response.envelope.resource_scopes, scopes);
    if !permitted {
        assert_eq!(
            response.envelope.reason_code,
            Some(ReasonCode::ServiceActionDenied.into())
        );
        assert_eq!(observed_state(fixture, family, principal, other), before);
        return;
    }
    assert_eq!(
        response.envelope.result.as_ref().unwrap()["executionState"],
        "completed"
    );
    let store = fixture.runtime.managed_store().unwrap();
    match family {
        Family::Membership => assert_eq!(
            store.groups(principal).unwrap().contains(&other.into()),
            action.ends_with("add")
        ),
        Family::Subject => assert_eq!(
            store
                .policy_grant(other)
                .unwrap()
                .subjects
                .contains(&format!("user:{principal}")),
            action.ends_with("add")
        ),
        Family::Credential => assert_eq!(
            store
                .resolve_user_credential(
                    fixture.runtime.credential_key_ring().unwrap(),
                    principal,
                    other,
                    "default",
                    "gitlab-access-token",
                )
                .unwrap(),
            agent_access_provider::host::bearer_credential("complete-scopes-secret".into())
        ),
    }
}

fn assert_projected_inventory(fixture: &Fixture, family: Family) {
    let context = ExecutionContext::new("default").unwrap();
    let service = fixture
        .runtime
        .service_discovery(&fixture.identity, &context, SERVICE_ID)
        .unwrap();
    for (kind, values) in [
        ("broker_principal", PRINCIPALS),
        (family.other_type(), family.others()),
    ] {
        let result = service
            .resources(&crate::ResourceListQuery {
                resource_type: Some(ResourceType::from_static(kind)),
                ..Default::default()
            })
            .unwrap();
        assert_eq!(
            result
                .resources
                .iter()
                .map(|resource| resource.value.as_str())
                .collect::<BTreeSet<_>>(),
            values.into_iter().collect()
        );
        for resource in result.resources {
            let value = serde_json::to_value(resource).unwrap();
            assert!(value.as_object().unwrap().keys().all(|field| {
                matches!(
                    field.as_str(),
                    "id" | "type" | "value" | "displayName" | "inputs"
                )
            }));
        }
    }
}

async fn exercise_complete_grants(family: Family) {
    let mut fixture = matrix_fixture(family);
    let reference = if matches!(family, Family::Credential) {
        capture_reference(&fixture, "complete-scopes-secret")
    } else {
        String::new()
    };
    // One principal-only grant and one other-endpoint-only grant grant no
    // complete operation, despite their combined resource inventory.
    for principal in 0..2 {
        for other in 0..2 {
            for action in family.actions() {
                assert_tuple(
                    &mut fixture,
                    family,
                    action,
                    principal,
                    other,
                    false,
                    &reference,
                )
                .await;
            }
        }
    }
    for (index, id) in ["provision", SECOND_GRANT].into_iter().enumerate() {
        set_grant(
            &fixture,
            id,
            family.actions(),
            selection(&[PRINCIPAL_RESOURCES[index], family.other_resources()[index]]),
            "active",
        );
    }
    // Each one-type inventory can contain both endpoints, while the complete
    // action query and actual invocation retain only the two authored pairs.
    assert_projected_inventory(&fixture, family);
    for principal in 0..2 {
        for other in 0..2 {
            for action in family.actions() {
                assert_tuple(
                    &mut fixture,
                    family,
                    action,
                    principal,
                    other,
                    principal == other,
                    &reference,
                )
                .await;
            }
        }
    }
    combine_grants(&fixture, family);
    for principal in 0..2 {
        for other in 0..2 {
            for action in family.actions() {
                assert_tuple(
                    &mut fixture,
                    family,
                    action,
                    principal,
                    other,
                    true,
                    &reference,
                )
                .await;
            }
        }
    }
}

#[tokio::test]
async fn membership_requires_complete_grants_and_preserves_pairings_for_add_and_remove() {
    exercise_complete_grants(Family::Membership).await;
}

#[tokio::test]
async fn subject_assignment_requires_complete_grants_and_preserves_pairings_for_add_and_remove() {
    exercise_complete_grants(Family::Subject).await;
}

#[tokio::test]
async fn credential_install_requires_complete_grants_and_preserves_pairings() {
    exercise_complete_grants(Family::Credential).await;
}

fn restrict_token(fixture: &mut Fixture, family: Family, resources: &ResourceSelection) {
    let token = fixture
        .runtime
        .managed_store()
        .unwrap()
        .issue_broker_token(
            fixture.runtime.broker_token_hasher().unwrap(),
            crate::BrokerTokenIssueRequest {
                principal_id: "operator".into(),
                name: "endpoint exclusions".into(),
                token_class: BrokerTokenClass::AgentInvoke,
                scopes: json!({
                    "allowedServices":[SERVICE_ID],
                    "allowedExecutionContexts":["default"],
                    "serviceRestrictions":{SERVICE_ID:{"actions":family.actions(),"resources":resources}}
                }),
                expires_at: None,
                created_by: "admin".into(),
            },
        )
        .unwrap();
    fixture.identity = fixture
        .runtime
        .resolve_identity(&HeaderMap::from_iter([(
            http::header::AUTHORIZATION,
            format!("Bearer {}", token.token).parse().unwrap(),
        )]))
        .unwrap();
}

async fn exercise_endpoint_exclusions(family: Family) {
    for token_restriction in [false, true] {
        for exclude_principal in [false, true] {
            let mut fixture = matrix_fixture(family);
            combine_grants(&fixture, family);
            let excluded = if exclude_principal {
                PRINCIPAL_RESOURCES[0]
            } else {
                family.other_resources()[0]
            };
            fixture
                .runtime
                .create_managed_resource_group(crate::CreateResourceGroupRequest {
                    id: Some("endpoint-exclusion".into()),
                    name: "Endpoint exclusion".into(),
                    included_resource_ids: all_resources(family).resource_ids,
                    excluded_resource_ids: vec![excluded.into()],
                    created_by: "admin".into(),
                })
                .unwrap();
            let resources = ResourceSelection {
                // A direct positive selection must not cancel a selected
                // resource group's exclusion of that same endpoint.
                resource_ids: vec![excluded.into()],
                resource_group_ids: vec!["endpoint-exclusion".into()],
            };
            if token_restriction {
                restrict_token(&mut fixture, family, &resources);
            } else {
                set_grant(&fixture, "provision", family.actions(), resources, "active");
            }
            let reference = if matches!(family, Family::Credential) {
                capture_reference(&fixture, "complete-scopes-secret")
            } else {
                String::new()
            };
            for action in family.actions() {
                assert_tuple(&mut fixture, family, action, 0, 0, false, &reference).await;
                // The opposite endpoint still has a viable partner; the
                // exclusion does not erase the whole other dimension.
                let (principal, other) = if exclude_principal { (1, 0) } else { (0, 1) };
                assert_tuple(
                    &mut fixture,
                    family,
                    action,
                    principal,
                    other,
                    true,
                    &reference,
                )
                .await;
            }
        }
    }
}

#[tokio::test]
async fn membership_grant_and_token_exclusions_block_either_endpoint() {
    exercise_endpoint_exclusions(Family::Membership).await;
}

#[tokio::test]
async fn subject_assignment_grant_and_token_exclusions_block_either_endpoint() {
    exercise_endpoint_exclusions(Family::Subject).await;
}

#[tokio::test]
async fn credential_install_grant_and_token_exclusions_block_either_endpoint() {
    exercise_endpoint_exclusions(Family::Credential).await;
}
