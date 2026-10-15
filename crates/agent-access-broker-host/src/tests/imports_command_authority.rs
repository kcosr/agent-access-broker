//! Command import authority over an imported resource type through the real
//! router, store, runtime publication and linked `command` adapter: the
//! Broker checks named resources before dispatch, command-enforced actions
//! pass their top band's grants, and caller discovery, resource discovery
//! and MCP agree with invocation. Dispatch fails closed until processes run,
//! so an admitted call ends `operation_failed` and audit shows which
//! credential mode it used.
use super::imports_command::{CommandFixture, enabled_tickets, mcp_tool_names, request, versions};
use super::imports_foundation::import_broker;
use super::*;
use agent_access_core::{BrokerTokenClass, ManagedPolicyGrantCreateRequest};

const PROBES: [&str; 6] = ["OPS", "ENG", "SEC", "HR", "FIN", "NEWPROJ"];

fn view_action() -> Value {
    json!({"name": "issue.view", "description": "Show a project's issues.", "readOnly": true,
        "inputSchema": {"type": "object", "required": ["project"],
            "properties": {"project": {"type": "string"}}, "additionalProperties": false},
        "resources": {"type": "project", "inputs": ["/project"]}})
}

fn manifest(view: Value) -> Value {
    json!({
        "format": "agent-access-command/1",
        "version": "1.0.0",
        "credential": {"kind": "token", "modes": ["service", "per_user"]},
        "resourceTypes": [{"id": "project", "label": "Project", "pluralLabel": "Projects",
            "example": "OPS", "pattern": "[A-Z][A-Z0-9]{1,9}"}],
        "actions": [
            view,
            {"name": "issue.bulk", "description": "Show issues of projects.", "readOnly": true,
             "inputSchema": {"type": "object", "required": ["projects"],
                "properties": {"projects": {"type": "array", "items": {"type": "string"}}},
                "additionalProperties": false},
             "resources": {"type": "project", "inputs": ["/projects"]}},
            {"name": "issue.search", "description": "Search issues.", "readOnly": true,
             "inputSchema": {"type": "object",
                "properties": {"query": {"type": "string"}}, "additionalProperties": false},
             "resources": {"type": "project"}}
        ]
    })
}

fn grant(
    id: &str,
    subject: &str,
    actions: &[&str],
    mode: &str,
    priority: i32,
    resource_ids: &[&str],
    resource_group_ids: &[&str],
) -> ManagedPolicyGrantCreateRequest {
    ManagedPolicyGrantCreateRequest {
        grant_id: Some(id.into()),
        subjects: vec![subject.into()],
        execution_contexts: vec!["default".into()],
        service: "tickets".into(),
        actions: actions.iter().map(|action| (*action).into()).collect(),
        resources: ResourceSelection {
            resource_ids: resource_ids.iter().map(|id| (*id).into()).collect(),
            resource_group_ids: resource_group_ids.iter().map(|id| (*id).into()).collect(),
        },
        credential_mode: mode.into(),
        priority: Some(priority),
        status: None,
        description: None,
        created_by: "admin".into(),
    }
}

async fn admin(app: &Router, token: &str, method: Method, path: &str, body: Value) {
    let (status, result) = request(app, token, method, path, Some(body)).await;
    assert_eq!(status, StatusCode::OK, "{path}: {result}");
}

/// The resources of the imported type: `wide` covers every project except a
/// security project, a disabled one and one eligible only in another
/// execution context.
async fn project_resources(app: &Router, token: &str) {
    for (id, selector, contexts) in [
        (
            "ops",
            json!({"kind": "exact", "value": "OPS"}),
            vec!["default"],
        ),
        (
            "eng",
            json!({"kind": "exact", "value": "ENG"}),
            vec!["default"],
        ),
        (
            "sec",
            json!({"kind": "exact", "value": "SEC"}),
            vec!["default"],
        ),
        (
            "hr",
            json!({"kind": "exact", "value": "HR"}),
            vec!["default"],
        ),
        (
            "fin",
            json!({"kind": "exact", "value": "FIN"}),
            vec!["external"],
        ),
        ("all", json!({"kind": "all"}), vec!["default", "external"]),
    ] {
        admin(
            app,
            token,
            Method::POST,
            "/v1/admin/policy/resources",
            json!({"id": id, "resourceType": "tickets_project", "selector": selector,
                "allowedExecutionContexts": contexts}),
        )
        .await;
    }
    admin(
        app,
        token,
        Method::PATCH,
        "/v1/admin/policy/resources/hr",
        json!({"expectedVersion": 1, "enabled": false}),
    )
    .await;
    admin(
        app,
        token,
        Method::POST,
        "/v1/admin/policy/resource-groups",
        json!({"id": "wide", "name": "Wide", "includedResourceIds": ["all"],
            "excludedResourceIds": ["sec", "hr", "fin"]}),
    )
    .await;
}

/// The outcome of one call: `admitted` when it reached the dispatch step,
/// which fails closed until processes run, else the denial's reason.
async fn outcome(app: &Router, agent: &str, action: &str, inputs: Value) -> String {
    let (_, response) = request(
        app,
        agent,
        Method::POST,
        &format!("/v1/invoke/tickets/{action}"),
        Some(json!({"inputs": inputs})),
    )
    .await;
    match response["reasonCode"].as_str().unwrap() {
        "operation_failed" => "admitted".into(),
        reason => reason.into(),
    }
}

/// The actions caller discovery offers for `resource`.
async fn actions_for(app: &Router, agent: &str, resource: &str) -> BTreeSet<String> {
    let (status, listed) = request(
        app,
        agent,
        Method::GET,
        &format!("/v1/services/tickets/actions?resource={resource}"),
        None,
    )
    .await;
    // A service with nothing visible to the caller is hidden.
    if status == StatusCode::FORBIDDEN {
        return BTreeSet::new();
    }
    assert_eq!(status, StatusCode::OK, "{resource}: {listed}");
    listed["actions"]
        .as_array()
        .unwrap()
        .iter()
        .map(|action| action.as_str().unwrap().to_owned())
        .collect()
}

/// The actions the service catalog lists for the caller.
async fn catalog_actions(app: &Router, agent: &str) -> BTreeSet<String> {
    let (status, discovered) = request(app, agent, Method::GET, "/v1/services/tickets", None).await;
    // A service with nothing visible to the caller is hidden.
    if status == StatusCode::FORBIDDEN {
        return BTreeSet::new();
    }
    assert_eq!(status, StatusCode::OK, "{discovered}");
    discovered["actions"]
        .as_array()
        .unwrap()
        .iter()
        .map(|action| action["action"].as_str().unwrap().to_owned())
        .collect()
}

/// Per probe value, the actions discovery offers for it.
async fn discovered_reach(app: &Router, agent: &str) -> BTreeMap<&'static str, BTreeSet<String>> {
    let mut reach = BTreeMap::new();
    for probe in PROBES {
        reach.insert(probe, actions_for(app, agent, probe).await);
    }
    reach
}

fn set(actions: &[&str]) -> BTreeSet<String> {
    actions.iter().map(|action| (*action).to_owned()).collect()
}

/// Each probe's Broker-enforced outcome matches whether discovery offers
/// `issue.view` for it.
async fn assert_view_agrees(
    app: &Router,
    agent: &str,
    reach: &BTreeMap<&'static str, BTreeSet<String>>,
) {
    for probe in PROBES {
        let admitted = outcome(app, agent, "issue.view", json!({"project": probe})).await;
        assert_eq!(
            admitted == "admitted",
            reach[probe].contains("issue.view"),
            "{probe}: {admitted} vs {reach:?}"
        );
    }
}

#[cfg(unix)]
#[tokio::test]
async fn imported_types_enforce_broker_and_command_authority_and_discovery_agrees() {
    let mut fixture = CommandFixture::new("tickets", &manifest(view_action()));
    fixture.config.mcp.enabled = true;
    fixture.config.mcp.public_url = Some("https://broker.example.test/mcp".into());
    fixture.config.execution_context = Some(agent_access_core::ExecutionContextConfig {
        allowed_values: vec!["default".into(), "external".into()],
        default_context: Some("default".into()),
    });
    let token = fixture.admin_token();
    let broker = import_broker(&fixture.config).await;
    let app = broker.app();
    let enabled = enabled_tickets(&app, &token, &["service", "per_user"]).await;
    assert_eq!(
        enabled["service"]["acceptedMetadata"]["resourceTypes"][0]["brokerType"],
        "tickets_project"
    );
    project_resources(&app, &token).await;

    let runtime = broker.runtime();
    let store = runtime.managed_store().unwrap();
    for group in ["eng", "ops"] {
        store
            .create_group(agent_access_core::GroupWriteRequest {
                group_id: group.into(),
                display_name: None,
                description: None,
                created_by: "admin".into(),
            })
            .unwrap();
        for principal in ["alice", "charlie"] {
            store.add_group(principal, group, "admin").unwrap();
        }
    }
    store
        .upsert_user_credential(
            runtime.credential_key_ring().unwrap(),
            CredentialWriteRequest {
                owner_principal_id: "alice".into(),
                service: "tickets".into(),
                name: "default".into(),
                profile: "token".into(),
                credential_kind: "bearer_token".into(),
                secret: json!({"token": "alice-example"}),
                metadata: json!({}),
                actor: "admin".into(),
            },
            agent_access_core::CredentialManagementPurpose::Administrative,
        )
        .unwrap();
    let broker_enforced = ["issue.view", "issue.bulk"];
    for grant in [
        grant(
            "search-eng-user",
            "group:eng",
            &["issue.search"],
            "per_user",
            10,
            &[],
            &["wide"],
        ),
        grant(
            "search-ops-service",
            "group:ops",
            &["issue.search"],
            "service",
            10,
            &["ops"],
            &[],
        ),
        // A lower band is never consulted.
        grant(
            "search-eng-low",
            "group:eng",
            &["issue.search"],
            "service",
            0,
            &["all"],
            &[],
        ),
        grant(
            "view-eng-user",
            "group:eng",
            &broker_enforced,
            "per_user",
            10,
            &[],
            &["wide"],
        ),
        grant(
            "view-ops-service",
            "group:ops",
            &broker_enforced,
            "service",
            10,
            &["ops"],
            &[],
        ),
    ] {
        runtime.create_managed_policy_grant(grant).unwrap();
    }
    drop(runtime);
    let every = set(&["issue.view", "issue.bulk", "issue.search"]);
    let scopes = |resources: Option<&[&str]>| {
        let mut scopes =
            json!({"allowedServices": ["tickets"], "allowedExecutionContexts": ["default"]});
        if let Some(resources) = resources {
            scopes["serviceRestrictions"] = json!({"tickets": {
                "actions": ["issue.view", "issue.bulk", "issue.search"],
                "resources": {"resourceIds": resources}}});
        }
        scopes
    };

    // Alice holds both credentials: the search passes both grants; the
    // excluded, disabled and ineligible projects are reachable by nothing.
    let alice = fixture.issue("alice", BrokerTokenClass::AgentInvoke, scopes(None));
    assert_eq!(
        outcome(&app, &alice, "issue.search", json!({})).await,
        "admitted"
    );
    let reach = discovered_reach(&app, &alice).await;
    assert_eq!(reach["OPS"], set(&["issue.search"]), "{reach:?}");
    assert_eq!(reach["ENG"], every, "{reach:?}");
    assert_eq!(reach["NEWPROJ"], every, "{reach:?}");
    for denied in ["SEC", "HR", "FIN"] {
        assert!(reach[denied].is_empty(), "{denied}: {reach:?}");
    }
    assert_view_agrees(&app, &alice, &reach).await;
    // Every named resource needs one grant covering it.
    for (projects, expected) in [
        (json!(["ENG", "NEWPROJ"]), "admitted"),
        (json!(["ENG", "SEC"]), "service_action_denied"),
        (json!(["ENG", "OPS"]), "admitted"),
        (json!(["OPS"]), "service_action_denied"),
    ] {
        assert_eq!(
            outcome(&app, &alice, "issue.bulk", json!({"projects": projects})).await,
            expected,
            "{projects}"
        );
    }
    let (status, listed) = request(
        &app,
        &alice,
        Method::GET,
        "/v1/services/tickets/resources",
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{listed}");
    assert_eq!(
        listed["resources"]
            .as_array()
            .unwrap()
            .iter()
            .map(|resource| resource["value"].as_str().unwrap())
            .collect::<BTreeSet<_>>(),
        BTreeSet::from(["ENG", "OPS"]),
        "{listed}"
    );
    assert_eq!(listed["coverage"][0]["selector"], json!({"kind": "all"}));
    assert_eq!(listed["coverage"][0]["restricted"], true);
    assert_eq!(catalog_actions(&app, &alice).await, every);
    let tools = mcp_tool_names(&app, &alice).await;
    for action in &every {
        let tool = action.replace('.', "_");
        assert!(tools.iter().any(|name| name.ends_with(&tool)), "{tools:?}");
    }

    // A token restricted to ENG and SEC: the personal grant keeps ENG, the
    // service grant's OPS lies outside the token and is not passed.
    let narrowed = fixture.issue(
        "alice",
        BrokerTokenClass::AgentInvoke,
        scopes(Some(&["eng", "sec"])),
    );
    assert_eq!(
        outcome(&app, &narrowed, "issue.search", json!({})).await,
        "admitted"
    );
    let reach = discovered_reach(&app, &narrowed).await;
    assert_eq!(reach["ENG"], every, "{reach:?}");
    for denied in ["OPS", "SEC", "HR", "FIN", "NEWPROJ"] {
        assert!(reach[denied].is_empty(), "{denied}: {reach:?}");
    }
    assert_view_agrees(&app, &narrowed, &reach).await;
    // A token reaching nothing the top band allows denies the search and
    // hides it, even though the lower band covers SEC.
    let outside = fixture.issue(
        "alice",
        BrokerTokenClass::AgentInvoke,
        scopes(Some(&["sec"])),
    );
    assert_eq!(
        outcome(&app, &outside, "issue.search", json!({})).await,
        "service_action_denied"
    );
    assert!(
        !catalog_actions(&app, &outside)
            .await
            .contains("issue.search")
    );
    assert!(
        !mcp_tool_names(&app, &outside)
            .await
            .iter()
            .any(|name| name.ends_with("issue_search"))
    );

    // Charlie has no personal credential: the search passes the service
    // grant alone, and a resource only the personal grant covers is denied
    // when its credential is resolved.
    let charlie = fixture.issue("charlie", BrokerTokenClass::AgentInvoke, scopes(None));
    assert_eq!(
        outcome(&app, &charlie, "issue.search", json!({})).await,
        "admitted"
    );
    let reach = discovered_reach(&app, &charlie).await;
    assert_eq!(reach["OPS"], set(&["issue.search"]), "{reach:?}");
    for denied in ["ENG", "SEC", "HR", "FIN", "NEWPROJ"] {
        assert!(reach[denied].is_empty(), "{denied}: {reach:?}");
    }
    assert_eq!(
        outcome(&app, &charlie, "issue.view", json!({"project": "ENG"})).await,
        "credential_not_found"
    );

    // A refresh that makes the view untyped would leave its grants'
    // resource selections invalid; the acceptance is refused and names them.
    let mut untyped = view_action();
    untyped.as_object_mut().unwrap().remove("resources");
    fixture.write_manifest(&manifest(untyped));
    let current = request(&app, &token, Method::GET, "/v1/admin/imports/tickets", None)
        .await
        .1;
    let (status, discovered) = request(
        &app,
        &token,
        Method::POST,
        "/v1/admin/imports/tickets/discover",
        Some(versions(&current["result"])),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{discovered}");
    let discovered = &discovered["result"];
    let mut accept = versions(discovered);
    accept["manifestHash"] = discovered["preview"]["manifestHash"].clone();
    accept["selections"] = json!(
        discovered["preview"]["manifest"]["tools"]
            .as_array()
            .unwrap()
            .iter()
            .map(|tool| json!({"source": tool["definition"]["source"],
                "action": tool["definition"]["action"], "readOnly": true}))
            .collect::<Vec<_>>()
    );
    accept["confirmAffectedGrants"] = json!(true);
    let (status, refused) = request(
        &app,
        &token,
        Method::POST,
        "/v1/admin/imports/tickets/accept",
        Some(accept),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{refused}");
    let message = refused.to_string();
    assert!(message.contains("view-eng-user"), "{refused}");
    assert!(
        message.contains("does not support resource selections"),
        "{refused}"
    );
    drop(app);
    broker.stop().await;

    // Audit records the mode each admitted search used: none when both were
    // passed, the personal mode under the narrowed token, the service mode
    // for Charlie.
    let audit = fixture.config.audit.as_ref().unwrap().path.clone();
    let modes = read_audit_records(Path::new(&audit))
        .into_iter()
        .filter(|record| record["service"] == "tickets" && record["action"] == "issue.search")
        .map(|record| {
            (
                record["principal"].as_str().unwrap().to_owned(),
                record.get("credentialMode").cloned().unwrap_or(Value::Null),
            )
        })
        .collect::<Vec<_>>();
    assert_eq!(
        modes,
        [
            ("alice".to_owned(), Value::Null),
            ("alice".to_owned(), json!("per_user")),
            ("alice".to_owned(), Value::Null),
            ("charlie".to_owned(), json!("service")),
        ]
    );
}

/// A refresh removes a type and its action; once the type has no resources
/// an acceptance drops it. The quarantined action still names it and fails
/// closed alone, while acceptance, publication and restart succeed and the
/// remaining action keeps its authority.
#[cfg(unix)]
#[tokio::test]
async fn an_action_naming_a_dropped_type_fails_closed_alone() {
    let queue = json!({"id": "queue", "label": "Queue", "pluralLabel": "Queues",
        "example": "triage", "pattern": "[a-z]+", "maxLength": 64});
    let queue_list = json!({"name": "queue.list", "description": "List queued issues.",
        "readOnly": true, "inputSchema": {"type": "object", "additionalProperties": false},
        "resources": {"type": "queue"}});
    let mut initial = manifest(view_action());
    initial["resourceTypes"]
        .as_array_mut()
        .unwrap()
        .push(queue.clone());
    initial["actions"].as_array_mut().unwrap().push(queue_list);
    let fixture = CommandFixture::new("tickets", &initial);
    let token = fixture.admin_token();
    let broker = import_broker(&fixture.config).await;
    let app = broker.app();
    enabled_tickets(&app, &token, &["service", "per_user"]).await;
    admin(
        &app,
        &token,
        Method::POST,
        "/v1/admin/policy/resources",
        json!({"id": "ops", "resourceType": "tickets_project",
            "selector": {"kind": "exact", "value": "OPS"}, "allowedExecutionContexts": ["default"]}),
    )
    .await;
    let runtime = broker.runtime();
    for grant in [
        grant(
            "view-alice",
            "user:alice",
            &["issue.view"],
            "service",
            0,
            &["ops"],
            &[],
        ),
        grant(
            "queue-alice",
            "user:alice",
            &["queue.list"],
            "service",
            0,
            &[],
            &[],
        ),
    ] {
        runtime.create_managed_policy_grant(grant).unwrap();
    }
    drop(runtime);

    // The source drops the queue type and its action; the type has no
    // resources, so the acceptance drops it.
    fixture.write_manifest(&manifest(view_action()));
    let current = request(&app, &token, Method::GET, "/v1/admin/imports/tickets", None)
        .await
        .1;
    let (status, discovered) = request(
        &app,
        &token,
        Method::POST,
        "/v1/admin/imports/tickets/discover",
        Some(versions(&current["result"])),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{discovered}");
    let discovered = &discovered["result"];
    let mut accept = versions(discovered);
    accept["manifestHash"] = discovered["preview"]["manifestHash"].clone();
    accept["selections"] = json!([]);
    let (status, accepted) = request(
        &app,
        &token,
        Method::POST,
        "/v1/admin/imports/tickets/accept",
        Some(accept),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{accepted}");
    assert_eq!(
        accepted["result"]["resourceTypeEffects"]["droppedTypes"],
        json!(["tickets_queue"]),
        "{accepted}"
    );
    let published = broker.runtime();
    let descriptor = published
        .service_descriptors()
        .find(|descriptor| descriptor.service == "tickets")
        .unwrap()
        .clone();
    assert_eq!(
        descriptor.resource_scopes["queue"].resource_type.as_str(),
        "unresolved_resource_type"
    );
    assert_eq!(
        descriptor.resource_scopes["project"].resource_type.as_str(),
        "tickets_project"
    );
    drop(published);
    let alice = fixture.issue(
        "alice",
        BrokerTokenClass::AgentInvoke,
        json!({"allowedServices": ["tickets"], "allowedExecutionContexts": ["default"]}),
    );
    assert_eq!(
        outcome(&app, &alice, "issue.view", json!({"project": "OPS"})).await,
        "admitted"
    );
    assert_ne!(
        outcome(&app, &alice, "queue.list", json!({})).await,
        "admitted"
    );
    assert_eq!(catalog_actions(&app, &alice).await, set(&["issue.view"]));
    drop(app);
    broker.stop().await;
    // The retained grant on the quarantined action still loads.
    BrokerRuntime::new(fixture.config.clone()).unwrap();
}
