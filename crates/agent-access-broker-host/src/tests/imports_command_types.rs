//! Command import resource types through the real router, store, runtime
//! publication and the linked `command` adapter: registration, declared
//! attribute validation and privacy, and the safe-change rules a refresh
//! previews and an acceptance rechecks against the stored resources.
use super::imports_command::{
    CommandFixture, assert_published_accept_result, definition, request, versions,
};
use super::imports_foundation::import_broker;
use super::*;
use agent_access_core::DeleteResourceRequest;

const SERVICE: &str = "tickets";

fn project_type() -> Value {
    json!({
        "id": "project", "label": "Project", "pluralLabel": "Projects",
        "example": "OPS", "pattern": "[A-Z][A-Z0-9]{1,9}",
        "attributes": [
            {"name": "region", "label": "Region", "description": "Hosting region.",
             "required": false, "pattern": "[a-z0-9-]{1,32}"},
            {"name": "webhookSecret", "label": "Webhook secret",
             "description": "Per-project signing secret.", "required": false}
        ]
    })
}

fn queue_type() -> Value {
    json!({"id": "queue", "label": "Queue", "pluralLabel": "Queues", "example": "triage",
        "pattern": "[a-z]+", "maxLength": 64})
}

fn view_action() -> Value {
    json!({"name": "issue.view", "description": "Show one issue.", "readOnly": true,
        "inputSchema": {"type": "object", "required": ["project"],
            "properties": {"project": {"type": "string"}}, "additionalProperties": false},
        "resources": {"type": "project", "inputs": ["/project"]}})
}

fn queue_action() -> Value {
    json!({"name": "queue.list", "description": "List queued issues.", "readOnly": true,
        "inputSchema": {"type": "object", "additionalProperties": false},
        "resources": {"type": "queue"}})
}

fn ping_action() -> Value {
    json!({"name": "ping", "description": "Check the command.", "readOnly": true,
        "inputSchema": {"type": "object", "additionalProperties": false}})
}

fn manifest(types: Vec<Value>, actions: Vec<Value>) -> Value {
    json!({"format": "agent-access-command/1", "version": "1.0.0",
        "resourceTypes": types, "actions": actions})
}

fn initial_manifest() -> Value {
    manifest(
        vec![project_type(), queue_type()],
        vec![view_action(), queue_action(), ping_action()],
    )
}

/// The project type with `change` applied.
fn project_with(change: impl FnOnce(&mut Value)) -> Value {
    let mut project = project_type();
    change(&mut project);
    project
}

async fn current(app: &Router, token: &str) -> Value {
    let (status, current) = request(
        app,
        token,
        Method::GET,
        &format!("/v1/admin/imports/{SERVICE}"),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{current}");
    current["result"].clone()
}

/// Runs discovery and returns the preview result.
async fn discover(app: &Router, token: &str) -> Value {
    let current = current(app, token).await;
    let (status, discovered) = request(
        app,
        token,
        Method::POST,
        &format!("/v1/admin/imports/{SERVICE}/discover"),
        Some(versions(&current)),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{discovered}");
    discovered["result"].clone()
}

/// Every supported tool of a preview, accepted as a read.
fn all_selections(discovered: &Value) -> Value {
    json!(
        discovered["preview"]["manifest"]["tools"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|tool| tool["unsupportedReason"].is_null())
            .map(|tool| json!({"source": tool["definition"]["source"],
                "action": tool["definition"]["action"], "readOnly": true}))
            .collect::<Vec<_>>()
    )
}

/// Accepts `discovered` with `selections` and extra body fields.
async fn accept_with(
    app: &Router,
    token: &str,
    discovered: &Value,
    selections: Value,
    extra: Value,
) -> (StatusCode, Value) {
    let mut body = versions(discovered);
    body["manifestHash"] = discovered["preview"]["manifestHash"].clone();
    body["selections"] = selections;
    body["confirmAffectedGrants"] = json!(true);
    for (key, value) in extra.as_object().unwrap() {
        body[key] = value.clone();
    }
    request(
        app,
        token,
        Method::POST,
        &format!("/v1/admin/imports/{SERVICE}/accept"),
        Some(body),
    )
    .await
}

/// Accepts every supported tool of `discovered`.
async fn accept(app: &Router, token: &str, discovered: &Value) -> Value {
    let (status, accepted) = accept_with(
        app,
        token,
        discovered,
        all_selections(discovered),
        json!({}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{accepted}");
    assert_published_accept_result(&accepted["result"]);
    accepted["result"].clone()
}

/// Creates the import and accepts the initial manifest's types and actions.
async fn accepted_import(app: &Router, token: &str) -> Value {
    let (status, created) = request(
        app,
        token,
        Method::POST,
        "/v1/admin/imports",
        Some(definition(SERVICE, SERVICE, &[])),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{created}");
    let discovered = discover(app, token).await;
    accept(app, token, &discovered).await
}

async fn create_resource(
    app: &Router,
    token: &str,
    id: &str,
    resource_type: &str,
    value: &str,
    attributes: Value,
) -> (StatusCode, Value) {
    request(
        app,
        token,
        Method::POST,
        "/v1/admin/policy/resources",
        Some(json!({"id": id, "resourceType": resource_type,
            "selector": {"kind": "exact", "value": value},
            "allowedExecutionContexts": ["default"], "attributes": attributes})),
    )
    .await
}

fn delete_resource(runtime: &BrokerRuntime, id: &str) {
    let version = runtime
        .managed_store()
        .unwrap()
        .resource(id)
        .unwrap()
        .version;
    runtime
        .delete_managed_resource(DeleteResourceRequest {
            id: id.into(),
            expected_version: version,
            updated_by: "admin".into(),
        })
        .unwrap();
}

/// The preview's change for manifest type `id`.
fn type_change<'a>(discovered: &'a Value, id: &str) -> &'a Value {
    discovered["resourceTypeChanges"]
        .as_array()
        .unwrap()
        .iter()
        .find(|change| change["id"] == id)
        .unwrap_or_else(|| panic!("no change for {id}: {discovered}"))
}

fn registered_types(runtime: &BrokerRuntime) -> Vec<String> {
    runtime
        .resource_type_metadata()
        .into_iter()
        .map(|metadata| metadata.id.as_str().to_owned())
        .collect()
}

fn action_statuses(result: &Value) -> BTreeMap<String, String> {
    result["service"]["actions"]
        .as_array()
        .unwrap()
        .iter()
        .map(|action| {
            (
                action["definition"]["action"].as_str().unwrap().to_owned(),
                action["status"].as_str().unwrap().to_owned(),
            )
        })
        .collect()
}

/// The success completion records of acceptances, in order.
fn acceptance_completions(fixture: &CommandFixture) -> Vec<Value> {
    read_audit_records(Path::new(&fixture.config.audit.as_ref().unwrap().path))
        .into_iter()
        .filter(|record| {
            record["providerAudit"]["management"]["operation"] == "admin.imports.accept"
                && record["providerAudit"]["management"]["phase"] == "success"
        })
        .collect()
}

/// The `/v1/resource-types` entry of `id`.
async fn listed_type(app: &Router, token: &str, id: &str) -> Value {
    let (status, listed) = request(app, token, Method::GET, "/v1/resource-types", None).await;
    assert_eq!(status, StatusCode::OK, "{listed}");
    listed["resourceTypes"]
        .as_array()
        .unwrap()
        .iter()
        .find(|entry| entry["id"] == id)
        .cloned()
        .unwrap_or_else(|| panic!("{id} is not listed: {listed}"))
}

async fn patch_resource(app: &Router, token: &str, id: &str, patch: Value) -> (StatusCode, Value) {
    let (status, current) = request(
        app,
        token,
        Method::GET,
        &format!("/v1/admin/policy/resources/{id}"),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{current}");
    let mut body = patch;
    body["expectedVersion"] = current["result"]["version"].clone();
    request(
        app,
        token,
        Method::PATCH,
        &format!("/v1/admin/policy/resources/{id}"),
        Some(body),
    )
    .await
}

/// The runtime's published attribute bindings equal the store's.
fn assert_bindings_match_store(runtime: &BrokerRuntime) {
    let stored = runtime
        .managed_store()
        .unwrap()
        .load_policy_snapshot()
        .unwrap();
    assert_eq!(
        runtime.published_attribute_bindings(),
        stored.catalog.attribute_bindings
    );
    assert_eq!(runtime.policy_generation(), stored.revision.generation);
}

#[cfg(unix)]
#[tokio::test]
async fn accepted_types_register_validate_privately_and_survive_restart() {
    let fixture = CommandFixture::new(SERVICE, &initial_manifest());
    let token = fixture.admin_token();
    let broker = import_broker(&fixture.config).await;
    let app = broker.app();
    let (status, created) = request(
        &app,
        &token,
        Method::POST,
        "/v1/admin/imports",
        Some(definition(SERVICE, SERVICE, &[])),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{created}");
    let discovered = discover(&app, &token).await;
    let project = type_change(&discovered, "project");
    assert_eq!(project["brokerType"], "tickets_project");
    assert_eq!(project["change"], "added");
    assert_eq!(project["outcome"], "applied");
    assert_eq!(project["editable"], true);
    assert_eq!(project["blocked"], false);
    assert_eq!(
        type_change(&discovered, "queue")["brokerType"],
        "tickets_queue"
    );

    // Added types' Broker type IDs can be chosen, within bounds and free of
    // every other owner's types and this import's other IDs.
    for (ids, expected) in [
        (json!({"project": "git_repository"}), "already registered"),
        (json!({"project": "jira_project"}), "already registered"),
        (
            json!({"project": "unresolved_resource_type"}),
            "already registered",
        ),
        (json!({"project": "Tickets"}), "must match"),
        (json!({"project": "tickets_queue"}), "invalid or duplicated"),
        (json!({"board": "tickets_board"}), "does not declare"),
    ] {
        let (status, rejected) = accept_with(
            &app,
            &token,
            &discovered,
            all_selections(&discovered),
            json!({"resourceTypeIds": ids}),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{ids}: {rejected}");
        assert!(
            rejected.to_string().contains(expected),
            "{expected}: {rejected}"
        );
    }
    let (status, accepted) = accept_with(
        &app,
        &token,
        &discovered,
        all_selections(&discovered),
        json!({"resourceTypeIds": {"project": "ticket_project"}}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{accepted}");
    let accepted = accepted["result"].clone();
    let types = &accepted["service"]["acceptedMetadata"]["resourceTypes"];
    assert_eq!(types[0]["brokerType"], "ticket_project");
    assert_eq!(types[0]["removed"], false);
    assert_eq!(types[1]["brokerType"], "tickets_queue");
    assert!(accepted.get("resourceTypeEffects").is_none(), "{accepted}");
    // The completion audit records the Broker type IDs the acceptance added.
    let completions = acceptance_completions(&fixture);
    assert_eq!(completions.len(), 1, "{completions:?}");
    let target = &completions[0]["providerAudit"]["management"]["target"];
    assert_eq!(target["service"], SERVICE);
    assert_eq!(
        target["resourceTypeIds"],
        json!({"project": "ticket_project", "queue": "tickets_queue"})
    );
    // Listed types name their import; active ones are not marked removed.
    let listed = listed_type(&app, &token, "ticket_project").await;
    assert_eq!(listed["importedService"], SERVICE);
    assert!(listed.get("removed").is_none(), "{listed}");
    assert!(
        listed_type(&app, &token, "git_repository")
            .await
            .get("importedService")
            .is_none()
    );

    // Accepted types are listed for every caller, with attribute names only.
    let (status, listed) = request(&app, &token, Method::GET, "/v1/resource-types", None).await;
    assert_eq!(status, StatusCode::OK, "{listed}");
    let listed_type = listed["resourceTypes"]
        .as_array()
        .unwrap()
        .iter()
        .find(|entry| entry["id"] == "ticket_project")
        .unwrap_or_else(|| panic!("{listed}"));
    assert_eq!(listed_type["label"], "Project");
    assert_eq!(listed_type["selectors"], json!(["exact", "all"]));
    assert_eq!(
        listed_type["attributes"]
            .as_array()
            .unwrap()
            .iter()
            .map(|attribute| (attribute["name"].clone(), attribute["secret"].clone()))
            .collect::<Vec<_>>(),
        [
            (json!("region"), json!(true)),
            (json!("webhookSecret"), json!(true))
        ]
    );

    // A refresh keeps the accepted IDs; they cannot be chosen again.
    let refreshed = discover(&app, &token).await;
    assert_eq!(refreshed["resourceTypeChanges"], json!([]), "{refreshed}");
    let (status, rejected) = accept_with(
        &app,
        &token,
        &refreshed,
        all_selections(&refreshed),
        json!({"resourceTypeIds": {"project": "tickets_project"}}),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{rejected}");
    assert!(
        rejected.to_string().contains("keeps its accepted"),
        "{rejected}"
    );

    // Attributes validate from the declaration, without a configured backend.
    for (attributes, case) in [
        (json!({"region": "EU 1"}), "pattern"),
        (json!({"owner": "avery"}), "unknown attribute"),
        (json!({"region": "x".repeat(33)}), "pattern bound"),
    ] {
        let (status, rejected) =
            create_resource(&app, &token, "ops", "ticket_project", "OPS", attributes).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{case}: {rejected}");
    }
    let (status, rejected) =
        create_resource(&app, &token, "ops", "ticket_project", "ops", json!({})).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{rejected}");
    let (status, created) = create_resource(
        &app,
        &token,
        "ops",
        "ticket_project",
        "OPS",
        json!({"region": "eu-1", "webhookSecret": "s3cr3t-example"}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{created}");
    assert_eq!(
        created["result"]["record"]["configuredAttributes"],
        json!(["region", "webhookSecret"])
    );
    assert!(!created.to_string().contains("s3cr3t-example"));

    // Admin reads show names only; the value is revealed only on request.
    for path in [
        "/v1/admin/policy/resources/ops",
        "/v1/admin/policy/resources",
        "/v1/admin/policy/catalog",
    ] {
        let (status, read) = request(&app, &token, Method::GET, path, None).await;
        assert_eq!(status, StatusCode::OK, "{path}: {read}");
        assert!(
            !read.to_string().contains("s3cr3t-example"),
            "{path}: {read}"
        );
    }
    let (status, revealed) = request(
        &app,
        &token,
        Method::POST,
        "/v1/admin/policy/resources/ops/attributes/webhookSecret/reveal",
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{revealed}");
    assert_eq!(revealed["result"]["value"], "s3cr3t-example");

    // Types survive disabling, retirement and restart, and so do resources.
    let mut enable = versions(&current(&app, &token).await);
    enable["status"] = json!("enabled");
    let (status, enabled) = request(
        &app,
        &token,
        Method::POST,
        &format!("/v1/admin/imports/{SERVICE}/status"),
        Some(enable),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{enabled}");
    for (status_name, confirm) in [("disabled", false), ("retired", true)] {
        let mut body = versions(&current(&app, &token).await);
        body["status"] = json!(status_name);
        body["confirm"] = json!(confirm);
        let (status, changed) = request(
            &app,
            &token,
            Method::POST,
            &format!("/v1/admin/imports/{SERVICE}/status"),
            Some(body),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{status_name}: {changed}");
        let registered = registered_types(&broker.runtime());
        assert!(
            registered.iter().any(|id| id == "ticket_project")
                && registered.iter().any(|id| id == "tickets_queue"),
            "{status_name}: {registered:?}"
        );
    }
    drop(app);
    broker.stop().await;
    let restarted = BrokerRuntime::new(fixture.config.clone()).unwrap();
    let registered = registered_types(&restarted);
    assert!(
        registered.iter().any(|id| id == "ticket_project"),
        "{registered:?}"
    );
    assert_bindings_match_store(&restarted);
    assert_eq!(
        restarted
            .managed_store()
            .unwrap()
            .resource("ops")
            .unwrap()
            .configured_attributes,
        ["region", "webhookSecret"]
    );
}

#[cfg(unix)]
#[tokio::test]
async fn refresh_applies_safe_type_changes_and_deletes_removed_attribute_values() {
    let fixture = CommandFixture::new(SERVICE, &initial_manifest());
    let token = fixture.admin_token();
    let broker = import_broker(&fixture.config).await;
    let app = broker.app();
    accepted_import(&app, &token).await;
    for (id, value, attributes) in [
        (
            "ops",
            "OPS",
            json!({"region": "eu-1", "webhookSecret": "first-secret"}),
        ),
        ("eng", "ENG", json!({"webhookSecret": "second-secret"})),
        ("web", "WEB", json!({})),
    ] {
        let (status, created) =
            create_resource(&app, &token, id, "tickets_project", value, attributes).await;
        assert_eq!(status, StatusCode::OK, "{created}");
    }
    let versions_of = |runtime: &BrokerRuntime| {
        ["ops", "eng", "web"].map(|id| {
            runtime
                .managed_store()
                .unwrap()
                .resource(id)
                .unwrap()
                .version
        })
    };
    let before = versions_of(&broker.runtime());

    // Labels and a new optional attribute apply to a type with resources and
    // touch none of them.
    fixture.write_manifest(&manifest(
        vec![
            project_with(|project| {
                project["label"] = json!("Space");
                project["attributes"][0]["label"] = json!("Hosting region");
                project["attributes"]
                    .as_array_mut()
                    .unwrap()
                    .push(json!({"name": "owner", "label": "Owner", "description": "",
                        "required": false, "pattern": "[a-z]+"}));
            }),
            queue_type(),
        ],
        vec![view_action(), queue_action(), ping_action()],
    ));
    let discovered = discover(&app, &token).await;
    let change = type_change(&discovered, "project");
    assert_eq!(change["change"], "changed");
    assert_eq!(change["outcome"], "applied");
    assert_eq!(
        change["details"],
        json!(["label", "attribute_added", "attribute_text"])
    );
    assert_eq!(change["resourceCount"], 3);
    assert_eq!(change["blocked"], false);
    assert_eq!(change["affectedResources"], json!([]));
    let generation = broker.runtime().policy_generation();
    let accepted = accept(&app, &token, &discovered).await;
    assert!(accepted.get("resourceTypeEffects").is_none(), "{accepted}");
    let runtime = broker.runtime();
    assert_eq!(versions_of(&runtime), before);
    assert_eq!(runtime.policy_generation(), generation);
    assert_eq!(
        runtime
            .resource_type_metadata()
            .into_iter()
            .find(|metadata| metadata.id.as_str() == "tickets_project")
            .unwrap()
            .label,
        "Space"
    );

    // A removed attribute's stored values are deleted on acceptance, each
    // affected resource's version advances, and the runtime's bindings match
    // the store at once, without a reload.
    fixture.write_manifest(&manifest(
        vec![
            project_with(|project| {
                project["attributes"].as_array_mut().unwrap().remove(1);
            }),
            queue_type(),
        ],
        vec![view_action(), queue_action(), ping_action()],
    ));
    let discovered = discover(&app, &token).await;
    let change = type_change(&discovered, "project");
    assert_eq!(
        change["details"],
        json!(["label", "attribute_text", "attribute_removed"])
    );
    assert_eq!(change["affectedResources"], json!(["eng", "ops"]));
    // A value set after the preview is deleted too.
    let (status, patched) = patch_resource(
        &app,
        &token,
        "web",
        json!({"attributes": {"webhookSecret": "late-secret"}}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{patched}");
    let generation = broker.runtime().policy_generation();
    let accepted = accept(&app, &token, &discovered).await;
    let effects = &accepted["resourceTypeEffects"];
    assert_eq!(
        effects["deletedAttributeValues"],
        json!([
            {"resourceId": "eng", "attributes": ["webhookSecret"]},
            {"resourceId": "ops", "attributes": ["webhookSecret"]},
            {"resourceId": "web", "attributes": ["webhookSecret"]}])
    );
    assert_eq!(effects["droppedTypes"], json!([]));
    assert_eq!(effects["previousRevision"]["generation"], generation);
    assert_eq!(effects["revision"]["generation"], generation + 1);
    let runtime = broker.runtime();
    assert_eq!(
        versions_of(&runtime),
        [before[0] + 1, before[1] + 1, before[2] + 2]
    );
    assert_eq!(runtime.policy_generation(), generation + 1);
    assert!(
        runtime
            .managed_store()
            .unwrap()
            .resource("web")
            .unwrap()
            .configured_attributes
            .is_empty()
    );
    // The completion audit names the deleted attributes, never their values.
    let completion = acceptance_completions(&fixture).pop().unwrap();
    let target = &completion["providerAudit"]["management"]["target"];
    assert_eq!(
        target["deletedAttributeValues"],
        effects["deletedAttributeValues"]
    );
    assert_eq!(target["deletedAttributeValueResources"], 3);
    assert_eq!(target["droppedTypes"], json!([]));
    assert_eq!(target["previousRevision"]["generation"], generation);
    assert_eq!(target["revision"]["generation"], generation + 1);
    for secret in ["first-secret", "second-secret", "late-secret"] {
        assert!(!completion.to_string().contains(secret), "{completion}");
    }
    let store = runtime.managed_store().unwrap();
    assert_eq!(
        store.resource("ops").unwrap().configured_attributes,
        ["region"]
    );
    assert!(
        store
            .resource("eng")
            .unwrap()
            .configured_attributes
            .is_empty()
    );
    assert_bindings_match_store(&runtime);
    let (status, revealed) = request(
        &app,
        &token,
        Method::POST,
        "/v1/admin/policy/resources/ops/attributes/webhookSecret/reveal",
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{revealed}");

    // Removing the last attribute leaves no bindings, again without a reload.
    fixture.write_manifest(&manifest(
        vec![
            project_with(|project| project["attributes"] = json!([])),
            queue_type(),
        ],
        vec![view_action(), queue_action(), ping_action()],
    ));
    let discovered = discover(&app, &token).await;
    assert_eq!(
        type_change(&discovered, "project")["affectedResources"],
        json!(["ops"])
    );
    accept(&app, &token, &discovered).await;
    let runtime = broker.runtime();
    assert_eq!(
        versions_of(&runtime),
        [before[0] + 2, before[1] + 1, before[2] + 2]
    );
    assert!(runtime.published_attribute_bindings().is_empty());
    assert_bindings_match_store(&runtime);

    // A pattern or maxLength change applies only while every stored value
    // still matches; the preview lists the others until they are fixed.
    let (status, created) = create_resource(
        &app,
        &token,
        "legacy",
        "tickets_project",
        "LEGACY",
        json!({}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{created}");
    fixture.write_manifest(&manifest(
        vec![
            project_with(|project| {
                project["attributes"] = json!([]);
                project["pattern"] = json!("[A-Z]{3}");
                project["maxLength"] = json!(3);
            }),
            queue_type(),
        ],
        vec![view_action(), queue_action(), ping_action()],
    ));
    let discovered = discover(&app, &token).await;
    let change = type_change(&discovered, "project");
    assert_eq!(change["details"], json!(["pattern", "max_length"]));
    assert_eq!(change["outcome"], "applied");
    assert_eq!(change["blocked"], true);
    assert_eq!(change["blockingResources"], json!(["legacy"]));
    let (status, rejected) = accept_with(
        &app,
        &token,
        &discovered,
        all_selections(&discovered),
        json!({}),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{rejected}");
    assert!(
        rejected.to_string().contains("tickets_project: legacy"),
        "{rejected}"
    );
    delete_resource(&broker.runtime(), "legacy");
    // An exact value edited after the preview so that it no longer fits the
    // pending grammar rejects the acceptance too, naming the resource.
    let (status, patched) = patch_resource(
        &app,
        &token,
        "web",
        json!({"selector": {"kind": "exact", "value": "WEBX"}}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{patched}");
    let (status, rejected) = accept_with(
        &app,
        &token,
        &discovered,
        all_selections(&discovered),
        json!({}),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{rejected}");
    assert!(
        rejected.to_string().contains("tickets_project: web"),
        "{rejected}"
    );
    // The blocking resources are also listed for clients.
    assert_eq!(
        rejected["target"]["resources"],
        json!([{"type": "tickets_project", "id": "web"}]),
        "{rejected}"
    );
    assert!(rejected["target"].get("affectedGrants").is_none());
    let (status, patched) = patch_resource(
        &app,
        &token,
        "web",
        json!({"selector": {"kind": "exact", "value": "WEB"}}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{patched}");
    let (status, preview) = request(
        &app,
        &token,
        Method::GET,
        &format!("/v1/admin/imports/{SERVICE}/preview"),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{preview}");
    assert_eq!(type_change(&preview["result"], "project")["blocked"], false);
    accept(&app, &token, &discovered).await;
    let runtime = broker.runtime();
    let project = runtime
        .resource_types()
        .get(&ResourceType::new("tickets_project").unwrap())
        .unwrap()
        .clone();
    assert!(project.is_canonical_target("OPS"));
    assert!(!project.is_canonical_target("LEGACY"));
    assert_bindings_match_store(&runtime);
    drop((runtime, app));
    broker.stop().await;
    let restarted = BrokerRuntime::new(fixture.config.clone()).unwrap();
    assert_bindings_match_store(&restarted);
}

#[cfg(unix)]
#[tokio::test]
async fn incompatible_changes_need_a_new_id_and_removed_types_stay_until_unused() {
    let fixture = CommandFixture::new(SERVICE, &initial_manifest());
    let token = fixture.admin_token();
    let broker = import_broker(&fixture.config).await;
    let app = broker.app();
    let accepted = accepted_import(&app, &token).await;
    let accepted_project = accepted["service"]["acceptedMetadata"]["resourceTypes"][0].clone();
    let (status, created) = create_resource(
        &app,
        &token,
        "ops",
        "tickets_project",
        "OPS",
        json!({"region": "eu-1"}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{created}");

    // New required attributes, optional ones made required and changed
    // attribute patterns need a new type id while resources exist: the
    // actions using the type are unsupported and quarantined, and the
    // accepted declaration stays.
    for project in [
        project_with(|project| {
            project["attributes"].as_array_mut().unwrap().push(
                json!({"name": "owner", "label": "Owner", "description": "", "required": true}),
            );
        }),
        project_with(|project| project["attributes"][1]["required"] = json!(true)),
        project_with(|project| project["attributes"][0]["pattern"] = json!("[a-z]+")),
    ] {
        fixture.write_manifest(&manifest(
            vec![project, queue_type()],
            vec![view_action(), queue_action(), ping_action()],
        ));
        let discovered = discover(&app, &token).await;
        let change = type_change(&discovered, "project");
        assert_eq!(change["outcome"], "needs_new_id", "{change}");
        assert_eq!(change["blockingResources"], json!(["ops"]));
        let view = discovered["preview"]["manifest"]["tools"]
            .as_array()
            .unwrap()
            .iter()
            .find(|tool| tool["definition"]["source"]["name"] == "issue.view")
            .unwrap();
        assert!(
            view["unsupportedReason"]
                .as_str()
                .unwrap()
                .contains("declare it under a new id"),
            "{view}"
        );
        assert_eq!(action_statuses(&discovered)["issue.view"], "quarantined");
        assert_eq!(
            discovered["preview"]["manifest"]["serviceMetadata"]["resourceTypes"][0],
            accepted_project
        );
        let accepted = accept(&app, &token, &discovered).await;
        assert_eq!(
            accepted["service"]["acceptedMetadata"]["resourceTypes"][0],
            accepted_project
        );
        assert_eq!(action_statuses(&accepted)["issue.view"], "quarantined");
    }

    // A removed type with resources is retained: its actions are
    // quarantined, it accepts no new resources, and existing ones stay valid.
    let (status, created) =
        create_resource(&app, &token, "triage", "tickets_queue", "triage", json!({})).await;
    assert_eq!(status, StatusCode::OK, "{created}");
    fixture.write_manifest(&manifest(
        vec![project_type()],
        vec![view_action(), ping_action()],
    ));
    let discovered = discover(&app, &token).await;
    let change = type_change(&discovered, "queue");
    assert_eq!(
        (change["change"].clone(), change["outcome"].clone()),
        (json!("removed"), json!("retained"))
    );
    assert_eq!(change["blockingResources"], json!(["triage"]));
    assert_eq!(action_statuses(&discovered)["queue.list"], "quarantined");
    let accepted = accept(&app, &token, &discovered).await;
    let queue = &accepted["service"]["acceptedMetadata"]["resourceTypes"][1];
    assert_eq!(
        (queue["brokerType"].clone(), queue["removed"].clone()),
        (json!("tickets_queue"), json!(true))
    );
    assert!(registered_types(&broker.runtime()).contains(&"tickets_queue".to_owned()));
    let listed = listed_type(&app, &token, "tickets_queue").await;
    assert_eq!(listed["removed"], true, "{listed}");
    assert_eq!(listed["importedService"], SERVICE);
    let (status, rejected) =
        create_resource(&app, &token, "intake", "tickets_queue", "intake", json!({})).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{rejected}");
    assert!(
        rejected.to_string().contains("accepts no new resources"),
        "{rejected}"
    );

    // The source then drops its last type and every action. While resources
    // remain, a metadata-only acceptance keeps both types.
    fixture.write_manifest(&manifest(Vec::new(), Vec::new()));
    let discovered = discover(&app, &token).await;
    for id in ["project", "queue"] {
        assert_eq!(type_change(&discovered, id)["outcome"], "retained");
    }
    let (status, accepted) = accept_with(&app, &token, &discovered, json!([]), json!({})).await;
    assert_eq!(status, StatusCode::OK, "{accepted}");
    assert_published_accept_result(&accepted["result"]);
    assert_eq!(
        accepted["result"]["service"]["acceptedMetadata"]["resourceTypes"]
            .as_array()
            .unwrap()
            .iter()
            .map(|declared| declared["removed"].clone())
            .collect::<Vec<_>>(),
        [json!(true), json!(true)]
    );
    assert!(
        action_statuses(&accepted["result"])
            .values()
            .all(|status| status == "quarantined")
    );

    // Once the resources are deleted, a metadata-only acceptance drops the
    // types; nothing else is selectable.
    delete_resource(&broker.runtime(), "ops");
    delete_resource(&broker.runtime(), "triage");
    let discovered = discover(&app, &token).await;
    for id in ["project", "queue"] {
        let change = type_change(&discovered, id);
        assert_eq!(change["outcome"], "dropped");
        assert_eq!(change["blocked"], false);
    }
    let generation = broker.runtime().policy_generation();
    let (status, accepted) = accept_with(&app, &token, &discovered, json!([]), json!({})).await;
    assert_eq!(status, StatusCode::OK, "{accepted}");
    // The type-drop acceptance matches the published result schema.
    assert_published_accept_result(&accepted["result"]);
    let effects = &accepted["result"]["resourceTypeEffects"];
    assert_eq!(effects["deletedAttributeValues"], json!([]));
    assert_eq!(
        effects["droppedTypes"],
        json!(["tickets_project", "tickets_queue"])
    );
    assert_eq!(effects["previousRevision"]["generation"], generation);
    assert_eq!(effects["revision"]["generation"], generation + 1);
    let completion = acceptance_completions(&fixture).pop().unwrap();
    assert_eq!(
        completion["providerAudit"]["management"]["target"]["droppedTypes"],
        effects["droppedTypes"]
    );
    assert_eq!(
        accepted["result"]["service"]["acceptedMetadata"]["resourceTypes"],
        json!([])
    );
    let runtime = broker.runtime();
    assert_eq!(runtime.policy_generation(), generation + 1);
    let registered = registered_types(&runtime);
    assert!(
        !registered.iter().any(|id| id.starts_with("tickets_")),
        "{registered:?}"
    );
    assert_bindings_match_store(&runtime);

    // A draft still needs a selection.
    let (status, created) = request(
        &app,
        &token,
        Method::POST,
        "/v1/admin/imports",
        Some(definition("drafts", SERVICE, &[])),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{created}");
    let (status, discovered) = request(
        &app,
        &token,
        Method::POST,
        "/v1/admin/imports/drafts/discover",
        Some(versions(&created["result"])),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{discovered}");
    let discovered = &discovered["result"];
    let mut body = versions(discovered);
    body["manifestHash"] = discovered["preview"]["manifestHash"].clone();
    body["selections"] = json!([]);
    let (status, rejected) = request(
        &app,
        &token,
        Method::POST,
        "/v1/admin/imports/drafts/accept",
        Some(body),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{rejected}");
    assert!(
        rejected.to_string().contains("select at least one"),
        "{rejected}"
    );
    drop((runtime, app));
    broker.stop().await;
    BrokerRuntime::new(fixture.config.clone()).unwrap();
}

/// A resource-dependent change the preview allowed, the resource created
/// after the preview that prevents it, and the stored project types before
/// the preview.
struct LateResourceCase {
    name: &'static str,
    project: Value,
    types: Vec<Value>,
    resource: (&'static str, &'static str, &'static str),
}

fn late_resource_cases() -> Vec<LateResourceCase> {
    vec![
        LateResourceCase {
            name: "new required attribute",
            project: project_with(|project| {
                project["attributes"].as_array_mut().unwrap().push(
                    json!({"name": "owner", "label": "Owner", "description": "", "required": true}),
                );
            }),
            types: vec![queue_type()],
            resource: ("ops", "tickets_project", "OPS"),
        },
        LateResourceCase {
            name: "optional attribute made required",
            project: project_with(|project| project["attributes"][0]["required"] = json!(true)),
            types: vec![queue_type()],
            resource: ("ops", "tickets_project", "OPS"),
        },
        LateResourceCase {
            name: "changed attribute pattern",
            project: project_with(|project| project["attributes"][0]["pattern"] = json!("[a-z]+")),
            types: vec![queue_type()],
            resource: ("ops", "tickets_project", "OPS"),
        },
        LateResourceCase {
            name: "pattern no longer matching",
            project: project_with(|project| {
                project["pattern"] = json!("[A-Z]{3}");
                project["maxLength"] = json!(3);
            }),
            types: vec![queue_type()],
            resource: ("legacy", "tickets_project", "LEGACY"),
        },
        LateResourceCase {
            name: "removed type in use",
            project: project_type(),
            types: Vec::new(),
            resource: ("triage", "tickets_queue", "triage"),
        },
    ]
}

#[cfg(unix)]
#[tokio::test]
async fn acceptance_rechecks_resources_created_after_the_preview() {
    for case in late_resource_cases() {
        let fixture = CommandFixture::new(SERVICE, &initial_manifest());
        let token = fixture.admin_token();
        let broker = import_broker(&fixture.config).await;
        let app = broker.app();
        accepted_import(&app, &token).await;
        let mut types = vec![case.project.clone()];
        types.extend(case.types.clone());
        fixture.write_manifest(&manifest(types, vec![view_action(), ping_action()]));
        let discovered = discover(&app, &token).await;
        assert!(
            discovered["resourceTypeChanges"]
                .as_array()
                .unwrap()
                .iter()
                .all(|change| change["blocked"] == false
                    && matches!(change["outcome"].as_str(), Some("applied" | "dropped"))),
            "{}: {discovered}",
            case.name
        );
        let (id, resource_type, value) = case.resource;
        let (status, created) =
            create_resource(&app, &token, id, resource_type, value, json!({})).await;
        assert_eq!(status, StatusCode::OK, "{}: {created}", case.name);
        let (status, rejected) = accept_with(
            &app,
            &token,
            &discovered,
            all_selections(&discovered),
            json!({}),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{}: {rejected}", case.name);
        assert!(
            rejected
                .to_string()
                .contains(&format!("{resource_type}: {id}")),
            "{}: {rejected}",
            case.name
        );
        // Nothing was applied, and the same preview applies once the
        // resource is gone.
        let runtime = broker.runtime();
        assert!(registered_types(&runtime).contains(&resource_type.to_owned()));
        delete_resource(&runtime, id);
        let (status, accepted) = accept_with(
            &app,
            &token,
            &discovered,
            all_selections(&discovered),
            json!({}),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{}: {accepted}", case.name);
        assert_bindings_match_store(&broker.runtime());
        drop((runtime, app));
        broker.stop().await;
    }
}

#[cfg(unix)]
#[tokio::test]
async fn concurrent_resource_writes_and_acceptance_leave_stored_resources_valid() {
    let fixture = CommandFixture::new(SERVICE, &initial_manifest());
    let token = fixture.admin_token();
    let broker = import_broker(&fixture.config).await;
    let app = broker.app();
    accepted_import(&app, &token).await;
    let required_owner = project_with(|project| {
        project["attributes"]
            .as_array_mut()
            .unwrap()
            .push(json!({"name": "owner", "label": "Owner", "description": "", "required": true}));
    });
    fixture.write_manifest(&manifest(
        vec![required_owner, queue_type()],
        vec![view_action(), queue_action(), ping_action()],
    ));
    let discovered = discover(&app, &token).await;
    assert_eq!(type_change(&discovered, "project")["outcome"], "applied");
    let ((accept_status, accepted), (create_status, created)) = tokio::join!(
        accept_with(
            &app,
            &token,
            &discovered,
            all_selections(&discovered),
            json!({})
        ),
        create_resource(&app, &token, "ops", "tickets_project", "OPS", json!({})),
    );
    // The mutations serialize: either the resource came first and the
    // acceptance names it, or the acceptance came first and the resource
    // lacks the new required attribute or targets a superseded generation.
    match (accept_status, create_status) {
        (StatusCode::OK, status) => {
            assert!(
                matches!(status, StatusCode::BAD_REQUEST | StatusCode::CONFLICT),
                "{created}"
            );
            assert!(
                broker
                    .runtime()
                    .managed_store()
                    .unwrap()
                    .resource("ops")
                    .is_err()
            );
        }
        (StatusCode::BAD_REQUEST, StatusCode::OK) => {
            assert!(
                accepted.to_string().contains("tickets_project: ops"),
                "{accepted}"
            );
        }
        statuses => panic!("unexpected outcome {statuses:?}: {accepted} {created}"),
    }
    assert_bindings_match_store(&broker.runtime());
    drop(app);
    broker.stop().await;
    BrokerRuntime::new(fixture.config.clone()).unwrap();
}

#[cfg(unix)]
#[tokio::test]
async fn attribute_rules_count_only_resources_that_can_hold_attribute_values() {
    let fixture = CommandFixture::new(SERVICE, &initial_manifest());
    let token = fixture.admin_token();
    let broker = import_broker(&fixture.config).await;
    let app = broker.app();
    accepted_import(&app, &token).await;
    // `all` selectors carry no attribute values, so a type whose only
    // resource is one gains a required attribute in place.
    for (id, resource_type) in [
        ("all-projects", "tickets_project"),
        ("all-queues", "tickets_queue"),
    ] {
        let (status, created) = request(
            &app,
            &token,
            Method::POST,
            "/v1/admin/policy/resources",
            Some(
                json!({"id": id, "resourceType": resource_type, "selector": {"kind": "all"},
                "allowedExecutionContexts": ["default"]}),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{created}");
    }
    let owner = |project: &mut Value| {
        project["attributes"]
            .as_array_mut()
            .unwrap()
            .push(json!({"name": "owner", "label": "Owner", "description": "", "required": true}));
    };
    // The queue type is removed at the same time; its `all` resource still
    // keeps it.
    fixture.write_manifest(&manifest(
        vec![project_with(owner)],
        vec![view_action(), ping_action()],
    ));
    let discovered = discover(&app, &token).await;
    let change = type_change(&discovered, "project");
    assert_eq!(change["outcome"], "applied", "{change}");
    assert_eq!(change["resourceCount"], 1);
    assert_eq!(change["blocked"], false);
    assert_eq!(type_change(&discovered, "queue")["outcome"], "retained");
    let accepted = accept(&app, &token, &discovered).await;
    let project = &accepted["service"]["acceptedMetadata"]["resourceTypes"][0];
    assert_eq!(project["attributes"][2]["name"], "owner");
    assert_eq!(project["attributes"][2]["required"], true);
    assert_bindings_match_store(&broker.runtime());

    // An exact resource still holds values: the next required attribute
    // needs a new type id.
    let (status, created) = create_resource(
        &app,
        &token,
        "ops",
        "tickets_project",
        "OPS",
        json!({"owner": "avery"}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{created}");
    fixture.write_manifest(&manifest(
        vec![project_with(|project| {
            owner(project);
            project["attributes"].as_array_mut().unwrap().push(
                json!({"name": "team", "label": "Team", "description": "", "required": true}),
            );
        })],
        vec![view_action(), ping_action()],
    ));
    let discovered = discover(&app, &token).await;
    let change = type_change(&discovered, "project");
    assert_eq!(change["outcome"], "needs_new_id", "{change}");
    assert_eq!(change["blockingResources"], json!(["ops"]));
    drop(app);
    broker.stop().await;
    BrokerRuntime::new(fixture.config.clone()).unwrap();
}

/// A credential-free manifest declaring `ids` as resource types and only an
/// untyped action.
fn many_types_manifest(ids: &[String]) -> Value {
    manifest(
        ids.iter()
            .map(|id| {
                json!({"id": id, "label": id, "pluralLabel": id, "example": "a",
                    "pattern": "[a-z]+"})
            })
            .collect(),
        vec![ping_action()],
    )
}

#[cfg(unix)]
#[tokio::test]
async fn a_full_command_renames_a_type_whose_old_type_keeps_its_resources() {
    let ids = (1..=16).map(|n| format!("t{n:02}")).collect::<Vec<_>>();
    let fixture = CommandFixture::new(SERVICE, &many_types_manifest(&ids));
    let token = fixture.admin_token();
    let broker = import_broker(&fixture.config).await;
    let app = broker.app();
    accepted_import(&app, &token).await;
    let (status, created) =
        create_resource(&app, &token, "kept", "tickets_t01", "kept", json!({})).await;
    assert_eq!(status, StatusCode::OK, "{created}");
    // `t01` becomes `t17`: sixteen declared types plus the retained one.
    let mut renamed = ids.clone();
    renamed[0] = "t17".into();
    fixture.write_manifest(&many_types_manifest(&renamed));
    let discovered = discover(&app, &token).await;
    assert_eq!(type_change(&discovered, "t01")["outcome"], "retained");
    assert_eq!(type_change(&discovered, "t17")["change"], "added");
    let accepted = accept(&app, &token, &discovered).await;
    let types = accepted["service"]["acceptedMetadata"]["resourceTypes"]
        .as_array()
        .unwrap()
        .clone();
    assert_eq!(types.len(), 17);
    assert_eq!(
        types
            .iter()
            .filter(|declared| declared["removed"] == true)
            .count(),
        1
    );
    let registered = registered_types(&broker.runtime());
    assert!(registered.contains(&"tickets_t01".to_owned()));
    assert!(registered.contains(&"tickets_t17".to_owned()));
    drop(app);
    broker.stop().await;
    BrokerRuntime::new(fixture.config.clone()).unwrap();
}

#[cfg(unix)]
#[tokio::test]
async fn acceptance_checks_stored_resources_against_the_new_registry() {
    let fixture = CommandFixture::new(SERVICE, &initial_manifest());
    let token = fixture.admin_token();
    let broker = import_broker(&fixture.config).await;
    let app = broker.app();
    accepted_import(&app, &token).await;
    let (status, created) = create_resource(
        &app,
        &token,
        "ops",
        "tickets_project",
        "OPS",
        json!({"region": "eu-1"}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{created}");
    // Stored state no planning rule looks at, written behind the Broker's
    // back: an attribute the type does not declare.
    let store_path = &fixture.config.managed_store.as_ref().unwrap().path;
    rusqlite::Connection::open(store_path)
        .unwrap()
        .execute(
            "INSERT INTO resource_secret_material(resource_id,attribute_name,material_version,key_id,nonce,ciphertext)
             VALUES('ops','stray','stray-version','test',zeroblob(12),zeroblob(16))",
            [],
        )
        .unwrap();
    // A label change applies no effects, yet the acceptance still checks
    // every stored resource of the import against the new registry.
    fixture.write_manifest(&manifest(
        vec![
            project_with(|project| project["label"] = json!("Space")),
            queue_type(),
        ],
        vec![view_action(), queue_action(), ping_action()],
    ));
    let discovered = discover(&app, &token).await;
    let (status, rejected) = accept_with(
        &app,
        &token,
        &discovered,
        all_selections(&discovered),
        json!({}),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{rejected}");
    assert!(
        rejected.to_string().contains("unknown resource attribute"),
        "{rejected}"
    );
    assert_eq!(
        broker
            .runtime()
            .resource_type_metadata()
            .into_iter()
            .find(|metadata| metadata.id.as_str() == "tickets_project")
            .unwrap()
            .label,
        "Project"
    );
    drop(app);
    broker.stop().await;
}
