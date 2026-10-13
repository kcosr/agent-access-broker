//! Base-administrator management of database-owned imported services.
use super::common::{
    ManagementAccess, ManagementContext, management_context,
    management_pre_audited_success_response, management_provider_error_response,
    management_store_call, management_store_error_response, management_success_response,
    management_write_audit_completion, management_write_audit_preflight,
};
use crate::state::AppState;
use agent_access_core::imports::{
    ImportedActionDefinition, ImportedCredentialMode, ImportedCredentialPurpose, ImportedDiscovery,
    ImportedDiscoveryCredential, ImportedServiceDefinition,
};
use agent_access_core::*;
use agent_access_provider::{ExecutionCredential, is_action_name, is_service_name};
use axum::{
    body::Bytes,
    extract::{ConnectInfo, Path, State},
    http::HeaderMap,
    response::Response,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    net::SocketAddr,
    sync::Arc,
};

#[derive(Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Versions {
    expected_version: u64,
    expected_catalog_revision: u64,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct UpdateBody {
    #[serde(flatten)]
    versions: Versions,
    definition: ImportedServiceDefinition,
    #[serde(default)]
    confirm_affected_grants: bool,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Selection {
    source: Value,
    action: String,
    label: Option<String>,
    read_only: bool,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct AcceptBody {
    #[serde(flatten)]
    versions: Versions,
    manifest_hash: String,
    selections: Vec<Selection>,
    #[serde(default)]
    confirm_affected_grants: bool,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct StatusBody {
    #[serde(flatten)]
    versions: Versions,
    status: String,
    #[serde(default)]
    confirm: bool,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SecretBody {
    #[serde(flatten)]
    versions: Versions,
    token: String,
}

fn invalid(message: &str) -> ManagedStoreError {
    ManagedStoreError::InputInvalid(message.into())
}
fn parse<T: serde::de::DeserializeOwned>(body: Bytes) -> Result<T, ManagedStoreError> {
    let value: Value =
        serde_json::from_slice(&body).map_err(|_| invalid("invalid import request body"))?;
    if !value.is_object() {
        return Err(invalid("import request body must be an object"));
    }
    serde_json::from_value(value).map_err(|_| invalid("invalid import request fields"))
}
fn parse_versions(body: Bytes) -> Result<Versions, ManagedStoreError> {
    let value: Value = parse(body)?;
    if value.as_object().is_none_or(|object| {
        object
            .keys()
            .any(|key| key != "expectedVersion" && key != "expectedCatalogRevision")
    }) {
        return Err(invalid("invalid import version request fields"));
    }
    serde_json::from_value(value).map_err(|_| invalid("import versions are required"))
}
fn current_record(
    context: &ManagementContext,
    service: &str,
) -> Result<ImportedServiceRecord, ManagedStoreError> {
    context
        .snapshot
        .runtime
        .imported_catalog()
        .service(service)
        .cloned()
        .ok_or_else(|| invalid("imported service was not found"))
}
fn check_versions(
    context: &ManagementContext,
    record: &ImportedServiceRecord,
    versions: &Versions,
) -> Result<(), ManagedStoreError> {
    if record.version != versions.expected_version
        || context.snapshot.runtime.import_catalog_revision() != versions.expected_catalog_revision
    {
        return Err(ManagedStoreError::VersionConflict);
    }
    Ok(())
}
fn record_result(runtime: &BrokerRuntime, catalog: &ImportedCatalog, service: &str) -> Value {
    let record = catalog.service(service);
    let unavailable = runtime.imported_service_unavailable_reason(service);
    json!({"catalogRevision": catalog.revision, "service":record, "operatorAllowed": record.is_some_and(|record| operator_allowed(runtime,&record.definition)), "available":unavailable.is_none(), "unavailableReason":unavailable,"importAuthentication":runtime.import_authentication(),"scopedMcp":runtime.scoped_mcp_diagnostics(service)})
}
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ScopedMcpWarning {
    tool_index: usize,
    proposed_action: String,
    codes: Vec<mcp::ScopedMcpIssueCode>,
}

fn preview_scoped_mcp_warnings(
    runtime: &BrokerRuntime,
    record: &ImportedServiceRecord,
    preview: Option<&ImportedPreview>,
) -> Result<Vec<ScopedMcpWarning>, ManagedStoreError> {
    let Some(preview) = preview else {
        return Ok(Vec::new());
    };
    let manifest: ImportedDiscovery = serde_json::from_value(preview.manifest.clone())
        .map_err(|_| invalid("stored discovery preview is invalid"))?;
    Ok(scoped_mcp_warnings(record, &manifest, |action| {
        runtime
            .imported_scoped_mcp_name(&record.definition, action)
            .ok()
    }))
}

// Warnings describe proposals, not accepted authority. Never alter the manifest,
// its hash, or unsupported_reason: these actions remain usable in aggregate MCP.
fn scoped_mcp_warnings(
    record: &ImportedServiceRecord,
    manifest: &ImportedDiscovery,
    name_for: impl Fn(&ImportedActionDefinition) -> Option<String>,
) -> Vec<ScopedMcpWarning> {
    let mut codes = vec![BTreeSet::new(); manifest.tools.len()];
    let mut names = BTreeMap::<String, Vec<Option<usize>>>::new();
    for (index, tool) in manifest.tools.iter().enumerate() {
        let name = name_for(&tool.definition);
        if let Some(issue) = mcp::scoped_name_issue(name.as_deref()) {
            codes[index].insert(issue);
        } else if let Some(name) = name {
            names.entry(name).or_default().push(Some(index));
        }
    }
    for action in record.actions.iter().filter(|action| {
        action.status == ImportedActionStatus::Enabled
            && !manifest
                .tools
                .iter()
                .any(|tool| tool.definition.source == action.definition.source)
    }) {
        if let Some(name) = name_for(&action.definition)
            && mcp::scoped_name_issue(Some(&name)).is_none()
        {
            names.entry(name).or_default().push(None);
        }
    }
    for occurrences in names.values().filter(|occurrences| occurrences.len() > 1) {
        for index in occurrences.iter().flatten() {
            codes[*index].insert(mcp::ScopedMcpIssueCode::DuplicateName);
        }
    }
    codes
        .into_iter()
        .enumerate()
        .filter_map(|(index, codes)| {
            (!codes.is_empty()).then(|| ScopedMcpWarning {
                tool_index: index,
                proposed_action: manifest.tools[index].definition.action.clone(),
                codes: codes.into_iter().collect(),
            })
        })
        .collect()
}

fn operator_allowed(runtime: &BrokerRuntime, definition: &ImportedServiceDefinition) -> bool {
    runtime.import_operator_allowed(definition)
}
fn mutation_request(
    record: &ImportedServiceRecord,
    versions: Versions,
    actor: String,
) -> ImportedServiceUpdateRequest {
    ImportedServiceUpdateRequest {
        definition: record.definition.clone(),
        status: record.status,
        actions: record
            .actions
            .iter()
            .map(|action| ImportedActionWrite {
                definition: action.definition.clone(),
                status: action.status,
            })
            .collect(),
        expected_version: versions.expected_version,
        expected_catalog_revision: versions.expected_catalog_revision,
        accepted_preview: None,
        actor,
    }
}
fn source_changed(old: &ImportedActionDefinition, new: &ImportedActionDefinition) -> bool {
    old.input_schema != new.input_schema
        || old.output_schema != new.output_schema
        || behavioral_annotations(&old.annotations) != behavioral_annotations(&new.annotations)
}
fn behavioral_annotations(annotations: &Value) -> Value {
    let mut annotations = annotations.clone();
    if let Some(fields) = annotations
        .get_mut("toolAnnotations")
        .and_then(Value::as_object_mut)
    {
        fields.remove("title");
    }
    annotations
}
fn affected_grants(
    store: &ManagedStore,
    service: &str,
    actions: Option<&BTreeSet<String>>,
) -> Result<Vec<String>, ManagedStoreError> {
    Ok(store
        .policy_grants()?
        .into_iter()
        .filter(|grant| {
            grant.status != "deleted"
                && grant.service == service
                && actions.is_none_or(|actions| {
                    grant.actions.iter().any(|action| actions.contains(action))
                })
        })
        .map(|grant| grant.grant_id)
        .collect())
}
fn grants_by_action(
    store: &ManagedStore,
    service: &str,
) -> Result<BTreeMap<String, Vec<String>>, ManagedStoreError> {
    let mut result = BTreeMap::<String, Vec<String>>::new();
    for grant in store
        .policy_grants()?
        .into_iter()
        .filter(|grant| grant.status != "deleted" && grant.service == service)
    {
        for action in grant.actions {
            result
                .entry(action)
                .or_default()
                .push(grant.grant_id.clone());
        }
    }
    Ok(result)
}

pub(crate) async fn list(
    State(state): State<AppState>,
    ConnectInfo(remote): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> Response {
    let operation = "admin.imports.list";
    let context = match management_context(
        &state,
        remote,
        &headers,
        operation,
        ManagementAccess::AdminRead,
    )
    .await
    {
        Ok(c) => c,
        Err(r) => return *r,
    };
    let catalog = context.snapshot.runtime.imported_catalog();
    management_success_response(&context, operation, None, json!({"catalogRevision":catalog.revision,"services":catalog.services,"operatorEnabled":context.snapshot.runtime.config().imports.enabled,"availableKinds":context.snapshot.runtime.available_import_kinds(),"importAuthentication":context.snapshot.runtime.import_authentication()})).await
}

pub(crate) async fn get(
    State(state): State<AppState>,
    Path(service): Path<String>,
    ConnectInfo(remote): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> Response {
    let operation = "admin.imports.inspect";
    let context = match management_context(
        &state,
        remote,
        &headers,
        operation,
        ManagementAccess::AdminRead,
    )
    .await
    {
        Ok(c) => c,
        Err(r) => return *r,
    };
    let target = Some(json!({"service":service}));
    match current_record(&context, &service) {
        Ok(_) => {
            management_success_response(
                &context,
                operation,
                target,
                record_result(
                    &context.snapshot.runtime,
                    context.snapshot.runtime.imported_catalog(),
                    &service,
                ),
            )
            .await
        }
        Err(e) => management_store_error_response(&context, operation, target, e).await,
    }
}

pub(crate) async fn preview(
    State(state): State<AppState>,
    Path(service): Path<String>,
    ConnectInfo(remote): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> Response {
    let operation = "admin.imports.preview";
    let context = match management_context(
        &state,
        remote,
        &headers,
        operation,
        ManagementAccess::AdminRead,
    )
    .await
    {
        Ok(c) => c,
        Err(r) => return *r,
    };
    preview_response(&context, operation, &service, false).await
}
async fn preview_response(
    context: &ManagementContext,
    operation: &str,
    service: &str,
    preaudited: bool,
) -> Response {
    let target = Some(json!({"service":service}));
    let service_owned = service.to_string();
    let config_revision = format!(
        "{}:{}",
        context.snapshot.generation, context.snapshot.config_hash
    );
    let runtime = context.snapshot.runtime.clone();
    let result = management_store_call(context, move |store| {
        let catalog = store.imported_catalog()?;
        let record = catalog.service(&service_owned).ok_or_else(|| invalid("imported service was not found"))?;
        let preview = store.imported_preview(&service_owned)?.filter(|preview| preview.config_revision == config_revision);
        let affected = affected_grants(&store, &service_owned, None)?;
        let by_action = grants_by_action(&store, &service_owned)?;
        let unavailable = runtime.imported_service_unavailable_reason(&service_owned);
        let warnings = preview_scoped_mcp_warnings(&runtime, record, preview.as_ref())?;
        Ok(json!({"catalogRevision":catalog.revision,"service":record,"preview":preview,"affectedGrants":affected,"affectedGrantsByAction":by_action,"operatorAllowed":operator_allowed(&runtime,&record.definition),"available":unavailable.is_none(),"unavailableReason":unavailable,"importAuthentication":runtime.import_authentication(),"scopedMcp":runtime.scoped_mcp_diagnostics(&service_owned),"scopedMcpWarnings":warnings}))
    }).await;
    match result {
        Ok(result) if preaudited => {
            management_pre_audited_success_response(context, operation, target, result)
        }
        Ok(result) => management_success_response(context, operation, target, result).await,
        Err(e) => management_store_error_response(context, operation, target, e).await,
    }
}

enum Change {
    Create,
    Update,
    Accept,
    Status,
    ActionStatus(String),
    SecretPut(ImportedCredentialPurpose),
    SecretDelete(ImportedCredentialPurpose),
}

macro_rules! service_mutation_handler {
    ($name:ident, $operation:literal, $change:expr) => {
        pub(crate) async fn $name(
            State(state): State<AppState>,
            Path(service): Path<String>,
            ConnectInfo(remote): ConnectInfo<SocketAddr>,
            headers: HeaderMap,
            body: Bytes,
        ) -> Response {
            change(
                &state,
                remote,
                &headers,
                $operation,
                Some(service),
                body,
                $change,
            )
            .await
        }
    };
}
service_mutation_handler!(update, "admin.imports.update", Change::Update);
service_mutation_handler!(accept, "admin.imports.accept", Change::Accept);
service_mutation_handler!(status, "admin.imports.status", Change::Status);
pub(crate) async fn create(
    State(state): State<AppState>,
    ConnectInfo(remote): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    change(
        &state,
        remote,
        &headers,
        "admin.imports.create",
        None,
        body,
        Change::Create,
    )
    .await
}
pub(crate) async fn action_status(
    State(state): State<AppState>,
    Path((service, action)): Path<(String, String)>,
    ConnectInfo(remote): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    change(
        &state,
        remote,
        &headers,
        "admin.imports.actions.status",
        Some(service),
        body,
        Change::ActionStatus(action),
    )
    .await
}
fn purpose(value: &str) -> Result<ImportedCredentialPurpose, ManagedStoreError> {
    match value {
        "execution" => Ok(ImportedCredentialPurpose::Execution),
        "discovery" => Ok(ImportedCredentialPurpose::Discovery),
        "transport" => Ok(ImportedCredentialPurpose::Transport),
        _ => Err(invalid("invalid import credential purpose")),
    }
}
pub(crate) async fn secret_put(
    State(state): State<AppState>,
    Path((service, slot)): Path<(String, String)>,
    ConnectInfo(remote): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    secret_change(&state, remote, &headers, service, slot, body, true).await
}
pub(crate) async fn secret_delete(
    State(state): State<AppState>,
    Path((service, slot)): Path<(String, String)>,
    ConnectInfo(remote): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    secret_change(&state, remote, &headers, service, slot, body, false).await
}
async fn secret_change(
    state: &AppState,
    remote: SocketAddr,
    headers: &HeaderMap,
    service: String,
    slot: String,
    body: Bytes,
    put: bool,
) -> Response {
    let operation = if put {
        "admin.imports.credentials.put"
    } else {
        "admin.imports.credentials.delete"
    };
    let slot = match purpose(&slot) {
        Ok(slot) => slot,
        Err(error) => {
            let context = match management_context(
                state,
                remote,
                headers,
                operation,
                ManagementAccess::AdminWrite,
            )
            .await
            {
                Ok(c) => c,
                Err(r) => return *r,
            };
            return management_store_error_response(
                &context,
                operation,
                Some(json!({"service":service})),
                error,
            )
            .await;
        }
    };
    change(
        state,
        remote,
        headers,
        operation,
        Some(service),
        body,
        if put {
            Change::SecretPut(slot)
        } else {
            Change::SecretDelete(slot)
        },
    )
    .await
}

async fn change(
    state: &AppState,
    remote: SocketAddr,
    headers: &HeaderMap,
    operation: &str,
    service: Option<String>,
    body: Bytes,
    change: Change,
) -> Response {
    let context = match management_context(
        state,
        remote,
        headers,
        operation,
        ManagementAccess::AdminWrite,
    )
    .await
    {
        Ok(c) => c,
        Err(r) => return *r,
    };
    let audit_service = service.clone().or_else(|| {
        serde_json::from_slice::<Value>(&body)
            .ok()?
            .get("service")?
            .as_str()
            .filter(|value| is_service_name(value))
            .map(str::to_owned)
    });
    let mut target = audit_service.map(|service| json!({"service":service}));
    if let (Some(target), Change::SecretPut(purpose) | Change::SecretDelete(purpose)) =
        (&mut target, &change)
    {
        target["credentialPurpose"] = json!(purpose.as_str());
    }
    if let Some(target) = &mut target {
        let request = serde_json::from_slice::<Value>(&body).unwrap_or(Value::Null);
        if let Change::ActionStatus(action) = &change
            && action.len() <= 256
            && is_action_name(action)
        {
            target["action"] = json!(action);
        }
        if matches!(change, Change::Status | Change::ActionStatus(_))
            && let Some(status @ ("enabled" | "disabled" | "retired")) = request["status"].as_str()
        {
            target["status"] = json!(status);
        }
        if matches!(change, Change::Accept) {
            if let Some(hash) = request["manifestHash"].as_str().filter(|hash| {
                hash.len() == 64 && hash.bytes().all(|byte| byte.is_ascii_hexdigit())
            }) {
                target["manifestHash"] = json!(hash);
            }
            if let Some(selections) = request["selections"]
                .as_array()
                .filter(|rows| rows.len() <= 2048)
            {
                target["actions"] = json!(
                    selections
                        .iter()
                        .filter_map(|row| {
                            let action = row["action"]
                                .as_str()
                                .filter(|name| name.len() <= 256 && is_action_name(name))?;
                            Some(json!({"action":action,"readOnly":row["readOnly"].as_bool()?}))
                        })
                        .collect::<Vec<_>>()
                );
            }
        }
    }
    // Auditing contains only identities, never discovery payloads or token material.
    if let Err(response) =
        management_write_audit_preflight(&context, operation, target.clone()).await
    {
        return *response;
    }
    let actor = context.identity.principal.clone();
    let config_revision = format!(
        "{}:{}",
        context.snapshot.generation, context.snapshot.config_hash
    );
    let result = state
        .reloadable
        .imported_service_mutation(context.snapshot.clone(), move |runtime| {
            let store = runtime
                .managed_store()
                .ok_or_else(|| invalid("imported services require managed storage"))?;
            match change {
                Change::Create => {
                    let definition: ImportedServiceDefinition = parse(body)?;
                    runtime.require_import_destination(&definition)?;
                    runtime.require_import_bindings(&definition, None)?;
                    validate_discovery_owner(&definition, &actor)?;
                    let service = definition.service.clone();
                    let record = ImportedServiceRecord {
                        definition: definition.clone(),
                        status: ImportedServiceStatus::Draft,
                        version: 1,
                        actions: vec![],
                        slot_versions: Default::default(),
                        created_at: String::new(),
                        created_by: actor.clone(),
                        updated_at: String::new(),
                        updated_by: actor.clone(),
                    };
                    let providers = runtime.prepare_imported_service_change(&record, None)?;
                    let mutation =
                        store.create_imported_service(definition, &actor, |catalog| {
                            runtime.with_imported_catalog(catalog.clone(), providers)
                        })?;
                    let response = record_result(&mutation.value, &mutation.catalog, &service);
                    Ok((mutation.value, response))
                }
                Change::SecretPut(purpose) => {
                    let service = service.ok_or_else(|| invalid("service is required"))?;
                    let body: SecretBody = parse(body)?;
                    let mut record = checked_record(&runtime, &service, &body.versions)?;
                    runtime.require_import_destination(&record.definition)?;
                    if record.status == ImportedServiceStatus::Retired {
                        return Err(invalid("retired imports cannot receive credentials"));
                    }
                    let token = ExecutionCredential {
                        kind: "bearer_token".into(),
                        username: None,
                        token: Some(body.token.clone()),
                    };
                    // The placeholder only signals presence; the store assigns the material version.
                    record.slot_versions.insert(purpose, "pending".into());
                    let override_token =
                        (purpose == ImportedCredentialPurpose::Transport).then_some(Some(token));
                    let providers =
                        runtime.prepare_imported_service_change(&record, override_token)?;
                    let request = ImportedSecretWriteRequest {
                        service: service.clone(),
                        purpose,
                        expected_version: body.versions.expected_version,
                        expected_catalog_revision: body.versions.expected_catalog_revision,
                        token: body.token,
                        actor,
                    };
                    let mutation = store.write_imported_secret(
                        request,
                        runtime
                            .credential_key_ring()
                            .ok_or_else(|| invalid("import encryption is unavailable"))?,
                        |catalog, proof| {
                            runtime.with_imported_catalog(
                                catalog.clone(),
                                providers.bind_secret_write(proof)?,
                            )
                        },
                    )?;
                    let response = record_result(&mutation.value, &mutation.catalog, &service);
                    Ok((mutation.value, response))
                }
                Change::SecretDelete(purpose) => {
                    let service = service.ok_or_else(|| invalid("service is required"))?;
                    let versions = parse_versions(body)?;
                    let mut record = checked_record(&runtime, &service, &versions)?;
                    record.slot_versions.remove(&purpose);
                    let providers = runtime.prepare_imported_service_change(
                        &record,
                        (purpose == ImportedCredentialPurpose::Transport).then_some(None),
                    )?;
                    let request = ImportedSecretDeleteRequest {
                        service: service.clone(),
                        purpose,
                        expected_version: versions.expected_version,
                        expected_catalog_revision: versions.expected_catalog_revision,
                        actor,
                    };
                    let mutation = store.delete_imported_secret(request, |catalog| {
                        runtime.with_imported_catalog(catalog.clone(), providers)
                    })?;
                    let response = record_result(&mutation.value, &mutation.catalog, &service);
                    Ok((mutation.value, response))
                }
                kind => {
                    let service = service.ok_or_else(|| invalid("service is required"))?;
                    let record = runtime
                        .imported_catalog()
                        .service(&service)
                        .cloned()
                        .ok_or_else(|| invalid("imported service was not found"))?;
                    let request = prepare_update(
                        &runtime,
                        store,
                        &record,
                        actor,
                        &config_revision,
                        body,
                        kind,
                    )?;
                    let mut candidate = record.clone();
                    candidate.definition = request.definition.clone();
                    candidate.status = request.status;
                    candidate.actions = request
                        .actions
                        .iter()
                        .map(|a| ImportedActionRecord {
                            definition: a.definition.clone(),
                            status: a.status,
                            version: 0,
                            definition_hash: String::new(),
                        })
                        .collect();
                    let providers = runtime.prepare_imported_service_change(&candidate, None)?;
                    let mutation = store.update_imported_service(request, |catalog| {
                        runtime.with_imported_catalog(catalog.clone(), providers)
                    })?;
                    let response = record_result(&mutation.value, &mutation.catalog, &service);
                    Ok((mutation.value, response))
                }
            }
        })
        .await;
    match result {
        Ok(result) => management_pre_audited_success_response(&context, operation, target, result),
        Err(error) => management_store_error_response(&context, operation, target, error).await,
    }
}

fn checked_record(
    runtime: &BrokerRuntime,
    service: &str,
    versions: &Versions,
) -> Result<ImportedServiceRecord, ManagedStoreError> {
    let record = runtime
        .imported_catalog()
        .service(service)
        .cloned()
        .ok_or_else(|| invalid("imported service was not found"))?;
    if record.version != versions.expected_version
        || runtime.import_catalog_revision() != versions.expected_catalog_revision
    {
        return Err(ManagedStoreError::VersionConflict);
    }
    Ok(record)
}
fn validate_discovery_owner(
    definition: &ImportedServiceDefinition,
    actor: &str,
) -> Result<(), ManagedStoreError> {
    if let ImportedDiscoveryCredential::PerUser { principal } = &definition.discovery
        && principal != actor
    {
        return Err(invalid(
            "personal discovery must use the invoking administrator's credential",
        ));
    }
    Ok(())
}
fn require_enabled_credentials(
    runtime: &BrokerRuntime,
    record: &ImportedServiceRecord,
) -> Result<(), ManagedStoreError> {
    if record.actions.is_empty() {
        return Err(invalid(
            "accept at least one action before enabling the import",
        ));
    }
    if !record.definition.execution_bindings.iter().any(|binding| {
        runtime.import_binding_available(&record.definition, binding)
            && (binding.owner_mode == ImportedCredentialMode::PerUser
                || record
                    .slot_versions
                    .contains_key(&ImportedCredentialPurpose::Execution))
    }) {
        return Err(invalid(
            "import has no supported provisioned execution credential mode",
        ));
    }
    if record.definition.transport_auth
        && !record
            .slot_versions
            .contains_key(&ImportedCredentialPurpose::Transport)
    {
        return Err(invalid("transport credential is not provisioned"));
    }
    Ok(())
}

fn prepare_update(
    runtime: &BrokerRuntime,
    store: &ManagedStore,
    record: &ImportedServiceRecord,
    actor: String,
    config_revision: &str,
    body: Bytes,
    change: Change,
) -> Result<ImportedServiceUpdateRequest, ManagedStoreError> {
    let service = &record.definition.service;
    match change {
        Change::Update => {
            let body: UpdateBody = parse(body)?;
            checked_record(runtime, service, &body.versions)?;
            runtime.require_import_destination(&body.definition)?;
            runtime.require_import_bindings(&body.definition, Some(&record.definition))?;
            if body.definition.service != *service {
                return Err(invalid("service identity cannot be changed"));
            }
            if body.definition.discovery != record.definition.discovery {
                validate_discovery_owner(&body.definition, &actor)?;
            }
            if record.definition.execution_bindings != body.definition.execution_bindings
                && !body.confirm_affected_grants
                && !affected_grants(store, service, None)?.is_empty()
            {
                return Err(invalid(
                    "credential binding changes affect existing grants; confirmAffectedGrants is required",
                ));
            }
            let mut request = mutation_request(record, body.versions, actor);
            request.definition = body.definition;
            Ok(request)
        }
        Change::Status => {
            let body: StatusBody = parse(body)?;
            checked_record(runtime, service, &body.versions)?;
            let status = match body.status.as_str() {
                "enabled" => ImportedServiceStatus::Enabled,
                "disabled" => ImportedServiceStatus::Disabled,
                "retired" => ImportedServiceStatus::Retired,
                _ => return Err(invalid("invalid import service status")),
            };
            if status == ImportedServiceStatus::Enabled {
                runtime.require_import_destination(&record.definition)?;
                require_enabled_credentials(runtime, record)?;
                if record.status != ImportedServiceStatus::Enabled
                    && !body.confirm
                    && !affected_grants(store, service, None)?.is_empty()
                {
                    return Err(invalid(
                        "enabling this service restores existing grants; confirm is required",
                    ));
                }
            }
            if status == ImportedServiceStatus::Retired && !body.confirm {
                return Err(invalid("retirement requires confirm"));
            }
            let mut request = mutation_request(record, body.versions, actor);
            request.status = status;
            Ok(request)
        }
        Change::ActionStatus(action) => {
            let body: StatusBody = parse(body)?;
            checked_record(runtime, service, &body.versions)?;
            let old = record
                .actions
                .iter()
                .find(|a| a.definition.action == action)
                .ok_or_else(|| invalid("imported action was not found"))?;
            let status = match body.status.as_str() {
                "enabled" => ImportedActionStatus::Enabled,
                "disabled" => ImportedActionStatus::Disabled,
                "retired" => ImportedActionStatus::Retired,
                _ => return Err(invalid("invalid imported action status")),
            };
            if old.status == ImportedActionStatus::Retired
                && status != ImportedActionStatus::Retired
            {
                return Err(invalid("retired action identities cannot be reused"));
            }
            if old.status == ImportedActionStatus::Quarantined
                && status != ImportedActionStatus::Retired
            {
                return Err(invalid("quarantined actions require preview acceptance"));
            }
            if status == ImportedActionStatus::Enabled {
                runtime.require_import_destination(&record.definition)?;
                if old.status != ImportedActionStatus::Enabled
                    && !body.confirm
                    && !affected_grants(store, service, Some(&BTreeSet::from([action.clone()])))?
                        .is_empty()
                {
                    return Err(invalid(
                        "enabling this action restores existing grants; confirm is required",
                    ));
                }
            }
            if status == ImportedActionStatus::Retired && !body.confirm {
                return Err(invalid("retirement requires confirm"));
            }
            let mut request = mutation_request(record, body.versions, actor);
            request
                .actions
                .iter_mut()
                .find(|a| a.definition.action == action)
                .expect("checked action")
                .status = status;
            Ok(request)
        }
        Change::Accept => {
            let body: AcceptBody = parse(body)?;
            checked_record(runtime, service, &body.versions)?;
            runtime.require_import_destination(&record.definition)?;
            let preview = store
                .imported_preview(service)?
                .ok_or(ManagedStoreError::VersionConflict)?;
            if preview.config_revision != config_revision
                || preview.manifest_hash != body.manifest_hash
            {
                return Err(ManagedStoreError::VersionConflict);
            }
            let manifest: ImportedDiscovery = serde_json::from_value(preview.manifest.clone())
                .map_err(|_| invalid("stored discovery preview is invalid"))?;
            if body.selections.is_empty() {
                return Err(invalid("select at least one discovered tool"));
            }
            let mut request = mutation_request(record, body.versions, actor);
            let mut sources = BTreeSet::new();
            let mut names = BTreeSet::new();
            let mut changed = BTreeSet::new();
            let adapter = runtime
                .config()
                .providers
                .registry()
                .imported_adapter(&record.definition.adapter_kind)
                .ok_or_else(|| invalid("import adapter is not linked"))?;
            for selection in body.selections {
                if !sources.insert(selection.source.to_string())
                    || !names.insert(selection.action.clone())
                {
                    return Err(invalid("duplicate tool selection or action name"));
                }
                let source = manifest
                    .tools
                    .iter()
                    .find(|tool| tool.definition.source == selection.source)
                    .ok_or_else(|| invalid("selected tool is absent from preview"))?;
                if source.unsupported_reason.is_some() {
                    return Err(invalid("unsupported tools cannot be accepted"));
                }
                let mut definition = source.definition.clone();
                definition.action = selection.action;
                definition.label = selection.label;
                definition.read_only = selection.read_only;
                definition
                    .validate(service)
                    .map_err(ManagedStoreError::InputInvalid)?;
                adapter
                    .validate_action(&definition)
                    .map_err(ManagedStoreError::InputInvalid)?;
                // Adapter source validation is independent of the scoped naming
                // profile. A valid but out-of-profile name remains acceptable.
                adapter
                    .scoped_mcp_name(&definition)
                    .map_err(ManagedStoreError::InputInvalid)?;
                if let Some(old) = record.actions.iter().find(|a| {
                    a.definition.source == definition.source
                        && a.status != ImportedActionStatus::Retired
                }) {
                    if old.definition.action != definition.action {
                        return Err(invalid("accepted action names cannot be changed"));
                    }
                    if old.status == ImportedActionStatus::Retired {
                        return Err(invalid("retired action identities cannot be reused"));
                    }
                    if source_changed(&old.definition, &definition)
                        || old.definition.read_only != definition.read_only
                        || old.status != ImportedActionStatus::Enabled
                    {
                        changed.insert(definition.action.clone());
                    }
                    let action = request
                        .actions
                        .iter_mut()
                        .find(|a| a.definition.action == definition.action)
                        .expect("retained action");
                    action.definition = definition;
                    action.status = ImportedActionStatus::Enabled;
                } else {
                    if record
                        .actions
                        .iter()
                        .any(|a| a.definition.action == definition.action)
                    {
                        return Err(invalid("action name already belongs to another source"));
                    }
                    request.actions.push(ImportedActionWrite {
                        definition,
                        status: ImportedActionStatus::Enabled,
                    });
                }
            }
            if !body.confirm_affected_grants
                && !affected_grants(store, service, Some(&changed))?.is_empty()
            {
                return Err(invalid(
                    "accepted changes affect existing grants; confirmAffectedGrants is required",
                ));
            }
            if request.status == ImportedServiceStatus::Draft {
                request.status = ImportedServiceStatus::Disabled;
            }
            request.accepted_preview = Some(ImportedPreviewAcceptance {
                manifest_hash: preview.manifest_hash,
                config_revision: preview.config_revision,
                credential_versions: preview.credential_versions,
            });
            Ok(request)
        }
        _ => unreachable!("separate import mutation branch"),
    }
}

pub(crate) async fn discover(
    State(state): State<AppState>,
    Path(service): Path<String>,
    ConnectInfo(remote): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let operation = "admin.imports.discover";
    let context = match management_context(
        &state,
        remote,
        &headers,
        operation,
        ManagementAccess::AdminWrite,
    )
    .await
    {
        Ok(c) => c,
        Err(r) => return *r,
    };
    let target = Some(json!({"service":service}));
    let prepared = (|| {
        let versions = parse_versions(body)?;
        let record = current_record(&context, &service)?;
        check_versions(&context, &record, &versions)?;
        Ok::<_, ManagedStoreError>((record, versions))
    })();
    let (record, versions) = match prepared {
        Ok(v) => v,
        Err(e) => return management_store_error_response(&context, operation, target, e).await,
    };
    if let Err(response) =
        management_write_audit_preflight(&context, operation, target.clone()).await
    {
        return *response;
    }
    let (discovery, credential_versions) = match context
        .snapshot
        .runtime
        .discover_imported_service(&service, &context.identity.principal)
        .await
    {
        Ok(v) => v,
        Err(e) => return management_provider_error_response(&context, operation, target, e).await,
    };
    let quarantine = record
        .actions
        .iter()
        .filter(|action| {
            action.status != ImportedActionStatus::Retired
                && discovery
                    .tools
                    .iter()
                    .find(|tool| tool.definition.source == action.definition.source)
                    .is_none_or(|tool| {
                        tool.unsupported_reason.is_some()
                            || source_changed(&action.definition, &tool.definition)
                    })
        })
        .map(|action| action.definition.action.clone())
        .collect::<Vec<_>>();
    let actor = context.identity.principal.clone();
    let config_revision = format!(
        "{}:{}",
        context.snapshot.generation, context.snapshot.config_hash
    );
    let service_for_store = service.clone();
    let context = Arc::new(context);
    let owner_context = context.clone();
    let owner_target = target.clone();
    // Own publication and its completion audit together even if the HTTP
    // response waiter is canceled after a complete discovery observation.
    let owner = tokio::spawn(async move {
        let context = owner_context;
        let target = owner_target;
        let result = state
            .reloadable
            .imported_service_mutation(context.snapshot.clone(), move |runtime| {
                let mut candidate = record;
                for action in &mut candidate.actions {
                    if quarantine.contains(&action.definition.action) {
                        action.status = ImportedActionStatus::Quarantined;
                    }
                }
                let providers = runtime.prepare_imported_service_change(&candidate, None)?;
                let store = runtime
                    .managed_store()
                    .ok_or_else(|| invalid("import storage unavailable"))?;
                let manifest = serde_json::to_value(discovery)
                    .map_err(|_| invalid("invalid discovery response"))?;
                let manifest_bytes = serde_json::to_vec(&manifest)
                    .map_err(|_| invalid("invalid discovery response"))?;
                let completion = json!({"service":service_for_store,
                "manifestHash":format!("{:x}", Sha256::digest(&manifest_bytes)),
                "quarantinedActions":quarantine});
                let request = ImportedPreviewWriteRequest {
                    service: service_for_store.clone(),
                    expected_version: versions.expected_version,
                    expected_catalog_revision: versions.expected_catalog_revision,
                    config_revision,
                    credential_versions,
                    manifest,
                    quarantine_actions: quarantine,
                    actor,
                };
                let mutation = store.write_imported_preview(request, |catalog| {
                    runtime.with_imported_catalog(catalog.clone(), providers)
                })?;
                // Always publish the committed catalog even if a subsequent metadata read fails.
                let response = (|| {
                    let preview = store.imported_preview(&service_for_store)?;
                    let affected = affected_grants(store, &service_for_store, None)?;
                    let by_action = grants_by_action(store, &service_for_store)?;
                    let mut response =
                        record_result(&mutation.value, &mutation.catalog, &service_for_store);
                    let record = mutation
                        .catalog
                        .service(&service_for_store)
                        .ok_or_else(|| invalid("imported service was not found"))?;
                    response["scopedMcpWarnings"] = json!(preview_scoped_mcp_warnings(
                        &mutation.value,
                        record,
                        preview.as_ref(),
                    )?);
                    response["preview"] = json!(preview);
                    response["affectedGrants"] = json!(affected);
                    response["affectedGrantsByAction"] = json!(by_action);
                    Ok::<_, ManagedStoreError>(response)
                })();
                Ok((mutation.value, (response, completion)))
            })
            .await;
        match result {
            Ok((result, completion)) => {
                if let Err(response) =
                    management_write_audit_completion(&context, operation, Some(completion)).await
                {
                    return *response;
                }
                match result {
                    Ok(result) => {
                        management_pre_audited_success_response(&context, operation, target, result)
                    }
                    Err(error) => {
                        management_store_error_response(&context, operation, target, error).await
                    }
                }
            }
            Err(e) => management_store_error_response(&context, operation, target, e).await,
        }
    });
    match owner.await {
        Ok(response) => response,
        Err(_) => {
            management_store_error_response(
                &context,
                operation,
                target,
                ManagedStoreError::Unavailable("import discovery completion failed".into()),
            )
            .await
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use agent_access_core::imports::ImportedDiscoveredTool;

    #[test]
    fn scoped_preview_warnings_are_provisional_and_do_not_change_the_manifest() {
        let action = |id: &str, name: &str| {
            let mut definition = crate::tests::conformance_import::conformance_import_action();
            definition.action = id.into();
            definition.source = json!({"name":name,"identity":id});
            definition
        };
        let mut record = ImportedServiceRecord {
            definition: ImportedServiceDefinition {
                service: "fixture".into(),
                display_name: "Fixture".into(),
                adapter_kind: "fixture".into(),
                endpoint: "https://synthetic.invalid/mcp".into(),
                connection_settings: BTreeMap::new(),
                execution_bindings: vec![],
                discovery: ImportedDiscoveryCredential::Anonymous,
                transport_auth: false,
                invocation_limit: None,
            },
            status: ImportedServiceStatus::Enabled,
            version: 1,
            actions: vec![],
            slot_versions: BTreeMap::new(),
            created_at: String::new(),
            created_by: String::new(),
            updated_at: String::new(),
            updated_by: String::new(),
        };
        for (id, name, status) in [
            ("retained", "shared", ImportedActionStatus::Enabled),
            ("inactive", "available", ImportedActionStatus::Disabled),
            ("retired", "available", ImportedActionStatus::Retired),
            (
                "quarantined",
                "available",
                ImportedActionStatus::Quarantined,
            ),
            ("same", "same", ImportedActionStatus::Enabled),
        ] {
            record.actions.push(ImportedActionRecord {
                definition: action(id, name),
                status,
                version: 1,
                definition_hash: String::new(),
            });
        }
        let manifest = ImportedDiscovery {
            protocol_version: "fixture".into(),
            metadata: json!({}),
            tools: [
                ("one", "shared"),
                ("two", "duplicate"),
                ("three", "duplicate"),
                ("invalid", "private/invalid name"),
                ("reserved", "resources_list"),
                ("free", "available"),
                ("same", "same"),
            ]
            .into_iter()
            .map(|(id, name)| ImportedDiscoveredTool {
                definition: action(id, name),
                unsupported_reason: None,
                read_only_hint: None,
            })
            .collect(),
        };
        let before = serde_json::to_value(&manifest).unwrap();
        let warnings = scoped_mcp_warnings(&record, &manifest, |definition| {
            definition.source["name"].as_str().map(str::to_owned)
        });
        let warnings = serde_json::to_value(warnings).unwrap();
        assert_eq!(
            warnings,
            json!([
                {"toolIndex":0,"proposedAction":"one","codes":["duplicate_name"]},
                {"toolIndex":1,"proposedAction":"two","codes":["duplicate_name"]},
                {"toolIndex":2,"proposedAction":"three","codes":["duplicate_name"]},
                {"toolIndex":3,"proposedAction":"invalid","codes":["invalid_name"]},
                {"toolIndex":4,"proposedAction":"reserved","codes":["reserved_name"]},
            ])
        );
        assert!(!warnings.to_string().contains("private/invalid name"));
        assert_eq!(serde_json::to_value(&manifest).unwrap(), before);
        assert!(
            manifest
                .tools
                .iter()
                .all(|tool| tool.unsupported_reason.is_none())
        );
    }

    #[test]
    fn title_changes_are_metadata_but_behavioral_hints_require_review() {
        let mut old = crate::tests::conformance_import::conformance_import_action();
        old.annotations = json!({"toolAnnotations":{},"execution":null});
        let mut new = old.clone();
        new.annotations["toolAnnotations"]["title"] = json!("New title");
        new.label = Some("New display label".into());
        new.description = "Updated display description".into();
        assert!(!source_changed(&old, &new));
        old.annotations["toolAnnotations"]["title"] = json!("Old title");
        assert!(!source_changed(&old, &new));
        new.annotations["toolAnnotations"]["readOnlyHint"] = json!(true);
        assert!(source_changed(&old, &new));
        new.annotations = old.annotations.clone();
        new.annotations["execution"] = json!({"taskSupport":"optional"});
        assert!(source_changed(&old, &new));
    }
}
